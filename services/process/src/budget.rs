// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The answer of the service to `Method::Budget` (proto_process::sporadic):
//! in 0.5.0 every operation is refused and no program gets a budget, so
//! no program binds, unbinds or reports on a budget of its own. The bodies
//! are read and checked as they will be (a flag or a reserved word that is
//! not zero is INVALID, a body of the wrong size BAD_SIZE), so that a layer
//! that sends a malformed message learns it whatever the release can do.
//! Pure: tested on the host.

use proto_process::sporadic::{
    BIND_WORK, BindWork, CLEAR, Clear, DROP, GET, QUERY, Query, RESERVE, Reserve, SET, Set,
    SharesHead, WORK, Work,
};
use proto_process::{FULL, PERMISSION};
use proto_wire::{Reader, Status};

/// What the service answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    /// A refusal: the status alone.
    Status(Status),
    /// The reply of QUERY: the status 0, this head and no entry.
    Shares(SharesHead),
}

/// The answer to the operation `op` with `body` (after the operation) and
/// `handles` handles, through a session (`session` true) or through the
/// channel with no label.
pub fn answer(session: bool, op: u32, mut body: Reader<'_>, handles: usize) -> Reply {
    let refuse = |code| Reply::Status(Status::from_code(code));
    // The operations of the service's own threads come through the channel
    // with no label, and the operations of a program through its session.
    let own = matches!(op, WORK | BIND_WORK);
    if own == session
        && matches!(
            op,
            WORK | BIND_WORK | SET | CLEAR | DROP | RESERVE | QUERY | GET
        )
    {
        return refuse(PERMISSION);
    }
    let read = |ok: Result<(), Status>, wanted: usize| match ok {
        Err(status) => Some(Reply::Status(status)),
        Ok(()) if handles != wanted => Some(Reply::Status(Status::BadSize)),
        Ok(()) => None,
    };
    let checked = match op {
        SET => read(Set::read(&mut body).map(drop), 1),
        CLEAR | DROP | GET => read(Clear::read(&mut body).map(drop), 0),
        RESERVE => read(Reserve::read(&mut body).map(drop), 0),
        WORK => read(Work::read(&mut body).map(drop), 0),
        BIND_WORK => read(BindWork::read(&mut body).map(drop), 1),
        QUERY => read(Query::read(&mut body).map(drop), 0),
        // A number that is no operation: distinct from a body off the rules,
        // so that a later layer can probe for an operation.
        _ => return Reply::Status(Status::UnknownMethod),
    };
    if let Some(reply) = checked {
        return reply;
    }
    if body.finish().is_err() {
        return Reply::Status(Status::BadSize);
    }
    match op {
        // No CPU has a share in 0.5.0.
        QUERY => Reply::Shares(SharesHead {
            flags: 0,
            reserved: 0,
            cpus: 0,
            count: 0,
        }),
        _ => refuse(FULL),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_process::INVALID;
    use proto_wire::Writer;

    fn set() -> Set {
        Set {
            thread: 2,
            cpu: 1,
            low: 3,
            max_repl: 4,
            flags: 0,
            reserved: 0,
            c_ns: 1_000_000,
            t_ns: 10_000_000,
        }
    }

    fn body(f: impl FnOnce(&mut Writer)) -> Vec<u8> {
        let mut w = Writer::new();
        f(&mut w);
        w.as_bytes().to_vec()
    }

    fn full() -> Reply {
        Reply::Status(Status::from_code(FULL))
    }

    #[test]
    fn a_program_that_asks_for_a_budget_gets_a_refusal_and_no_handle_comes_back() {
        let set_body = body(|w| set().write(w).unwrap());
        assert_eq!(answer(true, SET, Reader::new(&set_body), 1), full());
        let clear = body(|w| {
            Clear {
                thread: 2,
                flags: 0,
                reserved: 0,
            }
            .write(w)
            .unwrap()
        });
        assert_eq!(answer(true, CLEAR, Reader::new(&clear), 0), full());
        assert_eq!(answer(true, DROP, Reader::new(&clear), 0), full());
        let reserve = body(|w| {
            Reserve {
                child: 9,
                thread: 2,
                flags: 0,
                reserved: 0,
                set: set(),
            }
            .write(w)
            .unwrap();
        });
        assert_eq!(answer(true, RESERVE, Reader::new(&reserve), 0), full());
    }

    fn query() -> Vec<u8> {
        body(|w| {
            Query {
                first: 0,
                flags: 0,
                reserved: 0,
                count: 8,
            }
            .write(w)
            .unwrap()
        })
    }

    #[test]
    fn the_query_says_no_cpu_has_a_share() {
        assert_eq!(
            answer(true, QUERY, Reader::new(&query()), 0),
            Reply::Shares(SharesHead {
                flags: 0,
                reserved: 0,
                cpus: 0,
                count: 0
            })
        );
    }

    #[test]
    fn a_get_is_refused_like_the_rest() {
        let get = body(|w| {
            Clear {
                thread: 2,
                flags: 0,
                reserved: 0,
            }
            .write(w)
            .unwrap()
        });
        assert_eq!(answer(true, GET, Reader::new(&get), 0), full());
        assert_eq!(
            answer(false, GET, Reader::new(&get), 0),
            Reply::Status(Status::from_code(PERMISSION))
        );
    }

    #[test]
    fn a_body_off_the_rules_is_told_so() {
        let invalid = Reply::Status(Status::from_code(INVALID));
        let bad = body(|w| Set { flags: 1, ..set() }.write(w).unwrap());
        assert_eq!(answer(true, SET, Reader::new(&bad), 1), invalid);
        let bad = body(|w| {
            Set {
                reserved: 1,
                ..set()
            }
            .write(w)
            .unwrap()
        });
        assert_eq!(answer(true, SET, Reader::new(&bad), 1), invalid);
        let ok = body(|w| set().write(w).unwrap());
        // SET names its thread with one handle; none, or two, is a size error.
        assert_eq!(
            answer(true, SET, Reader::new(&ok), 0),
            Reply::Status(Status::BadSize)
        );
        assert_eq!(
            answer(true, SET, Reader::new(&ok), 2),
            Reply::Status(Status::BadSize)
        );
        assert_eq!(
            answer(true, SET, Reader::new(&ok[..39]), 1),
            Reply::Status(Status::BadSize)
        );
        let mut long = ok.clone();
        long.push(0);
        assert_eq!(
            answer(true, SET, Reader::new(&long), 1),
            Reply::Status(Status::BadSize)
        );
        assert_eq!(
            answer(true, QUERY, Reader::new(&[0]), 0),
            Reply::Status(Status::BadSize)
        );
        let mut long = query();
        long.push(0);
        assert_eq!(
            answer(true, QUERY, Reader::new(&long), 0),
            Reply::Status(Status::BadSize)
        );
        let flag = body(|w| {
            Query {
                first: 0,
                flags: 1,
                reserved: 0,
                count: 8,
            }
            .write(w)
            .unwrap()
        });
        assert_eq!(answer(true, QUERY, Reader::new(&flag), 0), invalid);
    }

    #[test]
    fn the_operations_of_the_services_own_threads_are_not_a_programs() {
        let perm = Reply::Status(Status::from_code(PERMISSION));
        let work = body(|w| {
            Work {
                seq: 0,
                status: 0,
                id: 0,
                flags: 0,
                reserved: 0,
            }
            .write(w)
            .unwrap()
        });
        assert_eq!(answer(true, WORK, Reader::new(&work), 0), perm);
        assert_eq!(answer(false, WORK, Reader::new(&work), 0), full());
        let bind = body(|w| {
            BindWork {
                seq: 0,
                status: 0,
                flags: 0,
                reserved: 0,
            }
            .write(w)
            .unwrap()
        });
        assert_eq!(answer(true, BIND_WORK, Reader::new(&bind), 1), perm);
        assert_eq!(answer(false, BIND_WORK, Reader::new(&bind), 1), full());
        // The channel with no label carries no operation of a program.
        let ok = body(|w| set().write(w).unwrap());
        assert_eq!(answer(false, SET, Reader::new(&ok), 1), perm);
        assert_eq!(answer(false, QUERY, Reader::new(&query()), 0), perm);
    }
}

#[cfg(test)]
mod unknown {
    use super::*;
    use proto_process::INVALID;

    #[test]
    fn a_number_that_is_no_operation_has_a_status_of_its_own() {
        for op in [0, 9, 99] {
            assert_eq!(
                answer(true, op, Reader::new(&[]), 0),
                Reply::Status(Status::UnknownMethod)
            );
            assert_ne!(Status::UnknownMethod, Status::from_code(INVALID));
        }
    }
}
