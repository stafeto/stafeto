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
    BIND_WORK, BindWork, CLEAR, Clear, DROP, QUERY, RESERVE, Reserve, SET, Set, Shares, WORK, Work,
};
use proto_process::{FULL, INVALID, PERMISSION};
use proto_wire::{Reader, Status};

/// What the service answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    /// A refusal: the status alone.
    Status(Status),
    /// The reply of QUERY: the status 0 and these shares.
    Shares(Shares),
}

/// The answer to the operation `op` with `body` (after the operation) and
/// `handles` handles, through a session (`session` true) or through the
/// channel with no label.
pub fn answer(session: bool, op: u32, mut body: Reader<'_>, handles: usize) -> Reply {
    let refuse = |code| Reply::Status(Status::from_code(code));
    // The operations of the service's own threads come through the channel
    // with no label, and the operations of a program through its session.
    let own = matches!(op, WORK | BIND_WORK);
    if own == session && matches!(op, WORK | BIND_WORK | SET | CLEAR | DROP | RESERVE | QUERY) {
        return refuse(PERMISSION);
    }
    let read = |ok: Result<(), Status>, wanted: usize| match ok {
        Err(status) => Some(Reply::Status(status)),
        Ok(()) if handles != wanted => Some(Reply::Status(Status::BadSize)),
        Ok(()) => None,
    };
    let checked = match op {
        SET => read(Set::read(&mut body).map(drop), 1),
        CLEAR | DROP => read(Clear::read(&mut body).map(drop), 0),
        RESERVE => read(Reserve::read(&mut body).map(drop), 0),
        WORK => read(Work::read(&mut body).map(drop), 0),
        BIND_WORK => read(BindWork::read(&mut body).map(drop), 1),
        QUERY => read(Ok(()), 0),
        _ => return refuse(INVALID),
    };
    if let Some(reply) = checked {
        return reply;
    }
    if body.finish().is_err() {
        return Reply::Status(Status::BadSize);
    }
    match op {
        QUERY => Reply::Shares(Shares { mask: 0, flags: 0 }),
        _ => refuse(FULL),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn the_query_says_no_cpu_has_a_share() {
        assert_eq!(
            answer(true, QUERY, Reader::new(&[]), 0),
            Reply::Shares(Shares { mask: 0, flags: 0 })
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
        assert_eq!(answer(true, 0, Reader::new(&[]), 0), invalid);
        assert_eq!(answer(true, 99, Reader::new(&[]), 0), invalid);
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
        assert_eq!(answer(false, QUERY, Reader::new(&[]), 0), perm);
    }
}
