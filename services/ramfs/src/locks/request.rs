// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Capture lock authority, access and seek bases from the genuine RAM fd.

use super::{
    Kind, Owner, Range, RangeError,
    actor::{Command, Error, Request, Response},
};
use crate::{Fds, Ram, TentativeOpen, storage::Root};
use proto_fs::{LockBlocker, LockKind, LockPhase, LockReply, LockStart};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Captured {
    pub request: Request,
    pub root: Root,
    pub source: TentativeOpen,
    /// The OFD GET/UNLCK extension completes without entering the actor.
    pub unlocked_query: bool,
}

impl Ram<'_> {
    /// Capture WAIT using the same genuine SET validation, without Control custody.
    pub fn capture_wait(&self, fds: &Fds, wire: proto_fs::WaitStart) -> Result<Captured, u32> {
        wire.validate().map_err(|error| error.code())?;
        self.capture_lock(
            fds,
            LockStart {
                // This key is local capture input only; no Control queue is touched.
                key: proto_fs::OpenKey {
                    slot: 32 + wire.key.slot,
                    generation: wire.key.generation,
                },
                description: wire.description,
                command: if wire.mode.ofd() {
                    proto_fs::LockCommand::SetOfd
                } else {
                    proto_fs::LockCommand::SetPid
                },
                kind: wire.kind,
                whence: wire.whence,
                start: wire.start,
                length: wire.length,
                pid: wire.pid,
            },
        )
    }

    /// Capture once at Start; later preparation preserves the normalized region.
    pub fn capture_lock(&self, fds: &Fds, wire: LockStart) -> Result<Captured, u32> {
        wire.validate().map_err(|error| error.code())?;
        let source = TentativeOpen {
            fd: wire.description.fd(),
            description: crate::storage::Token {
                slot: wire.description.slot() as u16,
                generation: wire.description.generation,
            },
        };
        let (inode, flags) = self.live_description(fds, source)?;
        let open = self.get(fds, source.fd)?;
        if open.file.kind() != crate::REG {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let kind = match wire.kind {
            LockKind::Read => Some(Kind::Read),
            LockKind::Write => Some(Kind::Write),
            LockKind::Unlock => None,
        };
        if !wire.command.get()
            && (kind == Some(Kind::Read) && flags & 3 == proto_fs::WRITE_ONLY
                || kind == Some(Kind::Write) && flags & 3 == proto_fs::READ_ONLY)
        {
            return Err(proto_fs::BAD_FD);
        }
        let owner = if wire.command.ofd() {
            Owner::Description {
                slot: source.description.slot,
                generation: source.description.generation,
            }
        } else {
            Owner::Process(fds.binding.close_pid().ok_or(proto_fs::NO_LOCKS)?)
        };
        let origin = match wire.whence {
            0 => 0,
            1 => u64::try_from(open.offset).map_err(|_| proto_fs::OFFSET_OVERFLOW)?,
            2 => self.length(open.file) as u64,
            _ => return Err(proto_fs::INVALID_ARGUMENT),
        };
        let range =
            Range::relative(origin, wire.start, wire.length).map_err(|error| match error {
                RangeError::Invalid => proto_fs::INVALID_ARGUMENT,
                RangeError::Overflow => proto_fs::OFFSET_OVERFLOW,
            })?;
        // An OFD GET with UNLCK uses the documented successful extension.
        let command = if wire.command.get() {
            Command::Get(kind.unwrap_or(Kind::Read))
        } else {
            Command::Set(kind)
        };
        Ok(Captured {
            request: Request {
                inode,
                owner,
                root: 0,
                range,
                command,
            },
            root: fds.root,
            source,
            unlocked_query: wire.command.get() && kind.is_none(),
        })
    }
}

pub fn reply(result: Result<Response, Error>) -> LockReply {
    let (result, blocker) = match result {
        Ok(Response::Changed | Response::Blocker(None)) => (0, None),
        Ok(Response::Blocker(Some(lock))) => {
            let (start, length) = lock.range.start_and_length();
            let pid = match lock.owner {
                Owner::Process(pid) => match i32::try_from(pid) {
                    Ok(pid) => pid,
                    Err(_) => {
                        return LockReply {
                            phase: LockPhase::Complete,
                            result: proto_fs::OFFSET_OVERFLOW,
                            blocker: None,
                        };
                    }
                },
                Owner::Description { .. } => -1,
            };
            (
                0,
                Some(LockBlocker {
                    kind: match lock.kind {
                        Kind::Read => LockKind::Read,
                        Kind::Write => LockKind::Write,
                    },
                    start,
                    length,
                    pid,
                }),
            )
        }
        Err(error) => (
            match error {
                Error::Invalid => proto_fs::INVALID_ARGUMENT,
                Error::NoLocks => proto_fs::NO_LOCKS,
                Error::Conflict(_) => proto_fs::LOCK_CONFLICT,
                Error::Cancelled => proto_fs::LOCK_CANCELLED,
                Error::Busy => proto_fs::RESOLVING,
            },
            None,
        ),
    };
    LockReply {
        phase: LockPhase::Complete,
        result,
        blocker,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_fs::{DataDescription, LockCommand, OpenKey, READ_ONLY, READ_WRITE, WRITE_ONLY};

    fn who(pid: u32) -> proto_process::WhoReply {
        proto_process::WhoReply {
            pid,
            credentials: proto_process::Credentials::NOBODY,
            generation: 1,
            loader: None,
            index: pid & 255,
            ctty: None,
            image: 1,
            groups: proto_process::Groups::EMPTY,
            limits: proto_process::ResourceLimits::initial(2 * 1024 * 1024),
            root: proto_process::ExpenditureRoot {
                pid: 10,
                generation: 1,
            },
        }
    }
    fn wire(ram: &Ram<'_>, fds: &Fds, fd: u32) -> LockStart {
        let (source, _) = ram.capture_description(fds, fd).unwrap();
        LockStart {
            key: OpenKey {
                slot: 32,
                generation: 1,
            },
            description: DataDescription {
                packed: ram.marked_open(fds, source).unwrap() & !proto_fs::OPEN_RANDOM,
                generation: source.description.generation,
            },
            command: LockCommand::SetPid,
            kind: LockKind::Read,
            whence: 0,
            start: 0,
            length: 0,
            pid: 2147,
        }
    }
    #[test]
    fn access_is_required_only_for_setting_the_corresponding_lock_kind() {
        let mut ram = Ram::default();
        let mut fds = Fds {
            binding: crate::authority::Binding::Active(who(257)),
            ..Fds::default()
        };
        for mode in [READ_ONLY, WRITE_ONLY, READ_WRITE] {
            let fd = ram.open(&mut fds, "/tmp/probe", mode).unwrap();
            let original = wire(&ram, &fds, fd);
            for command in [
                LockCommand::SetPid,
                LockCommand::SetOfd,
                LockCommand::GetPid,
                LockCommand::GetOfd,
            ] {
                for kind in [LockKind::Read, LockKind::Write, LockKind::Unlock] {
                    let request = LockStart {
                        command,
                        kind,
                        pid: 0,
                        ..original
                    };
                    let expected = if command == LockCommand::GetPid && kind == LockKind::Unlock {
                        Err(proto_fs::INVALID_ARGUMENT)
                    } else if !command.get()
                        && (kind == LockKind::Read && mode == WRITE_ONLY
                            || kind == LockKind::Write && mode == READ_ONLY)
                    {
                        Err(proto_fs::BAD_FD)
                    } else {
                        Ok(())
                    };
                    assert_eq!(
                        ram.capture_lock(&fds, request).map(|_| ()),
                        expected,
                        "{mode} {command:?} {kind:?}"
                    );
                }
            }
            ram.close(&mut fds, fd).unwrap();
        }
    }
    #[test]
    fn exact_true_fd_and_regular_file_are_required() {
        let entry = |path, mode| bootimg::rootfs::Entry {
            path,
            mode,
            uid: 0,
            gid: 0,
            file: if mode & bootimg::rootfs::DIRECTORY != 0 {
                0
            } else {
                2
            },
        };
        let bytes = crate::tree::test_image(&[
            entry("/dev", bootimg::rootfs::DIRECTORY | 0o755),
            entry("/dev/null", bootimg::rootfs::REGULAR | 0o666),
            entry("/dev/random", bootimg::rootfs::REGULAR | 0o666),
        ]);
        let mut index = crate::tree::Index::new();
        let mut ram = Ram::with_tree(
            proto_fs::Timestamp::ZERO,
            crate::tree::load(&bytes, &mut index).unwrap(),
        );
        let mut fds = Fds::default();
        for path in ["/dev/null", "/dev/random", "/tmp"] {
            let fd = ram.open(&mut fds, path, READ_ONLY).unwrap();
            let request = LockStart {
                command: LockCommand::GetOfd,
                pid: 0,
                ..wire(&ram, &fds, fd)
            };
            assert_eq!(
                ram.capture_lock(&fds, request),
                Err(proto_fs::INVALID_ARGUMENT)
            );
            ram.close(&mut fds, fd).unwrap();
        }
        let fd = ram.open(&mut fds, "/etc/motd", READ_ONLY).unwrap();
        let request = LockStart {
            command: LockCommand::GetOfd,
            pid: 0,
            ..wire(&ram, &fds, fd)
        };
        assert_eq!(
            ram.capture_lock(
                &fds,
                LockStart {
                    description: DataDescription {
                        generation: request.description.generation + 1,
                        ..request.description
                    },
                    ..request
                }
            ),
            Err(proto_fs::BAD_FD)
        );
        let captured = ram.capture_lock(&fds, request).unwrap();
        ram.detach_descriptor(&mut fds, captured.source).unwrap();
        assert_eq!(ram.read(&mut fds, fd, &mut [0]), Ok(1));
        assert_eq!(ram.capture_lock(&fds, request), Err(proto_fs::BAD_FD));
    }
    #[test]
    fn pid_and_root_come_from_genuine_binding_and_survive_credential_generation() {
        let mut ram = Ram::default();
        let mut fds = Fds::default();
        let fd = ram.open(&mut fds, "/etc/motd", READ_ONLY).unwrap();
        let request = wire(&ram, &fds, fd);
        assert_eq!(ram.capture_lock(&fds, request), Err(proto_fs::NO_LOCKS));
        fds.binding = crate::authority::Binding::Inherited(who(257));
        assert_eq!(ram.capture_lock(&fds, request), Err(proto_fs::NO_LOCKS));
        for generation in [1, 211] {
            let mut identity = who(257);
            identity.generation = generation;
            fds.binding = crate::authority::Binding::Active(identity);
            let captured = ram.capture_lock(&fds, request).unwrap();
            assert_eq!(captured.request.owner, Owner::Process(257));
            assert_eq!(captured.root, fds.root);
            assert_eq!(captured.request.root, 0);
        }
        fds.binding = crate::authority::Binding::Boot;
        let captured = ram
            .capture_lock(
                &fds,
                LockStart {
                    command: LockCommand::SetOfd,
                    pid: 0,
                    ..request
                },
            )
            .unwrap();
        assert_eq!(
            captured.request.owner,
            Owner::Description {
                slot: captured.source.description.slot,
                generation: captured.source.description.generation
            }
        );
    }
    #[test]
    fn seek_bases_and_signed_ranges_are_captured_without_moving_cursor() {
        let mut ram = Ram::default();
        let mut fds = Fds::default();
        let fd = ram.open(&mut fds, "/etc/motd", READ_ONLY).unwrap();
        let request = LockStart {
            command: LockCommand::GetOfd,
            pid: 0,
            ..wire(&ram, &fds, fd)
        };
        ram.seek_from(&mut fds, fd, 9, proto_fs::SeekFrom::Start)
            .unwrap();
        let current = ram
            .capture_lock(
                &fds,
                LockStart {
                    whence: 1,
                    start: 2,
                    length: -3,
                    ..request
                },
            )
            .unwrap();
        assert_eq!(current.request.range, Range::relative(9, 2, -3).unwrap());
        assert_eq!(
            ram.seek_from(&mut fds, fd, 0, proto_fs::SeekFrom::Current),
            Ok(9)
        );
        let size = ram.size(&fds, fd).unwrap();
        assert_eq!(
            ram.capture_lock(
                &fds,
                LockStart {
                    whence: 2,
                    start: -2,
                    length: 1,
                    ..request
                }
            )
            .unwrap()
            .request
            .range,
            Range::relative(u64::from(size), -2, 1).unwrap()
        );
        assert_eq!(
            ram.capture_lock(
                &fds,
                LockStart {
                    start: -1,
                    ..request
                }
            ),
            Err(proto_fs::INVALID_ARGUMENT)
        );
        assert_eq!(
            ram.capture_lock(
                &fds,
                LockStart {
                    start: i64::MAX,
                    length: 2,
                    ..request
                }
            ),
            Err(proto_fs::OFFSET_OVERFLOW)
        );
        assert_eq!(
            ram.capture_lock(
                &fds,
                LockStart {
                    start: 10,
                    length: i64::MIN,
                    ..request
                }
            ),
            Err(proto_fs::INVALID_ARGUMENT)
        );
    }
    #[test]
    fn unlocked_ofd_query_carries_no_mutating_actor_command() {
        let mut ram = Ram::default();
        let mut fds = Fds::default();
        let fd = ram.open(&mut fds, "/etc/motd", READ_ONLY).unwrap();
        let request = LockStart {
            command: LockCommand::GetOfd,
            kind: LockKind::Unlock,
            pid: 0,
            ..wire(&ram, &fds, fd)
        };
        let captured = ram.capture_lock(&fds, request).unwrap();
        assert!(captured.unlocked_query);
        assert!(matches!(captured.request.command, Command::Get(_)));
    }
    #[test]
    fn blockers_and_terminal_errors_use_canonical_reply_fields() {
        for owner in [
            Owner::Process(257),
            Owner::Description {
                slot: 3,
                generation: 8,
            },
        ] {
            let range = Range::relative(0, 91, 0).unwrap();
            let lock = super::super::Lock {
                owner,
                range,
                kind: Kind::Write,
            };
            let response = reply(Ok(Response::Blocker(Some(lock))));
            assert_eq!(
                response.blocker,
                Some(LockBlocker {
                    kind: LockKind::Write,
                    start: 91,
                    length: 0,
                    pid: if matches!(owner, Owner::Process(_)) {
                        257
                    } else {
                        -1
                    }
                })
            );
        }
        for (error, code) in [
            (Error::Invalid, proto_fs::INVALID_ARGUMENT),
            (Error::NoLocks, proto_fs::NO_LOCKS),
            (Error::Cancelled, proto_fs::LOCK_CANCELLED),
        ] {
            assert_eq!(
                reply(Err(error)),
                LockReply {
                    phase: LockPhase::Complete,
                    result: code,
                    blocker: None
                }
            );
        }
    }
}
