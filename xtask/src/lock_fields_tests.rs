// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Host checks of the actual public flock adapter using byte-preservation oracles.

#[allow(dead_code, unused_imports)]
#[path = "../../lib/posix-abi/src/constants.rs"]
mod constants;
#[path = "../../lib/posix-abi/src/lock_fields.rs"]
mod lock_fields;

use constants::{EAGAIN, EBADF, EFAULT, EINVAL, EIO, ENOLCK, EOVERFLOW};
use lock_fields::Input;
use proto_fs::{LockBlocker, LockCommand, LockKind, LockPhase, LockReply};

fn input(kind: i16, whence: i16, start: i64, length: i64, pid: i32) -> [u8; 32] {
    let mut bytes = [0xa5; 32];
    bytes[..2].copy_from_slice(&kind.to_ne_bytes());
    bytes[2..4].copy_from_slice(&whence.to_ne_bytes());
    bytes[8..16].copy_from_slice(&start.to_ne_bytes());
    bytes[16..24].copy_from_slice(&length.to_ne_bytes());
    bytes[24..28].copy_from_slice(&pid.to_ne_bytes());
    bytes
}
fn read(command: i32, bytes: &[u8; 32]) -> Result<Input, i32> {
    // SAFETY: the array contains every readable field.
    unsafe { Input::read(command, bytes.as_ptr()) }
}
fn finish(input: Input, bytes: &mut [u8; 32], reply: Result<LockReply, i32>) -> Result<i32, i32> {
    // SAFETY: the array contains every writable field; fixtures are canonical replies.
    unsafe { input.finish(bytes.as_mut_ptr(), reply) }
}
fn success(blocker: Option<LockBlocker>) -> LockReply {
    LockReply {
        phase: LockPhase::Complete,
        result: 0,
        blocker,
    }
}

#[test]
fn copied_signed_ranges_preserve_extremes_and_survive_caller_changes() {
    for (command, native) in [
        (5, LockCommand::GetPid),
        (6, LockCommand::SetPid),
        (36, LockCommand::GetOfd),
        (37, LockCommand::SetOfd),
    ] {
        for whence in 0..=2 {
            for (start, length) in [(i64::MIN, -19), (i64::MAX, 2), (-2, 0), (17, i64::MIN)] {
                let mut bytes = input(1, whence, start, length, 0);
                let copied = read(command, &bytes).unwrap();
                bytes.fill(0);
                assert_eq!(copied.command, native);
                assert_eq!(copied.kind, LockKind::Write);
                assert_eq!(copied.whence, whence as u32);
                assert_eq!((copied.start, copied.length), (start, length));
            }
        }
    }
}

#[test]
fn malformed_fields_and_partial_wait_commands_leave_input_unchanged() {
    for (command, bytes) in [
        (5, input(-1, 0, 0, 1, 0)),
        (6, input(3, 0, 0, 1, 0)),
        (5, input(0, -1, 0, 1, 0)),
        (37, input(0, 3, 0, 1, 0)),
        (5, input(2, 0, 0, 1, 0)),
        (7, input(0, 0, 0, 1, 0)),
        (38, input(1, 0, 0, 1, 0)),
        (999, input(0, 0, 0, 1, 0)),
    ] {
        let before = bytes;
        assert_eq!(read(command, &bytes), Err(EINVAL));
        assert_eq!(bytes, before);
    }
    // SAFETY: a null pointer requires no readable memory.
    assert_eq!(unsafe { Input::read(5, core::ptr::null()) }, Err(EFAULT));
}

#[test]
fn process_pid_is_ignored_and_ofd_pid_is_strict() {
    for pid in [i32::MIN, -1, 1, i32::MAX] {
        for command in [5, 6] {
            assert_eq!(read(command, &input(0, 0, 4, -2, pid)).unwrap().pid, 0);
        }
        for command in [36, 37] {
            assert_eq!(read(command, &input(0, 0, 4, -2, pid)), Err(EINVAL));
        }
    }
    assert_eq!(
        read(36, &input(2, 2, -2, 1, 0)).unwrap().kind,
        LockKind::Unlock
    );
    assert_eq!(
        read(37, &input(2, 0, 0, 0, 0)).unwrap().kind,
        LockKind::Unlock
    );
}

#[test]
fn no_blocker_changes_only_type_including_both_padding_regions() {
    for command in [5, 36] {
        for kind in [0, 1] {
            let mut bytes = input(kind, 2, -19, -7, 0);
            let before = bytes;
            let copied = read(command, &bytes).unwrap();
            assert_eq!(finish(copied, &mut bytes, Ok(success(None))), Ok(0));
            assert_eq!(&bytes[..2], &2_i16.to_ne_bytes());
            assert_eq!(&bytes[2..], &before[2..]);
        }
    }
}

#[test]
fn blocker_writes_absolute_fields_and_preserves_padding_for_pid_and_ofd() {
    for (pid, length) in [(257, 7), (-1, 0)] {
        let mut bytes = input(1, 1, -19, -7, 0);
        let copied = read(36, &bytes).unwrap();
        let expected = input(0, 0, 91, length, pid);
        assert_eq!(
            finish(
                copied,
                &mut bytes,
                Ok(success(Some(LockBlocker {
                    kind: LockKind::Read,
                    start: 91,
                    length,
                    pid,
                })))
            ),
            Ok(0)
        );
        assert_eq!(bytes, expected);
    }
}

#[test]
fn setters_never_write_flock_and_errors_preserve_every_byte() {
    for command in [6, 37] {
        let mut bytes = input(1, 2, i64::MAX, i64::MIN, 0);
        let copied = read(command, &bytes).unwrap();
        let before = bytes;
        assert_eq!(finish(copied, &mut bytes, Ok(success(None))), Ok(0));
        assert_eq!(bytes, before);
    }
    for command in [5, 6, 36, 37] {
        for (result, errno) in [
            (proto_fs::BAD_FD, EBADF),
            (proto_fs::INVALID_ARGUMENT, EINVAL),
            (proto_fs::OFFSET_OVERFLOW, EOVERFLOW),
            (proto_fs::NO_LOCKS, ENOLCK),
            (proto_fs::LOCK_CONFLICT, EAGAIN),
            (proto_fs::LOCK_CANCELLED, EIO),
            (proto_fs::JOBS_FULL, EIO),
            (u32::MAX, EIO),
        ] {
            let mut bytes = input(1, 1, 9, -3, 0);
            let before = bytes;
            let copied = read(command, &bytes).unwrap();
            assert_eq!(
                finish(
                    copied,
                    &mut bytes,
                    Ok(LockReply {
                        result,
                        ..success(None)
                    })
                ),
                Err(errno)
            );
            assert_eq!(bytes, before);
        }
    }
}

#[test]
fn pending_or_failed_driver_outcome_never_changes_caller_fields() {
    let mut bytes = input(1, 1, -1, 2, 0);
    let before = bytes;
    let copied = read(5, &bytes).unwrap();
    assert_eq!(finish(copied, &mut bytes, Err(EBADF)), Err(EBADF));
    assert_eq!(bytes, before);
    assert_eq!(
        finish(
            copied,
            &mut bytes,
            Ok(LockReply {
                phase: LockPhase::Pending,
                ..success(None)
            })
        ),
        Err(EIO)
    );
    assert_eq!(bytes, before);
}
