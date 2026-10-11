// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Sixty-four real paid OFD waiters retained before their first atomic Query.
use core::mem::ManuallyDrop;
use proto_fs::{LockKind, Method, WaitKey, WaitMode, WaitPhase, WaitReply, WaitStart};
use proto_wire::{Reader, Status, Writer};
use rt::fs::Files;

unsafe extern "C" {
    fn lock_fifo_full_control() -> i32;
}
fn reply(files: &Files, request: &Writer) -> Result<WaitReply, Status> {
    let response = Files::send_on(files.sessions().0, request.as_bytes())?;
    if !response.handles.is_empty() {
        return Err(Status::BadSize);
    }
    let mut bytes = [0; rt::abi::MESSAGE_MAX];
    WaitReply::read(Reader::new(response.bytes(&mut bytes)))
}
fn cleanup(files: &Files, key: WaitKey, expected: u32) -> Result<(), Status> {
    let mut request = Writer::new();
    proto_fs::write_wait_key(Method::WaitCancel, key, &mut request)?;
    let terminal = reply(files, &request)?;
    if terminal.phase != WaitPhase::Complete {
        return Err(Status::BadSize);
    }
    let canonical = terminal.result == expected;
    let mut request = Writer::new();
    proto_fs::write_wait_key(Method::WaitRelease, key, &mut request)?;
    for _ in 0..4096 {
        let response = Files::send_on(files.sessions().0, request.as_bytes())?;
        if !response.handles.is_empty() {
            return Err(Status::BadSize);
        }
        let mut bytes = [0; rt::abi::MESSAGE_MAX];
        let mut reader = Reader::new(response.bytes(&mut bytes));
        let status = reader.u32()?;
        if reader.u32()? != 0 {
            return Err(Status::BadSize);
        }
        reader.finish()?;
        if status == 0 {
            return if canonical {
                Ok(())
            } else {
                Err(Status::BadSize)
            };
        }
        if status != proto_fs::RESOLVING {
            return Err(Status::from_code(status));
        }
        rt::sys::yield_now().map_err(Status::Kernel)?;
    }
    Err(Status::BadSize)
}

#[unsafe(no_mangle)]
pub extern "C" fn lock_fifo_full_waiters() -> i32 {
    fn run() -> Result<(), i32> {
        let raw =
            posix_abi::shared::with_files(|files| Ok(files.sessions().0.raw())).map_err(|_| 1)?;
        let original = ManuallyDrop::new(Files::from_sessions(rt::Handle::from_raw(raw), None));
        let mut sessions: [Option<Files>; 5] = [const { None }; 5];
        let mut opened = [[None; 16]; 5];
        let mut started = [0; 5];
        let result = (|| {
            let mut clone = Writer::new();
            Method::Clone.header().write(&mut clone).map_err(|_| 2)?;
            clone.u32(0).map_err(|_| 2)?;
            for family in 0..4 {
                let channel =
                    Files::clone_on(original.sessions().0, clone.as_bytes()).map_err(|_| 2)?;
                let files = Files::from_sessions(channel, None);
                files
                    .bind(posix_abi::process::identity().ok_or(3)?)
                    .map_err(|_| 4)?;
                sessions[family] = Some(files);
                let files = sessions[family].as_ref().unwrap();
                for slot in 0..16 {
                    let fd = files
                        .open("/tmp/lock-fifo-full", proto_fs::READ_WRITE)
                        .map_err(|_| 5)?;
                    opened[family][slot] = Some(fd);
                    let held = files.capture_description(fd).map_err(|_| 6)?.held;
                    let wire = WaitStart {
                        key: WaitKey {
                            slot: slot as u32,
                            generation: 1,
                        },
                        description: proto_fs::DataDescription {
                            packed: held.marked_fd(),
                            generation: held.generation,
                        },
                        mode: WaitMode::Ofd,
                        kind: LockKind::Read,
                        whence: 0,
                        start: 0,
                        length: 127,
                        pid: 0,
                    };
                    let mut request = Writer::new();
                    wire.write(&mut request).map_err(|_| 7)?;
                    let got = reply(files, &request).map_err(|_| 8)?;
                    started[family] += 1;
                    if got.phase != WaitPhase::Queued || got.result != 0 {
                        return Err(9);
                    }
                }
            }
            // A public 65th admission witnesses the actual per-inode FIFO cap.
            let channel =
                Files::clone_on(original.sessions().0, clone.as_bytes()).map_err(|_| 12)?;
            let files = Files::from_sessions(channel, None);
            files
                .bind(posix_abi::process::identity().ok_or(13)?)
                .map_err(|_| 14)?;
            sessions[4] = Some(files);
            let files = sessions[4].as_ref().unwrap();
            let fd = files
                .open("/tmp/lock-fifo-full", proto_fs::READ_WRITE)
                .map_err(|_| 15)?;
            opened[4][0] = Some(fd);
            let held = files.capture_description(fd).map_err(|_| 16)?.held;
            let wire = WaitStart {
                key: WaitKey {
                    slot: 0,
                    generation: 1,
                },
                description: proto_fs::DataDescription {
                    packed: held.marked_fd(),
                    generation: held.generation,
                },
                mode: WaitMode::Ofd,
                kind: LockKind::Read,
                whence: 0,
                start: 0,
                length: 127,
                pid: 0,
            };
            let mut request = Writer::new();
            wire.write(&mut request).map_err(|_| 17)?;
            let got = reply(files, &request).map_err(|_| 18)?;
            started[4] = 1;
            if got.phase != WaitPhase::Complete || got.result != proto_fs::NO_LOCKS {
                return Err(19);
            }
            rt::println!("posix-procs: full lock FIFO: genuine 65th WAIT refused with NO_LOCKS");
            // No Query has granted a waiter: all 64 distinct real descriptions
            // remain in the public FIFO while the C client sends GET and SET.
            // SAFETY: the mapped single-threaded C supervisor owns this callback.
            if unsafe { lock_fifo_full_control() } != 0 {
                return Err(10);
            }
            Ok(())
        })();
        let mut cleaned = true;
        for family in 0..5 {
            if let Some(files) = &sessions[family] {
                for slot in 0..started[family] {
                    cleaned &= cleanup(
                        files,
                        WaitKey {
                            slot: slot as u32,
                            generation: 1,
                        },
                        if family == 4 {
                            proto_fs::NO_LOCKS
                        } else {
                            proto_fs::LOCK_CANCELLED
                        },
                    )
                    .is_ok();
                }
                for fd in opened[family].into_iter().flatten() {
                    cleaned &= files.close(fd).is_ok();
                }
            }
        }
        result?;
        if !cleaned {
            return Err(11);
        }
        Ok(())
    }
    run().err().unwrap_or(0)
}
