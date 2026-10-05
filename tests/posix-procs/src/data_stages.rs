// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Genuine bound-session requests exercise the admitted data journal.
use proto_fs::{DataDescription, DataKind, DataOutcome, DataPhase, DataResult, DataStart, OpenKey};
use proto_wire::Status;
use rt::fs::{Files, PreparedOpen};

fn args(held: PreparedOpen, slot: u32, kind: DataKind, count: u32, position: u64) -> DataStart {
    DataStart {
        key: OpenKey {
            slot,
            generation: 1,
        },
        kind,
        description: DataDescription {
            packed: held.fd | (held.slot << proto_fs::OPEN_DESCRIPTION_SHIFT),
            generation: held.generation,
        },
        count,
        position,
    }
}

fn complete(files: &Files, job: u64, args: DataStart) -> Result<DataOutcome, Status> {
    for _ in 0..3000 {
        match files.data_step_once(job) {
            Ok(()) => {}
            Err(Status::Unknown(proto_fs::RESOLVING)) => continue,
            Err(error) => return Err(error),
        }
        match files.data_commit_once(job, args) {
            Ok(outcome) => return Ok(outcome),
            Err(Status::Unknown(proto_fs::RESOLVING | proto_fs::TIME_DEFERRED)) => {}
            Err(error) => return Err(error),
        }
    }
    Err(Status::BadSize)
}

fn cleanup(files: &Files, key: OpenKey, ack: bool) -> Result<(), Status> {
    for _ in 0..3000 {
        let result = if ack {
            files.data_ack_once(key)
        } else {
            files.data_cancel_once(key)
        };
        match result {
            Ok(()) => return Ok(()),
            Err(Status::Unknown(proto_fs::RESOLVING)) => {}
            Err(error) => return Err(error),
        }
    }
    Err(Status::BadSize)
}

fn open(files: &Files, generation: u64, path: &[u8]) -> Result<PreparedOpen, Status> {
    let key = OpenKey {
        slot: 31,
        generation,
    };
    let id = files.open_start(key, path, proto_fs::CREATE | proto_fs::READ_WRITE, 0o600, 0)?;
    super::open_stages::prepared(files, id)?;
    let held = files.open_commit(id)?;
    if files.open_finish(key)? != held {
        return Err(Status::BadSize);
    }
    Ok(held)
}

fn run(files: &Files) -> Result<(), i32> {
    let held = open(files, 1, b"/tmp/data-stages").map_err(|_| 1)?;
    let input = [0x57; proto_fs::MAX_WRITE];
    let write = args(held, 0, DataKind::PWrite, input.len() as u32, 0);
    let (_, job) = files.data_start_once(write).map_err(|_| 2)?;
    if files.data_start_once(write) != Ok((DataPhase::Captured, job)) {
        return Err(3);
    }
    if files.data_ack_once(write.key) != Err(Status::Unknown(proto_fs::INVALID_ARGUMENT)) {
        return Err(4);
    }
    files
        .data_feed_once(job, 0, &input[..proto_fs::FEED_MAX])
        .map_err(|_| 5)?;
    files
        .data_feed_once(job, 0, &input[..proto_fs::FEED_MAX])
        .map_err(|_| 6)?;
    if files.data_feed_once(job, 0, b"mismatch") != Err(Status::Unknown(proto_fs::PERMISSION)) {
        return Err(7);
    }
    files
        .data_feed_once(job, proto_fs::FEED_MAX as u32, &input[proto_fs::FEED_MAX..])
        .map_err(|_| 8)?;
    let outcome = complete(files, job, write).map_err(|_| 9)?;
    if outcome.result != DataResult::Bytes(input.len() as u64)
        || files.data_commit_once(job, write) != Ok(outcome)
        || files.data_query_once(write) != Ok(outcome)
    {
        return Err(10);
    }
    cleanup(files, write.key, true).map_err(|_| 11)?;
    if files.data_query_once(write) != Err(Status::Unknown(proto_fs::OPEN_RETIRED)) {
        return Err(12);
    }

    let read = args(held, 1, DataKind::Read, input.len() as u32, 0);
    let (_, read_job) = files.data_start_once(read).map_err(|_| 13)?;
    let read_outcome = complete(files, read_job, read).map_err(|_| 14)?;
    if read_outcome.result != DataResult::Bytes(input.len() as u64) {
        return Err(15);
    }
    let replacement = args(held, 2, DataKind::PWrite, 3, 0);
    let (_, replacement_job) = files.data_start_once(replacement).map_err(|_| 16)?;
    files
        .data_feed_once(replacement_job, 0, b"new")
        .map_err(|_| 17)?;
    complete(files, replacement_job, replacement).map_err(|_| 18)?;
    cleanup(files, replacement.key, true).map_err(|_| 19)?;
    let mut out = [0; proto_fs::MAX_READ];
    if files
        .data_read_result_once(read.key, input.len(), &mut out)
        .map_err(|_| 20)?
        != input.len()
        || out[..input.len()] != input
        || files.data_commit_once(read_job, read) != Ok(read_outcome)
        || files
            .seek_from(held.fd, 0, proto_fs::SeekFrom::Current)
            .map_err(|_| 21)?
            != input.len() as i64
    {
        return Err(22);
    }
    cleanup(files, read.key, true).map_err(|_| 23)?;

    let shrink = args(held, 3, DataKind::Truncate, 0, 2);
    let (_, shrink_job) = files.data_start_once(shrink).map_err(|_| 24)?;
    let shrink_outcome = complete(files, shrink_job, shrink).map_err(|_| 25)?;
    if shrink_outcome.result != DataResult::Bytes(0) {
        return Err(26);
    }
    let grow = args(held, 4, DataKind::Truncate, 0, input.len() as u64);
    let (_, grow_job) = files.data_start_once(grow).map_err(|_| 27)?;
    complete(files, grow_job, grow).map_err(|_| 28)?;
    cleanup(files, grow.key, true).map_err(|_| 29)?;
    if files.data_commit_once(shrink_job, shrink) != Ok(shrink_outcome)
        || files.descriptor_information(held.fd).map_err(|_| 30)?.size != input.len() as u64
    {
        return Err(31);
    }
    cleanup(files, shrink.key, true).map_err(|_| 32)?;
    let zeros = args(held, 5, DataKind::PRead, input.len() as u32, 0);
    let (_, zeros_job) = files.data_start_once(zeros).map_err(|_| 33)?;
    complete(files, zeros_job, zeros).map_err(|_| 34)?;
    files
        .data_read_result_once(zeros.key, input.len(), &mut out)
        .map_err(|_| 35)?;
    if &out[..2] != b"ne" || out[2..input.len()].iter().any(|&b| b != 0) {
        return Err(36);
    }
    cleanup(files, zeros.key, true).map_err(|_| 37)?;

    let retained = args(held, 6, DataKind::PWrite, 1, 0);
    let (_, retained_job) = files.data_start_once(retained).map_err(|_| 38)?;
    files.close_exact(held).map_err(|_| 39)?;
    let reused = open(files, 2, b"/tmp/data-replacement").map_err(|_| 40)?;
    if reused.fd != held.fd || reused.slot == held.slot {
        return Err(41);
    }
    files
        .data_feed_once(retained_job, 0, b"R")
        .map_err(|_| 42)?;
    complete(files, retained_job, retained).map_err(|_| 43)?;
    if files
        .descriptor_information(reused.fd)
        .map_err(|_| 44)?
        .size
        != 0
    {
        return Err(45);
    }
    cleanup(files, retained.key, true).map_err(|_| 46)?;

    let fence = args(reused, 7, DataKind::PWrite, 1, 0);
    cleanup(files, fence.key, false).map_err(|_| 47)?;
    if files.data_start_once(fence) != Err(Status::Unknown(proto_fs::OPEN_RETIRED)) {
        return Err(48);
    }
    let mut admitted = [0; 16];
    for (i, job) in admitted.iter_mut().enumerate() {
        let request = args(reused, i as u32 + 8, DataKind::PWrite, 1, 0);
        *job = files.data_start_once(request).map_err(|_| 49)?.1;
    }
    let overflow = args(reused, 24, DataKind::PWrite, 1, 0);
    if files.data_start_once(overflow) != Err(Status::Unknown(proto_fs::TOO_MANY_OPEN_FILES)) {
        return Err(50);
    }
    if files.data_start_once(args(reused, 8, DataKind::PWrite, 1, 0))
        != Ok((DataPhase::Captured, admitted[0]))
    {
        return Err(51);
    }
    for slot in 8..24 {
        cleanup(
            files,
            OpenKey {
                slot,
                generation: 1,
            },
            false,
        )
        .map_err(|_| 52)?;
    }
    let (_, job) = files.data_start_once(overflow).map_err(|_| 53)?;
    files.data_feed_once(job, 0, b"X").map_err(|_| 54)?;
    complete(files, job, overflow).map_err(|_| 55)?;
    cleanup(files, overflow.key, true).map_err(|_| 56)?;
    files.close_exact(reused).map_err(|_| 57)?;
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn files_data_stages() -> i32 {
    let Ok(raw) = posix_abi::shared::with_files(|files| Ok(files.sessions().0.raw())) else {
        return 90;
    };
    let original =
        core::mem::ManuallyDrop::new(Files::from_sessions(rt::Handle::from_raw(raw), None));
    let Ok(files) = super::open_stages::clone_bound(&original, &[]) else {
        return 91;
    };
    run(&files).err().unwrap_or(0)
}
