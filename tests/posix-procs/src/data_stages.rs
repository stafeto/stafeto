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

fn unread_commit(files: &Files, job: u64, args: DataStart) -> Result<DataOutcome, Status> {
    for _ in 0..3000 {
        match files.data_step_once(job) {
            Ok(()) => {}
            Err(Status::Unknown(proto_fs::RESOLVING)) => continue,
            Err(error) => return Err(error),
        }
        let mut request = proto_wire::Writer::new();
        proto_fs::Method::DataCommit.header().write(&mut request)?;
        request.u64(job)?;
        // A real accepted native response is deliberately left unread.
        drop(rt::sys::send(files.sessions().0, request.as_bytes()).map_err(Status::Kernel)?);
        let outcome = files.data_query_once(args)?;
        if outcome.phase == DataPhase::Completed {
            return Ok(outcome);
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

fn full_mapping(files: &Files) -> Result<(), i32> {
    let held = open(files, 3, b"/tmp/data-full-map").map_err(|_| 60)?;
    for page in 0..2048 {
        let mut request = args(held, 25, DataKind::PWrite, 1, page * 4096);
        request.key.generation = page + 1;
        let (_, job) = files.data_start_once(request).map_err(|_| 61)?;
        files.data_feed_once(job, 0, b"M").map_err(|_| 62)?;
        if complete(files, job, request).map_err(|_| 63)?.result != DataResult::Bytes(1) {
            return Err(64);
        }
        cleanup(files, request.key, true).map_err(|_| 65)?;
    }
    let request = args(held, 26, DataKind::Truncate, 0, 4097);
    let (_, job) = files.data_start_once(request).map_err(|_| 66)?;
    let outcome = complete(files, job, request).map_err(|_| 67)?;
    if outcome.result != DataResult::Bytes(0) || files.data_commit_once(job, request) != Ok(outcome)
    {
        return Err(68);
    }
    cleanup(files, request.key, true).map_err(|_| 69)?;
    if files.descriptor_information(held.fd).map_err(|_| 70)?.size != 4097 {
        return Err(71);
    }
    let extend = args(held, 27, DataKind::Truncate, 0, 8 * 1024 * 1024);
    let (_, job) = files.data_start_once(extend).map_err(|_| 72)?;
    complete(files, job, extend).map_err(|_| 73)?;
    cleanup(files, extend.key, true).map_err(|_| 74)?;
    let read = args(held, 28, DataKind::PRead, 1, 2047 * 4096);
    let (_, job) = files.data_start_once(read).map_err(|_| 75)?;
    if complete(files, job, read).map_err(|_| 76)?.result != DataResult::Bytes(1) {
        return Err(77);
    }
    let mut byte = [9];
    files
        .data_read_result_once(read.key, 1, &mut byte)
        .map_err(|_| 78)?;
    if byte != [0] {
        return Err(79);
    }
    cleanup(files, read.key, true).map_err(|_| 80)?;
    // Only group zero is populated: logical2047 requires all 94 neighbor reads.
    files
        .seek_from(held.fd, 2047 * 4096, proto_fs::SeekFrom::Start)
        .map_err(|_| 114)?;
    if files.write(held.fd, b"L") != Ok(1) {
        return Err(115);
    }
    let sparse = args(held, 29, DataKind::PWrite, 1, 2046 * 4096);
    let (_, job) = files.data_start_once(sparse).map_err(|_| 116)?;
    files.data_feed_once(job, 0, b"S").map_err(|_| 117)?;
    if complete(files, job, sparse).map_err(|_| 118)?.result != DataResult::Bytes(1) {
        return Err(119);
    }
    cleanup(files, sparse.key, true).map_err(|_| 120)?;
    let verify = args(held, 30, DataKind::PRead, 1, 2046 * 4096);
    let (_, job) = files.data_start_once(verify).map_err(|_| 121)?;
    complete(files, job, verify).map_err(|_| 122)?;
    files
        .data_read_result_once(verify.key, 1, &mut byte)
        .map_err(|_| 123)?;
    if byte != *b"S" {
        return Err(124);
    }
    cleanup(files, verify.key, true).map_err(|_| 125)?;
    files.close_exact(held).map_err(|_| 81)?;
    Ok(())
}

#[cfg(feature = "data-carrier-probe")]
pub(super) fn counters(files: &Files) -> Result<([u32; 4], u32), Status> {
    fn query(files: &Files, method: u16, phase: Option<u32>) -> Result<rt::sys::Reply, Status> {
        let mut request = proto_wire::Writer::new();
        proto_wire::Header::new(method, proto_fs::VERSION).write(&mut request)?;
        if let Some(phase) = phase {
            request.u32(phase)?;
        }
        rt::sys::send(files.sessions().0, request.as_bytes()).map_err(Status::Kernel)
    }
    let reply = query(files, 0xfff8, None)?;
    if !reply.handles.is_empty() {
        return Err(Status::BadSize);
    }
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let mut input = proto_wire::Reader::new(reply.bytes(&mut buffer));
    if input.u32()? != 0 {
        return Err(Status::BadSize);
    }
    let mut counts = [0; 4];
    for count in &mut counts {
        *count = input.u32()?;
    }
    input.finish()?;
    let reply = query(files, 0xfffc, Some(3))?;
    if !reply.handles.is_empty() {
        return Err(Status::BadSize);
    }
    let mut input = proto_wire::Reader::new(reply.bytes(&mut buffer));
    if input.u32()? != 0 {
        return Err(Status::BadSize);
    }
    let pages = input.u32()?;
    input.finish()?;
    Ok((counts, pages))
}

#[cfg(feature = "data-carrier-probe")]
fn full_gone(files: &Files, held: PreparedOpen) -> Result<(), i32> {
    // Let preceding closed sessions finish their next periodic binding audit.
    // The temporary timer and channel leave before the resource snapshot.
    {
        let channel = rt::sys::channel_create(1).map_err(|_| 126)?;
        let timer = rt::sys::timer_create(&channel, 30).map_err(|_| 127)?;
        let deadline = rt::time::ticks_to_ns(rt::time::now()) + 1_000_000_000;
        rt::sys::timer_set(&timer, deadline).map_err(|_| 128)?;
        rt::sys::receive(&channel).map_err(|_| 129)?;
    }
    let before = counters(files).map_err(|_| 82)?;
    let child = super::open_stages::clone_bound(files, &[held.fd]).map_err(|_| 83)?;
    let bytes = [5; proto_fs::MAX_WRITE];
    for slot in 0..16 {
        let request = args(
            held,
            slot,
            DataKind::PWrite,
            bytes.len() as u32,
            12287 + slot as u64 * 8192,
        );
        let (_, job) = child.data_start_once(request).map_err(|_| 84)?;
        child
            .data_feed_once(job, 0, &bytes[..proto_fs::FEED_MAX])
            .map_err(|_| 85)?;
        child
            .data_feed_once(job, proto_fs::FEED_MAX as u32, &bytes[proto_fs::FEED_MAX..])
            .map_err(|_| 86)?;
        let mut ready = false;
        for _ in 0..16 {
            match child.data_step_once(job) {
                Ok(()) => {
                    ready = true;
                    break;
                }
                Err(Status::Unknown(proto_fs::RESOLVING)) => {}
                Err(_) => return Err(87),
            }
        }
        if !ready {
            return Err(88);
        }
    }
    let admitted = counters(files).map_err(|_| 89)?;
    if admitted.0 != [before.0[0], before.0[1] + 16, before.0[2] + 16, before.0[3]]
        || admitted.1 != before.1 + 32
    {
        return Err(92);
    }
    drop(child);
    let mut restored = false;
    for _ in 0..4000 {
        if counters(files).map_err(|_| 93)? == before {
            restored = true;
            break;
        }
        rt::sys::yield_now().map_err(|_| 94)?;
    }
    if !restored || files.descriptor_information(held.fd).map_err(|_| 95)?.size != 1 {
        return Err(96);
    }
    Ok(())
}

fn retained_completions(files: &Files, held: PreparedOpen) -> Result<(), i32> {
    let child = super::open_stages::clone_bound(files, &[held.fd]).map_err(|_| 101)?;
    for slot in 0..16 {
        let request = args(held, slot, DataKind::Read, 0, 0);
        let (_, job) = child.data_start_once(request).map_err(|_| 102)?;
        if complete(&child, job, request).map_err(|_| 103)?.result != DataResult::Bytes(0) {
            return Err(104);
        }
        cleanup(&child, request.key, false).map_err(|_| 105)?;
    }
    let extra = args(held, 16, DataKind::Read, 0, 0);
    if child.data_start_once(extra) != Err(Status::Unknown(proto_fs::TOO_MANY_OPEN_FILES)) {
        return Err(106);
    }
    for slot in 0..16 {
        let request = args(held, slot, DataKind::Read, 0, 0);
        let outcome = child.data_query_once(request).map_err(|_| 107)?;
        if outcome.phase != DataPhase::Canceling || outcome.result != DataResult::Bytes(0) {
            return Err(108);
        }
        child
            .data_read_result_once(request.key, 0, &mut [])
            .map_err(|_| 109)?;
        cleanup(&child, request.key, true).map_err(|_| 110)?;
        if child.data_query_once(request) != Err(Status::Unknown(proto_fs::OPEN_RETIRED)) {
            return Err(111);
        }
    }
    child.data_start_once(extra).map_err(|_| 112)?;
    cleanup(&child, extra.key, false).map_err(|_| 113)?;
    Ok(())
}

fn run(files: &Files) -> Result<(), i32> {
    let held = open(files, 1, b"/tmp/data-stages").map_err(|_| 1)?;
    let input = [0x57; proto_fs::MAX_WRITE];
    let write = args(held, 0, DataKind::PWrite, input.len() as u32, 0);
    let (_, job) = files.data_start_once(write).map_err(|_| 2)?;
    if files.data_start_once(write) != Ok((DataPhase::Captured, job)) {
        return Err(3);
    }
    if files.open_cancel(job) != Err(Status::Unknown(proto_fs::PERMISSION))
        || files.open_advance(job, false) != Err(Status::Unknown(proto_fs::PERMISSION))
        || files.open_start(write.key, b"/tmp/data-stages", proto_fs::READ_WRITE, 0, 0)
            != Err(Status::Unknown(proto_fs::PERMISSION))
    {
        return Err(97);
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
    let read_outcome = unread_commit(files, read_job, read).map_err(|_| 14)?;
    if read_outcome.result != DataResult::Bytes(input.len() as u64) {
        return Err(15);
    }
    cleanup(files, read.key, false).map_err(|_| 98)?;
    cleanup(files, read.key, false).map_err(|_| 99)?;
    let canceled_read = DataOutcome {
        phase: DataPhase::Canceling,
        ..read_outcome
    };
    if files.data_query_once(read) != Ok(canceled_read) {
        return Err(100);
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
        || files.data_commit_once(read_job, read) != Ok(canceled_read)
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
    retained_completions(files, reused)?;
    #[cfg(feature = "data-carrier-probe")]
    full_gone(files, reused)?;
    files.close_exact(reused).map_err(|_| 57)?;
    full_mapping(files)?;
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
