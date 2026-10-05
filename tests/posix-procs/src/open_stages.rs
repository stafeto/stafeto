// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Real paid Open stages; the C supervisor observes the returned failure code.
use core::sync::atomic::{AtomicU64, Ordering};
use proto_wire::Status;
use rt::fs::{Files, OpenOutcome, PreparedOpen};
static NEXT: AtomicU64 = AtomicU64::new(1);
fn key() -> proto_fs::OpenKey {
    proto_fs::OpenKey {
        slot: 0,
        generation: NEXT.fetch_add(1, Ordering::Relaxed),
    }
}

fn prepared(files: &Files, id: u64) -> Result<(), Status> {
    for prepare in [false, true] {
        let mut completed = false;
        for _ in 0..2000 {
            if files.open_advance(id, prepare)? {
                completed = true;
                break;
            }
        }
        if !completed {
            return Err(Status::BadSize);
        }
    }
    Ok(())
}
fn committed(
    files: &Files,
    path: &[u8],
    flags: u32,
    mode: u32,
    umask: u32,
) -> Result<(u64, PreparedOpen), Status> {
    let id = files.open_start(key(), path, flags, mode, umask)?;
    let result = prepared(files, id).and_then(|()| files.open_commit(id));
    match result {
        Ok(held) => Ok((id, held)),
        Err(error) => {
            let _ = files.open_cancel(id);
            Err(error)
        }
    }
}
fn raw_start(files: &Files, key: proto_fs::OpenKey) -> Result<rt::sys::Reply, Status> {
    let mut request = proto_wire::Writer::new();
    proto_fs::Method::OpenStart.header().write(&mut request)?;
    request.u32(key.slot)?;
    request.u64(key.generation)?;
    request.u32(0)?;
    request.u64(1)?;
    request.u32(proto_fs::READ_ONLY)?;
    request.u32(0)?;
    request.u32(0)?;
    request.bytes(b"/etc/motd")?;
    rt::sys::send(files.sessions().0, request.as_bytes()).map_err(Status::Kernel)
}
fn active_query(files: &Files, key: proto_fs::OpenKey) -> Result<(u64, u32), Status> {
    match files.open_query(key)? {
        OpenOutcome::Active { job, phase } => Ok((job, phase)),
        OpenOutcome::Finished(_) => Err(Status::BadSize),
    }
}
fn start_recovery(files: &Files) -> Result<(), i32> {
    let first = proto_fs::OpenKey {
        slot: 1,
        generation: 4,
    };
    // The genuine accepted reply goes unread; Query recovers its single paid job.
    drop(raw_start(files, first).map_err(|_| 40)?);
    let (id, phase) = active_query(files, first).map_err(|_| 41)?;
    if phase != 0 || files.open_start(first, b"/etc/motd", proto_fs::READ_ONLY, 0, 0) != Ok(id) {
        return Err(42);
    }
    if files.open_start(first, b"/etc/motd", proto_fs::READ_ONLY, 1, 0)
        != Err(Status::Unknown(proto_fs::PERMISSION))
    {
        return Err(43);
    }
    let mut reply = raw_start(files, first).map_err(|_| 44)?;
    reply.len = 4;
    if Files::open_start_reply(&reply) != Err(Status::BadSize) {
        return Err(45);
    }
    for (len, upper) in [(4, 0), (16, 0), (8, 1)] {
        reply.len = len;
        reply.words[0] = proto_fs::STALE_PROOF as u64 | (upper << 32);
        if Files::open_start_reply(&reply) != Err(Status::BadSize) {
            return Err(46);
        }
    }
    reply.len = 12;
    for bad in [0u64, 127, 384] {
        reply.words[0] = (bad as u32 as u64) << 32;
        reply.words[1] = bad >> 32;
        if Files::open_start_reply(&reply) != Err(Status::BadSize) {
            return Err(67);
        }
    }
    reply.len = 16;
    for (fd, generation) in [(2u32, 1), (35, 1), (3, 0)] {
        reply.words[0] = (fd as u64) << 32;
        reply.words[1] = generation;
        if Files::open_commit_reply(&reply) != Err(Status::BadSize) {
            return Err(68);
        }
    }
    for fd in [3u32, 32, 34] {
        reply.words[0] = (fd as u64) << 32;
        reply.words[1] = 1;
        if Files::open_commit_reply(&reply)
            != Ok(PreparedOpen {
                fd,
                slot: 0,
                generation: 1,
                random: false,
            })
        {
            return Err(69);
        }
    }
    // Corrupt accepted success replies retain ambiguous recovery semantics.
    for marked in [
        proto_fs::OPEN_RANDOM | 3,
        proto_fs::OPEN_RANDOM | 34 | (127 << proto_fs::OPEN_DESCRIPTION_SHIFT),
    ] {
        reply.len = 16;
        reply.words[0] = (marked as u64) << 32;
        reply.words[1] = 1;
        let expected = PreparedOpen {
            fd: marked & proto_fs::OPEN_FD_MASK,
            slot: (marked & proto_fs::OPEN_DESCRIPTION_MASK) >> proto_fs::OPEN_DESCRIPTION_SHIFT,
            generation: 1,
            random: true,
        };
        if Files::open_commit_reply(&reply) != Ok(expected) {
            return Err(105);
        }
        reply.len = 32;
        reply.words[0] = 5u64 << 32;
        reply.words[1] = 0;
        reply.words[2] = marked as u64;
        reply.words[3] = 1;
        if Files::open_query_reply(&reply) != Ok(OpenOutcome::Finished(expected)) {
            return Err(106);
        }
    }
    for marked in [
        proto_fs::OPEN_RANDOM | 2,
        proto_fs::OPEN_RANDOM | 35,
        (1u32 << 30) | 3,
        (1u32 << 6) | 3,
        (1u32 << 7) | 3,
        (1u32 << 15) | 3,
    ] {
        reply.len = 16;
        reply.words[0] = (marked as u64) << 32;
        reply.words[1] = 1;
        if Files::open_commit_reply(&reply) != Err(Status::BadSize) {
            return Err(107);
        }
        reply.len = 32;
        reply.words[0] = 5u64 << 32;
        reply.words[1] = 0;
        reply.words[2] = marked as u64;
        reply.words[3] = 1;
        if Files::open_query_reply(&reply) != Err(Status::BadSize) {
            return Err(108);
        }
    }
    reply.len = 20;
    reply.words[0] =
        ((proto_fs::OPEN_RANDOM | (127 << proto_fs::OPEN_DESCRIPTION_SHIFT) | 34) as u64) << 32;
    reply.words[1] = 1;
    reply.words[2] = proto_fs::WRITE_ONLY as u64;
    let capture = Files::capture_description_reply(&reply).map_err(|_| 129)?;
    if capture.held.slot != 127
        || capture.held.fd != 34
        || !capture.held.random
        || capture.flags != proto_fs::WRITE_ONLY
    {
        return Err(130);
    }
    for flags in [3u32, 1 << 20] {
        reply.words[2] = flags as u64;
        if Files::capture_description_reply(&reply) != Err(Status::BadSize) {
            return Err(131);
        }
    }
    reply.len = 8;
    for (outcome, expected) in [
        (0, Ok(rt::fs::CloseOutcome::Closed)),
        (1, Ok(rt::fs::CloseOutcome::AlreadyGone)),
        (2, Err(Status::BadSize)),
    ] {
        reply.words[0] = outcome << 32;
        if Files::close_exact_reply(&reply) != expected {
            return Err(132);
        }
    }
    if active_query(files, first) != Ok((id, 0)) {
        return Err(47);
    }
    let second = proto_fs::OpenKey {
        slot: 2,
        generation: 2,
    };
    let third = proto_fs::OpenKey {
        slot: 3,
        generation: 1,
    };
    let second_id = files
        .open_start(second, b"/etc/motd", proto_fs::READ_ONLY, 0, 0)
        .map_err(|_| 48)?;
    let third_id = files
        .open_start(third, b"/etc/motd", proto_fs::READ_ONLY, 0, 0)
        .map_err(|_| 49)?;
    if second_id == third_id {
        return Err(50);
    }
    // All sixteen preparations are actual jobs. Duplicate Start needs no extra charge.
    let mut keys = [first; 16];
    keys[1] = second;
    keys[2] = third;
    for (i, key) in keys.iter_mut().enumerate().skip(3) {
        *key = proto_fs::OpenKey {
            slot: i as u32 + 1,
            generation: 1,
        };
        files
            .open_start(*key, b"/etc/motd", proto_fs::READ_ONLY, 0, 0)
            .map_err(|_| 51)?;
    }
    if files.open_start(first, b"/etc/motd", proto_fs::READ_ONLY, 0, 0) != Ok(id) {
        return Err(52);
    }
    let extra = proto_fs::OpenKey {
        slot: 17,
        generation: 1,
    };
    if files.open_start(extra, b"/etc/motd", proto_fs::READ_ONLY, 0, 0)
        != Err(Status::Unknown(proto_fs::TOO_MANY_OPEN_FILES))
    {
        return Err(53);
    }
    // A refused admission retains the key for a later attempt after exact cleanup.
    files.open_cancel_key(first).map_err(|_| 54)?;
    let extra_id = files
        .open_start(extra, b"/etc/motd", proto_fs::READ_ONLY, 0, 0)
        .map_err(|_| 55)?;
    if active_query(files, extra) != Ok((extra_id, 0)) {
        return Err(56);
    }
    for key in keys {
        files.open_cancel_key(key).map_err(|_| 57)?;
    }
    files.open_cancel_key(extra).map_err(|_| 58)?;
    if files.open_start(first, b"/etc/motd", proto_fs::READ_ONLY, 0, 0)
        != Err(Status::Unknown(proto_fs::OPEN_RETIRED))
    {
        return Err(59);
    }
    // Cancel installs a fence before its ACK, so a delayed Start cannot appear later.
    let canceled = proto_fs::OpenKey {
        slot: 30,
        generation: 12,
    };
    files.open_cancel_key(canceled).map_err(|_| 60)?;
    if files.open_start(canceled, b"/etc/motd", proto_fs::READ_ONLY, 0, 0)
        != Err(Status::Unknown(proto_fs::OPEN_RETIRED))
    {
        return Err(61);
    }
    let last = proto_fs::OpenKey {
        slot: 31,
        generation: u64::MAX,
    };
    files
        .open_start(last, b"/etc/motd", proto_fs::READ_ONLY, 0, 0)
        .map_err(|_| 62)?;
    files.open_cancel_key(last).map_err(|_| 63)?;
    if files.open_start(last, b"/etc/motd", proto_fs::READ_ONLY, 0, 0)
        != Err(Status::Unknown(proto_fs::OPEN_RETIRED))
    {
        return Err(64);
    }
    Ok(())
}
fn clone_bound(files: &Files, numbers: &[u32]) -> Result<Files, Status> {
    let mut request = proto_wire::Writer::new();
    proto_fs::Method::Clone.header().write(&mut request)?;
    request.u32(numbers.len() as u32)?;
    for fd in numbers {
        request.u32(*fd)?;
    }
    let channel = Files::clone_on(files.sessions().0, request.as_bytes())?;
    let cloned = Files::from_sessions(channel, None);
    cloned.bind(posix_abi::process::identity().ok_or(Status::BadSize)?)?;
    Ok(cloned)
}
fn random_marker(files: &Files) -> Result<(), i32> {
    let files = clone_bound(files, &[]).map_err(|_| 110)?;
    let mut held = [PreparedOpen {
        fd: 0,
        slot: 0,
        generation: 0,
        random: false,
    }; 32];
    for (slot, result) in held.iter_mut().enumerate() {
        let key = proto_fs::OpenKey {
            slot: slot as u32,
            generation: 1,
        };
        let id = files
            .open_start(key, b"/dev/urandom", proto_fs::READ_WRITE, 0, 0)
            .map_err(|_| 111)?;
        prepared(&files, id).map_err(|_| 112)?;
        *result = files.open_commit(id).map_err(|_| 113)?;
        if result.fd != slot as u32 + 3 || !result.random {
            return Err(114);
        }
        if files.open_commit(id) != Ok(*result)
            || files.open_finish(key) != Ok(*result)
            || files.open_query(key) != Ok(OpenOutcome::Finished(*result))
        {
            return Err(115);
        }
    }
    let numbers = core::array::from_fn::<_, 32, _>(|slot| slot as u32 + 3);
    let child_channel = Files::clone_exact_on(files.sessions().0, &held).map_err(|_| 116)?;
    let child = Files::from_sessions(child_channel, None);
    child
        .bind(posix_abi::process::identity().ok_or(116)?)
        .map_err(|_| 116)?;
    let mut invalid = held;
    invalid[31].generation += 1;
    if Files::clone_exact_on(files.sessions().0, &invalid).err()
        != Some(Status::Unknown(proto_fs::STALE_PROOF))
    {
        return Err(137);
    }
    let mut corrupted = proto_wire::Writer::new();
    proto_fs::Method::CloneExact
        .header()
        .write(&mut corrupted)
        .map_err(|_| 138)?;
    corrupted
        .u32(1)
        .and_then(|()| corrupted.u32(held[0].marked_fd()))
        .and_then(|()| corrupted.u64(held[0].generation))
        .map_err(|_| 138)?;
    let refused = rt::sys::send(files.sessions().0, corrupted.as_bytes()).map_err(|_| 138)?;
    if refused.len != 8
        || refused.words[0] != proto_wire::BAD_SIZE as u64
        || !refused.handles.is_empty()
    {
        return Err(139);
    }
    for method in [proto_fs::Method::Clone, proto_fs::Method::CloneExact] {
        let mut missing_count = proto_wire::Writer::new();
        method.header().write(&mut missing_count).map_err(|_| 150)?;
        let refused =
            rt::sys::send(files.sessions().0, missing_count.as_bytes()).map_err(|_| 150)?;
        if refused.len != 8
            || refused.words[0] != proto_wire::BAD_SIZE as u64
            || !refused.handles.is_empty()
        {
            return Err(151);
        }
    }
    let capture = files.capture_description(34).map_err(|_| 133)?;
    if capture.held != held[31] || capture.flags != proto_fs::READ_WRITE {
        return Err(134);
    }
    files.close(held[0].fd).map_err(|_| 117)?;
    let old = proto_fs::OpenKey {
        slot: 0,
        generation: 1,
    };
    let new = proto_fs::OpenKey {
        slot: 0,
        generation: 2,
    };
    let id = files
        .open_start(new, b"/etc/motd", proto_fs::READ_ONLY, 0, 0)
        .map_err(|_| 118)?;
    prepared(&files, id).map_err(|_| 119)?;
    let regular = files.open_commit(id).map_err(|_| 120)?;
    if regular.fd != held[0].fd || regular.random || regular.slot == held[0].slot {
        return Err(121);
    }
    if files.open_finish(new) != Ok(regular)
        || files.open_query(old) != Err(Status::Unknown(proto_fs::OPEN_RETIRED))
    {
        return Err(122);
    }
    if files.close_exact(held[0]) != Ok(rt::fs::CloseOutcome::AlreadyGone) {
        return Err(135);
    }
    if Files::clone_exact_on(files.sessions().0, &held[..1]).err()
        != Some(Status::Unknown(proto_fs::STALE_PROOF))
    {
        return Err(136);
    }
    files.open_cancel_key(old).map_err(|_| 123)?;
    if files.open_query(new) != Ok(OpenOutcome::Finished(regular)) {
        return Err(124);
    }
    let writable_channel = Files::clone_exact_on(files.sessions().0, &[]).map_err(|_| 140)?;
    let writable = Files::from_sessions(writable_channel, None);
    writable
        .bind(posix_abi::process::identity().ok_or(140)?)
        .map_err(|_| 140)?;
    let key = proto_fs::OpenKey {
        slot: 0,
        generation: 1,
    };
    let job = writable
        .open_start(key, b"/dev/urandom", proto_fs::WRITE_ONLY, 0, 0)
        .map_err(|_| 141)?;
    prepared(&writable, job).map_err(|_| 142)?;
    let write_only = writable.open_commit(job).map_err(|_| 143)?;
    writable.open_finish(key).map_err(|_| 143)?;
    let capture = writable
        .capture_description(write_only.fd)
        .map_err(|_| 144)?;
    if capture.held != write_only || !capture.held.random || capture.flags != proto_fs::WRITE_ONLY {
        return Err(145);
    }
    let alias_channel =
        Files::clone_exact_on(writable.sessions().0, &[write_only]).map_err(|_| 146)?;
    let alias = Files::from_sessions(alias_channel, None);
    alias
        .bind(posix_abi::process::identity().ok_or(146)?)
        .map_err(|_| 146)?;
    if alias.capture_description(write_only.fd) != Ok(capture)
        || alias.read(write_only.fd, &mut [0]) != Err(Status::Unknown(proto_fs::BAD_FD))
    {
        return Err(147);
    }
    if alias.close_exact(write_only) != Ok(rt::fs::CloseOutcome::Closed)
        || alias.close_exact(write_only) != Ok(rt::fs::CloseOutcome::AlreadyGone)
    {
        return Err(148);
    }
    writable.close_exact(write_only).map_err(|_| 149)?;
    let mut byte = [0];
    if files.read(regular.fd, &mut byte) != Ok(1) {
        return Err(125);
    }
    for fd in numbers {
        if child.read(fd, &mut byte) != Err(Status::Unknown(proto_fs::INVALID_ARGUMENT)) {
            return Err(126);
        }
        child.close(fd).map_err(|_| 127)?;
        files.close(fd).map_err(|_| 128)?;
    }
    rt::println!("posix-files: Random marker full32 Clone and reuse ok");
    Ok(())
}
fn run(files: &Files) -> Result<(), i32> {
    start_recovery(files)?;
    random_marker(files)?;
    let flags = proto_fs::CREATE | proto_fs::EXCLUSIVE | proto_fs::READ_WRITE;
    let (id, held) = committed(files, b"/tmp/t3-created", flags, 0o666, 0o077).map_err(|_| 1)?;
    let result = (|| {
        if files.read(held.fd, &mut [0]) != Err(Status::Unknown(proto_fs::BAD_FD)) {
            return Err(2);
        }
        if files.open_commit(id) != Ok(held) {
            return Err(3);
        }
        let info = files.node_information("/tmp/t3-created").map_err(|_| 4)?;
        if info.permissions != 0o600 || info.size != 0 || info.uid != 0 {
            return Err(5);
        }
        // Write through a separate ordinary descriptor after the first CREATE effect.
        let fd = files
            .open("/tmp/t3-created", proto_fs::READ_WRITE)
            .map_err(|_| 6)?;
        let write = files.write(fd, b"created once");
        files.close(fd).map_err(|_| 7)?;
        if write != Ok(12) || files.open_commit(id) != Ok(held) {
            return Err(8);
        }
        Ok(())
    })();
    let current_key = proto_fs::OpenKey {
        slot: 0,
        generation: 1,
    };
    posix_abi::process::seteuid(65533).map_err(|_| 65)?;
    let query = active_query(files, current_key);
    let changed = files.open_commit(id);
    let restored = posix_abi::process::seteuid(0);
    if query != Ok((id, 3))
        || changed != Err(Status::Unknown(proto_fs::OPEN_RETIRED))
        || restored.is_err()
    {
        return Err(66);
    }
    files.open_cancel(id).map_err(|_| 9)?;
    result?;
    // Repeated cancellation and a late Commit cannot create another operation.
    files.open_cancel(id).map_err(|_| 10)?;
    if files.open_commit(id) != Err(Status::Unknown(proto_fs::STALE_PROOF)) {
        return Err(11);
    }
    let exclusive = files
        .open_start(key(), b"/tmp/t3-created", flags, 0o777, 0)
        .map_err(|_| 12)?;
    let exists = prepared(files, exclusive);
    files.open_cancel(exclusive).map_err(|_| 14)?;
    if exists != Err(Status::Unknown(proto_fs::ALREADY_EXISTS)) {
        return Err(15);
    }
    let (zero, _) = committed(files, b"/tmp/t3-mode-zero", flags, 0, 0).map_err(|_| 16)?;
    files.open_cancel(zero).map_err(|_| 17)?;
    if files
        .node_information("/tmp/t3-mode-zero")
        .map_err(|_| 18)?
        .permissions
        != 0
    {
        return Err(19);
    }
    // The TRUNC effect clears set-ID and a retry preserves subsequently written data.
    let (initial, _) = committed(files, b"/tmp/t3-truncate", flags, 0o6600, 0).map_err(|_| 20)?;
    files.open_cancel(initial).map_err(|_| 21)?;
    let (truncate, held) = committed(
        files,
        b"/tmp/t3-truncate",
        proto_fs::TRUNCATE | proto_fs::READ_WRITE,
        0,
        0,
    )
    .map_err(|_| 22)?;
    let result = (|| {
        if files
            .node_information("/tmp/t3-truncate")
            .map_err(|_| 23)?
            .permissions
            != 0o600
        {
            return Err(24);
        }
        let fd = files
            .open("/tmp/t3-truncate", proto_fs::READ_WRITE)
            .map_err(|_| 25)?;
        let write = files.write(fd, b"new after truncate");
        files.close(fd).map_err(|_| 26)?;
        if write != Ok(18) {
            return Err(27);
        }
        let before = files.node_information("/tmp/t3-truncate").map_err(|_| 28)?;
        if files.open_commit(truncate) != Ok(held) {
            return Err(29);
        }
        let after = files.node_information("/tmp/t3-truncate").map_err(|_| 30)?;
        if before != after {
            return Err(31);
        }
        let fd = files
            .open("/tmp/t3-truncate", proto_fs::READ_ONLY)
            .map_err(|_| 32)?;
        let mut bytes = [0; 18];
        let read = files.read(fd, &mut bytes);
        files.close(fd).map_err(|_| 33)?;
        if read != Ok(18) || &bytes != b"new after truncate" {
            return Err(34);
        }
        Ok(())
    })();
    files.open_cancel(truncate).map_err(|_| 35)?;
    result?;
    finish_recovery(files)
}
fn raw_key_request(
    files: &Files,
    method: proto_fs::Method,
    key: proto_fs::OpenKey,
) -> Result<rt::sys::Reply, Status> {
    let mut w = proto_wire::Writer::new();
    method.header().write(&mut w)?;
    w.u32(key.slot)?;
    w.u64(key.generation)?;
    rt::sys::send(files.sessions().0, w.as_bytes()).map_err(Status::Kernel)
}
fn finish_recovery(files: &Files) -> Result<(), i32> {
    let first = proto_fs::OpenKey {
        slot: 20,
        generation: 1,
    };
    let path = b"/tmp/t3-created";
    let flags = proto_fs::READ_WRITE | proto_fs::TRUNCATE;
    let id = files.open_start(first, path, flags, 0, 0).map_err(|_| 70)?;
    prepared(files, id).map_err(|_| 71)?;
    if files.open_finish(first) != Err(Status::Unknown(proto_fs::RESOLVING)) {
        return Err(72);
    }
    let held = files.open_commit(id).map_err(|_| 73)?;
    let ordinary = files
        .open("/tmp/t3-created", proto_fs::READ_WRITE)
        .map_err(|_| 74)?;
    if files.write(ordinary, b"finish once") != Ok(11) {
        return Err(75);
    }
    files.close(ordinary).map_err(|_| 76)?;
    let before = files.node_information("/tmp/t3-created").map_err(|_| 77)?;
    // An actual accepted Finish reply is consumed without decoding or saving its result.
    drop(raw_key_request(files, proto_fs::Method::OpenFinish, first).map_err(|_| 78)?);
    if files.open_query(first) != Ok(OpenOutcome::Finished(held))
        || files.open_finish(first) != Ok(held)
    {
        return Err(79);
    }
    if files.node_information("/tmp/t3-created").map_err(|_| 80)? != before {
        return Err(81);
    }
    posix_abi::process::seteuid(65533).map_err(|_| 82)?;
    let recovered = files.open_query(first);
    let finished = files.open_finish(first);
    let restored = posix_abi::process::seteuid(0);
    if recovered != Ok(OpenOutcome::Finished(held)) || finished != Ok(held) || restored.is_err() {
        return Err(83);
    }
    let mut reply = raw_key_request(files, proto_fs::Method::OpenQuery, first).map_err(|_| 84)?;
    for (len, phase, job, fd, padding, generation) in [
        (16, 5, 0, held.fd, 0, held.generation),
        (32, 5, id, held.fd, 0, held.generation),
        (32, 5, 0, held.fd, 1, held.generation),
        (32, 5, 0, 35, 0, held.generation),
        (32, 5, 0, held.fd, 0, 0),
        (32, 0, 0, held.fd, 0, held.generation),
    ] {
        reply.len = len;
        reply.words[0] = phase << 32;
        reply.words[1] = job;
        reply.words[2] = fd as u64 | (padding << 32);
        reply.words[3] = generation;
        if Files::open_query_reply(&reply) != Err(Status::BadSize) {
            return Err(85);
        }
    }
    let mut bytes = [0; 11];
    if files.read(held.fd, &mut bytes) != Ok(11) || &bytes != b"finish once" {
        return Err(86);
    }
    files.close(held.fd).map_err(|_| 87)?;
    let fresh = files
        .open("/tmp/t3-created", proto_fs::READ_WRITE)
        .map_err(|_| 88)?;
    if fresh != held.fd {
        return Err(89);
    }
    if files.open_query(first) != Err(Status::Unknown(proto_fs::OPEN_RETIRED))
        || files.open_finish(first) != Err(Status::Unknown(proto_fs::OPEN_RETIRED))
    {
        return Err(91);
    }
    files.open_cancel_key(first).map_err(|_| 92)?;
    if files.read(fresh, &mut bytes) != Ok(11) || &bytes != b"finish once" {
        return Err(93);
    }
    files.close(fresh).map_err(|_| 94)?;
    let second = proto_fs::OpenKey {
        slot: first.slot,
        generation: 2,
    };
    let next_id = files
        .open_start(second, path, flags, 0, 0)
        .map_err(|_| 95)?;
    prepared(files, next_id).map_err(|_| 96)?;
    let next = files.open_commit(next_id).map_err(|_| 97)?;
    if next.fd != held.fd || next.generation == held.generation {
        return Err(98);
    }
    if files.open_finish(second) != Ok(next) {
        return Err(99);
    }
    files.open_cancel_key(first).map_err(|_| 100)?;
    if files.open_query(second) != Ok(OpenOutcome::Finished(next)) {
        return Err(101);
    }
    files.open_cancel_key(second).map_err(|_| 102)?;
    files.open_cancel_key(second).map_err(|_| 103)?;
    if files.open_query(second) != Err(Status::Unknown(proto_fs::OPEN_RETIRED)) {
        return Err(104);
    }
    rt::println!("posix-files: exact Finish receipts ok");
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn files_open_stages() -> i32 {
    let Ok(raw) = posix_abi::shared::with_files(|files| Ok(files.sessions().0.raw())) else {
        return 90;
    };
    let files = core::mem::ManuallyDrop::new(Files::from_sessions(rt::Handle::from_raw(raw), None));
    // The native suite owns independent keys on its fresh genuinely bound session.
    // Local Table records retain their own client-key namespace in the shared session.
    let Ok(files) = clone_bound(&files, &[]) else {
        return 91;
    };
    let result = run(&files);
    #[cfg(feature = "ipc-loss")]
    let result = result.and_then(|()| super::reply_loss::run(&files));
    result.err().unwrap_or(0)
}
