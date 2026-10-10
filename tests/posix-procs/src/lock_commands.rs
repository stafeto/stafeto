// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Native lock RPCs use the supervisor's genuine Bind, Page and Root.

use proto_fs::{LockCommand, LockKind, LockPhase, LockReply, LockStart, Method, OpenKey};
use proto_wire::{Reader, Status, Writer};
use rt::fs::Files;

fn send(files: &Files, request: &Writer) -> Result<LockReply, Status> {
    let response = Files::send_on(files.sessions().0, request.as_bytes())?;
    if !response.handles.is_empty() {
        return Err(Status::BadSize);
    }
    let mut bytes = [0; rt::abi::MESSAGE_MAX];
    let body = response.bytes(&mut bytes);
    let code = Reader::new(body).u32()?;
    if code != 0 {
        return Err(Status::from_code(code));
    }
    LockReply::read(Reader::new(body))
}
#[inline(never)]
fn replay_during_bind(files: &Files, wire: LockStart, expected: LockReply) -> Result<(), Status> {
    let identity = posix_abi::process::identity().ok_or(Status::BadSize)?;
    let copy = rt::sys::handle_duplicate(
        identity,
        rt::abi::Rights::NOTIFY | rt::abi::Rights::DUPLICATE | rt::abi::Rights::TRANSFER,
    )
    .map_err(Status::Kernel)?;
    let response = rt::sys::send_handles(
        files.sessions().0,
        &Method::Bind.header().bytes(),
        [copy.erase()],
    )
    .map_err(|error| Status::Kernel(error.error))?;
    if response.words[0] as u32 != proto_fs::RESOLVING || !response.handles.is_empty() {
        return Err(Status::BadSize);
    }
    let mut request = Writer::new();
    wire.write(&mut request)?;
    // Inspect the direct response while the new Bind still has preparation custody.
    let response = rt::sys::send(files.sessions().0, request.as_bytes()).map_err(Status::Kernel)?;
    if !response.handles.is_empty() {
        return Err(Status::BadSize);
    }
    let mut bytes = [0; rt::abi::MESSAGE_MAX];
    let result = LockReply::read(Reader::new(response.bytes(&mut bytes)))?;
    if result != expected {
        return Err(Status::BadSize);
    }
    files.finish_binding()
}

fn release(files: &Files, key: OpenKey) -> Result<(), Status> {
    let mut request = Writer::new();
    proto_fs::write_lock_key(Method::LockRelease, key, &mut request)?;
    for _ in 0..16384 {
        let reply = Files::send_on(files.sessions().0, request.as_bytes())?;
        if !reply.handles.is_empty() {
            return Err(Status::BadSize);
        }
        let mut bytes = [0; rt::abi::MESSAGE_MAX];
        let body = reply.bytes(&mut bytes);
        let code = Reader::new(body).u32()?;
        if code == 0 {
            return Ok(());
        }
        if code != proto_fs::RESOLVING {
            return Err(Status::from_code(code));
        }
        rt::sys::yield_now().map_err(Status::Kernel)?;
    }
    Err(Status::BadSize)
}
fn command(files: &Files, wire: LockStart) -> Result<LockReply, Status> {
    let mut start = Writer::new();
    wire.write(&mut start)?;
    let mut result = loop {
        match send(files, &start) {
            Err(Status::Unknown(proto_fs::RESOLVING)) => {
                rt::sys::yield_now().map_err(Status::Kernel)?;
            }
            result => break result?,
        }
    };
    let mut query = Writer::new();
    proto_fs::write_lock_key(Method::LockQuery, wire.key, &mut query)?;
    for _ in 0..16384 {
        if result.phase == LockPhase::Complete {
            return Ok(result);
        }
        rt::sys::yield_now().map_err(Status::Kernel)?;
        result = send(files, &query)?;
    }
    Err(Status::BadSize)
}

fn custody(files: &Files, pid: i32) -> Result<(u32, u32), Status> {
    let mut request = Writer::new();
    proto_wire::Header::new(0xfff3, proto_fs::VERSION).write(&mut request)?;
    request.u32(pid as u32)?;
    for _ in 0..16384 {
        let reply = Files::send_on(files.sessions().0, request.as_bytes())?;
        if !reply.handles.is_empty() {
            return Err(Status::BadSize);
        }
        let mut bytes = [0; rt::abi::MESSAGE_MAX];
        let mut body = Reader::new(reply.bytes(&mut bytes));
        let code = body.u32()?;
        if matches!(code, proto_fs::RESOLVING | proto_fs::PERMISSION) {
            rt::sys::yield_now().map_err(Status::Kernel)?;
            continue;
        }
        if code != 0 {
            return Err(Status::from_code(code));
        }
        if body.u32()? != 1 {
            return Err(Status::BadSize);
        }
        let quota = body.u64()?;
        let used = body.u64()?;
        if quota.saturating_sub(used) < 128 * 4096 {
            return Err(Status::BadSize);
        }
        let jobs = body.u32()?;
        let places = body.u32()?;
        body.finish()?;
        return Ok((jobs, places));
    }
    Err(Status::BadSize)
}

#[unsafe(no_mangle)]
pub extern "C" fn ram_lock_commands(pid: i32) -> i32 {
    let result = (|| {
        let began = rt::time::now();
        let transport =
            posix_abi::shared::with_files(|files| Ok(files.transport())).map_err(|_| -1)?;
        let parent = transport.files();
        let mut held = [rt::fs::PreparedOpen {
            fd: 0,
            slot: 0,
            generation: 0,
            random: false,
        }; 2];
        for item in &mut held {
            let fd = parent
                .open("/etc/motd", proto_fs::READ_ONLY)
                .map_err(|_| -2)?;
            *item = parent.capture_description(fd).map_err(|_| -3)?.held;
        }
        let baseline = custody(&parent, pid).map_err(|_| -60)?;
        let endpoint = Files::clone_exact_on(parent.sessions().0, &held).map_err(|_| -4)?;
        let files = Files::from_sessions(endpoint, None);
        files
            .bind(posix_abi::process::identity().ok_or(-5)?)
            .map_err(|_| -6)?;
        let descriptions = held.map(|held| proto_fs::DataDescription {
            packed: held.marked_fd(),
            generation: held.generation,
        });
        let mut wire = LockStart {
            key: OpenKey {
                slot: 32,
                generation: 1,
            },
            description: descriptions[0],
            command: LockCommand::SetPid,
            kind: LockKind::Read,
            whence: 0,
            start: 2,
            length: 7,
            pid: 0,
        };
        // Release before Start fences an incoming old generation with no fd effect.
        release(&files, wire.key).map_err(|_| -7)?;
        let mut stale = Writer::new();
        wire.write(&mut stale).map_err(|_| -8)?;
        if send(&files, &stale) != Err(Status::Unknown(proto_fs::OPEN_RETIRED)) {
            return Err(-9);
        }
        wire.key.generation += 1;
        let set = command(&files, wire).map_err(|_| -10)?;
        if set.result != 0 || set.blocker.is_some() {
            return Err(-11);
        }
        replay_during_bind(&files, wire, set).map_err(|_| -68)?;
        // Exact completed replay and another family preserve this Control cell.
        if send(&files, &{
            let mut frame = Writer::new();
            wire.write(&mut frame).map_err(|_| -12)?;
            frame
        })
        .map_err(|_| -13)?
            != set
        {
            return Err(-14);
        }
        let mut wrong = Writer::new();
        Method::ChangeRelease
            .header()
            .write(&mut wrong)
            .map_err(|_| -15)?;
        wrong.u32(wire.key.slot).map_err(|_| -16)?;
        wrong.u64(wire.key.generation + 1).map_err(|_| -17)?;
        let reply = Files::send_on(files.sessions().0, wrong.as_bytes()).map_err(|_| -18)?;
        if reply.words[0] as u32 != proto_fs::PERMISSION {
            return Err(-19);
        }
        release(&files, wire.key).map_err(|_| -20)?;
        // A common family's retained preparation also rejects native takeover.
        let common_key = OpenKey {
            slot: 33,
            generation: 1,
        };
        let mut common = Writer::new();
        Method::ChangeStart
            .header()
            .write(&mut common)
            .map_err(|_| -41)?;
        proto_fs::ChangeStart {
            key: common_key,
            op: proto_fs::ChangeOp::Access,
            flags: 0,
            base: proto_fs::Base::Absolute,
            args: [4, 0, 0, 0],
            path: b"/etc/motd",
        }
        .write(&mut common)
        .map_err(|_| -42)?;
        let response = Files::send_on(files.sessions().0, common.as_bytes()).map_err(|_| -43)?;
        if response.words[0] as u32 != 0 {
            return Err(-44);
        }
        let takeover = LockStart {
            key: OpenKey {
                slot: 33,
                generation: 2,
            },
            command: LockCommand::GetPid,
            ..wire
        };
        let mut frame = Writer::new();
        takeover.write(&mut frame).map_err(|_| -45)?;
        if send(&files, &frame) != Err(Status::Unknown(proto_fs::JOBS_FULL)) {
            return Err(-46);
        }
        let mut wrong = Writer::new();
        proto_fs::write_lock_key(
            Method::LockRelease,
            OpenKey {
                slot: 33,
                generation: 100,
            },
            &mut wrong,
        )
        .map_err(|_| -47)?;
        let response = Files::send_on(files.sessions().0, wrong.as_bytes()).map_err(|_| -48)?;
        if response.words[0] as u32 != proto_fs::PERMISSION {
            return Err(-49);
        }
        let mut frame = Writer::new();
        Method::ChangeRelease
            .header()
            .write(&mut frame)
            .map_err(|_| -50)?;
        frame.u32(common_key.slot).map_err(|_| -51)?;
        frame.u64(common_key.generation).map_err(|_| -52)?;
        let mut released = false;
        for _ in 0..16384 {
            let response = Files::send_on(files.sessions().0, frame.as_bytes()).map_err(|_| -53)?;
            let code = response.words[0] as u32;
            if code == 0 {
                released = true;
                break;
            }
            if code != proto_fs::RESOLVING {
                return Err(-54);
            }
            rt::sys::yield_now().map_err(|_| -55)?;
        }
        if !released {
            return Err(-56);
        }
        if command(&files, takeover).map_err(|_| -57)?.result != 0 {
            return Err(-58);
        }
        release(&files, takeover.key).map_err(|_| -59)?;
        wire.key.generation += 1;
        wire.description = descriptions[1];
        wire.command = LockCommand::GetOfd;
        wire.kind = LockKind::Write;
        let conflict = command(&files, wire).map_err(|_| -21)?;
        if !conflict.blocker.is_some_and(|lock| {
            lock.pid == pid && lock.start == 2 && lock.length == 7 && lock.kind == LockKind::Read
        }) {
            return Err(-22);
        }
        release(&files, wire.key).map_err(|_| -23)?;
        wire.key.generation += 1;
        wire.command = LockCommand::SetOfd;
        wire.kind = LockKind::Read;
        if command(&files, wire).map_err(|_| -24)?.result != 0 {
            return Err(-25);
        }
        release(&files, wire.key).map_err(|_| -26)?;
        wire.key.generation += 1;
        wire.command = LockCommand::GetOfd;
        wire.kind = LockKind::Unlock;
        let unlocked = command(&files, wire).map_err(|_| -27)?;
        if unlocked.result != 0 || unlocked.blocker.is_some() {
            return Err(-28);
        }
        release(&files, wire.key).map_err(|_| -29)?;
        wire.key.generation += 1;
        wire.description = descriptions[0];
        wire.command = LockCommand::GetPid;
        wire.kind = LockKind::Write;
        let conflict = command(&files, wire).map_err(|_| -30)?;
        if !conflict
            .blocker
            .is_some_and(|lock| lock.pid == -1 && lock.start == 2 && lock.length == 7)
        {
            return Err(-31);
        }
        release(&files, wire.key).map_err(|_| -32)?;
        wire.key.generation += 1;
        wire.command = LockCommand::SetPid;
        wire.kind = LockKind::Unlock;
        if command(&files, wire).map_err(|_| -33)?.result != 0 {
            return Err(-34);
        }
        release(&files, wire.key).map_err(|_| -35)?;
        wire.key.generation += 1;
        wire.description = descriptions[1];
        wire.command = LockCommand::SetOfd;
        if command(&files, wire).map_err(|_| -36)?.result != 0 {
            return Err(-37);
        }
        release(&files, wire.key).map_err(|_| -38)?;
        // Completed answers retain all sixteen prepaid cells without active work.
        for slot in 32..48 {
            let wire = LockStart {
                key: OpenKey {
                    slot,
                    generation: 100,
                },
                command: LockCommand::GetOfd,
                kind: LockKind::Write,
                ..wire
            };
            if command(&files, wire).map_err(|_| -61)?.result != 0 {
                return Err(-62);
            }
        }
        if custody(&parent, pid).map_err(|_| -63)? != (baseline.0 + 16, baseline.1 + 1) {
            return Err(-64);
        }
        drop(files);
        // Give own notifications time to return debt with no request to RAM.
        for _ in 0..16384 {
            rt::sys::yield_now().map_err(|_| -65)?;
        }
        if custody(&parent, pid).map_err(|_| -66)? != baseline {
            return Err(-67);
        }
        rt::println!(
            "RAM native lock departure: sixteen held outcomes and genuine paid label return without another RAM request ok, ticks={}",
            rt::time::now().saturating_sub(began)
        );
        for item in held {
            parent.close_exact(item).map_err(|_| -40)?;
        }
        rt::println!(
            "RAM native locks: genuine PID, OFD conflict, unlocked query, replay, cross-family release and late Start fence ok, ticks={}",
            rt::time::now().saturating_sub(began)
        );
        Ok(0)
    })();
    result.unwrap_or_else(|error| error)
}
