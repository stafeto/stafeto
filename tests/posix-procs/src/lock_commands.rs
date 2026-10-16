// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Native lock requests use the supervisor's genuine Bind, Page and Root.

use proto_fs::{LockCommand, LockKind, LockReply, LockStart};
use proto_wire::{Reader, Status, Writer};
use rt::fs::Files;

fn send(files: &Files, wire: LockStart) -> Result<LockReply, Status> {
    let mut request = Writer::new();
    wire.write(&mut request)?;
    let response = loop {
        let response = Files::send_on(files.sessions().0, request.as_bytes())?;
        if response.words[0] as u32 != proto_fs::RESOLVING {
            break response;
        }
        rt::sys::yield_now().map_err(Status::Kernel)?;
    };
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
            description: descriptions[0],
            command: LockCommand::SetPid,
            kind: LockKind::Read,
            whence: 0,
            start: 2,
            length: 7,
            pid: 0,
        };
        let set = send(&files, wire).map_err(|_| -10)?;
        if set.result != 0 || set.blocker.is_some() {
            return Err(-11);
        }
        // The service keeps nothing: the same request gives the same answer.
        if send(&files, wire) != Ok(set) {
            return Err(-14);
        }
        wire.description = descriptions[1];
        wire.command = LockCommand::GetOfd;
        wire.kind = LockKind::Write;
        let conflict = send(&files, wire).map_err(|_| -21)?;
        if !conflict.blocker.is_some_and(|lock| {
            lock.pid == pid && lock.start == 2 && lock.length == 7 && lock.kind == LockKind::Read
        }) {
            return Err(-22);
        }
        if send(&files, wire) != Ok(conflict) {
            return Err(-23);
        }
        wire.command = LockCommand::SetOfd;
        wire.kind = LockKind::Read;
        if send(&files, wire).map_err(|_| -24)?.result != 0 {
            return Err(-25);
        }
        wire.command = LockCommand::GetOfd;
        wire.kind = LockKind::Unlock;
        let unlocked = send(&files, wire).map_err(|_| -27)?;
        if unlocked.result != 0 || unlocked.blocker.is_some() {
            return Err(-28);
        }
        wire.description = descriptions[0];
        wire.command = LockCommand::GetPid;
        wire.kind = LockKind::Write;
        let conflict = send(&files, wire).map_err(|_| -30)?;
        if !conflict
            .blocker
            .is_some_and(|lock| lock.pid == -1 && lock.start == 2 && lock.length == 7)
        {
            return Err(-31);
        }
        wire.command = LockCommand::SetPid;
        wire.kind = LockKind::Unlock;
        if send(&files, wire).map_err(|_| -33)?.result != 0 {
            return Err(-34);
        }
        wire.description = descriptions[1];
        wire.command = LockCommand::SetOfd;
        if send(&files, wire).map_err(|_| -36)?.result != 0 {
            return Err(-37);
        }
        // A description that was closed refuses a late request.
        parent.close_exact(held[1]).map_err(|_| -40)?;
        wire.command = LockCommand::GetOfd;
        wire.kind = LockKind::Write;
        match send(&files, wire) {
            Ok(reply) if reply.result == proto_fs::BAD_FD => {}
            Err(Status::Unknown(proto_fs::BAD_FD)) => {}
            _ => return Err(-41),
        }
        drop(files);
        parent.close_exact(held[0]).map_err(|_| -42)?;
        rt::println!(
            "RAM native locks: genuine PID, OFD conflict, unlocked query, repeat and closed description ok, ticks={}",
            rt::time::now().saturating_sub(began)
        );
        Ok(0)
    })();
    result.unwrap_or_else(|error| error)
}
