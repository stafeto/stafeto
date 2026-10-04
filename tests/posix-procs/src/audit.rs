// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Real bounded resolver jobs keep their capture across a cleanup-only audit.

use proto_wire::{Header, Reader, Status, Writer};
use rt::fs::Files;
use rt::handle::{Channel, Handle};
use rt::sys;

unsafe extern "C" {
    fn files_loader_abort_sleep() -> i32;
}

fn audit(files: &Files) -> Result<[u64; 3], Status> {
    let reply = sys::send(
        files.sessions().0,
        &Header::new(0xfffb, proto_fs::VERSION).bytes(),
    )
    .map_err(Status::Kernel)?;
    if reply.len != 32 || !reply.handles.is_empty() {
        return Err(Status::BadSize);
    }
    let bytes = rt::abi::inline_bytes(&reply.words);
    let mut reader = Reader::new(&bytes[..32]);
    if reader.u32()? != 0 {
        return Err(Status::BadSize);
    }
    let _purpose = reader.u32()?;
    let result = [reader.u64()?, reader.u64()?, reader.u64()?];
    reader.finish()?;
    Ok(result)
}

fn begin(files: &Files) -> Result<u64, Status> {
    let mut request = Writer::new();
    proto_fs::Method::ResolveStart
        .header()
        .write(&mut request)?;
    request.u32(0)?;
    request.u64(1)?;
    request.u32(0)?;
    request.u32(1)?;
    request.bytes(b"/etc/motd")?;
    let reply = Files::send_on(files.sessions().0, request.as_bytes())?;
    if reply.len != 12 || !reply.handles.is_empty() {
        return Err(Status::BadSize);
    }
    let bytes = rt::abi::inline_bytes(&reply.words);
    let mut reader = Reader::new(&bytes[..12]);
    let status = Status::from_code(reader.u32()?);
    if status != Status::Ok {
        return Err(status);
    }
    let job = reader.u64()?;
    reader.finish()?;
    Ok(job)
}

fn cancel(files: &Files, job: &mut u64) -> Result<(), Status> {
    if *job == 0 {
        return Ok(());
    }
    let mut request = Writer::new();
    proto_fs::Method::ResolveCancel
        .header()
        .write(&mut request)?;
    request.u64(*job)?;
    let reply = sys::send(files.sessions().0, request.as_bytes()).map_err(Status::Kernel)?;
    if reply.len != 8 || reply.words[0] != 0 || !reply.handles.is_empty() {
        return Err(Status::BadSize);
    }
    *job = 0;
    Ok(())
}

fn refused_read(files: &Files, fd: u32) -> Result<(), Status> {
    let mut request = Writer::new();
    proto_fs::Method::Read.header().write(&mut request)?;
    request.u32(fd)?;
    request.u32(1)?;
    let reply = sys::send(files.sessions().0, request.as_bytes()).map_err(Status::Kernel)?;
    if reply.len == 8
        && reply.words[0] == u64::from(proto_fs::TOO_MANY_OPEN_FILES)
        && reply.handles.is_empty()
    {
        Ok(())
    } else {
        Err(Status::BadSize)
    }
}

fn wait_audit(files: &Files, captured: u64) -> Result<(), Status> {
    for _ in 0..500 {
        let [target, audited, retained] = audit(files)?;
        if retained != captured {
            return Err(Status::BadSize);
        }
        if target != 0 && target == audited && target != captured {
            return Ok(());
        }
        // SAFETY: this C helper takes no pointers and returns the real nanosleep result.
        if unsafe { files_loader_abort_sleep() } != 0 {
            return Err(Status::BadSize);
        }
    }
    Err(Status::BadSize)
}

fn run(fd: i32, root_full: bool) -> Result<(), Status> {
    let fd = u32::try_from(fd).map_err(|_| Status::BadSize)?;
    let (raw, descriptor) = posix_abi::shared::with_files(|files| {
        let posix_fs::Target::Ram(descriptor) =
            files.target(fd).map_err(|_| posix_abi::constants::EIO)?
        else {
            return Err(posix_abi::constants::EIO);
        };
        Ok((files.sessions().0.raw(), descriptor))
    })
    .map_err(|_| Status::BadSize)?;
    let identity = posix_abi::process::identity().ok_or(Status::BadSize)?;
    let mut clone = Writer::new();
    proto_fs::Method::Clone.header().write(&mut clone)?;
    clone.u32(1)?;
    clone.u32(descriptor)?;
    let session_count = if root_full { 7 } else { 1 };
    let job_sessions = if root_full { 6 } else { 1 };
    let mut sessions: [Option<Files>; 7] = core::array::from_fn(|_| None);
    for session in &mut sessions[..session_count] {
        let channel = Files::clone_on(&Handle::<Channel>::borrowed(raw), clone.as_bytes())?;
        let files = Files::from_sessions(channel, None);
        files.bind(identity)?;
        *session = Some(files);
    }
    let mut jobs = [[0; 16]; 6];
    let target = sessions[session_count - 1]
        .as_ref()
        .ok_or(Status::BadSize)?;
    let captured = audit(target)?[2];
    let result = (|| {
        for (session, ids) in sessions[..job_sessions].iter().zip(jobs.iter_mut()) {
            let files = session.as_ref().ok_or(Status::BadSize)?;
            for job in ids {
                *job = begin(files)?;
            }
        }
        let before = super::loader_abort::counts(target.sessions().0)?;
        if before[0] != 1
            || before[2] != 0
            || before[3] != 1
            || before[4] != if root_full { 0 } else { 16 }
        {
            return Err(Status::BadSize);
        }
        posix_abi::process::seteuid(65533).map_err(|_| Status::BadSize)?;
        refused_read(target, descriptor)?;
        wait_audit(target, captured)?;
        if super::loader_abort::counts(target.sessions().0)?[..5] != before[..5] {
            return Err(Status::BadSize);
        }
        // The audit cache remains exclusive to maintenance at the full pool.
        refused_read(target, descriptor)?;
        cancel(
            sessions[0].as_ref().ok_or(Status::BadSize)?,
            &mut jobs[0][0],
        )?;
        let mut byte = [0];
        if target.read_at(descriptor, 0, &mut byte)? != 1 || byte != *b"s" {
            return Err(Status::BadSize);
        }
        if audit(target)?[2] == captured {
            return Err(Status::BadSize);
        }
        rt::println!(
            "posix-files: cleanup audit {} jobs preserves retained byte and frontend quota ok",
            job_sessions * 16
        );
        Ok(())
    })();
    for (session, ids) in sessions[..job_sessions].iter().zip(jobs.iter_mut()) {
        if let Some(files) = session {
            for job in ids {
                cancel(files, job)?;
            }
        }
    }
    posix_abi::process::seteuid(0).map_err(|_| Status::BadSize)?;
    for session in sessions.iter().flatten() {
        session.close(descriptor)?;
    }
    result
}

#[unsafe(no_mangle)]
extern "C" fn files_cleanup_audit(fd: i32) -> i32 {
    let result = run(fd, false).and_then(|()| run(fd, true));
    let restored = posix_abi::process::seteuid(0);
    match result {
        Ok(()) if restored.is_ok() => 0,
        Err(error) => {
            rt::println!("posix-files: cleanup audit failed {:?}", error);
            -1
        }
        _ => -1,
    }
}
