// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Retained capabilities observe genuine Take and an accepted ambiguous SetId.
use proto_wire::{Header, Reader, Status, Writer};
use rt::abi::{ObjectKind, Rights};
use rt::fs::Files;
use rt::handle::{Channel, Handle};
use rt::sys;

fn process() -> &'static Handle<Channel> {
    posix_abi::process::client().session()
}
fn canonical(reply: &sys::Reply) -> Result<(), Status> {
    if reply.len == 8 && reply.words[0] == 0 && reply.handles.is_empty() {
        Ok(())
    } else {
        Err(Status::BadSize)
    }
}
fn process_method(method: proto_process::Method, pid: Option<u32>) -> Result<(), Status> {
    let mut w = Writer::new();
    method.header().write(&mut w)?;
    if let Some(pid) = pid {
        w.u32(pid)?;
    }
    canonical(&sys::send(process(), w.as_bytes()).map_err(Status::Kernel)?)
}
struct Attempt {
    loader: Handle<Channel>,
    child: Option<u32>,
    active: bool,
}
impl Attempt {
    fn start(exec: bool) -> Result<Self, Status> {
        let mut w = Writer::new();
        let method = if exec {
            proto_process::Method::ExecStart
        } else {
            proto_process::Method::SpawnStart
        };
        method.header().write(&mut w)?;
        proto_process::SpawnStart {
            flags: 0,
            pgroup: 0,
            level: 1,
            mask: 0,
            default: 0,
        }
        .write(&mut w)?;
        let mut reply = sys::send(process(), w.as_bytes()).map_err(Status::Kernel)?;
        if reply.len != 8
            || reply.words[0] as u32 != 0
            || reply.handles.len() != 1
            || reply.handles.info(0) != Some((ObjectKind::Channel, Rights::SEND | Rights::TRANSFER))
        {
            return Err(Status::BadSize);
        }
        let pid = (reply.words[0] >> 32) as u32;
        let loader = reply.handles.take::<Channel>(0).map_err(Status::Kernel)?;
        Ok(Self {
            loader,
            child: if exec { None } else { Some(pid) },
            active: true,
        })
    }
    fn abort(&mut self) -> Result<(), Status> {
        if let Some(pid) = self.child {
            // Kill remains valid after Commit; SpawnAbort covers an unfinished load.
            let aborted = process_method(proto_process::Method::SpawnAbort, Some(pid));
            rt::println!(
                "posix-files: image abort SpawnAbort pid {} status {}",
                pid,
                aborted.map_or_else(|error| error.code(), |()| 0)
            );
            posix_abi::process::kill(pid as i32, proto_process::SIGKILL as i32).map_err(
                |errno| {
                    rt::println!("posix-files: image abort Kill pid {} errno {}", pid, errno);
                    Status::BadSize
                },
            )?;
            rt::println!("posix-files: image abort Kill pid {} ok", pid);
            let waited = posix_abi::process::waitpid(pid as i32, 0).map_err(|errno| {
                rt::println!(
                    "posix-files: image abort WaitPid pid {} errno {}",
                    pid,
                    errno
                );
                Status::BadSize
            })?;
            rt::println!(
                "posix-files: image abort WaitPid expected {} observed {}",
                pid,
                waited.pid
            );
            if waited.pid != pid as i32 {
                return Err(Status::BadSize);
            }
        } else {
            process_method(proto_process::Method::ExecAbort, None)?;
        }
        self.active = false;
        Ok(())
    }
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if self.active {
            let _ = self.abort();
        }
    }
}
fn capture(attempt: &Attempt, fd: i32) -> Result<Handle<Channel>, Status> {
    let (raw, fd) = posix_abi::shared::with_files(|files| {
        let fd = match files.target(fd as u32) {
            Ok(posix_fs::Target::Ram(fd)) => fd,
            _ => return Err(posix_abi::constants::EIO),
        };
        Ok((files.sessions().0.raw(), fd))
    })
    .map_err(|_| Status::BadSize)?;
    let mut w = Writer::new();
    proto_fs::Method::Clone.header().write(&mut w)?;
    w.u32(1)?;
    w.u32(fd.fd())?;
    let offered = Files::clone_on(&Handle::<Channel>::borrowed(raw), w.as_bytes())?;
    let mut reply = sys::send_handles(
        &attempt.loader,
        &Header::new(0xfffc, proto_loader::VERSION).bytes(),
        [offered.erase()],
    )
    .map_err(|refused| Status::Kernel(refused.error))?;
    if reply.len != 8
        || reply.words[0] != 0
        || reply.handles.len() != 1
        || reply.handles.info(0) != Some((ObjectKind::Channel, Rights::SEND | Rights::TRANSFER))
    {
        return Err(Status::BadSize);
    }
    reply.handles.take::<Channel>(0).map_err(Status::Kernel)
}
#[cfg(not(feature = "image-gates-normal"))]
fn image_snapshot(image: &Handle<Channel>) -> Result<[u64; 10], Status> {
    let reply = Files::send_on(image, &Header::new(0xfff9, proto_fs::VERSION).bytes())?;
    if reply.len != 80 || !reply.handles.is_empty() {
        return Err(Status::BadSize);
    }
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let mut r = Reader::new(reply.bytes(&mut buffer));
    let mut words = [0; 10];
    for word in &mut words {
        *word = r.u64()?;
    }
    r.finish()?;
    if words[0] != 0 || words[8] >> 32 != 0 {
        return Err(Status::BadSize);
    }
    Ok(words)
}
#[cfg(not(feature = "image-gates-normal"))]
struct Mapped {
    memory: Handle<rt::handle::Memory>,
}
#[cfg(not(feature = "image-gates-normal"))]
impl Mapped {
    const ADDRESS: usize = 0x59_0000_0000;
    fn new() -> Result<Self, Status> {
        let memory = sys::mem_create(4096).map_err(Status::Kernel)?;
        sys::mem_map(
            posix_abi::allocation::process(),
            &memory,
            0,
            4096,
            Self::ADDRESS,
            rt::abi::Access::ReadWrite,
        )
        .map_err(Status::Kernel)?;
        Ok(Self { memory })
    }
    fn read_elf(&self, image: &Handle<Channel>) -> Result<(), Status> {
        // SAFETY: the single-threaded probe exclusively owns this writable page.
        unsafe {
            core::ptr::write_bytes(Self::ADDRESS as *mut u8, 0, 4);
        }
        let mut w = Writer::new();
        proto_fs::Method::ReadInto.header().write(&mut w)?;
        w.u32(0)?;
        w.u64(0)?;
        w.u32(4)?;
        w.u64(0)?;
        loop {
            let copy = sys::handle_duplicate(
                &self.memory,
                Rights::MAP_READ | Rights::MAP_WRITE | Rights::TRANSFER,
            )
            .map_err(Status::Kernel)?;
            let reply = sys::send_handles(image, w.as_bytes(), [copy.erase()])
                .map_err(|refused| Status::Kernel(refused.error))?;
            if reply.len != 8 || !reply.handles.is_empty() {
                return Err(Status::BadSize);
            }
            if reply.words[0] == u64::from(proto_fs::AUTHENTICATING) {
                Files::finish_on(image)?;
                continue;
            }
            if reply.words[0] != 4 << 32 {
                return Err(Status::BadSize);
            }
            // SAFETY: service writes completed before reply and the mapping remains owned.
            let bytes = unsafe { core::slice::from_raw_parts(Self::ADDRESS as *const u8, 4) };
            return if bytes == b"\x7fELF" {
                Ok(())
            } else {
                Err(Status::BadSize)
            };
        }
    }
}
#[cfg(not(feature = "image-gates-normal"))]
impl Drop for Mapped {
    fn drop(&mut self) {
        // SAFETY: this mapping is owned solely by the fixture and no access follows Drop.
        let _ = unsafe { sys::mem_unmap(posix_abi::allocation::process(), Self::ADDRESS, 4096) };
    }
}
#[cfg(not(feature = "image-gates-normal"))]
fn take(fd: i32) -> Result<(), Status> {
    let mut attempt = Attempt::start(false)?;
    let pending = capture(&attempt, fd)?;
    let images = super::image_hold::capture(&pending)?;
    let before = image_snapshot(&images.handles[0])?;
    if before[2] >> 32 != 0 {
        return Err(Status::BadSize);
    }
    let observer = sys::channel_create(1).map_err(Status::Kernel)?;
    let copy = sys::handle_duplicate(&observer, Rights::NOTIFY | Rights::TRANSFER)
        .map_err(Status::Kernel)?;
    let reply = sys::send_handles(
        &attempt.loader,
        &Header::new(0xfffb, proto_loader::VERSION).bytes(),
        [copy.erase()],
    )
    .map_err(|refused| Status::Kernel(refused.error))?;
    canonical(&reply)?;
    super::loader_abort::load_image(&attempt.loader)?;
    let pid = attempt.child.ok_or(Status::BadSize)?;
    process_method(proto_process::Method::SpawnCommit, Some(pid))?;
    if !matches!(
        sys::receive(&observer).map_err(Status::Kernel)?,
        sys::Received::Notification { bits: 1, .. }
    ) {
        return Err(Status::BadSize);
    }
    let mut w = Writer::new();
    Header::new(0xfffa, proto_process::VERSION).write(&mut w)?;
    w.u32(pid)?;
    let reply = sys::send(process(), w.as_bytes()).map_err(Status::Kernel)?;
    if reply.len != 64 || !reply.handles.is_empty() {
        return Err(Status::BadSize);
    }
    let bytes = rt::abi::inline_bytes(&reply.words);
    let mut r = Reader::new(&bytes[..64]);
    if r.u64()? != 0 || r.u32()? != pid {
        return Err(Status::BadSize);
    }
    let image = r.u32()?;
    let ticket = r.u64()?;
    if r.u32()? != 1 || r.u32()? != 1 || r.u32()? != 0 || r.u32()? != 0 {
        return Err(Status::BadSize);
    }
    for expected in proto_process::Credentials::ROOT.words() {
        if r.u32()? != expected {
            return Err(Status::BadSize);
        }
    }
    r.finish()?;
    let mapped = Mapped::new()?;
    for held in &images.handles {
        super::image_hold::elf(held)?;
        mapped.read_elf(held)?;
        let after = image_snapshot(held)?;
        if after[1] as u32 != pid
            || after[2] as u32 != image
            || after[2] >> 32 != 1
            || after[4] != ticket
            || after[3] == 0
            || after[3] == before[3]
            || after[5..] != before[5..]
        {
            rt::println!(
                "posix-files: Handoff snapshot before {:?} after {:?}",
                before,
                after
            );
            return Err(Status::BadSize);
        }
        let mut open = Writer::new();
        proto_fs::Method::Open.header().write(&mut open)?;
        open.u32(proto_fs::WRITE_ONLY)?;
        open.bytes(b"/tmp/probe")?;
        let refused = Files::send_on(held, open.as_bytes())?;
        if refused.len != 8
            || refused.words[0] != u64::from(proto_fs::PERMISSION)
            || !refused.handles.is_empty()
        {
            return Err(Status::BadSize);
        }
    }
    for held in &images.handles {
        let mut write = Writer::new();
        proto_fs::Method::Write.header().write(&mut write)?;
        write.u32(0)?;
        write.bytes(b"X")?;
        let refused = Files::send_on(held, write.as_bytes())?;
        if refused.len != 8
            || refused.words[0] != u64::from(proto_fs::PERMISSION)
            || !refused.handles.is_empty()
        {
            return Err(Status::BadSize);
        }
        super::image_hold::elf(held)?;
    }
    attempt.abort()?;
    rt::println!("posix-files: image Take abort settled, checking released counts");
    super::image_hold::released(&images)?;
    rt::println!(
        "posix-files: actual Take retains exact Handoff reads and child death releases pins ok"
    );
    Ok(())
}
#[cfg(not(feature = "image-gates-normal"))]
fn trace(ticket: u64) -> Result<[u32; 18], Status> {
    let mut w = Writer::new();
    Header::new(0xfff9, proto_process::VERSION).write(&mut w)?;
    w.u64(ticket)?;
    let reply = sys::send(process(), w.as_bytes()).map_err(Status::Kernel)?;
    if reply.len != 88 || !reply.handles.is_empty() {
        return Err(Status::BadSize);
    }
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let mut r = Reader::new(reply.bytes(&mut buffer));
    if r.u64()? != 0 || r.u64()? != ticket {
        return Err(Status::BadSize);
    }
    let mut fields = [0; 18];
    for field in &mut fields {
        *field = r.u32()?;
    }
    r.finish()?;
    Ok(fields)
}
fn resolve(pending: &Handle<Channel>) -> Result<u64, Status> {
    let mut w = Writer::new();
    proto_fs::Method::ResolveStart.header().write(&mut w)?;
    w.u32(0)?;
    w.u64(1)?;
    w.u32(0)?;
    w.u32(1)?;
    w.bytes(b"/bin/setid-image")?;
    let reply = Files::send_on(pending, w.as_bytes())?;
    if reply.len != 12 || reply.words[0] as u32 != 0 || !reply.handles.is_empty() {
        return Err(Status::BadSize);
    }
    let bytes = rt::abi::inline_bytes(&reply.words);
    let mut r = Reader::new(&bytes[..12]);
    r.u32()?;
    let job = r.u64()?;
    let mut step = Writer::new();
    proto_fs::Method::ResolveStep.header().write(&mut step)?;
    step.u64(job)?;
    loop {
        let reply = Files::send_on(pending, step.as_bytes())?;
        if reply.len != 8 || !reply.handles.is_empty() {
            return Err(Status::BadSize);
        }
        match reply.words[0] {
            0 => return Ok(job),
            n if n == u64::from(proto_fs::RESOLVING) => {}
            _ => return Err(Status::BadSize),
        }
    }
}
#[cfg(not(feature = "image-gates-normal"))]
fn ambiguous_setid(fd: i32) -> Result<(), Status> {
    let before = posix_abi::process::client().query()?;
    let mut attempt = Attempt::start(true)?;
    let armed = sys::send(
        process(),
        &Header::new(0xfff8, proto_process::VERSION).bytes(),
    )
    .map_err(Status::Kernel)?;
    if armed.len != 24 || !armed.handles.is_empty() {
        return Err(Status::BadSize);
    }
    let bytes = rt::abi::inline_bytes(&armed.words);
    let mut r = Reader::new(&bytes[..24]);
    if r.u64()? != 0 {
        return Err(Status::BadSize);
    }
    let ticket = r.u64()?;
    let image = r.u32()?;
    if r.u32()? != before.pid {
        return Err(Status::BadSize);
    }
    let pending = capture(&attempt, fd)?;
    let job = resolve(&pending)?;
    let mut open = Writer::new();
    proto_fs::Method::OpenExec.header().write(&mut open)?;
    open.u64(job)?;
    loop {
        let reply = Files::send_on(&pending, open.as_bytes())?;
        if reply.len != 8 || !reply.handles.is_empty() {
            return Err(Status::BadSize);
        }
        if reply.words[0] == u64::from(proto_fs::RESOLVING) {
            continue;
        }
        if reply.words[0] != u64::from(proto_fs::IMAGE_ABORT_REQUIRED) {
            return Err(Status::BadSize);
        }
        break;
    }
    let live = trace(ticket)?;
    if live[0] != before.pid
        || live[1] != image
        || live[3..12] != [1, 1, 0, 1, 1, 37, 43, 1, 1]
        || live[12..] != before.credentials.words()
    {
        return Err(Status::BadSize);
    }
    let held = super::loader_abort::counts(&pending)?;
    for _ in 0..2 {
        let reply = Files::send_on(&pending, open.as_bytes())?;
        if reply.len != 8
            || reply.words[0] != u64::from(proto_fs::IMAGE_ABORT_REQUIRED)
            || !reply.handles.is_empty()
        {
            return Err(Status::BadSize);
        }
        let mut cancel = Writer::new();
        proto_fs::Method::ResolveCancel
            .header()
            .write(&mut cancel)?;
        cancel.u64(job)?;
        canonical(&Files::send_on(&pending, cancel.as_bytes())?)?;
        if trace(ticket)? != live {
            return Err(Status::BadSize);
        }
    }
    attempt.abort()?;
    let terminal = trace(ticket)?;
    if terminal[0..5] != live[0..5]
        || terminal[5..12] != [1, 0, 0, proto_process::NO_ID, proto_process::NO_ID, 0, 1]
        || terminal[12..] != before.credentials.words()
    {
        return Err(Status::BadSize);
    }
    for _ in 0..200 {
        let counts = super::loader_abort::counts(&pending)?;
        if counts[..5] == [0; 5] {
            let after = posix_abi::process::client().query()?;
            if after.pid != before.pid || after.credentials != before.credentials {
                return Err(Status::BadSize);
            }
            rt::println!(
                "posix-files: actual SetId {:?}, Abort clears pending tuple and held resources {:?} -> {:?}",
                live,
                held,
                counts
            );
            let mut fresh = Attempt::start(true)?;
            let reply = sys::send(
                process(),
                &Header::new(0xfff8, proto_process::VERSION).bytes(),
            )
            .map_err(Status::Kernel)?;
            if reply.len != 24 || !reply.handles.is_empty() {
                return Err(Status::BadSize);
            }
            let bytes = rt::abi::inline_bytes(&reply.words);
            let mut reader = Reader::new(&bytes[..24]);
            if reader.u64()? != 0 {
                return Err(Status::BadSize);
            }
            let new_ticket = reader.u64()?;
            if new_ticket == 0 || new_ticket == ticket {
                return Err(Status::BadSize);
            }
            reader.u32()?;
            if reader.u32()? != before.pid {
                return Err(Status::BadSize);
            }
            let clean = trace(new_ticket)?;
            if clean[3..10] != [0, 0, 0, 1, 0, proto_process::NO_ID, proto_process::NO_ID] {
                return Err(Status::BadSize);
            }
            fresh.abort()?;
            rt::println!("posix-files: fresh exec ticket differs after genuine Abort ok");
            return Ok(());
        }
        // SAFETY: this C helper takes no pointers and returns its observed result.
        if unsafe { super::loader_abort::sleep_for_cleanup() } != 0 {
            return Err(Status::BadSize);
        }
    }
    Err(Status::BadSize)
}
#[cfg(feature = "image-gates-normal")]
fn normal_setid(fd: i32) -> Result<(), Status> {
    let before = posix_abi::process::client().query()?;
    let mut attempt = Attempt::start(true)?;
    let pending = capture(&attempt, fd)?;
    let job = resolve(&pending)?;
    let mut open = Writer::new();
    proto_fs::Method::OpenExec.header().write(&mut open)?;
    open.u64(job)?;
    let image = loop {
        let mut reply = Files::send_on(&pending, open.as_bytes())?;
        if reply.len == 8
            && reply.words[0] == u64::from(proto_fs::RESOLVING)
            && reply.handles.is_empty()
        {
            continue;
        }
        if reply.len != 4
            || reply.words[0] as u32 != 0
            || reply.handles.len() != 1
            || reply.handles.info(0) != Some((ObjectKind::Channel, Rights::SEND | Rights::TRANSFER))
        {
            return Err(Status::BadSize);
        }
        break reply.handles.take::<Channel>(0).map_err(Status::Kernel)?;
    };
    super::image_hold::elf(&image)?;
    let initial = super::image_hold::image_counts(&image)?;
    if initial[0] != 1 || initial[1] != 1 || initial[3] != 1 {
        return Err(Status::BadSize);
    }
    attempt.abort()?;
    for _ in 0..200 {
        let after = super::image_hold::image_counts(&image)?;
        if after == [0, 0, initial[2].checked_sub(1).ok_or(Status::BadSize)?, 0] {
            let current = posix_abi::process::client().query()?;
            if current.pid != before.pid
                || current.credentials != before.credentials
                || super::image_hold::elf(&image).is_ok()
            {
                return Err(Status::BadSize);
            }
            rt::println!("posix-files: normal SetId same OpenExec branch and genuine Abort ok");
            return Ok(());
        }
        // SAFETY: this C helper takes no pointers and returns its observed result.
        if unsafe { super::loader_abort::sleep_for_cleanup() } != 0 {
            return Err(Status::BadSize);
        }
    }
    Err(Status::BadSize)
}
#[unsafe(no_mangle)]
extern "C" fn files_image_gates(fd: i32) -> i32 {
    #[cfg(not(feature = "image-gates-normal"))]
    let result = take(fd).and_then(|()| ambiguous_setid(fd));
    #[cfg(feature = "image-gates-normal")]
    let result = normal_setid(fd);
    match result {
        Ok(()) => 0,
        Err(error) => {
            rt::println!("posix-files: image gates failed {:?}", error);
            -1
        }
    }
}
