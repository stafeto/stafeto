// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Genuine authorized Clock publication during one RAM read-only PAGE snapshot.
use core::{
    cell::UnsafeCell,
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};
use proto_wire::{Reader, Status, Writer};
use rt::{
    abi::Rights,
    fs::{Files, OpenOutcome},
    handle::{Channel, Handle},
    sys,
};

unsafe extern "C" {
    fn pthread_create(
        thread: *mut usize,
        attributes: *const c_void,
        start: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
        arg: *mut c_void,
    ) -> i32;
    fn pthread_join(thread: usize, result: *mut *mut c_void) -> i32;
}
struct Helper {
    channel: Handle<Channel>,
    clock: posix_clock::Client,
    owner: u64,
    supervisor: u64,
    source: i32,
    prepared: UnsafeCell<Option<posix_abi::open_finalize_probe::Prepared>>,
    ready: AtomicBool,
    usage: UnsafeCell<Option<([u32; 4], u32)>>,
    entry: AtomicU32,
    handled: AtomicU32,
    done: AtomicBool,
}
struct Escrow(UnsafeCell<Option<Helper>>);
// SAFETY: one supervisor installs once before register/thread_start, and removes
// only after callback disable and the actual worker join. Shared fields are
// immutable or atomic; prepared has one writer before ready's Release.
unsafe impl Sync for Escrow {}
static ESCROW: Escrow = Escrow(UnsafeCell::new(None));
fn helper() -> &'static Helper {
    // SAFETY: all callers are inside that installed lifetime.
    unsafe { (&*ESCROW.0.get()).as_ref().expect("owned Clock helper") }
}
fn saved(helper: &Helper) -> Result<posix_abi::open_finalize_probe::Prepared, i32> {
    if !helper.ready.load(Ordering::Acquire) {
        return Err(215);
    }
    // SAFETY: prepared was written once before ready and remains immutable until join.
    unsafe { *helper.prepared.get() }.ok_or(215)
}
fn key(value: posix_abi::open_finalize_probe::Prepared) -> proto_fs::OpenKey {
    proto_fs::OpenKey {
        slot: value.token.slot() as u32,
        generation: value.token.generation(),
    }
}
fn arm(value: posix_abi::open_finalize_probe::Prepared) -> Result<(), i32> {
    let helper = helper();
    if value.owner.value() != helper.owner {
        return Err(216);
    }
    posix_abi::shared::with_files(|files| {
        let snapshot = files.open_snapshot(value.token).map_err(posix_abi::error)?;
        if files.sessions().0.raw() != value.session
            || snapshot.owner != Some(value.owner)
            || snapshot.claimant != Some(value.owner)
            || snapshot.phase != posix_fs::open::OpenPhase::Preparing
            || snapshot.entry.is_some()
            || !snapshot
                .recovery
                .is_some_and(|r| r.job == value.job && r.phase == posix_fs::open::Phase::Preparing)
        {
            return Err(217);
        }
        Ok(())
    })?;
    // SAFETY: register consumes this callback once on its exact owner, before
    // any rendezvous with the worker. No caller stack address is retained.
    unsafe { *helper.prepared.get() = Some(value) };
    helper.ready.store(true, Ordering::Release);
    let files =
        core::mem::ManuallyDrop::new(Files::from_sessions(Handle::from_raw(value.session), None));
    let before = super::data_stages::counters(&files).map_err(|_| 221)?;
    if super::data_stages::counters(&files).map_err(|_| 221)? != before {
        return Err(221);
    }
    let incorrect = sys::handle_duplicate(
        &helper.channel,
        Rights::SEND | Rights::TRANSFER | Rights::DUPLICATE,
    )
    .map_err(|_| 198)?;
    if control(&files, 1, key(value), value.job, Some(incorrect)) != Err(Status::BadSize) {
        return Err(212);
    }
    let incorrect =
        sys::handle_duplicate(&helper.channel, Rights::SEND | Rights::TRANSFER).map_err(|_| 198)?;
    if control(&files, 1, key(value), value.job + 128, Some(incorrect))
        != Err(Status::Unknown(proto_fs::PERMISSION))
    {
        return Err(213);
    }
    let offered =
        sys::handle_duplicate(&helper.channel, Rights::SEND | Rights::TRANSFER).map_err(|_| 198)?;
    control(&files, 1, key(value), value.job, Some(offered)).map_err(|_| 199)?;
    control(&files, 1, key(value), value.job, None).map_err(|_| 200)?;
    let foreign = super::open_stages::clone_bound(&files, &[]).map_err(|_| 214)?;
    if control(&foreign, 0, key(value), value.job, None)
        != Err(Status::Unknown(proto_fs::PERMISSION))
    {
        return Err(214);
    }
    let counts = super::data_stages::counters(&files).map_err(|_| 221)?;
    if counts != before {
        return Err(221);
    }
    // SAFETY: one supervisor callback writes before the worker is given its gate.
    unsafe { *helper.usage.get() = Some(counts) };
    helper.ready.store(true, Ordering::Release);
    Ok(())
}
extern "C" fn resumed(_: i32) {
    let result = (|| {
        let helper = helper();
        let value = saved(helper)?;
        posix_abi::shared::with_files(|files| {
            let snapshot = files.open_snapshot(value.token).map_err(posix_abi::error)?;
            if snapshot.owner != Some(value.owner)
                || snapshot.claimant.is_some()
                || snapshot.phase != posix_fs::open::OpenPhase::Preparing
                || snapshot.entry.is_some()
                || !snapshot.recovery.is_some_and(|r| {
                    r.job == value.job && r.phase == posix_fs::open::Phase::Preparing
                })
            {
                return Err(218);
            }
            Ok(())
        })?;
        let files = core::mem::ManuallyDrop::new(Files::from_sessions(
            Handle::from_raw(value.session),
            None,
        ));
        if files.open_query(key(value))
            != Ok(OpenOutcome::Active {
                job: value.job,
                phase: 2,
            })
            || files.node_information("/tmp/public-finalize-clock")
                != Err(Status::Unknown(proto_fs::NO_ENTRY))
        {
            return Err(219);
        }
        // SAFETY: callback wrote usage before Finish; ready was republished after it.
        let actual = super::data_stages::counters(&files).map_err(|_| 221)?;
        if unsafe { *helper.usage.get() } != Some(actual) {
            return Err(221);
        }
        let fd = helper.entry.load(Ordering::Acquire) as i32;
        if posix_abi::dup2(helper.source, fd) != Ok(fd) {
            return Err(220);
        }
        Ok(())
    })();
    helper()
        .handled
        .store(result.err().unwrap_or(1) as u32, Ordering::Release);
}
fn canonical(reply: &sys::Reply) -> Result<(), Status> {
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    if !reply.handles.is_empty() {
        return Err(Status::BadSize);
    }
    let mut body = Reader::new(reply.bytes(&mut buffer));
    let status = Status::from_code(body.u32()?);
    if body.u32()? != 0 || body.finish().is_err() {
        return Err(Status::BadSize);
    }
    if status == Status::Ok {
        Ok(())
    } else {
        Err(status)
    }
}
unsafe extern "C" fn publish(argument: *mut c_void) -> *mut c_void {
    // SAFETY: the supervisor keeps Helper alive and immutable until pthread_join.
    let helper = unsafe { &*argument.cast::<Helper>() };
    let result = (|| {
        let sys::Received::Message {
            label,
            len,
            words,
            handles,
            token,
        } = sys::receive(&helper.channel).map_err(Status::Kernel)?
        else {
            return Err(Status::BadSize);
        };
        let mut bytes = [0; 24];
        for (chunk, word) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(words) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        if label != 0 || len != 20 || !handles.is_empty() {
            token
                .reply(&proto_wire::reply(Status::BadSize))
                .map_err(Status::Kernel)?;
            return Err(Status::BadSize);
        }
        let mut body = Reader::new(&bytes[..len]);
        let key = proto_fs::OpenKey {
            slot: body.u32()?,
            generation: body.u64()?,
        };
        let job = body.u64()?;
        body.finish()?;
        if job == 0 && key.generation == 0 {
            token
                .reply(&proto_wire::reply(Status::Ok))
                .map_err(Status::Kernel)?;
            return Ok(());
        }
        let value = saved(helper).map_err(|_| Status::BadSize)?;
        let result = if key == self::key(value) && job == value.job {
            let fd = posix_abi::shared::with_files(|files| {
                let snapshot = files.open_snapshot(value.token).map_err(posix_abi::error)?;
                if snapshot.phase != posix_fs::open::OpenPhase::Reserved
                    || snapshot.owner != Some(value.owner)
                {
                    return Err(5);
                }
                Ok(snapshot.entry.ok_or(5)?.fd)
            })
            .map_err(|_| Status::BadSize)?;
            helper.entry.store(fd, Ordering::Release);
            // This session was genuinely vouched and authorized before arming RAM.
            helper.clock.set(
                posix_time::Time {
                    seconds: 42,
                    nanos: 123,
                },
                None,
            )?;
            if posix_abi::signals::kill_relibc_thread(helper.supervisor, 10) != 0 {
                return Err(Status::BadSize);
            }
            Ok(())
        } else {
            Err(Status::BadSize)
        };
        let status = result.err().unwrap_or(Status::Ok);
        helper.done.store(true, Ordering::Release);
        token
            .reply(&proto_wire::reply(status))
            .map_err(Status::Kernel)?;
        if status != Status::Ok {
            return Err(status);
        }
        Ok(())
    })();
    if result.is_ok() {
        core::ptr::dangling_mut::<c_void>()
    } else {
        core::ptr::null_mut()
    }
}
struct Worker<'a> {
    helper: &'a Helper,
    thread: usize,
    active: bool,
}
impl Worker<'_> {
    fn join(&mut self) -> Result<(), i32> {
        if !self.helper.done.load(Ordering::Acquire) {
            let mut stop = Writer::new();
            stop.u32(0)
                .and_then(|()| stop.u64(0))
                .and_then(|()| stop.u64(0))
                .map_err(|_| 206)?;
            canonical(&sys::send(&self.helper.channel, stop.as_bytes()).map_err(|_| 206)?)
                .map_err(|_| 206)?;
        }
        let mut value = core::ptr::null_mut();
        // SAFETY: thread is this worker's unique live pthread; Helper still exists.
        let result = unsafe { pthread_join(self.thread, &mut value) };
        self.active = false;
        if result != 0 || value != core::ptr::dangling_mut::<c_void>() {
            return Err(207);
        }
        Ok(())
    }
}
impl Drop for Worker<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.join();
        }
    }
}
fn control(
    files: &Files,
    action: u32,
    key: proto_fs::OpenKey,
    job: u64,
    offered: Option<Handle<Channel>>,
) -> Result<(), Status> {
    let mut w = Writer::new();
    proto_wire::Header::new(0xfff6, proto_fs::VERSION).write(&mut w)?;
    w.u32(action)?;
    w.u32(key.slot)?;
    w.u64(key.generation)?;
    w.u64(job)?;
    let reply = match offered {
        Some(channel) => sys::send_handles(files.sessions().0, w.as_bytes(), [channel.erase()])
            .map_err(|e| Status::Kernel(e.error))?,
        None => sys::send(files.sessions().0, w.as_bytes()).map_err(Status::Kernel)?,
    };
    canonical(&reply)
}
pub(super) fn run(_: &Files) -> Result<(), i32> {
    use posix_abi::constants::*;
    // Drain earlier fixture cleanup before comparing this exact no-effect attempt.
    // These temporary resources leave before the physical handle baseline.
    {
        let channel = sys::channel_create(1).map_err(|_| 222)?;
        let timer = sys::timer_create(&channel, 30).map_err(|_| 222)?;
        let deadline = rt::time::ticks_to_ns(rt::time::now()) + 1_000_000_000;
        sys::timer_set(&timer, deadline).map_err(|_| 222)?;
        sys::receive(&channel).map_err(|_| 222)?;
    }
    let process = posix_abi::allocation::process();
    let source = posix_abi::open_policy(b"/etc/motd", O_RDONLY, 0, 0).map_err(|_| 190)?;
    let baseline = sys::process_handles(process).map_err(|_| 190)?.live;
    let clock = {
        let named = posix_clock::Client::connect(&posix_crt::parent()).map_err(|_| 194)?;
        let mut reply = sys::send(
            named.session(),
            &proto_clock::Method::Clone.header().bytes(),
        )
        .map_err(|_| 194)?;
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        if reply.bytes(&mut buffer) != 0u32.to_le_bytes()
            || reply.handles.len() != 1
            || reply.handles.info(0)
                != Some((
                    rt::abi::ObjectKind::Channel,
                    Rights::SEND | Rights::TRANSFER,
                ))
        {
            return Err(194);
        }
        posix_clock::Client::from_session(reply.handles.take::<Channel>(0).map_err(|_| 194)?)
    };
    clock
        .set(
            posix_time::Time {
                seconds: 41,
                nanos: 321,
            },
            posix_abi::process::identity(),
        )
        .map_err(|_| 195)?;
    let owner = posix_abi::relibc::open_owner()?;
    let state = Helper {
        channel: sys::channel_create(1).map_err(|_| 196)?,
        clock,
        owner,
        supervisor: posix_abi::relibc::current(),
        source,
        prepared: UnsafeCell::new(None),
        ready: AtomicBool::new(false),
        usage: UnsafeCell::new(None),
        entry: AtomicU32::new(0),
        handled: AtomicU32::new(0),
        done: AtomicBool::new(false),
    };
    // SAFETY: this private suite runs once, with no callback/worker before install.
    unsafe { *ESCROW.0.get() = Some(state) };
    let helper = helper();
    let action = posix_abi::signals::sigaction(
        10,
        Some(posix_abi::signals::SigAction {
            handler: resumed as *const () as u64,
            mask: 0,
            flags: 0,
        }),
    )?;
    let mut thread = 0;
    // SAFETY: Helper lives in static owned escrow until disable and pthread_join;
    // pthread creates its own stack/message buffer before calling publish.
    if unsafe {
        pthread_create(
            &mut thread,
            core::ptr::null(),
            publish,
            (helper as *const Helper).cast_mut().cast(),
        )
    } != 0
    {
        posix_abi::signals::sigaction(10, Some(action))?;
        // SAFETY: no worker or registered callback exists.
        unsafe { *ESCROW.0.get() = None };
        let _ = posix_abi::close(source);
        return Err(197);
    }
    let mut worker = Worker {
        helper,
        thread,
        active: true,
    };
    posix_abi::open_finalize_probe::register(owner, arm)?;
    let opened = posix_abi::open_policy(
        b"/tmp/public-finalize-clock",
        O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_CLOFORK,
        0o600,
        0,
    );
    posix_abi::open_finalize_probe::disable(owner)?;
    let result = (|| {
        let fd = opened.map_err(|_| 201)?;
        let value = saved(helper)?;
        if posix_abi::open_finalize_probe::deferred_reason() != proto_fs::TIME_DEFERRED
            || !helper.done.load(Ordering::Acquire)
            || helper.handled.load(Ordering::Acquire) != 1
            || fd == helper.entry.load(Ordering::Acquire) as i32
        {
            return Err(202);
        }
        let (target, transport, flags) = posix_abi::shared::with_files(|files| {
            Ok((
                files.target(fd as u32).map_err(posix_abi::error)?,
                files.transport(),
                files
                    .descriptor_flags(fd as u32)
                    .map_err(posix_abi::error)?,
            ))
        })?;
        let posix_fs::Target::Ram(target) = target else {
            return Err(203);
        };
        if !flags.close_on_exec || !flags.close_on_fork {
            return Err(204);
        }
        let files = transport.files();
        let held = target.prepared();
        let info = files.descriptor_information(held.fd).map_err(|_| 205)?;
        if info.permissions != 0o600
            || info.size != 0
            || files.open_query(key(value)) != Ok(OpenOutcome::Finished(held))
            || files.open_finish_once(key(value)) != Ok(held)
            || files.descriptor_information(held.fd) != Ok(info)
        {
            return Err(208);
        }
        let mut byte = [0];
        if posix_abi::read(helper.entry.load(Ordering::Acquire) as i32, &mut byte) != Ok(1)
            || byte != *b"s"
        {
            return Err(209);
        }
        posix_abi::close(helper.entry.load(Ordering::Acquire) as i32)?;
        posix_abi::close(fd)?;
        Ok(())
    })();
    if let Ok(value) = saved(helper) {
        let files = core::mem::ManuallyDrop::new(Files::from_sessions(
            Handle::from_raw(value.session),
            None,
        ));
        let _ = control(&files, 0, key(value), value.job, None);
    }
    worker.join()?;
    drop(worker);
    posix_abi::signals::sigaction(10, Some(action))?;
    // SAFETY: callback is disabled and actual worker joined; no borrowed references remain.
    unsafe { *ESCROW.0.get() = None };
    posix_abi::close(source)?;
    result?;
    if sys::process_handles(process).map_err(|_| 210)?.live != baseline {
        return Err(211);
    }
    rt::println!(
        "posix-files: public Open genuine Clock325 unreserve handler reuse and same-key retry ok"
    );
    Ok(())
}
