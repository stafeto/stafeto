// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Genuine authorized Clock publication during one RAM read-only PAGE snapshot.
use core::{
    ffi::c_void,
    sync::atomic::{AtomicBool, Ordering},
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
    key: proto_fs::OpenKey,
    job: u64,
    done: AtomicBool,
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
        let result = if key == helper.key && job == helper.job {
            // This session was genuinely vouched and authorized before arming RAM.
            helper.clock.set(
                posix_time::Time {
                    seconds: 42,
                    nanos: 123,
                },
                None,
            )
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
fn finish(files: &Files, key: proto_fs::OpenKey) -> Result<sys::Reply, Status> {
    let mut w = Writer::new();
    proto_fs::Method::OpenFinish.header().write(&mut w)?;
    w.u32(key.slot)?;
    w.u64(key.generation)?;
    sys::send(files.sessions().0, w.as_bytes()).map_err(Status::Kernel)
}
pub(super) fn run(original: &Files) -> Result<(), i32> {
    let process = posix_abi::allocation::process();
    let baseline = sys::process_handles(process).map_err(|_| 190)?.live;
    let files = super::open_stages::clone_bound(original, &[]).map_err(|_| 191)?;
    let key = proto_fs::OpenKey {
        slot: 0,
        generation: 1,
    };
    let job = files
        .open_start(
            key,
            b"/tmp/finalize-clock",
            proto_fs::CREATE | proto_fs::EXCLUSIVE | proto_fs::READ_WRITE,
            0o600,
            0,
        )
        .map_err(|_| 192)?;
    super::open_stages::prepared(&files, job).map_err(|_| 193)?;
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
    let helper = Helper {
        channel: sys::channel_create(1).map_err(|_| 196)?,
        clock,
        key,
        job,
        done: AtomicBool::new(false),
    };
    let mut thread = 0;
    // SAFETY: Helper is stable in this stack frame until the worker is joined;
    // pthread creates its own stack and message buffer before calling publish.
    if unsafe {
        pthread_create(
            &mut thread,
            core::ptr::null(),
            publish,
            (&helper as *const Helper).cast_mut().cast(),
        )
    } != 0
    {
        return Err(197);
    }
    let mut worker = Worker {
        helper: &helper,
        thread,
        active: true,
    };
    let result = (|| {
        let incorrect = sys::handle_duplicate(
            &helper.channel,
            Rights::SEND | Rights::TRANSFER | Rights::DUPLICATE,
        )
        .map_err(|_| 198)?;
        if control(&files, 1, key, job, Some(incorrect)) != Err(Status::BadSize) {
            return Err(212);
        }
        let incorrect = sys::handle_duplicate(&helper.channel, Rights::SEND | Rights::TRANSFER)
            .map_err(|_| 198)?;
        if control(&files, 1, key, job + 128, Some(incorrect))
            != Err(Status::Unknown(proto_fs::PERMISSION))
        {
            return Err(213);
        }
        let offered = sys::handle_duplicate(&helper.channel, Rights::SEND | Rights::TRANSFER)
            .map_err(|_| 198)?;
        control(&files, 1, key, job, Some(offered)).map_err(|_| 199)?;
        let foreign = super::open_stages::clone_bound(original, &[]).map_err(|_| 214)?;
        if control(&foreign, 0, key, job, None) != Err(Status::Unknown(proto_fs::PERMISSION)) {
            return Err(214);
        }
        drop(foreign);
        // Repeated exact arm has no second capability or publication.
        control(&files, 1, key, job, None).map_err(|_| 200)?;
        let before = files.node_information("/tmp/finalize-clock");
        let reply = finish(&files, key).map_err(|_| 201)?;
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        if !reply.handles.is_empty()
            || reply.bytes(&mut buffer)
                != proto_wire::reply(Status::Unknown(proto_fs::TIME_DEFERRED))
            || !helper.done.load(Ordering::Acquire)
        {
            return Err(202);
        }
        if before != Err(Status::Unknown(proto_fs::NO_ENTRY))
            || files.node_information("/tmp/finalize-clock") != before
            || files.open_query(key) != Ok(OpenOutcome::Active { job, phase: 2 })
        {
            return Err(203);
        }
        control(&files, 0, key, job, None).map_err(|_| 204)?;
        let held = files.open_finish_once(key).map_err(|_| 205)?;
        let saved = files.descriptor_information(held.fd).map_err(|_| 205)?;
        if saved.permissions != 0o600
            || saved.size != 0
            || files.open_query(key) != Ok(OpenOutcome::Finished(held))
            || files.open_finish_once(key) != Ok(held)
            || files.descriptor_information(held.fd) != Ok(saved)
        {
            return Err(208);
        }
        files.close_exact(held).map_err(|_| 209)?;
        Ok(())
    })();
    let _ = control(&files, 0, key, job, None);
    if result.is_err() {
        let _ = files.open_cancel_key(key);
    }
    worker.join()?;
    drop(worker);
    drop(helper);
    drop(files);
    result?;
    if sys::process_handles(process).map_err(|_| 210)?.live != baseline {
        return Err(211);
    }
    rt::println!(
        "posix-files: genuine Clock publication deferred Finish with same-key Prepared recovery ok"
    );
    Ok(())
}
