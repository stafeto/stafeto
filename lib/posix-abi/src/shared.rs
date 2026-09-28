// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Private in-process owner of file and directory state. This pointer-based
//! transport is not an external service protocol. Clients block through IPC
//! and keep jobs live until acknowledgment; unexpected IPC failure is fail-stop.

use crate::{constants::ENOSYS, directory::Streams, tls};
use core::{
    cell::UnsafeCell,
    ffi::c_void,
    sync::atomic::{AtomicBool, Ordering},
};
use posix_fs::PosixFs;
use rt::{
    Stack,
    abi::Policy,
    handle::{Channel, Handle, Process},
    sys,
};

struct Cell<T>(UnsafeCell<Option<T>>);
// SAFETY: startup installs once; the channel stays immutable and the initial
// file state is consumed exactly once by its sole worker. Publication is atomic.
unsafe impl<T: Send> Sync for Cell<T> {}
static CHANNEL: Cell<Handle<Channel>> = Cell(UnsafeCell::new(None));
static FILES: Cell<PosixFs> = Cell(UnsafeCell::new(None));
static READY: AtomicBool = AtomicBool::new(false);
static STACK: Stack<32768> = Stack::new();

fn channel() -> &'static Handle<Channel> {
    // SAFETY: initialization or READY establishes an immutable installed handle.
    unsafe { (*CHANNEL.0.get()).as_ref().expect("file owner initialized") }
}

/// # Safety
/// Startup has exclusive access, before any client thread uses the file owner.
/// The worker stack is used once and its message page at 0xb00000 is unused.
pub unsafe fn init(process: &Handle<Process>, files: PosixFs) -> Result<(), rt::abi::Error> {
    if READY.load(Ordering::Acquire) {
        return Err(rt::abi::Error::BadState);
    }
    let channel = sys::channel_create(1)?;
    unsafe {
        *CHANNEL.0.get() = Some(channel);
        *FILES.0.get() = Some(files);
    }
    let started = (|| {
        let thread = unsafe {
            sys::thread_create(process, worker, STACK.top(), 0, 1, Policy::Fifo, 0xb00000)
        }?;
        // Publish initialization before the worker can run. Startup excludes clients.
        READY.store(true, Ordering::Release);
        sys::thread_start(&thread)
    })();
    if started.is_err() {
        READY.store(false, Ordering::Release);
        // SAFETY: a failed create/start left no worker able to consume this state.
        unsafe {
            *FILES.0.get() = None;
            *CHANNEL.0.get() = None;
        }
        return started;
    }
    Ok(())
}

type Execute = unsafe fn(*mut c_void, &Streams, &mut PosixFs);

extern "C" fn worker(_: u64) -> ! {
    assert!(READY.load(Ordering::Acquire), "published file owner");
    // SAFETY: startup handed this state exclusively to this worker.
    let mut files = unsafe { (*FILES.0.get()).take().expect("initial file state") };
    tls::with_files(&mut files, || {
        loop {
            let Ok(sys::Received::Message {
                len,
                words,
                token,
                handles,
                ..
            }) = sys::receive(channel())
            else {
                continue;
            };
            drop(handles);
            if len != 16 {
                let _ = token.reply(&[]);
                continue;
            }
            // SAFETY: this private channel carries only live jobs and monomorphized
            // executor addresses from call(). The client remains blocked through reply.
            let execute: Execute = unsafe { core::mem::transmute(words[0] as usize) };
            unsafe {
                execute(
                    words[1] as *mut c_void,
                    &*tls::directories(),
                    &mut *tls::files(),
                )
            };
            let _ = token.reply(&[]);
        }
    })
}

struct Job<F, T> {
    run: UnsafeCell<Option<F>>,
    result: UnsafeCell<Option<Result<T, i32>>>,
    published: AtomicBool,
    complete: AtomicBool,
}

unsafe fn execute<F, T>(pointer: *mut c_void, streams: &Streams, files: &mut PosixFs)
where
    F: FnOnce(&Streams, &mut PosixFs) -> Result<T, i32> + Send,
    T: Send,
{
    // SAFETY: the blocked client owns this live job; only this worker writes its
    // cells, and it publishes the result before replying or accessing another job.
    let job = unsafe { &*pointer.cast::<Job<F, T>>() };
    assert!(job.published.load(Ordering::Acquire), "published file job");
    let run = unsafe { (*job.run.get()).take().expect("one file job execution") };
    unsafe {
        *job.result.get() = Some(run(streams, files));
    }
    job.complete.store(true, Ordering::Release);
}

pub(crate) fn call<F, T>(run: F) -> Result<T, i32>
where
    F: FnOnce(&Streams, &mut PosixFs) -> Result<T, i32> + Send,
    T: Send,
{
    if !READY.load(Ordering::Acquire) {
        return Err(ENOSYS);
    }
    let mut job = Job {
        run: UnsafeCell::new(Some(run)),
        result: UnsafeCell::new(None),
        published: AtomicBool::new(false),
        complete: AtomicBool::new(false),
    };
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&(execute::<F, T> as Execute as usize as u64).to_le_bytes());
    bytes[8..].copy_from_slice(&(core::ptr::addr_of_mut!(job) as usize as u64).to_le_bytes());
    job.published.store(true, Ordering::Release);
    let reply = sys::send(channel(), &bytes);
    if reply.is_err()
        || reply.as_ref().is_ok_and(|reply| reply.len != 0)
        || !job.complete.load(Ordering::Acquire)
    {
        // A canceled/failed request could still name this stack job. End all
        // process threads instead of returning and recycling the stack underneath it.
        sys::process_exit(125);
    }
    // SAFETY: acknowledgment and acquire transfer sole ownership back to the client.
    unsafe {
        (*job.result.get())
            .take()
            .expect("completed file job result")
    }
}

/// Close process descriptors and streams after every client has stopped using them.
/// The worker remains alive until process exit. Callers must arrange quiescence.
pub fn cleanup() -> Result<(), i32> {
    call(|streams, files| {
        streams.close_all(files);
        for fd in 0..posix_fs::OPEN_MAX as u32 {
            match files.close(fd) {
                Ok(()) | Err(posix_fs::FsError::BadFileDescriptor) => (),
                Err(error) => return Err(crate::error(error)),
            }
        }
        Ok(())
    })
}

pub(crate) fn context<F, T>(run: F) -> Result<T, i32>
where
    F: FnOnce(&Streams, &mut PosixFs) -> Result<T, i32> + Send,
    T: Send,
{
    if tls::process_files() {
        return call(run);
    }
    let streams = tls::directories();
    let files = tls::files();
    if streams.is_null() || files.is_null() {
        return Err(ENOSYS);
    }
    // SAFETY: the local scope uniquely borrows files and owns its live registry.
    run(unsafe { &*streams }, unsafe { &mut *files })
}
