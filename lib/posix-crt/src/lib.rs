// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Initial static C-program startup. Args are a bounded, NUL-separated list
//! from init; environment inheritance and ELF TLS templates are pending.
//! The start goes in two steps (spec 2, 3.5): the process's
//! (`posix_init_process`: registration, clocks, files, heap, threads),
//! which leaves the thread's block alone, then the thread's
//! (`posix_abi::threads::attach`: its TCB in the main page and its entry
//! of signals). With relibc the second step moves to the platform's start,
//! after relibc built the TCB.

#![no_std]

use core::ffi::{c_char, c_int};
use core::ptr;
use posix_fs::PosixFs;
use rt::handle::{Channel, Handle, Process, Resource, Thread};

#[unsafe(no_mangle)]
pub static mut environ: *mut *mut c_char = ptr::null_mut();

unsafe extern "C" {
    fn main(argc: c_int, argv: *mut *mut c_char) -> c_int;
}

/// The first step of the start: the process's registration with the
/// process service (`session`), its clocks and files through `parent`,
/// its heap and its thread owner. The calling thread's block is not
/// touched.
///
/// # Safety
/// Runs once, on the main thread, before any other thread of the process;
/// `process` and `thread` are the program's own (rt::startup).
pub unsafe fn posix_init_process(
    session: Handle<Channel>,
    parent: &Handle<Channel>,
    process: Handle<Process>,
    thread: Handle<Thread>,
) -> Result<(), &'static str> {
    // SAFETY: startup runs once, before application threads and clock calls.
    unsafe { posix_abi::process::init(session) }.map_err(|_| "process registration failed")?;
    // SAFETY: as above.
    unsafe { posix_abi::clock::init(parent) }.map_err(|_| "clock connection failed")?;
    #[cfg(feature = "uart-input")]
    let files = PosixFs::connect_with_uart(parent);
    #[cfg(not(feature = "uart-input"))]
    let files = PosixFs::connect(parent);
    let files = files.map_err(|_| "file connection failed")?;
    // SAFETY: only startup owns file initialization and the message range is unused.
    unsafe { posix_abi::shared::init(&process, files) }.map_err(|_| "file worker failed")?;
    // SAFETY: startup is single-threaded and its layout reserves the heap ranges.
    unsafe { posix_abi::allocation::init(process) }.map_err(|_| "heap worker failed")?;
    // SAFETY: startup owns initialization and the manager ranges are unused.
    unsafe { posix_abi::threads::init(thread) }.map_err(|_| "thread worker failed")?;
    Ok(())
}

#[unsafe(export_name = "__rt_main")]
pub extern "C" fn crt_main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 125;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    let mut arguments = [ptr::null_mut(); 17];
    let mut bytes = [0; 256];
    let Ok(args) = proto_init::ServiceArgs::read(start.args()) else {
        rt::println!("POSIX startup: invalid start arguments");
        return 125;
    };
    let input = if args.own.is_empty() {
        b"stafeto\0".as_slice()
    } else {
        args.own
    };
    if input.len() > bytes.len() || input.last() != Some(&0) {
        rt::println!("POSIX startup: unterminated arguments");
        return 125;
    }
    bytes[..input.len()].copy_from_slice(input);
    let mut count = 0;
    let mut first = 0;
    for (index, &byte) in input.iter().enumerate() {
        if byte != 0 {
            continue;
        }
        if count == arguments.len() - 1 {
            rt::println!("POSIX startup: too many arguments");
            return 125;
        }
        // SAFETY: each pointer names a NUL-terminated part of the live bytes array.
        arguments[count] = unsafe { bytes.as_mut_ptr().add(first).cast() };
        first = index + 1;
        count += 1;
    }
    let Ok(session) = start.take::<Channel>(posix_abi::process::START_NAME) else {
        rt::println!("POSIX startup: no session with the process service");
        return 125;
    };
    // SAFETY: the main thread, once, before any other; the start channel
    // stays in `start` until main returned.
    if let Err(why) =
        unsafe { posix_init_process(session, &start.parent, start.process, start.thread) }
    {
        rt::println!("POSIX startup: {}", why);
        return 125;
    }
    let mut environment = [ptr::null_mut(); 1];
    // SAFETY: startup runs once, before C. This empty vector lives until main returns.
    unsafe { environ = environment.as_mut_ptr() };
    // SAFETY: the main page is the main thread's for its life.
    if unsafe {
        posix_abi::threads::attach(posix_abi::tls::main_page(), posix_thread::PAGE_SIZE, 1)
    }
    .is_err()
    {
        rt::println!("POSIX startup: main thread attach failed");
        return 125;
    }
    // SAFETY: argv has count live C strings and a NULL sentinel; main is linked by C.
    let status = unsafe { main(count as c_int, arguments.as_mut_ptr()) };
    (status & 255) as u64
}
