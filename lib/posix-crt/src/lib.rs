// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Initial static C-program startup. Args are a bounded, NUL-separated list
//! from init; environment inheritance and ELF TLS templates are pending.

#![no_std]

use core::ffi::{c_char, c_int};
use core::ptr;
use posix_fs::PosixFs;
use rt::handle::Resource;

#[unsafe(no_mangle)]
pub static mut environ: *mut *mut c_char = ptr::null_mut();

unsafe extern "C" {
    fn main(argc: c_int, argv: *mut *mut c_char) -> c_int;
}

#[unsafe(export_name = "__rt_main")]
pub extern "C" fn crt_main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 125;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    let Ok(files) = PosixFs::connect(&start.parent) else {
        rt::println!("POSIX startup: file connection failed");
        return 125;
    };
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
    let mut environment = [ptr::null_mut(); 1];
    // SAFETY: startup runs once, before C. This empty vector lives until main returns.
    unsafe { environ = environment.as_mut_ptr() };
    // SAFETY: only startup owns file initialization and the message range is unused.
    if unsafe { posix_abi::shared::init(&start.process, files) }.is_err() {
        rt::println!("POSIX startup: file worker failed");
        return 125;
    }
    // SAFETY: startup is single-threaded and its layout reserves the heap ranges.
    if unsafe { posix_abi::allocation::init(start.process) }.is_err() {
        rt::println!("POSIX startup: heap worker failed");
        return 125;
    }
    // SAFETY: startup owns initialization and the manager ranges are unused.
    if unsafe { posix_abi::threads::init(start.thread) }.is_err() {
        rt::println!("POSIX startup: thread worker failed");
        return 125;
    }
    posix_abi::tls::with_thread(1, || {
        // SAFETY: argv has count live C strings and a NULL sentinel; main is linked by C.
        let status = unsafe { main(count as c_int, arguments.as_mut_ptr()) };
        (status & 255) as u64
    })
}
