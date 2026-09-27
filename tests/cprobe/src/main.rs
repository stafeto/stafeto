// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Run a statically linked Picolibc C program against the RAM file service.

#![no_std]
#![no_main]

use rt::handle::Resource;

rt::entry!(main);

unsafe extern "C" {
    fn c_probe() -> i32;
}

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    if posix_bridge::init(&start.parent).is_err() {
        return 2;
    }
    // SAFETY: C code is linked into this program and uses the POSIX bridge.
    let code = unsafe { c_probe() };
    if code == 0 {
        rt::println!("cprobe: ok");
    } else {
        rt::println!("cprobe: failed {code}");
    }
    code as u64
}
