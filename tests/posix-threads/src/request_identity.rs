// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Native sender authentication on both QEMU and Apple VZ.

use core::{ffi::c_void, ptr};
use posix_abi::{process, threads};
use rt::{Handle, abi, handle::Channel, sys};

unsafe extern "C" fn sender(argument: *mut c_void) -> *mut c_void {
    let channel = Handle::<Channel>::borrowed(abi::Handle(argument as u64));
    let pid = process::getpid();
    let reply = sys::send(&channel, &(pid as u64).to_le_bytes());
    if reply.is_ok_and(|reply| reply.len == 0) {
        pid as usize as *mut c_void
    } else {
        ptr::null_mut()
    }
}

pub(super) fn run(expected: abi::ProcessIdentity) -> bool {
    let channel = sys::channel_create(1).expect("identity test channel");
    let mut thread = 0;
    if unsafe {
        threads::pthread_create(
            &mut thread,
            ptr::null(),
            Some(sender),
            channel.raw().0 as *mut c_void,
        )
    } != 0
    {
        return super::failed(480);
    }
    let sys::Received::Message { token, words, .. } =
        sys::receive(&channel).expect("identity request")
    else {
        return super::failed(481);
    };
    let first = token.sender_identity();
    let second = token.sender_identity();
    let reply = token.reply(&[]);
    let mut value = ptr::null_mut();
    let joined = unsafe { threads::pthread_join(thread, &mut value) };
    if first != Ok(expected)
        || second != first
        || words[0] != expected.id as u64
        || reply.is_err()
        || joined != 0
        || value as usize != expected.id as usize
    {
        return super::failed(482);
    }
    rt::println!(
        "request-identity-probe: authenticated native sender matches Rust PID/PPID; repeated reads preserve reply"
    );
    true
}
