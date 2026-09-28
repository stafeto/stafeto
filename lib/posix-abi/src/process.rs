// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Numeric process identity. Startup publishes the native process handle before
//! C entry. Queries allocate nothing and do not touch errno or application TLS.
use crate::allocation;

fn identity() -> rt::abi::ProcessIdentity {
    rt::sys::process_identity(allocation::process()).expect("live process identity")
}

#[unsafe(no_mangle)]
pub extern "C" fn getpid() -> i32 {
    i32::try_from(identity().id).expect("positive signed process namespace")
}

#[unsafe(no_mangle)]
pub extern "C" fn getppid() -> i32 {
    i32::try_from(identity().parent).expect("signed parent process namespace")
}
