// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use super::handle::{Handle, Process, Thread};
use abi::{Access, Error, Policy, Rights};
use bootimg::Part;
fn access(p: Part) -> Access {
    match p {
        Part::Code => Access::ReadExec,
        Part::Rodata => Access::Read,
        Part::Data => Access::ReadWrite,
    }
}
fn first_thread(_: &Handle<Process>, _: u64, _: u8, _: Policy) -> Result<Handle<Thread>, Error> {
    super::sys::call()?;
    Ok(super::sys::new(Rights::ALL))
}
#[path = "../../../lib/rt/src/loader/retained.rs"]
pub mod retained;
