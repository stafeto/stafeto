// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! One service-owned page of complete PID lifetimes, published read-only.

use proto_process::lifetimes::Page;
use rt::abi::{Access, Error, Rights};
use rt::handle::{Handle, Memory, Process};
use rt::sys;
const BASE: usize = 0x43_0000_0000;
const BYTES: u64 = 4096;
pub struct Lifetimes {
    object: Option<Handle<Memory>>,
}
impl Lifetimes {
    pub const fn new() -> Self {
        Self { object: None }
    }
    pub fn make(&mut self, own: &Handle<Process>) -> Result<(), Error> {
        const { assert!(core::mem::size_of::<Page>() <= BYTES as usize) };
        let object = sys::mem_create(BYTES)?;
        sys::mem_map(own, &object, 0, BYTES, BASE, Access::ReadWrite)?;
        // SAFETY: the exclusive service mapping contains aligned writable Page storage.
        unsafe { (BASE as *mut Page).write(Page::new()) };
        self.object = Some(object);
        Ok(())
    }
    fn page(&self) -> &Page {
        assert!(self.object.is_some());
        // SAFETY: make initialized the aligned permanent service mapping.
        unsafe { &*(BASE as *const Page) }
    }
    pub fn publish(&self, pid: u32) {
        self.page()
            .publish(pid)
            .expect("new or continuing live PID");
    }
    pub fn retire(&self, pid: u32) {
        self.page().retire(pid);
    }
    #[cfg(feature = "lifetime-probe")]
    pub fn live(&self, pid: u32) -> bool {
        self.page().live(pid)
    }
    pub fn copy(&self) -> Result<Handle<Memory>, Error> {
        let object = self.object.as_ref().ok_or(Error::BadState)?;
        sys::handle_duplicate(object, Rights::MAP_READ | Rights::TRANSFER)
    }
}
