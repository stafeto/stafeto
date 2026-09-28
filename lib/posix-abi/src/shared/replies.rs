// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Sole-owner reply journal. Reserve before effects; release only the matching nonce.
use crate::constants::ENOMEM;
use core::ptr::{self, NonNull};
use posix_heap::Allocator;
use proto_wire::Writer;
use rt::{
    abi::Access,
    handle::{Handle, Process},
    sys,
};

// Private owner storage works before process malloc is initialized. Committed
// chunks are retained for reuse until process exit, just like the main heap.
const BASE: usize = 0x2000_0000;
const LIMIT: usize = 0x2800_0000;
const CHUNK: usize = 65536;
struct Node {
    next: *mut Node,
    nonce: u64,
    reply: Writer,
}
pub(super) struct Journal<'a> {
    head: *mut Node,
    heap: Allocator,
    process: &'a Handle<Process>,
}
impl<'a> Journal<'a> {
    pub(super) const fn new(process: &'a Handle<Process>) -> Self {
        Self {
            head: ptr::null_mut(),
            heap: Allocator::new(),
            process,
        }
    }
    fn grow(&mut self) -> Result<(), i32> {
        let address = BASE.checked_add(self.heap.committed()).ok_or(ENOMEM)?;
        if address.checked_add(CHUNK).is_none_or(|end| end > LIMIT) {
            return Err(ENOMEM);
        }
        let memory = sys::mem_create(CHUNK as u64).map_err(|_| ENOMEM)?;
        sys::mem_map(
            self.process,
            &memory,
            0,
            CHUNK as u64,
            address,
            Access::ReadWrite,
        )
        .map_err(|_| ENOMEM)?;
        // SAFETY: a fresh disjoint mapping extends the sole owner's reserved range.
        // The kernel mapping retains its memory object after the handle is closed.
        unsafe {
            if self.heap.committed() == 0 {
                self.heap.init(address as *mut u8, CHUNK);
            } else {
                self.heap.extend(CHUNK);
            }
        }
        Ok(())
    }
    fn find(&self, nonce: u64) -> *mut Node {
        let mut node = self.head;
        while !node.is_null() {
            // SAFETY: only this worker owns/mutates the list and every node stays allocated.
            if unsafe { (*node).nonce } == nonce {
                return node;
            }
            node = unsafe { (*node).next };
        }
        ptr::null_mut()
    }
    pub(super) fn reserve(&mut self, nonce: u64) -> Result<(), i32> {
        assert!(self.find(nonce).is_null(), "fresh file transaction");
        let allocate = |heap: &mut Allocator| {
            heap.allocate(core::mem::size_of::<Node>(), core::mem::align_of::<Node>())
        };
        let storage = match allocate(&mut self.heap) {
            Ok(storage) => storage,
            Err(_) => {
                self.grow()?;
                allocate(&mut self.heap).map_err(|_| ENOMEM)?
            }
        };
        let node = storage.as_ptr().cast::<Node>();
        // SAFETY: the allocator supplies unique, aligned storage; initialization
        // finishes before linking it. No handler is bound on the owner thread.
        unsafe {
            node.write(Node {
                next: self.head,
                nonce,
                reply: Writer::new(),
            })
        };
        self.head = node;
        Ok(())
    }
    pub(super) fn output(&mut self, nonce: u64) -> &mut Writer {
        let node = self.find(nonce);
        assert!(!node.is_null(), "reserved file transaction");
        // SAFETY: this exclusive list borrow excludes all other node access.
        unsafe { &mut (*node).reply }
    }
    pub(super) fn reply(&self, nonce: u64) -> Option<&[u8]> {
        let node = self.find(nonce);
        // SAFETY: the list borrow keeps the owned node alive; removal needs &mut self.
        (!node.is_null()).then(|| unsafe { (*node).reply.as_bytes() })
    }
    pub(super) fn ack(&mut self, nonce: u64) {
        let mut link = ptr::addr_of_mut!(self.head);
        // SAFETY: links refer only to the sole owner's head or an allocated predecessor;
        // reading/copying the next link finishes before the removed node is freed.
        unsafe {
            while !(*link).is_null() {
                let node = *link;
                if (*node).nonce == nonce {
                    *link = (*node).next;
                    self.heap.deallocate(NonNull::new_unchecked(node.cast()));
                    return;
                }
                link = ptr::addr_of_mut!((*node).next);
            }
        }
    }
}
