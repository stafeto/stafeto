// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Sole-owner pending/ready results, reserved before effects and released by ACK.
use super::Cached;
use crate::allocation;
use core::ptr::{self, NonNull};
use posix_heap::Allocator;
use rt::{abi::Access, sys};

const BASE: usize = 0x2800_0000;
const LIMIT: usize = 0x3000_0000;
const CHUNK: usize = 65536;
struct Node {
    next: *mut Node,
    caller: u64,
    nonce: u64,
    answer: Option<Cached>,
}
pub(super) struct Journal {
    head: *mut Node,
    heap: Allocator,
}
impl Journal {
    pub(super) const fn new() -> Self {
        Self {
            head: ptr::null_mut(),
            heap: Allocator::new(),
        }
    }
    fn grow(&mut self) -> Result<(), ()> {
        let address = BASE.checked_add(self.heap.committed()).ok_or(())?;
        if address.checked_add(CHUNK).is_none_or(|end| end > LIMIT) {
            return Err(());
        }
        let memory = sys::mem_create(CHUNK as u64).map_err(|_| ())?;
        sys::mem_map(
            allocation::process(),
            &memory,
            0,
            CHUNK as u64,
            address,
            Access::ReadWrite,
        )
        .map_err(|_| ())?;
        // SAFETY: a fresh, writable mapping extends this sole owner's reserved
        // range. Its lifetime is the process lifetime, independent of malloc.
        unsafe {
            if self.heap.committed() == 0 {
                self.heap.init(address as *mut u8, CHUNK);
            } else {
                self.heap.extend(CHUNK);
            }
        }
        Ok(())
    }
    fn find(&self, caller: u64, nonce: u64) -> *mut Node {
        let mut node = self.head;
        while !node.is_null() {
            // SAFETY: the sole owner maintains allocated nodes until removal.
            unsafe {
                if (*node).caller == caller && (*node).nonce == nonce {
                    return node;
                }
                node = (*node).next;
            }
        }
        ptr::null_mut()
    }
    pub(super) fn reserve(&mut self, caller: u64, nonce: u64) -> Result<(), ()> {
        if !self.find(caller, nonce).is_null() {
            return Ok(());
        }
        let allocate = |heap: &mut Allocator| {
            heap.allocate(core::mem::size_of::<Node>(), core::mem::align_of::<Node>())
        };
        let storage = match allocate(&mut self.heap) {
            Ok(storage) => storage,
            Err(_) => {
                self.grow()?;
                allocate(&mut self.heap).map_err(|_| ())?
            }
        };
        let node = storage.as_ptr().cast::<Node>();
        // SAFETY: uniquely allocated aligned storage is initialized before linking.
        unsafe {
            node.write(Node {
                next: self.head,
                caller,
                nonce,
                answer: None,
            });
        }
        self.head = node;
        Ok(())
    }
    pub(super) fn ready(&self, caller: u64, nonce: u64) -> Option<Cached> {
        let node = self.find(caller, nonce);
        // SAFETY: the shared owner borrow prevents removal while copying.
        if node.is_null() {
            None
        } else {
            unsafe { (*node).answer }
        }
    }
    pub(super) fn complete(&mut self, caller: u64, answer: Cached) {
        let node = self.find(caller, answer.nonce);
        assert!(!node.is_null(), "reserved pthread result");
        // SAFETY: this exclusive owner borrow keeps the selected node live.
        unsafe {
            (*node).answer = Some(answer);
        }
    }
    pub(super) fn ack(&mut self, caller: u64, nonce: u64) {
        self.remove(caller, Some(nonce));
    }
    pub(super) fn forget(&mut self, caller: u64) {
        self.remove(caller, None);
    }
    fn remove(&mut self, caller: u64, nonce: Option<u64>) {
        let mut link = ptr::addr_of_mut!(self.head);
        // SAFETY: links point to the sole owner's head or a live predecessor.
        // Unlinking finishes before deallocation, and no node borrow escapes.
        unsafe {
            while !(*link).is_null() {
                let node = *link;
                if (*node).caller == caller && nonce.is_none_or(|n| (*node).nonce == n) {
                    *link = (*node).next;
                    self.heap.deallocate(NonNull::new_unchecked(node.cast()));
                    if nonce.is_some() {
                        return;
                    }
                } else {
                    link = ptr::addr_of_mut!((*node).next);
                }
            }
        }
    }
}
