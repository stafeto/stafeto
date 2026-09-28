// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Prepaid live-block metadata and independent retained allocation outcomes.
use super::{ALLOC, FREE, REALLOC, ZERO, config};
use crate::constants::*;
use core::ptr::{self, NonNull};
use posix_heap::Allocator;
use rt::{abi::Access, sys};

const BASE: usize = 0x3000_0000;
const LIMIT: usize = 0x3800_0000;
const CHUNK: usize = 65536;
pub(super) struct Node {
    next: *mut Node,
    nonce: u64,
    args: [u64; 4],
    pointer: usize,
    answer: Option<(i32, usize)>,
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
            &config().process,
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
    fn find(&self, nonce: u64) -> *mut Node {
        let mut node = self.head;
        while !node.is_null() {
            // SAFETY: this sole owner keeps nodes linked until their final ACK.
            unsafe {
                if (*node).nonce == nonce {
                    return node;
                }
                node = (*node).next;
            }
        }
        ptr::null_mut()
    }
    pub(super) fn ready(&self, nonce: u64, args: [u64; 4]) -> Option<(i32, usize)> {
        let node = self.find(nonce);
        if node.is_null() {
            return None;
        }
        // SAFETY: an immutable owner borrow prevents removal while copying.
        unsafe {
            Some(if (*node).args != args {
                (EINVAL, 0)
            } else {
                (*node).answer.expect("completed heap operation")
            })
        }
    }
    pub(super) fn reserve(&mut self, nonce: u64, args: [u64; 4]) -> Result<NonNull<Node>, i32> {
        let [op, _, _, pointer] = args;
        if !matches!(op, ALLOC | ZERO | REALLOC | FREE) {
            return Err(EINVAL);
        }
        if pointer != 0 && matches!(op, REALLOC | FREE) {
            let mut node = self.head;
            while !node.is_null() {
                // SAFETY: sole owner, allocated nodes; compare integer addresses
                // before accessing any application pointer or allocator header.
                unsafe {
                    if (*node).nonce == 0 && (*node).pointer == pointer as usize {
                        (*node).nonce = nonce;
                        (*node).args = args;
                        return Ok(NonNull::new_unchecked(node));
                    }
                    node = (*node).next;
                }
            }
            return Err(EINVAL);
        }
        #[cfg(feature = "transport-probe")]
        if super::REJECT_NEW.load(core::sync::atomic::Ordering::Acquire) {
            return Err(ENOMEM);
        }
        let allocate = |heap: &mut Allocator| {
            heap.allocate(core::mem::size_of::<Node>(), core::mem::align_of::<Node>())
        };
        let storage = match allocate(&mut self.heap) {
            Ok(storage) => storage,
            Err(_) => {
                self.grow().map_err(|_| ENOMEM)?;
                allocate(&mut self.heap).map_err(|_| ENOMEM)?
            }
        };
        let node = storage.as_ptr().cast::<Node>();
        // SAFETY: aligned unique storage is initialized before publication.
        unsafe {
            node.write(Node {
                next: self.head,
                nonce,
                args,
                pointer: 0,
                answer: None,
            });
        }
        self.head = node;
        Ok(unsafe { NonNull::new_unchecked(node) })
    }
    pub(super) fn complete(&mut self, node: NonNull<Node>, result: (i32, usize)) {
        // SAFETY: reserve returned this node to the sole owner; it stays linked.
        let node = unsafe { &mut *node.as_ptr() };
        if result.0 == 0 {
            node.pointer = if node.args[0] == FREE { 0 } else { result.1 };
        }
        node.answer = Some(result);
    }
    pub(super) fn ack(&mut self, nonce: u64) {
        let mut link = ptr::addr_of_mut!(self.head);
        // SAFETY: exclusive owner links point to head or an allocated predecessor.
        // Live blocks keep their paid metadata; freed/failed records are unlinked
        // before deallocation. No node borrow escapes the operation.
        unsafe {
            while !(*link).is_null() {
                let node = *link;
                if (*node).nonce == nonce {
                    if (*node).pointer != 0 {
                        (*node).nonce = 0;
                        (*node).args = [0; 4];
                        (*node).answer = None;
                    } else {
                        *link = (*node).next;
                        self.heap.deallocate(NonNull::new_unchecked(node.cast()));
                    }
                    return;
                }
                link = ptr::addr_of_mut!((*node).next);
            }
        }
    }
    #[cfg(feature = "transport-probe")]
    pub(super) fn stats(&self) -> (usize, usize) {
        (self.heap.used(), self.heap.committed())
    }
}
