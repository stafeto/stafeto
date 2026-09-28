// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Session replies reserved before effects, released only by ACK or disconnect.
use core::ptr::{self, NonNull};
use posix_heap::Allocator;
use proto_process::Change;
use rt::handle::{Handle, Process};
use rt::{abi::Access, sys};

const BASE: usize = 0x2800_0000;
const LIMIT: usize = 0x3000_0000;
const CHUNK: usize = 65536;
#[derive(Clone, Copy)]
pub(super) enum Reply {
    Change {
        operation: Change,
        id: u32,
        result: Result<(), posix_credentials::Error>,
    },
}
struct Node {
    next: *mut Node,
    label: u64,
    nonce: u64,
    pid: u32,
    answer: Option<Reply>,
}
pub(super) struct Journal {
    head: *mut Node,
    heap: Allocator,
    process: Handle<Process>,
    #[cfg(feature = "transport-probe")]
    pub(super) reject: Option<u64>,
}
impl Journal {
    pub(super) fn new(process: Handle<Process>) -> Self {
        Self {
            head: ptr::null_mut(),
            heap: Allocator::new(),
            process,
            #[cfg(feature = "transport-probe")]
            reject: None,
        }
    }
    fn grow(&mut self) -> Result<(), ()> {
        let address = BASE.checked_add(self.heap.committed()).ok_or(())?;
        if address.checked_add(CHUNK).is_none_or(|end| end > LIMIT) {
            return Err(());
        }
        let memory = sys::mem_create(CHUNK as u64).map_err(|_| ())?;
        sys::mem_map(
            &self.process,
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
    fn find(&self, pid: u32, label: u64, nonce: u64) -> *mut Node {
        let mut node = self.head;
        while !node.is_null() {
            // SAFETY: the sole owner maintains allocated nodes until removal.
            unsafe {
                if (*node).pid == pid && (*node).label == label && (*node).nonce == nonce {
                    return node;
                }
                node = (*node).next;
            }
        }
        ptr::null_mut()
    }
    pub(super) fn reserve(&mut self, pid: u32, label: u64, nonce: u64) -> Result<(), ()> {
        if !self.find(pid, label, nonce).is_null() {
            return Ok(());
        }
        #[cfg(feature = "transport-probe")]
        if self.reject == Some(label) {
            return Err(());
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
                label,
                nonce,
                pid,
                answer: None,
            });
        }
        self.head = node;
        Ok(())
    }
    pub(super) fn ready(&self, pid: u32, label: u64, nonce: u64) -> Option<Reply> {
        let node = self.find(pid, label, nonce);
        // SAFETY: the shared owner borrow prevents removal while copying.
        if node.is_null() {
            None
        } else {
            unsafe { (*node).answer }
        }
    }
    pub(super) fn complete(&mut self, pid: u32, label: u64, nonce: u64, answer: Reply) {
        let node = self.find(pid, label, nonce);
        assert!(!node.is_null(), "reserved process result");
        // SAFETY: this exclusive owner borrow keeps the selected node live.
        unsafe {
            (*node).answer = Some(answer);
        }
    }
    pub(super) fn ack(&mut self, pid: u32, label: u64, nonce: u64) {
        self.remove(Some(pid), Some(label), Some(nonce));
    }
    pub(super) fn forget(&mut self, label: u64) {
        self.remove(None, Some(label), None);
    }
    pub(super) fn forget_process(&mut self, pid: u32) {
        self.remove(Some(pid), None, None);
    }
    #[cfg(feature = "transport-probe")]
    pub(super) fn stats(&self) -> (u64, u64, u64, u64) {
        (
            self.heap.used() as u64,
            self.heap.committed() as u64,
            sys::process_handles(&self.process)
                .expect("process service handles")
                .live as u64,
            sys::process_memory(&self.process)
                .expect("process service memory")
                .used as u64,
        )
    }
    fn remove(&mut self, pid: Option<u32>, label: Option<u64>, nonce: Option<u64>) {
        let mut link = ptr::addr_of_mut!(self.head);
        // SAFETY: links point to the sole owner's head or a live predecessor.
        // Unlinking finishes before deallocation, and no node borrow escapes.
        unsafe {
            while !(*link).is_null() {
                let node = *link;
                if pid.is_none_or(|p| (*node).pid == p)
                    && label.is_none_or(|l| (*node).label == l)
                    && nonce.is_none_or(|n| (*node).nonce == n)
                {
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
