// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! POSIX allocation bookkeeping. The owner supplies contiguous committed
//! storage, serializes calls and keeps that storage live until the heap dies.

#![no_std]

use core::{
    alloc::Layout,
    mem::size_of,
    ptr::{self, NonNull},
};
use linked_list_allocator::Heap;

pub const FUNDAMENTAL_ALIGNMENT: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidAlignment,
    NoMemory,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct Header {
    requested: usize,
    allocation: usize,
    alignment: usize,
    prefix: usize,
}

pub struct Allocator {
    heap: Heap,
}

impl Default for Allocator {
    fn default() -> Self {
        Self::new()
    }
}

impl Allocator {
    pub const fn new() -> Self {
        Self {
            heap: Heap::empty(),
        }
    }

    /// # Safety
    /// base is writable, uniquely owned storage of size bytes, kept live until
    /// this allocator and every allocation are discarded. Called only once.
    pub unsafe fn init(&mut self, base: *mut u8, size: usize) {
        unsafe { self.heap.init(base, size) };
    }

    /// # Safety
    /// size newly committed bytes immediately follow the existing heap and
    /// have the same ownership and lifetime as its original storage.
    pub unsafe fn extend(&mut self, size: usize) {
        unsafe { self.heap.extend(size) };
    }

    pub fn committed(&self) -> usize {
        self.heap.size()
    }
    pub fn used(&self) -> usize {
        self.heap.used()
    }

    pub fn required(size: usize, alignment: usize) -> Result<usize, Error> {
        Self::layout(size, alignment).map(|(layout, _)| layout.size())
    }

    fn layout(size: usize, alignment: usize) -> Result<(Layout, usize), Error> {
        if !alignment.is_power_of_two() {
            return Err(Error::InvalidAlignment);
        }
        let alignment = alignment.max(FUNDAMENTAL_ALIGNMENT);
        let prefix = size_of::<Header>()
            .checked_add(alignment - 1)
            .ok_or(Error::NoMemory)?
            & !(alignment - 1);
        let total = prefix.checked_add(size.max(1)).ok_or(Error::NoMemory)?;
        let layout = Layout::from_size_align(total, alignment).map_err(|_| Error::NoMemory)?;
        Ok((layout, prefix))
    }

    pub fn allocate(&mut self, size: usize, alignment: usize) -> Result<NonNull<u8>, Error> {
        let (layout, prefix) = Self::layout(size, alignment)?;
        let base = self
            .heap
            .allocate_first_fit(layout)
            .map_err(|_| Error::NoMemory)?;
        // SAFETY: the reserved prefix fits Header; the payload stays in this allocation.
        let payload = unsafe { base.as_ptr().add(prefix) };
        let header = unsafe { payload.sub(size_of::<Header>()).cast::<Header>() };
        unsafe {
            header.write(Header {
                requested: size,
                allocation: layout.size(),
                alignment: layout.align(),
                prefix,
            })
        };
        Ok(unsafe { NonNull::new_unchecked(payload) })
    }

    /// # Safety
    /// pointer names a live allocation from this allocator.
    pub unsafe fn alignment(pointer: NonNull<u8>) -> usize {
        unsafe { (*pointer.as_ptr().sub(size_of::<Header>()).cast::<Header>()).alignment }
    }

    /// The bytes the caller asked for in the live allocation `pointer`.
    ///
    /// # Safety
    /// pointer names a live allocation from this allocator.
    pub unsafe fn requested(pointer: NonNull<u8>) -> usize {
        unsafe { (*pointer.as_ptr().sub(size_of::<Header>()).cast::<Header>()).requested }
    }

    /// # Safety
    /// pointer names a currently live allocation from this allocator, with no
    /// overlapping accesses. It may not be used again after this call.
    pub unsafe fn deallocate(&mut self, pointer: NonNull<u8>) {
        let header = unsafe {
            pointer
                .as_ptr()
                .sub(size_of::<Header>())
                .cast::<Header>()
                .read()
        };
        let layout = Layout::from_size_align(header.allocation, header.alignment).unwrap();
        let base = unsafe { NonNull::new_unchecked(pointer.as_ptr().sub(header.prefix)) };
        unsafe { self.heap.deallocate(base, layout) };
    }

    /// # Safety
    /// pointer satisfies deallocate's contract. Success invalidates the old
    /// pointer unless it is returned again. Failure keeps its bytes and lifetime.
    pub unsafe fn reallocate(
        &mut self,
        pointer: NonNull<u8>,
        size: usize,
    ) -> Result<NonNull<u8>, Error> {
        let address = unsafe { pointer.as_ptr().sub(size_of::<Header>()).cast::<Header>() };
        let mut header = unsafe { address.read() };
        if size <= header.requested {
            header.requested = size;
            unsafe { address.write(header) };
            return Ok(pointer);
        }
        let replacement = self.allocate(size, header.alignment)?;
        unsafe {
            ptr::copy_nonoverlapping(pointer.as_ptr(), replacement.as_ptr(), header.requested)
        };
        unsafe { self.deallocate(pointer) };
        Ok(replacement)
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    #[repr(align(4096))]
    struct Region([u8; 65536]);

    #[test]
    fn extension_preserves_live_data_and_coalesces_across_the_boundary() {
        let mut region = Region([0; 65536]);
        let mut allocator = Allocator::new();
        unsafe { allocator.init(region.0.as_mut_ptr(), 32768) };
        let first = allocator.allocate(30000, 16).unwrap();
        unsafe { first.as_ptr().write_bytes(91, 30000) };
        assert_eq!(allocator.allocate(32000, 16), Err(Error::NoMemory));
        unsafe { allocator.extend(32768) };
        let second = allocator.allocate(32000, 16).unwrap();
        unsafe { second.as_ptr().write_bytes(37, 32000) };
        for index in 0..30000 {
            assert_eq!(unsafe { first.as_ptr().add(index).read() }, 91);
        }
        unsafe {
            allocator.deallocate(first);
            allocator.deallocate(second);
        }
        assert_eq!(allocator.used(), 0);
        let large = allocator.allocate(65000, 16).unwrap();
        unsafe { allocator.deallocate(large) };
    }

    #[test]
    fn alignment_zero_sizes_coalescing_and_overflow() {
        let mut region = Region([0xaa; 65536]);
        let mut allocator = Allocator::new();
        unsafe { allocator.init(region.0.as_mut_ptr(), region.0.len()) };
        let a = allocator.allocate(0, 16).unwrap();
        let b = allocator.allocate(256, 4096).unwrap();
        let c = allocator.allocate(47, 16).unwrap();
        assert_eq!(a.as_ptr() as usize % 16, 0);
        assert_eq!(b.as_ptr() as usize % 4096, 0);
        assert_ne!(a, c);
        assert_eq!(allocator.allocate(1, 3), Err(Error::InvalidAlignment));
        assert_eq!(allocator.allocate(usize::MAX, 16), Err(Error::NoMemory));
        unsafe {
            allocator.deallocate(b);
            allocator.deallocate(a);
            allocator.deallocate(c);
        }
        assert_eq!(allocator.used(), 0);
        let large = allocator.allocate(65000, 16).unwrap();
        unsafe { allocator.deallocate(large) };
    }

    #[test]
    fn realloc_preserves_bytes_failure_and_alignment_and_reuses_shrink() {
        let mut region = Region([0; 65536]);
        let mut allocator = Allocator::new();
        unsafe { allocator.init(region.0.as_mut_ptr(), region.0.len()) };
        let a = allocator.allocate(31, 256).unwrap();
        for i in 0..31 {
            unsafe { a.as_ptr().add(i).write(i as u8) };
        }
        assert_eq!(
            unsafe { allocator.reallocate(a, usize::MAX) },
            Err(Error::NoMemory)
        );
        let b = unsafe { allocator.reallocate(a, 511) }.unwrap();
        assert_eq!(b.as_ptr() as usize % 256, 0);
        for i in 0..31 {
            assert_eq!(unsafe { b.as_ptr().add(i).read() }, i as u8);
        }
        assert_eq!(unsafe { allocator.reallocate(b, 7) }, Ok(b));
        unsafe { allocator.deallocate(b) };
        assert_eq!(allocator.used(), 0);
    }

    #[test]
    fn deterministic_fragmentation_preserves_disjoint_live_patterns() {
        let mut region = Region([0; 65536]);
        let mut allocator = Allocator::new();
        unsafe { allocator.init(region.0.as_mut_ptr(), region.0.len()) };
        let mut live: Vec<(NonNull<u8>, usize, u8)> = Vec::new();
        let mut seed = 1234567u32;
        for step in 0..2000 {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            if !live.is_empty() && seed.is_multiple_of(3) {
                let index = seed as usize % live.len();
                let (ptr, count, byte) = live.swap_remove(index);
                for i in 0..count {
                    assert_eq!(unsafe { ptr.as_ptr().add(i).read() }, byte);
                }
                unsafe { allocator.deallocate(ptr) };
            } else {
                let size = (seed as usize % 257) + 1;
                if let Ok(ptr) = allocator.allocate(size, 16) {
                    let byte = step as u8;
                    unsafe { ptr.as_ptr().write_bytes(byte, size) };
                    live.push((ptr, size, byte));
                }
            }
        }
        for (ptr, count, byte) in live {
            for i in 0..count {
                assert_eq!(unsafe { ptr.as_ptr().add(i).read() }, byte);
            }
            unsafe { allocator.deallocate(ptr) };
        }
        assert_eq!(allocator.used(), 0);
    }
}
