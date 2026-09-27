// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Read the same e2fsprogs image as the host tests, inside the guest.

#![no_std]
#![no_main]

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};
use ext4ro::{OutOfRange, ReadAt};

rt::entry!(main);

const IMAGE: &[u8] = include_bytes!("../../../lib/ext4ro/tests/ext4.img");
const HEAP_SIZE: usize = 2 * 1024 * 1024;

#[repr(align(16))]
struct Heap([u8; HEAP_SIZE]);

static mut HEAP: Heap = Heap([0; HEAP_SIZE]);
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Bump;

#[global_allocator]
static ALLOCATOR: Bump = Bump;

unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: only the address is formed; allocations use atomic offsets.
        let base = unsafe { ptr::addr_of_mut!(HEAP.0).cast::<u8>() as usize };
        let mut current = NEXT.load(Ordering::Relaxed);
        loop {
            let aligned = match base
                .checked_add(current)
                .and_then(|addr| addr.checked_add(layout.align() - 1))
                .map(|addr| addr & !(layout.align() - 1))
            {
                Some(addr) => addr,
                None => return ptr::null_mut(),
            };
            let end = match aligned
                .checked_sub(base)
                .and_then(|offset| offset.checked_add(layout.size()))
            {
                Some(end) if end <= HEAP_SIZE => end,
                _ => return ptr::null_mut(),
            };
            match NEXT.compare_exchange_weak(current, end, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return aligned as *mut u8,
                Err(value) => current = value,
            }
        }
    }

    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
}

struct Image;

impl ReadAt for Image {
    type Error = OutOfRange;

    fn read_exact_at(&mut self, offset: u64, out: &mut [u8]) -> Result<(), OutOfRange> {
        let start = usize::try_from(offset).map_err(|_| OutOfRange)?;
        let end = start.checked_add(out.len()).ok_or(OutOfRange)?;
        let bytes = IMAGE.get(start..end).ok_or(OutOfRange)?;
        out.copy_from_slice(bytes);
        Ok(())
    }
}

fn main(_: u64) -> u64 {
    let result = ext4ro::mount(Image, IMAGE.len() as u64).and_then(|fs| fs.read("/boot/message"));
    match result {
        Ok(bytes) if bytes == b"hello from ext4\n" => {
            rt::println!("ext4ro: guest read ok");
            0
        }
        Ok(_) => {
            rt::println!("ext4ro: wrong contents");
            1
        }
        Err(err) => {
            rt::println!("ext4ro: {err}");
            1
        }
    }
}
