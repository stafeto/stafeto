// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The loader's heap never frees (boot/efi-loader/src/arena.rs), so every
//! copy of the seed that a build leaves in it stays in RAM, which the kernel
//! takes as free memory (LoaderData). This test runs the loader's steps on a
//! heap of the same kind, one that never frees, and scans the whole of it
//! afterwards: the mixing of the sources, the tree with the placeholder, the
//! patch into the tree's room and the erasure of the blob must leave none of
//! the seed in the heap. The break `break-seed-in-heap` builds the tree with
//! the seed itself and the scan finds it.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};
use firmware_tree::acpi::{Table, Tables};
use firmware_tree::efimap::{Desc, classify};
use firmware_tree::platform::Platform;
use firmware_tree::seed::{self, SEED_BYTES};
use firmware_tree::tree::{Input, build};
use kcore::bootinfo::Region;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/qemu-efi");
const MAP: &[u8] = include_bytes!("fixtures/qemu-efi/memmap.bin");
const KERNEL: Region = Region {
    base: 0x4000_0000,
    size: 0x1d_0000,
};
const TREE: Region = Region {
    base: 0x401d_0000,
    size: 0x1_0000,
};
const IMAGE: Region = Region {
    base: 0x4800_0000,
    size: 0x3_2000,
};

fn tables() -> Tables<'static> {
    let mut names: Vec<_> = std::fs::read_dir(DIR)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".bin") && n.as_bytes()[2] == b'-')
        .collect();
    names.sort();
    let mut out = Vec::new();
    for name in names {
        let data: &'static [u8] = Box::leak(
            std::fs::read(format!("{DIR}/{name}"))
                .unwrap()
                .into_boxed_slice(),
        );
        out.push(Table {
            signature: data[..4].try_into().unwrap(),
            revision: data[8],
            data,
        });
    }
    Tables {
        tables: out,
        rejected: Vec::new(),
    }
}

fn map() -> Vec<Desc> {
    let u64_at = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    MAP.as_chunks::<32>()
        .0
        .iter()
        .map(|r| Desc {
            ty: u64_at(r, 0) as u32,
            phys: u64_at(r, 8),
            pages: u64_at(r, 16),
            attr: u64_at(r, 24),
        })
        .collect()
}

/// The tree with `seed` as the value of `rng-seed`, as the loader builds it.
fn tree_with(seed: &[u8]) -> Vec<u8> {
    let platform = Platform::from_tables(&tables()).unwrap();
    let memory = classify(&map(), &[KERNEL, TREE, IMAGE]).unwrap();
    build(&Input {
        platform: &platform,
        memory: &memory,
        initrd: IMAGE,
        boot_mpidr: 0,
        seed,
    })
    .unwrap()
}

const SIZE: usize = 64 << 20;

#[repr(align(4096))]
struct Block(UnsafeCell<[u8; SIZE]>);

struct Bump {
    block: Block,
    used: AtomicUsize,
}

// SAFETY: offsets are claimed with an atomic exchange; no two overlap.
unsafe impl Sync for Bump {}

// SAFETY: `alloc` returns disjoint aligned ranges or null; nothing is freed.
unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let base = self.block.0.get() as usize;
        let mut used = self.used.load(Ordering::Relaxed);
        loop {
            let start = (base + used).next_multiple_of(layout.align()) - base;
            let end = start + layout.size();
            if end > SIZE {
                return core::ptr::null_mut();
            }
            match self
                .used
                .compare_exchange(used, end, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return (base + start) as *mut u8,
                Err(now) => used = now,
            }
        }
    }

    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
}

#[global_allocator]
static HEAP: Bump = Bump {
    block: Block(UnsafeCell::new([0; SIZE])),
    used: AtomicUsize::new(0),
};

/// Whether any run of 16 bytes of `seed` lies in the used part of the heap.
fn heap_holds(seed: &[u8; SEED_BYTES]) -> bool {
    let used = HEAP.used.load(Ordering::Relaxed);
    // SAFETY: the first `used` bytes of the block were handed out and are initialised.
    let heap = unsafe { core::slice::from_raw_parts(HEAP.block.0.get().cast::<u8>(), used) };
    seed.windows(16)
        .step_by(8)
        .any(|w| heap.windows(16).any(|h| h == w))
}

#[test]
fn the_heap_holds_no_byte_of_the_seed_after_the_loaders_steps() {
    let efi: Vec<u8> = (0..64u8)
        .map(|i| i.wrapping_mul(37).wrapping_add(11))
        .collect();
    let trng: Vec<u8> = (0..72u8)
        .map(|i| i.wrapping_mul(91).wrapping_add(5))
        .collect();
    let mut gathered = [efi, trng];
    let mut mixed = seed::mix(&[&gathered[0], &gathered[1]]).unwrap();
    for g in gathered.iter_mut() {
        posix_random::erase(g);
    }
    // The tree is built with the placeholder, twice as the loader does, and
    // each blob is erased once it is in the room.
    // The tree's room is the loader's own memory, outside its heap.
    let mut room = [0u8; 1 << 16];
    let mut at = 0;
    for _ in 0..2 {
        let placeholder = seed::for_tree(&mixed);
        let mut blob = tree_with(&placeholder);
        at = blob
            .windows(SEED_BYTES)
            .position(|w| w == placeholder)
            .expect("the placeholder is in the tree");
        room[..blob.len()].copy_from_slice(&blob);
        posix_random::erase(&mut blob);
    }
    assert!(seed::patch(&mut room, at, &mixed));
    // The room, which the kernel clears, holds the seed.
    assert_eq!(&room[at..at + SEED_BYTES], &mixed);
    assert!(!heap_holds(&mixed), "a copy of the seed stays in the heap");
    posix_random::erase(&mut mixed);
}
