// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Native guest threads that relibc did not start: a thread the layer did
//! not attach gets a TCB in relibc's layout for its outermost scope
//! (posix-thread): the register names its ABI word, the word the TCB, the
//! layer's block 32 bytes on, and the register is 0 again after the scope;
//! a nested scope keeps the block. Two such threads have two blocks and
//! share the process's pages (`map_pages`).

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicUsize, Ordering};
use posix_abi::{allocation, tls};
use rt::{Stack, abi::Policy, sys};

rt::entry!(main);

static STACK: Stack<16384> = Stack::new();
static BLOCK: AtomicUsize = AtomicUsize::new(0);
static DONE: AtomicUsize = AtomicUsize::new(0);
static FAILURE: AtomicUsize = AtomicUsize::new(0);
static TRANSFER: AtomicUsize = AtomicUsize::new(0);
static RETURNED: AtomicUsize = AtomicUsize::new(0);
const PAGE: usize = 4096;

/// The calling thread's block found through the register, the ABI word
/// and the TCB; 0 when the chain is broken.
fn chained() -> usize {
    let word = posix_thread::thread_pointer();
    if word == 0 {
        return 0;
    }
    // SAFETY: the register names this thread's ABI word.
    let tcb = unsafe { *(word as *const usize) };
    // SAFETY: the word names the TCB; relibc's layout owns its first four words.
    let generic = unsafe { *(tcb as *const [usize; 4]) };
    let block = tcb + posix_thread::BLOCK_OFFSET;
    if tcb == word + posix_thread::TCB_OFFSET
        && generic[..3] == [tcb, 0, tcb]
        && block == posix_thread::block() as usize
    {
        block
    } else {
        0
    }
}

fn failed(code: usize) -> bool {
    FAILURE.store(code, Ordering::Release);
    false
}

extern "C" fn worker(done_channel: u64) -> ! {
    let passed = tls::with_process(|| {
        let block = chained();
        if block == 0 {
            return failed(19);
        }
        BLOCK.store(block, Ordering::Release);
        // The main thread's page, which it gave over.
        let input = TRANSFER.load(Ordering::Acquire) as *mut u8;
        if input.is_null() {
            return failed(1);
        }
        for index in 0..43 {
            // SAFETY: the main thread wrote the page and gave it over.
            if unsafe { input.add(index).read() } != index as u8 {
                return failed(2);
            }
        }
        // SAFETY: the page came from map_pages and nobody else uses it.
        unsafe { allocation::unmap_pages(core::ptr::NonNull::new_unchecked(input), PAGE) };
        let Ok(output) = allocation::map_pages(PAGE) else {
            return failed(4);
        };
        // SAFETY: the page is this thread's until it gives it over.
        unsafe { output.as_ptr().write_bytes(77, 91) };
        RETURNED.store(output.as_ptr() as usize, Ordering::Release);
        for _ in 0..8 {
            if sys::yield_now().is_err() || chained() != block {
                return failed(5);
            }
        }
        true
    });
    DONE.store(if passed { 1 } else { 2 }, Ordering::Release);
    let channel =
        rt::handle::Handle::<rt::handle::Channel>::borrowed(rt::abi::Handle(done_channel));
    let _ = sys::notify(&channel, 1);
    sys::thread_exit()
}

fn main(_: u64) -> u64 {
    let Some(own) = rt::init_handles() else {
        return 1;
    };
    rt::console::set(own.resource);
    // SAFETY: only the initial thread exists; the heap ranges are unused.
    if unsafe {
        allocation::init(
            match sys::handle_duplicate(&own.process, rt::abi::Rights::MANAGE) {
                Ok(process) => process,
                Err(_) => return 3,
            },
        )
    }
    .is_err()
    {
        return 3;
    }
    if posix_thread::thread_pointer() != 0 {
        return 4;
    }
    let passed = tls::with_process(|| {
        let block = chained();
        if block == 0 {
            return failed(20);
        }
        let Ok(transfer) = allocation::map_pages(PAGE) else {
            return failed(6);
        };
        for index in 0..43 {
            // SAFETY: the page is this thread's until it gives it over.
            unsafe { transfer.as_ptr().add(index).write(index as u8) };
        }
        TRANSFER.store(transfer.as_ptr() as usize, Ordering::Release);
        // A nested scope keeps the block.
        if tls::with_process(chained) != block {
            return failed(7);
        }
        let Ok(completion) = sys::channel_create(63) else {
            return failed(17);
        };
        // SAFETY: the static stack is used once by this worker. The buffer
        // page is outside program segments and the initial message buffer.
        let Ok(thread) = (unsafe {
            sys::thread_create(
                &own.process,
                worker,
                STACK.top(),
                completion.raw().0,
                63,
                Policy::Fifo,
                0x900000,
            )
        }) else {
            return failed(8);
        };
        if sys::thread_start(&thread).is_err() {
            return failed(9);
        }
        for _ in 0..32 {
            if chained() != block {
                return failed(10);
            }
            let Ok(page) = allocation::map_pages(PAGE) else {
                return failed(14);
            };
            // SAFETY: the page came from map_pages just now.
            unsafe { allocation::unmap_pages(page, PAGE) };
            if sys::yield_now().is_err() {
                return failed(15);
            }
        }
        if sys::receive(&completion).is_err() {
            return failed(18);
        }
        if DONE.load(Ordering::Acquire) != 1 || BLOCK.load(Ordering::Acquire) == block {
            return failed(11);
        }
        let output = RETURNED.load(Ordering::Acquire) as *mut u8;
        if output.is_null() {
            return failed(12);
        }
        for index in 0..91 {
            // SAFETY: the worker wrote the page and gave it over.
            if unsafe { output.add(index).read() } != 77 {
                return failed(13);
            }
        }
        // SAFETY: as above; nobody else uses it.
        unsafe { allocation::unmap_pages(core::ptr::NonNull::new_unchecked(output), PAGE) };
        true
    });
    if passed && posix_thread::thread_pointer() != 0 {
        rt::println!("posix-tls-probe: the register stays set after the scope");
        return 5;
    }
    if passed {
        rt::println!("posix-tls-probe: ok");
        0
    } else {
        rt::println!(
            "posix-tls-probe: failed stage {} done {}",
            FAILURE.load(Ordering::Acquire),
            DONE.load(Ordering::Acquire)
        );
        2
    }
}
