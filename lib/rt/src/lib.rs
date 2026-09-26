// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The runtime of stafeto programs, as small as milestone 1.3d needs it
//! (spec 13.2): the entry point, handles typed by the kind of their object
//! (`handle`, `init`), typed wrappers of the system calls the kernel has,
//! requests and their tokens among them, and a raw call for any other
//! (`sys`), the thread's message buffer (`msgbuf`), output through
//! `debug_write`
//! (`console`, `print!`, `println!`), the counter read without a call
//! (`time`), stacks for threads in static memory, and the panic handler.
//! The heap, the start protocol, the ELF loader and the service loop come
//! in milestone 1.4.
//!
//! A program names its main function with `rt::entry!`; `_start` calls it
//! with the x0 the kernel set and ends the process with the code it
//! returns.

#![no_std]

pub mod console;
pub mod handle;
pub mod msgbuf;
pub mod sys;
pub mod time;

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

pub use abi;
pub use handle::Handle;

/// Init's first handles (spec 13.3), typed. Each mention of a constant
/// gives a new value: a program that closed one of these handles stops
/// naming it itself.
pub mod init {
    use crate::handle::{Handle, Process, Resource, Thread};

    /// The system resource with DEVICE, DEBUG, KSTATS, DUPLICATE and
    /// TRANSFER (abi::INIT_RESOURCE_RIGHTS).
    pub const RESOURCE: Handle<Resource> = Handle::from_raw(abi::INIT_RESOURCE);
    /// Init's own process, with the owner's rights.
    pub const PROCESS: Handle<Process> = Handle::from_raw(abi::INIT_PROCESS);
    /// Init's first thread, with the owner's rights.
    pub const THREAD: Handle<Thread> = Handle::from_raw(abi::INIT_THREAD);
}

/// The first handle of a process that process_create made (spec 13.3):
/// entry 0 of its table, where the start channel goes. As with `init`,
/// each mention gives a new value, and a program that closed the handle
/// stops naming it itself.
pub const START_CHANNEL: Handle<handle::Channel> = Handle::from_raw(abi::START_CHANNEL);

/// Names the program's main function, a `fn(u64) -> u64`: `_start` calls
/// it with the x0 the program started with (0 for init, spec 13.3) and
/// ends the process with the code it returns.
#[macro_export]
macro_rules! entry {
    ($main:path) => {
        #[unsafe(no_mangle)]
        extern "C" fn __rt_main(arg: u64) -> u64 {
            let main: fn(u64) -> u64 = $main;
            main(arg)
        }
    };
}

/// Formats its arguments to the console (`console::write_fmt`); output
/// that fails is dropped.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        let _ = $crate::console::write_fmt(format_args!($($arg)*));
    }};
}

/// `print!` with a newline; a line of up to 64 bytes goes out in one call.
#[macro_export]
macro_rules! println {
    () => {
        $crate::print!("\n")
    };
    ($($arg:tt)*) => {
        $crate::print!("{}\n", format_args!($($arg)*))
    };
}

/// The program's entry point, where the ELF's entry and so the boot
/// image's point (lld's default name). The frame pointer and the link
/// register start at zero, which ends every backtrace; the stack is the
/// one the kernel set.
#[unsafe(naked)]
#[unsafe(no_mangle)]
extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov x29, xzr",
        "mov x30, xzr",
        "b {start}",
        start = sym start,
    )
}

extern "C" fn start(arg: u64) -> ! {
    unsafe extern "C" {
        /// The program's main function (`entry!`).
        fn __rt_main(arg: u64) -> u64;
    }
    // SAFETY: `entry!` defines the function with this signature.
    let code = unsafe { __rt_main(arg) };
    sys::process_exit(code)
}

/// A panic prints its message to the console, if the program set one, and
/// ends the process with abi::PANIC_EXIT_CODE. A panic while that message
/// prints ends the process with no more output.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    static PANICKING: AtomicBool = AtomicBool::new(false);
    if !PANICKING.swap(true, Ordering::Relaxed) {
        // Output that fails has nowhere else to go.
        let _ = console::write_fmt(format_args!("panic: {info}\n"));
    }
    sys::process_exit(abi::PANIC_EXIT_CODE)
}

/// Memory for a thread's stack in a static, which the linker puts in
/// `.bss`: `static STACK: Stack<16384> = Stack::new();`, and the thread
/// starts with `STACK.top()`. No guard page: an overflow overwrites the
/// statics next to it; stacks with a guard page come with mem_map
/// (milestone 1.3).
#[repr(C, align(16))]
pub struct Stack<const N: usize>(UnsafeCell<[u8; N]>);

// SAFETY: the program only takes the stack's address; the thread that
// gets the stack is its one user.
unsafe impl<const N: usize> Sync for Stack<N> {}

impl<const N: usize> Stack<N> {
    pub const fn new() -> Stack<N> {
        const {
            assert!(
                N > 0 && N.is_multiple_of(16),
                "a stack is whole 16-byte units"
            )
        };
        Stack(UnsafeCell::new([0; N]))
    }

    /// The stack pointer a thread on this stack starts with.
    pub fn top(&self) -> usize {
        self.0.get() as usize + N
    }
}

impl<const N: usize> Default for Stack<N> {
    fn default() -> Stack<N> {
        Stack::new()
    }
}
