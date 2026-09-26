// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The child program of the test init (spec 15.2): the second file of the
//! test boot image, which the test init loads with rt::loader. As it
//! starts, a child adds 1 to its mark STARTED, in the page its parent
//! mapped at child::MARKS, then asks for its start data through
//! abi::START_CHANNEL (spec 13.3): the reply names its role, with up to
//! seven arguments and four handles (lib.rs). The child ends with the code
//! its role returns, or by the fault its role exists for.

#![no_std]
#![no_main]

use abi::{Access, Error, Policy, Rights};
use child::{
    ARGS, FAILED, FAULT_AT, FULL, HELLO, IMAGE, MADE, MARKS, MOST_USED, NO_FAULT, QUOTA, ROUNDS,
    Role, SCRATCH, STARTED, WINDOW,
};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
use rt::handle::{Channel, Memory, Process, Resource};
use rt::sys::{self, Received};
use rt::{Handle, loader, msgbuf};

rt::entry!(main);

const PAGE: u64 = 4096;
/// Copies of handles Role::Churn holds at a time: more than the table of
/// a child its parent made for it takes.
const HELD_MAX: usize = 1024;

/// `ret`, the word Role::RunData writes and branches to: a word of the
/// data segment.
static DATA: AtomicU32 = AtomicU32::new(0);
/// The copies Role::Churn holds.
static HELD: [AtomicU64; HELD_MAX] = [const { AtomicU64::new(0) }; HELD_MAX];

/// The reply to the start request.
struct Start {
    role: Role,
    args: [u64; ARGS],
    handles: [abi::Handle; abi::MESSAGE_HANDLES],
}

fn main(_: u64) -> u64 {
    mark(STARTED).fetch_add(1, Relaxed);
    match ask() {
        Ok(start) => run(&start),
        Err(_) => FAILED,
    }
}

/// Mark `i` in the page at MARKS.
fn mark(i: usize) -> &'static AtomicU64 {
    // SAFETY: the parent mapped the page of marks, readable and writable,
    // before the child started; it stays while the child lives, and the
    // words are only reached as atomics.
    unsafe { &*(MARKS as *const AtomicU64).add(i) }
}

/// The start request (spec 13.3): HELLO through START_CHANNEL; the reply
/// holds the role's code, its arguments and its handles.
fn ask() -> Result<Start, Error> {
    let reply = sys::send(&rt::START_CHANNEL, &HELLO.to_le_bytes())?;
    let role = Role::from_code(reply.words[0]).ok_or(Error::InvalidArgs)?;
    let mut args = [0; ARGS];
    args.copy_from_slice(&reply.words[1..]);
    let handles = core::array::from_fn(|i| {
        if i < reply.handles {
            msgbuf::handle(i).0
        } else {
            abi::Handle::INVALID
        }
    });
    Ok(Start {
        role,
        args,
        handles,
    })
}

fn run(s: &Start) -> u64 {
    let a = &s.args;
    match s.role {
        Role::Exit => a[0],
        Role::Echo => echo(a),
        Role::Recurse => deeper(0),
        Role::Panic => {
            rt::console::set(&Handle::<Resource>::from_raw(s.handles[0]));
            panic!("{}", child::PANIC)
        }
        Role::Load => {
            let at = mark(FAULT_AT).as_ptr();
            // SAFETY: the load is the fault the role exists for; its address
            // goes to mark FAULT_AT first.
            unsafe {
                core::arch::asm!(
                    "adr {t}, 2f",
                    "str {t}, [{at}]",
                    "2: ldr {t}, [{a}]",
                    t = out(reg) _,
                    at = in(reg) at,
                    a = in(reg) a[0],
                    options(nostack),
                )
            };
            NO_FAULT
        }
        Role::WriteCode => {
            let own = Handle::<Process>::from_raw(s.handles[0]);
            // SAFETY: the call must fail; had it passed, the code would
            // only have become writable.
            let protected =
                unsafe { sys::mem_protect(&own, a[0] as usize, a[1], Access::ReadWrite) };
            if protected != Err(Error::AccessDenied) {
                return FAILED;
            }
            let code = main as fn(u64) -> u64 as usize;
            // SAFETY: the store is the fault the role exists for.
            unsafe { (code as *mut u32).write_volatile(0) };
            NO_FAULT
        }
        Role::RunData => {
            let own = Handle::<Process>::from_raw(s.handles[0]);
            let parts = [(a[0], a[1]), (a[2], a[3]), (MARKS as u64, PAGE)];
            let denied = parts.iter().all(|&(at, len)| {
                // SAFETY: the call must fail; had it passed, the child
                // would only fault sooner.
                let made = unsafe { sys::mem_protect(&own, at as usize, len, Access::ReadExec) };
                made == Err(Error::AccessDenied)
            });
            if !denied {
                return FAILED;
            }
            DATA.store(0xD65F_03C0, Relaxed);
            let data = (&raw const DATA).cast::<()>();
            // SAFETY: the branch is the fault the role exists for.
            let f = unsafe { core::mem::transmute::<*const (), extern "C" fn()>(data) };
            f();
            NO_FAULT
        }
        Role::WriteReadOnly => with_scratch(s, |own, at| {
            // SAFETY: the page is the child's own, readable and writable
            // until mem_protect, which nothing but this role uses.
            let protected = unsafe {
                at.write_volatile(1);
                sys::mem_protect(own, SCRATCH, PAGE, Access::Read)
            };
            if protected.is_err() {
                return FAILED;
            }
            // SAFETY: the store is the fault the role exists for.
            unsafe { at.write_volatile(2) };
            NO_FAULT
        }),
        Role::ReadUnmapped => with_scratch(s, |own, at| {
            // SAFETY: the page is the child's own, readable and writable.
            let seen = unsafe {
                at.write_volatile(1);
                at.read_volatile()
            };
            // SAFETY: nothing but this role uses the page.
            if seen != 1 || unsafe { sys::mem_unmap(own, SCRATCH, PAGE) }.is_err() {
                return FAILED;
            }
            // SAFETY: the load is the fault the role exists for.
            unsafe { at.read_volatile() };
            NO_FAULT
        }),
        Role::Grandparent => grandparent(s).unwrap_or(FAILED),
        Role::Spin => {
            let count = mark(a[0] as usize);
            loop {
                count.fetch_add(1, Relaxed);
            }
        }
        Role::Churn => churn(s, a[0]),
    }
}

/// Role::Echo.
fn echo(args: &[u64; ARGS]) -> u64 {
    let mut words = [0; 8];
    words[..ARGS].copy_from_slice(args);
    let bytes = abi::inline_bytes(&words);
    match sys::send(&rt::START_CHANNEL, &bytes[..8 * ARGS]) {
        Ok(reply) => reply.words[0],
        Err(_) => FAILED,
    }
}

/// Role::Recurse: each call keeps a frame the compiler cannot drop.
fn deeper(depth: u64) -> u64 {
    let frame = [depth; 32];
    if depth == u64::MAX {
        return NO_FAULT;
    }
    core::hint::black_box(&frame);
    deeper(depth + 1).wrapping_add(frame[1])
}

/// A page of a new object mapped at SCRATCH, RW, through handle 0, the
/// child's own process; `then` gets that handle and the page's first word.
fn with_scratch(s: &Start, then: impl FnOnce(&Handle<Process>, *mut u64) -> u64) -> u64 {
    let own = Handle::<Process>::from_raw(s.handles[0]);
    let Ok(m) = sys::mem_create(PAGE) else {
        return FAILED;
    };
    if sys::mem_map(&own, &m, 0, PAGE, SCRATCH, Access::ReadWrite).is_err() {
        return FAILED;
    }
    then(&own, SCRATCH as *mut u64)
}

/// Role::Grandparent: the grandchild runs Spin below the child, which then
/// waits in a request to its parent until it is killed.
fn grandparent(s: &Start) -> Result<u64, Error> {
    let [own, image, exit, marks] = s.handles;
    let own = Handle::<Process>::from_raw(own);
    let image = Handle::<Memory>::from_raw(image);
    let exit = Handle::<Channel>::from_raw(exit);
    let marks = Handle::<Memory>::from_raw(marks);
    let size = sys::memory_info(&image)?.size;
    sys::mem_map(&own, &image, 0, size, IMAGE, Access::Read)?;
    // SAFETY: the mapping shows the boot image, read-only, and stays.
    let bytes = unsafe { core::slice::from_raw_parts(IMAGE as *const u8, size as usize) };
    let program = bootimg::BootImage::parse(bytes)
        .ok()
        .and_then(|image| image.files().find(|f| f.name == "child"))
        .and_then(|file| bootimg::Program::parse(file.data).ok())
        .ok_or(Error::InvalidArgs)?;
    let requests = sys::channel_create(1)?;
    let start = sys::handle_label(&requests, Rights::SEND | Rights::TRANSFER, 1, 1)?;
    let level = s.args[1] as u8;
    let params = loader::Params {
        quota: s.args[0],
        handle_limit: 16,
        ceiling: level,
        exit: Some((&exit, 1)),
        start: Some(start),
        priority: level,
        policy: Policy::Fifo,
    };
    // SAFETY: only the loader uses WINDOW.
    let g = unsafe { loader::load(&own, &program, WINDOW, params) }.map_err(|(e, _)| e)?;
    sys::mem_map(&g.process, &marks, 0, PAGE, MARKS, Access::ReadWrite)?;
    sys::thread_start(&g.thread)?;
    let Received::Message { token, .. } = sys::receive(&requests)? else {
        return Ok(FAILED);
    };
    token.reply(&child::reply(Role::Spin, &[s.args[2]]))?;
    sys::send(&rt::START_CHANNEL, &[])?;
    Ok(FAILED)
}

/// Role::Churn.
fn churn(s: &Start, total: u64) -> u64 {
    let own = Handle::<Process>::from_raw(s.handles[0]);
    let (mut made, mut rounds, mut full, mut most) = (0, 0, 0, 0);
    while made < total {
        let mut n = 0;
        let error = loop {
            if n == HELD_MAX {
                break Error::LimitReached;
            }
            match sys::handle_duplicate(&own, Rights::NONE) {
                Ok(h) => {
                    HELD[n].store(h.raw().0, Relaxed);
                    n += 1;
                }
                Err(e) => break e,
            }
        };
        if let Ok(m) = sys::process_memory(&own) {
            most = most.max(m.used);
            mark(QUOTA).store(m.quota, Relaxed);
        }
        for h in &HELD[..n] {
            if Handle::<Process>::from_raw(abi::Handle(h.load(Relaxed)))
                .close()
                .is_err()
            {
                return FAILED;
            }
        }
        full += u64::from(error == Error::NoMemory);
        rounds += 1;
        made += n as u64;
        if n == 0 {
            break;
        }
    }
    mark(MADE).store(made, Relaxed);
    mark(ROUNDS).store(rounds, Relaxed);
    mark(FULL).store(full, Relaxed);
    mark(MOST_USED).store(most, Relaxed);
    0
}
