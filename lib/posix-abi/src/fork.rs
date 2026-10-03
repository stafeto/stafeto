// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `fork` by a full copy (spec 2, 3.2; 5d). The calling thread keeps its
//! registers of the AAPCS64 callee (x19 to x30, the stack pointer, d8 to
//! d15, FPCR, FPSR and TPIDR_EL0) in CONTEXT (`point`), and the process
//! service makes the child's record and process with the loader in it
//! (ForkStart, with the classes of the process's actions for the child's
//! page). The loader of the child takes the objects of the layer's memory
//! map (Fork, Regions), copies them into objects the child pays for at the
//! same addresses (Go), and once ForkCommit made the child live it writes
//! the child's handles into TRANSFER and jumps to `resume`, which takes
//! the registers back from the copy of CONTEXT and returns 0 from `point`
//! on the copy of the caller's stack. A program init started has no
//! segments in its map, and gets ENOSYS. No copy on write: the child pays
//! for every page it gets.

use crate::constants::*;
use crate::process::{ask, ask_loader, client, load_errno, request, start_errno};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use proto_loader::{Fork, Method, REGIONS_MAX, Region, TRANSFER_SIZE};
use proto_wire::{Status, Writer};
use rt::abi::{Access, Rights};
use rt::handle::{Channel, Handle, Memory, Outgoing};

/// The registers of the callee the calling thread had at `point`: x19 to
/// x30, the stack pointer, d8 to d15, FPCR, FPSR and TPIDR_EL0.
#[repr(C)]
struct Registers {
    x: [u64; 12],
    sp: u64,
    d: [u64; 8],
    fpcr: u64,
    fpsr: u64,
    tpidr: u64,
}

struct Context(UnsafeCell<Registers>);
// SAFETY: only `point` writes it, one fork at a time (FORKING), and only
// `resume` reads it, in the child, before anything else runs there.
unsafe impl Sync for Context {}
static CONTEXT: Context = Context(UnsafeCell::new(Registers {
    x: [0; 12],
    sp: 0,
    d: [0; 8],
    fpcr: 0,
    fpsr: 0,
    tpidr: 0,
}));
const _: () = {
    assert!(core::mem::offset_of!(Registers, sp) == 96);
    assert!(core::mem::offset_of!(Registers, d) == 104);
    assert!(core::mem::offset_of!(Registers, fpcr) == 168);
    assert!(core::mem::offset_of!(Registers, tpidr) == 184);
};

/// Where the child's loader writes its handles and map
/// (proto_loader::write_transfer), in the layer's data.
#[repr(C, align(8))]
struct Transfer(UnsafeCell<[u8; TRANSFER_SIZE]>);
// SAFETY: only the child's loader writes it, before the child runs, and
// the child alone reads it then.
unsafe impl Sync for Transfer {}
static TRANSFER: Transfer = Transfer(UnsafeCell::new([0; TRANSFER_SIZE]));

/// One fork of the process at a time: CONTEXT and TRANSFER are one.
static FORKING: AtomicBool = AtomicBool::new(false);

/// Keeps the registers of the callee in CONTEXT and tail-calls `work`
/// with `arg`: `work`'s value comes back to the caller of `point`. In the
/// child `resume` returns 0 from it.
///
/// # Safety
/// One call at a time (FORKING); `work` writes nothing of the caller's
/// frame that the child may not see as it was then.
#[unsafe(naked)]
unsafe extern "C" fn point(work: extern "C" fn(u64) -> i64, arg: u64) -> i64 {
    core::arch::naked_asm!(
        "adrp x9, {context}",
        "add x9, x9, :lo12:{context}",
        "stp x19, x20, [x9, #0]",
        "stp x21, x22, [x9, #16]",
        "stp x23, x24, [x9, #32]",
        "stp x25, x26, [x9, #48]",
        "stp x27, x28, [x9, #64]",
        "stp x29, x30, [x9, #80]",
        "mov x10, sp",
        "str x10, [x9, #96]",
        "stp d8, d9, [x9, #104]",
        "stp d10, d11, [x9, #120]",
        "stp d12, d13, [x9, #136]",
        "stp d14, d15, [x9, #152]",
        "mrs x10, fpcr",
        "str x10, [x9, #168]",
        "mrs x10, fpsr",
        "str x10, [x9, #176]",
        "mrs x10, tpidr_el0",
        "str x10, [x9, #184]",
        "mov x9, x0",
        "mov x0, x1",
        "br x9",
        context = sym CONTEXT,
    )
}

/// The child's first instruction, where its loader jumps: the registers
/// of CONTEXT back, TPIDR_EL0 among them (written at EL0), and 0 from
/// `point` to its caller.
#[unsafe(naked)]
unsafe extern "C" fn resume() -> ! {
    core::arch::naked_asm!(
        "adrp x9, {context}",
        "add x9, x9, :lo12:{context}",
        "ldp x19, x20, [x9, #0]",
        "ldp x21, x22, [x9, #16]",
        "ldp x23, x24, [x9, #32]",
        "ldp x25, x26, [x9, #48]",
        "ldp x27, x28, [x9, #64]",
        "ldp x29, x30, [x9, #80]",
        "ldr x10, [x9, #96]",
        "mov sp, x10",
        "ldp d8, d9, [x9, #104]",
        "ldp d10, d11, [x9, #120]",
        "ldp d12, d13, [x9, #136]",
        "ldp d14, d15, [x9, #152]",
        "ldr x10, [x9, #168]",
        "msr fpcr, x10",
        "ldr x10, [x9, #176]",
        "msr fpsr, x10",
        "ldr x10, [x9, #184]",
        "msr tpidr_el0, x10",
        "mov x0, #0",
        "ret",
        context = sym CONTEXT,
    )
}

/// Where a fork came out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Forked {
    /// In the parent, with the child's PID.
    Parent(i32),
    /// In the child: nothing of the layer is bound to it yet.
    Child,
}

/// What the parent's work came to, in the frame of `copy`'s caller.
struct Work {
    window: Option<fn()>,
    result: Result<i32, i32>,
}

extern "C" fn work(arg: u64) -> i64 {
    // SAFETY: `copy` passes its own Work, which lives across `point`.
    let work = unsafe { &mut *(arg as *mut Work) };
    work.result = parent(work.window);
    1
}

/// The copy of the calling process into a child (the module's text): in
/// the parent the child's PID once ForkCommit made it live, or the errno
/// of why none came (the child gone): ENOSYS for a program without
/// segments in its map, EAGAIN past the service's limits or while another
/// fork of the process goes on, ENOMEM past the pool or the child's quota.
/// `window` runs in the parent once the copy is ready, before ForkCommit
/// (the probes). In the child nothing of the layer is bound to it: the
/// caller binds it before it calls anything of the layer.
pub fn copy(window: Option<fn()>) -> Result<Forked, i32> {
    if FORKING.swap(true, Ordering::AcqRel) {
        return Err(EAGAIN);
    }
    let mut w = Work {
        window,
        result: Err(EIO),
    };
    // SAFETY: one fork at a time (FORKING); `work` writes only `w`.
    let from = unsafe { point(work, (&raw mut w) as u64) };
    if from == 0 {
        // The child's own flag, which the copy took raised.
        FORKING.store(false, Ordering::Release);
        return Ok(Forked::Child);
    }
    FORKING.store(false, Ordering::Release);
    w.result.map(Forked::Parent)
}

/// The regions of the memory map as the child's loader takes them, with
/// a copy of each handle (MAP_READ, TRANSFER) for it.
struct Regions {
    count: usize,
    regions: [Option<(Region, Handle<Memory>)>; REGIONS_MAX],
}

/// The map's regions, under the heap's lock; ENOSYS when no code region
/// holds `resume` (a program init started), ENOMEM when a copy of a handle
/// fails.
fn regions() -> Result<Regions, i32> {
    let mut out = Regions {
        count: 0,
        regions: [const { None }; REGIONS_MAX],
    };
    let at = resume as *const () as u64;
    let mut code = false;
    crate::allocation::regions(|map| {
        for region in map.iter() {
            let region_of = Region {
                address: region.address as u64,
                pages: u32::try_from(region.pages).map_err(|_| ENOMEM)?,
                access: region.access,
            };
            code |= region.access == Access::ReadExec && region_of.holds(at);
            let copy =
                rt::sys::handle_duplicate(&region.handle, Rights::MAP_READ | Rights::TRANSFER)
                    .map_err(|_| ENOMEM)?;
            out.regions[out.count] = Some((region_of, copy));
            out.count += 1;
        }
        Ok::<(), i32>(())
    })?;
    if code { Ok(out) } else { Err(ENOSYS) }
}

/// The parent's side of a fork: ForkStart, then Fork, Regions and Go
/// through the child's loader, the window and ForkCommit; ForkAbort when
/// anything fails after ForkStart.
fn parent(window: Option<fn()>) -> Result<i32, i32> {
    let regions = regions()?;
    let level = crate::threads::own_block()
        .base_level
        .load(Ordering::Relaxed) as u8;
    let page = crate::process::page();
    let start = proto_process::ForkStart {
        level,
        ignored: page.ignored.load(Ordering::Acquire),
        caught: page.caught.load(Ordering::Acquire),
        flags: page.flags.load(Ordering::Acquire) & proto_process::PAGE_FLAGS,
    };
    let mut w = Writer::new();
    proto_process::Method::ForkStart
        .header()
        .write(&mut w)
        .map_err(|_| EIO)?;
    start.write(&mut w).map_err(|_| EIO)?;
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let mut reply = loop {
        match rt::sys::send(client().session(), w.as_bytes()) {
            Err(rt::abi::Error::Interrupted) => continue,
            Err(_) => return Err(EAGAIN),
            Ok(reply) => break reply,
        }
    };
    let mut r = proto_wire::Reader::new(reply.bytes(&mut buffer));
    let status = Status::from_code(r.u32().map_err(|_| EIO)?);
    if status != Status::Ok {
        return Err(start_errno(status));
    }
    let pid = r.u32().map_err(|_| EIO)?;
    let c = reply.handles.take::<Channel>(0).map_err(|_| EIO)?;
    let made = make(&c, regions, window);
    let method = match made {
        Ok(()) => proto_process::Method::ForkCommit,
        Err(_) => proto_process::Method::ForkAbort,
    };
    let told = ask(&request(method, &[pid])?);
    made.and(told).map(|_| pid as i32)
}

/// Fork, Regions and Go through the child's loader `c`, then `window`.
fn make(c: &Handle<Channel>, regions: Regions, window: Option<fn()>) -> Result<(), i32> {
    // SAFETY: only CONTEXT's address and its stack pointer, which `point`
    // wrote before this ran.
    let sp = unsafe { (*CONTEXT.0.get()).sp };
    let fork = Fork {
        pc: resume as *const () as u64,
        sp,
        transfer: TRANSFER.0.get() as u64,
        regions: regions.count as u32,
    };
    let mut w = Writer::new();
    Method::Fork.header().write(&mut w).map_err(|_| EIO)?;
    fork.write(&mut w).map_err(|_| EIO)?;
    if ask_loader(c, &w, None) != 0 {
        return Err(EIO);
    }
    let Regions { count, regions } = regions;
    let mut list = regions.into_iter().take(count).flatten().peekable();
    while list.peek().is_some() {
        let mut w = Writer::new();
        Method::Regions.header().write(&mut w).map_err(|_| EIO)?;
        let mut handles = Outgoing::new();
        for (region, handle) in list.by_ref().take(rt::abi::MESSAGE_HANDLES) {
            region.write(&mut w).map_err(|_| EIO)?;
            handles.push(handle.erase()).map_err(|_| EIO)?;
        }
        if ask_loader(c, &w, Some(handles)) != 0 {
            return Err(EIO);
        }
    }
    let mut w = Writer::new();
    Method::Go.header().write(&mut w).map_err(|_| EIO)?;
    match ask_loader(c, &w, None) {
        0 => {}
        code => return Err(load_errno(code)),
    }
    if let Some(window) = window {
        window();
    }
    Ok(())
}

/// The probe of a bare fork (5d): every signal of the caller held across
/// the copy; in the child `child` runs on the copy with nothing of the
/// layer bound and the process exits with its value; in the parent the
/// mask comes back and the child's PID, or the errno.
pub fn probe_bare(child: impl FnOnce() -> i32, window: Option<fn()>) -> Result<i32, i32> {
    let block = crate::threads::own_block();
    let mask = block.mask.swap(!0, Ordering::SeqCst);
    match copy(window) {
        Ok(Forked::Child) => rt::sys::process_exit(child() as u64 & 0xFF),
        result => {
            block.mask.store(mask, Ordering::SeqCst);
            crate::signals::deliver_now();
            result.map(|forked| match forked {
                Forked::Parent(pid) => pid,
                Forked::Child => 0,
            })
        }
    }
}

/// The probe of a load of ForkStart that never gets its copy: SpawnCommit
/// of the child (ESRCH: no child of SpawnStart), ForkCommit (EIO: the
/// loader is not ready), then ForkAbort; the child's PID in `pid`, and 0
/// when the two were refused so, else the errno each gave in the bytes.
pub fn probe_abort(pid: &mut i32) -> i32 {
    use proto_process::Method::{ForkAbort, ForkCommit, ForkStart, SpawnCommit};
    let mut w = Writer::new();
    let start = proto_process::ForkStart {
        level: crate::threads::own_block()
            .base_level
            .load(Ordering::Relaxed) as u8,
        ignored: 0,
        caught: 0,
        flags: 0,
    };
    if ForkStart.header().write(&mut w).is_err() || start.write(&mut w).is_err() {
        return EIO;
    }
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let Ok(mut reply) = rt::sys::send(client().session(), w.as_bytes()) else {
        return EIO;
    };
    let mut r = proto_wire::Reader::new(reply.bytes(&mut buffer));
    let status = Status::from_code(r.u32().unwrap_or(proto_wire::BAD_SIZE));
    if status != Status::Ok {
        return start_errno(status);
    }
    let child = r.u32().unwrap_or(0);
    let _c = reply.handles.take::<Channel>(0);
    *pid = child as i32;
    let errno = |method| match request(method, &[child]).and_then(|w| ask(&w)) {
        Ok(_) => 0,
        Err(errno) => errno,
    };
    let spawn = errno(SpawnCommit);
    let early = errno(ForkCommit);
    let _ = errno(ForkAbort);
    if spawn == ESRCH && early == EIO {
        0
    } else {
        spawn | early << 8
    }
}

/// The most mappings an object of the memory map has, for the probe that
/// a child's loader leaves no mapping of the parent's objects behind.
pub fn probe_mappings() -> u64 {
    crate::allocation::regions(|map| {
        map.iter()
            .filter_map(|r| rt::sys::memory_info(&r.handle).ok())
            .map(|info| info.mappings)
            .max()
            .unwrap_or(0)
    })
}
