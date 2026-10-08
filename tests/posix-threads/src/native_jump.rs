// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A native thread with its own entry: a signal handler of the layer leaves
//! by siglongjmp, then a request of the thread's own entry still ends its
//! receive. Four variants cover what the jump leaves behind: a second wait
//! deeper than the abandoned frame (1), a second wait whose entry frame
//! overlaps the abandoned one (2), two jumps in a row (3) and a jump inside
//! a handler (4).
use super::*;
use crate::layer::signals::{self as api, SigAction};
use rt::{
    Stack,
    abi::{Error, Policy},
    upcall,
};

core::arch::global_asm!(
    ".global native_jump_around",
    ".type native_jump_around,%function",
    "native_jump_around:",
    "stp x29, x30, [sp, #-32]!",
    "mov x29, sp",
    "stp x19, x20, [sp, #16]",
    "mov x19, x0",
    "mov x20, x1",
    "mov x1, #1",
    "bl sigsetjmp",
    "cbnz w0, 1f",
    "blr x20",
    "mov w0, #0",
    "1:",
    "ldp x19, x20, [sp, #16]",
    "ldp x29, x30, [sp], #32",
    "ret",
);
unsafe extern "C" {
    /// sigsetjmp(buffer, 1), then body(); 0 when body returns, the value
    /// of siglongjmp otherwise.
    fn native_jump_around(buffer: *mut u64, body: extern "C" fn()) -> c_int;
    fn siglongjmp(buffer: *mut u64, value: c_int) -> !;
}

struct JumpBuffer(core::cell::UnsafeCell<[u64; 64]>);
// SAFETY: only the native worker and its handlers use it.
unsafe impl Sync for JumpBuffer {}
static BUFFER: JumpBuffer = JumpBuffer(core::cell::UnsafeCell::new([0; 64]));
static INNER: JumpBuffer = JumpBuffer(core::cell::UnsafeCell::new([0; 64]));
static STACK: Stack<32768> = Stack::new();
static READY: AtomicU64 = AtomicU64::new(0);
static BLOCKING: AtomicU64 = AtomicU64::new(0);
static ID: AtomicU64 = AtomicU64::new(0);
static STAGE: AtomicUsize = AtomicUsize::new(0);
static PRIMARY: AtomicUsize = AtomicUsize::new(0);
static ERROR: AtomicUsize = AtomicUsize::new(0);
/// Jumps the worker takes before its last wait.
static JUMPS: AtomicUsize = AtomicUsize::new(0);
/// The second wait is made this many levels (8 KiB each) deeper.
static DEEPER: AtomicUsize = AtomicUsize::new(0);
/// The stack pointers of the first and of the last wait.
static FIRST_SP: AtomicU64 = AtomicU64::new(0);
static LAST_SP: AtomicU64 = AtomicU64::new(0);
/// 0 checks nothing, 1 wants the last wait deeper than one entry frame
/// below the first, 2 wants the two within one entry frame of each other.
static SHAPE: AtomicUsize = AtomicUsize::new(0);
const ENTRY_FRAME: u64 = 1904;

fn borrowed(raw: &AtomicU64) -> core::mem::ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(rt::abi::Handle(raw.load(Ordering::SeqCst)))
}
fn stage(value: usize) {
    STAGE.store(value, Ordering::SeqCst);
    let _ = sys::notify(&borrowed(&READY), 1);
}
fn current_sp() -> u64 {
    let sp: u64;
    // SAFETY: reads the stack pointer.
    unsafe {
        core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack, preserves_flags))
    };
    sp
}
unsafe extern "C" fn primary() {
    PRIMARY.fetch_add(1, Ordering::SeqCst);
}
rt::upcall_entry!(primary_entry, primary);
unsafe extern "C" fn jump_out(_signal: c_int) {
    // SAFETY: the worker's sigsetjmp frame is live below this handler.
    unsafe { siglongjmp((*BUFFER.0.get()).as_mut_ptr(), 1) }
}
unsafe extern "C" fn jump_inner(_signal: c_int) {
    // SAFETY: the sigsetjmp frame of the outer handler is live.
    unsafe { siglongjmp((*INNER.0.get()).as_mut_ptr(), 1) }
}
extern "C" fn body() {
    FIRST_SP.store(current_sp(), Ordering::SeqCst);
    stage(JUMP_STAGE.fetch_add(1, Ordering::SeqCst) + 1);
    // Nobody sends here: only the entry of the signal ends this wait, and
    // its handler leaves by siglongjmp.
    let _ = sys::receive(&borrowed(&BLOCKING));
    ERROR.store(1, Ordering::SeqCst);
}
static JUMP_STAGE: AtomicUsize = AtomicUsize::new(0);

/// The last wait, `levels` frames of 8 KiB below its caller.
#[inline(never)]
fn last_wait(levels: usize) -> Result<sys::Received, Error> {
    let mut pad = [0u8; 8192];
    core::hint::black_box(&mut pad);
    if levels > 0 {
        let result = last_wait(levels - 1);
        core::hint::black_box(&mut pad);
        return result;
    }
    LAST_SP.store(current_sp(), Ordering::SeqCst);
    sys::receive(&borrowed(&BLOCKING))
}

/// The worker of variants 1 to 3.
extern "C" fn worker(_: u64) -> ! {
    // SAFETY: primary_entry is a complete adapter; primary is reentrant.
    unsafe { upcall::bind(primary_entry) }.expect("native primary bind");
    unsafe { upcall::enable() }.expect("native primary enable");
    let jumped = tls::with_process(|| {
        ID.store(ffi::pthread_self(), Ordering::SeqCst);
        let action = SigAction {
            handler: jump_out as *const () as u64,
            mask: 0,
            flags: 0,
        };
        let mut previous = SigAction {
            handler: 0,
            mask: 0,
            flags: 0,
        };
        if unsafe { api::sigaction(SIGUSR1, &action, &mut previous) } != 0 {
            return -1;
        }
        let mut result = 1;
        for _ in 0..JUMPS.load(Ordering::SeqCst) {
            // SAFETY: the buffer outlives the jump; body runs on this stack.
            let r = unsafe { native_jump_around((*BUFFER.0.get()).as_mut_ptr(), body) };
            if r != 1 {
                result = r;
            }
        }
        // The handler of the program comes back before the next wait.
        if unsafe { api::sigaction(SIGUSR1, &previous, ptr::null_mut()) } != 0 {
            return -2;
        }
        result
    });
    if jumped != 1 {
        ERROR.store(2, Ordering::SeqCst);
    }
    stage(JUMP_STAGE.fetch_add(1, Ordering::SeqCst) + 1);
    // Only a request of this thread's own entry ends this wait.
    let result = last_wait(DEEPER.load(Ordering::SeqCst));
    let (first, last) = (
        FIRST_SP.load(Ordering::SeqCst),
        LAST_SP.load(Ordering::SeqCst),
    );
    let shape_ok = match SHAPE.load(Ordering::SeqCst) {
        1 => first > last && first - last > ENTRY_FRAME,
        2 => first.abs_diff(last) < ENTRY_FRAME,
        _ => true,
    };
    if result != Err(Error::Interrupted) || PRIMARY.load(Ordering::SeqCst) != 1 {
        ERROR.store(3, Ordering::SeqCst);
    } else if !shape_ok {
        ERROR.store(9, Ordering::SeqCst);
    }
    stage(JUMP_STAGE.fetch_add(1, Ordering::SeqCst) + 1);
    sys::thread_exit()
}

/// SIGUSR1 of variant 4: sets its own jump target and waits inside it.
unsafe extern "C" fn outer_handler(_signal: c_int) {
    // SAFETY: the buffer outlives the jump; the body runs on this stack.
    let r = unsafe { native_jump_around((*INNER.0.get()).as_mut_ptr(), inner_body) };
    if r != 1 {
        ERROR.store(4, Ordering::SeqCst);
    }
    stage(3);
    // The request of the own entry comes while this handler is live: the
    // nested entry may not call the program's handler.
    let result = sys::receive(&borrowed(&BLOCKING));
    if result != Err(Error::Interrupted) || PRIMARY.load(Ordering::SeqCst) != 0 {
        ERROR.store(5, Ordering::SeqCst);
    }
}
extern "C" fn inner_body() {
    stage(2);
    let _ = sys::receive(&borrowed(&BLOCKING));
    ERROR.store(6, Ordering::SeqCst);
}
/// The worker of variant 4.
extern "C" fn worker_inside(_: u64) -> ! {
    // SAFETY: as in `worker`.
    unsafe { upcall::bind(primary_entry) }.expect("native primary bind");
    unsafe { upcall::enable() }.expect("native primary enable");
    tls::with_process(|| {
        ID.store(ffi::pthread_self(), Ordering::SeqCst);
        let outer = SigAction {
            handler: outer_handler as *const () as u64,
            mask: 0,
            flags: 0,
        };
        let inner = SigAction {
            handler: jump_inner as *const () as u64,
            mask: 0,
            flags: 0,
        };
        let mut old = [outer, inner];
        if unsafe { api::sigaction(SIGUSR1, &outer, &mut old[0]) } != 0
            || unsafe { api::sigaction(SIGUSR2, &inner, &mut old[1]) } != 0
        {
            ERROR.store(7, Ordering::SeqCst);
        }
        stage(1);
        // The entry of SIGUSR1 ends this wait once its handler returns.
        if sys::receive(&borrowed(&BLOCKING)) != Err(Error::Interrupted) {
            ERROR.store(8, Ordering::SeqCst);
        }
        let _ = unsafe { api::sigaction(SIGUSR1, &old[0], ptr::null_mut()) };
        let _ = unsafe { api::sigaction(SIGUSR2, &old[1], ptr::null_mut()) };
    });
    // After the outer handler returned, the program's handler has run once.
    if PRIMARY.load(Ordering::SeqCst) != 1 {
        ERROR.store(10, Ordering::SeqCst);
    }
    stage(4);
    sys::thread_exit()
}

/// The waits of the coordinator: the stages arrive on `ready`, and `pause`
/// is a channel nobody sends to, for a short sleep that lets the lower
/// worker run.
struct Ctx {
    waiter: rt::wait::Waiter,
    pause: rt::wait::Waiter,
    pause_channel: Handle<Channel>,
}

fn now() -> u64 {
    rt::time::ticks_to_ns(rt::time::now())
}

fn await_stage(ctx: &Ctx, value: usize) -> bool {
    let waiter = &ctx.waiter;
    let limit = rt::time::ticks_to_ns(rt::time::now()) + 500_000_000;
    while STAGE.load(Ordering::SeqCst) < value {
        if rt::time::ticks_to_ns(rt::time::now()) >= limit {
            return false;
        }
        let _ = waiter.receive_until(&borrowed(&READY), limit);
    }
    true
}

/// Waits until the worker, one level below this thread, waits in receive.
fn receiving(ctx: &Ctx, thread: &Handle<Thread>) -> bool {
    let limit = now() + 500_000_000;
    while sys::thread_info(thread).map(|info| info.state) != Ok(ThreadState::Receiving) {
        if now() >= limit {
            return false;
        }
        let _ = ctx.pause.receive_until(&ctx.pause_channel, now() + 100_000);
    }
    true
}

struct Shape {
    jumps: usize,
    deeper: usize,
    shape: usize,
}

/// Variants 1 to 3 and the main scenario: `jumps` waits end by a jump, a
/// last wait ends by the request of the own entry.
#[inline(never)]
fn scenario(
    name: &str,
    code: usize,
    shape: Shape,
    slot: usize,
    ctx: &Ctx,
    level: u8,
    base: u8,
) -> bool {
    STAGE.store(0, Ordering::SeqCst);
    JUMP_STAGE.store(0, Ordering::SeqCst);
    PRIMARY.store(0, Ordering::SeqCst);
    ERROR.store(0, Ordering::SeqCst);
    JUMPS.store(shape.jumps, Ordering::SeqCst);
    DEEPER.store(shape.deeper, Ordering::SeqCst);
    SHAPE.store(shape.shape, Ordering::SeqCst);
    let Some((native, ended)) = spawn(worker, slot, level, base) else {
        return failed(code + 1);
    };
    for jump in 1..=shape.jumps {
        if !await_stage(ctx, jump) {
            return failed(code + 1);
        }
        if !receiving(ctx, &native) {
            return failed(code + 2);
        }
        if ffi::pthread_kill(ID.load(Ordering::SeqCst), SIGUSR1) != 0 {
            return failed(code + 2);
        }
    }
    if !await_stage(ctx, shape.jumps + 1) {
        return failed(code + 2);
    }
    if !receiving(ctx, &native) {
        return failed(code + 2);
    }
    if sys::thread_upcall_request(&native).is_err() {
        return failed(code + 3);
    }
    if !await_stage(ctx, shape.jumps + 2) {
        rt::println!("native-jump: the own entry stays closed after siglongjmp ({name})");
        return failed(code + 4);
    }
    finish(name, code, &ended)
}

/// Creates and starts the worker of a variant on its own message buffer.
fn spawn(
    entry: extern "C" fn(u64) -> !,
    slot: usize,
    level: u8,
    base: u8,
) -> Option<(Handle<Thread>, Handle<Channel>)> {
    let ended = sys::channel_create(base).ok()?;
    let native = unsafe {
        sys::thread_create_with(
            abi::allocation::process(),
            entry,
            STACK.top(),
            0,
            level,
            Policy::Fifo,
            0xe20000 + slot * 0x1000,
            Some((&ended, base)),
        )
    }
    .ok()?;
    sys::thread_start(&native).ok()?;
    Some((native, ended))
}

fn finish(name: &str, code: usize, ended: &Handle<Channel>) -> bool {
    if ERROR.load(Ordering::SeqCst) != 0 {
        rt::println!(
            "native-jump: error {} ({name})",
            ERROR.load(Ordering::SeqCst)
        );
        return failed(code + 5);
    }
    loop {
        match sys::receive(ended) {
            Err(Error::Interrupted) => continue,
            Ok(sys::Received::Notification { .. }) => return true,
            _ => return failed(code + 6),
        }
    }
}

/// Variant 4: a jump to a target inside the live handler of the layer.
#[inline(never)]
fn inside(ctx: &Ctx, level: u8, base: u8) -> bool {
    const CODE: usize = 1540;
    STAGE.store(0, Ordering::SeqCst);
    PRIMARY.store(0, Ordering::SeqCst);
    ERROR.store(0, Ordering::SeqCst);
    let Some((native, ended)) = spawn(worker_inside, 4, level, base) else {
        return failed(CODE + 1);
    };
    for (stage_wanted, signal) in [(1, SIGUSR1), (2, SIGUSR2)] {
        if !await_stage(ctx, stage_wanted) {
            return failed(CODE + 1);
        }
        if !receiving(ctx, &native) {
            return failed(CODE + 2);
        }
        if ffi::pthread_kill(ID.load(Ordering::SeqCst), signal) != 0 {
            return failed(CODE + 2);
        }
    }
    if !await_stage(ctx, 3) {
        return failed(CODE + 2);
    }
    if !receiving(ctx, &native) {
        return failed(CODE + 2);
    }
    if sys::thread_upcall_request(&native).is_err() {
        return failed(CODE + 3);
    }
    if !await_stage(ctx, 4) {
        rt::println!("native-jump: the own entry stays closed after a jump inside a handler");
        return failed(CODE + 4);
    }
    finish("inside a handler", CODE, &ended)
}

#[inline(never)]
pub(super) fn run() -> bool {
    let main = unsafe { threads::probe_native(ffi::pthread_self()) }.expect("main identity");
    let base = sys::thread_info(&main).expect("main level").base;
    let level = base - 1;
    let ready = sys::channel_create(base).expect("native jump ready");
    let blocking = sys::channel_create(level).expect("native jump receive");
    READY.store(ready.raw().0, Ordering::SeqCst);
    BLOCKING.store(blocking.raw().0, Ordering::SeqCst);
    let pause_channel = sys::channel_create(base).expect("native jump pause");
    let ctx = Ctx {
        waiter: rt::wait::Waiter::new(&ready, 0, base).expect("native jump waiter"),
        pause: rt::wait::Waiter::new(&pause_channel, 0, base).expect("native jump pause timer"),
        pause_channel,
    };
    // The main scenario: one jump, the second wait close above the first,
    // so that the entry frame of the second overlaps the abandoned one (2).
    let one = Shape {
        jumps: 1,
        deeper: 0,
        shape: 2,
    };
    if !scenario("one jump", 1500, one, 0, &ctx, level, base) {
        return false;
    }
    // 1: the second wait far below the abandoned frame.
    let deep = Shape {
        jumps: 1,
        deeper: 1,
        shape: 1,
    };
    if !scenario("deep second wait", 1510, deep, 1, &ctx, level, base) {
        return false;
    }
    // 3: two jumps in a row.
    let twice = Shape {
        jumps: 2,
        deeper: 0,
        shape: 0,
    };
    if !scenario("two jumps", 1520, twice, 2, &ctx, level, base) {
        return false;
    }
    // 4: a jump inside a handler.
    if !inside(&ctx, level, base) {
        return false;
    }
    rt::println!("native-jump: own entry after siglongjmp from a layer handler");
    true
}
