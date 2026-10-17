// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The other CPUs (SMP stage 2): PSCI CPU_ON starts each CPU the device
//! tree lists at head.S's `secondary_entry` with the MMU off; the CPU
//! drops to EL1, turns its MMU on over the kernel's tables, sets up its
//! registers, its GIC interface and its timer, reports itself in its CPU
//! block and idles in `wfi`, serving the kernel's SGIs. Nothing is
//! scheduled on it yet: the scheduler stays on CPU 0 (stages 3 and 4). A
//! CPU other than CPU 0 touches no kernel structure but its own block and
//! the atomics here: the console and the locks are for one CPU until then.
//!
//! The probe of the SGIs lets every CPU ping every other and checks each
//! pong: what a sender wrote before its SGI is there when the SGI comes.

use crate::arch::{cache, cpu, gic, registers, symbols, timer};
use crate::boot::Boot;
use crate::psci;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use cpu::{CpuBlock, MAX_CPUS, UP};
use kcore::bootinfo::MPIDR_AFFINITY;
use kcore::gic::{Ack, SGI_GO, SGI_PING, SGI_PONG};
use kcore::layout::image_pa;

/// What a CPU reads with its MMU and caches off, at the physical address
/// PSCI hands it in x0 (head.S `secondary_entry`): the translation
/// registers of CPU 0, the roots of the tables, the stack and the block of
/// the CPU. One cache line.
#[repr(C, align(64))]
struct StartBlock {
    mair: u64,
    tcr: u64,
    /// TTBR0 for the switch: the identity map of the kernel's GiB.
    ttbr0_identity: u64,
    ttbr1: u64,
    /// TTBR0 once the MMU is on: the empty table, as for the kernel.
    ttbr0_kernel: u64,
    stack_top: u64,
    cpu_block: u64,
}

const _: () = {
    assert!(core::mem::offset_of!(StartBlock, ttbr0_identity) == 16);
    assert!(core::mem::offset_of!(StartBlock, ttbr0_kernel) == 32);
    assert!(core::mem::offset_of!(StartBlock, cpu_block) == 48);
    assert!(core::mem::size_of::<StartBlock>() == 64);
};

struct StartBlocks(UnsafeCell<[StartBlock; MAX_CPUS]>);

// SAFETY: CPU 0 writes a block before it starts the CPU that reads it, and
// never again.
unsafe impl Sync for StartBlocks {}

static START: StartBlocks = StartBlocks(UnsafeCell::new(
    [const {
        StartBlock {
            mair: 0,
            tcr: 0,
            ttbr0_identity: 0,
            ttbr1: 0,
            ttbr0_kernel: 0,
            stack_top: 0,
            cpu_block: 0,
        }
    }; MAX_CPUS],
));

unsafe extern "C" {
    fn secondary_entry();
}

/// How long CPU 0 waits for a CPU to come up, or for the SGIs of the
/// probe, in seconds of the counter: far longer than either takes, short
/// enough to stop a machine that lost a CPU.
const WAIT_SECONDS: u64 = 2;

/// The CPUs that are up, CPU 0 among them: one until `start` brings the
/// others.
static UP_COUNT: AtomicU32 = AtomicU32::new(1);

/// The number of CPUs that are up.
pub fn cpus() -> usize {
    UP_COUNT.load(Ordering::Relaxed) as usize
}

/// Starts every other CPU the device tree lists, up to MAX_CPUS in all,
/// and waits for each to report. Without a PSCI conduit the kernel stays
/// on one CPU. A CPU that PSCI refuses or that does not come up stops the
/// kernel.
pub fn start(boot: &Boot) {
    let info = &boot.info;
    let own = registers::mpidr_el1() & MPIDR_AFFINITY;
    let mut others = info
        .cpus
        .as_slice()
        .iter()
        .filter(|&&m| m != own)
        .peekable();
    if others.peek().is_none() {
        return;
    }
    if info.psci == kcore::bootinfo::PsciConduit::None {
        kprintln!("smp        no PSCI conduit: one CPU");
        return;
    }
    // CPU 0's own timer, which no thread has armed yet.
    let timer_ok = timer::self_test(timer::frequency() / 10_000);
    cpu::this()
        .timer_ok
        .store(timer_ok as u32, Ordering::Relaxed);
    let mut up = 1;
    for &mpidr in others.take(MAX_CPUS - 1) {
        start_one(boot, up, mpidr);
        up += 1;
    }
    UP_COUNT.store(up as u32, Ordering::Relaxed);
}

#[inline(never)]
fn start_one(boot: &Boot, index: usize, mpidr: u64) {
    let block = cpu::prepare(index);
    let pa = |va: usize| image_pa(boot.kernel_pa, va);
    // SAFETY: the CPU of this block has not started: nothing else reads it.
    let start = unsafe { &mut (*START.0.get())[index] };
    *start = StartBlock {
        mair: registers::mair_el1(),
        tcr: registers::tcr_el1(),
        ttbr0_identity: pa(symbols::identity_table()),
        ttbr1: registers::ttbr1_el1(),
        ttbr0_kernel: pa(symbols::empty_table()),
        stack_top: block.stack_top() as u64,
        cpu_block: block as *const CpuBlock as u64,
    };
    // The CPU reads the block with its MMU and caches off, from memory:
    // clean it there before CPU_ON [G18].
    cache::clean_to_memory(
        start as *const StartBlock as usize,
        core::mem::size_of::<StartBlock>(),
    );
    let entry = pa(secondary_entry as *const () as usize);
    let context = pa(start as *const StartBlock as usize);
    match psci::cpu_on(mpidr, entry, context) {
        Some(0) => {}
        status => panic!("PSCI CPU_ON of CPU {index} (MPIDR {mpidr:#x}) returned {status:?}"),
    }
    let limit = timer::now() + WAIT_SECONDS * timer::frequency();
    while block.state.load(Ordering::Acquire) != UP {
        if timer::now() > limit {
            panic!("CPU {index} (MPIDR {mpidr:#x}) did not come up");
        }
        core::hint::spin_loop();
    }
}

/// What CPU 0 says of each CPU: the boot report. The CPUs set the numbers
/// themselves.
pub fn report() {
    if cpus() < 2 {
        return;
    }
    for index in 0..cpus() {
        let b = cpu::block(index);
        kprintln!(
            "cpu {index}      MPIDR {:#x} EL{} timer {}",
            b.mpidr.load(Ordering::Relaxed),
            b.level.load(Ordering::Relaxed),
            if b.timer_ok.load(Ordering::Relaxed) != 0 {
                "ok"
            } else {
                "late"
            }
        );
    }
}

/// The code of a CPU other than CPU 0 from head.S, on its own stack with
/// its MMU on: the block it belongs to.
#[unsafe(no_mangle)]
extern "C" fn secondary_main(block: &'static CpuBlock) -> ! {
    cpu::attach(block);
    crate::arch::exceptions::init();
    crate::arch::user::init_registers();
    gic::init_secondary();
    timer::init_cpu();
    let timer_ok = timer::self_test(timer::frequency() / 10_000);
    block.mpidr.store(registers::mpidr_el1(), Ordering::Relaxed);
    block
        .level
        .store(registers::current_el() as u32, Ordering::Relaxed);
    block.timer_ok.store(timer_ok as u32, Ordering::Relaxed);
    block.state.store(UP, Ordering::Release);
    loop {
        if let Some(ack) = gic::wait() {
            handle(ack);
        }
    }
}

/// `PING[to][from]`: `from` wrote it for `to` before the SGI. Reset by
/// `to`, which then answers.
static PING: Matrix = Matrix::new();
/// `PONG[to][from]`: the answer of `from` to a ping of `to`.
static PONG: Matrix = Matrix::new();
/// `GOT_PING[to][from]` and `GOT_PONG[to][from]`: what arrived, for the
/// check.
static GOT_PING: Matrix = Matrix::new();
static GOT_PONG: Matrix = Matrix::new();
/// `GO[cpu]`: CPU 0 asks the CPU to ping the others.
static GO: [AtomicU8; MAX_CPUS] = [const { AtomicU8::new(0) }; MAX_CPUS];
struct Matrix([[AtomicU8; MAX_CPUS]; MAX_CPUS]);

impl Matrix {
    const fn new() -> Matrix {
        Matrix([const { [const { AtomicU8::new(0) }; MAX_CPUS] }; MAX_CPUS])
    }

    fn at(&self, to: usize, from: usize) -> &AtomicU8 {
        &self.0[to][from]
    }
}

/// An SGI of the probe on the CPU that took it, acknowledged: the flags
/// the senders wrote name the pairs; each is read with acquire, after the
/// SGI, so that the sender's barrier shows. Ends the interrupt.
pub fn handle(ack: Ack) {
    let me = cpu::this().index();
    let cpus = cpus();
    match ack.intid() {
        SGI_PING => {
            for from in (0..cpus).filter(|&f| f != me) {
                if PING.at(me, from).swap(0, Ordering::Acquire) != 0 {
                    GOT_PING.at(me, from).store(1, Ordering::Relaxed);
                    PONG.at(from, me).store(1, Ordering::Release);
                    gic::send_sgi(from, SGI_PONG);
                }
            }
        }
        SGI_PONG => {
            for from in (0..cpus).filter(|&f| f != me) {
                if PONG.at(me, from).swap(0, Ordering::Acquire) != 0 {
                    GOT_PONG.at(me, from).store(1, Ordering::Relaxed);
                }
            }
        }
        SGI_GO if GO[me].swap(0, Ordering::Acquire) != 0 => ping_all(me, cpus),
        _ => {}
    }
    gic::end(ack);
}

fn ping_all(me: usize, cpus: usize) {
    for to in (0..cpus).filter(|&t| t != me) {
        PING.at(to, me).store(1, Ordering::Release);
        gic::send_sgi(to, SGI_PING);
    }
}

/// The probe of the SGIs, on CPU 0, with every CPU up: each CPU pings each
/// other one and gets its pong. CPU 0 serves its own SGIs by polling. Stops
/// the kernel naming the pair whose ping or pong did not come.
pub fn sgi_probe() {
    let cpus = cpus();
    if cpus < 2 {
        return;
    }
    for (to, go) in GO.iter().enumerate().take(cpus).skip(1) {
        go.store(1, Ordering::Release);
        gic::send_sgi(to, SGI_GO);
    }
    ping_all(0, cpus);
    let limit = timer::now() + WAIT_SECONDS * timer::frequency();
    loop {
        if crate::arch::irq_pending()
            && let Some(ack) = gic::acknowledge()
        {
            handle(ack);
        }
        let missing = (0..cpus)
            .flat_map(|to| (0..cpus).map(move |from| (to, from)))
            .find(|&(to, from)| to != from && GOT_PONG.at(to, from).load(Ordering::Relaxed) == 0);
        let Some((to, from)) = missing else { break };
        if timer::now() > limit {
            panic!("SGI probe: the ping of CPU {to} to CPU {from} got no pong");
        }
    }
    for to in 0..cpus {
        for from in (0..cpus).filter(|&f| f != to) {
            if GOT_PING.at(to, from).load(Ordering::Relaxed) == 0 {
                panic!("SGI probe: CPU {to} never saw the ping of CPU {from}");
            }
        }
    }
    kprintln!(
        "sgi        {cpus} CPUs, all {} pairs: ping and pong ok",
        cpus * (cpus - 1)
    );
}
