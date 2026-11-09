// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The GICv3 ITS and the LPI tables (spec 9, 8.1; [G40]-[G48]): the tables
//! the redistributors and the ITS read, taken from RAM at boot outside
//! every quota (spec 7.8), the command queue, and the collection of each
//! CPU. The queue is written under `ITS_LOCK`, which is never held with
//! `OBJ`, and only while commands go into it; the wait for the ITS to run
//! them is outside the lock, in segments of POLLS reads of GITS_CREADR.
//! Programs never reach the registers or the tables: the ITS maps events of
//! a device to LPIs on behalf of the kernel alone.

#![allow(dead_code)]

use super::cpu;
use super::mmio;
use super::{cache, timer};
use crate::mm::phys;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use kcore::PAGE_SIZE;
use kcore::bootinfo::BootInfo;
use kcore::its::{self, Command};
use kcore::layout::LINEAR_BASE;
use kcore::quota::Account;
use kcore::sync::Ticket;

/// Reads of GITS_CREADR in one segment of a wait: a segment is what the
/// kernel spends outside `OBJ` between two looks at the system (spec 8.1).
const POLLS: u32 = 1000;
/// The wait for commands, in seconds of the counter, before the ITS is
/// taken for stopped (Linux gives it the same second).
const STALL_SECONDS: u64 = 1;

/// Virtual address of the ITS control frame; 0 without an ITS.
static BASE: AtomicUsize = AtomicUsize::new(0);
/// The size of an ITT entry, GITS_TYPER.
static ITT_ENTRY: AtomicUsize = AtomicUsize::new(0);
/// Whether the target of a collection is a physical address (PTA).
static PTA: AtomicBool = AtomicBool::new(false);
/// The tables have no shareability: lines are cleaned after each write.
static NON_SHAREABLE: AtomicBool = AtomicBool::new(false);
/// The physical address of GITS_TRANSLATER.
static TRANSLATER: AtomicU64 = AtomicU64::new(0);
/// The largest DeviceID the device table holds.
static MAX_DEVICE_ID: AtomicU32 = AtomicU32::new(0);
/// The property table (virtual address) and its physical address.
static PROP_VA: AtomicUsize = AtomicUsize::new(0);
static PROP_PA: AtomicU64 = AtomicU64::new(0);
/// The pending table of each CPU, physical addresses.
static PEND_PA: [AtomicU64; cpu::MAX_CPUS] = [const { AtomicU64::new(0) }; cpu::MAX_CPUS];
/// The longest segment of a wait, in counter ticks (`its command ticks`).
static LONGEST: AtomicU64 = AtomicU64::new(0);
/// A wait that took more than one segment, and the commands that went.
static LONG_WAITS: AtomicU64 = AtomicU64::new(0);
static COMMANDS: AtomicU64 = AtomicU64::new(0);

/// The queue: its virtual address and the offset the next command goes
/// to, which `ITS_LOCK` guards.
struct Queue {
    va: usize,
    write: usize,
}

struct Guarded(UnsafeCell<Queue>);

// SAFETY: the queue is reached only with `ITS_LOCK` held.
unsafe impl Sync for Guarded {}

static ITS_LOCK: Ticket = Ticket::new();
static QUEUE: Guarded = Guarded(UnsafeCell::new(Queue { va: 0, write: 0 }));

/// Where the commands of a `send` end in the queue: the CREADR offset
/// `wait` waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position(usize);

/// Whether the machine has an ITS the kernel drives.
pub fn present() -> bool {
    BASE.load(Ordering::Relaxed) != 0
}

/// The address a device writes the EventID to: GITS_TRANSLATER.
pub fn translater() -> u64 {
    TRANSLATER.load(Ordering::Relaxed)
}

/// The bytes of an ITT entry, from GITS_TYPER.
pub fn itt_entry() -> usize {
    ITT_ENTRY.load(Ordering::Relaxed)
}

/// The largest DeviceID the ITS has a place for.
pub fn max_device_id() -> u32 {
    MAX_DEVICE_ID.load(Ordering::Relaxed)
}

fn reg(at: usize) -> usize {
    BASE.load(Ordering::Relaxed) + at
}

fn read32(at: usize) -> u32 {
    // SAFETY: `init` stored the base of the ITS frame, which the kernel
    // tables map as device memory; `at` is a register of it.
    unsafe { mmio::read32(reg(at)) }
}

fn read64(at: usize) -> u64 {
    // SAFETY: as in `read32`; the 64-bit registers are 8-byte aligned.
    unsafe { mmio::read64(reg(at)) }
}

fn write32(at: usize, value: u32) {
    // SAFETY: as in `read32`.
    unsafe { mmio::write32(reg(at), value) }
}

fn write64(at: usize, value: u64) {
    // SAFETY: as in `read64`.
    unsafe { mmio::write64(reg(at), value) }
}

/// A block of 2^`order` frames from the allocator, outside every quota:
/// the boot reserve (spec 7.8) never goes back. The pointer is its virtual
/// address in the linear map, zeroed.
fn boot_block(order: u8) -> (usize, u64) {
    let mut account = Account::new(u64::MAX / 2);
    let frame = phys::alloc_zeroed(order, &mut account).expect("no frame for the ITS tables");
    let pa = frame.pa();
    // The block stays for good: the frame is forgotten, not freed.
    let _ = frame.into_raw();
    (LINEAR_BASE + pa as usize, pa)
}

/// The cacheability and shareability the tables get: inner shareable
/// write-back, or, when the registers hold no shareability, non-cacheable
/// with a clean after each write [G41].
fn attributes() -> (u64, u64) {
    if NON_SHAREABLE.load(Ordering::Relaxed) {
        (its::SHARE_NON, its::CACHE_NC)
    } else {
        (its::SHARE_INNER, its::CACHE_RAWAWB)
    }
}

/// Cleans the bytes ITS or a redistributor reads, when they are not
/// shareable.
fn publish(va: usize, len: usize) {
    if NON_SHAREABLE.load(Ordering::Relaxed) {
        cache::clean_to_memory(va, len);
    }
}

/// Sets the ITS up on the boot CPU, from the device tree (spec 9): the
/// property table, the pending tables of every CPU, the command queue, the
/// tables of devices and collections; GITS_CTLR.Enabled. `redistributor`
/// is the first RD_base frame, whose registers tell the shareability the
/// GIC implements. Does nothing without an ITS in the tree.
pub fn init(info: &BootInfo, redistributor: usize) {
    let Some(node) = info.its else {
        return;
    };
    let Some(max_device) = info.max_device_id() else {
        return;
    };
    BASE.store(LINEAR_BASE + node.regs.base as usize, Ordering::Relaxed);
    TRANSLATER.store(node.regs.base + its::GITS_TRANSLATER, Ordering::Relaxed);
    let typer = read64(its::GITS_TYPER);
    assert!(typer & 1 != 0, "the ITS has no physical LPIs");
    ITT_ENTRY.store(its::typer_itt_entry_size(typer) as usize, Ordering::Relaxed);
    PTA.store(its::typer_pta(typer), Ordering::Relaxed);
    let cpus = info.cpus.as_slice().len().max(1);
    // Shareability: writing inner shareable and reading zero back means the
    // GIC does not snoop; the tables are then non-cacheable and cleaned.
    // SAFETY: GICR_PROPBASER is a 64-bit register of the first RD_base
    // frame, which `init_v3` found and the tables map; LPIs are still off.
    let probe = unsafe {
        let at = redistributor + its::GICR_PROPBASER;
        mmio::write64(at, its::propbaser(0, its::ID_BITS, its::SHARE_INNER, 0));
        let read = mmio::read64(at);
        mmio::write64(at, 0);
        read
    };
    NON_SHAREABLE.store((probe >> 10) & 3 == 0, Ordering::Relaxed);
    let (share, cache) = attributes();

    let (prop_va, prop_pa) = boot_block(1);
    // Every LPI starts disabled; priority and Group 1 are set at the bind.
    // SAFETY: the block is ours and PROP_TABLE_BYTES long.
    unsafe {
        core::ptr::write_bytes(
            (prop_va) as *mut u8,
            its::prop_byte(0xA0) & !1,
            its::PROP_TABLE_BYTES,
        )
    };
    publish(prop_va, its::PROP_TABLE_BYTES);
    PROP_VA.store(prop_va, Ordering::Relaxed);
    PROP_PA.store(prop_pa, Ordering::Relaxed);

    for table in PEND_PA.iter().take(cpus) {
        // The pending table needs 64 KiB alignment, which only a block of
        // 16 frames has; the allocator takes blocks back whole, so the rest
        // of the block stays with the table (spec 7.8).
        let (_, pa) = boot_block(4);
        table.store(pa, Ordering::Relaxed);
    }

    // The ITS is off while its tables change.
    write32(its::GITS_CTLR, 0);
    for _ in 0..1_000_000 {
        if read32(its::GITS_CTLR) & its::CTLR_QUIESCENT != 0 {
            break;
        }
    }
    let (queue_va, queue_pa) = boot_block(0);
    // SAFETY: only this CPU runs and the queue is not in use yet.
    unsafe { (*QUEUE.0.get()).va = queue_va };
    write64(its::GITS_CBASER, its::cbaser(queue_pa, 1, share, cache));
    write64(its::GITS_CWRITER, 0);
    for n in 0..its::BASER_COUNT {
        let at = its::GITS_BASER + 8 * n;
        let old = read64(at);
        let pages = match its::baser_type(old) {
            its::BASER_TYPE_DEVICE => {
                // A flat table of at most 16 pages: DeviceIDs past it are
                // refused at msi_create (decision, section 4).
                let entry = its::baser_entry_size(old);
                let top = (16 * PAGE_SIZE / entry - 1) as u32;
                let max_device = max_device.min(top);
                MAX_DEVICE_ID.store(max_device, Ordering::Relaxed);
                its::device_table_pages(max_device, entry, 16).expect("a table of 16 pages")
            }
            its::BASER_TYPE_COLLECTION => {
                if its::typer_hcc(typer) >= cpus as u64 {
                    continue;
                }
                its::collection_table_pages(cpus, its::baser_entry_size(old))
            }
            _ => continue,
        };
        let order = pages.next_power_of_two().trailing_zeros() as u8;
        let (_, pa) = boot_block(order);
        // Pages of 4 KiB; a table that reads another page size back is
        // sized in its pages.
        write64(at, its::baser(old, pa, 1 << order, share, cache));
        let new = read64(at);
        assert!(
            its::baser_page_size(new) == PAGE_SIZE,
            "the ITS takes no 4 KiB table pages"
        );
    }
    write32(its::GITS_CTLR, its::CTLR_ENABLED);
}

/// This CPU's part of the LPIs, called by `gic::init_v3_cpu` once the
/// redistributor at `rd` is awake: the tables, EnableLPIs, and the CPU's
/// collection (ICID = the CPU's number) mapped to it (spec 9).
pub fn init_cpu(rd: usize) {
    if !present() {
        return;
    }
    let cpu = cpu::this().index();
    // SAFETY: GICR_CTLR, GICR_PROPBASER and GICR_PENDBASER are registers of
    // this CPU's RD_base frame.
    unsafe {
        let ctlr = mmio::read32(rd + kcore::gic::GICR_CTLR);
        // EnableLPIs set by firmware would leave tables the kernel did not
        // give; only AWS can show it (decision, section 6).
        assert!(
            ctlr & its::GICR_CTLR_ENABLE_LPIS == 0,
            "EnableLPIs was set before the kernel: the firmware's tables are in use"
        );
        let (share, cache) = attributes();
        mmio::write64(
            rd + its::GICR_PROPBASER,
            its::propbaser(PROP_PA.load(Ordering::Relaxed), its::ID_BITS, share, cache),
        );
        mmio::write64(
            rd + its::GICR_PENDBASER,
            its::pendbaser(PEND_PA[cpu].load(Ordering::Relaxed), share, cache),
        );
        mmio::write32(
            rd + kcore::gic::GICR_CTLR,
            ctlr | its::GICR_CTLR_ENABLE_LPIS,
        );
    }
    let typer = read64(its::GITS_TYPER);
    let target = if its::typer_pta(typer) {
        (rd - LINEAR_BASE) as u64
    } else {
        // SAFETY: GICR_TYPER is a 64-bit register of the RD_base frame.
        its::processor_number(unsafe { mmio::read64(rd + kcore::gic::GICR_TYPER) }) << 16
    };
    RDBASE[cpu].store(target, Ordering::Relaxed);
    let pos = send(&[
        Command::mapc(cpu as u16, target, true),
        Command::sync(target),
    ]);
    wait(pos, "MAPC");
}

/// The RDbase each CPU's collection was mapped to.
static RDBASE: [AtomicU64; cpu::MAX_CPUS] = [const { AtomicU64::new(0) }; cpu::MAX_CPUS];

/// The RDbase of CPU `cpu`'s collection, for the SYNC of a command.
pub fn rdbase(cpu: usize) -> u64 {
    RDBASE[cpu].load(Ordering::Relaxed)
}

/// Puts `commands` (at most MAX_BATCH) into the queue and tells the ITS:
/// `ITS_LOCK` is held for the writes and the write of GITS_CWRITER, no
/// longer (spec 8.1). The caller holds no `OBJ`, and `wait`s for the
/// position.
#[must_use = "the commands run when `wait` has seen them done"]
pub fn send(commands: &[Command]) -> Position {
    crate::obj::assert_not_held();
    assert!(commands.len() <= its::MAX_BATCH, "too many ITS commands");
    let ticket = ITS_LOCK.lock();
    // SAFETY: `ITS_LOCK` is held.
    let queue = unsafe { &mut *QUEUE.0.get() };
    let creadr = (read64(its::GITS_CREADR) & its::OFFSET_MASK) as usize;
    assert!(
        its::free_slots(creadr, queue.write) >= commands.len(),
        "the ITS command queue is full"
    );
    for command in commands {
        let at = queue.va + queue.write;
        for (i, word) in command.0.iter().enumerate() {
            // SAFETY: the slot is inside the queue page and the ITS does
            // not read it before CWRITER moves.
            unsafe { core::ptr::write_volatile((at + 8 * i) as *mut u64, *word) };
        }
        publish(at, its::COMMAND_BYTES);
        queue.write = its::next_offset(queue.write);
    }
    // SAFETY: the stores to the queue reach memory before the register
    // write that tells the ITS.
    unsafe { core::arch::asm!("dsb sy", options(nostack, preserves_flags)) };
    write64(its::GITS_CWRITER, queue.write as u64);
    LAST.store(commands.last().map_or(0, |c| c.0[0]), Ordering::Relaxed);
    COMMANDS.fetch_add(commands.len() as u64, Ordering::Relaxed);
    let end = queue.write;
    ITS_LOCK.unlock(ticket);
    Position(end)
}

/// The opcode and device of the command last written, for the message of
/// a stalled ITS.
static LAST: AtomicU64 = AtomicU64::new(0);

/// True once the ITS has read up to `pos`: the commands before it ran.
fn reached(pos: Position) -> bool {
    let creadr = (read64(its::GITS_CREADR) & its::OFFSET_MASK) as usize;
    // Commands between the ITS's position and the end of the batch are
    // still to run. At most MAX_BATCH of each CPU wait in the queue, so a
    // distance past the rest of the ring means the ITS is ahead of `pos`
    // already.
    let left = its::pending(creadr, pos.0);
    left == 0 || left > its::QUEUE_SLOTS - its::MAX_BATCH * cpu::MAX_CPUS
}

/// Waits for the commands up to `pos` in segments of POLLS reads of
/// GITS_CREADR; the longest segment is counted (`longest`). A queue that
/// does not move for STALL_SECONDS is a stopped ITS: the kernel stops,
/// naming the command (`what`).
pub fn wait(pos: Position, what: &str) {
    let limit = timer::frequency() * STALL_SECONDS;
    let began = timer::now();
    loop {
        let segment = timer::now();
        for _ in 0..POLLS {
            if reached(pos) {
                let took = timer::now() - segment;
                LONGEST.fetch_max(took, Ordering::Relaxed);
                return;
            }
        }
        let took = timer::now() - segment;
        LONGEST.fetch_max(took, Ordering::Relaxed);
        LONG_WAITS.fetch_add(1, Ordering::Relaxed);
        if timer::now() - began > limit {
            panic!(
                "the ITS stopped at {what}: GITS_CREADR {:#x}, CWRITER {:#x}, last opcode {:#x}",
                read64(its::GITS_CREADR),
                read64(its::GITS_CWRITER),
                LAST.load(Ordering::Relaxed) & 0xFF
            );
        }
    }
}

/// Writes the property byte of LPI `intid`: `Some(priority)` enables it,
/// None disables it, and cleans the line when the GIC does not snoop. The
/// redistributors reread it at the next INV (`Command::inv`).
pub fn set_property(intid: u32, priority: Option<u8>) {
    let at = PROP_VA.load(Ordering::Relaxed) + its::prop_index(intid);
    let byte = match priority {
        Some(p) => its::prop_byte(p),
        None => its::prop_byte(0xA0) & !its::PROP_ENABLE,
    };
    // SAFETY: the byte is inside the property table, which only the
    // redistributors and this function touch.
    unsafe { core::ptr::write_volatile(at as *mut u8, byte) };
    publish(at, 1);
}

/// Cleans the bytes of an ITT the ITS will read, when it needs it.
pub fn publish_itt(va: usize, len: usize) {
    publish(va, len);
}

/// The longest segment of a wait, the waits that took more than one, and
/// the commands sent: the `its command ticks` line of the probe.
pub fn stats() -> (u64, u64, u64) {
    (
        LONGEST.load(Ordering::Relaxed),
        LONG_WAITS.load(Ordering::Relaxed),
        COMMANDS.load(Ordering::Relaxed),
    )
}

/// The physical address of a kernel address in the linear map, for the ITT
/// and the queue the ITS reads.
pub fn pa(va: usize) -> u64 {
    (va - LINEAR_BASE) as u64
}
