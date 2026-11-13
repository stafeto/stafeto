// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The GICv3 ITS and the LPI tables (spec 9, 8.1; [G40]-[G48]): the tables
//! the redistributors and the ITS read, taken from RAM at boot outside
//! every quota (spec 7.8), the command queue, and the collection of each
//! CPU. The queue memory and the count are written under `Q_LOCK`, a leaf
//! that touches no register: a section under `OBJ` puts the commands of a
//! call into the queue in the order of the sections (`enqueue`), which keeps
//! a MAPTI behind the MAPD of its device and a teardown behind the mapping
//! it ends, and a sender outside `OBJ` puts them in the same way
//! (`try_send`). The registers belong to `RING_LOCK`, taken outside `OBJ`
//! alone: the reads of GITS_CREADR that refresh the count of commands run,
//! and the write of GITS_CWRITER that starts them (`ring`). A register
//! access may take long on a machine that models the ITS in its hypervisor,
//! and no section waits for one. The room a section asks for is counted
//! against the last count of commands run that anyone saw, which only lags. Commands are counted in 64 bits (`SENT`):
//! a call waits for a count, and what the ITS has run is that count less
//! the commands it has still to read (kcore::its::done). A wait is one
//! segment of POLLS reads of GITS_CREADR at most in a call (`wait_once`),
//! and in a portion of cleanup one look at the count (`step`). Programs
//! never reach the registers or the tables: the ITS maps events of a
//! device to LPIs on behalf of the kernel alone.

use super::cpu;
use super::mmio;
use super::{cache, timer};
use crate::mm::phys;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use kcore::bootinfo::BootInfo;
use kcore::gic::FIRST_LPI;
use kcore::its::{self, Command};
use kcore::layout::LINEAR_BASE;
use kcore::quota::Account;
use kcore::sync::{SetOnce, Ticket};

/// Reads of GITS_CREADR in one segment of a wait: a segment is what the
/// kernel spends outside `OBJ` between two looks at the system (spec 8.1).
const POLLS: u32 = 1000;
/// With the feature `its-slow`: the reads of GITS_CREADR a wait makes past
/// the one that shows the commands done, five segments.
#[cfg(feature = "its-slow")]
const SLOW_READS: u32 = 5 * POLLS;
#[cfg(all(feature = "its-slow", not(feature = "ktest")))]
compile_error!("its-slow is a deliberate breakage for the kernel tests alone");
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
/// RD_base registers the boot reads and writes for each CPU, kept for the
/// lines `report_cpus` prints once every CPU is up (a CPU in bring-up prints
/// nothing); only the kernel feature `its-int` keeps them.
#[cfg(feature = "its-int")]
const E_CTLR: usize = 0;
#[cfg(feature = "its-int")]
const E_TYPER: usize = 1;
#[cfg(feature = "its-int")]
const E_PROP: usize = 2;
#[cfg(feature = "its-int")]
const E_PEND: usize = 3;
const S_PROP_WROTE: usize = 4;
const S_PROP_READ: usize = 5;
const S_PEND_WROTE: usize = 6;
const S_PEND_READ: usize = 7;
const S_CTLR: usize = 8;
#[cfg(feature = "its-int")]
const CLEARED: usize = 9;
const TARGET: usize = 10;
const SET_DONE: usize = 11;
/// Sixteen words a CPU, so that the index is a shift (erratum 835769).
#[cfg(feature = "its-int")]
static CPU_LOG: [[AtomicU64; 16]; cpu::MAX_CPUS] =
    [const { [const { AtomicU64::new(0) }; 16] }; cpu::MAX_CPUS];
/// The wait for Register Write Pending after EnableLPIs is cleared: a tenth
/// of a second of the counter (100 ms) on each CPU at boot, outside `OBJ`,
/// however long a trapped read of GICR_CTLR takes.
const RWP_DIV: u64 = 10;
/// The wait of the boot self-test for one LPI: 10 ms of the counter.
const SELFTEST_HZ_DIV: u64 = 100;
/// The longest segment of a wait, in counter ticks (`its command ticks`).
#[cfg(feature = "ktest")]
static LONGEST: AtomicU64 = AtomicU64::new(0);
/// A wait that took more than one segment, and the commands that went.
#[cfg(feature = "ktest")]
static LONG_WAITS: AtomicU64 = AtomicU64::new(0);

/// The queue: its virtual address, which `Q_LOCK` guards.
struct Queue {
    va: usize,
}

struct Guarded(UnsafeCell<Queue>);

// SAFETY: the queue is reached only with `Q_LOCK` held.
unsafe impl Sync for Guarded {}

/// Guards the queue memory and the stores to `SENT`; held for a few
/// instructions, a leaf under `OBJ`, and never with a register access.
static Q_LOCK: Ticket = Ticket::new();
/// Guards GITS_CREADR reads and GITS_CWRITER writes; taken outside `OBJ`
/// only, and `Q_LOCK` may be taken under it.
static RING_LOCK: Ticket = Ticket::new();
static QUEUE: Guarded = Guarded(UnsafeCell::new(Queue { va: 0 }));
/// The commands put in the queue so far: written under `Q_LOCK`, read
/// without it. The queue starts empty at offset 0, so the offset of the
/// next command follows from it (kcore::its::write_offset).
static SENT: AtomicU64 = AtomicU64::new(0);
/// The count of commands GITS_CWRITER shows the ITS, under `RING_LOCK`.
static RUNG: AtomicU64 = AtomicU64::new(0);
/// The most commands the ITS was seen to have run: a count that only lags
/// the truth, which the room of a section is counted against.
static DONE_CACHE: AtomicU64 = AtomicU64::new(0);
/// The counter's time when `DONE_CACHE` last advanced, and when commands
/// last went in: the stall clock of the ITS (kcore::its::stalled).
static LAST_ADVANCE: AtomicU64 = AtomicU64::new(0);
static LAST_SEND: AtomicU64 = AtomicU64::new(0);
/// With the feature `its-slow`: the reads the ITS still seems slow for,
/// set at each send.
#[cfg(feature = "its-slow")]
static SLOW_LEFT: AtomicU32 = AtomicU32::new(0);

/// The count of commands sent when the commands of a call had gone in:
/// what `wait` and `reached` wait for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position(u64);

impl Position {
    /// The count itself, which a binding keeps to say later whether its
    /// mapping is in force (`mapped`).
    pub const fn count(self) -> u64 {
        self.0
    }
}

/// The device tree's `msi-map`, which msi_create translates requester IDs
/// with, and the tree it came from.
static TREE: SetOnce<BootInfo> = SetOnce::new();

/// The DeviceID the ITS sees for the requester ID `rid` (spec 9), from the
/// `msi-map` of the tree.
pub fn device_id(rid: u32) -> Option<u32> {
    TREE.get()?.device_id(rid)
}

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
#[inline(never)]
fn boot_block(order: u8) -> (usize, u64) {
    let mut account = Account::new(u64::MAX / 2);
    let frame = phys::alloc_zeroed(order, &mut account).expect("no frame for the ITS tables");
    let pa = frame.pa();
    // The block stays for good: the frame is forgotten, not freed.
    let _ = frame.into_raw();
    (LINEAR_BASE + pa as usize, pa)
}

/// A block for a table the hypervisor reads on a 64 KiB boundary: the queue
/// and the property table (`its::QUEUE_ORDER`, `its::PROP_ORDER`); each
/// block is checked to start on one. The break `break-its-align-4k` takes the
/// 4 KiB and 8 KiB blocks of before.
fn aligned_block(order: u8) -> (usize, u64) {
    let (va, pa) = boot_block(order);
    #[cfg(not(feature = "break-its-align-4k"))]
    assert!(its::table_aligned(pa), "an ITS table is not on 64 KiB");
    (va, pa)
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
#[inline(never)]
pub fn init(info: &BootInfo, redistributor: usize) {
    let Some(node) = info.its else {
        return;
    };
    let Some(max_device) = info.max_device_id() else {
        return;
    };
    assert!(TREE.set(*info).is_ok(), "its::init runs once");
    #[cfg(feature = "its-lpis-preset")]
    preset_lpis(redistributor);
    #[cfg(feature = "its-int")]
    record_entry(cpu::this().index(), redistributor);
    if let Err(why) = setup(info, node.regs.base, max_device, redistributor) {
        // Nothing has enabled the ITS yet: it stays off and the machine runs
        // without MSI (spec 9). `BASE` stays 0, so `present` says no.
        write32_at(node.regs.base, its::GITS_CTLR, 0);
        if !why.is_empty() {
            kprintln!("its off: {why}");
        }
    }
}

/// What a CPU's redistributor holds when the kernel gets it.
#[cfg(feature = "its-int")]
fn record_entry(cpu: usize, rd: usize) {
    let log = &CPU_LOG[cpu];
    // SAFETY: GICR_CTLR, GICR_TYPER, GICR_PROPBASER and GICR_PENDBASER are
    // registers of the CPU's RD_base frame, which the kernel tables map.
    unsafe {
        log[E_CTLR].store(
            u64::from(mmio::read32(rd + kcore::gic::GICR_CTLR)),
            Ordering::Relaxed,
        );
        note(cpu, E_TYPER, mmio::read64(rd + kcore::gic::GICR_TYPER));
        note(cpu, E_PROP, mmio::read64(rd + its::GICR_PROPBASER));
        note(cpu, E_PEND, mmio::read64(rd + its::GICR_PENDBASER));
    }
}

/// With the feature `its-lpis-preset`: every redistributor comes with tables
/// of its own and EnableLPIs set, as firmware that used LPIs would leave it
/// (xtask its-lpis).
#[cfg(feature = "its-lpis-preset")]
fn preset_lpis(first: usize) {
    let mut rd = first;
    loop {
        // SAFETY: the frames of the redistributors of the window, mapped.
        let typer = unsafe {
            mmio::write64(
                rd + its::GICR_PROPBASER,
                its::propbaser(0x0900_0000, its::ID_BITS, its::SHARE_NON, its::CACHE_NC),
            );
            mmio::write64(
                rd + its::GICR_PENDBASER,
                its::pendbaser(0x0900_0000, its::SHARE_NON, its::CACHE_NC),
            );
            mmio::write32(rd + kcore::gic::GICR_CTLR, its::GICR_CTLR_ENABLE_LPIS);
            mmio::read64(rd + kcore::gic::GICR_TYPER)
        };
        // GICR_TYPER.Last, and VLPIS (two more frames).
        if typer & (1 << 4) != 0 {
            return;
        }
        rd += if typer & (1 << 1) != 0 {
            0x4_0000
        } else {
            0x2_0000
        };
    }
}

/// Clears EnableLPIs of the redistributor at `rd` as Linux does (write 0,
/// wait for Register Write Pending, read again): Err(GICR_CTLR) when the
/// bit stays or RWP does not clear in 100 ms. The break
/// `break-its-keep-firmware-lpis` leaves the bit as it is.
#[inline(never)]
fn clear_lpis(rd: usize) -> Result<(), u32> {
    if cfg!(feature = "break-its-keep-firmware-lpis") {
        return Ok(());
    }
    let ctlr = rd + kcore::gic::GICR_CTLR;
    its::clear_enable_lpis(
        // SAFETY: GICR_CTLR of the RD_base frame at `rd`, mapped.
        || unsafe { mmio::read32(ctlr) },
        // SAFETY: as above.
        |v| unsafe { mmio::write32(ctlr, v) },
        || {
            let limit = timer::frequency() / RWP_DIV;
            let began = timer::now();
            loop {
                // SAFETY: as above.
                if unsafe { mmio::read32(ctlr) } & kcore::gic::GICR_CTLR_RWP == 0 {
                    return true;
                }
                if timer::now() - began > limit {
                    return false;
                }
            }
        },
    )
}

/// A CPU found the ITS unusable after it was on: the ITS is turned off, MSI
/// with it, and the line says which register of which CPU. The console takes
/// the line from a CPU in bring-up, which CPU 0 does not use meanwhile; only
/// CPU 0's boot uses the ITS.
fn off_cpu(reg: &str, cpu: usize, wrote: u64, read: u64) {
    write32(its::GITS_CTLR, 0);
    BASE.store(0, Ordering::Relaxed);
    kprintln!("its off: {reg} (CPU {cpu}) reads back {read:#x} (wrote {wrote:#x})");
}

/// `GITS_CTLR` written before `BASE` is set.
fn write32_at(base: u64, at: usize, value: u32) {
    // SAFETY: a register of the ITS control frame, which the kernel tables map.
    unsafe { mmio::write32(LINEAR_BASE + base as usize + at, value) }
}

/// The page sizes ladder starts at: 4 KiB, or 64 KiB in the probe image.
const FIRST_PAGE: u64 = if cfg!(feature = "its-page-64k") {
    0x1_0000
} else {
    0x1000
};

/// A block of the allocator for a table of `bytes`, zeroed and cleaned to
/// the point of coherency: the ITS may not snoop the caches.
fn table_block(bytes: usize) -> u64 {
    let (va, pa) = boot_block(its::block_order(bytes));
    cache::clean_to_memory(va, bytes);
    pa
}

/// Everything up to `GITS_CTLR.Enabled`; an Err is the reason the ITS stays
/// off, said in one line (decision 2026-11-13, 1.5).
fn setup(
    info: &BootInfo,
    regs: u64,
    max_device: u32,
    redistributor: usize,
) -> Result<(), &'static str> {
    BASE.store(LINEAR_BASE + regs as usize, Ordering::Relaxed);
    let off = |why: &'static str| -> Result<(), &'static str> {
        BASE.store(0, Ordering::Relaxed);
        Err(why)
    };
    TRANSLATER.store(regs + its::GITS_TRANSLATER, Ordering::Relaxed);
    let typer = read64(its::GITS_TYPER);
    let gicd = info.gic.as_ref().map(|g| g.mapped()[0].base).unwrap_or(0);
    let gicd_typer = if gicd != 0 {
        // SAFETY: GICD_TYPER is a 32-bit register of the distributor, mapped.
        unsafe { mmio::read32(LINEAR_BASE + gicd as usize + 0x4) }
    } else {
        0
    };
    let iidr = read32(0x4);
    kprintln!("its typer {typer:#x} gicd_typer {gicd_typer:#x} iidr {iidr:#x}");
    #[cfg(feature = "its-int")]
    if gicd != 0 {
        // SAFETY: GICD_IIDR is a 32-bit register of the distributor, mapped.
        let gicd_iidr = unsafe { mmio::read32(LINEAR_BASE + gicd as usize + 0x8) };
        kprintln!("gicd iidr {gicd_iidr:#x}");
    }
    if typer & 1 == 0 {
        return off("no physical LPIs");
    }
    if gicd != 0 && (!its::gicd_lpis(gicd_typer) || its::gicd_id_bits(gicd_typer) < its::ID_BITS) {
        return off("the distributor takes no 14-bit LPIs");
    }
    // SAFETY: GICR_TYPER of the first RD_base frame, mapped.
    if unsafe { mmio::read64(redistributor + kcore::gic::GICR_TYPER) } & its::GICR_TYPER_PLPIS == 0
    {
        return off("the redistributor takes no physical LPIs");
    }
    // EnableLPIs set by firmware: the register writes below need it clear.
    if clear_lpis(redistributor).is_err() {
        return off("EnableLPIs stays set at entry");
    }
    crate::irq::set_lpi_limit(its::lpi_limit(gicd_typer));
    ITT_ENTRY.store(its::typer_itt_entry_size(typer) as usize, Ordering::Relaxed);
    PTA.store(its::typer_pta(typer), Ordering::Relaxed);
    let cpus = info.cpus.as_slice().len().max(1);

    // The ITS is off while its tables change.
    write32(its::GITS_CTLR, 0);
    let mut quiet = false;
    for _ in 0..1_000_000 {
        if read32(its::GITS_CTLR) & its::CTLR_QUIESCENT != 0 {
            quiet = true;
            break;
        }
    }
    if !quiet {
        return off("not quiescent");
    }

    // Shareability: every register written inner shareable write-back is read
    // back; one that holds neither puts the whole ITS in the mode without
    // shareability (tables non-cacheable, cleaned by hand) [G51].
    let mut holds = !cfg!(feature = "its-nonshare");
    // SAFETY: GICR_PROPBASER is a 64-bit register of the first RD_base
    // frame, which `init_v3` found and the tables map; LPIs are still off.
    unsafe {
        let at = redistributor + its::GICR_PROPBASER;
        mmio::write64(
            at,
            its::propbaser(0, its::ID_BITS, its::SHARE_INNER, its::CACHE_RAWAWB),
        );
        holds &= its::holds_shareability(mmio::read64(at));
        mmio::write64(at, 0);
    }
    let (queue_va, queue_pa) = aligned_block(its::QUEUE_ORDER);
    cache::clean_to_memory(queue_va, its::QUEUE_BYTES);
    // SAFETY: only this CPU runs and the queue is not in use yet.
    unsafe { (*QUEUE.0.get()).va = queue_va };
    write64(
        its::GITS_CBASER,
        its::cbaser(queue_pa, 1, its::SHARE_INNER, its::CACHE_RAWAWB),
    );
    holds &= its::holds_shareability(read64(its::GITS_CBASER));
    let mut pages = [0u64; its::BASER_COUNT];
    for (n, page) in pages.iter_mut().enumerate() {
        let at = its::GITS_BASER + 8 * n;
        let old = read64(at);
        if !matches!(
            its::baser_type(old),
            its::BASER_TYPE_DEVICE | its::BASER_TYPE_COLLECTION
        ) {
            continue;
        }
        let Some(size) = its::pick_page(old, FIRST_PAGE, |probe| {
            write64(at, probe);
            read64(at)
        }) else {
            return off("no page size");
        };
        *page = size;
    }
    NON_SHAREABLE.store(!holds, Ordering::Relaxed);
    let (share, cache_attr) = attributes();
    let cbaser = its::cbaser(queue_pa, 1, share, cache_attr);
    write64(its::GITS_CBASER, cbaser);
    let cbaser_read = read64(its::GITS_CBASER);
    #[cfg(feature = "its-int")]
    kprintln!("its cbaser wrote {cbaser:#x} read {cbaser_read:#x}");
    if let Err(back) = its::verify("GITS_CBASER", cbaser, cbaser_read, its::CBASER_CHECK) {
        off_cpu(back.reg, 0, back.wrote, back.read);
        // The line is printed.
        return Err("");
    }
    write64(its::GITS_CWRITER, 0);

    let (prop_va, prop_pa) = aligned_block(its::PROP_ORDER);
    // Every LPI starts disabled; priority and Group 1 are set at the bind.
    // SAFETY: the block is ours and PROP_TABLE_BYTES long.
    unsafe {
        core::ptr::write_bytes(
            prop_va as *mut u8,
            its::prop_byte(0xA0) & !1,
            its::PROP_TABLE_BYTES,
        )
    };
    cache::clean_to_memory(prop_va, its::PROP_TABLE_BYTES);
    PROP_VA.store(prop_va, Ordering::Relaxed);
    PROP_PA.store(prop_pa, Ordering::Relaxed);
    let mut tables = [0u64; cpu::MAX_CPUS];
    #[cfg(feature = "its-int")]
    let (mut dt_pa, mut ct_pa) = (0, 0);
    for (n, table) in PEND_PA.iter().take(cpus).enumerate() {
        // The pending table needs 64 KiB alignment, which only a block of
        // 16 frames has; the allocator takes blocks back whole, so the rest
        // of the block stays with the table (spec 7.8).
        let (va, pa) = boot_block(4);
        cache::clean_to_memory(va, its::PEND_TABLE_BYTES);
        table.store(pa, Ordering::Relaxed);
        tables[n] = pa;
    }

    for (n, page) in pages.into_iter().enumerate() {
        let at = its::GITS_BASER + 8 * n;
        let old = read64(at);
        if page == 0 {
            // A table the firmware left in its own memory is not the ITS's
            // any more once the boot services are gone [N11].
            write64(at, 0);
            continue;
        }
        let entry = its::baser_entry_size(old);
        let table = match its::baser_type(old) {
            its::BASER_TYPE_DEVICE => {
                let t = its::device_table(max_device, entry, its::typer_device_bits(typer), page);
                MAX_DEVICE_ID.store(t.entries - 1, Ordering::Relaxed);
                t
            }
            _ => {
                if its::typer_hcc(typer) >= cpus as u64 {
                    write64(at, 0);
                    continue;
                }
                its::collection_table(cpus, entry, page)
            }
        };
        if table.pages > 256 {
            return off("a table of over 256 pages");
        }
        let pa = table_block(table.bytes);
        #[cfg(feature = "its-int")]
        if its::baser_type(old) == its::BASER_TYPE_DEVICE {
            dt_pa = pa;
        } else {
            ct_pa = pa;
        }
        write64(
            at,
            its::baser(old, pa, table.pages, page, share, cache_attr),
        );
        let new = read64(at);
        let want = its::baser(old, pa, table.pages, page, share, cache_attr);
        kprintln!(
            "its baser{n} type {:#x} esz {entry} page {page:#x} pages {} ids {:#x} share {} cache {} was {old:#x}",
            its::baser_type(old),
            table.pages,
            table.entries - 1,
            (new >> 10) & 3,
            (new >> 59) & 7
        );
        #[cfg(feature = "its-int")]
        kprintln!("its baser{n} wrote {want:#x} read {new:#x}");
        // Page size, Size, Valid and the address must read as written; the
        // shareability fields may differ (they are the ITS's to refuse).
        if let Err(back) = its::verify("GITS_BASER", want, new, its::baser_check(page)) {
            off_cpu(back.reg, 0, back.wrote, back.read);
            // The line is printed.
            return Err("");
        }
    }
    #[cfg(feature = "its-int")]
    kprintln!(
        "{}",
        its::Tables {
            queue: queue_pa,
            prop: prop_pa,
            pend: &tables[..cpus],
            dt: dt_pa,
            ct: ct_pa,
        }
    );
    write32(its::GITS_CTLR, its::CTLR_ENABLED);
    kprintln!(
        "its on, non-shareable {}",
        NON_SHAREABLE.load(Ordering::Relaxed)
    );
    Ok(())
}

/// Keeps a register value of this CPU for `report_cpus` (feature `its-int`).
#[cfg(feature = "its-int")]
fn note(cpu: usize, at: usize, value: u64) {
    CPU_LOG[cpu][at].store(value, Ordering::Relaxed);
}

#[cfg(not(feature = "its-int"))]
fn note(_cpu: usize, _at: usize, _value: u64) {}

/// This CPU's part of the LPIs, called by `gic::init_v3_cpu` once the
/// redistributor at `rd` is awake: the tables, EnableLPIs, and the CPU's
/// collection (ICID = the CPU's number) mapped to it (spec 9).
#[inline(never)]
pub fn init_cpu(rd: usize) {
    if !present() {
        return;
    }
    let cpu = cpu::this().index();
    #[cfg(feature = "its-int")]
    if cpu != 0 {
        record_entry(cpu, rd);
    }
    // EnableLPIs set by firmware: clear it, as Linux does, or leave the ITS
    // off (the tables of the firmware stay in use otherwise).
    let ctlr_at = rd + kcore::gic::GICR_CTLR;
    if let Err(ctlr) = clear_lpis(rd) {
        off_cpu("EnableLPIs", cpu, 0, u64::from(ctlr));
        return;
    }
    #[cfg(feature = "its-int")]
    {
        // SAFETY: GICR_CTLR of this CPU's RD_base frame.
        let now = unsafe { mmio::read32(ctlr_at) } & its::GICR_CTLR_ENABLE_LPIS;
        let was =
            CPU_LOG[cpu][E_CTLR].load(Ordering::Relaxed) & u64::from(its::GICR_CTLR_ENABLE_LPIS);
        note(cpu, CLEARED, u64::from(was != 0 && now == 0));
    }
    let (share, cache) = attributes();
    let prop = its::propbaser(PROP_PA.load(Ordering::Relaxed), its::ID_BITS, share, cache);
    let pend = its::pendbaser(PEND_PA[cpu].load(Ordering::Relaxed), share, cache);
    // SAFETY: GICR_CTLR, GICR_PROPBASER and GICR_PENDBASER are registers of
    // this CPU's RD_base frame; EnableLPIs is clear, so the writes take.
    let (prop_read, pend_read) = unsafe {
        mmio::write64(rd + its::GICR_PROPBASER, prop);
        mmio::write64(rd + its::GICR_PENDBASER, pend);
        (
            mmio::read64(rd + its::GICR_PROPBASER),
            mmio::read64(rd + its::GICR_PENDBASER),
        )
    };
    note(cpu, S_PROP_WROTE, prop);
    note(cpu, S_PROP_READ, prop_read);
    note(cpu, S_PEND_WROTE, pend);
    note(cpu, S_PEND_READ, pend_read);
    note(cpu, SET_DONE, 1);
    if its::verify("GICR_PROPBASER", prop, prop_read, its::PROPBASER_CHECK).is_err() {
        off_cpu("GICR_PROPBASER", cpu, prop, prop_read);
        return;
    }
    if its::verify("GICR_PENDBASER", pend, pend_read, its::PENDBASER_CHECK).is_err() {
        off_cpu("GICR_PENDBASER", cpu, pend, pend_read);
        return;
    }
    // SAFETY: as above.
    let ctlr = unsafe {
        let ctlr = mmio::read32(ctlr_at);
        mmio::write32(ctlr_at, ctlr | its::GICR_CTLR_ENABLE_LPIS);
        mmio::read32(ctlr_at)
    };
    note(cpu, S_CTLR, u64::from(ctlr));
    let typer = read64(its::GITS_TYPER);
    let target = if its::typer_pta(typer) {
        (rd - LINEAR_BASE) as u64
    } else {
        // SAFETY: GICR_TYPER is a 64-bit register of the RD_base frame.
        its::processor_number(unsafe { mmio::read64(rd + kcore::gic::GICR_TYPER) }) << 16
    };
    RDBASE[cpu].store(target, Ordering::Relaxed);
    note(cpu, TARGET, target);
    let pos = send(&[
        Command::mapc(cpu as u16, target, true),
        Command::sync(target),
    ]);
    wait(pos, "MAPC");
}

#[cfg(feature = "its-int")]
/// Up to seven named words of a console line: ` name 0xvalue` each, those
/// after the last name left out.
struct Words([(&'static str, u64); 7]);

#[cfg(feature = "its-int")]
impl core::fmt::Display for Words {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (name, value) in self.0.iter().filter(|w| !w.0.is_empty()) {
            write!(f, " {name} {value:#x}")?;
        }
        Ok(())
    }
}

/// The lines about the redistributors and the ITS of every CPU, from the
/// values `record_entry` and `init_cpu` kept: the console of a CPU in
/// bring-up is not used. Then the reason a CPU turned the ITS off.
#[cfg(feature = "its-int")]
fn report_cpus() {
    for (cpu, log) in CPU_LOG.iter().enumerate().take(crate::smp::cpus()) {
        let get = |i: usize| log[i].load(Ordering::Relaxed);
        let words = |at: usize, names: &[&'static str]| {
            let mut w = Words([("", 0); 7]);
            for (n, name) in names.iter().enumerate() {
                w.0[n] = (*name, get(at + n));
            }
            w
        };
        kprintln!(
            "gicr cpu {cpu} entry{}",
            words(E_CTLR, &["ctlr", "typer", "propbaser", "pendbaser"])
        );
        if get(SET_DONE) != 0 {
            kprintln!(
                "gicr cpu {cpu} set{}",
                words(
                    S_PROP_WROTE,
                    &[
                        "propbaser",
                        "read",
                        "pendbaser",
                        "read",
                        "ctlr",
                        "cleared",
                        "mapc target"
                    ]
                )
            );
        }
    }
}

/// The RDbase each CPU's collection was mapped to.
static RDBASE: [AtomicU64; cpu::MAX_CPUS] = [const { AtomicU64::new(0) }; cpu::MAX_CPUS];

/// The RDbase of CPU `cpu`'s collection, for the SYNC of a command.
pub fn rdbase(cpu: usize) -> u64 {
    RDBASE[cpu].load(Ordering::Relaxed)
}

/// Notes that the ITS has run `done` of the `sent` commands.
fn observe(done: u64) {
    let old = DONE_CACHE.fetch_max(done, Ordering::Relaxed);
    if done > old {
        LAST_ADVANCE.fetch_max(timer::now(), Ordering::Relaxed);
    }
}

/// A consistent look at the queue without any lock: the commands the ITS
/// has run. GITS_CREADR is read between two reads of the count, and the look
/// is None when a command went in meanwhile, which the caller takes as "not
/// yet": it looks again at its next poll. The ITS cannot have passed the
/// count it was read against, so a look never shows more commands run than
/// there are. Outside `OBJ`.
fn look() -> Option<u64> {
    let sent = SENT.load(Ordering::Acquire);
    let creadr = (read64(its::GITS_CREADR) & its::OFFSET_MASK) as usize;
    if SENT.load(Ordering::Acquire) != sent {
        return None;
    }
    let done = its::done(sent, creadr);
    observe(done);
    Some(done)
}

/// Whether the ITS has stopped: no command has run or gone in for
/// STALL_SECONDS (kcore::its::stalled).
fn stalled() -> bool {
    its::stalled(
        timer::now(),
        LAST_ADVANCE.load(Ordering::Relaxed),
        LAST_SEND.load(Ordering::Relaxed),
        timer::frequency() * STALL_SECONDS,
    )
}

/// Whether a section's `commands` commands fit: the call that is about to
/// change something asks before it does (LIMIT_REACHED otherwise), and its
/// `enqueue` then finds the room, since a sender outside `OBJ` leaves
/// QUEUE_KEEP slots and only a section at a time is in `OBJ`. Under `Q_LOCK`
/// alone and against the last count seen of commands run, so no register is
/// read in the section; a stale count only takes room away.
pub fn room(commands: usize) -> bool {
    crate::obj::assert_held();
    let ticket = Q_LOCK.lock();
    let room = its::room(
        SENT.load(Ordering::Relaxed),
        DONE_CACHE.load(Ordering::Relaxed),
        commands,
        0,
    );
    Q_LOCK.unlock(ticket);
    room
}

/// Writes `commands` into the queue, counts them and returns the count;
/// `Q_LOCK` is held, and `keep` slots stay free after them (None when they
/// do not fit).
fn put(commands: &[Command], keep: usize) -> Option<Position> {
    assert!(commands.len() <= its::MAX_BATCH, "too many ITS commands");
    // SAFETY: `Q_LOCK` is held.
    let queue = unsafe { &mut *QUEUE.0.get() };
    let sent = SENT.load(Ordering::Relaxed);
    if !its::room(
        sent,
        DONE_CACHE.load(Ordering::Relaxed),
        commands.len(),
        keep,
    ) {
        return None;
    }
    for (n, command) in commands.iter().enumerate() {
        let at = queue.va + its::write_offset(sent + n as u64);
        for (i, word) in command.0.iter().enumerate() {
            // SAFETY: the slot is inside the queue page and the ITS does
            // not read it before CWRITER moves.
            unsafe { core::ptr::write_volatile((at + 8 * i) as *mut u64, *word) };
        }
        publish(at, its::COMMAND_BYTES);
    }
    let end = sent + commands.len() as u64;
    LAST_SEND.store(timer::now(), Ordering::Relaxed);
    SENT.store(end, Ordering::Release);
    #[cfg(feature = "its-slow")]
    SLOW_LEFT.store(SLOW_READS, Ordering::Relaxed);
    Some(Position(end))
}

/// Reads GITS_CREADR and notes the commands run, with `RING_LOCK` held:
/// what the room of the next section is counted against.
fn refresh() {
    let sent = SENT.load(Ordering::Acquire);
    let creadr = (read64(its::GITS_CREADR) & its::OFFSET_MASK) as usize;
    if SENT.load(Ordering::Acquire) == sent {
        observe(its::done(sent, creadr));
    }
}

/// Tells the ITS about the commands written so far: GITS_CWRITER, with
/// `RING_LOCK` held. A write that shows nothing new is not made.
fn doorbell() {
    let sent = SENT.load(Ordering::Acquire);
    if RUNG.load(Ordering::Relaxed) == sent {
        return;
    }
    // SAFETY: the stores to the queue reach memory before the register
    // write that tells the ITS.
    unsafe { core::arch::asm!("dsb sy", options(nostack, preserves_flags)) };
    write64(its::GITS_CWRITER, its::write_offset(sent) as u64);
    RUNG.store(sent, Ordering::Relaxed);
}

/// Puts `commands` (at most MAX_BATCH) into the queue in a section under
/// `OBJ`, after `room` said they fit: the order of the queue is then the
/// order of the sections, so a MAPTI never stands before the MAPD of its
/// device, and the teardown of an event never before its MAPTI. `Q_LOCK` is
/// a leaf under `OBJ`, held for the writes alone, with no register access
/// (spec 8.1). The ITS does not read them until `ring`, which the call makes
/// after its section.
#[must_use = "the call rings the ITS after its section and may wait for the count"]
#[inline(never)]
pub fn enqueue(commands: &[Command]) -> Position {
    crate::obj::assert_held();
    let ticket = Q_LOCK.lock();
    let pos = put(commands, 0);
    Q_LOCK.unlock(ticket);
    pos.expect("a section found the room it asked for")
}

/// Tells the ITS about the commands `enqueue` put in, outside `OBJ`, and
/// refreshes the count of commands run.
#[inline(never)]
pub fn ring() {
    crate::obj::assert_not_held();
    let ticket = RING_LOCK.lock();
    doorbell();
    refresh();
    RING_LOCK.unlock(ticket);
}

/// Puts `commands` into the queue and tells the ITS, outside `OBJ`: None
/// when fewer than QUEUE_KEEP slots would stay free, which the caller
/// meets by asking again later (a portion of cleanup queues its object
/// again, `step`).
#[must_use = "the commands run when the count is reached"]
#[inline(never)]
pub fn try_send(commands: &[Command]) -> Option<Position> {
    crate::obj::assert_not_held();
    let ticket = RING_LOCK.lock();
    refresh();
    let q = Q_LOCK.lock();
    let pos = put(commands, its::QUEUE_KEEP);
    Q_LOCK.unlock(q);
    if pos.is_some() {
        doorbell();
    }
    RING_LOCK.unlock(ticket);
    pos
}

/// `try_send` that waits for room: the boot's commands and the kernel
/// tests', which no portion of cleanup serves. A queue with no room while
/// the ITS has not moved for STALL_SECONDS is a stopped ITS.
#[must_use = "the commands run when `wait` has seen them done"]
pub fn send(commands: &[Command]) -> Position {
    loop {
        if let Some(pos) = try_send(commands) {
            return pos;
        }
        if stalled() {
            ::core::panic!("the ITS command queue stayed full");
        }
    }
}

/// True once the ITS has run the commands up to `pos`.
fn reached(pos: Position) -> bool {
    #[cfg(feature = "its-slow")]
    if SLOW_LEFT
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
        .is_ok()
    {
        return false;
    }
    look().is_some_and(|done| done >= pos.0)
}

/// Whether the commands up to the count `target` have run, for a binding
/// that kept the count of its mapping; outside `OBJ` or in a section, one
/// read of GITS_CREADR.
pub fn mapped(target: u64) -> bool {
    reached(Position(target))
}

/// Waits for the commands up to `pos` in segments of POLLS reads of
/// GITS_CREADR; the longest segment is counted (`longest`). The ITS that has
/// not moved for STALL_SECONDS is stopped: the kernel stops, naming the
/// command (`what`). For the boot and the kernel tests, which hold nothing;
/// a call of a program waits one segment (`wait_once`).
#[inline(never)]
pub fn wait(pos: Position, what: &str) {
    loop {
        if wait_once(pos) {
            return;
        }
        if stalled() {
            ::core::panic!("the ITS stopped at {what}");
        }
    }
}

/// One segment of a wait: POLLS reads of GITS_CREADR at most, outside
/// `OBJ` (spec 8.1), counted for the longest segment. True when the
/// commands up to `pos` ran. The call of a program that waited for its
/// event to be mapped says whether they did (irq_bind, x4): the mapping
/// takes effect when the ITS has run the commands, and a vector that
/// raises its event before is lost (spec 9).
#[inline(never)]
pub fn wait_once(pos: Position) -> bool {
    crate::obj::assert_not_held();
    #[cfg(feature = "ktest")]
    let segment = timer::now();
    let mut seen = false;
    for _ in 0..POLLS {
        if reached(pos) {
            seen = true;
            break;
        }
    }
    #[cfg(feature = "ktest")]
    {
        LONGEST.fetch_max(timer::now() - segment, Ordering::Relaxed);
        if !seen {
            LONG_WAITS.fetch_add(1, Ordering::Relaxed);
        }
    }
    seen
}

/// One step of the wait of a portion of cleanup for the commands of its
/// object's teardown (spec 7.7, 8.1): the commands go in at the first step
/// the queue has room for them, and each step looks once at the count. A
/// portion that is not `Done` queues its object again and returns, so no
/// portion waits for the ITS. The ITS that has not moved for STALL_SECONDS
/// with commands outstanding stops the kernel naming `what`; how long the
/// portion itself waited for its turn does not count.
#[inline(never)]
pub fn step(wait: &mut its::Wait, commands: &[Command], what: &str) -> its::Step {
    // The deliberate break: the portion waits for the ITS in a loop.
    #[cfg(feature = "break-its-loop")]
    loop {
        let step = step_once(wait, commands, what);
        if step != its::Step::Again {
            return step;
        }
    }
    #[cfg(not(feature = "break-its-loop"))]
    step_once(wait, commands, what)
}

fn step_once(wait: &mut its::Wait, commands: &[Command], what: &str) -> its::Step {
    let step = wait.step(
        || try_send(commands).map(|p| p.0),
        || {
            #[cfg(feature = "its-slow")]
            if SLOW_LEFT
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                .is_ok()
            {
                return Some(0);
            }
            look()
        },
        stalled,
    );
    if step == its::Step::Stalled {
        ::core::panic!("the ITS stopped at {what}");
    }
    step
}

/// Writes the property byte of LPI `intid`: `Some(priority)` enables it,
/// None disables it, and cleans the line when the GIC does not snoop. The
/// redistributors reread it at the next INV (`Command::inv`).
#[inline(never)]
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

/// Fills the queue with `n` SYNCs the ITS is not told about (`ring`
/// tells it): the room a call finds is what is left.
#[cfg(feature = "ktest")]
pub fn hold_back(mut n: usize) {
    while n > 0 {
        let batch = n.min(its::MAX_BATCH);
        let sync = [Command::sync(rdbase(0)); its::MAX_BATCH];
        let ticket = Q_LOCK.lock();
        let _ = put(&sync[..batch], 0).expect("room for the held-back commands");
        Q_LOCK.unlock(ticket);
        n -= batch;
    }
}

/// Whether the ITS has run every command sent.
#[cfg(feature = "ktest")]
pub fn drained() -> bool {
    look().is_some_and(|done| done == SENT.load(Ordering::Relaxed))
}

/// The reads the ITS still seems slow for (`its-slow`).
#[cfg(all(feature = "ktest", feature = "its-slow"))]
pub fn slow_left() -> u32 {
    SLOW_LEFT.load(Ordering::Relaxed)
}

/// The reads of a segment of a wait, for the tests.
#[cfg(feature = "ktest")]
pub const SEGMENT_READS: u32 = POLLS;

/// The longest segment of a wait, the waits that took more than one, and
/// the commands sent: the `its command ticks` line of the probe.
#[cfg(feature = "ktest")]
pub fn stats() -> (u64, u64, u64) {
    (
        LONGEST.load(Ordering::Relaxed),
        LONG_WAITS.load(Ordering::Relaxed),
        SENT.load(Ordering::Relaxed),
    )
}

/// Which LPI each CPU took last, and when, in counter ticks.
static SEEN: [AtomicU64; cpu::MAX_CPUS] = [const { AtomicU64::new(0) }; cpu::MAX_CPUS];
#[cfg(feature = "its-int")]
static SEEN_AT: [AtomicU64; cpu::MAX_CPUS] = [const { AtomicU64::new(0) }; cpu::MAX_CPUS];

/// Called by the interrupt handler of any CPU for each LPI.
pub fn seen(intid: u32) {
    let cpu = cpu::this().index();
    #[cfg(feature = "its-int")]
    SEEN_AT[cpu].store(timer::now(), Ordering::Relaxed);
    SEEN[cpu].store(u64::from(intid), Ordering::Release);
}

/// A command sent and waited for: an ITS that has not run it in
/// `STALL_SECONDS` is stopped, which stops the kernel naming the step, as it
/// does at the MAPC of each CPU (`wait`).
#[inline(never)]
fn run(commands: &[Command]) {
    let pos = send(commands);
    wait(pos, "the self-test");
}

/// Waits `limit` ticks at most for the LPI on `cpu`; CPU 0 serves its own
/// interrupts by polling, the others in their idle loops. The ticks from
/// `since`.
fn wait_for(cpu: usize, lpi: u32, since: u64, limit: u64) -> Option<u64> {
    loop {
        // CPU 0 takes whatever reaches it, which shows an LPI that went to
        // the wrong CPU.
        crate::interrupt::poll();
        if SEEN[cpu].load(Ordering::Acquire) == u64::from(lpi) {
            #[cfg(feature = "its-int")]
            return Some(SEEN_AT[cpu].load(Ordering::Relaxed).saturating_sub(since));
            #[cfg(not(feature = "its-int"))]
            return Some(0);
        }
        if timer::now() - since > limit {
            return None;
        }
    }
}

/// The commands of one step of the self-test, sent and waited for: what the
/// kernel's own device does at each of them (one place for the commands, so
/// that the test stays small).
#[derive(Clone, Copy, PartialEq)]
enum Step {
    Device(bool),
    Map,
    Raise,
}

#[inline(never)]
fn step_of(what: Step, device: u32, itt_pa: u64, cpus: usize, e: usize) {
    let ev = e as u32;
    let sync = Command::sync(rdbase(e));
    let collection = if cfg!(feature = "its-int-drop") {
        cpus as u16
    } else if cfg!(feature = "break-its-int-collection") {
        0
    } else {
        e as u16
    };
    let bits = its::event_bits(cpus as u64);
    match what {
        Step::Device(valid) => run(&[
            Command::mapd(device, itt_pa, bits, valid),
            Command::sync(rdbase(0)),
        ]),
        Step::Map => run(&[
            Command::mapti(device, ev, FIRST_LPI + ev, collection),
            Command::inv(device, ev),
            sync,
        ]),
        Step::Raise => run(&[Command::int(device, ev), sync]),
    }
}

/// The self-test of the delivery at every boot, on CPU 0 once every CPU is
/// up and before init starts: the lines about the redistributors, then one
/// LPI for each CPU through a device of the kernel's own (MAPD, MAPTI, INT),
/// waited for 10 ms of the counter. An LPI that does not arrive turns the
/// ITS off with the line `its off: LPI <n> did not reach CPU <c>`: MSI is
/// unavailable (`present` says no) and the drivers poll. The wait for the
/// commands is the second of a stopped ITS at most (`run`). With the feature
/// `its-int-drop` the events go to a collection no CPU has, so that the test
/// must fail; `break-its-selftest-ignore` leaves the ITS on after a failure.
#[inline(never)]
pub fn selftest() {
    #[cfg(feature = "its-int")]
    report_cpus();
    if !present() {
        return;
    }
    let cpus = crate::smp::cpus();
    let device = max_device_id();
    let (itt_va, itt_pa) = boot_block(0);
    publish(itt_va, its::ITT_MAX_BYTES);
    #[cfg(feature = "its-int")]
    {
        kprintln!("its-int: device {device:#x} ITT {itt_pa:#x}");
    }
    let go = |what, e| step_of(what, device, itt_pa, cpus, e);
    go(Step::Device(true), 0);
    for e in 0..cpus {
        set_property(FIRST_LPI + e as u32, Some(kcore::gic::DEFAULT_PRIORITY));
        go(Step::Map, e);
    }
    let limit = timer::frequency() / SELFTEST_HZ_DIV;
    let mut arrived = 0u64;
    for (e, seen) in SEEN.iter().enumerate().take(cpus) {
        let lpi = FIRST_LPI + e as u32;
        seen.store(0, Ordering::Release);
        // The 10 ms start when the INT command has run.
        go(Step::Raise, e);
        let got = wait_for(e, lpi, timer::now(), limit);
        arrived |= u64::from(got.is_some()) << e;
        #[cfg(feature = "its-int")]
        match got {
            Some(ticks) => {
                kprintln!("its self-test: LPI {lpi} reached CPU {e} after {ticks} ticks")
            }
            None => {
                kprintln!("its self-test: LPI {lpi} did not reach CPU {e} in {limit} ticks");
                int_probe::diagnose(e, lpi);
            }
        }
    }
    for e in 0..cpus {
        set_property(FIRST_LPI + e as u32, None);
    }
    // MAPD with Valid clear drops the device and the events it maps.
    go(Step::Device(false), 0);
    if let Err(lost) = its::verdict(arrived, cpus)
        && !cfg!(feature = "break-its-selftest-ignore")
    {
        write32(its::GITS_CTLR, 0);
        BASE.store(0, Ordering::Relaxed);
        kprintln!("its off: LPI {} did not reach CPU {}", lost.lpi, lost.cpu);
    }
}

/// What the self-test of the ITS prints more with the kernel feature
/// `its-int` (xtask its-int, `cargo xtask aws image --its-int`), which the
/// first runs of MSI on Graviton need: the device line and a diagnosis of an
/// LPI that did not arrive.
#[cfg(feature = "its-int")]
pub mod int_probe {
    use super::*;

    /// What tells a delivery that failed apart from another: the LPI CPU 0 took last, the target CPU's GICR_CTLR (bit 0 is
    /// EnableLPIs), the property byte (bit 0 enables) and the pending bit of
    /// the LPI, read after the cache dropped the line of the pending table.
    pub fn diagnose(cpu: usize, lpi: u32) {
        let rd = cpu::block(cpu).gic.load(Ordering::Relaxed);
        // SAFETY: GICR_CTLR is a register of the CPU's RD_base frame, which
        // the kernel tables map.
        let ctlr = unsafe { mmio::read32(rd + kcore::gic::GICR_CTLR) };
        let pend_pa = PEND_PA[cpu].load(Ordering::Relaxed);
        cache::clean_invalidate_frames(pend_pa, 1);
        let prop_at = PROP_VA.load(Ordering::Relaxed) + its::prop_index(lpi);
        let pend_at = LINEAR_BASE + pend_pa as usize + (lpi / 8) as usize;
        // SAFETY: the bytes are inside the property table and the pending
        // table of the CPU.
        let (prop, pend) = unsafe {
            (
                core::ptr::read_volatile(prop_at as *const u8),
                core::ptr::read_volatile(pend_at as *const u8),
            )
        };
        kprintln!(
            "its-int: CPU {cpu}: ctlr {ctlr:#x} prop {prop:#x} pend {} seen {}",
            (pend >> (lpi % 8)) & 1,
            SEEN[0].load(Ordering::Acquire)
        );
    }
}
