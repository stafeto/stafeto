// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Interrupt bindings (spec 4, 6.5, 9): irq_bind ties a shared line of the
//! GIC to a channel, one binding a line. A binding is a source of
//! notifications of the channel (channel::Source): it holds the channel
//! with a counted reference and one of its slots, and its own slot of the
//! priority irq_bind gave, with the label of the channel handle it was
//! made through. It lies in the pool of bindings of the process that made
//! it, which pays for it by the page (spec 7.8), and holds that process's
//! shell until its place goes back. The table LINES names the binding of
//! each line, so that the interrupt finds it in O(1). Each interrupt of a
//! bound line masks the line at the distributor and posts bit 0 into the
//! binding's slot at the slot's priority (`deliver`); the line stays
//! masked until irq_ack, and a closed channel keeps it masked for good. The
//! line is edge- or level-triggered as irq_bind said, written to
//! GICD_ICFGR while the line is masked. A binding lives while references
//! to it are left: its handles, the one `bind` hands out, and its slot's
//! while the slot stands in the channel's queue. Its handles, with the
//! reference `bind` hands out, are counted apart: the last of them masks
//! the line and frees it in the table at once, in O(1), even while the
//! slot stays queued, so that a new irq_bind of the line succeeds from then
//! on. The last reference queues the binding (spec 7.7), whose portion
//! gives the channel's slot and reference back and lets the payer's shell
//! go.

use crate::arch::{gic, its};
use crate::channel::{self, Channel, Owner, Source};
use crate::cleanup::{self, Item};
use crate::msi::{self, Job, Msi};
use crate::obj::Guarded;
use crate::object::{Live, Object, Refs};
use crate::process::{self, Process};
use crate::qsbr::{self, Deferred};
use abi::{Error, IrqInfo};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, Ordering};
use kcore::gic::{FIRST_LPI, FIRST_SPI, FIRST_SPURIOUS};
use kcore::its::{Command, LpiMap, MAX_LPIS};

/// The bits of an interrupt (spec 6.5): bit 0 at each delivery.
const IRQ_BITS: u64 = 1;

/// The shared lines a binding may take: INTID 32-1019.
const LINE_COUNT: usize = (FIRST_SPURIOUS - FIRST_SPI) as usize;

/// The event of an MSI device a binding stands for.
#[derive(Clone, Copy)]
struct Event {
    device: NonNull<Msi>,
    id: u32,
}

pub struct Irq {
    /// Its source of notifications: the slot of its interrupts, the label
    /// of the channel handle it was made through (spec 5.3) and the
    /// channel.
    source: Source,
    /// Its handles, the reference `bind` hands out, and its slot's while
    /// the slot is queued: the references that keep it.
    refs: Refs,
    /// Its handles and the reference `bind` hands out: the references
    /// that keep its line.
    handles: u32,
    /// Its line, an INTID of 32-1019; for an event of an MSI device its LPI
    /// (`event`), an INTID of 8192 and up.
    line: u32,
    /// The CPU its interrupts go to.
    cpu: u32,
    /// The event this binding is, with the device it belongs to, which it
    /// holds with a counted reference; None for a binding of a line.
    event: Option<Event>,
    /// The line is edge-triggered; otherwise level-triggered.
    edge: bool,
    /// An interrupt masked the line, and no irq_ack opened it since.
    masked: bool,
    /// The process whose pool of bindings holds it, and whose shell it
    /// holds.
    payer: NonNull<Process>,
    /// The level the cleanup that retired the binding ran at, for the
    /// release of its payer's shell once the memory goes (`reclaim`).
    level: u8,
    /// Its place in the cleanup queue once nothing refers to it.
    cleanup: Item,
    /// The binding waits in the list of retired objects for the end of a
    /// quiescent period (qsbr), since another CPU may read `LINES` and hold
    /// the binding without a lock.
    deferred: Deferred,
}

impl Irq {
    /// A binding of `line` (an LPI for an `event`) with one reference and
    /// one handle, not yet attached to its channel.
    fn new(
        c: NonNull<Channel>,
        payer: NonNull<Process>,
        line: u32,
        cpu: u32,
        event: Option<Event>,
        edge: bool,
    ) -> Irq {
        Irq {
            source: Source::new(c),
            refs: Refs::one(),
            handles: 1,
            line,
            cpu,
            event,
            edge,
            masked: false,
            payer,
            level: 0,
            cleanup: Item::new(),
            deferred: Deferred::new(),
        }
    }
}

// SAFETY: bindings are reached under the kernel's rules (spec 8.1): one
// CPU, interrupts masked inside the kernel.
unsafe impl Send for Irq {}

/// The binding of each shared line, the first for INTID 32: 988 entries
/// of 8 bytes, outside every quota, like the table of thread numbers (spec
/// 7.8). An entry names a binding from `bind` until its last handle, or is
/// null. Written under `OBJ` with release, read without a lock with acquire
/// (`line_binding`): the binding a reader loaded stays in place until every
/// CPU passed a quiescent point after it left the table (qsbr).
static LINES: [AtomicPtr<Irq>; LINE_COUNT] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; LINE_COUNT];

/// The binding of each LPI the kernel hands out, the first for INTID
/// 8192: 1 024 entries of 8 bytes, outside every quota (spec 7.8), `.bss`.
/// Written under `OBJ` with release, read without a lock with acquire
/// (`lpi_binding`), as LINES is.
static LPIS: [AtomicPtr<Irq>; MAX_LPIS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_LPIS];

/// The LPIs taken (spec 7.8): a number goes back when the period after its
/// binding left LPIS has passed (`reclaim`). Under `OBJ`.
static LPI_MAP: Guarded<LpiMap> = Guarded::new(LpiMap::new());

/// Bindings whose places have not gone back.
static LIVE: Live = Live::new();

/// The entry of `line`, a shared line.
fn entry(line: u32) -> usize {
    (line - FIRST_SPI) as usize
}

/// Whether `line`, a shared line irq_bind checked, has a binding (spec 9):
/// irq_bind of it fails with BAD_STATE.
pub fn is_bound(line: u32) -> bool {
    line_binding(line).is_some()
}

/// The binding of `line`, read without a lock (see LINES).
fn line_binding(line: u32) -> Option<NonNull<Irq>> {
    NonNull::new(LINES[entry(line)].load(Ordering::Acquire))
}

/// A binding of `line`, a shared line with no binding, to `c`, an open
/// channel, as irq_bind checked them (spec 9): its slot has `priority` and
/// `label`, and the line is edge-triggered when `edge`. It takes one of the
/// channel's slots, LIMIT_REACHED past abi::MAX_SLOTS, then a place in the
/// pool of bindings of `payer`, the process of the thread that makes it,
/// whose quota pays for a page when the pool grows (spec 7.8), NO_MEMORY
/// when it falls short; nothing changes on either. Then the binding goes
/// into LINES, the kind of trigger into GICD_ICFGR while the line is still
/// masked, and the line opens: the binding waits for its first interrupt.
/// It holds the channel and the payer's shell; the caller gets the first
/// reference, which counts as a handle (`release_handle`).
pub fn bind(
    payer: NonNull<Process>,
    c: NonNull<Channel>,
    label: u64,
    line: u32,
    priority: u8,
    edge: bool,
    cpu: u32,
) -> Result<NonNull<Irq>, Error> {
    channel::reserve_source(c)?;
    let irq = Irq::new(c, payer, line, cpu, None, edge);
    let b = process::paid_alloc(payer, irq).inspect_err(|_| channel::remove_source(c))?;
    // SAFETY: the binding was just made, and nothing else refers to it.
    unsafe { (*b.as_ptr()).source.attach(Owner::Irq(b), priority, label) };
    process::retain_shell(payer);
    LIVE.made();
    LINES[entry(line)].store(b.as_ptr(), Ordering::Release);
    gic::set_trigger(line, edge);
    gic::set_route(line, cpu as usize);
    gic::unmask(line);
    Ok(b)
}

/// A binding of `event` of `device`, an MSI device with MANAGE, to `c`, an
/// open channel, as irq_bind checked them (spec 9): its slot has
/// `priority` and `label`, and its interrupts go to CPU `cpu`. It takes one
/// of the channel's slots, then a free LPI (LIMIT_REACHED when all
/// MAX_LPIS are taken), then a place in the pool of bindings of `payer`
/// (NO_MEMORY when the quota falls short); nothing changes on either. The
/// binding goes into LPIS and holds the device and the payer's shell. The
/// LPI is edge-triggered and the kernel masks nothing (spec 9): the
/// caller runs the returned job, the property byte and the ITS commands,
/// once its section ended. The caller gets the first reference, which
/// counts as a handle.
pub fn bind_event(
    payer: NonNull<Process>,
    c: NonNull<Channel>,
    label: u64,
    device: NonNull<Msi>,
    event: u32,
    priority: u8,
    cpu: u32,
) -> Result<(NonNull<Irq>, Job), Error> {
    channel::reserve_source(c)?;
    let Some(lpi) = LPI_MAP.lock().take() else {
        channel::remove_source(c);
        return Err(Error::LimitReached);
    };
    let irq = Irq::new(c, payer, lpi, cpu, Some(Event { device, id: event }), true);
    let b = match process::paid_alloc(payer, irq) {
        Ok(b) => b,
        Err(e) => {
            LPI_MAP.lock().give(lpi);
            channel::remove_source(c);
            return Err(e);
        }
    };
    // SAFETY: the binding was just made, and nothing else refers to it.
    unsafe { (*b.as_ptr()).source.attach(Owner::Irq(b), priority, label) };
    process::retain_shell(payer);
    msi::retain(device);
    msi::take(device, event);
    LIVE.made();
    LPIS[(lpi - FIRST_LPI) as usize].store(b.as_ptr(), Ordering::Release);
    let job = Job::MapEvent {
        device_id: msi::device_id(device),
        event,
        lpi,
        cpu,
    };
    Ok((b, job))
}

/// The count of references to `b`, through the raw pointer.
///
/// # Safety
/// `b` is alive, and nothing else borrows the count.
#[must_use]
unsafe fn refs<'a>(b: NonNull<Irq>) -> &'a mut Refs {
    // SAFETY: the caller's promise; only the field is borrowed.
    unsafe { &mut (*b.as_ptr()).refs }
}

/// The source of `b`, which lives as long as the binding.
fn source(b: NonNull<Irq>) -> NonNull<Source> {
    // SAFETY: the caller holds a reference to the binding, or LINES names
    // it; only the field's address is taken.
    unsafe { NonNull::new_unchecked(&raw mut (*b.as_ptr()).source) }
}

/// The label of `b`, which receive reports with its slot.
pub fn label(b: NonNull<Irq>) -> u64 {
    // SAFETY: the slot of the binding is being taken, and it holds the
    // binding; only the field is read.
    unsafe { (*b.as_ptr()).source.label() }
}

/// Adds the reference of `b`'s slot when the slot just went into the
/// channel's queue (channel::post), which holds the binding until receive
/// or the stage Close takes the slot (spec 6.5), or of a new handle
/// (`retain_handle`).
pub fn retain(b: NonNull<Irq>) {
    // SAFETY: the caller holds a reference to the binding; only the count
    // is touched.
    unsafe { refs(b) }.retain();
}

/// Drops a reference to `b`. The last one queues the binding for cleanup
/// at `cause` (spec 7.7); its line went with its last handle. O(1).
///
/// # Safety
/// The reference is the caller's, and the caller does not use it
/// afterwards.
pub unsafe fn release(b: NonNull<Irq>, cause: u8) {
    // SAFETY: the caller's reference keeps the binding alive until here;
    // the pool keeps it in place until its portion.
    unsafe {
        if refs(b).release() {
            let item = NonNull::new_unchecked(&raw mut (*b.as_ptr()).cleanup);
            cleanup::enqueue(item, Object::Irq(b), cause);
        }
    }
}

/// Adds the reference of a new handle to `b`.
pub fn retain_handle(b: NonNull<Irq>) {
    // SAFETY: the caller holds a handle to the binding; only the count is
    // touched.
    unsafe { (*b.as_ptr()).handles += 1 };
    retain(b);
}

/// Drops the reference of a handle to `b`, or the one `bind` handed out.
/// The last of them masks the line and frees it in LINES, so that no
/// interrupt finds the binding and irq_bind of the line succeeds from now
/// on, though its slot may still stand in the channel's queue; then the
/// reference goes as `release` lets it. O(1).
///
/// # Safety
/// As for `release`.
pub unsafe fn release_handle(b: NonNull<Irq>, cause: u8) {
    // SAFETY: the caller's reference keeps the binding alive until here;
    // only the fields are touched.
    unsafe {
        let p = b.as_ptr();
        (*p).handles -= 1;
        if (*p).handles == 0 {
            if (*p).event.is_some() {
                // An LPI has no mask in the GIC: no interrupt finds the
                // binding, and its enable byte goes; DISCARD follows in the
                // portion that takes the binding apart.
                LPIS[((*p).line - FIRST_LPI) as usize]
                    .store(core::ptr::null_mut(), Ordering::Release);
                its::set_property((*p).line, None);
            } else {
                gic::mask((*p).line);
                LINES[entry((*p).line)].store(core::ptr::null_mut(), Ordering::Release);
            }
        }
        release(b, cause);
    }
}

/// irq_ack (spec 9) of `b`, which the caller's handle holds: PEER_CLOSED
/// once the channel closed, and the line stays masked for good; otherwise
/// a line an interrupt masked opens again, and a line that is open stays
/// so. O(1).
pub fn ack(b: NonNull<Irq>) -> Result<(), Error> {
    let p = b.as_ptr();
    // SAFETY: the caller's handle holds the binding, which holds its
    // channel; only the fields are touched.
    unsafe {
        if channel::is_closed((*p).source.channel()) {
            return Err(Error::PeerClosed);
        }
        if (*p).masked {
            (*p).masked = false;
            gic::unmask((*p).line);
        }
    }
    Ok(())
}

/// object_info IRQ of `b`, which the caller holds (spec 11): its line,
/// whether it is masked until irq_ack, and whether it is edge-triggered.
pub fn info(b: NonNull<Irq>) -> IrqInfo {
    // SAFETY: the caller holds a reference to the binding; only the fields
    // are read.
    let (line, masked, edge, cpu, event) = unsafe {
        let p = b.as_ptr();
        ((*p).line, (*p).masked, (*p).edge, (*p).cpu, (*p).event)
    };
    let mut info = IrqInfo::line(line.into(), masked, edge, cpu.into());
    if let Some(event) = event {
        info.lpi = true;
        info.lpi_number = line.into();
        info.msi_address = its::translater();
        info.msi_data = event.id.into();
    }
    info
}

/// An interrupt of `line`, acknowledged at the GIC, before its EOI
/// (interrupt::handle, spec 9): false when no binding holds the line. A
/// bound line that is masked already, an interrupt that reached the CPU
/// before the mask did, gets nothing more. Otherwise the line is masked at
/// the distributor, and bit 0 goes into the binding's slot at the slot's
/// priority, the level of whatever the post lets go (spec 7.7); a closed
/// channel takes nothing, and the line stays masked. O(1).
pub fn deliver(line: u32) -> bool {
    if !(FIRST_SPI..FIRST_SPURIOUS).contains(&line) {
        return false;
    }
    // The lookup takes no lock: the binding stays in place until this CPU
    // passes a quiescent point, which it does not before this returns.
    let Some(b) = line_binding(line) else {
        return false;
    };
    crate::testpoint::line_read(line);
    let _section = crate::obj::lock();
    // The line may have been unbound meanwhile, by a CPU that held `OBJ`.
    if line_binding(line) != Some(b) {
        return false;
    }
    let p = b.as_ptr();
    // SAFETY: LINES names the binding still, under OBJ, so handles to it are
    // left, each with its reference, and none goes during the post: the
    // binding and its attached source live until it returns.
    unsafe {
        if (*p).masked {
            return true;
        }
        gic::mask(line);
        (*p).masked = true;
        let priority = (*p).source.priority();
        let _ = Source::post(source(b), IRQ_BITS, priority);
    }
    true
}

/// An interrupt of the LPI `lpi`, acknowledged at the GIC, before its EOI
/// (interrupt::handle, spec 9): false when no binding holds the LPI, which
/// the EOI then ends all the same. An LPI has no active state and no mask in
/// the GIC: notifications that come before the driver serves the device
/// merge in its slot, and bit 0 goes into the slot at the slot's priority,
/// the level of whatever the post lets go (spec 7.7); a closed channel takes
/// nothing. O(1).
pub fn deliver_lpi(lpi: u32) -> bool {
    let Some(index) = lpi
        .checked_sub(FIRST_LPI)
        .filter(|&i| (i as usize) < MAX_LPIS)
    else {
        return false;
    };
    // The lookup takes no lock: the binding stays in place until this CPU
    // passes a quiescent point, which it does not before this returns.
    let Some(b) = NonNull::new(LPIS[index as usize].load(Ordering::Acquire)) else {
        return false;
    };
    crate::testpoint::line_read(lpi);
    let _section = crate::obj::lock();
    // The binding may have been unbound meanwhile, by a CPU that held `OBJ`.
    if NonNull::new(LPIS[index as usize].load(Ordering::Acquire)) != Some(b) {
        return false;
    }
    // SAFETY: LPIS names the binding still, under OBJ, so handles to it are
    // left, each with its reference, and none goes during the post: the
    // binding and its attached source live until it returns.
    unsafe {
        let priority = (*b.as_ptr()).source.priority();
        let _ = Source::post(source(b), IRQ_BITS, priority);
    }
    true
}

/// The ITS side of the portion of a binding nothing refers to
/// (cleanup::portion), outside `OBJ` (spec 8.1): for an event of an MSI
/// device, INV of its disabled property byte, DISCARD of its mapping and
/// SYNC, which the portion waits for before its own section. Nothing for a
/// binding of a line.
///
/// # Safety
/// Nothing refers to the binding, and it is in no queue.
#[inline(never)]
pub unsafe fn unmap(b: NonNull<Irq>) {
    // SAFETY: the caller's promise; only the fields are read, and the device
    // lives while the binding holds its reference.
    let Some(event) = (unsafe { (*b.as_ptr()).event }) else {
        return;
    };
    let device_id = msi::device_id(event.device);
    // SAFETY: as above.
    let cpu = unsafe { (*b.as_ptr()).cpu };
    let pos = its::send(&[
        Command::inv(device_id, event.id),
        Command::discard(device_id, event.id),
        Command::sync(its::rdbase(cpu as usize)),
    ]);
    its::wait(pos, "DISCARD");
}

/// The portion of a binding nothing refers to (cleanup::portion), at
/// `level`: its source goes, which gives its slot in the channel back and
/// lets the channel go (Source::detach), its place goes back to the
/// payer's pool, and then the reference to the payer's shell goes; each may
/// queue what it held at `level`. Its line was freed with its last
/// handle, and its slot is in no queue: a queued slot holds the
/// binding. O(1).
///
/// # Safety
/// Nothing refers to the binding, and it is in no queue.
pub unsafe fn clean(b: NonNull<Irq>, level: u8) {
    // SAFETY: the caller's promise; nothing uses the binding afterwards;
    // the payer's pool is there, since the binding holds the payer's shell,
    // whose reference goes last.
    unsafe {
        (*b.as_ptr()).source.detach(level);
        (*b.as_ptr()).level = level;
        // DISCARD ran (`unmap`): the event is free for a new binding, and
        // the device may go once nothing else holds it.
        if let Some(event) = (*b.as_ptr()).event {
            msi::give(event.device, event.id);
            msi::release(event.device, level);
        }
        // Another CPU may read the binding from LINES as long as no period
        // passed since the line let go of it.
        qsbr::retire(NonNull::from(&mut (*b.as_ptr()).deferred), reclaim);
    }
}

/// Gives the memory of a binding back once the period passed: its place in
/// the payer's pool, and the reference to the payer's shell, which goes
/// last.
///
/// # Safety
/// `d` is the `deferred` of a retired binding, in a section under `OBJ`.
unsafe fn reclaim(d: NonNull<Deferred>) {
    let offset = core::mem::offset_of!(Irq, deferred);
    // SAFETY: the node is the field of a binding, which stays alive until
    // here; the payer's pool is there, since the binding holds its shell.
    unsafe {
        let b = NonNull::new_unchecked(d.as_ptr().byte_sub(offset).cast::<Irq>());
        let (payer, level) = ((*b.as_ptr()).payer, (*b.as_ptr()).level);
        let event = (*b.as_ptr()).event;
        let lpi = (*b.as_ptr()).line;
        process::paid_free(payer, b);
        LIVE.gone(b);
        if event.is_some() {
            // No CPU reads the binding from LPIS any more: its number may
            // be taken again.
            LPI_MAP.lock().give(lpi);
        }
        process::release_shell(payer, level);
    }
}

// The poison of a binding that went (Live::gone) reaches its count.
const _: () = ::core::assert!(core::mem::offset_of!(Irq, refs) >= 8);

#[cfg(feature = "ktest")]
pub use test_access::{bound, in_use, payer};

/// What the kernel tests read here (crate::ktest).
#[cfg(feature = "ktest")]
mod test_access {
    use super::*;

    /// Bindings whose places have not gone back.
    pub fn in_use() -> usize {
        LIVE.count()
    }

    /// The binding LINES names for `line`, a shared line.
    pub fn bound(line: u32) -> Option<NonNull<Irq>> {
        line_binding(line)
    }

    /// The process that pays for `b`, which the test holds.
    pub fn payer(b: NonNull<Irq>) -> NonNull<Process> {
        // SAFETY: the test holds a reference to the binding; only the field
        // is read.
        unsafe { (*b.as_ptr()).payer }
    }
}
