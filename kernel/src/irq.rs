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

use crate::arch::gic;
use crate::channel::{self, Channel, Owner, Source};
use crate::cleanup::{self, Item};
use crate::object::{Live, Object, Refs};
use crate::process::{self, Process};
use abi::{Error, IrqInfo};
use core::ptr::NonNull;
use kcore::gic::{FIRST_SPI, FIRST_SPURIOUS};
use kcore::sync::Lock;

/// The bits of an interrupt (spec 6.5): bit 0 at each delivery.
const IRQ_BITS: u64 = 1;

/// The shared lines a binding may take: INTID 32-1019.
const LINE_COUNT: usize = (FIRST_SPURIOUS - FIRST_SPI) as usize;

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
    /// Its line, an INTID of 32-1019.
    line: u32,
    /// The line is edge-triggered; otherwise level-triggered.
    edge: bool,
    /// An interrupt masked the line, and no irq_ack opened it since.
    masked: bool,
    /// The process whose pool of bindings holds it, and whose shell it
    /// holds.
    payer: NonNull<Process>,
    /// Its place in the cleanup queue once nothing refers to it.
    cleanup: Item,
}

// SAFETY: bindings are reached under the kernel's rules (spec 8.1): one
// CPU, interrupts masked inside the kernel.
unsafe impl Send for Irq {}

/// The binding of each shared line, the first for INTID 32: 988 entries
/// of 8 bytes, outside every quota, like the table of thread numbers (spec
/// 7.8). An entry names a binding from `bind` until its last handle.
struct Lines([Option<NonNull<Irq>>; LINE_COUNT]);

// SAFETY: as for Irq.
unsafe impl Send for Lines {}

static LINES: Lock<Lines> = Lock::new(Lines([None; LINE_COUNT]));

/// Bindings whose places have not gone back.
static LIVE: Live = Live::new();

/// The entry of `line`, a shared line.
fn entry(line: u32) -> usize {
    (line - FIRST_SPI) as usize
}

/// Whether `line`, a shared line irq_bind checked, has a binding (spec 9):
/// irq_bind of it fails with BAD_STATE.
pub fn is_bound(line: u32) -> bool {
    LINES.lock().0[entry(line)].is_some()
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
) -> Result<NonNull<Irq>, Error> {
    channel::reserve_source(c)?;
    let irq = Irq {
        source: Source::new(c),
        refs: Refs::one(),
        handles: 1,
        line,
        edge,
        masked: false,
        payer,
        cleanup: Item::new(),
    };
    let b = process::paid_alloc(payer, irq).inspect_err(|_| channel::remove_source(c))?;
    // SAFETY: the binding was just made, and nothing else refers to it.
    unsafe { (*b.as_ptr()).source.attach(Owner::Irq(b), priority, label) };
    process::retain_shell(payer);
    LIVE.made();
    LINES.lock().0[entry(line)] = Some(b);
    gic::set_trigger(line, edge);
    gic::unmask(line);
    Ok(b)
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
            gic::mask((*p).line);
            LINES.lock().0[entry((*p).line)] = None;
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
    let (line, masked, edge) =
        unsafe { ((*b.as_ptr()).line, (*b.as_ptr()).masked, (*b.as_ptr()).edge) };
    IrqInfo {
        line: line.into(),
        masked,
        edge,
    }
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
    let Some(b) = LINES.lock().0[entry(line)] else {
        return false;
    };
    let p = b.as_ptr();
    // SAFETY: LINES names a binding only while handles to it are left,
    // each with its reference, and none goes during the post: the binding
    // and its attached source live until it returns.
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
        let payer = (*b.as_ptr()).payer;
        (*b.as_ptr()).source.detach(level);
        process::paid_free(payer, b);
        LIVE.gone(b);
        process::release_shell(payer, level);
    }
}

// The poison of a binding that went (Live::gone) reaches its count.
const _: () = assert!(core::mem::offset_of!(Irq, refs) >= 8);

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
        LINES.lock().0[entry(line)]
    }

    /// The process that pays for `b`, which the test holds.
    pub fn payer(b: NonNull<Irq>) -> NonNull<Process> {
        // SAFETY: the test holds a reference to the binding; only the field
        // is read.
        unsafe { (*b.as_ptr()).payer }
    }
}
