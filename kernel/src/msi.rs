// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The MSI device (spec 4, 9): the kernel's object for one PCI function that
//! raises MSI-X vectors through the ITS. msi_create gives a process that
//! holds the system resource with DEVICE the device of the function with a
//! requester ID the device tree's `msi-map` names; the ITS maps its
//! DeviceID to an ITT, a table of its events that lives in the object, 1
//! KiB at most, which the creator's quota pays for with the object's place
//! in its pool (spec 7.5). The device is the right to bind its events
//! (irq_bind, `MANAGE`): the binding is an LPI (irq.rs). The ITS commands
//! that map and unmap the device run outside `OBJ` (its.rs, spec 8.1): the
//! call that makes the device sends them after its section, and the
//! portion that takes it apart sends them before its own. One device a
//! DeviceID: DEVICES names them, 64 at most.
//!
//! A device lives while references to it are left: its handles and the
//! binding of each of its events.

use crate::arch::its;
use crate::cleanup::{self, Item};
use crate::obj::Guarded;
use crate::object::{Live, Object, Refs};
use crate::process::{self, Process};
use abi::{Error, MsiInfo};
use core::ptr::NonNull;
use kcore::its::{Command, ITT_ALIGN, ITT_MAX_BYTES, MAX_MSI_EVENTS, event_bits, itt_bytes};
use kcore::layout::LINEAR_BASE;

/// The devices at most, one for each DeviceID (spec 7.8).
pub const MAX_DEVICES: usize = 64;

/// An MSI device: its ITT first, 256-byte aligned as MAPD needs it, then its
/// fields; the pool of the creator's process holds three to a page.
#[repr(C, align(256))]
pub struct Msi {
    itt: [u8; ITT_MAX_BYTES],
    /// Its handles and the bindings of its events: the references that
    /// keep it.
    refs: Refs,
    device_id: u32,
    events: u32,
    /// The events that have a binding, a bit each.
    bound: u64,
    /// The process whose pool holds it, and whose shell it holds.
    payer: NonNull<Process>,
    /// The level the cleanup that retired the device ran at.
    level: u8,
    /// Its place in the cleanup queue once nothing refers to it.
    cleanup: Item,
}

const _: () = ::core::assert!(core::mem::align_of::<Msi>() == ITT_ALIGN);
// The poison of a device that went (Live::gone) reaches its count.
const _: () = ::core::assert!(core::mem::offset_of!(Msi, refs) >= 8);

// SAFETY: devices are reached under the kernel's rules (spec 8.1).
unsafe impl Send for Msi {}

/// The device of each DeviceID that has one: (DeviceID, address of the
/// device), 0 for a free place. Under `OBJ`.
struct Devices([(u32, usize); MAX_DEVICES]);

static DEVICES: Guarded<Devices> = Guarded::new(Devices([(0, 0); MAX_DEVICES]));

/// Devices whose places have not gone back.
static LIVE: Live = Live::new();

/// The ITS work a call does after its section (spec 8.1), copied out of
/// the objects so that no object is read outside the section.
#[derive(Debug, Clone, Copy)]
pub enum Job {
    None,
    /// MAPD of a new device and the SYNC after it.
    MapDevice {
        device_id: u32,
        itt: u64,
        bits: u32,
    },
    /// The property byte, MAPTI, INV and SYNC of a new binding.
    MapEvent {
        device_id: u32,
        event: u32,
        lpi: u32,
        cpu: u32,
    },
}

impl Job {
    /// Does the work, outside `OBJ`: the commands go into the queue under
    /// ITS_LOCK and the wait for them follows without any lock.
    #[inline(never)]
    pub fn run(self) {
        let (commands, count, what) = match self {
            Job::None => return,
            Job::MapDevice {
                device_id,
                itt,
                bits,
            } => (
                [
                    Command::mapd(device_id, itt, bits, true),
                    Command::sync(its::rdbase(0)),
                    Command::sync(0),
                ],
                2,
                "MAPD",
            ),
            Job::MapEvent {
                device_id,
                event,
                lpi,
                cpu,
            } => {
                its::set_property(lpi, Some(kcore::gic::DEFAULT_PRIORITY));
                (
                    [
                        Command::mapti(device_id, event, lpi, cpu as u16),
                        Command::inv(device_id, event),
                        Command::sync(its::rdbase(cpu as usize)),
                    ],
                    3,
                    "MAPTI",
                )
            }
        };
        let pos = its::send(&commands[..count]);
        its::wait(pos, what);
    }
}

/// The checks of msi_create that read the tree and the ITS, in the order of
/// spec 11: INVALID_ARGS for events outside 1..=MAX_MSI_EVENTS, no ITS, a
/// requester ID the `msi-map` does not name, a DeviceID past the device
/// table, or an ITT that does not fit its 1 KiB. Returns the DeviceID.
pub fn check(rid: u64, events: u64) -> Result<u32, Error> {
    if !(1..=MAX_MSI_EVENTS).contains(&events) || rid >> 32 != 0 || !its::present() {
        return Err(Error::InvalidArgs);
    }
    let device_id = its::device_id(rid as u32).ok_or(Error::InvalidArgs)?;
    if device_id > its::max_device_id() || itt_bytes(events, its::itt_entry() as u64).is_none() {
        return Err(Error::InvalidArgs);
    }
    Ok(device_id)
}

/// A device for `device_id` with `events` events, as msi_create checked
/// them (spec 9), in the pool of `payer`, the process of the thread that
/// makes it, whose quota pays for a page when the pool grows (spec 7.8):
/// BAD_STATE when the DeviceID has a device, LIMIT_REACHED when DEVICES is
/// full, NO_MEMORY when the quota falls short; nothing changes then. The
/// device holds the payer's shell; the caller gets the first reference and
/// runs the returned job once its section ended.
pub fn create(
    payer: NonNull<Process>,
    device_id: u32,
    events: u32,
) -> Result<(NonNull<Msi>, Job), Error> {
    let mut devices = DEVICES.lock();
    if devices.0.iter().any(|&(id, at)| at != 0 && id == device_id) {
        return Err(Error::BadState);
    }
    let free = devices
        .0
        .iter()
        .position(|&(_, at)| at == 0)
        .ok_or(Error::LimitReached)?;
    let msi = Msi {
        itt: [0; ITT_MAX_BYTES],
        refs: Refs::one(),
        device_id,
        events,
        bound: 0,
        payer,
        level: 0,
        cleanup: Item::new(),
    };
    let m = process::paid_alloc(payer, msi)?;
    process::retain_shell(payer);
    LIVE.made();
    devices.0[free] = (device_id, m.as_ptr() as usize);
    // SAFETY: the device was just made, and nothing else refers to it.
    let itt = unsafe { (*m.as_ptr()).itt.as_ptr() } as usize;
    let job = Job::MapDevice {
        device_id,
        itt: (itt - LINEAR_BASE) as u64,
        bits: event_bits(u64::from(events)),
    };
    its::publish_itt(itt, ITT_MAX_BYTES);
    Ok((m, job))
}

/// The count of references to `m`, through the raw pointer.
///
/// # Safety
/// `m` is alive, and nothing else borrows the count.
#[must_use]
unsafe fn refs<'a>(m: NonNull<Msi>) -> &'a mut Refs {
    // SAFETY: the caller's promise; only the field is borrowed.
    unsafe { &mut (*m.as_ptr()).refs }
}

/// Adds a reference to `m`: a new handle, or the binding of an event.
pub fn retain(m: NonNull<Msi>) {
    // SAFETY: the caller holds a reference to the device; only the count is
    // touched.
    unsafe { refs(m) }.retain();
}

/// Drops a reference to `m`; the last one queues the device for cleanup at
/// `cause` (spec 7.7). O(1).
///
/// # Safety
/// The reference is the caller's, and the caller does not use it
/// afterwards.
pub unsafe fn release(m: NonNull<Msi>, cause: u8) {
    // SAFETY: the caller's reference keeps the device alive until here.
    unsafe {
        if refs(m).release() {
            let item = NonNull::new_unchecked(&raw mut (*m.as_ptr()).cleanup);
            cleanup::enqueue(item, Object::Msi(m), cause);
        }
    }
}

/// The DeviceID of `m`, which the caller holds.
pub fn device_id(m: NonNull<Msi>) -> u32 {
    // SAFETY: the caller holds a reference to the device; only the field
    // is read.
    unsafe { (*m.as_ptr()).device_id }
}

/// Marks `event` of `m` bound: INVALID_ARGS for an event past the device's,
/// BAD_STATE for one that has a binding (spec 9).
pub fn claim(m: NonNull<Msi>, event: u64) -> Result<u32, Error> {
    // SAFETY: the caller holds a reference to the device; only the fields
    // are touched, in a section.
    unsafe {
        let p = m.as_ptr();
        if event >= u64::from((*p).events) {
            return Err(Error::InvalidArgs);
        }
        if (*p).bound & 1 << event != 0 {
            return Err(Error::BadState);
        }
        Ok(event as u32)
    }
}

/// Takes `event` (a free event `claim` named) for a binding.
pub fn take(m: NonNull<Msi>, event: u32) {
    // SAFETY: as in `claim`.
    unsafe { (*m.as_ptr()).bound |= 1 << event };
}

/// Gives `event` back: its binding is gone and its mapping discarded.
pub fn give(m: NonNull<Msi>, event: u32) {
    // SAFETY: the binding held a reference to the device; only the field
    // is touched, in a section.
    unsafe { (*m.as_ptr()).bound &= !(1 << event) };
}

/// object_info MSI_DEVICE of `m`, which the caller holds (spec 11).
pub fn info(m: NonNull<Msi>) -> MsiInfo {
    // SAFETY: as for `device_id`.
    unsafe {
        MsiInfo {
            device_id: u64::from((*m.as_ptr()).device_id),
            events: u64::from((*m.as_ptr()).events),
            bound: u64::from((*m.as_ptr()).bound.count_ones()),
        }
    }
}

/// The ITS side of the portion of a device nothing refers to
/// (cleanup::portion), outside `OBJ`: MAPD with V = 0 and the SYNC, which
/// the portion waits for before it frees the ITT (spec 7.7, 8.1).
///
/// # Safety
/// Nothing refers to the device, and it is in no queue.
#[inline(never)]
pub unsafe fn unmap(m: NonNull<Msi>) {
    // SAFETY: the caller's promise; only the fields are read.
    let (device_id, itt) =
        unsafe { ((*m.as_ptr()).device_id, (*m.as_ptr()).itt.as_ptr() as usize) };
    let pos = its::send(&[
        Command::mapd(device_id, (itt - LINEAR_BASE) as u64, 1, false),
        Command::sync(its::rdbase(0)),
    ]);
    its::wait(pos, "MAPD");
}

/// The portion of a device nothing refers to, after `unmap`, in a section:
/// DEVICES lets go of it, its place goes back to the payer's pool, and the
/// reference to the payer's shell goes last.
///
/// # Safety
/// Nothing refers to the device, it is in no queue, and `unmap` ran.
#[inline(never)]
pub unsafe fn clean(m: NonNull<Msi>, level: u8) {
    let mut devices = DEVICES.lock();
    let at = m.as_ptr() as usize;
    for entry in devices.0.iter_mut().filter(|e| e.1 == at) {
        *entry = (0, 0);
    }
    drop(devices);
    // SAFETY: the caller's promise; the payer's pool is there, since the
    // device holds its shell, whose reference goes last.
    unsafe {
        let payer = (*m.as_ptr()).payer;
        (*m.as_ptr()).level = level;
        process::paid_free(payer, m);
        LIVE.gone(m);
        process::release_shell(payer, level);
    }
}

#[cfg(feature = "ktest")]
pub use test_access::{bound_events, in_use};

/// What the kernel tests read here (crate::ktest).
#[cfg(feature = "ktest")]
mod test_access {
    use super::*;

    /// Devices whose places have not gone back.
    pub fn in_use() -> usize {
        LIVE.count()
    }

    /// The bitmap of bound events of `m`, which the test holds.
    pub fn bound_events(m: NonNull<Msi>) -> u64 {
        // SAFETY: the test holds a reference; only the field is read.
        unsafe { (*m.as_ptr()).bound }
    }
}
