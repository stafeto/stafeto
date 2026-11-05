// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The second device in the hands of one program (spec 6, 3.9; the
//! protocol is `proto_net::fast`). CLAIM gives a process whose effective
//! user is the superuser, as the process service vouches for it, the whole
//! device when `/etc/netd.conf` says `handover 1`: copies of the window and
//! of the objects of the queues and of the buffers, without DUPLICATE, with
//! their physical addresses, the configuration space of the PCI function,
//! and the lease. The owner writes physical addresses into the descriptors
//! of a device without an IOMMU, so it is as trusted as the service: the
//! superuser and the line of the file are the boundary, and nothing of the
//! first device and nothing of another client goes to it.
//!
//! The line stays with the service (`second.rs`), and so does the DHCP
//! client of the second address, which talks through the owner's bypass
//! ring. When the owner's session goes (its process ended, or it closed
//! the session), the kernel took its mappings and handles, the objects
//! live on under the service's own handles, and the device comes back to
//! the service in steps (RETURN).

use crate::net::Client;
use crate::second::Mode;
use crate::{Driver, RETURN, dma};
use abi::{Access, Error, Rights};
use proto_net::fast::{self, Claimed, Object, RING_PAGES};
use proto_net::{Config, code};
use proto_wire::Status;
use rt::handle::{Channel, Handle, Memory, Outgoing};
use rt::service::{Answer, Request, Session};
use rt::sys;
use virtio_mmio::PAGE;

type Sess = Session<Client, 0>;

/// The rights the owner gets with each copy, and those its ring and its
/// channel must carry.
const GIVEN: Rights = Rights(Rights::MAP_READ.0 | Rights::MAP_WRITE.0 | Rights::TRANSFER.0);
const RING_NEEDS: Rights = Rights(Rights::MAP_READ.0 | Rights::MAP_WRITE.0);

/// The pages of the objects of the second device: `dma1`, then the four of
/// buffers (init's table).
const OBJECT_PAGES: [u32; fast::OBJECTS] = [8, 1024, 1024, 1024, 1024];

/// What the service knows of the device for a claim: whether the file
/// allows it, the transport, and the physical addresses of its objects.
pub struct Claimable {
    pub handover: bool,
    pub pci: bool,
    /// The second device's transport (QEMU) or function (VZ).
    pub at: u64,
    pub objects: [u64; fast::OBJECTS],
}

/// The owner of the second device.
pub struct Owner {
    /// The label of its session.
    pub label: u64,
    /// Its channel, labelled as it asked: the service notifies it.
    notify: Handle<Channel>,
    /// The ring object until CLAIM_MORE maps it.
    ring: Option<Handle<Memory>>,
    /// CLAIM_MORE gave the last two objects.
    more: bool,
}

fn refuse(c: u32) -> Answer {
    Answer::Status(code(c))
}

impl Driver<'_> {
    /// Tells the owner `bits` (`proto_net::fast`); nothing without one.
    pub(crate) fn tell_owner(&self, bits: u64) {
        if bits == 0 {
            return;
        }
        if let Some(owner) = &self.owner {
            let _ = sys::notify(&owner.notify, bits);
        }
    }

    /// Whether the session is the owner's.
    fn owns(&self, s: &Sess) -> bool {
        self.owner.as_ref().is_some_and(|o| o.label == s.label())
    }

    /// CLAIM (the table of `proto_net::fast`).
    pub(crate) fn claim(&mut self, s: &mut Sess, r: &mut Request<'_>) -> Answer {
        let (device, pages) = match fast::read_claim(r.body()) {
            Ok(body) => body,
            Err(status) => return Answer::Status(status),
        };
        if r.handles.len() != 3 {
            return Answer::Status(Status::BadSize);
        }
        if !self.claimable.handover {
            return refuse(proto_net::NOT_ALLOWED);
        }
        let Ok(identity) = r.handles.take::<Channel>(0) else {
            return refuse(proto_net::NOT_ALLOWED);
        };
        if self.net.vouch(identity) != Some(0) {
            return refuse(proto_net::NOT_ALLOWED);
        }
        if device != 1 || pages != RING_PAGES {
            return refuse(proto_net::INVALID);
        }
        let Some(second) = self.second.as_deref() else {
            return refuse(proto_net::INVALID);
        };
        if second.mode == Mode::Dead {
            return refuse(proto_net::INVALID);
        }
        if self.owner.is_some() || second.mode != Mode::Own {
            return refuse(proto_net::BUSY);
        }
        let Some(lease) = second.lease else {
            return refuse(proto_net::NET_DOWN);
        };
        let mac = second.device.mac;
        let rights = |i: usize| r.handles.info(i).map_or(Rights::NONE, |(_, rights)| rights);
        if rights(1).0 & Rights::NOTIFY.0 == 0 || rights(2).0 & RING_NEEDS.0 != RING_NEEDS.0 {
            return refuse(proto_net::INVALID);
        }
        let (Ok(notify), Ok(ring)) = (r.handles.take::<Channel>(1), r.handles.take::<Memory>(2))
        else {
            return refuse(proto_net::INVALID);
        };
        // An object of `mem_create` with every page its own.
        let size = RING_PAGES as u64 * PAGE as u64;
        match sys::memory_info(&ring) {
            Ok(info) if info.size >= size && info.pages * PAGE as u64 >= size => {}
            _ => return refuse(proto_net::INVALID),
        }
        let pci = self.claimable.pci;
        let window = if pci {
            self.maps.windows[1].as_ref()
        } else {
            self.maps.windows[2].as_ref()
        };
        let [dma1, net1a, net1b, ..] = &self.maps.second;
        let copies = [window, dma1.as_ref(), net1a.as_ref(), net1b.as_ref()];
        let mut handles = Outgoing::new();
        for h in copies {
            let Some(copy) = h.and_then(|h| sys::handle_duplicate(h, GIVEN).ok()) else {
                return Answer::Status(Status::Kernel(Error::BadState));
            };
            if handles.push(copy.erase()).is_err() {
                return Answer::Status(Status::Kernel(Error::BadState));
            }
        }
        let claimed = Claimed {
            kind: if pci { fast::PCI } else { fast::MMIO },
            transport: if pci {
                netd::pci::bar_offset(1)
            } else {
                self.claimable.at & (PAGE as u64 - 1)
            },
            config: Config {
                address: lease.address,
                prefix: u32::from(lease.prefix),
                gateway: lease.gateway,
                dns: lease.dns,
                mac,
            },
            objects: core::array::from_fn(|i| Object {
                pa: self.claimable.objects[i],
                pages: OBJECT_PAGES[i],
                uncached: i == 0,
            }),
            bar_sizes: if pci { netd::pci::BAR_SIZES } else { [0; 6] },
            snapshot: if pci {
                snapshot()
            } else {
                [0; fast::SNAPSHOT_WORDS]
            },
        };
        if claimed.write(r.reply()).is_err() {
            return Answer::Status(Status::BadSize);
        }
        // From here on the service touches neither the queues nor the
        // buffers of the device: the owner resets it and makes its own.
        if let Some(second) = self.second.as_deref_mut() {
            second.mode = Mode::Owned;
        }
        self.owner = Some(Owner {
            label: s.label(),
            notify,
            ring: Some(ring),
            more: false,
        });
        Answer::Reply(handles)
    }

    /// CLAIM_MORE: the last two objects, and the ring mapped; the DHCP client
    /// asks for its lease again through the ring.
    pub(crate) fn claim_more(&mut self, s: &mut Sess, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        if !self.owns(s) || self.owner.as_ref().is_some_and(|o| o.more) {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        let [_, _, _, net1c, net1d] = &self.maps.second;
        let mut handles = Outgoing::new();
        for h in [net1c.as_ref(), net1d.as_ref()] {
            let Some(copy) = h.and_then(|h| sys::handle_duplicate(h, GIVEN).ok()) else {
                return Answer::Status(Status::Kernel(Error::BadState));
            };
            let _ = handles.push(copy.erase());
        }
        let Some(process) = self.net.process.as_deref() else {
            return Answer::Status(Status::Kernel(Error::BadState));
        };
        let Some(ring) = self.owner.as_mut().and_then(|o| o.ring.take()) else {
            return Answer::Status(Status::Kernel(Error::BadState));
        };
        let size = RING_PAGES as u64 * PAGE as u64;
        if let Err(error) = sys::mem_map(process, &ring, 0, size, dma::RING_AT, Access::ReadWrite) {
            return Answer::Status(Status::Kernel(error));
        }
        // The mapping keeps the object.
        drop(ring);
        if let Some(owner) = self.owner.as_mut() {
            owner.more = true;
        }
        if let Some(second) = self.second.as_deref_mut() {
            // SAFETY: the ring object is mapped at RING_AT, read and write,
            // until the owner goes (`owner_gone` unmaps it after the ring
            // is dropped).
            unsafe { second.hand_over(dma::RING_AT) };
        }
        self.tell(crate::RX1);
        if r.reply().u32(Status::Ok.code()).is_err() {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply(handles)
    }

    /// KICK: the frames the owner put in the ring go into the stack, two in
    /// this step; the service's steps take the rest.
    pub(crate) fn kick(&mut self, s: &mut Sess, r: &mut Request<'_>) -> Answer {
        if let Err(status) = fast::read_kick(r.body()) {
            return Answer::Status(status);
        }
        if !self.owns(s) || self.second.as_deref().is_none_or(|s| s.fast.is_none()) {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        // A broken ring takes nothing any more: KICK is refused.
        if self.second.as_deref().is_some_and(|s| s.ring_broken()) {
            return refuse(proto_net::INVALID);
        }
        let taken = self.rx1_work(false);
        if self.second.as_deref().is_some_and(|s| s.ring_broken()) {
            return refuse(proto_net::INVALID);
        }
        rt::service::step_detail(u64::from(taken));
        if fast::write_kick_reply(taken, r.reply()).is_err() {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply(Outgoing::new())
    }

    /// The owner's session went: the ring is unmapped, its channel closes,
    /// and the device comes back in steps.
    pub(crate) fn owner_gone(&mut self, s: &Sess) {
        if !self.owns(s) {
            return;
        }
        let Some(owner) = self.owner.take() else {
            return;
        };
        if let Some(second) = self.second.as_deref_mut() {
            second.take_back();
        }
        if owner.more
            && let Some(process) = self.net.process.as_deref()
        {
            // SAFETY: the ring was the owner's memory; the service dropped
            // its view of it (`take_back`) and keeps nothing there.
            let _ =
                unsafe { sys::mem_unmap(process, dma::RING_AT, RING_PAGES as u64 * PAGE as u64) };
        }
        drop(owner);
        self.tell(RETURN);
    }
}

/// The 64 words of the configuration space of the second device's PCI
/// function, read through the window `ecam`, 32 bits at a time.
fn snapshot() -> [u32; fast::SNAPSHOT_WORDS] {
    let page = dma::ecam_at() + netd::pci::ecam_offset(1) as usize;
    core::array::from_fn(|i| {
        // SAFETY: the window maps the function's page as device memory, read
        // and write; a read of the configuration space changes nothing.
        unsafe { virtio_net::mmio::read32(page + 4 * i) }
    })
}
