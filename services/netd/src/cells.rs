// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The shared buffers of the sessions (BUFFER of proto_net): the client's
//! memory object mapped into the service for the session's life, and the
//! copies between a cell of it and a stream's queues.
//!
//! The client may write into its buffer while the service copies, so the
//! service never makes a Rust reference to that memory: the bytes go through
//! raw pointers (`core::ptr::copy_nonoverlapping`) inside the closures that
//! smoltcp gives its queues to. The offset and the length of a cell come in
//! the request and nothing else is read from the buffer. A client that writes
//! into the cell while the service copies spoils only its own bytes.

use crate::dma;
use crate::net::{Client, Net};
use abi::{Access, Error, Rights};
use netd::buffers::{Part, Refusal, copy_portion};
use netd::ring::BUFFER_PORTION;
use proto_net::{BUFFER_SIZE, code};
use proto_wire::Status;
use rt::handle::{Memory, Outgoing};
use rt::service::{Answer, Pending, Request, Session};
use rt::sys;
use smoltcp::socket::tcp;

type Sess = Session<Client, 0>;

/// A BUFFER that waits for its map: the client's object and the reply it is owed.
pub struct Waiting {
    object: rt::handle::Handle<Memory>,
    pending: Pending,
    /// The status of the map once it was made: the answer waits for a step of its own.
    status: Option<Status>,
}

/// The rights the object of BUFFER must carry.
const NEEDED: Rights = Rights(Rights::MAP_READ.0 | Rights::MAP_WRITE.0);

impl Net {
    /// BUFFER: the object the request carries becomes the session's shared
    /// buffer, mapped for the session's life. The request checks the object and takes an
    /// entry; the map of its 64 pages (the longest call of the service, about 11 000 ticks
    /// under -icount) and the reply are a step of their own (`map_waiting`), so that neither
    /// step comes near the bound.
    pub fn buffer(&mut self, s: &mut Sess, r: &mut Request<'_>) -> Answer {
        let size = match proto_net::read_buffer(r.body()) {
            Ok(size) => size,
            Err(status) => return Answer::Status(status),
        };
        if r.handles.len() != 1 {
            return Answer::Status(Status::BadSize);
        }
        let rights = r.handles.info(0).map_or(Rights::NONE, |(_, rights)| rights);
        let object = match r.handles.take::<Memory>(0) {
            Ok(object) => object,
            Err(_) => return Answer::Status(code(proto_net::INVALID)),
        };
        if size as usize != BUFFER_SIZE || rights.0 & NEEDED.0 != NEEDED.0 {
            return Answer::Status(code(proto_net::INVALID));
        }
        // An object of `mem_create`: as big as asked and with every page
        // its own (a device window owns none).
        match sys::memory_info(&object) {
            Ok(info)
                if info.size >= BUFFER_SIZE as u64
                    && info.pages * virtio_mmio::PAGE as u64 >= BUFFER_SIZE as u64 => {}
            _ => return Answer::Status(code(proto_net::INVALID)),
        }
        // A number whose entry was given back (a map that failed) is no buffer.
        if s.data
            .buffer
            .is_some_and(|i| self.buffers.held_by(usize::from(i), s.label()))
        {
            return Answer::Status(code(proto_net::EXISTS));
        }
        if self.process.is_none() {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        let i = match self.buffers.give(s.label()) {
            Ok(i) => i,
            Err(Refusal::Full) => return Answer::Status(Status::Kernel(Error::LimitReached)),
        };
        let Some(pending) = r.defer() else {
            self.buffers.free(i);
            return Answer::Status(Status::Kernel(Error::BadState));
        };
        self.buffers.wait(i);
        s.data.buffer = Some(i as u8);
        self.waiting[i] = Some(Waiting {
            object,
            pending,
            status: None,
        });
        self.buffer_wanted = true;
        Answer::Deferred
    }

    /// The step of a BUFFER that waits, one part a step: the map of the first entry whose
    /// object is not mapped, after the answer of the first whose map was made (the answers go first: with many BUFFERs at once each is answered two steps after its map) (the close of the
    /// handle and the reply are calls of the kernel of their own, and the map needs the step to
    /// itself). True when more is to do.
    pub fn map_waiting(&mut self) -> bool {
        let part = netd::buffers::next_part(self.waiting_answer(), self.waiting_map());
        if let Some(Part::Map(i)) = part {
            let at = dma::buffer_at(self.buffers.address_of(i));
            let status = match (self.process.as_deref(), self.waiting[i].as_ref()) {
                (Some(process), Some(w)) => {
                    match sys::mem_map(
                        process,
                        &w.object,
                        0,
                        BUFFER_SIZE as u64,
                        at,
                        Access::ReadWrite,
                    ) {
                        Ok(()) => {
                            // The quota the mappings cost, for the probe's role `B`
                            // (CONFIG prints it).
                            #[cfg(feature = "probe")]
                            match self.buffers.count() {
                                1 => self.counters.buffers_used[0] = quota_used(process),
                                64 => self.counters.buffers_used[1] = quota_used(process),
                                _ => {}
                            }
                            Status::Ok
                        }
                        Err(Error::NoMemory | Error::LimitReached) => {
                            Status::Kernel(Error::LimitReached)
                        }
                        Err(other) => Status::Kernel(other),
                    }
                }
                _ => Status::Kernel(Error::BadState),
            };
            if let Some(w) = self.waiting[i].as_mut() {
                w.status = Some(status);
            }
            return true;
        }
        let Some(Part::Answer(i)) = part else {
            return false;
        };
        if let Some(Waiting {
            object,
            pending,
            status: Some(status),
        }) = self.waiting[i].take()
        {
            // The mapping keeps the object; the handle goes.
            drop(object);
            if status == Status::Ok {
                self.buffers.mapped(i);
            } else {
                self.buffers.free(i);
            }
            let _ = pending.answer(&proto_wire::reply(status), Outgoing::new());
        }
        self.waiting_answer().is_some() || self.waiting_map().is_some()
    }

    /// The first entry that waits for its map.
    fn waiting_map(&self) -> Option<usize> {
        (0..self.waiting.len())
            .find(|&i| self.waiting[i].as_ref().is_some_and(|w| w.status.is_none()))
    }

    /// The first entry whose map was made (or refused) and whose BUFFER is not answered.
    fn waiting_answer(&self) -> Option<usize> {
        (0..self.waiting.len())
            .find(|&i| self.waiting[i].as_ref().is_some_and(|w| w.status.is_some()))
    }

    /// The buffer of entry `i` is unmapped and its entry freed: one call of
    /// the kernel (none for an entry whose BUFFER waits for its map: its object goes and its
    /// BUFFER unanswered). A failure leaves the mapping and frees nothing.
    pub fn unmap_buffer(&mut self, i: usize) -> bool {
        let made = self.waiting[i]
            .as_ref()
            .is_some_and(|w| w.status == Some(Status::Ok));
        if self.buffers.is_waiting(i) && !made {
            self.waiting[i] = None;
            self.buffers.free(i);
            return true;
        }
        let Some(process) = self.process.as_deref() else {
            return false;
        };
        // SAFETY: nothing of the service's own lies in the buffer's range;
        // the bytes there are the client's.
        let gone = unsafe {
            sys::mem_unmap(
                process,
                dma::buffer_at(self.buffers.address_of(i)),
                BUFFER_SIZE as u64,
            )
        };
        if gone.is_ok() {
            self.waiting[i] = None;
            self.buffers.free(i);
        }
        gone.is_ok()
    }

    /// The session lets go of its buffer at once (ABANDON before an exec):
    /// the new image starts without one.
    pub fn drop_buffer(&mut self, s: &mut Sess) {
        if let Some(i) = s.data.buffer.take() {
            let i = usize::from(i);
            if !self.buffers.held_by(i, s.label()) {
                return;
            }
            if !self.unmap_buffer(i) {
                // A step of departure tries again.
                self.buffers.retire(i);
                self.cleanup_wanted = true;
            }
        }
    }

    /// The session went: its buffer waits for a step of departure (one that waits for its map
    /// goes at once).
    pub fn retire_buffer(&mut self, s: &mut Sess) -> bool {
        let Some(i) = s.data.buffer.take() else {
            return false;
        };
        let i = usize::from(i);
        if !self.buffers.held_by(i, s.label()) {
            return false;
        }
        if self.unmap_if_waiting(i) {
            return false;
        }
        self.buffers.retire(i);
        true
    }

    /// An entry whose BUFFER waits for its map is given back without a call of the kernel.
    fn unmap_if_waiting(&mut self, i: usize) -> bool {
        let made = self.waiting[i]
            .as_ref()
            .is_some_and(|w| w.status == Some(Status::Ok));
        self.buffers.is_waiting(i) && !made && self.unmap_buffer(i)
    }

    /// One retired buffer is unmapped (a step of departure); true when more wait.
    pub fn unmap_retired(&mut self) -> bool {
        if let Some(i) = self.buffers.next_retired() {
            let _ = self.unmap_buffer(i);
        }
        self.buffers.next_retired().is_some()
    }

    /// The address of the cell at `offset` of the session's buffer for `len`
    /// bytes: INVALID for a cell that is not one, or a session without a buffer.
    pub fn cell(&self, s: &Sess, offset: u32, len: u32) -> Result<usize, u32> {
        let Some(i) = s.data.buffer else {
            return Err(proto_net::INVALID);
        };
        let i = usize::from(i);
        if !self.buffers.owned_by(i, s.label()) || !proto_net::cell_fits(offset, len) {
            return Err(proto_net::INVALID);
        }
        Ok(dma::buffer_at(self.buffers.address_of(i)) + offset as usize)
    }

    /// GETOPT BUFFERS and BUFFERED.
    pub fn buffers_word(&self, name: u32) -> u32 {
        if name == proto_net::sockets::opt::BUFFERS {
            u32::from(self.buffers.count()) | u32::from(self.buffers.limit()) << 16
        } else {
            (self.buffered >> 10) as u32
        }
    }
}

/// The pages charged to the service's quota now.
#[cfg(feature = "probe")]
fn quota_used(process: &rt::handle::Handle<rt::handle::Process>) -> u64 {
    sys::process_memory(process).map_or(0, |m| m.used) / virtio_mmio::PAGE as u64
}

/// Up to `BUFFER_PORTION` of `len` bytes from `from` into the queue of
/// sending of `t`: the bytes taken.
///
/// # Safety
/// `from` is the address of a cell of a mapped buffer with `len` bytes.
pub unsafe fn cell_to_queue(t: &mut tcp::Socket<'_>, from: usize, len: usize) -> usize {
    let from = from as *const u8;
    copy_portion(len, BUFFER_PORTION, |done, want| {
        t.send(|window| {
            let k = window.len().min(want);
            // SAFETY: `done + k` stays within the cell (the caller's bound);
            // the window is the queue's own and apart from the buffer.
            unsafe { core::ptr::copy_nonoverlapping(from.add(done), window.as_mut_ptr(), k) };
            (k, k)
        })
        .unwrap_or(0)
    })
}

/// Up to `BUFFER_PORTION` of `most` bytes from the queue of receiving of
/// `t` into `to`, which a peek leaves in the queue (the front of the queue
/// that lies in one piece): the bytes put.
///
/// # Safety
/// `to` is the address of a cell of a mapped buffer with room for `most`.
pub unsafe fn queue_to_cell(t: &mut tcp::Socket<'_>, to: usize, most: usize, peek: bool) -> usize {
    let to = to as *mut u8;
    if peek {
        let Ok(front) = t.peek(most.min(BUFFER_PORTION)) else {
            return 0;
        };
        // SAFETY: as below.
        unsafe { core::ptr::copy_nonoverlapping(front.as_ptr(), to, front.len()) };
        return front.len();
    }
    copy_portion(most, BUFFER_PORTION, |done, want| {
        t.recv(|window| {
            let k = window.len().min(want);
            // SAFETY: `done + k` stays within the cell (the caller's bound);
            // the window is the queue's own and apart from the buffer.
            unsafe { core::ptr::copy_nonoverlapping(window.as_ptr(), to.add(done), k) };
            (k, k)
        })
        .unwrap_or(0)
    })
}
