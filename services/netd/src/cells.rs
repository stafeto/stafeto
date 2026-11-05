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
use netd::buffers::{Refusal, copy_portion};
use netd::ring::BUFFER_PORTION;
use proto_net::{BUFFER_SIZE, code};
use proto_wire::Status;
use rt::handle::Memory;
use rt::service::{Answer, Request, Session};
use rt::sys;
use smoltcp::socket::tcp;

type Sess = Session<Client, 0>;

/// The rights the object of BUFFER must carry.
const NEEDED: Rights = Rights(Rights::MAP_READ.0 | Rights::MAP_WRITE.0);

impl Net {
    /// BUFFER: the object the request carries becomes the session's shared
    /// buffer, mapped for the session's life.
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
        if s.data.buffer.is_some() {
            return Answer::Status(code(proto_net::EXISTS));
        }
        let Some(process) = self.process.as_deref() else {
            return Answer::Status(Status::Kernel(Error::BadState));
        };
        let i = match self.buffers.give(s.label()) {
            Ok(i) => {
                rt::println!("DIAG buffer given {i} label {:#x} count {}", s.label(), self.buffers.count());
                i
            }
            Err(Refusal::Full) => {
                rt::println!("DIAG buffer FULL label {:#x} count {}", s.label(), self.buffers.count());
                return Answer::Status(Status::Kernel(Error::LimitReached));
            }
        };
        let at = dma::buffer_at(i);
        match sys::mem_map(
            process,
            &object,
            0,
            BUFFER_SIZE as u64,
            at,
            Access::ReadWrite,
        ) {
            Ok(()) => {
                s.data.buffer = Some(i as u8);
                // The quota the mappings cost, for the probe's role `B`
                // (CONFIG prints it).
                #[cfg(feature = "probe")]
                match self.buffers.count() {
                    1 => self.counters.buffers_used[0] = quota_used(process),
                    64 => self.counters.buffers_used[1] = quota_used(process),
                    _ => {}
                }
                // The mapping keeps the object; the handle goes.
                drop(object);
                Answer::Status(Status::Ok)
            }
            Err(error) => {
                rt::println!("DIAG buffer map failed {error:?} entry {i}");
                self.buffers.free(i);
                let error = match error {
                    Error::NoMemory | Error::LimitReached => Error::LimitReached,
                    other => other,
                };
                Answer::Status(Status::Kernel(error))
            }
        }
    }

    /// The buffer of entry `i` is unmapped and its entry freed: one call of
    /// the kernel. A failure leaves the mapping and frees nothing.
    pub fn unmap_buffer(&mut self, i: usize) -> bool {
        let Some(process) = self.process.as_deref() else {
            return false;
        };
        // SAFETY: nothing of the service's own lies in the buffer's range;
        // the bytes there are the client's.
        let gone = unsafe { sys::mem_unmap(process, dma::buffer_at(i), BUFFER_SIZE as u64) };
        if gone.is_ok() {
            self.buffers.free(i);
        }
        rt::println!("DIAG buffer unmap {i} ok {} count {}", gone.is_ok(), self.buffers.count());
        gone.is_ok()
    }

    /// The session lets go of its buffer at once (ABANDON before an exec):
    /// the new image starts without one.
    pub fn drop_buffer(&mut self, s: &mut Sess) {
        if let Some(i) = s.data.buffer.take() {
            let i = usize::from(i);
            if !self.unmap_buffer(i) {
                // A step of departure tries again.
                self.buffers.retire(i);
                self.cleanup_wanted = true;
            }
        }
    }

    /// The session went: its buffer waits for a step of departure.
    pub fn retire_buffer(&mut self, s: &mut Sess) -> bool {
        match s.data.buffer.take() {
            Some(i) => {
                rt::println!("DIAG buffer retire {i} label {:#x}", s.label());
                self.buffers.retire(usize::from(i));
                true
            }
            None => false,
        }
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
        Ok(dma::buffer_at(i) + offset as usize)
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
