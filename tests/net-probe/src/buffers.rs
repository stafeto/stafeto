// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The roles of the shared buffers (BUFFER of proto_net):
//!
//! - `G`: one connection through the loopback carries 1 MiB in requests
//!   with a cell (SEND and RECV with `BUF`, 16 KiB asked each), and every
//!   byte that arrives is the byte that was sent. The steps of the service
//!   at the portion it was built with are the measurement that chooses
//!   `BUFFER_PORTION`.
//! - `B`: 64 sessions take a buffer (one object, 64 mappings in the
//!   service), the sixty-fifth gets LIMIT_REACHED, an object of 128 KiB
//!   INVALID, a second BUFFER of a session EXISTS, a cell past the end of the
//!   buffer INVALID; every session sends and receives through its buffer;
//!   ABANDON lets one buffer go at once; the sessions go and 64 new ones take
//!   buffers again (the steps of departure unmapped the old).

use crate::{Fail, PAUSE_NS, Probe, call, is, ready, socket_call};
use abi::{Access, MESSAGE_MAX, Rights};
use proto_net::sockets::{self, Request, opt};
use proto_net::{Address, BUFFER_SIZE, Method, SLOT};
use proto_wire::Writer;
use rt::handle::{Channel, Handle, Memory};
use rt::sys;

/// Where the probe maps its buffer.
const BUFFER_AT: usize = 0x10_0000_0000;
/// The bytes role `G` carries.
const G_BYTES: u32 = 1024 * 1024;
/// The sessions role `B` gives a buffer.
const B_SESSIONS: usize = 64;
/// The ports of the listeners of the roles.
const G_PORT: u32 = 9500;
const B_PORT: u32 = 9600;

/// The byte at `offset` of the stream of the roles.
fn byte(offset: u32) -> u8 {
    (offset as u8)
        .wrapping_mul(13)
        .wrapping_add((offset >> 8) as u8)
}

/// The bytes of the probe's buffer, as one slice.
///
/// # Safety
/// The buffer is mapped at BUFFER_AT for BUFFER_SIZE bytes, and the service
/// copies to or from it only while the probe waits for a reply.
unsafe fn buffer() -> &'static mut [u8] {
    unsafe { core::slice::from_raw_parts_mut(BUFFER_AT as *mut u8, BUFFER_SIZE) }
}

/// One connection through the loopback of `net`: the client and the
/// accepted end.
struct Pair {
    listener: u32,
    ends: [u32; 2],
}

impl Probe<'_> {
    /// BUFFER of `object` (a copy with the rights of mapping) on `net`,
    /// asking for `size` bytes.
    fn give_buffer(
        &self,
        net: &Handle<Channel>,
        object: &Handle<Memory>,
        size: u32,
    ) -> Result<(), Fail> {
        let copy = sys::handle_duplicate(
            object,
            Rights::MAP_READ | Rights::MAP_WRITE | Rights::TRANSFER,
        )
        .map_err(Fail::Kernel)?;
        let mut w = Writer::new();
        proto_net::write_buffer(size, &mut w).map_err(Fail::Status)?;
        let reply = sys::send_handles(net, w.as_bytes(), [copy.erase()])
            .map_err(|refused| Fail::Kernel(refused.error))?;
        let mut buffer = [0; MESSAGE_MAX];
        let bytes = reply.bytes(&mut buffer);
        let word = bytes.get(..4).ok_or(Fail::Bad("a short reply"))?;
        match proto_wire::Status::from_code(u32::from_le_bytes([
            word[0], word[1], word[2], word[3],
        ])) {
            proto_wire::Status::Ok => Ok(()),
            status => Err(Fail::Status(status)),
        }
    }

    /// The probe's buffer: a new object mapped at BUFFER_AT.
    fn own_buffer(&self) -> Result<Handle<Memory>, &'static str> {
        let object = sys::mem_create(BUFFER_SIZE as u64).map_err(|_| "mem_create failed")?;
        sys::mem_map(
            self.process,
            &object,
            0,
            BUFFER_SIZE as u64,
            BUFFER_AT,
            Access::ReadWrite,
        )
        .map_err(|_| "the probe's buffer is not mapped")?;
        Ok(object)
    }

    /// A connection through the loopback of `net` on `port`.
    fn pair(&self, net: &Handle<Channel>, port: u32) -> Result<Pair, &'static str> {
        let listener = self
            .new_socket(net, sockets::STREAM)
            .map_err(|_| "SOCKET failed")?;
        self.bind(net, listener, [127, 0, 0, 1], port)
            .map_err(|_| "BIND failed")?;
        self.plain(
            net,
            Request::Listen {
                description: listener,
                backlog: 1,
            },
        )
        .map_err(|_| "LISTEN failed")?;
        let client = self
            .new_socket(net, sockets::STREAM)
            .map_err(|_| "SOCKET failed")?;
        self.connect_wait(net, client, Address::v4([127, 0, 0, 1], port))?;
        let mut buffer = [0; MESSAGE_MAX];
        let len = self
            .nonblocking(PAUSE_NS, || {
                socket_call(
                    net,
                    &Request::Accept {
                        key: None,
                        description: listener,
                        flags: sockets::NONBLOCK,
                    },
                    &mut buffer,
                )
                .map(|b| b.len())
            })
            .map_err(|_| "ACCEPT failed")?;
        let reply = ready(&buffer[..len]).map_err(|_| "ACCEPT's reply")?;
        let (accepted, _) = sockets::read_accepted(reply).map_err(|_| "ACCEPT's data")?;
        Ok(Pair {
            listener,
            ends: [client, accepted],
        })
    }

    fn close_pair(&self, net: &Handle<Channel>, p: &Pair) -> Result<(), &'static str> {
        for d in [p.ends[0], p.ends[1], p.listener] {
            self.close(net, d).map_err(|_| "CLOSE failed")?;
        }
        Ok(())
    }

    /// SEND with a cell: the bytes taken.
    fn send_cell(&self, net: &Handle<Channel>, d: u32, offset: u32, len: u32) -> Result<u32, Fail> {
        let mut buffer = [0; MESSAGE_MAX];
        let request = Request::SendCell {
            key: None,
            description: d,
            flags: 0,
            address: Address::NONE,
            offset,
            len,
        };
        let reply = socket_call(net, &request, &mut buffer)?;
        sockets::read_sent(ready(reply)?).map_err(Fail::Status)
    }

    /// RECV with a cell: the bytes put into it.
    fn recv_cell(
        &self,
        net: &Handle<Channel>,
        d: u32,
        offset: u32,
        most: u32,
    ) -> Result<u32, Fail> {
        let mut buffer = [0; MESSAGE_MAX];
        let request = Request::RecvCell {
            key: None,
            description: d,
            flags: 0,
            most,
            offset,
        };
        let reply = socket_call(net, &request, &mut buffer)?;
        let (_, _, count) =
            sockets::read_received_count(ready(reply)?, most).map_err(Fail::Status)?;
        Ok(count)
    }

    /// `total` bytes of the stream from end 0 of `p` to end 1 through the
    /// cells 0 (sending) and 1 (receiving) of the buffer of `net`.
    fn carry(&self, net: &Handle<Channel>, p: &Pair, total: u32) -> Result<(), &'static str> {
        // SAFETY: the probe's buffer is mapped; the service touches it only
        // in the requests below.
        let cells = unsafe { buffer() };
        let (sent_at, got_at) = (0usize, SLOT);
        let (mut sent, mut got) = (0u32, 0u32);
        let mut idle = 0u32;
        while got < total {
            let mut moved = false;
            if sent < total {
                let len = (total - sent).min(SLOT as u32);
                for i in 0..len {
                    cells[sent_at + i as usize] = byte(sent + i);
                }
                match self.send_cell(net, p.ends[0], sent_at as u32, len) {
                    Ok(n) if n <= len => {
                        sent += n;
                        moved |= n > 0;
                    }
                    Ok(_) => return Err("SEND took more than the cell"),
                    Err(fail) if is(&fail, proto_net::AGAIN) => {}
                    Err(fail) => {
                        rt::println!("net-probe: SEND with a cell: {fail:?}");
                        return Err("SEND with a cell failed");
                    }
                }
            }
            match self.recv_cell(net, p.ends[1], got_at as u32, SLOT as u32) {
                Ok(n) => {
                    for i in 0..n {
                        if cells[got_at + i as usize] != byte(got + i) {
                            return Err("a byte through the buffer is not the byte that was sent");
                        }
                    }
                    got += n;
                    moved |= n > 0;
                }
                Err(fail) if is(&fail, proto_net::AGAIN) => {}
                Err(fail) => {
                    rt::println!("net-probe: RECV with a cell: {fail:?}");
                    return Err("RECV with a cell failed");
                }
            }
            if moved {
                idle = 0;
            } else {
                idle += 1;
                if idle > 5_000 {
                    return Err("the stream through the buffer stopped");
                }
                self.sleep(PAUSE_NS);
            }
        }
        Ok(())
    }

    /// GETOPT `name` on description `d` of `net`.
    fn option(&self, net: &Handle<Channel>, d: u32, name: u32) -> Result<u32, &'static str> {
        let mut buffer = [0; MESSAGE_MAX];
        let reply = socket_call(
            net,
            &Request::GetOpt {
                description: d,
                name,
            },
            &mut buffer,
        )
        .map_err(|_| "GETOPT failed")?;
        sockets::read_word(reply).map_err(|_| "GETOPT's reply")
    }

    /// Role `G`.
    pub fn portion(&self, keep: &mut Option<Handle<Channel>>) -> Result<(), &'static str> {
        let root = self.connect()?;
        let object = self.own_buffer()?;
        let net = self.clone_empty(&root).map_err(|_| "CLONE failed")?;
        self.give_buffer(&net, &object, BUFFER_SIZE as u32)
            .map_err(|_| "BUFFER refused")?;
        let p = self.pair(&net, G_PORT)?;
        self.carry(&net, &p, G_BYTES)?;
        let kib = self.option(&net, p.ends[0], opt::BUFFERED)?;
        self.close_pair(&net, &p)?;
        // SAFETY: nothing of the probe's own lies in the buffer.
        unsafe { sys::mem_unmap(self.process, BUFFER_AT, BUFFER_SIZE as u64) }
            .map_err(|_| "the probe's buffer is not unmapped")?;
        rt::println!("net-probe: portion ok {G_BYTES} buffered {kib} KiB");
        *keep = Some(root);
        Ok(())
    }

    /// Role `B`.
    pub fn buffer_sessions(&self, keep: &mut Option<Handle<Channel>>) -> Result<(), &'static str> {
        let root = self.connect()?;
        let object = self.own_buffer()?;
        let small = sys::mem_create(BUFFER_SIZE as u64 / 2).map_err(|_| "mem_create failed")?;
        let mut sessions: [Option<Handle<Channel>>; B_SESSIONS] = [const { None }; B_SESSIONS];
        for slot in sessions.iter_mut() {
            let net = self.clone_empty(&root).map_err(|_| "CLONE failed")?;
            self.give_buffer(&net, &object, BUFFER_SIZE as u32)
                .map_err(|fail| {
                    rt::println!("net-probe: BUFFER: {fail:?}");
                    "a BUFFER within the limit was refused"
                })?;
            *slot = Some(net);
        }
        let mappings = sys::memory_info(&object).map_or(0, |i| i.mappings);
        // CONFIG has the service print what the mappings cost its quota.
        crate::config(&root).map_err(|_| "CONFIG failed")?;
        let extra = self.clone_empty(&root).map_err(|_| "CLONE failed")?;
        match self.give_buffer(&extra, &small, BUFFER_SIZE as u32) {
            Err(fail) if is(&fail, proto_net::INVALID) => {}
            _ => return Err("an object of 128 KiB was not refused with INVALID"),
        }
        match self.give_buffer(&extra, &object, BUFFER_SIZE as u32) {
            Err(Fail::Status(proto_wire::Status::Kernel(abi::Error::LimitReached))) => {}
            _ => return Err("the sixty-fifth buffer was not refused with LIMIT_REACHED"),
        }
        let first = sessions[0].as_ref().ok_or("no session")?;
        match self.give_buffer(first, &object, BUFFER_SIZE as u32) {
            Err(fail) if is(&fail, proto_net::EXISTS) => {}
            _ => return Err("a second BUFFER of a session was not refused with EXISTS"),
        }
        // Every session sends and receives through its buffer.
        let mut words = 0;
        for (i, net) in sessions.iter().enumerate() {
            let net = net.as_ref().ok_or("no session")?;
            let p = self.pair(net, B_PORT + i as u32)?;
            if i == 0 {
                match self.send_cell(net, p.ends[0], 255 * 1024, SLOT as u32) {
                    Err(fail) if is(&fail, proto_net::INVALID) => {}
                    _ => return Err("a cell past the end of the buffer was not refused"),
                }
                words = self.option(net, p.ends[0], opt::BUFFERS)?;
            }
            self.carry(net, &p, SLOT as u32)?;
            self.close_pair(net, &p)?;
        }
        if words != 64 | 64 << 16 {
            rt::println!("net-probe: BUFFERS {words:#x}");
            return Err("BUFFERS does not say 64 of 64");
        }
        // ABANDON lets the buffer of the session go at once.
        let mut buffer = [0; MESSAGE_MAX];
        call(first, &Method::Abandon.header().bytes(), &mut buffer)
            .map_err(|_| "ABANDON refused")?;
        let probe = self
            .new_socket(first, sockets::DGRAM)
            .map_err(|_| "SOCKET failed")?;
        let after = self.option(first, probe, opt::BUFFERS)? & 0xFFFF;
        if after != 63 {
            rt::println!("net-probe: BUFFERS after ABANDON {after}");
            return Err("ABANDON did not let the buffer go");
        }
        self.close(first, probe).map_err(|_| "CLOSE failed")?;
        // The sessions go; their buffers are unmapped in steps, and 64 new
        // sessions take buffers again.
        drop(extra);
        for slot in sessions.iter_mut() {
            *slot = None;
        }
        self.sleep(200_000_000);
        for slot in sessions.iter_mut() {
            let net = self.clone_empty(&root).map_err(|_| "CLONE failed")?;
            let end = self.now() + 3_000_000_000;
            loop {
                match self.give_buffer(&net, &object, BUFFER_SIZE as u32) {
                    Ok(()) => break,
                    Err(Fail::Status(proto_wire::Status::Kernel(abi::Error::LimitReached)))
                        if self.now() < end =>
                    {
                        self.sleep(10_000_000)
                    }
                    Err(fail) => {
                        rt::println!("net-probe: BUFFER again: {fail:?}");
                        return Err("the buffers of the sessions that went were not let go of");
                    }
                }
            }
            *slot = Some(net);
        }
        for slot in sessions.iter_mut() {
            *slot = None;
        }
        self.sleep(200_000_000);
        rt::println!("net-probe: buffers ok 64 then 64, object mappings {mappings}");
        *keep = Some(root);
        Ok(())
    }
}
