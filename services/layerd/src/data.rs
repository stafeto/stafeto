// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The calls to the data file service: the session of a native client (init gives the label
//! `proto_data::SERVICE`, so the service is user 0 there), one call at a time from the loop.

use layerd::volume::{BATCH_BYTES, R, Visit, Volume};
use proto_data as p;
use proto_data::Method;
use proto_wire::{Status, Writer};
use rt::handle::{Channel, Handle};
use rt::sys;

pub struct Data {
    pub session: Handle<Channel>,
}

struct Buf {
    bytes: [u8; abi::MESSAGE_MAX],
    len: usize,
}

impl Data {
    fn exchange(
        &self,
        build: impl FnOnce(&mut Writer) -> Result<(), Status>,
    ) -> R<(sys::Reply, Buf)> {
        let mut w = Writer::new();
        build(&mut w)?;
        let reply = match sys::send(&self.session, w.as_bytes()) {
            Ok(reply) => reply,
            Err(abi::Error::PeerClosed) => {
                rt::println!("layerd: the data file service went, ending for a new instance");
                sys::process_exit(crate::DATA_GONE)
            }
            Err(e) => return Err(Status::Kernel(e)),
        };
        let mut buf = Buf {
            bytes: [0; abi::MESSAGE_MAX],
            len: 0,
        };
        buf.len = reply.bytes(&mut buf.bytes).len();
        p::reply(&buf.bytes[..buf.len])?;
        Ok((reply, buf))
    }

    fn call(&self, build: impl FnOnce(&mut Writer) -> Result<(), Status>) -> R<Buf> {
        self.exchange(build).map(|(_, buf)| buf)
    }
}

/// The build for `cargo xtask layer-cut` prints the line of its point and stops there for good: the
/// host kills the machine on the line and starts it again on the same disk.
pub fn stop(point: u8) -> ! {
    rt::println!("layerd: cut point {point}");
    let held = sys::channel_create(crate::worker::LEVEL);
    loop {
        if let Ok(channel) = &held {
            let _ = sys::receive(channel);
        } else {
            core::hint::spin_loop();
        }
    }
}

impl Data {
    /// WINDOW with a copy of `memory` that has MAP_READ, MAP_WRITE and TRANSFER (the worker's).
    pub fn window(&mut self, memory: &rt::handle::Handle<rt::handle::Memory>) -> R<()> {
        let copy = sys::handle_duplicate(
            memory,
            abi::Rights::MAP_READ | abi::Rights::MAP_WRITE | abi::Rights::TRANSFER,
        )
        .map_err(Status::Kernel)?;
        let mut w = Writer::new();
        p::window(&mut w)?;
        let reply = sys::send_handles(&self.session, w.as_bytes(), [copy.erase()])
            .map_err(|refused| Status::Kernel(refused.error))?;
        let mut bytes = [0u8; abi::MESSAGE_MAX];
        let len = reply.bytes(&mut bytes).len();
        p::reply(&bytes[..len]).map(drop)
    }

    /// PWRITE_FROM of `count` bytes of the first cell at `offset` of `handle`, one part with no
    /// lease; the count written.
    pub fn part(&mut self, handle: u32, offset: u64, count: usize) -> R<usize> {
        let part = p::Part {
            handle,
            count: count as u32,
            offset,
            cell: 0,
            flags: 0,
            lease: 0,
        };
        let buf = self.call(|w| p::pwrite_from(&part, &[], w))?;
        let mut r = p::reply(&buf.bytes[..buf.len])?;
        let wrote = r.u32()? as usize;
        let flags = r.u32()?;
        let _lease = r.u32()?;
        // A part that lapsed wrote nothing that can be counted on.
        if flags & p::LAPSED != 0 {
            return Err(Status::Unknown(p::IO));
        }
        Ok(wrote)
    }
}

impl Volume for Data {
    type Pass = rt::handle::Handle<rt::handle::Any>;

    fn open(&mut self, path: &[u8], flags: u32, mode: u32) -> R<u32> {
        let buf = self.call(|w| p::open(path, flags, mode, w))?;
        let mut r = p::reply(&buf.bytes[..buf.len])?;
        r.u32()
    }

    fn open_numbered(&mut self, path: &[u8], flags: u32, mode: u32, ino: u64) -> R<u32> {
        let buf = self.call(|w| p::open_numbered(path, flags, mode, ino, w))?;
        let mut r = p::reply(&buf.bytes[..buf.len])?;
        r.u32()
    }

    fn truncate(&mut self, handle: u32, size: u64) -> R<()> {
        self.call(|w| p::truncate(handle, size, w)).map(drop)
    }

    fn chmod(&mut self, path: &[u8], mode: u32) -> R<()> {
        self.call(|w| p::chmod(path, mode, w)).map(drop)
    }

    fn chown(&mut self, path: &[u8], uid: u32, gid: u32) -> R<()> {
        self.call(|w| p::chown(path, uid, gid, w)).map(drop)
    }

    fn utimens(&mut self, path: &[u8], atime: i64, mtime: i64) -> R<()> {
        self.call(|w| {
            p::utimens(
                path,
                p::TimeSpec::from_word(atime)?,
                p::TimeSpec::from_word(mtime)?,
                w,
            )
        })
        .map(drop)
    }

    fn close(&mut self, handle: u32) -> R<()> {
        self.call(|w| p::handle_call(Method::Close, handle, w))
            .map(drop)
    }

    fn read(&mut self, handle: u32, out: &mut [u8]) -> R<usize> {
        let count = out.len().min(p::MAX_READ) as u32;
        let buf = self.call(|w| p::read(handle, count, w))?;
        let mut r = p::reply(&buf.bytes[..buf.len])?;
        let n = r.u32()? as usize;
        let bytes = r.bytes(n)?;
        let take = n.min(out.len());
        out[..take].copy_from_slice(&bytes[..take]);
        Ok(take)
    }

    fn write(&mut self, handle: u32, bytes: &[u8]) -> R<usize> {
        let part = &bytes[..bytes.len().min(900)];
        let buf = self.call(|w| p::write(handle, part, w))?;
        let mut r = p::reply(&buf.bytes[..buf.len])?;
        Ok(r.u32()? as usize)
    }

    fn fsync(&mut self, handle: u32) -> R<()> {
        self.call(|w| p::handle_call(Method::Fsync, handle, w))
            .map(drop)
    }

    fn stat(&mut self, path: &[u8]) -> R<p::Stat> {
        let buf = self.call(|w| p::path_call(Method::Stat, path, w))?;
        let mut r = p::reply(&buf.bytes[..buf.len])?;
        let bytes = r.bytes(p::STAT_LEN)?;
        p::Stat::from_bytes(bytes)
    }

    fn mkdir(&mut self, path: &[u8], mode: u32) -> R<()> {
        self.call(|w| p::mkdir(path, mode, w)).map(drop)
    }

    fn mkdir_numbered(&mut self, path: &[u8], mode: u32, ino: u64) -> R<()> {
        self.call(|w| p::mkdir_numbered(path, mode, ino, w))
            .map(drop)
    }

    fn cut(&mut self, point: u8) {
        stop(point)
    }

    fn rename(&mut self, from: &[u8], to: &[u8]) -> R<()> {
        self.call(|w| p::rename(from, to, w)).map(drop)
    }

    fn unlink(&mut self, path: &[u8]) -> R<()> {
        self.call(|w| p::path_call(Method::Unlink, path, w))
            .map(drop)
    }

    fn rmdir(&mut self, path: &[u8]) -> R<()> {
        self.call(|w| p::path_call(Method::Rmdir, path, w))
            .map(drop)
    }

    fn read_dir(&mut self, handle: u32, visit: Visit<'_>) -> R<bool> {
        let buf = self.call(|w| p::handle_call(Method::Readdir, handle, w))?;
        let r = p::reply(&buf.bytes[..buf.len])?;
        let mut entries = p::read_dir_reply(r)?;
        while let Some(e) = entries.next_entry()? {
            visit(e.ino, e.kind, e.name);
        }
        Ok(entries.more)
    }

    fn read_dir_raw(&mut self, handle: u32, out: &mut [u8; BATCH_BYTES]) -> R<(usize, bool)> {
        let buf = self.call(|w| p::handle_call(Method::Readdir, handle, w))?;
        let mut r = p::reply(&buf.bytes[..buf.len])?;
        let more = match r.u32()? {
            0 => false,
            1 => true,
            _ => return Err(Status::BadSize),
        };
        let rest = r.bytes(r.left())?;
        out[..rest.len()].copy_from_slice(rest);
        Ok((rest.len(), more))
    }

    fn export(&mut self, handle: u32) -> R<Self::Pass> {
        let (mut reply, _) = self.exchange(|w| p::handle_call(Method::Export, handle, w))?;
        reply.handles.take_any(0).map_err(|_| Status::BadSize)
    }
}
