// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The guest probe of the disk service (`blk`, services/virtio-blk), a
//! client of init. It picks its mode from sector 0 of the disk:
//!
//! - zeros, the mode of writing: the refusals of the service (a request
//!   before BUFFER, a count of 0 and 33, a cell past the buffer, a range
//!   past the disk, a cell in flight, a second BUFFER); a pattern of 4 MiB at sector 2048 and one of the last
//!   32 sectors of the disk, written four cells in flight, FLUSH; a CANCEL
//!   of a read in flight; the whole pattern read back and compared; sector
//!   0 marked `STAFBLK1`, the way `pkgd` will commit (data, flush, then the
//!   mark, flush).
//! - `STAFBLK1`, the mode of checking, in a new run of QEMU on the same
//!   file: the pattern read and compared; CRASH of the service; a new
//!   session with the restarted service, INFO, sector 0 and the last 32
//!   sectors read again.
//! - `STAFFLT1`, the mode of faults: the host's `blkdebug` fails the first
//!   flush and the first read of sector 4096; the client sees IO for each,
//!   and READY for the second try. The host also holds each write after the
//!   first for a second, so a FLUSH sent right after a write meets a
//!   write that is with the device and is refused BUSY.
//!
//! Every operation goes in two steps (proto_blk, proto_wire::long). Each
//! check prints its line, and xtask reads them.

#![no_std]
#![no_main]

use abi::{Access, MESSAGE_MAX, Rights, Source};
use proto_blk::{BUFFER_SIZE, CELL_BYTES, CELLS, Info, Key, Method, SECTOR, SECTORS_MAX, code};
use proto_wire::{Status, Writer, long};
use rt::handle::{Any, Channel, Memory, Process, Resource};
use rt::wait::{Waited, Waiter};
use rt::{Handle, sys, time};

rt::entry!(main);

/// Where the probe maps its shared buffer.
const BUFFER_AT: usize = 0x10_4000_0000;
/// The pattern: 4 MiB from this sector, and the last 32 sectors.
const PATTERN_START: u64 = 2048;
const PATTERN_SECTORS: u64 = 8192;
const TAIL: u64 = 32;
/// The marks of sector 0.
const WRITTEN: &[u8; 8] = b"STAFBLK1";
const FAULTS: &[u8; 8] = b"STAFFLT1";
/// The tries of a check that depends on the device being slower than the
/// probe.
const TRIES: usize = 200;
/// The requests of the speed pass: 256 of 16 KiB, 4 MiB.
const SPEED_REQUESTS: u64 = 256;
/// The pause between connects after CRASH.
const PAUSE_NS: u64 = 20_000_000;

type Fail = &'static str;

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    let level = sys::thread_info(&start.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(level) else {
        return 1;
    };
    let mut probe = Probe {
        parent: &start.parent,
        process: &start.process,
        channel,
        level,
        service: None,
        info: None,
        object: None,
    };
    match probe.run() {
        Ok(()) => 0,
        Err(reason) => {
            rt::println!("blk-probe: failed: {reason}");
            2
        }
    }
}

struct Probe<'a> {
    parent: &'a Handle<Channel>,
    process: &'a Handle<Process>,
    /// The probe's own channel, which the service notifies through a copy.
    channel: Handle<Channel>,
    level: u8,
    service: Option<Handle<Channel>>,
    info: Option<Info>,
    /// The shared buffer's object, mapped at BUFFER_AT for the run.
    object: Option<Handle<Memory>>,
}

/// What a request of a long operation gave.
enum Got {
    Ready,
    Wait(u64),
    Armed,
    Cancelled,
}

fn check(ok: bool, why: Fail) -> Result<(), Fail> {
    if ok { Ok(()) } else { Err(why) }
}

/// The next word of the generator of the pattern (xorshift64).
fn xorshift(mut x: u64) -> u64 {
    x ^= x << 13;
    x ^= x >> 7;
    x ^ x << 17
}

/// The bytes of sector `sector` of the pattern: word `i` is
/// `xorshift(sector * K + i)`, low byte first.
fn pattern(sector: u64, out: &mut [u8]) {
    for (i, word) in out.as_chunks_mut::<8>().0.iter_mut().enumerate() {
        let seed = sector
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(i as u64);
        word.copy_from_slice(&xorshift(seed).to_le_bytes());
    }
}

/// The bytes of cell `cell` of the shared buffer.
fn cell(cell: usize, sectors: u32) -> &'static mut [u8] {
    // SAFETY: the buffer is mapped at BUFFER_AT for the run (`Probe::give`)
    // before any cell is used; the service reads a cell only while a write
    // of it is in flight and writes it only for a read in flight, and the
    // probe touches a cell in flight never.
    unsafe {
        core::slice::from_raw_parts_mut(
            (BUFFER_AT + cell * CELL_BYTES as usize) as *mut u8,
            sectors as usize * SECTOR,
        )
    }
}

/// The runs of sectors of the pattern, each at most one cell: (first sector,
/// count), in order, for a disk of `sectors`.
fn runs(sectors: u64) -> impl Iterator<Item = (u64, u32)> {
    let span = |from: u64, to: u64| {
        (from..to)
            .step_by(SECTORS_MAX as usize)
            .map(move |s| (s, (to - s).min(u64::from(SECTORS_MAX)) as u32))
    };
    span(PATTERN_START, PATTERN_START + PATTERN_SECTORS).chain(span(sectors - TAIL, sectors))
}

impl Probe<'_> {
    fn service(&self) -> Result<&Handle<Channel>, Fail> {
        self.service.as_ref().ok_or("no session")
    }

    fn info(&self) -> Result<Info, Fail> {
        self.info.ok_or("no INFO")
    }

    /// A session with `blk`, trying again while init restarts the service.
    fn connect(&mut self) -> Result<(), Fail> {
        for _ in 0..TRIES {
            if let Ok(service) = rt::service::connect(self.parent, "blk") {
                self.service = Some(service);
                return Ok(());
            }
            self.pause();
        }
        Err("connect to blk")
    }

    fn pause(&self) {
        let Ok(timer) = Waiter::new(&self.channel, 0, self.level) else {
            return;
        };
        let deadline = time::ticks_to_ns(time::now()).saturating_add(PAUSE_NS);
        while let Ok(Waited::Got(_)) = timer.receive_until(&self.channel, deadline) {}
    }

    /// One request, with `handle` when there is one; the long reply or the
    /// refusal as its status.
    fn call(&self, request: &[u8], handle: Option<Handle<Any>>) -> Result<Got, Status> {
        let service = self.service.as_ref().ok_or(Status::BadSize)?;
        let reply = match handle {
            None => sys::send(service, request)?,
            Some(h) => sys::send_handles(service, request, [h]).map_err(|r| r.error)?,
        };
        let mut buffer = [0; MESSAGE_MAX];
        match long::Reply::read(reply.bytes(&mut buffer))? {
            long::Reply::Ready([]) => Ok(Got::Ready),
            long::Reply::Ready(_) => Err(Status::BadSize),
            long::Reply::Wait(key) => Ok(Got::Wait(key)),
            long::Reply::Armed => Ok(Got::Armed),
            long::Reply::Cancelled => Ok(Got::Cancelled),
        }
    }

    /// A request that answers with its status alone: Ok for status 0.
    fn status(&self, request: &[u8], handle: Option<Handle<Any>>) -> Result<(), Status> {
        let service = self.service.as_ref().ok_or(Status::BadSize)?;
        let reply = match handle {
            None => sys::send(service, request)?,
            Some(h) => sys::send_handles(service, request, [h]).map_err(|r| r.error)?,
        };
        let mut buffer = [0; MESSAGE_MAX];
        let bytes = reply.bytes(&mut buffer);
        let mut v = [0; 4];
        let word = bytes.get(..4).ok_or(Status::BadSize)?;
        v.copy_from_slice(word);
        match Status::from_code(u32::from_le_bytes(v)) {
            Status::Ok => Ok(()),
            status => Err(status),
        }
    }

    /// INFO.
    fn load_info(&mut self) -> Result<(), Fail> {
        let service = self.service()?;
        let request = Method::Info.header().bytes();
        let reply = sys::send(service, &request).map_err(|_| "INFO")?;
        let mut buffer = [0; MESSAGE_MAX];
        let info = Info::read(reply.bytes(&mut buffer)).map_err(|_| "INFO reply")?;
        self.info = Some(info);
        Ok(())
    }

    /// BUFFER: the probe's object, mapped for the run, given to the session.
    fn give(&mut self) -> Result<Result<(), Status>, Fail> {
        if self.object.is_none() {
            let object = sys::mem_create(u64::from(BUFFER_SIZE)).map_err(|_| "mem_create")?;
            sys::mem_map(
                self.process,
                &object,
                0,
                u64::from(BUFFER_SIZE),
                BUFFER_AT,
                Access::ReadWrite,
            )
            .map_err(|_| "the buffer is not mapped")?;
            self.object = Some(object);
        }
        let object = self.object.as_ref().ok_or("no buffer")?;
        let copy = sys::handle_duplicate(
            object,
            Rights::MAP_READ | Rights::MAP_WRITE | Rights::TRANSFER,
        )
        .map_err(|_| "a copy of the buffer")?;
        let mut w = Writer::new();
        proto_blk::write_buffer(BUFFER_SIZE, &mut w).map_err(|_| "BUFFER request")?;
        Ok(self.status(w.as_bytes(), Some(copy.erase())))
    }

    /// A READ or a WRITE of `count` sectors from `sector` in `cell`: its
    /// key, or the service's refusal.
    fn start(&self, method: Method, cell: u32, count: u32, sector: u64) -> Result<u64, Status> {
        let mut w = Writer::new();
        method.header().write(&mut w)?;
        w.u32(cell)?;
        w.u32(count)?;
        w.u64(sector)?;
        match self.call(w.as_bytes(), None)? {
            Got::Wait(key) => Ok(key),
            _ => Err(Status::BadSize),
        }
    }

    fn start_flush(&self) -> Result<u64, Status> {
        match self.call(&Method::Flush.header().bytes(), None)? {
            Got::Wait(key) => Ok(key),
            _ => Err(Status::BadSize),
        }
    }

    /// TAKE of `key`, with a labelled copy of the probe's channel the first
    /// time, until the result comes: Ok when READY, the refusal otherwise.
    fn finish(&self, key: u64) -> Result<(), Status> {
        let mut w = Writer::new();
        Key { key }.write(Method::Take, &mut w)?;
        let mut notify = Some(
            sys::handle_label(
                &self.channel,
                Rights::NOTIFY | Rights::TRANSFER,
                key,
                self.level,
            )?
            .erase(),
        );
        loop {
            match self.call(w.as_bytes(), notify.take())? {
                Got::Ready => return Ok(()),
                Got::Armed => {}
                _ => return Err(Status::BadSize),
            }
            loop {
                match sys::receive(&self.channel)? {
                    sys::Received::Notification {
                        source: Source::Session,
                        label,
                        bits,
                        ..
                    } if label == key && bits & 1 != 0 => break,
                    _ => {}
                }
            }
        }
    }

    /// TAKE or CANCEL of a key the service does not know.
    fn unknown(&self, method: Method, key: u64) -> bool {
        let mut w = Writer::new();
        Key { key }.write(method, &mut w).is_ok()
            && matches!(
                self.call(w.as_bytes(), None),
                Err(Status::Kernel(abi::Error::BadState))
            )
    }

    fn cancel(&self, key: u64) -> Result<Got, Status> {
        let mut w = Writer::new();
        Key { key }.write(Method::Cancel, &mut w)?;
        self.call(w.as_bytes(), None)
    }

    /// `count` sectors of `sector` into cell 0, waited for.
    fn read_into(&self, cell_no: u32, count: u32, sector: u64) -> Result<(), Fail> {
        cell(cell_no as usize, count).fill(0xA5);
        let key = self
            .start(Method::Read, cell_no, count, sector)
            .map_err(|_| "READ refused")?;
        self.finish(key).map_err(|_| "READ failed")
    }

    /// The pattern over all its runs, four cells in flight: written, or
    /// read and compared.
    fn pattern(&self, write: bool) -> Result<u64, Fail> {
        let sectors = self.info()?.sectors;
        let mut done = 0;
        let mut batch = [(0u64, 0u32, 0u64); CELLS as usize];
        let mut n = 0;
        let flush = |n: &mut usize, batch: &[(u64, u32, u64)]| -> Result<(), Fail> {
            for (i, &(sector, count, key)) in batch[..*n].iter().enumerate() {
                self.finish(key).map_err(|_| "a pattern request failed")?;
                if !write {
                    let bytes = cell(i, count);
                    let mut want = [0u8; SECTOR];
                    for (k, got) in bytes.as_chunks::<SECTOR>().0.iter().enumerate() {
                        pattern(sector + k as u64, &mut want);
                        check(*got == want, "the pattern read back differs")?;
                    }
                }
            }
            *n = 0;
            Ok(())
        };
        for (sector, count) in runs(sectors) {
            let c = n as u32;
            let key = if write {
                for k in 0..count {
                    let at = k as usize * SECTOR;
                    pattern(sector + u64::from(k), &mut cell(n, count)[at..at + SECTOR]);
                }
                self.start(Method::Write, c, count, sector)
            } else {
                cell(n, count).fill(0xA5);
                self.start(Method::Read, c, count, sector)
            }
            .map_err(|_| "a pattern request was refused")?;
            batch[n] = (sector, count, key);
            n += 1;
            done += u64::from(count);
            if n == batch.len() {
                flush(&mut n, &batch)?;
            }
        }
        flush(&mut n, &batch)?;
        Ok(done)
    }

    fn flush_all(&self) -> Result<(), Fail> {
        let key = self.start_flush().map_err(|_| "FLUSH refused")?;
        self.finish(key).map_err(|_| "FLUSH failed")
    }

    /// The start of every mode: a session, a request before BUFFER, INFO,
    /// BUFFER, and sector 0.
    fn open(&mut self, print: bool) -> Result<(), Fail> {
        self.connect()?;
        let before = self.start(Method::Read, 0, 1, 0);
        check(
            before == Err(code(proto_blk::NO_BUFFER)),
            "a READ before BUFFER was not refused",
        )?;
        self.load_info()?;
        let info = self.info()?;
        if print {
            rt::println!("blk-probe: READ before BUFFER is NO_BUFFER");
            rt::println!(
                "blk-probe: {} sectors, block {}, {}",
                info.sectors,
                info.block,
                if info.flush() { "flush" } else { "no flush" }
            );
        }
        check(self.give()?.is_ok(), "BUFFER refused")?;
        self.read_into(0, 1, 0)
    }

    fn run(&mut self) -> Result<(), Fail> {
        self.open(true)?;
        let mark = &cell(0, 1)[..8];
        if mark == [0; 8] {
            self.write_mode()
        } else if mark == WRITTEN {
            self.check_mode()
        } else if mark == FAULTS {
            self.faults_mode()
        } else {
            Err("sector 0 has no mark of the probe")
        }
    }

    /// The refusals, with a cell in flight and a FLUSH after a write.
    fn refusals(&mut self) -> Result<(), Fail> {
        let sectors = self.info()?.sectors;
        let raw = |method: Method, cell: u32, count: u32, sector: u64| -> Result<u64, Status> {
            let mut w = Writer::new();
            method.header().write(&mut w)?;
            w.u32(cell)?;
            w.u32(count)?;
            w.u64(sector)?;
            match self.call(w.as_bytes(), None)? {
                Got::Wait(key) => Ok(key),
                _ => Err(Status::BadSize),
            }
        };
        check(
            raw(Method::Read, 0, 0, 0) == Err(Status::BadSize),
            "count 0",
        )?;
        check(
            raw(Method::Read, 0, 33, 0) == Err(Status::BadSize),
            "count 33",
        )?;
        check(
            raw(Method::Read, 4, 1, 0) == Err(code(proto_blk::INVALID)),
            "cell 4",
        )?;
        let range: Result<u64, Status> = Err(code(proto_blk::RANGE));
        check(
            raw(Method::Read, 0, 2, sectors - 1) == range,
            "past the end",
        )?;
        check(raw(Method::Write, 0, 2, u64::MAX) == range, "an overflow")?;
        check(raw(Method::Read, 0, 1, sectors) == range, "at the end")?;
        check(
            raw(Method::Read, 0, 1, sectors - 1).is_ok_and(|k| self.finish(k).is_ok()),
            "the last sector",
        )?;
        check(
            self.unknown(Method::Take, 0x1234) && self.unknown(Method::Cancel, 0x1234),
            "an unknown key",
        )?;
        rt::println!("blk-probe: bad requests are refused: counts, cell, range, keys");
        // A cell stays busy from WAIT to TAKE.
        let key = self
            .start(Method::Read, 1, 1, 0)
            .map_err(|_| "READ refused")?;
        check(
            self.start(Method::Read, 1, 1, 0) == Err(code(proto_blk::BUSY)),
            "a cell in flight took a second request",
        )?;
        self.finish(key).map_err(|_| "READ failed")?;
        check(
            self.start(Method::Read, 1, 1, 0)
                .is_ok_and(|k| self.finish(k).is_ok()),
            "a cell after TAKE was busy",
        )?;
        let again = self.give()?;
        check(again == Err(code(proto_blk::EXISTS)), "a second BUFFER")?;
        rt::println!("blk-probe: a cell in flight is BUSY, a second BUFFER is EXISTS");
        Ok(())
    }

    /// CANCEL of a read in flight, then the cell free again.
    fn cancelled(&self) -> Result<(), Fail> {
        let key = self
            .start(Method::Read, 0, 32, PATTERN_START)
            .map_err(|_| "READ refused")?;
        check(matches!(self.cancel(key), Ok(Got::Cancelled)), "CANCEL")?;
        check(self.unknown(Method::Take, key), "TAKE after CANCEL")?;
        let mut free = false;
        for _ in 0..TRIES {
            match self.start(Method::Read, 0, 1, PATTERN_START) {
                Ok(key) => {
                    self.finish(key).map_err(|_| "READ failed")?;
                    free = true;
                    break;
                }
                Err(status) if status == code(proto_blk::BUSY) => {}
                Err(_) => return Err("READ after CANCEL was refused otherwise"),
            }
        }
        check(free, "the cell never came free after CANCEL")?;
        rt::println!("blk-probe: CANCEL ended a read in flight, the cell came free");
        Ok(())
    }

    /// Sector 0 with the mark `STAFBLK1` and the sectors of the pattern.
    fn mark(&self, sectors: u64) -> Result<(), Fail> {
        let bytes = cell(0, 1);
        bytes.fill(0);
        bytes[..8].copy_from_slice(WRITTEN);
        bytes[8..16].copy_from_slice(&sectors.to_le_bytes());
        let key = self
            .start(Method::Write, 0, 1, 0)
            .map_err(|_| "WRITE refused")?;
        self.finish(key).map_err(|_| "WRITE failed")?;
        self.flush_all()
    }

    fn write_mode(&mut self) -> Result<(), Fail> {
        self.refusals()?;
        let done = self.pattern(true)?;
        rt::println!("blk-probe: {done} sectors of the pattern written, four cells in flight");
        // The data first, the flush, then the mark and its flush.
        self.flush_all()?;
        rt::println!("blk-probe: FLUSH after the writes is READY");
        self.cancelled()?;
        check(self.pattern(false)? == done, "sectors read back")?;
        rt::println!("blk-probe: {done} sectors read back and equal");
        self.speed()?;
        self.mark(done)?;
        rt::println!("blk-probe: written {done} sectors");
        Ok(())
    }

    /// 4 MiB written and read again over a stretch past the pattern, four
    /// cells in flight, the cells as they are: the time of the service, the
    /// device and the queue, without the pattern's arithmetic. The line is
    /// for the people who read the log.
    fn speed(&self) -> Result<(), Fail> {
        const FROM: u64 = 20_000;
        let run = |method: Method| -> Result<u64, Fail> {
            let began = time::ticks_to_ns(time::now());
            for batch in 0..SPEED_REQUESTS / CELLS as u64 {
                let mut keys = [0u64; CELLS as usize];
                for (i, key) in keys.iter_mut().enumerate() {
                    let sector =
                        FROM + (batch * u64::from(CELLS) + i as u64) * u64::from(SECTORS_MAX);
                    *key = self
                        .start(method, i as u32, SECTORS_MAX, sector)
                        .map_err(|_| "a request of the speed pass was refused")?;
                }
                for key in keys {
                    self.finish(key)
                        .map_err(|_| "a request of the speed pass failed")?;
                }
            }
            Ok(time::ticks_to_ns(time::now()) - began)
        };
        let wrote = run(Method::Write)?;
        self.flush_all()?;
        let read = run(Method::Read)?;
        let sectors = SPEED_REQUESTS * u64::from(SECTORS_MAX);
        rt::println!(
            "blk-probe: speed: {sectors} sectors written in {} us, read in {} us, {} in flight",
            wrote / 1000,
            read / 1000,
            CELLS
        );
        Ok(())
    }

    fn check_mode(&mut self) -> Result<(), Fail> {
        let mut want = [0u8; 8];
        want.copy_from_slice(&cell(0, 1)[8..16]);
        let sectors = u64::from_le_bytes(want);
        let done = self.pattern(false)?;
        check(
            done == sectors,
            "the sectors of the pattern differ from the mark",
        )?;
        rt::println!("blk-probe: verified {done} sectors");
        // CRASH: the service never replies, its end gives PEER_CLOSED.
        rt::println!("blk-probe: crashing blk");
        check(
            sys::send(self.service()?, &Method::Crash.header().bytes()).is_err(),
            "CRASH answered",
        )?;
        self.service = None;
        self.pause();
        self.open(false)?;
        let last = self.info()?.sectors - TAIL;
        for (sector, count) in runs(self.info()?.sectors).filter(|r| r.0 >= last) {
            self.read_into(1, count, sector)?;
            let mut want = [0u8; SECTOR];
            for (k, got) in cell(1, count).as_chunks::<SECTOR>().0.iter().enumerate() {
                pattern(sector + k as u64, &mut want);
                check(*got == want, "the tail differs after the restart")?;
            }
        }
        rt::println!("blk-probe: restarted");
        Ok(())
    }

    fn faults_mode(&mut self) -> Result<(), Fail> {
        for k in 0..32 {
            pattern(2048 + k, &mut cell(0, 32)[k as usize * SECTOR..][..SECTOR]);
        }
        let key = self
            .start(Method::Write, 0, 32, 2048)
            .map_err(|_| "WRITE refused")?;
        self.finish(key).map_err(|_| "WRITE failed")?;
        // The bucket of the host's throttle takes two writes at once, and
        // holds the third for a second.
        let key = self
            .start(Method::Write, 2, 1, 2112)
            .map_err(|_| "WRITE refused")?;
        self.finish(key).map_err(|_| "WRITE failed")?;
        let held = self
            .start(Method::Write, 1, 1, 2080)
            .map_err(|_| "WRITE refused")?;
        check(
            self.start_flush() == Err(code(proto_blk::BUSY)),
            "FLUSH with a write at the device was not BUSY",
        )?;
        self.finish(held).map_err(|_| "WRITE failed")?;
        rt::println!("blk-probe: FLUSH with a write at the device is BUSY");
        // The first flush fails on the host.
        let key = self.start_flush().map_err(|_| "FLUSH refused")?;
        check(
            self.finish(key) == Err(code(proto_blk::IO)),
            "the first FLUSH did not fail with IO",
        )?;
        rt::println!("blk-probe: a failed FLUSH is IO");
        self.flush_all()?;
        rt::println!("blk-probe: the second FLUSH is READY");
        // The first read of sector 4096 fails.
        let key = self
            .start(Method::Read, 1, 1, 4096)
            .map_err(|_| "READ refused")?;
        check(
            self.finish(key) == Err(code(proto_blk::IO)),
            "the first READ did not fail with IO",
        )?;
        rt::println!("blk-probe: a failed READ is IO");
        self.read_into(1, 1, 4096)?;
        rt::println!("blk-probe: the second READ is READY");
        rt::println!("blk-probe: faults seen");
        Ok(())
    }
}
