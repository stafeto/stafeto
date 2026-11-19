// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The guest probe of the data file service (`datafs`, services/datafs), a client of init. Its mode
//! is fixed when it is built (`STAFETO_DATA_PROBE_MODE`):
//!
//! - `write`: a series of 12 steps on the volume, each of them durable before the next: a file made
//!   under a temporary name, written, synced, renamed to its name (every fourth step also removes a file
//!   of an earlier step), and the number of the step written into `/progress` the same way, after which
//!   the line `data-probe: synced N` goes out. Then `data-probe: written` and a STATFS, for the host
//!   that cuts the power in the middle of this series (`cargo xtask data-crash`).
//! - `load`: the file load of the frame-time probe (`frame_load::phases`): from the start of
//!   the first phase that has it to the end of the last, files of 64 KiB written under a
//!   temporary name, synced, renamed over the old file of the slot, and removed, round after
//!   round, one operation at a time (`frame_load::loads::file_op`); the files it made go when
//!   it stops. It takes its mode from the record's own arguments (`load`), where the other
//!   modes are fixed at the build. Every call of the load is one of the `Client`'s methods
//!   below, so a change of the protocol touches those and not the load.
//! - `verify`: the tree a cut left, or a clean run left. `/progress` says the last step whose line
//!   went out or the one after it (`STAFETO_DATA_PROBE_MIN` is the last line the host saw: the steps
//!   it names must all be there). Every file of the tree is whole (the bytes its name says, no
//!   torn file), the files of the steps up to the progress are there, those of the steps that
//!   removed them are gone, and a file of a step past the next is not there. A write and a read of one
//!   more file shows the volume takes the next writes. With `STAFETO_DATA_PROBE_WAIT_S` set the probe
//!   first sleeps that many seconds before it sends any request: the service walks the volume
//!   once its queue has been quiet for 2 s, and the host then finds the line of that walk (with its
//!   reads and time) before the probe's own requests.

#![no_std]
#![no_main]

use abi::{MESSAGE_MAX, Source};
use proto_data as p;
use proto_data::Method;
use proto_wire::{Status, Writer};
use rt::handle::{Channel, Resource};
use rt::sys::Received;
use rt::{Handle, sys};

rt::entry!(main);

const MODE: &str = match option_env!("STAFETO_DATA_PROBE_MODE") {
    Some(mode) => mode,
    None => "write",
};
/// The seconds the probe sleeps before its first request, 0 for none (`STAFETO_DATA_PROBE_WAIT_S`).
const WAIT_S: u64 = parse(match option_env!("STAFETO_DATA_PROBE_WAIT_S") {
    Some(text) => text,
    None => "0",
}) as u64;
/// The last step the host saw the line of, in a `verify` that follows a cut.
const MIN: u32 = parse(match option_env!("STAFETO_DATA_PROBE_MIN") {
    Some(text) => text,
    None => "0",
});
/// 1 when the series ran to its end before the cut (so every step must be there).
const STEPS: u32 = 12;

const fn parse(text: &str) -> u32 {
    let (bytes, mut n, mut i) = (text.as_bytes(), 0u32, 0);
    while i < bytes.len() {
        n = n * 10 + (bytes[i] - b'0') as u32;
        i += 1;
    }
    n
}

type Fail = &'static str;

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    let Ok(session) = rt::service::connect(&start.parent, "datafs") else {
        rt::println!("data-probe: failed: no session with datafs");
        return 2;
    };
    let client = Client { session };
    // The wait is 0 in a build that names none.
    #[allow(clippy::absurd_extreme_comparisons)]
    let waits = WAIT_S > 0;
    if waits {
        let level = sys::thread_info(&start.thread).map_or(1, |info| info.base);
        sleep(level, WAIT_S * 1_000_000_000);
        rt::println!("data-probe: waited {WAIT_S} s");
    }
    let own = proto_init::ServiceArgs::read(start.args()).map_or(&[][..], |a| a.own);
    let mode = if own.is_empty() {
        MODE
    } else {
        core::str::from_utf8(own).unwrap_or("")
    };
    let result = match mode {
        "load" => {
            let level = sys::thread_info(&start.thread).map_or(1, |info| info.base);
            load(&client, level)
        }
        "write" => write(&client),
        "verify" => verify(&client),
        _ => Err("unknown mode"),
    };
    match result {
        Ok(()) => 0,
        Err(reason) => {
            rt::println!("data-probe: failed: {reason}");
            2
        }
    }
}

/// Sleeps `ns` nanoseconds: a timer on a channel of its own, and the wait for its notification.
fn sleep(level: u8, ns: u64) {
    let Ok(channel) = sys::channel_create(level) else {
        return;
    };
    let Ok(timer) = sys::timer_create(&channel, level) else {
        return;
    };
    let until = rt::time::ticks_to_ns(rt::time::now()) + ns;
    if sys::timer_set(&timer, until).is_err() {
        return;
    }
    loop {
        match sys::receive(&channel) {
            Ok(Received::Notification {
                source: Source::Timer,
                ..
            }) if rt::time::reached(until) => return,
            Ok(_) => {}
            Err(_) => return,
        }
    }
}

struct Client {
    session: Handle<Channel>,
}

/// A reply: its bytes after the status.
struct Reply {
    bytes: [u8; MESSAGE_MAX],
    len: usize,
}

impl Reply {
    fn word(&self, at: usize) -> u32 {
        u32::from_le_bytes(self.bytes[4 + at..8 + at].try_into().unwrap_or([0; 4]))
    }
}

impl Client {
    fn call(&self, build: impl FnOnce(&mut Writer) -> Result<(), Status>) -> Result<Reply, Status> {
        let mut w = Writer::new();
        build(&mut w)?;
        let reply = sys::send(&self.session, w.as_bytes())?;
        let mut out = Reply {
            bytes: [0; MESSAGE_MAX],
            len: 0,
        };
        let bytes = reply.bytes(&mut out.bytes);
        out.len = bytes.len();
        p::reply(&out.bytes[..out.len])?;
        Ok(out)
    }

    fn open(&self, path: &[u8], flags: u32) -> Result<u32, Status> {
        Ok(self.call(|w| p::open(path, flags, 0o644, w))?.word(0))
    }

    fn close(&self, handle: u32) -> Result<(), Status> {
        self.call(|w| p::handle_call(Method::Close, handle, w))
            .map(drop)
    }

    fn mkdir(&self, path: &[u8]) -> Result<(), Status> {
        self.call(|w| p::mkdir(path, 0o755, w)).map(drop)
    }

    fn unlink(&self, path: &[u8]) -> Result<(), Status> {
        self.call(|w| p::path_call(Method::Unlink, path, w))
            .map(drop)
    }

    fn rename(&self, from: &[u8], to: &[u8]) -> Result<(), Status> {
        self.call(|w| p::rename(from, to, w)).map(drop)
    }

    /// A file made whole: created or truncated, written, synced, closed.
    fn put(&self, path: &[u8], len: usize, salt: u32) -> Result<(), Status> {
        let handle = self.open(path, p::WRITE | p::CREATE | p::TRUNCATE)?;
        let mut at = 0;
        let mut chunk = [0u8; 900];
        while at < len {
            let n = (len - at).min(chunk.len());
            fill(&mut chunk[..n], at, salt);
            let wrote = self.call(|w| p::write(handle, &chunk[..n], w))?.word(0) as usize;
            if wrote != n {
                return Err(Status::BadSize);
            }
            at += n;
        }
        self.call(|w| p::handle_call(Method::Fsync, handle, w))?;
        self.close(handle)
    }

    /// The whole file, compared to the bytes its salt says; Ok(false) when they differ.
    fn matches(&self, handle: u32, len: usize, salt: u32) -> Result<bool, Status> {
        let mut at = 0;
        let mut expected = [0u8; p::MAX_READ];
        loop {
            let reply = self.call(|w| p::read(handle, p::MAX_READ as u32, w))?;
            let n = reply.word(0) as usize;
            if n == 0 {
                return Ok(at == len);
            }
            if at + n > len {
                return Ok(false);
            }
            fill(&mut expected[..n], at, salt);
            if reply.bytes[8..8 + n] != expected[..n] {
                return Ok(false);
            }
            at += n;
        }
    }

    /// The whole file as a number in decimal (the progress file).
    fn number(&self, path: &[u8]) -> Result<Option<u32>, Status> {
        let handle = match self.open(path, p::READ) {
            Ok(handle) => handle,
            Err(Status::Unknown(p::NO_ENTRY)) => return Ok(None),
            Err(status) => return Err(status),
        };
        let reply = self.call(|w| p::read(handle, 32, w))?;
        let n = reply.word(0) as usize;
        let mut value = 0u32;
        for &b in &reply.bytes[8..8 + n] {
            if !b.is_ascii_digit() {
                self.close(handle)?;
                return Ok(Some(u32::MAX));
            }
            value = value * 10 + u32::from(b - b'0');
        }
        self.close(handle)?;
        Ok(Some(if n == 0 { u32::MAX } else { value }))
    }
}

/// The bytes of a file of the series: from the offset and the step's salt.
fn fill(out: &mut [u8], offset: usize, salt: u32) {
    for (i, b) in out.iter_mut().enumerate() {
        let k = offset + i;
        *b = (k as u32)
            .wrapping_mul(31)
            .wrapping_add(salt)
            .wrapping_add((k >> 8) as u32) as u8;
    }
}

/// The length of the file of step `j`.
fn length(j: u32) -> usize {
    300 + j as usize * 1700
}

/// The name `/w/f<j>`.
fn name(j: u32, out: &mut [u8; 16]) -> usize {
    let digits = if j >= 10 { 2 } else { 1 };
    out[..4].copy_from_slice(b"/w/f");
    let mut v = j;
    for i in (0..digits).rev() {
        out[4 + i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    4 + digits
}

fn decimal(j: u32, out: &mut [u8; 4]) -> usize {
    let digits = if j >= 10 { 2 } else { 1 };
    let mut v = j;
    for i in (0..digits).rev() {
        out[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    digits
}

fn wire<T>(r: Result<T, Status>, why: Fail) -> Result<T, Fail> {
    r.map_err(|status| {
        rt::println!("data-probe: {why}: status {}", status.code());
        why
    })
}

/// A step is removed by the step 3 after it when that is a multiple of 4.
fn removes(k: u32) -> Option<u32> {
    (k % 4 == 1).then_some(k + 3)
}

/// The file load: see the header.
fn load(c: &Client, level: u8) -> Result<(), Fail> {
    use frame_load::loads::{self, FILE_BYTES, FileOp};
    use frame_load::phases::Schedule;
    let schedule = Schedule::DEFAULT;
    let now = || rt::time::ticks_to_ns(rt::time::now());
    match c.mkdir(loads::DIRECTORY) {
        Ok(()) | Err(Status::Unknown(p::EXISTS)) => {}
        Err(_) => return Err("mkdir /load"),
    }
    let first = schedule
        .next_wanted(0, |p| p.loads().files)
        .ok_or("no phase has the file load")?;
    let wait = schedule.start_of(first).saturating_sub(now());
    sleep(level, wait);
    let (mut ops, mut bytes) = (0u64, 0u64);
    while schedule.at(now()).is_some_and(|p| p.loads().files) {
        match loads::file_op(ops) {
            FileOp::Write { salt, .. } => {
                wire(c.put(loads::TEMPORARY, FILE_BYTES, salt), "put tmp")?;
                bytes += FILE_BYTES as u64;
            }
            FileOp::Rename { slot } => {
                let mut n = [0u8; 16];
                let len = loads::slot_name(slot, &mut n);
                wire(c.rename(loads::TEMPORARY, &n[..len]), "rename tmp")?;
            }
            FileOp::Delete { slot } => {
                let mut n = [0u8; 16];
                let len = loads::slot_name(slot, &mut n);
                match c.unlink(&n[..len]) {
                    Ok(()) | Err(Status::Unknown(p::NO_ENTRY)) => {}
                    Err(_) => return Err("unlink"),
                }
            }
        }
        ops += 1;
    }
    // What the load made goes: a file of a slot and a temporary one the stop
    // came in the middle of.
    for slot in 0..loads::SLOTS {
        let mut n = [0u8; 16];
        let len = loads::slot_name(slot, &mut n);
        let _ = c.unlink(&n[..len]);
    }
    let _ = c.unlink(loads::TEMPORARY);
    rt::println!("data-probe: load ops {ops} bytes {bytes}");
    Ok(())
}

fn write(c: &Client) -> Result<(), Fail> {
    match c.mkdir(b"/w") {
        Ok(()) | Err(Status::Unknown(p::EXISTS)) => {}
        Err(_) => return Err("mkdir /w"),
    }
    for j in 1..=STEPS {
        wire(c.put(b"/w/tmp", length(j), j), "put tmp")?;
        let mut n = [0u8; 16];
        let len = name(j, &mut n);
        wire(c.rename(b"/w/tmp", &n[..len]), "rename tmp")?;
        if j % 4 == 0 {
            let len = name(j - 3, &mut n);
            wire(c.unlink(&n[..len]), "unlink")?;
        }
        let mut digits = [0u8; 4];
        let d = decimal(j, &mut digits);
        let handle = wire(
            c.open(b"/progress.tmp", p::WRITE | p::CREATE | p::TRUNCATE),
            "open progress",
        )?;
        wire(
            c.call(|w| p::write(handle, &digits[..d], w)),
            "write progress",
        )?;
        wire(
            c.call(|w| p::handle_call(Method::Fsync, handle, w)),
            "fsync progress",
        )?;
        wire(c.close(handle), "close progress")?;
        wire(c.rename(b"/progress.tmp", b"/progress"), "rename progress")?;
        rt::println!("data-probe: synced {j}");
    }
    rt::println!("data-probe: written");
    wire(c.call(p::statfs), "statfs")?;
    rt::println!("data-probe: finished");
    Ok(())
}

fn verify(c: &Client) -> Result<(), Fail> {
    let progress = wire(c.number(b"/progress"), "read progress")?;
    let done = match progress {
        None => 0,
        Some(u32::MAX) => return Err("the progress file is not a number"),
        Some(n) => n,
    };
    // The minimum is 0 in a build that names none.
    #[allow(clippy::absurd_extreme_comparisons)]
    let lost = done < MIN;
    if lost {
        rt::println!(
            "data-probe: progress {done} is behind the step {MIN} that was reported synced"
        );
        return Err("a synced step is lost");
    }
    if done > STEPS {
        return Err("the progress is past the last step");
    }
    // The tree: every name is known and every file whole.
    let dir = match c.open(b"/w", p::DIRECTORY | p::READ) {
        Ok(handle) => handle,
        // Nothing of the series is there yet: the cut came before the first step was durable.
        Err(_) if done == 0 => 0,
        Err(_) => return Err("the directory /w is lost"),
    };
    let mut present = [false; STEPS as usize + 2];
    let mut files = 0;
    if dir != 0 {
        let mut more = true;
        while more {
            let reply = wire(
                c.call(|w| p::handle_call(Method::Readdir, dir, w)),
                "readdir",
            )?;
            let mut batch = wire(
                p::read_dir_reply(proto_wire::Reader::new(&reply.bytes[4..reply.len])),
                "listing",
            )?;
            more = batch.more;
            while let Some(entry) = wire(batch.next_entry(), "entry")? {
                let (kind, name) = (entry.kind, entry.name);
                if name == b"." || name == b".." {
                    continue;
                }
                let mut path = [0u8; 32];
                path[..3].copy_from_slice(b"/w/");
                path[3..3 + name.len()].copy_from_slice(name);
                let path = &path[..3 + name.len()];
                if kind != p::KIND_FILE {
                    return Err("a directory in /w");
                }
                let stat = wire(c.call(|w| p::path_call(Method::Stat, path, w)), "stat")?;
                let size = wire(
                    p::Stat::from_bytes(&stat.bytes[4..stat.len]),
                    "the stat record",
                )?
                .size as usize;
                files += 1;
                if name == b"tmp" {
                    // Created with nothing written, or whole: the length of some step.
                    let handle = wire(c.open(path, p::READ), "open tmp")?;
                    let mut whole = size == 0;
                    for j in 1..=STEPS {
                        whole |= size == length(j) && wire(c.matches(handle, size, j), "read tmp")?;
                        if whole {
                            break;
                        }
                        wire(c.call(|w| p::seek(handle, 0, p::SEEK_SET, w)), "seek tmp")?;
                    }
                    wire(c.close(handle), "close tmp")?;
                    if !whole {
                        return Err("a torn tmp file");
                    }
                    continue;
                }
                let Some(j) = name
                    .strip_prefix(b"f")
                    .and_then(|d| core::str::from_utf8(d).ok())
                    .and_then(|d| d.parse::<u32>().ok())
                    .filter(|j| (1..=STEPS).contains(j))
                else {
                    return Err("a file of no step");
                };
                if j > done + 1 {
                    return Err("a file of a step that was not done");
                }
                if size != length(j) {
                    return Err("a file of the wrong length");
                }
                let handle = wire(c.open(path, p::READ), "open file")?;
                let whole = wire(c.matches(handle, size, j), "read file")?;
                wire(c.close(handle), "close file")?;
                if !whole {
                    return Err("a torn file");
                }
                present[j as usize] = true;
            }
        }
        wire(c.close(dir), "close /w")?;
    }
    for k in 1..=done.min(STEPS) {
        let gone = removes(k).is_some_and(|step| step <= done);
        let may_be_gone = removes(k).is_some_and(|step| step == done + 1);
        if gone && present[k as usize] {
            return Err("a file that a done step removed");
        }
        if !gone && !may_be_gone && !present[k as usize] {
            return Err("a file of a done step is gone");
        }
    }
    // The volume takes the next write.
    wire(c.put(b"/after", 5000, 77), "put after")?;
    let handle = wire(c.open(b"/after", p::READ), "open after")?;
    if !wire(c.matches(handle, 5000, 77), "read after")? {
        return Err("the file written after the cut reads back wrong");
    }
    wire(c.close(handle), "close after")?;
    rt::println!("data-probe: verify ok progress={done} files={files}");
    Ok(())
}
