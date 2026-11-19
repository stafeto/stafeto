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
//! - `settle`: no request; with `STAFETO_DATA_PROBE_WAIT_S` the probe sleeps that long, so the
//!   service converts the volume at mount and walks it in the quiet, and the probe ends.
//! - `fill`: the volume that `cargo xtask data-image --fill` made (1 GiB, small and large files, a
//!   directory of 1,000 entries, 200 empty directories) and one boot has converted: the time of the
//!   first call, of the listing, of RMDIR, of the longest WRITE of a file of 8 MiB, of the removal of
//!   large files and of the free count before and after the refresh walk, one line each
//!   (`data-probe: fill ...`), then `data-probe: fill done`.
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
/// The version 3 series (`STAFETO_DATA_PROBE_V3=1`, set for the writing and the verifying boot of
/// `cargo xtask data-probe`; the crash runs leave it out, since it would move their count of sectors): the
/// record of a native client's files, a CHMOD that survives the remount, and a session that is
/// neither marked nor bound.
const V3: bool = parse(match option_env!("STAFETO_DATA_PROBE_V3") {
    Some(text) => text,
    None => "0",
}) == 1;
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
    let result = match MODE {
        "write" => write(&client, &start),
        "verify" => verify(&client),
        // The boot that converts a volume made by an older release and ends (the host then boots
        // `fill` on the converted volume): nothing to ask, the sleep is the work.
        "settle" => Ok(()),
        "fill" => measure_fill(&client, &start),
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

fn write(c: &Client, start: &rt::startup::Startup) -> Result<(), Fail> {
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
    if V3 {
        v3_write(c, start)?;
    }
    rt::println!("data-probe: finished");
    Ok(())
}

/// The stat record of `path`.
fn stat_of(c: &Client, path: &[u8]) -> Result<p::Stat, Fail> {
    let reply = wire(c.call(|w| p::path_call(Method::Stat, path, w)), "stat")?;
    wire(
        p::Stat::from_bytes(&reply.bytes[4..reply.len]),
        "the stat record",
    )
}

/// The version 3 series, on the writing boot: the files of a native client (user 0, group 0) have
/// the mode they were made with and a number each, a CHMOD changes the mode at once, and a session
/// that is neither marked nor bound answers NOT_BOUND while a BIND with a copy that is no identity
/// session answers ACCESS.
fn v3_write(c: &Client, start: &rt::startup::Startup) -> Result<(), Fail> {
    wire(c.put(b"/v3a", 100, 5), "put v3a")?;
    wire(c.put(b"/v3b", 100, 6), "put v3b")?;
    wire(c.mkdir(b"/v3d"), "mkdir v3d")?;
    let (a, b, d) = (
        stat_of(c, b"/v3a")?,
        stat_of(c, b"/v3b")?,
        stat_of(c, b"/v3d")?,
    );
    // `put` opens with 0644, MKDIR is sent with 0755; the native client is user 0 and group 0.
    if (a.mode, a.uid, a.gid) != (0o644, 0, 0) || (d.mode, d.uid, d.gid) != (0o755, 0, 0) {
        rt::println!(
            "data-probe: v3 stat {:o} {}:{} and {:o}",
            a.mode,
            a.uid,
            a.gid,
            d.mode
        );
        return Err("the record of a new file is not the mode and owner it was made with");
    }
    if a.kind != p::KIND_FILE || d.kind != p::KIND_DIRECTORY {
        return Err("the kind of a new entry is wrong");
    }
    if a.ino == 0 || b.ino == 0 || d.ino == 0 || a.ino == b.ino || a.ino == d.ino || b.ino == d.ino
    {
        rt::println!("data-probe: v3 numbers {} {} {}", a.ino, b.ino, d.ino);
        return Err("the numbers of new entries are not distinct and non-zero");
    }
    rt::println!("data-probe: v3 stat 0644 0:0 ino ok");
    // The number is kept in a file, so that the verifying boot finds the same one.
    let mut digits = [0u8; 20];
    let mut n = a.ino;
    let mut at = digits.len();
    while n > 0 || at == digits.len() {
        at -= 1;
        digits[at] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    let handle = wire(
        c.open(b"/v3ino", p::WRITE | p::CREATE | p::TRUNCATE),
        "open v3ino",
    )?;
    wire(
        c.call(|w| p::write(handle, &digits[at..], w)),
        "write v3ino",
    )?;
    wire(
        c.call(|w| p::handle_call(Method::Fsync, handle, w)),
        "fsync v3ino",
    )?;
    wire(c.close(handle), "close v3ino")?;
    wire(c.call(|w| p::chmod(b"/v3a", 0o600, w)), "chmod v3a")?;
    if stat_of(c, b"/v3a")?.mode != 0o600 {
        return Err("a CHMOD did not change the mode");
    }
    // A session of CLONE has neither the mark nor an identity: every request that names a path is
    // NOT_BOUND until BIND, and a BIND that carries a channel that is no identity session of the
    // process service is ACCESS (a table with no process service never vouches).
    let held = wire(c.open(b"/v3a", p::READ), "open v3a")?;
    let mut w = Writer::new();
    wire(p::clone(&[held], &mut w), "clone")?;
    let child = match sys::send(&c.session, w.as_bytes()) {
        Ok(mut reply) => reply
            .handles
            .take::<Channel>(0)
            .map_err(|_| "CLONE brought no session")?,
        Err(_) => return Err("CLONE failed"),
    };
    let mut w = Writer::new();
    wire(p::path_call(Method::Stat, b"/v3a", &mut w), "stat request")?;
    let said = sys::send(&child, w.as_bytes())
        .map(|r| {
            let mut buffer = [0u8; MESSAGE_MAX];
            p::reply(r.bytes(&mut buffer)).err()
        })
        .map_err(|_| "no answer from the cloned session")?;
    if said != Some(Status::Unknown(p::NOT_BOUND)) {
        rt::println!("data-probe: unbound session said {said:?}");
        return Err("a session with no mark and no BIND was not refused with NOT_BOUND");
    }
    let level = sys::thread_info(&start.thread).map_or(1, |info| info.base);
    let foreign = sys::channel_create(level).map_err(|_| "no channel for the copy")?;
    let bind = proto_wire::Header::new(Method::Bind.number(), p::VERSION).bytes();
    let said = match sys::send_handles(&child, &bind, [foreign.erase()]) {
        Ok(r) => {
            let mut buffer = [0u8; MESSAGE_MAX];
            p::reply(r.bytes(&mut buffer)).err()
        }
        Err(_) => return Err("no answer to BIND"),
    };
    if said != Some(Status::Unknown(p::ACCESS)) {
        rt::println!("data-probe: bind with a foreign copy said {said:?}");
        return Err("a BIND with a copy that is no identity session was not ACCESS");
    }
    rt::println!("data-probe: unbound session refused ok");
    Ok(())
}

/// The version 3 series, on the verifying boot: the mode a CHMOD set and the number an entry got
/// are there after the remount.
fn v3_verify(c: &Client) -> Result<(), Fail> {
    let a = stat_of(c, b"/v3a")?;
    let number = wire(c.number(b"/v3ino"), "read v3ino")?;
    if (a.mode, a.uid, a.gid) != (0o600, 0, 0) {
        rt::println!(
            "data-probe: v3 after the remount {:o} {}:{}",
            a.mode,
            a.uid,
            a.gid
        );
        return Err("the mode a CHMOD set did not survive the remount");
    }
    if number != Some(a.ino as u32) || a.ino > u64::from(u32::MAX) {
        return Err("the number of an entry changed over the remount");
    }
    rt::println!("data-probe: chmod survives a remount ok");
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
    if V3 {
        v3_verify(c)?;
    }
    rt::println!("data-probe: verify ok progress={done} files={files}");
    Ok(())
}

/// Microseconds since the counter started.
fn now_us() -> u64 {
    rt::time::ticks_to_ns(rt::time::now()) / 1000
}

/// The free blocks and the total of STATFS.
fn statfs(c: &Client) -> Result<(u64, u64), Fail> {
    let reply = wire(c.call(p::statfs), "statfs")?;
    let pair = |at: usize| u64::from(reply.word(at)) | u64::from(reply.word(at + 4)) << 32;
    Ok((pair(0), pair(8)))
}

/// How long the probe keeps quiet after its removals: the service starts the refresh walk 2 s after
/// its queue is empty, and a request that comes during the walk stops it (the reader does not wait
/// for the walk's end: the request walks by itself), so the probe stays silent for the walk of a
/// volume this full at the slowest device the bounds allow (60 s) and a little more.
const QUIET_FOR_REFRESH_NS: u64 = 65_000_000_000;

/// The lines of `fill` (see the head of the file): each is one measurement of the service on a volume
/// of 1 GiB that is mostly full. The times are the client's, from the send to the reply.
fn measure_fill(c: &Client, start: &rt::startup::Startup) -> Result<(), Fail> {
    let at = now_us();
    let (blocks, free) = statfs(c)?;
    rt::println!(
        "data-probe: fill first call {} us, {blocks} blocks, {free} free",
        now_us() - at
    );
    // The listing of a directory of 1,000 entries, as the loop of a client reads it.
    let dir = wire(c.open(b"/rd", p::DIRECTORY | p::READ), "open /rd")?;
    let (begun, mut calls, mut entries, mut longest) = (now_us(), 0u32, 0u32, 0u64);
    let mut more = true;
    while more {
        let at = now_us();
        let reply = wire(
            c.call(|w| p::handle_call(Method::Readdir, dir, w)),
            "readdir",
        )?;
        longest = longest.max(now_us() - at);
        calls += 1;
        let mut batch = wire(
            p::read_dir_reply(proto_wire::Reader::new(&reply.bytes[4..reply.len])),
            "listing",
        )?;
        more = batch.more;
        while wire(batch.next_entry(), "entry")?.is_some() {
            entries += 1;
        }
    }
    rt::println!(
        "data-probe: fill readdir {entries} entries in {calls} calls, total {} us, longest {longest} us",
        now_us() - begun
    );
    wire(c.close(dir), "close /rd")?;
    // RMDIR of an empty directory in a volume of 200 of them and more.
    let at = now_us();
    wire(
        c.call(|w| p::path_call(Method::Rmdir, b"/rm/e0", w)),
        "rmdir",
    )?;
    rt::println!("data-probe: fill rmdir {} us", now_us() - at);
    // The rest of the empty directories, the oldest first: a `rm -rf` of 199 directories, each of
    // which looks the pair before it up in the list of every pair of the volume.
    let begun = now_us();
    for n in 1..200u32 {
        let mut name = [0u8; 16];
        name[..6].copy_from_slice(b"/rm/e");
        let mut digits = [0u8; 4];
        let d = decimal(n, &mut digits);
        name[5..5 + d].copy_from_slice(&digits[..d]);
        wire(
            c.call(|w| p::path_call(Method::Rmdir, &name[..5 + d], w)),
            "rmdir e",
        )?;
    }
    rt::println!(
        "data-probe: fill rm -rf 199 directories {} us",
        now_us() - begun
    );
    // A file of 8 MiB written in the largest writes: the longest call is the walk or the compaction
    // that the window and the pairs of the volume take inside one request.
    let handle = wire(
        c.open(b"/fill-out", p::WRITE | p::CREATE | p::TRUNCATE),
        "open fill-out",
    )?;
    let chunk = [0x5au8; p::MAX_WRITE];
    let (begun, mut longest, mut wrote, mut calls) = (now_us(), 0u64, 0usize, 0u32);
    while wrote < 8 << 20 {
        let at = now_us();
        let n = wire(c.call(|w| p::write(handle, &chunk, w)), "write")?.word(0) as usize;
        longest = longest.max(now_us() - at);
        if n == 0 {
            return Err("a write took nothing");
        }
        wrote += n;
        calls += 1;
    }
    wire(
        c.call(|w| p::handle_call(Method::Fsync, handle, w)),
        "fsync",
    )?;
    wire(c.close(handle), "close fill-out")?;
    rt::println!(
        "data-probe: fill write {wrote} bytes in {calls} calls, total {} us, longest call {longest} us",
        now_us() - begun
    );
    // Large files removed: 24 of 16 MiB are 384 MiB, over a sixteenth of the volume, so the service
    // walks again in the quiet after the removals and the free count of STATFS catches up.
    let (_, before) = statfs(c)?;
    let (begun, mut longest) = (now_us(), 0u64);
    for b in 0..24u32 {
        let mut name = [0u8; 16];
        name[..6].copy_from_slice(b"/big/b");
        let mut digits = [0u8; 4];
        let d = decimal(b, &mut digits);
        name[6..6 + d].copy_from_slice(&digits[..d]);
        let at = now_us();
        wire(c.unlink(&name[..6 + d]), "unlink big")?;
        longest = longest.max(now_us() - at);
    }
    rt::println!(
        "data-probe: fill unlink 24 files of 16 MiB, total {} us, longest {longest} us",
        now_us() - begun
    );
    let (_, low) = statfs(c)?;
    let level = sys::thread_info(&start.thread).map_or(1, |info| info.base);
    sleep(level, QUIET_FOR_REFRESH_NS);
    let (_, after) = statfs(c)?;
    rt::println!(
        "data-probe: fill free blocks {before} before the removals, {low} right after, {after} after the quiet"
    );
    rt::println!("data-probe: fill done");
    Ok(())
}
