// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `/proc` for the programs that read it (BusyBox `ps`): read only, in the
//! shape Linux gives it, and made from the process service's List.
//!
//! The directory `/proc` is a directory of the image. What lies under it
//! has no file in the file service: `/proc/<pid>/stat`, `cmdline` and
//! `status` and `/proc/uptime` are text made at the open of the path and
//! handed over as the read end of a pipe whose write end is closed, so the
//! descriptor reads, polls, is inherited and closes like any other; the
//! listing of `/proc` (`getdents`) names the live PIDs, and `stat` of
//! `/proc/<pid>` gives the directory of a process, owned by its effective
//! user. A path to open for writing, or to create, is EROFS.
//!
//! `/proc/mounts` lists the mounted file systems in the shape Linux gives
//! them (`getmntent` reads it, for `df`). A path reaches `/proc` by its
//! absolute form: the current directory and the dots and slashes of the
//! path are applied first (`absolute`), so `./proc/1` from `/` and
//! `/etc/../proc/1` name the same node as `/proc/1`.

use crate::constants::{
    EINVAL, EIO, EMFILE, ENOENT, O_ACCMODE, O_CLOEXEC, O_CLOFORK, O_CREAT, O_DIRECTORY, O_TRUNC,
};
use core::fmt::Write;
use proto_fs::{NodeInfo, Timestamp};
use proto_process::Listing;

const EROFS: i32 = 30;
const ENOTDIR: i32 = 20;
/// Processes the service lists, at most.
const PROCESSES: usize = proto_process::RECORDS;
/// The device number `stat` gives for the nodes of `/proc` (the ASCII of
/// "proc").
const DEVICE: u64 = 0x7072_6f63;

/// What a path under `/proc` names.
enum Node {
    /// `/proc/<pid>`.
    Process(u32),
    /// `/proc/<pid>/stat`, `cmdline` or `status`.
    File(u32, File),
    /// `/proc/uptime`.
    Uptime,
    /// `/proc/mounts`.
    Mounts,
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum File {
    Stat,
    Cmdline,
    Status,
}

/// The node a path under `/proc` names, if it is one of these. The path is
/// absolute and the part after "/proc/" is not empty.
fn parse(path: &[u8]) -> Option<Node> {
    let rest = path.strip_prefix(b"/proc/")?;
    let rest = rest.strip_suffix(b"/").unwrap_or(rest);
    if rest == b"uptime" {
        return Some(Node::Uptime);
    }
    if rest == b"mounts" {
        return Some(Node::Mounts);
    }
    let (number, tail) = match rest.iter().position(|&b| b == b'/') {
        Some(at) => (&rest[..at], Some(&rest[at + 1..])),
        None => (rest, None),
    };
    if number.is_empty() || number.len() > 10 || !number.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let pid = core::str::from_utf8(number).ok()?.parse::<u32>().ok()?;
    match tail {
        None => Some(Node::Process(pid)),
        Some(b"stat") => Some(Node::File(pid, File::Stat)),
        Some(b"cmdline") => Some(Node::File(pid, File::Cmdline)),
        Some(b"status") => Some(Node::File(pid, File::Status)),
        Some(_) => None,
    }
}

/// Whether a path is under `/proc` (not `/proc` itself, with or without a
/// slash at its end: the image's directory serves those).
pub fn is_under(path: &[u8]) -> bool {
    path.len() > b"/proc/".len() && path.starts_with(b"/proc/")
}

/// A path in its absolute form: made against the current directory, then
/// simplified (`posix_path::simplify`).
pub struct Absolute {
    bytes: [u8; crate::names::MAX_PATH + 1],
    length: usize,
}

impl Absolute {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    /// Whether the path names a node under `/proc`.
    pub fn is_under(&self) -> bool {
        is_under(self.bytes())
    }

    /// Whether the path is the directory `/proc` itself.
    pub fn is_proc(&self) -> bool {
        matches!(self.bytes(), b"/proc" | b"/proc/")
    }
}

/// The absolute form of `path`, if it can be made (an empty path, a path
/// too long or one with a NUL byte has none: the file service answers it).
pub fn absolute(path: &[u8]) -> Option<Absolute> {
    let resolved =
        crate::shared::with_files(|files| files.resolve(path).map_err(crate::error)).ok()?;
    let mut out = Absolute {
        bytes: [0; crate::names::MAX_PATH + 1],
        length: 0,
    };
    out.length = posix_path::simplify(resolved.as_bytes(), &mut out.bytes);
    Some(out)
}

/// The process `pid` in the service's table: its record is `pid % RECORDS`,
/// and the first live record from that index is the record itself when it
/// is live, so one request answers.
fn find(pid: u32) -> Result<Listing, i32> {
    let (_, found) = crate::process::list(pid % PROCESSES as u32)?;
    found.filter(|l| l.pid == pid).ok_or(ENOENT)
}

/// The live PIDs, in the order of the table: how many went into `pids`.
pub fn pids(pids: &mut [u32; PROCESSES]) -> Result<usize, i32> {
    let (mut cursor, mut count) = (0, 0);
    loop {
        let (next, found) = crate::process::list(cursor)?;
        if let Some(listing) = found
            && count < PROCESSES
        {
            pids[count] = listing.pid;
            count += 1;
        }
        match next {
            Some(next) => cursor = next,
            None => return Ok(count),
        }
    }
}

/// The text in a fixed buffer.
struct Text {
    bytes: [u8; 512],
    len: usize,
}

impl Write for Text {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let room = self.bytes.len() - self.len;
        let n = s.len().min(room);
        self.bytes[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

impl Text {
    fn new() -> Self {
        Self {
            bytes: [0; 512],
            len: 0,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        let room = self.bytes.len() - self.len;
        let n = bytes.len().min(room);
        self.bytes[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
    }
}

fn name_of(l: &Listing) -> &str {
    let end = l.name.iter().position(|&b| b == 0).unwrap_or(l.name.len());
    match core::str::from_utf8(&l.name[..end]) {
        Ok(name) if !name.is_empty() => name,
        _ => "?",
    }
}

fn state_letter(l: &Listing) -> char {
    match l.state {
        1 => 'T',
        2 => 'Z',
        _ => 'R',
    }
}

/// The terminal as Linux's tty_nr: the console is device 5,1, a PTY 136,n.
fn tty_nr(l: &Listing) -> u32 {
    match l.tty {
        0 => 0,
        1 => (5 << 8) | 1,
        n => (136 << 8) | ((n - 2) & 0xff),
    }
}

fn content(node: &Node) -> Result<Text, i32> {
    let mut text = Text::new();
    match *node {
        Node::Uptime => {
            let ns = rt::time::ticks_to_ns(rt::time::now());
            let _ = writeln!(
                text,
                "{}.{:02} 0.00",
                ns / 1_000_000_000,
                (ns / 10_000_000) % 100
            );
        }
        Node::File(pid, kind) => {
            let l = find(pid)?;
            match kind {
                File::Stat => {
                    // pid (comm) state ppid pgrp session tty_nr tpgid flags
                    // minflt cminflt majflt cmajflt utime stime cutime cstime
                    // priority nice num_threads itrealvalue starttime vsize rss
                    let _ = writeln!(
                        text,
                        "{} ({}) {} {} {} {} {} {} 0 0 0 0 0 {} 0 0 0 {} {} 1 0 0 0 0",
                        l.pid,
                        name_of(&l),
                        state_letter(&l),
                        l.parent,
                        l.pgid,
                        l.sid,
                        tty_nr(&l),
                        l.pgid,
                        // utime in clock ticks of 100 a second: all the time
                        // is user time.
                        rt::time::ticks_to_ns(l.ticks) / 10_000_000,
                        20 + l.nice,
                        l.nice,
                    );
                }
                File::Cmdline => {
                    // The name the program has; nothing for a process that
                    // was not started from a file.
                    if l.name[0] != 0 {
                        let end = l.name.iter().position(|&b| b == 0).unwrap_or(l.name.len());
                        text.push(&l.name[..end]);
                        text.push(&[0]);
                    }
                }
                File::Status => {
                    let _ = write!(
                        text,
                        "Name:\t{}\nState:\t{}\nPid:\t{}\nPPid:\t{}\nUid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\n",
                        name_of(&l),
                        state_letter(&l),
                        l.pid,
                        l.parent,
                        l.uid,
                        l.euid,
                        l.euid,
                        l.euid,
                        l.gid,
                        l.egid,
                        l.egid,
                        l.egid,
                    );
                }
            }
        }
        Node::Mounts => {
            // The root of the image is the file service's; /proc is this.
            let _ = write!(text, "ramfs / ramfs rw 0 0\nproc /proc proc ro 0 0\n");
        }
        Node::Process(_) => return Err(EINVAL),
    }
    Ok(text)
}

/// Opens a path under `/proc`: the read end of a pipe holding the text.
/// ENOENT for a name that is none of those above or a process that is gone,
/// EROFS to write or create, ENOTDIR for a directory flag on a file.
pub fn open(path: &[u8], flags: i32) -> Result<i32, i32> {
    let node = parse(path).ok_or(ENOENT)?;
    if flags & O_ACCMODE != 0 || flags & (O_CREAT | O_TRUNC) != 0 {
        return Err(EROFS);
    }
    if let Node::Process(pid) = node {
        // The directory of a process: a descriptor of the image's /proc
        // that remembers whose files `getdents` lists.
        find(pid)?;
        return open_directory(pid, flags);
    }
    if flags & O_DIRECTORY != 0 {
        return Err(ENOTDIR);
    }
    let text = content(&node)?;
    let ends = crate::pipe2(flags & (O_CLOEXEC | O_CLOFORK))?;
    let written = crate::write(ends[1], &text.bytes[..text.len]);
    let _ = crate::close(ends[1]);
    match written {
        Ok(n) if n == text.len => Ok(ends[0]),
        Ok(_) => {
            let _ = crate::close(ends[0]);
            Err(EIO)
        }
        Err(errno) => {
            let _ = crate::close(ends[0]);
            Err(if errno == EMFILE { EMFILE } else { errno })
        }
    }
}

/// A descriptor of the directory `/proc` of the image, which `getdents`
/// lists as the directory of `pid` (see `directory_pid`).
fn open_directory(pid: u32, flags: i32) -> Result<i32, i32> {
    use posix_fs::Target;
    let fd = crate::open_image(b"/proc", flags | O_DIRECTORY, 0, 0)?;
    let named = crate::shared::held(fd as u32, |_, target| match target {
        Target::Ram(ram) => Ok((ram.description_slot(), ram.generation())),
        _ => Err(EIO),
    });
    match named {
        Ok((slot, generation)) => {
            remember(slot, generation, pid);
            Ok(fd)
        }
        Err(errno) => {
            let _ = crate::close(fd);
            Err(errno)
        }
    }
}

/// How many directories of processes stay open at once with their PID; an
/// older one beyond that lists `/proc` itself.
const DIRECTORIES: usize = 8;
/// The directories of processes that are open: the description of the
/// image's `/proc` (its slot and generation in the file service) and the
/// PID, `0` for a free place. A spin flag guards the places.
static DIRECTORY_BUSY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static DIRECTORY_SLOT: [core::sync::atomic::AtomicU32; DIRECTORIES] =
    [const { core::sync::atomic::AtomicU32::new(0) }; DIRECTORIES];
static DIRECTORY_GENERATION: [core::sync::atomic::AtomicU64; DIRECTORIES] =
    [const { core::sync::atomic::AtomicU64::new(0) }; DIRECTORIES];
static DIRECTORY_PID: [core::sync::atomic::AtomicU32; DIRECTORIES] =
    [const { core::sync::atomic::AtomicU32::new(0) }; DIRECTORIES];
static DIRECTORY_NEXT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn directories<R>(run: impl FnOnce() -> R) -> R {
    use core::sync::atomic::Ordering;
    while DIRECTORY_BUSY
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    let result = run();
    DIRECTORY_BUSY.store(false, Ordering::Release);
    result
}

fn remember(slot: u32, generation: u64, pid: u32) {
    use core::sync::atomic::Ordering::Relaxed;
    directories(|| {
        let place = (0..DIRECTORIES)
            .find(|&i| {
                DIRECTORY_PID[i].load(Relaxed) != 0
                    && DIRECTORY_SLOT[i].load(Relaxed) == slot
                    && DIRECTORY_GENERATION[i].load(Relaxed) == generation
            })
            .or_else(|| (0..DIRECTORIES).find(|&i| DIRECTORY_PID[i].load(Relaxed) == 0))
            .unwrap_or_else(|| DIRECTORY_NEXT.fetch_add(1, Relaxed) % DIRECTORIES);
        DIRECTORY_SLOT[place].store(slot, Relaxed);
        DIRECTORY_GENERATION[place].store(generation, Relaxed);
        DIRECTORY_PID[place].store(pid, Relaxed);
    });
}

/// The PID whose directory the description of the image's `/proc` with this
/// slot and generation was opened for, if it was opened for one.
pub fn directory_pid(slot: u32, generation: u64) -> Option<u32> {
    use core::sync::atomic::Ordering::Relaxed;
    directories(|| {
        (0..DIRECTORIES)
            .find(|&i| {
                DIRECTORY_PID[i].load(Relaxed) != 0
                    && DIRECTORY_SLOT[i].load(Relaxed) == slot
                    && DIRECTORY_GENERATION[i].load(Relaxed) == generation
            })
            .map(|i| DIRECTORY_PID[i].load(Relaxed))
    })
}

/// `stat` of `/proc/<pid>` (a directory of the process's effective user),
/// of its files and of `/proc/uptime` (regular files of root and the user).
pub fn stat(path: &[u8]) -> Result<NodeInfo, i32> {
    let node = parse(path).ok_or(ENOENT)?;
    let (kind, permissions, uid, gid, inode) = match node {
        Node::Process(pid) => {
            let l = find(pid)?;
            (1, 0o555, l.euid, l.egid, u64::from(pid) << 4)
        }
        Node::File(pid, file) => {
            let l = find(pid)?;
            (
                2,
                0o444,
                l.euid,
                l.egid,
                (u64::from(pid) << 4) | (1 + file as u64),
            )
        }
        Node::Uptime => (2, 0o444, 0, 0, 1),
        Node::Mounts => (2, 0o444, 0, 0, 3),
    };
    let now = Timestamp::ZERO;
    Ok(NodeInfo {
        kind,
        permissions,
        device: DEVICE,
        special_device: 0,
        inode,
        links: if kind == 1 { 2 } else { 1 },
        uid,
        gid,
        size: 0,
        block_size: 4096,
        blocks: 0,
        access_time: now,
        modify_time: now,
        change_time: now,
    })
}

/// Whether `info` is the node of the directory `/proc` of the image, whose
/// listing is the live PIDs.
pub fn is_directory(info: &NodeInfo) -> bool {
    use core::sync::atomic::{AtomicU64, Ordering};
    static DEVICE_OF: AtomicU64 = AtomicU64::new(0);
    static INODE_OF: AtomicU64 = AtomicU64::new(0);
    if info.kind != 1 {
        return false;
    }
    if INODE_OF.load(Ordering::Acquire) == 0 {
        let Ok(proc) = crate::names::fstatat(crate::names::AT_FDCWD, Some(b"/proc"), 0) else {
            return false;
        };
        DEVICE_OF.store(proc.device, Ordering::Relaxed);
        INODE_OF.store(proc.inode.max(1), Ordering::Release);
    }
    info.device == DEVICE_OF.load(Ordering::Relaxed)
        && info.inode == INODE_OF.load(Ordering::Acquire)
}

/// The entries of the listing of `/proc` in Linux's dirent64 records from
/// `position`: ".", "..", "uptime", "mounts" and the live PIDs in ascending
/// order; for the directory of a process (`pid`), ".", ".." and its three
/// files. The offset after a PID is its number plus 4 (the fixed entries have
/// 1 to 4), so a listing that goes on in several calls, while processes
/// start and end, takes each process that lives throughout once.
pub fn entries(out: &mut [u8], position: u64, pid: Option<u32>) -> Result<usize, i32> {
    /// The entries before the PIDs of `/proc`.
    const FIXED: u64 = 4;
    let mut list = [0u32; PROCESSES];
    let count = match pid {
        Some(_) => 0,
        None => pids(&mut list)?,
    };
    list[..count].sort_unstable();
    let list = &list[..count];
    let at = core::cell::Cell::new(position);
    posix_change::dirent::fill(
        out,
        |name| {
            let here = at.get();
            let (len, kind, inode, after) = if let Some(pid) = pid {
                if here >= 5 {
                    return Ok(None);
                }
                let (text, kind, inode): (&[u8], u8, u64) = match here {
                    0 => (b".", 4, u64::from(pid) << 4),
                    1 => (b"..", 4, 2),
                    n => {
                        let (text, file): (&[u8], File) = match n {
                            2 => (b"cmdline", File::Cmdline),
                            3 => (b"stat", File::Stat),
                            _ => (b"status", File::Status),
                        };
                        (text, 8, (u64::from(pid) << 4) | (1 + file as u64))
                    }
                };
                name[..text.len()].copy_from_slice(text);
                (text.len(), kind, inode, here + 1)
            } else if here < FIXED {
                let (text, kind, inode): (&[u8], u8, u64) = match here {
                    0 => (b".", 4, 2),
                    1 => (b"..", 4, 2),
                    2 => (b"uptime", 8, 1),
                    _ => (b"mounts", 8, 3),
                };
                name[..text.len()].copy_from_slice(text);
                (text.len(), kind, inode, here + 1)
            } else {
                // The first process after the offset.
                let Some(&number) = list.iter().find(|&&p| u64::from(p) + FIXED > here) else {
                    return Ok(None);
                };
                let mut digits = [0u8; 10];
                let mut n = number;
                let mut start = digits.len();
                loop {
                    start -= 1;
                    digits[start] = b'0' + (n % 10) as u8;
                    n /= 10;
                    if n == 0 {
                        break;
                    }
                }
                let len = digits.len() - start;
                name[..len].copy_from_slice(&digits[start..]);
                (len, 4, u64::from(number) << 4, u64::from(number) + FIXED)
            };
            let item = posix_change::dirent::Item {
                inode,
                kind,
                name_len: len,
                before: here as i64,
                after: after as i64,
            };
            at.set(after);
            Ok(Some(item))
        },
        |offset| {
            at.set(u64::try_from(offset).map_err(|_| EINVAL)?);
            Ok(())
        },
    )
}
