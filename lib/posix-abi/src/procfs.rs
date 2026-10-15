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

/// Whether a path is under `/proc` (not `/proc` itself).
pub fn is_under(path: &[u8]) -> bool {
    path.starts_with(b"/proc/")
}

/// The process `pid` in the service's table.
fn find(pid: u32) -> Result<Listing, i32> {
    let mut cursor = 0;
    loop {
        let (next, found) = crate::process::list(cursor)?;
        if let Some(listing) = found.filter(|l| l.pid == pid) {
            return Ok(listing);
        }
        match next {
            Some(next) => cursor = next,
            None => return Err(ENOENT),
        }
    }
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
            let _ = writeln!(text, "{}.{:02} 0.00", ns / 1_000_000_000, (ns / 10_000_000) % 100);
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
                        "{} ({}) {} {} {} {} {} {} 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0",
                        l.pid,
                        name_of(&l),
                        state_letter(&l),
                        l.parent,
                        l.pgid,
                        l.sid,
                        tty_nr(&l),
                        l.pgid,
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
    if matches!(node, Node::Process(_)) {
        // The directory of a process is not opened, only its files.
        find(match node {
            Node::Process(pid) => pid,
            _ => 0,
        })?;
        return Err(ENOTDIR);
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
            (2, 0o444, l.euid, l.egid, (u64::from(pid) << 4) | (1 + file as u64))
        }
        Node::Uptime => (2, 0o444, 0, 0, 1),
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
/// `position` (the number of entries taken before): ".", "..", "uptime" and
/// the live PIDs.
pub fn entries(out: &mut [u8], position: u64) -> Result<usize, i32> {
    let mut list = [0u32; PROCESSES];
    let count = pids(&mut list)?;
    let total = 3 + count;
    let at = core::cell::Cell::new(usize::try_from(position).map_err(|_| EINVAL)?);
    posix_change::dirent::fill(
        out,
        |name| {
            let here = at.get();
            if here >= total {
                return Ok(None);
            }
            let (text, kind, inode): (&[u8], u8, u64) = match here {
                0 => (b".", 4, 2),
                1 => (b"..", 4, 2),
                2 => (b"uptime", 8, 1),
                n => (&[], 4, u64::from(list[n - 3]) << 4),
            };
            let len = if here >= 3 {
                let mut digits = [0u8; 10];
                let mut n = list[here - 3];
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
                len
            } else {
                name[..text.len()].copy_from_slice(text);
                text.len()
            };
            let item = posix_change::dirent::Item {
                inode,
                kind,
                name_len: len,
                before: here as i64,
                after: here as i64 + 1,
            };
            at.set(here + 1);
            Ok(Some(item))
        },
        |offset| {
            at.set(offset as usize);
            Ok(())
        },
    )
}
