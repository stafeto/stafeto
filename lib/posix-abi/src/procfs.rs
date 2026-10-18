// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `/proc` for the programs that read it (BusyBox `ps`): read only, in the
//! shape Linux gives it, and made from the process service's List.
//!
//! The directory `/proc` is a directory of the image. What lies under it
//! has no file in the file service: `/proc/<pid>/stat`, `statm`, `cmdline`
//! and `status`, and `/proc/uptime`, `stat`, `meminfo`, `cpuinfo` and `loadavg` are
//! text made at the open of the path and
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
    /// `/proc/<pid>/stat`, `statm`, `cmdline` or `status`.
    File(u32, File),
    /// `/proc/uptime`.
    Uptime,
    /// `/proc/stat`.
    SystemStat,
    /// `/proc/cpuinfo`.
    Cpuinfo,
    /// `/proc/meminfo`.
    Meminfo,
    /// `/proc/loadavg`.
    Loadavg,
    /// `/proc/mounts`.
    Mounts,
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum File {
    Stat,
    Cmdline,
    Status,
    Statm,
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
    if rest == b"stat" {
        return Some(Node::SystemStat);
    }
    if rest == b"cpuinfo" {
        return Some(Node::Cpuinfo);
    }
    if rest == b"meminfo" {
        return Some(Node::Meminfo);
    }
    if rest == b"loadavg" {
        return Some(Node::Loadavg);
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
        Some(name) => {
            // `task/<pid>/<file>`: a process has its one thread of that
            // number (htop reads the statistics of the main thread there).
            let name = match name.strip_prefix(b"task/") {
                Some(thread) => thread.strip_prefix(number)?.strip_prefix(b"/")?,
                None => name,
            };
            file_named(name).map(|file| Node::File(pid, file))
        }
    }
}

/// The file of a process `name` names, if it is one of these.
fn file_named(name: &[u8]) -> Option<File> {
    match name {
        b"stat" => Some(File::Stat),
        b"cmdline" => Some(File::Cmdline),
        b"status" => Some(File::Status),
        b"statm" => Some(File::Statm),
        _ => None,
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
    let (_, found, _) = crate::process::list(pid % PROCESSES as u32)?;
    found.filter(|l| l.pid == pid).ok_or(ENOENT)
}

/// The live PIDs, in the order of the table: how many went into `pids`.
pub fn pids(pids: &mut [u32; PROCESSES]) -> Result<usize, i32> {
    let (mut cursor, mut count) = (0, 0);
    loop {
        let (next, found, _) = crate::process::list(cursor)?;
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
    bytes: [u8; TEXT],
    len: usize,
}

/// The most bytes a file of `/proc` holds.
const TEXT: usize = 2048;

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
            bytes: [0; TEXT],
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
        3 => 'S',
        _ => 'R',
    }
}

/// The state as the line `State:` of Linux's `status` has it.
fn state_text(l: &Listing) -> &'static str {
    match l.state {
        1 => "T (stopped)",
        2 => "Z (zombie)",
        3 => "S (sleeping)",
        _ => "R (running)",
    }
}

/// The bytes of a page, as Linux counts `statm` and `rss`.
const PAGE: u64 = 4096;

/// What the whole table of processes comes to.
struct Totals {
    /// Live processes.
    processes: u32,
    /// Those not stopped or ended.
    running: u32,
    /// The highest PID of a live process.
    last_pid: u32,
    /// The time all processes ran, those that ended included, in hundredths
    /// of a second: it only grows.
    busy: u64,
}

fn totals() -> Result<Totals, i32> {
    let mut t = Totals {
        processes: 0,
        running: 0,
        last_pid: 0,
        busy: 0,
    };
    let (mut cursor, mut live) = (0, 0u64);
    loop {
        let (next, found, pool) = crate::process::list(cursor)?;
        if let Some(l) = found {
            t.processes += 1;
            if l.state == 0 {
                t.running += 1;
            }
            t.last_pid = t.last_pid.max(l.pid);
            // The time of a zombie is in the pool's account already.
            if l.state != 2 {
                live = live.saturating_add(l.ticks);
            }
        }
        match next {
            Some(next) => cursor = next,
            None => {
                // The pool of the last reply is the latest: a process that
                // ended while the table was read is counted there.
                let all = live.saturating_add(pool.retired);
                t.busy = rt::time::ticks_to_ns(all) / 10_000_000;
                return Ok(t);
            }
        }
    }
}

/// The calendar second the machine started: now less `up` seconds, 0 where
/// the clock cannot be read.
fn boot_time(up: u64) -> u64 {
    crate::clock::gettime(crate::clock::CLOCK_REALTIME)
        .ok()
        .and_then(|now| u64::try_from(now.seconds).ok())
        .map_or(0, |now| now.saturating_sub(up))
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
            let busy = totals().map_or(0, |t| t.busy);
            // The second number is the idle time of the one processor: the
            // time since the start less the time the processes ran.
            let idle = (ns / 10_000_000).saturating_sub(busy);
            let _ = writeln!(
                text,
                "{}.{:02} {}.{:02}",
                ns / 1_000_000_000,
                (ns / 10_000_000) % 100,
                idle / 100,
                idle % 100
            );
        }
        Node::SystemStat => {
            let t = totals()?;
            let up = rt::time::ticks_to_ns(rt::time::now()) / 10_000_000;
            let idle = up.saturating_sub(t.busy);
            // user nice system idle iowait irq softirq steal guest guest_nice
            // in hundredths of a second. Each CPU has a line of its own from
            // the kernel's count of its time (user, system, idle); the line
            // of the sum comes first. Without the kernel's count (a CPU it
            // does not tell) all the time the processes ran is user time on
            // CPU 0.
            let cpus = crate::cpus::count();
            let (mut rows, mut sum) = (
                [crate::cpus::Times {
                    user: 0,
                    system: 0,
                    idle: 0,
                }; 8],
                crate::cpus::Times {
                    user: 0,
                    system: 0,
                    idle: 0,
                },
            );
            let known = (0..cpus.min(rows.len()))
                .map(|i| crate::cpus::times(i).map(|row| rows[i] = row))
                .all(|row| row.is_some());
            if known {
                for row in &rows[..cpus.min(8)] {
                    sum.user += row.user;
                    sum.system += row.system;
                    sum.idle += row.idle;
                }
            } else {
                rows[0] = crate::cpus::Times {
                    user: t.busy,
                    system: 0,
                    idle,
                };
                sum = rows[0];
            }
            let _ = writeln!(
                text,
                "cpu  {} 0 {} {} 0 0 0 0 0 0",
                sum.user, sum.system, sum.idle
            );
            for (i, row) in rows
                .iter()
                .enumerate()
                .take(if known { cpus.min(8) } else { 1 })
            {
                let _ = writeln!(
                    text,
                    "cpu{i} {} 0 {} {} 0 0 0 0 0 0",
                    row.user, row.system, row.idle
                );
            }
            let _ = write!(
                text,
                "intr 0\nctxt 0\nbtime {}\nprocesses {}\nprocs_running {}\nprocs_blocked 0\n",
                boot_time(up / 100),
                t.last_pid,
                t.running,
            );
        }
        Node::Cpuinfo => {
            // One record for each CPU, in the shape of Linux's on aarch64:
            // the numbers htop and the scripts that count "processor" lines
            // read.
            for i in 0..crate::cpus::count() {
                let _ = write!(
                    text,
                    "processor\t: {i}\nBogoMIPS\t: 50.00\nFeatures\t: fp asimd\n\
                     CPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x0\n\
                     CPU part\t: 0xd03\nCPU revision\t: 4\n\n"
                );
            }
        }
        Node::Meminfo => {
            let pool = crate::process::list(0)?.2;
            let (total, free) = (pool.total >> 10, pool.free >> 10);
            let _ = write!(
                text,
                "MemTotal:       {total:8} kB\nMemFree:        {free:8} kB\nMemAvailable:   {free:8} kB\n\
                 Buffers:        {z:8} kB\nCached:         {z:8} kB\nSwapCached:     {z:8} kB\n\
                 SwapTotal:      {z:8} kB\nSwapFree:       {z:8} kB\nShmem:          {z:8} kB\n",
                z = 0
            );
        }
        Node::Loadavg => {
            let t = totals()?;
            // The averages of the run queue are not kept (the layer does
            // not see the scheduler's queue): 0.00 for each of the three.
            let _ = writeln!(
                text,
                "0.00 0.00 0.00 {}/{} {}",
                t.running.max(1),
                t.processes,
                t.last_pid
            );
        }
        Node::File(pid, kind) => {
            let l = find(pid)?;
            match kind {
                File::Stat => {
                    // pid (comm) state ppid pgrp session tty_nr tpgid flags
                    // minflt cminflt majflt cmajflt utime stime cutime cstime
                    // priority nice num_threads itrealvalue starttime vsize rss
                    // and the 28 fields after it as Linux has them (rsslim,
                    // the addresses, the signal sets, exit_signal 17,
                    // processor and so on), which htop reads one by one.
                    let _ = writeln!(
                        text,
                        "{} ({}) {} {} {} {} {} {} 0 0 0 0 0 {} 0 0 0 {} {} 1 0 0 {} {} \
                         18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 {} 0 0 0 0 0 0 0 0 0 0 0 0 0",
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
                        l.memory,
                        l.memory / PAGE,
                        l.cpu,
                    );
                }
                File::Statm => {
                    // size resident shared text lib data dt, in pages: all
                    // the memory charged to the process is resident.
                    let pages = l.memory / PAGE;
                    let _ = writeln!(text, "{pages} {pages} 0 0 0 {pages} 0");
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
                        "Name:\t{}\nState:\t{}\nTgid:\t{}\nPid:\t{}\nPPid:\t{}\nTracerPid:\t0\n\
                         Uid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\n\
                         VmSize:\t{:8} kB\nVmRSS:\t{:8} kB\nThreads:\t1\n",
                        name_of(&l),
                        state_text(&l),
                        l.pid,
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
                        l.memory >> 10,
                        l.memory >> 10,
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

/// The path of `name` read against the directory descriptor `dirfd`, when the
/// descriptor is one of `/proc` of the image (`open_directory` marks the
/// directories of processes; the directory `/proc` itself is the node that
/// `stat` of `/proc` names): `/proc/<pid>/<name>` for the first and
/// `/proc/<name>` for the second. The programs that walk `/proc` with
/// `openat` (htop) open a process's files this way. `None` for an absolute
/// name, any other descriptor and a path too long.
pub fn relative(dirfd: i32, name: &[u8]) -> Option<Absolute> {
    use posix_fs::Target;
    if name.is_empty() || name[0] == b'/' {
        return None;
    }
    let fd = u32::try_from(dirfd).ok()?;
    let (slot, generation) = crate::shared::held(fd, |_, target| match target {
        Target::Ram(ram) => Ok((ram.description_slot(), ram.generation())),
        _ => Err(EIO),
    })
    .ok()?;
    let mut text = Text::new();
    match directory_pid(slot, generation) {
        Some(pid) => write!(text, "/proc/{pid}/").ok()?,
        None => {
            let this = crate::names::fstatat(dirfd, None, 0).ok()?;
            let proc = crate::names::fstatat(crate::names::AT_FDCWD, Some(b"/proc"), 0).ok()?;
            if this.kind != 1 || (this.device, this.inode) != (proc.device, proc.inode) {
                return None;
            }
            text.write_str("/proc/").ok()?;
        }
    }
    if text.len + name.len() > text.bytes.len() {
        return None;
    }
    let (head, tail) = (text.len, name.len());
    text.bytes[head..head + tail].copy_from_slice(name);
    text.len += tail;
    absolute(&text.bytes[..text.len]).filter(Absolute::is_under)
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
        Node::SystemStat => (2, 0o444, 0, 0, 5),
        Node::Cpuinfo => (2, 0o444, 0, 0, 8),
        Node::Meminfo => (2, 0o444, 0, 0, 6),
        Node::Loadavg => (2, 0o444, 0, 0, 7),
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
/// `position`: ".", "..", "uptime", "mounts", "stat", "meminfo", "loadavg",
/// "cpuinfo" and the live PIDs in ascending
/// order; for the directory of a process (`pid`), ".", ".." and its four
/// files. The offset after a PID is its number plus 4 (the fixed entries have
/// 1 to 4), so a listing that goes on in several calls, while processes
/// start and end, takes each process that lives throughout once.
pub fn entries(out: &mut [u8], position: u64, pid: Option<u32>) -> Result<usize, i32> {
    /// The entries before the PIDs of `/proc`.
    const FIXED: u64 = 8;
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
                if here >= 6 {
                    return Ok(None);
                }
                let (text, kind, inode): (&[u8], u8, u64) = match here {
                    0 => (b".", 4, u64::from(pid) << 4),
                    1 => (b"..", 4, 2),
                    n => {
                        let (text, file): (&[u8], File) = match n {
                            2 => (b"cmdline", File::Cmdline),
                            3 => (b"stat", File::Stat),
                            4 => (b"statm", File::Statm),
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
                    3 => (b"mounts", 8, 3),
                    4 => (b"stat", 8, 5),
                    5 => (b"meminfo", 8, 6),
                    6 => (b"loadavg", 8, 7),
                    _ => (b"cpuinfo", 8, 8),
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
