// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the package service (xtask store-probe and store-crash, pk3-design R17):
//! the first POSIX process of the image, root, with a session of `pkgd`. It asks while the
//! service still reads its disk (a LIST, an INFO, a CLONE and a STATUS every 5 ms: the steps
//! of the service under load), then looks at what the service published and at the tree its
//! layers made. A disk with no packages is the second run: nothing is listed and nothing is
//! there. Started with `hello` as its name (the program of a package), it exits with 42.
//!
//! The file `/test/mode` of the image names another job: `full` installs, refuses, removes
//! and changes the settings on a disk that holds nothing (and, on the disk the next run of
//! the machine finds, looks at what stayed), `crash-install`, `crash-remove` and
//! `crash-settings` start the change a crash point stops in, and `verify` says what a
//! restarted service made of the store. The packages and the blobs it needs are files of
//! `/test/packages/`, described by `index`.

#![no_std]
#![no_main]

use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char, c_int, c_void};
use libc_ffi::{self as c, O_RDONLY, Timespec};
use proto_pkg::{self as pkg, Method, Stat};
use proto_wire::{Reader, Status, Writer, long};
use rt::abi::{Access, MESSAGE_MAX, Rights};
use rt::handle::{Any, Channel, Handle};
use rt::sys;

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

unsafe extern "C" {
    fn posix_spawn(
        pid: *mut c_int,
        path: *const c_char,
        actions: *const c_void,
        attributes: *const c_void,
        argv: *const *mut c_char,
        envp: *const *mut c_char,
    ) -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn nanosleep(request: *const Timespec, rest: *mut Timespec) -> c_int;
}

/// Where the probe maps the buffer it gives the service.
const BUFFER_AT: usize = 0x10_4000_0000;
/// The serial of `games` the disk of xtask's writer holds.
const GAMES_SERIAL: u64 = 4;
/// Where the files of the packages and the blobs are, in the image.
const FILES: &[u8] = b"/test/packages/";
/// The sizes the probe uses: the page of a package and a package too big for the memory.
const PAGE: u64 = 4096;

/// A place for the bytes of a blob the probe compares: static, since the stack is small.
struct Scratch(UnsafeCell<[u8; 65_536]>);
// SAFETY: the probe is one thread.
unsafe impl Sync for Scratch {}
static SCRATCH: Scratch = Scratch(UnsafeCell::new([0; 65_536]));

fn scratch() -> &'static mut [u8; 65_536] {
    // SAFETY: one thread, and no two borrows of it live at once.
    unsafe { &mut *SCRATCH.0.get() }
}

type Fail = &'static str;

macro_rules! say {
    ($($arg:tt)*) => { rt::println!("store-probe: {}", format_args!($($arg)*)) };
}

#[unsafe(no_mangle)]
extern "C" fn main(argc: isize, argv: *mut *mut c_char, _: *mut *mut c_char) -> c_int {
    // SAFETY: relibc supplies argc live NUL-terminated strings.
    let name = unsafe { CStr::from_ptr(*argv).to_bytes() };
    if argc > 0 && name.ends_with(b"hello") {
        return 42;
    }
    let mode = mode();
    let done = match mode.as_slice() {
        b"" => run(),
        // The client of xtask init-wait: it says when init started it.
        b"wait" => {
            say!(
                "client started at {} ns",
                rt::time::ticks_to_ns(rt::time::now())
            );
            Ok(())
        }
        other => scenario(other),
    };
    match done {
        Ok(()) => {
            say!("ok");
            0
        }
        Err(why) => {
            say!("failed: {why}");
            2
        }
    }
}

fn pause(ms: i64) {
    let t = Timespec {
        tv_sec: 0,
        tv_nsec: ms * 1_000_000,
    };
    // SAFETY: a valid request and no remainder wanted.
    unsafe { nanosleep(&t, core::ptr::null_mut()) };
}

struct Pkgd(Handle<Channel>);

impl Pkgd {
    /// A request with an optional handle; the reply in `out`, its length. The
    /// service's refusal is the error.
    fn call(
        &self,
        request: &[u8],
        handle: Option<Handle<Any>>,
        out: &mut [u8; MESSAGE_MAX],
    ) -> Result<usize, Status> {
        let reply = match handle {
            None => sys::send(&self.0, request)?,
            Some(h) => sys::send_handles(&self.0, request, [h]).map_err(|r| r.error)?,
        };
        let bytes = reply.bytes(out);
        let len = bytes.len();
        match Status::from_code(Reader::new(bytes).u32()?) {
            Status::Ok => Ok(len),
            status => Err(status),
        }
    }

    /// `call` again while the service is in the moment of changing its state and says BUSY.
    fn patient(&self, request: &[u8], out: &mut [u8; MESSAGE_MAX]) -> Result<usize, Status> {
        for _ in 0..2_000 {
            match self.call(request, None, out) {
                Err(Status::Unknown(pkg::BUSY)) => pause(2),
                done => return done,
            }
        }
        Err(Status::Unknown(pkg::BUSY))
    }

    fn word(
        &self,
        method: Method,
        value: u32,
        out: &mut [u8; MESSAGE_MAX],
    ) -> Result<usize, Status> {
        let mut w = Writer::new();
        pkg::write_word(method, value, &mut w)?;
        self.patient(w.as_bytes(), out)
    }

    fn status(&self) -> Result<Stat, Status> {
        let mut out = [0; MESSAGE_MAX];
        let len = self.patient(&Method::Status.header().bytes(), &mut out)?;
        Stat::read(&out[..len])
    }

    /// The `meta` of `name` whole, its length in `total`.
    fn info(&self, name: &[u8], total: &mut usize) -> Result<[u8; 4096], Status> {
        let mut meta = [0u8; 4096];
        let mut at = 0;
        loop {
            let mut w = Writer::new();
            pkg::write_info(name, at as u32, &mut w)?;
            let mut out = [0; MESSAGE_MAX];
            let len = self.patient(w.as_bytes(), &mut out)?;
            let mut r = Reader::new(&out[4..len]);
            *total = r.u32()? as usize;
            let part = r.bytes(r.left())?;
            meta[at..at + part.len()].copy_from_slice(part);
            at += part.len();
            if at >= *total || part.is_empty() {
                return Ok(meta);
            }
        }
    }

    fn serial(&self, repository: &[u8]) -> Result<u64, Status> {
        let mut w = Writer::new();
        pkg::write_serial(repository, None, &mut w)?;
        let mut out = [0; MESSAGE_MAX];
        let len = self.patient(w.as_bytes(), &mut out)?;
        Reader::new(&out[4..len]).u64()
    }

    /// The names and flags of the entries, in `names`; how many.
    fn list(&self, names: &mut [([u8; 64], u32); 16], report: bool) -> Result<usize, Status> {
        let (mut first, mut n) = (0, 0);
        loop {
            let mut out = [0; MESSAGE_MAX];
            let len = self.word(Method::List, first, &mut out)?;
            let mut entries = [None; 4];
            let (count, next) = pkg::read_list(&out[..len], &mut entries)?;
            for e in entries.iter().take(count as usize).flatten() {
                names[n].0[..e.name.len()].copy_from_slice(e.name);
                names[n].1 = e.flags;
                n += 1;
                if e.name == b"hello" && report {
                    say!(
                        "list: {} {} {} flags={}",
                        core::str::from_utf8(e.name).unwrap_or("?"),
                        core::str::from_utf8(e.version).unwrap_or("?"),
                        core::str::from_utf8(e.repository).unwrap_or("?"),
                        e.flags
                    );
                }
            }
            if next == 0 {
                return Ok(n);
            }
            first = next;
        }
    }

    fn clone_session(&self) -> Result<(), Status> {
        rt::service::clone_session(&self.0, &Method::Clone.header().bytes()).map(drop)
    }

    /// BUFFER with a new object, mapped for the run when `map`.
    fn buffer(&self, map: bool) -> Result<(), Status> {
        self.buffer_with(map, true)
    }

    /// BUFFER, with the identity session of the process after the object when `identity`.
    fn buffer_with(&self, map: bool, identity: bool) -> Result<(), Status> {
        let object = sys::mem_create(u64::from(pkg::BUFFER_SIZE))?;
        let process = posix_abi::allocation::process();
        if map {
            sys::mem_map(
                process,
                &object,
                0,
                u64::from(pkg::BUFFER_SIZE),
                BUFFER_AT,
                Access::ReadWrite,
            )?;
        }
        let copy = sys::handle_duplicate(
            &object,
            Rights::MAP_READ | Rights::MAP_WRITE | Rights::TRANSFER,
        )?;
        let mut w = Writer::new();
        pkg::write_word(Method::Buffer, pkg::BUFFER_SIZE, &mut w)?;
        let who = identity
            .then(posix_abi::process::identity)
            .flatten()
            .and_then(|i| sys::handle_duplicate(i, Rights::NOTIFY | Rights::TRANSFER).ok());
        let reply = match who {
            None => sys::send_handles(&self.0, w.as_bytes(), [copy.erase()]),
            Some(who) => sys::send_handles(&self.0, w.as_bytes(), [copy.erase(), who.erase()]),
        }
        .map_err(|r| r.error)?;
        let mut out = [0; MESSAGE_MAX];
        match Status::from_code(Reader::new(reply.bytes(&mut out)).u32()?) {
            Status::Ok => Ok(()),
            status => Err(status),
        }
    }
}

fn path(text: &[u8], buf: &mut [u8; 96]) -> *const c_char {
    buf[..text.len()].copy_from_slice(text);
    buf[text.len()] = 0;
    buf.as_ptr().cast()
}

/// The mode of the file, or None when it is not there.
fn mode_of(text: &[u8]) -> Option<u32> {
    let mut b = [0u8; 96];
    let mut st = [0u64; 16];
    // SAFETY: `st` is as big and as aligned as relibc's `struct stat`; its mode is at 16.
    let ok = unsafe { c::stat(path(text, &mut b), (&raw mut st).cast()) } == 0;
    ok.then(|| (st[2] & 0xffff_ffff) as u32)
}

/// The bytes of the file into `out`; their number.
fn read_file(text: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut b = [0u8; 96];
    // SAFETY: a NUL-terminated path.
    let fd = unsafe { c::open(path(text, &mut b), O_RDONLY) };
    if fd < 0 {
        return None;
    }
    let mut n = 0;
    loop {
        // SAFETY: the buffer after `n` is the room given.
        let got = unsafe { c::read(fd, out[n..].as_mut_ptr(), out.len() - n) };
        if got <= 0 {
            break;
        }
        n += got as usize;
    }
    // SAFETY: the descriptor opened above.
    unsafe { c::close(fd) };
    Some(n)
}

fn run() -> Result<(), Fail> {
    let parent = posix_crt::parent();
    let session = rt::service::connect(&parent, "pkgd").map_err(|_| "no session with pkgd")?;
    let pkgd = Pkgd(session);
    say!("pkgd answers");
    // While the service reads its disk: a mix of requests every 5 ms.
    let mut status = pkgd.status().map_err(|_| "STATUS")?;
    let mut rounds = 0;
    while status.flags & pkg::STATUS_STARTING != 0 {
        if rounds > 12_000 {
            return Err("pkgd never finished its start");
        }
        let mut names = [([0; 64], 0); 16];
        let _ = pkgd.list(&mut names, false);
        let mut total = 0;
        let _ = pkgd.info(b"hello", &mut total);
        let _ = pkgd.clone_session();
        pause(5);
        status = pkgd.status().map_err(|_| "STATUS")?;
        rounds += 1;
    }
    say!(
        "status generation={} blocks={} free={} disk={} image={} flags={}",
        status.generation,
        status.blocks,
        status.free,
        status.disk,
        status.image,
        status.flags
    );
    let mut names = [([0; 64], 0); 16];
    let listed = pkgd.list(&mut names, true).map_err(|_| "LIST")?;
    if status.disk == 0 {
        if listed != status.image as usize || mode_of(b"/opt/hello/bin/hello").is_some() {
            return Err("an empty store lists packages");
        }
        say!("empty store: nothing listed, nothing attached");
        return Ok(());
    }
    if listed != status.disk as usize
        || &names[0].0[..5] != b"hello"
        || names[0].1 != pkg::ENTRY_WORLD
    {
        return Err("LIST is not the packages of the disk, hello first");
    }
    let mut total = 0;
    let meta = pkgd.info(b"hello", &mut total).map_err(|_| "INFO")?;
    if !meta.starts_with(b"name hello\n") || !(100..=4096).contains(&total) {
        return Err("INFO of hello");
    }
    say!("info hello {total} bytes");
    if pkgd.info(b"nobody", &mut total) != Err(pkg::code(pkg::NOT_FOUND)) {
        return Err("INFO of nobody is not NOT_FOUND");
    }
    let serials = [b"games".as_slice(), b"stafeto", b"nobody"].map(|r| pkgd.serial(r));
    if serials != [Ok(GAMES_SERIAL), Ok(0), Ok(0)] {
        return Err("the serials");
    }
    say!("serial games={GAMES_SERIAL} stafeto=0 nobody=0");
    settings(&pkgd)?;
    let mut text = [0u8; 256];
    let n = read_file(b"/etc/pkg/repositories", &mut text).ok_or("no /etc/pkg/repositories")?;
    if &text[..n] != b"games https://example.org/games\n" {
        return Err("/etc/pkg/repositories");
    }
    if mode_of(b"/etc/pkg/keys/games.pub") != Some(0o100_644)
        || mode_of(b"/etc/pkg/repositories") != Some(0o100_644)
    {
        return Err("the mode of the settings files");
    }
    say!("settings layer: /etc/pkg/repositories and /etc/pkg/keys/games.pub with mode 0644");
    if mode_of(b"/opt/broken").is_some() || mode_of(b"/opt/revoked").is_some() {
        return Err("a package that must be skipped is attached");
    }
    say!("broken and revoked are not in the tree");
    hello()?;
    pkgd.clone_session().map_err(|_| "CLONE")?;
    if pkgd.buffer(false) != Err(pkg::code(pkg::INVALID)) {
        return Err("a second BUFFER is not refused");
    }
    let mut w = Writer::new();
    pkg::write_take(77, &mut w).map_err(|_| "TAKE")?;
    let mut out = [0; MESSAGE_MAX];
    if pkgd.call(w.as_bytes(), None, &mut out) != Err(Status::Kernel(rt::abi::Error::BadState)) {
        return Err("TAKE of an unknown key");
    }
    say!("clone, a second buffer and an unknown key are refused as they should be");
    buffers(&pkgd)
}

/// The places of the buffers: two sessions that are no one's in particular take the two places
/// for them and a third is BUSY, while the superuser's session still gets one of the two kept for it.
fn buffers(pkgd: &Pkgd) -> Result<(), Fail> {
    let (a, b, c, d) = (pkgd.other()?, pkgd.other()?, pkgd.other()?, pkgd.other()?);
    if a.buffer_with(false, false).is_err() || b.buffer_with(false, false).is_err() {
        return Err("the two places for any session");
    }
    if !is(c.buffer_with(false, false), pkg::BUSY) {
        return Err("a third session that is not the superuser's has a place");
    }
    if d.buffer_with(false, true).is_err() {
        return Err("the superuser's session has no place kept for it");
    }
    say!(
        "buffers: two places for any session, a third is BUSY, the superuser's session still has one"
    );
    Ok(())
}

/// SETTINGS_GET into the buffer of the session: the blob, parsed.
fn settings(pkgd: &Pkgd) -> Result<(), Fail> {
    let mut out = [0; MESSAGE_MAX];
    if pkgd.word(Method::SettingsGet, 0, &mut out) != Err(pkg::code(pkg::NO_BUFFER)) {
        return Err("SETTINGS_GET without a buffer");
    }
    pkgd.buffer(true).map_err(|_| "BUFFER")?;
    let len = pkgd
        .word(Method::SettingsGet, 0, &mut out)
        .map_err(|_| "SETTINGS_GET")?;
    let mut r = Reader::new(&out[4..len]);
    let (total, copied) = (
        r.u32().map_err(|_| "reply")? as usize,
        r.u32().map_err(|_| "reply")? as usize,
    );
    let mut blob = [0u8; 4096];
    if total != copied || total > blob.len() {
        return Err("the blob is not one cell");
    }
    // SAFETY: the buffer is mapped at BUFFER_AT; the service wrote cell 0 before it replied.
    blob[..copied]
        .copy_from_slice(unsafe { core::slice::from_raw_parts(BUFFER_AT as *const u8, copied) });
    let parsed = pkg::blob::Blob::parse(&blob[..copied]).map_err(|_| "the blob")?;
    let mut files = parsed.files();
    let (a, b) = (files.next().ok_or("blob")?, files.next().ok_or("blob")?);
    if parsed.count != 2 || a.name != b"repositories" || b.name != b"keys/games.pub" {
        return Err("the files of the blob");
    }
    say!("settings blob of {total} bytes: repositories and keys/games.pub");
    Ok(())
}

/// The program of the package `hello` runs from its layer and exits with 42.
fn hello() -> Result<(), Fail> {
    let mut b = [0u8; 96];
    let program = path(b"/opt/hello/bin/hello", &mut b);
    let argv = [c"hello".as_ptr().cast_mut(), core::ptr::null_mut()];
    let envp = [core::ptr::null_mut()];
    let mut pid = 0;
    // SAFETY: valid NUL-terminated strings and null-terminated vectors.
    let spawned = unsafe {
        posix_spawn(
            &mut pid,
            program,
            core::ptr::null(),
            core::ptr::null(),
            argv.as_ptr(),
            envp.as_ptr(),
        )
    };
    if spawned != 0 {
        say!("posix_spawn gave errno {spawned}");
        return Err("posix_spawn of /opt/hello/bin/hello");
    }
    let mut status = 0;
    // SAFETY: the pid of the child spawned above.
    if unsafe { waitpid(pid, &mut status, 0) } != pid || status != 42 << 8 {
        return Err("hello did not exit with 42");
    }
    say!("hello runs from its layer, exit code 42");
    Ok(())
}

// ---- the jobs the file `/test/mode` names -------------------------------------------------

/// The first line of `/test/mode`, empty when the image has none.
fn mode() -> Vec16 {
    let mut text = [0u8; 64];
    let n = read_file(b"/test/mode", &mut text).unwrap_or(0);
    let line = text[..n].split(|&b| b == b'\n').next().unwrap_or(&[]);
    let mut mode = Vec16 {
        bytes: [0; 16],
        len: 0,
    };
    let len = line.len().min(16);
    mode.bytes[..len].copy_from_slice(&line[..len]);
    mode.len = len;
    mode
}

/// A word of at most 16 bytes, on the stack.
struct Vec16 {
    bytes: [u8; 16],
    len: usize,
}

impl Vec16 {
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// One line of the index of the packages of the image.
struct Entry {
    name: [u8; 64],
    name_len: usize,
    version: [u8; 64],
    version_len: usize,
    size: u64,
    sha256: [u8; 32],
    /// The name of the file of the package, `<stem>.pkg`: the package's name unless the index says other.
    stem: [u8; 64],
    stem_len: usize,
}

impl Entry {
    const EMPTY: Entry = Entry {
        name: [0; 64],
        name_len: 0,
        version: [0; 64],
        version_len: 0,
        size: 0,
        sha256: [0; 32],
        stem: [0; 64],
        stem_len: 0,
    };

    fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    fn blocks(&self) -> u64 {
        self.size / PAGE
    }

    /// The path of the file of the package in the image.
    fn path(&self, buf: &mut [u8; 96]) -> *const c_char {
        let mut at = FILES.len();
        buf[..at].copy_from_slice(FILES);
        for part in [&self.stem[..self.stem_len], b".pkg"] {
            buf[at..at + part.len()].copy_from_slice(part);
            at += part.len();
        }
        buf[at] = 0;
        buf.as_ptr().cast()
    }
}

const MAX_ENTRIES: usize = 24;

struct Index {
    entries: [Entry; MAX_ENTRIES],
    count: usize,
}

fn hex(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// The lines `name version size sha256` of the index of the image.
fn load_index() -> Result<Index, Fail> {
    let text = scratch();
    let n = read_file(b"/test/packages/index", &mut text[..8192]).ok_or("no index")?;
    let mut index = Index {
        entries: [const { Entry::EMPTY }; MAX_ENTRIES],
        count: 0,
    };
    for line in text[..n].split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
        let mut fields = line.split(|&b| b == b' ');
        let (Some(name), Some(version), Some(size), Some(sha)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err("a line of the index");
        };
        let stem = fields.next().unwrap_or(name);
        let e = index
            .entries
            .get_mut(index.count)
            .ok_or("too many packages")?;
        e.name[..name.len()].copy_from_slice(name);
        e.name_len = name.len();
        e.stem[..stem.len()].copy_from_slice(stem);
        e.stem_len = stem.len();
        e.version[..version.len()].copy_from_slice(version);
        e.version_len = version.len();
        e.size = size
            .iter()
            .try_fold(0u64, |n, &d| {
                (d.is_ascii_digit()).then(|| n * 10 + u64::from(d - b'0'))
            })
            .ok_or("a size")?;
        for (i, pair) in sha.chunks(2).enumerate().take(32) {
            let (Some(&hi), Some(&lo)) = (pair.first(), pair.get(1)) else {
                return Err("a digest");
            };
            e.sha256[i] = hex(hi).ok_or("a digest")? << 4 | hex(lo).ok_or("a digest")?;
        }
        index.count += 1;
    }
    Ok(index)
}

impl Index {
    /// The package whose file is `<stem>.pkg`.
    fn get(&self, stem: &[u8]) -> Result<&Entry, Fail> {
        self.entries[..self.count]
            .iter()
            .find(|e| &e.stem[..e.stem_len] == stem)
            .ok_or("a package the index does not have")
    }
}

/// What the service says of its store.
struct Snap {
    stat: Stat,
    names: [([u8; 64], u32); 16],
    count: usize,
}

impl Snap {
    fn same(&self, other: &Snap) -> bool {
        self.stat.generation == other.stat.generation
            && self.stat.free == other.stat.free
            && self.stat.disk == other.stat.disk
            && self.count == other.count
            && self.names[..self.count] == other.names[..other.count]
    }

    fn has(&self, name: &[u8]) -> Option<u32> {
        self.names[..self.count]
            .iter()
            .find(|(n, _)| &n[..name.len()] == name && n[name.len()] == 0)
            .map(|(_, flags)| *flags)
    }
}

fn snap(pkgd: &Pkgd) -> Result<Snap, Fail> {
    let stat = pkgd.status().map_err(|_| "STATUS")?;
    let mut names = [([0; 64], 0); 16];
    let count = pkgd.list(&mut names, false).map_err(|_| "LIST")?;
    Ok(Snap { stat, names, count })
}

fn is(result: Result<impl Sized, Status>, c: u32) -> bool {
    matches!(result, Err(Status::Unknown(got)) if got == c)
}

/// The sum of the bytes' FNV-1a, to tell a blob from another without a second copy.
fn fnv(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    })
}

/// A file of the image into the buffer of the session (all of it, 64 KiB at most): its
/// length and checksum.
fn load_blob(name: &[u8]) -> Result<(usize, u64), Fail> {
    let mut path = [0u8; 96];
    path[..FILES.len()].copy_from_slice(FILES);
    path[FILES.len()..FILES.len() + name.len()].copy_from_slice(name);
    // SAFETY: the buffer is mapped at BUFFER_AT for 64 KiB.
    let buffer = unsafe { core::slice::from_raw_parts_mut(BUFFER_AT as *mut u8, 65_536) };
    let n = read_file(&path[..FILES.len() + name.len()], buffer).ok_or("a blob of the image")?;
    Ok((n, fnv(&buffer[..n])))
}

fn cell(n: u32) -> *mut u8 {
    (BUFFER_AT + n as usize * pkg::CELL_BYTES as usize) as *mut u8
}

impl Pkgd {
    /// The reply of a long operation after WAIT k: TAKE until READY. The first four bytes of its
    /// result, 0 for none.
    fn finish(&self, key: u64, hammer: bool) -> Result<u32, Status> {
        let mut w = Writer::new();
        pkg::write_take(key, &mut w)?;
        for _ in 0..200_000 {
            let reply = sys::send(&self.0, w.as_bytes())?;
            let mut out = [0; MESSAGE_MAX];
            match long::Reply::read(reply.bytes(&mut out))? {
                long::Reply::Ready(result) => {
                    let mut word = [0u8; 4];
                    let n = result.len().min(4);
                    word[..n].copy_from_slice(&result[..n]);
                    return Ok(u32::from_le_bytes(word));
                }
                long::Reply::Armed => {
                    if hammer {
                        self.hammer();
                    }
                    pause(if hammer { 5 } else { 1 });
                }
                _ => return Err(Status::BadSize),
            }
        }
        Err(Status::Kernel(rt::abi::Error::WouldBlock))
    }

    /// The mix of requests of the measurement of the steps: all kinds of the reads, at once with the
    /// work of the worker.
    fn hammer(&self) {
        let mut names = [([0; 64], 0); 16];
        let _ = self.list(&mut names, false);
        let mut total = 0;
        let _ = self.info(b"hello", &mut total);
        let _ = self.clone_session();
        let _ = self.status();
        let _ = self.serial(b"stafeto");
    }

    /// A change of the store: the request, with a copy of the identity session when
    /// `identity`; the first word of the result. BUSY is asked again: the worker may not
    /// have dropped a group that was cancelled.
    fn change(&self, request: &[u8], identity: bool, hammer: bool) -> Result<u32, Status> {
        for _ in 0..2_000 {
            let copy = identity
                .then(posix_abi::process::identity)
                .flatten()
                .and_then(|i| sys::handle_duplicate(i, Rights::NOTIFY | Rights::TRANSFER).ok());
            let reply = match copy {
                None => sys::send(&self.0, request)?,
                Some(h) => sys::send_handles(&self.0, request, [h.erase()]).map_err(|r| r.error)?,
            };
            let mut out = [0; MESSAGE_MAX];
            let key = match long::Reply::read(reply.bytes(&mut out)) {
                Ok(long::Reply::Wait(key)) => key,
                // The store is held for the moment: a group is being dropped.
                Err(Status::Unknown(pkg::BUSY)) => {
                    pause(5);
                    continue;
                }
                Ok(_) => return Err(Status::BadSize),
                Err(status) => return Err(status),
            };
            match self.finish(key, hammer) {
                Err(Status::Unknown(pkg::BUSY)) => pause(5),
                done => return done,
            }
        }
        Err(Status::Unknown(pkg::BUSY))
    }

    fn feed(&self, receipt: u32, cell: u32, len: u32) -> Result<(), Status> {
        let mut w = Writer::new();
        pkg::Feed { receipt, cell, len }.write(&mut w)?;
        let mut out = [0; MESSAGE_MAX];
        self.call(w.as_bytes(), None, &mut out).map(drop)
    }

    /// The package `e` of the image, installed from `repository`: INSTALL_BEGIN with its record,
    /// FEED with the bytes of its file in the cells of the buffer, INSTALL_COMMIT.
    fn install(&self, e: &Entry, how: &Install) -> Result<(), Status> {
        let mut sha256 = e.sha256;
        if how.bad_hash {
            sha256[0] ^= 1;
        }
        let begin = pkg::Begin {
            name: e.name(),
            version: &e.version[..e.version_len],
            size: e.size,
            sha256,
            repository: how.repository,
            flags: u32::from(how.world),
        };
        let mut w = Writer::new();
        begin.write(&mut w)?;
        let receipt = self.change(w.as_bytes(), true, how.hammer)?;
        let mut buf = [0u8; 96];
        // SAFETY: a NUL-terminated path.
        let fd = unsafe { c::open(e.path(&mut buf), O_RDONLY) };
        if fd < 0 {
            return Err(Status::BadSize);
        }
        let fed = self.feed_file(fd, receipt, e.size, how.extra_byte);
        // SAFETY: the descriptor opened above.
        unsafe { c::close(fd) };
        fed?;
        let mut w = Writer::new();
        pkg::write_commit(receipt, if how.end { pkg::COMMIT_END } else { 0 }, &mut w)?;
        self.change(w.as_bytes(), false, how.hammer).map(drop)
    }

    /// The bytes of the file `fd` into the cells, a FEED for each; `extra` adds a byte too many.
    fn feed_file(&self, fd: c_int, receipt: u32, size: u64, extra: bool) -> Result<(), Status> {
        let (mut sent, mut next) = (0u64, 0u32);
        while sent < size {
            let want = (size - sent).min(u64::from(pkg::CELL_BYTES)) as usize;
            let mut got = 0;
            while got < want {
                // SAFETY: the cell is in the mapped buffer, `want - got` bytes are in it.
                let n = unsafe { c::read(fd, cell(next).add(got), want - got) };
                if n <= 0 {
                    return Err(Status::BadSize);
                }
                got += n as usize;
            }
            self.feed(receipt, next, got as u32)?;
            sent += got as u64;
            next = (next + 1) % pkg::CELLS;
        }
        if extra {
            self.feed(receipt, next, 1)?;
        }
        Ok(())
    }

    fn remove(&self, names: &[&[u8]], identity: bool) -> Result<u32, Status> {
        let mut w = Writer::new();
        pkg::write_remove(names, &mut w)?;
        self.change(w.as_bytes(), identity, false)
    }

    fn serial_set(&self, repository: &[u8], serial: u64, identity: bool) -> Result<u32, Status> {
        let mut w = Writer::new();
        pkg::write_serial(repository, Some(serial), &mut w)?;
        self.change(w.as_bytes(), identity, false)
    }

    fn world_set(&self, name: &[u8], world: bool, identity: bool) -> Result<u32, Status> {
        let mut w = Writer::new();
        pkg::write_world(name, world, &mut w)?;
        self.change(w.as_bytes(), identity, false)
    }

    /// SETTINGS_SET or REVOKED_SET of the first `len` bytes of the buffer.
    fn blob_set(&self, method: Method, len: usize, identity: bool) -> Result<u32, Status> {
        let mut w = Writer::new();
        pkg::write_word(method, len as u32, &mut w)?;
        self.change(w.as_bytes(), identity, false)
    }

    /// The settings blob whole, in parts of a cell; a part that comes with another generation
    /// than the first starts the reading again. The bytes are in `scratch()`; the length, the
    /// number of parts and the generation.
    fn settings_blob(&self) -> Result<(usize, usize, u64), Fail> {
        'again: for _ in 0..20 {
            let (mut offset, mut parts, mut generation) = (0usize, 0, None);
            loop {
                let mut out = [0; MESSAGE_MAX];
                let len = self
                    .word(Method::SettingsGet, offset as u32, &mut out)
                    .map_err(|_| "SETTINGS_GET")?;
                let part =
                    pkg::Settings::read(&out[..len]).map_err(|_| "the reply of SETTINGS_GET")?;
                if *generation.get_or_insert(part.generation) != part.generation {
                    continue 'again;
                }
                let (total, copied) = (part.total as usize, part.copied as usize);
                // SAFETY: cell 0 of the mapped buffer holds `copied` bytes the service wrote.
                let bytes = unsafe { core::slice::from_raw_parts(cell(0), copied) };
                scratch()[offset..offset + copied].copy_from_slice(bytes);
                offset += copied;
                parts += 1;
                if offset >= total || copied == 0 {
                    return Ok((total, parts, part.generation));
                }
            }
        }
        Err("the generation of the settings kept changing")
    }
}

/// How an installation goes.
struct Install<'a> {
    repository: &'a [u8],
    world: bool,
    end: bool,
    bad_hash: bool,
    extra_byte: bool,
    hammer: bool,
}

impl<'a> Install<'a> {
    fn new(repository: &'a [u8], hammer: bool) -> Install<'a> {
        Install {
            repository,
            world: true,
            end: true,
            bad_hash: false,
            extra_byte: false,
            hammer,
        }
    }
}

/// Milliseconds since the tick `from` of the counter.
fn since_ms(from: u64) -> u64 {
    rt::time::ticks_to_ns(rt::time::now().wrapping_sub(from)) / 1_000_000
}

/// The start of every job: the service has read its disk, a buffer is given.
fn begin(pkgd: &Pkgd) -> Result<Snap, Fail> {
    let began = rt::time::now();
    let mut status = pkgd.status().map_err(|_| "STATUS")?;
    let mut rounds = 0;
    while status.flags & pkg::STATUS_STARTING != 0 {
        if rounds > 12_000 {
            return Err("pkgd never finished its start");
        }
        pause(5);
        status = pkgd.status().map_err(|_| "STATUS")?;
        rounds += 1;
    }
    say!("pkgd ready after {} ms", since_ms(began));
    pkgd.buffer(true).map_err(|_| "BUFFER")?;
    snap(pkgd)
}

fn scenario(mode: &[u8]) -> Result<(), Fail> {
    let parent = posix_crt::parent();
    let session = rt::service::connect(&parent, "pkgd").map_err(|_| "no session with pkgd")?;
    let pkgd = Pkgd(session);
    say!("pkgd answers");
    let index = load_index()?;
    match mode {
        b"full" => full(&pkgd, &index, false),
        b"full-steps" => full(&pkgd, &index, true),
        b"doom" => doom(&pkgd, &index),
        b"crash-install" => {
            begin(&pkgd)?;
            let second = index.get(b"second")?;
            pkgd.install(second, &Install::new(b"stafeto", false))
                .map_err(|_| "the installation went through: the crash point was not reached")
        }
        b"crash-remove" => {
            begin(&pkgd)?;
            pkgd.remove(&[b"second"], true)
                .map(drop)
                .map_err(|_| "the removal went through: the crash point was not reached")
        }
        b"crash-settings" => {
            begin(&pkgd)?;
            let (len, _) = load_blob(b"settings1.blob")?;
            pkgd.blob_set(Method::SettingsSet, len, true)
                .map(drop)
                .map_err(|_| "the settings went through: the crash point was not reached")
        }
        // The disk service stops answering at the first write of data (xtask store-probe deaf).
        b"deaf" => deaf(&pkgd, &index),
        // The disk is deaf from the first read: the start of the service fails (xtask store-probe no-store).
        b"no-store" => no_store(&pkgd, &index),
        // The store as a restart finds it: what the service lists, its numbers, its tree.
        b"verify" => verify(&pkgd),
        // A format that crashed: the service never finishes its start before the host kills the machine.
        b"crash-format" => begin(&pkgd).map(drop),
        _ => Err("an unknown mode"),
    }
}

/// The disk service that stops answering in the middle of an installation (built with `deaf`; the
/// service built with `short-deadline`): the wait of the service ends with IO within the deadline,
/// the store is as it was and free for the next receipt, and the next installation is refused at
/// once, since the disk is not asked any more.
fn deaf(pkgd: &Pkgd, index: &Index) -> Result<(), Fail> {
    let was = begin(pkgd)?;
    let big = index.get(b"big")?;
    let from = rt::time::now();
    if !is(pkgd.install(big, &Install::new(b"stafeto", false)), pkg::IO) {
        return Err("the installation on a deaf disk is not IO");
    }
    let first = since_ms(from);
    // The service waited for the deadline (3 s) and no more than seven times it.
    if !(2_900..20_000).contains(&first) {
        return Err("the wait of the service for the disk is not its deadline");
    }
    if !snap(pkgd)?.same(&was) {
        return Err("the store changed");
    }
    if pkgd.status().map_err(|_| "STATUS")?.flags & pkg::STATUS_NO_STORE == 0 {
        return Err("STATUS does not say the store is not served");
    }
    let hello = index.get(b"hello")?;
    let from = rt::time::now();
    if !is(
        pkgd.install(hello, &Install::new(b"stafeto", false)),
        pkg::IO,
    ) {
        return Err("the second installation on a deaf disk is not IO");
    }
    let second = since_ms(from);
    // Without the dead mark it would wait for the deadline again (3 s).
    if second >= 2_000 {
        say!("the second installation took {second} ms");
        return Err("the second installation did not end at once");
    }
    if !snap(pkgd)?.same(&was) {
        return Err("the store changed after the second installation");
    }
    say!(
        "the disk stopped answering: INSTALL is IO after {first} ms, the store is as it was and free, the next one is IO after {second} ms"
    );
    Ok(())
}

/// The disk service deaf from its first read (built with `deaf-start`, the package service with
/// `short-deadline`): the start of the service fails, it says READY all the same, STATUS says the
/// store is not served and a change is refused IO at once, where it used to be taken and never
/// answered.
fn no_store(pkgd: &Pkgd, index: &Index) -> Result<(), Fail> {
    begin(pkgd)?;
    if pkgd.status().map_err(|_| "STATUS")?.flags & pkg::STATUS_NO_STORE == 0 {
        return Err("STATUS does not say the store is not served");
    }
    let hello = index.get(b"hello")?;
    let from = rt::time::now();
    if !is(
        pkgd.install(hello, &Install::new(b"stafeto", false)),
        pkg::IO,
    ) {
        return Err("the installation without a store is not IO");
    }
    let took = since_ms(from);
    if took >= 2_000 {
        say!("the installation took {took} ms");
        return Err("the installation without a store did not end at once");
    }
    say!("the start failed on the disk: STATUS says no store, INSTALL is IO after {took} ms");
    Ok(())
}

/// Says what a restarted service made of the store: the status, the names, the settings, the tree.
fn verify(pkgd: &Pkgd) -> Result<(), Fail> {
    let snap = begin(pkgd)?;
    say!(
        "state generation={} free={} disk={} blocks={}",
        snap.stat.generation,
        snap.stat.free,
        snap.stat.disk,
        snap.stat.blocks
    );
    for (name, flags) in &snap.names[..snap.count] {
        let len = name.iter().position(|&b| b == 0).unwrap_or(64);
        say!(
            "state package {} flags={}",
            core::str::from_utf8(&name[..len]).unwrap_or("?"),
            flags
        );
    }
    let (total, _, generation) = pkgd.settings_blob()?;
    say!("state settings bytes={total} generation={generation}");
    for path in [&b"/opt/hello/bin/hello"[..], b"/opt/second/bin/second"] {
        say!(
            "state tree {} {}",
            core::str::from_utf8(path).unwrap_or("?"),
            if mode_of(path).is_some() { "yes" } else { "no" }
        );
    }
    Ok(())
}

/// The whole of it on a disk that holds nothing; on the disk of its own second run it looks at what stayed.
fn full(pkgd: &Pkgd, index: &Index, steps: bool) -> Result<(), Fail> {
    let first = begin(pkgd)?;
    if first.has(b"big").is_some() {
        return after_restart(pkgd, &first);
    }
    if first.stat.disk != 0 || first.stat.flags != 0 {
        return Err("the disk of the full scenario is not blank");
    }
    let stafeto = Install::new(b"stafeto", steps);
    // 1. A package signed by the development key: installed, attached, run.
    let hello_entry = index.get(b"hello")?;
    pkgd.install(hello_entry, &stafeto)
        .map_err(|_| "the installation of hello")?;
    let one = snap(pkgd)?;
    if one.stat.generation != first.stat.generation + 1
        || one.stat.disk != 1
        || one.has(b"hello") != Some(pkg::ENTRY_WORLD)
        || one.stat.free + hello_entry.blocks() != first.stat.free
    {
        return Err("the state after the installation of hello");
    }
    hello()?;
    say!("hello installed: the path is there, the program runs, the space is the package's");
    // 2. Each refusal leaves the state as it was.
    let refusals: [(&[u8], u32, &str); 5] = [
        (b"bad-sig", pkg::BAD_SIGNATURE, "BAD_SIGNATURE"),
        (b"other-key", pkg::UNTRUSTED_KEY, "UNTRUSTED_KEY"),
        (b"old-series", pkg::WRONG_SERIES, "WRONG_SERIES"),
        (b"bad-manifest", pkg::BAD_MANIFEST, "BAD_MANIFEST"),
        (b"conflict", pkg::CONFLICT, "CONFLICT"),
    ];
    for (name, wanted, what) in refusals {
        let done = pkgd.install(index.get(name)?, &stafeto);
        if !is(done, wanted) || !snap(pkgd)?.same(&one) {
            say!(
                "refusal of {} failed",
                core::str::from_utf8(name).unwrap_or("?")
            );
            return Err("a refusal");
        }
        say!("refused {what}, nothing changed");
    }
    let second = index.get(b"second")?;
    let bad_hash = Install {
        bad_hash: true,
        ..Install::new(b"stafeto", steps)
    };
    if !is(pkgd.install(second, &bad_hash), pkg::BAD_HASH) || !snap(pkgd)?.same(&one) {
        return Err("BAD_HASH");
    }
    say!("refused BAD_HASH, nothing changed");
    let too_long = Install {
        extra_byte: true,
        ..Install::new(b"stafeto", steps)
    };
    if !is(pkgd.install(second, &too_long), pkg::TOO_LONG) || !snap(pkgd)?.same(&one) {
        return Err("TOO_LONG");
    }
    say!("refused TOO_LONG, the receipt is gone, nothing changed");
    // A receipt of a package that is not finished: INSTALL_CANCEL frees the store and its space.
    cancel(pkgd, second, &one)?;
    for (size, wanted, what) in [
        (70 * 1024 * 1024u64, pkg::NO_MEMORY, "NO_MEMORY"),
        (600 * 1024 * 1024, pkg::NO_SPACE, "NO_SPACE"),
    ] {
        let mut w = Writer::new();
        let record = pkg::Begin {
            name: b"huge",
            version: b"1",
            size,
            sha256: [1; 32],
            repository: b"stafeto",
            flags: 1,
        };
        record.write(&mut w).map_err(|_| "a BEGIN")?;
        if !is(pkgd.change(w.as_bytes(), true, false), wanted) || !snap(pkgd)?.same(&one) {
            return Err("a package too big");
        }
        say!("refused {what}, nothing changed");
    }
    let mut w = Writer::new();
    let unknown = pkg::Begin {
        name: b"hello2",
        version: b"1",
        size: 8192,
        sha256: [1; 32],
        repository: b"nowhere",
        flags: 1,
    };
    unknown.write(&mut w).map_err(|_| "a BEGIN")?;
    if !is(pkgd.change(w.as_bytes(), true, false), pkg::INVALID) {
        return Err("a repository that is not known");
    }
    say!("refused INVALID for a repository the store does not know, nothing changed");
    // 3. Without the superuser: every change is refused, with the session or without one.
    not_allowed(pkgd, second, &one)?;
    session_goes(pkgd, second, &one)?;
    foreign(pkgd, second, &one)?;
    // 4. A group: nothing before its end, both after it.
    let big = index.get(b"big")?;
    let wide = index.get(b"wide")?;
    let part = Install {
        end: false,
        ..Install::new(b"stafeto", steps)
    };
    pkgd.install(big, &part)
        .map_err(|_| "big, the first of a group")?;
    if snap(pkgd)?.has(b"big").is_some() || mode_of(b"/big/data").is_some() {
        return Err("a package of an open group is there before its end");
    }
    pkgd.install(wide, &stafeto)
        .map_err(|_| "wide, the end of the group")?;
    let group = snap(pkgd)?;
    let mut head = [0u8; 64];
    if group.stat.disk != 3
        || group.stat.generation != one.stat.generation + 1
        || mode_of(b"/big/data").is_none()
        || mode_of(b"/wide/f0999").is_none()
        || read_file(b"/big/data", &mut head) != Some(64)
        || head
            .iter()
            .enumerate()
            .any(|(i, &b)| b != (i ^ (i >> 8) ^ (i >> 16)) as u8)
    {
        return Err("the group");
    }
    say!("group of big and wide: nothing before its end, both after, one generation");
    replace(pkgd, index, steps)?;
    changes(pkgd, index, steps)?;
    own_repository(pkgd, index)?;
    // 6. wide goes, and its space comes back.
    let before = snap(pkgd)?;
    pkgd.remove(&[b"wide"], true)
        .map_err(|_| "REMOVE of wide")?;
    let removed = snap(pkgd)?;
    if removed.has(b"wide").is_some()
        || mode_of(b"/wide/f0000").is_some()
        || removed.stat.free != before.stat.free + wide.blocks()
        || !is(pkgd.remove(&[b"wide"], true), pkg::NOT_FOUND)
    {
        return Err("the removal of wide");
    }
    say!("removed wide: the names are gone, its space is back, a second REMOVE is NOT_FOUND");
    if steps {
        long_names(pkgd, index)?;
    }
    let last = snap(pkgd)?;
    say!(
        "final status generation={} free={} disk={}",
        last.stat.generation,
        last.stat.free,
        last.stat.disk
    );
    say!("full scenario done");
    Ok(())
}

/// A receipt cut off by INSTALL_CANCEL: the group goes, and the space with it.
fn cancel(pkgd: &Pkgd, e: &Entry, was: &Snap) -> Result<(), Fail> {
    let mut w = Writer::new();
    let begin = pkg::Begin {
        name: e.name(),
        version: &e.version[..e.version_len],
        size: e.size,
        sha256: e.sha256,
        repository: b"stafeto",
        flags: 1,
    };
    begin.write(&mut w).map_err(|_| "a BEGIN")?;
    let receipt = pkgd
        .change(w.as_bytes(), true, false)
        .map_err(|_| "BEGIN to cancel")?;
    let mut buf = [0u8; 96];
    // SAFETY: a NUL-terminated path.
    let fd = unsafe { c::open(e.path(&mut buf), O_RDONLY) };
    if fd < 0 {
        return Err("the file of the package");
    }
    // Half of the package: four cells.
    let mut got = 0;
    while got < pkg::CELL_BYTES as usize {
        // SAFETY: the cell is in the mapped buffer.
        let n = unsafe { c::read(fd, cell(0).add(got), pkg::CELL_BYTES as usize - got) };
        if n <= 0 {
            break;
        }
        got += n as usize;
    }
    // SAFETY: the descriptor opened above.
    unsafe { c::close(fd) };
    pkgd.feed(receipt, 0, got as u32)
        .map_err(|_| "FEED before the cancel")?;
    let done = pkgd.word(Method::InstallCancel, receipt, &mut [0; MESSAGE_MAX]);
    if done.is_err() || !is(pkgd.feed(receipt, 0, 1), pkg::INVALID) {
        return Err("INSTALL_CANCEL");
    }
    if !snap(pkgd)?.same(was) {
        return Err("the state after INSTALL_CANCEL");
    }
    say!("INSTALL_CANCEL: the receipt is gone, the state is as it was");
    Ok(())
}

/// A change by a process that is not the superuser, or one that brings no identity session.
fn not_allowed(pkgd: &Pkgd, e: &Entry, was: &Snap) -> Result<(), Fail> {
    posix_abi::process::seteuid(1000).map_err(|_| "seteuid(1000)")?;
    let mut w = Writer::new();
    let begin = pkg::Begin {
        name: e.name(),
        version: &e.version[..e.version_len],
        size: e.size,
        sha256: e.sha256,
        repository: b"stafeto",
        flags: 1,
    };
    let mut refused =
        begin.write(&mut w).is_ok() && is(pkgd.change(w.as_bytes(), true, false), pkg::NOT_ALLOWED);
    refused &= is(pkgd.remove(&[b"hello"], true), pkg::NOT_ALLOWED);
    refused &= is(pkgd.serial_set(b"stafeto", 9, true), pkg::NOT_ALLOWED);
    refused &= is(pkgd.world_set(b"hello", false, true), pkg::NOT_ALLOWED);
    refused &= is(
        pkgd.blob_set(Method::SettingsSet, 100, true),
        pkg::NOT_ALLOWED,
    );
    refused &= is(
        pkgd.blob_set(Method::RevokedSet, 600, true),
        pkg::NOT_ALLOWED,
    );
    posix_abi::process::seteuid(0).map_err(|_| "seteuid(0) back")?;
    // The superuser without a session of identity is refused too.
    refused &= is(pkgd.remove(&[b"hello"], false), pkg::NOT_ALLOWED);
    refused &= is(pkgd.world_set(b"hello", false, false), pkg::NOT_ALLOWED);
    if !refused || !snap(pkgd)?.same(was) {
        return Err("NOT_ALLOWED");
    }
    say!(
        "not allowed without UID 0, or without an identity session: begin, remove, serial, settings, revoked"
    );
    Ok(())
}

/// The settings, the serial and the list of revocations.
fn changes(pkgd: &Pkgd, index: &Index, steps: bool) -> Result<(), Fail> {
    // The settings of the owner: games, then games2 in a blob of three cells; the layer follows.
    let (len, _) = load_blob(b"settings1.blob")?;
    pkgd.blob_set(Method::SettingsSet, len, true)
        .map_err(|_| "SETTINGS_SET games")?;
    let mut text = [0u8; 64];
    if mode_of(b"/etc/pkg/keys/games.pub").is_none()
        || read_file(b"/etc/pkg/repositories", &mut text).is_none()
    {
        return Err("the settings layer games");
    }
    let (len, sum) = load_blob(b"settings2.blob")?;
    pkgd.blob_set(Method::SettingsSet, len, true)
        .map_err(|_| "SETTINGS_SET games2")?;
    let (total, parts, _) = pkgd.settings_blob()?;
    if total != len || fnv(&scratch()[..total]) != sum || parts < 2 {
        return Err("the settings blob read back");
    }
    if mode_of(b"/etc/pkg/keys/games2.pub").is_none()
        || mode_of(b"/etc/pkg/keys/games.pub").is_some()
    {
        return Err("the settings layer games2");
    }
    say!(
        "settings: games then games2, the layer follows, the blob reads back whole in {parts} parts"
    );
    let (len, _) = load_blob(b"settings-bad.blob")?;
    if !is(pkgd.blob_set(Method::SettingsSet, len, true), pkg::INVALID) {
        return Err("a bad blob");
    }
    let (total2, _, _) = pkgd.settings_blob()?;
    if total2 != total || mode_of(b"/etc/pkg/keys/games2.pub").is_none() {
        return Err("a bad blob left a trace");
    }
    say!("settings: a blob that breaks the rules is INVALID, the old one stays");
    // The serial of a repository never goes back.
    let ok = pkgd.serial_set(b"games2", 2, true).is_ok()
        && pkgd.serial(b"games2") == Ok(2)
        && is(pkgd.serial_set(b"games2", 1, true), pkg::ROLLBACK)
        && pkgd.serial(b"games2") == Ok(2)
        && pkgd.serial_set(b"games2", 2, true).is_ok();
    if !ok {
        return Err("the serial");
    }
    say!("serial: 2 is set, 1 is ROLLBACK, 2 again changes nothing");
    // A package signed by the second key, then the list that revokes it.
    let keyb = index.get(b"keyb")?;
    pkgd.install(keyb, &Install::new(b"stafeto", steps))
        .map_err(|_| "keyb")?;
    if mode_of(b"/opt/keyb/bin/keyb").is_none() {
        return Err("keyb is not in the tree");
    }
    // The flag "world" is changed by itself: a dependency and back, the table alone.
    let before = snap(pkgd)?;
    if pkgd.world_set(b"keyb", false, true).is_err()
        || snap(pkgd)?.has(b"keyb") != Some(pkg::ENTRY_DEPENDENCY)
        || pkgd.world_set(b"keyb", false, true).is_err()
        || pkgd.world_set(b"keyb", true, true).is_err()
        || snap(pkgd)?.has(b"keyb") != Some(pkg::ENTRY_WORLD)
        || !is(pkgd.world_set(b"nobody", true, true), pkg::NOT_FOUND)
        || mode_of(b"/opt/keyb/bin/keyb").is_none()
        || snap(pkgd)?.stat.generation == before.stat.generation
    {
        return Err("WORLD_SET");
    }
    say!(
        "WORLD_SET: dependency and back, the same flag changes nothing, an unknown name is NOT_FOUND"
    );
    let (len, _) = load_blob(b"revoked-2.list")?;
    pkgd.blob_set(Method::RevokedSet, len, true)
        .map_err(|_| "REVOKED_SET 2")?;
    let now = snap(pkgd)?;
    if now.has(b"keyb") != Some(pkg::ENTRY_WORLD | pkg::ENTRY_REVOKED)
        || mode_of(b"/opt/keyb/bin/keyb").is_some()
    {
        return Err("keyb is not detached and flagged");
    }
    let (len, _) = load_blob(b"revoked-1.list")?;
    if !is(pkgd.blob_set(Method::RevokedSet, len, true), pkg::ROLLBACK) {
        return Err("a list of a smaller number");
    }
    let (len, _) = load_blob(b"revoked-2.list")?;
    // SAFETY: the buffer is mapped; a byte of the signature of the list.
    unsafe { *(BUFFER_AT as *mut u8).add(len - 456 + 130) ^= 1 };
    if !is(
        pkgd.blob_set(Method::RevokedSet, len, true),
        pkg::BAD_SIGNATURE,
    ) {
        return Err("a list with a bad signature");
    }
    if !is(
        pkgd.install(keyb, &Install::new(b"stafeto", steps)),
        pkg::REVOKED,
    ) {
        return Err("a package of a revoked key");
    }
    say!(
        "revoked: keyb is detached and flagged, an older list is ROLLBACK, a bad signature is BAD_SIGNATURE, the key is REVOKED"
    );
    Ok(())
}

/// Five packages whose names and versions are as long as they may be: LIST at its worst.
fn long_names(pkgd: &Pkgd, index: &Index) -> Result<(), Fail> {
    for n in 1..=5u8 {
        let mut name = [b'a'; 63];
        name[..18].copy_from_slice(b"long-name-package-");
        name[62] = b'0' + n;
        let e = index.get(&name)?;
        pkgd.install(e, &Install::new(b"stafeto", true))
            .map_err(|_| "a package of long names")?;
    }
    let mut names = [([0; 64], 0); 16];
    let listed = pkgd.list(&mut names, false).map_err(|_| "LIST")?;
    if listed < 5 {
        return Err("LIST of long names");
    }
    say!("five packages of the longest names are listed");
    Ok(())
}

/// The second run of the full scenario: what the first left is in place.
fn after_restart(pkgd: &Pkgd, now: &Snap) -> Result<(), Fail> {
    let (total, _, _) = pkgd.settings_blob()?;
    let (len, sum) = load_blob(b"settings2.blob")?;
    if now.has(b"hello").is_none()
        || now.has(b"wide").is_some()
        || now.has(b"keyb").is_some()
        || total != len
        || fnv(&scratch()[..total]) != sum
        || pkgd.serial(b"games2") != Ok(2)
        || mode_of(b"/big/data").is_none()
        || mode_of(b"/wide/f0000").is_some()
        || mode_of(b"/opt/keyb/bin/keyb").is_some()
        || mode_of(b"/etc/pkg/keys/games2.pub").is_none()
    {
        return Err("the store after a restart");
    }
    hello()?;
    say!(
        "status generation={} free={} disk={}",
        now.stat.generation,
        now.stat.free,
        now.stat.disk
    );
    say!(
        "restart: hello runs, big, the settings and the serial are in place, wide and keyb are not"
    );
    Ok(())
}

/// Doom from the packages `freedoom` and `doomgeneric`, built by `cargo xtask pkg-build`, installed
/// as a group; on the machine started again on the same disk, in place.
fn doom(pkgd: &Pkgd, index: &Index) -> Result<(), Fail> {
    let now = begin(pkgd)?;
    let (wad, program) = (&b"/games/freedoom1.wad"[..], &b"/bin/doom"[..]);
    if now.has(b"doomgeneric").is_some() {
        if now.has(b"freedoom").is_none() || mode_of(program).is_none() || mode_of(wad).is_none() {
            return Err("Doom is not in place after the restart");
        }
        say!("restart: Doom is in place, listed and in the tree");
        return Ok(());
    }
    let began = rt::time::now();
    let part = Install {
        end: false,
        ..Install::new(b"stafeto", false)
    };
    pkgd.install(index.get(b"freedoom")?, &part)
        .map_err(|_| "the installation of freedoom")?;
    pkgd.install(index.get(b"doomgeneric")?, &Install::new(b"stafeto", false))
        .map_err(|_| "the installation of doomgeneric")?;
    say!("Doom installed in {} ms", since_ms(began));
    let listed = snap(pkgd)?;
    if listed.has(b"freedoom").is_none()
        || listed.has(b"doomgeneric").is_none()
        || mode_of(program).is_none()
        || mode_of(wad).is_none()
    {
        return Err("Doom is not in the tree");
    }
    say!(
        "Doom installed: freedoom and doomgeneric as a group, the program and the WAD are in the tree"
    );
    Ok(())
}

impl Pkgd {
    /// A session of its own for a child of this one: another label at the service.
    fn other(&self) -> Result<Pkgd, Fail> {
        rt::service::clone_session(&self.0, &Method::Clone.header().bytes())
            .map(Pkgd)
            .map_err(|_| "CLONE")
    }

    /// The request of INSTALL_BEGIN for `e` from `repository`.
    fn begin_request(e: &Entry, repository: &[u8]) -> Result<Writer, Fail> {
        let mut w = Writer::new();
        pkg::Begin {
            name: e.name(),
            version: &e.version[..e.version_len],
            size: e.size,
            sha256: e.sha256,
            repository,
            flags: 1,
        }
        .write(&mut w)
        .map_err(|_| "a BEGIN")?;
        Ok(w)
    }
}

/// A session that goes while its INSTALL_BEGIN waits for the worker, and one that goes with a receipt
/// open, leave the store free for the next session.
fn session_goes(pkgd: &Pkgd, e: &Entry, was: &Snap) -> Result<(), Fail> {
    let request = Pkgd::begin_request(e, b"stafeto")?;
    // The begin is given and the session closes before anyone takes its result.
    {
        let other = pkgd.other()?;
        let identity = posix_abi::process::identity()
            .and_then(|i| sys::handle_duplicate(i, Rights::NOTIFY | Rights::TRANSFER).ok())
            .ok_or("no identity session")?;
        sys::send_handles(&other.0, request.as_bytes(), [identity.erase()])
            .map_err(|_| "BEGIN of a session that goes")?;
    }
    cancel(pkgd, e, was)?;
    // A session that goes with a receipt open.
    {
        let other = pkgd.other()?;
        other
            .change(request.as_bytes(), true, false)
            .map_err(|_| "BEGIN of a session that goes with a receipt")?;
    }
    cancel(pkgd, e, was)?;
    say!("a session that goes at once, or with a receipt open, leaves the store free");
    Ok(())
}

/// A receipt is its session's: another session cannot feed it, commit it or cancel it.
fn foreign(pkgd: &Pkgd, e: &Entry, was: &Snap) -> Result<(), Fail> {
    let request = Pkgd::begin_request(e, b"stafeto")?;
    let receipt = pkgd
        .change(request.as_bytes(), true, false)
        .map_err(|_| "BEGIN")?;
    let other = pkgd.other()?;
    let mut w = Writer::new();
    pkg::write_commit(receipt, pkg::COMMIT_END, &mut w).map_err(|_| "COMMIT")?;
    let refused = is(other.feed(receipt, 0, 16), pkg::INVALID)
        && is(other.change(w.as_bytes(), false, false), pkg::INVALID)
        && is(
            other.word(Method::InstallCancel, receipt, &mut [0; MESSAGE_MAX]),
            pkg::INVALID,
        );
    // The holder still has it, and ends it.
    let held = pkgd
        .word(Method::InstallCancel, receipt, &mut [0; MESSAGE_MAX])
        .is_ok();
    if !refused || !held {
        return Err("a receipt of another session");
    }
    // The next receipt of the holder begins as soon as the worker dropped this one.
    cancel(pkgd, e, was)?;
    say!("another session cannot feed, commit or cancel a receipt it does not hold");
    Ok(())
}

/// `hello` replaced by a new version, a replacement that conflicts refused, and a package of the
/// owner's repository (its key is in the settings blob) installed, the same signed by the release key refused.
fn replace(pkgd: &Pkgd, index: &Index, steps: bool) -> Result<(), Fail> {
    let before = snap(pkgd)?;
    let stafeto = Install::new(b"stafeto", steps);
    pkgd.install(index.get(b"hello-2")?, &stafeto)
        .map_err(|_| "hello 2.0")?;
    let after = snap(pkgd)?;
    let mut total = 0;
    let meta = pkgd.info(b"hello", &mut total).map_err(|_| "INFO")?;
    if after.stat.generation != before.stat.generation + 1
        || after.stat.disk != before.stat.disk
        || !meta[..total.min(4096)]
            .windows(12)
            .any(|w| w == b"version 2.0\n")
    {
        return Err("the replacement of hello");
    }
    hello()?;
    let conflict = index.get(b"hello-conflict")?;
    if !is(pkgd.install(conflict, &stafeto), pkg::CONFLICT) || !snap(pkgd)?.same(&after) {
        return Err("a replacement that conflicts");
    }
    hello()?;
    say!(
        "hello replaced by version 2.0: the new program runs, a replacement that conflicts is refused and the old one runs"
    );
    Ok(())
}

/// Packages of the owner's repository `games2`, whose key the settings blob holds.
fn own_repository(pkgd: &Pkgd, index: &Index) -> Result<(), Fail> {
    let before = snap(pkgd)?;
    let own = Install::new(b"games2", false);
    pkgd.install(index.get(b"own")?, &own)
        .map_err(|_| "a package of games2")?;
    let after = snap(pkgd)?;
    if after.has(b"own").is_none() || mode_of(b"/opt/own/bin/own").is_none() {
        return Err("the package of games2 is not there");
    }
    if !is(
        pkgd.install(index.get(b"own-bad")?, &own),
        pkg::UNTRUSTED_KEY,
    ) || !snap(pkgd)?.same(&after)
        || before.stat.disk + 1 != after.stat.disk
    {
        return Err("a package of games2 signed by the release key");
    }
    say!(
        "own repository: a package signed by the key of games2 is installed, one signed by the release key is UNTRUSTED_KEY"
    );
    Ok(())
}
