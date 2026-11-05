// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the package service (xtask store-probe, pk3-design R17): the first POSIX
//! process of the image, root, with a session of `pkgd`. It asks while the service still
//! reads its disk (a LIST, an INFO, a CLONE and a STATUS every 5 ms: the steps of the
//! service under load), then looks at what the service published and at the tree its layers
//! made. A disk with no packages is the second run: nothing is listed and nothing is there.
//! Started with `hello` as its name (the program of a package), it exits with 42.

#![no_std]
#![no_main]

use core::ffi::{CStr, c_char, c_int, c_void};
use libc_ffi::{self as c, O_RDONLY, Timespec};
use proto_pkg::{self as pkg, Method, Stat};
use proto_wire::{Reader, Status, Writer};
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
    match run() {
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

    fn word(
        &self,
        method: Method,
        value: u32,
        out: &mut [u8; MESSAGE_MAX],
    ) -> Result<usize, Status> {
        let mut w = Writer::new();
        pkg::write_word(method, value, &mut w)?;
        self.call(w.as_bytes(), None, out)
    }

    fn status(&self) -> Result<Stat, Status> {
        let mut out = [0; MESSAGE_MAX];
        let len = self.call(&Method::Status.header().bytes(), None, &mut out)?;
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
            let len = self.call(w.as_bytes(), None, &mut out)?;
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
        let len = self.call(w.as_bytes(), None, &mut out)?;
        Reader::new(&out[4..len]).u64()
    }

    /// The names and flags of the entries, in `names`; how many.
    fn list(&self, names: &mut [([u8; 64], u32); 8], report: bool) -> Result<usize, Status> {
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
        let mut out = [0; MESSAGE_MAX];
        self.call(w.as_bytes(), Some(copy.erase()), &mut out)
            .map(drop)
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
        let mut names = [([0; 64], 0); 8];
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
    let mut names = [([0; 64], 0); 8];
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
