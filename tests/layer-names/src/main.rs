// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the names of the layered root (`cargo xtask layer-names`). A POSIX program of the
//! superuser, started by init after the layer service said READY, that speaks to the service
//! directly: TakeRoot for its root, SESSION with a copy of its identity session, and the names
//! (`proto_fs::names`) with raw messages. The pass of a file of the layer is spent with ADOPT in a
//! session of its own with the data file service, and its bytes are read there. The volume is
//! made offline (`data_image::LAYER_VOLUME_ENTRIES`) and the lower set is the boot image
//! (`rootfs.rs`, `boot-layer-names.img`).
//!
//! Each check prints `layer-names: <check> ok` or `layer-names: <check> FAILED: <why>`; the last
//! line is `layer-names: read checks passed` when none failed. The checks after `drop privileges`
//! run as user 1000, on the session that was made before (the service reads the generation of the
//! process's record again) and on a new one.

#![no_std]
#![no_main]

use core::ffi::c_int;
use core::fmt::Write as _;
use proto_data as p;
use proto_fs::names::{self as n, NameMethod, OpenAnswer, UPPER_INO_TAG};
use proto_layer as l;
use proto_wire::{Reader, Writer};
use rt::abi::{MESSAGE_MAX, Rights};
use rt::handle::{Any, Channel, Handle};

// The C library and the layer under it are linked for the symbols the start and `setuid` need.
use libc_ffi as _;
use posix_abi as _;

mod restart;
mod scale;

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

unsafe extern "C" {
    fn write(fd: c_int, buf: *const u8, count: usize) -> isize;
    fn usleep(micros: u32) -> c_int;
    fn setgroups(count: usize, list: *const u32) -> c_int;
    fn setgid(id: u32) -> c_int;
    fn setuid(id: u32) -> c_int;
}

/// One line to the console, `layer-names: ` first.
fn say(args: core::fmt::Arguments<'_>) {
    struct Line([u8; 240], usize);
    impl core::fmt::Write for Line {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let room = self.0.len() - self.1 - 1;
            let n = s.len().min(room);
            self.0[self.1..self.1 + n].copy_from_slice(&s.as_bytes()[..n]);
            self.1 += n;
            Ok(())
        }
    }
    let mut line = Line([0; 240], 0);
    let _ = line.write_str("layer-names: ");
    let _ = line.write_fmt(args);
    line.0[line.1] = b'\n';
    // SAFETY: the buffer holds `line.1 + 1` bytes.
    unsafe { write(1, line.0.as_ptr(), line.1 + 1) };
}

struct Checks {
    failed: u32,
}

impl Checks {
    fn ok(&mut self, name: &str) {
        say(format_args!("{name} ok"));
    }

    fn fail(&mut self, name: &str, why: core::fmt::Arguments<'_>) {
        self.failed += 1;
        say(format_args!("{name} FAILED: {why}"));
    }

    fn check(&mut self, name: &str, result: Result<(), core::fmt::Arguments<'_>>) {
        match result {
            Ok(()) => self.ok(name),
            Err(why) => self.fail(name, why),
        }
    }
}

/// A reply: its bytes and the handles it brought.
struct Answer {
    bytes: [u8; MESSAGE_MAX],
    len: usize,
    reply: rt::sys::Reply,
}

impl Answer {
    fn status(&self) -> u32 {
        Reader::new(&self.bytes[..self.len])
            .u32()
            .unwrap_or(u32::MAX)
    }

    fn all(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

fn call(
    to: &Handle<Channel>,
    request: &[u8],
    handles: impl Into<rt::handle::Outgoing>,
) -> Option<Answer> {
    let reply = rt::sys::send_handles(to, request, handles).ok()?;
    let mut answer = Answer {
        bytes: [0; MESSAGE_MAX],
        len: 0,
        reply,
    };
    answer.len = answer.reply.bytes(&mut answer.bytes).len();
    Some(answer)
}

/// The root of a service from the process service (TakeRoot), asked again while it is not
/// registered yet.
fn take_root(which: u32) -> Option<Handle<Channel>> {
    let mut w = Writer::new();
    proto_process::take_root(which, &mut w).ok()?;
    for _ in 0..500 {
        let mut a = call(
            posix_abi::process::client().session(),
            w.as_bytes(),
            rt::handle::Outgoing::new(),
        )?;
        match a.status() {
            0 => return a.reply.handles.take::<Channel>(0).ok(),
            proto_process::UNREGISTERED => {
                // SAFETY: a plain call.
                unsafe { usleep(10_000) };
            }
            _ => return None,
        }
    }
    None
}

/// A copy of the identity session for a request to carry.
fn identity() -> Option<Handle<Any>> {
    let identity = posix_abi::process::identity()?;
    rt::sys::handle_duplicate(
        identity,
        Rights::NOTIFY | Rights::TRANSFER | Rights::DUPLICATE,
    )
    .ok()
    .map(Handle::erase)
}

/// A session from a root: `header` is the SESSION of the service.
fn session(root: &Handle<Channel>, header: proto_wire::Header) -> Option<Handle<Channel>> {
    let mut a = call(root, &header.bytes(), [identity()?])?;
    if a.status() != 0 {
        say(format_args!("SESSION answered {}", a.status()));
        return None;
    }
    a.reply.handles.take::<Channel>(0).ok()
}

/// What OPEN gave.
#[allow(clippy::large_enum_variant)]
enum Opened {
    Redirect {
        target: u32,
        path: [u8; 512],
        len: usize,
    },
    Pass(Handle<Any>),
    Directory(u32),
    Status(u32),
}

fn open(s: &Handle<Channel>, flags: u32, path: &str) -> Opened {
    let mut w = Writer::new();
    if n::write_open(flags, path.as_bytes(), &mut w).is_err() {
        return Opened::Status(u32::MAX);
    }
    let Some(mut a) = call(s, w.as_bytes(), rt::handle::Outgoing::new()) else {
        return Opened::Status(u32::MAX);
    };
    match OpenAnswer::read(a.all()) {
        Ok(OpenAnswer::Redirect(r)) => {
            let mut p = [0u8; 512];
            p[..r.path.len()].copy_from_slice(r.path);
            Opened::Redirect {
                target: r.target,
                path: p,
                len: r.path.len(),
            }
        }
        Ok(OpenAnswer::Pass) => match a.reply.handles.take_any(0) {
            Ok(h) => Opened::Pass(h),
            Err(_) => Opened::Status(u32::MAX - 1),
        },
        Ok(OpenAnswer::Directory { handle }) => Opened::Directory(handle),
        Err(_) => Opened::Status(a.status()),
    }
}

fn stat(s: &Handle<Channel>, path: &str) -> Result<proto_fs::NodeInfo, u32> {
    let mut w = Writer::new();
    n::write_stat(0, path.as_bytes(), &mut w).map_err(|_| u32::MAX)?;
    let a = call(s, w.as_bytes(), rt::handle::Outgoing::new()).ok_or(u32::MAX)?;
    n::read_info(a.all()).map_err(|_| a.status())
}

/// The names of a listing.
struct Names {
    names: [[u8; 40]; 48],
    lens: [usize; 48],
    count: usize,
}

impl Names {
    fn count_of(&self, name: &str) -> usize {
        (0..self.count)
            .filter(|&i| &self.names[i][..self.lens[i]] == name.as_bytes())
            .count()
    }

    fn any_starts(&self, prefix: &str) -> bool {
        (0..self.count).any(|i| self.names[i][..self.lens[i]].starts_with(prefix.as_bytes()))
    }
}

/// Every name of the description `h`, asked for until `more` is 0 (at most 64 requests).
fn list(s: &Handle<Channel>, h: u32) -> Option<Names> {
    let mut out = Names {
        names: [[0; 40]; 48],
        lens: [0; 48],
        count: 0,
    };
    for _ in 0..64 {
        let mut w = Writer::new();
        n::write_handle(NameMethod::ReadDir, h, &mut w).ok()?;
        let a = call(s, w.as_bytes(), rt::handle::Outgoing::new())?;
        let (more, _, entries) = n::read_dir_reply(a.all()).ok()?;
        for e in entries {
            let e = e.ok()?;
            if out.count < out.names.len() && e.name.len() <= 40 {
                out.names[out.count][..e.name.len()].copy_from_slice(e.name);
                out.lens[out.count] = e.name.len();
                out.count += 1;
            }
        }
        if !more {
            return Some(out);
        }
    }
    None
}

fn list_of(s: &Handle<Channel>, path: &str) -> Option<Names> {
    match open(s, proto_fs::READ_ONLY | proto_fs::DIRECTORY_ONLY, path) {
        Opened::Directory(h) => {
            let names = list(s, h);
            let mut w = Writer::new();
            let _ = n::write_handle(NameMethod::Close, h, &mut w);
            let _ = call(s, w.as_bytes(), rt::handle::Outgoing::new());
            names
        }
        _ => None,
    }
}

/// The bytes a pass leads to, read in a session of the data file service.
fn read_pass(data: &Handle<Channel>, pass: Handle<Any>, out: &mut [u8; 128]) -> Option<usize> {
    let mut w = Writer::new();
    p::adopt(&mut w).ok()?;
    let a = call(data, w.as_bytes(), [pass])?;
    let mut r = p::reply(a.all()).ok()?;
    let handle = r.u32().ok()?;
    let mut w = Writer::new();
    p::read(handle, 100, &mut w).ok()?;
    let a = call(data, w.as_bytes(), rt::handle::Outgoing::new())?;
    let mut r = p::reply(a.all()).ok()?;
    let count = r.u32().ok()? as usize;
    let bytes = r.bytes(count).ok()?;
    out[..count].copy_from_slice(bytes);
    Some(count)
}

fn expect_bytes(
    data: &Handle<Channel>,
    s: &Handle<Channel>,
    path: &str,
    want: &[u8],
) -> Result<(), core::fmt::Arguments<'static>> {
    let Opened::Pass(pass) = open(s, proto_fs::READ_ONLY, path) else {
        return Err(format_args!("no pass for the file"));
    };
    let mut buf = [0u8; 128];
    let Some(n) = read_pass(data, pass, &mut buf) else {
        return Err(format_args!("the pass was not spent or read"));
    };
    if &buf[..n] != want {
        return Err(format_args!("the bytes differ"));
    }
    Ok(())
}

fn status_is(opened: &Opened, want: u32) -> bool {
    matches!(opened, Opened::Status(s) if *s == want)
}

/// Whether STAT of `path` answers a redirect to the RAM file service with the plain `want`.
fn stat_redirect_is(s: &Handle<Channel>, path: &str, want: &str) -> bool {
    let mut w = Writer::new();
    if n::write_stat(0, path.as_bytes(), &mut w).is_err() {
        return false;
    }
    let Some(a) = call(s, w.as_bytes(), rt::handle::Outgoing::new()) else {
        return false;
    };
    matches!(proto_fs::Redirect::read_reply(a.all()),
        Some(Ok(r)) if r.target == proto_fs::REDIRECT_RAM && r.path == want.as_bytes())
}

fn redirect_is(opened: &Opened, path: &str) -> bool {
    matches!(opened, Opened::Redirect { target, path: p, len }
        if *target == proto_fs::REDIRECT_RAM && &p[..*len] == path.as_bytes())
}

#[unsafe(no_mangle)]
extern "C" fn main(
    _argc: isize,
    _argv: *mut *mut core::ffi::c_char,
    _envp: *mut *mut core::ffi::c_char,
) -> c_int {
    match option_env!("STAFETO_LAYER_NAMES_MODE") {
        Some("scale") => return scale::run(),
        Some("restart") => return restart::run(),
        _ => {}
    }
    let mut t = Checks { failed: 0 };
    let (Some(root), Some(data_root)) = (
        take_root(proto_process::ROOT_LAYER),
        take_root(proto_process::ROOT_DATA),
    ) else {
        say(format_args!("session FAILED: no root"));
        return 1;
    };
    let (Some(names), Some(control), Some(data)) = (
        session(&root, NameMethod::Session.header()),
        session(&root, l::Method::Session.header()),
        session(&data_root, p::Method::Session.header()),
    ) else {
        say(format_args!("session FAILED: no session"));
        return 1;
    };
    t.ok("sessions");
    // The layer's own protocol through the second session.
    let status = {
        let a = call(
            &control,
            &l::Method::Status.header().bytes(),
            rt::handle::Outgoing::new(),
        );
        a.map(|a| l::Stat::read(a.all()))
    };
    t.check(
        "status",
        match status {
            Some(Ok(s))
                if s.flags == 0
                    && s.live == 0
                    && s.frozen == 0
                    && s.added == 10
                    && s.deleted == 2
                    && s.names == 12 =>
            {
                Ok(())
            }
            Some(Ok(_)) => Err(format_args!("the counts of the index differ")),
            _ => Err(format_args!("no status")),
        },
    );
    // A lower file and a lower directory go to the RAM file service with the whole path.
    t.check(
        "a lower file is a redirect",
        if redirect_is(
            &open(&names, proto_fs::READ_ONLY, "/lower/keep"),
            "/lower/keep",
        ) && redirect_is(
            &open(&names, proto_fs::READ_ONLY, "/etc/layer-lower"),
            "/etc/layer-lower",
        ) && redirect_is(
            &open(&names, proto_fs::READ_ONLY, "/bin/layer-names"),
            "/bin/layer-names",
        ) {
            Ok(())
        } else {
            Err(format_args!(
                "not a redirect to the RAM file service with the path"
            ))
        },
    );
    t.check(
        "a lower directory is a redirect",
        if redirect_is(
            &open(
                &names,
                proto_fs::READ_ONLY | proto_fs::DIRECTORY_ONLY,
                "/bin",
            ),
            "/bin",
        ) && redirect_is(
            &open(&names, proto_fs::READ_ONLY, "/private/lower"),
            "/private/lower",
        ) {
            Ok(())
        } else {
            Err(format_args!("not a redirect"))
        },
    );
    // The pass of a file of the layer: its bytes after ADOPT in a session of the data service.
    t.check(
        "the pass of a file of the layer",
        expect_bytes(
            &data,
            &names,
            "/etc/layer-own",
            b"owned bytes of the layer\n",
        ),
    );
    t.check(
        "a file of the layer shadows the lower one",
        expect_bytes(&data, &names, "/lower/shadowed", b"upper shadow\n"),
    );
    // Numbers.
    t.check(
        "stat numbers",
        match (stat(&names, "/etc/layer-own"), stat(&names, "/")) {
            (Ok(own), Ok(root_info)) => {
                if own.inode != (UPPER_INO_TAG | 5)
                    || own.device != 0
                    || own.uid != 1000
                    || own.permissions != 0o640
                    || own.size != 25
                    || own.kind != 2
                {
                    Err(format_args!(
                        "the file of the layer: number, device, owner, mode or size"
                    ))
                } else if root_info.kind != 1 || root_info.device != 0 {
                    Err(format_args!("the root"))
                } else {
                    Ok(())
                }
            }
            _ => Err(format_args!("a stat failed")),
        },
    );
    // A lower name is not stat'ed here: the answer is a redirect, and the RAM file service gives
    // the numbers and checks the rights of the caller's own session.
    t.check(
        "a stat of a lower name is a redirect",
        if stat_redirect_is(&names, "/lower/keep", "/lower/keep")
            && stat_redirect_is(&names, "/bin", "/bin")
            // A `..` after the first lower name is the RAM file service's to answer: the path
            // goes whole.
            && stat_redirect_is(&names, "/bin/../lower/keep", "/bin/../lower/keep")
        {
            Ok(())
        } else {
            Err(format_args!("not a redirect to the RAM file service"))
        },
    );
    // The merged listing of /etc: the layer's names, the lower names, no mark of deletion.
    t.check(
        "merged listing of a directory",
        match list_of(&names, "/etc") {
            Some(l) => {
                if l.count_of("layer-note") != 1
                    || l.count_of("layer-own") != 1
                    || l.count_of("layer-lower") != 1
                {
                    Err(format_args!(
                        "a name of the layer or of the lower set is not there once"
                    ))
                } else if l.count_of("layer-hidden") != 0 {
                    Err(format_args!("a deleted name is listed"))
                } else if l.any_starts(".wh.") {
                    Err(format_args!("a mark of deletion is listed"))
                } else if l.count_of(".") != 1 || l.count_of("..") != 1 {
                    Err(format_args!("the dot names"))
                } else {
                    Ok(())
                }
            }
            None => Err(format_args!("no listing")),
        },
    );
    t.check(
        "a name of the layer is listed once over the lower one",
        match list_of(&names, "/lower") {
            Some(l)
                if l.count_of("shadowed") == 1
                    && l.count_of("keep") == 1
                    && l.count_of("hidden") == 0 =>
            {
                Ok(())
            }
            Some(_) => Err(format_args!("shadowed, keep or hidden")),
            None => Err(format_args!("no listing")),
        },
    );
    t.check("the names a layer deleted are gone", {
        let a = open(&names, proto_fs::READ_ONLY, "/etc/layer-hidden");
        let b = open(&names, proto_fs::READ_ONLY, "/lower/hidden");
        if status_is(&a, proto_fs::NO_ENTRY)
            && status_is(&b, proto_fs::NO_ENTRY)
            && stat(&names, "/lower/hidden") == Err(proto_fs::NO_ENTRY)
        {
            Ok(())
        } else {
            Err(format_args!("a deleted name opens or stats"))
        }
    });
    // A `..` through a directory of the layer is exact in the index, so the marks and the shadows
    // of the layer are met; after the first lower name the path goes whole to the RAM file service,
    // which answers a `..` with a redirect that routes by the path.
    t.check("a dot dot in the index and after a lower name", {
        let hidden = open(&names, proto_fs::READ_ONLY, "/etc/../etc/layer-hidden");
        let below = open(&names, proto_fs::READ_ONLY, "/lowdir/../lowdir/l1");
        let kept = open(&names, proto_fs::READ_ONLY, "/bin/../lower/./keep");
        if !status_is(&hidden, proto_fs::NO_ENTRY) || !status_is(&below, proto_fs::NO_ENTRY) {
            Err(format_args!("a deleted name opens through a dot dot"))
        } else if !redirect_is(&kept, "/bin/../lower/keep") {
            Err(format_args!("the redirect does not carry the path whole"))
        } else {
            expect_bytes(&data, &names, "/lower/../lower/shadowed", b"upper shadow\n")
        }
    });
    t.check(
        "an opaque directory lists only its own names",
        match list_of(&names, "/lowdir") {
            Some(l)
                if l.count_of("u1") == 1
                    && l.count_of("l1") == 0
                    && l.count_of("l2") == 0
                    && l.count == 3 =>
            {
                if status_is(
                    &open(&names, proto_fs::READ_ONLY, "/lowdir/l1"),
                    proto_fs::NO_ENTRY,
                ) {
                    Ok(())
                } else {
                    Err(format_args!("a lower name opens below an opaque directory"))
                }
            }
            Some(_) => Err(format_args!("the listing")),
            None => Err(format_args!("no listing")),
        },
    );
    // A description: rewind lists the same names, fstat says directory, close frees it.
    t.check(
        "rewind fstat and close",
        match open(
            &names,
            proto_fs::READ_ONLY | proto_fs::DIRECTORY_ONLY,
            "/etc",
        ) {
            Opened::Directory(h) => {
                let first = list(&names, h);
                let mut w = Writer::new();
                let _ = n::write_handle(NameMethod::Rewind, h, &mut w);
                let rewound =
                    call(&names, w.as_bytes(), rt::handle::Outgoing::new()).map(|a| a.status());
                let second = list(&names, h);
                let mut w = Writer::new();
                let _ = n::write_handle(NameMethod::Fstat, h, &mut w);
                let info = call(&names, w.as_bytes(), rt::handle::Outgoing::new())
                    .map(|a| n::read_info(a.all()));
                let mut w = Writer::new();
                let _ = n::write_handle(NameMethod::Close, h, &mut w);
                let closed =
                    call(&names, w.as_bytes(), rt::handle::Outgoing::new()).map(|a| a.status());
                let mut w = Writer::new();
                let _ = n::write_handle(NameMethod::Close, h, &mut w);
                let again =
                    call(&names, w.as_bytes(), rt::handle::Outgoing::new()).map(|a| a.status());
                match (first, second, rewound, info, closed, again) {
                    (Some(a), Some(b), Some(0), Some(Ok(i)), Some(0), Some(s))
                        if a.count == b.count
                            && a.count >= 5
                            && i.kind == 1
                            && s == proto_fs::BAD_FD =>
                    {
                        Ok(())
                    }
                    _ => Err(format_args!("a call on the description answered wrong")),
                }
            }
            _ => Err(format_args!("no description")),
        },
    );
    // A name of the lower set is copied up before it is written (the answer to the write is
    // COPYING with a ticket, and WAIT says how the copy ended); a program is never copied, so the
    // copy of one ends with a read-only file system (a rename of a lower file is a copy up as well,
    // so the rename of the program takes the same way, and a lower directory does not move). The
    // volume has no hard links. The program is the probe's own file, which no later check needs to be
    // written.
    {
        let name = "the lower set is copied up before it is written";
        let ticket_of =
            |op: Option<n::ChangeOp>, flags: u32, path: &[u8], second: &[u8]| -> Option<u64> {
                let mut w = Writer::new();
                match op {
                    None => n::write_open(flags, path, &mut w).ok()?,
                    Some(op) => n::Change {
                        op,
                        a: 0o755,
                        b: 0,
                        first: path,
                        second,
                    }
                    .write(&mut w)
                    .ok()?,
                }
                let a = call(&names, w.as_bytes(), rt::handle::Outgoing::new())?;
                n::read_copying(a.all())?.ok()
            };
        // WAIT for a copy, asked again while it goes on: the status that ended it.
        let ended = |ticket: u64| -> Option<u32> {
            for _ in 0..3000 {
                let mut w = Writer::new();
                n::write_wait(ticket, &mut w).ok()?;
                let a = call(&names, w.as_bytes(), rt::handle::Outgoing::new())?;
                if a.status() != proto_fs::COPYING {
                    return Some(a.status());
                }
                // SAFETY: a plain call of relibc.
                unsafe { usleep(10_000) };
            }
            None
        };
        let program = b"/bin/layer-names";
        let t1 = ticket_of(None, proto_fs::WRITE_ONLY, program, b"");
        let t2 = ticket_of(None, proto_fs::WRITE_ONLY | proto_fs::CREATE, program, b"");
        let t3 = ticket_of(Some(n::ChangeOp::Chmod), 0, program, b"");
        let t4 = ticket_of(
            Some(n::ChangeOp::Rename),
            0,
            program,
            b"/bin/layer-names-moved",
        );
        let change = |op: n::ChangeOp, first: &[u8], second: &[u8]| {
            let mut w = Writer::new();
            let request = n::Change {
                op,
                a: 0o755,
                b: 0,
                first,
                second,
            };
            let _ = request.write(&mut w);
            call(&names, w.as_bytes(), rt::handle::Outgoing::new()).map(|a| a.status())
        };
        let rename = change(n::ChangeOp::Rename, b"/lower", b"/lower-moved");
        let link = change(n::ChangeOp::Link, b"/lower/keep", b"/lower/hard");
        let (Some(t1), Some(t2), Some(t3), Some(t4)) = (t1, t2, t3, t4) else {
            t.fail(name, format_args!("a write of the program was not COPYING"));
            return 1;
        };
        let (e1, e2, e3, e4) = (ended(t1), ended(t2), ended(t3), ended(t4));
        // A ticket the service never gave is a copy that is over; one that is over keeps its answer.
        let never = ended(0x7777_0001);
        let again = ended(t1);
        // The program is still the lower set's, whole.
        let still = redirect_is(
            &open(&names, proto_fs::READ_ONLY, "/bin/layer-names"),
            "/bin/layer-names",
        );
        let erofs = Some(proto_fs::READ_ONLY_FILESYSTEM);
        if e1 == erofs
            && e2 == erofs
            && e3 == erofs
            && e4 == erofs
            && never == Some(0)
            && again == erofs
            && still
            && rename == Some(proto_fs::CROSS_DEVICE)
            && link == Some(proto_fs::TOO_MANY_LINKS)
        {
            t.ok(name);
        } else {
            t.fail(
                name,
                format_args!(
                    "ended {e1:?} {e2:?} {e3:?} {e4:?}, never {never:?}, again {again:?}, rename {rename:?}, link {link:?}, still lower {still}"
                ),
            );
        }
    }
    // The superuser searches /private.
    t.check(
        "the superuser searches a closed directory",
        match open(&names, proto_fs::READ_ONLY, "/private/f") {
            Opened::Pass(_) => Ok(()),
            _ => Err(format_args!("not a pass")),
        },
    );
    t.check(
        "the superuser reads a closed file",
        match open(&names, proto_fs::READ_ONLY, "/etc/layer-secret") {
            Opened::Pass(_) => Ok(()),
            _ => Err(format_args!("not a pass")),
        },
    );
    // User 1000 from here on, on the old session and on a new one.
    // SAFETY: plain calls of relibc.
    let dropped =
        unsafe { setgroups(0, core::ptr::null()) == 0 && setgid(1000) == 0 && setuid(1000) == 0 };
    if !dropped {
        t.fail("drop privileges", format_args!("setuid refused"));
        return 1;
    }
    let fresh = session(&root, NameMethod::Session.header());
    for (label, s) in [
        ("the session of before", Some(&names)),
        ("a new session", fresh.as_ref()),
    ] {
        let Some(s) = s else {
            t.fail(label, format_args!("no session"));
            continue;
        };
        let mut name = [0u8; 64];
        let mut at = 0;
        for part in ["search denied for user 1000 on ", label] {
            name[at..at + part.len()].copy_from_slice(part.as_bytes());
            at += part.len();
        }
        let shown = core::str::from_utf8(&name[..at]).unwrap_or("search denied");
        t.check(shown, {
            let a = open(s, proto_fs::READ_ONLY, "/private/f");
            let b = open(s, proto_fs::READ_ONLY, "/private/lower");
            let dots = open(s, proto_fs::READ_ONLY, "/etc/../private/lower");
            let c = open(
                s,
                proto_fs::READ_ONLY | proto_fs::DIRECTORY_ONLY,
                "/private",
            );
            if status_is(&a, proto_fs::ACCESS_DENIED)
                && status_is(&b, proto_fs::ACCESS_DENIED)
                && status_is(&dots, proto_fs::ACCESS_DENIED)
                && status_is(&c, proto_fs::ACCESS_DENIED)
                && stat(s, "/private/f") == Err(proto_fs::ACCESS_DENIED)
            {
                Ok(())
            } else {
                Err(format_args!(
                    "a path below a closed directory of the layer opens"
                ))
            }
        });
    }
    t.check("a file whose own mode denies the read is denied", {
        let a = open(&names, proto_fs::READ_ONLY, "/etc/layer-secret");
        if status_is(&a, proto_fs::ACCESS_DENIED) {
            Ok(())
        } else {
            Err(format_args!(
                "a 0600 file of the superuser opens for user 1000"
            ))
        }
    });
    // A lower directory closed to the user (0700, the lower set's rights) is the RAM file
    // service's to refuse: the layer answers a redirect and its session checks the rights.
    t.check(
        "a closed lower directory is left to the RAM file service",
        if redirect_is(
            &open(&names, proto_fs::READ_ONLY, "/lowpriv/f"),
            "/lowpriv/f",
        ) && stat_redirect_is(&names, "/lowpriv/f", "/lowpriv/f")
        {
            Ok(())
        } else {
            Err(format_args!("not a redirect"))
        },
    );
    t.check(
        "the owner reads the file of the layer",
        expect_bytes(
            &data,
            &names,
            "/etc/layer-own",
            b"owned bytes of the layer\n",
        ),
    );
    t.check(
        "a lower file stays reachable",
        if redirect_is(
            &open(&names, proto_fs::READ_ONLY, "/lower/keep"),
            "/lower/keep",
        ) {
            Ok(())
        } else {
            Err(format_args!("not a redirect"))
        },
    );
    if t.failed == 0 {
        say(format_args!("read checks passed"));
        0
    } else {
        say(format_args!("{} checks failed", t.failed));
        1
    }
}
