// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The scale checks of `cargo xtask layer-steps`: the live layer of the volume holds 8,192 names
//! and 2,005 marks of deletion (`data_image::layer_steps_entries`): a chain of 246 directories with
//! a file at its end (a path of 247 components), the directory `/etc` of 1,024 files that the lower
//! `/etc` lists beside, files in `d00` and on, the directory `/marks` of 2,000 marks, the opaque
//! directory `/opq` and `/mk2` of five marks. After the reads come the changes: at the depth of
//! 240, over a chain of 32 lower directories, of a directory of 1,024 names, into the opaque
//! directory, of a directory of marks, and a rename onto a directory of marks. The service has built its index in steps by the time the probe starts; the
//! longest step of each kind is what the service prints and the command reads (`steps` build).
//!
//! The copy up is measured with them: the probe writes a lower file of 64 MiB (`/lowbig/big`) before
//! the first read and waits for its copy after the last one, so that every request of the checks is
//! served while the worker thread of the service moves the bytes, and no step of the loop is longer
//! for it.

use super::{
    Checks, Opened, call, expect_bytes, open, read_pass, say, session, stat, stat_redirect_is,
    take_root, usleep,
};
use proto_data as p;
use proto_fs::names::{self as n, NameMethod};
use proto_layer as l;
use proto_wire::Writer;
use rt::handle::{Channel, Handle};

/// The names of the layer the probe counts: `data_image::STEPS_NAMES`, and the marks of the
/// volume (`STEPS_MARKS` and `STEPS_MK2_MARKS`).
const NAMES: u32 = 8192;
const MARKS: u32 = 2005;
/// The directories of the chain of lower directories below `/lowdeep` (`xtask::layer_steps`).
/// The service resolves a lower path one step of the RAM file service at a time (about 1,400
/// ticks each, polled in the steps of its loop), so the length of the path does not make a step
/// longer: the chain is `/lowdeep` and 32 directories.
const LOW_DEPTH: u32 = 32;
/// The names after the changes of the probe: `/lowdeep`, its directories and the one below them
/// made over the lower chain, the
/// `/mk2` the rename went over; the marks of `/marks` and of `/mk2` are gone.
/// The lower file of 64 MiB the probe writes while it measures: its copy makes `/lowbig` and
/// `/lowbig/big` names of the layer (`xtask::layer_steps`).
/// A build with `STAFETO_LAYER_NAMES_COPY=0` leaves the copy out (`cargo xtask layer-steps nocopy`:
/// the waits of the loop without it, to compare with the waits with it).
const COPY: bool = match option_env!("STAFETO_LAYER_NAMES_COPY") {
    Some(v) => !(v.len() == 1 && v.as_bytes()[0] == b'0'),
    None => true,
};
const COPIED_NAMES: u32 = if COPY { 2 } else { 0 };
const NAMES_AFTER: u32 = NAMES + LOW_DEPTH + 2 - 1 + COPIED_NAMES;
const BIG: &str = "/lowbig/big";
const BIG_BYTES: u64 = 64 << 20;
const LISTED: usize = 1024;
const CHAIN: usize = 246;

/// `count` times `piece`, then `tail`, in `out`; the text.
fn chain<'a>(out: &'a mut [u8; 512], count: usize, piece: &str, tail: &str) -> &'a str {
    let mut at = 0;
    for _ in 0..count {
        out[at..at + piece.len()].copy_from_slice(piece.as_bytes());
        at += piece.len();
    }
    out[at..at + tail.len()].copy_from_slice(tail.as_bytes());
    at += tail.len();
    core::str::from_utf8(&out[..at]).unwrap_or("")
}

/// The merged listing of `/etc` to its end: the names `x0000` and on seen once each, the other
/// names counted, and the requests it took.
struct Listed {
    all: usize,
    layer: usize,
    twice: usize,
    lower: usize,
    requests: u32,
}

fn list_etc(names: &rt::handle::Handle<rt::handle::Channel>) -> Option<Listed> {
    let Opened::Directory(h) = open(
        names,
        proto_fs::READ_ONLY | proto_fs::DIRECTORY_ONLY,
        "/etc",
    ) else {
        return None;
    };
    let mut seen = [0u8; LISTED];
    let mut out = Listed {
        all: 0,
        layer: 0,
        twice: 0,
        lower: 0,
        requests: 0,
    };
    for _ in 0..2000 {
        let mut w = Writer::new();
        n::write_handle(NameMethod::ReadDir, h, &mut w).ok()?;
        let a = call(names, w.as_bytes(), rt::handle::Outgoing::new())?;
        out.requests += 1;
        let (more, _, entries) = n::read_dir_reply(a.all()).ok()?;
        for e in entries {
            let e = e.ok()?;
            out.all += 1;
            let name = e.name;
            if name.len() == 5 && name[0] == b'x' && name[1..].iter().all(u8::is_ascii_digit) {
                let k = name[1..]
                    .iter()
                    .fold(0usize, |v, d| v * 10 + usize::from(d - b'0'));
                if k < LISTED {
                    seen[k] += 1;
                    out.layer += usize::from(seen[k] == 1);
                    out.twice += usize::from(seen[k] == 2);
                }
            } else if name == b"layer-lower" {
                out.lower += 1;
            }
        }
        if !more {
            let mut w = Writer::new();
            let _ = n::write_handle(NameMethod::Close, h, &mut w);
            let _ = call(names, w.as_bytes(), rt::handle::Outgoing::new());
            return Some(out);
        }
    }
    None
}

/// The write of the lower file of 64 MiB begins its copy: the ticket of COPYING.
fn begin_copy(names: &Handle<Channel>) -> Result<u64, u32> {
    let mut w = Writer::new();
    n::write_open(proto_fs::WRITE_ONLY, BIG.as_bytes(), &mut w).map_err(|_| u32::MAX)?;
    let a = call(names, w.as_bytes(), rt::handle::Outgoing::new()).ok_or(u32::MAX)?;
    match n::read_copying(a.all()) {
        Some(Ok(ticket)) => Ok(ticket),
        _ => Err(a.status()),
    }
}

/// WAIT for the copy, asked again every 200 ms of the probe's time until it is over: 0, or the
/// failure of the copy.
fn wait_copy(names: &Handle<Channel>, ticket: u64) -> u32 {
    for _ in 0..4000 {
        let mut w = Writer::new();
        if n::write_wait(ticket, &mut w).is_err() {
            return u32::MAX;
        }
        let Some(a) = call(names, w.as_bytes(), rt::handle::Outgoing::new()) else {
            return u32::MAX;
        };
        match a.status() {
            proto_fs::COPYING | l::STARTING => {
                // SAFETY: a plain call of relibc.
                unsafe { usleep(200_000) };
            }
            status => return status,
        }
    }
    u32::MAX
}

/// The copy is the layer's file: its size, and the bytes the lower file began with.
fn big_copy_is_there(
    data: &Handle<Channel>,
    names: &Handle<Channel>,
) -> Result<(), core::fmt::Arguments<'static>> {
    match stat(names, BIG) {
        Ok(info) if info.kind == 2 && info.size == BIG_BYTES => {}
        Ok(_) => return Err(format_args!("the copy is not a file of 64 MiB")),
        Err(_) => return Err(format_args!("no STAT of the copy")),
    }
    let Opened::Pass(pass) = open(names, proto_fs::READ_ONLY, BIG) else {
        return Err(format_args!("the copy gives no pass"));
    };
    let mut buf = [0u8; 128];
    let Some(count) = read_pass(data, pass, &mut buf) else {
        return Err(format_args!("the pass was not spent or read"));
    };
    // The lower file: the byte at i is (i % 251) | 1.
    if count != 100 || !(0..count).all(|i| buf[i] == ((i % 251) as u8 | 1)) {
        return Err(format_args!("the first bytes of the copy differ"));
    }
    Ok(())
}

pub fn run() -> i32 {
    let mut t = Checks { failed: 0 };
    let (Some(root), Some(data_root)) = (
        take_root(proto_process::ROOT_LAYER),
        take_root(proto_process::ROOT_DATA),
    ) else {
        say(format_args!("sessions FAILED: no root"));
        return 1;
    };
    let (Some(names), Some(control), Some(data)) = (
        session(&root, NameMethod::Session.header()),
        session(&root, l::Method::Session.header()),
        session(&data_root, proto_data::Method::Session.header()),
    ) else {
        say(format_args!("sessions FAILED: no session"));
        return 1;
    };
    t.ok("sessions");
    let status = call(
        &control,
        &l::Method::Status.header().bytes(),
        rt::handle::Outgoing::new(),
    )
    .map(|a| l::Stat::read(a.all()));
    t.check(
        "status counts the names of the layer",
        match status {
            Some(Ok(s)) if s.added == NAMES && s.deleted == MARKS && s.names == NAMES + MARKS => {
                Ok(())
            }
            Some(Ok(_)) => Err(format_args!("the counts of the index differ")),
            _ => Err(format_args!("no status")),
        },
    );
    // The copy of a lower file of 64 MiB goes on while the checks that follow are made.
    let ticket = if COPY { begin_copy(&names) } else { Ok(0) };
    if ticket.is_err() {
        say(format_args!(
            "a lower file of 64 MiB is written: no COPYING"
        ));
    }
    // A file at the end of a chain of 246 directories: 247 components, and the volume's path of it
    // 505 of 506 bytes.
    let mut buffer = [0u8; 512];
    let deep = chain(&mut buffer, CHAIN, "/a", "/f");
    t.check(
        "a file at the end of a chain of 247 components",
        expect_bytes(&data, &names, deep, b"the end of the chain\n"),
    );
    // A name of 200 bytes at two slashes is deferred by its length.
    let mut long_name = [0u8; 512];
    let long_path = chain(&mut long_name, 200, "n", "");
    let mut full = [0u8; 512];
    full[..6].copy_from_slice(b"/long/");
    full[6..6 + long_path.len()].copy_from_slice(long_path.as_bytes());
    t.check(
        "a file with a name of 200 bytes",
        expect_bytes(
            &data,
            &names,
            core::str::from_utf8(&full[..6 + long_path.len()]).unwrap_or(""),
            b"a long name\n",
        ),
    );
    // A path of 253 components: the walk goes through the 246 directories of the layer and the
    // 247th name is not there, so the whole path is the lower set's.
    let mut buffer = [0u8; 512];
    let long = chain(&mut buffer, 253, "/a", "");
    t.check(
        "a path of 253 components is the lower set's after the chain",
        if stat_redirect_is(&names, long, long) {
            Ok(())
        } else {
            Err(format_args!("not a redirect with the whole path"))
        },
    );
    // The last names of the table are found: a name of the last directory.
    t.check(
        "a name of the last directory of the layer",
        match super::stat(&names, "/d06/n0763") {
            Ok(info) if info.kind == 2 => Ok(()),
            _ => Err(format_args!("not found")),
        },
    );
    // The merged listing of a directory of 1,024 names of the layer and the lower names.
    let name = "a merged listing of 1,024 names of the layer";
    match list_etc(&names) {
        Some(l) if l.layer == LISTED && l.twice == 0 && l.lower == 1 && l.all >= LISTED + 2 => {
            say(format_args!(
                "listing of {} names in {} requests",
                l.all, l.requests
            ));
            t.ok(name);
        }
        Some(l) => t.fail(
            name,
            format_args!(
                "names of the layer {} (twice: {}), the lower layer-lower {}, all {}",
                l.layer, l.twice, l.lower, l.all
            ),
        ),
        None => t.fail(name, format_args!("no listing")),
    }
    // The copy ends, however long the checks took: the service says the copy is over, and the file
    // is the layer's, whole.
    let name = "a lower file of 64 MiB is copied up while the checks run";
    match ticket {
        Ok(_) if !COPY => {}
        Ok(ticket) => match wait_copy(&names, ticket) {
            0 => t.check(name, big_copy_is_there(&data, &names)),
            status => t.fail(
                name,
                format_args!("the copy ended with the status {status}"),
            ),
        },
        Err(status) => t.fail(name, format_args!("the write was answered {status}")),
    }
    changes(&mut t, &names, &control, &data);
    if t.failed == 0 {
        say(format_args!("scale checks passed"));
        0
    } else {
        say(format_args!("{} checks failed", t.failed));
        1
    }
}

/// A change by its operation, with the status it answered; a busy service (STARTING: the table of
/// jobs or the reaper is full) is asked again.
fn change(names: &Handle<Channel>, op: n::ChangeOp, a: u64, first: &str, second: &str) -> u32 {
    for _ in 0..3000 {
        let mut w = Writer::new();
        let request = n::Change {
            op,
            a,
            b: 0,
            first: first.as_bytes(),
            second: second.as_bytes(),
        };
        if request.write(&mut w).is_err() {
            return u32::MAX;
        }
        let Some(answer) = call(names, w.as_bytes(), rt::handle::Outgoing::new()) else {
            return u32::MAX;
        };
        match answer.status() {
            l::STARTING => {
                // SAFETY: a plain call of relibc.
                unsafe { usleep(10_000) };
            }
            status => return status,
        }
    }
    u32::MAX
}

fn status_of(control: &Handle<Channel>) -> Option<l::Stat> {
    let answer = call(
        control,
        &l::Method::Status.header().bytes(),
        rt::handle::Outgoing::new(),
    )?;
    l::Stat::read(answer.all()).ok()
}

/// A text of up to 512 bytes made by `write!`.
struct Text([u8; 512], usize);

impl core::fmt::Write for Text {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let end = self.1 + s.len();
        if end > self.0.len() {
            return Err(core::fmt::Error);
        }
        self.0[self.1..end].copy_from_slice(s.as_bytes());
        self.1 = end;
        Ok(())
    }
}

impl Text {
    fn new() -> Text {
        Text([0; 512], 0)
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.0[..self.1]).unwrap_or("")
    }
}

fn is_dir(names: &Handle<Channel>, path: &str) -> bool {
    matches!(super::stat(names, path), Ok(info) if info.kind == 1)
}

fn is_file(names: &Handle<Channel>, path: &str) -> bool {
    matches!(super::stat(names, path), Ok(info) if info.kind == 2)
}

fn is_missing(names: &Handle<Channel>, path: &str) -> bool {
    super::stat(names, path) == Err(proto_fs::NO_ENTRY)
}

/// The changes at the scale of the layer. Each is a job of the service in steps, and the gate of
/// `layer-steps` judges the longest step of them all.
fn changes(
    t: &mut Checks,
    names: &Handle<Channel>,
    control: &Handle<Channel>,
    data: &Handle<Channel>,
) {
    // 1. A file created, written, closed and removed at the depth of 240.
    let mut buf = [0u8; 512];
    let deep_file = chain(&mut buf, 240, "/a", "/w");
    t.check("a file made, written and removed at the depth of 240", {
        let flags = n::with_permissions(
            proto_fs::WRITE_ONLY | proto_fs::CREATE | proto_fs::EXCLUSIVE,
            0o644,
        );
        let wrote = match open(names, flags, deep_file) {
            Opened::Pass(pass) => {
                let mut w = Writer::new();
                let adopted = p::adopt(&mut w).ok().and_then(|()| {
                    let a = call(data, w.as_bytes(), [pass])?;
                    p::reply(a.all()).ok()?.u32().ok()
                });
                adopted.is_some_and(|handle| {
                    let mut w = Writer::new();
                    let put = p::write(handle, b"scale bytes", &mut w).is_ok()
                        && call(data, w.as_bytes(), rt::handle::Outgoing::new())
                            .is_some_and(|a| a.status() == 0);
                    let mut w = Writer::new();
                    let _ = p::handle_call(p::Method::Close, handle, &mut w);
                    let closed = call(data, w.as_bytes(), rt::handle::Outgoing::new())
                        .is_some_and(|a| a.status() == 0);
                    put && closed
                })
            }
            _ => false,
        };
        if !wrote {
            Err(format_args!("the file was not made or written"))
        } else if expect_bytes(data, names, deep_file, b"scale bytes").is_err() {
            Err(format_args!("the bytes were not read back"))
        } else if change(names, n::ChangeOp::Unlink, 0, deep_file, "") != 0 {
            Err(format_args!("the unlink failed"))
        } else if !stat_redirect_is(names, deep_file, deep_file) {
            Err(format_args!("the name is still there"))
        } else {
            Ok(())
        }
    });
    // 2. A directory made and removed at the depth of 240.
    let mut buf = [0u8; 512];
    let deep_dir = chain(&mut buf, 240, "/a", "/dd");
    t.check("a directory made and removed at the depth of 240", {
        if change(names, n::ChangeOp::Mkdir, 0o755, deep_dir, "") != 0 || !is_dir(names, deep_dir) {
            Err(format_args!("the mkdir failed"))
        } else if change(names, n::ChangeOp::Rmdir, 0, deep_dir, "") != 0
            || !stat_redirect_is(names, deep_dir, deep_dir)
        {
            Err(format_args!("the rmdir failed"))
        } else {
            Ok(())
        }
    });
    // 3. A directory below a chain of 32 lower directories: each is copied up into the layer.
    let mut low = Text::new();
    {
        use core::fmt::Write as _;
        let _ = low.write_str("/lowdeep");
        for k in 1..=LOW_DEPTH {
            let _ = write!(low, "/l{k}");
        }
        let _ = low.write_str("/x");
    }
    t.check("a directory below a chain of 32 lower directories", {
        if change(names, n::ChangeOp::Mkdir, 0o755, low.as_str(), "") != 0 {
            Err(format_args!("the mkdir failed"))
        } else if !is_dir(names, low.as_str()) {
            Err(format_args!("the directory is not there"))
        } else {
            Ok(())
        }
    });
    // 4. A directory of 1,024 names renamed and back, a name below it found each time.
    t.check("a directory of 1,024 names renamed and back", {
        if change(names, n::ChangeOp::Rename, 0, "/d00", "/d00m") != 0 {
            Err(format_args!("the rename failed"))
        } else if !is_file(names, "/d00m/n0005") || !is_missing_or_lower(names, "/d00/n0005") {
            Err(format_args!("the names did not follow the directory"))
        } else if change(names, n::ChangeOp::Rename, 0, "/d00m", "/d00") != 0 {
            Err(format_args!("the rename back failed"))
        } else if !is_file(names, "/d00/n0005") {
            Err(format_args!("the name is not back"))
        } else {
            Ok(())
        }
    });
    // 5. A directory with children into the opaque directory and back: the lower names of the
    // opaque directory stay hidden.
    t.check("a directory renamed into the opaque directory and back", {
        if !is_missing(names, "/opq/lowfile") {
            Err(format_args!(
                "a lower name shows through the opaque directory"
            ))
        } else if change(names, n::ChangeOp::Rename, 0, "/d01", "/opq/d01") != 0 {
            Err(format_args!("the rename in failed"))
        } else if !is_file(names, "/opq/d01/n0003") || !is_missing(names, "/opq/lowfile") {
            Err(format_args!(
                "the names below the moved directory are wrong"
            ))
        } else if change(names, n::ChangeOp::Rename, 0, "/opq/d01", "/d01") != 0 {
            Err(format_args!("the rename out failed"))
        } else if !is_file(names, "/d01/n0003") || !is_missing(names, "/opq/lowfile") {
            Err(format_args!("the names did not come back"))
        } else {
            Ok(())
        }
    });
    // 6. A directory of 2,000 marks removed: the name is free at once, STATUS falls by 2,001 when
    // the reaper is done, and a new directory of the name lists empty.
    t.check("a directory of 2,000 marks removed and made again", {
        let before = status_of(control).map_or(0, |s| s.names);
        if change(names, n::ChangeOp::Rmdir, 0, "/marks", "") != 0 {
            Err(format_args!("the rmdir failed"))
        } else {
            let mut fell = false;
            for _ in 0..6000 {
                if status_of(control).is_some_and(|s| s.names + 2001 == before) {
                    fell = true;
                    break;
                }
                // SAFETY: a plain call of relibc.
                unsafe { usleep(10_000) };
            }
            if !fell {
                Err(format_args!("STATUS did not fall by 2,001"))
            } else if change(names, n::ChangeOp::Mkdir, 0o755, "/marks", "") != 0 {
                Err(format_args!("the mkdir failed"))
            } else {
                match super::list_of(names, "/marks") {
                    Some(l) if !l.any_starts("m") && l.count <= 2 => Ok(()),
                    _ => Err(format_args!("the new directory does not list empty")),
                }
            }
        }
    });
    // 7. A rename onto a layer directory whose content is marks alone.
    t.check("a rename onto a directory of marks alone", {
        if change(names, n::ChangeOp::Rename, 0, "/d03", "/mk2") != 0 {
            Err(format_args!("the rename failed"))
        } else if !is_file(names, "/mk2/n0001") {
            Err(format_args!(
                "the contents of the source are not at the target"
            ))
        } else if !is_missing_or_lower(names, "/d03/n0001") {
            Err(format_args!("the source name is still there"))
        } else {
            Ok(())
        }
    });
    // 8. The counts after all of it, when the reaper is done.
    let name = "status counts the names after the changes";
    let mut last = None;
    for _ in 0..6000 {
        last = status_of(control);
        if last.is_some_and(|s| s.deleted == 0 && s.names == NAMES_AFTER) {
            break;
        }
        // SAFETY: a plain call of relibc.
        unsafe { usleep(10_000) };
    }
    match last {
        Some(s) if s.added == NAMES_AFTER && s.deleted == 0 && s.names == NAMES_AFTER => {
            t.ok(name);
        }
        Some(s) => t.fail(
            name,
            format_args!(
                "added {} deleted {} names {}, due {NAMES_AFTER} and none",
                s.added, s.deleted, s.names
            ),
        ),
        None => t.fail(name, format_args!("no status")),
    }
}

/// The name is gone from the layer: not found, or a redirect to the lower set.
fn is_missing_or_lower(names: &Handle<Channel>, path: &str) -> bool {
    is_missing(names, path) || stat_redirect_is(names, path, path)
}
