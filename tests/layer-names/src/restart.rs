// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The restart checks of `cargo xtask layer-restart`: the layer service ends on an OPEN of the name
//! `/.die` (its feature `probe-restart`) and later with the data file service, which ends on the
//! same name through its own protocol (its feature `probe-restart`). After each end the probe keeps
//! working: a description of the old instance answers STALE or its session is dead, a file the data
//! file service holds is read on, and a new session of the new instance lists and reads as before.

use super::{Checks, Opened, call, list_of, open, say, stat, status_is, take_root};
use proto_fs::names::{self as n, NameMethod};
use proto_wire::Writer;
use rt::handle::{Channel, Handle};

/// The bytes of `/etc/layer-own` of the layer, which the checks read.
const OWN: &[u8] = b"owned bytes of the layer\n";

/// Waits a little: a plain call of relibc.
fn pause_ms(ms: u32) {
    unsafe extern "C" {
        fn usleep(micros: u32) -> core::ffi::c_int;
    }
    // SAFETY: a plain call.
    unsafe { usleep(ms * 1000) };
}

/// A session of the layer service as the process service gives its current root, quiet: None while
/// the root is not registered, dead, or the service builds its index (STARTING).
fn try_names() -> Option<Handle<Channel>> {
    let root = take_root_once(proto_process::ROOT_LAYER)?;
    let mut a = call(
        &root,
        &NameMethod::Session.header().bytes(),
        [super::identity()?],
    )?;
    if a.status() != 0 {
        return None;
    }
    a.reply.handles.take::<Channel>(0).ok()
}

/// The same for the data file service.
fn try_data() -> Option<Handle<Channel>> {
    let root = take_root_once(proto_process::ROOT_DATA)?;
    let mut a = call(
        &root,
        &proto_data::Method::Session.header().bytes(),
        [super::identity()?],
    )?;
    if a.status() != 0 {
        return None;
    }
    a.reply.handles.take::<Channel>(0).ok()
}

/// TakeRoot once: the root the process service holds now.
fn take_root_once(which: u32) -> Option<Handle<Channel>> {
    let mut w = Writer::new();
    proto_process::take_root(which, &mut w).ok()?;
    let mut a = call(
        posix_abi::process::client().session(),
        w.as_bytes(),
        rt::handle::Outgoing::new(),
    )?;
    if a.status() != 0 {
        return None;
    }
    a.reply.handles.take::<Channel>(0).ok()
}

/// Asks again every 100 ms, for up to 90 s, until `make` gives a session.
fn again(make: fn() -> Option<Handle<Channel>>) -> Option<Handle<Channel>> {
    for _ in 0..900 {
        if let Some(s) = make() {
            return Some(s);
        }
        pause_ms(100);
    }
    None
}

/// ADOPT of a pass in a session of the data file service: the handle of the description there.
fn adopt(data: &Handle<Channel>, pass: rt::handle::Handle<rt::handle::Any>) -> Option<u32> {
    let mut w = Writer::new();
    proto_data::adopt(&mut w).ok()?;
    let a = call(data, w.as_bytes(), [pass])?;
    proto_data::reply(a.all()).ok()?.u32().ok()
}

/// The bytes of the description `handle` of the data file service, from its start.
fn read_at(data: &Handle<Channel>, handle: u32, out: &mut [u8; 128]) -> Option<usize> {
    let mut w = Writer::new();
    proto_data::pread(handle, 100, 0, &mut w).ok()?;
    let a = call(data, w.as_bytes(), rt::handle::Outgoing::new())?;
    let mut r = proto_data::reply(a.all()).ok()?;
    let count = r.u32().ok()? as usize;
    let bytes = r.bytes(count).ok()?;
    out[..count].copy_from_slice(bytes);
    Some(count)
}

/// The status of READ_DIR on `handle` (the first word of the reply), None when no reply came.
fn read_dir_status(names: &Handle<Channel>, handle: u32) -> Option<u32> {
    let mut w = Writer::new();
    n::write_handle(NameMethod::ReadDir, handle, &mut w).ok()?;
    call(names, w.as_bytes(), rt::handle::Outgoing::new()).map(|a| a.status())
}

pub fn run() -> i32 {
    let mut t = Checks { failed: 0 };
    let (Some(names1), Some(data1)) = (again(try_names), again(try_data)) else {
        say(format_args!("sessions FAILED: no session"));
        return 1;
    };
    t.ok("sessions");
    // The first instance: a directory description read half way, and a file the data service holds.
    let Opened::Directory(h1) = open(
        &names1,
        proto_fs::READ_ONLY | proto_fs::DIRECTORY_ONLY,
        "/etc",
    ) else {
        t.fail(
            "descriptions of the first instance",
            format_args!("no directory"),
        );
        return 1;
    };
    let half = read_dir_status(&names1, h1);
    let held = match open(&names1, proto_fs::READ_ONLY, "/etc/layer-own") {
        Opened::Pass(pass) => adopt(&data1, pass),
        _ => None,
    };
    let (Some(0), Some(file1)) = (half, held) else {
        t.fail(
            "descriptions of the first instance",
            format_args!("the listing or the pass failed"),
        );
        return 1;
    };
    t.ok("descriptions of the first instance");
    let epoch1 = h1 >> 16;
    // The service ends on the name `.die`: the request gets no reply.
    let died = open(&names1, proto_fs::READ_ONLY, "/.die");
    t.check(
        "the service ends on the request",
        if status_is(&died, u32::MAX) {
            Ok(())
        } else {
            Err(format_args!("the service answered"))
        },
    );
    // A new instance: the process service gives its new root, and a session of it works.
    let Some(names2) = again(try_names) else {
        t.fail(
            "a session of the new instance",
            format_args!("none in 90 s"),
        );
        return 1;
    };
    t.ok("a session of the new instance");
    t.check(
        "the session of the old instance is dead",
        if read_dir_status(&names1, h1).is_none() {
            Ok(())
        } else {
            Err(format_args!("the old session answered"))
        },
    );
    t.check(
        "a description of the old instance answers STALE",
        match read_dir_status(&names2, h1) {
            Some(proto_fs::STALE) => Ok(()),
            _ => Err(format_args!("not STALE")),
        },
    );
    t.check("a file of the old instance is read on", {
        let mut buf = [0u8; 128];
        match read_at(&data1, file1, &mut buf) {
            Some(len) if &buf[..len] == OWN => Ok(()),
            _ => Err(format_args!("the bytes are not there")),
        }
    });
    let again_open = open(
        &names2,
        proto_fs::READ_ONLY | proto_fs::DIRECTORY_ONLY,
        "/etc",
    );
    t.check(
        "a new description lists and carries the epoch of the new instance",
        match again_open {
            Opened::Directory(h2) if h2 >> 16 != epoch1 => match list_of(&names2, "/etc") {
                Some(l) if l.count_of("layer-own") == 1 && l.count_of("layer-lower") == 1 => Ok(()),
                _ => Err(format_args!("the listing")),
            },
            Opened::Directory(_) => Err(format_args!("the same epoch as the old instance")),
            _ => Err(format_args!("no description")),
        },
    );
    t.check(
        "a stat on the new session",
        match stat(&names2, "/etc/layer-own") {
            Ok(info) if u64::from(info.size) == OWN.len() as u64 && info.kind == 2 => Ok(()),
            _ => Err(format_args!("the stat failed")),
        },
    );
    // The data file service ends on the same name; the layer service meets its end at its next call
    // to it and ends too, and both come back.
    let mut w = Writer::new();
    let _ = proto_data::open(b"/.die", proto_data::READ, 0, &mut w);
    let gone = call(&data1, w.as_bytes(), rt::handle::Outgoing::new());
    t.check(
        "the data file service ends on the request",
        if gone.is_none() {
            Ok(())
        } else {
            Err(format_args!("the service answered"))
        },
    );
    // A call that needs the data file service: the layer service ends (no reply).
    let met = open(&names2, proto_fs::READ_ONLY, "/etc/layer-own");
    t.check(
        "the layer service ends when the data file service has ended",
        if status_is(&met, u32::MAX) {
            Ok(())
        } else {
            Err(format_args!("the service answered"))
        },
    );
    let (Some(names3), Some(data3)) = (again(try_names), again(try_data)) else {
        t.fail("both services are back", format_args!("no session in 90 s"));
        return 1;
    };
    t.ok("both services are back");
    t.check("the same bytes through the new instances", {
        match open(&names3, proto_fs::READ_ONLY, "/etc/layer-own") {
            Opened::Pass(pass) => match adopt(&data3, pass) {
                Some(handle) => {
                    let mut buf = [0u8; 128];
                    match read_at(&data3, handle, &mut buf) {
                        Some(len) if &buf[..len] == OWN => Ok(()),
                        _ => Err(format_args!("the bytes differ")),
                    }
                }
                None => Err(format_args!("the pass was not taken")),
            },
            _ => Err(format_args!("no pass")),
        }
    });
    t.check(
        "a listing of the third instance",
        match list_of(&names3, "/etc") {
            Some(l) if l.count_of("layer-own") == 1 && l.count_of("layer-lower") == 1 => Ok(()),
            _ => Err(format_args!("the listing")),
        },
    );
    if t.failed == 0 {
        say(format_args!("restart checks passed"));
        0
    } else {
        say(format_args!("{} checks failed", t.failed));
        1
    }
}
