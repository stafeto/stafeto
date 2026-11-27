// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The scale checks of `cargo xtask layer-steps`: the live layer of the volume holds 8,192 names
//! (`data_image::layer_steps_entries`): a chain of 246 directories with a file at its end (a path
//! of 247 components), the directory `/etc` of 1,024 files that the lower `/etc` lists beside, and
//! files in `d00` and on. The service has built its index in steps by the time the probe starts; the
//! longest step of each kind is what the service prints and the command reads (`steps` build).

use super::{Checks, Opened, call, expect_bytes, open, say, session, stat_redirect_is, take_root};
use proto_fs::names::{self as n, NameMethod};
use proto_layer as l;
use proto_wire::Writer;

/// The names of the layer the probe counts: `data_image::STEPS_NAMES`.
const NAMES: u32 = 8192;
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
            Some(Ok(s)) if s.added == NAMES && s.deleted == 0 && s.names == NAMES => Ok(()),
            Some(Ok(_)) => Err(format_args!("the counts of the index differ")),
            _ => Err(format_args!("no status")),
        },
    );
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
        match super::stat(&names, "/d06/n0766") {
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
    if t.failed == 0 {
        say(format_args!("scale checks passed"));
        0
    } else {
        say(format_args!("{} checks failed", t.failed));
        1
    }
}
