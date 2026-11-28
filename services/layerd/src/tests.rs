// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The tests of the answers of the service over a volume and a lower set in memory.

use crate::composition::Composition;
use crate::identity::{Vouched, vouched_from};
use crate::index::Index;
use crate::listing;
use crate::names::{Client, Core, Done, State};
use crate::scan::Scan;
use crate::testkit::{FakeLower, FakeVolume};
use crate::volume::R;
use proto_data as d;
use proto_fs as f;
use proto_fs::names::{self as n, OpenAnswer, UPPER_INO_TAG};
use proto_layer as l;
use proto_wire::{Status, Writer};
use std::boxed::Box;
use std::vec::Vec;

fn st(code: u32) -> Status {
    Status::Unknown(code)
}

/// The volume of the tests: the live layer 00 with /etc (a mark of deletion for motd, a file that
/// shadows a lower one, a file of its own), /home (0700) with a file, /opq (opaque) with a file,
/// and a file of the layer of the user only.
fn volume() -> FakeVolume {
    let mut v = FakeVolume::new();
    v.dir("/.layers", 0o700, 0)
        .dir("/.layers/00", 0o755, 0)
        .dir("/.layers/work", 0o700, 0)
        .file(
            "/.layers/COMPOSITION",
            0o600,
            0,
            b"STAFLAYR 1\nnext 01\nino 1\nlower -\nlayer 00 live unsealed - -\n",
        )
        .dir("/.layers/00/etc", 0o755, 0)
        .file("/.layers/00/etc/.wh.motd", 0o644, 0, b"")
        .file("/.layers/00/etc/passwd", 0o644, 0, b"upper passwd")
        .file_numbered(
            "/.layers/00/etc/own.conf",
            0o640,
            1000,
            UPPER_INO_TAG | 7,
            b"own bytes",
        )
        .dir("/.layers/00/home", 0o700, 0)
        .file("/.layers/00/home/secret", 0o644, 0, b"s")
        .dir("/.layers/00/opq", 0o755, 0)
        .file("/.layers/00/opq/.wh..wh..opq", 0o644, 0, b"")
        .file("/.layers/00/opq/u1", 0o644, 0, b"u1")
        .file("/.layers/00/opq/u2", 0o644, 0, b"u2");
    v
}

fn lower() -> FakeLower {
    let mut l = FakeLower::new();
    l.dir("/etc", 10)
        .file("/etc/motd", 11)
        .file("/etc/passwd", 12)
        .file("/etc/hostname", 13)
        .file("/etc/group", 14)
        .dir("/bin", 20)
        .file("/bin/ls", 21)
        .dir("/opq", 30)
        .file("/opq/l1", 31)
        .file("/opq/l2", 32)
        .dir("/home", 40)
        .file("/home/other", 41);
    for i in 0..20 {
        l.file(&format!("/etc/big{i:02}"), 100 + i);
    }
    l
}

struct World {
    index: Box<Index>,
    scan: Box<Scan>,
    work: Box<crate::reaper::Workers>,
}

impl World {
    fn new() -> World {
        World {
            index: crate::index::boxed(),
            scan: Box::new(Scan::new()),
            work: Box::new(crate::reaper::Workers::new()),
        }
    }

    fn core(&mut self, v: FakeVolume) -> Core<'_, FakeVolume, FakeLower> {
        Core::new(
            &mut self.index,
            &mut self.scan,
            &mut self.work,
            v,
            lower(),
            5,
        )
    }
}

fn ready(core: &mut Core<'_, FakeVolume, FakeLower>) {
    core.prepare();
    assert_eq!(core.state, State::Starting);
    let mut steps = 0;
    while !core.build_step() {
        steps += 1;
        assert!(steps < 1000);
    }
    assert_eq!(core.state, State::Ready);
}

fn who(uid: u32) -> Vouched {
    vouched_from(&crate::identity::tests_who(uid)).unwrap()
}

fn open(
    core: &mut Core<'_, FakeVolume, FakeLower>,
    uid: u32,
    flags: u32,
    path: &str,
) -> Result<(Vec<u8>, Option<Vec<u8>>), Status> {
    let v = who(uid);
    let c = Client {
        owner: 40 + u64::from(uid),
        who: &v,
    };
    let mut w = Writer::new();
    let done = core.open(&c, flags, path.as_bytes(), &mut w)?;
    Ok((
        w.as_bytes().to_vec(),
        match done {
            Done::Written => None,
            Done::Pass(p) => Some(p),
            Done::Continue(_) => unreachable!("an open runs its calls to the end"),
        },
    ))
}

/// A CHANGE as the user `uid`: the reply bytes.
fn change(
    core: &mut Core<'_, FakeVolume, FakeLower>,
    uid: u32,
    op: n::ChangeOp,
    a: u64,
    b: u64,
    first: &str,
    second: &str,
) -> Result<Vec<u8>, Status> {
    let v = who(uid);
    let c = Client {
        owner: 40 + u64::from(uid),
        who: &v,
    };
    let mut w = Writer::new();
    let req = n::Change {
        op,
        a,
        b,
        first: first.as_bytes(),
        second: second.as_bytes(),
    };
    let done = core.change(&c, &req, &mut w);
    while core.reap_step() {}
    done?;
    Ok(w.as_bytes().to_vec())
}

fn handle_of(reply: &[u8]) -> u32 {
    match OpenAnswer::read(reply).unwrap() {
        OpenAnswer::Directory { handle } => handle,
        other => panic!("{other:?}"),
    }
}

/// All the names of a directory description, with the number of requests it took.
fn list(core: &mut Core<'_, FakeVolume, FakeLower>, owner: u64, h: u32) -> (Vec<Vec<u8>>, usize) {
    let mut names = Vec::new();
    let mut requests = 0;
    loop {
        let (bytes, len) = core.read_dir(owner, h).unwrap();
        requests += 1;
        assert!(requests < 100);
        let (more, _, entries) = n::read_dir_reply(&bytes[..len]).unwrap();
        for e in entries {
            names.push(e.unwrap().name.to_vec());
        }
        if !more {
            return (names, requests);
        }
    }
}

fn sorted(mut v: Vec<Vec<u8>>) -> Vec<String> {
    v.sort();
    v.into_iter()
        .map(|n| String::from_utf8(n).unwrap())
        .collect()
}

#[test]
fn the_first_start_makes_the_layers_directory_and_the_composition() {
    let mut v = FakeVolume::new();
    let mut world = World::new();
    {
        let mut core = world.core(std::mem::take(&mut v));
        core.prepare();
        assert_eq!(core.state, State::Starting);
        let nodes = &core.volume.nodes;
        assert_eq!(nodes[&b"/.layers".to_vec()].mode, 0o700);
        assert_eq!(nodes[&b"/.layers".to_vec()].uid, 0);
        assert!(nodes[&b"/.layers/00".to_vec()].dir);
        assert!(nodes[&b"/.layers/work".to_vec()].dir);
        assert!(!nodes.contains_key(&b"/.layers/COMPOSITION.tmp".to_vec()));
        let text = &nodes[&b"/.layers/COMPOSITION".to_vec()].data;
        assert_eq!(Composition::parse(text), Ok(Composition::first()));
        // The file was made under another name, synced and renamed.
        assert_eq!(core.volume.calls_of("fsync"), 1);
        assert_eq!(core.volume.calls_of("rename"), 1);
        v = core.volume;
    }
    // A second start finds it and makes nothing.
    let mut world = World::new();
    let mut core = world.core(v);
    let before = core.volume.calls_of("mkdir");
    core.prepare();
    assert_eq!(core.state, State::Starting);
    assert_eq!(core.volume.calls_of("mkdir"), before);
    assert_eq!(core.volume.calls_of("rename"), 1);
}

#[test]
fn a_start_empties_the_work_directory() {
    let mut v = volume();
    v.file("/.layers/work/left", 0o600, 0, b"x")
        .dir("/.layers/work/dir", 0o700, 0)
        .file("/.layers/work/dir/inner", 0o600, 0, b"y");
    let mut world = World::new();
    let mut core = world.core(v);
    core.prepare();
    assert_eq!(core.state, State::Starting);
    assert!(core.volume.children(b"/.layers/work").is_empty());
    assert!(core.volume.nodes.contains_key(b"/.layers/work".as_slice()));
}

#[test]
fn a_start_empties_a_work_directory_of_any_depth_and_of_long_names() {
    let mut v = volume();
    // Twelve levels (the first version stopped at four), a file at each level, and names of 200
    // bytes in a directory of more files than one batch holds.
    let mut dir = String::from("/.layers/work");
    for level in 0..12 {
        dir.push_str(&format!("/d{level}"));
        v.dir(&dir, 0o700, 0);
        v.file(&format!("{dir}/f"), 0o600, 0, b"x");
    }
    let long = "n".repeat(200);
    v.dir("/.layers/work/wide", 0o700, 0);
    for k in 0..20 {
        v.file(&format!("/.layers/work/wide/{k:02}{long}"), 0o600, 0, b"y");
    }
    let mut world = World::new();
    let mut core = world.core(v);
    core.prepare();
    assert_eq!(core.state, State::Starting);
    assert!(core.volume.children(b"/.layers/work").is_empty());
    assert!(core.volume.nodes.contains_key(b"/.layers/work".as_slice()));
    assert_eq!(
        core.volume
            .nodes
            .keys()
            .filter(|k| k.starts_with(b"/.layers/work/"))
            .count(),
        0
    );
}

#[test]
fn a_frozen_layer_a_broken_file_and_a_lost_live_layer_are_damaged() {
    for text in [
        &b"STAFLAYR 1\nnext 02\nino 1\nlower -\nlayer 00 frozen unsealed - -\nlayer 01 live unsealed - -\n"[..],
        b"garbage\n",
        b"STAFLAYR 1\nnext 01\nino 1\nlower -\nlayer 05 live unsealed - -\n",
    ] {
        let mut v = volume();
        v.file("/.layers/COMPOSITION", 0o600, 0, text);
        let mut world = World::new();
        let mut core = world.core(v);
        core.prepare();
        assert_eq!(core.state, State::Damaged, "{text:?}");
        let mut w = Writer::new();
        assert_eq!(core.status(&mut w), Err(st(l::DAMAGED)));
        assert_eq!(
            open(&mut core, 0, f::READ_ONLY, "/etc/passwd").err(),
            Some(st(l::DAMAGED))
        );
    }
}

#[test]
fn with_no_volume_the_service_says_so() {
    let mut v = volume();
    v.not_ready = true;
    let mut world = World::new();
    let mut core = world.core(v);
    core.prepare();
    assert_eq!(core.state, State::NoStore);
    let mut w = Writer::new();
    core.status(&mut w).unwrap();
    let stat = l::Stat::read(w.as_bytes()).unwrap();
    assert_eq!(stat.flags, l::STATUS_NO_STORE);
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/etc").err(),
        Some(st(l::NO_STORE))
    );
}

#[test]
fn until_the_index_is_built_the_names_answer_starting() {
    let mut world = World::new();
    let mut core = world.core(volume());
    core.prepare();
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/etc/passwd").err(),
        Some(st(l::STARTING))
    );
    let mut w = Writer::new();
    core.status(&mut w).unwrap();
    assert_eq!(
        l::Stat::read(w.as_bytes()).unwrap().flags,
        l::STATUS_STARTING
    );
    // The build takes more than one step (the batches of the listing are three entries).
    let mut steps = 0;
    while !core.build_step() {
        steps += 1;
    }
    assert!(steps >= 6, "{steps}");
    assert_eq!(core.state, State::Ready);
    let mut w = Writer::new();
    core.status(&mut w).unwrap();
    let stat = l::Stat::read(w.as_bytes()).unwrap();
    assert_eq!((stat.flags, stat.live, stat.frozen), (0, 0, 0));
    // etc, home, opq, passwd, own.conf, secret, u1, u2 and the mark of motd.
    assert_eq!((stat.added, stat.deleted, stat.names), (8, 1, 9));
}

#[test]
fn the_index_holds_the_layer_with_its_marks_and_its_opaque_directories() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    let ix = &core.index;
    let etc = ix.lookup(0, b"etc").unwrap().0;
    assert_eq!(
        ix.lookup(etc, b"motd").unwrap().1.kind,
        crate::index::Kind::Whiteout
    );
    assert!(ix.lookup(etc, b".wh.motd").is_none());
    assert_eq!(
        ix.lookup(etc, b"own.conf").unwrap().1.number,
        UPPER_INO_TAG | 7
    );
    let opq = ix.lookup(0, b"opq").unwrap().0;
    assert_ne!(ix.flags(opq) & crate::index::OPAQUE, 0);
    assert!(ix.lookup(opq, b".wh..wh..opq").is_none());
    assert_eq!(ix.flags(etc) & crate::index::OPAQUE, 0);
    let home = ix.lookup(0, b"home").unwrap().0;
    assert_eq!(ix.attr(home).unwrap().mode, 0o700);
    assert_eq!(ix.attr(0).unwrap().mode, 0o755);
}

#[test]
fn a_name_of_the_lower_set_is_a_redirect_to_the_ram_service_with_the_whole_path() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    for path in ["/bin/ls", "/etc/hostname", "/usr/x", "/etc/../bin/ls"] {
        let (reply, pass) = open(&mut core, 1000, f::READ_ONLY, path).unwrap();
        assert!(pass.is_none());
        match OpenAnswer::read(&reply).unwrap() {
            OpenAnswer::Redirect(r) => {
                assert_eq!(r.target, f::REDIRECT_RAM);
                // The path goes whole: a `..` after the first lower name is the RAM file
                // service's to answer.
                assert_eq!(r.path, path.as_bytes());
                assert_eq!((r.index, r.links), (0, 0));
            }
            other => panic!("{other:?}"),
        }
    }
    // A directory of the lower set alone, and the names the root passes through.
    let (reply, _) = open(&mut core, 1000, f::READ_ONLY | f::DIRECTORY_ONLY, "/bin").unwrap();
    assert!(matches!(
        OpenAnswer::read(&reply).unwrap(),
        OpenAnswer::Redirect(r) if r.path == b"/bin"
    ));
    let (reply, _) = open(&mut core, 1000, f::READ_ONLY, "/data/x").unwrap();
    assert!(matches!(
        OpenAnswer::read(&reply).unwrap(),
        OpenAnswer::Redirect(r) if r.target == f::REDIRECT_DATA
    ));
    let (reply, _) = open(&mut core, 1000, f::READ_ONLY, "/tmp/x").unwrap();
    assert!(matches!(
        OpenAnswer::read(&reply).unwrap(),
        OpenAnswer::Redirect(r) if r.target == f::REDIRECT_RAM
    ));
}

#[test]
fn a_file_of_the_layer_of_the_user_is_a_pass_after_the_check_of_the_right_to_read() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    // 0640 owned by 1000: the owner reads, the superuser reads, another user does not.
    let (reply, pass) = open(&mut core, 1000, f::READ_ONLY, "/etc/own.conf").unwrap();
    assert_eq!(OpenAnswer::read(&reply), Ok(OpenAnswer::Pass));
    assert_eq!(pass.as_deref(), Some(&b"/.layers/00/etc/own.conf"[..]));
    assert!(
        open(&mut core, 0, f::READ_ONLY, "/etc/own.conf")
            .unwrap()
            .1
            .is_some()
    );
    assert_eq!(
        open(&mut core, 1001, f::READ_ONLY, "/etc/own.conf").err(),
        Some(st(f::ACCESS_DENIED))
    );
    // The description opened for the pass is closed again: the service holds none.
    assert_eq!(core.volume.calls_of("export"), 2);
    assert_eq!(
        core.volume.calls_of("open") - core.volume.calls_of("close"),
        0
    );
    // A file that shadows a lower one.
    let (_, pass) = open(&mut core, 1000, f::READ_ONLY, "/etc/passwd").unwrap();
    assert_eq!(pass.as_deref(), Some(&b"/.layers/00/etc/passwd"[..]));
}

#[test]
fn the_names_a_layer_deleted_or_never_had_are_not_there() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    // motd is in the lower set and the layer deleted it.
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/etc/motd").err(),
        Some(st(f::NO_ENTRY))
    );
    // The opaque directory shows its own names only.
    assert!(
        open(&mut core, 0, f::READ_ONLY, "/opq/u1")
            .unwrap()
            .1
            .is_some()
    );
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/opq/l1").err(),
        Some(st(f::NO_ENTRY))
    );
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/opq/u1/x").err(),
        Some(st(f::NOT_DIRECTORY))
    );
    assert_eq!(
        open(
            &mut core,
            0,
            f::READ_ONLY | f::DIRECTORY_ONLY,
            "/etc/own.conf"
        )
        .err(),
        Some(st(f::NOT_DIRECTORY))
    );
}

#[test]
fn each_directory_of_the_layer_is_checked_for_the_right_to_search() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    // /home is 0700 owned by root in the layer, and a lower /home/other exists: the user gets
    // EACCES for the one and the other, whatever the lower set says.
    for path in ["/home/secret", "/home/other", "/home/none"] {
        assert_eq!(
            open(&mut core, 1000, f::READ_ONLY, path).err(),
            Some(st(f::ACCESS_DENIED)),
            "{path}"
        );
    }
    assert!(
        open(&mut core, 0, f::READ_ONLY, "/home/secret")
            .unwrap()
            .1
            .is_some()
    );
    // The directory itself cannot be read either.
    assert_eq!(
        open(&mut core, 1000, f::READ_ONLY | f::DIRECTORY_ONLY, "/home").err(),
        Some(st(f::ACCESS_DENIED))
    );
}

#[test]
fn a_write_to_a_lower_name_waits_for_its_copy_up() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    // A name of the lower set is copied up before it is written: the answer is COPYING with the
    // ticket of the copy, the same one for every request for the file while it goes on.
    let mut ticket = None;
    for flags in [f::WRITE_ONLY, f::READ_WRITE, f::READ_ONLY | f::TRUNCATE] {
        for extra in [0, f::CREATE] {
            let (reply, pass) = open(&mut core, 0, flags | extra, "/bin/ls").unwrap();
            assert!(pass.is_none(), "{flags}");
            let t = proto_fs::names::read_copying(&reply)
                .expect("COPYING")
                .unwrap();
            assert_eq!(*ticket.get_or_insert(t), t, "{flags}");
        }
    }
    // A create of a name that is there opens it for reading, EXCLUSIVE says it exists, and an
    // append with read access writes nothing.
    assert!(
        open(&mut core, 0, f::READ_ONLY | f::CREATE, "/etc/passwd")
            .unwrap()
            .1
            .is_some()
    );
    assert!(
        open(&mut core, 0, f::READ_ONLY | f::APPEND, "/etc/passwd")
            .unwrap()
            .1
            .is_some()
    );
    for path in ["/etc/passwd", "/bin/ls"] {
        assert_eq!(
            open(&mut core, 0, f::READ_ONLY | f::CREATE | f::EXCLUSIVE, path).err(),
            Some(st(f::ALREADY_EXISTS)),
            "{path}"
        );
    }
    let (reply, _) = open(&mut core, 0, f::READ_ONLY | f::CREATE, "/bin/ls").unwrap();
    assert!(matches!(
        OpenAnswer::read(&reply),
        Ok(OpenAnswer::Redirect(r)) if r.path == b"/bin/ls"
    ));
    // A directory is not opened for writing.
    assert_eq!(
        open(&mut core, 0, f::WRITE_ONLY, "/etc").err(),
        Some(st(f::IS_DIRECTORY))
    );
    // The names the root passes through are the services' own.
    let (reply, _) = open(&mut core, 0, f::WRITE_ONLY | f::CREATE, "/tmp/x").unwrap();
    assert!(matches!(
        OpenAnswer::read(&reply),
        Ok(OpenAnswer::Redirect(_))
    ));
    // The attributes of a lower name are changed on its copy: the same ticket for the file.
    for (op, a) in [
        (n::ChangeOp::Chmod, 0o600),
        (n::ChangeOp::Chown, 1000),
        (n::ChangeOp::Truncate, 0),
        (n::ChangeOp::Utimens, 5),
    ] {
        let reply = change(&mut core, 0, op, a, 0, "/bin/ls", "").unwrap();
        assert_eq!(
            n::read_copying(&reply).unwrap().unwrap(),
            ticket.unwrap(),
            "{op:?}"
        );
    }
    assert_eq!(
        change(&mut core, 0, n::ChangeOp::Chmod, 0o600, 0, "/bin/none", "").err(),
        Some(st(f::NO_ENTRY))
    );
}

#[test]
fn a_merged_directory_lists_the_layer_then_the_lower_set_without_what_the_layer_hides() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    let (reply, _) = open(&mut core, 1000, f::READ_ONLY | f::DIRECTORY_ONLY, "/etc").unwrap();
    let h = handle_of(&reply);
    let (names, requests) = list(&mut core, 1040, h);
    let names = sorted(names);
    // The mark of motd and the file `.wh.motd` itself are not names; passwd is listed once.
    assert!(!names.iter().any(|n| n.starts_with(".wh.")));
    assert!(!names.contains(&"motd".into()));
    assert_eq!(names.iter().filter(|n| *n == "passwd").count(), 1);
    for expected in [
        ".", "..", "own.conf", "passwd", "hostname", "group", "big00", "big19",
    ] {
        assert!(
            names.contains(&expected.to_string()),
            "{expected}: {names:?}"
        );
    }
    // The lower directory has 4 names and 20 more: at most 8 of them in one reply.
    assert!(requests >= 4, "{requests}");
    let mut dups = names.clone();
    dups.dedup();
    assert_eq!(dups.len(), names.len());
}

#[test]
fn a_reply_takes_at_most_eight_entries_of_the_lower_set() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    let (reply, _) = open(&mut core, 0, f::READ_ONLY, "/etc").unwrap();
    let h = handle_of(&reply);
    let mut lower_seen = 0;
    loop {
        let (bytes, len) = core.read_dir(40, h).unwrap();
        let (more, cursor, entries) = n::read_dir_reply(&bytes[..len]).unwrap();
        let (stage, _) = n::split_cursor(cursor);
        let mut in_reply = 0;
        for e in entries {
            let e = e.unwrap();
            if e.ino < 1000 && e.ino > 1 {
                in_reply += 1;
            }
        }
        assert!(in_reply <= n::LOWER_PER_READDIR, "{in_reply}");
        lower_seen += in_reply;
        if !more {
            assert_eq!(stage, 1);
            break;
        }
    }
    // passwd (12) of the lower set is shadowed, motd (11) deleted: 3 + 20 remain... and the
    // lower inodes 13, 14 and 100..119.
    assert_eq!(lower_seen, 2 + 20);
}

/// The replies of a listing to its end: the cursor after each, its names, and the reads of the
/// lower directory and the opens the request made.
fn drain(
    core: &mut Core<'_, FakeVolume, FakeLower>,
    owner: u64,
    h: u32,
) -> Vec<(u64, Vec<Vec<u8>>, usize, usize)> {
    let mut out = Vec::new();
    loop {
        let (opened, nexts) = (core.lower.opened, core.lower.nexts);
        let (bytes, len) = core.read_dir(owner, h).unwrap();
        let (opened, nexts) = (core.lower.opened - opened, core.lower.nexts - nexts);
        let (more, cursor, entries) = n::read_dir_reply(&bytes[..len]).unwrap();
        let names = entries.map(|e| e.unwrap().name.to_vec()).collect();
        out.push((cursor, names, opened, nexts));
        if !more {
            return out;
        }
    }
}

#[test]
fn a_request_does_one_of_the_open_the_replay_and_a_few_reads_of_the_lower_directory() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    let (reply, _) = open(&mut core, 0, f::READ_ONLY, "/etc").unwrap();
    let h = handle_of(&reply);
    let owner = 40;
    let replies = drain(&mut core, owner, h);
    // The open is a request of its own, with no entry and no read.
    let opens: Vec<_> = replies.iter().filter(|r| r.2 == 1).collect();
    assert_eq!(opens.len(), 1);
    assert!(opens[0].1.is_empty() && opens[0].3 == 0);
    assert!(replies.iter().all(|r| r.3 <= listing::LOWER_PER_STEP + 1));
    // Past a cursor of the lower set a seek reopens the directory, replays up to the cursor a few
    // reads at a time (requests with no entry), and lists what followed the cursor the first time.
    let at = replies
        .iter()
        .position(|r| n::split_cursor(r.0).0 == 1 && r.0 > n::cursor(1, 6))
        .expect("a reply past the sixth entry of the lower set");
    let rest: Vec<Vec<u8>> = replies[at + 1..].iter().flat_map(|r| r.1.clone()).collect();
    assert!(!rest.is_empty());
    core.seek_dir(owner, h, replies[at].0).unwrap();
    let again = drain(&mut core, owner, h);
    assert_eq!(again.iter().filter(|r| r.2 == 1).count(), 1);
    assert!(again.iter().all(|r| r.3 <= listing::LOWER_PER_STEP + 1));
    assert!(
        again
            .iter()
            .any(|r| r.1.is_empty() && r.3 > 0 && r.0 == replies[at].0),
        "the replay took requests of its own"
    );
    let replayed: Vec<Vec<u8>> = again.iter().flat_map(|r| r.1.clone()).collect();
    assert_eq!(replayed, rest);
}

#[test]
fn a_listing_opens_the_lower_directory_over_requests_and_lists_what_it_does_without_them() {
    let names_of = |delay: u32| {
        let mut world = World::new();
        let mut core = world.core(volume());
        ready(&mut core);
        core.lower.delay = delay;
        let (reply, _) = open(&mut core, 0, f::READ_ONLY, "/etc").unwrap();
        let h = handle_of(&reply);
        let (names, requests) = list(&mut core, 40, h);
        assert_eq!(
            (core.lower.live, core.lower.most, core.resolving),
            (0, 1, 0)
        );
        (sorted(names), requests)
    };
    let (plain, few) = names_of(0);
    let (slow, many) = names_of(6);
    assert_eq!(plain, slow);
    assert!(many >= few + 6, "{many} requests against {few}");
}

#[test]
fn listings_resolving_at_once_are_capped_and_the_rest_ask_again() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    core.lower.delay = 2;
    let (reply, _) = open(&mut core, 0, f::READ_ONLY, "/etc").unwrap();
    let h = handle_of(&reply);
    // The places of the listings are all taken: the request answers more with no entry and
    // starts nothing.
    core.resolving = listing::LISTINGS_RESOLVING;
    // (The names of the layer come first and need no lower directory.)
    let mut stage = 0;
    for _ in 0..500 {
        let (bytes, len) = core.read_dir(40, h).unwrap();
        let (more, cursor, _) = n::read_dir_reply(&bytes[..len]).unwrap();
        assert!(more);
        stage = n::split_cursor(cursor).0;
        if stage == 1 {
            break;
        }
    }
    assert_eq!(stage, 1);
    for _ in 0..3 {
        assert_eq!(core.read_dir(40, h).err(), Some(st(proto_layer::STARTING)));
    }
    assert_eq!(core.lower.live, 0);
    core.resolving = 0;
    core.read_dir(40, h).unwrap();
    assert_eq!((core.lower.live, core.resolving), (1, 1));
    // A seek or a close in the middle of the open gives the place and the preparation back.
    core.seek_dir(40, h, n::cursor(1, 0)).unwrap();
    assert_eq!(
        (core.lower.live, core.lower.cancelled, core.resolving),
        (0, 1, 0)
    );
    core.read_dir(40, h).unwrap();
    assert_eq!((core.lower.live, core.resolving), (1, 1));
    core.close(40, h).unwrap();
    assert_eq!(
        (core.lower.live, core.lower.cancelled, core.resolving),
        (0, 2, 0)
    );
    // The session that goes does the same.
    let (reply, _) = open(&mut core, 0, f::READ_ONLY, "/etc").unwrap();
    let h = handle_of(&reply);
    loop {
        let (bytes, len) = core.read_dir(40, h).unwrap();
        let (_, cursor, _) = n::read_dir_reply(&bytes[..len]).unwrap();
        if core.resolving == 1 {
            assert_eq!(n::split_cursor(cursor).0, 1);
            break;
        }
    }
    assert_eq!((core.lower.live, core.resolving), (1, 1));
    core.gone(40);
    assert_eq!(
        (core.lower.live, core.lower.cancelled, core.resolving),
        (0, 3, 0)
    );
}

fn to_lower_stage(core: &mut Core<'_, FakeVolume, FakeLower>, owner: u64, h: u32) {
    for _ in 0..500 {
        let (bytes, len) = core.read_dir(owner, h).unwrap();
        let (_, cursor, _) = n::read_dir_reply(&bytes[..len]).unwrap();
        if n::split_cursor(cursor).0 == 1 {
            return;
        }
    }
    panic!("the lower stage is not reached");
}

#[test]
fn one_session_has_one_listing_opening_at_a_time_and_a_refused_start_is_busy() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    core.lower.delay = 50;
    let (reply, _) = open(&mut core, 0, f::READ_ONLY, "/etc").unwrap();
    let first = handle_of(&reply);
    let (reply, _) = open(&mut core, 0, f::READ_ONLY, "/").unwrap();
    let second = handle_of(&reply);
    to_lower_stage(&mut core, 40, first);
    core.read_dir(40, first).unwrap();
    assert_eq!(core.resolving, 1);
    // The second description of the session waits for its share, however often it asks, and
    // the first goes on.
    for _ in 0..5 {
        loop {
            if let Err(e) = core.read_dir(40, second) {
                assert_eq!(e, st(proto_layer::STARTING));
                break;
            }
            // The layer's own names of the second come first.
            assert!(core.resolving <= 1);
        }
        core.read_dir(40, first).unwrap();
    }
    assert_eq!(core.lower.most, 1);
    // A refusal of the RAM file service at the start is busy too, and starts nothing.
    core.gone(40);
    core.lower.limit = 1;
    core.lower.live = 1;
    let (reply, _) = open(&mut core, 1, f::READ_ONLY, "/etc").unwrap();
    let h = handle_of(&reply);
    let mut busy = false;
    for _ in 0..500 {
        if let Err(e) = core.read_dir(41, h) {
            assert_eq!(e, st(proto_layer::STARTING));
            busy = true;
            break;
        }
    }
    assert!(busy);
    assert_eq!(core.resolving, 0);
}

#[test]
fn an_error_of_a_poll_of_a_listing_gives_the_place_back() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    core.lower.delay = 3;
    let (reply, _) = open(&mut core, 0, f::READ_ONLY, "/etc").unwrap();
    let h = handle_of(&reply);
    to_lower_stage(&mut core, 40, h);
    core.lower.fail_at = Some(core.lower.polls + 2);
    let mut failed = None;
    for _ in 0..20 {
        if let Err(e) = core.read_dir(40, h) {
            failed = Some(e);
            break;
        }
    }
    assert_eq!(failed, Some(st(proto_fs::INVALID_ARGUMENT)));
    assert_eq!((core.lower.live, core.resolving), (0, 0));
}

#[test]
fn an_opaque_directory_lists_only_its_own_names_and_a_lower_only_one_is_no_description() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    let (reply, _) = open(&mut core, 0, f::READ_ONLY | f::DIRECTORY_ONLY, "/opq").unwrap();
    let h = handle_of(&reply);
    let (names, _) = list(&mut core, 40, h);
    assert_eq!(sorted(names), [".", "..", "u1", "u2"]);
    assert_eq!(core.lower.opened, 0, "the lower directory is never opened");
    // The root: the layer's names and the lower root's, the pass-through ones as the lower set
    // lists them.
    let (reply, _) = open(&mut core, 0, f::READ_ONLY, "/").unwrap();
    let root = handle_of(&reply);
    let (names, _) = list(&mut core, 40, root);
    let names = sorted(names);
    for expected in ["etc", "home", "opq", "bin"] {
        assert!(
            names.contains(&expected.to_string()),
            "{expected}: {names:?}"
        );
    }
    assert_eq!(names.iter().filter(|n| *n == "etc").count(), 1);
}

#[test]
fn a_description_rewinds_seeks_closes_and_goes_with_its_session() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    let (reply, _) = open(&mut core, 0, f::READ_ONLY, "/etc").unwrap();
    let h = handle_of(&reply);
    let owner = 40;
    let (first, _) = list(&mut core, owner, h);
    core.rewind(owner, h).unwrap();
    let (second, _) = list(&mut core, owner, h);
    assert_eq!(first, second);
    // A cursor a reply gave puts the listing back where it was.
    core.rewind(owner, h).unwrap();
    let (bytes, len) = core.read_dir(owner, h).unwrap();
    let (_, cursor, entries) = n::read_dir_reply(&bytes[..len]).unwrap();
    let head: Vec<_> = entries.map(|e| e.unwrap().name.to_vec()).collect();
    let (rest_a, _) = list(&mut core, owner, h);
    core.seek_dir(owner, h, cursor).unwrap();
    let (rest_b, _) = list(&mut core, owner, h);
    assert_eq!(rest_a, rest_b);
    assert!(!head.is_empty());
    assert_eq!(
        core.seek_dir(owner, h, n::cursor(2, 0)),
        Err(st(f::INVALID_ARGUMENT))
    );
    // Another session cannot use the handle, a handle of an earlier instance is STALE.
    assert_eq!(core.read_dir(41, h).err(), Some(st(f::BAD_FD)));
    let stale = n::handle(0, 1, core.epoch() + 1);
    assert_eq!(core.read_dir(owner, stale).err(), Some(st(f::STALE)));
    let mut w = Writer::new();
    core.fstat(owner, h, &mut w).unwrap();
    assert_eq!(n::read_info(w.as_bytes()).unwrap().kind, 1);
    core.close(owner, h).unwrap();
    assert_eq!(core.close(owner, h), Err(st(f::BAD_FD)));
    // The lower directory was opened and closed with it.
    assert_eq!(core.lower.opened, core.lower.closed);
    // A session that goes frees what it held.
    for _ in 0..3 {
        open(&mut core, 0, f::READ_ONLY, "/etc").unwrap();
    }
    assert_eq!(core.descriptions(), 3);
    core.gone(owner);
    assert_eq!(core.descriptions(), 0);
}

#[test]
fn a_session_holds_sixteen_descriptions() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    for _ in 0..crate::descriptions::PER_SESSION {
        open(&mut core, 0, f::READ_ONLY, "/etc").unwrap();
    }
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/etc").err(),
        Some(st(f::TOO_MANY_FILES_IN_SYSTEM))
    );
}

#[test]
fn the_sessions_of_one_process_hold_thirty_two_descriptions_together() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    let v = who(0);
    let other = vouched_from(&crate::identity::tests_who_of(8, 0)).unwrap();
    let mut w = Writer::new();
    // Two sessions of the process with the pid 7 take 16 each; a third gets none.
    for owner in [100, 101] {
        for _ in 0..crate::descriptions::PER_SESSION {
            let c = Client { owner, who: &v };
            core.open(&c, f::READ_ONLY, b"/etc", &mut w).unwrap();
        }
    }
    let c = Client {
        owner: 102,
        who: &v,
    };
    assert_eq!(
        core.open(&c, f::READ_ONLY, b"/etc", &mut w).err(),
        Some(st(f::TOO_MANY_FILES_IN_SYSTEM))
    );
    // Another process still has its share.
    let c = Client {
        owner: 103,
        who: &other,
    };
    assert!(core.open(&c, f::READ_ONLY, b"/etc", &mut w).is_ok());
}

#[test]
fn stat_numbers_come_from_the_service_that_holds_the_name() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    let v = who(1000);
    let c = Client { owner: 40, who: &v };
    let stat = |core: &mut Core<'_, FakeVolume, FakeLower>, path: &str| {
        let mut w = Writer::new();
        core.stat(&c, 0, path.as_bytes(), &mut w)
            .map(|()| n::read_info(w.as_bytes()).unwrap())
    };
    // A file of the layer: the number the data volume keeps, device 0.
    let own = stat(&mut core, "/etc/own.conf").unwrap();
    assert_eq!(own.inode, UPPER_INO_TAG | 7);
    assert_eq!(
        (own.device, own.uid, own.permissions, own.size),
        (0, 1000, 0o640, 9)
    );
    assert_eq!(own.kind, 2);
    // A lower name is a redirect to the RAM file service, which answers with the rights of the
    // caller's own session and the numbers it gives; so is a lower directory and a path with a
    // slash at the end.
    for path in ["/bin/ls", "/bin", "/bin/ls/", "/usr/none"] {
        let mut w = Writer::new();
        core.stat(&c, n::STAT_NO_FOLLOW, path.as_bytes(), &mut w)
            .unwrap();
        let r = proto_fs::Redirect::read_reply(w.as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(
            (r.target, r.path),
            (f::REDIRECT_RAM, path.as_bytes()),
            "{path}"
        );
    }
    assert_eq!(core.lower.opened, 0);
    // A directory of the layer, the root, a directory of the lower set.
    assert_eq!(stat(&mut core, "/etc").unwrap().kind, 1);
    let root = core.volume.nodes[&b"/.layers/00".to_vec()].ino;
    assert_eq!(stat(&mut core, "/").unwrap().inode, root);
    assert_eq!(stat(&mut core, "/etc/motd").err(), Some(st(f::NO_ENTRY)));
    assert_eq!(
        stat(&mut core, "/home/secret").err(),
        Some(st(f::ACCESS_DENIED))
    );
    assert_eq!(
        stat(&mut core, "/etc/own.conf/").err(),
        Some(st(f::NOT_DIRECTORY))
    );
    // The times are the data service's, in seconds and nanoseconds.
    assert_eq!(own.modify_time.seconds, 2);
    // A pass-through name is a redirect.
    let mut w = Writer::new();
    core.stat(&c, 0, b"/data", &mut w).unwrap();
    assert!(proto_fs::Redirect::read_reply(w.as_bytes()).is_some());
}

#[test]
fn access_checks_the_bits_of_the_file() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    let v = who(1001);
    let c = Client { owner: 41, who: &v };
    let mut w = Writer::new();
    assert!(core.access(&c, 0, 0, b"/etc/own.conf", &mut w).is_ok());
    let mut w = Writer::new();
    assert_eq!(
        core.access(&c, 4, 0, b"/etc/own.conf", &mut w),
        Err(st(f::ACCESS_DENIED))
    );
    let mut w = Writer::new();
    assert!(core.access(&c, 4, 0, b"/etc/passwd", &mut w).is_ok());
    let mut w = Writer::new();
    // The rights are the file's own: /etc/passwd is 0644 of root, so another user may not write.
    assert_eq!(
        core.access(&c, 2, 0, b"/etc/passwd", &mut w),
        Err(st(f::ACCESS_DENIED))
    );
    let mut w = Writer::new();
    core.readlink(&c, b"/bin/ls", &mut w).unwrap();
    let mut w = Writer::new();
    assert_eq!(
        core.readlink(&c, b"/etc/passwd", &mut w),
        Err(st(f::INVALID_ARGUMENT))
    );
}

#[test]
fn list_gives_the_lower_set_and_the_live_layer() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    let mut w = Writer::new();
    core.list(0, &mut w).unwrap();
    let mut out = [None; l::LIST_MAX as usize];
    let (count, next) = l::read_list(w.as_bytes(), &mut out).unwrap();
    assert_eq!((count, next), (2, 0));
    assert_eq!(out[0].unwrap().kind, l::KIND_PACKAGES);
    assert_eq!(out[1].unwrap().kind, l::KIND_LIVE);
    assert_eq!(out[1].unwrap().number, 0);
    let mut w = Writer::new();
    core.list(5, &mut w).unwrap();
    assert_eq!(l::read_list(w.as_bytes(), &mut out).unwrap().0, 0);
}

/// A step of the build of the index takes at most a stat and an open, or one batch of a listing,
/// whatever the layer holds (`break-layerd-one-step` walks it whole in one step).
/// A long path walked in steps of `lookup::STEP` components comes to the same answer as the walk in
/// one piece, for OPEN, STAT, ACCESS and READLINK, whatever the outcome.
#[test]
fn a_long_path_walked_in_steps_comes_to_the_answer_of_the_walk_in_one_piece() {
    let mut v = volume();
    let mut dir = String::from("/.layers/00");
    let mut plain = String::new();
    for _ in 0..40 {
        dir.push_str("/a");
        plain.push_str("/a");
        v.dir(&dir, 0o755, 0);
    }
    v.file(&format!("{dir}/f"), 0o644, 0, b"deep");
    v.dir(&format!("{dir}/closed"), 0o700, 0);
    v.file(&format!("{dir}/closed/g"), 0o644, 0, b"g");
    let mut world = World::new();
    let mut core = world.core(v);
    ready(&mut core);
    let paths = [
        format!("{plain}/f"),
        format!("{plain}/missing"),
        format!("{plain}/f/x"),
        format!("{plain}/closed/g"),
        format!("{plain}/../a/f"),
        "/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/b"
            .to_owned(),
        format!("{plain}/"),
    ];
    for uid in [0, 1000] {
        let who = who(uid);
        let c = Client {
            owner: 40 + u64::from(uid),
            who: &who,
        };
        for path in &paths {
            let mut pw = crate::names::Prewalk::new(path.as_bytes(), false, true);
            let mut steps = 0;
            let walked = loop {
                steps += 1;
                assert!(steps < 100);
                if let Some(done) = core.prewalk_step(&who, &mut pw) {
                    break done;
                }
            };
            // The first step makes the path plain, then 16 components a step.
            let comps = path
                .split('/')
                .filter(|p| !p.is_empty() && *p != "..")
                .count();
            assert!(
                steps > comps / 16 && steps <= comps / 16 + 3,
                "{path}: {steps} steps"
            );
            let mut once = Writer::new();
            let mut stepped = Writer::new();
            let a = core.open(&c, f::READ_ONLY, path.as_bytes(), &mut once);
            let mut b = core.open_walked(&c, f::READ_ONLY, Some(walked), true, b"", &mut stepped);
            // The calls to the volume go on one at a time: three of them for a file.
            let mut calls = 0;
            while let Ok(Done::Continue(cont)) = b {
                calls += 1;
                b = core.open_continue(&c, cont, &mut stepped);
            }
            assert!(calls == 0 || calls == 3, "{path}: {calls} calls");
            assert_eq!(a.as_ref().err(), b.as_ref().err(), "{path} as {uid}");
            // (The handle of a description of a directory is the next place, so it differs.)
            if !path.ends_with('/') {
                assert_eq!(once.as_bytes(), stepped.as_bytes(), "{path} as {uid}");
            }
            // The pass of the file (the fake volume's is its path on the volume) is the same.
            let pass = |r: &R<Done<Vec<u8>>>| match r {
                Ok(Done::Pass(p)) => Some(p.clone()),
                _ => None,
            };
            assert_eq!(pass(&a), pass(&b), "{path} as {uid}");
            let mut once = Writer::new();
            let mut stepped = Writer::new();
            let mut pw = crate::names::Prewalk::new(path.as_bytes(), false, true);
            let walked = loop {
                if let Some(done) = core.prewalk_step(&who, &mut pw) {
                    break done;
                }
            };
            let a = core.stat(&c, 0, path.as_bytes(), &mut once);
            let b = core.stat_walked(&c, 0, Some(walked), b"", &mut stepped);
            assert_eq!(a, b, "{path} as {uid}");
            assert_eq!(once.as_bytes(), stepped.as_bytes());
        }
    }
    // A path of a few components is no long one.
    assert!(!crate::names::Prewalk::long(b"/etc/passwd"));
    assert!(crate::names::Prewalk::long(b"/a/b/c/d"));
}

#[test]
fn a_step_of_the_build_makes_a_bounded_number_of_calls_to_the_volume() {
    let mut v = volume();
    for d in 0..4 {
        v.dir(&format!("/.layers/00/many{d}"), 0o755, 0);
        for i in 0..1000 {
            v.file(&format!("/.layers/00/many{d}/f{i:04}"), 0o644, 0, b"");
        }
    }
    v.batch = 20;
    let mut world = World::new();
    let mut core = world.core(v);
    core.prepare();
    let mut steps = 0;
    loop {
        let before = core.volume.calls.len();
        let done = core.build_step();
        let calls = core.volume.calls.len() - before;
        assert!(calls <= 3, "a step made {calls} calls to the volume");
        steps += 1;
        assert!(steps < 100_000);
        if done {
            break;
        }
    }
    assert_eq!(core.state, State::Ready);
    // 4,000 names in batches of 59 and the directories: many steps, none of them long.
    assert!(steps >= 4000 / 59, "{steps}");
}

/// The build of a volume to its end: the steps it took.
fn build_to_the_end(core: &mut Core<'_, FakeVolume, FakeLower>) -> u32 {
    core.prepare();
    let mut steps = 0;
    while !core.build_step() {
        steps += 1;
        assert!(steps < 200_000);
    }
    steps
}

fn status_flags(core: &Core<'_, FakeVolume, FakeLower>) -> u32 {
    let mut w = Writer::new();
    core.status(&mut w).unwrap();
    l::Stat::read(w.as_bytes()).unwrap().flags
}

#[test]
fn a_build_that_overflows_a_bucket_starts_again_under_another_seed() {
    let mut world = World::new();
    let mut core = world.core(volume());
    core.index.fail_inserts = 1;
    build_to_the_end(&mut core);
    assert_eq!(core.state, State::Ready);
    assert!(!core.partial);
    assert_eq!(core.left_out(), (0, 0));
    assert_eq!(status_flags(&core) & l::STATUS_PARTIAL, 0);
    assert!(open(&mut core, 0, f::READ_ONLY, "/etc/own.conf").is_ok());
}

#[test]
fn a_build_that_always_overflows_leaves_the_names_out_and_serves_the_root_read_only() {
    let mut world = World::new();
    let mut core = world.core(volume());
    core.index.fail_inserts = u32::MAX;
    build_to_the_end(&mut core);
    assert_eq!(core.state, State::Ready);
    assert!(core.partial);
    let (names, marks) = core.left_out();
    assert!(names > 0, "{names} {marks}");
    assert_ne!(status_flags(&core) & l::STATUS_PARTIAL, 0);
    // The names the table could not take are the lower set's or absent; the root answers.
    assert!(open(&mut core, 0, f::READ_ONLY, "/etc").is_ok());
}

#[test]
fn a_layer_over_the_places_of_the_table_serves_what_it_holds_read_only() {
    let mut v = volume();
    // More names than the table has places: 17,000 files in one directory.
    for i in 0..17_000 {
        v.file(&format!("/.layers/00/opq/f{i:05}"), 0o644, 0, b"");
    }
    v.batch = 20;
    let mut world = World::new();
    let mut core = world.core(v);
    build_to_the_end(&mut core);
    assert_eq!(core.state, State::Ready);
    assert!(core.partial);
    let (names, _) = core.left_out();
    assert!(
        names >= 17_000 + 100 - crate::index::SLOTS as u32,
        "{names}"
    );
    assert_ne!(status_flags(&core) & l::STATUS_PARTIAL, 0);
}

#[test]
fn the_volume_statuses_become_the_statuses_of_the_names() {
    let mut world = World::new();
    let mut v = volume();
    // The file is gone from the volume after the index was built.
    v.file("/.layers/00/etc/own.conf", 0o640, 1000, b"x");
    let mut core = world.core(v);
    ready(&mut core);
    core.volume
        .nodes
        .remove(b"/.layers/00/etc/own.conf".as_slice());
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/etc/own.conf").err(),
        Some(st(f::NO_ENTRY))
    );
    let _ = d::NO_ENTRY;
}

#[test]
fn a_request_looks_at_a_bounded_number_of_slots_of_the_index() {
    let mut v = volume();
    v.dir("/.layers/00/filler", 0o755, 0);
    for i in 0..1_500 {
        v.file(&format!("/.layers/00/filler/f{i:04}"), 0o644, 0, b"");
    }
    v.batch = 20;
    let mut world = World::new();
    let mut core = world.core(v);
    ready(&mut core);
    let (reply, _) = open(&mut core, 0, f::READ_ONLY | f::DIRECTORY_ONLY, "/etc").unwrap();
    let h = handle_of(&reply);
    let (names, requests) = list(&mut core, 40, h);
    let names = sorted(names);
    for expected in [".", "..", "big00", "hostname", "own.conf", "passwd"] {
        assert!(
            names.contains(&expected.to_string()),
            "{expected}: {names:?}"
        );
    }
    // The first stage follows the list of the directory's children: a directory of a few names
    // takes a few requests however large the table, a request looks at
    // `SLOTS_PER_READDIR` entries at most, and one that finds nothing says `more` with no entry.
    assert!(
        requests < crate::index::SLOTS / crate::listing::SLOTS_PER_READDIR,
        "{requests}"
    );
    let (reply, _) = open(&mut core, 0, f::READ_ONLY | f::DIRECTORY_ONLY, "/filler").unwrap();
    let h = handle_of(&reply);
    let (names, requests) = list(&mut core, 40, h);
    assert_eq!(names.len(), 1_500 + 2);
    // `ceil(1500 / 46)` requests at most for the names, one for `.` and `..`, the second stage.
    assert!(requests <= 1_500 / 20 + 4, "{requests}");
}

#[test]
fn a_dot_dot_before_the_first_lower_name_is_the_index_s_and_after_it_the_ram_service_s() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    // Through the index: the parent of a directory of the layer is exact, so the shadow of
    // /etc/passwd, the mark of /etc/motd and the closed /home are met.
    let (_, pass) = open(&mut core, 0, f::READ_ONLY, "/etc/../etc/passwd").unwrap();
    assert_eq!(pass.as_deref(), Some(&b"/.layers/00/etc/passwd"[..]));
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/etc/../etc/motd").err(),
        Some(st(f::NO_ENTRY))
    );
    assert_eq!(
        open(&mut core, 1000, f::READ_ONLY, "/etc/../home/secret").err(),
        Some(st(f::ACCESS_DENIED))
    );
    // After the first lower name (or a name the root passes through) the path goes whole to the
    // RAM file service, which answers the `..` with a redirect that routes by the path.
    for (path, target) in [
        ("/bin/../etc/motd", f::REDIRECT_RAM),
        ("/tmp/../home/secret", f::REDIRECT_RAM),
        ("/data/../home/x", f::REDIRECT_DATA),
        ("/bin/../usr/./x/../y", f::REDIRECT_RAM),
    ] {
        let (reply, _) = open(&mut core, 0, f::READ_ONLY, path).unwrap();
        let plain = path.replace("/./", "/");
        assert!(
            matches!(
                OpenAnswer::read(&reply),
                Ok(OpenAnswer::Redirect(r)) if r.path == plain.as_bytes() && r.target == target
            ),
            "{path}"
        );
    }
    // `/etc/..` and `/tmp/..` are the root of the layer.
    for path in ["/etc/..", "/etc/../etc/.."] {
        let (reply, _) = open(&mut core, 0, f::READ_ONLY, path).unwrap();
        assert!(
            matches!(OpenAnswer::read(&reply), Ok(OpenAnswer::Directory { .. })),
            "{path}"
        );
    }
}

#[test]
fn access_walks_the_path_with_the_identifiers_it_checks_the_bits_with() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    // Real user 1000, effective user 0: /home is closed to the real user and open to the
    // effective one.
    let mut v = who(0);
    v.ids.uid = 1000;
    let c = Client { owner: 40, who: &v };
    let mut w = Writer::new();
    assert!(core.access(&c, 0, 0, b"/home/secret", &mut w).is_ok());
    let mut w = Writer::new();
    assert_eq!(
        core.access(&c, 0, d::ACCESS_REAL, b"/home/secret", &mut w),
        Err(st(f::ACCESS_DENIED))
    );
}

#[test]
fn a_seek_goes_back_to_a_position_the_replies_gave_and_never_past() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    let (reply, _) = open(&mut core, 0, f::READ_ONLY, "/etc").unwrap();
    let h = handle_of(&reply);
    let owner = 40;
    // Nothing is given yet: only the start.
    assert_eq!(core.seek_dir(owner, h, n::cursor(0, 0)), Ok(()));
    assert_eq!(
        core.seek_dir(owner, h, n::cursor(0, 7)),
        Err(st(f::INVALID_ARGUMENT))
    );
    assert_eq!(
        core.seek_dir(owner, h, n::cursor(1, 0)),
        Err(st(f::INVALID_ARGUMENT))
    );
    let (bytes, len) = core.read_dir(owner, h).unwrap();
    let (_, cursor, _) = n::read_dir_reply(&bytes[..len]).unwrap();
    assert_eq!(core.seek_dir(owner, h, cursor), Ok(()));
    let (stage, at) = n::split_cursor(cursor);
    assert_eq!(
        core.seek_dir(owner, h, n::cursor(stage, at + 1)),
        Err(st(f::INVALID_ARGUMENT))
    );
    // After a rewind the furthest position stays what it was.
    core.rewind(owner, h).unwrap();
    assert_eq!(core.seek_dir(owner, h, cursor), Ok(()));
}

#[test]
fn a_file_whose_own_mode_denies_the_read_is_denied_in_an_open_directory() {
    let mut v = volume();
    v.file("/.layers/00/etc/secret", 0o600, 0, b"s");
    let mut world = World::new();
    let mut core = world.core(v);
    ready(&mut core);
    assert_eq!(
        open(&mut core, 1000, f::READ_ONLY, "/etc/secret").err(),
        Some(st(f::ACCESS_DENIED))
    );
    assert!(
        open(&mut core, 0, f::READ_ONLY, "/etc/secret")
            .unwrap()
            .1
            .is_some()
    );
}

/// CLONE and CLONE_MORE share the description of a merged directory with the child's session (the
/// choice of the split's part B: POSIX shares the open file description across a fork, so the
/// position is one). What the parent read, the child does not read again, and the lower directory
/// closes with the last holder.
#[test]
fn a_clone_shares_the_directory_position_with_the_parent() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    let parent = 40;
    let child = 9_000;
    let (reply, _) = open(&mut core, 0, 0, "/etc").unwrap();
    let h = handle_of(&reply);
    // The parent reads the first reply (the names of the layer and the first lower entries).
    let (bytes, len) = core.read_dir(parent, h).unwrap();
    let (more, _, entries) = n::read_dir_reply(&bytes[..len]).unwrap();
    assert!(more);
    let first: Vec<Vec<u8>> = entries.map(|e| e.unwrap().name.to_vec()).collect();
    assert!(first.contains(&b".".to_vec()));
    // The child's session holds it after CLONE: the same handle, the position where the parent left it.
    core.share(parent, &[h], child).unwrap();
    let (rest, _) = list(&mut core, child, h);
    let mut all = first.clone();
    all.extend(rest);
    // Every name once across the two reads, nothing twice.
    let mut once = sorted(all.clone());
    once.dedup();
    assert_eq!(once.len(), all.len());
    assert!(once.contains(&"hostname".to_owned()) && once.contains(&"own.conf".to_owned()));
    // The parent finds the end: the child consumed the rest of the one position.
    let (names, _) = list(&mut core, parent, h);
    assert!(names.is_empty());
    // A clone of a handle the session does not hold is BAD_FD, and none of the others is given.
    assert_eq!(
        core.share(parent, &[h, 0x0005_0105], 777).err(),
        Some(st(f::BAD_FD))
    );
    assert_eq!(core.descriptions(), 1);
    // The parent closes: the child's description lives on; the last holder closes it.
    core.close(parent, h).unwrap();
    assert_eq!(core.descriptions(), 1);
    assert_eq!(
        core.fstat(parent, h, &mut Writer::new()).err(),
        Some(st(f::BAD_FD))
    );
    core.fstat(child, h, &mut Writer::new()).unwrap();
    core.close(child, h).unwrap();
    assert_eq!(core.descriptions(), 0);
    // A session that goes without a close lets go of its share too.
    let (reply, _) = open(&mut core, 0, 0, "/etc").unwrap();
    let h = handle_of(&reply);
    core.share(parent, &[h], child).unwrap();
    core.gone(parent);
    assert_eq!(core.descriptions(), 1);
    core.gone(child);
    assert_eq!(core.descriptions(), 0);
}
