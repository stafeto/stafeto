// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The tests of the changes of names (`change`) over a volume and a lower set in memory: each
//! change and its refusals, what stays on the volume, what the index and the listing say, and a
//! start again from the volume that must see the same names.

use crate::composition::Composition;
use crate::identity::{Vouched, vouched_from};
use crate::index::{Index, Kind, OPAQUE};
use crate::names::{Client, Core, Done, State};
use crate::scan::Scan;
use crate::testkit::{FakeLower, FakeVolume};
use proto_data as d;
use proto_fs as f;
use proto_fs::names::{self as n, ChangeOp, OpenAnswer, UPPER_INO_TAG};
use proto_wire::{Status, Writer};
use std::boxed::Box;
use std::string::String;
use std::vec::Vec;

type C<'a> = Core<'a, FakeVolume, FakeLower>;

fn st(code: u32) -> Status {
    Status::Unknown(code)
}

/// The live layer 00 of the volume: /etc (a mark for motd, a shadow of passwd, a file of user
/// 1000), /shared (sticky, world-writable) with a file of root, and /opq (opaque).
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
        .dir("/.layers/00/shared", 0o1777, 0)
        .file("/.layers/00/shared/rootfile", 0o644, 0, b"r")
        .file("/.layers/00/shared/userfile", 0o644, 1000, b"u")
        .dir("/.layers/00/opq", 0o755, 0)
        .file("/.layers/00/opq/.wh..wh..opq", 0o644, 0, b"")
        .file("/.layers/00/opq/u1", 0o644, 0, b"u1");
    v
}

fn lower() -> FakeLower {
    let mut l = FakeLower::new();
    l.dir("/etc", 10)
        .file("/etc/motd", 11)
        .file("/etc/passwd", 12)
        .file("/etc/hostname", 13)
        .dir("/bin", 20)
        .file("/bin/ls", 21)
        .dir("/lowdir", 30)
        .attr("/lowdir", 0o750, 5, 6)
        .file("/lowdir/l1", 31)
        .dir("/gone", 40)
        .file("/gone/x", 41)
        .dir("/empty", 45)
        .dir("/deep", 50)
        .dir("/deep/a", 51)
        .dir("/deep/a/b", 52)
        .dir("/shared", 60)
        .dir("/opq", 70)
        .file("/opq/l1", 71)
        .dir("/opq/sub", 72)
        .file("/opq/sub/lx", 73)
        .link("/lowlink", 80)
        .file("/rootonly", 81)
        .attr("/rootonly", 0o600, 0, 0);
    let long = "a".repeat(250);
    l.dir(&format!("/{long}"), 90);
    l
}

struct World {
    index: Box<Index>,
    scan: Box<Scan>,
}

impl World {
    fn new() -> World {
        World {
            index: crate::index::boxed(),
            scan: Box::new(Scan::new()),
        }
    }

    fn core(&mut self, v: FakeVolume) -> C<'_> {
        Core::new(&mut self.index, &mut self.scan, v, lower(), 5)
    }
}

fn ready(core: &mut C<'_>) {
    core.prepare();
    assert_eq!(core.state, State::Starting);
    let mut steps = 0;
    while !core.build_step() {
        steps += 1;
        assert!(steps < 2000);
    }
    assert_eq!(core.state, State::Ready);
}

fn who(uid: u32) -> Vouched {
    vouched_from(&crate::identity::tests_who(uid)).unwrap()
}

fn open(
    core: &mut C<'_>,
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

fn change(
    core: &mut C<'_>,
    uid: u32,
    op: ChangeOp,
    a: u64,
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
        b: 0,
        first: first.as_bytes(),
        second: second.as_bytes(),
    };
    core.change(&c, &req, &mut w)?;
    Ok(w.as_bytes().to_vec())
}

fn mkdir(core: &mut C<'_>, uid: u32, path: &str, mode: u64) -> Result<(), Status> {
    change(core, uid, ChangeOp::Mkdir, mode, path, "").map(drop)
}

fn unlink(core: &mut C<'_>, uid: u32, path: &str) -> Result<(), Status> {
    change(core, uid, ChangeOp::Unlink, 0, path, "").map(drop)
}

fn rmdir(core: &mut C<'_>, uid: u32, path: &str) -> Result<(), Status> {
    change(core, uid, ChangeOp::Rmdir, 0, path, "").map(drop)
}

fn rename(core: &mut C<'_>, uid: u32, from: &str, to: &str) -> Result<(), Status> {
    change(core, uid, ChangeOp::Rename, 0, from, to).map(drop)
}

fn symlink(core: &mut C<'_>, uid: u32, path: &str, text: &str) -> Result<(), Status> {
    change(core, uid, ChangeOp::Symlink, 0, path, text).map(drop)
}

/// The flags of a create as the layer sends them: the mode in the high bits.
fn creating(access: u32, mode: u32) -> u32 {
    n::with_permissions(access | f::CREATE, mode)
}

fn stat(core: &mut C<'_>, uid: u32, path: &str, flags: u32) -> Result<Vec<u8>, Status> {
    let v = who(uid);
    let c = Client {
        owner: 40 + u64::from(uid),
        who: &v,
    };
    let mut w = Writer::new();
    core.stat(&c, flags, path.as_bytes(), &mut w)?;
    Ok(w.as_bytes().to_vec())
}

fn readlink(core: &mut C<'_>, uid: u32, path: &str) -> Result<Vec<u8>, Status> {
    let v = who(uid);
    let c = Client {
        owner: 40 + u64::from(uid),
        who: &v,
    };
    let mut w = Writer::new();
    core.readlink(&c, path.as_bytes(), &mut w)?;
    Ok(w.as_bytes()[4..].to_vec())
}

fn names_of(core: &mut C<'_>, owner_uid: u32, path: &str) -> Vec<String> {
    let (reply, _) = open(core, 0, f::READ_ONLY | f::DIRECTORY_ONLY, path).unwrap();
    let h = match OpenAnswer::read(&reply).unwrap() {
        OpenAnswer::Directory { handle } => handle,
        other => panic!("{other:?}"),
    };
    let owner = 40 + u64::from(owner_uid);
    let _ = owner;
    let mut names = Vec::new();
    let mut rounds = 0;
    loop {
        let (bytes, len) = core.read_dir(40, h).unwrap();
        rounds += 1;
        assert!(rounds < 200);
        let (more, _, entries) = n::read_dir_reply(&bytes[..len]).unwrap();
        for e in entries {
            let e = e.unwrap();
            names.push(format!(
                "{}:{}",
                String::from_utf8(e.name.to_vec()).unwrap(),
                e.kind
            ));
        }
        if !more {
            break;
        }
    }
    core.close(40, h).unwrap();
    names.sort();
    names
}

/// Every name a description gives, the dots left out.
fn drain(core: &mut C<'_>, owner: u64, h: u32) -> Vec<Vec<u8>> {
    let mut names = Vec::new();
    let mut rounds = 0;
    loop {
        let (bytes, len) = core.read_dir(owner, h).unwrap();
        rounds += 1;
        assert!(rounds < 200);
        let (more, _, entries) = n::read_dir_reply(&bytes[..len]).unwrap();
        for e in entries {
            let name = e.unwrap().name.to_vec();
            if name != b"." && name != b".." {
                names.push(name);
            }
        }
        if !more {
            return names;
        }
    }
}

fn listing(core: &mut C<'_>, path: &str) -> Vec<String> {
    names_of(core, 0, path)
        .into_iter()
        .filter(|n| !n.starts_with(".:") && !n.starts_with("..:"))
        .map(|n| n.split(':').next().unwrap().to_owned())
        .collect()
}

fn node<'a>(core: &'a C<'_>, path: &str) -> Option<&'a crate::testkit::Node> {
    core.volume.nodes.get(path.as_bytes())
}

fn is_redirect(reply: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
    match OpenAnswer::read(reply) {
        Ok(OpenAnswer::Redirect(r)) => Some((r.target, r.index, r.path.to_vec())),
        _ => None,
    }
}

fn redirect_of(reply: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
    f::Redirect::read_reply(reply)
        .and_then(Result::ok)
        .map(|r| (r.target, r.index, r.path.to_vec()))
}

// ---------------------------------------------------------------------- create and write

#[test]
fn a_file_is_made_with_its_owner_its_mode_and_a_number_of_the_layer() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    // /shared is the sticky 1777 directory: the user makes a file there.
    let (reply, pass) = open(
        &mut core,
        1000,
        creating(f::READ_WRITE, 0o640),
        "/shared/mine",
    )
    .unwrap();
    assert_eq!(OpenAnswer::read(&reply), Ok(OpenAnswer::Pass));
    assert_eq!(pass.as_deref(), Some(&b"/.layers/00/shared/mine"[..]));
    let made = node(&core, "/.layers/00/shared/mine").unwrap();
    assert_eq!((made.uid, made.gid, made.mode), (1000, 100, 0o640));
    assert!(made.ino & UPPER_INO_TAG != 0 && made.ino & (1 << 63) == 0);
    // The file was opened for reading and writing, once made, and was prepared in work/.
    assert!(
        core.volume
            .opens
            .iter()
            .any(|(p, fl)| p == b"/.layers/00/shared/mine"
                && fl & d::WRITE != 0
                && fl & d::READ != 0)
    );
    assert!(core.volume.children(b"/.layers/work").is_empty());
    // The index holds it, the listing shows it, and a second open finds it as a name of the layer.
    let id = core
        .index
        .lookup(core.index.lookup(0, b"shared").unwrap().0, b"mine");
    assert_eq!(
        id.map(|(_, e)| (e.kind, e.number)),
        Some((Kind::File, made.ino))
    );
    assert!(listing(&mut core, "/shared").contains(&"mine".to_owned()));
    assert!(
        open(&mut core, 1000, f::READ_ONLY, "/shared/mine")
            .unwrap()
            .1
            .is_some()
    );
    // The same name again with EXCLUSIVE exists; without it the file is opened.
    assert_eq!(
        open(
            &mut core,
            1000,
            creating(f::READ_WRITE, 0o600) | f::EXCLUSIVE,
            "/shared/mine"
        )
        .err(),
        Some(st(f::ALREADY_EXISTS))
    );
    assert!(
        open(
            &mut core,
            1000,
            creating(f::READ_WRITE, 0o600),
            "/shared/mine"
        )
        .unwrap()
        .1
        .is_some()
    );
    assert_eq!(node(&core, "/.layers/00/shared/mine").unwrap().mode, 0o640);
}

#[test]
fn the_numbers_of_the_files_come_from_the_counter_of_the_composition() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    let mut seen = Vec::new();
    for i in 0..300 {
        let path = std::format!("/shared/f{i}");
        open(&mut core, 0, creating(f::WRITE_ONLY, 0o600), &path).unwrap();
        seen.push(node(&core, &std::format!("/.layers/00{path}")).unwrap().ino);
    }
    let mut once = seen.clone();
    once.sort_unstable();
    once.dedup();
    assert_eq!(once.len(), 300);
    assert!(seen.iter().all(|n| n & UPPER_INO_TAG != 0));
    // The counter was written back in blocks: twice for 300 numbers of blocks of 256.
    let text = &node(&core, "/.layers/COMPOSITION").unwrap().data;
    let written = Composition::parse(text).unwrap();
    assert_eq!(written.ino, 1 + 2 * 256);
    // A start again from the volume goes on past what was reserved.
    let v = core.volume;
    let mut again = World::new();
    let mut core = again.core(v);
    ready(&mut core);
    open(
        &mut core,
        0,
        creating(f::WRITE_ONLY, 0o600),
        "/shared/after",
    )
    .unwrap();
    let n = node(&core, "/.layers/00/shared/after").unwrap().ino;
    assert!(n & !UPPER_INO_TAG > 2 * 256 && !seen.contains(&n));
}

#[test]
fn a_create_below_a_lower_directory_copies_the_directories_up_with_their_attributes() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    // /lowdir is 0750 5:6 in the lower set only; the superuser makes a file in it.
    open(&mut core, 0, creating(f::WRITE_ONLY, 0o600), "/lowdir/new").unwrap();
    let dir = node(&core, "/.layers/00/lowdir").unwrap();
    assert!(dir.dir);
    assert_eq!((dir.uid, dir.gid, dir.mode), (5, 6, 0o750));
    assert!(node(&core, "/.layers/00/lowdir/new").is_some());
    // The layer lists the directory with the lower names too.
    assert_eq!(listing(&mut core, "/lowdir"), ["l1", "new"]);
    // Three levels at once.
    open(
        &mut core,
        0,
        creating(f::WRITE_ONLY, 0o644),
        "/deep/a/b/leaf",
    )
    .unwrap();
    for path in ["deep", "deep/a", "deep/a/b"] {
        assert!(
            node(&core, &std::format!("/.layers/00/{path}"))
                .unwrap()
                .dir,
            "{path}"
        );
    }
    assert_eq!(
        node(&core, "/.layers/00/deep/a/b/leaf").unwrap().mode,
        0o644
    );
    assert!(core.volume.children(b"/.layers/work").is_empty());
}

#[test]
fn a_create_needs_write_and_search_on_the_directory_and_refuses_the_layer_s_names() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    // /etc is 0755 of root: user 1000 may not make a name there, and nothing was made.
    assert_eq!(
        open(&mut core, 1000, creating(f::WRITE_ONLY, 0o600), "/etc/new").err(),
        Some(st(f::ACCESS_DENIED))
    );
    assert!(node(&core, "/.layers/00/etc/new").is_none());
    // The lower /rootonly directory-less case: a lower directory of mode 0750 5:6 is closed to
    // user 1000 (no search bit for others), whatever it holds.
    assert_eq!(
        open(&mut core, 1000, creating(f::WRITE_ONLY, 0o600), "/lowdir/x").err(),
        Some(st(f::ACCESS_DENIED))
    );
    assert!(
        node(&core, "/.layers/00/lowdir").is_none(),
        "no directory is made for a refusal"
    );
    // The names `.wh.*` are the layer's own, and a name below a file is no directory.
    for path in [
        "/shared/.wh.x",
        "/shared/.wh..wh..opq",
        "/shared/.wh..wh.lnk.y",
    ] {
        assert_eq!(
            open(&mut core, 0, creating(f::WRITE_ONLY, 0o600), path).err(),
            Some(st(f::INVALID_ARGUMENT)),
            "{path}"
        );
    }
    assert_eq!(
        open(
            &mut core,
            0,
            creating(f::WRITE_ONLY, 0o600),
            "/shared/rootfile/x"
        )
        .err(),
        Some(st(f::NOT_DIRECTORY))
    );
    assert_eq!(
        open(&mut core, 0, creating(f::WRITE_ONLY, 0o600), "/nodir/x").err(),
        Some(st(f::NO_ENTRY))
    );
    assert_eq!(
        open(&mut core, 0, creating(f::WRITE_ONLY, 0o600), "/shared/dir/").err(),
        Some(st(f::IS_DIRECTORY))
    );
    // A name whose path on the volume would pass the limit of the volume.
    let long = "a".repeat(250);
    let path = std::format!("/{long}/{}", "b".repeat(250));
    assert_eq!(
        open(&mut core, 0, creating(f::WRITE_ONLY, 0o600), &path).err(),
        Some(st(f::NAME_TOO_LONG))
    );
    assert!(core.volume.children(b"/.layers/work").is_empty());
}

#[test]
fn an_upper_file_is_opened_for_writing_by_who_may_write_it() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    // /etc/own.conf is 0640 of user 1000: the owner writes, another user does not, root does.
    let (reply, pass) = open(&mut core, 1000, f::READ_WRITE | f::APPEND, "/etc/own.conf").unwrap();
    assert_eq!(OpenAnswer::read(&reply), Ok(OpenAnswer::Pass));
    assert!(pass.is_some());
    let last = core.volume.opens.last().unwrap().clone();
    assert_eq!(last.1, d::READ | d::WRITE | d::APPEND);
    assert_eq!(
        open(&mut core, 1001, f::WRITE_ONLY, "/etc/own.conf").err(),
        Some(st(f::ACCESS_DENIED))
    );
    assert!(
        open(&mut core, 0, f::WRITE_ONLY | f::TRUNCATE, "/etc/own.conf")
            .unwrap()
            .1
            .is_some()
    );
    assert_eq!(core.volume.opens.last().unwrap().1, d::WRITE | d::TRUNCATE);
    // O_TRUNC with read access writes: it needs the right to write.
    assert_eq!(
        open(&mut core, 1001, f::READ_ONLY | f::TRUNCATE, "/etc/passwd").err(),
        Some(st(f::ACCESS_DENIED))
    );
    // The shadow of a lower file is the layer's file: written. The lower one is not.
    assert!(
        open(&mut core, 0, f::WRITE_ONLY, "/etc/passwd")
            .unwrap()
            .1
            .is_some()
    );
    assert_eq!(
        open(&mut core, 0, f::WRITE_ONLY, "/etc/hostname").err(),
        Some(st(f::READ_ONLY_FILESYSTEM))
    );
}

// ---------------------------------------------------------------------- mkdir

#[test]
fn a_directory_is_made_in_the_layer_with_its_owner_and_the_lower_one_is_copied_up_first() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    mkdir(&mut core, 1000, "/shared/mine", 0o750).unwrap();
    let made = node(&core, "/.layers/00/shared/mine").unwrap();
    assert!(made.dir);
    assert_eq!((made.uid, made.gid, made.mode), (1000, 100, 0o750));
    assert!(listing(&mut core, "/shared").contains(&"mine".to_owned()));
    // Below a lower-only directory: the directory is copied up.
    mkdir(&mut core, 0, "/bin/sub", 0o755).unwrap();
    assert!(node(&core, "/.layers/00/bin").unwrap().dir);
    assert!(node(&core, "/.layers/00/bin/sub").unwrap().dir);
    assert_eq!(listing(&mut core, "/bin"), ["ls", "sub"]);
    // Refusals: the name is there (in the layer, and in the lower set), the directory is closed,
    // the name is the layer's own, or the parent is no directory.
    for path in [
        "/shared/mine",
        "/etc/own.conf",
        "/etc/hostname",
        "/bin/ls",
        "/etc",
        "/",
    ] {
        assert_eq!(
            mkdir(&mut core, 0, path, 0o755).err(),
            Some(st(f::ALREADY_EXISTS)),
            "{path}"
        );
    }
    assert_eq!(
        mkdir(&mut core, 1000, "/etc/d", 0o755).err(),
        Some(st(f::ACCESS_DENIED))
    );
    assert_eq!(
        mkdir(&mut core, 0, "/shared/.wh.d", 0o755).err(),
        Some(st(f::INVALID_ARGUMENT))
    );
    assert_eq!(
        mkdir(&mut core, 0, "/etc/own.conf/d", 0o755).err(),
        Some(st(f::NOT_DIRECTORY))
    );
    assert_eq!(
        mkdir(&mut core, 0, "/nowhere/d", 0o755).err(),
        Some(st(f::NO_ENTRY))
    );
}

#[test]
fn a_directory_with_a_group_bit_in_its_parent_passes_the_group_on() {
    let mut v = volume();
    v.dir("/.layers/00/setgid", 0o2775, 0);
    let mut world = World::new();
    let mut core = world.core(v);
    ready(&mut core);
    // The index holds what the scan stat'ed: the group of the parent is 0 there, so set it to a
    // group the user is in (7), which is not the user's own group (100).
    core.volume
        .nodes
        .get_mut(b"/.layers/00/setgid".as_slice())
        .unwrap()
        .gid = 7;
    let id = core.index.lookup(0, b"setgid").unwrap().0;
    core.index.set_attr(id, 1, 0, 7, 0o2775);
    mkdir(&mut core, 1000, "/setgid/d", 0o755).unwrap();
    let made = node(&core, "/.layers/00/setgid/d").unwrap();
    assert_eq!((made.gid, made.mode), (7, 0o2755));
}

// ---------------------------------------------------------------------- unlink and rmdir

#[test]
fn a_name_only_the_layer_has_goes_with_no_mark_and_a_lower_one_is_marked() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    // A name of the layer alone: nothing to hide below it.
    unlink(&mut core, 0, "/etc/own.conf").unwrap();
    assert!(node(&core, "/.layers/00/etc/own.conf").is_none());
    assert!(node(&core, "/.layers/00/etc/.wh.own.conf").is_none());
    assert!(!listing(&mut core, "/etc").contains(&"own.conf".to_owned()));
    // The layer's file that shadows a lower one: the lower one must not show again.
    unlink(&mut core, 0, "/etc/passwd").unwrap();
    assert!(node(&core, "/.layers/00/etc/passwd").is_none());
    assert!(node(&core, "/.layers/00/etc/.wh.passwd").is_some());
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/etc/passwd").err(),
        Some(st(f::NO_ENTRY))
    );
    // A name of the lower set alone is a mark, in a directory the layer holds or makes.
    unlink(&mut core, 0, "/etc/hostname").unwrap();
    assert!(node(&core, "/.layers/00/etc/.wh.hostname").is_some());
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/etc/hostname").err(),
        Some(st(f::NO_ENTRY))
    );
    unlink(&mut core, 0, "/bin/ls").unwrap();
    assert!(
        node(&core, "/.layers/00/bin").unwrap().dir,
        "the directory is copied up for the mark"
    );
    assert!(node(&core, "/.layers/00/bin/.wh.ls").is_some());
    let listed = listing(&mut core, "/etc");
    for gone in ["own.conf", "passwd", "hostname", "motd"] {
        assert!(!listed.contains(&gone.to_owned()), "{gone}: {listed:?}");
    }
    assert!(listing(&mut core, "/bin").is_empty());
    // The marks are written through work/ and a start again sees the same names.
    assert!(core.volume.children(b"/.layers/work").is_empty());
    let v = core.volume;
    let mut again = World::new();
    let mut core = again.core(v);
    ready(&mut core);
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/etc/hostname").err(),
        Some(st(f::NO_ENTRY))
    );
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/bin/ls").err(),
        Some(st(f::NO_ENTRY))
    );
    // The name is made again: the mark stays out of the way.
    open(
        &mut core,
        0,
        creating(f::WRITE_ONLY, 0o600),
        "/etc/hostname",
    )
    .unwrap();
    assert!(node(&core, "/.layers/00/etc/hostname").is_some());
    assert!(
        node(&core, "/.layers/00/etc/.wh.hostname").is_none(),
        "the mark goes with the new name"
    );
    assert!(listing(&mut core, "/etc").contains(&"hostname".to_owned()));
}

#[test]
fn unlink_refuses_what_it_should() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    assert_eq!(
        unlink(&mut core, 0, "/etc/none").err(),
        Some(st(f::NO_ENTRY))
    );
    assert_eq!(
        unlink(&mut core, 0, "/etc/motd").err(),
        Some(st(f::NO_ENTRY)),
        "already marked"
    );
    assert_eq!(
        unlink(&mut core, 0, "/shared").err(),
        Some(st(f::IS_DIRECTORY))
    );
    assert_eq!(
        unlink(&mut core, 0, "/bin").err(),
        Some(st(f::IS_DIRECTORY))
    );
    assert_eq!(
        unlink(&mut core, 0, "/etc/own.conf/").err(),
        Some(st(f::NOT_DIRECTORY))
    );
    assert_eq!(unlink(&mut core, 0, "/").err(), Some(st(f::BUSY)));
    assert_eq!(
        unlink(&mut core, 0, "/etc/.wh.motd").err(),
        Some(st(f::INVALID_ARGUMENT))
    );
    // /etc is closed to user 1000 for writes.
    assert_eq!(
        unlink(&mut core, 1000, "/etc/own.conf").err(),
        Some(st(f::ACCESS_DENIED))
    );
    assert_eq!(
        unlink(&mut core, 1000, "/etc/hostname").err(),
        Some(st(f::ACCESS_DENIED))
    );
    assert!(node(&core, "/.layers/00/etc/own.conf").is_some());
    assert!(node(&core, "/.layers/00/etc/.wh.hostname").is_none());
}

#[test]
fn a_sticky_directory_lets_the_owner_of_the_name_or_of_the_directory_remove_it() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    // /shared is 1777 of root: user 1001 does not own userfile (1000) or the directory.
    assert_eq!(
        unlink(&mut core, 1001, "/shared/userfile").err(),
        Some(st(f::PERMISSION))
    );
    assert_eq!(
        unlink(&mut core, 1001, "/shared/rootfile").err(),
        Some(st(f::PERMISSION))
    );
    assert!(node(&core, "/.layers/00/shared/userfile").is_some());
    // The owner of the name does, and so does root.
    unlink(&mut core, 1000, "/shared/userfile").unwrap();
    unlink(&mut core, 0, "/shared/rootfile").unwrap();
    // A rename out of a sticky directory is the same.
    open(&mut core, 1000, creating(f::WRITE_ONLY, 0o600), "/shared/a").unwrap();
    assert_eq!(
        rename(&mut core, 1001, "/shared/a", "/shared/b").err(),
        Some(st(f::PERMISSION))
    );
    rename(&mut core, 1000, "/shared/a", "/shared/b").unwrap();
    // An rmdir too.
    mkdir(&mut core, 1000, "/shared/d", 0o755).unwrap();
    assert_eq!(
        rmdir(&mut core, 1001, "/shared/d").err(),
        Some(st(f::PERMISSION))
    );
    rmdir(&mut core, 1000, "/shared/d").unwrap();
}

#[test]
fn rmdir_takes_a_directory_that_is_empty_in_the_merged_view_and_marks_a_lower_one() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    // A directory of the layer alone.
    mkdir(&mut core, 0, "/shared/new", 0o755).unwrap();
    open(
        &mut core,
        0,
        creating(f::WRITE_ONLY, 0o600),
        "/shared/new/f",
    )
    .unwrap();
    assert_eq!(
        rmdir(&mut core, 0, "/shared/new").err(),
        Some(st(f::NOT_EMPTY))
    );
    unlink(&mut core, 0, "/shared/new/f").unwrap();
    rmdir(&mut core, 0, "/shared/new").unwrap();
    assert!(node(&core, "/.layers/00/shared/new").is_none());
    assert!(
        node(&core, "/.layers/00/shared/.wh.new").is_none(),
        "nothing below it to hide"
    );
    // A lower directory with a name in it is not empty; /gone/x deleted, it is, and the marks
    // inside the directory of the layer go with it.
    assert_eq!(rmdir(&mut core, 0, "/gone").err(), Some(st(f::NOT_EMPTY)));
    unlink(&mut core, 0, "/gone/x").unwrap();
    assert!(node(&core, "/.layers/00/gone/.wh.x").is_some());
    rmdir(&mut core, 0, "/gone").unwrap();
    assert!(node(&core, "/.layers/00/gone").is_none());
    assert!(node(&core, "/.layers/00/gone/.wh.x").is_none());
    assert!(node(&core, "/.layers/00/.wh.gone").is_some());
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/gone").err(),
        Some(st(f::NO_ENTRY))
    );
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/gone/x").err(),
        Some(st(f::NO_ENTRY))
    );
    assert!(!listing(&mut core, "/").contains(&"gone".to_owned()));
    // An empty lower directory: a mark.
    rmdir(&mut core, 0, "/empty").unwrap();
    assert!(node(&core, "/.layers/00/.wh.empty").is_some());
    assert!(core.volume.children(b"/.layers/work").is_empty());
    // Refusals.
    assert_eq!(
        rmdir(&mut core, 0, "/etc/own.conf").err(),
        Some(st(f::NOT_DIRECTORY))
    );
    assert_eq!(
        rmdir(&mut core, 0, "/etc/none").err(),
        Some(st(f::NO_ENTRY))
    );
    assert_eq!(rmdir(&mut core, 0, "/").err(), Some(st(f::BUSY)));
    assert_eq!(rmdir(&mut core, 0, "/etc").err(), Some(st(f::NOT_EMPTY)));
    assert_eq!(
        rmdir(&mut core, 1000, "/empty").err(),
        Some(st(f::NO_ENTRY))
    );
}

#[test]
fn a_directory_over_a_removed_lower_one_is_opaque() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    unlink(&mut core, 0, "/gone/x").unwrap();
    rmdir(&mut core, 0, "/gone").unwrap();
    mkdir(&mut core, 0, "/gone", 0o700).unwrap();
    assert!(node(&core, "/.layers/00/gone/.wh..wh..opq").is_some());
    assert!(
        node(&core, "/.layers/00/.wh.gone").is_none(),
        "the mark goes with the new directory"
    );
    let id = core.index.lookup(0, b"gone").unwrap().0;
    assert_ne!(core.index.flags(id) & OPAQUE, 0);
    assert!(listing(&mut core, "/gone").is_empty());
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/gone/x").err(),
        Some(st(f::NO_ENTRY))
    );
    // A new lower name does not show through either; a name of the layer does.
    open(&mut core, 0, creating(f::WRITE_ONLY, 0o600), "/gone/own").unwrap();
    assert_eq!(listing(&mut core, "/gone"), ["own"]);
    // A start again sees the opaque directory.
    let v = core.volume;
    let mut again = World::new();
    let mut core = again.core(v);
    ready(&mut core);
    assert_eq!(listing(&mut core, "/gone"), ["own"]);
    // A directory over a lower directory the layer never deleted is not made at all (EEXIST), and
    // one over a deleted lower file needs no opaque marker.
    unlink(&mut core, 0, "/etc/hostname").unwrap();
    mkdir(&mut core, 0, "/etc/hostname", 0o755).unwrap();
    assert!(node(&core, "/.layers/00/etc/hostname/.wh..wh..opq").is_none());
}

#[test]
fn a_directory_made_below_an_opaque_one_has_none_of_the_lower_names() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    // /opq is opaque and the lower set has /opq/sub with a name in it: the new directory is a new
    // one, whatever the lower set has under the same path.
    mkdir(&mut core, 0, "/opq/sub", 0o755).unwrap();
    assert!(node(&core, "/.layers/00/opq/sub/.wh..wh..opq").is_none());
    assert!(listing(&mut core, "/opq/sub").is_empty());
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/opq/sub/lx").err(),
        Some(st(f::NO_ENTRY))
    );
    open(&mut core, 0, creating(f::WRITE_ONLY, 0o600), "/opq/sub/new").unwrap();
    assert_eq!(listing(&mut core, "/opq/sub"), ["new"]);
    // A lower link to a directory that the layer deleted and a directory made over it: opaque, so
    // the directory the link names does not show through.
    unlink(&mut core, 0, "/lowlink").unwrap();
    assert!(node(&core, "/.layers/00/.wh.lowlink").is_some());
    mkdir(&mut core, 0, "/lowlink", 0o755).unwrap();
    assert!(node(&core, "/.layers/00/lowlink/.wh..wh..opq").is_some());
}

#[test]
fn removing_or_moving_an_opaque_directory_keeps_the_deleted_lower_one_deleted() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    // /gone: delete the lower directory, make an opaque one over it, remove that one: the lower
    // directory stays deleted (a mark is made again).
    unlink(&mut core, 0, "/gone/x").unwrap();
    rmdir(&mut core, 0, "/gone").unwrap();
    mkdir(&mut core, 0, "/gone", 0o755).unwrap();
    rmdir(&mut core, 0, "/gone").unwrap();
    assert!(node(&core, "/.layers/00/.wh.gone").is_some());
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/gone/x").err(),
        Some(st(f::NO_ENTRY))
    );
    assert!(!listing(&mut core, "/").contains(&"gone".to_owned()));
    // Moving an opaque directory: a mark at the old name, and no lower content at the new one.
    mkdir(&mut core, 0, "/gone", 0o755).unwrap();
    open(&mut core, 0, creating(f::WRITE_ONLY, 0o600), "/gone/own").unwrap();
    rename(&mut core, 0, "/gone", "/moved").unwrap();
    assert!(node(&core, "/.layers/00/.wh.gone").is_some());
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/gone/x").err(),
        Some(st(f::NO_ENTRY))
    );
    assert_eq!(listing(&mut core, "/moved"), ["own"]);
    // A directory moved onto an opaque one over a lower directory is opaque too.
    rmdir(&mut core, 0, "/empty").unwrap();
    mkdir(&mut core, 0, "/empty", 0o755).unwrap();
    mkdir(&mut core, 0, "/src", 0o755).unwrap();
    open(&mut core, 0, creating(f::WRITE_ONLY, 0o600), "/src/s").unwrap();
    rename(&mut core, 0, "/src", "/empty").unwrap();
    assert_eq!(listing(&mut core, "/empty"), ["s"]);
    assert!(node(&core, "/.layers/00/empty/.wh..wh..opq").is_some());
    // rmdir of it marks the lower directory again.
    unlink(&mut core, 0, "/empty/s").unwrap();
    rmdir(&mut core, 0, "/empty").unwrap();
    assert!(node(&core, "/.layers/00/.wh.empty").is_some());
}

#[test]
fn a_rename_that_takes_a_subtree_past_the_limit_on_paths_is_refused() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    // /etc/dA with five levels of 80 bytes below it: 405 bytes under the directory.
    mkdir(&mut core, 0, "/etc/dA", 0o755).unwrap();
    let mut path = String::from("/etc/dA");
    for i in 0..5 {
        path.push('/');
        path.push_str(&format!("{i}").repeat(80));
        mkdir(&mut core, 0, &path, 0o755).unwrap();
    }
    let long = "n".repeat(80);
    assert_eq!(
        rename(&mut core, 0, "/etc/dA", &format!("/etc/{long}")).err(),
        Some(st(f::NAME_TOO_LONG))
    );
    assert!(node(&core, "/.layers/00/etc/dA").is_some());
    rename(&mut core, 0, "/etc/dA", "/etc/dB").unwrap();
    assert!(
        core.index.reach(
            core.index
                .lookup(core.index.lookup(0, b"etc").unwrap().0, b"dB")
                .unwrap()
                .0
        ) >= 405
    );
}

#[test]
fn the_build_lifts_how_far_each_directory_reaches() {
    let mut v = volume();
    let mut path = String::from("/.layers/00/etc");
    for i in 0..5 {
        path.push('/');
        path.push_str(&format!("{i}").repeat(40));
        v.dir(&path, 0o755, 0);
    }
    v.file(&format!("{path}/leaf"), 0o644, 0, b"x");
    let mut world = World::new();
    let mut core = world.core(v);
    ready(&mut core);
    let etc = core.index.lookup(0, b"etc").unwrap().0;
    // Five levels of 41 bytes and "/leaf".
    assert_eq!(core.index.reach(etc), 5 * 41 + 5);
}

#[test]
fn the_build_leaves_out_a_directory_whose_path_the_volume_refuses() {
    let mut v = volume();
    let mut path = String::from("/.layers/00/etc");
    for _ in 0..6 {
        path.push('/');
        path.push_str(&"q".repeat(90));
        v.dir(&path, 0o755, 0);
    }
    let mut world = World::new();
    let mut core = world.core(v);
    ready(&mut core);
    assert_eq!(core.skipped(), 1);
    // The rest of the layer is served.
    assert!(
        open(&mut core, 0, f::READ_ONLY, "/etc/own.conf")
            .unwrap()
            .1
            .is_some()
    );
}

#[test]
fn a_link_over_a_file_and_a_file_over_a_link_leave_one_name_and_an_empty_target_is_refused() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    assert_eq!(
        symlink(&mut core, 0, "/shared/e", "").err(),
        Some(st(f::NO_ENTRY))
    );
    symlink(&mut core, 0, "/shared/ln", "rootfile").unwrap();
    // A link over a file: the file's own entry goes, one name stays and it is a link.
    rename(&mut core, 0, "/shared/ln", "/shared/rootfile").unwrap();
    assert!(node(&core, "/.layers/00/shared/rootfile").is_none());
    assert!(node(&core, "/.layers/00/shared/.wh..wh.lnk.rootfile").is_some());
    assert_eq!(
        readlink(&mut core, 0, "/shared/rootfile").unwrap(),
        b"rootfile"
    );
    // A file over a link: the link's file goes.
    open(&mut core, 0, creating(f::WRITE_ONLY, 0o600), "/shared/f").unwrap();
    rename(&mut core, 0, "/shared/f", "/shared/rootfile").unwrap();
    assert!(node(&core, "/.layers/00/shared/.wh..wh.lnk.rootfile").is_none());
    assert!(node(&core, "/.layers/00/shared/rootfile").is_some());
    // A cut that left both: the file wins at the start.
    let mut v = core.volume;
    v.file("/.layers/00/shared/.wh..wh.lnk.rootfile", 0o644, 0, b"x");
    let mut again = World::new();
    let mut core = again.core(v);
    ready(&mut core);
    let shared = core.index.lookup(0, b"shared").unwrap().0;
    assert_eq!(
        core.index.lookup(shared, b"rootfile").map(|(_, e)| e.kind),
        Some(Kind::File)
    );
}

#[test]
fn create_and_unlink_churn_never_fills_the_probes() {
    let mut ix = crate::index::boxed();
    let f = crate::index::Fields {
        kind: Kind::File,
        layer: 0,
        number: 0,
        uid: 0,
        gid: 0,
        mode: 0,
    };
    // A name is made and removed again and again: its slot is a gone entry the next name takes.
    let mut live = std::collections::VecDeque::new();
    for i in 0..20_000u32 {
        let name = format!("c{i}");
        let id = ix
            .insert(0, name.as_bytes(), f)
            .expect("a place for the name");
        live.push_back(id);
        if live.len() > 500 {
            ix.remove(live.pop_front().unwrap());
        }
    }
    assert_eq!(ix.counts().0, 500);
}

#[test]
fn the_index_says_whether_a_name_has_room_before_the_volume_is_touched() {
    let mut ix = crate::index::boxed();
    assert!(ix.has_room(0, b"x"));
    assert!(!ix.has_room(99, b"x"));
    let f = crate::index::Fields {
        kind: Kind::File,
        layer: 0,
        number: 0,
        uid: 0,
        gid: 0,
        mode: 0,
    };
    let mut i = 0;
    while ix.insert(0, format!("n{i}").as_bytes(), f).is_ok() {
        i += 1;
    }
    // The name that failed has no room, and a name that is there does.
    assert!(!ix.has_room(0, format!("n{i}").as_bytes()));
    assert!(ix.has_room(0, b"n0"));
}

#[test]
fn a_directory_below_an_opaque_one_keeps_the_lower_set_hidden_after_a_build_and_a_move() {
    let mut v = volume();
    v.dir("/.layers/00/opq/sub", 0o755, 0)
        .file("/.layers/00/opq/sub/own", 0o644, 0, b"o");
    let mut world = World::new();
    let mut core = world.core(v);
    ready(&mut core);
    // The build: /opq is opaque, /opq/sub of the layer has the lower /opq/sub under it.
    assert_eq!(listing(&mut core, "/opq/sub"), ["own"]);
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/opq/sub/lx").err(),
        Some(st(f::NO_ENTRY))
    );
    // Moved out from under the opaque directory, it is a directory of the merged view again.
    rename(&mut core, 0, "/opq/sub", "/etc/sub").unwrap();
    let sub = core
        .index
        .lookup(core.index.lookup(0, b"etc").unwrap().0, b"sub")
        .unwrap()
        .0;
    assert!(core.index.lower_visible(sub));
    // And back under it, hidden.
    rename(&mut core, 0, "/etc/sub", "/opq/sub2").unwrap();
    let sub = core
        .index
        .lookup(core.index.lookup(0, b"opq").unwrap().0, b"sub2")
        .unwrap()
        .0;
    assert!(!core.index.lower_visible(sub));
}

// ---------------------------------------------------------------------- rename

#[test]
fn a_name_of_the_layer_is_renamed_inside_the_layer() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    let ino = node(&core, "/.layers/00/etc/own.conf").unwrap().ino;
    rename(&mut core, 0, "/etc/own.conf", "/etc/renamed").unwrap();
    assert!(node(&core, "/.layers/00/etc/own.conf").is_none());
    assert_eq!(node(&core, "/.layers/00/etc/renamed").unwrap().ino, ino);
    assert!(
        node(&core, "/.layers/00/etc/.wh.own.conf").is_none(),
        "no lower name to hide"
    );
    // Into another directory, over an existing file.
    rename(&mut core, 0, "/etc/renamed", "/shared/rootfile").unwrap();
    assert_eq!(node(&core, "/.layers/00/shared/rootfile").unwrap().ino, ino);
    assert!(
        open(&mut core, 0, f::READ_ONLY, "/shared/rootfile")
            .unwrap()
            .1
            .is_some()
    );
    let listed = listing(&mut core, "/etc");
    assert!(!listed.contains(&"renamed".to_owned()) && !listed.contains(&"own.conf".to_owned()));
    // A shadow of a lower name moves and the lower name stays hidden.
    rename(&mut core, 0, "/etc/passwd", "/etc/passwd2").unwrap();
    assert!(node(&core, "/.layers/00/etc/.wh.passwd").is_some());
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/etc/passwd").err(),
        Some(st(f::NO_ENTRY))
    );
    assert!(
        open(&mut core, 0, f::READ_ONLY, "/etc/passwd2")
            .unwrap()
            .1
            .is_some()
    );
    // A name onto a name the layer deleted: the mark goes.
    rename(&mut core, 0, "/etc/passwd2", "/etc/motd").unwrap();
    assert!(node(&core, "/.layers/00/etc/.wh.motd").is_none());
    assert!(
        open(&mut core, 0, f::READ_ONLY, "/etc/motd")
            .unwrap()
            .1
            .is_some()
    );
    // Same name, itself: nothing.
    rename(&mut core, 0, "/etc/motd", "/etc/motd").unwrap();
    assert!(core.volume.children(b"/.layers/work").is_empty());
    // A start again from the volume sees what the index saw.
    let v = core.volume;
    let mut again = World::new();
    let mut core = again.core(v);
    ready(&mut core);
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/etc/passwd").err(),
        Some(st(f::NO_ENTRY))
    );
    assert!(
        open(&mut core, 0, f::READ_ONLY, "/etc/motd")
            .unwrap()
            .1
            .is_some()
    );
}

#[test]
fn a_directory_moves_with_what_is_in_it_and_the_descriptions_follow() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    mkdir(&mut core, 0, "/shared/d1", 0o755).unwrap();
    open(&mut core, 0, creating(f::WRITE_ONLY, 0o600), "/shared/d1/f").unwrap();
    mkdir(&mut core, 0, "/shared/d1/sub", 0o755).unwrap();
    open(
        &mut core,
        0,
        creating(f::WRITE_ONLY, 0o600),
        "/shared/d1/sub/g",
    )
    .unwrap();
    // A description of the directory, open while it moves.
    let (reply, _) = open(&mut core, 0, f::READ_ONLY | f::DIRECTORY_ONLY, "/shared/d1").unwrap();
    let h = match OpenAnswer::read(&reply).unwrap() {
        OpenAnswer::Directory { handle } => handle,
        other => panic!("{other:?}"),
    };
    rename(&mut core, 0, "/shared/d1", "/shared/d2").unwrap();
    assert!(node(&core, "/.layers/00/shared/d2/sub/g").is_some());
    assert!(node(&core, "/.layers/00/shared/d1").is_none());
    assert_eq!(listing(&mut core, "/shared/d2"), ["f", "sub"]);
    assert_eq!(listing(&mut core, "/shared/d2/sub"), ["g"]);
    assert!(
        open(&mut core, 0, f::READ_ONLY, "/shared/d2/sub/g")
            .unwrap()
            .1
            .is_some()
    );
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/shared/d1/f")
            .map(|r| r.1)
            .ok()
            .flatten(),
        None
    );
    // The open description lists the moved directory.
    let names = drain(&mut core, 40, h);
    assert!(names.contains(&b"f".to_vec()) && names.contains(&b"sub".to_vec()));
    // Into its own subtree: no.
    assert_eq!(
        rename(&mut core, 0, "/shared/d2", "/shared/d2/sub/x").err(),
        Some(st(f::INVALID_ARGUMENT))
    );
    // A directory removed under an open description lists nothing and has no attributes.
    unlink(&mut core, 0, "/shared/d2/f").unwrap();
    unlink(&mut core, 0, "/shared/d2/sub/g").unwrap();
    rmdir(&mut core, 0, "/shared/d2/sub").unwrap();
    rmdir(&mut core, 0, "/shared/d2").unwrap();
    core.rewind(40, h).unwrap();
    assert!(drain(&mut core, 40, h).is_empty());
    assert_eq!(
        core.fstat(40, h, &mut Writer::new()).err(),
        Some(st(f::NO_ENTRY))
    );
    core.close(40, h).unwrap();
}

#[test]
fn rename_refuses_what_it_should() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    // A name of the lower set, and a directory that has a lower one: until the copy up.
    assert_eq!(
        rename(&mut core, 0, "/etc/hostname", "/etc/h2").err(),
        Some(st(f::CROSS_DEVICE))
    );
    assert_eq!(
        rename(&mut core, 0, "/etc", "/etc2").err(),
        Some(st(f::CROSS_DEVICE))
    );
    assert_eq!(
        rename(&mut core, 0, "/bin/ls", "/bin/ls2").err(),
        Some(st(f::CROSS_DEVICE))
    );
    assert!(
        node(&core, "/.layers/00/bin").is_none(),
        "no directory is copied up for a refusal"
    );
    assert_eq!(
        rename(&mut core, 0, "/etc/none", "/etc/x").err(),
        Some(st(f::NO_ENTRY))
    );
    assert_eq!(
        rename(&mut core, 0, "/etc/own.conf", "/etc/.wh.x").err(),
        Some(st(f::INVALID_ARGUMENT))
    );
    assert_eq!(rename(&mut core, 0, "/", "/x").err(), Some(st(f::BUSY)));
    mkdir(&mut core, 0, "/shared/d", 0o755).unwrap();
    open(&mut core, 0, creating(f::WRITE_ONLY, 0o600), "/shared/d/in").unwrap();
    mkdir(&mut core, 0, "/shared/e", 0o755).unwrap();
    assert_eq!(
        rename(&mut core, 0, "/etc/own.conf", "/shared/d").err(),
        Some(st(f::IS_DIRECTORY))
    );
    assert_eq!(
        rename(&mut core, 0, "/shared/d", "/etc/own.conf").err(),
        Some(st(f::NOT_DIRECTORY))
    );
    assert_eq!(
        rename(&mut core, 0, "/shared/e", "/shared/d").err(),
        Some(st(f::NOT_EMPTY))
    );
    // A name onto an empty directory takes its place, and the right of the directory is needed.
    assert_eq!(
        rename(&mut core, 1000, "/etc/own.conf", "/shared/x").err(),
        Some(st(f::ACCESS_DENIED))
    );
    unlink(&mut core, 0, "/shared/d/in").unwrap();
    rename(&mut core, 0, "/shared/e", "/shared/d").unwrap();
    assert!(node(&core, "/.layers/00/shared/d").unwrap().dir);
    assert!(node(&core, "/.layers/00/shared/e").is_none());
}

// ---------------------------------------------------------------------- symlinks and link

#[test]
fn a_symbolic_link_is_a_file_of_the_layer_and_a_path_through_it_is_a_redirect() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    symlink(&mut core, 1000, "/shared/ln", "rootfile").unwrap();
    let file = node(&core, "/.layers/00/shared/.wh..wh.lnk.ln").unwrap();
    assert_eq!(
        (file.data.as_slice(), file.uid, file.mode),
        (&b"rootfile"[..], 1000, 0o644)
    );
    assert!(file.ino & UPPER_INO_TAG != 0);
    // The listing shows the link as a link under its own name, and no file `.wh..wh.lnk.`.
    let kinds = names_of(&mut core, 0, "/shared");
    assert!(kinds.contains(&"ln:5".to_owned()), "{kinds:?}");
    assert!(!kinds.iter().any(|k| k.starts_with(".wh.")));
    // READLINK and the STAT that does not follow, and the STAT that follows (a redirect by the
    // path with the text put where the name was).
    assert_eq!(
        readlink(&mut core, 1000, "/shared/ln").unwrap(),
        b"rootfile"
    );
    let info = n::read_info(&stat(&mut core, 0, "/shared/ln", n::STAT_NO_FOLLOW).unwrap()).unwrap();
    assert_eq!((info.kind, info.size, info.permissions), (5, 8, 0o777));
    let reply = stat(&mut core, 0, "/shared/ln", 0).unwrap();
    assert_eq!(
        redirect_of(&reply),
        Some((f::REDIRECT_BY_PATH, 0, b"/shared/rootfile".to_vec()))
    );
    let (reply, _) = open(&mut core, 0, f::READ_ONLY, "/shared/ln").unwrap();
    assert_eq!(
        is_redirect(&reply),
        Some((f::REDIRECT_BY_PATH, 0, b"/shared/rootfile".to_vec()))
    );
    // O_NOFOLLOW is ELOOP, a create with EXCLUSIVE finds the name, a link in the middle of a path
    // is expanded with the rest of the path after it, and an absolute text stands alone.
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY | f::NO_FOLLOW, "/shared/ln").err(),
        Some(st(f::LOOP))
    );
    assert_eq!(
        open(
            &mut core,
            0,
            creating(f::WRITE_ONLY, 0o600) | f::EXCLUSIVE,
            "/shared/ln"
        )
        .err(),
        Some(st(f::ALREADY_EXISTS))
    );
    symlink(&mut core, 0, "/shared/dl", "../bin").unwrap();
    symlink(&mut core, 0, "/shared/abs", "/etc/passwd").unwrap();
    let (reply, _) = open(&mut core, 0, f::READ_ONLY, "/shared/dl/ls").unwrap();
    assert_eq!(
        is_redirect(&reply),
        Some((f::REDIRECT_BY_PATH, 0, b"/shared/../bin/ls".to_vec()))
    );
    let (reply, _) = open(&mut core, 0, f::READ_ONLY, "/shared/abs/x").unwrap();
    assert_eq!(
        is_redirect(&reply),
        Some((f::REDIRECT_BY_PATH, 0, b"/etc/passwd/x".to_vec()))
    );
    // A trailing slash follows the link, whatever the flag says.
    let reply = stat(&mut core, 0, "/shared/dl/", n::STAT_NO_FOLLOW).unwrap();
    assert_eq!(
        redirect_of(&reply).map(|r| r.2),
        Some(b"/shared/../bin/".to_vec())
    );
    // A link is no directory to list, and a path through a file is not a link.
    assert_eq!(
        readlink(&mut core, 0, "/shared/rootfile").err(),
        Some(st(f::INVALID_ARGUMENT))
    );
    // Refusals: the name is there, the name is the layer's own, the text or name is too long, the
    // directory is closed.
    assert_eq!(
        symlink(&mut core, 0, "/shared/ln", "x").err(),
        Some(st(f::ALREADY_EXISTS))
    );
    assert_eq!(
        symlink(&mut core, 0, "/etc/hostname", "x").err(),
        Some(st(f::ALREADY_EXISTS))
    );
    assert_eq!(
        symlink(&mut core, 0, "/shared/.wh.x", "x").err(),
        Some(st(f::INVALID_ARGUMENT))
    );
    assert_eq!(
        symlink(&mut core, 1000, "/etc/ln", "x").err(),
        Some(st(f::ACCESS_DENIED))
    );
    let long = "n".repeat(244);
    assert_eq!(
        symlink(&mut core, 0, &std::format!("/shared/{long}"), "x").err(),
        Some(st(f::NAME_TOO_LONG))
    );
    // Removed like a file.
    unlink(&mut core, 1000, "/shared/ln").unwrap();
    assert!(node(&core, "/.layers/00/shared/.wh..wh.lnk.ln").is_none());
    // The name is no name of the layer any more: the RAM file service answers for it.
    let v = who(0);
    let c = Client { owner: 40, who: &v };
    let mut w = Writer::new();
    core.readlink(&c, b"/shared/ln", &mut w).unwrap();
    assert!(f::Redirect::read_reply(w.as_bytes()).is_some());
    // A start again from the volume finds the others as links.
    let v = core.volume;
    let mut again = World::new();
    let mut core = again.core(v);
    ready(&mut core);
    assert_eq!(
        readlink(&mut core, 0, "/shared/abs").unwrap(),
        b"/etc/passwd"
    );
    let kinds = names_of(&mut core, 0, "/shared");
    assert!(kinds.contains(&"dl:5".to_owned()) && !kinds.iter().any(|k| k.starts_with("ln:")));
}

#[test]
fn a_link_of_the_layer_in_a_directory_part_is_a_redirect_of_the_path_it_was_in() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    symlink(&mut core, 0, "/shared/dl", "/etc").unwrap();
    // A change through the link: the layer's redirect names the first or the second path.
    let reply = change(&mut core, 0, ChangeOp::Mkdir, 0o755, "/shared/dl/new", "").unwrap();
    assert_eq!(
        redirect_of(&reply),
        Some((f::REDIRECT_BY_PATH, 0, b"/etc/new".to_vec()))
    );
    let reply = change(
        &mut core,
        0,
        ChangeOp::Rename,
        0,
        "/etc/own.conf",
        "/shared/dl/own",
    )
    .unwrap();
    assert_eq!(
        redirect_of(&reply),
        Some((f::REDIRECT_BY_PATH, 1, b"/etc/own".to_vec()))
    );
    assert!(node(&core, "/.layers/00/etc/own.conf").is_some());
    // The link itself is removed; it is not followed.
    unlink(&mut core, 0, "/shared/dl").unwrap();
    // A link of the lower set in the directory part: a redirect to the RAM file service for the
    // path (the client resolves the directory and asks again), for either path of a rename.
    let reply = change(&mut core, 0, ChangeOp::Mkdir, 0o755, "/lowlink/d", "").unwrap();
    assert_eq!(
        redirect_of(&reply),
        Some((f::REDIRECT_RAM, 0, b"/lowlink/d".to_vec()))
    );
    let reply = change(
        &mut core,
        0,
        ChangeOp::Rename,
        0,
        "/etc/own.conf",
        "/lowlink/o",
    )
    .unwrap();
    assert_eq!(
        redirect_of(&reply),
        Some((f::REDIRECT_RAM, 1, b"/lowlink/o".to_vec()))
    );
    // An open that creates meets it as a redirect to the RAM file service, which expands it.
    let (reply, _) = open(&mut core, 0, creating(f::WRITE_ONLY, 0o600), "/lowlink/x").unwrap();
    assert_eq!(
        is_redirect(&reply),
        Some((f::REDIRECT_RAM, 0, b"/lowlink/x".to_vec()))
    );
}

#[test]
fn link_is_too_many_links() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    assert_eq!(
        change(
            &mut core,
            0,
            ChangeOp::Link,
            0,
            "/etc/own.conf",
            "/etc/other"
        )
        .err(),
        Some(st(f::TOO_MANY_LINKS))
    );
    assert!(node(&core, "/.layers/00/etc/other").is_none());
}

// ---------------------------------------------------------------------- attributes

#[test]
fn chmod_chown_utimens_and_truncate_of_a_file_of_the_layer() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    let path = "/.layers/00/etc/own.conf";
    // The owner changes the mode; another user may not; root may.
    change(&mut core, 1000, ChangeOp::Chmod, 0o600, "/etc/own.conf", "").unwrap();
    assert_eq!(node(&core, path).unwrap().mode, 0o600);
    assert_eq!(
        change(&mut core, 1001, ChangeOp::Chmod, 0o777, "/etc/own.conf", "").err(),
        Some(st(f::PERMISSION))
    );
    change(&mut core, 0, ChangeOp::Chmod, 0o644, "/etc/own.conf", "").unwrap();
    // Only root changes the owner; the owner changes the group to one of its own.
    let v = who(0);
    let c = Client { owner: 40, who: &v };
    let req = n::Change {
        op: ChangeOp::Chown,
        a: 77,
        b: 8,
        first: b"/etc/own.conf",
        second: b"",
    };
    core.change(&c, &req, &mut Writer::new()).unwrap();
    assert_eq!(
        (
            node(&core, path).unwrap().uid,
            node(&core, path).unwrap().gid
        ),
        (77, 8)
    );
    let v = who(1000);
    let c = Client { owner: 41, who: &v };
    let req = n::Change {
        op: ChangeOp::Chown,
        a: 1000,
        b: 8,
        first: b"/etc/own.conf",
        second: b"",
    };
    assert_eq!(
        core.change(&c, &req, &mut Writer::new()).err(),
        Some(st(f::PERMISSION))
    );
    // Times: any value needs the owner; two "now" values need write permission.
    let v = who(77);
    let c = Client { owner: 42, who: &v };
    let req = n::Change {
        op: ChangeOp::Utimens,
        a: 5,
        b: 6,
        first: b"/etc/own.conf",
        second: b"",
    };
    core.change(&c, &req, &mut Writer::new()).unwrap();
    assert_eq!(node(&core, path).unwrap().times, (5, 6));
    let v = who(1001);
    let c = Client { owner: 43, who: &v };
    let req = n::Change {
        op: ChangeOp::Utimens,
        a: 5,
        b: 6,
        first: b"/etc/own.conf",
        second: b"",
    };
    assert_eq!(
        core.change(&c, &req, &mut Writer::new()).err(),
        Some(st(f::PERMISSION))
    );
    // Truncate: write permission on the file, a directory is refused.
    change(&mut core, 0, ChangeOp::Truncate, 3, "/etc/own.conf", "").unwrap();
    assert_eq!(node(&core, path).unwrap().data.len(), 3);
    assert_eq!(
        change(&mut core, 1001, ChangeOp::Truncate, 0, "/etc/own.conf", "").err(),
        Some(st(f::ACCESS_DENIED))
    );
    assert_eq!(
        change(&mut core, 0, ChangeOp::Truncate, 0, "/etc", "").err(),
        Some(st(f::IS_DIRECTORY))
    );
    // A directory of the layer: the mode is what the walk of a path checks next.
    mkdir(&mut core, 1000, "/shared/mine", 0o755).unwrap();
    open(
        &mut core,
        1000,
        creating(f::WRITE_ONLY, 0o600),
        "/shared/mine/f",
    )
    .unwrap();
    assert!(open(&mut core, 1001, f::READ_ONLY, "/shared/mine/f").is_err());
    change(&mut core, 1000, ChangeOp::Chmod, 0o700, "/shared/mine", "").unwrap();
    assert_eq!(
        open(&mut core, 1001, f::READ_ONLY, "/shared/mine/f").err(),
        Some(st(f::ACCESS_DENIED))
    );
    assert_eq!(
        open(
            &mut core,
            1001,
            f::READ_ONLY | f::DIRECTORY_ONLY,
            "/shared/mine"
        )
        .err(),
        Some(st(f::ACCESS_DENIED))
    );
}

// ---------------------------------------------------------------------- the index

#[test]
fn a_removed_name_leaves_the_probes_of_the_others_unbroken_and_is_taken_again() {
    let mut ix = crate::index::boxed();
    let f = |n: u64| crate::index::Fields {
        kind: Kind::File,
        layer: 0,
        number: n,
        uid: 0,
        gid: 0,
        mode: 0o644,
    };
    let mut ids = Vec::new();
    for i in 0..800u64 {
        let name = std::format!("n{i}");
        ids.push((name.clone(), ix.insert(0, name.as_bytes(), f(i)).unwrap()));
    }
    // Remove every other name: the rest is found, the removed are not, and the counts follow.
    for (i, (name, id)) in ids.iter().enumerate() {
        if i % 2 == 0 {
            ix.remove(*id);
            assert!(ix.lookup(0, name.as_bytes()).is_none());
        }
    }
    for (i, (name, id)) in ids.iter().enumerate() {
        if i % 2 == 1 {
            assert_eq!(
                ix.lookup(0, name.as_bytes()).map(|(i, _)| i),
                Some(*id),
                "{name}"
            );
        }
    }
    assert_eq!(ix.counts().0, 400);
    // The same name comes back to its own slot, with the name the arena holds.
    let (name, id) = &ids[0];
    assert_eq!(ix.insert(0, name.as_bytes(), f(99)).unwrap(), *id);
    assert_eq!(ix.entry(*id).map(|e| e.number), Some(99));
    assert_eq!(ix.counts().0, 401);
    // New names find the free slots of the removed ones.
    for i in 0..200u64 {
        let name = std::format!("fresh{i}");
        ix.insert(0, name.as_bytes(), f(i)).unwrap();
        assert!(ix.lookup(0, name.as_bytes()).is_some());
    }
    // The children of a directory go with it, and the others stay.
    let dir = ix
        .insert(
            0,
            b"dir",
            crate::index::Fields {
                kind: Kind::Dir,
                ..f(1)
            },
        )
        .unwrap();
    let a = ix.insert(dir, b"a", f(2)).unwrap();
    ix.insert(dir, b"b", f(3)).unwrap();
    let other = ix.insert(0, b"a", f(4)).unwrap();
    assert_eq!(ix.remove_children(dir), 2);
    assert!(ix.entry(a).is_none());
    assert_eq!(ix.lookup(0, b"a").map(|(i, _)| i), Some(other));
    // A move keeps the fields and takes the children along.
    let kid = ix.insert(dir, b"kid", f(5)).unwrap();
    let moved = ix.move_to(dir, 0, b"dir2").unwrap();
    assert!(ix.lookup(0, b"dir").is_none());
    assert_eq!(ix.lookup(0, b"dir2").map(|(i, _)| i), Some(moved));
    assert_eq!(Some(ix.parent_of(kid)), Some(moved));
    assert!(ix.move_to(moved, 0, b"a").is_err(), "a name that is taken");
}

#[test]
fn a_start_again_from_the_volume_sees_the_same_names_as_the_changes_left() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    mkdir(&mut core, 0, "/lowdir/sub", 0o755).unwrap();
    open(&mut core, 1000, creating(f::READ_WRITE, 0o640), "/shared/f").unwrap();
    symlink(&mut core, 0, "/shared/l", "f").unwrap();
    unlink(&mut core, 0, "/etc/hostname").unwrap();
    unlink(&mut core, 0, "/gone/x").unwrap();
    rmdir(&mut core, 0, "/gone").unwrap();
    mkdir(&mut core, 0, "/gone", 0o755).unwrap();
    rename(&mut core, 0, "/shared/f", "/shared/g").unwrap();
    let dirs = ["/", "/etc", "/shared", "/lowdir", "/gone"];
    let before: Vec<_> = dirs.iter().map(|d| names_of(&mut core, 0, d)).collect();
    let v = core.volume;
    let mut again = World::new();
    let mut core = again.core(v);
    ready(&mut core);
    let after: Vec<_> = dirs.iter().map(|d| names_of(&mut core, 0, d)).collect();
    assert_eq!(before, after);
}

#[test]
fn the_index_that_is_full_refuses_a_create_with_no_space_and_leaves_nothing_behind() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    // Fill the probes of one name: insert names until the table refuses at the slot the next
    // create would take.
    let mut full = None;
    for i in 0..crate::index::SLOTS * 2 {
        let name = std::format!("x{i}");
        let fields = crate::index::Fields {
            kind: Kind::File,
            layer: 0,
            number: 0,
            uid: 0,
            gid: 0,
            mode: 0,
        };
        let shared = core.index.lookup(0, b"shared").unwrap().0;
        if core.index.insert(shared, name.as_bytes(), fields).is_err() {
            full = Some(name);
            break;
        }
    }
    let name = full.expect("the table fills up");
    let before = core.volume.nodes.len();
    assert_eq!(
        open(
            &mut core,
            0,
            creating(f::WRITE_ONLY, 0o600),
            &std::format!("/shared/{name}")
        )
        .err(),
        Some(st(f::NO_SPACE))
    );
    assert_eq!(core.volume.nodes.len(), before, "the file is gone again");
}
