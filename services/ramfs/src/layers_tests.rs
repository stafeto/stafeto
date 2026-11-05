// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Layers on the host: package files built from byte slices, attached to the tree in portions.
extern crate std;
use crate::authority::Identity;
use crate::namespace::*;
use crate::resolve::{Intent, Progress, Resolve};
use crate::storage::layers::*;
use crate::storage::*;
use crate::{DIR, Fds, REG, Ram};
use bootimg::PACKAGE;
use proto_fs::{
    BAD_LAYER, BAD_MODE, CONFLICT, LayerReply, NO_ENTRY, NO_SPACE, PERMISSION, READ_ONLY,
    READ_ONLY_FILESYSTEM,
};
use proto_process::Groups;
use std::{format, string::String, vec, vec::Vec};

const NOW: proto_fs::Timestamp = proto_fs::Timestamp::legacy_ns(1_000);
const FIRST: Root = Root {
    id: 11,
    generation: 7,
};
const ROOT_USER: Identity = Identity {
    uid: 0,
    gid: 0,
    groups: Groups::EMPTY,
};

#[derive(Clone)]
struct Item {
    path: String,
    mode: u32,
    uid: u32,
    gid: u32,
    /// The container file of the content; 0 for a directory.
    file: u32,
}

/// A table of entries in the given order with no check of the order or the parents.
fn raw_table(items: &[Item], time: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"STAFROOT");
    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&(items.len() as u32).to_le_bytes());
    out.extend_from_slice(&time.to_le_bytes());
    let mut offset = 24 + 24 * items.len();
    for item in items {
        out.extend_from_slice(&(offset as u32).to_le_bytes());
        out.extend_from_slice(&(item.path.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&item.mode.to_le_bytes());
        out.extend_from_slice(&item.uid.to_le_bytes());
        out.extend_from_slice(&item.gid.to_le_bytes());
        out.extend_from_slice(&item.file.to_le_bytes());
        offset += item.path.len();
    }
    for item in items {
        out.extend_from_slice(item.path.as_bytes());
    }
    out
}

/// What a layer is made of: entries in the order of the table and the content files.
#[derive(Default)]
struct Spec {
    items: Vec<Item>,
    contents: Vec<Vec<u8>>,
    /// The file number of the content already given for a path, for hard links.
    time: u64,
}
impl Spec {
    fn new() -> Self {
        Self {
            time: 5_000,
            ..Self::default()
        }
    }
    fn push(mut self, path: &str, mode: u32, file: u32) -> Self {
        self.items.push(Item {
            path: path.into(),
            mode,
            uid: 0,
            gid: 0,
            file,
        });
        self
    }
    fn dir(self, path: &str) -> Self {
        self.push(path, rootfs_dir(0o755), 0)
    }
    fn file(mut self, path: &str, mode: u32, bytes: &[u8]) -> Self {
        self.contents.push(bytes.to_vec());
        let file = 2 + self.contents.len() as u32;
        self.push(path, bootimg::rootfs::REGULAR | mode, file)
    }
    /// A hard link to the file the earlier entry `of` names.
    fn link(self, path: &str, of: &str) -> Self {
        let item = self.items.iter().find(|i| i.path == of).unwrap().clone();
        self.push(path, item.mode, item.file)
    }
    fn symlink(mut self, path: &str, target: &str) -> Self {
        self.contents.push(target.as_bytes().to_vec());
        let file = 2 + self.contents.len() as u32;
        self.push(path, bootimg::rootfs::SYMLINK | 0o777, file)
    }
    fn owner(mut self, uid: u32, gid: u32) -> Self {
        let last = self.items.last_mut().unwrap();
        last.uid = uid;
        last.gid = gid;
        self
    }
    /// The package file, leaked so that its bytes outlive the test like a mapping would.
    fn build(&self) -> &'static [u8] {
        let table = raw_table(&self.items, self.time);
        let names: Vec<String> = (0..self.contents.len())
            .map(|n| format!("{}", n + 3))
            .collect();
        let mut files: Vec<(&str, &[u8])> = vec![
            ("meta", b"meta"),
            ("rootfs", &table),
            ("manifest", b"manifest"),
        ];
        for (name, content) in names.iter().zip(&self.contents) {
            files.push((name, content));
        }
        let mut image = bootimg::write::image_as(&PACKAGE, &files).unwrap();
        // The signature page of a real package is not read by the service.
        image.resize(image.len().next_multiple_of(4096) + 4096, 0);
        std::boxed::Box::leak(image.into_boxed_slice())
    }
}

fn rootfs_dir(mode: u32) -> u32 {
    bootimg::rootfs::DIRECTORY | mode
}

/// The layer the examples use: a program, a big file, a hard link, a link by name and a
/// directory the system does not have.
fn good() -> Spec {
    Spec::new()
        .dir("/layer")
        .dir("/layer/bin")
        .file("/layer/bin/hello", 0o755, b"hello program")
        .link("/layer/bin/hi", "/layer/bin/hello")
        .symlink("/layer/bin/world", "hello")
        .dir("/layer/data")
        .file("/layer/data/big", 0o644, &[0x5a; 10_000])
}

fn ram() -> Ram<'static> {
    Ram::new(NOW)
}

/// Attaches layer `number` to the end, as the client does: the answer of the last step.
fn attach(ram: &mut Ram<'_>, number: u32, bytes: &'static [u8]) -> LayerReply {
    attach_counting(ram, number, bytes).0
}

fn attach_counting(ram: &mut Ram<'_>, number: u32, bytes: &'static [u8]) -> (LayerReply, usize) {
    let index = match ram.storage.layer_begin_attach(number, false) {
        Ok(index) => index,
        Err(status) => return (LayerReply::Refused { status }, 0),
    };
    if let Err(reply) = ram.storage.layer_mapped(index, bytes.as_ptr(), bytes.len()) {
        ram.storage.layer_unmapped(index);
        return (reply, 0);
    }
    let mut steps = 0;
    loop {
        steps += 1;
        assert!(steps < 100_000, "the attach does not end");
        match ram.storage.layer_step(number, NOW, &Limits::PORTIONS) {
            LayerReply::Resolving => {}
            other => return (other, steps),
        }
    }
}

fn detach(ram: &mut Ram<'_>, number: u32) -> LayerReply {
    if let Err(status) = ram.storage.layer_begin_detach(number) {
        return LayerReply::Refused { status };
    }
    let mut steps = 0;
    loop {
        steps += 1;
        assert!(steps < 100_000);
        match ram.storage.layer_step(number, NOW, &Limits::PORTIONS) {
            LayerReply::Resolving => {}
            other => return other,
        }
    }
}

/// The layers the service would unmap now.
fn settle(ram: &mut Ram<'_>) -> Vec<Released> {
    let mut out = Vec::new();
    while let Some(done) = ram.storage.layer_next_released() {
        ram.storage.layer_unmapped(done.index);
        out.push(done);
    }
    out
}

fn path(ram: &Ram<'_>, path: &str) -> Result<Token, u32> {
    ram.storage.resolve(path.as_bytes())
}

fn names(ram: &Ram<'_>, dir: Token) -> Vec<String> {
    let mut out = Vec::new();
    let mut at = ram.storage.first_child(dir);
    while let Some(i) = at {
        let (_, name, _) = ram.storage.entry_record(i).unwrap();
        out.push(String::from_utf8(name.to_vec()).unwrap());
        at = ram.storage.child_next(i);
    }
    out
}

fn read_all(ram: &Ram<'_>, token: Token) -> Vec<u8> {
    let length = ram.storage.node(token).unwrap().length as usize;
    let mut out = vec![0; length];
    assert_eq!(ram.storage.read(token, 0, &mut out), Ok(length));
    out
}

fn same_tree(ram: &Ram<'_>) -> (FileSystemInfo, Vec<String>, Vec<String>) {
    (
        ram.storage.filesystem_information(FIRST),
        names(ram, ROOT),
        names(
            ram,
            Token {
                slot: 1,
                generation: 1,
            },
        ),
    )
}

fn user_file(ram: &mut Ram<'_>, parent: Token, name: &[u8]) -> Token {
    let r = ram
        .storage
        .reserve(FIRST, parent, name, (REG, 0o644, 0, 0))
        .unwrap();
    ram.storage.commit(r).unwrap()
}

#[test]
fn an_attached_layer_shows_names_modes_owners_sizes_links_and_symbolic_links() {
    let mut ram = ram();
    let before = same_tree(&ram);
    let bytes = good().build();
    assert_eq!(attach(&mut ram, 1, bytes), LayerReply::Done { names: 7 });
    assert_eq!(ram.storage.layer_state(1), Some(LayerState::Attached));
    let hello = path(&ram, "/layer/bin/hello").unwrap();
    let node = ram.storage.node(hello).unwrap();
    assert_eq!(
        (
            node.kind,
            node.mode,
            node.uid,
            node.gid,
            node.links,
            node.length
        ),
        (REG, 0o755, 0, 0, 2, 13)
    );
    assert_eq!(read_all(&ram, hello), b"hello program");
    // The second name is the same inode.
    assert_eq!(path(&ram, "/layer/bin/hi"), Ok(hello));
    let link = path(&ram, "/layer/bin/world").unwrap();
    let node = ram.storage.node(link).unwrap();
    assert_eq!((node.kind, node.mode, node.links), (SYMLINK, 0o777, 1));
    assert_eq!(read_all(&ram, link), b"hello");
    let big = path(&ram, "/layer/data/big").unwrap();
    assert_eq!(ram.storage.node(big).unwrap().length, 10_000);
    assert_eq!(read_all(&ram, big), vec![0x5a; 10_000]);
    assert_eq!(names(&ram, ROOT).last().map(String::as_str), Some("layer"));
    let layer = path(&ram, "/layer").unwrap();
    assert_eq!(names(&ram, layer), ["bin", "data"]);
    assert_eq!(ram.storage.node(layer).unwrap().mode, 0o755);
    // The time of the build is the time of the files.
    assert_eq!(
        ram.storage.node(hello).unwrap().times[1],
        proto_fs::Timestamp::new(5_000, 0).unwrap()
    );
    // The same names answer the calls that go by path.
    assert_eq!(ram.information("/layer/bin/hi").unwrap().links, 2);
    assert_eq!(detach(&mut ram, 1), LayerReply::Done { names: 7 });
    assert_eq!(settle(&mut ram).len(), 1);
    assert_eq!(same_tree(&ram), before);
}

#[test]
fn a_directory_that_merges_keeps_its_attributes_and_its_names() {
    let mut ram = ram();
    let etc = Token {
        slot: 1,
        generation: 1,
    };
    let before = *ram.storage.node(etc).unwrap();
    let layer = Spec::new()
        .push("/etc", rootfs_dir(0o700), 0)
        .file("/etc/layered.conf", 0o600, b"x")
        .build();
    assert_eq!(attach(&mut ram, 1, layer), LayerReply::Done { names: 2 });
    let after = *ram.storage.node(etc).unwrap();
    assert_eq!(
        (after.mode, after.uid, after.gid),
        (before.mode, before.uid, before.gid)
    );
    assert_eq!(after.links, before.links);
    assert!(path(&ram, "/etc/layered.conf").is_ok());
    assert!(names(&ram, etc).contains(&"layered.conf".into()));
    assert_eq!(detach(&mut ram, 1), LayerReply::Done { names: 2 });
    settle(&mut ram);
    assert_eq!(path(&ram, "/etc/layered.conf"), Err(NO_ENTRY));
    assert_eq!(names(&ram, etc), ["motd"]);
}

#[test]
fn every_kind_of_clash_answers_conflict_with_the_entry_and_leaves_the_tree_as_it_was() {
    let mut ram = ram();
    user_file(&mut ram, ROOT, b"userfile");
    let udir = {
        let r = ram
            .storage
            .reserve(FIRST, ROOT, b"userdir", (DIR, 0o755, 0, 0))
            .unwrap();
        ram.storage.commit(r).unwrap()
    };
    let _ = udir;
    assert_eq!(
        attach(
            &mut ram,
            1,
            Spec::new().dir("/ok").file("/ok/a", 0o644, b"a").build()
        ),
        LayerReply::Done { names: 2 }
    );
    let before = same_tree(&ram);
    let cases: [(&str, Spec, u32); 6] = [
        // A file of the system, a file of the user, a name of another layer, a directory where
        // a file is, a file where a directory is.
        ("system", Spec::new().file("/etc", 0o644, b"x"), 0),
        (
            "user",
            Spec::new()
                .dir("/ok")
                .file("/ok/b", 0o644, b"b")
                .file("/userfile", 0o644, b"x"),
            2,
        ),
        (
            "layer",
            Spec::new().dir("/ok").file("/ok/a", 0o644, b"b"),
            1,
        ),
        ("dir over file", Spec::new().dir("/userfile"), 0),
        (
            "file over dir",
            Spec::new().file("/userdir", 0o644, b"x"),
            0,
        ),
        (
            "file over motd dir",
            Spec::new().dir("/etc").file("/etc/motd", 0o644, b"x"),
            1,
        ),
    ];
    for (what, spec, entry) in cases {
        let reply = attach(&mut ram, 2, spec.build());
        assert_eq!(
            reply,
            LayerReply::Entry {
                status: CONFLICT,
                entry
            },
            "{what}"
        );
        let released = settle(&mut ram);
        assert_eq!(released.len(), 1, "{what}");
        assert!(released[0].failed, "{what}");
        assert_eq!(same_tree(&ram), before, "{what}");
        assert_eq!(ram.storage.layers_in_use(), 1, "{what}");
    }
    ram.storage.check_name_index();
}

#[test]
fn a_set_id_bit_or_an_owner_other_than_root_is_bad_mode_and_a_broken_table_is_bad_layer() {
    let mut ram = ram();
    let before = same_tree(&ram);
    let refuse = |ram: &mut Ram<'_>, spec: Spec| {
        let reply = attach(ram, 3, spec.build());
        assert_eq!(settle(ram).len(), 1);
        reply
    };
    for mode in [0o4755, 0o2755, 0o1755] {
        assert_eq!(
            refuse(&mut ram, Spec::new().dir("/d").file("/d/x", mode, b"x")),
            LayerReply::Entry {
                status: BAD_MODE,
                entry: 1
            },
            "{mode:o}"
        );
    }
    assert_eq!(
        refuse(&mut ram, Spec::new().file("/x", 0o644, b"x").owner(1, 0)),
        LayerReply::Entry {
            status: BAD_MODE,
            entry: 0
        }
    );
    // The order of the paths, a parent that is a file, a parent that is not there, a file
    // number past the container, a link with another mode.
    let mut swapped = Spec::new().file("/b", 0o644, b"b").file("/a", 0o644, b"a");
    assert_eq!(
        refuse(&mut ram, std::mem::take(&mut swapped)),
        LayerReply::Entry {
            status: BAD_LAYER,
            entry: 1
        }
    );
    assert_eq!(
        refuse(
            &mut ram,
            Spec::new()
                .file("/f", 0o644, b"x")
                .file("/f/g", 0o644, b"y")
        ),
        LayerReply::Entry {
            status: BAD_LAYER,
            entry: 1
        }
    );
    assert_eq!(
        refuse(&mut ram, Spec::new().file("/missing/g", 0o644, b"y")),
        LayerReply::Entry {
            status: BAD_LAYER,
            entry: 0
        }
    );
    let mut far = Spec::new().file("/f", 0o644, b"x");
    far.items[0].file = 99;
    assert_eq!(
        refuse(&mut ram, far),
        LayerReply::Entry {
            status: BAD_LAYER,
            entry: 0
        }
    );
    let mut mismatch = Spec::new().file("/a", 0o644, b"x").link("/b", "/a");
    mismatch.items[1].mode = bootimg::rootfs::REGULAR | 0o755;
    assert_eq!(
        refuse(&mut ram, mismatch),
        LayerReply::Entry {
            status: BAD_LAYER,
            entry: 1
        }
    );
    // A directory deeper than a stack allows is not the table's business here; a path under
    // a directory that is a sibling's child is.
    assert_eq!(
        refuse(
            &mut ram,
            Spec::new().dir("/a").dir("/b").file("/a/x", 0o644, b"x")
        ),
        LayerReply::Entry {
            status: BAD_LAYER,
            entry: 2
        }
    );
    assert_eq!(same_tree(&ram), before);
}

#[test]
fn a_container_that_is_cut_short_or_has_no_table_is_bad_layer_without_an_entry() {
    let mut ram = ram();
    let bytes = good().build();
    for cut in [0, 8, 15, 16, 60, 4096] {
        let reply = attach(&mut ram, 1, &bytes[..cut]);
        assert!(
            matches!(
                reply,
                LayerReply::Entry {
                    status: BAD_LAYER,
                    ..
                }
            ),
            "{cut}"
        );
        assert_eq!(ram.storage.layers_in_use(), 0);
    }
    let mut wrong = bytes.to_vec();
    wrong[0] ^= 1;
    let wrong = std::boxed::Box::leak(wrong.into_boxed_slice());
    assert!(matches!(
        attach(&mut ram, 1, wrong),
        LayerReply::Entry {
            status: BAD_LAYER,
            ..
        }
    ));
}

#[test]
fn a_readdir_started_before_the_attach_and_continued_in_portions_sees_each_name_at_most_once() {
    let mut ram = ram();
    let mut spec = Spec::new().dir("/many");
    for n in 0..300 {
        spec = spec.file(&format!("/many/f{n:03}"), 0o644, b"x");
    }
    let bytes = spec.build();
    let root_names = names(&ram, ROOT);
    // Read the root directory from the start, one name at a time, while the layer goes in.
    let mut seen: Vec<String> = Vec::new();
    let mut cookie = 2u64;
    let mut hint = NONE;
    let mut scan = NONE;
    let index = ram.storage.layer_begin_attach(1, false).unwrap();
    ram.storage
        .layer_mapped(index, bytes.as_ptr(), bytes.len())
        .unwrap();
    let mut attached = false;
    let mut positions = Vec::new();
    loop {
        match ram.storage.child_after(ROOT, cookie, hint, scan) {
            Walk::Found(i) => {
                let (c, name, _) = ram.storage.entry_record(i).unwrap();
                assert!(c > cookie, "the positions grow");
                positions.push(c);
                seen.push(String::from_utf8(name.to_vec()).unwrap());
                cookie = c;
                hint = i as u16;
                scan = NONE;
            }
            Walk::More(reached) => scan = reached,
            Walk::End if attached => break,
            Walk::End => {}
        }
        if !attached {
            match ram.storage.layer_step(1, NOW, &Limits::PORTIONS) {
                LayerReply::Resolving => {}
                LayerReply::Done { .. } => attached = true,
                other => panic!("{other:?}"),
            }
        }
    }
    let mut sorted = seen.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), seen.len(), "no name twice");
    for name in &root_names {
        assert!(seen.contains(name));
    }
    assert!(seen.contains(&"many".into()));
    assert!(positions.windows(2).all(|w| w[0] < w[1]));
    ram.storage.check_name_index();
}

#[test]
fn an_open_file_reads_to_the_end_after_the_detach_and_the_place_waits_for_the_close() {
    let mut ram = ram();
    assert_eq!(
        attach(&mut ram, 1, good().build()),
        LayerReply::Done { names: 7 }
    );
    let mut fds = Fds {
        root: FIRST,
        ..Fds::default()
    };
    let fd = ram.open(&mut fds, "/layer/data/big", READ_ONLY).unwrap();
    let mut first = [0; 4];
    ram.pread(&fds, fd, 0, &mut first, NOW).unwrap();
    assert_eq!(detach(&mut ram, 1), LayerReply::Done { names: 7 });
    assert_eq!(path(&ram, "/layer/data/big"), Err(NO_ENTRY));
    // Held: no release yet.
    assert_eq!(ram.storage.layer_state(1), Some(LayerState::Draining));
    assert!(settle(&mut ram).is_empty());
    let mut rest = vec![0; 10_000];
    assert_eq!(ram.pread(&fds, fd, 0, &mut rest, NOW), Ok(10_000));
    assert_eq!(rest, vec![0x5a; 10_000]);
    let held = ram.storage.resolve(b"/").unwrap();
    let _ = held;
    ram.close(&mut fds, fd).unwrap();
    let released = settle(&mut ram);
    assert_eq!(released.len(), 1);
    assert!(!released[0].failed);
    assert_eq!(ram.storage.layers_in_use(), 0);
    assert_eq!(ram.storage.layer_places_free(), LAYER_SLOTS);
    assert_eq!(ram.storage.layer_dirs_free(), LAYER_DIRS);
}

#[test]
fn the_link_count_of_an_open_file_is_zero_after_the_detach() {
    let mut ram = ram();
    attach(&mut ram, 1, good().build());
    let token = path(&ram, "/layer/bin/hello").unwrap();
    let mut fds = Fds {
        root: FIRST,
        ..Fds::default()
    };
    let fd = ram.open(&mut fds, "/layer/bin/hi", READ_ONLY).unwrap();
    detach(&mut ram, 1);
    assert_eq!(ram.token_information(token).unwrap().links, 0);
    // The second name's place went at once; the first waits for the file.
    assert_eq!(ram.storage.layer_state(1), Some(LayerState::Draining));
    ram.close(&mut fds, fd).unwrap();
    assert_eq!(settle(&mut ram).len(), 1);
}

#[test]
fn a_loading_program_holds_the_place_with_the_image_pin() {
    let mut ram = ram();
    attach(&mut ram, 1, good().build());
    let token = path(&ram, "/layer/bin/hello").unwrap();
    let entry = ram.storage.node(token).unwrap().boot;
    let mut fds = Fds {
        root: FIRST,
        ..Fds::default()
    };
    ram.hold_image(&mut fds, token, entry).unwrap();
    detach(&mut ram, 1);
    assert!(settle(&mut ram).is_empty());
    let mut out = [0; 13];
    assert_eq!(ram.held_image_read(&fds, 0, &mut out), Ok(13));
    assert_eq!(&out, b"hello program");
    assert!(ram.release_step(&mut fds));
    assert_eq!(settle(&mut ram).len(), 1);
}

#[test]
fn a_place_taken_again_has_another_inode_and_the_token_of_the_old_file_is_refused() {
    let mut ram = ram();
    attach(
        &mut ram,
        1,
        Spec::new().file("/one", 0o644, b"first").build(),
    );
    let old = path(&ram, "/one").unwrap();
    let old_inode = ram.token_information(old).unwrap().inode;
    detach(&mut ram, 1);
    settle(&mut ram);
    assert_eq!(ram.storage.node(old).err(), Some(NO_ENTRY));
    attach(
        &mut ram,
        2,
        Spec::new().file("/two", 0o644, b"second").build(),
    );
    let new = path(&ram, "/two").unwrap();
    // The same place of the image, another generation.
    assert_eq!(new.slot, old.slot);
    assert_ne!(new.generation, old.generation);
    assert_eq!(ram.storage.node(old).err(), Some(NO_ENTRY));
    assert_ne!(ram.token_information(new).unwrap().inode, old_inode);
    assert_eq!(read_all(&ram, new), b"second");
}

/// The unlink and the rest of the changes to the names and the attributes of a layer.
fn run_rename(ram: &mut Ram<'_>, from: &[u8], to: &[u8]) -> Result<NamespaceOutcome, u32> {
    run_ns(ram, NamespaceIntent::Rename, from, Some(to))
}

fn run_ns(
    ram: &mut Ram<'_>,
    intent: NamespaceIntent,
    from: &[u8],
    to: Option<&[u8]>,
) -> Result<NamespaceOutcome, u32> {
    let charge = ram.storage.charge_preparation(FIRST)?;
    let resolve = |ram: &mut Ram<'_>, path: &[u8], role| {
        let mut r = Resolve::with_intent(
            &mut ram.storage,
            path,
            ROOT,
            ROOT_USER,
            Intent::Namespace { path: role },
        )?;
        for _ in 0..100_000 {
            match r.step(&mut ram.storage, ROOT_USER) {
                Ok(Progress::More) => {}
                Ok(_) => return Ok(r),
                Err(code) => {
                    r.release(&mut ram.storage);
                    return Err(code);
                }
            }
        }
        panic!("no progress")
    };
    let source = resolve(ram, from, NamespacePath::Victim)?;
    let dest = match to
        .map(|to| resolve(ram, to, NamespacePath::Destination))
        .transpose()
    {
        Ok(dest) => dest,
        Err(code) => {
            source.release(&mut ram.storage);
            ram.storage.release_preparation(charge);
            return Err(code);
        }
    };
    let result = ram.storage.prepare_namespace_paid(
        FIRST,
        charge,
        intent,
        source
            .namespace_proof(&ram.storage, ROOT_USER, NamespacePath::Victim)
            .unwrap(),
        dest.as_ref().map(|d| {
            d.namespace_proof(&ram.storage, ROOT_USER, NamespacePath::Destination)
                .unwrap()
        }),
        ROOT_USER,
    );
    source.release(&mut ram.storage);
    if let Some(dest) = dest {
        dest.release(&mut ram.storage);
    }
    let mut prep = match result {
        Ok(prep) => prep,
        Err(code) => {
            ram.storage.release_preparation(charge);
            return Err(code);
        }
    };
    let result = (|| {
        while !prep.step(&mut ram.storage, ROOT_USER)? {}
        prep.commit(&mut ram.storage, ROOT_USER, NOW)
    })();
    while !prep.cancel_step(&mut ram.storage).unwrap() {}
    ram.storage.release_preparation(charge);
    result
}

#[test]
fn the_names_and_the_attributes_of_a_layer_cannot_be_changed_but_its_directories_take_user_files() {
    let mut ram = ram();
    attach(&mut ram, 1, good().build());
    let layer = path(&ram, "/layer").unwrap();
    let bin = path(&ram, "/layer/bin").unwrap();
    // Remove, rename to and from, link to.
    assert_eq!(
        ram.storage.unlink(bin, b"hello", FIRST),
        Err(READ_ONLY_FILESYSTEM)
    );
    assert_eq!(
        ram.storage.unlink(ROOT, b"layer", FIRST),
        Err(proto_fs::IS_DIRECTORY)
    );
    assert_eq!(
        run_ns(&mut ram, NamespaceIntent::Rmdir, b"/layer/data", None),
        Err(READ_ONLY_FILESYSTEM)
    );
    assert_eq!(
        run_ns(&mut ram, NamespaceIntent::Rmdir, b"/layer", None),
        Err(READ_ONLY_FILESYSTEM)
    );
    assert_eq!(
        run_rename(&mut ram, b"/layer/bin/hello", b"/layer/bin/gone"),
        Err(READ_ONLY_FILESYSTEM)
    );
    assert_eq!(
        run_rename(&mut ram, b"/layer", b"/moved"),
        Err(READ_ONLY_FILESYSTEM)
    );
    user_file(&mut ram, ROOT, b"mine");
    assert_eq!(
        run_rename(&mut ram, b"/mine", b"/layer/bin/hello"),
        Err(READ_ONLY_FILESYSTEM)
    );
    let hello = path(&ram, "/layer/bin/hello").unwrap();
    assert_eq!(
        ram.storage.link(FIRST, ROOT, b"alias", hello),
        Err(READ_ONLY_FILESYSTEM)
    );
    // Attributes.
    use crate::metadata::{MetadataIntent, MetadataJournal, MetadataProof, TimeSetting};
    for intent in [
        MetadataIntent::Chmod(0o600),
        MetadataIntent::Chown {
            uid: Some(5),
            gid: None,
        },
        MetadataIntent::Times([TimeSetting::Now, TimeSetting::Now]),
    ] {
        let charge = ram.storage.charge_preparation(FIRST).unwrap();
        let proof = MetadataProof {
            target: hello,
            identity: ROOT_USER,
            epoch: ram.storage.state.epoch,
            path: intent.path(true),
        };
        let mut journal =
            MetadataJournal::path(&mut ram.storage, FIRST, charge, proof, ROOT_USER, intent)
                .unwrap();
        let proof = MetadataProof {
            target: hello,
            identity: ROOT_USER,
            epoch: ram.storage.state.epoch,
            path: intent.path(true),
        };
        let outcome = journal
            .commit(&mut ram, FIRST, ROOT_USER, Some(proof), Some(NOW))
            .unwrap();
        assert_eq!(
            outcome,
            crate::metadata::MetadataOutcome::Failed(READ_ONLY_FILESYSTEM),
            "{intent:?}"
        );
        while !journal.cancel_step(&mut ram).unwrap() {}
        ram.storage.release_preparation(charge);
    }
    // A write or a truncation through open is refused too.
    let mut fds = Fds {
        root: FIRST,
        ..Fds::default()
    };
    assert_eq!(
        ram.open(&mut fds, "/layer/bin/hello", proto_fs::READ_WRITE),
        Err(proto_fs::ACCESS_DENIED)
    );
    for flags in [proto_fs::WRITE_ONLY, proto_fs::READ_WRITE] {
        assert_eq!(
            ram.open_token(&mut fds, hello, flags, ROOT_USER),
            Err(proto_fs::ACCESS_DENIED)
        );
    }
    // The paid open of the service refuses a write to the file of a layer as it does a file of
    // the system, with EROFS.
    assert_eq!(ram.read_only_regular(hello), Ok(true));
    // The files of users in a directory of a layer come and go.
    let mine = user_file(&mut ram, layer, b"note");
    assert_eq!(names(&ram, layer), ["bin", "data", "note"]);
    assert_eq!(ram.storage.unlink(layer, b"note", FIRST), Ok(mine));
    assert_eq!(names(&ram, layer), ["bin", "data"]);
    assert_eq!(ram.storage.node(hello).unwrap().mode, 0o755);
    assert_eq!(ram.storage.node(layer).unwrap().mode, 0o755);
}

#[test]
fn a_directory_both_layers_name_lives_until_the_second_is_detached_and_one_with_user_files_stays() {
    let mut ram = ram();
    let a = Spec::new()
        .dir("/shared")
        .file("/shared/a", 0o644, b"a")
        .build();
    let b = Spec::new()
        .dir("/shared")
        .file("/shared/b", 0o644, b"b")
        .build();
    attach(&mut ram, 1, a);
    attach(&mut ram, 2, b);
    let free = ram.storage.layer_dirs_free();
    assert_eq!(free, LAYER_DIRS - 1);
    let shared = path(&ram, "/shared").unwrap();
    assert_eq!(names(&ram, shared), ["a", "b"]);
    assert_eq!(detach(&mut ram, 1), LayerReply::Done { names: 2 });
    settle(&mut ram);
    assert_eq!(names(&ram, shared), ["b"]);
    assert_eq!(ram.storage.node(shared).map(|n| n.mode), Ok(0o755));
    assert_eq!(ram.storage.layer_dirs_free(), free);
    // Now the user puts a file in it: it outlives both layers and goes with its last name.
    user_file(&mut ram, shared, b"keep");
    assert_eq!(detach(&mut ram, 2), LayerReply::Done { names: 2 });
    settle(&mut ram);
    assert_eq!(names(&ram, shared), ["keep"]);
    assert_eq!(path(&ram, "/shared"), Ok(shared));
    assert_eq!(ram.storage.layer_dirs_free(), free);
    assert_eq!(
        ram.storage.unlink(shared, b"keep", FIRST).map(|_| ()),
        Ok(())
    );
    ram.storage.layer_maintain(NOW, &Limits::PORTIONS);
    assert_eq!(path(&ram, "/shared"), Err(NO_ENTRY));
    assert_eq!(ram.storage.layer_dirs_free(), LAYER_DIRS);
    assert_eq!(ram.storage.node(shared).err(), Some(NO_ENTRY));
    ram.storage.check_name_index();
}

#[test]
fn the_places_and_the_layers_run_out_without_changing_the_tree() {
    let mut ram = ram();
    // One layer of 1 024 files, four times: the places are 4 096.
    for number in 1..=4u32 {
        let mut spec = Spec::new();
        for n in 0..1024 {
            spec = spec.file(&format!("/l{number}-{n:04}"), 0o644, b"x");
        }
        assert_eq!(
            attach(&mut ram, number, spec.build()),
            LayerReply::Done { names: 1024 }
        );
    }
    assert_eq!(ram.storage.layer_places_free(), 0);
    let before = same_tree(&ram);
    assert_eq!(
        attach(&mut ram, 5, Spec::new().file("/more", 0o644, b"x").build()),
        LayerReply::Refused { status: NO_SPACE }
    );
    assert_eq!(same_tree(&ram), before);
    assert_eq!(ram.storage.layers_in_use(), 4);
    for number in 1..=4 {
        assert_eq!(detach(&mut ram, number), LayerReply::Done { names: 1024 });
        settle(&mut ram);
    }
    // Sixty-four layers at most.
    for number in 1..=64u32 {
        let spec = Spec::new().file(&format!("/s{number}"), 0o644, b"x");
        assert_eq!(
            attach(&mut ram, number, spec.build()),
            LayerReply::Done { names: 1 },
            "{number}"
        );
    }
    assert_eq!(
        attach(&mut ram, 65, Spec::new().file("/s65", 0o644, b"x").build()),
        LayerReply::Refused { status: NO_SPACE }
    );
    assert_eq!(path(&ram, "/s65"), Err(NO_ENTRY));
    ram.storage.check_name_index();
}

#[test]
fn the_name_of_a_free_place_is_empty_and_reads_no_memory_of_the_layer() {
    let mut ram = ram();
    let bytes = Spec::new().file("/ghost", 0o644, b"x").build();
    attach(&mut ram, 1, bytes);
    detach(&mut ram, 1);
    settle(&mut ram);
    // The layer's mapping is gone: the bytes are garbage now, and the places must not read them.
    let garbage = bytes.as_ptr() as *mut u8;
    // SAFETY: the buffer is leaked by the test and nothing else reads it.
    unsafe { core::ptr::write_bytes(garbage, 0xff, bytes.len()) };
    assert_eq!(path(&ram, "/ghost"), Err(NO_ENTRY));
    assert_eq!(names(&ram, ROOT), ["etc", "tmp"]);
    for b in [ENTRIES_MAX, ENTRIES_MAX + 1, ENTRIES_MAX + LAYER_SLOTS - 1] {
        assert!(ram.storage.layer_name(b).is_empty());
    }
    // The next lookup of every kind answers as before.
    assert_eq!(path(&ram, "/tmp").map(|t| t.slot), Ok(2));
    ram.storage.check_name_index();
}

#[test]
fn a_client_that_leaves_in_the_middle_of_the_insertion_takes_its_names_out_in_the_portions_of_the_service()
 {
    let mut ram = ram();
    let before = same_tree(&ram);
    let mut spec = Spec::new().dir("/part");
    for n in 0..100 {
        spec = spec.file(&format!("/part/f{n:03}"), 0o644, b"x");
    }
    let bytes = spec.build();
    let index = ram.storage.layer_begin_attach(1, false).unwrap();
    ram.storage
        .layer_mapped(index, bytes.as_ptr(), bytes.len())
        .unwrap();
    loop {
        // Until some of the names are in.
        assert_eq!(
            ram.storage.layer_step(1, NOW, &Limits::PORTIONS),
            LayerReply::Resolving
        );
        if ram.storage.layer_names(1) > 20 {
            break;
        }
    }
    assert!(path(&ram, "/part/f000").is_ok());
    ram.storage.layer_client_gone();
    assert!(ram.storage.layer_work());
    let mut rounds = 0;
    while ram.storage.layer_maintain(NOW, &Limits::PORTIONS) {
        rounds += 1;
        assert!(rounds < 100);
    }
    assert!(!ram.storage.layer_work());
    assert_eq!(path(&ram, "/part"), Err(NO_ENTRY));
    assert_eq!(settle(&mut ram).len(), 1);
    assert_eq!(same_tree(&ram), before);
    assert_eq!(ram.storage.layer_dirs_free(), LAYER_DIRS);
}

#[test]
fn the_steps_of_the_insertion_follow_the_portions_and_a_long_chain_goes_on_in_the_next_step() {
    let mut ram = ram();
    let mut spec = Spec::new();
    for n in 0..64 {
        spec = spec.file(&format!("/f{n:03}"), 0o644, b"x");
    }
    let bytes = spec.build();
    let (reply, steps) = attach_counting(&mut ram, 1, bytes);
    assert_eq!(reply, LayerReply::Done { names: 64 });
    // The check: 16 entries a step; the insertion: 8 entries a step; plus the first and last.
    let check = 64usize.div_ceil(CHECK_ENTRIES);
    let insert = 64usize.div_ceil(INSERT_ENTRIES);
    assert_eq!(steps, check + insert);
    detach(&mut ram, 1);
    settle(&mut ram);
    // All the names in one bucket: every lookup follows the chain, and a chain longer than the
    // portion of links goes on in the next step.
    let one = crate::storage::tests_support::OneBucket::new();
    let (reply, steps_chained) = attach_counting(&mut ram, 2, bytes);
    assert_eq!(reply, LayerReply::Done { names: 64 });
    assert!(steps_chained > steps, "{steps_chained} > {steps}");
    for n in 0..64 {
        assert!(path(&ram, &format!("/f{n:03}")).is_ok());
    }
    drop(one);
}

#[test]
fn a_rejected_number_or_a_second_job_changes_nothing() {
    let mut ram = ram();
    attach(&mut ram, 1, good().build());
    assert_eq!(
        ram.storage.layer_begin_attach(1, false),
        Err(proto_fs::ALREADY_EXISTS)
    );
    assert_eq!(ram.storage.layer_begin_detach(7), Err(NO_ENTRY));
    let index = ram.storage.layer_begin_attach(2, false).unwrap();
    assert_eq!(
        ram.storage.layer_begin_attach(3, false),
        Err(proto_fs::BUSY)
    );
    assert_eq!(ram.storage.layer_begin_detach(1), Err(proto_fs::BUSY));
    ram.storage.layer_unmapped(index);
    assert_eq!(ram.storage.layer_begin_detach(1), Ok(()));
}

#[test]
fn a_layer_of_the_image_is_not_detached() {
    let mut ram = ram();
    let bytes = good().build();
    assert_eq!(ram.storage.layer_attach_image(0x8000, bytes, NOW), Ok(7));
    assert!(ram.storage.layer_is_image(0x8000));
    assert_eq!(ram.storage.layer_begin_detach(0x8000), Err(PERMISSION));
    assert!(path(&ram, "/layer/bin/hello").is_ok());
    let clash = Spec::new()
        .dir("/layer")
        .file("/layer/bin", 0o644, b"x")
        .build();
    assert!(matches!(
        ram.storage.layer_attach_image(0x8001, clash, NOW),
        Err(LayerReply::Entry {
            status: CONFLICT,
            entry: 1
        })
    ));
    assert_eq!(ram.storage.layers_in_use(), 1);
}
