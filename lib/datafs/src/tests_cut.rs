// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The cut of the power through the server: the calls that move an open file (unlink while open,
//! rename over an open file, rename of an open file) and the recovery of the orphans, with a cut at
//! every sector they write and each of four things the cache can do. After the machine starts again
//! the volume mounts, `recover_orphans` runs, and each name is the old or the new, with no orphan
//! left and nothing to recover the second time.

use crate::fs::{Fs, Storage};
use crate::mem::{MemDevice, Survive};
use crate::server::{self, ORPHANS, Recovered, Server};
use crate::tests::{Node, Tree, pattern, read_tree};
use crate::{Device, Error};
use proto_data as p;
use proto_wire::{Status, Writer};
use std::boxed::Box;
use std::string::{String, ToString};
use std::vec::Vec;

const SECTORS: u64 = 4096;
const A: u64 = 1;
const B: u64 = 2;

struct Rig<'a> {
    server: Server,
    fs: Fs<'a, MemDevice>,
}

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

impl Rig<'_> {
    fn call(
        &mut self,
        owner: u64,
        build: impl FnOnce(&mut Writer) -> Result<(), Status>,
    ) -> Result<Vec<u8>, Status> {
        let mut w = Writer::new();
        build(&mut w).unwrap();
        let reply = self.server.handle(&mut self.fs, owner, 0, w.as_bytes());
        p::reply(reply.as_bytes()).map(|mut r| r.bytes(r.left()).unwrap().to_vec())
    }

    fn open(&mut self, owner: u64, path: &[u8], flags: u32) -> u32 {
        word(
            &self.call(owner, |w| p::open_v2(path, flags, w)).unwrap(),
            0,
        )
    }

    /// A file made, written whole and synced, through the protocol; the description stays open.
    fn put(&mut self, owner: u64, path: &[u8], data: &[u8]) -> u32 {
        let h = self.open(owner, path, p::READ | p::WRITE | p::CREATE);
        for chunk in data.chunks(900) {
            self.call(owner, |w| p::write(h, chunk, w)).unwrap();
        }
        self.call(owner, |w| p::handle_call(p::Method::Fsync, h, w))
            .unwrap();
        h
    }
}

type Setup = fn(&mut Rig<'_>) -> u32;
type Action = fn(&mut Rig<'_>, u32);

struct Scenario {
    name: &'static str,
    setup: Setup,
    action: Action,
    allowed: Vec<Tree>,
}

fn tree(files: &[(&str, Vec<u8>)]) -> Tree {
    let mut t: Tree = Tree::new();
    for (path, data) in files {
        t.insert((*path).to_string(), Node::File(data.clone()));
    }
    t
}

fn old() -> Vec<u8> {
    pattern(9000, 1)
}

fn source() -> Vec<u8> {
    pattern(3000, 2)
}

fn tail() -> Vec<u8> {
    [source(), b"tail".to_vec()].concat()
}

fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            name: "unlink of an open file",
            setup: |t| t.put(A, b"/a", &old()),
            action: |t, h| {
                let _ = t.call(B, |w| p::path_call(p::Method::Unlink, b"/a", w));
                let _ = t.call(A, |w| p::handle_call(p::Method::Close, h, w));
            },
            allowed: vec![tree(&[("/a", old())]), tree(&[])],
        },
        Scenario {
            name: "rename over an open file",
            setup: |t| {
                t.put(B, b"/s", &source());
                t.put(A, b"/t", &old())
            },
            action: |t, h| {
                let _ = t.call(B, |w| p::rename(b"/s", b"/t", w));
                let _ = t.call(A, |w| p::handle_call(p::Method::Close, h, w));
            },
            allowed: vec![
                tree(&[("/s", source()), ("/t", old())]),
                tree(&[("/t", source())]),
            ],
        },
        Scenario {
            name: "rename of an open file with an unsynced write",
            setup: |t| t.put(A, b"/s", &source()),
            action: |t, h| {
                let _ = t.call(A, |w| p::write(h, b"tail", w));
                let _ = t.call(B, |w| p::rename(b"/s", b"/n", w));
                let _ = t.call(A, |w| p::handle_call(p::Method::Close, h, w));
            },
            // Before the sync of the move, the write is lost whole; after it, the file has it
            // wherever the name is.
            allowed: vec![
                tree(&[("/s", source())]),
                tree(&[("/s", tail())]),
                tree(&[("/n", tail())]),
            ],
        },
    ]
}

/// One run: the setup (durable), the action with a cut after `cut` sectors, the power back with
/// `survive`, the mount, the recovery. The tree, what the recovery did, and the sectors written.
fn run(s: &Scenario, cut: Option<u64>, survive: Survive) -> (Tree, Recovered, u64) {
    let mut state = Box::new(Storage::new());
    let mut rig = Rig {
        server: Server::with_epoch(1),
        fs: Fs::new(MemDevice::new(SECTORS), &mut state).unwrap(),
    };
    rig.fs.format().unwrap();
    rig.fs.mount().unwrap();
    server::ensure_orphans(&mut rig.fs).unwrap();
    let h = (s.setup)(&mut rig);
    rig.fs.device().flush().unwrap();
    let before = rig.fs.device().written;
    rig.fs.device().cut_after(cut);
    (s.action)(&mut rig, h);
    let written = rig.fs.device().written - before;
    let mut device = rig.fs.into_device();
    device.power_cycle(survive);
    let mut state = Box::new(Storage::new());
    let mut fs = Fs::new(device, &mut state).unwrap();
    fs.mount().expect("the volume mounts after the cut");
    let done = server::recover_orphans(&mut fs).expect("the recovery runs");
    // Nothing is left under the orphans, and a second recovery finds nothing.
    assert_eq!(server::recover_orphans(&mut fs), Ok(Recovered::default()));
    let mut found = read_tree(&mut fs).expect("the tree reads");
    found.remove(core::str::from_utf8(ORPHANS).unwrap());
    (found, done, written)
}

fn outline(t: &Tree) -> Vec<String> {
    t.iter()
        .map(|(p, n)| match n {
            Node::Dir => std::format!("{p}/"),
            Node::File(b) => std::format!("{p} {}", b.len()),
        })
        .collect()
}

#[test]
fn a_cut_at_every_sector_of_a_move_of_an_open_file_leaves_the_old_name_or_the_new() {
    for s in scenarios() {
        let (whole, _, total) = run(&s, None, Survive::All);
        assert!(
            s.allowed.contains(&whole),
            "{}: the run without a cut",
            s.name
        );
        assert!(total >= 2, "{}: {total} sectors", s.name);
        let (mut removed, mut restored) = (0, 0);
        for cut in 0..total {
            for survive in [
                Survive::None,
                Survive::All,
                Survive::Random(cut * 2 + 1),
                Survive::Prefix(cut as usize % 5),
            ] {
                let (found, done, _) = run(&s, Some(cut), survive);
                assert!(
                    s.allowed.contains(&found),
                    "{}: cut {cut} {survive:?}: the tree is {:?}",
                    s.name,
                    outline(&found)
                );
                removed += done.removed;
                restored += done.restored;
                assert_eq!(done.failed, 0);
            }
        }
        // The recovery has work in the runs: orphans removed in each scenario that makes them, and
        // a file put back where the cut came between the two commits of the rename over a file.
        if !s.name.starts_with("rename of an open") {
            assert!(removed > 0, "{}: no orphan was ever removed", s.name);
        }
        if s.name == "rename over an open file" {
            assert!(restored > 0, "no marked file was ever put back");
        } else {
            assert_eq!(restored, 0, "{}", s.name);
        }
    }
}

/// The recovery is itself cut at each sector: a marked file whose home is free goes back, an
/// unmarked one goes, and a second pass after the next start finishes what the first began.
#[test]
fn a_cut_in_the_recovery_is_finished_by_the_next_one() {
    let data = pattern(7000, 5);
    let crafted = |cut: Option<u64>, survive: Survive| -> Tree {
        let mut state = Box::new(Storage::new());
        let mut fs = Fs::new(MemDevice::new(SECTORS), &mut state).unwrap();
        fs.format().unwrap();
        fs.mount().unwrap();
        server::ensure_orphans(&mut fs).unwrap();
        // A marked orphan (token 7, home /t, which is missing) and an unmarked one.
        let f = fs
            .open(
                b"/.orphans/7",
                crate::fs::Open::WRITE.with(crate::fs::Open::CREATE),
            )
            .unwrap();
        fs.write(f, &data).unwrap();
        fs.close(f).unwrap();
        let mut mark = 7u64.to_le_bytes().to_vec();
        mark.extend_from_slice(b"/t");
        fs.setattr(b"/.orphans/7", 0x68, &mark).unwrap();
        let g = fs
            .open(
                b"/.orphans/8",
                crate::fs::Open::WRITE.with(crate::fs::Open::CREATE),
            )
            .unwrap();
        fs.write(g, b"gone").unwrap();
        fs.close(g).unwrap();
        fs.device().flush().unwrap();
        fs.device().cut_after(cut);
        let _ = server::recover_orphans(&mut fs);
        let mut device = fs.into_device();
        device.power_cycle(survive);
        let mut state = Box::new(Storage::new());
        let mut fs = Fs::new(device, &mut state).unwrap();
        fs.mount().unwrap();
        server::recover_orphans(&mut fs).unwrap();
        assert_eq!(server::recover_orphans(&mut fs), Ok(Recovered::default()));
        let mut found = read_tree(&mut fs).unwrap();
        found.remove("/.orphans");
        found
    };
    let want = tree(&[("/t", data.clone())]);
    assert_eq!(crafted(None, Survive::All), want);
    let mut cuts = 0;
    for cut in 0..40 {
        for survive in [Survive::None, Survive::All, Survive::Random(cut + 3)] {
            assert_eq!(crafted(Some(cut), survive), want, "cut {cut} {survive:?}");
            cuts += 1;
        }
    }
    assert!(cuts > 100);
    let _ = (Error::Io, SECTORS);
}
