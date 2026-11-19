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
            &self
                .call(owner, |w| crate::tests::opening(path, flags, w))
                .unwrap(),
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

/// The attribute of the version-3 server under the cut of the power at every sector: the creation
/// of a file with its record, CHMOD, and the conversion of a volume of version 2.
mod attributes {
    use super::*;
    use crate::fs::Open;
    use crate::tests_perm::convert_to_the_end;
    use crate::tests_perm::{OWNER, ROOT, Rig, SECTORS};

    const SURVIVE: [Survive; 3] = [Survive::None, Survive::All, Survive::Random(7)];

    /// The device of `rig` after the machine started again with `survive` of its cache.
    fn restarted(rig: Rig, survive: Survive) -> Rig {
        let mut device = rig.fs.into_device();
        device.power_cycle(survive);
        Rig::on(device)
    }

    /// A fresh device with `/d` (mode 0777), settled, as the base of a cut.
    fn base() -> MemDevice {
        let mut rig = Rig::new();
        rig.mkdir(ROOT, b"/d", 0o777).unwrap();
        rig.put(OWNER, b"/d/old", 0o644, b"data");
        rig.fs.unmount().unwrap();
        rig.fs.into_device()
    }

    #[test]
    fn a_cut_in_the_creation_of_a_file_leaves_no_entry_the_whole_entry_or_an_empty_closed_one() {
        // How many sectors the creation writes, uncut.
        let mut probe = Rig::on(base());
        let before = probe.fs.device().written;
        probe.put(OWNER, b"/d/new", 0o640, b"");
        let sectors = probe.fs.device().written - before;
        assert!(sectors >= 2);
        let (mut none, mut whole, mut closed) = (0, 0, 0);
        for cut in 0..=sectors {
            for survive in SURVIVE {
                let mut rig = Rig::on(base());
                rig.fs.device().cut_after(Some(cut));
                let _ = rig.open(OWNER, b"/d/new", p::WRITE | p::CREATE, 0o640);
                let mut rig = restarted(rig, survive);
                match rig.stat(ROOT, b"/d/new") {
                    Err(_) => none += 1,
                    Ok(st) if (st.uid, st.gid, st.mode) == (1000, 100, 0o640) => {
                        assert_eq!(st.size, 0);
                        whole += 1;
                    }
                    Ok(st) => {
                        // The name was committed and the record was not: the closed default.
                        assert_eq!(
                            (st.uid, st.gid, st.mode, st.size),
                            (0, 0, 0o600, 0),
                            "cut {cut}"
                        );
                        assert_eq!(
                            rig.open(OWNER, b"/d/new", p::READ, 0),
                            Err(p::code(p::ACCESS))
                        );
                        closed += 1;
                    }
                }
                // The file that was there still reads, and the volume takes the next create.
                let h = rig.open(ROOT, b"/d/old", p::READ, 0).unwrap();
                assert_eq!(rig.read(ROOT, h, 10).unwrap(), b"data");
                rig.put(OWNER, b"/d/next", 0o644, b"x");
                let next = rig.stat(ROOT, b"/d/next").unwrap();
                assert_eq!(next.uid, 1000);
                // The number of the entry that survived the cut is not the next file's.
                if let Ok(survivor) = rig.stat(ROOT, b"/d/new") {
                    assert_ne!(survivor.ino, next.ino, "cut {cut}");
                }
            }
        }
        assert!(
            none > 0 && whole > 0,
            "{none} none, {whole} whole, {closed} closed"
        );
    }

    #[test]
    fn a_cut_in_chmod_leaves_the_old_mode_or_the_new_and_nothing_else_changed() {
        let mut probe = Rig::on(base());
        let before = probe.fs.device().written;
        probe.chmod(OWNER, b"/d/old", 0o600).unwrap();
        let sectors = probe.fs.device().written - before;
        let (mut old, mut new) = (0, 0);
        for cut in 0..=sectors {
            for survive in SURVIVE {
                let mut rig = Rig::on(base());
                rig.fs.device().cut_after(Some(cut));
                let _ = rig.chmod(OWNER, b"/d/old", 0o600);
                let mut rig = restarted(rig, survive);
                let st = rig.stat(ROOT, b"/d/old").unwrap();
                assert!(
                    st.mode == 0o644 || st.mode == 0o600,
                    "cut {cut}: {:o}",
                    st.mode
                );
                assert_eq!((st.uid, st.gid, st.size), (1000, 100, 4));
                if st.mode == 0o600 {
                    new += 1;
                } else {
                    old += 1;
                }
            }
        }
        assert!(old > 0 && new > 0);
    }

    /// A volume as the 0.5 service left it: no attribute anywhere.
    fn version_two() -> MemDevice {
        let mut state = Storage::new();
        let mut fs = Fs::new(MemDevice::new(SECTORS), &mut state).unwrap();
        fs.format().unwrap();
        fs.mount().unwrap();
        for dir in [&b"/ssh"[..], b"/etc", b"/etc/inner"] {
            fs.mkdir(dir).unwrap();
        }
        for (path, data) in [
            (&b"/ssh/host_key"[..], &b"secret"[..]),
            (b"/etc/conf", b"c"),
            (b"/etc/inner/deep", b"d"),
            (b"/top", b"t"),
        ] {
            let f = fs.open(path, Open::WRITE.with(Open::CREATE)).unwrap();
            fs.write(f, data).unwrap();
            fs.close(f).unwrap();
        }
        fs.unmount().unwrap();
        fs.into_device()
    }

    /// A volume a build with inline data on left: small files inside the pairs of their directories.
    fn inline_volume() -> MemDevice {
        let mut state = Storage::new();
        let mut fs = Fs::new(MemDevice::new(SECTORS), &mut state).unwrap();
        fs.set_inline_max(0);
        fs.format().unwrap();
        fs.mount().unwrap();
        fs.mkdir(b"/ssh").unwrap();
        for (path, data) in INLINE_FILES {
            let f = fs.open(path, Open::WRITE.with(Open::CREATE)).unwrap();
            fs.write(f, data).unwrap();
            fs.close(f).unwrap();
        }
        fs.unmount().unwrap();
        fs.into_device()
    }

    const INLINE_FILES: [(&[u8], &[u8]); 3] = [
        (b"/ssh/host_key", b"0123456789abcdef0123456789abcdef"),
        (b"/note", b"a short note"),
        (b"/empty", b""),
    ];

    /// The bytes of the file at `path`, read from the volume directly.
    fn bytes_of(fs: &mut Fs<'_, MemDevice>, path: &[u8]) -> Vec<u8> {
        let f = fs.open(path, Open::READ).unwrap();
        let mut out = vec![0u8; 64];
        let n = fs.read(f, &mut out).unwrap();
        fs.close(f).unwrap();
        out.truncate(n);
        out
    }

    #[test]
    fn a_cut_at_every_sector_of_the_move_out_of_inline_files_leaves_the_old_file_or_the_moved_one()
    {
        // The sectors of the whole mount work, uncut.
        let mut state = Storage::new();
        let mut fs = Fs::new(inline_volume(), &mut state).unwrap();
        fs.mount().unwrap();
        let mut server = server::Server::new();
        let before = fs.device().written;
        let report = server.mount_work(&mut fs).unwrap();
        assert!(report.pending, "{report:?}");
        let (_, moved) = convert_to_the_end(&mut server, &mut fs);
        assert_eq!(moved, 2);
        let sectors = fs.device().written - before;
        assert!(sectors >= 4, "{sectors} sectors");
        for cut in 0..=sectors {
            for survive in SURVIVE {
                let mut state = Storage::new();
                let mut fs = Fs::new(inline_volume(), &mut state).unwrap();
                fs.mount().unwrap();
                let mut server = server::Server::new();
                fs.device().cut_after(Some(cut));
                let _ = server.mount_work(&mut fs);
                while server.conversion_pending() {
                    if server.convert_step(&mut fs).is_err() {
                        break;
                    }
                }
                let mut device = fs.into_device();
                device.power_cycle(survive);
                // The volume mounts, and every file is whole: the old bytes, moved or not.
                let mut state = Storage::new();
                let mut fs = Fs::new(device, &mut state).unwrap();
                fs.mount().unwrap();
                for (path, data) in INLINE_FILES {
                    assert_eq!(bytes_of(&mut fs, path), data, "cut {cut} {path:?}");
                }
                // The next start finishes the work, and a write in the middle of the old key works.
                let mut server = server::Server::new();
                let done = server.mount_work(&mut fs).unwrap();
                assert!(done.pending || done.complete, "cut {cut}: {done:?}");
                convert_to_the_end(&mut server, &mut fs);
                let f = fs.open(b"/ssh/host_key", Open::READ_WRITE).unwrap();
                fs.seek(f, 8, crate::fs::Whence::Set).unwrap();
                fs.write(f, b"NEW!").unwrap();
                fs.close(f).unwrap();
                assert_eq!(
                    bytes_of(&mut fs, b"/ssh/host_key"),
                    b"01234567NEW!cdef0123456789abcdef".to_vec(),
                    "cut {cut}"
                );
            }
        }
    }

    #[test]
    fn a_cut_in_the_conversion_of_a_volume_of_version_2_starts_again_and_ends() {
        let paths: [&[u8]; 8] = [
            b"/",
            b"/ssh",
            b"/ssh/host_key",
            b"/etc",
            b"/etc/conf",
            b"/etc/inner",
            b"/etc/inner/deep",
            b"/top",
        ];
        // The sectors of the whole conversion, uncut.
        let device = version_two();
        let mut state = Storage::new();
        let mut fs = Fs::new(device, &mut state).unwrap();
        fs.mount().unwrap();
        let mut server = server::Server::new();
        let before = fs.device().written;
        let report = server.mount_work(&mut fs).unwrap();
        assert!(report.pending, "{report:?}");
        let (converted, _) = convert_to_the_end(&mut server, &mut fs);
        assert!(converted >= 8, "{converted} records");
        let sectors = fs.device().written - before;
        assert!(sectors >= 9, "{sectors} sectors");
        for cut in 0..=sectors {
            for survive in SURVIVE {
                let mut state = Storage::new();
                let mut fs = Fs::new(version_two(), &mut state).unwrap();
                fs.mount().unwrap();
                let mut server = server::Server::new();
                fs.device().cut_after(Some(cut));
                let _ = server.mount_work(&mut fs);
                while server.conversion_pending() {
                    if server.convert_step(&mut fs).is_err() {
                        break;
                    }
                }
                let mut device = fs.into_device();
                device.power_cycle(survive);
                // The next start finishes it: every entry has its record, the mark is there, the
                // numbers are all different, and the key is still closed.
                let mut rig = Rig::on(device);
                let mut numbers = Vec::new();
                for path in paths {
                    let st = rig.stat(ROOT, path).unwrap();
                    let (mode, want) = (
                        st.mode,
                        if path == b"/" {
                            0o755
                        } else if st.kind == p::KIND_DIRECTORY {
                            0o700
                        } else {
                            0o600
                        },
                    );
                    assert_eq!(mode, want, "cut {cut} {}", String::from_utf8_lossy(path));
                    assert_eq!((st.uid, st.gid), (0, 0));
                    numbers.push(st.ino);
                }
                numbers.sort_unstable();
                numbers.dedup();
                assert_eq!(numbers.len(), paths.len(), "cut {cut}: {numbers:?}");
                let mut mark = [0u8; 4];
                rig.fs
                    .getattr(b"/", crate::attr::ATTR_FORMAT_TYPE, &mut mark)
                    .unwrap();
                assert_eq!(u32::from_le_bytes(mark), crate::attr::VOLUME_FORMAT);
                assert_eq!(
                    rig.open(OWNER, b"/ssh/host_key", p::READ, 0),
                    Err(p::code(p::ACCESS))
                );
            }
        }
    }
}
