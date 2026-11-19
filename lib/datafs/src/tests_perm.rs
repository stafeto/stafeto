// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Permissions, identity, attributes and limits of the server (version 3 of `proto_data`): the
//! matrix of every method for the owner, a member of the group, another user and the superuser, the
//! rights an open description keeps, the binding of a session, the numbers and times of files, the
//! reserve, the file size limit, the cap of a directory, the conversion of a volume of version 2,
//! and the refusal of a later format.

use crate::Device;
use crate::attr::{ATTR_FORMAT_TYPE, ATTR_TYPE, Attr};
use crate::binding::{Binding, GROUPS_MAX, Vouched};
use crate::fs::{Fs, Open, Storage};
use crate::mem::MemDevice;
use crate::server::{self, Server};
use proto_data as p;
use proto_wire::{Reader, Status, Writer};
use std::boxed::Box;
use std::string::String;
use std::vec::Vec;

pub(crate) const OWNER: u64 = 11;
pub(crate) const GROUP: u64 = 12;
pub(crate) const OTHER: u64 = 13;
/// A native client of the list of init: user 0.
pub(crate) const ROOT: u64 = p::SERVICE | 1;

pub(crate) const SECTORS: u64 = 4096;

pub(crate) fn user(uid: u32, gid: u32, groups: &[u32]) -> Vouched {
    let mut g = [0u32; GROUPS_MAX];
    g[..groups.len()].copy_from_slice(groups);
    Vouched {
        pid: uid + 100,
        index: 0,
        generation: 1,
        uid,
        euid: uid,
        suid: uid,
        gid,
        egid: gid,
        sgid: gid,
        groups: g,
        group_count: groups.len(),
        fsize_limit: u64::MAX,
        root: u64::from(uid) + 100,
    }
}

/// A volume mounted, a server that does not treat every session as a native client's, the owner
/// (1000, group 100), a member of group 100 (1001), another user (2000, group 200) bound, and a
/// native client (user 0).
pub(crate) struct Rig {
    pub server: Server,
    pub fs: Fs<'static, MemDevice>,
}

impl Rig {
    pub fn new() -> Rig {
        Rig::on(MemDevice::new(SECTORS))
    }

    pub fn on(device: MemDevice) -> Rig {
        let state: &'static mut Storage = Box::leak(Box::new(Storage::new()));
        let mut fs = Fs::new(device, state).unwrap();
        if fs.mount().is_err() {
            fs.format().unwrap();
            fs.mount().unwrap();
        }
        let mut server = Server::new();
        server.default_service = false;
        server.set_now(1_000);
        server::ensure_orphans(&mut fs).unwrap();
        let mounted = server.mount_work(&mut fs).unwrap();
        assert!(mounted.complete || mounted.refused);
        let mut rig = Rig { server, fs };
        rig.bind(OWNER, user(1000, 100, &[]));
        rig.bind(GROUP, user(1001, 100, &[]));
        rig.bind(OTHER, user(2000, 200, &[]));
        rig
    }

    pub fn bind(&mut self, label: u64, v: Vouched) {
        self.server.bind_new(label, v).unwrap();
    }

    pub fn call(
        &mut self,
        who: u64,
        build: impl FnOnce(&mut Writer) -> Result<(), Status>,
    ) -> Result<Vec<u8>, Status> {
        let mut w = Writer::new();
        build(&mut w).unwrap();
        let reply = self.server.handle(&mut self.fs, who, 0, w.as_bytes());
        p::reply(reply.as_bytes()).map(|mut r| r.bytes(r.left()).unwrap().to_vec())
    }

    pub fn ok(
        &mut self,
        who: u64,
        build: impl FnOnce(&mut Writer) -> Result<(), Status>,
    ) -> Vec<u8> {
        self.call(who, build).unwrap()
    }

    pub fn open(&mut self, who: u64, path: &[u8], flags: u32, mode: u32) -> Result<u32, Status> {
        self.call(who, |w| p::open(path, flags, mode, w))
            .map(|r| u32::from_le_bytes(r[..4].try_into().unwrap()))
    }

    pub fn mkdir(&mut self, who: u64, path: &[u8], mode: u32) -> Result<(), Status> {
        self.call(who, |w| p::mkdir(path, mode, w)).map(drop)
    }

    pub fn stat(&mut self, who: u64, path: &[u8]) -> Result<p::Stat, Status> {
        let r = self.call(who, |w| p::path_call(p::Method::Stat, path, w))?;
        Ok(p::Stat::from_bytes(&r).unwrap())
    }

    pub fn chmod(&mut self, who: u64, path: &[u8], mode: u32) -> Result<(), Status> {
        self.call(who, |w| p::chmod(path, mode, w)).map(drop)
    }

    pub fn chown(&mut self, who: u64, path: &[u8], uid: u32, gid: u32) -> Result<(), Status> {
        self.call(who, |w| p::chown(path, uid, gid, w)).map(drop)
    }

    pub fn write(&mut self, who: u64, h: u32, data: &[u8]) -> Result<u32, Status> {
        self.call(who, |w| p::write(h, data, w))
            .map(|r| u32::from_le_bytes(r[..4].try_into().unwrap()))
    }

    pub fn read(&mut self, who: u64, h: u32, count: u32) -> Result<Vec<u8>, Status> {
        self.call(who, |w| p::read(h, count, w))
            .map(|r| r[4..].to_vec())
    }

    pub fn close(&mut self, who: u64, h: u32) {
        self.ok(who, |w| p::handle_call(p::Method::Close, h, w));
    }

    /// CLONE: a session `child` that holds the descriptions `handles` of `who`'s.
    pub fn clone_session(&mut self, who: u64, child: u64, handles: &[u32]) -> Result<(), Status> {
        let mut w = Writer::new();
        p::clone(handles, &mut w).unwrap();
        let reply = self.server.handle(&mut self.fs, who, child, w.as_bytes());
        p::reply(reply.as_bytes()).map(drop)
    }

    /// A file made as `who` with `data`, closed.
    pub fn put(&mut self, who: u64, path: &[u8], mode: u32, data: &[u8]) {
        let h = self.open(who, path, p::WRITE | p::CREATE, mode).unwrap();
        if !data.is_empty() {
            self.write(who, h, data).unwrap();
        }
        self.close(who, h);
    }

    /// The names of a directory, as `who` lists it.
    pub fn names(&mut self, who: u64, path: &[u8]) -> Result<Vec<String>, Status> {
        let dir = self.open(who, path, p::DIRECTORY | p::READ, 0)?;
        let mut names = Vec::new();
        loop {
            let e = self.call(who, |w| p::handle_call(p::Method::Readdir, dir, w))?;
            let mut batch = p::read_dir_reply(Reader::new(&e)).unwrap();
            while let Some(entry) = batch.next_entry().unwrap() {
                names.push(String::from_utf8(entry.name.to_vec()).unwrap());
            }
            if !batch.more {
                break;
            }
        }
        self.close(who, dir);
        Ok(names)
    }

    /// `/d` owned by 1000:100 with mode `mode`, and in it the file `/d/f` (0640, 1000:100) and the
    /// directory `/d/sub` (0750, 1000:100), all made by the superuser and then handed over.
    pub fn tree(&mut self, dir_mode: u32) {
        self.mkdir(ROOT, b"/d", 0o755).unwrap();
        self.put(ROOT, b"/d/f", 0o640, b"hello");
        self.mkdir(ROOT, b"/d/sub", 0o750).unwrap();
        for path in [&b"/d"[..], b"/d/f", b"/d/sub"] {
            self.chown(ROOT, path, 1000, 100).unwrap();
        }
        self.chmod(ROOT, b"/d", dir_mode).unwrap();
    }
}

const ACCESS: Status = p::code(p::ACCESS);
const PERMISSION: Status = p::code(p::PERMISSION);

type Op = fn(&mut Rig, u64) -> Result<(), Status>;

/// One row: the call, and what the owner, a member of the group, another user and the superuser get.
struct Row {
    name: &'static str,
    dir_mode: u32,
    op: Op,
    expect: [Result<(), Status>; 4],
}

fn rows() -> Vec<Row> {
    let ok = Ok(());
    vec![
        Row {
            name: "open for reading (file 0640)",
            dir_mode: 0o755,
            op: |r, w| r.open(w, b"/d/f", p::READ, 0).map(drop),
            expect: [ok, ok, Err(ACCESS), ok],
        },
        Row {
            name: "open for writing (file 0640)",
            dir_mode: 0o755,
            op: |r, w| r.open(w, b"/d/f", p::WRITE, 0).map(drop),
            expect: [ok, Err(ACCESS), Err(ACCESS), ok],
        },
        Row {
            name: "open with truncate (file 0640)",
            dir_mode: 0o755,
            op: |r, w| r.open(w, b"/d/f", p::WRITE | p::TRUNCATE, 0).map(drop),
            expect: [ok, Err(ACCESS), Err(ACCESS), ok],
        },
        Row {
            name: "stat through a directory 0755",
            dir_mode: 0o755,
            op: |r, w| r.stat(w, b"/d/f").map(drop),
            expect: [ok, ok, ok, ok],
        },
        Row {
            name: "stat through a directory 0700 (search on the ancestor)",
            dir_mode: 0o700,
            op: |r, w| r.stat(w, b"/d/f").map(drop),
            expect: [ok, Err(ACCESS), Err(ACCESS), ok],
        },
        Row {
            name: "open through a directory 0700",
            dir_mode: 0o700,
            op: |r, w| r.open(w, b"/d/f", p::READ, 0).map(drop),
            expect: [ok, Err(ACCESS), Err(ACCESS), ok],
        },
        Row {
            name: "access R_OK (file 0640)",
            dir_mode: 0o755,
            op: |r, w| {
                r.call(w, |b| p::access(b"/d/f", p::ACCESS_READ, 0, b))
                    .map(drop)
            },
            expect: [ok, ok, Err(ACCESS), ok],
        },
        Row {
            name: "access W_OK (file 0640)",
            dir_mode: 0o755,
            op: |r, w| {
                r.call(w, |b| p::access(b"/d/f", p::ACCESS_WRITE, 0, b))
                    .map(drop)
            },
            expect: [ok, Err(ACCESS), Err(ACCESS), ok],
        },
        Row {
            name: "access X_OK of a file with no execute bit",
            dir_mode: 0o755,
            op: |r, w| {
                r.call(w, |b| p::access(b"/d/f", p::ACCESS_EXEC, 0, b))
                    .map(drop)
            },
            expect: [Err(ACCESS), Err(ACCESS), Err(ACCESS), Err(ACCESS)],
        },
        Row {
            name: "access F_OK through a directory 0700",
            dir_mode: 0o700,
            op: |r, w| r.call(w, |b| p::access(b"/d/f", 0, 0, b)).map(drop),
            expect: [ok, Err(ACCESS), Err(ACCESS), ok],
        },
        Row {
            name: "chmod",
            dir_mode: 0o755,
            op: |r, w| r.chmod(w, b"/d/f", 0o600),
            expect: [ok, Err(PERMISSION), Err(PERMISSION), ok],
        },
        Row {
            name: "chown the owner",
            dir_mode: 0o755,
            op: |r, w| r.chown(w, b"/d/f", 5, p::UID_KEEP),
            expect: [Err(PERMISSION), Err(PERMISSION), Err(PERMISSION), ok],
        },
        Row {
            name: "chown the group to the caller's own group",
            dir_mode: 0o755,
            op: |r, w| r.chown(w, b"/d/f", p::UID_KEEP, 100),
            expect: [ok, Err(PERMISSION), Err(PERMISSION), ok],
        },
        Row {
            name: "chown the group to a group the caller is not in",
            dir_mode: 0o755,
            op: |r, w| r.chown(w, b"/d/f", p::UID_KEEP, 999),
            expect: [Err(PERMISSION), Err(PERMISSION), Err(PERMISSION), ok],
        },
        Row {
            name: "utimensat with the present moment (file 0640)",
            dir_mode: 0o755,
            op: |r, w| {
                r.call(w, |b| {
                    p::utimens(b"/d/f", p::TimeSpec::Now, p::TimeSpec::Now, b)
                })
                .map(drop)
            },
            expect: [ok, Err(ACCESS), Err(ACCESS), ok],
        },
        Row {
            name: "utimensat with a time of the caller's choice",
            dir_mode: 0o755,
            op: |r, w| {
                r.call(w, |b| {
                    p::utimens(b"/d/f", p::TimeSpec::At(5), p::TimeSpec::At(6), b)
                })
                .map(drop)
            },
            expect: [ok, Err(PERMISSION), Err(PERMISSION), ok],
        },
        Row {
            name: "utimensat omitting both times",
            dir_mode: 0o755,
            op: |r, w| {
                r.call(w, |b| {
                    p::utimens(b"/d/f", p::TimeSpec::Omit, p::TimeSpec::Omit, b)
                })
                .map(drop)
            },
            expect: [ok, ok, ok, ok],
        },
        Row {
            name: "unlink in a directory 0755 (write on the parent)",
            dir_mode: 0o755,
            op: |r, w| {
                r.call(w, |b| p::path_call(p::Method::Unlink, b"/d/f", b))
                    .map(drop)
            },
            expect: [ok, Err(ACCESS), Err(ACCESS), ok],
        },
        Row {
            name: "unlink in a directory 0775",
            dir_mode: 0o775,
            op: |r, w| {
                r.call(w, |b| p::path_call(p::Method::Unlink, b"/d/f", b))
                    .map(drop)
            },
            expect: [ok, ok, Err(ACCESS), ok],
        },
        Row {
            name: "rmdir in a directory 0755",
            dir_mode: 0o755,
            op: |r, w| {
                r.call(w, |b| p::path_call(p::Method::Rmdir, b"/d/sub", b))
                    .map(drop)
            },
            expect: [ok, Err(ACCESS), Err(ACCESS), ok],
        },
        Row {
            name: "mkdir in a directory 0755",
            dir_mode: 0o755,
            op: |r, w| r.mkdir(w, b"/d/new", 0o755),
            expect: [ok, Err(ACCESS), Err(ACCESS), ok],
        },
        Row {
            name: "mkdir in a directory 0775",
            dir_mode: 0o775,
            op: |r, w| r.mkdir(w, b"/d/new", 0o755),
            expect: [ok, ok, Err(ACCESS), ok],
        },
        Row {
            name: "create a file in a directory 0755",
            dir_mode: 0o755,
            op: |r, w| r.open(w, b"/d/new", p::WRITE | p::CREATE, 0o644).map(drop),
            expect: [ok, Err(ACCESS), Err(ACCESS), ok],
        },
        Row {
            name: "create a file in a directory 0777",
            dir_mode: 0o777,
            op: |r, w| r.open(w, b"/d/new", p::WRITE | p::CREATE, 0o644).map(drop),
            expect: [ok, ok, ok, ok],
        },
        Row {
            name: "create a file in a directory with write and no search",
            dir_mode: 0o666,
            op: |r, w| r.open(w, b"/d/new", p::WRITE | p::CREATE, 0o644).map(drop),
            expect: [Err(ACCESS), Err(ACCESS), Err(ACCESS), ok],
        },
        Row {
            name: "rename within a directory 0755",
            dir_mode: 0o755,
            op: |r, w| r.call(w, |b| p::rename(b"/d/f", b"/d/g", b)).map(drop),
            expect: [ok, Err(ACCESS), Err(ACCESS), ok],
        },
        Row {
            name: "rename into the directory from another that the caller may not write",
            dir_mode: 0o777,
            op: |r, w| r.call(w, |b| p::rename(b"/d/f", b"/top/f", b)).map(drop),
            expect: [Err(ACCESS), Err(ACCESS), Err(ACCESS), ok],
        },
        Row {
            name: "rename a directory to another parent (write on the directory itself)",
            dir_mode: 0o777,
            op: |r, w| {
                r.call(w, |b| p::rename(b"/d/sub", b"/open/sub", b))
                    .map(drop)
            },
            expect: [ok, Err(ACCESS), Err(ACCESS), ok],
        },
        Row {
            name: "open a directory for search only",
            dir_mode: 0o751,
            op: |r, w| r.open(w, b"/d", p::DIRECTORY, 0).map(drop),
            expect: [ok, ok, ok, ok],
        },
        Row {
            name: "open a directory 0750 for search only",
            dir_mode: 0o750,
            op: |r, w| r.open(w, b"/d", p::DIRECTORY, 0).map(drop),
            expect: [ok, ok, Err(ACCESS), ok],
        },
        Row {
            name: "open a directory 0750 for reading",
            dir_mode: 0o750,
            op: |r, w| r.open(w, b"/d", p::DIRECTORY | p::READ, 0).map(drop),
            expect: [ok, ok, Err(ACCESS), ok],
        },
        Row {
            name: "open a directory 0711 for reading",
            dir_mode: 0o711,
            op: |r, w| r.open(w, b"/d", p::DIRECTORY | p::READ, 0).map(drop),
            expect: [ok, Err(ACCESS), Err(ACCESS), ok],
        },
    ]
}

#[test]
fn the_matrix_of_every_method_for_the_owner_a_member_of_the_group_another_user_and_the_superuser() {
    let who = [OWNER, GROUP, OTHER, ROOT];
    let names = ["owner", "group", "other", "root"];
    let mut cases = 0;
    for row in rows() {
        for i in 0..4 {
            let mut rig = Rig::new();
            rig.tree(row.dir_mode);
            // Two more places for the rows that move a name.
            rig.mkdir(ROOT, b"/top", 0o755).unwrap();
            rig.mkdir(ROOT, b"/open", 0o777).unwrap();
            let got = (row.op)(&mut rig, who[i]);
            assert_eq!(got, row.expect[i], "{} as {}", row.name, names[i]);
            cases += 1;
        }
    }
    assert!(cases >= 120, "{cases} cases");
}

#[test]
fn an_open_description_keeps_its_rights_after_chmod_000_and_chown() {
    let mut rig = Rig::new();
    rig.tree(0o755);
    let r = rig.open(OWNER, b"/d/f", p::READ | p::WRITE, 0).unwrap();
    rig.chmod(OWNER, b"/d/f", 0).unwrap();
    rig.chown(ROOT, b"/d/f", 77, 77).unwrap();
    // A new open is refused, the description reads and writes as before.
    assert_eq!(rig.open(OWNER, b"/d/f", p::READ, 0), Err(ACCESS));
    assert_eq!(rig.read(OWNER, r, 10).unwrap(), b"hello");
    assert_eq!(rig.write(OWNER, r, b"!").unwrap(), 1);
    // It passes by CLONE and by a pass with the rights it has, and an unbound child reads on.
    rig.clone_session(OWNER, 501, &[r]).unwrap();
    assert!(rig.read(501, r, 10).is_ok());
}

#[test]
fn a_description_opened_for_reading_does_not_write() {
    let mut rig = Rig::new();
    rig.tree(0o755);
    let r = rig.open(OWNER, b"/d/f", p::READ, 0).unwrap();
    assert_eq!(rig.write(OWNER, r, b"x"), Err(p::code(p::BAD_HANDLE)));
}

#[test]
fn fchmod_fchown_and_futimens_check_the_owner_at_the_time_of_the_call() {
    let mut rig = Rig::new();
    rig.tree(0o755);
    // The superuser opens the file; another user's session cannot hold it, so give the open to a
    // group member by opening it as the group (group read) and changing it.
    let g = rig.open(GROUP, b"/d/f", p::READ, 0).unwrap();
    assert_eq!(rig.call(GROUP, |w| p::fchmod(g, 0o777, w)), Err(PERMISSION));
    assert_eq!(rig.call(GROUP, |w| p::fchown(g, 1, 1, w)), Err(PERMISSION));
    assert_eq!(
        rig.call(GROUP, |w| p::futimens(
            g,
            p::TimeSpec::At(1),
            p::TimeSpec::At(2),
            w
        )),
        Err(PERMISSION)
    );
    // The owner's description works; the check is of the session's identity now.
    let o = rig.open(OWNER, b"/d/f", p::READ, 0).unwrap();
    rig.call(OWNER, |w| p::fchmod(o, 0o600, w)).unwrap();
    assert_eq!(rig.stat(ROOT, b"/d/f").unwrap().mode, 0o600);
    rig.call(OWNER, |w| p::fchown(o, p::UID_KEEP, 100, w))
        .unwrap();
    rig.call(OWNER, |w| {
        p::futimens(o, p::TimeSpec::At(9), p::TimeSpec::At(10), w)
    })
    .unwrap();
    let st = rig.stat(ROOT, b"/d/f").unwrap();
    assert_eq!((st.atime, st.mtime), (9, 10));
}

#[test]
fn a_sticky_directory_lets_the_owner_of_an_entry_or_of_the_directory_remove_it() {
    let mut rig = Rig::new();
    rig.mkdir(ROOT, b"/tmp", 0o1777).unwrap();
    rig.put(OWNER, b"/tmp/mine", 0o644, b"x");
    rig.put(OTHER, b"/tmp/theirs", 0o666, b"y");
    let unlink = |rig: &mut Rig, who, path: &[u8]| {
        rig.call(who, |w| p::path_call(p::Method::Unlink, path, w))
    };
    assert_eq!(unlink(&mut rig, OTHER, b"/tmp/mine"), Err(PERMISSION));
    assert_eq!(unlink(&mut rig, GROUP, b"/tmp/mine"), Err(PERMISSION));
    // Neither does a rename of the other's entry, nor over it.
    assert_eq!(
        rig.call(OTHER, |w| p::rename(b"/tmp/mine", b"/tmp/z", w)),
        Err(PERMISSION)
    );
    assert_eq!(
        rig.call(OTHER, |w| p::rename(b"/tmp/theirs", b"/tmp/mine", w)),
        Err(PERMISSION)
    );
    assert!(unlink(&mut rig, OWNER, b"/tmp/mine").is_ok());
    // The owner of the directory (root here) and user 0 may.
    assert!(unlink(&mut rig, ROOT, b"/tmp/theirs").is_ok());
}

#[test]
fn creation_takes_the_owner_the_group_and_the_set_group_bit_of_the_directory() {
    let mut rig = Rig::new();
    rig.mkdir(ROOT, b"/shared", 0o2775).unwrap();
    rig.chown(ROOT, b"/shared", 0, 300).unwrap();
    rig.chmod(ROOT, b"/shared", 0o2777).unwrap();
    // A file in a set-group directory belongs to the directory's group; a directory keeps the bit.
    rig.put(OWNER, b"/shared/f", 0o644, b"");
    rig.mkdir(OWNER, b"/shared/sub", 0o755).unwrap();
    let f = rig.stat(ROOT, b"/shared/f").unwrap();
    assert_eq!((f.uid, f.gid, f.mode), (1000, 300, 0o644));
    let d = rig.stat(ROOT, b"/shared/sub").unwrap();
    assert_eq!((d.uid, d.gid, d.mode), (1000, 300, 0o2755));
    // A file asked with the set-group bit in a group its creator is not in loses it.
    rig.put(OWNER, b"/shared/g", 0o2755, b"");
    assert_eq!(rig.stat(ROOT, b"/shared/g").unwrap().mode, 0o755);
    // Elsewhere the group is the creator's.
    rig.mkdir(ROOT, b"/plain", 0o777).unwrap();
    rig.put(OTHER, b"/plain/f", 0o600, b"");
    let f = rig.stat(ROOT, b"/plain/f").unwrap();
    assert_eq!((f.uid, f.gid), (2000, 200));
}

#[test]
fn chown_clears_the_set_id_bits_of_a_file_and_a_write_clears_them_too() {
    let mut rig = Rig::new();
    rig.mkdir(ROOT, b"/d", 0o777).unwrap();
    rig.put(OWNER, b"/d/f", 0o644, b"");
    // The owner is in the file's group (100): both bits stay.
    rig.chmod(OWNER, b"/d/f", 0o6755).unwrap();
    assert_eq!(rig.stat(OWNER, b"/d/f").unwrap().mode, 0o6755);
    // In a group the owner is not in, asking for the set-group bit loses it; the set-user bit stays.
    rig.chown(ROOT, b"/d/f", p::UID_KEEP, 300).unwrap();
    rig.chmod(OWNER, b"/d/f", 0o6755).unwrap();
    assert_eq!(rig.stat(OWNER, b"/d/f").unwrap().mode, 0o4755);
    rig.chown(ROOT, b"/d/f", p::UID_KEEP, 100).unwrap();
    rig.chmod(OWNER, b"/d/f", 0o6755).unwrap();
    assert_eq!(rig.stat(OWNER, b"/d/f").unwrap().mode, 0o6755);
    // A write clears both at the sync.
    let h = rig.open(OWNER, b"/d/f", p::WRITE, 0).unwrap();
    rig.write(OWNER, h, b"x").unwrap();
    rig.ok(OWNER, |w| p::handle_call(p::Method::Fsync, h, w));
    assert_eq!(rig.stat(OWNER, b"/d/f").unwrap().mode, 0o755);
    // A change of group by the owner clears them as well.
    rig.chmod(OWNER, b"/d/f", 0o6755).unwrap();
    rig.chown(OWNER, b"/d/f", p::UID_KEEP, 100).unwrap();
    assert_eq!(rig.stat(OWNER, b"/d/f").unwrap().mode, 0o755);
    // A directory keeps them.
    rig.mkdir(OWNER, b"/d/sub", 0o755).unwrap();
    rig.chmod(OWNER, b"/d/sub", 0o6755).unwrap();
    rig.chown(OWNER, b"/d/sub", p::UID_KEEP, 100).unwrap();
    assert_eq!(rig.stat(OWNER, b"/d/sub").unwrap().mode, 0o6755);
}

#[test]
fn access_checks_the_real_identifiers_or_the_effective_ones_and_searches_with_the_same() {
    let mut rig = Rig::new();
    rig.tree(0o700);
    // A process of user 1000 with the effective user 0 (a `setuid` program): effective passes, real
    // is the owner, who passes too; make the file the other user's to tell them apart.
    rig.chown(ROOT, b"/d", 2000, 200).unwrap();
    rig.chmod(ROOT, b"/d", 0o700).unwrap();
    let mut v = user(1000, 100, &[]);
    v.euid = 0;
    rig.bind(40, v);
    let acc = |rig: &mut Rig, flags| {
        rig.call(40, |w| p::access(b"/d/f", p::ACCESS_READ, flags, w))
            .map(drop)
    };
    assert_eq!(
        acc(&mut rig, p::ACCESS_REAL),
        Err(ACCESS),
        "real: user 1000 cannot search /d"
    );
    assert_eq!(acc(&mut rig, 0), Ok(()), "effective: user 0 can");
}

#[test]
fn a_session_with_no_binding_is_not_bound_except_for_what_it_holds() {
    let mut rig = Rig::new();
    rig.tree(0o755);
    let h = rig.open(OWNER, b"/d/f", p::READ | p::WRITE, 0).unwrap();
    // A clone starts with no binding.
    rig.clone_session(OWNER, 500, &[h]).unwrap();
    let not_bound = Some(p::code(p::NOT_BOUND));
    assert_eq!((rig.open(500, b"/d/f", p::READ, 0)).err(), not_bound);
    assert_eq!((rig.stat(500, b"/d/f").map(drop)).err(), not_bound);
    assert_eq!((rig.mkdir(500, b"/x", 0o755)).err(), not_bound);
    assert_eq!((rig.write(500, h, b"x")).err(), not_bound);
    assert_eq!((rig.call(500, |w| p::truncate(h, 0, w))).err(), not_bound);
    assert_eq!(
        (rig.call(500, |w| p::handle_call(p::Method::Fsync, h, w))).err(),
        not_bound
    );
    assert_eq!((rig.call(500, |w| p::fchmod(h, 0o600, w))).err(), not_bound);
    assert_eq!((rig.call(500, p::statfs)).err(), not_bound);
    // It reads, seeks, stats and closes what it holds.
    assert_eq!(rig.read(500, h, 10).unwrap(), b"hello");
    rig.ok(500, |w| p::handle_call(p::Method::Fstat, h, w));
    rig.ok(500, |w| p::seek(h, 0, p::SEEK_SET, w));
    rig.ok(500, |w| p::handle_call(p::Method::GetFlags, h, w));
    rig.ok(500, |w| p::handle_call(p::Method::Where, h, w));
    // BIND binds it; a bound session answers BIND with INVALID; a lapse unbinds it again.
    rig.server.bind(500, user(1000, 100, &[])).unwrap();
    assert!(rig.stat(500, b"/d/f").is_ok());
    assert_eq!(
        rig.server.bind(500, user(1000, 100, &[])),
        Err(p::code(p::INVALID))
    );
    rig.server.set_binding(500, Binding::Unbound);
    assert_eq!((rig.stat(500, b"/d/f").map(drop)).err(), not_bound);
    rig.server.bind(500, user(2000, 200, &[])).unwrap();
    assert_eq!(
        rig.open(500, b"/d/f", p::READ, 0),
        Err(ACCESS),
        "bound as another user"
    );
}

#[test]
fn a_new_session_is_bound_from_its_birth_and_the_channels_keep_to_their_methods() {
    let mut rig = Rig::new();
    rig.tree(0o755);
    // The root channel takes no session method; a session takes neither SESSION nor VERIFY_SESSION.
    assert_eq!(rig.call(p::ROOT, p::statfs), Err(p::code(p::IS_ROOT)));
    assert_eq!(
        rig.call(OWNER, |w| p::header_only(p::Method::Session, w)),
        Err(p::code(p::IS_ROOT))
    );
    assert_eq!(
        rig.call(OWNER, |w| p::header_only(p::Method::VerifySession, w)),
        Err(p::code(p::IS_ROOT))
    );
    // The worker makes a session bound at birth, and finds it live.
    assert!(!rig.server.is_live(77));
    rig.server.bind_new(77, user(1000, 100, &[])).unwrap();
    assert!(rig.server.is_live(77));
    assert!(rig.stat(77, b"/d/f").is_ok());
    assert_eq!(
        rig.server.bind_new(77, user(1000, 100, &[])),
        Err(p::code(p::INVALID))
    );
}

#[test]
fn files_have_numbers_that_differ_and_survive_a_rename_and_the_times_are_the_services() {
    let mut rig = Rig::new();
    rig.mkdir(ROOT, b"/d", 0o777).unwrap();
    rig.mkdir(ROOT, b"/e", 0o777).unwrap();
    rig.server.set_now(5_000);
    rig.put(OWNER, b"/d/a", 0o644, b"");
    rig.put(OWNER, b"/d/b", 0o644, b"");
    let a = rig.stat(OWNER, b"/d/a").unwrap();
    let b = rig.stat(OWNER, b"/d/b").unwrap();
    assert_ne!(a.ino, b.ino);
    assert_eq!((a.atime, a.mtime, a.ctime), (5_000, 5_000, 5_000));
    // The directory's times follow a change of its names.
    assert_eq!(rig.stat(OWNER, b"/d").unwrap().mtime, 5_000);
    rig.server.set_now(6_000);
    rig.call(OWNER, |w| p::rename(b"/d/a", b"/e/a2", w))
        .unwrap();
    let moved = rig.stat(OWNER, b"/e/a2").unwrap();
    assert_eq!(moved.ino, a.ino, "the number goes with the entry");
    assert_eq!(rig.stat(OWNER, b"/d").unwrap().mtime, 6_000);
    assert_eq!(rig.stat(OWNER, b"/e").unwrap().mtime, 6_000);
    // The number of a name made over another is the new file's, never reused for another entry.
    let numbers: Vec<u64> = [&b"/d/b"[..], b"/e/a2", b"/d", b"/e"]
        .iter()
        .map(|path| rig.stat(OWNER, path).unwrap().ino)
        .collect();
    let mut sorted = numbers.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), numbers.len(), "{numbers:?}");
    // A write sets mtime and ctime at the sync, a read sets nothing.
    rig.server.set_now(9_000);
    let h = rig.open(OWNER, b"/d/b", p::READ | p::WRITE, 0).unwrap();
    rig.write(OWNER, h, b"x").unwrap();
    rig.ok(OWNER, |w| p::handle_call(p::Method::Fsync, h, w));
    let st = rig.stat(OWNER, b"/d/b").unwrap();
    assert_eq!(
        (st.atime, st.mtime, st.ctime, st.size),
        (5_000, 9_000, 9_000, 1)
    );
    rig.server.set_now(10_000);
    rig.read(OWNER, h, 10).unwrap();
    assert_eq!(rig.stat(OWNER, b"/d/b").unwrap().atime, 5_000);
    // The last close writes the time of writes that were not synced.
    rig.server.set_now(11_000);
    rig.write(OWNER, h, b"y").unwrap();
    rig.close(OWNER, h);
    assert_eq!(rig.stat(OWNER, b"/d/b").unwrap().mtime, 11_000);
    // chmod and utimensat set ctime; the caller's times are kept.
    rig.server.set_now(12_000);
    rig.call(OWNER, |w| {
        p::utimens(b"/d/b", p::TimeSpec::At(3), p::TimeSpec::Omit, w)
    })
    .unwrap();
    let st = rig.stat(OWNER, b"/d/b").unwrap();
    assert_eq!((st.atime, st.mtime, st.ctime), (3, 11_000, 12_000));
}

#[test]
fn numbers_come_in_blocks_and_a_restart_skips_what_it_had_not_given_out() {
    let mut rig = Rig::new();
    rig.put(ROOT, b"/a", 0o644, b"");
    let first = rig.stat(ROOT, b"/a").unwrap().ino;
    assert!(
        first >= 2 && first >> 63 == 0,
        "from the counter (the top bit marks a number from a path): {first}"
    );
    // The counter at the root reads one block beyond the first number.
    let mut c = [0u8; 8];
    rig.fs
        .getattr(b"/", crate::attr::ATTR_COUNTER_TYPE, &mut c)
        .unwrap();
    assert_eq!(u64::from_le_bytes(c), 2 + crate::attr::INO_BLOCK);
    // A new instance over the volume starts after the reserved block.
    let device = {
        rig.fs.unmount().unwrap();
        rig.fs.into_device()
    };
    let mut again = Rig::on(device);
    again.put(ROOT, b"/b", 0o644, b"");
    let second = again.stat(ROOT, b"/b").unwrap().ino;
    assert!(
        second >= 2 + crate::attr::INO_BLOCK,
        "{second} after {first}"
    );
}

#[test]
fn a_native_client_has_no_file_size_limit_and_a_bound_one_stops_short_at_its_limit() {
    let mut rig = Rig::new();
    rig.mkdir(ROOT, b"/d", 0o777).unwrap();
    let mut limited = user(1000, 100, &[]);
    limited.fsize_limit = 1000;
    rig.bind(41, limited);
    let h = rig.open(41, b"/d/f", p::WRITE | p::CREATE, 0o644).unwrap();
    // 900 bytes fit; 900 more stop short at 1000 and the count says so.
    assert_eq!(rig.write(41, h, &[1u8; 900]).unwrap(), 900);
    assert_eq!(rig.write(41, h, &[1u8; 900]).unwrap(), 100);
    // At the limit nothing can be written: the status comes.
    assert_eq!(rig.write(41, h, b"x"), Err(p::code(p::FILE_SIZE_LIMIT)));
    assert_eq!(
        rig.call(41, |w| p::pwrite(h, 1000, b"x", w)),
        Err(p::code(p::FILE_SIZE_LIMIT))
    );
    // A write inside the limit still works, and so does a truncation down.
    assert_eq!(
        rig.call(41, |w| p::pwrite(h, 990, b"abcdefghij", w))
            .unwrap()[..4],
        [10, 0, 0, 0]
    );
    assert_eq!(
        rig.call(41, |w| p::truncate(h, 2000, w)),
        Err(p::code(p::FILE_SIZE_LIMIT))
    );
    rig.ok(41, |w| p::truncate(h, 10, w));
    // A native client writes what it likes up to FILE_MAX.
    let big = rig
        .open(ROOT, b"/d/big", p::WRITE | p::CREATE, 0o644)
        .unwrap();
    assert_eq!(rig.write(ROOT, big, &[2u8; 900]).unwrap(), 900);
    assert_eq!(
        rig.call(ROOT, |w| p::pwrite(big, p::FILE_MAX + 1, b"x", w)),
        Err(p::code(p::TOO_BIG))
    );
}

/// The files of a small volume are written as the superuser until fewer than `RESERVE_BLOCKS`
/// are free.
fn fill_to_the_reserve(rig: &mut Rig) {
    rig.mkdir(ROOT, b"/d", 0o777).unwrap();
    let chunk = [9u8; 900];
    let mut n = 0;
    while rig.fs.free_blocks().unwrap() >= crate::attr::RESERVE_BLOCKS + 8 {
        let path = std::format!("/d/fill{n}");
        let h = rig
            .open(ROOT, path.as_bytes(), p::WRITE | p::CREATE, 0o644)
            .unwrap();
        for _ in 0..16 {
            rig.write(ROOT, h, &chunk).unwrap();
        }
        rig.close(ROOT, h);
        n += 1;
    }
}

#[test]
fn below_the_reserve_only_the_superuser_writes_or_creates_and_unlink_passes() {
    let mut rig = Rig::new();
    rig.put(ROOT, b"/keep", 0o666, b"abc");
    fill_to_the_reserve(&mut rig);
    // One more file as the superuser takes the free blocks under the reserve.
    let more = rig
        .open(ROOT, b"/d/more", p::WRITE | p::CREATE, 0o666)
        .unwrap();
    while rig.fs.free_blocks().unwrap() >= crate::attr::RESERVE_BLOCKS {
        rig.write(ROOT, more, &[1u8; 900]).unwrap();
    }
    let free = rig.fs.free_blocks().unwrap();
    assert!(free < crate::attr::RESERVE_BLOCKS);
    // STATFS: `free` has the reserve, `avail` leaves it out.
    let s = rig.ok(OWNER, p::statfs);
    let (blocks, f, a) = (
        u64::from_le_bytes(s[0..8].try_into().unwrap()),
        u64::from_le_bytes(s[8..16].try_into().unwrap()),
        u64::from_le_bytes(s[16..24].try_into().unwrap()),
    );
    assert_eq!((blocks, f, a), (SECTORS / 8, free, 0));
    // Another user's create and write are NO_SPACE; the superuser writes into the reserve.
    assert_eq!(
        rig.open(OWNER, b"/d/new", p::WRITE | p::CREATE, 0o644),
        Err(p::code(p::NO_SPACE))
    );
    assert_eq!(
        rig.mkdir(OWNER, b"/d/dir", 0o755),
        Err(p::code(p::NO_SPACE))
    );
    let h = rig.open(OWNER, b"/keep", p::WRITE, 0).unwrap();
    assert_eq!(
        rig.call(OWNER, |w| p::pwrite(h, 100_000, b"x", w)),
        Err(p::code(p::NO_SPACE))
    );
    assert_eq!(rig.write(ROOT, more, &[2u8; 900]).unwrap(), 900);
    // Unlink and rmdir pass for everyone.
    assert!(
        rig.call(OWNER, |w| p::path_call(p::Method::Unlink, b"/d/fill0", w))
            .is_ok()
    );
}

#[test]
fn a_write_at_the_edge_of_the_room_stops_short_with_the_count() {
    let mut rig = Rig::new();
    rig.put(ROOT, b"/keep", 0o666, b"");
    fill_to_the_reserve(&mut rig);
    // The room of another user is what is above the reserve; a write of more stops short at it.
    let h = rig.open(OWNER, b"/keep", p::WRITE, 0).unwrap();
    let free = rig.fs.free_blocks().unwrap();
    let room = free.saturating_sub(crate::attr::RESERVE_BLOCKS) * crate::BLOCK as u64;
    let big = vec![7u8; p::MAX_WRITE];
    let want = (big.len() as u64).min(room);
    match rig.write(OWNER, h, &big) {
        Ok(n) => {
            assert!(want > 0, "written with no room");
            assert_eq!(
                u64::from(n),
                want,
                "stops short at the room: {free} free blocks"
            );
        }
        Err(e) => {
            assert_eq!(want, 0, "refused with room");
            assert_eq!(e, p::code(p::NO_SPACE));
        }
    }
    // A write that leaves no room at all is NO_SPACE with nothing written.
    let at = room + 100_000;
    assert_eq!(
        rig.call(OWNER, |w| p::pwrite(h, at, b"x", w)),
        Err(p::code(p::NO_SPACE))
    );
}

#[test]
fn a_directory_holds_a_bounded_number_of_entries() {
    let mut rig = Rig::new();
    rig.mkdir(ROOT, b"/d", 0o777).unwrap();
    rig.mkdir(ROOT, b"/e", 0o777).unwrap();
    for i in 0..server::DIR_ENTRIES_MAX {
        let path = std::format!("/d/n{i}");
        let h = rig
            .open(ROOT, path.as_bytes(), p::WRITE | p::CREATE, 0o644)
            .unwrap();
        rig.close(ROOT, h);
    }
    let full = Some(p::code(p::NO_SPACE));
    assert_eq!(
        (rig.open(ROOT, b"/d/extra", p::WRITE | p::CREATE, 0o644)).err(),
        full
    );
    assert_eq!((rig.mkdir(ROOT, b"/d/extra", 0o755)).err(), full);
    // A rename that adds a name to the full directory too; one that replaces a name does not.
    rig.put(ROOT, b"/e/x", 0o644, b"");
    assert_eq!(
        (rig.call(ROOT, |w| p::rename(b"/e/x", b"/d/x", w))).err(),
        full
    );
    assert!(rig.call(ROOT, |w| p::rename(b"/e/x", b"/d/n5", w)).is_ok());
    // A rename inside it adds none.
    assert!(
        rig.call(ROOT, |w| p::rename(b"/d/n6", b"/d/renamed", w))
            .is_ok()
    );
    // Removing one makes room for one.
    rig.call(ROOT, |w| p::path_call(p::Method::Unlink, b"/d/n7", w))
        .unwrap();
    assert!(
        rig.open(ROOT, b"/d/extra", p::WRITE | p::CREATE, 0o644)
            .is_ok()
    );
    assert_eq!(
        (rig.open(ROOT, b"/d/extra2", p::WRITE | p::CREATE, 0o644)).err(),
        full
    );
}

#[test]
fn a_directory_with_an_open_directory_description_below_it_is_busy_for_rename_and_rmdir() {
    let mut rig = Rig::new();
    rig.mkdir(ROOT, b"/a", 0o777).unwrap();
    rig.mkdir(ROOT, b"/a/b", 0o777).unwrap();
    rig.mkdir(ROOT, b"/a/b/c", 0o777).unwrap();
    let d = rig.open(ROOT, b"/a/b/c", p::DIRECTORY, 0).unwrap();
    let busy = Some(p::code(p::BUSY));
    assert_eq!(
        (rig.call(ROOT, |w| p::rename(b"/a", b"/z", w)).map(drop)).err(),
        busy
    );
    assert_eq!(
        (rig.call(ROOT, |w| p::rename(b"/a/b", b"/a/y", w)).map(drop)).err(),
        busy
    );
    assert_eq!(
        (rig.call(ROOT, |w| p::path_call(p::Method::Rmdir, b"/a/b/c", w))
            .map(drop))
        .err(),
        busy
    );
    rig.close(ROOT, d);
    assert!(rig.call(ROOT, |w| p::rename(b"/a", b"/z", w)).is_ok());
}

#[test]
fn readdir_gives_numbers_that_stat_gives_in_batches_and_rewinds() {
    let mut rig = Rig::new();
    rig.mkdir(ROOT, b"/d", 0o755).unwrap();
    for i in 0..300 {
        let path = std::format!("/d/{i:0200}");
        rig.put(ROOT, path.as_bytes(), 0o644, b"");
    }
    let dir = rig.open(ROOT, b"/d", p::DIRECTORY | p::READ, 0).unwrap();
    let (mut seen, mut batches) = (Vec::new(), 0);
    loop {
        let e = rig.ok(ROOT, |w| p::handle_call(p::Method::Readdir, dir, w));
        let mut batch = p::read_dir_reply(Reader::new(&e)).unwrap();
        batches += 1;
        let mut count = 0;
        while let Some(entry) = batch.next_entry().unwrap() {
            seen.push((entry.name.to_vec(), entry.ino, entry.kind));
            count += 1;
        }
        assert!(count >= 1 || !batch.more);
        if !batch.more {
            break;
        }
    }
    assert!(batches > 1, "300 names of 200 bytes do not fit one reply");
    assert_eq!(seen.len(), 302);
    assert_eq!(
        (seen[0].0.as_slice(), seen[1].0.as_slice()),
        (&b"."[..], &b".."[..])
    );
    // `.` is the directory itself, `..` the root; each name's number is the stat's.
    let dot = rig.stat(ROOT, b"/d").unwrap().ino;
    assert_eq!(seen[0].1, dot);
    assert_eq!(seen[1].1, rig.stat(ROOT, b"/").unwrap().ino);
    for (name, ino, kind) in &seen[2..] {
        let mut path = b"/d/".to_vec();
        path.extend_from_slice(name);
        assert_eq!(
            (*ino, *kind),
            (rig.stat(ROOT, &path).unwrap().ino, p::KIND_FILE)
        );
    }
    // The end, then REWIND from the start; the hidden directory is not there.
    let end = rig.ok(ROOT, |w| p::handle_call(p::Method::Readdir, dir, w));
    assert_eq!(end, [0, 0, 0, 0]);
    rig.ok(ROOT, |w| p::handle_call(p::Method::Rewind, dir, w));
    let again = rig.ok(ROOT, |w| p::handle_call(p::Method::Readdir, dir, w));
    assert_eq!(
        p::read_dir_reply(Reader::new(&again))
            .unwrap()
            .next_entry()
            .unwrap()
            .unwrap()
            .name,
        b"."
    );
    let names = rig.names(ROOT, b"/").unwrap();
    assert!(!names.iter().any(|n| n == ".orphans"));
    // A description with no access bits has no listing.
    let search = rig.open(ROOT, b"/d", p::DIRECTORY, 0).unwrap();
    assert_eq!(
        rig.call(ROOT, |w| p::handle_call(p::Method::Readdir, search, w)),
        Err(p::code(p::BAD_HANDLE))
    );
    assert_eq!(
        rig.call(ROOT, |w| p::read(search, 1, w)),
        Err(p::code(p::BAD_HANDLE))
    );
}

#[test]
fn where_tells_the_path_of_a_description_and_no_entry_for_an_unlinked_file() {
    let mut rig = Rig::new();
    rig.mkdir(ROOT, b"/d", 0o755).unwrap();
    rig.put(ROOT, b"/d/f", 0o644, b"x");
    let h = rig.open(ROOT, b"/d/f", p::READ, 0).unwrap();
    assert_eq!(
        rig.ok(ROOT, |w| p::handle_call(p::Method::Where, h, w)),
        b"/d/f"
    );
    let d = rig.open(ROOT, b"/d", p::DIRECTORY, 0).unwrap();
    assert_eq!(
        rig.ok(ROOT, |w| p::handle_call(p::Method::Where, d, w)),
        b"/d"
    );
    rig.call(ROOT, |w| p::path_call(p::Method::Unlink, b"/d/f", w))
        .unwrap();
    assert_eq!(
        rig.call(ROOT, |w| p::handle_call(p::Method::Where, h, w)),
        Err(p::code(p::NO_ENTRY))
    );
    // FSTAT says the link count is 0.
    let st = rig.ok(ROOT, |w| p::handle_call(p::Method::Fstat, h, w));
    assert_eq!(p::Stat::from_bytes(&st).unwrap().nlink, 0);
}

#[test]
fn a_volume_of_version_2_gets_its_attributes_at_the_first_mount_and_the_mark_then() {
    // The volume as the 0.5 service left it: /ssh and /ssh/host_key with no attribute.
    let mut state = Storage::new();
    let mut fs = Fs::new(MemDevice::new(SECTORS), &mut state).unwrap();
    fs.format().unwrap();
    fs.mount().unwrap();
    fs.mkdir(b"/ssh").unwrap();
    let f = fs
        .open(b"/ssh/host_key", Open::WRITE.with(Open::CREATE))
        .unwrap();
    fs.write(f, b"secret key").unwrap();
    fs.close(f).unwrap();
    let device = {
        fs.unmount().unwrap();
        fs.into_device()
    };
    let mut rig = Rig::on(device);
    let key = rig.stat(ROOT, b"/ssh/host_key").unwrap();
    let ssh = rig.stat(ROOT, b"/ssh").unwrap();
    let root = rig.stat(ROOT, b"/").unwrap();
    assert_eq!((key.mode, key.uid, key.gid, key.size), (0o600, 0, 0, 10));
    assert_eq!((ssh.mode, ssh.uid, ssh.gid), (0o700, 0, 0));
    assert_eq!((root.mode, root.uid, root.gid), (0o755, 0, 0));
    assert!(key.ino >> 63 == 0 && ssh.ino >> 63 == 0, "from the counter");
    let mut mark = [0u8; 4];
    assert_eq!(
        rig.fs.getattr(b"/", ATTR_FORMAT_TYPE, &mut mark).unwrap(),
        4
    );
    assert_eq!(u32::from_le_bytes(mark), crate::attr::VOLUME_FORMAT);
    let hidden = rig
        .fs
        .getattr(b"/.orphans", ATTR_TYPE, &mut [0u8; 64])
        .unwrap();
    assert_eq!(hidden, 48);
    // The key stays closed to everyone but user 0.
    assert_eq!(rig.open(OWNER, b"/ssh/host_key", p::READ, 0), Err(ACCESS));
    assert_eq!(rig.open(OTHER, b"/ssh/host_key", p::READ, 0), Err(ACCESS));
    let h = rig.open(ROOT, b"/ssh/host_key", p::READ, 0).unwrap();
    assert_eq!(rig.read(ROOT, h, 100).unwrap(), b"secret key");
    // The second mount does no walk.
    let again = rig.server.mount_work(&mut rig.fs).unwrap();
    assert_eq!((again.converted, again.complete), (0, true));
}

#[test]
fn a_volume_whose_format_is_above_this_one_is_refused_and_left_alone() {
    let mut state = Storage::new();
    let mut fs = Fs::new(MemDevice::new(SECTORS), &mut state).unwrap();
    fs.format().unwrap();
    fs.mount().unwrap();
    fs.mkdir(b"/x").unwrap();
    fs.setattr(b"/", ATTR_FORMAT_TYPE, &4u32.to_le_bytes())
        .unwrap();
    let before = fs.device().medium().to_vec();
    let mut server = Server::new();
    let mounted = server.mount_work(&mut fs).unwrap();
    assert!(mounted.refused && !mounted.complete);
    // Every request answers NOT_READY, and nothing was written.
    let mut w = Writer::new();
    p::statfs(&mut w).unwrap();
    let reply = server.handle(&mut fs, ROOT, 0, w.as_bytes());
    assert_eq!(
        p::reply(reply.as_bytes()).map(drop),
        Err(p::code(p::NOT_READY))
    );
    fs.device().flush().unwrap();
    assert_eq!(fs.device().medium(), &before[..]);
    // The mark is read as it is: a word of another length is above too.
    fs.setattr(b"/", ATTR_FORMAT_TYPE, &[1, 0]).unwrap();
    assert!(Server::new().mount_work(&mut fs).unwrap().refused);
}

#[test]
fn an_attribute_of_a_format_this_service_does_not_know_is_never_rewritten() {
    let mut rig = Rig::new();
    rig.mkdir(ROOT, b"/d", 0o777).unwrap();
    rig.put(OWNER, b"/d/f", 0o644, b"hi");
    let mut foreign = Attr {
        uid: 1000,
        gid: 100,
        mode: 0o644,
        ino: 5,
        atime: 1,
        mtime: 2,
        ctime: 3,
    }
    .to_bytes();
    foreign[12] = 9;
    rig.fs.setattr(b"/d/f", ATTR_TYPE, &foreign).unwrap();
    // It reads as the default (0600, user 0), and every request that would write it is CORRUPT.
    let st = rig.stat(ROOT, b"/d/f").unwrap();
    assert_eq!((st.mode, st.uid), (0o600, 0));
    let corrupt = Some(p::code(p::CORRUPT));
    assert_eq!((rig.chmod(ROOT, b"/d/f", 0o644)).err(), corrupt);
    assert_eq!((rig.chown(ROOT, b"/d/f", 5, 5)).err(), corrupt);
    assert_eq!(
        (rig.call(ROOT, |w| p::utimens(
            b"/d/f",
            p::TimeSpec::At(1),
            p::TimeSpec::At(1),
            w
        )))
        .err(),
        corrupt
    );
    let h = rig.open(ROOT, b"/d/f", p::READ | p::WRITE, 0).unwrap();
    rig.write(ROOT, h, b"x").unwrap();
    assert_eq!(
        (rig.call(ROOT, |w| p::handle_call(p::Method::Fsync, h, w))).err(),
        corrupt
    );
    // The bytes on the volume are what they were.
    let mut now = [0u8; 64];
    let n = rig.fs.getattr(b"/d/f", ATTR_TYPE, &mut now).unwrap();
    assert_eq!(&now[..n], &foreign[..]);
}

#[test]
fn chmod_of_a_directory_closes_the_path_at_once_though_its_attributes_were_remembered() {
    let mut rig = Rig::new();
    rig.tree(0o755);
    // The group member's stat remembers /d with search for everyone.
    assert!(rig.stat(GROUP, b"/d/f").is_ok());
    rig.chmod(ROOT, b"/d", 0o700).unwrap();
    assert_eq!(rig.stat(GROUP, b"/d/f").map(drop), Err(ACCESS));
    // And a change of owner of a directory reaches the next path too.
    rig.chmod(ROOT, b"/d", 0o750).unwrap();
    assert!(rig.stat(GROUP, b"/d/f").is_ok());
    rig.chown(ROOT, b"/d", 0, 200).unwrap();
    assert_eq!(rig.stat(GROUP, b"/d/f").map(drop), Err(ACCESS));
    // A rename of a directory forgets what was remembered under its old name.
    rig.chmod(ROOT, b"/d", 0o755).unwrap();
    rig.mkdir(ROOT, b"/d/inner", 0o700).unwrap();
    rig.put(ROOT, b"/d/inner/x", 0o644, b"");
    assert_eq!(rig.stat(GROUP, b"/d/inner/x").map(drop), Err(ACCESS));
    rig.call(ROOT, |w| p::rename(b"/d/inner", b"/d/moved", w))
        .unwrap();
    assert_eq!(
        rig.stat(GROUP, b"/d/inner/x").map(drop),
        Err(p::code(p::NO_ENTRY))
    );
    assert_eq!(rig.stat(GROUP, b"/d/moved/x").map(drop), Err(ACCESS));
}

/// The device calls the jobs of the version-3 server make, counted on the host (reads, programs,
/// erases, flushes). Run by name: `cargo test -p datafs --lib tests_perm::costs -- --ignored
/// --nocapture`. The time is derived at the assumed rate of 10,000 reads a second, 100 us a program
/// and 1 ms a flush (assumptions).
#[test]
#[ignore = "prints a table; run by name"]
fn costs_of_the_common_jobs() {
    fn counts(rig: &mut Rig) -> (u64, u64, u64, u64) {
        let erases = rig.fs.erases();
        let d = rig.fs.device();
        (d.reads, d.programs, erases, d.flushes)
    }
    fn row(name: &str, rig: &mut Rig, job: &mut dyn FnMut(&mut Rig)) {
        let a = counts(rig);
        job(rig);
        let b = counts(rig);
        let (r, p, e, f) = (b.0 - a.0, b.1 - a.1, b.2 - a.2, b.3 - a.3);
        let ms = (r as f64 * 0.1) + (p as f64 * 0.1) + f as f64;
        std::println!("| {name} | {r} | {p} | {e} | {f} | {ms:.1} |");
    }
    let mut rig = Rig::on(MemDevice::new(32768));
    rig.mkdir(ROOT, b"/a", 0o777).unwrap();
    let mut deep = String::from("/a");
    for d in ["b", "c", "d", "e", "f", "g", "h"] {
        deep.push('/');
        deep.push_str(d);
        rig.mkdir(ROOT, deep.as_bytes(), 0o777).unwrap();
    }
    let deep_file = std::format!("{deep}/x");
    rig.put(OWNER, deep_file.as_bytes(), 0o644, b"x");
    rig.put(OWNER, b"/a/f", 0o644, b"x");
    rig.mkdir(ROOT, b"/big100", 0o755).unwrap();
    rig.mkdir(ROOT, b"/big1000", 0o755).unwrap();
    for i in 0..1000 {
        if i < 100 {
            rig.put(ROOT, std::format!("/big100/e{i:04}").as_bytes(), 0o644, b"");
        }
        rig.put(
            ROOT,
            std::format!("/big1000/e{i:04}").as_bytes(),
            0o644,
            b"",
        );
    }
    // A new instance: nothing remembered, the volume mounted cold.
    rig.fs.unmount().unwrap();
    let device = rig.fs.into_device();
    let mut rig = Rig::on(device);
    // The first walk of the volume is made (the service makes it in the idle after READY).
    rig.fs.walk().unwrap();
    std::println!("\n| job (user 1000) | reads | programs | erases | flushes | derived ms |");
    std::println!("|---|---:|---:|---:|---:|---:|");
    let stat = |rig: &mut Rig, path: &[u8]| {
        rig.stat(OWNER, path).unwrap();
    };
    row("stat depth 2, first", &mut rig, &mut |r| stat(r, b"/a/f"));
    row("stat depth 2, again", &mut rig, &mut |r| stat(r, b"/a/f"));
    row("stat depth 9, first", &mut rig, &mut |r| {
        stat(r, deep_file.as_bytes())
    });
    row("stat depth 9, again", &mut rig, &mut |r| {
        stat(r, deep_file.as_bytes())
    });
    row(
        "open + close an existing file, depth 2",
        &mut rig,
        &mut |r| {
            let h = r.open(OWNER, b"/a/f", p::READ, 0).unwrap();
            r.close(OWNER, h);
        },
    );
    row(
        "create a file with its attribute (open + close)",
        &mut rig,
        &mut |r| {
            let h = r
                .open(OWNER, b"/a/new1", p::WRITE | p::CREATE, 0o644)
                .unwrap();
            r.close(OWNER, h);
        },
    );
    row("create with 1 KiB written and synced", &mut rig, &mut |r| {
        let h = r
            .open(OWNER, b"/a/new2", p::WRITE | p::CREATE, 0o644)
            .unwrap();
        r.write(OWNER, h, &[1u8; 900]).unwrap();
        r.ok(OWNER, |w| p::handle_call(p::Method::Fsync, h, w));
        r.close(OWNER, h);
    });
    row("mkdir with its attribute", &mut rig, &mut |r| {
        r.mkdir(OWNER, b"/a/dir1", 0o755).unwrap()
    });
    row("stat /a/f (before the chmod)", &mut rig, &mut |r| {
        r.stat(OWNER, b"/a/f").unwrap();
    });
    row("chmod", &mut rig, &mut |r| {
        r.chmod(OWNER, b"/a/f", 0o600).unwrap()
    });
    row("chmod again", &mut rig, &mut |r| {
        r.chmod(OWNER, b"/a/f", 0o640).unwrap()
    });
    row("unlink", &mut rig, &mut |r| {
        r.call(OWNER, |w| p::path_call(p::Method::Unlink, b"/a/new1", w))
            .unwrap();
    });
    row("rename in a directory", &mut rig, &mut |r| {
        r.call(OWNER, |w| p::rename(b"/a/new2", b"/a/new3", w))
            .unwrap();
    });
    row("statfs", &mut rig, &mut |r| {
        r.ok(OWNER, p::statfs);
    });
    row(
        "readdir of a directory of 100 entries (all batches)",
        &mut rig,
        &mut |r| {
            r.names(ROOT, b"/big100").unwrap();
        },
    );
    row(
        "readdir of a directory of 1000 entries (all batches)",
        &mut rig,
        &mut |r| {
            r.names(ROOT, b"/big1000").unwrap();
        },
    );
    row(
        "create in a directory of 1000 entries (count scan, first)",
        &mut rig,
        &mut |r| {
            r.put(ROOT, b"/big1000/extra", 0o644, b"");
        },
    );
    row(
        "create in it again (count remembered)",
        &mut rig,
        &mut |r| {
            r.put(ROOT, b"/big1000/extra2", 0o644, b"");
        },
    );
}

/// A commit that compacts a metadata pair (one erase) costs 8 reads, or about the number of metadata
/// pairs of the volume every second time: `lfs_dir_commit` looks for the predecessor of the pair it
/// moved (`lfs_fs_pred`, lfs.c). Prints the cost of the first six.
#[test]
#[ignore = "prints numbers; run by name"]
fn a_commit_that_compacts_a_metadata_pair_reads_the_whole_list_of_pairs_every_second_time() {
    let mut rig = Rig::on(MemDevice::new(32768));
    rig.mkdir(ROOT, b"/big", 0o777).unwrap();
    for i in 0..600 {
        rig.put(ROOT, std::format!("/big/e{i:04}").as_bytes(), 0o644, b"");
    }
    rig.mkdir(ROOT, b"/a", 0o777).unwrap();
    rig.put(OWNER, b"/a/f", 0o644, b"x");
    let mut seen = 0;
    for n in 0..200u32 {
        let (r0, e0, p0) = (
            rig.fs.device().reads,
            rig.fs.erases(),
            rig.fs.device().programs,
        );
        rig.fs.setattr(b"/a/f", ATTR_TYPE, &[n as u8; 48]).unwrap();
        let (r1, e1, p1) = (
            rig.fs.device().reads,
            rig.fs.erases(),
            rig.fs.device().programs,
        );
        if e1 > e0 && seen < 6 {
            std::println!(
                "setattr {n}: {} reads, {} programs, {} erases",
                r1 - r0,
                p1 - p0,
                e1 - e0
            );
            seen += 1;
        }
    }
}

#[test]
fn stat_and_fstat_show_the_time_of_a_write_that_is_not_synced() {
    let mut rig = Rig::new();
    rig.mkdir(ROOT, b"/d", 0o777).unwrap();
    rig.server.set_now(5_000);
    rig.put(OWNER, b"/d/f", 0o4755, b"");
    rig.server.set_now(9_000);
    let h = rig.open(OWNER, b"/d/f", p::READ | p::WRITE, 0).unwrap();
    rig.write(OWNER, h, b"x").unwrap();
    let by_path = rig.stat(OWNER, b"/d/f").unwrap();
    assert_eq!(
        (by_path.mtime, by_path.ctime, by_path.size),
        (9_000, 9_000, 1)
    );
    assert_eq!(
        by_path.mode & 0o7000,
        0,
        "the set-ID bits go with the write"
    );
    let by_handle =
        p::Stat::from_bytes(&rig.ok(OWNER, |w| p::handle_call(p::Method::Fstat, h, w))).unwrap();
    assert_eq!((by_handle.mtime, by_handle.ctime), (9_000, 9_000));
    assert_eq!(by_handle.mode, by_path.mode);
    // Another session sees it too: the file is one.
    assert_eq!(rig.stat(ROOT, b"/d/f").unwrap().mtime, 9_000);
    // The time of a later write replaces it; the time of creation is kept as atime.
    rig.server.set_now(9_500);
    rig.write(OWNER, h, b"y").unwrap();
    let st = rig.stat(OWNER, b"/d/f").unwrap();
    assert_eq!((st.atime, st.mtime), (5_000, 9_500));
}

#[test]
fn futimens_and_fchmod_after_a_write_survive_the_last_close() {
    let mut rig = Rig::new();
    rig.mkdir(ROOT, b"/d", 0o777).unwrap();
    rig.server.set_now(5_000);
    rig.put(OWNER, b"/d/f", 0o644, b"");
    rig.server.set_now(9_000);
    let h = rig.open(OWNER, b"/d/f", p::READ | p::WRITE, 0).unwrap();
    rig.write(OWNER, h, b"x").unwrap();
    // cp -p: the times are set by description before the close.
    rig.call(OWNER, |w| {
        p::futimens(h, p::TimeSpec::At(42), p::TimeSpec::At(43), w)
    })
    .unwrap();
    rig.server.set_now(9_900);
    rig.close(OWNER, h);
    let st = rig.stat(OWNER, b"/d/f").unwrap();
    assert_eq!((st.atime, st.mtime), (42, 43), "the explicit times stand");
    assert_eq!(st.size, 1);
    // install: the set-user bit asked for after the write stays.
    let h = rig.open(OWNER, b"/d/f", p::READ | p::WRITE, 0).unwrap();
    rig.write(OWNER, h, b"y").unwrap();
    rig.call(OWNER, |w| p::fchmod(h, 0o4755, w)).unwrap();
    rig.close(OWNER, h);
    assert_eq!(rig.stat(OWNER, b"/d/f").unwrap().mode, 0o4755);
    // CHOWN by path folds the pending write in the same way, and a write after it is a new one.
    let h = rig.open(OWNER, b"/d/f", p::READ | p::WRITE, 0).unwrap();
    rig.server.set_now(11_000);
    rig.write(OWNER, h, b"z").unwrap();
    rig.chown(ROOT, b"/d/f", p::UID_KEEP, 100).unwrap();
    rig.close(OWNER, h);
    let st = rig.stat(OWNER, b"/d/f").unwrap();
    assert_eq!(st.mtime, 11_000);
    assert_eq!(
        st.mode & 0o6000,
        0,
        "the write and the chown cleared the set-ID bits"
    );
}

/// `/d` with `DIR_ENTRIES_MAX` entries: a directory `/d/sub` and files.
fn full_directory(rig: &mut Rig) {
    rig.mkdir(ROOT, b"/d", 0o777).unwrap();
    rig.mkdir(ROOT, b"/d/sub", 0o777).unwrap();
    for i in 1..server::DIR_ENTRIES_MAX {
        let path = std::format!("/d/n{i}");
        let h = rig
            .open(ROOT, path.as_bytes(), p::WRITE | p::CREATE, 0o644)
            .unwrap();
        rig.close(ROOT, h);
    }
}

#[test]
fn a_rename_of_a_directory_to_itself_does_nothing_and_opens_no_room() {
    let mut rig = Rig::new();
    full_directory(&mut rig);
    let before = rig.stat(ROOT, b"/d").unwrap();
    rig.server.set_now(77_000);
    for _ in 0..10 {
        rig.call(ROOT, |w| p::rename(b"/d/sub", b"/d/sub", w))
            .unwrap();
    }
    // The directory's time did not move, and ten creates past the cap are all refused.
    assert_eq!(rig.stat(ROOT, b"/d").unwrap().mtime, before.mtime);
    for i in 0..10 {
        let path = std::format!("/d/extra{i}");
        assert_eq!(
            rig.open(ROOT, path.as_bytes(), p::WRITE | p::CREATE, 0o644),
            Err(p::code(p::NO_SPACE))
        );
    }
}

#[test]
fn the_cap_holds_when_every_directory_place_is_held_and_after_a_create_with_truncate() {
    let mut rig = Rig::new();
    full_directory(&mut rig);
    rig.fs.unmount().unwrap();
    let device = rig.fs.into_device();
    // A new instance: no count is remembered. Sixteen descriptions of directories hold every place.
    let mut rig = Rig::on(device);
    let held: Vec<u32> = (0..crate::DIRS)
        .map(|_| rig.open(OTHER, b"/", p::READ | p::DIRECTORY, 0).unwrap())
        .collect();
    let refused = rig.open(ROOT, b"/d/extra", p::WRITE | p::CREATE, 0o644);
    assert_eq!(
        refused,
        Err(p::code(p::TABLE_FULL)),
        "not let through unchecked"
    );
    for h in held {
        rig.close(OTHER, h);
    }
    assert_eq!(
        rig.open(ROOT, b"/d/extra", p::WRITE | p::CREATE, 0o644),
        Err(p::code(p::NO_SPACE))
    );
    // A create that also truncates counts at once: the next one is refused.
    rig.call(ROOT, |w| p::path_call(p::Method::Unlink, b"/d/n5", w))
        .unwrap();
    let h = rig
        .open(ROOT, b"/d/again", p::WRITE | p::CREATE | p::TRUNCATE, 0o644)
        .unwrap();
    assert_eq!(
        rig.open(ROOT, b"/d/again2", p::WRITE | p::CREATE, 0o644),
        Err(p::code(p::NO_SPACE))
    );
    rig.close(ROOT, h);
}

#[test]
fn one_root_has_one_count_for_its_clones_and_its_sessions() {
    let mut rig = Rig::new();
    rig.mkdir(ROOT, b"/d", 0o777).unwrap();
    // A process tree asks SESSION as many times as a root may have sessions.
    let mine = user(5000, 500, &[]);
    for label in 0..server::ROOT_CLONES as u64 {
        rig.server.bind_new(1000 + label, mine).unwrap();
    }
    assert_eq!(
        rig.server.bind_new(2000, mine),
        Err(p::code(p::TOO_MANY_OPEN)),
        "the 33rd session of the root"
    );
    // CLONE from one of them sees the same count: it is refused, though it made no clone before.
    let h = rig.open(1000, b"/d", p::DIRECTORY, 0).unwrap();
    assert_eq!(
        rig.clone_session(1000, 3000, &[h]),
        Err(p::code(p::TOO_MANY_OPEN))
    );
    // Another root gets its session and its clone, and the table is not full for it.
    let other = user(6000, 600, &[]);
    rig.server.bind_new(4000, other).unwrap();
    let g = rig.open(4000, b"/d", p::DIRECTORY, 0).unwrap();
    rig.clone_session(4000, 4001, &[g]).unwrap();
    // The number of a root of init's and the number of an expenditure root do not meet: a client
    // of init whose label equals the number of the expenditure root has its own count.
    let root_number = mine.root;
    rig.bind(root_number, user(3000, 300, &[]));
    let k = rig.open(root_number, b"/d", p::DIRECTORY, 0).unwrap();
    rig.clone_session(root_number, 5000, &[k]).unwrap();
}

#[test]
fn in_the_reserve_rename_and_attribute_changes_are_the_superusers_and_rmdir_passes() {
    let mut rig = Rig::new();
    rig.put(ROOT, b"/keep", 0o666, b"abc");
    rig.mkdir(ROOT, b"/pub", 0o777).unwrap();
    rig.mkdir(ROOT, b"/pub/emptied", 0o777).unwrap();
    rig.put(OWNER, b"/pub/mine", 0o644, b"x");
    fill_to_the_reserve(&mut rig);
    let more = rig
        .open(ROOT, b"/d/more", p::WRITE | p::CREATE, 0o666)
        .unwrap();
    while rig.fs.free_blocks().unwrap() >= crate::attr::RESERVE_BLOCKS {
        rig.write(ROOT, more, &[1u8; 900]).unwrap();
    }
    let full = Some(p::code(p::NO_SPACE));
    // Another user's chmod, chown of the group, utimensat and rename are refused for space.
    assert_eq!(rig.chmod(OWNER, b"/pub/mine", 0o600).err(), full);
    assert_eq!(rig.chown(OWNER, b"/pub/mine", p::UID_KEEP, 100).err(), full);
    assert_eq!(
        rig.call(OWNER, |w| p::utimens(
            b"/pub/mine",
            p::TimeSpec::Now,
            p::TimeSpec::Now,
            w
        ))
        .err(),
        full
    );
    assert_eq!(
        rig.call(OWNER, |w| p::rename(b"/pub/mine", b"/pub/mine2", w))
            .err(),
        full
    );
    // The same by description.
    let h = rig.open(OWNER, b"/pub/mine", p::READ, 0).unwrap();
    assert_eq!(rig.call(OWNER, |w| p::fchmod(h, 0o600, w)).err(), full);
    // A refusal for lack of right still comes first: a stranger gets EPERM before any look at the room.
    assert_eq!(
        rig.chmod(OTHER, b"/pub/mine", 0o600).err(),
        Some(PERMISSION)
    );
    // The superuser does all of them into the reserve, MKDIR included.
    rig.chmod(ROOT, b"/pub/mine", 0o600).unwrap();
    rig.chown(ROOT, b"/pub/mine", 1000, 100).unwrap();
    rig.call(ROOT, |w| p::rename(b"/pub/mine", b"/pub/mine2", w))
        .unwrap();
    rig.mkdir(ROOT, b"/made-in-the-reserve", 0o755).unwrap();
    // RMDIR and UNLINK pass for everyone on a volume with no room.
    assert!(
        rig.call(OWNER, |w| p::path_call(p::Method::Unlink, b"/pub/mine2", w))
            .is_ok()
    );
    rig.chmod(ROOT, b"/pub/emptied", 0o777).unwrap();
    assert!(
        rig.call(OWNER, |w| p::path_call(
            p::Method::Rmdir,
            b"/pub/emptied",
            w
        ))
        .is_ok()
    );
}

#[test]
fn small_rules_of_open_truncate_rename_and_bind() {
    let mut rig = Rig::new();
    rig.mkdir(ROOT, b"/d", 0o777).unwrap();
    // O_CREAT|O_EXCL on an existing directory is EEXIST.
    assert_eq!(
        rig.open(ROOT, b"/d", p::WRITE | p::CREATE | p::EXCLUSIVE, 0o644),
        Err(p::code(p::EXISTS))
    );
    // A file larger than the limit may be made smaller; growing past it is refused.
    let mut limited = user(1000, 100, &[]);
    limited.fsize_limit = 1000;
    rig.bind(60, limited);
    let h = rig
        .open(ROOT, b"/d/big", p::WRITE | p::CREATE, 0o666)
        .unwrap();
    for _ in 0..3 {
        rig.write(ROOT, h, &[1u8; 900]).unwrap();
    }
    rig.close(ROOT, h);
    let h = rig.open(60, b"/d/big", p::WRITE, 0).unwrap();
    rig.ok(60, |w| p::truncate(h, 1500, w));
    assert_eq!(
        rig.call(60, |w| p::truncate(h, 1600, w)),
        Err(p::code(p::FILE_SIZE_LIMIT))
    );
    // A file renamed into a path under itself finds a part of the path that is no directory.
    rig.put(ROOT, b"/d/file", 0o644, b"x");
    assert_eq!(
        rig.call(ROOT, |w| p::rename(b"/d/file", b"/d/file/inner", w))
            .err(),
        Some(p::code(p::NOT_DIRECTORY))
    );
    // A directory into its own subtree is INVALID.
    rig.mkdir(ROOT, b"/d/a", 0o777).unwrap();
    assert_eq!(
        rig.call(ROOT, |w| p::rename(b"/d/a", b"/d/a/b", w)).err(),
        Some(p::code(p::INVALID))
    );
    // After BIND the birth window is shut: the parent's CLONE_MORE no longer reaches the child.
    let g = rig.open(OWNER, b"/d", p::DIRECTORY, 0).unwrap();
    let mut w = Writer::new();
    p::clone(&[g], &mut w).unwrap();
    let reply = rig.server.handle(&mut rig.fs, OWNER, 700, w.as_bytes());
    let birth = u32::from_le_bytes(
        p::reply(reply.as_bytes())
            .unwrap()
            .bytes(4)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    rig.server.bind(700, user(1000, 100, &[])).unwrap();
    let h2 = rig.open(OWNER, b"/d", p::DIRECTORY, 0).unwrap();
    assert_eq!(
        rig.call(OWNER, |w| p::clone_more(birth, &[h2], w)).err(),
        Some(p::code(p::BAD_HANDLE))
    );
}

#[test]
fn a_refused_directory_answers_access_before_anything_is_said_of_the_names_below_it() {
    let mut rig = Rig::new();
    rig.tree(0o700);
    // /d is closed to the group: whatever is asked below it, the answer is the access error.
    for path in [
        &b"/d/f"[..],
        b"/d/ghost",
        b"/d/ghost/deeper",
        b"/d/f/inside",
        b"/d/sub/x",
    ] {
        assert_eq!(rig.stat(GROUP, path).map(drop), Err(ACCESS), "{path:?}");
    }
    // With search allowed the errors of the names come: a missing directory, a file in the middle.
    rig.chmod(ROOT, b"/d", 0o755).unwrap();
    assert_eq!(
        rig.stat(GROUP, b"/d/ghost/deeper").map(drop),
        Err(p::code(p::NO_ENTRY))
    );
    assert_eq!(
        rig.stat(GROUP, b"/d/ghost").map(drop),
        Err(p::code(p::NO_ENTRY))
    );
    assert_eq!(
        rig.stat(GROUP, b"/d/f/inside").map(drop),
        Err(p::code(p::NOT_DIRECTORY))
    );
    // A directory refused below an existing one shows its access error before the missing name.
    rig.chmod(ROOT, b"/d/sub", 0o700).unwrap();
    assert_eq!(rig.stat(GROUP, b"/d/sub/ghost/x").map(drop), Err(ACCESS));
    // The create path: a missing last name in a directory the caller may not write.
    assert_eq!(
        rig.open(GROUP, b"/d/new", p::WRITE | p::CREATE, 0o644),
        Err(ACCESS)
    );
}

#[test]
fn an_attribute_that_is_not_exactly_48_bytes_is_not_trusted() {
    let mut rig = Rig::new();
    rig.mkdir(ROOT, b"/d", 0o700).unwrap();
    rig.put(ROOT, b"/d/f", 0o644, b"x");
    // A valid record with bytes added: it is longer than a record, so it reads as the closed default
    // (user 0, 0700 for a directory); the owner 1000 with mode 0777 it names is never seen.
    let mut longer = Attr {
        uid: 1000,
        gid: 100,
        mode: 0o777,
        ino: 99,
        atime: 0,
        mtime: 0,
        ctime: 0,
    }
    .to_bytes()
    .to_vec();
    longer.extend_from_slice(&[0u8; 8]);
    rig.fs.setattr(b"/d", ATTR_TYPE, &longer).unwrap();
    assert_eq!(
        rig.stat(OWNER, b"/d/f").map(drop),
        Err(ACCESS),
        "a longer attribute is not a record"
    );
    // The root's record is read the same way: its own format.
    let st = rig.stat(ROOT, b"/").unwrap();
    assert_eq!((st.mode, st.uid), (0o755, 0));
}

/// A chain of `depth` directories named `a`, and the path to the last.
fn deep(rig: &mut Rig, depth: usize) -> Vec<u8> {
    let mut path = Vec::new();
    for _ in 0..depth {
        path.extend_from_slice(b"/a");
        rig.mkdir(ROOT, &path, 0o755).unwrap();
    }
    path
}

#[test]
fn a_cold_stat_at_depth_200_costs_about_three_reads_a_level_and_depth_253_is_accepted() {
    let mut rig = Rig::new();
    let path = deep(&mut rig, 200);
    rig.fs.unmount().unwrap();
    let device = rig.fs.into_device();
    let mut rig = Rig::on(device);
    rig.fs.walk().unwrap();
    let before = rig.fs.device().reads;
    rig.stat(OTHER, &path).unwrap();
    let reads = rig.fs.device().reads - before;
    assert!(
        reads <= 3 * 200 + 20,
        "a cold stat of depth 200 read {reads} blocks"
    );
    // The longest path the protocol takes (506 bytes, 253 components) walks too: no name-too-long.
    let mut rig = Rig::new();
    let longest = deep(&mut rig, 253);
    assert_eq!(longest.len(), p::MAX_PATH);
    assert!(rig.stat(OTHER, &longest).is_ok());
    // One more is too long for the protocol before it reaches the walk.
    let mut over = longest.clone();
    over.extend_from_slice(b"/a");
    assert_eq!(
        rig.stat(OTHER, &over).map(drop),
        Err(p::code(p::NAME_TOO_LONG))
    );
}

#[test]
fn a_read_that_fails_in_a_listing_loses_no_entry_and_repeats_none() {
    let mut rig = Rig::new();
    rig.mkdir(ROOT, b"/d", 0o755).unwrap();
    let mut want: Vec<String> = vec![".".into(), "..".into()];
    for i in 0..80 {
        let name = std::format!("entry-{i:03}-{}", "n".repeat(60));
        rig.put(ROOT, std::format!("/d/{name}").as_bytes(), 0o644, b"");
        want.push(name);
    }
    rig.fs.unmount().unwrap();
    let device = rig.fs.into_device();
    let mut tried = 0;
    for k in 0..40 {
        let mut rig = Rig::on(device.clone());
        let dir = rig.open(ROOT, b"/d", p::DIRECTORY | p::READ, 0).unwrap();
        rig.fs.device().fail_read_after(Some(k));
        let (mut got, mut errors) = (Vec::new(), 0);
        loop {
            match rig.call(ROOT, |w| p::handle_call(p::Method::Readdir, dir, w)) {
                Ok(e) => {
                    let mut batch = p::read_dir_reply(Reader::new(&e)).unwrap();
                    while let Some(entry) = batch.next_entry().unwrap() {
                        got.push(String::from_utf8(entry.name.to_vec()).unwrap());
                    }
                    if !batch.more {
                        break;
                    }
                }
                Err(_) => {
                    errors += 1;
                    assert!(errors < 4, "point {k}");
                }
            }
        }
        tried += errors;
        assert_eq!(got, want, "a read failed at point {k}");
    }
    assert!(tried > 0, "no read of the listings failed");
}

#[test]
fn a_refused_change_of_a_file_with_a_pending_write_writes_nothing() {
    let mut rig = Rig::new();
    rig.mkdir(ROOT, b"/d", 0o777).unwrap();
    rig.server.set_now(5_000);
    rig.put(OWNER, b"/d/f", 0o4755, b"");
    rig.server.set_now(9_000);
    let h = rig.open(OWNER, b"/d/f", p::READ | p::WRITE, 0).unwrap();
    rig.write(OWNER, h, b"x").unwrap();
    let before = rig.fs.device().programs;
    // Another user may change neither the mode, the owner nor the times of the file.
    assert!(rig.chmod(OTHER, b"/d/f", 0o777).is_err());
    assert!(rig.chown(OTHER, b"/d/f", 5, p::UID_KEEP).is_err());
    assert_eq!(
        rig.fs.device().programs,
        before,
        "a refused change commits nothing"
    );
    // The write is still pending and the last close writes its time; the allowed change writes the
    // write's time and the new mode in one commit.
    rig.server.set_now(9_900);
    rig.chmod(OWNER, b"/d/f", 0o640).unwrap();
    rig.close(OWNER, h);
    let st = rig.stat(OWNER, b"/d/f").unwrap();
    assert_eq!((st.mode, st.mtime), (0o640, 9_000));
}

#[test]
fn a_directory_opened_for_search_holds_no_place_of_the_volume() {
    let mut rig = Rig::new();
    rig.mkdir(ROOT, b"/d", 0o755).unwrap();
    rig.mkdir(ROOT, b"/d/sub", 0o755).unwrap();
    rig.put(ROOT, b"/d/f", 0o644, b"x");
    // Forty current directories (more than the sixteen places of the volume) are all granted.
    let mut held = Vec::new();
    for who in [ROOT, OWNER, GROUP, OTHER] {
        for _ in 0..10 {
            held.push((who, rig.open(who, b"/d", p::DIRECTORY, 0).unwrap()));
        }
    }
    assert_eq!(held.len(), 40);
    // The places are all free: a listing opens, and so do sixteen of them, and a create works.
    let listings: Vec<u32> = (0..crate::DIRS)
        .map(|_| rig.open(ROOT, b"/d", p::READ | p::DIRECTORY, 0).unwrap())
        .collect();
    assert_eq!(
        rig.open(ROOT, b"/d", p::READ | p::DIRECTORY, 0),
        Err(p::code(p::TABLE_FULL)),
        "the listings hold the places"
    );
    for h in listings {
        rig.close(ROOT, h);
    }
    rig.put(ROOT, b"/d/new", 0o644, b"y");
    // What a search description does: FSTAT and WHERE answer, and no listing is there to read or
    // to start again.
    let (who, h) = held[0];
    assert_eq!(
        rig.ok(who, |w| p::handle_call(p::Method::Where, h, w)),
        b"/d"
    );
    let st = rig.ok(who, |w| p::handle_call(p::Method::Fstat, h, w));
    assert_eq!(p::Stat::from_bytes(&st).unwrap().kind, p::KIND_DIRECTORY);
    for method in [p::Method::Readdir, p::Method::Rewind] {
        assert_eq!(
            rig.call(who, |w| p::handle_call(method, h, w)),
            Err(p::code(p::BAD_HANDLE)),
            "{method:?}"
        );
    }
    // It still stops a rename of the directory, or of one above it, and goes with its close.
    assert_eq!(
        rig.call(ROOT, |w| p::rename(b"/d", b"/e", w)),
        Err(p::code(p::BUSY))
    );
    for (who, h) in held {
        rig.close(who, h);
    }
    rig.call(ROOT, |w| p::rename(b"/d", b"/e", w)).unwrap();
}

/// A session that passed VERIFY_SESSION (a loader sends it for the session a parent gave a set-ID
/// program) loses the binding of its old holder: it keeps its descriptions and reads them, writes
/// and path calls answer NOT_BOUND until the program binds it to its own identity, and the profile
/// of a native client is not touched.
#[test]
fn a_session_that_passed_verify_session_must_be_bound_again_by_its_new_holder() {
    let mut rig = Rig::new();
    rig.tree(0o755);
    let h = rig.open(OWNER, b"/d/f", p::READ | p::WRITE, 0).unwrap();
    assert!(rig.write(OWNER, h, b"x").is_ok());
    let not_bound = Some(p::code(p::NOT_BOUND));
    rig.server.unbind(OWNER);
    assert_eq!((rig.write(OWNER, h, b"y")).err(), not_bound);
    assert_eq!((rig.stat(OWNER, b"/d/f").map(drop)).err(), not_bound);
    assert!(
        rig.read(OWNER, h, 10).is_ok(),
        "what it holds is read without a binding"
    );
    // The new holder binds it to its own identity, which then rules.
    rig.server.bind(OWNER, user(2000, 200, &[])).unwrap();
    assert_eq!(rig.open(OWNER, b"/d/f", p::READ, 0), Err(ACCESS));
    // Unbinding a profile or an unknown label does nothing.
    rig.server.unbind(ROOT);
    assert!(rig.open(ROOT, b"/d/f", p::READ, 0).is_ok());
    rig.server.unbind(987_654);
}
