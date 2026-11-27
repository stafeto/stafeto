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

    /// A rig on a formatted volume with the mount work not run and no hidden directory.
    pub fn new_unmade() -> Rig {
        let state: &'static mut Storage = Box::leak(Box::new(Storage::new()));
        let mut fs = Fs::new(MemDevice::new(SECTORS), state).unwrap();
        fs.format().unwrap();
        fs.mount().unwrap();
        let mut server = Server::new();
        server.default_service = false;
        server.set_now(1_000);
        Rig { server, fs }
    }

    /// A rig on `device` whose conversion job has not run: the mount work only read the mark.
    pub fn unconverted(device: MemDevice) -> Rig {
        let state: &'static mut Storage = Box::leak(Box::new(Storage::new()));
        let mut fs = Fs::new(device, state).unwrap();
        fs.mount().unwrap();
        let mut server = Server::new();
        server.default_service = false;
        server.set_now(1_000);
        server::ensure_orphans(&mut fs).unwrap();
        server.mount_work(&mut fs).unwrap();
        let mut rig = Rig { server, fs };
        rig.bind(OWNER, user(1000, 100, &[]));
        rig.bind(GROUP, user(1001, 100, &[]));
        rig.bind(OTHER, user(2000, 200, &[]));
        rig
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
        assert!(mounted.complete || mounted.refused || mounted.pending);
        // The conversion job runs to its end before the tests ask anything (the service runs it after
        // READY, between requests; the tests of the job itself step it by hand).
        convert_to_the_end(&mut server, &mut fs);
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
    // The job has not run: the entries read as the closed default with the number their path gives.
    let mut rig = Rig::unconverted(device);
    let (key0, ssh0, root0) = (
        rig.stat(ROOT, b"/ssh/host_key").unwrap(),
        rig.stat(ROOT, b"/ssh").unwrap(),
        rig.stat(ROOT, b"/").unwrap(),
    );
    assert!(rig.server.conversion_pending());
    convert_to_the_end(&mut rig.server, &mut rig.fs);
    // After it every program sees the same owner, mode, times and `st_ino`: the record keeps what the
    // entry already showed.
    let key = rig.stat(ROOT, b"/ssh/host_key").unwrap();
    let ssh = rig.stat(ROOT, b"/ssh").unwrap();
    let root = rig.stat(ROOT, b"/").unwrap();
    for (before, after) in [(&key0, &key), (&ssh0, &ssh), (&root0, &root)] {
        assert_eq!(
            (
                before.ino,
                before.mode,
                before.uid,
                before.gid,
                before.mtime
            ),
            (after.ino, after.mode, after.uid, after.gid, after.mtime)
        );
    }
    assert_eq!((key.mode, key.uid, key.gid, key.size), (0o600, 0, 0, 10));
    assert_eq!((ssh.mode, ssh.uid, ssh.gid), (0o700, 0, 0));
    assert_eq!((root.mode, root.uid, root.gid), (0o755, 0, 0));
    assert!(
        key.ino >> 63 == 1 && ssh.ino >> 63 == 1,
        "the number of the path"
    );
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
    assert!(again.complete && !again.pending, "{again:?}");
}

#[test]
fn a_volume_whose_format_is_above_this_one_is_refused_and_left_alone() {
    let mut state = Storage::new();
    let mut fs = Fs::new(MemDevice::new(SECTORS), &mut state).unwrap();
    fs.format().unwrap();
    fs.mount().unwrap();
    fs.mkdir(b"/x").unwrap();
    fs.setattr(
        b"/",
        ATTR_FORMAT_TYPE,
        &(crate::attr::VOLUME_FORMAT + 1).to_le_bytes(),
    )
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

/// The cost of the jobs that change the tree, in volumes with more and more directories (a directory
/// is a pair of metadata blocks): a commit that splits or relocates a pair looks for the pair before
/// it in the list of every pair of the volume (`lfs_fs_pred`), so the worst of them grows with the
/// directories while the common one does not. Prints, for the table 4.2 of the plan, the common and
/// the worst reads of 120 CHMODs, 120 MKDIRs (each followed by its RMDIR) and the derived time of the
/// worst at 0.1 ms a read.
#[test]
#[ignore = "prints a table; run by name"]
fn the_worst_commit_grows_with_the_directories_of_the_volume() {
    fn stats(reads: &mut [u64]) -> (u64, u64) {
        reads.sort_unstable();
        (reads[reads.len() / 2], reads[reads.len() - 1])
    }
    std::println!(
        "| directories | chmod common | chmod worst | mkdir common | mkdir worst | rmdir new common | rmdir new worst | rmdir of the oldest | worst ms |"
    );
    std::println!("|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
    for dirs in [0u32, 500, 2_000, 6_000] {
        let mut rig = Rig::on(MemDevice::new(262_144));
        for parent in 0..8 {
            rig.mkdir(ROOT, std::format!("/p{parent}").as_bytes(), 0o755)
                .unwrap();
        }
        for n in 0..dirs {
            let path = std::format!("/p{}/d{n}", n % 8);
            rig.mkdir(ROOT, path.as_bytes(), 0o755).unwrap();
        }
        rig.mkdir(ROOT, b"/a", 0o777).unwrap();
        rig.put(OWNER, b"/a/f", 0o644, b"x");
        let (mut chmods, mut makes, mut removes) = (Vec::new(), Vec::new(), Vec::new());
        for n in 0..120u32 {
            let before = rig.fs.device().reads;
            rig.chmod(OWNER, b"/a/f", if n % 2 == 0 { 0o600 } else { 0o644 })
                .unwrap();
            chmods.push(rig.fs.device().reads - before);
            let name = std::format!("/a/m{n}");
            let before = rig.fs.device().reads;
            rig.mkdir(OWNER, name.as_bytes(), 0o755).unwrap();
            makes.push(rig.fs.device().reads - before);
            let before = rig.fs.device().reads;
            rig.call(OWNER, |w| {
                p::path_call(p::Method::Rmdir, name.as_bytes(), w)
            })
            .unwrap();
            removes.push(rig.fs.device().reads - before);
        }
        // The oldest directories are the far end of the list of pairs: removing one looks the pair
        // before it up from the head.
        let mut oldest = 0;
        for n in 0..8.min(dirs) {
            let path = std::format!("/p{}/d{n}", n % 8);
            let before = rig.fs.device().reads;
            rig.call(ROOT, |w| p::path_call(p::Method::Rmdir, path.as_bytes(), w))
                .unwrap();
            oldest = oldest.max(rig.fs.device().reads - before);
        }
        let ((cc, cw), (mc, mw), (rc, rw)) =
            (stats(&mut chmods), stats(&mut makes), stats(&mut removes));
        std::println!(
            "| {dirs} | {cc} | {cw} | {mc} | {mw} | {rc} | {rw} | {oldest} | {:.1} |",
            cw.max(mw).max(rw).max(oldest) as f64 * 0.1
        );
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

/// The cost of RENAME of an old directory and of `rm -rf` of a tree of directories, for the table 4.2
/// of the plan. The tree is `N` empty directories under 8 parents; `rm -rf` removes them in the order
/// of their making (the oldest pairs are at the far end of the list of pairs: the worst order) and
/// in the reverse order (the best). Prints the sum of the reads and the time at 3,000 and 10,000
/// reads a second.
#[test]
#[ignore = "prints a table; run by name"]
fn rename_of_an_old_directory_and_rm_rf_of_trees_of_directories() {
    std::println!(
        "| directories | rename old over an empty dir | rename old to another parent | rm -rf oldest first | rm -rf newest first | oldest first at 3,000/s |"
    );
    std::println!("|---:|---:|---:|---:|---:|---:|");
    for dirs in [500u32, 1_000, 2_000] {
        let build = |rig: &mut Rig| {
            for parent in 0..8 {
                rig.mkdir(ROOT, std::format!("/p{parent}").as_bytes(), 0o755)
                    .unwrap();
            }
            rig.mkdir(ROOT, b"/dst", 0o755).unwrap();
            for n in 0..dirs {
                rig.mkdir(ROOT, std::format!("/p{}/d{n:05}", n % 8).as_bytes(), 0o755)
                    .unwrap();
            }
        };
        let rmdir = |rig: &mut Rig, n: u32| {
            let path = std::format!("/p{}/d{n:05}", n % 8);
            rig.call(ROOT, |w| p::path_call(p::Method::Rmdir, path.as_bytes(), w))
                .unwrap();
        };
        let mut rig = Rig::on(MemDevice::new(262_144));
        rig.server.set_pairs_max(1_000_000);
        build(&mut rig);
        // The oldest directory renamed over an empty one made last, and then to another parent.
        rig.mkdir(ROOT, b"/dst/empty", 0o755).unwrap();
        let before = rig.fs.device().reads;
        rig.call(ROOT, |w| p::rename(b"/p0/d00000", b"/dst/empty", w))
            .unwrap();
        let over = rig.fs.device().reads - before;
        let before = rig.fs.device().reads;
        rig.call(ROOT, |w| p::rename(b"/p1/d00001", b"/dst/moved", w))
            .unwrap();
        let moved = rig.fs.device().reads - before;
        let before = rig.fs.device().reads;
        for n in 2..dirs {
            rmdir(&mut rig, n);
        }
        let oldest_first = rig.fs.device().reads - before;
        let mut rig = Rig::on(MemDevice::new(262_144));
        rig.server.set_pairs_max(1_000_000);
        build(&mut rig);
        let before = rig.fs.device().reads;
        for n in (2..dirs).rev() {
            rmdir(&mut rig, n);
        }
        let newest_first = rig.fs.device().reads - before;
        std::println!(
            "| {dirs} | {over} | {moved} | {oldest_first} | {newest_first} | {} s |",
            oldest_first / 3000
        );
    }
}

/// M6 of the review of step 5, with no inline data: how many entries a pair holds for names of 8 and of
/// 255 bytes (each with its 48-byte record), which operations split pairs, UNLINK in a directory of
/// 1,024 files behind 500 directories, and the removal of every directory of a volume at the cap.
/// Prints the figures for the table 4.2 and for the limit of names.
#[test]
#[ignore = "prints figures; run by name"]
fn what_makes_pairs_without_inline_data() {
    fn pairs(rig: &mut Rig) -> u64 {
        rig.fs.metadata_pairs().unwrap().0
    }
    fn reads(rig: &mut Rig) -> u64 {
        rig.fs.device().reads
    }
    rig_pairs_per_name_length();
    // The effect of single operations on 1,000 files of a directory: pairs before and after.
    let mut rig = Rig::on(MemDevice::new(262_144));
    rig.server.set_pairs_max(1_000_000);
    rig.mkdir(ROOT, b"/d", 0o755).unwrap();
    for n in 0..1000u32 {
        rig.put(ROOT, std::format!("/d/f{n:04}").as_bytes(), 0o644, b"");
    }
    let base = pairs(&mut rig);
    std::println!("1,000 empty files of 5 bytes of name: {base} pairs");
    let write_at = |rig: &mut Rig, len: usize| {
        for n in 0..1000u32 {
            let path = std::format!("/d/f{n:04}");
            let h = rig.open(ROOT, path.as_bytes(), p::WRITE, 0).unwrap();
            let data = std::vec![7u8; len];
            for chunk in data.chunks(900) {
                rig.write(ROOT, h, chunk).unwrap();
            }
            rig.close(ROOT, h);
        }
    };
    write_at(&mut rig, 500);
    std::println!("after writing 500 bytes to each: {} pairs", pairs(&mut rig));
    write_at(&mut rig, 4096);
    std::println!(
        "after writing 4,096 bytes to each: {} pairs",
        pairs(&mut rig)
    );
    for n in 0..1000u32 {
        let path = std::format!("/d/f{n:04}");
        let h = rig.open(ROOT, path.as_bytes(), p::WRITE, 0).unwrap();
        rig.call(ROOT, |w| p::truncate(h, 100, w)).unwrap();
        rig.close(ROOT, h);
    }
    std::println!(
        "after truncating each to 100 bytes: {} pairs",
        pairs(&mut rig)
    );
    for n in 0..1000u32 {
        let path = std::format!("/d/f{n:04}");
        rig.chmod(ROOT, path.as_bytes(), 0o600).unwrap();
    }
    std::println!(
        "after a CHMOD of each (an attribute of the same size): {} pairs",
        pairs(&mut rig)
    );
    for n in 0..1000u32 {
        let from = std::format!("/d/f{n:04}");
        let to = std::format!("/d/{}{n:04}", "r".repeat(240));
        rig.call(ROOT, |w| p::rename(from.as_bytes(), to.as_bytes(), w))
            .unwrap();
    }
    std::println!(
        "after renaming each to a name of 244 bytes: {} pairs",
        pairs(&mut rig)
    );
    // UNLINK of 1,024 files of a directory behind 500 directories.
    let mut rig = Rig::on(MemDevice::new(262_144));
    rig.server.set_pairs_max(1_000_000);
    for n in 0..500u32 {
        rig.mkdir(ROOT, std::format!("/p{}", n % 8).as_bytes(), 0o755)
            .ok();
        rig.mkdir(ROOT, std::format!("/p{}/d{n}", n % 8).as_bytes(), 0o755)
            .unwrap();
    }
    rig.mkdir(ROOT, b"/big", 0o755).unwrap();
    for n in 0..1023u32 {
        rig.put(ROOT, std::format!("/big/f{n:04}").as_bytes(), 0o644, b"x");
    }
    let total = pairs(&mut rig);
    let (mut sum, mut worst) = (0, 0);
    for n in 0..1023u32 {
        let before = reads(&mut rig);
        rig.call(ROOT, |w| {
            p::path_call(
                p::Method::Unlink,
                std::format!("/big/f{n:04}").as_bytes(),
                w,
            )
        })
        .unwrap();
        let spent = reads(&mut rig) - before;
        sum += spent;
        worst = worst.max(spent);
    }
    std::println!(
        "UNLINK of 1,023 files of /big behind 500 directories ({total} pairs): {sum} reads in all, {worst} the worst"
    );
}

/// Entries a pair holds: files with a name of `len` bytes and their records, until the pairs of the
/// directory number 20.
fn rig_pairs_per_name_length() {
    for len in [8usize, 12, 16, 24, 32, 64, 128, 255] {
        let mut rig = Rig::on(MemDevice::new(65_536));
        rig.server.set_pairs_max(1_000_000);
        rig.mkdir(ROOT, b"/d", 0o755).unwrap();
        let before = rig.fs.metadata_pairs().unwrap().0;
        let mut made = 0u32;
        while made < 1000 {
            let name = std::format!("{made:0>width$}", width = len);
            rig.put(ROOT, std::format!("/d/{name}").as_bytes(), 0o644, b"");
            made += 1;
        }
        let after = rig.fs.metadata_pairs().unwrap().0;
        std::println!(
            "names of {len} bytes: {made} entries in {} pairs, {:.1} an entry per pair",
            after - before,
            f64::from(made) / (after - before) as f64
        );
    }
}

#[test]
fn a_file_of_500_bytes_has_a_block_of_its_own() {
    let mut rig = Rig::new();
    rig.mkdir(ROOT, b"/d", 0o755).unwrap();
    let before = rig.fs.used_blocks().unwrap();
    rig.put(ROOT, b"/d/small", 0o644, &[7u8; 500]);
    let after = rig.fs.used_blocks().unwrap();
    // The block of the data; with inline data the file lives in the pair and adds none.
    assert!(after > before, "{before} blocks before, {after} after");
}

/// A rig whose caps are lowered so that a small volume reaches them.
fn capped(pairs: u64, dirs: u64) -> Rig {
    let mut rig = Rig::new();
    rig.server.set_pairs_max(pairs);
    rig.server.set_dirs_max(dirs);
    rig
}

fn no_space() -> Status {
    p::code(p::NO_SPACE)
}

fn rmdir(rig: &mut Rig, path: &str) -> Result<(), Status> {
    rig.call(ROOT, |w| p::path_call(p::Method::Rmdir, path.as_bytes(), w))
        .map(drop)
}

/// Directories until MKDIR is refused: how many were made.
fn mkdirs_until_refused(rig: &mut Rig, prefix: &str) -> u32 {
    for n in 0..500u32 {
        if let Err(status) = rig.mkdir(ROOT, std::format!("{prefix}{n}").as_bytes(), 0o755) {
            assert_eq!(status, no_space());
            return n;
        }
    }
    panic!("no cap in sight");
}

/// Files until a creation is refused: how many were made.
fn files_until_refused(rig: &mut Rig, prefix: &str) -> u32 {
    for n in 0..2000u32 {
        let name = std::format!("{prefix}{n:0>100}");
        let made = rig.open(ROOT, name.as_bytes(), p::WRITE | p::CREATE, 0o644);
        match made {
            Ok(h) => rig.close(ROOT, h),
            Err(status) => {
                assert_eq!(status, no_space());
                return n;
            }
        }
    }
    panic!("no cap in sight");
}

#[test]
fn every_creation_stops_at_the_cap_of_pairs_and_the_other_requests_pass() {
    let mut rig = capped(30, 1000);
    rig.mkdir(ROOT, b"/keep", 0o755).unwrap();
    rig.put(ROOT, b"/keep/old", 0o644, b"data");
    rig.mkdir(ROOT, b"/other", 0o755).unwrap();
    // Long names fill the pairs of /keep: files are refused at the cap.
    let made = files_until_refused(&mut rig, "/keep/f");
    assert!(made > 0, "the cap came before the first file");
    let (pairs, _) = rig.fs.metadata_pairs().unwrap();
    assert!(pairs >= 30, "refused at {pairs} pairs");
    // MKDIR, the creation of a file and RENAME into another directory are NO_SPACE.
    assert_eq!(rig.mkdir(ROOT, b"/new", 0o755), Err(no_space()));
    assert_eq!(
        rig.open(ROOT, b"/keep/another", p::WRITE | p::CREATE, 0o644),
        Err(no_space())
    );
    assert_eq!(
        rig.call(ROOT, |w| p::rename(b"/keep/old", b"/other/old", w))
            .map(drop),
        Err(no_space())
    );
    // At the cap a RENAME to a longer name in its own directory is refused too, and to a name of the
    // same length or a shorter one it passes.
    let long = std::format!("/keep/{}", "L".repeat(200));
    assert_eq!(
        rig.call(ROOT, |w| p::rename(b"/keep/old", long.as_bytes(), w))
            .map(drop),
        Err(no_space())
    );
    rig.call(ROOT, |w| p::rename(b"/keep/old", b"/keep/odd", w))
        .unwrap();
    rig.call(ROOT, |w| p::rename(b"/keep/odd", b"/keep/o", w))
        .unwrap();
    // Never refused: a write to an existing file, a truncation, CHMOD, CHOWN, UTIMENS, the removal.
    let h = rig.open(ROOT, b"/keep/o", p::WRITE, 0).unwrap();
    rig.write(ROOT, h, &[1u8; 700]).unwrap();
    rig.call(ROOT, |w| p::truncate(h, 10, w)).unwrap();
    rig.close(ROOT, h);
    rig.chmod(ROOT, b"/keep/o", 0o600).unwrap();
    rig.chown(ROOT, b"/keep/o", 5, 6).unwrap();
    rig.call(ROOT, |w| {
        p::utimens(b"/keep/o", p::TimeSpec::At(1), p::TimeSpec::At(2), w)
    })
    .unwrap();
    rig.call(ROOT, |w| p::path_call(p::Method::Unlink, b"/keep/o", w))
        .unwrap();
    // The removals make room: the service counts again at the next creation, finds the pairs under
    // the cap and the creation passes.
    for n in 0..made {
        let name = std::format!("/keep/f{n:0>100}");
        rig.call(ROOT, |w| {
            p::path_call(p::Method::Unlink, name.as_bytes(), w)
        })
        .unwrap();
    }
    rig.put(ROOT, b"/keep/after", 0o644, b"x");
}

/// The service counts at the mount and makes the hidden directory after READY: the directory is in
/// the count, so the cap lets exactly the directories through that the volume has room for.
#[test]
fn the_hidden_directory_made_after_the_mount_is_counted() {
    let mut rig = Rig::new_unmade();
    rig.server.mount_work(&mut rig.fs).unwrap();
    assert_eq!(rig.server.dirs_known(), Some(1));
    rig.server.make_orphans(&mut rig.fs).unwrap();
    assert_eq!(rig.server.dirs_known(), Some(2));
    rig.server.make_orphans(&mut rig.fs).unwrap();
    assert_eq!(rig.server.dirs_known(), Some(2));
    rig.server.set_dirs_max(12);
    let made = mkdirs_until_refused(&mut rig, "/d");
    assert_eq!(made, 12 - 2);
}

#[test]
fn the_cap_of_directories_refuses_only_mkdir_with_the_pairs_under_their_cap() {
    let mut rig = capped(1_000_000, 12);
    let made = mkdirs_until_refused(&mut rig, "/d");
    // The root and the hidden directory of the service count among the 12.
    assert_eq!(made, 12 - 2);
    assert_eq!(rig.server.dirs_known(), Some(12));
    // Files, renames and changes pass at the cap of directories.
    rig.put(ROOT, b"/file", 0o644, b"x");
    rig.call(ROOT, |w| p::rename(b"/file", b"/d0/file", w))
        .unwrap();
    rig.chmod(ROOT, b"/d1", 0o700).unwrap();
    // RMDIR gives one back and MKDIR passes once; the next is refused again.
    rmdir(&mut rig, "/d2").unwrap();
    assert_eq!(rig.server.dirs_known(), Some(11));
    rig.mkdir(ROOT, b"/again", 0o755).unwrap();
    assert_eq!(rig.mkdir(ROOT, b"/once-more", 0o755), Err(no_space()));
    // A directory a rename replaced is a removed directory.
    rig.mkdir(ROOT, b"/gone", 0o755).ok();
    rig.call(ROOT, |w| p::rename(b"/d3", b"/d4", w)).unwrap();
    assert_eq!(rig.server.dirs_known(), Some(11));
}

#[test]
fn the_cap_of_pairs_does_not_refuse_a_rename_that_does_not_lengthen_the_name() {
    // The cap of directories is far; the cap of pairs is where the files stop.
    let mut rig = capped(30, 1000);
    rig.mkdir(ROOT, b"/a", 0o755).unwrap();
    rig.mkdir(ROOT, b"/b", 0o755).unwrap();
    rig.put(ROOT, b"/a/same", 0o644, b"");
    files_until_refused(&mut rig, "/a/f");
    rig.call(ROOT, |w| p::rename(b"/a/same", b"/a/sama", w))
        .unwrap();
    rig.call(ROOT, |w| p::rename(b"/a/sama", b"/a/s", w))
        .unwrap();
    // Into another directory it is a new name there: refused.
    assert_eq!(
        rig.call(ROOT, |w| p::rename(b"/a/s", b"/b/s", w)).map(drop),
        Err(no_space())
    );
}

#[test]
fn a_refusal_is_made_only_after_an_exact_recount() {
    let mut rig = capped(1_000_000, 1_000_000);
    rig.mkdir(ROOT, b"/a", 0o755).unwrap();
    let (exact, _) = rig.fs.metadata_pairs().unwrap();
    // The estimate is far over the exact count (every creation adds 1 to it): a creation made when
    // the estimate reaches the cap counts again, finds room and passes; it is not refused.
    rig.server.set_pairs_max(exact + 6);
    for n in 0..12 {
        rig.put(ROOT, std::format!("/a/s{n}").as_bytes(), 0o644, b"");
    }
    let bound = rig.server.pairs_bound().unwrap();
    assert!(bound < exact + 6 + 12, "no recount happened: bound {bound}");
    // The count is told once for each recount.
    assert!(rig.server.take_pairs_report().is_some());
    assert!(rig.server.take_pairs_report().is_none());
}

#[test]
fn after_a_confirmed_refusal_the_pairs_are_not_counted_again_until_a_removal() {
    let mut rig = capped(30, 1000);
    rig.mkdir(ROOT, b"/a", 0o755).unwrap();
    let made = files_until_refused(&mut rig, "/a/f");
    // The refusal that confirmed the cap counted the pairs (told in a line); the next ones do not.
    rig.server.take_pairs_report();
    assert_eq!(rig.mkdir(ROOT, b"/x", 0o755), Err(no_space()));
    assert_eq!(rig.mkdir(ROOT, b"/y", 0o755), Err(no_space()));
    assert_eq!(
        rig.server.take_pairs_report(),
        None,
        "a refused loop counts again"
    );
    // The removals let the next creation count again: with the files gone it passes.
    for n in 0..made {
        let name = std::format!("/a/f{n:0>100}");
        rig.call(ROOT, |w| {
            p::path_call(p::Method::Unlink, name.as_bytes(), w)
        })
        .ok();
    }
    rig.put(ROOT, b"/a/new", 0o644, b"x");
    assert!(rig.server.take_pairs_report().is_some());
}

#[test]
fn the_directories_are_counted_by_soft_tails_not_by_every_tail() {
    let mut rig = capped(1_000_000, 1_000_000);
    // One directory split into many pairs by long names, and thirty small ones.
    rig.mkdir(ROOT, b"/big", 0o755).unwrap();
    for n in 0..60u32 {
        rig.put(ROOT, std::format!("/big/{n:0>150}").as_bytes(), 0o644, b"");
    }
    for n in 0..30 {
        rig.mkdir(ROOT, std::format!("/d{n}").as_bytes(), 0o755)
            .unwrap();
    }
    let (pairs, dirs) = rig.fs.metadata_pairs().unwrap();
    // The root, the hidden directory of the service, /big and thirty more: pairs of /big that go on
    // with a hard tail are no directories.
    assert_eq!(dirs, 3 + 30);
    assert!(
        pairs > dirs + 5,
        "{pairs} pairs of {dirs} directories: /big did not split"
    );
    assert_eq!(rig.server.dirs_known(), Some(dirs));
}

#[test]
fn a_volume_over_the_caps_mounts_and_works_and_only_the_creations_are_refused() {
    let mut rig = Rig::new();
    for n in 0..30 {
        rig.mkdir(ROOT, std::format!("/d{n}").as_bytes(), 0o755)
            .unwrap();
    }
    rig.server.set_pairs_max(10);
    rig.server.set_dirs_max(10);
    // The service has not counted since: the estimate is under the new caps until it counts, which
    // the next creation does at once (no count yet is a count to make).
    rig.server.recount_for_test(&mut rig.fs);
    assert_eq!(rig.mkdir(ROOT, b"/new", 0o755), Err(no_space()));
    assert!(rig.stat(ROOT, b"/d29").is_ok());
    rig.chmod(ROOT, b"/d3", 0o700).unwrap();
    rmdir(&mut rig, "/d0").unwrap();
    // Still over: the file is refused until enough is removed.
    assert!(
        rig.open(ROOT, b"/file", p::WRITE | p::CREATE, 0o644)
            .is_err()
    );
}

#[test]
fn a_file_of_500_bytes_keeps_its_data_out_of_the_pair() {
    let mut rig = Rig::new();
    rig.mkdir(ROOT, b"/d", 0o755).unwrap();
    let before = rig.fs.metadata_pairs().unwrap().0;
    for n in 0..300u32 {
        rig.put(
            ROOT,
            std::format!("/d/f{n:04}").as_bytes(),
            0o644,
            &[7u8; 500],
        );
    }
    // 300 files of 500 bytes with short names: with their data in the pairs they would take about
    // 150; with the data in blocks of their own about 20 pairs of names.
    let made = rig.fs.metadata_pairs().unwrap().0 - before;
    assert!(made < 40, "{made} pairs for 300 files");
}

#[test]
fn a_volume_with_an_inline_file_reads_and_a_write_moves_the_file_out() {
    // A file made the way an older release made it (small, inside the pair of its directory).
    let mut rig = Rig::new();
    rig.fs.unmount().unwrap();
    rig.fs.set_inline_max(0);
    rig.fs.mount().unwrap();
    rig.mkdir(ROOT, b"/d", 0o755).unwrap();
    rig.put(ROOT, b"/d/small", 0o644, b"inline bytes");
    let inline_blocks = rig.fs.used_blocks().unwrap();
    // The service of this release mounts the same volume with the inline limit off.
    rig.fs.unmount().unwrap();
    rig.fs.set_inline_max(u32::MAX);
    rig.fs.mount().unwrap();
    let h = rig.open(ROOT, b"/d/small", p::READ, 0).unwrap();
    let data = rig.ok(ROOT, |w| p::read(h, 64, w));
    assert_eq!(&data[4..4 + 12], b"inline bytes");
    rig.close(ROOT, h);
    // A write moves it out to a block of its own; the pair loses the data.
    let h = rig
        .open(ROOT, b"/d/small", p::WRITE | p::APPEND, 0)
        .unwrap();
    rig.write(ROOT, h, b" and more").unwrap();
    rig.close(ROOT, h);
    assert!(rig.fs.used_blocks().unwrap() > inline_blocks);
    let h = rig.open(ROOT, b"/d/small", p::READ, 0).unwrap();
    let data = rig.ok(ROOT, |w| p::read(h, 64, w));
    assert_eq!(&data[4..4 + 21], b"inline bytes and more");
    rig.close(ROOT, h);
}

/// `rm -rf` at the caps: 1,018 empty directories made first (the oldest pairs, the far end of the
/// list) behind about 1,000 pairs of files with long names, removed oldest first. Prints the sum of
/// the reads and the pairs the volume had, for the constant of the fill probe (the review estimated
/// 2 to 3 million reads).
#[test]
#[ignore = "prints figures; run by name"]
fn rm_rf_of_1024_directories_behind_a_thousand_pairs_of_files() {
    let mut rig = Rig::on(MemDevice::new(524_288));
    rig.server.set_pairs_max(1_000_000);
    rig.server.set_dirs_max(1_000_000);
    for parent in 0..8 {
        rig.mkdir(ROOT, std::format!("/p{parent}").as_bytes(), 0o755)
            .unwrap();
    }
    for n in 0..1010u32 {
        rig.mkdir(ROOT, std::format!("/p{}/d{n:05}", n % 8).as_bytes(), 0o755)
            .unwrap();
    }
    for dir in 0..4 {
        rig.mkdir(ROOT, std::format!("/files{dir}").as_bytes(), 0o755)
            .unwrap();
        for n in 0..800u32 {
            let name = std::format!("/files{dir}/{n:0>240}");
            rig.put(ROOT, name.as_bytes(), 0o644, b"");
        }
    }
    let (pairs, dirs) = rig.fs.metadata_pairs().unwrap();
    let before = rig.fs.device().reads;
    for n in 0..1010u32 {
        let path = std::format!("/p{}/d{n:05}", n % 8);
        rmdir(&mut rig, &path).unwrap();
    }
    let sum = rig.fs.device().reads - before;
    std::println!(
        "rm -rf of 1,010 directories (the volume has {dirs} directories in {pairs} pairs): {sum} reads, {:.2} a pair for each directory, {} s at 3,000 reads a second",
        sum as f64 / (1010.0 * pairs as f64),
        sum / 3000
    );
}

/// A volume as the part A build left it: records everywhere, the mark of the records, small files
/// inline (that build had inline data on).
fn part_a_volume() -> MemDevice {
    use crate::attr::{ATTR_FORMAT_TYPE, RECORDS_FORMAT};
    let mut rig = Rig::new();
    rig.fs.unmount().unwrap();
    rig.fs.set_inline_max(0);
    rig.fs.mount().unwrap();
    rig.mkdir(ROOT, b"/ssh", 0o700).unwrap();
    rig.put(
        ROOT,
        b"/ssh/host_key",
        0o600,
        b"0123456789abcdef0123456789abcdef",
    );
    rig.put(ROOT, b"/note", 0o644, b"a short note");
    rig.fs
        .setattr(b"/", ATTR_FORMAT_TYPE, &RECORDS_FORMAT.to_le_bytes())
        .unwrap();
    rig.fs.unmount().unwrap();
    rig.fs.into_device()
}

#[test]
fn a_write_at_the_start_or_in_the_middle_of_an_old_inline_file_after_the_mount_work_is_kept() {
    let mut rig = Rig::on(part_a_volume());
    // The mount work moved the two files out (the volume had the records already).
    for (offset, text) in [(0u64, &b"NEW-"[..]), (10, b"middle")] {
        let h = rig
            .open(ROOT, b"/ssh/host_key", p::READ | p::WRITE, 0)
            .unwrap();
        rig.call(ROOT, |w| p::pwrite(h, offset, text, w)).unwrap();
        rig.call(ROOT, |w| p::handle_call(p::Method::Fsync, h, w))
            .unwrap();
        rig.close(ROOT, h);
    }
    let h = rig.open(ROOT, b"/ssh/host_key", p::READ, 0).unwrap();
    let data = rig.ok(ROOT, |w| p::read(h, 64, w));
    assert_eq!(&data[4..4 + 32], b"NEW-456789middle0123456789abcdef");
}

#[test]
fn the_conversion_job_moves_the_inline_files_once_and_marks_the_volume() {
    use crate::attr::{ATTR_FORMAT_TYPE, VOLUME_FORMAT};
    let mut state = Storage::new();
    let mut fs = Fs::new(part_a_volume(), &mut state).unwrap();
    fs.mount().unwrap();
    let mut server = Server::new();
    let first = server.mount_work(&mut fs).unwrap();
    assert!(first.pending && !first.complete, "{first:?}");
    // READY does not wait for it: the mount work only read the mark and counted the pairs.
    let (converted, moved) = convert_to_the_end(&mut server, &mut fs);
    assert_eq!((converted, moved), (0, 2));
    let mut mark = [0u8; 4];
    fs.getattr(b"/", ATTR_FORMAT_TYPE, &mut mark).unwrap();
    assert_eq!(u32::from_le_bytes(mark), VOLUME_FORMAT);
    // The second mount reads the mark and walks nothing.
    let reads = fs.device().reads;
    let again = Server::new().mount_work(&mut fs).unwrap();
    assert!(again.complete && !again.pending, "{again:?}");
    assert!(
        fs.device().reads - reads < 60,
        "{} reads",
        fs.device().reads - reads
    );
}

#[test]
fn without_the_move_out_a_write_in_the_middle_of_an_old_inline_file_is_lost() {
    // What the mount work protects against (littlefs 2.11.3 with inline data off): the write fails at
    // close with CORRUPT and the old data stays. If this test fails, littlefs no longer loses the
    // write and the move-out is not needed for it.
    let mut state = Storage::new();
    let mut fs = Fs::new(part_a_volume(), &mut state).unwrap();
    fs.mount().unwrap();
    let f = fs.open(b"/ssh/host_key", crate::Open::READ_WRITE).unwrap();
    fs.seek(f, 8, crate::fs::Whence::Set).unwrap();
    fs.write(f, b"NEW!").unwrap();
    assert!(
        fs.close(f).is_err(),
        "the write was kept: the move-out is not needed"
    );
}

#[test]
fn a_move_out_that_is_skipped_leaves_the_write_lost_which_the_test_of_the_mount_work_sees() {
    // The planted fault: mount work with no move-out (the mark set, nothing moved) loses the write.
    use crate::attr::{ATTR_FORMAT_TYPE, VOLUME_FORMAT};
    let mut state = Storage::new();
    let mut fs = Fs::new(part_a_volume(), &mut state).unwrap();
    fs.mount().unwrap();
    fs.setattr(b"/", ATTR_FORMAT_TYPE, &VOLUME_FORMAT.to_le_bytes())
        .unwrap();
    let mounted = Server::new().mount_work(&mut fs).unwrap();
    assert!(mounted.complete && !mounted.pending);
    let f = fs.open(b"/ssh/host_key", crate::Open::READ_WRITE).unwrap();
    fs.seek(f, 8, crate::fs::Whence::Set).unwrap();
    fs.write(f, b"NEW!").unwrap();
    assert!(fs.close(f).is_err());
}

/// What the mount work costs on a volume of small inline files (part A's, with the mark of the
/// records): reads for each file moved out, and for each file already in a block (the walk alone).
#[test]
#[ignore = "prints figures; run by name"]
fn what_the_move_out_costs_at_the_mount() {
    use crate::attr::{ATTR_FORMAT_TYPE, RECORDS_FORMAT};
    for (inline, label) in [(true, "inline files"), (false, "files in blocks")] {
        let mut rig = Rig::on(MemDevice::new(65_536));
        rig.server.set_pairs_max(1_000_000);
        rig.fs.unmount().unwrap();
        rig.fs.set_inline_max(if inline { 0 } else { u32::MAX });
        rig.fs.mount().unwrap();
        for d in 0..6 {
            rig.mkdir(ROOT, std::format!("/d{d}").as_bytes(), 0o755)
                .unwrap();
            for n in 0..100 {
                rig.put(
                    ROOT,
                    std::format!("/d{d}/f{n:03}").as_bytes(),
                    0o644,
                    b"small file bytes",
                );
            }
        }
        rig.fs
            .setattr(b"/", ATTR_FORMAT_TYPE, &RECORDS_FORMAT.to_le_bytes())
            .unwrap();
        rig.fs.unmount().unwrap();
        rig.fs.set_inline_max(u32::MAX);
        rig.fs.mount().unwrap();
        let reads = rig.fs.device().reads;
        let mut server = Server::new();
        let mounted = server.mount_work(&mut rig.fs).unwrap();
        let before_job = rig.fs.device().reads - reads;
        let (_, moved) = convert_to_the_end(&mut server, &mut rig.fs);
        let spent = rig.fs.device().reads - reads;
        std::println!(
            "{label}: 600 files in 6 directories, {moved} moved, {before_job} reads before READY ({mounted:?}), {spent} reads in all: {:.1} reads for each file",
            spent as f64 / 600.0
        );
    }
}

#[test]
fn a_mkdir_whose_record_could_not_be_written_leaves_the_directory_count_as_it_was() {
    let mut rig = capped(1_000_000, 1_000_000);
    rig.mkdir(ROOT, b"/a", 0o755).unwrap();
    let before = rig.server.dirs_known().unwrap();
    rig.server.fail_record = true;
    assert!(rig.mkdir(ROOT, b"/b", 0o755).is_err());
    rig.server.fail_record = false;
    assert!(rig.stat(ROOT, b"/b").is_err(), "the name went again");
    assert_eq!(
        rig.server.dirs_known(),
        Some(before),
        "the rollback left a directory in the count"
    );
    assert_eq!(rig.fs.metadata_pairs().unwrap().1, before);
}

#[test]
fn mkdir_near_the_cap_is_refused_only_after_a_recount_and_a_difference_is_told() {
    let mut rig = capped(1_000_000, 12);
    rig.mkdir(ROOT, b"/a", 0o755).unwrap();
    let real = rig.server.dirs_known().unwrap();
    // The service believes the volume is at the cap, which it is not (a change it did not see).
    rig.server.set_dirs_tracked(12);
    rig.server.take_pairs_report();
    // The tracked count says full: the recount finds free places, MKDIR passes and the difference is told.
    rig.mkdir(ROOT, b"/fits", 0o755).unwrap();
    assert_eq!(rig.server.take_dirs_mismatch(), Some((12, real)));
    // Fill the volume: the recount confirms the cap and refuses; a loop of refusals counts once.
    mkdirs_until_refused(&mut rig, "/d");
    assert!(rig.server.take_pairs_report().is_some());
    assert_eq!(rig.mkdir(ROOT, b"/no2", 0o755), Err(no_space()));
    assert!(
        rig.server.take_pairs_report().is_none(),
        "a confirmed refusal counted again"
    );
}

/// Steps the conversion job of `server` until it ends (nothing to do for a volume that needs none):
/// the records given and the files moved out.
pub(crate) fn convert_to_the_end(
    server: &mut Server,
    fs: &mut Fs<'_, MemDevice>,
) -> (usize, usize) {
    let mut steps = 0;
    while server.conversion_pending() {
        match server.convert_step(fs).unwrap() {
            server::Step::More => steps += 1,
            server::Step::Done { converted, moved } => return (converted, moved),
        }
        assert!(steps < 200_000, "the conversion does not end");
    }
    (0, 0)
}

#[test]
fn a_write_to_an_inline_file_the_job_has_not_reached_is_moved_out_first_and_not_lost() {
    let mut rig = Rig::unconverted(part_a_volume());
    assert!(rig.server.conversion_pending());
    // A write at the start, then one in the middle, then a truncation, each before the job ran.
    let h = rig
        .open(ROOT, b"/ssh/host_key", p::READ | p::WRITE, 0)
        .unwrap();
    rig.call(ROOT, |w| p::pwrite(h, 0, b"NEW-", w)).unwrap();
    rig.call(ROOT, |w| p::pwrite(h, 10, b"middle", w)).unwrap();
    rig.call(ROOT, |w| p::handle_call(p::Method::Fsync, h, w))
        .unwrap();
    rig.close(ROOT, h);
    let h = rig.open(ROOT, b"/ssh/host_key", p::READ, 0).unwrap();
    let data = rig.ok(ROOT, |w| p::read(h, 64, w));
    assert_eq!(&data[4..4 + 32], b"NEW-456789middle0123456789abcdef");
    rig.close(ROOT, h);
    // A reader that holds the file open when a writer comes: the node is shared, the move-out goes
    // through it.
    let reader = rig.open(ROOT, b"/note", p::READ, 0).unwrap();
    let writer = rig.open(ROOT, b"/note", p::READ | p::WRITE, 0).unwrap();
    rig.call(ROOT, |w| p::pwrite(writer, 2, b"LONG", w))
        .unwrap();
    rig.close(ROOT, writer);
    let data = rig.ok(ROOT, |w| p::pread(reader, 64, 0, w));
    assert_eq!(&data[4..4 + 12], b"a LONGt note");
    rig.close(ROOT, reader);
    // The job still has its work; when it ends the files are whole.
    assert!(rig.server.conversion_pending());
    convert_to_the_end(&mut rig.server, &mut rig.fs);
    let h = rig.open(ROOT, b"/ssh/host_key", p::READ, 0).unwrap();
    let data = rig.ok(ROOT, |w| p::read(h, 64, w));
    assert_eq!(&data[4..4 + 32], b"NEW-456789middle0123456789abcdef");
}

/// A volume with one inline file (the build with inline data on) at `levels` directories deep and
/// the format mark `mark` (None: the mark 4 the first mount of the empty volume wrote stays).
fn inline_file_volume(levels: usize, mark: Option<u32>) -> (MemDevice, std::string::String) {
    use crate::attr::ATTR_FORMAT_TYPE;
    let mut rig = Rig::new();
    rig.fs.unmount().unwrap();
    rig.fs.set_inline_max(0);
    rig.fs.mount().unwrap();
    let mut path = std::string::String::new();
    for _ in 0..levels {
        path.push_str("/d");
        rig.mkdir(ROOT, path.as_bytes(), 0o755).unwrap();
    }
    path.push_str("/f");
    rig.put(
        ROOT,
        path.as_bytes(),
        0o644,
        b"0123456789abcdef0123456789abcdef",
    );
    if let Some(mark) = mark {
        rig.fs
            .setattr(b"/", ATTR_FORMAT_TYPE, &mark.to_le_bytes())
            .unwrap();
    }
    rig.fs.unmount().unwrap();
    (rig.fs.into_device(), path)
}

/// A write into the middle of the file, then the whole file read back.
fn write_in_the_middle_and_read(rig: &mut Rig, path: &str) -> std::vec::Vec<u8> {
    let h = rig
        .open(ROOT, path.as_bytes(), p::READ | p::WRITE, 0)
        .unwrap();
    rig.call(ROOT, |w| p::pwrite(h, 10, b"middle", w)).unwrap();
    rig.call(ROOT, |w| p::handle_call(p::Method::Fsync, h, w))
        .unwrap();
    rig.close(ROOT, h);
    let h = rig.open(ROOT, path.as_bytes(), p::READ, 0).unwrap();
    let data = rig.ok(ROOT, |w| p::read(h, 64, w));
    rig.close(ROOT, h);
    data[4..4 + 32].to_vec()
}

const MIDDLE_KEPT: &[u8] = b"0123456789middle0123456789abcdef";

#[test]
fn the_conversion_walk_reaches_an_inline_file_at_any_depth_a_path_can_have() {
    use crate::attr::RECORDS_FORMAT;
    // 33 levels (the old walk stopped at 32) and 250 (a path of 503 bytes).
    for levels in [33usize, 250] {
        let (device, path) = inline_file_volume(levels, Some(RECORDS_FORMAT));
        let mut rig = Rig::on(device);
        assert!(!rig.server.conversion_pending());
        assert_eq!(rig.fs.outline(path.as_bytes(), true), Ok(false), "{levels}");
        assert_eq!(write_in_the_middle_and_read(&mut rig, &path), MIDDLE_KEPT);
    }
}

#[test]
fn a_write_into_an_inline_file_is_kept_whatever_the_mark_and_the_job_say() {
    use crate::attr::VOLUME_FORMAT;
    // A volume marked 4 that still holds an inline file (written by an older build after the mark):
    // the mount work does nothing and the open moves the file out.
    let (device, path) = inline_file_volume(2, Some(VOLUME_FORMAT));
    let mut rig = Rig::on(device);
    assert!(!rig.server.conversion_pending());
    assert_eq!(write_in_the_middle_and_read(&mut rig, &path), MIDDLE_KEPT);
    // A job that was abandoned (the volume failed under it) leaves the file inline and the mark as it
    // was: the open of the file for writing still moves it out.
    let (device, path) = inline_file_volume(2, Some(crate::attr::RECORDS_FORMAT));
    let mut rig = Rig::unconverted(device);
    assert!(rig.server.conversion_pending());
    rig.server.abandon_conversion(&mut rig.fs);
    assert!(!rig.server.conversion_pending());
    assert_eq!(write_in_the_middle_and_read(&mut rig, &path), MIDDLE_KEPT);
    // And a job that ended: the same.
    let (device, path) = inline_file_volume(2, Some(crate::attr::RECORDS_FORMAT));
    let mut rig = Rig::on(device);
    assert_eq!(write_in_the_middle_and_read(&mut rig, &path), MIDDLE_KEPT);
}

#[test]
fn ready_does_not_wait_for_the_job_and_a_request_is_served_between_its_steps() {
    // 150 inline files in 3 directories (part A's volume).
    let mut rig = Rig::on(MemDevice::new(65_536));
    rig.fs.unmount().unwrap();
    rig.fs.set_inline_max(0);
    rig.fs.mount().unwrap();
    for d in 0..3 {
        rig.mkdir(ROOT, std::format!("/d{d}").as_bytes(), 0o755)
            .unwrap();
        for n in 0..50 {
            rig.put(
                ROOT,
                std::format!("/d{d}/f{n:02}").as_bytes(),
                0o644,
                b"small",
            );
        }
    }
    rig.fs
        .setattr(
            b"/",
            crate::attr::ATTR_FORMAT_TYPE,
            &crate::attr::RECORDS_FORMAT.to_le_bytes(),
        )
        .unwrap();
    rig.fs.unmount().unwrap();
    rig.fs.set_inline_max(u32::MAX);
    rig.fs.mount().unwrap();
    let reads = rig.fs.device().reads;
    let mut server = Server::new();
    server.default_service = false;
    let mounted = server.mount_work(&mut rig.fs).unwrap();
    let before_ready = rig.fs.device().reads - reads;
    assert!(mounted.pending);
    assert!(
        before_ready < 400,
        "{before_ready} reads before READY: the job did not wait for the first request"
    );
    rig.server = server;
    rig.bind(OWNER, user(1000, 100, &[]));
    // One entry a step: each step is short, and requests between them are answered.
    let (mut steps, mut longest) = (0u32, 0u64);
    while rig.server.conversion_pending() {
        let before = rig.fs.device().reads;
        let step = rig.server.convert_step(&mut rig.fs).unwrap();
        longest = longest.max(rig.fs.device().reads - before);
        steps += 1;
        if steps % 20 == 0 {
            // A request between two steps: served at once, the same answer as ever.
            assert_eq!(rig.stat(ROOT, b"/d1/f10").unwrap().size, 5);
        }
        if matches!(step, server::Step::Done { .. }) {
            break;
        }
    }
    assert!(steps >= 150, "{steps} steps for 150 files");
    assert!(
        longest < 400,
        "a step read {longest} blocks: a request would wait for it"
    );
}

/// A volume made offline as the fill probe makes it: files of 1 MiB and small ones, no hidden
/// directory of the orphans, no mark and no attribute.
fn volume_full_of_files() -> (MemDevice, u64) {
    let mut state = Storage::new();
    let mut fs = Fs::new(MemDevice::new(131_072), &mut state).unwrap();
    fs.format().unwrap();
    fs.mount().unwrap();
    let chunk = vec![0x5au8; 4096];
    fs.mkdir(b"/big").unwrap();
    for n in 0..30 {
        let f = fs
            .open(
                std::format!("/big/b{n}").as_bytes(),
                crate::Open::WRITE.with(crate::Open::CREATE),
            )
            .unwrap();
        for _ in 0..256 {
            fs.write(f, &chunk).unwrap();
        }
        fs.close(f).unwrap();
    }
    fs.mkdir(b"/small").unwrap();
    for n in 0..200 {
        let f = fs
            .open(
                std::format!("/small/s{n:03}").as_bytes(),
                crate::Open::WRITE.with(crate::Open::CREATE),
            )
            .unwrap();
        fs.write(f, &chunk[..2000]).unwrap();
        fs.close(f).unwrap();
    }
    let used = fs.used_blocks().unwrap();
    fs.unmount().unwrap();
    (fs.into_device(), used)
}

/// The most reads the work before READY may take on a volume full of files made offline: the count of
/// the pairs (about two reads each) and the reads of the mark, the epoch and the orphans' directory.
const READY_READS_MAX: u64 = 1_500;

#[test]
fn the_work_before_ready_does_not_traverse_the_files_of_a_volume_full_of_them() {
    let (device, used) = volume_full_of_files();
    assert!(used > 7_000, "{used} blocks used");
    let mut state = Storage::new();
    let mut fs = Fs::new(device.clone(), &mut state).unwrap();
    fs.mount().unwrap();
    let reads = fs.device().reads;
    let mut server = Server::new();
    let start = server.start_work(&mut fs);
    assert!(start.mounted.is_ok() && start.epoch.is_ok());
    let spent = fs.device().reads - reads;
    std::println!("the work before READY: {spent} reads on a volume of {used} blocks");
    assert!(
        spent <= READY_READS_MAX,
        "{spent} reads before READY on a volume of {used} blocks: something allocated"
    );
    // The same volume with the hidden directory made at the mount (the earlier order): the first
    // allocation scans the window, a traversal of every file's blocks.
    let mut state = Storage::new();
    let mut fs = Fs::new(device, &mut state).unwrap();
    fs.mount().unwrap();
    let reads = fs.device().reads;
    server::ensure_orphans(&mut fs).unwrap();
    let mut server = Server::new();
    server.start_work(&mut fs);
    let before = fs.device().reads - reads;
    std::println!("with the directory of the orphans made first: {before} reads");
    assert!(
        before > used / 4,
        "{before} reads: the test cannot tell the order apart"
    );
    // After READY the directory is made by its own job.
    let mut state = Storage::new();
    let mut fs = Fs::new(MemDevice::new(131_072), &mut state).unwrap();
    fs.format().unwrap();
    fs.mount().unwrap();
    server::ensure_orphans(&mut fs).unwrap();
    assert!(fs.stat(server::ORPHANS).is_ok());
}

/// A file of an eighth of the volume is made again and again: the even rounds truncate it and write
/// it anew, the odd rounds remove it and create a new file. Each round allocates new blocks and gives
/// the old ones back, which the window's bits do not see until a walk. The writes must not get
/// NO_SPACE while most of the volume is free: the request walks before it answers NO_SPACE. A
/// rewrite in place never needed the walk: the part over the file's own bytes always fits
/// (`fits = (size - start) + room`).
#[test]
fn rewrites_never_meet_no_space_on_a_mostly_free_volume() {
    let mut rig = Rig::new();
    let bytes = (SECTORS / 8 / 8 * 4096) as usize;
    let chunk = [5u8; 900];
    // Several times the bytes of the volume go through the allocator.
    let rounds = 6 * (SECTORS / 8 * 4096) as usize / bytes;
    for round in 0..rounds {
        let h = if round % 2 == 0 {
            rig.open(ROOT, b"/f", p::WRITE | p::CREATE | p::TRUNCATE, 0o666)
        } else {
            let _ = rig.call(ROOT, |w| p::path_call(p::Method::Unlink, b"/f", w));
            rig.open(ROOT, b"/f", p::WRITE | p::CREATE, 0o666)
        }
        .unwrap();
        for at in (0..bytes).step_by(chunk.len()) {
            let n = (bytes - at).min(chunk.len());
            let got = rig
                .call(ROOT, |w| p::pwrite(h, at as u64, &chunk[..n], w))
                .unwrap_or_else(|e| panic!("round {round} at {at}: {e:?}"));
            assert_eq!(u32::from_le_bytes(got[..4].try_into().unwrap()) as usize, n);
        }
        rig.close(ROOT, h);
        assert!(
            rig.fs.used_blocks().unwrap() < SECTORS / 8 / 2,
            "most of the volume is free"
        );
    }
}

/// Files of 14,400 bytes (4 blocks each) written as the superuser until a write is short, so that
/// the window has no free block. The number of files.
fn fill_full(rig: &mut Rig) -> usize {
    rig.mkdir(ROOT, b"/d", 0o777).unwrap();
    let chunk = [9u8; 900];
    let mut n = 0;
    loop {
        let path = std::format!("/d/fill{n}");
        let h = rig
            .open(ROOT, path.as_bytes(), p::WRITE | p::CREATE, 0o644)
            .unwrap();
        for _ in 0..16 {
            match rig.write(ROOT, h, &chunk) {
                Ok(900) => {}
                _ => {
                    rig.close(ROOT, h);
                    return n;
                }
            }
        }
        rig.close(ROOT, h);
        n += 1;
    }
}

fn append(rig: &mut Rig, who: u64, h: u32, bytes: usize) -> Result<u32, Status> {
    rig.write(who, h, &std::vec![3u8; bytes])
}

#[test]
fn a_write_far_in_a_file_on_a_mostly_free_volume_makes_no_walk() {
    let mut rig = Rig::new();
    let h = rig.open(ROOT, b"/f", p::WRITE | p::CREATE, 0o666).unwrap();
    rig.write(ROOT, h, b"x").unwrap();
    let reads = rig.fs.device().reads;
    // The gap of zeros up to the offset takes blocks, but the room holds them.
    rig.call(ROOT, |w| p::pwrite(h, 300 << 10, b"y", w))
        .unwrap();
    assert_eq!(rig.server.walks, 0);
    assert!(rig.fs.device().reads > reads);
}

#[test]
fn a_second_no_space_on_a_full_volume_reads_nothing_and_a_short_count_leads_to_one_walk() {
    let mut rig = Rig::new();
    fill_full(&mut rig);
    let h = rig
        .open(ROOT, b"/last", p::WRITE | p::CREATE, 0o644)
        .unwrap();
    // The last short write took the blocks that were left; this one has none to take: the window
    // holds blocks handed out since the walk, so it walks once to see what there is.
    let before = rig.server.walks;
    assert_eq!(append(&mut rig, ROOT, h, 900), Err(p::code(p::NO_SPACE)));
    assert!(rig.server.walks <= before + 1);
    // The walk found nothing: the window is fresh, and the next answers read no block.
    let settled = rig.server.walks;
    let reads = rig.fs.device().reads;
    assert_eq!(append(&mut rig, ROOT, h, 900), Err(p::code(p::NO_SPACE)));
    assert_eq!(append(&mut rig, ROOT, h, 900), Err(p::code(p::NO_SPACE)));
    assert_eq!(rig.fs.device().reads, reads, "no read, no walk");
    assert_eq!(rig.server.walks, settled);
}

#[test]
fn an_unlink_after_the_volume_is_full_is_seen_by_the_next_write() {
    let mut rig = Rig::new();
    fill_full(&mut rig);
    let h = rig
        .open(ROOT, b"/last", p::WRITE | p::CREATE, 0o644)
        .unwrap();
    let _ = append(&mut rig, ROOT, h, 900);
    assert_eq!(append(&mut rig, ROOT, h, 900), Err(p::code(p::NO_SPACE)));
    let walks = rig.server.walks;
    rig.ok(ROOT, |w| p::path_call(p::Method::Unlink, b"/d/fill0", w));
    assert_eq!(append(&mut rig, ROOT, h, 900), Ok(900));
    assert_eq!(rig.server.walks, walks + 1);
    // The walk saw all the blocks of the file: more than one write fits.
    assert_eq!(append(&mut rig, ROOT, h, 900), Ok(900));
    assert_eq!(rig.server.walks, walks + 1);
}

#[test]
fn a_growing_truncate_walks_for_the_blocks_an_unlink_gave_back() {
    let mut rig = Rig::new();
    fill_full(&mut rig);
    let h = rig
        .open(ROOT, b"/last", p::WRITE | p::CREATE, 0o644)
        .unwrap();
    let grow = |rig: &mut Rig, size: u64| rig.call(ROOT, |w| p::truncate(h, size, w));
    assert_eq!(grow(&mut rig, 100 << 10), Err(p::code(p::NO_SPACE)));
    let walks = rig.server.walks;
    let reads = rig.fs.device().reads;
    assert_eq!(grow(&mut rig, 100 << 10), Err(p::code(p::NO_SPACE)));
    assert_eq!(rig.fs.device().reads, reads);
    assert_eq!(rig.server.walks, walks);
    for n in 0..8 {
        let path = std::format!("/d/fill{n}");
        rig.ok(ROOT, |w| {
            p::path_call(p::Method::Unlink, path.as_bytes(), w)
        });
    }
    assert!(grow(&mut rig, 20 << 10).is_ok());
    assert_eq!(rig.server.walks, walks + 1);
}

#[test]
fn a_user_at_the_reserve_gets_no_space_without_a_walk_each_time() {
    let mut rig = Rig::new();
    rig.put(ROOT, b"/keep", 0o666, b"abc");
    fill_to_the_reserve(&mut rig);
    let h = rig.open(OWNER, b"/keep", p::WRITE, 0).unwrap();
    let far = |rig: &mut Rig| rig.call(OWNER, |w| p::pwrite(h, 100_000, b"x", w));
    assert_eq!(far(&mut rig), Err(p::code(p::NO_SPACE)));
    let walks = rig.server.walks;
    let reads = rig.fs.device().reads;
    assert_eq!(far(&mut rig), Err(p::code(p::NO_SPACE)));
    assert_eq!(rig.fs.device().reads, reads);
    assert_eq!(rig.server.walks, walks);
    // The superuser still writes into the reserve.
    let more = rig
        .open(ROOT, b"/d/more", p::WRITE | p::CREATE, 0o666)
        .unwrap();
    assert_eq!(rig.write(ROOT, more, &[2u8; 900]).unwrap(), 900);
}

#[test]
fn request_walks_cool_down_by_four_times_the_job_that_walked() {
    const T: u64 = 1_000_000;
    let mut rig = Rig::new();
    rig.server.set_mono(T);
    fill_full(&mut rig);
    let h = rig
        .open(ROOT, b"/last", p::WRITE | p::CREATE, 0o644)
        .unwrap();
    let _ = append(&mut rig, ROOT, h, 900);
    let _ = append(&mut rig, ROOT, h, 900);
    // The jobs above walked at T and ended 1,000 ns later: the next walk waits until T + 5,000.
    rig.server.set_mono(T + 1_000);
    rig.server.set_mono(T + 5_000);
    rig.ok(ROOT, |w| p::path_call(p::Method::Unlink, b"/d/fill0", w));
    let walks = rig.server.walks;
    assert_eq!(append(&mut rig, ROOT, h, 900), Ok(900));
    assert_eq!(rig.server.walks, walks + 1);
    // That job lasted 10 ns: the next walk waits until T + 5,010 + 40.
    rig.server.set_mono(T + 5_010);
    rig.ok(ROOT, |w| p::path_call(p::Method::Unlink, b"/d/fill1", w));
    // The blocks of the first file are used up, and those of the second are not seen yet.
    while append(&mut rig, ROOT, h, 900).is_ok() {}
    assert_eq!(
        rig.server.walks,
        walks + 1,
        "the cool-down holds the walk back"
    );
    rig.server.set_mono(T + 5_050);
    assert!(append(&mut rig, ROOT, h, 900).is_ok());
    assert_eq!(rig.server.walks, walks + 2);
}
