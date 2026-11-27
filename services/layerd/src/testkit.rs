// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A data volume and a lower set in memory, for the tests of the service.

use crate::volume::{Lower, LowerStat, R, Visit, Volume};
use proto_data as d;
use proto_wire::Status;
use std::collections::BTreeMap;
use std::string::String;
use std::vec::Vec;

fn st(code: u32) -> Status {
    Status::Unknown(code)
}

#[derive(Clone, Debug)]
pub struct Node {
    pub dir: bool,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub ino: u64,
    pub data: Vec<u8>,
    pub times: (i64, i64),
}

#[derive(Default)]
pub struct FakeVolume {
    pub nodes: BTreeMap<Vec<u8>, Node>,
    next_ino: u64,
    handles: BTreeMap<u32, (Vec<u8>, usize)>,
    next_handle: u32,
    /// The entries one batch of a listing holds.
    pub batch: usize,
    /// The calls made, by name.
    pub calls: Vec<String>,
    /// The paths and flags of the opens.
    pub opens: Vec<(Vec<u8>, u32)>,
    pub not_ready: bool,
}

impl FakeVolume {
    pub fn new() -> FakeVolume {
        let mut v = FakeVolume {
            next_ino: 10_000,
            next_handle: 1,
            batch: 3,
            ..Default::default()
        };
        v.nodes.insert(
            b"/".to_vec(),
            Node {
                dir: true,
                mode: 0o755,
                uid: 0,
                gid: 0,
                ino: 1,
                data: Vec::new(),
                times: (0, 0),
            },
        );
        v
    }

    pub fn dir(&mut self, path: &str, mode: u32, uid: u32) -> &mut Self {
        let ino = self.fresh();
        self.nodes.insert(
            path.as_bytes().to_vec(),
            Node {
                dir: true,
                mode,
                uid,
                gid: uid,
                ino,
                data: Vec::new(),
                times: (0, 0),
            },
        );
        self
    }

    pub fn file(&mut self, path: &str, mode: u32, uid: u32, data: &[u8]) -> &mut Self {
        let ino = self.fresh();
        self.file_numbered(path, mode, uid, ino, data)
    }

    pub fn file_numbered(
        &mut self,
        path: &str,
        mode: u32,
        uid: u32,
        ino: u64,
        data: &[u8],
    ) -> &mut Self {
        self.nodes.insert(
            path.as_bytes().to_vec(),
            Node {
                dir: false,
                mode,
                uid,
                gid: uid,
                ino,
                data: data.to_vec(),
                times: (0, 0),
            },
        );
        self
    }

    fn fresh(&mut self) -> u64 {
        self.next_ino += 1;
        self.next_ino
    }

    fn check(&mut self, call: &str) -> R<()> {
        self.calls.push(call.into());
        if self.not_ready {
            Err(st(d::NOT_READY))
        } else {
            Ok(())
        }
    }

    fn open_at(&mut self, path: &[u8], flags: u32, mode: u32, ino: Option<u64>) -> R<u32> {
        self.opens.push((path.to_vec(), flags));
        if !self.nodes.contains_key(path) {
            if flags & d::CREATE == 0 {
                return Err(st(d::NO_ENTRY));
            }
            let parent = match path.iter().rposition(|&b| b == b'/') {
                Some(0) => b"/".to_vec(),
                Some(i) => path[..i].to_vec(),
                None => return Err(st(d::INVALID)),
            };
            if !self.nodes.get(&parent).is_some_and(|n| n.dir) {
                return Err(st(d::NO_ENTRY));
            }
            let ino = ino.unwrap_or_else(|| self.fresh());
            self.nodes.insert(
                path.to_vec(),
                Node {
                    dir: false,
                    mode,
                    uid: 0,
                    gid: 0,
                    ino,
                    data: Vec::new(),
                    times: (0, 0),
                },
            );
        } else if flags & d::CREATE != 0 && flags & d::EXCLUSIVE != 0 {
            return Err(st(d::EXISTS));
        }
        let node = &self.nodes[path];
        if flags & d::DIRECTORY != 0 && !node.dir {
            return Err(st(d::NOT_DIRECTORY));
        }
        if flags & d::TRUNCATE != 0 {
            self.nodes.get_mut(path).unwrap().data.clear();
        }
        let h = self.next_handle;
        self.next_handle += 1;
        self.handles.insert(h, (path.to_vec(), 0));
        Ok(h)
    }

    pub fn children(&self, dir: &[u8]) -> Vec<(Vec<u8>, Node)> {
        let prefix: Vec<u8> = if dir == b"/" {
            b"/".to_vec()
        } else {
            [dir, b"/"].concat()
        };
        self.nodes
            .iter()
            .filter(|(p, _)| {
                p.len() > prefix.len()
                    && p.starts_with(&prefix)
                    && !p[prefix.len()..].contains(&b'/')
            })
            .map(|(p, n)| (p[prefix.len()..].to_vec(), n.clone()))
            .collect()
    }

    pub fn calls_of(&self, name: &str) -> usize {
        self.calls.iter().filter(|c| *c == name).count()
    }
}

fn stat_of(n: &Node) -> d::Stat {
    d::Stat {
        kind: if n.dir {
            d::KIND_DIRECTORY
        } else {
            d::KIND_FILE
        },
        mode: n.mode,
        uid: n.uid,
        gid: n.gid,
        size: n.data.len() as u64,
        ino: n.ino,
        atime: 1_000_000_000,
        mtime: 2_000_000_000,
        ctime: 3_000_000_000,
        nlink: 1,
    }
}

impl Volume for FakeVolume {
    type Pass = Vec<u8>;

    fn open(&mut self, path: &[u8], flags: u32, mode: u32) -> R<u32> {
        self.check("open")?;
        self.open_at(path, flags, mode, None)
    }

    fn open_numbered(&mut self, path: &[u8], flags: u32, mode: u32, ino: u64) -> R<u32> {
        self.check("open_numbered")?;
        if self.nodes.contains_key(path) {
            return Err(st(d::EXISTS));
        }
        self.open_at(path, flags, mode, Some(ino))
    }

    fn truncate(&mut self, handle: u32, size: u64) -> R<()> {
        self.check("truncate")?;
        let (path, _) = self.handles.get(&handle).ok_or(st(d::BAD_HANDLE))?;
        self.nodes
            .get_mut(path.as_slice())
            .unwrap()
            .data
            .resize(size as usize, 0);
        Ok(())
    }

    fn chmod(&mut self, path: &[u8], mode: u32) -> R<()> {
        self.check("chmod")?;
        self.nodes.get_mut(path).ok_or(st(d::NO_ENTRY))?.mode = mode;
        Ok(())
    }

    fn chown(&mut self, path: &[u8], uid: u32, gid: u32) -> R<()> {
        self.check("chown")?;
        let n = self.nodes.get_mut(path).ok_or(st(d::NO_ENTRY))?;
        if uid != d::UID_KEEP {
            n.uid = uid;
        }
        if gid != d::UID_KEEP {
            n.gid = gid;
        }
        // A change of owner clears the set-ID bits of a file.
        if !n.dir {
            n.mode &= !0o6000;
        }
        Ok(())
    }

    fn utimens(&mut self, path: &[u8], atime: i64, mtime: i64) -> R<()> {
        self.check("utimens")?;
        self.nodes.get_mut(path).ok_or(st(d::NO_ENTRY))?.times = (atime, mtime);
        Ok(())
    }

    fn close(&mut self, handle: u32) -> R<()> {
        self.check("close")?;
        self.handles
            .remove(&handle)
            .map(|_| ())
            .ok_or(st(d::BAD_HANDLE))
    }

    fn read(&mut self, handle: u32, out: &mut [u8]) -> R<usize> {
        self.check("read")?;
        let (path, pos) = self.handles.get_mut(&handle).ok_or(st(d::BAD_HANDLE))?;
        let data = &self.nodes[path.as_slice()].data;
        let n = out.len().min(data.len().saturating_sub(*pos));
        out[..n].copy_from_slice(&data[*pos..*pos + n]);
        *pos += n;
        Ok(n)
    }

    fn write(&mut self, handle: u32, bytes: &[u8]) -> R<usize> {
        self.check("write")?;
        let (path, _) = self.handles.get(&handle).ok_or(st(d::BAD_HANDLE))?;
        self.nodes
            .get_mut(path.as_slice())
            .unwrap()
            .data
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn fsync(&mut self, _: u32) -> R<()> {
        self.check("fsync")
    }

    fn stat(&mut self, path: &[u8]) -> R<d::Stat> {
        self.check("stat")?;
        self.nodes.get(path).map(stat_of).ok_or(st(d::NO_ENTRY))
    }

    fn mkdir(&mut self, path: &[u8], mode: u32) -> R<()> {
        self.check("mkdir")?;
        if self.nodes.contains_key(path) {
            return Err(st(d::EXISTS));
        }
        let parent = match path.iter().rposition(|&b| b == b'/') {
            Some(0) => b"/".to_vec(),
            Some(i) => path[..i].to_vec(),
            None => return Err(st(d::INVALID)),
        };
        if !self.nodes.get(&parent).is_some_and(|n| n.dir) {
            return Err(st(d::NO_ENTRY));
        }
        let ino = self.fresh();
        self.nodes.insert(
            path.to_vec(),
            Node {
                dir: true,
                mode,
                uid: 0,
                gid: 0,
                ino,
                data: Vec::new(),
                times: (0, 0),
            },
        );
        Ok(())
    }

    fn rename(&mut self, from: &[u8], to: &[u8]) -> R<()> {
        self.check("rename")?;
        let node = self.nodes.get(from).cloned().ok_or(st(d::NO_ENTRY))?;
        if let Some(over) = self.nodes.get(to) {
            if node.dir != over.dir {
                return Err(st(if over.dir {
                    d::IS_DIRECTORY
                } else {
                    d::NOT_DIRECTORY
                }));
            }
            if over.dir && !self.children(to).is_empty() {
                return Err(st(d::NOT_EMPTY));
            }
        }
        // A directory takes everything below it along.
        let prefix = [from, b"/"].concat();
        let below: Vec<Vec<u8>> = self
            .nodes
            .keys()
            .filter(|k| k.starts_with(&prefix))
            .cloned()
            .collect();
        for old in below {
            let n = self.nodes.remove(&old).unwrap();
            let mut new = to.to_vec();
            new.extend_from_slice(&old[from.len()..]);
            self.nodes.insert(new, n);
        }
        self.nodes.remove(from);
        self.nodes.insert(to.to_vec(), node);
        Ok(())
    }

    fn unlink(&mut self, path: &[u8]) -> R<()> {
        self.check("unlink")?;
        if self.nodes.get(path).is_some_and(|n| n.dir) {
            return Err(st(d::IS_DIRECTORY));
        }
        self.nodes.remove(path).map(|_| ()).ok_or(st(d::NO_ENTRY))
    }

    fn rmdir(&mut self, path: &[u8]) -> R<()> {
        self.check("rmdir")?;
        if !self.children(path).is_empty() {
            return Err(st(d::NOT_EMPTY));
        }
        self.nodes.remove(path).map(|_| ()).ok_or(st(d::NO_ENTRY))
    }

    fn read_dir(&mut self, handle: u32, visit: Visit<'_>) -> R<bool> {
        self.check("read_dir")?;
        let batch = self.batch;
        let (path, pos) = self
            .handles
            .get(&handle)
            .cloned()
            .ok_or(st(d::BAD_HANDLE))?;
        let mut all: Vec<(Vec<u8>, u64, u32)> = vec![
            (b".".to_vec(), 0, d::KIND_DIRECTORY),
            (b"..".to_vec(), 0, d::KIND_DIRECTORY),
        ];
        for (name, n) in self.children(&path) {
            all.push((
                name,
                n.ino,
                if n.dir {
                    d::KIND_DIRECTORY
                } else {
                    d::KIND_FILE
                },
            ));
        }
        let end = (pos + batch).min(all.len());
        for (name, ino, kind) in &all[pos..end] {
            visit(*ino, *kind, name);
        }
        self.handles.get_mut(&handle).unwrap().1 = end;
        Ok(end < all.len())
    }

    fn export(&mut self, handle: u32) -> R<Vec<u8>> {
        self.check("export")?;
        let (path, _) = self.handles.get(&handle).ok_or(st(d::BAD_HANDLE))?;
        Ok(path.clone())
    }
}

/// A lower set: nodes by path, a directory listing by its children.
#[derive(Default)]
pub struct FakeLower {
    pub nodes: BTreeMap<Vec<u8>, (u32, u64)>,
    /// The mode, owner and group of a name; 0755 or 0644 and user 0 where none is set.
    pub attrs: BTreeMap<Vec<u8>, (u32, u32, u32)>,
    pub stats: usize,
    pub opened: usize,
    pub closed: usize,
    /// The entries `next` gave (and the ones it found at the end), for the cost of a request.
    pub nexts: usize,
    /// The polls an open or a stat answers None to before its answer, as the steps of the RAM
    /// file service do.
    pub delay: u32,
    /// The polls made, the preparations in flight and the most that were, and the ones given back
    /// before their answer.
    pub polls: usize,
    pub live: usize,
    pub most: usize,
    pub cancelled: usize,
}

pub struct LowerDir {
    entries: Vec<(u64, u32, Vec<u8>)>,
    pos: usize,
    /// The polls left before the open is done; None once it is.
    opening: Option<(Vec<u8>, u32)>,
}

/// A stat in flight.
pub struct FakeProbe {
    path: Vec<u8>,
    left: u32,
    spent: bool,
}

impl FakeLower {
    pub fn new() -> FakeLower {
        let mut l = FakeLower::default();
        l.nodes.insert(b"/".to_vec(), (1, 1));
        l
    }

    pub fn dir(&mut self, path: &str, ino: u64) -> &mut Self {
        self.nodes.insert(path.as_bytes().to_vec(), (1, ino));
        self
    }

    pub fn file(&mut self, path: &str, ino: u64) -> &mut Self {
        self.nodes.insert(path.as_bytes().to_vec(), (2, ino));
        self
    }

    pub fn link(&mut self, path: &str, ino: u64) -> &mut Self {
        self.nodes.insert(path.as_bytes().to_vec(), (5, ino));
        self
    }

    pub fn attr(&mut self, path: &str, mode: u32, uid: u32, gid: u32) -> &mut Self {
        self.attrs
            .insert(path.as_bytes().to_vec(), (mode, uid, gid));
        self
    }
}

impl FakeLower {
    fn begin(&mut self) {
        self.live += 1;
        self.most = self.most.max(self.live);
    }

    fn open_now(&mut self, path: &[u8]) -> R<Vec<(u64, u32, Vec<u8>)>> {
        match self.nodes.get(path) {
            None => return Err(st(proto_fs::NO_ENTRY)),
            Some((2, _)) => return Err(st(proto_fs::NOT_DIRECTORY)),
            _ => {}
        }
        self.opened += 1;
        let prefix: Vec<u8> = if path == b"/" {
            b"/".to_vec()
        } else {
            [path, b"/"].concat()
        };
        let mut entries = vec![(1, 1, b".".to_vec()), (1, 1, b"..".to_vec())];
        for (p, (kind, ino)) in &self.nodes {
            if p.len() > prefix.len()
                && p.starts_with(&prefix)
                && !p[prefix.len()..].contains(&b'/')
            {
                entries.push((*ino, *kind, p[prefix.len()..].to_vec()));
            }
        }
        Ok(entries)
    }

    fn stat_now(&mut self, path: &[u8]) -> R<LowerStat> {
        self.stats += 1;
        // A name below a file or a link is no name.
        let mut at = 0;
        while let Some(i) = path[at + 1..].iter().position(|&b| b == b'/') {
            at += 1 + i;
            if matches!(self.nodes.get(&path[..at]), Some((k, _)) if *k != 1) {
                return Err(st(proto_fs::NOT_DIRECTORY));
            }
        }
        let (kind, ino) = *self.nodes.get(path).ok_or(st(proto_fs::NO_ENTRY))?;
        let (mode, uid, gid) =
            self.attrs
                .get(path)
                .copied()
                .unwrap_or((if kind == 1 { 0o755 } else { 0o644 }, 0, 0));
        Ok(LowerStat {
            kind,
            mode,
            uid,
            gid,
            ino,
        })
    }
}

impl Lower for FakeLower {
    type Dir = LowerDir;
    type Probe = FakeProbe;

    fn open_dir_start(&mut self, path: &[u8]) -> R<LowerDir> {
        self.begin();
        Ok(LowerDir {
            entries: Vec::new(),
            pos: 0,
            opening: Some((path.to_vec(), self.delay)),
        })
    }

    fn open_dir_poll(&mut self, dir: &mut LowerDir) -> R<bool> {
        let Some((path, left)) = dir.opening.as_mut() else {
            return Ok(true);
        };
        self.polls += 1;
        if *left > 0 {
            *left -= 1;
            return Ok(false);
        }
        let path = std::mem::take(path);
        dir.opening = None;
        self.live -= 1;
        dir.entries = self.open_now(&path)?;
        Ok(true)
    }

    fn next(&mut self, dir: &mut LowerDir, name: &mut [u8; 256]) -> R<Option<(u64, u32, usize)>> {
        assert!(dir.opening.is_none(), "next on a directory being opened");
        self.nexts += 1;
        let Some((ino, kind, n)) = dir.entries.get(dir.pos) else {
            return Ok(None);
        };
        dir.pos += 1;
        name[..n.len()].copy_from_slice(n);
        Ok(Some((*ino, *kind, n.len())))
    }

    fn close_dir(&mut self, dir: LowerDir) {
        if dir.opening.is_some() {
            self.live -= 1;
            self.cancelled += 1;
        } else {
            self.closed += 1;
        }
    }

    fn readlink(&mut self, _: &[u8], _: &mut [u8]) -> R<usize> {
        Err(st(proto_fs::INVALID_ARGUMENT))
    }

    fn stat_start(&mut self, path: &[u8], _follow: bool) -> R<FakeProbe> {
        self.begin();
        Ok(FakeProbe {
            path: path.to_vec(),
            left: self.delay,
            spent: false,
        })
    }

    fn stat_poll(&mut self, probe: &mut FakeProbe) -> R<Option<LowerStat>> {
        assert!(!probe.spent, "poll of a spent stat");
        self.polls += 1;
        if probe.left > 0 {
            probe.left -= 1;
            return Ok(None);
        }
        probe.spent = true;
        self.live -= 1;
        self.stat_now(&probe.path.clone()).map(Some)
    }

    fn stat_cancel(&mut self, probe: FakeProbe) {
        if !probe.spent {
            self.live -= 1;
            self.cancelled += 1;
        }
    }
}

/// The names of the volume of the scale probe (`xtask::data_image::layer_steps_entries`: 8,192
/// names, the chain of 246 directories, `/long`, `/etc` with 1,024 files, `d00` and on) and, as
/// that volume has them after the part that adds the marks, `/opq` and `/marks` with `marks` marks.
/// Each name is inserted in the index in the order the build lists them: the directory, the id, the
/// name and the id it got.
pub fn scale_set(
    ix: &mut crate::index::Index,
    marks: usize,
) -> Result<Vec<(u32, Vec<u8>, u32)>, crate::index::Error> {
    use crate::index::{Fields, Kind};
    let fields = |kind| Fields {
        kind,
        layer: 0,
        number: 1,
        uid: 0,
        gid: 0,
        mode: 0o755,
    };
    let mut out = Vec::new();
    let mut put = |ix: &mut crate::index::Index,
                   parent: u32,
                   name: &str,
                   kind: Kind|
     -> Result<u32, crate::index::Error> {
        let id = ix.insert_shallow(parent, name.as_bytes(), fields(kind))?;
        out.push((parent, name.as_bytes().to_vec(), id));
        Ok(id)
    };
    let mut names = 0;
    let mut at = 0;
    for _ in 0..246 {
        at = put(ix, at, "a", Kind::Dir)?;
        names += 1;
    }
    put(ix, at, "f", Kind::File)?;
    names += 1;
    let long = put(ix, 0, "long", Kind::Dir)?;
    put(ix, long, &"n".repeat(200), Kind::File)?;
    names += 2;
    let etc = put(ix, 0, "etc", Kind::Dir)?;
    names += 1;
    for k in 0..1024 {
        put(ix, etc, &std::format!("x{k:04}"), Kind::File)?;
        names += 1;
    }
    let mut d = 0;
    while names < 8192 {
        let dir = put(ix, 0, &std::format!("d{d:02}"), Kind::Dir)?;
        names += 1;
        let mut k = 0;
        while k < 1024 && names < 8192 {
            put(ix, dir, &std::format!("n{k:04}"), Kind::File)?;
            names += 1;
            k += 1;
        }
        d += 1;
    }
    put(ix, 0, "opq", Kind::Dir)?;
    let dir = put(ix, 0, "marks", Kind::Dir)?;
    for k in 0..marks {
        put(ix, dir, &std::format!("m{k:04}"), Kind::Whiteout)?;
    }
    Ok(out)
}
