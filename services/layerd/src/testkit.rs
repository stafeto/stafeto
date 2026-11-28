// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A data volume and a lower set in memory, for the tests of the service.

use crate::volume::{Bulk, CELL, Lower, LowerStat, R, Visit, Volume};
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

    fn mkdir_at(&mut self, path: &[u8], mode: u32, number: Option<u64>) -> R<()> {
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
        let ino = number.unwrap_or_else(|| self.fresh());
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

    pub fn handle_path(&self, handle: u32) -> Option<Vec<u8>> {
        self.handles.get(&handle).map(|(p, _)| p.clone())
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
        self.mkdir_at(path, mode, None)
    }

    fn mkdir_numbered(&mut self, path: &[u8], mode: u32, ino: u64) -> R<()> {
        self.check("mkdir_numbered")?;
        self.mkdir_at(path, mode, Some(ino))
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
    /// The answers that come back as stale after the delay (the tree changed under the resolve):
    /// the poll says None again, and the delay runs once more.
    pub stale: u32,
    /// The preparations the session holds at most (0 for no limit): a start past it is refused
    /// with TOO_MANY_OPEN_FILES.
    pub limit: usize,
    /// The poll after which a resolve fails with INVALID_ARGUMENT, counted over all of them.
    pub fail_at: Option<usize>,
    /// The bytes of a file, the text of a link, and the times of a name (access and modification,
    /// nanoseconds; 4,000 and 5,000 where none is set).
    pub data: BTreeMap<Vec<u8>, Vec<u8>>,
    pub texts: BTreeMap<Vec<u8>, Vec<u8>>,
    pub times: BTreeMap<Vec<u8>, (i64, i64)>,
    /// The reads of links in flight, as the stats are.
    pub links: usize,
    /// The GUARD requests the lower set got.
    pub guards: usize,
}

/// A read of a link in flight.
pub struct FakeLink {
    path: Vec<u8>,
    left: u32,
    spent: bool,
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

    pub fn bytes(&mut self, path: &str, data: &[u8]) -> &mut Self {
        self.data.insert(path.as_bytes().to_vec(), data.to_vec());
        self
    }

    pub fn text(&mut self, path: &str, text: &str) -> &mut Self {
        self.texts
            .insert(path.as_bytes().to_vec(), text.as_bytes().to_vec());
        self
    }

    pub fn times_of(&mut self, path: &str, atime: i64, mtime: i64) -> &mut Self {
        self.times.insert(path.as_bytes().to_vec(), (atime, mtime));
        self
    }

    pub fn attr(&mut self, path: &str, mode: u32, uid: u32, gid: u32) -> &mut Self {
        self.attrs
            .insert(path.as_bytes().to_vec(), (mode, uid, gid));
        self
    }
}

impl FakeLower {
    fn begin(&mut self) -> R<()> {
        if self.limit != 0 && self.live >= self.limit {
            return Err(st(proto_fs::TOO_MANY_OPEN_FILES));
        }
        self.live += 1;
        self.most = self.most.max(self.live);
        Ok(())
    }

    /// Whether this poll is the one that fails.
    fn failing(&self) -> bool {
        self.fail_at == Some(self.polls)
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
        let (atime, mtime) = self.times.get(path).copied().unwrap_or((4_000, 5_000));
        Ok(LowerStat {
            kind,
            mode,
            uid,
            gid,
            ino,
            atime,
            mtime,
        })
    }
}

impl Lower for FakeLower {
    type Dir = LowerDir;
    type Probe = FakeProbe;
    type Link = FakeLink;

    fn guard(&mut self) -> R<()> {
        self.guards += 1;
        Ok(())
    }

    fn open_dir_start(&mut self, path: &[u8]) -> R<LowerDir> {
        self.begin()?;
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
        if self.fail_at == Some(self.polls) {
            dir.opening = None;
            self.live -= 1;
            return Err(st(proto_fs::INVALID_ARGUMENT));
        }
        if *left > 0 {
            *left -= 1;
            return Ok(false);
        }
        if self.stale > 0 {
            self.stale -= 1;
            *left = self.delay;
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

    fn readlink_start(&mut self, path: &[u8]) -> R<FakeLink> {
        self.begin()?;
        self.links += 1;
        Ok(FakeLink {
            path: path.to_vec(),
            left: self.delay,
            spent: false,
        })
    }

    fn readlink_poll(&mut self, link: &mut FakeLink, out: &mut [u8; 512]) -> R<Option<usize>> {
        assert!(!link.spent, "poll of a spent read");
        self.polls += 1;
        if link.left > 0 {
            link.left -= 1;
            return Ok(None);
        }
        link.spent = true;
        self.live -= 1;
        match (self.nodes.get(&link.path), self.texts.get(&link.path)) {
            (Some((5, _)), Some(text)) => {
                out[..text.len()].copy_from_slice(text);
                Ok(Some(text.len()))
            }
            (None, _) => Err(st(proto_fs::NO_ENTRY)),
            _ => Err(st(proto_fs::INVALID_ARGUMENT)),
        }
    }

    fn readlink_cancel(&mut self, link: FakeLink) {
        if !link.spent {
            self.live -= 1;
            self.cancelled += 1;
        }
    }

    fn stat_start(&mut self, path: &[u8], _follow: bool) -> R<FakeProbe> {
        self.begin()?;
        Ok(FakeProbe {
            path: path.to_vec(),
            left: self.delay,
            spent: false,
        })
    }

    fn stat_poll(&mut self, probe: &mut FakeProbe) -> R<Option<LowerStat>> {
        assert!(!probe.spent, "poll of a spent stat");
        self.polls += 1;
        if self.failing() {
            probe.spent = true;
            self.live -= 1;
            return Err(st(proto_fs::INVALID_ARGUMENT));
        }
        if probe.left > 0 {
            probe.left -= 1;
            return Ok(None);
        }
        if self.stale > 0 {
            self.stale -= 1;
            probe.left = self.delay;
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

/// The calls of a copy over the tree of the volume and the lower set the test holds (`Core`'s own
/// two), with a cell of its own.
pub struct FakeBulk<'a> {
    pub volume: &'a mut FakeVolume,
    pub lower: &'a mut FakeLower,
    pub cell: Vec<u8>,
    fds: BTreeMap<u32, Vec<u8>>,
    next: u32,
    /// The calls made, by name, and the reads of the lower file as (offset, count).
    pub calls: Vec<String>,
    pub reads: Vec<(u64, usize)>,
    /// The call that fails (by name), with the status.
    pub fail: Option<(&'static str, Status)>,
    /// The writes of a cell, as (offset, count).
    pub writes: Vec<(u64, usize)>,
    /// A write that stops short: the count it does (None for all).
    pub short: Option<usize>,
}

impl<'a> FakeBulk<'a> {
    pub fn new(volume: &'a mut FakeVolume, lower: &'a mut FakeLower) -> FakeBulk<'a> {
        FakeBulk {
            volume,
            lower,
            cell: vec![0; CELL],
            fds: BTreeMap::new(),
            next: 1,
            calls: Vec::new(),
            reads: Vec::new(),
            fail: None,
            writes: Vec::new(),
            short: None,
        }
    }

    fn call(&mut self, name: &'static str) -> R<()> {
        self.calls.push(name.into());
        match self.fail {
            Some((n, status)) if n == name => Err(status),
            _ => Ok(()),
        }
    }

    pub fn open_fds(&self) -> usize {
        self.fds.len()
    }
}

impl Bulk for FakeBulk<'_> {
    fn open_lower(&mut self, path: &[u8]) -> R<u32> {
        self.call("open_lower")?;
        match self.lower.nodes.get(path) {
            Some((2, _)) => {}
            Some(_) => return Err(st(proto_fs::INVALID_ARGUMENT)),
            None => return Err(st(proto_fs::NO_ENTRY)),
        }
        let fd = self.next;
        self.next += 1;
        self.fds.insert(fd, path.to_vec());
        Ok(fd)
    }

    fn read_lower(&mut self, fd: u32, offset: u64, at: usize, len: usize) -> R<usize> {
        self.call("read_lower")?;
        assert!(len <= proto_fs::READ_PORTION && at.is_multiple_of(4096) && at + len <= CELL);
        self.reads.push((offset, len));
        let path = self.fds.get(&fd).ok_or(st(proto_fs::BAD_FD))?;
        let data = self.lower.data.get(path).map(Vec::as_slice).unwrap_or(&[]);
        let from = (offset as usize).min(data.len());
        let n = len.min(data.len() - from);
        self.cell[at..at + n].copy_from_slice(&data[from..from + n]);
        Ok(n)
    }

    fn cell(&self) -> &[u8] {
        &self.cell
    }

    fn close_lower(&mut self, fd: u32) {
        let _ = self.call("close_lower");
        self.fds.remove(&fd);
    }

    fn open_work(&mut self, path: &[u8], mode: u32, ino: u64) -> R<u32> {
        self.call("open_work")?;
        self.volume
            .open_numbered(path, d::WRITE | d::CREATE | d::EXCLUSIVE, mode, ino)
    }

    fn write_cell(&mut self, handle: u32, offset: u64, count: usize) -> R<usize> {
        self.call("write_cell")?;
        self.writes.push((offset, count));
        let count = self.short.map_or(count, |s| s.min(count));
        let path = self.volume.handle_path(handle).ok_or(st(d::BAD_HANDLE))?;
        let node = self.volume.nodes.get_mut(&path).ok_or(st(d::NO_ENTRY))?;
        assert_eq!(node.data.len() as u64, offset, "the cells go in order");
        node.data.extend_from_slice(&self.cell[..count]);
        Ok(count)
    }

    fn fsync(&mut self, handle: u32) -> R<()> {
        self.call("fsync")?;
        self.volume.fsync(handle)
    }

    fn chown(&mut self, path: &[u8], uid: u32, gid: u32) -> R<()> {
        self.call("chown")?;
        self.volume.chown(path, uid, gid)
    }

    fn chmod(&mut self, path: &[u8], mode: u32) -> R<()> {
        self.call("chmod")?;
        self.volume.chmod(path, mode)
    }

    fn utimens(&mut self, path: &[u8], atime: i64, mtime: i64) -> R<()> {
        self.call("utimens")?;
        self.volume.utimens(path, atime, mtime)
    }

    fn close(&mut self, handle: u32) -> R<()> {
        self.call("close")?;
        self.volume.close(handle)
    }
}
