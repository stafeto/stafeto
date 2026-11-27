// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A data volume and a lower set in memory, for the tests of the service.

use crate::volume::{Lower, R, Visit, Volume};
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

    fn open(&mut self, path: &[u8], flags: u32, _mode: u32) -> R<u32> {
        self.check("open")?;
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
            let ino = self.fresh();
            self.nodes.insert(
                path.to_vec(),
                Node {
                    dir: false,
                    mode: 0o600,
                    uid: 0,
                    gid: 0,
                    ino,
                    data: Vec::new(),
                },
            );
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
            },
        );
        Ok(())
    }

    fn rename(&mut self, from: &[u8], to: &[u8]) -> R<()> {
        self.check("rename")?;
        let node = self.nodes.remove(from).ok_or(st(d::NO_ENTRY))?;
        self.nodes.insert(to.to_vec(), node);
        Ok(())
    }

    fn unlink(&mut self, path: &[u8]) -> R<()> {
        self.check("unlink")?;
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
    pub opened: usize,
    pub closed: usize,
}

pub struct LowerDir {
    entries: Vec<(u64, u32, Vec<u8>)>,
    pos: usize,
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
}

impl Lower for FakeLower {
    type Dir = LowerDir;

    fn open_dir(&mut self, path: &[u8]) -> R<LowerDir> {
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
        Ok(LowerDir { entries, pos: 0 })
    }

    fn next(&mut self, dir: &mut LowerDir, name: &mut [u8; 256]) -> R<Option<(u64, u32, usize)>> {
        let Some((ino, kind, n)) = dir.entries.get(dir.pos) else {
            return Ok(None);
        };
        dir.pos += 1;
        name[..n.len()].copy_from_slice(n);
        Ok(Some((*ino, *kind, n.len())))
    }

    fn close_dir(&mut self, _: LowerDir) {
        self.closed += 1;
    }

    fn readlink(&mut self, _: &[u8], _: &mut [u8]) -> R<usize> {
        Err(st(proto_fs::INVALID_ARGUMENT))
    }
}
