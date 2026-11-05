// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the tests of the library share: development keys, signed packages and
//! a model of the disk that loses what was not flushed.

use crate::commit::{Device, Failed};
use crate::store::BLOCK;
use pkgfmt::cert::PURPOSE_PACKAGES;
use pkgfmt::container::write::{Content, Item, container, sign};
use pkgfmt::meta::Meta;
use pkgfmt::{Certificate, Key, Name, sig};
use std::collections::BTreeMap;

pub const ROOT_SEED: [u8; 32] = [1; 32];
pub const RELEASE_SEED: [u8; 32] = [2; 32];
pub const OTHER_SEED: [u8; 32] = [3; 32];

pub fn name(text: &str) -> Name {
    Name::new(text).unwrap()
}

pub fn root() -> Key {
    Key {
        name: name("test-root"),
        public: sig::public_key(&ROOT_SEED),
    }
}

pub fn certificate() -> [u8; pkgfmt::cert::SIZE] {
    Certificate::issue(
        &ROOT_SEED,
        name("test-root"),
        name("test-release"),
        sig::public_key(&RELEASE_SEED),
        PURPOSE_PACKAGES,
        1000,
        3_000_000_000,
    )
    .to_bytes()
}

/// What `package` varies.
pub struct Spec<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub series: &'a str,
    pub depends: &'a str,
    pub provides: &'a str,
    pub seed: [u8; 32],
    pub key: &'a str,
    pub certified: bool,
    pub time: u64,
    pub padding: usize,
}

impl Default for Spec<'_> {
    fn default() -> Self {
        Spec {
            name: "hello",
            version: "1.0",
            series: crate::SERIES,
            depends: "-",
            provides: "-",
            seed: RELEASE_SEED,
            key: "test-release",
            certified: true,
            time: 1_800_000_000,
            padding: 0,
        }
    }
}

/// A signed package file with a program at `/opt/<name>/bin/<name>`.
pub fn package(spec: &Spec<'_>) -> Vec<u8> {
    let path = format!("/opt/{}/bin/{}", spec.name, spec.name);
    let (dir, bin) = (
        format!("/opt/{}", spec.name),
        format!("/opt/{}/bin", spec.name),
    );
    let program = [b"\x7fELF test program ".to_vec(), vec![7u8; spec.padding]].concat();
    let items = [
        Item {
            path: "/opt",
            mode: 0o040755,
            content: Content::Directory,
        },
        Item {
            path: &dir,
            mode: 0o040755,
            content: Content::Directory,
        },
        Item {
            path: &bin,
            mode: 0o040755,
            content: Content::Directory,
        },
        Item {
            path: &path,
            mode: 0o100755,
            content: Content::Data(&program),
        },
    ];
    let meta = Meta {
        name: spec.name,
        version: spec.version,
        release: "1",
        arch: "aarch64",
        series: spec.series,
        license: "MIT",
        depends: spec.depends,
        provides: spec.provides,
        needs: "-",
        summary: "A test package",
        url: "https://example.org/hello.tar.gz",
        sha256: &"0".repeat(64),
        recipe: &"1".repeat(64),
        commit: &"2".repeat(40),
        relibc: "-",
        size: 0,
    };
    let covered = container(&meta, &items, 1_700_000_000).unwrap();
    let certificate = spec.certified.then(certificate);
    sign(covered, &spec.seed, name(spec.key), certificate, spec.time).unwrap()
}

/// A model of the disk: blocks never written are zeros; a write is pending
/// until a flush; a crash after the `limit`-th operation loses what was
/// pending in the way `Loss` says.
pub struct ModelDisk {
    blocks: u64,
    kept: BTreeMap<u64, [u8; BLOCK]>,
    pending: Vec<(u64, [u8; BLOCK], bool)>,
    pub ops: usize,
    pub limit: Option<usize>,
    pub log: Vec<String>,
    /// Blocks whose read fails.
    pub bad: Vec<u64>,
}

/// What a power failure does to the writes that were not flushed.
#[derive(Clone, Copy, Debug)]
pub enum Loss {
    /// All are lost.
    All,
    /// All reach the medium.
    None,
    /// The writes whose bit is set in the mask reach it (bit i for pending
    /// write i); a write to block 0 or 1 that reaches it may tear at 512 bytes.
    Some(u64),
}

impl ModelDisk {
    pub fn new(blocks: u64) -> ModelDisk {
        ModelDisk {
            blocks,
            kept: BTreeMap::new(),
            pending: Vec::new(),
            ops: 0,
            limit: None,
            log: Vec::new(),
            bad: Vec::new(),
        }
    }

    fn step(&mut self, what: String) -> Result<(), Failed> {
        if self.limit.is_some_and(|l| self.ops >= l) {
            return Err(Failed);
        }
        self.ops += 1;
        self.log.push(what);
        Ok(())
    }

    /// The disk after a power failure: what the medium holds now, as a
    /// fresh model with no limit.
    pub fn after(&self, loss: Loss, tear: bool) -> ModelDisk {
        let mut kept = self.kept.clone();
        for (i, (block, data, _)) in self.pending.iter().enumerate() {
            let lands = match loss {
                Loss::All => false,
                Loss::None => true,
                Loss::Some(mask) => mask >> i & 1 == 1,
            };
            if !lands {
                continue;
            }
            if tear && *block < 2 {
                let old = kept.get(block).copied().unwrap_or([0; BLOCK]);
                let mut torn = old;
                torn[..512].copy_from_slice(&data[..512]);
                kept.insert(*block, torn);
            } else {
                kept.insert(*block, *data);
            }
        }
        ModelDisk {
            blocks: self.blocks,
            kept,
            pending: Vec::new(),
            ops: 0,
            limit: None,
            log: Vec::new(),
            bad: Vec::new(),
        }
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    pub fn peek(&self, block: u64) -> [u8; BLOCK] {
        self.pending
            .iter()
            .rev()
            .find(|(b, ..)| *b == block)
            .map(|(_, d, _)| *d)
            .or_else(|| self.kept.get(&block).copied())
            .unwrap_or([0; BLOCK])
    }
}

impl Device for ModelDisk {
    fn blocks(&self) -> u64 {
        self.blocks
    }

    fn read(&mut self, block: u64, out: &mut [u8; BLOCK]) -> Result<(), Failed> {
        if self.bad.contains(&block) {
            return Err(Failed);
        }
        *out = self.peek(block);
        Ok(())
    }

    fn write(&mut self, block: u64, data: &[u8; BLOCK]) -> Result<(), Failed> {
        self.step(format!("write {block}"))?;
        self.pending.push((block, *data, false));
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Failed> {
        self.step("flush".into())?;
        for (block, data, _) in self.pending.drain(..) {
            self.kept.insert(block, data);
        }
        Ok(())
    }
}

impl ModelDisk {
    /// The block as the disk holds it now, flushed or not.
    pub fn read_block(&self, block: u64, out: &mut [u8; BLOCK]) {
        *out = self.peek(block);
    }
}
