// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A store written on the host (pk3-design R17): the same format and the
//! same steps as the service's, over any `Device`. xtask writes the disk
//! file of the probe with it, so the probe starts from a store whose
//! contents it knows.

use crate::commit::{self, Device, Failed};
use crate::store::{
    BLOCK, Extent, PACKAGES, RECORDS, REVOKED_LIST, REVOKED_SLOT, Record, SETTINGS, SETTINGS_SLOT,
    Table, find_free, free_blocks, to_field,
};
use pkgfmt::{Package, sha::sha256};
use std::string::String;
use std::vec::Vec;

/// A package to put in the store, as a file, with what the service would
/// have recorded when it installed it.
pub struct Item {
    pub bytes: Vec<u8>,
    pub repository: String,
    pub flags: u8,
    pub installed: u64,
}

/// What the store holds.
#[derive(Default)]
pub struct Contents {
    pub packages: Vec<Item>,
    pub settings: Option<Vec<u8>>,
    /// The file of the revocation list (text, then the signature block) and its serial.
    pub revoked: Option<(Vec<u8>, u64)>,
    /// The repositories after the official one, with their serials.
    pub repositories: Vec<(String, u64)>,
}

/// What the writer made.
#[derive(Debug, PartialEq, Eq)]
pub struct Layout {
    pub generation: u64,
    pub blocks: u64,
    pub free: u64,
}

fn fail(what: &str) -> String {
    format!("store: {what}")
}

impl From<Failed> for String {
    fn from(_: Failed) -> String {
        fail("the device failed")
    }
}

fn put(dev: &mut impl Device, first: u64, bytes: &[u8]) -> Result<(), Failed> {
    for (i, chunk) in bytes.chunks(BLOCK).enumerate() {
        let mut block = [0u8; BLOCK];
        block[..chunk.len()].copy_from_slice(chunk);
        dev.write(first + i as u64, &block)?;
    }
    Ok(())
}

/// A new store in `dev`: formatted, then `contents` in one state.
pub fn write_store(dev: &mut impl Device, contents: &Contents) -> Result<Layout, String> {
    let mut table = Box::new(Table::zeroed());
    let opened = commit::format(dev, &mut table)?;
    let blocks = opened.superblock.blocks;
    let accepted = Table(table.0);
    table.set_repo(0, b"stafeto", 0);
    for (i, (name, serial)) in contents.repositories.iter().enumerate() {
        if !table.set_repo(i + 1, name.as_bytes(), *serial) {
            return Err(fail("a repository name"));
        }
    }
    let place = |table: &Table, blocks_needed: u64| -> Result<u64, String> {
        let mut list = [Extent {
            first: 0,
            blocks: 0,
        }; RECORDS + 1];
        let n = table.occupied(opened.table_extent(), &mut list);
        find_free(&list[..n], &[], blocks, blocks_needed).ok_or_else(|| fail("no room"))
    };
    for (i, item) in contents.packages.iter().enumerate() {
        if i >= PACKAGES {
            return Err(fail("more than 64 packages"));
        }
        let package = Package::parse(&item.bytes).map_err(|e| fail(&format!("a package: {e}")))?;
        let repo = table
            .find_repo(item.repository.as_bytes())
            .ok_or_else(|| fail("a repository that is not listed"))?;
        let need = (item.bytes.len() as u64).div_ceil(BLOCK as u64);
        let first = place(&table, need)?;
        put(dev, first, &item.bytes)?;
        let name = to_field(package.meta.name.as_bytes()).ok_or_else(|| fail("a long name"))?;
        let version =
            to_field(package.meta.version.as_bytes()).ok_or_else(|| fail("a long version"))?;
        table.set_record(
            i,
            &Record {
                kind: crate::store::PACKAGE,
                flags: item.flags,
                repo: repo as u8,
                first,
                blocks: need as u32,
                length: item.bytes.len() as u64,
                number: 0,
                installed: item.installed,
                sha256: sha256(&item.bytes),
                name,
                version,
            },
        );
    }
    for (slot, kind, bytes, number) in [
        (SETTINGS_SLOT, SETTINGS, contents.settings.as_deref(), 0),
        (
            REVOKED_SLOT,
            REVOKED_LIST,
            contents.revoked.as_ref().map(|(b, _)| b.as_slice()),
            contents.revoked.as_ref().map_or(0, |(_, s)| *s),
        ),
    ] {
        let Some(bytes) = bytes else { continue };
        let need = (bytes.len() as u64).div_ceil(BLOCK as u64);
        let first = place(&table, need)?;
        put(dev, first, bytes)?;
        table.set_record(
            slot,
            &Record {
                kind,
                flags: 0,
                repo: crate::store::NO_REPO,
                first,
                blocks: need as u32,
                length: bytes.len() as u64,
                number,
                installed: 0,
                sha256: sha256(bytes),
                name: [0; 64],
                version: [0; 64],
            },
        );
    }
    // F1: the data before the table that names it.
    dev.flush()?;
    table.set_generation(opened.superblock.generation + 1);
    let state = commit::publish(dev, &opened, &accepted, &table)?;
    let mut list = [Extent {
        first: 0,
        blocks: 0,
    }; RECORDS + 1];
    let n = table.occupied(state.table_extent(), &mut list);
    Ok(Layout {
        generation: state.superblock.generation,
        blocks,
        free: free_blocks(&list[..n], blocks),
    })
}

/// A device over a file: a read of a block never written is zeros.
pub struct FileDevice {
    pub file: std::fs::File,
    pub blocks: u64,
}

impl Device for FileDevice {
    fn blocks(&self) -> u64 {
        self.blocks
    }

    fn read(&mut self, block: u64, out: &mut [u8; BLOCK]) -> Result<(), Failed> {
        use std::os::unix::fs::FileExt;
        out.fill(0);
        let mut done = 0;
        while done < BLOCK {
            match self
                .file
                .read_at(&mut out[done..], block * BLOCK as u64 + done as u64)
            {
                Ok(0) => break,
                Ok(n) => done += n,
                Err(_) => return Err(Failed),
            }
        }
        Ok(())
    }

    fn write(&mut self, block: u64, data: &[u8; BLOCK]) -> Result<(), Failed> {
        use std::os::unix::fs::FileExt;
        self.file
            .write_all_at(data, block * BLOCK as u64)
            .map_err(|_| Failed)
    }

    fn flush(&mut self) -> Result<(), Failed> {
        self.file.sync_all().map_err(|_| Failed)
    }
}
