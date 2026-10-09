// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Directory positions are boundaries within an exact shared open description.
//! Paid reads retain one immutable prefix and one cursor/atime effect.

use crate::{
    DIR, Fds, Ram,
    authority::Identity,
    io::Held,
    storage::{Root, Token},
};
use proto_fs::{
    BAD_FD, INVALID_ARGUMENT, MAX_READ, NOT_DIRECTORY, RESOLVING, STALE_PROOF, Timestamp,
    WRITE_ONLY,
};

/// Both target C layouts use the observed 64-bit inode/offset and 16-bit reclen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryFormat {
    Linux64,
    PosixDent,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryOutcome {
    Bytes { count: u16, next: i64 },
    Failed(u32),
}
type DirectoryRow<'a> = (u64, &'a [u8], Token);

#[derive(Clone, Copy)]
struct Candidate {
    cookie: u64,
    row: u16,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Scan,
    Copy,
    Ready,
    Committed,
    Canceled,
}
pub struct DirectoryJournal {
    identity: Identity,
    root: Root,
    charge: u16,
    node: Token,
    epoch: u64,
    /// The generation of the directory when the read began: a change of its names ends the read.
    dir_gen: u64,
    held: Option<Held>,
    format: DirectoryFormat,
    limit: u16,
    phase: Phase,
    scan: u16,
    selected: [Option<Candidate>; 3],
    copied: u8,
    output: [u8; MAX_READ],
    used: u16,
    next: i64,
    outcome: Option<DirectoryOutcome>,
}
impl Ram<'_> {
    /// A paid read captures the exact shared description and its cursor once.
    pub fn prepare_directory(
        &mut self,
        fds: &Fds,
        fd: u32,
        charge: u16,
        identity: Identity,
        limit: usize,
        format: DirectoryFormat,
    ) -> Result<DirectoryJournal, u32> {
        self.storage.namespace_charge(fds.root, charge)?;
        if limit > MAX_READ {
            return Err(INVALID_ARGUMENT);
        }
        let open = self.get(fds, fd)?;
        if !open.file.is_directory() {
            return Err(NOT_DIRECTORY);
        }
        if open.flags & 3 == WRITE_ONLY {
            return Err(BAD_FD);
        }
        if open.offset < 0 {
            return Err(INVALID_ARGUMENT);
        }
        let node = self.token(open.file);
        let held = self.io_retain(fds, fd)?;
        Ok(DirectoryJournal {
            identity,
            root: fds.root,
            charge,
            node,
            epoch: self.storage.state.epoch,
            dir_gen: self.storage.name_gen(node)?,
            held: Some(held),
            format,
            limit: limit as u16,
            phase: Phase::Scan,
            scan: 0,
            selected: [None; 3],
            copied: 0,
            output: [0; MAX_READ],
            used: 0,
            next: open.offset,
            outcome: None,
        })
    }
    /// A directory cookie is the boundary preceding the next emitted entry.
    pub fn directory_seek(&mut self, fds: &Fds, fd: u32, cookie: i64) -> Result<i64, u32> {
        let mut open = self.get(fds, fd)?;
        if !open.file.is_directory() {
            return Err(NOT_DIRECTORY);
        }
        if cookie < 0 {
            return Err(INVALID_ARGUMENT);
        }
        open.offset = cookie;
        self.put(fds, fd, open)?;
        Ok(cookie)
    }
    fn directory_row(&self, node: Token, row: usize) -> Result<Option<DirectoryRow<'_>>, u32> {
        let current = self.storage.node(node)?;
        Ok(match row {
            0 => Some((1, b".", node)),
            1 => Some((2, b"..", current.parent)),
            _ => self.storage.directory_entry(node, row - 2),
        })
    }
}
impl DirectoryJournal {
    pub fn outcome(&self) -> Option<DirectoryOutcome> {
        self.outcome
    }
    pub fn bytes(&self) -> Result<&[u8], u32> {
        if !matches!(self.outcome, Some(DirectoryOutcome::Bytes { .. })) {
            return Err(RESOLVING);
        }
        Ok(&self.output[..self.used as usize])
    }
    fn check(&self, ram: &Ram<'_>, identity: Identity) -> Result<(), u32> {
        if self.phase == Phase::Canceled
            || self.identity != identity
            || self.epoch != ram.storage.state.epoch
            || ram.storage.name_gen(self.node)? != self.dir_gen
        {
            return Err(STALE_PROOF);
        }
        ram.storage.namespace_charge(self.root, self.charge)?;
        ram.io_validate(self.held.as_ref().ok_or(STALE_PROOF)?)
    }
    fn select(&mut self, candidate: Candidate) {
        let Some(at) = self
            .selected
            .iter()
            .position(|slot| slot.is_none_or(|old| candidate.cookie < old.cookie))
        else {
            return;
        };
        for i in (at + 1..self.selected.len()).rev() {
            self.selected[i] = self.selected[i - 1];
        }
        self.selected[at] = Some(candidate);
    }
    /// Scan eight rows or copy one selected record into the resident prefix.
    pub fn step(&mut self, ram: &Ram<'_>, identity: Identity) -> Result<bool, u32> {
        if self.outcome.is_some() {
            return Ok(true);
        }
        self.check(ram, identity)?;
        match self.phase {
            Phase::Scan => {
                let end = (self.scan as usize + 8).min(ram.storage.entries() + 2);
                while (self.scan as usize) < end {
                    let row = self.scan;
                    self.scan += 1;
                    if let Some((cookie, _, _)) = ram.directory_row(self.node, row as usize)?
                        && cookie > self.held.as_ref().unwrap().open.offset as u64
                    {
                        self.select(Candidate { cookie, row });
                    }
                }
                if self.scan as usize == ram.storage.entries() + 2 {
                    self.phase = Phase::Copy;
                }
                Ok(false)
            }
            Phase::Copy => {
                let Some(candidate) = self.selected.get(self.copied as usize).copied().flatten()
                else {
                    self.phase = Phase::Ready;
                    return Ok(true);
                };
                let (cookie, name, target) = ram
                    .directory_row(self.node, candidate.row as usize)?
                    .ok_or(STALE_PROOF)?;
                if cookie != candidate.cookie {
                    return Err(STALE_PROOF);
                }
                let required = record_length(self.format, name.len())?;
                if self.used as usize + required > self.limit as usize {
                    if self.used == 0 {
                        return Err(INVALID_ARGUMENT);
                    }
                    self.phase = Phase::Ready;
                    return Ok(true);
                }
                let file = ram.file(target);
                let inode = ram.inode(file);
                let kind = ram.storage.node(target)?.kind;
                let start = self.used as usize;
                encode_record(
                    self.format,
                    inode,
                    cookie,
                    kind,
                    name,
                    &mut self.output[start..start + required],
                )?;
                self.used += required as u16;
                self.next = cookie as i64;
                self.copied += 1;
                Ok(false)
            }
            Phase::Ready => Ok(true),
            _ => Err(STALE_PROOF),
        }
    }
    /// Cursor and atime change together after every fallible validation.
    /// The caller supplies one trusted Clock observation and checks owner/image/stamp.
    pub fn commit(
        &mut self,
        ram: &mut Ram<'_>,
        identity: Identity,
        now: Timestamp,
    ) -> Result<DirectoryOutcome, u32> {
        if let Some(outcome) = self.outcome {
            return Ok(outcome);
        }
        self.check(ram, identity)?;
        if self.phase != Phase::Ready {
            return Err(RESOLVING);
        }
        if !now.valid() {
            return Err(INVALID_ARGUMENT);
        }
        ram.storage.node(self.node)?;
        let held = self.held.as_mut().unwrap();
        let description = held.description();
        let shared = ram.descriptions[description.slot as usize]
            .as_mut()
            .expect("retained directory description");
        shared.open.offset = self.next;
        held.open.offset = self.next;
        ram.storage
            .node_mut(self.node)
            .expect("retained directory inode")
            .times[0] = now;
        let outcome = DirectoryOutcome::Bytes {
            count: self.used,
            next: self.next,
        };
        self.outcome = Some(outcome);
        self.phase = Phase::Committed;
        Ok(outcome)
    }
    pub fn cancel_step(&mut self, ram: &mut Ram<'_>) -> bool {
        if let Some(held) = self.held.take() {
            ram.io_release(held);
        }
        self.phase = Phase::Canceled;
        true
    }
}
fn record_length(format: DirectoryFormat, name: usize) -> Result<usize, u32> {
    match format {
        DirectoryFormat::Linux64 | DirectoryFormat::PosixDent => {
            if name > 255 {
                return Err(INVALID_ARGUMENT);
            }
            Ok((19 + name + 1).next_multiple_of(8))
        }
    }
}
fn encode_record(
    format: DirectoryFormat,
    inode: u64,
    cookie: u64,
    kind: u32,
    name: &[u8],
    out: &mut [u8],
) -> Result<(), u32> {
    if cookie > i64::MAX as u64
        || name.contains(&0)
        || out.len() != record_length(format, name.len())?
    {
        return Err(INVALID_ARGUMENT);
    }
    let dtype = match kind {
        DIR => 4,
        crate::REG => 8,
        crate::CHAR => 2,
        crate::storage::SYMLINK => 10,
        _ => 0,
    };
    out.fill(0);
    out[..8].copy_from_slice(&inode.to_le_bytes());
    out[8..16].copy_from_slice(&cookie.to_le_bytes());
    let length = out.len() as u16;
    out[16..18].copy_from_slice(&length.to_le_bytes());
    out[18] = dtype;
    out[19..19 + name.len()].copy_from_slice(name);
    Ok(())
}

#[cfg(test)]
mod codec_tests {
    use super::*;
    #[test]
    fn observed_layout_raw_name_symlink_padding_and_malformed_inputs() {
        let mut linux = [0xcc; 24];
        let mut posix = [0xdd; 24];
        encode_record(
            DirectoryFormat::Linux64,
            7,
            123,
            crate::storage::SYMLINK,
            &[0xfe, 0xff],
            &mut linux,
        )
        .unwrap();
        encode_record(
            DirectoryFormat::PosixDent,
            7,
            123,
            crate::storage::SYMLINK,
            &[0xfe, 0xff],
            &mut posix,
        )
        .unwrap();
        assert_eq!(linux, posix);
        assert_eq!(&linux[..8], &7u64.to_le_bytes());
        assert_eq!(&linux[8..16], &123u64.to_le_bytes());
        assert_eq!(&linux[16..18], &24u16.to_le_bytes());
        assert_eq!(linux[18], 10);
        assert_eq!(&linux[19..21], &[0xfe, 0xff]);
        assert!(linux[21..].iter().all(|&b| b == 0));
        assert_eq!(
            encode_record(
                DirectoryFormat::PosixDent,
                7,
                i64::MAX as u64 + 1,
                DIR,
                b"x",
                &mut posix
            ),
            Err(INVALID_ARGUMENT)
        );
        assert_eq!(
            encode_record(DirectoryFormat::Linux64, 7, 1, DIR, b"x\0y", &mut linux),
            Err(INVALID_ARGUMENT)
        );
        let mut short = [0; 23];
        assert_eq!(
            encode_record(DirectoryFormat::Linux64, 7, 1, DIR, b"x", &mut short),
            Err(INVALID_ARGUMENT)
        );
    }
}
