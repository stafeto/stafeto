// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Paid data operations retain an exact shared description until cleanup.
//! The service journal owns admission, authenticated authority and reply recovery.

use crate::{Fds, File, Open, Ram, Token, storage};
use proto_fs::{BAD_FD, INVALID_ARGUMENT, IS_DIRECTORY, OFFSET_OVERFLOW, READ_ONLY, STALE_PROOF};

/// EFBIG. The protocol owner publishes this status with the data-operation wire.
pub use proto_fs::FILE_TOO_LARGE;

pub(crate) struct Held {
    description: Token,
    pub(crate) open: Open,
    capacity: u64,
}

impl Held {
    pub(crate) fn description(&self) -> Token {
        self.description
    }
}

/// One originating job retains this exact description until explicit cleanup.
/// The value is moved into preparation and has no implicit release.
pub struct DataLease {
    held: Held,
    originating_root: storage::Root,
}

impl DataLease {
    pub fn cancel(self, ram: &mut Ram<'_>) {
        ram.io_release(self.held);
    }

    /// Refresh only the retained description before an effect. Its access and root persist.
    pub fn refresh(&mut self, ram: &Ram<'_>) -> Result<(), u32> {
        let shared = ram.descriptions[self.held.description.slot as usize]
            .as_ref()
            .filter(|shared| shared.generation == self.held.description.generation)
            .ok_or(BAD_FD)?;
        if shared.open.flags & 3 != self.held.open.flags & 3 {
            return Err(BAD_FD);
        }
        self.held.open = shared.open;
        Ok(())
    }

    pub fn validate_kind(&self, kind: proto_fs::DataKind) -> Result<(), u32> {
        let open = self.held.open;
        if open.file.is_directory() {
            return Err(IS_DIRECTORY);
        }
        if kind.reads() {
            if open.flags & 3 == proto_fs::WRITE_ONLY {
                return Err(BAD_FD);
            }
            if matches!(open.file, File::Random(_)) {
                return Err(INVALID_ARGUMENT);
            }
        } else {
            if open.flags & 3 == READ_ONLY
                || matches!(open.file, File::Motd | File::ImageRegular(_))
            {
                return Err(BAD_FD);
            }
            if kind == proto_fs::DataKind::Truncate && open.file.is_device() {
                return Err(INVALID_ARGUMENT);
            }
        }
        if open.offset < 0 {
            return Err(OFFSET_OVERFLOW);
        }
        Ok(())
    }
}

fn io_capacity(file: File) -> u64 {
    if matches!(file, File::Scratch) {
        crate::FILE_CAPACITY as u64
    } else {
        (storage::FILE_PAGES * storage::PAGE) as u64
    }
}

pub struct WritePreparation {
    held: Option<Held>,
    data: Option<storage::DataWrite>,
    bytes: [u8; proto_fs::MAX_WRITE],
    count: usize,
    positioned: bool,
    result: Option<usize>,
    originating_root: storage::Root,
}

pub struct TruncatePreparation {
    held: Option<Held>,
    data: storage::DataTruncate,
    result: Option<u64>,
    originating_root: storage::Root,
}

impl Ram<'_> {
    pub(crate) fn io_retain(&mut self, fds: &Fds, fd: u32) -> Result<Held, u32> {
        let description = self.description_token(fds, fd)?;
        let shared = self.descriptions[description.slot as usize]
            .as_mut()
            .expect("named description");
        shared.refs = shared.refs.checked_add(1).ok_or(proto_fs::NO_SPACE)?;
        Ok(Held {
            description,
            open: shared.open,
            capacity: io_capacity(shared.open.file),
        })
    }

    pub(crate) fn io_validate(&self, held: &Held) -> Result<(), u32> {
        let shared = self.descriptions[held.description.slot as usize]
            .as_ref()
            .filter(|shared| shared.generation == held.description.generation)
            .ok_or(BAD_FD)?;
        if shared.open.offset != held.open.offset || shared.open.flags != held.open.flags {
            return Err(STALE_PROOF);
        }
        Ok(())
    }

    pub(crate) fn io_release(&mut self, held: Held) {
        let slot = held.description.slot as usize;
        let Some(shared) = self.descriptions[slot].as_mut() else {
            return;
        };
        assert_eq!(shared.generation, held.description.generation);
        self.release_shared(slot).expect("retained inode");
    }

    /// Capture the complete description identity before the service acknowledges Start.
    pub fn capture_data_lease(
        &mut self,
        fds: &Fds,
        fd: u32,
        expected: Token,
    ) -> Result<DataLease, u32> {
        if self.description_token(fds, fd)? != expected {
            return Err(BAD_FD);
        }
        Ok(DataLease {
            held: self.io_retain(fds, fd)?,
            originating_root: fds.root,
        })
    }

    /// Read one held chunk. The service caches bytes and count before exposing this effect.
    pub fn read_held(
        &mut self,
        lease: &DataLease,
        position: Option<u64>,
        out: &mut [u8],
        now: proto_fs::Timestamp,
    ) -> Result<usize, u32> {
        lease.validate_kind(if position.is_some() {
            proto_fs::DataKind::PRead
        } else {
            proto_fs::DataKind::Read
        })?;
        self.io_validate(&lease.held)?;
        let offset = position.unwrap_or(lease.held.open.offset as u64);
        if offset > i64::MAX as u64 {
            return Err(OFFSET_OVERFLOW);
        }
        let file = lease.held.open.file;
        let count = self.storage.read(self.token(file), offset, out)?;
        let next = offset
            .checked_add(count as u64)
            .filter(|&n| n <= i64::MAX as u64)
            .ok_or(OFFSET_OVERFLOW)?;
        if position.is_none() {
            self.descriptions[lease.held.description.slot as usize]
                .as_mut()
                .expect("held description")
                .open
                .offset = next as i64;
        }
        if !out.is_empty() {
            self.touch_access(file, now);
        }
        Ok(count)
    }

    /// Preparation consumes one exact lease; every refusal returns its cleanup owner.
    pub fn prepare_write_held(
        &mut self,
        lease: DataLease,
        bytes: &[u8],
        position: Option<u64>,
    ) -> Result<WritePreparation, (u32, DataLease)> {
        let prepare = || -> Result<Option<(Token, u64, usize)>, u32> {
            lease.validate_kind(if position.is_some() {
                proto_fs::DataKind::PWrite
            } else {
                proto_fs::DataKind::Write
            })?;
            self.io_validate(&lease.held)?;
            if bytes.len() > proto_fs::MAX_WRITE {
                return Err(INVALID_ARGUMENT);
            }
            if position.is_some_and(|offset| offset > i64::MAX as u64) {
                return Err(OFFSET_OVERFLOW);
            }
            if bytes.is_empty() || lease.held.open.file.is_device() {
                return Ok(None);
            }
            let token = self.token(lease.held.open.file);
            let offset = position.unwrap_or_else(|| {
                if lease.held.open.flags & proto_fs::APPEND != 0 {
                    self.storage.node(token).expect("held inode").length
                } else {
                    lease.held.open.offset as u64
                }
            });
            if offset >= lease.held.capacity {
                return Err(FILE_TOO_LARGE);
            }
            Ok(Some((
                token,
                offset,
                bytes.len().min((lease.held.capacity - offset) as usize),
            )))
        };
        let request = match prepare() {
            Ok(request) => request,
            Err(code) => return Err((code, lease)),
        };
        let mut data = None;
        let mut count = bytes.len();
        if let Some((token, offset, requested)) = request {
            match self
                .storage
                .prepare_data_write(token, lease.originating_root, offset, requested)
            {
                Ok(prepared) => {
                    count = prepared.count;
                    data = Some(prepared);
                }
                Err(code) => return Err((code, lease)),
            }
        }
        let mut prep = WritePreparation {
            held: Some(lease.held),
            data,
            bytes: [0; proto_fs::MAX_WRITE],
            count,
            positioned: position.is_some(),
            originating_root: lease.originating_root,
            result: if bytes.is_empty() { Some(0) } else { None },
        };
        prep.bytes[..count].copy_from_slice(&bytes[..count]);
        Ok(prep)
    }

    pub fn prepare_truncate_held(
        &mut self,
        lease: DataLease,
        length: u64,
    ) -> Result<TruncatePreparation, (u32, DataLease)> {
        let valid = lease
            .validate_kind(proto_fs::DataKind::Truncate)
            .and_then(|()| self.io_validate(&lease.held))
            .and({
                if length > i64::MAX as u64 {
                    Err(OFFSET_OVERFLOW)
                } else if length > lease.held.capacity {
                    Err(FILE_TOO_LARGE)
                } else {
                    Ok(())
                }
            });
        if let Err(code) = valid {
            return Err((code, lease));
        }
        match self
            .storage
            .prepare_data_truncate(self.token(lease.held.open.file), length)
        {
            Ok(data) => Ok(TruncatePreparation {
                held: Some(lease.held),
                data,
                result: None,
                originating_root: lease.originating_root,
            }),
            Err(code) => Err((code, lease)),
        }
    }

    /// The service supplies its existing paid job and authenticated owner.
    /// Cancel releases the captured references after every outcome, including commit.
    pub fn prepare_write(
        &mut self,
        fds: &Fds,
        fd: u32,
        bytes: &[u8],
        position: Option<u64>,
    ) -> Result<WritePreparation, u32> {
        let open = self.get(fds, fd)?;
        if open.file.is_directory() {
            return Err(IS_DIRECTORY);
        }
        if open.flags & 3 == READ_ONLY || matches!(open.file, File::Motd | File::ImageRegular(_)) {
            return Err(BAD_FD);
        }
        if bytes.len() > proto_fs::MAX_WRITE {
            return Err(INVALID_ARGUMENT);
        }
        if position.is_some_and(|offset| offset > i64::MAX as u64) || open.offset < 0 {
            return Err(OFFSET_OVERFLOW);
        }
        let mut prep = WritePreparation {
            held: None,
            data: None,
            bytes: [0; proto_fs::MAX_WRITE],
            count: bytes.len(),
            positioned: position.is_some(),
            result: None,
            originating_root: fds.root,
        };
        if bytes.is_empty() {
            prep.result = Some(0);
            return Ok(prep);
        }
        let mut data_request = None;
        if !open.file.is_device() {
            let token = self.token(open.file);
            let offset = position.unwrap_or_else(|| {
                if open.flags & proto_fs::APPEND != 0 {
                    self.storage.node(token).expect("retained inode").length
                } else {
                    open.offset as u64
                }
            });
            let capacity = io_capacity(open.file);
            if offset >= capacity {
                return Err(FILE_TOO_LARGE);
            }
            data_request = Some((token, offset, bytes.len().min((capacity - offset) as usize)));
        }
        let held = self.io_retain(fds, fd)?;
        if let Some((token, offset, requested)) = data_request {
            let data = match self
                .storage
                .prepare_data_write(token, fds.root, offset, requested)
            {
                Ok(data) => data,
                Err(error) => {
                    self.io_release(held);
                    return Err(error);
                }
            };
            prep.count = data.count;
            prep.data = Some(data);
        }
        prep.bytes[..prep.count].copy_from_slice(&bytes[..prep.count]);
        prep.held = Some(held);
        Ok(prep)
    }

    /// Access comes from the retained writer description. The shared offset is preserved.
    pub fn prepare_truncate(
        &mut self,
        fds: &Fds,
        fd: u32,
        length: u64,
    ) -> Result<TruncatePreparation, u32> {
        let open = self.get(fds, fd)?;
        if open.file.is_directory() {
            return Err(IS_DIRECTORY);
        }
        if open.flags & 3 == READ_ONLY || matches!(open.file, File::Motd | File::ImageRegular(_)) {
            return Err(BAD_FD);
        }
        if open.file.is_device() {
            return Err(INVALID_ARGUMENT);
        }
        if length > i64::MAX as u64 {
            return Err(OFFSET_OVERFLOW);
        }
        if length > io_capacity(open.file) {
            return Err(FILE_TOO_LARGE);
        }
        let held = self.io_retain(fds, fd)?;
        match self
            .storage
            .prepare_data_truncate(self.token(open.file), length)
        {
            Ok(data) => Ok(TruncatePreparation {
                held: Some(held),
                data,
                result: None,
                originating_root: fds.root,
            }),
            Err(error) => {
                self.io_release(held);
                Err(error)
            }
        }
    }
}

impl WritePreparation {
    /// Initialize at most one private page. True makes commit available.
    pub fn step(&mut self, ram: &mut Ram<'_>) -> Result<bool, u32> {
        if self.result.is_some() {
            return Ok(true);
        }
        ram.io_validate(self.held.as_ref().ok_or(BAD_FD)?)?;
        self.data
            .as_mut()
            .map_or(Ok(true), |data| ram.storage.step_data_write(data))
    }

    pub fn commit(&mut self, ram: &mut Ram<'_>, now: proto_fs::Timestamp) -> Result<usize, u32> {
        if let Some(result) = self.result {
            return Ok(result);
        }
        let held = self.held.as_ref().ok_or(BAD_FD)?;
        ram.io_validate(held)?;
        if let Some(data) = self.data.as_mut() {
            if data.offset + self.count as u64 > held.capacity {
                return Err(FILE_TOO_LARGE);
            }
            ram.storage
                .commit_data_write(data, &self.bytes[..self.count], now)?;
            if !self.positioned {
                ram.descriptions[held.description.slot as usize]
                    .as_mut()
                    .expect("retained description")
                    .open
                    .offset = (data.offset + self.count as u64) as i64;
            }
        }
        self.result = Some(self.count);
        Ok(self.count)
    }

    /// A pre-effect conflict releases private pages while preserving the exact lease.
    pub fn restart_step(&mut self, ram: &mut Ram<'_>) -> Result<Option<DataLease>, u32> {
        if self.result.is_some() {
            return Err(proto_fs::OPEN_RETIRED);
        }
        if let Some(data) = self.data.as_mut()
            && !ram.storage.cancel_data_write(data)?
        {
            return Ok(None);
        }
        self.data = None;
        let held = self.held.take().ok_or(BAD_FD)?;
        Ok(Some(DataLease {
            held,
            originating_root: self.originating_root,
        }))
    }

    /// Release at most one private page, overlay or retained description.
    pub fn cancel(&mut self, ram: &mut Ram<'_>) -> Result<bool, u32> {
        if let Some(data) = self.data.as_mut()
            && !ram.storage.cancel_data_write(data)?
        {
            return Ok(false);
        }
        self.data = None;
        if let Some(held) = self.held.take() {
            ram.io_release(held)
        }
        Ok(true)
    }
}

impl TruncatePreparation {
    pub fn step(&mut self, ram: &mut Ram<'_>) -> Result<bool, u32> {
        if self.result.is_some() {
            return Ok(true);
        }
        ram.io_validate(self.held.as_ref().ok_or(BAD_FD)?)?;
        ram.storage.step_data_truncate(&mut self.data)
    }

    pub fn commit(&mut self, ram: &mut Ram<'_>, now: proto_fs::Timestamp) -> Result<u64, u32> {
        if let Some(result) = self.result {
            return Ok(result);
        }
        let held = self.held.as_ref().ok_or(BAD_FD)?;
        ram.io_validate(held)?;
        if self.data.length > held.capacity {
            return Err(FILE_TOO_LARGE);
        }
        ram.storage.commit_data_truncate(&mut self.data, now)?;
        self.result = Some(self.data.length);
        Ok(self.data.length)
    }

    pub fn restart_step(&mut self, ram: &mut Ram<'_>) -> Result<Option<DataLease>, u32> {
        if self.result.is_some() {
            return Err(proto_fs::OPEN_RETIRED);
        }
        if !ram.storage.cancel_data_truncate(&mut self.data)? {
            return Ok(None);
        }
        let held = self.held.take().ok_or(BAD_FD)?;
        Ok(Some(DataLease {
            held,
            originating_root: self.originating_root,
        }))
    }

    pub fn cancel(&mut self, ram: &mut Ram<'_>) -> Result<bool, u32> {
        if !ram.storage.cancel_data_truncate(&mut self.data)? {
            return Ok(false);
        }
        if let Some(held) = self.held.take() {
            ram.io_release(held)
        }
        Ok(true)
    }
}
