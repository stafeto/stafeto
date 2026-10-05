// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Paid data operations retain an exact shared description until cleanup.
//! The service journal owns admission, authenticated authority and reply recovery.

use crate::{Fds, File, Open, Ram, Token, storage};
use proto_fs::{BAD_FD, INVALID_ARGUMENT, IS_DIRECTORY, OFFSET_OVERFLOW, READ_ONLY, STALE_PROOF};

/// EFBIG. The protocol owner publishes this status with the data-operation wire.
pub use proto_fs::FILE_TOO_LARGE;

struct Held {
    description: Token,
    open: Open,
    capacity: u64,
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
}

pub struct TruncatePreparation {
    held: Option<Held>,
    data: storage::DataTruncate,
    result: Option<u64>,
}

impl Ram<'_> {
    fn io_retain(&mut self, fds: &Fds, fd: u32) -> Result<Held, u32> {
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

    fn io_validate(&self, held: &Held) -> Result<(), u32> {
        let shared = self.descriptions[held.description.slot as usize]
            .as_ref()
            .filter(|shared| shared.generation == held.description.generation)
            .ok_or(BAD_FD)?;
        if shared.open.offset != held.open.offset || shared.open.flags != held.open.flags {
            return Err(STALE_PROOF);
        }
        Ok(())
    }

    fn io_release(&mut self, held: Held) {
        let slot = held.description.slot as usize;
        let Some(shared) = self.descriptions[slot].as_mut() else {
            return;
        };
        assert_eq!(shared.generation, held.description.generation);
        shared.refs -= 1;
        if shared.refs == 0 {
            let shared = self.descriptions[slot]
                .take()
                .expect("retained description");
            self.storage
                .unpin(self.token(shared.open.file), storage::Pin::Fd)
                .expect("retained inode");
            self.storage.release_description(shared.root);
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
