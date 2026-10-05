// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Private native actors retain actual paid reads in the ordinary file Table.
//! Admission and observation call no collector and allocate no client key table.

use crate::constants::EIO;
use posix_fs::Target;
use posix_fs::data::{DataKind, DataPhase, OwnerToken, ScalarToken};

fn owner() -> Result<OwnerToken, i32> {
    OwnerToken::new(crate::relibc::open_owner()?).map_err(|_| EIO)
}

/// Execute the ordinary carrier, preserving its completed byte until original ACK.
pub fn retain_read(fd: u32, position: u64) -> Result<ScalarToken, i32> {
    crate::data_driver::begin(fd, DataKind::PRead, 1, position, &[])?
        .ok_or(EIO)?
        .run_until_retained()
}

/// Count only complete reads of this exact original owner in the actual Table.
pub fn retained_count(expected: u8) -> Result<usize, i32> {
    let owner = owner()?;
    crate::shared::with_files(|files| {
        let mut count = 0;
        for token in files.data_tokens() {
            if files
                .retained_data_byte(token, owner)
                .map_err(crate::error)?
                != expected
            {
                return Err(EIO);
            }
            count += 1;
        }
        Ok(count)
    })
}

/// Replay the exact saved Start once while its completed result remains paid.
pub fn repeat_first() -> Result<bool, i32> {
    let owner = owner()?;
    let captured = crate::shared::with_files(|files| {
        let Some(token) = files.data_tokens().next() else {
            return Ok(None);
        };
        files
            .retained_data_byte(token, owner)
            .map_err(crate::error)?;
        let state = files.data_state(token).map_err(crate::error)?;
        let Some(Target::Ram(target)) = state.pin else {
            return Err(EIO);
        };
        let request = proto_fs::DataStart {
            key: proto_fs::OpenKey {
                slot: token.slot() as u32,
                generation: token.generation(),
            },
            kind: state.kind,
            description: proto_fs::DataDescription {
                packed: target.fd()
                    | (target.description_slot() << proto_fs::OPEN_DESCRIPTION_SHIFT),
                generation: target.generation(),
            },
            count: state.count,
            position: state.position,
        };
        Ok(Some((request, state.job, files.transport())))
    })?;
    let Some((request, job, transport)) = captured else {
        return Ok(false);
    };
    let (phase, replayed) = transport
        .files()
        .data_start_once(request)
        .map_err(|error| crate::error(posix_fs::FsError::from(error)))?;
    if phase != DataPhase::Completed || replayed != job {
        return Err(EIO);
    }
    Ok(true)
}

/// Clean and acknowledge one exact original result, including its cached byte.
pub fn release_first(expected: u8) -> Result<bool, i32> {
    let owner = owner()?;
    let token = crate::shared::with_files(|files| {
        let token = files.data_tokens().next();
        if let Some(token) = token
            && files
                .retained_data_byte(token, owner)
                .map_err(crate::error)?
                != expected
        {
            return Err(EIO);
        }
        Ok(token)
    })?;
    let Some(token) = token else { return Ok(false) };
    let mut byte = [0; 1];
    if crate::data_driver::retained_operation(token)?.run(&mut byte)? != 1 || byte[0] != expected {
        return Err(EIO);
    }
    Ok(true)
}
