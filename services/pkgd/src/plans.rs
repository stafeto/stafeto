// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The tables of the transactions that are not installations (pk3-design R7, R8): a
//! removal, a serial, the flag "world" of a package, a new settings blob and a new list of revocations. Each takes the
//! accepted table and writes the table of the next state (one generation more) into
//! `out`, or gives the code of its refusal; the extents of the settings blob and of the
//! list were chosen and written by the caller.

use crate::packages::{self, Entry};
use crate::store::{
    BLOCK, DEPENDENCY, Extent, NO_REPO, PACKAGE, PACKAGES, REPOS, REVOKED, REVOKED_LIST,
    REVOKED_SLOT, Record, SETTINGS, SETTINGS_SLOT, Table, WORLD,
};
use pkgfmt::Name;

/// The names a REMOVE holds at most.
pub const REMOVE_MAX: usize = proto_pkg::REMOVE_MAX as usize;

fn next_of(accepted: &Table, out: &mut Table) {
    out.0 = accepted.0;
    out.set_generation(accepted.generation() + 1);
}

/// SERIAL_SET: `serial` for `repository`. Ok(false) when the table holds that number
/// already (nothing is written), Ok(true) when `out` is the next table; `ROLLBACK` for a
/// smaller number than the table holds, `NO_SPACE` when sixteen repositories are known,
/// `INVALID` for a name that is not a repository's.
pub fn serial(
    accepted: &Table,
    out: &mut Table,
    repository: &[u8],
    serial: u64,
) -> Result<bool, u32> {
    let valid = core::str::from_utf8(repository).is_ok_and(|n| Name::new(n).is_ok());
    if !valid || repository.len() > 31 {
        return Err(proto_pkg::INVALID);
    }
    let place = accepted.find_repo(repository);
    let held = place
        .and_then(|i| accepted.repo(i))
        .map_or(0, |(_, serial)| serial);
    if serial < held {
        return Err(proto_pkg::ROLLBACK);
    }
    if serial == held {
        return Ok(false);
    }
    let place = place
        .or_else(|| (0..REPOS).find(|&i| accepted.repo(i).is_none()))
        .ok_or(proto_pkg::NO_SPACE)?;
    next_of(accepted, out);
    out.set_repo(place, repository, serial);
    Ok(true)
}

/// REMOVE of `names`: the places of the table whose packages go, in `slots`, how many;
/// `out` is the next table. A package of the image is `IN_IMAGE`, an unknown name
/// `NOT_FOUND`, a package some other package that stays needs `NEEDED_BY`. A name that
/// repeats counts once.
pub fn remove(
    accepted: &Table,
    out: &mut Table,
    entries: &[Option<Entry>],
    images: &[Option<Entry>],
    names: &[&[u8]],
    slots: &mut [usize; REMOVE_MAX],
) -> Result<usize, u32> {
    let mut n = 0;
    let mut gone: [&[u8]; REMOVE_MAX] = [&[]; REMOVE_MAX];
    for &name in names {
        if packages::in_image(images, name) {
            return Err(proto_pkg::IN_IMAGE);
        }
        let slot = (0..PACKAGES)
            .find(|&i| {
                let r = accepted.record(i);
                r.kind == PACKAGE && r.name_bytes() == name
            })
            .ok_or(proto_pkg::NOT_FOUND)?;
        if !gone[..n].contains(&name) {
            gone[n] = name;
            slots[n] = slot;
            n += 1;
        }
    }
    if packages::needed_by(entries, &gone[..n]).is_some() {
        return Err(proto_pkg::NEEDED_BY);
    }
    next_of(accepted, out);
    for &slot in &slots[..n] {
        out.set_record(slot, &Record::EMPTY);
    }
    Ok(n)
}

/// WORLD_SET: the flag "world" of the package `name` is `world`. Ok(None) when it is so
/// already (nothing is written), Ok(Some(slot)) when `out` is the next table, which
/// differs from the accepted one in that record alone. A package of the image is
/// `IN_IMAGE`, an unknown name `NOT_FOUND`. The flag "dependency" is the other one.
pub fn world(
    accepted: &Table,
    out: &mut Table,
    images: &[Option<Entry>],
    name: &[u8],
    world: bool,
) -> Result<Option<usize>, u32> {
    if packages::in_image(images, name) {
        return Err(proto_pkg::IN_IMAGE);
    }
    let slot = (0..PACKAGES)
        .find(|&i| {
            let r = accepted.record(i);
            r.kind == PACKAGE && r.name_bytes() == name
        })
        .ok_or(proto_pkg::NOT_FOUND)?;
    let mut r = accepted.record(slot);
    if (r.flags & WORLD != 0) == world {
        return Ok(None);
    }
    r.flags = if world {
        (r.flags | WORLD) & !DEPENDENCY
    } else {
        (r.flags & !WORLD) | DEPENDENCY
    };
    next_of(accepted, out);
    out.set_record(slot, &r);
    Ok(Some(slot))
}

fn blob_record(kind: u8, extent: Extent, length: u64, sha256: [u8; 32], number: u64) -> Record {
    Record {
        kind,
        flags: 0,
        repo: NO_REPO,
        first: extent.first,
        blocks: length.div_ceil(BLOCK as u64) as u32,
        length,
        number,
        installed: 0,
        sha256,
        name: [0; 64],
        version: [0; 64],
    }
}

/// SETTINGS_SET: the blob of `length` bytes at `extent` is the settings record.
pub fn settings(accepted: &Table, out: &mut Table, extent: Extent, length: u64, sha256: [u8; 32]) {
    next_of(accepted, out);
    out.set_record(
        SETTINGS_SLOT,
        &blob_record(SETTINGS, extent, length, sha256, 0),
    );
}

/// REVOKED_SET: the list of `length` bytes at `extent` with its `serial` is the list
/// record, and the flag "revoked" is set exactly on the packages `revoked` says. `ROLLBACK`
/// for a serial smaller than the one the table holds.
pub fn revoked(
    accepted: &Table,
    out: &mut Table,
    extent: Extent,
    length: u64,
    sha256: [u8; 32],
    serial: u64,
    revoked: &[bool; PACKAGES],
) -> Result<(), u32> {
    let held = accepted.record(REVOKED_SLOT);
    if held.kind == REVOKED_LIST && serial < held.number {
        return Err(proto_pkg::ROLLBACK);
    }
    next_of(accepted, out);
    out.set_record(
        REVOKED_SLOT,
        &blob_record(REVOKED_LIST, extent, length, sha256, serial),
    );
    for (slot, &flag) in revoked.iter().enumerate() {
        let mut r = out.record(slot);
        if r.kind != PACKAGE {
            continue;
        }
        r.flags = if flag {
            r.flags | REVOKED
        } else {
            r.flags & !REVOKED
        };
        out.set_record(slot, &r);
    }
    Ok(())
}
