// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The packages in the service's memory (pk3-design R5, R11): those of the
//! disk and those of the boot image, each with a copy of its `meta` and the
//! tail of its signature, so INFO and the check of a revocation list need no
//! mapping of the object. Dependencies are by name, as `meta` writes them.

use crate::store::{DEPENDENCY, REVOKED, Record, WORLD};
use pkgfmt::meta::{Meta, list};
use proto_pkg::{ENTRY_DEPENDENCY, ENTRY_IMAGE, ENTRY_REVOKED, ENTRY_WORLD};

/// The bytes of `meta` one entry keeps, and of the tail of the signature.
pub const META_MAX: usize = 4096;
pub const TRAILER: usize = pkgfmt::sig::BLOCK_SIZE;

/// A package the service knows.
#[derive(Clone, Copy)]
pub struct Entry {
    /// What the table holds of it; for a package of the image the name and
    /// version, and nothing else.
    pub record: Record,
    pub image: bool,
    /// The number of the layer in the file service, 0 while none.
    pub layer: u32,
    pub meta_len: u16,
    pub meta: [u8; META_MAX],
    pub trailer: [u8; TRAILER],
}

impl Entry {
    pub fn name(&self) -> &[u8] {
        self.record.name_bytes()
    }

    pub fn meta(&self) -> &[u8] {
        &self.meta[..usize::from(self.meta_len)]
    }

    /// The flags LIST shows.
    pub fn flags(&self) -> u32 {
        let r = &self.record;
        let mut flags = 0;
        if r.flags & WORLD != 0 {
            flags |= ENTRY_WORLD;
        }
        if r.flags & DEPENDENCY != 0 {
            flags |= ENTRY_DEPENDENCY;
        }
        if r.flags & REVOKED != 0 {
            flags |= ENTRY_REVOKED;
        }
        if self.image {
            flags |= ENTRY_IMAGE;
        }
        flags
    }

    /// A copy of `meta` and the trailer into the entry; false when `meta`
    /// is too long.
    pub fn keep(&mut self, meta: &[u8], trailer: &[u8]) -> bool {
        if meta.len() > META_MAX || trailer.len() > TRAILER {
            return false;
        }
        self.meta_len = meta.len() as u16;
        self.meta[..meta.len()].copy_from_slice(meta);
        self.trailer[..trailer.len()].copy_from_slice(trailer);
        true
    }
}

/// The text of `meta` of an entry.
fn parsed(entry: &Entry) -> Option<Meta<'_>> {
    Meta::parse(core::str::from_utf8(entry.meta()).ok()?).ok()
}

/// Whether `name` is the name of an entry or one it provides.
fn provided(entries: &[Option<Entry>], removed: &[&[u8]], name: &str) -> bool {
    entries.iter().flatten().any(|e| {
        let gone = removed.contains(&e.name());
        !gone
            && (e.name() == name.as_bytes()
                || parsed(e).is_some_and(|m| list(m.provides).any(|p| p == name)))
    })
}

/// The first package that stays and needs something only the packages named
/// in `removed` give: the package it would break (NEEDED_BY).
pub fn needed_by<'a>(entries: &'a [Option<Entry>], removed: &[&[u8]]) -> Option<&'a [u8]> {
    let mut stays = entries
        .iter()
        .flatten()
        .filter(|e| !removed.contains(&e.name()));
    stays.find_map(|e| {
        let meta = parsed(e)?;
        let broken = list(meta.depends).any(|d| {
            // A dependency that the whole set gives and the rest does not.
            provided(entries, &[], d) && !provided(entries, removed, d)
        });
        broken.then_some(e.name())
    })
}

/// The entry named `name`.
pub fn find<'a>(entries: &'a [Option<Entry>], name: &[u8]) -> Option<(usize, &'a Entry)> {
    entries
        .iter()
        .enumerate()
        .find_map(|(i, e)| e.as_ref().filter(|e| e.name() == name).map(|e| (i, e)))
}

/// The packages of the boot image `image`: for each file named `*.stpkg` an
/// entry with the flag `image`, the name and version of its `meta` and a copy
/// of it, in `out`; how many. `skipped(file, why)` hears of each file left out.
pub fn read_image(
    image: &[u8],
    out: &mut [Option<Entry>],
    mut skipped: impl FnMut(&str, &'static str),
) -> usize {
    let Ok(container) = bootimg::BootImage::parse(image) else {
        return 0;
    };
    let mut n = 0;
    for file in container.files().filter(|f| f.name.ends_with(".stpkg")) {
        let raw = bootimg::BootImage::view_as(file.data, &pkgfmt::PACKAGE)
            .ok()
            .and_then(|v| v.file(0).ok())
            .map(|f| f.data);
        let Some(raw) = raw else {
            skipped(file.name, "not a package");
            continue;
        };
        let Some(meta) = core::str::from_utf8(raw)
            .ok()
            .and_then(|t| Meta::parse(t).ok())
        else {
            skipped(file.name, "meta is not good");
            continue;
        };
        let (Some(name), Some(version)) = (
            crate::store::to_field(meta.name.as_bytes()),
            crate::store::to_field(meta.version.as_bytes()),
        ) else {
            skipped(file.name, "name or version too long");
            continue;
        };
        let mut entry = Entry {
            record: Record {
                kind: crate::store::PACKAGE,
                repo: crate::store::NO_REPO,
                name,
                version,
                ..Record::EMPTY
            },
            image: true,
            layer: 0,
            meta_len: 0,
            meta: [0; META_MAX],
            trailer: [0; TRAILER],
        };
        if n >= out.len() {
            skipped(file.name, "too many packages");
        } else if !entry.keep(raw, &[]) {
            skipped(file.name, "meta too long");
        } else {
            out[n] = Some(entry);
            n += 1;
        }
    }
    n
}

/// Whether a package of the image has this name: the package of the disk of
/// the same name is left out.
pub fn in_image(images: &[Option<Entry>], name: &[u8]) -> bool {
    images.iter().flatten().any(|e| e.name() == name)
}

/// The most packages of the boot image the service lists: the full image has 21, and the
/// service said `too many packages, skipped` to the five after the sixteenth.
pub const IMAGE_MAX: usize = 32;
