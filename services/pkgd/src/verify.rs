// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the service checks of a package file before it attaches it (pk3-design
//! R4, R10): the SHA-256 of the file against the one the store holds, the
//! layout (`Package::parse`), the name, the version and the series in `meta`,
//! and the signature against the trust of the package's repository and the
//! revocation list. The hash of the covered part and of the whole file come
//! from the reading, which hashes as the bytes arrive; the manifest, which
//! only an installation checks, is not here.

use crate::store::Record;
use pkgfmt::revoked::Revoked;
use pkgfmt::sig::BLOCK_SIZE;
use pkgfmt::{Error, Key, Package, Trust, trust};

/// Why a package is refused, as the codes of proto_pkg name it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// The file is not the one the store or the index names.
    BadHash,
    /// The signature covers other bytes than the file holds: a file changed
    /// after it was signed.
    Covered,
    BadPackage,
    /// A file of the package is not the one the manifest names.
    BadManifest,
    WrongSeries,
    UntrustedKey,
    Revoked,
    BadSignature,
}

impl Fault {
    /// The code of proto_pkg.
    pub const fn code(self) -> u32 {
        match self {
            Fault::BadHash | Fault::Covered => proto_pkg::BAD_HASH,
            Fault::BadPackage => proto_pkg::BAD_PACKAGE,
            Fault::BadManifest => proto_pkg::BAD_MANIFEST,
            Fault::WrongSeries => proto_pkg::WRONG_SERIES,
            Fault::UntrustedKey => proto_pkg::UNTRUSTED_KEY,
            Fault::Revoked => proto_pkg::REVOKED,
            Fault::BadSignature => proto_pkg::BAD_SIGNATURE,
        }
    }

    /// The words of the line a skipped package gets.
    pub const fn words(self) -> &'static str {
        match self {
            Fault::BadHash => "not the file of the table",
            Fault::BadPackage => "not a package",
            Fault::BadManifest => "bad manifest",
            Fault::WrongSeries => "wrong series",
            Fault::UntrustedKey => "untrusted key",
            Fault::Revoked => "key revoked",
            Fault::BadSignature | Fault::Covered => "bad signature",
        }
    }
}

/// The errors of `pkgfmt` that a signature check gives, as faults.
pub fn fault_of(error: Error) -> Fault {
    match error {
        Error::UnknownKey
        | Error::BadCertificate
        | Error::WrongPurpose
        | Error::OutsideCertificate => Fault::UntrustedKey,
        Error::Revoked => Fault::Revoked,
        Error::BadSignature => Fault::BadSignature,
        Error::BadHash | Error::LengthMismatch => Fault::Covered,
        _ => Fault::BadPackage,
    }
}

/// What a package that passed gives the service to keep.
pub struct Checked<'a> {
    /// The bytes of `meta`.
    pub meta: &'a [u8],
    /// The signature block, as the trailer holds it.
    pub trailer: &'a [u8],
}

/// Where a check is, for the one who times its parts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// The layout is read and the names and the series are right.
    Parsed,
    /// The signature is checked against the trust.
    Signed,
    /// One portion of a file was hashed for the manifest (only an installation).
    Portion,
}

/// The bytes the manifest check hashes at a time.
const PORTION: usize = 16 * 1024;

/// Checks the package file `bytes`. `covered` is the SHA-256 of the covered
/// part (all but the trailer page) and `whole` that of the file, both from
/// the reading; `record` is what the store says of it, and `series` the
/// system's. `revoked` is the list of revocations whole: names in it are
/// ascending without repeats, so at most one entry names the key that signed.
/// With `manifest` (an installation, not a start from the disk, where the signature
/// that covers the manifest and the bytes is enough) the SHA-256 of each file is
/// compared with its line in the manifest. `seen` hears each phase.
#[allow(clippy::too_many_arguments)]
pub fn check<'a>(
    bytes: &'a [u8],
    covered: &[u8; 32],
    whole: &[u8; 32],
    record: &Record,
    series: &str,
    trust: &Trust,
    revoked: Option<&Revoked<'_>>,
    manifest: bool,
    seen: &mut dyn FnMut(Phase),
) -> Result<Checked<'a>, Fault> {
    if *whole != record.sha256 || bytes.len() as u64 != record.length {
        return Err(Fault::BadHash);
    }
    let package = Package::parse(bytes).map_err(|_| Fault::BadPackage)?;
    let meta = &package.meta;
    if meta.name.as_bytes() != record.name_bytes()
        || meta.version.as_bytes() != record.version_bytes()
    {
        return Err(Fault::BadPackage);
    }
    if meta.series != series {
        return Err(Fault::WrongSeries);
    }
    seen(Phase::Parsed);
    let hit = revoked.and_then(|list| list.entries().find(|r| r.name == package.trailer.key));
    trust::verify(
        &package.trailer,
        pkgfmt::Kind::Package,
        covered,
        package.covered().len() as u64,
        trust,
        hit.as_slice(),
    )
    .map_err(fault_of)?;
    seen(Phase::Signed);
    if manifest {
        let n = package.rootfs.len() as u32;
        for (i, line) in package.manifest.entries().enumerate().take(n as usize) {
            let Some(digest) = line.sha256 else { continue };
            let mut stream = pkgfmt::sha::Stream::new();
            for part in package.content(i as u32).chunks(PORTION) {
                stream.update(part);
                seen(Phase::Portion);
            }
            if stream.finish() != digest {
                return Err(Fault::BadManifest);
            }
        }
    }
    let meta_file = package.image.file_at(0).ok_or(Fault::BadPackage)?;
    let at = package.covered().len();
    Ok(Checked {
        meta: meta_file.data,
        trailer: &bytes[at..at + BLOCK_SIZE],
    })
}

/// The trust a package of a repository is checked against: the official one
/// by the roots alone, the owner's by the keys he gave it alone.
pub fn select<'k>(official: bool, roots: &'k [Key], own: &'k [Key]) -> Trust<'k> {
    if official {
        Trust { roots, direct: &[] }
    } else {
        Trust {
            roots: &[],
            direct: own,
        }
    }
}

/// Whether the list of revocations names the key that signed the package whose trailer
/// (the signature block) is `trailer`, at or before the time it signed.
pub fn revoked_by(trailer: &[u8], list: &Revoked<'_>) -> bool {
    let Ok(block) = pkgfmt::Block::parse(trailer) else {
        return false;
    };
    list.entries()
        .any(|r| r.name == block.key && block.time >= r.since)
}
