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
use pkgfmt::sig::BLOCK_SIZE;
use pkgfmt::{Error, Key, Package, Revocation, Trust, trust};

/// Why a package is refused, as the codes of proto_pkg name it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// The file is not the one the store or the index names.
    BadHash,
    /// The signature covers other bytes than the file holds: a file changed
    /// after it was signed.
    Covered,
    BadPackage,
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

/// Checks the package file `bytes`. `covered` is the SHA-256 of the covered
/// part (all but the trailer page) and `whole` that of the file, both from
/// the reading; `record` is what the store says of it, and `series` the
/// system's.
pub fn check<'a>(
    bytes: &'a [u8],
    covered: &[u8; 32],
    whole: &[u8; 32],
    record: &Record,
    series: &str,
    trust: &Trust,
    revoked: &[Revocation],
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
    trust::verify(
        &package.trailer,
        pkgfmt::Kind::Package,
        covered,
        package.covered().len() as u64,
        trust,
        revoked,
    )
    .map_err(fault_of)?;
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
