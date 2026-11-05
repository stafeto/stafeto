// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The stafeto package file `.stpkg` and what surrounds it: the signature
//! block (`STAFSIG1`), the certificate of a release key (`STAFCRT1`), the
//! rules that decide whom to trust, the repository index, the revocation
//! list and the key files. Reading needs no allocator (a device reads
//! packages with it); the writers and the checks that hash whole packages
//! are behind the feature `write`, for xtask on the host.
//!
//! The package file is a container with the layout of the boot image
//! (`bootimg::BootImage::parse_as` with `PACKAGE`), so the one reader of
//! tables serves both.

#![cfg_attr(not(test), no_std)]

#[cfg(any(test, feature = "write"))]
extern crate alloc;

pub mod b64;
pub mod cert;
pub mod container;
pub mod index;
pub mod keyfile;
pub mod manifest;
pub mod meta;
pub mod revoked;
pub mod sha;
pub mod sig;
mod text;
pub mod time;
pub mod trust;

use core::fmt;

pub use bootimg::Format;
pub use cert::Certificate;
pub use container::Package;
pub use sig::{Block, Kind};
pub use trust::{Key, Revocation, Signer, Trust};

/// The container format of a package file.
pub const PACKAGE: Format = Format {
    magic: *b"STAFPKG1",
    version: 1,
    name: "STAFPKG1",
};

/// The public keys of the official roots, one `.pub` line each.
pub const OFFICIAL_ROOTS: &[&str] = &[include_str!("../../../keys/stafeto-root-1.pub")];

/// The official roots, parsed. The trust of the official repository is these
/// as `roots` and no key in `direct`: the roots sign certificates, never
/// packages.
pub fn official_roots() -> Result<[Key; OFFICIAL_ROOTS.len()], Error> {
    let mut out = [keyfile::parse_public(OFFICIAL_ROOTS[0])?; OFFICIAL_ROOTS.len()];
    for (slot, line) in out.iter_mut().zip(OFFICIAL_ROOTS) {
        *slot = keyfile::parse_public(line)?;
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The bytes end before the structure does.
    Truncated,
    /// The block does not start with `STAFSIG1`.
    NoSignatureBlock,
    /// A format version this reader does not know.
    BadVersion(u32),
    /// The block is for another kind of signed data.
    WrongKind,
    /// `covered` is not the length of the signed data.
    LengthMismatch,
    /// The SHA-256 of the signed data is not the one in the block.
    BadHash,
    /// The key is in neither list that its kind of data needs.
    UnknownKey,
    /// The certificate is malformed, not from a root, or not signed by it.
    BadCertificate,
    /// The certificate does not allow this use.
    WrongPurpose,
    /// The block was signed outside the certificate's term.
    OutsideCertificate,
    /// The key was revoked at or before the time of signing.
    Revoked,
    /// The Ed25519 signature does not verify.
    BadSignature,
    /// A name is not 1 to 63 bytes of `[a-z0-9-]` in its field.
    BadName,
    /// A reserved field of a block or certificate is not zero.
    BadBlock,
    /// The trailer page has bytes after the block that are not zero.
    BadTrailer,
    BadBase64,
    BadTime,
    /// A key file that is not the expected shape.
    BadKeyFile,
    /// A private key that is not an unencrypted PKCS#8 Ed25519 key.
    NotPkcs8Ed25519,
    /// The container's own rules (`bootimg`).
    Container(bootimg::Error),
    /// The `rootfs` table.
    Rootfs(bootimg::rootfs::Error),
    /// The package as a whole breaks a rule.
    BadLayout(&'static str),
    /// Entry `n` of `rootfs` breaks a rule.
    BadEntry(u32, &'static str),
    /// A line of `meta`, `manifest`, `INDEX` or `revoked`, counted from 1.
    BadMeta(u32),
    BadManifest(u32),
    BadIndex(u32),
    BadRevoked(u32),
    /// The package breaks the policy of an official package.
    Policy(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Container(e) => write!(f, "container: {e}"),
            Error::Rootfs(e) => write!(f, "rootfs: {e}"),
            other => write!(f, "{other:?}"),
        }
    }
}

/// The name of a key: 1 to 63 bytes of `[a-z0-9-]`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Name {
    len: u8,
    bytes: [u8; 63],
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.as_str())
    }
}

impl Name {
    pub fn new(text: &str) -> Result<Name, Error> {
        let b = text.as_bytes();
        if b.is_empty()
            || b.len() > 63
            || !b.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        {
            return Err(Error::BadName);
        }
        let mut bytes = [0; 63];
        bytes[..b.len()].copy_from_slice(b);
        Ok(Name {
            len: b.len() as u8,
            bytes,
        })
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len as usize]).expect("checked ASCII")
    }

    /// The 64-byte field: the length, the name, zeros.
    pub fn to_field(&self) -> [u8; 64] {
        let mut f = [0; 64];
        f[0] = self.len;
        f[1..=self.len as usize].copy_from_slice(&self.bytes[..self.len as usize]);
        f
    }

    pub fn from_field(field: &[u8]) -> Result<Name, Error> {
        if field.len() != 64 || field[0] == 0 || field[0] > 63 {
            return Err(Error::BadName);
        }
        let len = field[0] as usize;
        if field[1 + len..].iter().any(|&b| b != 0) {
            return Err(Error::BadName);
        }
        let text = core::str::from_utf8(&field[1..=len]).map_err(|_| Error::BadName)?;
        Name::new(text)
    }
}

pub(crate) fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("four bytes"))
}

pub(crate) fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("eight bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_strict() {
        let n = Name::new("stafeto-root-1").unwrap();
        assert_eq!(Name::from_field(&n.to_field()), Ok(n));
        assert_eq!(n.as_str(), "stafeto-root-1");
        for bad in ["", "Upper", "a b", "a_b", "é"] {
            assert_eq!(Name::new(bad), Err(Error::BadName));
        }
        assert_eq!(Name::new(&"a".repeat(64)), Err(Error::BadName));
        assert!(Name::new(&"a".repeat(63)).is_ok());
        let mut f = n.to_field();
        f[63] = 1;
        assert_eq!(Name::from_field(&f), Err(Error::BadName));
        f = n.to_field();
        f[0] = 0;
        assert_eq!(Name::from_field(&f), Err(Error::BadName));
    }

    #[test]
    fn the_official_root_is_the_owners() {
        let roots = official_roots().unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].name.as_str(), "stafeto-root-1");
        let mut buf = [0u8; 44];
        assert_eq!(
            b64::encode(&roots[0].public, &mut buf),
            "8dx4D8txlgoMV5y1CYcDJ6kg9fRqfKdrjHk/tJrNkEI="
        );
        assert_eq!(
            OFFICIAL_ROOTS[0],
            "ed25519 8dx4D8txlgoMV5y1CYcDJ6kg9fRqfKdrjHk/tJrNkEI= stafeto-root-1\n"
        );
    }
}
