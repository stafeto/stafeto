// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The certificate `STAFCRT1`: a root vouches for a release key for some
//! purposes and a term. 256 bytes, little endian:
//!
//! | offset | size | field |
//! |---|---|---|
//! | 0 | 8 | `STAFCRT1` |
//! | 8 | 4 | version = 1 |
//! | 12 | 4 | purposes: bit 0 `packages` (packages and indexes), bit 1 `elf` |
//! | 16 | 64 | key name (as in the signature block) |
//! | 80 | 32 | public key |
//! | 112 | 8 | start of the term, seconds UTC |
//! | 120 | 8 | end of the term |
//! | 128 | 64 | name of the issuing root |
//! | 192 | 64 | the root's signature |
//!
//! The signed message is `stafeto certificate v1\0` followed by bytes 0 to
//! 192.

use crate::{Error, Name, sig, u32_at, u64_at};

pub const SIZE: usize = 256;
pub const MAGIC: [u8; 8] = *b"STAFCRT1";
pub const VERSION: u32 = 1;
pub const PURPOSE_PACKAGES: u32 = 1;
pub const PURPOSE_ELF: u32 = 2;
const PREFIX: &[u8; 23] = b"stafeto certificate v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Certificate {
    pub purposes: u32,
    pub key: Name,
    pub public: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    pub issuer: Name,
    pub signature: [u8; 64],
}

impl Certificate {
    pub fn parse(bytes: &[u8]) -> Result<Certificate, Error> {
        if bytes.len() != SIZE {
            return Err(Error::BadCertificate);
        }
        if bytes[..8] != MAGIC || u32_at(bytes, 8) != VERSION {
            return Err(Error::BadCertificate);
        }
        let purposes = u32_at(bytes, 12);
        let (not_before, not_after) = (u64_at(bytes, 112), u64_at(bytes, 120));
        if purposes & !(PURPOSE_PACKAGES | PURPOSE_ELF) != 0 || not_before > not_after {
            return Err(Error::BadCertificate);
        }
        Ok(Certificate {
            purposes,
            key: Name::from_field(&bytes[16..80]).map_err(|_| Error::BadCertificate)?,
            public: bytes[80..112].try_into().expect("32 bytes"),
            not_before,
            not_after,
            issuer: Name::from_field(&bytes[128..192]).map_err(|_| Error::BadCertificate)?,
            signature: bytes[192..256].try_into().expect("64 bytes"),
        })
    }

    pub fn to_bytes(&self) -> [u8; SIZE] {
        let mut b = [0u8; SIZE];
        b[..8].copy_from_slice(&MAGIC);
        b[8..12].copy_from_slice(&VERSION.to_le_bytes());
        b[12..16].copy_from_slice(&self.purposes.to_le_bytes());
        b[16..80].copy_from_slice(&self.key.to_field());
        b[80..112].copy_from_slice(&self.public);
        b[112..120].copy_from_slice(&self.not_before.to_le_bytes());
        b[120..128].copy_from_slice(&self.not_after.to_le_bytes());
        b[128..192].copy_from_slice(&self.issuer.to_field());
        b[192..].copy_from_slice(&self.signature);
        b
    }

    fn message(&self) -> [u8; PREFIX.len() + 192] {
        let b = self.to_bytes();
        let mut m = [0; PREFIX.len() + 192];
        m[..PREFIX.len()].copy_from_slice(PREFIX);
        m[PREFIX.len()..].copy_from_slice(&b[..192]);
        m
    }

    /// The certificate of `public` under the name `key`, signed with the
    /// seed of the root `issuer`.
    pub fn issue(
        root_seed: &[u8; 32],
        issuer: Name,
        key: Name,
        public: [u8; 32],
        purposes: u32,
        not_before: u64,
        not_after: u64,
    ) -> Certificate {
        let mut c = Certificate {
            purposes,
            key,
            public,
            not_before,
            not_after,
            issuer,
            signature: [0; 64],
        };
        c.signature = sig::sign(root_seed, &c.message());
        c
    }

    /// Whether the root's key `root` signed this certificate.
    pub fn check_signature(&self, root: &[u8; 32]) -> bool {
        sig::verify(root, &self.message(), &self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Certificate {
        Certificate::issue(
            &[1; 32],
            Name::new("t-root").unwrap(),
            Name::new("t-release").unwrap(),
            sig::public_key(&[2; 32]),
            PURPOSE_PACKAGES,
            1000,
            2000,
        )
    }

    #[test]
    fn a_certificate_round_trips_and_verifies() {
        let c = sample();
        assert_eq!(Certificate::parse(&c.to_bytes()), Ok(c));
        assert!(c.check_signature(&sig::public_key(&[1; 32])));
        assert!(!c.check_signature(&sig::public_key(&[2; 32])));
        let mut other = c;
        other.not_after += 1;
        assert!(!other.check_signature(&sig::public_key(&[1; 32])));
    }

    #[test]
    fn malformed_certificates_are_refused() {
        let good = sample().to_bytes();
        let mut b = good;
        b[13] = 1; // purpose bit 8
        assert_eq!(Certificate::parse(&b), Err(Error::BadCertificate));
        b = good;
        b[112..120].copy_from_slice(&3000u64.to_le_bytes()); // start after end
        assert_eq!(Certificate::parse(&b), Err(Error::BadCertificate));
        b = good;
        b[0] = 0;
        assert_eq!(Certificate::parse(&b), Err(Error::BadCertificate));
        assert_eq!(Certificate::parse(&good[..255]), Err(Error::BadCertificate));
    }
}
