// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Whom to trust. A block is checked against the data it covers, then
//! against the trust: without a certificate the key must be a root (for a
//! revocation list) or a direct key (for a package or an index of a
//! repository the owner of the device added); with a certificate a root must
//! have issued it for packages, and the block must be signed inside its
//! term. A key named in the revocation list is refused for blocks signed at
//! or after the `since` time of its entry. The clock of the device takes no
//! part here: only the times in the signed data do.

use crate::sig::{Block, Kind};
use crate::{Certificate, Error, Name, cert};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key {
    pub name: Name,
    pub public: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
pub struct Trust<'a> {
    pub roots: &'a [Key],
    pub direct: &'a [Key],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revocation {
    pub name: Name,
    pub since: u64,
}

/// Who signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signer {
    pub key: Name,
    pub time: u64,
    /// The root that vouched for the key; `None` for a key trusted directly
    /// or a root itself.
    pub root: Option<Name>,
}

fn find<'a>(keys: &'a [Key], name: &Name) -> Option<&'a Key> {
    keys.iter().find(|k| k.name == *name)
}

/// Checks `block` for the data it should cover (`covered` bytes with SHA-256
/// `digest`).
pub fn verify(
    block: &Block,
    kind: Kind,
    digest: &[u8; 32],
    covered: u64,
    trust: &Trust,
    revoked: &[Revocation],
) -> Result<Signer, Error> {
    if block.kind != kind {
        return Err(Error::WrongKind);
    }
    if block.covered != covered {
        return Err(Error::LengthMismatch);
    }
    if block.digest != *digest {
        return Err(Error::BadHash);
    }
    let (public, root) = match &block.certificate {
        None => {
            let keys = if kind == Kind::Revoked { trust.roots } else { trust.direct };
            let key = find(keys, &block.key).ok_or(Error::UnknownKey)?;
            (key.public, None)
        }
        Some(_) if kind == Kind::Revoked => return Err(Error::BadCertificate),
        Some(bytes) => {
            let c = Certificate::parse(bytes)?;
            let root = find(trust.roots, &c.issuer).ok_or(Error::BadCertificate)?;
            if !c.check_signature(&root.public) || c.key != block.key {
                return Err(Error::BadCertificate);
            }
            if c.purposes & cert::PURPOSE_PACKAGES == 0 {
                return Err(Error::WrongPurpose);
            }
            if block.time < c.not_before || block.time > c.not_after {
                return Err(Error::OutsideCertificate);
            }
            (c.public, Some(c.issuer))
        }
    };
    if revoked.iter().any(|r| r.name == block.key && block.time >= r.since) {
        return Err(Error::Revoked);
    }
    if !block.check_signature(&public) {
        return Err(Error::BadSignature);
    }
    Ok(Signer {
        key: block.key,
        time: block.time,
        root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sig::public_key;

    const ROOT: [u8; 32] = [1; 32];
    const REL: [u8; 32] = [2; 32];
    const DIGEST: [u8; 32] = [3; 32];

    fn n(s: &str) -> Name {
        Name::new(s).unwrap()
    }

    fn root_key() -> Key {
        Key {
            name: n("t-root"),
            public: public_key(&ROOT),
        }
    }

    fn certificate(purposes: u32) -> [u8; cert::SIZE] {
        Certificate::issue(&ROOT, n("t-root"), n("t-release"), public_key(&REL), purposes, 1000, 2000)
            .to_bytes()
    }

    fn block(kind: Kind, time: u64, cert: Option<[u8; cert::SIZE]>) -> Block {
        Block::sign(&REL, kind, 77, DIGEST, time, n("t-release"), cert)
    }

    fn check(b: &Block, kind: Kind, roots: &[Key], direct: &[Key], rev: &[Revocation]) -> Result<Signer, Error> {
        verify(b, kind, &DIGEST, 77, &Trust { roots, direct }, rev)
    }

    #[test]
    fn a_certified_key_signs_packages() {
        let b = block(Kind::Package, 1500, Some(certificate(1)));
        let s = check(&b, Kind::Package, &[root_key()], &[], &[]).unwrap();
        assert_eq!(s.root, Some(n("t-root")));
        assert_eq!(s.key, n("t-release"));
    }

    #[test]
    fn data_must_match_the_block() {
        let b = block(Kind::Package, 1500, Some(certificate(1)));
        let t = Trust { roots: &[root_key()], direct: &[] };
        assert_eq!(verify(&b, Kind::Index, &DIGEST, 77, &t, &[]), Err(Error::WrongKind));
        assert_eq!(verify(&b, Kind::Package, &DIGEST, 76, &t, &[]), Err(Error::LengthMismatch));
        assert_eq!(verify(&b, Kind::Package, &[4; 32], 77, &t, &[]), Err(Error::BadHash));
    }

    #[test]
    fn a_signature_of_an_index_is_no_signature_of_a_package() {
        // The same key signs an index; the block's kind is then edited to
        // Package: the covered fields match, the signature does not.
        let mut b = block(Kind::Index, 1500, Some(certificate(1)));
        b.kind = Kind::Package;
        assert_eq!(
            check(&b, Kind::Package, &[root_key()], &[], &[]),
            Err(Error::BadSignature)
        );
        assert_eq!(
            check(&b, Kind::Index, &[root_key()], &[], &[]),
            Err(Error::WrongKind)
        );
    }

    #[test]
    fn the_term_of_the_certificate_bounds_the_time_of_signing() {
        let t = |time| check(&block(Kind::Package, time, Some(certificate(1))), Kind::Package, &[root_key()], &[], &[]);
        assert!(t(1000).is_ok());
        assert!(t(2000).is_ok());
        assert_eq!(t(2001), Err(Error::OutsideCertificate));
        assert_eq!(t(999), Err(Error::OutsideCertificate));
    }

    #[test]
    fn the_certificate_must_come_from_a_root_for_packages() {
        let b = block(Kind::Package, 1500, Some(certificate(1)));
        let stranger = Key { name: n("t-root"), public: public_key(&[9; 32]) };
        assert_eq!(check(&b, Kind::Package, &[stranger], &[], &[]), Err(Error::BadCertificate));
        let other = Key { name: n("other-root"), public: public_key(&ROOT) };
        assert_eq!(check(&b, Kind::Package, &[other], &[], &[]), Err(Error::BadCertificate));
        let elf_only = block(Kind::Package, 1500, Some(certificate(cert::PURPOSE_ELF)));
        assert_eq!(check(&elf_only, Kind::Package, &[root_key()], &[], &[]), Err(Error::WrongPurpose));
        // The block's key name differs from the certificate's.
        let mut renamed = block(Kind::Package, 1500, Some(certificate(1)));
        renamed.key = n("t-release-2");
        assert_eq!(check(&renamed, Kind::Package, &[root_key()], &[], &[]), Err(Error::BadCertificate));
    }

    #[test]
    fn revocation_counts_from_since_on() {
        let b = block(Kind::Package, 1500, Some(certificate(1)));
        let rev = |since| [Revocation { name: n("t-release"), since }];
        assert_eq!(check(&b, Kind::Package, &[root_key()], &[], &rev(1500)), Err(Error::Revoked));
        assert!(check(&b, Kind::Package, &[root_key()], &[], &rev(1501)).is_ok());
        let other = [Revocation { name: n("else"), since: 0 }];
        assert!(check(&b, Kind::Package, &[root_key()], &[], &other).is_ok());
    }

    #[test]
    fn direct_keys_sign_without_a_certificate_and_roots_do_not_sign_packages() {
        let direct = Key { name: n("t-release"), public: public_key(&REL) };
        let b = block(Kind::Package, 1500, None);
        assert_eq!(check(&b, Kind::Package, &[root_key()], &[], &[]), Err(Error::UnknownKey));
        assert_eq!(check(&b, Kind::Package, &[], &[direct], &[]).unwrap().root, None);
        // A revocation list is signed by a root directly.
        let rb = Block::sign(&ROOT, Kind::Revoked, 77, DIGEST, 1500, n("t-root"), None);
        assert!(check(&rb, Kind::Revoked, &[root_key()], &[], &[]).is_ok());
        assert_eq!(check(&rb, Kind::Revoked, &[], &[root_key()], &[]), Err(Error::UnknownKey));
        // Nor does a certificate belong on it.
        let cb = Block::sign(&REL, Kind::Revoked, 77, DIGEST, 1500, n("t-release"), Some(certificate(1)));
        assert_eq!(check(&cb, Kind::Revoked, &[root_key()], &[], &[]), Err(Error::BadCertificate));
    }

    #[test]
    fn a_bad_signature_is_refused() {
        let mut b = block(Kind::Package, 1500, Some(certificate(1)));
        b.signature[3] ^= 1;
        assert_eq!(check(&b, Kind::Package, &[root_key()], &[], &[]), Err(Error::BadSignature));
    }
}
