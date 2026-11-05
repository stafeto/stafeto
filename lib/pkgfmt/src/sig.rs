// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The signature block `STAFSIG1`, 456 bytes, little endian:
//!
//! | offset | size | field |
//! |---|---|---|
//! | 0 | 8 | `STAFSIG1` |
//! | 8 | 4 | version = 1 |
//! | 12 | 4 | kind: 1 package, 2 index, 3 revocation list |
//! | 16 | 8 | `covered`: the length of the signed bytes |
//! | 24 | 32 | SHA-256 of the signed bytes |
//! | 56 | 8 | time of signing, seconds UTC |
//! | 64 | 64 | key name: length u8, 1 to 63 bytes of `[a-z0-9-]`, zeros |
//! | 128 | 64 | Ed25519 signature |
//! | 192 | 4 | length of the certificate: 0 or 256 |
//! | 196 | 4 | zeros |
//! | 200 | 256 | the certificate or zeros |
//!
//! The signed message is `stafeto signature v1\0` followed by bytes 8 to 128
//! of the block, so the kind, the length, the hash, the time and the key name
//! are all signed, and a signature of an index cannot pass for one of a
//! package.

use crate::{Error, Name, cert, u32_at, u64_at};
use ed25519_compact::{KeyPair, PublicKey, Seed, Signature};

pub const BLOCK_SIZE: usize = 456;
pub const MAGIC: [u8; 8] = *b"STAFSIG1";
pub const VERSION: u32 = 1;
const PREFIX: &[u8; 21] = b"stafeto signature v1\0";
const SIGNED_FROM: usize = 8;
const SIGNED_TO: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Package = 1,
    Index = 2,
    Revoked = 3,
}

impl Kind {
    fn from_u32(v: u32) -> Option<Kind> {
        match v {
            1 => Some(Kind::Package),
            2 => Some(Kind::Index),
            3 => Some(Kind::Revoked),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Block {
    pub kind: Kind,
    pub covered: u64,
    pub digest: [u8; 32],
    pub time: u64,
    pub key: Name,
    pub signature: [u8; 64],
    pub certificate: Option<[u8; cert::SIZE]>,
}

impl Block {
    /// The block at the start of `bytes` (which may be longer).
    pub fn parse(bytes: &[u8]) -> Result<Block, Error> {
        if bytes.len() < BLOCK_SIZE {
            return Err(Error::Truncated);
        }
        if bytes[..8] != MAGIC {
            return Err(Error::NoSignatureBlock);
        }
        let version = u32_at(bytes, 8);
        if version != VERSION {
            return Err(Error::BadVersion(version));
        }
        let kind = Kind::from_u32(u32_at(bytes, 12)).ok_or(Error::BadBlock)?;
        let cert_len = u32_at(bytes, 192) as usize;
        if cert_len != 0 && cert_len != cert::SIZE {
            return Err(Error::BadBlock);
        }
        let cert_bytes = &bytes[200..200 + cert::SIZE];
        let certificate = if cert_len == 0 {
            if cert_bytes.iter().any(|&b| b != 0) {
                return Err(Error::BadBlock);
            }
            None
        } else {
            let mut c = [0; cert::SIZE];
            c.copy_from_slice(cert_bytes);
            Some(c)
        };
        if bytes[196..200].iter().any(|&b| b != 0) {
            return Err(Error::BadBlock);
        }
        Ok(Block {
            kind,
            covered: u64_at(bytes, 16),
            digest: bytes[24..56].try_into().expect("32 bytes"),
            time: u64_at(bytes, 56),
            key: Name::from_field(&bytes[64..128])?,
            signature: bytes[128..192].try_into().expect("64 bytes"),
            certificate,
        })
    }

    pub fn to_bytes(&self) -> [u8; BLOCK_SIZE] {
        let mut b = [0u8; BLOCK_SIZE];
        b[..8].copy_from_slice(&MAGIC);
        b[8..12].copy_from_slice(&VERSION.to_le_bytes());
        b[12..16].copy_from_slice(&(self.kind as u32).to_le_bytes());
        b[16..24].copy_from_slice(&self.covered.to_le_bytes());
        b[24..56].copy_from_slice(&self.digest);
        b[56..64].copy_from_slice(&self.time.to_le_bytes());
        b[64..128].copy_from_slice(&self.key.to_field());
        b[128..192].copy_from_slice(&self.signature);
        if let Some(c) = &self.certificate {
            b[192..196].copy_from_slice(&(cert::SIZE as u32).to_le_bytes());
            b[200..].copy_from_slice(c);
        }
        b
    }

    /// The bytes the signature covers.
    pub fn message(&self) -> [u8; PREFIX.len() + SIGNED_TO - SIGNED_FROM] {
        let bytes = self.to_bytes();
        let mut m = [0; PREFIX.len() + SIGNED_TO - SIGNED_FROM];
        m[..PREFIX.len()].copy_from_slice(PREFIX);
        m[PREFIX.len()..].copy_from_slice(&bytes[SIGNED_FROM..SIGNED_TO]);
        m
    }

    /// Signs with the key of `seed`; the signature is deterministic.
    pub fn sign(
        seed: &[u8; 32],
        kind: Kind,
        covered: u64,
        digest: [u8; 32],
        time: u64,
        key: Name,
        certificate: Option<[u8; cert::SIZE]>,
    ) -> Block {
        let mut block = Block {
            kind,
            covered,
            digest,
            time,
            key,
            signature: [0; 64],
            certificate,
        };
        block.signature = sign(seed, &block.message());
        block
    }

    /// Whether the signature is valid for `public`.
    pub fn check_signature(&self, public: &[u8; 32]) -> bool {
        verify(public, &self.message(), &self.signature)
    }
}

/// Ed25519 over `message` with the key of `seed`.
pub fn sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let pair = KeyPair::from_seed(Seed::new(*seed));
    *pair.sk.sign(message, None)
}

/// Ed25519: whether `signature` is valid for `message` under `public`.
pub fn verify(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    PublicKey::new(*public)
        .verify(message, &Signature::new(*signature))
        .is_ok()
}

/// The public key of the key with this seed.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    *KeyPair::from_seed(Seed::new(*seed)).pk
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 8032, section 7.1, tests 1 to 3: secret key, public key, message,
    /// signature.
    const RFC8032: [(&str, &str, &str, &str); 3] = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ];

    #[test]
    fn rfc_8032_vectors() {
        for (i, (secret, public, message, signature)) in RFC8032.iter().enumerate() {
            let seed: [u8; 32] = unhex(secret).try_into().unwrap();
            let message = unhex(message);
            let signature: [u8; 64] = unhex(signature).try_into().unwrap();
            let pk = public_key(&seed);
            if !public.is_empty() {
                assert_eq!(pk.to_vec(), unhex(public), "public key {i}");
            }
            assert_eq!(sign(&seed, &message), signature, "signature {i}");
            assert!(verify(&pk, &message, &signature), "verify {i}");
            let mut bad = signature;
            bad[0] ^= 1;
            assert!(!verify(&pk, &message, &bad));
        }
    }

    /// `cargo test -p pkgfmt --release -- --ignored --nocapture`: the cost of
    /// one signature check and of hashing 30 MB on the host.
    #[test]
    #[ignore]
    fn timing() {
        let seed = [5u8; 32];
        let public = public_key(&seed);
        let signature = sign(&seed, b"message");
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            assert!(verify(&public, b"message", &signature));
        }
        eprintln!("Ed25519 verify: {:?} each", start.elapsed() / 1000);
        let data = alloc::vec![7u8; 30_000_000];
        let start = std::time::Instant::now();
        let digest = crate::sha::sha256(&data);
        eprintln!(
            "SHA-256 of 30 MB: {:?} ({:02x})",
            start.elapsed(),
            digest[0]
        );
    }

    /// The group order L of Ed25519, little endian.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];

    #[test]
    fn verification_is_strict() {
        let (secret, public, message, signature) = RFC8032[0];
        let seed: [u8; 32] = unhex(secret).try_into().unwrap();
        let public: [u8; 32] = unhex(public).try_into().unwrap();
        let message = unhex(message);
        let good: [u8; 64] = unhex(signature).try_into().unwrap();
        assert!(verify(&public, &message, &good));
        assert_eq!(sign(&seed, &message), good);
        // S + L is the same point equation, and a strict verifier refuses it.
        let mut malleable = good;
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = u16::from(good[32 + i]) + u16::from(L[i]) + carry;
            malleable[32 + i] = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0);
        assert!(!verify(&public, &message, &malleable));
        // A key of small order (the identity point, and the point of order
        // two) checks no signature.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut order_two = [0u8; 32];
        order_two[..31].fill(0xff);
        order_two[0] = 0xec;
        order_two[31] = 0x7f;
        for weak in [identity, order_two] {
            assert!(!verify(&weak, &message, &good));
            let mut forged = [0u8; 64];
            forged[0] = 1; // R is the identity, S is 0: the equation holds for any message with a weak A
            assert!(!verify(&weak, b"anything", &forged));
        }
        // R with a non-canonical encoding (y = p + 1, the identity again), and
        // the same for the key.
        let mut alias = [0xffu8; 32];
        alias[0] = 0xee;
        alias[31] = 0x7f;
        let mut bent = good;
        bent[..32].copy_from_slice(&alias);
        assert!(!verify(&public, &message, &bent));
        assert!(!verify(&alias, &message, &good));
    }

    fn sample() -> Block {
        Block::sign(
            &[7; 32],
            Kind::Package,
            8192,
            [9; 32],
            1_800_000_000,
            Name::new("dev-release").unwrap(),
            None,
        )
    }

    #[test]
    fn a_block_round_trips() {
        let b = sample();
        assert_eq!(Block::parse(&b.to_bytes()), Ok(b));
        assert!(b.check_signature(&public_key(&[7; 32])));
        let with = Block {
            certificate: Some([5; cert::SIZE]),
            ..b
        };
        assert_eq!(Block::parse(&with.to_bytes()), Ok(with));
    }

    #[test]
    fn the_kind_is_in_the_message() {
        let b = sample();
        let other = Block {
            kind: Kind::Index,
            ..b
        };
        assert!(!other.check_signature(&public_key(&[7; 32])));
    }

    #[test]
    fn reserved_bytes_must_be_zero() {
        let good = sample().to_bytes();
        let mut b = good;
        b[196] = 1;
        assert_eq!(Block::parse(&b), Err(Error::BadBlock));
        b = good;
        b[300] = 1;
        assert_eq!(Block::parse(&b), Err(Error::BadBlock));
        b = good;
        b[192] = 7;
        assert_eq!(Block::parse(&b), Err(Error::BadBlock));
        b = good;
        b[12] = 4;
        assert_eq!(Block::parse(&b), Err(Error::BadBlock));
        b = good;
        b[8] = 2;
        assert_eq!(Block::parse(&b), Err(Error::BadVersion(2)));
        b = good;
        b[0] = b'X';
        assert_eq!(Block::parse(&b), Err(Error::NoSignatureBlock));
        assert_eq!(Block::parse(&good[..455]), Err(Error::Truncated));
    }
}
