// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What an index and a list of revocations must pass before anything of
//! them is used (pk4-design R7, R8): the signature against the trust of the
//! repository, the header against this system and this repository, the
//! `expires` against the clock, and the serial against the one the package
//! service holds. The package service verifies each package again when it
//! attaches it; the index is `pkg`'s to verify, since it decides what is
//! downloaded.

use alloc::format;
use alloc::string::{String, ToString};
use pkgfmt::index::Index;
use pkgfmt::sig::{Block, Kind};
use pkgfmt::{Error, Key, Revocation, Trust, sha, time};

/// The guest's clock may be this far behind the time an index was signed
/// and still be taken for right (the slack of the probes of TLS).
pub const CLOCK_SLACK_S: u64 = 600;

/// What breaks a check, with what the line of the refusal says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fault {
    /// The key is in no list of the repository's trust, or its certificate is not a root's.
    Untrusted(String),
    Revoked(String),
    OutsideTerm,
    /// The block does not verify, or does not cover these bytes.
    BadSignature,
    /// The index or the list is malformed at this line.
    Malformed(u32),
    /// The header names another repository, series or architecture.
    Header {
        field: &'static str,
        found: String,
        own: String,
    },
    Expired {
        expires: u64,
        now: u64,
    },
    ClockBehind {
        now: u64,
        signed: u64,
    },
    /// The index or the list is older than the one accepted before.
    Rollback {
        what: &'static str,
        serial: u64,
        held: Option<u64>,
    },
}

/// RFC 3339 of a number of seconds, as `pkgfmt::time` writes it.
pub fn stamp(secs: u64) -> String {
    let mut buf = [0; time::TEXT_LEN];
    time::format(secs, &mut buf).unwrap_or("?").to_string()
}

impl Fault {
    /// The line of the refusal: `pkg: <repository>: ...`.
    pub fn line(&self, repository: &str) -> String {
        let what = match self {
            Fault::Untrusted(key) => {
                format!("signed by {key}, a key this repository does not trust")
            }
            Fault::Revoked(key) => format!("key {key} revoked"),
            Fault::OutsideTerm => "signed outside the term of its certificate".into(),
            Fault::BadSignature => "bad signature".into(),
            Fault::Malformed(line) => format!("not a valid index or list (line {line})"),
            Fault::Header { field, found, own } => {
                let whose = if *field == "repository" {
                    "this repository"
                } else {
                    "this system"
                };
                format!("index is for {field} {found}, {whose} is {own}")
            }
            Fault::Expired { expires, now } => format!(
                "index expired at {}, clock says {}",
                stamp(*expires),
                stamp(*now)
            ),
            Fault::ClockBehind { now, signed } => format!(
                "the clock says {}, before the index was signed at {}; set the clock (date -s)",
                stamp(*now),
                stamp(*signed)
            ),
            Fault::Rollback { what, serial, held } => match held {
                Some(held) => format!(
                    "{what} serial {serial} is older than serial {held} already accepted (rollback)"
                ),
                None => {
                    format!("{what} {serial} is older than the one already accepted (rollback)")
                }
            },
        };
        format!("pkg: {repository}: {what}")
    }
}

/// The fault of a failed check of a block, which was read as `block`.
fn of_error(e: Error, key: &str) -> Fault {
    match e {
        Error::UnknownKey | Error::BadCertificate | Error::WrongPurpose => {
            Fault::Untrusted(key.to_string())
        }
        Error::Revoked => Fault::Revoked(key.to_string()),
        Error::OutsideCertificate => Fault::OutsideTerm,
        _ => Fault::BadSignature,
    }
}

/// The signed block, checked against `data`.
fn block_of(
    data: &[u8],
    sig: &[u8],
    kind: Kind,
    trust: &Trust,
    revoked: &[Revocation],
) -> Result<pkgfmt::Signer, Fault> {
    if sig.len() != pkgfmt::sig::BLOCK_SIZE {
        return Err(Fault::BadSignature);
    }
    let block = Block::parse(sig).map_err(|_| Fault::BadSignature)?;
    pkgfmt::trust::verify(
        &block,
        kind,
        &sha::sha256(data),
        data.len() as u64,
        trust,
        revoked,
    )
    .map_err(|e| of_error(e, block.key.as_str()))
}

/// A list of revocations that passed.
#[derive(Debug, PartialEq, Eq)]
pub struct Revocations {
    pub serial: u64,
    pub entries: alloc::vec::Vec<Revocation>,
}

/// The list `list` signed by `sig`: by one of the `roots` (a certified key or a key of an
/// owner never signs a list).
pub fn revocations(list: &[u8], sig: &[u8], roots: &[Key]) -> Result<Revocations, Fault> {
    block_of(list, sig, Kind::Revoked, &Trust { roots, direct: &[] }, &[])?;
    let text = core::str::from_utf8(list).map_err(|_| Fault::Malformed(1))?;
    let parsed = pkgfmt::revoked::Revoked::parse(text).map_err(|e| match e {
        Error::BadRevoked(n) => Fault::Malformed(n),
        _ => Fault::Malformed(1),
    })?;
    Ok(Revocations {
        serial: parsed.serial,
        entries: parsed.entries().collect(),
    })
}

/// What an index that passed says of itself.
#[derive(Debug, PartialEq, Eq)]
pub struct Accepted {
    pub serial: u64,
    pub expires: u64,
    /// The key that signed and the time it signed.
    pub key: String,
    pub signed: u64,
}

/// The index `index` signed by `sig` for the repository `repository`, on
/// a system of series `series` at the time `now`: the signature by `trust`
/// with the revocations of the list `revoked`, the header, and the clock.
pub fn index(
    data: &[u8],
    sig: &[u8],
    repository: &str,
    series: &str,
    trust: &Trust,
    revoked: &[Revocation],
    now: u64,
) -> Result<Accepted, Fault> {
    let signer = block_of(data, sig, Kind::Index, trust, revoked)?;
    let text = core::str::from_utf8(data).map_err(|_| Fault::Malformed(1))?;
    let parsed = Index::parse(text).map_err(|e| match e {
        Error::BadIndex(n) => Fault::Malformed(n),
        _ => Fault::Malformed(1),
    })?;
    let head = parsed.header;
    let wrong = |field, found: &str, own: &str| Fault::Header {
        field,
        found: found.to_string(),
        own: own.to_string(),
    };
    if head.repository != repository {
        return Err(wrong("repository", head.repository, repository));
    }
    if head.series != series {
        return Err(wrong("series", head.series, series));
    }
    if head.arch != "aarch64" {
        return Err(wrong("arch", head.arch, "aarch64"));
    }
    clock(now, signer.time, head.expires)?;
    Ok(Accepted {
        serial: head.serial,
        expires: head.expires,
        key: signer.key.as_str().to_string(),
        signed: signer.time,
    })
}

/// The clock against an index signed at `signed` that is good until
/// `expires`. The clock must not be more than `CLOCK_SLACK_S` behind the time
/// of the signing (a clock that started from its default would make an expired
/// index look good), and must be strictly before `expires`.
pub fn clock(now: u64, signed: u64, expires: u64) -> Result<(), Fault> {
    if signed > now + CLOCK_SLACK_S {
        return Err(Fault::ClockBehind { now, signed });
    }
    if now >= expires {
        return Err(Fault::Expired { expires, now });
    }
    Ok(())
}

/// What a serial says against the one the package service holds (0 for a
/// repository it does not know).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Serial {
    /// Older: refused.
    Older,
    /// The same: nothing to write.
    Same,
    /// Newer: written to the service before any package is received.
    Newer,
}

pub fn serial(new: u64, held: u64) -> Serial {
    match new.cmp(&held) {
        core::cmp::Ordering::Less => Serial::Older,
        core::cmp::Ordering::Equal => Serial::Same,
        core::cmp::Ordering::Greater => Serial::Newer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use pkgfmt::cert::{Certificate, PURPOSE_PACKAGES};
    use pkgfmt::index::{Entry, Header};
    use pkgfmt::sig::public_key;

    const ROOT: [u8; 32] = [1; 32];
    const RELEASE: [u8; 32] = [2; 32];
    const OWN: [u8; 32] = [9; 32];
    const SIGNED: u64 = 1_800_000_000;
    const EXPIRES: u64 = SIGNED + 30 * 86_400;
    const NOW: u64 = SIGNED + 100;

    fn name(s: &str) -> pkgfmt::Name {
        pkgfmt::Name::new(s).unwrap()
    }

    fn root() -> Key {
        Key {
            name: name("t-root"),
            public: public_key(&ROOT),
        }
    }

    fn certificate(purposes: u32) -> [u8; pkgfmt::cert::SIZE] {
        Certificate::issue(
            &ROOT,
            name("t-root"),
            name("t-release"),
            public_key(&RELEASE),
            purposes,
            SIGNED - 1000,
            EXPIRES + 1000,
        )
        .to_bytes()
    }

    fn text(repository: &str, series: &str, serial: u64, expires: u64) -> String {
        let header = Header {
            repository,
            series,
            arch: "aarch64",
            serial,
            expires,
        };
        let entry = Entry {
            name: "hello",
            version: "1.0-1",
            provides: None,
            depends: None,
            needs: None,
            license: "MIT",
            size: 10,
            sha256: &"a".repeat(64),
            recipe: &"b".repeat(64),
            file: "hello-1.0-1.stpkg",
            source: None,
            summary: "A hello",
        };
        pkgfmt::index::write(&header, &[entry]).unwrap()
    }

    fn sign_index(data: &str, time: u64) -> Vec<u8> {
        Block::sign(
            &RELEASE,
            Kind::Index,
            data.len() as u64,
            sha::sha256(data.as_bytes()),
            time,
            name("t-release"),
            Some(certificate(PURPOSE_PACKAGES)),
        )
        .to_bytes()
        .to_vec()
    }

    fn official<'a>(roots: &'a [Key]) -> Trust<'a> {
        Trust { roots, direct: &[] }
    }

    fn check(data: &str, sig: &[u8], now: u64) -> Result<Accepted, Fault> {
        let roots = [root()];
        index(
            data.as_bytes(),
            sig,
            "stafeto",
            "0.3",
            &official(&roots),
            &[],
            now,
        )
    }

    #[test]
    fn a_good_index_is_accepted_and_names_its_signer() {
        let data = text("stafeto", "0.3", 2, EXPIRES);
        let sig = sign_index(&data, SIGNED);
        assert_eq!(
            check(&data, &sig, NOW),
            Ok(Accepted {
                serial: 2,
                expires: EXPIRES,
                key: "t-release".into(),
                signed: SIGNED
            })
        );
    }

    #[test]
    fn a_key_of_an_owner_signs_his_repository_directly() {
        let data = text("games", "0.3", 1, EXPIRES);
        let key = Key {
            name: name("games-1"),
            public: public_key(&OWN),
        };
        let sig = Block::sign(
            &OWN,
            Kind::Index,
            data.len() as u64,
            sha::sha256(data.as_bytes()),
            SIGNED,
            name("games-1"),
            None,
        )
        .to_bytes();
        let own = Trust {
            roots: &[],
            direct: &[key],
        };
        assert!(index(data.as_bytes(), &sig, "games", "0.3", &own, &[], NOW).is_ok());
        // The same block against the official trust: not that repository's key.
        let roots = [root()];
        let e = index(
            data.as_bytes(),
            &sig,
            "games",
            "0.3",
            &official(&roots),
            &[],
            NOW,
        );
        assert_eq!(e, Err(Fault::Untrusted("games-1".into())));
    }

    #[test]
    fn every_error_of_the_signature_has_its_line() {
        let data = text("stafeto", "0.3", 2, EXPIRES);
        let good = sign_index(&data, SIGNED);
        // A changed byte of the index: the digest no longer matches.
        let mut other = data.clone().into_bytes();
        other[10] ^= 1;
        let roots = [root()];
        let t = official(&roots);
        assert_eq!(
            index(&other, &good, "stafeto", "0.3", &t, &[], NOW),
            Err(Fault::BadSignature)
        );
        // A changed signature.
        let mut bad = good.clone();
        bad[130] ^= 1;
        assert_eq!(check(&data, &bad, NOW), Err(Fault::BadSignature));
        // A block of another length.
        assert_eq!(check(&data, &good[..400], NOW), Err(Fault::BadSignature));
        // A key whose certificate is not a root's.
        let stranger = Trust {
            roots: &[Key {
                name: name("t-root"),
                public: public_key(&[7; 32]),
            }],
            direct: &[],
        };
        assert_eq!(
            index(
                data.as_bytes(),
                &good,
                "stafeto",
                "0.3",
                &stranger,
                &[],
                NOW
            ),
            Err(Fault::Untrusted("t-release".into()))
        );
        // A key revoked at the time of the signing.
        let list = [Revocation {
            name: name("t-release"),
            since: SIGNED,
        }];
        assert_eq!(
            index(data.as_bytes(), &good, "stafeto", "0.3", &t, &list, NOW),
            Err(Fault::Revoked("t-release".into()))
        );
        // Signed before the revocation: still good.
        let later = [Revocation {
            name: name("t-release"),
            since: SIGNED + 1,
        }];
        assert!(index(data.as_bytes(), &good, "stafeto", "0.3", &t, &later, NOW).is_ok());
        // Signed outside the term of the certificate.
        let early = sign_index(&data, SIGNED - 5000);
        assert_eq!(check(&data, &early, NOW), Err(Fault::OutsideTerm));
        assert_eq!(
            Fault::Untrusted("k".into()).line("stafeto"),
            "pkg: stafeto: signed by k, a key this repository does not trust"
        );
        assert_eq!(
            Fault::Revoked("k".into()).line("stafeto"),
            "pkg: stafeto: key k revoked"
        );
        assert_eq!(
            Fault::OutsideTerm.line("stafeto"),
            "pkg: stafeto: signed outside the term of its certificate"
        );
        assert_eq!(Fault::BadSignature.line("x"), "pkg: x: bad signature");
    }

    #[test]
    fn the_header_must_name_this_repository_and_this_system() {
        let sig = |d: &str| sign_index(d, SIGNED);
        let d = text("other", "0.3", 2, EXPIRES);
        let e = check(&d, &sig(&d), NOW).unwrap_err();
        assert_eq!(
            e.line("stafeto"),
            "pkg: stafeto: index is for repository other, this repository is stafeto"
        );
        let d = text("stafeto", "0.2", 2, EXPIRES);
        let e = check(&d, &sig(&d), NOW).unwrap_err();
        assert_eq!(
            e.line("games"),
            "pkg: games: index is for series 0.2, this system is 0.3"
        );
    }

    #[test]
    fn an_index_is_good_until_expires_and_not_at_it() {
        let data = text("stafeto", "0.3", 2, EXPIRES);
        let sig = sign_index(&data, SIGNED);
        assert!(check(&data, &sig, EXPIRES - 1).is_ok());
        let e = check(&data, &sig, EXPIRES).unwrap_err();
        assert_eq!(
            e,
            Fault::Expired {
                expires: EXPIRES,
                now: EXPIRES
            }
        );
        assert!(check(&data, &sig, EXPIRES + 86_400).is_err());
        assert_eq!(
            Fault::Expired {
                expires: 1_796_515_200,
                now: 1_796_601_600
            }
            .line("stafeto"),
            "pkg: stafeto: index expired at 2026-12-06T00:00:00Z, clock says 2026-12-07T00:00:00Z"
        );
    }

    #[test]
    fn a_clock_behind_the_signing_is_refused_beyond_the_slack() {
        let data = text("stafeto", "0.3", 2, EXPIRES);
        let sig = sign_index(&data, SIGNED);
        // 599 and 600 seconds behind: taken; 601: refused.
        assert!(check(&data, &sig, SIGNED - 599).is_ok());
        assert!(check(&data, &sig, SIGNED - 600).is_ok());
        let e = check(&data, &sig, SIGNED - 601).unwrap_err();
        assert_eq!(
            e,
            Fault::ClockBehind {
                now: SIGNED - 601,
                signed: SIGNED
            }
        );
        assert!(e.line("stafeto").contains("set the clock (date -s)"));
        assert_eq!(
            Fault::ClockBehind {
                now: 1_767_225_612,
                signed: 1_793_872_800
            }
            .line("stafeto"),
            "pkg: stafeto: the clock says 2026-01-01T00:00:12Z, before the index was signed at 2026-11-05T10:00:00Z; set the clock (date -s)"
        );
    }

    #[test]
    fn the_serial_goes_up_and_never_down() {
        assert_eq!(serial(1, 2), Serial::Older);
        assert_eq!(serial(2, 2), Serial::Same);
        assert_eq!(serial(3, 2), Serial::Newer);
        assert_eq!(serial(1, 0), Serial::Newer);
        assert_eq!(
            Fault::Rollback {
                what: "index",
                serial: 1,
                held: Some(2)
            }
            .line("stafeto"),
            "pkg: stafeto: index serial 1 is older than serial 2 already accepted (rollback)"
        );
        assert_eq!(
            Fault::Rollback {
                what: "revocation list",
                serial: 1,
                held: None
            }
            .line("stafeto"),
            "pkg: stafeto: revocation list 1 is older than the one already accepted (rollback)"
        );
    }

    fn list(serial: u64, entries: &[Revocation]) -> (String, Vec<u8>) {
        let text = pkgfmt::revoked::write(serial, entries).unwrap();
        let sig = Block::sign(
            &ROOT,
            Kind::Revoked,
            text.len() as u64,
            sha::sha256(text.as_bytes()),
            SIGNED,
            name("t-root"),
            None,
        )
        .to_bytes()
        .to_vec();
        (text, sig)
    }

    #[test]
    fn a_list_of_revocations_is_signed_by_a_root_and_takes_a_key_from_an_index() {
        let entry = Revocation {
            name: name("t-release"),
            since: SIGNED - 10,
        };
        let (text, sig) = list(4, &[entry]);
        let roots = [root()];
        let got = revocations(text.as_bytes(), &sig, &roots).unwrap();
        assert_eq!(got.serial, 4);
        assert_eq!(got.entries, vec![entry]);
        // The index signed by the revoked key is refused with this list.
        let data = text_index();
        let isig = sign_index(&data, SIGNED);
        let t = official(&roots);
        assert_eq!(
            index(
                data.as_bytes(),
                &isig,
                "stafeto",
                "0.3",
                &t,
                &got.entries,
                NOW
            ),
            Err(Fault::Revoked("t-release".into()))
        );
        // A list signed by a key that is no root.
        let owner = Trust {
            roots: &[],
            direct: &[],
        };
        let none = [Key {
            name: name("other"),
            public: [1; 32],
        }];
        assert!(revocations(text.as_bytes(), &sig, &none).is_err());
        let _ = owner;
        // A changed byte.
        let mut broken = text.clone().into_bytes();
        broken[0] ^= 1;
        assert_eq!(revocations(&broken, &sig, &roots), Err(Fault::BadSignature));
    }

    fn text_index() -> String {
        text("stafeto", "0.3", 2, EXPIRES)
    }
}
