// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask repo resign`: a published index signed again with a new
//! serial and a new term (docs/release.md). The weekly job of
//! `publish-packages.yml` does it for every series, and the publication of a
//! release does it once for the copy of the index in the release. The records
//! stay as they were, byte for byte: only `serial` and `expires` of the header
//! change. An index whose signature the roots of the tree do not accept, or
//! whose key the list of revocations names, is refused, so that a file laid
//! into the repository of the pages cannot get a signature of the release key.

use crate::keys::{self, Signing};
use pkgfmt::cert::Certificate;
use pkgfmt::index::Index;
use pkgfmt::sig::{Block, Kind};
use pkgfmt::{Key, Revocation, Trust, sha, time};
use std::path::PathBuf;

const DAY: u64 = 86_400;

/// What the new signature promises.
pub struct Term {
    pub serial: u64,
    pub expires_days: u64,
    pub now: u64,
    /// The certificate of the signing key has to last this many days more.
    pub certificate_days: u64,
}

/// The new text of the index and its signature block. `roots` and
/// `revocations` judge the signature of the old index; `signing` signs the
/// new one, and `accepts` is what a device must accept of it.
pub fn resign(
    text: &[u8],
    old_signature: &[u8],
    roots: &[Key],
    revocations: &[Revocation],
    signing: &Signing,
    term: &Term,
    accepts: &Trust,
) -> Result<(String, Vec<u8>), String> {
    let old_block = Block::parse(old_signature).map_err(|e| format!("INDEX.sig: {e}"))?;
    pkgfmt::trust::verify(
        &old_block,
        Kind::Index,
        &sha::sha256(text),
        text.len() as u64,
        &Trust { roots, direct: &[] },
        revocations,
    )
    .map_err(|e| format!("INDEX.sig is not accepted: {e}"))?;
    let old_text = std::str::from_utf8(text).map_err(|e| format!("INDEX: {e}"))?;
    let old = Index::parse(old_text).map_err(|e| format!("INDEX: {e}"))?;
    if term.serial < old.header.serial {
        return Err(format!(
            "--serial {} is under the serial {} of the index: a device that has seen it refuses the rollback",
            term.serial, old.header.serial
        ));
    }
    if let Some(bytes) = &signing.certificate {
        let c = Certificate::parse(bytes).map_err(|e| format!("certificate: {e}"))?;
        let left = c.not_after.saturating_sub(term.now) / DAY;
        if c.not_after < term.now + term.certificate_days * DAY {
            return Err(format!(
                "the certificate of {} ends in {left} days, under the {} days a signature wants",
                signing.key.as_str(),
                term.certificate_days
            ));
        }
    }
    let (head, records) = old_text
        .split_once("\n\n")
        .ok_or("INDEX: no empty line after the header")?;
    let mut buf = [0u8; time::TEXT_LEN];
    let expires = time::format(term.now + term.expires_days * DAY, &mut buf)
        .ok_or("the term does not fit a date")?;
    let mut new_head = Vec::new();
    for line in head.lines() {
        new_head.push(match line.split_once(' ') {
            Some(("serial", _)) => format!("serial {}", term.serial),
            Some(("expires", _)) => format!("expires {expires}"),
            _ => line.to_string(),
        });
    }
    let new_text = format!("{}\n\n{records}", new_head.join("\n"));
    let new = Index::parse(&new_text).map_err(|e| format!("the new INDEX: {e}"))?;
    let same = old.header.repository == new.header.repository
        && old.header.series == new.header.series
        && old.header.arch == new.header.arch
        && old.entries().eq(new.entries());
    if !same || new.header.serial != term.serial {
        return Err(
            "the new index differs from the old one in more than serial and expires".into(),
        );
    }
    let block = Block::sign(
        &signing.seed,
        Kind::Index,
        new_text.len() as u64,
        sha::sha256(new_text.as_bytes()),
        term.now,
        signing.key,
        signing.certificate,
    );
    pkgfmt::trust::verify(
        &block,
        Kind::Index,
        &sha::sha256(new_text.as_bytes()),
        new_text.len() as u64,
        accepts,
        &[],
    )
    .map_err(|e| {
        format!(
            "the signature of the key {} is not accepted: {e}",
            signing.key.as_str()
        )
    })?;
    Ok((new_text, block.to_bytes().to_vec()))
}

/// The serial for the index of a release: that of the index published at `base`
/// plus one, after the roots of the tree have accepted its signature (the time of
/// a revoked key does not matter here: only the number is taken), or 1 when
/// the series is not published. The signing job takes the number from nowhere else.
pub fn serial_after(
    base: &str,
    fetch: crate::carry::Fetch<'_>,
    roots: &[Key],
) -> Result<u64, String> {
    let get = |name: &str| fetch(&crate::carry::address_of(base, name));
    let Some(text) = get("INDEX")? else {
        return Ok(1);
    };
    let sig = get("INDEX.sig")?.ok_or_else(|| format!("{base}: INDEX.sig is missing"))?;
    let block = Block::parse(&sig).map_err(|e| format!("INDEX.sig: {e}"))?;
    pkgfmt::trust::verify(
        &block,
        Kind::Index,
        &sha::sha256(&text),
        text.len() as u64,
        &Trust { roots, direct: &[] },
        &[],
    )
    .map_err(|e| format!("{base}: INDEX.sig is not accepted: {e}"))?;
    let text = std::str::from_utf8(&text).map_err(|e| format!("INDEX: {e}"))?;
    let serial = Index::parse(text)
        .map_err(|e| format!("INDEX: {e}"))?
        .header
        .serial;
    // A number near the end of u64 is a number nobody could follow.
    if serial >= u64::MAX / 2 {
        return Err(format!("{base}: the serial {serial} is out of reason"));
    }
    Ok(serial + 1)
}

/// `cargo xtask repo resign --index F --serial N --out D [--sig F.sig]
/// [--expires-days D] [--key K.key --cert K.cert] [--root R.pub]
/// [--min-certificate-days N]`. The roots are the official ones and the list
/// is `keys/revoked`, unless `--root` names the root of a probe.
pub fn command(args: &[String]) -> Result<(), String> {
    let usage = "usage: cargo xtask repo resign --index F --serial N --out D [--sig F.sig] [--expires-days D] [--key K.key [--cert K.cert]] [--root R.pub] [--min-certificate-days N]";
    let (mut index, mut sig, mut out, mut key, mut cert, mut root) =
        (None, None, None, None, None, None);
    let (mut serial, mut expires_days, mut certificate_days) = (None, 30u64, 0u64);
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        i += 1;
        let value = args
            .get(i)
            .cloned()
            .ok_or_else(|| format!("{flag} wants a value\n{usage}"))?;
        let number = |what: &str| {
            value
                .parse::<u64>()
                .map_err(|_| format!("{what} {value}: not a number"))
        };
        match flag {
            "--index" => index = Some(PathBuf::from(&value)),
            "--sig" => sig = Some(PathBuf::from(&value)),
            "--out" => out = Some(PathBuf::from(&value)),
            "--key" => key = Some(PathBuf::from(&value)),
            "--cert" => cert = Some(PathBuf::from(&value)),
            "--root" => root = Some(PathBuf::from(&value)),
            "--serial" => serial = Some(number("--serial")?),
            "--expires-days" => {
                expires_days = number("--expires-days")?;
                if expires_days == 0 || expires_days > 30 {
                    return Err("--expires-days: an index lives 1 to 30 days".into());
                }
            }
            "--min-certificate-days" => certificate_days = number("--min-certificate-days")?,
            other => return Err(format!("{other}: unknown argument\n{usage}")),
        }
        i += 1;
    }
    let (index, out, serial) = (index.ok_or(usage)?, out.ok_or(usage)?, serial.ok_or(usage)?);
    let sig = sig.unwrap_or_else(|| PathBuf::from(format!("{}.sig", index.display())));
    let tree = crate::root();
    let (roots, revocations) = match &root {
        Some(path) => {
            let text =
                std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
            let key = pkgfmt::keyfile::parse_public(&text)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            let list = crate::carry::tree_revocations(&tree, true)?;
            (vec![key], list.map(|(_, l)| l).unwrap_or_default())
        }
        None => (
            keys::official_roots()?,
            crate::carry::tree_revocations(&tree, false)?
                .map(|(_, l)| l)
                .unwrap_or_default(),
        ),
    };
    let signing = keys::signing(key.as_deref(), cert.as_deref(), &tree)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let text = std::fs::read(&index).map_err(|e| format!("{}: {e}", index.display()))?;
    let old = std::fs::read(&sig).map_err(|e| format!("{}: {e}", sig.display()))?;
    let (own_roots, direct) = keys::trust_of(&signing, &tree)?;
    let (new_text, new_sig) = resign(
        &text,
        &old,
        &roots,
        &revocations,
        &signing,
        &Term {
            serial,
            expires_days,
            now,
            certificate_days,
        },
        &Trust {
            roots: &own_roots,
            direct: &direct,
        },
    )?;
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    std::fs::write(out.join("INDEX"), new_text).map_err(|e| format!("INDEX: {e}"))?;
    std::fs::write(out.join("INDEX.sig"), new_sig).map_err(|e| format!("INDEX.sig: {e}"))?;
    println!(
        "repo resign: serial {serial}, signed by {}, in {}",
        signing.key.as_str(),
        out.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkgfmt::Name;
    use pkgfmt::cert::PURPOSE_PACKAGES;
    use pkgfmt::index::{Entry, Header};
    use pkgfmt::sig;

    const ROOT: [u8; 32] = [3; 32];
    const REL: [u8; 32] = [5; 32];
    const OTHER: [u8; 32] = [6; 32];
    const NOW: u64 = 1_800_000_000;

    fn n(s: &str) -> Name {
        Name::new(s).unwrap()
    }

    fn root() -> Key {
        Key {
            name: n("t-root"),
            public: sig::public_key(&ROOT),
        }
    }

    fn signing(seed: &[u8; 32], name: &str, until: u64) -> Signing {
        Signing {
            seed: *seed,
            key: n(name),
            certificate: Some(
                Certificate::issue(
                    &ROOT,
                    n("t-root"),
                    n(name),
                    sig::public_key(seed),
                    PURPOSE_PACKAGES,
                    0,
                    until,
                )
                .to_bytes(),
            ),
        }
    }

    /// An index of two entries with serial 5 signed by `s`, and its signature.
    fn index(s: &Signing) -> (String, Vec<u8>) {
        let entry = |name: &'static str, file: &'static str| Entry {
            name,
            version: "1.0-1",
            provides: None,
            depends: None,
            needs: None,
            license: "MIT",
            size: 7,
            sha256: "ab".repeat(32).leak(),
            recipe: "cd".repeat(32).leak(),
            file,
            source: Some("src/x-src.tar.xz"),
            summary: "a summary",
        };
        let text = pkgfmt::index::write(
            &Header {
                repository: "stafeto",
                series: "0.3",
                arch: "aarch64",
                serial: 5,
                expires: NOW + DAY,
            },
            &[
                entry("a", "https://example.org/a.stpkg"),
                entry("b", "b.stpkg"),
            ],
        )
        .unwrap();
        let block = Block::sign(
            &s.seed,
            Kind::Index,
            text.len() as u64,
            sha::sha256(text.as_bytes()),
            NOW - DAY,
            s.key,
            s.certificate,
        );
        (text, block.to_bytes().to_vec())
    }

    fn term(serial: u64) -> Term {
        Term {
            serial,
            expires_days: 30,
            now: NOW,
            certificate_days: 35,
        }
    }

    fn go(
        text: &[u8],
        sig: &[u8],
        revoked: &[Revocation],
        by: &Signing,
        t: &Term,
    ) -> Result<(String, Vec<u8>), String> {
        let trust = Trust {
            roots: &[root()],
            direct: &[],
        };
        resign(text, sig, &[root()], revoked, by, t, &trust)
    }

    #[test]
    fn the_records_stay_byte_for_byte_and_the_header_moves() {
        let old = signing(&REL, "t-release", NOW * 2);
        let (text, sig) = index(&old);
        let (new_text, new_sig) = go(text.as_bytes(), &sig, &[], &old, &term(6)).unwrap();
        let tail = |t: &str| t.split_once("\n\n").unwrap().1.to_string();
        assert_eq!(tail(&text), tail(&new_text));
        assert!(new_text.contains("\nserial 6\n"));
        assert!(
            new_text.contains("\nexpires 2027-02-14T08:00:00Z\n"),
            "{new_text}"
        );
        assert_ne!(new_text, text);
        let block = Block::parse(&new_sig).unwrap();
        assert_eq!(block.time, NOW);
        pkgfmt::trust::verify(
            &block,
            Kind::Index,
            &sha::sha256(new_text.as_bytes()),
            new_text.len() as u64,
            &Trust {
                roots: &[root()],
                direct: &[],
            },
            &[],
        )
        .unwrap();
    }

    #[test]
    fn an_index_with_a_wrong_signature_is_not_signed_again() {
        let old = signing(&REL, "t-release", NOW * 2);
        let (text, sig) = index(&old);
        // A record changed after the signature.
        let forged = text.replace("size 7", "size 8");
        let e = go(forged.as_bytes(), &sig, &[], &old, &term(6)).unwrap_err();
        assert!(e.contains("not accepted"), "{e}");
        // A key no root vouches for.
        let stranger = Signing {
            certificate: Some(
                Certificate::issue(
                    &OTHER,
                    n("t-root"),
                    n("t-release"),
                    sig::public_key(&REL),
                    PURPOSE_PACKAGES,
                    0,
                    NOW * 2,
                )
                .to_bytes(),
            ),
            ..signing(&REL, "t-release", NOW * 2)
        };
        let (text, sig) = index(&stranger);
        assert!(go(text.as_bytes(), &sig, &[], &old, &term(6)).is_err());
        // A broken block.
        assert!(go(text.as_bytes(), &sig[..sig.len() - 1], &[], &old, &term(6)).is_err());
    }

    #[test]
    fn an_index_signed_after_the_leak_of_its_key_is_not_signed_again() {
        let old = signing(&REL, "t-release", NOW * 2);
        let (text, sig) = index(&old);
        let leak = [Revocation {
            name: n("t-release"),
            since: NOW - 2 * DAY,
        }];
        assert!(go(text.as_bytes(), &sig, &leak, &old, &term(6)).is_err());
        let before = [Revocation {
            name: n("t-release"),
            since: NOW,
        }];
        assert!(go(text.as_bytes(), &sig, &before, &old, &term(6)).is_ok());
    }

    #[test]
    fn the_serial_of_a_release_follows_the_published_index_and_nothing_else() {
        let dir = std::env::temp_dir().join(format!("stafeto-after-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.to_str().unwrap();
        let fetch = crate::carry::fetch;
        assert_eq!(
            serial_after(base, &fetch, &[root()]).unwrap(),
            1,
            "not published"
        );
        let by = signing(&REL, "t-release", NOW * 2);
        let (text, sig) = index(&by);
        std::fs::write(dir.join("INDEX"), &text).unwrap();
        std::fs::write(dir.join("INDEX.sig"), &sig).unwrap();
        assert_eq!(serial_after(base, &fetch, &[root()]).unwrap(), 6);
        // A forged number, a stranger's signature and a number near the end are refused.
        std::fs::write(dir.join("INDEX"), text.replace("serial 5", "serial 9")).unwrap();
        assert!(serial_after(base, &fetch, &[root()]).is_err());
        let high = text.replace("serial 5", "serial 18446744073709551614");
        std::fs::write(dir.join("INDEX"), &high).unwrap();
        let block = Block::sign(
            &by.seed,
            Kind::Index,
            high.len() as u64,
            sha::sha256(high.as_bytes()),
            NOW,
            by.key,
            by.certificate,
        );
        std::fs::write(dir.join("INDEX.sig"), block.to_bytes()).unwrap();
        assert!(
            serial_after(base, &fetch, &[root()])
                .unwrap_err()
                .contains("out of reason")
        );
        std::fs::write(dir.join("INDEX"), &text).unwrap();
        std::fs::write(dir.join("INDEX.sig"), &sig).unwrap();
        assert!(serial_after(base, &fetch, &[]).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_serial_does_not_go_back() {
        let old = signing(&REL, "t-release", NOW * 2);
        let (text, sig) = index(&old);
        assert!(
            go(text.as_bytes(), &sig, &[], &old, &term(4))
                .unwrap_err()
                .contains("rollback")
        );
        assert!(go(text.as_bytes(), &sig, &[], &old, &term(5)).is_ok());
    }

    #[test]
    fn a_certificate_that_ends_within_35_days_is_refused() {
        let old = signing(&REL, "t-release", NOW * 2);
        let (text, sig) = index(&old);
        let soon = signing(&REL, "t-release", NOW + 34 * DAY);
        let e = go(text.as_bytes(), &sig, &[], &soon, &term(6)).unwrap_err();
        assert!(e.contains("ends in 34 days"), "{e}");
        let fine = signing(&REL, "t-release", NOW + 36 * DAY);
        assert!(go(text.as_bytes(), &sig, &[], &fine, &term(6)).is_ok());
    }

    #[test]
    fn a_new_signer_signs_the_same_records() {
        let old = signing(&REL, "t-release-2026", NOW * 2);
        let (text, sig) = index(&old);
        let next = signing(&OTHER, "t-release-2027", NOW * 2);
        let (new_text, new_sig) = go(text.as_bytes(), &sig, &[], &next, &term(6)).unwrap();
        assert_eq!(
            Block::parse(&new_sig).unwrap().key.as_str(),
            "t-release-2027"
        );
        assert_eq!(Index::parse(&new_text).unwrap().header.serial, 6);
    }
}
