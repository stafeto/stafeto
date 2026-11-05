// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The line of every refusal of the package service (pk4-design R14): one
//! line to the standard error, `pkg: <package or repository>: <reason>`, for
//! each of the codes of `proto_pkg::CODES`. A test goes through all of them,
//! so a code the service learns without a line here fails the build of the
//! tests.

use crate::output::megabytes;
use alloc::format;
use alloc::string::String;
use proto_pkg as p;

/// There is no session with the package service in this image.
pub const NO_SERVICE: &str = "pkg: no package service in this image";
/// The channel of the session says the service ended.
pub const SERVICE_GONE: &str = "pkg: the package service is not running, reboot";
/// The service is still starting after the wait.
pub const STARTING: &str = "pkg: the package service is still starting; try again";
/// Another installation holds the store.
pub const BUSY: &str = "pkg: another installation is running";
pub const DENIED: &str = "pkg: permission denied";

/// What a line may name besides the subject.
#[derive(Clone, Copy, Debug, Default)]
pub struct Detail<'a> {
    /// The length the package was to have, for TOO_LONG.
    pub size: u64,
    /// The bytes free on the disk, for NO_SPACE.
    pub free: u64,
    /// The repository, for UNTRUSTED_KEY.
    pub repository: &'a str,
    /// The package that needs the subject, for NEEDED_BY.
    pub needed_by: &'a str,
}

/// The line for the refusal `code` of the service about `subject`.
pub fn line(code: u32, subject: &str, d: &Detail<'_>) -> String {
    let about = |reason: &str| format!("pkg: {subject}: {reason}");
    match code {
        p::NOT_ALLOWED => DENIED.into(),
        p::BAD_SIGNATURE => about("bad signature"),
        p::BAD_HASH => about("the file is not the one the index names"),
        p::BAD_MANIFEST => about("a file does not match its manifest"),
        p::UNTRUSTED_KEY => about(&format!(
            "signed by a key the repository {} does not trust",
            d.repository
        )),
        p::CONFLICT => about("a path of the package is already there"),
        p::NO_SPACE => about(&format!(
            "no space on the disk ({} free)",
            megabytes(d.free)
        )),
        p::NO_MEMORY => about("not enough memory in the package service"),
        p::TOO_LONG => about(&format!("the server sent more than {} bytes", d.size)),
        p::IN_IMAGE => about("part of the image"),
        p::NEEDED_BY if d.needed_by.is_empty() => about("needed by another package"),
        p::NEEDED_BY => about(&format!("needed by {}", d.needed_by)),
        p::ROLLBACK => {
            about("the revocation list is older than the one already accepted (rollback)")
        }
        p::WRONG_SERIES => about("built for another series"),
        p::REVOKED => about("signed by a revoked key"),
        p::BAD_PACKAGE => about("not a valid package (name, version or layout)"),
        p::NOT_FOUND => about("not installed"),
        p::BUSY => BUSY.into(),
        p::NO_BUFFER => "pkg: the package service has no buffer free".into(),
        p::IO => "pkg: the disk failed; nothing changed".into(),
        p::NO_FLUSH => "pkg: the disk cannot flush; nothing is written".into(),
        p::DAMAGED => "pkg: the store is damaged; see pkg check".into(),
        p::INVALID => about("the package service refused the request as invalid"),
        other => about(&format!("the package service refused with {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeSet;

    fn detail() -> Detail<'static> {
        Detail {
            size: 1234,
            free: 5_500_000,
            repository: "stafeto",
            needed_by: "doomgeneric",
        }
    }

    #[test]
    fn every_code_of_the_service_has_a_line_of_its_own() {
        let mut seen = BTreeSet::new();
        for code in p::CODES {
            let text = line(code, "hello", &detail());
            assert!(text.starts_with("pkg: "), "{code}: {text}");
            assert!(
                !text.contains("the package service refused with"),
                "{code}: {text}"
            );
            assert!(!text.contains('\u{2014}'));
            assert!(seen.insert(text.clone()), "{code} repeats the line {text}");
        }
        assert_eq!(seen.len(), p::CODES.len());
        assert_eq!(p::CODES.len(), 22);
    }

    #[test]
    fn the_lines_of_the_note() {
        let d = detail();
        let l = |code, subject| line(code, subject, &d);
        assert_eq!(l(p::NOT_ALLOWED, "x"), "pkg: permission denied");
        assert_eq!(
            l(p::BAD_HASH, "hello"),
            "pkg: hello: the file is not the one the index names"
        );
        assert_eq!(l(p::BAD_SIGNATURE, "hello"), "pkg: hello: bad signature");
        assert_eq!(
            l(p::UNTRUSTED_KEY, "alien"),
            "pkg: alien: signed by a key the repository stafeto does not trust"
        );
        assert_eq!(
            l(p::REVOKED, "hello"),
            "pkg: hello: signed by a revoked key"
        );
        assert_eq!(
            l(p::BAD_MANIFEST, "hello"),
            "pkg: hello: a file does not match its manifest"
        );
        assert_eq!(
            l(p::BAD_PACKAGE, "hello"),
            "pkg: hello: not a valid package (name, version or layout)"
        );
        assert_eq!(
            l(p::WRONG_SERIES, "hello"),
            "pkg: hello: built for another series"
        );
        assert_eq!(
            l(p::NO_SPACE, "freedoom"),
            "pkg: freedoom: no space on the disk (5.5 MB free)"
        );
        assert_eq!(
            l(p::TOO_LONG, "freedoom"),
            "pkg: freedoom: the server sent more than 1234 bytes"
        );
        assert_eq!(l(p::IN_IMAGE, "doom"), "pkg: doom: part of the image");
        assert_eq!(
            l(p::NEEDED_BY, "freedoom"),
            "pkg: freedoom: needed by doomgeneric"
        );
        assert_eq!(l(p::NOT_FOUND, "doom"), "pkg: doom: not installed");
        assert_eq!(l(p::BUSY, "x"), "pkg: another installation is running");
        assert_eq!(
            l(p::DAMAGED, "x"),
            "pkg: the store is damaged; see pkg check"
        );
        assert_eq!(
            line(p::NEEDED_BY, "freedoom", &Detail::default()),
            "pkg: freedoom: needed by another package"
        );
        assert_eq!(
            l(9999, "x"),
            "pkg: x: the package service refused with 9999"
        );
    }
}
