// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The file `meta` of a package: UTF-8 text, one `key value` line per key,
//! exactly these keys in this order, each once. A list with no members is
//! written `-`. No other key, no other order, no empty value, no space at
//! the end of a line, a newline at the end of the file, 512 bytes a line.
//!
//! ```text
//! name doomgeneric
//! version e257a09527062bfb986b6e5e0780839b6cbd5b71
//! release 1
//! arch aarch64
//! series 0.2
//! license GPL-2.0-or-later
//! depends freedoom
//! provides doom
//! needs display input
//! summary Doom engine (Doomgeneric)
//! url https://github.com/ozkl/doomgeneric/archive/e257a095.tar.gz
//! sha256 <64 hex digits: the source>
//! recipe <64 hex digits>
//! commit <40 hex digits: the commit of stafeto that built it>
//! relibc pin-<8 hex digits> | -
//! size <total length of the content files, bytes>
//! ```

use crate::Error;
use crate::text::{Lines, decimal, field, names_ok};

pub const LINE_MAX: usize = 512;
/// `meta` is at most this long.
pub const FILE_MAX: usize = 4096;
const KEYS: [&str; 16] = [
    "name", "version", "release", "arch", "series", "license", "depends", "provides", "needs",
    "summary", "url", "sha256", "recipe", "commit", "relibc", "size",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meta<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub release: &'a str,
    pub arch: &'a str,
    pub series: &'a str,
    pub license: &'a str,
    pub depends: &'a str,
    pub provides: &'a str,
    pub needs: &'a str,
    pub summary: &'a str,
    pub url: &'a str,
    pub sha256: &'a str,
    pub recipe: &'a str,
    pub commit: &'a str,
    pub relibc: &'a str,
    pub size: u64,
}

/// The members of a list value (`-` is none).
pub fn list(value: &str) -> impl Iterator<Item = &str> {
    value.split(' ').filter(|w| *w != "-")
}

fn hex(v: &str, n: usize) -> bool {
    v.len() == n
        && v.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn valid(key: &str, v: &str) -> bool {
    match key {
        "name" => crate::text::package_name(v),
        "version" => {
            !v.is_empty()
                && v.len() <= 96
                && v.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._+~-".contains(&c))
        }
        "release" => decimal(v).is_some(),
        "arch" => v == "aarch64",
        "series" => v
            .split_once('.')
            .is_some_and(|(a, b)| decimal(a).is_some() && decimal(b).is_some()),
        "license" => v.is_ascii(),
        "depends" | "provides" => names_ok(v),
        "needs" => {
            v == "-"
                || v.split(' ')
                    .all(|w| matches!(w, "display" | "input" | "net"))
        }
        "summary" => v.len() <= 80 && v.is_ascii() && !v.contains('"'),
        "url" => v.starts_with("https://") && !v.contains(' '),
        "sha256" | "recipe" => hex(v, 64),
        "commit" => hex(v, 40),
        "relibc" => v == "-" || v.strip_prefix("pin-").is_some_and(|h| hex(h, 8)),
        "size" => decimal(v).is_some(),
        _ => false,
    }
}

impl<'a> Meta<'a> {
    pub fn parse(text: &'a str) -> Result<Meta<'a>, Error> {
        let mut lines = Lines::new(text, LINE_MAX);
        let mut values = [""; 16];
        for (slot, key) in values.iter_mut().zip(KEYS) {
            let (n, line) = match lines.next_line() {
                Ok(Some(l)) => l,
                Ok(None) => return Err(Error::BadMeta(lines.number() + 1)),
                Err(n) => return Err(Error::BadMeta(n)),
            };
            let v = field(line, key)
                .filter(|v| valid(key, v))
                .ok_or(Error::BadMeta(n))?;
            *slot = v;
        }
        match lines.next_line() {
            Ok(None) => {}
            Ok(Some((n, _))) | Err(n) => return Err(Error::BadMeta(n)),
        }
        let [
            name,
            version,
            release,
            arch,
            series,
            license,
            depends,
            provides,
            needs,
            summary,
            url,
            sha256,
            recipe,
            commit,
            relibc,
            size,
        ] = values;
        Ok(Meta {
            name,
            version,
            release,
            arch,
            series,
            license,
            depends,
            provides,
            needs,
            summary,
            url,
            sha256,
            recipe,
            commit,
            relibc,
            size: decimal(size).ok_or(Error::BadMeta(16))?,
        })
    }

    /// The text of `meta`; `parse` reads it back.
    #[cfg(any(test, feature = "write"))]
    pub fn to_text(&self) -> Result<alloc::string::String, Error> {
        let size = alloc::format!("{}", self.size);
        let values = [
            self.name,
            self.version,
            self.release,
            self.arch,
            self.series,
            self.license,
            self.depends,
            self.provides,
            self.needs,
            self.summary,
            self.url,
            self.sha256,
            self.recipe,
            self.commit,
            self.relibc,
            &size,
        ];
        let mut out = alloc::string::String::new();
        for (key, v) in KEYS.iter().zip(values) {
            out.push_str(&alloc::format!("{key} {v}\n"));
        }
        Meta::parse(&out)?;
        Ok(out)
    }
}

#[cfg(test)]
pub(crate) fn sample() -> Meta<'static> {
    Meta {
        name: "doomgeneric",
        version: "e257a09527062bfb986b6e5e0780839b6cbd5b71",
        release: "1",
        arch: "aarch64",
        series: "0.2",
        license: "GPL-2.0-or-later",
        depends: "freedoom",
        provides: "doom",
        needs: "display input",
        summary: "Doom engine (Doomgeneric)",
        url: "https://github.com/ozkl/doomgeneric/archive/e257a09527062bfb986b6e5e0780839b6cbd5b71.tar.gz",
        sha256: "26f8f60daa6c6e4d3c01e5eac9fb700d592dede803d13ac848154ff356b2a2e7",
        recipe: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        commit: "43e5fdb5aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relibc: "pin-0a1b2c3d",
        size: 1234,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn meta_round_trips() {
        let text = sample().to_text().unwrap();
        assert_eq!(Meta::parse(&text), Ok(sample()));
        assert!(text.starts_with("name doomgeneric\nversion e257"));
        assert_eq!(
            list("display input").collect::<Vec<_>>(),
            ["display", "input"]
        );
        assert_eq!(list("-").count(), 0);
    }

    #[test]
    fn mistakes_name_their_line() {
        let good = sample().to_text().unwrap();
        let line_of = |bad: &str| match Meta::parse(bad) {
            Err(Error::BadMeta(n)) => n,
            other => panic!("{other:?}"),
        };
        // Two lines swapped.
        let l: Vec<&str> = good.lines().collect();
        let mut swapped = l.clone();
        swapped.swap(2, 3);
        assert_eq!(line_of(&(swapped.join("\n") + "\n")), 3);
        // An unknown key, an empty value, a trailing space, no final newline.
        assert_eq!(line_of(&good.replace("release 1", "relase 1")), 3);
        assert_eq!(line_of(&good.replace("release 1\n", "release \n")), 3);
        assert_eq!(line_of(&good.replace("release 1\n", "release 1 \n")), 3);
        assert_eq!(line_of(good.trim_end()), 16);
        assert_eq!(
            line_of(&good.replace("needs display input", "needs sound")),
            9
        );
        assert_eq!(line_of(&good.replace("release 1", "release 01")), 3);
        assert_eq!(line_of(&good.replace("arch aarch64", "arch x86")), 4);
        assert_eq!(line_of(&(good.clone() + "extra 1\n")), 17);
        assert_eq!(
            line_of(&good.replace(
                "name doomgeneric",
                &alloc::format!("name {}", "a".repeat(600))
            )),
            1
        );
        assert_eq!(
            line_of(&good.replace("relibc pin-0a1b2c3d", "relibc pin-0A1B2C3D")),
            15
        );
    }
}
