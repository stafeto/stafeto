// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The repository index `INDEX`, signed in `INDEX.sig` by a `Kind::Index`
//! block. A header, an empty line, then the entries with one empty line
//! between them, names ascending without repeats. The fields of an entry
//! come in exactly this order; the optional ones are left out whole:
//!
//! ```text
//! format 1
//! repository stafeto
//! series 0.2
//! arch aarch64
//! serial 1
//! expires 2026-12-05T00:00:00Z
//!
//! name doomgeneric
//! version e257a09527062bfb986b6e5e0780839b6cbd5b71-1
//! provides doom                 (optional)
//! depends freedoom              (optional)
//! needs display input           (optional)
//! license GPL-2.0-or-later
//! size 1105920                  (the length of the .stpkg file)
//! sha256 <64>                   (of the whole .stpkg file, trailer included)
//! recipe <64>
//! file doomgeneric-e257a095-1.stpkg
//! source src/doomgeneric-e257a095-1-src.tar.xz   (optional)
//! summary Doom engine (Doomgeneric)
//! ```
//!
//! The notes in brackets are not in the file. A line is at most 1 024 bytes.

use crate::meta::list;
use crate::text::{Lines, decimal, field, names_ok, package_name};
use crate::{Error, time};

pub const LINE_MAX: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header<'a> {
    pub repository: &'a str,
    pub series: &'a str,
    pub arch: &'a str,
    pub serial: u64,
    /// Seconds UTC.
    pub expires: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry<'a> {
    pub name: &'a str,
    /// `<version>-<release>`.
    pub version: &'a str,
    pub provides: Option<&'a str>,
    pub depends: Option<&'a str>,
    pub needs: Option<&'a str>,
    pub license: &'a str,
    pub size: u64,
    pub sha256: &'a str,
    pub recipe: &'a str,
    pub file: &'a str,
    pub source: Option<&'a str>,
    pub summary: &'a str,
}

impl Entry<'_> {
    pub fn depends(&self) -> impl Iterator<Item = &str> {
        list(self.depends.unwrap_or("-"))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Index<'a> {
    pub header: Header<'a>,
    body: &'a str,
    count: u32,
}

fn hex64(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// A relative name (no leading `/`, no `.` or `..` or empty part) or an
/// `https://` address.
fn location(v: &str) -> bool {
    if let Some(rest) = v.strip_prefix("https://") {
        return !rest.is_empty() && !v.contains(' ');
    }
    !v.contains(' ') && v.split('/').all(|p| !p.is_empty() && p != "." && p != "..")
}

fn repository_ok(v: &str) -> bool {
    (1..=32).contains(&v.len())
        && v.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

fn version_ok(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 96
        && v.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._+~-".contains(&c))
}

/// Reads one entry; the cursor stops after its last line.
fn read_entry<'a>(lines: &mut Lines<'a>) -> Result<Entry<'a>, Error> {
    let bad = Error::BadIndex;
    // The next line of the entry, if it carries `key`.
    fn take<'a>(lines: &mut Lines<'a>, key: &str, optional: bool) -> Result<Option<&'a str>, u32> {
        let mut peek = lines.clone();
        match peek.next_line()? {
            Some((n, line)) => match field(line, key) {
                Some(v) => {
                    *lines = peek;
                    Ok(Some(v))
                }
                None if optional && !line.is_empty() => {
                    // Another key may follow; an empty line or a mismatch of
                    // a required key is the caller's error.
                    Ok(None)
                }
                None => Err(n),
            },
            None => Err(peek.number() + 1),
        }
    }
    let need = |lines: &mut Lines<'a>, key| -> Result<&'a str, Error> {
        take(lines, key, false)
            .map_err(bad)?
            .ok_or(bad(lines.number()))
    };
    let maybe = |lines: &mut Lines<'a>, key| take(lines, key, true).map_err(bad);

    let name = need(lines, "name")?;
    let line_of = |l: &Lines| l.number();
    if !package_name(name) {
        return Err(bad(line_of(lines)));
    }
    let version = need(lines, "version")?;
    if !version_ok(version) {
        return Err(bad(line_of(lines)));
    }
    let provides = maybe(lines, "provides")?;
    if provides.is_some_and(|v| !names_ok(v) || v == "-") {
        return Err(bad(line_of(lines)));
    }
    let depends = maybe(lines, "depends")?;
    if depends.is_some_and(|v| !names_ok(v) || v == "-") {
        return Err(bad(line_of(lines)));
    }
    let needs = maybe(lines, "needs")?;
    if needs.is_some_and(|v| {
        !v.split(' ')
            .all(|w| matches!(w, "display" | "input" | "net"))
    }) {
        return Err(bad(line_of(lines)));
    }
    let license = need(lines, "license")?;
    let size = decimal(need(lines, "size")?).ok_or(bad(line_of(lines)))?;
    let sha256 = need(lines, "sha256")?;
    if !hex64(sha256) {
        return Err(bad(line_of(lines)));
    }
    let recipe = need(lines, "recipe")?;
    if !hex64(recipe) {
        return Err(bad(line_of(lines)));
    }
    let file = need(lines, "file")?;
    if !location(file) {
        return Err(bad(line_of(lines)));
    }
    let source = maybe(lines, "source")?;
    if source.is_some_and(|v| !location(v)) {
        return Err(bad(line_of(lines)));
    }
    let summary = need(lines, "summary")?;
    if summary.len() > 80 || !summary.is_ascii() {
        return Err(bad(line_of(lines)));
    }
    Ok(Entry {
        name,
        version,
        provides,
        depends,
        needs,
        license,
        size,
        sha256,
        recipe,
        file,
        source,
        summary,
    })
}

impl<'a> Index<'a> {
    pub fn parse(text: &'a str) -> Result<Index<'a>, Error> {
        let bad = Error::BadIndex;
        let mut lines = Lines::new(text, LINE_MAX);
        let head = |lines: &mut Lines<'a>, key: &str| -> Result<&'a str, Error> {
            match lines.next_line().map_err(bad)? {
                Some((n, l)) => field(l, key).ok_or(bad(n)),
                None => Err(bad(lines.number() + 1)),
            }
        };
        if head(&mut lines, "format")? != "1" {
            return Err(bad(1));
        }
        let repository = head(&mut lines, "repository")?;
        if !repository_ok(repository) {
            return Err(bad(2));
        }
        let series = head(&mut lines, "series")?;
        if !series
            .split_once('.')
            .is_some_and(|(a, b)| decimal(a).is_some() && decimal(b).is_some())
        {
            return Err(bad(3));
        }
        let arch = head(&mut lines, "arch")?;
        if arch != "aarch64" {
            return Err(bad(4));
        }
        let serial = decimal(head(&mut lines, "serial")?).ok_or(bad(5))?;
        let expires = time::parse(head(&mut lines, "expires")?).ok_or(bad(6))?;
        match lines.next_line().map_err(bad)? {
            Some((_, "")) => {}
            Some((n, _)) => return Err(bad(n)),
            None => return Err(bad(7)),
        }
        let body_at = text
            .split_inclusive('\n')
            .take(7)
            .map(str::len)
            .sum::<usize>();
        let mut count = 0;
        let mut previous: Option<&str> = None;
        loop {
            let mut ahead = lines.clone();
            if ahead.next_line().map_err(bad)?.is_none() {
                break;
            }
            let start = lines.number() + 1;
            let entry = read_entry(&mut lines)?;
            if previous.is_some_and(|p| p >= entry.name) {
                return Err(bad(start));
            }
            previous = Some(entry.name);
            count += 1;
            // After an entry: the end, or one empty line and another entry.
            match lines.next_line().map_err(bad)? {
                None => break,
                Some((_, "")) => {
                    let mut ahead = lines.clone();
                    if ahead.next_line().map_err(bad)?.is_none() {
                        return Err(bad(lines.number()));
                    }
                }
                Some((n, _)) => return Err(bad(n)),
            }
        }
        Ok(Index {
            header: Header {
                repository,
                series,
                arch,
                serial,
                expires,
            },
            body: &text[body_at..],
            count,
        })
    }

    pub fn len(&self) -> u32 {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn entries(&self) -> impl Iterator<Item = Entry<'a>> {
        let mut lines = Lines::new(self.body, LINE_MAX);
        let mut left = self.count;
        core::iter::from_fn(move || {
            if left == 0 {
                return None;
            }
            left -= 1;
            let entry = read_entry(&mut lines).expect("parse checked every entry");
            let _ = lines.next_line();
            Some(entry)
        })
    }

    /// The entry named `name`.
    pub fn find(&self, name: &str) -> Option<Entry<'a>> {
        self.entries().find(|e| e.name == name)
    }
}

/// The text of an index; the entries may come in any order. The result is
/// read back.
#[cfg(any(test, feature = "write"))]
pub fn write(header: &Header<'_>, entries: &[Entry<'_>]) -> Result<alloc::string::String, Error> {
    use alloc::format;
    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| a.name.cmp(b.name));
    let mut buf = [0u8; time::TEXT_LEN];
    let expires = time::format(header.expires, &mut buf).ok_or(Error::BadTime)?;
    let mut out = format!(
        "format 1\nrepository {}\nseries {}\narch {}\nserial {}\nexpires {expires}\n\n",
        header.repository, header.series, header.arch, header.serial
    );
    for (i, e) in sorted.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let mut put = |key: &str, v: &str| out.push_str(&format!("{key} {v}\n"));
        put("name", e.name);
        put("version", e.version);
        for (key, v) in [
            ("provides", e.provides),
            ("depends", e.depends),
            ("needs", e.needs),
        ] {
            if let Some(v) = v {
                put(key, v);
            }
        }
        put("license", e.license);
        put("size", &format!("{}", e.size));
        put("sha256", e.sha256);
        put("recipe", e.recipe);
        put("file", e.file);
        if let Some(s) = e.source {
            put("source", s);
        }
        put("summary", e.summary);
    }
    Index::parse(&out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec::Vec;

    const D: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn entry<'a>(name: &'a str, file: &'a str) -> Entry<'a> {
        Entry {
            name,
            version: "1.0-1",
            provides: None,
            depends: None,
            needs: None,
            license: "MIT OR Apache-2.0",
            size: 4096,
            sha256: D,
            recipe: D,
            file,
            source: None,
            summary: "A package",
        }
    }

    fn header() -> Header<'static> {
        Header {
            repository: "stafeto",
            series: "0.2",
            arch: "aarch64",
            serial: 1,
            expires: 1_796_428_800,
        }
    }

    fn sample() -> String {
        let mut doom = entry("doomgeneric", "doomgeneric-e257a095-1.stpkg");
        doom.provides = Some("doom");
        doom.depends = Some("freedoom");
        doom.needs = Some("display input");
        doom.source = Some("src/doomgeneric-e257a095-1-src.tar.xz");
        write(
            &header(),
            &[entry("freedoom", "freedoom-0.13-1.stpkg"), doom],
        )
        .unwrap()
    }

    #[test]
    fn write_read_write_gives_the_same_bytes() {
        let text = sample();
        assert!(text.starts_with("format 1\nrepository stafeto\nseries 0.2\narch aarch64\nserial 1\nexpires 2026-12-05T00:00:00Z\n\nname doomgeneric\n"));
        let idx = Index::parse(&text).unwrap();
        assert_eq!(idx.header, header());
        assert_eq!(idx.len(), 2);
        let entries: Vec<_> = idx.entries().collect();
        assert_eq!(entries[0].name, "doomgeneric");
        assert_eq!(entries[0].depends().collect::<Vec<_>>(), ["freedoom"]);
        assert_eq!(entries[1].source, None);
        assert_eq!(idx.find("freedoom"), Some(entries[1]));
        assert_eq!(write(&idx.header, &entries).unwrap(), text);
        let empty = write(&header(), &[]).unwrap();
        assert_eq!(Index::parse(&empty).unwrap().len(), 0);
    }

    fn refused(text: &str) -> u32 {
        match Index::parse(text) {
            Err(Error::BadIndex(n)) => n,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn mistakes_name_their_line() {
        let text = sample();
        // size and license swapped: the entry starts at line 8 with provides,
        // depends and needs, so license is expected on line 13.
        let a = "license MIT OR Apache-2.0\nsize 4096\n";
        let b = "size 4096\nlicense MIT OR Apache-2.0\n";
        assert_eq!(refused(&text.replacen(a, b, 1)), 13);
        // Names out of order, an empty line inside an entry, two empty lines.
        assert_eq!(refused(&text.replace("name freedoom", "name aaa")), 21);
        assert_eq!(refused(&text.replacen("serial 1\n", "serial 1\n\n", 1)), 6);
        assert_eq!(
            refused(&text.replace("\n\nname freedoom", "\n\n\nname freedoom")),
            21
        );
        assert_eq!(refused(&text.replacen("format 1", "format 2", 1)), 1);
        assert_eq!(refused(&text.replacen("arch aarch64", "arch x86", 1)), 4);
        assert_eq!(
            refused(&text.replacen("expires 2026-12-05T00:00:00Z", "expires 2026-12-05", 1)),
            6
        );
        assert_eq!(
            refused(&text.replacen("file freedoom-0.13-1.stpkg", "file ../x", 1)),
            27
        );
        assert_eq!(
            refused(&text.replacen("file freedoom-0.13-1.stpkg", "file /x", 1)),
            27
        );
        assert_eq!(refused(&(text.clone() + "\n")), 29);
        assert_eq!(refused(text.trim_end()), 28);
        assert_eq!(refused(&text.replacen("sha256 0123", "sha256 ABCD", 1)), 15);
        let long = alloc::format!("{}summary {}\n", &text[..text.len() - 18], "x".repeat(1030));
        assert_eq!(refused(&long), 28);
    }

    #[test]
    fn locations_are_relative_or_https() {
        let mut e = entry("a", "https://example.org/a.stpkg");
        e.source = Some("src/a.tar.xz");
        assert!(Index::parse(&write(&header(), &[e]).unwrap()).is_ok());
        for bad in ["/a", "a/../b", "a//b", "a b", "./a", "http://x/a"] {
            let mut e = entry("a", bad);
            e.source = None;
            assert!(write(&header(), &[e]).is_err(), "{bad}");
        }
    }
}
