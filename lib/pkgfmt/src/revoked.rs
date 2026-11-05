// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The revocation list, signed with a `Kind::Revoked` block by a root:
//!
//! ```text
//! format 1
//! serial 1
//! revoke stafeto-release-2026 2027-01-10T00:00:00Z
//! ```
//!
//! Zero or more `revoke` lines, names ascending without repeats.

use crate::text::{Lines, decimal, field};
use crate::{Error, Name, Revocation, time};

const LINE_MAX: usize = 1024;

#[derive(Debug, Clone, Copy)]
pub struct Revoked<'a> {
    pub serial: u64,
    body: &'a str,
}

fn parse_entry(line: &str) -> Option<Revocation> {
    let rest = field(line, "revoke")?;
    let (name, when) = rest.split_once(' ')?;
    Some(Revocation {
        name: Name::new(name).ok()?,
        since: time::parse(when)?,
    })
}

impl<'a> Revoked<'a> {
    pub fn parse(text: &'a str) -> Result<Revoked<'a>, Error> {
        let bad = Error::BadRevoked;
        let mut lines = Lines::new(text, LINE_MAX);
        let next = |lines: &mut Lines<'a>| lines.next_line().map_err(bad);
        match next(&mut lines)? {
            Some((_, "format 1")) => {}
            Some((n, _)) => return Err(bad(n)),
            None => return Err(bad(1)),
        }
        let serial = match next(&mut lines)? {
            Some((n, l)) => field(l, "serial").and_then(decimal).ok_or(bad(n))?,
            None => return Err(bad(2)),
        };
        let body_at = text.split_inclusive('\n').take(2).map(str::len).sum::<usize>();
        let mut previous: Option<Name> = None;
        while let Some((n, line)) = next(&mut lines)? {
            let r = parse_entry(line).ok_or(bad(n))?;
            if previous.is_some_and(|p| p.as_str() >= r.name.as_str()) {
                return Err(bad(n));
            }
            previous = Some(r.name);
        }
        Ok(Revoked {
            serial,
            body: &text[body_at..],
        })
    }

    pub fn entries(&self) -> impl Iterator<Item = Revocation> + 'a {
        self.body.lines().map(|l| parse_entry(l).expect("parse checked every line"))
    }
}

/// The text of a list; the entries may come in any order.
#[cfg(any(test, feature = "write"))]
pub fn write(serial: u64, entries: &[Revocation]) -> Result<alloc::string::String, Error> {
    use alloc::string::String;
    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| a.name.as_str().cmp(b.name.as_str()));
    let mut out = String::new();
    out.push_str(&alloc::format!("format 1\nserial {serial}\n"));
    for r in &sorted {
        let mut buf = [0u8; time::TEXT_LEN];
        let when = time::format(r.since, &mut buf).ok_or(Error::BadTime)?;
        out.push_str(&alloc::format!("revoke {} {when}\n", r.name.as_str()));
    }
    Revoked::parse(&out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn r(name: &str, since: u64) -> Revocation {
        Revocation {
            name: Name::new(name).unwrap(),
            since,
        }
    }

    #[test]
    fn a_list_round_trips() {
        let text = write(3, &[r("zed", 4_107_542_400), r("alpha", 0)]).unwrap();
        assert_eq!(
            text,
            "format 1\nserial 3\nrevoke alpha 1970-01-01T00:00:00Z\nrevoke zed 2100-03-01T00:00:00Z\n"
        );
        let parsed = Revoked::parse(&text).unwrap();
        assert_eq!(parsed.serial, 3);
        assert_eq!(
            parsed.entries().collect::<Vec<_>>(),
            [r("alpha", 0), r("zed", 4_107_542_400)]
        );
        let empty = write(1, &[]).unwrap();
        assert_eq!(empty, "format 1\nserial 1\n");
        assert_eq!(Revoked::parse(&empty).unwrap().entries().count(), 0);
    }

    #[test]
    fn mistakes_name_their_line() {
        for (text, line) in [
            ("format 2\nserial 1\n", 1),
            ("format 1\nserial 01\n", 2),
            ("format 1\nserial 1\nrevoke b 1970-01-01T00:00:00Z\nrevoke a 1970-01-01T00:00:00Z\n", 4),
            ("format 1\nserial 1\nrevoke a 1970-01-01T00:00:00Z\nrevoke a 1970-01-01T00:00:00Z\n", 4),
            ("format 1\nserial 1\nrevoke a 1970-01-01T00:00:00\n", 3),
            ("format 1\nserial 1\nrevoke A 1970-01-01T00:00:00Z\n", 3),
            ("format 1\nserial 1\n\n", 3),
            ("format 1\nserial 1\nrevoke a 1970-01-01T00:00:00Z", 3),
        ] {
            assert_eq!(Revoked::parse(text).err(), Some(Error::BadRevoked(line)), "{text:?}");
        }
    }
}
