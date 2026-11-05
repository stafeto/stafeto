// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The line rules the text files share: UTF-8, `\n` ends every line, no
//! trailing space, no control characters, and a limit on a line's length.

#[derive(Clone)]
pub(crate) struct Lines<'a> {
    rest: &'a str,
    number: u32,
    limit: usize,
}

impl<'a> Lines<'a> {
    pub(crate) fn new(text: &'a str, limit: usize) -> Lines<'a> {
        Lines {
            rest: text,
            number: 0,
            limit,
        }
    }

    /// The next line without its `\n`, or `Err(number)` of the line that
    /// breaks a rule. `Ok(None)` at the end.
    pub(crate) fn next_line(&mut self) -> Result<Option<(u32, &'a str)>, u32> {
        if self.rest.is_empty() {
            return Ok(None);
        }
        self.number += 1;
        let Some(end) = self.rest.find('\n') else {
            return Err(self.number);
        };
        let line = &self.rest[..end];
        self.rest = &self.rest[end + 1..];
        if line.len() > self.limit || line.ends_with(' ') || line.chars().any(|c| c.is_control()) {
            return Err(self.number);
        }
        Ok(Some((self.number, line)))
    }

    pub(crate) fn number(&self) -> u32 {
        self.number
    }
}

/// The value of a `key value` line when the key matches; the value is not
/// empty and starts after exactly one space.
pub(crate) fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(key)?.strip_prefix(' ')?;
    if rest.is_empty() || rest.starts_with(' ') {
        None
    } else {
        Some(rest)
    }
}

/// A decimal number without a sign, a plus or leading zeros.
pub(crate) fn decimal(text: &str) -> Option<u64> {
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    text.parse().ok()
}

/// A name of a package or of a repository piece: `[a-z0-9][a-z0-9._+-]*`,
/// at most 64 bytes.
pub(crate) fn package_name(text: &str) -> bool {
    let b = text.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._+-".contains(&c))
}

/// Words of a list line: names separated by single spaces.
pub(crate) fn names_ok(list: &str) -> bool {
    list == "-" || list.split(' ').all(package_name)
}
