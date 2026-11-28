// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The first line of a script (`#!interpreter [argument]`), which the POSIX layer reads for a
//! script of a layer of the user (`posix_abi::script`). Pure: the host tests it.

/// The bytes of the first line a script may have: the interpreter, its argument and the newline
/// (Linux's BINPRM_BUF_SIZE).
pub const HEAD: usize = 256;

/// The line `#!interpreter [argument]` of a script, as positions in the head it was read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Line {
    interpreter: (usize, usize),
    argument: Option<(usize, usize)>,
}

impl Line {
    pub fn interpreter<'a>(&self, head: &'a [u8]) -> &'a [u8] {
        &head[self.interpreter.0..self.interpreter.1]
    }

    pub fn argument<'a>(&self, head: &'a [u8]) -> Option<&'a [u8]> {
        self.argument.map(|(from, to)| &head[from..to])
    }
}

/// The line of a script in `head`, the first bytes of the file. None for a file that does not
/// start with `#!`, a first line with no end in `head` (too long: ENOEXEC as on Linux, which cuts
/// it) and a line with no interpreter. The interpreter ends at a blank or a tab; what follows it,
/// with the blanks at both ends cut, is one argument.
pub fn parse(head: &[u8]) -> Option<Line> {
    let rest = head.strip_prefix(b"#!")?;
    let end = rest.iter().position(|&b| b == b'\n')?;
    let line = &rest[..end];
    let blank = |b: &u8| matches!(*b, b' ' | b'\t' | b'\r');
    let start = line.iter().position(|b| !blank(b))?;
    let stop = line[start..]
        .iter()
        .position(blank)
        .map_or(line.len(), |at| start + at);
    let from = line[stop..]
        .iter()
        .position(|b| !blank(b))
        .map(|at| stop + at);
    let argument = from.map(|from| {
        let to = line
            .iter()
            .rposition(|b| !blank(b))
            .map_or(from, |at| at + 1);
        (2 + from, 2 + to)
    });
    Some(Line {
        interpreter: (2 + start, 2 + stop),
        argument,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(text: &[u8]) -> Option<(&[u8], Option<&[u8]>)> {
        parse(text).map(|l| (l.interpreter(text), l.argument(text)))
    }

    /// The Linux rule: the interpreter ends at a blank, the rest of the line is one argument with
    /// the blanks at its ends cut, and a line that is no `#!` line or has no end is no script.
    #[test]
    fn the_line_has_an_interpreter_and_one_argument() {
        assert_eq!(line(b"#!/bin/sh\necho\n"), Some((&b"/bin/sh"[..], None)));
        assert_eq!(line(b"#! /bin/sh \n"), Some((&b"/bin/sh"[..], None)));
        assert_eq!(
            line(b"#!/usr/bin/env python3\n"),
            Some((&b"/usr/bin/env"[..], Some(&b"python3"[..])))
        );
        assert_eq!(
            line(b"#!\t/bin/awk  -f  x y \t\r\nBEGIN\n"),
            Some((&b"/bin/awk"[..], Some(&b"-f  x y"[..])))
        );
        assert_eq!(line(b"#!/bin/sh"), None, "a line with no end in the head");
        assert_eq!(line(b"#!\n"), None);
        assert_eq!(line(b"#! \t\n"), None);
        assert_eq!(line(b"# !/bin/sh\n"), None);
        assert_eq!(line(b"\x7fELF"), None);
        assert_eq!(line(b""), None);
        assert_eq!(line(b"#"), None);
    }
}
