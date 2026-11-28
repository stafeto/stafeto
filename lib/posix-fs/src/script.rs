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

/// The line of a script in `head`, the first bytes of the file. None (the caller answers ENOEXEC)
/// for a file that does not start with `#!`, a line with no interpreter, and a line whose
/// interpreter is cut: `head` is `HEAD` bytes long, has no newline, and the interpreter's path runs
/// to its end. The end of the file ends the line like a newline (a `head` shorter than `HEAD`
/// is the whole file), and a cut argument is the argument as far as it goes (as Linux since 5.0).
/// The interpreter ends at a blank or a tab; what follows it, with the blanks at both ends cut, is
/// one argument. The carriage return counts as a blank (lenient: Linux has it in the path).
pub fn parse(head: &[u8]) -> Option<Line> {
    let rest = head.strip_prefix(b"#!")?;
    let (line, cut) = match rest.iter().position(|&b| b == b'\n') {
        Some(end) => (&rest[..end], false),
        None => (rest, head.len() >= HEAD),
    };
    let blank = |b: &u8| matches!(*b, b' ' | b'\t' | b'\r');
    let start = line.iter().position(|b| !blank(b))?;
    let stop = line[start..]
        .iter()
        .position(blank)
        .map_or(line.len(), |at| start + at);
    if cut && stop == line.len() {
        return None;
    }
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

    /// The interpreter ends at a blank, the rest of the line is one argument with the blanks at its
    /// ends cut, the end of the file ends the line, and a line that is no `#!` line is no script.
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
        assert_eq!(
            line(b"#!/bin/sh"),
            Some((&b"/bin/sh"[..], None)),
            "the file's end ends the line"
        );
        assert_eq!(
            line(b"#!/bin/sh -x"),
            Some((&b"/bin/sh"[..], Some(&b"-x"[..])))
        );
        assert_eq!(line(b"#!\n"), None);
        assert_eq!(line(b"#! \t\n"), None);
        assert_eq!(line(b"# !/bin/sh\n"), None);
        assert_eq!(line(b"\x7fELF"), None);
        assert_eq!(line(b""), None);
        assert_eq!(line(b"#"), None);
    }

    /// A first line as long as the head has no end in it: a cut interpreter fails, a cut argument is
    /// the argument as far as it goes.
    #[test]
    fn a_line_cut_by_the_head_fails_in_the_interpreter_and_goes_on_in_the_argument() {
        let mut path = b"#!/".to_vec();
        path.resize(HEAD, b'a');
        assert_eq!(parse(&path), None);
        let mut argument = b"#!/bin/sh ".to_vec();
        argument.resize(HEAD, b'x');
        let l = parse(&argument).expect("a cut argument");
        assert_eq!(l.interpreter(&argument), b"/bin/sh");
        assert_eq!(l.argument(&argument).map(<[u8]>::len), Some(HEAD - 10));
        // The same bytes with a newline at the end of the head are a whole line.
        let mut whole = path.clone();
        *whole.last_mut().unwrap() = b'\n';
        assert!(parse(&whole).is_some());
    }
}
