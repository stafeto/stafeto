// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The line the shell edits (spec 13.6): the bytes of input one at a
//! time, each with what the shell echoes for it. CR or LF ends the line,
//! and an LF right after the CR that ended a line ends nothing, so a CR LF
//! pair ends one; DEL and BS take the last byte back; the line keeps its
//! first LINE_MAX bytes and drops the rest, and other control bytes.

/// The bytes of a line at most.
pub const LINE_MAX: usize = 128;
/// Backspace and delete: each takes the last byte back.
pub const BACKSPACE: u8 = 0x08;
pub const DELETE: u8 = 0x7F;
/// What the shell echoes for a byte taken back: over it, a space, back.
pub const ERASE: &[u8] = b"\x08 \x08";

/// What a byte of input does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// The byte joined the line: echo it.
    Echo(u8),
    /// The last byte went: echo ERASE.
    Erase,
    /// The line ended: echo a newline and run it.
    End,
    /// Nothing changed and nothing is echoed.
    Nothing,
}

/// A line as it is typed.
pub struct Line {
    bytes: [u8; LINE_MAX],
    len: usize,
    /// The last byte was the CR that ended a line.
    after_cr: bool,
}

impl Line {
    pub const fn new() -> Line {
        Line {
            bytes: [0; LINE_MAX],
            len: 0,
            after_cr: false,
        }
    }

    /// Takes byte `b` of input (the rules above).
    pub fn push(&mut self, b: u8) -> Step {
        let after_cr = core::mem::replace(&mut self.after_cr, false);
        match b {
            b'\r' => {
                self.after_cr = true;
                Step::End
            }
            b'\n' if after_cr => Step::Nothing,
            b'\n' => Step::End,
            BACKSPACE | DELETE if self.len > 0 => {
                self.len -= 1;
                Step::Erase
            }
            0..=0x1F | DELETE => Step::Nothing,
            _ if self.len == LINE_MAX => Step::Nothing,
            _ => {
                self.bytes[self.len] = b;
                self.len += 1;
                Step::Echo(b)
            }
        }
    }

    /// The line so far.
    pub fn text(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// An empty line for the next command; an LF that follows the CR of
    /// the last still ends nothing.
    pub fn clear(&mut self) {
        self.len = 0;
    }
}

impl Default for Line {
    fn default() -> Line {
        Line::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pushes `input` into `line`: the steps, and the line when one ended.
    fn typed(line: &mut Line, input: &[u8]) -> Vec<Step> {
        input.iter().map(|&b| line.push(b)).collect()
    }

    #[test]
    fn a_line_ends_at_cr_or_lf() {
        for end in *b"\r\n" {
            let mut line = Line::new();
            let steps = typed(&mut line, b"help");
            assert!(steps.iter().all(|s| matches!(s, Step::Echo(_))));
            assert_eq!(line.push(end), Step::End, "{end:#x}");
            assert_eq!(line.text(), b"help");
            line.clear();
            assert_eq!(line.text(), b"");
        }
        // An empty line ends too.
        assert_eq!(Line::new().push(b'\r'), Step::End);
    }

    #[test]
    fn a_cr_lf_pair_ends_one_line() {
        let mut line = Line::new();
        typed(&mut line, b"ps");
        assert_eq!(line.push(b'\r'), Step::End);
        line.clear();
        assert_eq!(line.push(b'\n'), Step::Nothing);
        // An LF later, or a second CR, ends a line of its own.
        assert_eq!(line.push(b'\n'), Step::End);
        assert_eq!(line.push(b'\r'), Step::End);
        assert_eq!(line.push(b'\r'), Step::End);
        // Across the pair the next line starts clean.
        line.clear();
        assert_eq!(
            typed(&mut line, b"\nmem\r\n"),
            [
                Step::Nothing,
                Step::Echo(b'm'),
                Step::Echo(b'e'),
                Step::Echo(b'm'),
                Step::End,
                Step::Nothing,
            ]
        );
        assert_eq!(line.text(), b"mem");
    }

    #[test]
    fn backspace_takes_the_last_byte_back() {
        let mut line = Line::new();
        typed(&mut line, b"echp");
        assert_eq!(line.push(DELETE), Step::Erase);
        assert_eq!(line.text(), b"ech");
        assert_eq!(line.push(BACKSPACE), Step::Erase);
        assert_eq!(line.text(), b"ec");
        typed(&mut line, b"ho");
        assert_eq!(line.text(), b"echo");
        // Nothing is taken back from an empty line, and other control
        // bytes are dropped.
        let mut empty = Line::new();
        assert_eq!(empty.push(DELETE), Step::Nothing);
        assert_eq!(empty.push(BACKSPACE), Step::Nothing);
        assert_eq!(empty.push(0x1B), Step::Nothing);
        assert_eq!(empty.text(), b"");
    }

    #[test]
    fn a_long_line_keeps_its_first_128_bytes() {
        let mut line = Line::new();
        let input: Vec<u8> = (0..200).map(|i| b'a' + (i % 26) as u8).collect();
        let steps = typed(&mut line, &input);
        let echoed = steps.iter().filter(|s| matches!(s, Step::Echo(_))).count();
        assert_eq!(echoed, LINE_MAX);
        assert_eq!(line.text(), &input[..LINE_MAX]);
        // Room comes back with a byte taken back.
        assert_eq!(line.push(DELETE), Step::Erase);
        assert_eq!(line.push(b'!'), Step::Echo(b'!'));
        assert_eq!(line.text().last(), Some(&b'!'));
        assert_eq!(line.push(b'\r'), Step::End);
        assert_eq!(line.text().len(), LINE_MAX);
    }
}
