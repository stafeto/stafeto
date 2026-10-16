// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The size of the host's window, which the host writes into the console's
//! input as a report: GS, `W`, the rows in decimal, `;`, the columns in
//! decimal and GS (GS is byte 0x1D, Ctrl-]). The console of the machine is a
//! serial line on QEMU (the PL011) and a Virtio console on Apple VZ, and
//! neither carries the size of a window beside the bytes, so the report
//! travels in the byte stream and the terminal service takes it out before
//! the discipline sees the input. Anything that does not complete the
//! report goes on to the discipline as it came; a lone GS is held until
//! the rest comes or the service's wait for it (HOLD_NS) passes, when the
//! held bytes go on as input.

/// The longest report: GS, `W`, five digits, `;`, five digits, GS.
pub const REPORT_MAX: usize = 14;

/// How long held bytes wait for the rest of a report, in nanoseconds.
pub const HOLD_NS: u64 = 75_000_000;

const GS: u8 = 0x1d;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Idle,
    /// GS came.
    Lead,
    /// `W` came, and the digits of the rows so far.
    Rows,
    /// The `;` came, and the digits of the columns so far.
    Columns,
}

/// A window size the host reported: the rows and the columns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Size {
    pub rows: u16,
    pub columns: u16,
}

/// The reader of the reports in the console's input.
pub struct Reader {
    state: State,
    held: [u8; REPORT_MAX],
    len: usize,
    rows: u32,
    columns: u32,
    digits: u8,
}

impl Default for Reader {
    fn default() -> Self {
        Self::new()
    }
}

impl Reader {
    pub const fn new() -> Self {
        Self {
            state: State::Idle,
            held: [0; REPORT_MAX],
            len: 0,
            rows: 0,
            columns: 0,
            digits: 0,
        }
    }

    /// Takes the reports out of `input`: the bytes that stay go to the
    /// front of `out`, which holds `input.len() + REPORT_MAX` bytes at
    /// least. Gives their count and the last size a report in `input`
    /// completed.
    pub fn filter(&mut self, input: &[u8], out: &mut [u8]) -> (usize, Option<Size>) {
        let mut n = 0;
        let mut size = None;
        for &b in input {
            if let Some(found) = self.step(b, out, &mut n) {
                size = Some(found);
            }
        }
        (n, size)
    }

    /// Whether bytes are held back, waiting for the rest of a report.
    pub fn pending(&self) -> bool {
        self.len > 0
    }

    /// The held bytes, as they came, into `out` (REPORT_MAX bytes at
    /// least): what no report followed within the time the service waits.
    pub fn flush(&mut self, out: &mut [u8]) -> usize {
        let mut n = 0;
        self.release(out, &mut n);
        n
    }

    fn step(&mut self, b: u8, out: &mut [u8], n: &mut usize) -> Option<Size> {
        match self.state {
            State::Idle => {}
            State::Lead => {
                if b == b'W' {
                    self.hold(b);
                    self.state = State::Rows;
                    return None;
                }
                self.release(out, n);
            }
            State::Rows | State::Columns => {
                if b.is_ascii_digit() && self.digits < 5 {
                    self.hold(b);
                    let value = if self.state == State::Rows {
                        &mut self.rows
                    } else {
                        &mut self.columns
                    };
                    *value = *value * 10 + u32::from(b - b'0');
                    self.digits += 1;
                    return None;
                }
                if b == b';' && self.state == State::Rows && self.digits > 0 {
                    self.hold(b);
                    self.state = State::Columns;
                    self.digits = 0;
                    return None;
                }
                if b == GS && self.state == State::Columns && self.digits > 0 {
                    let rows = u16::try_from(self.rows).ok().filter(|&v| v > 0);
                    let columns = u16::try_from(self.columns).ok().filter(|&v| v > 0);
                    if let (Some(rows), Some(columns)) = (rows, columns) {
                        self.reset();
                        return Some(Size { rows, columns });
                    }
                }
                self.release(out, n);
            }
        }
        // The byte is not part of a report in progress; GS starts one.
        if b == GS {
            self.hold(b);
            self.state = State::Lead;
        } else {
            out[*n] = b;
            *n += 1;
        }
        None
    }

    fn hold(&mut self, b: u8) {
        self.held[self.len] = b;
        self.len += 1;
    }

    /// The held bytes go out as they came.
    fn release(&mut self, out: &mut [u8], n: &mut usize) {
        out[*n..*n + self.len].copy_from_slice(&self.held[..self.len]);
        *n += self.len;
        self.reset();
    }

    fn reset(&mut self) {
        self.state = State::Idle;
        self.len = 0;
        self.rows = 0;
        self.columns = 0;
        self.digits = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(reader: &mut Reader, input: &[u8]) -> (Vec<u8>, Option<Size>) {
        let mut out = vec![0; input.len() + REPORT_MAX];
        let (n, size) = reader.filter(input, &mut out);
        out.truncate(n);
        (out, size)
    }

    #[test]
    fn a_report_is_taken_out_of_the_input() {
        let mut reader = Reader::new();
        let (out, size) = run(&mut reader, b"ab\x1dW40;132\x1dcd");
        assert_eq!(out, b"abcd");
        assert_eq!(
            size,
            Some(Size {
                rows: 40,
                columns: 132
            })
        );
    }

    #[test]
    fn a_report_split_between_chunks_is_held() {
        let mut reader = Reader::new();
        let (out, size) = run(&mut reader, b"x\x1dW2");
        assert_eq!((out.as_slice(), size), (&b"x"[..], None));
        let (out, size) = run(&mut reader, b"4;8");
        assert_eq!((out.as_slice(), size), (&b""[..], None));
        let (out, size) = run(&mut reader, b"0\x1dy");
        assert_eq!(out, b"y");
        assert_eq!(
            size,
            Some(Size {
                rows: 24,
                columns: 80
            })
        );
    }

    #[test]
    fn what_is_no_report_goes_on_as_it_came() {
        for input in [
            &b"\x1dx"[..],
            b"\x1dW;5\x1d",
            b"\x1dW5;\x1d",
            b"\x1dW0;5\x1d",
            b"\x1dW5;0\x1d",
            b"\x1dW5;70000\x1d",
            b"\x1dW123456;5\x1d",
            b"\x1dW5;5x",
            b"\x1d\x1d",
        ] {
            let mut reader = Reader::new();
            let (mut out, size) = run(&mut reader, input);
            // A trailing GS is held until the next byte.
            let (rest, more) = run(&mut reader, b"!");
            out.extend(rest);
            assert_eq!(size, None, "{input:?}");
            assert_eq!(more, None, "{input:?}");
            let mut want = input.to_vec();
            want.push(b'!');
            assert_eq!(out, want, "{input:?}");
        }
    }

    #[test]
    fn a_report_after_a_broken_one_is_taken() {
        let mut reader = Reader::new();
        let (out, size) = run(&mut reader, b"\x1dW5;\x1dW6;7\x1d");
        assert_eq!(out, b"\x1dW5;");
        assert_eq!(
            size,
            Some(Size {
                rows: 6,
                columns: 7
            })
        );
    }

    #[test]
    fn the_last_report_of_a_chunk_counts() {
        let mut reader = Reader::new();
        let (out, size) = run(&mut reader, b"\x1dW1;2\x1d\x1dW3;4\x1d");
        assert!(out.is_empty());
        assert_eq!(
            size,
            Some(Size {
                rows: 3,
                columns: 4
            })
        );
    }

    #[test]
    fn held_bytes_are_flushed_as_they_came() {
        let mut reader = Reader::new();
        let (out, _) = run(&mut reader, b"a\x1dW4;");
        assert_eq!(out, b"a");
        assert!(reader.pending());
        let mut flushed = [0; REPORT_MAX];
        let n = reader.flush(&mut flushed);
        assert_eq!(&flushed[..n], b"\x1dW4;");
        assert!(!reader.pending());
        let (out, size) = run(&mut reader, b"5;6\x1d");
        assert_eq!((out.as_slice(), size), (&b"5;6"[..], None));
        assert!(reader.pending());
    }

    #[test]
    fn bytes_out_never_exceed_bytes_in_plus_the_held() {
        let mut reader = Reader::new();
        let mut out = [0u8; 64 + REPORT_MAX];
        let input = [0x1d; 64];
        let (n, _) = reader.filter(&input, &mut out);
        assert!(n <= input.len() + REPORT_MAX);
    }
}
