// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Whole lines on the console. A record of the kernel log holds 64 bytes
//! at most and names no writer, so the pieces of a line longer than a
//! record could meet the records of another writer between them. A line
//! that fits in one record (64 bytes, its newline included) goes as it is
//! and cannot be cut. A longer line goes in tagged pieces: a header of
//! HEADER bytes (a mark, MORE for a piece with more to come and LAST for
//! the final one, an identifier of the writer's line in three printable
//! bytes, and the length of the text in one) and up to PAYLOAD bytes of
//! the text. The console's
//! driver holds the pieces of each identifier in a slot (`Lines`) and puts
//! the line out when its LAST piece comes, so lines of different writers
//! never mix.
//!
//! The bound: a driver holds SLOTS lines of up to LINE_MAX bytes each. A
//! line longer than LINE_MAX goes out in parts of LINE_MAX bytes at most,
//! each whole in itself; a line whose writer stops (no LAST piece) goes
//! out as it is after QUIET empty batches of the log; a fifth open line
//! sends out the oldest slot first. A driver that ended with lines open
//! loses their held pieces (the pieces left its ring when it took them);
//! the last piece of such a line, which comes to the next driver with no
//! slot, goes out after the mark CUT. A line all of whose pieces the dead
//! driver held leaves no trace but init's line that the driver ended.

#![no_std]

/// The mark of a piece with more of its line to come.
pub const MORE: u8 = 0x1E;
/// The mark of the last piece of a line (or of a call's last bytes).
pub const LAST: u8 = 0x1F;
/// The header: the mark, three bytes of the identifier and the length of
/// the text (0x40 + length).
pub const HEADER: usize = 5;
/// The text a tagged piece carries: a record's 64 bytes less the header.
pub const PAYLOAD: usize = 64 - HEADER;
/// The lines the driver holds open at once.
pub const SLOTS: usize = 4;
/// The longest line the driver puts out in one part.
pub const LINE_MAX: usize = 128;
/// The empty batches of the log after which the lines still open go out.
pub const QUIET: u8 = 2;
/// What goes before the last piece of a line whose earlier pieces the driver
/// does not hold: it ended and started again, or it put the line out early.
pub const CUT: &[u8] = b"[console: the start of this line was lost] ";
/// The most bytes `Lines::record` puts out for one record: the oldest slot
/// or a full line, then the line the record ends or the mark and the tail
/// of a line whose start was lost.
pub const RECORD_OUT: usize = LINE_MAX + PAYLOAD + CUT.len();
/// The most bytes `Lines::quiet` puts out.
pub const QUIET_OUT: usize = SLOTS * LINE_MAX;

/// The bytes of the identifier are 0x40 to 0x7F: six bits each.
const ID_BITS: u32 = 18;

/// A piece of `payload` (up to PAYLOAD bytes) of the line `id`, `last` or
/// not, in `out`: its length.
pub fn piece(id: u32, last: bool, payload: &[u8], out: &mut [u8; 64]) -> usize {
    assert!(payload.len() <= PAYLOAD, "a piece carries 59 bytes at most");
    out[0] = if last { LAST } else { MORE };
    out[1] = 0x40 | ((id >> 12) & 0x3F) as u8;
    out[2] = 0x40 | ((id >> 6) & 0x3F) as u8;
    out[3] = 0x40 | (id & 0x3F) as u8;
    out[4] = 0x40 + payload.len() as u8;
    out[HEADER..HEADER + payload.len()].copy_from_slice(payload);
    HEADER + payload.len()
}

/// The identifier a writer of a line takes from a counter: 18 bits.
pub fn id_from(ticks: u64) -> u32 {
    ((ticks ^ (ticks >> ID_BITS) ^ (ticks >> (2 * ID_BITS))) & ((1 << ID_BITS) - 1)) as u32
}

/// The header at the start of `bytes`: whether the piece is the last, the
/// identifier of its line and the length of its text. None when `bytes`
/// does not start with a header.
pub fn header(bytes: &[u8]) -> Option<(bool, u32, usize)> {
    let [mark, a, b, c, n, ..] = *bytes else {
        return None;
    };
    let id_byte = |x: u8| (0x40..=0x7F).contains(&x);
    if !(mark == MORE || mark == LAST) || !(id_byte(a) && id_byte(b) && id_byte(c)) {
        return None;
    }
    let len = usize::from(n.checked_sub(0x40)?);
    if len > PAYLOAD {
        return None;
    }
    let id = (u32::from(a & 0x3F) << 12) | (u32::from(b & 0x3F) << 6) | u32::from(c & 0x3F);
    Some((mark == LAST, id, len))
}

/// The longest text of one debug_write call.
pub const CALL_MAX: usize = 64;

/// `text` (an assembled line, up to LINE_MAX bytes) in the pieces one
/// debug_write call takes each, untagged: a program that shows text the
/// driver assembled, with the port the kernel's, cuts it with this.
pub fn calls(text: &[u8]) -> core::slice::Chunks<'_, u8> {
    #[cfg(feature = "break-line-split")]
    return text.chunks(2 * CALL_MAX);
    #[cfg(not(feature = "break-line-split"))]
    text.chunks(CALL_MAX)
}

/// `text` as a console that has no driver to assemble the pieces shows
/// it: a whole tagged piece without its header, anything else as it is. It
/// allocates nothing and keeps no state; the kernel calls it where it
/// writes a record to its own port.
pub fn strip(text: &[u8]) -> &[u8] {
    #[cfg(feature = "break-line-strip")]
    return text;
    #[cfg(not(feature = "break-line-strip"))]
    match tag(text) {
        Some(_) => &text[HEADER..],
        None => text,
    }
}

/// The tag of a record's `text`: a whole piece, header and text.
fn tag(text: &[u8]) -> Option<(bool, u32)> {
    let (last, id, len) = header(text)?;
    (text.len() == HEADER + len).then_some((last, id))
}

#[derive(Clone, Copy)]
struct Slot {
    open: bool,
    id: u32,
    /// The order the slot opened in, for the oldest.
    seq: u64,
    len: usize,
    buf: [u8; LINE_MAX],
}

/// The lines of the writers that are still open.
pub struct Lines {
    slots: [Slot; SLOTS],
    seq: u64,
    quiet: u8,
}

impl Lines {
    pub const fn new() -> Lines {
        Lines {
            slots: [Slot {
                open: false,
                id: 0,
                seq: 0,
                len: 0,
                buf: [0; LINE_MAX],
            }; SLOTS],
            seq: 0,
            quiet: 0,
        }
    }

    /// One record's `text` of the kernel log: put out as it is when it is
    /// not a tagged piece, held in the slot of its line otherwise, and the
    /// line put out whole to `put` once its LAST piece comes.
    pub fn record(&mut self, text: &[u8], put: &mut impl FnMut(&[u8])) {
        self.quiet = 0;
        let Some((last, id)) = tag(text) else {
            put(text);
            return;
        };
        #[cfg(feature = "break-line-assembly")]
        let id = 0;
        let payload = &text[HEADER..];
        // The last piece of a line is never its only one: with no slot, the
        // pieces before it went with an earlier driver or went out early.
        #[cfg(not(feature = "break-line-cut"))]
        if last && !self.slots.iter().any(|s| s.open && s.id == id) {
            put(CUT);
            put(payload);
            return;
        }
        let at = match self.slots.iter().position(|s| s.open && s.id == id) {
            Some(at) => at,
            None => {
                let at = match self.slots.iter().position(|s| !s.open) {
                    Some(at) => at,
                    None => {
                        let oldest = (0..SLOTS)
                            .min_by_key(|&i| self.slots[i].seq)
                            .expect("SLOTS is not 0");
                        self.close(oldest, put);
                        oldest
                    }
                };
                self.seq += 1;
                let s = &mut self.slots[at];
                s.open = true;
                s.id = id;
                s.seq = self.seq;
                s.len = 0;
                at
            }
        };
        if self.slots[at].len + payload.len() > LINE_MAX {
            self.flush(at, put);
        }
        let s = &mut self.slots[at];
        s.buf[s.len..s.len + payload.len()].copy_from_slice(payload);
        s.len += payload.len();
        if last {
            self.close(at, put);
        }
    }

    /// A batch of the log had no records: after QUIET of them in a row the
    /// lines still open go out as they are, for their writers stopped.
    pub fn quiet(&mut self, put: &mut impl FnMut(&[u8])) {
        self.quiet = self.quiet.saturating_add(1);
        if self.quiet >= QUIET {
            self.finish(put);
        }
    }

    /// Puts out every open line as it is.
    pub fn finish(&mut self, put: &mut impl FnMut(&[u8])) {
        for at in 0..SLOTS {
            self.close(at, put);
        }
        self.quiet = 0;
    }

    fn flush(&mut self, at: usize, put: &mut impl FnMut(&[u8])) {
        let s = &mut self.slots[at];
        if s.len > 0 {
            put(&s.buf[..s.len]);
            s.len = 0;
        }
    }

    fn close(&mut self, at: usize, put: &mut impl FnMut(&[u8])) {
        if self.slots[at].open {
            self.flush(at, put);
            self.slots[at].open = false;
        }
    }
}

impl Default for Lines {
    fn default() -> Lines {
        Lines::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec;
    use std::vec::Vec;

    /// The pieces a writer with identifier `id` sends for `line`.
    fn pieces(id: u32, line: &[u8]) -> Vec<Vec<u8>> {
        let chunks: Vec<&[u8]> = line.chunks(PAYLOAD).collect();
        let n = chunks.len();
        chunks
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let mut out = [0; 64];
                let len = piece(id, i + 1 == n, c, &mut out);
                out[..len].to_vec()
            })
            .collect()
    }

    fn run(records: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let mut lines = Lines::new();
        let mut out = Vec::new();
        for r in records {
            lines.record(r, &mut |b| out.push(b.to_vec()));
        }
        out
    }

    const A: &[u8] =
        b"service step: 12 kind 64 3480 ticks of 23806, the longest of its loop so far\n";
    const B: &[u8] = b"store-probe: refused TOO_LONG, the receipt is gone, nothing changed\n";

    #[test]
    fn strip_takes_the_header_of_a_whole_piece_and_nothing_else() {
        let p = pieces(5, A);
        assert!(p.len() > 1);
        let text: Vec<u8> = p.iter().flat_map(|x| strip(x).to_vec()).collect();
        assert_eq!(text, A);
        assert_eq!(strip(b"plain line\n"), b"plain line\n");
        // A header whose length does not match the record is text.
        let mut cut = p[0].clone();
        cut.pop();
        assert_eq!(strip(&cut), &cut[..]);
        assert_eq!(strip(&[MORE, b'a']), &[MORE, b'a']);
    }

    #[test]
    fn an_assembled_line_goes_in_calls_of_64_bytes_at_most() {
        let line = [b'x'; LINE_MAX];
        let calls: Vec<&[u8]> = calls(&line).collect();
        assert!(
            calls.iter().all(|c| c.len() <= CALL_MAX),
            "a call is refused"
        );
        assert_eq!(calls.concat(), line);
    }

    #[test]
    fn a_tail_whose_start_was_lost_is_marked() {
        let p = pieces(8, A);
        let out = run(&p[p.len() - 1..]);
        assert_eq!(out.len(), 2, "{out:?}");
        assert_eq!(out[0], CUT);
    }

    #[test]
    fn a_short_record_goes_as_it_is() {
        let out = run(&[b"entropy: seeded from the boot page (32 bytes)\n".to_vec()]);
        assert_eq!(
            out,
            [b"entropy: seeded from the boot page (32 bytes)\n".to_vec()]
        );
    }

    #[test]
    fn lines_of_two_writers_interleaved_by_pieces_come_out_whole() {
        let a = pieces(5, A);
        let b = pieces(9, B);
        assert!(a.len() > 1 && b.len() > 1);
        let mut records = Vec::new();
        let (mut ia, mut ib) = (a.iter(), b.iter());
        loop {
            let (x, y) = (ia.next(), ib.next());
            if x.is_none() && y.is_none() {
                break;
            }
            // B's first piece comes between A's, with a whole short line.
            records.extend(y.cloned());
            records.push(b"entropy: seeded from the boot page (32 bytes)\n".to_vec());
            records.extend(x.cloned());
        }
        let out = run(&records);
        let joined: Vec<Vec<u8>> = out;
        assert!(joined.contains(&A.to_vec()), "{joined:?}");
        assert!(joined.contains(&B.to_vec()), "{joined:?}");
        assert!(joined.contains(&b"entropy: seeded from the boot page (32 bytes)\n".to_vec()));
    }

    #[test]
    fn a_line_over_the_bound_goes_in_whole_parts() {
        let long: Vec<u8> = (0..300).map(|i| b'a' + (i % 26) as u8).collect();
        let out = run(&pieces(1, &long));
        assert!(out.iter().all(|p| p.len() <= LINE_MAX));
        assert_eq!(out.concat(), long);
    }

    #[test]
    fn the_fifth_open_line_sends_the_oldest_out() {
        let mut records = Vec::new();
        for id in 0..=SLOTS as u32 {
            let mut out = [0; 64];
            let len = piece(id, false, b"half", &mut out);
            records.push(out[..len].to_vec());
        }
        let out = run(&records);
        assert_eq!(out, [b"half".to_vec()]);
    }

    #[test]
    fn a_writer_that_stopped_is_put_out_after_quiet_batches() {
        let mut lines = Lines::new();
        let mut out = Vec::new();
        let mut put = |b: &[u8]| out.push(b.to_vec());
        let mut buf = [0; 64];
        let len = piece(3, false, b"cut here", &mut buf);
        lines.record(&buf[..len], &mut put);
        lines.quiet(&mut put);
        lines.record(b"x\n", &mut put);
        lines.quiet(&mut put);
        lines.quiet(&mut put);
        assert_eq!(out, [b"x\n".to_vec(), b"cut here".to_vec()]);
    }

    #[test]
    fn what_has_no_header_is_not_a_piece() {
        let out = run(&[vec![MORE, b'a'], vec![LAST, b'a', b'b', b'\n', b'c', b'd']]);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn one_record_puts_out_at_most_the_bound() {
        let mut lines = Lines::new();
        let mut worst = 0;
        for id in 0..40u32 {
            let mut buf = [0; 64];
            for k in 0..6 {
                let len = piece(id, k == 5, &[b'z'; PAYLOAD], &mut buf);
                let mut n = 0;
                lines.record(&buf[..len], &mut |b| n += b.len());
                worst = worst.max(n);
            }
        }
        assert!(worst <= RECORD_OUT, "{worst}");
    }
}
