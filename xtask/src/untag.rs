// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The console's output as the kernel itself writes it (before the console's
//! driver runs and after it ends): a line longer than one record of the
//! kernel log comes in tagged pieces (lib/console-line) that other writers'
//! text can lie between. `Untag` puts each such line back whole where its
//! last piece stands.

use console_line::{HEADER, LAST, MORE};

/// A decoder of the tagged pieces in a stream of bytes, fed as it comes.
#[derive(Default)]
pub struct Untag {
    /// The bytes of a piece the last feed ended in the middle of.
    held: Vec<u8>,
    /// The lines whose last piece did not come yet, by identifier.
    open: Vec<(u32, Vec<u8>)>,
}

impl Untag {
    /// The bytes of `bytes` as the console shows them: text that is not a
    /// piece as it is, a line of pieces whole at its last piece.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut input = std::mem::take(&mut self.held);
        input.extend_from_slice(bytes);
        let mut out = Vec::with_capacity(input.len());
        let mut i = 0;
        while i < input.len() {
            let rest = &input[i..];
            if rest[0] != MORE && rest[0] != LAST {
                out.push(rest[0]);
                i += 1;
                continue;
            }
            match console_line::header(rest) {
                Some((last, id, len)) => {
                    if rest.len() < HEADER + len {
                        self.held = rest.to_vec();
                        return out;
                    }
                    let text = &rest[HEADER..HEADER + len];
                    let at = self.open.iter().position(|(k, _)| *k == id);
                    let at = at.unwrap_or_else(|| {
                        self.open.push((id, Vec::new()));
                        self.open.len() - 1
                    });
                    self.open[at].1.extend_from_slice(text);
                    if last {
                        out.extend_from_slice(&self.open.remove(at).1);
                    }
                    i += HEADER + len;
                }
                None if rest.len() < HEADER
                    && rest[1..].iter().take(3).all(|b| (0x40..=0x7F).contains(b)) =>
                {
                    // A header the feed ended in.
                    self.held = rest.to_vec();
                    return out;
                }
                None => {
                    out.push(rest[0]);
                    i += 1;
                }
            }
        }
        out
    }

    /// What is left at the end of the output: the lines without a last
    /// piece, as they stand, and the bytes of a piece cut short.
    pub fn finish(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        for (_, text) in self.open.drain(..) {
            out.extend_from_slice(&text);
        }
        out.append(&mut self.held);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pieces(id: u32, line: &[u8]) -> Vec<Vec<u8>> {
        let chunks: Vec<&[u8]> = line.chunks(console_line::PAYLOAD).collect();
        let n = chunks.len();
        chunks
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let mut out = [0; 64];
                let len = console_line::piece(id, i + 1 == n, c, &mut out);
                out[..len].to_vec()
            })
            .collect()
    }

    #[test]
    fn pieces_among_other_text_come_back_whole() {
        let line =
            b"virtio-net: virtio-mmio at 0xa000e00, line 55, status 0x0, mac 52:54:00:12:34:56\n";
        let p = pieces(77, line);
        assert!(p.len() > 1);
        let mut stream = Vec::new();
        stream.extend_from_slice(&p[0]);
        stream.extend_from_slice(b"virtio-rng: seeded\n");
        stream.extend_from_slice(&p[1]);
        // Fed in cuts through every header and text.
        for cut in 1..stream.len() {
            let mut u = Untag::default();
            let mut out = u.feed(&stream[..cut]);
            out.extend(u.feed(&stream[cut..]));
            out.extend(u.finish());
            let mut want = b"virtio-rng: seeded\n".to_vec();
            want.extend_from_slice(line);
            assert_eq!(
                String::from_utf8_lossy(&out),
                String::from_utf8_lossy(&want),
                "cut {cut}"
            );
        }
    }

    #[test]
    fn text_without_pieces_is_as_it_is() {
        let mut u = Untag::default();
        assert_eq!(u.feed(b"plain \x1e text \x1f\n"), b"plain \x1e text \x1f\n");
        assert!(u.finish().is_empty());
    }
}
