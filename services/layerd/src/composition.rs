// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The COMPOSITION file, version 1: the one point of commit of the layers of a volume
//! (`/.layers/COMPOSITION`). It is text, strict, and a file the service does not understand is
//! refused whole:
//!
//! ```text
//! STAFLAYR 1
//! next 01
//! ino 1
//! lower -
//! layer 00 live unsealed - -
//! ```
//!
//! The first four lines come in this order, once each: `next NN` (two digits) is the number the
//! next layer gets, `ino N` (decimal, no leading zero) the counter of the numbers of the files the
//! service creates (below 2^62), `lower` the digest of the lower set at the last freeze (64 hex
//! digits in lower case) or `-`. Then come the layers, bottom up, one line each:
//! `layer NN <live|frozen|deferred> <sealed|unsealed> <root|-> <chain|->`. A sealed layer has a
//! root and a chain id, an unsealed one has `-` for both. Exactly one layer is live, a number
//! appears once, at most `MAX_LAYERS` layers, every line ends with one newline, fields are
//! separated by one space, and any other line, any other order and any trailing byte is an error.

use proto_layer::{LAYERS_MAX, NUMBER_MAX};

pub const MAX_LAYERS: usize = LAYERS_MAX;
/// The bytes of the longest COMPOSITION file.
pub const MAX_TEXT: usize = 4096;
const MAGIC: &[u8] = b"STAFLAYR 1";
/// The counter of the numbers stays below this bit, which the numbers of the service carry.
const INO_LIMIT: u64 = 1 << 62;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Live,
    Frozen,
    Deferred,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layer {
    pub number: u8,
    pub state: State,
    pub sealed: bool,
    pub root: Option<[u8; 32]>,
    pub chain: Option<[u8; 32]>,
}

/// Why a file was refused. The line is counted from 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The text does not end with a newline, holds a carriage return or a NUL, or is empty.
    Text,
    /// A line is not the one the order asks for.
    Line(usize),
    /// A field of a line is none of what the line takes.
    Field(usize),
    /// A layer number twice.
    Duplicate(usize),
    /// A number over 99, or not two digits.
    Number(usize),
    /// More than `MAX_LAYERS` layers.
    TooMany,
    /// No layer, or more than one, is live.
    Live,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Composition {
    pub next: u8,
    pub ino: u64,
    pub lower: Option<[u8; 32]>,
    layers: [Layer; MAX_LAYERS],
    count: usize,
}

const NONE: Layer = Layer {
    number: 0,
    state: State::Frozen,
    sealed: false,
    root: None,
    chain: None,
};

impl Composition {
    /// What a volume with no `/.layers` gets: the live layer 00 and the counter at 1.
    pub fn first() -> Composition {
        let mut layers = [NONE; MAX_LAYERS];
        layers[0] = Layer {
            number: 0,
            state: State::Live,
            sealed: false,
            root: None,
            chain: None,
        };
        Composition {
            next: 1,
            ino: 1,
            lower: None,
            layers,
            count: 1,
        }
    }

    pub fn layers(&self) -> &[Layer] {
        &self.layers[..self.count]
    }

    /// The live layer: `parse` and `first` guarantee there is one.
    pub fn live(&self) -> &Layer {
        self.layers()
            .iter()
            .find(|l| l.state == State::Live)
            .unwrap_or(&self.layers[0])
    }

    /// Whether the composition holds a layer other than the live one (frozen and deferred layers
    /// need the sealing and the checks of later steps).
    pub fn has_stack(&self) -> bool {
        self.layers().iter().any(|l| l.state != State::Live)
    }

    pub fn parse(text: &[u8]) -> Result<Composition, Error> {
        if text.is_empty() || text.last() != Some(&b'\n') || text.contains(&0) || text.contains(&b'\r')
        {
            return Err(Error::Text);
        }
        let mut lines = text[..text.len() - 1].split(|&b| b == b'\n');
        let mut n = 0;
        let mut line = |n: &mut usize| {
            *n += 1;
            lines.next().ok_or(Error::Line(*n))
        };
        if line(&mut n)? != MAGIC {
            return Err(Error::Line(n));
        }
        let next = {
            let l = line(&mut n)?;
            let v = l.strip_prefix(b"next ").ok_or(Error::Line(n))?;
            two_digits(v).ok_or(Error::Number(n))?
        };
        let ino = {
            let l = line(&mut n)?;
            let v = l.strip_prefix(b"ino ").ok_or(Error::Line(n))?;
            let v = decimal(v).ok_or(Error::Field(n))?;
            if v >= INO_LIMIT {
                return Err(Error::Field(n));
            }
            v
        };
        let lower = {
            let l = line(&mut n)?;
            let v = l.strip_prefix(b"lower ").ok_or(Error::Line(n))?;
            digest(v).ok_or(Error::Field(n))?
        };
        let mut layers = [NONE; MAX_LAYERS];
        let mut count = 0;
        let mut live = 0;
        loop {
            let Some(l) = lines.next() else { break };
            n += 1;
            let rest = l.strip_prefix(b"layer ").ok_or(Error::Line(n))?;
            if count == MAX_LAYERS {
                return Err(Error::TooMany);
            }
            let mut f = rest.split(|&b| b == b' ');
            let (Some(num), Some(state), Some(seal), Some(root), Some(chain), None) =
                (f.next(), f.next(), f.next(), f.next(), f.next(), f.next())
            else {
                return Err(Error::Field(n));
            };
            let number = two_digits(num).ok_or(Error::Number(n))?;
            if layers[..count].iter().any(|x| x.number == number) {
                return Err(Error::Duplicate(n));
            }
            let state = match state {
                b"live" => State::Live,
                b"frozen" => State::Frozen,
                b"deferred" => State::Deferred,
                _ => return Err(Error::Field(n)),
            };
            let sealed = match seal {
                b"sealed" => true,
                b"unsealed" => false,
                _ => return Err(Error::Field(n)),
            };
            let (root, chain) = (
                digest(root).ok_or(Error::Field(n))?,
                digest(chain).ok_or(Error::Field(n))?,
            );
            if sealed != root.is_some() || sealed != chain.is_some() {
                return Err(Error::Field(n));
            }
            if state == State::Live {
                live += 1;
                if sealed {
                    return Err(Error::Field(n));
                }
            }
            layers[count] = Layer {
                number,
                state,
                sealed,
                root,
                chain,
            };
            count += 1;
        }
        if live != 1 {
            return Err(Error::Live);
        }
        Ok(Composition {
            next,
            ino,
            lower,
            layers,
            count,
        })
    }

    /// The text of the composition; the bytes of `out` before the returned length.
    pub fn render(&self, out: &mut [u8; MAX_TEXT]) -> usize {
        let mut at = 0;
        let mut put = |bytes: &[u8]| {
            out[at..at + bytes.len()].copy_from_slice(bytes);
            at += bytes.len();
        };
        let put_digest = |put: &mut dyn FnMut(&[u8]), d: &Option<[u8; 32]>| match d {
            None => put(b"-"),
            Some(d) => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                for b in d {
                    put(&[HEX[usize::from(b >> 4)], HEX[usize::from(b & 15)]]);
                }
            }
        };
        put(MAGIC);
        put(b"\nnext ");
        put(&two(self.next));
        put(b"\nino ");
        let mut buf = [0u8; 20];
        put(number(self.ino, &mut buf));
        put(b"\nlower ");
        put_digest(&mut put, &self.lower);
        put(b"\n");
        for l in self.layers() {
            put(b"layer ");
            put(&two(l.number));
            put(match l.state {
                State::Live => b" live ",
                State::Frozen => b" frozen ",
                State::Deferred => b" deferred ",
            });
            put(if l.sealed { b"sealed " } else { b"unsealed " });
            put_digest(&mut put, &l.root);
            put(b" ");
            put_digest(&mut put, &l.chain);
            put(b"\n");
        }
        at
    }
}

fn two(n: u8) -> [u8; 2] {
    [b'0' + n / 10, b'0' + n % 10]
}

fn number(mut v: u64, buf: &mut [u8; 20]) -> &[u8] {
    let mut at = buf.len();
    loop {
        at -= 1;
        buf[at] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    &buf[at..]
}

/// Exactly two digits, at most `NUMBER_MAX`.
fn two_digits(v: &[u8]) -> Option<u8> {
    match v {
        [a @ b'0'..=b'9', b @ b'0'..=b'9'] => {
            let n = (a - b'0') * 10 + (b - b'0');
            (u32::from(n) <= NUMBER_MAX).then_some(n)
        }
        _ => None,
    }
}

/// Decimal digits with no leading zero (0 alone is allowed), at most 19 of them.
fn decimal(v: &[u8]) -> Option<u64> {
    if v.is_empty() || v.len() > 19 || (v.len() > 1 && v[0] == b'0') {
        return None;
    }
    v.iter().try_fold(0u64, |acc, &b| match b {
        b'0'..=b'9' => Some(acc * 10 + u64::from(b - b'0')),
        _ => None,
    })
}

/// `-` for none, or 64 lower case hex digits.
fn digest(v: &[u8]) -> Option<Option<[u8; 32]>> {
    if v == b"-" {
        return Some(None);
    }
    if v.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in v.chunks(2).enumerate() {
        let hex = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        };
        out[i] = hex(pair[0])? << 4 | hex(pair[1])?;
    }
    Some(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(c: &Composition) -> std::vec::Vec<u8> {
        let mut out = [0u8; MAX_TEXT];
        let n = c.render(&mut out);
        out[..n].to_vec()
    }

    #[test]
    fn the_first_composition_renders_and_parses_back() {
        let first = Composition::first();
        let text = render(&first);
        assert_eq!(
            text,
            b"STAFLAYR 1\nnext 01\nino 1\nlower -\nlayer 00 live unsealed - -\n"
        );
        assert_eq!(Composition::parse(&text), Ok(first));
        assert_eq!(first.live().number, 0);
        assert!(!first.has_stack());
    }

    fn full_text() -> std::string::String {
        let d1 = "ab".repeat(32);
        let d2 = "0f".repeat(32);
        std::format!(
            "STAFLAYR 1\nnext 07\nino 4096\nlower {d1}\nlayer 03 frozen sealed {d1} {d2}\nlayer 05 live unsealed - -\nlayer 06 deferred sealed {d2} {d1}\n"
        )
    }

    #[test]
    fn a_stack_round_trips_with_its_digests() {
        let text = full_text();
        let c = Composition::parse(text.as_bytes()).unwrap();
        assert_eq!((c.next, c.ino), (7, 4096));
        assert_eq!(c.layers().len(), 3);
        assert_eq!(c.live().number, 5);
        assert!(c.has_stack());
        assert_eq!(c.layers()[0].root.unwrap()[0], 0xab);
        assert_eq!(render(&c), text.as_bytes());
    }

    #[test]
    fn every_unknown_line_and_every_loose_form_is_refused() {
        let good = full_text();
        let cases: [(&str, Error); 14] = [
            ("", Error::Text),
            ("STAFLAYR 1", Error::Text),
            ("STAFLAYR 2\n", Error::Line(1)),
            ("STAFLAYR 1\nino 1\n", Error::Line(2)),
            ("STAFLAYR 1\nnext 1\n", Error::Number(2)),
            ("STAFLAYR 1\nnext 100\n", Error::Number(2)),
            ("STAFLAYR 1\nnext 01\nino 01\n", Error::Field(3)),
            ("STAFLAYR 1\nnext 01\nino 4611686018427387904\n", Error::Field(3)),
            ("STAFLAYR 1\nnext 01\nino 1\nlower ABC\n", Error::Field(4)),
            ("STAFLAYR 1\nnext 01\nino 1\nlower -\n", Error::Live),
            (
                "STAFLAYR 1\nnext 01\nino 1\nlower -\nlayer 00 live unsealed - -\nextra 1\n",
                Error::Line(6),
            ),
            (
                "STAFLAYR 1\nnext 01\nino 1\nlower -\nlayer 00 live unsealed - -\nlayer 00 frozen unsealed - -\n",
                Error::Duplicate(6),
            ),
            (
                "STAFLAYR 1\nnext 01\nino 1\nlower -\nlayer 00 live unsealed - -\nlayer 100 frozen unsealed - -\n",
                Error::Number(6),
            ),
            (
                "STAFLAYR 1\nnext 01\nino 1\nlower -\nlayer 00 live unsealed - -\nnext 02\n",
                Error::Line(6),
            ),
        ];
        for (text, error) in cases {
            assert_eq!(Composition::parse(text.as_bytes()), Err(error), "{text:?}");
        }
        // Two live layers, a sealed live layer, a sealed layer without a root, double spaces and
        // a carriage return.
        for text in [
            "STAFLAYR 1\nnext 01\nino 1\nlower -\nlayer 00 live unsealed - -\nlayer 01 live unsealed - -\n",
            "STAFLAYR 1\nnext 01\nino 1\nlower -\nlayer 00 live sealed - -\n",
            "STAFLAYR 1\nnext 01\nino 1\nlower -\nlayer 00 live unsealed - -\nlayer 01 frozen sealed - -\n",
            "STAFLAYR 1\nnext 01\nino 1\nlower -\nlayer 00  live unsealed - -\n",
            "STAFLAYR 1\r\nnext 01\nino 1\nlower -\nlayer 00 live unsealed - -\n",
            "STAFLAYR 1\nnext 01\nino 1\nlower -\nlayer 00 live unsealed - - \n",
        ] {
            assert!(Composition::parse(text.as_bytes()).is_err(), "{text:?}");
        }
        assert!(Composition::parse(good.as_bytes()).is_ok());
    }

    #[test]
    fn seventeen_layers_are_too_many_and_sixteen_fit() {
        let mut text = std::string::String::from("STAFLAYR 1\nnext 20\nino 1\nlower -\n");
        for n in 0..15 {
            text.push_str(&std::format!("layer {n:02} deferred unsealed - -\n"));
        }
        text.push_str("layer 15 live unsealed - -\n");
        let c = Composition::parse(text.as_bytes()).unwrap();
        assert_eq!(c.layers().len(), 16);
        let mut at_most = text.clone();
        at_most.push_str("layer 16 frozen unsealed - -\n");
        assert_eq!(Composition::parse(at_most.as_bytes()), Err(Error::TooMany));
        assert!(text.len() < MAX_TEXT);
    }
}
