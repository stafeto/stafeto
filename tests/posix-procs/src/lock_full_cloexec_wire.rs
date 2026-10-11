// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
//! Bounded old-image receipts and phase transitions shared by guest and host.
use super::lock_full_exec_wire::{BACKEND_MASK, MAGIC, WORDS, active};
pub const SLOT: usize = 160;
pub fn tag(nonce: u64, phase: u8) -> Option<u64> {
    (nonce >> 8 != 0 && phase != 0).then_some(nonce ^ u64::from(phase))
}
pub fn count(case: u64) -> usize {
    if case == 5 { 2 } else { 1 }
}
pub fn offset(ordinal: usize) -> Option<usize> {
    (1..=2)
        .contains(&ordinal)
        .then(|| 32 + (ordinal - 1) * SLOT)
}
fn header(s: &[u64]) -> bool {
    s.len() == WORDS
        && (3..=5).contains(&s[2])
        && tag(s[3], 1).is_some()
        && s[0] == MAGIC
        && s[1] == 2
        && s[5] < 32
        && s[6] == u64::from(s[2] == 5)
        && s[7] != 0
        && active(&s[8..17])
        && s[17] < 32
        && s[17] != s[5]
        && s[18] != 0
        && s[19] & !BACKEND_MASK == 0
        && s[20] != 0
        && s[26..29] == [256, 128, 8]
}
pub fn initial(s: &[u64], nonce: u64) -> bool {
    header(s)
        && s[3] == nonce
        && tag(nonce, 1) == Some(s[31])
        && (1..=count(s[2])).all(|n| {
            let r = &s[offset(n).unwrap()..offset(n).unwrap() + 24];
            r[0] < 32
                && r[0] != s[5]
                && (s[2] == 5 || r[0] != s[17])
                && r[1] != 0
                && r[2..4] == s[19..21]
                && r[4..10] == [0; 6]
                && r[10..19] == s[8..17]
                && r[19] == 1
                && r[20] == s[7]
                && r[21] == nonce
                && r[22] == n as u64
                && r[23] == 0
                && s[offset(n).unwrap() + 24..offset(n).unwrap() + SLOT]
                    .iter()
                    .all(|w| *w == 0)
        })
        && (s[2] != 5 || s[32] < s[192])
        && (s[2] == 5 || s[192..].iter().all(|w| *w == 0))
}
pub fn permitted_header(s: &[u64]) -> bool {
    s.len() == WORDS
        && s[4] != 0
        && s[21] & !BACKEND_MASK == 0
        && s[22] != 0
        && s[23] != 0
        && s[23] != s[9]
        && s[24..26] == s[13..15]
        && s[29] == 2
        && tag(s[3], 2) == Some(s[30])
}
pub fn old_header(s: &[u64], expected: &[u64]) -> bool {
    header(s)
        && expected.len() == 32
        && tag(s[3], 1) == Some(s[31])
        && permitted_header(s)
        && (0..32).all(|i| matches!(i, 29 | 30) || s[i] == expected[i])
}
pub fn independent_key(fd: u64, slot: u64, generation: u64, other: [u64; 3]) -> bool {
    other[2] == 0 || other[0] == fd || other[1] != slot || other[2] != generation
}
#[derive(Clone, Copy)]
pub enum Outcome {
    Attempt,
    Accepted,
    Physical,
}
/// The sample comes from the actual journal before its record acknowledgement.
pub fn observe(r: &mut [u64; 24], sample: [u64; 7], outcome: Outcome) -> Result<bool, ()> {
    if sample[..4] != r[..4] || sample[4] >= 16 || sample[5] == 0 || sample[6] > 1 {
        return Err(());
    }
    if r[5] == 0 {
        if !matches!(outcome, Outcome::Attempt) {
            return Err(());
        }
        r[4..7].copy_from_slice(&sample[4..7]);
    } else if r[4..7] != sample[4..7] {
        return Err(());
    }
    let attempts = r[7] & 0xffff_ffff;
    let accepted = r[7] >> 32;
    let physical = r[8] & 0xffff_ffff;
    let discarded = r[8] >> 32;
    if attempts > 32 || accepted > attempts || physical > 32 || discarded > 1 {
        return Err(());
    }
    match outcome {
        Outcome::Attempt => {
            if attempts == 32 {
                return Err(());
            }
            r[7] += 1;
            Ok(false)
        }
        Outcome::Accepted => {
            if accepted >= attempts || accepted == 32 {
                return Err(());
            }
            r[7] += 1 << 32;
            if discarded == 0 {
                r[8] += 1 << 32;
                Ok(true)
            } else {
                Ok(false)
            }
        }
        Outcome::Physical => {
            if physical == 32 {
                return Err(());
            }
            r[8] += 1;
            Ok(false)
        }
    }
}
pub fn immutable_receipt(r: &[u64], expected: &[u64]) -> bool {
    r.len() == 24
        && expected.len() == 24
        && (0..24).all(|i| matches!(i, 4..=9 | 23) || r[i] == expected[i])
}
pub fn receipt(s: &[u64], expected: &[u64], n: usize) -> bool {
    let Some(at) = offset(n) else {
        return false;
    };
    if s.len() != WORDS || expected.len() != 80 || n > count(expected[2]) {
        return false;
    }
    let r = &s[at..at + 24];
    immutable_receipt(r, &expected[32 + (n - 1) * 24..56 + (n - 1) * 24])
        && active(&r[10..19])
        && r[4] < 16
        && r[5] != 0
        && (n == 1 || independent_key(r[0], r[4], r[5], [s[32], s[36], s[37]]))
        && r[6] == u64::from(expected[2] == 5 && n == 2)
        && (2..=32).contains(&(r[7] >> 32))
        && (r[7] & 0xffff_ffff) >= r[7] >> 32
        && r[7] & 0xffff_ffff <= 32
        && r[8] >> 32 == 1
        && r[8] & 0xffff_ffff <= 32
        && (r[6] == 0 && r[8] & 0xffff_ffff == 0 || r[6] == 1 && r[8] & 0xffff_ffff >= 1)
        && r[9] == 1
        && tag(expected[3], 16 + n as u8) == Some(r[23])
}
pub fn acknowledged(s: &[u64], expected: &[u64], n: usize, profile: u64) -> bool {
    if !(profile == 4 || profile == 7) || !receipt(s, expected, n) {
        return false;
    }
    let at = offset(n).unwrap();
    let c = &s[at + 144..at + 160];
    let last = n == count(expected[2]);
    row_slot(s, expected, n)
        && c[0] == n as u64
        && c[1] == expected[3]
        && c[6] == 1
        && c[7] == n as u64
        && c[8] == expected[3]
        && tag(expected[3], 32 + n as u8) == Some(c[9])
        && c[10..16] == [s[4], profile, 32, u64::from(!last), 0, s[4]]
}
pub fn new_identity(s: &[u64], expected: &[u64], profile: u64) -> bool {
    if !header(s) || expected.len() != 80 {
        return false;
    }
    (1..=count(expected[2])).all(|n| acknowledged(s, expected, n, profile))
        && (0..32).all(|i| matches!(i,4|8..=16|21..=25|29..=31) || s[i] == expected[i])
        && s[4] == expected[4]
        && s[4] != 0
        && s[9..11] == expected[9..11]
        && s[11] > expected[11]
        && s[12] > expected[12]
        && s[13..17] == [expected[13], expected[14], 0, s[12]]
        && s[21..26] == expected[21..26]
        && s[29] != 0
        && tag(expected[3], 48) == Some(s[31])
        && tag(expected[3], 2) == Some(s[30])
}

pub fn row_slot(s: &[u64], expected: &[u64], n: usize) -> bool {
    let Some(at) = offset(n) else {
        return false;
    };
    if s.len() != WORDS || expected.len() != 80 {
        return false;
    }
    let r = &s[at..at + 24];
    let p = &s[at + 24..at + 144];
    let c = &s[at + 144..at + 160];
    let present = matches!(expected[2], 3 | 6) || expected[2] == 5 && n == 2;
    if !present {
        return c[2] == 0
            && c[3] == 0xfffff_u64 << 32
            && c[4] == 0
            && c[5] == 0
            && p.iter().all(|w| *w == 0);
    }
    let page = |i: usize| &p[i * 6..i * 6 + 6];
    let mask = page(0)[4];
    c[2] == 1
        && c[3] == 20
        && c[4] == 1
        && c[5] == 1
        && page(0)[1] == 1
        && page(0)[2] == 1
        && page(0)[5] == 49
        && mask <= 65535
        && mask & (1 << 15) != 0
        && (0..20).all(|i| page(i)[0] == s[4] && page(i)[1] == 1)
        && page(17)[2..6]
            == [
                r[11],
                r[2] | (r[4] << 32) | (u64::from(expected[2] == 5) << 62) | (r[6] << 63),
                r[3],
                r[5],
            ]
        && page(19)[4] & (1 << 15) == 0
        && page(19)[4] & !mask == 0
        && page(19)[5] == mask
        && page(18)[5] == 1
        && page(18)[2].checked_sub(page(18)[3]) == Some(page(0)[3])
        && page(0)[3] <= 20410
        && (0..16).all(|bit| {
            let visits = (page(19)[2 + bit / 8] >> ((bit % 8) * 8)) & 255;
            visits <= 8 && (mask & (1 << bit) != 0 || visits == 0)
        })
}

pub fn same_receipts(s: &[u64], saved: &[u64]) -> bool {
    s.len() == WORDS
        && saved.len() == 48
        && (3..=5).contains(&s[2])
        && (1..=count(s[2]))
            .all(|n| s[offset(n).unwrap()..offset(n).unwrap() + 24] == saved[(n - 1) * 24..n * 24])
        && (s[2] == 5 || s[192..].iter().all(|w| *w == 0))
}
pub fn pending(marker: u64, wanted: u64, previous: u64) -> Result<bool, ()> {
    if wanted == 0 || wanted == previous {
        return Err(());
    }
    if marker == wanted {
        Ok(true)
    } else if marker == previous {
        Ok(false)
    } else {
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn initial_state(case: u64) -> ([u64; WORDS], [u64; 80]) {
        let mut s = [0; WORDS];
        let nonce = 0x9900;
        s[..8].copy_from_slice(&[MAGIC, 2, case, nonce, 7, 7, u64::from(case == 5), 101]);
        s[8..17].copy_from_slice(&[1, 513, 1, 2, 7, 257, 1, 0, 7]);
        s[17..21].copy_from_slice(&[3, 9, 0x301, 1 << 40]);
        s[21..32].copy_from_slice(&[
            0x501,
            1 << 43,
            514,
            257,
            1,
            256,
            128,
            8,
            2,
            tag(nonce, 2).unwrap(),
            tag(nonce, 1).unwrap(),
        ]);
        for n in 1..=count(case) {
            let at = offset(n).unwrap();
            s[at..at + 4].copy_from_slice(&[
                if case == 5 { n as u64 + 2 } else { 4 },
                10,
                0x301,
                1 << 40,
            ]);
            s[at + 10..at + 19].copy_from_slice(&[1, 513, 1, 2, 7, 257, 1, 0, 7]);
            s[at + 19..at + 23].copy_from_slice(&[1, 101, nonce, n as u64]);
        }
        let mut e = [0; 80];
        e[..32].copy_from_slice(&s[..32]);
        for n in 1..=count(case) {
            e[32 + (n - 1) * 24..56 + (n - 1) * 24]
                .copy_from_slice(&s[offset(n).unwrap()..offset(n).unwrap() + 24]);
        }
        assert!(initial(&s, nonce));
        assert!(permitted_header(&s));
        assert!(old_header(&s, &e[..32]));
        (s, e)
    }
    fn close(s: &mut [u64; WORDS], e: &[u64; 80], n: usize) {
        let at = offset(n).unwrap();
        let last = e[2] == 5 && n == 2;
        let r: &mut [u64; 24] = (&mut s[at..at + 24]).try_into().unwrap();
        let sample = [
            r[0],
            r[1],
            r[2],
            r[3],
            2,
            (1 << 44) + (n as u64 - 1),
            u64::from(last),
        ];
        assert!(!observe(r, sample, Outcome::Attempt).unwrap());
        assert!(observe(r, sample, Outcome::Accepted).unwrap());
        assert!(!observe(r, sample, Outcome::Attempt).unwrap());
        assert!(!observe(r, sample, Outcome::Accepted).unwrap());
        if last {
            assert!(!observe(r, sample, Outcome::Physical).unwrap());
        }
        r[9] = 1;
        r[23] = tag(e[3], 16 + n as u8).unwrap();
        let present = e[2] == 3 || last;
        if present {
            for page in 0..20 {
                s[at + 24 + page * 6] = 7;
                s[at + 25 + page * 6] = 1;
            }
            s[at + 24..at + 30].copy_from_slice(&[7, 1, 1, 3, 1 << 15, 49]);
            s[at + 24 + 17 * 6..at + 30 + 17 * 6].copy_from_slice(&[
                7,
                1,
                513,
                0x301 | (2 << 32) | (u64::from(e[2] == 5) << 62) | (u64::from(last) << 63),
                1 << 40,
                (1 << 44) + (n as u64 - 1),
            ]);
            s[at + 24 + 18 * 6..at + 30 + 18 * 6].copy_from_slice(&[7, 1, 10, 7, 0, 1]);
            s[at + 24 + 19 * 6..at + 30 + 19 * 6].copy_from_slice(&[7, 1, 0, 1 << 56, 0, 1 << 15]);
        }
        s[at + 144..at + 160].copy_from_slice(&[
            n as u64,
            e[3],
            u64::from(present),
            if present { 20 } else { 0xfffff << 32 },
            u64::from(present),
            u64::from(present),
            1,
            n as u64,
            e[3],
            tag(e[3], 32 + n as u8).unwrap(),
            7,
            4,
            32,
            u64::from(n < count(e[2])),
            0,
            7,
        ]);
        assert!(receipt(s, e, n));
        assert!(acknowledged(s, e, n, 4));
    }
    #[test]
    fn each_full_key_discards_only_its_first_real_accepted_receipt() {
        let (mut s, e) = initial_state(5);
        close(&mut s, &e, 1);
        close(&mut s, &e, 2);
        assert_eq!(s[39] >> 32, 2);
        assert_eq!(s[199] >> 32, 2);
        assert!(independent_key(
            s[192],
            s[196],
            s[197],
            [s[32], s[36], s[37]]
        ));
        assert!(!independent_key(
            s[192],
            s[36],
            s[37],
            [s[32], s[36], s[37]]
        ));
        let mut duplicate = s;
        duplicate[197] = duplicate[37];
        assert!(!receipt(&duplicate, &e, 2));
        let mut r: [u64; 24] = s[32..56].try_into().unwrap();
        let changed = [r[0], r[1], r[2], r[3], r[4], r[5] ^ (1 << 32), r[6]];
        assert!(observe(&mut r, changed, Outcome::Attempt).is_err());
        let unknown = [31, r[1], r[2], r[3], r[4], r[5], r[6]];
        assert!(observe(&mut r, unknown, Outcome::Attempt).is_err());
        let mut overflow = r;
        overflow[7] = (2 << 32) | 32;
        let sample = [r[0], r[1], r[2], r[3], r[4], r[5], r[6]];
        assert!(observe(&mut overflow, sample, Outcome::Attempt).is_err());
    }
    #[test]
    fn success_requires_public_ok_accepted_discard_and_exact_immutable_alias() {
        let (mut s, e) = initial_state(3);
        close(&mut s, &e, 1);
        let good = s;
        for (index, value) in [
            (41, 0),
            (39, 2),
            (40, 0),
            (37, 0),
            (33, 0),
            (51, 0),
            (43, 514),
            (47, 2),
            (55, tag(e[3], 18).unwrap()),
        ] {
            s = good;
            s[index] = value;
            assert!(!receipt(&s, &e, 1), "index {index}");
        }
        s = good;
        s[37] ^= 1 << 32;
        assert!(!acknowledged(&s, &e, 1, 4));
    }
    #[test]
    fn two_closes_preserve_absent_first_and_one_exact_final_effect() {
        let (mut s, e) = initial_state(5);
        close(&mut s, &e, 1);
        close(&mut s, &e, 2);
        let good = s;
        s[216 + 2] = 2;
        assert!(!acknowledged(&s, &e, 2, 4));
        s = good;
        s[216 + 7 * 6 + 1] = 2;
        assert!(!acknowledged(&s, &e, 2, 4));
        s = good;
        s[216 + 17 * 6 + 5] ^= 1 << 32;
        assert!(!acknowledged(&s, &e, 2, 4));
        s = good;
        s[56] = 7;
        assert!(!acknowledged(&s, &e, 1, 4));
        let (mut surviving, e) = initial_state(4);
        close(&mut surviving, &e, 1);
        assert!(acknowledged(&surviving, &e, 1, 4));
        surviving[179] = 0;
        assert!(!acknowledged(&surviving, &e, 1, 4));
    }
    #[test]
    fn fresh_identity_waits_for_real_stop_last_ack_and_keeps_old_proof() {
        let (mut s, e) = initial_state(5);
        close(&mut s, &e, 1);
        close(&mut s, &e, 2);
        let mut saved = [0; 48];
        saved[..24].copy_from_slice(&s[32..56]);
        saved[24..].copy_from_slice(&s[192..216]);
        s[11] += 1;
        s[12] += 1;
        s[16] = s[12];
        s[29] = 11;
        s[31] = tag(e[3], 48).unwrap();
        assert!(new_identity(&s, &e, 4));
        assert!(same_receipts(&s, &saved));
        let good = s;
        for (index, value) in [
            (350, 1),
            (345, 0),
            (11, e[11]),
            (12, e[12]),
            (16, e[12]),
            (29, 0),
            (31, tag(e[3], 1).unwrap()),
            (21, 0),
            (17, 4),
            (13, 258),
        ] {
            s = good;
            s[index] = value;
            assert!(!new_identity(&s, &e, 4), "index {index}");
        }
        for credential in [e[12], e[12] - 1] {
            s = good;
            s[12] = credential;
            s[16] = credential;
            assert!(!new_identity(&s, &e, 4));
        }
        s = good;
        s[39] += 1;
        assert!(!same_receipts(&s, &saved));
        s = good;
        s[37] ^= 1 << 32;
        assert!(!same_receipts(&s, &saved));
    }
    #[test]
    fn old_header_cannot_refresh_identity_entry_or_scope_before_close_ack() {
        let (s, e) = initial_state(3);
        assert!(!initial(&s[..351], s[3]));
        assert!(!receipt(&s[..351], &e, 1));
        assert!(!acknowledged(&s, &e, 0, 4));
        assert!(!new_identity(&s, &e[..79], 4));
        for index in [4, 8, 11, 12, 17, 18, 21, 22, 23, 24, 25, 31] {
            let mut changed = s;
            changed[index] ^= 1;
            assert!(!old_header(&changed, &e[..32]), "index {index}");
        }
        let mut changed = s;
        changed[29] = 11;
        assert!(!old_header(&changed, &e[..32]));
    }
    #[test]
    fn public_marker_rejects_missing_wrong_stale_and_extra_fields() {
        for case in 3..=5 {
            let line = format!(
                "lock-full: exec cloexec profile=4 mode={case} closes={} replay=confirmed discard=once oldscope=denied published=256 common=128 payers=8",
                count(case)
            );
            assert!(marker(&line, 4, case));
            assert!(!marker(&line, 7, case));
            assert!(!marker(
                &line.replace("replay=confirmed", "replay=attempted"),
                4,
                case
            ));
            assert!(!marker(
                &line.replace("oldscope=denied", "oldscope=granted"),
                4,
                case
            ));
            assert!(!marker(&format!("{line} extra=1"), 4, case));
        }
    }
    #[test]
    fn exact_tags_reject_unknown_stale_and_zero_nonce() {
        assert_eq!(pending(0, 0, 1), Err(()));
        assert_eq!(pending(1, 1, 1), Err(()));
        assert!(offset(0).is_none());
        assert!(offset(3).is_none());
        assert!(offset(usize::MAX).is_none());
        assert!(tag(0, 48).is_none());
        assert!(tag(7, 48).is_none());
        assert!(tag(0x9900, 0).is_none());
        for (phase, prior) in [(48, 1), (49, 2)] {
            let wanted = tag(0x9900, phase).unwrap();
            let previous = tag(0x9900, prior).unwrap();
            assert_eq!(pending(previous, wanted, previous), Ok(false));
            assert_eq!(pending(wanted, wanted, previous), Ok(true));
            assert_eq!(pending(tag(0x9900, 17).unwrap(), wanted, previous), Err(()));
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn marker(line: &str, profile: u64, case: u64) -> bool {
    if !(profile == 4 || profile == 7) || !(3..=5).contains(&case) {
        return false;
    }
    let mut fields = line.split_whitespace();
    for expected in ["lock-full:", "exec", "cloexec"] {
        if fields.next() != Some(expected) {
            return false;
        }
    }
    for (name, value) in [
        ("profile=", profile),
        ("mode=", case),
        ("closes=", count(case) as u64),
    ] {
        if fields
            .next()
            .and_then(|w| w.strip_prefix(name))
            .and_then(|w| w.parse::<u64>().ok())
            != Some(value)
        {
            return false;
        }
    }
    [
        "replay=confirmed",
        "discard=once",
        "oldscope=denied",
        "published=256",
        "common=128",
        "payers=8",
    ]
    .into_iter()
    .all(|w| fields.next() == Some(w))
        && fields.next().is_none()
}
