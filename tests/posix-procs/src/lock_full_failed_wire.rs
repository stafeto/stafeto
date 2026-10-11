// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
//! Failed loader attempts retain their immutable witnesses through the next exec.
use super::lock_full_cloexec_wire as close;
use super::lock_full_exec_wire::{BACKEND_MASK, MAGIC, WORDS, active};
const BAD: usize = 192;
fn tag(s: &[u64], phase: u8) -> Option<u64> {
    close::tag(s[3], phase)
}
fn header(s: &[u64]) -> bool {
    s.len() == WORDS
        && s[0] == MAGIC
        && s[1] == 3
        && matches!(s[2], 6 | 7)
        && tag(s, 1).is_some()
        && s[5] < 32
        && s[6] == u64::from(s[2] == 7)
        && s[7] != 0
        && active(&s[8..17])
        && s[17] < 32
        && s[17] != s[5]
        && s[18] != 0
        && s[19] & !BACKEND_MASK == 0
        && s[20] != 0
        && s[26..29] == [256, 128, 8]
}
fn source(s: &[u64]) -> bool {
    s[4] != 0
        && s[21] & !BACKEND_MASK == 0
        && s[22] != 0
        && s[23] != 0
        && s[23] != s[9]
        && s[24..26] == s[13..15]
}
fn empty_receipt(r: &[u64], s: &[u64]) -> bool {
    r[0] < 32
        && r[0] != s[17]
        && r[0] != s[5]
        && r[1] != 0
        && r[2..4] == s[19..21]
        && r[4..10] == [0; 6]
        && r[10..19] == s[8..17]
        && r[19] == 1
        && r[20] == s[7]
        && r[21] == s[3]
        && r[22] == 1
        && r[23] == 0
}
fn pre(s: &[u64]) -> bool {
    let b = &s[BAD..];
    b[96] == s[5]
        && b[97] != 0
        && b[98] & !BACKEND_MASK == 0
        && b[99] != 0
        && b[104] != 0
        && b[104] != s[7]
        && b[106] == 4096
        && b[120..123] == [0, 1, 0]
        && b[123..160] == [0; 37]
}
fn fixed_header(s: &[u64], e: &[u64]) -> bool {
    e.len() == 80 && (0..32).all(|i| matches!(i, 29 | 30 | 31) || s[i] == e[i])
}
fn bad_return(s: &[u64], e: &[u64]) -> bool {
    let b = &s[BAD..];
    header(s)
        && source(s)
        && pre(s)
        && fixed_header(s, e)
        && b[0..29] == e[0..29]
        && b[29] == 2
        && b[30] == tag(s, 2).unwrap()
        && b[31] == tag(s, 1).unwrap()
        && b[32..56] == e[32..56]
        && b[96..100] == e[56..60]
        && b[104] == e[60]
        && b[106] == e[61]
        && b[120..123] == e[62..65]
        && b[78] == e[65]
        && (0..6).all(|i| b[108 + 2 * i] == e[66 + i])
        && s[32..56] == e[32..56]
        && s[56..192] == [0; 136]
        && empty_receipt(&s[32..56], s)
        && b[56] == 8
        && b[57] == 15
        && active(&b[58..67])
        && b[59..62] == b[9..12]
        && b[62] > b[12]
        && b[63..67] == [b[13], b[14], 0, b[62]]
        && b[67..71] == b[17..21]
        && b[71..75] == b[32..36]
        && b[75..78] == b[120..123]
        && b[78] == b[79]
        && b[96..100] == b[100..104]
        && b[104] == b[105]
        && b[106] == b[107]
        && (108..120).step_by(2).all(|i| b[i] == b[i + 1])
        && s[29] == 2
        && s[30] == tag(s, 2).unwrap()
        && s[31] == tag(s, 3).unwrap()
}
fn failed_ack(s: &[u64], profile: u64) -> bool {
    let b = &s[BAD..];
    matches!(profile, 4 | 7)
        && b[80] == s[3]
        && b[81] == s[4]
        && b[82..88] == [s[4], profile, 32, 1, 0, s[4]]
        && b[88..94] == [256, 128, 8, 0xfffff, 1, 1]
        && b[94] == 1
        && b[95] == tag(s, 4).unwrap()
}
fn saved_bad(s: &[u64], b: &[u64], profile: u64) -> bool {
    b.len() == 160
        && s[BAD..] == *b
        && pre(s)
        && failed_ack(s, profile)
        && (0..29).all(|i| matches!(i, 8..=16) || s[i] == b[i])
        && b[56] == 8
        && b[57] == 15
        && active(&b[58..67])
        && b[59..62] == b[9..12]
        && b[62] > b[12]
        && b[63..67] == [b[13], b[14], 0, b[62]]
        && b[67..71] == b[17..21]
        && b[71..75] == b[32..36]
        && b[75..78] == b[120..123]
        && b[78] == b[79]
        && b[96..100] == b[100..104]
        && b[104] == b[105]
        && b[106] == b[107]
        && (108..120).step_by(2).all(|i| b[i] == b[i + 1])
}
fn success_header(s: &[u64], e: &[u64]) -> bool {
    header(s)
        && source(s)
        && fixed_header(s, e)
        && s[8..17] == s[BAD + 58..BAD + 67]
        && s[29] == 5
        && s[30] == tag(s, 5).unwrap()
        && s[31] == tag(s, 3).unwrap()
}
pub fn valid(s: &[u64], e: &[u64], b: &[u64], stage: u32, profile: u64) -> bool {
    if s.len() != WORDS || e.len() != 80 || b.len() != 160 || !header(s) {
        return false;
    }
    match stage {
        1 | 2 => {
            pre(s)
                && empty_receipt(&s[32..56], s)
                && s[56..192] == [0; 136]
                && (56..96).all(|i| i == 78 || s[BAD + i] == 0)
                && s[BAD + 100..BAD + 104] == [0; 4]
                && s[BAD + 105] == 0
                && s[BAD + 107] == 0
                && (109..120).step_by(2).all(|i| s[BAD + i] == 0)
                && s[BAD..BAD + 29] == s[..29]
                && s[BAD + 32..BAD + 56] == s[32..56]
                && (stage == 1 && s[31] == tag(s, 1).unwrap()
                    || stage == 2
                        && source(s)
                        && s[29] == 2
                        && s[30] == tag(s, 2).unwrap()
                        && s[31] == tag(s, 1).unwrap())
        }
        3 => bad_return(s, e) && s[BAD + 80..BAD + 96] == [0; 16],
        4 => bad_return(s, e) && failed_ack(s, profile),
        5 => {
            saved_bad(s, b, profile)
                && success_header(s, e)
                && empty_receipt(&s[32..56], s)
                && s[56..192] == [0; 136]
        }
        6 => saved_bad(s, b, profile) && success_header(s, e) && close::receipt(s, e, 1),
        7 => {
            saved_bad(s, b, profile)
                && success_header(s, e)
                && close::acknowledged(s, e, 1, profile)
        }
        8 => {
            saved_bad(s, b, profile)
                && e[8..17] == b[58..67]
                && close::acknowledged(s, e, 1, profile)
                && (0..32).all(|i| matches!(i,8..=16|29..=31) || s[i] == e[i])
                && s[9..11] == e[9..11]
                && s[11] > e[11]
                && s[12] > e[12]
                && s[13..17] == [e[13], e[14], 0, s[12]]
                && s[29] != 0
                && s[31] == tag(s, 48).unwrap()
                && s[30] == tag(s, 5).unwrap()
        }
        _ => false,
    }
}
pub fn marker(line: &str, profile: u64, case: u64) -> bool {
    let mut fields = line.split_whitespace();
    for word in ["lock-full:", "exec", "failed"] {
        if fields.next() != Some(word) {
            return false;
        }
    }
    let number = |word: Option<&str>, key: &str, expected: u64| {
        word.and_then(|v| v.strip_prefix(key))
            .and_then(|v| v.parse::<u64>().ok())
            == Some(expected)
    };
    matches!(profile, 4 | 7)
        && matches!(case, 6 | 7)
        && number(fields.next(), "profile=", profile)
        && number(fields.next(), "mode=", case)
        && [
            "errno=ENOEXEC",
            "abort=fresh",
            "oldfiles=preserved",
            "close=none",
            "next=committed",
            "replay=confirmed",
            "discard=once",
            "oldscope=denied",
            "published=256",
            "common=128",
            "payers=8",
        ]
        .into_iter()
        .all(|word| fields.next() == Some(word))
        && fields.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn expected(s: &[u64; WORDS]) -> [u64; 80] {
        let mut e = [0; 80];
        e[..32].copy_from_slice(&s[..32]);
        e[32..56].copy_from_slice(&s[32..56]);
        e[56..60].copy_from_slice(&s[BAD + 96..BAD + 100]);
        e[60] = s[BAD + 104];
        e[61] = s[BAD + 106];
        e[62..65].copy_from_slice(&s[BAD + 120..BAD + 123]);
        e[65] = s[BAD + 78];
        for i in 0..6 {
            e[66 + i] = s[BAD + 108 + 2 * i];
        }
        e
    }
    fn initial(case: u64) -> [u64; WORDS] {
        let mut s = [0; WORDS];
        s[..8].copy_from_slice(&[MAGIC, 3, case, 0x1200, 7, 6, u64::from(case == 7), 44]);
        s[8..17].copy_from_slice(&[1, 513, 1, 2, 7, 1001, 9, 0, 7]);
        s[17..21].copy_from_slice(&[4, 1 << 35, 0x301, 1 << 40]);
        s[21..26].copy_from_slice(&[0x401, 1 << 41, 777, 1001, 9]);
        s[26..29].copy_from_slice(&[256, 128, 8]);
        s[31] = tag(&s, 1).unwrap();
        s[32..36].copy_from_slice(&[5, 1 << 36, 0x301, 1 << 40]);
        let binding = core::array::from_fn::<_, 9, _>(|i| s[8 + i]);
        s[42..51].copy_from_slice(&binding);
        s[51..55].copy_from_slice(&[1, 44, 0x1200, 1]);
        let old = core::array::from_fn::<_, 32, _>(|i| s[i]);
        let receipt = core::array::from_fn::<_, 24, _>(|i| s[32 + i]);
        s[BAD..BAD + 32].copy_from_slice(&old);
        s[BAD + 32..BAD + 56].copy_from_slice(&receipt);
        s[BAD + 96..BAD + 100].copy_from_slice(&[6, 1 << 37, 0x503, 1 << 43]);
        s[BAD + 104] = 45;
        s[BAD + 106] = 4096;
        s[BAD + 121] = 1;
        s[BAD + 78] = 128;
        s
    }
    fn failure(case: u64) -> ([u64; WORDS], [u64; 80]) {
        let mut s = initial(case);
        let e = expected(&s);
        assert!(valid(&s, &e, &[0; 160], 1, 4));
        s[29] = 2;
        s[30] = tag(&s, 2).unwrap();
        let old = core::array::from_fn::<_, 32, _>(|i| s[i]);
        s[BAD..BAD + 32].copy_from_slice(&old);
        assert!(valid(&s, &e, &[0; 160], 2, 4));
        let e = expected(&s);
        let b = &mut s[BAD..];
        b[56] = 8;
        b[57] = 15;
        let mut binding = core::array::from_fn::<_, 9, _>(|i| b[8 + i]);
        binding[4] = 8;
        binding[8] = 8;
        b[58..67].copy_from_slice(&binding);
        let t = core::array::from_fn::<_, 4, _>(|i| b[17 + i]);
        let u = core::array::from_fn::<_, 4, _>(|i| b[32 + i]);
        b[67..71].copy_from_slice(&t);
        b[71..75].copy_from_slice(&u);
        b[76] = 1;
        b[79] = b[78];
        let state = core::array::from_fn::<_, 4, _>(|i| b[96 + i]);
        b[100..104].copy_from_slice(&state);
        b[105] = b[104];
        b[107] = 4096;
        s[31] = tag(&s, 3).unwrap();
        assert!(valid(&s, &e, &[0; 160], 3, 4));
        (s, e)
    }
    fn success(case: u64) -> ([u64; WORDS], [u64; 80], [u64; 160]) {
        let (mut s, e) = failure(case);
        let b = &mut s[BAD..];
        b[80..96].copy_from_slice(&[
            0x1200, 7, 7, 4, 32, 1, 0, 7, 256, 128, 8, 0xfffff, 1, 1, 1, 0x1204,
        ]);
        assert!(valid(&s, &e, &[0; 160], 4, 4));
        let b = core::array::from_fn(|i| s[BAD + i]);
        let binding = core::array::from_fn::<_, 9, _>(|i| b[58 + i]);
        s[8..17].copy_from_slice(&binding);
        s[42..51].copy_from_slice(&binding);
        s[29] = 5;
        s[30] = tag(&s, 5).unwrap();
        let e = expected(&s);
        assert!(valid(&s, &e, &b, 5, 4));
        (s, e, b)
    }
    fn acknowledged(case: u64) -> ([u64; WORDS], [u64; 80], [u64; 160]) {
        let (mut s, e, b) = success(case);
        s[36] = 2;
        s[37] = 1 << 44;
        s[39] = 2 | (2 << 32);
        s[40] = 1 << 32;
        s[41] = 1;
        s[55] = tag(&s, 17).unwrap();
        assert!(valid(&s, &e, &b, 6, 4));
        if case == 6 {
            for p in 0..20 {
                s[56 + p * 6] = 7;
                s[57 + p * 6] = 1;
            }
            s[56..62].copy_from_slice(&[7, 1, 1, 3, 1 << 15, 49]);
            s[158..164].copy_from_slice(&[7, 1, 513, 0x301 | (2 << 32), 1 << 40, 1 << 44]);
            s[164..170].copy_from_slice(&[7, 1, 4, 1, 0, 1]);
            s[170..176].copy_from_slice(&[7, 1, 0, 1 << 56, 0, 1 << 15]);
            s[178..182].copy_from_slice(&[1, 20, 1, 1]);
        } else {
            s[179] = 0xfffff << 32;
        }
        s[176] = 1;
        s[177] = 0x1200;
        s[182] = 1;
        s[183] = 1;
        s[184] = 0x1200;
        s[185] = 0x1221;
        s[186..192].copy_from_slice(&[7, 4, 32, 0, 0, 7]);
        assert!(valid(&s, &e, &b, 7, 4));
        (s, e, b)
    }
    #[test]
    fn actual_failed_then_successful_exec_boundaries() {
        for case in [6, 7] {
            let (mut s, e, b) = acknowledged(case);
            s[11] = 4;
            s[12] = 9;
            s[16] = 9;
            s[29] = 99;
            s[31] = tag(&s, 48).unwrap();
            assert!(valid(&s, &e, &b, 8, 4));
            let mut wrong = s;
            wrong[12] = 8;
            wrong[16] = 8;
            assert!(!valid(&wrong, &e, &b, 8, 4));
            wrong = s;
            wrong[11] = 2;
            assert!(!valid(&wrong, &e, &b, 8, 4));
            wrong = s;
            wrong[BAD + 96] ^= 1;
            assert!(!valid(&wrong, &e, &b, 8, 4));
        }
    }
    #[test]
    fn failed_errno_authority_and_identity_are_real() {
        let (s, e) = failure(6);
        for cell in [
            56, 57, 59, 60, 61, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74,
        ] {
            let mut wrong = s;
            wrong[BAD + cell] ^= 1;
            assert!(!valid(&wrong, &e, &[0; 160], 3, 4), "cell {cell}");
        }
        for generation in [7, 6] {
            let mut wrong = s;
            wrong[BAD + 62] = generation;
            wrong[BAD + 66] = generation;
            assert!(!valid(&wrong, &e, &[0; 160], 3, 4));
        }
    }
    #[test]
    fn three_actual_fd_flags_state_tokens_offsets_and_mask_survive() {
        let (s, e) = failure(7);
        for cell in [
            75, 76, 77, 79, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
            111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123,
        ] {
            let mut wrong = s;
            wrong[BAD + cell] ^= 1;
            assert!(!valid(&wrong, &e, &[0; 160], 3, 4), "cell {cell}");
        }
        let mut wrong = s;
        wrong[BAD + 77] = 1;
        wrong[BAD + 122] = 1;
        assert!(!valid(&wrong, &e, &[0; 160], 3, 4));
        let mut wrong = s;
        wrong[BAD + 97] ^= 1;
        wrong[BAD + 101] ^= 1;
        assert!(!valid(&wrong, &e, &[0; 160], 3, 4));
        assert!(!valid(&s[..WORDS - 1], &e, &[0; 160], 3, 4));
    }
    #[test]
    fn failed_phase_has_no_close_or_public_success() {
        let (s, e) = failure(6);
        for cell in [36, 37, 38, 39, 40, 41, 55, 56, 176, 185] {
            let mut wrong = s;
            wrong[cell] = 1;
            assert!(!valid(&wrong, &e, &[0; 160], 3, 4), "cell {cell}");
        }
    }
    #[test]
    fn original_scope_failed_ack_and_snapshot_cannot_be_replaced() {
        let (s, e, b) = success(6);
        for cell in [4, 21, 22, 23, 24, 25, 29, 30, 31] {
            let mut wrong = s;
            wrong[cell] ^= 1;
            assert!(!valid(&wrong, &e, &b, 5, 4), "header {cell}");
        }
        for cell in [
            0, 8, 12, 32, 58, 62, 80, 81, 82, 85, 86, 88, 89, 90, 91, 92, 93, 94, 95,
        ] {
            let mut wrong = s;
            wrong[BAD + cell] ^= 1;
            assert!(!valid(&wrong, &e, &b, 5, 4), "snapshot {cell}");
        }
    }
    #[test]
    fn success_requires_actual_accepted_replay_and_exact_single_effect() {
        for case in [6, 7] {
            let (s, e, b) = acknowledged(case);
            for cell in [40, 41, 55, 178, 179, 180, 181, 185, 186, 189] {
                let mut wrong = s;
                wrong[cell] ^= 1;
                assert!(!valid(&wrong, &e, &b, 7, 4), "cell {cell}, case {case}");
            }
            for (cell, value) in [(36, 16), (37, 0), (39, 2 | (1 << 32))] {
                let mut wrong = s;
                wrong[cell] = value;
                assert!(!valid(&wrong, &e, &b, 7, 4));
            }
            if case == 6 {
                for cell in [56, 57, 58, 61, 158, 159, 160, 161, 162, 163, 174, 175] {
                    let mut wrong = s;
                    wrong[cell] ^= 1;
                    assert!(!valid(&wrong, &e, &b, 7, 4), "row {cell}");
                }
            }
        }
    }
    #[test]
    fn strict_failed_marker_and_phase_guards() {
        let line = "lock-full: exec failed profile=4 mode=6 errno=ENOEXEC abort=fresh oldfiles=preserved close=none next=committed replay=confirmed discard=once oldscope=denied published=256 common=128 payers=8";
        assert!(marker(line, 4, 6));
        assert!(!marker(line, 7, 6));
        assert!(!marker(line, 4, 7));
        for part in [
            "ENOEXEC",
            "abort=fresh",
            "oldfiles=preserved",
            "close=none",
            "next=committed",
            "replay=confirmed",
        ] {
            assert!(!marker(&line.replace(part, "missing"), 4, 6));
        }
        assert!(!marker(&format!("{line} extra"), 4, 6));
        assert!(close::pending(0x1203, 0x1203, 0x1201) == Ok(true));
        assert!(close::pending(0x1211, 0x1203, 0x1201).is_err());
        assert!(close::pending(0, 0, 0).is_err());
    }
}
