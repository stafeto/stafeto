// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
//! The same bounded state checks are called by the guest and host negatives.
pub const WORDS: usize = 352;
pub const MAGIC: u64 = 0x6578656332353602;
pub const BACKEND_MASK: u64 = 0x7f3f;
pub const ABSENT: u64 = 0xfffff << 32;

pub fn binding(bytes: &[u8], nonce: u64) -> Result<[u64; 9], ()> {
    if bytes.len() != 56 || nonce == 0 {
        return Err(());
    }
    let small = |at| u64::from(u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()));
    let wide = |at| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    if small(0) != 0 || wide(4) != nonce {
        return Err(());
    }
    let out = [
        small(12),
        small(16),
        small(20),
        small(24),
        wide(28),
        small(36),
        small(40),
        small(44),
        wide(48),
    ];
    if active(&out) { Ok(out) } else { Err(()) }
}

pub fn active(w: &[u64]) -> bool {
    w.len() == 9
        && w[0] == 1
        && w[1] > 255
        && w[1] <= u64::from(u32::MAX)
        && w[2] < 256
        && w[1] % 256 == w[2]
        && w[3] > 0
        && w[3] < (1 << 21)
        && w[4] != 0
        && w[4] >> 63 == 0
        && w[5] != 0
        && w[5] <= u64::from(u32::MAX)
        && w[6] != 0
        && w[6] <= u64::from(u32::MAX)
        && w[7] == 0
        && w[8] == w[4]
}

pub fn initial(s: &[u64], case: u64, nonce: u64) -> bool {
    s.len() == WORDS
        && (case == 1 || case == 2)
        && nonce != 0
        && s[0] == MAGIC
        && s[1] == 1
        && s[2] == case
        && s[3] == nonce
        && s[5] < 32
        && s[6] == 0
        && s[7] != 0
        && active(&s[8..17])
        && s[17] < 32
        && s[17] != s[5]
        && s[18] != 0
        && s[19] & !BACKEND_MASK == 0
        && s[20] != 0
        && s[26..29] == [256, 128, 8]
        && s[31] == nonce
}

pub fn permitted(s: &[u64], case: u64, nonce: u64) -> bool {
    initial(s, case, nonce)
        && s[4] != 0
        && s[21] & !BACKEND_MASK == 0
        && s[22] != 0
        && s[23] != 0
        && s[23] != s[9]
        && s[24] == s[13]
        && s[25] == s[14]
        && s[29] == 2
        && s[30] == nonce
}

pub fn frozen(s: &[u64], expected: &[u64]) -> bool {
    s.len() == WORDS
        && expected.len() == 32
        && (0..32).all(|index| matches!(index, 4 | 29 | 30) || s[index] == expected[index])
}

pub fn ready(s: &[u64], case: u64, nonce: u64) -> bool {
    if !permitted(s, case, nonce) || s[55] != nonce {
        return false;
    }
    let r = &s[32..56];
    active(&r[4..13])
        && r[0] == s[17]
        && r[1] != 0
        && r[2] == s[19]
        && r[3] == s[20]
        && r[5] == s[9]
        && r[6] == s[10]
        && r[7] > s[11]
        && r[8] > s[12]
        && r[9] == s[13]
        && r[10] == s[14]
        && r[13] == s[6]
        && r[14] == s[7]
        && r[15] == s[5]
        && r[16] == 310
        && r[17] == 3
        && r[18] == nonce
        && r[19..23] == [0; 4]
}

pub fn stopped(s: &[u64], case: u64, nonce: u64) -> bool {
    ready(s, case, nonce)
        && s[56..176].iter().all(|w| *w == 0)
        && s[176] == s[4]
        && s[177] == 4
        && s[178] == nonce
        && s[179] == 1
        && s[180] == 0
        && s[181] == ABSENT
        && s[182] == 0
        && s[183] == 0
        && s[184] == 1
        && s[185] == nonce
        && s[186..192] == [s[4], s[187], 32, 0, 0, s[4]]
        && (s[187] == 4 || s[187] == 7)
        && s[192..].iter().all(|w| *w == 0)
}

pub fn absence(status: &[i32]) -> bool {
    status.len() == 20 && status.iter().all(|code| *code == -304)
}

pub fn advance(current: u64, next: u64) -> bool {
    matches!((current, next), (1, 2) | (2, 3) | (3, 4))
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn marker(line: &str, profile: u64, case: u64) -> bool {
    let mut fields = line.split_whitespace();
    for expected in ["lock-full:", "exec", "retained"] {
        if fields.next() != Some(expected) {
            return false;
        }
    }
    let mut number = |name: &str| fields.next()?.strip_prefix(name)?.parse::<u64>().ok();
    if number("profile=") != Some(profile) || number("mode=") != Some(case) {
        return false;
    }
    let Some(pid) = number("pid=") else {
        return false;
    };
    let Some(old) = number("old-image=") else {
        return false;
    };
    let Some(new) = number("new-image=") else {
        return false;
    };
    let Some(da) = fields.next().and_then(|s| s.strip_prefix("da=")) else {
        return false;
    };
    let Some((packed, generation)) = da.split_once('/') else {
        return false;
    };
    let (Ok(packed), Ok(generation)) = (packed.parse::<u64>(), generation.parse::<u64>()) else {
        return false;
    };
    let mut number = |name: &str| fields.next()?.strip_prefix(name)?.parse::<u64>().ok();
    let Some(old_credential) = number("old-credential=") else {
        return false;
    };
    let Some(new_credential) = number("new-credential=") else {
        return false;
    };
    pid > 255
        && pid <= u64::from(u32::MAX)
        && old > 0
        && new > old
        && new < (1 << 21)
        && packed & !BACKEND_MASK == 0
        && generation > 0
        && old_credential > 0
        && old_credential >> 63 == 0
        && new_credential > 0
        && new_credential > old_credential
        && new_credential >> 63 == 0
        && fields.next() == Some("oldscope=denied")
        && fields.next() == Some("published=256")
        && fields.next() == Some("common=128")
        && fields.next() == Some("payers=8")
        && fields.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn state() -> [u64; WORDS] {
        let mut s = [0; WORDS];
        s[..8].copy_from_slice(&[MAGIC, 1, 1, 99, 1, 4, 0, 101]);
        s[8..17].copy_from_slice(&[1, 513, 1, 2, 7, 257, 1, 0, 7]);
        s[17..32].copy_from_slice(&[
            3,
            9,
            0x301,
            0x100000001,
            0x402,
            0x200000002,
            514,
            257,
            1,
            256,
            128,
            8,
            2,
            99,
            99,
        ]);
        s[32..56].copy_from_slice(&[
            3,
            1,
            0x301,
            0x100000001,
            1,
            513,
            1,
            3,
            8,
            257,
            1,
            0,
            8,
            0,
            101,
            4,
            310,
            3,
            99,
            0,
            0,
            0,
            0,
            99,
        ]);
        s[176..192].copy_from_slice(&[1, 4, 99, 1, 0, ABSENT, 0, 0, 1, 99, 1, 4, 32, 0, 0, 1]);
        s
    }
    #[test]
    fn fresh_credentials_reject_old_or_lower_generation_even_with_matching_live() {
        let s = state();
        for credential in [s[12], s[12] - 1] {
            let mut wrong = s;
            wrong[40] = credential;
            wrong[44] = credential;
            assert!(active(&wrong[36..45]));
            assert!(!ready(&wrong, 1, 99));
            assert!(!stopped(&wrong, 1, 99));
        }
    }
    #[test]
    fn guest_summary_rejects_missing_wrong_stale_and_extra_fields() {
        let line = "lock-full: exec retained profile=4 mode=1 pid=513 old-image=2 new-image=3 da=769/4294967297 old-credential=7 new-credential=8 oldscope=denied published=256 common=128 payers=8";
        assert!(marker(line, 4, 1));
        assert!(!marker(line, 7, 1));
        assert!(!marker(line, 4, 2));
        for credential in [7, 6] {
            assert!(!marker(
                &line.replace("new-credential=8", &format!("new-credential={credential}")),
                4,
                1
            ));
        }
        for (before, after) in [
            ("new-image=3", "new-image=2"),
            ("oldscope=denied", "oldscope=granted"),
            ("common=128", "common=127"),
            ("da=769/4294967297", "da=769/0"),
            ("new-credential=8", "new-credential=0"),
            ("payers=8", "payers=9"),
        ] {
            assert!(!marker(&line.replace(before, after), 4, 1));
        }
        assert!(!marker(&format!("{line} extra=1"), 4, 1));
        assert!(!marker(line.strip_suffix(" payers=8").unwrap(), 4, 1));
    }
    #[test]
    fn authenticated_binding_rejects_short_wrong_nonce_status_and_stale_live() {
        let mut bytes = [0u8; 56];
        bytes[4..12].copy_from_slice(&99u64.to_le_bytes());
        for (offset, value) in [(12, 1u32), (16, 513), (20, 1), (24, 2), (36, 257), (40, 1)] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes[28..36].copy_from_slice(&7u64.to_le_bytes());
        bytes[48..56].copy_from_slice(&7u64.to_le_bytes());
        assert!(binding(&bytes, 99).is_ok());
        assert!(binding(&bytes, 98).is_err());
        for n in 0..56 {
            assert!(binding(&bytes[..n], 99).is_err());
        }
        for (at, value) in [(0, 1u8), (12, 2), (20, 2), (44, 1), (48, 8)] {
            let mut wrong = bytes;
            wrong[at] = value;
            assert!(binding(&wrong, 99).is_err());
        }
    }
    #[test]
    fn genuine_retained_state_accepts_new_local_entry_and_live_generation() {
        let s = state();
        assert!(stopped(&s, 1, 99));
        let mut ofd = s;
        ofd[2] = 2;
        assert!(stopped(&ofd, 2, 99));
        assert_ne!(s[18], s[33]);
    }
    #[test]
    fn missing_wrong_stale_and_short_states_fail_the_guest_decoder() {
        let s = state();
        let expected = &s[..32];
        for n in 0..WORDS {
            assert!(!stopped(&s[..n], 1, 99));
        }
        for index in [
            0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 12, 13, 14, 16, 17, 19, 20, 21, 22, 23, 24, 25, 26, 27,
            28, 29, 30, 31, 32, 34, 35, 37, 38, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
            53, 54, 55, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190,
            191, 193,
        ] {
            let mut wrong = s;
            wrong[index] ^= 1;
            assert!(
                !stopped(&wrong, 1, 99) || !frozen(&wrong, expected),
                "field {index}"
            );
        }
        let mut old = s;
        old[39] = s[11];
        assert!(!ready(&old, 1, 99));
        old = s;
        old[55] = 0;
        assert!(!ready(&old, 1, 99));
        old = s;
        old[185] = 98;
        assert!(!stopped(&old, 1, 99));
        assert!(!stopped(&s, 1, 98));
    }
    #[test]
    fn replay_and_skipped_phase_cannot_advance() {
        for pair in [(1, 2), (2, 3), (3, 4)] {
            assert!(advance(pair.0, pair.1));
        }
        for pair in [(1, 1), (2, 2), (3, 3), (4, 4), (1, 3), (3, 2), (4, 1)] {
            assert!(!advance(pair.0, pair.1));
        }
    }
    #[test]
    fn twenty_real_absences_do_not_accept_auth_errors_or_partial_pages() {
        let mut status = [-304; 20];
        assert!(absence(&status));
        for code in [-310, -321, 0] {
            status[19] = code;
            assert!(!absence(&status));
        }
        assert!(!absence(&[-304; 19]));
    }
}
