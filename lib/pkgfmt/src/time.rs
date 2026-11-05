// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Times as seconds since 1970-01-01T00:00:00Z and as RFC 3339 text in the
//! one shape `YYYY-MM-DDThh:mm:ssZ`, by the algorithm of days from a civil
//! date.

/// The text is always this long.
pub const TEXT_LEN: usize = 20;

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn month_days(y: i64, m: i64) -> i64 {
    match m {
        2 if is_leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a civil date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn digits(b: &[u8]) -> Option<i64> {
    let mut v = 0;
    for &c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + i64::from(c - b'0');
    }
    Some(v)
}

/// The seconds of `YYYY-MM-DDThh:mm:ssZ`; years 1970 to 9999, real dates and
/// times only (no leap seconds, no offsets, no lower case).
pub fn parse(text: &str) -> Option<u64> {
    let b = text.as_bytes();
    if b.len() != TEXT_LEN
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let (y, m, d) = (digits(&b[0..4])?, digits(&b[5..7])?, digits(&b[8..10])?);
    let (h, mi, s) = (digits(&b[11..13])?, digits(&b[14..16])?, digits(&b[17..19])?);
    if y < 1970 || !(1..=12).contains(&m) || d < 1 || d > month_days(y, m) || h > 23 || mi > 59 || s > 59 {
        return None;
    }
    Some((days_from_civil(y, m, d) * 86_400 + h * 3600 + mi * 60 + s) as u64)
}

/// The text of `secs`; `None` after 9999-12-31T23:59:59Z.
pub fn format(secs: u64, out: &mut [u8; TEXT_LEN]) -> Option<&str> {
    if secs > 253_402_300_799 {
        return None;
    }
    let days = (secs / 86_400) as i64;
    let rest = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    let put = |out: &mut [u8; TEXT_LEN], at: usize, n: usize, mut v: i64| {
        for i in (0..n).rev() {
            out[at + i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    };
    put(out, 0, 4, y);
    out[4] = b'-';
    put(out, 5, 2, m);
    out[7] = b'-';
    put(out, 8, 2, d);
    out[10] = b'T';
    put(out, 11, 2, (rest / 3600) as i64);
    out[13] = b':';
    put(out, 14, 2, (rest % 3600 / 60) as i64);
    out[16] = b':';
    put(out, 17, 2, (rest % 60) as i64);
    out[19] = b'Z';
    core::str::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CASES: [(&str, u64); 5] = [
        ("1970-01-01T00:00:00Z", 0),
        ("2000-02-29T12:34:56Z", 951_827_696),
        ("2100-03-01T00:00:00Z", 4_107_542_400),
        ("2026-12-05T00:00:00Z", 1_796_428_800),
        ("9999-12-31T23:59:59Z", 253_402_300_799),
    ];

    #[test]
    fn known_instants_both_ways() {
        for (text, secs) in CASES {
            assert_eq!(parse(text), Some(secs), "{text}");
            let mut buf = [0u8; TEXT_LEN];
            assert_eq!(format(secs, &mut buf), Some(text));
        }
        let mut buf = [0u8; TEXT_LEN];
        assert_eq!(format(253_402_300_800, &mut buf), None);
    }

    #[test]
    fn every_day_round_trips() {
        for days in (0..2_932_897).step_by(7) {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }

    #[test]
    fn bad_dates_are_refused() {
        for bad in [
            "2100-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-00-10T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T00:60:00Z",
            "2026-01-01T00:00:60Z",
            "2026-01-01t00:00:00Z",
            "2026-01-01T00:00:00z",
            "2026-01-01T00:00:00+00:00",
            "1969-12-31T23:59:59Z",
            "2026-1-01T00:00:00Z",
            "",
        ] {
            assert_eq!(parse(bad), None, "{bad}");
        }
    }
}
