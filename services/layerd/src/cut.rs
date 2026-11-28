// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The cut points of the copy up and of the rename of a lower name, for `cargo xtask layer-cut copy`.
//! A build with the feature `probe-cut` and `STAFETO_LAYERD_CUT_AT=<point>` prints a line at that
//! point and stops there for good (`Volume::cut`, `Bulk::cut`); the host kills the machine on the
//! line and starts it again on the same disk. Every other build has no point (`AT` is 0) and the
//! calls are not made.

/// The file in `work/` was made (OPEN_NUMBERED answered), no byte is in it.
pub const WORK_MADE: u8 = 1;
/// The first cell of a file of more than one cell was written, and no more.
pub const MID_COPY: u8 = 2;
/// The file in `work/` is whole and closed, and not visible.
pub const WORK_CLOSED: u8 = 3;
/// The copy was renamed into the layer, and the index does not know it yet.
pub const COPY_RENAMED: u8 = 4;
/// The mark of the old name of a rename was written, and the name was not moved yet.
pub const MARKED: u8 = 5;
/// The volume has the new name of a rename, and the index does not follow yet.
pub const MOVED: u8 = 6;

/// The point of the build, 0 for none.
pub const AT: u8 = if cfg!(feature = "probe-cut") {
    match option_env!("STAFETO_LAYERD_CUT_AT") {
        Some(text) => parse(text.as_bytes()),
        None => 0,
    }
} else {
    0
};

const fn parse(text: &[u8]) -> u8 {
    let mut value = 0u32;
    let mut i = 0;
    while i < text.len() {
        value = value * 10 + (text[i] - b'0') as u32;
        i += 1;
    }
    if value > 255 { 0 } else { value as u8 }
}

/// Whether this build stops at `point`.
pub const fn armed(point: u8) -> bool {
    AT != 0 && AT == point
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_points_are_distinct_and_a_build_with_none_stops_nowhere() {
        let all = [
            WORK_MADE,
            MID_COPY,
            WORK_CLOSED,
            COPY_RENAMED,
            MARKED,
            MOVED,
        ];
        for (i, a) in all.iter().enumerate() {
            assert!(*a != 0);
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
            assert!(!armed(*a));
        }
        assert_eq!(parse(b"6"), 6);
        assert_eq!(parse(b"300"), 0);
    }
}
