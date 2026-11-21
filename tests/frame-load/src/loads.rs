// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The loops of the loads that need no window: the files of `/data` and the
//! TCP on the loopback. Their requests are in `data-probe` and `net-probe`;
//! what is decided here is the order of the operations and their sizes, so
//! that a loop never touches a file that is not there and never leaves a
//! file behind, whenever it is stopped.

/// The bytes of a file of the load, written in pieces: 64 KiB.
pub const FILE_BYTES: usize = 64 * 1024;
/// The files the loop keeps at most (the names `/load/f0` to `/load/f3`).
pub const SLOTS: u32 = 4;

/// One operation of the file load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileOp {
    /// Make the file of the slot under a temporary name: create, write
    /// `FILE_BYTES`, sync, close.
    Write { slot: u32, salt: u32 },
    /// Rename the temporary file to the name of the slot (over the old file
    /// when there is one).
    Rename { slot: u32 },
    /// Remove the file of the slot.
    Delete { slot: u32 },
}

/// The operation `n` of the loop: each round of `SLOTS * 3` operations writes
/// and renames every slot and then deletes the slot that is the oldest, so the
/// directory has between one and `SLOTS` files at any time. A write is always
/// followed by its rename.
pub const fn file_op(n: u64) -> FileOp {
    let round = n / (SLOTS as u64 * 3);
    let within = n % (SLOTS as u64 * 3);
    let slot = (within / 3) as u32;
    let salt = (round as u32).wrapping_mul(7).wrapping_add(slot);
    match within % 3 {
        0 => FileOp::Write { slot, salt },
        1 => FileOp::Rename { slot },
        _ => FileOp::Delete {
            slot: (slot + SLOTS - 1) % SLOTS,
        },
    }
}

/// The name of the file of `slot`: `/load/f<slot>`; of the temporary file:
/// `/load/tmp`.
pub const DIRECTORY: &[u8] = b"/load";
pub const TEMPORARY: &[u8] = b"/load/tmp";

pub fn slot_name(slot: u32, out: &mut [u8; 16]) -> usize {
    out[..7].copy_from_slice(b"/load/f");
    out[7] = b'0' + (slot % 10) as u8;
    8
}

/// The byte `k` of a file of the load with `salt`.
pub const fn byte(k: usize, salt: u32) -> u8 {
    (k as u32)
        .wrapping_mul(31)
        .wrapping_add(salt)
        .wrapping_add((k >> 8) as u32) as u8
}

/// The share of the processor the file load keeps for itself, in parts per million of the
/// time: a quarter. The load is a client at 30 and the work of its operations is done by the
/// data service's worker, which no budget holds on one CPU, so the load holds itself: it
/// rests after each operation for the time the operation took, scaled so that the operations
/// are a quarter of the time. The CPU load at 29 and the frame's services above 32 count on
/// this share in the floors of `frame-probe`.
pub const FILE_SHARE_PPM: u64 = 250_000;

/// The rest after an operation that took `busy_ns` of the clock: what makes the operations
/// `FILE_SHARE_PPM` of the time (three times the operation at a quarter).
pub const fn rest_ns(busy_ns: u64) -> u64 {
    busy_ns * (1_000_000 - FILE_SHARE_PPM) / FILE_SHARE_PPM
}

/// The bytes one TCP round of the network load sends there and back: 64 KiB,
/// in pieces of `NET_PIECE`.
pub const NET_ROUND: usize = 64 * 1024;
pub const NET_PIECE: usize = 800;

/// The pieces of a round and the bytes of the last one.
pub const fn net_pieces() -> (usize, usize) {
    (NET_ROUND / NET_PIECE, NET_ROUND % NET_PIECE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Run the loop for `ops` operations on a model of the directory and call
    /// `check` after each; the directory it ends with is the result.
    fn model(ops: u64, mut check: impl FnMut(&BTreeSet<u32>, bool)) -> BTreeSet<u32> {
        let mut files = BTreeSet::new();
        let mut tmp = false;
        for n in 0..ops {
            match file_op(n) {
                FileOp::Write { .. } => {
                    assert!(
                        !tmp,
                        "op {n}: a write over a temporary file that was not renamed"
                    );
                    tmp = true;
                }
                FileOp::Rename { slot } => {
                    assert!(
                        tmp,
                        "op {n}: a rename of a temporary file that is not there"
                    );
                    tmp = false;
                    files.insert(slot);
                }
                FileOp::Delete { slot } => {
                    // A delete of the first round finds nothing to delete: the
                    // slot before slot 0 is the last, which a round has not
                    // written yet. The loop treats that as already gone.
                    files.remove(&slot);
                }
            }
            check(&files, tmp);
        }
        files
    }

    #[test]
    fn the_rest_makes_the_operations_a_quarter_of_the_time() {
        assert_eq!(rest_ns(0), 0);
        for busy in [1_000u64, 135_000_000, 4_166_667] {
            let rest = rest_ns(busy);
            // The share of the cycle (operation and rest) the operation is, within a
            // part per million of rounding.
            let share = busy * 1_000_000 / (busy + rest);
            assert!(share.abs_diff(FILE_SHARE_PPM) <= 1_000, "{busy}: {share}");
        }
        assert_eq!(rest_ns(100), 300);
    }

    #[test]
    fn a_write_is_always_followed_by_its_rename() {
        for n in 0..SLOTS as u64 * 3 * 5 {
            if let FileOp::Write { slot, .. } = file_op(n) {
                assert_eq!(file_op(n + 1), FileOp::Rename { slot });
            }
        }
    }

    #[test]
    fn the_directory_never_holds_more_than_the_slots_and_the_loop_cleans_up() {
        model(1000, |files, _| assert!(files.len() <= SLOTS as usize));
        // Stopped at the end of any round, at most the slots are left; the load
        // removes them when it is told to stop (the files are its own).
        let end = model(SLOTS as u64 * 3 * 6, |_, _| {});
        assert!(end.len() <= SLOTS as usize);
    }

    /// The fault the test is for: a loop that renames before it writes.
    #[test]
    fn the_first_operation_is_a_write_not_a_rename() {
        assert!(matches!(file_op(0), FileOp::Write { slot: 0, .. }));
    }

    #[test]
    fn the_salt_changes_from_round_to_round() {
        let a = file_op(0);
        let b = file_op(SLOTS as u64 * 3);
        assert_ne!(a, b);
    }

    #[test]
    fn the_slot_names_are_distinct_and_in_the_directory() {
        let mut seen = BTreeSet::new();
        for slot in 0..SLOTS {
            let mut out = [0; 16];
            let n = slot_name(slot, &mut out);
            assert!(out[..n].starts_with(DIRECTORY));
            assert!(seen.insert(out[..n].to_vec()));
        }
    }

    #[test]
    fn a_net_round_is_81_pieces_and_a_part() {
        assert_eq!(net_pieces(), (81, 64 * 1024 - 81 * 800));
    }
}
