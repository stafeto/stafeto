// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
//! Strict production decoder shared with the host oracle tests.
pub fn reply(bytes: &[u8], nonce: u64, epoch: Option<u64>) -> Result<[u64; 6], ()> {
    let mut r = proto_wire::Reader::new(bytes);
    if r.u32().map_err(|_| ())? != 0 || r.u64().map_err(|_| ())? != nonce {
        return Err(());
    }
    let mut out = [0; 6];
    for word in &mut out {
        *word = r.u64().map_err(|_| ())?;
    }
    r.finish().map_err(|_| ())?;
    if epoch.is_some_and(|expected| out[0] != expected) {
        return Err(());
    }
    Ok(out)
}
pub fn census(first: u32, words: [u64; 5]) -> Result<bool, ()> {
    let [next, flags, id, generation, counts] = words;
    let found = flags >> 63 != 0;
    let visited = flags & !(1 << 63);
    if first >= 320
        || visited == 0
        || visited > 8
        || next != u64::from(first) + visited
        || next > 320
        || counts >> 48 != 0
        || (found && (id == 0 || generation == 0 || counts == 0))
        || (!found && (id != 0 || generation != 0 || counts != 0))
    {
        return Err(());
    }
    Ok(found)
}
/// Validate one complete immutable post-Stop witness, not a mix of page revisions.
#[cfg_attr(not(test), allow(dead_code))]
pub fn row(pages: &[[u64; 6]; 20]) -> Result<(), ()> {
    let epoch = pages[0][0];
    let serial = pages[0][1];
    let mask = pages[0][4];
    if epoch == 0
        || serial == 0
        || pages[0][2] == 0
        || mask > 65535
        || pages.iter().any(|p| p[0] != epoch || p[1] != serial)
        || pages[19][5] != mask
        || pages[19][4] & !mask != 0
        || pages[18][5] != 1
        || pages[18][2].checked_sub(pages[18][3]) != Some(pages[0][3])
        || pages[0][3] > 20410
    {
        return Err(());
    }
    for bit in 0..16 {
        let visits = (pages[19][2 + bit / 8] >> ((bit % 8) * 8)) & 255;
        // These are explicit marked work portions; hidden sixteen-cell lookups
        // remain part of the measured complete dispatch timing.
        if visits > 8 || (mask & (1 << bit) == 0 && visits != 0) {
            return Err(());
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_envelope_rejects_wrong_scope_truncation_and_tail() {
        let mut w = proto_wire::Writer::new();
        w.u32(0).unwrap();
        w.u64(41).unwrap();
        for n in [7, 1_u64 << 40, (1_u64 << 42) + 9, 2, 3, 4] {
            w.u64(n).unwrap();
        }
        let b = w.as_bytes();
        assert_eq!(reply(b, 41, Some(7)).unwrap()[2], (1 << 42) + 9);
        assert!(reply(b, 40, Some(7)).is_err());
        assert!(reply(b, 41, Some(8)).is_err());
        assert!(reply(&b[..59], 41, None).is_err());
        w.u32(0).unwrap();
        assert!(reply(w.as_bytes(), 41, None).is_err());
    }
    #[test]
    fn census_preserves_full_identity_and_bounded_physical_cursor() {
        assert_eq!(
            census(319, [320, (1 << 63) | 1, 1 << 40, 1 << 48, 16]),
            Ok(true)
        );
        assert_eq!(census(312, [320, 8, 0, 0, 0]), Ok(false));
        for bad in [
            [320, 9, 0, 0, 0],
            [320, 8, 1, 0, 0],
            [319, 8, 0, 0, 0],
            [320, (1 << 63) | 8, 1, 0, 16],
            [320, (1 << 63) | 8, 1, 1, 1 << 48],
        ] {
            assert!(census(312, bad).is_err());
        }
        assert!(census(300, [309, 9, 0, 0, 0]).is_err());
        assert!(census(320, [320, 0, 0, 0, 0]).is_err());
    }
    #[test]
    fn row_rejects_mixed_revision_unbounded_portion_and_forged_timing() {
        let mut pages = [[1, 9, 0, 0, 0, 0]; 20];
        pages[0] = [1, 9, 3, 20410, 1, 54];
        pages[18] = [1, 9, 20417, 7, 0, 1];
        pages[19] = [1, 9, 8, 0, 0, 1];
        assert_eq!(row(&pages), Ok(()));
        let original = pages;
        pages[7][1] += 1;
        assert!(row(&pages).is_err());
        pages = original;
        pages[3][0] += 1;
        assert!(row(&pages).is_err());
        pages = original;
        pages[19][2] = 9;
        assert!(row(&pages).is_err());
        pages = original;
        pages[18][2] += 1;
        assert!(row(&pages).is_err());
        pages = original;
        pages[19][5] = 0;
        assert!(row(&pages).is_err());
        pages = original;
        pages[0][3] += 1;
        pages[18][2] += 1;
        assert!(row(&pages).is_err());
    }
}

#[derive(Clone, Copy)]
#[cfg_attr(not(test), allow(dead_code))]
pub struct WaitObservation {
    pub nonce: u64,
    pub pid: u32,
    pub owner: u64,
    pub slot: u32,
    pub generation: u64,
    pub first: u32,
    pub discover: bool,
}
#[cfg_attr(not(test), allow(dead_code))]
pub fn wait_observation(bytes: &[u8], expected: WaitObservation) -> Result<bool, ()> {
    let mut r = proto_wire::Reader::new(bytes);
    if expected.nonce == 0
        || expected.pid == 0
        || expected.owner == 0
        || expected.slot >= 16
        || expected.generation == 0
        || !matches!(expected.first, 0 | 8)
        || r.u32().map_err(|_| ())? != 0
        || r.u64().map_err(|_| ())? != expected.nonce
        || r.u32().map_err(|_| ())? != expected.pid
    {
        return Err(());
    }
    let visited = r.u32().map_err(|_| ())?;
    let present = r.u32().map_err(|_| ())?;
    let owner = r.u64().map_err(|_| ())?;
    let slot = r.u32().map_err(|_| ())?;
    let generation = r.u64().map_err(|_| ())?;
    let registration = r.u32().map_err(|_| ())?;
    r.finish().map_err(|_| ())?;
    if !(1..=8).contains(&visited) || present > 1 {
        return Err(());
    }
    if present == 0 {
        if owner != 0 || slot != 0 || generation != 0 || registration != 0 {
            return Err(());
        }
        return Ok(false);
    }
    if owner != expected.owner
        || slot != expected.slot
        || generation != expected.generation
        || !(expected.first..expected.first + 8).contains(&registration)
            && (expected.discover || registration != u32::MAX)
    {
        return Err(());
    }
    Ok(true)
}
#[cfg(test)]
mod capacity_tests {
    use super::*;
    fn response(registration: u32) -> (Vec<u8>, WaitObservation) {
        let expected = WaitObservation {
            nonce: 33,
            pid: 257,
            owner: (1 << 63) | 99,
            slot: 3,
            generation: 1 << 40,
            first: 8,
            discover: false,
        };
        let mut w = proto_wire::Writer::new();
        w.u32(0).unwrap();
        w.u64(expected.nonce).unwrap();
        w.u32(expected.pid).unwrap();
        w.u32(8).unwrap();
        w.u32(1).unwrap();
        w.u64(expected.owner).unwrap();
        w.u32(expected.slot).unwrap();
        w.u64(expected.generation).unwrap();
        w.u32(registration).unwrap();
        (w.as_bytes().to_vec(), expected)
    }
    #[test]
    fn exact_queue_only_is_present_but_not_discovered_sleeping() {
        let (bytes, mut expected) = response(u32::MAX);
        assert_eq!(wait_observation(&bytes, expected), Ok(true));
        expected.discover = true;
        assert_eq!(wait_observation(&bytes, expected), Err(()));
    }
    #[test]
    fn full_generation_and_physical_half_cannot_be_substituted() {
        let (mut bytes, expected) = response(9);
        assert_eq!(wait_observation(&bytes, expected), Ok(true));
        bytes[36..44].copy_from_slice(&1_u64.to_le_bytes());
        assert_eq!(wait_observation(&bytes, expected), Err(()));
        let (bytes, mut expected) = response(9);
        expected.first = 0;
        assert_eq!(wait_observation(&bytes, expected), Err(()));
    }
    #[test]
    fn absence_requires_zero_identity_and_bounded_actual_visits() {
        let (mut bytes, expected) = response(9);
        bytes[20..24].copy_from_slice(&0_u32.to_le_bytes());
        assert_eq!(wait_observation(&bytes, expected), Err(()));
        bytes[24..48].fill(0);
        assert_eq!(wait_observation(&bytes, expected), Ok(false));
        bytes[16..20].copy_from_slice(&9_u32.to_le_bytes());
        assert_eq!(wait_observation(&bytes, expected), Err(()));
    }
}
