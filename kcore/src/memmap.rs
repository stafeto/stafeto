// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Usable RAM (spec 7.1): memory regions minus what the boot left in place,
//! in whole 4 KiB pages.

use crate::bootinfo::{Region, RegionList};

pub const PAGE: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemMapError {
    TooManyRegions,
}

fn align_down(x: u64) -> u64 {
    x & !(PAGE - 1)
}

fn align_up(x: u64) -> u64 {
    x.checked_add(PAGE - 1)
        .map_or(align_down(u64::MAX), align_down)
}

fn push<const N: usize>(
    list: &mut [Region; N],
    len: &mut usize,
    r: Region,
) -> Result<(), MemMapError> {
    if *len == N {
        return Err(MemMapError::TooManyRegions);
    }
    list[*len] = r;
    *len += 1;
    Ok(())
}

/// The part of `r` inside `window`, if any.
pub fn clip(r: Region, window: Region) -> Option<Region> {
    let base = r.base.max(window.base);
    let end = r.end().min(window.end());
    (end > base).then(|| Region {
        base,
        size: end - base,
    })
}

/// `memory` minus `reserved`, sorted by address. Memory regions shrink to
/// page boundaries; reserved ranges grow to them.
pub fn usable<const N: usize>(
    memory: &[Region],
    reserved: &[Region],
) -> Result<RegionList<N>, MemMapError> {
    let empty = Region { base: 0, size: 0 };
    let mut pieces = [empty; N];
    let mut len = 0;
    for m in memory {
        let (base, end) = (align_up(m.base), align_down(m.end()));
        if end > base {
            push(
                &mut pieces,
                &mut len,
                Region {
                    base,
                    size: end - base,
                },
            )?;
        }
    }
    for r in reserved {
        let (lo, hi) = (align_down(r.base), align_up(r.end()));
        if hi <= lo {
            continue;
        }
        let mut next = [empty; N];
        let mut n = 0;
        for p in &pieces[..len] {
            let (pb, pe) = (p.base, p.end());
            if hi <= pb || lo >= pe {
                push(&mut next, &mut n, *p)?;
                continue;
            }
            if lo > pb {
                push(
                    &mut next,
                    &mut n,
                    Region {
                        base: pb,
                        size: lo - pb,
                    },
                )?;
            }
            if hi < pe {
                push(
                    &mut next,
                    &mut n,
                    Region {
                        base: hi,
                        size: pe - hi,
                    },
                )?;
            }
        }
        pieces = next;
        len = n;
    }
    pieces[..len].sort_unstable_by_key(|p| p.base);
    let mut out = RegionList::new();
    for p in &pieces[..len] {
        out.push(*p).map_err(|_| MemMapError::TooManyRegions)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(base: u64, size: u64) -> Region {
        Region { base, size }
    }

    const MIB: u64 = 1 << 20;

    #[test]
    fn memory_without_reservations_is_usable_as_is() {
        let u = usable::<4>(&[r(0x4000_0000, 512 * MIB)], &[]).unwrap();
        assert_eq!(u.as_slice(), [r(0x4000_0000, 512 * MIB)]);
    }

    #[test]
    fn reservation_in_the_middle_splits_a_region() {
        let u = usable::<4>(&[r(0x4000_0000, 16 * MIB)], &[r(0x4040_0000, MIB)]).unwrap();
        assert_eq!(
            u.as_slice(),
            [r(0x4000_0000, 4 * MIB), r(0x4050_0000, 11 * MIB)]
        );
    }

    #[test]
    fn reservations_at_the_edges_trim_a_region() {
        let u = usable::<4>(
            &[r(0x4000_0000, 16 * MIB)],
            &[r(0x4000_0000, MIB), r(0x40F0_0000, MIB)],
        )
        .unwrap();
        assert_eq!(u.as_slice(), [r(0x4010_0000, 14 * MIB)]);
    }

    #[test]
    fn reservation_covering_everything_leaves_nothing() {
        let u = usable::<4>(&[r(0x4000_0000, MIB)], &[r(0x3000_0000, 1 << 30)]).unwrap();
        assert!(u.as_slice().is_empty());
    }

    #[test]
    fn reservation_outside_memory_changes_nothing() {
        let u = usable::<4>(&[r(0x4000_0000, MIB)], &[r(0x9000_0000, MIB)]).unwrap();
        assert_eq!(u.as_slice(), [r(0x4000_0000, MIB)]);
    }

    #[test]
    fn unaligned_memory_shrinks_and_unaligned_reservations_grow() {
        let u = usable::<4>(&[r(0x4000_0800, 0x5000)], &[r(0x4000_2100, 0x100)]).unwrap();
        assert_eq!(
            u.as_slice(),
            [r(0x4000_1000, 0x1000), r(0x4000_3000, 0x2000)]
        );
    }

    #[test]
    fn output_is_sorted_by_address() {
        let u = usable::<4>(&[r(0x8000_0000, MIB), r(0x4000_0000, MIB)], &[]).unwrap();
        assert_eq!(u.as_slice(), [r(0x4000_0000, MIB), r(0x8000_0000, MIB)]);
    }

    #[test]
    fn too_many_pieces_is_an_error() {
        let res = [r(0x4010_0000, MIB), r(0x4030_0000, MIB)];
        assert_eq!(
            usable::<2>(&[r(0x4000_0000, 8 * MIB)], &res).err(),
            Some(MemMapError::TooManyRegions)
        );
    }

    #[test]
    fn reservation_reaching_the_top_of_the_address_space() {
        let u = usable::<4>(
            &[r(0x4000_0000, 2 * MIB)],
            &[r(0x4010_0000, u64::MAX - 0x4010_0000)],
        )
        .unwrap();
        assert_eq!(u.as_slice(), [r(0x4000_0000, MIB)]);
    }

    #[test]
    fn clip_returns_the_overlap_or_nothing() {
        assert_eq!(
            clip(r(0x3000_0000, 1 << 30), r(0x4000_0000, 1 << 30)),
            Some(r(0x4000_0000, 0x3000_0000))
        );
        assert_eq!(clip(r(0x4000_0000, MIB), r(0x8000_0000, MIB)), None);
        assert_eq!(clip(r(0x4000_0000, MIB), r(0x4010_0000, MIB)), None);
    }
}
