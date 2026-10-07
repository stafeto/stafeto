// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Finite process-owned snapshots. Public setters and enforcement follow separately.

use proto_wire::{Reader, Status, Writer};

pub const SUPPLEMENTARY_MAX: usize = 16;
pub const LIMITS: usize = 6;
pub const CORE: usize = 0;
pub const DATA: usize = 1;
pub const FSIZE: usize = 2;
pub const NOFILE: usize = 3;
pub const STACK: usize = 4;
pub const AS: usize = 5;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Groups {
    pub count: u32,
    pub ids: [u32; SUPPLEMENTARY_MAX],
}
impl Groups {
    pub const EMPTY: Self = Self {
        count: 0,
        ids: [0; SUPPLEMENTARY_MAX],
    };
    pub fn contains(&self, gid: u32) -> bool {
        self.ids[..self.count as usize].contains(&gid)
    }
    pub fn valid(&self) -> bool {
        if self.count == 0 {
            return self.ids == [0; SUPPLEMENTARY_MAX];
        }
        self.count as usize <= SUPPLEMENTARY_MAX
            && !self.ids[..self.count as usize].contains(&u32::MAX)
            && self.ids[self.count as usize..].iter().all(|&id| id == 0)
    }
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        if !self.valid() {
            return Err(Status::BadSize);
        }
        #[cfg(target_endian = "little")]
        {
            const {
                assert!(core::mem::size_of::<Groups>() == 68);
            }
            // SAFETY: repr(C) has 17 initialized u32 words and no padding, in wire byte order.
            w.bytes(unsafe {
                core::slice::from_raw_parts(core::ptr::from_ref(self).cast::<u8>(), 68)
            })
        }
        #[cfg(target_endian = "big")]
        {
            w.u32(self.count)?;
            for id in self.ids {
                w.u32(id)?;
            }
            Ok(())
        }
    }
    pub fn read(r: &mut Reader<'_>) -> Result<Self, Status> {
        let count = r.u32()?;
        let mut ids = [0; SUPPLEMENTARY_MAX];
        for id in &mut ids {
            *id = r.u32()?;
        }
        let groups = Self { count, ids };
        if !groups.valid() {
            return Err(Status::BadSize);
        }
        Ok(groups)
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limit {
    pub soft: u64,
    pub hard: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceLimits {
    pub values: [Limit; LIMITS],
}
impl ResourceLimits {
    pub const fn initial(quota: u64) -> Self {
        let mut values = [Limit {
            soft: quota,
            hard: quota,
        }; LIMITS];
        values[CORE] = Limit { soft: 0, hard: 0 };
        values[FSIZE] = Limit {
            soft: 8 * 1024 * 1024,
            hard: 8 * 1024 * 1024,
        };
        values[NOFILE] = Limit { soft: 32, hard: 32 };
        values[STACK] = Limit {
            soft: 64 * 1024,
            hard: 64 * 1024,
        };
        Self { values }
    }
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        if self
            .values
            .iter()
            .any(|l| l.soft > l.hard || l.hard == u64::MAX)
        {
            return Err(Status::BadSize);
        }
        #[cfg(target_endian = "little")]
        {
            const {
                assert!(core::mem::size_of::<ResourceLimits>() == 96);
            }
            // SAFETY: repr(C) consists of 12 initialized u64 fields and no padding, in wire byte order.
            w.bytes(unsafe {
                core::slice::from_raw_parts(core::ptr::from_ref(self).cast::<u8>(), 96)
            })
        }
        #[cfg(target_endian = "big")]
        {
            for l in self.values {
                w.u64(l.soft)?;
                w.u64(l.hard)?;
            }
            Ok(())
        }
    }
    pub fn read(r: &mut Reader<'_>) -> Result<Self, Status> {
        let mut values = [Limit { soft: 0, hard: 0 }; LIMITS];
        for l in &mut values {
            *l = Limit {
                soft: r.u64()?,
                hard: r.u64()?,
            };
            if l.soft > l.hard || l.hard == u64::MAX {
                return Err(Status::BadSize);
            }
        }
        Ok(Self { values })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpenditureRoot {
    pub pid: u32,
    pub generation: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sixteen_groups_and_finite_limits_round_trip_and_reject_malformed_bounds() {
        let groups = Groups {
            count: 16,
            ids: [42; 16],
        };
        let mut w = Writer::new();
        groups.write(&mut w).unwrap();
        assert_eq!(Groups::read(&mut Reader::new(w.as_bytes())), Ok(groups));
        assert!(
            !Groups {
                count: 17,
                ..groups
            }
            .valid()
        );
        assert!(!Groups { count: 0, ..groups }.valid());
        let limits = ResourceLimits::initial(3 * 1024 * 1024);
        let mut w = Writer::new();
        limits.write(&mut w).unwrap();
        assert_eq!(
            ResourceLimits::read(&mut Reader::new(w.as_bytes())),
            Ok(limits)
        );
        for limit in [
            Limit { soft: 2, hard: 1 },
            Limit {
                soft: 1,
                hard: u64::MAX,
            },
        ] {
            let mut bad = limits;
            bad.values[AS] = limit;
            assert_eq!(bad.write(&mut Writer::new()), Err(Status::BadSize));
        }
        assert_eq!(limits.values[CORE].hard, 0);
        assert_eq!(limits.values[STACK].hard, 64 * 1024);
        assert_eq!(limits.values[NOFILE].hard, 32);
    }
}
