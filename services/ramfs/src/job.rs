// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The paid jobs of the service: one table of 128 places shared by the
//! path jobs of Resolve and Open, the data jobs and the change jobs.

use crate::authority::Stamp;
use crate::change::{ChangeJob, SECONDS};
use crate::data;
use crate::open::Journal as OpenJournal;
use crate::resolve::Resolve;
use crate::storage::PREPARATIONS;

pub struct ResolveJob {
    pub id: u64,
    pub owner: u64,
    pub root: u16,
    pub real: bool,
    pub authority: Option<Stamp>,
    pub operation: JobOperation,
    pub open_key: Option<proto_fs::OpenKey>,
    pub raw_base: (u32, u64),
    pub abandoned: bool,
}
pub struct PathJob {
    pub resolver: Resolve,
    pub second: Option<Resolve>,
    pub open: Option<OpenJournal>,
}
#[allow(clippy::large_enum_variant)]
pub enum JobOperation {
    Path(PathJob),
    Data(data::Journal),
    Change(ChangeJob),
}
impl ResolveJob {
    pub fn path(&self) -> &PathJob {
        match &self.operation {
            JobOperation::Path(path) => path,
            _ => panic!("validated path job"),
        }
    }
    pub fn path_mut(&mut self) -> &mut PathJob {
        match &mut self.operation {
            JobOperation::Path(path) => path,
            _ => panic!("validated path job"),
        }
    }
}

/// The table of jobs and the generation of each place.
pub type JobTable = [Option<ResolveJob>; PREPARATIONS];
pub type JobGenerations = [u64; PREPARATIONS];
/// The second paths of the change jobs that have one (rename, link) and the
/// contents of the links that symlink makes. A job reserves its place when
/// it starts, so that a full side table is JOBS_FULL before any effect; the
/// resolver itself comes with the Second.
pub struct Seconds {
    pub slots: [Option<Resolve>; SECONDS],
    reserved: u32,
}
impl Seconds {
    pub const fn new() -> Self {
        Self {
            slots: [const { None }; SECONDS],
            reserved: 0,
        }
    }
    pub fn reserve(&mut self) -> Option<usize> {
        let place = (!self.reserved).trailing_zeros() as usize;
        if place >= SECONDS {
            return None;
        }
        self.reserved |= 1 << place;
        Some(place)
    }
    pub fn free(&mut self, place: usize) {
        self.reserved &= !(1 << place);
    }
    pub fn is_clear(&self) -> bool {
        self.reserved == 0 && self.slots.iter().all(Option::is_none)
    }
}
impl Default for Seconds {
    fn default() -> Self {
        Self::new()
    }
}
const _: () = assert!(SECONDS == 32);
