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
/// contents of the links that symlink makes.
pub type Seconds = [Option<Resolve>; SECONDS];
