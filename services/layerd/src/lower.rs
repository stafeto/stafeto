// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The lower set through the RAM file service: the session of the service with the boot profile
//! (init gives it to the clients of `BOOT_PROFILE_CLIENTS`), spoken through `rt::fs::Files` as
//! the host key service does. A directory is opened with one OPEN of its path and read with
//! READ_DIR_FD, and stays open between the requests of a listing. The calls are single round
//! trips of the boot profile, so that no step of the loop holds the several phases of an open
//! of the general file layer (`posix_fs::PosixFs::opendir` is three of them, and its open alone
//! costs more than the bound of a step).

use layerd::volume::{Lower, LowerStat, R};
use proto_wire::Status;
use rt::fs::{Files, PathJob};

pub struct Ram {
    pub files: Files,
}

/// What a resolve of the RAM file service is for: its finishing call.
#[derive(Clone, Copy)]
enum Goal {
    Stat,
    Open(u32),
}

/// A path in flight: the job of the service and its finishing call. None once the service
/// released the job.
pub struct Resolve {
    job: Option<PathJob>,
    goal: Goal,
}

/// A directory of the lower set: the resolve of its open, then the descriptor of the RAM file
/// service.
pub enum Dir {
    Opening(Resolve),
    Open(u32),
}

impl Ram {
    fn cancel(&mut self, r: &mut Resolve) {
        if let Some(job) = r.job.take() {
            self.files.path_cancel(job);
        }
    }
}

impl Lower for Ram {
    type Dir = Dir;
    type Probe = Resolve;

    fn open_dir_start(&mut self, path: &[u8]) -> R<Dir> {
        let flags = proto_fs::READ_ONLY | proto_fs::DIRECTORY_ONLY;
        Ok(Dir::Opening(Resolve {
            job: Some(self.files.path_start(None, path, true)?),
            goal: Goal::Open(flags),
        }))
    }

    fn open_dir_poll(&mut self, dir: &mut Dir) -> R<bool> {
        let Dir::Opening(Resolve {
            job: Some(job),
            goal: Goal::Open(flags),
        }) = dir
        else {
            return Ok(true);
        };
        match self.files.path_open_poll(job, *flags)? {
            Some((fd, _)) => {
                *dir = Dir::Open(fd);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn next(&mut self, dir: &mut Dir, name: &mut [u8; 256]) -> R<Option<(u64, u32, usize)>> {
        let Dir::Open(fd) = dir else {
            return Err(Status::Unknown(proto_fs::BAD_FD));
        };
        Ok(self
            .files
            .read_dir_fd(*fd, &mut name[..])?
            .map(|(len, kind, inode)| (inode, kind, len)))
    }

    fn close_dir(&mut self, dir: Dir) {
        match dir {
            Dir::Open(fd) => {
                let _ = self.files.close(fd);
            }
            Dir::Opening(mut resolve) => self.cancel(&mut resolve),
        }
    }

    fn readlink(&mut self, _path: &[u8], _out: &mut [u8]) -> R<usize> {
        Err(proto_wire::Status::Unknown(proto_fs::INVALID_ARGUMENT))
    }

    fn stat_start(&mut self, path: &[u8], follow: bool) -> R<Resolve> {
        Ok(Resolve {
            job: Some(self.files.path_start(None, path, follow)?),
            goal: Goal::Stat,
        })
    }

    fn stat_poll(&mut self, probe: &mut Resolve) -> R<Option<LowerStat>> {
        let Some(job) = probe.job.as_mut() else {
            return Err(Status::Unknown(proto_fs::STALE_PROOF));
        };
        Ok(self.files.path_stat_poll(job)?.map(|info| LowerStat {
            kind: info.kind,
            mode: info.permissions,
            uid: info.uid,
            gid: info.gid,
            ino: info.inode,
        }))
    }

    fn stat_cancel(&mut self, mut probe: Resolve) {
        self.cancel(&mut probe);
    }
}
