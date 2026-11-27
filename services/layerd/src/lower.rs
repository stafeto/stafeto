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
use proto_fs::{Base, ChangeOp, ChangeStart, OpenKey, RESULT_MAX};
use proto_wire::Status;
use rt::fs::{Files, PathJob};

pub struct Ram {
    pub files: Files,
    /// The generation of the next read of a link (the job key of the service, slot 0).
    link_generation: u64,
}

impl Ram {
    pub const fn new(files: Files) -> Ram {
        Ram {
            files,
            link_generation: 0,
        }
    }
}

/// Where a read of a link stands: started, answered (the text is kept), or the job released.
enum LinkState {
    Stepping,
    Releasing,
}

/// A read of a link in flight: the job of the Change family of the RAM file service (ReadLink)
/// under the key `key`.
pub struct Link {
    key: OpenKey,
    state: LinkState,
    /// The text, once the job has answered.
    text: [u8; 512],
    len: usize,
    /// An error to give once the job is released.
    failed: Option<Status>,
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
    type Link = Link;

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

    fn readlink_start(&mut self, path: &[u8]) -> R<Link> {
        self.link_generation += 1;
        let key = OpenKey {
            slot: 0,
            generation: self.link_generation,
        };
        let start = ChangeStart {
            key,
            op: ChangeOp::ReadLink,
            flags: 0,
            base: Base::Absolute,
            args: [511, 0, 0, 0],
            path,
        };
        // No place for a job (or the key is taken) is a start made again in the next step, the
        // answer a session with no path job free gets.
        match self.files.change_start_once(&start) {
            Ok(_) => {}
            Err(Status::Unknown(proto_fs::JOBS_FULL)) => {
                return Err(Status::Unknown(proto_fs::TOO_MANY_OPEN_FILES));
            }
            Err(e) => return Err(e),
        }
        Ok(Link {
            key,
            state: LinkState::Stepping,
            text: [0; 512],
            len: 0,
            failed: None,
        })
    }

    fn readlink_poll(&mut self, link: &mut Link, out: &mut [u8; 512]) -> R<Option<usize>> {
        match &mut link.state {
            LinkState::Stepping => {
                let mut bytes = [0u8; RESULT_MAX];
                match self.files.change_step_once(link.key, &mut bytes) {
                    Ok(None) => Ok(None),
                    Ok(Some(done)) => {
                        let len = done.length.min(RESULT_MAX).min(link.text.len());
                        link.text[..len].copy_from_slice(&bytes[..len]);
                        link.len = len;
                        if done.result != 0 {
                            link.failed = Some(Status::from_code(done.result));
                        }
                        link.state = LinkState::Releasing;
                        Ok(None)
                    }
                    Err(Status::Unknown(proto_fs::RESOLVING | proto_fs::JOBS_FULL)) => Ok(None),
                    Err(e) => {
                        let _ = self.files.change_release_once(link.key);
                        Err(e)
                    }
                }
            }
            LinkState::Releasing => {
                // Release answers 0 for any key; a failed one is asked again in the next step.
                if self.files.change_release_once(link.key).is_err() {
                    return Ok(None);
                }
                if let Some(e) = link.failed.take() {
                    return Err(e);
                }
                out[..link.len].copy_from_slice(&link.text[..link.len]);
                Ok(Some(link.len))
            }
        }
    }

    fn readlink_cancel(&mut self, link: Link) {
        let _ = self.files.change_release_once(link.key);
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
            atime: ns_of(info.access_time),
            mtime: ns_of(info.modify_time),
        }))
    }

    fn stat_cancel(&mut self, mut probe: Resolve) {
        self.cancel(&mut probe);
    }
}

/// A time of the RAM file service in the words of `proto_data::TimeSpec`: nanoseconds, clamped
/// so that no time is one of the two sentinels.
fn ns_of(t: proto_fs::Timestamp) -> i64 {
    let ns = t.value().unwrap_or(0);
    ns.clamp(i128::from(i64::MIN) + 2, i128::from(i64::MAX)) as i64
}
