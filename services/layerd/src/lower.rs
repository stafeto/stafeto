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
use rt::fs::Files;

pub struct Ram {
    pub files: Files,
}

/// A directory of the lower set: the descriptor of the RAM file service.
pub struct Dir {
    fd: u32,
}

impl Lower for Ram {
    type Dir = Dir;

    fn open_dir(&mut self, path: &[u8]) -> R<Dir> {
        let flags = proto_fs::READ_ONLY | proto_fs::DIRECTORY_ONLY;
        self.files
            .open_marked_bytes(path, flags)
            .map(|(fd, _)| Dir { fd })
    }

    fn next(&mut self, dir: &mut Dir, name: &mut [u8; 256]) -> R<Option<(u64, u32, usize)>> {
        Ok(self
            .files
            .read_dir_fd(dir.fd, &mut name[..])?
            .map(|(len, kind, inode)| (inode, kind, len)))
    }

    fn close_dir(&mut self, dir: Dir) {
        let _ = self.files.close(dir.fd);
    }

    fn readlink(&mut self, _path: &[u8], _out: &mut [u8]) -> R<usize> {
        Err(proto_wire::Status::Unknown(proto_fs::INVALID_ARGUMENT))
    }

    fn stat(&mut self, path: &[u8], follow: bool) -> R<LowerStat> {
        let info = self.files.node_information_from(None, path, follow)?;
        Ok(LowerStat {
            kind: info.kind,
            mode: info.permissions,
            uid: info.uid,
            gid: info.gid,
            ino: info.inode,
        })
    }
}
