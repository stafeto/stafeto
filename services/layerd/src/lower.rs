// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The lower set through the RAM file service: the session of the service with the boot profile
//! (init gives it to the clients of `BOOT_PROFILE_CLIENTS`), spoken through `PosixFs` as the host
//! key service does. A directory is read with READ_DIR_FD and kept open between the requests of
//! a listing.

use layerd::volume::{Lower, R};
use posix_fs::{Directory, FileKind, FsError, PosixFs};
use proto_fs::NodeInfo;
use proto_wire::Status;

pub struct Ram {
    pub files: &'static mut PosixFs,
}

fn status(e: FsError) -> Status {
    Status::Unknown(match e {
        FsError::NoEntry => proto_fs::NO_ENTRY,
        FsError::NotDirectory => proto_fs::NOT_DIRECTORY,
        FsError::PermissionDenied | FsError::OperationNotPermitted => proto_fs::ACCESS_DENIED,
        FsError::NameTooLong => proto_fs::NAME_TOO_LONG,
        FsError::Loop => proto_fs::LOOP,
        FsError::TooManyOpenFiles => proto_fs::TOO_MANY_OPEN_FILES,
        FsError::TooManyInSystem => proto_fs::TOO_MANY_FILES_IN_SYSTEM,
        FsError::IsDirectory => proto_fs::IS_DIRECTORY,
        _ => proto_fs::INVALID_ARGUMENT,
    })
}

fn kind(k: FileKind) -> u32 {
    match k {
        FileKind::Directory => 1,
        FileKind::Regular => 2,
        FileKind::Character => 3,
        FileKind::Fifo => 4,
        FileKind::Symlink => 5,
        FileKind::Socket => 6,
    }
}

impl Lower for Ram {
    type Dir = Directory;

    /// A link at the end of the path is followed in every case: the session of the RAM file
    /// service answers the node the link names.
    fn stat(&mut self, path: &[u8], _no_follow: bool) -> R<NodeInfo> {
        self.files.stat_information(path).map_err(status)
    }

    fn open_dir(&mut self, path: &[u8]) -> R<Directory> {
        match self.files.opendir(path) {
            Ok(d) => Ok(d),
            // The pages of the table of descriptors are all given at the start.
            Err(FsError::NeedPage(_)) => Err(Status::Unknown(proto_fs::NO_SPACE)),
            Err(e) => Err(status(e)),
        }
    }

    fn next(&mut self, dir: &mut Directory, name: &mut [u8; 256]) -> R<Option<(u64, u32, usize)>> {
        match self.files.readdir(dir, &mut name[..]) {
            Ok(Some(e)) => Ok(Some((e.inode, kind(e.kind), e.name_len))),
            Ok(None) => Ok(None),
            Err(e) => Err(status(e)),
        }
    }

    fn close_dir(&mut self, dir: Directory) {
        let _ = self.files.closedir(&dir);
    }

    fn readlink(&mut self, _path: &[u8], _out: &mut [u8]) -> R<usize> {
        Err(Status::Unknown(proto_fs::INVALID_ARGUMENT))
    }
}
