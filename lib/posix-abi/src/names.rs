// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The operations on names and metadata that start at a path: unlink, mkdir
//! and access to begin with, each as one Change job (`crate::change`). This layer checks what it can without
//! the service (an empty path, the length of a path, the flags, the base of a
//! relative path, the virtual names of the terminal) and sends the rest.
//!
//! A relative path against the current directory goes as the string of that
//! directory, a slash and the raw bytes of the path: the service resolves
//! `..` and the links. A relative path against a descriptor goes with the
//! descriptor and the generation of its description.

use crate::change::{Request, run};
use crate::constants::*;
use core::ffi::c_int;
use posix_change::{Named, Refusal, mode_allows, virtual_refusal};
use posix_fs::{FsError, Target, Transport};
use proto_fs::{Base, ChangeOp, RESULT_MAX};

pub const AT_FDCWD: c_int = -100;
pub const AT_REMOVEDIR: c_int = 0x200;
pub const AT_EACCESS: c_int = 0x200;

const MAX_PATH: usize = proto_fs::MAX_PATH;

/// A path ready for a request: where it starts and its bytes.
struct Placed {
    base: Base,
    bytes: [u8; MAX_PATH + 1],
    length: usize,
    trailing_slash: bool,
}

impl Placed {
    fn path(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
    /// The base for the node information the checks of the layer ask.
    fn start_fd(&self) -> Option<(u32, u64)> {
        match self.base {
            Base::Fd { fd, generation } => Some((fd, generation)),
            _ => None,
        }
    }
}

fn error(error: FsError) -> c_int {
    crate::error(error)
}

/// The base of a path that starts at the descriptor `dirfd`: a descriptor of
/// the file service. EBADF for a number that is closed, ENOTDIR for a
/// descriptor of another service (a pipe, a terminal, the console), which is
/// no directory.
fn descriptor_base(dirfd: c_int) -> Result<Base, c_int> {
    let fd = u32::try_from(dirfd).map_err(|_| EBADF)?;
    crate::shared::with_files(|files| match files.target(fd).map_err(error)? {
        Target::Ram(target) | Target::Random(target) => Ok(Base::Fd {
            fd: target.fd(),
            generation: target.generation(),
        }),
        _ => Err(ENOTDIR),
    })
}

/// A path for a request. An empty path is ENOENT and never reaches the
/// service. An absolute path takes no base; a relative one starts at the
/// current directory (`AT_FDCWD`) or at `dirfd`. A path too long against the
/// current directory is ENAMETOOLONG.
fn place(dirfd: c_int, path: &[u8]) -> Result<Placed, c_int> {
    if path.is_empty() {
        return Err(ENOENT);
    }
    if path.len() > MAX_PATH {
        return Err(ENAMETOOLONG);
    }
    let mut placed = Placed {
        base: Base::Absolute,
        bytes: [0; MAX_PATH + 1],
        length: 0,
        trailing_slash: path.last() == Some(&b'/'),
    };
    if path[0] == b'/' || dirfd == AT_FDCWD {
        placed.length = crate::shared::with_files(|files| {
            let resolved = files.resolve(path).map_err(error)?;
            let bytes = resolved.as_bytes();
            placed.bytes[..bytes.len()].copy_from_slice(bytes);
            Ok(bytes.len())
        })?;
        return Ok(placed);
    }
    placed.base = descriptor_base(dirfd)?;
    placed.bytes[..path.len()].copy_from_slice(path);
    placed.length = path.len();
    Ok(placed)
}

/// Whether the path names a virtual node of the terminal service. A path
/// with a slash in the end makes the answer ENOTDIR when `directory_error`.
fn virtual_leaf(
    transport: Transport,
    placed: &Placed,
    directory_error: bool,
) -> Result<Option<(u32, u32)>, c_int> {
    transport
        .terminal_leaf(
            placed.start_fd(),
            placed.path(),
            directory_error && placed.trailing_slash,
        )
        .map_err(error)
}

/// The errno of a refusal of the layer.
fn refused(refusal: Refusal) -> c_int {
    match refusal {
        Refusal::Exists => EEXIST,
        Refusal::Busy => EBUSY,
        Refusal::CrossDevice => EXDEV,
        Refusal::ReadOnly => EROFS,
        // The caller checks the metadata; no refusal of its own.
        Refusal::ByMetadata => EACCES,
    }
}

/// Checks the virtual names of the paths against the table of the layer
/// before any request. `first` and `second` are the placed paths.
fn check_virtual(
    op: Named,
    first: &Placed,
    second: Option<&Placed>,
    directory_error: bool,
) -> Result<(), c_int> {
    let transport = crate::shared::with_files(|files| Ok(files.transport()))?;
    let one = virtual_leaf(transport, first, directory_error)?.is_some();
    let two = match second {
        Some(second) => virtual_leaf(transport, second, false)?.is_some(),
        None => false,
    };
    match virtual_refusal(op, one, two) {
        Some(Refusal::ByMetadata) | None => Ok(()),
        Some(refusal) => Err(refused(refusal)),
    }
}

fn request<'a>(op: ChangeOp, placed: &'a Placed) -> Request<'a> {
    Request {
        op,
        flags: 0,
        base: placed.base,
        args: [0; 4],
        path: placed.path(),
        second: None,
    }
}

fn run_unit(request: &Request<'_>) -> Result<(), c_int> {
    run(request, &mut [0; RESULT_MAX]).map(|_| ())
}

/// unlink and rmdir: `flags` is 0 or AT_REMOVEDIR.
pub fn unlinkat(dirfd: c_int, path: &[u8], flags: c_int) -> Result<(), c_int> {
    if flags & !AT_REMOVEDIR != 0 {
        return Err(EINVAL);
    }
    let placed = place(dirfd, path)?;
    let remove_directory = flags & AT_REMOVEDIR != 0;
    check_virtual(
        if remove_directory {
            Named::Rmdir
        } else {
            Named::Unlink
        },
        &placed,
        None,
        true,
    )?;
    let mut unlink = request(ChangeOp::Unlink, &placed);
    unlink.flags = if remove_directory {
        proto_fs::UNLINK_REMOVEDIR
    } else {
        0
    };
    run_unit(&unlink)
}

/// mkdir: the mode with the creation mask of the process.
pub fn mkdirat(dirfd: c_int, path: &[u8], mode: u32, umask: u32) -> Result<(), c_int> {
    let placed = place(dirfd, path)?;
    // A name of the terminal exists even with a slash after it.
    check_virtual(Named::Mkdir, &placed, None, false)?;
    let mut mkdir = request(ChangeOp::Mkdir, &placed);
    mkdir.args = [u64::from(mode & 0o7777), u64::from(umask & 0o777), 0, 0];
    run_unit(&mkdir)
}

/// access and faccessat: the real IDs, the effective with AT_EACCESS.
pub fn faccessat(dirfd: c_int, path: &[u8], mode: c_int, flags: c_int) -> Result<(), c_int> {
    if flags & !AT_EACCESS != 0 || !(0..=7).contains(&mode) {
        return Err(EINVAL);
    }
    let placed = place(dirfd, path)?;
    let effective = flags & AT_EACCESS != 0;
    let transport = crate::shared::with_files(|files| Ok(files.transport()))?;
    if let Some((kind, number)) = virtual_leaf(transport, &placed, true)? {
        // A name the terminal service keeps: the answer is its metadata.
        let info = transport
            .terminal_leaf_information(kind, number)
            .map_err(error)?;
        let (uid, gid) = if effective {
            (crate::process::geteuid(), crate::process::getegid())
        } else {
            (crate::process::getuid(), crate::process::getgid())
        };
        return if mode_allows(
            info.permissions,
            info.kind == 1,
            info.uid,
            info.gid,
            uid,
            gid,
            mode as u32,
        ) {
            Ok(())
        } else {
            Err(EACCES)
        };
    }
    let mut access = request(ChangeOp::Access, &placed);
    access.flags = if effective {
        proto_fs::ACCESS_EFFECTIVE
    } else {
        0
    };
    access.args = [mode as u64, 0, 0, 0];
    run_unit(&access)
}
