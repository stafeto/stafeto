// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The operations on names and metadata that start at a path: unlink, mkdir,
//! rename, link, symlink, readlink, chmod, chown, access and utimens, each as
//! one Change job (`crate::change`). This layer checks what it can without
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
pub const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
pub const AT_REMOVEDIR: c_int = 0x200;
pub const AT_EACCESS: c_int = 0x200;
pub const AT_SYMLINK_FOLLOW: c_int = 0x400;
pub const AT_EMPTY_PATH: c_int = 0x1000;
/// The values of tv_nsec that stand for "now" and "leave it".
pub const UTIME_NOW: i64 = proto_fs::TIME_NOW as i64;
pub const UTIME_OMIT: i64 = proto_fs::TIME_OMIT as i64;

pub const MAX_PATH: usize = proto_fs::MAX_PATH;

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
pub(crate) fn descriptor_base(dirfd: c_int) -> Result<Base, c_int> {
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

/// rename: `renameat2` without flags.
pub fn renameat(old_dirfd: c_int, old: &[u8], new_dirfd: c_int, new: &[u8]) -> Result<(), c_int> {
    let first = place(old_dirfd, old)?;
    let second = place(new_dirfd, new)?;
    check_virtual(Named::Rename, &first, Some(&second), true)?;
    let mut rename = request(ChangeOp::Rename, &first);
    rename.second = Some((second.base, second.path()));
    run_unit(&rename)
}

/// link and linkat: the new name is a link to the old name itself unless
/// AT_SYMLINK_FOLLOW says to follow a symbolic link at the old name.
pub fn linkat(
    old_dirfd: c_int,
    old: &[u8],
    new_dirfd: c_int,
    new: &[u8],
    flags: c_int,
) -> Result<(), c_int> {
    if flags & !AT_SYMLINK_FOLLOW != 0 {
        return Err(EINVAL);
    }
    let first = place(old_dirfd, old)?;
    let second = place(new_dirfd, new)?;
    check_virtual(Named::Link, &first, Some(&second), true)?;
    let mut link = request(ChangeOp::Link, &first);
    link.flags = if flags & AT_SYMLINK_FOLLOW != 0 {
        proto_fs::LINK_FOLLOW
    } else {
        0
    };
    link.second = Some((second.base, second.path()));
    run_unit(&link)
}

/// symlink: `target` is stored as it is, up to 511 bytes, empty too.
pub fn symlinkat(target: &[u8], new_dirfd: c_int, linkpath: &[u8]) -> Result<(), c_int> {
    if target.len() > MAX_PATH {
        return Err(ENAMETOOLONG);
    }
    let placed = place(new_dirfd, linkpath)?;
    check_virtual(Named::Symlink, &placed, None, false)?;
    let mut symlink = request(ChangeOp::Symlink, &placed);
    symlink.second = Some((Base::Absolute, target));
    run_unit(&symlink)
}

/// readlink: the contents of the link, cut to the size of `out`, without a
/// NUL. EINVAL for a buffer of no bytes and for a node that is no link.
pub fn readlinkat(dirfd: c_int, path: &[u8], out: &mut [u8]) -> Result<usize, c_int> {
    if out.is_empty() {
        return Err(EINVAL);
    }
    let placed = place(dirfd, path)?;
    let mut read = request(ChangeOp::ReadLink, &placed);
    read.args = [out.len().min(RESULT_MAX) as u64, 0, 0, 0];
    let mut buffer = [0; RESULT_MAX];
    let outcome = run(&read, &mut buffer)?;
    let length = outcome.length.min(out.len());
    out[..length].copy_from_slice(&buffer[..length]);
    Ok(length)
}

/// What a metadata call names: a path, or with AT_EMPTY_PATH the object of a
/// descriptor. A descriptor of another service answers here: a pipe has no
/// such metadata (EINVAL), the terminal keeps its own (EROFS).
fn metadata_target(dirfd: c_int, path: &[u8], at_flags: c_int) -> Result<(Placed, bool), c_int> {
    if at_flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(EINVAL);
    }
    if !path.is_empty() {
        return Ok((place(dirfd, path)?, false));
    }
    if at_flags & AT_EMPTY_PATH == 0 {
        return Err(ENOENT);
    }
    let mut placed = Placed {
        base: Base::Absolute,
        bytes: [0; MAX_PATH + 1],
        length: 0,
        trailing_slash: false,
    };
    if dirfd == AT_FDCWD {
        // The current directory itself.
        placed.length = crate::shared::with_files(|files| {
            let cwd = files.cwd();
            placed.bytes[..cwd.len()].copy_from_slice(cwd);
            Ok(cwd.len())
        })?;
        return Ok((placed, true));
    }
    let fd = u32::try_from(dirfd).map_err(|_| EBADF)?;
    let target = crate::shared::with_files(|files| files.target(fd).map_err(error))?;
    match target {
        Target::Ram(target) | Target::Random(target) => {
            placed.base = Base::Fd {
                fd: target.fd(),
                generation: target.generation(),
            };
        }
        Target::Pipe(_) => return Err(EINVAL),
        _ => return Err(EROFS),
    }
    Ok((placed, true))
}

fn metadata(
    op: ChangeOp,
    named: Named,
    dirfd: c_int,
    path: &[u8],
    at_flags: c_int,
    args: [u64; 4],
) -> Result<(), c_int> {
    let (placed, itself) = metadata_target(dirfd, path, at_flags)?;
    if !itself {
        check_virtual(named, &placed, None, true)?;
    }
    let mut change = request(op, &placed);
    change.flags = if at_flags & AT_SYMLINK_NOFOLLOW != 0 {
        proto_fs::NOFOLLOW
    } else {
        0
    };
    change.args = args;
    run_unit(&change)
}

/// chmod, fchmod (AT_EMPTY_PATH) and fchmodat.
pub fn fchmodat(dirfd: c_int, path: &[u8], mode: u32, flags: c_int) -> Result<(), c_int> {
    metadata(
        ChangeOp::Chmod,
        Named::Chmod,
        dirfd,
        path,
        flags,
        [u64::from(mode & 0o7777), 0, 0, 0],
    )
}

/// chown, lchown, fchown and fchownat: an ID of `u32::MAX` keeps the field.
pub fn fchownat(dirfd: c_int, path: &[u8], uid: u32, gid: u32, flags: c_int) -> Result<(), c_int> {
    metadata(
        ChangeOp::Chown,
        Named::Chown,
        dirfd,
        path,
        flags,
        [u64::from(uid), u64::from(gid), 0, 0],
    )
}

/// One time of utimensat: the seconds and the nanoseconds or a mark.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Time {
    pub seconds: i64,
    pub nanos: i64,
}

fn time_args(time: Time) -> Result<(u64, u64), c_int> {
    match time.nanos {
        UTIME_NOW | UTIME_OMIT => Ok((0, time.nanos as u64)),
        0..=999_999_999 => Ok((time.seconds as u64, time.nanos as u64)),
        _ => Err(EINVAL),
    }
}

/// utimensat and futimens (AT_EMPTY_PATH): no times is now for both.
pub fn utimensat(
    dirfd: c_int,
    path: &[u8],
    times: Option<[Time; 2]>,
    flags: c_int,
) -> Result<(), c_int> {
    let now = Time {
        seconds: 0,
        nanos: UTIME_NOW,
    };
    let [access, modify] = times.unwrap_or([now, now]);
    let (access_seconds, access_nanos) = time_args(access)?;
    let (modify_seconds, modify_nanos) = time_args(modify)?;
    metadata(
        ChangeOp::Times,
        Named::Times,
        dirfd,
        path,
        flags,
        [access_seconds, access_nanos, modify_seconds, modify_nanos],
    )
}

/// fstatat: the node information of a path, or with no path (or an empty
/// one and AT_EMPTY_PATH) of the descriptor itself. The last link is not
/// followed with AT_SYMLINK_NOFOLLOW, unless the path ends with a slash, which
/// names the directory the link leads to. Other flags are EINVAL, an empty
/// path without AT_EMPTY_PATH is ENOENT, a relative path against a descriptor
/// of another service is ENOTDIR.
pub fn fstatat(
    dirfd: c_int,
    path: Option<&[u8]>,
    flags: c_int,
) -> Result<proto_fs::NodeInfo, c_int> {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(EINVAL);
    }
    let nonempty = path.filter(|path| !path.is_empty());
    if let Some(path) = nonempty {
        let placed = place(dirfd, path)?;
        let transport = crate::shared::with_files(|files| Ok(files.transport()))?;
        if let Some((kind, number)) = transport
            .terminal_leaf(placed.start_fd(), placed.path(), placed.trailing_slash)
            .map_err(error)?
        {
            return transport
                .terminal_leaf_information(kind, number)
                .map_err(error);
        }
        let follow = flags & AT_SYMLINK_NOFOLLOW == 0 || placed.trailing_slash;
        let info = transport
            .files()
            .node_information_from(placed.start_fd(), placed.path(), follow)
            .map_err(|status| error(FsError::from(status)))?;
        if placed.trailing_slash && info.kind != 1 {
            return Err(ENOTDIR);
        }
        return Ok(info);
    }
    if path.is_some() && flags & AT_EMPTY_PATH == 0 {
        return Err(ENOENT);
    }
    if dirfd == AT_FDCWD {
        // The current directory itself.
        return fstatat(dirfd, Some(b"."), flags & !AT_EMPTY_PATH);
    }
    let fd = u32::try_from(dirfd).map_err(|_| EBADF)?;
    crate::shared::held(fd, |transport, target| {
        transport.descriptor_information(target).map_err(error)
    })
}

/// The canonical path of the directory `path` names, against the current
/// directory: the service resolves the links, `.` and `..`, and checks that
/// the caller may search it. The path of a name of the terminal is ENOTDIR.
pub fn directory_path(path: &[u8], out: &mut [u8; MAX_PATH + 1]) -> Result<usize, c_int> {
    let placed = place(AT_FDCWD, path)?;
    let transport = crate::shared::with_files(|files| Ok(files.transport()))?;
    if virtual_leaf(transport, &placed, false)?.is_some() {
        return Err(ENOTDIR);
    }
    path_query(
        &placed,
        proto_fs::PATH_REQUIRE_DIR | proto_fs::PATH_FOLLOW_LAST,
        out,
    )
}

/// The canonical path of the object of `target` (a directory of the file
/// service), or the errno: ENOTDIR for any other descriptor, EACCES without
/// the right to search the directory. The service names it by its path from
/// the root, without links, `.` and `..`.
pub fn descriptor_path(target: Target, out: &mut [u8; MAX_PATH + 1]) -> Result<usize, c_int> {
    let base = match target {
        Target::Ram(target) | Target::Random(target) => Base::Fd {
            fd: target.fd(),
            generation: target.generation(),
        },
        _ => return Err(ENOTDIR),
    };
    let placed = Placed {
        base,
        bytes: [0; MAX_PATH + 1],
        length: 0,
        trailing_slash: false,
    };
    path_query(
        &placed,
        proto_fs::PATH_REQUIRE_DIR | proto_fs::PATH_FOLLOW_LAST,
        out,
    )
}

fn path_query(placed: &Placed, flags: u32, out: &mut [u8; MAX_PATH + 1]) -> Result<usize, c_int> {
    let mut query = request(ChangeOp::Path, placed);
    query.flags = flags;
    let mut buffer = [0; RESULT_MAX];
    let outcome = run(&query, &mut buffer)?;
    if outcome.length == 0 || outcome.length > MAX_PATH {
        return Err(EIO);
    }
    out[..outcome.length].copy_from_slice(&buffer[..outcome.length]);
    Ok(outcome.length)
}

/// fchdir: the current directory becomes the directory `fd` names.
pub fn fchdir(fd: c_int) -> Result<(), c_int> {
    let fd = u32::try_from(fd).map_err(|_| EBADF)?;
    crate::shared::held(fd, |_, target| {
        let mut canonical = [0; MAX_PATH + 1];
        let length = descriptor_path(target, &mut canonical)?;
        crate::shared::with_files(|files| files.set_cwd(&canonical[..length]).map_err(error))
    })
}

/// realpath: the canonical path of `path` against the current directory,
/// the last link followed, `.` and `..` gone: its length, and the bytes in
/// `out`. ENOENT for an empty path and for a name that does not exist,
/// ENOTDIR for a part that is no directory, ELOOP, EACCES. A name of the
/// terminal service is its directory's path and its name.
pub fn realpath(path: &[u8], out: &mut [u8; MAX_PATH + 1]) -> Result<usize, c_int> {
    let placed = place(AT_FDCWD, path)?;
    let transport = crate::shared::with_files(|files| Ok(files.transport()))?;
    if virtual_leaf(transport, &placed, false)?.is_none() {
        return path_query(&placed, proto_fs::PATH_FOLLOW_LAST, out);
    }
    let bytes = placed.path();
    let end = bytes
        .iter()
        .rposition(|&byte| byte != b'/')
        .map_or(0, |last| last + 1);
    let split = bytes[..end]
        .iter()
        .rposition(|&byte| byte == b'/')
        .unwrap_or(0);
    let leaf = &bytes[split + 1..end];
    let directory = Placed {
        base: Base::Absolute,
        bytes: {
            let mut copy = [0; MAX_PATH + 1];
            let head = &bytes[..split.max(1)];
            copy[..head.len()].copy_from_slice(head);
            copy
        },
        length: split.max(1),
        trailing_slash: false,
    };
    let length = path_query(
        &directory,
        proto_fs::PATH_REQUIRE_DIR | proto_fs::PATH_FOLLOW_LAST,
        out,
    )?;
    let slash = usize::from(out[length - 1] != b'/');
    if length + slash + leaf.len() > MAX_PATH {
        return Err(ENAMETOOLONG);
    }
    if slash == 1 {
        out[length] = b'/';
    }
    out[length + slash..length + slash + leaf.len()].copy_from_slice(leaf);
    Ok(length + slash + leaf.len())
}

/// The fields of statvfs in the order of relibc's struct: f_bsize, f_frsize,
/// f_blocks, f_bfree, f_bavail, f_files, f_ffree, f_favail, f_fsid, f_flag,
/// f_namemax.
pub type Statvfs = [u64; 11];

/// What a descriptor or a name of another service reports: no blocks, no
/// files, names of 255 bytes.
const NO_FILESYSTEM: Statvfs = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255];

fn statvfs_words(request: &Request<'_>) -> Result<Statvfs, c_int> {
    let mut buffer = [0; RESULT_MAX];
    let outcome = run(request, &mut buffer)?;
    if outcome.length != proto_fs::STATVFS_BYTES {
        return Err(EIO);
    }
    let mut words = [0; 11];
    for (i, word) in words.iter_mut().enumerate() {
        let bytes: [u8; 8] = buffer[i * 8..i * 8 + 8].try_into().map_err(|_| EIO)?;
        *word = u64::from_le_bytes(bytes);
    }
    Ok(words)
}

/// statvfs: the file system of `path`. The right to search the directories
/// above it is all it needs: a file of mode 0 answers.
pub fn statvfs(path: &[u8]) -> Result<Statvfs, c_int> {
    let placed = place(AT_FDCWD, path)?;
    let transport = crate::shared::with_files(|files| Ok(files.transport()))?;
    if virtual_leaf(transport, &placed, true)?.is_some() {
        return Ok(NO_FILESYSTEM);
    }
    statvfs_words(&request(ChangeOp::StatVfs, &placed))
}

/// fstatvfs: the file system of the file `fd` names.
pub fn fstatvfs(fd: c_int) -> Result<Statvfs, c_int> {
    let fd = u32::try_from(fd).map_err(|_| EBADF)?;
    let target = crate::shared::with_files(|files| files.target(fd).map_err(error))?;
    let base = match target {
        Target::Ram(target) | Target::Random(target) => Base::Fd {
            fd: target.fd(),
            generation: target.generation(),
        },
        _ => return Ok(NO_FILESYSTEM),
    };
    let placed = Placed {
        base,
        bytes: [0; MAX_PATH + 1],
        length: 0,
        trailing_slash: false,
    };
    statvfs_words(&request(ChangeOp::StatVfs, &placed))
}
