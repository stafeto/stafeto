// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The operations on names and metadata through the bridges `stafeto_*` of the
//! layer, which relibc's platform calls. Every function answers with an effect
//! that is looked at afterwards (the node information of the path, besides the
//! return value), and every refusal leaves the tree as it was.
use core::ffi::{c_char, c_int};
use proto_fs::NodeInfo;
use proto_wire::Status;

unsafe extern "C" {
    fn stafeto_unlinkat(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int;
    fn stafeto_mkdirat(dirfd: c_int, path: *const c_char, mode: u32) -> c_int;
    fn stafeto_faccessat(dirfd: c_int, path: *const c_char, mode: c_int, flags: c_int) -> c_int;
    fn stafeto_openat(dirfd: c_int, path: *const c_char, flags: c_int, mode: u32) -> c_int;
    fn stafeto_close(fd: c_int) -> c_int;
    fn stafeto_renameat(
        old_dirfd: c_int,
        old: *const c_char,
        new_dirfd: c_int,
        new: *const c_char,
    ) -> c_int;
    fn stafeto_linkat(
        old_dirfd: c_int,
        old: *const c_char,
        new_dirfd: c_int,
        new: *const c_char,
        flags: c_int,
    ) -> c_int;
    fn stafeto_symlinkat(target: *const c_char, dirfd: c_int, linkpath: *const c_char) -> c_int;
    fn stafeto_readlinkat(dirfd: c_int, path: *const c_char, buf: *mut u8, len: usize) -> isize;
    fn stafeto_fchmodat(dirfd: c_int, path: *const c_char, mode: u32, flags: c_int) -> c_int;
    fn stafeto_fchownat(
        dirfd: c_int,
        path: *const c_char,
        uid: u32,
        gid: u32,
        flags: c_int,
    ) -> c_int;
    fn stafeto_utimensat(
        dirfd: c_int,
        path: *const c_char,
        times: *const [i64; 4],
        flags: c_int,
    ) -> c_int;
    fn stafeto_pipe2(fds: *mut c_int, flags: c_int) -> c_int;
    fn stafeto_chdir(path: *const c_char) -> c_int;
    fn stafeto_getcwd(buf: *mut u8, len: usize) -> c_int;
    fn stafeto_fstatat(
        dirfd: c_int,
        path: *const c_char,
        out: *mut [u64; 16],
        flags: c_int,
    ) -> c_int;
}

const AT_FDCWD: c_int = -100;
const AT_REMOVEDIR: c_int = 0x200;
const O_RDONLY: c_int = 0;
const O_DIRECTORY: c_int = 0o40000;
const EBADF: c_int = 9;
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
const AT_SYMLINK_FOLLOW: c_int = 0x400;
const AT_EMPTY_PATH: c_int = 0x1000;
const UTIME_NOW: i64 = (1 << 30) - 1;
const UTIME_OMIT: i64 = (1 << 30) - 2;
const EISDIR: c_int = 21;
const EROFS: c_int = 30;
const EOPNOTSUPP: c_int = 95;
const AT_EACCESS: c_int = 0x200;
const EPERM: c_int = 1;
const ENOENT: c_int = 2;
const EACCES: c_int = 13;
const EEXIST: c_int = 17;
const ENOTDIR: c_int = 20;
const EINVAL: c_int = 22;
const ENAMETOOLONG: c_int = 36;
const ENOTEMPTY: c_int = 39;
const EBUSY: c_int = 16;
const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0o100;
const R_OK: c_int = 4;
const W_OK: c_int = 2;
const X_OK: c_int = 1;

/// A path with its NUL.
struct Name([u8; 600]);
fn name(bytes: &[u8]) -> Name {
    let mut name = Name([0; 600]);
    name.0[..bytes.len()].copy_from_slice(bytes);
    name
}
impl Name {
    fn pointer(&self) -> *const c_char {
        self.0.as_ptr().cast()
    }
}

fn unlink(path: &[u8], flags: c_int) -> c_int {
    let path = name(path);
    // SAFETY: a live C string.
    unsafe { stafeto_unlinkat(AT_FDCWD, path.pointer(), flags) }
}
fn mkdir(path: &[u8], mode: u32) -> c_int {
    let path = name(path);
    // SAFETY: a live C string.
    unsafe { stafeto_mkdirat(AT_FDCWD, path.pointer(), mode) }
}
fn access(path: &[u8], mode: c_int, flags: c_int) -> c_int {
    let path = name(path);
    // SAFETY: a live C string.
    unsafe { stafeto_faccessat(AT_FDCWD, path.pointer(), mode, flags) }
}
/// A file created and closed, mode 0600 before the mask.
fn create(path: &[u8]) -> c_int {
    let path = name(path);
    // SAFETY: a live C string.
    let fd = unsafe { stafeto_openat(AT_FDCWD, path.pointer(), O_CREAT | O_WRONLY, 0o600) };
    if fd < 0 {
        return fd;
    }
    // SAFETY: a descriptor the layer gave.
    unsafe { stafeto_close(fd) }
}

fn rename(old: &[u8], new: &[u8]) -> c_int {
    let (old, new) = (name(old), name(new));
    // SAFETY: live C strings.
    unsafe { stafeto_renameat(AT_FDCWD, old.pointer(), AT_FDCWD, new.pointer()) }
}
fn link(old: &[u8], new: &[u8], flags: c_int) -> c_int {
    let (old, new) = (name(old), name(new));
    // SAFETY: live C strings.
    unsafe { stafeto_linkat(AT_FDCWD, old.pointer(), AT_FDCWD, new.pointer(), flags) }
}
fn symlink(target: &[u8], path: &[u8]) -> c_int {
    let (target, path) = (name(target), name(path));
    // SAFETY: live C strings.
    unsafe { stafeto_symlinkat(target.pointer(), AT_FDCWD, path.pointer()) }
}
/// The bytes of a link, or the negated errno.
fn readlink(path: &[u8], buffer: &mut [u8]) -> isize {
    let path = name(path);
    // SAFETY: a live C string and a writable buffer.
    unsafe { stafeto_readlinkat(AT_FDCWD, path.pointer(), buffer.as_mut_ptr(), buffer.len()) }
}
fn chmod(path: &[u8], mode: u32, flags: c_int) -> c_int {
    let path = name(path);
    // SAFETY: a live C string.
    unsafe { stafeto_fchmodat(AT_FDCWD, path.pointer(), mode, flags) }
}
fn chown(path: &[u8], uid: u32, gid: u32, flags: c_int) -> c_int {
    let path = name(path);
    // SAFETY: a live C string.
    unsafe { stafeto_fchownat(AT_FDCWD, path.pointer(), uid, gid, flags) }
}
/// utimensat with the times as the four numbers of two timespecs, or none.
fn utimens(path: &[u8], times: Option<[i64; 4]>, flags: c_int) -> c_int {
    let path = name(path);
    let pointer = times
        .as_ref()
        .map_or(core::ptr::null(), core::ptr::from_ref);
    // SAFETY: a live C string, and null or two timespecs.
    unsafe { stafeto_utimensat(AT_FDCWD, path.pointer(), pointer, flags) }
}

/// The node information of `path` with the last link not followed, from the
/// service itself, outside the bridges under test.
fn lstat(path: &[u8]) -> Result<NodeInfo, Status> {
    let transport = posix_abi::shared::with_files(|files| Ok(files.transport()))
        .map_err(|_| Status::BadSize)?;
    transport.files().node_information_from(None, path, false)
}

pub(crate) fn absent(path: &[u8]) -> bool {
    lstat(path) == Err(Status::Unknown(proto_fs::NO_ENTRY))
}

pub(crate) fn is(path: &[u8], kind: u32) -> bool {
    lstat(path).is_ok_and(|info| info.kind == kind)
}

const DIR: u32 = 1;
pub(crate) const REG: u32 = 2;

/// A result of 0 or the negated errno, or the line of the failure.
fn expect(result: c_int, errno: c_int, line: i32) -> Result<(), i32> {
    if result == -errno { Ok(()) } else { Err(line) }
}
pub(crate) fn ok(result: c_int, line: i32) -> Result<(), i32> {
    expect(result, 0, line)
}
pub(crate) fn check(condition: bool, line: i32) -> Result<(), i32> {
    if condition { Ok(()) } else { Err(line) }
}

/// mkdir, rmdir, unlink and access: the four the first commit of the layer
/// carries through, each with its refusals and the tree after them.
fn first_four() -> Result<(), i32> {
    // mkdir: the mode with the mask 022 of the process.
    ok(mkdir(b"/tmp/nm", 0o777), 1)?;
    check(
        lstat(b"/tmp/nm").is_ok_and(|info| info.kind == DIR && info.permissions == 0o755),
        2,
    )?;
    expect(mkdir(b"/tmp/nm", 0o777), EEXIST, 3)?;
    expect(mkdir(b"/tmp/nm/", 0o777), EEXIST, 4)?;
    expect(mkdir(b"/tmp/none/x", 0o777), ENOENT, 5)?;
    // An empty path is ENOENT and never reaches the service, which would
    // answer INVALID_ARGUMENT.
    expect(mkdir(b"", 0o777), ENOENT, 6)?;
    expect(mkdir(b"/etc/motd/x", 0o777), ENOTDIR, 7)?;
    let mut long = [b'x'; 257];
    long[0] = b'/';
    expect(mkdir(&long, 0o777), ENAMETOOLONG, 8)?;
    check(absent(&long[..256]), 9)?;
    // A path of 512 bytes is too long for the layer itself.
    let mut over = [b'a'; 512];
    over[0] = b'/';
    let path = name(&over);
    // SAFETY: a live C string of 512 bytes and a NUL.
    let result = unsafe { stafeto_mkdirat(AT_FDCWD, path.pointer(), 0o777) };
    expect(result, ENAMETOOLONG, 10)?;
    // A null path is EFAULT.
    // SAFETY: the bridge checks for null.
    expect(
        unsafe { stafeto_mkdirat(AT_FDCWD, core::ptr::null(), 0o777) },
        14,
        11,
    )?;
    rt::println!("posix-files: layer mkdir made a directory and refused six paths");
    // access.
    ok(access(b"/tmp/nm", 0, 0), 20)?;
    ok(access(b"/tmp/nm", R_OK | W_OK | X_OK, 0), 21)?;
    expect(access(b"/tmp/none", 0, 0), ENOENT, 22)?;
    expect(access(b"", 0, 0), ENOENT, 23)?;
    expect(access(b"/tmp/nm", 8, 0), EINVAL, 24)?;
    expect(access(b"/tmp/nm", 0, 1), EINVAL, 25)?;
    expect(access(b"/etc/motd/x", 0, 0), ENOTDIR, 26)?;
    // Real and effective identities: a file of the superuser with mode 0600.
    ok(create(b"/tmp/nm/f"), 27)?;
    ok(access(b"/tmp/nm/f", R_OK | W_OK, 0), 28)?;
    posix_abi::process::seteuid(65533).map_err(|_| 29)?;
    // The real ID is still 0: the default check passes, the effective check
    // is the one that refuses.
    let real = access(b"/tmp/nm/f", R_OK | W_OK, 0);
    let effective = access(b"/tmp/nm/f", R_OK, AT_EACCESS);
    let restored = posix_abi::process::seteuid(0);
    ok(real, 30)?;
    expect(effective, EACCES, 31)?;
    restored.map_err(|_| 32)?;
    // X_OK of the superuser needs an execute bit: the file has none.
    expect(access(b"/tmp/nm/f", X_OK, 0), EACCES, 33)?;
    rt::println!("posix-files: layer access took the real and the effective identity");
    // unlink.
    expect(unlink(b"/tmp/nm", 0), EPERM, 40)?;
    check(is(b"/tmp/nm", DIR), 41)?;
    expect(unlink(b"/tmp/nm/none", 0), ENOENT, 42)?;
    expect(unlink(b"", 0), ENOENT, 43)?;
    expect(unlink(b"/tmp/nm/f", 2), EINVAL, 44)?;
    expect(unlink(b"/tmp/nm/f/", 0), ENOTDIR, 45)?;
    check(is(b"/tmp/nm/f", REG), 46)?;
    ok(unlink(b"/tmp/nm/f", 0), 47)?;
    check(absent(b"/tmp/nm/f"), 48)?;
    rt::println!("posix-files: layer unlink removed a file and refused a directory");
    // rmdir.
    ok(create(b"/tmp/nm/g"), 50)?;
    expect(unlink(b"/tmp/nm", AT_REMOVEDIR), ENOTEMPTY, 51)?;
    check(is(b"/tmp/nm", DIR), 52)?;
    expect(unlink(b"/tmp/nm/g", AT_REMOVEDIR), ENOTDIR, 53)?;
    check(is(b"/tmp/nm/g", REG), 54)?;
    expect(unlink(b"/tmp/nm/.", AT_REMOVEDIR), EINVAL, 55)?;
    expect(unlink(b"/", AT_REMOVEDIR), EBUSY, 56)?;
    ok(unlink(b"/tmp/nm/g", 0), 57)?;
    ok(unlink(b"/tmp/nm/", AT_REMOVEDIR), 58)?;
    check(absent(b"/tmp/nm"), 59)?;
    rt::println!("posix-files: layer rmdir refused a full directory and removed an empty one");
    // Forty operations in a row take forty places and give them back: the
    // service keeps sixteen jobs of a session, and a Release that is not sent
    // would leave its key busy.
    for _ in 0..40 {
        ok(mkdir(b"/tmp/nm2", 0o700), 60)?;
        ok(unlink(b"/tmp/nm2", AT_REMOVEDIR), 61)?;
    }
    check(absent(b"/tmp/nm2"), 62)?;
    rt::println!("posix-files: layer kept no job after eighty operations");
    Ok(())
}

fn inode(path: &[u8]) -> Option<u64> {
    lstat(path).ok().map(|info| info.inode)
}

/// rename, link, symlink and readlink in a directory of their own.
fn two_paths() -> Result<(), i32> {
    ok(mkdir(b"/tmp/nm3", 0o777), 100)?;
    ok(create(b"/tmp/nm3/a"), 101)?;
    let file = inode(b"/tmp/nm3/a").ok_or(102)?;
    // rename: the node moves and keeps its identity.
    ok(rename(b"/tmp/nm3/a", b"/tmp/nm3/b"), 103)?;
    check(
        absent(b"/tmp/nm3/a") && inode(b"/tmp/nm3/b") == Some(file),
        104,
    )?;
    expect(rename(b"/tmp/nm3/a", b"/tmp/nm3/c"), ENOENT, 105)?;
    expect(rename(b"", b"/tmp/nm3/c"), ENOENT, 106)?;
    expect(rename(b"/tmp/nm3/b", b""), ENOENT, 107)?;
    check(inode(b"/tmp/nm3/b") == Some(file), 108)?;
    // Directories: into itself, over a file, a file over a directory, a full one.
    ok(mkdir(b"/tmp/nm3/d", 0o777), 109)?;
    ok(mkdir(b"/tmp/nm3/d/e", 0o777), 110)?;
    expect(rename(b"/tmp/nm3/d", b"/tmp/nm3/d/e/f"), EINVAL, 111)?;
    check(is(b"/tmp/nm3/d/e", DIR) && absent(b"/tmp/nm3/d/e/f"), 112)?;
    expect(rename(b"/tmp/nm3/d", b"/tmp/nm3/b"), ENOTDIR, 113)?;
    expect(rename(b"/tmp/nm3/b", b"/tmp/nm3/d"), EISDIR, 114)?;
    ok(mkdir(b"/tmp/nm3/g", 0o777), 115)?;
    expect(rename(b"/tmp/nm3/g", b"/tmp/nm3/d"), ENOTEMPTY, 116)?;
    expect(rename(b"/tmp/nm3/b/", b"/tmp/nm3/h"), ENOTDIR, 117)?;
    check(
        inode(b"/tmp/nm3/b") == Some(file) && absent(b"/tmp/nm3/h"),
        118,
    )?;
    ok(rename(b"/tmp/nm3/g", b"/tmp/nm3/g"), 119)?;
    ok(rename(b"/tmp/nm3/d/e", b"/tmp/nm3/g2"), 120)?;
    ok(unlink(b"/tmp/nm3/g2", AT_REMOVEDIR), 121)?;
    rt::println!("posix-files: layer rename moved a node and refused seven pairs");
    // link: a second name for the same node.
    ok(link(b"/tmp/nm3/b", b"/tmp/nm3/b2", 0), 130)?;
    check(
        inode(b"/tmp/nm3/b2") == Some(file)
            && lstat(b"/tmp/nm3/b").is_ok_and(|info| info.links == 2),
        131,
    )?;
    expect(link(b"/tmp/nm3/b", b"/tmp/nm3/b2", 0), EEXIST, 132)?;
    expect(link(b"/tmp/nm3/d", b"/tmp/nm3/d2", 0), EPERM, 133)?;
    check(absent(b"/tmp/nm3/d2"), 134)?;
    expect(link(b"/tmp/nm3/none", b"/tmp/nm3/n", 0), ENOENT, 135)?;
    expect(link(b"/tmp/nm3/b", b"/tmp/nm3/n", 1), EINVAL, 136)?;
    expect(link(b"", b"/tmp/nm3/n", 0), ENOENT, 137)?;
    expect(link(b"/tmp/nm3/b", b"", 0), ENOENT, 138)?;
    // symlink and readlink.
    ok(symlink(b"/tmp/nm3/b", b"/tmp/nm3/l"), 140)?;
    check(is(b"/tmp/nm3/l", 5), 141)?;
    let mut bytes = [0xaa; 600];
    check(
        readlink(b"/tmp/nm3/l", &mut bytes) == 10 && &bytes[..10] == b"/tmp/nm3/b",
        142,
    )?;
    check(bytes[10] == 0xaa, 143)?;
    let mut short = [0xaa; 4];
    check(
        readlink(b"/tmp/nm3/l", &mut short[..3]) == 3 && &short[..3] == b"/tm",
        144,
    )?;
    check(short[3] == 0xaa, 145)?;
    expect(symlink(b"x", b"/tmp/nm3/l"), EEXIST, 146)?;
    expect(readlink(b"/tmp/nm3/b", &mut bytes) as c_int, EINVAL, 147)?;
    expect(readlink(b"/tmp/nm3/none", &mut bytes) as c_int, ENOENT, 148)?;
    expect(
        readlink(b"/tmp/nm3/l", &mut bytes[..0]) as c_int,
        EINVAL,
        149,
    )?;
    expect(readlink(b"", &mut bytes) as c_int, ENOENT, 150)?;
    // An empty target is a link too; 511 bytes fit and 512 do not.
    ok(symlink(b"", b"/tmp/nm3/empty"), 151)?;
    check(
        is(b"/tmp/nm3/empty", 5) && readlink(b"/tmp/nm3/empty", &mut bytes) == 0,
        152,
    )?;
    ok(symlink(&[b'z'; 511], b"/tmp/nm3/long"), 153)?;
    check(readlink(b"/tmp/nm3/long", &mut bytes) == 511, 154)?;
    expect(
        symlink(&[b'z'; 512], b"/tmp/nm3/toolong"),
        ENAMETOOLONG,
        155,
    )?;
    check(absent(b"/tmp/nm3/toolong"), 156)?;
    expect(symlink(b"x", b""), ENOENT, 157)?;
    // A link without the flag is a link to the link; with the flag, to the file.
    let symbolic = inode(b"/tmp/nm3/l").ok_or(158)?;
    ok(link(b"/tmp/nm3/l", b"/tmp/nm3/l2", 0), 159)?;
    check(
        inode(b"/tmp/nm3/l2") == Some(symbolic) && is(b"/tmp/nm3/l2", 5),
        160,
    )?;
    ok(link(b"/tmp/nm3/l", b"/tmp/nm3/l3", AT_SYMLINK_FOLLOW), 161)?;
    check(
        inode(b"/tmp/nm3/l3") == Some(file) && is(b"/tmp/nm3/l3", REG),
        162,
    )?;
    // rename moves the link itself.
    ok(rename(b"/tmp/nm3/l", b"/tmp/nm3/m"), 163)?;
    check(
        is(b"/tmp/nm3/m", 5) && absent(b"/tmp/nm3/l") && is(b"/tmp/nm3/b", REG),
        164,
    )?;
    rt::println!("posix-files: layer link, symlink and readlink kept their bytes and names");
    Ok(())
}

/// The metadata of a pipe belongs to no file: EINVAL for every call by
/// descriptor. The image of the files has no pipe service; this runs where
/// there is one.
fn pipe_metadata() -> Result<(), i32> {
    let mut ends = [0; 2];
    // SAFETY: two ints.
    check(unsafe { stafeto_pipe2(ends.as_mut_ptr(), 0) } == 0, 170)?;
    let empty = name(b"");
    // SAFETY: a live C string and descriptors of the layer.
    let (chmod, chown, times) = unsafe {
        (
            stafeto_fchmodat(ends[0], empty.pointer(), 0o600, AT_EMPTY_PATH),
            stafeto_fchownat(ends[1], empty.pointer(), 1, 1, AT_EMPTY_PATH),
            stafeto_utimensat(ends[0], empty.pointer(), core::ptr::null(), AT_EMPTY_PATH),
        )
    };
    // SAFETY: descriptors of the layer.
    unsafe {
        stafeto_close(ends[0]);
        stafeto_close(ends[1]);
    }
    expect(chmod, EINVAL, 171)?;
    expect(chown, EINVAL, 172)?;
    expect(times, EINVAL, 173)?;
    rt::println!("posix-files: layer refused the metadata of a pipe");
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn files_names_pipe() -> i32 {
    pipe_metadata().err().unwrap_or(0)
}

/// chmod, chown and the times, by path and by descriptor.
fn metadata() -> Result<(), i32> {
    let file = b"/tmp/nm3/b";
    ok(chmod(file, 0o640, 0), 200)?;
    check(lstat(file).is_ok_and(|info| info.permissions == 0o640), 201)?;
    expect(chmod(b"/tmp/nm3/none", 0o600, 0), ENOENT, 202)?;
    expect(chmod(b"", 0o600, 0), ENOENT, 203)?;
    expect(chmod(file, 0o600, 1), EINVAL, 204)?;
    // The link itself cannot take a mode.
    expect(
        chmod(b"/tmp/nm3/m", 0o600, AT_SYMLINK_NOFOLLOW),
        EOPNOTSUPP,
        205,
    )?;
    // By descriptor: an empty path with AT_EMPTY_PATH.
    let path = name(file);
    // SAFETY: a live C string.
    let fd = unsafe { stafeto_openat(AT_FDCWD, path.pointer(), O_WRONLY, 0) };
    check(fd >= 0, 206)?;
    let empty = name(b"");
    // SAFETY: a live C string and a descriptor of the layer.
    ok(
        unsafe { stafeto_fchmodat(fd, empty.pointer(), 0o604, AT_EMPTY_PATH) },
        207,
    )?;
    check(lstat(file).is_ok_and(|info| info.permissions == 0o604), 208)?;
    // SAFETY: as above.
    expect(
        unsafe { stafeto_fchmodat(fd, empty.pointer(), 0o604, 0) },
        ENOENT,
        209,
    )?;
    // The console keeps its metadata out of the file service.
    // SAFETY: as above.
    expect(
        unsafe { stafeto_fchmodat(1, empty.pointer(), 0o600, AT_EMPTY_PATH) },
        EROFS,
        211,
    )?;
    rt::println!("posix-files: layer chmod set the mode by path and by descriptor");
    // chown: the superuser changes both; minus one keeps a field.
    ok(chown(file, 1234, 5678, 0), 220)?;
    check(
        lstat(file).is_ok_and(|info| (info.uid, info.gid) == (1234, 5678)),
        221,
    )?;
    ok(chown(file, u32::MAX, 99, 0), 222)?;
    check(
        lstat(file).is_ok_and(|info| (info.uid, info.gid) == (1234, 99)),
        223,
    )?;
    ok(chown(file, u32::MAX, u32::MAX, 0), 224)?;
    check(
        lstat(file).is_ok_and(|info| (info.uid, info.gid) == (1234, 99)),
        225,
    )?;
    expect(chown(b"/tmp/nm3/none", 1, 1, 0), ENOENT, 226)?;
    expect(chown(file, 1, 1, 2), EINVAL, 227)?;
    // A user who is not the owner cannot give a file away.
    posix_abi::process::seteuid(65533).map_err(|_| 228)?;
    let refused = chown(file, 65533, u32::MAX, 0);
    let restored = posix_abi::process::seteuid(0);
    expect(refused, EPERM, 229)?;
    restored.map_err(|_| 230)?;
    check(lstat(file).is_ok_and(|info| info.uid == 1234), 231)?;
    // SAFETY: as above.
    ok(
        unsafe { stafeto_fchownat(fd, empty.pointer(), 1, 2, AT_EMPTY_PATH) },
        232,
    )?;
    check(
        lstat(file).is_ok_and(|info| (info.uid, info.gid) == (1, 2)),
        233,
    )?;
    rt::println!("posix-files: layer chown kept a field at minus one and refused a stranger");
    // The times.
    let stamp = |path: &[u8]| lstat(path).map(|info| (info.access_time, info.modify_time));
    ok(utimens(file, Some([100, 5, 200, 6]), 0), 240)?;
    let (access, modify) = stamp(file).map_err(|_| 241)?;
    check(
        (access.seconds, access.nanos) == (100, 5) && (modify.seconds, modify.nanos) == (200, 6),
        242,
    )?;
    // OMIT leaves a time as it is; the seconds beside a mark mean nothing.
    ok(utimens(file, Some([7, UTIME_OMIT, 300, 0]), 0), 243)?;
    let (access, modify) = stamp(file).map_err(|_| 244)?;
    check(
        (access.seconds, access.nanos) == (100, 5) && (modify.seconds, modify.nanos) == (300, 0),
        245,
    )?;
    // Two marks of OMIT change nothing, the change time too.
    let before = lstat(file).map_err(|_| 246)?;
    ok(utimens(file, Some([0, UTIME_OMIT, 0, UTIME_OMIT]), 0), 247)?;
    check(lstat(file) == Ok(before), 248)?;
    // NOW and a null pointer put the clock in.
    ok(utimens(file, Some([0, UTIME_NOW, 0, UTIME_NOW]), 0), 249)?;
    let (access, modify) = stamp(file).map_err(|_| 250)?;
    check(
        access != before.access_time && modify != before.modify_time,
        251,
    )?;
    // The clock gives a time other than zero.
    check(
        (access.seconds, access.nanos) != (0, 0) && (modify.seconds, modify.nanos) != (0, 0),
        251,
    )?;
    ok(utimens(file, Some([1, 2, 3, 4]), 0), 252)?;
    ok(utimens(file, None, 0), 253)?;
    let (access, modify) = stamp(file).map_err(|_| 254)?;
    check(
        (access.seconds, access.nanos) != (1, 2) && (modify.seconds, modify.nanos) != (3, 4),
        255,
    )?;
    // The nanoseconds out of range change nothing.
    let before = lstat(file).map_err(|_| 256)?;
    expect(
        utimens(file, Some([0, 1_000_000_000, 0, 0]), 0),
        EINVAL,
        257,
    )?;
    expect(utimens(file, Some([0, -1, 0, 0]), 0), EINVAL, 258)?;
    expect(
        utimens(file, Some([0, 0, 0, 1_000_000_000]), 0),
        EINVAL,
        259,
    )?;
    expect(utimens(file, None, 1), EINVAL, 260)?;
    expect(utimens(b"/tmp/nm3/none", None, 0), ENOENT, 261)?;
    expect(utimens(b"", None, 0), ENOENT, 262)?;
    check(lstat(file) == Ok(before), 263)?;
    // By descriptor.
    let times = [11, 12, 13, 14];
    // SAFETY: as above.
    ok(
        unsafe { stafeto_utimensat(fd, empty.pointer(), &times, AT_EMPTY_PATH) },
        264,
    )?;
    let (access, modify) = stamp(file).map_err(|_| 265)?;
    check(
        (access.seconds, access.nanos) == (11, 12) && (modify.seconds, modify.nanos) == (13, 14),
        266,
    )?;
    // SAFETY: a descriptor of the layer.
    unsafe { stafeto_close(fd) };
    rt::println!("posix-files: layer utimensat set, kept and refused times");
    // The directory goes.
    for leaf in [
        b"/tmp/nm3/b".as_slice(),
        b"/tmp/nm3/b2",
        b"/tmp/nm3/m",
        b"/tmp/nm3/empty",
        b"/tmp/nm3/long",
        b"/tmp/nm3/l2",
        b"/tmp/nm3/l3",
    ] {
        ok(unlink(leaf, 0), 270)?;
    }
    ok(unlink(b"/tmp/nm3/d", AT_REMOVEDIR), 271)?;
    ok(unlink(b"/tmp/nm3/g", AT_REMOVEDIR), 271)?;
    ok(unlink(b"/tmp/nm3", AT_REMOVEDIR), 272)?;
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn files_names_stages() -> i32 {
    first_four()
        .and_then(|()| two_paths())
        .and_then(|()| metadata())
        .and_then(|()| physical_chdir())
        .and_then(|()| against_descriptors())
        .and_then(|()| own_places())
        .err()
        .unwrap_or(0)
}

fn chdir(path: &[u8]) -> c_int {
    let path = name(path);
    // SAFETY: a live C string.
    unsafe { stafeto_chdir(path.pointer()) }
}

fn getcwd() -> Result<([u8; 520], usize), i32> {
    let mut buffer = [0; 520];
    // SAFETY: a writable buffer.
    if unsafe { stafeto_getcwd(buffer.as_mut_ptr(), buffer.len()) } < 0 {
        return Err(300);
    }
    let length = buffer.iter().position(|&b| b == 0).ok_or(301)?;
    Ok((buffer, length))
}

fn cwd_is(expected: &[u8]) -> bool {
    getcwd().is_ok_and(|(buffer, length)| &buffer[..length] == expected)
}

/// The inode and the mode of `fstatat` through the bridge.
fn fstatat(dirfd: c_int, path: Option<&[u8]>, flags: c_int) -> Result<(u64, u32), c_int> {
    let path = path.map(name);
    let pointer = path.as_ref().map_or(core::ptr::null(), Name::pointer);
    let mut out = [0u64; 16];
    // SAFETY: null or a live C string, and a buffer of a struct stat.
    let result = unsafe { stafeto_fstatat(dirfd, pointer, &mut out, flags) };
    if result < 0 {
        return Err(-result);
    }
    Ok((out[1], out[2] as u32))
}

fn open_at(dirfd: c_int, path: &[u8], flags: c_int) -> c_int {
    let path = name(path);
    // SAFETY: a live C string.
    unsafe { stafeto_openat(dirfd, path.pointer(), flags, 0) }
}

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

/// The current directory is a place: chdir takes the canonical path, and `..`
/// goes to the parent of that place.
fn physical_chdir() -> Result<(), i32> {
    ok(mkdir(b"/tmp/pc", 0o777), 310)?;
    ok(mkdir(b"/tmp/pc/a", 0o777), 311)?;
    ok(mkdir(b"/tmp/pc/b", 0o777), 312)?;
    ok(mkdir(b"/tmp/pc/b/c", 0o777), 313)?;
    ok(symlink(b"/tmp/pc/b/c", b"/tmp/pc/a/l"), 314)?;
    // Through the link: the answer is the path of the place.
    ok(chdir(b"/tmp/pc/a/l"), 315)?;
    check(cwd_is(b"/tmp/pc/b/c"), 316)?;
    // `..` of the place is the parent of the place; the lexical `..` of the
    // way would be /tmp/pc/a.
    ok(chdir(b".."), 317)?;
    check(cwd_is(b"/tmp/pc/b"), 318)?;
    ok(chdir(b"c/./../c"), 319)?;
    check(cwd_is(b"/tmp/pc/b/c"), 320)?;
    // The same through a path that is not a directory change.
    let beyond = fstatat(AT_FDCWD, Some(b"/tmp/pc/a/l/.."), 0).map_err(|_| 321)?;
    let parent = fstatat(AT_FDCWD, Some(b"/tmp/pc/b"), 0).map_err(|_| 322)?;
    let lexical = fstatat(AT_FDCWD, Some(b"/tmp/pc/a"), 0).map_err(|_| 323)?;
    check(beyond.0 == parent.0 && beyond.0 != lexical.0, 324)?;
    // A relative name against the place.
    ok(create(b"f"), 325)?;
    check(is(b"/tmp/pc/b/c/f", REG), 326)?;
    ok(unlink(b"f", 0), 327)?;
    // Refusals leave the place where it was.
    ok(create(b"/tmp/pc/file"), 328)?;
    expect(chdir(b"/tmp/pc/file"), ENOTDIR, 329)?;
    expect(chdir(b"/tmp/pc/none"), ENOENT, 330)?;
    expect(chdir(b""), ENOENT, 331)?;
    expect(chdir(b"/tmp/pc/file/x"), ENOTDIR, 332)?;
    check(cwd_is(b"/tmp/pc/b/c"), 333)?;
    // A directory the caller cannot search.
    ok(mkdir(b"/tmp/pc/closed", 0o700), 334)?;
    posix_abi::process::seteuid(65533).map_err(|_| 335)?;
    let refused = chdir(b"/tmp/pc/closed");
    let restored = posix_abi::process::seteuid(0);
    expect(refused, EACCES, 336)?;
    restored.map_err(|_| 337)?;
    check(cwd_is(b"/tmp/pc/b/c"), 338)?;
    ok(chdir(b"/"), 339)?;
    check(cwd_is(b"/"), 340)?;
    rt::println!("posix-files: layer chdir took the canonical path of the place");
    Ok(())
}

/// A path against a descriptor: openat and fstatat follow the directory the
/// descriptor holds, wherever it goes.
fn against_descriptors() -> Result<(), i32> {
    ok(unlink(b"/tmp/pc/closed", AT_REMOVEDIR), 349)?;
    ok(create(b"/tmp/pc/b/c/f"), 350)?;
    let dir = open_at(AT_FDCWD, b"/tmp/pc", O_RDONLY | O_DIRECTORY);
    check(dir >= 0, 351)?;
    // Through the link, in another branch.
    let fd = open_at(dir, b"a/l/f", O_RDONLY);
    check(fd >= 0, 352)?;
    // SAFETY: a descriptor the layer gave.
    unsafe { stafeto_close(fd) };
    let (_, mode) = fstatat(dir, Some(b"b/c/f"), 0).map_err(|_| 353)?;
    check(mode & S_IFMT == S_IFREG, 354)?;
    let (_, mode) = fstatat(dir, Some(b"a/l"), AT_SYMLINK_NOFOLLOW).map_err(|_| 355)?;
    check(mode & S_IFMT == S_IFLNK, 356)?;
    let (_, mode) = fstatat(dir, Some(b"a/l"), 0).map_err(|_| 357)?;
    check(mode & S_IFMT == S_IFDIR, 358)?;
    // The descriptor itself.
    let (itself, _) = fstatat(dir, None, 0).map_err(|_| 359)?;
    let (empty, _) = fstatat(dir, Some(b""), AT_EMPTY_PATH).map_err(|_| 360)?;
    let (named, _) = fstatat(AT_FDCWD, Some(b"/tmp/pc"), 0).map_err(|_| 361)?;
    check(itself == named && empty == named, 362)?;
    expect(
        fstatat(dir, Some(b""), 0).err().map_or(0, |e| -e),
        ENOENT,
        363,
    )?;
    expect(
        fstatat(dir, Some(b"b"), 2).err().map_or(0, |e| -e),
        EINVAL,
        364,
    )?;
    // The creating calls use it too.
    let dir_name = name(b"n");
    // SAFETY: a live C string and a descriptor of the layer.
    ok(
        unsafe { stafeto_mkdirat(dir, dir_name.pointer(), 0o777) },
        365,
    )?;
    check(is(b"/tmp/pc/n", DIR), 366)?;
    // SAFETY: as above.
    ok(
        unsafe { stafeto_unlinkat(dir, dir_name.pointer(), AT_REMOVEDIR) },
        367,
    )?;
    check(absent(b"/tmp/pc/n"), 368)?;
    // The directory moves; the descriptor goes with it.
    ok(rename(b"/tmp/pc", b"/tmp/pc2"), 370)?;
    let (_, mode) = fstatat(dir, Some(b"b/c/f"), 0).map_err(|_| 371)?;
    check(mode & S_IFMT == S_IFREG, 372)?;
    check(absent(b"/tmp/pc"), 373)?;
    let moved = name(b"b/c/f");
    // SAFETY: as above.
    ok(unsafe { stafeto_unlinkat(dir, moved.pointer(), 0) }, 374)?;
    check(absent(b"/tmp/pc2/b/c/f"), 375)?;
    // The search permission of the directory is checked at each call.
    ok(chmod(b"/tmp/pc2", 0, 0), 376)?;
    posix_abi::process::seteuid(65533).map_err(|_| 377)?;
    let search = open_at(dir, b"b", O_RDONLY | O_DIRECTORY);
    let status = fstatat(dir, Some(b"b"), 0);
    let restored = posix_abi::process::seteuid(0);
    expect(search, EACCES, 378)?;
    expect(status.err().map_or(0, |e| -e), EACCES, 379)?;
    restored.map_err(|_| 380)?;
    ok(chmod(b"/tmp/pc2", 0o755, 0), 381)?;
    // A descriptor of a file, a number that is closed, and one of another service.
    ok(create(b"/tmp/pc2/file2"), 382)?;
    let regular = open_at(AT_FDCWD, b"/tmp/pc2/file2", O_RDONLY);
    check(regular >= 0, 383)?;
    expect(open_at(regular, b"x", O_RDONLY), ENOTDIR, 384)?;
    expect(
        fstatat(regular, Some(b"x"), 0).err().map_or(0, |e| -e),
        ENOTDIR,
        385,
    )?;
    expect(open_at(29, b"x", O_RDONLY), EBADF, 386)?;
    expect(
        fstatat(29, Some(b"x"), 0).err().map_or(0, |e| -e),
        EBADF,
        387,
    )?;
    expect(open_at(1, b"x", O_RDONLY), ENOTDIR, 388)?;
    expect(
        fstatat(1, Some(b"x"), 0).err().map_or(0, |e| -e),
        ENOTDIR,
        389,
    )?;
    let mkdir_there = name(b"x");
    // SAFETY: as above.
    expect(
        unsafe { stafeto_mkdirat(regular, mkdir_there.pointer(), 0o777) },
        ENOTDIR,
        390,
    )?;
    // An absolute path does not look at the descriptor.
    let motd = open_at(29, b"/etc/motd", O_RDONLY);
    check(motd >= 0, 391)?;
    // SAFETY: a descriptor the layer gave.
    unsafe { stafeto_close(motd) };
    // A path with an empty name is no path.
    expect(open_at(dir, b"", O_RDONLY), ENOENT, 392)?;
    // SAFETY: descriptors of the layer.
    unsafe {
        stafeto_close(regular);
        stafeto_close(dir);
    }
    for leaf in [
        b"/tmp/pc2/file2".as_slice(),
        b"/tmp/pc2/file",
        b"/tmp/pc2/a/l",
    ] {
        ok(unlink(leaf, 0), 393)?;
    }
    for leaf in [
        b"/tmp/pc2/b/c".as_slice(),
        b"/tmp/pc2/b",
        b"/tmp/pc2/a",
        b"/tmp/pc2",
    ] {
        ok(unlink(leaf, AT_REMOVEDIR), 394)?;
    }
    rt::println!("posix-files: layer openat and fstatat followed a descriptor through a rename");
    Ok(())
}

/// The names of the big directory: the number, in the four digits after `f`.
pub(crate) const BIG: u32 = 360;
pub(crate) fn big_name(index: u32) -> [u8; 14] {
    let mut path = *b"/tmp/big/f0000";
    let mut rest = index;
    for digit in (10..14).rev() {
        path[digit] = b'0' + (rest % 10) as u8;
        rest /= 10;
    }
    path
}

/// A directory of 360 names of one file: the service keeps 512 names for
/// all, so the names are links. Finding a name in it takes forty steps of the
/// service (eight names to a step), so a rename inside it stays in flight long
/// enough for a signal.
#[unsafe(no_mangle)]
pub extern "C" fn files_names_big() -> i32 {
    fn fill() -> Result<(), i32> {
        ok(mkdir(b"/tmp/big", 0o777), 400)?;
        ok(create(&big_name(0)), 401)?;
        for index in 1..BIG {
            let made = link(&big_name(0), &big_name(index), 0);
            if made != 0 {
                rt::println!("posix-files: the big directory stopped at {index} with {made}");
            }
            ok(made, 402)?;
        }
        Ok(())
    }
    fill().err().unwrap_or(0)
}

/// Moves the last name of the big directory to a new name, or back. The
/// negated errno of the answer, 0 for success.
#[cfg(feature = "names-probe")]
pub(crate) fn slow_rename() -> i32 {
    let last = big_name(BIG - 1);
    if is(b"/tmp/big/n", REG) {
        -rename(b"/tmp/big/n", &last)
    } else {
        -rename(&last, b"/tmp/big/n")
    }
}

/// The big directory goes.
#[unsafe(no_mangle)]
pub extern "C" fn files_names_big_gone() -> i32 {
    fn gone() -> Result<(), i32> {
        if is(b"/tmp/big/n", REG) {
            ok(unlink(b"/tmp/big/n", 0), 410)?;
        }
        for index in 0..BIG {
            let path = big_name(index);
            if is(&path, REG) {
                ok(unlink(&path, 0), 411)?;
            }
        }
        ok(unlink(b"/tmp/big", AT_REMOVEDIR), 412)
    }
    gone().err().unwrap_or(0)
}

unsafe extern "C" {
    fn nanosleep(request: *const [i64; 2], remaining: *mut [i64; 2]) -> c_int;
}

/// The sixteen places of the jobs of a session, taken by hand: records the
/// way a thread leaves them when it is inside sixteen operations (frames that
/// contain this one) or has left them by a long jump (frames that do not).
mod places {
    use super::*;
    use entries::Frame;
    use posix_fs::change::{ControlClaimToken, ControlResult, ControlToken, OwnerToken};

    pub const EAGAIN: c_int = 11;

    fn owner() -> Result<OwnerToken, i32> {
        let value = posix_abi::relibc::open_owner().map_err(|_| 500)?;
        OwnerToken::new(value).map_err(|_| 501)
    }

    /// Sixteen records of this thread with this frame, or the places that
    /// were free.
    pub fn take(frame: Frame) -> Result<[Option<(ControlToken, ControlClaimToken)>; 16], i32> {
        let owner = owner()?;
        let mut held = [None; 16];
        for place in &mut held {
            *place = posix_abi::shared::with_files(|files| {
                files
                    .begin_change_record(owner, frame)
                    .map(Some)
                    .map_err(|_| 502)
            })?;
        }
        Ok(held)
    }

    /// The operation behind the record ends: its place goes. These jobs
    /// never started in the service, so no Release is owed.
    pub fn give(token: ControlToken, claim: ControlClaimToken) -> Result<(), i32> {
        let owner = owner()?;
        posix_abi::shared::with_files(|files| {
            files
                .complete_change_record(claim, ControlResult::Value(0))
                .map_err(|_| 503)?;
            files.begin_change_cleanup(token).map_err(|_| 504)?;
            files.finish_change_cleanup(token).map_err(|_| 505)?;
            files.ack_change_record(token, owner).map_err(|_| 506)?;
            Ok(())
        })
    }

    pub fn in_use() -> Result<usize, i32> {
        posix_abi::shared::with_files(|files| Ok(files.change_tokens().count()))
    }
}

/// A thread inside sixteen operations answers EAGAIN to a seventeenth, and
/// the places its records have left behind are released by its next operation.
fn own_places() -> Result<(), i32> {
    use entries::Frame;
    // Sixteen operations the thread is inside of: the frames lie above this one.
    let held = places::take(Frame::main(u64::MAX))?;
    expect(mkdir(b"/tmp/pl", 0o777), places::EAGAIN, 440)?;
    check(absent(b"/tmp/pl"), 441)?;
    // One of them ends: there is room, and the others are left alone.
    let (token, claim) = held[0].ok_or(442)?;
    places::give(token, claim)?;
    ok(mkdir(b"/tmp/pl", 0o777), 443)?;
    check(places::in_use()? == 15, 444)?;
    ok(unlink(b"/tmp/pl", AT_REMOVEDIR), 445)?;
    for (token, claim) in held[1..].iter().flatten() {
        places::give(*token, *claim)?;
    }
    check(places::in_use()? == 0, 446)?;
    // Sixteen operations the thread has left by a long jump: the frames lie
    // below this one. The next operation releases them and goes on.
    let _left = places::take(Frame::main(0))?;
    check(places::in_use()? == 16, 447)?;
    ok(mkdir(b"/tmp/pl", 0o777), 448)?;
    check(places::in_use()? == 0, 449)?;
    ok(unlink(b"/tmp/pl", AT_REMOVEDIR), 450)?;
    rt::println!(
        "posix-files: layer answered EAGAIN to a thread inside sixteen operations and released the places it left"
    );
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn files_names_own_places() -> i32 {
    own_places().err().unwrap_or(0)
}

/// The body of a thread that holds the sixteen places for `tenths` of a
/// millisecond: the records of operations in flight, which end when it wakes.
#[unsafe(no_mangle)]
pub extern "C" fn files_names_hold_places(tenths: i32) -> i32 {
    use entries::Frame;
    fn hold(tenths: i32) -> Result<(), i32> {
        let held = places::take(Frame::main(u64::MAX))?;
        let pause = [0, i64::from(tenths) * 100_000];
        // SAFETY: relibc's nanosleep and a live timespec.
        unsafe { nanosleep(&pause, core::ptr::null_mut()) };
        for (token, claim) in held.iter().flatten() {
            places::give(*token, *claim)?;
        }
        posix_abi::change::wake_places();
        Ok(())
    }
    hold(tenths).err().unwrap_or(0)
}

/// The seventeenth operation of another thread: it waits for the places of
/// the holder and ends with success.
#[unsafe(no_mangle)]
pub extern "C" fn files_names_wait_for_places() -> i32 {
    let result = mkdir(b"/tmp/pw", 0o777);
    if result != 0 {
        return 510;
    }
    unlink(b"/tmp/pw", AT_REMOVEDIR).abs()
}

/// How many places of jobs are taken now.
#[unsafe(no_mangle)]
pub extern "C" fn files_names_places_in_use() -> i32 {
    places::in_use().map_or(-1, |used| used as i32)
}
