// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The operations on names and metadata through the bridges `stafeto_*` of the
//! layer, which relibc's platform calls. Every function answers with an effect
//! that is looked at afterwards (the node information of the path, not the
//! return value alone), and every refusal leaves the tree as it was.
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
}

const AT_FDCWD: c_int = -100;
const AT_REMOVEDIR: c_int = 0x200;
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
const AT_SYMLINK_FOLLOW: c_int = 0x400;
const AT_EMPTY_PATH: c_int = 0x1000;
const UTIME_NOW: i64 = (1 << 30) - 1;
const UTIME_OMIT: i64 = (1 << 30) - 2;
const EXDEV: c_int = 18;
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
/// service itself and not through the bridges under test.
fn lstat(path: &[u8]) -> Result<NodeInfo, Status> {
    let transport = posix_abi::shared::with_files(|files| Ok(files.transport()))
        .map_err(|_| Status::BadSize)?;
    transport.files().node_information_from(None, path, false)
}

fn absent(path: &[u8]) -> bool {
    lstat(path) == Err(Status::Unknown(proto_fs::NO_ENTRY))
}

fn is(path: &[u8], kind: u32) -> bool {
    lstat(path).is_ok_and(|info| info.kind == kind)
}

const DIR: u32 = 1;
const REG: u32 = 2;

/// A result of 0 or the negated errno, or the line of the failure.
fn expect(result: c_int, errno: c_int, line: i32) -> Result<(), i32> {
    if result == -errno { Ok(()) } else { Err(line) }
}
fn ok(result: c_int, line: i32) -> Result<(), i32> {
    expect(result, 0, line)
}
fn check(condition: bool, line: i32) -> Result<(), i32> {
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
    // The clock, and not a time of zero.
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
        .err()
        .unwrap_or(0)
}
