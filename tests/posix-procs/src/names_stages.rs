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
}

const AT_FDCWD: c_int = -100;
const AT_REMOVEDIR: c_int = 0x200;
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

#[unsafe(no_mangle)]
pub extern "C" fn files_names_stages() -> i32 {
    first_four().err().unwrap_or(0)
}
