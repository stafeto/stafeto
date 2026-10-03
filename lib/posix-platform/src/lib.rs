// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The layer's side of relibc's stafeto platform (spec 2, 3.10): the C
//! functions `stafeto_*` that the module `src/platform/stafeto` of the
//! fork stafeto/relibc calls as its system calls. Each returns a
//! value or a negated errno; numbers and structures are those of Linux
//! AArch64 as relibc sees them.
//!
//! relibc builds the TCB of the main thread from `PT_TLS` and installs it
//! (`TPIDR_EL0`); the layer's block is its `os_specific`, 32 bytes on
//! (posix-thread). Its start checks `STAFETO_PLATFORM_ABI` and calls
//! `stafeto_init`, which attaches the thread. Calls before that run with
//! a TCB of the layer on the stack (posix_abi::tls).

#![no_std]

mod files;
mod signals;

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::AtomicU32;
use posix_abi::constants::{EFAULT, EINVAL, EISDIR, ENOMEM};
use posix_types::Timespec;

/// The version of the interface of the functions `stafeto_*`; relibc
/// expects the same.
pub const PLATFORM_INTERFACE: u64 = 13;

/// The ABI word relibc checks at start: the size of the block in bits 0
/// to 15, its offset in the TCB in bits 16 to 31, the interface in bits 32
/// to 63.
#[unsafe(no_mangle)]
pub static STAFETO_PLATFORM_ABI: u64 = posix_thread::BLOCK_SIZE as u64
    | (posix_thread::BLOCK_OFFSET as u64) << 16
    | PLATFORM_INTERFACE << 32;

/// Runs one call of the layer on a thread with a block: its own, or
/// before relibc attached the main thread (its start) a transient one
/// (posix_abi::tls). The layer gives a value or an errno and keeps none.
fn call<T>(run: impl FnOnce() -> Result<T, c_int>) -> Result<T, c_int> {
    posix_abi::tls::with_process(run)
}

/// A value of the platform's interface: the value, or the negated errno.
fn value(result: Result<i64, c_int>) -> i64 {
    result.unwrap_or_else(|errno| -i64::from(errno))
}

/// Attaches the main thread, whose TCB relibc built and installed, to the
/// layer: its block, channel, timer and entry of signals.
///
/// # Safety
/// relibc's start calls it once, on the main thread, with its TCB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_init(tcb: *mut c_void) -> c_int {
    posix_abi::relibc::configure(unmap);
    // SAFETY: the caller's promise.
    match unsafe { posix_abi::threads::attach_installed(tcb.cast(), 1) } {
        Ok(()) => {
            // SAFETY: the main thread's block lies 32 bytes into its TCB.
            unsafe {
                posix_abi::relibc::attach_main(
                    tcb.cast::<u8>().add(posix_thread::BLOCK_OFFSET).cast(),
                )
            };
            // The main thread routes the process's signals, and those that
            // came before its entry was bound come now (spec 2, 3.3).
            let routed =
                call(|| posix_abi::process::register_router(&posix_abi::threads::main_handle()));
            let _ = call(|| {
                posix_abi::signals::take_waiting();
                Ok::<(), i32>(())
            });
            match routed {
                Ok(()) => 0,
                Err(errno) => -errno,
            }
        }
        Err(errno) => -errno,
    }
}

/// getrandom (posix_abi::random::getrandom): `len` bytes of the
/// process's generator into `buf`, with GRND_NONBLOCK, GRND_RANDOM and
/// GRND_INSECURE; relibc's getentropy calls it with no flag and its limit
/// checked.
///
/// # Safety
/// `buf` is writable for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_getrandom(buf: *mut u8, len: usize, flags: u32) -> isize {
    if buf.is_null() && len != 0 {
        return -(EFAULT as isize);
    }
    let bytes = if len == 0 {
        &mut [][..]
    } else {
        // SAFETY: the caller's promise.
        unsafe { core::slice::from_raw_parts_mut(buf, len) }
    };
    value(call(|| posix_abi::random::getrandom(bytes, flags)).map(|n| n as i64)) as isize
}

/// # Safety
/// `buf` is readable for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_write(fd: c_int, buf: *const u8, len: usize) -> isize {
    if buf.is_null() && len != 0 {
        return -(EFAULT as isize);
    }
    // SAFETY: the caller's promise.
    let bytes = if len == 0 {
        &[][..]
    } else {
        unsafe { core::slice::from_raw_parts(buf, len) }
    };
    value(call(|| posix_abi::write(fd, bytes)).map(|n| n as i64)) as isize
}

/// # Safety
/// `buf` is writable for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_read(fd: c_int, buf: *mut u8, len: usize) -> isize {
    if buf.is_null() && len != 0 {
        return -(EFAULT as isize);
    }
    let buffer = if len == 0 {
        &mut [][..]
    } else {
        // SAFETY: the caller's promise.
        unsafe { core::slice::from_raw_parts_mut(buf, len) }
    };
    value(call(|| posix_abi::read(fd, buffer)).map(|n| n as i64)) as isize
}

/// relibc's open flags (its headers for AArch64 Linux, asm/fcntl.h).
const AT_FDCWD: c_int = -100;
const O_ACCMODE: c_int = 0o3;
const O_RDONLY: c_int = 0;
const O_CREAT: c_int = 0o100;
const O_TRUNC: c_int = 0o1000;
const O_APPEND: c_int = 0o2000;
const O_NOCTTY: c_int = 0o400;
const O_DIRECTORY: c_int = 0o40000;
const O_NOFOLLOW: c_int = 0o100000;
const O_LARGEFILE: c_int = 0o400000;
const O_CLOEXEC: c_int = 0o2000000;
/// relibc's O_CLOFORK of stafeto (POSIX 2024; Linux has none).
const O_CLOFORK: c_int = 0o1_0000_0000;
const O_NONBLOCK: c_int = 0o4000;

/// Opens `path`, relative to the current directory or absolute (any
/// `dirfd` then). The layer opens files of the RAM file service: the
/// access mode, O_DIRECTORY and O_CLOEXEC; O_NOCTTY, O_NOFOLLOW (no
/// symbolic links yet) and O_LARGEFILE change nothing; other flags, and a
/// relative path from a directory other than `AT_FDCWD`, answer EINVAL.
/// O_CREAT, O_TRUNC and O_APPEND name a directory as POSIX has it: EISDIR
/// for O_CREAT without O_DIRECTORY and for O_TRUNC or O_APPEND with write
/// access; O_APPEND for reading opens the directory; on anything else they
/// go to the service, which takes them for the null device only and
/// answers EINVAL for any other file (it creates, truncates and appends
/// nothing yet).
///
/// # Safety
/// `path` is a live C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_openat(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    _mode: u32,
) -> c_int {
    let known =
        O_ACCMODE | O_NOCTTY | O_DIRECTORY | O_NOFOLLOW | O_LARGEFILE | O_CLOEXEC | O_CLOFORK;
    let changes = O_CREAT | O_TRUNC | O_APPEND;
    // SAFETY: the caller's promise.
    let absolute = !path.is_null() && unsafe { *path } == b'/' as c_char;
    if (dirfd != AT_FDCWD && !absolute) || flags & !(known | changes) != 0 {
        return -EINVAL;
    }
    // SAFETY: the caller's promise.
    let name = match unsafe { posix_abi::path(path) } {
        Ok(name) => name,
        Err(errno) => return -errno,
    };
    let mut ours_changes = 0;
    if flags & changes != 0 {
        let reads = flags & O_ACCMODE == O_RDONLY;
        let creates = flags & O_CREAT != 0 && flags & O_DIRECTORY == 0;
        let directory = (creates || !reads || flags & changes == O_APPEND) && is_directory(name);
        if directory && (creates || !reads) {
            return -EISDIR;
        }
        // The null device takes them; the service refuses any other file.
        if !(directory && flags & changes == O_APPEND) {
            ours_changes = posix_abi::constants::O_CHANGES;
        }
    }
    let mut ours = flags & O_ACCMODE | ours_changes;
    if flags & O_DIRECTORY != 0 {
        ours |= posix_abi::constants::O_DIRECTORY;
    }
    if flags & O_CLOEXEC != 0 {
        ours |= posix_abi::constants::O_CLOEXEC;
    }
    if flags & O_CLOFORK != 0 {
        ours |= posix_abi::constants::O_CLOFORK;
    }
    value(call(|| posix_abi::open(name, ours)).map(i64::from)) as c_int
}

/// Whether `name` opens as a directory.
fn is_directory(name: &[u8]) -> bool {
    call(|| posix_abi::open(name, posix_abi::constants::O_DIRECTORY).and_then(posix_abi::close))
        .is_ok()
}

/// pipe2: the read end into `fds[0]` and the write end into `fds[1]`
/// (posix_abi::pipe2: O_NONBLOCK, O_CLOEXEC and O_CLOFORK).
///
/// # Safety
/// `fds` is writable for two ints.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_pipe2(fds: *mut c_int, flags: c_int) -> c_int {
    if fds.is_null() {
        return -EFAULT;
    }
    let mut ours = 0;
    for (theirs, layer) in [
        (O_CLOEXEC, posix_abi::constants::O_CLOEXEC),
        (O_CLOFORK, posix_abi::constants::O_CLOFORK),
        (O_NONBLOCK, posix_abi::constants::O_NONBLOCK),
    ] {
        if flags & theirs != 0 {
            ours |= layer;
        }
    }
    if flags & !(O_CLOEXEC | O_CLOFORK | O_NONBLOCK) != 0 {
        return -EINVAL;
    }
    match call(|| posix_abi::pipe2(ours)) {
        Ok(ends) => {
            // SAFETY: the caller's promise.
            unsafe {
                fds.write(ends[0]);
                fds.add(1).write(ends[1]);
            }
            0
        }
        Err(errno) => -errno,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_close(fd: c_int) -> c_int {
    value(call(|| posix_abi::close(fd)).map(|()| 0)) as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_lseek(fd: c_int, offset: i64, whence: c_int) -> i64 {
    value(call(|| posix_abi::lseek(fd, offset, whence)))
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_exit(status: c_int) -> ! {
    posix_abi::exit(status)
}

/// CLOCK_MONOTONIC from the counter, CLOCK_REALTIME from the clock
/// service's page: no call of the kernel.
///
/// # Safety
/// `out` is writable for a timespec, whose layout is Linux's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_clock_gettime(clock: c_int, out: *mut Timespec) -> c_int {
    match posix_abi::clock::gettime(clock) {
        Ok(time) => {
            // SAFETY: the caller's promise.
            unsafe {
                out.write(Timespec {
                    tv_sec: time.seconds,
                    tv_nsec: time.nanos,
                })
            };
            0
        }
        Err(errno) => -errno,
    }
}

/// # Safety
/// `out` is null or writable for a timespec.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_clock_getres(clock: c_int, out: *mut Timespec) -> c_int {
    match posix_abi::clock::getres(clock) {
        Ok(time) => {
            // SAFETY: the caller's promise.
            if let Some(out) = unsafe { out.as_mut() } {
                *out = Timespec {
                    tv_sec: time.seconds,
                    tv_nsec: time.nanos,
                };
            }
            0
        }
        Err(errno) => -errno,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_getpid() -> c_int {
    posix_abi::process::getpid()
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_getppid() -> c_int {
    posix_abi::process::getppid()
}

/// waitpid (posix_abi::process::waitpid): the child's PID, 0 for WNOHANG
/// with none, its status (Linux's layout) at `status`; or the negated
/// errno.
///
/// # Safety
/// `status` is writable for an int.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int {
    match call(|| posix_abi::process::waitpid(pid, options)) {
        Ok(waited) => {
            let word = waited.end.map_or(0, proto_process::End::wait_status);
            // SAFETY: the caller's promise.
            unsafe { status.write(word) };
            waited.pid
        }
        Err(errno) => -errno,
    }
}

/// The idtype_t of waitid.
const P_ALL: c_int = 0;
const P_PID: c_int = 1;
const P_PGID: c_int = 2;
/// SIGCHLD, and the offsets of the child's fields in Linux's siginfo_t.
const SIGCHLD: i32 = 17;
const SIGINFO_LEN: usize = 128;

/// waitid (POSIX: the child that `idtype` and `id` name, as `options`
/// say): 0 with Linux's siginfo_t of the child at `info` (signo SIGCHLD,
/// code CLD_EXITED or CLD_KILLED, pid, uid, status), zeroed for WNOHANG
/// with none; or the negated errno: EINVAL for another idtype, no
/// WEXITED, WSTOPPED or WCONTINUED, or another option.
///
/// # Safety
/// `info` is writable for a siginfo_t.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_waitid(
    idtype: c_int,
    id: u32,
    info: *mut u8,
    options: c_int,
) -> c_int {
    use proto_process::{
        CLD_EXITED, CLD_KILLED, End, Selector, WAIT_OPTIONS, WCONTINUED, WEXITED, WSTOPPED,
    };
    let Ok(options) = u32::try_from(options) else {
        return -EINVAL;
    };
    if options & (WEXITED | WSTOPPED | WCONTINUED) == 0 || options & !WAIT_OPTIONS != 0 {
        return -EINVAL;
    }
    let own = posix_abi::process::page()
        .pgid
        .load(core::sync::atomic::Ordering::Relaxed);
    let selector = match (idtype, id) {
        (P_ALL, _) => Selector::Any,
        (P_PID, pid) if pid != 0 => Selector::Pid(pid),
        (P_PGID, 0) => Selector::Group(own),
        (P_PGID, pgid) => Selector::Group(pgid),
        _ => return -EINVAL,
    };
    match call(|| posix_abi::process::wait(selector, options)) {
        Ok(waited) => {
            let mut words = [0i32; SIGINFO_LEN / 4];
            if let Some(end) = waited.end {
                let (code, status) = match end {
                    End::Exited(code) => (CLD_EXITED, i32::from(code)),
                    End::Signaled(n) => (CLD_KILLED, i32::from(n)),
                };
                words[0] = SIGCHLD;
                words[2] = code;
                words[4] = waited.pid;
                words[5] = waited.uid as i32;
                words[6] = status;
            }
            // SAFETY: the caller's promise.
            unsafe { ptr::copy_nonoverlapping(words.as_ptr().cast::<u8>(), info, SIGINFO_LEN) };
            0
        }
        Err(errno) => -errno,
    }
}

/// What relibc's posix_spawn gives of its attributes: the spawn-flags
/// and the process group, the masks of POSIX_SPAWN_SETSIGMASK and
/// POSIX_SPAWN_SETSIGDEF (bit n - 1 for signal n).
#[repr(C)]
pub struct SpawnAttributes {
    flags: c_int,
    pgroup: c_int,
    mask: u64,
    default: u64,
}

/// A file action as relibc's posix_spawn gives it: OPEN (1) of `path`
/// with `flags` at `fd`, CLOSE (2) of `fd`, DUP2 (3) of `fd` to `newfd`,
/// CHDIR (4) to `path`, FCHDIR (5) to `fd`.
#[repr(C)]
pub struct SpawnAction {
    kind: c_int,
    fd: c_int,
    newfd: c_int,
    flags: c_int,
    mode: u32,
    path: *const c_char,
}

/// The file actions of `list`, `count` of them, as the layer takes them;
/// a kind it does not know is a close of a number past the table, which
/// fails with EBADF.
///
/// # Safety
/// `list` is null or holds `count` actions whose paths are C strings that
/// live through the call.
unsafe fn actions<'a>(
    list: *const SpawnAction,
    count: usize,
) -> impl Iterator<Item = posix_abi::process::FileAction<'a>> + Clone {
    use posix_abi::process::FileAction;
    let count = if list.is_null() { 0 } else { count };
    (0..count).map(move |i| {
        // SAFETY: the caller's promise.
        let a = unsafe { &*list.add(i) };
        let number = |n: c_int| u32::try_from(n).unwrap_or(u32::MAX);
        // SAFETY: as above, for the paths of OPEN and CHDIR.
        let path = || unsafe { bytes_of(a.path) };
        match a.kind {
            1 => FileAction::Open {
                fd: number(a.fd),
                path: path(),
                flags: a.flags,
            },
            2 => FileAction::Close(number(a.fd)),
            3 => FileAction::Dup2(number(a.fd), number(a.newfd)),
            4 => FileAction::Chdir(path()),
            5 => FileAction::Fchdir(number(a.fd)),
            _ => FileAction::Close(u32::MAX),
        }
    })
}

/// The bytes of the C string `path`, without its NUL; empty for null.
///
/// # Safety
/// `path` is null or a C string that lives as long as `'a`.
unsafe fn bytes_of<'a>(path: *const c_char) -> &'a [u8] {
    if path.is_null() {
        return &[];
    }
    // SAFETY: the caller's promise.
    unsafe { core::ffi::CStr::from_ptr(path) }.to_bytes()
}

/// The strings of the NULL-ended list `list` of C strings, without NULs.
///
/// # Safety
/// `list` is null or a NULL-ended array of C strings that live through
/// the call.
unsafe fn strings<'a>(list: *const *const c_char) -> impl Iterator<Item = &'a [u8]> + Clone {
    let mut i = 0;
    core::iter::from_fn(move || {
        if list.is_null() {
            return None;
        }
        // SAFETY: the caller's promise: the array ends with NULL.
        let p = unsafe { *list.add(i) };
        if p.is_null() {
            return None;
        }
        i += 1;
        // SAFETY: as above, each entry is a C string.
        Some(unsafe { core::ffi::CStr::from_ptr(p) }.to_bytes())
    })
}

/// posix_spawn of the program at `path` with `argv`, `envp` and the
/// attributes at `attributes` (null for none): from its file through the
/// loader (posix_abi::process::spawn_file, 5c). The child's PID, or the
/// negated errno.
///
/// # Safety
/// `path` is a C string; `argv` and `envp` are null or NULL-ended arrays
/// of C strings; `attributes` is null or points to SpawnAttributes;
/// `file_actions` is null or holds `count` SpawnAction.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_spawn(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
    attributes: *const SpawnAttributes,
    file_actions: *const SpawnAction,
    count: usize,
) -> c_int {
    // SAFETY: the caller's promise.
    let path = unsafe { core::ffi::CStr::from_ptr(path) }.to_bytes();
    // SAFETY: as above.
    let attributes = unsafe { attributes.as_ref() };
    let (flags, pgroup) = attributes.map_or((0, 0), |a| (a.flags, a.pgroup));
    let (Ok(flags), Ok(pgroup)) = (u32::try_from(flags), u32::try_from(pgroup)) else {
        return -posix_abi::constants::EINVAL;
    };
    let mask = attributes
        .filter(|_| flags & proto_process::SPAWN_SETSIGMASK != 0)
        .map(|a| a.mask);
    let default = attributes
        .filter(|_| flags & proto_process::SPAWN_SETSIGDEF != 0)
        .map_or(0, |a| a.default);
    let umask = files::umask();
    let attributes = posix_abi::process::SpawnAttributes {
        flags,
        pgroup,
        mask,
        default,
        umask,
    };
    // SAFETY: the caller's promise for argv, envp and the file actions.
    let (argv, envp, file_actions) =
        unsafe { (strings(argv), strings(envp), actions(file_actions, count)) };
    match call(|| {
        posix_abi::process::spawn_file(
            path,
            argv.clone(),
            envp.clone(),
            attributes,
            file_actions.clone(),
        )
    }) {
        Ok(pid) => pid,
        Err(errno) => -errno,
    }
}

/// execve of the program in the file at `path` with `argv` and `envp`
/// (posix_abi::process::exec): it returns only with the negated errno.
///
/// # Safety
/// `path` is a C string; `argv` and `envp` are null or NULL-ended arrays
/// of C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_exec(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    // SAFETY: the caller's promise.
    let path = unsafe { bytes_of(path) };
    // SAFETY: as above.
    let (argv, envp) = unsafe { (strings(argv), strings(envp)) };
    let umask = files::umask();
    match call(|| posix_abi::process::exec(path, argv.clone(), envp.clone(), umask)) {
        Ok(never) => match never {},
        Err(errno) => -errno,
    }
}

/// fork (posix_abi::fork::fork): the child's PID in the parent, 0 in the
/// child, or the negated errno. The window a probe set
/// (`stafeto_probe_fork_window`) runs in the parent before ForkCommit.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_fork() -> c_int {
    let set = FORK_WINDOW.load(core::sync::atomic::Ordering::Acquire) != 0;
    let window = set.then_some(fork_window as fn());
    match call(|| posix_abi::fork::fork(window)) {
        Ok(pid) => pid,
        Err(errno) => -errno,
    }
}

/// The probes of the window of exec (posix_abi::process): ExecCommit
/// with no exec gives its errno; an exec whose old image ends with `code`
/// before ExecCommit (by its own SIGKILL for 137) returns only on an
/// error.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_exec_commit() -> c_int {
    posix_abi::process::probe_exec_commit()
}

/// # Safety
/// `path` is a C string; `argv` a NULL-ended array of C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_probe_exec_then_exit(
    path: *const c_char,
    argv: *const *const c_char,
    code: c_int,
) -> c_int {
    // SAFETY: the caller's promise.
    let (path, argv) = unsafe { (bytes_of(path), strings(argv)) };
    posix_abi::process::probe_exec_then_exit(path, argv, code as u64)
}

/// The probe of an exec whose old image outlives its ExecCommit and asks
/// the clock service to set the time (posix_abi::process::probe_exec_outlive):
/// returns only on an error, with its errno.
///
/// # Safety
/// `path` is a C string; `argv` a NULL-ended array of C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_probe_exec_outlive(
    path: *const c_char,
    argv: *const *const c_char,
) -> c_int {
    // SAFETY: the caller's promise.
    let (path, argv) = unsafe { (bytes_of(path), strings(argv)) };
    posix_abi::process::probe_exec_outlive(path, argv)
}

/// The probe of a SpawnCommit before the loader's image is ready
/// (posix_abi::process::probe_commit_early): its errno, and the child's
/// PID in `pid` to reap.
///
/// # Safety
/// `pid` points to an int.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_probe_commit_early(pid: *mut c_int) -> c_int {
    let mut child = -1;
    let errno = posix_abi::process::probe_commit_early(&mut child);
    // SAFETY: the caller's promise.
    unsafe { pid.write(child) };
    errno
}

/// The loads the calling record may have at once
/// (posix_abi::process::probe_loads).
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_loads() -> c_int {
    posix_abi::process::probe_loads()
}

/// The bytes of the process service's quota left for children (Pool),
/// for the probe that the ends of loads give theirs back.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_pool() -> u64 {
    posix_abi::process::probe_pool()
}

/// The probe of `addopen` (posix_abi::process::probe_addopen_cloexec):
/// 1 when the caller's own descriptor of an open action has FD_CLOEXEC.
///
/// # Safety
/// `path` is a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_probe_addopen_cloexec(path: *const c_char) -> c_int {
    // SAFETY: the caller's promise.
    let path = unsafe { core::ffi::CStr::from_ptr(path) }.to_bytes();
    posix_abi::process::probe_addopen_cloexec(path)
}

/// Arms the notification of the process's identity session
/// (posix_abi::process::probe_notify_identity): 0 or EIO.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_notify_identity() -> c_int {
    posix_abi::process::probe_notify_identity()
}

/// OPEN_EXEC through the process's own session with the RAM file
/// service (posix_abi::process::probe_open_exec): 0 or the errno, for the
/// probes of 5c.
///
/// # Safety
/// `path` is a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_probe_open_exec(path: *const c_char) -> c_int {
    // SAFETY: the caller's promise.
    let path = unsafe { core::ffi::CStr::from_ptr(path) }.to_bytes();
    posix_abi::process::probe_open_exec(path)
}

/// The probe of condition O2 of 5c: Start of the next spawns carries a
/// channel of the caller's (posix_abi::process::probe_decoy).
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_decoy(on: c_int) {
    posix_abi::process::probe_decoy(on != 0);
}

/// The probe of the loader's refusal of a pipe's end with no session of
/// the pipe service (posix_abi::process::probe_no_pipes_session): the
/// next spawns give the loader none.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_no_pipes_session(on: c_int) {
    posix_abi::process::probe_no_pipes_session(on != 0);
}

/// The C function a probe of fork runs in the parent between Go and
/// ForkCommit (`stafeto_probe_fork_bare`), 0 for none.
static FORK_WINDOW: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn fork_window() {
    let hook = FORK_WINDOW.load(core::sync::atomic::Ordering::Acquire);
    if hook != 0 {
        // SAFETY: only `stafeto_probe_fork_bare` stores a value, a C
        // function of no arguments.
        let hook: extern "C" fn() = unsafe { core::mem::transmute::<usize, extern "C" fn()>(hook) };
        hook();
    }
}

/// A bare fork for the probes of 5d (posix_abi::fork::probe_bare): the
/// child runs `child(arg)` on its copy with nothing of the layer bound,
/// and exits with its value; `window`, when given, runs in the parent
/// once the copy is ready, before ForkCommit. The child's PID, or the
/// negated errno.
///
/// # Safety
/// `child` touches memory alone, and calls nothing of the layer but the
/// probes that say so; `window` is a C function of no arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_probe_fork_bare(
    child: extern "C" fn(*mut c_void) -> c_int,
    arg: *mut c_void,
    window: Option<extern "C" fn()>,
) -> c_int {
    FORK_WINDOW.store(
        window.map_or(0, |f| f as usize),
        core::sync::atomic::Ordering::Release,
    );
    let hook: Option<fn()> = window.map(|_| fork_window as fn());
    match call(|| posix_abi::fork::probe_bare(|| child(arg), hook)) {
        Ok(pid) => pid,
        Err(errno) => -errno,
    }
}

/// The C function the next forks run in the parent between Go and
/// ForkCommit (`stafeto_fork`), None for none: for the probes.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_fork_window(window: Option<extern "C" fn()>) {
    FORK_WINDOW.store(
        window.map_or(0, |f| f as usize),
        core::sync::atomic::Ordering::Release,
    );
}

/// The C function an early window of the next fork runs
/// (posix_abi::fork::probe_early_window), once the loader took the first
/// message of Regions.
static EARLY_WINDOW: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn early_window() {
    let hook = EARLY_WINDOW.load(core::sync::atomic::Ordering::Acquire);
    if hook != 0 {
        // SAFETY: only `stafeto_probe_fork_early` stores a value, a C
        // function of no arguments.
        let hook: extern "C" fn() = unsafe { core::mem::transmute::<usize, extern "C" fn()>(hook) };
        hook();
    }
}

/// The C function the next fork runs in the parent once its loader took
/// the first message of Regions, for the probes.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_fork_early(window: Option<extern "C" fn()>) {
    EARLY_WINDOW.store(
        window.map_or(0, |f| f as usize),
        core::sync::atomic::Ordering::Release,
    );
    posix_abi::fork::probe_early_window(window.map(|_| early_window as fn()));
}

/// A word of the process's page (proto_process::Page): 0 the pending
/// signals, 1 those it ignores, 2 those it catches, 3 its flags of
/// SIGCHLD. A bare child may call it.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_page(word: c_int) -> u64 {
    use core::sync::atomic::Ordering::Acquire;
    let page = posix_abi::process::page();
    match word {
        0 => page.pending.load(Acquire),
        1 => page.ignored.load(Acquire),
        2 => page.caught.load(Acquire),
        3 => page.flags.load(Acquire),
        _ => 0,
    }
}

/// The processor to the next thread ready at the caller's level; a bare
/// child may call it.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_yield() {
    let _ = rt::sys::yield_now();
}

/// Waits for good on a channel of its own, for a bare child that lives
/// until it is killed.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_park() -> ! {
    if let Ok(channel) = rt::sys::channel_create(1) {
        loop {
            let _ = rt::sys::receive(&channel);
        }
    }
    rt::sys::process_exit(1)
}

/// A ForkStart whose child never gets its copy
/// (posix_abi::fork::probe_abort): 0 when SpawnCommit and an early
/// ForkCommit were refused, the child's PID in `pid`.
///
/// # Safety
/// `pid` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_probe_fork_abort(pid: *mut c_int) -> c_int {
    let mut child = 0;
    let result =
        call(|| Ok::<_, c_int>(posix_abi::fork::probe_abort(&mut child))).unwrap_or(EINVAL);
    // SAFETY: the caller's promise.
    unsafe { pid.write(child) };
    result
}

/// Holds a lock of the layer for `us` microseconds
/// (posix_abi::fork::probe_hold): 0 the heap's, 1 the files', 2 a bucket's.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_hold(which: c_int, us: u64) -> c_int {
    posix_abi::fork::probe_hold(which as u32, us.saturating_mul(1000))
}

/// The next anonymous mapping of the layer sleeps `us` microseconds first
/// (posix_abi::allocation::probe_sleep_next), for the probe of relibc's
/// allocator across a fork.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_mmap_sleep(us: u64) {
    posix_abi::allocation::probe_sleep_next(us.saturating_mul(1000));
}

/// How many threads the process's table holds
/// (posix_abi::fork::probe_threads).
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_threads() -> c_int {
    posix_abi::fork::probe_threads() as c_int
}

/// The most mappings an object of the layer's map has
/// (posix_abi::fork::probe_mappings).
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_map_mappings() -> u64 {
    posix_abi::fork::probe_mappings()
}

/// The layer's memory map for the probes (posix_abi::allocation::regions):
/// the address, the pages and the access (1 R, 3 RW, 5 RX) of each region,
/// three words each, into `out` for `max` regions at most; the number of
/// regions the map holds, which may exceed `max`.
///
/// # Safety
/// `out` has room for `3 * max` words.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_probe_memory_map(out: *mut u64, max: usize) -> usize {
    posix_abi::allocation::regions(|map| {
        for (i, region) in map.iter().take(max).enumerate() {
            let words = [
                region.address as u64,
                region.pages as u64,
                region.access.raw(),
            ];
            // SAFETY: the caller gives room for `3 * max` words.
            unsafe { out.add(3 * i).copy_from_nonoverlapping(words.as_ptr(), 3) };
        }
        map.len()
    })
}

/// The bytes charged to the process (object_info PROCESS_MEMORY), for the
/// probe that compares them with the memory map; 0 when the call fails.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_memory_used() -> u64 {
    rt::sys::process_memory(posix_abi::allocation::process()).map_or(0, |memory| memory.used)
}

const PAGE: usize = 4096;

/// The anonymous mappings relibc holds: (first page, pages) of each, in
/// pages of the address space (32 bits each reach 16 TiB), 0 pages for a
/// free record. The pages come from the layer's heap (no header), so
/// munmap gives back the whole mapping, pages from either edge, or pages
/// from the middle, which splits the record in two.
const MAPPINGS: usize = 256;
type Records = [(u32, u32); MAPPINGS];
struct Mappings(UnsafeCell<Records>);
// SAFETY: only `mappings` borrows the records, under MAPPINGS_LOCK.
unsafe impl Sync for Mappings {}
static MAPS: Mappings = Mappings(UnsafeCell::new([(0, 0); MAPPINGS]));
static MAPPINGS_LOCK: posix_sync::LayerLock = posix_sync::LayerLock::new();

/// A record of the bytes from `start` to `end`, both page-aligned.
fn record(start: usize, end: usize) -> (u32, u32) {
    ((start / PAGE) as u32, ((end - start) / PAGE) as u32)
}

/// The bytes a record holds: its start and end.
fn bounds((page, pages): (u32, u32)) -> (usize, usize) {
    let start = page as usize * PAGE;
    (start, start + pages as usize * PAGE)
}

fn mappings<R>(f: impl FnOnce(&mut Records) -> R) -> R {
    let _guard = MAPPINGS_LOCK.lock();
    // SAFETY: the lock gives this borrow alone.
    f(unsafe { &mut *MAPS.0.get() })
}

/// Zeroed, page-aligned memory for `len` bytes from the layer's heap, or
/// null, which relibc reports as ENOMEM.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_mmap_anonymous(len: usize) -> *mut c_void {
    let Some(size) = len.checked_next_multiple_of(PAGE).filter(|&size| size != 0) else {
        return ptr::null_mut();
    };
    let Ok(pointer) = posix_abi::allocation::map_pages(size) else {
        return ptr::null_mut();
    };
    let start = pointer.as_ptr() as usize;
    let recorded = mappings(|maps| {
        maps.iter_mut()
            .find(|free| free.1 == 0)
            .map(|free| *free = record(start, start + size))
            .is_some()
    });
    if !recorded {
        // SAFETY: the pages are this call's, and nobody saw them.
        unsafe { posix_abi::allocation::unmap_pages(pointer, size) };
        return ptr::null_mut();
    }
    pointer.as_ptr().cast()
}

/// Unmaps whole pages of a mapping of `stafeto_mmap_anonymous`: all of it,
/// pages from an edge, or pages from the middle. A range that meets no
/// mapping is left alone (POSIX: success); EINVAL for one that is part in
/// a mapping and part outside or across two, ENOMEM when a split finds no
/// free record.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_munmap(addr: *mut c_void, len: usize) -> c_int {
    let start = addr as usize;
    let Some(size) = len.checked_next_multiple_of(PAGE).filter(|&size| size != 0) else {
        return -EINVAL;
    };
    let Some(end) = start
        .checked_add(size)
        .filter(|_| start.is_multiple_of(PAGE))
    else {
        return -EINVAL;
    };
    let result: Result<bool, c_int> = mappings(|maps| {
        let Some(index) = maps.iter().position(|&held| {
            let (first, last) = bounds(held);
            held.1 != 0 && first <= start && end <= last
        }) else {
            let meets = maps.iter().any(|&held| {
                let (first, last) = bounds(held);
                held.1 != 0 && first < end && start < last
            });
            return if meets { Err(EINVAL) } else { Ok(false) };
        };
        let (first, last) = bounds(maps[index]);
        match (start == first, end == last) {
            (true, true) => maps[index] = (0, 0),
            (true, false) => maps[index] = record(end, last),
            (false, true) => maps[index] = record(first, start),
            (false, false) => {
                let free = maps.iter().position(|free| free.1 == 0).ok_or(ENOMEM)?;
                maps[index] = record(first, start);
                maps[free] = record(end, last);
            }
        }
        Ok(true)
    });
    match result {
        Ok(false) => 0,
        Ok(true) => {
            // SAFETY: the pages left the records: relibc gave them up.
            unsafe {
                posix_abi::allocation::unmap_pages(
                    core::ptr::NonNull::new_unchecked(addr.cast()),
                    size,
                )
            };
            0
        }
        Err(errno) => -errno,
    }
}

/// Takes back one of relibc's mappings for the thread table.
fn unmap(address: usize, length: usize) {
    let _ = stafeto_munmap(address as *mut c_void, length);
}

/// A new thread's first instructions: the stack holds what relibc pushed
/// for its clone (the shim, then its arguments, 64 bytes); the shim never
/// returns.
#[unsafe(naked)]
extern "C" fn thread_entry(_id: u64) -> ! {
    core::arch::naked_asm!(
        "ldp x8, x0, [sp], #16",
        "ldp x1, x2, [sp], #16",
        "ldp x3, x4, [sp], #16",
        "ldr x5, [sp], #16",
        "mov x29, xzr",
        "mov x30, xzr",
        "br x8",
    )
}

/// # Safety
/// `stack` is the new thread's, prepared by relibc; `block` is the block of
/// the TCB relibc made for it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_thread_create(stack: *mut usize, block: *mut c_void) -> c_int {
    // SAFETY: the caller's promise.
    match unsafe { posix_abi::relibc::create(thread_entry, stack as usize, block.cast()) } {
        Ok(id) => id as c_int,
        Err(errno) => -errno,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_thread_id() -> c_int {
    posix_abi::relibc::current() as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_thread_started() -> c_int {
    match posix_abi::relibc::started() {
        Ok(()) => 0,
        Err(errno) => -errno,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_thread_leaving() {
    posix_abi::relibc::leaving();
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_thread_release(id: c_int) {
    posix_abi::relibc::release(id as u64);
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_exit_thread(stack: *mut c_void, size: usize) -> ! {
    posix_abi::relibc::exit_thread(stack as usize, size)
}

/// # Safety
/// `addr` is a live aligned word of the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_futex_wait(addr: *mut u32, val: u32, deadline: u64) -> c_int {
    // SAFETY: the caller's promise.
    let word = unsafe { &*addr.cast::<AtomicU32>() };
    let deadline = (deadline != u64::MAX).then_some(deadline);
    match posix_sync::futex_wait(word, val, posix_sync::CLOCK_MONOTONIC, deadline) {
        Ok(_) => 0,
        Err(errno) => -errno,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_futex_wake(addr: *mut u32, count: u32) -> u32 {
    posix_sync::futex_wake(addr.cast::<AtomicU32>(), count)
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_sched_yield() -> c_int {
    let _ = rt::sys::yield_now();
    0
}

/// # Safety
/// `request` is a readable timespec; `remaining` is null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_nanosleep(
    request: *const Timespec,
    remaining: *mut Timespec,
) -> c_int {
    // relibc's nanosleep: 0 or a negated errno.
    // SAFETY: the caller's promise.
    -unsafe { sleep(CLOCK_REALTIME, 0, request, remaining) }
}

/// clock_nanosleep: 0 or an error number.
///
/// # Safety
/// `request` is a readable timespec; `remaining` is null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_clock_nanosleep(
    clock: c_int,
    flags: c_int,
    request: *const Timespec,
    remaining: *mut Timespec,
) -> c_int {
    // SAFETY: the caller's promise.
    unsafe { sleep(clock, flags, request, remaining) }
}

const CLOCK_REALTIME: c_int = 0;

/// A sleep of the layer: 0 or the error number; the time left of a cut
/// relative sleep goes to `remaining`. The clocks and TIMER_ABSTIME are
/// Linux's numbers in both.
///
/// # Safety
/// `request` is a readable timespec; `remaining` is null or writable.
unsafe fn sleep(
    clock: c_int,
    flags: c_int,
    request: *const Timespec,
    remaining: *mut Timespec,
) -> c_int {
    // SAFETY: the caller's promise.
    let Some(requested) = (unsafe { request.as_ref() }).copied() else {
        return EFAULT;
    };
    match call(|| {
        posix_abi::threads::sleep::clock_nanosleep(clock, flags, requested).map_err(
            |(errno, left)| {
                // SAFETY: the caller's promise.
                if let (Some(left), Some(out)) = (left, unsafe { remaining.as_mut() }) {
                    *out = left;
                }
                errno
            },
        )
    }) {
        Ok(()) => 0,
        Err(errno) => errno,
    }
}

/// relibc's cancellation states and types (its pthread.h).
const PTHREAD_CANCEL_ASYNCHRONOUS: c_int = 0;
const PTHREAD_CANCEL_ENABLE: c_int = 1;
const PTHREAD_CANCEL_DEFERRED: c_int = 2;
const PTHREAD_CANCEL_DISABLE: c_int = 3;

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_cancel(id: c_int) -> c_int {
    -posix_abi::relibc::cancel(id as u64)
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_testcancel() -> c_int {
    c_int::from(posix_abi::relibc::testcancel())
}

/// # Safety
/// `old` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_setcancelstate(state: c_int, old: *mut c_int) -> c_int {
    let enabled = match state {
        PTHREAD_CANCEL_ENABLE => true,
        PTHREAD_CANCEL_DISABLE => false,
        _ => return -EINVAL,
    };
    match posix_abi::relibc::set_cancel_enabled(enabled) {
        Ok(was) => {
            let value = if was {
                PTHREAD_CANCEL_ENABLE
            } else {
                PTHREAD_CANCEL_DISABLE
            };
            // SAFETY: the caller's promise.
            unsafe { old.write(value) };
            0
        }
        Err(errno) => -errno,
    }
}

/// # Safety
/// `old` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_setcanceltype(kind: c_int, old: *mut c_int) -> c_int {
    let asynchronous = match kind {
        PTHREAD_CANCEL_ASYNCHRONOUS => true,
        PTHREAD_CANCEL_DEFERRED => false,
        _ => return -EINVAL,
    };
    let was = posix_abi::relibc::set_cancel_asynchronous(asynchronous);
    let value = if was {
        PTHREAD_CANCEL_ASYNCHRONOUS
    } else {
        PTHREAD_CANCEL_DEFERRED
    };
    // SAFETY: the caller's promise.
    unsafe { old.write(value) };
    0
}
