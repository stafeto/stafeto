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
mod ipc;
mod mapping;
mod names;
mod signals;
mod sockets;
mod wait;

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::AtomicU32;
use posix_abi::constants::{EFAULT, EINVAL};
use posix_types::Timespec;

/// The version of the interface of the functions `stafeto_*`; relibc
/// expects the same.
pub const PLATFORM_INTERFACE: u64 = 21;

/// The ABI word relibc checks at start: the size of the block in bits 0
/// to 15, its offset in the TCB in bits 16 to 31, the interface in bits 32
/// to 63.
#[unsafe(no_mangle)]
pub static STAFETO_PLATFORM_ABI: u64 = posix_thread::BLOCK_SIZE as u64
    | (posix_thread::BLOCK_OFFSET as u64) << 16
    | PLATFORM_INTERFACE << 32;

/// Local custody mark before relibc restores a valid main-stack jump target.
/// The caller holds one kernel entry deferral through the actual restoration.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_longjmp_mark_v1(target_sp: u64) {
    posix_abi::shared::jump_mark(target_sp);
}

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
    posix_abi::relibc::configure_cancel(cancelled);
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
    // The layer takes one message of a write to a file or the console at a
    // time; a write of a regular file completes, so the rest goes after a
    // full message. A failure after a part is the count of the part, and a
    // pipe or a terminal, which take all, end the loop at once.
    let mut done = 0;
    loop {
        let rest = &bytes[done..];
        let got = value(call(|| posix_abi::write(fd, rest)).map(|n| n as i64)) as isize;
        if got == posix_request::MAX_WRITE as isize && rest.len() > posix_request::MAX_WRITE {
            done += posix_request::MAX_WRITE;
            continue;
        }
        return if got < 0 && done > 0 {
            done as isize
        } else if got < 0 {
            got
        } else {
            done as isize + got
        };
    }
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
    // A read of a regular file fills the buffer unless the file ends; the
    // layer returns one message of it, so the rest is read after a full
    // message. A pipe, a terminal or a socket return what is there.
    let mut done = 0;
    loop {
        let rest = &mut buffer[done..];
        let size = rest.len();
        let got = value(call(|| posix_abi::read(fd, rest)).map(|n| n as i64)) as isize;
        if got == posix_request::MAX_READ as isize
            && size > posix_request::MAX_READ
            && files::is_file(fd)
        {
            done += posix_request::MAX_READ;
            continue;
        }
        return if got < 0 && done > 0 {
            done as isize
        } else if got < 0 {
            got
        } else {
            done as isize + got
        };
    }
}

/// relibc's open flags (its headers for AArch64 Linux, asm/fcntl.h).
const O_ACCMODE: c_int = 0o3;
const O_CREAT: c_int = 0o100;
const O_EXCL: c_int = 0o200;
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
/// O_DSYNC and O_SYNC (O_RSYNC is O_SYNC): the RAM service has every write
/// done when the call returns, so an open takes the flags and leaves them
/// out of the description.
const O_SYNC_FLAGS: c_int = 0o4010000;

/// O_PATH, as Linux has it: the open only names the place, and the layer
/// takes it as the ordinary read-only open of a directory (htop opens the
/// directory of each CPU so).
const O_PATH_FLAG: c_int = 0o10000000;

/// Translates relibc Open flags into the process-local request interface.
fn open_flags(flags: c_int) -> Result<c_int, c_int> {
    let flags = if flags & O_PATH_FLAG != 0 {
        flags & !O_PATH_FLAG & !O_ACCMODE
    } else {
        flags
    };
    let known = O_ACCMODE
        | O_CREAT
        | O_EXCL
        | O_TRUNC
        | O_APPEND
        | O_NOCTTY
        | O_DIRECTORY
        | O_NOFOLLOW
        | O_LARGEFILE
        | O_CLOEXEC
        | O_CLOFORK
        | O_NONBLOCK
        | O_SYNC_FLAGS;
    if flags & !known != 0 || flags & O_ACCMODE == O_ACCMODE {
        return Err(EINVAL);
    }
    let mut mapped = flags & O_ACCMODE;
    for (native, local) in [
        (O_CREAT, posix_abi::constants::O_CREAT),
        (O_EXCL, posix_abi::constants::O_EXCL),
        (O_TRUNC, posix_abi::constants::O_TRUNC),
        (O_APPEND, posix_abi::constants::O_APPEND),
        (O_NOFOLLOW, posix_abi::constants::O_NOFOLLOW),
        (O_DIRECTORY, posix_abi::constants::O_DIRECTORY),
        (O_CLOEXEC, posix_abi::constants::O_CLOEXEC),
        (O_CLOFORK, posix_abi::constants::O_CLOFORK),
        (O_NOCTTY, posix_abi::constants::O_NOCTTY),
        (O_NONBLOCK, posix_abi::constants::O_NONBLOCK),
    ] {
        if flags & native != 0 {
            mapped |= local;
        }
    }
    Ok(mapped)
}

/// Opens a path with captured mode and umask: an absolute one, one under the
/// current directory (`AT_FDCWD`), or one under the directory `dirfd` names.
///
/// # Safety
/// `path` is a live C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_openat(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: u32,
) -> c_int {
    let mapped = match open_flags(flags) {
        Ok(mapped) => mapped,
        Err(errno) => return -errno,
    };
    // SAFETY: the caller's promise.
    let name = match unsafe { posix_abi::path(path) } {
        Ok(name) => name,
        Err(errno) => return -errno,
    };
    let captured_umask = files::umask();
    value(
        call(|| posix_abi::openat_policy(dirfd, name, mapped, mode, captured_umask)).map(i64::from),
    ) as c_int
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
    mapping::flush_all();
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

/// The processor time of the process, for `clock` (the same figure as
/// `times` and CLOCK_PROCESS_CPUTIME_ID: posix_abi::cpu::process_ns); the
/// time the process has run when the kernel gives no figure.
///
/// # Safety
/// `out` is writable for a timespec.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_clock_process(out: *mut Timespec) -> c_int {
    let (seconds, nanos) = match posix_abi::cpu::process_ns() {
        Ok(ns) => ((ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as _),
        Err(_) => {
            let time = posix_abi::clock::process_time();
            (time.seconds, time.nanos)
        }
    };
    // SAFETY: the caller's promise.
    unsafe {
        out.write(Timespec {
            tv_sec: seconds,
            tv_nsec: nanos,
        })
    };
    0
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
            let word = if let Some(signal) = waited.stopped {
                (i32::from(signal) << 8) | 0x7f
            } else if waited.continued {
                0xffff
            } else {
                waited.end.map_or(0, proto_process::End::wait_status)
            };
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
            if waited.pid != 0 {
                let (code, status) = if let Some(signal) = waited.stopped {
                    (proto_process::CLD_STOPPED, i32::from(signal))
                } else if waited.continued {
                    (proto_process::CLD_CONTINUED, proto_process::SIGCONT as i32)
                } else {
                    match waited.end.expect("a wait report") {
                        End::Exited(code) => (CLD_EXITED, i32::from(code)),
                        End::Signaled(n) => (CLD_KILLED, i32::from(n)),
                    }
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
    /// The spawn-schedpolicy and the sched_priority of spawn-schedparam.
    policy: c_int,
    priority: c_int,
}

/// POSIX_SPAWN_SETSCHEDPARAM and POSIX_SPAWN_SETSCHEDULER (the values of
/// relibc's spawn.h): the layer takes them as the scheduling of the child.
const SPAWN_SETSCHEDPARAM: c_int = 0x10;
const SPAWN_SETSCHEDULER: c_int = 0x20;

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
                mode: a.mode,
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
    unsafe { spawn(path, None, argv, envp, attributes, file_actions, count) }
}

/// posix_spawnp: `file` is a name without a slash. The directories of
/// `search` (the value of PATH; null for no PATH) are searched after the
/// file actions, from the current directory they left.
///
/// # Safety
/// As `stafeto_spawn`; `search` is null or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_spawnp(
    file: *const c_char,
    search: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
    attributes: *const SpawnAttributes,
    file_actions: *const SpawnAction,
    count: usize,
) -> c_int {
    if search.is_null() {
        return -posix_abi::constants::ENOENT;
    }
    // SAFETY: the caller's promise.
    let search = unsafe { bytes_of(search) };
    // SAFETY: the caller's promise.
    unsafe {
        spawn(
            file,
            Some(search),
            argv,
            envp,
            attributes,
            file_actions,
            count,
        )
    }
}

/// # Safety
/// As `stafeto_spawn`.
unsafe fn spawn(
    path: *const c_char,
    search: Option<&[u8]>,
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
    let (flags, pgroup) = attributes.map_or((0, 0), |a| {
        (
            a.flags & !(SPAWN_SETSCHEDPARAM | SPAWN_SETSCHEDULER),
            a.pgroup,
        )
    });
    // The policy of the child: the attribute under SETSCHEDULER, else the
    // caller's own (XSH posix_spawn) with the priority of SETSCHEDPARAM.
    let sched = attributes.and_then(|a| {
        if a.flags & SPAWN_SETSCHEDULER != 0 {
            Some((a.policy, a.priority))
        } else if a.flags & SPAWN_SETSCHEDPARAM != 0 {
            let own = posix_abi::sched::own_policy();
            Some((own, a.priority))
        } else {
            None
        }
    });
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
        sched,
    };
    // SAFETY: the caller's promise for argv, envp and the file actions.
    let (argv, envp, file_actions) =
        unsafe { (strings(argv), strings(envp), actions(file_actions, count)) };
    match call(|| {
        posix_abi::process::spawn_search(
            path,
            search,
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
    mapping::flush_all();
    match call(|| posix_abi::process::exec(path, argv.clone(), envp.clone(), umask)) {
        Ok(never) => match never {},
        Err(errno) => -errno,
    }
}

/// Execute one retained file description, returning only a negated errno.
///
/// # Safety
/// `argv` and `envp` are null or NULL-ended arrays of C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_fexecve(
    fd: c_int,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    // SAFETY: the caller's promise.
    let (argv, envp) = unsafe { (strings(argv), strings(envp)) };
    let umask = files::umask();
    mapping::flush_all();
    match call(|| posix_abi::process::fexec(fd, argv.clone(), envp.clone(), umask)) {
        Ok(never) => match never {},
        Err(errno) => -errno,
    }
}

/// fork (posix_abi::fork::fork): the child's PID in the parent, 0 in the
/// child, or the negated errno. The window a probe set
/// (`stafeto_probe_fork_window`) runs in the parent before ForkCommit.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_fork() -> c_int {
    // The child reads the files as the shared mappings of the parent show
    // them.
    mapping::flush_files();
    let set = FORK_WINDOW.load(core::sync::atomic::Ordering::Acquire) != 0;
    let window = set.then_some(fork_window as fn());
    match call(|| posix_abi::fork::fork_held(window)) {
        Ok(pid) => pid,
        Err(errno) => -errno,
    }
}

/// The end of fork for relibc, after it let go of its locks: the signals
/// that came while fork held them are delivered.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_fork_done() {
    posix_abi::fork::deliver_after_fork();
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

/// A SpawnStart whose load waits for the parent, for the probe of the waits
/// of other clients (posix_abi::process::probe_load_start): its errno, and
/// the child's PID in `pid`.
///
/// # Safety
/// `pid` points to an int.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_probe_load_start(place: c_int, pid: *mut c_int) -> c_int {
    let mut child = -1;
    let errno = posix_abi::process::probe_load_start(place as usize, &mut child);
    // SAFETY: the caller's promise.
    unsafe { pid.write(child) };
    errno
}

/// SpawnAbort of that load (posix_abi::process::probe_load_abort).
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_load_abort(place: c_int, pid: c_int) -> c_int {
    posix_abi::process::probe_load_abort(place as usize, pid)
}

/// The loads the calling record may have at once
/// (posix_abi::process::probe_loads).
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_loads() -> c_int {
    posix_abi::process::probe_loads()
}

/// TtySignal through the process's own session
/// (posix_abi::process::probe_tty_signal): the errno of the refusal.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_tty_signal(pgid: c_int, signal: c_int) -> c_int {
    posix_abi::process::probe_tty_signal(pgid as u32, signal as u32)
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

/// PID at an explicitly installed fork loader window, for regression probes.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_loading_pid() -> c_int {
    posix_abi::fork::probe_loading_pid() as c_int
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

/// Waits with entries deferred for another thread to stop the process and
/// parks, with the stopper's request pending, as `deliver_now` does
/// (posix_abi::signals::probe_park_now).
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_park_now() {
    posix_abi::signals::probe_park_now();
}

/// The calling thread's next wait at `site` (1 poll, 2 open of a FIFO, 3
/// wait by address, 4 sigwait) stops after its last check until it has
/// parked for a stop of another thread (posix_abi::signals::probe_window_arm).
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_window(site: c_int) {
    posix_abi::signals::probe_window_arm(site as u32);
}

/// Whether the wait `stafeto_probe_window` armed stands at its site (1) or
/// not yet (0).
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_window_reached() -> c_int {
    posix_abi::signals::probe_window_reached() as c_int
}

/// The next anonymous mapping of the layer sleeps `us` microseconds first
/// (posix_abi::allocation::probe_sleep_next), for the probe of relibc's
/// allocator across a fork.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_mmap_sleep(us: u64) {
    posix_abi::allocation::probe_sleep_next(us.saturating_mul(1000));
}

/// An actual mapping consumed the allocator sleep probe.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_mmap_sleep_entered() -> c_int {
    i32::from(posix_abi::allocation::probe_sleep_entered())
}

/// How many threads the process's table holds
/// (posix_abi::fork::probe_threads).
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_threads() -> c_int {
    posix_abi::fork::probe_threads() as c_int
}

/// The key of the shared memory of the file with this device and inode, for
/// the probes of the process service's rendezvous.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_share_key(device: u64, inode: u64) -> u64 {
    posix_abi::shares::key_of(device, inode)
}

/// A Get of the rendezvous for `key` with no vouching of a file service
/// first: 0 when it answered, else the errno.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_share_get(key: u64) -> c_int {
    match posix_abi::shares::get(key) {
        Ok(_) => 0,
        Err(errno) => errno,
    }
}

/// The vouching of the file service for the file of `fd` (ShareGrant): 0, or
/// the errno.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_share_grant(fd: c_int) -> c_int {
    match posix_abi::shares::grant(fd) {
        Ok(()) => 0,
        Err(errno) => errno,
    }
}

/// A process with the file of `fd` open (vouched for) hands the rendezvous
/// an object of its own as the shared memory of the file, as a forked
/// child does: 0 when it did, else the errno.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_share_plant(fd: c_int, key: u64) -> c_int {
    if let Err(errno) = posix_abi::shares::grant(fd) {
        return errno;
    }
    let Ok(object) = rt::sys::mem_create(4096) else {
        return 12;
    };
    match posix_abi::shares::attach(key, 1, &object) {
        Ok(()) => 0,
        Err(errno) => errno,
    }
}

/// Vouched for the file of `fd`, asks the rendezvous for its object and tries
/// to map it for writing past the layer at a free address: 0 when the
/// kernel mapped it, 100 + errno when the rendezvous gave none, else 200 + the
/// kernel's error.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_share_map_write(fd: c_int, key: u64) -> c_int {
    use posix_abi::shares::Got;
    if let Err(errno) = posix_abi::shares::grant(fd) {
        return 100 + errno;
    }
    let memory = match posix_abi::shares::get(key) {
        Ok(Got::Found(memory, _)) => memory,
        Ok(_) => return 101,
        Err(errno) => return 100 + errno,
    };
    let process = posix_abi::allocation::process();
    match rt::sys::mem_map(
        process,
        &memory,
        0,
        4096,
        0x3000_0000,
        rt::abi::Access::ReadWrite,
    ) {
        Ok(()) => {
            // SAFETY: the mapping was made just now, and nothing uses it.
            let _ = unsafe { rt::sys::mem_unmap(process, 0x3000_0000, 4096) };
            0
        }
        Err(_) => 200,
    }
}

/// The shared objects the layer's map holds (posix_abi::fork::probe_shared_objects).
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_shared_objects() -> u64 {
    posix_abi::fork::probe_shared_objects()
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
                region.pages() as u64,
                region.access().raw(),
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

/// The actual process memory ceiling used by the quota exhaustion probe.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_memory_quota() -> u64 {
    rt::sys::process_memory(posix_abi::allocation::process()).map_or(0, |memory| memory.quota)
}

/// Takes back one of relibc's mappings for the thread table.
fn unmap(address: usize, length: usize) {
    let _ = mapping::stafeto_munmap(address as *mut c_void, length);
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

/// The stack of a new thread: `size` bytes with `guard` bytes of hole below
/// them (no mapping, no memory). The lowest address of the stack, or the
/// negated errno. `munmap` of the stack and its guard together gives both
/// back.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_stack_map(size: usize, guard: usize) -> isize {
    match posix_abi::mmap::stack_map(size, guard) {
        Ok(address) => address as isize,
        Err(errno) => -(errno as isize),
    }
}

/// Frees the stacks and blocks of the threads that ended and were released,
/// for a `pthread_create` that found no memory for its own.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_collect() {
    let _ = posix_abi::relibc::collect();
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
    let before = posix_sync::clear_no_restart();
    let waited = posix_sync::futex_wait(word, val, posix_sync::CLOCK_MONOTONIC, deadline);
    let ran = posix_sync::interrupted(before);
    cancel_if_asynchronous();
    match waited {
        // A handler without SA_RESTART ran during the wait: the caller may
        // report EINTR (sem_wait); the others look at their word again.
        Ok(posix_sync::Woken::Entry) if ran => -posix_sync::EINTR,
        Ok(_) => 0,
        Err(errno) => -errno,
    }
}

unsafe extern "C" {
    /// relibc's pthread_exit.
    fn pthread_exit(value: *mut c_void) -> !;
}

/// What ends a thread that asynchronous cancellation reaches:
/// pthread_exit(PTHREAD_CANCELED).
fn cancelled() -> ! {
    // SAFETY: pthread_exit never returns; PTHREAD_CANCELED is (void *)-1.
    unsafe { pthread_exit(usize::MAX as *mut c_void) }
}

/// A wait of the platform that a request of cancellation ended: a thread
/// with asynchronous cancellation enabled ends here.
fn cancel_if_asynchronous() {
    if posix_abi::relibc::async_cancel_due() {
        posix_abi::relibc::cancel_exit();
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

/// getrusage: the time of the process (`who` 0, RUSAGE_SELF), of its
/// children that were waited for (-1) or of the calling thread (1) in
/// nanoseconds, or a negated errno.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_cpu_ns(who: c_int) -> i64 {
    let ns = match who {
        0 => posix_abi::cpu::process_ns(),
        -1 => call(posix_abi::cpu::children_ns),
        1 => posix_abi::cpu::thread_ns(),
        _ => Err(EINVAL),
    };
    ns.map_or_else(
        |errno| -i64::from(errno),
        |ns| ns.min(i64::MAX as u64) as i64,
    )
}

/// The part of the time `stafeto_cpu_ns` gives for `who` that was spent in
/// the kernel (the system time of getrusage and times), in nanoseconds, or a
/// negated errno; the rest is the user time.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_cpu_system_ns(who: c_int) -> i64 {
    let split = match who {
        0 => posix_abi::cpu::process_split_ns(),
        -1 => call(posix_abi::cpu::children_split_ns),
        1 => posix_abi::cpu::thread_split_ns(),
        _ => Err(EINVAL),
    };
    split.map_or_else(
        |errno| -i64::from(errno),
        |(_, system)| system.min(i64::MAX as u64) as i64,
    )
}

/// getrusage and times: the user and the system time of `who` (0, 1 and -1
/// as in `stafeto_cpu_ns`) in nanoseconds from one reading of the kernel, or
/// a negated errno. The two parts of separate readings drift apart by what
/// the kernel counts between them: a host that stalls the guest there moves
/// that time from the user part to the system part, and the user time of a
/// later reading may fall below an earlier one.
///
/// # Safety
/// `user` and `system` are writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_cpu_split_ns(
    who: c_int,
    user: *mut u64,
    system: *mut u64,
) -> c_int {
    let split = match who {
        0 => posix_abi::cpu::process_split_ns(),
        -1 => call(posix_abi::cpu::children_split_ns),
        1 => posix_abi::cpu::thread_split_ns(),
        _ => Err(EINVAL),
    };
    match split {
        Ok((u, s)) => {
            // SAFETY: the caller's promise.
            unsafe {
                user.write(u);
                system.write(s);
            }
            0
        }
        Err(errno) => -errno,
    }
}

/// pthread_getcpuclockid: the id of the CPU-time clock of thread `tid`.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_thread_cpu_clock(tid: c_int) -> c_int {
    posix_abi::cpu::thread_clock(tid as u64)
}

/// getpriority: 20 minus the nice value (1 to 40) of the process(es) named
/// by `which` and `who`, or a negated errno.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_getpriority(which: c_int, who: u32) -> c_int {
    call(|| posix_abi::cpu::nice_get(which as u32, who))
        .map_or_else(|errno| -errno, |nice| 20 - nice)
}

/// setpriority: `nice` for the process(es) named by `which` and `who`.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_setpriority(which: c_int, who: u32, nice: c_int) -> c_int {
    call(|| posix_abi::cpu::nice_set(which as u32, who, nice)).map_or_else(|errno| -errno, |()| 0)
}

/// sched_get_priority_min (`max` 0) and sched_get_priority_max (`max` 1):
/// the priority, or a negated errno.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_sched_priority_range(policy: c_int, max: c_int) -> c_int {
    posix_abi::sched::priority_range(policy, max != 0).unwrap_or_else(|errno| -errno)
}

/// sched_getscheduler: the policy of the process, or a negated errno.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_sched_getscheduler(pid: c_int) -> c_int {
    call(|| posix_abi::sched::getscheduler(pid)).unwrap_or_else(|errno| -errno)
}

/// sched_getparam: the priority of the process into `priority`.
///
/// # Safety
/// `priority` points to an int.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_sched_getparam(pid: c_int, priority: *mut c_int) -> c_int {
    match call(|| posix_abi::sched::getparam(pid)) {
        Ok(value) => {
            // SAFETY: the caller's promise.
            unsafe { priority.write(value) };
            0
        }
        Err(errno) => -errno,
    }
}

/// sched_setscheduler (a policy) and sched_setparam (a negative policy):
/// the process's old policy, or a negated errno.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_sched_set(pid: c_int, policy: c_int, priority: c_int) -> c_int {
    call(|| posix_abi::sched::set(pid, policy, priority)).unwrap_or_else(|errno| -errno)
}

/// The CPUs that are up (sysconf `_SC_NPROCESSORS_CONF` and
/// `_SC_NPROCESSORS_ONLN`), at least 1.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_cpu_count() -> c_int {
    posix_abi::cpus::count() as c_int
}

/// The CPU the calling thread runs on (sched_getcpu).
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_cpu_current() -> c_int {
    posix_abi::cpus::current() as c_int
}

/// sched_getaffinity: the mask of the process `pid` into `size` bytes at
/// `mask`, or a negated errno.
///
/// # Safety
/// `mask` points to `size` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_sched_getaffinity(
    pid: c_int,
    size: usize,
    mask: *mut u8,
) -> c_int {
    // SAFETY: the caller's promise.
    let out = unsafe { core::slice::from_raw_parts_mut(mask, size) };
    posix_abi::cpus::getaffinity(pid, out).map_or_else(|errno| -errno, |()| 0)
}

/// sched_setaffinity: the mask of the process `pid` from `size` bytes at
/// `mask`, or a negated errno.
///
/// # Safety
/// `mask` points to `size` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_sched_setaffinity(
    pid: c_int,
    size: usize,
    mask: *const u8,
) -> c_int {
    // SAFETY: the caller's promise.
    let bytes = unsafe { core::slice::from_raw_parts(mask, size) };
    posix_abi::cpus::setaffinity(pid, bytes).map_or_else(|errno| -errno, |()| 0)
}

/// pthread_getschedparam of the thread `tid`.
///
/// # Safety
/// `policy` and `priority` point to ints.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_thread_sched_get(
    tid: c_int,
    policy: *mut c_int,
    priority: *mut c_int,
) -> c_int {
    match posix_abi::sched::thread_get(tid as u64) {
        Ok((kind, value)) => {
            // SAFETY: the caller's promise.
            unsafe {
                policy.write(kind);
                priority.write(value);
            }
            0
        }
        Err(errno) => -errno,
    }
}

/// pthread_setschedparam (`tail` 1) and pthread_setschedprio (`tail` 0,
/// a negative policy) of the thread `tid`.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_thread_sched_set(
    tid: c_int,
    policy: c_int,
    priority: c_int,
    tail: c_int,
) -> c_int {
    posix_abi::sched::thread_set(tid as u64, policy, priority, tail != 0)
        .map_or_else(|errno| -errno, |_| 0)
}

/// The policy and priority of the thread the caller makes next
/// (PTHREAD_EXPLICIT_SCHED); a negative policy forgets them.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_thread_next_sched(policy: c_int, priority: c_int) -> c_int {
    posix_abi::sched::next_sched(policy, priority).map_or_else(|errno| -errno, |()| 0)
}

/// futex_wait for a mutex of PTHREAD_PRIO_INHERIT that the thread `owner`
/// holds.
///
/// # Safety
/// `addr` is a live aligned word of the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_futex_wait_pi(
    addr: *mut u32,
    val: u32,
    deadline: u64,
    owner: u32,
) -> c_int {
    // SAFETY: the caller's promise.
    let word = unsafe { &*addr.cast::<AtomicU32>() };
    let deadline = (deadline != u64::MAX).then_some(deadline);
    let waited =
        posix_abi::sched::futex_wait_pi(word, val, posix_sync::CLOCK_MONOTONIC, deadline, owner);
    cancel_if_asynchronous();
    match waited {
        Ok(_) => 0,
        Err(errno) => -errno,
    }
}

/// The unlock of a mutex of PTHREAD_PRIO_INHERIT: the waiters' levels go
/// off the caller, then up to `count` wake.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_futex_wake_pi(addr: *mut u32, count: u32) -> u32 {
    posix_abi::sched::futex_wake_pi(addr.cast::<AtomicU32>(), count)
}

/// The caller takes a mutex of PTHREAD_PRIO_PROTECT of ceiling `priority`.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_protect_enter(priority: c_int) -> c_int {
    posix_abi::sched::protect_enter(priority).map_or_else(|errno| -errno, |()| 0)
}

/// The caller let a mutex of PTHREAD_PRIO_PROTECT of ceiling `priority` go.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_protect_leave(priority: c_int) {
    posix_abi::sched::protect_leave(priority);
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
            // A request that waited for the state to be enabled acts now
            // when the type is asynchronous.
            cancel_if_asynchronous();
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
    // A request that came before the asynchronous type acts now (XSH 2.9.5.1).
    cancel_if_asynchronous();
    0
}

/// Controls the loader channel functional probe.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_loader_start(mode: u32) -> c_int {
    posix_abi::loader_probe::start(mode)
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_loader_listen() -> u32 {
    posix_abi::loader_probe::listen()
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_loader_stop() -> u32 {
    posix_abi::loader_probe::stop()
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_loader_disable() {
    posix_abi::loader_probe::disable();
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_loader_full(slot: u32) -> c_int {
    posix_abi::loader_probe::full(slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_loader_bundle(mode: u32) {
    posix_abi::loader_probe::bundle_mode(mode);
}
