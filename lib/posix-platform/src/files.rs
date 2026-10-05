// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Files, directories and the process's identity for relibc's stafeto
//! platform: relibc's numbers and structures (its headers for Linux
//! AArch64: struct stat of asm-generic, dirent64, struct termios, struct
//! utsname, struct rlimit) on the layer's files (posix-fs).

use super::{call, value};
use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::mem::{offset_of, size_of};
use core::sync::atomic::{AtomicU32, Ordering};
use posix_abi::constants::{EBADF, EFAULT, EINVAL, ENOSYS, ESPIPE};
use posix_fs::{DescriptorFlags, FileKind, NodeInfo, SeekFrom, Target, Transport};

/// relibc's struct stat on AArch64 Linux (asm-generic/stat.h).
#[repr(C)]
pub struct LinuxStat {
    dev: u64,
    ino: u64,
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u64,
    pad1: u64,
    size: i64,
    blksize: i32,
    pad2: i32,
    blocks: i64,
    atime: [i64; 2],
    mtime: [i64; 2],
    ctime: [i64; 2],
    unused: [u32; 2],
}
const _: () = {
    assert!(size_of::<LinuxStat>() == 128);
    assert!(offset_of!(LinuxStat, mode) == 16);
    assert!(offset_of!(LinuxStat, nlink) == 20);
    assert!(offset_of!(LinuxStat, size) == 48);
    assert!(offset_of!(LinuxStat, blksize) == 56);
    assert!(offset_of!(LinuxStat, blocks) == 64);
    assert!(offset_of!(LinuxStat, atime) == 72);
    assert!(offset_of!(LinuxStat, ctime) == 104);
};

/// The file type bits of st_mode.
const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;
const S_IFCHR: u32 = 0o020_000;
const S_IFIFO: u32 = 0o010_000;
/// Linux's dirent64 d_type.
const DT_FIFO: u8 = 1;
const DT_CHR: u8 = 2;
const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;
/// relibc's (Linux's) AT_ values.
const AT_FDCWD: c_int = -100;
const AT_EMPTY_PATH: c_int = 0x1000;

fn time(ns: u64) -> [i64; 2] {
    [(ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as i64]
}

fn linux_stat(info: &NodeInfo) -> LinuxStat {
    let kind = match info.kind {
        1 => S_IFDIR,
        2 => S_IFREG,
        posix_fs::FIFO => S_IFIFO,
        _ => S_IFCHR,
    };
    LinuxStat {
        dev: info.device,
        ino: info.inode,
        mode: kind | (info.permissions & 0o7777),
        nlink: info.links as u32,
        uid: info.uid,
        gid: info.gid,
        rdev: info.special_device,
        pad1: 0,
        size: info.size as i64,
        blksize: info.block_size as i32,
        pad2: 0,
        blocks: info.blocks as i64,
        atime: time(info.access_ns),
        mtime: time(info.modify_ns),
        ctime: time(info.change_ns),
        unused: [0; 2],
    }
}

fn number(fd: c_int) -> Result<u32, c_int> {
    u32::try_from(fd).map_err(|_| EBADF)
}

/// The bytes of a C string, without its NUL.
///
/// # Safety
/// `path` is a live C string.
unsafe fn bytes<'a>(path: *const c_char) -> &'a [u8] {
    // SAFETY: the caller's promise.
    unsafe { core::ffi::CStr::from_ptr(path) }.to_bytes()
}

/// fstat (`path` null or empty with AT_EMPTY_PATH), stat and lstat (no
/// symbolic links yet) in relibc's struct stat.
///
/// # Safety
/// `path` is null or a live C string; `out` is writable for a LinuxStat.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_fstatat(
    fd: c_int,
    path: *const c_char,
    out: *mut LinuxStat,
    flags: c_int,
) -> c_int {
    if out.is_null() {
        return -EFAULT;
    }
    // SAFETY: the caller's promise.
    let path = (!path.is_null()).then(|| unsafe { bytes(path) });
    use posix_abi::shared::{held, resolved};
    let info = match path {
        Some(path) if !path.is_empty() => {
            if fd != AT_FDCWD && path.first() != Some(&b'/') {
                Err(ENOSYS)
            } else {
                resolved(path, |transport, path| {
                    transport.stat_information(path).map_err(posix_abi::error)
                })
            }
        }
        _ if path.is_none() || flags & AT_EMPTY_PATH != 0 => number(fd).and_then(|fd| {
            held(fd, |transport, target| {
                transport
                    .descriptor_information(target)
                    .map_err(posix_abi::error)
            })
        }),
        _ => Err(posix_abi::constants::ENOENT),
    };
    match info {
        Ok(info) => {
            // SAFETY: the caller's promise.
            unsafe { out.write(linux_stat(&info)) };
            0
        }
        Err(errno) => -errno,
    }
}

/// Writes one dirent64 record at `out`, `reclen` bytes; false when it
/// does not fit.
fn record(out: &mut [u8], inode: u64, next: i64, kind: u8, name: &[u8]) -> Option<usize> {
    // ino 8, off 8, reclen 2, type 1, the name and its NUL; 8-byte steps.
    let length = (19 + name.len() + 1).next_multiple_of(8);
    let record = out.get_mut(..length)?;
    record.fill(0);
    record[..8].copy_from_slice(&inode.to_ne_bytes());
    record[8..16].copy_from_slice(&next.to_ne_bytes());
    record[16..18].copy_from_slice(&(length as u16).to_ne_bytes());
    record[18] = kind;
    record[19..19 + name.len()].copy_from_slice(name);
    Some(length)
}

fn entries(files: Transport, fd: Target, out: &mut [u8], position: u64) -> Result<usize, c_int> {
    let error = posix_abi::error;
    if files.fstat(fd).map_err(error)?.kind != FileKind::Directory {
        return Err(posix_abi::error(posix_fs::FsError::NotDirectory));
    }
    let position = i64::try_from(position).map_err(|_| EINVAL)?;
    files.lseek(fd, position, SeekFrom::Start).map_err(error)?;
    let mut used = 0;
    loop {
        let before = files.lseek(fd, 0, SeekFrom::Current).map_err(error)?;
        let mut name = [0u8; 256];
        let Some(entry) = files.readdir(fd, &mut name).map_err(error)? else {
            break;
        };
        let after = files.lseek(fd, 0, SeekFrom::Current).map_err(error)?;
        let kind = match entry.kind {
            FileKind::Directory => DT_DIR,
            FileKind::Regular => DT_REG,
            FileKind::Character => DT_CHR,
            FileKind::Fifo => DT_FIFO,
        };
        let name = &name[..entry.name_len.min(name.len())];
        match record(&mut out[used..], entry.inode, after, kind, name) {
            Some(length) => used += length,
            None => {
                // The next call takes this entry again.
                files.lseek(fd, before, SeekFrom::Start).map_err(error)?;
                if used == 0 {
                    return Err(EINVAL);
                }
                break;
            }
        }
    }
    Ok(used)
}

/// Linux dirent64 records of directory `fd` from `position` (the d_off of
/// the last record relibc took, a position of the descriptor): how many
/// bytes, 0 at the end.
///
/// # Safety
/// `buf` is writable for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_getdents(
    fd: c_int,
    buf: *mut u8,
    len: usize,
    position: u64,
) -> isize {
    // SAFETY: the caller's promise.
    let out = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    let result = number(fd).and_then(|fd| {
        posix_abi::shared::held(fd, |transport, target| {
            entries(transport, target, out, position)
        })
    });
    match result {
        Ok(used) => used as isize,
        Err(errno) => -(errno as isize),
    }
}

/// pread and pwrite: at `offset`, the description's own offset as it
/// was (READ_AT and WRITE_AT of the service), outside the lock.
fn at_offset(
    fd: c_int,
    offset: i64,
    run: impl FnOnce(Transport, u32, u64) -> Result<usize, posix_fs::FsError>,
) -> isize {
    let result = number(fd).and_then(|fd| {
        posix_abi::shared::held(fd, |transport, target| {
            // The console has no offset: ESPIPE.
            let Target::Ram(fd) = target else {
                return Err(ESPIPE);
            };
            let offset = u64::try_from(offset).map_err(|_| EINVAL)?;
            run(transport, fd.fd(), offset).map_err(posix_abi::error)
        })
    });
    match result {
        Ok(count) => count as isize,
        Err(errno) => -(errno as isize),
    }
}

/// # Safety
/// `buf` is writable for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_pread(fd: c_int, buf: *mut u8, len: usize, offset: i64) -> isize {
    // SAFETY: the caller's promise.
    let out = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    at_offset(fd, offset, |files, fd, at| files.read_at(fd, at, out))
}

/// # Safety
/// `buf` is readable for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_pwrite(
    fd: c_int,
    buf: *const u8,
    len: usize,
    offset: i64,
) -> isize {
    // SAFETY: the caller's promise.
    let bytes = unsafe { core::slice::from_raw_parts(buf, len) };
    at_offset(fd, offset, |files, fd, at| files.write_at(fd, at, bytes))
}

/// # Safety
/// `buf` is writable for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_getcwd(buf: *mut u8, len: usize) -> c_int {
    if len == 0 {
        return -EINVAL;
    }
    if buf.is_null() {
        return -EFAULT;
    }
    // SAFETY: the caller's promise.
    let buffer = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    value(call(|| posix_abi::getcwd(buffer)).map(|_| 0)) as c_int
}

/// # Safety
/// `path` is a live C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_chdir(path: *const c_char) -> c_int {
    // SAFETY: the caller's promise.
    let name = match unsafe { posix_abi::path(path) } {
        Ok(name) => name,
        Err(errno) => return -errno,
    };
    value(call(|| posix_abi::chdir(name)).map(|()| 0)) as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_dup(fd: c_int) -> c_int {
    value(call(|| posix_abi::dup(fd)).map(i64::from)) as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_dup2(fd: c_int, target: c_int) -> c_int {
    value(call(|| posix_abi::dup2(fd, target)).map(i64::from)) as c_int
}

/// relibc's fcntl commands (Linux's).
const F_DUPFD: c_int = 0;
const F_GETFD: c_int = 1;
const F_SETFD: c_int = 2;
const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;
/// The status flags F_SETFL cannot take yet (Linux's O_APPEND, O_NONBLOCK)
/// but on a pipe, whose O_NONBLOCK it sets.
const UNSUPPORTED_STATUS: u64 = 0o2000 | 0o4000;
const F_DUPFD_CLOEXEC: c_int = 1030;
/// relibc's F_DUPFD_CLOFORK of stafeto (POSIX 2024; Linux has none).
const F_DUPFD_CLOFORK: c_int = 1100;
/// relibc's FD_CLOEXEC (its fcntl.h), which differs from Linux's 1: both
/// are taken, relibc's comes back.
const FD_CLOEXEC: c_int = 0x8_0000;
const LINUX_FD_CLOEXEC: c_int = 1;
/// relibc's FD_CLOFORK of stafeto (POSIX 2024; Linux has none).
const FD_CLOFORK: c_int = 0x100_0000;
/// Access modes for F_GETFL.
const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
const O_RDWR: c_int = 2;

/// fcntl: F_DUPFD, F_DUPFD_CLOEXEC and F_DUPFD_CLOFORK (the lowest free
/// number from the argument), F_GETFD and F_SETFD (close-on-exec and
/// close-on-fork), F_GETFL (the access
/// mode by the descriptor's kind: the console's input reads, its output
/// writes, a file of the service reads and writes as the service allows,
/// an end of a pipe reads or writes with its O_NONBLOCK),
/// F_SETFL with no flag to change (0; O_APPEND and O_NONBLOCK are
/// EINVAL) and O_NONBLOCK of a pipe's end (O_APPEND ignored there); EINVAL
/// for the rest.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_fcntl(fd: c_int, command: c_int, argument: u64) -> c_int {
    // A pipe's status flags are its description's, in the pipe service:
    // the request goes outside the lock of the files.
    if command == F_GETFL || command == F_SETFL {
        let set = (command == F_SETFL).then_some(argument as c_int);
        match call(|| posix_abi::pipe_status_flags(fd, set)) {
            Ok(Some(flags)) => return flags,
            Ok(None) => {}
            Err(errno) => return -errno,
        }
    }
    let result = posix_abi::shared::with_files(|files| {
        let error = posix_abi::error;
        let fd = number(fd)?;
        match command {
            F_DUPFD | F_DUPFD_CLOEXEC | F_DUPFD_CLOFORK => {
                let minimum = u32::try_from(argument).map_err(|_| EINVAL)?;
                let flags = DescriptorFlags {
                    close_on_exec: command == F_DUPFD_CLOEXEC,
                    close_on_fork: command == F_DUPFD_CLOFORK,
                };
                files
                    .dup_from(fd, minimum, flags)
                    .map(|new| new as c_int)
                    .map_err(error)
            }
            F_GETFD => {
                let flags = files.descriptor_flags(fd).map_err(error)?;
                let exec = if flags.close_on_exec { FD_CLOEXEC } else { 0 };
                let fork = if flags.close_on_fork { FD_CLOFORK } else { 0 };
                Ok(exec | fork)
            }
            F_SETFD => {
                let mut flags = files.descriptor_flags(fd).map_err(error)?;
                flags.close_on_exec = argument as c_int & (FD_CLOEXEC | LINUX_FD_CLOEXEC) != 0;
                flags.close_on_fork = argument as c_int & FD_CLOFORK != 0;
                files.set_descriptor_flags(fd, flags).map_err(error)?;
                Ok(0)
            }
            F_GETFL => {
                files.descriptor_flags(fd).map_err(error)?;
                Ok(if files.console_input(fd).map_err(error)? {
                    O_RDONLY
                } else if files.console_route(fd).map_err(error)?.is_some() {
                    O_WRONLY
                } else {
                    O_RDWR
                })
            }
            F_SETFL => {
                files.descriptor_flags(fd).map_err(error)?;
                if argument & UNSUPPORTED_STATUS != 0 {
                    return Err(EINVAL);
                }
                Ok(0)
            }
            _ => Err(EINVAL),
        }
    });
    result.unwrap_or_else(|errno| -errno)
}

/// relibc's struct termios (Linux): four flag words, the line, 32 control
/// characters, two speeds.
#[repr(C)]
struct Termios {
    iflag: u32,
    oflag: u32,
    cflag: u32,
    lflag: u32,
    line: u8,
    cc: [u8; 32],
    ispeed: u32,
    ospeed: u32,
}
const _: () = {
    assert!(size_of::<Termios>() == 60);
    assert!(offset_of!(Termios, line) == 16);
    assert!(offset_of!(Termios, cc) == 17);
    assert!(offset_of!(Termios, ispeed) == 52);
    assert!(offset_of!(Termios, ospeed) == 56);
    // The service's settings are this less the line, which no POSIX
    // interface names (proto_tty asserts the numbers of the flags and the
    // control characters, and relibc asserts them on its side).
    assert!(proto_tty::NCCS == 32 && proto_tty::TERMIOS_LEN == 56);
};

impl Termios {
    fn of(t: &proto_tty::Termios) -> Termios {
        Termios {
            iflag: t.iflag,
            oflag: t.oflag,
            cflag: t.cflag,
            lflag: t.lflag,
            line: 0,
            cc: t.cc,
            ispeed: t.ispeed,
            ospeed: t.ospeed,
        }
    }

    fn settings(&self) -> proto_tty::Termios {
        proto_tty::Termios {
            iflag: self.iflag,
            oflag: self.oflag,
            cflag: self.cflag,
            lflag: self.lflag,
            cc: self.cc,
            ispeed: self.ispeed,
            ospeed: self.ospeed,
        }
    }
}

/// The ioctl requests of Linux that relibc's termios functions send
/// (sys/ioctl.h): TCSETS + 1 and + 2 are the waiting and the flushing
/// forms.
const TCGETS: c_ulong = 0x5401;
const TCSETS: c_ulong = 0x5402;
const TCSETSW: c_ulong = 0x5403;
const TCSETSF: c_ulong = 0x5404;
const TCSBRK: c_ulong = 0x5409;
const TCXONC: c_ulong = 0x540A;
const TCFLSH: c_ulong = 0x540B;
const TIOCSCTTY: c_ulong = 0x540E;
const TIOCNOTTY: c_ulong = 0x5422;
const TIOCGWINSZ: c_ulong = 0x5413;
const TIOCSWINSZ: c_ulong = 0x5414;
const TIOCGPTN: c_ulong = 0x80045430;
const TIOCSPTLCK: c_ulong = 0x40045431;
const TIOCGPGRP: c_ulong = 0x540F;
const TIOCSPGRP: c_ulong = 0x5410;
const TIOCGSID: c_ulong = 0x5429;
const _: () = assert!(TCSETSW - TCSETS == proto_tty::DRAIN as c_ulong);
const _: () = assert!(TCSETSF - TCSETS == proto_tty::FLUSH as c_ulong);
const ENOTTY: c_int = 25;

/// An ioctl on terminal `terminal` of the terminal service: tcgetattr and
/// tcsetattr (TCGETS, TCSETS, TCSETSW, TCSETSF), tcflush (TCFLSH, the
/// queue in `argument`), tcflow (TCXONC, the action there), tcdrain
/// (TCSBRK with an argument) and tcsendbreak (TCSBRK with 0: the
/// console has no line to hold at zero, so it takes none and succeeds).
/// The service checks the queue and the action (EINVAL).
fn terminal_ioctl(
    transport: Transport,
    terminal: u32,
    request: c_ulong,
    argument: *mut c_void,
) -> Result<c_int, c_int> {
    use posix_abi::terminal;
    let word = argument as usize;
    match request {
        TCGETS => {
            if argument.is_null() {
                return Err(EFAULT);
            }
            let settings = terminal::get_attr(transport, terminal)?;
            // SAFETY: the caller's promise: writable for a struct termios.
            unsafe { argument.cast::<Termios>().write(Termios::of(&settings)) };
            Ok(0)
        }
        TCSETS | TCSETSW | TCSETSF => {
            if argument.is_null() {
                return Err(EFAULT);
            }
            // SAFETY: the caller's promise: readable for a struct termios.
            let settings = unsafe { argument.cast::<Termios>().read() }.settings();
            terminal::set_attr(transport, terminal, (request - TCSETS) as u32, settings)?;
            Ok(0)
        }
        TIOCGWINSZ => {
            if argument.is_null() {
                return Err(EFAULT);
            }
            let size = terminal::get_winsize(transport, terminal)?;
            // SAFETY: the caller supplies a writable Linux winsize (8 bytes).
            unsafe { argument.cast::<proto_tty::Winsize>().write(size) };
            Ok(0)
        }
        TIOCSWINSZ => {
            if argument.is_null() {
                return Err(EFAULT);
            }
            // SAFETY: the caller supplies a readable Linux winsize (8 bytes).
            let size = unsafe { argument.cast::<proto_tty::Winsize>().read() };
            terminal::set_winsize(transport, terminal, size)?;
            Ok(0)
        }
        TCFLSH => {
            let queue = u32::try_from(word).map_err(|_| EINVAL)?;
            terminal::control(transport, terminal, proto_tty::Method::FlushQueues, queue)?;
            Ok(0)
        }
        TCXONC => {
            let action = u32::try_from(word).map_err(|_| EINVAL)?;
            terminal::control(transport, terminal, proto_tty::Method::Flow, action)?;
            Ok(0)
        }
        TCSBRK if word != 0 => terminal::drain(transport, terminal).map(|()| 0),
        TCSBRK => Ok(0),
        // The controlling terminal (5f, T3): tcsetpgrp, tcgetpgrp,
        // tcgetsid, TIOCSCTTY.
        TIOCSPGRP => {
            if argument.is_null() {
                return Err(EFAULT);
            }
            // SAFETY: the caller's promise: readable for a pid_t.
            let group = unsafe { argument.cast::<i32>().read() };
            let group = u32::try_from(group).map_err(|_| EINVAL)?;
            let method = proto_tty::Method::SetPgrp;
            terminal::job(transport, terminal, method, Some(group)).map(|_| 0)
        }
        TIOCGPGRP | TIOCGSID => {
            if argument.is_null() {
                return Err(EFAULT);
            }
            let method = if request == TIOCGPGRP {
                proto_tty::Method::GetPgrp
            } else {
                proto_tty::Method::GetSid
            };
            let number = terminal::job(transport, terminal, method, None)?;
            // SAFETY: the caller's promise: writable for a pid_t.
            unsafe { argument.cast::<i32>().write(number as i32) };
            Ok(0)
        }
        TIOCGPTN => {
            if argument.is_null() {
                return Err(EFAULT);
            }
            let value =
                terminal::description(transport, terminal, proto_tty::Method::Number, None)?;
            // SAFETY: the caller supplies writable storage for the number.
            unsafe { argument.cast::<u32>().write(value) };
            Ok(0)
        }
        TIOCSPTLCK => {
            if argument.is_null() {
                return Err(EFAULT);
            }
            // SAFETY: the caller supplies readable storage for the lock flag.
            let value = unsafe { argument.cast::<i32>().read() };
            if !matches!(value, 0 | 1) {
                return Err(EINVAL);
            }
            terminal::description(
                transport,
                terminal,
                proto_tty::Method::Lock,
                Some(value as u32),
            )
            .map(|_| 0)
        }
        TIOCNOTTY => terminal::job(transport, terminal, proto_tty::Method::Detach, None).map(|_| 0),
        TIOCSCTTY => {
            terminal::job(transport, terminal, proto_tty::Method::Acquire, None).map(|_| 0)
        }
        _ => Err(ENOTTY),
    }
}

/// ioctl: the terminal requests of a descriptor that is a terminal
/// (`terminal_ioctl`); ENOTTY for a descriptor of any other kind. A
/// process with no session with the terminal service (its console is the
/// driver's) answers TCGETS for its console with the settings of the
/// opened terminal and ENOSYS for setting them.
///
/// # Safety
/// `argument` is what `request` says: writable for a struct termios for
/// TCGETS, readable for one for TCSETS, TCSETSW and TCSETSF, the integer
/// itself for the rest.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_ioctl(
    fd: c_int,
    request: c_ulong,
    argument: *mut c_void,
) -> c_int {
    let result = number(fd).and_then(|fd| {
        posix_abi::shared::held(fd, |transport, target| {
            if let Some(terminal) = transport.terminal_number(target) {
                return terminal_ioctl(transport, terminal, request, argument);
            }
            let console = matches!(
                target,
                posix_fs::Target::Input | posix_fs::Target::Output | posix_fs::Target::Error
            );
            match (request, console) {
                (TCGETS, true) => {
                    if argument.is_null() {
                        return Err(EFAULT);
                    }
                    // SAFETY: the caller's promise.
                    unsafe {
                        argument
                            .cast::<Termios>()
                            .write(Termios::of(&proto_tty::Termios::opened()))
                    };
                    Ok(0)
                }
                (TCSETS | TCSETSW | TCSETSF, true) => Err(ENOSYS),
                _ => Err(ENOTTY),
            }
        })
    });
    result.unwrap_or_else(|errno| -errno)
}

/// Validate a PTY master and set the slave owner and mode through Grant.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_grantpt(fd: c_int) -> c_int {
    call(|| {
        posix_abi::shared::held(number(fd)?, |transport, target| {
            let Target::Tty(id) = target else {
                return Err(EINVAL);
            };
            posix_abi::terminal::description(transport, id, proto_tty::Method::Grant, None)
                .map(|_| 0)
        })
    })
    .unwrap_or_else(|errno| -errno)
}

/// ttyname_r: the name of the terminal `fd` is, NUL-terminated, into the
/// `len` bytes at `buf`: its length without the NUL; ENOTTY for another
/// kind of descriptor, ERANGE when the name and its NUL do not fit.
///
/// # Safety
/// `buf` is writable for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_ttyname(fd: c_int, buf: *mut u8, len: usize) -> isize {
    let mut name = [0u8; 20];
    let result = number(fd).and_then(|fd| {
        posix_abi::shared::held(fd, |transport, target| {
            let id = transport.terminal_number(target).ok_or(ENOTTY)?;
            let info = posix_abi::terminal::stat(transport, id)?;
            let text = if info.side != 0 {
                b"/dev/ptmx".as_slice()
            } else if info.terminal == 0 {
                b"/dev/console".as_slice()
            } else {
                b"/dev/pts/".as_slice()
            };
            name[..text.len()].copy_from_slice(text);
            if info.side == 0 && info.terminal != 0 {
                if info.terminal > 8 {
                    return Err(ENOTTY);
                }
                name[text.len()] = b'0' + (info.terminal - 1) as u8;
                Ok(text.len() + 1)
            } else {
                Ok(text.len())
            }
        })
    });
    match result {
        Err(errno) => -(errno as isize),
        Ok(n) if buf.is_null() || len <= n => -(posix_abi::constants::ERANGE as isize),
        Ok(n) => {
            // SAFETY: the caller provides writable storage and the name fits.
            let out = unsafe { core::slice::from_raw_parts_mut(buf, n + 1) };
            out[..n].copy_from_slice(&name[..n]);
            out[n] = 0;
            n as isize
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_getuid() -> u32 {
    posix_abi::process::getuid()
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_geteuid() -> u32 {
    posix_abi::process::geteuid()
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_getgid() -> u32 {
    posix_abi::process::getgid()
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_getegid() -> u32 {
    posix_abi::process::getegid()
}

/// setresuid as relibc's setuid (r = e, s kept) and seteuid (only e) call
/// it; other forms are ENOSYS until the process service has them.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_setresuid(real: u32, effective: u32, saved: u32) -> c_int {
    let keep = u32::MAX;
    let status = match (real, saved) {
        (r, s) if r == keep && s == keep => {
            value(call(|| posix_abi::process::seteuid(effective)).map(|()| 0))
        }
        (r, s) if r == effective && s == keep => {
            value(call(|| posix_abi::process::setuid(effective)).map(|()| 0))
        }
        _ => return -ENOSYS,
    };
    status as c_int
}

/// setresgid as relibc's setgid and setegid call it.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_setresgid(real: u32, effective: u32, saved: u32) -> c_int {
    let keep = u32::MAX;
    let status = match (real, saved) {
        (r, s) if r == keep && s == keep => {
            value(call(|| posix_abi::process::setegid(effective)).map(|()| 0))
        }
        (r, s) if r == effective && s == keep => {
            value(call(|| posix_abi::process::setgid(effective)).map(|()| 0))
        }
        _ => return -ENOSYS,
    };
    status as c_int
}

static UMASK: AtomicU32 = AtomicU32::new(0o022);

/// The process's umask, which a child spawned from a file inherits.
pub(crate) fn umask() -> u32 {
    UMASK.load(Ordering::Relaxed)
}

/// umask: the process's mask (no file the layer creates reads it yet).
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_umask(mask: u32) -> u32 {
    UMASK.swap(mask & 0o777, Ordering::Relaxed)
}

/// relibc's struct rlimit and the limits it names.
#[repr(C)]
pub struct Rlimit {
    current: u64,
    maximum: u64,
}
const RLIMIT_NOFILE: c_int = 7;
const RLIM_INFINITY: u64 = u64::MAX;

/// getrlimit: RLIMIT_NOFILE is the size of the layer's table of
/// descriptors; the others have no limit the layer keeps.
///
/// # Safety
/// `out` is writable for a struct rlimit.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_getrlimit(resource: c_int, out: *mut Rlimit) -> c_int {
    if !(0..16).contains(&resource) {
        return -EINVAL;
    }
    let value = if resource == RLIMIT_NOFILE {
        posix_fs::OPEN_MAX as u64
    } else {
        RLIM_INFINITY
    };
    // SAFETY: the caller's promise.
    unsafe {
        out.write(Rlimit {
            current: value,
            maximum: value,
        })
    };
    0
}

/// relibc's struct utsname: six fields of 65 bytes.
const UTS: usize = 65;

/// # Safety
/// `out` is writable for a struct utsname.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_uname(out: *mut [[u8; UTS]; 6]) -> c_int {
    let mut fields = [[0u8; UTS]; 6];
    for (field, text) in fields.iter_mut().zip([
        &b"stafeto"[..],
        b"stafeto",
        b"0.1.0",
        b"5a'",
        b"aarch64",
        b"",
    ]) {
        field[..text.len()].copy_from_slice(text);
    }
    // SAFETY: the caller's promise.
    unsafe { out.write(fields) };
    0
}

/// # Safety
/// `time` is a readable timespec.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_clock_settime(
    clock: c_int,
    time: *const posix_types::Timespec,
) -> c_int {
    // SAFETY: the caller's promise.
    let Some(time) = (unsafe { time.as_ref() }).copied() else {
        return -EFAULT;
    };
    value(call(|| posix_abi::clock::settime(clock, time)).map(|()| 0)) as c_int
}
