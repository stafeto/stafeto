// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the terminal: a C main on relibc (tty.c); posix-crt starts
//! the layer, relibc starts C.

#![no_std]
#![no_main]

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_terminal_full_exec() -> i32 {
    posix_abi::terminal::probe_full_exec()
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_terminal_edge(group: u32) -> i32 {
    posix_abi::terminal::probe_edge(group)
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_trusted_terminal(target: i32, newborn: i32) -> i32 {
    posix_abi::terminal::probe_trusted(target as u32, newborn != 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_terminal_fake_start() -> i32 {
    posix_abi::process::probe_terminal_fake_start()
}
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_terminal_fake_control() -> i32 {
    posix_abi::process::probe_terminal_fake_control()
}
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_terminal_fake_listen() -> u32 {
    posix_abi::process::probe_terminal_fake_listen()
}
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_terminal_fake_stop() -> i32 {
    posix_abi::process::probe_terminal_fake_stop()
}
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_terminal_fake_close() {
    posix_abi::process::probe_terminal_fake_close()
}

/// Snapshot the full service interval before printing any measurement.
#[cfg(feature = "quiet-control")]
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_terminal_control_stats() -> i32 {
    use proto_wire::{Header, Reader, Writer};
    use rt::handle::{Channel, Handle};
    let channel = match posix_abi::shared::with_files(|fs| Ok(fs.terminal().map(Handle::raw))) {
        Ok(Some(raw)) => Handle::<Channel>::borrowed(raw),
        _ => return 5,
    };
    let mut maxima = [(0u64, 0u64); 5];
    for (index, maximum) in maxima.iter_mut().enumerate() {
        let mut request = Writer::new();
        if Header::new(30, proto_tty::VERSION)
            .write(&mut request)
            .and_then(|()| request.u32(index as u32 + 16))
            .is_err()
        {
            return 5;
        }
        let Ok(reply) = rt::sys::send(&channel, request.as_bytes()) else {
            return 5;
        };
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        let mut body = Reader::new(reply.bytes(&mut buffer));
        if body.u32() != Ok(0) {
            return 5;
        }
        let (Ok(ticks), Ok(detail)) = (body.u64(), body.u64()) else {
            return 5;
        };
        if body.finish().is_err() {
            return 5;
        }
        *maximum = (ticks, detail);
    }
    // xtask compares the numbers with term B.
    let invalid = maxima.iter().any(|(ticks, _)| *ticks == 0);
    for (index, (ticks, detail)) in maxima.into_iter().enumerate() {
        rt::println!(
            "service step: 5 kind {} {} ticks detail {}",
            index + 16,
            ticks,
            detail
        );
    }
    if invalid { 5 } else { 0 }
}

/// Exercise Controlling with this real client's descriptor and identity.
#[cfg(feature = "quiet-control")]
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_terminal_controlling(fd: i32) -> i32 {
    let outcome = posix_abi::shared::with_files(|fs| {
        let target = fs.target(fd as u32).map_err(|_| 9)?;
        Ok((fs.transport(), target))
    });
    let Ok((transport, posix_fs::Target::Tty(description))) = outcome else {
        return 9;
    };
    posix_abi::terminal::job(transport, description, proto_tty::Method::Controlling, None)
        .map_or_else(|error| error, |_| 0)
}

/// The virtual names of the terminal service and the operations on names
/// (the bridges of the layer): the layer refuses by its own table and the RAM
/// service never sees the request.
mod virtual_names {
    use core::ffi::{c_char, c_int};

    unsafe extern "C" {
        fn stafeto_unlinkat(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int;
        fn stafeto_mkdirat(dirfd: c_int, path: *const c_char, mode: u32) -> c_int;
        fn stafeto_faccessat(dirfd: c_int, path: *const c_char, mode: c_int, flags: c_int)
        -> c_int;
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
        fn stafeto_symlinkat(target: *const c_char, dirfd: c_int, linkpath: *const c_char)
        -> c_int;
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
        fn stafeto_fstatat(
            dirfd: c_int,
            path: *const c_char,
            out: *mut [u64; 16],
            flags: c_int,
        ) -> c_int;
        fn stafeto_openat(dirfd: c_int, path: *const c_char, flags: c_int, mode: u32) -> c_int;
        fn stafeto_close(fd: c_int) -> c_int;
    }

    const AT_FDCWD: c_int = -100;
    const AT_REMOVEDIR: c_int = 0x200;
    const EEXIST: c_int = 17;
    const EBUSY: c_int = 16;
    const EXDEV: c_int = 18;
    const EROFS: c_int = 30;
    const EACCES: c_int = 13;
    const ENOTDIR: c_int = 20;
    const O_RDWR: c_int = 2;
    const O_NOCTTY: c_int = 0o400;
    const O_DIRECTORY: c_int = 0o40000;
    const S_IFMT: u32 = 0o170000;
    const S_IFCHR: u32 = 0o020000;

    /// A path with its NUL.
    struct Name([u8; 64]);
    fn name(bytes: &[u8]) -> Name {
        let mut name = Name([0; 64]);
        name.0[..bytes.len()].copy_from_slice(bytes);
        name
    }
    impl Name {
        fn pointer(&self) -> *const c_char {
            self.0.as_ptr().cast()
        }
    }

    /// The device and the mode of a path, or the errno.
    fn stat(dirfd: c_int, path: &[u8]) -> Result<(u64, u32), c_int> {
        let path = name(path);
        let mut out = [0u64; 16];
        // SAFETY: a live C string and a buffer of a struct stat.
        let result = unsafe { stafeto_fstatat(dirfd, path.pointer(), &mut out, 0) };
        if result < 0 {
            return Err(-result);
        }
        Ok((out[0], out[2] as u32))
    }

    fn expect(result: c_int, errno: c_int, line: i32) -> Result<(), i32> {
        if result == -errno { Ok(()) } else { Err(line) }
    }

    fn run() -> Result<(), i32> {
        let tty = name(b"/dev/tty");
        let console = name(b"/dev/console");
        let ptmx = name(b"/dev/ptmx");
        let plain = name(b"/tmp");
        let moved = name(b"/tmp/moved");
        // SAFETY (the whole block): live C strings.
        unsafe {
            // A new name over a virtual one exists already.
            expect(stafeto_mkdirat(AT_FDCWD, tty.pointer(), 0o777), EEXIST, 1)?;
            expect(
                stafeto_mkdirat(AT_FDCWD, console.pointer(), 0o777),
                EEXIST,
                2,
            )?;
            expect(stafeto_mkdirat(AT_FDCWD, ptmx.pointer(), 0o777), EEXIST, 3)?;
            expect(
                stafeto_symlinkat(plain.pointer(), AT_FDCWD, tty.pointer()),
                EEXIST,
                4,
            )?;
            // Another device than the RAM service's: no link, no rename.
            expect(
                stafeto_linkat(AT_FDCWD, tty.pointer(), AT_FDCWD, moved.pointer(), 0),
                EXDEV,
                5,
            )?;
            expect(
                stafeto_linkat(AT_FDCWD, plain.pointer(), AT_FDCWD, tty.pointer(), 0),
                EEXIST,
                6,
            )?;
            expect(
                stafeto_renameat(AT_FDCWD, console.pointer(), AT_FDCWD, moved.pointer()),
                EXDEV,
                7,
            )?;
            expect(
                stafeto_renameat(AT_FDCWD, plain.pointer(), AT_FDCWD, tty.pointer()),
                EXDEV,
                8,
            )?;
            // They cannot go.
            expect(stafeto_unlinkat(AT_FDCWD, console.pointer(), 0), EBUSY, 9)?;
            expect(stafeto_unlinkat(AT_FDCWD, tty.pointer(), 0), EBUSY, 10)?;
            expect(
                stafeto_unlinkat(AT_FDCWD, ptmx.pointer(), AT_REMOVEDIR),
                EBUSY,
                11,
            )?;
            let slash = name(b"/dev/console/");
            expect(stafeto_unlinkat(AT_FDCWD, slash.pointer(), 0), ENOTDIR, 12)?;
            // Their metadata is the terminal service's.
            expect(
                stafeto_fchmodat(AT_FDCWD, console.pointer(), 0o600, 0),
                EROFS,
                13,
            )?;
            expect(
                stafeto_fchownat(AT_FDCWD, console.pointer(), 1, 1, 0),
                EROFS,
                14,
            )?;
            expect(
                stafeto_utimensat(AT_FDCWD, console.pointer(), core::ptr::null(), 0),
                EROFS,
                15,
            )?;
            // access gives the answer of stat: the console is 0666, no one executes it.
            expect(
                stafeto_faccessat(AT_FDCWD, console.pointer(), 4 | 2, 0),
                0,
                16,
            )?;
            expect(
                stafeto_faccessat(AT_FDCWD, console.pointer(), 1, 0),
                EACCES,
                17,
            )?;
        }
        // Nothing was created, moved or removed.
        let (console_device, console_mode) = stat(AT_FDCWD, b"/dev/console").map_err(|_| 20)?;
        let (_, tty_mode) = stat(AT_FDCWD, b"/dev/tty").map_err(|_| 21)?;
        if console_mode & S_IFMT != S_IFCHR || tty_mode & S_IFMT != S_IFCHR {
            return Err(22);
        }
        if stat(AT_FDCWD, b"/tmp/moved").is_ok() {
            return Err(23);
        }
        // The virtual names lie on a device of their own: the rename and the
        // link that answered EXDEV match what stat says.
        let (ram_device, _) = stat(AT_FDCWD, b"/tmp").map_err(|_| 24)?;
        if console_device == ram_device {
            return Err(25);
        }
        // From a descriptor of /dev the same rules hold.
        let dev = name(b"/dev");
        // SAFETY: live C strings.
        unsafe {
            let dev_fd = stafeto_openat(AT_FDCWD, dev.pointer(), O_NOCTTY | O_DIRECTORY, 0);
            if dev_fd < 0 {
                return Err(30);
            }
            let leaf = name(b"console");
            let result = (
                stafeto_unlinkat(dev_fd, leaf.pointer(), 0),
                stafeto_mkdirat(dev_fd, leaf.pointer(), 0o777),
                stafeto_fchmodat(dev_fd, leaf.pointer(), 0o600, 0),
            );
            let opened = stafeto_openat(dev_fd, leaf.pointer(), O_RDWR | O_NOCTTY, 0);
            let statted = stat(dev_fd, b"tty");
            if opened >= 0 {
                stafeto_close(opened);
            }
            stafeto_close(dev_fd);
            expect(result.0, EBUSY, 31)?;
            expect(result.1, EEXIST, 32)?;
            expect(result.2, EROFS, 33)?;
            if opened < 0 {
                return Err(34);
            }
            if statted.map(|(_, mode)| mode & S_IFMT) != Ok(S_IFCHR) {
                return Err(35);
            }
        }
        Ok(())
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn tty_virtual_names() -> i32 {
        run().err().unwrap_or(0)
    }
}
