// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The files of the service, through a session with the file service that
//! init gives this service the boot profile for: `/etc/netd.conf`, read once
//! at the start, and `/etc/resolv.conf`, written when a lease or the static
//! address names the name servers. The table of files (posix_fs::PosixFs,
//! about 28 KiB) lives in a static for the life of the service.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU32, Ordering};
use netd::config::{self, FILE_MAX, Settings};
use posix_fs::{DescriptorFlags, FsError, PosixFs, StartupFiles};
use rt::Handle;
use rt::handle::Channel;

struct Cell(UnsafeCell<MaybeUninit<PosixFs>>);

// SAFETY: the table is reached from the one thread of the service.
unsafe impl Sync for Cell {}

static FILES: Cell = Cell(UnsafeCell::new(MaybeUninit::uninit()));

/// Why the file gave no settings.
pub enum Failure {
    /// The files could not be reached or the file not read.
    Unreadable(FsError),
    /// The file is there and refused.
    Refused(config::Error),
}

/// The settings of the file; the default settings (DHCP) when the file is
/// not there.
pub fn read(parent: &Handle<Channel>) -> Result<Settings, Failure> {
    let startup = StartupFiles::connect(parent, false).map_err(Failure::Unreadable)?;
    // SAFETY: FILES is aligned, writable and used by nobody else; the
    // table stays initialized for `write_resolv`.
    let initialized = unsafe {
        PosixFs::initialize_at(
            (*FILES.0.get()).as_mut_ptr(),
            startup,
            b"/",
            None,
            false,
            &mut posix_fs::Late::new(),
        )
    };
    initialized.map_err(Failure::Unreadable)?;
    // SAFETY: initialize_at succeeded, and no reference to the table
    // outlives a call of this module.
    let files = unsafe { (*FILES.0.get()).assume_init_mut() };
    // A file that cannot be opened for writing leaves the addresses and
    // /etc/hosts to live without it.
    if let Err(error) = open_resolv(files) {
        rt::println!("net: resolv.conf unwritable: {error:?}");
    }
    let mut text = [0u8; FILE_MAX + 1];
    let outcome = match files.open(b"/etc/netd.conf", proto_fs::READ_ONLY) {
        Err(FsError::NoEntry) => Ok(None),
        Err(error) => Err(Failure::Unreadable(error)),
        Ok(fd) => {
            let read = files.read(fd, &mut text);
            let closed = files.close(fd);
            match (read, closed) {
                (Ok(n), Ok(())) => Ok(Some(n)),
                (Err(error), _) | (_, Err(error)) => Err(Failure::Unreadable(error)),
            }
        }
    };
    match outcome? {
        None => Ok(Settings::default()),
        Some(n) => config::parse(&text[..n]).map_err(Failure::Refused),
    }
}

/// The descriptor of `/etc/resolv.conf`, opened at the start (u32::MAX: none).
static RESOLV_FD: AtomicU32 = AtomicU32::new(u32::MAX);

/// Opens `/etc/resolv.conf` for writing, made root's with mode 644 when it is
/// not there (its text stays until the first write), in the start of the service: the open walks the
/// path with several calls to the file service, more than a step of the loop
/// may wait for (the waits of a step stay under CALL_WAIT_MAX). The file
/// stays open; `write_resolv` rewrites it from its start.
fn open_resolv(files: &mut PosixFs) -> Result<(), FsError> {
    let flags = proto_fs::WRITE_ONLY | proto_fs::CREATE;
    let fd = files.open_policy(
        b"/etc/resolv.conf",
        flags,
        0o644,
        0,
        DescriptorFlags::default(),
    )?;
    RESOLV_FD.store(fd, Ordering::Relaxed);
    Ok(())
}

/// Writes `text` to `/etc/resolv.conf` from its start, followed by empty
/// lines to the size the file has now (`fstat`; others may have written it),
/// which the resolver skips. A file past `PAD_MAX` bytes keeps its tail and
/// the service says so.
pub fn write_resolv(text: &[u8]) -> Result<(), FsError> {
    let fd = RESOLV_FD.load(Ordering::Relaxed);
    if fd == u32::MAX {
        return Err(FsError::BadFileDescriptor);
    }
    // SAFETY: the table is initialized by `read`, which opened the file, and
    // the one thread of the service is the only one here.
    let files = unsafe { (*FILES.0.get()).assume_init_mut() };
    let size = files.fstat(fd)?.size as usize;
    let mut out = [0u8; netd::resolv::PAD_MAX];
    let (total, capped) = netd::resolv::pad(text, size, &mut out);
    if capped {
        rt::println!("net: resolv.conf is {size} bytes, a tail past {total} stays");
    }
    files.lseek(fd, 0, posix_fs::SeekFrom::Start)?;
    if files.write(fd, &out[..total])? != total {
        return Err(FsError::NoSpace);
    }
    Ok(())
}
