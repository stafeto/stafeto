// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Reads `/etc/netd.conf` once, at the start, through a session with the
//! file service that init gives this service the boot profile for. The
//! table of files (posix_fs::PosixFs, about 28 KiB) lives in a static for
//! the duration of the read.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use netd::config::{self, FILE_MAX, Settings};
use posix_fs::{FsError, PosixFs, StartupFiles};
use rt::Handle;
use rt::handle::Channel;

struct Cell(UnsafeCell<MaybeUninit<PosixFs>>);

// SAFETY: `read` is called once, from the one thread of the service.
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
    // table is dropped before this function returns.
    let initialized = unsafe {
        PosixFs::initialize_at((*FILES.0.get()).as_mut_ptr(), startup, b"/", None, false)
    };
    initialized.map_err(Failure::Unreadable)?;
    // SAFETY: initialize_at succeeded, and no reference to the table
    // outlives this block.
    let files = unsafe { (*FILES.0.get()).assume_init_mut() };
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
    // SAFETY: as above; the table is initialized and not borrowed.
    unsafe { (*FILES.0.get()).assume_init_drop() };
    match outcome? {
        None => Ok(Settings::default()),
        Some(n) => config::parse(&text[..n]).map_err(Failure::Refused),
    }
}
