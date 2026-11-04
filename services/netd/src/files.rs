// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The files of the service, through a session with the file service that
//! init gives this service the boot profile for: `/etc/netd.conf`, read once
//! at the start, and `/etc/resolv.conf`, written when a lease or the static
//! address names the name servers. The table of files (posix_fs::PosixFs,
//! about 28 KiB) lives in a static for the life of the service.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
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
        PosixFs::initialize_at((*FILES.0.get()).as_mut_ptr(), startup, b"/", None, false)
    };
    initialized.map_err(Failure::Unreadable)?;
    // SAFETY: initialize_at succeeded, and no reference to the table
    // outlives a call of this module.
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
    match outcome? {
        None => Ok(Settings::default()),
        Some(n) => config::parse(&text[..n]).map_err(Failure::Refused),
    }
}

/// Replaces `/etc/resolv.conf` with `text`: root's file of mode 644, made
/// when it is not there. There is no rename in the service's own file calls,
/// so the file is truncated and written whole; the short time it is empty
/// falls on a change of the servers only.
pub fn write_resolv(text: &[u8]) -> Result<(), FsError> {
    // SAFETY: `read` initialized the table (the service does not start
    // without it), and the one thread of the service is the only one here.
    let files = unsafe { (*FILES.0.get()).assume_init_mut() };
    let flags = proto_fs::WRITE_ONLY | proto_fs::CREATE | proto_fs::TRUNCATE;
    let fd = files.open_policy(
        b"/etc/resolv.conf",
        flags,
        0o644,
        0,
        DescriptorFlags::default(),
    )?;
    let written = files.write(fd, text);
    let closed = files.close(fd);
    match written? {
        n if n == text.len() => closed,
        _ => Err(FsError::NoSpace),
    }
}
