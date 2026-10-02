// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Directory streams backed by real process descriptors. A scope reserves
//! OPEN_MAX stable stream objects; the process's streams live under the
//! lock of its files (shared.rs). Callers still serialize reads and closure
//! of the same stream while using its escaped entry buffer.

use crate::{constants::*, error, fail, fd, path};
use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int};
use core::ptr;
use posix_fs::{Directory, FileKind, OPEN_MAX, PosixFs};
use posix_request::Request;
use posix_types::Dirent;

/// Opaque to C. The entry buffer belongs to this stream and is overwritten
/// by the next successful readdir on the same stream.
pub struct Stream {
    directory: Option<Directory>,
    entry: Dirent,
}

impl Stream {
    const fn new() -> Self {
        Self {
            directory: None,
            entry: Dirent::empty(),
        }
    }
}

pub(crate) struct Streams {
    slots: [UnsafeCell<Stream>; OPEN_MAX],
}

impl Streams {
    pub(crate) const fn new() -> Self {
        Self {
            slots: [const { UnsafeCell::new(Stream::new()) }; OPEN_MAX],
        }
    }

    fn vacant(&self) -> Result<usize, c_int> {
        self.slots
            .iter()
            // SAFETY: the unique scope owner inspects initialized registry slots.
            .position(|slot| unsafe { (*slot.get()).directory.is_none() })
            .ok_or(EMFILE)
    }

    fn slot(&self, pointer: *mut Stream) -> Result<*mut Stream, c_int> {
        let slot = self
            .slots
            .iter()
            .find(|slot| ptr::eq(slot.get(), pointer))
            .ok_or(EBADF)?;
        // SAFETY: the registry lives in the unique current-thread file scope.
        if unsafe { (*slot.get()).directory.is_none() } {
            return Err(EBADF);
        }
        Ok(slot.get())
    }

    fn directory(&self, pointer: *mut Stream) -> Result<&Directory, c_int> {
        let pointer = self.slot(pointer)?;
        // SAFETY: slot checked membership and active state; calls are serialized.
        Ok(unsafe { &(*pointer).directory }.as_ref().unwrap())
    }

    fn install(&self, index: usize, directory: Directory) -> *mut Stream {
        let slot = self.slots[index].get();
        // SAFETY: index is a vacant slot, exclusively accessed by this scope.
        unsafe {
            slot.write(Stream {
                directory: Some(directory),
                entry: Dirent::empty(),
            })
        };
        slot
    }

    pub(crate) fn perform(&self, request: Request<'_>, files: &mut PosixFs) -> Result<u64, c_int> {
        match request {
            Request::OpenDir { path } => {
                let index = self.vacant()?;
                let directory = files.opendir(path).map_err(error)?;
                Ok(self.install(index, directory) as u64)
            }
            Request::FdOpenDir { fd } => {
                let index = self.vacant()?;
                if self.slots.iter().any(|slot| {
                    // SAFETY: only this owner accesses the initialized registry.
                    unsafe { &*slot.get() }
                        .directory
                        .as_ref()
                        .is_some_and(|dir| dir.descriptor() == fd)
                }) {
                    return Err(EINVAL);
                }
                let directory = files.fdopendir(fd).map_err(error)?;
                Ok(self.install(index, directory) as u64)
            }
            Request::DirRead { stream } => {
                let pointer = self.slot(stream as *mut Stream)?;
                // SAFETY: membership is validated before accessing the registry slot.
                let slot = unsafe { &mut *pointer };
                let entry = files
                    .readdir(
                        slot.directory.as_mut().unwrap(),
                        &mut slot.entry.d_name[..NAME_MAX as usize],
                    )
                    .map_err(error)?;
                let Some(entry) = entry else {
                    return Ok(0);
                };
                slot.entry.d_ino = entry.inode;
                slot.entry.d_type = match entry.kind {
                    FileKind::Directory => DT_DIR,
                    FileKind::Regular => DT_REG,
                    FileKind::Character => DT_CHR,
                } as u8;
                slot.entry.d_name[entry.name_len] = 0;
                Ok(&mut slot.entry as *mut Dirent as u64)
            }
            Request::DirClose { stream } => {
                let pointer = self.slot(stream as *mut Stream)?;
                // SAFETY: membership and active state are validated above.
                let slot = unsafe { &mut *pointer };
                files
                    .closedir(slot.directory.as_ref().unwrap())
                    .map_err(error)?;
                slot.directory = None;
                Ok(0)
            }
            Request::DirFd { stream } => {
                Ok(self.directory(stream as *mut Stream)?.descriptor() as u64)
            }
            Request::DirTell { stream } => files
                .directory_position(self.directory(stream as *mut Stream)?)
                .map(|n| n as u64)
                .map_err(error),
            Request::DirSeek { stream, position } => {
                files
                    .seekdir(self.directory(stream as *mut Stream)?, position)
                    .map_err(error)?;
                Ok(0)
            }
            Request::DirRewind { stream } => {
                files
                    .rewinddir(self.directory(stream as *mut Stream)?)
                    .map_err(error)?;
                Ok(0)
            }
            _ => Err(ENOSYS),
        }
    }

    pub(crate) fn close_all(&self, files: &mut PosixFs) {
        for slot in &self.slots {
            // SAFETY: C has returned and can no longer access this scope's streams.
            let slot = unsafe { &mut *slot.get() };
            if let Some(dir) = &slot.directory {
                let _ = files.closedir(dir);
                slot.directory = None;
            }
        }
    }
}

/// # Safety
/// name is a live C string; this thread has an initialized file scope.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn opendir(name: *const c_char) -> *mut Stream {
    unsafe { path(name) }
        .and_then(|path| crate::shared::number(Request::OpenDir { path }))
        .map(|address| address as *mut Stream)
        .unwrap_or_else(|code| {
            fail(code);
            ptr::null_mut()
        })
}

/// # Safety
/// Success transfers ownership of number to this stream; the caller must not
/// close, replace or adopt it again before closedir. An ABI scope is required.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn fdopendir(number: c_int) -> *mut Stream {
    fd(number)
        .and_then(|fd| crate::shared::number(Request::FdOpenDir { fd }))
        .map(|address| address as *mut Stream)
        .unwrap_or_else(|code| {
            fail(code);
            ptr::null_mut()
        })
}

/// # Safety
/// pointer is a live stream. The returned buffer remains valid until the next
/// read on that stream or closedir; callers serialize use of the same stream.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn readdir(pointer: *mut Stream) -> *mut Dirent {
    read_entry(pointer).unwrap_or_else(|code| {
        fail(code);
        ptr::null_mut()
    })
}

pub(crate) fn read_entry(pointer: *mut Stream) -> Result<*mut Dirent, c_int> {
    crate::shared::number(Request::DirRead {
        stream: pointer as u64,
    })
    .map(|address| address as *mut Dirent)
}

/// # Safety
/// pointer is a live stream. Success closes its descriptor and invalidates it.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn closedir(pointer: *mut Stream) -> c_int {
    crate::shared::number(Request::DirClose {
        stream: pointer as u64,
    })
    .map_or_else(|code| fail(code) as c_int, |_| 0)
}

/// # Safety
/// pointer is a live stream in this process's file scope.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn dirfd(pointer: *mut Stream) -> c_int {
    crate::shared::number(Request::DirFd {
        stream: pointer as u64,
    })
    .map_or_else(|code| fail(code) as c_int, |fd| fd as c_int)
}

/// # Safety
/// pointer is a live stream in this process's file scope.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn telldir(pointer: *mut Stream) -> i64 {
    crate::shared::number(Request::DirTell {
        stream: pointer as u64,
    })
    .map(|n| n as i64)
    .unwrap_or_else(fail)
}

/// # Safety
/// position was returned by telldir on this stream since its last rewinddir.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn seekdir(pointer: *mut Stream, position: i64) {
    if let Err(code) = crate::shared::number(Request::DirSeek {
        stream: pointer as u64,
        position,
    }) {
        fail(code);
    }
}

/// # Safety
/// pointer is a live stream in this process's file scope.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn rewinddir(pointer: *mut Stream) {
    if let Err(code) = crate::shared::number(Request::DirRewind {
        stream: pointer as u64,
    }) {
        fail(code);
    }
}
