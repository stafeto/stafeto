// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Directory streams backed by real process descriptors. The initial ABI
//! scope reserves OPEN_MAX stable stream objects; its single owner serializes
//! calls. Process scopes route calls to the shared owner. Callers still serialize
//! reads and closure of the same stream while using its escaped entry buffer.

use crate::{constants::*, error, fail, fd, path};
use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int};
use core::ptr;
use posix_fs::{Directory, FileKind, OPEN_MAX, PosixFs};
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

fn context<T: Send>(
    run: impl FnOnce(&Streams, &mut PosixFs) -> Result<T, c_int> + Send,
) -> Result<T, c_int> {
    crate::shared::context(run)
}

/// # Safety
/// name is a live C string; this thread has an initialized file scope.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn opendir(name: *const c_char) -> *mut Stream {
    let result = unsafe { path(name) }.and_then(|path| {
        context(|streams, files| {
            let index = streams.vacant()?;
            let directory = files.opendir(path).map_err(error)?;
            Ok(streams.install(index, directory) as usize)
        })
    });
    result
        .map(|address| address as *mut Stream)
        .unwrap_or_else(|code| {
            fail(code);
            ptr::null_mut()
        })
}

/// # Safety
/// An initialized file scope is required. On success the stream owns number;
/// the caller must not close, replace or adopt it again before closedir.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fdopendir(number: c_int) -> *mut Stream {
    let result = fd(number).and_then(|fd| {
        context(|streams, files| {
            let index = streams.vacant()?;
            if streams.slots.iter().any(|slot| {
                // SAFETY: the unique scope owner inspects an initialized slot.
                unsafe { &*slot.get() }
                    .directory
                    .as_ref()
                    .is_some_and(|dir| dir.descriptor() == fd)
            }) {
                return Err(EINVAL);
            }
            let directory = files.fdopendir(fd).map_err(error)?;
            Ok(streams.install(index, directory) as usize)
        })
    });
    result
        .map(|address| address as *mut Stream)
        .unwrap_or_else(|code| {
            fail(code);
            ptr::null_mut()
        })
}

/// # Safety
/// pointer is a live stream in this thread's file scope. Returned storage must
/// not be freed; it remains valid until another read on this stream or closedir.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn readdir(pointer: *mut Stream) -> *mut Dirent {
    read_entry(pointer).unwrap_or_else(|code| {
        fail(code);
        ptr::null_mut()
    })
}

pub(crate) fn read_entry(pointer: *mut Stream) -> Result<*mut Dirent, c_int> {
    let address = pointer as usize;
    context(|streams, files| {
        let pointer = streams.slot(address as *mut Stream)?;
        // SAFETY: this call uniquely accesses this stream; other buffers stay untouched.
        let slot = unsafe { &mut *pointer };
        let entry = files
            .readdir(
                slot.directory.as_mut().unwrap(),
                &mut slot.entry.d_name[..NAME_MAX as usize],
            )
            .map_err(error)?;
        let Some(entry) = entry else {
            return Ok(0usize);
        };
        slot.entry.d_ino = entry.inode;
        slot.entry.d_type = match entry.kind {
            FileKind::Directory => DT_DIR,
            FileKind::Regular => DT_REG,
            FileKind::Character => DT_CHR,
        } as u8;
        slot.entry.d_name[entry.name_len] = 0;
        Ok(&mut slot.entry as *mut Dirent as usize)
    })
    .map(|address| address as *mut Dirent)
}

/// # Safety
/// pointer is a live stream in this thread's file scope. Success invalidates
/// the stream and closes its descriptor; duplicates keep their shared backend.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn closedir(pointer: *mut Stream) -> c_int {
    let address = pointer as usize;
    context(|streams, files| {
        let pointer = streams.slot(address as *mut Stream)?;
        // SAFETY: this call uniquely accesses this stream; other buffers stay untouched.
        let slot = unsafe { &mut *pointer };
        files
            .closedir(slot.directory.as_ref().unwrap())
            .map_err(error)?;
        slot.directory = None;
        Ok(())
    })
    .map_or_else(|code| fail(code) as c_int, |()| 0)
}

/// # Safety
/// pointer is a live stream in this thread's file scope.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dirfd(pointer: *mut Stream) -> c_int {
    let address = pointer as usize;
    context(|streams, _| Ok(streams.directory(address as *mut Stream)?.descriptor()))
        .map_or_else(|code| fail(code) as c_int, |fd| fd as c_int)
}

/// # Safety
/// pointer is a live stream in this thread's file scope.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn telldir(pointer: *mut Stream) -> i64 {
    let address = pointer as usize;
    context(|streams, files| {
        files
            .directory_position(streams.directory(address as *mut Stream)?)
            .map_err(error)
    })
    .unwrap_or_else(fail)
}

/// # Safety
/// pointer is a live stream; position was returned by telldir on this stream
/// since its most recent rewinddir. The current fixed namespace uses indices.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seekdir(pointer: *mut Stream, position: i64) {
    let address = pointer as usize;
    if let Err(code) = context(|streams, files| {
        files
            .seekdir(streams.directory(address as *mut Stream)?, position)
            .map_err(error)
    }) {
        fail(code);
    }
}

/// # Safety
/// pointer is a live stream in this thread's file scope.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rewinddir(pointer: *mut Stream) {
    let address = pointer as usize;
    if let Err(code) = context(|streams, files| {
        files
            .rewinddir(streams.directory(address as *mut Stream)?)
            .map_err(error)
    }) {
        fail(code);
    }
}
