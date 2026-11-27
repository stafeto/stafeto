// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The build without the layer service (the feature `layer` is off): no path belongs to the
//! layered root, no description is one of the service, and the sessions of a child carry nothing.
//! The same names as `layer.rs`, so that the callers need no `cfg` of their own.

use crate::constants::{EBADF, EIO};
use core::ffi::c_int;
use posix_fs::LayerTarget;
use rt::handle::{Channel, Handle};

const WIDE: usize = crate::names::MAX_PATH + 1;

/// A path of the layered root: there is none.
pub struct Abs;

impl Abs {
    pub fn bytes(&self) -> &[u8] {
        &[]
    }
}

pub fn route(_dirfd: c_int, _path: &[u8]) -> Result<Option<Abs>, i32> {
    Ok(None)
}

pub fn refuse_write(_dirfd: c_int, _path: &[u8]) -> Result<(), i32> {
    Ok(())
}

pub fn open(_abs: &Abs, _flags: c_int, _mode: u32, _umask: u32) -> Result<c_int, i32> {
    Err(EIO)
}

pub fn stat(_abs: &Abs, _follow: bool) -> Result<proto_fs::NodeInfo, i32> {
    Err(EIO)
}

pub fn access(_abs: &Abs, _bits: c_int, _effective: bool) -> Result<(), i32> {
    Err(EIO)
}

pub fn readlink(_abs: &Abs, _out: &mut [u8]) -> Result<usize, i32> {
    Err(EIO)
}

pub fn directory(_abs: &Abs, _out: &mut [u8; WIDE]) -> Result<usize, i32> {
    Err(EIO)
}

pub fn realpath(_abs: &Abs, _out: &mut [u8; WIDE]) -> Result<usize, i32> {
    Err(EIO)
}

pub fn check_exec(_abs: &Abs) -> Result<Abs, i32> {
    Err(EIO)
}

pub fn descriptor_path(_target: LayerTarget, _out: &mut [u8; WIDE]) -> Result<usize, i32> {
    Err(EBADF)
}

pub fn seek(_target: LayerTarget, _offset: i64, _whence: i32) -> Result<u64, i32> {
    Err(EBADF)
}

pub fn fstat(_handle: u32) -> Result<proto_fs::NodeInfo, i32> {
    Err(EBADF)
}

pub fn entries(_handle: u32, _out: &mut [u8], _position: Option<u64>) -> Result<usize, i32> {
    Err(EBADF)
}

pub fn close_description(_handle: u32) {}

pub fn mark_inherited(_fds: &[u32]) {}

/// # Safety
/// Startup, on the only thread.
pub unsafe fn init(_session: Option<Handle<Channel>>) {}

/// # Safety
/// The child's only thread, before anything else of the layer runs.
pub unsafe fn after_fork(_session: Option<Handle<Channel>>) {}

pub fn session() -> Option<rt::abi::Handle> {
    None
}

pub fn clone_for_fork() -> Result<Option<Handle<Channel>>, i32> {
    Ok(None)
}

pub fn clone_for_child(
    _held: impl IntoIterator<Item = posix_fs::layer::Held>,
) -> Result<Option<Handle<Channel>>, i32> {
    Ok(None)
}

pub fn session_for_exec() -> Option<rt::abi::Handle> {
    None
}
