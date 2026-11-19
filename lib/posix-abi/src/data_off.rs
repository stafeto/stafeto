// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The process's place for the data file service (`proto_data`): the session that the start area
//! gives in the slot `Data`, as `packages` keeps the package service's. The slot is empty until a
//! process uses `/data` (the process takes a session from the root of the service with TakeRoot
//! and SESSION, step by step in the layer's paths for `/data`); a forked or spawned child gets a
//! clone of the session only when it holds descriptions of `/data` or a current directory there,
//! and `exec` moves the session to the new image. A set-ID program starts with the session the
//! loader verified with the service's root: the genuine one with its descriptions, or none.
//!
//! This build has none of the service's code (feature `data` is off): the session is held and
//! passed on, never used. The session is sent, never closed or
//! replaced by a caller.

use core::sync::atomic::{AtomicU64, Ordering};
use rt::handle::{Channel, Handle};

/// The session with the data file service, 0 for none.
static SESSION: AtomicU64 = AtomicU64::new(0);

/// The process's session with the data file service, which the loader's slot Data gives.
///
/// # Safety
/// Startup, on the only thread.
pub unsafe fn init(session: Option<Handle<Channel>>) {
    SESSION.store(session.map_or(0, |s| s.into_raw().0), Ordering::Release);
}

/// A forked child: `session`, the clone the parent made, takes the place of the parent's value,
/// which names nothing of the child's.
///
/// # Safety
/// The child's only thread, before anything else of the layer runs.
pub unsafe fn after_fork(session: Option<Handle<Channel>>) {
    SESSION.store(session.map_or(0, |s| s.into_raw().0), Ordering::Release);
}

/// The session with the data file service, for the requests.
pub fn session() -> Option<rt::abi::Handle> {
    match SESSION.load(Ordering::Acquire) {
        0 => None,
        raw => Some(rt::abi::Handle(raw)),
    }
}

// The rest of the module is what the paths and descriptions of `/data` call. Without the feature
// no path is the volume's and no descriptor names it: each of these answers as a layer with no
// such service.

use crate::constants::{EBADF, EIO};
use core::ffi::c_int;
use posix_fs::DataTarget;

const WIDE: usize = crate::names::MAX_PATH + 1;

/// A path of the volume: there is none.
pub struct Vol;

pub fn route(_dirfd: c_int, _path: &[u8]) -> Result<Option<Vol>, i32> {
    Ok(None)
}

pub fn open(_vol: &Vol, _flags: c_int, _mode: u32, _umask: u32) -> Result<c_int, i32> {
    Err(EIO)
}

pub fn stat(_vol: &Vol) -> Result<proto_fs::NodeInfo, i32> {
    Err(EIO)
}

pub fn access(_vol: &Vol, _bits: c_int, _effective: bool) -> Result<(), i32> {
    Err(EIO)
}

pub fn statvfs() -> Result<[u64; 11], i32> {
    Err(EIO)
}

pub fn realpath(_vol: &Vol, _out: &mut [u8; WIDE]) -> Result<usize, i32> {
    Err(EIO)
}

pub fn directory(_vol: &Vol, _out: &mut [u8; WIDE]) -> Result<usize, i32> {
    Err(EIO)
}

pub fn descriptor_path(_target: DataTarget, _out: &mut [u8; WIDE]) -> Result<usize, i32> {
    Err(EBADF)
}

pub fn sync_cwd(_absolute: &[u8]) -> Result<(), i32> {
    Ok(())
}

pub fn read(_handle: u32, _out: &mut [u8]) -> Result<usize, i32> {
    Err(EBADF)
}

pub fn pread(_handle: u32, _offset: u64, _out: &mut [u8]) -> Result<usize, i32> {
    Err(EBADF)
}

pub fn seek(_target: DataTarget, _offset: i64, _whence: i32) -> Result<u64, i32> {
    Err(EBADF)
}

pub fn fstat(_handle: u32) -> Result<proto_fs::NodeInfo, i32> {
    Err(EBADF)
}

pub fn entries(_handle: u32, _out: &mut [u8], _position: Option<u64>) -> Result<usize, i32> {
    Err(EBADF)
}

pub fn clone_for_fork() -> Result<Option<Handle<Channel>>, i32> {
    Ok(None)
}

pub fn session_for_exec() -> Option<rt::abi::Handle> {
    session()
}

pub fn clone_for_child(
    _held: impl IntoIterator<Item = posix_fs::data::Held>,
    _with_cwd: bool,
) -> Result<Option<Handle<Channel>>, i32> {
    Ok(None)
}

pub fn write(_handle: u32, _bytes: &[u8]) -> Result<usize, i32> {
    Err(EBADF)
}

pub fn pwrite(_handle: u32, _offset: u64, _bytes: &[u8]) -> Result<usize, i32> {
    Err(EBADF)
}

pub fn truncate(_handle: u32, _size: u64) -> Result<(), i32> {
    Err(EBADF)
}

pub fn fsync(_target: DataTarget) -> Result<(), i32> {
    Err(EBADF)
}

pub fn data_target(_fd: c_int) -> Option<DataTarget> {
    None
}

pub fn status_flags(_fd: c_int, _set: Option<c_int>) -> Result<Option<c_int>, i32> {
    Ok(None)
}

pub fn mkdir(_vol: &Vol, _mode: u32, _umask: u32) -> Result<(), i32> {
    Err(EIO)
}

pub fn unlink(_vol: &Vol, _directory: bool) -> Result<(), i32> {
    Err(EIO)
}

pub fn rename(_from: &Vol, _to: &Vol) -> Result<(), i32> {
    Err(EIO)
}

pub fn pair(
    _old_dirfd: c_int,
    _old: &[u8],
    _new_dirfd: c_int,
    _new: &[u8],
) -> Result<Option<(Vol, Vol)>, i32> {
    Ok(None)
}

pub fn link(_old: &Vol) -> Result<(), i32> {
    Err(EIO)
}

pub fn change(
    _op: proto_fs::ChangeOp,
    _dirfd: c_int,
    _path: &[u8],
    _args: [u64; 4],
) -> Result<bool, i32> {
    Ok(false)
}

pub fn export(_handle: u32) -> Result<Handle<Channel>, i32> {
    Err(crate::constants::EOPNOTSUPP)
}

pub fn adopt(_pass: Handle<Channel>, _cloexec: bool) -> Result<c_int, i32> {
    Err(EBADF)
}
