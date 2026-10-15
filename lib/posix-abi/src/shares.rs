// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The client of the process service's rendezvous of shared memory
//! (proto_process::Method::Share): processes that map the same file with
//! MAP_SHARED get the same memory object, by the key of the file. All calls
//! are messages outside the heap's lock.

use crate::constants::*;
use proto_process::Method;
use proto_wire::{Reader, Writer};
use rt::{
    abi::{MESSAGE_MAX, Rights},
    handle::{Handle, Memory, Outgoing},
    sys::Reply,
};

/// What the service answers to Get.
pub enum Got {
    /// The object, with its pages.
    Found(Handle<Memory>, usize),
    /// The caller makes the object and Puts it.
    Reserved,
    /// The service keeps no more entries: the object is the caller's alone.
    Full,
    /// Another process makes the object now.
    Busy,
}

/// The key of a file: the device and the inode, never 0.
pub fn key_of(device: u64, inode: u64) -> u64 {
    proto_process::share_key(device, inode)
}

fn request(operation: u32, key: u64, pages: u32) -> Result<Writer, i32> {
    let mut w = Writer::new();
    Method::Share.header().write(&mut w).map_err(|_| EIO)?;
    w.u32(operation).map_err(|_| EIO)?;
    w.u64(key).map_err(|_| EIO)?;
    w.u32(pages).map_err(|_| EIO)?;
    Ok(w)
}

/// Sends `w` with `handles` and gives the reply. A handle moves with the
/// message, so the signal entry is masked meanwhile (as `ask_loader` does).
fn exchange(w: &Writer, handles: Option<Outgoing>) -> Result<Reply, i32> {
    let was_masked = rt::upcall::mask().map_err(|_| EIO)?;
    let mut handles = handles;
    let result = loop {
        let sent = match handles.take() {
            Some(h) => rt::sys::send_handles(crate::process::client().session(), w.as_bytes(), h)
                .map_err(|refused| {
                    handles = refused.back;
                    refused.error
                }),
            None => rt::sys::send(crate::process::client().session(), w.as_bytes()),
        };
        match sent {
            Err(rt::abi::Error::Interrupted) => continue,
            Err(_) => break Err(EIO),
            Ok(reply) => break Ok(reply),
        }
    };
    if !was_masked {
        // SAFETY: restores the entry state this thread had on the way in.
        unsafe { rt::upcall::enable() }.expect("restore the entry state");
    }
    result
}

fn status_errno(status: u32) -> i32 {
    match status {
        proto_process::PERMISSION => EPERM,
        proto_process::INVALID => EINVAL,
        _ => EIO,
    }
}

/// The file service vouches to the process service that this process has
/// the file of `fd` open (ShareGrant): it comes before Get, Put and Attach.
pub fn grant(fd: i32) -> Result<(), i32> {
    let number = u32::try_from(fd).map_err(|_| EBADF)?;
    crate::shared::held(number, |transport, target| {
        let posix_fs::Target::Ram(ram) = target else {
            return Err(ENODEV);
        };
        transport.files().share_grant(ram.fd()).map_err(|status| {
            if status.code() == proto_fs::ACCESS_DENIED {
                EACCES
            } else {
                EIO
            }
        })
    })
}

/// The object of `key`, or the right to make it.
pub fn get(key: u64) -> Result<Got, i32> {
    let w = request(proto_process::SHARE_GET, key, 0)?;
    let mut reply = exchange(&w, None)?;
    let mut buffer = [0; MESSAGE_MAX];
    let mut r = Reader::new(reply.bytes(&mut buffer));
    let status = r.u32().map_err(|_| EIO)?;
    if status != 0 {
        return Err(status_errno(status));
    }
    let kind = r.u32().map_err(|_| EIO)?;
    let pages = r.u32().map_err(|_| EIO)? as usize;
    match kind {
        proto_process::SHARED_FOUND => {
            let memory = reply.handles.take::<Memory>(0).map_err(|_| EIO)?;
            Ok(Got::Found(memory, pages))
        }
        proto_process::SHARED_RESERVED => Ok(Got::Reserved),
        proto_process::SHARED_FULL => Ok(Got::Full),
        proto_process::SHARED_BUSY => Ok(Got::Busy),
        _ => Err(EIO),
    }
}

fn hand_over(operation: u32, key: u64, pages: usize, memory: &Handle<Memory>) -> Result<(), i32> {
    let w = request(operation, key, u32::try_from(pages).map_err(|_| EINVAL)?)?;
    let rights = Rights::MAP_READ | Rights::DUPLICATE | Rights::TRANSFER;
    let copy = rt::sys::handle_duplicate(memory, rights | Rights::MAP_WRITE)
        .or_else(|_| rt::sys::handle_duplicate(memory, rights))
        .map_err(|_| ENOMEM)?;
    let reply = exchange(&w, Some([copy.erase()].into()))?;
    let mut buffer = [0; MESSAGE_MAX];
    match Reader::new(reply.bytes(&mut buffer)).u32() {
        Ok(0) => Ok(()),
        Ok(status) => Err(status_errno(status)),
        Err(_) => Err(EIO),
    }
}

/// The maker of the object of `key` hands it over.
pub fn put(key: u64, pages: usize, memory: &Handle<Memory>) -> Result<(), i32> {
    hand_over(proto_process::SHARE_PUT, key, pages, memory)
}

/// A process that maps an object it has (a forked child) joins its key.
pub fn attach(key: u64, pages: usize, memory: &Handle<Memory>) -> Result<(), i32> {
    hand_over(proto_process::SHARE_ATTACH, key, pages, memory)
}

/// The caller maps the object of `key` no more, or could not make it.
pub fn detach(key: u64) {
    if let Ok(w) = request(proto_process::SHARE_DETACH, key, 0) {
        let _ = exchange(&w, None);
    }
}
