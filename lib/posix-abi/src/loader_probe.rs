// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Functional probes of loader channel normalization and clone accounting.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use proto_loader::Slot;
use proto_wire::{Reader, Status, Writer};
use rt::abi::{Error, Rights};
use rt::handle::{Channel, Handle};
use rt::sys;

static ENDPOINT: AtomicU64 = AtomicU64::new(0);
static MODE: AtomicU32 = AtomicU32::new(0);

/// Modes 1 and 2 replace Files and Clock with a receiving channel;
/// modes 3 and 4 use a closed endpoint for Files and Clock respectively.
pub fn start(mode: u32) -> i32 {
    let result = (|| {
        let root = sys::channel_create(1)?;
        let endpoint = if mode >= 3 {
            sys::handle_label(
                &root,
                Rights::SEND | Rights::TRANSFER | Rights::DUPLICATE,
                1,
                1,
            )?
        } else {
            root
        };
        ENDPOINT.store(endpoint.into_raw().0, Ordering::Release);
        MODE.store(mode, Ordering::Release);
        Ok::<_, Error>(())
    })();
    if result.is_ok() {
        0
    } else {
        crate::constants::EIO
    }
}

pub fn disable() {
    MODE.store(0, Ordering::Release);
}

pub(crate) fn replace(slot: Slot, offered: Handle<Channel>) -> Result<Handle<Channel>, Error> {
    let mode = MODE.load(Ordering::Acquire);
    let selected = matches!((mode, slot), (1 | 3, Slot::Files) | (2 | 4, Slot::Clock));
    if !selected {
        return Ok(offered);
    }
    let root = Handle::<Channel>::borrowed(rt::abi::Handle(ENDPOINT.load(Ordering::Acquire)));
    let rights = Rights::SEND | Rights::TRANSFER;
    if mode >= 3 {
        sys::handle_duplicate(&root, rights)
    } else {
        sys::handle_label(&root, rights, 1, 1)
    }
}

/// Counts ordinary messages. The receiver inspects only the stop header.
pub fn listen() -> u32 {
    let root = Handle::<Channel>::borrowed(rt::abi::Handle(ENDPOINT.load(Ordering::Acquire)));
    let mut requests = 0;
    loop {
        match sys::receive(&root) {
            Ok(sys::Received::Message { token, words, .. }) => {
                let stop =
                    u16::from_le_bytes(rt::abi::inline_bytes(&words)[..2].try_into().unwrap())
                        == u16::MAX;
                let _ = token.reply(&proto_wire::reply(Status::UnknownMethod));
                if stop {
                    return requests;
                }
                requests += 1;
            }
            Ok(_) => {}
            Err(_) => return u32::MAX,
        }
    }
}

pub fn stop() -> u32 {
    let mode = MODE.swap(0, Ordering::AcqRel);
    let raw = ENDPOINT.swap(0, Ordering::AcqRel);
    if raw == 0 {
        return 1;
    }
    let root = Handle::<Channel>::from_raw(rt::abi::Handle(raw));
    if mode < 3 {
        let request = proto_wire::Header::new(u16::MAX, proto_clock::VERSION).bytes();
        if sys::send(&root, &request).is_err() {
            return 1;
        }
    }
    0
}

/// Verifies a real session at the established per-client limit, including
/// the RAM description's shared offset and release of all temporary handles.
pub fn full(slot: u32) -> i32 {
    let before = sys::process_handles(crate::allocation::process()).map(|info| info.live);
    let result = (|| {
        let files = crate::shared::with_files(|fs| Ok(fs.sessions().0.raw()))?;
        let ram_fd = if slot == Slot::Files as u32 {
            crate::shared::with_files(|fs| match fs.target(3) {
                Ok(posix_fs::Target::Ram(fd)) => Ok(fd),
                _ => Err(crate::constants::EIO),
            })?
        } else {
            0
        };
        let clock = crate::clock::session().ok_or(crate::constants::EIO)?.raw();
        let (root, method) = if slot == Slot::Files as u32 {
            (files, proto_fs::Method::Clone.header())
        } else {
            (clock, proto_clock::Method::Clone.header())
        };
        let root = Handle::<Channel>::borrowed(root);
        let mut request = Writer::new();
        method
            .write(&mut request)
            .map_err(|_| crate::constants::EIO)?;
        // RAM clones inherit fd 3, so Verify must keep its description.
        if slot == Slot::Files as u32 {
            request
                .u32(1)
                .and_then(|()| request.u32(ram_fd))
                .map_err(|_| crate::constants::EIO)?;
        }
        let mut clones: [Option<Handle<Channel>>; proto_wire::clones::PER_CLIENT] =
            core::array::from_fn(|_| None);
        for clone in &mut clones {
            *clone = Some(
                if slot == Slot::Files as u32 {
                    rt::fs::Files::clone_on(&root, request.as_bytes())
                } else {
                    rt::service::clone_session(&root, request.as_bytes())
                }
                .map_err(|_| crate::constants::EIO)?,
            );
        }
        if !matches!(
            if slot == Slot::Files as u32 {
                rt::fs::Files::clone_on(&root, request.as_bytes())
            } else {
                rt::service::clone_session(&root, request.as_bytes())
            },
            Err(Status::Kernel(Error::LimitReached))
        ) {
            return Err(crate::constants::EIO);
        }
        let mut verify = Writer::new();
        let method = if slot == Slot::Files as u32 {
            proto_fs::Method::VerifySession.header()
        } else {
            proto_clock::Method::VerifySession.header()
        };
        method
            .write(&mut verify)
            .map_err(|_| crate::constants::EIO)?;
        if slot == Slot::Files as u32 {
            verify.u32(1).map_err(|_| crate::constants::EIO)?;
        }
        let offered = clones[0].take().ok_or(crate::constants::EIO)?;
        let offered = if slot == Slot::Files as u32 {
            rt::fs::Files::verify_on(&root, verify.as_bytes(), offered)
                .map_err(|_| crate::constants::EIO)?
        } else {
            let mut reply = sys::send_handles(&root, verify.as_bytes(), [offered.erase()])
                .map_err(|_| crate::constants::EIO)?;
            let mut buffer = [0; rt::abi::MESSAGE_MAX];
            if Reader::new(reply.bytes(&mut buffer)).u32() != Ok(0) {
                return Err(crate::constants::EIO);
            }
            reply
                .handles
                .take::<Channel>(0)
                .map_err(|_| crate::constants::EIO)?
        };
        let returned = offered;
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        if slot == Slot::Files as u32 {
            // This probe becomes the true holder before using the verified capture.
            let files = core::mem::ManuallyDrop::new(rt::fs::Files::from_sessions(
                Handle::from_raw(returned.raw()),
                None,
            ));
            files
                .bind(crate::process::identity().ok_or(crate::constants::EIO)?)
                .map_err(|_| crate::constants::EIO)?;
            let mut read = Writer::new();
            proto_fs::Method::Read
                .header()
                .write(&mut read)
                .and_then(|()| read.u32(ram_fd))
                .and_then(|()| read.u32(1))
                .map_err(|_| crate::constants::EIO)?;
            let reply = sys::send(&returned, read.as_bytes()).map_err(|_| crate::constants::EIO)?;
            let mut r = Reader::new(reply.bytes(&mut buffer));
            if r.u32() != Ok(0) || r.u32() != Ok(1) || r.bytes(1) != Ok(&b"s"[..]) {
                return Err(crate::constants::EIO);
            }
            clones[0] = Some(returned);
        } else {
            let mut get = Writer::new();
            proto_clock::Method::Get
                .header()
                .write(&mut get)
                .and_then(|()| get.u32(proto_clock::MONOTONIC))
                .map_err(|_| crate::constants::EIO)?;
            let reply = sys::send(&returned, get.as_bytes()).map_err(|_| crate::constants::EIO)?;
            if Reader::new(reply.bytes(&mut buffer)).u32() != Ok(0) {
                return Err(crate::constants::EIO);
            }
            clones[0] = Some(returned);
        }
        if !matches!(
            if slot == Slot::Files as u32 {
                rt::fs::Files::clone_on(&root, request.as_bytes())
            } else {
                rt::service::clone_session(&root, request.as_bytes())
            },
            Err(Status::Kernel(Error::LimitReached))
        ) {
            return Err(crate::constants::EIO);
        }
        drop(clones);
        drop(
            if slot == Slot::Files as u32 {
                rt::fs::Files::clone_on(&root, request.as_bytes())
            } else {
                rt::service::clone_session(&root, request.as_bytes())
            }
            .map_err(|_| crate::constants::EIO)?,
        );
        Ok(())
    })();
    if sys::process_handles(crate::allocation::process()).map(|info| info.live) != before {
        return crate::constants::EIO;
    }
    result.err().unwrap_or(0)
}

static BUNDLE: AtomicU32 = AtomicU32::new(0);

/// Adds a Driver channel to force another packet; mode 2 omits Terminal,
/// mode 3 checks refusal of requests after HandlesDone, and mode 4 omits it.
/// Modes 5, 6, 7 and 8 omit Files, Clock, Pipes and Entropy from the snapshot.
pub fn bundle_mode(mode: u32) {
    BUNDLE.store(mode, Ordering::Release);
}

type Bundle<const N: usize> = [(Slot, Option<Handle<Channel>>); N];

pub(crate) fn bundle<const N: usize>(mut sessions: Bundle<N>) -> Result<Bundle<N>, Error> {
    let mode = BUNDLE.load(Ordering::Acquire);
    for (slot, channel) in &mut sessions {
        if mode != 0 && *slot == Slot::Driver && channel.is_none() {
            let root = sys::channel_create(1)?;
            *channel = Some(sys::handle_label(
                &root,
                Rights::SEND | Rights::TRANSFER,
                1,
                1,
            )?);
        }
        if matches!(
            (mode, *slot),
            (2, Slot::Terminal)
                | (5, Slot::Files)
                | (6, Slot::Clock)
                | (7, Slot::Pipes)
                | (8, Slot::Entropy)
        ) {
            *channel = None;
        }
    }
    Ok(sessions)
}

pub(crate) fn repeat_bundle() -> bool {
    BUNDLE.load(Ordering::Acquire) == 3
}

pub(crate) fn omit_completion() -> bool {
    BUNDLE.load(Ordering::Acquire) == 4
}
