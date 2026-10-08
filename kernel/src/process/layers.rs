// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Fixed metadata for current-thread Layer publication and O(1) selection.
//! Every operation runs under SCHED. A live registered Thread keeps its
//! Process and its scheduler reference; this list owns no new reference.

use super::{Process, check_alive};
use crate::thread::Thread;
use abi::Error;
use core::ptr::NonNull;

pub(crate) const PRIMARY: u8 = 1;
pub(crate) const OBSERVER: u8 = 2;

#[derive(Clone, Copy)]
pub(crate) struct LayerLinks {
    prev: NonNull<Thread>,
    next: NonNull<Thread>,
    roles: u8,
}

/// The selected pointer is borrowed only through the caller's SCHED guard.
#[derive(Clone, Copy)]
pub(crate) struct Selected {
    pub thread: NonNull<Thread>,
    pub observer: bool,
}

/// # Safety
/// SCHED guards p, all membership changes and the selected Thread.
pub(crate) unsafe fn select(p: NonNull<Process>, rotate: bool) -> Result<Selected, Error> {
    check_alive(p)?;
    // SAFETY: all links remain inside held live Thread objects under SCHED.
    unsafe {
        let t = (*p.as_ptr()).layer_head.ok_or(Error::BadState)?;
        let links = (*t.as_ptr()).layer.expect("published Layer node");
        if rotate {
            (*p.as_ptr()).layer_head = Some(links.next);
        }
        Ok(Selected {
            thread: t,
            observer: links.roles & OBSERVER != 0,
        })
    }
}

/// # Safety
/// SCHED guards the current Thread and its held Process.
pub(crate) unsafe fn set_role(
    t: NonNull<Thread>,
    role: u8,
    enabled: bool,
) -> Result<Option<Selected>, Error> {
    // SAFETY: the current Thread holds its Process and every linked sibling.
    unsafe {
        let p = t.as_ref().process();
        if enabled {
            check_alive(p)?;
            if !t.as_ref().upcall.registered(role == OBSERVER) {
                return Err(Error::BadState);
            }
        }
        if let Some(mut links) = (*t.as_ptr()).layer {
            links.roles = if enabled {
                links.roles | role
            } else {
                links.roles & !role
            };
            if links.roles == 0 {
                unlink(p, t);
            } else {
                (*t.as_ptr()).layer = Some(links);
            }
        } else if enabled {
            if let Some(head) = (*p.as_ptr()).layer_head {
                let tail = (*head.as_ptr()).layer.expect("Layer head").prev;
                (*t.as_ptr()).layer = Some(LayerLinks {
                    prev: tail,
                    next: head,
                    roles: role,
                });
                (*tail.as_ptr()).layer.as_mut().expect("Layer tail").next = t;
                (*head.as_ptr()).layer.as_mut().expect("Layer head").prev = t;
            } else {
                (*t.as_ptr()).layer = Some(LayerLinks {
                    prev: t,
                    next: t,
                    roles: role,
                });
                (*p.as_ptr()).layer_head = Some(t);
            }
        } else {
            return Ok(None);
        }
        // Even the same head with a new preferred lane must take page.pending.
        Ok(select(p, false).ok())
    }
}

/// # Safety
/// SCHED guards all links; called before End or a last-role removal.
unsafe fn unlink(p: NonNull<Process>, t: NonNull<Thread>) {
    // SAFETY: the node's neighbours are held live members of this Process.
    unsafe {
        let Some(links) = (*t.as_ptr()).layer.take() else {
            return;
        };
        if links.next == t {
            (*p.as_ptr()).layer_head = None;
        } else {
            (*links.prev.as_ptr())
                .layer
                .as_mut()
                .expect("Layer previous")
                .next = links.next;
            (*links.next.as_ptr())
                .layer
                .as_mut()
                .expect("Layer next")
                .prev = links.prev;
            if (*p.as_ptr()).layer_head == Some(t) {
                (*p.as_ptr()).layer_head = Some(links.next);
            }
        }
    }
}

/// # Safety
/// SCHED guards the ending Thread, before its scheduler reference is released.
pub(crate) unsafe fn ending(t: NonNull<Thread>) -> Option<Selected> {
    // SAFETY: the ending Thread still holds its Process.
    unsafe {
        let p = t.as_ref().process();
        t.as_ref().layer?;
        unlink(p, t);
        // Ended Processes are being torn down and receive no new request.
        select(p, false).ok()
    }
}
