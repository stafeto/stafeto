// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The client side of the composition service's windows of the second
//! revision (`proto_comp`), as logic with no kernel call in it, so that the
//! host tests it. The layer that makes the calls is `posix_abi::window` and
//! the C functions are `posix_crt`'s `window_c.rs`, behind the header
//! `lib/posix-crt/window/stafeto/window.h`.
//!
//! * `layout`: the structures and constants of the header.
//! * `account`: which buffers are free, by the bits the service sends.
//! * `damage`: the rectangles of a POST, merged to what the service takes.
//! * `events`: the 16 bytes of an event, both ways.
//! * `errno`: the service's refusals and the kernel's as errno.

#![cfg_attr(not(test), no_std)]

pub mod account;
pub mod damage;
pub mod errno;
pub mod events;
pub mod layout;
