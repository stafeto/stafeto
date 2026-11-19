// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The client side of the composition service's windows of the second
//! revision (`proto_comp`), as logic with no kernel call in it, so that the
//! host tests it. The layer that makes the calls is `posix_abi::window` and
//! the C functions are `posix_crt`'s `window_c.rs`, behind the header
//! `lib/posix-crt/window/stafeto/window.h`.

#![cfg_attr(not(test), no_std)]

pub mod layout;
