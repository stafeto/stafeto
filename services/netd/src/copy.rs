// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `memcpy` of the service: the routine of `virtio_net::copy` (64 bytes a turn
//! with `ldp` and `stp` at any alignment) under the name every copy of the
//! compiler takes. The target `aarch64-unknown-none` builds with
//! `+strict-align`, and the `memcpy` of compiler_builtins reads a source that
//! is not aligned like its destination one byte at a time. The routine is
//! right in this service: the memory it copies is ordinary memory (the
//! sockets' buffers, the frames in the object `net`, mapped cached; the window
//! of the device's registers is touched only by volatile accesses of one word,
//! never by `memcpy`), and the kernel leaves SCTLR_EL1.A clear for EL0
//! (kcore/src/sysreg.rs). The ranges do not overlap (`memcpy`); `memmove`
//! stays compiler_builtins'. The library's tests compare the routine with
//! `copy_from_slice`.

#[cfg(target_os = "none")]
core::arch::global_asm!(
    ".global memcpy",
    ".type memcpy, %function",
    "memcpy:",
    virtio_net::copy_body!(),
    ".size memcpy, . - memcpy"
);
