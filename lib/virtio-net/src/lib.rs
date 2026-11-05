// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A driver of the Virtio network device (Virtio 1.2, 5.1) as a library:
//! the header and the checksums of a frame (`frames`), the books of the two
//! rings (`books`), the rings over the queues of the device's crate
//! (`rings`), the DMA of the device's crate over a driver's objects
//! (`host`), the transport of a device on virtio-mmio or Virtio PCI
//! (`transport`, with the configuration space of a function from a copy,
//! `Snapshot`), the start of a device (`open`), the accesses to its
//! registers and the barriers of its rings (`mmio`, `barrier`), and the copy
//! of a frame (`copy`).
//!
//! It makes no call of the kernel and holds no stack: whoever maps the
//! objects and the window, and owns the line, uses it. The network service
//! drives its two devices through it; the library builds for the host too,
//! where `cargo test -p virtio-net` exercises it.

#![cfg_attr(not(test), no_std)]

pub mod barrier;
pub mod books;
pub mod copy;
pub mod frames;
pub mod host;
pub mod mmio;
pub mod open;
pub mod rings;
pub mod transport;

pub use host::{Host, Region};
pub use open::{OpenFailure, Opened, open};
pub use rings::{RxRing, TxRing};
