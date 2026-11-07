// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the network service decides (Virtio 1.2, 5.1; RFC 2131 for the
//! lease), apart from the device and the calls it makes: the header of a
//! frame (`frames`), the books of the two rings (`ring`) and the file
//! `/etc/netd.conf` (`config`), and the text it prints (`lines`). Everything here builds for the host too,
//! where `cargo test -p netd` exercises it.

#![cfg_attr(not(test), no_std)]

pub mod births;
pub mod buffers;
pub mod bypass;
pub mod chains;
pub mod choose;
pub mod config;
pub mod copy;
pub mod demux;
pub mod frames;
pub mod gates;
pub mod groups;
pub mod interest;
pub mod lines;
pub mod owners;
pub mod passes;
pub mod pci;
pub mod places;
pub mod ports;
pub mod profile;
pub mod resolv;
pub mod reuse;
pub mod ring;
pub mod spsc;
pub mod switchlogic;
