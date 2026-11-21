// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The image of the probe of focus and composition (tests/focus-probe,
//! stage G2 of the graphics design): the compositor with a virtio-tablet
//! for its pointer (a second instance of the input driver), two clients with
//! windows that overlap, a manager and a program that injects events.
//!
//! The tablet is the transport 13 at 0xa001a00 on the page 0xa001000, the line 61
//! (`-device virtio-tablet-device,bus=virtio-mmio-bus.13`, xtask's
//! `qemu::TABLET`). The keyboard's transport (15) shares the page, and this
//! image has no keyboard record: the keys come from INJECT. The compositor
//! connects to the driver under the name `pointer`.
//!
//! The manager and the injector are clients that ask the compositor for the
//! session its name gives them (`table::comp_mark`): their labels carry the
//! marks no other client gets.

use super::input;
use super::{Binding, Record, Window, Write, comp};
use crate::PAGE;

/// The virtio-mmio transport of the tablet on QEMU and its line.
pub const TRANSPORT: u64 = 0x0a00_1a00;
pub const LINE: u32 = 48 + 13;
/// `Status` of a virtio-mmio transport (Virtio 1.2, 4.2.2).
const MMIO_STATUS: u64 = 0x70;

/// The input driver of the tablet: the keyboard's program and record on
/// another transport.
pub const POINTER: Record = Record {
    name: "pointer",
    windows: &[Window {
        name: "mmio",
        base: TRANSPORT & !(PAGE - 1),
        len: PAGE,
        duplicate: false,
        at: super::At::Fixed,
    }],
    bindings: &[Binding {
        name: "irq",
        line: LINE,
        edge: false,
        of: None,
    }],
    args: &TRANSPORT.to_le_bytes(),
    quiesce: &[Write {
        window: "mmio",
        offset: (TRANSPORT & (PAGE - 1)) + MMIO_STATUS,
        bits: 32,
        value: 0,
        settled: 0xFFFF_FFFF,
        only_if: None,
        confirm: None,
    }],
    ..input::INPUT
};

/// The compositor with the pointer's driver as an input service of its own.
pub const COMPOSITOR: Record = Record {
    connects: &["display", "pointer"],
    ..comp::COMPOSITOR
};

/// The compositor of the image of the probe of focus, which calibrates the prices of
/// its bands before its first request: a deadline of 4 s for the silence of its
/// heartbeats (`comp::PROBE_COMPOSITOR`).
const PROBE_COMPOSITOR: Record = Record {
    kind: comp::PROBE_COMPOSITOR.kind,
    ..COMPOSITOR
};

/// The first client (role `a`): a window of its own, opaque.
const PROBE_A: Record = Record {
    name: "focus-a",
    program: "focus-probe",
    args: b"a",
    ..comp::PROBE
};

/// The second client (role `b`): a window with an alpha, over the first.
const PROBE_B: Record = Record {
    name: "focus-b",
    program: "focus-probe",
    args: b"b",
    ..comp::PROBE
};

/// The manager (role `m`): the compositor's manager session.
const PROBE_WM: Record = Record {
    name: "focus-wm",
    program: "focus-probe",
    args: b"m",
    ..comp::PROBE
};

/// The many windows (role `n`, in the run under -icount): seven windows over
/// the first client's, in two contexts, for the bound on the bands. Its quota
/// is the seven buffers of 30 pages and the stack.
const PROBE_MANY: Record = Record {
    name: "focus-many",
    program: "focus-probe",
    args: b"n",
    ..comp::PROBE
};

/// The injector (role `i`): the compositor's input session, which drives the
/// scenes and prints the lines whose CRC xtask compares with the screen.
const PROBE_INPUT: Record = Record {
    name: "focus-inject",
    program: "focus-probe",
    args: b"i",
    ..comp::PROBE
};

/// The probe's image on QEMU.
pub const TABLE: &[Record] = &[
    comp::DISPLAY,
    POINTER,
    PROBE_COMPOSITOR,
    PROBE_A,
    PROBE_B,
    PROBE_WM,
    PROBE_INPUT,
    PROBE_MANY,
];

// ------------------------------------------------------------ the window manager

/// The window manager (the program `wm`, apps/wm): the compositor's manager
/// session by its name (`table::COMP_MANAGERS`). It needs the pages of its
/// program and its stack and nothing else.
const WM: Record = Record {
    name: "wm",
    program: "wm",
    args: &[],
    quota: 256 * PAGE,
    ..comp::PROBE
};

/// The native client (role `p`): a window of 240 by 180, and the list of its
/// events, which the manager's focus and the chords make.
const WM_PROBE_NEW: Record = Record {
    name: "wm-new",
    program: "focus-probe",
    args: b"p",
    ..comp::PROBE
};

/// The client of the first revision (role `o`): the window of the whole
/// screen OPEN gives, and the keys its session of focus reads.
const WM_PROBE_OLD: Record = Record {
    name: "wm-old",
    program: "focus-probe",
    args: b"o",
    ..comp::PROBE
};

/// The injector (role `j`): the keys of the scene, which the manager's
/// chords and the compositor's routing must answer to.
const WM_PROBE_INPUT: Record = Record {
    name: "wm-inject",
    program: "focus-probe",
    args: b"j",
    ..comp::PROBE
};

/// The image of the window manager's probe on QEMU: the compositor with a
/// keyboard (`comp::COMPOSITOR_KEYS`: it holds the keyboard's focus and
/// serves the keys of the window of the first revision; no key is typed, the
/// keys come from INJECT), the manager, a client of the first revision and a
/// native one.
pub const WM_TABLE: &[Record] = &[
    comp::DISPLAY,
    input::INPUT,
    comp::COMPOSITOR_KEYS,
    WM,
    WM_PROBE_NEW,
    WM_PROBE_OLD,
    WM_PROBE_INPUT,
];
