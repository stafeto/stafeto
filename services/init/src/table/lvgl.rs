// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The image of the LVGL demo's probe (`boot-lvgl.img` and
//! `boot-lvgl-steps.img`, xtask lvgl-probe and lvgl): the games image's
//! table (`doom::TABLE`: the shell's dialog with the quota of a game, a
//! session with the display service in the launcher's `connects`, which the
//! shell's children inherit as their place `Display`) with the tablet for the
//! pointer and the injector of the demo's scenario.
//!
//! The compositor is the one of the probe of focus (`focus::COMPOSITOR`): it
//! takes the pointer from the tablet's driver (`focus::POINTER`, transport
//! 13) and the keys of a window from its own ring, which INJECT fills. The
//! image has no keyboard's driver: the keyboard (transport 15) shares its
//! page of the transports with the tablet (transport 13), and the page has one
//! window to give (see `input.rs`), as in the probe of focus. The keys of the
//! scenario are injected, so the demo needs no other.
//!
//! The injector (`lvgl-inject`, tests/lvgl-inject) is a native client of the
//! compositor with its input session (`table::COMP_INJECTORS`). It starts with
//! the image, polls the service for the window the demo makes when someone
//! types its line into the shell, and injects the 22 events of the scenario.
//! It holds no buffer: its quota is its program, its stack and its few
//! objects.

use super::doom;
use super::focus;
use super::{Record, comp};
use crate::PAGE;

/// The injector of the scenario.
pub const INJECT: Record = Record {
    name: "lvgl-inject",
    program: "lvgl-inject",
    args: &[],
    quota: 128 * PAGE,
    ..comp::PROBE
};

/// The table of the LVGL demo's image: the games table without the
/// keyboard, with the tablet, the compositor that reads it and the injector.
pub const TABLE: &[Record] = &[
    doom::TABLE[0],
    doom::TABLE[1],
    doom::TABLE[2],
    doom::TABLE[3],
    doom::TABLE[4],
    doom::TABLE[5],
    doom::TABLE[6],
    doom::TABLE[7],
    doom::TABLE[8],
    focus::POINTER,
    comp::DISPLAY,
    focus::COMPOSITOR,
    INJECT,
];

#[cfg(test)]
mod tests {
    use super::*;

    fn named(name: &str) -> &'static Record {
        TABLE.iter().find(|r| r.name == name).unwrap()
    }

    /// The image has the tablet and no keyboard (they share a page of
    /// transports), the compositor reads the tablet and nothing else, and
    /// the injector reaches the compositor and holds no device.
    #[test]
    fn the_image_has_the_tablet_the_compositor_and_the_injector() {
        assert!(TABLE.iter().all(|r| r.name != "input"));
        assert_eq!(named("pointer").windows, focus::POINTER.windows);
        assert_eq!(named("gpu").connects, &["display", "pointer"]);
        assert_eq!(named("display").connects, comp::DISPLAY.connects);
        let injector = named("lvgl-inject");
        assert_eq!(injector.connects, &["gpu"]);
        assert!(injector.windows.is_empty() && injector.dma.is_empty());
        assert!(injector.args.is_empty());
        // The shell's launcher and the injector have the display service (the compositor).
        assert_eq!(
            TABLE.iter().filter(|r| r.connects.contains(&"gpu")).count(),
            2
        );
        // The compositor and the drivers start before the injector.
        let at = |name: &str| TABLE.iter().position(|r| r.name == name).unwrap();
        assert!(
            at("pointer") < at("gpu") && at("display") < at("gpu") && at("gpu") < at("lvgl-inject")
        );
    }
}
