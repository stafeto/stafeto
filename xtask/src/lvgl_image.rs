// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The images of the LVGL demo's probe (stage G4): `boot-lvgl.img` for
//! `lvgl-probe` on QEMU's own emulation (and for `lvgl`, the run with the
//! window of QEMU) and `boot-lvgl-steps.img` for its run under -icount, whose
//! services of the screen and the pointer count their steps and whose
//! injector is built with `quick`. Both are the games image without Doom and
//! its data: the shell, the packages of the shell image, the games of the
//! games image that are not Doom (`lvgl` with the program `lvgl-demo`, which
//! its package gives, and the font), the table `table::lvgl` of init, the
//! tablet's driver (`virtio-input` under the name `pointer`), the
//! compositor and the injector `lvgl-inject` (tests/lvgl-inject).
//!
//! What the demo's package gives: the program `lvgl-demo` in
//! `PACKAGE_PROGRAMS` (a static program, so a stack of its own), its path
//! `/bin/lvgl-demo` and the font in the package's files; the shell starts it
//! as `lvgl-demo --probe`. The table starts no demo: the probe types the
//! line into ash.

use super::*;
use crate::{comp_probe, gpu_probe};

pub const IMAGE: &str = "boot-lvgl.img";
pub const STEPS_IMAGE: &str = "boot-lvgl-steps.img";
/// The stack of the injector: a native program with a small call depth.
const INJECT_STACK_SIZE: u32 = CHILD_STACK_SIZE;

/// The programs of `boot-lvgl.img`.
pub fn programs() -> &'static [ImageProgram] {
    static LIST: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| image_programs(IMAGE, &[], &[]))
}

/// The programs of `boot-lvgl-steps.img`: the screen's and the pointer's
/// services count their steps, the injector does not wait for a photograph.
pub fn steps_programs() -> &'static [ImageProgram] {
    static LIST: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| image_programs(STEPS_IMAGE, &["steps"], &["quick"]))
}

fn image_programs(
    image: &str,
    services: &'static [&'static str],
    injector: &'static [&'static str],
) -> Vec<ImageProgram> {
    let packages = packages::of_image(image).unwrap_or_else(|e| panic!("the image {image}: {e}"));
    let mut programs = SHELL_SERVICES.to_vec();
    programs[0] = ("init", "init", INIT_STACK_SIZE, &["table-lvgl"]);
    for program in packages.iter().filter_map(|p| p.program.as_deref()) {
        let entry = PACKAGE_PROGRAMS
            .iter()
            .find(|p| p.0 == program)
            .unwrap_or_else(|| panic!("no build of the program {program} (PACKAGE_PROGRAMS)"));
        programs.push(*entry);
    }
    programs.extend(SHELL_SERVICES_LAST);
    // The tablet's driver is the program of the keyboard's, under another
    // record (table::focus::POINTER).
    programs.push((
        "virtio-input",
        "virtio-input",
        input_probe::INPUT_STACK_SIZE,
        services,
    ));
    programs.push((
        "virtio-gpu",
        "virtio-gpu",
        gpu_probe::GPU_STACK_SIZE,
        services,
    ));
    programs.push((
        "compositor",
        "compositor",
        comp_probe::COMP_STACK_SIZE,
        services,
    ));
    programs.push(("lvgl-inject", "lvgl-inject", INJECT_STACK_SIZE, injector));
    programs
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The injector is the last program, built with `quick` in the image of
    /// the measures alone, and init has the table of this image.
    #[test]
    fn the_images_have_the_injector_and_their_table() {
        for (list, quick) in [(programs(), false), (steps_programs(), true)] {
            assert_eq!(list[0].3, &["table-lvgl"]);
            let inject = list.last().unwrap();
            assert_eq!((inject.0, inject.1), ("lvgl-inject", "lvgl-inject"));
            assert_eq!(inject.3.contains(&"quick"), quick);
            for name in ["virtio-input", "virtio-gpu", "compositor"] {
                let service = list.iter().find(|p| p.0 == name).unwrap();
                assert_eq!(service.3.contains(&"steps"), quick, "{name}");
            }
        }
    }

    /// The images hold the shell's packages and no Doom.
    #[test]
    fn the_images_hold_no_doom() {
        for image in [IMAGE, STEPS_IMAGE] {
            let held = packages::of_image(image).unwrap();
            assert!(held.iter().any(|p| p.name == "lvgl"));
            assert!(
                held.iter()
                    .all(|p| p.name != "doomgeneric" && p.name != "freedoom")
            );
            assert!(held.iter().any(|p| p.name == "busybox"));
        }
    }
}
