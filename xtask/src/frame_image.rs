// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The images for the measurements of the frame time and the words to build
//! and run them.
//!
//! `boot-frame.img` and `boot-frame-steps.img` (init's table `table::frame`)
//! have the screen, a disk and the network together with the programs that
//! load them (tests/frame-load, the mode `load` of tests/data-probe and the
//! role `L` of tests/net-probe). The steps image has the display driver and the
//! compositor count their steps.
//!
//! - `cargo xtask frame-image`: builds both images on the host and prints their
//!   sizes (no machine runs).
//! - `cargo xtask frame-loads [steps]`: boots the image on QEMU's `virt` with
//!   the screen, a disk of 64 MiB and QEMU's user network, runs the phases of
//!   the loads (about 40 s of the guest's time after the boot) and checks that
//!   every load did its work in the phases it is meant for: the paced client
//!   posted, the client of the first revision flushed, the CPU loop turned, the
//!   files were written and the network loop made its rounds. `steps` runs the
//!   image of the measures under -icount, as the frame probe does. It is the
//!   check that the loads are alive; the probe judges the frames.

use super::*;
use crate::{comp_probe, gpu_probe};
use frame_load::phases::{ORDER, Phase, Scene};

pub const IMAGE: &str = "boot-frame.img";
pub const STEPS_IMAGE: &str = "boot-frame-steps.img";
/// The disk of a run: the volume of the data service, made fresh.
const DISK_BYTES: u64 = 64 << 20;
const DATAFS_STACK_SIZE: u32 = 32 * 1024;
/// The stack of the network client: its roles keep tables of connections.
const NET_LOAD_STACK_SIZE: u32 = 128 * 1024;

/// The programs of `boot-frame.img`.
pub fn programs() -> &'static [ImageProgram] {
    static LIST: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| image_programs(&[], &[]))
}

/// The programs of `boot-frame-steps.img`: the display driver and the
/// compositor count their steps.
pub fn steps_programs() -> &'static [ImageProgram] {
    static LIST: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| image_programs(&["steps"], &["steps"]))
}

/// The programs of `boot-frame-steps.img` for a run that traces the bands: the compositor
/// also reads the system time of its thread and the entries its lookups look at in the table
/// of images (its feature `irq-trace`, which adds two calls of the kernel to a band: the
/// steps of such a run are no verdict of the gates).
pub fn trace_programs() -> &'static [ImageProgram] {
    static LIST: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| image_programs(&["steps"], &["irq-trace"]))
}

fn image_programs(
    driver: &'static [&'static str],
    compositor: &'static [&'static str],
) -> Vec<ImageProgram> {
    vec![
        ("init", "init", INIT_STACK_SIZE, &["table-frame"]),
        ("uart", "uart", UART_STACK_SIZE, &[]),
        ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
        ("pipe", "pipe", PIPE_STACK_SIZE, &[]),
        ("tty", "tty", TTY_STACK_SIZE, &[]),
        (
            "entropy",
            "entropy",
            crate::entropy::ENTROPY_STACK_SIZE,
            &[],
        ),
        ("netd", "netd", crate::net::NETD_STACK_SIZE, &[]),
        (
            "virtio-blk",
            "virtio-blk",
            crate::blk_probe::BLK_STACK_SIZE,
            &[],
        ),
        ("datafsd", "datafsd", DATAFS_STACK_SIZE, &[]),
        (
            "virtio-gpu",
            "virtio-gpu",
            gpu_probe::GPU_STACK_SIZE,
            driver,
        ),
        (
            "compositor",
            "compositor",
            comp_probe::COMP_STACK_SIZE,
            compositor,
        ),
        ("frame-load", "frame-load", CHILD_STACK_SIZE, &[]),
        ("data-probe", "data-probe", CHILD_STACK_SIZE, &[]),
        ("net-probe", "net-probe", NET_LOAD_STACK_SIZE, &[]),
    ]
}

/// `cargo xtask frame-image`: both images built on the host.
pub fn images() -> Result<(), String> {
    for (name, list) in [(IMAGE, programs()), (STEPS_IMAGE, steps_programs())] {
        let path = build_boot_image(name, list, BOOT_PROFILE)?;
        let size = std::fs::metadata(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?
            .len();
        println!("frame-image: {name}: {size} bytes ({})", path.display());
    }
    Ok(())
}

/// What a load printed, by the lines of the run.
fn number_after(lines: &[String], prefix: &str, word: &str) -> Option<u64> {
    let line = lines.iter().find(|l| l.starts_with(prefix))?;
    let mut words = line.split_whitespace();
    while let Some(w) = words.next() {
        if w == word {
            return words.next()?.parse().ok();
        }
    }
    None
}

/// Judges the lines of a run: no load failed, and every load did its work in the
/// phases the schedule gives it. The text is what the check says on success.
pub fn loads_verdict(lines: &[String]) -> Result<String, String> {
    if let Some(failed) = lines.iter().find(|l| {
        l.starts_with("frame-load: failed")
            || l.starts_with("net-probe: failed")
            || l.starts_with("data-probe: failed")
    }) {
        return Err(failed.clone());
    }
    let has = |text: &str| lines.iter().any(|l| l == text);
    if !has("frame-load: done") {
        return Err("the conductor never said done".to_owned());
    }
    let mut said = Vec::new();
    for phase in ORDER {
        let name = phase.name();
        if !lines
            .iter()
            .any(|l| l.starts_with(&format!("frame-load: phase {name} ")))
        {
            return Err(format!("no line of the phase {name}"));
        }
        if phase.loads().cpu || phase == Phase::Quiet {
            let prefix = format!("frame-load: cpu {name} ");
            match number_after(lines, &prefix, "loops-per-s") {
                Some(n) if n > 0 => said.push(format!("cpu {name} {n}")),
                _ => return Err(format!("no loops of the CPU load in the phase {name}")),
            }
        }
        match phase.scene() {
            Scene::P | Scene::F | Scene::O => {
                let prefix = format!("frame-load: draw {name} ");
                match number_after(lines, &prefix, "posts") {
                    Some(n) if n > 0 => said.push(format!("{name} posts {n}")),
                    _ => {
                        return Err(format!(
                            "the paced client posted nothing in the phase {name}"
                        ));
                    }
                }
            }
            Scene::D => {
                let prefix = format!("frame-load: legacy {name} ");
                match number_after(lines, &prefix, "flushes") {
                    Some(n) if n > 0 => said.push(format!("{name} flushes {n}")),
                    _ => return Err("the client of the first revision flushed nothing".to_owned()),
                }
            }
            Scene::None => {}
        }
    }
    let rounds = number_after(lines, "net-probe: load rounds", "rounds")
        .filter(|n| *n > 0)
        .ok_or("the network load made no round")?;
    let ops = number_after(lines, "data-probe: load ops", "ops")
        .filter(|n| *n > 0)
        .ok_or("the file load did no operation")?;
    said.push(format!("net rounds {rounds}"));
    said.push(format!("file ops {ops}"));
    Ok(said.join(", "))
}

/// Boots the image (the one of the measures under -icount when `steps`), runs
/// the phases and returns the lines of the run, the lines of the loads printed.
pub fn run(steps: bool) -> Result<Vec<String>, String> {
    run_traced(steps, false)
}

/// `run`, with the bands traced when `trace` (the steps image with `trace_programs`).
pub fn run_traced(steps: bool, trace: bool) -> Result<Vec<String>, String> {
    relibc()?;
    let kernel = build(Variant::Normal)?;
    let (name, list) = if trace {
        (STEPS_IMAGE, trace_programs())
    } else if steps {
        (STEPS_IMAGE, steps_programs())
    } else {
        (IMAGE, programs())
    };
    let image = build_boot_image(name, list, BOOT_PROFILE)?;
    let disk = std::env::temp_dir().join(format!("stafeto-frame-{}.img", std::process::id()));
    qemu::store_file(&disk, DISK_BYTES, true)?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::GPU);
    cmd.args(qemu::net(&[]));
    cmd.args(qemu::store(&disk, None));
    if steps {
        // The clock follows the instructions, and sleeps with the host while
        // the guest waits for the disk (stafeto/stafeto#459).
        cmd.args(["-icount", "shift=4,sleep=on"]);
    }
    let output = run_until(
        cmd,
        Duration::from_secs(1800),
        Some("frame-load: done"),
        &kernel.elf,
    );
    let _ = std::fs::remove_file(&disk);
    let output = output?;
    for line in output.lines.iter().filter(|l| {
        l.starts_with("frame-load: ")
            || l.starts_with("net-probe: ")
            || l.starts_with("data-probe: ")
    }) {
        println!("{line}");
    }
    Ok(output.lines)
}

/// `cargo xtask frame-loads [steps]`.
pub fn loads(args: &[String]) -> Result<(), String> {
    let steps = match args {
        [] => false,
        [word] if word == "steps" => true,
        _ => return Err("frame-loads [steps]".to_owned()),
    };
    let lines = run(steps)?;
    let said = loads_verdict(&lines).map_err(|e| format!("frame-loads: {e}"))?;
    println!(
        "frame-loads on {}: the loads are alive: {said}",
        qemu::VIRT.name
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lines of a good run.
    fn good() -> Vec<String> {
        let mut lines: Vec<String> = Vec::new();
        for phase in ORDER {
            let name = phase.name();
            lines.push(format!(
                "frame-load: phase {name} frames 240 bands 10 bypassed 0"
            ));
            if phase.loads().cpu || phase == Phase::Quiet {
                lines.push(format!("frame-load: cpu {name} loops-per-s 812345"));
            }
            match phase.scene() {
                Scene::P | Scene::F | Scene::O => lines.push(format!(
                    "frame-load: draw {name} posts 239 no-free-buffer 0"
                )),
                Scene::D => lines.push(format!("frame-load: legacy {name} flushes 77")),
                Scene::None => {}
            }
        }
        lines.push("net-probe: load rounds 31 bytes 8126464".to_owned());
        lines.push("data-probe: load ops 120 bytes 2031616".to_owned());
        lines.push("frame-load: done".to_owned());
        lines
    }

    #[test]
    fn a_good_run_passes() {
        let said = loads_verdict(&good()).unwrap();
        assert!(
            said.contains("net rounds 31") && said.contains("file ops 120"),
            "{said}"
        );
        assert!(said.contains("direct flushes 77"), "{said}");
    }

    /// Each load that did nothing, or a phase that is missing, fails with its name.
    #[test]
    fn a_load_that_did_nothing_fails() {
        let without = |text: &str| -> Vec<String> {
            good().into_iter().filter(|l| !l.contains(text)).collect()
        };
        for (cut, want) in [
            ("cpu full-loaded", "CPU load in the phase full-loaded"),
            (
                "draw net posts",
                "paced client posted nothing in the phase net",
            ),
            ("legacy direct flushes", "first revision flushed nothing"),
            ("load rounds", "no round"),
            ("load ops", "no operation"),
            ("phase files", "no line of the phase files"),
            ("frame-load: done", "never said done"),
        ] {
            let error = loads_verdict(&without(cut)).unwrap_err();
            assert!(error.contains(want), "{cut}: {error}");
        }
        let mut lines = good();
        for l in lines.iter_mut() {
            *l = l.replace("posts 239", "posts 0");
        }
        assert!(
            loads_verdict(&lines)
                .unwrap_err()
                .contains("posted nothing")
        );
    }

    #[test]
    fn a_failed_load_fails_the_run() {
        for failed in [
            "frame-load: failed: started after the epoch",
            "net-probe: failed: SEND failed",
            "data-probe: failed: put tmp",
        ] {
            let mut lines = good();
            lines.insert(3, failed.to_owned());
            assert_eq!(loads_verdict(&lines).unwrap_err(), failed);
        }
    }

    /// The images have the programs of their table and count the steps of the
    /// two services in the image of the measures alone.
    #[test]
    fn the_images_have_the_table_and_the_loads() {
        for (list, steps) in [(programs(), false), (steps_programs(), true)] {
            assert_eq!(list[0].3, &["table-frame"]);
            for name in ["virtio-gpu", "compositor"] {
                let service = list.iter().find(|p| p.0 == name).unwrap();
                assert_eq!(service.3.contains(&"steps"), steps, "{name}");
            }
            for program in ["frame-load", "data-probe", "net-probe", "netd", "datafsd"] {
                assert!(list.iter().any(|p| p.0 == program), "{program}");
            }
        }
    }
}
