// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The cube in a pbuffer (apps/gles-cube, `--pbuffer`): a static C program
//! on relibc with the Mesa of tools/build-mesa.py, in an image of the POSIX
//! probe's services with no display driver and no compositor. The program
//! draws ten frames with Mesa's softpipe driver into a surface of EGL that has
//! no window, reads each with glReadPixels and prints its CRC-32 and the sum of
//! its bytes; `verdict` checks the lines, and the CRCs against the ones of the
//! same Mesa built for Linux (tools/mesa-reference) when they are pinned.

use crate::{
    BOOT_PROFILE, INIT_STACK_SIZE, ImageProgram, PIPE_STACK_SIZE, RAMFS_STACK_SIZE, Variant, build,
    build_boot_image, qemu, run_until,
};
use std::time::Duration;

/// The stack of the cube's main thread: the GLSL compiler and NIR recurse
/// deeper than a C program of the probes does.
const CUBE_STACK_SIZE: u32 = 1024 * 1024;

/// The probe's image: the services of the POSIX process probe, with the cube
/// as its probe program.
pub const PROGRAMS: [ImageProgram; 9] = [
    ("init", "init", INIT_STACK_SIZE, &["table-gles-pbuffer"]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    ("pipe", "pipe", PIPE_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    ("gles-cube", "gles-cube", CUBE_STACK_SIZE, &[]),
    ("loader", "loader", 0, &[]),
    (
        "virtio-rng",
        "virtio-rng",
        crate::entropy::RNG_STACK_SIZE,
        &[],
    ),
    (
        "entropy",
        "entropy",
        crate::entropy::ENTROPY_STACK_SIZE,
        &[],
    ),
];

const ENDED: &str = "init: gles-cube ended: exit code 0, not restarted";
/// softpipe under TCG draws a frame in seconds, and the compiler of GLSL
/// runs for the shaders of the cube first.
const TIMEOUT: Duration = Duration::from_secs(900);
/// The prefix of the program's lines.
const PREFIX: &str = "gles-cube: ";
/// The frames the program draws.
pub const FRAMES: usize = 10;
/// The CRC-32 of each frame as the program prints it, once pinned: the
/// frames are the same on every run of the same build; the value is pinned
/// after two agreeing runs on different machines and a comparison with the
/// Linux build of the same Mesa (docs/egl.md).
pub const EXPECTED_CRCS: Option<[u32; FRAMES]> = Some([
    0x5e4a_1ff8,
    0xd6f0_240f,
    0xa9a4_73d5,
    0xf08d_b9a3,
    0xe83b_3f52,
    0x7b80_a167,
    0x59b3_27f6,
    0x775e_0ae2,
    0x90c5_0c70,
    0xab2d_6545,
]);

/// One frame line of the program: its number, CRC and byte sum.
fn frame_line(line: &str) -> Option<(usize, u32, u64)> {
    let mut words = line.split(' ');
    if words.next()? != "frame" {
        return None;
    }
    let number = words.next()?.parse().ok()?;
    if words.next()? != "crc" {
        return None;
    }
    let crc_text = words.next()?;
    if crc_text.len() != 8 {
        return None;
    }
    let crc = u32::from_str_radix(crc_text, 16).ok()?;
    if words.next()? != "sum" {
        return None;
    }
    let sum = words.next()?.parse().ok()?;
    if words.next().is_some() {
        return None;
    }
    Some((number, crc, sum))
}

/// What is wrong with the lines of a run, or `Ok`: a check of the program that
/// failed names itself; then the strings of the library (Mesa on softpipe,
/// OpenGL ES 3), the ten frames in order with ten different CRCs (the cube
/// turns), the last line of the program and the end line of init.
pub fn verdict(lines: &[String], expected: Option<[u32; FRAMES]>) -> Result<(), String> {
    if let Some(failed) = lines
        .iter()
        .find(|l| l.starts_with("gles-cube: check failed") || l.starts_with("gles-cube: shader"))
    {
        return Err(failed.clone());
    }
    let seen: Vec<&str> = lines
        .iter()
        .filter_map(|l| l.strip_prefix(PREFIX))
        .collect();
    let find = |prefix: &str| {
        seen.iter()
            .find_map(|l| l.strip_prefix(prefix))
            .ok_or_else(|| format!("the program printed no line {prefix:?}"))
    };
    if !find("EGL ")?.starts_with("1.5 ") {
        return Err(format!("EGL is {:?}, 1.5 expected", find("EGL ")?));
    }
    let renderer = find("GL_RENDERER ")?;
    if !renderer.contains("softpipe") {
        return Err(format!("the renderer is {renderer:?}, softpipe expected"));
    }
    let version = find("GL_VERSION ")?;
    if !version.contains("OpenGL ES 3.") || !version.contains("Mesa 26.3.1") {
        return Err(format!(
            "the version is {version:?}, OpenGL ES 3.x of Mesa 26.3.1 expected"
        ));
    }
    let frames: Vec<(usize, u32, u64)> = seen.iter().filter_map(|l| frame_line(l)).collect();
    if frames.len() != FRAMES {
        return Err(format!(
            "the program printed {} frame lines, {FRAMES} expected",
            frames.len()
        ));
    }
    for (at, (number, crc, sum)) in frames.iter().enumerate() {
        if *number != at {
            return Err(format!("frame line {at} is the one of frame {number}"));
        }
        if *sum == 0 {
            return Err(format!("frame {at} is all zeros"));
        }
        if let Some(expected) = expected
            && *crc != expected[at]
        {
            return Err(format!(
                "frame {at} has the CRC {crc:08x}, {:08x} expected",
                expected[at]
            ));
        }
    }
    let mut crcs: Vec<u32> = frames.iter().map(|f| f.1).collect();
    crcs.sort_unstable();
    crcs.dedup();
    if crcs.len() != FRAMES {
        return Err("two frames of the turning cube have the same CRC".to_owned());
    }
    if seen.last() != Some(&"ok") {
        return Err(format!(
            "the program ended with {:?}, \"ok\" expected",
            seen.last()
        ));
    }
    if !lines.iter().any(|l| l == ENDED) {
        return Err(format!("init never printed {ENDED:?}"));
    }
    Ok(())
}

/// `cargo xtask gles-pbuffer`.
pub fn probe(machine: &qemu::Machine) -> Result<(), String> {
    crate::mesa()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-gles-pbuffer.img", &PROGRAMS, BOOT_PROFILE)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    // Stops on any end of the program, so that a failure shows at once.
    let output = run_until(cmd, TIMEOUT, Some("init: gles-cube ended"), &kernel.elf)?;
    for line in output.lines.iter().filter(|l| l.starts_with(PREFIX)) {
        println!("{line}");
    }
    verdict(&output.lines, EXPECTED_CRCS)
        .map_err(|e| format!("gles-pbuffer on {}: {e}", machine.name))?;
    println!(
        "gles-pbuffer on {}: EGL 1.5 and OpenGL ES 3 on Mesa's softpipe, ten frames of a cube read back from a pbuffer: ok",
        machine.name
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run() -> Vec<String> {
        let mut lines = vec![
            "gles-cube: EGL 1.5 Mesa Project".to_owned(),
            "gles-cube: GL_VENDOR Mesa".to_owned(),
            "gles-cube: GL_RENDERER softpipe (LLVM none)".to_owned(),
            "gles-cube: GL_VERSION OpenGL ES 3.1 Mesa 26.3.1".to_owned(),
        ];
        for k in 0..FRAMES {
            lines.push(format!(
                "gles-cube: frame {k} crc {:08x} sum {}",
                0x1000_0000 + k as u32 * 0x1111,
                900_000 + k
            ));
        }
        lines.push("gles-cube: ok".to_owned());
        lines.insert(2, "unrelated line of the console".to_owned());
        lines.push(ENDED.to_owned());
        lines
    }

    #[test]
    fn the_expected_run_passes() {
        assert_eq!(verdict(&run(), None), Ok(()));
    }

    #[test]
    fn a_frame_line_is_read_whole_or_not_at_all() {
        assert_eq!(
            frame_line("frame 3 crc 0000abcd sum 17"),
            Some((3, 0xabcd, 17))
        );
        assert_eq!(frame_line("frame 3 crc abcd sum 17"), None);
        assert_eq!(frame_line("frame 3 crc 0000abcd sum 17 extra"), None);
        assert_eq!(frame_line("frame x crc 0000abcd sum 17"), None);
        assert_eq!(frame_line("frame 3 crc 0000abcg sum 17"), None);
        assert_eq!(frame_line("frames 3 crc 0000abcd sum 17"), None);
    }

    #[test]
    fn a_failed_check_names_itself() {
        let mut lines = run();
        lines.insert(
            6,
            "gles-cube: check failed at line 9: x == 1 (egl 0x3000 gl 0x0)".to_owned(),
        );
        assert!(verdict(&lines, None).unwrap_err().contains("check failed"));
    }

    #[test]
    fn a_doubled_frame_line_with_another_crc_is_refused() {
        let mut lines = run();
        let at = lines.iter().position(|l| l.contains("frame 4 ")).unwrap();
        lines.insert(at + 1, "gles-cube: frame 4 crc 00000001 sum 5".to_owned());
        assert!(verdict(&lines, None).unwrap_err().contains("frame lines"));
    }

    #[test]
    fn frames_out_of_order_or_alike_or_empty_are_refused() {
        let mut lines = run();
        let first = lines.iter().position(|l| l.contains("frame 2 ")).unwrap();
        lines.swap(first, first + 1);
        assert!(verdict(&lines, None).unwrap_err().contains("frame line"));
        let mut lines = run();
        let at = lines.iter().position(|l| l.contains("frame 6 ")).unwrap();
        lines[at] = "gles-cube: frame 6 crc 10000000 sum 900006".to_owned();
        assert!(verdict(&lines, None).unwrap_err().contains("same CRC"));
        let mut lines = run();
        let at = lines.iter().position(|l| l.contains("frame 1 ")).unwrap();
        lines[at] = "gles-cube: frame 1 crc 10001111 sum 0".to_owned();
        assert!(verdict(&lines, None).unwrap_err().contains("all zeros"));
    }

    #[test]
    fn the_pinned_crcs_are_compared() {
        let mut expected = [0u32; FRAMES];
        for (k, e) in expected.iter_mut().enumerate() {
            *e = 0x1000_0000 + k as u32 * 0x1111;
        }
        assert_eq!(verdict(&run(), Some(expected)), Ok(()));
        expected[7] ^= 1;
        assert!(
            verdict(&run(), Some(expected))
                .unwrap_err()
                .contains("frame 7")
        );
    }

    #[test]
    fn the_library_is_mesa_softpipe_on_es3() {
        let mut lines = run();
        let at = lines
            .iter()
            .position(|l| l.contains("GL_RENDERER"))
            .unwrap();
        lines[at] = "gles-cube: GL_RENDERER llvmpipe".to_owned();
        assert!(verdict(&lines, None).unwrap_err().contains("softpipe"));
        let mut lines = run();
        let at = lines.iter().position(|l| l.contains("GL_VERSION")).unwrap();
        lines[at] = "gles-cube: GL_VERSION OpenGL ES 2.0".to_owned();
        assert!(verdict(&lines, None).unwrap_err().contains("expected"));
    }

    #[test]
    fn a_run_without_the_last_line_or_the_end_of_init_is_refused() {
        let mut lines = run();
        lines.pop();
        assert!(verdict(&lines, None).unwrap_err().contains("init never"));
        let mut lines = run();
        let at = lines.iter().position(|l| l == "gles-cube: ok").unwrap();
        lines.remove(at);
        assert!(verdict(&lines, None).unwrap_err().contains("ok"));
    }
}
