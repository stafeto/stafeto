// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Build, run and test stafeto. Usage: `cargo xtask <command>`.

mod image;
mod qemu;

use std::path::{Path, PathBuf};
use std::process::{Command, exit};
use std::time::Duration;

const KERNEL_TARGET: &str = "aarch64-unknown-none-softfloat";
/// Spec 3.4: the kernel image file stays under 200 KB.
const KERNEL_LIMIT: u64 = 200 * 1024;
const BOOT_TIMEOUT: Duration = Duration::from_secs(30);
const TEST_TIMEOUT: Duration = Duration::from_secs(60);

const USAGE: &str = "usage: cargo xtask <command>

commands:
  build     build the kernel image and the boot image
  run       build and boot in QEMU (Ctrl-A X quits)
  test      host tests, then boot checks and kernel tests in QEMU
  gdb       boot in QEMU halted at the first instruction, debugger on :1234
  ci        formatting, clippy, then everything `test` does
  help      this text";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("build") => build(false).map(|_| ()),
        Some("run") => run(),
        Some("test") => test(),
        Some("gdb") => gdb(),
        Some("ci") => ci(),
        Some("help") | None => {
            println!("{USAGE}");
            Ok(())
        }
        Some(other) => Err(format!("unknown command {other:?}\n\n{USAGE}")),
    };
    if let Err(e) = result {
        eprintln!("xtask: {e}");
        exit(1);
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives in the workspace")
        .to_path_buf()
}

fn cargo() -> Command {
    let mut c = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    c.current_dir(root());
    c
}

fn run_cmd(cmd: &mut Command) -> Result<(), String> {
    let status = cmd.status().map_err(|e| format!("{cmd:?}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{cmd:?} failed: {status}"))
    }
}

fn stdout_of(cmd: &mut Command) -> Result<String, String> {
    let out = cmd.output().map_err(|e| format!("{cmd:?}: {e}"))?;
    String::from_utf8(out.stdout).map_err(|e| e.to_string())
}

/// Path of an LLVM tool from the `llvm-tools` rustup component.
fn llvm_tool(name: &str) -> Result<PathBuf, String> {
    let sysroot = stdout_of(
        Command::new("rustc")
            .current_dir(root())
            .args(["--print", "sysroot"]),
    )?;
    let version = stdout_of(Command::new("rustc").current_dir(root()).arg("-vV"))?;
    let host = version
        .lines()
        .find_map(|l| l.strip_prefix("host: "))
        .ok_or("`rustc -vV` has no host line")?;
    let path = Path::new(sysroot.trim())
        .join("lib/rustlib")
        .join(host)
        .join("bin")
        .join(name);
    if path.exists() {
        Ok(path)
    } else {
        Err(format!(
            "{} not found: run `rustup component add llvm-tools`",
            path.display()
        ))
    }
}

struct Artifacts {
    elf: PathBuf,
    image: PathBuf,
    boot_image: PathBuf,
}

fn build(ktest: bool) -> Result<Artifacts, String> {
    let mut cmd = cargo();
    cmd.args([
        "build",
        "--package",
        "kernel",
        "--release",
        "--target",
        KERNEL_TARGET,
    ]);
    if ktest {
        cmd.args(["--features", "ktest"]);
    }
    run_cmd(&mut cmd)?;
    let target = root().join("target");
    // Both builds write the same cargo output path; a copy next to each image
    // keeps the symbols that match it.
    let (elf, image) = if ktest {
        ("stafeto-ktest.elf", "stafeto-ktest.img")
    } else {
        ("stafeto.elf", "stafeto.img")
    };
    let (elf, image) = (target.join(elf), target.join(image));
    let built = target.join(KERNEL_TARGET).join("release").join("kernel");
    std::fs::copy(&built, &elf)
        .map_err(|e| format!("{} -> {}: {e}", built.display(), elf.display()))?;
    run_cmd(
        Command::new(llvm_tool("llvm-objcopy")?)
            .args(["-O", "binary"])
            .arg(&elf)
            .arg(&image),
    )?;
    let bytes = std::fs::read(&image).map_err(|e| format!("{}: {e}", image.display()))?;
    image::check_header(&bytes)?;
    image::check_size(bytes.len() as u64, KERNEL_LIMIT)?;
    let boot_image = target.join("boot.img");
    std::fs::write(&boot_image, image::placeholder_boot_image())
        .map_err(|e| format!("{}: {e}", boot_image.display()))?;
    println!(
        "kernel image {} ({} bytes, limit {KERNEL_LIMIT})",
        image.display(),
        bytes.len()
    );
    Ok(Artifacts {
        elf,
        image,
        boot_image,
    })
}

fn run() -> Result<(), String> {
    let a = build(false)?;
    run_cmd(qemu::command(&a.image, Some(&a.boot_image)).arg("-nographic"))
}

fn test() -> Result<(), String> {
    host_tests()?;
    boot_smoke()?;
    elf_boot_reports_missing_device_tree()?;
    kernel_tests()?;
    println!("all checks passed");
    Ok(())
}

fn host_tests() -> Result<(), String> {
    run_cmd(cargo().args(["test", "--package", "kcore", "--package", "xtask"]))
}

/// A normal build boots, prints its report and powers the machine off.
fn boot_smoke() -> Result<(), String> {
    let a = build(false)?;
    let mut cmd = qemu::command(&a.image, Some(&a.boot_image));
    cmd.args(qemu::HEADLESS);
    let o = qemu::run_until(cmd, BOOT_TIMEOUT, None)?;
    qemu::expect_clean_exit_with(&o, "boot complete")
}

/// Booting the ELF leaves x0 = 0; the kernel must say why it stops.
fn elf_boot_reports_missing_device_tree() -> Result<(), String> {
    let a = build(false)?;
    let mut cmd = qemu::command(&a.elf, None);
    cmd.args(qemu::HEADLESS);
    let o = qemu::run_until(cmd, BOOT_TIMEOUT, Some("no device tree in x0"))?;
    qemu::expect_marker(&o, "no device tree in x0")?;
    if !o.stopped_on_marker {
        return Err("QEMU was not stopped on the marker line".into());
    }
    Ok(())
}

/// Kernel built with `ktest`: runs its tests and exits QEMU through semihosting.
fn kernel_tests() -> Result<(), String> {
    let a = build(true)?;
    let mut cmd = qemu::command(&a.image, Some(&a.boot_image));
    cmd.args(qemu::HEADLESS).arg("-semihosting");
    let o = qemu::run_until(cmd, TEST_TIMEOUT, None)?;
    let r = qemu::parse_report(&o.lines);
    qemu::verdict(&o, &r)?;
    println!("kernel tests: {} passed", r.passed.len());
    Ok(())
}

fn gdb() -> Result<(), String> {
    let a = build(false)?;
    println!(
        "QEMU is halted before the kernel starts (kernel entry: PA 0x40200000). In another terminal:\n  lldb {} -o 'gdb-remote 1234'\nCode before the MMU runs at physical addresses; see docs/debugging.md.",
        a.elf.display()
    );
    run_cmd(qemu::command(&a.image, Some(&a.boot_image)).args(["-nographic", "-s", "-S"]))
}

fn ci() -> Result<(), String> {
    run_cmd(cargo().args(["fmt", "--all", "--check"]))?;
    run_cmd(cargo().args([
        "clippy",
        "--package",
        "kcore",
        "--package",
        "xtask",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ]))?;
    run_cmd(cargo().args([
        "clippy",
        "--package",
        "kcore",
        "--target",
        KERNEL_TARGET,
        "--",
        "-D",
        "warnings",
    ]))?;
    run_cmd(cargo().args([
        "clippy",
        "--package",
        "kernel",
        "--release",
        "--target",
        KERNEL_TARGET,
        "--",
        "-D",
        "warnings",
    ]))?;
    run_cmd(cargo().args([
        "clippy",
        "--package",
        "kernel",
        "--release",
        "--target",
        KERNEL_TARGET,
        "--features",
        "ktest",
        "--",
        "-D",
        "warnings",
    ]))?;
    test()
}
