// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The system through the EFI loader (stafeto-design tasks/2026-11-12-aws-efi-loader.md, section 7): the disk of
//! `efi_disk`, QEMU's edk2 firmware, the machines `EFI` and `EFI_EL2`, and
//! the checks that the system reaches the shell by this route and that the
//! kernel's boot report is the one of the same machine started with
//! `-kernel`.

use crate::qemu::{self, Machine};
use crate::{Artifacts, Variant, build, efi_disk};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// The GICv3 machine with an ITS and ACPI tables, the kernel entered at EL1.
/// With `acpi=on` QEMU still builds a device tree for `-kernel`, which is
/// what the reference run takes (the note, section 7).
pub const EFI: Machine = Machine {
    name: "EFI",
    machine: "virt,gic-version=3,its=on,acpi=on,highmem-ecam=off",
    cpu: "cortex-a72",
    memory: "512M",
    accel: "tcg",
};

/// `EFI` with the kernel entered at EL2 (PSCI through SMC).
pub const EFI_EL2: Machine = Machine {
    name: "EFI_EL2",
    machine: "virt,gic-version=3,its=on,acpi=on,highmem-ecam=off,virtualization=on",
    cpu: "cortex-a72",
    memory: "512M",
    accel: "tcg",
};

/// `EFI` with 2 GiB: RAM spans two GiBs, which the break `break-dtb-gib`
/// needs to put the tree across a GiB boundary.
pub const EFI_2G: Machine = Machine {
    name: "EFI_2G",
    machine: "virt,gic-version=3,its=on,acpi=on,highmem-ecam=off",
    cpu: "cortex-a72",
    memory: "2G",
    accel: "tcg",
};

/// Where the loader puts the kernel on these machines: the first 2 MiB
/// boundary of free memory (the loader prints it).
const LOADER_KERNEL_PA: u64 = 0x4000_0000;

pub const MACHINES: [&Machine; 2] = [&EFI, &EFI_EL2];

/// The firmware's two files, as QEMU installs them under `share/qemu` next to
/// the binary: the code and the template of the variables (edk2's
/// descriptor `60-edk2-aarch64.json`).
pub struct Firmware {
    pub code: PathBuf,
    pub vars: PathBuf,
}

const CODE_FILE: &str = "edk2-aarch64-code.fd";
const VARS_FILE: &str = "edk2-arm-vars.fd";

pub fn firmware() -> Result<Firmware, String> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let qemu = std::env::split_paths(&path)
        .map(|d| d.join("qemu-system-aarch64"))
        .find(|p| p.is_file())
        .ok_or("no qemu-system-aarch64 on PATH")?;
    let qemu = qemu
        .canonicalize()
        .map_err(|e| format!("{}: {e}", qemu.display()))?;
    let share = qemu
        .parent()
        .and_then(Path::parent)
        .map(|p| p.join("share/qemu"))
        .ok_or("QEMU's binary has no prefix")?;
    let find = |name: &str| {
        let p = share.join(name);
        p.is_file().then_some(p.clone()).ok_or(format!(
            "{} is missing: this QEMU ships no edk2 firmware (a build from source installs it \
             next to the binary when bzip2 is present; the ci cache key of QEMU is raised then)",
            p.display()
        ))
    };
    Ok(Firmware {
        code: find(CODE_FILE)?,
        vars: find(VARS_FILE)?,
    })
}

/// The loader built for the UEFI target with `features`, copied to a name of
/// its own under target/.
pub fn build_loader(features: &[&str]) -> Result<PathBuf, String> {
    let mut cmd = crate::cargo();
    cmd.args([
        "build",
        "--package",
        "efi-loader",
        "--release",
        "--target",
        "aarch64-unknown-uefi",
    ]);
    if !features.is_empty() {
        cmd.args(["--features", &features.join(",")]);
    }
    crate::run_cmd(&mut cmd)?;
    let built = crate::target_dir().join("aarch64-unknown-uefi/release/efi-loader.efi");
    let tag = if features.is_empty() {
        "plain".to_string()
    } else {
        features.join("+")
    };
    let copy = crate::target_dir().join(format!("efi-loader-{tag}.efi"));
    std::fs::copy(&built, &copy).map_err(|e| format!("{}: {e}", built.display()))?;
    Ok(copy)
}

/// The disk with the loader as the removable-media default, the kernel and
/// the boot image of `a`.
pub fn make_disk(loader: &Path, a: &Artifacts, out: &Path) -> Result<(), String> {
    let read = |p: &Path| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
    let (loader, kernel, image) = (read(loader)?, read(&a.image)?, read(&a.boot_image)?);
    efi_disk::build(
        out,
        &[
            efi_disk::EspFile {
                path: "EFI/BOOT/BOOTAA64.EFI",
                bytes: &loader,
            },
            efi_disk::EspFile {
                path: "stafeto/Image",
                bytes: &kernel,
            },
            efi_disk::EspFile {
                path: "stafeto/boot.img",
                bytes: &image,
            },
        ],
    )
}

/// QEMU on `disk` under edk2: the firmware's code read-only, a fresh copy of
/// the template for the variables, the disk on an NVMe controller (the
/// nearest thing to EBS, which leaves the virtio-blk of the store alone),
/// `snapshot=on` unless the run writes to it (the dump of the tables).
pub fn command(
    m: &Machine,
    fw: &Firmware,
    disk: &Path,
    snapshot: bool,
    name: &str,
) -> Result<Command, String> {
    let vars = crate::target_dir().join(format!("efi-vars-{name}.fd"));
    std::fs::copy(&fw.vars, &vars).map_err(|e| format!("{}: {e}", vars.display()))?;
    let mut c = Command::new("qemu-system-aarch64");
    c.args([
        "-machine", m.machine, "-accel", m.accel, "-cpu", m.cpu, "-m", m.memory, "-smp", "2",
    ]);
    c.args(qemu::ENTROPY).args(qemu::NO_NIC);
    c.arg("-drive").arg(format!(
        "if=pflash,format=raw,unit=0,readonly=on,file={}",
        fw.code.display()
    ));
    c.arg("-drive").arg(format!(
        "if=pflash,format=raw,unit=1,file={}",
        vars.display()
    ));
    c.arg("-drive").arg(format!(
        "file={},if=none,format=raw,id=esp{}",
        disk.display(),
        if snapshot { ",snapshot=on" } else { "" }
    ));
    c.args(["-device", "nvme,drive=esp,serial=stafeto-esp,bootindex=0"]);
    c.args(qemu::HEADLESS);
    Ok(c)
}

/// The lines of the boot report the two routes must give alike (the note,
/// section 7): the interrupt controller, the ITS, the CPUs, PSCI, the
/// timer's frequency. The memory and the boot image lines differ with the
/// places the loader and QEMU chose.
fn alike(line: &str) -> bool {
    ["gic ", "its ", "cpu ", "psci ", "timer ", "sgi ", "pl011 "]
        .iter()
        .any(|p| line.starts_with(p))
}

fn report_lines(lines: &[String]) -> Vec<String> {
    lines.iter().filter(|l| alike(l)).cloned().collect()
}

pub struct Booted {
    pub lines: Vec<String>,
    pub to_shell: Duration,
}

/// Boots `cmd` to the shell, runs `echo hello stafeto` there, and gives the console's
/// lines and the time from the start to the shell (host clock).
fn boot(cmd: Command, what: &str, elf: &Path) -> Result<Booted, String> {
    let start = Instant::now();
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let talked = (|| {
        run.expect_line(
            crate::SHELL_CONNECTED,
            |l| l == crate::SHELL_CONNECTED,
            Duration::from_secs(120),
        )?;
        let to_shell = start.elapsed();
        run.expect(crate::PROMPT, crate::DIALOG_STEP)?;
        run.send("echo hello stafeto")?;
        run.expect_line("echo", |l| l == "hello stafeto", crate::DIALOG_STEP)?;
        Ok::<_, String>(to_shell)
    })();
    let o = run.stop();
    crate::symbolize::backtrace(&o.lines, elf);
    let to_shell = talked.map_err(|e| format!("{what}: {e}"))?;
    if let Some(p) = o.lines.iter().find(|l| l.contains("KERNEL PANIC")) {
        return Err(format!("{what}: {p}"));
    }
    Ok(Booted {
        lines: o.lines,
        to_shell,
    })
}

/// Waits until no run of another worktree measures on the host (the rule
/// of the shared Mac): at most 40 minutes.
fn wait_for_quiet_mac() -> Result<(), String> {
    for _ in 0..40 {
        let out = Command::new("sh")
            .args([
                "-c",
                "ps -ax | grep -E 'vz-run|wrk |xtask net-bench' | grep -v grep | grep -v gated.sh | grep -v 'zsh -c' | wc -l",
            ])
            .output()
            .map_err(|e| e.to_string())?;
        if String::from_utf8_lossy(&out.stdout).trim() == "0" || std::env::var_os("CI").is_some() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(60));
    }
    Err("another run keeps measuring on this Mac".into())
}

/// `cargo xtask efi [EFI|EFI_EL2]`: for each machine, the reference boot with
/// `-kernel`, then the boot through the loader and edk2 from the disk, and
/// the comparison of the boot reports.
pub fn run(names: &[String]) -> Result<(), String> {
    let fw = firmware()?;
    let machines: Vec<&Machine> = if names.is_empty() {
        MACHINES.to_vec()
    } else {
        names
            .iter()
            .map(|n| {
                MACHINES
                    .into_iter()
                    .find(|m| m.name == n)
                    .ok_or(format!("no machine {n}"))
            })
            .collect::<Result<_, _>>()?
    };
    let a = build(Variant::Normal)?;
    let loader = build_loader(&[])?;
    for m in machines {
        let disk = crate::target_dir().join(format!("efi-disk-{}.raw", m.name));
        make_disk(&loader, &a, &disk)?;
        wait_for_quiet_mac()?;
        let mut reference = qemu::command(m, &a.image, Some(&a.boot_image));
        reference.args(["-smp", "2"]).args(qemu::HEADLESS);
        let want = boot(reference, &format!("{} with -kernel", m.name), &a.elf)?;
        wait_for_quiet_mac()?;
        let cmd = command(m, &fw, &disk, true, m.name)?;
        let got = boot(cmd, &format!("{} through the loader", m.name), &a.elf)?;
        let (w, g) = (report_lines(&want.lines), report_lines(&got.lines));
        if w.is_empty() || w != g {
            return Err(format!(
                "{}: the boot report differs:\n-kernel: {w:#?}\nloader:  {g:#?}",
                m.name
            ));
        }
        let loader_lines: Vec<&String> = got
            .lines
            .iter()
            .filter(|l| l.contains("efi-loader:"))
            .collect();
        for l in &loader_lines {
            println!("{}: {l}", m.name);
        }
        println!(
            "efi on {}: ok; boot report equal to -kernel ({} lines), {:.1} s from the firmware to the shell (-kernel {:.1} s)",
            m.name,
            w.len(),
            got.to_shell.as_secs_f64(),
            want.to_shell.as_secs_f64()
        );
    }
    Ok(())
}

/// Where the samples of the host test of the translation live.
pub const FIXTURES: &str = "boot/firmware-tree/tests/fixtures";

/// `cargo xtask efi-fixtures [NAME]`: the loader with `dump` on `EFI` writes
/// the firmware's ACPI tables, its memory map and the GUIDs of its
/// configuration tables to the ESP and stops; the files and QEMU's own
/// tree of the same machine (`dumpdtb`) go to `FIXTURES/qemu-efi/`.
pub fn fixtures(args: &[String]) -> Result<(), String> {
    // `efi-fixtures vz DISK`: the dump a run of vz-run --efi-writable left on DISK.
    if let [kind, disk] = args {
        if kind == "vz-disk" {
            // A fresh disk with the dump loader, for `vz-run --efi-writable`.
            let a = build(Variant::Normal)?;
            return make_disk(&build_loader(&["dump"])?, &a, Path::new(disk));
        }
        if kind != "vz" {
            return Err("usage: efi-fixtures [vz DISK]".into());
        }
        let out = crate::root().join(FIXTURES).join("vz-efi");
        std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
        for (name, bytes) in efi_disk::read_dir(Path::new(disk), "stafeto/dump")? {
            std::fs::write(out.join(&name), bytes).map_err(|e| format!("{name}: {e}"))?;
            println!("fixture vz-efi/{name}");
        }
        return Ok(());
    }
    let fw = firmware()?;
    let a = build(Variant::Normal)?;
    let loader = build_loader(&["dump"])?;
    let disk = crate::target_dir().join("efi-disk-dump.raw");
    make_disk(&loader, &a, &disk)?;
    wait_for_quiet_mac()?;
    let cmd = command(&EFI, &fw, &disk, false, "dump")?;
    let o = qemu::run_until(
        cmd,
        Duration::from_secs(120),
        Some("efi-loader: dump written"),
    )?;
    if !o.stopped_on_marker {
        return Err(format!(
            "the loader wrote no dump; last lines: {:?}",
            &o.lines[o.lines.len().saturating_sub(6)..]
        ));
    }
    let out = crate::root().join(FIXTURES).join("qemu-efi");
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    for (name, bytes) in efi_disk::read_dir(&disk, "stafeto/dump")? {
        std::fs::write(out.join(&name), bytes).map_err(|e| format!("{name}: {e}"))?;
        println!("fixture {name}");
    }
    // QEMU's tree of the same machine: the arguments of the run, and the
    // machine told to write it out and exit.
    let dtb = out.join("virt.dtb");
    wait_for_quiet_mac()?;
    let status = Command::new("qemu-system-aarch64")
        .args([
            "-machine",
            &format!("{},dumpdtb={}", EFI.machine, dtb.display()),
        ])
        .args([
            "-cpu", EFI.cpu, "-m", EFI.memory, "-smp", "2", "-display", "none",
        ])
        .args(qemu::ENTROPY)
        .args(qemu::NO_NIC)
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!("dumpdtb: {status}"));
    }
    // QEMU writes its whole 1 MiB buffer and says so in the header: the
    // blob ends where its strings do, and the header says that.
    let mut blob = std::fs::read(&dtb).map_err(|e| e.to_string())?;
    let be = |at: usize| u32::from_be_bytes(blob[at..at + 4].try_into().unwrap()) as usize;
    let end = (be(8) + be(36)).max(be(12) + be(32));
    blob.truncate(end);
    blob[4..8].copy_from_slice(&(end as u32).to_be_bytes());
    std::fs::write(&dtb, blob).map_err(|e| e.to_string())?;
    std::fs::write(
        out.join("machine.txt"),
        format!(
            "{} -cpu {} -m {} -smp 2\n",
            EFI.machine, EFI.cpu, EFI.memory
        ),
    )
    .map_err(|e| e.to_string())?;
    println!("fixture virt.dtb");
    Ok(())
}

/// What a deliberate break must do (stafeto-design tasks/2026-11-12-aws-efi-loader.md, section 7), the host tests
/// of `firmware-tree` and the run of the loader under QEMU.
struct Break {
    feature: &'static str,
    /// The host tests of firmware-tree with the feature must fail.
    host_fails: bool,
    /// The loader's own run: Some(what it must show).
    run: Option<Expect>,
}

enum Expect {
    /// The loader refuses, saying a text with this fragment, and the shell
    /// never comes.
    Refused(&'static str),
    /// The kernel's boot report lacks its `pl011` line: the tree has no
    /// PL011 node, as the kernel reads the console from it.
    NoPl011,
    /// The kernel panics before it knows its port; the text is read from
    /// the log ring in RAM through the monitor (spec 3.2).
    KernelPanic(&'static str),
}

const BREAKS: [Break; 4] = [
    Break {
        feature: "break-merge",
        host_fails: true,
        run: Some(Expect::Refused("more regions")),
    },
    Break {
        feature: "break-spcr",
        host_fails: true,
        run: Some(Expect::NoPl011),
    },
    Break {
        feature: "break-iort-count",
        host_fails: true,
        run: None,
    },
    Break {
        feature: "break-dtb-gib",
        host_fails: true,
        run: Some(Expect::KernelPanic("crosses a GiB boundary")),
    },
];

fn host_tests_fail(feature: &str) -> Result<bool, String> {
    let status = crate::cargo()
        .args([
            "test",
            "--package",
            "firmware-tree",
            "--features",
            feature,
            "--quiet",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| e.to_string())?;
    Ok(!status.success())
}

/// A boot of `m` from a disk with the loader built with `features`: the
/// outcome of a run that stops on the shell or after `limit`.
fn loader_run(
    m: &Machine,
    a: &Artifacts,
    features: &[&str],
    limit: Duration,
) -> Result<qemu::Outcome, String> {
    let fw = firmware()?;
    let loader = build_loader(features)?;
    let disk = crate::target_dir().join(format!("efi-disk-{}.raw", m.name));
    make_disk(&loader, a, &disk)?;
    wait_for_quiet_mac()?;
    let cmd = command(m, &fw, &disk, true, m.name)?;
    qemu::run_until(cmd, limit, Some(crate::SHELL_CONNECTED))
}

/// The loader built with `feature` on `EFI_2G`, with a monitor: the kernel's
/// panic text is read from its log ring in RAM until it holds `text`.
fn ring_panic(a: &Artifacts, feature: &str, text: &str) -> Result<(), String> {
    let fw = firmware()?;
    let loader = build_loader(&[feature])?;
    let disk = crate::target_dir().join("efi-disk-EFI_2G.raw");
    make_disk(&loader, a, &disk)?;
    wait_for_quiet_mac()?;
    let mut cmd = command(&EFI_2G, &fw, &disk, true, EFI_2G.name)?;
    let port = crate::ring::free_port()?;
    // The headless arguments of `command` set `-monitor none`: the later
    // monitor of the ring wins.
    cmd.args(crate::ring::monitor_args(port));
    let dump = crate::target_dir().join("efi-ring.bin");
    crate::ring::wait_for_at(
        LOADER_KERNEL_PA,
        cmd,
        port,
        &dump,
        text,
        Duration::from_secs(120),
    )
    .map(|_| ())
    .map_err(|e| format!("{feature}: {e}"))
}

/// `cargo xtask efi-breaks`: every deliberate break fails its test: the host
/// tests that compare the tree, and the run under edk2 that sees the
/// loader refuse or the kernel stay silent; the stale key of the exit is
/// survived and, without the retry, refused.
pub fn breaks() -> Result<(), String> {
    let a = build(Variant::Normal)?;
    for b in &BREAKS {
        if b.host_fails && !host_tests_fail(b.feature)? {
            return Err(format!("{}: the host tests still pass", b.feature));
        }
        println!("{}: the host tests fail", b.feature);
        let Some(expect) = &b.run else { continue };
        if let Expect::KernelPanic(text) = expect {
            ring_panic(&a, b.feature, text)?;
            println!(
                "{}: the run under edk2 ends in the kernel's panic",
                b.feature
            );
            continue;
        }
        let o = loader_run(&EFI, &a, &[b.feature], Duration::from_secs(90))?;
        let shell = o.lines.iter().any(|l| l == crate::SHELL_CONNECTED);
        let booted = o.lines.iter().any(|l| crate::is_booting(l));
        match expect {
            Expect::Refused(text) => {
                let said = o
                    .lines
                    .iter()
                    .any(|l| l.contains("efi-loader: refused") && l.contains(text));
                if shell || !said {
                    return Err(format!(
                        "{}: the loader did not refuse with {text:?}",
                        b.feature
                    ));
                }
            }
            Expect::KernelPanic(_) => unreachable!(),
            Expect::NoPl011 => {
                if o.lines.iter().any(|l| l.starts_with("pl011 ")) || !booted {
                    return Err(format!("{}: the kernel still reports its PL011", b.feature));
                }
            }
        }
        println!("{}: the run under edk2 fails as it must", b.feature);
    }
    // The stale key: survived with the retry, refused without it.
    let o = loader_run(&EFI, &a, &["stale-key"], Duration::from_secs(120))?;
    if !o.lines.iter().any(|l| l == crate::SHELL_CONNECTED)
        || !o
            .lines
            .iter()
            .any(|l| l.contains("ExitBootServices took 2 attempts"))
    {
        return Err("stale-key: the exit did not retry and succeed".into());
    }
    println!("stale-key: the exit retried once and the system came up");
    let o = loader_run(
        &EFI,
        &a,
        &["stale-key", "break-ebs-retry"],
        Duration::from_secs(90),
    )?;
    if o.lines.iter().any(|l| l == crate::SHELL_CONNECTED)
        || !o.lines.iter().any(|l| l.contains("stale memory map key"))
    {
        return Err("break-ebs-retry: the loader did not stop on the stale key".into());
    }
    println!("break-ebs-retry: the loader stops on the stale key");
    println!(
        "break-clean: not caught under TCG, which models no caches (G18, G38); the clean is checked \
         by the HVF run and by reading the hand-over (cpu::clean_range)"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_lines_of_the_hardware_are_compared() {
        assert!(alike(
            "gic        v3 distributor 0x8000000, redistributor 0x80a0000"
        ));
        assert!(!alike("memory     0x40000000..0x60000000"));
        assert!(!alike("boot image 0x48000000..0x48005000"));
    }

    #[test]
    fn the_machines_differ_in_the_level_the_kernel_is_entered_at() {
        assert_eq!((EFI.psci(), EFI_EL2.psci()), ("Hvc", "Smc"));
        assert!(EFI.msi() && EFI_EL2.msi());
    }
}
