// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask layer-time`: the measurement of the layered root on the machine of the try-out on
//! QEMU (EFI's machine with the second NVMe controller as the data volume), the local twin of
//! `cargo xtask aws image --layered` followed by `cargo xtask aws boot --end "layer-time: done"`.
//! It builds the image of the try-out with the layered root and the program `layer-time`
//! (`STAFETO_LAYERED_ROOT=1`, `STAFETO_LAYER_TIME=1`), the volume of the steps probe (8,192 names
//! in the live layer) as the data volume, boots until the program says `layer-time: done`, and
//! prints the lines of the measurement: the build of the index of the layer service, the
//! start of the shell, and the lines of `layer-time`. The numbers are the machine's own (TCG on the
//! host), so they check the program and the image and measure nothing about EC2.

use crate::net_try::IMAGE;
use crate::{
    BOOT_PROFILE, Variant, build, busybox_build, efi, keys, nano_build, probe_ca, qemu, relibc,
};
use std::time::{Duration, Instant};

/// The line the measurement ends with.
pub const END: &str = "layer-time: done";
/// The serial number of the data volume the table of the try-out asks for.
const DATA_SERIAL: &str = "stafeto-data";
/// The time the boot and the measurement may take on the host's emulation.
const WITHIN: Duration = Duration::from_secs(900);

/// The lines of the measurement in the console of a boot: those that belong to it, in order.
pub fn report(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter(|l| {
            l.contains("layer-time:")
                || l.contains("datafs: READY at ")
                || l.contains("layerd: STARTING answered")
                || l.contains("layerd: index of ")
                || l.contains("layerd: serve ran")
                || l.contains("init: free pages ")
                || l.contains("busybox-probe")
        })
        .cloned()
        .collect()
}

/// The measurements the program must have made: each of these starts a line that is there.
const DUE: [&str; 9] = [
    "layer-time: first path of a fresh process",
    "layer-time: second path",
    "layer-time: copy up of 1 KiB",
    "layer-time: copy up of 1 MiB",
    "layer-time: copy up of 16 MiB",
    "layer-time: open of the copy of 16 MiB again",
    "layer-time: copy of an open that truncates",
    "layer-time: answers STARTING",
    END,
];

/// Whether the lines hold every measurement, each once, and no failure.
pub fn check(lines: &[String]) -> Result<(), String> {
    for due in DUE {
        let n = lines.iter().filter(|l| l.contains(due)).count();
        if n != 1 {
            return Err(format!("the line {due:?} came {n} times, once was due"));
        }
    }
    if let Some(bad) = lines
        .iter()
        .find(|l| l.contains("layer-time:") && (l.contains("failed") || l.contains("errno")))
    {
        return Err(format!("a measurement failed: {bad}"));
    }
    if !lines.iter().any(|l| l.contains("layerd: index of ")) {
        return Err("the layer service said nothing of the build of its index".to_owned());
    }
    // The uptime at READY of both services, to read the time from one to the other.
    if !lines.iter().any(|l| l.contains("datafs: READY at ")) {
        return Err("the data file service said nothing of its uptime at READY".to_owned());
    }
    if !lines
        .iter()
        .any(|l| l.contains("layerd: index of ") && l.contains("READY at "))
    {
        return Err("the line of the index has no uptime at READY".to_owned());
    }
    // The counts of the answers STARTING by cause: one line with the READY line, and one after
    // the measurement (the program asks once more after a pause).
    let counts = lines
        .iter()
        .filter(|l| l.contains("layerd: STARTING answered"))
        .count();
    if counts < 1 {
        return Err("the layer service printed no count of its answers STARTING".to_owned());
    }
    Ok(())
}

pub fn command(_args: &[String]) -> Result<(), String> {
    // Read where the program list and the files of the image are made.
    // SAFETY: xtask is single-threaded here, before anything is built.
    unsafe {
        std::env::set_var("STAFETO_LAYERED_ROOT", "1");
        std::env::set_var("STAFETO_LAYER_TIME", "1");
    }
    let machine = &qemu::VIRT_2G;
    if machine.ram() < 2 << 30 {
        return Err(format!(
            "layer-time needs a machine of 2 GiB, {} has {}",
            machine.name, machine.memory
        ));
    }
    let dir = crate::target_dir().join("layer-time");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    relibc()?;
    busybox_build()?;
    nano_build()?;
    crate::net_build()?;
    let kernel = build(Variant::Normal)?;
    // The image of EC2 with the measurement passes the gate `aws image` runs before it registers
    // the disk (the image check, no private key, the notices).
    let aws_image = crate::aws_boot_image()?;
    crate::net_try::gate_aws_image(&aws_image)?;
    for (what, want) in [
        ("/bin/layer-time", true),
        ("/usr/share/layer-time/big", true),
    ] {
        let files = crate::rootfs::files_of(crate::net_try::AWS_IMAGE);
        if files.iter().any(|f| f.path == what) != want {
            return Err(format!("the image of EC2 lacks {what}"));
        }
    }
    probe_ca::ensure(false)?;
    keys::dev_keys(&crate::root())?;
    let roots = crate::pkg_probe::roots_path();
    let roots_text = roots.display().to_string();
    let image = crate::write_boot_image_files(
        IMAGE,
        crate::aws_qemu_programs(),
        BOOT_PROFILE,
        &[("STAFETO_PKG_ROOTS", &roots_text)],
        Vec::new(),
    )?;
    let firmware = efi::firmware()?;
    let loader = efi::build_loader(&[])?;
    let esp = crate::target_dir().join("efi-disk-layer-time.raw");
    let artifacts = crate::Artifacts {
        boot_image: image,
        ..kernel.clone()
    };
    efi::make_disk(&loader, &artifacts, &esp)?;
    let volume = dir.join("data-volume.raw");
    crate::data_image::make_layer_steps_volume(&volume, crate::data_image::DEFAULT_SIZE)?;
    let mut cmd = efi::command(&efi::EFI_2G, &firmware, &esp, true, "layer-time")?;
    cmd.arg("-drive").arg(format!(
        "file={},if=none,format=raw,id=data,cache=writeback,werror=report,rerror=report",
        volume.display()
    ));
    cmd.args([
        "-device",
        &format!("nvme,serial={DATA_SERIAL},bus=pcie.0,addr=0x4,drive=data"),
    ]);
    cmd.args(qemu::net(&[]));
    let began = Instant::now();
    let mut run = qemu::Run::start(cmd, qemu::Input::Null)?;
    let ended = run.expect_line(END, |l| l.contains(END), WITHIN);
    let output = run.stop();
    crate::symbolize::backtrace(&output.lines, &kernel.elf);
    ended?;
    let lines = report(&output.lines);
    check(&output.lines)?;
    println!(
        "layer-time: the measurement ran on the image of the try-out on QEMU in {} s; the lines of it:",
        began.elapsed().as_secs()
    );
    for l in lines {
        println!("  {l}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines() -> Vec<String> {
        let mut v = vec![
            "datafs: READY at 1500 ms of uptime".to_owned(),
            "layerd: index of 8192 names and 2005 deletions built in 900 ms, 1700 steps, 3 overruns, READY at 2500 ms of uptime"
                .to_owned(),
            "layerd: STARTING answered 3: build 3 notary 0 jobs 0 copies 0 compaction 0 reaper 0 listing 0 lock 0".to_owned(),
        ];
        v.extend(DUE.iter().map(|d| format!("{d}: 5 us")));
        v
    }

    #[test]
    fn a_run_with_every_measurement_passes() {
        assert!(check(&lines()).is_ok());
    }

    #[test]
    fn a_missing_measurement_or_a_failed_one_does_not() {
        let mut v = lines();
        v.remove(5);
        assert!(check(&v).is_err());
        let mut v = lines();
        v.push("layer-time: open of /x failed, errno 2".to_owned());
        assert!(check(&v).is_err());
        let mut v = lines();
        v.remove(1);
        assert!(check(&v).is_err());
        let mut v = lines();
        v.remove(0);
        assert!(check(&v).is_err());
        let mut v = lines();
        v.remove(2);
        assert!(check(&v).is_err());
    }

    #[test]
    fn the_report_keeps_the_lines_of_the_measurement() {
        let mut v = lines();
        v.push("net: lease 10.0.0.2".to_owned());
        assert_eq!(report(&v).len(), lines().len());
    }
}
