// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the time in the ash dialog (#380): `date` shows the time of
//! the host, and the files of the image have the time of the build that the
//! table of the image carries (`date -r`).

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{DIALOG_STEP, qemu};

/// How far the guest's `date` may be from the host's, in seconds: the time
/// a command takes to type and run, with room for a slow host.
const SKEW: u64 = 120;

/// The time of the build in the table of the boot image at `path`.
pub fn image_time(path: &Path) -> Result<u64, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let image =
        bootimg::BootImage::parse(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    let table = image
        .files()
        .find(|f| f.name == "rootfs")
        .ok_or_else(|| format!("{}: no table of files", path.display()))?;
    let table = bootimg::rootfs::Rootfs::parse(table.data, image.count())
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(table.time())
}

fn host_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| e.to_string())
}

/// `date` and `date -r` in the dialog at its prompt. `image` is the boot
/// image of the machine.
pub fn check(run: &mut qemu::Run, image: &Path) -> Result<(), String> {
    let built = image_time(image)?;
    if built < rtc::FLOOR {
        return Err(format!(
            "the table of {} has the build time {built}, before 2026",
            image.display()
        ));
    }
    run.send("date +%s")?;
    run.expect("date +%s", DIALOG_STEP)?;
    let seconds = run.expect_line(
        "the seconds of date",
        |line| !line.is_empty() && line.bytes().all(|b| b.is_ascii_digit()),
        DIALOG_STEP,
    )?;
    let guest: u64 = seconds
        .parse()
        .map_err(|_| format!("date gave {seconds:?}"))?;
    let host = host_now()?;
    if guest.abs_diff(host) > SKEW {
        return Err(format!(
            "the guest's date is {guest} and the host's {host}: more than {SKEW} s apart"
        ));
    }
    run.expect("# ", DIALOG_STEP)?;
    for path in ["/bin/busybox", "/etc/passwd"] {
        let command = format!("date -r {path} +%s");
        run.send(&command)?;
        run.expect(&command, DIALOG_STEP)?;
        let seconds = run.expect_line(
            path,
            |line| !line.is_empty() && line.bytes().all(|b| b.is_ascii_digit()),
            DIALOG_STEP,
        )?;
        let modified: u64 = seconds
            .parse()
            .map_err(|_| format!("date -r {path} gave {seconds:?}"))?;
        if modified != built {
            return Err(format!(
                "{path} is dated {modified}, the image was built at {built}"
            ));
        }
        if guest <= built {
            return Err(format!(
                "the guest's date {guest} is not after the build {built}"
            ));
        }
        run.expect("# ", DIALOG_STEP)?;
    }
    Ok(())
}
