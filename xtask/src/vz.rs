// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Run an arm64 Image on Apple's Virtualization.framework.

use std::path::Path;
use std::process::Command;

use crate::{Variant, build, root, run_cmd, target_dir};

pub fn run() -> Result<(), String> {
    if !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        return Err("Virtualization.framework requires an Apple silicon Mac".into());
    }
    let root = root();
    let binary = target_dir().join("vz-run");
    run_cmd(
        Command::new("swiftc")
            .arg(root.join("tools/vz-run.swift"))
            .args(["-o"])
            .arg(&binary),
    )?;
    run_cmd(
        Command::new("codesign")
            .args(["--force", "--sign", "-", "--entitlements"])
            .arg(root.join("tools/vz-entitlements.plist"))
            .arg(&binary),
    )?;
    let artifacts = build(Variant::Vz)?;
    let status = Command::new(&binary)
        .arg(Path::new(&artifacts.image))
        .arg(Path::new(&artifacts.boot_image))
        .status()
        .map_err(|e| format!("{}: {e}", binary.display()))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{} exited with {status}", binary.display()))
    }
}
