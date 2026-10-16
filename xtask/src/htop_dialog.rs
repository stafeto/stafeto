// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The dialog of htop in the shell image (`/bin/htop`, started from ash): its
//! screen drawn with ncurses and the terminfo entry of the image, the meters
//! of CPU and memory and the list of processes it reads from /proc, and the
//! key `q` that ends it.

use super::*;

/// The version `tools/build-htop.py` builds.
fn version() -> Result<String, String> {
    script_value("tools/build-htop.py", "VERSION")
}

/// htop's licence text and the note of its copyright and of the exact source
/// of the program in the image.
pub fn htop_terms() -> Result<(Vec<u8>, String), String> {
    let version = version()?;
    let sha256 = script_value("tools/build-htop.py", "SHA256")?;
    let path = target_dir().join(format!("htop/htop-{version}/COPYING"));
    let licence = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let relibc = script_value("tools/build-relibc.py", "COMMIT")?;
    let source = format!(
        "htop holds htop {version}, Copyright (C) the htop dev team and Hisham Muhammad.\n\
         Licensed under GPLv2 or later (HTOP-LICENSE).\n\n\
         Its source: https://github.com/htop-dev/htop/releases/download/{version}/htop-{version}.tar.xz\n\
         (SHA-256 {sha256}), built unchanged by tools/build-htop.py\n\
         of https://github.com/stafeto/stafeto at commit {}; linked with relibc\n\
         https://github.com/stafeto/relibc at commit {relibc}\n\
         (THIRD-PARTY-NOTICES) and with ncurses (NCURSES-LICENSE, NANO-SOURCE\n\
         names its source).\n",
        rtbench2::commit()
    );
    Ok((licence, source))
}

/// Fails unless the boot image at `path` carries htop's terms.
fn image_has_htop_terms(path: &Path) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let image =
        bootimg::BootImage::parse(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    let (licence, _) = htop_terms()?;
    let version = version()?;
    let archive = format!("htop-{version}.tar.xz");
    let carries = |name: &str, check: &dyn Fn(&[u8]) -> bool| {
        image
            .files()
            .any(|file| file.name == name && check(file.data))
    };
    if carries(HTOP_LICENSE, &|data| data == licence.as_slice())
        && carries(HTOP_SOURCE, &|data| {
            data.windows(archive.len()).any(|w| w == archive.as_bytes())
                && data.windows(5).any(|w| w == b"GPLv2")
        })
    {
        Ok(())
    } else {
        Err(format!("{} carries no htop terms", path.display()))
    }
}

pub fn htop_dialog() -> Result<(), String> {
    relibc()?;
    busybox_build()?;
    nano_build()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(
        "boot-ash-dialog.img",
        &ASH_INTERACTIVE_PROGRAMS,
        BOOT_PROFILE,
    )?;
    image_has_htop_terms(&image)?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let talked = (|| {
        run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
        run.expect("# ", DIALOG_STEP)?;
        // htop samples at once only when the wall clock reads more than
        // 1.5 s (its delay; before that its first screen reads a table of
        // colours past its end). The clock of a guest starts at the epoch,
        // so the shell waits first, as a user of a phone has long done.
        run.send("sleep 2")?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("htop")?;
        // The header: the meters of CPU and memory, the counts of tasks and
        // the load; the list: the process of htop itself and the shell.
        run.expect("CPU", DIALOG_STEP)?;
        run.expect("Tasks:", DIALOG_STEP)?;
        // Memory used and total, as /proc/meminfo gives them (a few MB of the
        // 31 the image's pool holds).
        run.expect("Mem", DIALOG_STEP)?;
        run.expect("M/", DIALOG_STEP)?;
        run.expect("PID", DIALOG_STEP)?;
        run.expect("htop", DIALOG_STEP)?;
        run.expect("ash", DIALOG_STEP)?;
        // q ends htop and ash prompts again.
        run.type_raw(b"q")?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("echo htop-status:$?")?;
        run.expect_line("the status", |l| l == "htop-status:0", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        // Ctrl-D on an empty line ends ash.
        run.type_raw(b"\x04")?;
        run.expect(
            "init: busybox-probe ended: exit code 0, not restarted",
            DIALOG_STEP,
        )
    })();
    let output = run.stop();
    symbolize::backtrace(&output.lines, &kernel.elf);
    talked?;
    if output.lines.iter().any(|line| {
        line.contains("process fault:")
            || line.contains("KERNEL PANIC")
            || line.contains("out of memory")
            || line.contains("I/O error")
            || line.contains("Error opening terminal")
    }) {
        return Err("htop dialog faulted".into());
    }
    let elf = image_elf(&target_dir(), "boot-ash-dialog.img", "htop");
    let size = std::fs::metadata(&elf)
        .map_err(|e| format!("{}: {e}", elf.display()))?
        .len();
    let version = version()?;
    println!("htop {version} interactive guest dialog passed; ELF {size} bytes");
    Ok(())
}
