// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask vi-dialog`: BusyBox `vi` of the shell image (`/bin/vi`, started from ash) edits a
//! new file on the data volume. The image is the shell image with the disk service of the volume
//! and the data file service (`boot-vi-dialog.img`, init's table `table-busybox-dialog-data`); a
//! blank disk of the run is formatted by the first boot. The dialog types a few lines, saves with
//! `:wq`, reads the file back with `cat`, edits it again and reads it back, and a second boot of
//! the same disk reads it a third time and finds the volume mounted (a format would be logged).
//!
//! `vi` writes a file in place (`open` with `O_WRONLY | O_CREAT`, `write`, `ftruncate`, `close`),
//! so it needs of the volume what the write checks of `data-posix` already cover.

use super::*;
use std::time::Duration;

/// The image of the dialog.
pub const IMAGE: &str = "boot-vi-dialog.img";

/// The size of the disk of the run.
const DISK_BYTES: u64 = 64 << 20;

/// The file the dialog edits.
const FILE: &str = "/data/v.txt";

/// The programs of the image: those of the shell image with init's table that has the data
/// volume, the disk service and the data file service.
pub fn programs() -> &'static [ImageProgram] {
    static LIST: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        let mut programs = shell_programs().to_vec();
        programs[0] = (
            "init",
            "init",
            INIT_STACK_SIZE,
            &["table-busybox-dialog-data"],
        );
        programs.push(("virtio-blk", "virtio-blk", blk_probe::BLK_STACK_SIZE, &[]));
        programs.push(("datafsd", "datafsd", 32 * 1024, &[]));
        programs
    })
}

const ESC: &[u8] = b"\x1b";

/// Starts `vi file` and waits for its status line, `reads` being the position in it (`1/3`:
/// the first of three lines).
fn open(run: &mut qemu::Run, reads: &str) -> Result<(), String> {
    run.send(&format!("vi {FILE}"))?;
    run.expect(reads, DIALOG_STEP)
}

/// Escape, `:wq` and Enter; the prompt of ash comes back.
fn save_and_quit(run: &mut qemu::Run) -> Result<(), String> {
    run.type_raw(ESC)?;
    // vi waits a moment after an escape for the rest of a key sequence.
    std::thread::sleep(Duration::from_millis(300));
    run.type_raw(b":wq\r")?;
    run.expect("# ", DIALOG_STEP)
}

/// `cat file` shows exactly `lines`.
fn cat(run: &mut qemu::Run, lines: &[&str]) -> Result<(), String> {
    run.send(&format!("cat {FILE}"))?;
    for expected in lines {
        run.expect_line(expected, |line| line == *expected, DIALOG_STEP)?;
    }
    run.expect("# ", DIALOG_STEP)
}

/// One boot: the services started, the prompt, then `dialog`; the lines of the boot come back.
fn boot(
    kernel: &Artifacts,
    image: &Path,
    disk: &Path,
    dialog: impl FnOnce(&mut qemu::Run) -> Result<(), String>,
) -> Result<Vec<String>, String> {
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(image));
    cmd.args(qemu::HEADLESS).args(qemu::store(disk, None));
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let talked = (|| {
        run.expect(SERVICES_STARTED, BOOT_TIMEOUT * 4)?;
        run.expect("# ", BOOT_TIMEOUT * 4)?;
        dialog(&mut run)
    })();
    let output = run.stop();
    symbolize::backtrace(&output.lines, &kernel.elf);
    talked?;
    if output.lines.iter().any(|line| {
        line.contains("process fault:")
            || line.contains("KERNEL PANIC")
            || line.contains("out of memory")
            || line.contains("I/O error")
    }) {
        return Err("vi dialog faulted".into());
    }
    Ok(output.lines)
}

pub fn vi_dialog() -> Result<(), String> {
    relibc()?;
    busybox_build()?;
    nano_build()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(IMAGE, programs(), BOOT_PROFILE)?;
    let disk = std::env::temp_dir().join(format!("stafeto-vi-dialog-{}.img", std::process::id()));
    let result: Result<(), String> = (|| {
        qemu::store_file(&disk, DISK_BYTES, true)?;
        // The first boot: the blank volume is formatted, vi makes the file and edits it.
        boot(&kernel, &image, &disk, |run| {
            run.send("ls -d /data")?;
            run.expect_line("the mount point", |l| l == "/data", DIALOG_STEP)?;
            run.expect("# ", DIALOG_STEP)?;
            open(run, " 1/1 ")?;
            run.type_raw(b"i")?;
            run.type_raw(b"first line\rsecond line\rthird line")?;
            save_and_quit(run)?;
            cat(run, &["first line", "second line", "third line"])?;
            // The file that exists is read, a line is added at its end and it is written back.
            open(run, " 1/3 ")?;
            run.type_raw(b"G")?;
            run.type_raw(b"o")?;
            run.type_raw(b"fourth line")?;
            save_and_quit(run)?;
            cat(
                run,
                &["first line", "second line", "third line", "fourth line"],
            )
        })?;
        // The second boot of the same disk: the volume is mounted and the file is there.
        let lines = boot(&kernel, &image, &disk, |run| {
            cat(
                run,
                &["first line", "second line", "third line", "fourth line"],
            )
        })?;
        if lines.iter().any(|l| l.contains("data volume formatted")) {
            return Err("the second boot formatted the volume again".into());
        }
        Ok(())
    })();
    let _ = std::fs::remove_file(&disk);
    result?;
    println!("vi-dialog: saved and read back ok");
    Ok(())
}
