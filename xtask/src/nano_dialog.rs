// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The dialog of GNU nano in the shell image (`/bin/nano`, started from ash):
//! the screen it draws with ncurses and the terminfo entry of the image, the
//! text typed into a file and saved, the arrow keys, and the file read back
//! with `cat`.

use super::*;

/// The version `tools/build-nano.py` builds, as nano prints it in its title.
fn version() -> Result<String, String> {
    packages::value("nano", "version")
}

/// nano's and ncurses' licence texts and the note of their copyright and of
/// the exact sources of the programs in the image.
pub fn nano_terms() -> Result<(Vec<u8>, Vec<u8>, String), String> {
    let version = version()?;
    let sha256 = packages::value("nano", "sha256")?;
    let curses = packages::value("ncurses", "version")?;
    let curses_sha256 = packages::value("ncurses", "sha256")?;
    let read = |path: PathBuf| std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()));
    let licence = read(target_dir().join(format!("nano/nano-{version}/COPYING")))?;
    let ncurses = read(target_dir().join(format!("ncurses/ncurses-{curses}/COPYING")))?;
    let relibc = script_value("tools/build-relibc.py", "COMMIT")?;
    let source = format!(
        "nano holds GNU nano {version}, Copyright (C) the Free Software Foundation, Inc.\n\
         Licensed under GPLv3 or later (NANO-LICENSE).\n\n\
         Its source: https://ftp.gnu.org/gnu/nano/nano-{version}.tar.xz\n\
         (SHA-256 {sha256}), built unchanged by tools/build-nano.py\n\
         of https://github.com/stafeto/stafeto at commit {}; linked with relibc\n\
         https://github.com/stafeto/relibc at commit {relibc}\n\
         (THIRD-PARTY-NOTICES) and with ncurses {curses}, Copyright (C) the\n\
         ncurses authors (MIT, NCURSES-LICENSE), built unchanged by\n\
         tools/build-ncurses.py from\n\
         https://ftp.gnu.org/gnu/ncurses/ncurses-{curses}.tar.gz\n\
         (SHA-256 {curses_sha256}). The terminfo entries in /usr/share/terminfo\n\
         (xterm-256color, xterm, vt100, linux) are compiled from the terminfo.src\n\
         of that archive.\n",
        rtbench2::commit()
    );
    Ok((licence, ncurses, source))
}

/// Fails unless the boot image at `path` carries the terms of nano and
/// ncurses.
fn image_has_nano_terms(path: &Path) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let image =
        bootimg::BootImage::parse(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    let (licence, ncurses, _) = nano_terms()?;
    let version = version()?;
    let carries = |name: &str, check: &dyn Fn(&[u8]) -> bool| {
        image
            .files()
            .any(|file| file.name == name && check(file.data))
    };
    let archive = format!("nano-{version}.tar.xz");
    if carries(NANO_LICENSE, &|data| data == licence.as_slice())
        && carries(NCURSES_LICENSE, &|data| data == ncurses.as_slice())
        && carries(NANO_SOURCE, &|data| {
            data.windows(archive.len()).any(|w| w == archive.as_bytes())
                && data.windows(5).any(|w| w == b"GPLv3")
        })
    {
        Ok(())
    } else {
        Err(format!("{} carries no nano terms", path.display()))
    }
}

/// Keys as an xterm sends them in the application mode that nano's `keypad`
/// asks for (`smkx` of xterm-256color).
const LEFT: &[u8] = b"\x1bOD";
const UP: &[u8] = b"\x1bOA";
const DOWN: &[u8] = b"\x1bOB";
const CTRL_O: &[u8] = b"\x0f";
const CTRL_X: &[u8] = b"\x18";

/// Starts `nano file` and waits for its screen: the title and the shortcut
/// bar.
fn open(run: &mut qemu::Run, file: &str, version: &str, reads: &str) -> Result<(), String> {
    run.send(&format!("nano {file}"))?;
    // The message of the status bar is drawn before the title bar.
    run.expect(reads, DIALOG_STEP)?;
    run.expect(&format!("GNU nano {version}"), DIALOG_STEP)?;
    Ok(())
}

/// Ctrl-O, the file name nano proposes, Enter; nano says what it wrote.
fn save(run: &mut qemu::Run, file: &str, wrote: &str) -> Result<(), String> {
    run.type_raw(CTRL_O)?;
    run.expect("Write to File: ", DIALOG_STEP)?;
    run.expect(file, DIALOG_STEP)?;
    run.type_raw(b"\r")?;
    run.expect(wrote, DIALOG_STEP)
}

/// Ctrl-X, and the prompt of ash.
fn exit(run: &mut qemu::Run) -> Result<(), String> {
    run.type_raw(CTRL_X)?;
    run.expect("# ", DIALOG_STEP)
}

/// `cat file` shows exactly `lines`.
fn cat(run: &mut qemu::Run, file: &str, lines: &[&str]) -> Result<(), String> {
    run.send(&format!("cat {file}"))?;
    for expected in lines {
        run.expect_line(expected, |line| line == *expected, DIALOG_STEP)?;
    }
    run.expect("# ", DIALOG_STEP)
}

pub fn nano_dialog() -> Result<(), String> {
    relibc()?;
    busybox_build()?;
    nano_build()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-ash-dialog.img", shell_programs(), BOOT_PROFILE)?;
    image_has_nano_terms(&image)?;
    let version = version()?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let talked = (|| {
        run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
        run.expect("# ", DIALOG_STEP)?;
        // The terminal of the shell's programs.
        run.send("echo term=$TERM")?;
        run.expect_line("the terminal", |l| l == "term=xterm-256color", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        // A new file: nano draws its screen from the terminfo entry, the
        // text goes in, Ctrl-O Enter writes it, Ctrl-X leaves.
        open(&mut run, "/tmp/f", &version, "New File")?;
        run.type_raw(b"hello from nano")?;
        save(&mut run, "/tmp/f", "Wrote 1 line")?;
        exit(&mut run)?;
        cat(&mut run, "/tmp/f", &["hello from nano"])?;
        // The arrow keys: Left puts the cursor back inside the line, and
        // the text typed there lands in the middle of it.
        open(&mut run, "/tmp/g", &version, "New File")?;
        run.type_raw(b"ad")?;
        run.type_raw(LEFT)?;
        run.type_raw(b"bc")?;
        run.type_raw(b"\r")?;
        run.type_raw(b"two")?;
        // Enter splits "abcd" after "c", so "d" begins the second line and
        // "two" goes before it. Up keeps the column (3, the end of "abc");
        // Down goes to the end of "twod" and Left steps back from it.
        run.type_raw(UP)?;
        run.type_raw(b"!")?;
        run.type_raw(DOWN)?;
        run.type_raw(LEFT)?;
        run.type_raw(b"?")?;
        save(&mut run, "/tmp/g", "Wrote 2 lines")?;
        exit(&mut run)?;
        cat(&mut run, "/tmp/g", &["abc!", "two?d"])?;
        // A file that exists is read, edited in the middle and written back.
        open(&mut run, "/tmp/g", &version, "Read 2 lines")?;
        run.type_raw(DOWN)?;
        run.type_raw(b"+")?;
        save(&mut run, "/tmp/g", "Wrote 2 lines")?;
        exit(&mut run)?;
        cat(&mut run, "/tmp/g", &["abc!", "+two?d"])?;
        // Leaving a file nobody changed asks nothing.
        open(&mut run, "/tmp/g", &version, "Read 2 lines")?;
        exit(&mut run)?;
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
        return Err("nano dialog faulted".into());
    }
    let elf = image_elf(&target_dir(), "boot-ash-dialog.img", "nano");
    let size = std::fs::metadata(&elf)
        .map_err(|e| format!("{}: {e}", elf.display()))?
        .len();
    println!("GNU nano {version} interactive guest dialog passed; ELF {size} bytes");
    Ok(())
}
