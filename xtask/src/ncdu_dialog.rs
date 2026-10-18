// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The dialog of ncdu in the shell image (`/bin/ncdu`, started from ash): its
//! screen drawn with ncurses and the terminfo entry of the image, the sizes of
//! the directories of `/`, the files of several hard links counted once, the
//! option `-x` that stays on the file system of the start, and the key `q`
//! that ends it.

use super::*;

/// The version `tools/build-ncdu.py` builds.
fn version() -> Result<String, String> {
    packages::value("ncdu", "version")
}

/// ncdu's licence text and the note of its copyright and of the exact source
/// of the program in the image.
pub fn ncdu_terms() -> Result<(Vec<u8>, String), String> {
    let version = version()?;
    let sha256 = packages::value("ncdu", "sha256")?;
    let url = packages::value("ncdu", "url")?;
    let path = target_dir().join(format!("ncdu/ncdu-{version}/COPYING"));
    let licence = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let relibc = script_value("tools/build-relibc.py", "COMMIT")?;
    let source = format!(
        "ncdu holds ncdu {version}, Copyright (c) Yorhel.\n\
         Licensed under the MIT licence (NCDU-LICENSE).\n\n\
         Its source: {url}\n\
         (SHA-256 {sha256}), built unchanged by tools/build-ncdu.py\n\
         of https://github.com/stafeto/stafeto at commit {}; linked with relibc\n\
         https://github.com/stafeto/relibc at commit {relibc}\n\
         (THIRD-PARTY-NOTICES) and with ncurses (NCURSES-LICENSE, NANO-SOURCE\n\
         names its source).\n",
        rtbench2::commit()
    );
    Ok((licence, source))
}

/// Fails unless the boot image at `path` carries ncdu's terms.
fn image_has_ncdu_terms(path: &Path) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let image =
        bootimg::BootImage::parse(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    let (licence, _) = ncdu_terms()?;
    let archive = format!("ncdu-{}.tar.gz", version()?);
    let carries = |name: &str, check: &dyn Fn(&[u8]) -> bool| {
        image
            .files()
            .any(|file| file.name == name && check(file.data))
    };
    if carries(NCDU_LICENSE, &|data| data == licence.as_slice())
        && carries(NCDU_SOURCE, &|data| {
            data.windows(archive.len()).any(|w| w == archive.as_bytes())
                && data.windows(3).any(|w| w == b"MIT")
        })
    {
        Ok(())
    } else {
        Err(format!("{} carries no ncdu terms", path.display()))
    }
}

/// `text` without the escape sequences of the terminal (CSI sequences and
/// the selections of a character set), as ncurses wrote them.
fn plain(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('[') => {
                for f in chars.by_ref() {
                    if ('@'..='~').contains(&f) {
                        break;
                    }
                }
            }
            Some('(') | Some(')') => {
                chars.next();
            }
            _ => {}
        }
    }
    out
}

/// `n` bytes as ncdu writes them with `--si`: one decimal and the prefix.
fn si(n: u64) -> String {
    let mut value = n as f64;
    for unit in ["B", "kB", "MB", "GB"] {
        if value < 1000.0 || unit == "GB" {
            return format!("{value:.1} {unit}");
        }
        value /= 1000.0;
    }
    unreachable!()
}

/// The number after `label` in the screen text `line`.
fn number_after_label(line: &str, label: &str) -> Option<u64> {
    let rest = &line[line.find(label)? + label.len()..];
    let digits: String = rest
        .trim_start()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// Starts `command` (ncdu with its arguments), waits for the screen of the
/// finished scan, which ends with the footer's item count, and gives that
/// screen's text and the count. The key `q` leaves ncdu and ash prompts
/// again with the status 0.
fn browse(run: &mut qemu::Run, command: &str, shown: &[&str]) -> Result<(String, u64), String> {
    run.send(command)?;
    run.expect("Items: ", DIALOG_STEP)?;
    run.type_raw(b"q")?;
    // ncdu leaves the screen of its own (the terminfo entry's `rmcup`) and
    // the prompt follows.
    run.expect("\x1b[?1049l", DIALOG_STEP)?;
    run.expect("# ", DIALOG_STEP)?;
    run.send("echo ncdu-status:$?")?;
    run.expect_line("the status", |l| l == "ncdu-status:0", DIALOG_STEP)?;
    run.expect("# ", DIALOG_STEP)?;
    // The screen is part of the line the echo of the next command ended.
    let screen = run
        .lines()
        .iter()
        .rev()
        .find(|l| l.contains("Total disk usage:"))
        .cloned()
        .ok_or_else(|| format!("{command}: no footer on the screen"))?;
    // One space between words: ncdu pads its columns.
    let screen = plain(&screen)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for name in shown {
        if !screen.contains(name) {
            return Err(format!("{command}: the screen lacks {name}: {screen:?}"));
        }
    }
    let items = number_after_label(&screen, "Items:")
        .ok_or_else(|| format!("{command}: no item count: {screen:?}"))?;
    Ok((screen, items))
}

pub fn ncdu_dialog() -> Result<(), String> {
    relibc()?;
    busybox_build()?;
    nano_build()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-ash-dialog.img", shell_programs(), BOOT_PROFILE)?;
    image_has_ncdu_terms(&image)?;
    let busybox = std::fs::metadata(image_elf(
        &target_dir(),
        "boot-ash-dialog.img",
        "busybox-probe",
    ))
    .map_err(|e| format!("busybox-probe: {e}"))?
    .len();
    let version = version()?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let talked = (|| {
        run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
        run.expect("# ", DIALOG_STEP)?;
        // The directories of `/` with their sizes: the title of ncdu with
        // its version, a row of each top directory, and the footer's totals.
        let title = format!("ncdu {version} ~ Use the arrow keys");
        browse(
            &mut run,
            "ncdu /",
            &[
                &title,
                "/bin",
                "/libexec",
                "/tmp",
                "/etc",
                "/proc",
                "MiB [",
                "Apparent size:",
            ],
        )?;
        // BusyBox under three names: two hard links and a symbolic link.
        // ncdu counts the file once and does not follow the symbolic link,
        // so the apparent size of the directory is the file's size and the
        // length of the link's target (`/bin/busybox`).
        run.send(
            "mkdir /tmp/h && ln /bin/busybox /tmp/h/b1 && ln /bin/busybox /tmp/h/b2 \
             && ln -s /bin/busybox /tmp/h/s && echo tree-made",
        )?;
        run.expect_line("the tree", |l| l == "tree-made", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        let once = si(busybox + "/bin/busybox".len() as u64);
        browse(
            &mut run,
            "ncdu --si --apparent-size /tmp/h",
            &["b1", "b2", &format!("Apparent size: {once} Items: 3")],
        )?;
        // The files of /proc are on a file system of their own (their device
        // number is not the one of `/proc` itself): with `-x` ncdu marks each
        // row `>` and counts no size; without it no row has the mark.
        let (other, _) = browse(&mut run, "ncdu -x /proc", &["uptime", "Items: 8"])?;
        let marked = other.matches("> 0.0 B [").count();
        if marked < 5 {
            return Err(format!(
                "ncdu -x /proc marks {marked} rows as another file system: {other:?}"
            ));
        }
        let (same, _) = browse(&mut run, "ncdu /proc", &["uptime", "Items: 8"])?;
        if same.contains("> 0.0 B [") {
            return Err(format!(
                "ncdu /proc marks rows as another file system: {same:?}"
            ));
        }
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
            || line.contains("Error obtaining")
    }) {
        return Err("ncdu dialog faulted".into());
    }
    let elf = image_elf(&target_dir(), "boot-ash-dialog.img", "ncdu");
    let size = std::fs::metadata(&elf)
        .map_err(|e| format!("{}: {e}", elf.display()))?
        .len();
    println!("ncdu {version} interactive guest dialog passed; ELF {size} bytes");
    Ok(())
}
