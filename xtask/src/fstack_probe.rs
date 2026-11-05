// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of F-Stack on its own loopback (`cargo xtask fstack-probe`,
//! stage P6b-1 of subproject 6): the TCP/IP stack of FreeBSD 15 of
//! F-Stack's libfstack.a (tools/build-fstack.py) in a process of the
//! shell's image, with no network device and no network service. xtask
//! runs `fstack-probe` (tests/fstack-probe/main.c) from the shell: the
//! stack starts from `/etc/fstack.ini`, two fills of its random source
//! differ, the stack's arc4random gives full 32-bit values, a listener becomes ready in kqueue, 16 MiB go through a pair of
//! sockets on 127.0.0.1, one write of 1 MiB on a non-blocking socket takes
//! part of it, two connects get two ports, 1 000 connections open and
//! close, a connect to a closed port is refused, and a SYN the stack
//! ignored is sent again after its timer. The program prints a line for
//! each check and xtask compares them with its own list.
//!
//! `cargo xtask fstack-probe write-blocking` prints what one write of 1 MiB
//! does on a blocking socket nobody reads.

use std::time::{Duration, Instant};

use crate::{
    BOOT_PROFILE, BOOT_TIMEOUT, DIALOG_STEP, INIT_STACK_SIZE, ImageProgram, SERVICES_STARTED,
    Variant, build, build_boot_image, busybox_build, nano_build, qemu, relibc, shell_programs,
    symbolize,
};

/// The image: the shell's, with the table of larger commands and the probe.
pub const IMAGE: &str = "boot-fstack-probe.img";

/// The note of the image with F-Stack's licence and the acknowledgements
/// its four-clause files ask for, and the note of its source.
pub const LICENSE: &str = "FSTACK-LICENSE";
pub const SOURCE: &str = "FSTACK-SOURCE";

/// F-Stack's terms for an image that carries the stack: its licence with
/// the acknowledgements (tools/build-fstack.py wrote both), and where the
/// exact source is.
pub fn terms() -> Result<(Vec<u8>, String), String> {
    let work = crate::target_dir().join("f-stack");
    let read = |name: &str| {
        let path = work.join(name);
        std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))
    };
    let mut licence = crate::notices::licence_text("f-stack")?;
    licence.extend_from_slice(b"\n");
    licence.extend(read("ACKNOWLEDGEMENTS")?);
    // The copyright lines and terms of the files the stack compiled
    // (tools/build-fstack.py): the second condition of every BSD licence.
    licence.extend_from_slice(b"\n");
    licence.extend(read("NOTICES")?);
    let url = crate::packages::value("f-stack", "url")?;
    let sha256 = crate::packages::value("f-stack", "sha256")?;
    let source = format!(
        "The image holds F-Stack (the TCP/IP stack of FreeBSD 15 in user space) in\n\
         fstack-probe, fast-layer and nginx-fast,\n\
         under BSD-2-Clause, BSD-3-Clause, BSD-4-Clause, RSA-MD, Beerware, MIT-CMU,\n\
         ISC and MIT (FSTACK-LICENSE).\n\n\
         Its source: {url}\n\
         (SHA-256 of the tar stream {sha256}), built by tools/build-fstack.py with\n\
         ports/f-stack of https://github.com/stafeto/stafeto at commit {}.\n",
        crate::rtbench2::commit()
    );
    Ok((licence, source))
}

/// The checks of `fstack-probe`, in the order the program runs them.
pub const CHECKS: [&str; 10] = [
    "init",
    "random",
    "stack-random",
    "kevent",
    "stream-16m",
    "write-partial",
    "ephemeral",
    "connections-1000",
    "refused",
    "syn-timer",
];

/// The line after the checks.
const ALL: &str = "all ok";

/// How long the checks may take in all on TCG.
const CHECKS_WITHIN: Duration = Duration::from_secs(120);

/// The programs of the image: the shell's with init's table of the probe,
/// and the probe, a dynamic program on libc.so.
pub fn programs() -> &'static [ImageProgram] {
    static LIST: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        let mut programs = shell_programs().to_vec();
        programs[0] = ("init", "init", INIT_STACK_SIZE, &["table-fstack-probe"]);
        programs.push(("fstack-probe", "fstack-probe", 0, &["dynamic"]));
        programs
    })
}

/// What a line says after `fstack-probe: `; the first line may follow the
/// prompt on the same line.
fn text_of(line: &str) -> Option<&str> {
    line.split_once("fstack-probe: ").map(|(_, text)| text)
}

/// Follows the lines of the program until `all ok`: every check in its
/// order, a failure named.
fn checks(run: &mut qemu::Run, within: Duration) -> Result<Vec<String>, String> {
    let mut seen = 0;
    let mut notes = Vec::new();
    let end = Instant::now() + within;
    loop {
        let left = end.saturating_duration_since(Instant::now());
        let line = run.expect_line("a line of fstack-probe", |l| text_of(l).is_some(), left)?;
        let text = text_of(&line).unwrap_or_default();
        if text.starts_with("check failed") {
            return Err(format!("fstack-probe: {text}"));
        }
        if text == ALL {
            if seen != CHECKS.len() {
                return Err(format!(
                    "fstack-probe ended after {seen} checks, xtask knows {}",
                    CHECKS.len()
                ));
            }
            return Ok(notes);
        }
        let Some(name) = text.strip_suffix(" ok") else {
            notes.push(text.to_owned());
            continue;
        };
        if CHECKS.get(seen) != Some(&name) {
            return Err(format!(
                "check {} is {name}, wanted {:?}",
                seen + 1,
                CHECKS.get(seen)
            ));
        }
        seen += 1;
    }
}

/// `cargo xtask fstack-probe [write-blocking] [tcg|hvf]`.
pub fn command(args: &[String]) -> Result<(), String> {
    let (blocking, rest) = match args.first().map(String::as_str) {
        Some("write-blocking") => (true, &args[1..]),
        _ => (false, args),
    };
    let machine = match rest {
        [] => &qemu::VIRT,
        [name] => match name.as_str() {
            "hvf" => &qemu::HVF_V3,
            "tcg" => &qemu::VIRT,
            other => qemu::machine(Some(&other.to_owned()))?,
        },
        _ => return Err("usage: cargo xtask fstack-probe [write-blocking] [tcg|hvf]".to_owned()),
    };
    probe(machine, blocking)
}

pub fn probe(machine: &'static qemu::Machine, blocking: bool) -> Result<(), String> {
    if machine.is_hvf() {
        crate::hvf_host().map_err(|why| format!("hvf needs macOS on Apple Silicon: {why}"))?;
    }
    busybox_build()?;
    nano_build()?;
    relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(IMAGE, programs(), BOOT_PROFILE)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let started = Instant::now();
    let talked = (|| {
        run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
        run.expect("# ", DIALOG_STEP)?;
        if blocking {
            run.send("fstack-probe write-blocking")?;
            let line = run.expect_line(
                "the write on a blocking socket",
                |l| text_of(l).is_some_and(|t| t.starts_with("one write of 1 MiB on a blocking")),
                CHECKS_WITHIN,
            )?;
            println!("{}", text_of(&line).unwrap_or_default());
            run.expect("# ", CHECKS_WITHIN)?;
            return Ok::<Vec<String>, String>(Vec::new());
        }
        run.send("fstack-probe")?;
        let notes = checks(&mut run, CHECKS_WITHIN)?;
        run.expect("# ", DIALOG_STEP)?;
        Ok(notes)
    })();
    let output = run.stop();
    symbolize::backtrace(&output.lines, &kernel.elf);
    let notes = talked?;
    if output.lines.iter().any(|line| {
        line.contains("process fault:")
            || line.contains("KERNEL PANIC")
            || line.contains("out of memory")
    }) {
        return Err("the image of fstack-probe faulted".into());
    }
    if !blocking {
        println!(
            "fstack-probe passed in {:.0} s on {}: {} checks; {}",
            started.elapsed().as_secs_f64(),
            machine.name,
            CHECKS.len(),
            notes.join("; ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The checks xtask expects are those the program prints, in its order.
    #[test]
    fn the_checks_are_those_of_the_program() {
        let source =
            std::fs::read_to_string(crate::root().join("tests/fstack-probe/main.c")).unwrap();
        let printed: Vec<&str> = source
            .split("ok(\"")
            .skip(1)
            .filter_map(|rest| rest.split('"').next())
            .filter(|name| *name != "all")
            .collect();
        let mut sorted_printed = printed.clone();
        sorted_printed.sort_unstable();
        let mut known: Vec<&str> = CHECKS.to_vec();
        known.sort_unstable();
        assert_eq!(sorted_printed, known);
    }

    #[test]
    fn the_lines_of_the_program_are_read() {
        assert_eq!(text_of("fstack-probe: init ok"), Some("init ok"));
        assert_eq!(text_of("/ # fstack-probe: init ok"), Some("init ok"));
        assert_eq!(text_of("posix-net: limits ok"), None);
    }
}
