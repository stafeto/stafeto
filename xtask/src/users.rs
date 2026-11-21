// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the ordinary account and of the account tools (`cargo xtask users`, stafeto#565),
//! on the image of the SSH probe (`boot-ssh-probe.img`: the shell with the network service and
//! Dropbear) on QEMU's user network. xtask drives the root shell on the serial port, as `net-ssh`
//! does, and the checks run there; each prints one line `users: <name> ok`.
//!
//! 1. Privilege: `/bin/su`, `/bin/passwd` and `/bin/doas` are set-user-ID root (mode 4755);
//!    `/bin/busybox` is 0755 and no file of /bin that is a link to it is more; there is no
//!    /etc/busybox.conf; /etc/doas.conf is 0400 root with the one rule.
//! 2. `doas`: `user` (a member of `wheel`) runs `id` as root, and as `nobody`; `nobody`
//!    (not a member) is refused; no password is asked for.
//! 3. `su` and `passwd`, the set-user-ID BusyBox: `user` runs `id` and an ordinary program
//!    after them with its own identifiers; `su root` by `user` without a password is refused;
//!    `passwd` of another account is refused to `user`.

use std::time::Duration;

use crate::qemu::{Forward, Proto};
use crate::{
    BOOT_PROFILE, BOOT_TIMEOUT, DIALOG_STEP, SERVICES_STARTED, Variant, build, build_boot_image,
    busybox_build, nano_build, net_ssh, net_tls, qemu, relibc, symbolize,
};

/// The image of the run.
const IMAGE: &str = net_ssh::IMAGE;

/// The whole run.
const RUN_WITHIN: Duration = Duration::from_secs(900);

/// The lines `command` printed in the root shell.
fn guest(run: &mut qemu::Run, command: &str, marker: &str) -> Result<String, String> {
    Ok(net_tls::capture(run, command, marker, DIALOG_STEP)?.join("\n"))
}

/// Runs `command` and requires every text of `present` in what it printed and none of `absent`.
fn check(
    run: &mut qemu::Run,
    name: &str,
    command: &str,
    present: &[&str],
    absent: &[&str],
) -> Result<(), String> {
    let marker = name.replace(' ', "-");
    let said = guest(run, command, &marker)?;
    for text in present {
        if !said.contains(text) {
            return Err(format!("{name}: wanted {text:?} in {said:?}"));
        }
    }
    for text in absent {
        if said.contains(text) {
            return Err(format!("{name}: found {text:?} in {said:?}"));
        }
    }
    println!("users: {name} ok");
    Ok(())
}

/// Step 1: the modes of the files that carry privilege.
fn privilege(run: &mut qemu::Run) -> Result<(), String> {
    let said = guest(
        run,
        "ls -ln /bin/su /bin/passwd /bin/doas /bin/busybox /etc/doas.conf /etc/shadow",
        "modes",
    )?;
    // The mode, then the owner and the group (both 0), and the path last.
    for (path, mode) in [
        ("/bin/su", "-rwsr-xr-x"),
        ("/bin/passwd", "-rwsr-xr-x"),
        ("/bin/doas", "-rwsr-xr-x"),
        ("/bin/busybox", "-rwxr-xr-x"),
        ("/etc/doas.conf", "-r--------"),
        ("/etc/shadow", "-rw-------"),
    ] {
        let line = said
            .lines()
            .find(|l| l.trim_end().ends_with(path))
            .ok_or_else(|| format!("modes: no line for {path} in {said:?}"))?;
        let words: Vec<&str> = line.split_whitespace().collect();
        if words.first() != Some(&mode) || words.get(2) != Some(&"0") || words.get(3) != Some(&"0")
        {
            return Err(format!("modes: {path} is {line:?}, wanted {mode} of 0 0"));
        }
    }
    println!("users: modes ok");
    check(
        run,
        "no table of applets",
        "ls /etc/busybox.conf 2>&1; cat /etc/doas.conf",
        &["No such file", "permit nopass :wheel"],
        &["keepenv", "persist"],
    )?;
    // Every link of /bin to BusyBox is a link: its mode is that of a link (the bit belongs to
    // the program it names, which is not BusyBox's file).
    check(
        run,
        "busybox has no bit",
        "for f in /bin/busybox /bin/ash /bin/cat; do [ -u $f ] && echo \"suid $f\"; done; echo done",
        &["done"],
        &["suid"],
    )
}

/// Step 2: `doas`.
fn doas(run: &mut qemu::Run) -> Result<(), String> {
    check(
        run,
        "doas as root",
        "su user -c 'PATH=/bin; export PATH; id; doas id; doas -u nobody id; doas -n true; echo rc=$?'",
        &[
            "uid=1000(user)",
            "wheel",
            "uid=0(root)",
            "uid=65534(nobody)",
            "rc=0",
        ],
        &["Authentication required"],
    )?;
    check(
        run,
        "doas refuses",
        "su -s /bin/ash nobody -c 'PATH=/bin; export PATH; doas id; echo rc=$?'",
        &["Operation not permitted", "rc=1"],
        &["uid=0"],
    )?;
    check(
        run,
        "doas rules",
        "su user -c 'PATH=/bin; export PATH; doas -C /etc/doas.conf id 2>&1; echo rc=$?'",
        &[],
        &["uid=0"],
    )
}

/// Step 3: `su` and `passwd`.
fn suid_busybox(run: &mut qemu::Run) -> Result<(), String> {
    check(
        run,
        "su keeps identity",
        "su user -c '/bin/id -u; /bin/id -un'",
        &["1000", "user"],
        &["must be suid"],
    )?;
    check(
        run,
        "su root needs a password",
        "su user -c 'su root -c id < /dev/null 2>&1; echo rc=$?'",
        &["rc="],
        &["uid=0", "rc=0"],
    )?;
    check(
        run,
        "passwd of another",
        "su user -c 'passwd nobody < /dev/null 2>&1; echo rc=$?'",
        &["rc="],
        &["rc=0"],
    )
}

pub fn command(args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err("usage: cargo xtask users".to_owned());
    }
    probe(&qemu::VIRT)
}

pub fn probe(machine: &'static qemu::Machine) -> Result<(), String> {
    busybox_build()?;
    nano_build()?;
    crate::net_build()?;
    relibc()?;
    let kernel = build(Variant::Normal)?;
    let dir = crate::target_dir().join("users");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let (_, line) = net_ssh::make_key(&dir, "good")?;
    net_ssh::set_key(line)?;
    let image = build_boot_image(IMAGE, net_ssh::programs(), BOOT_PROFILE)?;
    let port = crate::net_curl::free_tcp_port()?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::net_on(
        machine,
        &[Forward {
            proto: Proto::Tcp,
            host: port,
            guest: 22,
        }],
    ));
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let started = std::time::Instant::now();
    let talked = (|| {
        run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
        run.expect_line("the lease", |l| l.contains("net: lease "), BOOT_TIMEOUT)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("S=ok")?;
        run.expect("# ", DIALOG_STEP)?;
        privilege(&mut run)?;
        doas(&mut run)?;
        suid_busybox(&mut run)?;
        if started.elapsed() > RUN_WITHIN {
            return Err("the run took too long".to_owned());
        }
        Ok(())
    })();
    let output = run.stop();
    symbolize::backtrace(&output.lines, &kernel.elf);
    talked?;
    if output.lines.iter().any(|line| {
        line.contains("process fault:")
            || line.contains("KERNEL PANIC")
            || line.contains("out of memory")
    }) {
        return Err("the image faulted".into());
    }
    println!(
        "users passed in {:.0} s on {}",
        started.elapsed().as_secs_f64(),
        machine.name
    );
    Ok(())
}
