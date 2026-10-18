// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The dialog of the CPUs in the shell image: what a program sees of the
//! machine's CPUs and how the process service spreads work over them. On N
//! CPUs `nproc` and the CPU lines of `/proc/stat` and `/proc/cpuinfo` say N,
//! the mask of `taskset -p` names N CPUs, N loops in the background land on N
//! different CPUs (the `processor` field of `/proc/<pid>/stat`) and keep each
//! CPU busy in its line of `/proc/stat`, a command under `taskset -c` runs on
//! the CPU the mask names, and htop shows a meter for each CPU under that
//! load. On one CPU everything is as before: `nproc` says 1 and every process
//! is on CPU 0.

use super::*;
use std::cell::RefCell;

/// The hundredths of a second a CPU must have been busy (user and system)
/// after the loops ran a few seconds.
const BUSY_MIN: u64 = 150;

/// The numbers of a line, split at the colons after its label.
fn numbers(line: &str, label: &str) -> Vec<u64> {
    line.strip_prefix(label)
        .map(|rest| rest.split(':').filter_map(|n| n.parse().ok()).collect())
        .unwrap_or_default()
}

/// The text of a screen without its escape sequences (CSI and the charset
/// switches ncurses writes).
fn strip_escapes(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('[') => {
                while let Some(&n) = chars.peek() {
                    chars.next();
                    if ('@'..='~').contains(&n) {
                        break;
                    }
                }
            }
            Some('(' | ')') => {
                chars.next();
            }
            _ => {}
        }
    }
    out
}

/// Sends `command` and waits for the line `want` the shell answers with.
fn answers(run: &mut qemu::Run, command: &str, what: &str, want: &str) -> Result<(), String> {
    run.send(command)?;
    run.expect_line(what, |l| l == want, DIALOG_STEP)?;
    run.expect("# ", DIALOG_STEP)
}

pub fn cpus_dialog(cpus: usize) -> Result<(), String> {
    qemu::on_cpus(cpus, || dialog(cpus))
}

fn dialog(cpus: usize) -> Result<(), String> {
    relibc()?;
    busybox_build()?;
    nano_build()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-ash-dialog.img", shell_programs(), BOOT_PROFILE)?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let talked = (|| {
        let n = cpus.to_string();
        run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
        run.expect("# ", DIALOG_STEP)?;
        // The count of CPUs, as BusyBox counts the mask of sched_getaffinity
        // and as the files of /proc list them.
        answers(&mut run, "nproc", "nproc", &n)?;
        answers(
            &mut run,
            "grep -c '^cpu[0-9]' /proc/stat",
            "the CPU lines of /proc/stat",
            &n,
        )?;
        answers(
            &mut run,
            "grep -c '^processor' /proc/cpuinfo",
            "the records of /proc/cpuinfo",
            &n,
        )?;
        // The listing of /sys/devices/system/cpu, which `nproc --all` and
        // htop count.
        run.send("ls /sys/devices/system/cpu")?;
        run.expect("# ", DIALOG_STEP)?;
        answers(&mut run, "nproc --all", "nproc --all", &n)?;
        let mask = format!("affinity mask: {:x}", (1u32 << cpus) - 1);
        run.send("taskset -p $$")?;
        run.expect_line(
            "the mask of taskset",
            |l| l.starts_with("pid ") && l.ends_with(&mask),
            DIALOG_STEP,
        )?;
        run.expect("# ", DIALOG_STEP)?;
        // One loop for each CPU, in the background; they are made one after
        // the other, so that each placement sees the loops before it.
        run.send("for i in 1 2 3 4 5 6 7 8; do [ $i -le $(nproc) ] && { while :; do :; done; } & [ $i -le $(nproc) ] && echo loop:$!; done")?;
        let mut pids = Vec::new();
        for _ in 0..cpus {
            let line = run.expect_line("a loop", |l| l.starts_with("loop:"), DIALOG_STEP)?;
            pids.push(
                numbers(&line, "loop:")
                    .first()
                    .copied()
                    .ok_or("a loop gave no PID")?,
            );
        }
        run.expect("# ", DIALOG_STEP)?;
        // Some seconds of load, then where each loop runs and what each CPU
        // spent.
        run.send("sleep 4")?;
        run.expect("# ", Duration::from_secs(20))?;
        let mut placed = Vec::new();
        for pid in &pids {
            run.send(&format!(
                "echo cpu:{pid}:$(cut -d' ' -f39 /proc/{pid}/stat)"
            ))?;
            let line = run.expect_line(
                "the CPU of a loop",
                |l| l.starts_with(&format!("cpu:{pid}:")),
                DIALOG_STEP,
            )?;
            let cpu = *numbers(&line, "cpu:")
                .get(1)
                .ok_or(format!("no CPU in {line:?}"))?;
            placed.push(cpu);
            run.expect("# ", DIALOG_STEP)?;
        }
        let mut distinct = placed.clone();
        distinct.sort_unstable();
        distinct.dedup();
        println!("the loops {pids:?} run on the CPUs {placed:?}");
        if distinct.len() != cpus || distinct.iter().any(|&c| c >= cpus as u64) {
            return Err(format!(
                "{cpus} loops are on the CPUs {placed:?}, not on {cpus} different CPUs"
            ));
        }
        run.send(
            "grep '^cpu[0-9]' /proc/stat | while read c u n s i r; do echo stat:$c:$u:$s:$i; done",
        )?;
        let busy = RefCell::new(Vec::new());
        for _ in 0..cpus {
            let line = run.expect_line(
                "a CPU line of /proc/stat",
                |l| l.starts_with("stat:cpu"),
                DIALOG_STEP,
            )?;
            let parts: Vec<&str> = line.split(':').collect();
            let field = |at: usize| parts.get(at).and_then(|n| n.parse::<u64>().ok());
            let (Some(user), Some(system), Some(idle)) = (field(2), field(3), field(4)) else {
                return Err(format!("{line:?} is no CPU line"));
            };
            println!("{}: user {user}, system {system}, idle {idle}", parts[1]);
            busy.borrow_mut().push(user + system);
        }
        run.expect("# ", DIALOG_STEP)?;
        if let Some(lazy) = busy.borrow().iter().position(|&b| b < BUSY_MIN) {
            return Err(format!(
                "CPU {lazy} was busy {} hundredths of a second under a loop of its own: {:?}",
                busy.borrow()[lazy],
                busy.borrow()
            ));
        }
        // htop under the load, with a meter for each CPU in its header (its
        // default is one meter for the average).
        run.send("mkdir -p /root/.config/htop && { echo header_layout=two_50_50; echo column_meters_0=AllCPUs Memory Swap; echo column_meter_modes_0=1 1 1; echo column_meters_1=Tasks LoadAverage Uptime; echo column_meter_modes_1=2 2 2; } > /root/.config/htop/htoprc")?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("htop")?;
        run.expect("Tasks:", Duration::from_secs(20))?;
        run.expect("PID", DIALOG_STEP)?;
        let screen = strip_escapes(&run.text().join("\n"));
        run.type_raw(b"q")?;
        run.expect("# ", DIALOG_STEP)?;
        if cpus > 1 {
            for cpu in 0..cpus {
                if !screen.contains(&format!("{cpu}[")) {
                    return Err(format!("htop shows no meter for CPU {cpu}: {screen:?}"));
                }
            }
        } else if !screen.contains("CPU[") {
            return Err(format!("htop shows no meter of the CPU: {screen:?}"));
        }
        if screen.contains(&format!("{cpus}[")) && cpus > 1 {
            return Err(format!("htop shows a meter for CPU {cpus}: {screen:?}"));
        }
        let all: Vec<String> = pids.iter().map(u64::to_string).collect();
        run.send(&format!("kill {}", all.join(" ")))?;
        run.expect("# ", DIALOG_STEP)?;
        // A command under a mask runs on the CPU the mask names.
        let target = cpus - 1;
        run.send(&format!("taskset -c {target} sleep 30 &"))?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("sleep 1; echo taskset:$!")?;
        let line = run.expect_line(
            "the PID of taskset",
            |l| l.starts_with("taskset:"),
            Duration::from_secs(20),
        )?;
        let pid = numbers(&line, "taskset:")
            .first()
            .copied()
            .ok_or("no PID of taskset")?;
        run.expect("# ", DIALOG_STEP)?;
        answers(
            &mut run,
            &format!("echo under:$(cut -d' ' -f39 /proc/{pid}/stat)"),
            "the CPU of a command under taskset",
            &format!("under:{target}"),
        )?;
        run.send(&format!("kill {pid}"))?;
        run.expect("# ", DIALOG_STEP)?;
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
    }) {
        return Err("the CPUs dialog faulted".into());
    }
    println!("CPUs dialog on {cpus} CPUs passed");
    Ok(())
}
