// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask init-wait`: a record that waits for a service's READY (pk3-design R14, R17) on
//! QEMU's `virt`. The table is the store probe's with a client at its end, the program of the
//! store probe whose file `/test/mode` says `wait` (it prints the time it started and ends), that
//! waits 3 s for the package service (`INIT_WAIT_TABLE`). Three runs on an empty disk:
//!
//! 1. The service as it is: the client starts after the line `pkgd: ready`, within the 3 s, and
//!    init says nothing of a wait that failed.
//! 2. The service built with `no-ready` (it never says READY): init prints
//!    `init: pkgd not ready after 3 s` and the client starts after the 3 s.
//! 3. The service built with `exit-before-ready` (it ends where it would say READY, with exit
//!    code 7): init prints `init: pkgd ended before ready` and the client starts at once.
//!
//! The 30 s of the base table are held by the host tests of `init`.

use super::*;

/// The three runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Run {
    Ready,
    NoReady,
    ExitBeforeReady,
}

const CLIENT: &str = "store-probe: client started at ";
const ENDED: &str = "init: init-wait ended: ";
const WAIT_NS: u64 = 3_000_000_000;
/// How long after the deadline the client may start on a loaded host, in ns.
const SLACK_NS: u64 = 10_000_000_000;

impl Run {
    const ALL: [Run; 3] = [Run::Ready, Run::NoReady, Run::ExitBeforeReady];

    fn name(self) -> &'static str {
        match self {
            Run::Ready => "ready",
            Run::NoReady => "no-ready",
            Run::ExitBeforeReady => "exit-before-ready",
        }
    }

    fn features(self) -> &'static [&'static str] {
        match self {
            Run::Ready => &[],
            Run::NoReady => &["no-ready"],
            Run::ExitBeforeReady => &["exit-before-ready"],
        }
    }
}

/// The programs of the image of a run: the store probe's, with the wait table in init and the
/// features of the run in the package service.
fn programs(run: Run) -> &'static [ImageProgram] {
    let mut list = store_probe::PROGRAMS.to_vec();
    list[0].3 = &["table-init-wait"];
    let pkgd = list
        .iter_mut()
        .find(|p| p.0 == "pkgd")
        .expect("the store probe's image has the package service");
    pkgd.3 = run.features();
    Box::leak(list.into_boxed_slice())
}

/// The position of the first line that contains `text`.
fn at(lines: &[String], text: &str) -> Option<usize> {
    lines.iter().position(|l| l.contains(text))
}

/// What a run shows, from the lines of the console: the time the client started, in ns, or why
/// the run is wrong.
pub fn verdict(run: Run, lines: &[String]) -> Result<u64, String> {
    let client = at(lines, CLIENT).ok_or("the client never started")?;
    let ns: u64 = lines[client]
        .split_once(CLIENT)
        .and_then(|(_, rest)| rest.strip_suffix(" ns"))
        .and_then(|n| n.trim().parse().ok())
        .ok_or_else(|| format!("the line of the client: {:?}", lines[client]))?;
    let late = at(lines, "init: pkgd not ready after");
    let ended = at(lines, "init: pkgd ended before ready");
    match run {
        Run::Ready => {
            let ready = at(lines, "pkgd: ready,").ok_or("pkgd never said it is ready")?;
            if ready > client {
                return Err("the client started before pkgd was ready".into());
            }
            if late.is_some() || ended.is_some() {
                return Err("init said the wait failed".into());
            }
            if ns >= WAIT_NS {
                return Err(format!("the client started at {ns} ns, after the deadline"));
            }
        }
        Run::NoReady => {
            let late = late.ok_or("no line of the deadline")?;
            if lines[late] != "init: pkgd not ready after 3 s" {
                return Err(format!("the line of the deadline: {:?}", lines[late]));
            }
            if late > client {
                return Err("the client started before the deadline's line".into());
            }
            if !(WAIT_NS..WAIT_NS + SLACK_NS).contains(&ns) {
                return Err(format!(
                    "the client started at {ns} ns: not after the 3 s deadline"
                ));
            }
            if ended.is_some() {
                return Err("init said pkgd ended".into());
            }
        }
        Run::ExitBeforeReady => {
            let ended = ended.ok_or("no line of the end before READY")?;
            if lines[ended] != "init: pkgd ended before ready" {
                return Err(format!("the line of the end: {:?}", lines[ended]));
            }
            at(lines, "init: pkgd ended: exit code 7, not restarted")
                .ok_or("init never saw the end of pkgd")?;
            if ended > client {
                return Err("the client started before the line of the end".into());
            }
            if late.is_some() {
                return Err("init said the deadline passed".into());
            }
            if ns >= WAIT_NS {
                return Err(format!("the client started at {ns} ns, not at once"));
            }
        }
    }
    Ok(ns)
}

fn run(which: Run) -> Result<u64, String> {
    if std::env::var_os("STAFETO_RELIBC_SYSROOT").is_none() {
        relibc()?;
    }
    let name: &'static str =
        Box::leak(format!("boot-init-wait-{}.img", which.name()).into_boxed_str());
    let image = store_probe::image_with(
        name,
        programs(which),
        vec![("mode".to_owned(), b"wait\n".to_vec())],
        None,
    )?;
    let disk = store_probe::Disk::new(which.name());
    store_probe::write_disk(&disk, None)?;
    let kernel = build(Variant::Normal)?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS).args(qemu::store(&disk.0, None));
    let output = run_until(cmd, BOOT_TIMEOUT * 4, Some(ENDED), &kernel.elf)?;
    qemu::expect_stopped_on(&output, "init: init-wait ended: exit code 0, not restarted")?;
    verdict(which, &output.lines).map_err(|e| format!("init-wait {}: {e}", which.name()))
}

/// `cargo xtask init-wait`.
pub fn command(_: &[String]) -> Result<(), String> {
    let mut said = Vec::new();
    for which in Run::ALL {
        let ns = run(which)?;
        said.push(format!("{} {:.2} s", which.name(), ns as f64 / 1e9));
    }
    println!(
        "init-wait: the client of a wait started after READY, after the deadline of 3 s, and at once when pkgd ended: ok ({})",
        said.join(", ")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &[&str]) -> Vec<String> {
        text.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_normal_run_starts_the_client_after_the_ready_line() {
        let ok = lines(&[
            "pkgd: ready, 0 packages from the disk, 0 from the image, 131065 blocks free",
            "store-probe: client started at 900000000 ns",
        ]);
        assert_eq!(verdict(Run::Ready, &ok), Ok(900_000_000));
        let early = lines(&[
            "store-probe: client started at 100 ns",
            "pkgd: ready, 0 packages from the disk, 0 from the image, 1 blocks free",
        ]);
        assert!(verdict(Run::Ready, &early).is_err());
        let late = lines(&[
            "pkgd: ready, 0 packages from the disk, 0 from the image, 1 blocks free",
            "init: pkgd not ready after 3 s",
            "store-probe: client started at 3100000000 ns",
        ]);
        assert!(verdict(Run::Ready, &late).is_err());
        assert!(verdict(Run::Ready, &lines(&["pkgd: ready, 0"])).is_err());
    }

    #[test]
    fn the_deadline_run_starts_the_client_after_three_seconds() {
        let ok = lines(&[
            "init: pkgd not ready after 3 s",
            "store-probe: client started at 3050000000 ns",
        ]);
        assert_eq!(verdict(Run::NoReady, &ok), Ok(3_050_000_000));
        let early = lines(&[
            "init: pkgd not ready after 3 s",
            "store-probe: client started at 1000000000 ns",
        ]);
        assert!(verdict(Run::NoReady, &early).is_err());
        let wrong = lines(&[
            "init: pkgd not ready after 30 s",
            "store-probe: client started at 3050000000 ns",
        ]);
        assert!(verdict(Run::NoReady, &wrong).is_err());
        assert!(
            verdict(
                Run::NoReady,
                &lines(&["store-probe: client started at 5 ns"])
            )
            .is_err()
        );
    }

    #[test]
    fn the_end_run_starts_the_client_at_once() {
        let ok = lines(&[
            "init: pkgd ended: exit code 7, not restarted",
            "init: pkgd ended before ready",
            "store-probe: client started at 700000000 ns",
        ]);
        assert_eq!(verdict(Run::ExitBeforeReady, &ok), Ok(700_000_000));
        let slow = lines(&[
            "init: pkgd ended: exit code 7, not restarted",
            "init: pkgd ended before ready",
            "store-probe: client started at 3100000000 ns",
        ]);
        assert!(verdict(Run::ExitBeforeReady, &slow).is_err());
        let silent = lines(&["store-probe: client started at 5 ns"]);
        assert!(verdict(Run::ExitBeforeReady, &silent).is_err());
    }
}
