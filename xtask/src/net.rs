// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The image of the shell with the network service (`boot-net.img`): the
//! shell's image with the table of init that starts `netd` beside the
//! services of the shell, on QEMU's user-mode networking. `cargo xtask net`
//! runs it with the console on the terminal and two ports of the host
//! forwarded (8080 to 80, 2222 to 22: the first stage has no listener, so
//! they stay shut). The service is built without the methods of the probe.

use super::*;

/// The image of the shell with the network.
pub const IMAGE: &str = "boot-net.img";
/// The stack of the network service. The frame of `main` holds the two
/// queues of the device's crate (about 8 KiB each), the rings' books, the
/// stack's interface and sockets, and the buffers of the start (the key, the
/// file `netd.conf`): about 62 KiB in the release build at 256 places, more at
/// 320 groups of sockets (1 280 places); the image of two devices ran out of
/// 128 KiB inside the second device's queue. 192 KiB leaves the calls under it
/// their room.
pub const NETD_STACK_SIZE: u32 = 192 * 1024;

/// The ports of the host forwarded to the guest: HTTP and SSH.
pub const FORWARDS: [qemu::Forward; 2] = [
    qemu::Forward {
        proto: qemu::Proto::Tcp,
        host: 8080,
        guest: 80,
    },
    qemu::Forward {
        proto: qemu::Proto::Tcp,
        host: 2222,
        guest: 22,
    },
];

/// The programs of the image: those of the shell image with the table
/// that has the network service, the service itself, and the programs of
/// the network packages (curl, openssl).
pub fn programs() -> &'static [ImageProgram] {
    static LIST: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        let mut programs = shell_programs().to_vec();
        programs[0] = ("init", "init", INIT_STACK_SIZE, &["table-net"]);
        programs.push(("netd", "netd", NETD_STACK_SIZE, &[]));
        let net: Vec<packages::Package> = packages::of_image(IMAGE)
            .unwrap_or_else(|e| panic!("{IMAGE}: {e}"))
            .into_iter()
            .filter(|p| p.kind == packages::Kind::Net)
            .collect();
        programs.extend(package_programs(&net));
        programs
    })
}

/// The programs of the image on Apple VZ with one network device or, with
/// `two`, two: those of the image of QEMU with the Virtio console's driver
/// for the PL011's, and init's table of VZ.
pub fn vz_programs(two: bool) -> &'static [ImageProgram] {
    static ONE: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    static TWO: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    let list = if two { &TWO } else { &ONE };
    list.get_or_init(|| {
        let mut programs = programs().to_vec();
        for program in &mut programs {
            match program.0 {
                "init" => {
                    program.3 = if two {
                        &["table-net-vz2"]
                    } else {
                        &["table-net-vz"]
                    }
                }
                "uart" => {
                    *program = ("virtio-console", "virtio-console", UART_STACK_SIZE, &[]);
                }
                _ => {}
            }
        }
        programs
    })
}

/// Where `cargo xtask net` runs the image: QEMU on a machine, or Apple VZ
/// with one or two network devices.
enum Target {
    Qemu(&'static qemu::Machine),
    Vz(usize),
}

fn target_of(args: &[String]) -> Result<Target, String> {
    let usage = "usage: cargo xtask net [--machine hvf|tcg|vz|NAME] [--net N]";
    let mut machine = None;
    let mut net = None;
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        let value = rest.next().ok_or(usage)?;
        match flag.as_str() {
            "--machine" => machine = Some(value.as_str()),
            "--net" => {
                net = Some(
                    value
                        .parse::<usize>()
                        .ok()
                        .filter(|n| (1..=2).contains(n))
                        .ok_or("--net takes 1 or 2")?,
                )
            }
            _ => return Err(usage.to_owned()),
        }
    }
    match (machine, net) {
        (Some("vz"), net) => Ok(Target::Vz(net.unwrap_or(1))),
        (_, Some(_)) => Err("--net belongs to --machine vz".to_owned()),
        (None | Some("tcg"), None) => Ok(Target::Qemu(&qemu::VIRT)),
        (Some("hvf"), None) => Ok(Target::Qemu(&qemu::HVF_V3)),
        (Some(other), None) => Ok(Target::Qemu(qemu::machine(Some(&other.to_owned()))?)),
    }
}

/// `cargo xtask net [--machine hvf|vz] [--net N]`: QEMU with the console on
/// the terminal (Ctrl-A X quits), the network device on the user network,
/// and the shell; or, with `--machine vz`, Apple VZ with N network devices
/// on the NAT (the Mac reaches the guest at the address of its lease). The
/// service prints `net: lease ...` once DHCP answers.
pub fn run(args: &[String]) -> Result<(), String> {
    let machine = match target_of(args)? {
        Target::Qemu(machine) => machine,
        Target::Vz(devices) => return run_vz(devices),
    };
    if machine.is_hvf() {
        hvf_host().map_err(|why| {
            format!(
                "--machine hvf needs macOS on Apple Silicon with the Hypervisor framework: {why}"
            )
        })?;
    }
    busybox_build()?;
    nano_build()?;
    net_build()?;
    relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(IMAGE, programs(), BOOT_PROFILE)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args([
        "-display",
        "none",
        "-chardev",
        "stdio,id=console,mux=on,signal=off",
        "-serial",
        "chardev:console",
        "-mon",
        "chardev=console,mode=readline",
    ]);
    cmd.args(qemu::net(&FORWARDS));
    println!(
        "net on {}: the console is ash; the service prints `net: lease` when DHCP answers; Ctrl-A X quits QEMU",
        machine.name
    );
    let status = cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .status()
        .map_err(|e| format!("{cmd:?}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("QEMU exited with {status}"))
    }
}

/// The image on VZ whose service counts its steps (`cargo xtask net-vz
/// --steps`), with one device or two.
pub fn vz_steps_programs(two: bool) -> &'static [ImageProgram] {
    static ONE: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    static TWO: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    let list = if two { &TWO } else { &ONE };
    list.get_or_init(|| {
        let mut programs = vz_programs(two).to_vec();
        for program in &mut programs {
            if program.0 == "netd" {
                program.3 = &["steps"];
            }
        }
        programs
    })
}

/// The names of the images on VZ: one device, two.
pub const VZ_IMAGE: &str = "boot-net-vz.img";
pub const VZ2_IMAGE: &str = "boot-net-vz2.img";
pub const VZ2_STATIC_IMAGE: &str = "boot-net-vz2-static.img";
pub const VZ_STEPS_IMAGE: &str = "boot-net-vz-steps.img";
pub const VZ2_STEPS_IMAGE: &str = "boot-net-vz2-steps.img";

/// The shell with the network on Apple VZ on the terminal.
fn run_vz(devices: usize) -> Result<(), String> {
    busybox_build()?;
    nano_build()?;
    net_build()?;
    relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(
        if devices == 2 { VZ2_IMAGE } else { VZ_IMAGE },
        vz_programs(devices == 2),
        BOOT_PROFILE,
    )?;
    let machine = vz::Machine {
        net: devices,
        ..vz::Machine::default()
    };
    let mut cmd = vz::command_on(&kernel.image, &image, machine)?;
    println!(
        "net on VZ with {devices} network devices: the console is ash; the service prints `net: lease` when DHCP answers; reach the guest at that address from this Mac (bridge100)"
    );
    let status = cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .status()
        .map_err(|e| format!("vz-run: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("vz-run exited with {status}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipping service has no PING and no CRASH: the image of the
    /// shell holds `netd` built without the feature `probe`, like the games
    /// image holds the screen service built without `crash`.
    #[test]
    fn the_shell_image_has_the_network_service_built_without_the_probe() {
        let netd = programs().iter().find(|p| p.0 == "netd").unwrap();
        assert!(!netd.3.contains(&"probe"));
        assert!(!netd.3.contains(&"steps"));
        assert_eq!(netd.2, NETD_STACK_SIZE);
        assert_eq!(programs()[0].3, &["table-net"]);
        assert!(programs().iter().any(|p| p.0 == "ash-launcher"));
    }

    #[test]
    fn the_run_forwards_http_and_ssh() {
        let args = qemu::net(&FORWARDS).join(" ");
        assert!(args.contains("hostfwd=tcp:127.0.0.1:8080-:80"));
        assert!(args.contains("hostfwd=tcp:127.0.0.1:2222-:22"));
    }

    #[test]
    fn the_target_comes_from_the_flags() {
        let args = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let name = |list: &[&str]| match target_of(&args(list)) {
            Ok(Target::Qemu(machine)) => machine.name.to_owned(),
            Ok(Target::Vz(n)) => format!("vz {n}"),
            Err(why) => why,
        };
        assert_eq!(name(&[]), qemu::VIRT.name);
        assert_eq!(name(&["--machine", "hvf"]), qemu::HVF_V3.name);
        assert_eq!(name(&["--machine", "vz"]), "vz 1");
        assert_eq!(name(&["--machine", "vz", "--net", "2"]), "vz 2");
        assert!(target_of(&args(&["--net", "2"])).is_err());
        assert!(target_of(&args(&["--machine", "vz", "--net", "3"])).is_err());
        assert!(target_of(&args(&["x"])).is_err());
    }

    /// The images on VZ hold the Virtio console's driver in place of the
    /// PL011's and the table of VZ, and the shipping service.
    #[test]
    fn the_vz_images_have_the_consoles_driver_and_the_table_of_vz() {
        let one = vz_programs(false);
        assert_eq!(one[0].3, &["table-net-vz"]);
        assert!(one.iter().any(|p| p.0 == "virtio-console"));
        assert!(!one.iter().any(|p| p.0 == "uart"));
        let netd = one.iter().find(|p| p.0 == "netd").unwrap();
        assert!(!netd.3.contains(&"probe"));
    }
}
