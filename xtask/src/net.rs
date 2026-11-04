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
/// file `netd.conf`): about 62 KiB in the release build. 128 KiB leaves the
/// calls under it their room.
pub const NETD_STACK_SIZE: u32 = 128 * 1024;

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
/// that has the network service, and the service itself.
pub fn programs() -> &'static [ImageProgram] {
    static LIST: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        let mut programs = shell_programs().to_vec();
        programs[0] = ("init", "init", INIT_STACK_SIZE, &["table-net"]);
        programs.push(("netd", "netd", NETD_STACK_SIZE, &[]));
        programs
    })
}

fn machine_of(args: &[String]) -> Result<&'static qemu::Machine, String> {
    match args {
        [] => Ok(&qemu::VIRT),
        [flag, name] if flag == "--machine" => match name.as_str() {
            "hvf" => Ok(&qemu::HVF_V3),
            "tcg" => Ok(&qemu::VIRT),
            other => qemu::machine(Some(&other.to_owned())),
        },
        _ => Err("usage: cargo xtask net [--machine hvf|tcg|NAME]".to_owned()),
    }
}

/// `cargo xtask net [--machine hvf]`: QEMU with the console on the
/// terminal (Ctrl-A X quits), the network device on the user network, and
/// the shell. The service prints `net: lease ...` once DHCP answers.
pub fn run(args: &[String]) -> Result<(), String> {
    let machine = machine_of(args)?;
    if machine.is_hvf() {
        hvf_host().map_err(|why| {
            format!(
                "--machine hvf needs macOS on Apple Silicon with the Hypervisor framework: {why}"
            )
        })?;
    }
    busybox_build()?;
    nano_build()?;
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
    fn the_machine_comes_from_the_flag() {
        assert_eq!(machine_of(&[]).map(|m| m.name), Ok(qemu::VIRT.name));
        let hvf = ["--machine".to_owned(), "hvf".to_owned()];
        assert_eq!(machine_of(&hvf).map(|m| m.name), Ok(qemu::HVF_V3.name));
        assert!(machine_of(&["x".to_owned()]).is_err());
    }
}
