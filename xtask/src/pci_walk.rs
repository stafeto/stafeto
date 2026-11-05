// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask pci-walk-vz [--net N]`: the walk of bus 0 on Apple VZ
//! (tests/pci-walk) with N network devices (0 to 2). The runner collects
//! the lines `pci: ...` up to `pci-walk: done`, prints them and checks
//! what the drivers of the machine expect: the console at device 5
//! (1af4:1043), the entropy device at device 6 (1af4:1044), and N network
//! functions (1af4:1041).
//!
//! `cargo xtask pci-walk [--hvf]` is the same walk on QEMU's `virt` machine
//! with the disk (`qemu::store`), checked against `virtio_pci::qemu`: the
//! host bridge at device 0 and the disk, 1af4:1042, at device 1 with the
//! one BAR 4 of 16 KiB and the common configuration at its start.

use super::*;

const DONE: &str = "pci-walk: done";
const CONSOLE_DEVICE: u32 = 5;
const ENTROPY_DEVICE: u32 = 6;

/// The image of the walk: init with the table of the walk, the console's
/// driver and the program.
const PROGRAMS_VZ: [ImageProgram; 3] = [
    ("init", "init", INIT_STACK_SIZE, &["table-pci-walk-vz"]),
    ("virtio-console", "virtio-console", UART_STACK_SIZE, &[]),
    ("pci-walk", "pci-walk", CHILD_STACK_SIZE, &[]),
];

/// The image of the walk on QEMU: init with its table, the PL011's driver
/// and the program.
const PROGRAMS_QEMU: [ImageProgram; 3] = [
    ("init", "init", INIT_STACK_SIZE, &["table-pci-walk-qemu"]),
    ("uart", "uart", UART_STACK_SIZE, &[]),
    ("pci-walk", "pci-walk", CHILD_STACK_SIZE, &[]),
];

/// A function that answered, as the program printed it.
#[derive(Debug, PartialEq, Eq)]
pub struct Function {
    pub device: u32,
    pub function: u32,
    pub vendor: u32,
    pub id: u32,
    pub class: u32,
    /// The interrupt pin: 1 is INTA.
    pub pin: u32,
    /// The lines of the BARs and capabilities that follow, as printed
    /// after `dev D fn F`.
    pub details: Vec<String>,
}

fn hex(text: &str) -> Option<u32> {
    u32::from_str_radix(text.trim_start_matches("0x"), 16).ok()
}

/// The functions in the lines `pci: ...` of the walk.
pub fn parse(lines: &[String]) -> Vec<Function> {
    let mut found: Vec<Function> = Vec::new();
    for line in lines {
        let Some(rest) = line.strip_prefix("pci: dev ") else {
            continue;
        };
        let words: Vec<&str> = rest.split_whitespace().collect();
        let (Some(device), Some("fn"), Some(function)) = (
            words.first().and_then(|w| w.parse::<u32>().ok()),
            words.get(1).copied(),
            words.get(2).and_then(|w| w.parse::<u32>().ok()),
        ) else {
            continue;
        };
        if words.get(3) == Some(&"id") {
            let (Some(id), Some(class)) = (
                words.get(4).and_then(|w| w.split_once(':')),
                words.get(6).and_then(|w| hex(w)),
            ) else {
                continue;
            };
            let (Some(vendor), Some(id)) = (hex(id.0), hex(id.1)) else {
                continue;
            };
            found.push(Function {
                device,
                function,
                vendor,
                id,
                class,
                pin: words.get(10).and_then(|w| w.parse().ok()).unwrap_or(0),
                details: Vec::new(),
            });
        } else if let Some(last) = found
            .iter_mut()
            .rev()
            .find(|f| f.device == device && f.function == function)
        {
            last.details.push(words[3..].join(" "));
        }
    }
    found
}

/// What the walk of a machine with `net` network devices must show.
pub fn check(functions: &[Function], net: usize) -> Result<(), String> {
    let at = |device: u32, vendor: u32, id: u32| {
        functions
            .iter()
            .any(|f| f.device == device && f.function == 0 && f.vendor == vendor && f.id == id)
    };
    if !at(CONSOLE_DEVICE, 0x1af4, 0x1043) {
        return Err("no 1af4:1043 at device 5".into());
    }
    if !at(ENTROPY_DEVICE, 0x1af4, 0x1044) {
        return Err("no 1af4:1044 at device 6".into());
    }
    let nets: Vec<&Function> = functions
        .iter()
        .filter(|f| f.vendor == 0x1af4 && f.id == 0x1041)
        .collect();
    if nets.len() != net {
        return Err(format!(
            "{} functions 1af4:1041, {net} expected",
            nets.len()
        ));
    }
    // The numbers `netd::pci` stands on: the devices, the size and kind of
    // BAR 0, the common configuration at its start.
    let bar0 = format!("bar 0 size {:#x} mem64", netd::pci::BAR_LEN);
    for (i, f) in nets.iter().enumerate() {
        if u64::from(f.device) != netd::pci::DEVICE[i] || f.function != 0 {
            return Err(format!(
                "network function {i} is at device {} function {}, netd::pci has device {}",
                f.device,
                f.function,
                netd::pci::DEVICE[i]
            ));
        }
        for wanted in [bar0.as_str(), "common bar 0 offset 0x0"] {
            if !f.details.iter().any(|d| d == wanted) {
                return Err(format!(
                    "network function {i} (device {}) lacks {wanted:?}: {:?}",
                    f.device, f.details
                ));
            }
        }
    }
    Ok(())
}

/// What the walk of QEMU's `virt` machine with the disk must show, from
/// `virtio_pci::qemu`: the host bridge at device 0, the disk at device 1
/// with INTA, one BAR (BAR 4, 64-bit, of the table's length) and the
/// common configuration at its start; no other function.
pub fn check_qemu(functions: &[Function]) -> Result<(), String> {
    let disk = virtio_pci::qemu::DISK;
    let (vendor, id) = (disk.id & 0xFFFF, disk.id >> 16);
    let device = virtio_pci::qemu::DISK_DEVICE as u32;
    let [bridge, store] = functions else {
        return Err(format!("{} functions, 2 expected", functions.len()));
    };
    if (bridge.device, bridge.function, bridge.vendor, bridge.id) != (0, 0, 0x1b36, 0x0008) {
        return Err(format!(
            "device 0 function 0 is {:04x}:{:04x}, 1b36:0008 expected",
            bridge.vendor, bridge.id
        ));
    }
    if (store.device, store.function) != (device, 0) || (store.vendor, store.id) != (vendor, id) {
        return Err(format!(
            "the disk is {vendor:04x}:{id:04x} at device {device} function 0, found {:04x}:{:04x} at device {} function {}",
            store.vendor, store.id, store.device, store.function
        ));
    }
    if store.class >> 16 != 0x01 || store.pin != 1 {
        return Err(format!(
            "class {:06x} pin {}, storage with INTA expected",
            store.class, store.pin
        ));
    }
    let bar = format!("bar {} size {:#x} mem64", disk.index, disk.len);
    let common = format!("common bar {} offset 0x0", disk.index);
    let bars = store
        .details
        .iter()
        .filter(|d| d.starts_with("bar "))
        .count();
    for wanted in [bar.as_str(), common.as_str()] {
        if !store.details.iter().any(|d| d == wanted) {
            return Err(format!("the disk lacks {wanted:?}: {:?}", store.details));
        }
    }
    if bars != 1 {
        return Err(format!(
            "the disk has {bars} BARs, one expected: {:?}",
            store.details
        ));
    }
    Ok(())
}

/// `cargo xtask pci-walk [--hvf]`: the walk on QEMU with a disk file of
/// 1 MiB; with `--hvf`, on both HVF machines.
pub fn command_qemu(args: &[String]) -> Result<(), String> {
    let machines: &[&qemu::Machine] = match args {
        [] => &[&qemu::VIRT],
        [flag] if flag == "--hvf" => {
            hvf_host()?;
            &[&qemu::HVF_V3, &qemu::HVF_V2]
        }
        _ => return Err("usage: cargo xtask pci-walk [--hvf]".into()),
    };
    let kernel = build(Variant::Normal)?;
    let boot = build_boot_image("boot-pci-walk-qemu.img", &PROGRAMS_QEMU, BOOT_PROFILE)?;
    let store = root().join("target").join("pci-walk-store.img");
    qemu::store_file(&store, 1 << 20, true)?;
    for machine in machines {
        let mut cmd = qemu::command(machine, &kernel.image, Some(&boot));
        cmd.args(qemu::HEADLESS).args(qemu::store(&store, None));
        let mut run = qemu::Run::start(cmd, qemu::Input::Null)?;
        let result = run.expect_seen(DONE, BOOT_TIMEOUT);
        let lines: Vec<String> = run.lines().to_vec();
        run.stop();
        result.map_err(|e| format!("pci-walk on {}: {e}", machine.name))?;
        let functions = parse(&lines);
        check_qemu(&functions).map_err(|e| format!("pci-walk on {}: {e}", machine.name))?;
        println!("pci-walk on {}: ok", machine.name);
    }
    Ok(())
}

pub fn command(args: &[String]) -> Result<(), String> {
    let net = match args {
        [] => 0,
        [flag, n] if flag == "--net" => n
            .parse::<usize>()
            .ok()
            .filter(|n| *n <= 2)
            .ok_or("--net takes 0, 1 or 2")?,
        _ => return Err("usage: cargo xtask pci-walk-vz [--net N]".into()),
    };
    let kernel = build(Variant::Normal)?;
    let boot = build_boot_image("boot-pci-walk-vz.img", &PROGRAMS_VZ, BOOT_PROFILE)?;
    let suffix = if net > 0 {
        Some(vz::claim_suffix()?)
    } else {
        None
    };
    let machine = vz::Machine {
        net,
        mac_suffix: suffix.as_ref().map_or(0, |s| s.value),
        ..vz::Machine::default()
    };
    let mut run = qemu::Run::start(
        vz::command_on(&kernel.image, &boot, machine)?,
        qemu::Input::Pipe,
    )?;
    let result = run.expect_seen(DONE, BOOT_TIMEOUT);
    let lines: Vec<String> = run.lines().to_vec();
    run.stop();
    vz::stop_hint(result).map_err(|e| format!("pci-walk on VZ: {e}"))?;
    for line in lines.iter().filter(|l| l.starts_with("pci: ")) {
        println!("{line}");
    }
    let functions = parse(&lines);
    check(&functions, net)
        .map_err(|e| format!("pci-walk on VZ with {net} network devices: {e}"))?;
    println!("pci-walk on VZ with {net} network devices: ok");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &str) -> Vec<String> {
        text.lines().map(str::to_owned).collect()
    }

    const WALK: &str = "\
pci: dev 0 fn 0 id 106b:1a00 class 060000 header 00 pin 0
pci: dev 1 fn 0 id 1af4:1041 class 020000 header 00 pin 1
pci: dev 1 fn 0 bar 0 size 0x10000 mem64
pci: dev 1 fn 0 cap type 1 bar 0 offset 0x0 length 0x38
pci: dev 1 fn 0 common bar 0 offset 0x0
pci: dev 5 fn 0 id 1af4:1043 class 078000 header 00 pin 1
pci: dev 6 fn 0 id 1af4:1044 class 00ff00 header 00 pin 1
";

    #[test]
    fn the_walk_is_read_function_by_function() {
        let functions = parse(&lines(WALK));
        assert_eq!(functions.len(), 4);
        assert_eq!(functions[1].class, 0x020000);
        assert_eq!(functions[1].details.len(), 3);
        assert_eq!(functions[1].details[0], "bar 0 size 0x10000 mem64");
        check(&functions, 1).unwrap();
    }

    #[test]
    fn a_moved_network_device_or_another_bar_size_fails() {
        let moved = WALK.replace("dev 1 fn 0", "dev 3 fn 0");
        let functions = parse(&lines(&moved));
        assert!(
            check(&functions, 1)
                .unwrap_err()
                .contains("netd::pci has device 1")
        );
        let bigger = WALK.replace("size 0x10000", "size 0x20000");
        assert!(
            check(&parse(&lines(&bigger)), 1)
                .unwrap_err()
                .contains("bar 0 size 0x10000")
        );
        let elsewhere = WALK.replace("common bar 0 offset 0x0", "common bar 0 offset 0x1000");
        assert!(
            check(&parse(&lines(&elsewhere)), 1)
                .unwrap_err()
                .contains("common bar 0")
        );
    }

    #[test]
    fn a_wrong_count_or_a_moved_driver_device_fails() {
        let functions = parse(&lines(WALK));
        assert!(check(&functions, 0).unwrap_err().contains("1 functions"));
        assert!(check(&functions, 2).is_err());
        let moved = WALK.replace("dev 5 fn 0", "dev 4 fn 0");
        assert!(
            check(&parse(&lines(&moved)), 1)
                .unwrap_err()
                .contains("device 5")
        );
    }
    const QEMU_WALK: &str = "\
pci: dev 0 fn 0 id 1b36:0008 class 060000 header 00 pin 0
pci: dev 1 fn 0 id 1af4:1042 class 010000 header 00 pin 1
pci: dev 1 fn 0 bar 4 size 0x4000 mem64
pci: dev 1 fn 0 cap type 5 bar 0 offset 0x0 length 0x0
pci: dev 1 fn 0 cap type 2 bar 4 offset 0x3000 length 0x1000
pci: dev 1 fn 0 cap type 4 bar 4 offset 0x2000 length 0x1000
pci: dev 1 fn 0 cap type 3 bar 4 offset 0x1000 length 0x1000
pci: dev 1 fn 0 cap type 1 bar 4 offset 0x0 length 0x1000
pci: dev 1 fn 0 common bar 4 offset 0x0
";

    #[test]
    fn the_walk_of_qemu_shows_the_disk_the_table_names() {
        let functions = parse(&lines(QEMU_WALK));
        assert_eq!(functions.len(), 2);
        assert_eq!(functions[1].pin, 1);
        check_qemu(&functions).unwrap();
    }

    #[test]
    fn another_id_a_bigger_bar_or_a_moved_structure_fails() {
        let other = QEMU_WALK.replace("1af4:1042", "1af4:1001");
        assert!(
            check_qemu(&parse(&lines(&other)))
                .unwrap_err()
                .contains("1042")
        );
        let bigger = QEMU_WALK.replace("size 0x4000", "size 0x8000");
        assert!(
            check_qemu(&parse(&lines(&bigger)))
                .unwrap_err()
                .contains("bar 4 size 0x4000")
        );
        let moved = QEMU_WALK.replace("common bar 4", "common bar 0");
        assert!(
            check_qemu(&parse(&lines(&moved)))
                .unwrap_err()
                .contains("common bar 4")
        );
        let more =
            format!("{QEMU_WALK}pci: dev 2 fn 0 id 1af4:1041 class 020000 header 00 pin 1\n");
        assert!(
            check_qemu(&parse(&lines(&more)))
                .unwrap_err()
                .contains("3 functions")
        );
        let extra_bar = format!("{QEMU_WALK}pci: dev 1 fn 0 bar 0 size 0x1000 io\n");
        assert!(
            check_qemu(&parse(&lines(&extra_bar)))
                .unwrap_err()
                .contains("2 BARs")
        );
        let moved_dev = QEMU_WALK.replace("dev 1 fn 0", "dev 2 fn 0");
        assert!(
            check_qemu(&parse(&lines(&moved_dev)))
                .unwrap_err()
                .contains("device 1")
        );
    }
}
