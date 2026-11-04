// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask pci-walk-vz [--net N]`: the walk of bus 0 on Apple VZ
//! (tests/pci-walk) with N network devices (0 to 2). The runner collects
//! the lines `pci: ...` up to `pci-walk: done`, prints them and checks
//! what the drivers of the machine expect: the console at device 5
//! (1af4:1043), the entropy device at device 6 (1af4:1044), and N network
//! functions (1af4:1041).

use super::*;

const DONE: &str = "pci-walk: done";
const CONSOLE_DEVICE: u32 = 5;
const ENTROPY_DEVICE: u32 = 6;

/// The image of the walk: init with the table of the walk, the console's
/// driver and the program.
const PROGRAMS: [ImageProgram; 3] = [
    ("init", "init", INIT_STACK_SIZE, &["table-pci-walk-vz"]),
    ("virtio-console", "virtio-console", UART_STACK_SIZE, &[]),
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
    let nets = functions
        .iter()
        .filter(|f| f.vendor == 0x1af4 && f.id == 0x1041)
        .count();
    if nets != net {
        return Err(format!("{nets} functions 1af4:1041, {net} expected"));
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
    let boot = build_boot_image("boot-pci-walk-vz.img", &PROGRAMS, BOOT_PROFILE)?;
    let machine = vz::Machine {
        net,
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
    check(&functions, net).map_err(|e| format!("pci-walk on VZ with {net} network devices: {e}"))?;
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
pci: dev 1 fn 0 bar 0 size 0x4000 mem64
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
        assert_eq!(functions[1].details[0], "bar 0 size 0x4000 mem64");
        check(&functions, 1).unwrap();
    }

    #[test]
    fn a_wrong_count_or_a_moved_driver_device_fails() {
        let functions = parse(&lines(WALK));
        assert!(check(&functions, 0).unwrap_err().contains("1 functions"));
        assert!(check(&functions, 2).is_err());
        let moved = WALK.replace("dev 5 fn 0", "dev 4 fn 0");
        assert!(check(&parse(&lines(&moved)), 1).unwrap_err().contains("device 5"));
    }
}
