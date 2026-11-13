// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The device tree for stafeto from a `Platform` and the classified memory
//! map (stafeto-design tasks/2026-11-12-aws-efi-loader.md, section 3). It is written for the
//! kernel's `kcore::bootinfo::parse` and for nothing else: loading Linux with
//! it is not a goal.

use crate::efimap::Classified;
use crate::error::Error;
use crate::platform::{Platform, Uart, UartKind};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use kcore::bootinfo::Region;
use kcore::fdt::Builder;

/// The phandle of the ITS node, which the `msi-map` entries name.
pub const ITS_PHANDLE: u32 = 1;

/// A window of a PCI host as the firmware set it up: `kind` is the space
/// code of the `ranges` cell (1 I/O, 2 memory 32-bit, 3 memory 64-bit),
/// `prefetchable` sets bit 30.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciWindow {
    pub kind: u8,
    pub prefetchable: bool,
    pub pci_base: u64,
    pub cpu_base: u64,
    pub size: u64,
}

pub struct Input<'a> {
    pub platform: &'a Platform,
    pub memory: &'a Classified,
    pub initrd: Region,
    /// MPIDR_EL1 of the CPU the loader runs on (affinity fields): it goes
    /// first in `/cpus`.
    pub boot_mpidr: u64,
    pub pci_windows: &'a [PciWindow],
}

fn hi(v: u64) -> u32 {
    (v >> 32) as u32
}

fn lo(v: u64) -> u32 {
    v as u32
}

/// A property of 64-bit values, each as two cells.
fn wide(b: Builder, name: &str, vals: &[u64]) -> Builder {
    let cells: Vec<u32> = vals.iter().flat_map(|&v| [hi(v), lo(v)]).collect();
    b.cells(name, &cells)
}

fn strz(b: Builder, name: &str, value: &str) -> Builder {
    let mut v = Vec::from(value.as_bytes());
    v.push(0);
    b.prop(name, &v)
}

/// The Linux `interrupts` flags of a GTDT timer: level high 4, level low 8,
/// edge rising 1, edge falling 2.
fn irq_flags(gtdt_flags: u32) -> u32 {
    match (gtdt_flags & 1 != 0, gtdt_flags & 2 != 0) {
        (false, false) => 4,
        (false, true) => 8,
        (true, false) => 1,
        (true, true) => 2,
    }
}

/// The names of the unit address in node names are lower-case hex, as dtc
/// writes them.
pub fn build(input: &Input<'_>) -> Result<Vec<u8>, Error> {
    let p = input.platform;
    let gic = p.gic.as_ref().ok_or(Error::Missing("GIC"))?;

    let mut b = Builder::new().begin("");
    b = strz(b, "compatible", "stafeto,efi");
    b = b.cells("#address-cells", &[2]).cells("#size-cells", &[2]);

    // /chosen
    b = b.begin("chosen");
    b = wide(b, "linux,initrd-start", &[input.initrd.base]);
    b = wide(b, "linux,initrd-end", &[input.initrd.end()]);
    let console = p.uart.as_ref().and_then(console_node);
    if let Some((name, _)) = &console {
        b = strz(b, "stdout-path", &format!("/{name}"));
    }
    b = b.end();

    // /memory
    for r in &input.memory.memory {
        b = b.begin(&format!("memory@{:x}", r.base));
        b = strz(b, "device_type", "memory");
        b = wide(b, "reg", &[r.base, r.size]).end();
    }
    // /reserved-memory
    b = b
        .begin("reserved-memory")
        .cells("#address-cells", &[2])
        .cells("#size-cells", &[2])
        .prop("ranges", &[]);
    for r in &input.memory.reserved {
        b = b.begin(&format!("reserved@{:x}", r.base));
        b = wide(b, "reg", &[r.base, r.size]).prop("no-map", &[]).end();
    }
    b = b.end();

    // /cpus, the boot CPU first.
    if !p.cpus.iter().any(|c| c.mpidr == input.boot_mpidr) {
        return Err(Error::Unsupported(
            "the boot CPU's MPIDR is not an enabled GICC of the MADT",
        ));
    }
    b = b
        .begin("cpus")
        .cells("#address-cells", &[2])
        .cells("#size-cells", &[0]);
    let ordered = p
        .cpus
        .iter()
        .filter(|c| c.mpidr == input.boot_mpidr)
        .chain(p.cpus.iter().filter(|c| c.mpidr != input.boot_mpidr));
    for c in ordered {
        b = b.begin(&format!("cpu@{:x}", c.mpidr));
        b = strz(b, "device_type", "cpu");
        b = strz(b, "compatible", "arm,armv8");
        b = wide(b, "reg", &[c.mpidr]);
        b = strz(b, "enable-method", "psci").end();
    }
    b = b.end();

    // /psci
    if let Some(hvc) = p.psci_hvc {
        b = b.begin("psci");
        b = b.prop("compatible", b"arm,psci-1.0\0arm,psci-0.2\0");
        b = strz(b, "method", if hvc { "hvc" } else { "smc" }).end();
    }

    // /timer
    if let Some(t) = &p.timer {
        let mut cells = Vec::new();
        // A timer the GTDT leaves out (GSIV 0: Apple's firmware has no
        // secure timer) takes the architectural PPI of the slot (G27).
        const ARCHITECTURAL: [u32; 4] = [29, 30, 27, 26];
        for (i, irq) in t.irqs.iter().enumerate() {
            let irq = if irq.gsiv == 0 {
                crate::platform::TimerIrq {
                    gsiv: ARCHITECTURAL[i],
                    flags: 0,
                }
            } else {
                *irq
            };
            if !(16..32).contains(&irq.gsiv) {
                return Err(Error::Unsupported("GTDT timer interrupt is not a PPI"));
            }
            if i == 2 && (irq.gsiv != 27 || irq.flags & 1 != 0) {
                return Err(Error::Unsupported(
                    "GTDT virtual timer is not level-triggered INTID 27, which the kernel takes",
                ));
            }
            cells.extend([1, irq.gsiv - 16, irq_flags(irq.flags)]);
        }
        b = b.begin("timer");
        b = strz(b, "compatible", "arm,armv8-timer");
        b = b.cells("interrupts", &cells);
        if t.irqs.iter().any(|i| i.flags & 4 != 0) {
            b = b.prop("always-on", &[]);
        }
        b = b.end();
    }

    // /intc with the ITS the IORT leads a root complex to.
    let its = p
        .msi
        .first()
        .and_then(|m| p.its.iter().find(|i| i.id == m.its_id));
    let &[(redist_base, redist_len)] = gic.redistributors.as_slice() else {
        return Err(Error::Unsupported("GIC redistributor range"));
    };
    b = b.begin(&format!("intc@{:x}", gic.distributor));
    b = strz(b, "compatible", "arm,gic-v3");
    b = b
        .cells("#interrupt-cells", &[3])
        .cells("#address-cells", &[2])
        .cells("#size-cells", &[2])
        .prop("interrupt-controller", &[])
        .prop("ranges", &[]);
    b = wide(
        b,
        "reg",
        &[gic.distributor, 0x1_0000, redist_base, redist_len],
    );
    if let Some(its) = its {
        b = b.begin(&format!("its@{:x}", its.base));
        b = strz(b, "compatible", "arm,gic-v3-its");
        b = b.prop("msi-controller", &[]).cells("#msi-cells", &[1]);
        b = wide(b, "reg", &[its.base, 0x2_0000]);
        b = b.cells("phandle", &[ITS_PHANDLE]).end();
    }
    b = b.end();

    // The console.
    if let Some((name, u)) = &console {
        b = b.begin(name);
        b = match u.kind {
            UartKind::Pl011 => b.prop("compatible", b"arm,pl011\0arm,primecell\0"),
            UartKind::Ns16550 => strz(b, "compatible", "ns16550a"),
        };
        let size = match u.kind {
            UartKind::Pl011 => 0x1000,
            UartKind::Ns16550 => 8 << shift_of(u),
        };
        b = wide(b, "reg", &[u.base, size]);
        if u.kind == UartKind::Ns16550 {
            b = b
                .cells("reg-shift", &[shift_of(u)])
                .cells("reg-io-width", &[width_of(u)]);
            if u.clock_hz != 0 {
                b = b.cells("clock-frequency", &[u.clock_hz]);
            }
        }
        if let Some(rate) = baud(u.baud_code) {
            b = b.cells("current-speed", &[rate]);
        }
        if let Some(g) = u.gsiv.filter(|&g| g >= 32) {
            b = b.cells("interrupts", &[0, g - 32, 4]);
        }
        b = b.end();
    }

    // The PCI hosts.
    for e in &p.ecam {
        let n = u64::from(e.last_bus - e.first_bus) + 1;
        b = b.begin(&format!("pcie@{:x}", e.base));
        b = strz(b, "compatible", "pci-host-ecam-generic");
        b = strz(b, "device_type", "pci");
        b = wide(
            b,
            "reg",
            &[e.base + (u64::from(e.first_bus) << 20), n << 20],
        );
        b = b.cells(
            "bus-range",
            &[u32::from(e.first_bus), u32::from(e.last_bus)],
        );
        b = b.cells("linux,pci-domain", &[u32::from(e.segment)]);
        b = b.cells("#address-cells", &[3]).cells("#size-cells", &[2]);
        let mut ranges = Vec::new();
        for w in input.pci_windows {
            let space = (u32::from(w.kind) << 24) | (u32::from(w.prefetchable) << 30);
            ranges.extend([
                space,
                hi(w.pci_base),
                lo(w.pci_base),
                hi(w.cpu_base),
                lo(w.cpu_base),
                hi(w.size),
                lo(w.size),
            ]);
        }
        b = b.cells("ranges", &ranges);
        let mut map = Vec::new();
        for m in p.msi.iter().filter(|m| m.segment == u32::from(e.segment)) {
            if its.is_some_and(|i| i.id == m.its_id) {
                map.extend([m.rid_base, ITS_PHANDLE, m.device_base, m.count]);
            }
        }
        if map.len() / 4 > kcore::bootinfo::MSI_MAP_ENTRIES {
            return Err(Error::TooManyRegions("msi-map entries after the merge"));
        }
        if !map.is_empty() {
            b = b.cells("msi-map", &map);
        }
        b = b.end();
    }
    Ok(b.end().finish())
}

fn shift_of(u: &Uart) -> u32 {
    if u.bit_width == 32 { 2 } else { 0 }
}

fn width_of(u: &Uart) -> u32 {
    match (u.access_size, u.bit_width) {
        (1, _) | (0, 8) => 1,
        (3, _) | (0, 32) => 4,
        _ => 1,
    }
}

fn baud(code: u8) -> Option<u32> {
    match code {
        3 => Some(9600),
        4 => Some(19200),
        6 => Some(57600),
        7 => Some(115200),
        _ => None,
    }
}

/// The node name and port of the console, or None when the port cannot be
/// described (a 16550 whose access size is a word).
fn console_node(u: &Uart) -> Option<(String, Uart)> {
    if u.kind == UartKind::Ns16550 && matches!(u.access_size, 2 | 4) {
        return None;
    }
    #[cfg(feature = "break-spcr")]
    let kind = match u.kind {
        UartKind::Pl011 => UartKind::Ns16550,
        k => k,
    };
    #[cfg(not(feature = "break-spcr"))]
    let kind = u.kind;
    let name = match kind {
        UartKind::Pl011 => format!("pl011@{:x}", u.base),
        UartKind::Ns16550 => format!("serial@{:x}", u.base),
    };
    Some((name, Uart { kind, ..*u }))
}
