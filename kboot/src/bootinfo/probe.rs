// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the boot loader and the host tests read from a device tree and the
//! kernel does not: the 16550 UART node, the PCI hosts, and the limits the
//! loader checks its tree against. A module of its own, so that the kernel's
//! `parse` and `classify` keep their code, symbols and place in the image.

use super::{BootInfoError, Cells, DEFAULT_CELLS, RegIter, Region};
use crate::fdt::{Event, Fdt, MAX_DEPTH, be32};

/// The PCI hosts `pci_hosts` lists, at most.
pub const PCI_HOSTS: usize = 4;

/// A 16550-style UART node (`ns16550a`, `ns16550`): the register block, the
/// distance of the registers as a shift of the offset, and the width of one
/// access in bytes. The boot loader writes it from an SPCR table (the PCI
/// 16550 of an EC2 instance takes byte accesses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uart16550 {
    pub regs: Region,
    pub reg_shift: u8,
    pub io_width: u8,
}

/// An ECAM host bridge (`pci-host-ecam-generic`): the configuration space
/// of the buses `bus_first..=bus_last` of `segment`, which starts at
/// `ecam.base` for bus `bus_first`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciHost {
    pub segment: u32,
    pub bus_first: u8,
    pub bus_last: u8,
    pub ecam: Region,
}

/// The PCI hosts of a tree, in its order, at most `PCI_HOSTS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciHosts {
    items: [PciHost; PCI_HOSTS],
    len: usize,
}

impl PciHosts {
    pub fn as_slice(&self) -> &[PciHost] {
        &self.items[..self.len]
    }
}

/// The properties of one node that `uart_16550` and `pci_hosts` read. A
/// second small walk, so that `parse` and the kernel's code stay as they are:
/// the kernel does not call these (the console of the console part moves
/// `uart_16550` into `BootInfo`).
#[derive(Clone, Copy)]
struct Probe<'a> {
    child_cells: Cells,
    compatible: &'a [u8],
    reg: &'a [u8],
    status: &'a [u8],
    reg_shift: Option<u32>,
    io_width: Option<u32>,
    bus_range: &'a [u8],
    pci_domain: u32,
}

impl<'a> Probe<'a> {
    fn new() -> Self {
        Self {
            child_cells: DEFAULT_CELLS,
            compatible: &[],
            reg: &[],
            status: &[],
            reg_shift: None,
            io_width: None,
            bus_range: &[],
            pci_domain: 0,
        }
    }

    fn enabled(&self) -> bool {
        self.status.is_empty() || self.status == b"okay\0" || self.status == b"ok\0"
    }

    fn is_compatible(&self, wanted: &str) -> bool {
        self.compatible
            .split(|&b| b == 0)
            .any(|s| s == wanted.as_bytes())
    }
}

/// Calls `f` with every node at its end: the node, its parent's cell sizes.
fn for_each_probe<'a>(
    fdt: &Fdt<'a>,
    mut f: impl FnMut(&Probe<'a>, Cells) -> Result<(), BootInfoError>,
) -> Result<(), BootInfoError> {
    let mut stack = [Probe::new(); MAX_DEPTH + 1];
    let mut depth = 0usize;
    let mut failure: Option<BootInfoError> = None;
    fdt.walk(|event| {
        if failure.is_some() {
            return;
        }
        match event {
            Event::BeginNode { depth: d, .. } => {
                depth = d;
                stack[d] = Probe::new();
            }
            Event::Prop { name, value } => {
                let node = &mut stack[depth];
                match name {
                    "#address-cells" => {
                        node.child_cells.address = be32(value, 0).unwrap_or(DEFAULT_CELLS.address)
                    }
                    "#size-cells" => {
                        node.child_cells.size = be32(value, 0).unwrap_or(DEFAULT_CELLS.size)
                    }
                    "compatible" => node.compatible = value,
                    "reg" => node.reg = value,
                    "status" => node.status = value,
                    "reg-shift" => node.reg_shift = be32(value, 0).ok(),
                    "reg-io-width" => node.io_width = be32(value, 0).ok(),
                    "bus-range" => node.bus_range = value,
                    "linux,pci-domain" => node.pci_domain = be32(value, 0).unwrap_or(0),
                    _ => {}
                }
            }
            Event::EndNode => {
                let cells = if depth >= 2 {
                    stack[depth - 1].child_cells
                } else {
                    DEFAULT_CELLS
                };
                if let Err(e) = f(&stack[depth], cells) {
                    failure = Some(e);
                }
                depth -= 1;
            }
        }
    })?;
    failure.map_or(Ok(()), Err)
}

/// The first enabled 16550 node (`ns16550a` or `ns16550`). `reg-shift`
/// defaults to 0 and takes 0 to 3; `reg-io-width` defaults to 1 and takes 1
/// or 4; anything else is `BadReg`.
pub fn uart_16550(fdt: &Fdt<'_>) -> Result<Option<Uart16550>, BootInfoError> {
    let mut found = None;
    for_each_probe(fdt, |node, cells| {
        if found.is_some()
            || !node.enabled()
            || !(node.is_compatible("ns16550a") || node.is_compatible("ns16550"))
        {
            return Ok(());
        }
        let regs = RegIter::new(node.reg, cells)?
            .next()
            .transpose()?
            .ok_or(BootInfoError::BadReg)?;
        let reg_shift = match node.reg_shift.unwrap_or(0) {
            s @ 0..=3 => s as u8,
            _ => return Err(BootInfoError::BadReg),
        };
        let io_width = match node.io_width.unwrap_or(1) {
            w @ (1 | 4) => w as u8,
            _ => return Err(BootInfoError::BadReg),
        };
        found = Some(Uart16550 {
            regs,
            reg_shift,
            io_width,
        });
        Ok(())
    })?;
    Ok(found)
}

/// The enabled `pci-host-ecam-generic` nodes: `reg` is the configuration
/// space of the buses from `bus-range`'s first on (so the block of bus 0
/// starts `first << 20` bytes below `reg`'s base, which nobody needs), the
/// segment is `linux,pci-domain`. More than `PCI_HOSTS` is `TooManyRegions`;
/// a `bus-range` that is not two cells with first <= last <= 255, or a `reg`
/// too small for its buses, is `BadReg`; no `bus-range` means 0 to 255.
pub fn pci_hosts(fdt: &Fdt<'_>) -> Result<PciHosts, BootInfoError> {
    let mut out = PciHosts {
        items: [PciHost {
            segment: 0,
            bus_first: 0,
            bus_last: 0,
            ecam: Region { base: 0, size: 0 },
        }; PCI_HOSTS],
        len: 0,
    };
    for_each_probe(fdt, |node, cells| {
        if !node.enabled() || !node.is_compatible("pci-host-ecam-generic") {
            return Ok(());
        }
        let ecam = RegIter::new(node.reg, cells)?
            .next()
            .transpose()?
            .ok_or(BootInfoError::BadReg)?;
        let (first, last) = match node.bus_range.len() {
            0 => (0, 255),
            8 => (
                be32(node.bus_range, 0).map_err(|_| BootInfoError::BadReg)?,
                be32(node.bus_range, 4).map_err(|_| BootInfoError::BadReg)?,
            ),
            _ => return Err(BootInfoError::BadReg),
        };
        if first > last || last > 255 || ecam.size < (u64::from(last - first) + 1) << 20 {
            return Err(BootInfoError::BadReg);
        }
        if out.len == PCI_HOSTS {
            return Err(BootInfoError::TooManyRegions);
        }
        out.items[out.len] = PciHost {
            segment: node.pci_domain,
            bus_first: first as u8,
            bus_last: last as u8,
            ecam,
        };
        out.len += 1;
        Ok(())
    })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootinfo::{
        BOOT_TAKEN, BootInfo, MEMORY_REGIONS, RegionList, USABLE_REGIONS, parse,
    };
    use crate::fdt::Builder;

    const VIRT: &[u8] = include_bytes!("../../tests/fixtures/virt.dtb");
    const VIRT_ITS: &[u8] = include_bytes!("../../tests/fixtures/virt-its.dtb");
    const APPLE_VZ: &[u8] = include_bytes!("../../tests/fixtures/apple-vz.dtb");
    const A64: &[u8] = include_bytes!("../../tests/fixtures/a64-like.dtb");

    fn info(blob: &[u8]) -> Result<BootInfo, BootInfoError> {
        parse(&Fdt::new(blob).unwrap())
    }

    fn region(base: u64, size: u64) -> Region {
        Region { base, size }
    }

    #[test]
    fn a_16550_node_gives_its_registers_shift_and_width() {
        let build = |shift: Option<u32>, width: Option<u32>, status: Option<&[u8]>| {
            let mut b = Builder::new()
                .begin("")
                .cells("#address-cells", &[2])
                .cells("#size-cells", &[2])
                .begin("serial@1000")
                .prop("compatible", b"ns16550a\0")
                .cells("reg", &[0, 0x1000, 0, 0x100]);
            if let Some(s) = shift {
                b = b.cells("reg-shift", &[s]);
            }
            if let Some(w) = width {
                b = b.cells("reg-io-width", &[w]);
            }
            if let Some(st) = status {
                b = b.prop("status", st);
            }
            let blob = b.end().end().finish();
            uart_16550(&Fdt::new(&blob).unwrap())
        };
        let regs = region(0x1000, 0x100);
        let some = |reg_shift, io_width| {
            Ok(Some(Uart16550 {
                regs,
                reg_shift,
                io_width,
            }))
        };
        assert_eq!(build(None, None, None), some(0, 1), "defaults");
        assert_eq!(build(Some(0), Some(1), None), some(0, 1));
        assert_eq!(build(Some(2), Some(4), None), some(2, 4));
        assert_eq!(build(Some(2), Some(1), None), some(2, 1));
        assert_eq!(build(None, None, Some(b"disabled\0")), Ok(None));
        assert_eq!(build(Some(7), None, None), Err(BootInfoError::BadReg));
        assert_eq!(build(None, Some(2), None), Err(BootInfoError::BadReg));
    }

    #[test]
    fn a_bad_16550_node_stops_parse_only_without_a_pl011() {
        let tree = |pl011: bool| {
            let mut b = Builder::new()
                .begin("")
                .cells("#address-cells", &[2])
                .cells("#size-cells", &[2])
                .begin("memory@40000000")
                .prop("device_type", b"memory\0")
                .cells("reg", &[0, 0x4000_0000, 0, 0x100_0000])
                .end();
            if pl011 {
                b = b
                    .begin("pl011@9000000")
                    .prop("compatible", b"arm,pl011\0")
                    .cells("reg", &[0, 0x0900_0000, 0, 0x1000])
                    .end();
            }
            let blob = b
                .begin("serial@1000")
                .prop("compatible", b"ns16550a\0")
                .cells("reg", &[0, 0x1000, 0, 0x100])
                .cells("reg-io-width", &[2])
                .end()
                .end()
                .finish();
            info(&blob)
        };
        let ok = tree(true).unwrap();
        assert_eq!(ok.uart_pl011, Some(region(0x0900_0000, 0x1000)));
        assert_eq!(ok.uart_16550, None);
        assert_eq!(tree(false), Err(BootInfoError::BadReg));
    }

    #[test]
    fn trees_without_a_16550_give_none_and_pl011_is_not_one() {
        for blob in [VIRT, VIRT_ITS, APPLE_VZ, A64] {
            assert_eq!(uart_16550(&Fdt::new(blob).unwrap()), Ok(None));
        }
    }

    fn ecam_tree(buses: &[u32], base: u32, size: u32, domain: u32) -> Vec<u8> {
        let mut node = Builder::new()
            .begin("")
            .cells("#address-cells", &[2])
            .cells("#size-cells", &[2])
            .begin("pcie@0")
            .prop("compatible", b"pci-host-ecam-generic\0")
            .cells("reg", &[0, base, 0, size])
            .cells("linux,pci-domain", &[domain]);
        if !buses.is_empty() {
            node = node.cells("bus-range", buses);
        }
        node.end().end().finish()
    }

    #[test]
    fn a_pci_host_gives_its_ecam_segment_and_buses() {
        let blob = ecam_tree(&[0, 255], 0x1000_0000, 0x1000_0000, 0);
        let hosts = pci_hosts(&Fdt::new(&blob).unwrap()).unwrap();
        assert_eq!(
            hosts.as_slice(),
            [PciHost {
                segment: 0,
                bus_first: 0,
                bus_last: 255,
                ecam: region(0x1000_0000, 0x1000_0000)
            }]
        );
        // The first bus is not 0: reg covers the buses 16..=31 only.
        let blob = ecam_tree(&[16, 31], 0x2000_0000, 16 << 20, 3);
        let host = pci_hosts(&Fdt::new(&blob).unwrap()).unwrap().as_slice()[0];
        assert_eq!((host.segment, host.bus_first, host.bus_last), (3, 16, 31));
        assert_eq!(host.ecam, region(0x2000_0000, 16 << 20));
        // No bus-range: all 256 buses.
        let blob = ecam_tree(&[], 0x1000_0000, 0x1000_0000, 0);
        assert_eq!(
            pci_hosts(&Fdt::new(&blob).unwrap()).unwrap().as_slice()[0].bus_last,
            255
        );
    }

    #[test]
    fn a_pci_host_with_a_bad_range_or_a_small_ecam_is_an_error() {
        for (buses, size) in [
            (&[5u32, 4][..], 0x1000_0000u32),
            (&[0, 256][..], 0x2000_0000),
            (&[0, 255][..], 0x10_0000),
            (&[0][..], 0x1000_0000),
        ] {
            let blob = ecam_tree(buses, 0x1000_0000, size, 0);
            assert_eq!(
                pci_hosts(&Fdt::new(&blob).unwrap()),
                Err(BootInfoError::BadReg),
                "{buses:?} {size:#x}"
            );
        }
    }

    #[test]
    fn the_qemu_trees_have_one_host_and_the_others_none() {
        let host = pci_hosts(&Fdt::new(VIRT_ITS).unwrap()).unwrap().as_slice()[0];
        assert_eq!(
            host,
            PciHost {
                segment: 0,
                bus_first: 0,
                bus_last: 255,
                ecam: region(0x40_1000_0000, 0x1000_0000)
            }
        );
        assert!(
            pci_hosts(&Fdt::new(A64).unwrap())
                .unwrap()
                .as_slice()
                .is_empty()
        );
    }

    #[test]
    fn five_pci_hosts_are_too_many() {
        let mut b = Builder::new()
            .begin("")
            .cells("#address-cells", &[2])
            .cells("#size-cells", &[2]);
        for i in 0..=PCI_HOSTS as u32 {
            b = b
                .begin("pcie")
                .prop("compatible", b"pci-host-ecam-generic\0")
                .cells("reg", &[0, 0x1000_0000 * (i + 1), 0, 0x1000_0000])
                .end();
        }
        let blob = b.end().finish();
        assert_eq!(
            pci_hosts(&Fdt::new(&blob).unwrap()),
            Err(BootInfoError::TooManyRegions)
        );
    }

    #[test]
    fn the_kernels_lists_hold_the_worst_tree_the_limits_allow() {
        // `boot::collect`: the kernel, the tree, the boot image and every
        // reserved region go in `taken`; `usable` splits `memory` once per
        // taken range.
        let reserved = 16;
        assert!(3 + reserved <= BOOT_TAKEN);
        assert!(MEMORY_REGIONS + 3 + reserved <= USABLE_REGIONS);
        let _: RegionList<BOOT_TAKEN> = RegionList::new();
    }

    #[test]
    fn a_tree_of_eight_memory_and_sixteen_reserved_regions_passes_the_kernels_checks() {
        let mut b = Builder::new()
            .begin("")
            .cells("#address-cells", &[2])
            .cells("#size-cells", &[2]);
        for i in 0..MEMORY_REGIONS as u32 {
            b = b
                .begin("memory")
                .prop("device_type", b"memory\0")
                .cells("reg", &[0, 0x4000_0000 + i * 0x100_0000, 0, 0x80_0000])
                .end();
        }
        b = b
            .begin("reserved-memory")
            .cells("#address-cells", &[2])
            .cells("#size-cells", &[2]);
        for i in 0..16u32 {
            // The odd ones fall in the middle of a memory region and split it.
            let base = 0x4000_0000 + (i / 2) * 0x100_0000 + (i % 2) * 0x10_0000 + 0x1000;
            b = b.begin("r").cells("reg", &[0, base, 0, 0x1000]);
            if i % 2 == 0 {
                b = b.prop("no-map", &[]);
            }
            b = b.end();
        }
        let blob = b.end().end().finish();
        let parsed = info(&blob).unwrap();
        assert_eq!(parsed.memory.as_slice().len(), MEMORY_REGIONS);
        assert_eq!(parsed.reserved.as_slice().len(), 16);
        let mut taken: RegionList<BOOT_TAKEN> = RegionList::new();
        for r in [region(0x4000_0000, 0x1000), region(0x4000_2000, 0x1000)]
            .into_iter()
            .chain(Some(region(0x4000_4000, 0x1000)))
            .chain(parsed.reserved.as_slice().iter().copied())
        {
            taken.push(r).unwrap();
        }
        let usable =
            crate::memmap::usable::<USABLE_REGIONS>(parsed.memory.as_slice(), taken.as_slice());
        assert!(usable.is_ok());
        // A ninth region is `TooManyRegions`.
        let blob = Builder::new()
            .begin("")
            .cells("#address-cells", &[2])
            .cells("#size-cells", &[2])
            .begin("memory")
            .prop("device_type", b"memory\0")
            .cells(
                "reg",
                &(0..=MEMORY_REGIONS as u32)
                    .flat_map(|i| [0, 0x4000_0000 + i * 0x100_0000, 0, 0x1000])
                    .collect::<Vec<_>>(),
            )
            .end()
            .end()
            .finish();
        assert_eq!(info(&blob), Err(BootInfoError::TooManyRegions));
    }
}
