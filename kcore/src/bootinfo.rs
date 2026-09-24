// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the kernel needs from the device tree at boot: RAM, reserved ranges,
//! the boot image (initrd), the early console, the interrupt controller and
//! the PSCI conduit.

use crate::fdt::{be32, be64, Event, Fdt, FdtError, MAX_DEPTH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub base: u64,
    pub size: u64,
}

impl Region {
    pub fn end(&self) -> u64 {
        self.base.saturating_add(self.size)
    }
}

/// How PSCI calls reach the firmware (`/psci` `method`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsciConduit {
    None,
    Hvc,
    Smc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootInfoError {
    Fdt(FdtError),
    BadReg,
    BadInitrd,
    TooManyRegions,
    NoMemory,
}

impl From<FdtError> for BootInfoError {
    fn from(e: FdtError) -> Self {
        BootInfoError::Fdt(e)
    }
}

/// A fixed-capacity list, since the kernel has no allocator at this point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionList<const N: usize> {
    items: [Region; N],
    len: usize,
}

impl<const N: usize> RegionList<N> {
    pub const fn new() -> Self {
        Self { items: [Region { base: 0, size: 0 }; N], len: 0 }
    }

    pub fn push(&mut self, r: Region) -> Result<(), BootInfoError> {
        if self.len == N {
            return Err(BootInfoError::TooManyRegions);
        }
        self.items[self.len] = r;
        self.len += 1;
        Ok(())
    }

    pub fn as_slice(&self) -> &[Region] {
        &self.items[..self.len]
    }
}

impl<const N: usize> Default for RegionList<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootInfo {
    pub memory: RegionList<8>,
    pub reserved: RegionList<16>,
    pub initrd: Option<Region>,
    pub uart_pl011: Option<Region>,
    pub gic_distributor: Option<Region>,
    pub gic_cpu_interface: Option<Region>,
    pub psci: PsciConduit,
}

#[derive(Debug, Clone, Copy)]
struct Cells {
    address: u32,
    size: u32,
}

/// Devicetree specification defaults when a node has no `#address-cells` or `#size-cells`.
const DEFAULT_CELLS: Cells = Cells { address: 2, size: 1 };

/// Properties of one node, collected until its end, when the node is classified.
#[derive(Debug, Clone, Copy)]
struct Node<'a> {
    name: &'a str,
    child_cells: Cells,
    compatible: &'a [u8],
    reg: &'a [u8],
    device_type: &'a [u8],
    status: &'a [u8],
    method: &'a [u8],
    initrd_start: Option<u64>,
    initrd_end: Option<u64>,
}

impl<'a> Node<'a> {
    fn new(name: &'a str) -> Self {
        Self {
            name,
            child_cells: DEFAULT_CELLS,
            compatible: &[],
            reg: &[],
            device_type: &[],
            status: &[],
            method: &[],
            initrd_start: None,
            initrd_end: None,
        }
    }

    fn enabled(&self) -> bool {
        self.status.is_empty() || self.status == b"okay\0" || self.status == b"ok\0"
    }

    fn is_compatible(&self, wanted: &str) -> bool {
        self.compatible.split(|&b| b == 0).any(|s| s == wanted.as_bytes())
    }

    fn named(&self, base: &str) -> bool {
        self.name == base || self.name.strip_prefix(base).is_some_and(|rest| rest.starts_with('@'))
    }
}

/// A 32- or 64-bit property value.
fn number(value: &[u8]) -> Option<u64> {
    match value.len() {
        4 => be32(value, 0).ok().map(u64::from),
        8 => be64(value, 0).ok(),
        _ => None,
    }
}

struct RegIter<'a> {
    data: &'a [u8],
    cells: Cells,
    off: usize,
}

impl<'a> RegIter<'a> {
    fn new(data: &'a [u8], cells: Cells) -> Result<Self, BootInfoError> {
        if cells.address == 0 || cells.address > 2 || cells.size > 2 {
            return Err(BootInfoError::BadReg);
        }
        let entry = 4 * (cells.address + cells.size) as usize;
        if data.len() % entry != 0 {
            return Err(BootInfoError::BadReg);
        }
        Ok(Self { data, cells, off: 0 })
    }

    fn read(&mut self, n: u32) -> Result<u64, BootInfoError> {
        let v = match n {
            0 => 0,
            1 => u64::from(be32(self.data, self.off)?),
            _ => be64(self.data, self.off)?,
        };
        self.off += 4 * n as usize;
        Ok(v)
    }
}

impl Iterator for RegIter<'_> {
    type Item = Result<Region, BootInfoError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.off >= self.data.len() {
            return None;
        }
        let base = self.read(self.cells.address);
        let size = self.read(self.cells.size);
        Some(match (base, size) {
            (Ok(base), Ok(size)) => Ok(Region { base, size }),
            _ => Err(BootInfoError::BadReg),
        })
    }
}

fn classify(node: &Node<'_>, depth: usize, cells: Cells, info: &mut BootInfo) -> Result<(), BootInfoError> {
    let top = depth == 2;
    if node.device_type == b"memory\0" || (top && node.named("memory")) {
        for r in RegIter::new(node.reg, cells)? {
            info.memory.push(r?)?;
        }
    }
    if top && node.name == "chosen" {
        info.initrd = match (node.initrd_start, node.initrd_end) {
            (None, None) => None,
            (Some(s), Some(e)) if e == s => None,
            (Some(s), Some(e)) if e > s => Some(Region { base: s, size: e - s }),
            _ => return Err(BootInfoError::BadInitrd),
        };
    }
    if top && node.named("psci") {
        info.psci = match node.method {
            b"hvc\0" => PsciConduit::Hvc,
            b"smc\0" => PsciConduit::Smc,
            _ => PsciConduit::None,
        };
    }
    if !node.enabled() {
        return Ok(());
    }
    if info.uart_pl011.is_none() && node.is_compatible("arm,pl011") {
        info.uart_pl011 = RegIter::new(node.reg, cells)?.next().transpose()?;
    }
    if node.is_compatible("arm,cortex-a15-gic") || node.is_compatible("arm,gic-400") {
        let mut regs = RegIter::new(node.reg, cells)?;
        info.gic_distributor = regs.next().transpose()?;
        info.gic_cpu_interface = regs.next().transpose()?;
    }
    Ok(())
}

/// Collects boot information. `reg` is decoded with the parent's cell sizes;
/// bus `ranges` are assumed to be identity (true for QEMU `virt` and the A64).
pub fn parse(fdt: &Fdt<'_>) -> Result<BootInfo, BootInfoError> {
    let mut info = BootInfo {
        memory: RegionList::new(),
        reserved: RegionList::new(),
        initrd: None,
        uart_pl011: None,
        gic_distributor: None,
        gic_cpu_interface: None,
        psci: PsciConduit::None,
    };
    let mut stack = [Node::new(""); MAX_DEPTH + 1];
    let mut depth = 0usize;
    let mut failure: Option<BootInfoError> = None;
    fdt.walk(|event| {
        if failure.is_some() {
            return;
        }
        match event {
            Event::BeginNode { name, depth: d } => {
                depth = d;
                stack[d] = Node::new(name);
            }
            Event::Prop { name, value } => {
                let node = &mut stack[depth];
                match name {
                    "#address-cells" => node.child_cells.address = be32(value, 0).unwrap_or(2),
                    "#size-cells" => node.child_cells.size = be32(value, 0).unwrap_or(1),
                    "compatible" => node.compatible = value,
                    "reg" => node.reg = value,
                    "device_type" => node.device_type = value,
                    "status" => node.status = value,
                    "method" => node.method = value,
                    "linux,initrd-start" => node.initrd_start = number(value),
                    "linux,initrd-end" => node.initrd_end = number(value),
                    _ => {}
                }
            }
            Event::EndNode => {
                let cells = if depth >= 2 { stack[depth - 1].child_cells } else { DEFAULT_CELLS };
                if let Err(e) = classify(&stack[depth], depth, cells, &mut info) {
                    failure = Some(e);
                }
                depth -= 1;
            }
        }
    })?;
    if let Some(e) = failure {
        return Err(e);
    }
    for (base, size) in fdt.reservations() {
        info.reserved.push(Region { base, size })?;
    }
    if info.memory.as_slice().is_empty() {
        return Err(BootInfoError::NoMemory);
    }
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(blob: &[u8]) -> Result<BootInfo, BootInfoError> {
        parse(&Fdt::new(blob).unwrap())
    }

    const VIRT: &[u8] = include_bytes!("../tests/fixtures/virt.dtb");
    const A64: &[u8] = include_bytes!("../tests/fixtures/a64-like.dtb");
    const NOCELLS: &[u8] = include_bytes!("../tests/fixtures/nocells.dtb");
    const NOMEM: &[u8] = include_bytes!("../tests/fixtures/nomem.dtb");
    const BADINITRD: &[u8] = include_bytes!("../tests/fixtures/badinitrd.dtb");

    fn region(base: u64, size: u64) -> Region {
        Region { base, size }
    }

    #[test]
    fn virt_memory() {
        assert_eq!(info(VIRT).unwrap().memory.as_slice(), [region(0x4000_0000, 0x2000_0000)]);
    }

    #[test]
    fn virt_devices_skip_disabled_nodes() {
        let i = info(VIRT).unwrap();
        assert_eq!(i.uart_pl011, Some(region(0x0900_0000, 0x1000)));
        assert_eq!(i.gic_distributor, Some(region(0x0800_0000, 0x1_0000)));
        assert_eq!(i.gic_cpu_interface, Some(region(0x0801_0000, 0x1_0000)));
    }

    #[test]
    fn virt_initrd_psci_and_reservations() {
        let i = info(VIRT).unwrap();
        assert_eq!(i.initrd, Some(region(0x4800_0000, 0x1000)));
        assert_eq!(i.psci, PsciConduit::Hvc);
        assert_eq!(i.reserved.as_slice(), [region(0x4800_0000, 0x1000)]);
    }

    #[test]
    fn a64_like_tree_reads_bus_nodes_and_32bit_cells() {
        let i = info(A64).unwrap();
        assert_eq!(i.memory.as_slice(), [region(0x4000_0000, 0x8000_0000)]);
        assert_eq!(i.initrd, Some(region(0x4ff0_0000, 0x1_0000)));
        assert_eq!(i.gic_distributor, Some(region(0x01c8_1000, 0x1000)));
        assert_eq!(i.gic_cpu_interface, Some(region(0x01c8_2000, 0x2000)));
        assert_eq!(i.psci, PsciConduit::Smc);
        assert_eq!(i.uart_pl011, None);
    }

    #[test]
    fn root_without_cells_uses_defaults() {
        assert_eq!(info(NOCELLS).unwrap().memory.as_slice(), [region(0x4000_0000, 0x1000_0000)]);
    }

    #[test]
    fn missing_memory_is_an_error() {
        assert_eq!(info(NOMEM).err(), Some(BootInfoError::NoMemory));
    }

    #[test]
    fn initrd_ending_before_it_starts_is_an_error() {
        assert_eq!(info(BADINITRD).err(), Some(BootInfoError::BadInitrd));
    }

    #[test]
    fn region_list_refuses_overflow() {
        let mut list = RegionList::<1>::new();
        assert!(list.push(region(1, 1)).is_ok());
        assert_eq!(list.push(region(2, 2)), Err(BootInfoError::TooManyRegions));
    }

    #[test]
    fn never_panics_on_any_single_corrupted_byte() {
        for blob in [VIRT, A64] {
            for i in 0..blob.len() {
                let mut b = blob.to_vec();
                b[i] ^= 0x5a;
                if let Ok(fdt) = Fdt::new(&b) {
                    let _ = parse(&fdt);
                }
            }
        }
    }
}
