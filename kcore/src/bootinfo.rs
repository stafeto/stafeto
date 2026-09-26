// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the kernel needs from the device tree at boot: RAM, reserved ranges,
//! the boot image (initrd), the early console, the interrupt controller and
//! the PSCI conduit.

use crate::fdt::{Event, Fdt, FdtError, MAX_DEPTH, be32, be64};
use crate::gic::REDISTRIBUTOR_WINDOW;

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
        Self {
            items: [Region { base: 0, size: 0 }; N],
            len: 0,
        }
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

/// The RAM regions a device tree names, at most (`BootInfo::memory`,
/// `kcore::window::Forbidden`).
pub const MEMORY_REGIONS: usize = 8;

/// The regions of the interrupt controller's node, at most (`Gic::regs`,
/// `kcore::window::Forbidden`).
pub const GIC_REGIONS: usize = 8;

/// The architecture of the interrupt controller, from its node's
/// `compatible` (spec 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GicVersion {
    /// `arm,cortex-a15-gic` or `arm,gic-400`.
    V2,
    /// `arm,gic-v3`.
    V3,
}

/// The interrupt controller's node (spec 9): its version and every region
/// of its `reg` in the node's order, at least two. A GICv2 has the
/// distributor, the CPU interface, then maybe the virtual interface
/// control and the virtual CPU interface; a GICv3 has the distributor,
/// the redistributor regions, then maybe the GICv2 CPU interface, the
/// virtual interface control and the virtual CPU interface. Child nodes
/// (MSI frames, ITS) are other nodes and not part of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gic {
    pub version: GicVersion,
    pub regs: RegionList<GIC_REGIONS>,
}

impl Gic {
    /// The two blocks the kernel maps and drives: the distributor, and the
    /// CPU interface of a GICv2 or the first REDISTRIBUTOR_WINDOW bytes of
    /// the first redistributor region of a GICv3.
    pub fn mapped(&self) -> [Region; 2] {
        let [dist, second] = [self.regs.as_slice()[0], self.regs.as_slice()[1]];
        let cpu = match self.version {
            GicVersion::V2 => second,
            GicVersion::V3 => Region {
                base: second.base,
                size: second.size.min(REDISTRIBUTOR_WINDOW),
            },
        };
        [dist, cpu]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootInfo {
    pub memory: RegionList<MEMORY_REGIONS>,
    pub reserved: RegionList<16>,
    /// Reserved regions marked `no-map`: never allocated and never mapped.
    pub no_map: RegionList<8>,
    pub initrd: Option<Region>,
    pub uart_pl011: Option<Region>,
    /// The first enabled node of an interrupt controller the kernel knows.
    pub gic: Option<Gic>,
    pub psci: PsciConduit,
}

#[derive(Debug, Clone, Copy)]
struct Cells {
    address: u32,
    size: u32,
}

/// Devicetree specification defaults when a node has no `#address-cells` or `#size-cells`.
const DEFAULT_CELLS: Cells = Cells {
    address: 2,
    size: 1,
};

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
    no_map: bool,
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
            no_map: false,
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

    /// The version of a GIC node the kernel drives (spec 9); None for any
    /// other node.
    fn gic_version(&self) -> Option<GicVersion> {
        if self.is_compatible("arm,cortex-a15-gic") || self.is_compatible("arm,gic-400") {
            Some(GicVersion::V2)
        } else if self.is_compatible("arm,gic-v3") {
            Some(GicVersion::V3)
        } else {
            None
        }
    }

    fn named(&self, base: &str) -> bool {
        self.name == base
            || self
                .name
                .strip_prefix(base)
                .is_some_and(|rest| rest.starts_with('@'))
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
        if !data.len().is_multiple_of(entry) {
            return Err(BootInfoError::BadReg);
        }
        Ok(Self {
            data,
            cells,
            off: 0,
        })
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

fn classify(
    node: &Node<'_>,
    parent: &str,
    depth: usize,
    cells: Cells,
    info: &mut BootInfo,
) -> Result<(), BootInfoError> {
    let top = depth == 2;
    if node.device_type == b"memory\0" || (top && node.named("memory")) {
        for r in RegIter::new(node.reg, cells)? {
            info.memory.push(r?)?;
        }
    }
    if depth == 3 && parent == "reserved-memory" && node.enabled() {
        for r in RegIter::new(node.reg, cells)? {
            let r = r?;
            info.reserved.push(r)?;
            if node.no_map {
                info.no_map.push(r)?;
            }
        }
    }
    if top && node.name == "chosen" {
        info.initrd = match (node.initrd_start, node.initrd_end) {
            (None, None) => None,
            (Some(s), Some(e)) if e == s => None,
            (Some(s), Some(e)) if e > s => Some(Region {
                base: s,
                size: e - s,
            }),
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
    if info.gic.is_none()
        && let Some(version) = node.gic_version()
    {
        let mut regs = RegionList::new();
        for r in RegIter::new(node.reg, cells)? {
            regs.push(r?)?;
        }
        if regs.as_slice().len() < 2 {
            return Err(BootInfoError::BadReg);
        }
        info.gic = Some(Gic { version, regs });
    }
    Ok(())
}

/// Collects boot information. `reg` is decoded with the parent's cell sizes;
/// bus `ranges` are assumed to be identity (true for QEMU `virt` and the A64).
pub fn parse(fdt: &Fdt<'_>) -> Result<BootInfo, BootInfoError> {
    let mut info = BootInfo {
        memory: RegionList::new(),
        reserved: RegionList::new(),
        no_map: RegionList::new(),
        initrd: None,
        uart_pl011: None,
        gic: None,
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
                    "#address-cells" => {
                        node.child_cells.address = be32(value, 0).unwrap_or(DEFAULT_CELLS.address)
                    }
                    "#size-cells" => {
                        node.child_cells.size = be32(value, 0).unwrap_or(DEFAULT_CELLS.size)
                    }
                    "compatible" => node.compatible = value,
                    "reg" => node.reg = value,
                    "device_type" => node.device_type = value,
                    "status" => node.status = value,
                    "method" => node.method = value,
                    "linux,initrd-start" => node.initrd_start = number(value),
                    "linux,initrd-end" => node.initrd_end = number(value),
                    "no-map" => node.no_map = true,
                    _ => {}
                }
            }
            Event::EndNode => {
                let (cells, parent) = if depth >= 2 {
                    (stack[depth - 1].child_cells, stack[depth - 1].name)
                } else {
                    (DEFAULT_CELLS, "")
                };
                if let Err(e) = classify(&stack[depth], parent, depth, cells, &mut info) {
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
    use crate::fdt::Builder;

    fn info(blob: &[u8]) -> Result<BootInfo, BootInfoError> {
        parse(&Fdt::new(blob).unwrap())
    }

    const VIRT: &[u8] = include_bytes!("../tests/fixtures/virt.dtb");
    const VIRT_GICV3: &[u8] = include_bytes!("../tests/fixtures/virt-gicv3.dtb");
    const A64: &[u8] = include_bytes!("../tests/fixtures/a64-like.dtb");
    const NOCELLS: &[u8] = include_bytes!("../tests/fixtures/nocells.dtb");
    const NOMEM: &[u8] = include_bytes!("../tests/fixtures/nomem.dtb");
    const BADINITRD: &[u8] = include_bytes!("../tests/fixtures/badinitrd.dtb");

    fn region(base: u64, size: u64) -> Region {
        Region { base, size }
    }

    #[test]
    fn virt_memory() {
        assert_eq!(
            info(VIRT).unwrap().memory.as_slice(),
            [region(0x4000_0000, 0x2000_0000)]
        );
    }

    #[test]
    fn virt_devices_skip_disabled_nodes() {
        let i = info(VIRT).unwrap();
        assert_eq!(i.uart_pl011, Some(region(0x0900_0000, 0x1000)));
        let gic = i.gic.unwrap();
        assert_eq!(gic.version, GicVersion::V2);
        assert_eq!(
            gic.regs.as_slice(),
            [region(0x0800_0000, 0x1_0000), region(0x0801_0000, 0x1_0000)]
        );
        assert_eq!(
            gic.mapped(),
            [gic.regs.as_slice()[0], gic.regs.as_slice()[1]]
        );
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
        assert_eq!(i.psci, PsciConduit::Smc);
        assert_eq!(i.uart_pl011, None);
    }

    #[test]
    fn gic_node_keeps_every_reg() {
        let gic = info(A64).unwrap().gic.unwrap();
        assert_eq!(gic.version, GicVersion::V2);
        assert_eq!(
            gic.regs.as_slice(),
            [
                region(0x01c8_1000, 0x1000),
                region(0x01c8_2000, 0x2000),
                region(0x01c8_4000, 0x2000),
                region(0x01c8_6000, 0x2000)
            ]
        );
        assert_eq!(
            gic.mapped(),
            [region(0x01c8_1000, 0x1000), region(0x01c8_2000, 0x2000)]
        );
    }

    #[test]
    fn gicv3_node_gives_distributor_and_redistributors() {
        let i = info(VIRT_GICV3).unwrap();
        let gic = i.gic.unwrap();
        assert_eq!(gic.version, GicVersion::V3);
        assert_eq!(
            gic.regs.as_slice(),
            [
                region(0x0800_0000, 0x1_0000),
                region(0x080A_0000, 0xF6_0000)
            ]
        );
        assert_eq!(
            gic.mapped(),
            [
                region(0x0800_0000, 0x1_0000),
                region(0x080A_0000, REDISTRIBUTOR_WINDOW)
            ]
        );
        assert_eq!(i.uart_pl011, Some(region(0x0900_0000, 0x1000)));
        assert_eq!(i.psci, PsciConduit::Hvc);
    }

    /// A tree with 64 MiB of RAM and a GIC node of `compatible` with
    /// `regs` (address and size cells of two words), which holds `child`,
    /// a node of that `compatible` with one region, if any.
    fn tree_with_gic(
        compatible: &str,
        regs: &[(u64, u64)],
        child: Option<(&str, (u64, u64))>,
    ) -> Vec<u8> {
        let words =
            |(base, size): (u64, u64)| [base, size].map(|w| [(w >> 32) as u32, w as u32]).concat();
        let string = |s: &str| [s.as_bytes(), b"\0"].concat();
        let mut b = Builder::new()
            .begin("")
            .cells("#address-cells", &[2])
            .cells("#size-cells", &[2])
            .begin("memory@40000000")
            .prop("device_type", b"memory\0")
            .cells("reg", &words((0x4000_0000, 0x400_0000)))
            .end()
            .begin("intc@8000000")
            .prop("compatible", &string(compatible))
            .cells("#address-cells", &[2])
            .cells("#size-cells", &[2])
            .cells(
                "reg",
                &regs.iter().flat_map(|&r| words(r)).collect::<Vec<_>>(),
            );
        if let Some((compatible, reg)) = child {
            b = b
                .begin("frame")
                .prop("compatible", &string(compatible))
                .cells("reg", &words(reg))
                .end();
        }
        b.end().end().finish()
    }

    #[test]
    fn gic_children_are_not_taken() {
        let its = info(VIRT_GICV3).unwrap().gic.unwrap();
        assert_eq!(its.regs.as_slice().len(), 2);
        assert!(its.regs.as_slice().iter().all(|r| r.base != 0x0808_0000));
        let gic = [(0x0800_0000, 0x1_0000), (0x0801_0000, 0x1_0000)];
        let v2m = Some(("arm,gic-v2m-frame", (0x0802_0000, 0x1000)));
        let tree = tree_with_gic("arm,cortex-a15-gic", &gic, v2m);
        let v2m = info(&tree).unwrap().gic.unwrap();
        assert_eq!(v2m.regs.as_slice(), gic.map(|(b, s)| region(b, s)));
    }

    #[test]
    fn gic_with_too_many_regs_is_an_error() {
        let regs: Vec<_> = (0..GIC_REGIONS as u64 + 1)
            .map(|i| (0x0800_0000 + i * 0x1_0000, 0x1_0000))
            .collect();
        let most = tree_with_gic("arm,gic-v3", &regs[..GIC_REGIONS], None);
        assert_eq!(
            info(&most).unwrap().gic.unwrap().regs.as_slice().len(),
            GIC_REGIONS
        );
        let more = tree_with_gic("arm,gic-v3", &regs, None);
        assert_eq!(info(&more).err(), Some(BootInfoError::TooManyRegions));
    }

    #[test]
    fn gic_with_one_reg_is_an_error() {
        let one = tree_with_gic("arm,gic-400", &[(0x0800_0000, 0x1000)], None);
        assert_eq!(info(&one).err(), Some(BootInfoError::BadReg));
    }

    #[test]
    fn root_without_cells_uses_defaults() {
        assert_eq!(
            info(NOCELLS).unwrap().memory.as_slice(),
            [region(0x4000_0000, 0x1000_0000)]
        );
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
    fn reserved_memory_children_are_reserved_and_no_map_is_noted() {
        let i = info(A64).unwrap();
        assert_eq!(
            i.reserved.as_slice(),
            [
                region(0x4000_0000, 0x8_0000),
                region(0x7e00_0000, 0x100_0000)
            ]
        );
        assert_eq!(i.no_map.as_slice(), [region(0x4000_0000, 0x8_0000)]);
    }

    #[test]
    fn disabled_reserved_memory_children_are_not_reserved() {
        let i = info(A64).unwrap();
        let disabled = region(0x7f00_0000, 0x10_0000);
        assert!(!i.reserved.as_slice().contains(&disabled));
        assert!(!i.no_map.as_slice().contains(&disabled));
    }

    #[test]
    fn virt_has_no_no_map_regions() {
        assert!(info(VIRT).unwrap().no_map.as_slice().is_empty());
    }

    #[test]
    fn never_panics_on_any_single_corrupted_byte() {
        for blob in [VIRT, VIRT_GICV3, A64] {
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
