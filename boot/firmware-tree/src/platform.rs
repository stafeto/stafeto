// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the kernel needs from the static ACPI tables (stafeto-design tasks/2026-11-12-aws-efi-loader.md, section
//! 3): the CPUs and the interrupt controller from the MADT, the PSCI
//! conduit from the FADT, the timer interrupts from the GTDT, the console
//! from the SPCR, the PCI hosts from the MCFG, and the DeviceID map of the
//! MSI controller from the IORT. AML (DSDT, SSDT) is not read. Offsets are
//! those of Linux `include/acpi/actbl*.h` (ACPI 6.5, Arm DEN 0049, the SPCR
//! of Microsoft).

use crate::acpi::{Table, Tables, records, u16_at, u32_at, u64_at};
use crate::error::Error;
use alloc::vec::Vec;

/// A GICv3 redistributor frame pair is 128 KiB, 256 KiB with direct LPI
/// injection (GICv4) (spec 9, G39).
const GICR_FRAME_V3: u64 = 0x2_0000;
const GICR_FRAME_V4: u64 = 0x4_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cpu {
    pub mpidr: u64,
    /// This GICC's own redistributor, when the MADT gives it there.
    pub gicr: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gic {
    /// 3 or 4.
    pub version: u8,
    pub distributor: u64,
    /// The redistributor ranges of the GICR structures: (base, length).
    pub redistributors: Vec<(u64, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Its {
    pub id: u32,
    pub base: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerIrq {
    pub gsiv: u32,
    /// GTDT flags: bit 0 edge, bit 1 active low, bit 2 always on.
    pub flags: u32,
}

/// The four timers in the order of the device tree's `interrupts`: secure
/// EL1, non-secure EL1, virtual, hypervisor (G27).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timer {
    pub irqs: [TimerIrq; 4],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UartKind {
    Pl011,
    Ns16550,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uart {
    pub kind: UartKind,
    /// The SPCR's interface type (a DBG2 port subtype).
    pub interface_type: u8,
    pub base: u64,
    /// Bits of one register in the GAS: 8 or 32 (0 when the table leaves it).
    pub bit_width: u8,
    /// GAS access size: 0 undefined, 1 byte, 2 word, 3 dword, 4 qword.
    pub access_size: u8,
    pub gsiv: Option<u32>,
    /// SPCR baud code: 3 9600, 4 19200, 6 57600, 7 115200.
    pub baud_code: u8,
    pub clock_hz: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ecam {
    pub base: u64,
    pub segment: u16,
    pub first_bus: u8,
    pub last_bus: u8,
}

/// One entry of the MSI map of a PCI host: the requester IDs
/// `rid_base..rid_base + count` of `segment` reach the ITS `its_id` as
/// DeviceIDs from `device_base` on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsiRange {
    pub segment: u32,
    pub rid_base: u32,
    pub its_id: u32,
    pub device_base: u32,
    pub count: u32,
}

impl Uart {
    /// Register shift and access width in bytes of a 16550, decided from the
    /// access size alone as Linux does (`drivers/acpi/spcr.c`: byte is
    /// `mmio`, dword is `mmio32`, which is shift 2); a bit width that
    /// contradicts it is refused, as are word and qword accesses, which a
    /// 16550 driver does not make. PL011 gives (2, 4).
    pub fn regs(&self) -> Result<(u8, u8), Error> {
        if self.kind == UartKind::Pl011 {
            return Ok((2, 4));
        }
        let (shift, width) = match self.access_size {
            0 | 1 => (0, 1),
            3 => (2, 4),
            _ => {
                return Err(Error::Unsupported(
                    "SPCR 16550 access size (byte or dword only)",
                ));
            }
        };
        if self.bit_width != 0 && self.bit_width != width * 8 {
            return Err(Error::Unsupported(
                "SPCR register bit width and access size disagree",
            ));
        }
        Ok((shift, width))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Platform {
    pub cpus: Vec<Cpu>,
    pub gic: Option<Gic>,
    pub its: Vec<Its>,
    /// `Some(true)` PSCI over HVC, `Some(false)` over SMC, None: no PSCI.
    pub psci_hvc: Option<bool>,
    pub timer: Option<Timer>,
    pub uart: Option<Uart>,
    pub ecam: Vec<Ecam>,
    pub msi: Vec<MsiRange>,
    /// What was accepted with a caveat, for the loader's summary.
    pub warnings: Vec<&'static str>,
    /// The GICR base of every enabled GICC, until the version is known.
    gicc_gicr: Vec<u64>,
}

impl Platform {
    pub fn from_tables(tables: &Tables<'_>) -> Result<Self, Error> {
        let mut p = Platform::default();
        let madt = tables.find(b"APIC").ok_or(Error::Missing("MADT"))?;
        p.read_madt(madt)?;
        if p.its.len() > 1 {
            p.warnings
                .push("MADT lists more than one ITS (the kernel keeps one)");
        }
        if let Some(fadt) = tables.find(b"FACP") {
            p.read_fadt(fadt)?;
        }
        if let Some(gtdt) = tables.find(b"GTDT") {
            p.read_gtdt(gtdt)?;
        }
        if let Some(spcr) = tables.find(b"SPCR") {
            p.read_spcr(spcr)?;
        }
        if let Some(mcfg) = tables.find(b"MCFG") {
            p.read_mcfg(mcfg)?;
        }
        if let Some(iort) = tables.find(b"IORT") {
            p.read_iort(iort)?;
        }
        Ok(p)
    }

    fn read_madt(&mut self, t: &Table<'_>) -> Result<(), Error> {
        const ERR: Error = Error::Truncated("MADT record");
        let mut gicr_bases = Vec::new();
        let mut gicr_ranges = Vec::new();
        for rec in records(t.data, 44) {
            let (kind, r) = rec?;
            match kind {
                // GICC (ACPI 6.5, "GIC CPU Interface (GICC) Structure").
                0xB if r.len() >= 76 => {
                    if u32_at(r, 12).ok_or(ERR)? & 1 != 0 {
                        self.cpus.push(Cpu {
                            mpidr: u64_at(r, 68).ok_or(ERR)? & kcore::bootinfo::MPIDR_AFFINITY,
                            gicr: u64_at(r, 60).ok_or(ERR)?,
                        });
                        gicr_bases.push(u64_at(r, 60).ok_or(ERR)?);
                    }
                }
                0xB => return Err(ERR),
                // GICD.
                0xC if r.len() >= 24 && self.gic.is_none() => {
                    self.gic = Some(Gic {
                        version: r[20],
                        distributor: u64_at(r, 8).ok_or(ERR)?,
                        redistributors: Vec::new(),
                    });
                }
                // GICR.
                0xE if r.len() >= 16 => {
                    let range = (
                        u64_at(r, 4).ok_or(ERR)?,
                        u64::from(u32_at(r, 12).ok_or(ERR)?),
                    );
                    gicr_ranges.push(range);
                }
                // GIC ITS.
                0xF if r.len() >= 20 => self.its.push(Its {
                    id: u32_at(r, 4).ok_or(ERR)?,
                    base: u64_at(r, 8).ok_or(ERR)?,
                }),
                _ => {}
            }
        }
        let gic = self.gic.as_mut().ok_or(Error::Missing("MADT GICD"))?;
        gic.redistributors = gicr_ranges;
        if self.cpus.is_empty() {
            return Err(Error::Missing("MADT enabled GICC"));
        }
        self.gicc_gicr = gicr_bases;
        // Version 0 means "discover from the hardware" (ACPI 6.5, GICD
        // structure): the loader reads GICD_PIDR2 and calls
        // `resolve_gic_version` before anything uses the version.
        if self.gic.as_ref().is_some_and(|g| g.version != 0) {
            self.finish_gic()?;
        }
        Ok(())
    }

    /// The checks and the GICC-derived range that need the version.
    fn finish_gic(&mut self) -> Result<(), Error> {
        let gic = self.gic.as_mut().ok_or(Error::Missing("MADT GICD"))?;
        if !matches!(gic.version, 3 | 4) {
            return Err(Error::Unsupported(
                "GIC version (the kernel drives v3 and v4 under ACPI)",
            ));
        }
        if gic.redistributors.len() > 1 {
            return Err(Error::Unsupported(
                "more than one GICR range (the kernel maps the first)",
            ));
        }
        if gic.redistributors.is_empty() {
            // GICC-only layout: one range from the GICR base of every CPU.
            let frame = if gic.version == 4 {
                GICR_FRAME_V4
            } else {
                GICR_FRAME_V3
            };
            let mut bases = self.gicc_gicr.clone();
            bases.sort_unstable();
            let first = bases[0];
            if first == 0 {
                return Err(Error::Missing(
                    "GICR base (no GICR structure, GICC has none)",
                ));
            }
            for (i, b) in bases.iter().enumerate() {
                if *b != first + i as u64 * frame {
                    return Err(Error::Unsupported(
                        "GICC redistributor bases are not one range",
                    ));
                }
            }
            gic.redistributors.push((first, frame * bases.len() as u64));
            self.warnings
                .push("GICR range built from the GICC structures");
        }
        Ok(())
    }

    /// A GICD of version 0 takes its version from the hardware: `read(address)`
    /// reads the 32-bit register at the physical address, `GICD_PIDR2` at
    /// the distributor + 0xFFE8, whose bits [7:4] are ArchRev.
    pub fn resolve_gic_version(&mut self, read: impl FnOnce(u64) -> u32) -> Result<(), Error> {
        let Some(g) = self.gic.as_mut().filter(|g| g.version == 0) else {
            return Ok(());
        };
        g.version = ((read(g.distributor + 0xFFE8) >> 4) & 0xF) as u8;
        self.finish_gic()
    }

    /// FADT `ARM_BOOT_ARCH` at byte 129 (ACPI 6.5, "ARM Architecture Boot
    /// Flags"): bit 0 PSCI_COMPLIANT, bit 1 PSCI_USE_HVC.
    fn read_fadt(&mut self, t: &Table<'_>) -> Result<(), Error> {
        let flags = u16_at(t.data, 129).ok_or(Error::Truncated("FADT"))?;
        if flags & 1 != 0 {
            self.psci_hvc = Some(flags & 2 != 0);
        }
        Ok(())
    }

    fn read_gtdt(&mut self, t: &Table<'_>) -> Result<(), Error> {
        const ERR: Error = Error::Truncated("GTDT");
        let mut irqs = [TimerIrq { gsiv: 0, flags: 0 }; 4];
        for (i, off) in [48usize, 56, 64, 72].into_iter().enumerate() {
            irqs[i] = TimerIrq {
                gsiv: u32_at(t.data, off).ok_or(ERR)?,
                flags: u32_at(t.data, off + 4).ok_or(ERR)?,
            };
        }
        self.timer = Some(Timer { irqs });
        Ok(())
    }

    /// SPCR (Microsoft, "Serial Port Console Redirection Table"): the type
    /// is a DBG2 port subtype: 0, 1, 0x12 are 16550, 3, 0xD, 0xE are PL011 or
    /// SBSA, which the PL011 driver runs.
    fn read_spcr(&mut self, t: &Table<'_>) -> Result<(), Error> {
        const ERR: Error = Error::Truncated("SPCR");
        let d = t.data;
        let kind = match *d.get(36).ok_or(ERR)? {
            3 | 0xD | 0xE => UartKind::Pl011,
            0 | 1 | 0x12 => UartKind::Ns16550,
            _ => {
                self.warnings
                    .push("SPCR: a port type the kernel has no driver for");
                return Ok(());
            }
        };
        if *d.get(40).ok_or(ERR)? != 0 {
            self.warnings.push("SPCR: the port is not in memory space");
            return Ok(());
        }
        let gsiv = (*d.get(52).ok_or(ERR)? & 8 != 0)
            .then(|| u32_at(d, 54).ok_or(ERR))
            .transpose()?;
        let interface_type = d[36];
        let uart = Uart {
            kind,
            interface_type,
            base: u64_at(d, 44).ok_or(ERR)?,
            bit_width: *d.get(41).ok_or(ERR)?,
            access_size: *d.get(43).ok_or(ERR)?,
            gsiv,
            baud_code: *d.get(58).ok_or(ERR)?,
            clock_hz: if t.revision >= 3 {
                u32_at(d, 76).unwrap_or(0)
            } else {
                0
            },
        };
        // A 16550 with contradictory access fields is refused here, before
        // the exit, where the message can still be read.
        uart.regs()?;
        self.uart = Some(uart);
        Ok(())
    }

    /// MCFG (PCI Firmware Specification, "MCFG Table"): 16-byte allocations
    /// from byte 44.
    fn read_mcfg(&mut self, t: &Table<'_>) -> Result<(), Error> {
        const ERR: Error = Error::Truncated("MCFG");
        let body = t.data.get(44..).ok_or(ERR)?;
        for a in body.as_chunks::<16>().0 {
            let seg = u16_at(a, 8).ok_or(ERR)?;
            self.ecam.push(Ecam {
                base: u64_at(a, 0).ok_or(ERR)?,
                segment: seg,
                first_bus: a[10],
                last_bus: a[11],
            });
        }
        Ok(())
    }

    /// IORT (Arm DEN 0049, "IO Remapping Table"): every Root Complex node's
    /// mappings, followed through an SMMU node to an ITS group.
    fn read_iort(&mut self, t: &Table<'_>) -> Result<(), Error> {
        const ERR: Error = Error::Truncated("IORT node");
        let d = t.data;
        let count = u32_at(d, 36).ok_or(ERR)? as usize;
        let mut off = u32_at(d, 40).ok_or(ERR)? as usize;
        let node = |off: usize| -> Result<&[u8], Error> {
            let len = u16_at(d, off + 1).ok_or(ERR)? as usize;
            d.get(off..off + len).filter(|_| len >= 16).ok_or(ERR)
        };
        let mappings = |n: &[u8]| -> Result<Vec<[u32; 5]>, Error> {
            let cnt = u32_at(n, 8).ok_or(ERR)? as usize;
            let at = u32_at(n, 12).ok_or(ERR)? as usize;
            let mut v = Vec::new();
            for i in 0..cnt {
                let m = n.get(at + 20 * i..at + 20 * i + 20).ok_or(ERR)?;
                v.push([
                    u32_at(m, 0).ok_or(ERR)?,
                    u32_at(m, 4).ok_or(ERR)?,
                    u32_at(m, 8).ok_or(ERR)?,
                    u32_at(m, 12).ok_or(ERR)?,
                    u32_at(m, 16).ok_or(ERR)?,
                ]);
            }
            Ok(v)
        };
        // The ITS the group at node offset `at` names: its first identifier.
        let its_of = |at: usize| -> Result<Option<u32>, Error> {
            let n = node(at)?;
            if n[0] != 0 || u32_at(n, 16).ok_or(ERR)? == 0 {
                return Ok(None);
            }
            Ok(Some(u32_at(n, 20).ok_or(ERR)?))
        };
        for _ in 0..count {
            let n = node(off)?;
            off += n.len();
            if n[0] != 2 {
                continue;
            }
            let segment = u32_at(n, 28).ok_or(ERR)?;
            for [input, ids, output, target, flags] in mappings(n)? {
                if flags & 1 != 0 {
                    return Err(Error::Unsupported("IORT: single mapping of a root complex"));
                }
                #[cfg(feature = "break-iort-count")]
                let count = ids;
                // The count in the table is the number of IDs minus one
                // (DEN 0049, "Number of IDs"; Linux `iort_id_map`).
                #[cfg(not(feature = "break-iort-count"))]
                let count = ids
                    .checked_add(1)
                    .ok_or(Error::Unsupported("IORT: ID count"))?;
                let target = target as usize;
                match node(target)?[0] {
                    0 => {
                        if let Some(its_id) = its_of(target)? {
                            self.push_msi(MsiRange {
                                segment,
                                rid_base: input,
                                its_id,
                                device_base: output,
                                count,
                            });
                        }
                    }
                    // SMMUv3 (4) and SMMUv1/2 (3): StreamID to DeviceID by the
                    // SMMU's own mappings; the kernel drives no SMMU, so the
                    // chain folds into one RID to DeviceID range.
                    3 | 4 => {
                        self.warnings
                            .push("IORT: root complex behind an SMMU (folded, no SMMU driver)");
                        for [s_in, s_ids, s_out, s_target, s_flags] in mappings(node(target)?)? {
                            if s_flags & 1 != 0 {
                                continue;
                            }
                            let s_count = s_ids.saturating_add(1);
                            let lo = output.max(s_in);
                            let hi = output
                                .saturating_add(count)
                                .min(s_in.saturating_add(s_count));
                            if hi <= lo {
                                continue;
                            }
                            if let Some(its_id) = its_of(s_target as usize)? {
                                self.push_msi(MsiRange {
                                    segment,
                                    rid_base: input + (lo - output),
                                    its_id,
                                    device_base: s_out + (lo - s_in),
                                    count: hi - lo,
                                });
                            }
                        }
                    }
                    _ => self
                        .warnings
                        .push("IORT: root complex mapping to an unknown node"),
                }
            }
        }
        Ok(())
    }

    /// Neighbours with continuous input and output join into one entry.
    fn push_msi(&mut self, m: MsiRange) {
        if let Some(last) = self.msi.last_mut()
            && last.segment == m.segment
            && last.its_id == m.its_id
            && last.rid_base + last.count == m.rid_base
            && last.device_base + last.count == m.device_base
        {
            last.count += m.count;
            return;
        }
        self.msi.push(m);
    }
}
