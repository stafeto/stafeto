// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The whole chain on synthetic tables: ACPI in, tree out, the kernel's
//! `parse` over the tree. The tables of QEMU's machine come in the tests
//! of the loader's fixtures; these are the shapes QEMU does not give (the
//! Graviton's 16550 console, an SMMU in the IORT, a GICR-less MADT).

use crate::acpi::Tables;
use crate::acpi::testing::{finish, firmware, resolver, table};
use crate::check::{Placement, check};
use crate::efimap::{Classified, Desc, classify};
use crate::platform::Platform;
use crate::tree::{Input, build};
use crate::{Error, efimap};
use kboot::bootinfo::{BootInfo, PsciConduit, Region, parse, pci_hosts, uart_16550};
use kboot::fdt::Fdt;

const GICD: u64 = 0x0800_0000;
const GICR: u64 = 0x080a_0000;
const ITS: u64 = 0x0808_0000;

fn gicc(mpidr: u64, flags: u32, gicr: u64) -> Vec<u8> {
    let mut r = vec![0xB, 82, 0, 0];
    r.extend(0u32.to_le_bytes());
    r.extend(mpidr.to_le_bytes()[..4].iter()); // uid
    r.extend(flags.to_le_bytes());
    r.resize(60, 0);
    r.extend(gicr.to_le_bytes());
    r.extend(mpidr.to_le_bytes());
    r.resize(82, 0);
    r
}

fn gicd(version: u8) -> Vec<u8> {
    let mut r = vec![0xC, 24, 0, 0, 0, 0, 0, 0];
    r.extend(GICD.to_le_bytes());
    r.extend([0; 4]);
    r.extend([version, 0, 0, 0]);
    r
}

fn gicr(base: u64, len: u32) -> Vec<u8> {
    let mut r = vec![0xE, 16, 0, 0];
    r.extend(base.to_le_bytes());
    r.extend(len.to_le_bytes());
    r
}

fn its(id: u32, base: u64) -> Vec<u8> {
    let mut r = vec![0xF, 20, 0, 0];
    r.extend(id.to_le_bytes());
    r.extend(base.to_le_bytes());
    r.extend([0; 4]);
    r
}

fn madt(records: &[Vec<u8>]) -> Vec<u8> {
    let mut body = vec![0u8; 8];
    for r in records {
        body.extend(r);
    }
    table(b"APIC", 5, &body)
}

fn fadt(arm_flags: u16) -> Vec<u8> {
    let mut body = vec![0u8; 140 - 36];
    body[129 - 36..131 - 36].copy_from_slice(&arm_flags.to_le_bytes());
    table(b"FACP", 6, &body)
}

fn gtdt(virtual_gsiv: u32, virtual_flags: u32) -> Vec<u8> {
    let mut body = vec![0u8; 8 + 4];
    for (gsiv, flags) in [
        (29u32, 0u32),
        (30, 0),
        (virtual_gsiv, virtual_flags),
        (26, 0),
    ] {
        body.extend(gsiv.to_le_bytes());
        body.extend(flags.to_le_bytes());
    }
    body.resize(100 - 36, 0);
    table(b"GTDT", 3, &body)
}

fn spcr(kind: u8, base: u64, width: u8, access: u8) -> Vec<u8> {
    let mut body = vec![kind, 0, 0, 0, 0, width, 0, access];
    body.extend(base.to_le_bytes());
    body.extend([0, 0]);
    body.extend(0u32.to_le_bytes());
    body.push(7);
    body.resize(88 - 36, 0);
    table(b"SPCR", 3, &body)
}

fn mcfg(base: u64, first: u8, last: u8) -> Vec<u8> {
    let mut body = vec![0u8; 8];
    body.extend(base.to_le_bytes());
    body.extend([0, 0, first, last]);
    body.extend([0; 4]);
    table(b"MCFG", 1, &body)
}

/// A node of the IORT: its type, data after the header, and mappings as
/// (input base, count - 1, output base, index of the target node, flags).
struct Node {
    kind: u8,
    data: Vec<u8>,
    maps: Vec<(u32, u32, u32, usize, u32)>,
}

fn its_group(ids: &[u32]) -> Node {
    let mut data = (ids.len() as u32).to_le_bytes().to_vec();
    for i in ids {
        data.extend(i.to_le_bytes());
    }
    Node {
        kind: 0,
        data,
        maps: vec![],
    }
}

fn root_complex(segment: u32, maps: Vec<(u32, u32, u32, usize, u32)>) -> Node {
    let mut data = vec![0u8; 16];
    data[12..16].copy_from_slice(&segment.to_le_bytes());
    data.extend([48, 0, 0, 0]);
    Node {
        kind: 2,
        data,
        maps,
    }
}

fn smmu_v3(maps: Vec<(u32, u32, u32, usize, u32)>) -> Node {
    Node {
        kind: 4,
        data: vec![0; 40],
        maps,
    }
}

fn iort(nodes: &[Node]) -> Vec<u8> {
    let mut lens = Vec::new();
    for n in nodes {
        lens.push(16 + n.data.len() + 20 * n.maps.len());
    }
    let mut offsets = Vec::new();
    let mut at = 48usize;
    for l in &lens {
        offsets.push(at);
        at += l;
    }
    let mut body = Vec::new();
    body.extend((nodes.len() as u32).to_le_bytes());
    body.extend(48u32.to_le_bytes());
    body.extend([0; 4]);
    for (n, len) in nodes.iter().zip(&lens) {
        body.push(n.kind);
        body.extend((*len as u16).to_le_bytes());
        body.push(0);
        body.extend([0; 4]);
        body.extend((n.maps.len() as u32).to_le_bytes());
        body.extend(
            if n.maps.is_empty() {
                0
            } else {
                16 + n.data.len() as u32
            }
            .to_le_bytes(),
        );
        body.extend(&n.data);
        for (i, c, o, t, f) in &n.maps {
            for v in [*i, *c, *o, offsets[*t] as u32, *f] {
                body.extend(v.to_le_bytes());
            }
        }
    }
    table(b"IORT", 0, &body)
}

/// QEMU `virt` with its=on: two CPUs, a GICv3 with one GICR range and an
/// ITS, PSCI over HVC, the PL011, one ECAM, and all RIDs straight to the ITS.
struct Machine {
    madt: Vec<Vec<u8>>,
    fadt: u16,
    gtdt: (u32, u32),
    spcr: (u8, u64, u8, u8),
    iort: Vec<Node>,
}

impl Machine {
    fn qemu() -> Self {
        Machine {
            madt: vec![
                gicc(0, 1, 0),
                gicc(1, 1, 0),
                gicd(3),
                gicr(GICR, 0x20_0000),
                its(0, ITS),
            ],
            fadt: 3,
            gtdt: (27, 0),
            spcr: (3, 0x0900_0000, 32, 3),
            iort: vec![its_group(&[0]), root_complex(0, vec![(0, 0xFFFF, 0, 0, 0)])],
        }
    }

    fn tables(&self) -> Vec<Vec<u8>> {
        let (kind, base, width, access) = self.spcr;
        vec![
            madt(&self.madt),
            fadt(self.fadt),
            gtdt(self.gtdt.0, self.gtdt.1),
            spcr(kind, base, width, access),
            mcfg(0x3f00_0000, 0, 15),
            iort(&self.iort),
        ]
    }

    fn platform(&self) -> Result<Platform, Error> {
        let (xsdt, placed) = firmware(self.tables());
        let tables = Tables::read(&xsdt, resolver(&placed)).unwrap();
        assert!(tables.rejected.is_empty());
        Platform::from_tables(&tables)
    }
}

const KERNEL: Region = Region {
    base: 0x4020_0000,
    size: 0x30_0000,
};
const TREE: Region = Region {
    base: 0x4050_0000,
    size: 0x1_0000,
};
const IMAGE: Region = Region {
    base: 0x4060_0000,
    size: 0x4_0000,
};

fn memory() -> Classified {
    classify(
        &[
            Desc {
                ty: 7,
                phys: 0x4000_0000,
                pages: 0x2000,
                attr: 0xF,
            },
            Desc {
                ty: 5,
                phys: 0x4200_0000,
                pages: 0x10,
                attr: 0xF,
            },
            Desc {
                ty: 7,
                phys: 0x4201_0000,
                pages: 0x1000,
                attr: 0xF,
            },
        ],
        &[KERNEL, TREE, IMAGE],
    )
    .unwrap()
}

fn tree_of(p: &Platform, memory: &Classified) -> Result<Vec<u8>, Error> {
    build(&Input {
        platform: p,
        memory,
        initrd: IMAGE,
        boot_mpidr: 0,
        seed: &[],
    })
}

fn placement() -> Placement {
    Placement {
        kernel: KERNEL,
        tree: TREE,
        boot_image: IMAGE,
    }
}

fn run(m: &Machine) -> Result<(Vec<u8>, BootInfo), Error> {
    let blob = tree_of(&m.platform()?, &memory())?;
    let (_, info) = check(&blob, &placement())?;
    Ok((blob, info))
}

#[test]
fn qemu_shaped_tables_give_a_tree_the_kernel_reads_as_it_reads_qemus() {
    let (blob, info) = run(&Machine::qemu()).unwrap();
    let gic = info.gic.unwrap();
    assert_eq!(gic.version, kboot::bootinfo::GicVersion::V3);
    assert_eq!(
        gic.mapped()[0],
        Region {
            base: GICD,
            size: 0x1_0000
        }
    );
    assert_eq!(gic.mapped()[1].base, GICR);
    assert_eq!(
        info.its.unwrap().regs,
        Region {
            base: ITS,
            size: 0x2_0000
        }
    );
    assert_eq!(info.psci, PsciConduit::Hvc);
    assert_eq!(info.cpus.as_slice(), [0, 1]);
    assert_eq!(
        info.uart_pl011,
        Some(Region {
            base: 0x0900_0000,
            size: 0x1000
        })
    );
    assert_eq!(info.initrd, Some(IMAGE));
    for rid in [0, 8, 0x10, 0xFF, 0xFFFF] {
        assert_eq!(info.device_id(rid), Some(rid), "rid {rid:#x}");
    }
    assert_eq!(info.device_id(0x1_0000), None);
    assert_eq!(
        info.max_device_id(),
        Some(0xFFFF),
        "the count in the IORT is one less than the number of IDs"
    );
    let fdt = Fdt::new(&blob).unwrap();
    let host = pci_hosts(&fdt).unwrap().as_slice()[0];
    assert_eq!((host.segment, host.bus_first, host.bus_last), (0, 0, 15));
    assert_eq!(
        host.ecam,
        Region {
            base: 0x3f00_0000,
            size: 16 << 20
        }
    );
    assert_eq!(uart_16550(&fdt), Ok(None));
}

#[test]
fn the_boot_cpu_goes_first_and_an_unknown_one_is_refused() {
    let p = Machine::qemu().platform().unwrap();
    let blob = build(&Input {
        platform: &p,
        memory: &memory(),
        initrd: IMAGE,
        boot_mpidr: 1,
        seed: &[],
    })
    .unwrap();
    assert_eq!(
        parse(&Fdt::new(&blob).unwrap()).unwrap().cpus.as_slice(),
        [1, 0]
    );
    let refused = build(&Input {
        platform: &p,
        memory: &memory(),
        initrd: IMAGE,
        boot_mpidr: 7,
        seed: &[],
    });
    assert!(matches!(refused, Err(Error::Unsupported(_))));
}

#[test]
fn a_disabled_gicc_is_not_a_cpu_and_psci_follows_the_fadt() {
    let mut m = Machine::qemu();
    m.madt[1] = gicc(1, 0, 0);
    m.fadt = 0;
    let (_, info) = run(&m).unwrap();
    assert_eq!(info.cpus.as_slice(), [0]);
    assert_eq!(info.psci, PsciConduit::None);
    m.fadt = 1;
    assert_eq!(run(&m).unwrap().1.psci, PsciConduit::Smc);
    m.fadt = 3;
    assert_eq!(m.platform().unwrap().psci_hvc, Some(true));
}

#[test]
fn the_gravitons_console_is_a_16550_with_byte_access_and_the_variant_with_32_bit_registers() {
    let mut m = Machine::qemu();
    m.spcr = (0, 0x7000_0000, 8, 1);
    let (blob, info) = run(&m).unwrap();
    assert_eq!(info.uart_pl011, None);
    let u = uart_16550(&Fdt::new(&blob).unwrap()).unwrap().unwrap();
    assert_eq!(
        (u.regs.base, u.regs.size, u.reg_shift, u.io_width),
        (0x7000_0000, 8, 0, 1)
    );
    m.spcr = (0x12, 0x7000_0000, 32, 3);
    let (blob, _) = run(&m).unwrap();
    let u = uart_16550(&Fdt::new(&blob).unwrap()).unwrap().unwrap();
    assert_eq!((u.regs.size, u.reg_shift, u.io_width), (32, 2, 4));
}

#[test]
fn an_smmu_between_the_root_complex_and_the_its_folds_into_one_map_with_a_warning() {
    let mut m = Machine::qemu();
    // RIDs 0..=0xFF -> SMMU StreamIDs 0x100.., which the SMMU gives to the ITS as DeviceIDs 0x2000...
    m.iort = vec![
        its_group(&[0]),
        smmu_v3(vec![(0x100, 0xFF, 0x2000, 0, 0)]),
        root_complex(0, vec![(0, 0xFF, 0x100, 1, 0)]),
    ];
    let p = m.platform().unwrap();
    assert!(p.warnings.iter().any(|w| w.contains("SMMU")));
    // The loader refuses a machine whose devices may see translated addresses.
    assert!(p.dma_translated, "fails under break-smmu-ignore");
    let (_, info) = run(&m).unwrap();
    assert_eq!(info.device_id(0), Some(0x2000));
    assert_eq!(info.device_id(0xFF), Some(0x20FF));
    assert_eq!(info.device_id(0x100), None);
}

#[test]
fn neighbouring_mappings_with_continuous_ranges_join_and_a_single_mapping_is_refused() {
    let mut m = Machine::qemu();
    m.iort = vec![
        its_group(&[0]),
        root_complex(
            0,
            vec![
                (0, 0xFF, 0, 0, 0),
                (0x100, 0xFF, 0x100, 0, 0),
                (0x400, 0xFF, 0x800, 0, 0),
            ],
        ),
    ];
    let p = m.platform().unwrap();
    assert_eq!(p.msi.len(), 2);
    assert_eq!((p.msi[0].rid_base, p.msi[0].count), (0, 0x200));
    m.iort[1] = root_complex(0, vec![(0, 0, 0, 0, 1)]);
    assert!(matches!(m.platform(), Err(Error::Unsupported(_))));
}

#[test]
fn ten_separate_mappings_are_refused_with_a_message() {
    let mut m = Machine::qemu();
    let maps = (0..10)
        .map(|i| (i * 0x100, 0xFF, i * 0x1000, 0usize, 0))
        .collect();
    m.iort = vec![its_group(&[0]), root_complex(0, maps)];
    let p = m.platform().unwrap();
    assert_eq!(p.msi.len(), 10);
    assert_eq!(
        tree_of(&p, &memory()),
        Err(Error::TooManyRegions("msi-map entries after the merge"))
    );
}

#[test]
fn without_gicr_structures_one_range_comes_from_the_giccs() {
    let mut m = Machine::qemu();
    m.madt = vec![
        gicc(0, 1, GICR),
        gicc(1, 1, GICR + 0x2_0000),
        gicd(3),
        its(0, ITS),
    ];
    let p = m.platform().unwrap();
    assert_eq!(p.gic.as_ref().unwrap().redistributors, [(GICR, 0x4_0000)]);
    assert!(!p.warnings.is_empty());
    assert_eq!(run(&m).unwrap().1.gic.unwrap().mapped()[1].base, GICR);
    // GICv4 frames are 256 KiB.
    m.madt[2] = gicd(4);
    m.madt[1] = gicc(1, 1, GICR + 0x4_0000);
    assert_eq!(
        m.platform().unwrap().gic.unwrap().redistributors,
        [(GICR, 0x8_0000)]
    );
    // Bases that are not one range, or none at all.
    m.madt[1] = gicc(1, 1, GICR + 0x9_0000);
    assert!(matches!(m.platform(), Err(Error::Unsupported(_))));
    m.madt[0] = gicc(0, 1, 0);
    assert!(matches!(m.platform(), Err(Error::Missing(_))));
}

#[test]
fn two_gicr_ranges_and_a_gic_that_is_not_v3_or_v4_are_refused() {
    let mut m = Machine::qemu();
    m.madt.push(gicr(0x0900_0000, 0x1_0000));
    assert!(matches!(m.platform(), Err(Error::Unsupported(_))));
    let mut m = Machine::qemu();
    m.madt[2] = gicd(2);
    assert!(matches!(m.platform(), Err(Error::Unsupported(_))));
}

#[test]
fn a_virtual_timer_other_than_level_27_is_refused_and_the_flags_translate() {
    let mut m = Machine::qemu();
    m.gtdt = (28, 0);
    let p = m.platform().unwrap();
    assert!(matches!(tree_of(&p, &memory()), Err(Error::Unsupported(_))));
    m.gtdt = (27, 1);
    assert!(matches!(
        tree_of(&m.platform().unwrap(), &memory()),
        Err(Error::Unsupported(_))
    ));
    m.gtdt = (27, 2);
    let blob = tree_of(&m.platform().unwrap(), &memory()).unwrap();
    // The cells of `interrupts`: <1 13 4> <1 14 4> <1 11 8> <1 10 4>, big-endian.
    let words: Vec<u32> = [1u32, 13, 4, 1, 14, 4, 1, 11, 8, 1, 10, 4].to_vec();
    let needle: Vec<u8> = words.iter().flat_map(|w| w.to_be_bytes()).collect();
    assert!(blob.windows(needle.len()).any(|w| w == needle.as_slice()));
}

#[test]
fn the_tree_check_catches_what_would_panic_the_kernel() {
    let p = Machine::qemu().platform().unwrap();
    let blob = tree_of(&p, &memory()).unwrap();
    let mut at = placement();
    assert!(check(&blob, &at).is_ok());
    // The tree in GiB 0 (devices).
    at.tree.base = 0x0800_0000;
    assert!(matches!(check(&blob, &at), Err(Error::Check(m)) if m.contains("outside")));
    // The tree across a GiB boundary.
    at.tree.base = 0x8000_0000 - 0x100;
    assert!(matches!(check(&blob, &at), Err(Error::Check(m)) if m.contains("GiB")));
    // The boot image over the tree.
    let mut at = placement();
    let blob_over = tree_of(&p, &memory()).unwrap();
    at.boot_image = Region {
        base: TREE.base + 0x1000,
        size: 0x1000,
    };
    let _ = blob_over;
    assert!(check(&blob, &at).is_err());
    // A kernel off the 2 MiB boundary.
    let mut at = placement();
    at.kernel.base += 0x1000;
    assert!(check(&blob, &at).is_err());
    // A tree that names another boot image.
    let mut at = placement();
    at.boot_image.size += 0x1000;
    assert!(check(&blob, &at).is_err());
}

#[test]
fn a_map_with_twelve_runtime_regions_passes_the_kernels_checks_only_after_the_merge() {
    let mut map = Vec::new();
    let mut at = 0x4000_0000u64;
    for _ in 0..12 {
        map.push(Desc {
            ty: 7,
            phys: at,
            pages: 0x2000,
            attr: 0xF,
        });
        at += 0x2000 * 4096;
        map.push(Desc {
            ty: 6,
            phys: at,
            pages: 4,
            attr: 0xF,
        });
        at += 4 * 4096;
    }
    let c = classify(&map, &[KERNEL, TREE, IMAGE]).unwrap();
    let p = Machine::qemu().platform().unwrap();
    let blob = tree_of(&p, &c).unwrap();
    let verdict = check(&blob, &placement());
    if cfg!(feature = "break-merge") {
        assert!(
            matches!(verdict, Err(Error::Check(m)) if m.contains("more regions")),
            "{verdict:?}"
        );
    } else {
        assert!(verdict.is_ok(), "{verdict:?}");
        assert_eq!(c.reserved.len(), efimap::NO_MAP_REGIONS);
    }
}

#[test]
fn damaged_tables_leave_the_kernel_what_it_needs_or_stop() {
    let m = Machine::qemu();
    let mut tables = m.tables();
    tables.remove(0);
    let (xsdt, placed) = firmware(tables);
    let read = Tables::read(&xsdt, resolver(&placed)).unwrap();
    assert_eq!(Platform::from_tables(&read), Err(Error::Missing("MADT")));
    let mut broken = m.tables();
    broken[0][50] ^= 0xFF;
    let (xsdt, placed) = firmware(broken);
    let read = Tables::read(&xsdt, resolver(&placed)).unwrap();
    assert_eq!(read.rejected.len(), 1);
    assert_eq!(Platform::from_tables(&read), Err(Error::Missing("MADT")));
    let _ = finish;
}

#[test]
fn more_than_one_its_warns_and_two_in_the_iort_are_refused() {
    let mut m = Machine::qemu();
    m.madt.push(its(1, 0x0810_0000));
    assert!(
        m.platform()
            .unwrap()
            .warnings
            .iter()
            .any(|w| w.contains("more than one ITS"))
    );
    m.iort = vec![
        its_group(&[0]),
        its_group(&[1]),
        root_complex(0, vec![(0, 0xFF, 0, 0, 0), (0x100, 0xFF, 0x100, 1, 0)]),
    ];
    let p = m.platform().unwrap();
    assert!(
        matches!(tree_of(&p, &memory()), Err(Error::Unsupported(w)) if w.contains("more than one ITS"))
    );
    // An ITS the MADT does not list.
    m.madt.truncate(5);
    m.iort = vec![its_group(&[7]), root_complex(0, vec![(0, 0xFF, 0, 0, 0)])];
    let p = m.platform().unwrap();
    assert!(
        matches!(tree_of(&p, &memory()), Err(Error::Unsupported(w)) if w.contains("does not list"))
    );
}

#[test]
fn a_gicd_of_version_0_takes_its_version_from_pidr2() {
    let mut m = Machine::qemu();
    m.madt[2] = gicd(0);
    m.madt[4] = its(0, ITS);
    let mut p = m.platform().unwrap();
    assert_eq!(p.gic.as_ref().unwrap().version, 0);
    let mut asked = 0;
    p.resolve_gic_version(|a| {
        asked = a;
        3 << 4
    })
    .unwrap();
    assert_eq!(asked, GICD + 0xFFE8);
    assert_eq!(p.gic.as_ref().unwrap().version, 3);
    assert!(tree_of(&p, &memory()).is_ok());
    // A hardware that reports v2 is refused; a known version is not read again.
    let mut p = m.platform().unwrap();
    assert!(p.resolve_gic_version(|_| 2 << 4).is_err());
    let mut p = Machine::qemu().platform().unwrap();
    p.resolve_gic_version(|_| unreachable!()).unwrap();
}

#[test]
fn a_16550_with_contradictory_access_fields_is_refused_when_the_tables_are_read() {
    let mut m = Machine::qemu();
    m.spcr = (0, 0x7000_0000, 8, 3);
    assert!(matches!(m.platform(), Err(Error::Unsupported(w)) if w.contains("disagree")));
    m.spcr = (0, 0x7000_0000, 8, 2);
    assert!(matches!(m.platform(), Err(Error::Unsupported(w)) if w.contains("access size")));
}

/// The seed of the loader goes to `/chosen/rng-seed` whole, and the kernel's
/// own parser finds it where the kernel will clear it; with no seed the
/// tree has none.
#[test]
fn the_seed_goes_into_the_trees_chosen_node_and_the_kernel_finds_it() {
    let p = Machine::qemu().platform().unwrap();
    let seed: Vec<u8> = (1..=64).collect();
    let blob = build(&Input {
        platform: &p,
        memory: &memory(),
        initrd: IMAGE,
        boot_mpidr: 0,
        seed: &seed,
    })
    .unwrap();
    let (_, info) = check(&blob, &placement()).unwrap();
    let found = info.seed.expect("the kernel finds no rng-seed in the tree");
    assert_eq!(found.size, 64);
    let at = found.base as usize;
    assert_eq!(&blob[at..at + 64], &seed[..]);
    // No seed, no property.
    let (_, info) = run(&Machine::qemu()).unwrap();
    assert_eq!(info.seed, None);
}
