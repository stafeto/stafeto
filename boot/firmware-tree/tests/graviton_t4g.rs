// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The tables and the memory map of a t4g.small (`cargo xtask aws dump`), read
//! by the loader's code: what the firmware of EC2 says, as facts the next
//! parts rely on. The numbers in the asserts are the ones the first boot on
//! EC2 printed (the loader's summary) and the ones Amazon Linux read from the
//! same tables.

use firmware_tree::acpi::{Table, Tables};
use firmware_tree::check::{Placement, check};
use firmware_tree::efimap::{Desc, classify};
use firmware_tree::platform::{Platform, UartKind};
use firmware_tree::tree::{Input, build};
use kcore::bootinfo::{BootInfo, Region, parse};
use kcore::fdt::Fdt;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/graviton-t4g");
const MAP: &[u8] = include_bytes!("fixtures/graviton-t4g/memmap.bin");

fn file(name: &str) -> &'static [u8] {
    Box::leak(
        std::fs::read(format!("{DIR}/{name}"))
            .unwrap()
            .into_boxed_slice(),
    )
}

fn tables() -> Tables<'static> {
    let mut names: Vec<_> = std::fs::read_dir(DIR)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".bin") && n.as_bytes()[2] == b'-')
        .collect();
    names.sort();
    Tables {
        tables: names
            .iter()
            .map(|n| {
                let data = file(n);
                Table {
                    signature: data[..4].try_into().unwrap(),
                    revision: data[8],
                    data,
                }
            })
            .collect(),
        rejected: Vec::new(),
    }
}

fn map() -> Vec<Desc> {
    let u64_at = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    MAP.as_chunks::<32>()
        .0
        .iter()
        .map(|r| Desc {
            ty: u64_at(r, 0) as u32,
            phys: u64_at(r, 8),
            pages: u64_at(r, 16),
            attr: u64_at(r, 24),
        })
        .collect()
}

const KERNEL: Region = Region {
    base: 0x4020_0000,
    size: 0x2_c000,
};
const TREE: Region = Region {
    base: 0x4022_c000,
    size: 0x1_0000,
};
const IMAGE: Region = Region {
    base: 0x4800_0000,
    size: 0x3_2000,
};

fn blob() -> Vec<u8> {
    let platform = Platform::from_tables(&tables()).unwrap();
    let memory = classify(&map(), &[KERNEL, TREE, IMAGE]).unwrap();
    build(&Input {
        platform: &platform,
        memory: &memory,
        initrd: IMAGE,
        boot_mpidr: 0,
        seed: &[],
    })
    .unwrap()
}

fn info(blob: &[u8]) -> BootInfo {
    parse(&Fdt::new(blob).unwrap()).unwrap()
}

#[test]
fn the_console_the_spcr_names_is_a_byte_16550_at_an_address_that_is_not_the_pci_bar() {
    let p = Platform::from_tables(&tables()).unwrap();
    let u = p.uart.unwrap();
    assert_eq!(u.kind, UartKind::Ns16550);
    assert_eq!((u.interface_type, u.bit_width, u.access_size), (0, 8, 1));
    assert_eq!(u.regs().unwrap(), (0, 1));
    assert_eq!((u.base, u.gsiv, u.baud_code), (0x090a_0000, Some(37), 7));
    // The same SPCR carries the PCI identity of the console (device ID at 64,
    // vendor ID at 66): vendor 1d0f, device 8250, bus 0 device 1 function 0, and Linux's ttyS0 is that
    // function at its BAR 0 (iomem.txt, pci.txt), 0x8000c000.
    let spcr = file("02-SPCR.bin");
    assert_eq!(u16::from_le_bytes(spcr[64..66].try_into().unwrap()), 0x8250);
    assert_eq!(u16::from_le_bytes(spcr[66..68].try_into().unwrap()), 0x1d0f);
    assert_eq!(&spcr[68..71], &[0, 1, 0]);
    assert_ne!(u.base, 0x8000_c000);
    let pci = std::fs::read_to_string(format!("{DIR}/pci.txt")).unwrap();
    assert!(pci.contains("0000:00:01.0 vendor=0x1d0f device=0x8250"));
    assert!(pci.contains("0x000000008000c000 0x000000008000cfff"));
}

#[test]
fn the_interrupt_controller_has_one_distributor_one_redistributor_range_and_one_its() {
    let p = Platform::from_tables(&tables()).unwrap();
    let g = p.gic.as_ref().unwrap();
    assert_eq!((g.distributor, g.version), (0x1000_0000, 3));
    assert_eq!(g.redistributors, [(0x1020_0000, 0x0fdf_0000)]);
    assert_eq!(p.its.len(), 1);
    assert_eq!((p.its[0].id, p.its[0].base), (0, 0x1008_0000));
    assert_eq!(p.psci_hvc, Some(true));
    assert_eq!(p.cpus.len(), 2);
    let i = info(&blob());
    assert_eq!(
        i.max_device_id(),
        Some(0xffff),
        "the IORT maps every RID to the ITS"
    );
}

#[test]
fn the_iort_has_no_smmu_so_the_devices_address_physical_memory() {
    let p = Platform::from_tables(&tables()).unwrap();
    assert!(!p.dma_translated);
    // The two nodes of the fixture's IORT are the ITS group (type 0) and the root complex
    // (type 2); no SMMU node (3 or 4) is there.
    let iort = file("06-IORT.bin");
    let count = u32::from_le_bytes(iort[36..40].try_into().unwrap());
    let first = u32::from_le_bytes(iort[40..44].try_into().unwrap()) as usize;
    let mut at = first;
    let mut kinds = Vec::new();
    for _ in 0..count {
        kinds.push(iort[at]);
        at += usize::from(u16::from_le_bytes(iort[at + 1..at + 3].try_into().unwrap()));
    }
    assert_eq!(kinds, [0, 2]);
}

#[test]
fn the_pci_host_is_ecam_at_0x20000000_for_buses_0_to_255() {
    let p = Platform::from_tables(&tables()).unwrap();
    assert_eq!(p.ecam.len(), 1);
    let e = &p.ecam[0];
    assert_eq!((e.base, e.first_bus, e.last_bus), (0x2000_0000, 0, 255));
}

#[test]
fn the_memory_map_has_22_descriptors_and_ram_in_two_places() {
    let m = map();
    assert_eq!(m.len(), 22);
    let ram = |d: &Desc| d.ty == 7 || d.ty == 3 || d.ty == 4 || d.ty == 1 || d.ty == 2;
    let low = m.iter().filter(|d| ram(d) && d.phys < 1 << 32).count();
    let high = m.iter().filter(|d| ram(d) && d.phys >= 1 << 32).count();
    assert_eq!((low > 0, high), (true, 1));
    // The firmware lists two MMIO pages and nothing at the SPCR address.
    let mmio: Vec<u64> = m.iter().filter(|d| d.ty == 11).map(|d| d.phys).collect();
    assert_eq!(mmio, [0x0901_0000, 0x0905_0000]);
}

#[test]
fn the_tree_passes_the_kernels_checks_as_the_loader_placed_it() {
    let b = blob();
    let (summary, _) = check(
        &b,
        &Placement {
            kernel: KERNEL,
            tree: Region {
                base: TREE.base,
                size: b.len() as u64,
            },
            boot_image: IMAGE,
        },
    )
    .unwrap();
    assert_eq!(summary.cpus, 2);
    assert_eq!(summary.msi_entries, 1);
}
