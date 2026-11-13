// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The UEFI application that boots stafeto (stafeto-design tasks/2026-11-12-aws-efi-loader.md). The firmware runs
//! it as `\EFI\BOOT\BOOTAA64.EFI` from the ESP. It reads `\stafeto\Image` and
//! `\stafeto\boot.img` from the same volume, builds the device tree from the
//! ACPI tables and the EFI memory map (`firmware-tree`), checks the tree with
//! the kernel's own code, leaves the boot services and enters `head.S` the
//! way U-Boot's `booti` does: x0 = the tree, the MMU and the data cache off.
//! Every refusal is printed to the firmware's console, or to the port of the
//! SPCR after the exit: the kernel's panic before it reads the tree is not
//! visible on EC2 (spec 3.2).

#![no_std]
#![no_main]

extern crate alloc;

mod arena;
mod cpu;
mod port;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use firmware_tree::acpi::{self, Tables};
use firmware_tree::check::{self, Placement};
use firmware_tree::efimap::{self, Classified, Desc};
use firmware_tree::platform::Platform;
use firmware_tree::tree;
use kcore::bootinfo::{MPIDR_AFFINITY, Region};
use uefi::boot::{self, AllocateType, MemoryType};
use uefi::prelude::*;
use uefi::proto::media::file::{
    Directory, File, FileAttribute, FileInfo, FileMode, FileType, RegularFile,
};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::{CStr16, Status, cstr16};

#[global_allocator]
static HEAP: arena::Bump = arena::Bump::new();

const PAGE: u64 = 4096;
const KERNEL_PATH: &CStr16 = cstr16!("stafeto\\Image");
const BOOT_IMAGE_PATH: &CStr16 = cstr16!("stafeto\\boot.img");
/// The boot page tables map the GiBs 1..511 (the note, 2.1 item 6).
const BELOW_512_GIB: u64 = 512 << 30;

static EXITED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// The line a refusal ends with, fixed so that `get-console-output` and the
/// instance's state can be searched for it.
const FAILED_MARKER: &str = "STAFETO-EFI-LOADER-FAILED";

/// 0 no PSCI, 1 over HVC, 2 over SMC (the FADT's).
static CONDUIT: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Ends a failed run: PSCI `SYSTEM_OFF` when the FADT names a conduit, so
/// that the instance stops and says so, otherwise a wait for events.
fn halt() -> ! {
    use core::sync::atomic::Ordering::Relaxed;
    const SYSTEM_OFF: u64 = 0x8400_0008;
    // SAFETY: PSCI SYSTEM_OFF does not return; x0 is the function id.
    unsafe {
        match CONDUIT.load(Relaxed) {
            1 => core::arch::asm!("hvc #0", in("x0") SYSTEM_OFF, options(nostack)),
            2 => core::arch::asm!("smc #0", in("x0") SYSTEM_OFF, options(nostack)),
            _ => {}
        }
    }
    loop {
        // SAFETY: waits for an event.
        unsafe { core::arch::asm!("wfe") };
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    let mut text = String::new();
    let _ = writeln!(text, "efi-loader: panic: {info}");
    say(&text);
    say(&format!("{FAILED_MARKER}\n"));
    halt()
}

/// A line to the firmware's console, or to the port after the exit.
fn say(text: &str) {
    if EXITED.load(core::sync::atomic::Ordering::Relaxed) {
        port::puts(text);
    } else {
        uefi::print!("{}", text.replace('\n', "\r\n"));
    }
}

/// A refusal: said with the fixed marker, then the machine is powered off
/// (the console keeps the text) or, with no PSCI, waits.
fn refuse(why: &dyn core::fmt::Display) -> ! {
    say(&format!("efi-loader: refused: {why}\n"));
    say(&format!("{FAILED_MARKER}\n"));
    if !EXITED.load(core::sync::atomic::Ordering::Relaxed) {
        boot::stall(core::time::Duration::from_secs(5));
    }
    halt()
}

macro_rules! ensure {
    ($cond:expr, $($why:tt)*) => {
        if !$cond {
            refuse(&format!($($why)*));
        }
    };
}

fn up(x: u64) -> u64 {
    x.div_ceil(PAGE) * PAGE
}

// ---- the files of the ESP ------------------------------------------------

/// The root of the volume the loader came from. The protocols are opened
/// without the exclusive attribute: an exclusive open of the file system
/// stops the partition driver under it, and the first read then fails with
/// MEDIA_CHANGED.
fn open_volume() -> Directory {
    use uefi::boot::{OpenProtocolAttributes, OpenProtocolParams};
    use uefi::proto::loaded_image::LoadedImage;
    let me = boot::image_handle();
    let params = |handle| OpenProtocolParams {
        handle,
        agent: me,
        controller: None,
    };
    // SAFETY: the loader's own image handle and the device it was loaded from;
    // both protocols stay open until the exit.
    let image = unsafe {
        boot::open_protocol::<LoadedImage>(params(me), OpenProtocolAttributes::GetProtocol)
    }
    .unwrap_or_else(|e| refuse(&format!("no loaded-image protocol: {e}")));
    let device = image
        .device()
        .unwrap_or_else(|| refuse(&"the loader's image has no device"));
    // SAFETY: as above.
    let mut fs = unsafe {
        boot::open_protocol::<SimpleFileSystem>(params(device), OpenProtocolAttributes::GetProtocol)
    }
    .unwrap_or_else(|e| refuse(&format!("no file system on the loader's volume: {e}")));
    let root = fs
        .open_volume()
        .unwrap_or_else(|e| refuse(&format!("cannot open the volume: {e}")));
    core::mem::forget(fs);
    core::mem::forget(image);
    root
}

fn open_file(root: &mut Directory, path: &CStr16) -> RegularFile {
    let handle = root
        .open(path, FileMode::Read, FileAttribute::empty())
        .unwrap_or_else(|e| refuse(&format!("cannot open {path}: {e}")));
    match handle.into_type() {
        Ok(FileType::Regular(f)) => f,
        _ => refuse(&format!("{path} is not a file")),
    }
}

fn file_size(file: &mut RegularFile) -> u64 {
    let mut buf = [0u8; 512];
    let info = file
        .get_info::<FileInfo>(&mut buf)
        .unwrap_or_else(|_| refuse(&"cannot read the size of a file"));
    info.file_size()
}

/// Reads the whole file into `dest`, which is at least its size.
fn read_all(file: &mut RegularFile, dest: &mut [u8], name: &CStr16) {
    let mut done = 0;
    while done < dest.len() {
        match file.read(&mut dest[done..]) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(e) => refuse(&format!("cannot read {name}: {e}")),
        }
    }
    ensure!(done == dest.len(), "{name} is shorter than its size");
}

// ---- the memory map ---------------------------------------------------------

/// One snapshot of the map: the descriptors, and the key.
struct Map {
    descs: Vec<Desc>,
}

fn boot_services() -> *mut uefi_raw::table::boot::BootServices {
    let st = uefi::table::system_table_raw().expect("system table");
    // SAFETY: the system table is valid for the loader's whole run.
    unsafe { (*st.as_ptr()).boot_services }.cast()
}

/// A raw `GetMemoryMap` into `buf`: the key, the descriptor stride and the
/// bytes used; Err carries the status and, for BUFFER_TOO_SMALL, the size.
fn raw_map(buf: &mut [u8]) -> Result<(usize, usize, usize), (Status, usize)> {
    let mut size = buf.len();
    let (mut key, mut stride, mut version) = (0usize, 0usize, 0u32);
    let bs = boot_services();
    // SAFETY: the buffer is valid for `size` bytes; the service is the firmware's.
    let status = unsafe {
        ((*bs).get_memory_map)(
            &mut size,
            buf.as_mut_ptr().cast(),
            &mut key,
            &mut stride,
            &mut version,
        )
    };
    if status == Status::SUCCESS {
        Ok((key, stride, size))
    } else {
        Err((status, size))
    }
}

fn parse_map(buf: &[u8], stride: usize, used: usize) -> Vec<Desc> {
    let u64_at = |o: usize| u64::from_le_bytes(buf[o..o + 8].try_into().unwrap());
    (0..used / stride)
        .map(|i| {
            let o = i * stride;
            Desc {
                ty: u32::from_le_bytes(buf[o..o + 4].try_into().unwrap()),
                phys: u64_at(o + 8),
                pages: u64_at(o + 24),
                attr: u64_at(o + 32),
            }
        })
        .collect()
}

/// Pages that outlive the loader's heap: the buffer of the memory map (the
/// first call's size and room for 16 more descriptors, the note, 4.4).
fn pages(count: usize) -> &'static mut [u8] {
    let p = boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, count)
        .unwrap_or_else(|e| refuse(&format!("out of memory: {e}")));
    // SAFETY: freshly allocated pages, ours for good.
    unsafe { core::slice::from_raw_parts_mut(p.as_ptr(), count * PAGE as usize) }
}

fn snapshot(buf: &mut [u8]) -> Map {
    let (_, stride, used) =
        raw_map(buf).unwrap_or_else(|(s, _)| refuse(&format!("GetMemoryMap: {s:?}")));
    Map {
        descs: parse_map(buf, stride, used),
    }
}

// ---- the tables -----------------------------------------------------------

struct Acpi {
    platform: Platform,
    /// The tables that passed their checks, by signature.
    tables: Vec<([u8; 4], &'static [u8])>,
    rejected: Vec<([u8; 4], firmware_tree::Error)>,
}

fn read_acpi() -> Acpi {
    let rsdp_at = uefi::system::with_config_table(|tables| {
        tables
            .iter()
            .find(|t| t.guid == uefi::table::cfg::ConfigTableEntry::ACPI2_GUID)
            .map(|t| t.address as u64)
    })
    .unwrap_or_else(|| refuse(&"no ACPI 2.0 table in the EFI configuration table"));
    // SAFETY: the firmware's tables, in memory that stays mapped until the exit.
    let at = |addr: u64, len: usize| -> Option<&'static [u8]> {
        (addr != 0).then(|| unsafe { core::slice::from_raw_parts(addr as *const u8, len) })
    };
    let rsdp = at(rsdp_at, 36).unwrap_or_else(|| refuse(&"no RSDP"));
    let xsdt_at = acpi::xsdt_address(rsdp).unwrap_or_else(|e| refuse(&e));
    let header = at(xsdt_at, acpi::HEADER_SIZE).unwrap_or_else(|| refuse(&"no XSDT"));
    let xsdt_len = acpi::u32_at(header, 4).unwrap_or(0) as usize;
    ensure!(
        (acpi::HEADER_SIZE..=acpi::MAX_TABLE).contains(&xsdt_len),
        "the XSDT's length is {xsdt_len}"
    );
    let xsdt = at(xsdt_at, xsdt_len).unwrap_or_else(|| refuse(&"no XSDT"));
    let tables = Tables::read(xsdt, at).unwrap_or_else(|e| refuse(&e));
    let platform = Platform::from_tables(&tables).unwrap_or_else(|e| refuse(&e));
    let kept = tables
        .tables
        .iter()
        .map(|t| (t.signature, t.data))
        .collect();
    Acpi {
        platform,
        tables: kept,
        rejected: tables.rejected.clone(),
    }
}

// ---- the summary --------------------------------------------------------------

fn summary_cpu() {
    let el = cpu::current_el();
    say(&format!(
        "efi-loader: CurrentEL={el} MPIDR_EL1={:#x} SCTLR={:#x} CNTFRQ_EL0={} ID_AA64MMFR0_EL1={:#x}\n",
        cpu::mpidr(),
        cpu::sctlr(),
        cpu::cntfrq(),
        cpu::id_aa64mmfr0()
    ));
    ensure!(
        cpu::mpidr() & 0xff == 0,
        "the boot CPU's Aff0 is not 0: head.S parks every CPU with Aff0 other than 0"
    );
    if el == 2 {
        let hcr = cpu::hcr_el2();
        say(&format!("efi-loader: HCR_EL2={hcr:#x}\n"));
        ensure!(
            hcr & (1 << 34) == 0,
            "HCR_EL2.E2H is set: the kernel's EL2 drop assumes a firmware without VHE"
        );
    }
}

// ---- the dump of the tables (feature `dump`) ----------------------------------

fn dump(root: &mut Directory, tables: &[([u8; 4], &[u8])], map: &[Desc]) -> ! {
    use uefi::proto::media::file::FileAttribute as A;
    let mut dir = match root
        .open(
            cstr16!("stafeto\\dump"),
            FileMode::CreateReadWrite,
            A::DIRECTORY,
        )
        .ok()
        .and_then(|h| h.into_directory())
    {
        Some(d) => d,
        None => refuse(&"cannot create \\stafeto\\dump (is the disk read-only?)"),
    };
    let mut write = |name: &str, bytes: &[u8]| {
        let mut buf16 = [0u16; 32];
        let name16 = CStr16::from_str_with_buf(name, &mut buf16).expect("name");
        // A file of an earlier dump goes first: a write does not shorten it.
        if let Ok(old) = dir.open(name16, FileMode::ReadWrite, A::empty()) {
            let _ = old.delete();
        }
        let handle = dir
            .open(name16, FileMode::CreateReadWrite, A::empty())
            .unwrap_or_else(|e| refuse(&format!("cannot create {name}: {e}")));
        let Some(mut f) = handle.into_regular_file() else {
            refuse(&"not a file")
        };
        f.write(bytes)
            .unwrap_or_else(|_| refuse(&format!("cannot write {name}")));
        f.flush().ok();
    };
    for (i, (sig, data)) in tables.iter().enumerate() {
        let sig = core::str::from_utf8(sig).unwrap_or("____");
        write(&format!("{i:02}-{sig}.bin"), data);
    }
    // The map as 32-byte records: type, phys, pages, attr (little endian).
    let mut raw = Vec::new();
    for d in map {
        raw.extend(u64::from(d.ty).to_le_bytes());
        raw.extend(d.phys.to_le_bytes());
        raw.extend(d.pages.to_le_bytes());
        raw.extend(d.attr.to_le_bytes());
    }
    write("memmap.bin", &raw);
    let mut guids = String::new();
    uefi::system::with_config_table(|t| {
        for e in t {
            let _ = writeln!(guids, "{}", e.guid);
        }
    });
    write("cfgtab.txt", guids.as_bytes());
    say("efi-loader: dump written, stopping\n");
    loop {
        // SAFETY: waits for an event.
        unsafe { core::arch::asm!("wfe") };
    }
}

// ---- the main path ----------------------------------------------------------------

struct Loaded {
    kernel: Region,
    tree: Region,
    image: Region,
}

fn write_tree(blob: &[u8], at: Region) {
    ensure!(
        blob.len() as u64 <= efimap::TREE_ROOM,
        "the tree is {} bytes, over its room",
        blob.len()
    );
    // SAFETY: the tree's room, allocated for it and ours.
    let dest =
        unsafe { core::slice::from_raw_parts_mut(at.base as *mut u8, efimap::TREE_ROOM as usize) };
    dest[..blob.len()].copy_from_slice(blob);
    dest[blob.len()..].fill(0);
}

/// The tree for `map`, checked as the kernel will read it.
fn make_tree(
    platform: &Platform,
    map: &[Desc],
    loaded: &Loaded,
    boot_mpidr: u64,
) -> (Vec<u8>, Classified, check::Summary) {
    let protect = [
        Region {
            base: loaded.kernel.base,
            size: loaded.kernel.size + efimap::TREE_ROOM,
        },
        loaded.tree,
        loaded.image,
    ];
    let classified = efimap::classify(map, &protect).unwrap_or_else(|e| refuse(&e));
    let blob = tree::build(&tree::Input {
        platform,
        memory: &classified,
        initrd: loaded.image,
        boot_mpidr,
    })
    .unwrap_or_else(|e| refuse(&e));
    let at = Placement {
        kernel: loaded.kernel,
        tree: Region {
            base: loaded.tree.base,
            size: blob.len() as u64,
        },
        boot_image: loaded.image,
    };
    let (summary, _) = check::check(&blob, &at).unwrap_or_else(|e| refuse(&e));
    (blob, classified, summary)
}

fn report(platform: &Platform, classified: &Classified, s: &check::Summary, tree_bytes: usize) {
    let st = &classified.stats;
    say(&format!(
        "efi-loader: map {} descriptors; memory {} -> {}, reserved {} -> {}, lost {} bytes\n",
        st.descriptors, st.memory_before, st.memory, st.reserved_before, st.reserved, st.lost_bytes
    ));
    say(&format!(
        "efi-loader: tree {tree_bytes} bytes; cpus {}, no-map {}, usable pieces {}, msi-map {}\n",
        s.cpus, s.no_map, s.usable, s.msi_entries
    ));
    for w in &platform.warnings {
        say(&format!("efi-loader: warning: {w}\n"));
    }
}

/// What the tables said, for the first boot on a machine nobody can look at:
/// the console, the interrupt controller, PSCI.
fn describe(p: &Platform) {
    match &p.uart {
        Some(u) => say(&format!(
            "efi-loader: SPCR type {:#x} space 0 bit width {} access size {} address {:#x}, {}\n",
            u.interface_type,
            u.bit_width,
            u.access_size,
            u.base,
            match u.kind {
                firmware_tree::platform::UartKind::Pl011 => String::from("PL011"),
                firmware_tree::platform::UartKind::Ns16550 => {
                    let (shift, width) = u.regs().unwrap_or((0, 0));
                    format!("16550 shift {shift} width {width}")
                }
            }
        )),
        None => say("efi-loader: no SPCR console\n"),
    }
    if let Some(g) = &p.gic {
        say(&format!(
            "efi-loader: GICD {:#x} version {}; GICR ranges {:x?}\n",
            g.distributor, g.version, g.redistributors
        ));
    }
    for its in &p.its {
        say(&format!(
            "efi-loader: ITS id {} at {:#x}\n",
            its.id, its.base
        ));
    }
    say(&format!(
        "efi-loader: PSCI {}\n",
        match p.psci_hvc {
            Some(true) => "HVC",
            Some(false) => "SMC",
            None => "absent",
        }
    ));
}

#[entry]
fn main() -> Status {
    say("efi-loader: stafeto EFI loader\n");
    summary_cpu();
    let boot_mpidr = cpu::mpidr() & MPIDR_AFFINITY;

    let mut root = open_volume();
    let mut kernel_file = open_file(&mut root, KERNEL_PATH);
    let mut image_file = open_file(&mut root, BOOT_IMAGE_PATH);
    let kernel_len = file_size(&mut kernel_file);
    let image_len = file_size(&mut image_file);
    ensure!(kernel_len >= 64, "Image is {kernel_len} bytes");
    ensure!(
        image_len > 0 && image_len.is_multiple_of(PAGE),
        "boot.img is {image_len} bytes: not whole pages"
    );

    let Acpi {
        mut platform,
        tables,
        rejected,
    } = read_acpi();
    CONDUIT.store(
        match platform.psci_hvc {
            Some(true) => 1,
            Some(false) => 2,
            None => 0,
        },
        core::sync::atomic::Ordering::Relaxed,
    );
    // A GICD of version 0 takes its version from GICD_PIDR2 (ACPI 6.5).
    platform
        .resolve_gic_version(|address| {
            // SAFETY: the distributor's register block, which the firmware maps.
            unsafe { port::read32(address) }
        })
        .unwrap_or_else(|e| refuse(&e));
    describe(&platform);
    for (sig, e) in &rejected {
        say(&format!(
            "efi-loader: warning: table {}: {e}\n",
            core::str::from_utf8(sig).unwrap_or("????")
        ));
    }
    if let Some(u) = &platform.uart {
        port::remember(u);
    }

    // The buffers first, then the map that finds the slot: an allocation
    // after the map could take the slot's pages.
    let buf = pages(16);
    let kernel_buf = pages(kernel_len.div_ceil(PAGE) as usize);
    read_all(
        &mut kernel_file,
        &mut kernel_buf[..kernel_len as usize],
        KERNEL_PATH,
    );
    let image_size =
        check::image_size(&kernel_buf[..kernel_len as usize]).unwrap_or_else(|e| refuse(&e));
    let first = snapshot(buf);
    if cfg!(feature = "dump") {
        dump(&mut root, &tables, &first.descs);
    }
    let slot_len = up(image_size) + efimap::TREE_ROOM;
    let slot = efimap::find_slot(&first.descs, slot_len).unwrap_or_else(|| {
        refuse(&"no 2 MiB aligned free memory for the kernel inside one GiB of 1..511")
    });
    boot::allocate_pages(
        AllocateType::Address(slot),
        MemoryType::LOADER_DATA,
        (slot_len / PAGE) as usize,
    )
    .unwrap_or_else(|e| refuse(&format!("cannot take {slot:#x} for the kernel: {e}")));
    // SAFETY: the slot was just allocated for the kernel and the tree.
    let place = unsafe { core::slice::from_raw_parts_mut(slot as *mut u8, slot_len as usize) };
    place[..kernel_len as usize].copy_from_slice(&kernel_buf[..kernel_len as usize]);
    place[kernel_len as usize..].fill(0);

    // The tree's address: after the image in the slot (the break puts it across a GiB boundary).
    let tree_base = efimap::tree_base(slot, image_size);
    if tree_base < slot || tree_base >= slot + slot_len {
        boot::allocate_pages(
            AllocateType::Address(tree_base & !(PAGE - 1)),
            MemoryType::LOADER_DATA,
            (efimap::TREE_ROOM / PAGE) as usize,
        )
        .unwrap_or_else(|e| refuse(&format!("cannot take {tree_base:#x} for the tree: {e}")));
    }

    // The boot image.
    let image_ptr = boot::allocate_pages(
        AllocateType::MaxAddress(BELOW_512_GIB - PAGE),
        MemoryType::LOADER_DATA,
        (image_len / PAGE) as usize,
    )
    .unwrap_or_else(|e| refuse(&format!("cannot take memory for boot.img: {e}")));
    // SAFETY: the pages were just allocated for the image.
    let image_buf =
        unsafe { core::slice::from_raw_parts_mut(image_ptr.as_ptr(), image_len as usize) };
    read_all(&mut image_file, image_buf, BOOT_IMAGE_PATH);

    let loaded = Loaded {
        kernel: Region {
            base: slot,
            size: image_size,
        },
        tree: Region {
            base: tree_base,
            size: efimap::TREE_ROOM,
        },
        image: Region {
            base: image_ptr.as_ptr() as u64,
            size: image_len,
        },
    };
    say(&format!(
        "efi-loader: kernel {:#x}+{:#x}, tree {:#x}, boot image {:#x}+{:#x}\n",
        loaded.kernel.base,
        loaded.kernel.size,
        loaded.tree.base,
        loaded.image.base,
        loaded.image.size
    ));

    // The trial tree from the map as it is now, with the boot services alive.
    let trial = snapshot(buf);
    let (blob, classified, summary) = make_tree(&platform, &trial.descs, &loaded, boot_mpidr);
    report(&platform, &classified, &summary, blob.len());
    write_tree(&blob, loaded.tree);

    // The exit, with the 64 KiB buffer allocated for the map (a few hundred
    // descriptors fit; the call reports BUFFER_TOO_SMALL otherwise).
    say("efi-loader: leaving the boot services\n");
    let (final_map, tries) = exit_boot_services(buf);
    EXITED.store(true, core::sync::atomic::Ordering::Relaxed);
    // The first line through the port: if the console is silent from here on,
    // this is the one that shows the exit worked.
    say(&format!(
        "efi-loader: boot services left after {tries} attempt(s)\n"
    ));
    let (blob, _, _) = make_tree(&platform, &final_map, &loaded, boot_mpidr);
    write_tree(&blob, loaded.tree);
    // The part of the kernel's own check that the tree's size decides was
    // done with this blob: the tree region is now the final one.

    // The hand-over (the note, 2.2 items 3 to 5).
    // SAFETY: the ranges are the loader's own allocations, and boot services are gone.
    unsafe {
        say(&format!(
            "efi-loader: entering kernel at {:#x}, tree {:#x}\n",
            loaded.kernel.base, loaded.tree.base
        ));
        if !cfg!(feature = "break-clean") {
            cpu::clean_range(loaded.kernel.base, loaded.kernel.size + efimap::TREE_ROOM);
            cpu::clean_range(loaded.tree.base, efimap::TREE_ROOM);
            cpu::clean_range(loaded.image.base, loaded.image.size);
            let (t, len) = cpu::trampoline();
            cpu::clean_range(t, len);
        }
        say("efi-loader: jumping\n");
        #[cfg(feature = "early-marks")]
        let mark_port = port::mark_base();
        #[cfg(feature = "early-marks")]
        say(&format!("efi-loader: stage marks to {mark_port:#x}\n"));
        #[cfg(not(feature = "early-marks"))]
        let mark_port = 0;
        cpu::enter_kernel(loaded.kernel.base, loaded.tree.base, mark_port)
    }
}

/// `GetMemoryMap` and `ExitBootServices` into `buf`, again on a stale key
/// (UEFI 2.10, "EFI_BOOT_SERVICES.ExitBootServices()"), at most 4 times: the
/// wrapper of the `uefi` crate retries once and resets the machine on a
/// second failure, which hides the cause. Returns the final map and the
/// attempts. After the first call only memory services are allowed, so a
/// failure is said through the port of the SPCR.
fn exit_boot_services(buf: &mut [u8]) -> (Vec<Desc>, u32) {
    let handle = boot::image_handle();
    let max_tries = if cfg!(feature = "break-ebs-retry") {
        1
    } else {
        4
    };
    for attempt in 1..=max_tries {
        let (key, stride, used) = match raw_map(buf) {
            Ok(m) => m,
            Err((s, need)) => {
                EXITED.store(true, core::sync::atomic::Ordering::Relaxed);
                refuse(&format!(
                    "GetMemoryMap before the exit: {s:?}, needs {need} bytes, has {}",
                    buf.len()
                ))
            }
        };
        // A page taken between the map and the exit makes the key stale.
        if cfg!(feature = "stale-key") && attempt == 1 {
            let _ = boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1);
        }
        let bs = boot_services();
        // SAFETY: the loader holds no reference to boot-services data that it uses afterwards.
        let status = unsafe { ((*bs).exit_boot_services)(handle.as_ptr(), key) };
        if status == Status::SUCCESS {
            return (parse_map(buf, stride, used), attempt);
        }
        EXITED.store(true, core::sync::atomic::Ordering::Relaxed);
        if status != Status::INVALID_PARAMETER {
            refuse(&format!("ExitBootServices: {status:?}"));
        }
        if attempt == max_tries {
            refuse(&format!(
                "ExitBootServices: stale memory map key after {attempt} attempts"
            ));
        }
    }
    unreachable!()
}
