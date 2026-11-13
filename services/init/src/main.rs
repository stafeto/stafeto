// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! init, the first program (spec 13.4), which from milestone 1.4c lives as
//! long as the system. It checks its table of services
//! (init::table::TABLE) before anything else, and refuses a table it could
//! not keep its promises with, or one whose program the boot image lacks,
//! with the line `init: table refused: <reason>` and the code 2, which the
//! kernel ends with a panic (spec 7.9). Then it maps the boot image, makes
//! its channel, starts its worker thread (worker.rs), which loads the
//! records of the table in the order of their dependencies, and serves the
//! channel from its main thread at 63 (serve.rs), where it restarts the
//! services that fail. Once the first start of each record is done, or
//! waits for quota, it prints `init: services started`.

#![no_std]
#![no_main]

mod serve;
mod worker;

use abi::{Access, Rights};
use bootimg::{BootImage, Program};
use core::cell::UnsafeCell;
use init::labels::Labels;
use init::resolve::{self, Store};
use init::table::{self, At, MAX_RECORDS, Record, TABLE};
use proto_init::{OWN_ARGS_MAX, SERVICE_ARGS_FIXED};
use rt::handle::{Memory, Process};
use rt::service::Config;
use rt::{Handle, mmio, println, sys};

rt::entry!(main);

// The arguments init gives a record fit the start data of rt (spec 13.3).
const _: () = assert!(SERVICE_ARGS_FIXED + OWN_ARGS_MAX <= rt::startup::ARGS_MAX);
// Init lives on the stack of the main thread (64 KiB, INIT_STACK_SIZE of
// xtask), twice while `Init::new` builds it: 44 KiB at most, 20 left. The
// handles of eight DMA objects of each record's instance (table::MAX_DMA,
// for the network service with two devices) made it 22 000 bytes.
const _: () = assert!(core::mem::size_of::<serve::Init>() <= 22 * 1024);

/// Where init maps the boot image, read-only, for as long as it lives: the
/// programs it loads are read from there.
const IMAGE: usize = 0x50_0000_0000;
/// The priority of the slot of label 0 of init's channel: no handle
/// without a label with SEND or NOTIFY ever leaves init.
const CHANNEL_PRIORITY: u8 = 1;
/// The sessions of init's channel: those of the instance of each record,
/// and of the one before it until its CLIENT_GONE.
const SESSIONS: usize = 2 * MAX_RECORDS;
/// Init's code for a table it refuses.
const REFUSED: u64 = 2;

fn main(_: u64) -> u64 {
    let init = rt::init_handles().expect("init's first handles come once");
    // The console gets a copy with DEBUG alone; init keeps the resource
    // for the windows, the bindings and the consoles it gives.
    if let Ok(console) = sys::handle_duplicate(&init.resource, Rights::DEBUG) {
        rt::console::set(console);
    }
    if let Err(e) = table::check(TABLE) {
        println!("init: table refused: {e}");
        return REFUSED;
    }
    if (table::PLATFORM.is_some() || resolve::needs(TABLE)) && !resolved(&init) {
        return REFUSED;
    }
    let table = table::table();
    let order = match table::check(table) {
        Ok(order) => order,
        Err(e) => {
            println!("init: table refused after the places were found: {e}");
            return REFUSED;
        }
    };
    let programs = match programs(&init.process, &init.boot_image) {
        Ok(programs) => programs,
        Err(r) => {
            println!(
                "init: table refused: {} has no program {} in the boot image",
                r.name, r.program
            );
            return REFUSED;
        }
    };
    let channel = sys::channel_create(CHANNEL_PRIORITY).expect("init makes its channel");
    let mut labels = Labels::new();
    let label = labels.next().expect("the first label");
    let worker = worker::Worker::start(
        &init.process,
        &channel,
        &init.resource,
        label,
        init.boot_image,
    )
    .expect("init starts its worker thread");
    let mut service = serve::Init::new(
        init.process,
        &channel,
        init.resource,
        worker,
        labels,
        programs,
    );
    service.start(&channel, &order);
    #[cfg(feature = "steps")]
    rt::service::report_steps(6);
    let config = Config {
        issued: 0,
        heartbeat: None,
    };
    let error = rt::service::run::<_, SESSIONS, 1>(&channel, &mut service, config);
    panic!("init stopped serving its channel: {error:?}")
}

/// Where init maps the ECAM it walks to find the functions the table names
/// (`resolve`), until the walk is done.
const ECAM_WINDOW: usize = 0x63_0000_0000;

/// The room of the resolved table, which lives as long as init.
struct Room(UnsafeCell<Store>);

// SAFETY: `resolved` hands it out once, on init's main thread, before any
// other thread of init exists.
unsafe impl Sync for Room {}

static ROOM: Room = Room(UnsafeCell::new(Store::EMPTY));

/// The words of the functions through the window over ECAM at `ECAM_WINDOW`.
struct Walk {
    ecam: pci::Ecam,
}

impl pci::Config for Walk {
    fn read(&mut self, at: pci::Address, offset: usize) -> u32 {
        let page = self.ecam.offset(at).unwrap_or(0) as usize;
        // SAFETY: `resolved` maps the bus range of the platform read and write
        // at ECAM_WINDOW as device memory; `at` lies in it (the walk is bounded
        // by that range) and `offset` is a word within the function's page.
        unsafe { mmio::read32(ECAM_WINDOW + page + offset) }
    }

    fn write(&mut self, at: pci::Address, offset: usize, value: u32) {
        let page = self.ecam.offset(at).unwrap_or(0) as usize;
        // SAFETY: as for `read`.
        unsafe { mmio::write32(ECAM_WINDOW + page + offset, value) }
    }
}

/// Walks the buses of the platform once: prints a line for each function
/// with its BARs (init::resolve::list), then finds the places the table
/// names by function (init::resolve) and installs the resolved table; false,
/// with the line of the cause, when a record that is not optional has no
/// place.
fn resolved(init: &rt::InitHandles) -> bool {
    let Some(platform) = table::PLATFORM else {
        println!("init: table refused: the table names functions and the platform has no ECAM");
        return false;
    };
    let len = platform.window_len();
    let Ok(window) = sys::device_window_create(&init.resource, platform.ecam.base, len) else {
        println!("init: table refused: no window over the ECAM");
        return false;
    };
    if sys::mem_map(
        &init.process,
        &window,
        0,
        len,
        ECAM_WINDOW,
        Access::ReadWrite,
    )
    .is_err()
    {
        println!("init: table refused: the ECAM does not map");
        return false;
    }
    let mut walk = Walk {
        ecam: platform.ecam,
    };
    // SAFETY: the room is used here only, once, before init has a second thread.
    let room = unsafe { &mut *ROOM.0.get() };
    resolve::list(&mut walk, &platform, |line| println!("{line}"));
    let outcome = if resolve::needs(TABLE) {
        resolve::resolve(TABLE, &platform, &mut walk, room).map(Some)
    } else {
        Ok(None)
    };
    // SAFETY: the window is init's own, mapped above, and nothing reads it now.
    let _ = unsafe { sys::mem_unmap(&init.process, ECAM_WINDOW, len) };
    match outcome {
        Ok(None) => true,
        Ok(Some(found)) => {
            for left_out in found.skipped.iter().flatten() {
                println!("init: left out: {left_out}");
            }
            print_places(TABLE, found.table);
            resolve::install(found.table);
            true
        }
        Err(refusal) => {
            println!("init: table refused: {refusal}");
            false
        }
    }
}

/// One line for each window the walk placed: the record, the window and
/// the physical range the firmware's BAR gave it.
fn print_places(named: &[Record], found: &[Record]) {
    for r in named {
        let Some(placed) = found.iter().find(|f| f.name == r.name) else {
            continue;
        };
        for (was, now) in r.windows.iter().zip(placed.windows) {
            if was.at != At::Fixed {
                println!(
                    "init: {} {} at {:#x} len {:#x}",
                    r.name, now.name, now.base, now.len
                );
            }
        }
    }
}

/// The program of each record of the table, by its place, from the boot
/// image `image`, which init maps at IMAGE through its process `own`; the
/// first record whose program is not in the image.
fn programs(
    own: &Handle<Process>,
    image: &Handle<Memory>,
) -> Result<[Option<Program<'static>>; MAX_RECORDS], &'static Record> {
    let size = sys::memory_info(image).map_or(0, |info| info.size);
    let mapped = sys::mem_map(own, image, 0, size, IMAGE, Access::Read).is_ok();
    let bytes: &'static [u8] = if mapped {
        // SAFETY: the boot image is mapped at IMAGE, read-only, for as long
        // as init lives, and nothing maps anything else there.
        unsafe { core::slice::from_raw_parts(IMAGE as *const u8, size as usize) }
    } else {
        &[]
    };
    let boot = BootImage::parse(bytes).ok();
    let mut programs = [None; MAX_RECORDS];
    for (place, r) in table::table().iter().enumerate() {
        let file = boot.and_then(|b| b.files().find(|f| f.name == r.program));
        let program = file.and_then(|f| Program::parse(f.data).ok());
        programs[place] = Some(program.ok_or(r)?);
    }
    Ok(programs)
}
