// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The guest probe of the host key service (`datakey`): what the boot script of Dropbear does about
//! the host key, without the shell. A session with `datakey` holds it back until the service has put the key of the volume in place. A key in `/etc/dropbear` is
//! kept; with none, the probe makes one of 64 bytes from the counter (test bytes, no key of any server)
//! and writes it with mode 0600. Either way one line tells the checksum of the file, in the form of the
//! script's line:
//!
//! `ssh: host key FNV:<16 hex digits>`
//!
//! Then the probe waits until `datakey` ends (it keeps a new key on the volume first), for two minutes at
//! most, and ends. The
//! bytes of the key are never printed.

#![no_std]
#![no_main]

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use posix_fs::{DescriptorFlags, FsError, PosixFs, StartupFiles};

rt::entry!(main);

const KEY: &[u8] = b"/etc/dropbear/dropbear_ed25519_host_key";
const KEY_MAX: usize = 1024;

struct Cell(UnsafeCell<MaybeUninit<PosixFs>>);

// SAFETY: the table is reached from the one thread of the program.
unsafe impl Sync for Cell {}

static FILES: Cell = Cell(UnsafeCell::new(MaybeUninit::uninit()));

fn fnv(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

fn run(files: &mut PosixFs) -> Result<u64, FsError> {
    let mut bytes = [0u8; KEY_MAX];
    let len = match files.open(KEY, proto_fs::READ_ONLY) {
        Ok(fd) => {
            let n = files.read(fd, &mut bytes)?;
            files.close(fd)?;
            n
        }
        Err(FsError::NoEntry) => {
            let mut x = rt::time::now() | 1;
            for b in &mut bytes[..64] {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                *b = x as u8;
            }
            let flags = proto_fs::WRITE_ONLY | proto_fs::CREATE | proto_fs::TRUNCATE;
            let fd = files.open_policy(KEY, flags, 0o600, 0, DescriptorFlags::default())?;
            let wrote = files.write(fd, &bytes[..64])?;
            files.close(fd)?;
            if wrote != 64 {
                return Err(FsError::NoSpace);
            }
            64
        }
        Err(error) => return Err(error),
    };
    Ok(fnv(&bytes[..len]))
}

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<rt::handle::Resource>("console") {
        rt::console::set(console);
    }
    // The service registers once it has put the key of the volume into the file service: the
    // session comes then (an end of the service after that makes it fail, and the key is in place).
    let session = rt::service::connect(&start.parent, "datakey").ok();
    let Ok(startup) = StartupFiles::connect(&start.parent, false) else {
        rt::println!("datakey-probe: failed: no file service");
        return 2;
    };
    // SAFETY: FILES is aligned, writable and used by nobody else.
    let made = unsafe {
        PosixFs::initialize_at(
            (*FILES.0.get()).as_mut_ptr(),
            startup,
            b"/",
            None,
            false,
            &mut posix_fs::Late::new(),
        )
    };
    if made.is_err() {
        rt::println!("datakey-probe: failed: the table of files");
        return 2;
    }
    // SAFETY: initialize_at succeeded; the one thread of the program is the only user.
    let files = unsafe { (*FILES.0.get()).assume_init_mut() };
    match run(files) {
        Ok(sum) => rt::println!("ssh: host key FNV:{sum:016x}"),
        Err(error) => {
            rt::println!("datakey-probe: failed: {error:?}");
            return 2;
        }
    }
    // The service ends once it has kept a new key (or has none to wait for): a request to it then
    // fails. A look every tenth of a second, and a limit of two minutes.
    if let Some(session) = session {
        let limit = rt::time::now() + 120 * rt::time::frequency();
        while rt::time::now() < limit && rt::sys::send(&session, &[0]).is_ok() {
            let until = rt::time::now() + rt::time::frequency() / 10;
            while rt::time::now() < until {
                let _ = rt::sys::yield_now();
            }
        }
    }
    rt::println!("datakey-probe: ended");
    0
}
