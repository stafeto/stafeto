// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The host key service: keeps the SSH host key of Dropbear on the data volume (`datafs`) and puts it
//! into the file service (`ramfs`) at `/etc/dropbear` before the shell's boot script starts the server.
//!
//! At the start the service reads `/ssh/dropbear_ed25519_host_key` of the volume. A key there is written
//! to `/etc/dropbear/dropbear_ed25519_host_key` with mode 0600, and the service says READY and ends.
//! A key that is already in `/etc/dropbear` (the launcher started the boot script after its wait for this
//! service, and the script made a key) is left as it is: the file is created with the exclusive flag.
//! A volume with no key gets READY at once, and the service looks for the key the boot script makes
//! (once a second, 120 times, at its heartbeat): a file that has the same bytes in two looks in a row is
//! written to the volume as `.tmp`, synced, and renamed to its name, and the service ends. With no data
//! volume (no service, or a volume that is not mounted) it says READY and ends: the key of the boot then
//! lives in memory only. The key itself is never printed.

#![no_std]
#![no_main]

mod keep;

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use posix_fs::{DescriptorFlags, FsError, PosixFs, StartupFiles};
use proto_data as p;
use proto_data::Method;
use proto_init::ServiceArgs;
use proto_wire::{Status, Writer};
use rt::handle::{Channel, Resource};
use rt::service::{Answer, Config, Heartbeat, Notice, Request, Service, Session};
use rt::{Handle, sys};

rt::entry!(main);

/// The key in the file service, where the server reads it.
const RAM_KEY: &[u8] = b"/etc/dropbear/dropbear_ed25519_host_key";
/// The key on the volume: the directory, the file and the name it is written under.
const DATA_DIR: &[u8] = b"/ssh";
const DATA_KEY: &[u8] = b"/ssh/dropbear_ed25519_host_key";
const DATA_TMP: &[u8] = b"/ssh/dropbear_ed25519_host_key.tmp";
/// The largest key file (a dropbear Ed25519 key is about 120 bytes).
const KEY_MAX: usize = 1024;
/// The looks for the key of the boot script, one for each heartbeat of a second.
const LOOKS: u32 = 120;
const SECOND_NS: u64 = 1_000_000_000;

const START_FAILED: u64 = 1;
const NOT_REGISTERED: u64 = 2;

struct Cell(UnsafeCell<MaybeUninit<PosixFs>>);

// SAFETY: the table is reached from the one thread of the service.
unsafe impl Sync for Cell {}

static FILES: Cell = Cell(UnsafeCell::new(MaybeUninit::uninit()));

/// The files of the file service, once `connect_files` has made the table.
fn files() -> &'static mut PosixFs {
    // SAFETY: only called after `connect_files` succeeded, from the one thread of the service.
    unsafe { (*FILES.0.get()).assume_init_mut() }
}

fn connect_files(parent: &Handle<Channel>) -> Result<(), FsError> {
    let startup = StartupFiles::connect(parent, false)?;
    // SAFETY: FILES is aligned, writable and used by nobody else.
    unsafe {
        PosixFs::initialize_at(
            (*FILES.0.get()).as_mut_ptr(),
            startup,
            b"/",
            None,
            false,
            &mut posix_fs::Late::new(),
        )
    }
}

/// A key file: its bytes and their count.
struct Key {
    bytes: [u8; KEY_MAX],
    len: usize,
}

impl Key {
    const fn new() -> Key {
        Key {
            bytes: [0; KEY_MAX],
            len: 0,
        }
    }

    fn data(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Writes zeros over the bytes.
    fn wipe(&mut self) {
        self.bytes.fill(0);
        // The zeros are kept: the array may be read through the pointer from here on.
        core::hint::black_box(self.bytes.as_mut_ptr());
        self.len = 0;
    }
}

/// Reads `/etc/dropbear/dropbear_ed25519_host_key` of the file service. Ok(false): not there.
fn read_ram(key: &mut Key) -> Result<bool, FsError> {
    let files = files();
    let fd = match files.open(RAM_KEY, proto_fs::READ_ONLY) {
        Ok(fd) => fd,
        Err(FsError::NoEntry) => return Ok(false),
        Err(error) => return Err(error),
    };
    let mut len = 0;
    let result = loop {
        if len == KEY_MAX {
            break Err(FsError::FileTooLarge);
        }
        match files.read(fd, &mut key.bytes[len..]) {
            Ok(0) => break Ok(()),
            Ok(n) => len += n,
            Err(error) => break Err(error),
        }
    };
    let closed = files.close(fd);
    result.and(closed)?;
    key.len = len;
    Ok(true)
}

/// Writes the key into the file service, mode 0600, from its start. The file is created here: a key that
/// is already there (the boot script made one, because the launcher did not wait for this service any
/// longer) is never replaced, so `/etc/dropbear` stays as the running server has it
/// (`FsError::AlreadyExists`).
fn write_ram(key: &Key) -> Result<(), FsError> {
    let files = files();
    let flags = proto_fs::WRITE_ONLY | proto_fs::CREATE | proto_fs::EXCLUSIVE;
    let fd = files.open_policy(RAM_KEY, flags, 0o600, 0, DescriptorFlags::default())?;
    let mut done = 0;
    let result = loop {
        if done == key.len {
            break Ok(());
        }
        match files.write(fd, &key.data()[done..]) {
            Ok(0) => break Err(FsError::NoSpace),
            Ok(n) => done += n,
            Err(error) => break Err(error),
        }
    };
    let closed = files.close(fd);
    let outcome = result.and(closed);
    if outcome.is_err() {
        // No part of a key stays behind: the file is emptied again (the file service has no removal
        // for a service), and the boot script makes a new key when the file holds none.
        if let Ok(fd) = files.open(RAM_KEY, proto_fs::WRITE_ONLY | proto_fs::TRUNCATE) {
            let _ = files.close(fd);
        }
    }
    outcome
}

/// The session with `datafs`.
struct Data {
    session: Handle<Channel>,
}

struct Reply {
    bytes: [u8; abi::MESSAGE_MAX],
    len: usize,
}

impl Reply {
    fn word(&self, at: usize) -> u32 {
        u32::from_le_bytes(self.bytes[4 + at..8 + at].try_into().unwrap_or([0; 4]))
    }
}

impl Data {
    fn call(&self, build: impl FnOnce(&mut Writer) -> Result<(), Status>) -> Result<Reply, Status> {
        let mut w = Writer::new();
        build(&mut w)?;
        let reply = sys::send(&self.session, w.as_bytes())?;
        let mut out = Reply {
            bytes: [0; abi::MESSAGE_MAX],
            len: 0,
        };
        out.len = reply.bytes(&mut out.bytes).len();
        p::reply(&out.bytes[..out.len])?;
        Ok(out)
    }

    fn open(&self, path: &[u8], flags: u32) -> Result<u32, Status> {
        Ok(self.call(|w| p::open(path, flags, 0o600, w))?.word(0))
    }

    fn close(&self, handle: u32) -> Result<(), Status> {
        self.call(|w| p::handle_call(Method::Close, handle, w))
            .map(drop)
    }

    /// The key file of the volume. Ok(false): not there.
    fn read(&self, key: &mut Key) -> Result<bool, Status> {
        let handle = match self.open(DATA_KEY, p::READ) {
            Ok(handle) => handle,
            Err(Status::Unknown(p::NO_ENTRY)) => return Ok(false),
            Err(status) => return Err(status),
        };
        let mut len = 0;
        let result = loop {
            let reply = match self.call(|w| p::read(handle, p::MAX_READ as u32, w)) {
                Ok(reply) => reply,
                Err(status) => break Err(status),
            };
            let n = reply.word(0) as usize;
            if n == 0 {
                break Ok(());
            }
            // The count lies inside the bytes of the reply.
            if n > reply.len.saturating_sub(8) {
                break Err(Status::BadSize);
            }
            if len + n > KEY_MAX {
                break Err(Status::Unknown(p::TOO_BIG));
            }
            key.bytes[len..len + n].copy_from_slice(&reply.bytes[8..8 + n]);
            len += n;
        };
        let closed = self.close(handle);
        result.and(closed)?;
        key.len = len;
        Ok(true)
    }

    /// The modes of the root, of `/ssh` and of the key file as the volume says them, in one line
    /// (the probe of an upgrade reads it): `datakey: modes / 0755 /ssh 0700 key 0600`.
    #[cfg(feature = "modes")]
    fn modes(&self) {
        let mode = |path: &[u8]| {
            self.call(|w| p::path_call(Method::Stat, path, w))
                .ok()
                .and_then(|r| p::Stat::from_bytes(&r.bytes[4..r.len]).ok())
                .map(|s| s.mode)
        };
        match (mode(b"/"), mode(DATA_DIR), mode(DATA_KEY)) {
            (Some(root), Some(dir), Some(key)) => {
                rt::println!("datakey: modes / {root:04o} /ssh {dir:04o} key {key:04o}")
            }
            other => rt::println!("datakey: modes could not be read: {other:?}"),
        }
    }

    /// The key rewritten where it stands: the bytes at its start and at its middle read and written
    /// back, synced, and read again (`datakey: key rewritten in place and read back`). On a volume
    /// the 0.5.1 service made the key is an inline file, and a write at its start or in its middle
    /// is lost in littlefs 2.11.3 unless the mount work moved the file out: the probe of an upgrade
    /// needs this to work. The bytes are the same, so the fingerprint does not change.
    #[cfg(feature = "modes")]
    fn rewrite_in_place(&self) {
        let rewrite = || -> Result<bool, Status> {
            let handle = self.open(DATA_KEY, p::READ | p::WRITE)?;
            let mut same = true;
            for offset in [0u64, 16] {
                let read = self.call(|w| p::pread(handle, 8, offset, w))?;
                let n = (read.word(0) as usize).min(8);
                let mut bytes = [0u8; 8];
                bytes[..n].copy_from_slice(&read.bytes[8..8 + n]);
                let wrote = self
                    .call(|w| p::pwrite(handle, offset, &bytes[..n], w))?
                    .word(0) as usize;
                let again = self.call(|w| p::pread(handle, 8, offset, w))?;
                same &= wrote == n
                    && again.word(0) as usize == n
                    && again.bytes[8..8 + n] == bytes[..n];
            }
            self.call(|w| p::handle_call(Method::Fsync, handle, w))?;
            self.close(handle)?;
            Ok(same)
        };
        match rewrite() {
            Ok(true) => rt::println!("datakey: key rewritten in place and read back"),
            Ok(false) => {
                rt::println!("datakey: the key read back differs after a rewrite in place")
            }
            Err(status) => {
                rt::println!("datakey: rewrite in place failed: status {}", status.code())
            }
        }
    }

    /// The key written as `.tmp`, synced, and renamed to its name.
    fn save(&self, key: &Key) -> Result<(), Status> {
        match self.call(|w| p::mkdir(DATA_DIR, 0o700, w)) {
            Ok(_) | Err(Status::Unknown(p::EXISTS)) => {}
            Err(status) => return Err(status),
        }
        let handle = self.open(DATA_TMP, p::WRITE | p::CREATE | p::TRUNCATE)?;
        let written = (|| {
            let mut at = 0;
            while at < key.len {
                let n = (key.len - at).min(900);
                let wrote = self
                    .call(|w| p::write(handle, &key.data()[at..at + n], w))?
                    .word(0) as usize;
                if wrote != n {
                    return Err(Status::BadSize);
                }
                at += n;
            }
            self.call(|w| p::handle_call(Method::Fsync, handle, w))
                .map(drop)
        })();
        let closed = self.close(handle);
        written.and(closed)?;
        self.call(|w| p::rename(DATA_TMP, DATA_KEY, w)).map(drop)
    }
}

/// What the start found on the volume.
#[derive(Clone, Copy)]
enum Found {
    /// The key was there (and is in the file service now).
    Restored,
    /// The volume is mounted and holds no key.
    NoKey,
    /// No volume to keep a key on.
    NoVolume,
}

fn main(_: u64) -> u64 {
    let Ok(mut s) = rt::startup() else {
        return START_FAILED;
    };
    if let Ok(console) = s.take::<Resource>("console") {
        rt::console::set(console);
    }
    let args = ServiceArgs::read(s.args()).ok();
    let files_ok = match connect_files(&s.parent) {
        Ok(()) => true,
        Err(error) => {
            rt::println!("datakey: no file service: {error:?}");
            false
        }
    };
    let data = rt::service::connect(&s.parent, "datafs")
        .ok()
        .map(|session| Data { session });
    let mut key = Key::new();
    let found = match (&data, files_ok) {
        (Some(data), true) => match data.read(&mut key) {
            // A key of no bytes is no key.
            Ok(true) if key.len == 0 => Found::NoKey,
            Ok(true) => {
                match write_ram(&key) {
                    Ok(()) => rt::println!("datakey: host key restored from /data"),
                    Err(FsError::AlreadyExists) => rt::println!(
                        "datakey: /etc/dropbear has a key already, the key of /data is not restored"
                    ),
                    Err(error) => rt::println!("datakey: the key could not be placed: {error:?}"),
                }
                #[cfg(feature = "modes")]
                {
                    data.modes();
                    data.rewrite_in_place();
                }
                Found::Restored
            }
            Ok(false) => Found::NoKey,
            Err(Status::Unknown(p::NOT_READY)) => Found::NoVolume,
            Err(status) => {
                rt::println!("datakey: the volume refused: status {}", status.code());
                Found::NoVolume
            }
        },
        _ => Found::NoVolume,
    };
    key.wipe();
    // The account files, placed before READY: the launcher starts the boot script after it.
    let volume = !matches!(found, Found::NoVolume);
    let watch = if files_ok {
        keep::start(data.as_ref(), volume)
    } else {
        None
    };
    let Ok(channel) = sys::channel_create(1) else {
        return NOT_REGISTERED;
    };
    if rt::service::register(&s.parent, &channel).is_err() {
        return NOT_REGISTERED;
    }
    if let Err(why) = rt::service::ready(&s.parent) {
        rt::println!("datakey: READY refused: {why:?}");
    }
    // The service stays while a volume is there: it keeps the host key the boot script makes
    // (a volume with none) and the account files.
    let (true, Some(data)) = (volume, data) else {
        return 0;
    };
    let host_key = matches!(found, Found::NoKey);
    if host_key {
        rt::println!("datakey: no host key on /data, waiting for the boot script's");
    }
    let mut service = Waiting {
        data,
        last: Key::new(),
        looks: 0,
        host_key,
        watch,
    };
    let config = Config {
        issued: 0,
        heartbeat: Some(Heartbeat {
            to: &s.parent,
            period_ns: args.map_or(SECOND_NS, |a| a.period_ns).max(1),
            priority: sys::thread_info(&s.thread).map_or(1, |info| info.base),
        }),
    };
    let _ = rt::service::run::<Waiting, 2, 0>(&channel, &mut service, config);
    0
}

struct Waiting {
    data: Data,
    /// The bytes the last look found, for the next look to compare with.
    last: Key,
    looks: u32,
    /// The host key is still waited for.
    host_key: bool,
    /// The account files, once placed.
    watch: Option<keep::Watch>,
}

impl Waiting {
    /// One look a second: the host key while it is waited for, and the account files.
    fn tick(&mut self) {
        if self.host_key {
            self.look();
        }
        if let Some(watch) = &mut self.watch {
            watch.look(&self.data);
        }
        if !self.host_key && self.watch.is_none() {
            sys::process_exit(0);
        }
    }

    fn look(&mut self) {
        self.looks += 1;
        if self.looks > LOOKS {
            rt::println!("datakey: no host key appeared in {LOOKS} s, nothing is kept");
            self.host_key = false;
            return;
        }
        let mut now = Key::new();
        match read_ram(&mut now) {
            Ok(true) if now.len > 0 => {}
            _ => {
                self.last.wipe();
                return;
            }
        }
        if self.last.len != now.len || self.last.data() != now.data() {
            self.last = now;
            return;
        }
        match self.data.save(&now) {
            Ok(()) => {
                rt::println!("datakey: host key saved to /data");
                self.last.wipe();
                now.wipe();
                self.host_key = false;
            }
            Err(status) => {
                rt::println!(
                    "datakey: the key could not be saved: status {}",
                    status.code()
                );
                now.wipe();
            }
        }
    }
}

impl Service<0> for Waiting {
    const VERSION: u16 = 1;
    const METHODS: &'static [u16] = &[];
    type Data = ();

    fn request(&mut self, _: &mut Session<(), 0>, _: &mut Request<'_>) -> Answer {
        Answer::Status(Status::Kernel(abi::Error::BadState))
    }

    fn maintenance(&mut self, _: &mut [Option<Session<(), 0>>], notice: Notice) {
        if notice.source == abi::Source::Timer && notice.label == 0 {
            self.tick();
        }
    }
}
