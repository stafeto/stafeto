// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The start of a C program on relibc. A program init starts takes its
//! arguments, a bounded NUL-separated list, from its start data; one its
//! loader started (posix_spawn from a file, spec 2, 3.2; 5c) finds them
//! with its environment and its sessions in the start area the loader
//! wrote (proto_loader::Start), x0 naming it. The start goes in
//! two steps (spec 2, 3.5): the process's (`posix_init_process`:
//! registration, clocks, files, heap, the clock's page), which leaves the
//! thread alone, then relibc's: `crt_main` hands the thread to
//! `relibc_start_v1` with a Linux initial stack and `TPIDR_EL0` at 0;
//! relibc builds the TCB and its platform attaches the thread to the layer
//! (posix-platform `stafeto_init`).

#![no_std]

use core::ffi::{c_char, c_int};
use core::mem::ManuallyDrop;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};
use posix_fs::StartupFiles;
use rt::handle::{Channel, Handle, Process, Resource, Thread};

// relibc's platform calls the layer through posix-platform's functions.
extern crate posix_platform;

type Main = unsafe extern "C" fn(isize, *mut *mut c_char, *mut *mut c_char) -> c_int;

unsafe extern "C" {
    fn main(argc: isize, argv: *mut *mut c_char, envp: *mut *mut c_char) -> c_int;
    fn relibc_start_v1(stack: *const usize, main: Main) -> !;
    /// The process's umask (posix-platform).
    fn stafeto_umask(mask: u32) -> u32;
    /// The ELF header, which lld maps with the read-only data.
    static __ehdr_start: [u8; 64];
}

/// Linux auxiliary vector keys relibc's start reads.
mod auxv {
    pub const AT_NULL: usize = 0;
    pub const AT_PHDR: usize = 3;
    pub const AT_PHENT: usize = 4;
    pub const AT_PHNUM: usize = 5;
    pub const AT_PAGESZ: usize = 6;
    pub const AT_SECURE: usize = 23;
}

/// The auxiliary vector into `out`, pairs of words: the program headers
/// (relibc builds the static TLS from `PT_TLS`), the page size and, for
/// a set-ID program, AT_SECURE; then AT_NULL. Six pairs.
fn auxiliary(out: &mut [usize], secure: bool) {
    use auxv::*;
    let header = ptr::addr_of!(__ehdr_start).cast::<u8>();
    // SAFETY: the ELF header is 64 readable bytes.
    let (phoff, phent, phnum) = unsafe {
        (
            ptr::read_unaligned(header.add(32).cast::<u64>()) as usize,
            usize::from(ptr::read_unaligned(header.add(54).cast::<u16>())),
            usize::from(ptr::read_unaligned(header.add(56).cast::<u16>())),
        )
    };
    let pairs = [
        (AT_PHDR, header as usize + phoff),
        (AT_PHENT, phent),
        (AT_PHNUM, phnum),
        (AT_PAGESZ, 4096),
        (AT_SECURE, usize::from(secure)),
        (AT_NULL, 0),
    ];
    for (index, (key, value)) in pairs.into_iter().enumerate() {
        out[2 * index] = key;
        out[2 * index + 1] = value;
    }
}

/// Hands the main thread to relibc's start with the initial stack of a
/// Linux process: argc, the `count` arguments, NULL, an empty environment
/// (until 5c), the auxiliary vector with the program headers (relibc
/// builds the static TLS from `PT_TLS`) and the page size.
fn start_relibc(arguments: &[*mut c_char]) -> ! {
    let mut stack = [0usize; 42];
    stack[0] = arguments.len();
    for (word, &argument) in stack[1..].iter_mut().zip(arguments) {
        *word = argument as usize;
    }
    // argv's NULL and the empty environment's NULL follow the arguments.
    let auxv = 1 + arguments.len() + 2;
    auxiliary(&mut stack[auxv..], false);
    // SAFETY: the stack follows the Linux start contract, and it lives on:
    // relibc's start does not return.
    unsafe { enter_relibc(stack.as_ptr()) }
}

/// relibc's start with the initial stack at `stack`.
///
/// # Safety
/// `stack` holds a Linux initial stack (argc, argv, NULL, envp, NULL, the
/// auxiliary vector) that lives for the program's life.
unsafe fn enter_relibc(stack: *const usize) -> ! {
    // relibc builds the TCB and the static TLS only when the register is
    // 0; the layer's start left no TCB there, and this says so.
    // SAFETY: no TCB of the layer is installed on this thread.
    unsafe { posix_thread::activate(ptr::null_mut()) };
    // SAFETY: the caller's promise; relibc's start does not return.
    unsafe { relibc_start_v1(stack, main) }
}

/// The first step of the start: the process's registration with the
/// process service (`session`), its clocks and files through `parent`,
/// its heap and its table of threads; no helper thread. The calling
/// thread's block is not touched.
///
/// # Safety
/// Runs once, on the main thread, before any other thread of the process;
/// `process` and `thread` are the program's own (rt::startup).
pub unsafe fn posix_init_process(
    session: Handle<Channel>,
    identity: Option<Handle<Channel>>,
    parent: &Handle<Channel>,
    process: Handle<Process>,
    thread: Handle<Thread>,
) -> Result<(), &'static str> {
    // SAFETY: startup runs once, before application threads and clock calls.
    unsafe { posix_abi::process::init(session) }.map_err(|_| "process registration failed")?;
    if let Some(identity) = identity {
        // SAFETY: startup owns process identity installation.
        unsafe { posix_abi::process::set_identity(identity) };
    }
    // SAFETY: as above.
    unsafe { posix_abi::clock::init(parent) }.map_err(|_| "clock connection failed")?;
    // The console's input through the terminal service when init's table
    // gives the program one (5f), through the console's driver otherwise.
    #[cfg(feature = "uart-input")]
    let files = match rt::service::connect(parent, "tty") {
        Ok(terminal) => StartupFiles::connect(parent, false).map(|mut fs| {
            fs.set_terminal(Some(terminal));
            fs
        }),
        Err(_) => StartupFiles::connect(parent, true),
    };
    #[cfg(not(feature = "uart-input"))]
    let files = StartupFiles::connect(parent, false);
    let files = files.map_err(|_| "file connection failed")?;
    // SAFETY: only startup owns file initialization.
    unsafe { posix_abi::shared::init(files, b"/", None, false, posix_abi::process::identity()) }
        .map_err(|_| "files failed")?;
    // The entropy service, when the record names it; none otherwise, and
    // getentropy gives ENOSYS. SAFETY: startup, on the only thread.
    unsafe { posix_abi::random::init(rt::service::connect(parent, "entropy").ok()) };
    // SAFETY: startup is single-threaded and its layout reserves the heap ranges.
    unsafe { posix_abi::allocation::init(process) }.map_err(|_| "heap failed")?;
    // CLOCK_REALTIME without IPC; a clock service without its page leaves
    // the requests. SAFETY: startup, after the clock's connection; the
    // page's address is the layer's.
    let _ = unsafe { posix_abi::clock::attach_page(posix_abi::allocation::process()) };
    // SAFETY: startup owns initialization and the stack ranges are unused.
    unsafe { posix_abi::threads::init(thread) }.map_err(|_| "threads failed")?;
    Ok(())
}

/// The start's parent channel, which stays open for the program's life
/// (crt_main does not return).
static PARENT: AtomicU64 = AtomicU64::new(0);

/// The start's parent channel, for a program that connects to services by
/// name beyond its files and clocks (the guest probes).
pub fn parent() -> ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(rt::abi::Handle(PARENT.load(Ordering::Acquire)))
}

/// A forked child's start channel is its parent's value, which names
/// nothing of its own: it has none (posix_abi::fork::at_child).
fn forked() {
    PARENT.store(0, Ordering::Release);
}

/// The live handles of the process at the start of a program its loader
/// started, and the handles its start area names (its slots and the
/// objects of its memory map): the loader closed all that was its own when
/// the two agree (spec 2, 3.2, condition O6).
static START_HANDLES: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

/// The handles of the process at its start and those its start area
/// named, for the probes: zeros for a program init started.
///
/// # Safety
/// `out` is null or has room for two words.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_start_handles(out: *mut u64) {
    if out.is_null() {
        return;
    }
    for (i, value) in START_HANDLES.iter().enumerate() {
        // SAFETY: the caller gives room for two words.
        unsafe { out.add(i).write(value.load(Ordering::Relaxed)) };
    }
}

/// The descriptors the start area names (proto_loader::Descriptor), as
/// the layer's files take them.
fn inherited(area: &proto_loader::Start) -> [posix_fs::Inherited; proto_loader::DESCRIPTORS] {
    use posix_fs::{Inherited, Target};
    use proto_loader::{DESCRIPTOR, DESCRIPTORS, Descriptor, Names};
    let mut list = [Inherited {
        fd: 0,
        target: Target::Input,
    }; DESCRIPTORS];
    let count = (area.descriptor_count as usize).min(DESCRIPTORS);
    // SAFETY: the loader wrote `count` descriptors at `descriptors` in
    // the area, which stays mapped.
    let bytes =
        unsafe { core::slice::from_raw_parts(area.descriptors as *const u8, count * DESCRIPTOR) };
    for (place, d) in list.iter_mut().zip(
        bytes
            .as_chunks::<DESCRIPTOR>()
            .0
            .iter()
            .filter_map(|c| Descriptor::read(c)),
    ) {
        let target = match d.names {
            Names::Input => Target::Input,
            Names::Output => Target::Output,
            Names::Error => Target::Error,
            Names::File(n) => Target::Ram(n),
            Names::Pipe(n) => Target::Pipe(n),
            Names::Terminal(n) => Target::Tty(n),
            Names::Random(n) => Target::Random(n),
            Names::PendingTerminal(_) => continue,
        };
        *place = Inherited { fd: d.fd, target };
    }
    list
}

/// The memory map the loader handed over (proto_loader::MapEntry in the
/// start area) goes to the layer's map (posix_abi::allocation::adopt).
///
/// # Safety
/// Runs once at startup, after the heap's `init`, on the only thread.
unsafe fn adopt_map(area: &proto_loader::Start) -> Result<(), &'static str> {
    use proto_loader::{MAP_ENTRIES, MAP_ENTRY, MapEntry};
    let count = area.map_count as usize;
    if count > MAP_ENTRIES {
        return Err("memory map too long");
    }
    // SAFETY: the loader wrote `count` entries at `map` in the area, which
    // stays mapped.
    let bytes = unsafe { core::slice::from_raw_parts(area.map as *const u8, count * MAP_ENTRY) };
    for chunk in bytes.as_chunks::<MAP_ENTRY>().0 {
        let entry = MapEntry::read(chunk).ok_or("memory map entry malformed")?;
        // SAFETY: the loader gave the handle to this process for the
        // layer's map; the caller's promise for the rest.
        unsafe {
            posix_abi::allocation::adopt(
                entry.address as usize,
                entry.pages as usize,
                entry.access,
                Handle::from_raw(rt::abi::Handle(entry.handle)),
            )
        }
        .map_err(|_| "memory map entry refused")?;
    }
    Ok(())
}

/// The start of a program its loader started: the area at
/// proto_loader::START_AREA names its handles, its current directory, its
/// umask and its initial stack, whose auxiliary vector this fills.
fn loaded_main() -> u64 {
    use proto_loader::{SECURE, START_AREA, START_SIZE, Slot, Start};
    // SAFETY: the loader mapped the area read and write at START_AREA for
    // the program's life, its header first.
    let header = unsafe { core::slice::from_raw_parts(START_AREA as *const u8, START_SIZE) };
    let Some(area) = Start::read(header) else {
        return 125;
    };
    let value = |slot: Slot| rt::abi::Handle(area.handles[slot as usize]);
    let named = (area.handles.iter().filter(|&&h| h != 0).count() + area.map_count as usize) as u64;
    let one = |slot: Slot| (value(slot) != rt::abi::Handle::INVALID).then(|| value(slot));
    if let Some(console) = one(Slot::Console) {
        rt::console::set(Handle::<Resource>::from_raw(console));
    }
    let (Some(process), Some(thread), Some(posix), Some(files), Some(clock)) = (
        one(Slot::Process),
        one(Slot::Thread),
        one(Slot::Posix),
        one(Slot::Files),
        one(Slot::Clock),
    ) else {
        rt::println!("POSIX startup: the start area lacks a handle");
        return 125;
    };
    let process = Handle::<Process>::from_raw(process);
    if let Ok(table) = rt::sys::process_handles(&process) {
        START_HANDLES[0].store(table.live, Ordering::Relaxed);
        START_HANDLES[1].store(named, Ordering::Relaxed);
    }
    let cwd = if area.cwd == 0 {
        &[][..]
    } else {
        // SAFETY: the loader wrote the current directory as a C string in
        // the area.
        unsafe { core::ffi::CStr::from_ptr(area.cwd as *const c_char) }.to_bytes()
    };
    // SAFETY: the main thread, once, before any other.
    let started = unsafe {
        posix_abi::signals::carry_pending(area.pending);
        posix_abi::process::init(Handle::from_raw(posix))
            .map_err(|_| "process registration failed")
            .and_then(|()| {
                posix_abi::clock::init_with(Handle::from_raw(clock))
                    .map_err(|_| "clock session failed")
            })
            .and_then(|()| {
                let uart = one(Slot::Driver).map(Handle::from_raw);
                let inherited = inherited(&area);
                let count = area.descriptor_count as usize;
                let secure = area.flags & SECURE != 0;
                if let Some(identity) = one(Slot::PosixId) {
                    posix_abi::process::set_identity(Handle::from_raw(identity));
                }
                let startup = StartupFiles::from_sessions(
                    Handle::from_raw(files),
                    uart,
                    one(Slot::Pipes).map(Handle::from_raw),
                    one(Slot::Terminal).map(Handle::from_raw),
                );
                posix_abi::shared::init(
                    startup,
                    cwd,
                    Some(&inherited[..count.min(inherited.len())]),
                    secure,
                    posix_abi::process::identity(),
                )
                .map_err(|_| "files failed")
            })
            .and_then(|()| posix_abi::allocation::init(process).map_err(|_| "heap failed"))
            .and_then(|()| adopt_map(&area))
            .and_then(|()| {
                let _ = posix_abi::clock::attach_page(posix_abi::allocation::process());
                posix_abi::threads::init(Handle::from_raw(thread)).map_err(|_| "threads failed")
            })
    };
    if let Err(why) = started {
        rt::println!("POSIX startup: {}", why);
        return 125;
    }
    // SAFETY: still single-threaded.
    unsafe { posix_abi::random::init(one(Slot::Entropy).map(Handle::from_raw)) };
    posix_abi::fork::at_child(forked);
    // SAFETY: the platform's umask takes any mask.
    unsafe { stafeto_umask(area.umask) };
    // The auxiliary vector's pairs lie in the area, after the NULL of envp.
    // SAFETY: the loader left proto_loader::AUXV_PAIRS pairs of words there.
    let auxv = unsafe {
        core::slice::from_raw_parts_mut(area.auxv as *mut usize, 2 * proto_loader::AUXV_PAIRS)
    };
    auxiliary(auxv, area.flags & SECURE != 0);
    // SAFETY: the area holds the initial stack and lives for good.
    unsafe { enter_relibc(area.stack as *const usize) }
}

#[unsafe(export_name = "__rt_main")]
pub extern "C" fn crt_main(arg: u64) -> u64 {
    if arg == proto_loader::START_AREA {
        return loaded_main();
    }
    let Ok(mut start) = rt::startup() else {
        return 125;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    let mut arguments = [ptr::null_mut(); 17];
    let mut bytes = [0; 256];
    let Ok(args) = proto_init::ServiceArgs::read(start.args()) else {
        rt::println!("POSIX startup: invalid start arguments");
        return 125;
    };
    let input = if args.own.is_empty() {
        b"stafeto\0".as_slice()
    } else {
        args.own
    };
    if input.len() > bytes.len() || input.last() != Some(&0) {
        rt::println!("POSIX startup: unterminated arguments");
        return 125;
    }
    bytes[..input.len()].copy_from_slice(input);
    let mut count = 0;
    let mut first = 0;
    for (index, &byte) in input.iter().enumerate() {
        if byte != 0 {
            continue;
        }
        if count == arguments.len() - 1 {
            rt::println!("POSIX startup: too many arguments");
            return 125;
        }
        // SAFETY: each pointer names a NUL-terminated part of the live bytes array.
        arguments[count] = unsafe { bytes.as_mut_ptr().add(first).cast() };
        first = index + 1;
        count += 1;
    }
    let Ok(session) = start.take::<Channel>(posix_abi::process::START_NAME) else {
        rt::println!("POSIX startup: no session with the process service");
        return 125;
    };
    PARENT.store(start.parent.raw().0, Ordering::Release);
    // The identity session: a process whose start data has none gives no
    // service a way to ask who it is.
    let identity = start
        .take::<Channel>(posix_abi::process::IDENTITY_NAME)
        .ok();
    // SAFETY: the main thread, once, before any other; the start channel
    // stays in `start` until main returned.
    if let Err(why) = unsafe {
        posix_init_process(
            session,
            identity,
            &start.parent,
            start.process,
            start.thread,
        )
    } {
        rt::println!("POSIX startup: {}", why);
        return 125;
    }
    posix_abi::fork::at_child(forked);
    start_relibc(&arguments[..count])
}
