// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The protocol of the loader (spec 2, 3.2): a small program of the boot
//! image that the process service maps into a new POSIX process, in the
//! region from LOADER_BASE, and starts there. The loader makes its own
//! start channel C, and the parent gets a copy of it with SEND and label
//! 1; the service gets one with NOTIFY and label 2, through which it says
//! "the record is ready". Through C, label 1, version VERSION:
//!
//! - Start: body the length of the block u32 and one handle, a memory
//!   object with MAP_READ that holds the block (`Block`) from its first
//!   byte. The loader copies the block into the new process and only then
//!   checks it; reply its status, BAD_SIZE for a block out of the layout
//!   or a second Start.
//! - Go: no body. The loader opens the program's file through the session
//!   of the loaders (proto_fs OpenExec), reads it and makes its segments,
//!   stack and start area, all paid by the new process; reply 0 for "the
//!   image is ready", or one of the codes below.
//! - Handles: body the slot of each handle u32 (`Slot::Files`, `Clock`,
//!   `Driver`, `Pipes`, `Terminal`, `Entropy`, each once over all Handles) and as many
//!   handles, sessions with SEND, after "the image is ready" (after Fork for
//!   a copy); reply its status. One message takes abi::MESSAGE_HANDLES
//!   handles at most: additional sessions goes in a second Handles.
//! - Fork, in place of Start (spec 2, 3.2; 5d): body `Fork`, the copy of
//!   the parent's memory the loader makes for a `fork`; reply its status,
//!   BAD_SIZE past REGIONS_MAX regions or a second Fork or Start.
//! - Regions, after Fork: body an entry (`Region`, REGION bytes) for each
//!   of its handles, one to four memory objects of the parent's memory map
//!   with MAP_READ, each at least the entry's pages long; the loader takes
//!   an entry only inside the layout of a program (`room_of`) and apart
//!   from those it has; reply its status. Go after Fork copies every
//!   region into objects of the new process, which pays for them, at the
//!   parent's addresses with the parent's access, adjacent writable ones
//!   in one object (`groups`), once the regions are all there and
//!   `check_fork` holds; reply 0 for "the copy is ready", NO_MEMORY or
//!   BAD_SIZE.
//!
//! The loader trusts no handle of C for its own requests: its session with
//! the process service, the session of the loaders and its identity come
//! from the service. Once "the record is ready" came through label 2 it
//! asks the service for the program's sessions (proto_process Take),
//! writes the start area (`Start`), closes everything that was its own,
//! unmaps its data and stack and jumps to the program's entry with x0 =
//! START_AREA. The program's start (posix-crt) reads the area. The end of
//! a copy writes the transfer (`write_transfer`) at the address Fork named
//! and jumps to Fork's `pc` with its `sp` and x0 = 0.
//!
//! The conditions of OpenExec (spec 2, 3.2), which the code names O1 to
//! O8: O1 only the loaders' session and a loader's identity open; O2 the
//! loader takes its own handles from the service alone; O3 the file
//! service resolves, checks and opens in one step; O4 SetId lives in the
//! loader's place and goes with the attempt; O5 a loader's identity
//! proves something only until SpawnCommit; O6 the loader closes all of
//! its own before the jump; O7 a set-ID program starts in the secure mode;
//! O8 writable files (step 5g) keep the opened node.

#![cfg_attr(not(test), no_std)]

use core::ops::Range;
use proto_wire::{Header, Reader, Status};

pub const VERSION: u16 = 2;

/// The region of the loader: 16 MiB under the top of a process's lower
/// half (spec 2, 3.2), which no program's segment may take.
pub const LOADER_BASE: u64 = (1 << 48) - (16 << 20);
pub const LOADER_END: u64 = 1 << 48;
/// The pages a program's segments may take: below the fixed addresses of
/// the POSIX layer (its buffers of the threads from 0x200_0000, the page of
/// the record, the clock's pages, the heap), the start area and the stack.
pub const PROGRAM_ROOM: Range<u64> = 0x1000..0x0200_0000;
/// The program's main stack: right under abi::INIT_STACK_TOP, with the
/// guard page below it unmapped.
pub const STACK_SIZE: u64 = 64 * 1024;
/// The start area (`Start`), which the loader makes and fills.
pub const START_AREA: u64 = 0xF000_0000;
/// The most bytes of the start area: the area itself and the copy of the
/// block the loader made it from.
pub const AREA_MAX: u64 = 0x4_0000;
/// {ARG_MAX}: the bytes of the strings of `argv` and `envp` with their NULs
/// and of their pointers with the two NULLs (E2BIG past it).
pub const ARG_MAX: usize = 64 * 1024;
/// The longest path a block carries, without its NUL (proto_fs::MAX_PATH).
pub const PATH_MAX: usize = 511;
/// The most bytes of a block: the header, the path, the current directory
/// and the strings.
pub const BLOCK_MAX: usize = HEADER + 2 * PATH_MAX + DESCRIPTORS * DESCRIPTOR + ARG_MAX;
/// The descriptors a block carries at most, and the bytes of each: the
/// number u32, what it names u32 (`Names`) and the service's number of its
/// open description u32.
pub const DESCRIPTORS: usize = 32;
pub const DESCRIPTOR: usize = 12;

/// What a descriptor of a block names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Names {
    Input,
    Output,
    Error,
    /// The open description of this number in the session of the RAM file
    /// service the child gets (Clone shares it).
    File(u32),
    /// The end of a pipe of this number in the session of the pipe
    /// service the child gets, which holds it (5e). The loader takes the
    /// kind only with a session in the slot Pipes.
    Pipe(u32),
    /// The terminal of this number of the terminal service, which the
    /// child's session in the slot Terminal serves (5f); the loader takes
    /// the kind only with that session.
    Terminal(u32),
    /// The open description of this number of a random device (5e'), in
    /// the same session of the RAM file service as `File`; the child's
    /// layer serves its reads from its own generator.
    Random(u32),
}

/// A descriptor the child starts with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub fd: u32,
    pub names: Names,
}

impl Descriptor {
    fn bytes(&self) -> [u8; DESCRIPTOR] {
        let (kind, file) = match self.names {
            Names::Input => (0, 0),
            Names::Output => (1, 0),
            Names::Error => (2, 0),
            Names::File(n) => (3, n),
            Names::Pipe(n) => (4, n),
            Names::Terminal(n) => (5, n),
            Names::Random(n) => (6, n),
        };
        let mut out = [0; DESCRIPTOR];
        out[..4].copy_from_slice(&self.fd.to_le_bytes());
        out[4..8].copy_from_slice(&u32::to_le_bytes(kind));
        out[8..].copy_from_slice(&file.to_le_bytes());
        out
    }

    /// The descriptor in `bytes`: a number below DESCRIPTORS and a kind it
    /// knows, or None.
    pub fn read(bytes: &[u8]) -> Option<Descriptor> {
        let word = |i: usize| u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap());
        let fd = word(0);
        let names = match (word(1), word(2)) {
            (0, 0) => Names::Input,
            (1, 0) => Names::Output,
            (2, 0) => Names::Error,
            (3, n) => Names::File(n),
            (4, n) => Names::Pipe(n),
            (5, n) => Names::Terminal(n),
            (6, n) => Names::Random(n),
            _ => return None,
        };
        ((fd as usize) < DESCRIPTORS).then_some(Descriptor { fd, names })
    }
}
/// The bytes of the header of a block.
pub const HEADER: usize = 72;

/// What an exec carries to the new image besides `argv` and `envp` ([P24-
/// EXEC], spec 2, 3.2 step 2): the signals pending for the calling thread,
/// the word of the timers that expired with no delivery yet, and the
/// absolute deadline of `alarm` by the counter (0 for none). Timers and
/// `alarm` come with step 5h: until then both are 0. A spawn carries none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Carried {
    pub pending: u64,
    pub timers: u64,
    pub alarm: u64,
}

/// The methods through C.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Method {
    Start = 1,
    Go = 2,
    Handles = 3,
    Fork = 4,
    Regions = 5,
    TerminalActions = 6,
}

impl Method {
    pub const fn header(self) -> Header {
        Header {
            version: VERSION,
            method: self as u16,
        }
    }

    pub const fn from_number(n: u16) -> Option<Method> {
        match n {
            1 => Some(Method::Start),
            2 => Some(Method::Go),
            3 => Some(Method::Handles),
            4 => Some(Method::Fork),
            5 => Some(Method::Regions),
            6 => Some(Method::TerminalActions),
            _ => None,
        }
    }
}

/// The label of the parent's copy of C, and of the service's.
pub const PARENT: u64 = 1;
pub const SERVICE: u64 = 2;

/// The codes of a reply to Go that is no "the image is ready": ENOENT,
/// EACCES, ENOEXEC, ENOMEM, E2BIG, ENAMETOOLONG, EPERM, EIO, ENOTDIR.
pub const NO_ENTRY: u32 = 600;
pub const ACCESS: u32 = 601;
pub const NOT_EXEC: u32 = 602;
pub const NO_MEMORY: u32 = 603;
pub const TOO_BIG: u32 = 604;
pub const NAME_TOO_LONG: u32 = 605;
pub const PERMISSION: u32 = 606;
pub const IO: u32 = 607;
pub const NOT_DIRECTORY: u32 = 608;
pub const NO_CONTROLLING: u32 = 609;

/// Terminal opens run in the loader after SpawnStart and before OpenExec.
/// Keep all accepted opens, including those later closed or CLOEXEC.
/// Terminal numbers reserve this path for future PTY names as well.
pub const TERMINAL_ACTIONS: usize = 32;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TerminalOpen {
    pub terminal: u32,
    pub controlling: bool,
    pub no_ctty: bool,
}

impl TerminalOpen {
    pub fn write(self, w: &mut proto_wire::Writer) -> Result<(), Status> {
        w.u32(self.terminal)?;
        w.u32(u32::from(self.controlling) | u32::from(self.no_ctty) << 1)
    }

    pub fn read(r: &mut Reader<'_>) -> Result<Self, Status> {
        let terminal = r.u32()?;
        let flags = r.u32()?;
        if flags & !3 != 0 {
            return Err(Status::BadSize);
        }
        Ok(Self {
            terminal,
            controlling: flags & 1 != 0,
            no_ctty: flags & 2 != 0,
        })
    }
}

/// The handles of the start area, by their place in `Start::handles`; the
/// sessions the parent gives with Handles are Files, Clock, Driver (the
/// console's driver), Pipes (5e) Terminal (the terminal service, 5f), and Entropy (5e').
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Slot {
    Process = 0,
    Thread = 1,
    Posix = 2,
    PosixId = 3,
    Files = 4,
    Clock = 5,
    Driver = 6,
    Console = 7,
    Pipes = 8,
    Terminal = 9,
    Entropy = 10,
}

/// The handles a start area names.
pub const SLOTS: usize = 11;

impl Slot {
    /// The sessions Handles brings, in their order.
    pub const GIVEN: [Slot; 6] = [
        Slot::Files,
        Slot::Clock,
        Slot::Driver,
        Slot::Pipes,
        Slot::Terminal,
        Slot::Entropy,
    ];

    /// The slot of a handle Handles brings: Files, Clock, Driver, Pipes or
    /// Terminal or Entropy.
    pub const fn given(n: u32) -> Option<Slot> {
        match n {
            4 => Some(Slot::Files),
            5 => Some(Slot::Clock),
            6 => Some(Slot::Driver),
            8 => Some(Slot::Pipes),
            9 => Some(Slot::Terminal),
            10 => Some(Slot::Entropy),
            _ => None,
        }
    }
}

/// The slots of the handles of a Handles request with `count` handles:
/// one u32 each, each a slot the parent gives (`Slot::given`) and none
/// twice; BAD_SIZE otherwise, or for more than abi::MESSAGE_HANDLES.
pub fn handle_slots(
    mut body: Reader<'_>,
    count: usize,
) -> Result<[Option<Slot>; abi::MESSAGE_HANDLES], Status> {
    let mut slots = [None; abi::MESSAGE_HANDLES];
    for i in 0..count {
        let slot = Slot::given(body.u32()?).ok_or(Status::BadSize)?;
        if slots[..i].contains(&Some(slot)) {
            return Err(Status::BadSize);
        }
        *slots.get_mut(i).ok_or(Status::BadSize)? = Some(slot);
    }
    body.finish()?;
    Ok(slots)
}

/// Why a block is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockError {
    /// Out of the layout: a field past the bytes, a count of strings that
    /// is not the count of their NULs, a path that is empty or holds a NUL,
    /// a current directory that is not absolute.
    Malformed,
    /// The strings and pointers of `argv` and `envp` pass ARG_MAX.
    TooBig,
    /// A path or the current directory longer than PATH_MAX.
    NameTooLong,
}

const MAGIC: [u8; 8] = *b"STAFSPWN";
const BLOCK_VERSION: u32 = 1;

/// The bytes of `argv` and `envp` as {ARG_MAX} counts them: their
/// strings with the NULs and a pointer for each and for the two NULLs.
pub const fn arg_size(argc: usize, envc: usize, strings: usize) -> usize {
    strings + 8 * (argc + envc + 2)
}

/// What the parent gives the loader (spec 2, 3.2): the path of the
/// program and the parent's current directory, its umask, `argv`, `envp`
/// and the descriptors the child starts with. The layout: the signature
/// `STAFSPWN`, the version u32, the length u32, the umask u32, argc u32,
/// envc u32, the length of the path u32, of the current directory u32, of
/// the strings u32, the count of descriptors u32 and 4 zero bytes; then
/// the path, the current directory (empty or absolute), the descriptors
/// (`Descriptor`, DESCRIPTOR bytes each, distinct numbers), and the
/// strings of `argv` and then `envp`, each with its NUL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Block<'a> {
    pub umask: u32,
    pub path: &'a [u8],
    pub cwd: &'a [u8],
    pub argc: usize,
    pub envc: usize,
    pub carried: Carried,
    descriptors: &'a [u8],
    strings: &'a [u8],
}

impl<'a> Block<'a> {
    /// The bytes a block of these lengths takes.
    pub const fn len(path: usize, cwd: usize, strings: usize) -> usize {
        HEADER + path + cwd + strings
    }

    /// The descriptors the child starts with.
    /// Whether the block's descriptors need a session in `slot` to mean
    /// anything: a RAM file needs Files, a pipe needs Pipes (5e), and a
    /// terminal needs Terminal (5f). The loader answers a Handles that leaves such a
    /// slot empty with BAD_SIZE.
    pub fn needs(&self, slot: Slot) -> bool {
        self.descriptors().any(|d| {
            matches!(
                (slot, d.names),
                (Slot::Files, Names::File(_))
                    | (Slot::Pipes, Names::Pipe(_))
                    | (Slot::Terminal, Names::Terminal(_))
            )
        })
    }

    pub fn descriptors(&self) -> impl Iterator<Item = Descriptor> + 'a {
        self.descriptors
            .as_chunks::<DESCRIPTOR>()
            .0
            .iter()
            .filter_map(|chunk| Descriptor::read(chunk))
    }

    /// `write` with the descriptors `descriptors` (DESCRIPTORS at most).
    #[allow(clippy::too_many_arguments)]
    pub fn write_with<'s>(
        out: &mut [u8],
        path: &[u8],
        cwd: &[u8],
        umask: u32,
        argv: impl Iterator<Item = &'s [u8]> + Clone,
        envp: impl Iterator<Item = &'s [u8]> + Clone,
        descriptors: &[Descriptor],
    ) -> Result<usize, BlockError> {
        if descriptors.len() > DESCRIPTORS {
            return Err(BlockError::Malformed);
        }
        let len = Self::write(out, path, cwd, umask, argv, envp)?;
        let extra = DESCRIPTOR * descriptors.len();
        let at = HEADER + path.len() + cwd.len();
        let total = len + extra;
        let out = out.get_mut(..total).ok_or(BlockError::Malformed)?;
        out.copy_within(at..len, at + extra);
        for (i, d) in descriptors.iter().enumerate() {
            out[at + DESCRIPTOR * i..at + DESCRIPTOR * (i + 1)].copy_from_slice(&d.bytes());
        }
        out[12..16].copy_from_slice(&(total as u32).to_le_bytes());
        out[40..44].copy_from_slice(&(descriptors.len() as u32).to_le_bytes());
        Ok(total)
    }

    /// Writes the block of `path`, `cwd`, `umask`, `argv` and `envp` (each
    /// string without its NUL) into `out`; its length. TooBig past
    /// ARG_MAX, NameTooLong for a path or a current directory past
    /// PATH_MAX, Malformed for an empty path, a NUL in a string or `out`
    /// too short.
    pub fn write<'s>(
        out: &mut [u8],
        path: &[u8],
        cwd: &[u8],
        umask: u32,
        argv: impl Iterator<Item = &'s [u8]> + Clone,
        envp: impl Iterator<Item = &'s [u8]> + Clone,
    ) -> Result<usize, BlockError> {
        if path.len() > PATH_MAX || cwd.len() > PATH_MAX {
            return Err(BlockError::NameTooLong);
        }
        if path.is_empty() || path.contains(&0) || cwd.contains(&0) {
            return Err(BlockError::Malformed);
        }
        let (mut argc, mut envc, mut strings) = (0usize, 0usize, 0usize);
        for s in argv.clone() {
            argc += 1;
            strings += s.len() + 1;
        }
        for s in envp.clone() {
            envc += 1;
            strings += s.len() + 1;
        }
        if arg_size(argc, envc, strings) > ARG_MAX {
            return Err(BlockError::TooBig);
        }
        let len = Self::len(path.len(), cwd.len(), strings);
        let out = out.get_mut(..len).ok_or(BlockError::Malformed)?;
        out[..8].copy_from_slice(&MAGIC);
        out[48..HEADER].fill(0);
        let words = [
            BLOCK_VERSION,
            len as u32,
            umask,
            argc as u32,
            envc as u32,
            path.len() as u32,
            cwd.len() as u32,
            strings as u32,
            0,
            0,
        ];
        for (i, w) in words.iter().enumerate() {
            out[8 + 4 * i..12 + 4 * i].copy_from_slice(&w.to_le_bytes());
        }
        let mut at = HEADER;
        for part in [path, cwd] {
            out[at..at + part.len()].copy_from_slice(part);
            at += part.len();
        }
        for s in argv.chain(envp) {
            if s.contains(&0) {
                return Err(BlockError::Malformed);
            }
            out[at..at + s.len()].copy_from_slice(s);
            out[at + s.len()] = 0;
            at += s.len() + 1;
        }
        Ok(len)
    }

    /// The block in `bytes`, all of them: the loader reads it from its own
    /// copy, never from the parent's object.
    pub fn read(bytes: &'a [u8]) -> Result<Block<'a>, BlockError> {
        let header = bytes.get(..HEADER).ok_or(BlockError::Malformed)?;
        if header[..8] != MAGIC {
            return Err(BlockError::Malformed);
        }
        let word = |i: usize| {
            let mut w = [0; 4];
            w.copy_from_slice(&header[8 + 4 * i..12 + 4 * i]);
            u32::from_le_bytes(w) as usize
        };
        let (version, len, umask, argc, envc) = (word(0), word(1), word(2), word(3), word(4));
        let (path_len, cwd_len, strings_len) = (word(5), word(6), word(7));
        let count = word(8);
        if version != BLOCK_VERSION as usize || count > DESCRIPTORS || word(9) != 0 {
            return Err(BlockError::Malformed);
        }
        if path_len > PATH_MAX || cwd_len > PATH_MAX {
            return Err(BlockError::NameTooLong);
        }
        let total = HEADER
            .checked_add(path_len)
            .and_then(|n| n.checked_add(cwd_len))
            .and_then(|n| n.checked_add(DESCRIPTOR * count))
            .and_then(|n| n.checked_add(strings_len));
        if total != Some(len) || len != bytes.len() {
            return Err(BlockError::Malformed);
        }
        if arg_size(argc, envc, strings_len) > ARG_MAX {
            return Err(BlockError::TooBig);
        }
        let path = &bytes[HEADER..HEADER + path_len];
        let cwd = &bytes[HEADER + path_len..HEADER + path_len + cwd_len];
        let at = HEADER + path_len + cwd_len;
        let descriptors = &bytes[at..at + DESCRIPTOR * count];
        let strings = &bytes[at + DESCRIPTOR * count..];
        let mut seen = 0u64;
        for chunk in descriptors.as_chunks::<DESCRIPTOR>().0 {
            let d = Descriptor::read(chunk).ok_or(BlockError::Malformed)?;
            if seen & 1 << d.fd != 0 {
                return Err(BlockError::Malformed);
            }
            seen |= 1 << d.fd;
        }
        let nuls = strings.iter().filter(|&&b| b == 0).count();
        let well_formed = !path.is_empty()
            && !path.contains(&0)
            && !cwd.contains(&0)
            && (cwd.is_empty() || cwd[0] == b'/')
            && nuls == argc + envc
            && strings.last().is_none_or(|&b| b == 0);
        if !well_formed {
            return Err(BlockError::Malformed);
        }
        let long = |at: usize| u64::from_le_bytes(header[at..at + 8].try_into().unwrap());
        Ok(Block {
            umask: umask as u32,
            path,
            cwd,
            argc,
            envc,
            carried: Carried {
                pending: long(48),
                timers: long(56),
                alarm: long(64),
            },
            descriptors,
            strings,
        })
    }

    /// Writes `carried` into the block `out` that `write` or `write_with`
    /// made.
    pub fn carry(out: &mut [u8], carried: Carried) -> Result<(), BlockError> {
        let header = out.get_mut(..HEADER).ok_or(BlockError::Malformed)?;
        for (at, value) in [
            (48, carried.pending),
            (56, carried.timers),
            (64, carried.alarm),
        ] {
            header[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        Ok(())
    }

    /// The strings of `argv` and then of `envp`, each with its NUL.
    pub fn strings(&self) -> &'a [u8] {
        self.strings
    }

    /// The path the loader opens: the path when it is absolute, else the
    /// current directory and the path joined by one slash, into `out`;
    /// NameTooLong past PATH_MAX. `..` and links are the file service's to
    /// resolve.
    pub fn full_path<'o>(&self, out: &'o mut [u8; PATH_MAX]) -> Result<&'o [u8], BlockError> {
        let parts: [&[u8]; 3] = if self.path[0] == b'/' {
            [self.path, b"", b""]
        } else if self.cwd.is_empty() || self.cwd.last() == Some(&b'/') {
            [
                if self.cwd.is_empty() { b"/" } else { self.cwd },
                self.path,
                b"",
            ]
        } else {
            [self.cwd, b"/", self.path]
        };
        let len: usize = parts.iter().map(|p| p.len()).sum();
        if len > PATH_MAX {
            return Err(BlockError::NameTooLong);
        }
        let mut at = 0;
        for p in parts {
            out[at..at + p.len()].copy_from_slice(p);
            at += p.len();
        }
        Ok(&out[..len])
    }
}

/// The block of the parent's `len` bytes, which `source` gives byte by
/// byte: each is read once, into `copy`, and the block is read from the
/// copy alone, so a parent that writes its object meanwhile
/// changes nothing the loader checked. Malformed for a `copy` too short.
pub fn copy_block<'a>(
    source: impl Fn(usize) -> u8,
    len: usize,
    copy: &'a mut [u8],
) -> Result<Block<'a>, BlockError> {
    let copy = copy.get_mut(..len).ok_or(BlockError::Malformed)?;
    for (i, byte) in copy.iter_mut().enumerate() {
        *byte = source(i);
    }
    Block::read(copy)
}

/// The start area's header at START_AREA, which the program's start reads
/// (posix-crt): what the loader wrote for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Start {
    pub magic: [u8; 8],
    pub version: u32,
    /// SECURE: the program runs with a real ID other than the effective
    /// one, the secure mode of a set-ID program (AT_SECURE).
    pub flags: u32,
    pub umask: u32,
    pub argc: u32,
    /// The current directory, a C string; 0 for none.
    pub cwd: u64,
    /// The initial stack of a Linux process for the C library's start:
    /// argc, `argv`, NULL, `envp`, NULL, then AUXV_PAIRS pairs of zeros
    /// at `auxv` for the start to fill.
    pub stack: u64,
    pub auxv: u64,
    /// The values of the handles, by `Slot`; 0 for none.
    pub handles: [u64; SLOTS],
    /// The descriptors the program starts with (`Descriptor`, DESCRIPTOR
    /// bytes each) and their count.
    pub descriptors: u64,
    pub descriptor_count: u32,
    /// The entries of the memory map the loader hands over (`MapEntry`,
    /// MAP_ENTRY bytes each) and their count, at most MAP_ENTRIES.
    pub map_count: u32,
    /// What an exec carried (`Carried`), all 0 for a spawn.
    pub pending: u64,
    pub timers: u64,
    pub alarm: u64,
    pub map: u64,
    /// Zero: the initial stack after the header stays on 16 bytes.
    pub reserved: u64,
}

pub const START_MAGIC: [u8; 8] = *b"STAFSTRT";
pub const START_VERSION: u32 = 4;
pub const SECURE: u32 = 1;
/// The pairs of the auxiliary vector the start may fill.
pub const AUXV_PAIRS: usize = 8;
/// The bytes of the header.
pub const START_SIZE: usize = core::mem::size_of::<Start>();
const _: () = assert!(START_SIZE == 192);

/// The entries of the memory map the loader hands over at most: the three
/// segments of a program, its stack and the start area itself.
pub const MAP_ENTRIES: usize = 5;
/// The bytes of an entry: the address u64, the pages u32, the access u32
/// (abi::Access) and the handle's value u64.
pub const MAP_ENTRY: usize = 24;

/// One mapped memory object the loader hands the program (spec 2, 3.2):
/// `pages` whole pages at `address` mapped with `access`, and the value of
/// a handle to the object that holds MAP_READ, DUPLICATE and TRANSFER
/// (and MAP_WRITE for a writable part) for the layer's map (posix-map). A
/// handle never has MAP_EXEC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapEntry {
    pub address: u64,
    pub pages: u32,
    pub access: abi::Access,
    pub handle: u64,
}

impl MapEntry {
    pub fn to_bytes(self) -> [u8; MAP_ENTRY] {
        let mut out = [0; MAP_ENTRY];
        out[..8].copy_from_slice(&self.address.to_le_bytes());
        out[8..12].copy_from_slice(&self.pages.to_le_bytes());
        out[12..16].copy_from_slice(&(self.access.raw() as u32).to_le_bytes());
        out[16..].copy_from_slice(&self.handle.to_le_bytes());
        out
    }

    /// The entry of `bytes`; None for no pages or an access that is none.
    pub fn read(bytes: &[u8; MAP_ENTRY]) -> Option<MapEntry> {
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let long = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        let access = abi::Access::from_raw(word(12).into())?;
        (word(8) > 0).then_some(MapEntry {
            address: long(0),
            pages: word(8),
            access,
            handle: long(16),
        })
    }
}

/// The bytes of the start area of `block`: the header, the initial stack,
/// room for MAP_ENTRIES entries of the map and the strings, rounded up to
/// 16.
pub const fn area_len(block: &Block<'_>) -> usize {
    let stack = 8 * (1 + block.argc + 1 + block.envc + 1 + 2 * AUXV_PAIRS);
    let strings = block.cwd.len() + 1 + block.strings.len() + block.descriptors.len();
    (START_SIZE + stack + MAP_ENTRIES * MAP_ENTRY + strings).next_multiple_of(16)
}

/// Writes the start area of `block` into `area`, which lies at `at` in the
/// program's space: the header with `flags` and `handles`, the initial
/// stack, the `maps` entries and the strings it points to. Malformed when
/// `area` is shorter than `area_len` or `maps` holds more than MAP_ENTRIES.
pub fn write_area(
    area: &mut [u8],
    at: u64,
    block: &Block<'_>,
    flags: u32,
    handles: [u64; SLOTS],
    maps: &[MapEntry],
) -> Result<(), BlockError> {
    let len = area_len(block);
    let area = area.get_mut(..len).ok_or(BlockError::Malformed)?;
    if maps.len() > MAP_ENTRIES {
        return Err(BlockError::Malformed);
    }
    let stack_at = START_SIZE;
    let words = 1 + block.argc + 1 + block.envc + 1 + 2 * AUXV_PAIRS;
    let maps_at = stack_at + 8 * words;
    for (i, entry) in maps.iter().enumerate() {
        area[maps_at + i * MAP_ENTRY..maps_at + (i + 1) * MAP_ENTRY]
            .copy_from_slice(&entry.to_bytes());
    }
    let strings_at = maps_at + MAP_ENTRIES * MAP_ENTRY;
    // The strings: the current directory, then those of the block.
    let cwd_at = strings_at;
    area[cwd_at..cwd_at + block.cwd.len()].copy_from_slice(block.cwd);
    area[cwd_at + block.cwd.len()] = 0;
    let copied_at = cwd_at + block.cwd.len() + 1;
    area[copied_at..copied_at + block.strings.len()].copy_from_slice(block.strings);
    let descriptors_at = copied_at + block.strings.len();
    area[descriptors_at..descriptors_at + block.descriptors.len()]
        .copy_from_slice(block.descriptors);
    let mut word = |i: usize, value: u64| {
        area[stack_at + 8 * i..stack_at + 8 * i + 8].copy_from_slice(&value.to_le_bytes());
    };
    word(0, block.argc as u64);
    // The pointers of argv, NULL, those of envp, NULL; the strings follow
    // one another, each ended by its NUL.
    let (mut index, mut start, mut n) = (1, copied_at, 0);
    for (i, _) in block.strings.iter().enumerate().filter(|(_, b)| **b == 0) {
        if n == block.argc {
            word(index, 0);
            index += 1;
        }
        word(index, at + start as u64);
        index += 1;
        start = copied_at + i + 1;
        n += 1;
    }
    if n == block.argc {
        word(index, 0);
        index += 1;
    }
    word(index, 0);
    index += 1;
    let auxv = index;
    for i in 0..2 * AUXV_PAIRS {
        word(auxv + i, 0);
    }
    let header = Start {
        magic: START_MAGIC,
        version: START_VERSION,
        flags,
        umask: block.umask,
        argc: block.argc as u32,
        cwd: if block.cwd.is_empty() {
            0
        } else {
            at + cwd_at as u64
        },
        stack: at + stack_at as u64,
        auxv: at + (stack_at + 8 * auxv) as u64,
        handles,
        descriptors: at + descriptors_at as u64,
        descriptor_count: (block.descriptors.len() / DESCRIPTOR) as u32,
        map_count: maps.len() as u32,
        pending: block.carried.pending,
        timers: block.carried.timers,
        alarm: block.carried.alarm,
        map: at + maps_at as u64,
        reserved: 0,
    };
    // SAFETY: Start is repr(C) of integers and bytes with no padding
    // (START_SIZE is the sum of its fields), so its bytes are its value.
    let bytes: [u8; START_SIZE] = unsafe { core::mem::transmute(header) };
    area[..START_SIZE].copy_from_slice(&bytes);
    Ok(())
}

impl Start {
    /// The header at the start of `area`, when it has the signature and
    /// the version.
    pub fn read(area: &[u8]) -> Option<Start> {
        let bytes: [u8; START_SIZE] = area.get(..START_SIZE)?.try_into().ok()?;
        // SAFETY: any bytes are a value of Start, which holds integers and
        // bytes alone.
        let start: Start = unsafe { core::mem::transmute(bytes) };
        (start.magic == START_MAGIC && start.version == START_VERSION).then_some(start)
    }
}

/// The regions a copy takes at most: the kernel's mappings of a process
/// (abi::MAX_MAPPINGS), which the layer's map holds at most (posix-map).
pub const REGIONS_MAX: usize = abi::MAX_MAPPINGS as usize;
/// The bytes of an entry of Regions: the address u64, the pages u32 and
/// the access u32 (abi::Access).
pub const REGION: usize = 16;
/// The heap of the POSIX layer, where the chunks of its map lie.
pub const HEAP_ROOM: Range<u64> = 0x1000_0000..0x2000_0000;
/// The rooms of a program's layout a region of a copy lies in, each whole
/// in one: the segments, the layer's heap, the start area and the main
/// stack. The loader's region, the page of the record, the clock's page
/// and the buffers of the threads lie in none.
pub const ROOMS: [Range<u64>; 4] = [
    PROGRAM_ROOM,
    HEAP_ROOM,
    START_AREA..START_AREA + AREA_MAX,
    abi::INIT_STACK_TOP - STACK_SIZE..abi::INIT_STACK_TOP,
];

/// One region of the parent's memory a copy takes: `pages` whole pages
/// from `address`, mapped with `access`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub address: u64,
    pub pages: u32,
    pub access: abi::Access,
}

impl Region {
    /// The first address past the region.
    pub const fn end(&self) -> u64 {
        self.address.saturating_add(self.pages as u64 * PAGE)
    }

    pub fn write(&self, w: &mut proto_wire::Writer) -> Result<(), Status> {
        w.u64(self.address)?;
        w.u32(self.pages)?;
        w.u32(self.access.raw() as u32)
    }

    /// BAD_SIZE out of the layout, for no pages or an access that is
    /// none.
    pub fn read(r: &mut Reader<'_>) -> Result<Region, Status> {
        let (address, pages, access) = (r.u64()?, r.u32()?, r.u32()?);
        let access = abi::Access::from_raw(access.into()).ok_or(Status::BadSize)?;
        if pages == 0 {
            return Err(Status::BadSize);
        }
        Ok(Region {
            address,
            pages,
            access,
        })
    }

    /// Whether `address` lies in the region.
    pub const fn holds(&self, address: u64) -> bool {
        self.address <= address && address < self.end()
    }
}

const PAGE: u64 = 4096;

/// The room of ROOMS that holds all of `region`, which starts on a page;
/// None for none.
pub fn room_of(region: &Region) -> Option<usize> {
    if !region.address.is_multiple_of(PAGE) {
        return None;
    }
    let end = region.address.checked_add(region.pages as u64 * PAGE)?;
    ROOMS
        .iter()
        .position(|room| room.start <= region.address && end <= room.end)
}

/// Whether a copy that holds `held` takes `region` too: inside a room
/// (`room_of`), apart from every region it holds, and fewer than
/// REGIONS_MAX before it; BAD_SIZE otherwise.
pub fn admit(held: &[Region], region: &Region) -> Result<(), Status> {
    if held.len() >= REGIONS_MAX || room_of(region).is_none() {
        return Err(Status::BadSize);
    }
    if held
        .iter()
        .any(|h| h.address < region.end() && region.address < h.end())
    {
        return Err(Status::BadSize);
    }
    Ok(())
}

/// Whether a handle of Regions names what a region may be copied from: a
/// memory object with MAP_READ. A window on a device's registers, any
/// other kind and a memory object the loader may not read are refused.
/// (A buffer of a device made with MEM_CONTIGUOUS is a memory object the
/// kernel shows as any other; a POSIX process has none: it holds no device
/// resource.)
pub fn region_object(kind: abi::ObjectKind, rights: abi::Rights) -> bool {
    kind == abi::ObjectKind::Memory && rights.contains(abi::Rights::MAP_READ)
}

/// The body of Fork: where the copy goes on, the address `pc` of the
/// layer's code it jumps to with the stack pointer `sp` and x0 = 0, the
/// address `transfer` of TRANSFER_SIZE bytes of the layer's data the
/// loader writes the child's handles into (`write_transfer`), and how many
/// regions Regions brings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fork {
    pub pc: u64,
    pub sp: u64,
    pub transfer: u64,
    pub regions: u32,
}

impl Fork {
    pub fn write(&self, w: &mut proto_wire::Writer) -> Result<(), Status> {
        w.u64(self.pc)?;
        w.u64(self.sp)?;
        w.u64(self.transfer)?;
        w.u32(self.regions)
    }

    /// BAD_SIZE out of the layout, for no regions or past REGIONS_MAX.
    pub fn read(mut r: Reader<'_>) -> Result<Fork, Status> {
        let (pc, sp, transfer, regions) = (r.u64()?, r.u64()?, r.u64()?, r.u32()?);
        r.finish()?;
        if regions == 0 || regions as usize > REGIONS_MAX {
            return Err(Status::BadSize);
        }
        Ok(Fork {
            pc,
            sp,
            transfer,
            regions,
        })
    }
}

/// Whether the copy of `fork` may go with the regions `held`, all of
/// them come: `pc` in code (ReadExec) on an instruction, `sp` in or at the
/// top of a writable region and 16-byte aligned, and the transfer whole in
/// one writable region and 8-byte aligned; BAD_SIZE otherwise.
pub fn check_fork(fork: &Fork, held: &[Region]) -> Result<(), Status> {
    use abi::Access::{ReadExec, ReadWrite};
    let fits = held.len() == fork.regions as usize
        && fork.pc.is_multiple_of(4)
        && held
            .iter()
            .any(|r| r.access == ReadExec && r.holds(fork.pc))
        && fork.sp.is_multiple_of(16)
        && held
            .iter()
            .any(|r| r.access == ReadWrite && r.address < fork.sp && fork.sp <= r.end())
        && fork.transfer.is_multiple_of(8)
        && fork
            .transfer
            .checked_add(TRANSFER_SIZE as u64)
            .is_some_and(|end| {
                held.iter()
                    .any(|r| r.access == ReadWrite && r.address <= fork.transfer && end <= r.end())
            });
    if fits { Ok(()) } else { Err(Status::BadSize) }
}

/// The objects of a copy of `sorted`, regions sorted by address: the
/// range of the regions each takes, adjacent writable regions one object
/// (the chunks of the layer's heap), any other region one of its own.
pub fn groups(sorted: &[Region]) -> impl Iterator<Item = Range<usize>> + '_ {
    let mut at = 0;
    core::iter::from_fn(move || {
        let first = sorted.get(at)?;
        let start = at;
        at += 1;
        if first.access == abi::Access::ReadWrite {
            while let Some(next) = sorted.get(at) {
                if next.access != abi::Access::ReadWrite || next.address != sorted[at - 1].end() {
                    break;
                }
                at += 1;
            }
        }
        Some(start..at)
    })
}

/// The signature of a transfer.
pub const TRANSFER_MAGIC: [u8; 8] = *b"STAFFORK";
/// The bytes of a transfer: the signature, the child's handles by `Slot`
/// (u64 each, 0 for none), the count u32 of the entries of its memory
/// map and 4 zero bytes, then REGIONS_MAX entries (`MapEntry`).
pub const TRANSFER_SIZE: usize = 8 + 8 * SLOTS + 8 + REGIONS_MAX * MAP_ENTRY;

/// Writes the transfer of a copy into `out`: the child's `handles` by
/// `Slot` and the objects of its memory map, `map`, REGIONS_MAX at most;
/// Malformed otherwise or for `out` short of TRANSFER_SIZE.
pub fn write_transfer(
    out: &mut [u8],
    handles: [u64; SLOTS],
    map: &[MapEntry],
) -> Result<(), BlockError> {
    let out = out.get_mut(..TRANSFER_SIZE).ok_or(BlockError::Malformed)?;
    if map.len() > REGIONS_MAX {
        return Err(BlockError::Malformed);
    }
    out.fill(0);
    out[..8].copy_from_slice(&TRANSFER_MAGIC);
    for (i, h) in handles.iter().enumerate() {
        out[8 + 8 * i..16 + 8 * i].copy_from_slice(&h.to_le_bytes());
    }
    let count = 8 + 8 * SLOTS;
    out[count..count + 4].copy_from_slice(&(map.len() as u32).to_le_bytes());
    for (i, entry) in map.iter().enumerate() {
        let at = count + 8 + i * MAP_ENTRY;
        out[at..at + MAP_ENTRY].copy_from_slice(&entry.to_bytes());
    }
    Ok(())
}

/// The transfer a copy's loader wrote: the child's handles by `Slot` and
/// the objects of its memory map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transfer<'a> {
    pub handles: [u64; SLOTS],
    map: &'a [u8],
}

impl<'a> Transfer<'a> {
    /// The transfer in `bytes`, with its signature and a count up to
    /// REGIONS_MAX; None otherwise.
    pub fn read(bytes: &'a [u8]) -> Option<Transfer<'a>> {
        let bytes = bytes.get(..TRANSFER_SIZE)?;
        if bytes[..8] != TRANSFER_MAGIC {
            return None;
        }
        let mut handles = [0; SLOTS];
        for (i, h) in handles.iter_mut().enumerate() {
            *h = u64::from_le_bytes(bytes[8 + 8 * i..16 + 8 * i].try_into().ok()?);
        }
        let at = 8 + 8 * SLOTS;
        let count = u32::from_le_bytes(bytes[at..at + 4].try_into().ok()?) as usize;
        if count > REGIONS_MAX {
            return None;
        }
        Some(Transfer {
            handles,
            map: &bytes[at + 8..at + 8 + count * MAP_ENTRY],
        })
    }

    /// The entries of the child's memory map; a malformed one is left out.
    pub fn map(&self) -> impl Iterator<Item = MapEntry> + 'a {
        self.map
            .as_chunks::<MAP_ENTRY>()
            .0
            .iter()
            .filter_map(MapEntry::read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_wire::Writer;

    fn block(out: &mut [u8], argv: &[&[u8]], envp: &[&[u8]]) -> usize {
        Block::write(
            out,
            b"ls",
            b"/etc",
            0o022,
            argv.iter().copied(),
            envp.iter().copied(),
        )
        .unwrap()
    }

    #[test]
    fn a_block_round_trips() {
        let mut out = vec![0; BLOCK_MAX];
        let len = block(&mut out, &[b"ls", b"-l"], &[b"X=1"]);
        let read = Block::read(&out[..len]).unwrap();
        assert_eq!(
            (read.path, read.cwd, read.umask),
            (&b"ls"[..], &b"/etc"[..], 0o022)
        );
        assert_eq!((read.argc, read.envc), (2, 1));
        assert_eq!(read.strings(), b"ls\0-l\0X=1\0");
        let mut path = [0; PATH_MAX];
        assert_eq!(read.full_path(&mut path), Ok(&b"/etc/ls"[..]));
    }

    /// The loader checks its own copy: each field out of the layout is
    /// refused, and a length past the bytes it copied too.
    #[test]
    fn a_block_out_of_the_layout_is_refused() {
        let mut out = vec![0; BLOCK_MAX];
        let len = block(&mut out, &[b"ls"], &[]);
        let good = out[..len].to_vec();
        assert_eq!(Block::read(&good[..len - 1]), Err(BlockError::Malformed));
        for (at, value) in [
            (0, b'x'),
            (8, 2),
            (12, 0xFF),
            (20, 2),
            (24, 1),
            (28, 0),
            (40, 1),
        ] {
            let mut bad = good.clone();
            bad[at] = value;
            assert!(Block::read(&bad).is_err(), "byte {at}");
        }
        // A length that runs past the copy.
        let mut bad = good.clone();
        bad[12..16].copy_from_slice(&(len as u32 + 4096).to_le_bytes());
        assert_eq!(Block::read(&bad), Err(BlockError::Malformed));
        // A header whose fields agree, past the bytes that were copied.
        assert_eq!(Block::read(&good[..HEADER]), Err(BlockError::Malformed));
        // A string without its NUL.
        let mut bad = good.clone();
        *bad.last_mut().unwrap() = b'x';
        assert_eq!(Block::read(&bad), Err(BlockError::Malformed));
        // A relative current directory.
        let mut bad = good;
        bad[HEADER + 2] = b'e';
        assert_eq!(Block::read(&bad), Err(BlockError::Malformed));
    }

    /// {ARG_MAX}: 64 KiB of strings and pointers pass, one byte more is
    /// E2BIG, at the writer and at the reader.
    #[test]
    fn arg_max_is_64_kib() {
        let mut out = vec![0; BLOCK_MAX + 4096];
        let room = ARG_MAX - 8 * 3 - 1;
        let long = vec![b'a'; room];
        assert!(
            Block::write(
                &mut out,
                b"/a",
                b"",
                0,
                [&long[..]].into_iter(),
                [].into_iter()
            )
            .is_ok()
        );
        let longer = vec![b'a'; room + 1];
        assert_eq!(
            Block::write(
                &mut out,
                b"/a",
                b"",
                0,
                [&longer[..]].into_iter(),
                [].into_iter()
            ),
            Err(BlockError::TooBig)
        );
        let len = block(&mut out, &[b"ls"], &[]);
        let mut bad = out[..len].to_vec();
        bad[20..24].copy_from_slice(&(ARG_MAX as u32 / 8).to_le_bytes());
        assert_eq!(Block::read(&bad), Err(BlockError::TooBig));
        let deep = vec![b'd'; PATH_MAX + 1];
        assert_eq!(
            Block::write(&mut out, &deep, b"", 0, [].into_iter(), [].into_iter()),
            Err(BlockError::NameTooLong)
        );
    }

    #[test]
    fn the_full_path_joins_the_current_directory() {
        let mut out = vec![0; BLOCK_MAX];
        let mut path = [0; PATH_MAX];
        for (p, cwd, full) in [
            (&b"/bin/ls"[..], &b"/etc"[..], &b"/bin/ls"[..]),
            (b"ls", b"/", b"/ls"),
            (b"ls", b"", b"/ls"),
            (b"./ls", b"/bin", b"/bin/./ls"),
        ] {
            let len = Block::write(&mut out, p, cwd, 0, [].into_iter(), [].into_iter()).unwrap();
            let read = Block::read(&out[..len]).unwrap();
            assert_eq!(read.full_path(&mut path), Ok(full));
        }
        let cwd = vec![b'c'; PATH_MAX];
        let mut cwd = cwd;
        cwd[0] = b'/';
        let len = Block::write(&mut out, b"x", &cwd, 0, [].into_iter(), [].into_iter()).unwrap();
        let read = Block::read(&out[..len]).unwrap();
        assert_eq!(read.full_path(&mut path), Err(BlockError::NameTooLong));
    }

    /// Handles takes Files, Clock, Driver, Pipes and Terminal, each once,
    /// four handles at most: a fifth, a slot twice, another slot are
    /// refused.
    #[test]
    fn handles_name_given_slots_once() {
        let body = |slots: &[u32]| {
            let mut w = Writer::new();
            for s in slots {
                w.u32(*s).unwrap();
            }
            w
        };
        let w = body(&[4, 5, 6]);
        assert_eq!(
            handle_slots(Reader::new(w.as_bytes()), 3),
            Ok([
                Some(Slot::Files),
                Some(Slot::Clock),
                Some(Slot::Driver),
                None
            ])
        );
        let w = body(&[8, 4, 5, 6]);
        assert_eq!(
            handle_slots(Reader::new(w.as_bytes()), 4),
            Ok([
                Some(Slot::Pipes),
                Some(Slot::Files),
                Some(Slot::Clock),
                Some(Slot::Driver)
            ])
        );
        let w = body(&[9]);
        assert_eq!(
            handle_slots(Reader::new(w.as_bytes()), 1),
            Ok([Some(Slot::Terminal), None, None, None])
        );
        let w = body(&[10]);
        assert_eq!(
            handle_slots(Reader::new(w.as_bytes()), 1),
            Ok([Some(Slot::Entropy), None, None, None])
        );
        for (slots, count) in [
            (&[11][..], 1),
            (&[10, 10][..], 2),
            (&[4, 5, 6, 8, 5][..], 5),
            (&[8, 8][..], 2),
            (&[4, 4][..], 2),
            (&[2][..], 1),
            (&[7][..], 1),
            (&[4, 5][..], 1),
        ] {
            let w = body(slots);
            assert_eq!(
                handle_slots(Reader::new(w.as_bytes()), count),
                Err(Status::BadSize),
                "{slots:?}"
            );
        }
    }

    /// The block is read from the loader's copy: a parent that changes its
    /// bytes after they were copied changes nothing, and each byte of its
    /// object is read once.
    #[test]
    fn the_block_is_checked_in_the_copy() {
        use core::cell::Cell;
        let mut good = vec![0; BLOCK_MAX];
        let len = block(&mut good, &[b"ls"], &[]);
        let reads = Cell::new(0usize);
        // The parent's object: good bytes at the first read of each, a
        // forged argc ever after (a parent that writes meanwhile).
        let seen = vec![Cell::new(false); len];
        let source = |i: usize| {
            reads.set(reads.get() + 1);
            if seen[i].replace(true) {
                if i == 20 { 9 } else { good[i] }
            } else {
                good[i]
            }
        };
        let mut copy = vec![0; len];
        let read = copy_block(source, len, &mut copy).unwrap();
        assert_eq!(read.argc, 1);
        assert_eq!(reads.get(), len, "each byte once");
        assert!(copy_block(|i| good[i], len, &mut [0; 8]).is_err());
    }

    /// The room of a program's segments leaves out the loader's region, the
    /// layer's fixed pages, the start area and the stack.
    #[test]
    fn the_program_room_keeps_off_the_reserved_pages() {
        let fixed = [
            0x200_0000,  // the buffers of the layer's threads
            0x0D00_0000, // the page of the record (proto_process::PAGE_ADDRESS)
            0x0E00_0000, // the clock's page
            0x1000_0000, // the heap
            START_AREA,
            abi::INIT_STACK_TOP - STACK_SIZE,
            LOADER_BASE,
        ];
        for address in fixed {
            assert!(!PROGRAM_ROOM.contains(&address), "{address:#x}");
        }
        assert!(
            PROGRAM_ROOM.contains(&0x20_0000),
            "where lld puts a program"
        );
        const { assert!(START_AREA + AREA_MAX <= abi::INIT_STACK_TOP - STACK_SIZE - 4096) };
    }

    /// The start area: the header names the stack, whose pointers name
    /// the strings in the area, `argv` then `envp`, each list ended by
    /// NULL, then the zero pairs of the auxiliary vector.
    #[test]
    fn the_start_area_points_into_itself() {
        let mut out = vec![0; BLOCK_MAX];
        for (argv, envp) in [
            (&[&b"ls"[..], b"/etc"][..], &[&b"X=1"[..]][..]),
            (&[&b"ls"[..]][..], &[][..]),
            (&[][..], &[&b"A=b"[..], b"C="][..]),
        ] {
            let len = block(&mut out, argv, envp);
            let read = Block::read(&out[..len]).unwrap();
            let at = START_AREA;
            let mut area = vec![0xAA; area_len(&read)];
            let handles = [1, 2, 3, 4, 5, 6, 0, 8, 9, 10, 11];
            write_area(&mut area, at, &read, SECURE, handles, &[]).unwrap();
            assert!(write_area(&mut vec![0; area.len() - 1], at, &read, 0, handles, &[]).is_err());
            let start = Start::read(&area).unwrap();
            assert_eq!(
                (start.flags, start.umask, start.handles),
                (SECURE, 0o022, handles)
            );
            let word = |addr: u64| {
                let i = (addr - at) as usize;
                u64::from_le_bytes(area[i..i + 8].try_into().unwrap())
            };
            let string = |addr: u64| {
                let i = (addr - at) as usize;
                let end = area[i..].iter().position(|&b| b == 0).unwrap();
                area[i..i + end].to_vec()
            };
            assert_eq!(string(start.cwd), b"/etc");
            assert_eq!(word(start.stack), argv.len() as u64);
            let mut p = start.stack + 8;
            for a in argv {
                assert_eq!(string(word(p)), *a);
                p += 8;
            }
            assert_eq!(word(p), 0);
            p += 8;
            for e in envp {
                assert_eq!(string(word(p)), *e);
                p += 8;
            }
            assert_eq!(word(p), 0);
            assert_eq!(start.auxv, p + 8);
            for i in 0..2 * AUXV_PAIRS as u64 {
                assert_eq!(word(start.auxv + 8 * i), 0);
            }
            assert_eq!(start.stack % 16, 0);
        }
    }

    /// The descriptors ride between the current directory and the strings,
    /// each number once, and reach the start area.
    #[test]
    fn descriptors_ride_in_the_block_and_the_area() {
        let list = [
            Descriptor {
                fd: 0,
                names: Names::Input,
            },
            Descriptor {
                fd: 4,
                names: Names::File(7),
            },
            Descriptor {
                fd: 5,
                names: Names::Pipe(9),
            },
            Descriptor {
                fd: 6,
                names: Names::Terminal(0),
            },
            Descriptor {
                fd: 7,
                names: Names::Random(11),
            },
        ];
        let mut out = vec![0; BLOCK_MAX];
        let argv: [&[u8]; 1] = [b"ls"];
        let len = Block::write_with(
            &mut out,
            b"/bin/ls",
            b"/",
            0,
            argv.into_iter(),
            [].into_iter(),
            &list,
        )
        .unwrap();
        let read = Block::read(&out[..len]).unwrap();
        assert_eq!(read.descriptors().collect::<Vec<_>>(), list);
        assert_eq!(read.strings(), b"ls\0");
        assert!(read.needs(Slot::Pipes) && read.needs(Slot::Terminal) && read.needs(Slot::Files));
        let mut plain = vec![0; BLOCK_MAX];
        let plain_len = Block::write_with(
            &mut plain,
            b"/bin/ls",
            b"/",
            0,
            [&b"ls"[..]].into_iter(),
            [].into_iter(),
            &list[..2],
        )
        .unwrap();
        let plain = Block::read(&plain[..plain_len]).unwrap();
        assert!(!plain.needs(Slot::Pipes) && !plain.needs(Slot::Terminal));
        let mut twice = out[..len].to_vec();
        let at = HEADER + 7 + 1;
        twice[at + DESCRIPTOR..at + DESCRIPTOR + 4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            Block::read(&twice),
            Err(BlockError::Malformed),
            "fd 0 twice"
        );
        let mut far = out[..len].to_vec();
        far[at..at + 4].copy_from_slice(&32u32.to_le_bytes());
        assert_eq!(Block::read(&far), Err(BlockError::Malformed), "fd 32");
        let mut area = vec![0; area_len(&read)];
        write_area(&mut area, START_AREA, &read, 0, [0; SLOTS], &[]).unwrap();
        let start = Start::read(&area).unwrap();
        assert_eq!(start.descriptor_count as usize, list.len());
        let at = (start.descriptors - START_AREA) as usize;
        let back: Vec<_> = area[at..at + list.len() * DESCRIPTOR]
            .as_chunks::<DESCRIPTOR>()
            .0
            .iter()
            .filter_map(|chunk| Descriptor::read(chunk))
            .collect();
        assert_eq!(back, list);
    }

    /// What an exec carries reaches the start area; a spawn's block
    /// carries zeros.
    #[test]
    fn an_exec_carries_its_pending_signals_timers_and_alarm() {
        let mut out = vec![0xFF; BLOCK_MAX];
        let len = block(&mut out, &[b"ls"], &[]);
        assert_eq!(
            Block::read(&out[..len]).unwrap().carried,
            Carried::default()
        );
        let carried = Carried {
            pending: 1 << 9,
            timers: 3,
            alarm: 12_345,
        };
        Block::carry(&mut out[..len], carried).unwrap();
        let read = Block::read(&out[..len]).unwrap();
        assert_eq!(read.carried, carried);
        let mut area = vec![0; area_len(&read)];
        write_area(&mut area, START_AREA, &read, 0, [0; SLOTS], &[]).unwrap();
        let start = Start::read(&area).unwrap();
        assert_eq!(
            (start.pending, start.timers, start.alarm),
            (1 << 9, 3, 12_345)
        );
    }

    /// The memory map the loader hands over reaches the start area: each
    /// entry with its address, pages, access and handle, inside the area and
    /// before the strings; MAP_ENTRIES at most.
    #[test]
    fn the_memory_map_rides_in_the_start_area() {
        use abi::Access;
        let mut out = vec![0; BLOCK_MAX];
        let len = block(&mut out, &[b"ls", b"-l"], &[b"X=1"]);
        let read = Block::read(&out[..len]).unwrap();
        let entry = |i: u32, access| MapEntry {
            address: 0x1000 * (i as u64 + 1),
            pages: i + 1,
            access,
            handle: 40 + i as u64,
        };
        let list = [
            entry(0, Access::ReadExec),
            entry(1, Access::Read),
            entry(2, Access::ReadWrite),
            entry(3, Access::ReadWrite),
            entry(4, Access::ReadWrite),
        ];
        let mut area = vec![0xAA; area_len(&read)];
        write_area(&mut area, START_AREA, &read, 0, [0; SLOTS], &list).unwrap();
        let start = Start::read(&area).unwrap();
        assert_eq!(start.map_count as usize, MAP_ENTRIES);
        let at = (start.map - START_AREA) as usize;
        assert!(at + MAP_ENTRIES * MAP_ENTRY <= (start.cwd - START_AREA) as usize);
        let back: Vec<_> = area[at..at + MAP_ENTRIES * MAP_ENTRY]
            .as_chunks::<MAP_ENTRY>()
            .0
            .iter()
            .filter_map(MapEntry::read)
            .collect();
        assert_eq!(back, list);
        let mut few = vec![0; area_len(&read)];
        write_area(&mut few, START_AREA, &read, 0, [0; SLOTS], &list[..3]).unwrap();
        assert_eq!(Start::read(&few).unwrap().map_count, 3);
        let mut too_many = list.to_vec();
        too_many.push(entry(5, Access::Read));
        assert_eq!(
            write_area(&mut area, START_AREA, &read, 0, [0; SLOTS], &too_many),
            Err(BlockError::Malformed)
        );
        let mut bytes = list[0].to_bytes();
        bytes[8..12].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(MapEntry::read(&bytes), None, "no pages");
        let mut bytes = list[0].to_bytes();
        bytes[12..16].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(MapEntry::read(&bytes), None, "W and X together");
    }

    fn region(address: u64, pages: u32, access: abi::Access) -> Region {
        Region {
            address,
            pages,
            access,
        }
    }

    /// The regions of a program from a file: its code, read-only data and
    /// data, three chunks of the heap, its start area and its stack.
    fn program() -> Vec<Region> {
        use abi::Access::{Read, ReadExec, ReadWrite};
        vec![
            region(0x20_0000, 16, ReadExec),
            region(0x21_0000, 4, Read),
            region(0x22_0000, 2, ReadWrite),
            region(0x1000_0000, 16, ReadWrite),
            region(0x1001_0000, 32, ReadWrite),
            region(0x1003_0000, 16, ReadWrite),
            region(START_AREA, 1, ReadWrite),
            region(abi::INIT_STACK_TOP - STACK_SIZE, 16, ReadWrite),
        ]
    }

    fn fork(regions: usize) -> Fork {
        Fork {
            pc: 0x20_0100,
            sp: abi::INIT_STACK_TOP - 0x400,
            transfer: 0x22_0100,
            regions: regions as u32,
        }
    }

    /// Regions takes memory objects with MAP_READ alone.
    #[test]
    fn a_region_comes_from_a_readable_memory_object() {
        use abi::{ObjectKind, Rights};
        assert!(region_object(
            ObjectKind::Memory,
            Rights::MAP_READ | Rights::TRANSFER
        ));
        for (kind, rights) in [
            (ObjectKind::DeviceWindow, Rights::MAP_READ),
            (ObjectKind::Channel, Rights::MAP_READ),
            (ObjectKind::Process, Rights::MAP_READ),
            (ObjectKind::Memory, Rights::MAP_WRITE | Rights::TRANSFER),
            (ObjectKind::Unknown(9), Rights::MAP_READ),
        ] {
            assert!(!region_object(kind, rights), "{kind:?}");
        }
    }

    /// Fork round-trips; no regions or more than REGIONS_MAX are refused.
    #[test]
    fn fork_round_trips_and_counts_its_regions() {
        let f = fork(8);
        let mut w = Writer::new();
        f.write(&mut w).unwrap();
        assert_eq!(Fork::read(Reader::new(w.as_bytes())), Ok(f));
        for n in [0, REGIONS_MAX + 1] {
            let mut w = Writer::new();
            fork(n).write(&mut w).unwrap();
            assert_eq!(Fork::read(Reader::new(w.as_bytes())), Err(Status::BadSize));
        }
        let mut w = Writer::new();
        region(0x1000, 1, abi::Access::Read).write(&mut w).unwrap();
        let mut bytes = w.as_bytes().to_vec();
        bytes[12] = 7;
        assert_eq!(
            Region::read(&mut Reader::new(&bytes)),
            Err(Status::BadSize),
            "W and X together"
        );
    }

    /// A copy takes regions inside the rooms of a program alone, each apart
    /// from the others, REGIONS_MAX at most.
    #[test]
    fn a_copy_takes_regions_of_the_layout_alone() {
        use abi::Access::{Read, ReadWrite};
        let mut held = Vec::new();
        for r in program() {
            assert_eq!(admit(&held, &r), Ok(()), "{r:?}");
            held.push(r);
        }
        let refused = [
            region(0x22_1000, 1, ReadWrite),               // meets the data
            region(0x1000_8000, 4, ReadWrite),             // inside a chunk
            region(0x0FFF_F000, 2, ReadWrite),             // across the heap's edge
            region(LOADER_BASE, 1, Read),                  // the loader's region
            region(LOADER_BASE + (8 << 20), 1, ReadWrite), // its window
            region(0x0D00_0000, 1, ReadWrite),             // the page of the record
            region(0x0E00_0000, 1, Read),                  // the clock's page
            region(0x0200_0000, 1, ReadWrite),             // a buffer of a thread
            region(abi::INIT_MSGBUF, 1, ReadWrite),        // the main buffer
            region(0x3000_0000, 1, ReadWrite),             // the window of spawn
            region(0x1F_F800, 1, ReadWrite),               // off a page
            region(0x1F00_0000, u32::MAX, ReadWrite),      // past the heap
            region(!0xFFF, 2, ReadWrite),                  // wraps
        ];
        for r in refused {
            assert_eq!(admit(&held, &r), Err(Status::BadSize), "{r:?}");
        }
        let mut full: Vec<_> = (0..REGIONS_MAX as u64)
            .map(|i| region(0x1000_0000 + i * 0x1000, 1, ReadWrite))
            .collect();
        let last = full.pop().unwrap();
        assert_eq!(admit(&full, &last), Ok(()));
        full.push(last);
        assert_eq!(
            admit(&full, &region(0x1100_0000, 1, ReadWrite)),
            Err(Status::BadSize),
            "a region past REGIONS_MAX"
        );
    }

    /// The copy goes on in code, on a stack and with a transfer in writable
    /// regions it took, once all of them came.
    #[test]
    fn a_copy_jumps_into_code_with_a_stack_it_took() {
        let held = program();
        assert_eq!(check_fork(&fork(held.len()), &held), Ok(()));
        // The stack pointer at the top of the stack is in it.
        let top = Fork {
            sp: abi::INIT_STACK_TOP,
            ..fork(held.len())
        };
        assert_eq!(check_fork(&top, &held), Ok(()));
        let bad = [
            ("a region missing", fork(held.len() + 1)),
            (
                "pc in data",
                Fork {
                    pc: 0x22_0000,
                    ..fork(held.len())
                },
            ),
            (
                "pc in read-only data",
                Fork {
                    pc: 0x21_0000,
                    ..fork(held.len())
                },
            ),
            (
                "pc off an instruction",
                Fork {
                    pc: 0x20_0102,
                    ..fork(held.len())
                },
            ),
            (
                "sp in code",
                Fork {
                    sp: 0x20_0100,
                    ..fork(held.len())
                },
            ),
            (
                "sp nowhere",
                Fork {
                    sp: 0x3000_0000,
                    ..fork(held.len())
                },
            ),
            (
                "sp at the bottom of the stack",
                Fork {
                    sp: abi::INIT_STACK_TOP - STACK_SIZE,
                    ..fork(held.len())
                },
            ),
            (
                "sp unaligned",
                Fork {
                    sp: abi::INIT_STACK_TOP - 0x408,
                    ..fork(held.len())
                },
            ),
            (
                "transfer across the data's end",
                Fork {
                    transfer: 0x22_2000 - 64,
                    ..fork(held.len())
                },
            ),
            (
                "transfer in read-only data",
                Fork {
                    transfer: 0x21_0000,
                    ..fork(held.len())
                },
            ),
            (
                "transfer unaligned",
                Fork {
                    transfer: 0x22_0104,
                    ..fork(held.len())
                },
            ),
        ];
        for (what, f) in bad {
            assert_eq!(check_fork(&f, &held), Err(Status::BadSize), "{what}");
        }
    }

    /// Adjacent writable regions make one object; code, read-only data and
    /// regions apart make their own.
    #[test]
    fn adjacent_writable_regions_are_one_object() {
        let held = program();
        let objects: Vec<_> = groups(&held).collect();
        assert_eq!(objects, [0..1, 1..2, 2..3, 3..6, 6..7, 7..8]);
        assert_eq!(groups(&[]).count(), 0);
        use abi::Access::ReadExec;
        let code = [region(0x1000, 1, ReadExec), region(0x2000, 1, ReadExec)];
        assert_eq!(groups(&code).collect::<Vec<_>>(), [0..1, 1..2]);
    }

    /// The transfer carries the child's handles and its map.
    #[test]
    fn the_transfer_round_trips() {
        use abi::Access;
        let map: Vec<_> = (0..REGIONS_MAX as u64)
            .map(|i| MapEntry {
                address: 0x1000_0000 + i * 0x1000,
                pages: 1,
                access: Access::ReadWrite,
                handle: 100 + i,
            })
            .collect();
        let handles = [1, 2, 3, 4, 5, 0, 7, 8, 9, 10, 11];
        let mut out = vec![0xAA; TRANSFER_SIZE];
        write_transfer(&mut out, handles, &map).unwrap();
        let t = Transfer::read(&out).unwrap();
        assert_eq!(t.handles, handles);
        assert_eq!(t.map().collect::<Vec<_>>(), map);
        assert!(write_transfer(&mut out[..TRANSFER_SIZE - 1], handles, &map).is_err());
        let mut more = map.clone();
        more.push(map[0]);
        assert!(write_transfer(&mut out, handles, &more).is_err());
        write_transfer(&mut out, handles, &map[..2]).unwrap();
        assert_eq!(Transfer::read(&out).unwrap().map().count(), 2);
        out[0] = b'x';
        assert_eq!(Transfer::read(&out), None);
    }
}
