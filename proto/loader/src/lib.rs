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
//!   `Uart`, each once) and as many handles, sessions with SEND, after
//!   "the image is ready"; reply its status.
//!
//! The loader trusts no handle of C for its own requests: its session with
//! the process service, the session of the loaders and its identity come
//! from the service. Once "the record is ready" came through label 2 it
//! asks the service for the program's sessions (proto_process Take),
//! writes the start area (`Start`), closes everything that was its own,
//! unmaps its data and stack and jumps to the program's entry with x0 =
//! START_AREA. The program's start (posix-crt) reads the area.
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

pub const VERSION: u16 = 1;

/// The region of the loader: 16 MiB under the top of a process's lower
/// half (spec 2, 3.2), which no program's segment may take.
pub const LOADER_BASE: u64 = (1 << 48) - (16 << 20);
pub const LOADER_END: u64 = 1 << 48;
/// Where the loader maps the objects it fills, in its own region.
pub const LOADER_WINDOW: u64 = LOADER_BASE + (8 << 20);
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

/// The handles of the start area, by their place in `Start::handles`; the
/// sessions the parent gives with Handles are Files, Clock and Uart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Slot {
    Process = 0,
    Thread = 1,
    Posix = 2,
    PosixId = 3,
    Files = 4,
    Clock = 5,
    Uart = 6,
    Console = 7,
}

/// The handles a start area names.
pub const SLOTS: usize = 8;

impl Slot {
    /// The slot of a handle Handles brings: Files, Clock or Uart.
    pub const fn given(n: u32) -> Option<Slot> {
        match n {
            4 => Some(Slot::Files),
            5 => Some(Slot::Clock),
            6 => Some(Slot::Uart),
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
    /// copy, never from the parent's object (sp3.M6).
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
/// copy alone (sp3.M6), so a parent that writes its object meanwhile
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
    _reserved: u32,
    /// What an exec carried (`Carried`), all 0 for a spawn.
    pub pending: u64,
    pub timers: u64,
    pub alarm: u64,
    _pad: u64,
}

pub const START_MAGIC: [u8; 8] = *b"STAFSTRT";
pub const START_VERSION: u32 = 1;
pub const SECURE: u32 = 1;
/// The pairs of the auxiliary vector the start may fill.
pub const AUXV_PAIRS: usize = 8;
/// The bytes of the header.
pub const START_SIZE: usize = core::mem::size_of::<Start>();
const _: () = assert!(START_SIZE == 160);

/// The bytes of the start area of `block`: the header, the initial stack
/// and the strings, rounded up to 16.
pub const fn area_len(block: &Block<'_>) -> usize {
    let stack = 8 * (1 + block.argc + 1 + block.envc + 1 + 2 * AUXV_PAIRS);
    let strings = block.cwd.len() + 1 + block.strings.len() + block.descriptors.len();
    (START_SIZE + stack + strings).next_multiple_of(16)
}

/// Writes the start area of `block` into `area`, which lies at `at` in the
/// program's space: the header with `flags` and `handles`, the initial
/// stack and the strings it points to. Malformed when `area` is shorter
/// than `area_len`.
pub fn write_area(
    area: &mut [u8],
    at: u64,
    block: &Block<'_>,
    flags: u32,
    handles: [u64; SLOTS],
) -> Result<(), BlockError> {
    let len = area_len(block);
    let area = area.get_mut(..len).ok_or(BlockError::Malformed)?;
    let stack_at = START_SIZE;
    let words = 1 + block.argc + 1 + block.envc + 1 + 2 * AUXV_PAIRS;
    let strings_at = stack_at + 8 * words;
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
        _reserved: 0,
        pending: block.carried.pending,
        timers: block.carried.timers,
        alarm: block.carried.alarm,
        _pad: 0,
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

    /// Handles takes Files, Clock and Uart, each once, four handles at
    /// most: a fifth, a slot twice, another slot are refused.
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
            Ok([Some(Slot::Files), Some(Slot::Clock), Some(Slot::Uart), None])
        );
        for (slots, count) in [
            (&[4, 5, 6, 4, 5][..], 5),
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
            let handles = [1, 2, 3, 4, 5, 6, 0, 8];
            write_area(&mut area, at, &read, SECURE, handles).unwrap();
            assert!(write_area(&mut vec![0; area.len() - 1], at, &read, 0, handles).is_err());
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
        write_area(&mut area, START_AREA, &read, 0, [0; SLOTS]).unwrap();
        let start = Start::read(&area).unwrap();
        assert_eq!(start.descriptor_count, 2);
        let at = (start.descriptors - START_AREA) as usize;
        let back: Vec<_> = area[at..at + 2 * DESCRIPTOR]
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
        write_area(&mut area, START_AREA, &read, 0, [0; SLOTS]).unwrap();
        let start = Start::read(&area).unwrap();
        assert_eq!(
            (start.pending, start.timers, start.alarm),
            (1 << 9, 3, 12_345)
        );
    }
}
