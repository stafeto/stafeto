// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The stafeto kernel interface shared by the kernel and programs (spec 5,
//! 6, 8, 11, 12, 13.3): handle layout, rights, system call numbers and
//! where their arguments and results go, what `receive` returns, init's
//! first handles, scheduling policies and error codes.

#![cfg_attr(not(test), no_std)]

/// A process's name for a kernel object (spec 5.1): the low 16 bits index
/// its handle table, the high 48 bits carry the entry's generation. The
/// layout belongs to the kernel; programs treat the value as opaque.
/// Generations start at 1, so no handle is zero.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Handle(pub u64);

impl Handle {
    pub const INDEX_BITS: u32 = 16;
    pub const GENERATION_BITS: u32 = u64::BITS - Self::INDEX_BITS;
    pub const MAX_INDEX: u32 = (1 << Self::INDEX_BITS) - 1;
    /// An entry freed at this generation is retired, never reused.
    pub const MAX_GENERATION: u64 = (1 << Self::GENERATION_BITS) - 1;
    pub const INVALID: Handle = Handle(0);

    pub const fn new(index: u32, generation: u64) -> Handle {
        Handle(
            ((generation & Self::MAX_GENERATION) << Self::INDEX_BITS)
                | (index & Self::MAX_INDEX) as u64,
        )
    }

    pub const fn index(self) -> u32 {
        (self.0 & Self::MAX_INDEX as u64) as u32
    }

    pub const fn generation(self) -> u64 {
        self.0 >> Self::INDEX_BITS
    }
}

/// What a handle allows (spec 5.2). A copy carries a subset, never more.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rights(pub u32);

impl Rights {
    pub const NONE: Rights = Rights(0);
    pub const DUPLICATE: Rights = Rights(1 << 0);
    pub const TRANSFER: Rights = Rights(1 << 1);
    pub const SEND: Rights = Rights(1 << 2);
    pub const NOTIFY: Rights = Rights(1 << 3);
    pub const RECEIVE: Rights = Rights(1 << 4);
    pub const MAP_READ: Rights = Rights(1 << 5);
    pub const MAP_WRITE: Rights = Rights(1 << 6);
    pub const MAP_EXEC: Rights = Rights(1 << 7);
    pub const MANAGE: Rights = Rights(1 << 8);
    pub const DEVICE: Rights = Rights(1 << 9);
    pub const DEBUG: Rights = Rights(1 << 10);
    pub const KSTATS: Rights = Rights(1 << 11);
    /// Every right there is: `handle_duplicate` fails any other bit with
    /// INVALID_ARGS.
    pub const ALL: Rights = Rights((1 << 12) - 1);

    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }

    pub const fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }
}

impl core::ops::BitOr for Rights {
    type Output = Rights;
    fn bitor(self, other: Rights) -> Rights {
        self.union(other)
    }
}

/// Rights of the handle that `process_create`, `thread_create` or
/// `timer_create` returns, and of init's handles to its own process and
/// first thread.
pub const OWNER_RIGHTS: Rights =
    Rights(Rights::DUPLICATE.0 | Rights::TRANSFER.0 | Rights::MANAGE.0);

/// Rights of the handle that `channel_create` returns (spec 5.2): SEND for
/// requests (milestone 1.3c), NOTIFY, RECEIVE, DUPLICATE and TRANSFER.
pub const CHANNEL_RIGHTS: Rights = Rights(
    Rights::SEND.0
        | Rights::NOTIFY.0
        | Rights::RECEIVE.0
        | Rights::DUPLICATE.0
        | Rights::TRANSFER.0,
);

/// Rights of init's handle to the system resource (spec 13.3).
pub const INIT_RESOURCE_RIGHTS: Rights = Rights(
    Rights::DEVICE.0
        | Rights::DEBUG.0
        | Rights::KSTATS.0
        | Rights::DUPLICATE.0
        | Rights::TRANSFER.0,
);

/// Init's first handles (spec 13.3): the kernel puts them in the first
/// entries of init's table, so each has generation 1.
pub const INIT_RESOURCE: Handle = Handle::new(0, 1);
pub const INIT_PROCESS: Handle = Handle::new(1, 1);
pub const INIT_THREAD: Handle = Handle::new(2, 1);
/// Kept for the boot image, a memory object from milestone 1.3 on. Until
/// then the entry is freed at once: the value is BAD_HANDLE and never
/// names another object.
pub const INIT_BOOT_IMAGE: Handle = Handle::new(3, 1);

/// The first handle of a process that `process_create` made (spec 13.3):
/// entry 0 of its fresh table. The sixth argument of `process_create`, a
/// channel, moves there from milestone 1.3b on; without one the entry
/// holds a stub that goes at once, and the value is BAD_HANDLE for good.
pub const START_CHANNEL: Handle = Handle::new(0, 1);

/// Threads of one process that have not ended, at most (spec 8):
/// `thread_create` past it fails with LIMIT_REACHED.
pub const MAX_THREADS: u32 = 64;

/// Timers one process pays for, at most (spec 10): `timer_create` past it
/// fails with LIMIT_REACHED.
pub const MAX_TIMERS: u32 = 64;

/// Top of the stack of init's first thread (spec 13.3). The kernel maps the
/// stack the boot image asks for right under it, with an unmapped guard
/// page below; init's program lies under that guard page.
pub const INIT_STACK_TOP: u64 = 0x1_0000_0000;
/// The message buffer of init's first thread: one page above the stack,
/// with an unmapped page between them.
pub const INIT_MSGBUF: u64 = INIT_STACK_TOP + 0x1000;

/// System calls (spec 11). The number goes in the immediate of `svc #n`.
/// Arguments go in x0-x9. On success x0 is 0 and the call's values are in
/// x1 and up; on an error x0 holds the error code and nothing else
/// changes. Registers from x10 up, SP_EL0, the flags, TPIDR_EL0 and the FP
/// and SIMD registers stay as they were, but for x10 and x11 of a
/// `receive` that took something (`Notification`). Unknown numbers, 0 included, and
/// reserved values of arguments fail with INVALID_ARGS; a narrow argument
/// with bits set above its width is such a value.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Call {
    HandleClose = 1,
    HandleDuplicate = 2,
    CreateChannel = 3,
    Send = 4,
    Receive = 5,
    Reply = 6,
    Notify = 7,
    MemCreate = 8,
    MemMap = 9,
    MemUnmap = 10,
    MemProtect = 11,
    ProcessCreate = 12,
    ProcessKill = 13,
    ProcessExit = 14,
    ThreadCreate = 15,
    ThreadStart = 16,
    ThreadExit = 17,
    ThreadSetPriority = 18,
    Yield = 19,
    DeviceWindowCreate = 20,
    IrqBind = 21,
    IrqAck = 22,
    ClockNow = 23,
    TimerCreate = 24,
    TimerSet = 25,
    TimerCancel = 26,
    ObjectInfo = 27,
    DebugWrite = 28,
}

impl Call {
    /// Every call, in the order of its number.
    pub const ALL: [Call; 28] = [
        Call::HandleClose,
        Call::HandleDuplicate,
        Call::CreateChannel,
        Call::Send,
        Call::Receive,
        Call::Reply,
        Call::Notify,
        Call::MemCreate,
        Call::MemMap,
        Call::MemUnmap,
        Call::MemProtect,
        Call::ProcessCreate,
        Call::ProcessKill,
        Call::ProcessExit,
        Call::ThreadCreate,
        Call::ThreadStart,
        Call::ThreadExit,
        Call::ThreadSetPriority,
        Call::Yield,
        Call::DeviceWindowCreate,
        Call::IrqBind,
        Call::IrqAck,
        Call::ClockNow,
        Call::TimerCreate,
        Call::TimerSet,
        Call::TimerCancel,
        Call::ObjectInfo,
        Call::DebugWrite,
    ];

    pub const fn number(self) -> u16 {
        self as u16
    }

    /// The call with this number, if any.
    pub const fn from_number(number: u16) -> Option<Call> {
        match number {
            1..=28 => Some(Self::ALL[number as usize - 1]),
            _ => None,
        }
    }
}

/// System call numbers that belong to the kernel's test builds (spec 11):
/// no real system call gets one.
pub const TEST_CALLS: core::ops::RangeInclusive<u16> = 0xFF00..=0xFFFF;

/// Registers a call returns values in on success: x1-x9.
pub const RESULT_VALUES: usize = 9;

/// Bytes a call carries in registers x2-x9 (spec 11): `debug_write` and,
/// from milestone 1.3, messages.
pub const INLINE_MAX: usize = 64;

/// Packs up to INLINE_MAX bytes into the words for x2-x9: byte i goes into
/// word i / 8 at bit 8 * (i % 8), low byte first; the rest is zero.
pub fn inline_words(bytes: &[u8]) -> [u64; 8] {
    assert!(bytes.len() <= INLINE_MAX, "x2-x9 carry at most 64 bytes");
    let mut words = [0; 8];
    for (i, chunk) in bytes.chunks(8).enumerate() {
        let mut word = [0; 8];
        word[..chunk.len()].copy_from_slice(chunk);
        words[i] = u64::from_le_bytes(word);
    }
    words
}

/// The bytes that x2-x9 carry, in the order of `inline_words`.
pub fn inline_bytes(words: &[u64; 8]) -> [u8; INLINE_MAX] {
    let mut bytes = [0; INLINE_MAX];
    for (chunk, word) in bytes.chunks_mut(8).zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

/// Bit 16 of the flags of `receive` (spec 6.1, 11), and of the description
/// of `send` from milestone 1.3c: the call does not wait. The other bits of
/// the flags are reserved.
pub const NO_WAIT: u64 = 1 << 16;

/// Bytes a message carries at most (spec 6.1, 6.2): bytes 0-63 in x2-x9,
/// the rest in the message buffer.
pub const MESSAGE_MAX: usize = 1024;

/// Handles a message carries at most (spec 6.1).
pub const MESSAGE_HANDLES: usize = 4;

/// Where the count of handles starts in the description of a message, x1
/// of `send`, `reply` and of the results that carry a message (spec 11):
/// bits 12-14. The length takes bits 0-10.
pub const HANDLES_SHIFT: u32 = 12;

/// Where the kind of what `receive` took starts in its x1: bits 24-27.
pub const SOURCE_SHIFT: u32 = 24;

/// Bit 63 of the bits of a session's notification: the last handle with
/// its label went, or the process that held it ended (spec 5.3). Only the
/// kernel posts it: `notify` with it fails with INVALID_ARGS.
pub const CLIENT_GONE: u64 = 1 << 63;

/// Notification slots of one channel, its slot of label 0 among them
/// (spec 6.5): a source past them fails with LIMIT_REACHED. A source holds
/// its slot from its creation until it goes.
pub const MAX_SLOTS: u32 = 1024;

/// What `receive` took (spec 6.5, 11): bits 24-27 of its x1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A request (milestone 1.3c).
    Message,
    /// The channel's slot of label 0: `notify` through a handle with no
    /// label.
    Unlabeled,
    /// The slot of a session: `notify` through a labelled handle, or
    /// CLIENT_GONE (spec 5.3).
    Session,
    /// A timer (spec 10).
    Timer,
    /// The exit of a process (`process_create` x3, spec 7.9).
    Exit,
    /// An interrupt line (milestone 1.3e).
    Interrupt,
    /// A kind this abi does not know, which a later kernel may return: its
    /// code.
    Unknown(u64),
}

impl Source {
    /// The code in bits 24-27 of x1.
    pub const fn code(self) -> u64 {
        match self {
            Source::Message => 0,
            Source::Unlabeled => 1,
            Source::Session => 2,
            Source::Timer => 3,
            Source::Exit => 4,
            Source::Interrupt => 5,
            Source::Unknown(code) => code,
        }
    }

    /// The kind with this code; `Unknown` for a code this abi does not
    /// know.
    pub const fn from_code(code: u64) -> Source {
        match code {
            0 => Source::Message,
            1 => Source::Unlabeled,
            2 => Source::Session,
            3 => Source::Timer,
            4 => Source::Exit,
            5 => Source::Interrupt,
            _ => Source::Unknown(code),
        }
    }
}

/// A notification as `receive` returns it (spec 6.5, 11): the kind of its
/// source, the label of the handle the source came through (0 for none),
/// the bits posted since the last `receive` took the slot, ORed together,
/// and how many posts they merge, up to u32::MAX.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Notification {
    pub source: Source,
    pub label: u64,
    pub bits: u64,
    pub count: u32,
}

impl Notification {
    /// x1-x11 as `receive` leaves them: x1 the description (no data and no
    /// handles, the source in bits 24-27), x2 the bits, x3 the count, x4-x9
    /// zero, x10 the label, and x11 the token of a request, which a
    /// notification does not have: 0.
    pub const fn to_words(self) -> [u64; 11] {
        let mut words = [0; 11];
        self.write_words(&mut words);
        words
    }

    /// Writes the words of `to_words` into `words` in place, as the kernel
    /// writes them into the registers of the thread that takes the
    /// notification.
    pub const fn write_words(self, words: &mut [u64; 11]) {
        *words = [0; 11];
        words[0] = self.source.code() << SOURCE_SHIFT;
        words[1] = self.bits;
        words[2] = self.count as u64;
        words[9] = self.label;
    }

    /// The notification from x1-x11 after `receive`.
    pub const fn from_words(words: [u64; 11]) -> Notification {
        Notification {
            source: Source::from_code((words[0] >> SOURCE_SHIFT) & 0xF),
            label: words[9],
            bits: words[1],
            count: words[2] as u32,
        }
    }
}

/// A message as `receive` returns it (spec 6.1, 11): x1 its description,
/// the length in bits 0-10 and the count of handles from HANDLES_SHIFT,
/// source 0; x2-x9 bytes 0-63 as `inline_words` packs them, zero past the
/// length; x10 the label of the handle the request came through, 0 for
/// none; x11 the token of its reply, never 0. The reply comes back to
/// `send` in x1-x9 the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message {
    pub len: usize,
    pub handles: usize,
    pub words: [u64; 8],
    pub label: u64,
    pub token: u64,
}

impl Message {
    /// The description in x1: the length and the count of handles.
    pub const fn description(&self) -> u64 {
        self.len as u64 | (self.handles as u64) << HANDLES_SHIFT
    }

    /// x1-x11 as `receive` leaves them for this message.
    pub const fn to_words(self) -> [u64; 11] {
        let mut words = [0; 11];
        words[0] = self.description();
        let mut i = 0;
        while i < 8 {
            words[1 + i] = self.words[i];
            i += 1;
        }
        words[9] = self.label;
        words[10] = self.token;
        words
    }

    /// The message from x1-x11 after `receive`, or from x1-x9 after `send`
    /// with x10 and x11 as 0.
    pub const fn from_words(words: [u64; 11]) -> Message {
        let mut data = [0; 8];
        let mut i = 0;
        while i < 8 {
            data[i] = words[1 + i];
            i += 1;
        }
        Message {
            len: (words[0] & ((1 << 11) - 1)) as usize,
            handles: ((words[0] >> HANDLES_SHIFT) & 0b111) as usize,
            words: data,
            label: words[9],
            token: words[10],
        }
    }
}

/// Kinds of `object_info` (spec 11); 0 is reserved, and so is x2, which
/// is 0.
///
/// PROCESS_STATE takes a process handle, with no right needed, and returns
/// `ProcessState::to_words` in x1-x4.
pub const INFO_PROCESS_STATE: u64 = 1;
/// PROCESS_MEMORY takes a process handle, with no right needed, and
/// returns `ProcessMemory::to_words` in x1-x3.
pub const INFO_PROCESS_MEMORY: u64 = 2;
/// PROCESS_HANDLES takes a process handle, with no right needed, and
/// returns `ProcessHandles::to_words` in x1-x3.
pub const INFO_PROCESS_HANDLES: u64 = 3;
/// KERNEL_STATS takes the system resource with KSTATS and returns
/// `KernelStats::to_words` in x1-x8.
pub const INFO_KERNEL_STATS: u64 = 4;

/// A process's memory quota (spec 7.5), in bytes: the limit its parent
/// gave it, what is charged to it now, and what went back to the parent.
/// At its stage Quota the free part goes back, `returned` becomes `quota`
/// minus `used`, and then stays: what is charged, its shell and the shells
/// others still hold, only shrinks, and the rest goes back with its shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessMemory {
    pub quota: u64,
    pub used: u64,
    pub returned: u64,
}

impl ProcessMemory {
    /// The words `object_info` returns in x1-x3.
    pub const fn to_words(self) -> [u64; 3] {
        [self.quota, self.used, self.returned]
    }

    /// The quota from x1-x3 of `object_info`.
    pub const fn from_words(words: [u64; 3]) -> ProcessMemory {
        ProcessMemory {
            quota: words[0],
            used: words[1],
            returned: words[2],
        }
    }
}

/// A process's handle table (spec 5.1): the handles that are live, the
/// entries retired at their last generation, which still take room, and
/// the limit `process_create` set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessHandles {
    pub live: u64,
    pub retired: u64,
    pub limit: u64,
}

impl ProcessHandles {
    /// The words `object_info` returns in x1-x3.
    pub const fn to_words(self) -> [u64; 3] {
        [self.live, self.retired, self.limit]
    }

    /// The table from x1-x3 of `object_info`.
    pub const fn from_words(words: [u64; 3]) -> ProcessHandles {
        ProcessHandles {
            live: words[0],
            retired: words[1],
            limit: words[2],
        }
    }
}

/// What the kernel counts about itself (spec 15.3, 16). Times are in ticks
/// of the counter CNTVCT_EL0 reads, at the frequency CNTFRQ_EL0 gives
/// (rt::time::frequency).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelStats {
    /// Ticks the kernel slept in `wfi` with nothing to do.
    pub idle: u64,
    /// The longest time from a timer's deadline to the thread that ran
    /// after its interrupt, when the interrupt woke the kernel from `wfi`.
    pub idle_latency: u64,
    /// The same, when the interrupt came while a thread ran at EL0 or the
    /// kernel worked.
    pub irq_latency: u64,
    /// Objects in the cleanup queue now.
    pub cleanup_queue: u64,
    /// The longest portion of cleanup so far, in ticks: what one portion
    /// adds to the blocking of any thread (spec 7.7).
    pub longest_portion: u64,
    /// Free frames of the frame allocator.
    pub free_frames: u64,
    /// Pages the pools of kernel objects hold, and the list pages that name
    /// them: a pool takes a page as it grows, and the pages of a payer's
    /// pools go back with its shell (spec 7.8).
    pub pool_pages: u64,
    /// The longest batch of expired timers one timer interrupt took, in
    /// ticks: what the timers of programs add to the blocking of any
    /// thread (spec 10).
    pub longest_batch: u64,
}

impl KernelStats {
    /// The words `object_info` returns in x1-x8.
    pub const fn to_words(self) -> [u64; 8] {
        [
            self.idle,
            self.idle_latency,
            self.irq_latency,
            self.cleanup_queue,
            self.longest_portion,
            self.free_frames,
            self.pool_pages,
            self.longest_batch,
        ]
    }

    /// The counts from x1-x8 of `object_info`.
    pub const fn from_words(words: [u64; 8]) -> KernelStats {
        KernelStats {
            idle: words[0],
            idle_latency: words[1],
            irq_latency: words[2],
            cleanup_queue: words[3],
            longest_portion: words[4],
            free_frames: words[5],
            pool_pages: words[6],
            longest_batch: words[7],
        }
    }
}

/// Whether a process lives and, if not, why it ended (spec 7.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Alive,
    Exited {
        code: u64,
    },
    Killed,
    /// A synchronous exception at EL0. FAR is 0 unless the fault sets it.
    Fault {
        esr: u64,
        far: u64,
        elr: u64,
    },
    /// A state this abi does not know, which a later kernel may return:
    /// the four words as `object_info` left them. The kernel this abi
    /// comes with never returns one.
    Unknown([u64; 4]),
}

impl ProcessState {
    /// The words `object_info` returns in x1-x4: the state (0 alive, 1
    /// exited, 2 killed, 3 fault), then the exit code, or ESR, FAR and ELR.
    pub const fn to_words(self) -> [u64; 4] {
        match self {
            ProcessState::Alive => [0, 0, 0, 0],
            ProcessState::Exited { code } => [1, code, 0, 0],
            ProcessState::Killed => [2, 0, 0, 0],
            ProcessState::Fault { esr, far, elr } => [3, esr, far, elr],
            ProcessState::Unknown(words) => words,
        }
    }

    /// The state from x1-x4 of `object_info`; `Unknown` for a state this
    /// abi does not know.
    pub const fn from_words(words: [u64; 4]) -> ProcessState {
        match words[0] {
            0 => ProcessState::Alive,
            1 => ProcessState::Exited { code: words[1] },
            2 => ProcessState::Killed,
            3 => ProcessState::Fault {
                esr: words[1],
                far: words[2],
                elr: words[3],
            },
            _ => ProcessState::Unknown(words),
        }
    }
}

/// Priority levels (spec 8): 0 to 63, higher runs first. Level 0 goes to
/// no thread: the kernel idles when no thread is ready.
pub const PRIORITY_LEVELS: u8 = 64;

/// The round-robin quantum (spec 8).
pub const RR_QUANTUM_NS: u64 = 4_000_000;

/// Scheduling policies (spec 8), as `thread_create` and
/// `thread_set_priority` take them.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Round robin with a quantum of RR_QUANTUM_NS.
    RoundRobin = 0,
    /// First in, first out, no quantum: for real-time threads.
    Fifo = 1,
}

impl Policy {
    /// The policy a register holds; None for any other value.
    pub const fn from_raw(raw: u64) -> Option<Policy> {
        match raw {
            0 => Some(Policy::RoundRobin),
            1 => Some(Policy::Fifo),
            _ => None,
        }
    }
}

/// Errors of system calls (spec 12), each with its code in x0; zero means
/// success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    BadHandle,
    WrongType,
    AccessDenied,
    InvalidArgs,
    NoMemory,
    LimitReached,
    PeerClosed,
    WouldBlock,
    BadState,
    /// A code this abi does not know, which a later kernel may return; it
    /// is above the codes of `KNOWN`. The kernel this abi comes with never
    /// returns one.
    Unknown(u64),
}

impl Error {
    /// The errors this abi knows, in the order of their codes from 1.
    pub const KNOWN: [Error; 9] = [
        Error::BadHandle,
        Error::WrongType,
        Error::AccessDenied,
        Error::InvalidArgs,
        Error::NoMemory,
        Error::LimitReached,
        Error::PeerClosed,
        Error::WouldBlock,
        Error::BadState,
    ];

    /// The code of the error in x0.
    pub const fn code(self) -> u64 {
        match self {
            Error::BadHandle => 1,
            Error::WrongType => 2,
            Error::AccessDenied => 3,
            Error::InvalidArgs => 4,
            Error::NoMemory => 5,
            Error::LimitReached => 6,
            Error::PeerClosed => 7,
            Error::WouldBlock => 8,
            Error::BadState => 9,
            Error::Unknown(code) => code,
        }
    }

    /// The error whose code x0 holds after a call; None for 0, which is
    /// success, and `Unknown` for a code this abi does not know.
    pub const fn from_code(code: u64) -> Option<Error> {
        match code {
            0 => None,
            1..=9 => Some(Self::KNOWN[code as usize - 1]),
            _ => Some(Error::Unknown(code)),
        }
    }
}

/// The exit code of a program that panicked (lib/rt), the one Rust's own
/// programs exit with.
pub const PANIC_EXIT_CODE: u64 = 101;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_packs_index_and_generation() {
        let h = Handle::new(0xBEEF, 0x1234_5678_9ABC);
        assert_eq!(h.0, 0x1234_5678_9ABC_BEEF);
        assert_eq!((h.index(), h.generation()), (0xBEEF, 0x1234_5678_9ABC));
    }

    #[test]
    fn max_generation_keeps_the_index() {
        assert_eq!(Handle::GENERATION_BITS, 48);
        assert_eq!(Handle::MAX_GENERATION, (1 << 48) - 1);
        let h = Handle::new(Handle::MAX_INDEX, Handle::MAX_GENERATION);
        assert_eq!(h, Handle(u64::MAX));
        assert_eq!(
            (h.index(), h.generation()),
            (Handle::MAX_INDEX, Handle::MAX_GENERATION)
        );
    }

    #[test]
    fn handle_is_eight_bytes() {
        assert_eq!(core::mem::size_of::<Handle>(), 8);
    }

    #[test]
    fn handle_with_a_generation_is_never_zero() {
        assert_ne!(Handle::new(0, 1), Handle::INVALID);
    }

    #[test]
    fn rights_contain_their_subsets() {
        let r = Rights::SEND | Rights::DUPLICATE;
        assert!(r.contains(Rights::SEND));
        assert!(r.contains(Rights::NONE));
        assert!(!r.contains(Rights::RECEIVE));
        assert!(!r.contains(Rights::SEND | Rights::RECEIVE));
    }

    #[test]
    fn rights_are_distinct_bits() {
        let all = [
            Rights::DUPLICATE,
            Rights::TRANSFER,
            Rights::SEND,
            Rights::NOTIFY,
            Rights::RECEIVE,
            Rights::MAP_READ,
            Rights::MAP_WRITE,
            Rights::MAP_EXEC,
            Rights::MANAGE,
            Rights::DEVICE,
            Rights::DEBUG,
            Rights::KSTATS,
        ];
        let union = all.iter().fold(Rights::NONE, |a, b| a | *b);
        assert_eq!(union.0.count_ones(), 12);
        assert_eq!(union, Rights::ALL);
    }

    #[test]
    fn call_numbers_are_dense_from_one() {
        assert_eq!(Call::ALL.len(), 28);
        for (i, call) in Call::ALL.iter().enumerate() {
            assert_eq!(call.number(), i as u16 + 1);
            assert_eq!(Call::from_number(call.number()), Some(*call));
            assert!(!TEST_CALLS.contains(&call.number()));
        }
        for n in [0, 29, 0xFEFF, *TEST_CALLS.start(), *TEST_CALLS.end()] {
            assert_eq!(Call::from_number(n), None);
        }
    }

    #[test]
    fn calls_keep_the_order_of_the_spec() {
        assert_eq!(Call::HandleClose.number(), 1);
        assert_eq!(Call::MemCreate.number(), 8);
        assert_eq!(Call::ProcessCreate.number(), 12);
        assert_eq!(Call::ThreadCreate.number(), 15);
        assert_eq!(Call::Yield.number(), 19);
        assert_eq!(Call::ClockNow.number(), 23);
        assert_eq!(Call::ObjectInfo.number(), 27);
        assert_eq!(Call::DebugWrite.number(), 28);
        assert_eq!(RESULT_VALUES, 9);
    }

    #[test]
    fn inline_bytes_fill_x2_to_x9_low_byte_first() {
        assert_eq!(INLINE_MAX, 64);
        let bytes: [u8; INLINE_MAX] = core::array::from_fn(|i| i as u8 + 1);
        let words = inline_words(&bytes);
        assert_eq!(words[0], 0x0807_0605_0403_0201);
        assert_eq!(words[7], 0x403F_3E3D_3C3B_3A39);
        assert_eq!(inline_bytes(&words), bytes);
        assert_eq!(inline_words(b"abc"), [0x63_6261, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(inline_words(b""), [0; 8]);
    }

    #[test]
    #[should_panic(expected = "at most 64 bytes")]
    fn inline_words_take_at_most_64_bytes() {
        inline_words(&[0; INLINE_MAX + 1]);
    }

    #[test]
    fn init_handles_are_the_first_entries_at_generation_one() {
        assert_eq!(INIT_RESOURCE, Handle::new(0, 1));
        assert_eq!(INIT_PROCESS, Handle::new(1, 1));
        assert_eq!(INIT_THREAD, Handle::new(2, 1));
        assert_eq!(INIT_BOOT_IMAGE, Handle::new(3, 1));
    }

    #[test]
    fn init_stack_and_message_buffer_have_fixed_places() {
        assert_eq!(INIT_STACK_TOP, 0x1_0000_0000);
        assert_eq!(INIT_MSGBUF, 0x1_0000_1000);
    }

    #[test]
    fn handles_from_the_kernel_carry_fixed_rights() {
        assert_eq!(
            INIT_RESOURCE_RIGHTS,
            Rights::DEVICE | Rights::DEBUG | Rights::KSTATS | Rights::DUPLICATE | Rights::TRANSFER
        );
        assert_eq!(
            OWNER_RIGHTS,
            Rights::DUPLICATE | Rights::TRANSFER | Rights::MANAGE
        );
        assert_eq!(
            CHANNEL_RIGHTS,
            Rights::SEND | Rights::NOTIFY | Rights::RECEIVE | Rights::DUPLICATE | Rights::TRANSFER
        );
    }

    #[test]
    fn sources_keep_their_codes() {
        let known = [
            (Source::Message, 0),
            (Source::Unlabeled, 1),
            (Source::Session, 2),
            (Source::Timer, 3),
            (Source::Exit, 4),
            (Source::Interrupt, 5),
        ];
        for (source, code) in known {
            assert_eq!(source.code(), code);
            assert_eq!(Source::from_code(code), source);
        }
        assert_eq!(Source::from_code(15), Source::Unknown(15));
        assert_eq!(Source::Unknown(15).code(), 15);
        assert_eq!((NO_WAIT, SOURCE_SHIFT), (1 << 16, 24));
        assert_eq!((MESSAGE_MAX, MESSAGE_HANDLES, HANDLES_SHIFT), (1024, 4, 12));
    }

    #[test]
    fn sessions_have_fixed_bounds() {
        assert_eq!(CLIENT_GONE, 1 << 63);
        assert_eq!(MAX_SLOTS, 1024);
    }

    #[test]
    fn timers_have_a_fixed_bound() {
        assert_eq!(MAX_TIMERS, 64);
    }

    #[test]
    fn notification_travels_in_eleven_words() {
        let n = Notification {
            source: Source::Session,
            label: 0x1ABE1,
            bits: 1 << 63 | 5,
            count: u32::MAX,
        };
        let words = [
            2 << 24,
            1 << 63 | 5,
            0xFFFF_FFFF,
            0,
            0,
            0,
            0,
            0,
            0,
            0x1ABE1,
            0,
        ];
        assert_eq!(n.to_words(), words);
        assert_eq!(Notification::from_words(words), n);
    }

    #[test]
    fn message_travels_in_eleven_words() {
        let m = Message {
            len: 1024,
            handles: 4,
            words: core::array::from_fn(|i| i as u64 + 1),
            label: 0x1ABE1,
            token: 7 << 16 | 3,
        };
        let words = [1024 | 4 << 12, 1, 2, 3, 4, 5, 6, 7, 8, 0x1ABE1, 7 << 16 | 3];
        assert_eq!(m.to_words(), words);
        assert_eq!(Message::from_words(words), m);
        let mut w = [u64::MAX; 11];
        Notification::from_words(words).write_words(&mut w);
        assert_eq!(w, Notification::from_words(words).to_words());
    }

    #[test]
    fn process_state_travels_in_four_words() {
        assert_eq!(INFO_PROCESS_STATE, 1);
        let fault = ProcessState::Fault {
            esr: 0x9200_0004,
            far: 0x1000,
            elr: 0x40_0000,
        };
        let states = [
            (ProcessState::Alive, [0, 0, 0, 0]),
            (ProcessState::Exited { code: 7 }, [1, 7, 0, 0]),
            (ProcessState::Killed, [2, 0, 0, 0]),
            (fault, [3, 0x9200_0004, 0x1000, 0x40_0000]),
        ];
        for (state, words) in states {
            assert_eq!(state.to_words(), words);
            assert_eq!(ProcessState::from_words(words), state);
        }
    }

    #[test]
    fn process_memory_travels_in_three_words() {
        assert_eq!(INFO_PROCESS_MEMORY, 2);
        let memory = ProcessMemory {
            quota: 64 << 10,
            used: 1536,
            returned: (64 << 10) - 1536,
        };
        assert_eq!(memory.to_words(), [64 << 10, 1536, (64 << 10) - 1536]);
        assert_eq!(ProcessMemory::from_words(memory.to_words()), memory);
    }

    #[test]
    fn process_handles_travel_in_three_words() {
        assert_eq!(INFO_PROCESS_HANDLES, 3);
        let handles = ProcessHandles {
            live: 5,
            retired: 1,
            limit: 16,
        };
        assert_eq!(handles.to_words(), [5, 1, 16]);
        assert_eq!(ProcessHandles::from_words(handles.to_words()), handles);
    }

    #[test]
    fn kernel_stats_travel_in_eight_words() {
        assert_eq!(INFO_KERNEL_STATS, 4);
        let words = [1, 2, 3, 4, 5, 6, 7, 8];
        let stats = KernelStats::from_words(words);
        assert_eq!(
            (stats.idle, stats.cleanup_queue, stats.pool_pages),
            (1, 4, 7)
        );
        assert_eq!(
            (stats.idle_latency, stats.irq_latency, stats.longest_portion),
            (2, 3, 5)
        );
        assert_eq!((stats.free_frames, stats.longest_batch), (6, 8));
        assert_eq!(stats.to_words(), words);
    }

    #[test]
    fn unknown_process_state_keeps_its_words() {
        for words in [[4, 5, 6, 7], [u64::MAX, 0, 0, 1]] {
            let state = ProcessState::from_words(words);
            assert_eq!(state, ProcessState::Unknown(words));
            assert_eq!(state.to_words(), words);
        }
    }

    #[test]
    fn policies_and_levels_are_fixed() {
        assert_eq!(Policy::RoundRobin as u8, 0);
        assert_eq!(Policy::Fifo as u8, 1);
        assert_eq!(Policy::from_raw(0), Some(Policy::RoundRobin));
        assert_eq!(Policy::from_raw(1), Some(Policy::Fifo));
        assert_eq!(Policy::from_raw(2), None);
        assert_eq!(Policy::from_raw(1 << 32), None);
        assert_eq!(PRIORITY_LEVELS, 64);
        assert_eq!(RR_QUANTUM_NS, 4_000_000);
    }

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(Error::BadHandle.code(), 1);
        assert_eq!(Error::InvalidArgs.code(), 4);
        assert_eq!(Error::WouldBlock.code(), 8);
        assert_eq!(Error::BadState.code(), 9);
    }

    #[test]
    fn error_codes_come_back_from_x0() {
        assert_eq!(Error::from_code(0), None);
        for (i, e) in Error::KNOWN.iter().enumerate() {
            let code = i as u64 + 1;
            assert_eq!(e.code(), code);
            assert_eq!(Error::from_code(code), Some(*e));
        }
        assert_eq!(Error::from_code(4), Some(Error::InvalidArgs));
    }

    #[test]
    fn unknown_error_codes_come_back_as_they_are() {
        for code in [10, 1 << 32, u64::MAX] {
            assert_eq!(Error::from_code(code), Some(Error::Unknown(code)));
            assert_eq!(Error::Unknown(code).code(), code);
        }
    }

    #[test]
    fn a_panic_ends_a_program_with_its_own_code() {
        assert_eq!(PANIC_EXIT_CODE, 101);
    }
}
