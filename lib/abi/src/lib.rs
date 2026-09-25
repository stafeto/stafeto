// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The stafeto kernel interface shared by the kernel and programs (spec 5,
//! 8, 11, 12, 13.3): handle layout, rights, system call numbers and where
//! their arguments and results go, init's first handles, scheduling
//! policies and error codes.

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

/// Rights of the handle that `process_create` or `thread_create` returns,
/// and of init's handles to its own process and first thread.
pub const OWNER_RIGHTS: Rights =
    Rights(Rights::DUPLICATE.0 | Rights::TRANSFER.0 | Rights::MANAGE.0);

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
/// and SIMD registers stay as they were. Unknown numbers, 0 included, and
/// reserved values of arguments fail with INVALID_ARGS; a narrow argument
/// with bits set above its width is such a value.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Call {
    HandleClose = 1,
    HandleDuplicate = 2,
    ChannelCreate = 3,
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
        Call::ChannelCreate,
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

/// Kinds of `object_info` (spec 11); 0 is reserved.
///
/// PROCESS_STATE takes a process handle, with no right needed, and returns
/// `ProcessState::to_words` in x1-x4.
pub const INFO_PROCESS_STATE: u64 = 1;

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
        }
    }

    /// The state from x1-x4 of `object_info`; None for an unknown one.
    pub const fn from_words(words: [u64; 4]) -> Option<ProcessState> {
        match words[0] {
            0 => Some(ProcessState::Alive),
            1 => Some(ProcessState::Exited { code: words[1] }),
            2 => Some(ProcessState::Killed),
            3 => Some(ProcessState::Fault {
                esr: words[1],
                far: words[2],
                elr: words[3],
            }),
            _ => None,
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

/// Error codes of system calls (spec 12); zero means success.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    BadHandle = 1,
    WrongType = 2,
    AccessDenied = 3,
    InvalidArgs = 4,
    NoMemory = 5,
    LimitReached = 6,
    PeerClosed = 7,
    WouldBlock = 8,
    BadState = 9,
}

impl Error {
    /// The error whose code x0 holds after a call; None for 0, which is
    /// success, and for a code no error has.
    pub const fn from_code(code: u64) -> Option<Error> {
        match code {
            1 => Some(Error::BadHandle),
            2 => Some(Error::WrongType),
            3 => Some(Error::AccessDenied),
            4 => Some(Error::InvalidArgs),
            5 => Some(Error::NoMemory),
            6 => Some(Error::LimitReached),
            7 => Some(Error::PeerClosed),
            8 => Some(Error::WouldBlock),
            9 => Some(Error::BadState),
            _ => None,
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
            assert_eq!(ProcessState::from_words(words), Some(state));
        }
        assert_eq!(ProcessState::from_words([4, 0, 0, 0]), None);
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
        assert_eq!(Error::BadHandle as u32, 1);
        assert_eq!(Error::WouldBlock as u32, 8);
        assert_eq!(Error::BadState as u32, 9);
    }

    #[test]
    fn error_codes_come_back_from_x0() {
        for code in 1..=9 {
            let e = Error::from_code(code).expect("a known code");
            assert_eq!(e as u64, code);
        }
        assert_eq!(Error::from_code(4), Some(Error::InvalidArgs));
        for code in [0, 10, 1 << 32, u64::MAX] {
            assert_eq!(Error::from_code(code), None);
        }
    }

    #[test]
    fn a_panic_ends_a_program_with_its_own_code() {
        assert_eq!(PANIC_EXIT_CODE, 101);
    }
}
