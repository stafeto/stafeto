// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the test init (tests/init) and its child program (src/main.rs,
//! the second file of the test boot image) agree on (spec 13.3, 15.2): the
//! child's start request, the roles its parent names in the reply, with
//! their arguments and handles, and the places of the child's space the
//! tests use.

#![no_std]

/// The 8 bytes of the start request a child sends through
/// abi::START_CHANNEL as it starts (spec 13.3).
pub const HELLO: u64 = u64::from_le_bytes(*b"child up");

/// Arguments of a role: the words of the reply after the role's code.
pub const ARGS: usize = 7;

/// Where the parent maps a page of marks into its child before the child's
/// first thread starts: words the child writes and the parent reads. It
/// shares the table of the last level with the program, which lld puts at
/// 0x20_0000.
pub const MARKS: usize = 0x3F_F000;
/// The mark each child adds 1 to as it starts, before its start request.
pub const STARTED: usize = 0;

/// Where a child maps a page of its own (WriteReadOnly, ReadUnmapped),
/// under the same table as its marks.
pub const SCRATCH: usize = 0x3F_E000;
/// Where a grandparent maps the boot image, and the window of its loader
/// (rt::loader): above its message buffer, under the table of the second
/// level that the buffer took.
pub const IMAGE: usize = 0x1_0020_0000;
pub const WINDOW: usize = 0x1_0040_0000;

/// The message of the child's panic (Role::Panic).
pub const PANIC: &str = "the child panics on purpose";

/// The code a role ends with when the fault it exists for did not come.
pub const NO_FAULT: u64 = 0xFA17;
/// The code a child ends with when its start request failed or named no
/// role, and when a call of its role failed.
pub const FAILED: u64 = 0xBAD;

/// The marks of Role::Churn: copies made, rounds, rounds that ended with
/// NO_MEMORY, the most the child used and its quota.
pub const MADE: usize = 1;
pub const ROUNDS: usize = 2;
pub const FULL: usize = 3;
pub const MOST_USED: usize = 4;
pub const QUOTA: usize = 5;
/// The address of the instruction Role::Load faults at, which the child
/// marks before it.
pub const FAULT_AT: usize = 6;

/// What a child does once its start request has its answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Ends with the code in argument 0.
    Exit = 1,
    /// Sends its seven arguments back as a request through its start
    /// channel and ends with the first word of the reply.
    Echo = 2,
    /// Recurses without end: its stack runs into the guard page.
    Recurse = 3,
    /// Prints through handle 0, the system resource with DEBUG, and
    /// panics with PANIC.
    Panic = 4,
    /// Loads the word at the address in argument 0, with the address of
    /// the load in its mark FAULT_AT first.
    Load = 5,
    /// Asks mem_protect through handle 0, its own process with MANAGE, to
    /// make its code, the mapping of argument 1 bytes at argument 0,
    /// writable, which must fail with ACCESS_DENIED; then writes a word
    /// of its code.
    WriteCode = 6,
    /// Asks mem_protect through handle 0, its own process with MANAGE, to
    /// make its data (argument 1 bytes at argument 0), its stack (argument
    /// 3 bytes at argument 2) and its page of marks executable, which must
    /// fail with ACCESS_DENIED each: they are mapped through copies with
    /// MAP_READ and MAP_WRITE alone. Then branches to a word of its data.
    RunData = 7,
    /// Maps a page of a new object at SCRATCH, RW, through handle 0, its
    /// own process with MANAGE, writes to it, makes it R with mem_protect
    /// and writes to it again.
    WriteReadOnly = 8,
    /// Maps a page of a new object at SCRATCH, RW, through handle 0,
    /// writes and reads it, unmaps it and reads it again.
    ReadUnmapped = 9,
    /// Loads the child program of the boot image, handle 1, as its own
    /// child: quota argument 0, ceiling and priority argument 1, exit
    /// channel handle 2 at priority 1, marks mapped from handle 3, a
    /// memory object; handle 0 is its own process with MANAGE. It answers
    /// the grandchild's start request with Spin on the word in argument
    /// 2, then sends an empty request through its start channel and waits
    /// for good.
    Grandparent = 10,
    /// Adds 1 to the mark in argument 0 for ever.
    Spin = 11,
    /// Makes copies of handle 0, its own process with DUPLICATE, until a
    /// call fails, and closes them, round after round, until it made the
    /// number in argument 0; leaves its marks MADE to QUOTA.
    Churn = 12,
}

impl Role {
    pub const ALL: [Role; 12] = [
        Role::Exit,
        Role::Echo,
        Role::Recurse,
        Role::Panic,
        Role::Load,
        Role::WriteCode,
        Role::RunData,
        Role::WriteReadOnly,
        Role::ReadUnmapped,
        Role::Grandparent,
        Role::Spin,
        Role::Churn,
    ];

    /// The role whose code is `code`.
    pub fn from_code(code: u64) -> Option<Role> {
        Role::ALL.into_iter().find(|&r| r as u64 == code)
    }
}

/// The bytes of the reply to a start request: the role's code, then `args`,
/// at most ARGS words, then zeros.
pub fn reply(role: Role, args: &[u64]) -> [u8; abi::INLINE_MAX] {
    let mut words = [0; 8];
    words[0] = role as u64;
    words[1..=args.len()].copy_from_slice(args);
    abi::inline_bytes(&words)
}
