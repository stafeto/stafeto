// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the test init (tests/init) and its child program (src/main.rs,
//! the second file of the test boot image) agree on (spec 13.3, 15.2): the
//! roles a parent names in the start data of its child (rt::startup), with
//! their arguments and handles, the codes of a child whose start failed,
//! and the places of the child's space the tests use.

#![no_std]

use rt::startup::StartError;

/// Arguments of a role: the words of the start data's arguments after the
/// role's code.
pub const ARGS: usize = 7;
/// The names the handles of a role come under in its start data, handle
/// i under name i.
pub const NAMES: [&str; 4] = ["0", "1", "2", "3"];

/// Where the parent maps a page of marks into its child before the child's
/// first thread starts: words the child writes and the parent reads. It
/// shares the table of the last level with the program, which lld puts at
/// 0x20_0000.
pub const MARKS: usize = 0x3F_F000;
/// The mark each child adds 1 to as it starts, before its start request.
pub const STARTED: usize = 0;

/// Where a child maps SCRATCH_PAGES pages of an object of its own
/// (WriteProtected, ReadUnmapped), below SHARED, under the same table as
/// its marks.
pub const SCRATCH: usize = 0x3B_E000;
/// Two pages more than a portion of mem_protect and mem_unmap, 32 pages,
/// or 8 when they become executable (spec 7.7): the last page is the
/// second of the last portion of each of these changes, past the first
/// page of any portion.
pub const SCRATCH_PAGES: usize = 34;
/// The page of the scratch mapping that the roles write, read and fault
/// at: its last.
pub const SCRATCH_LAST: usize = SCRATCH + (SCRATCH_PAGES - 1) * 0x1000;
/// Where a child maps a memory object that a message brought or that it
/// made to send (Role::Service, Role::Provider), and the pages there,
/// between the scratch mapping and its marks: under the same table as its
/// marks, so the mapping takes no new table.
pub const SHARED: usize = 0x3E_0000;
pub const SHARED_PAGES: usize = 16;
const _: () = assert!(
    SCRATCH + SCRATCH_PAGES * 0x1000 <= SHARED && SHARED + SHARED_PAGES * 0x1000 <= MARKS,
    "the places of a child's own mappings overlap"
);
/// Where a grandparent maps the boot image, and the window of its loader
/// (rt::loader): above its message buffer, under the table of the second
/// level that the buffer took.
pub const IMAGE: usize = 0x1_0020_0000;
pub const WINDOW: usize = 0x1_0040_0000;

/// The message of the child's panic (Role::Panic).
pub const PANIC: &str = "the child panics on purpose";
/// The first byte of the kernel's image (kcore::layout::KERNEL_VIRT),
/// which a program may not reach.
pub const KERNEL: u64 = 0xFFFF_FFFF_C000_0000;
/// The ceiling of a child that runs Role::Ceiling.
pub const CEILING: u8 = 30;

/// The 8 bytes of the request of Role::Rtc that brings its channel for a
/// binding.
pub const BIND: u64 = u64::from_le_bytes(*b"bind rtc");

/// The code a role ends with when the fault it exists for did not come.
pub const NO_FAULT: u64 = 0xFA17;
/// The code a child ends with when its start data named no role, and
/// when a call of its role failed.
pub const FAILED: u64 = 0xBAD;
/// The codes a child ends with when rt::startup failed (`start_failed`).
pub const START_FAILED: u64 = 0x57A7_0000;

/// The code of a child whose rt::startup failed with `e`: START_FAILED
/// plus 1 for Taken, 2 for Malformed, 3 for TooMuch, 4 for Missing, 0x100
/// and the code of the kernel's error, 0x1000 and the status of a refusal.
pub fn start_failed(e: StartError) -> u64 {
    START_FAILED
        + match e {
            StartError::Taken => 1,
            StartError::Malformed => 2,
            StartError::TooMuch => 3,
            StartError::Missing => 4,
            StartError::Kernel(e) => 0x100 + e.code(),
            StartError::Refused(status) => 0x1000 + u64::from(status.code()),
        }
}

/// The marks of Role::Churn: copies made, rounds, rounds that ended with
/// NO_MEMORY, the most the child used and its quota.
pub const MADE: usize = 1;
pub const ROUNDS: usize = 2;
pub const FULL: usize = 3;
pub const MOST_USED: usize = 4;
pub const QUOTA: usize = 5;
/// The address of the instruction Role::Load and Role::Wfi fault at, which
/// the child marks before it.
pub const FAULT_AT: usize = 6;
/// The mark a helper thread of a role adds 1 to as it runs, and what it
/// saw (Role::LastThread, Role::BufferBack): 1 for what it looked for.
pub const HELPER: usize = 7;
pub const SEEN: usize = 8;

/// What a child does once it has its start data.
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
    /// Maps SCRATCH_PAGES pages of a new object at SCRATCH, RW, through
    /// handle 0, its own process with MANAGE, writes to SCRATCH_LAST, gives
    /// the mapping the access in argument 0 (abi::Access, R or RX) with
    /// mem_protect and writes to that page again.
    WriteProtected = 8,
    /// Maps SCRATCH_PAGES pages of a new object at SCRATCH, RW, through
    /// handle 0, writes and reads SCRATCH_LAST, unmaps the mapping and
    /// reads that page again.
    ReadUnmapped = 9,
    /// Loads the child program of the boot image, handle 1, as its own
    /// child: quota argument 0, ceiling and priority argument 1, exit
    /// channel handle 2 at priority 1, marks mapped from handle 3, a
    /// memory object; handle 0 is its own process with MANAGE. It answers
    /// the grandchild's START requests with its process, its thread and
    /// Spin on the word in argument 2 (rt::startup::Giver), then sends an
    /// empty request through its start channel and waits for good.
    Grandparent = 10,
    /// Adds 1 to the mark in argument 0 for ever.
    Spin = 11,
    /// Makes copies of handle 0, its own process with DUPLICATE, until a
    /// call fails, and closes them, round after round, until it made the
    /// number in argument 0; leaves its marks MADE to QUOTA.
    Churn = 12,
    /// Waits for an interrupt with `wfi`, which traps at EL0 (spec 7.9),
    /// with the address of the `wfi` in its mark FAULT_AT first.
    Wfi = 13,
    /// Starts a helper thread at argument 0, below itself, which marks
    /// SEEN when object_info of handle 0, its own process, says it lives,
    /// marks HELPER and ends; makes another thread it never starts; and
    /// ends its own thread first.
    LastThread = 14,
    /// Starts a helper thread at argument 1, below itself, which would
    /// mark HELPER, and ends its process with the code in argument 0.
    ExitProcess = 15,
    /// Starts a helper thread at argument 0, below itself, which would
    /// mark HELPER, and kills its own process through handle 0.
    KillItself = 16,
    /// Notifies its start channel with the bits in argument 0, which
    /// carries SEND and TRANSFER alone (rt::loader::spawn), and ends with
    /// the code of the error, or 0.
    Notify = 17,
    /// Replies with 8 bytes to the token in argument 0 and ends with x0 of
    /// the call.
    Reply = 18,
    /// Takes a request through handle 0, a channel with RECEIVE, and ends
    /// its process with 0, answering nothing.
    TakeThenExit = 19,
    /// Sends argument 0 as 8 bytes through handle 0, a channel with SEND,
    /// and ends with the first word of the reply or the code of the
    /// error; it keeps handle 1.
    Send = 20,
    /// Through handle 0, its own process, and handle 1, its first thread:
    /// starts a helper thread at argument 0, below itself, and lowers
    /// itself below the helper, which marks SEEN when its message buffer
    /// reads zero and takes a write, and ends. Ends with 0 when the buffer
    /// was charged, its used memory is back as it was before the helper,
    /// and the helper's handle still names a thread that ended
    /// (BAD_STATE); else with a code that says what was wrong.
    BufferBack = 21,
    /// Answers the number of requests in argument 0 through handle 0, a
    /// channel with RECEIVE, each with its own bytes, and ends with 0.
    Serve = 22,
    /// Under ceiling CEILING, makes the calls of Checked argument 0 with
    /// priorities above and at its ceiling, through handle 0, a thread,
    /// and handle 1, its process, both under ceiling 63 with MANAGE, and
    /// ends with 0 when each did as it must, else with the number of the
    /// first case that did not.
    Ceiling = 23,
    /// A service of memory objects (spec 6.2): takes one request through
    /// handle 0, a channel with RECEIVE, whose words give a length in
    /// bytes and a word to write and which brings a memory object, and
    /// maps the object at SHARED through handle 1, its own process with
    /// MANAGE, RW; when that fails, it asks for RX, then maps it R and asks
    /// mem_protect of that mapping to RW and to RX. It answers with seven
    /// words: the info word of the object's handle, the sum of the object's
    /// words, its first word, and x0 of the calls that map RW and RX and
    /// change R to RW and RX (0 for those it did not make); a mapping RW
    /// gets the word to write in its second word after the sum. A service
    /// that goes by what the words say copies them to its own memory first;
    /// this one only adds them up. Ends with 0.
    Service = 24,
    /// A provider of memory objects (spec 6.2): takes one request through
    /// handle 0, a channel with RECEIVE, whose words give a count of pages
    /// and a seed; makes an object of that many pages, which its quota
    /// pays for, maps it at SHARED through handle 1, its own process with
    /// MANAGE, RW, puts the seed plus i in its word i, unmaps it, and
    /// answers with the memory it uses then (PROCESS_MEMORY) and a copy of
    /// the object's handle with MAP_READ and TRANSFER alone, the only one
    /// left once it closed its own. Ends with 0.
    Provider = 25,
    /// A driver of the PL031 (spec 13.4, 13.5): makes a channel, sends a
    /// copy of it with NOTIFY and TRANSFER through its start channel in a
    /// request of BIND, whose reply brings the binding of the PL031's line
    /// to the channel; waits in receive for an interrupt, then sends the
    /// info word of the binding's handle and the source, label, bits and
    /// count of the notification in a request that no reply answers. It
    /// never calls irq_ack: the line stays masked until the child dies.
    /// With a word other than 0 it sends a second copy of its channel with
    /// RECEIVE and TRANSFER in BIND, and after the reply waits in a request that
    /// no reply answers without taking the notification.
    Rtc = 26,
    /// Handle 0 the system resource with DEBUG, its console. Notifies
    /// through the value of a channel it made and closed: in the strict
    /// build of the test images BAD_HANDLE panics (spec 5.4), the panic
    /// names the call, and the child ends with abi::PANIC_EXIT_CODE; it
    /// ends with the code of the error otherwise.
    BadHandle = 27,
    /// Handle 0 the system resource with DEBUG, its console. Makes a
    /// channel, takes its value a second time with Handle::from_raw,
    /// closes the channel and drops the second handle: in the strict build
    /// the drop's BAD_HANDLE panics and names handle_close; it ends with 0
    /// otherwise.
    DoubleClose = 28,
    /// Checks its start data (rt::startup): its process lives
    /// (PROCESS_STATE), its thread answers THREAD_STATE, handle 0 taken as
    /// a timer is WrongKind and stays, taken as the system resource it
    /// comes, handle 1 comes as a memory object, no handle comes under
    /// name 2, and name 0 is gone once taken. Ends with 0, or with the
    /// number of the first check that failed.
    Named = 29,
    /// Asks for its start data a second time and for init's first handles:
    /// ends with 0 when rt::startup gives Taken and rt::init_handles None.
    Once = 30,
    /// Checks that its start data brought handles under the names 0 to 5
    /// and ARGS_MAX (256) bytes of arguments, byte i past the first 64
    /// being i as a byte. Ends with 0, or with the number of the first
    /// check that failed.
    Spans = 31,
}

impl Role {
    pub const ALL: [Role; 31] = [
        Role::Exit,
        Role::Echo,
        Role::Recurse,
        Role::Panic,
        Role::Load,
        Role::WriteCode,
        Role::RunData,
        Role::WriteProtected,
        Role::ReadUnmapped,
        Role::Grandparent,
        Role::Spin,
        Role::Churn,
        Role::Wfi,
        Role::LastThread,
        Role::ExitProcess,
        Role::KillItself,
        Role::Notify,
        Role::Reply,
        Role::TakeThenExit,
        Role::Send,
        Role::BufferBack,
        Role::Serve,
        Role::Ceiling,
        Role::Service,
        Role::Provider,
        Role::Rtc,
        Role::BadHandle,
        Role::DoubleClose,
        Role::Named,
        Role::Once,
        Role::Spans,
    ];

    /// The role whose code is `code`.
    pub fn from_code(code: u64) -> Option<Role> {
        Role::ALL.into_iter().find(|&r| r as u64 == code)
    }
}

/// The calls whose priority Role::Ceiling checks against its own ceiling
/// (spec 8, 11): thread_set_priority and thread_create above the ceiling
/// of the caller, under that of the target; process_create, its ceiling
/// and, with an exit channel, the priority of the exit notification (x4);
/// channel_create; handle_duplicate with a label; timer_create.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Checked {
    ThreadSetPriority = 1,
    ThreadCreate = 2,
    ProcessCreate = 3,
    ExitChannel = 4,
    CreateChannel = 5,
    Label = 6,
    TimerCreate = 7,
}

impl Checked {
    pub const ALL: [Checked; 7] = [
        Checked::ThreadSetPriority,
        Checked::ThreadCreate,
        Checked::ProcessCreate,
        Checked::ExitChannel,
        Checked::CreateChannel,
        Checked::Label,
        Checked::TimerCreate,
    ];

    /// The call whose code is `code`.
    pub fn from_code(code: u64) -> Option<Checked> {
        Checked::ALL.into_iter().find(|&c| c as u64 == code)
    }
}

/// The first 64 bytes of the arguments of a child's start data: the
/// role's code, then `args`, at most ARGS words, then zeros.
pub fn args(role: Role, args: &[u64]) -> [u8; abi::INLINE_MAX] {
    let mut words = [0; 8];
    words[0] = role as u64;
    words[1..=args.len()].copy_from_slice(args);
    abi::inline_bytes(&words)
}

/// The role and its words in the arguments of a child's start data; None
/// when they are shorter than 64 bytes or name no role.
pub fn role_of(args: &[u8]) -> Option<(Role, [u64; ARGS])> {
    let words = abi::inline_words(args.get(..abi::INLINE_MAX)?);
    let role = Role::from_code(words[0])?;
    let mut rest = [0; ARGS];
    rest.copy_from_slice(&words[1..]);
    Some((role, rest))
}

/// x0-x9 filled with marks, for calls that must change x0 alone.
pub fn marked() -> rt::sys::Regs {
    core::array::from_fn(|i| 0x5A5A_0000 + i as u64)
}

/// Call `N` with `args` in x0 and up and marks in the rest of x0-x9: true
/// when x0 comes back as `x0`, 0 or the code of an error, and no other
/// register changed (spec 11). The caller passes arguments the call
/// refuses, or makes a call that returns nothing and runs no code of the
/// caller's process.
pub fn x0_alone<const N: u16>(args: &[u64], x0: u64) -> bool {
    let mut x = marked();
    x[..args.len()].copy_from_slice(args);
    // SAFETY: by the contract above, the call runs no code of this process
    // and uses none of its memory.
    let after = unsafe { rt::sys::raw::<N>(x) };
    after[0] == x0 && after[1..] == x[1..]
}

/// The child program, the file `child` of the boot image `image` (spec
/// 13.1): None when the image or the program does not parse.
pub fn program_in(image: &[u8]) -> Option<bootimg::Program<'_>> {
    bootimg::BootImage::parse(image)
        .ok()
        .and_then(|image| image.files().find(|f| f.name == "child"))
        .and_then(|file| bootimg::Program::parse(file.data).ok())
}
