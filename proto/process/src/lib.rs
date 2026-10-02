// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Process protocol v4 (spec 2, section 3.1). The service creates every
//! POSIX process itself, so that a record comes with its process and goes
//! only with the notification of its end. The label of a session names
//! the caller's record (`Label`), never the body.
//!
//! Through the service's channel with no label, which only the service's
//! own threads and init hold: Create, body `Create` (`Create::write`) and
//! two handles, the start channel init gave (B) and the witness, which the
//! service closes once the process ended (proto_init ADOPT); the service makes the
//! record, its exit place and the process, and replies status u32, pid
//! u32, label u64 with two handles: the process (MANAGE, DUPLICATE,
//! TRANSFER) for the load, and the record's session. Loaded, body label
//! u64 and one handle, the first thread (MANAGE), the router of the
//! process's signals: the process was loaded and runs; reply its status, and the parent
//! whose Spawn made it gets its PID. Abandon, body label u64 (0 for no
//! record), parent label u64 (0 for none) and status u32: the process,
//! if any, is killed, and the record goes with its end; the parent's
//! Spawn gets the status; reply its own status. Next: no body; the reply,
//! once a Spawn waits, is status u32, zero u32, the parent's label u64,
//! the name of the record of init's table, 16 bytes, and the level of the
//! parent's Spawn u32 (`Next`).
//!
//! WaitStart, WaitTake and WaitCancel, through a session: wait for a child
//! in two steps (proto_wire::long, spec 2, 3.4). WaitStart: body
//! `WaitStart`; READY with a `WaitResult` when a child's state is there
//! (or none is, for WNOHANG, or there is no such child), WAIT k otherwise.
//! WaitTake: body k u64 and a copy of the caller's channel with NOTIFY,
//! labelled k: READY or ARMED, then bit 0 through the copy once a child of
//! the selector ended. WaitCancel: body k u64: READY or CANCELLED.
//!
//! Kill, through a session: body pid i32 as a u32 and signal u32 (0 to
//! 64); pid > 0 names a process, 0 the sender's group, -1 every process
//! but the sender's the sender may signal, < -1 the group -pid; the
//! reply, once the signal is there or the walk of a group or of every
//! process is over (one step at a time, in the service's loop), is its
//! status: NO_PROCESS for none found, PERMISSION when none took it,
//! INVALID for a signal past 64 and for the stop signals until stops come
//! (5e), AGAIN while another walk of the sender's record is on. Router, through a
//! session: no body and one handle, the thread (MANAGE) whose entry the
//! service asks for once it set a signal on the page, in place of the
//! first thread; reply its status.
//!
//! SetPgid: pid u32 (0 for the caller) and pgid u32 (0 for the target's
//! PID); reply its status: NO_PROCESS, PERMISSION, ACCESS. SetSid: no
//! body; reply status u32 and the new session's number u32 (the PID);
//! PERMISSION for a leader of a group. GetPgid and GetSid: pid u32 (0 for
//! the caller); reply status u32 and the number u32; NO_PROCESS. The page
//! carries the caller's own group and session, which it reads without a
//! call.
//!
//! The page of the record (`Page`) lies at PAGE_ADDRESS of the process,
//! the service's to write but for the fields the process writes.
//!
//! Spawn, through a session: body `Spawn`; the reply, once the child was
//! loaded and init took it (Loaded), is status u32 and the child's PID
//! u32, or the status of why not. One Spawn of a record waits at a time
//! and CHILDREN_MAX children live (AGAIN past either).
//!
//! Through a session: Query has no body or handles. Snapshot reply:
//! status u32, pid u32, parent u32, uid/euid/suid/gid/egid/sgid u32.
//! Change: operation u32, id u32; reply status alone. The kernel answers
//! an accepted request once (spec 6.1): a client sends a Change again only
//! when its send came back INTERRUPTED, which the service never saw, so a
//! Change takes effect once with no journal.
#![cfg_attr(not(test), no_std)]
use abi::ProcessState;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64};
use proto_wire::{Header, Name, Reader, Status, Writer};
pub const VERSION: u16 = 4;
pub const INVALID: u32 = 500;
pub const PERMISSION: u32 = 501;
pub const FULL: u32 = 502;
pub const UNREGISTERED: u32 = 503;
/// ESRCH: no process of that number.
pub const NO_PROCESS: u32 = 504;
/// ECHILD: no child to wait for.
pub const NO_CHILD: u32 = 505;
/// EAGAIN: a limit of the moment.
pub const AGAIN: u32 = 506;
/// EACCES.
pub const ACCESS: u32 = 507;
/// ENOENT: no program of that name.
pub const NOT_FOUND: u32 = 508;

/// The flags of Spawn: those of posix_spawnattr_setflags (Linux values).
pub const SPAWN_SETPGROUP: u32 = 0x02;
pub const SPAWN_SETSID: u32 = 0x80;

/// Records of the service at most: PID = index + RECORDS * generation.
pub const RECORDS: usize = 256;
/// Generations of a record run from 1 to this and wrap to 1, so that a
/// PID stays a positive i32.
pub const GENERATION_MAX: u32 = (1 << 23) - 1;
/// The parent PID of a record that init created, and of an orphan: the
/// service itself, the system process that adopts them.
pub const INIT_PID: u32 = 1;
/// The image number of a label until exec comes (5c).
pub const IMAGE: u32 = 1;

/// Which of the record's three places of the service's channel a label
/// names: its session, its identity session (bit 62, 5b T6), the place of
/// the notification of its end (bit 61).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    Work,
    Identity,
    Exit,
}

/// The label of a place the service gave (spec 2, section 3.1): bit 63
/// set, which no label of init has; bit 62 the identity session, bit 61
/// the exit place, never both; the image number in bits 40-60 (IMAGE); the
/// generation of the record in bits 16-39; its index in bits 0-15.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Label {
    pub index: u16,
    pub generation: u32,
}

impl Label {
    const SERVICE: u64 = 1 << 63;
    const IDENTITY: u64 = 1 << 62;
    const EXIT: u64 = 1 << 61;
    const IMAGE_SHIFT: u32 = 40;
    const IMAGE_MASK: u64 = (1 << 21) - 1;

    /// The label of the record's session.
    pub const fn raw(self) -> u64 {
        Self::SERVICE
            | (IMAGE as u64) << Self::IMAGE_SHIFT
            | (self.generation as u64) << 16
            | self.index as u64
    }

    /// The label of the record's exit place.
    pub const fn exit(self) -> u64 {
        self.raw() | Self::EXIT
    }

    /// The label of the record's identity session.
    pub const fn identity(self) -> u64 {
        self.raw() | Self::IDENTITY
    }

    /// The record and the place `raw` names, when it is a label the
    /// service gives: bit 63, not both of bits 62 and 61, the image IMAGE,
    /// an index below RECORDS and a generation of 1 to GENERATION_MAX.
    pub const fn parse(raw: u64) -> Option<(Self, Place)> {
        let index = (raw & 0xFFFF) as u16;
        let generation = ((raw >> 16) & 0xFF_FFFF) as u32;
        let image = (raw >> Self::IMAGE_SHIFT) & Self::IMAGE_MASK;
        let place = match (raw & Self::IDENTITY != 0, raw & Self::EXIT != 0) {
            (false, false) => Place::Work,
            (true, false) => Place::Identity,
            (false, true) => Place::Exit,
            (true, true) => return None,
        };
        if raw & Self::SERVICE == 0
            || image != IMAGE as u64
            || index as usize >= RECORDS
            || generation == 0
            || generation > GENERATION_MAX
        {
            return None;
        }
        Some((Self { index, generation }, place))
    }

    /// The record whose session has the label `raw`.
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match Self::parse(raw) {
            Some((label, Place::Work)) => Some(label),
            _ => None,
        }
    }

    /// The PID of the record: index + RECORDS * generation.
    pub const fn pid(self) -> u32 {
        self.index as u32 + RECORDS as u32 * self.generation
    }

    /// The generation after `generation`, from 1 to GENERATION_MAX.
    pub const fn next_generation(generation: u32) -> u32 {
        if generation >= GENERATION_MAX {
            1
        } else {
            generation + 1
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Credentials {
    pub uid: u32,
    pub euid: u32,
    pub suid: u32,
    pub gid: u32,
    pub egid: u32,
    pub sgid: u32,
}
impl Credentials {
    pub const ROOT: Self = Self {
        uid: 0,
        euid: 0,
        suid: 0,
        gid: 0,
        egid: 0,
        sgid: 0,
    };
    /// The credentials of a process init creates without root.
    pub const NOBODY: Self = Self {
        uid: 65534,
        euid: 65534,
        suid: 65534,
        gid: 65534,
        egid: 65534,
        sgid: 65534,
    };
    pub const fn words(self) -> [u32; 6] {
        [
            self.uid, self.euid, self.suid, self.gid, self.egid, self.sgid,
        ]
    }
    pub const fn from_words(w: [u32; 6]) -> Self {
        Self {
            uid: w[0],
            euid: w[1],
            suid: w[2],
            gid: w[3],
            egid: w[4],
            sgid: w[5],
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Method {
    Create = 1,
    Query = 2,
    Change = 3,
    Loaded = 6,
    Abandon = 7,
    Spawn = 8,
    Next = 9,
    WaitStart = 10,
    WaitTake = 11,
    WaitCancel = 12,
    Kill = 13,
    Router = 14,
    SetPgid = 15,
    SetSid = 16,
    GetPgid = 17,
    GetSid = 18,
}
impl Method {
    pub const fn header(self) -> Header {
        Header {
            version: VERSION,
            method: self as u16,
        }
    }
}
pub const METHODS: &[u16] = &[1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Change {
    Uid = 1,
    EffectiveUid = 2,
    Gid = 3,
    EffectiveGid = 4,
}
impl Change {
    pub const fn from_number(n: u32) -> Option<Self> {
        match n {
            1 => Some(Self::Uid),
            2 => Some(Self::EffectiveUid),
            3 => Some(Self::Gid),
            4 => Some(Self::EffectiveGid),
            _ => None,
        }
    }
}

/// The body of Create: the process as init's table has it (proto_init
/// ADOPT), its quota in bytes, room for handles, ceiling and the priority
/// of its first thread, root credentials when `root`, and the label of the
/// parent whose Spawn asked for it, 0 for a record init's table starts.
///
/// | Bytes | Field |
/// |---|---|
/// | 0..8 | quota |
/// | 8..12 | handle limit |
/// | 12 | ceiling |
/// | 13 | priority |
/// | 14 | root: 0 or 1 |
/// | 15 | zero |
/// | 16..24 | parent |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Create {
    pub quota: u64,
    pub handle_limit: u32,
    pub ceiling: u8,
    pub priority: u8,
    pub root: bool,
    pub parent: u64,
}

impl Create {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u64(self.quota)?;
        w.u32(self.handle_limit)?;
        w.bytes(&[self.ceiling, self.priority, u8::from(self.root), 0])?;
        w.u64(self.parent)
    }

    /// BAD_SIZE out of the layout; a ceiling or priority past 63, a
    /// priority above the ceiling or a root byte past 1 too.
    pub fn read(mut r: Reader<'_>) -> Result<Self, Status> {
        let quota = r.u64()?;
        let handle_limit = r.u32()?;
        let b = r.bytes(4)?;
        let parent = r.u64()?;
        r.finish()?;
        let (ceiling, priority) = (b[0], b[1]);
        if ceiling > 63 || priority == 0 || priority > ceiling || b[2] > 1 || b[3] != 0 {
            return Err(Status::BadSize);
        }
        Ok(Self {
            quota,
            handle_limit,
            ceiling,
            priority,
            root: b[2] == 1,
            parent,
        })
    }
}

/// The options of WaitStart, with Linux's values: WNOHANG, WSTOPPED (or
/// WUNTRACED), WEXITED, WCONTINUED and WNOWAIT. Waitpid sends WEXITED.
pub const WNOHANG: u32 = 1;
pub const WSTOPPED: u32 = 2;
pub const WEXITED: u32 = 4;
pub const WCONTINUED: u32 = 8;
pub const WNOWAIT: u32 = 0x0100_0000;
pub const WAIT_OPTIONS: u32 = WNOHANG | WSTOPPED | WEXITED | WCONTINUED | WNOWAIT;

/// The children a wait takes: the child of a PID, any child, or the
/// children of a process group (waitpid's pid > 0, -1, < -1; 0 is the
/// caller's own group).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selector {
    Pid(u32),
    Any,
    Group(u32),
}

impl Selector {
    /// The selector of waitpid's `pid`, with the caller's group `own`.
    pub const fn of(pid: i32, own: u32) -> Self {
        match pid {
            -1 => Selector::Any,
            0 => Selector::Group(own),
            p if p > 0 => Selector::Pid(p as u32),
            p => Selector::Group(p.unsigned_abs()),
        }
    }
}

/// The body of WaitStart: waitpid's pid (the caller's group already put
/// for 0) and the options.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitStart {
    pub selector: Selector,
    pub options: u32,
}

impl WaitStart {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        let (kind, id) = match self.selector {
            Selector::Pid(pid) => (1, pid),
            Selector::Any => (0, 0),
            Selector::Group(pgid) => (2, pgid),
        };
        w.u32(kind)?;
        w.u32(id)?;
        w.u32(self.options)
    }

    /// BAD_SIZE out of the layout, for an unknown kind, an id of 0 or an
    /// option past WAIT_OPTIONS.
    pub fn read(mut r: Reader<'_>) -> Result<Self, Status> {
        let (kind, id, options) = (r.u32()?, r.u32()?, r.u32()?);
        r.finish()?;
        let selector = match (kind, id) {
            (0, 0) => Selector::Any,
            (1, pid) if pid != 0 => Selector::Pid(pid),
            (2, pgid) if pgid != 0 => Selector::Group(pgid),
            _ => return Err(Status::BadSize),
        };
        if options & !WAIT_OPTIONS != 0 {
            return Err(Status::BadSize);
        }
        Ok(Self { selector, options })
    }
}

/// What a wait found: a child that exited or died by a signal, none yet
/// (WNOHANG), or no child of the selector at all (ECHILD).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitResult {
    Ended { pid: u32, end: End, uid: u32 },
    Nothing,
    NoChild,
}

impl WaitResult {
    /// pid u32, kind u32 (1 exited, 2 signaled, 0 nothing, 3 no child),
    /// value u32 (the code or the signal), uid u32: 16 bytes.
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        let (pid, kind, value, uid) = match *self {
            WaitResult::Ended {
                pid,
                end: End::Exited(code),
                uid,
            } => (pid, 1, code, uid),
            WaitResult::Ended {
                pid,
                end: End::Signaled(n),
                uid,
            } => (pid, 2, n, uid),
            WaitResult::Nothing => (0, 0, 0, 0),
            WaitResult::NoChild => (0, 3, 0, 0),
        };
        w.u32(pid)?;
        w.u32(kind)?;
        w.u32(value.into())?;
        w.u32(uid)
    }

    pub fn read(bytes: &[u8]) -> Result<Self, Status> {
        let mut r = Reader::new(bytes);
        let (pid, kind, value, uid) = (r.u32()?, r.u32()?, r.u32()?, r.u32()?);
        r.finish()?;
        let value = u8::try_from(value).map_err(|_| Status::BadSize)?;
        match (kind, pid) {
            (1, p) if p != 0 => Ok(WaitResult::Ended {
                pid,
                end: End::Exited(value),
                uid,
            }),
            (2, p) if p != 0 => Ok(WaitResult::Ended {
                pid,
                end: End::Signaled(value),
                uid,
            }),
            (0, 0) => Ok(WaitResult::Nothing),
            (3, 0) => Ok(WaitResult::NoChild),
            _ => Err(Status::BadSize),
        }
    }
}

/// Where the page of its record lies in a POSIX process.
pub const PAGE_ADDRESS: usize = 0x0D00_0000;
/// The version of the page's layout.
pub const PAGE_VERSION: u32 = 1;

/// The page of a record (spec 2, 3.1, 3.3), one page in the process at
/// PAGE_ADDRESS and in the service. The service writes the identity and
/// the signals that wait for the process with their information; the
/// process writes which signals it ignores and catches, and the flags of
/// SIGCHLD, which the service reads as hints and checks.
#[repr(C)]
pub struct Page {
    pub version: AtomicU32,
    pub pid: AtomicU32,
    pub ppid: AtomicU32,
    pub pgid: AtomicU32,
    pub sid: AtomicU32,
    _zero: u32,
    /// The signals sent to the process that no thread took yet, bit n - 1
    /// for signal n.
    pub pending: AtomicU64,
    /// The process's: the signals whose action ignores them, those it
    /// catches, and PAGE_NOCLDWAIT, PAGE_NOCLDSTOP, PAGE_CHLD_IGNORED.
    pub ignored: AtomicU64,
    pub caught: AtomicU64,
    pub flags: AtomicU64,
    _reserved: [u64; 3],
    /// The information of the first sending of each pending signal.
    pub info: [PageInfo; 64],
}

/// SA_NOCLDWAIT on SIGCHLD.
pub const PAGE_NOCLDWAIT: u64 = 1;
/// SA_NOCLDSTOP on SIGCHLD.
pub const PAGE_NOCLDSTOP: u64 = 2;
/// SIGCHLD set to SIG_IGN, which reaps children at once.
pub const PAGE_CHLD_IGNORED: u64 = 4;

/// The information of a signal sent to a process (siginfo_t): its code,
/// the sender's PID and real UID, and for SIGCHLD the child's status.
#[repr(C)]
pub struct PageInfo {
    pub code: AtomicI32,
    pub pid: AtomicU32,
    pub uid: AtomicU32,
    pub status: AtomicI32,
}

const _: () = assert!(core::mem::size_of::<Page>() <= 4096);

/// si_code of a signal kill sent, and of SIGCHLD.
pub const SI_USER: i32 = 0;
pub const CLD_EXITED: i32 = 1;
pub const CLD_KILLED: i32 = 2;

/// The body of Spawn: the name of the record of init's table, 16 bytes,
/// the spawn-flags u32, the process group u32 and the caller's level u32,
/// which the copy of the child's program runs at least at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Spawn {
    pub name: Name,
    pub flags: u32,
    pub pgroup: u32,
    pub level: u8,
}

impl Spawn {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.name(Some(self.name))?;
        w.u32(self.flags)?;
        w.u32(self.pgroup)?;
        w.u32(self.level.into())
    }

    /// BAD_SIZE out of the layout, without a name or with a level past 63.
    pub fn read(mut r: Reader<'_>) -> Result<Self, Status> {
        let name = r.name()?.ok_or(Status::BadSize)?;
        let (flags, pgroup, level) = (r.u32()?, r.u32()?, r.u32()?);
        r.finish()?;
        let level = u8::try_from(level)
            .ok()
            .filter(|&l| l <= 63)
            .ok_or(Status::BadSize)?;
        Ok(Self {
            name,
            flags,
            pgroup,
            level,
        })
    }
}

/// The reply to Next that is no refusal: the spawn the spawning thread
/// makes next, and the level of the parent's Spawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Next {
    pub parent: u64,
    pub name: Name,
    pub level: u8,
}

impl Next {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(0)?;
        w.u32(0)?;
        w.u64(self.parent)?;
        w.name(Some(self.name))?;
        w.u32(self.level.into())
    }

    /// BAD_SIZE unless `bytes` hold status 0 and the fields.
    pub fn read(bytes: &[u8]) -> Result<Self, Status> {
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 || r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let parent = r.u64()?;
        let name = r.name()?.ok_or(Status::BadSize)?;
        let level = u8::try_from(r.u32()?).map_err(|_| Status::BadSize)?;
        r.finish()?;
        Ok(Self {
            parent,
            name,
            level,
        })
    }
}

/// How a process ended, as wait reports it (spec 2, section 3.1): the
/// kernel's reason read with PROCESS_STATE. The layer's `_exit(s)` exits
/// with `s & 0xFF`, its death by signal `n` with `0x100 | n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// WIFEXITED, the low 8 bits of the status.
    Exited(u8),
    /// WIFSIGNALED with the signal's number.
    Signaled(u8),
}

pub const SIGHUP: u8 = 1;
pub const SIGILL: u8 = 4;
pub const SIGTRAP: u8 = 5;
pub const SIGBUS: u8 = 7;
pub const SIGFPE: u8 = 8;
pub const SIGKILL: u8 = 9;
pub const SIGUSR1: u8 = 10;
pub const SIGSEGV: u8 = 11;
pub const SIGTERM: u8 = 15;
pub const SIGCHLD: u8 = 17;
pub const SIGCONT: u8 = 18;
pub const SIGSTOP: u8 = 19;
pub const SIGTSTP: u8 = 20;
pub const SIGTTIN: u8 = 21;
pub const SIGTTOU: u8 = 22;
/// The highest signal number (Linux AArch64, relibc's NSIG - 1).
pub const SIGNAL_MAX: u8 = 64;

impl End {
    /// The end that `state` reports; None for a process alive. A kill is
    /// SIGKILL; a fault the signal of its class of exception (ESR EC):
    /// SIGSEGV for an abort of an instruction or data (EC 0x20, 0x21, 0x24,
    /// 0x25) but an alignment fault, SIGBUS for that and a misaligned PC
    /// or SP (EC 0x22, 0x26), SIGFPE for a floating-point trap (EC 0x2C),
    /// SIGTRAP for BRK (EC 0x3C), SIGILL for the others (EC 0x00, 0x0E).
    /// A state this abi does not know counts as a kill.
    pub const fn of(state: ProcessState) -> Option<End> {
        match state {
            ProcessState::Alive => None,
            ProcessState::Exited { code } => Some(Self::exited(code)),
            ProcessState::Killed | ProcessState::Unknown(_) => Some(End::Signaled(SIGKILL)),
            ProcessState::Fault { esr, .. } => Some(End::Signaled(fault_signal(esr))),
        }
    }

    /// The end of a process_exit with `code`.
    pub const fn exited(code: u64) -> End {
        let n = (code & 0xFF) as u8;
        if code >> 8 == 1 && n >= 1 && n <= SIGNAL_MAX {
            End::Signaled(n)
        } else {
            End::Exited(n)
        }
    }

    /// The status wait stores (Linux's layout): the code in bits 8-15 for
    /// an exit, the signal in bits 0-6 for a death by signal.
    pub const fn wait_status(self) -> i32 {
        match self {
            End::Exited(code) => (code as i32) << 8,
            End::Signaled(n) => n as i32,
        }
    }
}

/// The signal of a fault whose ESR is `esr` (End::of).
pub const fn fault_signal(esr: u64) -> u8 {
    const ALIGNMENT: u64 = 0b10_0001;
    let class = (esr >> 26) & 0x3F;
    let status = esr & 0x3F;
    match class {
        0x20 | 0x21 | 0x24 | 0x25 if status == ALIGNMENT => SIGBUS,
        0x20 | 0x21 | 0x24 | 0x25 => SIGSEGV,
        0x22 | 0x26 => SIGBUS,
        0x2C => SIGFPE,
        0x3C => SIGTRAP,
        _ => SIGILL,
    }
}

/// The name of signal `n` of Linux AArch64, as init prints an end.
pub const fn signal_name(n: u8) -> &'static str {
    const NAMES: [&str; 32] = [
        "SIG0",
        "SIGHUP",
        "SIGINT",
        "SIGQUIT",
        "SIGILL",
        "SIGTRAP",
        "SIGABRT",
        "SIGBUS",
        "SIGFPE",
        "SIGKILL",
        "SIGUSR1",
        "SIGSEGV",
        "SIGUSR2",
        "SIGPIPE",
        "SIGALRM",
        "SIGTERM",
        "SIGSTKFLT",
        "SIGCHLD",
        "SIGCONT",
        "SIGSTOP",
        "SIGTSTP",
        "SIGTTIN",
        "SIGTTOU",
        "SIGURG",
        "SIGXCPU",
        "SIGXFSZ",
        "SIGVTALRM",
        "SIGPROF",
        "SIGWINCH",
        "SIGIO",
        "SIGPWR",
        "SIGSYS",
    ];
    if (n as usize) < NAMES.len() {
        NAMES[n as usize]
    } else {
        "SIGRT"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protocol_fields_and_numbers_are_stable() {
        let value = Credentials::from_words([1, 2, 3, 4, 5, 6]);
        assert_eq!(value.words(), [1, 2, 3, 4, 5, 6]);
        assert_eq!(Credentials::ROOT.words(), [0; 6]);
        let methods = [
            Method::Create,
            Method::Query,
            Method::Change,
            Method::Loaded,
            Method::Abandon,
            Method::Spawn,
            Method::Next,
            Method::WaitStart,
            Method::WaitTake,
            Method::WaitCancel,
            Method::Kill,
            Method::Router,
            Method::SetPgid,
            Method::SetSid,
            Method::GetPgid,
            Method::GetSid,
        ];
        assert_eq!(methods.len(), METHODS.len());
        for (i, m) in methods.iter().enumerate() {
            assert_eq!(*m as u16, METHODS[i]);
            assert_eq!(m.header().version, 4);
        }
        for i in 1..=4 {
            assert_eq!(Change::from_number(i).unwrap() as u32, i);
        }
        assert_eq!(Change::from_number(0), None);
        assert_eq!(Change::from_number(5), None);
        assert_eq!(Credentials::NOBODY.words(), [65534; 6]);
    }

    #[test]
    fn labels_are_the_services_own_and_name_one_place() {
        let label = Label {
            index: 5,
            generation: 3,
        };
        assert_eq!(label.raw(), 1 << 63 | 1 << 40 | 3 << 16 | 5);
        assert_eq!(Label::from_raw(label.raw()), Some(label));
        assert_eq!(Label::parse(label.exit()), Some((label, Place::Exit)));
        assert_eq!(
            Label::parse(label.identity()),
            Some((label, Place::Identity))
        );
        assert_eq!(Label::from_raw(label.exit()), None, "no session's label");
        assert_eq!(label.pid(), 5 + 256 * 3);
        // Labels of init, both place bits, other image numbers, an index
        // past the records and generation 0 name no record.
        for raw in [
            0,
            7,
            3 << 16 | 5,
            label.raw() | 1 << 62 | 1 << 61,
            label.raw() & !(1 << 40),
            label.raw() | 1 << 41,
            1 << 63 | 1 << 40 | 3 << 16 | 256,
            1 << 63 | 1 << 40 | 5,
            1 << 63 | 1 << 40 | u64::from(GENERATION_MAX + 1) << 16,
        ] {
            assert_eq!(Label::parse(raw), None, "{raw:#x}");
        }
        let last = Label {
            index: 255,
            generation: GENERATION_MAX,
        };
        assert_eq!(Label::from_raw(last.raw()), Some(last));
        assert!(i32::try_from(last.pid()).is_ok());
        assert_eq!(Label::next_generation(GENERATION_MAX), 1);
        assert_eq!(Label::next_generation(1), 2);
    }

    #[test]
    fn create_round_trips_and_refuses_bad_levels() {
        let create = Create {
            quota: 512 * 4096,
            handle_limit: 32,
            ceiling: 31,
            priority: 30,
            root: true,
            parent: Label {
                index: 2,
                generation: 1,
            }
            .raw(),
        };
        let mut w = Writer::new();
        create.write(&mut w).unwrap();
        assert_eq!(w.as_bytes().len(), 24);
        assert_eq!(Create::read(Reader::new(w.as_bytes())), Ok(create));
        for (ceiling, priority, root) in [(64, 30, 0), (31, 32, 0), (31, 0, 0), (31, 30, 2)] {
            let mut w = Writer::new();
            w.u64(4096).unwrap();
            w.u32(16).unwrap();
            w.bytes(&[ceiling, priority, root, 0]).unwrap();
            w.u64(0).unwrap();
            assert_eq!(
                Create::read(Reader::new(w.as_bytes())),
                Err(Status::BadSize),
                "{ceiling} {priority} {root}"
            );
        }
    }

    #[test]
    fn spawn_and_next_round_trip() {
        let name = Name::new(b"procs-child").unwrap();
        let spawn = Spawn {
            name,
            flags: SPAWN_SETPGROUP,
            pgroup: 0,
            level: 30,
        };
        let mut w = Writer::new();
        spawn.write(&mut w).unwrap();
        assert_eq!(w.as_bytes().len(), 28);
        assert_eq!(Spawn::read(Reader::new(w.as_bytes())), Ok(spawn));
        assert_eq!(
            Spawn::read(Reader::new(&w.as_bytes()[..27])),
            Err(Status::BadSize)
        );
        assert_eq!(
            Spawn::read(Reader::new(&[0; 28])),
            Err(Status::BadSize),
            "no name"
        );
        let mut high = w.as_bytes().to_vec();
        high[24] = 64;
        assert_eq!(
            Spawn::read(Reader::new(&high)),
            Err(Status::BadSize),
            "level 64"
        );
        let next = Next {
            parent: 7,
            name,
            level: 30,
        };
        let mut w = Writer::new();
        next.write(&mut w).unwrap();
        assert_eq!(w.as_bytes().len(), 36);
        assert_eq!(Next::read(w.as_bytes()), Ok(next));
        assert_eq!(
            Next::read(&proto_wire::reply(Status::BadSize)),
            Err(Status::BadSize)
        );
    }

    #[test]
    fn waits_round_trip() {
        assert_eq!(Selector::of(-1, 300), Selector::Any);
        assert_eq!(Selector::of(0, 300), Selector::Group(300));
        assert_eq!(Selector::of(257, 300), Selector::Pid(257));
        assert_eq!(Selector::of(-260, 300), Selector::Group(260));
        for selector in [Selector::Any, Selector::Pid(9), Selector::Group(4)] {
            let start = WaitStart {
                selector,
                options: WNOHANG | WEXITED | WNOWAIT,
            };
            let mut w = Writer::new();
            start.write(&mut w).unwrap();
            assert_eq!(WaitStart::read(Reader::new(w.as_bytes())), Ok(start));
        }
        let mut w = Writer::new();
        w.u32(1).unwrap();
        w.u32(0).unwrap();
        w.u32(0).unwrap();
        assert_eq!(
            WaitStart::read(Reader::new(w.as_bytes())),
            Err(Status::BadSize),
            "pid 0"
        );
        for result in [
            WaitResult::Ended {
                pid: 300,
                end: End::Exited(7),
                uid: 0,
            },
            WaitResult::Ended {
                pid: 301,
                end: End::Signaled(SIGSEGV),
                uid: 65534,
            },
            WaitResult::Nothing,
            WaitResult::NoChild,
        ] {
            let mut w = Writer::new();
            result.write(&mut w).unwrap();
            assert_eq!(w.as_bytes().len(), 16);
            assert_eq!(WaitResult::read(w.as_bytes()), Ok(result));
        }
    }

    /// The reasons of PROCESS_STATE as wait reports them (decision 4 of
    /// the design of 5b).
    #[test]
    fn the_end_comes_from_the_kernels_reason() {
        let exited = |code| End::of(ProcessState::Exited { code });
        assert_eq!(exited(7), Some(End::Exited(7)));
        assert_eq!(exited(0), Some(End::Exited(0)));
        assert_eq!(exited(0x106), Some(End::Signaled(6)));
        assert_eq!(exited(0x100 | 15), Some(End::Signaled(15)));
        // Out of the layer's two forms: the low 8 bits, an exit.
        assert_eq!(exited(0x100), Some(End::Exited(0)));
        assert_eq!(exited(0x100 | 65), Some(End::Exited(65)));
        assert_eq!(exited(0x206), Some(End::Exited(6)));
        assert_eq!(End::of(ProcessState::Killed), Some(End::Signaled(SIGKILL)));
        assert_eq!(End::of(ProcessState::Alive), None);
        let fault = |esr| {
            End::of(ProcessState::Fault {
                esr,
                far: 0,
                elr: 0,
            })
        };
        // A data abort from EL0, translation fault level 2: SIGSEGV.
        assert_eq!(fault(0x9200_0046), Some(End::Signaled(SIGSEGV)));
        assert_eq!(fault(0x8200_0006), Some(End::Signaled(SIGSEGV)));
        // An alignment fault, a misaligned PC and SP: SIGBUS.
        assert_eq!(fault(0x9200_0061), Some(End::Signaled(SIGBUS)));
        assert_eq!(fault(0x8a00_0000), Some(End::Signaled(SIGBUS)));
        assert_eq!(fault(0x9a00_0000), Some(End::Signaled(SIGBUS)));
        // An unknown instruction and an illegal execution state: SIGILL.
        assert_eq!(fault(0x0200_0000), Some(End::Signaled(SIGILL)));
        assert_eq!(fault(0x3a00_0000), Some(End::Signaled(SIGILL)));
        assert_eq!(End::Exited(7).wait_status(), 7 << 8);
        assert_eq!(End::Signaled(SIGSEGV).wait_status(), 11);
        assert_eq!(signal_name(6), "SIGABRT");
        assert_eq!(signal_name(15), "SIGTERM");
        assert_eq!(signal_name(40), "SIGRT");
    }
}
