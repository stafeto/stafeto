// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Process protocol v10 (spec 2, section 3.1). The service creates every
//! POSIX process itself, so that a record comes with its process and goes
//! only with the notification of its end. The label of a session names
//! the caller's record (`Label`), never the body.
//!
//! Through the service's channel with no label, which only the service's
//! own threads and init hold: Create, body `Create` (`Create::write`) and
//! two handles, the start channel init gave (B) and the witness, which the
//! service closes once the process ended (proto_init ADOPT); the service makes the
//! record, its exit place and the process, and replies status u32, pid
//! u32, label u64 with three handles: the process (MANAGE, DUPLICATE,
//! TRANSFER) for the load, the record's session, and its identity session
//! (SEND, TRANSFER, DUPLICATE). Loaded, body label
//! u64 and one handle, the first thread (MANAGE), the router of the
//! process's signals: the process was loaded and runs; reply its status.
//! Abandon, body label u64 (0 for no record): the process, if any, is
//! killed, and the record goes with its end; reply its status.
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
//! The identity session of a record (label bit 62, `Label::identity`) is
//! a copy of a channel of the service that no loop serves, with NOTIFY,
//! TRANSFER and DUPLICATE: the service gives it with Create, init
//! puts it in the process's start data under `posix-id`, and the process
//! gives a copy to a service it asks something of, such as the clock. It
//! carries no request: it proves who brought it. Through a notary session
//! (a label with NOTARY and no bit 63, which only init gives, on CONNECT,
//! to the services of its table's VOUCHERS): Vouch, no body and one
//! handle, a copy a client gave; the kernel tells the service the copy's
//! label (object_info LABEL, which answers the owner of the channel alone,
//! O(1)), so a channel of anyone else proves nothing (PERMISSION); the reply
//! (`WhoReply`) is that record's PID, its six credentials and the
//! generation of its credentials. Register, no body; the reply is a copy
//! of the page of the credentials generations with MAP_READ and TRANSFER
//! (`GENERATIONS_SIZE` bytes, a u64 per record index, which the service
//! raises with Release before it answers a Change and when it makes a
//! record): the voucher remembers an answer with the generation and asks
//! again only when the page's word of the record moved. Nothing else is
//! asked through a notary session, and a record's session asks neither.
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
//! SpawnStart, through a session (spec 2, 3.2; 5c): body `SpawnStart`.
//! The service makes the child's record (LOADING), its process with the
//! loader mapped in the loader's region (proto_loader) and the loader's
//! session in entry 0, and starts the loader at the caller's level; the
//! reply waits for the loader's Boot: status u32, the child's PID u32 and
//! one handle, the parent's copy of the loader's start channel C. AGAIN
//! while a spawn of the record waits, past CHILDREN_MAX children or the
//! 16 places of loaders; INVALID for a flag past SPAWN_FLAGS; PERMISSION
//! for a group setpgid would refuse; NOT_FOUND without a loader in the
//! boot image or a session of the loaders. SpawnCommit, body the child's
//! PID u32: the LOADING child of the caller is alive, with the set-ID of
//! its place (SetId) applied and its credentials' generation raised
//! before the reply, and the loader is told through C that the record is
//! ready; reply its status. SpawnAbort, body the child's PID u32: the
//! LOADING child is killed and the SetId of its place wiped; reply its
//! status. NO_PROCESS for a PID of no LOADING child of the caller.
//!
//! ExecStart, through a session (spec 2, 3.2; 5c): body `SpawnStart` with
//! no flags and no group. The service makes a new process for the record,
//! image number one past its own (AGAIN past IMAGE_MAX), with the loader
//! and the record's page, as SpawnStart; the reply waits for Boot: status
//! u32, the record's PID u32 and the copy of C. One exec of a record at a
//! time. ExecCommit, no body, once the loader said "the image is ready":
//! the record moves to the new process in one step (its image number +1,
//! the set-ID of the loader's place, the generation of its credentials
//! raised, its caught signals the default on the page), the loads of
//! children the record started and not committed stop, the service kills
//! the old process and the loader hears that the record is ready. For a
//! record of init's table the loader hears it, and the old process is
//! killed, only once init took the new process for its end line (Replace,
//! below). ExecAbort, no body: the new process is killed and the place
//! goes. The end of the old process before ExecCommit, by itself or by
//! SIGKILL, kills the new one and its quota comes back to the service;
//! the end of the old one after ExecCommit carries the old image number
//! and ends nothing. The identity session carries the image number too:
//! a copy of an old image's identity vouches for nothing.
//!
//! ForkStart, through a session (spec 2, 3.2; 5d): body `ForkStart`. As
//! SpawnStart with no flags and no group: the child's record (LOADING) in
//! the caller's group and session with the caller's six credentials, its
//! process with the caller's quota from the service's pool, the loader at
//! the caller's level; before the record is a target of any signal, its
//! page takes the classes of the caller's actions the body names, so a
//! signal sent to the group while the copy goes on finds what the child
//! will ignore and catch. The reply waits for Boot: status u32, the
//! child's PID u32 and the parent's copy of C, whose loader copies the
//! caller's memory (proto_loader Fork). ForkCommit and ForkAbort, body the
//! child's PID u32: as SpawnCommit and SpawnAbort, for a child of
//! ForkStart alone (NO_PROCESS for any other); SpawnCommit and SpawnAbort
//! take no child of ForkStart.
//!
//! Pool, through a session, no body: status u32 and the bytes u64 of the
//! service's quota left for the children past its reserve, what a probe
//! reads to see that ended loads gave their quota back.
//!
//! Replace, through the channel with no label, from the service's own
//! thread that tells init of an exec (replace.rs): body the session label
//! u64, at its new image, of the record whose exec init heard of (0 for
//! none yet); the reply waits for an ExecCommit of a record of init's
//! table: status u32, zero u32, that label u64, the ticket init gave the
//! record u64, and one handle, the new process (DUPLICATE, TRANSFER). The
//! thread gives init the process (proto_init REPLACED) and names the label
//! in its next Replace, on which the loader and the old image hear the
//! exec is done.
//!
//! Through the session of a loader (label `Label::loader` on the
//! service's channel, entry 0 of its process): Ready, no body, once the
//! image is loaded and before the loader answers Go: the place may be
//! committed from then on, and SpawnCommit or ExecCommit before it is
//! BAD_STATE, so a parent that commits a load it never let finish holds
//! no place. Boot, no body and two
//! handles, the copies of C for the parent (SEND) and for the service
//! (NOTIFY); reply status u32, the address and the length u64 of the
//! loader's data and stack, which it unmaps at its end, and four handles:
//! the process and the
//! loader's thread (MANAGE, DUPLICATE, TRANSFER), the session of the
//! loaders with the RAM file service (SEND) and the loader's identity
//! (NOTIFY, DUPLICATE, TRANSFER, label `Label::loader` on the identity
//! channel). Take, no body, once the record is ready: reply status u32,
//! the six credentials u32 and the program's session, its identity
//! session and a console (DEBUG) when the service has one; the place of
//! the loader goes with it. BAD_STATE out of that order.
//!
//! SetId, through a notary session whose label has SET_ID (init gives it
//! to the file services of its table): body `SetId`; the place of the
//! loader the ticket names, while it loads (from Boot until Ready) and
//! has no SetId yet, keeps the IDs; PERMISSION otherwise. Vouch of a
//! loader's identity, of the image its place loads, answers with the
//! image and the ticket of its place (`LoaderOf`) only while it loads.
//!
//! TtySignal, SetCtty and DropCtty, through a notary session whose label
//! has TERMINAL (init gives it to the terminal service of its table; 5f):
//! the service keeps which session each terminal is the controlling
//! terminal of. SetCtty: body the terminal u32 and the session u32: the
//! terminal becomes the controlling terminal of the session, whose leader
//! lives, when the terminal has no session with a live leader and the
//! session has no terminal; PERMISSION for a session with no live leader,
//! ACCESS for a terminal or a session taken. DropCtty: body the terminal
//! u32: it is no session's. The end of a session's leader takes its
//! terminal from the session. TtySignal: body the terminal u32, the group
//! u32 and the signal u32: the signal goes to every member of the group,
//! with no check of permission (XBD 11.1.9), when the group lies in the
//! session of the terminal; PERMISSION when it does not, NO_PROCESS for a
//! group nobody is in, INVALID for a signal the members refuse (the stop
//! signals until stops come); the reply comes once the walk of the group
//! is over, as for Kill.
//!
//! The second half of the page of the generations (from GROUPS_AT) holds a
//! word for each record index: its group in the high half and its session
//! in the low half (`groups_word`), which the service stores with Release
//! when it makes the record, moves it between groups or sessions, and
//! clears when the record is reaped. Vouch's reply names the record index,
//! so a voucher reads the group and session of a client with no call.
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
use proto_wire::{Header, Reader, Status, Writer};
pub const VERSION: u16 = 12;

mod limits;
mod retained;
pub use limits::{AS, CORE, DATA, FSIZE, NOFILE, STACK};
pub use limits::{ExpenditureRoot, Groups, Limit, ResourceLimits, SUPPLEMENTARY_MAX};
pub use retained::{RetainedLoader, RetainedLoaderReply, RetainedLoaderState};
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
/// A terminal stop was refused for an orphaned group.
pub const ORPHAN: u32 = 509;

/// The flags of Spawn: those of posix_spawnattr_setflags (Linux values).
pub const SPAWN_SETPGROUP: u32 = 0x02;
pub const SPAWN_SETSID: u32 = 0x80;
pub const SPAWN_RESETIDS: u32 = 0x01;
pub const SPAWN_SETSIGDEF: u32 = 0x04;
pub const SPAWN_SETSIGMASK: u32 = 0x08;
/// The flags SpawnStart takes; the scheduling flags wait for step 5h.
pub const SPAWN_FLAGS: u32 =
    SPAWN_SETPGROUP | SPAWN_SETSID | SPAWN_RESETIDS | SPAWN_SETSIGDEF | SPAWN_SETSIGMASK;

/// Records of the service at most: PID = index + RECORDS * generation.
pub const RECORDS: usize = 256;
/// Generations of a record run from 1 to this. Exhausted indices retire,
/// so a PID stays a positive i32 and an old endpoint never names a new record.
pub const GENERATION_MAX: u32 = (1 << 23) - 1;
/// The parent PID of a record that init created, and of an orphan: the
/// service itself, the system process that adopts them.
pub const INIT_PID: u32 = 1;
/// The image number of a record's first process; each exec gives the next
/// (5c), up to IMAGE_MAX, past which exec is AGAIN: a number never names
/// two images of one record.
pub const IMAGE: u32 = 1;
pub const IMAGE_MAX: u32 = (1 << 21) - 1;

/// Which place of the service a label names: the record's session, its
/// identity session (bit 62), the place of the notification of its end
/// (bit 61), or, with both bits, the session and the identity of the
/// loader of the record's image (5c).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    Work,
    Identity,
    Exit,
    Loader,
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

    /// The label of the record's session of its first image.
    pub const fn raw(self) -> u64 {
        self.raw_at(IMAGE)
    }

    /// The label of the record's session of image `image` (5c: `exec`
    /// gives a record one image after another, IMAGE first).
    pub const fn raw_at(self, image: u32) -> u64 {
        Self::SERVICE
            | (image as u64 & Self::IMAGE_MASK) << Self::IMAGE_SHIFT
            | (self.generation as u64) << 16
            | self.index as u64
    }

    /// The label of the record's exit place of its first image.
    pub const fn exit(self) -> u64 {
        self.exit_at(IMAGE)
    }

    /// The label of the exit place of the process of image `image`.
    pub const fn exit_at(self, image: u32) -> u64 {
        self.raw_at(image) | Self::EXIT
    }

    /// The label of the session and of the identity of the loader of
    /// image `image` of the record.
    pub const fn loader_at(self, image: u32) -> u64 {
        self.raw_at(image) | Self::IDENTITY | Self::EXIT
    }

    /// The label of the identity session of the record's first image.
    pub const fn identity(self) -> u64 {
        self.identity_at(IMAGE)
    }

    /// The label of the identity session of image `image` of the record:
    /// it vouches for the record only while that image is the record's.
    pub const fn identity_at(self, image: u32) -> u64 {
        self.raw_at(image) | Self::IDENTITY
    }

    /// The label of the session and of the identity of the loader of the
    /// record's image: both of bits 62 and 61.
    pub const fn loader(self) -> u64 {
        self.raw() | Self::IDENTITY | Self::EXIT
    }

    /// The record and the place `raw` names, when it is a label the
    /// service gives: bit 63, an image of 1 to IMAGE_MAX, an index below
    /// RECORDS and a generation of 1 to GENERATION_MAX.
    pub const fn parse(raw: u64) -> Option<(Self, Place)> {
        match Self::parse_image(raw) {
            Some((label, place, _)) => Some((label, place)),
            None => None,
        }
    }

    /// `parse` with the image the label names.
    pub const fn parse_image(raw: u64) -> Option<(Self, Place, u32)> {
        let index = (raw & 0xFFFF) as u16;
        let generation = ((raw >> 16) & 0xFF_FFFF) as u32;
        let image = (raw >> Self::IMAGE_SHIFT) & Self::IMAGE_MASK;
        let place = match (raw & Self::IDENTITY != 0, raw & Self::EXIT != 0) {
            (false, false) => Place::Work,
            (true, false) => Place::Identity,
            (false, true) => Place::Exit,
            (true, true) => Place::Loader,
        };
        if raw & Self::SERVICE == 0
            || image == 0
            || index as usize >= RECORDS
            || generation == 0
            || generation > GENERATION_MAX
        {
            return None;
        }
        Some((Self { index, generation }, place, image as u32))
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

    /// The next generation, or exhaustion before another endpoint is issued.
    pub const fn next_generation(generation: u32) -> Option<u32> {
        if generation >= GENERATION_MAX {
            None
        } else {
            Some(generation + 1)
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
    WaitStart = 10,
    WaitTake = 11,
    WaitCancel = 12,
    Kill = 13,
    Router = 14,
    SetPgid = 15,
    SetSid = 16,
    GetPgid = 17,
    GetSid = 18,
    Register = 20,
    Vouch = 21,
    SpawnStart = 22,
    Boot = 23,
    Take = 24,
    SpawnCommit = 25,
    SpawnAbort = 26,
    SetId = 27,
    ExecStart = 28,
    ExecCommit = 29,
    ExecAbort = 30,
    Replace = 31,
    Ready = 32,
    Pool = 33,
    ForkStart = 34,
    ForkCommit = 35,
    ForkAbort = 36,
    TtySignal = 37,
    SetCtty = 38,
    DropCtty = 39,
    TtyEvents = 40,
    AckCtty = 41,
    LoaderTerminal = 43,
    /// Empty body and no handles, through an active loader session before Ready.
    /// Reply: status and the trusted Clock endpoint with SEND|TRANSFER.
    LoaderClock = 45,
    /// Generate a directed job signal and return its epoch ticket.
    SignalGeneration = 48,
    /// Apply a delivered default stop with its epoch ticket.
    StopSelf = 49,
    /// Trusted terminal request: detach one PID, including a leader.
    DetachCtty = 50,
    /// Return a claimed process-origin signal; ordinary numbers require ticket 0.
    ReturnSignal = 51,
    /// Exact terminal/SID/link generation, followed by whether CLOCAL is clear.
    DisconnectCtty = 52,
    /// Read the exact retained authority of a previously vouched loader.
    RetainedLoader = 53,
    InitialMapQuery = 56,
    InitialMapAck = 57,
}
impl Method {
    pub const fn header(self) -> Header {
        Header {
            version: VERSION,
            method: self as u16,
        }
    }
}
pub const METHODS: &[u16] = &[
    1, 2, 3, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 18, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
    31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 43, 45, 48, 49, 50, 51, 52, 53, 56, 57,
];

/// The mark of a notary session's label: bit 62 with bit 63 clear, which
/// no record's label has; only init makes such labels on the service's
/// channel (proto_init CONNECT of a voucher).
pub const NOTARY: u64 = 1 << 62;

/// Whether `label` is that of a notary session.
pub const fn is_notary(label: u64) -> bool {
    label & (1 << 63) == 0 && label & NOTARY != 0
}

/// The mark of the notary session of a service that may say a file is
/// set-ID (SetId): bit 61 with NOTARY, which init gives only to the file
/// services its table names.
pub const SET_ID: u64 = 1 << 61;

/// The mark of the notary session of the terminal service: bit 60 with
/// NOTARY, which init gives only to the terminal services its table names
/// (TtySignal, SetCtty, DropCtty).
pub const TERMINAL: u64 = 1 << 60;

/// Whether `label` is that of the terminal service's notary session.
pub const fn is_terminal(label: u64) -> bool {
    is_notary(label) && label & TERMINAL != 0
}

/// The terminals of the terminal service: the console and 8
/// pseudo-terminals.
pub const TERMINALS: usize = 9;
/// Pending departures per terminal, including the active link's reserve.
pub const CTTY_EVENTS: usize = 8;

/// The offset of the group and session words in the page of the
/// generations.
pub const GROUPS_AT: usize = RECORDS * 8;

/// The word of a record's group `pgid` and session `sid`.
pub const fn groups_word(pgid: u32, sid: u32) -> u64 {
    (pgid as u64) << 32 | sid as u64
}

/// The group and session of a word of the second half of the page; None
/// for a cleared word.
pub const fn groups_of(word: u64) -> Option<(u32, u32)> {
    if word == 0 {
        None
    } else {
        Some(((word >> 32) as u32, word as u32))
    }
}

/// Whether `label` is that of a notary session that may send SetId.
pub const fn may_set_id(label: u64) -> bool {
    is_notary(label) && label & SET_ID != 0
}
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
/// of its first thread, root credentials when `root`, and the ticket init
/// gave the record (proto_init Adoption), which Replace names the record's
/// new process by after an exec; 0 for a process init knows nothing of.
///
/// | Bytes | Field |
/// |---|---|
/// | 0..8 | quota |
/// | 8..12 | handle limit |
/// | 12 | ceiling |
/// | 13 | priority |
/// | 14 | root: 0 or 1 |
/// | 15 | zero |
/// | 16..24 | ticket |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Create {
    pub quota: u64,
    pub handle_limit: u32,
    pub ceiling: u8,
    pub priority: u8,
    pub root: bool,
    pub ticket: u64,
}

impl Create {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u64(self.quota)?;
        w.u32(self.handle_limit)?;
        w.bytes(&[self.ceiling, self.priority, u8::from(self.root), 0])?;
        w.u64(self.ticket)
    }

    /// BAD_SIZE out of the layout; a ceiling or priority past 63, a
    /// priority above the ceiling or a root byte past 1 too.
    pub fn read(mut r: Reader<'_>) -> Result<Self, Status> {
        let quota = r.u64()?;
        let handle_limit = r.u32()?;
        let b = r.bytes(4)?;
        let ticket = r.u64()?;
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
            ticket,
        })
    }
}

/// The bytes of the page of the credentials generations: a u64 for each
/// record index (see Register).
pub const GENERATIONS_SIZE: usize = RECORDS * 8;
/// A retired record has this mark until its index starts a later generation.
pub const GENERATION_DEAD: u64 = 1 << 63;
/// The final generation remains terminal, including after retirement or reuse.
/// Ordinary reuse clears death; invalidation can retain a retired death mark.
pub const fn next_generation(old: u64, retain_dead: bool) -> u64 {
    let generation = old & !GENERATION_DEAD;
    if generation == GENERATION_DEAD - 1 {
        return u64::MAX;
    }
    (generation + 1)
        | if retain_dead {
            old & GENERATION_DEAD
        } else {
            0
        }
}

/// Reserve live generations before a mutation or a multi-stage handoff.
pub const fn generation_room(old: u64, steps: u64) -> bool {
    let used = old & !GENERATION_DEAD;
    steps != 0 && steps <= !GENERATION_DEAD && used <= !GENERATION_DEAD - steps
}

/// The reply to Vouch: status u32 (0), the record's PID u32, the six
/// credentials u32, the generation of the credentials u64, then 1 u32
/// for the identity of a loader (0 for a process's), the image u32 and the
/// ticket of the loader's place u64 (zeros for a process), the record's
/// index u32 and a zero u32, then the terminal u32 and its generation u64
/// (u32::MAX and 0 for no attachment), current image, groups, finite limits and expenditure root: 252 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WhoReply {
    pub pid: u32,
    pub credentials: Credentials,
    pub generation: u64,
    pub loader: Option<LoaderOf>,
    pub index: u32,
    /// Controlling terminal attachment; invalidated by its exact departure.
    pub ctty: Option<(u32, u64)>,
    pub image: u32,
    pub groups: Groups,
    pub limits: ResourceLimits,
    pub root: ExpenditureRoot,
}

/// What Vouch says of a loader's identity: the image of the record it
/// loads, and the ticket of its place, which SetId names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoaderOf {
    pub image: u32,
    pub ticket: u64,
}

/// A service-owned snapshot encoded directly from its immutable record fields.
pub struct Vouch<'a> {
    pub pid: u32,
    pub credentials: Credentials,
    pub generation: u64,
    pub loader: Option<LoaderOf>,
    pub index: u32,
    pub ctty: Option<(u32, u64)>,
    pub image: u32,
    pub groups: &'a Groups,
    pub limits: &'a ResourceLimits,
    pub root: ExpenditureRoot,
}
impl Vouch<'_> {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        let mut words = [0u32; 19];
        words[1] = self.pid;
        words[2..8].copy_from_slice(&self.credentials.words());
        let pair = |v: u64| [v as u32, (v >> 32) as u32];
        words[8..10].copy_from_slice(&pair(self.generation));
        let (mark, image, ticket) = self.loader.map_or((0, 0, 0), |l| (1, l.image, l.ticket));
        words[10] = mark;
        words[11] = image;
        words[12..14].copy_from_slice(&pair(ticket));
        words[14] = self.index;
        let (terminal, generation) = self.ctty.unwrap_or((u32::MAX, 0));
        words[16] = terminal;
        words[17..19].copy_from_slice(&pair(generation));
        for word in &mut words {
            *word = word.to_le();
        }
        // SAFETY: the initialized u32 array has no padding; every word is little endian.
        w.bytes(unsafe {
            core::slice::from_raw_parts(words.as_ptr().cast::<u8>(), words.len() * 4)
        })?;
        w.u32(self.image)?;
        self.groups.write(w)?;
        self.limits.write(w)?;
        w.u32(self.root.pid)?;
        w.u32(self.root.generation)
    }
}
impl WhoReply {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        Vouch {
            pid: self.pid,
            credentials: self.credentials,
            generation: self.generation,
            loader: self.loader,
            index: self.index,
            ctty: self.ctty,
            image: self.image,
            groups: &self.groups,
            limits: &self.limits,
            root: self.root,
        }
        .write(w)
    }

    /// BAD_SIZE out of the layout, for a PID of 0 or past the signed range,
    /// or a credential of -1.
    pub fn read(bytes: &[u8]) -> Result<Self, Status> {
        if bytes.len() != 252 {
            return Err(Status::BadSize);
        }
        let mut wire = core::mem::MaybeUninit::<[u32; 63]>::uninit();
        // SAFETY: exactly 252 source bytes initialize the aligned array's 63 words.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                wire.as_mut_ptr().cast::<u8>(),
                bytes.len(),
            )
        };
        // SAFETY: the exact whole array was initialized by the copy above.
        let mut wire = unsafe { wire.assume_init() };
        for word in &mut wire {
            *word = u32::from_le(*word);
        }
        if wire[0] != 0 {
            return Err(Status::BadSize);
        }
        let wide = |at: usize| u64::from(wire[at]) | (u64::from(wire[at + 1]) << 32);
        let pid = wire[1];
        let mut words = [0; 6];
        words.copy_from_slice(&wire[2..8]);
        let generation = wide(8);
        let (mark, loader_image, ticket) = (wire[10], wire[11], wide(12));
        let (index, zero) = (wire[14], wire[15]);
        let (terminal, ctty_generation) = (wire[16], wide(17));
        let ctty = match (terminal, ctty_generation) {
            (u32::MAX, 0) => None,
            (t, g) if (t as usize) < TERMINALS && g != 0 => Some((t, g)),
            _ => return Err(Status::BadSize),
        };
        let image = wire[19];
        let groups = Groups {
            count: wire[20],
            ids: wire[21..37].try_into().map_err(|_| Status::BadSize)?,
        };
        if !groups.valid() {
            return Err(Status::BadSize);
        }
        let limits = ResourceLimits {
            values: core::array::from_fn(|i| Limit {
                soft: wide(37 + 4 * i),
                hard: wide(39 + 4 * i),
            }),
        };
        if limits
            .values
            .iter()
            .any(|limit| limit.soft > limit.hard || limit.hard == u64::MAX)
        {
            return Err(Status::BadSize);
        }
        let root = ExpenditureRoot {
            pid: wire[61],
            generation: wire[62],
        };
        if generation == 0
            || generation & GENERATION_DEAD != 0
            || image == 0
            || root.pid == 0
            || root.generation == 0
        {
            return Err(Status::BadSize);
        }
        if pid == 0
            || pid > i32::MAX as u32
            || words.contains(&u32::MAX)
            || index as usize >= RECORDS
            || zero != 0
        {
            return Err(Status::BadSize);
        }
        let loader = match (mark, loader_image, ticket) {
            (0, 0, 0) => None,
            (1, loader_image, ticket) if loader_image == image && ticket != 0 => Some(LoaderOf {
                image: loader_image,
                ticket,
            }),
            _ => return Err(Status::BadSize),
        };
        Ok(Self {
            pid,
            credentials: Credentials::from_words(words),
            generation,
            loader,
            index,
            ctty,
            image,
            groups,
            limits,
            root,
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

/// What a wait found: the latest child exit, stop or continuation, none
/// yet (WNOHANG), or no child of the selector at all (ECHILD).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitResult {
    Ended { pid: u32, end: End, uid: u32 },
    Stopped { pid: u32, signal: u8, uid: u32 },
    Continued { pid: u32, uid: u32 },
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
            WaitResult::Stopped { pid, signal, uid } => (pid, 4, signal, uid),
            WaitResult::Continued { pid, uid } => (pid, 5, SIGCONT, uid),
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
            (4, p) if p != 0 && matches!(value, SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU) => {
                Ok(WaitResult::Stopped {
                    pid,
                    signal: value,
                    uid,
                })
            }
            (5, p) if p != 0 && value == SIGCONT => Ok(WaitResult::Continued { pid, uid }),
            (0, 0) => Ok(WaitResult::Nothing),
            (3, 0) => Ok(WaitResult::NoChild),
            _ => Err(Status::BadSize),
        }
    }
}

/// Where the page of its record lies in a POSIX process.
pub mod initial_map;
pub mod job;

pub const PAGE_ADDRESS: usize = 0x0D00_0000;
/// The version of the page's layout.
pub const PAGE_VERSION: u32 = 2;

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
    /// The signal mask of the main thread at the process's start: that of
    /// the thread whose posix_spawn made it ([P24-SPAWN]); the service
    /// writes it, and `ignored` too, before the process runs.
    pub start_mask: AtomicU64,
    /// Epoch and pending bits for maskable job stops and SIGCONT.
    pub stop_word: AtomicU64,
    pub cont_word: AtomicU64,
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
/// The code of a signal of the terminal (INTR, QUIT, SUSP): Linux's SI_KERNEL.
pub const SI_KERNEL: i32 = 0x80;
pub const CLD_EXITED: i32 = 1;
pub const CLD_KILLED: i32 = 2;
pub const CLD_STOPPED: i32 = 5;
pub const CLD_CONTINUED: i32 = 6;

/// The body of SpawnStart: the spawn-flags u32 (SPAWN_FLAGS), the
/// process group u32, the caller's level u32, at which the loader runs,
/// the signal mask u64 the child's main thread starts with (the caller's,
/// or that of POSIX_SPAWN_SETSIGMASK) and the signals u64 whose action
/// POSIX_SPAWN_SETSIGDEF sets to the default (bit n - 1 for signal n).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpawnStart {
    pub flags: u32,
    pub pgroup: u32,
    pub level: u8,
    pub mask: u64,
    pub default: u64,
}

impl SpawnStart {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.flags)?;
        w.u32(self.pgroup)?;
        w.u32(self.level.into())?;
        w.u64(self.mask)?;
        w.u64(self.default)
    }

    /// BAD_SIZE out of the layout or with a level past 63.
    pub fn read(mut r: Reader<'_>) -> Result<Self, Status> {
        let (flags, pgroup, level) = (r.u32()?, r.u32()?, r.u32()?);
        let (mask, default) = (r.u64()?, r.u64()?);
        r.finish()?;
        let level = u8::try_from(level)
            .ok()
            .filter(|&l| l <= 63)
            .ok_or(Status::BadSize)?;
        Ok(Self {
            flags,
            pgroup,
            level,
            mask,
            default,
        })
    }
}

/// The body of ForkStart: the caller's level u32, at which the loader
/// runs, then the words of the page (`Page`) the child starts with: the
/// signals its actions ignore u64 and catch u64, and its flags of SIGCHLD
/// u64 (PAGE_NOCLDWAIT, PAGE_NOCLDSTOP, PAGE_CHLD_IGNORED).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForkStart {
    pub level: u8,
    pub ignored: u64,
    pub caught: u64,
    pub flags: u64,
}

/// The flags of the page ForkStart takes.
pub const PAGE_FLAGS: u64 = PAGE_NOCLDWAIT | PAGE_NOCLDSTOP | PAGE_CHLD_IGNORED;

impl ForkStart {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.level.into())?;
        w.u64(self.ignored)?;
        w.u64(self.caught)?;
        w.u64(self.flags)
    }

    /// BAD_SIZE out of the layout, with a level past 63 or a flag past
    /// PAGE_FLAGS.
    pub fn read(mut r: Reader<'_>) -> Result<Self, Status> {
        let level = r.u32()?;
        let (ignored, caught, flags) = (r.u64()?, r.u64()?, r.u64()?);
        r.finish()?;
        let level = u8::try_from(level)
            .ok()
            .filter(|&l| l <= 63)
            .ok_or(Status::BadSize)?;
        if flags & !PAGE_FLAGS != 0 {
            return Err(Status::BadSize);
        }
        Ok(Self {
            level,
            ignored,
            caught,
            flags,
        })
    }
}

/// The body of SetId: the ticket of the loader's place u64 (Vouch's
/// `LoaderOf`), the record's PID u32 and image u32, the user ID u32 and
/// the group ID u32 the file sets (NO_ID for none).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetId {
    pub ticket: u64,
    pub pid: u32,
    pub image: u32,
    pub uid: u32,
    pub gid: u32,
}

/// An ID SetId leaves as it is.
pub const NO_ID: u32 = u32::MAX;

impl SetId {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u64(self.ticket)?;
        w.u32(self.pid)?;
        w.u32(self.image)?;
        w.u32(self.uid)?;
        w.u32(self.gid)
    }

    /// BAD_SIZE out of the layout or with neither ID.
    pub fn read(mut r: Reader<'_>) -> Result<Self, Status> {
        let ticket = r.u64()?;
        let (pid, image, uid, gid) = (r.u32()?, r.u32()?, r.u32()?, r.u32()?);
        r.finish()?;
        if uid == NO_ID && gid == NO_ID {
            return Err(Status::BadSize);
        }
        Ok(Self {
            ticket,
            pid,
            image,
            uid,
            gid,
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
    fn exhausted_generation_never_reopens_an_old_authority() {
        assert_eq!(next_generation(0, false), 1);
        assert_eq!(next_generation(GENERATION_DEAD | 7, false), 8);
        assert_eq!(
            next_generation(GENERATION_DEAD | 7, true),
            GENERATION_DEAD | 8
        );
        let last = GENERATION_DEAD - 1;
        let exhausted = next_generation(last, false);
        assert_eq!(exhausted, u64::MAX);
        for retain in [false, true] {
            assert_eq!(next_generation(last, retain), exhausted);
            assert_eq!(next_generation(exhausted, retain), exhausted);
        }
        assert!(!generation_room(last, 1));
        assert!(generation_room(last - 1, 1));
        assert!(!generation_room(last - 1, 2));
        assert!(generation_room(last - 2, 2));
        assert!(!generation_room(last - 2, 3));
        assert!(generation_room(last - 3, 3));
        assert!(generation_room(GENERATION_DEAD | 7, 4));
        assert!(!generation_room(exhausted, 1));
        assert!(!generation_room(0, 0));
    }

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
            Method::WaitStart,
            Method::WaitTake,
            Method::WaitCancel,
            Method::Kill,
            Method::Router,
            Method::SetPgid,
            Method::SetSid,
            Method::GetPgid,
            Method::GetSid,
            Method::Register,
            Method::Vouch,
            Method::SpawnStart,
            Method::Boot,
            Method::Take,
            Method::SpawnCommit,
            Method::SpawnAbort,
            Method::SetId,
            Method::ExecStart,
            Method::ExecCommit,
            Method::ExecAbort,
            Method::Replace,
            Method::Ready,
            Method::Pool,
            Method::ForkStart,
            Method::ForkCommit,
            Method::ForkAbort,
            Method::TtySignal,
            Method::SetCtty,
            Method::DropCtty,
            Method::TtyEvents,
            Method::AckCtty,
            Method::LoaderTerminal,
            Method::LoaderClock,
            Method::SignalGeneration,
            Method::StopSelf,
            Method::DetachCtty,
            Method::ReturnSignal,
            Method::DisconnectCtty,
            Method::RetainedLoader,
            Method::InitialMapQuery,
            Method::InitialMapAck,
        ];
        assert_eq!(methods.len(), METHODS.len());
        for (i, m) in methods.iter().enumerate() {
            assert_eq!(*m as u16, METHODS[i]);
            assert_eq!(m.header().version, VERSION);
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
        assert_eq!(Label::parse(label.loader()), Some((label, Place::Loader)));
        assert_eq!(Label::from_raw(label.loader()), None, "no record's session");
        assert_eq!(label.pid(), 5 + 256 * 3);
        // Labels of init, both place bits, other image numbers, an index
        // past the records and generation 0 name no record.
        for raw in [
            0,
            7,
            3 << 16 | 5,
            label.loader() & !(1 << 63),
            label.raw() & !(1 << 40),
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
        assert_eq!(Label::next_generation(GENERATION_MAX), None);
        assert_eq!(
            Label::next_generation(GENERATION_MAX - 1),
            Some(GENERATION_MAX)
        );
        assert_eq!(Label::next_generation(1), Some(2));
    }

    #[test]
    fn create_round_trips_and_refuses_bad_levels() {
        let create = Create {
            quota: 512 * 4096,
            handle_limit: 32,
            ceiling: 31,
            priority: 30,
            root: true,
            ticket: 0x1234,
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
    fn who_round_trips_and_refuses_what_is_no_identity() {
        let reply = WhoReply {
            pid: 300,
            credentials: Credentials::NOBODY,
            generation: 1 << 40 | 7,
            loader: None,
            index: 44,
            ctty: Some((0, 5)),
            image: 1,
            groups: Groups::EMPTY,
            limits: ResourceLimits::initial(2 * 1024 * 1024),
            root: ExpenditureRoot {
                pid: 2,
                generation: 1,
            },
        };
        let mut w = Writer::new();
        reply.write(&mut w).unwrap();
        assert_eq!(w.as_bytes().len(), 252);
        assert_eq!(WhoReply::read(w.as_bytes()), Ok(reply));
        let mut bytes = w.as_bytes().to_vec();
        bytes[4..8].fill(0);
        assert_eq!(WhoReply::read(&bytes), Err(Status::BadSize), "pid 0");
        assert_eq!(WhoReply::read(&w.as_bytes()[..63]), Err(Status::BadSize));
        bytes = w.as_bytes().to_vec();
        bytes[56..60].copy_from_slice(&(RECORDS as u32).to_le_bytes());
        assert_eq!(WhoReply::read(&bytes), Err(Status::BadSize), "index");
        let loader = WhoReply {
            loader: Some(LoaderOf {
                image: 1,
                ticket: 3 << 8 | 5,
            }),
            ..reply
        };
        let mut w = Writer::new();
        loader.write(&mut w).unwrap();
        assert_eq!(WhoReply::read(w.as_bytes()), Ok(loader));
        let mut bytes = w.as_bytes().to_vec();
        bytes[40] = 2;
        assert_eq!(WhoReply::read(&bytes), Err(Status::BadSize), "mark 2");
        assert_eq!(GENERATIONS_SIZE, 2048);
        assert_eq!(GROUPS_AT + RECORDS * 8, 4096, "both halves in a page");
        assert_eq!(groups_of(groups_word(300, 257)), Some((300, 257)));
        assert_eq!(groups_of(0), None);
        assert!(is_terminal(NOTARY | TERMINAL));
        assert!(!is_terminal(NOTARY));
        assert!(!is_terminal(1 << 63 | NOTARY | TERMINAL));
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

    #[test]
    fn spawn_start_and_set_id_round_trip() {
        let start = SpawnStart {
            flags: SPAWN_SETSIGMASK | SPAWN_RESETIDS,
            pgroup: 0,
            level: 30,
            mask: 1 << 9,
            default: 1 << 14,
        };
        let mut w = Writer::new();
        start.write(&mut w).unwrap();
        assert_eq!(SpawnStart::read(Reader::new(w.as_bytes())), Ok(start));
        let mut high = w.as_bytes().to_vec();
        high[8] = 64;
        assert_eq!(SpawnStart::read(Reader::new(&high)), Err(Status::BadSize));
        let set = SetId {
            ticket: 7 << 8 | 2,
            pid: 300,
            image: 1,
            uid: 0,
            gid: NO_ID,
        };
        let mut w = Writer::new();
        set.write(&mut w).unwrap();
        assert_eq!(SetId::read(Reader::new(w.as_bytes())), Ok(set));
        let none = SetId { uid: NO_ID, ..set };
        let mut w = Writer::new();
        none.write(&mut w).unwrap();
        assert_eq!(SetId::read(Reader::new(w.as_bytes())), Err(Status::BadSize));
        let fork = ForkStart {
            level: 30,
            ignored: 1 << 1,
            caught: 1 << 9,
            flags: PAGE_NOCLDSTOP,
        };
        let mut w = Writer::new();
        fork.write(&mut w).unwrap();
        assert_eq!(ForkStart::read(Reader::new(w.as_bytes())), Ok(fork));
        let mut bad = w.as_bytes().to_vec();
        bad[20] = 8;
        assert_eq!(ForkStart::read(Reader::new(&bad)), Err(Status::BadSize));
        // Only a notary label with SET_ID may send SetId.
        assert!(may_set_id(NOTARY | SET_ID | 7));
        assert!(!may_set_id(NOTARY | 7));
        assert!(!may_set_id(1 << 63 | NOTARY | SET_ID));
        assert!(is_notary(NOTARY | SET_ID | 7));
    }
}
