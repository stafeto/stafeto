// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Version 11 of the bounded RAM file service. Numbers are little endian.
//! Ordinary sessions first Bind with a genuine Process identity capability,
//! then FinishBinding until OK. Admission, Vouch, validation and commit are separate steps.
//! Init grants the named RAM diagnostic client an explicit boot profile.
//! BindPending admits a real Loader identity and a genuine unclaimed clone;
//! an unsuitable empty endpoint may be replaced when descriptors are optional.
//! With require_fds=0 the offered endpoint may be omitted: only LoaderOf is sent.
//! The returned fresh session holds a paid preparation; FinishBinding commits
//! its captured references under the same authentic Pending image and generation.
//! A paid RetainedLoader refresh distinguishes Loading from Handoff. Handoff
//! preserves the exact successful target's fd/CWD capture and permits only
//! Close, cancellation, FinishBinding and genuine Bind of that target identity.
//! File effects resume after the exact PID/index/image/root binds with loader=None.
//! Such Bind supersedes a queued retained-loader refresh; its candidate keeps
//! the old capability and capture for rollback on an invalid identity.
//!
//! ResolveStart retains raw bytes and the authenticated session's base inode.
//! Its body is base slot u32, generation u64, real_ids u32, follow_final u32,
//! then 1..=511 pathname bytes. Absolute paths use root. Names have 255 bytes.
//! The reply carries a generation-tagged job u64. ResolveStep, body job u64,
//! handles one component, up to eight dentry comparisons or one link expansion.
//! RESOLVING asks for another step. OK leaves a proof for the final operation.
//! ResolveSecond adds base slot/generation, follow_final and another path under
//! one job charge. Both paths retain their bases until ResolveCancel(job u64).
//! Loader executable proofs use a fresh genuine Pending session from BindPending.
//! A cold named loader root answers BindPending with canonical AUTHENTICATING
//! and all actual incoming Channels in their original order (one identity, or
//! offered session then identity). The caller retries with those returned handles
//! on the same root; FinishBinding begins after the new Pending capability exists.
//! Subsequent operations use that unforgeable session and recheck its generation.
//! Traversal, metadata or credential changes invalidate proofs; STALE_PROOF
//! requires another ResolveStep before retrying the final operation.
//!
//! OpenStart first carries client hold slot u32 and nonwrapping generation u64.
//! Live duplicate keys require exact original arguments and return the same job.
//! OpenQuery/OpenCancel address this key before a Start reply supplies its job ID.
//! Retired keys are terminal and can never repeat a file effect.
//! OpenStart captures base slot u32/generation u64, flags/mode/umask u32 and
//! raw pathname bytes under one paid job. ResolveStep produces an exact existing
//! edge or missing final edge. OpenPrepare(job u64) prepays creation and hidden
//! descriptor resources in separate steps; RESOLVING continues preparation.
//! OpenCommit(job u64) commits the file effect once and returns the hidden fd
//! packed u32 plus its description generation u64. Replays return the exact held result.
//! OpenFinish(client key) publishes its exact descriptor and releases the paid job.
//! Query active phases0..4 reply status0/phase/jobID (16 bytes). Finished phase5
//! replies status0/5/jobID0/fd/reserved0/description generation (32 bytes).
//! Close retains a tombstone; a replaced receipt returns terminal OPEN_RETIRED.
//! Commit/Finish/FinishedQuery pack fd bits0..5, description slot bits8..14 and
//! OPEN_RANDOM bit31. All other bits are zero. Numeric operations use the bare fd;
//! recovery retains the full description token and captured device type.
//! ResolveCancel releases the job and hidden descriptor; committed file effects
//! remain observable. Ordinary descriptor APIs and Clone exclude the hidden fd.
//!
//! OPEN: flags u32, proof u64. Reply: status, fd u32, optional RANDOM_DEVICE u32.
//! LOOKUP/INFO_PATH: proof u64. Reply: status then metadata/NodeInfo.
//! READ_DIR: index u32, proof u64. Reply: status, kind u32, name bytes.
//! OPEN_EXEC through a bound Pending session takes the original proof u64.
//! Its prepaid image resources return RESOLVING before a separate SetId effect.
//! Success replies with one SEND|TRANSFER image channel and status0 (4 bytes).
//! Replays of that exact proof return the same retained image without another SetId.
//! ResolveCancel retires the source's private recovery copy; external caps retain
//! the inode pin, fd0/root description charge and exact loader identity.
//! Completed ProofCancel retains terminal OPEN_RETIRED metadata for the old attempt.
//! Image labels carry opaque places/generations; ReadAt/ReadInto/InfoFd use fd0.
//! IMAGE_ABORT_REQUIRED is terminal after an uncertain SetId outcome.
//! Other final path operations consume their proofs. Cancellation is idempotent.
//! READ/WRITE: fd u32, count u32 or bytes. Reply: status, count u32, read bytes.
//! READ_AT/WRITE_AT add an offset u64; they preserve the description's position.
//! SEEK: fd u32, offset u32. SEEK_FROM adds signed offset i64 and origin u32.
//! STAT: fd u32, reply size u32. INFO_FD returns NodeInfo without ABI padding.
//! READ_DIR_FD advances the shared description and returns kind/inode/name.
//! CLOSE: fd u32, reply status and zero u32.
//! CLONE: count u32, descriptor numbers u32; a genuine child session shares
//! descriptions and retains the creator's authority until its own authentic Bind.
//! VerifySession only verifies the authenticated caller's own genuine clone.
//! AUTHENTICATING guarantees no file effect; FinishBinding completes a staged
//! retained-identity refresh, then the caller retries its exact original request.
//! Handle-free calls return no handles at this barrier. VerifySession returns
//! exactly its received Channel with SEND|TRANSFER rights, preserving its
//! captured fd/CWD snapshot; retry transfers that returned handle, never the
//! consumed old outgoing handle. FinishBinding's terminal result is journaled
//! until the next Bind or refresh, including completion by maintenance.
//! Raw LoaderRoot Resolve requests are refused; executable proofs require the
//! genuine fresh BindPending session described above.
//! READ_INTO on an image session: fd0, offset/count, destination memory capability.

#![cfg_attr(not(test), no_std)]

mod directory;
pub use directory::DirectoryEntry;
mod info;
mod time;
pub use info::NodeInfo;
pub use time::Timestamp;

use abi::MESSAGE_MAX;
use proto_wire::{HEADER_LEN, Header, Status};

pub const VERSION: u16 = 11;
pub const MAX_PATH: usize = 511;
pub const MAX_READ: usize = MESSAGE_MAX - 8;
pub const MAX_WRITE: usize = MESSAGE_MAX - HEADER_LEN - 4;
/// The bytes of one READ_INTO at most: the copy one request of an image
/// session makes in the service's step.
pub const READ_INTO_MAX: usize = 12 * 1024;

pub const READ_ONLY: u32 = 0;
pub const WRITE_ONLY: u32 = 1;
pub const READ_WRITE: u32 = 2;
/// Require a directory atomically when establishing the open description.
pub const DIRECTORY_ONLY: u32 = 4;
/// The caller asked for O_CREAT, O_TRUNC or O_APPEND: the null device takes
/// them (it has no contents to create, cut or follow), any other file
/// answers INVALID_ARGUMENT.
pub const CHANGES: u32 = 8;
/// Distinct mutable-open flags; the legacy CHANGES profile remains separate.
pub const CREATE: u32 = 16;
pub const EXCLUSIVE: u32 = 32;
pub const TRUNCATE: u32 = 64;
pub const APPEND: u32 = 128;
pub const NO_FOLLOW: u32 = 256;
/// The third word of the reply to an OPEN of a random device.
pub const RANDOM_DEVICE: u32 = 1;
/// Commit, Finish and FinishedQuery encode a captured Random description in fd bit31.
/// Bits0..5 hold fd3..34; bits8..14 hold its shared description slot0..127.
pub const OPEN_RANDOM: u32 = 1 << 31;
/// A success word retains the exact shared description slot.
pub const OPEN_DESCRIPTION_SHIFT: u32 = 8;
pub const OPEN_DESCRIPTION_MASK: u32 = 127 << OPEN_DESCRIPTION_SHIFT;
pub const OPEN_FD_MASK: u32 = 63;
pub const OPEN_RESULT_MASK: u32 = OPEN_RANDOM | OPEN_DESCRIPTION_MASK | OPEN_FD_MASK;

pub const NO_ENTRY: u32 = 300;
pub const BAD_FD: u32 = 301;
pub const IS_DIRECTORY: u32 = 302;
pub const NO_SPACE: u32 = 303;
pub const INVALID_ARGUMENT: u32 = 304;
pub const OFFSET_OVERFLOW: u32 = 305;
pub const NO_DATA: u32 = 306;
pub const TOO_MANY_OPEN_FILES: u32 = 307;
pub const ACCESS_DENIED: u32 = 308;
pub const NOT_DIRECTORY: u32 = 309;
/// EPERM: missing genuine Pending Loader authority or a cleanup-only session.
pub const PERMISSION: u32 = 310;
pub const NAME_TOO_LONG: u32 = 311;
pub const LOOP: u32 = 312;
pub const STALE_PROOF: u32 = 313;
pub const RESOLVING: u32 = 314;
/// The original request made no file effect. FinishBinding completes the
/// retained authority refresh before the caller retries the original request.
pub const AUTHENTICATING: u32 = 315;
pub const ALREADY_EXISTS: u32 = 316;
pub const READ_ONLY_FILESYSTEM: u32 = 317;
pub const TEXT_BUSY: u32 = 318;
/// The former operation may have completed; a fresh pathname retry is forbidden.
pub const OPEN_RETIRED: u32 = 319;
/// The implementation regular-file capacity was reached (EFBIG).
pub const FILE_TOO_LARGE: u32 = 320;
/// A SetId outcome requires a genuine loader abort before another execution attempt.
pub const IMAGE_ABORT_REQUIRED: u32 = 321;
/// Existing local hold slots give independent idempotency domains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenKey {
    pub slot: u32,
    pub generation: u64,
}
impl OpenKey {
    pub fn validate(self) -> Result<usize, u32> {
        if self.slot >= 32 || self.generation == 0 {
            return Err(INVALID_ARGUMENT);
        }
        Ok(self.slot as usize)
    }
}
pub const BOOT_PROFILE: u64 = 1 << 61;

/// Init issues this profile exclusively to the named diagnostic client.
pub const fn is_boot_profile(label: u64) -> bool {
    label & (OWN | LOADERS) == 0 && label & BOOT_PROFILE != 0
}

/// The mark of the label of the session of the loaders: bit 62 with bit
/// 63 clear, which init gives only to the process service's session with
/// the RAM file service.
pub const LOADERS: u64 = 1 << 62;

/// Whether `label` is that of the session of the loaders.
pub const fn is_loaders(label: u64) -> bool {
    label & (1 << 63) == 0 && label & LOADERS != 0
}

/// Genuine issued sessions carry OWN; image sessions also carry IMAGE_SESSION.
/// The remaining bits identify an opaque place and its nonwrapping generation.
pub const OWN: u64 = 1 << 63;
pub const IMAGE_SESSION: u64 = 1 << 62;
pub const fn is_image(label: u64) -> bool {
    label & (OWN | IMAGE_SESSION) == OWN | IMAGE_SESSION
}

/// Origins for the signed 64-bit SEEK_FROM request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SeekFrom {
    Start = 0,
    Current = 1,
    End = 2,
    Data = 3,
    Hole = 4,
}

impl SeekFrom {
    pub fn from_number(number: u32) -> Option<Self> {
        match number {
            0 => Some(Self::Start),
            1 => Some(Self::Current),
            2 => Some(Self::End),
            3 => Some(Self::Data),
            4 => Some(Self::Hole),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub kind: u32,
    pub size: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Open = 1,
    Read = 2,
    Write = 3,
    Seek = 4,
    Stat = 5,
    Close = 6,
    ReadDir = 7,
    Lookup = 8,
    SeekFrom = 9,
    InfoFd = 10,
    InfoPath = 11,
    ReadDirFd = 12,
    ReadAt = 13,
    OpenExec = 14,
    Clone = 15,
    WriteAt = 16,
    ReadInto = 17,
    /// VerifySession: body require_fds u32 (0 or 1), one offered channel.
    /// Only this authenticated caller's true unclaimed clone is accepted.
    VerifySession = 18,
    /// Process identity capability, no body. A session retains the vouched principal.
    Bind = 19,
    /// Trusted loader root: require_fds u32, target Files and LoaderOf identity capabilities.
    BindPending = 20,
    /// base slot u32/generation u64, real_ids u32/follow_final u32, raw pathname bytes.
    ResolveStart = 21,
    /// Resolve job u64. One component and at most eight dentry comparisons.
    ResolveStep = 22,
    /// Resolve job u64. Releases its charge and retained bases.
    ResolveCancel = 23,
    /// Add a second captured base/path to the same paid preparation.
    ResolveSecond = 24,
    /// On a prepared genuine session: no body, no handles. RESOLVING requests another step.
    FinishBinding = 25,
    /// Captured base, mutable-open flags, mode, umask and raw path; reply job u64.
    OpenStart = 26,
    /// Paid job u64. Prepay creation and a hidden description before file effects.
    OpenPrepare = 27,
    /// Paid job u64. Commit once; reply packed fd/slot/type u32 and description generation u64.
    OpenCommit = 28,
    /// Client key slot u32/generation u64. Publish the exact committed descriptor once.
    OpenFinish = 29,
    /// Client key slot u32/generation u64. Release exact ownership; effects persist.
    OpenCancel = 30,
    /// Client key slot u32/generation u64. Find the original paid operation.
    OpenQuery = 31,
    /// Published fd u32. Read-only status/packed token/generation/access flags (20 bytes).
    CaptureDescription = 32,
    /// Packed fd/slot u32 and generation u64. Reply status and Closed0/AlreadyGone1.
    CloseExact = 33,
    /// Count u32 and exact packed fd/slot u32 + generation u64 entries. Maximum 32.
    CloneExact = 34,
}

impl Method {
    pub const fn header(self) -> Header {
        Header::new(self as u16, VERSION)
    }

    pub fn from_number(n: u16) -> Option<Self> {
        match n {
            1 => Some(Self::Open),
            2 => Some(Self::Read),
            3 => Some(Self::Write),
            4 => Some(Self::Seek),
            5 => Some(Self::Stat),
            6 => Some(Self::Close),
            7 => Some(Self::ReadDir),
            8 => Some(Self::Lookup),
            9 => Some(Self::SeekFrom),
            10 => Some(Self::InfoFd),
            11 => Some(Self::InfoPath),
            12 => Some(Self::ReadDirFd),
            13 => Some(Self::ReadAt),
            14 => Some(Self::OpenExec),
            15 => Some(Self::Clone),
            16 => Some(Self::WriteAt),
            17 => Some(Self::ReadInto),
            18 => Some(Self::VerifySession),
            19 => Some(Self::Bind),
            20 => Some(Self::BindPending),
            21 => Some(Self::ResolveStart),
            22 => Some(Self::ResolveStep),
            23 => Some(Self::ResolveCancel),
            24 => Some(Self::ResolveSecond),
            25 => Some(Self::FinishBinding),
            26 => Some(Self::OpenStart),
            27 => Some(Self::OpenPrepare),
            28 => Some(Self::OpenCommit),
            29 => Some(Self::OpenFinish),
            30 => Some(Self::OpenCancel),
            31 => Some(Self::OpenQuery),
            32 => Some(Self::CaptureDescription),
            33 => Some(Self::CloseExact),
            34 => Some(Self::CloneExact),
            _ => None,
        }
    }
}

pub const METHODS: &[u16] = &[
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 33, 34,
];

pub fn valid_path(path: &[u8]) -> Result<&str, Status> {
    if path.is_empty() || path.len() > MAX_PATH || path[0] != b'/' || path.contains(&0) {
        return Err(Status::BadSize);
    }
    core::str::from_utf8(path).map_err(|_| Status::BadSize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_reject_empty_relative_nul_and_bad_utf8() {
        for path in [b"".as_slice(), b"tmp/a", b"/a\0b", b"/\xff"] {
            assert_eq!(valid_path(path), Err(Status::BadSize));
        }
        assert_eq!(valid_path(b"/tmp/a"), Ok("/tmp/a"));
        assert_eq!(valid_path(b"/"), Ok("/"));
    }

    #[test]
    fn paths_take_511_bytes_and_a_request_with_them_fits_a_message() {
        // PATH_MAX is 512 with the terminator.
        assert_eq!(MAX_PATH + 1, 512);
        let mut path = [b'a'; MAX_PATH + 1];
        path[0] = b'/';
        assert_eq!(valid_path(&path[..MAX_PATH]).map(str::len), Ok(MAX_PATH));
        assert_eq!(valid_path(&path), Err(Status::BadSize));
        const { assert!(HEADER_LEN + 4 + MAX_PATH <= MESSAGE_MAX) };
    }

    #[test]
    fn every_method_number_round_trips_and_is_listed() {
        for number in 0..=31u16 {
            let method = Method::from_number(number);
            assert_eq!(method.is_some(), METHODS.contains(&number), "{number}");
            if let Some(method) = method {
                assert_eq!(method as u16, number);
            }
        }
    }

    /// Only init's mark names the loaders; the service's own labels have
    /// bit 63, and an image session's carries its entry.
    #[test]
    fn labels_of_the_loaders_and_of_image_sessions() {
        assert!(is_loaders(LOADERS | 7));
        assert!(!is_loaders(7));
        assert!(!is_loaders(OWN | LOADERS | 7), "an image session");
        assert!(is_image(OWN | IMAGE_SESSION | 12));
        assert!(!is_image(OWN | 12));
        assert!(!is_image(LOADERS | 12));
    }
}
