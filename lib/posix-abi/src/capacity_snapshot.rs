// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Strict private observations of two authenticated capacity leaders.
use proto_wire::{Reader, Status};
use rt::abi::{MemoryInfo, ProcessHandles, ProcessMemory};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Phases {
    pub own: u8,
    /// Registration order has no implicit RootA or RootB meaning.
    pub registered: [u8; 2],
}
impl Phases {
    fn read(word: u32) -> Result<Self, Status> {
        let [own, a, b, reserved] = word.to_le_bytes();
        if reserved != 0 || own > 5 || a > 5 || b > 5 || (own != 0 && own != a && own != b) {
            return Err(Status::BadSize);
        }
        Ok(Self {
            own,
            registered: [a, b],
        })
    }
    pub fn other_at_least(self, phase: u8) -> bool {
        self.own != 0
            && (1..=5).contains(&phase)
            && self.registered.iter().filter(|p| **p >= phase).count()
                > usize::from(self.own >= phase)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub pid: u32,
    pub image: u32,
    pub root: [u64; 2],
    pub memory: ProcessMemory,
    /// Startup, warm, actual peak, allocation attempts and failed attempts.
    pub meter: [u64; 5],
    pub handles: ProcessHandles,
    pub backing: MemoryInfo,
    /// Free inodes, dentries and physical data-page slots.
    pub available: [u32; 3],
    /// Root inodes, dentries, pages and descriptions.
    pub usage: [u32; 4],
    pub jobs: u32,
    pub preparations: u32,
    pub root_preparations: u32,
    pub phases: Phases,
}
impl Snapshot {
    pub fn read(bytes: &[u8], handles: usize) -> Result<Self, Status> {
        if handles != 0 {
            return Err(Status::BadSize);
        }
        let mut r = Reader::new(bytes);
        let status = Status::from_code(r.u32()?);
        if status != Status::Ok {
            if r.u32()? != 0 {
                return Err(Status::BadSize);
            }
            r.finish()?;
            return Err(status);
        }
        if bytes.len() != 192 || r.u32()? != 2 {
            return Err(Status::BadSize);
        }
        let pid = r.u32()?;
        let image = r.u32()?;
        let root = [r.u64()?, r.u64()?];
        let memory = ProcessMemory::from_words([r.u64()?, r.u64()?, r.u64()?]);
        let meter = [r.u64()?, r.u64()?, r.u64()?, r.u64()?, r.u64()?];
        let handles = ProcessHandles::from_words([r.u64()?, r.u64()?, r.u64()?]);
        let backing = MemoryInfo::from_words([r.u64()?, r.u64()?, r.u64()?]);
        let available = [r.u32()?, r.u32()?, r.u32()?];
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let usage = [r.u32()?, r.u32()?, r.u32()?, r.u32()?];
        let jobs = r.u32()?;
        let preparations = r.u32()?;
        let root_preparations = r.u32()?;
        let phases = Phases::read(r.u32()?)?;
        r.finish()?;
        if pid == 0
            || image == 0
            || root.contains(&0)
            || memory.used > memory.quota
            || handles
                .live
                .checked_add(handles.retired)
                .is_none_or(|n| n > handles.limit)
            || backing.size != 4096 * 4096
            || backing.pages != 4096
            || available[2] > 4096
            || usage[2] > 4096
            || jobs > 128
            || preparations > 128
            || root_preparations > 96
        {
            return Err(Status::BadSize);
        }
        Ok(Self {
            pid,
            image,
            root,
            memory,
            meter,
            handles,
            backing,
            available,
            usage,
            jobs,
            preparations,
            root_preparations,
            phases,
        })
    }
}

/// Read the current session's genuine authenticated Root and process measurements.
pub fn snapshot() -> Result<Snapshot, i32> {
    let transport = crate::shared::with_files(|files| Ok(files.transport()))?;
    let request = proto_wire::Header::new(0xfff0, proto_fs::VERSION).bytes();
    let reply = rt::sys::send(transport.files().sessions().0, &request)
        .map_err(|_| crate::constants::EIO)?;
    if reply.len == 8 {
        let inline = rt::abi::inline_bytes(&reply.words);
        return Snapshot::read(&inline[..8], reply.handles.len())
            .map_err(|e| crate::error(posix_fs::FsError::from(e)));
    }
    if reply.len != 192 || !reply.handles.is_empty() {
        return Err(crate::constants::EIO);
    }
    let mut bytes = [0; 192];
    rt::msgbuf::read(0, &mut bytes);
    Snapshot::read(&bytes, reply.handles.len())
        .map_err(|e| crate::error(posix_fs::FsError::from(e)))
}

/// Mutate only this original leader's existing phase card, or fix the idle warm point.
pub fn control(action: u32, phase: u32) -> Result<(), i32> {
    let transport = crate::shared::with_files(|files| Ok(files.transport()))?;
    let mut request = [0; 16];
    request[..8].copy_from_slice(&proto_wire::Header::new(0xfff1, proto_fs::VERSION).bytes());
    request[8..12].copy_from_slice(&action.to_le_bytes());
    request[12..16].copy_from_slice(&phase.to_le_bytes());
    let reply = rt::sys::send(transport.files().sessions().0, &request)
        .map_err(|_| crate::constants::EIO)?;
    if reply.len != 8 || !reply.handles.is_empty() || reply.words[0] >> 32 != 0 {
        return Err(crate::constants::EIO);
    }
    match Status::from_code(reply.words[0] as u32) {
        Status::Ok => Ok(()),
        e => Err(crate::error(posix_fs::FsError::from(e))),
    }
}

/// Bind the observation to the actual Ready claim before the final native call.
pub fn retired_arm(event: crate::data_probe::Event) -> Result<(), i32> {
    let claim = event.claim.ok_or(crate::constants::EIO)?;
    crate::shared::with_files(|files| {
        let actual = files.data_claim_state(claim).map_err(crate::error)?;
        if actual != event.state
            || actual.owner != Some(event.owner)
            || actual.claimant != Some(event.owner)
            || actual.kind != proto_fs::DataKind::Truncate
            || actual.progress != posix_fs::data::Phase::Ready
            || actual.job == 0
            || actual.result.is_some()
            || files.sessions().0.raw().0 != actual.session_handle
        {
            return Err(crate::constants::EIO);
        }
        Ok(())
    })?;
    retired_control(0, event)
}
/// Release only the same retained session/key/job observation after a refused call.
pub fn retired_disarm(event: crate::data_probe::Event) -> Result<(), i32> {
    retired_control(1, event)
}
fn retired_control(action: u32, event: crate::data_probe::Event) -> Result<(), i32> {
    let transport = crate::shared::with_files(|files| {
        if files.sessions().0.raw().0 != event.state.session_handle {
            return Err(crate::constants::EIO);
        }
        Ok(files.transport())
    })?;
    let mut request = [0; 32];
    request[..8].copy_from_slice(&proto_wire::Header::new(0xfff2, proto_fs::VERSION).bytes());
    request[8..12].copy_from_slice(&action.to_le_bytes());
    request[12..16].copy_from_slice(&(event.token.slot() as u32).to_le_bytes());
    request[16..24].copy_from_slice(&event.token.generation().to_le_bytes());
    request[24..32].copy_from_slice(&event.state.job.to_le_bytes());
    let reply = rt::sys::send(transport.files().sessions().0, &request)
        .map_err(|_| crate::constants::EIO)?;
    if reply.len != 8 || !reply.handles.is_empty() || reply.words[0] >> 32 != 0 {
        return Err(crate::constants::EIO);
    }
    match Status::from_code(reply.words[0] as u32) {
        Status::Ok => Ok(()),
        error => Err(crate::error(posix_fs::FsError::from(error))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> [u8; 192] {
        let mut b = [0; 192];
        for (at, value) in [(4, 2), (8, 19), (12, 1), (188, 2 | (3 << 8) | (2 << 16))] {
            b[at..at + 4].copy_from_slice(&u32::to_le_bytes(value));
        }
        for (at, value) in [
            (16, 19),
            (24, 1),
            (32, 6000),
            (40, 5100),
            (112, 128),
            (120, 4096 * 4096),
            (128, 4096),
        ] {
            b[at..at + 8].copy_from_slice(&u64::to_le_bytes(value));
        }
        b
    }
    #[test]
    fn schema_two_preserves_exact_root_and_registration_order() {
        let b = fixture();
        let s = Snapshot::read(&b, 0).unwrap();
        assert_eq!(s.root, [19, 1]);
        assert_eq!(s.phases.own, 2);
        assert_eq!(s.phases.registered, [3, 2]);
        assert!(s.phases.other_at_least(3));
        assert!(!s.phases.other_at_least(4));
        assert!(
            !Phases::read(3 | (3 << 8) | (1 << 16))
                .unwrap()
                .other_at_least(3)
        );
        assert!(
            !Phases::read((3 << 8) | (1 << 16))
                .unwrap()
                .other_at_least(3)
        );
    }
    #[test]
    fn schema_reserved_caps_and_phase_range_fail_before_observation() {
        let b = fixture();
        for (at, value) in [
            (4, 1),
            (4, 3),
            (156, 1),
            (188, 0x01030202),
            (188, 6),
            (188, 2 | (6 << 8)),
            (188, 2 | (6 << 16)),
            (188, 4 | (3 << 8) | (2 << 16)),
        ] {
            let mut malformed = b;
            malformed[at..at + 4].copy_from_slice(&u32::to_le_bytes(value));
            assert_eq!(Snapshot::read(&malformed, 0), Err(Status::BadSize));
        }
        assert_eq!(Snapshot::read(&b, 1), Err(Status::BadSize));
        assert_eq!(Snapshot::read(&b[..191], 0), Err(Status::BadSize));
        let mut trailing = [0; 193];
        trailing[..192].copy_from_slice(&b);
        assert_eq!(Snapshot::read(&trailing, 0), Err(Status::BadSize));
        let mut error = proto_wire::reply(Status::Unknown(proto_fs::NO_SPACE));
        assert_eq!(
            Snapshot::read(&error, 0),
            Err(Status::Unknown(proto_fs::NO_SPACE))
        );
        error[4] = 1;
        assert_eq!(Snapshot::read(&error, 0), Err(Status::BadSize));
    }
}
