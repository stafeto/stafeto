// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! C ABI types and checked conversions for the stafeto Rust POSIX layer.

#![no_std]

pub mod constants;

/// Ordinary signal numbers use bits 0..30; unused bits remain reserved.
pub type SigSet = u64;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigAction {
    /// SIG_DFL = 0, SIG_IGN = 1, otherwise a live C handler address.
    pub handler: u64,
    pub mask: SigSet,
    pub flags: i32,
}

/// Alternate signal stack descriptor. No alternate stack is enabled yet.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SignalStack {
    pub ss_sp: *mut core::ffi::c_void,
    pub ss_size: usize,
    pub ss_flags: i32,
}

/// AArch64 machine context. Field names are stafeto ABI extensions; TLS and
/// the native IPC address remain private to the runtime's return frame.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct MachineContext {
    pub registers: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    pub vectors: [u128; 32],
    pub fpcr: u64,
    pub fpsr: u64,
}

/// Context interrupted by signal delivery, valid throughout that handler.
/// uc_link is null for a signal frame; uc_stack describes the disabled
/// alternate signal stack. getcontext/setcontext are not implemented yet.
#[repr(C)]
pub struct UserContext {
    pub uc_link: *mut UserContext,
    pub uc_sigmask: SigSet,
    pub uc_stack: SignalStack,
    pub uc_mcontext: MachineContext,
}
const _: () = {
    assert!(core::mem::size_of::<SignalStack>() == 24);
    assert!(core::mem::size_of::<MachineContext>() == 800);
    assert!(core::mem::offset_of!(MachineContext, vectors) == 272);
    assert!(core::mem::size_of::<UserContext>() == 848);
    assert!(core::mem::align_of::<UserContext>() == 16);
    assert!(core::mem::offset_of!(UserContext, uc_mcontext) == 48);
};

/// Fixed-width signal information, matching the AArch64 C siginfo_t layout.
/// si_value stores the object representation of the C union sigval. Sources
/// initialize all eight bytes; pointer and integer interpretations belong to
/// the application and are never dereferenced by the runtime.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigInfo {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    pub si_pid: i32,
    pub si_uid: u32,
    pub si_status: i32,
    pub si_addr: u64,
    pub si_value: u64,
}

impl SigInfo {
    /// Value-carrying source. The process owner supplies the authenticated PID
    /// and real UID; application-supplied values are copied without dereferencing.
    pub const fn queued(signal: i32, pid: i32, uid: u32, value: u64) -> Self {
        Self {
            si_signo: signal,
            si_errno: 0,
            si_code: constants::SI_QUEUE,
            si_pid: pid,
            si_uid: uid,
            si_status: 0,
            si_addr: 0,
            si_value: value,
        }
    }

    /// Current non-value-generating thread-directed source. Fields other than
    /// signo/code are unspecified for SI_THREAD and deterministically zeroed.
    pub const fn thread(signal: i32) -> Self {
        Self {
            si_signo: signal,
            si_errno: 0,
            si_code: constants::SI_THREAD,
            si_pid: 0,
            si_uid: 0,
            si_status: 0,
            si_addr: 0,
            si_value: 0,
        }
    }

    /// Field encoding avoids reading C padding and keeps signed fields intact.
    pub fn words(self) -> [u64; 5] {
        let pair = |low: u32, high: u32| u64::from(low) | (u64::from(high) << 32);
        [
            pair(self.si_signo as u32, self.si_errno as u32),
            pair(self.si_code as u32, self.si_pid as u32),
            pair(self.si_uid, self.si_status as u32),
            self.si_addr,
            self.si_value,
        ]
    }

    pub fn from_words(words: [u64; 5]) -> Self {
        Self {
            si_signo: words[0] as u32 as i32,
            si_errno: (words[0] >> 32) as u32 as i32,
            si_code: words[1] as u32 as i32,
            si_pid: (words[1] >> 32) as u32 as i32,
            si_uid: words[2] as u32,
            si_status: (words[2] >> 32) as u32 as i32,
            si_addr: words[3],
            si_value: words[4],
        }
    }
}

const _: () = {
    assert!(core::mem::size_of::<SigAction>() == 24);
    assert!(core::mem::align_of::<SigAction>() == 8);
    assert!(core::mem::size_of::<SigInfo>() == 40);
    assert!(core::mem::align_of::<SigInfo>() == 8);
    assert!(core::mem::offset_of!(SigInfo, si_addr) == 24);
    assert!(core::mem::offset_of!(SigInfo, si_value) == 32);
};

#[derive(Debug, Eq, PartialEq)]
pub enum ConversionError {
    Malformed,
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

impl Timespec {
    fn from_ns(ns: u64) -> Self {
        Self {
            tv_sec: (ns / 1_000_000_000) as i64,
            tv_nsec: (ns % 1_000_000_000) as i64,
        }
    }
}

#[repr(C)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u64,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atim: Timespec,
    pub st_mtim: Timespec,
    pub st_ctim: Timespec,
}

const _: () = {
    assert!(core::mem::size_of::<Timespec>() == 16);
    assert!(core::mem::size_of::<Stat>() == constants::STAFETO_STAT_SIZE as usize);
    assert!(core::mem::align_of::<Stat>() == 8);
    assert!(core::mem::offset_of!(Stat, st_size) == 48);
    assert!(core::mem::offset_of!(Stat, st_atim) == 72);
};

impl TryFrom<proto_fs::NodeInfo> for Stat {
    type Error = ConversionError;

    fn try_from(info: proto_fs::NodeInfo) -> Result<Self, Self::Error> {
        if info.permissions & !0o7777 != 0 || info.block_size == 0 {
            return Err(ConversionError::Malformed);
        }
        let kind = match info.kind {
            1 => constants::S_IFDIR,
            2 => constants::S_IFREG,
            3 => constants::S_IFCHR,
            _ => return Err(ConversionError::Malformed),
        };
        Ok(Self {
            st_dev: info.device,
            st_ino: info.inode,
            st_mode: kind | info.permissions,
            st_nlink: info.links,
            st_uid: info.uid,
            st_gid: info.gid,
            st_rdev: info.special_device,
            st_size: i64::try_from(info.size).map_err(|_| ConversionError::Overflow)?,
            st_blksize: i64::from(info.block_size),
            st_blocks: i64::try_from(info.blocks).map_err(|_| ConversionError::Overflow)?,
            st_atim: Timespec::from_ns(info.access_ns),
            st_mtim: Timespec::from_ns(info.modify_ns),
            st_ctim: Timespec::from_ns(info.change_ns),
        })
    }
}

/// Directory entry returned by the C ABI. d_type is a convenience extension.
#[repr(C)]
pub struct Dirent {
    pub d_ino: u64,
    pub d_type: u8,
    pub d_name: [u8; constants::NAME_MAX as usize + 1],
}

impl Dirent {
    pub const fn empty() -> Self {
        Self {
            d_ino: 0,
            d_type: 0,
            d_name: [0; constants::NAME_MAX as usize + 1],
        }
    }
}

const _: () = {
    assert!(core::mem::size_of::<Dirent>() == constants::STAFETO_DIRENT_SIZE as usize);
    assert!(core::mem::offset_of!(Dirent, d_name) == 9);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_information_preserves_signed_fields_and_full_values() {
        let info = SigInfo {
            si_signo: 64,
            si_errno: i32::MIN,
            si_code: -1,
            si_pid: i32::MAX,
            si_uid: u32::MAX,
            si_status: -127,
            si_addr: 0xfedc_ba98_7654_3210,
            si_value: 0x8765_4321_fedc_ba98,
        };
        assert_eq!(SigInfo::from_words(info.words()), info);
        assert_eq!(info.words()[0], 0x8000_0000_0000_0040);
        assert_eq!(info.words()[1], 0x7fff_ffff_ffff_ffff);
        let thread = SigInfo::thread(constants::SIGUSR1);
        assert_eq!(thread.si_signo, constants::SIGUSR1);
        assert_eq!(thread.si_code, constants::SI_THREAD);
        assert_eq!(&thread.words()[2..], &[0; 3]);
    }

    fn node() -> proto_fs::NodeInfo {
        proto_fs::NodeInfo {
            kind: 2,
            permissions: 0o6754,
            device: u64::MAX,
            special_device: u64::MAX - 1,
            inode: u64::MAX - 2,
            links: u64::MAX - 3,
            uid: u32::MAX,
            gid: u32::MAX - 1,
            size: i64::MAX as u64,
            block_size: u32::MAX,
            blocks: i64::MAX as u64,
            access_ns: 1_000_000_001,
            modify_ns: u64::MAX,
            change_ns: 999_999_999,
        }
    }

    #[test]
    fn wide_fields_and_normalized_times_survive_conversion() {
        let value = Stat::try_from(node()).unwrap();
        assert_eq!(value.st_dev, u64::MAX);
        assert_eq!(value.st_rdev, u64::MAX - 1);
        assert_eq!(value.st_ino, u64::MAX - 2);
        assert_eq!(value.st_nlink, u64::MAX - 3);
        assert_eq!((value.st_uid, value.st_gid), (u32::MAX, u32::MAX - 1));
        assert_eq!(value.st_mode, constants::S_IFREG | 0o6754);
        assert_eq!((value.st_size, value.st_blocks), (i64::MAX, i64::MAX));
        assert_eq!(value.st_blksize, i64::from(u32::MAX));
        assert_eq!(
            value.st_atim,
            Timespec {
                tv_sec: 1,
                tv_nsec: 1
            }
        );
        assert_eq!(
            value.st_mtim,
            Timespec {
                tv_sec: 18_446_744_073,
                tv_nsec: 709_551_615
            }
        );
        assert_eq!(
            value.st_ctim,
            Timespec {
                tv_sec: 0,
                tv_nsec: 999_999_999
            }
        );
    }

    #[test]
    fn signed_overflow_and_invalid_modes_are_rejected() {
        let mut value = node();
        value.size += 1;
        assert!(matches!(
            Stat::try_from(value),
            Err(ConversionError::Overflow)
        ));
        value = node();
        value.blocks += 1;
        assert!(matches!(
            Stat::try_from(value),
            Err(ConversionError::Overflow)
        ));
        for (kind, permissions, block_size) in
            [(0, 0, 512), (4, 0, 512), (1, 0o10000, 512), (2, 0, 0)]
        {
            value = node();
            value.kind = kind;
            value.permissions = permissions;
            value.block_size = block_size;
            assert!(matches!(
                Stat::try_from(value),
                Err(ConversionError::Malformed)
            ));
        }
    }
}
