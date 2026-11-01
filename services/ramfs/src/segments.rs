// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The files of XSI shared memory segments, `/dev/shm/.sysvN`, as the service
//! deals with them when the pipe service has a job for one (proto_pipe::jobs):
//! the new owner, group and mode of a file, and its removal, which takes
//! portions (`StagedUnlink`). The service runs these with no session behind
//! them: the pipe service has checked who may change the segment.

use crate::namespace::StagedUnlink;
use crate::storage::{BOOT_ROOT, Storage};
use crate::{SET_GID, SET_UID};

/// The directory of the files.
const DIRECTORY: &[u8] = b"/dev/shm";

/// The name of the file of the segment `serial`: `.sysv` and sixteen digits.
pub fn name_of(serial: u64) -> [u8; 21] {
    let mut name = *b".sysv0000000000000000";
    let mut rest = serial;
    for byte in name[5..].iter_mut().rev() {
        *byte = b"0123456789abcdef"[(rest & 15) as usize];
        rest >>= 4;
    }
    name
}

/// The file of the segment `serial` gets this owner and group and the
/// permission bits `mode` (its other bits stay), and loses the set-ID bits
/// when the owner or the group changes, as `chown` does. Whether the file
/// was there to change.
pub fn change(storage: &mut Storage<'_>, serial: u64, uid: u32, gid: u32, mode: u32) -> bool {
    let name = name_of(serial);
    let Ok(dir) = storage.resolve(DIRECTORY) else {
        return false;
    };
    let Ok(token) = storage.lookup(dir, &name) else {
        return false;
    };
    let Ok(node) = storage.node(token) else {
        return false;
    };
    let mut bits = (node.mode & !0o777) | (mode & 0o777);
    if node.uid != uid || node.gid != gid {
        bits &= !(SET_UID | SET_GID);
    }
    storage.set_attributes(token, bits, uid, gid).is_ok()
}

/// The start of the removal of the file of the segment `serial`; None where
/// the file is not there, or the removal cannot be paid for.
pub fn begin_remove(storage: &mut Storage<'_>, serial: u64) -> Option<StagedUnlink> {
    let name = name_of(serial);
    let dir = storage.resolve(DIRECTORY).ok()?;
    StagedUnlink::begin(storage, dir, &name, BOOT_ROOT).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace::UnlinkStep;
    use crate::storage::{ROOT, Root, Token};
    use crate::{DIR, REG, Ram};
    use proto_fs::Timestamp;

    const PAYER: Root = Root {
        id: 5,
        generation: 1,
    };

    fn make(ram: &mut Ram<'_>, parent: Token, name: &[u8], kind: u32, mode: u32) -> Token {
        let reserve = ram
            .storage
            .reserve(PAYER, parent, name, (kind, mode, 100, 100))
            .unwrap();
        ram.storage.commit(reserve).unwrap()
    }

    fn shm(ram: &mut Ram<'_>) -> Token {
        let dev = make(ram, ROOT, b"dev", DIR, 0o755);
        make(ram, dev, b"shm", DIR, 0o1777)
    }

    fn finish(ram: &mut Ram<'_>, mut unlink: StagedUnlink) -> usize {
        for portions in 1..200 {
            match unlink.advance(&mut ram.storage) {
                UnlinkStep::More => {}
                UnlinkStep::Done => return portions,
                UnlinkStep::Refused => panic!("the cleanup was refused"),
            }
        }
        panic!("the removal never ends");
    }

    #[test]
    fn a_name_is_the_serial_in_sixteen_digits() {
        assert_eq!(&name_of(0xabc), b".sysv0000000000000abc");
        assert_eq!(&name_of(u64::MAX), b".sysvffffffffffffffff");
    }

    #[test]
    fn a_job_of_owner_changes_owner_group_and_permission_bits_and_the_set_id_bits_go() {
        let mut ram = Ram::new(Timestamp::ZERO);
        let dir = shm(&mut ram);
        let serial = 0x1234_5678_9abc_def0;
        let file = make(&mut ram, dir, &name_of(serial), REG, 0o4755);
        assert!(change(&mut ram.storage, serial, 200, 300, 0o640));
        let node = ram.storage.node(file).unwrap();
        assert_eq!((node.uid, node.gid, node.mode), (200, 300, 0o640));
        // The owner stays: the set-ID bits stay, the permission bits change.
        let set_id = make(&mut ram, dir, &name_of(7), REG, 0o2755);
        assert!(change(&mut ram.storage, 7, 100, 100, 0o600));
        assert_eq!(ram.storage.node(set_id).unwrap().mode, 0o2600);
        // A file that is not there is no error and changes nothing.
        assert!(!change(&mut ram.storage, 99, 1, 1, 0o600));
    }

    #[test]
    fn the_removal_of_a_file_takes_portions_frees_its_name_and_then_its_pages() {
        let mut ram = Ram::new(Timestamp::ZERO);
        let dir = shm(&mut ram);
        let serial = 0x42;
        let file = make(&mut ram, dir, &name_of(serial), REG, 0o600);
        ram.storage.write(file, PAYER, 0, &[7u8; 3 * 4096]).unwrap();
        let held = ram.storage.usage(PAYER);
        assert!(held.pages >= 3);
        let unlink = begin_remove(&mut ram.storage, serial).expect("the file is there");
        let portions = finish(&mut ram, unlink);
        assert!(portions > 1, "the removal is not one step: {portions}");
        assert!(ram.storage.lookup(dir, &name_of(serial)).is_err());
        // Nothing is held for the removal, and the pages go in the steps of
        // the service's maintenance.
        assert_eq!(ram.storage.preparations_used(), 0);
        for _ in 0..1000 {
            if !ram.storage.reclaim_step() {
                break;
            }
        }
        assert!(ram.storage.usage(PAYER).pages < held.pages);
    }

    #[test]
    fn the_removal_of_a_file_that_is_not_there_holds_nothing() {
        let mut ram = Ram::new(Timestamp::ZERO);
        shm(&mut ram);
        assert!(begin_remove(&mut ram.storage, 5).is_none());
        assert_eq!(ram.storage.preparations_used(), 0);
        // Nor does a removal with no /dev/shm.
        let mut bare = Ram::new(Timestamp::ZERO);
        assert!(begin_remove(&mut bare.storage, 5).is_none());
    }
}
