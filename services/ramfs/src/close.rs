// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! An exact numeric-close receipt precedes descriptor reuse and physical I/O cleanup.

use crate::{
    Fds, Ram, TentativeOpen,
    locks::{Owner, simple::SimpleLocks},
    storage::Token,
};
use proto_fs::{CloseEvent, OPEN_DESCRIPTION_MASK, OPEN_DESCRIPTION_SHIFT, OPEN_FD_MASK};

impl Ram<'_> {
    /// Session disappearance retires true OFD references without a PID close event.
    pub fn detach_session_descriptions(
        &mut self,
        fds: &mut Fds,
        _locks: &mut SimpleLocks,
    ) -> usize {
        let mut detached = 0;
        for slot in 0..crate::OPEN_MAX {
            if fds.live_fds & (1 << slot) == 0 {
                continue;
            }
            let fd = slot as u32 + 3;
            let description = self
                .description_token(fds, fd)
                .expect("published session description");
            let close = self
                .detach_descriptor(fds, TentativeOpen { fd, description })
                .expect("exact session descriptor")
                .expect("published true reference");
            // Logical reference death is immediate. The bounded inode sweep
            // reclaims invisible OFD records without walking 32 lock lists here.
            let _ = close;
            detached += 1;
        }
        detached
    }

    /// Apply one genuine alias close exactly once while preserving physical custody.
    /// A fresh event identifies its validated inode; exact replay has no new effect.
    pub fn close_event(
        &mut self,
        fds: &mut Fds,
        locks: &mut SimpleLocks,
        event: CloseEvent,
    ) -> Result<Option<Token>, u32> {
        let index = event.validate()?;
        if let Some(previous) = fds.close_receipts[index] {
            if previous.key.generation == event.key.generation {
                return if previous == event {
                    Ok(None)
                } else {
                    Err(proto_fs::INVALID_ARGUMENT)
                };
            }
            if previous.key.generation > event.key.generation {
                return Err(proto_fs::OPEN_RETIRED);
            }
        }
        let held = TentativeOpen {
            fd: event.packed & OPEN_FD_MASK,
            description: Token {
                slot: ((event.packed & OPEN_DESCRIPTION_MASK) >> OPEN_DESCRIPTION_SHIFT) as u16,
                generation: event.description_generation,
            },
        };
        let inode = if event.last_alias {
            self.live_description(fds, held)?.0
        } else {
            // A final alias event may arrive first; other Closing records still
            // retain this exact physical description until their own replies.
            if self.capture_description(fds, held.fd)?.0 != held {
                return Err(proto_fs::BAD_FD);
            }
            self.description_node(fds, held.fd, held.description.generation)?
        };
        let final_ofd = if event.last_alias {
            let detached = self
                .detach_descriptor(fds, held)?
                .expect("preflighted real descriptor");
            assert_eq!(detached.inode, inode);
            detached.last_fd.then_some(Owner::Description {
                slot: held.description.slot,
                generation: held.description.generation,
            })
        } else {
            None
        };
        // A final close may revoke both owner classes on the same full inode.
        // Retire them in one bounded traversal, after exact descriptor preflight.
        locks
            .close_owners(
                &mut self.storage,
                inode,
                fds.binding.close_pid().map(Owner::Process),
                final_ofd,
            )
            .expect("validated exact numeric close");
        fds.close_receipts[index] = Some(event);
        Ok(Some(inode))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::locks::{
        Kind, Range,
        simple::{Command, Request, SweepCursor},
    };
    use crate::storage::Root;
    use std::boxed::Box;

    fn locks() -> Box<SimpleLocks> {
        let mut out = Box::<SimpleLocks>::new_uninit();
        // SAFETY: exclusive aligned allocation initialized directly.
        unsafe {
            SimpleLocks::initialize_at(out.as_mut_ptr());
            out.assume_init()
        }
    }
    fn who() -> proto_process::WhoReply {
        proto_process::WhoReply {
            pid: 257,
            credentials: proto_process::Credentials::NOBODY,
            generation: 1,
            loader: None,
            index: 1,
            ctty: None,
            image: 1,
            groups: proto_process::Groups::EMPTY,
            limits: proto_process::ResourceLimits::initial(2 * 1024 * 1024),
            root: proto_process::ExpenditureRoot {
                pid: 10,
                generation: 1,
            },
        }
    }
    fn fds() -> Fds {
        Fds {
            root: Root {
                id: 10,
                generation: 1,
            },
            binding: crate::authority::Binding::Active(who()),
            ..Fds::default()
        }
    }
    fn event(ram: &Ram<'_>, fds: &Fds, fd: u32, slot: u32, last_alias: bool) -> CloseEvent {
        let held = ram.capture_description(fds, fd).unwrap().0;
        CloseEvent {
            key: proto_fs::CloseKey {
                slot,
                generation: 1,
            },
            packed: fd | u32::from(held.description.slot) << OPEN_DESCRIPTION_SHIFT,
            description_generation: held.description.generation,
            last_alias,
        }
    }
    fn set(ram: &mut Ram<'_>, locks: &mut SimpleLocks, inode: Token, owner: Owner, start: i64) {
        locks
            .set(
                &mut ram.storage,
                Root {
                    id: 10,
                    generation: 1,
                },
                Request {
                    inode,
                    owner,
                    root: 0,
                    range: Range::relative(0, start, 1).unwrap(),
                    command: Command::Set(Some(Kind::Read)),
                },
                |_| true,
            )
            .unwrap();
    }
    #[test]
    fn final_close_removes_full_mixed_pid_and_ofd_list_in_one_revision() {
        let mut ram = Ram::default();
        let mut fds = fds();
        let mut locks = locks();
        let fd = ram
            .open(&mut fds, "/tmp/probe", proto_fs::READ_ONLY)
            .unwrap();
        let held = ram.capture_description(&fds, fd).unwrap().0;
        let inode = ram.live_description(&fds, held).unwrap().0;
        let ofd = Owner::Description {
            slot: held.description.slot,
            generation: held.description.generation,
        };
        for index in 0..32 {
            set(&mut ram, &mut locks, inode, Owner::Process(257), 4 * index);
            set(&mut ram, &mut locks, inode, ofd, 4 * index + 2);
        }
        assert_eq!(locks.count(inode), 64);
        let revision = locks.revision(inode);
        let close = event(&ram, &fds, fd, 48, true);
        assert_eq!(
            ram.close_event(&mut fds, &mut locks, close),
            Ok(Some(inode))
        );
        assert_eq!(locks.count(inode), 0);
        assert_eq!(locks.revision(inode), revision + 1);
        assert!(!ram.lock_parts().1.live(held.description));
        assert_eq!(ram.close_event(&mut fds, &mut locks, close), Ok(None));
        assert_eq!(locks.revision(inode), revision + 1);
    }
    #[test]
    fn every_numeric_alias_close_removes_pid_locks_and_exact_replay_preserves_relock() {
        let mut ram = Ram::default();
        let mut fds = fds();
        let mut locks = locks();
        let fd = ram
            .open(&mut fds, "/tmp/probe", proto_fs::READ_ONLY)
            .unwrap();
        let held = ram.capture_description(&fds, fd).unwrap().0;
        let inode = ram.live_description(&fds, held).unwrap().0;
        let ofd = Owner::Description {
            slot: held.description.slot,
            generation: held.description.generation,
        };
        set(&mut ram, &mut locks, inode, Owner::Process(257), 0);
        set(&mut ram, &mut locks, inode, Owner::Process(258), 2);
        set(&mut ram, &mut locks, inode, ofd, 4);
        let close = event(&ram, &fds, fd, 48, false);
        assert_eq!(
            ram.close_event(&mut fds, &mut locks, close),
            Ok(Some(inode))
        );
        assert_eq!(locks.count(inode), 2);
        assert!(ram.live_description(&fds, held).is_ok());
        set(&mut ram, &mut locks, inode, Owner::Process(257), 0);
        assert_eq!(ram.close_event(&mut fds, &mut locks, close), Ok(None));
        assert_eq!(locks.count(inode), 3);
        assert_eq!(
            ram.close_event(
                &mut fds,
                &mut locks,
                CloseEvent {
                    last_alias: true,
                    ..close
                }
            ),
            Err(proto_fs::INVALID_ARGUMENT)
        );
        assert_eq!(locks.count(inode), 3);
    }
    #[test]
    fn reordered_final_alias_preserves_custody_and_late_numeric_close_revokes_new_pid_lock() {
        let mut ram = Ram::default();
        let mut fds = fds();
        let mut locks = locks();
        let fd = ram
            .open(&mut fds, "/tmp/probe", proto_fs::READ_ONLY)
            .unwrap();
        let inode = ram
            .live_description(&fds, ram.capture_description(&fds, fd).unwrap().0)
            .unwrap()
            .0;
        let early = event(&ram, &fds, fd, 48, false);
        let last = event(&ram, &fds, fd, 49, true);
        ram.close_event(&mut fds, &mut locks, last).unwrap();
        let replacement = ram
            .open(&mut fds, "/tmp/probe", proto_fs::READ_ONLY)
            .unwrap();
        assert_ne!(replacement, fd, "physical custody survives logical close");
        set(&mut ram, &mut locks, inode, Owner::Process(257), 0);
        ram.close_event(&mut fds, &mut locks, early).unwrap();
        assert_eq!(locks.count(inode), 0);
        set(&mut ram, &mut locks, inode, Owner::Process(257), 0);
        assert_eq!(ram.close_event(&mut fds, &mut locks, early), Ok(None));
        assert_eq!(locks.count(inode), 1);
    }
    #[test]
    fn ofd_lock_survives_parent_close_until_last_real_child_reference() {
        let mut ram = Ram::default();
        let mut parent = fds();
        let mut locks = locks();
        let fd = ram
            .open(&mut parent, "/tmp/probe", proto_fs::READ_ONLY)
            .unwrap();
        let held = ram.capture_description(&parent, fd).unwrap().0;
        let inode = ram.live_description(&parent, held).unwrap().0;
        let mut child = ram.clone_fds(&parent, &[fd]).unwrap();
        child.binding = crate::authority::Binding::Inherited(who());
        set(
            &mut ram,
            &mut locks,
            inode,
            Owner::Description {
                slot: held.description.slot,
                generation: held.description.generation,
            },
            2,
        );
        let close = event(&ram, &parent, fd, 48, true);
        ram.close_event(&mut parent, &mut locks, close).unwrap();
        assert_eq!(locks.count(inode), 1);
        assert!(ram.lock_parts().1.live(held.description));
        set(&mut ram, &mut locks, inode, Owner::Process(257), 0);
        let close = event(&ram, &child, fd, 48, true);
        ram.close_event(&mut child, &mut locks, close).unwrap();
        assert_eq!(
            locks.count(inode),
            1,
            "inherited child close preserves parent's PID lock"
        );
        assert!(!ram.lock_parts().1.live(held.description));
    }
    #[test]
    fn session_departure_hides_ofd_immediately_then_sweeps_without_pid_close() {
        let mut ram = Ram::default();
        let mut fds = fds();
        let mut locks = locks();
        let fd = ram
            .open(&mut fds, "/tmp/probe", proto_fs::READ_ONLY)
            .unwrap();
        let held = ram.capture_description(&fds, fd).unwrap().0;
        let inode = ram.live_description(&fds, held).unwrap().0;
        set(&mut ram, &mut locks, inode, Owner::Process(257), 0);
        set(
            &mut ram,
            &mut locks,
            inode,
            Owner::Description {
                slot: held.description.slot,
                generation: held.description.generation,
            },
            2,
        );
        assert_eq!(ram.detach_session_descriptions(&mut fds, &mut locks), 1);
        let (storage, descriptions) = ram.lock_parts();
        assert!(!descriptions.live(held.description));
        assert!(!descriptions.source_live(&fds, held));
        let mut cursor = SweepCursor {
            inode: inode.slot as usize,
        };
        let result = locks.sweep(storage, &mut cursor, 1, |owner| match owner {
            Owner::Process(_) => true,
            Owner::Description { slot, generation } => {
                descriptions.live(Token { slot, generation })
            }
        });
        assert_eq!(result.visited, 1);
        assert_eq!(result.removed, 1);
        assert_eq!(
            locks.count(inode),
            1,
            "old exec session death preserves stable PID locks"
        );
    }
}
