// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! An exact numeric-close receipt precedes descriptor reuse and physical I/O cleanup.

use crate::{
    Fds, Ram, TentativeOpen,
    locks::{Owner, service::LockService},
    storage::Token,
};
use proto_fs::{CloseEvent, OPEN_DESCRIPTION_MASK, OPEN_DESCRIPTION_SHIFT, OPEN_FD_MASK};

impl Ram<'_> {
    /// Session disappearance retires true OFD references without a PID close event.
    pub fn detach_session_descriptions(&mut self, fds: &mut Fds, locks: &mut LockService) -> usize {
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
            if close.last_fd {
                locks
                    .close(
                        close.inode,
                        Owner::Description {
                            slot: description.slot,
                            generation: description.generation,
                        },
                    )
                    .expect("exact departed OFD");
            }
            detached += 1;
        }
        detached
    }

    /// Apply one genuine alias close exactly once while preserving physical custody.
    pub fn close_event(
        &mut self,
        fds: &mut Fds,
        locks: &mut LockService,
        event: CloseEvent,
    ) -> Result<(), u32> {
        let index = event.validate()?;
        if let Some(previous) = fds.close_receipts[index] {
            if previous.key.generation == event.key.generation {
                return if previous == event {
                    Ok(())
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
        if let Some(pid) = fds.binding.close_pid() {
            locks
                .close(inode, Owner::Process(pid))
                .expect("validated exact PID close");
        }
        if event.last_alias {
            let detached = self
                .detach_descriptor(fds, held)?
                .expect("preflighted real descriptor");
            assert_eq!(detached.inode, inode);
            if detached.last_fd {
                locks
                    .close(
                        inode,
                        Owner::Description {
                            slot: held.description.slot,
                            generation: held.description.generation,
                        },
                    )
                    .expect("validated exact OFD close");
            }
        }
        fds.close_receipts[index] = Some(event);
        Ok(())
    }
}
