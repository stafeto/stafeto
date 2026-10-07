// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Test-only observation of actual loading attempts and pending SetId stores.

use crate::loaders::{Loaders, Place, Refused};

pub const ARM: u16 = 0xfff8;
pub const TRACE: u16 = 0xfff9;
pub const CHILD_HANDOFF: u16 = 0xfffa;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Counts {
    pub attempts: u32,
    pub successes: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u32)]
pub enum Terminal {
    #[default]
    Live = 0,
    Aborted = 1,
    Taken = 2,
    Ended = 3,
}

/// One observation per existing record, retained through its loader retirement.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Observation {
    pub ticket: u64,
    pub image: u32,
    pub counts: Counts,
    pub terminal: Terminal,
    corrupted: bool,
}

impl Observation {
    pub fn arm(&mut self, ticket: u64, image: u32) -> Result<(), Refused> {
        if ticket == 0 || image == 0 {
            return Err(Refused);
        }
        if self.ticket == ticket {
            return if self.image == image && self.terminal == Terminal::Live {
                Ok(())
            } else {
                Err(Refused)
            };
        }
        *self = Self {
            ticket,
            image,
            ..Self::default()
        };
        Ok(())
    }

    pub fn matches(&self, ticket: u64, image: u32) -> bool {
        self.ticket == ticket && self.image == image && self.terminal == Terminal::Live
    }
}

/// Count the real call, store through Loaders, then corrupt its accepted reply once.
pub fn set_id<T>(
    loaders: &mut Loaders<T>,
    observation: &mut Observation,
    ticket: u64,
    record: usize,
    image: u32,
    ids: (u32, u32),
) -> Result<bool, Refused> {
    let observed = observation.matches(ticket, image);
    if observed {
        let slot = loaders.of(record).ok_or(Refused)?;
        if loaders.ticket(slot) != ticket {
            return Err(Refused);
        }
        let place = loaders.get_mut(slot).ok_or(Refused)?;
        place.image_probe_counts.attempts = place
            .image_probe_counts
            .attempts
            .checked_add(1)
            .ok_or(Refused)?;
        observation.counts = place.image_probe_counts;
    }
    loaders.set_id(ticket, record, image, ids)?;
    if observed {
        let slot = loaders.of(record).ok_or(Refused)?;
        let place = loaders.get_mut(slot).ok_or(Refused)?;
        place.image_probe_counts.successes += 1;
        observation.counts = place.image_probe_counts;
        if !observation.corrupted {
            observation.corrupted = true;
            return Ok(true);
        }
    }
    Ok(false)
}

pub type StageResult<C> =
    Result<(crate::executable::Staged<C>, bool), crate::executable::Refused<C>>;

/// Observe one genuine atomic Stage store and corrupt its accepted reply once.
/// Checked observation counters are prepaid before the capability/SetId mutation.
pub fn stage_exec<T: crate::executable::ExecHolder>(
    loaders: &mut Loaders<T>,
    observation: &mut Observation,
    record: usize,
    args: proto_process::StageExec,
    cap: T::Cap,
) -> StageResult<T::Cap> {
    use crate::executable::{Refused, Staged};
    let observed = observation.matches(args.ticket, args.image)
        && args.kind == proto_process::ExecKind::Execute;
    let counts = if observed {
        let Some(slot) = loaders.of(record) else {
            return Err(Refused(cap));
        };
        if loaders.ticket(slot) != args.ticket {
            return Err(Refused(cap));
        }
        let place = loaders.get_mut(slot).expect("an exact observed place");
        if place.image != args.image {
            return Err(Refused(cap));
        }
        if place.held.exec_custody().receipt.is_none() {
            let (Some(attempts), Some(successes)) = (
                place.image_probe_counts.attempts.checked_add(1),
                place.image_probe_counts.successes.checked_add(1),
            ) else {
                return Err(Refused(cap));
            };
            Some(Counts {
                attempts,
                successes,
            })
        } else {
            None
        }
    } else {
        None
    };
    let staged = loaders.stage_exec(record, args, cap)?;
    if matches!(staged, Staged::Installed)
        && let Some(counts) = counts
    {
        let slot = loaders.of(record).expect("a staged observed place");
        let place = loaders.get_mut(slot).unwrap();
        let custody = place.held.exec_custody();
        debug_assert_eq!(custody.receipt, Some(args.receipt()));
        debug_assert!(custody.pending_exec.is_some());
        debug_assert_eq!(place.set_id, Some((args.uid, args.gid)));
        place.image_probe_counts = counts;
        observation.counts = counts;
        let corrupted = !observation.corrupted;
        observation.corrupted = true;
        return Ok((staged, corrupted));
    }
    Ok((staged, false))
}

/// Preserve a terminal observation after the actual place and tuple disappear.
pub fn free<T>(
    loaders: &mut Loaders<T>,
    observation: &mut Observation,
    record: usize,
    terminal: Terminal,
) -> Option<Place<T>> {
    let slot = loaders.of(record)?;
    let ticket = loaders.ticket(slot);
    let place = loaders.free(record)?;
    if observation.matches(ticket, place.image) {
        observation.counts = place.image_probe_counts;
        observation.terminal = terminal;
    }
    Some(place)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loaders::Stage;

    fn attempt(loaders: &mut Loaders<()>, image: u32) -> u64 {
        let slot = loaders.take(5, 5, image, ()).unwrap();
        loaders.get_mut(slot).unwrap().stage = Stage::Loading;
        loaders.ticket(slot)
    }

    #[test]
    fn corruption_follows_actual_store_and_counts_real_repeated_attempt() {
        let mut loaders = Loaders::new();
        let ticket = attempt(&mut loaders, 2);
        let mut observation = Observation::default();
        observation.arm(ticket, 2).unwrap();
        assert_eq!(
            set_id(&mut loaders, &mut observation, ticket, 5, 2, (37, 43)),
            Ok(true)
        );
        let slot = loaders.of(5).unwrap();
        assert_eq!(loaders.get(slot).unwrap().set_id, Some((37, 43)));
        assert_eq!(
            observation.counts,
            Counts {
                attempts: 1,
                successes: 1
            }
        );
        observation.arm(ticket, 2).unwrap();
        assert!(observation.corrupted);
        assert_eq!(
            observation.counts,
            Counts {
                attempts: 1,
                successes: 1
            }
        );
        assert_eq!(
            set_id(&mut loaders, &mut observation, ticket, 5, 2, (0, 0)),
            Err(Refused)
        );
        assert_eq!(
            observation.counts,
            Counts {
                attempts: 2,
                successes: 1
            }
        );
        assert_eq!(loaders.get(slot).unwrap().set_id, Some((37, 43)));
    }

    #[test]
    fn actual_abort_clears_tuple_and_terminal_ticket_cannot_arm_next_attempt() {
        let mut loaders = Loaders::new();
        let ticket = attempt(&mut loaders, 2);
        let mut observation = Observation::default();
        observation.arm(ticket, 2).unwrap();
        set_id(&mut loaders, &mut observation, ticket, 5, 2, (37, 43)).unwrap();
        let removed = free(&mut loaders, &mut observation, 5, Terminal::Aborted).unwrap();
        assert_eq!(removed.set_id, Some((37, 43)));
        assert_eq!(loaders.of(5), None);
        assert_eq!(loaders.count(), 0);
        assert_eq!(observation.terminal, Terminal::Aborted);
        assert_eq!(
            observation.counts,
            Counts {
                attempts: 1,
                successes: 1
            }
        );
        let next = attempt(&mut loaders, 3);
        assert_ne!(next, ticket);
        assert_eq!(loaders.get(loaders.of(5).unwrap()).unwrap().set_id, None);
        assert_eq!(
            set_id(&mut loaders, &mut observation, ticket, 5, 2, (37, 43)),
            Err(Refused)
        );
        assert_eq!(
            observation.counts,
            Counts {
                attempts: 1,
                successes: 1
            }
        );
        observation.arm(next, 3).unwrap();
        assert_eq!(observation.counts, Counts::default());
    }

    #[test]
    fn unarmed_real_store_keeps_normal_reply_and_take_removes_actual_place() {
        let mut loaders = Loaders::new();
        let ticket = attempt(&mut loaders, 2);
        let mut observation = Observation::default();
        assert_eq!(
            set_id(&mut loaders, &mut observation, ticket, 5, 2, (37, 43)),
            Ok(false)
        );
        assert_eq!(
            loaders.get(loaders.of(5).unwrap()).unwrap().set_id,
            Some((37, 43))
        );
        loaders.loaded(5).unwrap();
        assert_eq!(loaders.commit(5), Ok(Some((37, 43))));
        free(&mut loaders, &mut observation, 5, Terminal::Taken).unwrap();
        assert_eq!(loaders.of(5), None);
        assert_eq!(observation, Observation::default());
    }

    #[test]
    fn foreign_attempt_does_not_consume_armed_injection() {
        let mut loaders = Loaders::new();
        let ticket = attempt(&mut loaders, 2);
        let mut observation = Observation::default();
        observation.arm(ticket, 2).unwrap();
        assert_eq!(
            set_id(&mut loaders, &mut observation, ticket, 4, 2, (37, 43)),
            Err(Refused)
        );
        assert_eq!(observation.counts, Counts::default());
        assert_eq!(
            set_id(&mut loaders, &mut observation, ticket, 5, 2, (37, 43)),
            Ok(true)
        );
    }

    #[test]
    fn real_record_credentials_and_active_image_survive_store_and_abort() {
        use crate::records::{Join, Records, State};
        use proto_process::Credentials;
        let mut records = Records::<u32>::new();
        let label = records.next_label().unwrap();
        let credentials = Credentials {
            uid: 7,
            euid: 11,
            suid: 11,
            gid: 8,
            egid: 12,
            sgid: 12,
        };
        let record = records.insert(label, 77, None, credentials, 40, Join::NewSession);
        records.get_mut(record).unwrap().state = State::Alive;
        let active_image = records.get(record).unwrap().image;
        let mut loaders = Loaders::new();
        let slot = loaders.take(record, record, active_image + 1, ()).unwrap();
        loaders.get_mut(slot).unwrap().stage = Stage::Loading;
        let ticket = loaders.ticket(slot);
        let observation = &mut records.get_mut(record).unwrap().image_probe;
        observation.arm(ticket, active_image + 1).unwrap();
        assert_eq!(
            set_id(
                &mut loaders,
                observation,
                ticket,
                record,
                active_image + 1,
                (37, 43)
            ),
            Ok(true)
        );
        assert_eq!(loaders.get(slot).unwrap().set_id, Some((37, 43)));
        assert_eq!(records.get(record).unwrap().credentials, credentials);
        let observation = &mut records.get_mut(record).unwrap().image_probe;
        free(&mut loaders, observation, record, Terminal::Aborted).unwrap();
        let old = records.get(record).unwrap();
        assert_eq!(old.image, active_image);
        assert_eq!(old.credentials, credentials);
        assert_eq!(old.process, 77);
        assert_eq!(old.state, State::Alive);
        assert_eq!(loaders.of(record), None);
    }

    #[test]
    fn observation_layout_and_end_retirement_are_bounded() {
        assert_eq!(core::mem::size_of::<Observation>(), 32);
        assert_eq!(core::mem::size_of::<Counts>(), 8);
        let mut loaders = Loaders::new();
        let ticket = attempt(&mut loaders, 2);
        let mut observation = Observation::default();
        observation.arm(ticket, 2).unwrap();
        set_id(&mut loaders, &mut observation, ticket, 5, 2, (37, 43)).unwrap();
        free(&mut loaders, &mut observation, 5, Terminal::Ended).unwrap();
        assert_eq!(observation.terminal, Terminal::Ended);
        assert_eq!(observation.ticket, ticket);
        assert_eq!(loaders.count(), 0);
        assert!(free(&mut loaders, &mut observation, 5, Terminal::Aborted).is_none());
        assert_eq!(observation.terminal, Terminal::Ended);
    }
    struct ImageHeld(crate::executable::ExecCustody<u32>);
    impl crate::executable::ExecHolder for ImageHeld {
        type Cap = u32;
        fn exec_custody(&mut self) -> &mut crate::executable::ExecCustody<u32> {
            &mut self.0
        }
        fn fork(&self) -> bool {
            false
        }
    }
    fn stage_attempt(
        loaders: &mut Loaders<ImageHeld>,
        record: usize,
        image: u32,
    ) -> proto_process::StageExec {
        let slot = loaders
            .take(
                record,
                record,
                image,
                ImageHeld(crate::executable::ExecCustody::new()),
            )
            .unwrap();
        loaders.get_mut(slot).unwrap().stage = Stage::Loading;
        proto_process::StageExec {
            pid: record as u32 + 256,
            image,
            ticket: loaders.ticket(slot),
            uid: 37,
            gid: 43,
            kind: proto_process::ExecKind::Execute,
            label: 91,
        }
    }

    #[test]
    fn stage_probe_counts_only_actual_atomic_store_and_abort_preserves_old_record() {
        use crate::{
            executable::{Refused as CapRefused, Staged},
            records::{Join, Records, State},
        };
        let mut records = Records::<u32, u32>::with_exec_custody();
        let label = records.next_label().unwrap();
        let credentials = proto_process::Credentials {
            uid: 7,
            euid: 11,
            suid: 11,
            gid: 8,
            egid: 12,
            sgid: 12,
        };
        let record = records.insert(label, 77, None, credentials, 40, Join::NewSession);
        records.get_mut(record).unwrap().state = State::Alive;
        records.get_mut(record).unwrap().active_exec = Some(99);
        let mut loaders = Loaders::new();
        let args = stage_attempt(&mut loaders, record, 2);
        let observation = &mut records.get_mut(record).unwrap().image_probe;
        observation.arm(args.ticket, args.image).unwrap();
        assert!(matches!(
            stage_exec(&mut loaders, observation, record, args, 11),
            Ok((Staged::Installed, true))
        ));
        let slot = loaders.of(record).unwrap();
        let actual = loaders.get(slot).unwrap();
        assert_eq!(actual.set_id, Some((37, 43)));
        assert_eq!(actual.held.0.pending_exec, Some(11));
        assert_eq!(actual.held.0.receipt, Some(args.receipt()));
        assert_eq!(
            observation.counts,
            Counts {
                attempts: 1,
                successes: 1
            }
        );
        assert!(matches!(
            stage_exec(&mut loaders, observation, record, args, 12),
            Ok((Staged::Replay(12), false))
        ));
        assert_eq!(
            observation.counts,
            Counts {
                attempts: 1,
                successes: 1
            }
        );
        let changed = proto_process::StageExec { uid: 38, ..args };
        assert!(matches!(
            stage_exec(&mut loaders, observation, record, changed, 13),
            Err(CapRefused(13))
        ));
        assert_eq!(
            observation.counts,
            Counts {
                attempts: 1,
                successes: 1
            }
        );
        // The original fixture's genuine legacy repeat observes the installed tuple.
        assert_eq!(
            set_id(
                &mut loaders,
                observation,
                args.ticket,
                record,
                args.image,
                (37, 43)
            ),
            Err(Refused)
        );
        assert_eq!(
            observation.counts,
            Counts {
                attempts: 2,
                successes: 1
            }
        );
        let actual = loaders.get(slot).unwrap();
        assert_eq!(actual.set_id, Some((37, 43)));
        assert_eq!(actual.held.0.pending_exec, Some(11));
        let removed = free(&mut loaders, observation, record, Terminal::Aborted).unwrap();
        assert_eq!(removed.set_id, Some((37, 43)));
        assert_eq!(removed.held.0.pending_exec, Some(11));
        assert!(loaders.of(record).is_none());
        assert_eq!(observation.terminal, Terminal::Aborted);
        let old = records.get(record).unwrap();
        assert_eq!(old.credentials, credentials);
        assert_eq!(
            (old.image, old.process, old.active_exec, old.state),
            (1, 77, Some(99), State::Alive)
        );
        let next = stage_attempt(&mut loaders, record, 3);
        assert_ne!(next.ticket, args.ticket);
        let observation = &mut records.get_mut(record).unwrap().image_probe;
        assert!(matches!(
            stage_exec(&mut loaders, observation, record, args, 14),
            Err(CapRefused(14))
        ));
        observation.arm(next.ticket, 3).unwrap();
        assert_eq!(observation.counts, Counts::default());
        assert_eq!(
            loaders.get(loaders.of(record).unwrap()).unwrap().set_id,
            None
        );
        assert!(matches!(
            stage_exec(&mut loaders, observation, record, next, 15),
            Ok((Staged::Installed, true))
        ));
    }

    #[test]
    fn stage_probe_counter_preflight_and_ready_replay_preserve_existing_authority() {
        use crate::executable::{Refused as CapRefused, Staged};
        let mut loaders = Loaders::new();
        let args = stage_attempt(&mut loaders, 5, 2);
        let slot = loaders.of(5).unwrap();
        let mut observation = Observation::default();
        observation.arm(args.ticket, 2).unwrap();
        for exhausted in [
            Counts {
                attempts: u32::MAX,
                successes: 0,
            },
            Counts {
                attempts: 0,
                successes: u32::MAX,
            },
        ] {
            loaders.get_mut(slot).unwrap().image_probe_counts = exhausted;
            assert!(matches!(
                stage_exec(&mut loaders, &mut observation, 5, args, 17),
                Err(CapRefused(17))
            ));
            let place = loaders.get(slot).unwrap();
            assert_eq!(place.set_id, None);
            assert_eq!(place.held.0.pending_exec, None);
            assert_eq!(place.held.0.receipt, None);
            assert!(!observation.corrupted);
        }
        loaders.get_mut(slot).unwrap().image_probe_counts = Counts::default();
        assert!(matches!(
            stage_exec(&mut loaders, &mut observation, 5, args, 18),
            Ok((Staged::Installed, true))
        ));
        loaders.loaded(5).unwrap();
        assert_eq!(loaders.commit(5), Ok(Some((37, 43))));
        assert_eq!(loaders.get(slot).unwrap().set_id, None);
        loaders.get_mut(slot).unwrap().image_probe_counts = Counts {
            attempts: u32::MAX,
            successes: u32::MAX,
        };
        observation.counts = loaders.get(slot).unwrap().image_probe_counts;
        assert!(matches!(
            stage_exec(&mut loaders, &mut observation, 5, args, 19),
            Ok((Staged::Replay(19), false))
        ));
        assert_eq!(
            observation.counts,
            Counts {
                attempts: u32::MAX,
                successes: u32::MAX
            }
        );
        assert_eq!(loaders.take_pending_exec(5), Some(18));
        free(&mut loaders, &mut observation, 5, Terminal::Taken).unwrap();
        assert!(matches!(
            stage_exec(&mut loaders, &mut observation, 5, args, 20),
            Err(CapRefused(20))
        ));
        assert_eq!(observation.terminal, Terminal::Taken);
        let next = stage_attempt(&mut loaders, 5, 3);
        let mut unarmed = Observation::default();
        assert!(matches!(
            stage_exec(&mut loaders, &mut unarmed, 5, next, 21),
            Ok((Staged::Installed, false))
        ));
        assert_eq!(unarmed, Observation::default());
        assert_eq!(
            loaders.get(loaders.of(5).unwrap()).unwrap().set_id,
            Some((37, 43))
        );
    }
}
