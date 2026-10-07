// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! One paid path job advances through creation, descriptor prepayment and publication.
//! The service validates its exact session, identity stamp and intent before each effect.

use crate::authority::Identity;
use crate::resolve::ResultProof;
use crate::storage::{NONE, Reservation};
use crate::{Fds, REG, Ram, TentativeOpen};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    None,
    Created,
    Truncated,
}
#[derive(Clone, Copy, Debug)]
pub enum Phase {
    Resolving,
    Canceled {
        effect: Effect,
    },
    Reserved(Reservation),
    Prepared {
        creation: Option<Reservation>,
        held: TentativeOpen,
    },
    Committed {
        held: TentativeOpen,
        effect: Effect,
    },
}
#[derive(Clone, Copy, Debug)]
pub struct Journal {
    pub flags: u32,
    pub mode: u32,
    pub umask: u32,
    pub phase: Phase,
}
impl Journal {
    pub fn new(flags: u32, mode: u32, umask: u32) -> Result<Self, u32> {
        let allowed = 3
            | proto_fs::DIRECTORY_ONLY
            | proto_fs::CHANGES
            | proto_fs::CREATE
            | proto_fs::EXCLUSIVE
            | proto_fs::TRUNCATE
            | proto_fs::APPEND
            | proto_fs::NO_FOLLOW;
        if flags & !allowed != 0 || flags & 3 == 3 {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        if flags & proto_fs::CHANGES != 0
            && flags
                & (proto_fs::CREATE
                    | proto_fs::EXCLUSIVE
                    | proto_fs::TRUNCATE
                    | proto_fs::APPEND
                    | proto_fs::NO_FOLLOW)
                != 0
        {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        Ok(Self {
            flags,
            mode,
            umask,
            phase: Phase::Resolving,
        })
    }
    /// A missing final edge first acquires a reserve. Its fd is prepaid on the next step.
    pub fn prepare(
        &mut self,
        ram: &mut Ram<'_>,
        fds: &mut Fds,
        proof: ResultProof<'_>,
        identity: Identity,
        charge: &mut u16,
    ) -> Result<bool, u32> {
        match self.phase {
            Phase::Canceled { .. } => Err(proto_fs::STALE_PROOF),
            Phase::Committed { held, .. } | Phase::Prepared { held, .. } => {
                ram.validate_tentative(fds, held)?;
                Ok(true)
            }
            Phase::Reserved(r) => {
                self.validate_creation(ram, fds, r, &proof, identity)?;
                let held = ram.prepare_open_token(fds, r.token, self.flags, identity, Some(r))?;
                self.phase = Phase::Prepared {
                    creation: Some(r),
                    held,
                };
                Ok(true)
            }
            Phase::Resolving => {
                if let Some(token) = proof.target {
                    let held = ram.prepare_open_token(fds, token, self.flags, identity, None)?;
                    self.phase = Phase::Prepared {
                        creation: None,
                        held,
                    };
                    return Ok(true);
                }
                if self.flags & proto_fs::CHANGES != 0 {
                    return Err(proto_fs::INVALID_ARGUMENT);
                }
                if self.flags & proto_fs::CREATE == 0 {
                    return Err(proto_fs::NO_ENTRY);
                }
                if self.flags & proto_fs::DIRECTORY_ONLY != 0 {
                    return Err(proto_fs::NOT_DIRECTORY);
                }
                let parent = ram.storage.node(proof.parent)?;
                if !identity.permits(parent, 3) {
                    return Err(proto_fs::ACCESS_DENIED);
                }
                let attributes = identity.creation(parent, REG, self.mode, self.umask);
                let r = ram.storage.reserve_paid(
                    fds.root,
                    proof.parent,
                    proof.leaf,
                    attributes,
                    charge,
                )?;
                self.phase = Phase::Reserved(r);
                Ok(false)
            }
        }
    }
    /// Only a first creation or regular-file truncation consumes a timestamp.
    pub fn needs_time(&self, ram: &Ram<'_>, fds: &Fds) -> Result<bool, u32> {
        match self.phase {
            Phase::Prepared {
                creation: Some(_), ..
            } => Ok(true),
            Phase::Prepared { held, .. } if self.flags & proto_fs::TRUNCATE != 0 => {
                let token = ram.validate_tentative(fds, held)?;
                Ok(ram.storage.node(token)?.kind == REG)
            }
            _ => Ok(false),
        }
    }
    /// The caller validates owner, identity stamp and intent before every entry.
    /// A committed replay uses its exact descriptor and remains independent of path epoch.
    pub fn commit(
        &mut self,
        ram: &mut Ram<'_>,
        fds: &mut Fds,
        proof: Option<ResultProof<'_>>,
        identity: Identity,
        charge: &mut u16,
        now: proto_fs::Timestamp,
    ) -> Result<TentativeOpen, u32> {
        if let Phase::Committed { held, .. } = self.phase {
            ram.validate_tentative(fds, held)?;
            return Ok(held);
        }
        if matches!(self.phase, Phase::Canceled { .. }) {
            return Err(proto_fs::STALE_PROOF);
        }
        let Phase::Prepared { creation, held } = self.phase else {
            return Err(proto_fs::RESOLVING);
        };
        let proof = proof.ok_or(proto_fs::STALE_PROOF)?;
        let target = ram.validate_tentative(fds, held)?;
        let effect = if let Some(r) = creation {
            self.validate_creation(ram, fds, r, &proof, identity)?;
            if r.token != target {
                return Err(proto_fs::STALE_PROOF);
            }
            ram.storage.commit_keep_charge(r)?;
            ram.storage
                .node_mut(r.token)
                .expect("published creation")
                .times = [now; 3];
            let parent = ram
                .storage
                .node_mut(proof.parent)
                .expect("retained creation parent");
            parent.times[1] = now;
            parent.times[2] = now;
            *charge = r.charge();
            Effect::Created
        } else {
            if proof.target != Some(target) {
                return Err(proto_fs::STALE_PROOF);
            }
            let node = ram.storage.node(target)?;
            let bits = match self.flags & 3 {
                proto_fs::READ_ONLY => 4,
                proto_fs::WRITE_ONLY => 2,
                _ => 6,
            };
            if !identity.permits(node, bits) {
                return Err(proto_fs::ACCESS_DENIED);
            }
            if self.flags & proto_fs::TRUNCATE != 0 && node.kind == REG {
                ram.storage.truncate_zero(target, now)?;
                ram.storage
                    .node_mut(target)
                    .expect("retained truncate target")
                    .mode &= !(crate::SET_UID | crate::SET_GID);
                Effect::Truncated
            } else {
                Effect::None
            }
        };
        self.phase = Phase::Committed { held, effect };
        Ok(held)
    }
    fn validate_creation(
        &self,
        ram: &Ram<'_>,
        fds: &Fds,
        r: Reservation,
        proof: &ResultProof<'_>,
        identity: Identity,
    ) -> Result<(), u32> {
        if proof.target.is_some() || proof.trailing_slash {
            return Err(proto_fs::STALE_PROOF);
        }
        ram.storage
            .reserved_edge(r, fds.root, proof.parent, proof.leaf)?;
        if !identity.permits(ram.storage.node(proof.parent)?, 3) {
            return Err(proto_fs::ACCESS_DENIED);
        }
        Ok(())
    }
    /// Reset an unpublished phase while retaining the job admission.
    pub fn reset_unpublished(
        &mut self,
        ram: &mut Ram<'_>,
        fds: &mut Fds,
        charge: &mut u16,
    ) -> Result<(), u32> {
        if matches!(self.phase, Phase::Committed { .. } | Phase::Canceled { .. }) {
            return Err(proto_fs::STALE_PROOF);
        }
        self.cancel(ram, fds, charge)?;
        self.phase = Phase::Resolving;
        Ok(())
    }
    /// Cancel the exact fd ownership and retain a terminal operation outcome.
    /// Cancel one descriptor or reservation per retained cleanup visit.
    pub fn cancel_step(
        &mut self,
        ram: &mut Ram<'_>,
        fds: &mut Fds,
        charge: &mut u16,
    ) -> Result<bool, u32> {
        if let Phase::Prepared {
            creation: Some(creation),
            held,
        } = self.phase
        {
            ram.cancel_open(fds, held)?;
            self.phase = Phase::Reserved(creation);
            return Ok(false);
        }
        let done = matches!(self.phase, Phase::Canceled { .. } | Phase::Resolving);
        self.cancel(ram, fds, charge)?;
        Ok(done)
    }

    /// A committed CREATE/TRUNC remains observable after its tentative fd is canceled.
    pub fn cancel(
        &mut self,
        ram: &mut Ram<'_>,
        fds: &mut Fds,
        charge: &mut u16,
    ) -> Result<Effect, u32> {
        let phase = self.phase;
        let mut effect = Effect::None;
        match phase {
            Phase::Canceled { effect } => return Ok(effect),
            Phase::Resolving => {}
            Phase::Reserved(r) => {
                ram.storage.cancel_keep_charge(r)?;
                *charge = r.charge();
            }
            Phase::Prepared { creation, held } => {
                ram.cancel_open(fds, held)?;
                if let Some(r) = creation {
                    ram.storage.cancel_keep_charge(r)?;
                    *charge = r.charge();
                }
            }
            Phase::Committed {
                held,
                effect: committed,
            } => {
                ram.cancel_open(fds, held)?;
                effect = committed;
            }
        }
        debug_assert_ne!(*charge, NONE);
        self.phase = Phase::Canceled { effect };
        Ok(effect)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::{Intent, Progress, Resolve};
    use crate::storage::{ROOT, Root, Token};
    use proto_process::Groups;

    const OWNER: Identity = Identity {
        uid: 0,
        gid: 0,
        groups: Groups::EMPTY,
    };
    const ROOT_ACCOUNT: Root = Root {
        id: 700,
        generation: 1,
    };
    fn ready(ram: &mut Ram<'_>, path: &[u8], flags: u32) -> Resolve {
        let mut resolver =
            Resolve::with_intent(&mut ram.storage, path, ROOT, OWNER, Intent::Open { flags })
                .unwrap();
        for _ in 0..2000 {
            if resolver.step(&mut ram.storage, OWNER).unwrap() != Progress::More {
                return resolver;
            }
        }
        panic!("resolver did not finish");
    }
    fn proof<'a>(ram: &Ram<'_>, resolver: &'a Resolve, flags: u32) -> ResultProof<'a> {
        resolver
            .result_proof(&ram.storage, OWNER, Intent::Open { flags })
            .unwrap()
    }
    macro_rules! with_proof {
        (prepare, $journal:ident, $ram:ident, $fds:ident, $resolver:ident, plain, $identity:expr, $charge:expr $(,)?) => {{
            let p = proof(&$ram, &$resolver, $journal.flags);
            $journal.prepare(&mut $ram, &mut $fds, p, $identity, $charge)
        }};
        (commit, $journal:ident, $ram:ident, $fds:ident, $resolver:ident, some, $identity:expr, $charge:expr, $now:expr $(,)?) => {{
            let p = proof(&$ram, &$resolver, $journal.flags);
            $journal.commit(&mut $ram, &mut $fds, Some(p), $identity, $charge, $now)
        }};
    }
    fn fds() -> Fds {
        Fds {
            root: ROOT_ACCOUNT,
            ..Fds::default()
        }
    }
    fn create(ram: &mut Ram<'_>, name: &[u8]) -> Token {
        let reserve = ram
            .storage
            .reserve(ROOT_ACCOUNT, ROOT, name, (REG, 0o600, 0, 0))
            .unwrap();
        ram.storage.commit(reserve).unwrap()
    }

    #[test]
    fn final_publication_is_prepaid_and_creation_time_is_consumed_once() {
        let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
        let mut fds = fds();
        let flags = proto_fs::CREATE | proto_fs::READ_WRITE;
        let resolver = ready(&mut ram, b"/finalized", flags);
        let mut charge = ram.storage.charge_preparation(ROOT_ACCOUNT).unwrap();
        let mut journal = Journal::new(flags, 0o600, 0).unwrap();
        while !with_proof!(
            prepare,
            journal,
            ram,
            fds,
            resolver,
            plain,
            OWNER,
            &mut charge
        )
        .unwrap()
        {}
        let Phase::Prepared { held, .. } = journal.phase else {
            panic!("prepared")
        };
        let key = proto_fs::OpenKey {
            slot: 0,
            generation: 1,
        };
        assert!(journal.needs_time(&ram, &fds).unwrap());
        let stale = TentativeOpen {
            description: crate::storage::Token {
                generation: held.description.generation + 1,
                ..held.description
            },
            ..held
        };
        assert!(ram.preflight_finish_open(&fds, key, stale).is_err());
        let publication = ram.preflight_finish_open(&fds, key, held).unwrap();
        assert_eq!(ram.finished_open(&fds, key), Err(proto_fs::OPEN_RETIRED));
        assert_eq!(
            ram.storage.lookup(ROOT, b"finalized"),
            Err(proto_fs::NO_ENTRY)
        );
        let slots = fds.slots;
        let tentative = fds.tentative;
        let receipts = fds.open_receipts;
        let now = proto_fs::Timestamp::legacy_ns(123);
        with_proof!(
            commit,
            journal,
            ram,
            fds,
            resolver,
            some,
            OWNER,
            &mut charge,
            now
        )
        .unwrap();
        assert_eq!(fds.slots, slots);
        assert_eq!(fds.tentative, tentative);
        assert!(fds.open_receipts == receipts);
        assert!(!journal.needs_time(&ram, &fds).unwrap());
        assert_eq!(ram.finish_preflighted(&mut fds, publication), held);
        assert_eq!(ram.finished_open(&fds, key), Ok(held));
        let token = ram.storage.lookup(ROOT, b"finalized").unwrap();
        assert_eq!(ram.storage.node(token).unwrap().times, [now; 3]);
        let replay = ram.preflight_finish_open(&fds, key, held).unwrap();
        assert_eq!(ram.finish_preflighted(&mut fds, replay), held);
        assert_eq!(ram.storage.node(token).unwrap().times, [now; 3]);
        ram.cancel_finished_open(&mut fds, key).unwrap();
        assert!(ram.preflight_finish_open(&fds, key, held).is_err());
        ram.storage.release_preparation(charge);
        resolver.release(&mut ram.storage);
    }

    #[test]
    fn retained_prepared_create_cancels_descriptor_then_reservation_then_pins() {
        let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
        let mut fds = fds();
        let flags = proto_fs::CREATE | proto_fs::EXCLUSIVE | proto_fs::READ_WRITE;
        let mut resolver = ready(&mut ram, b"/retained", flags);
        let mut charge = ram.storage.charge_preparation(ROOT_ACCOUNT).unwrap();
        let mut journal = Journal::new(flags, 0o600, 0).unwrap();
        assert!(
            !with_proof!(
                prepare,
                journal,
                ram,
                fds,
                resolver,
                plain,
                OWNER,
                &mut charge
            )
            .unwrap()
        );
        assert!(
            with_proof!(
                prepare,
                journal,
                ram,
                fds,
                resolver,
                plain,
                OWNER,
                &mut charge
            )
            .unwrap()
        );
        assert!(matches!(
            journal.phase,
            Phase::Prepared {
                creation: Some(_),
                ..
            }
        ));
        let before = ram.storage.preparations_used();
        assert!(
            !journal
                .cancel_step(&mut ram, &mut fds, &mut charge)
                .unwrap()
        );
        assert_eq!(ram.open_descriptions(), 0);
        assert_eq!(ram.storage.preparations_used(), before);
        assert!(matches!(journal.phase, Phase::Reserved(_)));
        assert!(
            !journal
                .cancel_step(&mut ram, &mut fds, &mut charge)
                .unwrap()
        );
        assert!(matches!(journal.phase, Phase::Canceled { .. }));
        assert!(
            journal
                .cancel_step(&mut ram, &mut fds, &mut charge)
                .unwrap()
        );
        assert_ne!(charge, NONE);
        let before_pins =
            ram.storage.node(ROOT).unwrap().pins[crate::storage::Pin::Pending as usize];
        assert!(before_pins >= 2);
        assert!(!resolver.release_step(&mut ram.storage));
        assert_eq!(
            ram.storage.node(ROOT).unwrap().pins[crate::storage::Pin::Pending as usize],
            before_pins - 1
        );
        assert!(!resolver.release_step(&mut ram.storage));
        assert_eq!(
            ram.storage.node(ROOT).unwrap().pins[crate::storage::Pin::Pending as usize],
            before_pins - 2
        );
        assert!(resolver.release_step(&mut ram.storage));
        ram.storage.release_preparation(charge);
    }

    #[test]
    fn timestamp_hint_distinguishes_regular_truncate_from_existing_create() {
        let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
        let mut fds = fds();
        create(&mut ram, b"existing");
        for (flags, timed) in [
            (proto_fs::READ_ONLY, false),
            (proto_fs::READ_ONLY | proto_fs::CREATE, false),
            (proto_fs::READ_WRITE | proto_fs::TRUNCATE, true),
        ] {
            let resolver = ready(&mut ram, b"/existing", flags);
            let mut charge = ram.storage.charge_preparation(ROOT_ACCOUNT).unwrap();
            let mut journal = Journal::new(flags, 0o600, 0).unwrap();
            with_proof!(
                prepare,
                journal,
                ram,
                fds,
                resolver,
                plain,
                OWNER,
                &mut charge
            )
            .unwrap();
            assert_eq!(journal.needs_time(&ram, &fds), Ok(timed));
            journal.cancel(&mut ram, &mut fds, &mut charge).unwrap();
            assert_eq!(journal.needs_time(&ram, &fds), Ok(false));
            ram.storage.release_preparation(charge);
            resolver.release(&mut ram.storage);
        }
    }

    #[test]
    fn created_commit_is_cached_after_epoch_change_and_cancel_is_terminal() {
        let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
        let mut fds = fds();
        let flags = proto_fs::CREATE | proto_fs::EXCLUSIVE | proto_fs::READ_WRITE;
        let resolver = ready(&mut ram, b"/created", flags);
        let mut charge = ram.storage.charge_preparation(ROOT_ACCOUNT).unwrap();
        let mut journal = Journal::new(flags, 0, 0o777).unwrap();
        assert!(
            !with_proof!(
                prepare,
                journal,
                ram,
                fds,
                resolver,
                plain,
                OWNER,
                &mut charge
            )
            .unwrap()
        );
        assert_eq!(charge, NONE);
        assert!(
            with_proof!(
                prepare,
                journal,
                ram,
                fds,
                resolver,
                plain,
                OWNER,
                &mut charge
            )
            .unwrap()
        );
        let held = with_proof!(
            commit,
            journal,
            ram,
            fds,
            resolver,
            some,
            OWNER,
            &mut charge,
            proto_fs::Timestamp::legacy_ns(11),
        )
        .unwrap();
        assert!(
            resolver
                .result_proof(&ram.storage, OWNER, Intent::Open { flags })
                .is_err()
        );
        let token = ram.storage.lookup(ROOT, b"created").unwrap();
        assert_eq!(ram.storage.node(token).unwrap().mode, 0);
        assert_eq!(
            ram.storage.node(token).unwrap().times,
            [proto_fs::Timestamp::legacy_ns(11); 3]
        );
        assert_eq!(
            ram.storage.node(ROOT).unwrap().times[1..],
            [proto_fs::Timestamp::legacy_ns(11); 2]
        );
        assert_eq!(
            journal
                .commit(
                    &mut ram,
                    &mut fds,
                    None,
                    OWNER,
                    &mut charge,
                    proto_fs::Timestamp::legacy_ns(12)
                )
                .unwrap(),
            held
        );
        assert_eq!(
            journal.cancel(&mut ram, &mut fds, &mut charge),
            Ok(Effect::Created)
        );
        assert_eq!(
            journal.cancel(&mut ram, &mut fds, &mut charge),
            Ok(Effect::Created)
        );
        assert_eq!(
            journal.commit(
                &mut ram,
                &mut fds,
                None,
                OWNER,
                &mut charge,
                proto_fs::Timestamp::legacy_ns(13)
            ),
            Err(proto_fs::STALE_PROOF)
        );
        assert_eq!(
            journal.reset_unpublished(&mut ram, &mut fds, &mut charge),
            Err(proto_fs::STALE_PROOF)
        );
        let retry = ready(&mut ram, b"/created", flags);
        assert_eq!(
            with_proof!(prepare, journal, ram, fds, retry, plain, OWNER, &mut charge),
            Err(proto_fs::STALE_PROOF)
        );
        assert_eq!(ram.storage.lookup(ROOT, b"created"), Ok(token));
        assert_eq!(ram.open_descriptions(), 0);
        assert_eq!(ram.storage.preparations_used(), 1);
        resolver.release(&mut ram.storage);
        retry.release(&mut ram.storage);
        ram.storage.release_preparation(charge);
        assert_eq!(ram.storage.preparations_used(), 0);
    }

    #[test]
    fn truncation_commit_revalidates_access_and_replay_preserves_new_bytes() {
        let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
        let mut fds = fds();
        let token = create(&mut ram, b"truncate");
        ram.storage.write(token, ROOT_ACCOUNT, 0, b"old").unwrap();
        ram.storage.node_mut(token).unwrap().mode = 0o6600;
        let flags = proto_fs::READ_WRITE | proto_fs::TRUNCATE;
        let resolver = ready(&mut ram, b"/truncate", flags);
        let mut charge = ram.storage.charge_preparation(ROOT_ACCOUNT).unwrap();
        let mut journal = Journal::new(flags, 0, 0).unwrap();
        with_proof!(
            prepare,
            journal,
            ram,
            fds,
            resolver,
            plain,
            OWNER,
            &mut charge,
        )
        .unwrap();
        let denied = Identity {
            uid: 99,
            gid: 99,
            groups: Groups::EMPTY,
        };
        assert_eq!(
            with_proof!(
                commit,
                journal,
                ram,
                fds,
                resolver,
                some,
                denied,
                &mut charge,
                proto_fs::Timestamp::legacy_ns(20)
            ),
            Err(proto_fs::ACCESS_DENIED)
        );
        assert_eq!(ram.storage.node(token).unwrap().length, 3);
        let held = with_proof!(
            commit,
            journal,
            ram,
            fds,
            resolver,
            some,
            OWNER,
            &mut charge,
            proto_fs::Timestamp::legacy_ns(21),
        )
        .unwrap();
        assert_eq!(ram.storage.node(token).unwrap().mode, 0o600);
        ram.storage.write(token, ROOT_ACCOUNT, 0, b"new").unwrap();
        assert_eq!(
            journal.commit(
                &mut ram,
                &mut fds,
                None,
                OWNER,
                &mut charge,
                proto_fs::Timestamp::legacy_ns(22)
            ),
            Ok(held)
        );
        let mut bytes = [0; 3];
        ram.storage.read(token, 0, &mut bytes).unwrap();
        assert_eq!(&bytes, b"new");
        assert_eq!(
            journal.cancel(&mut ram, &mut fds, &mut charge),
            Ok(Effect::Truncated)
        );
        assert_eq!(ram.storage.node(token).unwrap().length, 3);
        resolver.release(&mut ram.storage);
        ram.storage.release_preparation(charge);
    }

    #[test]
    fn reserved_edge_and_every_unpublished_phase_keep_one_charge_at_full_pool() {
        let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
        let mut fds = fds();
        let mut charges = [NONE; crate::storage::PREPARATIONS];
        for (i, charge) in charges.iter_mut().enumerate() {
            *charge = ram
                .storage
                .charge_preparation(if i < 96 {
                    ROOT_ACCOUNT
                } else {
                    Root {
                        id: 701,
                        generation: 1,
                    }
                })
                .unwrap();
        }
        let flags = proto_fs::CREATE | proto_fs::READ_WRITE;
        for stop in 0..3 {
            let resolver = ready(&mut ram, b"/rollback", flags);
            let mut journal = Journal::new(flags, 0o600, 0).unwrap();
            for _ in 0..stop {
                with_proof!(
                    prepare,
                    journal,
                    ram,
                    fds,
                    resolver,
                    plain,
                    OWNER,
                    &mut charges[0],
                )
                .unwrap();
            }
            if stop == 1 {
                let wrong = ResultProof {
                    parent: ROOT,
                    leaf: b"other",
                    target: None,
                    trailing_slash: false,
                };
                assert_eq!(
                    journal.prepare(&mut ram, &mut fds, wrong, OWNER, &mut charges[0]),
                    Err(proto_fs::STALE_PROOF)
                );
            }
            if stop == 2 {
                let wrong = ResultProof {
                    parent: ROOT,
                    leaf: b"other",
                    target: None,
                    trailing_slash: false,
                };
                assert_eq!(
                    journal.commit(
                        &mut ram,
                        &mut fds,
                        Some(wrong),
                        OWNER,
                        &mut charges[0],
                        proto_fs::Timestamp::legacy_ns(30)
                    ),
                    Err(proto_fs::STALE_PROOF)
                );
            }
            journal
                .reset_unpublished(&mut ram, &mut fds, &mut charges[0])
                .unwrap();
            assert_ne!(charges[0], NONE);
            assert_eq!(ram.storage.preparations_used(), 128);
            assert_eq!(ram.open_descriptions(), 0);
            assert_eq!(
                ram.storage.lookup(ROOT, b"rollback"),
                Err(proto_fs::NO_ENTRY)
            );
            resolver.release(&mut ram.storage);
        }
        for charge in charges {
            ram.storage.release_preparation(charge);
        }
        assert_eq!(ram.storage.preparations_used(), 0);
    }
}

#[cfg(test)]
mod create_directory_policy_tests {
    use super::*;
    use crate::storage::{ROOT, Root};
    #[test]
    fn read_only_create_directory_refuses_before_descriptor_charge() {
        let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(0));
        let mut fds = Fds {
            root: Root {
                id: 700,
                generation: 1,
            },
            ..Fds::default()
        };
        let identity = Identity {
            uid: 0,
            gid: 0,
            groups: proto_process::Groups::EMPTY,
        };
        assert!(matches!(
            ram.prepare_open_token(&mut fds, ROOT, proto_fs::CREATE, identity, None),
            Err(proto_fs::IS_DIRECTORY)
        ));
        assert!(fds.slots.iter().all(Option::is_none));
        let held = ram
            .prepare_open_token(
                &mut fds,
                ROOT,
                proto_fs::CREATE | proto_fs::DIRECTORY_ONLY,
                identity,
                None,
            )
            .unwrap();
        ram.cancel_open(&mut fds, held).unwrap();
        assert!(fds.slots.iter().all(Option::is_none));
        assert!(matches!(
            ram.prepare_open_token(
                &mut fds,
                ROOT,
                proto_fs::CREATE | proto_fs::EXCLUSIVE,
                identity,
                None
            ),
            Err(proto_fs::ALREADY_EXISTS)
        ));
    }
}

#[cfg(test)]
mod concurrent_create_retry_tests {
    use super::*;
    #[cfg(feature = "full-capacity-probe")]
    mod warmup {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/posix-procs/src/capacity_warm.rs"
        ));
    }
    use crate::resolve::{Intent, Progress, Resolve};
    use crate::storage::{ROOT, Root};

    fn resolve(ram: &mut Ram<'_>, resolver: &mut Resolve, identity: Identity) {
        for _ in 0..2000 {
            if resolver.step(&mut ram.storage, identity).unwrap() != Progress::More {
                return;
            }
        }
        panic!("bounded resolver did not complete");
    }

    #[test]
    fn two_root_creation_refreshes_stale_proof_with_same_paid_admission() {
        interleaved_creates(true);
    }

    #[test]
    fn stale_between_resolve_and_prepare_retains_the_same_paid_admission() {
        interleaved_creates(false);
    }

    #[cfg(feature = "full-capacity-probe")]
    #[test]
    fn stale_create_can_leave_paid_inode_gc_after_all_preparations_end() {
        interleaved_with_reclamation(true, false);
    }

    fn interleaved_creates(fully_prepared: bool) {
        interleaved_with_reclamation(fully_prepared, true);
    }

    fn interleaved_with_reclamation(fully_prepared: bool, drain_before_retry: bool) {
        let mut ram = Ram::new(proto_fs::Timestamp::ZERO);
        let identities = [
            Identity {
                uid: 0,
                gid: 0,
                groups: proto_process::Groups::EMPTY,
            },
            Identity {
                uid: 65534,
                gid: 65534,
                groups: proto_process::Groups::EMPTY,
            },
        ];
        let roots = [
            Root {
                id: 700,
                generation: 1,
            },
            Root {
                id: 701,
                generation: 1,
            },
        ];
        let mut sessions = roots.map(|root| Fds {
            root,
            ..Fds::default()
        });
        let flags = proto_fs::CREATE | proto_fs::EXCLUSIVE | proto_fs::READ_WRITE;
        let names: [&[u8]; 2] = [b"/tmp/concurrent-a", b"/tmp/concurrent-b"];
        let mut resolvers = core::array::from_fn::<_, 2, _>(|i| {
            Resolve::with_intent(
                &mut ram.storage,
                names[i],
                ROOT,
                identities[i],
                Intent::Open { flags },
            )
            .unwrap()
        });
        let mut journals =
            core::array::from_fn::<_, 2, _>(|_| Journal::new(flags, 0o600, 0).unwrap());
        let mut charges = roots.map(|root| ram.storage.charge_preparation(root).unwrap());
        let paid = charges;
        for i in 0..2 {
            resolve(&mut ram, &mut resolvers[i], identities[i]);
            loop {
                let proof = resolvers[i]
                    .result_proof(&ram.storage, identities[i], Intent::Open { flags })
                    .unwrap();
                if journals[i]
                    .prepare(
                        &mut ram,
                        &mut sessions[i],
                        proof,
                        identities[i],
                        &mut charges[i],
                    )
                    .unwrap()
                    || (i == 1 && !fully_prepared)
                {
                    break;
                }
            }
        }
        let first = resolvers[0]
            .result_proof(&ram.storage, identities[0], Intent::Open { flags })
            .unwrap();
        let held_a = journals[0]
            .commit(
                &mut ram,
                &mut sessions[0],
                Some(first),
                identities[0],
                &mut charges[0],
                proto_fs::Timestamp::ZERO,
            )
            .unwrap();
        assert!(matches!(
            resolvers[1].result_proof(&ram.storage, identities[1], Intent::Open { flags }),
            Err(proto_fs::STALE_PROOF)
        ));
        journals[1]
            .reset_unpublished(&mut ram, &mut sessions[1], &mut charges[1])
            .unwrap();
        assert_eq!(charges, paid);
        assert_eq!(ram.storage.preparations_used(), 2);
        assert_eq!(ram.open_descriptions(), 1);
        if drain_before_retry {
            for _ in 0..20_000 {
                if !ram.storage.reclaim_step() {
                    break;
                }
            }
        }
        assert_eq!(
            ram.storage.usage(roots[1]).inodes,
            u16::from(!drain_before_retry)
        );
        assert_eq!(ram.storage.usage(roots[1]).descriptions, 0);
        resolve(&mut ram, &mut resolvers[1], identities[1]);
        loop {
            let proof = resolvers[1]
                .result_proof(&ram.storage, identities[1], Intent::Open { flags })
                .unwrap();
            if journals[1]
                .prepare(
                    &mut ram,
                    &mut sessions[1],
                    proof,
                    identities[1],
                    &mut charges[1],
                )
                .unwrap()
            {
                break;
            }
        }
        let refreshed = resolvers[1]
            .result_proof(&ram.storage, identities[1], Intent::Open { flags })
            .unwrap();
        let held_b = journals[1]
            .commit(
                &mut ram,
                &mut sessions[1],
                Some(refreshed),
                identities[1],
                &mut charges[1],
                proto_fs::Timestamp::ZERO,
            )
            .unwrap();
        assert_eq!(
            journals[0]
                .commit(
                    &mut ram,
                    &mut sessions[0],
                    None,
                    identities[0],
                    &mut charges[0],
                    proto_fs::Timestamp::ZERO
                )
                .unwrap(),
            held_a
        );
        let tmp = ram.storage.lookup(ROOT, b"tmp").unwrap();
        for (i, leaf) in [b"concurrent-a".as_slice(), b"concurrent-b".as_slice()]
            .into_iter()
            .enumerate()
        {
            let token = ram.storage.lookup(tmp, leaf).unwrap();
            let node = ram.storage.node(token).unwrap();
            assert_eq!(
                (node.uid, node.gid, node.mode, node.links),
                (identities[i].uid, identities[i].gid, 0o600, 1)
            );
            assert_eq!(
                ram.storage.usage(roots[i]).inodes,
                1 + u16::from(i == 1 && !drain_before_retry)
            );
            #[cfg(feature = "full-capacity-probe")]
            if i == 1 && !drain_before_retry {
                ram.publish_open(&mut sessions[1], held_b).unwrap();
                ram.storage.release_preparation(charges[1]);
                for resolver in resolvers {
                    resolver.release(&mut ram.storage);
                }
                let before = ram.storage.usage(roots[1]);
                assert_eq!(
                    (
                        before.inodes,
                        before.dentries,
                        before.pages,
                        before.descriptions
                    ),
                    (2, 1, 0, 1)
                );
                assert_eq!(ram.storage.preparations_used(), 0);
                assert_eq!(ram.storage.available().pages, crate::storage::PAGES as u16);
                assert!(ram.storage.reclamation_pending());
                assert!(!warmup::initial_ready(
                    0,
                    u32::from(ram.storage.preparations_used()),
                    u32::from(ram.storage.preparations_for_root(roots[1])),
                    u32::from(ram.storage.available().pages),
                    u32::from(before.pages),
                    ram.storage.reclamation_pending(),
                ));
                for _ in 0..20_000 {
                    if !ram.storage.reclaim_step() {
                        break;
                    }
                }
                let after = ram.storage.usage(roots[1]);
                assert_eq!(
                    (
                        after.inodes,
                        after.dentries,
                        after.pages,
                        after.descriptions
                    ),
                    (1, 1, 0, 1)
                );
                assert_eq!(ram.storage.preparations_used(), 0);
                assert_eq!(ram.storage.available().pages, crate::storage::PAGES as u16);
                assert!(!ram.storage.reclamation_pending());
                assert!(warmup::initial_ready(
                    0,
                    u32::from(ram.storage.preparations_used()),
                    u32::from(ram.storage.preparations_for_root(roots[1])),
                    u32::from(ram.storage.available().pages),
                    u32::from(after.pages),
                    ram.storage.reclamation_pending(),
                ));
                assert_eq!(ram.storage.lookup(tmp, b"concurrent-b"), Ok(token));
                ram.release(&mut sessions[1]);
                return;
            }
            let _ = held_b;
            journals[i]
                .cancel(&mut ram, &mut sessions[i], &mut charges[i])
                .unwrap();
            ram.storage.release_preparation(charges[i]);
        }
        for resolver in resolvers {
            resolver.release(&mut ram.storage);
        }
        assert_eq!(ram.open_descriptions(), 0);
        assert_eq!(ram.storage.preparations_used(), 0);
        assert!(sessions.iter().all(|s| s.slots.iter().all(Option::is_none)));
    }
}
