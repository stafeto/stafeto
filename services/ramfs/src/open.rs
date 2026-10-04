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
            | proto_fs::CREATE
            | proto_fs::EXCLUSIVE
            | proto_fs::TRUNCATE
            | proto_fs::APPEND
            | proto_fs::NO_FOLLOW;
        if flags & !allowed != 0 || flags & 3 == 3 {
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
    /// The caller validates owner, identity stamp and intent before every entry.
    /// A committed replay uses its exact descriptor and remains independent of path epoch.
    pub fn commit(
        &mut self,
        ram: &mut Ram<'_>,
        fds: &mut Fds,
        proof: Option<ResultProof<'_>>,
        identity: Identity,
        charge: &mut u16,
        now: u64,
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
    fn created_commit_is_cached_after_epoch_change_and_cancel_is_terminal() {
        let mut ram = Ram::new(0);
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
            11,
        )
        .unwrap();
        assert!(
            resolver
                .result_proof(&ram.storage, OWNER, Intent::Open { flags })
                .is_err()
        );
        let token = ram.storage.lookup(ROOT, b"created").unwrap();
        assert_eq!(ram.storage.node(token).unwrap().mode, 0);
        assert_eq!(ram.storage.node(token).unwrap().times, [11; 3]);
        assert_eq!(ram.storage.node(ROOT).unwrap().times[1..], [11; 2]);
        assert_eq!(
            journal
                .commit(&mut ram, &mut fds, None, OWNER, &mut charge, 12)
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
            journal.commit(&mut ram, &mut fds, None, OWNER, &mut charge, 13),
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
        let mut ram = Ram::new(0);
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
                20
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
            21,
        )
        .unwrap();
        assert_eq!(ram.storage.node(token).unwrap().mode, 0o600);
        ram.storage.write(token, ROOT_ACCOUNT, 0, b"new").unwrap();
        assert_eq!(
            journal.commit(&mut ram, &mut fds, None, OWNER, &mut charge, 22),
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
        let mut ram = Ram::new(0);
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
                    journal.commit(&mut ram, &mut fds, Some(wrong), OWNER, &mut charges[0], 30),
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
