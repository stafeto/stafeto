// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Resident memory custody for one authenticated initial admission.
//! Native callers additionally validate sender, current attempt, object
//! kinds, rights, sizes and Program ranges before constructing this state.

use proto_process::initial_map::{ENTRIES, Key, Receipt, Reply};
use proto_process::initial_publication::{Admission, Publication};
use proto_wire::Status;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Retained,
    Acked,
}

pub struct InitialMapSet<M> {
    publication: Publication,
    objects: [Option<M>; ENTRIES],
    state: State,
}

pub struct Refused<M> {
    pub objects: [Option<M>; ENTRIES],
    pub status: Status,
}

impl<M> InitialMapSet<M> {
    /// `admission` and `current` come from the authenticated resident Work.
    /// Decoding a Publication alone does not satisfy this caller contract.
    /// A refusal returns every incoming object for explicit cleanup.
    pub fn new(
        admission: &Admission,
        current: Receipt,
        publication: Publication,
        objects: [Option<M>; ENTRIES],
    ) -> Result<Self, Refused<M>> {
        let count = usize::from(publication.map.count);
        let valid = publication.validate().is_ok()
            && current == publication.map.receipt
            && current.init_ticket == admission.create.ticket
            && current.key.image == proto_process::IMAGE
            && admission.source == publication.source
            && objects
                .iter()
                .enumerate()
                .all(|(i, m)| m.is_some() == (i < count));
        if !valid {
            return Err(Refused {
                objects,
                status: Status::BadSize,
            });
        }
        Ok(Self {
            publication,
            objects,
            state: State::Retained,
        })
    }

    /// The native handler authenticates the own record session first.
    /// After acknowledgment, every query gets a terminal reply with no caps.
    pub fn query(&self, key: Key) -> Option<Reply> {
        if self.state != State::Retained
            || (key != Key::FIRST && key != self.publication.map.receipt.key)
        {
            return None;
        }
        Some(self.publication.map)
    }

    /// Read an original for duplication. Native code extracts its raw handle
    /// and ends the resident borrow before making the duplication call.
    pub fn original(&self, key: Key, slot: usize) -> Option<&M> {
        self.query(key)?;
        self.objects.get(slot)?.as_ref()
    }

    /// Metadata equality preserves the original objects on publication replay.
    /// It makes no claim about the identity of newly received Memory objects.
    /// The caller retains incoming extras for cleanup outside this borrow.
    pub fn matches_publication(&self, publication: &Publication) -> bool {
        self.publication == *publication
    }

    /// Repeated acknowledgment returns the same receipt without closing a cap.
    pub fn ack(&mut self, key: Key) -> Option<Receipt> {
        if key != self.publication.map.receipt.key {
            return None;
        }
        self.state = State::Acked;
        Some(self.publication.map.receipt)
    }

    pub fn acknowledged(&self) -> Option<Receipt> {
        (self.state == State::Acked).then_some(self.publication.map.receipt)
    }

    /// Moves at most one original out; its close happens outside resident state.
    pub fn cleanup_one(&mut self) -> Option<M> {
        if self.state != State::Acked {
            return None;
        }
        self.objects.iter_mut().find_map(Option::take)
    }

    /// The caller saves this value in Record/origin until exact image End.
    /// Work can be reused only after all originals have left custody.
    pub fn finished(&self) -> Option<Receipt> {
        (self.state == State::Acked && self.objects.iter().all(Option::is_none))
            .then_some(self.publication.map.receipt)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use proto_init::InitialSource;
    use proto_process::{
        Create, Label,
        initial_map::{Entry, PAGE},
    };
    use std::{cell::RefCell, rc::Rc, vec::Vec};
    struct Cap {
        id: usize,
        closed: Rc<RefCell<Vec<usize>>>,
    }
    impl Drop for Cap {
        fn drop(&mut self) {
            self.closed.borrow_mut().push(self.id);
        }
    }
    fn fixture(count: u16) -> (Admission, Publication) {
        let label = Label {
            index: 7,
            generation: 3,
        };
        let source = InitialSource {
            artifact: 5,
            raw: 12,
            canonical: Some(3),
        };
        let admission = Admission {
            create: Create {
                quota: 4096,
                handle_limit: 32,
                ceiling: 31,
                priority: 30,
                root: true,
                ticket: 23,
            },
            program: proto_wire::Name::new(b"posix-probe").unwrap(),
            source,
        };
        let mut map = Reply {
            receipt: Receipt {
                key: Key { key: 19, image: 1 },
                label: label.raw_at(1),
                pid: label.pid(),
                init_ticket: 23,
            },
            count,
            entries: [Entry::EMPTY; ENTRIES],
        };
        for (i, e) in map.entries[..usize::from(count)].iter_mut().enumerate() {
            *e = Entry {
                address: (i as u64 + 1) * PAGE,
                pages: 1,
                access: rt_access(i),
                slot: i as u32,
            };
        }
        (admission, Publication { map, source })
    }
    fn rt_access(i: usize) -> abi::Access {
        [
            abi::Access::ReadExec,
            abi::Access::Read,
            abi::Access::ReadWrite,
            abi::Access::ReadWrite,
        ][i]
    }
    fn caps(count: usize, closed: &Rc<RefCell<Vec<usize>>>) -> [Option<Cap>; ENTRIES] {
        core::array::from_fn(|i| {
            (i < count).then(|| Cap {
                id: i,
                closed: Rc::clone(closed),
            })
        })
    }
    #[test]
    fn ack_preserves_receipt_and_cleanup_moves_one_object_at_a_time() {
        for count in 1..=4 {
            let (a, p) = fixture(count);
            let closed = Rc::new(RefCell::new(Vec::new()));
            let mut set = InitialMapSet::new(&a, p.map.receipt, p, caps(count as usize, &closed))
                .unwrap_or_else(|_| panic!("valid"));
            assert_eq!(set.query(Key::FIRST), Some(p.map));
            assert_eq!(set.query(p.map.receipt.key), Some(p.map));
            for slot in 0..count as usize {
                assert_eq!(set.original(Key::FIRST, slot).unwrap().id, slot);
            }
            assert!(set.cleanup_one().is_none());
            assert!(closed.borrow().is_empty());
            assert!(set.finished().is_none());
            let stale = Key {
                key: 20,
                ..p.map.receipt.key
            };
            assert!(set.ack(stale).is_none());
            assert!(set.query(stale).is_none());
            assert_eq!(set.ack(p.map.receipt.key), Some(p.map.receipt));
            assert_eq!(set.ack(p.map.receipt.key), Some(p.map.receipt));
            assert!(set.query(Key::FIRST).is_none());
            assert!(set.original(p.map.receipt.key, 0).is_none());
            assert!(set.matches_publication(&p));
            assert!(closed.borrow().is_empty());
            for slot in 0..count as usize {
                assert!(set.finished().is_none());
                let cap = set.cleanup_one().unwrap();
                assert_eq!(cap.id, slot);
                assert_eq!(closed.borrow().len(), slot);
                drop(cap);
                assert_eq!(set.acknowledged(), Some(p.map.receipt));
            }
            assert!(set.cleanup_one().is_none());
            assert_eq!(set.finished(), Some(p.map.receipt));
            assert_eq!(closed.borrow().len(), count as usize);
        }
    }
    #[test]
    fn refusals_preserve_objects_and_replay_requires_every_field() {
        let (a, p) = fixture(4);
        let closed = Rc::new(RefCell::new(Vec::new()));
        let mut bad_admission = a;
        bad_admission.create.ticket += 1;
        let refused = InitialMapSet::new(&bad_admission, p.map.receipt, p, caps(4, &closed))
            .err()
            .unwrap();
        assert!(closed.borrow().is_empty());
        assert_eq!(refused.status, Status::BadSize);
        drop(refused);
        closed.borrow_mut().clear();
        let mut stale = p.map.receipt;
        stale.key.key += 1;
        let refused = InitialMapSet::new(&a, stale, p, caps(4, &closed))
            .err()
            .unwrap();
        assert!(closed.borrow().is_empty());
        drop(refused);
        closed.borrow_mut().clear();
        let refused = InitialMapSet::new(&a, p.map.receipt, p, caps(3, &closed))
            .err()
            .unwrap();
        assert!(closed.borrow().is_empty());
        drop(refused);
        closed.borrow_mut().clear();
        let set = InitialMapSet::new(&a, p.map.receipt, p, caps(4, &closed))
            .unwrap_or_else(|_| panic!("valid"));
        let mut bad = p;
        bad.source.raw += 1;
        assert!(!set.matches_publication(&bad));
        let mut bad = p;
        bad.map.entries[3].pages += 1;
        assert!(!set.matches_publication(&bad));
        let mut bad = p;
        bad.map.receipt.key.key += 1;
        assert!(!set.matches_publication(&bad));
        assert!(set.matches_publication(&p));
        assert!(closed.borrow().is_empty());
    }
}
