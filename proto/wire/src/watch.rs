// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Bounded watches shared by services with readiness notifications.
//! Start carries a count and (description, events) pairs. Take and Cancel
//! carry the nonzero key alone. Ready carries a count and one event word
//! per original pair. A waiting registration lives through Ready until
//! Cancel; each service owns its LongOps key and reverse subscriptions.

use crate::{Reader, Status, Writer};

pub const MAX: usize = 32;
pub const IN: u32 = 0x001;
pub const PRI: u32 = 0x002;
pub const OUT: u32 = 0x004;
pub const ERR: u32 = 0x008;
pub const HUP: u32 = 0x010;
pub const NVAL: u32 = 0x020;
pub const RDNORM: u32 = 0x040;
pub const RDBAND: u32 = 0x080;
pub const WRNORM: u32 = 0x100;
pub const WRBAND: u32 = 0x200;
pub const EVENTS: u32 = 0x3ff;
pub const READ: u32 = IN | RDNORM;
pub const WRITE: u32 = OUT | WRNORM;
pub const ALWAYS: u32 = ERR | HUP | NVAL;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Item {
    pub description: u32,
    pub events: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Set {
    pub len: usize,
    pub items: [Item; MAX],
}

impl Default for Set {
    fn default() -> Self {
        Self::new()
    }
}

impl Set {
    pub const fn new() -> Self {
        Self {
            len: 0,
            items: [Item {
                description: 0,
                events: 0,
            }; MAX],
        }
    }

    pub fn parse(mut body: Reader<'_>) -> Result<Self, Status> {
        let mut set = Self::new();
        set.len = body.u32()? as usize;
        if set.len == 0 || set.len > MAX {
            return Err(Status::BadSize);
        }
        for item in &mut set.items[..set.len] {
            *item = Item {
                description: body.u32()?,
                events: body.u32()?,
            };
            if item.events & !EVENTS != 0 {
                return Err(Status::BadSize);
            }
        }
        body.finish()?;
        Ok(set)
    }

    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        if self.len == 0 || self.len > MAX {
            return Err(Status::BadSize);
        }
        w.u32(self.len as u32)?;
        for item in &self.items[..self.len] {
            if item.events & !EVENTS != 0 {
                return Err(Status::BadSize);
            }
            w.u32(item.description)?;
            w.u32(item.events)?;
        }
        Ok(())
    }

    /// Each actual description once, retaining its first occurrence.
    /// Registration and removal use only the description, without event unions.
    pub fn descriptions(&self) -> impl Iterator<Item = u32> + '_ {
        self.items[..self.len]
            .iter()
            .enumerate()
            .filter_map(move |(i, item)| {
                (!self.items[..i]
                    .iter()
                    .any(|before| before.description == item.description))
                .then_some(item.description)
            })
    }

    /// Each actual description once, with the union of its requested events.
    pub fn unique(&self) -> impl Iterator<Item = Item> + '_ {
        self.items[..self.len]
            .iter()
            .enumerate()
            .filter_map(move |(i, item)| {
                if self.items[..i]
                    .iter()
                    .any(|before| before.description == item.description)
                {
                    return None;
                }
                let events = self.items[i..self.len]
                    .iter()
                    .filter(|other| other.description == item.description)
                    .fold(0, |events, other| events | other.events);
                Some(Item {
                    description: item.description,
                    events,
                })
            })
    }

    /// Readiness remains separate for every original element, including
    /// duplicates and elements requesting no events. No data is consumed.
    pub fn ready(&self, mut readiness: impl FnMut(u32) -> u32) -> Ready {
        let mut ready = Ready {
            len: self.len,
            events: [0; MAX],
        };
        for (out, item) in ready.events[..self.len].iter_mut().zip(&self.items) {
            *out = readiness(item.description) & (item.events | ALWAYS);
        }
        ready
    }
}

pub fn key(mut body: Reader<'_>) -> Result<u64, Status> {
    let key = body.u64()?;
    body.finish()?;
    if key == 0 {
        Err(Status::BadSize)
    } else {
        Ok(key)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ready {
    pub len: usize,
    pub events: [u32; MAX],
}

impl Ready {
    pub fn any(&self) -> bool {
        self.events[..self.len].iter().any(|&event| event != 0)
    }
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        if self.len > MAX {
            return Err(Status::BadSize);
        }
        w.u32(self.len as u32)?;
        for &event in &self.events[..self.len] {
            w.u32(event)?;
        }
        Ok(())
    }
    pub fn parse(mut body: Reader<'_>) -> Result<Self, Status> {
        let len = body.u32()? as usize;
        if len > MAX {
            return Err(Status::BadSize);
        }
        let mut ready = Self {
            len,
            events: [0; MAX],
        };
        for event in &mut ready.events[..len] {
            *event = body.u32()?;
            if *event & !EVENTS != 0 {
                return Err(Status::BadSize);
            }
        }
        body.finish()?;
        Ok(ready)
    }
}

#[derive(Clone, Copy)]
struct Registration {
    label: u64,
    key: u64,
    set: Set,
    retired: bool,
    cleaned: usize,
}

/// Active watches and retired reverse links share this bounded pool.
/// A retired watch keeps its exact generation key while LongOps may reuse
/// the operation's place. Cleanup therefore removes only its own links.
pub struct Pool<const N: usize> {
    list: [Option<Registration>; N],
}

impl<const N: usize> Default for Pool<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Pool<N> {
    pub const fn new() -> Self {
        Self { list: [None; N] }
    }
    pub fn insert(&mut self, label: u64, key: u64, set: Set) -> bool {
        let Some(free) = self.list.iter_mut().find(|item| item.is_none()) else {
            return false;
        };
        *free = Some(Registration {
            label,
            key,
            set,
            retired: false,
            cleaned: 0,
        });
        true
    }
    pub fn get(&self, label: u64, key: u64) -> Option<&Set> {
        self.list
            .iter()
            .flatten()
            .find(|item| !item.retired && item.label == label && item.key == key)
            .map(|item| &item.set)
    }
    pub fn remove(&mut self, label: u64, key: u64) -> Option<Set> {
        self.list
            .iter_mut()
            .find(|item| {
                item.is_some_and(|item| !item.retired && item.label == label && item.key == key)
            })?
            .take()
            .map(|item| item.set)
    }
    pub fn retire(&mut self, label: u64) {
        for item in self
            .list
            .iter_mut()
            .flatten()
            .filter(|item| item.label == label)
        {
            item.retired = true;
        }
    }
    pub fn cleanup_due(&self) -> bool {
        self.list.iter().flatten().any(|item| item.retired)
    }
    /// One retired reverse link per step, with its original owner and key.
    pub fn cleanup(&mut self) -> Option<(u64, u64, u32)> {
        let slot = self
            .list
            .iter_mut()
            .find(|item| item.is_some_and(|item| item.retired))?;
        let item = slot.as_mut()?;
        let result = (
            item.label,
            item.key,
            item.set.items[item.cleaned].description,
        );
        item.cleaned += 1;
        if item.cleaned == item.set.len {
            *slot = None;
        }
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn set() -> Set {
        let mut set = Set::new();
        set.len = 3;
        set.items[..3].copy_from_slice(&[
            Item {
                description: 7,
                events: IN,
            },
            Item {
                description: 7,
                events: OUT,
            },
            Item {
                description: 8,
                events: 0,
            },
        ]);
        set
    }
    #[test]
    fn duplicates_share_links_and_keep_individual_events() {
        assert_eq!(
            set().unique().collect::<std::vec::Vec<_>>(),
            [
                Item {
                    description: 7,
                    events: IN | OUT
                },
                Item {
                    description: 8,
                    events: 0
                }
            ]
        );
        let ready = set().ready(|_| IN | HUP);
        assert_eq!(&ready.events[..3], [IN | HUP, HUP, HUP]);
        let mut w = Writer::new();
        set().write(&mut w).unwrap();
        assert_eq!(Set::parse(Reader::new(w.as_bytes())), Ok(set()));
        let mut w = Writer::new();
        ready.write(&mut w).unwrap();
        assert_eq!(Ready::parse(Reader::new(w.as_bytes())), Ok(ready));
    }
    #[test]
    fn retired_generation_cannot_remove_a_new_registration() {
        let mut pool = Pool::<2>::new();
        assert!(pool.insert(9, 0x100000001, set()));
        pool.retire(9);
        assert!(pool.get(9, 0x100000001).is_none());
        assert!(pool.insert(9, 0x200000001, set()));
        assert!(!pool.insert(9, 0x300000001, set()));
        for description in [7, 7, 8] {
            assert_eq!(pool.cleanup(), Some((9, 0x100000001, description)));
            assert!(pool.get(9, 0x200000001).is_some());
        }
        assert!(!pool.cleanup_due());
        assert!(pool.remove(9, 0x200000001).is_some());
        assert!(pool.remove(9, 0x200000001).is_none());
    }
    #[test]
    fn wire_refuses_empty_overlarge_and_reserved_events() {
        for count in [0, MAX as u32 + 1] {
            assert_eq!(
                Set::parse(Reader::new(&count.to_le_bytes())),
                Err(Status::BadSize)
            );
        }
        let mut set = set();
        set.items[0].events = 1 << 31;
        assert_eq!(set.write(&mut Writer::new()), Err(Status::BadSize));
        assert_eq!(key(Reader::new(&0u64.to_le_bytes())), Err(Status::BadSize));
    }
}
