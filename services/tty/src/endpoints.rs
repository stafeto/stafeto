// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Open terminal descriptions and their session and operation references.
//! IDs carry a generation; a retired PTY stays allocated while its old slave
//! descriptions or its controlling link remain live.

pub const PTYS: usize = 8;
pub const TERMINALS: usize = PTYS + 1;
pub const DESCRIPTIONS: usize = 256;
pub const HOLDS: usize = 32;
const ID_GENERATION_MAX: u32 = u32::MAX >> 8;
pub const NONBLOCK: u32 = 0o4000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Master,
    Slave,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    BadDescription,
    Invalid,
    Limit,
    Locked,
    Overflow,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub terminal: usize,
    pub generation: u64,
    pub side: Side,
    pub flags: u32,
}
#[derive(Clone, Copy)]
struct Description {
    generation: u32,
    references: u32,
    pins: u32,
    endpoint: Endpoint,
}
impl Description {
    const fn empty() -> Self {
        Self {
            generation: 0,
            references: 0,
            pins: 0,
            endpoint: Endpoint {
                terminal: 0,
                generation: 0,
                side: Side::Slave,
                flags: 0,
            },
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Instance {
    pub generation: u64,
    pub allocated: bool,
    pub disconnected: bool,
    pub locked: bool,
    pub uid: u32,
    pub mode: u32,
    masters: u32,
    slaves: u32,
    pins: u32,
    linked: bool,
}
impl Instance {
    const fn empty() -> Self {
        Self {
            generation: 0,
            allocated: false,
            disconnected: false,
            locked: true,
            uid: 0,
            mode: 0,
            masters: 0,
            slaves: 0,
            pins: 0,
            linked: false,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Disconnect {
    pub terminal: usize,
    pub generation: u64,
}

/// Each session owns one reference to each open description it holds.
/// Local dup creates another fd reference to this same session hold.
#[derive(Clone)]
pub struct Holds {
    ids: [Option<u32>; HOLDS],
}
impl Default for Holds {
    fn default() -> Self {
        Self::new()
    }
}
impl Holds {
    pub const fn new() -> Self {
        Self { ids: [None; HOLDS] }
    }
    pub fn contains(&self, id: u32) -> bool {
        self.ids.contains(&Some(id))
    }
    pub fn ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.ids.iter().flatten().copied()
    }
    pub fn first(&self) -> Option<u32> {
        self.ids().next()
    }
    fn room(&self) -> Result<usize, Failure> {
        self.ids
            .iter()
            .position(Option::is_none)
            .ok_or(Failure::Limit)
    }
}

pub struct Endpoints {
    descriptions: [Description; DESCRIPTIONS],
    instances: [Instance; TERMINALS],
}
impl Default for Endpoints {
    fn default() -> Self {
        Self::new()
    }
}
impl Endpoints {
    pub const fn new() -> Self {
        let mut instances = [Instance::empty(); TERMINALS];
        instances[0].generation = 1;
        instances[0].allocated = true;
        instances[0].locked = false;
        instances[0].mode = 0o620;
        Self {
            descriptions: [Description::empty(); DESCRIPTIONS],
            instances,
        }
    }
    pub fn instance(&self, terminal: usize) -> Option<&Instance> {
        self.instances.get(terminal).filter(|i| i.allocated)
    }
    fn locate(&self, id: u32) -> Result<usize, Failure> {
        let index = (id & 255) as usize;
        let d = &self.descriptions[index];
        let i = &self.instances[d.endpoint.terminal];
        if id >> 8 != d.generation
            || d.references == 0
            || !i.allocated
            || d.endpoint.generation != i.generation
        {
            return Err(Failure::BadDescription);
        }
        Ok(index)
    }
    pub fn resolve(&self, holds: &Holds, id: u32) -> Result<Endpoint, Failure> {
        if !holds.contains(id) {
            return Err(Failure::BadDescription);
        }
        Ok(self.descriptions[self.locate(id)?].endpoint)
    }
    pub fn pinned(&self, id: u32) -> Result<Endpoint, Failure> {
        Ok(self.descriptions[self.locate(id)?].endpoint)
    }
    fn free_description(&self) -> Result<usize, Failure> {
        self.descriptions
            .iter()
            .position(|d| d.references == 0 && d.generation < ID_GENERATION_MAX)
            .ok_or(Failure::Limit)
    }
    fn publish(
        &mut self,
        holds: &mut Holds,
        place: usize,
        index: usize,
        endpoint: Endpoint,
    ) -> u32 {
        let d = &mut self.descriptions[index];
        d.generation += 1;
        d.references = 1;
        d.pins = 0;
        d.endpoint = endpoint;
        let id = d.generation << 8 | index as u32;
        holds.ids[place] = Some(id);
        let i = &mut self.instances[endpoint.terminal];
        match endpoint.side {
            Side::Master => i.masters += 1,
            Side::Slave => i.slaves += 1,
        }
        id
    }
    pub fn open_console(&mut self, holds: &mut Holds, flags: u32) -> Result<u32, Failure> {
        let place = holds.room()?;
        let index = self.free_description()?;
        Ok(self.publish(
            holds,
            place,
            index,
            Endpoint {
                terminal: 0,
                generation: 1,
                side: Side::Slave,
                flags,
            },
        ))
    }
    pub fn open_master(&mut self, holds: &mut Holds, flags: u32) -> Result<u32, Failure> {
        let place = holds.room()?;
        let index = self.free_description()?;
        let terminal = (1..TERMINALS)
            .find(|&n| !self.instances[n].allocated && self.instances[n].generation != u64::MAX)
            .ok_or(Failure::Limit)?;
        let generation = self.instances[terminal].generation + 1;
        self.instances[terminal] = Instance {
            generation,
            allocated: true,
            ..Instance::empty()
        };
        Ok(self.publish(
            holds,
            place,
            index,
            Endpoint {
                terminal,
                generation,
                side: Side::Master,
                flags,
            },
        ))
    }
    pub fn open_slave(
        &mut self,
        holds: &mut Holds,
        number: usize,
        flags: u32,
    ) -> Result<u32, Failure> {
        let terminal = number
            .checked_add(1)
            .filter(|&n| n < TERMINALS)
            .ok_or(Failure::Invalid)?;
        let i = self.instance(terminal).ok_or(Failure::Invalid)?;
        if i.locked {
            return Err(Failure::Locked);
        }
        if i.disconnected {
            return Err(Failure::Invalid);
        }
        let endpoint = Endpoint {
            terminal,
            generation: i.generation,
            side: Side::Slave,
            flags,
        };
        let place = holds.room()?;
        let index = self.free_description()?;
        Ok(self.publish(holds, place, index, endpoint))
    }
    pub fn master(&self, holds: &Holds, id: u32) -> Result<Endpoint, Failure> {
        let endpoint = self.resolve(holds, id)?;
        if endpoint.side != Side::Master {
            return Err(Failure::Invalid);
        }
        Ok(endpoint)
    }
    pub fn number(&self, holds: &Holds, id: u32) -> Result<u32, Failure> {
        Ok((self.master(holds, id)?.terminal - 1) as u32)
    }
    pub fn lock(&mut self, holds: &Holds, id: u32, locked: bool) -> Result<(), Failure> {
        let e = self.master(holds, id)?;
        self.instances[e.terminal].locked = locked;
        Ok(())
    }
    pub fn grant(&mut self, holds: &Holds, id: u32, uid: u32) -> Result<(), Failure> {
        let e = self.master(holds, id)?;
        self.instances[e.terminal].uid = uid;
        self.instances[e.terminal].mode = 0o620;
        Ok(())
    }
    pub fn set_flags(&mut self, holds: &Holds, id: u32, flags: u32) -> Result<(), Failure> {
        self.resolve(holds, id)?;
        let d = &mut self.descriptions[self.locate(id)?];
        d.endpoint.flags = (d.endpoint.flags & !NONBLOCK) | (flags & NONBLOCK);
        Ok(())
    }
    fn retain(&mut self, id: u32, real: bool) -> Result<(), Failure> {
        let index = self.locate(id)?;
        let d = self.descriptions[index];
        let i = &self.instances[d.endpoint.terminal];
        let count = if real {
            match d.endpoint.side {
                Side::Master => i.masters,
                Side::Slave => i.slaves,
            }
        } else {
            i.pins
        };
        let references = d.references.checked_add(1).ok_or(Failure::Overflow)?;
        let count = count.checked_add(1).ok_or(Failure::Overflow)?;
        let pins = d
            .pins
            .checked_add(u32::from(!real))
            .ok_or(Failure::Overflow)?;
        self.descriptions[index].references = references;
        self.descriptions[index].pins = pins;
        let i = &mut self.instances[d.endpoint.terminal];
        if real {
            match d.endpoint.side {
                Side::Master => i.masters = count,
                Side::Slave => i.slaves = count,
            }
        } else {
            i.pins = count;
        }
        Ok(())
    }
    pub fn clone_holds(&mut self, parent: &Holds) -> Result<Holds, Failure> {
        // Validate every increment before publishing any child reference.
        for id in parent.ids() {
            let d = self.descriptions[self.locate(id)?];
            if d.references == u32::MAX {
                return Err(Failure::Overflow);
            }
            let i = &self.instances[d.endpoint.terminal];
            let additional = parent
                .ids()
                .filter(|&other| {
                    self.descriptions[(other & 255) as usize].endpoint.terminal
                        == d.endpoint.terminal
                        && self.descriptions[(other & 255) as usize].endpoint.side
                            == d.endpoint.side
                })
                .count() as u32;
            let count = match d.endpoint.side {
                Side::Master => i.masters,
                Side::Slave => i.slaves,
            };
            count.checked_add(additional).ok_or(Failure::Overflow)?;
        }
        for id in parent.ids() {
            self.retain(id, true)?;
        }
        Ok(parent.clone())
    }
    pub fn pin(&mut self, holds: &Holds, id: u32) -> Result<(), Failure> {
        self.resolve(holds, id)?;
        self.retain(id, false)
    }
    fn release(&mut self, id: u32, real: bool) -> Result<Option<Disconnect>, Failure> {
        let index = self.locate(id)?;
        let d = self.descriptions[index];
        if (real && d.references == d.pins) || (!real && d.pins == 0) {
            return Err(Failure::BadDescription);
        }
        self.descriptions[index].references -= 1;
        let i = &mut self.instances[d.endpoint.terminal];
        if real {
            match d.endpoint.side {
                Side::Master => i.masters -= 1,
                Side::Slave => i.slaves -= 1,
            }
        } else {
            self.descriptions[index].pins -= 1;
            i.pins -= 1;
        }
        let disconnected =
            real && d.endpoint.terminal != 0 && d.endpoint.side == Side::Master && i.masters == 0;
        if disconnected {
            i.disconnected = true;
        }
        let effect = disconnected.then_some(Disconnect {
            terminal: d.endpoint.terminal,
            generation: i.generation,
        });
        self.recycle(d.endpoint.terminal);
        Ok(effect)
    }
    pub fn close(&mut self, holds: &mut Holds, id: u32) -> Result<Option<Disconnect>, Failure> {
        let place = holds
            .ids
            .iter()
            .position(|&item| item == Some(id))
            .ok_or(Failure::BadDescription)?;
        self.locate(id)?;
        holds.ids[place] = None;
        self.release(id, true)
    }
    pub fn unpin(&mut self, id: u32) -> Result<Option<Disconnect>, Failure> {
        self.release(id, false)
    }
    pub fn set_link(
        &mut self,
        terminal: usize,
        generation: u64,
        linked: bool,
    ) -> Result<(), Failure> {
        let i = self.instances.get_mut(terminal).ok_or(Failure::Invalid)?;
        if !i.allocated || i.generation != generation {
            return Err(Failure::BadDescription);
        }
        i.linked = linked;
        self.recycle(terminal);
        Ok(())
    }
    fn recycle(&mut self, terminal: usize) {
        let i = &mut self.instances[terminal];
        if terminal != 0 && i.masters == 0 && i.slaves == 0 && i.pins == 0 && !i.linked {
            i.allocated = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_clones_keep_the_line_and_pins_only_keep_the_instance() {
        let mut table = Endpoints::new();
        let mut parent = Holds::new();
        let master = table.open_master(&mut parent, 2).unwrap();
        table.grant(&parent, master, 77).unwrap();
        table.lock(&parent, master, false).unwrap();
        let slave = table.open_slave(&mut parent, 0, 2).unwrap();
        let mut child = table.clone_holds(&parent).unwrap();
        table.pin(&child, master).unwrap();
        assert_eq!(table.close(&mut parent, master), Ok(None));
        let effect = table.close(&mut child, master).unwrap().unwrap();
        assert_eq!(effect.terminal, 1);
        assert!(table.instance(1).unwrap().disconnected);
        assert_eq!(
            table.resolve(&parent, slave).unwrap().generation,
            effect.generation
        );
        assert_eq!(table.open_slave(&mut parent, 0, 2), Err(Failure::Invalid));
        assert_eq!(table.close(&mut parent, slave), Ok(None));
        assert!(table.instance(1).is_some());
        assert_eq!(table.close(&mut child, slave), Ok(None));
        assert!(table.instance(1).is_some());
        assert!(table.pinned(master).is_ok());
        assert_eq!(table.unpin(master), Ok(None));
        assert!(table.instance(1).is_none());
        let fresh = table.open_master(&mut parent, 2).unwrap();
        assert_ne!(fresh, master);
        assert!(table.resolve(&parent, fresh).unwrap().generation > effect.generation);
        assert_eq!(table.pinned(master), Err(Failure::BadDescription));
    }

    #[test]
    fn lock_grant_flags_and_controlling_link_keep_their_scope() {
        let mut table = Endpoints::new();
        let mut parent = Holds::new();
        let master = table.open_master(&mut parent, 2).unwrap();
        assert_eq!(table.open_slave(&mut parent, 0, 2), Err(Failure::Locked));
        table.grant(&parent, master, 91).unwrap();
        table.lock(&parent, master, false).unwrap();
        let slave = table.open_slave(&mut parent, 0, 0).unwrap();
        let mut child = table.clone_holds(&parent).unwrap();
        table.grant(&child, master, 123).unwrap();
        assert_eq!(table.instance(1).unwrap().uid, 123);
        assert_eq!(table.instance(1).unwrap().mode, 0o620);
        table.set_flags(&child, master, NONBLOCK).unwrap();
        assert_eq!(table.resolve(&parent, master).unwrap().flags, 2 | NONBLOCK);
        assert_eq!(table.resolve(&parent, slave).unwrap().flags, 0);
        assert_eq!(table.grant(&parent, slave, 0), Err(Failure::Invalid));
        let generation = table.instance(1).unwrap().generation;
        table.set_link(1, generation, true).unwrap();
        for id in [master, slave] {
            table.close(&mut parent, id).unwrap();
            table.close(&mut child, id).unwrap();
        }
        assert!(table.instance(1).is_some());
        assert_eq!(
            table.set_link(1, generation + 1, false),
            Err(Failure::BadDescription)
        );
        table.set_link(1, generation, false).unwrap();
        assert!(table.instance(1).is_none());
    }

    #[test]
    fn eight_instances_and_session_limit_fail_before_publication() {
        let mut table = Endpoints::new();
        let mut holders = Holds::new();
        for _ in 0..PTYS {
            table.open_master(&mut holders, 2).unwrap();
        }
        assert_eq!(table.open_master(&mut holders, 2), Err(Failure::Limit));
        for _ in PTYS..HOLDS {
            table.open_console(&mut holders, 2).unwrap();
        }
        assert_eq!(holders.ids().count(), HOLDS);
        assert_eq!(table.open_console(&mut holders, 2), Err(Failure::Limit));
        assert_eq!(
            table
                .descriptions
                .iter()
                .filter(|d| d.references != 0)
                .count(),
            HOLDS
        );
        let mut empty = Holds::new();
        let foreign = holders.first().unwrap();
        assert_eq!(
            table.close(&mut empty, foreign),
            Err(Failure::BadDescription)
        );
        assert!(table.resolve(&holders, foreign).is_ok());
    }

    #[test]
    fn exhausted_description_and_instance_generations_are_never_reused() {
        let mut table = Endpoints::new();
        let mut holders = Holds::new();
        table.descriptions[0].generation = ID_GENERATION_MAX;
        table.instances[1].generation = u64::MAX;
        let master = table.open_master(&mut holders, 2).unwrap();
        assert_eq!(master & 255, 1);
        assert_eq!(table.number(&holders, master), Ok(1));
        assert!(!table.instances[1].allocated);
        table.descriptions[(master & 255) as usize].references = u32::MAX;
        let before = table.instance(2).unwrap().masters;
        assert_eq!(table.clone_holds(&holders).err(), Some(Failure::Overflow));
        assert_eq!(table.instance(2).unwrap().masters, before);
    }
}
