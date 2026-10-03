// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The pipes of the pipe service (5e), apart from its loop: a pool of
//! PIPES rings of CAPACITY bytes, two descriptions for each, the
//! descriptions each session holds, and the operations that wait at each
//! end. A description counts the sessions that hold it (its references):
//! a pipe has no writer once its write end has none, and no reader once
//! its read end has none. A session that goes lets go of its descriptions
//! in steps of one description each (`gone`, `step`), so no step of the
//! service grows with what a session held; the loop wakes the operations
//! each change names (`Wakes`). Every operation here is O(1) or bounded
//! by WAITERS or HELD_MAX.

#![cfg_attr(not(test), no_std)]

pub use proto_pipe::{
    AGAIN, ATOMIC, BAD_FD, BROKEN, CAPACITY, CREATED_MAX, HELD_MAX, INVALID, MFILE, NFILE,
    NONBLOCK, PIPES, WAITERS, WRITE_END,
};

/// The descriptions of the service: two for each pipe.
pub const DESCRIPTIONS: usize = 2 * PIPES;

/// An operation that waits: the label of its client and its key.
pub type Waiter = (u64, u64);

/// The descriptions a session holds, a bit for each.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Held {
    bits: u128,
}

impl Held {
    pub fn holds(&self, description: u32) -> bool {
        (description as usize) < DESCRIPTIONS && self.bits & 1 << description != 0
    }

    pub fn count(&self) -> usize {
        self.bits.count_ones() as usize
    }

    fn add(&mut self, description: usize) {
        self.bits |= 1 << description;
    }

    fn remove(&mut self, description: usize) {
        self.bits &= !(1 << description);
    }
}

/// The operations a change woke: those that wait at one end.
#[derive(Clone, Copy, Debug, Default)]
pub struct Wakes {
    list: [Option<Waiter>; WAITERS],
}

impl Wakes {
    pub fn iter(&self) -> impl Iterator<Item = Waiter> + '_ {
        self.list.iter().flatten().copied()
    }
}

/// One end of a pipe, its description.
#[derive(Clone, Copy, Debug)]
struct End {
    /// The sessions that hold it, the births of Clone among them.
    refs: u16,
    nonblock: bool,
    waiters: [Option<Waiter>; WAITERS],
}

/// A pipe: its creator's label, where its bytes start in the ring and how
/// many there are, and its ends, the read end first.
#[derive(Clone, Copy, Debug)]
struct Pipe {
    live: bool,
    creator: u64,
    head: u16,
    len: u16,
    ends: [End; 2],
}

impl End {
    /// The waiters `keep` keeps, in the order they came: the list stays
    /// a queue, its free places at its tail, so a new waiter queues behind
    /// those that wait already and is told after them.
    fn keep(&mut self, keep: impl Fn(Waiter) -> bool) {
        let mut at = 0;
        for i in 0..WAITERS {
            if let Some(w) = self.waiters[i]
                && keep(w)
            {
                self.waiters[at] = Some(w);
                at += 1;
            }
        }
        for slot in &mut self.waiters[at..] {
            *slot = None;
        }
    }

    const NONE: End = End {
        refs: 0,
        nonblock: false,
        waiters: [None; WAITERS],
    };
}

impl Pipe {
    const FREE: Pipe = Pipe {
        live: false,
        creator: 0,
        head: 0,
        len: 0,
        ends: [End::NONE; 2],
    };
}

/// The pipes and descriptions of the service, their rings among them:
/// the service keeps them in its `.bss`.
pub struct Pipes {
    pipes: [Pipe; PIPES],
    rings: [[u8; CAPACITY]; PIPES],
    /// The references of each description that sessions which went let
    /// go of, and the descriptions that have some: `step` takes them back
    /// one description at a time.
    dropping: [u16; DESCRIPTIONS],
    dirty: u128,
}

/// The pipe and the end of `description`, a held one of the kind asked.
fn split(held: &Held, description: u32, write: Option<bool>) -> Result<(usize, usize), u32> {
    if !held.holds(description) {
        return Err(BAD_FD);
    }
    let (pipe, is_write) = proto_pipe::end_of(description);
    if write.is_some_and(|w| w != is_write) {
        return Err(BAD_FD);
    }
    Ok((pipe, is_write as usize))
}

impl Default for Pipes {
    fn default() -> Self {
        Self::new()
    }
}

impl Pipes {
    pub const fn new() -> Pipes {
        Pipes {
            pipes: [Pipe::FREE; PIPES],
            rings: [[0; CAPACITY]; PIPES],
            dropping: [0; DESCRIPTIONS],
            dirty: 0,
        }
    }

    /// A new pipe of the session `held` of the root `creator`: its read end and its
    /// write end, which the session holds; NFILE with all pipes in use,
    /// MFILE past CREATED_MAX live pipes of `creator` or HELD_MAX held.
    pub fn create(&mut self, held: &mut Held, creator: u64, flags: u32) -> Result<(u32, u32), u32> {
        if flags & !NONBLOCK != 0 {
            return Err(INVALID);
        }
        if held.count() + 2 > HELD_MAX
            || self
                .pipes
                .iter()
                .filter(|p| p.live && p.creator == creator)
                .count()
                >= CREATED_MAX
        {
            return Err(MFILE);
        }
        let index = self.pipes.iter().position(|p| !p.live).ok_or(NFILE)?;
        let nonblock = flags & NONBLOCK != 0;
        let end = End {
            refs: 1,
            nonblock,
            waiters: [None; WAITERS],
        };
        self.pipes[index] = Pipe {
            live: true,
            creator,
            head: 0,
            len: 0,
            ends: [end; 2],
        };
        held.add(2 * index);
        held.add(2 * index + 1);
        Ok((2 * index as u32, 2 * index as u32 + 1))
    }

    /// Up to `out.len()` bytes of the read end `description`: Some(n) when
    /// done, n = 0 at the end of the data (no writer); None when the read
    /// waits; AGAIN for an empty pipe with NONBLOCK. A read wakes the
    /// writers.
    pub fn read(
        &mut self,
        held: &Held,
        description: u32,
        out: &mut [u8],
        wakes: &mut Wakes,
    ) -> Result<Option<usize>, u32> {
        let (index, end) = split(held, description, Some(false))?;
        let pipe = &mut self.pipes[index];
        if pipe.len == 0 {
            if pipe.ends[1].refs == 0 {
                return Ok(Some(0));
            }
            if pipe.ends[end].nonblock {
                return Err(AGAIN);
            }
            return Ok(None);
        }
        let n = out.len().min(usize::from(pipe.len));
        let ring = &self.rings[index];
        let head = usize::from(pipe.head);
        let first = n.min(CAPACITY - head);
        out[..first].copy_from_slice(&ring[head..head + first]);
        out[first..n].copy_from_slice(&ring[..n - first]);
        pipe.head = ((head + n) % CAPACITY) as u16;
        pipe.len -= n as u16;
        wakes.list = pipe.ends[1].waiters;
        Ok(Some(n))
    }

    /// `bytes` into the write end `description`: Some(n) for the bytes
    /// put, all of them up to ATOMIC, as many as there is room for past
    /// it; None when the write waits; BROKEN with no reader, AGAIN where
    /// it would wait with NONBLOCK. A write wakes the readers.
    pub fn write(
        &mut self,
        held: &Held,
        description: u32,
        bytes: &[u8],
        wakes: &mut Wakes,
    ) -> Result<Option<usize>, u32> {
        let (index, end) = split(held, description, Some(true))?;
        let pipe = &mut self.pipes[index];
        if pipe.ends[0].refs == 0 {
            return Err(BROKEN);
        }
        let room = CAPACITY - usize::from(pipe.len);
        let n = if bytes.len() <= ATOMIC {
            if room >= bytes.len() { bytes.len() } else { 0 }
        } else {
            room.min(bytes.len())
        };
        if n == 0 && !bytes.is_empty() {
            if pipe.ends[end].nonblock {
                return Err(AGAIN);
            }
            return Ok(None);
        }
        let ring = &mut self.rings[index];
        let tail = (usize::from(pipe.head) + usize::from(pipe.len)) % CAPACITY;
        let first = n.min(CAPACITY - tail);
        ring[tail..tail + first].copy_from_slice(&bytes[..first]);
        ring[..n - first].copy_from_slice(&bytes[first..n]);
        pipe.len += n as u16;
        wakes.list = pipe.ends[0].waiters;
        Ok(Some(n))
    }

    /// The operation `waiter` waits at `description`: FULL past WAITERS,
    /// after the operations `alive` says went are left out.
    pub fn wait(
        &mut self,
        description: u32,
        waiter: Waiter,
        alive: impl Fn(Waiter) -> bool,
    ) -> Result<(), u32> {
        let (index, is_write) = proto_pipe::end_of(description);
        let end = self
            .pipes
            .get_mut(index)
            .map(|p| &mut p.ends[is_write as usize])
            .ok_or(BAD_FD)?;
        if end.waiters.contains(&Some(waiter)) {
            return Ok(());
        }
        end.keep(alive);
        let free = end.waiters.iter_mut().find(|w| w.is_none()).ok_or(AGAIN)?;
        *free = Some(waiter);
        Ok(())
    }

    /// The operation `waiter` waits at `description` no more.
    pub fn unwait(&mut self, description: u32, waiter: Waiter) {
        let (index, is_write) = proto_pipe::end_of(description);
        if let Some(pipe) = self.pipes.get_mut(index) {
            pipe.ends[is_write as usize].keep(|w| w != waiter);
        }
    }

    /// CLOSE: the session lets go of `description`.
    pub fn close(
        &mut self,
        held: &mut Held,
        description: u32,
        wakes: &mut Wakes,
    ) -> Result<(), u32> {
        split(held, description, None)?;
        held.remove(description as usize);
        self.unref(description as usize, 1, wakes);
        Ok(())
    }

    /// `count` references of `description` go. Its last wakes the other
    /// end: the readers see the end of the data, the writers BROKEN; the
    /// pipe is free once neither end has any.
    fn unref(&mut self, description: usize, count: u16, wakes: &mut Wakes) {
        let (index, is_write) = proto_pipe::end_of(description as u32);
        let pipe = &mut self.pipes[index];
        let end = &mut pipe.ends[is_write as usize];
        debug_assert!(end.refs >= count, "the references of a description");
        end.refs = end.refs.saturating_sub(count);
        if end.refs != 0 {
            return;
        }
        end.waiters = [None; WAITERS];
        wakes.list = pipe.ends[!is_write as usize].waiters;
        if pipe.ends.iter().all(|e| e.refs == 0)
            && self.dropping[2 * index] == 0
            && self.dropping[2 * index + 1] == 0
        {
            *pipe = Pipe::FREE;
        }
    }

    /// The session of `held` went: each description it held is to let go
    /// of by `step`. Whether a step is due. O(HELD_MAX).
    pub fn gone(&mut self, held: &mut Held) -> bool {
        let mut bits = held.bits;
        while bits != 0 {
            let d = bits.trailing_zeros() as usize;
            bits &= bits - 1;
            self.dropping[d] += 1;
            self.dirty |= 1 << d;
        }
        held.bits = 0;
        self.dirty != 0
    }

    /// One description that sessions which went let go of: its references
    /// go (`unref`). Whether another step is due.
    pub fn step(&mut self, wakes: &mut Wakes) -> bool {
        if self.dirty == 0 {
            return false;
        }
        let d = self.dirty.trailing_zeros() as usize;
        self.dirty &= !(1 << d);
        let count = core::mem::take(&mut self.dropping[d]);
        self.unref(d, count, wakes);
        self.dirty != 0
    }

    /// Clone: a new session's holding of the descriptions `list` of
    /// `held`, each one more reference; BAD_FD for one it does not hold.
    pub fn clone_held(&mut self, held: &Held, list: &[u32]) -> Result<Held, u32> {
        let mut out = Held::default();
        for &d in list {
            if !held.holds(d) {
                return Err(BAD_FD);
            }
            out.add(d as usize);
        }
        let mut bits = out.bits;
        while bits != 0 {
            let d = bits.trailing_zeros() as usize;
            bits &= bits - 1;
            let (index, is_write) = proto_pipe::end_of(d as u32);
            self.pipes[index].ends[is_write as usize].refs += 1;
        }
        Ok(out)
    }

    /// GET_FLAGS of `description`.
    pub fn flags(&self, held: &Held, description: u32) -> Result<u32, u32> {
        let (index, end) = split(held, description, None)?;
        let nonblock = if self.pipes[index].ends[end].nonblock {
            NONBLOCK
        } else {
            0
        };
        Ok(nonblock | if end == 1 { WRITE_END } else { 0 })
    }

    /// SET_FLAGS of `description`: NONBLOCK alone.
    pub fn set_flags(&mut self, held: &Held, description: u32, flags: u32) -> Result<(), u32> {
        let (index, end) = split(held, description, None)?;
        if flags & !NONBLOCK != 0 {
            return Err(INVALID);
        }
        self.pipes[index].ends[end].nonblock = flags & NONBLOCK != 0;
        Ok(())
    }

    /// STAT of `description`: its pipe and the bytes in it.
    pub fn stat(&self, held: &Held, description: u32) -> Result<(u32, u32), u32> {
        let (index, _) = split(held, description, None)?;
        Ok((index as u32, u32::from(self.pipes[index].len)))
    }

    /// The pipes in use.
    pub fn live(&self) -> usize {
        self.pipes.iter().filter(|p| p.live).count()
    }
}

/// The long operations that wait for the sessions of one root at most: a
/// client of init's and the clones of its chain (the processes it forked
/// and spawned), so that one process tree cannot take all OPERATIONS of
/// the service; past them, AGAIN.
pub const ROOT_OPERATIONS: u16 = 32;

/// The operations that wait, counted for each root that has some: N
/// places, one for each operation the service may keep at most, so a root
/// with an operation always finds its place. O(N).
pub struct Roots<const N: usize> {
    list: [Option<(u64, u16)>; N],
}

impl<const N: usize> Default for Roots<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Roots<N> {
    pub const fn new() -> Self {
        Self { list: [None; N] }
    }

    /// One operation more for `root`: AGAIN at ROOT_OPERATIONS or with
    /// every place taken.
    pub fn take(&mut self, root: u64) -> Result<(), u32> {
        if let Some((_, count)) = self.list.iter_mut().flatten().find(|(r, _)| *r == root) {
            if *count >= ROOT_OPERATIONS {
                return Err(AGAIN);
            }
            *count += 1;
            return Ok(());
        }
        let free = self.list.iter_mut().find(|e| e.is_none()).ok_or(AGAIN)?;
        *free = Some((root, 1));
        Ok(())
    }

    /// `n` operations of `root` are over.
    pub fn give(&mut self, root: u64, n: u16) {
        if n == 0 {
            return;
        }
        if let Some(entry) = self
            .list
            .iter_mut()
            .find(|e| e.is_some_and(|(r, _)| r == root))
        {
            let (_, count) = entry.as_mut().expect("a found entry");
            debug_assert!(*count >= n, "the operations of a root");
            *count = count.saturating_sub(n);
            if *count == 0 {
                *entry = None;
            }
        }
    }

    /// The operations `root` has that wait.
    pub fn of(&self, root: u64) -> u16 {
        self.list
            .iter()
            .flatten()
            .find(|(r, _)| *r == root)
            .map_or(0, |(_, c)| *c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pipes() -> Box<Pipes> {
        Box::new(Pipes::new())
    }

    fn woke(w: &Wakes) -> Vec<Waiter> {
        w.iter().collect()
    }

    /// The writer in one session, the reader in another (a clone): the
    /// reader waits on an empty pipe, a write wakes it, and once the last
    /// writer closes it reads the end of the data.
    #[test]
    fn the_end_of_the_data_comes_after_the_last_writer_in_another_session() {
        let mut p = pipes();
        let mut a = Held::default();
        let (rd, wr) = p.create(&mut a, 1, 0).unwrap();
        let mut b = p.clone_held(&a, &[rd, wr]).unwrap();
        // The parent keeps the write end alone.
        p.close(&mut a, rd, &mut Wakes::default()).unwrap();
        let mut w = Wakes::default();
        p.close(&mut b, wr, &mut w).unwrap();
        assert!(woke(&w).is_empty(), "a writer is left");
        let mut out = [0; 8];
        assert_eq!(p.read(&b, rd, &mut out, &mut Wakes::default()), Ok(None));
        p.wait(rd, (2, 5), |_| true).unwrap();
        let mut w = Wakes::default();
        assert_eq!(p.write(&a, wr, b"hi", &mut w), Ok(Some(2)));
        assert_eq!(woke(&w), [(2, 5)]);
        assert_eq!(p.read(&b, rd, &mut out, &mut Wakes::default()), Ok(Some(2)));
        assert_eq!(&out[..2], b"hi");
        let mut w = Wakes::default();
        p.close(&mut a, wr, &mut w).unwrap();
        assert_eq!(woke(&w), [(2, 5)], "the last writer wakes the reader");
        assert_eq!(p.read(&b, rd, &mut out, &mut Wakes::default()), Ok(Some(0)));
    }

    /// A session that goes lets go of its descriptions in steps: the
    /// reader's end of the data comes once the step of the write end ran.
    #[test]
    fn the_end_of_the_data_comes_in_steps_after_the_session_goes() {
        let mut p = pipes();
        let mut a = Held::default();
        let (rd, wr) = p.create(&mut a, 1, 0).unwrap();
        let (rd2, wr2) = p.create(&mut a, 1, 0).unwrap();
        let b = p.clone_held(&a, &[rd, rd2]).unwrap();
        p.close(&mut a, rd, &mut Wakes::default()).unwrap();
        p.close(&mut a, rd2, &mut Wakes::default()).unwrap();
        p.wait(rd, (2, 7), |_| true).unwrap();
        p.wait(rd2, (2, 8), |_| true).unwrap();
        assert!(p.gone(&mut a));
        assert_eq!(a.count(), 0);
        let mut out = [0; 4];
        assert_eq!(
            p.read(&b, rd, &mut out, &mut Wakes::default()),
            Ok(None),
            "no step yet"
        );
        let mut w = Wakes::default();
        assert!(p.step(&mut w), "one step for each description");
        assert_eq!(woke(&w), [(2, 7)]);
        assert_eq!(p.read(&b, rd, &mut out, &mut Wakes::default()), Ok(Some(0)));
        let mut w = Wakes::default();
        assert!(!p.step(&mut w));
        assert_eq!(woke(&w), [(2, 8)]);
        assert_eq!(
            p.read(&b, rd2, &mut out, &mut Wakes::default()),
            Ok(Some(0))
        );
        let _ = (wr, wr2);
    }

    /// No reader: BROKEN; the writer that waited is woken by the last
    /// reader's close.
    #[test]
    fn a_write_without_a_reader_is_broken() {
        let mut p = pipes();
        let mut a = Held::default();
        let (rd, wr) = p.create(&mut a, 1, 0).unwrap();
        assert_eq!(
            p.write(&a, wr, &[1; 1000], &mut Wakes::default()),
            Ok(Some(1000))
        );
        assert_eq!(
            p.write(&a, wr, &[1; 4000], &mut Wakes::default()),
            Ok(Some(3096))
        );
        assert_eq!(p.write(&a, wr, b"x", &mut Wakes::default()), Ok(None));
        p.wait(wr, (1, 3), |_| true).unwrap();
        let mut w = Wakes::default();
        p.close(&mut a, rd, &mut w).unwrap();
        assert_eq!(woke(&w), [(1, 3)]);
        assert_eq!(p.write(&a, wr, b"x", &mut Wakes::default()), Err(BROKEN));
    }

    /// A write of ATOMIC bytes waits whole with ATOMIC - 1 free; one of
    /// 600 goes in part.
    #[test]
    fn writes_up_to_atomic_go_whole() {
        let mut p = pipes();
        let mut a = Held::default();
        let (rd, wr) = p.create(&mut a, 1, 0).unwrap();
        let fill = CAPACITY - (ATOMIC - 1);
        assert_eq!(
            p.write(&a, wr, &vec![1; fill], &mut Wakes::default()),
            Ok(Some(fill))
        );
        assert_eq!(
            p.write(&a, wr, &[2; ATOMIC], &mut Wakes::default()),
            Ok(None)
        );
        assert_eq!(
            p.write(&a, wr, &[3; 600], &mut Wakes::default()),
            Ok(Some(ATOMIC - 1))
        );
        let mut out = vec![0; CAPACITY];
        let mut taken = 0;
        while taken < CAPACITY {
            let n = p
                .read(&a, rd, &mut out[taken..], &mut Wakes::default())
                .unwrap()
                .unwrap();
            taken += n;
        }
        assert!(out[..fill].iter().all(|&b| b == 1));
        assert!(out[fill..].iter().all(|&b| b == 3));
        // The ring wraps: bytes written across its end come back in order.
        let bytes: Vec<u8> = (0..ATOMIC as u32).map(|i| i as u8).collect();
        assert_eq!(
            p.write(&a, wr, &bytes, &mut Wakes::default()),
            Ok(Some(ATOMIC))
        );
        let mut back = [0; ATOMIC];
        assert_eq!(
            p.read(&a, rd, &mut back, &mut Wakes::default()),
            Ok(Some(ATOMIC))
        );
        assert_eq!(back.as_slice(), bytes.as_slice());
    }

    /// O_NONBLOCK ([write], [read]): an empty pipe AGAIN; up to ATOMIC
    /// whole or AGAIN; past it a part or AGAIN when full; the flag is the
    /// description's, shared by its sessions.
    #[test]
    fn nonblock_answers_again() {
        let mut p = pipes();
        let mut a = Held::default();
        let (rd, wr) = p.create(&mut a, 1, NONBLOCK).unwrap();
        let b = p.clone_held(&a, &[rd, wr]).unwrap();
        let mut out = [0; 4];
        assert_eq!(p.read(&a, rd, &mut out, &mut Wakes::default()), Err(AGAIN));
        let fill = CAPACITY - 100;
        assert_eq!(
            p.write(&a, wr, &vec![1; fill], &mut Wakes::default()),
            Ok(Some(fill))
        );
        assert_eq!(
            p.write(&a, wr, &[1; 200], &mut Wakes::default()),
            Err(AGAIN)
        );
        assert_eq!(
            p.write(&a, wr, &[1; 600], &mut Wakes::default()),
            Ok(Some(100))
        );
        assert_eq!(
            p.write(&a, wr, &[1; 600], &mut Wakes::default()),
            Err(AGAIN)
        );
        p.set_flags(&b, wr, 0).unwrap();
        assert_eq!(p.flags(&a, wr), Ok(WRITE_END), "the description's flag");
        assert_eq!(p.write(&a, wr, &[1; 600], &mut Wakes::default()), Ok(None));
        assert_eq!(p.flags(&a, rd), Ok(NONBLOCK));
        assert_eq!(p.set_flags(&a, rd, 4), Err(INVALID));
    }

    /// Clone counts its references: the end of the data waits for the
    /// clone's writer too, and a description held by no session of the
    /// list is BAD_FD.
    #[test]
    fn clone_shares_the_counts() {
        let mut p = pipes();
        let mut a = Held::default();
        let (rd, wr) = p.create(&mut a, 1, 0).unwrap();
        let mut b = p.clone_held(&a, &[wr]).unwrap();
        assert!(!b.holds(rd));
        assert_eq!(p.clone_held(&b, &[rd]), Err(BAD_FD));
        p.close(&mut a, wr, &mut Wakes::default()).unwrap();
        let mut out = [0; 2];
        assert_eq!(
            p.read(&a, rd, &mut out, &mut Wakes::default()),
            Ok(None),
            "the clone writes"
        );
        assert_eq!(p.write(&b, wr, b"ok", &mut Wakes::default()), Ok(Some(2)));
        assert_eq!(p.read(&b, rd, &mut out, &mut Wakes::default()), Err(BAD_FD));
        p.close(&mut b, wr, &mut Wakes::default()).unwrap();
        assert_eq!(p.read(&a, rd, &mut out, &mut Wakes::default()), Ok(Some(2)));
        assert_eq!(p.read(&a, rd, &mut out, &mut Wakes::default()), Ok(Some(0)));
        assert_eq!(p.close(&mut b, wr, &mut Wakes::default()), Err(BAD_FD));
    }

    /// The limits: PIPES pipes in the service (NFILE), CREATED_MAX live
    /// pipes of one creator and HELD_MAX descriptions of a session
    /// (MFILE), WAITERS operations at one end (AGAIN, after the ones that
    /// went are left out).
    #[test]
    fn the_limits_hold() {
        let mut p = pipes();
        let mut sessions = [Held::default(); 4];
        for (i, s) in sessions.iter_mut().enumerate() {
            for _ in 0..CREATED_MAX {
                let (rd, _) = p.create(s, i as u64, 0).unwrap();
                // The write end keeps the pipe live; the session holds 16.
                p.close(s, rd, &mut Wakes::default()).unwrap();
            }
            assert_eq!(s.count(), CREATED_MAX);
            assert_eq!(p.create(s, i as u64, 0), Err(MFILE), "the creator's 17th");
        }
        assert_eq!(p.live(), PIPES);
        let mut more = Held::default();
        assert_eq!(p.create(&mut more, 9, 0), Err(NFILE), "the 65th pipe");
        let mut w = Wakes::default();
        p.close(&mut sessions[0], 1, &mut w).unwrap();
        assert_eq!(p.live(), PIPES - 1);
        let (rd, _) = p.create(&mut more, 9, 0).unwrap();
        for k in 0..WAITERS as u64 {
            p.wait(rd, (5, k + 1), |_| true).unwrap();
        }
        assert_eq!(p.wait(rd, (5, 99), |_| true), Err(AGAIN), "the 9th waiter");
        p.wait(rd, (5, 99), |w| w.1 != 1).unwrap();
        // HELD_MAX descriptions: the write ends of two sessions' pipes in
        // one clone, which may create no pipe.
        let mut c = p.clone_held(&sessions[1], &[]).unwrap();
        for s in &sessions[1..3] {
            let bits = p.clone_held(s, &(0..128).filter(|&d| s.holds(d)).collect::<Vec<_>>());
            c.bits |= bits.unwrap().bits;
        }
        assert_eq!(c.count(), HELD_MAX);
        assert_eq!(p.create(&mut c, 77, 0), Err(MFILE));
    }

    /// The waiters of an end are a queue: after a read the writer that
    /// waited first is told first, and one that waits again (a part of
    /// its write went) queues behind the others.
    #[test]
    fn waiters_are_told_in_the_order_they_came() {
        let mut p = pipes();
        let mut a = Held::default();
        let (rd, wr) = p.create(&mut a, 1, 0).unwrap();
        assert_eq!(
            p.write(&a, wr, &[0; CAPACITY], &mut Wakes::default()),
            Ok(Some(CAPACITY))
        );
        for k in 1..=3 {
            p.wait(wr, (7, k), |_| true).unwrap();
        }
        let mut w = Wakes::default();
        let mut out = [0; 100];
        p.read(&a, rd, &mut out, &mut w).unwrap();
        assert_eq!(woke(&w), [(7, 1), (7, 2), (7, 3)]);
        // The first went with a part, and waits again with a new key.
        p.unwait(wr, (7, 1));
        p.wait(wr, (7, 4), |_| true).unwrap();
        let mut w = Wakes::default();
        p.read(&a, rd, &mut out, &mut w).unwrap();
        assert_eq!(woke(&w), [(7, 2), (7, 3), (7, 4)]);
        // Those that went are left out, and the queue keeps its order.
        p.wait(wr, (7, 5), |k| k.1 != 3).unwrap();
        let mut w = Wakes::default();
        p.read(&a, rd, &mut out, &mut w).unwrap();
        assert_eq!(woke(&w), [(7, 2), (7, 4), (7, 5)]);
    }

    /// A root has ROOT_OPERATIONS that wait at most, others have theirs.
    #[test]
    fn roots_bound_the_operations_of_a_tree() {
        let mut r = Roots::<128>::new();
        for _ in 0..ROOT_OPERATIONS {
            r.take(5).unwrap();
        }
        assert_eq!(r.take(5), Err(AGAIN));
        assert_eq!(r.take(6), Ok(()));
        r.give(5, 2);
        assert_eq!(r.of(5), ROOT_OPERATIONS - 2);
        assert_eq!(r.take(5), Ok(()));
        r.give(5, ROOT_OPERATIONS - 1);
        r.give(6, 1);
        assert_eq!((r.of(5), r.of(6)), (0, 0));
        assert!(r.list.iter().all(Option::is_none), "places go back");
    }

    /// `dup` in a process and the close of one of its descriptors leave
    /// the description held: the process's table counts its descriptors,
    /// the service its sessions. A second close of the same session is
    /// BAD_FD and takes no reference of another session.
    #[test]
    fn a_session_is_one_reference() {
        let mut p = pipes();
        let mut a = Held::default();
        let (rd, wr) = p.create(&mut a, 1, 0).unwrap();
        let mut b = p.clone_held(&a, &[wr]).unwrap();
        p.close(&mut b, wr, &mut Wakes::default()).unwrap();
        assert_eq!(p.close(&mut b, wr, &mut Wakes::default()), Err(BAD_FD));
        let mut out = [0; 1];
        assert_eq!(
            p.read(&a, rd, &mut out, &mut Wakes::default()),
            Ok(None),
            "a writer is left"
        );
        assert_eq!(p.stat(&a, wr), Ok((0, 0)));
    }
}
