// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The sessions a service gave its clients' children with Clone (spec 2,
//! 3.7; 5c), counted: each takes a slot of the service's channel and room
//! in its table of sessions, so a client has PER_CLIENT of them alive at
//! most and the service N. A clone counts until the end of its last copy
//! (CLIENT_GONE of its label).

/// The live clones of each client at most.
pub const PER_CLIENT: usize = 48;

/// Why a Clone is refused: the client or the service has its most.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full;

/// The live clones of a service: each one's label and its client's.
pub struct Clones<const N: usize> {
    live: [Option<(u64, u64)>; N],
}

impl<const N: usize> Default for Clones<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Clones<N> {
    pub const fn new() -> Self {
        Self { live: [None; N] }
    }

    /// Whether `client` may have one clone more.
    pub fn room(&self, client: u64) -> Result<(), Full> {
        self.room_within(client, PER_CLIENT)
    }

    /// Whether `client` may have one clone more with `most` of its own at
    /// most, for a service that counts its clients otherwise (the pipe
    /// service counts the clones of a whole tree of processes).
    pub fn room_within(&self, client: u64, most: usize) -> Result<(), Full> {
        let own = self
            .live
            .iter()
            .flatten()
            .filter(|(_, c)| *c == client)
            .count();
        if own >= most || self.live.iter().all(Option::is_some) {
            return Err(Full);
        }
        Ok(())
    }

    /// The clone `label` of `client` is alive; Full past the limits.
    pub fn add(&mut self, label: u64, client: u64) -> Result<(), Full> {
        self.add_within(label, client, PER_CLIENT)
    }

    /// `add` with `most` clones of `client` at most (`room_within`).
    pub fn add_within(&mut self, label: u64, client: u64, most: usize) -> Result<(), Full> {
        self.room_within(client, most)?;
        let free = self.live.iter_mut().find(|l| l.is_none()).ok_or(Full)?;
        *free = Some((label, client));
        Ok(())
    }

    /// The client the live clone `label` was made for, if it is one.
    pub fn client_of(&self, label: u64) -> Option<u64> {
        self.live
            .iter()
            .flatten()
            .find(|(l, _)| *l == label)
            .map(|(_, c)| *c)
    }

    /// The last copy of the clone `label` went.
    pub fn gone(&mut self, label: u64) {
        if let Some(slot) = self
            .live
            .iter_mut()
            .find(|l| l.is_some_and(|(l, _)| l == label))
        {
            *slot = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client has PER_CLIENT live clones: the next is refused until one
    /// goes; the service's N bound all clients.
    #[test]
    fn clones_are_bounded_per_client_and_in_all() {
        let mut c = Clones::<64>::new();
        for i in 0..PER_CLIENT as u64 {
            assert_eq!(c.add(100 + i, 7), Ok(()));
        }
        assert_eq!(c.add(999, 7), Err(Full), "one more of client 7");
        assert_eq!(c.add(999, 8), Ok(()), "another client's");
        c.gone(100);
        assert_eq!(c.add(1000, 7), Ok(()));
        for i in 0..15 {
            assert_eq!(c.add(2000 + i, 9), Ok(()));
        }
        assert_eq!(c.add(3000, 10), Err(Full), "the service's 64");
        assert_eq!(c.client_of(1000), Some(7));
        assert_eq!(c.client_of(100), None, "gone");
    }
}
