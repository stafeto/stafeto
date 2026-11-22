// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Leases on files: the atomicity of one call of any size (`proto_data`, "Parts and leases").
//!
//! A call larger than a cell goes in parts. The first part (`MORE`, lease 0) takes a lease on the
//! file the description names: a write lease for WRITE_FROM and PWRITE_FROM, a read lease for
//! READ_INTO and PREAD_INTO. While a write lease is held, the jobs of other calls that touch the file
//! (a read, a write, a truncation, a `fstat` or `stat`, an open with truncation) wait; while a read
//! lease is held, the writes and truncations wait and the reads go on. The parts of the holder carry
//! the lease number and run. The last part (no `MORE`), a part that a limit stopped or that failed, a
//! RELEASE, the end of the session and a gap of `LEASE_GAP_NS` after a part with no next one end the
//! lease; a part that comes after the lapse runs as a call of its own and is answered `LAPSED`.
//!
//! The worker does not run a job that has to wait: `Server::pick` chooses among the queued jobs the
//! one to run, which is the oldest one that no lease holds back, and a part of the holder is put at
//! the place of the oldest job that waits for the file (so the holder does not queue behind those who
//! wait for it, and they wait no longer than its call lasts). A new read lease waits behind a writer
//! that waits, so that a stream of readers cannot starve it. A file nobody holds is served as before;
//! the jobs on other files never wait for a lease.

use super::*;

/// How long a lease lives with no part after the answer to the last one, in nanoseconds.
pub const LEASE_GAP_NS: u64 = 1_000_000_000;

/// The queued jobs `pick` looks at: the most it takes in one call.
pub const CANDIDATES_MAX: usize = 32;

#[derive(Clone, Copy)]
pub(super) struct Lease {
    pub(super) used: bool,
    /// The generation of the last lease of the slot (1 to 255, then again from 1): a number made of
    /// an earlier one is told from the live one.
    pub(super) generation: u8,
    pub(super) owner: u64,
    pub(super) description: u8,
    pub(super) node: u8,
    pub(super) write: bool,
    /// The instant after which the lease lapses, on the clock `set_mono` gives.
    pub(super) expires: u64,
}

impl Lease {
    pub(super) const EMPTY: Lease = Lease {
        used: false,
        generation: 0,
        owner: 0,
        description: 0,
        node: 0,
        write: false,
        expires: 0,
    };
}

/// What a lease number is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Number {
    /// A lease that is held.
    Live(usize),
    /// A lease of this instance that has ended or lapsed.
    Ended,
    /// A number of an earlier instance (a restart since it was given).
    Stale,
    /// A number the service never gave.
    Never,
}

/// A queued job, as `pick` sees it: the place in the job table, the order of arrival, the session it
/// came from and the request.
#[derive(Clone, Copy)]
pub struct Candidate<'a> {
    pub id: usize,
    pub ticket: u64,
    pub owner: u64,
    pub request: &'a [u8],
}

/// What a job does to a file: the node, whether it changes it, the lease it runs under and whether
/// it asks for one.
#[derive(Clone, Copy, Default)]
struct Wants {
    node: Option<usize>,
    write: bool,
    holder: bool,
    takes: bool,
}

impl Server {
    /// Sets the clock of the leases, in nanoseconds (monotonic), before a job.
    pub fn set_mono(&mut self, ns: u64) {
        self.mono = ns;
    }

    pub(super) fn lease_number(&self, slot: usize) -> u32 {
        (self.epoch << EPOCH_BITS)
            | (u32::from(self.leases[slot].generation) << 8)
            | (slot as u32 + 1)
    }

    /// What `number` names now.
    pub(super) fn lease_lookup(&self, number: u32) -> Number {
        let epoch = number >> EPOCH_BITS;
        if epoch == 0 {
            return Number::Never;
        }
        if epoch != self.epoch {
            return Number::Stale;
        }
        let Some(slot) = ((number & 0xFF) as usize)
            .checked_sub(1)
            .filter(|&s| s < p::LEASES)
        else {
            return Number::Never;
        };
        let generation = ((number >> 8) & 0xFF) as u8;
        let l = &self.leases[slot];
        if l.used && l.generation == generation {
            Number::Live(slot)
        } else if l.generation != 0
            && generation != 0
            && l.generation.wrapping_sub(generation) < 128
        {
            // Not ahead of the last one the slot gave: it was given and is over.
            Number::Ended
        } else {
            Number::Never
        }
    }

    /// A lease of `owner` on `node` for the description `di`, or None at a limit (`LEASES_PER_SESSION`
    /// for the session, `LEASES` for the service) or when the description cannot take one more
    /// reference. The description keeps its reference until the lease ends, so a CLOSE in the middle
    /// of a call does not end it.
    pub(super) fn lease_take(
        &mut self,
        owner: u64,
        di: usize,
        node: usize,
        write: bool,
    ) -> Option<u32> {
        if self
            .leases
            .iter()
            .filter(|l| l.used && l.owner == owner)
            .count()
            >= p::LEASES_PER_SESSION
            || self.descriptions[di].refs == u8::MAX
        {
            return None;
        }
        let slot = self.leases.iter().position(|l| !l.used)?;
        let l = &mut self.leases[slot];
        l.generation = if l.generation == u8::MAX {
            1
        } else {
            l.generation + 1
        };
        *l = Lease {
            used: true,
            generation: l.generation,
            owner,
            description: di as u8,
            node: node as u8,
            write,
            expires: self.mono.saturating_add(LEASE_GAP_NS),
        };
        self.descriptions[di].refs += 1;
        Some(self.lease_number(slot))
    }

    /// The lease `slot` goes on for another gap.
    pub(super) fn lease_renew(&mut self, slot: usize) {
        self.leases[slot].expires = self.mono.saturating_add(LEASE_GAP_NS);
    }

    /// The lease `slot` ends: its reference of the description goes.
    pub(super) fn lease_end<D: Device>(&mut self, fs: &mut Fs<'_, D>, slot: usize) {
        if !self.leases[slot].used {
            return;
        }
        self.leases[slot].used = false;
        let di = usize::from(self.leases[slot].description);
        let _ = self.deref(fs, di);
    }

    /// The leases of the session `label` end (the session went, or ran a new image).
    pub fn leases_end_of<D: Device>(&mut self, fs: &mut Fs<'_, D>, label: u64) {
        for slot in 0..p::LEASES {
            if self.leases[slot].used && self.leases[slot].owner == label {
                self.lease_end(fs, slot);
            }
        }
    }

    /// Every lease ends (the service stops): the jobs that wait for one run.
    pub fn leases_end_all<D: Device>(&mut self, fs: &mut Fs<'_, D>) {
        for slot in 0..p::LEASES {
            self.lease_end(fs, slot);
        }
    }

    /// The leases whose gap is over end. Called before the worker chooses a job.
    pub fn leases_sweep<D: Device>(&mut self, fs: &mut Fs<'_, D>) {
        for slot in 0..p::LEASES {
            if self.leases[slot].used && self.leases[slot].expires <= self.mono {
                self.lease_end(fs, slot);
            }
        }
    }

    /// The instant the first lease lapses, None when no lease is held: the worker wakes then.
    pub fn next_lease_expiry(&self) -> Option<u64> {
        self.leases
            .iter()
            .filter(|l| l.used)
            .map(|l| l.expires)
            .min()
    }

    /// The leases held now.
    pub fn lease_count(&self) -> usize {
        self.leases.iter().filter(|l| l.used).count()
    }

    /// The node and the lease of a request, as far as the request names them.
    fn wants(&self, owner: u64, request: &[u8]) -> Wants {
        let none = Wants::default();
        let mut r = Reader::new(request);
        let Ok(header) = Header::read(&mut r) else {
            return none;
        };
        if header.version != p::VERSION {
            return none;
        }
        let Some(method) = Method::from_number(header.method) else {
            return none;
        };
        let Some(si) = self
            .sessions
            .iter()
            .position(|s| s.used && s.label == owner)
        else {
            // A session the server has not seen holds no description and no lease.
            return none;
        };
        let file_node = |handle: u32| -> Option<usize> {
            let di = self.find(si, handle).ok()?;
            let d = &self.descriptions[di];
            (d.kind == Kind::File).then_some(usize::from(d.object))
        };
        match method {
            Method::Read
            | Method::Pread
            | Method::Write
            | Method::Pwrite
            | Method::Truncate
            | Method::Fstat => {
                let Ok(handle) = r.u32() else { return none };
                Wants {
                    node: file_node(handle),
                    write: matches!(method, Method::Write | Method::Pwrite | Method::Truncate),
                    ..none
                }
            }
            Method::ReadInto | Method::PreadInto | Method::WriteFrom | Method::PwriteFrom => {
                let Ok(part) = p::read_part(method, r) else {
                    return none;
                };
                let write = matches!(method, Method::WriteFrom | Method::PwriteFrom);
                if part.part.lease != 0
                    && let Number::Live(slot) = self.lease_lookup(part.part.lease)
                    && self.leases[slot].owner == owner
                {
                    return Wants {
                        node: Some(usize::from(self.leases[slot].node)),
                        write: self.leases[slot].write,
                        holder: true,
                        takes: false,
                    };
                }
                Wants {
                    node: file_node(part.part.handle),
                    write,
                    holder: false,
                    takes: part.part.lease == 0 && part.part.flags & p::MORE != 0,
                }
            }
            Method::Stat | Method::Open => {
                let mut path = [0u8; MAX_PATH];
                let raw = if method == Method::Open {
                    match p::read_open(r) {
                        Ok((flags, _, raw)) if flags & p::TRUNCATE != 0 => raw,
                        _ => return none,
                    }
                } else {
                    match r.bytes(r.left()) {
                        Ok(raw) => raw,
                        Err(_) => return none,
                    }
                };
                let Ok(n) = canonical(raw, &mut path) else {
                    return none;
                };
                Wants {
                    node: self.node_at(&path[..n]),
                    write: method == Method::Open,
                    ..none
                }
            }
            _ => none,
        }
    }

    /// Whether a lease on the file holds the job back: any other call waits for a write lease, and a
    /// write waits for a read lease. The holder's own parts are never held back.
    fn held_back(&self, w: &Wants) -> bool {
        let Some(node) = w.node else { return false };
        if w.holder {
            return false;
        }
        self.leases
            .iter()
            .any(|l| l.used && usize::from(l.node) == node && (l.write || w.write))
    }

    /// The job to run next among the queued ones: None when no job can run (all wait for a lease, or
    /// there are none). The oldest job that no lease holds back, by its place in the queue: a part of
    /// a holder takes the place of the oldest job that waits for the same file, and a job that asks
    /// for a new read lease waits behind a writer that waits for the file and came before it.
    pub fn pick(&self, jobs: &[Candidate<'_>]) -> Option<usize> {
        let n = jobs.len().min(CANDIDATES_MAX);
        let mut wants = [Wants::default(); CANDIDATES_MAX];
        let mut held = [false; CANDIDATES_MAX];
        for i in 0..n {
            wants[i] = self.wants(jobs[i].owner, jobs[i].request);
            held[i] = self.held_back(&wants[i]);
        }
        let mut best: Option<(u64, u64, usize)> = None;
        for i in 0..n {
            if held[i] {
                continue;
            }
            let (w, ticket) = (&wants[i], jobs[i].ticket);
            let waiting = |k: usize| held[k] && wants[k].node == w.node && w.node.is_some();
            // A new read lease waits behind a writer that waits.
            if w.takes
                && !w.write
                && (0..n).any(|k| k != i && waiting(k) && wants[k].write && jobs[k].ticket < ticket)
            {
                continue;
            }
            // A part of the holder takes the place of the oldest job that waits for the file.
            let mut place = ticket;
            if w.holder {
                for k in (0..n).filter(|&k| k != i && waiting(k)) {
                    place = place.min(jobs[k].ticket);
                }
            }
            if best.is_none_or(|(p, t, _)| (place, ticket) < (p, t)) {
                best = Some((place, ticket, i));
            }
        }
        best.map(|(_, _, i)| jobs[i].id)
    }
}
