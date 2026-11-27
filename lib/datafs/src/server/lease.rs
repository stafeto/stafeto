// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Leases on files: the atomicity of one call of any size (`proto_data`, "Parts and leases").
//!
//! A call larger than a cell goes in parts. The first part (`MORE`, lease 0) takes a lease on the
//! file the description names: a write lease for WRITE_FROM and PWRITE_FROM, a read lease for
//! READ_INTO and PREAD_INTO. While a write lease is held, the jobs of other calls that touch the file
//! (a read, a write, a truncation, a seek, a `fstat` or `stat`, an open with truncation) wait; while a
//! read lease is held, the writes, truncations and seeks wait and the reads go on. The parts of the
//! holder carry the lease number and run, one at a time and in the order they came. The last part
//! (no `MORE`), a part that a limit stopped or that failed, a RELEASE, the end of the session and the
//! lapse end the lease. The call takes the `APPEND` and `SYNC` of its description at its first part.
//!
//! A lease lapses when no next part has come `LEASE_GAP_NS` after the answer to the last one, and,
//! while jobs of the file wait for it, when the time the client has taken between parts, summed over
//! the whole lease (the gap from the answer to a part to the arrival of the next), passes
//! `LEASE_CLIENT_MAX_NS`. A part that comes after a lapse is NOT run: it is answered `LAPSED` with a
//! count of 0, and the layer returns the sum of the parts done (a short `read` or `write`). With
//! `SYNC` the node is synced when the lease lapses, before that answer. A lease whose next part is
//! queued does not lapse by the gap: the queue is not the holder's fault.
//!
//! The worker does not run a job that has to wait: `Server::pick` chooses among the queued jobs the
//! one to run, which is the oldest one that no lease holds back, and a part of the holder is put at
//! the place of the oldest job that waits for the file (so the holder does not queue behind those who
//! wait for it, and they wait no longer than its call lasts). A new read lease waits behind a writer
//! that waits, so that a stream of readers cannot starve it, and a part that would take a lease
//! beyond the limits waits until one ends. A file nobody holds is served as before; the jobs on other
//! files never wait for a lease.
//!
//! The bound of the wait of a job for a file, for `docs/data.md`: a job of another file waits no more
//! than W (`docs/data.md`), as before. A job that waits for a file waits at most
//!
//! ```text
//! W_lease <= W + sum over the holders ahead [ n_i * (T_part + T_job + 2 * T_slice) + LEASE_CLIENT_MAX ] + T_tail
//! ```
//!
//! where a holder ahead is a lease on the file, or an older waiting call that takes a lease (a new
//! read lease does not queue behind a waiting writer, so it is not ahead of it), `n_i` is the number of
//! parts the holder has left, `ceil(count / 64 KiB)`, `T_part` is one job of a part, `T_job` one
//! job of another file that runs between two parts and `T_slice` one step of a copy of a tail (a step
//! runs after every job, so one after the part and one after the job between).
//!
//! `T_tail` is the cost of the tail of a rewrite that stopped. When a call that rewrites a file from
//! the middle lapses, littlefs has to write out everything past the last byte written
//! (`lfs_file_flush`: a copy of `size - stop_position`). The copy has no bound of its own but
//! `FILE_MAX`, it is about a second per MiB of the file past the stopped write on QEMU (a Mac with
//! Apple silicon; the GitHub runners take 2.6 times as long). The service runs it in steps of
//! `TAIL_SLICE_BLOCKS` blocks, one step after every job and in the idle time (`tail.rs`, issue #626).
//! The waiter for the file waits for the steps of every tail that runs, since the steps take turns
//! across the tails: `T_tail` is the sum of the tails running, in steps, each with the job that runs
//! before it. A file that is only appended to or made again has no tail. The lapse itself comes
//! within the wake of the timer after the gap, and the waiter is chosen at once after it
//! (`Server::lapse`), when it has no tail to wait for.

use super::*;

/// How long a lease lives with no part after the answer to the last one, in nanoseconds (the policy
/// of the service, `LEASE_GAP` of the protocol text).
pub const LEASE_GAP_NS: u64 = 1_000_000_000;

/// The most client time a lease may take while jobs of its file wait for it, in nanoseconds: the sum
/// of the gaps from the answer to a part to the arrival of the next, over the whole lease. Without a
/// waiter the lease lives on by the gap alone.
pub const LEASE_CLIENT_MAX_NS: u64 = 1_000_000_000;

/// The queued jobs `pick` looks at: the most it takes in one call. Every job of the table is one.
pub const CANDIDATES_MAX: usize = 32;
const _: () = assert!(CANDIDATES_MAX >= crate::admit::JOBS);

#[derive(Clone, Copy)]
pub(super) struct Lease {
    pub(super) used: bool,
    /// The generation of the last lease of the slot (1 to 255, then again from 1): a number made of
    /// an earlier one is told from the live one. It is 8 bits, so a number that is 128 or more
    /// leases of its slot old is taken for one that was never given (it answers BAD_HANDLE where LAPSED is true), and a
    /// number 256 leases old for the live lease: a call keeps its number for a few parts, and a slot
    /// is not given out 256 times in one call.
    pub(super) generation: u8,
    pub(super) owner: u64,
    pub(super) description: u8,
    pub(super) node: u8,
    pub(super) write: bool,
    /// The `APPEND` and `SYNC` of the description at the first part: a call goes on with them even
    /// if SET_FLAGS changes the description in the middle of it.
    pub(super) append: bool,
    pub(super) sync: bool,
    /// A part ran since the clock was last read: the gap counts from the answer to it, which the
    /// worker stamps (`leases_stamp`) after the job, so that the time of the part is not in the gap.
    pub(super) stamp: bool,
    /// The instant of the answer to the last part, on the clock `set_mono` gives, and the client time
    /// of the lease so far: the sum of the gaps from an answer to the arrival of the next part.
    pub(super) answered: u64,
    pub(super) client: u64,
    /// The instant the worker wakes to look at the lease again: the gap after the answer, and, while
    /// jobs of the file wait, the earlier instant the client time reaches its bound. Set by the sweep
    /// from the jobs it looked at, so that the timer never fires for a lapse that cannot come.
    pub(super) expiry: u64,
}

impl Lease {
    pub(super) const EMPTY: Lease = Lease {
        used: false,
        generation: 0,
        owner: 0,
        description: 0,
        node: 0,
        write: false,
        append: false,
        sync: false,
        stamp: false,
        answered: 0,
        client: 0,
        expiry: 0,
    };
}

/// The last lapse of a lease that jobs of its file waited for, for the probes: the instants are on
/// the clock `set_mono` gives, in nanoseconds (all 0 before the first one).
///
/// The waiter is the oldest job of the file that was queued when the sweep ended the lease; it is
/// found again by its `queued_at`. A waiter that leaves the queue without being chosen (its session
/// goes) leaves `ran` at 0 and no line is told, and when two leases lapse in one sweep the later
/// one overwrites the record: the probes run one lapse at a time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lapse {
    /// The answer to the last part of the lease.
    pub answered: u64,
    /// The instant the worker's timer was set to look at the lease (`expiry`): the gap after the
    /// answer, or, with a waiter, the sooner instant the client time reaches its bound.
    pub expiry: u64,
    /// The instant the oldest waiting job was queued.
    pub queued: u64,
    /// The instant the sweep ended the lease.
    pub at: u64,
    /// The instant the waiter was chosen to run (0 until it is).
    pub ran: u64,
    /// How many lapses with a waiter there have been.
    pub count: u64,
    /// The record of the lapse was told (`lapse_told`).
    pub told: bool,
    /// The steps of a copy of a tail (`tail.rs`) the worker ran between the lapse and the choice
    /// of the waiter: the waiter of a file with a tail waits for them.
    pub steps: u32,
}

impl Lapse {
    /// No lapse yet (a constant, as `Lease::EMPTY` is: `Server::new` is a `const fn`).
    pub(super) const EMPTY: Lapse = Lapse {
        answered: 0,
        expiry: 0,
        queued: 0,
        at: 0,
        ran: 0,
        count: 0,
        told: false,
        steps: 0,
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
    /// The instant the request thread queued it, on the clock `set_mono` gives.
    pub queued_at: u64,
    pub request: &'a [u8],
}

/// What a job does to a file: the node, whether it changes it, the lease it runs under and whether
/// it asks for one.
#[derive(Clone, Copy, Default)]
struct Wants {
    node: Option<usize>,
    write: bool,
    /// The lease the job runs under (a live lease of its session).
    holder: Option<usize>,
    takes: bool,
    /// The node whose unfinished tail (`tail.rs`) the job would flush, and whether the job is a
    /// write that goes on where the last one stopped, which does not flush it.
    flushes: Option<(usize, bool)>,
    /// A second node it would flush: the file a rename replaces.
    flushes_too: Option<usize>,
}

impl Server {
    /// Sets the clock of the leases, in nanoseconds (monotonic), before a job.
    pub fn set_mono(&mut self, ns: u64) {
        self.mono = ns;
        if let Some(began) = self.walk_began.take() {
            self.walk_after = ns.saturating_add(4 * ns.saturating_sub(began));
        }
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
        if !self.lease_free_for(owner) || self.descriptions[di].refs == u8::MAX {
            return None;
        }
        let slot = self.leases.iter().position(|l| !l.used)?;
        let generation = match self.leases[slot].generation {
            u8::MAX => 1,
            g => g + 1,
        };
        let d = self.descriptions[di];
        self.leases[slot] = Lease {
            used: true,
            generation,
            owner,
            description: di as u8,
            node: node as u8,
            write,
            append: d.append,
            sync: d.sync,
            stamp: true,
            answered: self.mono,
            client: 0,
            expiry: self.mono.saturating_add(LEASE_GAP_NS),
        };
        self.descriptions[di].refs += 1;
        Some(self.lease_number(slot))
    }

    /// Whether `owner` may take one more lease: a session has `LEASES_PER_SESSION`, the service
    /// `LEASES`. A part that would take one and cannot waits (`pick`) until a lease ends.
    pub(super) fn lease_free_for(&self, owner: u64) -> bool {
        self.leases.iter().any(|l| !l.used)
            && self
                .leases
                .iter()
                .filter(|l| l.used && l.owner == owner)
                .count()
                < p::LEASES_PER_SESSION
    }

    /// The lease `slot` goes on for another gap, counted from the answer to the part that ran: the
    /// worker reads the clock after the job and `leases_stamp` sets the instant.
    pub(super) fn lease_renew(&mut self, slot: usize) {
        if cfg!(feature = "break-datafs-lease-renew") {
            return;
        }
        self.leases[slot].stamp = true;
    }

    /// The gap of every lease a part ran under starts at `now`, the clock after the job.
    pub fn leases_stamp(&mut self, now: u64) {
        for l in self.leases.iter_mut().filter(|l| l.used && l.stamp) {
            l.stamp = false;
            l.answered = now;
            l.expiry = now.saturating_add(LEASE_GAP_NS);
        }
    }

    /// The lease `slot` ends: its reference of the description goes.
    pub(super) fn lease_end<D: Device>(&mut self, fs: &mut Fs<'_, D>, slot: usize) {
        if !self.leases[slot].used {
            return;
        }
        self.leases[slot].used = false;
        if cfg!(feature = "break-datafs-lease-deref") {
            return;
        }
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

    /// The leases that lapse end, before the worker chooses a job (`jobs` are the jobs it chooses
    /// among). A lease lapses by the gap when `LEASE_GAP_NS` has passed since the answer to the last part
    /// without the next one arriving; a lease whose next part arrived in time and is queued does not
    /// lapse (the queue is not the holder's fault). While jobs of its file wait for it, a lease lapses too when its client
    /// time, with the gap now running (to the arrival of its queued part, or to the present), is over
    /// `LEASE_CLIENT_MAX_NS`. With `SYNC` the node is synced as the lease ends, so that the parts done
    /// are durable before the late part is answered `LAPSED`.
    pub fn leases_sweep<D: Device>(&mut self, fs: &mut Fs<'_, D>, jobs: &[Candidate<'_>]) {
        let n = jobs.len().min(CANDIDATES_MAX);
        for slot in 0..p::LEASES {
            let l = self.leases[slot];
            if !l.used || l.stamp {
                continue;
            }
            // The next part of this lease, if it is queued, and who waits for the file.
            let mut part_at = None;
            let mut waiting = false;
            let mut oldest_waiter = u64::MAX;
            for j in &jobs[..n] {
                let w = self.wants(j.owner, j.request);
                if w.holder == Some(slot) {
                    part_at = Some(j.queued_at);
                } else if w.node == Some(usize::from(l.node)) && (l.write || w.write) {
                    waiting = true;
                    oldest_waiter = oldest_waiter.min(j.queued_at);
                }
            }
            // The gap runs to the arrival of the queued part, or to the present when none is queued:
            // a part that came in time and waits behind other jobs is not late.
            let to = match part_at {
                Some(at) => at.min(self.mono),
                None => self.mono,
            };
            let gap = to.saturating_sub(l.answered);
            let lapsed = gap >= LEASE_GAP_NS
                || (waiting && l.client.saturating_add(gap) > LEASE_CLIENT_MAX_NS);
            if !lapsed {
                // When to look again: the gap, and with a waiter the sooner instant its client time
                // reaches the bound. With no waiter the bound does not apply, so the instant is never
                // in the past and the timer does not fire for nothing.
                let left = LEASE_CLIENT_MAX_NS.saturating_sub(l.client);
                let step = if waiting {
                    LEASE_GAP_NS.min(left + 1)
                } else {
                    LEASE_GAP_NS
                };
                self.leases[slot].expiry = l.answered.saturating_add(step);
            }
            if lapsed {
                if waiting {
                    self.lapse = Lapse {
                        answered: l.answered,
                        expiry: l.expiry,
                        queued: oldest_waiter,
                        at: self.mono,
                        ran: 0,
                        count: self.lapse.count + 1,
                        told: false,
                        steps: 0,
                    };
                }
                if l.sync && l.write {
                    let _ = self.sync_node(fs, usize::from(l.node));
                }
                self.lease_end(fs, slot);
                // The writer is gone for now: nobody goes on where it stopped, so the tail of a
                // rewrite is copied at once, in steps (`tail.rs`).
                if l.write {
                    self.tail_begin_unleased(fs, usize::from(l.node));
                }
            }
        }
    }

    /// The instant the worker wakes to look at the leases again, None when none is held: the first
    /// `expiry` the last sweep set (a lease taken or renewed since has the gap after its answer).
    pub fn next_lease_expiry(&self) -> Option<u64> {
        self.leases
            .iter()
            .filter(|l| l.used)
            .map(|l| l.expiry)
            .min()
    }

    /// The last lapse that jobs waited for.
    pub fn lapse(&self) -> Lapse {
        self.lapse
    }

    /// The job queued at `queued_at` was chosen to run at `now`: when it is the waiter of the last
    /// lapse (the job that was the oldest waiter, not chosen yet), the instant is kept and the answer
    /// is true.
    pub fn lapse_waiter_ran(&mut self, queued_at: u64, now: u64) -> bool {
        let first = self.lapse.count != 0 && self.lapse.ran == 0 && self.lapse.queued == queued_at;
        if first {
            self.lapse.ran = now;
        }
        first
    }

    /// The record of the last lapse once its waiter has run: the worker tells it after the job.
    pub fn lapse_told(&mut self, queued_at: u64) -> Option<Lapse> {
        let l = self.lapse;
        if l.ran == 0 || l.told || l.queued != queued_at {
            return None;
        }
        self.lapse.told = true;
        Some(self.lapse)
    }

    /// The parts that were answered `UNLEASED` so far (they could not take a lease): for the probes.
    pub fn unleased(&self) -> u64 {
        self.unleased
    }

    /// The numbers of the leases held, 0 for a free slot: the worker publishes them for the request
    /// thread, which admits the part of a live lease outside the shares (`admit::holder_part`).
    pub fn lease_numbers(&self, out: &mut [u32; p::LEASES]) {
        for (slot, number) in out.iter_mut().enumerate() {
            *number = if self.leases[slot].used {
                self.lease_number(slot)
            } else {
                0
            };
        }
    }

    /// The leases held now.
    pub fn lease_count(&self) -> usize {
        self.leases.iter().filter(|l| l.used).count()
    }

    /// The client time a part adds to its lease: the gap from the answer to the last part to the
    /// arrival of this one, by the instant the request thread queued it (`set_job_queued`).
    pub(super) fn lease_client_gap(&mut self, slot: usize) {
        let gap = self.job_queued.saturating_sub(self.leases[slot].answered);
        self.leases[slot].client = self.leases[slot].client.saturating_add(gap);
    }

    /// Sets the instant the request thread queued the job about to run, for the client time.
    pub fn set_job_queued(&mut self, ns: u64) {
        self.job_queued = ns;
    }

    /// The node whose unfinished tail the request would flush, and whether it is a write that goes
    /// on where the last one stopped (which does not flush it).
    pub(super) fn flush_of(&self, owner: u64, request: &[u8]) -> [Option<(usize, bool)>; 2] {
        let w = self.wants(owner, request);
        [w.flushes, w.flushes_too.map(|ni| (ni, false))]
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
        // The unlink of an open file and the rename of one (or over one) move its node, which
        // syncs it: they wait for the stepped copy of its tail as an open with truncation does.
        if matches!(method, Method::Unlink | Method::Rename) {
            let (mut first, mut second) = ([0u8; MAX_PATH], [0u8; MAX_PATH]);
            let (a, b) = if method == Method::Unlink {
                match r.bytes(r.left()) {
                    Ok(raw) => (canonical(raw, &mut first).ok(), None),
                    Err(_) => return none,
                }
            } else {
                match p::read_rename(r) {
                    Ok((from, to)) => (
                        canonical(from, &mut first).ok(),
                        canonical(to, &mut second).ok(),
                    ),
                    Err(_) => return none,
                }
            };
            return Wants {
                flushes: a
                    .and_then(|n| self.node_at(&first[..n]))
                    .map(|ni| (ni, false)),
                flushes_too: b.and_then(|n| self.node_at(&second[..n])),
                ..none
            };
        }
        // The calls that name a path need no session: the file is the one at the path.
        if matches!(method, Method::Stat | Method::Open) {
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
            let node = self.node_at(&path[..n]);
            return Wants {
                node,
                write: method == Method::Open,
                // An open with truncation runs the flush of the file.
                flushes: node
                    .filter(|_| method == Method::Open)
                    .map(|ni| (ni, false)),
                ..none
            };
        }
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
            // A seek changes the position a call in parts goes on from, and SEEK_END reads the size
            // a call that writes is changing: it waits for any lease on the file but its holder's.
            Method::Read
            | Method::Pread
            | Method::Write
            | Method::Pwrite
            | Method::Truncate
            | Method::Fstat
            | Method::Seek => {
                let Ok(handle) = r.u32() else { return none };
                let node = file_node(handle);
                // What runs the flush of the node: every read and truncation, and a write that
                // does not go on where the last write of the node stopped.
                let flushes = node.and_then(|ni| match method {
                    Method::Read | Method::Pread | Method::Truncate => Some((ni, false)),
                    Method::Write | Method::Pwrite => {
                        let d = &self.descriptions[self.find(si, handle).ok()?];
                        let (start, append) = if method == Method::Pwrite {
                            (u32::try_from(r.u64().ok()?).ok(), false)
                        } else {
                            (Some(d.pos), d.append)
                        };
                        Some((ni, !append && start.is_some() && self.nodes[ni].at == start))
                    }
                    _ => None,
                });
                Wants {
                    node,
                    write: matches!(
                        method,
                        Method::Write | Method::Pwrite | Method::Truncate | Method::Seek
                    ),
                    flushes,
                    ..none
                }
            }
            // The close of the last description and the sync of a node run its flush.
            Method::Close | Method::Fsync => {
                let Ok(handle) = r.u32() else { return none };
                let flushes = file_node(handle)
                    .filter(|&ni| method == Method::Fsync || self.nodes[ni].refs <= 1)
                    .map(|ni| (ni, false));
                Wants { flushes, ..none }
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
                        holder: Some(slot),
                        takes: false,
                        flushes: None,
                        flushes_too: None,
                    };
                }
                let node = file_node(part.part.handle);
                let flushes = node.and_then(|ni| {
                    if !write {
                        return Some((ni, false));
                    }
                    let d = &self.descriptions[self.find(si, part.part.handle).ok()?];
                    let positional = method == Method::PwriteFrom;
                    let start = if positional {
                        u32::try_from(part.part.offset).ok()
                    } else {
                        Some(d.pos)
                    };
                    let append = d.append && !positional;
                    Some((ni, !append && start.is_some() && self.nodes[ni].at == start))
                });
                Wants {
                    node,
                    write,
                    holder: None,
                    takes: part.part.lease == 0 && part.part.flags & p::MORE != 0,
                    flushes,
                    flushes_too: None,
                }
            }
            _ => none,
        }
    }

    /// Whether a lease on the file holds the job back: any other call waits for a write lease, and a
    /// write waits for a read lease. The holder's own parts are never held back.
    fn held_back(&self, w: &Wants) -> bool {
        if cfg!(feature = "break-datafs-lease-hold") {
            return false;
        }
        // A job that would flush a node whose tail is being copied waits for the copy.
        if [w.flushes.map(|(ni, _)| ni), w.flushes_too]
            .into_iter()
            .flatten()
            .any(|ni| self.nodes[ni].tail == tail::Tail::Running)
        {
            return true;
        }
        let Some(node) = w.node else { return false };
        if w.holder.is_some() {
            return false;
        }
        self.leases
            .iter()
            .any(|l| l.used && usize::from(l.node) == node && (l.write || w.write))
    }

    /// The job to run next among the queued ones, and which of them wait. The job is the oldest one
    /// that nothing holds back, by its place in the queue: a part of a holder takes the place of the
    /// oldest job that waits for the same file, and a job that asks for a new read lease waits behind
    /// a writer that waits for the file and came before it. A job waits when a lease holds its file
    /// back, when it would take a lease and the limits allow none (it goes when one ends, so that a
    /// call is not made less atomic by a busy service), and when an older part of the same lease is
    /// queued (the parts of a lease run one at a time, in the order they came).
    pub fn pick(&self, jobs: &[Candidate<'_>]) -> Pick {
        let n = jobs.len().min(CANDIDATES_MAX);
        let mut wants = [Wants::default(); CANDIDATES_MAX];
        let mut held = [false; CANDIDATES_MAX];
        let mut parked = 0u32;
        for i in 0..n {
            wants[i] = self.wants(jobs[i].owner, jobs[i].request);
            held[i] = self.held_back(&wants[i]);
            if held[i] {
                parked |= 1 << i;
            }
        }
        let mut best: Option<(u64, u64, usize)> = None;
        for i in 0..n {
            if held[i] {
                continue;
            }
            let (w, ticket) = (&wants[i], jobs[i].ticket);
            // A part that would take a lease and cannot waits for one to end.
            if w.takes && w.node.is_some() && !self.lease_free_for(jobs[i].owner) {
                parked |= 1 << i;
                continue;
            }
            // The parts of one lease run in the order they came.
            if w.holder.is_some()
                && (0..n).any(|k| k != i && wants[k].holder == w.holder && jobs[k].ticket < ticket)
            {
                parked |= 1 << i;
                continue;
            }
            let waiting = |k: usize| held[k] && wants[k].node == w.node && w.node.is_some();
            // A new read lease waits behind a writer that waits.
            if !cfg!(feature = "break-datafs-lease-reader")
                && w.takes
                && !w.write
                && (0..n).any(|k| k != i && waiting(k) && wants[k].write && jobs[k].ticket < ticket)
            {
                parked |= 1 << i;
                continue;
            }
            // A part of the holder takes the place of the oldest job that waits for the file.
            let mut place = ticket;
            if w.holder.is_some() && !cfg!(feature = "break-datafs-lease-place") {
                for k in (0..n).filter(|&k| k != i && waiting(k)) {
                    place = place.min(jobs[k].ticket);
                }
            }
            if best.is_none_or(|(p, t, _)| (place, ticket) < (p, t)) {
                best = Some((place, ticket, i));
            }
        }
        Pick {
            run: best.map(|(_, _, i)| jobs[i].id),
            parked,
        }
    }
}

/// The choice of `Server::pick`: the job to run, and the jobs (by their place in the slice given)
/// that wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pick {
    pub run: Option<usize>,
    pub parked: u32,
}
