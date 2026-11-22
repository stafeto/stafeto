// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The decisions of the service's request thread that need no kernel: which jobs a session may
//! have, what becomes of the handle a reply carries, which labels wait for a free job. The thread
//! (`services/datafs/src/main.rs`) calls these; the tests run here on the host.

use proto_data as p;

/// Whether the one handle of a WINDOW request may be a window: a memory object (not a device
/// window, whose bytes are registers: littlefs would copy into device memory with accesses the
/// device refuses and with side effects) that the sender let the service map for reading and
/// writing. The kind and the rights come with the message, so the request thread checks them before
/// it takes the handle; the worker's test map is a second guard.
pub fn window_offered(kind: abi::ObjectKind, rights: abi::Rights) -> bool {
    kind == abi::ObjectKind::Memory
        && rights.contains(abi::Rights::MAP_READ)
        && rights.contains(abi::Rights::MAP_WRITE)
}

/// The requests in flight at once, and the notice of a session that went.
pub const JOBS: usize = 24;

/// The jobs one session may have in flight at once: no session fills the table alone.
pub const SESSION_JOBS: usize = 4;

/// The jobs one root (a process tree, or a client of init) may have in flight at once, whatever
/// the number of its sessions (up to `ROOT_CLONES` and one for each process of the tree): three
/// roots fill the table, and no tree starves another.
pub const ROOT_JOBS: usize = 8;

/// The jobs only the sessions of native clients may take: the last of the table, so that the
/// sessions of the process trees (many, each with its share) never leave `datakey` with no job.
pub const NATIVE_JOBS: usize = 4;

/// The jobs kept for the parts of calls that hold a lease: a part with a live lease number takes a
/// job outside the shares of its session and its tree and outside the native reserve, so that a
/// holder is never refused for the jobs that wait for it (readers of the same session or tree parked
/// behind its write lease would otherwise take its place, the lease would lapse and the call would
/// be broken). Other requests leave these places free.
pub const HOLDER_JOBS: usize = 4;

/// The SESSION requests of the root channel that wait for a job over the root's share (a first in,
/// first out queue): every SESSION arrives with the one root label, so a process of four threads
/// could keep the share busy and fail the first `/data` call of the others. Over the queue the
/// answer is busy.
pub const WAITING_MAX: usize = 32;

/// The places of the loop's table kept for the sessions of native clients (`datakey` and the
/// other services): no process tree makes sessions or clones into them.
pub const SERVICE_SESSIONS: usize = 4;

/// What the table of jobs looks like to a request of one session.
#[derive(Clone, Copy, Debug)]
pub struct Load {
    /// The first free job, if any.
    pub free_job: Option<usize>,
    /// How many jobs are free.
    pub free: usize,
    /// The jobs of the session in flight.
    pub mine: usize,
    /// The jobs of the session's root in flight.
    pub tree: usize,
    /// The session is a native client's.
    pub native: bool,
    /// The request is a part of a call that holds a live lease.
    pub holder: bool,
}

/// A job for a request under every rule at once: the table, the session's share, the root's share
/// and the places kept for the native clients. Every request that takes a job goes through it,
/// VERIFY_SESSION's UNBIND too: a loop of requests of one session or of one tree fills no more than
/// its share.
pub fn admit(load: Load) -> Option<usize> {
    // A part of a lease holder takes any free job: the places it is kept are the last ones.
    if load.holder {
        return load.free_job;
    }
    if load.free <= HOLDER_JOBS
        || !leaves_for_native(load.free, load.native, NATIVE_JOBS + HOLDER_JOBS)
        || !root_has_room(load.tree, ROOT_JOBS)
    {
        return None;
    }
    job_for(load.free_job, load.mine, SESSION_JOBS)
}

/// Whether the request is a part (READ_INTO, PREAD_INTO, WRITE_FROM, PWRITE_FROM) that carries the
/// number of a lease `live` says is held: the request thread admits it outside the shares.
pub fn holder_part(request: &[u8], live: impl Fn(u32) -> bool) -> bool {
    let mut r = proto_wire::Reader::new(request);
    let Ok(header) = proto_wire::Header::read(&mut r) else {
        return false;
    };
    if header.version != p::VERSION {
        return false;
    }
    let Some(method) = p::Method::from_number(header.method) else {
        return false;
    };
    match p::read_part(method, r) {
        Ok(part) => part.part.lease != 0 && live(part.part.lease),
        Err(_) => false,
    }
}

/// What the request thread does with a request of the root channel that asks for a session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Wait {
    /// A job is free inside the shares and nobody waits before it: run it.
    Run,
    /// Keep it in the queue: its turn comes when a job frees.
    Defer,
    /// The queue is full: busy.
    Busy,
}

/// Run a SESSION request when a job is admitted and none waits (first in, first out); queue it
/// while the queue has room; busy when it has none.
pub fn wait_plan(admitted: bool, waiting: usize) -> Wait {
    if admitted && waiting == 0 {
        Wait::Run
    } else if waiting < WAITING_MAX {
        Wait::Defer
    } else {
        Wait::Busy
    }
}

/// Whether another session or clone of a process tree may be made: the last `SERVICE_SESSIONS`
/// places of the table stay for the sessions of native clients, so that a restarted `datakey`
/// always finds one.
pub fn may_make(made: usize, sessions: usize) -> bool {
    made + SERVICE_SESSIONS < sessions
}

/// A first in, first out queue of at most `N` entries.
pub struct Fifo<T, const N: usize> {
    items: [Option<T>; N],
    head: usize,
    count: usize,
}

impl<T, const N: usize> Default for Fifo<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Fifo<T, N> {
    pub fn new() -> Self {
        Self {
            items: [const { None }; N],
            head: 0,
            count: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The entry back when the queue is full.
    pub fn push(&mut self, item: T) -> Result<(), T> {
        if self.count == N {
            return Err(item);
        }
        self.items[(self.head + self.count) % N] = Some(item);
        self.count += 1;
        Ok(())
    }

    /// The entry that comes out next.
    pub fn front(&self) -> Option<&T> {
        self.items[self.head].as_ref()
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.count == 0 {
            return None;
        }
        let item = self.items[self.head].take();
        self.head = (self.head + 1) % N;
        self.count -= 1;
        item
    }
}

/// A free job for a request of a session that has `mine` jobs in flight, when `limit` is the most it
/// may have: None when there is no free job or the session has its share.
pub fn job_for(free: Option<usize>, mine: usize, limit: usize) -> Option<usize> {
    free.filter(|_| mine < limit)
}

/// Whether a process tree (a root) that has `mine` jobs in flight may take one more when `limit` is
/// the most a root may have: the sessions of one tree are many (up to 32), each with its own share
/// of jobs, and no tree may fill the table for the others.
pub fn root_has_room(mine: usize, limit: usize) -> bool {
    mine < limit
}

/// Whether a request of a session may take a job when `free` jobs are free: a session of a native
/// client may take any, every other session leaves the last `reserve` for the native clients. The
/// sessions of one process tree are many (up to 32 for a root, 4 jobs each, more than the table), and
/// the request thread does not know the trees, so the table keeps a share for `datakey` and the
/// other native clients that no tree can use up.
pub fn leaves_for_native(free: usize, native: bool, reserve: usize) -> bool {
    native || free > reserve
}

/// Whether the session of `label` is one VERIFY_SESSION may give back as a genuine session of a
/// process: it is neither the root channel, nor a pass of EXPORT, nor the profile of a native client.
pub fn verifiable(label: u64) -> bool {
    !p::is_root(label) && !p::is_pass(label) && !p::is_service(label)
}

/// What a reply's status is: whether it is a success (the status word is zero).
pub fn said_yes(reply: &[u8]) -> bool {
    reply.get(..4) == Some(&[0; 4][..])
}

/// The status word of a reply, or None when it has none.
pub fn status_of(reply: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(reply.get(..4)?.try_into().ok()?))
}

/// What a request thread holds a handle for until its job is done.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Held {
    /// A new session (CLONE) or a pass (EXPORT) that goes to the client when the service says yes.
    Made,
    /// The pass a client spent in ADOPT: it goes back to the client when the service refused for a
    /// limit that the client can lift (the pass was not spent), and closes otherwise.
    Spent,
}

/// What becomes of a held handle once the worker has answered with `reply`: true when it goes to
/// the client in the reply, false when it closes.
pub fn carries(held: Held, reply: &[u8]) -> bool {
    matches!(
        (held, status_of(reply)),
        (Held::Made, Some(0)) | (Held::Spent, Some(p::TOO_MANY_OPEN | p::TABLE_FULL))
    )
}

/// What a request for ADOPT meets before it is queued: how many handles it brought and whether a
/// job is free for its session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Adopt {
    /// Not one handle: BAD_SIZE.
    BadSize,
    /// A job is free: queue it with the pass.
    Queue,
    /// No job: answer busy and give the pass back, so that the client may ask again.
    GiveBack,
}

pub fn adopt_plan(handles: usize, job_free: bool) -> Adopt {
    match (handles, job_free) {
        (1, true) => Adopt::Queue,
        (1, false) => Adopt::GiveBack,
        _ => Adopt::BadSize,
    }
}

/// The labels whose close found no free job: what they held is closed when jobs free up.
pub struct Forgotten<const N: usize> {
    labels: [u64; N],
    count: usize,
}

impl<const N: usize> Default for Forgotten<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Forgotten<N> {
    pub const fn new() -> Self {
        Self {
            labels: [0; N],
            count: 0,
        }
    }

    /// False when the list is full: the label is lost, so the size must cover everything that can
    /// close at once (`closers`).
    pub fn push(&mut self, label: u64) -> bool {
        if self.count == N {
            return false;
        }
        self.labels[self.count] = label;
        self.count += 1;
        true
    }

    pub fn pop(&mut self) -> Option<u64> {
        self.count = self.count.checked_sub(1)?;
        Some(self.labels[self.count])
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// The labels that can have gone while no job was free: every session of the loop and every clone
/// the worker holds (`sessions`, as many as its table), every pass (`passes`), and for each job
/// in flight the handle its reply would have carried and the pass its ADOPT spent (`jobs` of each,
/// and one more for the label of the request itself).
pub const fn closers(sessions: usize, passes: usize, jobs: usize) -> usize {
    sessions + passes + 3 * jobs
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_part_of_a_live_lease_is_admitted_outside_the_shares_and_the_places_are_kept() {
        let load = |free: usize, mine, tree, native, holder| Load {
            free_job: (free > 0).then_some(0),
            free,
            mine,
            tree,
            native,
            holder,
        };
        // A thread writes in parts while four others of its session read the file and wait: the
        // session has its four jobs in flight, the tree its eight, and the holder's next part still
        // gets a job, as does the next part when the table is down to the places kept for holders.
        assert!(admit(load(10, SESSION_JOBS, ROOT_JOBS, false, false)).is_none());
        assert!(admit(load(10, SESSION_JOBS, ROOT_JOBS, false, true)).is_some());
        assert!(admit(load(HOLDER_JOBS, SESSION_JOBS, ROOT_JOBS, false, true)).is_some());
        assert!(admit(load(1, SESSION_JOBS, ROOT_JOBS, false, true)).is_some());
        // With no job free there is none to give.
        assert!(admit(load(0, 0, 0, false, true)).is_none());
        // The places kept for the holders are not given to other requests, native clients included.
        assert!(admit(load(HOLDER_JOBS, 0, 0, false, false)).is_none());
        assert!(admit(load(HOLDER_JOBS, 0, 0, true, false)).is_none());
        assert!(admit(load(HOLDER_JOBS + 1, 0, 0, true, false)).is_some());
        assert!(admit(load(HOLDER_JOBS + NATIVE_JOBS, 0, 0, false, false)).is_none());
        assert!(admit(load(HOLDER_JOBS + NATIVE_JOBS + 1, 0, 0, false, false)).is_some());
    }

    #[test]
    fn a_request_is_a_holder_part_when_it_carries_the_number_of_a_live_lease() {
        let part = |lease: u32| {
            let mut w = proto_wire::Writer::new();
            let head = p::Part {
                handle: 1,
                count: 10,
                offset: 0,
                cell: 0,
                flags: p::MORE,
                lease,
            };
            p::write_from(&head, &[], &mut w).unwrap();
            w.as_bytes().to_vec()
        };
        assert!(holder_part(&part(0x0001_0105), |n| n == 0x0001_0105));
        assert!(
            !holder_part(&part(0x0001_0105), |_| false),
            "a number that is not live"
        );
        assert!(!holder_part(&part(0), |_| true), "no lease");
        let mut w = proto_wire::Writer::new();
        p::read(1, 10, &mut w).unwrap();
        assert!(!holder_part(w.as_bytes(), |_| true), "not a part");
        assert!(!holder_part(&[1, 2, 3], |_| true));
    }

    #[test]
    fn only_a_memory_object_with_both_map_rights_is_a_window() {
        use abi::{ObjectKind as K, Rights as R};
        let rw = R(R::MAP_READ.0 | R::MAP_WRITE.0 | R::TRANSFER.0);
        assert!(super::window_offered(K::Memory, rw));
        // A window of a device is memory the program may map, but its bytes are registers.
        assert!(!super::window_offered(K::DeviceWindow, rw));
        for kind in [
            K::Channel,
            K::Process,
            K::Thread,
            K::Timer,
            K::Resource,
            K::Interrupt,
        ] {
            assert!(!super::window_offered(kind, rw), "{kind:?}");
        }
        // Both rights are needed: a cell is read to write the file and written to read it.
        assert!(!super::window_offered(
            K::Memory,
            R(R::MAP_READ.0 | R::TRANSFER.0)
        ));
        assert!(!super::window_offered(
            K::Memory,
            R(R::MAP_WRITE.0 | R::TRANSFER.0)
        ));
        assert!(!super::window_offered(K::Memory, R(0)));
    }

    use super::*;

    fn reply(status: u32) -> [u8; 8] {
        let mut r = [0; 8];
        r[..4].copy_from_slice(&status.to_le_bytes());
        r
    }

    #[test]
    fn a_session_gets_a_job_only_inside_its_share() {
        assert_eq!(job_for(Some(3), 0, 4), Some(3));
        assert_eq!(job_for(Some(3), 3, 4), Some(3));
        assert_eq!(job_for(Some(3), 4, 4), None);
        assert_eq!(job_for(None, 0, 4), None);
    }

    #[test]
    fn a_tree_takes_jobs_only_inside_its_share_whatever_its_sessions_have() {
        // Thirty-two sessions of one tree with four jobs each would be 128 jobs: the tree has the
        // share of its root.
        assert!(root_has_room(0, 8) && root_has_room(7, 8));
        assert!(!root_has_room(8, 8));
        assert!(!root_has_room(9, 8));
    }

    #[test]
    fn the_last_jobs_are_kept_for_the_native_clients() {
        assert!(leaves_for_native(5, false, 4));
        assert!(!leaves_for_native(4, false, 4));
        assert!(!leaves_for_native(1, false, 4));
        assert!(
            leaves_for_native(1, true, 4),
            "a native client takes the last one"
        );
    }

    #[test]
    fn a_made_handle_goes_with_a_yes_and_closes_with_anything_else() {
        assert!(carries(Held::Made, &reply(0)));
        assert!(!carries(Held::Made, &reply(p::BAD_HANDLE)));
        assert!(!carries(Held::Made, &reply(p::TOO_MANY_OPEN)));
        assert!(!carries(Held::Made, &[]));
        assert!(said_yes(&reply(0)) && !said_yes(&reply(1)) && !said_yes(&[0, 0]));
    }

    #[test]
    fn a_spent_pass_comes_back_only_when_the_limit_left_it_unspent() {
        assert!(carries(Held::Spent, &reply(p::TOO_MANY_OPEN)));
        assert!(carries(Held::Spent, &reply(p::TABLE_FULL)));
        assert!(
            !carries(Held::Spent, &reply(0)),
            "adopted: the pass is spent"
        );
        assert!(!carries(Held::Spent, &reply(p::BAD_HANDLE)));
        assert!(!carries(Held::Spent, &reply(p::IO)));
        assert!(!carries(Held::Spent, &[]));
    }

    /// SESSION without vouching: the session the loop made for it never reaches the caller, whatever
    /// the refusal, and the answer carries no handle (the worker's replies are ACCESS, TABLE_FULL
    /// and the rest; only success lets the made session go).
    #[test]
    fn a_session_call_the_worker_refuses_gives_no_session() {
        for status in [
            p::ACCESS,
            p::TABLE_FULL,
            p::TOO_MANY_OPEN,
            p::INVALID,
            p::NOT_READY,
            1,
        ] {
            assert!(!carries(Held::Made, &reply(status)), "{status}");
        }
        assert!(carries(Held::Made, &reply(0)));
    }

    /// VERIFY_SESSION answers BAD_HANDLE and no handle for a channel that is no live session of the
    /// service; of the live ones, the root, a pass and a native client's profile are not sessions
    /// of a process.
    #[test]
    fn only_the_session_of_a_process_is_given_back_by_verify_session() {
        assert!(verifiable(p::OWN | 5));
        assert!(!verifiable(p::ROOT));
        assert!(!verifiable(p::PASS | 5));
        assert!(!verifiable(p::SERVICE | 3));
        // A session of a process made by SESSION or CLONE has OWN and none of the marks.
        assert!(verifiable(p::OWN | 1));
    }

    #[test]
    fn adopt_needs_one_handle_and_gives_it_back_when_no_job_is_free() {
        assert_eq!(adopt_plan(1, true), Adopt::Queue);
        assert_eq!(adopt_plan(1, false), Adopt::GiveBack);
        assert_eq!(adopt_plan(0, true), Adopt::BadSize);
        assert_eq!(adopt_plan(2, false), Adopt::BadSize);
    }

    #[test]
    fn the_forgotten_hold_exactly_their_size_and_come_back_last_first() {
        let mut f = Forgotten::<3>::new();
        assert!(f.is_empty());
        assert!(f.push(1) && f.push(2) && f.push(3));
        assert!(!f.push(4), "full: the label would be lost");
        assert_eq!(f.len(), 3);
        assert_eq!(
            (f.pop(), f.pop(), f.pop(), f.pop()),
            (Some(3), Some(2), Some(1), None)
        );
    }

    #[test]
    fn the_list_of_the_forgotten_covers_everything_that_can_close_at_once() {
        assert_eq!(closers(32, 8, 12), 76);
        assert!(closers(1, 1, 1) > 3);
    }

    /// One session that loops VERIFY_SESSION on itself, and a tree of sessions that does: the UNBIND
    /// jobs stay inside the shares, the places of the native clients stay free, and so does a place
    /// of another tree.
    #[test]
    fn repeated_verify_session_fills_no_more_than_its_share() {
        // Worst case: no UNBIND finishes while the loop runs.
        let mut in_flight = 0;
        let mut taken = 0;
        for _ in 0..30 {
            let load = Load {
                free_job: (in_flight < JOBS).then_some(in_flight),
                free: JOBS - in_flight,
                mine: in_flight,
                tree: in_flight,
                native: false,
                holder: false,
            };
            if admit(load).is_some() {
                in_flight += 1;
                taken += 1;
            }
        }
        assert_eq!(
            taken, SESSION_JOBS,
            "one session takes its share and no more"
        );
        assert!(JOBS - in_flight >= NATIVE_JOBS + ROOT_JOBS);
        // Thirty sessions of one tree, one job each, never finishing.
        let mut tree = 0;
        for _ in 0..30 {
            let load = Load {
                free_job: (tree < JOBS).then_some(tree),
                free: JOBS - tree,
                mine: 0,
                tree,
                native: false,
                holder: false,
            };
            if admit(load).is_some() {
                tree += 1;
            }
        }
        assert_eq!(tree, ROOT_JOBS);
        assert!(JOBS - tree >= NATIVE_JOBS, "the native places stay");
        // Another tree and a native client still get a job.
        let load = |native, tree| Load {
            free_job: Some(tree),
            free: JOBS - tree,
            mine: 0,
            tree: 0,
            native,
            holder: false,
        };
        assert!(admit(load(false, ROOT_JOBS)).is_some());
        assert!(admit(load(true, ROOT_JOBS)).is_some());
    }

    #[test]
    fn root_requests_wait_in_turn_and_busy_comes_only_from_a_full_queue() {
        assert_eq!(wait_plan(true, 0), Wait::Run);
        assert_eq!(wait_plan(false, 0), Wait::Defer);
        assert_eq!(wait_plan(true, 1), Wait::Defer, "first in, first out");
        assert_eq!(wait_plan(false, WAITING_MAX - 1), Wait::Defer);
        assert_eq!(wait_plan(false, WAITING_MAX), Wait::Busy);
        assert_eq!(wait_plan(true, WAITING_MAX), Wait::Busy);
    }

    #[test]
    fn the_queue_keeps_order_and_bounds() {
        let mut f = Fifo::<u32, 3>::new();
        assert!(f.is_empty() && f.pop().is_none());
        assert!(f.push(1).is_ok() && f.push(2).is_ok() && f.push(3).is_ok());
        assert_eq!(f.push(4), Err(4));
        assert_eq!(f.pop(), Some(1));
        assert!(f.push(5).is_ok(), "the place of the first is used again");
        assert_eq!(
            (f.pop(), f.pop(), f.pop(), f.pop()),
            (Some(2), Some(3), Some(5), None)
        );
        assert_eq!(f.len(), 0);
    }

    #[test]
    fn the_places_of_native_clients_are_kept_in_the_table() {
        assert!(may_make(0, 65));
        assert!(may_make(65 - SERVICE_SESSIONS - 1, 65));
        assert!(!may_make(65 - SERVICE_SESSIONS, 65));
        assert!(!may_make(65, 65));
    }
}
