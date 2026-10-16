// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The message queues, semaphores and shared memory segments of the
//! service (Ф11b; proto_pipe::ipc). The POSIX message queues are named
//! (`/name`) and opened for a description of the third kind (an `Sock`
//! slot of kind MQ_KIND, so that fork, exec, dup, close and the limits of
//! sessions are a socket's); the XSI queues and semaphore sets are found
//! by a key and named by an id; both kinds of queue share one pool of
//! messages, a table of 16 queues and the lists of operations that wait.
//! The named semaphores of POSIX are semaphore sets of one semaphore with a
//! name. A shared memory segment is an accounting entry: its pages are a
//! file of `/dev/shm` that the layer makes and maps.
//!
//! An operation that waits (a send to a full queue, a receive from an
//! empty one, a `semop` that would block) is told to wait at the queue of
//! its object (`QUEUE_BASE + object`): any change of the object wakes the
//! whole list of eight, and each woken operation asks again. A session
//! that goes leaves its semaphore adjustments (SEM_UNDO), its attachments
//! of segments and its opens of named semaphores to `step`, which lets go
//! of one in a step. Every operation here is O(1) or bounded by the tables.

use super::*;
use proto_pipe::ipc::{Answer, Call, Cred, MQ_KIND, NAME_MAX, TEXT_MAX, WORDS_MAX, Who, op};

/// The queues of POSIX and XSI together.
pub const QUEUES: usize = 16;
/// The semaphore sets, named semaphores among them.
pub const SEMSETS: usize = 8;
/// The shared memory segments.
pub const SEGS: usize = 8;
/// The messages of all queues together.
pub const MSGS: usize = 64;
/// The messages one queue holds at most (the `mq_maxmsg` too).
pub const QUEUE_MSGS: usize = 16;
/// The semaphores of a set at most.
pub const SEMS_MAX: usize = 16;
/// {SEMVMX}: the value of a semaphore at most.
pub const SEM_VALUE_MAX: u32 = 32767;
/// The operations of one `semop` at most.
pub const SEMOPS_MAX: usize = 8;
/// The largest segment, in bytes.
pub const SHM_MAX: u64 = 1 << 20;
/// The default and the largest {MSGMNB} of an XSI queue.
pub const QBYTES_DEFAULT: u32 = 8192;
pub const QBYTES_MAX: u32 = 16384;
/// The objects of a kind one root made at most.
pub const ROOT_OBJECTS: usize = 6;
/// The semaphore adjustments, and the attachments and opens, the service
/// keeps at most.
pub const UNDO_MAX: usize = 32;
pub const HOLD_MAX: usize = 48;
/// The number of the queue of the waits: after the pipes' and the sockets'.
pub const QUEUE_BASE: u32 = (DESCRIPTIONS + SOCKETS) as u32;
/// The waits of IPC objects: a queue each, then a semaphore set each.
pub const WAIT_QUEUES: usize = QUEUES + SEMSETS + 1;
/// The messages the queues of one root hold at most, of the 64: a root that
/// has its share waits for the pool, which any release wakes.
pub const ROOT_MSGS: usize = 32;
/// The files of freed segments a session that did not remove them is told
/// of (so that it removes them).
pub const REAP_MAX: usize = 16;

/// The id of the endpoint an IPC operation is taken for: no real
/// description has bit 29.
pub const IPC_TAG: u32 = 1 << 29;

/// The operations that wait the service counts: receivers (a notification
/// of a queue is not sent while one waits) and `semop`s (GETNCNT, GETZCNT).
pub const BLOCKED_MAX: usize = 128;

// Linux's numbers, relibc's.
const EPERM: u32 = 1;
const ENOENT: u32 = 2;
const E2BIG: u32 = 7;
const EBADF: u32 = 9;
const EAGAIN: u32 = 11;
const ENOMEM: u32 = 12;
const EACCES: u32 = 13;
const EBUSY: u32 = 16;
const EEXIST: u32 = 17;
const EINVAL: u32 = 22;
const ENOSPC: u32 = 28;
const ERANGE: u32 = 34;
const ENOMSG: u32 = 42;
const EIDRM: u32 = 43;
const EFBIG: u32 = 27;
const EOVERFLOW: u32 = 75;
const EMSGSIZE: u32 = 90;

const fn fail(errno: u32) -> u32 {
    proto_pipe::ipc::ERRNO + errno
}

// The values the library sends (Linux's, relibc's).
const O_ACCMODE: u64 = 3;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_NONBLOCK: u64 = 0o4000;
const IPC_CREAT: u64 = 0o1000;
const IPC_EXCL: u64 = 0o2000;
const IPC_NOWAIT: u64 = 0o4000;
const MSG_NOERROR: u64 = 0o10000;
const MSG_EXCEPT: u64 = 0o20000;
const SEM_UNDO: i64 = 0x1000;
const IPC_RMID: u64 = 0;
const IPC_SET: u64 = 1;
const IPC_STAT: u64 = 2;
const GETPID: u64 = 11;
const GETVAL: u64 = 12;
const GETALL: u64 = 13;
const GETNCNT: u64 = 14;
const GETZCNT: u64 = 15;
const SETVAL: u64 = 16;
const SETALL: u64 = 17;
const SHM_RDONLY: u64 = 0o10000;
const MQ_PRIO_MAX: u64 = 32768;
const NIL: u8 = 255;

/// What an operation gives besides its status: the words and the bytes of
/// its answer.
pub struct Out {
    pub words: [u64; WORDS_MAX],
    pub n: usize,
    pub bytes: [u8; TEXT_MAX],
    pub len: usize,
}

impl Out {
    pub const fn new() -> Out {
        Out {
            words: [0; WORDS_MAX],
            n: 0,
            bytes: [0; TEXT_MAX],
            len: 0,
        }
    }

    fn word(&mut self, v: u64) {
        self.words[self.n] = v;
        self.n += 1;
    }

    pub fn answer(&self) -> Answer<'_> {
        Answer::new(&self.words[..self.n], &self.bytes[..self.len])
    }
}

impl Default for Out {
    fn default() -> Self {
        Out::new()
    }
}

/// Which wait an operation makes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Block {
    Plain,
    /// A receive from a queue of POSIX.
    Recv,
    /// A `semop` on a semaphore (and whether for it to be zero).
    Sem(u8, bool),
}

/// What a call came to: done, or to wait at a queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    Done,
    Wait { queue: u32, block: Block },
}

#[derive(Clone, Copy)]
struct Perm {
    key: i32,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u16,
}

impl Perm {
    const NONE: Perm = Perm {
        key: 0,
        uid: 0,
        gid: 0,
        cuid: 0,
        cgid: 0,
        mode: 0,
    };

    fn new(key: i32, cred: &Cred, mode: u64) -> Perm {
        Perm {
            key,
            uid: cred.uid,
            gid: cred.gid,
            cuid: cred.uid,
            cgid: cred.gid,
            mode: (mode & 0o777) as u16,
        }
    }

    /// Whether `cred` may read (`read`) and write (`write`).
    fn allows(&self, cred: &Cred, read: bool, write: bool) -> bool {
        if cred.uid == 0 {
            return true;
        }
        let bits = if cred.uid == self.uid || cred.uid == self.cuid {
            self.mode >> 6
        } else if cred.gid == self.gid || cred.gid == self.cgid {
            self.mode >> 3
        } else {
            self.mode
        } & 7;
        (!read || bits & 4 != 0) && (!write || bits & 2 != 0)
    }

    /// Whether `cred` owns the object (RMID, SET).
    fn owns(&self, cred: &Cred) -> bool {
        cred.uid == 0 || cred.uid == self.uid || cred.uid == self.cuid
    }

    fn put(&self, out: &mut Out, seq: u32) {
        out.word(self.key as u32 as u64);
        out.word(u64::from(self.uid));
        out.word(u64::from(self.gid));
        out.word(u64::from(self.cuid));
        out.word(u64::from(self.cgid));
        out.word(u64::from(self.mode));
        out.word(u64::from(seq));
    }
}

#[derive(Clone, Copy)]
struct Msg {
    used: bool,
    next: u8,
    /// The priority of a POSIX message, the type of an XSI one.
    tag: i64,
    len: u16,
    data: [u8; TEXT_MAX],
}

impl Msg {
    const FREE: Msg = Msg {
        used: false,
        next: NIL,
        tag: 0,
        len: 0,
        data: [0; TEXT_MAX],
    };
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Notify {
    None,
    /// Registered by the description in the slot.
    Armed(u8),
    /// A message came to the empty queue, for the description in the slot.
    Fired(u8),
}

#[derive(Clone, Copy)]
struct Queue {
    live: bool,
    era: u32,
    /// A queue of POSIX (named, opened) and not an XSI one.
    mq: bool,
    perm: Perm,
    name: [u8; NAME_MAX + 1],
    name_len: u8,
    unlinked: bool,
    opens: u16,
    maxmsg: u16,
    msgsize: u16,
    qbytes: u32,
    head: u8,
    tail: u8,
    count: u8,
    bytes: u32,
    stime: i64,
    rtime: i64,
    ctime: i64,
    lspid: u32,
    lrpid: u32,
    waiters: End,
    notify: Notify,
    root: u64,
}

impl Queue {
    const FREE: Queue = Queue {
        live: false,
        era: 0,
        mq: false,
        perm: Perm::NONE,
        name: [0; NAME_MAX + 1],
        name_len: 0,
        unlinked: false,
        opens: 0,
        maxmsg: 0,
        msgsize: 0,
        qbytes: 0,
        head: NIL,
        tail: NIL,
        count: 0,
        bytes: 0,
        stime: 0,
        rtime: 0,
        ctime: 0,
        lspid: 0,
        lrpid: 0,
        waiters: End::NONE,
        notify: Notify::None,
        root: 0,
    };

    fn has_name(&self, name: &[u8]) -> bool {
        self.live && self.mq && !self.unlinked && &self.name[..usize::from(self.name_len)] == name
    }
}

#[derive(Clone, Copy)]
struct SemSet {
    live: bool,
    era: u32,
    /// A named semaphore of POSIX.
    named: bool,
    perm: Perm,
    name: [u8; NAME_MAX + 1],
    name_len: u8,
    unlinked: bool,
    opens: u16,
    nsems: u8,
    vals: [u16; SEMS_MAX],
    pids: [u32; SEMS_MAX],
    otime: i64,
    ctime: i64,
    waiters: End,
    root: u64,
}

impl SemSet {
    const FREE: SemSet = SemSet {
        live: false,
        era: 0,
        named: false,
        perm: Perm::NONE,
        name: [0; NAME_MAX + 1],
        name_len: 0,
        unlinked: false,
        opens: 0,
        nsems: 0,
        vals: [0; SEMS_MAX],
        pids: [0; SEMS_MAX],
        otime: 0,
        ctime: 0,
        waiters: End::NONE,
        root: 0,
    };
}

#[derive(Clone, Copy)]
struct Seg {
    live: bool,
    era: u32,
    perm: Perm,
    size: u64,
    serial: u64,
    cpid: u32,
    lpid: u32,
    nattch: u16,
    atime: i64,
    dtime: i64,
    ctime: i64,
    /// IPC_RMID came while it was attached: it goes with the last detach.
    removed: bool,
    root: u64,
}

impl Seg {
    const FREE: Seg = Seg {
        live: false,
        era: 0,
        perm: Perm::NONE,
        size: 0,
        serial: 0,
        cpid: 0,
        lpid: 0,
        nattch: 0,
        atime: 0,
        dtime: 0,
        ctime: 0,
        removed: false,
        root: 0,
    };
}

/// Why the operations of a `semop` do not go through.
enum Try {
    /// An operation waits for the semaphore (and whether for zero).
    Block(usize, bool),
    /// An operation with IPC_NOWAIT would wait.
    Again,
    /// A value would pass {SEMVMX}.
    Range,
}

/// A semaphore adjustment of a session (SEM_UNDO).
#[derive(Clone, Copy)]
struct Undo {
    used: bool,
    dying: bool,
    label: u64,
    set: u8,
    era: u32,
    num: u8,
    adj: i32,
}

/// What a session holds of an object that has no description: segments it
/// attached and named semaphores it opened.
#[derive(Clone, Copy)]
struct Hold {
    used: bool,
    dying: bool,
    sem: bool,
    label: u64,
    obj: u8,
    era: u32,
    count: u16,
}

/// An operation that waits and is counted.
#[derive(Clone, Copy)]
struct Blocked {
    used: bool,
    label: u64,
    key: u64,
    /// The wait queue it waits at.
    queue: u32,
    block: Block,
}

pub struct Ipc {
    queues: [Queue; QUEUES],
    sems: [SemSet; SEMSETS],
    segs: [Seg; SEGS],
    msgs: [Msg; MSGS],
    undo: [Undo; UNDO_MAX],
    holds: [Hold; HOLD_MAX],
    blocked: [Blocked; BLOCKED_MAX],
    /// The places of `blocked` in use: the common case, none, costs nothing.
    counted: u8,
    /// The senders that wait for the pool of messages.
    pool: End,
    /// The serial and the creator's uid of freed segments whose file is left.
    reap: [(u64, u32); REAP_MAX],
    reaped: u8,
    dying: u16,
}

const UNDO_FREE: Undo = Undo {
    used: false,
    dying: false,
    label: 0,
    set: 0,
    era: 0,
    num: 0,
    adj: 0,
};
const HOLD_FREE: Hold = Hold {
    used: false,
    dying: false,
    sem: false,
    label: 0,
    obj: 0,
    era: 0,
    count: 0,
};
const BLOCKED_FREE: Blocked = Blocked {
    used: false,
    label: 0,
    key: 0,
    queue: 0,
    block: Block::Plain,
};

fn id_of(slot: usize, era: u32) -> u64 {
    ((u64::from(era) & 0xffff) << 5 | slot as u64) + 1
}

fn split_id(id: u64) -> Option<(usize, u32)> {
    let v = id.checked_sub(1)?;
    (v < 1 << 21).then_some(((v & 31) as usize, (v >> 5) as u32))
}

impl Default for Ipc {
    fn default() -> Self {
        Ipc::new()
    }
}

impl Ipc {
    pub const fn new() -> Ipc {
        Ipc {
            queues: [Queue::FREE; QUEUES],
            sems: [SemSet::FREE; SEMSETS],
            segs: [Seg::FREE; SEGS],
            msgs: [Msg::FREE; MSGS],
            undo: [UNDO_FREE; UNDO_MAX],
            holds: [HOLD_FREE; HOLD_MAX],
            blocked: [BLOCKED_FREE; BLOCKED_MAX],
            counted: 0,
            pool: End::NONE,
            reap: [(0, 0); REAP_MAX],
            reaped: 0,
            dying: 0,
        }
    }

    /// The list of operations that wait at the wait queue `queue`.
    pub(super) fn queue_waiters(&mut self, queue: u32) -> Result<&mut End, u32> {
        let at = (queue as usize)
            .checked_sub(QUEUE_BASE as usize)
            .filter(|&at| at < WAIT_QUEUES)
            .ok_or(BAD_FD)?;
        if at == QUEUES + SEMSETS {
            Ok(&mut self.pool)
        } else if at < QUEUES {
            let q = &mut self.queues[at];
            if !q.live {
                return Err(BAD_FD);
            }
            Ok(&mut q.waiters)
        } else {
            let s = &mut self.sems[at - QUEUES];
            if !s.live {
                return Err(BAD_FD);
            }
            Ok(&mut s.waiters)
        }
    }

    fn queue_number(slot: usize) -> u32 {
        QUEUE_BASE + slot as u32
    }

    fn set_number(slot: usize) -> u32 {
        QUEUE_BASE + (QUEUES + slot) as u32
    }

    // ---- the pool of messages and the list of a queue ----

    fn msg_alloc(&mut self) -> Option<usize> {
        self.msgs.iter().position(|m| !m.used)
    }

    fn live_msgs(&self) -> usize {
        self.msgs.iter().filter(|m| m.used).count()
    }

    /// The wait queue of the pool of messages.
    fn pool_number() -> u32 {
        QUEUE_BASE + (QUEUES + SEMSETS) as u32
    }

    /// Whether the pool has no place for another message of the queue `q`:
    /// all 64 are in use, or the queues of its root hold their share.
    fn pool_full(&self, q: usize) -> bool {
        let root = self.queues[q].root;
        let held: usize = self
            .queues
            .iter()
            .filter(|x| x.live && x.root == root)
            .map(|x| usize::from(x.count))
            .sum();
        held >= ROOT_MSGS || self.live_msgs() >= MSGS
    }

    /// The senders that wait for the pool wake: a message went.
    fn wake_pool(&self, wakes: &mut Wakes) {
        Self::wake(self.pool.waiters, wakes);
    }

    /// The freed segment `serial`, of the creator `uid`, has its file left.
    fn reap_push(&mut self, serial: u64, uid: u32) {
        if usize::from(self.reaped) == REAP_MAX {
            self.reap.copy_within(1.., 0);
            self.reaped -= 1;
        }
        self.reap[usize::from(self.reaped)] = (serial, uid);
        self.reaped += 1;
    }

    /// The serial of a freed segment the caller may remove the file of (its
    /// creator, or the superuser), or 0.
    fn reap_take(&mut self, c: &Cred) -> u64 {
        let n = usize::from(self.reaped);
        let Some(at) = self.reap[..n]
            .iter()
            .position(|&(_, uid)| c.uid == 0 || c.uid == uid)
        else {
            return 0;
        };
        let (serial, _) = self.reap[at];
        self.reap.copy_within(at + 1..n, at);
        self.reaped -= 1;
        serial
    }

    /// Puts a message at the end of the list of queue `q`, or before the
    /// first message of a lower tag when `by_tag` (POSIX priorities).
    fn enqueue(&mut self, q: usize, tag: i64, bytes: &[u8], by_tag: bool) -> bool {
        let Some(m) = self.msg_alloc() else {
            return false;
        };
        self.msgs[m] = Msg {
            used: true,
            next: NIL,
            tag,
            len: bytes.len() as u16,
            data: {
                let mut data = [0; TEXT_MAX];
                data[..bytes.len()].copy_from_slice(bytes);
                data
            },
        };
        let queue = &mut self.queues[q];
        // Where it goes: after the last message whose tag is not lower.
        let mut before = NIL;
        let mut at = queue.head;
        if by_tag {
            while at != NIL && self.msgs[usize::from(at)].tag >= tag {
                before = at;
                at = self.msgs[usize::from(at)].next;
            }
        } else {
            before = queue.tail;
            at = NIL;
        }
        self.msgs[m].next = at;
        if before == NIL {
            queue.head = m as u8;
        } else {
            self.msgs[usize::from(before)].next = m as u8;
        }
        if at == NIL {
            queue.tail = m as u8;
        }
        queue.count += 1;
        queue.bytes += bytes.len() as u32;
        true
    }

    /// Takes message `m`, whose predecessor in the list is `before`, out of
    /// queue `q`.
    fn unlink(&mut self, q: usize, before: u8, m: u8) {
        let next = self.msgs[usize::from(m)].next;
        let queue = &mut self.queues[q];
        if before == NIL {
            queue.head = next;
        } else {
            self.msgs[usize::from(before)].next = next;
        }
        if queue.tail == m {
            queue.tail = before;
        }
        queue.count -= 1;
        queue.bytes -= u32::from(self.msgs[usize::from(m)].len);
        self.msgs[usize::from(m)] = Msg::FREE;
    }

    fn free_messages(&mut self, q: usize) {
        let mut at = self.queues[q].head;
        while at != NIL {
            let next = self.msgs[usize::from(at)].next;
            self.msgs[usize::from(at)] = Msg::FREE;
            at = next;
        }
        let queue = &mut self.queues[q];
        queue.head = NIL;
        queue.tail = NIL;
        queue.count = 0;
        queue.bytes = 0;
    }

    fn queue_free(&mut self, q: usize) -> [Option<Waiter>; WAITERS] {
        self.free_messages(q);
        let queue = &mut self.queues[q];
        let waiters = queue.waiters.waiters;
        let era = queue.era;
        *queue = Queue::FREE;
        queue.era = era;
        waiters
    }

    fn root_count(&self, root: u64, f: impl Fn(&Queue) -> bool) -> usize {
        self.queues
            .iter()
            .filter(|q| q.live && q.root == root && f(q))
            .count()
    }

    fn queue_alloc(&mut self, mq: bool, root: u64) -> Result<usize, u32> {
        if self.root_count(root, |q| q.mq == mq) >= ROOT_OBJECTS {
            return Err(fail(ENOSPC));
        }
        let q = self
            .queues
            .iter()
            .position(|q| !q.live)
            .ok_or(fail(ENOSPC))?;
        let era = self.queues[q].era.wrapping_add(1);
        self.queues[q] = Queue {
            live: true,
            era,
            mq,
            root,
            ..Queue::FREE
        };
        Ok(q)
    }

    /// The live XSI queue of the id, EIDRM for one that went when `retry`.
    fn msg_queue(&self, id: u64, retry: bool) -> Result<usize, u32> {
        let gone = if retry { fail(EIDRM) } else { fail(EINVAL) };
        let (q, era) = split_id(id).ok_or(fail(EINVAL))?;
        let queue = self.queues.get(q).ok_or(fail(EINVAL))?;
        if !queue.live || queue.mq || queue.era & 0xffff != era & 0xffff {
            return Err(gone);
        }
        Ok(q)
    }

    fn sem_set(&self, id: u64, retry: bool) -> Result<usize, u32> {
        let gone = if retry { fail(EIDRM) } else { fail(EINVAL) };
        let (s, era) = split_id(id).ok_or(fail(EINVAL))?;
        let set = self.sems.get(s).ok_or(fail(EINVAL))?;
        if !set.live || set.era & 0xffff != era & 0xffff {
            return Err(gone);
        }
        Ok(s)
    }

    fn segment(&self, id: u64) -> Result<usize, u32> {
        let (g, era) = split_id(id).ok_or(fail(EINVAL))?;
        let seg = self.segs.get(g).ok_or(fail(EINVAL))?;
        if !seg.live || seg.era & 0xffff != era & 0xffff {
            return Err(fail(EINVAL));
        }
        Ok(g)
    }

    // ---- the tables of the sessions' holds ----

    fn hold_find(&mut self, label: u64, sem: bool, obj: usize, era: u32) -> Option<usize> {
        self.holds.iter().position(|h| {
            h.used
                && !h.dying
                && h.label == label
                && h.sem == sem
                && usize::from(h.obj) == obj
                && h.era == era
        })
    }

    fn hold_add(&mut self, label: u64, sem: bool, obj: usize, era: u32) -> Result<(), u32> {
        if let Some(h) = self.hold_find(label, sem, obj, era) {
            self.holds[h].count += 1;
            return Ok(());
        }
        let h = self
            .holds
            .iter()
            .position(|h| !h.used)
            .ok_or(fail(ENOMEM))?;
        self.holds[h] = Hold {
            used: true,
            dying: false,
            sem,
            label,
            obj: obj as u8,
            era,
            count: 1,
        };
        Ok(())
    }

    /// One hold of the session less; whether it had one.
    fn hold_drop(&mut self, label: u64, sem: bool, obj: usize, era: u32) -> bool {
        let Some(h) = self.hold_find(label, sem, obj, era) else {
            return false;
        };
        self.holds[h].count -= 1;
        if self.holds[h].count == 0 {
            self.holds[h] = HOLD_FREE;
        }
        true
    }

    // ---- semaphores ----

    /// Whether the operations `ops` (num, op, flags) go through on `vals`;
    /// the values they leave in `vals` when so.
    fn sem_try(vals: &mut [u16; SEMS_MAX], ops: &[(usize, i64, i64)]) -> Result<(), Try> {
        for &(num, delta, flags) in ops {
            let nowait = flags as u64 & IPC_NOWAIT != 0;
            if delta == 0 {
                if vals[num] != 0 {
                    return Err(if nowait {
                        Try::Again
                    } else {
                        Try::Block(num, true)
                    });
                }
            } else if delta > 0 {
                let v = i64::from(vals[num]) + delta;
                if v > i64::from(SEM_VALUE_MAX) {
                    return Err(Try::Range);
                }
                vals[num] = v as u16;
            } else {
                let v = i64::from(vals[num]) + delta;
                if v < 0 {
                    return Err(if nowait {
                        Try::Again
                    } else {
                        Try::Block(num, false)
                    });
                }
                vals[num] = v as u16;
            }
        }
        Ok(())
    }

    fn undo_add(
        &mut self,
        label: u64,
        set: usize,
        era: u32,
        num: usize,
        adj: i32,
    ) -> Result<(), u32> {
        let found = self.undo.iter().position(|u| {
            u.used
                && !u.dying
                && u.label == label
                && usize::from(u.set) == set
                && u.era == era
                && usize::from(u.num) == num
        });
        let at = match found {
            Some(at) => at,
            None => {
                if adj == 0 {
                    return Ok(());
                }
                let at = self.undo.iter().position(|u| !u.used).ok_or(fail(ENOSPC))?;
                self.undo[at] = Undo {
                    used: true,
                    dying: false,
                    label,
                    set: set as u8,
                    era,
                    num: num as u8,
                    adj: 0,
                };
                at
            }
        };
        self.undo[at].adj += adj;
        if self.undo[at].adj == 0 {
            self.undo[at] = UNDO_FREE;
        }
        Ok(())
    }

    fn semwait_count(&self, set: usize, num: usize, zero: bool) -> u64 {
        if self.counted == 0 {
            return 0;
        }
        let queue = Self::set_number(set);
        self.blocked
            .iter()
            .filter(|b| b.used && b.queue == queue && b.block == Block::Sem(num as u8, zero))
            .count() as u64
    }

    /// Whether a receiver waits at queue `q`.
    fn recv_waiting(&self, q: usize) -> bool {
        if self.counted == 0 {
            return false;
        }
        let queue = Self::queue_number(q);
        self.blocked
            .iter()
            .any(|b| b.used && b.queue == queue && b.block == Block::Recv)
    }

    /// The place of the operation `key` in `blocked`: the service's keys
    /// carry the number of the operation (1 to 128) in their low half.
    fn blocked_place(key: u64) -> Option<usize> {
        let at = (key & 0xffff_ffff).checked_sub(1)? as usize;
        (at < BLOCKED_MAX).then_some(at)
    }

    /// Notes that the operation (`label`, `key`) waits, for the counts.
    pub fn note_wait(&mut self, label: u64, key: u64, queue: u32, block: Block) {
        if block == Block::Plain {
            return;
        }
        if let Some(at) = Self::blocked_place(key) {
            if !self.blocked[at].used {
                self.counted += 1;
            }
            self.blocked[at] = Blocked {
                used: true,
                label,
                key,
                queue,
                block,
            };
        }
    }

    /// The operation (`label`, `key`) waits no more.
    pub fn wait_done(&mut self, label: u64, key: u64) {
        if let Some(at) = Self::blocked_place(key) {
            let b = &mut self.blocked[at];
            if b.used && b.label == label && b.key == key {
                *b = BLOCKED_FREE;
                self.counted -= 1;
            }
        }
    }

    /// Every operation of the session waits no more.
    pub fn forget(&mut self, label: u64) {
        if self.counted == 0 {
            return;
        }
        for b in &mut self.blocked {
            if b.used && b.label == label {
                *b = BLOCKED_FREE;
                self.counted -= 1;
            }
        }
    }

    /// Wakes the list of a queue or set when the object is gone or changed.
    fn wake(waiters: [Option<Waiter>; WAITERS], wakes: &mut Wakes) {
        wakes.add(waiters);
    }

    // ---- session ends ----

    /// The session `label` went: its adjustments, attachments and opens are
    /// to be let go of, one in each step. Whether a step is due.
    pub fn gone(&mut self, label: u64) -> bool {
        for u in &mut self.undo {
            if u.used && !u.dying && u.label == label {
                u.dying = true;
                self.dying += 1;
            }
        }
        for h in &mut self.holds {
            if h.used && !h.dying && h.label == label {
                h.dying = true;
                self.dying += 1;
            }
        }
        self.dying != 0
    }

    pub fn due(&self) -> bool {
        self.dying != 0
    }

    /// One adjustment or hold of a session that went is let go of. Whether
    /// another step is due.
    pub fn step(&mut self, wakes: &mut Wakes) -> bool {
        if let Some(at) = self.undo.iter().position(|u| u.used && u.dying) {
            let u = self.undo[at];
            self.undo[at] = UNDO_FREE;
            self.dying -= 1;
            let s = usize::from(u.set);
            let set = &mut self.sems[s];
            if set.live && set.era == u.era {
                let v = i64::from(set.vals[usize::from(u.num)]) + i64::from(u.adj);
                set.vals[usize::from(u.num)] = v.clamp(0, i64::from(SEM_VALUE_MAX)) as u16;
                Self::wake(set.waiters.waiters, wakes);
            }
        } else if let Some(at) = self.holds.iter().position(|h| h.used && h.dying) {
            let h = self.holds[at];
            self.holds[at] = HOLD_FREE;
            self.dying -= 1;
            let o = usize::from(h.obj);
            if h.sem {
                let set = &mut self.sems[o];
                if set.live && set.era == h.era {
                    set.opens = set.opens.saturating_sub(h.count);
                    if set.unlinked && set.opens == 0 {
                        Self::wake(set.waiters.waiters, wakes);
                        let era = set.era;
                        *set = SemSet::FREE;
                        set.era = era;
                    }
                }
            } else {
                let seg = &mut self.segs[o];
                if seg.live && seg.era == h.era {
                    seg.nattch = seg.nattch.saturating_sub(h.count);
                    if seg.removed && seg.nattch == 0 {
                        let (era, serial, uid) = (seg.era, seg.serial, seg.perm.cuid);
                        *seg = Seg::FREE;
                        seg.era = era;
                        self.reap_push(serial, uid);
                    }
                }
            }
        }
        self.dying != 0
    }

    /// The holds of `parent` the child `child` gets at fork (shared segments
    /// stay attached, named semaphores stay open); whether there is room.
    pub fn inherit_room(&self, parent: u64) -> bool {
        let need = self
            .holds
            .iter()
            .filter(|h| h.used && !h.dying && h.label == parent)
            .count();
        self.holds.iter().filter(|h| !h.used).count() >= need
    }

    pub fn inherit(&mut self, parent: u64, child: u64) {
        for i in 0..HOLD_MAX {
            let h = self.holds[i];
            if !h.used || h.dying || h.label != parent {
                continue;
            }
            let Some(at) = self.holds.iter().position(|x| !x.used) else {
                return;
            };
            self.holds[at] = Hold { label: child, ..h };
            let o = usize::from(h.obj);
            if h.sem {
                self.sems[o].opens += h.count;
            } else {
                self.segs[o].nattch += h.count;
            }
        }
    }

    /// The image of the session `label` was replaced (exec): its segments are
    /// detached and its named semaphores closed, one in each step. Whether a
    /// step is due.
    pub fn exec(&mut self, label: u64) -> bool {
        for h in &mut self.holds {
            if h.used && !h.dying && h.label == label {
                h.dying = true;
                self.dying += 1;
            }
        }
        self.dying != 0
    }

    // ---- XSI message queues ----

    fn msg_get(&mut self, root: u64, w: &[u64], c: &Cred) -> Result<u64, u32> {
        let key = w[0] as u32 as i32;
        let flags = w[1];
        if key != 0
            && let Some(q) = self
                .queues
                .iter()
                .position(|q| q.live && !q.mq && q.perm.key == key)
        {
            if flags & IPC_CREAT != 0 && flags & IPC_EXCL != 0 {
                return Err(fail(EEXIST));
            }
            if !self.queues[q]
                .perm
                .allows(c, flags & 0o400 != 0, flags & 0o200 != 0)
            {
                return Err(fail(EACCES));
            }
            return Ok(id_of(q, self.queues[q].era));
        }
        if key != 0 && flags & IPC_CREAT == 0 {
            return Err(fail(ENOENT));
        }
        let q = self.queue_alloc(false, root)?;
        let queue = &mut self.queues[q];
        queue.perm = Perm::new(key, c, flags);
        queue.qbytes = QBYTES_DEFAULT;
        queue.maxmsg = QUEUE_MSGS as u16;
        queue.ctime = c.now;
        Ok(id_of(q, queue.era))
    }

    fn msg_snd(
        &mut self,
        w: &[u64],
        c: &Cred,
        bytes: &[u8],
        retry: bool,
        wakes: &mut Wakes,
    ) -> Result<Flow, u32> {
        let q = self.msg_queue(w[0], retry)?;
        let tag = w[1] as i64;
        if tag < 1 || bytes.len() > TEXT_MAX {
            return Err(fail(EINVAL));
        }
        let queue = &self.queues[q];
        if !queue.perm.allows(c, false, true) {
            return Err(fail(EACCES));
        }
        if bytes.len() as u32 > queue.qbytes {
            return Err(fail(EINVAL));
        }
        let queue_full = queue.bytes + bytes.len() as u32 > queue.qbytes
            || usize::from(queue.count) >= QUEUE_MSGS;
        if queue_full || self.pool_full(q) {
            if w[2] != 0 {
                return Err(fail(EAGAIN));
            }
            // The queue's own room comes with a receive, the pool's with any.
            return Ok(Flow::Wait {
                queue: if queue_full {
                    Self::queue_number(q)
                } else {
                    Self::pool_number()
                },
                block: Block::Plain,
            });
        }
        self.enqueue(q, tag, bytes, false);
        let queue = &mut self.queues[q];
        queue.lspid = c.pid;
        queue.stime = c.now;
        Self::wake(queue.waiters.waiters, wakes);
        Ok(Flow::Done)
    }

    fn msg_rcv(
        &mut self,
        w: &[u64],
        c: &Cred,
        out: &mut Out,
        retry: bool,
        wakes: &mut Wakes,
    ) -> Result<Flow, u32> {
        let q = self.msg_queue(w[0], retry)?;
        let max = w[1] as usize;
        let want = w[2] as i64;
        let flags = w[3];
        if !self.queues[q].perm.allows(c, true, false) {
            return Err(fail(EACCES));
        }
        // The message: by the type asked.
        let mut found = (NIL, NIL);
        let mut before = NIL;
        let mut at = self.queues[q].head;
        while at != NIL {
            let m = &self.msgs[usize::from(at)];
            let hit = if want == 0 {
                true
            } else if want > 0 {
                if flags & MSG_EXCEPT != 0 {
                    m.tag != want
                } else {
                    m.tag == want
                }
            } else {
                m.tag <= -want
            };
            if hit {
                let better =
                    found.1 == NIL || (want < 0 && m.tag < self.msgs[usize::from(found.1)].tag);
                if better {
                    found = (before, at);
                }
                if want >= 0 {
                    break;
                }
            }
            before = at;
            at = m.next;
        }
        if found.1 == NIL {
            if flags & IPC_NOWAIT != 0 {
                return Err(fail(ENOMSG));
            }
            return Ok(Flow::Wait {
                queue: Self::queue_number(q),
                block: Block::Plain,
            });
        }
        let m = self.msgs[usize::from(found.1)];
        let len = usize::from(m.len);
        if len > max && flags & MSG_NOERROR == 0 {
            return Err(fail(E2BIG));
        }
        let give = len.min(max);
        out.word(m.tag as u64);
        out.word(len as u64);
        out.bytes[..give].copy_from_slice(&m.data[..give]);
        out.len = give;
        self.unlink(q, found.0, found.1);
        let queue = &mut self.queues[q];
        queue.lrpid = c.pid;
        queue.rtime = c.now;
        Self::wake(queue.waiters.waiters, wakes);
        self.wake_pool(wakes);
        Ok(Flow::Done)
    }

    fn msg_ctl(
        &mut self,
        w: &[u64],
        c: &Cred,
        out: &mut Out,
        wakes: &mut Wakes,
    ) -> Result<(), u32> {
        let q = self.msg_queue(w[0], false)?;
        match w[1] {
            IPC_STAT => {
                let queue = &self.queues[q];
                if !queue.perm.allows(c, true, false) {
                    return Err(fail(EACCES));
                }
                queue.perm.put(out, queue.era);
                for v in [
                    queue.stime as u64,
                    queue.rtime as u64,
                    queue.ctime as u64,
                    u64::from(queue.bytes),
                    u64::from(queue.count),
                    u64::from(queue.qbytes),
                    u64::from(queue.lspid),
                    u64::from(queue.lrpid),
                ] {
                    out.word(v);
                }
                Ok(())
            }
            IPC_SET => {
                let queue = &mut self.queues[q];
                if !queue.perm.owns(c) {
                    return Err(fail(EPERM));
                }
                let qbytes = w[5] as u32;
                if qbytes > queue.qbytes.max(QBYTES_MAX) || qbytes == 0 {
                    return Err(fail(EPERM));
                }
                queue.perm.uid = w[2] as u32;
                queue.perm.gid = w[3] as u32;
                queue.perm.mode = (w[4] & 0o777) as u16;
                queue.qbytes = qbytes;
                queue.ctime = c.now;
                Self::wake(queue.waiters.waiters, wakes);
                Ok(())
            }
            IPC_RMID => {
                if !self.queues[q].perm.owns(c) {
                    return Err(fail(EPERM));
                }
                let waiters = self.queue_free(q);
                Self::wake(waiters, wakes);
                self.wake_pool(wakes);
                Ok(())
            }
            _ => Err(fail(EINVAL)),
        }
    }

    // ---- semaphore sets ----

    fn set_alloc(&mut self, root: u64) -> Result<usize, u32> {
        if self
            .sems
            .iter()
            .filter(|s| s.live && s.root == root)
            .count()
            >= ROOT_OBJECTS
        {
            return Err(fail(ENOSPC));
        }
        let s = self.sems.iter().position(|s| !s.live).ok_or(fail(ENOSPC))?;
        let era = self.sems[s].era.wrapping_add(1);
        self.sems[s] = SemSet {
            live: true,
            era,
            root,
            ..SemSet::FREE
        };
        Ok(s)
    }

    fn sem_get(&mut self, root: u64, w: &[u64], c: &Cred) -> Result<u64, u32> {
        let key = w[0] as u32 as i32;
        let nsems = w[1] as usize;
        let flags = w[2];
        if key != 0
            && let Some(s) = self
                .sems
                .iter()
                .position(|s| s.live && !s.named && s.perm.key == key)
        {
            if flags & IPC_CREAT != 0 && flags & IPC_EXCL != 0 {
                return Err(fail(EEXIST));
            }
            if nsems > usize::from(self.sems[s].nsems) {
                return Err(fail(EINVAL));
            }
            if !self.sems[s]
                .perm
                .allows(c, flags & 0o400 != 0, flags & 0o200 != 0)
            {
                return Err(fail(EACCES));
            }
            return Ok(id_of(s, self.sems[s].era));
        }
        if key != 0 && flags & IPC_CREAT == 0 {
            return Err(fail(ENOENT));
        }
        if nsems == 0 || nsems > SEMS_MAX {
            return Err(fail(EINVAL));
        }
        let s = self.set_alloc(root)?;
        let set = &mut self.sems[s];
        set.perm = Perm::new(key, c, flags);
        set.nsems = nsems as u8;
        set.ctime = c.now;
        Ok(id_of(s, set.era))
    }

    fn sem_op(
        &mut self,
        label: u64,
        w: &[u64],
        c: &Cred,
        retry_key: Option<u64>,
        wakes: &mut Wakes,
    ) -> Result<Flow, u32> {
        let retry = retry_key.is_some();
        let s = self.sem_set(w[0], retry)?;
        let count = w[1] as usize;
        if count == 0 || count > SEMOPS_MAX || w.len() < 2 + Cred::WORDS + 3 * count {
            return Err(fail(E2BIG));
        }
        let mut ops = [(0usize, 0i64, 0i64); SEMOPS_MAX];
        let mut alters = false;
        for (i, op) in ops[..count].iter_mut().enumerate() {
            let at = 2 + Cred::WORDS + 3 * i;
            let num = w[at] as usize;
            if num >= usize::from(self.sems[s].nsems) {
                return Err(fail(EFBIG));
            }
            *op = (
                num,
                i64::from(w[at + 1] as i16),
                i64::from(w[at + 2] as i16),
            );
            alters |= op.1 != 0;
        }
        if !self.sems[s].perm.allows(c, !alters, alters) {
            return Err(fail(EACCES));
        }
        let mut vals = self.sems[s].vals;
        match Self::sem_try(&mut vals, &ops[..count]) {
            Ok(()) => {}
            Err(Try::Block(num, zero)) => {
                return Ok(Flow::Wait {
                    queue: Self::set_number(s),
                    block: Block::Sem(num as u8, zero),
                });
            }
            Err(Try::Again) => return Err(fail(EAGAIN)),
            Err(Try::Range) => return Err(fail(ERANGE)),
        }
        // Applied: the adjustments of SEM_UNDO first, so that a full table
        // leaves the set as it was.
        let era = self.sems[s].era;
        let undo_before = self.undo;
        for &(num, delta, flags) in &ops[..count] {
            if flags & SEM_UNDO != 0
                && delta != 0
                && let Err(e) = self.undo_add(label, s, era, num, -(delta as i32))
            {
                self.undo = undo_before;
                return Err(e);
            }
        }
        let set = &mut self.sems[s];
        set.vals = vals;
        for &(num, delta, _) in &ops[..count] {
            let _ = delta;
            set.pids[num] = c.pid;
        }
        set.otime = c.now;
        Self::wake(set.waiters.waiters, wakes);
        Ok(Flow::Done)
    }

    fn sem_ctl(
        &mut self,
        w: &[u64],
        c: &Cred,
        bytes: &[u8],
        out: &mut Out,
        wakes: &mut Wakes,
    ) -> Result<(), u32> {
        let s = self.sem_set(w[0], false)?;
        let num = w[1] as usize;
        let cmd = w[2];
        let arg = w[3];
        let nsems = usize::from(self.sems[s].nsems);
        match cmd {
            IPC_RMID => {
                if !self.sems[s].perm.owns(c) {
                    return Err(fail(EPERM));
                }
                let set = &mut self.sems[s];
                let waiters = set.waiters.waiters;
                let era = set.era;
                *set = SemSet::FREE;
                set.era = era;
                for u in &mut self.undo {
                    if u.used && usize::from(u.set) == s && u.era == era {
                        *u = UNDO_FREE;
                    }
                }
                for h in &mut self.holds {
                    if h.used && h.sem && usize::from(h.obj) == s && h.era == era {
                        *h = HOLD_FREE;
                    }
                }
                Self::wake(waiters, wakes);
                Ok(())
            }
            IPC_SET => {
                let set = &mut self.sems[s];
                if !set.perm.owns(c) {
                    return Err(fail(EPERM));
                }
                if w.len() < 4 + Cred::WORDS + 3 {
                    return Err(fail(EINVAL));
                }
                set.perm.uid = w[4 + Cred::WORDS] as u32;
                set.perm.gid = w[5 + Cred::WORDS] as u32;
                set.perm.mode = (w[6 + Cred::WORDS] & 0o777) as u16;
                set.ctime = c.now;
                Ok(())
            }
            IPC_STAT => {
                let set = &self.sems[s];
                if !set.perm.allows(c, true, false) {
                    return Err(fail(EACCES));
                }
                set.perm.put(out, set.era);
                out.word(set.otime as u64);
                out.word(set.ctime as u64);
                out.word(u64::from(set.nsems));
                Ok(())
            }
            GETVAL | GETPID | GETNCNT | GETZCNT | SETVAL => {
                if num >= nsems {
                    return Err(fail(EINVAL));
                }
                let set = &mut self.sems[s];
                if !set.perm.allows(c, cmd != SETVAL, cmd == SETVAL) {
                    return Err(fail(EACCES));
                }
                match cmd {
                    GETVAL => out.word(u64::from(set.vals[num])),
                    GETPID => out.word(u64::from(set.pids[num])),
                    GETNCNT => {
                        let n = self.semwait_count(s, num, false);
                        out.word(n);
                    }
                    GETZCNT => {
                        let n = self.semwait_count(s, num, true);
                        out.word(n);
                    }
                    _ => {
                        if arg > u64::from(SEM_VALUE_MAX) {
                            return Err(fail(ERANGE));
                        }
                        set.vals[num] = arg as u16;
                        set.ctime = c.now;
                        for u in &mut self.undo {
                            if u.used
                                && !u.dying
                                && usize::from(u.set) == s
                                && u.era == set.era
                                && usize::from(u.num) == num
                            {
                                *u = UNDO_FREE;
                            }
                        }
                        Self::wake(set.waiters.waiters, wakes);
                    }
                }
                Ok(())
            }
            GETALL => {
                let set = &self.sems[s];
                if !set.perm.allows(c, true, false) {
                    return Err(fail(EACCES));
                }
                for i in 0..nsems {
                    out.bytes[2 * i..2 * i + 2].copy_from_slice(&set.vals[i].to_le_bytes());
                }
                out.len = 2 * nsems;
                Ok(())
            }
            SETALL => {
                if bytes.len() != 2 * nsems {
                    return Err(fail(EINVAL));
                }
                let mut vals = [0u16; SEMS_MAX];
                for i in 0..nsems {
                    let v = u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]);
                    if u32::from(v) > SEM_VALUE_MAX {
                        return Err(fail(ERANGE));
                    }
                    vals[i] = v;
                }
                let set = &mut self.sems[s];
                if !set.perm.allows(c, false, true) {
                    return Err(fail(EACCES));
                }
                set.vals = vals;
                set.ctime = c.now;
                for u in &mut self.undo {
                    if u.used && !u.dying && usize::from(u.set) == s && u.era == set.era {
                        *u = UNDO_FREE;
                    }
                }
                Self::wake(set.waiters.waiters, wakes);
                Ok(())
            }
            _ => Err(fail(EINVAL)),
        }
    }

    // ---- shared memory segments ----

    fn shm_get(&mut self, root: u64, w: &[u64], c: &Cred, out: &mut Out) -> Result<(), u32> {
        let key = w[0] as u32 as i32;
        let size = w[1];
        let flags = w[2];
        if key != 0
            && let Some(g) = self
                .segs
                .iter()
                .position(|g| g.live && !g.removed && g.perm.key == key)
        {
            if flags & IPC_CREAT != 0 && flags & IPC_EXCL != 0 {
                return Err(fail(EEXIST));
            }
            if size > self.segs[g].size {
                return Err(fail(EINVAL));
            }
            if !self.segs[g]
                .perm
                .allows(c, flags & 0o400 != 0, flags & 0o200 != 0)
            {
                return Err(fail(EACCES));
            }
            out.word(id_of(g, self.segs[g].era));
            out.word(self.segs[g].serial);
            out.word(0);
            let reap = self.reap_take(c);
            out.word(reap);
            return Ok(());
        }
        if key != 0 && flags & IPC_CREAT == 0 {
            return Err(fail(ENOENT));
        }
        if size == 0 || size > SHM_MAX {
            return Err(fail(EINVAL));
        }
        if self
            .segs
            .iter()
            .filter(|g| g.live && g.root == root)
            .count()
            >= ROOT_OBJECTS
        {
            return Err(fail(ENOSPC));
        }
        // The name of the file of the pages is the creator's random number:
        // nobody else knows it before the file is there.
        let nonce = w[3];
        if nonce == 0 {
            return Err(fail(EINVAL));
        }
        if self.segs.iter().any(|g| g.live && g.serial == nonce) {
            return Err(fail(EEXIST));
        }
        let g = self.segs.iter().position(|g| !g.live).ok_or(fail(ENOSPC))?;
        let era = self.segs[g].era.wrapping_add(1);
        self.segs[g] = Seg {
            live: true,
            era,
            perm: Perm::new(key, c, flags),
            size,
            serial: nonce,
            cpid: c.pid,
            ctime: c.now,
            root,
            ..Seg::FREE
        };
        out.word(id_of(g, era));
        out.word(nonce);
        out.word(1);
        let reap = self.reap_take(c);
        out.word(reap);
        Ok(())
    }

    fn shm_at(&mut self, label: u64, w: &[u64], c: &Cred, out: &mut Out) -> Result<(), u32> {
        let g = self.segment(w[0])?;
        let seg = &self.segs[g];
        if seg.removed {
            return Err(fail(EIDRM));
        }
        if !seg.perm.allows(c, true, w[1] & SHM_RDONLY == 0) {
            return Err(fail(EACCES));
        }
        let era = seg.era;
        self.hold_add(label, false, g, era)?;
        let seg = &mut self.segs[g];
        seg.nattch += 1;
        seg.atime = c.now;
        seg.lpid = c.pid;
        out.word(seg.serial);
        out.word(seg.size);
        out.word(u64::from(seg.perm.uid));
        out.word(u64::from(seg.perm.cuid));
        let reap = self.reap_take(c);
        out.word(reap);
        Ok(())
    }

    fn shm_dt(&mut self, label: u64, w: &[u64], c: &Cred, out: &mut Out) -> Result<(), u32> {
        let g = self.segment(w[0])?;
        let era = self.segs[g].era;
        let counted = self.hold_drop(label, false, g, era);
        let seg = &mut self.segs[g];
        if counted {
            seg.nattch = seg.nattch.saturating_sub(1);
            seg.dtime = c.now;
            seg.lpid = c.pid;
        }
        if seg.removed && seg.nattch == 0 {
            let (serial, creator) = (seg.serial, seg.perm.cuid);
            out.word(1);
            out.word(serial);
            *seg = Seg::FREE;
            seg.era = era;
            // The caller removes the file; another user's, left to its creator.
            if c.uid != creator && c.uid != 0 {
                self.reap_push(serial, creator);
            }
        } else {
            out.word(0);
            out.word(seg.serial);
        }
        let reap = self.reap_take(c);
        out.word(reap);
        Ok(())
    }

    fn shm_ctl(&mut self, w: &[u64], c: &Cred, out: &mut Out) -> Result<(), u32> {
        let g = self.segment(w[0])?;
        match w[1] {
            IPC_STAT => {
                let seg = &self.segs[g];
                if !seg.perm.allows(c, true, false) {
                    return Err(fail(EACCES));
                }
                seg.perm.put(out, seg.era);
                for v in [
                    seg.size,
                    seg.atime as u64,
                    seg.dtime as u64,
                    seg.ctime as u64,
                    u64::from(seg.cpid),
                    u64::from(seg.lpid),
                    u64::from(seg.nattch),
                    seg.serial,
                ] {
                    out.word(v);
                }
                let reap = self.reap_take(c);
                out.word(reap);
                Ok(())
            }
            IPC_SET => {
                let seg = &mut self.segs[g];
                if !seg.perm.owns(c) {
                    return Err(fail(EPERM));
                }
                seg.perm.uid = w[5] as u32;
                seg.perm.gid = w[6] as u32;
                seg.perm.mode = (w[7] & 0o777) as u16;
                seg.ctime = c.now;
                out.word(0);
                out.word(seg.serial);
                let reap = self.reap_take(c);
                out.word(reap);
                Ok(())
            }
            IPC_RMID => {
                let seg = &mut self.segs[g];
                if !seg.perm.owns(c) {
                    return Err(fail(EPERM));
                }
                if seg.nattch == 0 {
                    let (serial, era, creator) = (seg.serial, seg.era, seg.perm.cuid);
                    *seg = Seg::FREE;
                    seg.era = era;
                    out.word(1);
                    out.word(serial);
                    if c.uid != creator && c.uid != 0 {
                        self.reap_push(serial, creator);
                    }
                } else {
                    // The key goes now; the segment goes with its last detach.
                    seg.removed = true;
                    seg.perm.key = 0;
                    out.word(0);
                    out.word(seg.serial);
                }
                let reap = self.reap_take(c);
                out.word(reap);
                Ok(())
            }
            _ => Err(fail(EINVAL)),
        }
    }

    // ---- named semaphores ----

    fn nsem_open(
        &mut self,
        label: u64,
        root: u64,
        w: &[u64],
        c: &Cred,
        name: &[u8],
    ) -> Result<u64, u32> {
        let oflag = w[0];
        if name.is_empty() || name.len() > NAME_MAX {
            return Err(fail(if name.is_empty() { EINVAL } else { 36 }));
        }
        let found = self.sems.iter().position(|s| {
            s.live && s.named && !s.unlinked && &s.name[..usize::from(s.name_len)] == name
        });
        let s = match found {
            Some(s) => {
                if oflag & O_CREAT != 0 && oflag & O_EXCL != 0 {
                    return Err(fail(EEXIST));
                }
                if !self.sems[s].perm.allows(c, true, true) {
                    return Err(fail(EACCES));
                }
                s
            }
            None => {
                if oflag & O_CREAT == 0 {
                    return Err(fail(ENOENT));
                }
                if w[2] > u64::from(SEM_VALUE_MAX) {
                    return Err(fail(EINVAL));
                }
                let s = self.set_alloc(root)?;
                let set = &mut self.sems[s];
                set.named = true;
                set.perm = Perm::new(0, c, w[1]);
                set.name[..name.len()].copy_from_slice(name);
                set.name_len = name.len() as u8;
                set.nsems = 1;
                set.vals[0] = w[2] as u16;
                set.ctime = c.now;
                s
            }
        };
        let era = self.sems[s].era;
        if let Err(e) = self.hold_add(label, true, s, era) {
            if found.is_none() {
                self.sems[s] = SemSet {
                    era,
                    ..SemSet::FREE
                };
            }
            return Err(e);
        }
        self.sems[s].opens += 1;
        Ok(id_of(s, era))
    }

    fn nsem_unlink(&mut self, name: &[u8], c: &Cred, wakes: &mut Wakes) -> Result<(), u32> {
        let s = self
            .sems
            .iter()
            .position(|s| {
                s.live && s.named && !s.unlinked && &s.name[..usize::from(s.name_len)] == name
            })
            .ok_or(fail(ENOENT))?;
        let set = &mut self.sems[s];
        if !set.perm.owns(c) {
            return Err(fail(EACCES));
        }
        set.unlinked = true;
        if set.opens == 0 {
            Self::wake(set.waiters.waiters, wakes);
            let era = set.era;
            *set = SemSet::FREE;
            set.era = era;
        }
        Ok(())
    }

    fn nsem_close(&mut self, label: u64, w: &[u64], wakes: &mut Wakes) -> Result<(), u32> {
        let s = self.sem_set(w[0], false)?;
        let era = self.sems[s].era;
        if self.hold_drop(label, true, s, era) {
            let set = &mut self.sems[s];
            set.opens = set.opens.saturating_sub(1);
            if set.unlinked && set.opens == 0 {
                Self::wake(set.waiters.waiters, wakes);
                *set = SemSet {
                    era,
                    ..SemSet::FREE
                };
            }
        }
        Ok(())
    }

    fn nsem_wait(
        &mut self,
        label: u64,
        w: &[u64],
        c: &Cred,
        retry: bool,
        wakes: &mut Wakes,
    ) -> Result<Flow, u32> {
        let s = self.sem_set(w[0], retry)?;
        let set = &mut self.sems[s];
        if !set.named {
            return Err(fail(EINVAL));
        }
        let _ = label;
        if set.vals[0] > 0 {
            set.vals[0] -= 1;
            set.pids[0] = c.pid;
            return Ok(Flow::Done);
        }
        let _ = wakes;
        if w[1] != 0 {
            return Err(fail(EAGAIN));
        }
        Ok(Flow::Wait {
            queue: Self::set_number(s),
            block: Block::Plain,
        })
    }

    fn nsem_post(&mut self, w: &[u64], c: &Cred, wakes: &mut Wakes) -> Result<(), u32> {
        let s = self.sem_set(w[0], false)?;
        let set = &mut self.sems[s];
        if !set.named {
            return Err(fail(EINVAL));
        }
        if u32::from(set.vals[0]) >= SEM_VALUE_MAX {
            return Err(fail(EOVERFLOW));
        }
        set.vals[0] += 1;
        set.pids[0] = c.pid;
        Self::wake(set.waiters.waiters, wakes);
        Ok(())
    }

    // ---- POSIX message queues ----

    fn name_ok(name: &[u8]) -> Result<&[u8], u32> {
        // "/name": one slash first, no other.
        if name.len() < 2 || name[0] != b'/' || name[1..].contains(&b'/') {
            return Err(fail(EINVAL));
        }
        if name.len() > NAME_MAX {
            return Err(fail(36));
        }
        Ok(&name[1..])
    }

    /// The live queue `queue` (slot, era) a description names.
    fn mq_queue(&self, queue: (u8, u32)) -> Result<usize, u32> {
        let q = usize::from(queue.0);
        match self.queues.get(q) {
            Some(x) if x.live && x.mq && x.era == queue.1 => Ok(q),
            _ => Err(fail(EBADF)),
        }
    }
}

impl Pipes {
    /// The wait queue `queue` of an IPC object, from the numbers after the
    /// sockets'.
    pub(super) fn ipc_queue(&mut self, queue: u32) -> Result<&mut End, u32> {
        self.ipc.queue_waiters(queue)
    }

    /// An open message queue's last description closed.
    pub(super) fn mq_closed(&mut self, slot: usize, queue: (u8, u32), wakes: &mut Wakes) {
        let Ok(q) = self.ipc.mq_queue(queue) else {
            return;
        };
        let x = &mut self.ipc.queues[q];
        x.opens = x.opens.saturating_sub(1);
        if matches!(x.notify, Notify::Armed(d) | Notify::Fired(d) if usize::from(d) == slot) {
            x.notify = Notify::None;
        }
        if x.unlinked && x.opens == 0 {
            let waiters = self.ipc.queue_free(q);
            Ipc::wake(waiters, wakes);
            self.ipc.wake_pool(wakes);
        } else {
            Ipc::wake(x.waiters.waiters, wakes);
        }
    }

    /// A call of the IPC methods. `label` is the session's, `root` its
    /// root; `held` its descriptions (an open adds one).
    #[allow(clippy::too_many_arguments)]
    pub fn ipc_call(
        &mut self,
        held: &mut Held,
        label: u64,
        root: u64,
        call: &Call<'_>,
        who: Who,
        out: &mut Out,
        wakes: &mut Wakes,
    ) -> Result<Flow, u32> {
        let w = call.words();
        let retry = call.key.is_some();
        // The words every operation needs, and the credentials where the
        // operation has them.
        let need = |n: usize| -> Result<(), u32> {
            if w.len() < n {
                Err(fail(EINVAL))
            } else {
                Ok(())
            }
        };
        let cred = |at: usize| -> Result<Cred, u32> {
            if w.len() < at + Cred::WORDS {
                Err(fail(EINVAL))
            } else {
                Ok(Cred::of(who, &w[at..at + Cred::WORDS]))
            }
        };
        match call.op {
            op::MQ_OPEN => {
                need(5 + Cred::WORDS)?;
                let c = cred(5)?;
                self.mq_open(held, label, root, w, &c, call.bytes, out)?;
                Ok(Flow::Done)
            }
            op::MQ_UNLINK => {
                need(Cred::WORDS)?;
                let c = cred(0)?;
                let name = Ipc::name_ok(call.bytes)?;
                let q = self
                    .ipc
                    .queues
                    .iter()
                    .position(|q| q.has_name(name))
                    .ok_or(fail(ENOENT))?;
                let x = &mut self.ipc.queues[q];
                // The name is the owner's to take away (EACCES otherwise).
                if !x.perm.owns(&c) {
                    return Err(fail(EACCES));
                }
                x.unlinked = true;
                if x.opens == 0 {
                    let waiters = self.ipc.queue_free(q);
                    Ipc::wake(waiters, wakes);
                    self.ipc.wake_pool(wakes);
                }
                Ok(Flow::Done)
            }
            op::MQ_SEND => {
                need(3 + Cred::WORDS)?;
                let c = cred(3)?;
                self.mq_send(held, w, &c, call.bytes, wakes)
            }
            op::MQ_RECV => {
                need(2 + Cred::WORDS)?;
                let c = cred(2)?;
                self.mq_receive(held, w, &c, out, wakes)
            }
            op::MQ_GETATTR | op::MQ_SETATTR => {
                need(if call.op == op::MQ_SETATTR { 2 } else { 1 })?;
                let (i, queue, _, nonblock) =
                    self.mq_slot(held, Endpoint::socket(slot_of(w[0])))?;
                let q = self.ipc.mq_queue(queue)?;
                let x = &self.ipc.queues[q];
                out.word(if nonblock { O_NONBLOCK } else { 0 });
                out.word(u64::from(x.maxmsg));
                out.word(u64::from(x.msgsize));
                out.word(u64::from(x.count));
                if call.op == op::MQ_SETATTR {
                    self.mq_set_nonblock(i, w[1] & O_NONBLOCK != 0);
                }
                Ok(Flow::Done)
            }
            op::MQ_NOTIFY => {
                need(2)?;
                let (i, queue, _, _) = self.mq_slot(held, Endpoint::socket(slot_of(w[0])))?;
                let q = self.ipc.mq_queue(queue)?;
                let x = &mut self.ipc.queues[q];
                if w[1] != 0 {
                    if x.notify != Notify::None {
                        return Err(fail(EBUSY));
                    }
                    x.notify = Notify::Armed(i as u8);
                } else if matches!(x.notify, Notify::Armed(d) | Notify::Fired(d) if usize::from(d) == i)
                {
                    x.notify = Notify::None;
                    Ipc::wake(x.waiters.waiters, wakes);
                }
                Ok(Flow::Done)
            }
            op::MQ_NOTIFY_WAIT => {
                need(1)?;
                let (i, queue, _, _) = self.mq_slot(held, Endpoint::socket(slot_of(w[0])))?;
                let q = self.ipc.mq_queue(queue)?;
                let x = &mut self.ipc.queues[q];
                match x.notify {
                    Notify::Fired(d) if usize::from(d) == i => {
                        x.notify = Notify::None;
                        out.word(1);
                        Ok(Flow::Done)
                    }
                    Notify::Armed(d) if usize::from(d) == i => Ok(Flow::Wait {
                        queue: Ipc::queue_number(q),
                        block: Block::Plain,
                    }),
                    _ => {
                        out.word(2);
                        Ok(Flow::Done)
                    }
                }
            }
            op::MSG_GET => {
                need(2 + Cred::WORDS)?;
                let c = cred(2)?;
                out.word(self.ipc.msg_get(root, w, &c)?);
                Ok(Flow::Done)
            }
            op::MSG_SND => {
                need(3 + Cred::WORDS)?;
                let c = cred(3)?;
                self.ipc.msg_snd(w, &c, call.bytes, retry, wakes)
            }
            op::MSG_RCV => {
                need(4 + Cred::WORDS)?;
                let c = cred(4)?;
                self.ipc.msg_rcv(w, &c, out, retry, wakes)
            }
            op::MSG_CTL => {
                need(2 + Cred::WORDS)?;
                let c = cred(2)?;
                // IPC_SET carries uid, gid, mode and qbytes after the credentials.
                let mut set = [0u64; 6];
                set[0] = w[0];
                set[1] = w[1];
                if w[1] == IPC_SET {
                    need(2 + Cred::WORDS + 4)?;
                    set[2..6].copy_from_slice(&w[2 + Cred::WORDS..2 + Cred::WORDS + 4]);
                }
                self.ipc.msg_ctl(&set, &c, out, wakes)?;
                Ok(Flow::Done)
            }
            op::SEM_GET => {
                need(3 + Cred::WORDS)?;
                let c = cred(3)?;
                out.word(self.ipc.sem_get(root, w, &c)?);
                Ok(Flow::Done)
            }
            op::SEM_OP => {
                need(2 + Cred::WORDS)?;
                let c = cred(2)?;
                self.ipc.sem_op(label, w, &c, call.key, wakes)
            }
            op::SEM_CTL => {
                need(4 + Cred::WORDS)?;
                let c = cred(4)?;
                self.ipc.sem_ctl(w, &c, call.bytes, out, wakes)?;
                Ok(Flow::Done)
            }
            op::SHM_GET => {
                need(4 + Cred::WORDS)?;
                let c = cred(4)?;
                self.ipc.shm_get(root, w, &c, out)?;
                Ok(Flow::Done)
            }
            op::SHM_AT => {
                need(2 + Cred::WORDS)?;
                let c = cred(2)?;
                self.ipc.shm_at(label, w, &c, out)?;
                Ok(Flow::Done)
            }
            op::SHM_DT => {
                need(1 + Cred::WORDS)?;
                let c = cred(1)?;
                self.ipc.shm_dt(label, w, &c, out)?;
                Ok(Flow::Done)
            }
            op::SHM_CTL => {
                need(2 + Cred::WORDS)?;
                let c = cred(2)?;
                let mut set = [0u64; 8];
                set[0] = w[0];
                set[1] = w[1];
                if w[1] == IPC_SET {
                    need(2 + Cred::WORDS + 3)?;
                    set[5..8].copy_from_slice(&w[2 + Cred::WORDS..2 + Cred::WORDS + 3]);
                }
                self.ipc.shm_ctl(&set, &c, out)?;
                Ok(Flow::Done)
            }
            op::NSEM_OPEN => {
                need(3 + Cred::WORDS)?;
                let c = cred(3)?;
                let name = Ipc::name_ok(call.bytes)?;
                out.word(self.ipc.nsem_open(label, root, w, &c, name)?);
                Ok(Flow::Done)
            }
            op::NSEM_UNLINK => {
                need(Cred::WORDS)?;
                let c = cred(0)?;
                let name = Ipc::name_ok(call.bytes)?;
                self.ipc.nsem_unlink(name, &c, wakes)?;
                Ok(Flow::Done)
            }
            op::NSEM_CLOSE => {
                need(1)?;
                self.ipc.nsem_close(label, w, wakes)?;
                Ok(Flow::Done)
            }
            op::NSEM_WAIT => {
                need(2 + Cred::WORDS)?;
                let c = cred(2)?;
                self.ipc.nsem_wait(label, w, &c, retry, wakes)
            }
            op::NSEM_POST => {
                need(1 + Cred::WORDS)?;
                let c = cred(1)?;
                self.ipc.nsem_post(w, &c, wakes)?;
                Ok(Flow::Done)
            }
            op::NSEM_VALUE => {
                need(1)?;
                let s = self.ipc.sem_set(w[0], false)?;
                out.word(u64::from(self.ipc.sems[s].vals[0]));
                Ok(Flow::Done)
            }
            _ => Err(fail(EINVAL)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn mq_open(
        &mut self,
        held: &mut Held,
        label: u64,
        root: u64,
        w: &[u64],
        c: &Cred,
        name: &[u8],
        out: &mut Out,
    ) -> Result<(), u32> {
        let name = Ipc::name_ok(name)?;
        let oflag = w[0];
        let access = (oflag & O_ACCMODE) as u32;
        if access == 3 {
            return Err(fail(EINVAL));
        }
        let (read, write) = (access != 1, access != 0);
        let existing = self.ipc.queues.iter().position(|q| q.has_name(name));
        let (q, created) = match existing {
            Some(q) => {
                if oflag & O_CREAT != 0 && oflag & O_EXCL != 0 {
                    return Err(fail(EEXIST));
                }
                if !self.ipc.queues[q].perm.allows(c, read, write) {
                    return Err(fail(EACCES));
                }
                (q, false)
            }
            None => {
                if oflag & O_CREAT == 0 {
                    return Err(fail(ENOENT));
                }
                let (maxmsg, msgsize) = if w[4] != 0 {
                    if w[2] == 0 || w[2] > QUEUE_MSGS as u64 || w[3] == 0 || w[3] > TEXT_MAX as u64
                    {
                        return Err(fail(EINVAL));
                    }
                    (w[2] as u16, w[3] as u16)
                } else {
                    (8, TEXT_MAX as u16)
                };
                let q = self.ipc.queue_alloc(true, root)?;
                let x = &mut self.ipc.queues[q];
                x.perm = Perm::new(0, c, w[1]);
                x.name[..name.len()].copy_from_slice(name);
                x.name_len = name.len() as u8;
                x.maxmsg = maxmsg;
                x.msgsize = msgsize;
                x.ctime = c.now;
                (q, true)
            }
        };
        let era = self.ipc.queues[q].era;
        match self.mq_alloc(
            held,
            label,
            root,
            oflag & O_NONBLOCK != 0,
            access,
            (q as u8, era),
        ) {
            Ok(id) => {
                self.ipc.queues[q].opens += 1;
                out.word(u64::from(id));
                Ok(())
            }
            Err(code) => {
                if created {
                    let _ = self.ipc.queue_free(q);
                }
                Err(code)
            }
        }
    }

    fn mq_send(
        &mut self,
        held: &Held,
        w: &[u64],
        c: &Cred,
        bytes: &[u8],
        wakes: &mut Wakes,
    ) -> Result<Flow, u32> {
        let (_, queue, access, nonblock) = self.mq_slot(held, Endpoint::socket(slot_of(w[0])))?;
        if access == 0 {
            return Err(fail(EBADF));
        }
        let q = self.ipc.mq_queue(queue)?;
        let prio = w[1];
        let x = &self.ipc.queues[q];
        if prio >= MQ_PRIO_MAX {
            return Err(fail(EINVAL));
        }
        if bytes.len() > usize::from(x.msgsize) {
            return Err(fail(EMSGSIZE));
        }
        let queue_full = usize::from(x.count) >= usize::from(x.maxmsg);
        if queue_full || self.ipc.pool_full(q) {
            if nonblock {
                return Err(fail(EAGAIN));
            }
            return Ok(Flow::Wait {
                queue: if queue_full {
                    Ipc::queue_number(q)
                } else {
                    Ipc::pool_number()
                },
                block: Block::Plain,
            });
        }
        let was_empty = x.count == 0;
        let recv_waiting = self.ipc.recv_waiting(q);
        self.ipc.enqueue(q, prio as i64, bytes, true);
        let x = &mut self.ipc.queues[q];
        x.lspid = c.pid;
        x.stime = c.now;
        if was_empty
            && !recv_waiting
            && let Notify::Armed(d) = x.notify
        {
            x.notify = Notify::Fired(d);
        }
        Ipc::wake(x.waiters.waiters, wakes);
        Ok(Flow::Done)
    }

    fn mq_receive(
        &mut self,
        held: &Held,
        w: &[u64],
        c: &Cred,
        out: &mut Out,
        wakes: &mut Wakes,
    ) -> Result<Flow, u32> {
        let (_, queue, access, nonblock) = self.mq_slot(held, Endpoint::socket(slot_of(w[0])))?;
        if access == 1 {
            return Err(fail(EBADF));
        }
        let q = self.ipc.mq_queue(queue)?;
        let x = &self.ipc.queues[q];
        if (w[1] as usize) < usize::from(x.msgsize) {
            return Err(fail(EMSGSIZE));
        }
        if x.count == 0 {
            if nonblock {
                return Err(fail(EAGAIN));
            }
            return Ok(Flow::Wait {
                queue: Ipc::queue_number(q),
                block: Block::Recv,
            });
        }
        let head = x.head;
        let m = self.ipc.msgs[usize::from(head)];
        out.word(m.tag as u64);
        out.bytes[..usize::from(m.len)].copy_from_slice(&m.data[..usize::from(m.len)]);
        out.len = usize::from(m.len);
        self.ipc.unlink(q, NIL, head);
        let x = &mut self.ipc.queues[q];
        x.lrpid = c.pid;
        x.rtime = c.now;
        Ipc::wake(x.waiters.waiters, wakes);
        self.ipc.wake_pool(wakes);
        Ok(Flow::Done)
    }

    /// The session `label` went (see [Ipc::gone]).
    pub fn ipc_gone(&mut self, label: u64) -> bool {
        self.ipc.gone(label)
    }

    /// An operation that waited is over.
    pub fn ipc_wait_done(&mut self, label: u64, key: u64) {
        self.ipc.wait_done(label, key);
    }

    /// An operation starts to wait.
    pub fn ipc_note_wait(&mut self, label: u64, key: u64, queue: u32, block: Block) {
        self.ipc.note_wait(label, key, queue, block);
    }

    /// The operations of the session wait no more.
    pub fn ipc_forget(&mut self, label: u64) {
        self.ipc.forget(label);
    }

    /// Whether a child of `parent` can get the holds of `parent`.
    pub fn ipc_inherit_room(&self, parent: u64) -> bool {
        self.ipc.inherit_room(parent)
    }

    /// A child of fork gets the attachments and opens of its parent.
    pub fn ipc_inherit(&mut self, parent: u64, child: u64) {
        self.ipc.inherit(parent, child);
    }

    /// The session's image was replaced (exec): its holds go. Whether a step
    /// is due.
    pub fn ipc_exec(&mut self, label: u64) -> bool {
        self.ipc.exec(label)
    }

    pub fn ipc_step(&mut self, wakes: &mut Wakes) -> bool {
        self.ipc.step(wakes)
    }

    pub fn ipc_due(&self) -> bool {
        self.ipc.due()
    }
}

/// The slot of the description a word names (`SOCK_END | slot`).
fn slot_of(word: u64) -> u32 {
    (word as u32) & !SOCK_END
}

#[allow(dead_code)]
const _: () = assert!(MQ_KIND != proto_pipe::sock::STREAM && MQ_KIND != proto_pipe::sock::DGRAM);

#[cfg(test)]
mod tests {
    use super::*;

    const WHO: Who = Who {
        uid: 1000,
        gid: 100,
        pid: 7,
    };
    const NOW: u64 = 50;

    /// A name for the file of a new segment, as the library draws one.
    fn nonce() -> u64 {
        static NEXT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0x5eed_0000);
        NEXT.fetch_add(0x9e37, core::sync::atomic::Ordering::Relaxed)
    }

    fn pipes() -> Box<Pipes> {
        Box::new(Pipes::new())
    }

    fn cred() -> Vec<u64> {
        vec![NOW]
    }

    struct Run {
        held: Held,
        wakes: Wakes,
        who: Who,
    }

    impl Run {
        fn new() -> Run {
            Run {
                held: Held::default(),
                wakes: Wakes::default(),
                who: WHO,
            }
        }

        fn call(
            &mut self,
            p: &mut Pipes,
            label: u64,
            op: u32,
            words: &[u64],
            bytes: &[u8],
            key: Option<u64>,
        ) -> (Result<Flow, u32>, Out) {
            let mut call = Call::new(op, words, bytes);
            call.key = key;
            let mut out = Out::new();
            self.wakes = Wakes::default();
            let flow = p.ipc_call(
                &mut self.held,
                label,
                label,
                &call,
                self.who,
                &mut out,
                &mut self.wakes,
            );
            (flow, out)
        }

        fn ok(&mut self, p: &mut Pipes, op: u32, words: &[u64], bytes: &[u8]) -> Out {
            let (flow, out) = self.call(p, 1, op, words, bytes, None);
            assert_eq!(flow, Ok(Flow::Done), "op {op}");
            out
        }

        fn err(&mut self, p: &mut Pipes, op: u32, words: &[u64], bytes: &[u8]) -> u32 {
            let (flow, _) = self.call(p, 1, op, words, bytes, None);
            flow.expect_err("an error") - proto_pipe::ipc::ERRNO
        }
    }

    fn with_cred(words: &[u64]) -> Vec<u64> {
        let mut v = words.to_vec();
        v.extend(cred());
        v
    }

    fn open(r: &mut Run, p: &mut Pipes, name: &[u8], oflag: u64, maxmsg: u64, msgsize: u64) -> u64 {
        let w = with_cred(&[oflag, 0o600, maxmsg, msgsize, 1]);
        r.ok(p, op::MQ_OPEN, &w, name).words[0]
    }

    #[test]
    fn a_queue_hands_out_the_highest_priority_first() {
        let (mut p, mut r) = (pipes(), Run::new());
        let d = open(&mut r, &mut p, b"/q", O_CREAT | 2, 2, 3);
        r.ok(&mut p, op::MQ_SEND, &with_cred(&[d, 0, 0]), b"foo");
        r.ok(&mut p, op::MQ_SEND, &with_cred(&[d, 1, 0]), b"bar");
        assert_eq!(r.err(&mut p, op::MQ_RECV, &with_cred(&[d, 1]), b""), 90);
        let out = r.ok(&mut p, op::MQ_RECV, &with_cred(&[d, 3]), b"");
        assert_eq!((out.words[0], &out.bytes[..out.len]), (1, &b"bar"[..]));
        let out = r.ok(&mut p, op::MQ_RECV, &with_cred(&[d, 3]), b"");
        assert_eq!((out.words[0], &out.bytes[..out.len]), (0, &b"foo"[..]));
    }

    #[test]
    fn equal_priorities_keep_their_order() {
        let (mut p, mut r) = (pipes(), Run::new());
        let d = open(&mut r, &mut p, b"/q", O_CREAT | 2, 4, 1);
        for (prio, text) in [(1, b"a"), (1, b"b"), (2, b"c"), (1, b"d")] {
            r.ok(&mut p, op::MQ_SEND, &with_cred(&[d, prio, 0]), text);
        }
        let mut got = Vec::new();
        for _ in 0..4 {
            let out = r.ok(&mut p, op::MQ_RECV, &with_cred(&[d, 1]), b"");
            got.push(out.bytes[0]);
        }
        assert_eq!(got, b"cabd");
    }

    #[test]
    fn a_full_queue_waits_or_is_eagain_and_a_receive_wakes_the_sender() {
        let (mut p, mut r) = (pipes(), Run::new());
        let d = open(&mut r, &mut p, b"/q", O_CREAT | 2, 1, 1);
        r.ok(&mut p, op::MQ_SEND, &with_cred(&[d, 0, 0]), b"x");
        let (flow, _) = r.call(&mut p, 1, op::MQ_SEND, &with_cred(&[d, 0, 0]), b"y", None);
        let Ok(Flow::Wait { queue, block }) = flow else {
            panic!("{flow:?}");
        };
        assert_eq!(block, Block::Plain);
        p.wait(queue, (9, 9), |_| true).unwrap();
        r.ok(&mut p, op::MQ_RECV, &with_cred(&[d, 1]), b"");
        assert_eq!(r.wakes.iter().collect::<Vec<_>>(), vec![(9, 9)]);
        // The description's flag makes it EAGAIN.
        r.ok(&mut p, op::MQ_SETATTR, &[d, O_NONBLOCK], b"");
        r.ok(&mut p, op::MQ_SEND, &with_cred(&[d, 0, 0]), b"x");
        assert_eq!(r.err(&mut p, op::MQ_SEND, &with_cred(&[d, 0, 0]), b"y"), 11);
    }

    #[test]
    fn an_empty_queue_waits_and_the_message_wakes_the_receiver() {
        let (mut p, mut r) = (pipes(), Run::new());
        let d = open(&mut r, &mut p, b"/q", O_CREAT | 2, 1, 1);
        let (flow, _) = r.call(&mut p, 1, op::MQ_RECV, &with_cred(&[d, 1]), b"", None);
        let Ok(Flow::Wait { queue, block }) = flow else {
            panic!()
        };
        assert_eq!(block, Block::Recv);
        p.wait(queue, (4, 4), |_| true).unwrap();
        r.ok(&mut p, op::MQ_SEND, &with_cred(&[d, 0, 0]), b"z");
        assert_eq!(r.wakes.iter().collect::<Vec<_>>(), vec![(4, 4)]);
    }

    #[test]
    fn the_sizes_of_a_queue_are_checked() {
        let (mut p, mut r) = (pipes(), Run::new());
        let d = open(&mut r, &mut p, b"/q", O_CREAT | 2, 1, 2);
        assert_eq!(
            r.err(&mut p, op::MQ_SEND, &with_cred(&[d, 0, 0]), b"abc"),
            90
        );
        assert_eq!(
            r.err(&mut p, op::MQ_SEND, &with_cred(&[d, 40000, 0]), b"a"),
            22
        );
        let w = with_cred(&[O_CREAT | 2, 0o600, 0, 5, 1]);
        assert_eq!(r.err(&mut p, op::MQ_OPEN, &w, b"/bad"), 22);
        assert_eq!(
            r.err(
                &mut p,
                op::MQ_OPEN,
                &with_cred(&[2, 0, 0, 0, 0]),
                b"noslash"
            ),
            22
        );
        assert_eq!(
            r.err(&mut p, op::MQ_OPEN, &with_cred(&[2, 0, 0, 0, 0]), b"/a/b"),
            22
        );
        assert_eq!(
            r.err(&mut p, op::MQ_OPEN, &with_cred(&[2, 0, 0, 0, 0]), b"/none"),
            2
        );
    }

    #[test]
    fn exclusive_creation_and_permissions() {
        let (mut p, mut r) = (pipes(), Run::new());
        open(&mut r, &mut p, b"/q", O_CREAT | 2, 1, 1);
        let w = with_cred(&[O_CREAT | O_EXCL | 2, 0o600, 1, 1, 1]);
        assert_eq!(r.err(&mut p, op::MQ_OPEN, &w, b"/q"), 17);
        // Another user finds no permission in a mode of 0600.
        let other = with_cred(&[2, 0, 0, 0, 0]);
        r.who = Who {
            uid: 2000,
            gid: 200,
            pid: 8,
        };
        assert_eq!(r.err(&mut p, op::MQ_OPEN, &other, b"/q"), 13);
        // Nor may it take the name away.
        assert_eq!(r.err(&mut p, op::MQ_UNLINK, &cred(), b"/q"), 13);
        r.who.uid = 0;
        r.ok(&mut p, op::MQ_OPEN, &other, b"/q");
        r.ok(&mut p, op::MQ_UNLINK, &cred(), b"/q");
    }

    #[test]
    fn an_unlinked_queue_lives_until_its_last_description_closes() {
        let (mut p, mut r) = (pipes(), Run::new());
        let d = open(&mut r, &mut p, b"/q", O_CREAT | 2, 1, 1);
        r.ok(&mut p, op::MQ_SEND, &with_cred(&[d, 0, 0]), b"x");
        r.ok(&mut p, op::MQ_UNLINK, &cred(), b"/q");
        assert_eq!(
            r.err(&mut p, op::MQ_OPEN, &with_cred(&[2, 0, 0, 0, 0]), b"/q"),
            2
        );
        let out = r.ok(&mut p, op::MQ_RECV, &with_cred(&[d, 1]), b"");
        assert_eq!(&out.bytes[..out.len], b"x");
        // A new queue by the name is another one.
        let e = open(&mut r, &mut p, b"/q", O_CREAT | 2, 1, 1);
        assert_ne!(e, d);
        let mut w = Wakes::default();
        p.close_endpoint(&mut r.held, Endpoint::socket(slot_of(d)), &mut w)
            .unwrap();
        // Both queues are alive until their descriptions go: the first one is
        // free now, so the table has one live queue.
        assert_eq!(p.ipc.queues.iter().filter(|q| q.live).count(), 1);
        p.close_endpoint(&mut r.held, Endpoint::socket(slot_of(e)), &mut w)
            .unwrap();
        assert_eq!(
            p.ipc.queues.iter().filter(|q| q.live).count(),
            1,
            "named stays"
        );
        r.ok(&mut p, op::MQ_UNLINK, &cred(), b"/q");
        assert_eq!(p.ipc.queues.iter().filter(|q| q.live).count(), 0);
    }

    #[test]
    fn a_descriptor_is_no_socket_and_the_session_that_goes_lets_it_go() {
        let (mut p, mut r) = (pipes(), Run::new());
        let d = open(&mut r, &mut p, b"/q", O_CREAT | 2, 1, 1);
        let e = Endpoint::socket(slot_of(d));
        let mut w = Wakes::default();
        assert_eq!(
            p.sock_bind(&r.held, e, proto_pipe::sock::Addr::inet(1)),
            Err(proto_pipe::sock::NOT_SOCKET)
        );
        assert_eq!(
            p.read_endpoint(&r.held, e, &mut [0; 4], &mut w),
            Err(proto_pipe::sock::NOT_SOCKET)
        );
        // Clone adds an opener; both closed free the description.
        let mut child = p.clone_endpoints(&r.held, &[e]).unwrap();
        assert_eq!(p.ipc.queues.iter().find(|q| q.live).unwrap().opens, 1);
        assert!(p.gone(&mut r.held));
        while p.step(&mut w) {}
        assert!(p.live_sockets() > 0);
        assert!(p.gone(&mut child));
        while p.step(&mut w) {}
        assert_eq!(p.live_sockets(), 0);
        // The queue is named still.
        assert_eq!(p.ipc.queues.iter().filter(|q| q.live).count(), 1);
    }

    #[test]
    fn a_notification_comes_once_to_the_empty_queue_unless_a_receiver_waits() {
        let (mut p, mut r) = (pipes(), Run::new());
        let d = open(&mut r, &mut p, b"/q", O_CREAT | 2, 2, 1);
        r.ok(&mut p, op::MQ_NOTIFY, &[d, 1], b"");
        assert_eq!(r.err(&mut p, op::MQ_NOTIFY, &[d, 1], b""), 16);
        let (flow, _) = r.call(&mut p, 1, op::MQ_NOTIFY_WAIT, &[d], b"", None);
        let Ok(Flow::Wait { queue, .. }) = flow else {
            panic!()
        };
        p.wait(queue, (5, 5), |_| true).unwrap();
        r.ok(&mut p, op::MQ_SEND, &with_cred(&[d, 0, 0]), b"a");
        assert!(r.wakes.iter().any(|w| w == (5, 5)));
        let out = r.ok(&mut p, op::MQ_NOTIFY_WAIT, &[d], b"");
        assert_eq!(out.words[0], 1);
        // Registered again, a second message to a non-empty queue sends nothing.
        r.ok(&mut p, op::MQ_NOTIFY, &[d, 1], b"");
        r.ok(&mut p, op::MQ_SEND, &with_cred(&[d, 0, 0]), b"b");
        let (flow, _) = r.call(&mut p, 1, op::MQ_NOTIFY_WAIT, &[d], b"", None);
        assert!(matches!(flow, Ok(Flow::Wait { .. })));
        // Removed, the wait ends with 2.
        r.ok(&mut p, op::MQ_NOTIFY, &[d, 0], b"");
        let out = r.ok(&mut p, op::MQ_NOTIFY_WAIT, &[d], b"");
        assert_eq!(out.words[0], 2);
        // A receiver that waits keeps the notification back.
        r.ok(&mut p, op::MQ_RECV, &with_cred(&[d, 1]), b"");
        r.ok(&mut p, op::MQ_RECV, &with_cred(&[d, 1]), b"");
        r.ok(&mut p, op::MQ_NOTIFY, &[d, 1], b"");
        let (flow, _) = r.call(&mut p, 1, op::MQ_RECV, &with_cred(&[d, 1]), b"", None);
        let Ok(Flow::Wait { queue, block }) = flow else {
            panic!()
        };
        p.ipc_note_wait(1, 77, queue, block);
        r.ok(&mut p, op::MQ_SEND, &with_cred(&[d, 0, 0]), b"c");
        let (flow, _) = r.call(&mut p, 1, op::MQ_NOTIFY_WAIT, &[d], b"", None);
        assert!(matches!(flow, Ok(Flow::Wait { .. })), "still armed");
    }

    #[test]
    fn xsi_queues_select_by_type() {
        let (mut p, mut r) = (pipes(), Run::new());
        let id = r
            .ok(&mut p, op::MSG_GET, &with_cred(&[0, 0o600]), b"")
            .words[0];
        for (t, text) in [(3u64, b"c"), (1, b"a"), (2, b"b"), (1, b"d")] {
            r.ok(&mut p, op::MSG_SND, &with_cred(&[id, t, 0]), text);
        }
        let get = |r: &mut Run, p: &mut Pipes, want: i64, flags: u64| -> Result<(u64, u8), u32> {
            let (flow, out) = r.call(
                p,
                1,
                op::MSG_RCV,
                &with_cred(&[id, 8, want as u64, flags]),
                b"",
                None,
            );
            match flow {
                Ok(Flow::Done) => Ok((out.words[0], out.bytes[0])),
                Ok(Flow::Wait { .. }) => Err(0),
                Err(e) => Err(e - proto_pipe::ipc::ERRNO),
            }
        };
        assert_eq!(get(&mut r, &mut p, 2, 0), Ok((2, b'b')));
        assert_eq!(get(&mut r, &mut p, -2, 0), Ok((1, b'a')));
        assert_eq!(get(&mut r, &mut p, 1, MSG_EXCEPT), Ok((3, b'c')));
        assert_eq!(get(&mut r, &mut p, 0, 0), Ok((1, b'd')));
        assert_eq!(get(&mut r, &mut p, 0, IPC_NOWAIT), Err(42));
        assert_eq!(get(&mut r, &mut p, 0, 0), Err(0));
    }

    #[test]
    fn xsi_queues_cut_or_refuse_long_messages_and_stat_and_go() {
        let (mut p, mut r) = (pipes(), Run::new());
        let id = r
            .ok(
                &mut p,
                op::MSG_GET,
                &with_cred(&[5, IPC_CREAT | 0o640]),
                b"",
            )
            .words[0];
        assert_eq!(
            r.ok(&mut p, op::MSG_GET, &with_cred(&[5, 0o640]), b"")
                .words[0],
            id
        );
        assert_eq!(
            r.err(
                &mut p,
                op::MSG_GET,
                &with_cred(&[5, IPC_CREAT | IPC_EXCL]),
                b""
            ),
            17
        );
        assert_eq!(r.err(&mut p, op::MSG_GET, &with_cred(&[6, 0]), b""), 2);
        r.ok(&mut p, op::MSG_SND, &with_cred(&[id, 1, 0]), b"hello");
        assert_eq!(
            r.err(&mut p, op::MSG_RCV, &with_cred(&[id, 2, 0, 0]), b""),
            7
        );
        let out = r.ok(
            &mut p,
            op::MSG_RCV,
            &with_cred(&[id, 2, 0, MSG_NOERROR]),
            b"",
        );
        assert_eq!((out.words[1], out.len), (5, 2));
        let st = r.ok(&mut p, op::MSG_CTL, &with_cred(&[id, IPC_STAT]), b"");
        assert_eq!(st.words[1], 1000);
        assert_eq!(st.words[4], 100);
        assert_eq!(st.words[5], 0o640);
        assert_eq!(st.words[11], 0);
        r.ok(&mut p, op::MSG_CTL, &with_cred(&[id, IPC_RMID]), b"");
        assert_eq!(
            r.err(&mut p, op::MSG_CTL, &with_cred(&[id, IPC_STAT]), b""),
            22
        );
        let (flow, _) = r.call(
            &mut p,
            1,
            op::MSG_SND,
            &with_cred(&[id, 1, 0]),
            b"x",
            Some(3),
        );
        assert_eq!(
            flow,
            Err(proto_pipe::ipc::ERRNO + 43),
            "a waiter finds the queue gone"
        );
        // Another user cannot remove it.
        let id = r
            .ok(&mut p, op::MSG_GET, &with_cred(&[0, 0o666]), b"")
            .words[0];
        let other = with_cred(&[id, IPC_RMID]);
        r.who = Who {
            uid: 2000,
            gid: 200,
            pid: 9,
        };
        assert_eq!(r.err(&mut p, op::MSG_CTL, &other, b""), 1);
        r.who.uid = 0;
        r.ok(&mut p, op::MSG_CTL, &other, b"");
    }

    #[test]
    fn a_full_xsi_queue_waits_by_bytes() {
        let (mut p, mut r) = (pipes(), Run::new());
        let id = r
            .ok(&mut p, op::MSG_GET, &with_cred(&[0, 0o600]), b"")
            .words[0];
        let big = [7u8; TEXT_MAX];
        let mut sent = 0;
        loop {
            let (flow, _) = r.call(&mut p, 1, op::MSG_SND, &with_cred(&[id, 1, 1]), &big, None);
            match flow {
                Ok(Flow::Done) => sent += 1,
                Err(e) => {
                    assert_eq!(e - proto_pipe::ipc::ERRNO, 11);
                    break;
                }
                _ => panic!(),
            }
        }
        assert_eq!(sent, QBYTES_DEFAULT as usize / TEXT_MAX);
    }

    fn sem_words(id: u64, ops: &[(u64, i16, i16)]) -> Vec<u64> {
        let mut w = vec![id, ops.len() as u64];
        w.extend(cred());
        for &(num, op, flags) in ops {
            w.extend([num, op as u16 as u64, flags as u16 as u64]);
        }
        w
    }

    fn semctl(id: u64, num: u64, cmd: u64, arg: u64) -> Vec<u64> {
        with_cred(&[id, num, cmd, arg])
    }

    #[test]
    fn semaphores_operate_all_or_none() {
        let (mut p, mut r) = (pipes(), Run::new());
        let id = r
            .ok(&mut p, op::SEM_GET, &with_cred(&[0, 2, 0o600]), b"")
            .words[0];
        r.ok(&mut p, op::SEM_CTL, &semctl(id, 0, SETVAL, 1), b"");
        // Two operations: take from 0 (ok), take from 1 (empty): none applies.
        let w = sem_words(id, &[(0, -1, 0), (1, -1, 0)]);
        let (flow, _) = r.call(&mut p, 1, op::SEM_OP, &w, b"", None);
        let Ok(Flow::Wait { block, .. }) = flow else {
            panic!("{flow:?}")
        };
        assert_eq!(block, Block::Sem(1, false));
        assert_eq!(
            r.ok(&mut p, op::SEM_CTL, &semctl(id, 0, GETVAL, 0), b"")
                .words[0],
            1
        );
        // With IPC_NOWAIT it is EAGAIN.
        let w = sem_words(id, &[(0, -1, 0), (1, -1, IPC_NOWAIT as i16)]);
        assert_eq!(r.err(&mut p, op::SEM_OP, &w, b""), 11);
        // Raise 1 and the pair goes through.
        r.ok(&mut p, op::SEM_CTL, &semctl(id, 1, SETVAL, 1), b"");
        let w = sem_words(id, &[(0, -1, 0), (1, -1, 0)]);
        r.ok(&mut p, op::SEM_OP, &w, b"");
        assert_eq!(
            r.ok(&mut p, op::SEM_CTL, &semctl(id, 0, GETVAL, 0), b"")
                .words[0],
            0
        );
        assert_eq!(
            r.ok(&mut p, op::SEM_CTL, &semctl(id, 0, GETPID, 0), b"")
                .words[0],
            7
        );
        // Wait for zero, errors.
        let w = sem_words(id, &[(0, 0, 0)]);
        r.ok(&mut p, op::SEM_OP, &w, b"");
        assert_eq!(
            r.err(&mut p, op::SEM_OP, &sem_words(id, &[(2, 1, 0)]), b""),
            27
        );
        assert_eq!(
            r.err(
                &mut p,
                op::SEM_OP,
                &sem_words(id, &[(0, 32767, 0), (0, 1, 0)]),
                b""
            ),
            34
        );
    }

    #[test]
    fn a_change_wakes_the_waiters_of_the_set_and_the_counts_follow_them() {
        let (mut p, mut r) = (pipes(), Run::new());
        let id = r
            .ok(&mut p, op::SEM_GET, &with_cred(&[0, 1, 0o600]), b"")
            .words[0];
        let w = sem_words(id, &[(0, -1, 0)]);
        let (flow, _) = r.call(&mut p, 1, op::SEM_OP, &w, b"", None);
        let Ok(Flow::Wait { queue, block }) = flow else {
            panic!()
        };
        p.wait(queue, (3, 3), |_| true).unwrap();
        p.ipc_note_wait(1, 3, queue, block);
        assert_eq!(
            r.ok(&mut p, op::SEM_CTL, &semctl(id, 0, GETNCNT, 0), b"")
                .words[0],
            1
        );
        assert_eq!(
            r.ok(&mut p, op::SEM_CTL, &semctl(id, 0, GETZCNT, 0), b"")
                .words[0],
            0
        );
        r.ok(&mut p, op::SEM_OP, &sem_words(id, &[(0, 1, 0)]), b"");
        assert_eq!(r.wakes.iter().collect::<Vec<_>>(), vec![(3, 3)]);
        p.ipc_wait_done(1, 3);
        p.unwait(queue, (3, 3));
        assert_eq!(
            r.ok(&mut p, op::SEM_CTL, &semctl(id, 0, GETNCNT, 0), b"")
                .words[0],
            0
        );
        // RMID wakes them too, and a waiter's retry finds EIDRM.
        let (flow, _) = r.call(
            &mut p,
            1,
            op::SEM_OP,
            &sem_words(id, &[(0, -2, 0)]),
            b"",
            None,
        );
        let Ok(Flow::Wait { queue, .. }) = flow else {
            panic!()
        };
        p.wait(queue, (6, 6), |_| true).unwrap();
        r.ok(&mut p, op::SEM_CTL, &semctl(id, 0, IPC_RMID, 0), b"");
        assert_eq!(r.wakes.iter().collect::<Vec<_>>(), vec![(6, 6)]);
        let (flow, _) = r.call(
            &mut p,
            1,
            op::SEM_OP,
            &sem_words(id, &[(0, -2, 0)]),
            b"",
            Some(8),
        );
        assert_eq!(flow, Err(proto_pipe::ipc::ERRNO + 43));
    }

    #[test]
    fn the_adjustments_of_a_session_that_goes_are_made() {
        let (mut p, mut r) = (pipes(), Run::new());
        let id = r
            .ok(&mut p, op::SEM_GET, &with_cred(&[0, 1, 0o600]), b"")
            .words[0];
        r.ok(&mut p, op::SEM_CTL, &semctl(id, 0, SETVAL, 3), b"");
        let (flow, _) = r.call(
            &mut p,
            55,
            op::SEM_OP,
            &sem_words(id, &[(0, -2, SEM_UNDO as i16)]),
            b"",
            None,
        );
        assert_eq!(flow, Ok(Flow::Done));
        assert_eq!(
            r.ok(&mut p, op::SEM_CTL, &semctl(id, 0, GETVAL, 0), b"")
                .words[0],
            1
        );
        // The adjustments cancel: take 2, give 2 with undo: none left.
        let (flow, _) = r.call(
            &mut p,
            56,
            op::SEM_OP,
            &sem_words(id, &[(0, 1, SEM_UNDO as i16)]),
            b"",
            None,
        );
        assert_eq!(flow, Ok(Flow::Done));
        let (flow, _) = r.call(
            &mut p,
            56,
            op::SEM_OP,
            &sem_words(id, &[(0, -1, SEM_UNDO as i16)]),
            b"",
            None,
        );
        assert_eq!(flow, Ok(Flow::Done));
        assert_eq!(p.ipc.undo.iter().filter(|u| u.used).count(), 1);
        assert!(p.ipc_gone(55));
        let mut w = Wakes::default();
        while p.ipc_step(&mut w) {}
        assert_eq!(
            r.ok(&mut p, op::SEM_CTL, &semctl(id, 0, GETVAL, 0), b"")
                .words[0],
            3
        );
        assert!(!p.ipc_due());
    }

    #[test]
    fn a_full_undo_table_leaves_the_set_as_it_was() {
        let (mut p, mut r) = (pipes(), Run::new());
        let id = r
            .ok(&mut p, op::SEM_GET, &with_cred(&[0, 8, 0o600]), b"")
            .words[0];
        for n in 0..8 {
            r.ok(&mut p, op::SEM_CTL, &semctl(id, n, SETVAL, 5), b"");
        }
        let mut filled = 0;
        'fill: for label in 1000..1010u64 {
            for n in 0..8u64 {
                let (flow, _) = r.call(
                    &mut p,
                    label,
                    op::SEM_OP,
                    &sem_words(id, &[(n, -1, SEM_UNDO as i16)]),
                    b"",
                    None,
                );
                match flow {
                    Ok(Flow::Done) => filled += 1,
                    Err(e) => {
                        assert_eq!(e - proto_pipe::ipc::ERRNO, 28);
                        assert_eq!(
                            r.ok(&mut p, op::SEM_CTL, &semctl(id, n, GETVAL, 0), b"")
                                .words[0],
                            1
                        );
                        break 'fill;
                    }
                    _ => panic!(),
                }
            }
        }
        assert_eq!(filled, UNDO_MAX);
    }

    #[test]
    fn semctl_sets_and_reads_all_values() {
        let (mut p, mut r) = (pipes(), Run::new());
        let id = r
            .ok(&mut p, op::SEM_GET, &with_cred(&[0, 3, 0o600]), b"")
            .words[0];
        let mut bytes = Vec::new();
        for v in [1u16, 2, 3] {
            bytes.extend(v.to_le_bytes());
        }
        r.ok(&mut p, op::SEM_CTL, &semctl(id, 0, SETALL, 0), &bytes);
        let out = r.ok(&mut p, op::SEM_CTL, &semctl(id, 0, GETALL, 0), b"");
        assert_eq!(&out.bytes[..out.len], &bytes[..]);
        assert_eq!(
            r.err(&mut p, op::SEM_CTL, &semctl(id, 0, SETALL, 0), &bytes[..4]),
            22
        );
        let st = r.ok(&mut p, op::SEM_CTL, &semctl(id, 0, IPC_STAT, 0), b"");
        assert_eq!((st.words[1], st.words[9]), (1000, 3));
        assert_eq!(
            r.err(&mut p, op::SEM_GET, &with_cred(&[0, 0, 0o600]), b""),
            22
        );
        assert_eq!(
            r.err(&mut p, op::SEM_CTL, &semctl(id, 3, GETVAL, 0), b""),
            22
        );
        assert_eq!(
            r.err(&mut p, op::SEM_CTL, &semctl(id, 0, SETVAL, 40000), b""),
            34
        );
    }

    #[test]
    fn a_segment_is_counted_attached_and_goes_with_its_last_detach() {
        let (mut p, mut r) = (pipes(), Run::new());
        let out = r.ok(&mut p, op::SHM_GET, &with_cred(&[0, 4096, 0o600, nonce()]), b"");
        let (id, serial) = (out.words[0], out.words[1]);
        let st = r.ok(&mut p, op::SHM_CTL, &with_cred(&[id, IPC_STAT]), b"");
        assert_eq!(
            (
                st.words[1],
                st.words[4],
                st.words[7],
                st.words[11],
                st.words[13]
            ),
            (1000, 100, 4096, 7, 0)
        );
        assert_eq!(st.words[7 + 6], 0);
        let at = r.ok(&mut p, op::SHM_AT, &with_cred(&[id, 0]), b"");
        assert_eq!((at.words[0], at.words[1]), (serial, 4096));
        let st = r.ok(&mut p, op::SHM_CTL, &with_cred(&[id, IPC_STAT]), b"");
        assert_eq!(st.words[7 + 6], 1);
        let rm = r.ok(&mut p, op::SHM_CTL, &with_cred(&[id, IPC_RMID]), b"");
        assert_eq!(rm.words[0], 0, "attached: it stays");
        assert_eq!(r.err(&mut p, op::SHM_AT, &with_cred(&[id, 0]), b""), 43);
        let dt = r.ok(&mut p, op::SHM_DT, &with_cred(&[id]), b"");
        assert_eq!((dt.words[0], dt.words[1]), (1, serial));
        assert_eq!(
            r.err(&mut p, op::SHM_CTL, &with_cred(&[id, IPC_STAT]), b""),
            22
        );
    }

    #[test]
    fn a_segment_by_key_and_a_session_that_goes_detaches() {
        let (mut p, mut r) = (pipes(), Run::new());
        let id = r
            .ok(
                &mut p,
                op::SHM_GET,
                &with_cred(&[9, 4096, IPC_CREAT | 0o600, nonce()]),
                b"",
            )
            .words[0];
        assert_eq!(
            r.ok(&mut p, op::SHM_GET, &with_cred(&[9, 100, 0o600, nonce()]), b"")
                .words[0],
            id
        );
        assert_eq!(
            r.err(&mut p, op::SHM_GET, &with_cred(&[9, 8192, 0o600, nonce()]), b""),
            22
        );
        assert_eq!(
            r.err(&mut p, op::SHM_GET, &with_cred(&[0, 0, 0o600, nonce()]), b""),
            22
        );
        let (flow, _) = r.call(&mut p, 77, op::SHM_AT, &with_cred(&[id, 0]), b"", None);
        assert_eq!(flow, Ok(Flow::Done));
        let st = r.ok(&mut p, op::SHM_CTL, &with_cred(&[id, IPC_STAT]), b"");
        assert_eq!(st.words[7 + 6], 1);
        r.ok(&mut p, op::SHM_CTL, &with_cred(&[id, IPC_RMID]), b"");
        assert!(p.ipc_gone(77));
        let mut w = Wakes::default();
        while p.ipc_step(&mut w) {}
        // The segment went with the session that held it.
        assert_eq!(p.ipc.segs.iter().filter(|s| s.live).count(), 0);
    }

    #[test]
    fn named_semaphores_count_waits_and_go_with_the_last_close() {
        let (mut p, mut r) = (pipes(), Run::new());
        let w = with_cred(&[O_CREAT | O_EXCL, 0o600, 1]);
        let id = r.ok(&mut p, op::NSEM_OPEN, &w, b"/s").words[0];
        assert_eq!(r.err(&mut p, op::NSEM_OPEN, &w, b"/s"), 17);
        assert_eq!(
            r.ok(&mut p, op::NSEM_OPEN, &with_cred(&[0, 0, 0]), b"/s")
                .words[0],
            id
        );
        r.ok(&mut p, op::NSEM_WAIT, &with_cred(&[id, 0]), b"");
        let (flow, _) = r.call(&mut p, 1, op::NSEM_WAIT, &with_cred(&[id, 0]), b"", None);
        let Ok(Flow::Wait { queue, .. }) = flow else {
            panic!()
        };
        p.wait(queue, (2, 2), |_| true).unwrap();
        assert_eq!(r.err(&mut p, op::NSEM_WAIT, &with_cred(&[id, 1]), b""), 11);
        r.ok(&mut p, op::NSEM_POST, &with_cred(&[id]), b"");
        assert_eq!(r.wakes.iter().collect::<Vec<_>>(), vec![(2, 2)]);
        assert_eq!(r.ok(&mut p, op::NSEM_VALUE, &[id], b"").words[0], 1);
        r.ok(&mut p, op::NSEM_UNLINK, &cred(), b"/s");
        assert_eq!(
            r.err(&mut p, op::NSEM_OPEN, &with_cred(&[0, 0, 0]), b"/s"),
            2
        );
        r.ok(&mut p, op::NSEM_CLOSE, &[id], b"");
        assert!(p.ipc.sems[0].live, "one open is left");
        r.ok(&mut p, op::NSEM_CLOSE, &[id], b"");
        assert!(!p.ipc.sems.iter().any(|s| s.live));
        // A session that goes closes what it opened.
        let id = r
            .ok(
                &mut p,
                op::NSEM_OPEN,
                &with_cred(&[O_CREAT, 0o600, 0]),
                b"/t",
            )
            .words[0];
        r.ok(&mut p, op::NSEM_UNLINK, &cred(), b"/t");
        assert!(p.ipc.sems[0].live);
        assert!(p.ipc_gone(1));
        let mut w = Wakes::default();
        while p.ipc_step(&mut w) {}
        let _ = id;
        assert!(!p.ipc.sems.iter().any(|s| s.live));
    }

    #[test]
    fn the_limits_of_a_root_hold() {
        let (mut p, mut r) = (pipes(), Run::new());
        for i in 0..ROOT_OBJECTS {
            r.ok(&mut p, op::MSG_GET, &with_cred(&[0, 0o600]), b"");
            let _ = i;
        }
        assert_eq!(r.err(&mut p, op::MSG_GET, &with_cred(&[0, 0o600]), b""), 28);
        // Another root has its own share.
        let (flow, _) = {
            let mut call = Call::new(op::MSG_GET, &with_cred(&[0, 0o600]), b"");
            call.key = None;
            let mut out = Out::new();
            let mut w = Wakes::default();
            (
                p.ipc_call(&mut r.held, 1, 2, &call, WHO, &mut out, &mut w),
                out,
            )
        };
        assert_eq!(flow, Ok(Flow::Done));
    }

    #[test]
    fn a_wait_queue_is_beyond_the_sockets_and_dead_ones_are_refused() {
        let mut p = pipes();
        assert!(
            p.wait(QUEUE_BASE, (1, 1), |_| true).is_err(),
            "no queue yet"
        );
        let mut r = Run::new();
        r.ok(&mut p, op::MSG_GET, &with_cred(&[0, 0o600]), b"");
        assert!(p.wait(QUEUE_BASE, (1, 1), |_| true).is_ok());
        assert!(
            p.wait(QUEUE_BASE + WAIT_QUEUES as u32, (1, 1), |_| true)
                .is_err()
        );
        p.unwait(QUEUE_BASE, (1, 1));
    }

    #[test]
    fn a_sender_that_waits_for_the_pool_wakes_when_any_message_goes() {
        let (mut p, mut r) = (pipes(), Run::new());
        let mut ids = Vec::new();
        for _ in 0..3 {
            ids.push(
                r.ok(&mut p, op::MSG_GET, &with_cred(&[0, 0o600]), b"")
                    .words[0],
            );
        }
        // Two queues of 16 take the share of the root (32 of 64).
        for id in &ids[..2] {
            for _ in 0..QUEUE_MSGS {
                r.ok(&mut p, op::MSG_SND, &with_cred(&[*id, 1, 1]), b"x");
            }
        }
        assert_eq!(
            r.err(&mut p, op::MSG_SND, &with_cred(&[ids[2], 1, 1]), b"x"),
            11
        );
        let (flow, _) = r.call(
            &mut p,
            1,
            op::MSG_SND,
            &with_cred(&[ids[2], 1, 0]),
            b"x",
            None,
        );
        let Ok(Flow::Wait { queue, .. }) = flow else {
            panic!("{flow:?}")
        };
        assert_eq!(
            queue,
            Ipc::pool_number(),
            "its own queue has room: the pool is what it waits for"
        );
        p.wait(queue, (7, 7), |_| true).unwrap();
        // A receive from another queue of the tree frees a place and wakes it.
        r.ok(&mut p, op::MSG_RCV, &with_cred(&[ids[0], 8, 0, 0]), b"");
        assert!(r.wakes.iter().any(|w| w == (7, 7)));
        // The same for a queue of POSIX.
        r.ok(&mut p, op::MSG_SND, &with_cred(&[ids[0], 1, 1]), b"x");
        let d = open(&mut r, &mut p, b"/pool", O_CREAT | 2, 4, 1);
        let (flow, _) = r.call(&mut p, 1, op::MQ_SEND, &with_cred(&[d, 0, 0]), b"z", None);
        assert!(matches!(flow, Ok(Flow::Wait { queue, .. }) if queue == Ipc::pool_number()));
    }

    #[test]
    fn a_root_that_used_its_share_leaves_the_pool_to_the_others() {
        let (mut p, mut r) = (pipes(), Run::new());
        let a = r
            .ok(&mut p, op::MSG_GET, &with_cred(&[0, 0o600]), b"")
            .words[0];
        let b = r
            .ok(&mut p, op::MSG_GET, &with_cred(&[0, 0o600]), b"")
            .words[0];
        for id in [a, b] {
            for _ in 0..QUEUE_MSGS {
                r.ok(&mut p, op::MSG_SND, &with_cred(&[id, 1, 1]), b"x");
            }
        }
        // Another root, its own queue: the pool has room for it.
        let mut call = Call::new(op::MSG_GET, &with_cred(&[0, 0o600]), b"");
        call.key = None;
        let (mut out, mut w) = (Out::new(), Wakes::default());
        p.ipc_call(&mut r.held, 5, 5, &call, WHO, &mut out, &mut w)
            .unwrap();
        let other = out.words[0];
        let call = Call::new(op::MSG_SND, &with_cred(&[other, 1, 1]), b"y");
        assert_eq!(
            p.ipc_call(&mut r.held, 5, 5, &call, WHO, &mut out, &mut w),
            Ok(Flow::Done)
        );
    }

    #[test]
    fn a_child_holds_what_its_parent_holds_and_exec_lets_it_go() {
        let (mut p, mut r) = (pipes(), Run::new());
        let out = r.ok(&mut p, op::SHM_GET, &with_cred(&[0, 4096, 0o600, nonce()]), b"");
        let id = out.words[0];
        let (flow, _) = r.call(&mut p, 10, op::SHM_AT, &with_cred(&[id, 0]), b"", None);
        assert_eq!(flow, Ok(Flow::Done));
        let (flow, _) = r.call(
            &mut p,
            10,
            op::NSEM_OPEN,
            &with_cred(&[O_CREAT, 0o600, 1]),
            b"/s",
            None,
        );
        assert_eq!(flow, Ok(Flow::Done));
        let stat = |r: &mut Run, p: &mut Pipes| {
            r.ok(p, op::SHM_CTL, &with_cred(&[id, IPC_STAT]), b"").words[13]
        };
        assert_eq!(stat(&mut r, &mut p), 1);
        assert!(p.ipc_inherit_room(10));
        p.ipc_inherit(10, 11);
        assert_eq!(stat(&mut r, &mut p), 2, "the child is counted");
        // The child detaches: it had the hold.
        let (flow, _) = r.call(&mut p, 11, op::SHM_DT, &with_cred(&[id]), b"", None);
        assert_eq!(flow, Ok(Flow::Done));
        assert_eq!(stat(&mut r, &mut p), 1);
        // An exec lets go of the image's holds, in steps.
        assert!(p.ipc_exec(10));
        assert!(p.ipc_gone(11));
        let mut w = Wakes::default();
        while p.ipc_step(&mut w) {}
        assert_eq!(stat(&mut r, &mut p), 0);
        assert!(p.ipc.sems.iter().any(|s| s.live && s.opens == 0));
    }

    #[test]
    fn a_child_is_refused_when_the_holds_have_no_room() {
        let (mut p, mut r) = (pipes(), Run::new());
        let id = r
            .ok(&mut p, op::SHM_GET, &with_cred(&[0, 4096, 0o600, nonce()]), b"")
            .words[0];
        for label in 100..100 + HOLD_MAX as u64 {
            let (flow, _) = r.call(&mut p, label, op::SHM_AT, &with_cred(&[id, 0]), b"", None);
            assert_eq!(flow, Ok(Flow::Done));
        }
        assert!(!p.ipc_inherit_room(100), "no hold is free for a copy");
    }

    #[test]
    fn a_freed_segment_names_its_file_to_its_creator_until_it_is_removed() {
        let (mut p, mut r) = (pipes(), Run::new());
        let out = r.ok(&mut p, op::SHM_GET, &with_cred(&[0, 4096, 0o600, nonce()]), b"");
        let (id, serial) = (out.words[0], out.words[1]);
        let (flow, _) = r.call(&mut p, 77, op::SHM_AT, &with_cred(&[id, 0]), b"", None);
        assert_eq!(flow, Ok(Flow::Done));
        let rm = r.ok(&mut p, op::SHM_CTL, &with_cred(&[id, IPC_RMID]), b"");
        assert_eq!(
            (rm.words[0], rm.words[2]),
            (0, 0),
            "attached: nothing to remove yet"
        );
        // The attaching process is killed: its hold goes in a step.
        assert!(p.ipc_gone(77));
        let mut w = Wakes::default();
        while p.ipc_step(&mut w) {}
        // Another user is not told of the file; its creator is, once.
        r.who.uid = 2000;
        let other = r.ok(&mut p, op::SHM_GET, &with_cred(&[0, 4096, 0o600, nonce()]), b"");
        assert_eq!(other.words[3], 0);
        r.who = WHO;
        let again = r.ok(&mut p, op::SHM_GET, &with_cred(&[0, 4096, 0o600, nonce()]), b"");
        assert_eq!(again.words[3], serial);
        let third = r.ok(&mut p, op::SHM_GET, &with_cred(&[0, 4096, 0o600, nonce()]), b"");
        assert_eq!(third.words[3], 0);
    }

    #[test]
    fn the_counted_waits_are_found_by_the_number_of_their_operation() {
        let mut ipc = Box::new(Ipc::new());
        let key = (7u64 << 32) | 5;
        ipc.note_wait(3, key, QUEUE_BASE, Block::Recv);
        assert_eq!(ipc.counted, 1);
        // Another label with the same place finds nothing to take away.
        ipc.wait_done(4, key);
        assert_eq!(ipc.counted, 1);
        ipc.wait_done(3, key);
        assert_eq!(ipc.counted, 0);
        ipc.note_wait(3, (1 << 32) | 9, QUEUE_BASE, Block::Recv);
        ipc.note_wait(3, (1 << 32) | 10, QUEUE_BASE, Block::Recv);
        ipc.note_wait(8, (1 << 32) | 11, QUEUE_BASE, Block::Recv);
        ipc.forget(3);
        assert_eq!(ipc.counted, 1);
        // A key that names no place is ignored.
        ipc.note_wait(3, 0, QUEUE_BASE, Block::Recv);
        ipc.note_wait(3, (1 << 32) | 100_000, QUEUE_BASE, Block::Recv);
        assert_eq!(ipc.counted, 1);
    }

    #[test]
    fn the_name_of_a_segment_file_is_the_creators_number_and_a_used_one_is_refused() {
        let (mut p, mut r) = (pipes(), Run::new());
        let w = |n: u64| with_cred(&[0, 4096, 0o600, n]);
        assert_eq!(r.err(&mut p, op::SHM_GET, &w(0), b""), 22);
        let out = r.ok(&mut p, op::SHM_GET, &w(0xabcdef), b"");
        assert_eq!(out.words[1], 0xabcdef);
        assert_eq!(r.err(&mut p, op::SHM_GET, &w(0xabcdef), b""), 17);
        // The answers of an attach name who may own the file.
        let at = r.ok(&mut p, op::SHM_AT, &with_cred(&[out.words[0], 0]), b"");
        assert_eq!((at.words[0], at.words[1], at.words[2], at.words[3]), (0xabcdef, 4096, 1000, 1000));
        let st = r.ok(&mut p, op::SHM_CTL, &with_cred(&[out.words[0], IPC_STAT]), b"");
        assert_eq!(st.words[14], 0xabcdef);
    }
}
