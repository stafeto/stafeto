// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Message queues, semaphores and shared memory segments of the pipe
//! service (Ф11b): the POSIX message queues (`mq_*`) and named semaphores
//! (`sem_open`), and the XSI message queues, semaphore sets and shared
//! memory segments (`msg*`, `sem*`, `shm*`). Three methods carry them all.
//!
//! - IPC: body the operation u32, the count of words u32, as many words
//!   u64, then the bytes the operation carries (a name, a message). An
//!   operation that does not wait answers at once: status, the count of
//!   words u32, the words, the bytes.
//! - IPC_TAKE: body the key k u64 first, then the body of IPC again. An
//!   operation that waits is a long operation in two steps
//!   (proto_wire::long): READY with the answer as above (without a status),
//!   or WAIT k, and IPC_TAKE with a handle labelled k brings the answer or
//!   waits on. The service keeps no word and no byte of a request that
//!   waits; it tells the operation that something changed and the take asks
//!   again.
//! - IPC_CANCEL: body the key k u64. CANCELLED, or READY when the answer
//!   was there.
//!
//! The words of each operation are in the table of [op]. A failure of an
//! operation answers the code `ERRNO + errno` (Linux's numbers, relibc's).
//! The service learns who a caller is from the process service: a session
//! brings a copy of the identity session of its process (`posix-id`, as for
//! the clock and the file service) as the first handle of a request, and
//! the service has it vouched (Vouch) and remembers the answer with the
//! generation of the credentials. Only the time, in seconds, comes in the
//! words. A session without a copy gets NEED_ID.
//!
//! A message queue of POSIX is opened for a descriptor, a description of
//! the service of the third kind (`SOCK_END | slot`): fork, exec, dup,
//! close and the limits of sessions are those of the sockets, and a queue
//! lives until it is unlinked and its last description is closed. A
//! descriptor of a queue reads and writes as nothing (EBADF), and polls as
//! NVAL.

use proto_wire::{Reader, Status, Writer};

/// The kind of a description of the third kind that is an open message queue
/// (a socket's is STREAM or DGRAM).
pub const MQ_KIND: u32 = 99;

/// The code of a refusal: this plus the errno.
pub const ERRNO: u32 = 2000;

/// The words of a request or an answer at most.
pub const WORDS_MAX: usize = 32;
/// The bytes of a message of a queue at most (`mq_msgsize`, `msgsz`).
pub const TEXT_MAX: usize = 512;
/// The bytes of a name at most.
pub const NAME_MAX: usize = 47;

/// The operations. Words of the request (`w0` ...) and of the answer
/// (`=>`); `cred` is the time of the caller in
/// seconds, one word.
pub mod op {
    /// mq_open: w0 oflag, w1 mode, w2 maxmsg, w3 msgsize (0 for the
    /// defaults), w4 attr given, then cred; bytes the name. => the
    /// descriptor.
    pub const MQ_OPEN: u32 = 1;
    /// mq_unlink: cred; bytes the name.
    pub const MQ_UNLINK: u32 = 2;
    /// mq_send (long): w0 descriptor, w1 priority, w2 nonblock override
    /// (1 for the descriptor's flag), cred; bytes the message.
    pub const MQ_SEND: u32 = 3;
    /// mq_receive (long): w0 descriptor, w1 the most bytes, cred. =>
    /// w0 priority; bytes the message.
    pub const MQ_RECV: u32 = 4;
    /// mq_getattr: w0 descriptor. => flags, maxmsg, msgsize, curmsgs.
    pub const MQ_GETATTR: u32 = 5;
    /// mq_setattr: w0 descriptor, w1 flags (NONBLOCK or 0). => the flags
    /// before.
    pub const MQ_SETATTR: u32 = 6;
    /// mq_notify: w0 descriptor, w1 1 to register or 0 to remove. EBUSY
    /// when another descriptor holds the registration.
    pub const MQ_NOTIFY: u32 = 7;
    /// The wait of the registration (long): w0 descriptor. => w0 1 when a
    /// message came to the empty queue, 2 when the registration went.
    pub const MQ_NOTIFY_WAIT: u32 = 8;

    /// msgget: w0 key, w1 flags (IPC_CREAT, IPC_EXCL, the mode), cred. =>
    /// the id.
    pub const MSG_GET: u32 = 16;
    /// msgsnd (long): w0 id, w1 type, w2 nowait, cred; bytes the text.
    pub const MSG_SND: u32 = 17;
    /// msgrcv (long): w0 id, w1 the most bytes, w2 type, w3 flags
    /// (IPC_NOWAIT, MSG_NOERROR, MSG_EXCEPT), cred. => w0 type, w1 the
    /// bytes in the message; bytes the text, cut to the most.
    pub const MSG_RCV: u32 = 18;
    /// msgctl: w0 id, w1 cmd (IPC_RMID, IPC_SET, IPC_STAT), cred, then for
    /// IPC_SET w uid, gid, mode, qbytes. => the status (see [stat]).
    pub const MSG_CTL: u32 = 19;

    /// semget: w0 key, w1 nsems, w2 flags, cred. => the id.
    pub const SEM_GET: u32 = 20;
    /// semop (long): w0 id, w1 the count of operations, cred, then for
    /// each operation w num, w op (as i16), w flags (as i16).
    pub const SEM_OP: u32 = 21;
    /// semctl: w0 id, w1 semnum, w2 cmd, w3 argument, cred; bytes for
    /// SETALL the values u16 each. => the value, the status, or in bytes
    /// the values of GETALL.
    pub const SEM_CTL: u32 = 22;

    /// shmget: w0 key, w1 size, w2 flags, w3 a random number the caller
    /// drew (the name of the file of the pages; EEXIST for one in use, EINVAL
    /// for 0), cred. => the id, the serial (that number), 1 when the segment
    /// is new (its file is to be made), a serial whose file is left to remove
    /// or 0.
    pub const SHM_GET: u32 = 24;
    /// shmat: w0 id, w1 flags (SHM_RDONLY), cred. => the serial, the size, the
    /// owner's uid, the creator's uid (the file is to be theirs), a serial
    /// whose file is left to remove or 0.
    pub const SHM_AT: u32 = 25;
    /// shmdt: w0 id, cred. => 1 when the segment is gone and its file is
    /// to be removed, w1 its serial.
    pub const SHM_DT: u32 = 26;
    /// shmctl: w0 id, w1 cmd, cred, then for IPC_SET w uid, gid, mode. Every
    /// answer ends with a serial whose file is left to remove, or 0. =>
    /// the status, w[0] 1 when the segment is gone and its file is to be
    /// removed, w[1] the serial.
    pub const SHM_CTL: u32 = 27;

    /// sem_open: w0 oflag, w1 mode, w2 value, cred; bytes the name. =>
    /// the id.
    pub const NSEM_OPEN: u32 = 32;
    /// sem_unlink: cred; bytes the name.
    pub const NSEM_UNLINK: u32 = 33;
    /// sem_close: w0 id.
    pub const NSEM_CLOSE: u32 = 34;
    /// sem_wait (long): w0 id, w1 nowait.
    pub const NSEM_WAIT: u32 = 35;
    /// sem_post: w0 id.
    pub const NSEM_POST: u32 = 36;
    /// sem_getvalue: w0 id. => the value.
    pub const NSEM_VALUE: u32 = 37;

    /// Whether the operation is a long one: a start that may answer WAIT
    /// and the takes that follow.
    pub const fn is_long(op: u32) -> bool {
        matches!(
            op,
            MQ_SEND | MQ_RECV | MQ_NOTIFY_WAIT | MSG_SND | MSG_RCV | SEM_OP | NSEM_WAIT
        )
    }
}

/// The words of the stat answers: the permission part, then the fields of
/// the kind.
pub mod stat {
    /// key, uid, gid, cuid, cgid, mode, seq.
    pub const PERM: usize = 7;
}

/// Who the caller is, as the process service vouched for it (Vouch): the
/// service never takes the credentials from a request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Who {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

/// The caller as an operation sees it: who, and the time the layer read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cred {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub now: i64,
}

impl Cred {
    /// The words of a request that stand for the caller: the time in seconds.
    pub const WORDS: usize = 1;

    /// `who` and the time `w` carries.
    pub fn of(who: Who, w: &[u64]) -> Cred {
        Cred {
            uid: who.uid,
            gid: who.gid,
            pid: who.pid,
            now: w[0] as i64,
        }
    }
}

/// Bit 31 of the operation on the wire: the request carries the identity
/// session of the caller's process as its first handle.
pub const ID_ATTACHED: u32 = 1 << 31;

/// The status of a refusal for a session that has not shown its identity
/// session yet: the layer sends it with the request again.
pub const NEED_ID: u32 = ERRNO + 999;

/// An IPC or IPC_TAKE request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Call<'a> {
    pub key: Option<u64>,
    pub op: u32,
    /// The request carries a copy of the identity session of the caller's
    /// process as its first handle (bit 31 of the operation on the wire).
    pub id: bool,
    pub words: [u64; WORDS_MAX],
    pub n: usize,
    pub bytes: &'a [u8],
}

impl<'a> Call<'a> {
    pub fn new(op: u32, words: &[u64], bytes: &'a [u8]) -> Call<'a> {
        let mut all = [0; WORDS_MAX];
        all[..words.len()].copy_from_slice(words);
        Call {
            key: None,
            op,
            id: false,
            words: all,
            n: words.len(),
            bytes,
        }
    }

    pub fn words(&self) -> &[u64] {
        &self.words[..self.n]
    }

    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        if self.n > WORDS_MAX {
            return Err(Status::BadSize);
        }
        match self.key {
            None => crate::Method::Ipc.header().write(w)?,
            Some(key) => {
                if key == 0 {
                    return Err(Status::BadSize);
                }
                crate::Method::IpcTake.header().write(w)?;
                w.u64(key)?;
            }
        }
        w.u32(self.op | if self.id { ID_ATTACHED } else { 0 })?;
        w.u32(self.n as u32)?;
        for &word in self.words() {
            w.u64(word)?;
        }
        w.bytes(self.bytes)
    }

    pub fn parse(mut body: Reader<'a>, take: bool) -> Result<Call<'a>, Status> {
        let key = if take { Some(body.u64()?) } else { None };
        let op = body.u32()?;
        let (op, id) = (op & !ID_ATTACHED, op & ID_ATTACHED != 0);
        let n = body.u32()? as usize;
        if n > WORDS_MAX || key == Some(0) {
            return Err(Status::BadSize);
        }
        let mut words = [0; WORDS_MAX];
        for word in &mut words[..n] {
            *word = body.u64()?;
        }
        let len = body.left();
        let bytes = body.bytes(len)?;
        body.finish()?;
        Ok(Call {
            key,
            op,
            id,
            words,
            n,
            bytes,
        })
    }
}

/// An answer: the words and the bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Answer<'a> {
    pub words: [u64; WORDS_MAX],
    pub n: usize,
    pub bytes: &'a [u8],
}

impl<'a> Answer<'a> {
    pub fn new(words: &[u64], bytes: &'a [u8]) -> Answer<'a> {
        let mut all = [0; WORDS_MAX];
        all[..words.len()].copy_from_slice(words);
        Answer {
            words: all,
            n: words.len(),
            bytes,
        }
    }

    pub fn words(&self) -> &[u64] {
        &self.words[..self.n]
    }

    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.n as u32)?;
        for &word in self.words() {
            w.u64(word)?;
        }
        w.bytes(self.bytes)
    }

    pub fn parse(mut body: Reader<'a>) -> Result<Answer<'a>, Status> {
        let n = body.u32()? as usize;
        if n > WORDS_MAX {
            return Err(Status::BadSize);
        }
        let mut words = [0; WORDS_MAX];
        for word in &mut words[..n] {
            *word = body.u64()?;
        }
        let len = body.left();
        let bytes = body.bytes(len)?;
        body.finish()?;
        Ok(Answer { words, n, bytes })
    }
}

/// The key of an IPC_CANCEL.
pub fn cancel_key(mut body: Reader<'_>) -> Result<u64, Status> {
    let key = body.u64()?;
    body.finish()?;
    if key == 0 {
        return Err(Status::BadSize);
    }
    Ok(key)
}

/// The errno a refusal of the service stands for, if it is one.
pub fn errno_of(status: Status) -> Option<i32> {
    let code = status.code();
    (ERRNO..ERRNO + 1000)
        .contains(&code)
        .then(|| (code - ERRNO) as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_call_goes_through_its_bytes() {
        let call = Call::new(op::MQ_SEND, &[3, 1, 0, 7, 8, 9, 10], b"hello");
        let mut w = Writer::new();
        call.write(&mut w).unwrap();
        let bytes = w.as_bytes();
        let mut r = Reader::new(&bytes[proto_wire::HEADER_LEN..]);
        let _ = &mut r;
        let parsed = Call::parse(Reader::new(&bytes[proto_wire::HEADER_LEN..]), false).unwrap();
        assert_eq!(parsed, call);
    }

    #[test]
    fn a_take_carries_the_key_first() {
        let mut call = Call::new(op::MSG_RCV, &[1, 2], b"");
        call.key = Some(9);
        let mut w = Writer::new();
        call.write(&mut w).unwrap();
        let parsed =
            Call::parse(Reader::new(&w.as_bytes()[proto_wire::HEADER_LEN..]), true).unwrap();
        assert_eq!(parsed, call);
        call.key = Some(0);
        assert!(call.write(&mut Writer::new()).is_err());
    }

    #[test]
    fn an_answer_goes_through_its_bytes() {
        let a = Answer::new(&[5, 6], b"xyz");
        let mut w = Writer::new();
        a.write(&mut w).unwrap();
        assert_eq!(Answer::parse(Reader::new(w.as_bytes())).unwrap(), a);
    }

    #[test]
    fn too_many_words_are_refused() {
        let mut w = Writer::new();
        w.u32(1).unwrap();
        w.u32(WORDS_MAX as u32 + 1).unwrap();
        assert!(Call::parse(Reader::new(w.as_bytes()), false).is_err());
    }

    #[test]
    fn the_codes_of_errors_are_the_errno_plus_a_base() {
        assert_eq!(errno_of(Status::from_code(ERRNO + 22)), Some(22));
        assert_eq!(errno_of(Status::from_code(702)), None);
    }
}
