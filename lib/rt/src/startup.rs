// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The start protocol (spec 13.3, proto_init): a program its parent
//! started asks for its start data with START requests through its start
//! channel, entry 0 of its table, and each reply brings up to four handles,
//! each under a name, and a piece of its arguments, until the reply with
//! LAST. `startup` is the program's side, `Giver` the parent's. The
//! handles named `process` and `thread`, the program's own process and
//! first thread, always come; the rest is what the role of the program
//! asks for. Init has no start data: its first handles come from
//! `init_handles`.

use crate::handle::{Any, Channel, Handle, Kind, Outgoing, Process, Thread};
use crate::msgbuf;
use crate::sys::{self, Reply, Token};
use abi::{Error, INLINE_MAX, MESSAGE_HANDLES, MESSAGE_MAX, ObjectKind, START_CHANNEL};
use proto_init::{Method, START_NAMES, StartReply, VERSION};
use proto_wire::{Header, Name, Reader, Status, Writer};

/// The names a program takes besides `process` and `thread`, the bytes of
/// its arguments, and the replies to START, at most: the start data lies
/// on the stack of `main`, and five round trips with the parent bound the
/// start.
pub const NAMES_MAX: usize = 8;
pub const ARGS_MAX: usize = 256;
pub const REPLIES_MAX: usize = 4;
/// The handles a `Giver` holds: `process`, `thread` and NAMES_MAX more.
pub const GIVER_HANDLES: usize = NAMES_MAX + 2;

/// The names of the program's own process and first thread.
pub const PROCESS: Name = name(b"process");
pub const THREAD: Name = name(b"thread");

const fn name(bytes: &[u8]) -> Name {
    match Name::new(bytes) {
        Ok(name) => name,
        Err(_) => panic!("not a name"),
    }
}

/// Why `startup` gave no start data. Whatever came closes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartError {
    /// The start data went already, or the program is init, whose first
    /// handles come from `init_handles`.
    Taken,
    /// send through the start channel failed, PEER_CLOSED when the parent
    /// closed it.
    Kernel(Error),
    /// The parent refused a START with this status, BAD_VERSION among
    /// them.
    Refused(Status),
    /// A reply out of the layout of proto_init, a name that came twice, or
    /// `process` or `thread` of another kind.
    Malformed,
    /// More than NAMES_MAX names, ARGS_MAX bytes of arguments or
    /// REPLIES_MAX replies.
    TooMuch,
    /// No `process` or no `thread`.
    Missing,
}

/// Why `Startup::take` gave no handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TakeError {
    /// No handle came under the name, or it was taken.
    Missing,
    /// The handle's object is of another kind; it stays.
    WrongKind,
}

/// The start data of a program (spec 13.3), which `startup` gives once.
pub struct Startup {
    /// The program's own process, with the rights its parent gave (MANAGE
    /// and TRANSFER from rt::loader::spawn).
    pub process: Handle<Process>,
    /// The program's first thread, likewise.
    pub thread: Handle<Thread>,
    /// The start channel, entry 0 of the table: for a service its
    /// connection to init.
    pub parent: Handle<Channel>,
    args: [u8; ARGS_MAX],
    args_len: usize,
    named: Named,
}

/// The handles that came under names other than `process` and `thread`,
/// each with the kind of its object; those nobody took close with it.
struct Named {
    count: usize,
    /// The values; abi::Handle::INVALID once taken.
    entries: [(Name, ObjectKind, abi::Handle); NAMES_MAX],
}

impl Named {
    const EMPTY: (Name, ObjectKind, abi::Handle) =
        (PROCESS, ObjectKind::Unknown(0), abi::Handle::INVALID);

    fn new() -> Named {
        Named {
            count: 0,
            entries: [Named::EMPTY; NAMES_MAX],
        }
    }
}

impl Drop for Named {
    /// Closes the handles nobody took.
    fn drop(&mut self) {
        for &(_, _, h) in &self.entries[..self.count] {
            if h != abi::Handle::INVALID {
                drop(Handle::<Any>::from_raw(h));
            }
        }
    }
}

impl Startup {
    /// The arguments, the pieces of all replies joined; what they mean
    /// the protocol of the program's role says.
    pub fn args(&self) -> &[u8] {
        &self.args[..self.args_len]
    }

    /// The handle that came under `name`, when its object is of kind `K`:
    /// it leaves the start data. WrongKind leaves it there.
    pub fn take<K: Kind>(&mut self, name: &str) -> Result<Handle<K>, TakeError> {
        let named = &mut self.named;
        let (_, kind, value) = named.entries[..named.count]
            .iter_mut()
            .find(|(n, _, h)| n.as_bytes() == name.as_bytes() && *h != abi::Handle::INVALID)
            .ok_or(TakeError::Missing)?;
        if !K::accepts(*kind) {
            return Err(TakeError::WrongKind);
        }
        Ok(Handle::from_raw(core::mem::replace(
            value,
            abi::Handle::INVALID,
        )))
    }
}

/// The start data of this program (spec 13.3), at the first call: START
/// requests through the start channel, one per reply, until the reply with
/// LAST. Once a START passed, the channel is the program's own
/// (`Startup::parent`); before, the entry is only seen (`Handle::borrowed`),
/// since a process made without a start channel has none there, and in a
/// strict build that first send panics with BAD_HANDLE. Init, whose first
/// thread starts with x0 0, has no start data (`init_handles`), and every
/// call after the first gets `Taken`.
pub fn startup() -> Result<Startup, StartError> {
    if !crate::first_handles(false) {
        return Err(StartError::Taken);
    }
    let start = Handle::<Channel>::borrowed(START_CHANNEL);
    let ask = || sys::send(&start, &Method::Start.header().bytes()).map_err(StartError::Kernel);
    let mut reply = ask()?;
    let parent = Handle::<Channel>::from_raw(START_CHANNEL);
    let mut got = Collected::new();
    for replies in 1..=REPLIES_MAX {
        if got.add(&mut reply)? {
            return got.finish(parent);
        }
        if replies < REPLIES_MAX {
            reply = ask()?;
        }
    }
    Err(StartError::TooMuch)
}

/// What the replies to START brought so far.
struct Collected {
    process: Option<Handle<Process>>,
    thread: Option<Handle<Thread>>,
    args: [u8; ARGS_MAX],
    args_len: usize,
    named: Named,
}

impl Collected {
    fn new() -> Collected {
        Collected {
            process: None,
            thread: None,
            args: [0; ARGS_MAX],
            args_len: 0,
            named: Named::new(),
        }
    }

    /// Takes in one reply: true for the one with LAST.
    fn add(&mut self, reply: &mut Reply) -> Result<bool, StartError> {
        let mut buffer = [0; MESSAGE_MAX];
        let bytes = bytes_of(reply, &mut buffer);
        match Reader::new(bytes).u32().map(Status::from_code) {
            Ok(Status::Ok) => {}
            Ok(status) => return Err(StartError::Refused(status)),
            Err(_) => return Err(StartError::Malformed),
        }
        let start =
            StartReply::read(bytes, reply.handles.len()).map_err(|_| StartError::Malformed)?;
        for (i, name) in start.names.iter().enumerate() {
            let Some(name) = *name else { break };
            self.named_once(name)?;
            if name == PROCESS {
                self.process = Some(reply.handles.take(i).map_err(|_| StartError::Malformed)?);
            } else if name == THREAD {
                self.thread = Some(reply.handles.take(i).map_err(|_| StartError::Malformed)?);
            } else {
                let named = &mut self.named;
                let entry = named
                    .entries
                    .get_mut(named.count)
                    .ok_or(StartError::TooMuch)?;
                let (kind, _) = reply.handles.info(i).ok_or(StartError::Malformed)?;
                let h = reply
                    .handles
                    .take_any(i)
                    .map_err(|_| StartError::Malformed)?;
                *entry = (name, kind, h.into_raw());
                named.count += 1;
            }
        }
        let end = self.args_len + start.args.len();
        let room = self
            .args
            .get_mut(self.args_len..end)
            .ok_or(StartError::TooMuch)?;
        room.copy_from_slice(start.args);
        self.args_len = end;
        Ok(start.last)
    }

    /// Malformed when `name` came before.
    fn named_once(&self, name: Name) -> Result<(), StartError> {
        let seen = match name {
            PROCESS => self.process.is_some(),
            THREAD => self.thread.is_some(),
            _ => self.named.entries[..self.named.count]
                .iter()
                .any(|(n, ..)| *n == name),
        };
        if seen {
            Err(StartError::Malformed)
        } else {
            Ok(())
        }
    }

    fn finish(self, parent: Handle<Channel>) -> Result<Startup, StartError> {
        let (Some(process), Some(thread)) = (self.process, self.thread) else {
            return Err(StartError::Missing);
        };
        Ok(Startup {
            process,
            thread,
            parent,
            args: self.args,
            args_len: self.args_len,
            named: self.named,
        })
    }
}

/// The bytes of `reply`: from x2-x9, or from the message buffer when they
/// are more than 64 (sys::keep_whole put them all there).
fn bytes_of<'a>(reply: &Reply, buffer: &'a mut [u8; MESSAGE_MAX]) -> &'a [u8] {
    let bytes = &mut buffer[..reply.len.min(MESSAGE_MAX)];
    if reply.len <= INLINE_MAX {
        bytes.copy_from_slice(&abi::inline_bytes(&reply.words)[..reply.len]);
    } else {
        msgbuf::read(0, bytes);
    }
    bytes
}

/// How `Giver::answer` answered a request.
#[derive(Debug, PartialEq, Eq)]
pub enum Answered {
    /// A reply to START without LAST: more come.
    Piece,
    /// The reply with LAST.
    Last,
    /// The request was refused with this status: BAD_SIZE or BAD_VERSION
    /// for a START out of the layout, BAD_STATE for one after LAST.
    Refused(Status),
    /// A request of another method, which the caller answers.
    Other { method: u16, token: Token },
}

/// The parent's side of the start protocol (spec 13.3): the handles, each
/// under a name, and the arguments a program gets, which `answer` gives
/// out in replies to its START requests. It holds GIVER_HANDLES handles
/// and ARGS_MAX bytes; handles that never went close with it.
pub struct Giver {
    count: usize,
    sent: usize,
    names: [Option<Name>; GIVER_HANDLES],
    handles: [Option<Handle<Any>>; GIVER_HANDLES],
    args: [u8; ARGS_MAX],
    args_len: usize,
    done: bool,
}

impl Giver {
    pub fn new() -> Giver {
        Giver {
            count: 0,
            sent: 0,
            names: [None; GIVER_HANDLES],
            handles: Default::default(),
            args: [0; ARGS_MAX],
            args_len: 0,
            done: false,
        }
    }

    /// Gives `h`, a handle with TRANSFER, under `name`: 1 to 16 bytes,
    /// none zero, and none given before. `h` comes back when the name is
    /// not one of those, or when GIVER_HANDLES are there already.
    pub fn give(&mut self, name: &str, h: Handle<Any>) -> Result<(), Handle<Any>> {
        let Ok(name) = Name::new(name.as_bytes()) else {
            return Err(h);
        };
        if self.count == GIVER_HANDLES || self.names.contains(&Some(name)) {
            return Err(h);
        }
        self.names[self.count] = Some(name);
        self.handles[self.count] = Some(h);
        self.count += 1;
        Ok(())
    }

    /// The arguments: INVALID_ARGS for more than ARGS_MAX bytes.
    pub fn set_args(&mut self, args: &[u8]) -> Result<(), Error> {
        let room = self.args.get_mut(..args.len()).ok_or(Error::InvalidArgs)?;
        room.copy_from_slice(args);
        self.args_len = args.len();
        Ok(())
    }

    /// Answers `request`, the bytes of a request whose token is `token`. A
    /// START of this version gets the next reply: the next four handles
    /// with their names, and the arguments with the first, LAST once all
    /// went. A request of another method comes back to the caller with its
    /// token; a START out of the layout gets BAD_SIZE, one of another
    /// version BAD_VERSION, one after LAST BAD_STATE. The handles of a
    /// reply that failed come back here when they stayed in this process's
    /// table (sys::Refused), and the error comes back: PEER_CLOSED when
    /// the program ended, and its handles went with it. When the kernel
    /// refused the reply before it reached the request (a handle without
    /// TRANSFER, say), the program gets the error as its status; when the
    /// handles went, every later START gets BAD_STATE.
    pub fn answer(&mut self, request: &[u8], token: Token) -> Result<Answered, Error> {
        let mut r = Reader::new(request);
        let header = match Header::read(&mut r) {
            Ok(header) => header,
            Err(status) => return refuse(token, status),
        };
        if header.method != Method::Start.number() {
            return Ok(Answered::Other {
                method: header.method,
                token,
            });
        }
        if header.version != VERSION {
            return refuse(token, Status::BadVersion);
        }
        if r.finish().is_err() {
            return refuse(token, Status::BadSize);
        }
        if self.done {
            return refuse(token, Status::Kernel(Error::BadState));
        }
        let first = self.sent;
        let n = (self.count - first).min(MESSAGE_HANDLES);
        let mut names = [None; START_NAMES];
        names[..n].copy_from_slice(&self.names[first..first + n]);
        let last = first + n == self.count;
        let args = if first == 0 {
            &self.args[..self.args_len]
        } else {
            &[]
        };
        let mut w = Writer::new();
        // The pieces fit: ARGS_MAX is under proto_init::START_PIECE_MAX.
        let _ = StartReply { last, names, args }.write(&mut w);
        let mut handles = Outgoing::new();
        for h in self.handles[first..first + n].iter_mut() {
            if let Some(h) = h.take() {
                let _ = handles.push(h);
            }
        }
        match token.reply_handles(w.as_bytes(), handles) {
            Ok(()) => {
                self.sent += n;
                self.done = last;
                Ok(if last {
                    Answered::Last
                } else {
                    Answered::Piece
                })
            }
            Err(refused) => {
                match refused.back {
                    Some(mut back) => {
                        for slot in self.handles[first..first + n].iter_mut().rev() {
                            *slot = back.pop();
                        }
                    }
                    // The handles went: the program ended, or its startup()
                    // fails with the same error; no START is answered again.
                    None => self.done = true,
                }
                if let Some(token) = refused.token {
                    // The request still waits: the program learns the error
                    // as the status of its START.
                    let _ = token.reply(&proto_wire::reply(Status::Kernel(refused.error)));
                }
                Err(refused.error)
            }
        }
    }
}

impl Default for Giver {
    fn default() -> Giver {
        Giver::new()
    }
}

/// Refuses a request with `status` alone.
fn refuse(token: Token, status: Status) -> Result<Answered, Error> {
    token.reply(&proto_wire::reply(status))?;
    Ok(Answered::Refused(status))
}
