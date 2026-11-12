// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The requests and replies of the sockets' methods (the table in the
//! description of the crate). `Request::write` is the client's side and
//! `Request::parse` the service's; a body that is short, long or has a
//! field out of its range is BAD_SIZE.

use crate::{Address, DATA_MAX, Method, SLOT};
use proto_wire::{Reader, Status, Writer, watch};

/// The most descriptions one CLONE carries.
pub const CLONE_MAX: usize = 64;

/// The kinds of a socket.
pub const STREAM: u32 = 1;
pub const DGRAM: u32 = 2;

/// The flags of SOCKET and ACCEPT: the new description does not wait.
pub const NONBLOCK: u32 = 1;
/// The flags of SEND and RECV.
pub const PEEK: u32 = 1;
pub const DONTWAIT: u32 = 2;
/// The bytes are in a cell of the session's shared buffer (BUFFER): SEND
/// names the cell and the length, RECV the cell, and no byte travels in the
/// message.
pub const BUF: u32 = 4;
/// The flag of RECV's reply: the datagram was longer than the bytes asked.
pub const OUT_TRUNC: u32 = 1;

/// SHUTDOWN's kinds.
pub const SHUT_READ: u32 = 0;
pub const SHUT_WRITE: u32 = 1;
pub const SHUT_BOTH: u32 = 2;

/// NAME's subjects: the socket's own address or its peer's.
pub const OWN_NAME: u32 = 0;
pub const PEER_NAME: u32 = 1;

/// The names of the options. Those with a number of `proto_pipe::sock` mean
/// what they mean there.
pub mod opt {
    pub const REUSEADDR: u32 = 1;
    pub const TYPE: u32 = 2;
    pub const ERROR: u32 = 3;
    pub const RCVBUF: u32 = 4;
    pub const SNDBUF: u32 = 5;
    pub const ACCEPTCONN: u32 = 6;
    pub const DOMAIN: u32 = 7;
    pub const KEEPALIVE: u32 = 8;
    pub const BROADCAST: u32 = 9;
    pub const NODELAY: u32 = 32;
    /// The description's own flag NONBLOCK, for `fcntl`.
    pub const NONBLOCK: u32 = 33;
    /// The bytes ready to read: of a stream the bytes in the queue of
    /// receiving, of a datagram socket the length of the next datagram.
    pub const NREAD: u32 = 34;
    /// SO_LINGER: 0 for off, else `LINGER_ON` with the seconds (0 to 65 535).
    pub const LINGER: u32 = 35;
    /// SO_REUSEPORT: a stream before BIND; a datagram socket has no such option.
    pub const REUSEPORT: u32 = 36;
    /// SO_RCVTIMEO and SO_SNDTIMEO in milliseconds, 0 for none.
    pub const RCVTIMEO: u32 = 37;
    pub const SNDTIMEO: u32 = 38;
    /// GETOPT on any description of the session: the sessions that hold a
    /// shared buffer now (bits 0-15) and the limit of them (bits 16-31).
    pub const BUFFERS: u32 = 39;
    /// GETOPT on any description of the session: the KiB that went through
    /// the shared buffers since the service started (wrapping).
    pub const BUFFERED: u32 = 40;
    /// GETOPT on any description of the session: the number of the stack instance that holds
    /// the session (its home).
    pub const HOME: u32 = 41;
    /// GETOPT on any description of the session: the requests the instance has answered since
    /// the service started (wrapping).
    pub const CALLS: u32 = 42;
    /// The bit of the value of LINGER that says it is on.
    pub const LINGER_ON: u32 = 0x8000_0000;
}

/// The values CLOSE's `linger` word takes: the caller may wait for the close
/// to finish (a description with a linger time that it was the last to hold).
pub const CLOSE_MAY_WAIT: u32 = 1;

/// The passes `netd` holds at once, and for one session (EXPORT).
pub const PASSES_MAX: usize = 64;
pub const SESSION_PASSES: usize = 16;
/// The tag of the label of a pass: a copy of the service's channel that
/// carries a description (EXPORT), apart from `proto_pipe::OWN`.
pub const PASS: u64 = 1 << 62;

/// The records one EPOLL_SET carries at most: the largest of 16, 8 and 4 for
/// which the step with records on a place that holds 15 already stays within
/// the budget of a step (`cargo xtask net-probe steps`, role `e`).
pub const EPOLL_BATCH: usize = 16;
/// The pairs one EPOLL_WAIT answers at most.
pub const EPOLL_MOST: usize = 64;
/// The actions of a record of EPOLL_SET.
pub const EPOLL_ADD: u32 = 1;
pub const EPOLL_MOD: u32 = 2;
pub const EPOLL_DEL: u32 = 3;
/// The bits of events on the wire are those of Linux's epoll.
pub mod epoll {
    pub const IN: u32 = 0x1;
    pub const PRI: u32 = 0x2;
    pub const OUT: u32 = 0x4;
    pub const ERR: u32 = 0x8;
    pub const HUP: u32 = 0x10;
    pub const RDNORM: u32 = 0x40;
    pub const WRNORM: u32 = 0x100;
    pub const RDHUP: u32 = 0x2000;
    pub const EXCLUSIVE: u32 = 1 << 28;
    pub const ONESHOT: u32 = 1 << 30;
    pub const ET: u32 = 1 << 31;
    /// The events a record may ask for besides the modes.
    pub const EVENTS: u32 = IN | PRI | OUT | ERR | HUP | RDNORM | WRNORM | RDHUP;
}

/// One record of EPOLL_SET.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EpollRecord {
    pub action: u32,
    pub description: u32,
    pub events: u32,
    pub label: u32,
}

/// The records of an EPOLL_SET.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpollList {
    pub len: usize,
    pub records: [EpollRecord; EPOLL_BATCH],
}

impl EpollList {
    pub fn new(items: &[EpollRecord]) -> Option<EpollList> {
        let mut list = EpollList {
            len: items.len(),
            records: [EpollRecord::default(); EPOLL_BATCH],
        };
        list.records.get_mut(..items.len())?.copy_from_slice(items);
        Some(list)
    }

    pub fn as_slice(&self) -> &[EpollRecord] {
        &self.records[..self.len]
    }
}

/// The pairs of an EPOLL_WAIT's READY: the label of the record and the events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpollReady {
    pub len: usize,
    pub pairs: [(u32, u32); EPOLL_MOST],
}

impl EpollReady {
    pub const EMPTY: EpollReady = EpollReady {
        len: 0,
        pairs: [(0, 0); EPOLL_MOST],
    };

    pub fn push(&mut self, label: u32, events: u32) -> bool {
        match self.pairs.get_mut(self.len) {
            Some(pair) => {
                *pair = (label, events);
                self.len += 1;
                true
            }
            None => false,
        }
    }

    pub fn as_slice(&self) -> &[(u32, u32)] {
        &self.pairs[..self.len]
    }

    /// The data of READY.
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.len as u32)?;
        for &(label, events) in self.as_slice() {
            w.u32(label)?;
            w.u32(events)?;
        }
        Ok(())
    }

    /// The pairs of the data of a READY: BAD_SIZE unless the count is within
    /// `EPOLL_MOST` and the bytes are exactly those of the pairs.
    pub fn parse(data: &[u8]) -> Result<EpollReady, Status> {
        let mut r = Reader::new(data);
        let len = r.u32()? as usize;
        if len > EPOLL_MOST {
            return Err(Status::BadSize);
        }
        let mut ready = EpollReady::EMPTY;
        for pair in &mut ready.pairs[..len] {
            *pair = (r.u32()?, r.u32()?);
        }
        ready.len = len;
        r.finish()?;
        Ok(ready)
    }
}

/// EPOLL_WAIT's flag: no waiting, READY with no pairs when none is ready.
pub const EPOLL_DONTWAIT: u32 = DONTWAIT;

/// EPOLL_SET's reply: status 0, the set and one status word for each record.
pub fn write_epoll_set(w: &mut Writer, set: u32, statuses: &[u32]) -> Result<(), Status> {
    w.u32(Status::Ok.code())?;
    w.u32(set)?;
    for &status in statuses {
        w.u32(status)?;
    }
    Ok(())
}

/// The set and the statuses of a reply of EPOLL_SET with `count` records
/// (`statuses` gets them); a refusal is the error.
pub fn read_epoll_set(reply: &[u8], count: usize, statuses: &mut [u32]) -> Result<u32, Status> {
    let mut r = Reader::new(reply);
    match Status::from_code(r.u32()?) {
        Status::Ok => {}
        status => return Err(status),
    }
    let set = r.u32()?;
    for status in statuses.get_mut(..count).ok_or(Status::BadSize)? {
        *status = r.u32()?;
    }
    r.finish()?;
    Ok(set)
}

/// The bits of a description on the wire: the place in the service's table
/// (12 bits) and the generation of the place (20 bits, never 0).
pub const SLOT_BITS: u32 = 12;

pub const fn slot(description: u32) -> usize {
    (description & ((1 << SLOT_BITS) - 1)) as usize
}

pub const fn generation(description: u32) -> u32 {
    description >> SLOT_BITS
}

pub const fn description(slot: usize, generation: u32) -> u32 {
    (generation << SLOT_BITS) | slot as u32
}

/// The list of descriptions of a CLONE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct List {
    pub len: usize,
    pub items: [u32; CLONE_MAX],
}

impl List {
    pub fn new(items: &[u32]) -> Option<List> {
        let mut list = List {
            len: items.len(),
            items: [0; CLONE_MAX],
        };
        list.items.get_mut(..items.len())?.copy_from_slice(items);
        Some(list)
    }

    pub fn as_slice(&self) -> &[u32] {
        &self.items[..self.len]
    }
}

/// A request of the sockets' methods. `key` is the key of a long operation
/// in a method that takes the result (`*_TAKE`), None in the start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> {
    Socket {
        family: u32,
        kind: u32,
        flags: u32,
    },
    Bind {
        description: u32,
        address: Address,
    },
    Listen {
        description: u32,
        backlog: u32,
    },
    Connect {
        key: Option<u64>,
        description: u32,
        address: Address,
    },
    Accept {
        key: Option<u64>,
        description: u32,
        flags: u32,
    },
    Send {
        key: Option<u64>,
        description: u32,
        flags: u32,
        address: Address,
        data: &'a [u8],
    },
    Recv {
        key: Option<u64>,
        description: u32,
        flags: u32,
        most: u32,
    },
    /// SEND with `BUF`: `len` bytes (1..=`SLOT`) of the cell at `offset` of
    /// the session's shared buffer.
    SendCell {
        key: Option<u64>,
        description: u32,
        flags: u32,
        address: Address,
        offset: u32,
        len: u32,
    },
    /// RECV with `BUF`: up to `most` bytes (1..=`SLOT`) into the cell at
    /// `offset`.
    RecvCell {
        key: Option<u64>,
        description: u32,
        flags: u32,
        most: u32,
        offset: u32,
    },
    Shutdown {
        description: u32,
        how: u32,
    },
    Close {
        description: u32,
        linger: u32,
    },
    /// The wait of a CLOSE that answered WAIT k.
    CloseTake(u64),
    /// A pass for the description, to hand to another process (one handle in
    /// the reply).
    Export {
        description: u32,
    },
    /// The description a pass names becomes the session's (the request
    /// carries the pass).
    Adopt,
    GetOpt {
        description: u32,
        name: u32,
    },
    SetOpt {
        description: u32,
        name: u32,
        value: u32,
    },
    Name {
        description: u32,
        which: u32,
    },
    Watch(watch::Set),
    WatchTake(u64),
    WatchCancel(u64),
    Abandon,
    Clone(List),
    /// More descriptions for the birth CLONE's reply named (`birth`): 1 to
    /// `CLONE_MAX`.
    CloneMore {
        birth: u32,
        list: List,
    },
    Cancel(u64),
    /// The interest records of a set of the session (0 makes a set).
    EpollSet {
        set: u32,
        list: EpollList,
    },
    EpollDrop(u32),
    EpollWait {
        key: Option<u64>,
        set: u32,
        most: u32,
        flags: u32,
    },
}

impl<'a> Request<'a> {
    /// The method that carries the request.
    pub fn method(&self) -> Method {
        match self {
            Request::Socket { .. } => Method::Socket,
            Request::Bind { .. } => Method::Bind,
            Request::Listen { .. } => Method::Listen,
            Request::Connect { key: None, .. } => Method::Connect,
            Request::Connect { .. } => Method::ConnectTake,
            Request::Accept { key: None, .. } => Method::Accept,
            Request::Accept { .. } => Method::AcceptTake,
            Request::Send { key: None, .. } => Method::Send,
            Request::Send { .. } => Method::SendTake,
            Request::Recv { key: None, .. } => Method::Recv,
            Request::Recv { .. } => Method::RecvTake,
            Request::SendCell { key: None, .. } => Method::Send,
            Request::SendCell { .. } => Method::SendTake,
            Request::RecvCell { key: None, .. } => Method::Recv,
            Request::RecvCell { .. } => Method::RecvTake,
            Request::Shutdown { .. } => Method::Shutdown,
            Request::Close { .. } => Method::Close,
            Request::CloseTake(_) => Method::CloseTake,
            Request::Export { .. } => Method::Export,
            Request::Adopt => Method::Adopt,
            Request::GetOpt { .. } => Method::GetOpt,
            Request::SetOpt { .. } => Method::SetOpt,
            Request::Name { .. } => Method::Name,
            Request::Watch(_) => Method::Watch,
            Request::WatchTake(_) => Method::WatchTake,
            Request::WatchCancel(_) => Method::WatchCancel,
            Request::Abandon => Method::Abandon,
            Request::Clone(_) => Method::Clone,
            Request::CloneMore { .. } => Method::CloneMore,
            Request::Cancel(_) => Method::Cancel,
            Request::EpollSet { .. } => Method::EpollSet,
            Request::EpollDrop(_) => Method::EpollDrop,
            Request::EpollWait { key: None, .. } => Method::EpollWait,
            Request::EpollWait { .. } => Method::EpollWaitTake,
        }
    }

    /// The whole request: the header and the body.
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        self.method().header().write(w)?;
        match *self {
            Request::Socket {
                family,
                kind,
                flags,
            } => {
                w.u32(family)?;
                w.u32(kind)?;
                w.u32(flags)
            }
            Request::Bind {
                description,
                address,
            } => {
                w.u32(description)?;
                address.write(w)
            }
            Request::Listen {
                description,
                backlog,
            } => {
                w.u32(description)?;
                w.u32(backlog)
            }
            Request::Connect {
                key,
                description,
                address,
            } => {
                put_key(w, key)?;
                w.u32(description)?;
                address.write(w)
            }
            Request::Accept {
                key,
                description,
                flags,
            } => {
                put_key(w, key)?;
                w.u32(description)?;
                w.u32(flags)
            }
            Request::Send {
                key,
                description,
                flags,
                address,
                data,
            } => {
                put_key(w, key)?;
                w.u32(description)?;
                w.u32(flags)?;
                address.write(w)?;
                w.bytes(data)
            }
            Request::Recv {
                key,
                description,
                flags,
                most,
            } => {
                put_key(w, key)?;
                w.u32(description)?;
                w.u32(flags)?;
                w.u32(most)
            }
            Request::SendCell {
                key,
                description,
                flags,
                address,
                offset,
                len,
            } => {
                put_key(w, key)?;
                w.u32(description)?;
                w.u32(flags | BUF)?;
                address.write(w)?;
                w.u32(offset)?;
                w.u32(len)
            }
            Request::RecvCell {
                key,
                description,
                flags,
                most,
                offset,
            } => {
                put_key(w, key)?;
                w.u32(description)?;
                w.u32(flags | BUF)?;
                w.u32(most)?;
                w.u32(offset)
            }
            Request::Shutdown { description, how } => {
                w.u32(description)?;
                w.u32(how)
            }
            Request::Close {
                description,
                linger,
            } => {
                w.u32(description)?;
                w.u32(linger)
            }
            Request::CloseTake(key) => w.u64(key),
            Request::Export { description } => w.u32(description),
            Request::Adopt => Ok(()),
            Request::GetOpt { description, name } => {
                w.u32(description)?;
                w.u32(name)
            }
            Request::SetOpt {
                description,
                name,
                value,
            } => {
                w.u32(description)?;
                w.u32(name)?;
                w.u32(value)
            }
            Request::Name { description, which } => {
                w.u32(description)?;
                w.u32(which)
            }
            Request::Watch(set) => set.write(w),
            Request::WatchTake(key) | Request::WatchCancel(key) | Request::Cancel(key) => {
                w.u64(key)
            }
            Request::Abandon => Ok(()),
            Request::Clone(list) => {
                w.u32(list.len as u32)?;
                for &d in list.as_slice() {
                    w.u32(d)?;
                }
                Ok(())
            }
            Request::CloneMore { birth, list } => {
                w.u32(birth)?;
                w.u32(list.len as u32)?;
                for &d in list.as_slice() {
                    w.u32(d)?;
                }
                Ok(())
            }
            Request::EpollSet { set, list } => {
                w.u32(set)?;
                w.u32(list.len as u32)?;
                for record in list.as_slice() {
                    w.u32(record.action)?;
                    w.u32(record.description)?;
                    w.u32(record.events)?;
                    w.u32(record.label)?;
                }
                Ok(())
            }
            Request::EpollDrop(set) => w.u32(set),
            Request::EpollWait {
                key,
                set,
                most,
                flags,
            } => {
                put_key(w, key)?;
                w.u32(set)?;
                w.u32(most)?;
                w.u32(flags)
            }
        }
    }

    /// The request of `method` from `body`, the bytes after the header.
    /// None for a method that is no socket's.
    pub fn parse(method: Method, mut body: Reader<'a>) -> Option<Result<Request<'a>, Status>> {
        let take = matches!(
            method,
            Method::ConnectTake | Method::AcceptTake | Method::SendTake | Method::RecvTake
        );
        let b = &mut body;
        let request = match method {
            Method::Socket => (|| {
                Ok(Request::Socket {
                    family: b.u32()?,
                    kind: b.u32()?,
                    flags: b.u32()?,
                })
            })(),
            Method::Bind => (|| {
                Ok(Request::Bind {
                    description: b.u32()?,
                    address: Address::read(b)?,
                })
            })(),
            Method::Listen => (|| {
                Ok(Request::Listen {
                    description: b.u32()?,
                    backlog: b.u32()?,
                })
            })(),
            Method::Connect | Method::ConnectTake => (|| {
                Ok(Request::Connect {
                    key: get_key(b, take)?,
                    description: b.u32()?,
                    address: Address::read(b)?,
                })
            })(),
            Method::Accept | Method::AcceptTake => (|| {
                Ok(Request::Accept {
                    key: get_key(b, take)?,
                    description: b.u32()?,
                    flags: b.u32()?,
                })
            })(),
            Method::Send | Method::SendTake => (|| {
                let key = get_key(b, take)?;
                let description = b.u32()?;
                let flags = b.u32()?;
                let address = Address::read(b)?;
                if flags & BUF != 0 {
                    let offset = b.u32()?;
                    let len = b.u32()?;
                    if !(1..=SLOT as u32).contains(&len) {
                        return Err(Status::BadSize);
                    }
                    return Ok(Request::SendCell {
                        key,
                        description,
                        flags: flags & !BUF,
                        address,
                        offset,
                        len,
                    });
                }
                let left = b.left();
                if left > DATA_MAX {
                    return Err(Status::BadSize);
                }
                Ok(Request::Send {
                    key,
                    description,
                    flags,
                    address,
                    data: b.bytes(left)?,
                })
            })(),
            Method::Recv | Method::RecvTake => (|| {
                let key = get_key(b, take)?;
                let description = b.u32()?;
                let flags = b.u32()?;
                let most = b.u32()?;
                if flags & BUF != 0 {
                    let offset = b.u32()?;
                    if !(1..=SLOT as u32).contains(&most) {
                        return Err(Status::BadSize);
                    }
                    return Ok(Request::RecvCell {
                        key,
                        description,
                        flags: flags & !BUF,
                        most,
                        offset,
                    });
                }
                if !(1..=DATA_MAX as u32).contains(&most) {
                    return Err(Status::BadSize);
                }
                Ok(Request::Recv {
                    key,
                    description,
                    flags,
                    most,
                })
            })(),
            Method::Shutdown => (|| {
                Ok(Request::Shutdown {
                    description: b.u32()?,
                    how: b.u32()?,
                })
            })(),
            Method::Close => (|| {
                Ok(Request::Close {
                    description: b.u32()?,
                    linger: b.u32()?,
                })
            })(),
            Method::CloseTake => (|| match b.u64()? {
                0 => Err(Status::BadSize),
                key => Ok(Request::CloseTake(key)),
            })(),
            Method::Export => (|| {
                Ok(Request::Export {
                    description: b.u32()?,
                })
            })(),
            Method::Adopt => Ok(Request::Adopt),
            Method::GetOpt => (|| {
                Ok(Request::GetOpt {
                    description: b.u32()?,
                    name: b.u32()?,
                })
            })(),
            Method::SetOpt => (|| {
                Ok(Request::SetOpt {
                    description: b.u32()?,
                    name: b.u32()?,
                    value: b.u32()?,
                })
            })(),
            Method::Name => (|| {
                Ok(Request::Name {
                    description: b.u32()?,
                    which: b.u32()?,
                })
            })(),
            Method::Watch => return Some(watch::Set::parse(body).map(Request::Watch)),
            Method::WatchTake => return Some(watch::key(body).map(Request::WatchTake)),
            Method::WatchCancel => return Some(watch::key(body).map(Request::WatchCancel)),
            Method::Cancel => return Some(watch::key(body).map(Request::Cancel)),
            Method::Abandon => Ok(Request::Abandon),
            Method::Clone => (|| {
                let count = b.u32()? as usize;
                if count > CLONE_MAX {
                    return Err(Status::BadSize);
                }
                let mut list = List {
                    len: count,
                    items: [0; CLONE_MAX],
                };
                for item in &mut list.items[..count] {
                    *item = b.u32()?;
                }
                Ok(Request::Clone(list))
            })(),
            Method::CloneMore => (|| {
                let birth = b.u32()?;
                let count = b.u32()? as usize;
                if !(1..=CLONE_MAX).contains(&count) {
                    return Err(Status::BadSize);
                }
                let mut list = List {
                    len: count,
                    items: [0; CLONE_MAX],
                };
                for item in &mut list.items[..count] {
                    *item = b.u32()?;
                }
                Ok(Request::CloneMore { birth, list })
            })(),
            Method::EpollSet => (|| {
                let set = b.u32()?;
                let count = b.u32()? as usize;
                if count > EPOLL_BATCH {
                    return Err(Status::BadSize);
                }
                let mut list = EpollList {
                    len: count,
                    records: [EpollRecord::default(); EPOLL_BATCH],
                };
                for record in &mut list.records[..count] {
                    *record = EpollRecord {
                        action: b.u32()?,
                        description: b.u32()?,
                        events: b.u32()?,
                        label: b.u32()?,
                    };
                }
                Ok(Request::EpollSet { set, list })
            })(),
            Method::EpollDrop => (|| Ok(Request::EpollDrop(b.u32()?)))(),
            Method::EpollWait | Method::EpollWaitTake => (|| {
                let key = get_key(b, method == Method::EpollWaitTake)?;
                let set = b.u32()?;
                let most = b.u32()?;
                let flags = b.u32()?;
                if !(1..=EPOLL_MOST as u32).contains(&most) || flags & !EPOLL_DONTWAIT != 0 {
                    return Err(Status::BadSize);
                }
                Ok(Request::EpollWait {
                    key,
                    set,
                    most,
                    flags,
                })
            })(),
            _ => return None,
        };
        Some(match request {
            Ok(request) => body.finish().map(|()| request),
            Err(status) => Err(status),
        })
    }
}

fn put_key(w: &mut Writer, key: Option<u64>) -> Result<(), Status> {
    match key {
        Some(key) => w.u64(key),
        None => Ok(()),
    }
}

/// The key of a take: not 0.
fn get_key(r: &mut Reader<'_>, take: bool) -> Result<Option<u64>, Status> {
    if !take {
        return Ok(None);
    }
    match r.u64()? {
        0 => Err(Status::BadSize),
        key => Ok(Some(key)),
    }
}

/// A reply of status 0 and one word: SOCKET's description, GETOPT's value.
pub fn write_word(w: &mut Writer, word: u32) -> Result<(), Status> {
    w.u32(Status::Ok.code())?;
    w.u32(word)
}

/// The word of a reply of `write_word`; a refusal is the error.
pub fn read_word(reply: &[u8]) -> Result<u32, Status> {
    let mut r = Reader::new(reply);
    match Status::from_code(r.u32()?) {
        Status::Ok => {}
        status => return Err(status),
    }
    let word = r.u32()?;
    r.finish()?;
    Ok(word)
}

/// NAME's reply: status 0 and the address.
pub fn write_name(w: &mut Writer, address: &Address) -> Result<(), Status> {
    w.u32(Status::Ok.code())?;
    address.write(w)
}

pub fn read_name(reply: &[u8]) -> Result<Address, Status> {
    let mut r = Reader::new(reply);
    match Status::from_code(r.u32()?) {
        Status::Ok => {}
        status => return Err(status),
    }
    let address = Address::read(&mut r)?;
    r.finish()?;
    Ok(address)
}

/// The data of READY for CONNECT: none. For ACCEPT: the new description
/// and the peer's address.
pub fn write_accepted(w: &mut Writer, description: u32, peer: &Address) -> Result<(), Status> {
    w.u32(description)?;
    peer.write(w)
}

/// The reply of ADOPT: the description and its kind.
pub fn write_adopted(w: &mut Writer, description: u32, kind: u32) -> Result<(), Status> {
    w.u32(Status::Ok.code())?;
    w.u32(description)?;
    w.u32(kind)
}

/// The description and the kind of an ADOPT reply.
pub fn read_adopted(reply: &[u8]) -> Result<(u32, u32), Status> {
    let mut r = Reader::new(reply);
    match Status::from_code(r.u32()?) {
        Status::Ok => {}
        status => return Err(status),
    }
    let description = r.u32()?;
    let kind = r.u32()?;
    r.finish()?;
    Ok((description, kind))
}

pub fn read_accepted(data: &[u8]) -> Result<(u32, Address), Status> {
    let mut r = Reader::new(data);
    let description = r.u32()?;
    let peer = Address::read(&mut r)?;
    r.finish()?;
    Ok((description, peer))
}

/// The data of READY for SEND: the bytes taken.
pub fn read_sent(data: &[u8]) -> Result<u32, Status> {
    let mut r = Reader::new(data);
    let n = r.u32()?;
    r.finish()?;
    Ok(n)
}

/// The data of READY for RECV: the flags (`OUT_TRUNC`), the sender's
/// address and the bytes.
pub fn write_received(
    w: &mut Writer,
    flags: u32,
    from: &Address,
    bytes: &[u8],
) -> Result<(), Status> {
    w.u32(flags)?;
    from.write(w)?;
    w.bytes(bytes)
}

/// The data of READY for RECV with `BUF`: the flags, the sender's address
/// and the count of the bytes the service put into the cell.
pub fn write_received_count(
    w: &mut Writer,
    flags: u32,
    from: &Address,
    count: u32,
) -> Result<(), Status> {
    w.u32(flags)?;
    from.write(w)?;
    w.u32(count)
}

/// The flags, the sender and the count of a READY of RECV with `BUF`; a
/// count past `most` is BAD_SIZE.
pub fn read_received_count(data: &[u8], most: u32) -> Result<(u32, Address, u32), Status> {
    let mut r = Reader::new(data);
    let flags = r.u32()?;
    let from = Address::read(&mut r)?;
    let count = r.u32()?;
    r.finish()?;
    if count > most || flags & !OUT_TRUNC != 0 {
        return Err(Status::BadSize);
    }
    Ok((flags, from, count))
}

pub fn read_received(data: &[u8]) -> Result<(u32, Address, &[u8]), Status> {
    let mut r = Reader::new(data);
    let flags = r.u32()?;
    let from = Address::read(&mut r)?;
    let left = r.left();
    let bytes = r.bytes(left)?;
    if bytes.len() > DATA_MAX || flags & !OUT_TRUNC != 0 {
        return Err(Status::BadSize);
    }
    Ok((flags, from, bytes))
}

/// CLONE's reply: status 0 and the word of the birth (`birth_word`), which
/// CLONE_MORE names; the session comes as a handle.
pub fn write_cloned(w: &mut Writer, birth: u32) -> Result<(), Status> {
    write_word(w, birth)
}

/// The word of the birth of a clone made at place `place` of the service's
/// table with the generation `generation` (the low 16 bits of each): the
/// number CLONE_MORE names it by.
pub const fn birth_word(place: usize, generation: u64) -> u32 {
    (place as u32 & 0xFFFF) | ((generation as u32 & 0xFFFF) << 16)
}

/// The reply of ABANDON: status 0 and how many of the session's long
/// operations are left; the caller asks again until it is 0.
pub fn write_abandoned(w: &mut Writer, left: u32) -> Result<(), Status> {
    write_word(w, left)
}

/// The operations left in an ABANDON reply.
pub fn read_abandoned(reply: &[u8]) -> Result<u32, Status> {
    read_word(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::MESSAGE_MAX;

    fn address() -> Address {
        Address::v4([10, 0, 2, 15], 8080)
    }

    fn set() -> watch::Set {
        let mut set = watch::Set::new();
        set.len = 2;
        set.items[0] = watch::Item {
            description: 5,
            events: watch::IN,
        };
        set.items[1] = watch::Item {
            description: 6,
            events: watch::OUT | watch::IN,
        };
        set
    }

    fn samples(data: &[u8]) -> Vec<Request<'_>> {
        vec![
            Request::Socket {
                family: crate::INET,
                kind: STREAM,
                flags: NONBLOCK,
            },
            Request::Bind {
                description: 1,
                address: address(),
            },
            Request::Listen {
                description: 1,
                backlog: 9,
            },
            Request::Connect {
                key: None,
                description: 2,
                address: address(),
            },
            Request::Connect {
                key: Some(7),
                description: 2,
                address: address(),
            },
            Request::Accept {
                key: None,
                description: 3,
                flags: NONBLOCK,
            },
            Request::Accept {
                key: Some(1 << 33),
                description: 3,
                flags: 0,
            },
            Request::Send {
                key: None,
                description: 4,
                flags: DONTWAIT,
                address: Address::NONE,
                data,
            },
            Request::Send {
                key: Some(9),
                description: 4,
                flags: 0,
                address: address(),
                data: &[],
            },
            Request::Recv {
                key: None,
                description: 4,
                flags: PEEK,
                most: 800,
            },
            Request::Recv {
                key: Some(3),
                description: 4,
                flags: 0,
                most: 1,
            },
            Request::SendCell {
                key: None,
                description: 4,
                flags: DONTWAIT,
                address: Address::NONE,
                offset: 0,
                len: SLOT as u32,
            },
            Request::SendCell {
                key: Some(10),
                description: 4,
                flags: 0,
                address: Address::NONE,
                offset: (15 * SLOT) as u32,
                len: 1,
            },
            Request::RecvCell {
                key: None,
                description: 4,
                flags: PEEK,
                most: SLOT as u32,
                offset: SLOT as u32,
            },
            Request::RecvCell {
                key: Some(4),
                description: 4,
                flags: DONTWAIT,
                most: 1,
                offset: 0,
            },
            Request::Shutdown {
                description: 4,
                how: SHUT_BOTH,
            },
            Request::Close {
                description: 4,
                linger: 0,
            },
            Request::Close {
                description: 4,
                linger: CLOSE_MAY_WAIT,
            },
            Request::CloseTake(14),
            Request::Export { description: 4 },
            Request::Adopt,
            Request::GetOpt {
                description: 4,
                name: opt::ERROR,
            },
            Request::SetOpt {
                description: 4,
                name: opt::NODELAY,
                value: 1,
            },
            Request::Name {
                description: 4,
                which: PEER_NAME,
            },
            Request::Watch(set()),
            Request::WatchTake(11),
            Request::WatchCancel(12),
            Request::Abandon,
            Request::Clone(List::new(&[]).unwrap()),
            Request::Clone(List::new(&[1, 2, 3 | 1 << 12]).unwrap()),
            Request::CloneMore {
                birth: 0x0005_0003,
                list: List::new(&[1, 2, 3 | 1 << 12]).unwrap(),
            },
            Request::Cancel(13),
            Request::EpollSet {
                set: 0,
                list: EpollList::new(&[]).unwrap(),
            },
            Request::EpollSet {
                set: 3 | 2 << 8,
                list: EpollList::new(&[
                    EpollRecord {
                        action: EPOLL_ADD,
                        description: 5,
                        events: epoll::IN | epoll::ET,
                        label: 0x0001_0007,
                    },
                    EpollRecord {
                        action: EPOLL_DEL,
                        description: 6,
                        events: 0,
                        label: 0,
                    },
                ])
                .unwrap(),
            },
            Request::EpollDrop(3 | 2 << 8),
            Request::EpollWait {
                key: None,
                set: 1,
                most: 64,
                flags: 0,
            },
            Request::EpollWait {
                key: Some(5),
                set: 1,
                most: 1,
                flags: EPOLL_DONTWAIT,
            },
        ]
    }

    fn written(request: &Request<'_>) -> Vec<u8> {
        let mut w = Writer::new();
        request.write(&mut w).unwrap();
        w.as_bytes().to_vec()
    }

    fn parsed(bytes: &[u8]) -> Result<Request<'_>, Status> {
        let mut r = Reader::new(bytes);
        let header = proto_wire::Header::read(&mut r)?;
        crate::check_version(header)?;
        let method = Method::from_number(header.method).ok_or(Status::UnknownMethod)?;
        Request::parse(method, r).ok_or(Status::UnknownMethod)?
    }

    #[test]
    fn every_request_round_trips() {
        let data = [7u8; 100];
        for request in samples(&data) {
            let bytes = written(&request);
            assert_eq!(parsed(&bytes), Ok(request), "{request:?}");
        }
    }

    #[test]
    fn a_body_of_the_wrong_length_is_refused() {
        let data = [7u8; 100];
        for request in samples(&data) {
            let bytes = written(&request);
            if matches!(request, Request::Abandon) {
                continue;
            }
            // Data at the end of SEND has any length, so only its fixed
            // fields are cut there.
            let fixed = match request {
                Request::Send { data, .. } => bytes.len() - data.len(),
                _ => bytes.len(),
            };
            assert_eq!(
                parsed(&bytes[..fixed - 1]),
                Err(Status::BadSize),
                "short {request:?}"
            );
            if !matches!(request, Request::Send { .. }) {
                let mut long = bytes.clone();
                long.push(0);
                assert_eq!(parsed(&long), Err(Status::BadSize), "long {request:?}");
            }
        }
        let bytes = written(&Request::Abandon);
        let mut long = bytes;
        long.push(0);
        assert_eq!(parsed(&long), Err(Status::BadSize));
    }

    #[test]
    fn a_cell_carries_no_bytes_and_asks_for_one_to_a_slot() {
        let cell = Request::SendCell {
            key: None,
            description: 1,
            flags: 0,
            address: Address::NONE,
            offset: 0,
            len: 1,
        };
        let bytes = written(&cell);
        assert_eq!(bytes.len(), 8 + 4 + 4 + 24 + 4 + 4);
        assert_eq!(u32::from_le_bytes(bytes[12..16].try_into().unwrap()), BUF);
        for len in [0, SLOT as u32 + 1] {
            let wrong = Request::SendCell {
                key: None,
                description: 1,
                flags: 0,
                address: Address::NONE,
                offset: 0,
                len,
            };
            assert_eq!(parsed(&written(&wrong)), Err(Status::BadSize), "{len}");
        }
        let recv = Request::RecvCell {
            key: None,
            description: 1,
            flags: 0,
            most: SLOT as u32,
            offset: 0,
        };
        assert_eq!(parsed(&written(&recv)), Ok(recv));
        for most in [0, SLOT as u32 + 1] {
            let wrong = Request::RecvCell {
                key: None,
                description: 1,
                flags: 0,
                most,
                offset: 0,
            };
            assert_eq!(parsed(&written(&wrong)), Err(Status::BadSize), "{most}");
        }
        // A RECV without BUF still asks for 800 at most.
        let plain = Request::Recv {
            key: None,
            description: 1,
            flags: 0,
            most: 801,
        };
        assert_eq!(parsed(&written(&plain)), Err(Status::BadSize));
        // The count of a reply with BUF is at most what was asked.
        let mut w = Writer::new();
        write_received_count(&mut w, 0, &address(), 100).unwrap();
        assert_eq!(
            read_received_count(w.as_bytes(), 100),
            Ok((0, address(), 100))
        );
        assert_eq!(read_received_count(w.as_bytes(), 99), Err(Status::BadSize));
        // The options of the buffers are new numbers.
        assert_eq!((opt::BUFFERS, opt::BUFFERED), (39, 40));
        assert_eq!((opt::HOME, opt::CALLS), (41, 42));
    }

    #[test]
    fn a_foreign_version_is_refused() {
        let mut bytes = written(&Request::Abandon);
        bytes[2] = 2;
        assert_eq!(parsed(&bytes), Err(Status::BadVersion));
    }

    #[test]
    fn data_of_the_limit_goes_and_one_more_does_not() {
        let data = [1u8; DATA_MAX];
        let request = Request::Send {
            key: Some(1),
            description: 1,
            flags: 0,
            address: address(),
            data: &data,
        };
        let bytes = written(&request);
        assert_eq!(bytes.len(), 8 + 8 + 4 + 4 + 24 + 800);
        assert_eq!(parsed(&bytes), Ok(request));
        let more = [1u8; DATA_MAX + 1];
        let request = Request::Send {
            key: Some(1),
            description: 1,
            flags: 0,
            address: address(),
            data: &more,
        };
        assert_eq!(parsed(&written(&request)), Err(Status::BadSize));
    }

    #[test]
    fn the_largest_messages_fit() {
        let data = [0u8; DATA_MAX];
        let longest = samples(&data)
            .iter()
            .map(|r| written(r).len())
            .max()
            .unwrap();
        assert!(longest <= MESSAGE_MAX);
        // RECV's reply: status, READY, flags, address, bytes.
        let mut w = Writer::new();
        proto_wire::long::Reply::Ready(&{
            let mut inner = Writer::new();
            write_received(&mut inner, OUT_TRUNC, &address(), &data).unwrap();
            inner.as_bytes().to_vec()
        })
        .write(&mut w)
        .unwrap();
        assert_eq!(w.as_bytes().len(), 4 + 4 + 4 + 24 + 800);
        assert!(w.as_bytes().len() <= MESSAGE_MAX);
        // CLONE with 64 descriptions.
        let list = List::new(&[1; CLONE_MAX]).unwrap();
        assert_eq!(written(&Request::Clone(list)).len(), 8 + 4 + 64 * 4);
        assert!(List::new(&[1; CLONE_MAX + 1]).is_none());
    }

    #[test]
    fn a_clone_of_too_many_descriptions_is_refused() {
        let mut bytes = written(&Request::Clone(List::new(&[]).unwrap()));
        bytes[8..12].copy_from_slice(&65u32.to_le_bytes());
        bytes.extend_from_slice(&[0; 65 * 4]);
        assert_eq!(parsed(&bytes), Err(Status::BadSize));
    }

    #[test]
    fn recv_asks_for_one_to_800_bytes_and_a_take_has_a_key() {
        for most in [0u32, 801] {
            let mut bytes = written(&Request::Recv {
                key: None,
                description: 1,
                flags: 0,
                most: 1,
            });
            let at = bytes.len() - 4;
            bytes[at..].copy_from_slice(&most.to_le_bytes());
            assert_eq!(parsed(&bytes), Err(Status::BadSize), "most {most}");
        }
        let mut bytes = written(&Request::Accept {
            key: Some(1),
            description: 1,
            flags: 0,
        });
        bytes[8..16].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(parsed(&bytes), Err(Status::BadSize));
    }

    #[test]
    fn clone_more_takes_one_to_sixty_four_descriptions() {
        let more = |count: usize| {
            let list = List {
                len: count,
                items: [7; CLONE_MAX],
            };
            written(&Request::CloneMore { birth: 9, list })
        };
        assert_eq!(more(64).len(), 8 + 8 + 64 * 4);
        let mut empty = more(1);
        empty.truncate(8 + 8);
        empty[12..16].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(parsed(&empty), Err(Status::BadSize), "no descriptions");
        let mut many = more(1);
        many[12..16].copy_from_slice(&65u32.to_le_bytes());
        assert_eq!(parsed(&many), Err(Status::BadSize), "65 descriptions");
    }

    #[test]
    fn the_replies_of_clone_and_abandon_carry_a_word() {
        let mut w = Writer::new();
        write_cloned(&mut w, birth_word(0x1_0002, 0x7_0003)).unwrap();
        assert_eq!(read_word(w.as_bytes()), Ok(0x0003_0002));
        let mut w = Writer::new();
        write_abandoned(&mut w, 4).unwrap();
        assert_eq!(read_abandoned(w.as_bytes()), Ok(4));
    }

    #[test]
    fn epoll_requests_and_replies_fit_and_round_trip() {
        let full = EpollList::new(&[EpollRecord::default(); EPOLL_BATCH]).unwrap();
        let bytes = written(&Request::EpollSet { set: 1, list: full });
        assert_eq!(bytes.len(), 8 + 8 + EPOLL_BATCH * 16);
        assert!(bytes.len() <= MESSAGE_MAX);
        assert!(EpollList::new(&[EpollRecord::default(); EPOLL_BATCH + 1]).is_none());
        // One record more than a batch is a bad size.
        let mut over = written(&Request::EpollSet {
            set: 1,
            list: EpollList::new(&[]).unwrap(),
        });
        over[12..16].copy_from_slice(&(EPOLL_BATCH as u32 + 1).to_le_bytes());
        over.extend_from_slice(&[0; (EPOLL_BATCH + 1) * 16]);
        assert_eq!(parsed(&over), Err(Status::BadSize));
        // The most pairs of a wait are one to 64, and the flags only DONTWAIT.
        for (most, flags) in [(0u32, 0u32), (65, 0), (1, 1), (1, 4)] {
            let mut bytes = written(&Request::EpollWait {
                key: None,
                set: 1,
                most: 1,
                flags: 0,
            });
            let at = bytes.len() - 8;
            bytes[at..at + 4].copy_from_slice(&most.to_le_bytes());
            bytes[at + 4..].copy_from_slice(&flags.to_le_bytes());
            assert_eq!(parsed(&bytes), Err(Status::BadSize), "{most} {flags}");
        }
        // The longest reply: 64 pairs in a READY.
        let mut ready = EpollReady::EMPTY;
        for k in 0..EPOLL_MOST as u32 {
            assert!(ready.push(k, epoll::IN));
        }
        assert!(!ready.push(0, 0));
        let mut inner = Writer::new();
        ready.write(&mut inner).unwrap();
        assert_eq!(EpollReady::parse(inner.as_bytes()), Ok(ready));
        let mut w = Writer::new();
        proto_wire::long::Reply::Ready(inner.as_bytes())
            .write(&mut w)
            .unwrap();
        assert_eq!(w.as_bytes().len(), 4 + 4 + 4 + 64 * 8);
        assert!(w.as_bytes().len() <= MESSAGE_MAX);
        let mut cut = inner.as_bytes().to_vec();
        cut.pop();
        assert_eq!(EpollReady::parse(&cut), Err(Status::BadSize));
        let mut w = Writer::new();
        write_epoll_set(&mut w, 9, &[0, crate::EXISTS]).unwrap();
        let mut statuses = [0; 2];
        assert_eq!(read_epoll_set(w.as_bytes(), 2, &mut statuses), Ok(9));
        assert_eq!(statuses, [0, crate::EXISTS]);
        assert!(read_epoll_set(w.as_bytes(), 1, &mut statuses).is_err());
    }

    #[test]
    fn the_methods_of_other_kinds_are_not_sockets() {
        assert!(Request::parse(Method::Config, Reader::new(&[])).is_none());
        // CLONE_MORE is a sockets' method now: a short body is a bad size.
        assert!(matches!(
            Request::parse(Method::CloneMore, Reader::new(&[])),
            Some(Err(_))
        ));
        assert!(Request::parse(Method::Ping, Reader::new(&[])).is_none());
    }

    #[test]
    fn descriptions_hold_the_place_and_the_generation() {
        let d = description(4095, 0xfffff);
        assert_eq!(d, u32::MAX);
        assert_eq!(slot(d), 4095);
        assert_eq!(generation(d), 0xfffff);
        assert_eq!(slot(description(7, 3)), 7);
        assert_eq!(generation(description(7, 3)), 3);
        // The place table of the service has 256 places, far below 4096.
        assert!(slot(description(255, 1)) < 1 << SLOT_BITS);
    }

    #[test]
    fn replies_round_trip() {
        let mut w = Writer::new();
        write_word(&mut w, 42).unwrap();
        assert_eq!(read_word(w.as_bytes()), Ok(42));
        assert_eq!(
            read_word(&proto_wire::reply(crate::code(crate::BAD_FD))),
            Err(crate::code(crate::BAD_FD))
        );
        let mut w = Writer::new();
        write_name(&mut w, &address()).unwrap();
        assert_eq!(read_name(w.as_bytes()), Ok(address()));
        let mut w = Writer::new();
        write_accepted(&mut w, 9, &address()).unwrap();
        assert_eq!(read_accepted(w.as_bytes()), Ok((9, address())));
        assert_eq!(read_sent(&5u32.to_le_bytes()), Ok(5));
        assert_eq!(read_sent(&[1, 0]), Err(Status::BadSize));
        let mut w = Writer::new();
        write_received(&mut w, 0, &address(), b"abc").unwrap();
        assert_eq!(read_received(w.as_bytes()), Ok((0, address(), &b"abc"[..])));
        let mut w = Writer::new();
        write_received(&mut w, 2, &address(), b"").unwrap();
        assert_eq!(read_received(w.as_bytes()), Err(Status::BadSize));
    }

    #[test]
    fn the_reply_of_adopt_carries_the_description_and_its_kind() {
        let mut w = Writer::new();
        write_adopted(&mut w, 5 | 3 << 12, DGRAM).unwrap();
        assert_eq!(read_adopted(w.as_bytes()), Ok((5 | 3 << 12, DGRAM)));
        let mut w = Writer::new();
        w.u32(crate::BAD_FD).unwrap();
        assert!(read_adopted(w.as_bytes()).is_err());
    }

    #[test]
    fn a_close_take_without_a_key_is_refused() {
        let mut w = Writer::new();
        w.u64(0).unwrap();
        let body = Reader::new(w.as_bytes());
        assert!(matches!(
            Request::parse(Method::CloseTake, body),
            Some(Err(Status::BadSize))
        ));
    }
}
