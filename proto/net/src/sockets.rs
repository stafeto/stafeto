// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The requests and replies of the sockets' methods (the table in the
//! description of the crate). `Request::write` is the client's side and
//! `Request::parse` the service's; a body that is short, long or has a
//! field out of its range is BAD_SIZE.

use crate::{Address, DATA_MAX, Method};
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
    /// Reserved for a later stage (the bytes ready to read).
    pub const NREAD: u32 = 34;
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
    Shutdown {
        description: u32,
        how: u32,
    },
    Close {
        description: u32,
        linger: u32,
    },
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
    Cancel(u64),
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
            Request::Shutdown { .. } => Method::Shutdown,
            Request::Close { .. } => Method::Close,
            Request::GetOpt { .. } => Method::GetOpt,
            Request::SetOpt { .. } => Method::SetOpt,
            Request::Name { .. } => Method::Name,
            Request::Watch(_) => Method::Watch,
            Request::WatchTake(_) => Method::WatchTake,
            Request::WatchCancel(_) => Method::WatchCancel,
            Request::Abandon => Method::Abandon,
            Request::Clone(_) => Method::Clone,
            Request::Cancel(_) => Method::Cancel,
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

/// CLONE's reply: status 0 (the session comes as a handle).
pub fn write_ok(w: &mut Writer) -> Result<(), Status> {
    w.u32(Status::Ok.code())
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
            Request::Shutdown {
                description: 4,
                how: SHUT_BOTH,
            },
            Request::Close {
                description: 4,
                linger: 0,
            },
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
            Request::Cancel(13),
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
    fn the_methods_of_other_kinds_are_not_sockets() {
        assert!(Request::parse(Method::Config, Reader::new(&[])).is_none());
        assert!(Request::parse(Method::CloneMore, Reader::new(&[])).is_none());
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
}
