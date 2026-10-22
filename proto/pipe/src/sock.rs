// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Sockets of the pipe service. A socket is a description of the
//! service of a third kind, numbered `SOCK_END | slot`; the layer names it
//! like a pipe end (`Target::Pipe`), so read, write, close, dup, fork, exec,
//! fcntl and poll take the paths of the pipes. The calls only a socket has
//! are the methods SOCK_*.
//!
//! - SOCK_CREATE: body domain u32 (UNIX, INET), kind u32 (STREAM, DGRAM),
//!   flags u32 (NONBLOCK alone). Reply: status, the socket u32.
//!   SOCK_PAIR: the same body, UNIX only. Reply: status, two sockets.
//! - SOCK_BIND: body the socket, an address. SOCK_LISTEN: the socket, the
//!   backlog u32. SOCK_CONNECT: the socket, an address. SOCK_SHUTDOWN: the
//!   socket, how u32 (0 read, 1 write, 2 both). SOCK_NAME: the socket,
//!   which u32 (0 own, 1 peer); reply status and the address. SOCK_OPT: the
//!   socket, the option u32, set u32 (0 get, 1 set), the value u32; reply
//!   status and the value.
//! - SOCK_ACCEPT, SOCK_ACCEPT_TAKE (body k u64 first): the listening
//!   socket. A long operation (proto_wire::long); READY with the new socket
//!   u32 and the peer's address.
//! - SOCK_SEND, SOCK_SEND_TAKE: the socket, flags u32, the count of
//!   descriptions u32 and each one u32, an address (NONE for the connected
//!   peer), then the bytes. READY with the count u32 sent.
//! - SOCK_RECV, SOCK_RECV_TAKE: the socket, flags u32, the most bytes u32,
//!   the most descriptions u32. READY with the flags of the message u32
//!   (OUT_TRUNC, OUT_CTRUNC), the count of descriptions u32 and each one
//!   u32, the sender's address, then the bytes.
//!
//! An address is kind u32 (NONE, INET, UNIX), port u32, the file node u64,
//! the length of the path u32 and the path (at most NAME_MAX bytes).

use proto_wire::{Reader, Status, Writer};

/// A socket's description number: `SOCK_END | slot`.
pub const SOCK_END: u32 = 1 << 30;
/// The sockets of the service.
pub const SOCKETS: usize = 40;
/// The bytes of a socket's receive buffer (SO_RCVBUF, SO_SNDBUF).
pub const RING: usize = 4096;
/// The most bytes one send carries, and so the largest datagram.
pub const SEND_MAX: usize = 800;
/// The most descriptions one message carries.
pub const FDS_MAX: usize = 8;
/// The most bytes of a path in an address (sun_path).
pub const NAME_MAX: usize = 108;
/// The sockets that wait for an accept at one listener at most.
pub const BACKLOG_MAX: usize = 4;

pub const UNIX: u32 = 1;
pub const INET: u32 = 2;
pub const STREAM: u32 = 1;
pub const DGRAM: u32 = 2;

/// Flags of a send or receive (the layer maps MSG_* to them).
pub const PEEK: u32 = 1;
pub const DONTWAIT: u32 = 2;
/// The last byte of a send is out of band; a receive takes that byte.
pub const OOB: u32 = 4;
/// Flags of a received message.
pub const OUT_TRUNC: u32 = 1;
pub const OUT_CTRUNC: u32 = 2;

pub const OPT_REUSEADDR: u32 = 1;
pub const OPT_TYPE: u32 = 2;
pub const OPT_ERROR: u32 = 3;
pub const OPT_RCVBUF: u32 = 4;
pub const OPT_SNDBUF: u32 = 5;
pub const OPT_ACCEPTCONN: u32 = 6;
pub const OPT_DOMAIN: u32 = 7;
pub const OPT_KEEPALIVE: u32 = 8;
pub const OPT_BROADCAST: u32 = 9;
/// Whether the next byte to read is the mark of a pending out-of-band byte.
pub const OPT_ATMARK: u32 = 10;

/// EADDRINUSE.
pub const IN_USE: u32 = 708;
/// ENOTCONN.
pub const NOT_CONNECTED: u32 = 709;
/// EISCONN.
pub const CONNECTED: u32 = 710;
/// ECONNREFUSED.
pub const REFUSED: u32 = 711;
/// EDESTADDRREQ.
pub const NO_DESTINATION: u32 = 712;
/// EPROTOTYPE.
pub const BAD_TYPE: u32 = 713;
/// EOPNOTSUPP.
pub const NOT_SUPPORTED: u32 = 714;
/// EADDRNOTAVAIL.
pub const NO_ADDRESS: u32 = 715;
/// EMSGSIZE.
pub const TOO_BIG: u32 = 716;
/// ENOBUFS.
pub const NO_BUFFERS: u32 = 717;
/// ENOPROTOOPT.
pub const NO_OPTION: u32 = 718;
/// ENOTSOCK.
pub const NOT_SOCKET: u32 = 719;
/// ENETUNREACH.
pub const UNREACHABLE: u32 = 720;
/// EAFNOSUPPORT.
pub const NO_FAMILY: u32 = 721;
/// ETOOMANYREFS: a send that would make a cycle of descriptions in flight.
pub const TOO_MANY_REFS: u32 = 722;

pub const ADDR_NONE: u32 = 0;
pub const ADDR_INET: u32 = 1;
pub const ADDR_UNIX: u32 = 2;

/// An address of a socket: a port of the loopback (INET) or a file node and
/// its path (UNIX).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Addr {
    pub kind: u32,
    pub port: u16,
    pub node: u64,
    pub len: u8,
    pub name: [u8; NAME_MAX],
}

/// The longest address on the wire.
pub const ADDR_MAX: usize = 20 + NAME_MAX;

impl Addr {
    pub const NONE: Addr = Addr {
        kind: ADDR_NONE,
        port: 0,
        node: 0,
        len: 0,
        name: [0; NAME_MAX],
    };

    pub const fn inet(port: u16) -> Addr {
        Addr {
            kind: ADDR_INET,
            port,
            ..Addr::NONE
        }
    }

    pub fn unix(node: u64, path: &[u8]) -> Option<Addr> {
        if path.len() > NAME_MAX {
            return None;
        }
        let mut a = Addr {
            kind: ADDR_UNIX,
            node,
            len: path.len() as u8,
            ..Addr::NONE
        };
        a.name[..path.len()].copy_from_slice(path);
        Some(a)
    }

    pub fn path(&self) -> &[u8] {
        &self.name[..usize::from(self.len)]
    }

    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.kind)?;
        w.u32(u32::from(self.port))?;
        w.u64(self.node)?;
        w.u32(u32::from(self.len))?;
        w.bytes(self.path())
    }

    pub fn read(r: &mut Reader<'_>) -> Result<Addr, Status> {
        let kind = r.u32()?;
        let port = r.u32()?;
        let node = r.u64()?;
        let len = r.u32()? as usize;
        if kind > ADDR_UNIX || port > 0xffff || len > NAME_MAX {
            return Err(Status::BadSize);
        }
        let mut a = Addr {
            kind,
            port: port as u16,
            node,
            len: len as u8,
            ..Addr::NONE
        };
        a.name[..len].copy_from_slice(r.bytes(len)?);
        Ok(a)
    }
}

/// SOCK_SEND or SOCK_SEND_TAKE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Send<'a> {
    pub key: Option<u64>,
    pub end: u32,
    pub flags: u32,
    pub fds: [u32; FDS_MAX],
    pub nfds: usize,
    pub to: Addr,
    pub bytes: &'a [u8],
}

impl<'a> Send<'a> {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        if self.bytes.len() > SEND_MAX || self.nfds > FDS_MAX || self.key == Some(0) {
            return Err(Status::BadSize);
        }
        match self.key {
            None => crate::Method::SockSend.header().write(w)?,
            Some(key) => {
                crate::Method::SockSendTake.header().write(w)?;
                w.u64(key)?;
            }
        }
        w.u32(self.end)?;
        w.u32(self.flags)?;
        w.u32(self.nfds as u32)?;
        for &fd in &self.fds[..self.nfds] {
            w.u32(fd)?;
        }
        self.to.write(w)?;
        w.bytes(self.bytes)
    }

    pub fn parse(mut body: Reader<'a>, take: bool) -> Result<Send<'a>, Status> {
        let key = if take { Some(body.u64()?) } else { None };
        let end = body.u32()?;
        let flags = body.u32()?;
        let nfds = body.u32()? as usize;
        if nfds > FDS_MAX || key == Some(0) || flags & !(PEEK | DONTWAIT | OOB) != 0 {
            return Err(Status::BadSize);
        }
        let mut fds = [0; FDS_MAX];
        for fd in &mut fds[..nfds] {
            *fd = body.u32()?;
        }
        let to = Addr::read(&mut body)?;
        let len = body.left();
        if len > SEND_MAX {
            return Err(Status::BadSize);
        }
        let bytes = body.bytes(len)?;
        Ok(Send {
            key,
            end,
            flags,
            fds,
            nfds,
            to,
            bytes,
        })
    }
}

/// SOCK_RECV or SOCK_RECV_TAKE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recv {
    pub key: Option<u64>,
    pub end: u32,
    pub flags: u32,
    pub count: u32,
    pub max_fds: u32,
}

impl Recv {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        if self.count as usize > SEND_MAX || self.max_fds as usize > FDS_MAX || self.key == Some(0)
        {
            return Err(Status::BadSize);
        }
        match self.key {
            None => crate::Method::SockRecv.header().write(w)?,
            Some(key) => {
                crate::Method::SockRecvTake.header().write(w)?;
                w.u64(key)?;
            }
        }
        w.u32(self.end)?;
        w.u32(self.flags)?;
        w.u32(self.count)?;
        w.u32(self.max_fds)
    }

    pub fn parse(mut body: Reader<'_>, take: bool) -> Result<Recv, Status> {
        let key = if take { Some(body.u64()?) } else { None };
        let r = Recv {
            key,
            end: body.u32()?,
            flags: body.u32()?,
            count: body.u32()?,
            max_fds: body.u32()?,
        };
        body.finish()?;
        if r.count as usize > SEND_MAX
            || r.max_fds as usize > FDS_MAX
            || key == Some(0)
            || r.flags & !(PEEK | DONTWAIT | OOB) != 0
        {
            return Err(Status::BadSize);
        }
        Ok(r)
    }
}

/// The result of a READY receive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Received<'a> {
    pub flags: u32,
    pub fds: [u32; FDS_MAX],
    pub nfds: usize,
    pub from: Addr,
    pub bytes: &'a [u8],
}

impl<'a> Received<'a> {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.flags)?;
        w.u32(self.nfds as u32)?;
        for &fd in &self.fds[..self.nfds] {
            w.u32(fd)?;
        }
        self.from.write(w)?;
        w.bytes(self.bytes)
    }

    pub fn parse(bytes: &'a [u8]) -> Result<Received<'a>, Status> {
        let mut r = Reader::new(bytes);
        let flags = r.u32()?;
        let nfds = r.u32()? as usize;
        if nfds > FDS_MAX {
            return Err(Status::BadSize);
        }
        let mut fds = [0; FDS_MAX];
        for fd in &mut fds[..nfds] {
            *fd = r.u32()?;
        }
        let from = Addr::read(&mut r)?;
        let left = r.left();
        Ok(Received {
            flags,
            fds,
            nfds,
            from,
            bytes: r.bytes(left)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Endpoint, Method};
    use proto_wire::HEADER_LEN;

    #[test]
    fn endpoints_of_sockets_are_a_kind_of_their_own() {
        let e = Endpoint::socket(39);
        assert!(e.is_sock() && !e.is_named());
        assert_eq!(e.slot(), 39);
        let mut w = Writer::new();
        e.write(&mut w).unwrap();
        assert_eq!(Endpoint::parse(&mut Reader::new(w.as_bytes())), Ok(e));
        let mut w = Writer::new();
        w.u32(SOCK_END | SOCKETS as u32).unwrap();
        assert_eq!(
            Endpoint::parse(&mut Reader::new(w.as_bytes())),
            Err(Status::BadSize)
        );
        let mut w = Writer::new();
        w.u32(SOCK_END | crate::NAMED_END | 1).unwrap();
        w.u64(1).unwrap();
        assert_eq!(
            Endpoint::parse(&mut Reader::new(w.as_bytes())),
            Err(Status::BadSize)
        );
    }

    #[test]
    fn addresses_round_trip() {
        for a in [
            Addr::NONE,
            Addr::inet(49152),
            Addr::unix(77, b"/tmp/x.sock").unwrap(),
            Addr::unix(1, &[b'a'; NAME_MAX]).unwrap(),
        ] {
            let mut w = Writer::new();
            a.write(&mut w).unwrap();
            assert!(w.as_bytes().len() <= ADDR_MAX);
            assert_eq!(Addr::read(&mut Reader::new(w.as_bytes())), Ok(a));
        }
        assert!(Addr::unix(1, &[0; NAME_MAX + 1]).is_none());
    }

    #[test]
    fn sends_and_receives_fit_a_message() {
        let bytes = [3u8; SEND_MAX];
        let send = Send {
            key: Some(9),
            end: SOCK_END | 3,
            flags: DONTWAIT,
            fds: [1, 2, 3, 4, 5, 6, 7, 8],
            nfds: FDS_MAX,
            to: Addr::unix(5, &[b'p'; NAME_MAX]).unwrap(),
            bytes: &bytes,
        };
        let mut w = Writer::new();
        send.write(&mut w).unwrap();
        assert!(w.as_bytes().len() <= abi::MESSAGE_MAX);
        assert_eq!(
            Send::parse(Reader::new(&w.as_bytes()[HEADER_LEN..]), true),
            Ok(send)
        );
        let recv = Recv {
            key: None,
            end: SOCK_END | 1,
            flags: PEEK,
            count: SEND_MAX as u32,
            max_fds: 8,
        };
        let mut w = Writer::new();
        recv.write(&mut w).unwrap();
        assert_eq!(
            Recv::parse(Reader::new(&w.as_bytes()[HEADER_LEN..]), false),
            Ok(recv)
        );
        let got = Received {
            flags: OUT_TRUNC,
            fds: [9; FDS_MAX],
            nfds: FDS_MAX,
            from: Addr::unix(5, &[b'p'; NAME_MAX]).unwrap(),
            bytes: &bytes,
        };
        let mut inner = Writer::new();
        got.write(&mut inner).unwrap();
        assert_eq!(Received::parse(inner.as_bytes()), Ok(got));
        let mut w = Writer::new();
        proto_wire::long::Reply::Ready(inner.as_bytes())
            .write(&mut w)
            .unwrap();
        assert!(w.as_bytes().len() <= abi::MESSAGE_MAX);
        assert_eq!(Method::SockSend.number(), 36);
    }
}
