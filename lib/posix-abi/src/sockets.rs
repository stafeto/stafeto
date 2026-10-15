// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Sockets (Ф9; proto_pipe::sock): AF_UNIX and the loopback of AF_INET,
//! streams and datagrams. A socket is a description of the pipe service
//! that a descriptor names as a pipe end does (`Target::Pipe`, the number
//! with `SOCK_END`), so read, write, close, dup, fork, exec, fcntl and poll
//! take the paths of the pipes. The calls only a socket has go here: the
//! addresses of C become those of the protocol (a port, or the file node of
//! a path), and the calls that wait are long operations in two steps from
//! the calling thread (`long::run_with`), like a read of a pipe. A message
//! is gathered or spread by the caller, at most SEND_MAX bytes at a time.

use crate::constants::*;
use crate::long;
use crate::names::AT_FDCWD;
use crate::shared;
use posix_fs::{Target, Transport};
use proto_pipe::sock::{
    ADDR_INET, ADDR_NONE, ADDR_UNIX, Addr, DGRAM, DONTWAIT, FDS_MAX, INET, NAME_MAX, OOB,
    OPT_ACCEPTCONN, OPT_ATMARK, OPT_BROADCAST, OPT_DOMAIN, OPT_ERROR, OPT_KEEPALIVE, OPT_RCVBUF,
    OPT_REUSEADDR, OPT_SNDBUF, OPT_TYPE, OUT_CTRUNC, OUT_TRUNC, PEEK, Received, Recv, SEND_MAX,
    SOCK_END, STREAM, Send, UNIX,
};
use proto_pipe::{Endpoint, Method};
use proto_wire::{Reader, Status, Writer};
use rt::abi::MESSAGE_MAX;
use rt::handle::{Channel, Handle};

pub const AF_UNIX: i32 = 1;
pub const AF_INET: i32 = 2;
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;
/// relibc's values: Linux's.
pub const SOCK_NONBLOCK: i32 = 0o4000;
pub const SOCK_CLOEXEC: i32 = 0o2000000;
pub const SOL_SOCKET: i32 = 1;
pub const IPPROTO_TCP: i32 = 6;
pub const IPPROTO_UDP: i32 = 17;
pub const SO_REUSEADDR: i32 = 2;
pub const SO_TYPE: i32 = 3;
pub const SO_ERROR: i32 = 4;
pub const SO_BROADCAST: i32 = 6;
pub const SO_SNDBUF: i32 = 7;
pub const SO_RCVBUF: i32 = 8;
pub const SO_KEEPALIVE: i32 = 9;
pub const SO_ACCEPTCONN: i32 = 30;
pub const SO_DOMAIN: i32 = 39;
pub const TCP_NODELAY: i32 = 1;
pub const SCM_RIGHTS: i32 = 1;
pub const MSG_OOB: i32 = 1;
pub const MSG_PEEK: i32 = 2;
pub const MSG_CTRUNC: i32 = 8;
pub const MSG_TRUNC: i32 = 32;
pub const MSG_DONTWAIT: i32 = 64;
pub const MSG_EOR: i32 = 128;
pub const MSG_WAITALL: i32 = 256;
pub const MSG_NOSIGNAL: i32 = 0x4000;
pub const MSG_CMSG_CLOEXEC: i32 = 0x4000_0000;
pub const SHUT_RDWR: i32 = 2;

// Linux's numbers, relibc's.
const ENOTSOCK: i32 = 88;
const EDESTADDRREQ: i32 = 89;
const EMSGSIZE: i32 = 90;
const EPROTOTYPE: i32 = 91;
const ENOPROTOOPT: i32 = 92;
const EPROTONOSUPPORT: i32 = 93;
const EAFNOSUPPORT: i32 = 97;
const ETOOMANYREFS: i32 = 109;
const EADDRINUSE: i32 = 98;
const EADDRNOTAVAIL: i32 = 99;
const ENETUNREACH: i32 = 101;
const ENOBUFS: i32 = 105;
const EISCONN: i32 = 106;
const ENOTCONN: i32 = 107;
const ECONNREFUSED: i32 = 111;

/// The size of a `cmsghdr` (len, level, type) and of the alignment of data.
const CMSG_HEADER: usize = 16;

/// The errno of a refusal of the pipe service for a socket call.
pub(crate) fn refusal(status: Status) -> Option<i32> {
    Some(match status.code() {
        proto_pipe::BAD_FD => EBADF,
        proto_pipe::AGAIN => EAGAIN,
        proto_pipe::BROKEN => EPIPE,
        proto_pipe::NFILE => ENFILE,
        proto_pipe::MFILE => EMFILE,
        proto_pipe::INVALID => EINVAL,
        proto_pipe::sock::IN_USE => EADDRINUSE,
        proto_pipe::sock::NOT_CONNECTED => ENOTCONN,
        proto_pipe::sock::CONNECTED => EISCONN,
        proto_pipe::sock::REFUSED => ECONNREFUSED,
        proto_pipe::sock::NO_DESTINATION => EDESTADDRREQ,
        proto_pipe::sock::BAD_TYPE => EPROTOTYPE,
        proto_pipe::sock::NOT_SUPPORTED => EOPNOTSUPP,
        proto_pipe::sock::NO_ADDRESS => EADDRNOTAVAIL,
        proto_pipe::sock::TOO_BIG => EMSGSIZE,
        proto_pipe::sock::NO_BUFFERS => ENOBUFS,
        proto_pipe::sock::NO_OPTION => ENOPROTOOPT,
        proto_pipe::sock::NOT_SOCKET => ENOTSOCK,
        proto_pipe::sock::UNREACHABLE => ENETUNREACH,
        proto_pipe::sock::NO_FAMILY => EAFNOSUPPORT,
        proto_pipe::sock::TOO_MANY_REFS => ETOOMANYREFS,
        _ => return None,
    })
}

/// One request that answers at once, and the bytes of its reply after the
/// status.
#[inline(never)]
fn rpc(transport: Transport, request: &[u8], out: &mut [u8; MESSAGE_MAX]) -> Result<usize, i32> {
    let pipes = transport.pipes().map_err(crate::error)?;
    let reply = loop {
        match rt::sys::send(&pipes, request) {
            Err(rt::abi::Error::Interrupted) => continue,
            other => break other.map_err(|_| EIO)?,
        }
    };
    let bytes = reply.bytes(out);
    let len = bytes.len();
    let mut r = Reader::new(&out[..len]);
    match Status::from_code(r.u32().map_err(|_| EIO)?) {
        Status::Ok => {
            let left = r.left();
            out.copy_within(len - left..len, 0);
            Ok(left)
        }
        status => Err(refusal(status).unwrap_or(EIO)),
    }
}

/// The socket a descriptor names, as a held target: ENOTSOCK for another.
fn sock_end(target: Target) -> Result<u32, i32> {
    match target {
        Target::Pipe(id) if id & SOCK_END != 0 => Ok(id),
        _ => Err(ENOTSOCK),
    }
}

fn with_socket<R>(fd: i32, run: impl FnOnce(Transport, u32) -> Result<R, i32>) -> Result<R, i32> {
    let fd = u32::try_from(fd).map_err(|_| EBADF)?;
    shared::held(fd, |transport, target| run(transport, sock_end(target)?))
}

fn pipes_of(transport: Transport) -> Result<core::mem::ManuallyDrop<Handle<Channel>>, i32> {
    transport.pipes().map_err(crate::error)
}

fn endpoint(end: u32) -> Endpoint {
    Endpoint::socket(end & !SOCK_END)
}

fn simple(transport: Transport, method: Method, end: u32, words: &[u32]) -> Result<(), i32> {
    let mut w = Writer::new();
    method.header().write(&mut w).map_err(|_| EIO)?;
    endpoint(end).write(&mut w).map_err(|_| EIO)?;
    for &word in words {
        w.u32(word).map_err(|_| EIO)?;
    }
    rpc(transport, w.as_bytes(), &mut [0; MESSAGE_MAX]).map(drop)
}

fn option(transport: Transport, end: u32, option: u32, set: bool, value: u32) -> Result<u32, i32> {
    let mut w = Writer::new();
    Method::SockOpt.header().write(&mut w).map_err(|_| EIO)?;
    endpoint(end).write(&mut w).map_err(|_| EIO)?;
    for word in [option, u32::from(set), value] {
        w.u32(word).map_err(|_| EIO)?;
    }
    let mut out = [0; MESSAGE_MAX];
    let n = rpc(transport, w.as_bytes(), &mut out)?;
    Reader::new(&out[..n]).u32().map_err(|_| EIO)
}

fn descriptor_flags(flags: i32) -> posix_fs::DescriptorFlags {
    posix_fs::DescriptorFlags {
        close_on_exec: flags & SOCK_CLOEXEC != 0,
        close_on_fork: false,
    }
}

/// The type of `kind` without the flags of the creation, and the flags.
fn kind_of(kind: i32) -> Result<(u32, bool, bool), i32> {
    if kind & !(0xf | SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return Err(EINVAL);
    }
    let ty = match kind & 0xf {
        SOCK_STREAM => STREAM,
        SOCK_DGRAM => DGRAM,
        _ => return Err(EPROTOTYPE),
    };
    Ok((ty, kind & SOCK_NONBLOCK != 0, kind & SOCK_CLOEXEC != 0))
}

fn domain_of(domain: i32, protocol: i32, ty: u32) -> Result<u32, i32> {
    match domain {
        AF_UNIX if protocol == 0 => Ok(UNIX),
        AF_INET
            if protocol == 0
                || (protocol == IPPROTO_TCP && ty == STREAM)
                || (protocol == IPPROTO_UDP && ty == DGRAM) =>
        {
            Ok(INET)
        }
        AF_UNIX | AF_INET => Err(EPROTONOSUPPORT),
        _ => Err(EAFNOSUPPORT),
    }
}

fn create_request(method: Method, domain: u32, ty: u32, nonblock: bool) -> Writer {
    let mut w = Writer::new();
    let _ = method.header().write(&mut w);
    let _ = w.u32(domain);
    let _ = w.u32(ty);
    let _ = w.u32(if nonblock { proto_pipe::NONBLOCK } else { 0 });
    w
}

fn transport() -> Result<Transport, i32> {
    shared::with_files(|files| {
        files.pipes().ok_or(ENOSYS)?;
        Ok(files.transport())
    })
}

pub fn socket(domain: i32, kind: i32, protocol: i32) -> Result<i32, i32> {
    let (ty, nonblock, cloexec) = kind_of(kind)?;
    let domain = domain_of(domain, protocol, ty)?;
    let transport = transport()?;
    let request = create_request(Method::SockCreate, domain, ty, nonblock);
    let mut out = [0; MESSAGE_MAX];
    let n = rpc(transport, request.as_bytes(), &mut out)?;
    let id = Reader::new(&out[..n]).u32().map_err(|_| EIO)?;
    publish(transport, id, cloexec)
}

/// A descriptor for the socket `id`; the socket goes again on an error.
fn publish(transport: Transport, id: u32, cloexec: bool) -> Result<i32, i32> {
    let flags = descriptor_flags(if cloexec { SOCK_CLOEXEC } else { 0 });
    let inserted = shared::with_files(|files| {
        files
            .insert(Target::Pipe(id), flags)
            .map(|fd| fd as i32)
            .map_err(crate::error)
    });
    if inserted.is_err() {
        let _ = transport.release(Some(Target::Pipe(id)));
    }
    inserted
}

pub fn socketpair(domain: i32, kind: i32, protocol: i32) -> Result<[i32; 2], i32> {
    let (ty, nonblock, cloexec) = kind_of(kind)?;
    let domain = domain_of(domain, protocol, ty)?;
    if domain != UNIX {
        return Err(EOPNOTSUPP);
    }
    let transport = transport()?;
    let request = create_request(Method::SockPair, domain, ty, nonblock);
    let mut out = [0; MESSAGE_MAX];
    let n = rpc(transport, request.as_bytes(), &mut out)?;
    let mut r = Reader::new(&out[..n]);
    let (a, b) = (r.u32().map_err(|_| EIO)?, r.u32().map_err(|_| EIO)?);
    let first = match publish(transport, a, cloexec) {
        Ok(fd) => fd,
        Err(errno) => {
            let _ = transport.release(Some(Target::Pipe(b)));
            return Err(errno);
        }
    };
    match publish(transport, b, cloexec) {
        Ok(second) => Ok([first, second]),
        Err(errno) => {
            let _ = crate::close(first);
            Err(errno)
        }
    }
}

/// How an address of C is to be read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Use {
    Bind,
    Reach,
}

/// The address `raw` (a sockaddr_in or sockaddr_un) as the protocol has
/// it. A path is resolved here: `Bind` makes the node (`umask` is the
/// process's), `Reach` takes the node that is there.
fn wire_address(
    transport: Transport,
    end: u32,
    raw: &[u8],
    usage: Use,
    umask: u32,
) -> Result<(Addr, bool), i32> {
    if raw.len() < 2 {
        return Err(EINVAL);
    }
    let family = i32::from(u16::from_ne_bytes([raw[0], raw[1]]));
    match family {
        AF_INET => {
            if raw.len() < 8 {
                return Err(EINVAL);
            }
            if option(transport, end, OPT_DOMAIN, false, 0)? != INET {
                return Err(EAFNOSUPPORT);
            }
            let port = u16::from_be_bytes([raw[2], raw[3]]);
            let ip = [raw[4], raw[5], raw[6], raw[7]];
            if ip != [0; 4] && ip[0] != 127 {
                return Err(match usage {
                    Use::Bind => EADDRNOTAVAIL,
                    Use::Reach => ENETUNREACH,
                });
            }
            Ok((Addr::inet(port), false))
        }
        AF_UNIX => {
            if option(transport, end, OPT_DOMAIN, false, 0)? != UNIX {
                return Err(EAFNOSUPPORT);
            }
            let text = &raw[2..];
            let len = text.iter().position(|&b| b == 0).unwrap_or(text.len());
            let path = &text[..len];
            if path.is_empty() || path[0] == 0 {
                return Err(EINVAL);
            }
            if path.len() > NAME_MAX - 1 {
                return Err(ENAMETOOLONG);
            }
            match usage {
                Use::Bind => {
                    match crate::names::mksockat(AT_FDCWD, path, 0o777, umask) {
                        Ok(()) => {}
                        Err(EEXIST) => return Err(EADDRINUSE),
                        Err(errno) => return Err(errno),
                    }
                    let node = match crate::names::fstatat(AT_FDCWD, Some(path), 0) {
                        Ok(info) => info.inode,
                        Err(errno) => {
                            let _ = crate::names::unlinkat(AT_FDCWD, path, 0);
                            return Err(errno);
                        }
                    };
                    let addr = Addr::unix(node, path).ok_or(ENAMETOOLONG)?;
                    Ok((addr, true))
                }
                Use::Reach => {
                    let info = crate::names::fstatat(AT_FDCWD, Some(path), 0)?;
                    if info.kind != posix_fs::SOCKET {
                        return Err(ECONNREFUSED);
                    }
                    crate::names::faccessat(AT_FDCWD, path, 2, 0)?;
                    let addr = Addr::unix(info.inode, path).ok_or(ENAMETOOLONG)?;
                    Ok((addr, false))
                }
            }
        }
        _ => Err(EAFNOSUPPORT),
    }
}

/// The sockaddr of `addr` (of AF_INET when `inet`, else AF_UNIX) into
/// `out`: its true length.
fn c_address(addr: &Addr, inet: bool, out: &mut [u8]) -> usize {
    let mut full = [0u8; 2 + NAME_MAX + 1];
    let len = if addr.kind == ADDR_INET || (addr.kind == ADDR_NONE && inet) {
        full[..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
        full[2..4].copy_from_slice(&addr.port.to_be_bytes());
        if addr.kind == ADDR_INET {
            full[4..8].copy_from_slice(&[127, 0, 0, 1]);
        }
        16
    } else {
        full[..2].copy_from_slice(&(AF_UNIX as u16).to_ne_bytes());
        let path = addr.path();
        full[2..2 + path.len()].copy_from_slice(path);
        if addr.kind == ADDR_UNIX {
            2 + path.len() + 1
        } else {
            2
        }
    };
    let n = len.min(out.len());
    out[..n].copy_from_slice(&full[..n]);
    len
}

pub fn bind(fd: i32, raw: &[u8], umask: u32) -> Result<(), i32> {
    with_socket(fd, |transport, end| {
        let (addr, made) = wire_address(transport, end, raw, Use::Bind, umask)?;
        let mut w = Writer::new();
        Method::SockBind.header().write(&mut w).map_err(|_| EIO)?;
        endpoint(end).write(&mut w).map_err(|_| EIO)?;
        addr.write(&mut w).map_err(|_| EIO)?;
        let result = rpc(transport, w.as_bytes(), &mut [0; MESSAGE_MAX]).map(drop);
        if result.is_err() && made {
            let _ = crate::names::unlinkat(AT_FDCWD, addr.path(), 0);
        }
        result
    })
}

pub fn listen(fd: i32, backlog: i32) -> Result<(), i32> {
    with_socket(fd, |transport, end| {
        simple(transport, Method::SockListen, end, &[backlog.max(0) as u32])
    })
}

pub fn connect(fd: i32, raw: &[u8]) -> Result<(), i32> {
    let point = crate::threads::cancel::Point::begin();
    let result = with_socket(fd, |transport, end| {
        let (addr, _) = if raw.len() >= 2 && u16::from_ne_bytes([raw[0], raw[1]]) == 0 {
            (Addr::NONE, false)
        } else {
            wire_address(transport, end, raw, Use::Reach, 0)?
        };
        let mut w = Writer::new();
        Method::SockConnect
            .header()
            .write(&mut w)
            .map_err(|_| EIO)?;
        endpoint(end).write(&mut w).map_err(|_| EIO)?;
        addr.write(&mut w).map_err(|_| EIO)?;
        rpc(transport, w.as_bytes(), &mut [0; MESSAGE_MAX]).map(drop)
    });
    finish(point, &result);
    result
}

fn finish<T>(point: crate::threads::cancel::Point, result: &Result<T, i32>) {
    if result.is_ok() {
        point.end();
    } else {
        point.finish();
    }
}

fn cancel_request(method: Method, key: u64, end: Endpoint, w: &mut Writer) -> Result<(), Status> {
    method.header().write(w)?;
    w.u64(key)?;
    end.write(w)
}

/// ACCEPT: a descriptor for the next connection, with the peer's address
/// into `out` (its true length). `flags` are SOCK_NONBLOCK and SOCK_CLOEXEC.
pub fn accept(fd: i32, out: Option<&mut [u8]>, flags: i32) -> Result<(i32, usize), i32> {
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return Err(EINVAL);
    }
    let point = crate::threads::cancel::Point::begin();
    let result = with_socket(fd, |transport, end| {
        let pipes = pipes_of(transport)?;
        let e = endpoint(end);
        let mut start = Writer::new();
        Method::SockAccept
            .header()
            .write(&mut start)
            .map_err(|_| EIO)?;
        e.write(&mut start).map_err(|_| EIO)?;
        let mut reply = [0u8; MESSAGE_MAX];
        let n = long::run_with(
            &pipes,
            start.as_bytes(),
            |cancel, key, w| {
                if cancel {
                    cancel_request(Method::ReadCancel, key, e, w)
                } else {
                    Method::SockAcceptTake.header().write(w)?;
                    w.u64(key)?;
                    e.write(w)
                }
            },
            &mut reply,
            &refusal,
        )?;
        let mut r = Reader::new(&reply[..n]);
        let id = r.u32().map_err(|_| EIO)?;
        let peer = Addr::read(&mut r).map_err(|_| EIO)?;
        let inet = peer.kind == ADDR_INET
            || option(transport, end, OPT_DOMAIN, false, 0).is_ok_and(|d| d == INET);
        let new = publish(transport, id, flags & SOCK_CLOEXEC != 0)?;
        if flags & SOCK_NONBLOCK != 0 {
            let nb = crate::pipes::set_status_flags(transport, id, O_NONBLOCK);
            if let Err(errno) = nb {
                let _ = crate::close(new);
                return Err(errno);
            }
        }
        let len = out.map_or(0, |out| c_address(&peer, inet, out));
        Ok((new, len))
    });
    finish(point, &result);
    result
}

fn name(fd: i32, peer: bool, out: &mut [u8]) -> Result<usize, i32> {
    with_socket(fd, |transport, end| {
        let mut w = Writer::new();
        Method::SockName.header().write(&mut w).map_err(|_| EIO)?;
        endpoint(end).write(&mut w).map_err(|_| EIO)?;
        w.u32(u32::from(peer)).map_err(|_| EIO)?;
        let mut reply = [0; MESSAGE_MAX];
        let n = rpc(transport, w.as_bytes(), &mut reply)?;
        let addr = Addr::read(&mut Reader::new(&reply[..n])).map_err(|_| EIO)?;
        let inet = addr.kind == ADDR_INET
            || (addr.kind == ADDR_NONE
                && option(transport, end, OPT_DOMAIN, false, 0).is_ok_and(|d| d == INET));
        Ok(c_address(&addr, inet, out))
    })
}

pub fn getsockname(fd: i32, out: &mut [u8]) -> Result<usize, i32> {
    name(fd, false, out)
}

pub fn getpeername(fd: i32, out: &mut [u8]) -> Result<usize, i32> {
    name(fd, true, out)
}

/// The option of the protocol for an option of C: None for TCP_NODELAY,
/// which has no effect here and reads as 0.
fn option_number(level: i32, name: i32) -> Result<Option<u32>, i32> {
    if level == IPPROTO_TCP && name == TCP_NODELAY {
        return Ok(None);
    }
    if level != SOL_SOCKET {
        return Err(ENOPROTOOPT);
    }
    Ok(Some(match name {
        SO_REUSEADDR => OPT_REUSEADDR,
        SO_TYPE => OPT_TYPE,
        SO_ERROR => OPT_ERROR,
        SO_BROADCAST => OPT_BROADCAST,
        SO_SNDBUF => OPT_SNDBUF,
        SO_RCVBUF => OPT_RCVBUF,
        SO_KEEPALIVE => OPT_KEEPALIVE,
        SO_ACCEPTCONN => OPT_ACCEPTCONN,
        SO_DOMAIN => OPT_DOMAIN,
        _ => return Err(ENOPROTOOPT),
    }))
}

/// getsockopt: the int of the option into `out`; its true length, 4.
pub fn getsockopt(fd: i32, level: i32, name: i32, out: &mut [u8]) -> Result<usize, i32> {
    let number = option_number(level, name)?;
    with_socket(fd, |transport, end| {
        let value = match number {
            None => 0,
            Some(number) => option(transport, end, number, false, 0)?,
        };
        let bytes = value.to_ne_bytes();
        let n = out.len().min(4);
        out[..n].copy_from_slice(&bytes[..n]);
        Ok(4)
    })
}

pub fn setsockopt(fd: i32, level: i32, name: i32, value: &[u8]) -> Result<(), i32> {
    let number = option_number(level, name)?;
    if value.len() < 4 {
        return Err(EINVAL);
    }
    let word = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
    with_socket(fd, |transport, end| match number {
        None => Ok(()),
        Some(number) => option(transport, end, number, true, word).map(drop),
    })
}

pub fn shutdown(fd: i32, how: i32) -> Result<(), i32> {
    if !(0..=SHUT_RDWR).contains(&how) {
        return Err(EINVAL);
    }
    with_socket(fd, |transport, end| {
        simple(transport, Method::SockShutdown, end, &[how as u32])
    })
}

/// sockatmark: no socket has out-of-band data.
pub fn sockatmark(fd: i32) -> Result<i32, i32> {
    with_socket(fd, |transport, end| {
        option(transport, end, OPT_ATMARK, false, 0).map(|mark| mark as i32)
    })
}

fn wire_flags(flags: i32) -> Result<u32, i32> {
    if flags
        & !(MSG_PEEK
            | MSG_DONTWAIT
            | MSG_NOSIGNAL
            | MSG_EOR
            | MSG_WAITALL
            | MSG_CMSG_CLOEXEC
            | MSG_TRUNC
            | MSG_OOB)
        != 0
    {
        return Err(EOPNOTSUPP);
    }
    Ok(if flags & MSG_PEEK != 0 { PEEK } else { 0 }
        | if flags & MSG_DONTWAIT != 0 {
            DONTWAIT
        } else {
            0
        }
        | if flags & MSG_OOB != 0 { OOB } else { 0 })
}

/// The descriptions the SCM_RIGHTS messages of `control` carry: the numbers
/// of their service's descriptions. EOPNOTSUPP for another kind of message
/// or a descriptor that is no description of the pipe service.
fn rights(control: &[u8], ids: &mut [u32; FDS_MAX]) -> Result<usize, i32> {
    let mut at = 0;
    let mut count = 0;
    while control.len() - at >= CMSG_HEADER {
        let len = usize::from_ne_bytes(control[at..at + 8].try_into().unwrap());
        let level = i32::from_ne_bytes(control[at + 8..at + 12].try_into().unwrap());
        let ty = i32::from_ne_bytes(control[at + 12..at + 16].try_into().unwrap());
        if len < CMSG_HEADER || at + len > control.len() {
            return Err(EINVAL);
        }
        if level != SOL_SOCKET || ty != SCM_RIGHTS {
            return Err(EOPNOTSUPP);
        }
        for chunk in control[at + CMSG_HEADER..at + len].as_chunks::<4>().0 {
            let fd = i32::from_ne_bytes(*chunk);
            let fd = u32::try_from(fd).map_err(|_| EBADF)?;
            let target = shared::with_fd(fd, |files| files.target(fd).map_err(crate::error))?;
            let Target::Pipe(id) = target else {
                return Err(EOPNOTSUPP);
            };
            if count == FDS_MAX {
                return Err(EINVAL);
            }
            ids[count] = id;
            count += 1;
        }
        at += (len + 7) & !7;
    }
    Ok(count)
}

#[inline(never)]
fn send_once(
    pipes: &Handle<Channel>,
    end: u32,
    flags: u32,
    ids: &[u32],
    to: &Addr,
    bytes: &[u8],
) -> Result<usize, i32> {
    let e = endpoint(end);
    let mut fds = [0; FDS_MAX];
    fds[..ids.len()].copy_from_slice(ids);
    let message = |key| Send {
        key,
        end: e.id,
        flags,
        fds,
        nfds: ids.len(),
        to: *to,
        bytes,
    };
    let mut start = Writer::new();
    message(None).write(&mut start).map_err(|_| EIO)?;
    let mut result = [0; 4];
    let n = long::run_with(
        pipes,
        start.as_bytes(),
        |cancel, key, w| {
            if cancel {
                cancel_request(Method::WriteCancel, key, e, w)
            } else {
                message(Some(key)).write(w)
            }
        },
        &mut result,
        &refusal,
    )?;
    if n != 4 {
        return Err(EIO);
    }
    Ok(u32::from_le_bytes(result) as usize)
}

/// sendto and sendmsg: `data` (gathered by the caller, as much of the
/// message as it chose), the descriptions in `control`, the destination
/// `name` (or none). All the bytes go unless a signal, O_NONBLOCK or the end
/// of the reader stops a stream after some. EPIPE follows SIGPIPE unless
/// MSG_NOSIGNAL.
pub fn send(
    fd: i32,
    flags: i32,
    name: Option<&[u8]>,
    iov: &[&[u8]],
    control: &[u8],
) -> Result<usize, i32> {
    let size: usize = iov.iter().map(|part| part.len()).sum();
    let wire = wire_flags(flags)?;
    let point = crate::threads::cancel::Point::begin();
    let result = with_socket(fd, |transport, end| {
        let to = match name {
            Some(raw) if raw.len() >= 2 => wire_address(transport, end, raw, Use::Reach, 0)?.0,
            _ => Addr::NONE,
        };
        let mut ids = [0; FDS_MAX];
        let nfds = rights(control, &mut ids)?;
        let pipes = pipes_of(transport)?;
        let ty = option(transport, end, OPT_TYPE, false, 0)?;
        if ty == DGRAM {
            if size > SEND_MAX {
                return Err(EMSGSIZE);
            }
            let mut piece = [0u8; SEND_MAX];
            gather(iov, 0, &mut piece[..size]);
            return send_once(&pipes, end, wire, &ids[..nfds], &to, &piece[..size]);
        }
        let mut done = 0;
        let mut piece = [0u8; SEND_MAX];
        loop {
            let n = gather(iov, done, &mut piece);
            let with = if done == 0 { &ids[..nfds] } else { &[][..] };
            match send_once(&pipes, end, wire, with, &to, &piece[..n]) {
                // A short count goes on: the next call waits for room, or says
                // EAGAIN (a non-blocking socket), which ends the send with
                // the bytes that went.
                Ok(sent) => done += sent,
                Err(_) if done > 0 => break,
                Err(errno) => return Err(errno),
            }
            if done >= size {
                break;
            }
        }
        Ok(done)
    });
    if result == Err(EPIPE) && flags & MSG_NOSIGNAL == 0 {
        let _ = crate::signals::raise(SIGPIPE);
    }
    finish(point, &result);
    result
}

/// Up to `out.len()` bytes of `iov` from `offset` on, into `out`: how many.
fn gather(iov: &[&[u8]], offset: usize, out: &mut [u8]) -> usize {
    let (mut skip, mut put) = (offset, 0);
    for part in iov {
        if skip >= part.len() {
            skip -= part.len();
            continue;
        }
        let n = (part.len() - skip).min(out.len() - put);
        out[put..put + n].copy_from_slice(&part[skip..skip + n]);
        put += n;
        skip = 0;
        if put == out.len() {
            break;
        }
    }
    put
}

/// `bytes` into `iov` from `offset` on.
fn scatter(iov: &mut [&mut [u8]], offset: usize, bytes: &[u8]) {
    let (mut skip, mut at) = (offset, 0);
    for part in iov.iter_mut() {
        if skip >= part.len() {
            skip -= part.len();
            continue;
        }
        let n = (part.len() - skip).min(bytes.len() - at);
        part[skip..skip + n].copy_from_slice(&bytes[at..at + n]);
        at += n;
        skip = 0;
        if at == bytes.len() {
            break;
        }
    }
}

/// What recvmsg tells besides the bytes it put into `data`.
pub struct Message {
    pub count: usize,
    /// The sender's address into the caller's buffer: its true length.
    pub name_len: usize,
    /// MSG_TRUNC and MSG_CTRUNC.
    pub flags: i32,
    /// The bytes of control written.
    pub control_len: usize,
}

/// recvfrom and recvmsg: up to `data.len()` bytes (SEND_MAX at most per
/// call, except where MSG_WAITALL asks for more of a stream), the sender's
/// address into `name`, descriptions that came into `control` as a message.
pub fn recv(
    fd: i32,
    flags: i32,
    name: Option<&mut [u8]>,
    iov: &mut [&mut [u8]],
    control: &mut [u8],
) -> Result<Message, i32> {
    let size: usize = iov.iter().map(|part| part.len()).sum();
    let wire = wire_flags(flags)?;
    let point = crate::threads::cancel::Point::begin();
    let result = with_socket(fd, |transport, end| {
        let pipes = pipes_of(transport)?;
        let e = endpoint(end);
        let room = control.len().saturating_sub(CMSG_HEADER) / 4;
        let max_fds = room.min(FDS_MAX) as u32;
        let ty = option(transport, end, OPT_TYPE, false, 0)?;
        let mut total = 0;
        let mut message = Message {
            count: 0,
            name_len: 0,
            flags: 0,
            control_len: 0,
        };
        let mut name = name;
        loop {
            let want = (size - total).min(SEND_MAX) as u32;
            let req = |key| Recv {
                key,
                end: e.id,
                flags: wire,
                count: want,
                max_fds: if total == 0 { max_fds } else { 0 },
            };
            let mut start = Writer::new();
            req(None).write(&mut start).map_err(|_| EIO)?;
            let mut reply = [0u8; MESSAGE_MAX];
            let n = long::run_with(
                &pipes,
                start.as_bytes(),
                |cancel, key, w| {
                    if cancel {
                        cancel_request(Method::ReadCancel, key, e, w)
                    } else {
                        req(Some(key)).write(w)
                    }
                },
                &mut reply,
                &refusal,
            );
            let n = match n {
                Ok(n) => n,
                Err(_) if total > 0 => break,
                Err(errno) => return Err(errno),
            };
            let got = Received::parse(&reply[..n]).map_err(|_| EIO)?;
            scatter(iov, total, got.bytes);
            if total == 0 {
                if let Some(out) = name.as_deref_mut() {
                    let inet = got.from.kind == ADDR_INET
                        || (got.from.kind == ADDR_NONE
                            && option(transport, end, OPT_DOMAIN, false, 0)
                                .is_ok_and(|d| d == INET));
                    message.name_len = c_address(&got.from, inet, out);
                }
                if got.flags & OUT_TRUNC != 0 {
                    message.flags |= MSG_TRUNC;
                }
                if got.flags & OUT_CTRUNC != 0 {
                    message.flags |= MSG_CTRUNC;
                }
                message.control_len = install(
                    transport,
                    &got.fds[..got.nfds],
                    flags & MSG_CMSG_CLOEXEC != 0,
                    control,
                    &mut message.flags,
                )?;
            }
            total += got.bytes.len();
            if got.bytes.is_empty() || ty != STREAM || flags & MSG_WAITALL == 0 || total >= size {
                break;
            }
        }
        message.count = total;
        Ok(message)
    });
    finish(point, &result);
    result
}

/// The descriptions `ids` as new descriptors and an SCM_RIGHTS message in
/// `control`; the bytes written. A description the process holds already
/// gets another descriptor like a dup does. A descriptor that cannot be made
/// ends the message there (MSG_CTRUNC) and lets go of its description.
fn install(
    transport: Transport,
    ids: &[u32],
    cloexec: bool,
    control: &mut [u8],
    flags: &mut i32,
) -> Result<usize, i32> {
    if ids.is_empty() {
        return Ok(0);
    }
    let mut made = [0i32; FDS_MAX];
    let mut count = 0;
    for &id in ids {
        let inserted = shared::with_files(|files| {
            files
                .insert(
                    Target::Pipe(id),
                    descriptor_flags(if cloexec { SOCK_CLOEXEC } else { 0 }),
                )
                .map(|fd| (fd as i32, ()))
                .map_err(crate::error)
        });
        match inserted {
            Ok((fd, _)) => {
                made[count] = fd;
                count += 1;
            }
            Err(_) => {
                *flags |= MSG_CTRUNC;
                // The process held it already: the table keeps it. Else
                // the service lets go of it.
                let held = shared::with_files(|files| {
                    Ok(files.descriptors().any(|(_, t, _)| t == Target::Pipe(id)))
                })
                .unwrap_or(true);
                if !held {
                    let _ = transport.release(Some(Target::Pipe(id)));
                }
            }
        }
    }
    let fit = (control.len().saturating_sub(CMSG_HEADER) / 4).min(count);
    if fit < count {
        *flags |= MSG_CTRUNC;
        for &fd in &made[fit..count] {
            let _ = crate::close(fd);
        }
    }
    if fit == 0 {
        return Ok(0);
    }
    let len = CMSG_HEADER + 4 * fit;
    control[..8].copy_from_slice(&len.to_ne_bytes());
    control[8..12].copy_from_slice(&SOL_SOCKET.to_ne_bytes());
    control[12..16].copy_from_slice(&SCM_RIGHTS.to_ne_bytes());
    for (k, fd) in made[..fit].iter().enumerate() {
        control[CMSG_HEADER + 4 * k..CMSG_HEADER + 4 * k + 4].copy_from_slice(&fd.to_ne_bytes());
    }
    Ok(len)
}

#[cfg(test)]
mod tests {}
