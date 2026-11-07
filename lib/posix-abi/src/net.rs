// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Sockets of the network service (`proto_net`, services/netd): the
//! process's session with the service, which the start gives in the slot
//! `Net`, and the calls of AF_INET on it. A descriptor names a socket as
//! `posix_fs::Target::Net` with the service's description of it.
//!
//! * `session()` is the process's `Net` session (SEND, DUPLICATE, TRANSFER),
//!   None in an image without the service: `socket(AF_INET, ...)` then goes
//!   to the pipe service's loopback as before.
//! * The waiting calls (accept, send, recv, connect) are long operations in
//!   two steps from the calling thread (`long::run_with`). A signal ends
//!   the wait with EINTR unless its handler had SA_RESTART; `connect` ends
//!   with EINTR for any handler, and the handshake goes on in the service.
//! * A forked child, a spawned child and an exec'd image each get a
//!   session of their own that holds the descriptions of the descriptors
//!   they keep (CLONE), or the session itself (`exec`, after ABANDON).
//! * When the service has ended, every request on a session of it gives
//!   ENETDOWN, and a close of the descriptor still succeeds. A child that
//!   forks then gets a copy of the dead session, so that its AF_INET calls
//!   fail the same way and none goes to another service by mistake.

use crate::constants::*;
use crate::long;
use crate::netbuf::{self, Cell};
use crate::shared;
use crate::sockets::{
    AF_INET, IPPROTO_TCP, IPPROTO_UDP, KEPT_FLAGS, MSG_CMSG_CLOEXEC, MSG_DONTWAIT, MSG_NOSIGNAL,
    MSG_OOB, MSG_PEEK, MSG_TRUNC, MSG_WAITALL, Message, SO_ACCEPTCONN, SO_BROADCAST, SO_DOMAIN,
    SO_ERROR, SO_KEEPALIVE, SO_LINGER, SO_RCVBUF, SO_RCVTIMEO, SO_REUSEADDR, SO_REUSEPORT,
    SO_SNDBUF, SO_SNDTIMEO, SO_STAFETO_BUFFERED, SO_STAFETO_BUFFERS, SO_TYPE, SOCK_DGRAM,
    SOCK_NONBLOCK, SOCK_STREAM, SOL_SOCKET, TCP_NODELAY,
};
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicU64, Ordering};
use posix_fs::{NetTarget, Target};
use proto_net::sockets::{self as wire, CLONE_MAX, List, Request, opt};
use proto_net::{Address, DATA_MAX};
use proto_wire::{Reader, Status, Writer};
use rt::abi::{Error, MESSAGE_MAX, Rights};
use rt::handle::{Channel, Handle};

// Linux's numbers, relibc's.
const ENOTSOCK: i32 = 88;
const EMSGSIZE: i32 = 90;
const EPROTOTYPE: i32 = 91;
const ENOPROTOOPT: i32 = 92;
const EPROTONOSUPPORT: i32 = 93;
const EAFNOSUPPORT: i32 = 97;
const EADDRINUSE: i32 = 98;
const EADDRNOTAVAIL: i32 = 99;
const ENETDOWN: i32 = 100;
const ENETUNREACH: i32 = 101;
const ECONNRESET: i32 = 104;
const ENOBUFS: i32 = 105;
const EISCONN: i32 = 106;
const ENOTCONN: i32 = 107;
const ECONNREFUSED: i32 = 111;
const EALREADY: i32 = 114;
const EINPROGRESS: i32 = 115;

/// The session with the network service, 0 for none.
static SESSION: AtomicU64 = AtomicU64::new(0);

/// The process's session with the network service, which the start gives
/// (init's CONNECT, or the loader's slot Net), and the hook that closes the
/// descriptions the layer's descriptors held.
///
/// # Safety
/// Startup, on the only thread.
pub unsafe fn init(session: Option<Handle<Channel>>) {
    SESSION.store(session.map_or(0, |s| s.into_raw().0), Ordering::Release);
    posix_fs::set_net_release(close_description);
    posix_fs::set_epoll_release(crate::epoll::release);
}

/// A forked child: `session`, the clone the parent made, takes the place of
/// the parent's value, which names nothing of the child's.
///
/// # Safety
/// The child's only thread, before anything else of the layer runs.
pub unsafe fn after_fork(session: Option<Handle<Channel>>) {
    SESSION.store(session.map_or(0, |s| s.into_raw().0), Ordering::Release);
    // The clone has no shared buffer: the child asks for its own.
    netbuf::after_fork();
}

/// The session with the network service, for the requests and for the
/// clones a child gets.
pub fn session() -> Option<rt::abi::Handle> {
    match SESSION.load(Ordering::Acquire) {
        0 => None,
        raw => Some(rt::abi::Handle(raw)),
    }
}

fn channel() -> Result<ManuallyDrop<Handle<Channel>>, i32> {
    session().map(Handle::borrowed).ok_or(ENETDOWN)
}

/// The errno of a refusal of the network service.
pub(crate) fn refusal(status: Status) -> Option<i32> {
    Some(match status.code() {
        proto_net::BAD_FD => EBADF,
        proto_net::AGAIN => EAGAIN,
        proto_net::MFILE => EMFILE,
        proto_net::INVALID => EINVAL,
        proto_net::IN_USE => EADDRINUSE,
        proto_net::NOT_CONNECTED => ENOTCONN,
        proto_net::CONNECTED => EISCONN,
        proto_net::REFUSED => ECONNREFUSED,
        proto_net::BAD_TYPE => EPROTOTYPE,
        proto_net::NOT_SUPPORTED => EOPNOTSUPP,
        proto_net::NO_ADDRESS => EADDRNOTAVAIL,
        proto_net::TOO_BIG => EMSGSIZE,
        proto_net::NO_BUFFERS => ENOBUFS,
        proto_net::NO_OPTION => ENOPROTOOPT,
        proto_net::NOT_SOCKET => ENOTSOCK,
        proto_net::UNREACHABLE => ENETUNREACH,
        proto_net::NO_FAMILY => EAFNOSUPPORT,
        proto_net::NOT_ALLOWED => EACCES,
        proto_net::RESET => ECONNRESET,
        proto_net::PIPE => EPIPE,
        proto_net::NET_DOWN => ENETDOWN,
        proto_net::TIMEOUT => ETIMEDOUT,
        proto_net::ALREADY => EALREADY,
        proto_net::IN_PROGRESS => EINPROGRESS,
        _ => return None,
    })
}

fn kernel(error: Error) -> i32 {
    match error {
        Error::PeerClosed => ENETDOWN,
        _ => EIO,
    }
}

/// Whether the service of the session has ended: a request that any live
/// service refuses (a description that is none) fails with PEER_CLOSED only
/// on a dead one.
fn service_gone() -> bool {
    let Ok(service) = channel() else { return true };
    let mut w = Writer::new();
    let probe = Request::GetOpt {
        description: 0,
        name: opt::TYPE,
    };
    if probe.write(&mut w).is_err() {
        return false;
    }
    loop {
        match rt::sys::send(&service, w.as_bytes()) {
            Err(Error::Interrupted) => continue,
            Err(Error::PeerClosed) => return true,
            _ => return false,
        }
    }
}

/// The errno of a failed long operation: EIO becomes ENETDOWN when the
/// service has ended (the kernel's error of a send to it is not kept apart
/// by `long`).
fn long_errno(errno: i32) -> i32 {
    if errno == EIO && service_gone() {
        ENETDOWN
    } else {
        errno
    }
}

/// One request that answers at once, the bytes of its reply after the
/// status into the start of `out`: their count. `handle` goes with it.
#[inline(never)]
fn rpc(
    request: &Request<'_>,
    handle: Option<Handle<Channel>>,
    out: &mut [u8; MESSAGE_MAX],
) -> Result<usize, i32> {
    let service = channel()?;
    let mut w = Writer::new();
    request.write(&mut w).map_err(|_| EIO)?;
    let mut handle = handle;
    let reply = loop {
        let sent = match handle.take() {
            Some(h) => rt::sys::send_handles(&service, w.as_bytes(), [h.erase()])
                .map_err(|refused| refused.error),
            None => rt::sys::send(&service, w.as_bytes()),
        };
        match sent {
            Err(Error::Interrupted) => continue,
            other => break other.map_err(kernel)?,
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
        Status::Kernel(Error::PeerClosed) => Err(ENETDOWN),
        status => Err(refusal(status).unwrap_or(EIO)),
    }
}

/// A request of the switch (PORT_HOLD, JOIN) that `Request` does not name:
/// the bytes of its reply after the status, or the status of the refusal.
/// `handle` goes with it.
fn switch_call(
    w: &Writer,
    handle: Option<Handle<Channel>>,
    out: &mut [u8; MESSAGE_MAX],
) -> Result<usize, Status> {
    let service = channel().map_err(|_| Status::Kernel(Error::PeerClosed))?;
    let mut handle = handle;
    let reply = loop {
        let sent = match handle.take() {
            Some(h) => rt::sys::send_handles(&service, w.as_bytes(), [h.erase()])
                .map_err(|refused| refused.error),
            None => rt::sys::send(&service, w.as_bytes()),
        };
        match sent {
            Err(Error::Interrupted) => continue,
            other => break other.map_err(Status::Kernel)?,
        }
    };
    let bytes = reply.bytes(out);
    let len = bytes.len();
    let mut r = Reader::new(&out[..len]);
    match Status::from_code(r.u32().map_err(|_| Status::BadSize)?) {
        Status::Ok => {
            let left = r.left();
            out.copy_within(len - left..len, 0);
            Ok(left)
        }
        status => Err(status),
    }
}

/// The errno of a refusal of PORT_HOLD or JOIN.
fn switch_errno(status: Status) -> i32 {
    match status {
        Status::Kernel(Error::PeerClosed) => ENETDOWN,
        Status::Kernel(Error::LimitReached) => ENOMEM,
        status => refusal(status).unwrap_or(EIO),
    }
}

/// PORT_HOLD of TCP port `port` for the switch: the description of the
/// right to the port, a descriptor of the process (`kept`: its CLOEXEC and
/// CLOFORK bits, so that a fork carries it to the child and an exec closes
/// it as the program's socket would). The service has the process service
/// vouch for the superuser when the port is below 1024. `Ok(None)` when the
/// service has no switch (it does not know the method). EADDRINUSE,
/// EACCES, ENOMEM (no group) and the like from the service.
pub(crate) fn port_hold(port: u16, reuseport: bool, kept: i32) -> Result<Option<i32>, i32> {
    let hold = proto_net::switch::Hold {
        protocol: 6,
        first: u32::from(port),
        count: 1,
        flags: if reuseport {
            proto_net::switch::REUSEPORT
        } else {
            0
        },
    };
    let mut w = Writer::new();
    proto_net::switch::write_port_hold(&hold, &mut w).map_err(|_| EIO)?;
    let identity = crate::process::identity().and_then(|identity| {
        rt::sys::handle_duplicate(identity, Rights::NOTIFY | Rights::TRANSFER).ok()
    });
    let mut out = [0u8; MESSAGE_MAX];
    match switch_call(&w, identity, &mut out) {
        Ok(n) => {
            let place = Reader::new(&out[..n]).u32().map_err(|_| EIO)?;
            let held = publish(place, true, kept).map(Some)?;
            // The stack of this process (and of the workers it forks) owns the port: a
            // packet of the loopback network for it stays inside (`fast::own_port`).
            crate::fast::note_own_port(port);
            Ok(held)
        }
        Err(Status::UnknownMethod) => Ok(None),
        Err(status) => Err(switch_errno(status)),
    }
}

/// JOIN: the consumer of this session becomes a member of the group of the
/// port description `fd`.
pub(crate) fn port_join(fd: i32) -> Result<(), i32> {
    with_socket(fd, |description| {
        let mut w = Writer::new();
        proto_net::switch::write_join(description, &mut w).map_err(|_| EIO)?;
        switch_call(&w, None, &mut [0; MESSAGE_MAX])
            .map(drop)
            .map_err(switch_errno)
    })
}

fn simple(request: &Request<'_>) -> Result<(), i32> {
    rpc(request, None, &mut [0; MESSAGE_MAX]).map(drop)
}

fn word(request: &Request<'_>) -> Result<u32, i32> {
    let mut out = [0; MESSAGE_MAX];
    let n = rpc(request, None, &mut out)?;
    Reader::new(&out[..n]).u32().map_err(|_| EIO)
}

/// EPOLL_SET: the records of `list` in the set `set` of the session (0 makes
/// a set); the set and one status word for each record. ENOMEM when the
/// service has no set to give, EBADF for a set that is gone.
pub(crate) fn epoll_set(
    set: u32,
    list: wire::EpollList,
    statuses: &mut [u32; wire::EPOLL_BATCH],
) -> Result<u32, i32> {
    let service = channel()?;
    let mut w = Writer::new();
    Request::EpollSet { set, list }
        .write(&mut w)
        .map_err(|_| EIO)?;
    let reply = loop {
        match rt::sys::send(&service, w.as_bytes()) {
            Err(Error::Interrupted) => continue,
            other => break other.map_err(kernel)?,
        }
    };
    let mut out = [0; MESSAGE_MAX];
    let bytes = reply.bytes(&mut out);
    match wire::read_epoll_set(bytes, list.len, statuses) {
        Ok(set) => Ok(set),
        Err(Status::Kernel(Error::PeerClosed)) => Err(ENETDOWN),
        Err(Status::Kernel(Error::LimitReached)) => Err(ENOMEM),
        Err(status) => Err(refusal(status).unwrap_or(EIO)),
    }
}

/// EPOLL_DROP: the set goes. A service that ended holds none.
pub(crate) fn epoll_drop(set: u32) {
    let Ok(service) = channel() else { return };
    let mut w = Writer::new();
    if proto_net::Method::EpollDrop.header().write(&mut w).is_err() || w.u32(set).is_err() {
        return;
    }
    loop {
        match rt::sys::send(&service, w.as_bytes()) {
            Err(Error::Interrupted) => continue,
            _ => return,
        }
    }
}

/// CLOSE of a description, the hook of the last close of a descriptor. A
/// service that ended holds nothing: the close succeeds.
fn close_description(description: u32) {
    // The reply is a long one: READY at once, or WAIT k while a stream with a
    // linger time has data the peer has not acknowledged. A signal or the end
    // of the service ends the wait, and the close is done all the same.
    let Ok(service) = channel() else { return };
    let mut start = Writer::new();
    let request = Request::Close {
        description,
        linger: wire::CLOSE_MAY_WAIT,
    };
    if request.write(&mut start).is_err() {
        return;
    }
    let keyed = |cancel: bool, key: u64, w: &mut Writer| {
        if cancel {
            Request::Cancel(key).write(w)
        } else {
            Request::CloseTake(key).write(w)
        }
    };
    let _ = long::run_no_point(&service, start.as_bytes(), keyed, &mut [], &refusal);
}

/// ABANDON of the process's session: the long operations of its threads go.
/// An exec asks it before the session moves to the new image, whose stopped
/// threads never end their waits. The service lets go of a few operations
/// in each answer and says how many are left; the ask goes on until none is.
pub(crate) fn abandon() {
    let Ok(service) = channel() else { return };
    let request = proto_net::Method::Abandon.header().bytes();
    loop {
        let reply = match rt::sys::send(&service, &request) {
            Err(Error::Interrupted) => continue,
            Ok(reply) => reply,
            Err(_) => return,
        };
        let mut buffer = [0u8; MESSAGE_MAX];
        match wire::read_abandoned(reply.bytes(&mut buffer)) {
            Ok(left) if left > 0 => {}
            _ => return,
        }
    }
}

/// A clone of the process's session for a child that holds the descriptions
/// `portion` gives, the descriptors the child keeps; None when the process
/// has no session. `portion` fills one portion of up to `CLONE_MAX`
/// descriptions into its argument and says how many and whether there is
/// another; the first goes with CLONE, the rest with CLONE_MORE (each at most
/// 64, so that no step of the service is longer for a process with many
/// sockets). A refusal other than the service's end fails the fork or spawn
/// (the child without its sockets would close them silently): the errno,
/// and the clone made so far is closed, which lets the service go of its
/// descriptions. The end of the service gives the child a copy of the dead
/// session.
pub(crate) fn clone_kept(
    mut portion: impl FnMut(&mut [u32; CLONE_MAX]) -> Result<(usize, bool), i32>,
) -> Result<Option<Handle<Channel>>, i32> {
    let Some(raw) = session() else {
        return Ok(None);
    };
    let service = Handle::<Channel>::borrowed(raw);
    let mut items = [0u32; CLONE_MAX];
    let (count, mut more) = portion(&mut items)?;
    let list = List::new(&items[..count]).ok_or(EIO)?;
    let mut w = Writer::new();
    Request::Clone(list).write(&mut w).map_err(|_| EIO)?;
    let (clone, birth) = match rt::service::clone_session_word(&service, w.as_bytes()) {
        Ok(made) => made,
        Err(Status::Kernel(Error::PeerClosed)) => return Ok(dead_copy(&service)),
        Err(status) => return Err(crate::process::clone_errno(status)),
    };
    while more {
        let (count, next) = portion(&mut items)?;
        more = next;
        if count == 0 {
            continue;
        }
        let list = List::new(&items[..count]).ok_or(EIO)?;
        simple(&Request::CloneMore { birth, list })
            .map_err(|errno| if errno == ENETDOWN { EIO } else { errno })?;
    }
    Ok(Some(clone))
}

/// The copy of the dead session a child gets when the service has ended.
fn dead_copy(service: &Handle<Channel>) -> Option<Handle<Channel>> {
    let copy =
        rt::sys::handle_duplicate(service, Rights::SEND | Rights::TRANSFER | Rights::DUPLICATE);
    if copy.is_err() {
        rt::println!("posix: the network service is gone; the child has no session");
    }
    copy.ok()
}

/// The portions of the descriptions of the descriptors without FD_CLOFORK the
/// layer keeps across a fork: the closure `clone_kept` takes.
pub(crate) fn kept_by_fork_portions()
-> impl FnMut(&mut [u32; CLONE_MAX]) -> Result<(usize, bool), i32> {
    let mut start = 0;
    move |out| {
        let (count, next) = shared::nets_kept_by_fork_from(start, out)?;
        match next {
            Some(fd) => {
                start = fd;
                Ok((count, true))
            }
            None => Ok((count, false)),
        }
    }
}

// ---------------------------------------------------------------- addresses

/// The address `raw` (a sockaddr_in) as the protocol has it.
fn wire_address(raw: &[u8]) -> Result<Address, i32> {
    if raw.len() < 16 {
        return Err(EINVAL);
    }
    if i32::from(u16::from_ne_bytes([raw[0], raw[1]])) != AF_INET {
        return Err(EAFNOSUPPORT);
    }
    let port = u16::from_be_bytes([raw[2], raw[3]]);
    Ok(Address::v4(
        [raw[4], raw[5], raw[6], raw[7]],
        u32::from(port),
    ))
}

/// The sockaddr_in of `address` into `out`: its true length, 16.
fn c_address(address: &Address, out: &mut [u8]) -> usize {
    let mut full = [0u8; 16];
    full[..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
    full[2..4].copy_from_slice(&(address.port as u16).to_be_bytes());
    if let Some(ip) = address.ipv4() {
        full[4..8].copy_from_slice(&ip);
    }
    let n = out.len().min(full.len());
    out[..n].copy_from_slice(&full[..n]);
    full.len()
}

// ------------------------------------------------------------------ the calls

fn descriptor_flags(kept: i32) -> posix_fs::DescriptorFlags {
    posix_fs::DescriptorFlags {
        close_on_exec: kept & crate::sockets::SOCK_CLOEXEC != 0,
        close_on_fork: kept & crate::sockets::SOCK_CLOFORK != 0,
    }
}

/// Whether `fd` names a socket of the network service.
pub fn is_net(fd: i32) -> bool {
    u32::try_from(fd).is_ok_and(|fd| {
        shared::with_fd(fd, |files| Ok(files.target(fd).ok()))
            .is_ok_and(|target| matches!(target, Some(Target::Net(_))))
    })
}

/// Runs `run` on the description `fd` names, the descriptor held so that
/// no other thread's close ends the description meanwhile.
fn with_net<R>(fd: i32, run: impl FnOnce(NetTarget) -> Result<R, i32>) -> Result<R, i32> {
    let fd = u32::try_from(fd).map_err(|_| EBADF)?;
    shared::held(fd, |_, target| match target {
        Target::Net(net) => run(net),
        _ => Err(ENOTSOCK),
    })
}

/// `with_net` for the calls that need the description alone.
fn with_socket<R>(fd: i32, run: impl FnOnce(u32) -> Result<R, i32>) -> Result<R, i32> {
    with_net(fd, |net| run(net.description))
}

/// EXPORT: a pass for the socket of descriptor `fd`, a copy of the session's
/// channel that carries the description and that another process may adopt.
/// ENOTSOCK for a descriptor that is no socket of this service, ENOBUFS when
/// the service has its passes all given out.
pub(crate) fn export(fd: i32) -> Result<Handle<Channel>, i32> {
    with_socket(fd, |description| {
        let service = channel()?;
        let mut w = Writer::new();
        Request::Export { description }
            .write(&mut w)
            .map_err(|_| EIO)?;
        let reply = loop {
            match rt::sys::send(&service, w.as_bytes()) {
                Err(Error::Interrupted) => continue,
                other => break other.map_err(kernel)?,
            }
        };
        let mut buffer = [0u8; MESSAGE_MAX];
        let mut r = Reader::new(reply.bytes(&mut buffer));
        match Status::from_code(r.u32().map_err(|_| EIO)?) {
            Status::Ok => {}
            Status::Kernel(Error::LimitReached) => return Err(ENOBUFS),
            Status::Kernel(Error::PeerClosed) => return Err(ENETDOWN),
            status => return Err(refusal(status).unwrap_or(EIO)),
        }
        let mut handles = reply.handles;
        handles.take::<Channel>(0).map_err(|_| EIO)
    })
}

/// ADOPT: the description a pass names becomes a descriptor of this
/// process's session. The pass is spent either way. ENOTSOCK for a handle
/// that is no pass of the service the session is with.
pub(crate) fn adopt(pass: Handle<Channel>, kept: i32) -> Result<i32, i32> {
    let mut reply = [0u8; MESSAGE_MAX];
    let n = rpc(&Request::Adopt, Some(pass), &mut reply)?;
    // `rpc` took the status off: the description and the kind are left.
    let mut r = Reader::new(&reply[..n]);
    let description = r.u32().map_err(|_| EIO)?;
    let kind = r.u32().map_err(|_| EIO)?;
    publish(description, kind == wire::STREAM, kept)
}

/// A descriptor for the description `description`; the service closes it
/// again on an error.
fn publish(description: u32, stream: bool, kept: i32) -> Result<i32, i32> {
    let target = Target::Net(NetTarget {
        description,
        stream,
    });
    let inserted = shared::growing(|files| {
        files
            .insert(target, descriptor_flags(kept))
            .map(|fd| fd as i32)
            .map_err(shared::page_error)
    });
    if inserted.is_err() {
        close_description(description);
    }
    inserted
}

fn finish<T>(point: crate::threads::cancel::Point, result: &Result<T, i32>) {
    if result.is_ok() {
        point.end();
    } else {
        point.finish();
    }
}

pub fn socket(domain: i32, kind: i32, protocol: i32) -> Result<i32, i32> {
    if domain != AF_INET {
        return Err(EAFNOSUPPORT);
    }
    if kind & !(0xf | SOCK_NONBLOCK | KEPT_FLAGS) != 0 {
        return Err(EINVAL);
    }
    let ty = match kind & 0xf {
        SOCK_STREAM => wire::STREAM,
        SOCK_DGRAM => wire::DGRAM,
        _ => return Err(EPROTOTYPE),
    };
    let fits = protocol == 0
        || (protocol == IPPROTO_TCP && ty == wire::STREAM)
        || (protocol == IPPROTO_UDP && ty == wire::DGRAM);
    if !fits {
        return Err(EPROTONOSUPPORT);
    }
    let description = word(&Request::Socket {
        family: proto_net::INET,
        kind: ty,
        flags: if kind & SOCK_NONBLOCK != 0 {
            wire::NONBLOCK
        } else {
            0
        },
    })?;
    publish(description, ty == wire::STREAM, kind & KEPT_FLAGS)
}

pub fn bind(fd: i32, raw: &[u8]) -> Result<(), i32> {
    with_socket(fd, |description| {
        let address = wire_address(raw)?;
        let request = Request::Bind {
            description,
            address,
        };
        // Every bind brings a copy of the identity session: the service has
        // the process service vouch for it when the port is below 1024 or
        // the socket shares its port (SO_REUSEPORT), and the layer cannot
        // tell whether the option is set.
        let identity = crate::process::identity().and_then(|identity| {
            rt::sys::handle_duplicate(identity, Rights::NOTIFY | Rights::TRANSFER).ok()
        });
        rpc(&request, identity, &mut [0; MESSAGE_MAX]).map(drop)
    })
}

pub fn listen(fd: i32, backlog: i32) -> Result<(), i32> {
    with_socket(fd, |description| {
        simple(&Request::Listen {
            description,
            backlog: backlog.max(0) as u32,
        })
    })
}

/// A long operation in two steps: `make(key)` is the start (None) and the
/// take (Some); a cancel is CANCEL k. `restart` false ends the wait for a
/// handler of any kind (`long::run_no_restart`).
fn run<'a>(
    restart: bool,
    make: impl Fn(Option<u64>) -> Request<'a>,
    out: &mut [u8],
) -> Result<usize, i32> {
    let service = channel()?;
    let mut start = Writer::new();
    make(None).write(&mut start).map_err(|_| EIO)?;
    let keyed = |cancel: bool, key: u64, w: &mut Writer| {
        if cancel {
            Request::Cancel(key).write(w)
        } else {
            make(Some(key)).write(w)
        }
    };
    let result = if restart {
        long::run_with(&service, start.as_bytes(), keyed, out, &refusal)
    } else {
        long::run_no_restart(&service, start.as_bytes(), keyed, out, &refusal)
    };
    result.map_err(long_errno)
}

pub fn connect(fd: i32, raw: &[u8]) -> Result<(), i32> {
    let point = crate::threads::cancel::Point::begin();
    let result = with_socket(fd, |description| {
        let address = wire_address(raw)?;
        // A handler of any kind ends the wait: the handshake goes on, and
        // a later connect sees its end.
        run(
            false,
            |key| Request::Connect {
                key,
                description,
                address,
            },
            &mut [],
        )
        .map(drop)
    });
    finish(point, &result);
    result
}

/// accept and accept4: the new descriptor and the true length of the
/// peer's address, which goes into `out`.
pub fn accept(fd: i32, out: Option<&mut [u8]>, flags: i32) -> Result<(i32, usize), i32> {
    if flags & !(SOCK_NONBLOCK | KEPT_FLAGS) != 0 {
        return Err(EINVAL);
    }
    let point = crate::threads::cancel::Point::begin();
    let result = with_socket(fd, |description| {
        let wire_flags = if flags & SOCK_NONBLOCK != 0 {
            wire::NONBLOCK
        } else {
            0
        };
        let mut reply = [0u8; MESSAGE_MAX];
        let n = run(
            true,
            |key| Request::Accept {
                key,
                description,
                flags: wire_flags,
            },
            &mut reply,
        )?;
        let (new, peer) = wire::read_accepted(&reply[..n]).map_err(|_| EIO)?;
        let fd = publish(new, true, flags & KEPT_FLAGS)?;
        let len = out.map_or(0, |out| c_address(&peer, out));
        Ok((fd, len))
    });
    finish(point, &result);
    result
}

fn name(fd: i32, peer: bool, out: &mut [u8]) -> Result<usize, i32> {
    with_socket(fd, |description| {
        let mut reply = [0; MESSAGE_MAX];
        let n = rpc(
            &Request::Name {
                description,
                which: if peer {
                    wire::PEER_NAME
                } else {
                    wire::OWN_NAME
                },
            },
            None,
            &mut reply,
        )?;
        let address = Address::read(&mut Reader::new(&reply[..n])).map_err(|_| EIO)?;
        Ok(c_address(&address, out))
    })
}

pub fn getsockname(fd: i32, out: &mut [u8]) -> Result<usize, i32> {
    name(fd, false, out)
}

pub fn getpeername(fd: i32, out: &mut [u8]) -> Result<usize, i32> {
    name(fd, true, out)
}

/// The option of the protocol for an option of C, and whether it is a
/// flag (any non-zero value sets it).
fn option_number(level: i32, name: i32) -> Result<(u32, bool), i32> {
    if level == IPPROTO_TCP && name == TCP_NODELAY {
        return Ok((opt::NODELAY, true));
    }
    if level != SOL_SOCKET {
        return Err(ENOPROTOOPT);
    }
    Ok(match name {
        SO_REUSEADDR => (opt::REUSEADDR, true),
        SO_REUSEPORT => (opt::REUSEPORT, true),
        SO_TYPE => (opt::TYPE, false),
        SO_ERROR => (opt::ERROR, false),
        SO_BROADCAST => (opt::BROADCAST, true),
        SO_SNDBUF => (opt::SNDBUF, false),
        SO_RCVBUF => (opt::RCVBUF, false),
        SO_KEEPALIVE => (opt::KEEPALIVE, true),
        SO_ACCEPTCONN => (opt::ACCEPTCONN, false),
        SO_DOMAIN => (opt::DOMAIN, false),
        SO_STAFETO_BUFFERS => (opt::BUFFERS, false),
        SO_STAFETO_BUFFERED => (opt::BUFFERED, false),
        _ => return Err(ENOPROTOOPT),
    })
}

/// The options whose value is not an int: SO_LINGER (a `struct linger`) and
/// the timeouts (a `struct timeval`), the number of the protocol's option.
fn structured(level: i32, name: i32) -> Option<u32> {
    if level != SOL_SOCKET {
        return None;
    }
    match name {
        SO_LINGER => Some(opt::LINGER),
        SO_RCVTIMEO => Some(opt::RCVTIMEO),
        SO_SNDTIMEO => Some(opt::SNDTIMEO),
        _ => None,
    }
}

/// The bytes of the structure of the option `number` for the value `value` of
/// the protocol: `struct linger` (two ints) or `struct timeval` (seconds and
/// microseconds, 8 bytes each).
fn structure_of(number: u32, value: u32, out: &mut [u8; 16]) -> usize {
    if number == opt::LINGER {
        let on = value & opt::LINGER_ON != 0;
        let seconds = value & 0xFFFF;
        out[..4].copy_from_slice(&i32::from(on).to_ne_bytes());
        out[4..8].copy_from_slice(&(seconds as i32).to_ne_bytes());
        8
    } else {
        out[..8].copy_from_slice(&i64::from(value / 1000).to_ne_bytes());
        out[8..16].copy_from_slice(&(i64::from(value % 1000) * 1000).to_ne_bytes());
        16
    }
}

/// The value of the protocol for the structure `value` of the option
/// `number`: EINVAL for a short or a negative one.
fn value_of(number: u32, value: &[u8]) -> Result<u32, i32> {
    if number == opt::LINGER {
        if value.len() < 8 {
            return Err(EINVAL);
        }
        let on = i32::from_ne_bytes(value[..4].try_into().map_err(|_| EINVAL)?);
        let seconds = i32::from_ne_bytes(value[4..8].try_into().map_err(|_| EINVAL)?);
        if on == 0 {
            return Ok(0);
        }
        if seconds < 0 {
            return Err(EINVAL);
        }
        return Ok(opt::LINGER_ON | seconds.min(i32::from(u16::MAX)) as u32);
    }
    if value.len() < 16 {
        return Err(EINVAL);
    }
    let seconds = i64::from_ne_bytes(value[..8].try_into().map_err(|_| EINVAL)?);
    let micros = i64::from_ne_bytes(value[8..16].try_into().map_err(|_| EINVAL)?);
    if seconds < 0 || !(0..1_000_000).contains(&micros) {
        return Err(EINVAL);
    }
    // A time below a millisecond is one, so that it does not mean "none".
    let millis = seconds
        .saturating_mul(1000)
        .saturating_add((micros + 999) / 1000);
    Ok(millis.min(i64::from(u32::MAX)) as u32)
}

/// getsockopt: the int of the option into `out`; its true length, 4 (8 for
/// SO_LINGER, 16 for the timeouts).
pub fn getsockopt(fd: i32, level: i32, name: i32, out: &mut [u8]) -> Result<usize, i32> {
    if let Some(number) = structured(level, name) {
        return with_socket(fd, |description| {
            let value = word(&Request::GetOpt {
                description,
                name: number,
            })?;
            let mut bytes = [0u8; 16];
            let len = structure_of(number, value, &mut bytes);
            let n = out.len().min(len);
            out[..n].copy_from_slice(&bytes[..n]);
            Ok(len)
        });
    }
    let (number, _) = option_number(level, name)?;
    with_socket(fd, |description| {
        let mut value = word(&Request::GetOpt {
            description,
            name: number,
        })?;
        // The deferred error of the service is a code of its protocol: the
        // option holds the errno.
        if number == opt::ERROR && value != 0 {
            value = refusal(Status::from_code(value)).unwrap_or(EIO) as u32;
        }
        let bytes = value.to_ne_bytes();
        let n = out.len().min(4);
        out[..n].copy_from_slice(&bytes[..n]);
        Ok(4)
    })
}

pub fn setsockopt(fd: i32, level: i32, name: i32, value: &[u8]) -> Result<(), i32> {
    if let Some(number) = structured(level, name) {
        let word = value_of(number, value)?;
        return with_socket(fd, |description| {
            simple(&Request::SetOpt {
                description,
                name: number,
                value: word,
            })
        });
    }
    let (number, flag) = option_number(level, name)?;
    if value.len() < 4 {
        return Err(EINVAL);
    }
    let word = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
    with_socket(fd, |description| {
        simple(&Request::SetOpt {
            description,
            name: number,
            value: if flag { u32::from(word != 0) } else { word },
        })
    })
}

pub fn shutdown(fd: i32, how: i32) -> Result<(), i32> {
    if !(0..=2).contains(&how) {
        return Err(EINVAL);
    }
    with_socket(fd, |description| {
        simple(&Request::Shutdown {
            description,
            how: how as u32,
        })
    })
}

/// sockatmark: no socket has out-of-band data.
pub fn sockatmark(fd: i32) -> Result<i32, i32> {
    with_socket(fd, |_| Ok(0))
}

fn send_flags(flags: i32) -> Result<u32, i32> {
    if flags & !(MSG_DONTWAIT | MSG_NOSIGNAL | MSG_PEEK | MSG_TRUNC | MSG_WAITALL | MSG_OOB) != 0
        || flags & MSG_OOB != 0
    {
        return Err(EOPNOTSUPP);
    }
    Ok(if flags & MSG_DONTWAIT != 0 {
        wire::DONTWAIT
    } else {
        0
    })
}

fn receive_flags(flags: i32) -> Result<u32, i32> {
    if flags
        & !(MSG_DONTWAIT | MSG_NOSIGNAL | MSG_PEEK | MSG_TRUNC | MSG_WAITALL | MSG_CMSG_CLOEXEC)
        != 0
    {
        return Err(EOPNOTSUPP);
    }
    Ok(if flags & MSG_PEEK != 0 { wire::PEEK } else { 0 }
        | if flags & MSG_DONTWAIT != 0 {
            wire::DONTWAIT
        } else {
            0
        })
}

/// One SEND of at most DATA_MAX bytes: how many the service took.
#[inline(never)]
fn send_once(description: u32, flags: u32, address: Address, bytes: &[u8]) -> Result<usize, i32> {
    let mut result = [0; 4];
    let n = run(
        true,
        |key| Request::Send {
            key,
            description,
            flags,
            address,
            data: bytes,
        },
        &mut result,
    )?;
    let sent = wire::read_sent(&result[..n]).map_err(|_| EIO)? as usize;
    if sent > bytes.len() {
        return Err(EIO);
    }
    Ok(sent)
}

/// One SEND of the first `len` bytes of `cell`: how many the service took.
#[inline(never)]
fn send_cell(description: u32, flags: u32, cell: &Cell, len: usize) -> Result<usize, i32> {
    let mut result = [0; 4];
    let offset = cell.offset();
    let n = run(
        true,
        |key| Request::SendCell {
            key,
            description,
            flags,
            address: Address::NONE,
            offset,
            len: len as u32,
        },
        &mut result,
    )?;
    let sent = wire::read_sent(&result[..n]).map_err(|_| EIO)? as usize;
    if sent > len {
        return Err(EIO);
    }
    Ok(sent)
}

/// The bytes of `iov` from `done` on through `cell`, all of them unless a
/// signal or a non-blocking description stops it after some: their count,
/// `done` among them. Each request carries what the cell holds, and the
/// rest of the cell goes again after the bytes the service took.
fn send_through(
    description: u32,
    flags: u32,
    iov: &[&[u8]],
    size: usize,
    mut cell: Cell,
) -> Result<usize, i32> {
    let mut done = 0;
    while done < size {
        let len = crate::sockets::gather(iov, done, cell.bytes());
        match send_cell(description, flags, &cell, len) {
            Ok(sent) => done += sent,
            Err(_) if done > 0 => break,
            Err(errno) => return Err(errno),
        }
    }
    Ok(done)
}

/// One RECV of up to `most` bytes into `cell`: the flags, the sender and
/// the count.
#[inline(never)]
fn recv_cell(
    description: u32,
    flags: u32,
    cell: &Cell,
    most: usize,
) -> Result<(u32, Address, usize), i32> {
    let mut reply = [0u8; MESSAGE_MAX];
    let offset = cell.offset();
    let most = most.min(proto_net::SLOT) as u32;
    let n = run(
        true,
        |key| Request::RecvCell {
            key,
            description,
            flags,
            most,
            offset,
        },
        &mut reply,
    )?;
    let (got_flags, from, count) = wire::read_received_count(&reply[..n], most).map_err(|_| EIO)?;
    Ok((got_flags, from, count as usize))
}

/// `bytes` to the connection of `description`, all of them unless a
/// signal or a non-blocking description stops it after some: their count.
fn send_all(description: u32, flags: u32, address: Address, bytes: &[u8]) -> Result<usize, i32> {
    if let Some(cell) = netbuf::cell(bytes.len()) {
        return send_through(description, flags, &[bytes], bytes.len(), cell);
    }
    let mut done = 0;
    loop {
        let piece = &bytes[done..bytes.len().min(done + DATA_MAX)];
        match send_once(description, flags, address, piece) {
            Ok(sent) => done += sent,
            Err(_) if done > 0 => break,
            Err(errno) => return Err(errno),
        }
        if done >= bytes.len() {
            break;
        }
    }
    Ok(done)
}

/// sendto and sendmsg: `iov` gathered, to `name` for a datagram socket.
/// EPIPE follows SIGPIPE unless MSG_NOSIGNAL.
pub fn send(
    fd: i32,
    flags: i32,
    name: Option<&[u8]>,
    iov: &[&[u8]],
    control: &[u8],
) -> Result<usize, i32> {
    let size: usize = iov.iter().map(|part| part.len()).sum();
    let wire_flags = send_flags(flags)?;
    if !control.is_empty() {
        return Err(EOPNOTSUPP);
    }
    let point = crate::threads::cancel::Point::begin();
    let result = with_net(
        fd,
        |NetTarget {
             description,
             stream,
         }| {
            let to = match name {
                Some(raw) if raw.len() >= 2 => wire_address(raw)?,
                _ => Address::NONE,
            };
            if !stream {
                if size > DATA_MAX {
                    return Err(EMSGSIZE);
                }
                let mut piece = [0u8; DATA_MAX];
                crate::sockets::gather(iov, 0, &mut piece[..size]);
                return send_once(description, wire_flags, to, &piece[..size]);
            }
            if let Some(cell) = netbuf::cell(size) {
                return send_through(description, wire_flags, iov, size, cell);
            }
            let mut done = 0;
            let mut piece = [0u8; DATA_MAX];
            loop {
                let n = crate::sockets::gather(iov, done, &mut piece);
                match send_once(description, wire_flags, to, &piece[..n]) {
                    Ok(sent) => done += sent,
                    Err(_) if done > 0 => break,
                    Err(errno) => return Err(errno),
                }
                if done >= size {
                    break;
                }
            }
            Ok(done)
        },
    );
    if result == Err(EPIPE) && flags & MSG_NOSIGNAL == 0 {
        let _ = crate::signals::raise(SIGPIPE);
    }
    finish(point, &result);
    result
}

/// recvfrom and recvmsg: up to `iov`'s size, the sender's address into
/// `name`; a datagram longer than that is cut and says MSG_TRUNC.
pub fn recv(
    fd: i32,
    flags: i32,
    name: Option<&mut [u8]>,
    iov: &mut [&mut [u8]],
    control: &mut [u8],
) -> Result<Message, i32> {
    let size: usize = iov.iter().map(|part| part.len()).sum();
    let wire_flags = receive_flags(flags)?;
    let point = crate::threads::cancel::Point::begin();
    let result = with_net(
        fd,
        |NetTarget {
             description,
             stream,
         }| {
            let mut message = Message {
                count: 0,
                name_len: 0,
                flags: 0,
                control_len: 0,
            };
            let _ = control;
            if size == 0 && stream {
                return Ok(message);
            }
            let mut total = 0;
            let mut name = name;
            let mut cell = if stream { netbuf::cell(size) } else { None };
            loop {
                if let Some(cell) = cell.as_mut() {
                    let got = recv_cell(description, wire_flags, cell, size - total);
                    let (got_flags, from, count) = match got {
                        Ok(got) => got,
                        Err(_) if total > 0 => break,
                        Err(errno) => return Err(errno),
                    };
                    crate::sockets::scatter(iov, total, &cell.bytes()[..count]);
                    if total == 0 {
                        if let Some(out) = name.as_deref_mut() {
                            message.name_len = c_address(&from, out);
                        }
                        if got_flags & wire::OUT_TRUNC != 0 {
                            message.flags |= MSG_TRUNC;
                        }
                    }
                    total += count;
                    if count == 0
                        || flags & (MSG_WAITALL | MSG_PEEK) != MSG_WAITALL
                        || total >= size
                    {
                        break;
                    }
                    continue;
                }
                let most = (size - total).clamp(1, DATA_MAX) as u32;
                let mut reply = [0u8; MESSAGE_MAX];
                let n = run(
                    true,
                    |key| Request::Recv {
                        key,
                        description,
                        flags: wire_flags,
                        most,
                    },
                    &mut reply,
                );
                let n = match n {
                    Ok(n) => n,
                    Err(_) if total > 0 => break,
                    Err(errno) => return Err(errno),
                };
                let (got_flags, from, bytes) = wire::read_received(&reply[..n]).map_err(|_| EIO)?;
                let take = bytes.len().min(size - total);
                crate::sockets::scatter(iov, total, &bytes[..take]);
                if total == 0 {
                    if let Some(out) = name.as_deref_mut() {
                        message.name_len = c_address(&from, out);
                    }
                    if got_flags & wire::OUT_TRUNC != 0 || take < bytes.len() {
                        message.flags |= MSG_TRUNC;
                    }
                }
                total += take;
                // A peek reads the head of the queue again on each ask: one ask.
                if bytes.is_empty()
                    || !stream
                    || flags & (MSG_WAITALL | MSG_PEEK) != MSG_WAITALL
                    || total >= size
                {
                    break;
                }
            }
            message.count = total;
            Ok(message)
        },
    );
    finish(point, &result);
    result
}

/// A read of the description (`read` on the descriptor): up to
/// `out.len()` bytes, DATA_MAX at most; 0 at the end of the stream.
#[inline(never)]
pub fn read(description: u32, out: &mut [u8]) -> Result<usize, i32> {
    if out.is_empty() {
        return Ok(0);
    }
    let most = out.len().min(DATA_MAX) as u32;
    let mut reply = [0u8; MESSAGE_MAX];
    let n = run(
        true,
        |key| Request::Recv {
            key,
            description,
            flags: 0,
            most,
        },
        &mut reply,
    )?;
    let (_, _, bytes) = wire::read_received(&reply[..n]).map_err(|_| EIO)?;
    let n = bytes.len().min(out.len());
    out[..n].copy_from_slice(&bytes[..n]);
    Ok(n)
}

/// A read of a stream socket `fd` of more than DATA_MAX bytes through a cell
/// of the shared buffer (`read` on the descriptor): None when `fd` is no
/// stream of the service, or no cell is to be had; the read then goes by
/// messages.
pub fn read_large(fd: i32, out: &mut [u8]) -> Option<Result<usize, i32>> {
    if out.len() <= DATA_MAX || !is_net(fd) {
        return None;
    }
    let read = with_net(fd, |net| {
        if !net.stream {
            return Ok(None);
        }
        let Some(mut cell) = netbuf::cell(out.len()) else {
            return Ok(None);
        };
        let (_, _, count) = recv_cell(net.description, 0, &cell, out.len())?;
        out[..count].copy_from_slice(&cell.bytes()[..count]);
        Ok(Some(count))
    });
    match read {
        Ok(None) => None,
        Ok(Some(n)) => Some(Ok(n)),
        Err(errno) => Some(Err(errno)),
    }
}

/// writev of a stream socket `fd` as one send (relibc's writev asks first):
/// None for any other descriptor.
pub fn writev(fd: i32, iov: &[&[u8]]) -> Option<Result<usize, i32>> {
    if !is_net(fd) {
        return None;
    }
    let stream = with_net(fd, |net| Ok(net.stream)).ok()?;
    if !stream {
        return None;
    }
    Some(send(fd, 0, None, iov, &[]))
}

/// A write of `bytes` to the description (`write` on the descriptor): all of
/// them unless a signal or O_NONBLOCK stops it after some; EPIPE comes
/// before any byte went, and the caller follows it with SIGPIPE.
#[inline(never)]
pub fn write(description: u32, bytes: &[u8]) -> Result<usize, i32> {
    if bytes.is_empty() {
        return Ok(0);
    }
    send_all(description, 0, Address::NONE, bytes)
}

/// F_GETFL (`set` None) or F_SETFL of a socket's description: its flags, or
/// 0 once set. O_NONBLOCK belongs to the description, which every process
/// that holds it shares.
pub fn status_flags(description: u32, set: Option<i32>) -> Result<i32, i32> {
    match set {
        None => {
            let nonblock = word(&Request::GetOpt {
                description,
                name: opt::NONBLOCK,
            })?;
            Ok(O_RDWR | if nonblock != 0 { O_NONBLOCK } else { 0 })
        }
        Some(flags) => set_nonblock(description, flags & O_NONBLOCK != 0).map(|()| 0),
    }
}

/// FIONBIO and F_SETFL: the description's non-blocking flag.
pub fn set_nonblock(description: u32, on: bool) -> Result<(), i32> {
    simple(&Request::SetOpt {
        description,
        name: opt::NONBLOCK,
        value: u32::from(on),
    })
}

/// FIONREAD of a socket: the bytes of a stream waiting to be read, or the
/// length of the next datagram (0 with none).
pub fn readable(fd: i32) -> Result<u32, i32> {
    with_socket(fd, |description| {
        word(&Request::GetOpt {
            description,
            name: opt::NREAD,
        })
    })
}

/// FIONBIO of the descriptor `fd`.
pub fn nonblocking(fd: i32, on: bool) -> Result<(), i32> {
    with_socket(fd, |description| set_nonblock(description, on))
}
