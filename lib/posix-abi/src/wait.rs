// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Bounded descriptor readiness. Pins outlive every service registration;
//! no file-table lock spans IPC. Ready registrations live until Cancel.

use crate::{constants::*, shared, signals, threads};
use core::sync::atomic::{AtomicU64, Ordering};
use posix_fs::{Target, Transport};
use posix_types::PollFd;
use proto_wire::{Reader, Status, Writer, long, watch};
use rt::abi::{Error, Rights};
use rt::handle::{Channel, Handle, Timer};
use rt::sys;

/// The descriptions one poll or select takes on the direct path: the holds of
/// the table (each entry of a poll holds its description while the poll waits).
/// A Watch of a service takes `watch::MAX` of them at most, so a poll splits its
/// set into several Watches of the same service (as it does for the terminal).
pub const POLL_INLINE: usize = posix_fs::HOLDS_MAX;
pub const MAX: usize = POLL_INLINE;
const LIMIT: usize = MAX;
const _: () = assert!(LIMIT >= watch::MAX && LIMIT <= 256);

static NEXT: AtomicU64 = AtomicU64::new(1);
const TAG: u64 = 1 << 63;

/// The absolute counter deadline, taken from the invocation's start.
pub fn deadline(nanos: Option<u64>) -> Result<Option<u64>, i32> {
    nanos
        .map(|n| now().checked_add(n).ok_or(EINVAL))
        .transpose()
}
pub fn now() -> u64 {
    rt::time::ticks_to_ns(rt::time::now())
}

struct Pins {
    targets: [Option<Target>; LIMIT],
    loans: [Option<(posix_fd::IoToken, posix_fd::OwnerToken)>; LIMIT],
    transport: Option<Transport>,
}
impl Pins {
    const BLANK: Self = Self {
        targets: [None; LIMIT],
        loans: [None; LIMIT],
        transport: None,
    };

    /// Holds the descriptions of `items`, in place (the table is large).
    fn fill(&mut self, items: &[PollFd], ready: &mut [u32; LIMIT]) -> Result<(), i32> {
        let pins = self;
        let mut numbers = [u32::MAX; LIMIT];
        for (number, item) in numbers.iter_mut().zip(items) {
            if item.fd >= 0 {
                *number = item.fd as u32;
            }
        }
        let owner = crate::relibc::open_owner()
            .ok()
            .and_then(|owner| posix_fd::OwnerToken::new(owner).ok());
        let frame = crate::change::frame();
        shared::with_descriptors(&numbers[..items.len()], |files| {
            pins.transport = Some(files.transport());
            for (index, item) in items.iter().enumerate() {
                if item.fd >= 0 {
                    let held = match files.target(item.fd as u32) {
                        Ok(Target::Fifo(_)) => {
                            let owner = owner.ok_or(EIO)?;
                            files.begin_fifo_io(owner, item.fd as u32, frame).map(
                                |(token, target)| {
                                    pins.loans[index] = Some((token, owner));
                                    target
                                },
                            )
                        }
                        Ok(_) => files.hold(item.fd as u32),
                        Err(error) => Err(error),
                    };
                    match held.map_err(crate::error) {
                        Ok(target) => pins.targets[index] = Some(target),
                        Err(EBADF) => ready[index] = watch::NVAL,
                        Err(error) => return Err(error),
                    }
                }
            }
            Ok(())
        })
    }
}
impl Drop for Pins {
    fn drop(&mut self) {
        let Some(transport) = self.transport else {
            return;
        };
        for (index, target) in self.targets.iter_mut().enumerate() {
            let Some(target) = target.take() else {
                continue;
            };
            if let Some((token, owner)) = self.loans[index].take() {
                crate::fifo_io::finish(token, owner);
            } else if let Ok(Some(release)) = shared::with_files(|files| Ok(files.unhold(target))) {
                while transport.release(Some(release)).map_err(crate::error) == Err(EINTR) {}
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Service {
    Pipe,
    Terminal,
    Net,
}
impl Service {
    /// The header of the operation: 0 starts a Watch, 1 takes it, 2
    /// cancels it. The network service numbers the three apart.
    fn method(self, operation: u16) -> proto_wire::Header {
        const NET: [proto_net::Method; 3] = [
            proto_net::Method::Watch,
            proto_net::Method::WatchTake,
            proto_net::Method::WatchCancel,
        ];
        if let Self::Net = self {
            return NET[usize::from(operation)].header();
        }
        proto_wire::Header::new(
            (match self {
                Self::Pipe => 14,
                _ => 25,
            }) + operation,
            match self {
                Self::Pipe => proto_pipe::VERSION,
                _ => proto_tty::VERSION,
            },
        )
    }
}

struct Subscription {
    service: Service,
    owner: u64,
    key: u64,
    armed: bool,
    /// Taken at the start of the turn: no second take before the sleep.
    fresh: bool,
    label: u64,
    set: proto_pipe::WatchSet,
    original: [u8; watch::MAX],
}
impl Subscription {
    const BLANK: Self = Self {
        service: Service::Pipe,
        owner: 0,
        key: 0,
        armed: false,
        fresh: false,
        label: 0,
        set: proto_pipe::WatchSet::new(),
        original: [0; watch::MAX],
    };
    fn add(&mut self, description: u32, events: u32, index: usize) {
        self.add_endpoint(
            proto_pipe::Endpoint {
                id: description,
                generation: 0,
            },
            events,
            index,
        );
    }
    fn add_endpoint(&mut self, endpoint: proto_pipe::Endpoint, events: u32, index: usize) {
        self.original[self.set.len] = index as u8;
        self.set.generations[self.set.len] = endpoint.generation;
        let description = endpoint.id;
        self.set.items[self.set.len] = watch::Item {
            description,
            events,
        };
        self.set.len += 1;
    }
    fn merge(&self, incoming: watch::Ready, ready: &mut [u32; LIMIT]) -> Result<(), i32> {
        if incoming.len != self.set.len {
            return Err(EIO);
        }
        for (event, index) in incoming.events[..incoming.len].iter().zip(&self.original) {
            ready[usize::from(*index)] |= event;
        }
        Ok(())
    }
    #[inline(never)]
    fn call(&self, request: &[u8], notify: Option<Handle<Channel>>) -> Result<Reply, i32> {
        let owner = Handle::<Channel>::borrowed(rt::abi::Handle(self.owner));
        let result = match notify {
            Some(notify) => sys::send_handles(&owner, request, [notify.erase()])
                .map_err(|refused| refused.error),
            None => sys::send(&owner, request),
        }
        .map_err(kernel_error)?;
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        match long::Reply::read(result.bytes(&mut buffer)) {
            Ok(long::Reply::Wait(key)) => Ok(Reply::Wait(key)),
            Ok(long::Reply::Armed) => Ok(Reply::Armed),
            Ok(long::Reply::Ready(bytes)) => watch::Ready::parse(Reader::new(bytes))
                .map(Reply::Ready)
                .map_err(|_| EIO),
            Err(Status::Kernel(Error::LimitReached)) => Err(EAGAIN),
            Err(Status::Kernel(error)) => Err(kernel_error(error)),
            Err(Status::Unknown(code)) if code == proto_pipe::AGAIN => Err(EAGAIN),
            _ => Err(EIO),
        }
    }
    fn start(&mut self, ready: &mut [u32; LIMIT]) -> Result<(), i32> {
        if self.set.len == 0 {
            return Ok(());
        }
        let mut body = Writer::new();
        self.service.method(0).write(&mut body).map_err(|_| EIO)?;
        match self.service {
            Service::Pipe => self.set.write(&mut body),
            Service::Terminal | Service::Net => watch::Set {
                len: self.set.len,
                items: self.set.items,
            }
            .write(&mut body),
        }
        .map_err(|_| EIO)?;
        match self.call(body.as_bytes(), None)? {
            Reply::Wait(key) => {
                self.key = key;
                Ok(())
            }
            Reply::Ready(value) => self.merge(value, ready),
            _ => Err(EIO),
        }
    }
    fn keyed(&self, operation: u16) -> Result<Writer, i32> {
        let mut body = Writer::new();
        self.service
            .method(operation)
            .write(&mut body)
            .map_err(|_| EIO)?;
        body.u64(self.key).map_err(|_| EIO)?;
        Ok(body)
    }
    fn take(
        &mut self,
        channel: &Handle<Channel>,
        level: u8,
        ready: &mut [u32; LIMIT],
    ) -> Result<(), i32> {
        if self.key == 0 {
            return Ok(());
        }
        // Keep one notification session for the registration. Replacing it
        // on every Take closes the previous session and emits CLIENT_GONE
        // to this channel, which would wake an empty poll repeatedly.
        let notify = if self.armed {
            None
        } else {
            Some(
                sys::handle_label(
                    channel,
                    Rights::NOTIFY | Rights::TRANSFER,
                    self.label,
                    level,
                )
                .map_err(kernel_error)?,
            )
        };
        match self.call(self.keyed(1)?.as_bytes(), notify)? {
            Reply::Ready(value) => {
                self.armed = true;
                self.merge(value, ready)
            }
            Reply::Armed => {
                self.armed = true;
                Ok(())
            }
            _ => Err(EIO),
        }
    }
    fn cancel(&mut self, ready: &mut [u32; LIMIT]) -> Result<(), i32> {
        if self.key == 0 {
            return Ok(());
        }
        let body = self.keyed(2)?;
        loop {
            match self.call(body.as_bytes(), None) {
                // Interrupted means the request never reached the service.
                Err(EINTR) => continue,
                Ok(Reply::Ready(value)) => {
                    self.key = 0;
                    return self.merge(value, ready);
                }
                Err(EIO) => return Err(EIO),
                _ => return Err(EIO),
            }
        }
    }
}
impl Drop for Subscription {
    fn drop(&mut self) {
        if self.key != 0 && self.cancel(&mut [0; LIMIT]).is_err() {
            // No owner/key is discarded after an unconfirmed cleanup.
            // A fatal protocol failure closes this process's sessions.
            panic!("readiness watch cleanup was not confirmed");
        }
    }
}
enum Reply {
    Wait(u64),
    Armed,
    Ready(watch::Ready),
}
fn kernel_error(error: Error) -> i32 {
    match error {
        Error::Interrupted => EINTR,
        Error::LimitReached => EAGAIN,
        _ => EIO,
    }
}

/// The wait of the network service for the ready records of an interest set
/// (EPOLL_WAIT): one more subscription of `run`, whose answers are the pairs
/// of the records that were ready (the service takes them off its list when
/// it answers READY, so a cancel loses none).
pub struct NetWait {
    set: u32,
    most: u32,
    key: u64,
    armed: bool,
    fresh: bool,
    label: u64,
    /// The pairs taken: the label of a record and its events.
    pub ready: proto_net::sockets::EpollReady,
}

// The pairs of a READY are the one large variant, and a reply lives on the stack
// for the length of one call.
#[allow(clippy::large_enum_variant)]
enum NetReply {
    Wait(u64),
    Armed,
    Ready(proto_net::sockets::EpollReady),
    Cancelled,
}

/// The errno of a refusal of the network service on the wait.
fn net_refusal(status: Status) -> i32 {
    match status {
        Status::Kernel(Error::LimitReached) => EAGAIN,
        Status::Kernel(error) => kernel_error(error),
        Status::Unknown(code) => match code {
            proto_net::BAD_FD => EBADF,
            proto_net::AGAIN => EAGAIN,
            _ => EIO,
        },
        _ => EIO,
    }
}

impl NetWait {
    /// A wait on `set` for at most `most` pairs (1 to 64).
    pub fn new(set: u32, most: u32) -> Self {
        Self {
            set,
            most,
            key: 0,
            armed: false,
            fresh: false,
            label: 0,
            ready: proto_net::sockets::EpollReady::EMPTY,
        }
    }

    fn call(
        &self,
        request: &proto_net::sockets::Request<'_>,
        notify: Option<Handle<Channel>>,
    ) -> Result<NetReply, i32> {
        use proto_net::sockets::EpollReady;
        let mut body = Writer::new();
        request.write(&mut body).map_err(|_| EIO)?;
        let session = crate::net::session().ok_or(EBADF)?;
        let owner = Handle::<Channel>::borrowed(session);
        let result = match notify {
            Some(notify) => sys::send_handles(&owner, body.as_bytes(), [notify.erase()])
                .map_err(|refused| refused.error),
            None => sys::send(&owner, body.as_bytes()),
        }
        .map_err(kernel_error)?;
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        match long::Reply::read(result.bytes(&mut buffer)) {
            Ok(long::Reply::Wait(key)) => Ok(NetReply::Wait(key)),
            Ok(long::Reply::Armed) => Ok(NetReply::Armed),
            Ok(long::Reply::Cancelled) => Ok(NetReply::Cancelled),
            Ok(long::Reply::Ready(bytes)) => EpollReady::parse(bytes)
                .map(NetReply::Ready)
                .map_err(|_| EIO),
            Err(status) => Err(net_refusal(status)),
        }
    }

    fn wait_request(&self, key: Option<u64>, flags: u32) -> proto_net::sockets::Request<'static> {
        proto_net::sockets::Request::EpollWait {
            key,
            set: self.set,
            most: self.most,
            flags,
        }
    }

    fn start(&mut self) -> Result<(), i32> {
        match self.call(&self.wait_request(None, 0), None)? {
            NetReply::Wait(key) => {
                self.key = key;
                Ok(())
            }
            NetReply::Ready(ready) => {
                self.ready = ready;
                Ok(())
            }
            _ => Err(EIO),
        }
    }

    /// The next pairs without waiting: the records that are ready now are
    /// taken into `ready` in place of the pairs it had (a poll over many
    /// descriptors asks again while each answer is full). How many came.
    pub fn more(&mut self) -> Result<usize, i32> {
        match self.call(
            &self.wait_request(None, proto_net::sockets::EPOLL_DONTWAIT),
            None,
        )? {
            NetReply::Ready(ready) => {
                self.ready = ready;
                Ok(ready.len)
            }
            _ => Err(EIO),
        }
    }

    fn take(&mut self, channel: &Handle<Channel>, level: u8) -> Result<(), i32> {
        if self.key == 0 {
            return Ok(());
        }
        let notify = if self.armed {
            None
        } else {
            Some(
                sys::handle_label(
                    channel,
                    Rights::NOTIFY | Rights::TRANSFER,
                    self.label,
                    level,
                )
                .map_err(kernel_error)?,
            )
        };
        match self.call(&self.wait_request(Some(self.key), 0), notify)? {
            NetReply::Ready(ready) => {
                // The operation is over with its answer.
                self.key = 0;
                self.armed = false;
                self.ready = ready;
                Ok(())
            }
            NetReply::Armed => {
                self.armed = true;
                Ok(())
            }
            _ => Err(EIO),
        }
    }

    fn cancel(&mut self) -> Result<(), i32> {
        if self.key == 0 {
            return Ok(());
        }
        let request = proto_net::sockets::Request::Cancel(self.key);
        loop {
            match self.call(&request, None) {
                Err(EINTR) => continue,
                Ok(NetReply::Cancelled) => {
                    self.key = 0;
                    return Ok(());
                }
                // The set went (EPOLL_DROP, or the session): nothing waits.
                Err(EBADF) => {
                    self.key = 0;
                    return Ok(());
                }
                _ => return Err(EIO),
            }
        }
    }
}
impl Drop for NetWait {
    fn drop(&mut self) {
        let _ = self.cancel();
    }
}

/// The terminal descriptions placed in the Watches so far.
fn terminals_placed(subscriptions: &[Subscription]) -> usize {
    subscriptions[2..6].iter().map(|s| s.set.len).sum()
}

fn ready_count(ready: &[u32]) -> usize {
    ready.iter().filter(|&&events| events != 0).count()
}

/// Poll's core, with an absolute deadline supplied before mask/pending checks.
/// The outer C boundary owns cancellation and, for ppoll, the temporary mask.
fn run(
    items: &mut [PollFd],
    until: Option<u64>,
    handled: u64,
    selecting: bool,
    net: Option<&mut NetWait>,
) -> Result<usize, i32> {
    run_waking(items, until, handled, selecting, net, None)
}

/// `run` that also ends when `wake` says so. `wake` is asked at the top of
/// each round and again with the entries deferred, just before the receive
/// that sleeps: whatever it watches (the bank of the service's
/// notifications) is set by a receiver that runs outside this loop, and the
/// kernel keeps a notification until a receive takes it, so a notification
/// that comes after the second look ends the receive at once.
fn run_waking(
    items: &mut [PollFd],
    until: Option<u64>,
    handled: u64,
    selecting: bool,
    mut net: Option<&mut NetWait>,
    wake: Option<fn() -> bool>,
) -> Result<usize, i32> {
    let mut watching = Watching::BLANK;
    watching.build(items, selecting, net.as_deref_mut())?;
    let outcome = watching.turn(until, handled, wake, net.as_deref_mut());
    let closed = watching.close(net);
    closed?;
    outcome?;
    if threads::own_block().handled.load(Ordering::SeqCst) != handled
        || threads::cancel::requested()
    {
        return Err(EINTR);
    }
    Ok(watching.revents(items))
}

/// The subscriptions of a wait with the pins of its descriptors. One wait
/// that turns more than once (the loop of `epoll_pwait`) keeps them between
/// its turns, so that a turn costs a look at each service and not the
/// making and the cancelling of its subscriptions; the owner builds a new
/// one when its records change.
pub(crate) struct Watching {
    // The subscriptions go before the pins: they are cancelled while the
    // descriptions are still held.
    subscriptions: [Subscription; 8],
    timer: Option<Handle<Timer>>,
    pins: Pins,
    /// What the snapshot already knows (a descriptor that is not open).
    known: [u32; LIMIT],
    ready: [u32; LIMIT],
    len: usize,
    id: u64,
}

impl Watching {
    /// Nothing watched yet. The structure is large (the stack of a thread is
    /// not): it is made from this constant in its place, then `build`.
    pub(crate) const BLANK: Self = Self {
        subscriptions: [Subscription::BLANK; 8],
        timer: None,
        pins: Pins::BLANK,
        known: [0; LIMIT],
        ready: [0; LIMIT],
        len: 0,
        id: 0,
    };

    /// The subscriptions and the pins for `items`, in place; `net` gets its
    /// label.
    pub(crate) fn build(
        &mut self,
        items: &[PollFd],
        selecting: bool,
        net: Option<&mut NetWait>,
    ) -> Result<(), i32> {
        if items.len() > LIMIT {
            return Err(EINVAL);
        }
        let id = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                n.checked_add(1).filter(|next| *next < TAG >> 4)
            })
            .map_err(|_| EAGAIN)?;
        let mut ready = [0; LIMIT];
        self.pins.fill(items, &mut ready)?;
        let pins = &self.pins;
        let transport = pins.transport.ok_or(EIO)?;
        if let Some(net) = net {
            net.label = TAG | id << 4 | 9;
        }
        // The Watches of the pipe service take `watch::MAX` elements each, those of
        // the terminal service `proto_tty::WATCH_MAX` (`proto_tty::watch_group`),
        // those of the network service `watch::MAX` again; every one has a label
        // of its own. The low four bits of a label: 0 and 4 the pipes, 1, 3, 5
        // and 7 the terminal's, 2 the timer, 8 and 12 the network's, 9 its wait on
        // an interest set.
        const PIPE_WATCHES: usize = LIMIT.div_ceil(watch::MAX);
        const TERMINAL_WATCHES: usize = LIMIT.div_ceil(proto_tty::WATCH_MAX);
        const NET_WATCHES: usize = LIMIT.div_ceil(watch::MAX);
        const _: () = assert!(PIPE_WATCHES == 2 && TERMINAL_WATCHES == 4 && NET_WATCHES == 2);
        const PIPE_LABELS: [u64; PIPE_WATCHES] = [0, 4];
        const TERMINAL_LABELS: [u64; TERMINAL_WATCHES] = [1, 3, 5, 7];
        const NET_LABELS: [u64; NET_WATCHES] = [8, 12];
        let subscriptions = &mut self.subscriptions;
        for (slot, (service, label)) in subscriptions.iter_mut().zip([
            (Service::Pipe, PIPE_LABELS[0]),
            (Service::Pipe, PIPE_LABELS[1]),
            (Service::Terminal, TERMINAL_LABELS[0]),
            (Service::Terminal, TERMINAL_LABELS[1]),
            (Service::Terminal, TERMINAL_LABELS[2]),
            (Service::Terminal, TERMINAL_LABELS[3]),
            (Service::Net, NET_LABELS[0]),
            (Service::Net, NET_LABELS[1]),
        ]) {
            *slot = Subscription::BLANK;
            slot.service = service;
            slot.label = TAG | id << 4 | label;
        }
        for (index, (item, target)) in items.iter().zip(&pins.targets).enumerate() {
            let requested = (item.events as u16 as u32) & watch::EVENTS;
            if selecting && ready[index] == watch::NVAL {
                return Err(EBADF);
            }
            if selecting && requested & watch::PRI != 0 && matches!(target, Some(Target::Ram(_))) {
                let target = (*target).ok_or(EIO)?;
                let regular = transport.fstat(target).map_err(crate::error)?.kind
                    == posix_fs::FileKind::Regular;
                ready[index] =
                    requested & (watch::READ | watch::WRITE | if regular { watch::PRI } else { 0 });
                continue;
            }
            if selecting && requested & (watch::READ | watch::WRITE) == 0 {
                continue;
            }
            match target {
                Some(Target::Pipe(end)) => {
                    let at = (subscriptions[0].set.len + subscriptions[1].set.len) / watch::MAX;
                    subscriptions[at].owner = transport.pipes().map_err(crate::error)?.raw().0;
                    subscriptions[at].add(*end, requested, index);
                }
                Some(Target::Fifo(target)) => {
                    let at = (subscriptions[0].set.len + subscriptions[1].set.len) / watch::MAX;
                    subscriptions[at].owner = transport.pipes().map_err(crate::error)?.raw().0;
                    subscriptions[at].add_endpoint(target.endpoint(), requested, index);
                }
                Some(Target::Tty(terminal)) => {
                    let group = proto_tty::watch_group(terminals_placed(&*subscriptions));
                    let owner = transport.terminal().ok_or(EBADF)?.raw().0;
                    subscriptions[2 + group].owner = owner;
                    subscriptions[2 + group].add(*terminal, requested, index);
                }
                Some(Target::Input | Target::Output | Target::Error)
                    if transport.terminal().is_some() =>
                {
                    let group = proto_tty::watch_group(terminals_placed(&*subscriptions));
                    let owner = transport.terminal().ok_or(EIO)?.raw().0;
                    subscriptions[2 + group].owner = owner;
                    subscriptions[2 + group].add(proto_tty::CONSOLE, requested, index);
                }
                Some(Target::Net(description)) => {
                    let at = 6 + (subscriptions[6].set.len + subscriptions[7].set.len) / watch::MAX;
                    subscriptions[at].owner = crate::net::session().ok_or(EBADF)?.0;
                    // The service knows POLLRDHUP of a stream.
                    let rdhup = item.events as u16 as u32 & watch::RDHUP;
                    subscriptions[at].add(description.description, requested | rdhup, index);
                }
                // A poll of an epoll descriptor reports POLLERR: a departure from
                // Linux, which reports POLLIN when records are ready (nesting is not
                // supported).
                Some(Target::Epoll(_)) => ready[index] = watch::ERR,
                Some(_) => ready[index] = requested & (watch::READ | watch::WRITE),
                None => {}
            }
        }
        self.known = ready;
        self.ready = ready;
        self.len = items.len();
        self.id = id;
        self.timer = None;
        Ok(())
    }

    /// One turn: waits until a descriptor is ready, `until` comes, `wake`
    /// says so or a signal needs the caller. What is ready is in `revents`
    /// after it. The subscriptions of an earlier turn stay (a turn looks at
    /// each with one call); `close` cancels them.
    pub(crate) fn turn(
        &mut self,
        until: Option<u64>,
        handled: u64,
        wake: Option<fn() -> bool>,
        mut net: Option<&mut NetWait>,
    ) -> Result<(), i32> {
        let block = threads::own_block();
        let channel =
            Handle::<Channel>::borrowed(rt::abi::Handle(block.channel.load(Ordering::Relaxed)));
        let level = (block.base_level.load(Ordering::Relaxed) as u8).max(1);
        let id = self.id;
        self.ready = self.known;
        let len = self.len;
        let outcome = (|| {
            if signals::pending_unblocked() {
                signals::deliver_now();
            }
            if block.handled.load(Ordering::SeqCst) != handled || threads::cancel::requested() {
                return Err(EINTR);
            }
            // A look at each service: what is not started starts, what is
            // started is taken (the answer is what is ready now).
            for subscription in &mut self.subscriptions {
                subscription.fresh = false;
                loop {
                    let ready = &mut self.ready;
                    let step = if subscription.key == 0 {
                        subscription.start(ready)
                    } else {
                        subscription.fresh = true;
                        subscription.take(&channel, level, ready)
                    };
                    match step {
                        Err(EINTR)
                            if block.handled.load(Ordering::SeqCst) == handled
                                && !threads::cancel::requested() =>
                        {
                            continue;
                        }
                        result => {
                            result?;
                            break;
                        }
                    }
                }
            }
            if let Some(net) = net.as_deref_mut() {
                net.fresh = false;
                loop {
                    let step = if net.key == 0 {
                        net.start()
                    } else {
                        net.fresh = true;
                        net.take(&channel, level)
                    };
                    match step {
                        Err(EINTR)
                            if block.handled.load(Ordering::SeqCst) == handled
                                && !threads::cancel::requested() =>
                        {
                            continue;
                        }
                        result => {
                            result?;
                            break;
                        }
                    }
                }
            }
            loop {
                if signals::pending_unblocked() {
                    signals::deliver_now();
                }
                if block.handled.load(Ordering::SeqCst) != handled || threads::cancel::requested() {
                    return Err(EINTR);
                }
                if ready_count(&self.ready[..len]) != 0
                    || net.as_deref().is_some_and(|n| n.ready.len != 0)
                    || until.is_some_and(|deadline| now() >= deadline)
                    || wake.is_some_and(|w| w())
                {
                    return Ok(());
                }
                for subscription in &mut self.subscriptions {
                    if core::mem::take(&mut subscription.fresh) {
                        continue;
                    }
                    loop {
                        match subscription.take(&channel, level, &mut self.ready) {
                            Err(EINTR)
                                if block.handled.load(Ordering::SeqCst) == handled
                                    && !threads::cancel::requested() =>
                            {
                                continue;
                            }
                            result => {
                                result?;
                                break;
                            }
                        }
                    }
                }
                if let Some(net) = net.as_deref_mut() {
                    if core::mem::take(&mut net.fresh) {
                        // Taken a moment ago.
                    } else {
                        loop {
                            match net.take(&channel, level) {
                                Err(EINTR)
                                    if block.handled.load(Ordering::SeqCst) == handled
                                        && !threads::cancel::requested() =>
                                {
                                    continue;
                                }
                                result => {
                                    result?;
                                    break;
                                }
                            }
                        }
                    }
                }
                if ready_count(&self.ready[..len]) != 0
                    || net.as_deref().is_some_and(|n| n.ready.len != 0)
                {
                    continue;
                }
                signals::probe_window(signals::window::POLL);
                let guard = rt::upcall::defer_entries().map_err(|_| EIO)?;
                if block.handled.load(Ordering::SeqCst) != handled
                    || signals::pending_unblocked()
                    || threads::cancel::requested()
                {
                    drop(guard);
                    continue;
                }
                if wake.is_some_and(|w| w()) {
                    drop(guard);
                    return Ok(());
                }
                if let Some(until) = until {
                    if self.timer.is_none() {
                        let labelled =
                            sys::handle_label(&channel, Rights::RECEIVE, TAG | id << 4 | 2, level)
                                .map_err(kernel_error)?;
                        self.timer =
                            Some(sys::timer_create(&labelled, level).map_err(kernel_error)?);
                    }
                    sys::timer_set(self.timer.as_ref().ok_or(EIO)?, until).map_err(kernel_error)?;
                }
                let incoming = crate::fast::receive(&channel);
                drop(guard);
                match incoming {
                    Ok(_) | Err(Error::Interrupted) => {}
                    Err(error) => return Err(kernel_error(error)),
                }
                // Woken: the next round takes each subscription again.
                for subscription in &mut self.subscriptions {
                    subscription.fresh = false;
                }
                if let Some(net) = net.as_deref_mut() {
                    net.fresh = false;
                }
            }
        })();
        if let Some(timer) = self.timer.as_ref() {
            let _ = sys::timer_cancel(timer);
        }
        outcome
    }

    /// Cancels every subscription (and `net`'s wait) and empties what late
    /// wakeups left on the thread's channel. The first error of the
    /// cancelling, after all were tried.
    pub(crate) fn close(&mut self, net: Option<&mut NetWait>) -> Result<(), i32> {
        // Every subscription cancels even after partial registration or an early error.
        let mut cleanup_error = None;
        for subscription in &mut self.subscriptions {
            if let Err(error) = subscription.cancel(&mut [0; LIMIT]) {
                cleanup_error.get_or_insert(error);
            }
        }
        if let Some(net) = net
            && let Err(error) = net.cancel()
        {
            cleanup_error.get_or_insert(error);
        }
        self.timer = None;
        // Late wakeups and the CLIENT_GONE of the sessions above stay queued on the
        // thread's channel and each holds a source place; drain them so the places
        // of the next wait are free.
        let block = threads::own_block();
        let channel =
            Handle::<Channel>::borrowed(rt::abi::Handle(block.channel.load(Ordering::Relaxed)));
        for _ in 0..rt::abi::MAX_SLOTS {
            if crate::fast::try_receive(&channel).is_err() {
                break;
            }
        }
        cleanup_error.map_or(Ok(()), Err)
    }

    /// The events that came, into the entries; how many entries have some.
    pub(crate) fn revents(&self, items: &mut [PollFd]) -> usize {
        // A socket of the pipe service whose peer went says POLLRDHUP with its
        // POLLHUP, as Linux's AF_UNIX sockets do.
        let mut ready = self.ready;
        for ((item, events), target) in items
            .iter_mut()
            .zip(ready.iter_mut())
            .zip(&self.pins.targets)
        {
            let unix =
                matches!(target, Some(Target::Pipe(end)) if end & proto_pipe::sock::SOCK_END != 0);
            if unix && *events & watch::HUP != 0 {
                *events |= item.events as u16 as u32 & POLLRDHUP;
            }
            item.revents = *events as i16;
        }
        ready_count(&ready[..self.len])
    }
}

/// A cancellation boundary shared by the four C readiness interfaces.
/// `duration` is relative nanoseconds; the temporary mask spans all cleanup.
pub(crate) fn boundary<T>(
    duration: Option<u64>,
    mask: Option<u64>,
    mut operation: impl FnMut(Option<u64>, u64) -> Result<T, i32>,
) -> Result<T, i32> {
    let point = threads::cancel::Point::begin();
    let handled = threads::own_block().handled.load(Ordering::SeqCst);
    let result = deadline(duration).and_then(|until| {
        let old = mask.map(signals::swap_mask);
        let result = loop {
            let result = operation(until, handled);
            if !matches!(result, Err(EINTR))
                || threads::own_block().handled.load(Ordering::SeqCst) != handled
                || threads::cancel::requested()
            {
                break result;
            }
        };
        if let Some(old) = old {
            signals::swap_mask(old);
        }
        if threads::own_block().handled.load(Ordering::SeqCst) != handled
            || threads::cancel::requested()
        {
            Err(EINTR)
        } else {
            result
        }
    });
    point.finish();
    result
}

pub fn poll(items: &mut [PollFd], duration: Option<u64>, mask: Option<u64>) -> Result<usize, i32> {
    // A fast socket is not waited for here: the stack's `epoll` is the way.
    if crate::fastnet::registered()
        && items
            .iter()
            .any(|item| crate::fastnet::classify(item.fd).is_some())
    {
        return Err(EINVAL);
    }
    boundary(duration, mask, |until, handled| {
        engine(items, until, handled, false)
    })
}

/// The entries of an epoll wait on the other descriptors, and the wait of the
/// service's set with them (`epoll::pwait`): `run` with the set's wait.
pub(crate) fn run_net(
    items: &mut [PollFd],
    net: Option<&mut NetWait>,
    until: Option<u64>,
    handled: u64,
) -> Result<usize, i32> {
    run_waking(items, until, handled, false, net, None)
}

/// POLLRDHUP of Linux: the peer of a stream shut its writing or went.
pub const POLLRDHUP: u32 = watch::RDHUP;

/// The most entries a poll or select takes: the descriptors of a process.
pub const MAX_LARGE: usize = posix_fs::OPEN_MAX;

/// Up to `MAX` entries go the direct way (the holds and the Watches); more
/// go through the engine of epoll, with a set of the network service for the
/// sockets (`large`).
fn engine(
    items: &mut [PollFd],
    until: Option<u64>,
    handled: u64,
    selecting: bool,
) -> Result<usize, i32> {
    if items.len() <= LIMIT {
        run(items, until, handled, selecting, None)
    } else if items.len() <= MAX_LARGE {
        large(items, until, handled, selecting)
    } else {
        Err(EINVAL)
    }
}

/// The work space of a large poll: for each descriptor number the first
/// entry that names it (plus one), the events asked for (the union over the
/// entries that name it) and the events that came.
#[repr(C)]
struct Work {
    first: [u16; MAX_LARGE],
    asked: [u16; MAX_LARGE],
    got: [u16; MAX_LARGE],
    /// For a descriptor number that names a socket the description of which
    /// an earlier number has, that number plus one: the service keeps one
    /// record for a description, and the events of the record are the
    /// numbers' alike.
    alias: [u16; MAX_LARGE],
    /// For each place of the service's table, the first number that names a
    /// description there, plus one.
    owner_of_place: [u16; 1 << proto_net::sockets::SLOT_BITS],
}
const WORK_PAGES: usize = core::mem::size_of::<Work>().div_ceil(4096) * 4096;

/// A poll or select over more than `MAX` entries (spec 6, 3.4): a temporary
/// interest set in the network service holds the sockets, the other
/// descriptors (at most `MAX` of them, EAGAIN past that) go the direct way,
/// and one wait takes both. By level, one record for each number.
#[inline(never)]
fn large(
    items: &mut [PollFd],
    until: Option<u64>,
    handled: u64,
    selecting: bool,
) -> Result<usize, i32> {
    let page = crate::allocation::map_pages(WORK_PAGES).map_err(|_| EAGAIN)?;
    // SAFETY: zeroed pages of the size of `Work`, this call's alone.
    let work = unsafe { &mut *page.as_ptr().cast::<Work>() };
    let mut net = NetWait::new(0, 64);
    let result = large_in(items, until, handled, selecting, work, &mut net);
    if net.set != 0 {
        crate::net::epoll_drop(net.set);
    }
    // SAFETY: the pages came from `map_pages` and nothing uses them now.
    unsafe { crate::allocation::unmap_pages(page, WORK_PAGES) };
    result
}

fn large_in(
    items: &mut [PollFd],
    until: Option<u64>,
    handled: u64,
    selecting: bool,
    work: &mut Work,
    net: &mut NetWait,
) -> Result<usize, i32> {
    use proto_net::sockets::{self as wire, EpollList, EpollRecord};
    let mut others = [PollFd::default(); LIMIT];
    let mut other_fd = [0u16; LIMIT];
    let mut others_len = 0;
    // The first entry of each number, the union of the events asked.
    for (k, item) in items.iter().enumerate() {
        let fd = item.fd;
        if fd < 0 || fd as usize >= MAX_LARGE {
            continue;
        }
        let fd = fd as usize;
        if work.first[fd] == 0 {
            work.first[fd] = k as u16 + 1;
        }
        work.asked[fd] |= item.events as u16 & (watch::EVENTS | POLLRDHUP) as u16;
    }
    let mut records = [EpollRecord::default(); wire::EPOLL_BATCH];
    let mut count = 0;
    let mut invalid = false;
    let session = crate::net::session();
    // The records of a batch go in one EPOLL_SET; the first makes the set.
    let send = |records: &[EpollRecord], net: &mut NetWait| -> Result<(), i32> {
        if records.is_empty() {
            return Ok(());
        }
        let list = EpollList::new(records).ok_or(EIO)?;
        let mut out = [0u32; wire::EPOLL_BATCH];
        net.set = crate::net::epoll_set(net.set, list, &mut out)?;
        // A description that closed meanwhile is not an error of the poll.
        if out[..records.len()]
            .iter()
            .any(|&status| status != 0 && status != proto_net::BAD_FD)
        {
            return Err(EAGAIN);
        }
        Ok(())
    };
    // The targets in groups of 64 under one lock each.
    let mut start = 0;
    while start < items.len() {
        let end = (start + 64).min(items.len());
        let mut targets = [None; 64];
        let mut numbers = [u32::MAX; 64];
        for (k, item) in items[start..end].iter().enumerate() {
            let fd = item.fd;
            if fd >= 0
                && (fd as usize) < MAX_LARGE
                && work.first[fd as usize] == (start + k) as u16 + 1
            {
                numbers[k] = fd as u32;
            }
        }
        shared::with_descriptors(&numbers[..end - start], |files| {
            for (k, &fd) in numbers[..end - start].iter().enumerate() {
                if fd != u32::MAX {
                    targets[k] = Some(files.target(fd).ok());
                }
            }
            Ok(())
        })?;
        for (k, target) in targets[..end - start].iter().enumerate() {
            let Some(target) = *target else { continue };
            let at = start + k;
            let fd = items[at].fd as usize;
            match target {
                None => {
                    invalid = true;
                    work.got[fd] |= watch::NVAL as u16;
                }
                Some(Target::Net(n)) if session.is_some() => {
                    let place = wire::slot(n.description);
                    let owner = usize::from(work.owner_of_place[place]);
                    if owner != 0 {
                        // Another number of the same description: its events
                        // join the record of that number (a MOD).
                        work.alias[fd] = owner as u16;
                        let first = usize::from(work.first[owner - 1]) - 1;
                        work.asked[owner - 1] |= work.asked[fd];
                        records[count] = EpollRecord {
                            action: wire::EPOLL_MOD,
                            description: n.description,
                            events: u32::from(work.asked[owner - 1]),
                            label: first as u32,
                        };
                        count += 1;
                        if count == records.len() {
                            send(&records[..count], net)?;
                            count = 0;
                        }
                        continue;
                    }
                    work.owner_of_place[place] = fd as u16 + 1;
                    records[count] = EpollRecord {
                        action: wire::EPOLL_ADD,
                        description: n.description,
                        events: u32::from(work.asked[fd]),
                        label: at as u32,
                    };
                    count += 1;
                    if count == records.len() {
                        send(&records[..count], net)?;
                        count = 0;
                    }
                }
                Some(_) => {
                    // At most `LIMIT` other descriptors: EAGAIN past that.
                    if others_len == LIMIT {
                        return Err(EAGAIN);
                    }
                    others[others_len] = PollFd {
                        fd: fd as i32,
                        events: work.asked[fd] as i16,
                        revents: 0,
                    };
                    other_fd[others_len] = fd as u16;
                    others_len += 1;
                }
            }
        }
        start = end;
    }
    send(&records[..count], net)?;
    if invalid && selecting {
        return Err(EBADF);
    }
    let with_net = net.set != 0;
    run(
        &mut others[..others_len],
        until,
        handled,
        selecting,
        with_net.then_some(&mut *net),
    )?;
    for k in 0..others_len {
        work.got[usize::from(other_fd[k])] |= others[k].revents as u16;
    }
    // The pairs came in answers of 64 at most: ask again while one was full.
    let mut absorbed = 0;
    loop {
        for &(label, events) in net.ready.as_slice() {
            let fd = items[label as usize].fd as usize;
            work.got[fd] |= events as u16;
        }
        absorbed += 1;
        if !with_net || net.ready.len < 64 || absorbed > MAX_LARGE / 64 + 1 {
            break;
        }
        if net.more()? == 0 {
            break;
        }
    }
    for item in items.iter() {
        let fd = item.fd;
        if fd >= 0 && (fd as usize) < MAX_LARGE && work.alias[fd as usize] != 0 {
            let owner = usize::from(work.alias[fd as usize]) - 1;
            work.got[fd as usize] |= work.got[owner];
        }
    }
    let mut total = 0;
    for item in items.iter_mut() {
        let fd = item.fd;
        item.revents = if fd < 0 {
            0
        } else if fd as usize >= MAX_LARGE || work.first[fd as usize] == 0 {
            watch::NVAL as i16
        } else {
            (u32::from(work.got[fd as usize]) & (item.events as u16 as u32 | watch::ALWAYS)) as i16
        };
        if item.revents != 0 {
            total += 1;
        }
    }
    Ok(total)
}

/// Select preserves input sets on failure and counts each returned set bit.
pub fn select(
    nfds: i32,
    sets: &mut [posix_types::FdSet; 3],
    duration: Option<u64>,
    mask: Option<u64>,
) -> Result<(usize, Option<u64>), i32> {
    boundary(duration, mask, |until, handled| {
        if !(0..=posix_types::FD_SETSIZE as i32).contains(&nfds) {
            return Err(EINVAL);
        }
        let named = (0..nfds as usize)
            .filter(|&fd| has(&sets[0], fd) || has(&sets[1], fd) || has(&sets[2], fd))
            .count();
        if (0..nfds as usize).any(|fd| {
            fd >= posix_fs::OPEN_MAX
                && (has(&sets[0], fd) || has(&sets[1], fd) || has(&sets[2], fd))
        }) {
            return Err(EBADF);
        }
        // Up to `LIMIT` entries live on the stack, more in pages of the heap.
        let mut small = [PollFd::default(); LIMIT];
        let pages = if named > LIMIT {
            let size = (named * core::mem::size_of::<PollFd>()).div_ceil(4096) * 4096;
            Some((
                crate::allocation::map_pages(size).map_err(|_| EAGAIN)?,
                size,
            ))
        } else {
            None
        };
        let items: &mut [PollFd] = match pages {
            // SAFETY: zeroed pages for `named` entries, this call's alone.
            Some((page, _)) => unsafe {
                core::slice::from_raw_parts_mut(page.as_ptr().cast::<PollFd>(), named)
            },
            None => &mut small[..named],
        };
        let mut count = 0;
        for fd in 0..nfds as usize {
            let bits = [has(&sets[0], fd), has(&sets[1], fd), has(&sets[2], fd)];
            if bits.iter().any(|&b| b) {
                items[count] = PollFd {
                    fd: fd as i32,
                    events: ((if bits[0] { watch::IN } else { 0 })
                        | (if bits[1] { watch::OUT } else { 0 })
                        | (if bits[2] { watch::PRI } else { 0 }))
                        as i16,
                    revents: 0,
                };
                count += 1;
            }
        }
        let polled = engine(&mut items[..count], until, handled, true);
        let items = &items[..count];
        let result = polled.map(|_| {
            let mut output = [[0; 16]; 3];
            let mut bits = 0;
            for item in items {
                let fd = item.fd as usize;
                let ready = item.revents as u16 as u32;
                for (set, events) in [
                    watch::IN | watch::HUP | watch::ERR,
                    watch::OUT | watch::ERR,
                    watch::PRI,
                ]
                .into_iter()
                .enumerate()
                {
                    if has(&sets[set], fd) && ready & events != 0 {
                        output[set][fd / 64] |= 1 << (fd % 64);
                        bits += 1;
                    }
                }
            }
            (output, bits)
        });
        if let Some((page, size)) = pages {
            // SAFETY: the pages came from `map_pages` and nothing uses them now.
            unsafe { crate::allocation::unmap_pages(page, size) };
        }
        let (output, bits) = result?;
        *sets = output;
        Ok((bits, until.map(|until| until.saturating_sub(now()))))
    })
}
fn has(set: &posix_types::FdSet, fd: usize) -> bool {
    set[fd / 64] & (1 << (fd % 64)) != 0
}

pub fn timespec(value: posix_types::Timespec) -> Result<u64, i32> {
    interval(value.tv_sec, value.tv_nsec, 1_000_000_000, 1)
}
pub fn timeval(value: posix_types::Timeval) -> Result<u64, i32> {
    interval(value.tv_sec, value.tv_usec, 1_000_000, 1_000)
}
fn interval(seconds: i64, fraction: i64, limit: i64, scale: u64) -> Result<u64, i32> {
    if seconds < 0 || !(0..limit).contains(&fraction) {
        return Err(EINVAL);
    }
    (seconds as u64)
        .checked_mul(1_000_000_000)
        .and_then(|s| s.checked_add(fraction as u64 * scale))
        .ok_or(EINVAL)
}
