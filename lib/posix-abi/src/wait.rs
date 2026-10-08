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

pub const MAX: usize = watch::MAX;

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
    targets: [Option<Target>; watch::MAX],
    transport: Option<Transport>,
}
impl Pins {
    fn snapshot(items: &[PollFd], ready: &mut [u32; watch::MAX]) -> Result<Self, i32> {
        let mut pins = Self {
            targets: [None; watch::MAX],
            transport: None,
        };
        shared::with_files(|files| {
            pins.transport = Some(files.transport());
            for (index, item) in items.iter().enumerate() {
                if item.fd >= 0 {
                    match files.hold(item.fd as u32).map_err(crate::error) {
                        Ok(target) => pins.targets[index] = Some(target),
                        Err(EBADF) => ready[index] = watch::NVAL,
                        Err(error) => return Err(error),
                    }
                }
            }
            Ok(())
        })?;
        Ok(pins)
    }
}
impl Drop for Pins {
    fn drop(&mut self) {
        let Some(transport) = self.transport else {
            return;
        };
        for target in self.targets.iter_mut().filter_map(Option::take) {
            if let Ok(Some(release)) = shared::with_files(|files| Ok(files.unhold(target))) {
                while transport.release(Some(release)).map_err(crate::error) == Err(EINTR) {}
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Service {
    Pipe,
    Terminal,
}
impl Service {
    fn method(self, operation: u16) -> proto_wire::Header {
        proto_wire::Header::new(
            (match self {
                Self::Pipe => 14,
                Self::Terminal => 25,
            }) + operation,
            match self {
                Self::Pipe => proto_pipe::VERSION,
                Self::Terminal => proto_tty::VERSION,
            },
        )
    }
}

struct Subscription {
    service: Service,
    owner: u64,
    key: u64,
    armed: bool,
    label: u64,
    set: watch::Set,
    original: [usize; watch::MAX],
}
impl Subscription {
    fn new(service: Service, label: u64) -> Self {
        Self {
            service,
            owner: 0,
            key: 0,
            armed: false,
            label,
            set: watch::Set::new(),
            original: [0; watch::MAX],
        }
    }
    fn add(&mut self, description: u32, events: u32, index: usize) {
        self.original[self.set.len] = index;
        self.set.items[self.set.len] = watch::Item {
            description,
            events,
        };
        self.set.len += 1;
    }
    fn merge(&self, incoming: watch::Ready, ready: &mut [u32; watch::MAX]) -> Result<(), i32> {
        if incoming.len != self.set.len {
            return Err(EIO);
        }
        for (event, index) in incoming.events[..incoming.len].iter().zip(&self.original) {
            ready[*index] |= event;
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
    fn start(&mut self, ready: &mut [u32; watch::MAX]) -> Result<(), i32> {
        if self.set.len == 0 {
            return Ok(());
        }
        let mut body = Writer::new();
        self.service.method(0).write(&mut body).map_err(|_| EIO)?;
        self.set.write(&mut body).map_err(|_| EIO)?;
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
        ready: &mut [u32; watch::MAX],
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
    fn cancel(&mut self, ready: &mut [u32; watch::MAX]) -> Result<(), i32> {
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
        if self.key != 0 && self.cancel(&mut [0; watch::MAX]).is_err() {
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
) -> Result<usize, i32> {
    if items.len() > watch::MAX {
        return Err(EINVAL);
    }
    let block = threads::own_block();
    let id = NEXT
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            n.checked_add(1).filter(|next| *next < TAG >> 3)
        })
        .map_err(|_| EAGAIN)?;
    let mut ready = [0; watch::MAX];
    let pins = Pins::snapshot(items, &mut ready)?;
    let transport = pins.transport.ok_or(EIO)?;
    // The pipes' Watch, then the terminal's Watches of WATCH_MAX elements
    // each (`proto_tty::watch_group`), every one with a label of its own.
    // The low three bits of a label: 0 the pipes, 1 and 3 the terminal's
    // Watches, 2 the timer.
    const _: () = assert!(proto_tty::WATCH_GROUPS == 2);
    let mut subscriptions = [
        Subscription::new(Service::Pipe, TAG | id << 3),
        Subscription::new(Service::Terminal, TAG | id << 3 | 1),
        Subscription::new(Service::Terminal, TAG | id << 3 | 3),
    ];
    for (index, (item, target)) in items.iter().zip(&pins.targets).enumerate() {
        let requested = (item.events as u16 as u32) & watch::EVENTS;
        if selecting && ready[index] == watch::NVAL {
            return Err(EBADF);
        }
        if selecting && requested & watch::PRI != 0 && matches!(target, Some(Target::Ram(_))) {
            let target = (*target).ok_or(EIO)?;
            let regular =
                transport.fstat(target).map_err(crate::error)?.kind == posix_fs::FileKind::Regular;
            ready[index] =
                requested & (watch::READ | watch::WRITE | if regular { watch::PRI } else { 0 });
            continue;
        }
        if selecting && requested & (watch::READ | watch::WRITE) == 0 {
            continue;
        }
        match target {
            Some(Target::Pipe(end)) => {
                subscriptions[0].owner = transport.pipes().map_err(crate::error)?.raw().0;
                subscriptions[0].add(*end, requested, index);
            }
            Some(Target::Tty(terminal)) => {
                let group =
                    proto_tty::watch_group(subscriptions[1].set.len + subscriptions[2].set.len);
                let owner = transport.terminal().ok_or(EBADF)?.raw().0;
                subscriptions[1 + group].owner = owner;
                subscriptions[1 + group].add(*terminal, requested, index);
            }
            Some(Target::Input | Target::Output | Target::Error)
                if transport.terminal().is_some() =>
            {
                let group =
                    proto_tty::watch_group(subscriptions[1].set.len + subscriptions[2].set.len);
                let owner = transport.terminal().ok_or(EIO)?.raw().0;
                subscriptions[1 + group].owner = owner;
                subscriptions[1 + group].add(proto_tty::CONSOLE, requested, index);
            }
            Some(_) => ready[index] = requested & (watch::READ | watch::WRITE),
            None => {}
        }
    }
    let channel =
        Handle::<Channel>::borrowed(rt::abi::Handle(block.channel.load(Ordering::Relaxed)));
    let level = (block.base_level.load(Ordering::Relaxed) as u8).max(1);
    let mut timer: Option<Handle<Timer>> = None;
    let outcome = (|| {
        if signals::pending_unblocked() {
            signals::deliver_now();
        }
        if block.handled.load(Ordering::SeqCst) != handled || threads::cancel::requested() {
            return Err(EINTR);
        }
        for subscription in &mut subscriptions {
            loop {
                match subscription.start(&mut ready) {
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
            if ready_count(&ready[..items.len()]) != 0
                || until.is_some_and(|deadline| now() >= deadline)
            {
                return Ok(());
            }
            for subscription in &mut subscriptions {
                loop {
                    match subscription.take(&channel, level, &mut ready) {
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
            if ready_count(&ready[..items.len()]) != 0 {
                continue;
            }
            let guard = rt::upcall::defer_entries().map_err(|_| EIO)?;
            if block.handled.load(Ordering::SeqCst) != handled
                || signals::pending_unblocked()
                || threads::cancel::requested()
            {
                drop(guard);
                continue;
            }
            if let Some(until) = until {
                if timer.is_none() {
                    let labelled =
                        sys::handle_label(&channel, Rights::RECEIVE, TAG | id << 3 | 2, level)
                            .map_err(kernel_error)?;
                    timer = Some(sys::timer_create(&labelled, level).map_err(kernel_error)?);
                }
                sys::timer_set(timer.as_ref().ok_or(EIO)?, until).map_err(kernel_error)?;
            }
            let incoming = sys::receive(&channel);
            drop(guard);
            match incoming {
                Ok(_) | Err(Error::Interrupted) => {}
                Err(error) => return Err(kernel_error(error)),
            }
        }
    })();
    if let Some(timer) = timer.as_ref() {
        let _ = sys::timer_cancel(timer);
    }
    // Every subscription cancels even after partial registration or an early error.
    let mut cleanup_error = None;
    for subscription in &mut subscriptions {
        if let Err(error) = subscription.cancel(&mut ready) {
            cleanup_error.get_or_insert(error);
        }
    }
    drop(subscriptions);
    drop(timer);
    drop(pins);
    if let Some(error) = cleanup_error {
        return Err(error);
    }
    outcome?;
    if block.handled.load(Ordering::SeqCst) != handled || threads::cancel::requested() {
        return Err(EINTR);
    }
    for (item, events) in items.iter_mut().zip(ready) {
        item.revents = events as i16;
    }
    Ok(ready_count(&ready[..items.len()]))
}

/// A cancellation boundary shared by the four C readiness interfaces.
/// `duration` is relative nanoseconds; the temporary mask spans all cleanup.
fn boundary<T>(
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
    boundary(duration, mask, |until, handled| {
        run(items, until, handled, false)
    })
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
        let mut items = [PollFd::default(); watch::MAX];
        let mut count = 0;
        for fd in 0..nfds as usize {
            let bits = [has(&sets[0], fd), has(&sets[1], fd), has(&sets[2], fd)];
            if bits.iter().any(|&b| b) {
                if fd >= posix_fs::OPEN_MAX {
                    return Err(EBADF);
                }
                if count == watch::MAX {
                    return Err(EINVAL);
                }
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
        run(&mut items[..count], until, handled, true)?;
        let mut output = [[0; 16]; 3];
        let mut bits = 0;
        for item in &items[..count] {
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
