// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Ordinary service requests exposed to the C protocol probe. Its caller
//! keeps every descriptor open until its WatchCancel has returned.

use core::sync::atomic::{AtomicU64, Ordering};
use posix_fs::{Target, Transport};
use proto_wire::{Reader, Status, Writer, long, watch};
use rt::abi::{Error, Rights};
use rt::handle::{Channel, Handle};
use rt::sys;
static NOTIFICATIONS: AtomicU64 = AtomicU64::new(0);
fn own_channel() -> Result<core::mem::ManuallyDrop<Handle<Channel>>, i32> {
    let mut raw = NOTIFICATIONS.load(Ordering::Acquire);
    if raw == 0 {
        raw = sys::channel_create(1).map_err(|_| 5)?.into_raw().0;
        NOTIFICATIONS.store(raw, Ordering::Release);
    }
    Ok(Handle::borrowed(rt::abi::Handle(raw)))
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_watch_bit(key: u64) -> i32 {
    let got: Result<i32, i32> = (|| {
        let channel = own_channel()?;
        loop {
            if let sys::Received::Notification {
                source: rt::abi::Source::Session,
                label,
                bits,
                ..
            } = sys::receive(&channel).map_err(|_| 5)?
                && label == key
                && bits & 1 != 0
            {
                return Ok(0);
            }
        }
    })();
    got.unwrap_or_else(|error| -error)
}
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_watch_close_channel() {
    let raw = NOTIFICATIONS.swap(0, Ordering::AcqRel);
    if raw != 0 {
        drop(Handle::<Channel>::from_raw(rt::abi::Handle(raw)));
    }
}

fn service<R>(
    fd: u32,
    run: impl FnOnce(&Handle<Channel>, u32, bool) -> Result<R, i32>,
) -> Result<R, i32> {
    posix_abi::shared::held(fd, |transport: Transport, target| match target {
        Target::Pipe(end) => {
            let channel = transport.pipes().map_err(|_| 5)?;
            run(&channel, end, false)
        }
        Target::Tty(terminal) => {
            let channel = transport.terminal().ok_or(5)?;
            run(&channel, terminal, true)
        }
        Target::Input | Target::Output | Target::Error => {
            let channel = transport.terminal().ok_or(5)?;
            run(&channel, proto_tty::CONSOLE, true)
        }
        _ => Err(22),
    })
}

fn method(terminal: bool, operation: u32) -> proto_wire::Header {
    proto_wire::Header::new(
        (if terminal { 25 } else { 14 }) + operation as u16,
        if terminal {
            proto_tty::VERSION
        } else {
            proto_pipe::VERSION
        },
    )
}

fn result(reply: rt::sys::Reply, key: &mut u64, out: &mut [u32]) -> Result<i32, i32> {
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    match long::Reply::read(reply.bytes(&mut buffer)) {
        Ok(long::Reply::Wait(value)) => {
            *key = value;
            Ok(1)
        }
        Ok(long::Reply::Armed) => Ok(1),
        Ok(long::Reply::Ready(bytes)) => {
            let ready = watch::Ready::parse(Reader::new(bytes)).map_err(|_| 5)?;
            if ready.len > out.len() {
                return Err(5);
            }
            out[..ready.len].copy_from_slice(&ready.events[..ready.len]);
            Ok(0)
        }
        Err(Status::Kernel(Error::LimitReached)) => Err(11),
        Err(status) if status.code() == proto_pipe::AGAIN => Err(11),
        Err(_) | Ok(long::Reply::Cancelled) => Err(5),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_watch_start(
    fds: *const u32,
    events: *const u32,
    count: u32,
    key: *mut u64,
    ready: *mut u32,
) -> i32 {
    if count == 0 || count as usize > watch::MAX {
        return -22;
    }
    let count = count as usize;
    // SAFETY: the C probe passes readable arrays and writable result storage.
    let (fds, events, key, out) = unsafe {
        (
            core::slice::from_raw_parts(fds, count),
            core::slice::from_raw_parts(events, count),
            &mut *key,
            core::slice::from_raw_parts_mut(ready, count),
        )
    };
    *key = 0;
    service(fds[0], |channel, _, terminal| {
        let mut set = watch::Set::new();
        set.len = count;
        posix_abi::shared::with_files(|files| {
            for (item, (&fd, &events)) in set.items.iter_mut().zip(fds.iter().zip(events)) {
                let target = files.target(fd).map_err(|_| 9)?;
                let description = match target {
                    Target::Pipe(end) if !terminal => end,
                    Target::Tty(end) if terminal => end,
                    Target::Input | Target::Output | Target::Error if terminal => {
                        proto_tty::CONSOLE
                    }
                    _ => return Err(22),
                };
                *item = watch::Item {
                    description,
                    events,
                };
            }
            Ok(())
        })?;
        let mut w = Writer::new();
        method(terminal, 0).write(&mut w).map_err(|_| 5)?;
        set.write(&mut w).map_err(|_| 22)?;
        result(sys::send(channel, w.as_bytes()).map_err(|_| 5)?, key, out)
    })
    .unwrap_or_else(|error| -error)
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_watch_keyed(
    fd: u32,
    key: u64,
    cancel: u32,
    armed: u32,
    ready: *mut u32,
    count: u32,
) -> i32 {
    if count as usize > watch::MAX {
        return -22;
    }
    // SAFETY: the C probe passes room for count event words.
    let out = unsafe { core::slice::from_raw_parts_mut(ready, count as usize) };
    service(fd, |channel, _, terminal| {
        let mut w = Writer::new();
        method(terminal, if cancel != 0 { 2 } else { 1 })
            .write(&mut w)
            .map_err(|_| 5)?;
        w.u64(key).map_err(|_| 5)?;
        let reply = if armed != 0 {
            let own = own_channel()?;
            let notify = sys::handle_label(&own, Rights::NOTIFY | Rights::TRANSFER, key, 1)
                .map_err(|_| 5)?;
            sys::send_handles(channel, w.as_bytes(), [notify.erase()]).map_err(|_| 5)?
        } else {
            sys::send(channel, w.as_bytes()).map_err(|_| 5)?
        };
        result(reply, &mut 0, out)
    })
    .unwrap_or_else(|error| -error)
}

/// Sixteen armed registrations of a fresh ordinary session fill two ends.
fn fill_pipe(parent: &Handle<Channel>, clone: &[u8], count: usize) -> Result<Handle<Channel>, i32> {
    let channel = rt::service::clone_session(parent, clone).map_err(|_| 5)?;
    let mut create = Writer::new();
    proto_pipe::Method::Create
        .header()
        .write(&mut create)
        .map_err(|_| 5)?;
    create.u32(0).map_err(|_| 5)?;
    let reply = sys::send(&channel, create.as_bytes()).map_err(|_| 5)?;
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let mut body = Reader::new(reply.bytes(&mut buffer));
    if body.u32().map_err(|_| 5)? != 0 {
        return Err(5);
    }
    let ends = [body.u32().map_err(|_| 5)?, body.u32().map_err(|_| 5)?];
    body.finish().map_err(|_| 5)?;
    for index in 0..count {
        let mut set = watch::Set::new();
        set.len = 1;
        set.items[0].description = ends[index / 8];
        let mut start = Writer::new();
        method(false, 0).write(&mut start).map_err(|_| 5)?;
        set.write(&mut start).map_err(|_| 5)?;
        let mut key = 0;
        if result(
            sys::send(&channel, start.as_bytes()).map_err(|_| 5)?,
            &mut key,
            &mut [0],
        )? != 1
        {
            return Err(5);
        }
        let own = own_channel()?;
        let notify =
            sys::handle_label(&own, Rights::NOTIFY | Rights::TRANSFER, key, 1).map_err(|_| 5)?;
        let mut take = Writer::new();
        method(false, 1).write(&mut take).map_err(|_| 5)?;
        take.u64(key).map_err(|_| 5)?;
        if result(
            sys::send_handles(&channel, take.as_bytes(), [notify.erase()]).map_err(|_| 5)?,
            &mut 0,
            &mut [0],
        )? != 1
        {
            return Err(5);
        }
    }
    Ok(channel)
}

/// Exercises the service's full set of 32 distinct held descriptions,
/// through its ordinary empty clone, including the eight-link limit.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_watch_full_pipe(fd: u32, gone: u32) -> i32 {
    service(fd, |parent, _, terminal| {
        if terminal {
            return Err(22);
        }
        let mut clone = Writer::new();
        proto_pipe::Method::Clone
            .header()
            .write(&mut clone)
            .map_err(|_| 5)?;
        clone.u32(0).map_err(|_| 5)?;
        // Eighty-seven live watches precede the full 32-end registration. Their
        // sixteen armed handles also exercise the maximum session Gone.
        let mut fillers: [Option<Handle<Channel>>; 6] = [const { None }; 6];
        if gone != 0 {
            for (index, filler) in fillers.iter_mut().enumerate() {
                *filler = Some(fill_pipe(
                    parent,
                    clone.as_bytes(),
                    if index == 5 { 7 } else { 16 },
                )?);
            }
        }
        let channel = rt::service::clone_session(parent, clone.as_bytes()).map_err(|_| 5)?;
        let mut set = watch::Set::new();
        set.len = watch::MAX;
        for pair in set.items.as_chunks_mut::<2>().0 {
            let mut create = Writer::new();
            proto_pipe::Method::Create
                .header()
                .write(&mut create)
                .map_err(|_| 5)?;
            create.u32(0).map_err(|_| 5)?;
            let reply = sys::send(&channel, create.as_bytes()).map_err(|_| 5)?;
            let mut buffer = [0; rt::abi::MESSAGE_MAX];
            let mut body = Reader::new(reply.bytes(&mut buffer));
            if body.u32().map_err(|_| 5)? != 0 {
                return Err(5);
            }
            pair[0] = watch::Item {
                description: body.u32().map_err(|_| 5)?,
                events: 0,
            };
            pair[1] = watch::Item {
                description: body.u32().map_err(|_| 5)?,
                events: 0,
            };
            body.finish().map_err(|_| 5)?;
        }
        let mut start = Writer::new();
        method(false, 0).write(&mut start).map_err(|_| 5)?;
        set.write(&mut start).map_err(|_| 5)?;
        let mut keys = [0; 8];
        let mut ready = [0; watch::MAX];
        for key in &mut keys {
            if result(
                sys::send(&channel, start.as_bytes()).map_err(|_| 5)?,
                key,
                &mut ready,
            )? != 1
            {
                return Err(5);
            }
            let own = own_channel()?;
            let notify = sys::handle_label(&own, Rights::NOTIFY | Rights::TRANSFER, *key, 1)
                .map_err(|_| 5)?;
            let mut take = Writer::new();
            method(false, 1).write(&mut take).map_err(|_| 5)?;
            take.u64(*key).map_err(|_| 5)?;
            if result(
                sys::send_handles(&channel, take.as_bytes(), [notify.erase()]).map_err(|_| 5)?,
                &mut 0,
                &mut ready,
            )? != 1
            {
                return Err(5);
            }
        }
        let refused = sys::send(&channel, start.as_bytes()).map_err(|_| 5)?;
        if result(refused, &mut 0, &mut ready) != Err(11) {
            return Err(5);
        }
        if gone == 0 {
            for key in keys {
                let mut cancel = Writer::new();
                method(false, 2).write(&mut cancel).map_err(|_| 5)?;
                cancel.u64(key).map_err(|_| 5)?;
                if result(
                    sys::send(&channel, cancel.as_bytes()).map_err(|_| 5)?,
                    &mut 0,
                    &mut ready,
                )? != 0
                    || ready.iter().any(|&event| event != 0)
                {
                    return Err(5);
                }
            }
        }
        // Dropping the ordinary clone exercises CLIENT_GONE with the
        // original generation keys and, in gone mode, eight Notify handles.
        drop(channel);
        Ok(0)
    })
    .unwrap_or_else(|error| -error)
}

/// Eight console subscriptions retain their keys through all Take requests.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_watch_full_tty(fd: u32, gone: u32) -> i32 {
    service(fd, |parent, description, terminal| {
        if !terminal {
            return Err(22);
        }
        let mut clone = Writer::new();
        proto_tty::Method::Clone
            .header()
            .write(&mut clone)
            .map_err(|_| 5)?;
        let channel = rt::service::clone_session(parent, clone.as_bytes()).map_err(|_| 5)?;
        let mut set = watch::Set::new();
        set.len = proto_tty::WATCH_MAX;
        set.items.fill(watch::Item {
            description,
            events: 0,
        });
        let mut start = Writer::new();
        method(true, 0).write(&mut start).map_err(|_| 5)?;
        set.write(&mut start).map_err(|_| 5)?;
        let mut keys = [0; 8];
        let mut ready = [0; watch::MAX];
        for key in &mut keys {
            if result(
                sys::send(&channel, start.as_bytes()).map_err(|_| 5)?,
                key,
                &mut ready,
            )? != 1
            {
                return Err(5);
            }
            let own = own_channel()?;
            let notify = sys::handle_label(&own, Rights::NOTIFY | Rights::TRANSFER, *key, 1)
                .map_err(|_| 5)?;
            let mut take = Writer::new();
            method(true, 1).write(&mut take).map_err(|_| 5)?;
            take.u64(*key).map_err(|_| 5)?;
            if result(
                sys::send_handles(&channel, take.as_bytes(), [notify.erase()]).map_err(|_| 5)?,
                &mut 0,
                &mut ready,
            )? != 1
            {
                return Err(5);
            }
        }
        if result(
            sys::send(&channel, start.as_bytes()).map_err(|_| 5)?,
            &mut 0,
            &mut ready,
        ) != Err(11)
        {
            return Err(5);
        }
        if gone == 0 {
            for key in keys {
                let mut cancel = Writer::new();
                method(true, 2).write(&mut cancel).map_err(|_| 5)?;
                cancel.u64(key).map_err(|_| 5)?;
                if result(
                    sys::send(&channel, cancel.as_bytes()).map_err(|_| 5)?,
                    &mut 0,
                    &mut ready,
                )? != 0
                    || ready.iter().any(|&event| event != 0)
                {
                    return Err(5);
                }
            }
        }
        drop(channel);
        Ok(0)
    })
    .unwrap_or_else(|error| -error)
}

/// Reads both quiet service snapshots before printing any measurements.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_watch_stats(pipe: u32, tty: u32) -> i32 {
    let mut maxima = [[[(0u64, 0u64); 66]; 2]; 2];
    for (index, fd) in [pipe, tty].into_iter().enumerate() {
        let outcome = service(fd, |channel, _, terminal| {
            for (case, rows) in maxima[index].iter_mut().enumerate() {
                for (kind, maximum) in rows.iter_mut().enumerate() {
                    let mut request = Writer::new();
                    proto_wire::Header::new(
                        if terminal { 30 } else { 17 },
                        if terminal {
                            proto_tty::VERSION
                        } else {
                            proto_pipe::VERSION
                        },
                    )
                    .write(&mut request)
                    .map_err(|_| 5)?;
                    request.u32(kind as u32).map_err(|_| 5)?;
                    if case == 1 {
                        request.u64(if terminal { 16 } else { 32 }).map_err(|_| 5)?;
                    }
                    let reply = sys::send(channel, request.as_bytes()).map_err(|_| 5)?;
                    let mut buffer = [0; rt::abi::MESSAGE_MAX];
                    let mut body = Reader::new(reply.bytes(&mut buffer));
                    if body.u32().map_err(|_| 5)? != 0 {
                        return Err(5);
                    }
                    *maximum = (body.u64().map_err(|_| 5)?, body.u64().map_err(|_| 5)?);
                    body.finish().map_err(|_| 5)?;
                }
            }
            Ok(())
        });
        if let Err(error) = outcome {
            return -error;
        }
    }
    for (index, cases) in maxima.into_iter().enumerate() {
        for (case, rows) in cases.into_iter().enumerate() {
            for (kind, (ticks, detail)) in rows.into_iter().enumerate() {
                if ticks != 0 {
                    rt::println!(
                        "service {}: {} kind {} {} ticks detail {}",
                        if case == 0 { "step" } else { "case" },
                        index + 4,
                        kind,
                        ticks,
                        detail
                    );
                }
            }
        }
    }
    0
}
