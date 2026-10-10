// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The dedicated guest observes the actual service page and its transferred rights.

static BUDGET_PRINTED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

#[unsafe(no_mangle)]
pub extern "C" fn ram_lifetime(pid: i32) -> i32 {
    let result = (|| {
        let raw =
            posix_abi::shared::with_files(|files| Ok(files.sessions().0.raw())).map_err(|_| -1)?;
        let channel = rt::Handle::<rt::handle::Channel>::borrowed(raw);
        let mut request = proto_wire::Writer::new();
        proto_wire::Header::new(0xfff3, proto_fs::VERSION)
            .write(&mut request)
            .map_err(|_| -2)?;
        request.u32(pid as u32).map_err(|_| -3)?;
        for _ in 0..128 {
            let reply = rt::fs::Files::send_on(&channel, request.as_bytes()).map_err(|_| -4)?;
            if !reply.handles.is_empty() {
                return Err(-5);
            }
            let mut buffer = [0; rt::abi::MESSAGE_MAX];
            let mut body = proto_wire::Reader::new(reply.bytes(&mut buffer));
            let status = body.u32().map_err(|_| -6)?;
            if status == proto_fs::RESOLVING {
                if body.u32().map_err(|_| -9)? != 0 {
                    return Err(-9);
                }
                body.finish().map_err(|_| -9)?;
                rt::sys::yield_now().map_err(|_| -11)?;
                continue;
            }
            if status != 0 {
                return Err(-7);
            }
            let live = body.u32().map_err(|_| -8)?;
            let quota = body.u64().map_err(|_| -13)?;
            let used = body.u64().map_err(|_| -14)?;
            let _lock_jobs = body.u32().map_err(|_| -16)?;
            let _places = body.u32().map_err(|_| -17)?;
            body.finish().map_err(|_| -9)?;
            if quota.saturating_sub(used) < 128 * 4096 {
                return Err(-15);
            }
            if !BUDGET_PRINTED.swap(true, core::sync::atomic::Ordering::Relaxed) {
                rt::println!(
                    "RAM lifetime budget: quota={} used={} free={} pages ticks={}",
                    quota / 4096,
                    used / 4096,
                    quota.saturating_sub(used) / 4096,
                    rt::time::now()
                );
            }
            if live > 1 {
                return Err(-10);
            }
            return Ok(live as i32);
        }
        Err(-12)
    })();
    result.unwrap_or_else(|error| error)
}

#[unsafe(no_mangle)]
pub extern "C" fn process_lifetime(pid: i32) -> i32 {
    let result = (|| {
        let mut request = proto_wire::Writer::new();
        proto_wire::Header::new(0xfff0, proto_process::VERSION)
            .write(&mut request)
            .map_err(|_| -1)?;
        request.u32(pid as u32).map_err(|_| -2)?;
        let mut reply = rt::sys::send(posix_abi::process::client().session(), request.as_bytes())
            .map_err(|_| -3)?;
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        let mut body = proto_wire::Reader::new(reply.bytes(&mut buffer));
        if body.u32().map_err(|_| -4)? != 0 {
            return Err(-5);
        }
        let live = body.u32().map_err(|_| -6)?;
        body.finish().map_err(|_| -7)?;
        if reply.handles.info(0)
            != Some((
                rt::abi::ObjectKind::Memory,
                rt::abi::Rights::MAP_READ | rt::abi::Rights::TRANSFER,
            ))
            || reply.handles.len() != 1
            || live > 1
        {
            return Err(-8);
        }
        const WINDOW: usize = 0x60_0000_0000;
        let memory = reply
            .handles
            .take::<rt::handle::Memory>(0)
            .map_err(|_| -9)?;
        let process = posix_abi::allocation::process();
        rt::sys::mem_map(process, &memory, 0, 4096, WINDOW, rt::abi::Access::Read)
            .map_err(|_| -10)?;
        // SAFETY: the service initialized Page in this aligned read-only mapping.
        let mapped_live =
            unsafe { &*(WINDOW as *const proto_process::lifetimes::Page) }.live(pid as u32);
        // SAFETY: this single-threaded fixture no longer accesses its temporary mapping.
        unsafe { rt::sys::mem_unmap(process, WINDOW, 4096) }.map_err(|_| -11)?;
        if u32::from(mapped_live) != live {
            return Err(-12);
        }
        Ok(live as i32)
    })();
    result.unwrap_or_else(|error| error)
}

#[unsafe(no_mangle)]
pub extern "C" fn ram_close_event() -> i32 {
    let result = (|| {
        let began = rt::time::now();
        let transport =
            posix_abi::shared::with_files(|files| Ok(files.transport())).map_err(|_| -1)?;
        let files = transport.files();
        let mut held = [rt::fs::PreparedOpen {
            fd: 0,
            slot: 0,
            generation: 0,
            random: false,
        }; 32];
        for item in &mut held[..2] {
            let fd = files
                .open("/etc/motd", proto_fs::READ_ONLY)
                .map_err(|_| -2)?;
            *item = files.capture_description(fd).map_err(|_| -3)?.held;
        }
        let endpoint =
            rt::fs::Files::clone_exact_on(files.sessions().0, &held[..2]).map_err(|_| -4)?;
        let child = rt::fs::Files::from_sessions(endpoint, None);
        let event = proto_fs::CloseEvent {
            key: proto_fs::CloseKey {
                slot: 63,
                generation: 9,
            },
            packed: held[0].marked_fd(),
            description_generation: held[0].generation,
            last_alias: true,
        };
        child.close_event_once(event).map_err(|_| -5)?;
        let earlier_alias = proto_fs::CloseEvent {
            key: proto_fs::CloseKey {
                slot: 62,
                generation: 9,
            },
            last_alias: false,
            ..event
        };
        child.close_event_once(earlier_alias).map_err(|_| -25)?;
        if child.close_exact(held[0]).map_err(|_| -6)? != rt::fs::CloseOutcome::Closed {
            return Err(-7);
        }
        child.close_event_once(event).map_err(|_| -8)?;
        child.close_event_once(earlier_alias).map_err(|_| -26)?;
        let other = proto_fs::CloseEvent {
            packed: held[1].marked_fd(),
            description_generation: held[1].generation,
            ..event
        };
        if child.close_event_once(other)
            != Err(proto_wire::Status::Unknown(proto_fs::INVALID_ARGUMENT))
        {
            return Err(-9);
        }
        let newer = proto_fs::CloseKey {
            generation: 10,
            ..event.key
        };
        if child.close_event_once(proto_fs::CloseEvent {
            key: newer,
            ..event
        }) != Err(proto_wire::Status::Unknown(proto_fs::BAD_FD))
        {
            return Err(-10);
        }
        child.close_event_once(event).map_err(|_| -11)?;
        child
            .close_event_once(proto_fs::CloseEvent {
                key: newer,
                ..other
            })
            .map_err(|_| -12)?;
        if child.close_event_once(event) != Err(proto_wire::Status::Unknown(proto_fs::OPEN_RETIRED))
        {
            return Err(-13);
        }
        if child.close_exact(held[1]).map_err(|_| -14)? != rt::fs::CloseOutcome::Closed {
            return Err(-15);
        }
        for item in &held[..2] {
            if files.read_at(item.fd, 0, &mut [0; 1]).map_err(|_| -16)? != 1 {
                return Err(-17);
            }
            if files.close_exact(*item).map_err(|_| -18)? != rt::fs::CloseOutcome::Closed {
                return Err(-19);
            }
        }
        drop(child);
        for last_references in [false, true] {
            for item in &mut held {
                let fd = files
                    .open("/etc/motd", proto_fs::READ_ONLY)
                    .map_err(|_| -20)?;
                *item = files.capture_description(fd).map_err(|_| -21)?.held;
            }
            // Cover both shared references and all 32 final true OFD references.
            let mut born =
                Some(rt::fs::Files::clone_exact_on(files.sessions().0, &held).map_err(|_| -22)?);
            if !last_references {
                drop(born.take());
            }
            for item in &held {
                if files.close_exact(*item).map_err(|_| -23)? != rt::fs::CloseOutcome::Closed {
                    return Err(-24);
                }
            }
            drop(born);
        }
        rt::println!(
            "RAM close event: exact replay, stale body, physical I/O and 32-reference birth cleanup ok, ticks={}",
            rt::time::now().saturating_sub(began)
        );
        Ok(0)
    })();
    result.unwrap_or_else(|error| error)
}

use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
static CLOSE_MODE: AtomicUsize = AtomicUsize::new(0);
static CLOSE_FD: AtomicI32 = AtomicI32::new(-1);
static CLOSE_NEW_FD: AtomicI32 = AtomicI32::new(-1);
static CLOSE_ERROR: AtomicI32 = AtomicI32::new(0);
static CLOSE_EVENTS: AtomicUsize = AtomicUsize::new(0);
static CLOSE_PHYSICAL: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" {
    fn close_probe_signal_jump();
}

fn close_hook(phase: posix_abi::CloseProbe, token: posix_fs::closing::CloseToken) -> bool {
    let proof = posix_abi::shared::with_files(|files| {
        Ok((
            files.transport(),
            files.close_snapshot(token).map_err(posix_abi::error)?,
        ))
    });
    match proof {
        Ok((transport, snapshot)) => {
            if let posix_fs::Target::Ram(held) | posix_fs::Target::Random(held) = snapshot.backend {
                let confirmed = match phase {
                    posix_abi::CloseProbe::Event => {
                        let other = proto_fs::CloseEvent {
                            key: proto_fs::CloseKey {
                                slot: token.slot() as u32,
                                generation: token.generation(),
                            },
                            packed: held.prepared().marked_fd(),
                            description_generation: held.generation(),
                            last_alias: !snapshot.last_alias,
                        };
                        transport.files().close_event_once(other)
                            == Err(proto_wire::Status::Unknown(proto_fs::INVALID_ARGUMENT))
                    }
                    posix_abi::CloseProbe::Physical => {
                        transport.files().close_exact(held.prepared())
                            == Ok(rt::fs::CloseOutcome::AlreadyGone)
                    }
                };
                if !confirmed {
                    CLOSE_ERROR.store(-33, Ordering::SeqCst);
                }
            } else {
                CLOSE_ERROR.store(-34, Ordering::SeqCst);
            }
        }
        Err(_) => {
            CLOSE_ERROR.store(-35, Ordering::SeqCst);
        }
    }
    let wanted = match phase {
        posix_abi::CloseProbe::Event => {
            CLOSE_EVENTS.fetch_add(1, Ordering::SeqCst);
            [1, 3]
        }
        posix_abi::CloseProbe::Physical => {
            CLOSE_PHYSICAL.fetch_add(1, Ordering::SeqCst);
            [2, 4]
        }
    };
    let mode = CLOSE_MODE.load(Ordering::SeqCst);
    if !wanted.contains(&mode)
        || CLOSE_MODE
            .compare_exchange(mode, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
    {
        return false;
    }
    if mode == 1 || mode == 2 {
        return true;
    }
    if mode == 3 {
        let fd = CLOSE_FD.load(Ordering::SeqCst);
        if posix_abi::shared::held(fd as u32, |_, _| Ok(())) != Err(posix_abi::constants::EBADF) {
            CLOSE_ERROR.store(-30, Ordering::SeqCst);
        }
        match posix_abi::open(b"/etc/motd", posix_abi::constants::O_RDONLY) {
            Ok(next) => CLOSE_NEW_FD.store(next, Ordering::SeqCst),
            Err(_) => CLOSE_ERROR.store(-31, Ordering::SeqCst),
        }
    } else {
        // The C handler takes a genuine SIGUSR1 and abandons this unlocked frame.
        unsafe {
            close_probe_signal_jump();
        }
        CLOSE_ERROR.store(-32, Ordering::SeqCst);
    }
    false
}
fn install_close_hook(mode: usize, fd: i32) {
    CLOSE_MODE.store(mode, Ordering::SeqCst);
    CLOSE_FD.store(fd, Ordering::SeqCst);
    CLOSE_NEW_FD.store(-1, Ordering::SeqCst);
    CLOSE_ERROR.store(0, Ordering::SeqCst);
    CLOSE_EVENTS.store(0, Ordering::SeqCst);
    CLOSE_PHYSICAL.store(0, Ordering::SeqCst);
    posix_abi::probe_close_hook(Some(close_hook));
}

#[unsafe(no_mangle)]
pub extern "C" fn close_driver_receipts() -> i32 {
    let began = rt::time::now();
    let result = (|| {
        for mode in 1..=3 {
            let fd =
                posix_abi::open(b"/etc/motd", posix_abi::constants::O_RDONLY).map_err(|_| -1)?;
            install_close_hook(mode, fd);
            let closed = posix_abi::close(fd);
            posix_abi::probe_close_hook(None);
            closed.map_err(|_| -2)?;
            if CLOSE_MODE.load(Ordering::SeqCst) != 0 || CLOSE_ERROR.load(Ordering::SeqCst) != 0 {
                return Err(-3);
            }
            let events = CLOSE_EVENTS.load(Ordering::SeqCst);
            let physical = CLOSE_PHYSICAL.load(Ordering::SeqCst);
            if (events, physical) != if mode == 2 { (1, 2) } else { (2, 1) } {
                return Err(-4);
            }
            if mode == 3 {
                let next = CLOSE_NEW_FD.load(Ordering::SeqCst);
                if next != fd || posix_abi::read(next, &mut [0; 1]) != Ok(1) {
                    return Err(-5);
                }
                posix_abi::close(next).map_err(|_| -6)?;
            }
        }
        for mode in 1..=2 {
            let source =
                posix_abi::open(b"/etc/motd", posix_abi::constants::O_RDONLY).map_err(|_| -40)?;
            let target =
                posix_abi::open(b"/etc/motd", posix_abi::constants::O_RDONLY).map_err(|_| -41)?;
            install_close_hook(mode, target);
            let replaced = posix_abi::dup2(source, target);
            posix_abi::probe_close_hook(None);
            if replaced != Ok(target)
                || CLOSE_ERROR.load(Ordering::SeqCst) != 0
                || CLOSE_MODE.load(Ordering::SeqCst) != 0
                || (
                    CLOSE_EVENTS.load(Ordering::SeqCst),
                    CLOSE_PHYSICAL.load(Ordering::SeqCst),
                ) != if mode == 2 { (1, 2) } else { (2, 1) }
            {
                return Err(-42);
            }
            posix_abi::close(source).map_err(|_| -43)?;
            if posix_abi::read(target, &mut [0; 1]) != Ok(1) {
                return Err(-44);
            }
            posix_abi::close(target).map_err(|_| -45)?;
        }
        rt::println!(
            "POSIX close receipts: event loss, physical loss and helper reuse ok, ticks={}",
            rt::time::now().saturating_sub(began)
        );
        Ok(0)
    })();
    posix_abi::probe_close_hook(None);
    result.unwrap_or_else(|error| error)
}

#[unsafe(no_mangle)]
pub extern "C" fn close_driver_jump_arm(fd: i32) {
    install_close_hook(4, fd);
}
#[unsafe(no_mangle)]
pub extern "C" fn close_driver_jump_recover(old_fd: i32) -> i32 {
    posix_abi::probe_close_hook(None);
    let began = rt::time::now();
    let result = (|| {
        if CLOSE_MODE.load(Ordering::SeqCst) != 0 || CLOSE_ERROR.load(Ordering::SeqCst) != 0 {
            return Err(-10);
        }
        let debt = posix_abi::shared::with_files(|files| {
            Ok(files.close_tokens().any(|token| {
                files
                    .close_snapshot(token)
                    .is_ok_and(|snapshot| snapshot.complete && snapshot.release.is_some())
            }))
        })
        .map_err(|_| -11)?;
        if !debt {
            return Err(-12);
        }
        let next =
            posix_abi::open(b"/etc/motd", posix_abi::constants::O_RDONLY).map_err(|_| -13)?;
        if next != old_fd {
            return Err(-14);
        }
        for _ in 0..64 {
            posix_abi::shared::help_open_recovery();
        }
        if posix_abi::shared::with_files(|files| Ok(files.close_tokens().next().is_none()))
            != Ok(true)
        {
            return Err(-15);
        }
        if posix_abi::read(next, &mut [0; 1]) != Ok(1) {
            return Err(-16);
        }
        posix_abi::close(next).map_err(|_| -17)?;
        rt::println!(
            "POSIX close signal: genuine SIGUSR1 siglongjmp preserves physical debt and reused fd ok, ticks={}",
            rt::time::now().saturating_sub(began)
        );
        Ok(0)
    })();
    result.unwrap_or_else(|error| error)
}

#[unsafe(no_mangle)]
pub extern "C" fn close_driver_full_places() -> i32 {
    let began = rt::time::now();
    let result = (|| {
        let mut fds = [0; 17];
        for fd in &mut fds {
            *fd = posix_abi::open(b"/etc/motd", posix_abi::constants::O_RDONLY).map_err(|_| -20)?;
        }
        let owner =
            posix_fs::change::OwnerToken::new(posix_abi::relibc::open_owner().map_err(|_| -21)?)
                .map_err(|_| -22)?;
        let sp: u64;
        // SAFETY: this live fixture frame encloses all registered control work.
        unsafe {
            core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack, preserves_flags));
        }
        let frame = entries::Frame::main(sp);
        let controls = posix_abi::shared::with_files(|files| {
            let mut controls = [None; 16];
            for control in &mut controls {
                *control = Some(
                    files
                        .begin_change_record(owner, frame)
                        .map_err(posix_abi::error)?,
                );
            }
            for &fd in &fds[..16] {
                if !matches!(
                    files
                        .begin_close_record(None, fd as u32, frame)
                        .map_err(posix_abi::error)?,
                    posix_fs::closing::CloseAdmission::Started { .. }
                ) {
                    return Err(-23);
                }
            }
            Ok(controls)
        })
        .map_err(|_| -24)?;
        posix_abi::close(fds[16]).map_err(|_| -25)?;
        for _ in 0..128 {
            posix_abi::shared::help_open_recovery();
        }
        posix_abi::shared::with_files(|files| {
            if files.close_tokens().next().is_some() || files.change_tokens().count() != 16 {
                return Err(-26);
            }
            for &fd in &fds {
                if files.target(fd as u32).is_ok() {
                    return Err(-27);
                }
            }
            for (token, claim) in controls.into_iter().flatten() {
                files
                    .complete_change_record(claim, posix_fs::change::ControlResult::Value(0))
                    .map_err(posix_abi::error)?;
                files
                    .ack_change_record(token, owner)
                    .map_err(posix_abi::error)?;
            }
            Ok(())
        })
        .map_err(|_| -28)?;
        rt::println!(
            "POSIX close places: all 16 Closing and 16 Control slots retain independent progress ok, ticks={}",
            rt::time::now().saturating_sub(began)
        );
        Ok(0)
    })();
    result.unwrap_or_else(|error| error)
}

#[path = "lock_commands.rs"]
mod lock_commands;
