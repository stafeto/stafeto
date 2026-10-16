// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of POSIX processes: a C main on relibc (procs.c); posix-crt
//! starts the layer, relibc starts C. The math-probe feature selects math.c.

#![no_std]
#![no_main]

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

#[cfg(feature = "lifetime-probe")]
mod lifetime;
#[cfg(feature = "lifetime-probe")]
mod lock_deadlock;
#[cfg(feature = "lifetime-probe")]
mod lock_loss;
#[cfg(feature = "lifetime-probe")]
mod lock_signal;
#[cfg(feature = "lifetime-probe")]
mod wait_fifo;
#[cfg(feature = "lifetime-probe")]
mod wait_locks;

#[cfg(feature = "pending-open")]
mod pending_open;

#[cfg(feature = "loader-abort")]
mod audit;
#[cfg(feature = "image-gates")]
mod image_gates;
#[cfg(feature = "loader-abort")]
mod image_hold;
#[cfg(feature = "loader-abort")]
mod loader_abort;

/// A counterfeit identity capability must leave the already bound session intact.
#[cfg(feature = "files")]
#[unsafe(no_mangle)]
extern "C" fn files_fake_identity() -> i32 {
    use rt::abi::Rights;
    let Ok(fake) = rt::sys::channel_create(1) else {
        return -1;
    };
    let Ok(copy) =
        rt::sys::handle_duplicate(&fake, Rights::NOTIFY | Rights::DUPLICATE | Rights::TRANSFER)
    else {
        return -2;
    };
    let Ok(raw) = posix_abi::shared::with_files(|f| Ok(f.sessions().0.raw())) else {
        return -3;
    };
    let channel = rt::Handle::<rt::handle::Channel>::borrowed(raw);
    let request = proto_fs::Method::Bind.header().bytes();
    let Ok(reply) = rt::sys::send_handles(&channel, &request, [copy.erase()]) else {
        return -4;
    };
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let mut status = proto_wire::Reader::new(reply.bytes(&mut buffer)).u32();
    let request = proto_fs::Method::FinishBinding.header().bytes();
    while status == Ok(proto_fs::RESOLVING) {
        let Ok(reply) = rt::sys::send(&channel, &request) else {
            return -5;
        };
        status = proto_wire::Reader::new(reply.bytes(&mut buffer)).u32();
    }
    if status == Ok(proto_fs::PERMISSION) {
        // A lost terminal refusal must remain a refusal on the same Finish.
        let Ok(reply) = rt::sys::send(&channel, &request) else {
            return -7;
        };
        if proto_wire::Reader::new(reply.bytes(&mut buffer)).u32() != status {
            return -8;
        }
        0
    } else {
        -6
    }
}

#[cfg(feature = "stages")]
mod change_stages;
#[cfg(feature = "auth-probe")]
mod cleanup;
#[cfg(feature = "files")]
mod data_stages;
#[cfg(feature = "names-probe")]
mod names_fork;
#[cfg(feature = "names-loss")]
mod names_loss;
#[cfg(feature = "stages")]
mod names_stages;
#[cfg(feature = "change-steps")]
mod names_volley;
#[cfg(feature = "stages")]
mod open_stages;
/// Sixteen real sessions retain all thirty-two descriptions during both
/// credential changes. Every reply and retained byte is checked by the guest.
#[cfg(feature = "files")]
#[unsafe(no_mangle)]
extern "C" fn files_full_sessions() -> i32 {
    use proto_wire::{Status, Writer};
    use rt::fs::Files;
    use rt::handle::{Channel, Handle};
    fn run() -> Result<(), Status> {
        let raw = posix_abi::shared::with_files(|files| Ok(files.sessions().0.raw()))
            .map_err(|_| Status::BadSize)?;
        let original =
            core::mem::ManuallyDrop::new(Files::from_sessions(Handle::from_raw(raw), None));
        let identity = posix_abi::process::identity().ok_or(Status::BadSize)?;
        original.bind(identity)?;
        // A completed or lost Finish reply remains OK until another preparation.
        Files::finish_on(original.sessions().0)?;
        Files::finish_on(original.sessions().0)?;
        let mut descriptors = [0; 32];
        for descriptor in &mut descriptors {
            *descriptor = original.open("/etc/motd", proto_fs::READ_ONLY)?;
        }
        let mut request = Writer::new();
        proto_fs::Method::Clone.header().write(&mut request)?;
        request.u32(descriptors.len() as u32)?;
        for descriptor in descriptors {
            request.u32(descriptor)?;
        }
        let mut sessions: [Option<Files>; 16] = core::array::from_fn(|_| None);
        let mut source = raw;
        for session in &mut sessions {
            let clone = Files::clone_on(&Handle::<Channel>::borrowed(source), request.as_bytes())?;
            let files = Files::from_sessions(clone, None);
            files.bind(identity)?;
            source = files.sessions().0.raw();
            *session = Some(files);
        }
        posix_abi::process::seteuid(65533).map_err(|_| Status::BadSize)?;
        for session in sessions.iter().flatten() {
            if session.open("/tmp/probe", proto_fs::WRITE_ONLY)
                != Err(Status::Unknown(proto_fs::ACCESS_DENIED))
            {
                return Err(Status::BadSize);
            }
            for descriptor in descriptors {
                let mut byte = [0];
                if session.read_at(descriptor, 0, &mut byte)? != 1 || byte != *b"s" {
                    return Err(Status::BadSize);
                }
            }
        }
        posix_abi::process::seteuid(0).map_err(|_| Status::BadSize)?;
        for session in sessions.iter().flatten() {
            for descriptor in descriptors {
                let mut byte = [0];
                if session.read_at(descriptor, 0, &mut byte)? != 1 || byte != *b"s" {
                    return Err(Status::BadSize);
                }
                session.close(descriptor)?;
            }
        }
        for descriptor in descriptors {
            original.close(descriptor)?;
        }
        Ok(())
    }
    let result = run();
    // A failed observation must also leave the C supervisor's real UID restored.
    let restored = posix_abi::process::seteuid(0);
    if result.is_ok() && restored.is_ok() {
        0
    } else {
        -1
    }
}

#[cfg(feature = "lock-fifo-full")]
mod lock_fifo_full;
#[cfg(feature = "lifetime-probe")]
mod lock_ring;

/// Observes a real retained FIFO wait before the C guest sends a signal.
#[cfg(any(feature = "fifo-probe", feature = "fifo-steps"))]
#[unsafe(no_mangle)]
extern "C" fn stafeto_fifo_waiting() -> i32 {
    i32::from(posix_abi::fifo_waiting())
}

/// Read existing init records while the FIFO guest holds live endpoints.
#[cfg(any(feature = "fifo-probe", feature = "fifo-steps"))]
#[unsafe(no_mangle)]
extern "C" fn stafeto_fifo_service_reserve() -> i32 {
    let parent = posix_crt::parent();
    let mut first = 0;
    let mut found = 0;
    loop {
        let mut writer = proto_wire::Writer::new();
        if (proto_init::ListRequest { first })
            .write(&mut writer)
            .is_err()
        {
            return -1;
        }
        let Ok(reply) = rt::sys::send(&parent, writer.as_bytes()) else {
            return -2;
        };
        let mut bytes = [0; rt::abi::MESSAGE_MAX];
        let Ok(page) = proto_init::ListReply::read(reply.bytes(&mut bytes)) else {
            return -3;
        };
        for record in page.records() {
            let name = record.name.as_bytes();
            if name == b"ramfs" || name == b"pipe" {
                rt::println!(
                    "posix-fifo: service {} memory {} pages quota {} pages handles {} limit {}",
                    core::str::from_utf8(name).unwrap_or("?"),
                    record.used_pages,
                    record.quota_pages,
                    record.live,
                    record.limit
                );
                if record.quota_pages == 0
                    || u64::from(record.used_pages) * 10 > u64::from(record.quota_pages) * 9
                    || record.limit == 0
                    || u64::from(record.live) * 10 > u64::from(record.limit) * 9
                {
                    return -4;
                }
                found += 1;
            }
        }
        if page.is_empty() {
            return -5;
        }
        first += page.len() as u16;
        if first >= page.total {
            break;
        }
    }
    if found == 2 { 0 } else { -6 }
}
