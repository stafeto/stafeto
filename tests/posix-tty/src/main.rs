// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the terminal: a C main on relibc (tty.c); posix-crt starts
//! the layer, relibc starts C.

#![no_std]
#![no_main]

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_terminal_full_exec() -> i32 {
    posix_abi::terminal::probe_full_exec()
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_terminal_edge(group: u32) -> i32 {
    posix_abi::terminal::probe_edge(group)
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_trusted_terminal(target: i32, newborn: i32) -> i32 {
    posix_abi::terminal::probe_trusted(target as u32, newborn != 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_terminal_fake_start() -> i32 {
    posix_abi::process::probe_terminal_fake_start()
}
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_terminal_fake_control() -> i32 {
    posix_abi::process::probe_terminal_fake_control()
}
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_terminal_fake_listen() -> u32 {
    posix_abi::process::probe_terminal_fake_listen()
}
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_terminal_fake_stop() -> i32 {
    posix_abi::process::probe_terminal_fake_stop()
}
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_terminal_fake_close() {
    posix_abi::process::probe_terminal_fake_close()
}

/// Snapshot the full service interval before printing any measurement.
#[cfg(feature = "quiet-control")]
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_terminal_control_stats() -> i32 {
    use proto_wire::{Header, Reader, Writer};
    use rt::handle::{Channel, Handle};
    let channel = match posix_abi::shared::with_files(|fs| Ok(fs.terminal().map(Handle::raw))) {
        Ok(Some(raw)) => Handle::<Channel>::borrowed(raw),
        _ => return 5,
    };
    let mut maxima = [(0u64, 0u64); 5];
    for (index, maximum) in maxima.iter_mut().enumerate() {
        let mut request = Writer::new();
        if Header::new(30, proto_tty::VERSION)
            .write(&mut request)
            .and_then(|()| request.u32(index as u32 + 16))
            .is_err()
        {
            return 5;
        }
        let Ok(reply) = rt::sys::send(&channel, request.as_bytes()) else {
            return 5;
        };
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        let mut body = Reader::new(reply.bytes(&mut buffer));
        if body.u32() != Ok(0) {
            return 5;
        }
        let (Ok(ticks), Ok(detail)) = (body.u64(), body.u64()) else {
            return 5;
        };
        if body.finish().is_err() {
            return 5;
        }
        *maximum = (ticks, detail);
    }
    let invalid = maxima
        .iter()
        .any(|(ticks, _)| *ticks == 0 || *ticks > rt::abi::time::TERM_B_TICKS);
    for (index, (ticks, detail)) in maxima.into_iter().enumerate() {
        rt::println!(
            "service step: 5 kind {} {} ticks detail {}",
            index + 16,
            ticks,
            detail
        );
    }
    if invalid { 5 } else { 0 }
}

/// Exercise Controlling with this real client's descriptor and identity.
#[cfg(feature = "quiet-control")]
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_terminal_controlling(fd: i32) -> i32 {
    let outcome = posix_abi::shared::with_files(|fs| {
        let target = fs.target(fd as u32).map_err(|_| 9)?;
        Ok((fs.transport(), target))
    });
    let Ok((transport, posix_fs::Target::Tty(description))) = outcome else {
        return 9;
    };
    posix_abi::terminal::job(transport, description, proto_tty::Method::Controlling, None)
        .map_or_else(|error| error, |_| 0)
}
