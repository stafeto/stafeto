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
