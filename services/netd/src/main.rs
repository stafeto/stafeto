// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
#![no_std]
#![no_main]
rt::entry!(main);
fn main(_: u64) -> u64 {
    use smoltcp::iface::SocketSet;
    let mut s = [smoltcp::iface::SocketStorage::EMPTY; 4];
    let _x = SocketSet::new(&mut s[..]);
    0
}
