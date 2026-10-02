// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Malformed value messages and full-page payloads through a live file owner.

use super::*;
use posix_request::{MAX_READ, MAX_WRITE, MESSAGE_MAX, Reply, Request, VERSION};
use proto_wire::{Header, Writer};

fn refused(bytes: &[u8], errno: i32) -> bool {
    let mut out = [0; MESSAGE_MAX];
    shared::probe(bytes, &mut out)
        .is_ok_and(|len| Reply::read(&out[..len]) == Ok(Reply::Error(errno)))
}

pub fn before_heap() -> bool {
    tls::with_process(|| {
        let mut cwd = [0; 3];
        if abi::getcwd(&mut cwd) != Ok(1) || &cwd[..2] != b"/\0" {
            return fail(60);
        }
        if !refused(&[1], EINVAL)
            || !refused(&Header::new(10, VERSION + 1).bytes(), ENOSYS)
            || !refused(&Header::new(65535, VERSION).bytes(), ENOSYS)
        {
            return fail(61);
        }
        let mut reserved = Header::new(10, VERSION).bytes();
        reserved[7] = 1;
        if !refused(&reserved, EINVAL) {
            return fail(62);
        }
        // The former transport accepted two executable/job addresses. These
        // bytes now receive a format error; neither value can be dereferenced.
        let mut legacy = [0; 16];
        legacy[..8].copy_from_slice(&0x205b48u64.to_le_bytes());
        legacy[8..].copy_from_slice(&0xdeadbeefu64.to_le_bytes());
        if !refused(&legacy, ENOSYS) {
            return fail(63);
        }
        let mut request = Writer::new();
        Request::DirRead { stream: u64::MAX }
            .write(&mut request)
            .unwrap();
        // Directory streams are relibc's: the layer refuses their requests.
        if !refused(request.as_bytes(), ENOSYS) {
            return fail(64);
        }
        let mut long_path = [b'x'; 82];
        long_path[0] = b'/';
        long_path[81] = 0;
        if abi::open(&long_path[..81], O_RDONLY) != Err(ENOENT) {
            return fail(65);
        }
        if abi::getcwd(&mut cwd) != Ok(1) || &cwd[..2] != b"/\0" {
            return fail(66);
        }
        rt::println!("posix-message-probe: malformed requests rejected before heap");
        true
    })
}

pub fn payload() -> bool {
    let Ok(fd) = abi::open(b"/tmp/probe", O_RDWR) else {
        return fail(67);
    };
    if fd != 3 {
        return fail(67);
    }
    let mut bytes = [0; 1024];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (index.wrapping_mul(37) ^ (index >> 3)) as u8;
    }
    if abi::write(fd, &bytes) != Ok(MAX_WRITE)
        || abi::write(fd, &bytes[MAX_WRITE..]) != Ok(bytes.len() - MAX_WRITE)
        || abi::lseek(fd, 0, SEEK_SET) != Ok(0)
    {
        return fail(68);
    }
    let mut copy = [0; 1024];
    if abi::read(fd, &mut copy) != Ok(MAX_READ)
        || abi::read(fd, &mut copy[MAX_READ..]) != Ok(copy.len() - MAX_READ)
        || copy != bytes
        || abi::close(fd).is_err()
    {
        return fail(69);
    }
    rt::println!("posix-message-probe: full request and reply payloads preserved");
    true
}
