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
        let errno = unsafe { abi::__errno_location() };
        unsafe { *errno = EIO };
        let mut cwd = [0; 3];
        if unsafe { abi::getcwd(cwd.as_mut_ptr(), cwd.len()) }.is_null() || &cwd[..2] != b"/\0" {
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
        if !refused(request.as_bytes(), EBADF) {
            return fail(64);
        }
        let mut long_path = [b'x'; 82];
        long_path[0] = b'/';
        long_path[81] = 0;
        if unsafe { abi::open(long_path.as_ptr().cast(), O_RDONLY) } != -1
            || unsafe { *errno } != ENOENT
        {
            return fail(65);
        }
        unsafe { *errno = EIO };
        if unsafe { abi::getcwd(cwd.as_mut_ptr(), cwd.len()) }.is_null()
            || &cwd[..2] != b"/\0"
            || unsafe { *errno } != EIO
        {
            return fail(66);
        }
        rt::println!("posix-message-probe: malformed requests rejected before heap");
        true
    })
}

pub fn payload() -> bool {
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = EIO };
    let fd = unsafe { abi::open(c"/tmp/probe".as_ptr(), O_RDWR) };
    if fd != 3 {
        return fail(67);
    }
    let mut bytes = [0; 1024];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (index.wrapping_mul(37) ^ (index >> 3)) as u8;
    }
    if unsafe { abi::write(fd, bytes.as_ptr(), bytes.len()) } != MAX_WRITE as isize
        || unsafe { abi::write(fd, bytes[MAX_WRITE..].as_ptr(), bytes.len() - MAX_WRITE) }
            != (bytes.len() - MAX_WRITE) as isize
        || unsafe { abi::lseek(fd, 0, SEEK_SET) } != 0
    {
        return fail(68);
    }
    let mut copy = [0; 1024];
    if unsafe { abi::read(fd, copy.as_mut_ptr(), copy.len()) } != MAX_READ as isize
        || unsafe { abi::read(fd, copy[MAX_READ..].as_mut_ptr(), copy.len() - MAX_READ) }
            != (copy.len() - MAX_READ) as isize
        || copy != bytes
        || unsafe { *errno } != EIO
        || unsafe { abi::close(fd) } != 0
    {
        return fail(69);
    }
    rt::println!("posix-message-probe: full request and reply payloads preserved");
    true
}
