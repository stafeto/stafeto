// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The socket calls of relibc's platform (posix_abi::sockets): addresses,
//! messages and options as relibc has them (Linux AArch64's layouts), each
//! a value or a negated errno.

use super::{call, files, value};
use core::ffi::c_int;
use core::mem::{offset_of, size_of};
use posix_abi::constants::{EFAULT, EINVAL};
use posix_abi::sockets as layer;

/// struct iovec and struct msghdr of Linux AArch64.
#[repr(C)]
pub struct IoVec {
    base: *mut u8,
    len: usize,
}

#[repr(C)]
pub struct MsgHdr {
    name: *mut u8,
    namelen: u32,
    iov: *mut IoVec,
    iovlen: usize,
    control: *mut u8,
    controllen: usize,
    flags: c_int,
}

const _: () = {
    assert!(size_of::<IoVec>() == 16);
    assert!(size_of::<MsgHdr>() == 56);
    assert!(offset_of!(MsgHdr, iov) == 16);
    assert!(offset_of!(MsgHdr, control) == 32);
    assert!(offset_of!(MsgHdr, flags) == 48);
};

/// The most parts of a message the platform gathers or spreads.
const IOV_MAX: usize = 16;

/// # Safety
/// `pointer` is null or readable for `len` bytes.
unsafe fn input<'a>(pointer: *const u8, len: usize) -> Result<&'a [u8], c_int> {
    if len == 0 {
        return Ok(&[]);
    }
    if pointer.is_null() {
        return Err(EFAULT);
    }
    // SAFETY: the caller's promise.
    Ok(unsafe { core::slice::from_raw_parts(pointer, len) })
}

/// # Safety
/// `pointer` is null or writable for `len` bytes.
unsafe fn output<'a>(pointer: *mut u8, len: usize) -> Result<&'a mut [u8], c_int> {
    if len == 0 {
        return Ok(&mut []);
    }
    if pointer.is_null() {
        return Err(EFAULT);
    }
    // SAFETY: the caller's promise.
    Ok(unsafe { core::slice::from_raw_parts_mut(pointer, len) })
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int {
    value(call(|| layer::socket(domain, kind, protocol)).map(i64::from)) as c_int
}

/// # Safety
/// `sv` is writable for two ints.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_socketpair(
    domain: c_int,
    kind: c_int,
    protocol: c_int,
    sv: *mut c_int,
) -> c_int {
    if sv.is_null() {
        return -EFAULT;
    }
    match call(|| layer::socketpair(domain, kind, protocol)) {
        Ok(pair) => {
            // SAFETY: the caller's promise.
            unsafe {
                sv.write(pair[0]);
                sv.add(1).write(pair[1]);
            }
            0
        }
        Err(errno) => -errno,
    }
}

/// # Safety
/// `address` is readable for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_bind(fd: c_int, address: *const u8, len: usize) -> c_int {
    // SAFETY: the caller's promise.
    let raw = match unsafe { input(address, len) } {
        Ok(raw) => raw,
        Err(errno) => return -errno,
    };
    let umask = files::umask();
    value(call(|| layer::bind(fd, raw, umask)).map(|()| 0)) as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_listen(fd: c_int, backlog: c_int) -> c_int {
    value(call(|| layer::listen(fd, backlog)).map(|()| 0)) as c_int
}

/// # Safety
/// `address` is readable for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_connect(fd: c_int, address: *const u8, len: usize) -> c_int {
    // SAFETY: the caller's promise.
    let raw = match unsafe { input(address, len) } {
        Ok(raw) => raw,
        Err(errno) => return -errno,
    };
    value(call(|| layer::connect(fd, raw)).map(|()| 0)) as c_int
}

/// accept and accept4: the new descriptor; the peer's address into
/// `address` (`*len` bytes) and its true length into `*len`, when both are
/// not null.
///
/// # Safety
/// `address` is writable for `*len` bytes, `len` for a u32.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_accept(
    fd: c_int,
    address: *mut u8,
    len: *mut u32,
    flags: c_int,
) -> c_int {
    let want = !address.is_null() && !len.is_null();
    // SAFETY: the caller's promise.
    let out = if want {
        match unsafe { output(address, len.read() as usize) } {
            Ok(out) => Some(out),
            Err(errno) => return -errno,
        }
    } else {
        None
    };
    match call(|| layer::accept(fd, out, flags)) {
        Ok((new, true_len)) => {
            if want {
                // SAFETY: the caller's promise.
                unsafe { len.write(true_len as u32) };
            }
            new
        }
        Err(errno) => -errno,
    }
}

/// # Safety
/// `address` is writable for `*len` bytes, `len` for a u32.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_getsockname(fd: c_int, address: *mut u8, len: *mut u32) -> c_int {
    names(fd, address, len, false)
}

/// # Safety
/// `address` is writable for `*len` bytes, `len` for a u32.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_getpeername(fd: c_int, address: *mut u8, len: *mut u32) -> c_int {
    names(fd, address, len, true)
}

fn names(fd: c_int, address: *mut u8, len: *mut u32, peer: bool) -> c_int {
    if len.is_null() {
        return -EFAULT;
    }
    // SAFETY: the caller's promise.
    let out = match unsafe { output(address, len.read() as usize) } {
        Ok(out) => out,
        Err(errno) => return -errno,
    };
    let result = call(|| {
        if peer {
            layer::getpeername(fd, out)
        } else {
            layer::getsockname(fd, out)
        }
    });
    match result {
        Ok(true_len) => {
            // SAFETY: the caller's promise.
            unsafe { len.write(true_len as u32) };
            0
        }
        Err(errno) => -errno,
    }
}

/// # Safety
/// `option` is writable for `*len` bytes, `len` for a u32.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_getsockopt(
    fd: c_int,
    level: c_int,
    name: c_int,
    option: *mut u8,
    len: *mut u32,
) -> c_int {
    if len.is_null() {
        return -EFAULT;
    }
    // SAFETY: the caller's promise.
    let out = match unsafe { output(option, len.read() as usize) } {
        Ok(out) => out,
        Err(errno) => return -errno,
    };
    match call(|| layer::getsockopt(fd, level, name, out)) {
        Ok(true_len) => {
            // SAFETY: the caller's promise.
            unsafe { len.write(true_len as u32) };
            0
        }
        Err(errno) => -errno,
    }
}

/// # Safety
/// `option` is readable for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_setsockopt(
    fd: c_int,
    level: c_int,
    name: c_int,
    option: *const u8,
    len: usize,
) -> c_int {
    // SAFETY: the caller's promise.
    let value_bytes = match unsafe { input(option, len) } {
        Ok(bytes) => bytes,
        Err(errno) => return -errno,
    };
    value(call(|| layer::setsockopt(fd, level, name, value_bytes)).map(|()| 0)) as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_shutdown(fd: c_int, how: c_int) -> c_int {
    value(call(|| layer::shutdown(fd, how)).map(|()| 0)) as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_sockatmark(fd: c_int) -> c_int {
    value(call(|| layer::sockatmark(fd)).map(i64::from)) as c_int
}

/// sendmsg (and, built on it, send, sendto): the bytes sent.
///
/// # Safety
/// `message` is a readable struct msghdr whose parts are readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_sendmsg(fd: c_int, message: *const MsgHdr, flags: c_int) -> isize {
    if message.is_null() {
        return -(EFAULT as isize);
    }
    // SAFETY: the caller's promise.
    let m = unsafe { &*message };
    if m.iovlen > IOV_MAX {
        return -(EINVAL as isize);
    }
    let mut parts: [&[u8]; IOV_MAX] = [&[]; IOV_MAX];
    for (k, part) in parts.iter_mut().enumerate().take(m.iovlen) {
        // SAFETY: the caller's promise.
        let v = unsafe { &*m.iov.add(k) };
        *part = match unsafe { input(v.base, v.len) } {
            Ok(bytes) => bytes,
            Err(errno) => return -(errno as isize),
        };
    }
    // SAFETY: the caller's promise.
    let control = match unsafe { input(m.control, m.controllen) } {
        Ok(bytes) => bytes,
        Err(errno) => return -(errno as isize),
    };
    let name = if m.name.is_null() || m.namelen == 0 {
        None
    } else {
        // SAFETY: the caller's promise.
        match unsafe { input(m.name, m.namelen as usize) } {
            Ok(bytes) => Some(bytes),
            Err(errno) => return -(errno as isize),
        }
    };
    value(call(|| layer::send(fd, flags, name, &parts[..m.iovlen], control)).map(|n| n as i64))
        as isize
}

/// recvmsg (and, built on it, recv, recvfrom): the bytes received; the
/// length of the sender's address, the flags of the message and the length
/// of the control data are set in `message`.
///
/// # Safety
/// `message` is a writable struct msghdr whose parts are writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_recvmsg(fd: c_int, message: *mut MsgHdr, flags: c_int) -> isize {
    if message.is_null() {
        return -(EFAULT as isize);
    }
    // SAFETY: the caller's promise.
    let m = unsafe { &mut *message };
    if m.iovlen > IOV_MAX {
        return -(EINVAL as isize);
    }
    let mut parts: [&mut [u8]; IOV_MAX] = core::array::from_fn(|_| &mut [][..]);
    for (k, part) in parts.iter_mut().enumerate().take(m.iovlen) {
        // SAFETY: the caller's promise.
        let v = unsafe { &*m.iov.add(k) };
        *part = match unsafe { output(v.base, v.len) } {
            Ok(bytes) => bytes,
            Err(errno) => return -(errno as isize),
        };
    }
    // SAFETY: the caller's promise.
    let control = match unsafe { output(m.control, m.controllen) } {
        Ok(bytes) => bytes,
        Err(errno) => return -(errno as isize),
    };
    let name = if m.name.is_null() || m.namelen == 0 {
        None
    } else {
        // SAFETY: the caller's promise.
        match unsafe { output(m.name, m.namelen as usize) } {
            Ok(bytes) => Some(bytes),
            Err(errno) => return -(errno as isize),
        }
    };
    match call(|| layer::recv(fd, flags, name, &mut parts[..m.iovlen], control)) {
        Ok(got) => {
            if !m.name.is_null() {
                m.namelen = got.name_len as u32;
            }
            m.controllen = got.control_len;
            m.flags = got.flags;
            got.count as isize
        }
        Err(errno) => -(errno as isize),
    }
}
