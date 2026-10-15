// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `mmap`, `munmap`, `mprotect`, `msync` and the checks of `madvise` and
//! `mlock` for relibc's stafeto platform. The pages and the memory map are
//! the layer's (posix_abi::mmap); a file is read into a mapping with
//! `pread` and a shared mapping of a file is written back with `pwrite`
//! through a descriptor the layer keeps for it (`msync`, `munmap`), outside
//! the layer's locks.

use super::call;
use core::ffi::{c_int, c_void};
use posix_abi::constants::{EBADF, EINVAL, ENODEV};
use posix_abi::mmap::{self, Back, FilePiece, MAP_ANONYMOUS, MAP_SHARED, PROT_WRITE};

const PAGE: usize = 4096;
/// The lowest number the layer's descriptors of mapped files take: near the
/// top of the table, away from the numbers a program picks.
const KEEP_FROM: u32 = posix_fs::OPEN_MAX as u32 - 8;
/// relibc's F_DUPFD_CLOEXEC.
const F_DUPFD_CLOEXEC: c_int = 1030;
/// relibc's MS_ASYNC, MS_INVALIDATE and MS_SYNC.
const MS_ASYNC: c_int = 1;
const MS_INVALIDATE: c_int = 2;
const MS_SYNC: c_int = 4;
/// Pieces of shared mappings of files one call handles at most.
const PIECES: usize = 32;

/// The size of the regular file `fd` names, or an errno (ENODEV for any
/// other kind: only files are mapped).
fn file_size(fd: c_int) -> Result<u64, c_int> {
    let info = call(|| posix_abi::names::fstatat(fd, None, 0))?;
    if info.kind != 2 {
        return Err(ENODEV);
    }
    Ok(info.size)
}

/// Reads the file from `offset` into `address`, `len` bytes at most, up
/// to its end: what lies past it stays zero.
fn fill(fd: c_int, address: usize, len: usize, offset: u64) {
    let mut done = 0;
    while done < len {
        // SAFETY: the mapping is writable for `len` bytes and no one else
        // has its address yet (or the caller refills it on MS_INVALIDATE).
        let got = unsafe {
            super::files::stafeto_pread(
                fd,
                (address + done) as *mut u8,
                len - done,
                (offset + done as u64) as i64,
            )
        };
        if got <= 0 {
            break;
        }
        done += got as usize;
    }
}

/// Writes the pieces back to their files, up to each file's end.
fn write_back(pieces: &[FilePiece]) {
    for piece in pieces {
        let Ok(size) = file_size(piece.fd) else {
            continue;
        };
        let len = (piece.pages * PAGE) as u64;
        let Some(room) = size.checked_sub(piece.offset) else {
            continue;
        };
        let len = len.min(room) as usize;
        let mut done = 0;
        while done < len {
            // SAFETY: the pages are mapped readable at `address`.
            let put = unsafe {
                super::files::stafeto_pwrite(
                    piece.fd,
                    (piece.address + done) as *const u8,
                    len - done,
                    (piece.offset + done as u64) as i64,
                )
            };
            if put <= 0 {
                break;
            }
            done += put as usize;
        }
    }
}

/// Closes the descriptors of the files whose last mapping went.
fn close_released() {
    let mut fds = [0; 16];
    let n = mmap::closed_files(&mut fds);
    for &fd in &fds[..n] {
        super::stafeto_close(fd);
    }
}

/// `mmap`: the address, or the negative of an errno.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_mmap(
    addr: *mut c_void,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: i64,
) -> isize {
    let result = if flags & MAP_ANONYMOUS != 0 {
        mmap::mmap(addr as usize, len, prot, flags, None)
    } else {
        file_mapping(addr as usize, len, prot, flags, fd, offset)
    };
    match result {
        Ok(address) => address as isize,
        Err(errno) => -(errno as isize),
    }
}

fn file_mapping(
    addr: usize,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: i64,
) -> Result<usize, c_int> {
    if fd < 0 {
        return Err(EBADF);
    }
    let offset = u64::try_from(offset).map_err(|_| EINVAL)?;
    if !offset.is_multiple_of(PAGE as u64) {
        return Err(EINVAL);
    }
    file_size(fd)?;
    let shared = flags & MAP_SHARED != 0;
    // A shared mapping writes through a descriptor of its own, which stays
    // when the program closes `fd`.
    let keep = if shared {
        let kept = super::files::stafeto_fcntl(fd, F_DUPFD_CLOEXEC, u64::from(KEEP_FROM));
        if kept < 0 {
            return Err(-kept);
        }
        Some(kept)
    } else {
        None
    };
    let back = keep.map(|fd| Back::new(fd, offset));
    // The pages are written first and get the access asked for after.
    let made = mmap::mmap(addr, len, prot | PROT_WRITE, flags, back);
    let address = match made {
        Ok(address) => address,
        Err(errno) => {
            if let Some(kept) = keep {
                super::stafeto_close(kept);
            }
            return Err(errno);
        }
    };
    fill(keep.unwrap_or(fd), address, len, offset);
    if prot & PROT_WRITE == 0 {
        if let Err(errno) = mmap::mprotect(address, len, prot) {
            let _ = mmap::munmap(address, len);
            close_released();
            return Err(errno);
        }
    }
    Ok(address)
}

/// `munmap`: shared mappings of files are written back first. 0, or the
/// negative of an errno.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_munmap(addr: *mut c_void, len: usize) -> c_int {
    let mut pieces = [FilePiece::default(); PIECES];
    let n = mmap::file_pieces(addr as usize, len, &mut pieces);
    write_back(&pieces[..n]);
    let result = mmap::munmap(addr as usize, len);
    close_released();
    match result {
        Ok(()) => 0,
        Err(errno) => -errno,
    }
}

/// `mprotect` through the layer: 0, or the negative of an errno.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_mprotect(addr: *mut c_void, len: usize, prot: c_int) -> c_int {
    match mmap::mprotect(addr as usize, len, prot) {
        Ok(()) => 0,
        Err(errno) => -errno,
    }
}

/// The checks of `madvise`, `posix_madvise` and `mlock` on a range: 0, or
/// the negative of an errno.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_map_check(addr: *const c_void, len: usize) -> c_int {
    match mmap::check_range(addr as usize, len) {
        Ok(()) => 0,
        Err(errno) => -errno,
    }
}

/// `msync`: shared mappings of files in the range are written back to
/// their files (MS_SYNC and MS_ASYNC alike: the write is done on return).
/// MS_INVALIDATE changes nothing: the mapping is the layer's one view of
/// the file.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_msync(addr: *mut c_void, len: usize, flags: c_int) -> c_int {
    if flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC) != 0
        || (flags & MS_SYNC != 0) == (flags & MS_ASYNC != 0)
    {
        return -EINVAL;
    }
    let checked = stafeto_map_check(addr, len);
    if checked != 0 {
        return checked;
    }
    let mut pieces = [FilePiece::default(); PIECES];
    let n = mmap::file_pieces(addr as usize, len, &mut pieces);
    write_back(&pieces[..n]);
    0
}
