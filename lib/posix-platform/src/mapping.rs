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
const KEEP_FROM: u32 = posix_fs::OPEN_MAX as u32 / 2;
/// relibc's F_DUPFD_CLOEXEC.
const F_DUPFD_CLOEXEC: c_int = 1030;
/// relibc's MS_ASYNC, MS_INVALIDATE and MS_SYNC.
const MS_ASYNC: c_int = 1;
const MS_INVALIDATE: c_int = 2;
const MS_SYNC: c_int = 4;
/// Pieces of shared mappings of files one call handles at most.
const PIECES: usize = 32;

/// What the regular file `fd` names: its size, and the key of the process
/// service's rendezvous of shared memory (ENODEV for any other kind: only
/// files are mapped).
fn file_info(fd: c_int) -> Result<(u64, u64), c_int> {
    let info = call(|| posix_abi::names::fstatat(fd, None, 0))?;
    if info.kind != 2 {
        return Err(ENODEV);
    }
    Ok((
        info.size,
        posix_abi::shares::key_of(info.device, info.inode),
    ))
}

fn file_size(fd: c_int) -> Result<u64, c_int> {
    file_info(fd).map(|(size, _)| size)
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

/// Closes the descriptors of the files whose last mapping went, and tells
/// the process service that this process maps their objects no more.
fn close_released() {
    let mut files = [(0, 0); 16];
    let n = mmap::closed_files(&mut files);
    for &(fd, key) in &files[..n] {
        if fd >= 0 {
            super::stafeto_close(fd);
        }
        if key != 0 {
            posix_abi::shares::detach(key);
        }
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
    if len == 0 {
        return Err(EINVAL);
    }
    let (_, key) = file_info(fd)?;
    if flags & MAP_SHARED == 0 {
        return private_file(addr, len, prot, flags, fd, offset);
    }
    // A shared mapping writes through a descriptor of its own, which stays
    // when the program closes `fd`; mappings of one file share it.
    let (kept, new) = match mmap::fd_of_key(key) {
        Some(kept) => (kept, false),
        None => {
            let mut kept = super::files::stafeto_fcntl(fd, F_DUPFD_CLOEXEC, u64::from(KEEP_FROM));
            if kept < 0 {
                kept = super::files::stafeto_fcntl(fd, F_DUPFD_CLOEXEC, 3);
            }
            if kept < 0 {
                return Err(-kept);
            }
            (kept, true)
        }
    };
    let result = shared_file(addr, len, prot, flags, fd, kept, offset, key);
    if result.is_err() && new {
        super::stafeto_close(kept);
    }
    result
}

/// A private mapping of a file: pages of the layer's own, read from the file.
fn private_file(
    addr: usize,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: u64,
) -> Result<usize, c_int> {
    let address = mmap::mmap(addr, len, prot | PROT_WRITE, flags, None)?;
    fill(fd, address, len, offset);
    if prot & PROT_WRITE == 0
        && let Err(errno) = mmap::mprotect(address, len, prot)
    {
        let _ = mmap::munmap(address, len);
        return Err(errno);
    }
    Ok(address)
}

/// A shared mapping of a file: the object the process service keeps for the
/// file when another process maps it, else a new one, read from the file and
/// registered there.
#[allow(clippy::too_many_arguments)]
fn shared_file(
    addr: usize,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    kept: c_int,
    offset: u64,
    key: u64,
) -> Result<usize, c_int> {
    use posix_abi::shares::Got;
    let first = (offset / PAGE as u64) as usize;
    let pages = len.div_ceil(PAGE);
    let source = |existing, key| mmap::FileSource {
        existing,
        offset_pages: first,
        back: Back::new(kept, 0, key),
    };
    // Ask the rendezvous; a process that makes the object meanwhile is
    // waited for.
    let mut asks = 0;
    let got = loop {
        match posix_abi::shares::get(key) {
            Ok(Got::Busy) if asks < 2000 => {
                asks += 1;
                let _ = rt::sys::yield_now();
            }
            Ok(got) => break Some(got),
            Err(_) => break None,
        }
    };
    let address = match got {
        Some(Got::Found(memory, covers)) if covers >= first + pages => {
            let address = mmap::mmap(addr, len, prot, flags, Some(source(Some(memory), key)))?;
            return Ok(address);
        }
        // An object too short for the mapping (the file grew) is not used:
        // this mapping makes its own, apart from the others.
        Some(Got::Found(..)) | Some(Got::Full) | Some(Got::Busy) | None => {
            mmap::mmap(addr, len, prot | PROT_WRITE, flags, Some(source(None, 0)))?
        }
        Some(Got::Reserved) => {
            match mmap::mmap(addr, len, prot | PROT_WRITE, flags, Some(source(None, key))) {
                Ok(address) => address,
                Err(errno) => {
                    posix_abi::shares::detach(key);
                    return Err(errno);
                }
            }
        }
    };
    fill(kept, address, len, offset);
    if matches!(got, Some(Got::Reserved)) {
        // The file is read: the others may map the object.
        let handed = mmap::object_at(address)
            .map(|(memory, covers)| posix_abi::shares::put(key, covers, &memory));
        if !matches!(handed, Some(Ok(()))) {
            posix_abi::shares::detach(key);
        }
    }
    if prot & PROT_WRITE == 0
        && let Err(errno) = mmap::mprotect(address, len, prot)
    {
        let _ = mmap::munmap(address, len);
        close_released();
        return Err(errno);
    }
    let _ = fd;
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
