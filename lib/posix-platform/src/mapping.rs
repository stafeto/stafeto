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
use core::sync::atomic::{AtomicU32, Ordering};
use posix_abi::constants::{EACCES, EBADF, EBUSY, EINVAL, EIO, ENODEV, ENOMEM};
use posix_abi::mmap::{
    self, Back, FilePiece, MAP_ANONYMOUS, MAP_SHARED, PROT_NONE, PROT_READ, PROT_WRITE,
};

const PAGE: usize = 4096;

/// The pause in milliseconds a probe asks of the maker of a shared object
/// between its mapping and its reading of the file (`stafeto_probe_fill_pause`),
/// to hold the entry reserved while another process asks for it. 0 in a
/// program.
static FILL_PAUSE_MS: AtomicU32 = AtomicU32::new(0);

/// Sets the pause of the maker of the next shared objects of this process.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_probe_fill_pause(milliseconds: u32) {
    FILL_PAUSE_MS.store(milliseconds, Ordering::Relaxed);
}

/// The probe's pause, if any.
fn pause_before_fill() {
    let ms = i64::from(FILL_PAUSE_MS.load(Ordering::Relaxed));
    if ms != 0 {
        let request = posix_types::Timespec {
            tv_sec: ms / 1000,
            tv_nsec: ms % 1000 * 1_000_000,
        };
        let _ = posix_abi::threads::sleep::clock_nanosleep(CLOCK_MONOTONIC, 0, request);
    }
}

/// relibc's CLOCK_MONOTONIC.
const CLOCK_MONOTONIC: c_int = 1;
/// The lowest number the layer's descriptors of mapped files take: near the
/// top of the table, away from the numbers a program picks.
const KEEP_FROM: u32 = posix_fs::OPEN_MAX as u32 / 2;
/// The flag of O_APPEND in the flags of a description (proto_fs::APPEND).
const APPEND: u32 = 128;
/// relibc's F_DUPFD_CLOEXEC.
const F_DUPFD_CLOEXEC: c_int = 1030;
/// relibc's MS_ASYNC, MS_INVALIDATE and MS_SYNC.
const MS_ASYNC: c_int = 1;
const MS_INVALIDATE: c_int = 2;
const MS_SYNC: c_int = 4;
/// Pieces of shared mappings of files one call handles at most.
const PIECES: usize = 32;

/// What the regular file `fd` names: its size, and its identity (the key
/// of the process service's rendezvous of shared memory); ENODEV for any
/// other kind: only files are mapped.
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

/// The flags the description of `fd` was opened with: the access mode in
/// the low two bits and O_APPEND.
fn open_flags(fd: c_int) -> Result<u32, c_int> {
    let number = u32::try_from(fd).map_err(|_| EBADF)?;
    call(|| {
        posix_abi::shared::held(number, |transport, target| {
            let posix_fs::Target::Ram(ram) = target else {
                return Err(ENODEV);
            };
            transport
                .files()
                .capture_description(ram.fd())
                .map(|captured| captured.flags)
                .map_err(|_| EIO)
        })
    })
}

/// Whether `fd` still shows the file of identity `key`: a program may have
/// closed the number the layer keeps for a mapping, or put another file
/// there (`dup2`).
fn still(fd: c_int, key: u64) -> bool {
    file_info(fd).is_ok_and(|(_, now)| now == key)
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

/// The pages of a mapping of a file that lie wholly past its end get no
/// access, and a reference to them is SIGBUS.
fn cut_past_end(fd: c_int, address: usize, len: usize, offset: u64, prot: c_int) {
    let Ok((size, _)) = file_info(fd) else {
        return;
    };
    let in_file = size
        .div_ceil(PAGE as u64)
        .saturating_sub(offset / PAGE as u64) as usize;
    let pages = len.div_ceil(PAGE);
    if in_file < pages {
        let start = address + in_file * PAGE;
        let tail = (pages - in_file) * PAGE;
        if mmap::mprotect(start, tail, PROT_NONE).is_ok() {
            mmap::mark_past_end(start, start + tail, prot);
        }
    }
}

/// Writes the pieces back to their files, up to each file's end, those
/// whose descriptor still shows the file only. The first error of a write
/// comes back after all the pieces were tried.
fn write_back(pieces: &[FilePiece]) -> Result<(), c_int> {
    let mut first = Ok(());
    for piece in pieces {
        let Ok((size, key)) = file_info(piece.fd) else {
            continue;
        };
        if key != piece.key {
            continue;
        }
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
                if first.is_ok() {
                    first = Err(if put < 0 { -put as c_int } else { EIO });
                }
                break;
            }
            done += put as usize;
        }
    }
    first
}

/// Writes every shared mapping of a file back (`exit`, `_exit` and `exec`:
/// the pages of the program are gone after them).
pub(crate) fn flush_all() {
    let mut from = 0;
    loop {
        let mut pieces = [FilePiece::default(); PIECES];
        let n = mmap::file_pieces_from(from, &mut pieces);
        if n == 0 {
            return;
        }
        let _ = write_back(&pieces[..n]);
        let last = &pieces[n - 1];
        from = last.address + last.pages * PAGE;
    }
}

/// Closes the descriptors of the files whose last mapping went (those that
/// still show the file), and tells the process service that this process
/// maps their objects no more.
fn close_released() {
    let mut files = [(0, 0, false); 16];
    let n = mmap::closed_files(&mut files);
    for &(fd, key, registered) in &files[..n] {
        if fd >= 0 && still(fd, key) {
            super::stafeto_close(fd);
        }
        if registered {
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
    // POSIX mmap: the descriptor is open for reading, whatever the
    // protection; a shared mapping that can be written needs it open for
    // writing, and not for appending.
    let opened = open_flags(fd)?;
    let (mode, append) = (opened & 3, opened & APPEND != 0);
    if mode == 1 {
        return Err(EACCES);
    }
    let writing = mode == 2 && !append;
    if flags & MAP_SHARED != 0 && prot & PROT_WRITE != 0 && !writing {
        return Err(EACCES);
    }
    if flags & MAP_SHARED == 0 {
        return private_file(addr, len, prot, flags, fd, offset);
    }
    // A shared mapping writes through a descriptor of its own, which stays
    // when the program closes `fd`; mappings of one file share it.
    let (kept, new) = match mmap::fd_of_key(key).filter(|&kept| still(kept, key)) {
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
    let result = shared_file(addr, len, prot, flags, fd, kept, offset, key, writing);
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
    // The whole of the last page too: the file shows through it up to its end.
    fill(fd, address, len.div_ceil(PAGE) * PAGE, offset);
    if prot & PROT_WRITE == 0
        && let Err(errno) = mmap::mprotect(address, len, prot)
    {
        let _ = mmap::munmap(address, len);
        return Err(errno);
    }
    cut_past_end(fd, address, len, offset, prot);
    Ok(address)
}

/// A critical section of the layer (`posix_sync::enter`), left when it drops.
struct Critical;

impl Drop for Critical {
    fn drop(&mut self) {
        posix_sync::leave();
    }
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
    may_write: bool,
) -> Result<usize, c_int> {
    use posix_abi::shares::Got;
    let first = (offset / PAGE as u64) as usize;
    let pages = len.div_ceil(PAGE);
    let source = |existing, registered| mmap::FileSource {
        existing,
        offset_pages: first,
        back: Back::new(kept, 0, key, registered),
        may_write,
        writable: prot & PROT_WRITE != 0,
    };
    // The file service vouches first that this process has the file open;
    // without that the object is this mapping's alone.
    let granted = match posix_abi::shares::grant(fd) {
        Ok(()) => true,
        // The service has no place for one more vouching of this process.
        Err(errno) if errno == ENOMEM => return Err(ENOMEM),
        Err(_) => false,
    };
    // From the ask to the Put or the Detach no entry of a signal runs: a
    // handler that jumps out of `mmap` would leave the entry reserved, and
    // every other asker waiting for an object nobody makes. The ask itself
    // waits in the service while another process or thread makes the
    // object (its reply comes when the object is there or the maker is
    // gone), so there is nothing to retry here. The wait is the other's
    // reading of the file; a program of real time maps its files before it
    // starts.
    posix_sync::enter();
    let _critical = Critical;
    let got = if granted {
        posix_abi::shares::get(key).ok()
    } else {
        None
    };
    let address = match got {
        Some(Got::Found(memory, covers)) if covers >= first + pages => {
            let address = mmap::mmap(addr, len, prot, flags, Some(source(Some(memory), true)))?;
            return Ok(address);
        }
        // An object too short for the mapping (the file grew) is not used:
        // this mapping makes its own, apart from the others. So is the
        // answer Busy of a service with no place for one more waiting ask.
        Some(Got::Found(..)) | Some(Got::Full) | Some(Got::Busy) | None => mmap::mmap(
            addr,
            len,
            prot | PROT_WRITE,
            flags,
            Some(source(None, false)),
        )?,
        Some(Got::Reserved) => {
            match mmap::mmap(
                addr,
                len,
                prot | PROT_WRITE,
                flags,
                Some(source(None, true)),
            ) {
                Ok(address) => address,
                Err(errno) => {
                    posix_abi::shares::detach(key);
                    return Err(errno);
                }
            }
        }
    };
    if matches!(got, Some(Got::Reserved)) {
        pause_before_fill();
    }
    fill(kept, address, len.div_ceil(PAGE) * PAGE, offset);
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
    cut_past_end(kept, address, len, offset, prot);
    Ok(address)
}

/// `munmap`: shared mappings of files are written back first. 0, or the
/// negative of an errno.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_munmap(addr: *mut c_void, len: usize) -> c_int {
    let mut pieces = [FilePiece::default(); PIECES];
    let n = mmap::file_pieces(addr as usize, len, true, &mut pieces);
    let _ = write_back(&pieces[..n]);
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

/// `mlock`: the range is rounded out to whole pages and checked, and the
/// caller must be allowed to lock that much (RLIMIT_MEMLOCK; EPERM at 0
/// for anyone but the superuser, ENOMEM past it). The memory is resident
/// already, so nothing else is done.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_mlock(addr: *const c_void, len: usize) -> c_int {
    const PAGE: usize = 4096;
    let start = (addr as usize) & !(PAGE - 1);
    let Some(end) = (addr as usize)
        .checked_add(len)
        .and_then(|e| e.checked_next_multiple_of(PAGE))
    else {
        return -posix_abi::constants::ENOMEM;
    };
    if let Err(errno) = posix_abi::resources::lock_check((end - start) as u64) {
        return -errno;
    }
    stafeto_map_check(start as *const c_void, end - start)
}

/// `munlock`: the range is rounded out to whole pages and checked.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_munlock(addr: *const c_void, len: usize) -> c_int {
    const PAGE: usize = 4096;
    let start = (addr as usize) & !(PAGE - 1);
    let Some(end) = (addr as usize)
        .checked_add(len)
        .and_then(|e| e.checked_next_multiple_of(PAGE))
    else {
        return -posix_abi::constants::ENOMEM;
    };
    stafeto_map_check(start as *const c_void, end - start)
}

/// `mlockall` (`flags` MCL_CURRENT, MCL_FUTURE) and `munlockall` (0 flags).
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_mlockall(flags: c_int) -> c_int {
    if flags == 0 {
        posix_abi::resources::unlock_all();
        return 0;
    }
    match posix_abi::resources::lock_all(flags & 1 != 0, flags & 2 != 0) {
        Ok(()) => 0,
        Err(errno) => -errno,
    }
}

/// `msync`: shared mappings of files in the range that the program had
/// writable are written back to their files (MS_SYNC and MS_ASYNC alike:
/// the write is done on return, and its error is the error of the call).
/// MS_INVALIDATE reads the file again into the pages instead.
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
    if flags & MS_INVALIDATE != 0 {
        // A page that mlockall locked is not invalidated (EBUSY).
        if posix_abi::resources::locked_all() {
            return -EBUSY;
        }
        let n = mmap::file_pieces(addr as usize, len, false, &mut pieces);
        for piece in &pieces[..n] {
            refresh(piece);
        }
        return 0;
    }
    let n = mmap::file_pieces(addr as usize, len, true, &mut pieces);
    match write_back(&pieces[..n]) {
        Ok(()) => 0,
        Err(errno) => -errno,
    }
}

/// Writes back every shared mapping of a file that the program had writable,
/// as `msync` does: a process that starts from this one (fork) reads the
/// files as the mappings show them.
pub(crate) fn flush_files() {
    let mut pieces = [FilePiece::default(); PIECES];
    let n = mmap::file_pieces(0, usize::MAX / 2, true, &mut pieces);
    if n > 0 {
        let _ = write_back(&pieces[..n]);
    }
}

/// Reads the pages of a piece again from the file; a piece that cannot be
/// written is made writable for that and back.
fn refresh(piece: &FilePiece) {
    let Ok((size, key)) = file_info(piece.fd) else {
        return;
    };
    if key != piece.key {
        return;
    }
    let len = (piece.pages * PAGE) as u64;
    let room = size.saturating_sub(piece.offset).min(len) as usize;
    let span = piece.pages * PAGE;
    let writable = piece.access == rt::abi::Access::ReadWrite;
    if !writable && mmap::mprotect(piece.address, span, PROT_READ | PROT_WRITE).is_err() {
        return;
    }
    fill(piece.fd, piece.address, room, piece.offset);
    if !writable {
        let back = if piece.access == rt::abi::Access::None {
            0
        } else {
            PROT_READ
        };
        let _ = mmap::mprotect(piece.address, span, back);
    }
}
