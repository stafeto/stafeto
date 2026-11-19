// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The volume: littlefs behind a safe interface. Files and directories are slots of the volume's own
//! table (`File`, `Dir`); the error codes are littlefs's, which are the errno of Linux with a minus.

use crate::{BLOCK, BLOCK_SECTORS, BLOCKS_MIN, DIRS, Device, FILES, NAME_MAX, SECTOR};
use core::ffi::{c_char, c_int, c_void};
use core::fmt;

/// The longest path the interface takes, in bytes (the file service's `MAX_PATH`).
pub const PATH_MAX: usize = 511;
/// The most blocks of a volume the allocator's window covers: one bit for each, in 128 KiB (4 GiB).
/// A larger volume would walk the tree on every STATFS and every wrap of the allocator, so
/// `volume::open` refuses it.
pub const BLOCKS_MAX: u64 = 1 << 20;
/// The bytes of memory a volume uses at most (`Storage`); the C structure is checked against it.
pub const STORAGE_BYTES: usize = (56 + 68 + 128) * 1024;

unsafe extern "C" {
    fn datafs_state_size() -> usize;
    fn datafs_state_align() -> usize;
    fn datafs_files() -> c_int;
    fn datafs_dirs() -> c_int;
    fn datafs_setup(d: *mut c_void, blocks: u32);
    fn datafs_format(d: *mut c_void, ctx: *mut c_void) -> c_int;
    fn datafs_mount(d: *mut c_void, ctx: *mut c_void) -> c_int;
    fn datafs_unmount(d: *mut c_void, ctx: *mut c_void) -> c_int;
    fn datafs_used(d: *mut c_void, ctx: *mut c_void) -> i64;
    fn datafs_pairs(d: *mut c_void, ctx: *mut c_void, out: *mut u32) -> c_int;
    fn datafs_outline(d: *mut c_void, ctx: *mut c_void, path: *const c_char, dry: c_int) -> c_int;
    fn datafs_set_inline(d: *mut c_void, max: u32);
    fn datafs_open(d: *mut c_void, ctx: *mut c_void, path: *const c_char, flags: c_int) -> c_int;
    fn datafs_close(d: *mut c_void, ctx: *mut c_void, slot: c_int) -> c_int;
    fn datafs_read(d: *mut c_void, ctx: *mut c_void, slot: c_int, buf: *mut u8, size: u32) -> i64;
    fn datafs_write(
        d: *mut c_void,
        ctx: *mut c_void,
        slot: c_int,
        buf: *const u8,
        size: u32,
    ) -> i64;
    fn datafs_sync(d: *mut c_void, ctx: *mut c_void, slot: c_int) -> c_int;
    fn datafs_seek(
        d: *mut c_void,
        ctx: *mut c_void,
        slot: c_int,
        offset: i32,
        whence: c_int,
    ) -> i64;
    fn datafs_truncate(d: *mut c_void, ctx: *mut c_void, slot: c_int, size: u32) -> c_int;
    fn datafs_size(d: *mut c_void, ctx: *mut c_void, slot: c_int) -> i64;
    fn datafs_mkdir(d: *mut c_void, ctx: *mut c_void, path: *const c_char) -> c_int;
    fn datafs_remove(d: *mut c_void, ctx: *mut c_void, path: *const c_char) -> c_int;
    fn datafs_rename(
        d: *mut c_void,
        ctx: *mut c_void,
        from: *const c_char,
        to: *const c_char,
    ) -> c_int;
    fn datafs_stat(
        d: *mut c_void,
        ctx: *mut c_void,
        path: *const c_char,
        kind: *mut u8,
        size: *mut u32,
        name: *mut u8,
    ) -> c_int;
    fn datafs_opendir(d: *mut c_void, ctx: *mut c_void, path: *const c_char) -> c_int;
    fn datafs_closedir(d: *mut c_void, ctx: *mut c_void, slot: c_int) -> c_int;
    fn datafs_readdir(
        d: *mut c_void,
        ctx: *mut c_void,
        slot: c_int,
        kind: *mut u8,
        size: *mut u32,
        name: *mut u8,
    ) -> c_int;
    fn datafs_rewinddir(d: *mut c_void, ctx: *mut c_void, slot: c_int) -> c_int;
    fn datafs_tell_dir(d: *mut c_void, ctx: *mut c_void, slot: c_int) -> i64;
    fn datafs_seek_dir(d: *mut c_void, ctx: *mut c_void, slot: c_int, off: u32) -> c_int;
    fn datafs_getattr(
        d: *mut c_void,
        ctx: *mut c_void,
        path: *const c_char,
        kind: u8,
        buffer: *mut u8,
        size: u32,
    ) -> c_int;
    fn datafs_setattr(
        d: *mut c_void,
        ctx: *mut c_void,
        path: *const c_char,
        kind: u8,
        buffer: *const u8,
        size: u32,
    ) -> c_int;
    fn datafs_removeattr(d: *mut c_void, ctx: *mut c_void, path: *const c_char, kind: u8) -> c_int;
    fn datafs_walk(d: *mut c_void, ctx: *mut c_void) -> c_int;
    fn datafs_window_blocks(d: *const c_void) -> u32;
    fn datafs_window_state(d: *const c_void, out: *mut u32);
    fn datafs_window_free(d: *const c_void) -> i64;
}

// The host measurements (`tests_scale`): the window of the allocator at another size, the erase
// count and a file opened with an attribute in its configuration.
#[cfg(test)]
unsafe extern "C" {
    fn datafs_set_lookahead(d: *mut c_void, buffer: *mut u8, size: u32);
    fn datafs_erases(d: *const c_void) -> u32;
    fn datafs_open_attr(
        d: *mut c_void,
        ctx: *mut c_void,
        path: *const c_char,
        flags: c_int,
        kind: u8,
        buffer: *const u8,
        size: u32,
    ) -> c_int;
}

/// The device of the volume as the C side calls back: `ctx` is a pointer to a `&mut dyn Device`
/// that `Fs::call` makes for the length of one call.
type Ctx = *mut c_void;

/// # Safety
/// Called by littlefs with the context of the running call and a buffer of `size` bytes.
#[unsafe(no_mangle)]
unsafe extern "C" fn datafs_rs_read(
    ctx: Ctx,
    block: u32,
    off: u32,
    buffer: *mut u8,
    size: u32,
) -> c_int {
    // SAFETY: `ctx` is the `&mut &mut dyn Device` of the call that is running; the buffer is the
    // size littlefs names.
    let (device, out) = unsafe {
        (
            &mut *(ctx as *mut &mut dyn Device),
            core::slice::from_raw_parts_mut(buffer, size as usize),
        )
    };
    if !(off as usize).is_multiple_of(SECTOR) || !(size as usize).is_multiple_of(SECTOR) {
        return Error::Io.code();
    }
    let sector = u64::from(block) * BLOCK_SECTORS + u64::from(off) / SECTOR as u64;
    match device.read(sector, out) {
        Ok(()) => 0,
        Err(_) => Error::Io.code(),
    }
}

/// # Safety
/// As `datafs_rs_read`.
#[unsafe(no_mangle)]
unsafe extern "C" fn datafs_rs_prog(
    ctx: Ctx,
    block: u32,
    off: u32,
    buffer: *const u8,
    size: u32,
) -> c_int {
    // SAFETY: as above.
    let (device, data) = unsafe {
        (
            &mut *(ctx as *mut &mut dyn Device),
            core::slice::from_raw_parts(buffer, size as usize),
        )
    };
    if !(off as usize).is_multiple_of(SECTOR) || !(size as usize).is_multiple_of(SECTOR) {
        return Error::Io.code();
    }
    let sector = u64::from(block) * BLOCK_SECTORS + u64::from(off) / SECTOR as u64;
    match device.write(sector, data) {
        Ok(()) => 0,
        Err(_) => Error::Io.code(),
    }
}

/// # Safety
/// As `datafs_rs_read`.
#[unsafe(no_mangle)]
unsafe extern "C" fn datafs_rs_sync(ctx: Ctx) -> c_int {
    #[cfg(feature = "break-datafs-sync")]
    {
        let _ = ctx;
        return 0;
    }
    #[cfg(not(feature = "break-datafs-sync"))]
    {
        // SAFETY: as above.
        let device = unsafe { &mut *(ctx as *mut &mut dyn Device) };
        match device.flush() {
            Ok(()) => 0,
            Err(_) => Error::Io.code(),
        }
    }
}

/// The memory of a volume: littlefs's state, its caches and the buffers of the open files. Static in
/// the service; the volume takes it for as long as it lives.
#[repr(C, align(16))]
pub struct Storage([u8; STORAGE_BYTES]);

impl Storage {
    pub const fn new() -> Self {
        Self([0; STORAGE_BYTES])
    }
}

impl Default for Storage {
    fn default() -> Self {
        Self::new()
    }
}

/// An error of the volume: the errno of Linux that littlefs's codes stand for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The device failed (EIO).
    Io,
    /// The volume is damaged, or holds no littlefs (EILSEQ in the files service; 84 here).
    Corrupt,
    NoEntry,
    /// No attribute of that kind (ENODATA).
    NoAttr,
    Exists,
    NotDirectory,
    IsDirectory,
    NotEmpty,
    BadDescriptor,
    TooBig,
    Invalid,
    NoSpace,
    NoMemory,
    NameTooLong,
    /// Any other code of littlefs, with its value.
    Other(i32),
}

impl Error {
    pub const fn code(self) -> i32 {
        match self {
            Self::Io => -5,
            Self::Corrupt => -84,
            Self::NoEntry => -2,
            Self::NoAttr => -61,
            Self::Exists => -17,
            Self::NotDirectory => -20,
            Self::IsDirectory => -21,
            Self::NotEmpty => -39,
            Self::BadDescriptor => -9,
            Self::TooBig => -27,
            Self::Invalid => -22,
            Self::NoSpace => -28,
            Self::NoMemory => -12,
            Self::NameTooLong => -36,
            Self::Other(code) => code,
        }
    }

    pub const fn from_code(code: i32) -> Self {
        match code {
            -5 => Self::Io,
            -84 => Self::Corrupt,
            -2 => Self::NoEntry,
            -61 => Self::NoAttr,
            -17 => Self::Exists,
            -20 => Self::NotDirectory,
            -21 => Self::IsDirectory,
            -39 => Self::NotEmpty,
            -9 => Self::BadDescriptor,
            -27 => Self::TooBig,
            -22 => Self::Invalid,
            -28 => Self::NoSpace,
            -12 => Self::NoMemory,
            -36 => Self::NameTooLong,
            other => Self::Other(other),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "littlefs error {}", self.code())
    }
}

type Res<T> = Result<T, Error>;

fn check(code: c_int) -> Res<c_int> {
    if code < 0 {
        Err(Error::from_code(code))
    } else {
        Ok(code)
    }
}

fn check64(code: i64) -> Res<u64> {
    if code < 0 {
        Err(Error::from_code(code as i32))
    } else {
        Ok(code as u64)
    }
}

/// The flags of `open`, littlefs's (the values of `lfs_open_flags`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Open(pub u32);

impl Open {
    pub const READ: Open = Open(1);
    pub const WRITE: Open = Open(2);
    pub const READ_WRITE: Open = Open(3);
    pub const CREATE: Open = Open(0x0100);
    pub const EXCLUSIVE: Open = Open(0x0200);
    pub const TRUNCATE: Open = Open(0x0400);
    pub const APPEND: Open = Open(0x0800);

    pub const fn with(self, other: Open) -> Open {
        Open(self.0 | other.0)
    }

    pub const fn writes(self) -> bool {
        self.0 & 2 != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Whence {
    Set = 0,
    Current = 1,
    End = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    File,
    Directory,
}

/// What `stat` says of a path: its kind and, for a file, its size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Info {
    pub kind: Kind,
    pub size: u32,
}

/// One entry of a directory.
#[derive(Clone, Copy)]
pub struct Entry {
    pub kind: Kind,
    pub size: u32,
    name: [u8; NAME_MAX + 1],
    len: usize,
}

impl Entry {
    pub fn name(&self) -> &[u8] {
        &self.name[..self.len]
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("kind", &self.kind)
            .field("size", &self.size)
            .field("name", &core::str::from_utf8(self.name()).unwrap_or("?"))
            .finish()
    }
}

/// An open file: the slot in the volume's table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct File(pub u8);

/// An open directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Dir(pub u8);

/// A path as the C string littlefs takes.
struct CPath {
    bytes: [u8; PATH_MAX + 1],
}

impl CPath {
    fn new(path: &[u8]) -> Res<Self> {
        if path.len() > PATH_MAX {
            return Err(Error::NameTooLong);
        }
        if path.contains(&0) {
            return Err(Error::Invalid);
        }
        let mut bytes = [0; PATH_MAX + 1];
        bytes[..path.len()].copy_from_slice(path);
        Ok(Self { bytes })
    }

    fn ptr(&self) -> *const c_char {
        self.bytes.as_ptr().cast()
    }
}

/// A volume over a device.
pub struct Fs<'a, D: Device> {
    device: D,
    state: &'a mut Storage,
    blocks: u32,
    mounted: bool,
    freed: u64,
}

impl<'a, D: Device> Fs<'a, D> {
    /// The volume over `device`, nothing read: `format` or `mount` comes next.
    pub fn new(device: D, state: &'a mut Storage) -> Res<Self> {
        // SAFETY: the functions only report constants of the C side.
        let ok = unsafe {
            datafs_state_size() <= STORAGE_BYTES
                && datafs_state_align() <= core::mem::align_of::<Storage>()
                && datafs_files() as usize == FILES
                && datafs_dirs() as usize == DIRS
        };
        let blocks = device.sectors() / BLOCK_SECTORS;
        if !ok || blocks < BLOCKS_MIN {
            return Err(Error::Invalid);
        }
        let blocks = u32::try_from(blocks).unwrap_or(u32::MAX);
        // SAFETY: `state` is writable memory of the size and alignment the checks above name.
        unsafe { datafs_setup(state.0.as_mut_ptr().cast(), blocks) };
        Ok(Self {
            device,
            state,
            blocks,
            mounted: false,
            freed: 0,
        })
    }

    /// The blocks of the volume.
    pub fn blocks(&self) -> u64 {
        u64::from(self.blocks)
    }

    pub fn is_mounted(&self) -> bool {
        self.mounted
    }

    /// The device, for the tests that look at the medium.
    pub fn device(&mut self) -> &mut D {
        &mut self.device
    }

    pub fn into_device(self) -> D {
        self.device
    }

    fn call<R>(&mut self, f: impl FnOnce(*mut c_void, Ctx) -> R) -> R {
        let mut object: &mut dyn Device = &mut self.device;
        let ctx = (&raw mut object).cast::<c_void>();
        f(self.state.0.as_mut_ptr().cast(), ctx)
    }

    /// Writes an empty file system over the volume.
    pub fn format(&mut self) -> Res<()> {
        // SAFETY: the C side works inside `state`, calling back into the device `ctx` names.
        check(self.call(|d, ctx| unsafe { datafs_format(d, ctx) })).map(drop)
    }

    pub fn mount(&mut self) -> Res<()> {
        // SAFETY: as above.
        check(self.call(|d, ctx| unsafe { datafs_mount(d, ctx) }))?;
        self.mounted = true;
        Ok(())
    }

    /// Closes the volume; the files must be closed first.
    pub fn unmount(&mut self) -> Res<()> {
        // SAFETY: as above.
        let result = check(self.call(|d, ctx| unsafe { datafs_unmount(d, ctx) }));
        self.mounted = false;
        result.map(drop)
    }

    /// The blocks in use.
    pub fn used_blocks(&mut self) -> Res<u64> {
        // SAFETY: as above.
        check64(self.call(|d, ctx| unsafe { datafs_used(d, ctx) }))
    }

    /// The metadata pairs of the volume and its directories (the pairs are the list `lfs_fs_pred` walks to find the pair before the one a
    /// removal takes out): about two reads for each pair.
    pub fn metadata_pairs(&mut self) -> Res<(u64, u64)> {
        let mut out = [0u32; 2];
        // SAFETY: as above; `out` holds the two words.
        check(self.call(|d, ctx| unsafe { datafs_pairs(d, ctx, out.as_mut_ptr()) }))?;
        Ok((u64::from(out[0]), u64::from(out[1])))
    }

    /// Whether the file at `path` is inline and not empty (`dry`), or, with `dry` false, moves such
    /// a file out to blocks of its own in one commit; true for such a file, false for any other (a
    /// file in a block, an empty file, a directory is an error).
    pub fn outline(&mut self, path: &[u8], dry: bool) -> Res<bool> {
        let path = CPath::new(path)?;
        // SAFETY: as above; the path is a C string that lives through the call.
        let r = self.call(|d, ctx| unsafe { datafs_outline(d, ctx, path.ptr(), c_int::from(dry)) });
        check(r).map(|n| n == 1)
    }

    /// Walks the file system once and fills the allocator's window from it: every block the tree
    /// refers to is marked, the others are free. The walk only reads. The estimate of freed blocks
    /// starts again from 0. Make it where no operation is half done (between jobs).
    pub fn walk(&mut self) -> Res<()> {
        // SAFETY: as above.
        check(self.call(|d, ctx| unsafe { datafs_walk(d, ctx) }))?;
        self.freed = 0;
        Ok(())
    }

    /// The allocator's window: its first block, the next block it hands out and its size in
    /// blocks. The next block goes back to 0 at each walk of the volume.
    pub fn window_state(&self) -> (u32, u32, u32) {
        let mut out = [0u32; 3];
        // SAFETY: reads fields of the state into three words.
        unsafe { datafs_window_state(self.state.0.as_ptr().cast(), out.as_mut_ptr()) };
        (out[0], out[1], out[2])
    }

    /// The free blocks the window still holds, counted from its bits: no device access.
    pub fn window_free(&self) -> u64 {
        // SAFETY: reads the window of the state.
        unsafe { datafs_window_free(self.state.0.as_ptr().cast()) as u64 }
    }

    /// The blocks the volume is not using, without reading the device when the window holds the
    /// whole volume and has been filled by a walk: the bits of the window from the next block to
    /// its end. The count is exact right after a walk and after allocations; blocks given back
    /// since the walk are not seen, so it is never above the true free count. Before the first walk
    /// it makes the walk. A volume larger than the window (over 4 GiB) walks the tree on every
    /// call, as `used_blocks` does.
    pub fn free_blocks(&mut self) -> Res<u64> {
        // SAFETY: reads a field of the state.
        let capacity = u64::from(unsafe { datafs_window_blocks(self.state.0.as_ptr().cast()) });
        if capacity < self.blocks() {
            return Ok(self.blocks().saturating_sub(self.used_blocks()?));
        }
        // An empty window (after the mount, or after a walk that was stopped) is filled by a walk.
        // A window that was filled in the middle of a request is as long as the checkpoint allowed
        // (shorter than the volume at times); its bits give a count that is low, never high, and the
        // worker walks again in the idle (`Fs::window_short`).
        if self.window_state().2 == 0 {
            self.walk()?;
        }
        Ok(self.window_free())
    }

    /// The window is filled and holds less than the volume: the allocator walked in the middle of a
    /// request and the checkpoint cut the window short. The free count from the bits is low until
    /// a walk fills it whole.
    pub fn window_short(&self) -> bool {
        let size = u64::from(self.window_state().2);
        size != 0 && size < self.blocks()
    }

    /// The blocks that removes, truncations and renames over a file gave back since the last walk,
    /// as far as the callers told (`note_freed_file`, `note_freed_blocks`) and truncation counts. The
    /// worker walks again in the idle when it is large and the window is low.
    pub fn freed_estimate(&self) -> u64 {
        self.freed
    }

    /// A file of `bytes` left the tree: its blocks come back at the next walk. A file small enough to
    /// live inside its directory's metadata (`INLINE_MAX` bytes or fewer) owns no block.
    pub fn note_freed_file(&mut self, bytes: u64) {
        self.freed += file_blocks(bytes);
    }

    /// `blocks` blocks came back (a directory's pair, for one).
    pub fn note_freed_blocks(&mut self, blocks: u64) {
        self.freed += blocks;
    }

    pub fn open(&mut self, path: &[u8], flags: Open) -> Res<File> {
        let path = CPath::new(path)?;
        // SAFETY: as above; the path is a C string that lives through the call.
        let slot = self.call(|d, ctx| unsafe { datafs_open(d, ctx, path.ptr(), flags.0 as c_int) });
        check(slot).map(|slot| File(slot as u8))
    }

    pub fn close(&mut self, file: File) -> Res<()> {
        // SAFETY: as above.
        check(self.call(|d, ctx| unsafe { datafs_close(d, ctx, c_int::from(file.0)) })).map(drop)
    }

    pub fn read(&mut self, file: File, out: &mut [u8]) -> Res<usize> {
        let size = u32::try_from(out.len()).unwrap_or(u32::MAX);
        // SAFETY: as above; `out` holds `size` bytes.
        let done = self.call(|d, ctx| unsafe {
            datafs_read(d, ctx, c_int::from(file.0), out.as_mut_ptr(), size)
        });
        check64(done).map(|n| n as usize)
    }

    pub fn write(&mut self, file: File, data: &[u8]) -> Res<usize> {
        let size = u32::try_from(data.len()).unwrap_or(u32::MAX);
        // SAFETY: as above.
        let done = self.call(|d, ctx| unsafe {
            datafs_write(d, ctx, c_int::from(file.0), data.as_ptr(), size)
        });
        check64(done).map(|n| n as usize)
    }

    /// The file's data and the metadata that names them are on the medium when this returns.
    pub fn sync(&mut self, file: File) -> Res<()> {
        // SAFETY: as above.
        check(self.call(|d, ctx| unsafe { datafs_sync(d, ctx, c_int::from(file.0)) })).map(drop)
    }

    /// Moves the offset of the file; the new offset from the start.
    pub fn seek(&mut self, file: File, offset: i32, whence: Whence) -> Res<u64> {
        // SAFETY: as above.
        let at = self.call(|d, ctx| unsafe {
            datafs_seek(d, ctx, c_int::from(file.0), offset, whence as c_int)
        });
        check64(at)
    }

    pub fn truncate(&mut self, file: File, size: u32) -> Res<()> {
        let before = self.size(file).unwrap_or(0);
        // SAFETY: as above.
        check(self.call(|d, ctx| unsafe { datafs_truncate(d, ctx, c_int::from(file.0), size) }))?;
        self.freed += file_blocks(before).saturating_sub(file_blocks(u64::from(size)));
        Ok(())
    }

    pub fn size(&mut self, file: File) -> Res<u64> {
        // SAFETY: as above.
        check64(self.call(|d, ctx| unsafe { datafs_size(d, ctx, c_int::from(file.0)) }))
    }

    pub fn mkdir(&mut self, path: &[u8]) -> Res<()> {
        let path = CPath::new(path)?;
        // SAFETY: as above.
        check(self.call(|d, ctx| unsafe { datafs_mkdir(d, ctx, path.ptr()) })).map(drop)
    }

    /// Removes a file or an empty directory.
    pub fn remove(&mut self, path: &[u8]) -> Res<()> {
        let path = CPath::new(path)?;
        // SAFETY: as above.
        check(self.call(|d, ctx| unsafe { datafs_remove(d, ctx, path.ptr()) })).map(drop)
    }

    /// Renames, replacing a file or an empty directory at `to` of the same kind. One commit of the
    /// directories, so a cut of the power leaves the old name or the new.
    pub fn rename(&mut self, from: &[u8], to: &[u8]) -> Res<()> {
        let (from, to) = (CPath::new(from)?, CPath::new(to)?);
        // SAFETY: as above.
        check(self.call(|d, ctx| unsafe { datafs_rename(d, ctx, from.ptr(), to.ptr()) })).map(drop)
    }

    pub fn stat(&mut self, path: &[u8]) -> Res<Info> {
        let path = CPath::new(path)?;
        let (mut kind, mut size, mut name) = (0u8, 0u32, [0u8; NAME_MAX + 1]);
        // SAFETY: as above; the outputs are as large as the C side writes.
        check(self.call(|d, ctx| unsafe {
            datafs_stat(d, ctx, path.ptr(), &mut kind, &mut size, name.as_mut_ptr())
        }))?;
        Ok(Info {
            kind: kind_of(kind)?,
            size,
        })
    }

    pub fn opendir(&mut self, path: &[u8]) -> Res<Dir> {
        let path = CPath::new(path)?;
        // SAFETY: as above.
        let slot = self.call(|d, ctx| unsafe { datafs_opendir(d, ctx, path.ptr()) });
        check(slot).map(|slot| Dir(slot as u8))
    }

    pub fn closedir(&mut self, dir: Dir) -> Res<()> {
        // SAFETY: as above.
        check(self.call(|d, ctx| unsafe { datafs_closedir(d, ctx, c_int::from(dir.0)) })).map(drop)
    }

    /// The next entry, `.` and `..` first; None at the end.
    pub fn readdir(&mut self, dir: Dir) -> Res<Option<Entry>> {
        let (mut kind, mut size, mut name) = (0u8, 0u32, [0u8; NAME_MAX + 1]);
        // SAFETY: as above.
        let more = check(self.call(|d, ctx| unsafe {
            datafs_readdir(
                d,
                ctx,
                c_int::from(dir.0),
                &mut kind,
                &mut size,
                name.as_mut_ptr(),
            )
        }))?;
        if more == 0 {
            return Ok(None);
        }
        let len = name.iter().position(|&b| b == 0).unwrap_or(NAME_MAX);
        Ok(Some(Entry {
            kind: kind_of(kind)?,
            size,
            name,
            len,
        }))
    }

    /// The user attribute `kind` of `path` into `out`: its size, or NoAttr when there is none.
    pub fn getattr(&mut self, path: &[u8], kind: u8, out: &mut [u8]) -> Res<usize> {
        let path = CPath::new(path)?;
        let size = u32::try_from(out.len()).unwrap_or(u32::MAX);
        // SAFETY: as above; `out` holds `size` bytes.
        let n = self.call(|d, ctx| unsafe {
            datafs_getattr(d, ctx, path.ptr(), kind, out.as_mut_ptr(), size)
        });
        check(n).map(|n| n as usize)
    }

    /// Sets the attribute `kind` of `path` in one commit.
    pub fn setattr(&mut self, path: &[u8], kind: u8, data: &[u8]) -> Res<()> {
        let path = CPath::new(path)?;
        let size = u32::try_from(data.len()).unwrap_or(u32::MAX);
        // SAFETY: as above.
        check(self.call(|d, ctx| unsafe {
            datafs_setattr(d, ctx, path.ptr(), kind, data.as_ptr(), size)
        }))
        .map(drop)
    }

    pub fn removeattr(&mut self, path: &[u8], kind: u8) -> Res<()> {
        let path = CPath::new(path)?;
        // SAFETY: as above.
        check(self.call(|d, ctx| unsafe { datafs_removeattr(d, ctx, path.ptr(), kind) })).map(drop)
    }

    /// The position of the iterator of `dir`: the entries it has gone past, `.` and `..` included.
    pub fn tell_dir(&mut self, dir: Dir) -> Res<u32> {
        // SAFETY: as above.
        check64(self.call(|d, ctx| unsafe { datafs_tell_dir(d, ctx, c_int::from(dir.0)) }))
            .map(|at| at as u32)
    }

    /// Moves the iterator of `dir` to a position `tell_dir` gave (from the start, so the cost
    /// grows with the position: it is for a read that failed).
    pub fn seek_dir(&mut self, dir: Dir, at: u32) -> Res<()> {
        // SAFETY: as above.
        check(self.call(|d, ctx| unsafe { datafs_seek_dir(d, ctx, c_int::from(dir.0), at) }))
            .map(drop)
    }

    pub fn rewinddir(&mut self, dir: Dir) -> Res<()> {
        // SAFETY: as above.
        check(self.call(|d, ctx| unsafe { datafs_rewinddir(d, ctx, c_int::from(dir.0)) })).map(drop)
    }
}

fn kind_of(kind: u8) -> Res<Kind> {
    match kind {
        1 => Ok(Kind::File),
        2 => Ok(Kind::Directory),
        _ => Err(Error::Corrupt),
    }
}

/// The largest file littlefs keeps inside the metadata of its directory: the smaller of the cache
/// (4096), the attribute limit (1022) and an eighth of the block (512). Such a file owns no block.
pub const INLINE_MAX: u64 = 512;

/// The blocks a file of `bytes` owns: none when it is inline, else its bytes in blocks, rounded up.
pub const fn file_blocks(bytes: u64) -> u64 {
    if bytes <= INLINE_MAX {
        0
    } else {
        blocks_of(bytes)
    }
}

impl<D: Device> Fs<'_, D> {
    /// The inline limit of the configuration for the next mount: 0 for littlefs's default (small
    /// files inside the pair of their directory, the layout an older release made, which the makers
    /// of test volumes write), `u32::MAX` for none (the service's setting).
    pub fn set_inline_max(&mut self, max: u32) {
        // SAFETY: sets a word of the configuration of the state.
        unsafe { datafs_set_inline(self.state.0.as_mut_ptr().cast(), max) };
    }
}

/// The blocks of 4 KiB `bytes` take, rounded up.
pub const fn blocks_of(bytes: u64) -> u64 {
    bytes.div_ceil(BLOCK as u64)
}

/// Calls only the host measurements make: a test-only switch for the allocator's window (the
/// service's window is the size of its volume) and the counters.
#[cfg(test)]
impl<D: Device> Fs<'_, D> {
    /// Sets the allocator's window to `buffer` (a multiple of 8 bytes) before the next format or
    /// mount: the host measurements compare the window of 128 bytes the first release had with
    /// the window of the volume's size the service has now.
    pub fn set_lookahead(&mut self, buffer: &'static mut [u8]) {
        assert!(buffer.len().is_multiple_of(8) && !buffer.is_empty());
        // SAFETY: the buffer lives for the rest of the process, and littlefs reads the pointer
        // only at the next format or mount.
        unsafe {
            datafs_set_lookahead(
                self.state.0.as_mut_ptr().cast(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
            )
        };
    }

    /// The erases littlefs has asked for since the volume was set up.
    pub fn erases(&self) -> u64 {
        // SAFETY: reads a counter of the state.
        u64::from(unsafe { datafs_erases(self.state.0.as_ptr().cast()) })
    }

    /// Opens a file with the attribute `kind` in its configuration: littlefs writes it at the
    /// sync of the file.
    pub fn open_with_attr(&mut self, path: &[u8], flags: Open, kind: u8, data: &[u8]) -> Res<File> {
        let path = CPath::new(path)?;
        let size = data.len() as u32;
        // SAFETY: as `open`; the C side copies the attribute (at most 64 bytes) into its state.
        let slot = self.call(|d, ctx| unsafe {
            datafs_open_attr(
                d,
                ctx,
                path.ptr(),
                flags.0 as c_int,
                kind,
                data.as_ptr(),
                size,
            )
        });
        check(slot).map(|slot| File(slot as u8))
    }
}

// The entries of a directory and the status of a path with a user attribute, in one read of the
// metadata pair (third-party/littlefs/STAFETO-CHANGES.md).
unsafe extern "C" {
    fn datafs_readdir_attr(
        d: *mut c_void,
        ctx: *mut c_void,
        slot: c_int,
        kind: *mut u8,
        size: *mut u32,
        name: *mut u8,
        attr: u8,
        buffer: *mut u8,
        bufsize: u32,
        attr_res: *mut i32,
    ) -> c_int;
    fn datafs_path_attrs(
        d: *mut c_void,
        ctx: *mut c_void,
        path: *const c_char,
        kind: *mut u8,
        size: *mut u32,
        name: *mut u8,
        attr: u8,
        out: *mut PathEntry,
        buffer: *mut u8,
        each: u32,
        capacity: u32,
        count: *mut u32,
    ) -> c_int;
    fn datafs_stat_attr(
        d: *mut c_void,
        ctx: *mut c_void,
        path: *const c_char,
        kind: *mut u8,
        size: *mut u32,
        name: *mut u8,
        attr: u8,
        buffer: *mut u8,
        bufsize: u32,
        attr_res: *mut i32,
    ) -> c_int;
}

/// The size of the attribute on disk, or None when the entry has none (the code of
/// `Error::NoAttr`).
fn attribute_size(found: i32) -> Res<Option<usize>> {
    match found {
        n if n == Error::NoAttr.code() => Ok(None),
        n if n >= 0 => Ok(Some(n as usize)),
        n => Err(Error::from_code(n)),
    }
}

impl<D: Device> Fs<'_, D> {
    /// The next entry of `dir` and its attribute `attr` (at most `out.len()` bytes into `out`):
    /// the entry and the size of the attribute on disk, which is None for an entry with no such
    /// attribute and always for `.` and `..`. None at the end of the directory.
    pub fn readdir_attr(
        &mut self,
        dir: Dir,
        attr: u8,
        out: &mut [u8],
    ) -> Res<Option<(Entry, Option<usize>)>> {
        let (mut kind, mut size, mut name) = (0u8, 0u32, [0u8; NAME_MAX + 1]);
        let mut found = Error::NoAttr.code();
        let room = u32::try_from(out.len()).unwrap_or(u32::MAX);
        // SAFETY: as `readdir`; `out` holds `room` bytes and `found` is a word.
        let more = check(self.call(|d, ctx| unsafe {
            datafs_readdir_attr(
                d,
                ctx,
                c_int::from(dir.0),
                &mut kind,
                &mut size,
                name.as_mut_ptr(),
                attr,
                out.as_mut_ptr(),
                room,
                &mut found,
            )
        }))?;
        if more == 0 {
            return Ok(None);
        }
        let len = name.iter().position(|&b| b == 0).unwrap_or(NAME_MAX);
        let entry = Entry {
            kind: kind_of(kind)?,
            size,
            name,
            len,
        };
        Ok(Some((entry, attribute_size(found)?)))
    }

    /// The status of `path` and its attribute `attr` (at most `out.len()` bytes into `out`): the
    /// size of the attribute on disk, or None for an entry with no such attribute.
    pub fn stat_attr(
        &mut self,
        path: &[u8],
        attr: u8,
        out: &mut [u8],
    ) -> Res<(Info, Option<usize>)> {
        let path = CPath::new(path)?;
        let (mut kind, mut size, mut name) = (0u8, 0u32, [0u8; NAME_MAX + 1]);
        let mut found = Error::NoAttr.code();
        let room = u32::try_from(out.len()).unwrap_or(u32::MAX);
        // SAFETY: as `stat`; `out` holds `room` bytes and `found` is a word.
        check(self.call(|d, ctx| unsafe {
            datafs_stat_attr(
                d,
                ctx,
                path.ptr(),
                &mut kind,
                &mut size,
                name.as_mut_ptr(),
                attr,
                out.as_mut_ptr(),
                room,
                &mut found,
            )
        }))?;
        let info = Info {
            kind: kind_of(kind)?,
            size,
        };
        Ok((info, attribute_size(found)?))
    }

    /// The status of `path` and the attribute `attr` of the root and of every entry of the path,
    /// in one walk of it that repeats no lookup (about 3 reads for each component, what a `stat` costs). `entries`
    /// and `bytes` receive the root and each entry in path order, `each` bytes of attribute for
    /// an entry (`bytes` holds `entries.len() * each`); the first number returned is how many
    /// were filled, also when the walk fails. The result is the status of the last entry, or the
    /// error: `NoEntry` for a missing name and `NotDirectory` for a file in the middle of the path
    /// with the entries above it filled, and `NameTooLong` for a path with more entries than
    /// `entries` holds.
    pub fn path_attrs(
        &mut self,
        path: &[u8],
        attr: u8,
        entries: &mut [PathEntry],
        bytes: &mut [u8],
        each: usize,
    ) -> (usize, Res<Info>) {
        let path = match CPath::new(path) {
            Ok(path) => path,
            Err(e) => return (0, Err(e)),
        };
        let capacity = entries
            .len()
            .min(bytes.len().checked_div(each).unwrap_or(usize::MAX));
        let (mut kind, mut size, mut name) = (0u8, 0u32, [0u8; NAME_MAX + 1]);
        let mut count = 0u32;
        // SAFETY: as `stat`; `entries` holds `capacity` records and `bytes` holds `capacity * each`
        // bytes, which the C side fills for the entries it counts.
        let status = self.call(|d, ctx| unsafe {
            datafs_path_attrs(
                d,
                ctx,
                path.ptr(),
                &mut kind,
                &mut size,
                name.as_mut_ptr(),
                attr,
                entries.as_mut_ptr(),
                bytes.as_mut_ptr(),
                u32::try_from(each).unwrap_or(u32::MAX),
                u32::try_from(capacity).unwrap_or(u32::MAX),
                &mut count,
            )
        });
        let count = count as usize;
        match check(status).and_then(|_| kind_of(kind)) {
            Ok(kind) => (count, Ok(Info { kind, size })),
            Err(e) => (count, Err(e)),
        }
    }
}

/// One entry of a path as `Fs::path_attrs` gives it: its kind and the size of its attribute.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PathEntry {
    res: i32,
    kind: u8,
}

impl PathEntry {
    /// A record to fill an array with.
    pub const EMPTY: PathEntry = PathEntry { res: 0, kind: 0 };

    pub fn kind(&self) -> Res<Kind> {
        kind_of(self.kind)
    }

    /// The size of the attribute on disk, or None when the entry has none.
    pub fn attr_size(&self) -> Res<Option<usize>> {
        attribute_size(self.res)
    }
}
