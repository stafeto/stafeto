// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Guest round trip through the RAM service and the descriptor client.

#![no_std]
#![no_main]

use posix_fs::{DescriptorFlags, FileKind, FsError, OPEN_MAX, PosixFs, SeekFrom, StartupFiles};
use posix_path::{MAX_PATH, PathState};
use proto_fs::{
    ACCESS_DENIED, BAD_FD, INVALID_ARGUMENT, NO_ENTRY, READ_ONLY, READ_WRITE, WRITE_ONLY,
};
use proto_wire::Status;
use rt::fs::Files;
use rt::handle::Resource;

rt::entry!(main);

struct FileCell(core::cell::UnsafeCell<core::mem::MaybeUninit<PosixFs>>);
// SAFETY: FILES_BUSY admits one native owner; its guard drops the initialized table.
unsafe impl Sync for FileCell {}
static FILES: FileCell = FileCell(core::cell::UnsafeCell::new(core::mem::MaybeUninit::uninit()));
static FILES_BUSY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
struct NativeFiles;
impl NativeFiles {
    fn connect(parent: &rt::Handle<rt::handle::Channel>) -> Result<Self, FsError> {
        use core::sync::atomic::Ordering;
        if FILES_BUSY.swap(true, Ordering::Acquire) {
            return Err(FsError::Io);
        }
        let result = StartupFiles::connect(parent, false).and_then(|startup| {
            // SAFETY: this guard owns the allocation exclusively and keeps it pinned.
            unsafe {
                PosixFs::initialize_at((*FILES.0.get()).as_mut_ptr(), startup, b"/", None, false)
            }
        });
        if let Err(error) = result {
            FILES_BUSY.store(false, Ordering::Release);
            return Err(error);
        }
        Ok(Self)
    }
}
impl core::ops::Deref for NativeFiles {
    type Target = PosixFs;
    fn deref(&self) -> &Self::Target {
        // SAFETY: a successful guard witnesses initialization and exclusive ownership.
        unsafe { (*FILES.0.get()).assume_init_ref() }
    }
}
impl core::ops::DerefMut for NativeFiles {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: a mutable guard gives the only borrow of the initialized allocation.
        unsafe { (*FILES.0.get()).assume_init_mut() }
    }
}
impl Drop for NativeFiles {
    fn drop(&mut self) {
        // SAFETY: the guard owns initialized fields and no borrowed transport survives it.
        unsafe { (*FILES.0.get()).assume_init_drop() };
        FILES_BUSY.store(false, core::sync::atomic::Ordering::Release);
    }
}

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    let result = check_initialization(&start.parent, &start.process)
        .and_then(|()| check_exact_imports(&start.parent, &start.process))
        .and_then(|()| check(&start.parent));
    match result {
        Ok(()) => {
            rt::println!("ramfs-probe: ok");
            0
        }
        Err(reason) => {
            rt::println!("ramfs-probe: failed {reason}");
            2
        }
    }
}

fn check_initialization(
    parent: &rt::Handle<rt::handle::Channel>,
    process: &rt::Handle<rt::handle::Process>,
) -> Result<(), &'static str> {
    let held = |slot, generation| rt::fs::PreparedOpen {
        fd: 34,
        slot,
        generation,
        random: true,
    };
    let old = posix_fs::RamTarget::from_prepared(held(0, 1)).map_err(|_| "old exact target")?;
    let replacement =
        posix_fs::RamTarget::from_prepared(held(127, 1)).map_err(|_| "replacement exact target")?;
    let next = posix_fs::RamTarget::from_prepared(held(0, 2)).map_err(|_| "next exact target")?;
    if old == replacement
        || old == next
        || replacement.fd() != 34
        || replacement.description_slot() != 127
        || replacement.generation() != 1
        || replacement.prepared()
            != (rt::fs::PreparedOpen {
                fd: 34,
                slot: 127,
                generation: 1,
                random: false,
            })
    {
        return Err("full target identity");
    }
    for (fd, slot, generation) in [(2, 0, 1), (35, 0, 1), (3, 128, 1), (3, 0, 0)] {
        if posix_fs::RamTarget::from_prepared(rt::fs::PreparedOpen {
            fd,
            slot,
            generation,
            random: false,
        }) != Err(FsError::Io)
        {
            return Err("invalid target publication");
        }
    }
    let before = rt::sys::process_handles(process)
        .map_err(|_| "initial handles")?
        .live;
    let duplicate = [
        posix_fs::Inherited {
            fd: 4,
            target: posix_fs::InheritedTarget::Ready(posix_fs::Target::Output),
        },
        posix_fs::Inherited {
            fd: 4,
            target: posix_fs::InheritedTarget::Ready(posix_fs::Target::Error),
        },
    ];
    let outside = [posix_fs::Inherited {
        fd: OPEN_MAX as u32,
        target: posix_fs::InheritedTarget::Ready(posix_fs::Target::Input),
    }];
    for (cwd, list, expected) in [
        (b"/bad\0cwd".as_slice(), None, FsError::InvalidArgument),
        (
            b"/".as_slice(),
            Some(duplicate.as_slice()),
            FsError::InvalidArgument,
        ),
        (
            b"/".as_slice(),
            Some(outside.as_slice()),
            FsError::BadFileDescriptor,
        ),
    ] {
        // SAFETY: this startup-only check has no initialized owner or competing user.
        let destination = unsafe { (*FILES.0.get()).as_mut_ptr() };
        // SAFETY: the entire uninitialized allocation is writable; the byte sentinel
        // is inspected exclusively as bytes until successful initialization.
        unsafe {
            destination
                .cast::<u8>()
                .write_bytes(0xa5, core::mem::size_of::<PosixFs>())
        };
        let startup =
            StartupFiles::connect(parent, false).map_err(|_| "error fixture transports")?;
        // SAFETY: the startup-only allocation is aligned, exclusive and uninitialized.
        if unsafe { PosixFs::initialize_at(destination, startup, cwd, list, false) }
            != Err(expected)
        {
            return Err("initialization error result");
        }
        // SAFETY: the sentinel initialized every byte; failed preflight writes no fields.
        let bytes = unsafe {
            core::slice::from_raw_parts(destination.cast::<u8>(), core::mem::size_of::<PosixFs>())
        };
        if bytes.iter().any(|&byte| byte != 0xa5) {
            return Err("failed initialization changed allocation");
        }
        if rt::sys::process_handles(process)
            .map_err(|_| "released startup handles")?
            .live
            != before
        {
            return Err("failed initialization retained transports");
        }
    }
    let files = NativeFiles::connect(parent).map_err(|_| "initialize after rejected preflight")?;
    if files.cwd() != b"/" || files.descriptors().count() != 3 {
        return Err("initial table state");
    }
    Ok(())
}

fn check_exact_imports(
    parent: &rt::Handle<rt::handle::Channel>,
    process: &rt::Handle<rt::handle::Process>,
) -> Result<(), &'static str> {
    use posix_fs::{Inherited, InheritedTarget, Target};
    let source = Files::connect(parent).map_err(|_| "import source")?;
    let fd = source
        .open("/etc/motd", READ_ONLY)
        .map_err(|_| "import open")?;
    let held = source
        .capture_description(fd)
        .map_err(|_| "import capture")?
        .held;
    let raw = InheritedTarget::RawRam {
        fd,
        random_hint: false,
    };
    let wrong = posix_fs::RamTarget::from_prepared(rt::fs::PreparedOpen {
        slot: (held.slot + 1) % 128,
        ..held
    })
    .map_err(|_| "mismatched import token")?;
    for (last, expected) in [
        (
            InheritedTarget::RawRam {
                fd: 35,
                random_hint: false,
            },
            FsError::BadFileDescriptor,
        ),
        (InheritedTarget::Ready(Target::Ram(wrong)), FsError::Io),
    ] {
        let before = rt::sys::process_handles(process)
            .map_err(|_| "import handle baseline")?
            .live;
        let channel = Files::clone_exact_on(source.sessions().0, &[held])
            .map_err(|_| "import failure clone")?;
        let startup = StartupFiles::from_sessions(channel, None, None, None);
        let list = [
            Inherited { fd: 4, target: raw },
            Inherited {
                fd: 7,
                target: last,
            },
        ];
        // SAFETY: no native guard owns this startup allocation.
        let destination = unsafe { (*FILES.0.get()).as_mut_ptr() };
        // SAFETY: the full allocation is uninitialized and exclusive.
        unsafe {
            destination
                .cast::<u8>()
                .write_bytes(0xa5, core::mem::size_of::<PosixFs>())
        };
        // SAFETY: the allocation is aligned, exclusive and retains no initialized fields.
        if unsafe { PosixFs::initialize_at(destination, startup, b"/", Some(&list), false) }
            != Err(expected)
        {
            return Err("last import failure");
        }
        // SAFETY: the sentinel initialized every byte and preflight must preserve them.
        let bytes = unsafe {
            core::slice::from_raw_parts(destination.cast::<u8>(), core::mem::size_of::<PosixFs>())
        };
        if bytes.iter().any(|&byte| byte != 0xa5) {
            return Err("last import changed destination");
        }
        if rt::sys::process_handles(process)
            .map_err(|_| "import released handle")?
            .live
            != before
        {
            return Err("last import retained channel");
        }
    }
    let channel =
        Files::clone_exact_on(source.sessions().0, &[held]).map_err(|_| "alias import clone")?;
    let startup = StartupFiles::from_sessions(channel, None, None, None);
    let list = [
        Inherited { fd: 4, target: raw },
        Inherited { fd: 7, target: raw },
    ];
    // SAFETY: the failed preflights left the allocation uninitialized and exclusive.
    unsafe {
        PosixFs::initialize_at(
            (*FILES.0.get()).as_mut_ptr(),
            startup,
            b"/",
            Some(&list),
            false,
        )
    }
    .map_err(|_| "alias import initialization")?;
    FILES_BUSY.store(true, core::sync::atomic::Ordering::Release);
    let mut native = NativeFiles;
    let exact = posix_fs::RamTarget::from_prepared(held).map_err(|_| "alias exact target")?;
    if native.target(4) != Ok(Target::Ram(exact)) || native.target(7) != Ok(Target::Ram(exact)) {
        return Err("alias import token");
    }
    let mut kept = [held; OPEN_MAX];
    if native.kept_by_fork(&mut kept) != 1 || kept[0] != exact.prepared() {
        return Err("exact alias clone list");
    }
    let child = Files::clone_exact_on(native.sessions().0, &kept[..1])
        .map_err(|_| "normalized exact clone")?;
    let child = Files::from_sessions(child, None);
    if child
        .capture_description(fd)
        .map_err(|_| "child exact token")?
        .held
        != held
    {
        return Err("clone changed full token");
    }
    let mut bytes = [0; 3];
    if native.read(4, &mut bytes) != Ok(3) || &bytes != b"sta" {
        return Err("first imported alias read");
    }
    if native.read(7, &mut bytes) != Ok(3) || &bytes != b"fet" {
        return Err("import aliases shared offset");
    }
    native.close(4).map_err(|_| "close first import alias")?;
    if native.read(7, &mut bytes) != Ok(3) || &bytes != b"o r" {
        return Err("import surviving alias");
    }
    check_cancel_ack(&mut native)?;
    native.close(7).map_err(|_| "close last import alias")?;
    // The child's own reference remains live after the parent's exact Close.
    if child.read(fd, &mut bytes) != Ok(3) || &bytes != b"amf" {
        return Err("child retained exact clone");
    }
    child.close_exact(held).map_err(|_| "child exact close")?;
    source.close_exact(held).map_err(|_| "source exact close")?;
    Ok(())
}

fn check_cancel_ack(files: &mut PosixFs) -> Result<(), &'static str> {
    use posix_fs::open::{Completion, OwnerToken};
    let owner = OwnerToken::new(17).map_err(|_| "cancel original owner")?;
    let foreign = OwnerToken::new(18).map_err(|_| "cancel foreign owner")?;
    for canonical in [true, false] {
        for _ in 0..64 {
            let (token, claim) = files
                .begin_open_record(owner, READ_ONLY, posix_fs::DescriptorFlags::default())
                .map_err(|_| "cancel race admission")?;
            files
                .begin_open_cancel(claim)
                .map_err(|_| "cancel race transition")?;
            // The helper's first canonical result is saved before the original reply.
            files
                .finish_open_cancel(token, 13)
                .map_err(|_| "helper saved cancellation")?;
            if files.acknowledge_open_cancel(token, foreign, canonical, 5)
                != Err(FsError::BadFileDescriptor)
                || files.acknowledge_open_cancel(token, owner, canonical, 5)
                    != Ok(Some(Completion::Failed(13)))
                || files.open_tokens().next().is_some()
            {
                return Err("helper original cancel acknowledgement");
            }
        }
    }
    rt::println!("ramfs-probe: exact imports and 128 Cancel/ACK races ok");
    Ok(())
}

fn check(parent: &rt::Handle<rt::handle::Channel>) -> Result<(), &'static str> {
    let fs = Files::connect(parent).map_err(|_| "connect")?;
    let mut name = [0; 32];
    if fs.read_dir("/", 2, &mut name) != Ok(Some((3, 1))) || &name[..3] != b"etc" {
        return Err("root entry");
    }
    // The directories of the boot image's table follow `etc` and `tmp`.
    if fs.read_dir("/", 4, &mut name) != Ok(Some((3, 1))) || &name[..3] != b"bin" {
        return Err("root entry of the image");
    }
    if fs.read_dir("/", 6, &mut name) != Ok(None)
        || fs.read_dir("/missing", 0, &mut name) != Err(Status::Unknown(NO_ENTRY))
    {
        return Err("directory end and error");
    }
    if fs.read_dir("/etc", 2, &mut name) != Ok(Some((4, 2))) || &name[..4] != b"motd" {
        return Err("etc entry");
    }
    let mut paths = PathState::new();
    paths.set_cwd(b"/etc").map_err(|_| "set cwd")?;
    let mut path = [0; MAX_PATH + 1];
    let length = paths
        .resolve(b"./motd", &mut path)
        .map_err(|_| "resolve relative")?;
    let path = core::str::from_utf8(&path[..length]).map_err(|_| "ramfs path encoding")?;
    let relative_motd = fs.open(path, READ_ONLY).map_err(|_| "open resolved motd")?;
    fs.close(relative_motd).map_err(|_| "close resolved motd")?;
    let motd = fs.open("/etc/motd", READ_ONLY).map_err(|_| "open motd")?;
    if fs.fstat_size(motd) != Ok(14) {
        return Err("stat motd");
    }
    let mut bytes = [0; 32];
    let n = fs.read(motd, &mut bytes).map_err(|_| "read motd")?;
    if &bytes[..n] != b"stafeto ramfs\n" {
        return Err("motd data");
    }
    fs.close(motd).map_err(|_| "close motd")?;
    if fs.read(motd, &mut bytes) != Err(Status::Unknown(BAD_FD)) {
        return Err("closed fd");
    }
    if fs.open("/missing", READ_ONLY) != Err(Status::Unknown(NO_ENTRY)) {
        return Err("missing path");
    }
    let fd = fs
        .open("/tmp/probe", READ_WRITE)
        .map_err(|_| "open scratch")?;
    if fs.write(fd, b"abc") != Ok(3) {
        return Err("write scratch");
    }
    if fs.lseek(fd, 1) != Ok(1) {
        return Err("seek scratch");
    }
    if fs.write(fd, b"Z") != Ok(1) {
        return Err("overwrite scratch");
    }
    if fs.fstat_size(fd) != Ok(3) {
        return Err("stat scratch");
    }
    fs.lseek(fd, 0).map_err(|_| "rewind scratch")?;
    if fs.read(fd, &mut bytes[..3]) != Ok(3) || &bytes[..3] != b"aZc" {
        return Err("scratch data");
    }
    let line = b"ramfs-probe: stdout ok\n";
    if fs.write(1, line) != Ok(line.len()) {
        return Err("stdout");
    }
    fs.close(fd).map_err(|_| "close scratch")?;
    check_image(&fs)?;
    check_posix(parent)?;
    check_seek(parent)?;
    check_duplicates(parent)?;
    check_descriptor_limit(parent)?;
    Ok(())
}

/// The files of the boot image's table (xtask's rootfs.rs): modes, owners,
/// sizes, links and reads at an offset.
fn check_image(fs: &Files) -> Result<(), &'static str> {
    let program = fs
        .node_information("/bin/ramfs-probe")
        .map_err(|_| "stat image file")?;
    if (
        program.kind,
        program.permissions,
        program.uid,
        program.gid,
        program.links,
    ) != (2, 0o755, 0, 0, 3)
    {
        return Err("image file mode, owner or links");
    }
    // xtask compares this size with the ELF file on the host.
    rt::println!("ramfs-probe: image file size {}", program.size);
    let link = fs.node_information("/bin/probe").map_err(|_| "stat link")?;
    let service = fs
        .node_information("/bin/ramfs")
        .map_err(|_| "stat service")?;
    if link.inode != program.inode
        || link.size != program.size
        || service.inode == program.inode
        || (service.permissions, service.uid, service.gid) != (0o4750, 1000, 100)
    {
        return Err("image links and owners");
    }
    let bin = fs.node_information("/bin").map_err(|_| "stat directory")?;
    if (bin.kind, bin.permissions, bin.links) != (1, 0o755, 2) {
        return Err("image directory");
    }
    let mut name = [0; 32];
    for (index, expected) in [".", "..", "probe", "ramfs", "ramfs-probe"]
        .iter()
        .enumerate()
    {
        let entry = fs.read_dir("/bin", index as u32, &mut name);
        if entry != Ok(Some((expected.len(), if index < 2 { 1 } else { 2 })))
            || &name[..expected.len()] != expected.as_bytes()
        {
            return Err("image directory entries");
        }
    }
    if fs.read_dir("/bin", 5, &mut name) != Ok(None) {
        return Err("image directory end");
    }
    let fd = fs
        .open("/bin/ramfs-probe", READ_ONLY)
        .map_err(|_| "open image file")?;
    let mut magic = [0; 4];
    if fs.read_at(fd, 0, &mut magic) != Ok(4) || &magic != b"\x7fELF" {
        return Err("ELF magic at offset 0");
    }
    // The whole file in pieces of 1 000 bytes at their offsets, and the
    // same bytes read in order from the position of the description.
    let (mut offset, mut chunk, mut order) = (0u64, [0; 1000], [0; 1000]);
    while offset < program.size {
        let n = fs.read_at(fd, offset, &mut chunk).map_err(|_| "read at")?;
        if n == 0 || fs.read(fd, &mut order[..n]) != Ok(n) || chunk[..n] != order[..n] {
            return Err("read at against read");
        }
        offset += n as u64;
    }
    if offset != program.size {
        return Err("read at sums to the size");
    }
    // The read at an offset left the position where the reads put it: the end.
    if fs.read(fd, &mut chunk) != Ok(0)
        || fs.read_at(fd, program.size, &mut chunk) != Ok(0)
        || fs.read_at(fd, 1 << 40, &mut chunk) != Ok(0)
        || fs.read_at(fd, 1 << 63, &mut chunk) != Err(Status::Unknown(INVALID_ARGUMENT))
        || fs.read_at(99, 0, &mut chunk) != Err(Status::Unknown(BAD_FD))
    {
        return Err("read at the end and past it");
    }
    fs.close(fd).map_err(|_| "close image file")?;
    if fs.open("/bin/ramfs-probe", WRITE_ONLY) != Err(Status::Unknown(ACCESS_DENIED)) {
        return Err("image files are read-only");
    }
    // The longest path: a name of 255 bytes, then one of 254.
    let mut path = [b'm'; MAX_PATH];
    path[0] = b'/';
    path[256] = b'/';
    path[1..256].fill(b'n');
    let deep = core::str::from_utf8(&path).map_err(|_| "deep path")?;
    let deep_info = fs
        .node_information(deep)
        .map_err(|_| "stat the longest path")?;
    let deep_fd = fs
        .open(deep, READ_ONLY)
        .map_err(|_| "open the longest path")?;
    if deep_info.inode != program.inode
        || fs.read_at(deep_fd, 0, &mut magic) != Ok(4)
        || &magic != b"\x7fELF"
    {
        return Err("the longest path");
    }
    fs.close(deep_fd).map_err(|_| "close the longest path")?;
    // One byte more is no path; the same length with another name is absent.
    let mut over = [b'm'; MAX_PATH + 1];
    over[0] = b'/';
    let over = core::str::from_utf8(&over).map_err(|_| "over path")?;
    if fs.open(over, READ_ONLY) != Err(Status::BadSize) {
        return Err("path over the limit");
    }
    path[300] = b'x';
    let absent = core::str::from_utf8(&path).map_err(|_| "absent path")?;
    if fs.open(absent, READ_ONLY) != Err(Status::Unknown(NO_ENTRY)) {
        return Err("path of the limit but absent");
    }
    Ok(())
}

fn check_posix(parent: &rt::Handle<rt::handle::Channel>) -> Result<(), &'static str> {
    let mut posix = NativeFiles::connect(parent).map_err(|_| "connect POSIX files")?;
    if posix.stat(b"/").map_err(|_| "stat root")?.kind != FileKind::Directory {
        return Err("root type");
    }
    let motd = posix.stat(b"/etc/motd").map_err(|_| "stat path")?;
    if motd.kind != FileKind::Regular || motd.size != 14 {
        return Err("motd metadata");
    }
    if posix.stat(b"/etc/motd/") != Err(FsError::NotDirectory)
        || posix.stat(b"/missing") != Err(FsError::NoEntry)
    {
        return Err("POSIX path errors");
    }
    if posix
        .stat(b"/tmp/probe")
        .map_err(|_| "stat scratch path")?
        .size
        != 3
        || posix.open(b"/etc/motd/", READ_ONLY) != Err(FsError::NotDirectory)
        || posix.open(b"/etc", proto_fs::WRITE_ONLY) != Err(FsError::IsDirectory)
    {
        return Err("POSIX metadata and open errors");
    }
    posix.chdir(b"etc").map_err(|_| "POSIX chdir")?;
    if posix.cwd() != b"/etc" || posix.chdir(b"motd") != Err(FsError::NotDirectory) {
        return Err("POSIX cwd");
    }
    let fd = posix.open(b"./motd", READ_ONLY).map_err(|_| "POSIX open")?;
    let mut bytes = [0; 32];
    if posix.read(fd, &mut bytes).map_err(|_| "POSIX read")? != 14
        || &bytes[..14] != b"stafeto ramfs\n"
    {
        return Err("POSIX file contents");
    }
    posix.close(fd).map_err(|_| "POSIX close")?;
    let mut dir = posix.opendir(b".").map_err(|_| "POSIX opendir")?;
    if posix.descriptor_flags(dir.descriptor())
        != Ok(DescriptorFlags {
            close_on_exec: true,
            close_on_fork: false,
        })
    {
        return Err("opendir close-on-exec flag");
    }
    let mut name = [0; 32];
    for expected in [b".".as_slice(), b"..".as_slice(), b"motd".as_slice()] {
        let entry = posix
            .readdir(&mut dir, &mut name)
            .map_err(|_| "POSIX readdir")?
            .ok_or("POSIX directory short")?;
        if &name[..entry.name_len] != expected {
            return Err("POSIX directory entry");
        }
    }
    if posix.readdir(&mut dir, &mut name) != Ok(None)
        || posix.opendir(b"motd").err() != Some(FsError::NotDirectory)
    {
        return Err("POSIX directory end or error");
    }
    posix.rewinddir(&dir).map_err(|_| "POSIX rewind position")?;
    if posix
        .readdir(&mut dir, &mut name)
        .map_err(|_| "POSIX rewind")?
        .is_none()
    {
        return Err("POSIX directory rewind");
    }
    posix.closedir(&dir).map_err(|_| "POSIX closedir")?;
    let fd = posix
        .open(b"/etc", READ_ONLY)
        .map_err(|_| "directory open")?;
    let flags = DescriptorFlags {
        close_on_exec: false,
        close_on_fork: true,
    };
    posix
        .set_descriptor_flags(fd, flags)
        .map_err(|_| "directory flags")?;
    let dir = posix.fdopendir(fd).map_err(|_| "fdopendir")?;
    if dir.descriptor() != fd || posix.descriptor_flags(fd) != Ok(flags) {
        return Err("fdopendir flag retention");
    }
    posix.closedir(&dir).map_err(|_| "fdopendir close")?;
    if posix.fstat(fd) != Err(FsError::BadFileDescriptor) {
        return Err("closedir ownership");
    }
    Ok(())
}

fn check_seek(parent: &rt::Handle<rt::handle::Channel>) -> Result<(), &'static str> {
    let mut posix = NativeFiles::connect(parent).map_err(|_| "connect seek")?;
    let fd = posix
        .open(b"/tmp/probe", READ_WRITE)
        .map_err(|_| "open seek")?;
    if posix.lseek(fd, -1, SeekFrom::End) != Ok(2)
        || posix.lseek(fd, -1, SeekFrom::Current) != Ok(1)
        || posix.lseek(fd, -2, SeekFrom::Current) != Err(FsError::InvalidArgument)
        || posix.lseek(fd, 0, SeekFrom::Current) != Ok(1)
        || posix.lseek(fd, 1, SeekFrom::Data) != Ok(1)
        || posix.lseek(fd, 1, SeekFrom::Hole) != Ok(3)
        || posix.lseek(fd, 3, SeekFrom::Data) != Err(FsError::NoData)
        || posix.lseek(fd, 3, SeekFrom::Hole) != Err(FsError::NoData)
    {
        return Err("seek origins or errors");
    }
    if posix.lseek(fd, i64::MAX, SeekFrom::Start) != Ok(i64::MAX)
        || posix.lseek(fd, 1, SeekFrom::Current) != Err(FsError::OffsetOverflow)
        || posix.lseek(fd, -1, SeekFrom::Start) != Err(FsError::InvalidArgument)
        || posix.lseek(fd, 0, SeekFrom::Current) != Ok(i64::MAX)
        || posix.read(fd, &mut [0; 1]) != Ok(0)
        || posix.write(fd, b"x") != Err(FsError::NoSpace)
        || posix.write(fd, b"") != Ok(0)
        || posix.fstat(fd).map_err(|_| "seek stat")?.size != 3
    {
        return Err("wide seek preserves offset and size");
    }
    if posix.lseek(fd, 7, SeekFrom::Start) != Ok(7) || posix.write(fd, b"z") != Ok(1) {
        return Err("write after seek beyond EOF");
    }
    posix
        .lseek(fd, 0, SeekFrom::Start)
        .map_err(|_| "rewind gap")?;
    let mut bytes = [0; 8];
    if posix.read(fd, &mut bytes) != Ok(8) || &bytes != b"aZc\0\0\0\0z" {
        return Err("seek gap zero fill");
    }
    posix.close(fd).map_err(|_| "close seek")?;
    if posix.lseek(fd, 0, SeekFrom::Start) != Err(FsError::BadFileDescriptor)
        || posix.read(fd, &mut []) != Err(FsError::BadFileDescriptor)
        || posix.write(fd, b"") != Err(FsError::BadFileDescriptor)
    {
        return Err("zero IO closed descriptor");
    }
    let read = posix
        .open(b"/etc/motd", READ_ONLY)
        .map_err(|_| "open read only")?;
    let write = posix
        .open(b"/tmp/probe", proto_fs::WRITE_ONLY)
        .map_err(|_| "open write only")?;
    if posix.write(read, b"") != Err(FsError::BadFileDescriptor)
        || posix.read(write, &mut []) != Err(FsError::BadFileDescriptor)
        || posix.read(write, &mut bytes) != Err(FsError::BadFileDescriptor)
    {
        return Err("zero IO access modes");
    }
    posix.close(read).map_err(|_| "close read only")?;
    posix.close(write).map_err(|_| "close write only")?;
    Ok(())
}

fn check_duplicates(parent: &rt::Handle<rt::handle::Channel>) -> Result<(), &'static str> {
    let mut fs = NativeFiles::connect(parent).map_err(|_| "dup connect")?;
    if fs.fstat(1).map_err(|_| "console stat")?.kind != FileKind::Character
        || fs.lseek(1, 0, SeekFrom::Start) != Err(FsError::NotSeekable)
        || fs.read(1, &mut []) != Err(FsError::BadFileDescriptor)
        || fs.write(0, b"") != Err(FsError::BadFileDescriptor)
    {
        return Err("console descriptor semantics");
    }
    let original = fs.open(b"/etc/motd", READ_ONLY).map_err(|_| "dup open")?;
    let flags = DescriptorFlags {
        close_on_exec: true,
        close_on_fork: true,
    };
    fs.set_descriptor_flags(original, flags)
        .map_err(|_| "set descriptor flags")?;
    let copy = fs.dup(original).map_err(|_| "dup")?;
    let independent = fs
        .open(b"/etc/motd", READ_ONLY)
        .map_err(|_| "independent open")?;
    if (original, copy, independent) != (3, 4, 5)
        || fs.descriptor_flags(copy) != Ok(DescriptorFlags::default())
        || fs.descriptor_flags(original) != Ok(flags)
    {
        return Err("descriptor allocation and flags");
    }
    if fs.write(copy, b"x") != Err(FsError::BadFileDescriptor) {
        return Err("dup preserves read-only access mode");
    }
    let mut bytes = [0; 8];
    if fs.read(original, &mut bytes[..3]) != Ok(3)
        || &bytes[..3] != b"sta"
        || fs.read(copy, &mut bytes[..4]) != Ok(4)
        || &bytes[..4] != b"feto"
        || fs.lseek(copy, 0, SeekFrom::Start) != Ok(0)
        || fs.read(original, &mut bytes[..1]) != Ok(1)
        || bytes[0] != b's'
        || fs.read(independent, &mut bytes[..1]) != Ok(1)
        || bytes[0] != b's'
    {
        return Err("dup shares offset; open has its own");
    }
    if fs.dup2(original, original) != Ok(original)
        || fs.descriptor_flags(original) != Ok(flags)
        || fs.dup3(original, original, flags) != Err(FsError::InvalidArgument)
        || fs.dup2(99, independent) != Err(FsError::BadFileDescriptor)
        || fs.read(independent, &mut bytes[..1]) != Ok(1)
        || bytes[0] != b't'
    {
        return Err("dup2 invalid source and same descriptor");
    }
    if fs.dup3(original, independent, flags) != Ok(independent)
        || fs.descriptor_flags(independent) != Ok(flags)
        || fs.dup2(original, independent) != Ok(independent)
        || fs.descriptor_flags(independent) != Ok(DescriptorFlags::default())
    {
        return Err("dup3 flags and dup2 clearing");
    }
    fs.close(original).map_err(|_| "close original")?;
    if fs.read(original, &mut []) != Err(FsError::BadFileDescriptor)
        || fs.read(copy, &mut bytes[..2]) != Ok(2)
        || &bytes[..2] != b"ta"
    {
        return Err("duplicate survives source close");
    }
    fs.close(independent).map_err(|_| "close replacement")?;
    fs.close(copy).map_err(|_| "close final copy")?;
    // Repeated replacement must release the old service description each time.
    let target = fs
        .open(b"/etc/motd", READ_ONLY)
        .map_err(|_| "open replacement target")?;
    for _ in 0..64 {
        let source = fs
            .open(b"/etc/motd", READ_ONLY)
            .map_err(|_| "replacement leaked backend")?;
        fs.dup2(source, target).map_err(|_| "replace backend")?;
        fs.close(source).map_err(|_| "close replacement source")?;
    }
    fs.close(target).map_err(|_| "close final target")?;
    let saved = fs.dup(1).map_err(|_| "save stdout")?;
    let file = fs
        .open(b"/tmp/probe", READ_WRITE)
        .map_err(|_| "open redirection")?;
    fs.dup2(file, 1).map_err(|_| "redirect stdout")?;
    fs.close(file).map_err(|_| "close redirection source")?;
    if fs.write(1, b"redirect") != Ok(8) || fs.fstat(1).map_err(|_| "redirect stat")?.size != 8 {
        return Err("redirected stdout writes file");
    }
    fs.lseek(1, 0, SeekFrom::Start)
        .map_err(|_| "redirect rewind")?;
    if fs.read(1, &mut bytes) != Ok(8) || &bytes != b"redirect" {
        return Err("redirect contents");
    }
    fs.dup2(saved, 1).map_err(|_| "restore stdout")?;
    fs.close(saved).map_err(|_| "close saved stdout")?;
    let marker = b"ramfs-probe: restored stdout ok\n";
    if fs.write(1, marker) != Ok(marker.len()) {
        return Err("restored console output");
    }
    fs.close(0).map_err(|_| "close stdin")?;
    let zero = fs
        .open(b"/etc/motd", READ_ONLY)
        .map_err(|_| "open descriptor zero")?;
    if zero != 0 || fs.read(zero, &mut bytes[..1]) != Ok(1) || bytes[0] != b's' {
        return Err("file at descriptor zero");
    }
    fs.close(zero).map_err(|_| "close descriptor zero")?;
    Ok(())
}

fn check_descriptor_limit(parent: &rt::Handle<rt::handle::Channel>) -> Result<(), &'static str> {
    let mut fs = NativeFiles::connect(parent).map_err(|_| "limit connect")?;
    let source = fs.open(b"/etc/motd", READ_ONLY).map_err(|_| "limit open")?;
    for expected in 4..OPEN_MAX as u32 {
        if fs.dup(source) != Ok(expected) {
            return Err("dup limit allocation");
        }
    }
    if fs.dup(source) != Err(FsError::TooManyOpenFiles)
        || fs.open(b"/etc/motd", READ_ONLY) != Err(FsError::TooManyOpenFiles)
        || fs.dup2(source, OPEN_MAX as u32) != Err(FsError::BadFileDescriptor)
    {
        return Err("descriptor exhaustion");
    }
    for fd in 4..OPEN_MAX as u32 {
        fs.close(fd).map_err(|_| "close limit duplicate")?;
    }
    let fresh = fs
        .open(b"/etc/motd", READ_ONLY)
        .map_err(|_| "reuse descriptor")?;
    if fresh != 4 || fs.read(source, &mut [0; 1]) != Ok(1) {
        return Err("limit recovery preserves open description");
    }
    fs.close(fresh).map_err(|_| "close fresh")?;
    fs.close(source).map_err(|_| "close limit source")?;
    // The advertised local bound must also be reachable with distinct opens.
    for expected in 3..OPEN_MAX as u32 {
        if fs.open(b"/etc/motd", READ_ONLY) != Ok(expected) {
            return Err("distinct open descriptions reach local bound");
        }
    }
    if fs.open(b"/etc/motd", READ_ONLY) != Err(FsError::TooManyOpenFiles) {
        return Err("distinct open descriptor exhaustion");
    }
    for fd in 3..OPEN_MAX as u32 {
        fs.close(fd).map_err(|_| "close distinct description")?;
    }
    Ok(())
}
