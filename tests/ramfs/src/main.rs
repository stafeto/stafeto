// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Guest round trip through the RAM service and the descriptor client.

#![no_std]
#![no_main]

use posix_fs::{DescriptorFlags, FileKind, FsError, OPEN_MAX, PosixFs, SeekFrom};
use posix_path::{MAX_PATH, PathState};
use proto_fs::{BAD_FD, NO_ENTRY, READ_ONLY, READ_WRITE};
use proto_wire::Status;
use rt::fs::Files;
use rt::handle::Resource;

rt::entry!(main);

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    let result = check(&start.parent);
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

fn check(parent: &rt::Handle<rt::handle::Channel>) -> Result<(), &'static str> {
    let fs = Files::connect(parent).map_err(|_| "connect")?;
    let mut name = [0; 32];
    if fs.read_dir("/", 2, &mut name) != Ok(Some((3, 1))) || &name[..3] != b"etc" {
        return Err("root entry");
    }
    if fs.read_dir("/", 4, &mut name) != Ok(None)
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
    check_posix(parent)?;
    check_seek(parent)?;
    check_duplicates(parent)?;
    check_descriptor_limit(parent)?;
    Ok(())
}

fn check_posix(parent: &rt::Handle<rt::handle::Channel>) -> Result<(), &'static str> {
    let mut posix = PosixFs::connect(parent).map_err(|_| "connect POSIX files")?;
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
    let mut posix = PosixFs::connect(parent).map_err(|_| "connect seek")?;
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
    let mut fs = PosixFs::connect(parent).map_err(|_| "dup connect")?;
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
    let mut fs = PosixFs::connect(parent).map_err(|_| "limit connect")?;
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
