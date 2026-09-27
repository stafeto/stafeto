// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Guest round trip through the RAM service and the descriptor client.

#![no_std]
#![no_main]

use posix_fs::{FileKind, FsError, PosixFs};
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
        || posix.open(b"/etc", READ_ONLY) != Err(FsError::IsDirectory)
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
    dir.rewind();
    if posix
        .readdir(&mut dir, &mut name)
        .map_err(|_| "POSIX rewind")?
        .is_none()
    {
        return Err("POSIX directory rewind");
    }
    Ok(())
}
