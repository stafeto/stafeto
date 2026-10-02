// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Single-threaded RAM file service. Each client session has its own fds.
//! The service opens a program's file for a loader (OPEN_EXEC, spec 2,
//! 3.2; 5c) through the session of the loaders alone, with the process
//! service vouching for the loader's identity through the service's
//! notary session, and gives a client a session for its child (CLONE).

#![no_std]
#![no_main]

use core::cell::UnsafeCell;
use core::mem::ManuallyDrop;
use proto_fs::{MAX_READ, MAX_WRITE, Method, VERSION, valid_path};
use proto_init::ServiceArgs;
use proto_wire::Status;
use ramfs::tree::{self, Index};
use ramfs::{Exec, SET_GID, SET_UID};
use ramfs::{Fds, Ram};
use rt::abi::{Access, Rights};
use rt::handle::{Channel, Handle, Memory, Outgoing, Resource};
use rt::service::{Answer, Config, Heartbeat, Request, Service, Session};
use rt::sys;

rt::entry!(main);

const METHODS: &[u16] = proto_fs::METHODS;
/// The sessions: one place the image sessions share (they hold nothing),
/// then the clients', with room for the children of POSIX processes.
const SESSIONS: usize = 16;
/// Where the service maps the boot image, read-only, for as long as it
/// lives: the files of its table are read from there.
const IMAGE: usize = 0x50_0000_0000;

/// The index of the table of the boot image, in the service's `.bss`.
struct Table(UnsafeCell<Index>);
// SAFETY: only the main thread reaches it, once (`image_tree`).
unsafe impl Sync for Table {}
static TABLE: Table = Table(UnsafeCell::new(Index::new()));

/// The files of the boot image's table: the image is mapped from the
/// start data (`bootimage`, given to this record by init), and the table is
/// read. An image with no table, or no image, leaves the fixed tree alone.
fn image_tree(start: &mut rt::startup::Startup) -> Option<tree::Tree<'static>> {
    let image = start.take::<Memory>("bootimage").ok()?;
    let size = sys::memory_info(&image).ok()?.size;
    sys::mem_map(&start.process, &image, 0, size, IMAGE, Access::Read).ok()?;
    // SAFETY: the image stays mapped, read-only, for the life of the process.
    let bytes = unsafe { core::slice::from_raw_parts(IMAGE as *const u8, size as usize) };
    // SAFETY: only the main thread reaches TABLE, here once.
    let index = unsafe { &mut *TABLE.0.get() };
    match tree::load(bytes, index) {
        Ok(tree) => Some(tree),
        Err(tree::Error::Missing) => None,
        Err(error) => {
            rt::println!("ramfs: the table of the boot image is refused: {error:?}");
            None
        }
    }
}

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    let now = rt::time::ticks_to_ns(rt::time::now());
    let ram = match image_tree(&mut start) {
        Some(tree) => Ram::with_tree(now, tree),
        None => Ram::new(now),
    };
    let args = ServiceArgs::read(start.args()).ok();
    let level = sys::thread_info(&start.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(1) else {
        return 2;
    };
    if rt::service::register(&start.parent, &channel).is_err() {
        return 3;
    }
    let heartbeat = Heartbeat {
        to: &start.parent,
        period_ns: args.map_or(0, |args| args.period_ns),
        priority: level,
    };
    let config = Config {
        issued: 0,
        heartbeat: Some(heartbeat),
    };
    rt::println!("ramfs: ready");
    let mut fs = Fs {
        ram,
        channel: Handle::borrowed(channel.raw()),
        parent: Handle::borrowed(start.parent.raw()),
        notary: None,
        given: 0,
        level,
    };
    let _ = rt::service::run::<Fs, SESSIONS, 0>(&channel, &mut fs, config);
    4
}

struct Fs {
    ram: Ram<'static>,
    /// The service's channel, which its own sessions are copies of, and
    /// its connection to init, which gives the notary session.
    channel: ManuallyDrop<Handle<Channel>>,
    parent: ManuallyDrop<Handle<Channel>>,
    /// The notary session with the process service (init's VOUCHERS),
    /// asked for at the first OPEN_EXEC.
    notary: Option<Handle<Channel>>,
    /// The sessions the service gave itself so far.
    given: u64,
    level: u8,
}

impl Fs {
    /// The notary session, asked of init once.
    fn notary(&mut self) -> Option<&Handle<Channel>> {
        if self.notary.is_none() {
            self.notary = rt::service::connect(&self.parent, "posix").ok();
        }
        self.notary.as_ref()
    }

    /// A session of the service's own with `label` for a client.
    fn session(&mut self, label: u64) -> Result<Handle<Channel>, rt::abi::Error> {
        self.given += 1;
        sys::handle_label(
            &self.channel,
            Rights::SEND | Rights::TRANSFER,
            label,
            self.level,
        )
    }

    /// OPEN_EXEC of `path` for the loader whose identity `r` brings, from
    /// the session of the loaders (condition O1, condition O3): the process service vouches
    /// for it, the path resolves for the effective IDs of the record it
    /// loads in this one step, the set-ID bits go to the process service
    /// before the reply, and the reply brings the image session.
    fn open_exec(&mut self, r: &mut Request<'_>) -> Answer {
        if !proto_fs::is_loaders(r.label()) || r.handles.len() != 1 {
            return status(proto_fs::PERMISSION);
        }
        let label = r.label();
        let Ok(path) = r.body().bytes(r.body().left()).and_then(valid_path) else {
            return Answer::Status(Status::BadSize);
        };
        // The copy goes to the process service, and no copy stays here.
        let Ok(identity) = r.handles.take::<Channel>(0) else {
            return status(proto_fs::PERMISSION);
        };
        let Some(notary) = self.notary() else {
            return status(proto_fs::PERMISSION);
        };
        let request = proto_process::Method::Vouch.header().bytes();
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        let who = sys::send_handles(notary, &request, [identity.erase()])
            .ok()
            .and_then(|reply| proto_process::WhoReply::read(reply.bytes(&mut buffer)).ok());
        let (ids, pid, loader) = match ramfs::exec_for(label, who) {
            Ok(found) => found,
            Err(code) => return status(code),
        };
        let exec = match self.ram.exec(path, ids) {
            Ok(exec) => exec,
            Err(code) => return status(code),
        };
        if !self.tell_set_id(&exec, pid, loader) {
            return status(proto_fs::PERMISSION);
        }
        let label = proto_fs::image_label(self.given, exec.entry);
        match self.session(label) {
            Ok(session) => {
                if r.reply().u32(0).is_err() {
                    return Answer::Status(Status::BadSize);
                }
                Answer::Reply([session.erase()].into())
            }
            Err(e) => Answer::Status(Status::Kernel(e)),
        }
    }

    /// SetId for a file with a set-ID bit, through the notary session:
    /// whether the process service kept it, or the file has none.
    fn tell_set_id(&mut self, exec: &Exec, pid: u32, loader: proto_process::LoaderOf) -> bool {
        if exec.mode & (SET_UID | SET_GID) == 0 {
            return true;
        }
        let pick = |bit, id| {
            if exec.mode & bit != 0 {
                id
            } else {
                proto_process::NO_ID
            }
        };
        let set = proto_process::SetId {
            ticket: loader.ticket,
            pid,
            image: loader.image,
            uid: pick(SET_UID, exec.uid),
            gid: pick(SET_GID, exec.gid),
        };
        let mut w = proto_wire::Writer::new();
        if proto_process::Method::SetId.header().write(&mut w).is_err()
            || set.write(&mut w).is_err()
        {
            return false;
        }
        let Some(notary) = self.notary() else {
            return false;
        };
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        sys::send(notary, w.as_bytes())
            .is_ok_and(|reply| reply.bytes(&mut buffer) == proto_wire::reply(Status::Ok))
    }

    /// A request through an image session for the file of `entry`:
    /// READ_AT and INFO_FD of fd 0 alone.
    fn image(&mut self, entry: u16, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        match Method::from_number(r.method()) {
            Some(Method::ReadAt) => {
                let (Ok(fd), Ok(offset), Ok(count)) = (body.u32(), body.u64(), body.u32()) else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() || fd != 0 || count as usize > MAX_READ {
                    return Answer::Status(Status::BadSize);
                }
                let mut bytes = [0; MAX_READ];
                match self
                    .ram
                    .image_read(entry, offset, &mut bytes[..count as usize])
                {
                    Ok(n) => {
                        let w = r.reply();
                        if w.u32(0)
                            .and_then(|()| w.u32(n as u32))
                            .and_then(|()| w.bytes(&bytes[..n]))
                            .is_err()
                        {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            Some(Method::InfoFd) => {
                if body.u32() != Ok(0) || body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                match self.ram.image_information(entry) {
                    Ok(info) => {
                        let w = r.reply();
                        if w.u32(0).and_then(|()| info.write(w)).is_err() {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            _ => status(proto_fs::PERMISSION),
        }
    }
}

fn status(code: u32) -> Answer {
    Answer::Status(Status::from_code(code))
}

fn value(r: &mut Request<'_>, number: u32) -> Answer {
    let w = r.reply();
    if w.u32(0).and_then(|()| w.u32(number)).is_err() {
        return Answer::Status(Status::BadSize);
    }
    Answer::Reply(Outgoing::new())
}

impl Service<0> for Fs {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = METHODS;
    const PLACED: usize = 1;
    type Data = Fds;

    /// The image sessions share place 0: they hold nothing.
    fn place(&self, label: u64) -> Option<usize> {
        proto_fs::image_entry(label).map(|_| 0)
    }

    fn request(&mut self, s: &mut Session<Fds, 0>, r: &mut Request<'_>) -> Answer {
        if let Some(entry) = proto_fs::image_entry(r.label()) {
            return self.image(entry, r);
        }
        if r.method() == Method::OpenExec as u16 {
            return self.open_exec(r);
        }
        // The session of the loaders opens programs and nothing else.
        if proto_fs::is_loaders(r.label()) {
            return status(proto_fs::PERMISSION);
        }
        let mut body = r.body();
        match Method::from_number(r.method()) {
            Some(Method::Clone) => {
                if body.finish().is_err() || !r.handles.is_empty() {
                    return Answer::Status(Status::BadSize);
                }
                let label = proto_fs::OWN | self.given;
                match self.session(label) {
                    Ok(session) => {
                        if r.reply().u32(0).is_err() {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply([session.erase()].into())
                    }
                    Err(e) => Answer::Status(Status::Kernel(e)),
                }
            }
            Some(Method::OpenExec) => status(proto_fs::PERMISSION),
            Some(Method::Open) => {
                let Ok(flags) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                let Ok(path) = body.bytes(body.left()).and_then(valid_path) else {
                    return Answer::Status(Status::BadSize);
                };
                match self.ram.open(&mut s.data, path, flags) {
                    Ok(fd) => value(r, fd),
                    Err(code) => status(code),
                }
            }
            Some(Method::Read) => {
                let (Ok(fd), Ok(count)) = (body.u32(), body.u32()) else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() || count as usize > MAX_READ {
                    return Answer::Status(Status::BadSize);
                }
                let mut bytes = [0; MAX_READ];
                match self.ram.read_at(
                    &mut s.data,
                    fd,
                    &mut bytes[..count as usize],
                    rt::time::ticks_to_ns(rt::time::now()),
                ) {
                    Ok(n) => {
                        let w = r.reply();
                        if w.u32(0)
                            .and_then(|()| w.u32(n as u32))
                            .and_then(|()| w.bytes(&bytes[..n]))
                            .is_err()
                        {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            Some(Method::ReadAt) => {
                let (Ok(fd), Ok(offset), Ok(count)) = (body.u32(), body.u64(), body.u32()) else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() || count as usize > MAX_READ {
                    return Answer::Status(Status::BadSize);
                }
                let mut bytes = [0; MAX_READ];
                match self.ram.pread(
                    &s.data,
                    fd,
                    offset,
                    &mut bytes[..count as usize],
                    rt::time::ticks_to_ns(rt::time::now()),
                ) {
                    Ok(n) => {
                        let w = r.reply();
                        if w.u32(0)
                            .and_then(|()| w.u32(n as u32))
                            .and_then(|()| w.bytes(&bytes[..n]))
                            .is_err()
                        {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            Some(Method::Write) => {
                let Ok(fd) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                let Ok(bytes) = body.bytes(body.left()) else {
                    return Answer::Status(Status::BadSize);
                };
                if bytes.len() > MAX_WRITE {
                    return Answer::Status(Status::BadSize);
                }
                match self.ram.write_at(
                    &mut s.data,
                    fd,
                    bytes,
                    rt::time::ticks_to_ns(rt::time::now()),
                ) {
                    Ok(n) => value(r, n as u32),
                    Err(code) => status(code),
                }
            }
            Some(Method::Seek) => {
                let (Ok(fd), Ok(offset)) = (body.u32(), body.u32()) else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                match s.data.seek(fd, offset) {
                    Ok(offset) => value(r, offset),
                    Err(code) => status(code),
                }
            }
            Some(Method::SeekFrom) => {
                let (Ok(fd), Ok(offset), Ok(origin)) = (body.u32(), body.u64(), body.u32()) else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                let Some(origin) = proto_fs::SeekFrom::from_number(origin) else {
                    return status(proto_fs::INVALID_ARGUMENT);
                };
                match self.ram.seek_from(&mut s.data, fd, offset as i64, origin) {
                    Ok(offset) => {
                        let w = r.reply();
                        if w.u32(0).and_then(|()| w.u64(offset as u64)).is_err() {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            Some(Method::Stat) => {
                let Ok(fd) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                match self.ram.size(&s.data, fd) {
                    Ok(size) => value(r, size),
                    Err(code) => status(code),
                }
            }
            Some(Method::Close) => {
                let Ok(fd) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                match s.data.close(fd) {
                    Ok(()) => Answer::Status(Status::Ok),
                    Err(code) => status(code),
                }
            }
            Some(Method::ReadDir) => {
                let Ok(index) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                let Ok(path) = body.bytes(body.left()).and_then(valid_path) else {
                    return Answer::Status(Status::BadSize);
                };
                match self.ram.directory_read_path(
                    path,
                    index,
                    rt::time::ticks_to_ns(rt::time::now()),
                ) {
                    Ok(entry) => {
                        let (name, kind) = entry.map_or(("", 0), |entry| (entry.name, entry.kind));
                        let w = r.reply();
                        if w.u32(0)
                            .and_then(|()| w.u32(kind))
                            .and_then(|()| w.bytes(name.as_bytes()))
                            .is_err()
                        {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            Some(Method::ReadDirFd) => {
                let Ok(fd) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                match self.ram.directory_read(
                    &mut s.data,
                    fd,
                    rt::time::ticks_to_ns(rt::time::now()),
                ) {
                    Ok(entry) => {
                        let entry = entry.map(|entry| proto_fs::DirectoryEntry {
                            name: entry.name.as_bytes(),
                            kind: entry.kind,
                            inode: entry.inode,
                        });
                        let w = r.reply();
                        if w.u32(0)
                            .and_then(|()| proto_fs::DirectoryEntry::write(entry, w))
                            .is_err()
                        {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            Some(Method::InfoFd | Method::InfoPath) => {
                let info = if r.method() == Method::InfoFd as u16 {
                    let Ok(fd) = body.u32() else {
                        return Answer::Status(Status::BadSize);
                    };
                    if body.finish().is_err() {
                        return Answer::Status(Status::BadSize);
                    }
                    self.ram.descriptor_information(&s.data, fd)
                } else {
                    let Ok(path) = body.bytes(body.left()).and_then(valid_path) else {
                        return Answer::Status(Status::BadSize);
                    };
                    self.ram.information(path)
                };
                match info {
                    Ok(info) => {
                        let w = r.reply();
                        if w.u32(0).and_then(|()| info.write(w)).is_err() {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            Some(Method::Lookup) => {
                let Ok(path) = body.bytes(body.left()).and_then(valid_path) else {
                    return Answer::Status(Status::BadSize);
                };
                match self.ram.lookup(path) {
                    Ok(meta) => {
                        let w = r.reply();
                        if w.u32(0)
                            .and_then(|()| w.u32(meta.kind))
                            .and_then(|()| w.u32(meta.size))
                            .is_err()
                        {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            None => Answer::Status(Status::UnknownMethod),
        }
    }
}
