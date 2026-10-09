// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Raw requests of the Change family against the RAM service on a genuinely
//! bound session. Every operation prints a line with an observable result.
use proto_fs::{
    Base, ChangeOp, ChangePhase, ChangeReply, ChangeSecond, ChangeStart, Method, OpenKey,
};
use proto_wire::{Reader, Status, Writer};
use rt::abi::MESSAGE_MAX;
use rt::fs::{Files, PreparedOpen};

/// What a finished job answered: its result code and the bytes of its result.
pub struct Done {
    pub result: u32,
    pub restarts: u32,
    pub length: usize,
    pub bytes: [u8; 512],
}

pub fn key(slot: u32, generation: u64) -> OpenKey {
    OpenKey { slot, generation }
}

fn send(files: &Files, w: &Writer) -> Result<([u8; MESSAGE_MAX], usize), Status> {
    let reply = Files::send_on(files.sessions().0, w.as_bytes())?;
    if !reply.handles.is_empty() {
        return Err(Status::BadSize);
    }
    let mut buffer = [0; MESSAGE_MAX];
    let length = reply.bytes(&mut buffer).len();
    Ok((buffer, length))
}

pub fn start(files: &Files, req: &ChangeStart<'_>) -> Result<ChangePhase, Status> {
    let mut w = Writer::new();
    Method::ChangeStart.header().write(&mut w)?;
    req.write(&mut w)?;
    let (bytes, length) = send(files, &w)?;
    proto_fs::change_start_reply(&bytes[..length], 0)
}

pub fn second(files: &Files, key: OpenKey, base: Base, bytes: &[u8]) -> Result<(), Status> {
    let mut w = Writer::new();
    Method::ChangeSecond.header().write(&mut w)?;
    ChangeSecond { key, base, bytes }.write(&mut w)?;
    let (reply, length) = send(files, &w)?;
    status_only(&reply[..length])
}

fn status_only(reply: &[u8]) -> Result<(), Status> {
    let mut input = Reader::new(reply);
    match Status::from_code(input.u32()?) {
        Status::Ok => {
            if input.u32()? != 0 {
                return Err(Status::BadSize);
            }
            input.finish()
        }
        status => Err(status),
    }
}

/// One Step or Query. `Ok(None)` is a job that still runs.
pub fn step(files: &Files, key: OpenKey, query: bool) -> Result<Option<Done>, Status> {
    let mut w = Writer::new();
    (if query {
        Method::ChangeQuery
    } else {
        Method::ChangeStep
    })
    .header()
    .write(&mut w)?;
    proto_fs::write_key_body(&mut w, key)?;
    let (bytes, length) = send(files, &w)?;
    let reply = ChangeReply::read(&bytes[..length], 0)?;
    if !reply.done {
        return Ok(None);
    }
    let mut done = Done {
        result: reply.result,
        restarts: reply.restarts,
        length: reply.bytes.len(),
        bytes: [0; 512],
    };
    done.bytes[..reply.bytes.len()].copy_from_slice(reply.bytes);
    Ok(Some(done))
}

pub fn release(files: &Files, key: OpenKey) -> Result<(), Status> {
    let mut w = Writer::new();
    Method::ChangeRelease.header().write(&mut w)?;
    proto_fs::write_key_body(&mut w, key)?;
    let (reply, length) = send(files, &w)?;
    status_only(&reply[..length])
}

/// Start, Second, Step until done, Release.
pub fn run(
    files: &Files,
    req: &ChangeStart<'_>,
    second_path: Option<(Base, &[u8])>,
) -> Result<Done, Status> {
    start(files, req)?;
    if let Some((base, bytes)) = second_path {
        second(files, req.key, base, bytes)?;
    }
    let mut done = None;
    for _ in 0..100_000 {
        if let Some(finished) = step(files, req.key, false)? {
            done = Some(finished);
            break;
        }
    }
    let done = done.ok_or(Status::BadSize)?;
    // The outcome stays until Release, for a Query as for a repeated Step.
    let again = step(files, req.key, true)?.ok_or(Status::BadSize)?;
    if again.result != done.result || again.length != done.length || again.restarts != done.restarts
    {
        return Err(Status::BadSize);
    }
    release(files, req.key)?;
    Ok(done)
}

fn req(slot: u32, generation: u64, op: ChangeOp, path: &[u8]) -> ChangeStart<'_> {
    ChangeStart {
        key: key(slot, generation),
        op,
        flags: 0,
        base: Base::Absolute,
        args: [0; 4],
        path,
    }
}

fn mkdir(slot: u32, generation: u64, path: &[u8], mode: u64) -> ChangeStart<'_> {
    let mut start = req(slot, generation, ChangeOp::Mkdir, path);
    start.args = [mode, 0o022, 0, 0];
    start
}

fn rmdir(slot: u32, generation: u64, path: &[u8]) -> ChangeStart<'_> {
    let mut start = req(slot, generation, ChangeOp::Unlink, path);
    start.flags = proto_fs::UNLINK_REMOVEDIR;
    start
}

fn access(slot: u32, generation: u64, path: &[u8], bits: u64) -> ChangeStart<'_> {
    let mut start = req(slot, generation, ChangeOp::Access, path);
    start.args[0] = bits;
    start
}

/// A prepared open of `path`, with the generation of its description.
fn open(files: &Files, generation: u64, path: &[u8], flags: u32) -> Result<PreparedOpen, Status> {
    let key = OpenKey {
        slot: 30,
        generation,
    };
    let id = files.open_start(key, path, flags, 0o600, 0)?;
    super::open_stages::prepared(files, id)?;
    let held = files.open_commit(id)?;
    if files.open_finish(key)? != held {
        return Err(Status::BadSize);
    }
    Ok(held)
}

/// Whether `path` opens now.
fn exists(files: &Files, generation: u64, path: &[u8], flags: u32) -> Result<bool, Status> {
    match open(files, generation, path, flags) {
        Ok(held) => {
            files.close_exact(held)?;
            Ok(true)
        }
        Err(Status::Unknown(proto_fs::NO_ENTRY)) => Ok(false),
        Err(error) => Err(error),
    }
}

fn expect(result: Result<Done, Status>, code: u32, line: i32) -> Result<(), i32> {
    match result {
        Ok(done) if done.result == code => Ok(()),
        _ => Err(line),
    }
}

fn run_stages(files: &Files) -> Result<(), i32> {
    let dir_flags = proto_fs::READ_ONLY | proto_fs::DIRECTORY_ONLY;
    // mkdir: made once, then it exists.
    expect(run(files, &mkdir(0, 1, b"/tmp/cs", 0o777), None), 0, 1)?;
    if !exists(files, 1, b"/tmp/cs", dir_flags).map_err(|_| 2)? {
        return Err(2);
    }
    expect(
        run(files, &mkdir(0, 2, b"/tmp/cs", 0o777), None),
        proto_fs::ALREADY_EXISTS,
        3,
    )?;
    rt::println!("posix-files: change mkdir made /tmp/cs and refused it twice");
    // A relative path from a directory descriptor.
    let held = open(files, 2, b"/tmp/cs", dir_flags).map_err(|_| 4)?;
    let at = |slot, generation, path, base| ChangeStart {
        base,
        ..mkdir(slot, generation, path, 0o755)
    };
    let base = Base::Fd {
        fd: held.fd,
        generation: held.generation,
    };
    expect(run(files, &at(0, 3, b"sub", base), None), 0, 5)?;
    if !exists(files, 3, b"/tmp/cs/sub", dir_flags).map_err(|_| 6)? {
        return Err(6);
    }
    let wrong = Base::Fd {
        fd: held.fd,
        generation: held.generation + 1,
    };
    expect(
        run(files, &at(0, 4, b"other", wrong), None),
        proto_fs::BAD_FD,
        7,
    )?;
    expect(
        run(files, &at(0, 5, b"other", Base::Cwd), None),
        proto_fs::BAD_FD,
        8,
    )?;
    expect(
        run(files, &at(0, 6, b"other", Base::Absolute), None),
        proto_fs::BAD_FD,
        9,
    )?;
    // The absolute path ignores a base that means nothing.
    expect(
        run(
            files,
            &ChangeStart {
                base: wrong,
                ..mkdir(0, 7, b"/tmp/cs/abs", 0o755)
            },
            None,
        ),
        0,
        10,
    )?;
    if exists(files, 4, b"/tmp/cs/other", dir_flags).map_err(|_| 11)? {
        return Err(11);
    }
    rt::println!(
        "posix-files: change mkdir from a descriptor, a wrong generation and a reserved base"
    );
    // access.
    expect(run(files, &access(0, 8, b"/tmp/cs/sub", 7), None), 0, 12)?;
    expect(
        run(files, &access(0, 9, b"/tmp/cs/none", 0), None),
        proto_fs::NO_ENTRY,
        13,
    )?;
    expect(run(files, &access(0, 10, b"/etc/motd", 4), None), 0, 14)?;
    rt::println!("posix-files: change access of a directory, a missing name and a file");
    // unlink and rmdir.
    expect(
        run(files, &req(0, 11, ChangeOp::Unlink, b"/tmp/cs"), None),
        proto_fs::PERMISSION,
        15,
    )?;
    expect(
        run(files, &rmdir(0, 12, b"/tmp/cs"), None),
        proto_fs::NOT_EMPTY,
        16,
    )?;
    expect(run(files, &rmdir(0, 13, b"/tmp/cs/sub/"), None), 0, 17)?;
    expect(run(files, &rmdir(0, 14, b"/tmp/cs/abs"), None), 0, 18)?;
    files.close_exact(held).map_err(|_| 19)?;
    expect(run(files, &rmdir(0, 15, b"/tmp/cs"), None), 0, 20)?;
    if exists(files, 5, b"/tmp/cs", dir_flags).map_err(|_| 21)? {
        return Err(21);
    }
    // A file made by open goes by unlink.
    let file = open(
        files,
        6,
        b"/tmp/cs-file",
        proto_fs::CREATE | proto_fs::READ_WRITE,
    )
    .map_err(|_| 22)?;
    files.close_exact(file).map_err(|_| 23)?;
    expect(
        run(files, &req(0, 16, ChangeOp::Unlink, b"/tmp/cs-file/"), None),
        proto_fs::NOT_DIRECTORY,
        24,
    )?;
    expect(
        run(files, &req(0, 17, ChangeOp::Unlink, b"/tmp/cs-file"), None),
        0,
        25,
    )?;
    if exists(files, 7, b"/tmp/cs-file", proto_fs::READ_ONLY).map_err(|_| 26)? {
        return Err(26);
    }
    rt::println!("posix-files: change unlink and rmdir by kind, with a slash and by a held name");
    // Keys: the same Start returns the job, other arguments are refused, a
    // released key is retired.
    let first = mkdir(1, 20, b"/tmp/cs-key", 0o755);
    if start(files, &first) != Ok(ChangePhase::Resolving)
        || start(files, &first) != Ok(ChangePhase::Resolving)
    {
        return Err(27);
    }
    if start(files, &mkdir(1, 20, b"/tmp/cs-other", 0o755))
        != Err(Status::Unknown(proto_fs::PERMISSION))
    {
        return Err(28);
    }
    if start(files, &mkdir(1, 21, b"/tmp/cs-other", 0o755))
        != Err(Status::Unknown(proto_fs::TOO_MANY_OPEN_FILES))
    {
        return Err(29);
    }
    release(files, first.key).map_err(|_| 30)?;
    release(files, first.key).map_err(|_| 31)?;
    if start(files, &first) != Err(Status::Unknown(proto_fs::OPEN_RETIRED)) {
        return Err(32);
    }
    if step(files, first.key, false).err() != Some(Status::Unknown(proto_fs::OPEN_RETIRED)) {
        return Err(33);
    }
    if step(files, key(9, 1), true).err() != Some(Status::Unknown(proto_fs::NO_ENTRY)) {
        return Err(34);
    }
    if exists(files, 8, b"/tmp/cs-key", dir_flags).map_err(|_| 35)? {
        return Err(35);
    }
    // A Release before its Start closes the key: the late Start is retired.
    release(files, key(8, 5)).map_err(|_| 39)?;
    if start(files, &mkdir(8, 5, b"/tmp/cs-late", 0o755))
        != Err(Status::Unknown(proto_fs::OPEN_RETIRED))
    {
        return Err(40);
    }
    // An operation number that does not exist is a protocol error.
    let mut w = Writer::new();
    Method::ChangeStart.header().write(&mut w).map_err(|_| 36)?;
    req(2, 1, ChangeOp::Unlink, b"/tmp/x")
        .write(&mut w)
        .map_err(|_| 36)?;
    let mut raw = [0; MESSAGE_MAX];
    let length = w.as_bytes().len();
    raw[..length].copy_from_slice(w.as_bytes());
    raw[8 + 12..8 + 16].copy_from_slice(&99u32.to_le_bytes());
    let reply = Files::send_on(files.sessions().0, &raw[..length]).map_err(|_| 37)?;
    let mut buffer = [0; MESSAGE_MAX];
    let bytes = reply.bytes(&mut buffer);
    if status_only(bytes) != Err(Status::Unknown(proto_fs::INVALID_ARGUMENT)) {
        return Err(38);
    }
    rt::println!("posix-files: change keys, retired keys and a refused operation number");
    Ok(())
}

fn info(files: &Files, path: &[u8]) -> Result<proto_fs::NodeInfo, i32> {
    files.node_information_bytes(path).map_err(|_| 200)
}

fn names(files: &Files) -> Result<(), i32> {
    let dir_flags = proto_fs::READ_ONLY | proto_fs::DIRECTORY_ONLY;
    let mut generation = 100;
    let mut next = || {
        generation += 1;
        generation
    };
    let _ = dir_flags;
    expect(
        run(files, &mkdir(3, next(), b"/tmp/cs2", 0o777), None),
        0,
        101,
    )?;
    // A file to work on.
    let held = open(
        files,
        next(),
        b"/tmp/cs2/a",
        proto_fs::CREATE | proto_fs::READ_WRITE,
    )
    .map_err(|_| 102)?;
    let inode = info(files, b"/tmp/cs2/a")?.inode;
    files.close_exact(held).map_err(|_| 103)?;
    // rename: Second, a repeat of Second, then the Steps; the inode is kept.
    let rename = req(3, next(), ChangeOp::Rename, b"/tmp/cs2/a");
    start(files, &rename).map_err(|_| 104)?;
    if step(files, rename.key, false).err() != Some(Status::Unknown(proto_fs::INVALID_ARGUMENT)) {
        return Err(105);
    }
    second(files, rename.key, Base::Absolute, b"/tmp/cs2/b").map_err(|_| 106)?;
    second(files, rename.key, Base::Absolute, b"/tmp/cs2/b").map_err(|_| 107)?;
    if second(files, rename.key, Base::Absolute, b"/tmp/cs2/c").err()
        != Some(Status::Unknown(proto_fs::PERMISSION))
    {
        return Err(108);
    }
    let mut done = None;
    for _ in 0..10_000 {
        if let Some(finished) = step(files, rename.key, false).map_err(|_| 109)? {
            done = Some(finished);
            break;
        }
    }
    if done.map(|d| d.result) != Some(0) {
        return Err(110);
    }
    second(files, rename.key, Base::Absolute, b"/tmp/cs2/b").map_err(|_| 111)?;
    release(files, rename.key).map_err(|_| 112)?;
    if info(files, b"/tmp/cs2/b")?.inode != inode
        || files.node_information_bytes(b"/tmp/cs2/a").err()
            != Some(Status::Unknown(proto_fs::NO_ENTRY))
    {
        return Err(113);
    }
    rt::println!("posix-files: change rename kept the inode and repeated Second safely");
    // A directory cannot go into itself; a missing name is NO_ENTRY.
    expect(
        run(
            files,
            &req(3, next(), ChangeOp::Rename, b"/tmp/cs2"),
            Some((Base::Absolute, b"/tmp/cs2/inside")),
        ),
        proto_fs::INVALID_ARGUMENT,
        114,
    )?;
    expect(
        run(
            files,
            &req(3, next(), ChangeOp::Rename, b"/tmp/cs2/none"),
            Some((Base::Absolute, b"/tmp/cs2/x")),
        ),
        proto_fs::NO_ENTRY,
        115,
    )?;
    // link: a second name, one more link.
    expect(
        run(
            files,
            &req(3, next(), ChangeOp::Link, b"/tmp/cs2/b"),
            Some((Base::Absolute, b"/tmp/cs2/c")),
        ),
        0,
        116,
    )?;
    let c = info(files, b"/tmp/cs2/c")?;
    if c.inode != inode || c.links != 2 {
        return Err(117);
    }
    expect(
        run(
            files,
            &req(3, next(), ChangeOp::Link, b"/tmp/cs2/b"),
            Some((Base::Absolute, b"/tmp/cs2/c")),
        ),
        proto_fs::ALREADY_EXISTS,
        118,
    )?;
    rt::println!("posix-files: change link made a second name and refused an existing one");
    // symlink and readlink.
    expect(
        run(
            files,
            &req(3, next(), ChangeOp::Symlink, b"/tmp/cs2/s"),
            Some((Base::Absolute, b"b")),
        ),
        0,
        119,
    )?;
    if info(files, b"/tmp/cs2/s")?.inode != inode {
        return Err(120);
    }
    let mut read = req(3, next(), ChangeOp::ReadLink, b"/tmp/cs2/s");
    read.args[0] = 511;
    let done = run(files, &read, None).map_err(|_| 121)?;
    if done.result != 0 || done.length != 1 || done.bytes[0] != b'b' {
        return Err(122);
    }
    read.key = key(3, next());
    read.path = b"/tmp/cs2/b";
    let done = run(files, &read, None).map_err(|_| 123)?;
    if done.result != proto_fs::INVALID_ARGUMENT {
        return Err(124);
    }
    expect(
        run(
            files,
            &req(3, next(), ChangeOp::Symlink, b"/tmp/cs2/e"),
            Some((Base::Absolute, b"")),
        ),
        0,
        125,
    )?;
    read.key = key(3, next());
    read.path = b"/tmp/cs2/e";
    let done = run(files, &read, None).map_err(|_| 126)?;
    if done.result != 0 || done.length != 0 {
        return Err(127);
    }
    rt::println!("posix-files: change symlink and readlink kept the bytes and the empty target");
    // chmod, chown and times by path, then by descriptor.
    let mut chmod = req(3, next(), ChangeOp::Chmod, b"/tmp/cs2/b");
    chmod.args[0] = 0o640;
    expect(run(files, &chmod, None), 0, 128)?;
    if info(files, b"/tmp/cs2/b")?.permissions != 0o640 {
        return Err(129);
    }
    let mut chown = req(3, next(), ChangeOp::Chown, b"/tmp/cs2/b");
    chown.args = [1000, proto_fs::ID_UNCHANGED, 0, 0];
    expect(run(files, &chown, None), 0, 130)?;
    let b = info(files, b"/tmp/cs2/b")?;
    if b.uid != 1000 || b.gid != 0 {
        return Err(131);
    }
    let mut times = req(3, next(), ChangeOp::Times, b"/tmp/cs2/b");
    times.args = [11, 12, 13, 14];
    expect(run(files, &times, None), 0, 132)?;
    let b = info(files, b"/tmp/cs2/b")?;
    if (b.access_time.seconds, b.access_time.nanos) != (11, 12)
        || (b.modify_time.seconds, b.modify_time.nanos) != (13, 14)
    {
        return Err(133);
    }
    let held = open(files, next(), b"/tmp/cs2/b", proto_fs::READ_ONLY).map_err(|_| 134)?;
    let mut fchmod = req(3, next(), ChangeOp::Chmod, b"");
    fchmod.args[0] = 0o600;
    fchmod.base = Base::Fd {
        fd: held.fd,
        generation: held.generation,
    };
    expect(run(files, &fchmod, None), 0, 135)?;
    if info(files, b"/tmp/cs2/b")?.permissions != 0o600 {
        return Err(136);
    }
    fchmod.key = key(3, next());
    fchmod.base = Base::Fd {
        fd: held.fd,
        generation: held.generation + 1,
    };
    expect(run(files, &fchmod, None), proto_fs::BAD_FD, 137)?;
    files.close_exact(held).map_err(|_| 138)?;
    rt::println!("posix-files: change chmod, chown and times by path and by descriptor");
    // Clean up the names.
    for name in [
        &b"/tmp/cs2/b"[..],
        b"/tmp/cs2/c",
        b"/tmp/cs2/s",
        b"/tmp/cs2/e",
    ] {
        expect(
            run(files, &req(3, next(), ChangeOp::Unlink, name), None),
            0,
            139,
        )?;
    }
    expect(run(files, &rmdir(3, next(), b"/tmp/cs2"), None), 0, 140)?;
    Ok(())
}

fn word(bytes: &[u8], i: usize) -> u64 {
    let mut word = [0; 8];
    word.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
    u64::from_le_bytes(word)
}

/// OpenStart from a base the caller chose, then the whole open.
fn open_from(
    files: &Files,
    key: OpenKey,
    base: (u32, u64),
    path: &[u8],
    flags: u32,
) -> Result<PreparedOpen, Status> {
    let mut w = Writer::new();
    Method::OpenStart.header().write(&mut w)?;
    w.u32(key.slot)?;
    w.u64(key.generation)?;
    w.u32(base.0)?;
    w.u64(base.1)?;
    w.u32(flags)?;
    w.u32(0o600)?;
    w.u32(0)?;
    w.bytes(path)?;
    let reply = Files::send_on(files.sessions().0, w.as_bytes())?;
    let id = Files::open_start_reply(&reply)?;
    super::open_stages::prepared(files, id)?;
    let held = files.open_commit(id)?;
    if files.open_finish(key)? != held {
        return Err(Status::BadSize);
    }
    Ok(held)
}

fn volume_and_paths(files: &Files) -> Result<(), i32> {
    let mut generation = 200;
    let mut next = || {
        generation += 1;
        generation
    };
    // statvfs: the numbers, and one directory less of free inodes.
    let mut stat = req(4, next(), ChangeOp::StatVfs, b"/tmp");
    let before = run(files, &stat, None).map_err(|_| 201)?;
    if before.result != 0 || before.length != proto_fs::STATVFS_BYTES {
        return Err(202);
    }
    if word(&before.bytes, 0) != 4096 || word(&before.bytes, 10) != 255 {
        return Err(203);
    }
    expect(
        run(files, &mkdir(4, next(), b"/tmp/cs3", 0o777), None),
        0,
        204,
    )?;
    stat.key = key(4, next());
    let after = run(files, &stat, None).map_err(|_| 205)?;
    if word(&after.bytes, 6) + 1 != word(&before.bytes, 6)
        || word(&after.bytes, 2) != word(&before.bytes, 2)
    {
        return Err(206);
    }
    stat.key = key(4, next());
    stat.path = b"/tmp/none";
    expect(run(files, &stat, None), proto_fs::NO_ENTRY, 207)?;
    rt::println!("posix-files: change statvfs gave the sizes and counted a free inode less");
    // path: canonical names, links and a descriptor.
    expect(
        run(
            files,
            &req(4, next(), ChangeOp::Symlink, b"/tmp/cs3/l"),
            Some((Base::Absolute, b".")),
        ),
        0,
        208,
    )?;
    let mut path = req(4, next(), ChangeOp::Path, b"/tmp/cs3/l/l/../cs3/./l");
    path.flags = proto_fs::PATH_FOLLOW_LAST;
    let done = run(files, &path, None).map_err(|_| 209)?;
    if done.result != 0 || &done.bytes[..done.length] != b"/tmp/cs3" {
        return Err(210);
    }
    path.key = key(4, next());
    path.flags = 0;
    path.path = b"/tmp/cs3/l";
    let done = run(files, &path, None).map_err(|_| 211)?;
    if done.result != 0 || &done.bytes[..done.length] != b"/tmp/cs3/l" {
        return Err(212);
    }
    path.key = key(4, next());
    path.flags = proto_fs::PATH_REQUIRE_DIR;
    path.path = b"/etc/motd";
    expect(run(files, &path, None), proto_fs::NOT_DIRECTORY, 213)?;
    let held = open(
        files,
        next(),
        b"/tmp/cs3",
        proto_fs::READ_ONLY | proto_fs::DIRECTORY_ONLY,
    )
    .map_err(|_| 214)?;
    let mut by_fd = req(4, next(), ChangeOp::Path, b"");
    by_fd.flags = proto_fs::PATH_REQUIRE_DIR;
    by_fd.base = Base::Fd {
        fd: held.fd,
        generation: held.generation,
    };
    let done = run(files, &by_fd, None).map_err(|_| 215)?;
    if done.result != 0 || &done.bytes[..done.length] != b"/tmp/cs3" {
        return Err(216);
    }
    rt::println!("posix-files: change path gave canonical names of paths and descriptors");
    // OpenStart from the descriptor, and from the reserved current directory.
    let key = OpenKey {
        slot: 30,
        generation: next(),
    };
    let marker = open_from(
        files,
        key,
        (held.fd | 1 << 31, held.generation),
        b"marker",
        proto_fs::CREATE | proto_fs::READ_WRITE,
    )
    .map_err(|_| 217)?;
    files.close_exact(marker).map_err(|_| 218)?;
    if info(files, b"/tmp/cs3/marker")?.kind != 2 {
        return Err(219);
    }
    let key = OpenKey {
        slot: 30,
        generation: next(),
    };
    if open_from(
        files,
        key,
        (held.fd | 1 << 31, held.generation + 1),
        b"marker",
        proto_fs::READ_ONLY,
    )
    .err()
        != Some(Status::Unknown(proto_fs::BAD_FD))
    {
        return Err(220);
    }
    let key = OpenKey {
        slot: 30,
        generation: next(),
    };
    if open_from(
        files,
        key,
        (proto_fs::BASE_CWD, 0),
        b"marker",
        proto_fs::READ_ONLY,
    )
    .err()
        != Some(Status::Unknown(proto_fs::BAD_FD))
    {
        return Err(221);
    }
    files.close_exact(held).map_err(|_| 222)?;
    expect(
        run(
            files,
            &req(4, next(), ChangeOp::Unlink, b"/tmp/cs3/marker"),
            None,
        ),
        0,
        223,
    )?;
    expect(
        run(
            files,
            &req(4, next(), ChangeOp::Unlink, b"/tmp/cs3/l"),
            None,
        ),
        0,
        224,
    )?;
    expect(run(files, &rmdir(4, next(), b"/tmp/cs3"), None), 0, 225)?;
    rt::println!("posix-files: change open from a descriptor and from the reserved base");
    Ok(())
}

/// The cancel of a rename of names of the boot table at every phase near the
/// end: the most the service has staged is a name for the tombstone of each
/// side, one for the new name and an inode for each node. The renames that
/// are cancelled leave both directories where they were.
fn release_in_flight(files: &Files) -> Result<(), i32> {
    let mut generation = 300;
    let mut next = || {
        generation += 1;
        generation
    };
    // The same rename on two other names, to count its steps.
    let dry = req(5, next(), ChangeOp::Rename, b"/chg/c");
    start(files, &dry).map_err(|_| 301)?;
    second(files, dry.key, Base::Absolute, b"/chg/d").map_err(|_| 302)?;
    let mut steps = 0usize;
    loop {
        steps += 1;
        if steps > 10_000 {
            return Err(303);
        }
        if step(files, dry.key, false).map_err(|_| 304)?.is_some() {
            break;
        }
    }
    release(files, dry.key).map_err(|_| 305)?;
    for taken in steps.saturating_sub(12)..steps {
        let job = req(5, next(), ChangeOp::Rename, b"/chg/a");
        start(files, &job).map_err(|_| 306)?;
        second(files, job.key, Base::Absolute, b"/chg/b").map_err(|_| 307)?;
        let mut finished = false;
        for _ in 0..taken {
            if step(files, job.key, false).map_err(|_| 308)?.is_some() {
                finished = true;
                break;
            }
        }
        release(files, job.key).map_err(|_| 309)?;
        if finished {
            break;
        }
        // Cancelled: nothing moved.
        if files.node_information_bytes(b"/chg/a").is_err()
            || files.node_information_bytes(b"/chg/b").is_err()
        {
            return Err(310);
        }
    }
    rt::println!("posix-files: change release of a rename in flight left both names");
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn files_change_stages() -> i32 {
    let Ok(raw) = posix_abi::shared::with_files(|files| Ok(files.sessions().0.raw())) else {
        return 90;
    };
    let original =
        core::mem::ManuallyDrop::new(Files::from_sessions(rt::Handle::from_raw(raw), None));
    let Ok(files) = super::open_stages::clone_bound(&original, &[]) else {
        return 91;
    };
    run_stages(&files)
        .and_then(|()| names(&files))
        .and_then(|()| volume_and_paths(&files))
        .and_then(|()| release_in_flight(&files))
        .err()
        .unwrap_or(0)
}
