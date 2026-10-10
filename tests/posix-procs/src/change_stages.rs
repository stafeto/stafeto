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

/// Clones `count` identity sessions of the bound one and closes each: every
/// close leaves an end in the identity channel of the process service.
#[unsafe(no_mangle)]
pub extern "C" fn files_closed_sessions(count: i32) -> i32 {
    let Ok(raw) = posix_abi::shared::with_files(|files| Ok(files.sessions().0.raw())) else {
        return 90;
    };
    let original =
        core::mem::ManuallyDrop::new(Files::from_sessions(rt::Handle::from_raw(raw), None));
    for _ in 0..count {
        if super::open_stages::clone_bound(&original, &[]).is_err() {
            return 91;
        }
    }
    0
}

unsafe extern "C" {
    fn _exit(code: i32) -> !;
    fn execve(
        path: *const core::ffi::c_char,
        argv: *const *const core::ffi::c_char,
        envp: *const *const core::ffi::c_char,
    ) -> i32;
    fn nanosleep(request: *const [i64; 2], remaining: *mut [i64; 2]) -> i32;
}

/// The process that goes in the middle of a prepaid rename. A first rename
/// of one directory over an empty one runs to its end, to count its steps;
/// the same rename of the second pair is started, paid and taken to a step
/// a few before its last (the count of the first varies by one or two). The
/// process then ends with `_exit(7)` (`exec` 0) or calls `execve` of a program that ends with 7 (`exec` 1), with the job alive in
/// its session. The parent looks at the names and at the places afterwards
/// (`files_gone_places`). The pairs are in /tmp/gn: p1 q1 p2 q2 for the
/// first, r1 s1 r2 s2 for the second.
#[unsafe(no_mangle)]
pub extern "C" fn files_gone_child(exec: i32) -> i32 {
    fn run(exec: i32) -> Result<(), i32> {
        let raw =
            posix_abi::shared::with_files(|files| Ok(files.sessions().0.raw())).map_err(|_| 90)?;
        let original =
            core::mem::ManuallyDrop::new(Files::from_sessions(rt::Handle::from_raw(raw), None));
        let files = super::open_stages::clone_bound(&original, &[]).map_err(|_| 91)?;
        let (dry_old, dry_new, old, new): (&[u8], &[u8], &[u8], &[u8]) = if exec == 0 {
            (b"/tmp/gn/p1", b"/tmp/gn/q1", b"/tmp/gn/p2", b"/tmp/gn/q2")
        } else {
            (b"/tmp/gn/r1", b"/tmp/gn/s1", b"/tmp/gn/r2", b"/tmp/gn/s2")
        };
        let dry = req(0, 1, ChangeOp::Rename, dry_old);
        start(&files, &dry).map_err(|_| 92)?;
        second(&files, dry.key, Base::Absolute, dry_new).map_err(|_| 93)?;
        let mut steps = 0usize;
        loop {
            steps += 1;
            if steps > 10_000 {
                return Err(94);
            }
            if step(&files, dry.key, false).map_err(|_| 95)?.is_some() {
                break;
            }
        }
        release(&files, dry.key).map_err(|_| 96)?;
        let job = req(1, 2, ChangeOp::Rename, old);
        start(&files, &job).map_err(|_| 97)?;
        second(&files, job.key, Base::Absolute, new).map_err(|_| 98)?;
        for taken in 1..steps.saturating_sub(5) {
            if step(&files, job.key, false).map_err(|_| 99)?.is_some() {
                rt::println!("posix-files: gone: the job ended at step {taken} of {steps}");
                return Err(100);
            }
        }
        // The job is paid and has staged nearly all its steps. The process
        // goes with it.
        if exec == 0 {
            // SAFETY: relibc's _exit.
            unsafe { _exit(7) };
        }
        let program = c"/bin/procs-child";
        let argv = [
            c"procs-child".as_ptr(),
            c"exit7".as_ptr(),
            core::ptr::null(),
        ];
        let envp = [core::ptr::null()];
        // SAFETY: relibc's execve over live C strings.
        unsafe { execve(program.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
        Err(101)
    }
    run(exec).err().unwrap_or(0)
}

/// Whether the root can hold all 24 places of the side table again: two
/// sessions start 16 and 8 renames, which a job left behind by a process that
/// went would cut to 23 until the service has cancelled it. The service does
/// it a job a turn of its maintenance, so the volley is repeated for a second
/// (a hundred times with a pause of 10 ms). 0 when all 24 went through; 1 when the places stayed taken.
#[unsafe(no_mangle)]
pub extern "C" fn files_gone_places() -> i32 {
    fn volley(a: &Files, b: &Files, generation: u64) -> Result<bool, i32> {
        let mut held: [Option<(&Files, OpenKey)>; 24] = [None; 24];
        let mut full = false;
        for (i, entry) in held.iter_mut().enumerate() {
            let (files, slot) = if i < 16 {
                (a, i as u32)
            } else {
                (b, (i - 16) as u32)
            };
            let job = req(slot, generation, ChangeOp::Rename, b"/tmp/gn");
            match start(files, &job) {
                Ok(_) => *entry = Some((files, job.key)),
                Err(Status::Unknown(code)) if code == proto_fs::JOBS_FULL => {
                    full = true;
                    break;
                }
                Err(_) => return Err(110),
            }
        }
        for (files, key) in held.into_iter().flatten() {
            release(files, key).map_err(|_| 111)?;
        }
        Ok(!full)
    }
    fn run() -> Result<bool, i32> {
        let raw =
            posix_abi::shared::with_files(|files| Ok(files.sessions().0.raw())).map_err(|_| 90)?;
        let original =
            core::mem::ManuallyDrop::new(Files::from_sessions(rt::Handle::from_raw(raw), None));
        let a = super::open_stages::clone_bound(&original, &[]).map_err(|_| 91)?;
        let b = super::open_stages::clone_bound(&original, &[]).map_err(|_| 91)?;
        for attempt in 0..100u64 {
            if volley(&a, &b, 10 + attempt)? {
                return Ok(true);
            }
            let ten_ms = [0i64, 10_000_000];
            let mut left = [0i64; 2];
            // SAFETY: relibc's nanosleep over live arrays.
            unsafe { nanosleep(&ten_ms, &mut left) };
        }
        Ok(false)
    }
    match run() {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(code) => code,
    }
}

// The worst states of the steps of the service, built on purpose (the steps
// run reads the longest step of each kind from the service itself): a Start
// with the share of the root in the table taken, with two paths of 511 bytes and a descriptor for a
// base, and the restart that follows a stale proof at the commit of a rename
// of a directory over an empty one, after the prepayment.

/// The cloned sessions that hold jobs, with how many each holds.
struct HeldSessions(core::cell::UnsafeCell<[Option<(Files, u32)>; 7]>);
// SAFETY: the probe uses it from its main thread alone.
unsafe impl Sync for HeldSessions {}
static HELD: HeldSessions = HeldSessions(core::cell::UnsafeCell::new([const { None }; 7]));

/// Starts `count` jobs (an access of `/`, never stepped) in cloned sessions,
/// sixteen to a session, and keeps them: the places of the table and of the
/// root stay taken until `files_bounds_release`. The count of jobs, or a
/// negative number.
#[unsafe(no_mangle)]
pub extern "C" fn files_bounds_hold(count: i32) -> i32 {
    fn run(count: i32) -> Result<(), i32> {
        let raw =
            posix_abi::shared::with_files(|files| Ok(files.sessions().0.raw())).map_err(|_| -1)?;
        let original =
            core::mem::ManuallyDrop::new(Files::from_sessions(rt::Handle::from_raw(raw), None));
        // SAFETY: the main thread alone touches the sessions.
        let held = unsafe { &mut *HELD.0.get() };
        let mut left = count as u32;
        for entry in held.iter_mut() {
            if left == 0 {
                break;
            }
            let files = super::open_stages::clone_bound(&original, &[]).map_err(|_| -2)?;
            let here = left.min(16);
            for slot in 0..here {
                if let Err(status) = start(&files, &access(slot, 1, b"/", 0)) {
                    rt::println!("posix-procs: bounds: the start of a held job gave {status:?}");
                    return Err(-3);
                }
            }
            *entry = Some((files, here));
            left -= here;
        }
        Ok(())
    }
    match run(count) {
        Ok(()) => count,
        Err(code) => code,
    }
}

/// Gives the held jobs back and closes the sessions.
#[unsafe(no_mangle)]
pub extern "C" fn files_bounds_release() -> i32 {
    // SAFETY: the main thread alone touches the sessions.
    let held = unsafe { &mut *HELD.0.get() };
    let mut failed = 0;
    for entry in held.iter_mut() {
        if let Some((files, count)) = entry.take() {
            for slot in 0..count {
                if release(&files, key(slot, 1)).is_err() {
                    failed += 1;
                }
            }
        }
    }
    failed
}

/// A name of `length` bytes, then a slash and one more of the same, of one
/// letter: a relative path of 2 * length + 1 bytes.
fn long_path(letter: u8, length: usize) -> ([u8; 511], usize) {
    let mut bytes = [letter; 511];
    bytes[length] = b'/';
    (bytes, 2 * length + 1)
}

/// The Start of a rename with two relative paths of 511 bytes from a
/// directory descriptor, with every place of the share of the root taken but
/// one (the caller holds 95 jobs): the job ends with ENOENT after its steps.
/// 0 when it did.
#[unsafe(no_mangle)]
pub extern "C" fn files_bounds_start() -> i32 {
    fn work() -> Result<(), i32> {
        let raw =
            posix_abi::shared::with_files(|files| Ok(files.sessions().0.raw())).map_err(|_| 90)?;
        let original =
            core::mem::ManuallyDrop::new(Files::from_sessions(rt::Handle::from_raw(raw), None));
        let files = super::open_stages::clone_bound(&original, &[]).map_err(|_| 91)?;
        let dir_flags = proto_fs::READ_ONLY | proto_fs::DIRECTORY_ONLY;
        let held = open(&files, 40, b"/tmp", dir_flags).map_err(|_| 92)?;
        let (first, first_length) = long_path(b'a', 255);
        let (second_path, second_length) = long_path(b'b', 255);
        let mut job = req(2, 41, ChangeOp::Rename, &first[..first_length]);
        job.base = Base::Fd {
            fd: held.fd,
            generation: held.generation,
        };
        let done = run(
            &files,
            &job,
            Some((job.base, &second_path[..second_length])),
        )
        .map_err(|_| 93)?;
        if done.result != proto_fs::NO_ENTRY {
            rt::println!(
                "posix-procs: bounds: the rename of 511 bytes gave {}",
                done.result
            );
            return Err(94);
        }
        files.close_exact(held).map_err(|_| 95)?;
        Ok(())
    }
    work().err().unwrap_or(0)
}

/// The commit of a rename of a directory over an empty one finds the proof
/// stale: another client takes the empty directory away and makes it again
/// after the prepayment. The next step restarts the job with the journal at
/// its heaviest. 0 when the job restarted and ended with success.
#[unsafe(no_mangle)]
pub extern "C" fn files_bounds_stale() -> i32 {
    fn run_all() -> Result<(), i32> {
        let raw =
            posix_abi::shared::with_files(|files| Ok(files.sessions().0.raw())).map_err(|_| 90)?;
        let original =
            core::mem::ManuallyDrop::new(Files::from_sessions(rt::Handle::from_raw(raw), None));
        let files = super::open_stages::clone_bound(&original, &[]).map_err(|_| 91)?;
        for (generation, path) in [
            &b"/tmp/bs"[..],
            b"/tmp/bs/a1",
            b"/tmp/bs/a2",
            b"/tmp/bs/b1",
            b"/tmp/bs/b2",
        ]
        .into_iter()
        .enumerate()
        {
            expect(
                run(&files, &mkdir(0, 50 + generation as u64, path, 0o755), None),
                0,
                100,
            )?;
        }
        // A rename to count its steps.
        let dry = req(1, 51, ChangeOp::Rename, b"/tmp/bs/a1");
        start(&files, &dry).map_err(|_| 101)?;
        second(&files, dry.key, Base::Absolute, b"/tmp/bs/a2").map_err(|_| 102)?;
        let mut steps = 0usize;
        loop {
            steps += 1;
            if steps > 10_000 {
                return Err(103);
            }
            if step(&files, dry.key, false).map_err(|_| 104)?.is_some() {
                break;
            }
        }
        release(&files, dry.key).map_err(|_| 105)?;
        // The same, stopped before the commit.
        let job = req(2, 52, ChangeOp::Rename, b"/tmp/bs/b1");
        start(&files, &job).map_err(|_| 106)?;
        second(&files, job.key, Base::Absolute, b"/tmp/bs/b2").map_err(|_| 107)?;
        for _ in 1..steps {
            if step(&files, job.key, false).map_err(|_| 108)?.is_some() {
                return Err(109);
            }
        }
        // The empty directory goes and comes back.
        expect(run(&files, &rmdir(3, 53, b"/tmp/bs/b2"), None), 0, 110)?;
        expect(
            run(&files, &mkdir(3, 54, b"/tmp/bs/b2", 0o755), None),
            0,
            111,
        )?;
        let mut last = None;
        for _ in 0..10_000 {
            if let Some(done) = step(&files, job.key, false).map_err(|_| 112)? {
                last = Some(done);
                break;
            }
        }
        let done = last.ok_or(113)?;
        release(&files, job.key).map_err(|_| 114)?;
        if done.result != 0 || done.restarts == 0 {
            rt::println!(
                "posix-procs: bounds: the rename gave {} with {} restarts",
                done.result,
                done.restarts
            );
            return Err(115);
        }
        for (generation, path) in [(55, &b"/tmp/bs/a2"[..]), (56, b"/tmp/bs/b2")] {
            expect(run(&files, &rmdir(3, generation, path), None), 0, 116)?;
        }
        // The directories a1 and b1 went over a2 and b2; what is left goes.
        expect(run(&files, &rmdir(3, 57, b"/tmp/bs"), None), 0, 117)?;
        Ok(())
    }
    run_all().err().unwrap_or(0)
}

/// A creation commits after 500 other names were published in its directory.
#[unsafe(no_mangle)]
pub extern "C" fn files_bounds_publish() -> i32 {
    unsafe extern "C" {
        fn files_bounds_fill(remove_names: i32) -> i32;
    }
    fn work() -> Result<(), i32> {
        let raw =
            posix_abi::shared::with_files(|files| Ok(files.sessions().0.raw())).map_err(|_| 90)?;
        let original =
            core::mem::ManuallyDrop::new(Files::from_sessions(rt::Handle::from_raw(raw), None));
        let files = super::open_stages::clone_bound(&original, &[]).map_err(|_| 89)?;
        expect(run(&files, &mkdir(0, 70, b"/tmp/bp", 0o755), None), 0, 91)?;
        let dry = mkdir(1, 71, b"/tmp/bp/pending", 0o755);
        start(&files, &dry).map_err(|_| 92)?;
        let mut steps = 0;
        let baseline_ticks;
        loop {
            steps += 1;
            if steps > 1000 {
                return Err(93);
            }
            let begin = rt::time::now();
            if step(&files, dry.key, false).map_err(|_| 94)?.is_some() {
                baseline_ticks = rt::time::now() - begin;
                break;
            }
        }
        release(&files, dry.key).map_err(|_| 95)?;
        expect(run(&files, &rmdir(0, 72, dry.path), None), 0, 96)?;
        // SAFETY: the helper starts with no raw job in flight.
        let prepare = unsafe { files_bounds_fill(-1) };
        if prepare != 0 {
            return Err(120 + prepare);
        }
        let job = mkdir(1, 73, dry.path, 0o755);
        start(&files, &job).map_err(|_| 97)?;
        for _ in 1..steps {
            if step(&files, job.key, false).map_err(|_| 98)?.is_some() {
                return Err(99);
            }
        }
        // SAFETY: the C helper takes only a scalar and owns its strings.
        let fill = unsafe { files_bounds_fill(0) };
        if fill != 0 {
            return Err(100 + fill);
        }
        let begin = rt::time::now();
        let done = step(&files, job.key, false).map_err(|_| 110)?.ok_or(111)?;
        let commit_ticks = rt::time::now() - begin;
        if done.result != 0 || done.restarts != 0 {
            return Err(112);
        }
        release(&files, job.key).map_err(|_| 113)?;
        rt::println!(
            "posix-procs: names bounds commit after 500 rival names: 0 restarts, commit {} ticks, baseline {} ticks",
            commit_ticks,
            baseline_ticks
        );
        // SAFETY: the helper removes the names it created.
        if unsafe { files_bounds_fill(1) } != 0 {
            return Err(114);
        }
        expect(run(&files, &rmdir(0, 74, dry.path), None), 0, 115)?;
        expect(run(&files, &rmdir(0, 75, b"/tmp/bp"), None), 0, 116)?;
        Ok(())
    }
    work().err().unwrap_or(0)
}

fn reclaim_probe(files: &Files, command: u32) -> Result<u32, Status> {
    let mut out = Writer::new();
    proto_wire::Header::new(0xfff5, proto_fs::VERSION).write(&mut out)?;
    out.u32(command)?;
    let (bytes, length) = send(files, &out)?;
    let mut input = Reader::new(&bytes[..length]);
    let code = input.u32()?;
    if code != 0 {
        return Err(Status::from_code(code));
    }
    let backlog = input.u32()?;
    input.finish()?;
    Ok(backlog)
}

/// Commit a replacing rename with one node and with 32 paid page-owning nodes queued.
#[unsafe(no_mangle)]
pub extern "C" fn files_bounds_reclaim() -> i32 {
    unsafe extern "C" {
        fn files_bounds_garbage(count: i32) -> i32;
    }
    fn work() -> Result<(), i32> {
        let raw =
            posix_abi::shared::with_files(|files| Ok(files.sessions().0.raw())).map_err(|_| 90)?;
        let original =
            core::mem::ManuallyDrop::new(Files::from_sessions(rt::Handle::from_raw(raw), None));
        let files = super::open_stages::clone_bound(&original, &[]).map_err(|_| 91)?;
        for (i, path) in [
            b"/tmp/bg".as_slice(),
            b"/tmp/bg/gc",
            b"/tmp/bg/a1",
            b"/tmp/bg/a2",
            b"/tmp/bg/b1",
            b"/tmp/bg/b2",
            b"/tmp/bg/c1",
            b"/tmp/bg/c2",
        ]
        .into_iter()
        .enumerate()
        {
            expect(
                run(&files, &mkdir(0, 100 + i as u64, path, 0o755), None),
                0,
                92,
            )?;
        }
        // Count the unperturbed steps, including the final commit.
        let dry = req(1, 110, ChangeOp::Rename, b"/tmp/bg/a1");
        start(&files, &dry).map_err(|_| 93)?;
        second(&files, dry.key, Base::Absolute, b"/tmp/bg/a2").map_err(|_| 94)?;
        let mut steps = 0;
        loop {
            steps += 1;
            if steps > 1000 {
                return Err(95);
            }
            if step(&files, dry.key, false).map_err(|_| 96)?.is_some() {
                break;
            }
        }
        release(&files, dry.key).map_err(|_| 97)?;
        for (generation, count, source, destination) in [
            (111, 1, b"/tmp/bg/b1".as_slice(), b"/tmp/bg/b2".as_slice()),
            (112, 32, b"/tmp/bg/c1".as_slice(), b"/tmp/bg/c2".as_slice()),
        ] {
            let job = req(1, generation, ChangeOp::Rename, source);
            start(&files, &job).map_err(|_| 98)?;
            second(&files, job.key, Base::Absolute, destination).map_err(|_| 99)?;
            for _ in 1..steps {
                if step(&files, job.key, false).map_err(|_| 100)?.is_some() {
                    return Err(101);
                }
            }
            let mut empty = false;
            for _ in 0..256 {
                if reclaim_probe(&files, 0).map_err(|_| 102)? == 0 {
                    empty = true;
                    break;
                }
                reclaim_probe(&files, 2).map_err(|_| 115)?;
            }
            if !empty {
                return Err(103);
            }
            // SAFETY: the C helper receives a scalar and owns all its buffers.
            if unsafe { files_bounds_garbage(count) } != 0 {
                return Err(104);
            }
            let before = reclaim_probe(&files, 1).map_err(|_| 105)?;
            let pages_before = reclaim_probe(&files, 3).map_err(|_| 113)?;
            let begin = rt::time::now();
            let done = step(&files, job.key, false).map_err(|_| 106)?.ok_or(107)?;
            let ticks = rt::time::now() - begin;
            let after = reclaim_probe(&files, 1).map_err(|_| 108)?;
            let pages_after = reclaim_probe(&files, 3).map_err(|_| 114)?;
            // One page is freed at the threshold; both queues still retain their nodes.
            rt::println!(
                "posix-procs: names bounds reclaim: {} nodes with pages, backlog {} -> {}, pages {} -> {}, commit {} ticks, {} restarts",
                count,
                before,
                after,
                pages_before,
                pages_after,
                ticks,
                done.restarts
            );
            if before != count as u32
                || after != before + 1
                || pages_after != pages_before - u32::from(count >= 32)
                || done.result != 0
                || done.restarts != 0
            {
                return Err(109);
            }
            reclaim_probe(&files, 2).map_err(|_| 110)?;
            release(&files, job.key).map_err(|_| 111)?;
        }
        for (i, path) in [
            b"/tmp/bg/a2".as_slice(),
            b"/tmp/bg/b2",
            b"/tmp/bg/c2",
            b"/tmp/bg/gc",
            b"/tmp/bg",
        ]
        .into_iter()
        .enumerate()
        {
            expect(run(&files, &rmdir(0, 120 + i as u64, path), None), 0, 112)?;
        }
        Ok(())
    }
    work().err().unwrap_or(0)
}
