// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Real paid Open stages; the C supervisor observes the returned failure code.
use proto_wire::Status;
use rt::fs::{Files, PreparedOpen};

fn prepared(files: &Files, id: u64) -> Result<(), Status> {
    for prepare in [false, true] {
        let mut completed = false;
        for _ in 0..2000 {
            if files.open_advance(id, prepare)? {
                completed = true;
                break;
            }
        }
        if !completed {
            return Err(Status::BadSize);
        }
    }
    Ok(())
}
fn committed(
    files: &Files,
    path: &[u8],
    flags: u32,
    mode: u32,
    umask: u32,
) -> Result<(u64, PreparedOpen), Status> {
    let id = files.open_start(path, flags, mode, umask)?;
    let result = prepared(files, id).and_then(|()| files.open_commit(id));
    match result {
        Ok(held) => Ok((id, held)),
        Err(error) => {
            let _ = files.open_cancel(id);
            Err(error)
        }
    }
}
fn run(files: &Files) -> Result<(), i32> {
    let flags = proto_fs::CREATE | proto_fs::EXCLUSIVE | proto_fs::READ_WRITE;
    let (id, held) = committed(files, b"/tmp/t3-created", flags, 0o666, 0o077).map_err(|_| 1)?;
    let result = (|| {
        if files.read(held.fd, &mut [0]) != Err(Status::Unknown(proto_fs::BAD_FD)) {
            return Err(2);
        }
        if files.open_commit(id) != Ok(held) {
            return Err(3);
        }
        let info = files.node_information("/tmp/t3-created").map_err(|_| 4)?;
        if info.permissions != 0o600 || info.size != 0 || info.uid != 0 {
            return Err(5);
        }
        // Write through a separate ordinary descriptor after the first CREATE effect.
        let fd = files
            .open("/tmp/t3-created", proto_fs::READ_WRITE)
            .map_err(|_| 6)?;
        let write = files.write(fd, b"created once");
        files.close(fd).map_err(|_| 7)?;
        if write != Ok(12) || files.open_commit(id) != Ok(held) {
            return Err(8);
        }
        Ok(())
    })();
    files.open_cancel(id).map_err(|_| 9)?;
    result?;
    // Repeated cancellation and a late Commit cannot create another operation.
    files.open_cancel(id).map_err(|_| 10)?;
    if files.open_commit(id) != Err(Status::Unknown(proto_fs::STALE_PROOF)) {
        return Err(11);
    }
    let exclusive = files
        .open_start(b"/tmp/t3-created", flags, 0o777, 0)
        .map_err(|_| 12)?;
    let exists = prepared(files, exclusive);
    files.open_cancel(exclusive).map_err(|_| 14)?;
    if exists != Err(Status::Unknown(proto_fs::ALREADY_EXISTS)) {
        return Err(15);
    }
    let (zero, _) = committed(files, b"/tmp/t3-mode-zero", flags, 0, 0).map_err(|_| 16)?;
    files.open_cancel(zero).map_err(|_| 17)?;
    if files
        .node_information("/tmp/t3-mode-zero")
        .map_err(|_| 18)?
        .permissions
        != 0
    {
        return Err(19);
    }
    // The TRUNC effect clears set-ID and a retry preserves subsequently written data.
    let (initial, _) = committed(files, b"/tmp/t3-truncate", flags, 0o6600, 0).map_err(|_| 20)?;
    files.open_cancel(initial).map_err(|_| 21)?;
    let (truncate, held) = committed(
        files,
        b"/tmp/t3-truncate",
        proto_fs::TRUNCATE | proto_fs::READ_WRITE,
        0,
        0,
    )
    .map_err(|_| 22)?;
    let result = (|| {
        if files
            .node_information("/tmp/t3-truncate")
            .map_err(|_| 23)?
            .permissions
            != 0o600
        {
            return Err(24);
        }
        let fd = files
            .open("/tmp/t3-truncate", proto_fs::READ_WRITE)
            .map_err(|_| 25)?;
        let write = files.write(fd, b"new after truncate");
        files.close(fd).map_err(|_| 26)?;
        if write != Ok(18) {
            return Err(27);
        }
        let before = files.node_information("/tmp/t3-truncate").map_err(|_| 28)?;
        if files.open_commit(truncate) != Ok(held) {
            return Err(29);
        }
        let after = files.node_information("/tmp/t3-truncate").map_err(|_| 30)?;
        if before != after {
            return Err(31);
        }
        let fd = files
            .open("/tmp/t3-truncate", proto_fs::READ_ONLY)
            .map_err(|_| 32)?;
        let mut bytes = [0; 18];
        let read = files.read(fd, &mut bytes);
        files.close(fd).map_err(|_| 33)?;
        if read != Ok(18) || &bytes != b"new after truncate" {
            return Err(34);
        }
        Ok(())
    })();
    files.open_cancel(truncate).map_err(|_| 35)?;
    result
}
#[unsafe(no_mangle)]
pub extern "C" fn files_open_stages() -> i32 {
    let Ok(raw) = posix_abi::shared::with_files(|files| Ok(files.sessions().0.raw())) else {
        return 90;
    };
    let files = core::mem::ManuallyDrop::new(Files::from_sessions(rt::Handle::from_raw(raw), None));
    run(&files).err().unwrap_or(0)
}
