// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use super::*;

#[test]
fn all_request_kinds_roundtrip() {
    let bytes = [0x91; MAX_WRITE];
    let requests = [
        Request::Open {
            flags: 2,
            path: b"/tmp/probe",
        },
        Request::Close { fd: 3 },
        Request::Read { fd: 4, count: 1016 },
        Request::Write {
            fd: 5,
            bytes: &bytes,
        },
        Request::Seek {
            fd: 6,
            offset: -91,
            origin: SeekFrom::End,
        },
        Request::Dup { fd: 7 },
        Request::Dup2 {
            source: 8,
            target: 9,
        },
        Request::Dup3 {
            source: 9,
            target: 10,
            flags: 0,
        },
        Request::Chdir { path: b"/etc" },
        Request::Cwd,
        Request::Stat { path: b"/etc/motd" },
        Request::Fstat { fd: 11 },
        Request::OpenDir { path: b"/" },
        Request::FdOpenDir { fd: 12 },
        Request::DirRead {
            stream: 0x1234567890,
        },
        Request::DirClose { stream: 31 },
        Request::DirFd { stream: 32 },
        Request::DirTell { stream: 33 },
        Request::DirSeek {
            stream: 34,
            position: -5,
        },
        Request::DirRewind { stream: 35 },
        Request::Cleanup,
    ];
    for request in requests {
        let mut out = Writer::new();
        request.write(&mut out).unwrap();
        assert_eq!(Request::read(out.as_bytes()), Ok(request));
    }
}

#[test]
fn fixed_fields_have_checked_lengths_and_little_endian_values() {
    let request = Request::Seek {
        fd: 0x12345678,
        offset: -2,
        origin: SeekFrom::End,
    };
    let mut out = Writer::new();
    request.write(&mut out).unwrap();
    let bytes = out.as_bytes();
    assert_eq!(
        &bytes[..12],
        &[5, 0, 1, 0, 0, 0, 0, 0, 0x78, 0x56, 0x34, 0x12]
    );
    assert_eq!(&bytes[12..20], &(-2i64).to_le_bytes());
    assert_eq!(&bytes[20..], &[2, 0, 0, 0]);
    for end in 0..bytes.len() {
        assert!(Request::read(&bytes[..end]).is_err());
    }
    let mut extra = bytes.to_vec();
    extra.push(0);
    assert_eq!(Request::read(&extra), Err(Status::BadSize));
    extra[20..24].copy_from_slice(&7u32.to_le_bytes());
    extra.pop();
    assert_eq!(Request::read(&extra), Err(Status::BadSize));
}

#[test]
fn unknown_versions_methods_reserved_fields_and_invalid_paths_are_rejected() {
    let mut header = Header::new(10, VERSION).bytes();
    header[2] = 2;
    assert_eq!(Request::read(&header), Err(Status::BadVersion));
    header = Header::new(65535, VERSION).bytes();
    assert_eq!(Request::read(&header), Err(Status::UnknownMethod));
    header = Header::new(10, VERSION).bytes();
    header[7] = 1;
    assert_eq!(Request::read(&header), Err(Status::BadSize));
    // 511 bytes of path and the terminator make PATH_MAX (512).
    assert_eq!(MAX_PATH, 511);
    assert!(
        Request::Stat { path: &[b'x'; 511] }
            .write(&mut Writer::new())
            .is_ok()
    );
    for path in [&[b'x'; 512][..], &b"a\0b"[..]] {
        assert_eq!(
            Request::Stat { path }.write(&mut Writer::new()),
            Err(Status::BadSize)
        );
        let mut out = Writer::new();
        Header::new(11, VERSION).write(&mut out).unwrap();
        out.bytes(path).unwrap();
        assert_eq!(Request::read(out.as_bytes()), Err(Status::BadSize));
    }
}

#[test]
fn full_payloads_fit_the_kernel_message_and_do_not_alias_the_source() {
    let mut payload = [0x71; MAX_WRITE];
    let mut out = Writer::new();
    Request::Write {
        fd: 0x01020304,
        bytes: &payload,
    }
    .write(&mut out)
    .unwrap();
    let mut wire = Writer::new();
    exchange::Exchange::Execute {
        nonce: 1,
        request: out.as_bytes(),
    }
    .write(&mut wire)
    .unwrap();
    assert_eq!(wire.as_bytes().len(), MESSAGE_MAX);
    assert_eq!(&out.as_bytes()[..12], &[4, 0, 1, 0, 0, 0, 0, 0, 4, 3, 2, 1]);
    payload.fill(0);
    let exchange::Exchange::Execute { request, .. } =
        exchange::Exchange::read(wire.as_bytes()).unwrap()
    else {
        panic!();
    };
    let Request::Write { bytes, .. } = Request::read(request).unwrap() else {
        panic!();
    };
    assert!(bytes.iter().all(|b| *b == 0x71));
    assert_eq!(
        Request::Write {
            fd: 1,
            bytes: &[0; MAX_WRITE + 1]
        }
        .write(&mut Writer::new()),
        Err(Status::BadSize)
    );
    let data = [0x81; MAX_READ];
    let mut out = Writer::new();
    Reply::Bytes(&data).write(&mut out).unwrap();
    assert_eq!(out.as_bytes().len(), MESSAGE_MAX);
    assert_eq!(Reply::read(out.as_bytes()), Ok(Reply::Bytes(&data)));
    for end in 0..out.as_bytes().len() {
        assert!(Reply::read(&out.as_bytes()[..end]).is_err());
    }
}

#[test]
fn reply_tags_status_input_extent_and_metadata_are_validated() {
    let info = NodeInfo {
        kind: 2,
        permissions: 0o640,
        device: 1,
        special_device: 0,
        inode: 19,
        links: 1,
        uid: 1000,
        gid: 1000,
        size: 91,
        block_size: 1024,
        blocks: 1,
        access_ns: 1,
        modify_ns: 2,
        change_ns: 3,
    };
    let replies = [
        Reply::Unit,
        Reply::Error(5),
        Reply::Number(u64::MAX),
        Reply::Info(info),
        Reply::Input {
            uart: None,
            extent: 1,
        },
        Reply::Input {
            uart: Some(19),
            extent: MAX_READ as u32,
        },
    ];
    for reply in replies {
        let mut out = Writer::new();
        reply.write(&mut out).unwrap();
        assert_eq!(Reply::read(out.as_bytes()), Ok(reply));
        for end in 0..out.as_bytes().len() {
            assert!(Reply::read(&out.as_bytes()[..end]).is_err());
        }
        let mut extra = out.as_bytes().to_vec();
        extra.push(0);
        assert!(Reply::read(&extra).is_err());
    }
    for invalid in [
        Reply::Error(0),
        Reply::Error(4096),
        Reply::Input {
            uart: Some(0),
            extent: 1,
        },
        Reply::Input {
            uart: None,
            extent: 0,
        },
        Reply::Input {
            uart: None,
            extent: MAX_READ as u32 + 1,
        },
    ] {
        assert_eq!(invalid.write(&mut Writer::new()), Err(Status::BadSize));
    }
    let mut out = Writer::new();
    Reply::Info(info).write(&mut out).unwrap();
    let mut invalid = out.as_bytes().to_vec();
    invalid[8..12].copy_from_slice(&9u32.to_le_bytes());
    assert_eq!(Reply::read(&invalid), Err(Status::BadSize));
    for words in [[0, 99], [0, 0x10001], [4096, 0], [5, 1]] {
        let mut out = Writer::new();
        for word in words {
            out.u32(word).unwrap();
        }
        assert_eq!(Reply::read(out.as_bytes()), Err(Status::BadSize));
    }
}
