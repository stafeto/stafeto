// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Native workers lose successful replies through the ordinary Reply path.
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicU64, Ordering};
use proto_fs::{Method, OpenKey};
use proto_wire::{Reader, Status};
use rt::abi::{Error, Policy, ProcessState, Rights, ThreadState};
use rt::fs::{Files, OpenOutcome, PreparedOpen};
use rt::{Handle, Stack, sys};

static STACKS: [Stack<16384>; 11] = [const { Stack::new() }; 11];
static ALTERNATE: AtomicU64 = AtomicU64::new(0);
static ENDPOINT: AtomicU64 = AtomicU64::new(0);
static GENERATION: AtomicU64 = AtomicU64::new(0);
static JOB: AtomicU64 = AtomicU64::new(0);
static METHOD: AtomicU64 = AtomicU64::new(0);
static RETURNED: AtomicU64 = AtomicU64::new(0);
const SLOT: u32 = 28;

extern "C" fn worker(_: u64) -> ! {
    // SAFETY: main retains the session until this worker has ended.
    let channel = unsafe { Handle::from_raw(rt::abi::Handle(ENDPOINT.load(Ordering::Acquire))) };
    let files = ManuallyDrop::new(Files::from_sessions(channel, None));
    let key = OpenKey {
        slot: SLOT,
        generation: GENERATION.load(Ordering::Acquire),
    };
    let method = match METHOD.load(Ordering::Acquire) {
        0 => Method::OpenStart,
        1 => Method::OpenCommit,
        _ => Method::OpenFinish,
    };
    let mut args = [0; 10];
    args[0] = files.sessions().0.raw().0;
    args[1] = u64::from_le_bytes(method.header().bytes());
    args[2] = key.slot as u64;
    args[3] = key.generation;
    args[4] = JOB.load(Ordering::Acquire);
    args[5] = u64::from(matches!(method, Method::OpenCommit));
    // SAFETY: the dedicated guest kernel retains this native worker and endpoint.
    let armed = unsafe { sys::raw::<0xffe0>(args) };
    if armed[0] == 0 {
        match method {
            Method::OpenStart => {
                let _ = files.open_start(key, b"/etc/motd", proto_fs::READ_ONLY, 0, 0);
            }
            Method::OpenCommit => {
                let _ = files.open_commit(args[4]);
            }
            _ => {
                let _ = files.open_finish(key);
            }
        }
    }
    RETURNED.store(1, Ordering::Release);
    sys::thread_exit()
}

fn lose(files: &Files, index: usize, key: OpenKey, job: u64, method: u64) -> Result<(), i32> {
    let process = posix_abi::allocation::process();
    let pid = posix_abi::process::getpid();
    ENDPOINT.store(files.sessions().0.raw().0, Ordering::Release);
    GENERATION.store(key.generation, Ordering::Release);
    JOB.store(job, Ordering::Release);
    METHOD.store(method, Ordering::Release);
    RETURNED.store(0, Ordering::Release);
    // SAFETY: each static stack and message page belongs to one worker used once.
    let thread = unsafe {
        sys::thread_create(
            process,
            worker,
            STACKS[index].top(),
            0,
            31,
            Policy::Fifo,
            0xe00000 + index * 4096,
        )
    }
    .map_err(|_| 110)?;
    sys::thread_start(&thread).map_err(|_| 111)?;
    let mut ended = false;
    for _ in 0..1000 {
        if sys::thread_info(&thread).is_ok_and(|info| info.state == ThreadState::Ended) {
            ended = true;
            break;
        }
        sys::yield_now().map_err(|_| 112)?;
    }
    // SAFETY: snapshot reads value-only results from the dedicated test kernel.
    let snapshot = unsafe { sys::raw::<0xffe1>([0; 10]) };
    if !ended
        || RETURNED.load(Ordering::Acquire) != 0
        || snapshot[..6]
            != [
                0,
                1,
                1,
                Error::PeerClosed.code(),
                key.slot as u64,
                key.generation,
            ]
        || sys::process_state(process) != Ok(ProcessState::Alive)
        || posix_abi::process::getpid() != pid
    {
        rt::println!(
            "posix-files: loss snapshot {:?}, ended {}, returned {}",
            &snapshot[..6],
            ended,
            RETURNED.load(Ordering::Acquire)
        );
        return Err(113);
    }
    Ok(())
}

fn arm_args(endpoint: u64, key: OpenKey) -> sys::Regs {
    let mut args = [0; 10];
    args[0] = endpoint;
    args[1] = u64::from_le_bytes(Method::OpenStart.header().bytes());
    args[2] = key.slot as u64;
    args[3] = key.generation;
    args
}
fn probe<const CALL: u16>(args: sys::Regs) -> sys::Regs {
    // SAFETY: these dedicated guest calls accept registers and retain their own references.
    unsafe { sys::raw::<CALL>(args) }
}
extern "C" fn negative_worker(mode: u64) -> ! {
    // SAFETY: main retains this session until the sequential worker has ended.
    let channel = unsafe { Handle::from_raw(rt::abi::Handle(ENDPOINT.load(Ordering::Acquire))) };
    let files = ManuallyDrop::new(Files::from_sessions(channel, None));
    let key = OpenKey {
        slot: 26,
        generation: 4000 + mode,
    };
    let mut args = arm_args(files.sessions().0.raw().0, key);
    let extra = if mode == 5 {
        sys::channel_create(1).ok()
    } else {
        None
    };
    match mode {
        2 => args[1] = u64::from_le_bytes(Method::OpenQuery.header().bytes()),
        3 => args[3] += 1,
        4 => {
            args[1] = u64::from_le_bytes(Method::OpenCommit.header().bytes());
            args[4] = 42;
            args[5] = 1;
        }
        5 => {
            if let Some(extra) = &extra {
                args[0] = extra.raw().0;
            } else {
                RETURNED.store(3, Ordering::Release);
                sys::thread_exit();
            }
        }
        _ => {}
    }
    if mode == 6 {
        args[0] = ALTERNATE.load(Ordering::Acquire);
    }
    let mut good = probe::<0xffe0>(args)[0] == 0;
    if mode == 1 {
        good &= probe::<0xffe2>([0; 10])[0] == 0 && probe::<0xffe2>([0; 10])[0] == 0;
    }
    if good && mode != 0 {
        if mode == 6 {
            let endpoint = Handle::borrowed(rt::abi::Handle(args[0]));
            let mut request = proto_wire::Writer::new();
            good = Method::OpenStart.header().write(&mut request).is_ok()
                && request.u32(key.slot).is_ok()
                && request.u64(key.generation).is_ok();
            if good {
                good = sys::send(&endpoint, request.as_bytes()).is_ok_and(|reply| {
                    let mut buffer = [0; rt::abi::MESSAGE_MAX];
                    reply.len == 8
                        && Reader::new(reply.bytes(&mut buffer)).u32() == Ok(proto_fs::OPEN_RETIRED)
                });
            }
        } else if mode == 4 {
            good = files.open_commit(0).is_err();
        } else {
            good = files
                .open_start(key, b"/etc/motd", proto_fs::READ_ONLY, 0, 0)
                .is_ok();
            good &= files.open_cancel_key(key).is_ok();
        }
    }
    drop(extra);
    RETURNED.store(if good { 2 } else { 3 }, Ordering::Release);
    sys::thread_exit()
}
fn negatives(files: &Files) -> Result<(), i32> {
    let endpoint = files.sessions().0;
    let process = posix_abi::allocation::process();
    let key = OpenKey {
        slot: 26,
        generation: 3000,
    };
    let args = arm_args(endpoint.raw().0, key);
    let owned = sys::channel_create(1).map_err(|_| 150)?;
    let restricted = sys::handle_duplicate(&owned, Rights::NONE).map_err(|_| 150)?;
    for (index, value, expected) in [
        (2, 32, Error::InvalidArgs),
        (3, 0, Error::InvalidArgs),
        (5, 2, Error::InvalidArgs),
        (0, 0, Error::BadHandle),
        (0, process.raw().0, Error::WrongType),
        (0, restricted.raw().0, Error::AccessDenied),
    ] {
        let mut bad = args;
        bad[index] = value;
        if probe::<0xffe0>(bad)[0] != expected.code() || probe::<0xffe2>([0; 10])[0] != 0 {
            return Err(151);
        }
    }
    // A failed replacement removes the previous arm before validation.
    if probe::<0xffe0>(args)[0] != 0 {
        return Err(152);
    }
    let mut invalid = args;
    invalid[3] = 0;
    if probe::<0xffe0>(invalid)[0] != Error::InvalidArgs.code() {
        return Err(153);
    }
    files
        .open_start(key, b"/etc/motd", proto_fs::READ_ONLY, 0, 0)
        .map_err(|_| 154)?;
    files.open_cancel_key(key).map_err(|_| 155)?;
    let baseline = counts(files)?;
    ENDPOINT.store(endpoint.raw().0, Ordering::Release);
    for mode in 0..7 {
        RETURNED.store(0, Ordering::Release);
        let alternate = sys::channel_create(1).map_err(|_| 160)?;
        ALTERNATE.store(alternate.raw().0, Ordering::Release);
        // SAFETY: each worker owns a distinct static stack and message page, used once.
        let thread = unsafe {
            sys::thread_create(
                process,
                negative_worker,
                STACKS[4 + mode].top(),
                mode as u64,
                31,
                Policy::Fifo,
                0xe00000 + (4 + mode) * 4096,
            )
        }
        .map_err(|_| 156)?;
        sys::thread_start(&thread).map_err(|_| 157)?;
        if mode == 6 {
            if probe::<0xffe2>([0; 10])[0] != Error::AccessDenied.code() {
                return Err(161);
            }
            let sys::Received::Message { token, .. } =
                sys::try_receive(&alternate).map_err(|_| 162)?
            else {
                return Err(163);
            };
            let mut wrong = [0; 10];
            wrong[0] = u64::MAX;
            wrong[1] = 8;
            // SAFETY: the invalid reply token carries no handles or borrowed memory.
            if unsafe { sys::raw::<{ rt::abi::Call::Reply.number() }>(wrong) }[0]
                != Error::BadState.code()
                || !sys::thread_info(&thread)
                    .is_ok_and(|info| info.state == ThreadState::AwaitingReply)
            {
                return Err(164);
            }
            let mut response = proto_wire::Writer::new();
            response.u32(proto_fs::OPEN_RETIRED).map_err(|_| 165)?;
            response.u32(0).map_err(|_| 165)?;
            token.reply(response.as_bytes()).map_err(|_| 166)?;
        }
        let mut ended = false;
        for _ in 0..1000 {
            if sys::thread_info(&thread).is_ok_and(|info| info.state == ThreadState::Ended) {
                ended = true;
                break;
            }
            sys::yield_now().map_err(|_| 158)?;
        }
        if !ended
            || RETURNED.load(Ordering::Acquire) != 2
            || probe::<0xffe1>([0; 10])[0] != Error::BadState.code()
            || sys::process_state(process) != Ok(ProcessState::Alive)
            || counts(files)? != baseline
        {
            return Err(159);
        }
    }
    rt::println!("posix-files: native ARM rejection and teardown ok");
    Ok(())
}

fn counts(files: &Files) -> Result<[u32; 4], i32> {
    let request = proto_wire::Header::new(0xfffa, proto_fs::VERSION).bytes();
    let reply = sys::send(files.sessions().0, &request).map_err(|_| 114)?;
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let mut reader = Reader::new(reply.bytes(&mut buffer));
    if reader.u32() != Ok(0) {
        return Err(115);
    }
    let mut counts = [0; 4];
    for count in &mut counts {
        *count = reader.u32().map_err(|_| 116)?;
    }
    reader.finish().map_err(|_| 117)?;
    Ok(counts)
}
fn prepare(files: &Files, key: OpenKey, flags: u32) -> Result<u64, i32> {
    let job = files
        .open_start(key, b"/tmp/native-loss", flags, 0o600, 0)
        .map_err(|_| 118)?;
    for preparing in [false, true] {
        let mut done = false;
        for _ in 0..2000 {
            if files.open_advance(job, preparing).map_err(|_| 119)? {
                done = true;
                break;
            }
        }
        if !done {
            return Err(120);
        }
    }
    Ok(job)
}
fn payload(files: &Files, held: PreparedOpen, bytes: &[u8]) -> Result<(), i32> {
    if files.write(held.fd, bytes) != Ok(bytes.len())
        || files.open_finish(OpenKey {
            slot: SLOT,
            generation: GENERATION.load(Ordering::Acquire),
        }) != Ok(held)
    {
        return Err(121);
    }
    let mut read = [0; 16];
    if files.read_at(held.fd, 0, &mut read) != Ok(bytes.len()) || &read[..bytes.len()] != bytes {
        return Err(122);
    }
    Ok(())
}
pub fn run(files: &Files) -> Result<(), i32> {
    negatives(files)?;
    let baseline = counts(files)?;
    let key = OpenKey {
        slot: SLOT,
        generation: 1001,
    };
    lose(files, 0, key, 0, 0)?;
    let job = match files.open_query(key).map_err(|_| 123)? {
        OpenOutcome::Active { job, phase: 0 } => job,
        _ => return Err(124),
    };
    if files.open_start(key, b"/etc/motd", proto_fs::READ_ONLY, 0, 0) != Ok(job) {
        return Err(125);
    }
    let mut paid = baseline;
    for count in &mut paid[..3] {
        *count += 1;
    }
    if counts(files)? != paid {
        return Err(126);
    }
    files.open_cancel_key(key).map_err(|_| 127)?;
    if counts(files)? != baseline {
        return Err(128);
    }
    // Fill the genuine session preparation pool after recovering the lost Start.
    let mut keys = [OpenKey {
        slot: 0,
        generation: 2000,
    }; 16];
    for (slot, key) in keys.iter_mut().enumerate() {
        key.slot = slot as u32;
        files
            .open_start(*key, b"/etc/motd", proto_fs::READ_ONLY, 0, 0)
            .map_err(|_| 142)?;
    }
    if files.open_start(
        OpenKey {
            slot: 27,
            generation: 2000,
        },
        b"/etc/motd",
        proto_fs::READ_ONLY,
        0,
        0,
    ) != Err(Status::Unknown(proto_fs::TOO_MANY_OPEN_FILES))
    {
        return Err(143);
    }
    for key in keys {
        files.open_cancel_key(key).map_err(|_| 144)?;
    }
    if counts(files)? != baseline {
        return Err(145);
    }

    for (index, generation, flags, lost_method) in [
        (
            1,
            1002,
            proto_fs::CREATE | proto_fs::EXCLUSIVE | proto_fs::READ_WRITE,
            1,
        ),
        (2, 1003, proto_fs::TRUNCATE | proto_fs::READ_WRITE, 1),
        (3, 1004, proto_fs::READ_WRITE, 2),
    ] {
        let key = OpenKey {
            slot: SLOT,
            generation,
        };
        let job = prepare(files, key, flags)?;
        let held = if lost_method == 2 {
            Some(files.open_commit(job).map_err(|_| 129)?)
        } else {
            None
        };
        lose(files, index, key, job, lost_method)?;
        let recovered = if let Some(held) = held {
            if files.open_query(key) != Ok(OpenOutcome::Finished(held)) {
                return Err(130);
            }
            held
        } else {
            if files.open_query(key) != Ok(OpenOutcome::Active { job, phase: 3 }) {
                return Err(131);
            }
            files.open_commit(job).map_err(|_| 132)?
        };
        if files.open_finish(key) != Ok(recovered) {
            return Err(133);
        }
        if index == 2 && files.fstat_size(recovered.fd) != Ok(0) {
            return Err(134);
        }
        // Replaying Finish preserves writes made after publication.
        payload(files, recovered, b"native reply")?;
        files.close(recovered.fd).map_err(|_| 135)?;
        let fresh = files
            .open("/tmp/native-loss", proto_fs::READ_ONLY)
            .map_err(|_| 136)?;
        if fresh != recovered.fd
            || files.open_query(key) != Err(Status::Unknown(proto_fs::OPEN_RETIRED))
        {
            return Err(137);
        }
        files.open_cancel_key(key).map_err(|_| 138)?;
        let mut bytes = [0; 12];
        if files.read(fresh, &mut bytes) != Ok(12) || &bytes != b"native reply" {
            return Err(139);
        }
        files.close(fresh).map_err(|_| 140)?;
        if counts(files)? != baseline {
            return Err(141);
        }
    }
    rt::println!("posix-files: genuine native reply loss ok");
    Ok(())
}
