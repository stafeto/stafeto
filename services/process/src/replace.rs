// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The existing init worker. Commands and outgoing capabilities stay in
//! the shared process table; a retained Replace request proves parking.

use crate::{controller::Controller, make};
use core::sync::atomic::{AtomicU64, Ordering};
use posix_process_service::worker_control::{
    Claim, Command, Completion, Outcome, init_status, reply_serial,
};
use proto_process::Method;
use proto_wire::{Name, Reader, Status, Writer};
use rt::handle::{Channel, Handle, Incoming, Process, Thread};
use rt::{Stack, abi, sys};

const STACK_SIZE: usize = 16 * 1024;
static STACK: Stack<STACK_SIZE> = Stack::new();
const BUFFER: usize = abi::INIT_MSGBUF as usize + 2 * 4096;
static THREAD: AtomicU64 = AtomicU64::new(0);

pub fn create(
    own: &Handle<Process>,
    level: u8,
    exit: &Handle<Channel>,
) -> Result<Handle<Thread>, abi::Error> {
    // SAFETY: this static stack and buffer are reused only after the
    // controller has settled all owners and observed genuine Ended.
    unsafe {
        sys::thread_create_with(
            own,
            replacer,
            STACK.top(),
            0,
            level,
            abi::Policy::Fifo,
            BUFFER,
            Some((exit, level)),
        )
    }
}

pub fn publish_worker(raw: u64) {
    THREAD.store(raw, Ordering::Release);
}

pub fn start(
    own: &Handle<Process>,
    level: u8,
    exit: &Handle<Channel>,
    control: &mut Controller,
) -> Result<(), abi::Error> {
    let thread = create(own, level, exit)?;
    publish_worker(thread.raw().0);
    control.worker = Some(thread);
    sys::thread_start(control.worker.as_ref().expect("the owned worker"))
}

pub fn owns_slots(pointer: u64) -> bool {
    let pointer = pointer as usize;
    pointer.is_multiple_of(core::mem::align_of::<AtomicU64>())
        && pointer >= STACK.top() - STACK_SIZE
        && pointer
            .checked_add(4 * core::mem::size_of::<AtomicU64>())
            .is_some_and(|end| end <= STACK.top())
}

/// Move every unexpected incoming cap before publishing, without an SVC.
fn retain(incoming: &mut Incoming, slots: &[AtomicU64; 4]) {
    for (index, slot) in slots.iter().enumerate().take(incoming.len()) {
        assert_eq!(slot.load(Ordering::Acquire), 0);
        let cap = incoming.take_any(index).expect("an untouched incoming cap");
        slot.store(cap.into_raw().0, Ordering::Relaxed);
    }
}

fn canonical(reply: &sys::Reply, buffer: &mut [u8; abi::MESSAGE_MAX]) -> bool {
    init_status(Reader::new(reply.bytes(buffer))) == Ok(0)
}

fn replace(
    init: &Handle<Channel>,
    ticket: u64,
    raw: u64,
    slots: &[AtomicU64; 4],
    buffer: &mut [u8; abi::MESSAGE_MAX],
) -> Outcome {
    let mut writer = Writer::new();
    proto_init::Method::Replaced
        .header()
        .write(&mut writer)
        .and_then(|()| writer.u64(ticket))
        .expect("a fixed Replaced request fits");
    let process = Handle::<Process>::from_raw(abi::Handle(raw));
    match sys::send_handles(init, writer.as_bytes(), [process.erase()]) {
        Ok(mut reply) => {
            let acknowledged = reply.handles.is_empty() && canonical(&reply, buffer);
            retain(&mut reply.handles, slots);
            Outcome {
                raw: 0,
                status: if acknowledged {
                    0
                } else {
                    Status::BadSize.code()
                },
                acknowledged,
                reply_slots: slots.as_ptr() as u64,
            }
        }
        Err(mut refused) => {
            let returned = refused
                .back
                .as_mut()
                .and_then(|back| back.pop())
                .map_or(0, |cap| cap.into_raw().0);
            Outcome {
                raw: returned,
                status: Status::Kernel(refused.error).code(),
                acknowledged: false,
                reply_slots: slots.as_ptr() as u64,
            }
        }
    }
}

fn refresh(
    init: &Handle<Channel>,
    slots: &[AtomicU64; 4],
    buffer: &mut [u8; abi::MESSAGE_MAX],
) -> Outcome {
    let mut writer = Writer::new();
    proto_init::Connect {
        name: Name::new(b"ramfs").expect("a fixed service name"),
    }
    .write(&mut writer)
    .expect("a fixed Connect request fits");
    let mut outcome = Outcome {
        raw: 0,
        status: Status::BadSize.code(),
        acknowledged: false,
        reply_slots: slots.as_ptr() as u64,
    };
    match sys::send(init, writer.as_bytes()) {
        Ok(mut reply) => {
            let rights = abi::Rights::SEND | abi::Rights::DUPLICATE | abi::Rights::TRANSFER;
            if canonical(&reply, buffer)
                && reply.handles.len() == 1
                && reply.handles.info(0) == Some((abi::ObjectKind::Channel, rights))
            {
                outcome.raw = reply
                    .handles
                    .take::<Channel>(0)
                    .expect("the checked Channel")
                    .into_raw()
                    .0;
                outcome.status = 0;
                outcome.acknowledged = true;
            } else {
                retain(&mut reply.handles, slots);
            }
        }
        Err(error) => outcome.status = Status::Kernel(error).code(),
    }
    outcome
}

extern "C" fn replacer(_: u64) -> ! {
    let init = make::init();
    let channel = make::channel();
    let shared = crate::worker_shared();
    let slots = [const { AtomicU64::new(0) }; 4];
    let mut buffer = [0; abi::MESSAGE_MAX];
    let mut completion = Completion {
        worker: THREAD.load(Ordering::Acquire),
        serial: shared.serial(),
        status: 0,
    };
    loop {
        let mut writer = Writer::new();
        Method::Replace
            .header()
            .write(&mut writer)
            .and_then(|()| completion.write(&mut writer))
            .expect("a fixed completion fits");
        let mut reply = match sys::send(&channel, writer.as_bytes()) {
            Ok(reply) => reply,
            // Keep the exact completion and stable slots on interruption.
            Err(abi::Error::Interrupted) => continue,
            // The entire service ends; this is not an isolated ThreadExit.
            Err(_) => sys::process_exit(12),
        };
        let packet = reply_serial(Reader::new(reply.bytes(&mut buffer)), reply.handles.len());
        // A real command reply follows main's slots0/outgoing-settled
        // proof. Take unexpected caps before any subsequent SVC.
        assert!(slots.iter().all(|slot| slot.load(Ordering::Acquire) == 0));
        retain(&mut reply.handles, &slots);
        let serial = shared.serial();
        let outcome = match shared.claim(serial) {
            Claim::Owned(command, raw) => {
                let expected = match command {
                    Command::Replace { label, .. } => (0, label, serial),
                    Command::Refresh => (1, 0, serial),
                    Command::Idle => (u32::MAX, 0, serial),
                };
                if packet != Ok(expected) {
                    Outcome {
                        raw,
                        status: Status::BadSize.code(),
                        acknowledged: false,
                        reply_slots: slots.as_ptr() as u64,
                    }
                } else {
                    match command {
                        Command::Replace { ticket, .. } => {
                            replace(&init, ticket, raw, &slots, &mut buffer)
                        }
                        Command::Refresh => refresh(&init, &slots, &mut buffer),
                        Command::Idle => unreachable!("an idle command cannot be published"),
                    }
                }
            }
            Claim::Cancelled => Outcome {
                raw: shared.raw(),
                status: Status::Kernel(abi::Error::Interrupted).code(),
                acknowledged: false,
                reply_slots: slots.as_ptr() as u64,
            },
            // Main never answers without a published command. Ending the
            // whole service releases its table; no isolated lost owner.
            Claim::Stale => sys::process_exit(13),
        };
        assert!(shared.complete(serial, outcome));
        completion.serial = serial;
        completion.status = outcome.status;
    }
}
