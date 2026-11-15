// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The thread that asks init for the time budgets of POSIX threads
//! (SCHED_SPORADIC, proto_init BUDGET): the loop never sends to init, which
//! lies below it, so this thread waits in the loop for the next job (WORK,
//! proto_process::sporadic), asks init for the budget or gives a share back,
//! and tells the loop how it went in its next WORK, which the loop answers
//! when it has another job. The thread works at the loop's level; its stack
//! and message buffer are its own.

use crate::make;
use core::sync::atomic::{AtomicU64, Ordering};
use proto_process::Method;
use proto_process::sporadic::{self, Done, JOB_ASK, Job};
use proto_wire::{Reader, Writer};
use rt::handle::{Budget, Handle, Outgoing, Thread};
use rt::{Stack, abi, sys};

const STACK_SIZE: usize = 16 * 1024;
static STACK: Stack<STACK_SIZE> = Stack::new();
/// The thread's message buffer, five pages after the main thread's.
const BUFFER: usize = abi::INIT_MSGBUF as usize + 5 * 4096;
/// The value of the thread's own handle, which the service keeps for good.
static THREAD: AtomicU64 = AtomicU64::new(0);

/// Starts the thread at `level` in `own`, the service's process.
pub fn start(own: &Handle<rt::handle::Process>, level: u8) -> Result<(), abi::Error> {
    // SAFETY: STACK is the thread's alone, and the page five after the main
    // thread's buffer is free.
    let thread = unsafe {
        sys::thread_create(
            own,
            budgeter,
            STACK.top(),
            0,
            level,
            abi::Policy::Fifo,
            BUFFER,
        )
    }?;
    THREAD.store(thread.into_raw().0, Ordering::Release);
    sys::thread_start(&Handle::<Thread>::borrowed(abi::Handle(
        THREAD.load(Ordering::Acquire),
    )))
}

/// What init answered a job: its status (0 or the kernel's code of the
/// refusal), the number it gave and, for a budget made, the budget.
fn ask_init(job: &Job) -> (Done, Outgoing) {
    let init = make::init();
    let mut buffer = [0; abi::MESSAGE_MAX];
    let mut w = Writer::new();
    let sent = match job.kind {
        JOB_ASK => {
            let ask = proto_init::BudgetAsk {
                cpu: job.ask.cpu,
                low: job.ask.low,
                max_repl: job.ask.max_repl,
                c_ns: job.ask.c_ns,
                t_ns: job.ask.t_ns,
                replace: job.id,
            };
            proto_init::Method::Budget
                .header()
                .write(&mut w)
                .and_then(|()| w.u32(proto_init::BUDGET_ASK))
                .and_then(|()| ask.write(&mut w))
        }
        _ => proto_init::Method::Budget
            .header()
            .write(&mut w)
            .and_then(|()| w.u32(proto_init::BUDGET_RELEASE))
            .and_then(|()| w.u64(job.id)),
    };
    let failed = |status| {
        (
            Done {
                seq: job.seq,
                status,
                id: 0,
            },
            Outgoing::new(),
        )
    };
    if sent.is_err() {
        return failed(proto_process::INVALID);
    }
    let mut reply = loop {
        match sys::send(&init, w.as_bytes()) {
            Err(abi::Error::Interrupted) => continue,
            Err(_) => return failed(proto_process::INVALID),
            Ok(reply) => break reply,
        }
    };
    let mut r = Reader::new(reply.bytes(&mut buffer));
    let status = r.u32().unwrap_or(proto_process::INVALID);
    if status != 0 || job.kind != JOB_ASK {
        return failed(status);
    }
    let id = r.u32().and_then(|_| r.u64()).unwrap_or(0);
    let mut held = Outgoing::new();
    if let Ok(budget) = reply.handles.take::<Budget>(0) {
        let _ = held.push(budget.erase());
    }
    if id == 0 || held.is_empty() {
        return failed(proto_process::INVALID);
    }
    (
        Done {
            seq: job.seq,
            status: 0,
            id,
        },
        held,
    )
}

extern "C" fn budgeter(_: u64) -> ! {
    let channel = make::channel();
    let mut buffer = [0; abi::MESSAGE_MAX];
    let mut done = Done {
        seq: 0,
        status: 0,
        id: 0,
    };
    // The budget init gave for the job that finished, until a WORK carries it.
    let mut held = Outgoing::new();
    loop {
        let mut w = Writer::new();
        if Method::Budget.header().write(&mut w).is_err()
            || w.u32(sporadic::WORK).is_err()
            || done.write(&mut w).is_err()
        {
            sys::process_exit(13);
        }
        let sent = if held.is_empty() {
            sys::send(&channel, w.as_bytes())
        } else {
            sys::send_handles(&channel, w.as_bytes(), core::mem::take(&mut held)).map_err(
                |refused| {
                    held = refused.back.unwrap_or_default();
                    refused.error
                },
            )
        };
        let reply = match sent {
            Ok(reply) => reply,
            Err(abi::Error::Interrupted) => continue,
            // The loop does not answer any more: the service ends.
            Err(_) => sys::process_exit(14),
        };
        let mut r = Reader::new(reply.bytes(&mut buffer));
        let (Ok(0), Ok(job)) = (r.u32(), Job::read(&mut r)) else {
            // The reply of a loop that had no job to give: ask again.
            done = Done {
                seq: 0,
                status: 0,
                id: 0,
            };
            continue;
        };
        (done, held) = ask_init(&job);
    }
}
