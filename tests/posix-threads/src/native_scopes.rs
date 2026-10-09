// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
//! Real native IPC, process-stop barriers and joinable libc exit intent.
use super::*;
use abi::signals;
use rt::{
    Stack,
    abi::{Error, Policy, Source},
    upcall,
};

static STACK: Stack<16384> = Stack::new();
static COMPLETION: AtomicU64 = AtomicU64::new(0);
static GATE: AtomicU64 = AtomicU64::new(0);
static BLOCKING: AtomicU64 = AtomicU64::new(0);
static ROUND: AtomicUsize = AtomicUsize::new(0);
static ERROR: AtomicUsize = AtomicUsize::new(0);
static OWNER: AtomicU64 = AtomicU64::new(0);
static NATIVE: AtomicU64 = AtomicU64::new(0);
static CREATED: AtomicU64 = AtomicU64::new(0);
static POINTER: AtomicUsize = AtomicUsize::new(0);
static ID: AtomicU64 = AtomicU64::new(0);
static INTERRUPTED: AtomicUsize = AtomicUsize::new(0);
static RETURNED: AtomicUsize = AtomicUsize::new(0);
static PRIMARY_RAN: AtomicUsize = AtomicUsize::new(0);

fn borrowed(raw: &AtomicU64) -> core::mem::ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(rt::abi::Handle(raw.load(Ordering::SeqCst)))
}
fn mark_error(stage: usize) {
    ERROR.store(stage, Ordering::SeqCst);
}
fn report() {
    let _ = sys::notify(&borrowed(&COMPLETION), 1);
}
/// Set just before the libc leaving tail: every entry calls the handler of
/// the program after the resident one, so only the entry that follows this
/// mark ends the thread.
static ARMED: AtomicUsize = AtomicUsize::new(0);
unsafe extern "C" fn primary_end() {
    if ARMED.load(Ordering::SeqCst) == 0 {
        return;
    }
    PRIMARY_RAN.store(1, Ordering::SeqCst);
    sys::thread_exit()
}
rt::upcall_entry!(primary_entry, primary_end);

extern "C" fn worker(_: u64) -> ! {
    let created = Handle::<Thread>::borrowed(rt::abi::Handle(CREATED.load(Ordering::SeqCst)));
    assert!(sys::is_current_thread(&created).expect("genuine selected native caller"));
    // Preserve a genuine application primary handler alongside the resident handler.
    unsafe { upcall::bind(primary_entry) }.expect("native primary bind");
    unsafe { upcall::enable() }.expect("native primary enable");
    for round in 1..=2 {
        let outer = upcall::defer_entries().expect("native outer deferral");
        tls::with_process(|| {
            let trace = signals::probe_native_stop_arm().expect("native trace admission");
            OWNER.store(trace.owner, Ordering::SeqCst);
            NATIVE.store(trace.native, Ordering::SeqCst);
            POINTER.store(posix_thread::thread_pointer(), Ordering::SeqCst);
            ID.store(ffi::pthread_self(), Ordering::SeqCst);
            signals::probe_native_stop_outer(true);
            ROUND.store(round, Ordering::SeqCst);
            report();
            // Nobody sends to this channel. Only a real requested upcall interrupts it.
            if sys::receive(&borrowed(&BLOCKING)) != Err(Error::Interrupted) {
                mark_error(1);
            }
            INTERRUPTED.store(round, Ordering::SeqCst);
            if signals::probe_native_stop_snapshot().entries != 0 {
                mark_error(2);
            }
            signals::probe_native_stop_outer(false);
            // This last Resume enters the resident handler, which parks before Drop returns.
            drop(outer);
            RETURNED.store(round, Ordering::SeqCst);
        });
        report();
        // The coordinator validates the full trace before allowing its reset/reuse.
        receive_completion(&borrowed(&GATE)).expect("native next scenario");
    }
    tls::with_process(|| {
        let trace = signals::probe_native_stop_arm().expect("native fork scope");
        OWNER.store(trace.owner, Ordering::SeqCst);
        ROUND.store(3, Ordering::SeqCst);
        report();
        if sys::receive(&borrowed(&BLOCKING)) != Err(Error::Interrupted) {
            mark_error(3);
        }
        RETURNED.store(3, Ordering::SeqCst);
    });
    report();
    receive_completion(&borrowed(&GATE)).expect("native libc exit release");
    tls::with_process(|| {
        let trace = signals::probe_native_stop_arm().expect("native exit scope");
        OWNER.store(trace.owner, Ordering::SeqCst);
        ARMED.store(1, Ordering::SeqCst);
        signals::probe_native_exit_queue();
        // The actual libc leaving tail queues primary_end while its own Defer is held.
        unsafe { ffi::pthread_exit(37usize as *mut c_void) }
    })
}

fn receive_completion(channel: &Handle<Channel>) -> Result<sys::Received, Error> {
    loop {
        match sys::receive(channel) {
            Err(Error::Interrupted) => continue,
            result => return result,
        }
    }
}

fn await_round(channel: &Handle<Channel>, round: usize) -> bool {
    while ROUND.load(Ordering::SeqCst) != round {
        if receive_completion(channel).is_err() {
            return false;
        }
    }
    true
}
fn await_return(channel: &Handle<Channel>, round: usize) -> bool {
    while RETURNED.load(Ordering::SeqCst) != round {
        if receive_completion(channel).is_err() {
            return false;
        }
    }
    true
}

#[inline(never)]
pub(super) fn run() -> bool {
    let main = unsafe { threads::probe_native(ffi::pthread_self()) }.expect("main identity");
    let original_info = sys::thread_info(&main).expect("main priority");
    let original = original_info.base;
    if original < 3 || threads::set_level(original - 2).is_err() {
        return failed(730);
    }
    // A receive ends a retained boost; an unpublished empty
    // channel makes this a single nonblocking operation at the lowered base.
    let settle = sys::channel_create(original - 2).expect("native startup boost channel");
    let settled = matches!(sys::try_receive(&settle), Err(Error::WouldBlock));
    drop(settle);
    if !settled {
        return failed(731);
    }
    let main_info = sys::thread_info(&main).expect("lowered main priority");
    let mut raised_info = main_info;
    abi::shared::probe_hold(|| {
        raised_info = sys::thread_info(&main).expect("actual raising lock priority");
    });
    let raised = raised_info.priority;
    let level = original - 1;
    if !(main_info.priority < level && level < raised) {
        rt::println!(
            "native-scopes: priority original={}/{}/{} main={}/{}/{} raised={}/{}/{}",
            u32::from(original_info.base),
            u32::from(original_info.priority),
            original_info
                .policy
                .map_or(u32::MAX, |policy| policy as u32),
            u32::from(main_info.base),
            u32::from(main_info.priority),
            main_info.policy.map_or(u32::MAX, |policy| policy as u32),
            u32::from(raised_info.base),
            u32::from(raised_info.priority),
            raised_info.policy.map_or(u32::MAX, |policy| policy as u32)
        );
        return failed(731);
    }
    // Both raising locks use the same process ceiling; the scan hook itself has no SVC.
    let completion = sys::channel_create(main_info.base).expect("native completion");
    let gate = sys::channel_create(level).expect("native gate");
    let blocking = sys::channel_create(level).expect("native empty receive");
    let ended = sys::channel_create(main_info.base).expect("native end notice");
    COMPLETION.store(completion.raw().0, Ordering::SeqCst);
    GATE.store(gate.raw().0, Ordering::SeqCst);
    BLOCKING.store(blocking.raw().0, Ordering::SeqCst);
    let native = unsafe {
        sys::thread_create_with(
            abi::allocation::process(),
            worker,
            STACK.top(),
            0,
            level,
            Policy::Fifo,
            0xe00000,
            Some((&ended, main_info.base)),
        )
    }
    .expect("native thread create");
    CREATED.store(native.raw().0, Ordering::SeqCst);
    if sys::thread_info(&native).expect("native priority").priority != level
        || sys::thread_start(&native).is_err()
    {
        return failed(732);
    }
    let mut previous: Option<(u64, u64, usize)> = None;
    for round in 1..=2 {
        if !await_round(&completion, round)
            || sys::thread_info(&native).expect("native receive").state != ThreadState::Receiving
        {
            return failed(733);
        }
        let identity = (
            OWNER.load(Ordering::SeqCst),
            NATIVE.load(Ordering::SeqCst),
            POINTER.load(Ordering::SeqCst),
        );
        if let Some((owner, cap, page)) = previous
            && (identity.0 & 63 != owner & 63
                || identity.0 >> 6 != (owner >> 6) + 1
                || identity.1 != cap
                || identity.2 != page)
        {
            return failed(734);
        }
        previous = Some(identity);
        let result = abi::process::exec(
            b"/native-defer-no-such-image",
            [].into_iter(),
            [].into_iter(),
            0o022,
        );
        if result != Err(ENOENT) || !await_return(&completion, round) {
            return failed(735);
        }
        let trace = signals::probe_native_stop_snapshot();
        if trace.owner != identity.0
            || trace.native != identity.1
            || !trace.waited
            || trace.unsafe_accept
            || trace.early_entry
            || trace.entries == 0
            || trace.parked == 0
            || trace.parked != trace.channel
            || INTERRUPTED.load(Ordering::SeqCst) != round
            || ERROR.load(Ordering::SeqCst) != 0
        {
            return failed(736);
        }
        if sys::notify(&gate, 1).is_err() {
            return failed(737);
        }
    }
    if !await_round(&completion, 3) {
        return failed(738);
    }
    let pid = match abi::fork::fork(None) {
        Ok(0) => sys::process_exit(0),
        Ok(pid) => pid,
        Err(_) => return failed(739),
    };
    let waited = abi::process::wait(
        proto_process::Selector::Pid(pid as u32),
        proto_process::WEXITED,
    );
    if !waited.is_ok_and(|waited| waited.end == Some(proto_process::End::exited(0))) {
        let (errno, end_tag, status) = match waited {
            Err(errno) => (errno, 0, 0),
            Ok(waited) => match waited.end {
                None => (0, 0, 0),
                Some(end @ proto_process::End::Exited(_)) => (0, 1, end.wait_status()),
                Some(end @ proto_process::End::Signaled(_)) => (0, 2, end.wait_status()),
            },
        };
        rt::println!("native wait: errno={errno} end={end_tag} status={status}");
        return failed(740);
    }
    if !await_return(&completion, 3) {
        return failed(7402);
    }
    let trace = signals::probe_native_stop_snapshot();
    if trace.parked == 0 || trace.parked != trace.channel {
        return failed(741);
    }
    if sys::notify(&gate, 1).is_err() {
        return failed(742);
    }
    match receive_completion(&ended) {
        Ok(sys::Received::Notification {
            source: Source::Exit,
            ..
        }) => {}
        _ => return failed(743),
    }
    if sys::thread_info(&native).expect("genuine native End").state != ThreadState::Ended {
        return failed(744);
    }
    // A missing held Defer executes the real primary handler before libc posts its retval.
    // Detect that marker before attempting a join, so the negative cannot hang in join.
    if PRIMARY_RAN.load(Ordering::SeqCst) != 0 || signals::probe_native_stop_snapshot().queued != 1
    {
        return failed(745);
    }
    let saved = signals::probe_native_stop_snapshot();
    // Collect must retain this genuine-ended, joinable row and its exact page/Block.
    abi::relibc::collect();
    if !abi::relibc::probe_native_retained(&saved) {
        return failed(748);
    }
    let mut value = ptr::null_mut();
    if unsafe { ffi::pthread_join(ID.load(Ordering::SeqCst), &mut value) } != 0
        || value as usize != 37
    {
        return failed(746);
    }
    abi::relibc::collect();
    if !abi::relibc::probe_native_freed(saved.owner) {
        return failed(749);
    }
    if threads::set_level(original).is_err() {
        return failed(747);
    }
    rt::println!(
        "native-scope-probe: Receive Interrupted under outer Defer; repeated owner renewal, exec rollback, fork/reap and joinable primary exit intent passed"
    );
    true
}
