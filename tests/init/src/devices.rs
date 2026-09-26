// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Tests of interrupt lines and device windows (spec 9).

use crate::calls::LOWER_END;
use crate::harness::*;
use crate::messages::answer_all;
use crate::processes::{DATA_ABORT, KID_WAIT_NS, Kid, LEAF_QUOTA, START};
use crate::transfers::{close_raw, copy_raw, give, handle_client};
use rt::mmio;

/// The tests of this module, in the order they run.
pub(crate) const TESTS: [Test; 17] = [
    (
        "irq_bind_checks_its_arguments",
        irq_bind_checks_its_arguments,
    ),
    ("irq_ack_checks_its_handle", irq_ack_checks_its_handle),
    ("a_line_takes_one_binding", a_line_takes_one_binding),
    (
        "binding_goes_with_its_last_handle",
        binding_goes_with_its_last_handle,
    ),
    (
        "irq_info_reports_line_mask_and_trigger",
        irq_info_reports_line_mask_and_trigger,
    ),
    (
        "device_window_create_checks_its_arguments",
        device_window_create_checks_its_arguments,
    ),
    (
        "window_is_checked_by_whole_pages",
        window_is_checked_by_whole_pages,
    ),
    (
        "window_handle_is_a_device_window",
        window_handle_is_a_device_window,
    ),
    (
        "window_maps_read_write_but_never_exec",
        window_maps_read_write_but_never_exec,
    ),
    ("window_reads_its_device", window_reads_its_device),
    (
        "window_info_counts_its_mappings",
        window_info_counts_its_mappings,
    ),
    (
        "window_over_a_hole_faults_only_its_process",
        window_over_a_hole_faults_only_its_process,
    ),
    (
        "rtc_alarm_comes_as_a_notification",
        rtc_alarm_comes_as_a_notification,
    ),
    (
        "line_stays_masked_until_irq_ack",
        line_stays_masked_until_irq_ack,
    ),
    (
        "level_line_fires_again_until_its_source_is_cleared",
        level_line_fires_again_until_its_source_is_cleared,
    ),
    ("dead_driver_frees_its_line", dead_driver_frees_its_line),
    (
        "driver_dying_with_a_queued_alarm_frees_its_line",
        driver_dying_with_a_queued_alarm_frees_its_line,
    ),
];

/// A shared line with no device behind it in the tests' machine, the
/// first of `virtio-mmio`, which the tests bind edge-triggered.
const EDGE_LINE: u32 = 48;
/// The line of the PL031 of QEMU `virt`, level-triggered.
const RTC_LINE: u32 = 34;

/// A binding of `line` to `c` through the system resource, the slot at
/// QUIET, edge-triggered when `edge`.
fn bound(line: u32, c: &Handle<Channel>, edge: bool) -> Result<Handle<Interrupt>, &'static str> {
    sys::irq_bind(&resource(), line, c, QUIET, edge).map_err(|_| "irq_bind failed")
}

/// irq_bind(x0 system resource with DEVICE, x1 line, x2 channel with
/// NOTIFY, x3 priority, x4 flags) checks the values first, then the
/// handles in their order, then the state (spec 9, 11), and changes x0
/// alone on an error: a line outside 32-1019, the most lines a GIC has
/// (the end of this machine's lines is the kernel test
/// irq_bind_refuses_lines_past_the_distributor), or the kernel's console
/// line 33, a flag other than TRIGGER_EDGE and a priority outside 1-63
/// fail with INVALID_ARGS, through closed handles too; x0 closed, a
/// channel or a copy of the resource without DEVICE with BAD_HANDLE,
/// WRONG_TYPE and ACCESS_DENIED; x2 closed, a process or a copy of the
/// channel without NOTIFY the same; a closed channel with PEER_CLOSED. A
/// copy with NOTIFY alone makes a binding, x0 and x1 alone changed, whose
/// handle carries abi::OWNER_RIGHTS and no more.
fn irq_bind_checks_its_arguments() -> Outcome {
    const N: u16 = Call::IrqBind.number();
    let gone = closed_handle()?;
    let c = channel(QUIET)?;
    let notify = copy(&c, Rights::NOTIFY)?;
    let receive = copy(&c, Rights::RECEIVE)?;
    let no_device = copy(&resource(), Rights::DEBUG)?;
    let (resource, line) = (resource().raw().0, u64::from(EDGE_LINE));
    let good = [resource, line, notify.raw().0, QUIET.into(), TRIGGER_EDGE];
    let with = |i: usize, value: u64| {
        let mut x = good;
        x[i] = value;
        x
    };
    let invalid = [27, 31, 33, 1020, 1 << 32 | line]
        .map(|l| with(1, l))
        .into_iter()
        .chain([with(4, 2), with(3, 0), with(3, 64), with(3, 0x100 | 1)])
        .chain([[gone, 31, gone, 0, 2]])
        .all(|x| x0_alone::<N>(&x, Error::InvalidArgs.code()));
    let refused = [
        (with(0, gone), Error::BadHandle),
        (with(0, c.raw().0), Error::WrongType),
        (with(0, no_device.raw().0), Error::AccessDenied),
        (with(2, gone), Error::BadHandle),
        (with(2, own().raw().0), Error::WrongType),
        (with(2, receive.raw().0), Error::AccessDenied),
    ]
    .iter()
    .all(|(x, e)| x0_alone::<N>(x, e.code()));
    let mut x = marked();
    x[..5].copy_from_slice(&good);
    // SAFETY: irq_bind only reads its registers.
    let after = unsafe { sys::raw::<N>(x) };
    let made = after[0] == 0 && after[1] != 0 && after[2..] == x[2..];
    let b: Handle<Interrupt> = Handle::from_raw(abi::Handle(after[1]));
    let all = sys::handle_duplicate(&b, OWNER_RIGHTS).map(close);
    let more = sys::handle_duplicate(&b, OWNER_RIGHTS | Rights::NOTIFY).map(close);
    if made {
        close(b)?;
    }
    close(receive)?;
    close(c)?;
    let closed = x0_alone::<N>(&good, Error::PeerClosed.code());
    close(notify)?;
    close(no_device)?;
    check(
        invalid,
        "a bad line, flag or priority did not fail with INVALID_ARGS alone",
    )?;
    check(
        refused,
        "a bad resource or channel handle did not fail alone in its order",
    )?;
    check(made, "a good irq_bind failed or changed registers past x1")?;
    check(
        all == Ok(Ok(())) && more == Err(Error::AccessDenied),
        "the handle of irq_bind does not carry OWNER_RIGHTS and no more",
    )?;
    check(
        closed,
        "irq_bind of a closed channel did not fail with PEER_CLOSED alone",
    )
}

/// irq_ack(x0 binding with MANAGE) checks its handle (spec 9, 11) and
/// changes x0 alone: a closed handle fails with BAD_HANDLE, a channel with
/// WRONG_TYPE, a copy without MANAGE with ACCESS_DENIED. On a line that
/// is open it returns 0; once the binding's channel closed, PEER_CLOSED.
fn irq_ack_checks_its_handle() -> Outcome {
    const N: u16 = Call::IrqAck.number();
    let gone = closed_handle()?;
    let c = channel(QUIET)?;
    let b = bound(EDGE_LINE, &c, true)?;
    let seen = copy(&b, Rights::DUPLICATE)?;
    let refused = [
        (gone, Error::BadHandle),
        (c.raw().0, Error::WrongType),
        (seen.raw().0, Error::AccessDenied),
    ]
    .iter()
    .all(|&(h, e)| x0_alone::<N>(&[h], e.code()));
    let open = x0_alone::<N>(&[b.raw().0], 0);
    close(c)?;
    let closed = x0_alone::<N>(&[b.raw().0], Error::PeerClosed.code());
    close(seen)?;
    close(b)?;
    check(
        refused,
        "a closed handle, a channel or a copy without MANAGE did not fail alone",
    )?;
    check(open, "irq_ack of an open line did not return 0 alone")?;
    check(
        closed,
        "irq_ack after the channel closed did not fail with PEER_CLOSED alone",
    )
}

/// One binding a line (spec 9): a second irq_bind of a bound line fails
/// with BAD_STATE and changes x0 alone, through another channel too, and
/// before the state of the channel: a closed one does not change it.
fn a_line_takes_one_binding() -> Outcome {
    const N: u16 = Call::IrqBind.number();
    let c = channel(QUIET)?;
    let other = channel(QUIET)?;
    let shut = channel(QUIET)?;
    let notify = copy(&shut, Rights::NOTIFY)?;
    close(shut)?;
    let b = bound(EDGE_LINE, &c, true)?;
    let args = |h: &Handle<Channel>| {
        [
            resource().raw().0,
            EDGE_LINE.into(),
            h.raw().0,
            QUIET.into(),
            TRIGGER_EDGE,
        ]
    };
    let refused = [&c, &other, &notify]
        .iter()
        .all(|h| x0_alone::<N>(&args(h), Error::BadState.code()));
    close(b)?;
    close(notify)?;
    close(other)?;
    close(c)?;
    check(refused, "a bound line took a second binding")
}

/// A binding lives while a handle to it is left (spec 4, 9): with a copy
/// left the line stays bound after the first handle closed; once the last
/// one closed, a new irq_bind of the line succeeds at once.
fn binding_goes_with_its_last_handle() -> Outcome {
    let c = channel(QUIET)?;
    let b = bound(EDGE_LINE, &c, true)?;
    let kept = copy(&b, OWNER_RIGHTS)?;
    close(b)?;
    let held = sys::irq_bind(&resource(), EDGE_LINE, &c, QUIET, true).err();
    close(kept)?;
    let again = bound(EDGE_LINE, &c, false);
    let made = again.is_ok();
    if let Ok(b) = again {
        close(b)?;
    }
    close(c)?;
    check(
        held == Some(Error::BadState),
        "the line was free while a copy of its binding was left",
    )?;
    check(made, "the line stayed bound after its last handle closed")
}

/// object_info(IRQ) of a binding, with no right needed (spec 11): its
/// line, whether it is masked, and its kind of trigger. Right after
/// irq_bind a line is open, edge-triggered with TRIGGER_EDGE and
/// level-triggered without.
fn irq_info_reports_line_mask_and_trigger() -> Outcome {
    let c = channel(QUIET)?;
    let edge = bound(EDGE_LINE, &c, true)?;
    let level = bound(RTC_LINE, &c, false)?;
    let seen = copy(&level, Rights::NONE)?;
    let infos = (sys::irq_info(&edge), sys::irq_info(&seen));
    close(seen)?;
    close(level)?;
    close(edge)?;
    close(c)?;
    check(
        infos
            == (
                Ok(IrqInfo {
                    line: EDGE_LINE.into(),
                    masked: false,
                    edge: true,
                }),
                Ok(IrqInfo {
                    line: RTC_LINE.into(),
                    masked: false,
                    edge: false,
                }),
            ),
        "IRQ does not report the line, the open mask and the trigger of a new binding",
    )
}

/// The page of the PL031 of QEMU `virt`, the tests' device window: its
/// first register, at offset 0, holds the count of seconds (RTCDR).
const RTC: u64 = 0x0901_0000;
/// A page of QEMU `virt` with no device behind it: a load there is a
/// synchronous external abort.
const HOLE: u64 = 0x0904_0000;
/// The fault status of a synchronous external abort that is not on a
/// table walk, bits 5:0 of ESR ([G22]); an abort from EL0 gives ESR
/// 0x92000010 whole.
const EXTERNAL: u64 = 0b01_0000;

/// A device window over `len` bytes from `addr` through the system
/// resource.
fn device_window(addr: u64, len: u64) -> Result<Handle<Memory>, &'static str> {
    sys::device_window_create(&resource(), addr, len).map_err(|_| "device_window_create failed")
}

/// device_window_create(x0 system resource with DEVICE, x1 address, x2
/// length) checks the values first, then the handle, then the range
/// against RAM and the kernel's devices (spec 9, 11), and changes x0 alone
/// on an error: a length of 0, more than abi::MAX_MEMORY, a range that
/// wraps around or ends past 2^48 fail with INVALID_ARGS through a closed
/// handle too; a closed handle, a channel and a copy of the resource
/// without DEVICE with BAD_HANDLE, WRONG_TYPE and ACCESS_DENIED, over RAM
/// too; a page of RAM, of the GIC's distributor or of the PL011 with
/// INVALID_ARGS; the kernel test device_window_refuses_every_gic_page
/// checks the other regions of the GIC, which differ between machines. A
/// window on the PL031 changes x0 and x1 alone, and its handle carries
/// abi::WINDOW_RIGHTS and no MAP_EXEC.
fn device_window_create_checks_its_arguments() -> Outcome {
    const N: u16 = Call::DeviceWindowCreate.number();
    let gone = closed_handle()?;
    let c = channel(QUIET)?;
    let no_device = copy(&resource(), Rights::DEBUG)?;
    let (resource, page) = (resource().raw().0, PAGE as u64);
    let invalid = [
        (RTC, 0),
        (RTC, abi::MAX_MEMORY + page),
        (u64::MAX - 0x10, 0x20),
        (LOWER_END - page, 2 * page),
    ]
    .iter()
    .all(|&(addr, len)| x0_alone::<N>(&[gone, addr, len], Error::InvalidArgs.code()));
    let refused = [
        (gone, Error::BadHandle),
        (c.raw().0, Error::WrongType),
        (no_device.raw().0, Error::AccessDenied),
    ]
    .iter()
    .all(|&(h, e)| x0_alone::<N>(&[h, 0x4000_0000, page], e.code()));
    let kernel = [0x4000_0000, 0x0800_0000, 0x0900_0000]
        .iter()
        .all(|&addr| x0_alone::<N>(&[resource, addr, page], Error::InvalidArgs.code()));
    let mut x = marked();
    x[..3].copy_from_slice(&[resource, RTC, page]);
    // SAFETY: device_window_create only reads its registers.
    let after = unsafe { sys::raw::<N>(x) };
    let made = after[0] == 0 && after[1] != 0 && after[2..] == x[2..];
    let w: Handle<Memory> = Handle::from_raw(abi::Handle(after[1]));
    let all = sys::handle_duplicate(&w, WINDOW_RIGHTS).map(close);
    let more = sys::handle_duplicate(&w, WINDOW_RIGHTS | Rights::MAP_EXEC).map(close);
    if made {
        close(w)?;
    }
    close(no_device)?;
    close(c)?;
    check(
        invalid,
        "a bad length or range did not fail with INVALID_ARGS alone",
    )?;
    check(
        refused,
        "a bad resource handle did not fail alone before the range",
    )?;
    check(
        kernel,
        "a window over RAM or a device of the kernel was made",
    )?;
    check(
        made,
        "a good device_window_create failed or changed registers past x1",
    )?;
    check(
        all == Ok(Ok(())) && more == Err(Error::AccessDenied),
        "the handle of a window does not carry WINDOW_RIGHTS and no more",
    )
}

/// A window is checked by whole pages (spec 9): 32 bytes across the end of
/// the PL011's page touch it and fail with INVALID_ARGS; the same bytes
/// across the end of the PL031's page make a window of two pages.
fn window_is_checked_by_whole_pages() -> Outcome {
    let over = sys::device_window_create(&resource(), 0x0900_0FF0, 0x20).err();
    let w = device_window(RTC + 0xFF0, 0x20)?;
    let size = sys::memory_info(&w).map(|i| i.size);
    close(w)?;
    check(
        over == Some(Error::InvalidArgs),
        "a window that shares the page of the PL011 was made",
    )?;
    check(
        size == Ok(2 * PAGE as u64),
        "a window was not rounded out to whole pages",
    )
}

/// A window is a device window (spec 4, 6.2): a copy of its handle with
/// WINDOW_RIGHTS that a client sends comes with the kind DeviceWindow and
/// those rights in its info word.
fn window_handle_is_a_device_window() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    let w = device_window(RTC, PAGE as u64)?;
    give(&[copy_raw(&w, WINDOW_RIGHTS)?]);
    let t = spawn(0, handle_client, 0, HIGH, Policy::Fifo)?;
    let mut got = sys::try_receive(&c);
    let (h, info) = came(&mut got)[0];
    let replied = answer_all([got]);
    let closed = close_raw(h);
    close(t)?;
    close(c)?;
    close(w)?;
    check(
        info == (abi::ObjectKind::DeviceWindow, WINDOW_RIGHTS),
        "the window's handle came with another kind or other rights",
    )?;
    check(
        replied && ended(0) && closed.is_ok(),
        "the client did not get the reply",
    )
}

/// Spec 15.2 (memory, devices): a window maps R and RW, never RX (spec
/// 7.4): mem_map with RX and mem_protect of the RW mapping to RX fail with
/// ACCESS_DENIED, since the handle has no MAP_EXEC.
fn window_maps_read_write_but_never_exec() -> Outcome {
    let page = PAGE as u64;
    let w = device_window(RTC, page)?;
    let r = sys::mem_map(&own(), &w, 0, page, WINDOW, Access::Read);
    let rw = sys::mem_map(&own(), &w, 0, page, WINDOW + PAGE, Access::ReadWrite);
    let rx = sys::mem_map(&own(), &w, 0, page, WINDOW + 2 * PAGE, Access::ReadExec);
    // SAFETY: the mapping is the test's window, which nothing runs.
    let protected = unsafe { sys::mem_protect(&own(), WINDOW + PAGE, page, Access::ReadExec) };
    for (mapped, at) in [(r, WINDOW), (rw, WINDOW + PAGE)] {
        if mapped.is_ok() {
            unmap(at, page)?;
        }
    }
    close(w)?;
    check(r.is_ok() && rw.is_ok(), "a window did not map R or RW")?;
    check(
        rx == Err(Error::AccessDenied) && protected == Err(Error::AccessDenied),
        "a window mapped RX or became RX",
    )
}

/// A window shows its device (spec 9): the count of seconds of the PL031,
/// read twice through a window mapped R with loads of 32 bits (rt::mmio),
/// is not 0 and does not go back.
fn window_reads_its_device() -> Outcome {
    let page = PAGE as u64;
    let w = device_window(RTC, page)?;
    map(&w, 0, page, WINDOW, Access::Read)?;
    // SAFETY: the page is the PL031's registers, mapped R as device memory;
    // RTCDR is a 32-bit register at offset 0.
    let (first, second) = unsafe { (mmio::read32(WINDOW), mmio::read32(WINDOW)) };
    unmap(WINDOW, page)?;
    close(w)?;
    check(
        first != 0 && second >= first,
        "the PL031's count through the window is 0 or went back",
    )
}

/// MEMORY of a window (spec 11): its size, no page of frames it owns, and
/// its mappings now, two, then one.
fn window_info_counts_its_mappings() -> Outcome {
    let page = PAGE as u64;
    let w = device_window(RTC, page)?;
    let info = |mappings| {
        Ok(MemoryInfo {
            size: page,
            pages: 0,
            mappings,
        })
    };
    let before = sys::memory_info(&w);
    map(&w, 0, page, WINDOW, Access::Read)?;
    map(&w, 0, page, WINDOW + PAGE, Access::Read)?;
    let two = sys::memory_info(&w);
    unmap(WINDOW + PAGE, page)?;
    let one = sys::memory_info(&w);
    unmap(WINDOW, page)?;
    close(w)?;
    check(
        before == info(0) && two == info(2) && one == info(1),
        "MEMORY of a window does not count its mappings or counts pages",
    )
}

/// Spec 15.2 (faults), 7.9: a load through a window where no device
/// answers is a synchronous external abort of the process that made it,
/// and ends only that process. Init maps a window on a hole into a child
/// with code, which loads from it (Role::Load): the child ends with a data
/// abort from EL0 whose fault is external, FAR at the load; init lives on.
fn window_over_a_hole_faults_only_its_process() -> Outcome {
    let page = PAGE as u64;
    let w = device_window(HOLE, page)?;
    let kid = Kid::load(LEAF_QUOTA, 16, LEVEL)?;
    let at = child::SHARED;
    let state = sys::mem_map(&kid.process, &w, 0, page, at, Access::Read)
        .map_err(|_| "the window did not map into the child")
        .and_then(|()| kid.start())
        .and_then(|()| kid.serve(Role::Load, &[at as u64], &[]))
        .and_then(|()| kid.end());
    kid.close()?;
    let_run()?;
    close(w)?;
    match state? {
        ProcessState::Fault { esr, far, .. } => check(
            (esr >> 26 & 0x3F, esr & 0x3F, far) == (DATA_ABORT, EXTERNAL, at as u64),
            "the child's fault is no external abort at the load",
        ),
        ProcessState::Exited { code } if code == child::NO_FAULT => {
            Err("the child read the hole and did not fault")
        }
        _ => Err("the child did not end with a fault"),
    }
}

/// The registers of the PL031 the driver uses, 32 bits each, by their
/// offsets in its page: the count of seconds (RTCDR), the match (RTCMR),
/// the mask of its interrupt (RTCIMSC), the raw status of the alarm
/// (RTCRIS) and its clear (RTCICR).
const RTC_DR: usize = 0x00;
const RTC_MR: usize = 0x04;
const RTC_IMSC: usize = 0x10;
const RTC_RIS: usize = 0x14;
const RTC_ICR: usize = 0x1C;
/// The alarm bit of RTCIMSC, RTCRIS and RTCICR.
const ALARM: u32 = 1;
/// The priority of the slot of init's binding of the PL031: above init.
const DRIVER: u8 = 50;
/// Writes of the match that `Rtc::raise` tries: the count turns once a
/// second, between the read of the count and the write at most once.
const RAISE_TRIES: u32 = 3;
/// The rights of the binding a driver gets (spec 13.4): irq_ack, and the
/// move in a message, which the handle needs to reach the driver; no copy
/// of it outlives the driver without init.
const DRIVER_RIGHTS: Rights = Rights::MANAGE.union(Rights::TRANSFER);
/// A child that runs Role::Rtc: a page of its pool of channels more.
const RTC_QUOTA: u64 = LEAF_QUOTA + PAGE as u64;

/// Init as the driver of the PL031 (spec 13.5): a device window on its
/// page, mapped RW at WINDOW, a channel for the binding of RTC_LINE, and a
/// timer on the channel that bounds each wait. The alarm rises at once:
/// the match written with the count the driver read raises it (the
/// device's rule), so no test waits for time to pass.
struct Rtc {
    window: Handle<Memory>,
    channel: Handle<Channel>,
    guard: Handle<Timer>,
}

impl Rtc {
    /// The driver's window, channel and timer, with the alarm masked and
    /// cleared in the device.
    fn open() -> Result<Rtc, &'static str> {
        let window = device_window(RTC, PAGE as u64)?;
        map(&window, 0, PAGE as u64, WINDOW, Access::ReadWrite)?;
        let channel = channel(QUIET)?;
        let guard = timer(&channel)?;
        let rtc = Rtc {
            window,
            channel,
            guard,
        };
        rtc.write(RTC_IMSC, 0);
        rtc.write(RTC_ICR, ALARM);
        Ok(rtc)
    }

    fn read(&self, reg: usize) -> u32 {
        // SAFETY: the window maps the PL031's page at WINDOW, RW, as device
        // memory; each register is 32 bits at its offset.
        unsafe { mmio::read32(WINDOW + reg) }
    }

    fn write(&self, reg: usize, value: u32) {
        // SAFETY: as in `read`.
        unsafe { mmio::write32(WINDOW + reg, value) }
    }

    /// The binding of RTC_LINE, level-triggered, to the channel at DRIVER.
    fn bind(&self) -> Result<Handle<Interrupt>, &'static str> {
        sys::irq_bind(&resource(), RTC_LINE, &self.channel, DRIVER, false)
            .map_err(|_| "irq_bind of the PL031's line failed")
    }

    /// Raises the alarm: unmasks it in the device and writes the count it
    /// reads into the match; when the count turned in between, the raw
    /// status stays 0 and it tries again.
    fn raise(&self) -> Outcome {
        self.write(RTC_IMSC, ALARM);
        for _ in 0..RAISE_TRIES {
            let count = self.read(RTC_DR);
            self.write(RTC_MR, count);
            if self.read(RTC_RIS) & ALARM != 0 {
                return Ok(());
            }
        }
        Err("the PL031's alarm did not rise at its count")
    }

    /// Clears the alarm and reads its status back, as a driver does before
    /// irq_ack (spec 13.5).
    fn clear(&self) -> Outcome {
        self.write(RTC_ICR, ALARM);
        check(
            self.read(RTC_RIS) & ALARM == 0,
            "the PL031's alarm did not clear",
        )
    }

    /// What the channel takes next, within KID_WAIT_NS; the timer's
    /// expiry is a failure.
    fn wait(&self) -> Result<Received, &'static str> {
        arm(&self.guard, clock_now()? + KID_WAIT_NS)?;
        let got = sys::receive(&self.channel);
        let cancelled = sys::timer_cancel(&self.guard);
        match got {
            _ if cancelled.is_err() => Err("timer_cancel failed"),
            Ok(Received::Notification {
                source: Source::Timer,
                ..
            }) => Err("no interrupt came in time"),
            Ok(got) => Ok(got),
            Err(_) => Err("receive on the driver's channel failed"),
        }
    }

    /// What the channel holds now; WOULD_BLOCK when nothing.
    fn now(&self) -> Result<Received, Error> {
        sys::try_receive(&self.channel)
    }

    /// Masks and clears the alarm, unmaps the window and closes the
    /// handles.
    fn close(self) -> Outcome {
        self.write(RTC_IMSC, 0);
        self.write(RTC_ICR, ALARM);
        unmap(WINDOW, PAGE as u64)?;
        let closed = [
            self.guard.close(),
            self.channel.close(),
            self.window.close(),
        ];
        check(
            closed.iter().all(Result::is_ok),
            "a handle of the driver did not close",
        )
    }
}

/// An interrupt through a handle with no label, merged `count` times.
fn interrupt(count: u32) -> Received {
    Received::Notification {
        source: Source::Interrupt,
        label: 0,
        bits: 1,
        count,
    }
}

/// What IRQ says of init's binding of the PL031.
fn rtc_line(masked: bool) -> Result<IrqInfo, Error> {
    Ok(IrqInfo {
        line: RTC_LINE.into(),
        masked,
        edge: false,
    })
}

/// Spec 15.2 (devices), 9, 13.5: the PL031's alarm comes as a notification
/// of an interrupt, label 0, bit 0, one delivery, and the line is masked
/// meanwhile; the driver clears the alarm, reads the status back and
/// calls irq_ack, which opens the line, and nothing more comes.
fn rtc_alarm_comes_as_a_notification() -> Outcome {
    let rtc = Rtc::open()?;
    let b = rtc.bind()?;
    let got = rtc.raise().and_then(|()| rtc.wait());
    let masked = sys::irq_info(&b);
    let cleared = rtc.clear();
    let acked = sys::irq_ack(&b);
    let rest = rtc.now();
    let open = sys::irq_info(&b);
    close(b)?;
    rtc.close()?;
    check(
        got? == interrupt(1),
        "the alarm did not come as one notification of an interrupt",
    )?;
    check(
        masked == rtc_line(true),
        "the line was not masked after its notification",
    )?;
    cleared?;
    check(
        acked.is_ok() && rest == Err(Error::WouldBlock),
        "a cleared alarm came again after irq_ack",
    )?;
    check(open == rtc_line(false), "irq_ack did not open the line")
}

/// Spec 15.2 (devices), 9: a line stays masked until irq_ack. The driver
/// clears the first alarm and raises it again without irq_ack: nothing
/// comes; irq_ack opens the line, and the alarm comes before the call
/// returns.
fn line_stays_masked_until_irq_ack() -> Outcome {
    let rtc = Rtc::open()?;
    let b = rtc.bind()?;
    let first = rtc.raise().and_then(|()| rtc.wait());
    let again = rtc.clear().and_then(|()| rtc.raise());
    let held = rtc.now();
    let acked = sys::irq_ack(&b);
    let second = rtc.now();
    let last = rtc.clear().map(|()| sys::irq_ack(&b));
    let rest = rtc.now();
    close(b)?;
    rtc.close()?;
    check(first? == interrupt(1), "the first alarm did not come")?;
    again?;
    check(
        held == Err(Error::WouldBlock),
        "an alarm came while the line was masked",
    )?;
    check(
        acked.is_ok() && second == Ok(interrupt(1)),
        "the alarm raised under the mask did not come at irq_ack",
    )?;
    check(
        last == Ok(Ok(())) && rest == Err(Error::WouldBlock),
        "a cleared alarm came again",
    )
}

/// Spec 9, 13.5: a level-triggered line stays up until the driver clears
/// its source. irq_ack without the clear gives a second notification at
/// once; after the clear, the read back and irq_ack, no third comes.
fn level_line_fires_again_until_its_source_is_cleared() -> Outcome {
    let rtc = Rtc::open()?;
    let b = rtc.bind()?;
    let first = rtc.raise().and_then(|()| rtc.wait());
    let acked = sys::irq_ack(&b);
    let second = rtc.now();
    let cleared = rtc.clear();
    let last = sys::irq_ack(&b);
    let third = rtc.now();
    close(b)?;
    rtc.close()?;
    check(first? == interrupt(1), "the first alarm did not come")?;
    check(
        acked.is_ok() && second == Ok(interrupt(1)),
        "a line still up gave no second notification after irq_ack",
    )?;
    cleared?;
    check(
        last.is_ok() && third == Err(Error::WouldBlock),
        "a cleared line gave a third notification",
    )
}

/// Spec 15.2 (devices), 9, 13.4: a driver that dies frees its line. A child
/// (Role::Rtc) sends init a copy of its channel with NOTIFY; init binds the
/// PL031's line through it and answers with a copy of the binding with
/// MANAGE and TRANSFER alone, which moves to the child. Init raises the
/// alarm, the child reports the notification and never calls irq_ack. Once
/// init killed it and heard of its end, init binds the line to its own
/// channel, and the alarm, never cleared, comes before irq_bind returns and
/// masks the line.
fn dead_driver_frees_its_line() -> Outcome {
    let rtc = Rtc::open()?;
    let kid = Kid::load(RTC_QUOTA, 16, LEVEL)?;
    let heard = kid
        .start()
        .and_then(|()| kid.serve(Role::Rtc, &[], &[]))
        .and_then(|()| bind_for(&kid, false).map(drop))
        .and_then(|()| rtc.raise())
        .and_then(|()| kid.ear.next());
    let killed = sys::process_kill(&kid.process);
    let state = kid.end();
    kid.close()?;
    let_run()?;
    let again = rtc.bind();
    let got = rtc.now();
    let info = again.as_ref().ok().map(sys::irq_info);
    let cleared = rtc.clear();
    let rest = again.as_ref().ok().map(|b| (sys::irq_ack(b), rtc.now()));
    if let Ok(b) = again {
        close(b)?;
    }
    rtc.close()?;
    let binding = abi::msgbuf::info(abi::ObjectKind::Interrupt, DRIVER_RIGHTS);
    match heard? {
        Received::Message {
            label: START,
            len: 40,
            words,
            ..
        } => check(
            words[..5] == [binding, Source::Interrupt.code(), 0, 1, 1],
            "the child's binding or notification was not as sent",
        )?,
        _ => return Err("the child did not report its notification"),
    }
    check(
        killed.is_ok() && state? == ProcessState::Killed,
        "the child did not end killed",
    )?;
    check(
        info == Some(rtc_line(true)) && got == Ok(interrupt(1)),
        "the line of a dead driver did not bind again and deliver at once",
    )?;
    cleared?;
    check(
        rest == Some((Ok(()), Err(Error::WouldBlock))),
        "the alarm came again once cleared",
    )
}

/// Spec 15.2 (devices), 9, 13.4: a driver that dies with a notification
/// in its channel's queue frees its line at once. The child (Role::Rtc,
/// word 1) sends init besides a copy of its channel with RECEIVE and
/// TRANSFER, and waits in a request once it holds the binding, taking
/// nothing. Init raises the alarm, which the way out of the kernel
/// delivers before init runs again: CHANNEL of the copy shows one
/// notification queued. Init's copy keeps the channel open, and the
/// notification in its queue, after the child's end; irq_bind of the line
/// succeeds all the same, and the alarm, never cleared, comes before it
/// returns. The old notification still waits in the child's channel.
fn driver_dying_with_a_queued_alarm_frees_its_line() -> Outcome {
    let rtc = Rtc::open()?;
    let kid = Kid::load(RTC_QUOTA, 16, LEVEL)?;
    let seen = kid
        .start()
        .and_then(|()| kid.serve(Role::Rtc, &[1], &[]))
        .and_then(|()| bind_for(&kid, true));
    let queued = match &seen {
        Ok(Some(s)) => kid
            .ear
            .next()
            .and_then(|_| rtc.raise())
            .and_then(|()| let_run())
            .map(|()| sys::channel_info(s).map(|i| i.queued)),
        Ok(None) => Err("the child sent no second copy of its channel"),
        Err(e) => Err(*e),
    };
    let killed = sys::process_kill(&kid.process);
    let state = kid.end();
    kid.close()?;
    let again = rtc.bind();
    let got = rtc.now();
    let cleared = rtc.clear();
    let rest = again.as_ref().ok().map(|b| (sys::irq_ack(b), rtc.now()));
    if let Ok(b) = again {
        close(b)?;
    }
    let left = match seen {
        Ok(Some(s)) => {
            let left = sys::channel_info(&s).map(|i| i.queued);
            close(s)?;
            left
        }
        _ => Err(Error::BadHandle),
    };
    rtc.close()?;
    check(
        queued? == Ok(1) && left == Ok(1),
        "the alarm did not wait in the child's channel",
    )?;
    check(
        killed.is_ok() && state? == ProcessState::Killed,
        "the child did not end killed",
    )?;
    check(
        rest.is_some() && got == Ok(interrupt(1)),
        "the line of a driver that died with a notification queued did not bind again at once",
    )?;
    cleared?;
    check(
        rest == Some((Ok(()), Err(Error::WouldBlock))),
        "the alarm came again once cleared",
    )
}

/// Takes the child's request BIND with a copy of its channel with NOTIFY,
/// and when `seen` a second copy with RECEIVE and TRANSFER, which init
/// keeps and returns; binds RTC_LINE through the first at LEVEL, closes it, and
/// answers with a copy of the binding with DRIVER_RIGHTS, which moves to
/// the child; init's own handle goes (spec 13.4).
fn bind_for(kid: &Kid, seen: bool) -> Result<Option<Handle<Channel>>, &'static str> {
    let Received::Message {
        label: START,
        len: 8,
        mut handles,
        token,
        words,
    } = kid.ear.next()?
    else {
        return Err("the child did not send its channel");
    };
    let (c, kept) = (handles.take::<Channel>(0).ok(), handles.take(1).ok());
    check(
        handles.len() == 1 + usize::from(seen),
        "the child sent another count of handles",
    )?;
    let c = c.ok_or("the child did not send its channel")?;
    let b = sys::irq_bind(&resource(), RTC_LINE, &c, LEVEL, false);
    close(c)?;
    check(words[0] == child::BIND, "the child's request is not BIND")?;
    let b = b.map_err(|_| "irq_bind through the child's channel failed")?;
    let given = copy(&b, DRIVER_RIGHTS);
    close(b)?;
    token
        .reply_handles(&[], [given?.erase()])
        .map_err(|_| "the reply with the binding failed")?;
    Ok(kept)
}
