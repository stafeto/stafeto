// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The guest probe of the input service (`input`, services/virtio-input).
//! A client of init whose role the byte of its own arguments names:
//!
//! - `g`, the display service's place: its session from init (`connects`)
//!   is the one that may GRANT and REVOKE. A key pressed with no focus is
//!   dropped; after GRANT, `sendkey a` of xtask comes as the events
//!   `1 30 1` and `1 30 0`; a burst of presses nobody reads leaves 64
//!   events and LOST, and LOST comes once; a second GRANT revokes the first
//!   focus (its READ is REVOKED) and the keys go to the second; after
//!   REVOKE a key goes nowhere and the READ of the revoked focus is
//!   REVOKED; the focus cannot GRANT, the grantor cannot READ, and READ
//!   takes 1 to 120 events. The pauses are for xtask to press the keys: it
//!   reads the lines `input-probe: send ...` and answers with `sendkey`.
//!   Then the service of the screen stands in for that place: OPEN gives
//!   the owner a session of focus (status 0, three handles), and `sendkey`
//!   reaches it; CLOSE of the screen revokes it (REVOKED), a key pressed
//!   then goes nowhere, and the next OPEN's focus is another that has only
//!   the keys pressed since, while the old one stays REVOKED.
//! - `x`, a program init gave no session: its CONNECT is refused.
//!
//! With the feature `quick` (the run under -icount) the probe asks for the
//! focus, polls READ until the key `z` came, and gives the focus back.
//!
//! Each check prints its line, and the last says `input-probe: ok`; xtask
//! reads them.

#![no_std]
#![no_main]

use abi::MESSAGE_MAX;
use proto_gpu::{CLEARING, Method as GpuMethod, Screen};
use proto_init::ServiceArgs;
use proto_input::{
    Event, INVALID, LOST, MAX_READ, Method, NOT_ALLOWED, REVOKED, RING, code, read_events,
};
use proto_wire::{Status, Writer};
use rt::handle::{Channel, Resource};
use rt::wait::Waiter;
use rt::{Handle, sys, time};

rt::entry!(main);

/// The pause for xtask to press a key and the device to deliver it, when
/// the run has the wall clock; the burst's longer pause; the polling
/// period of the quick run and its longest wait.
const KEY_NS: u64 = if cfg!(feature = "quick") {
    0
} else {
    2_000_000_000
};
const BURST_NS: u64 = if cfg!(feature = "quick") {
    0
} else {
    8_000_000_000
};
const POLL_NS: u64 = 100_000_000;
const WAIT_NS: u64 = 3_600_000_000_000;
/// The key codes of Linux the probe expects: KEY_A, KEY_C, KEY_Z.
const KEY_A: u16 = 30;
const KEY_C: u16 = 46;
const KEY_Z: u16 = 44;

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    let own = ServiceArgs::read(start.args()).map_or(&[][..], |a| a.own);
    let level = sys::thread_info(&start.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(level) else {
        return 1;
    };
    let Ok(waiter) = Waiter::new(&channel, 0, level) else {
        return 1;
    };
    let probe = Probe {
        parent: &start.parent,
        channel,
        waiter,
    };
    let result = match own {
        b"g" if cfg!(feature = "quick") => probe.quick(),
        b"g" => probe.grantor(),
        b"x" => probe.stranger(),
        _ => Err("an unknown role"),
    };
    match result {
        Ok(()) => {
            rt::println!("input-probe: ok");
            0
        }
        Err(reason) => {
            rt::println!("input-probe: failed: {reason}");
            2
        }
    }
}

struct Probe<'a> {
    parent: &'a Handle<Channel>,
    channel: Handle<Channel>,
    waiter: Waiter,
}

/// What a request to the service came to.
#[derive(Debug, PartialEq, Eq)]
enum Fail {
    Status(Status),
    Kernel(abi::Error),
    Bad(&'static str),
}

/// One request, and the status of its reply with the reply's handles.
fn call(session: &Handle<Channel>, request: &[u8]) -> Result<(Status, sys::Reply), Fail> {
    let reply = sys::send(session, request).map_err(Fail::Kernel)?;
    let mut buffer = [0; MESSAGE_MAX];
    let bytes = reply.bytes(&mut buffer);
    let word = bytes.get(..4).ok_or(Fail::Bad("a short reply"))?;
    let status = Status::from_code(u32::from_le_bytes([word[0], word[1], word[2], word[3]]));
    Ok((status, reply))
}

/// A request of the header alone; Ok for status 0.
fn plain(session: &Handle<Channel>, method: Method) -> Result<(), Fail> {
    match call(session, &method.header().bytes())? {
        (Status::Ok, _) => Ok(()),
        (status, _) => Err(Fail::Status(status)),
    }
}

/// GRANT: the new session of focus.
fn grant(session: &Handle<Channel>) -> Result<Handle<Channel>, Fail> {
    let (status, mut reply) = call(session, &Method::Grant.header().bytes())?;
    if status != Status::Ok {
        return Err(Fail::Status(status));
    }
    if reply.handles.len() != 1 {
        return Err(Fail::Bad("GRANT's handle count"));
    }
    reply
        .handles
        .take::<Channel>(0)
        .map_err(|_| Fail::Bad("GRANT's handle"))
}

/// The events one READ gave, and its flags.
struct Got {
    events: [Event; MAX_READ as usize],
    count: usize,
    flags: u32,
}

/// READ of up to `max` events through the focus session, or whatever the
/// service said instead (`max` is sent as it is).
fn read(session: &Handle<Channel>, max: u32) -> Result<Got, Fail> {
    let mut w = Writer::new();
    Method::Read.header().write(&mut w).map_err(Fail::Status)?;
    w.u32(max).map_err(Fail::Status)?;
    let (_, reply) = call(session, w.as_bytes())?;
    let mut buffer = [0; MESSAGE_MAX];
    let bytes = reply.bytes(&mut buffer);
    let mut got = Got {
        events: [Event::default(); MAX_READ as usize],
        count: 0,
        flags: 0,
    };
    let flags = read_events(bytes, |e| {
        if let Some(slot) = got.events.get_mut(got.count) {
            *slot = e;
        }
        got.count += 1;
    })
    .map_err(Fail::Status)?;
    got.flags = flags;
    if got.count > max as usize {
        return Err(Fail::Bad("more events than asked"));
    }
    Ok(got)
}

/// CLOSE of the screen through the owner's session.
fn plain_gpu(owner: &Handle<Channel>) -> Result<(), Fail> {
    match call(owner, &GpuMethod::Close.header().bytes())? {
        (Status::Ok, _) => Ok(()),
        (status, _) => Err(Fail::Status(status)),
    }
}

impl Got {
    fn events(&self) -> &[Event] {
        &self.events[..self.count]
    }
}

impl Probe<'_> {
    fn sleep(&self, ns: u64) {
        if ns == 0 {
            return;
        }
        let deadline = time::ticks_to_ns(time::now()).saturating_add(ns);
        while let Ok(rt::wait::Waited::Got(_)) = self.waiter.receive_until(&self.channel, deadline)
        {
        }
    }

    fn input(&self) -> Result<Handle<Channel>, &'static str> {
        rt::service::connect(self.parent, "input").map_err(|_| "connect to input")
    }

    fn stranger(self) -> Result<(), &'static str> {
        match rt::service::connect(self.parent, "input") {
            Err(Status::Kernel(abi::Error::AccessDenied)) => {}
            _ => return Err("a program with no connection to input got a session"),
        }
        rt::println!("input-probe: a program init gave no session is refused");
        Ok(())
    }

    /// The run under -icount: the focus, the keys, polling until `z`.
    fn quick(self) -> Result<(), &'static str> {
        let display = self.input()?;
        let focus = grant(&display).map_err(|_| "GRANT")?;
        rt::println!("input-probe: send keys");
        let end = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
        'wait: loop {
            let got = read(&focus, MAX_READ).map_err(|_| "READ")?;
            if got
                .events()
                .iter()
                .any(|e| e.code == KEY_Z && e.value == proto_input::PRESS)
            {
                break 'wait;
            }
            if time::ticks_to_ns(time::now()) > end {
                return Err("the key z never came");
            }
            self.sleep(POLL_NS);
        }
        plain(&display, Method::Revoke).map_err(|_| "REVOKE")?;
        Ok(())
    }

    fn grantor(self) -> Result<(), &'static str> {
        let display = self.input()?;
        // 1. A key with no focus is dropped.
        rt::println!("input-probe: send b");
        self.sleep(KEY_NS);
        let first = grant(&display).map_err(|_| "GRANT")?;
        let got = read(&first, MAX_READ).map_err(|_| "READ after GRANT")?;
        if got.count != 0 || got.flags != 0 {
            return Err("the key pressed before GRANT came");
        }
        rt::println!("input-probe: a key with no focus is dropped");
        // 2. The codes of one key.
        rt::println!("input-probe: send a");
        self.sleep(KEY_NS);
        let got = read(&first, MAX_READ).map_err(|_| "READ")?;
        let (press, release) = (Event::key(KEY_A, true), Event::key(KEY_A, false));
        if got.events() != [press, release] || got.flags != 0 {
            return Err("the key a did not come as a press and a release");
        }
        rt::println!(
            "input-probe: key {} {} {}",
            press.kind,
            press.code,
            press.value
        );
        rt::println!(
            "input-probe: key {} {} {}",
            release.kind,
            release.code,
            release.value
        );
        // 3. A burst nobody reads: 64 events and LOST, once.
        rt::println!("input-probe: send burst");
        self.sleep(BURST_NS);
        let got = read(&first, MAX_READ).map_err(|_| "READ after the burst")?;
        if got.count != RING || got.flags != LOST {
            rt::println!(
                "input-probe: burst gave {} events, flags {}",
                got.count,
                got.flags
            );
            return Err("the burst did not leave 64 events and LOST");
        }
        let alternate = got
            .events()
            .iter()
            .enumerate()
            .all(|(i, e)| e.kind == 1 && e.code == KEY_A && (e.value == 1) == (i % 2 == 0));
        if !alternate {
            return Err("the events of the burst are not a's presses and releases in order");
        }
        let again = read(&first, MAX_READ).map_err(|_| "READ after LOST")?;
        if again.count != 0 || again.flags != 0 {
            return Err("LOST came twice");
        }
        rt::println!("input-probe: a burst leaves 64 events and LOST once");
        // 4. A second GRANT takes the focus from the first.
        let second = grant(&display).map_err(|_| "second GRANT")?;
        if read(&first, 1).err() != Some(Fail::Status(code(REVOKED))) {
            return Err("the first focus was not revoked by the second GRANT");
        }
        rt::println!("input-probe: send c");
        self.sleep(KEY_NS);
        let got = read(&second, MAX_READ).map_err(|_| "READ of the second focus")?;
        if got.events() != [Event::key(KEY_C, true), Event::key(KEY_C, false)] {
            return Err("the key c did not reach the second focus");
        }
        if read(&first, 1).err() != Some(Fail::Status(code(REVOKED))) {
            return Err("the first focus reads again");
        }
        rt::println!("input-probe: the focus goes to the last GRANT, the first is REVOKED");
        // 5. Who may call what; READ takes 1 to 120.
        let not_allowed = Some(Fail::Status(code(NOT_ALLOWED)));
        if plain(&second, Method::Grant).err() != not_allowed
            || plain(&second, Method::Revoke).err() != not_allowed
            || read(&display, 1).err() != not_allowed
        {
            return Err("a method of the other kind of session was not refused");
        }
        if read(&second, 0).err() != Some(Fail::Status(code(INVALID)))
            || read(&second, MAX_READ + 1).err() != Some(Fail::Status(code(INVALID)))
        {
            return Err("READ took a count outside 1 to 120");
        }
        let (_, short) = call(&second, &Method::Read.header().bytes()).map_err(|_| "READ call")?;
        let mut buffer = [0; MESSAGE_MAX];
        if short.bytes(&mut buffer).len() != 8 {
            return Err("READ without a count was not refused by its status alone");
        }
        rt::println!("input-probe: a session calls its own methods only");
        // 6. REVOKE: the keys go nowhere and the focus reads no more.
        plain(&display, Method::Revoke).map_err(|_| "REVOKE")?;
        rt::println!("input-probe: send d");
        self.sleep(KEY_NS);
        if read(&second, 1).err() != Some(Fail::Status(code(REVOKED))) {
            return Err("the revoked focus was not REVOKED");
        }
        let third = grant(&display).map_err(|_| "GRANT after REVOKE")?;
        let got = read(&third, MAX_READ).map_err(|_| "READ of the new focus")?;
        if got.count != 0 || got.flags != 0 {
            return Err("a key pressed after REVOKE came to the next focus");
        }
        rt::println!("input-probe: after REVOKE a key goes nowhere and the focus is REVOKED");
        self.owner(&third)
    }

    /// OPEN until the service stops saying CLEARING: the screen's owner and
    /// its session of focus (status 0 and three handles).
    fn open(
        &self,
        gpu: &Handle<Channel>,
    ) -> Result<(Handle<Channel>, Handle<Channel>), &'static str> {
        let end = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
        loop {
            let (status, mut reply) =
                call(gpu, &GpuMethod::Open.header().bytes()).map_err(|_| "OPEN of the screen")?;
            if status == code(CLEARING) {
                if time::ticks_to_ns(time::now()) > end {
                    return Err("CLEARING for good");
                }
                self.sleep(5_000_000);
                continue;
            }
            let mut buffer = [0; MESSAGE_MAX];
            match Screen::read(reply.bytes(&mut buffer)) {
                Ok((Status::Ok, _)) => {}
                _ => return Err("OPEN gave no session of focus"),
            }
            if reply.handles.len() != 3 {
                return Err("OPEN's handle count");
            }
            let owner = reply
                .handles
                .take::<Channel>(1)
                .map_err(|_| "OPEN's owner")?;
            let focus = reply
                .handles
                .take::<Channel>(2)
                .map_err(|_| "OPEN's focus")?;
            return Ok((owner, focus));
        }
    }

    /// Twenty owners in turn, each keeping every focus it had: the old
    /// foci read REVOKED and do not fill the service's table, so the next
    /// owner's READ still passes.
    fn many_owners(&self, gpu: &Handle<Channel>) -> Result<(), &'static str> {
        const OWNERS: usize = 20;
        let mut kept: [Option<Handle<Channel>>; OWNERS] = [const { None }; OWNERS];
        for i in 0..OWNERS {
            let (screen, focus) = self.open(gpu)?;
            plain_gpu(&screen).map_err(|_| "CLOSE of the screen")?;
            kept[i] = Some(focus);
            for old in kept[..=i].iter().flatten() {
                if read(old, 1).err() != Some(Fail::Status(code(REVOKED))) {
                    return Err("an old focus was not REVOKED");
                }
            }
        }
        let (_screen, last) = self.open(gpu)?;
        read(&last, 1).map_err(|_| "READ of the next owner after many foci")?;
        rt::println!("input-probe: 20 owners in turn keep their foci, the next owner reads");
        Ok(())
    }

    /// The display service's part: the focus follows the owner of the
    /// screen. `stale` is a focus of the grantor's own, revoked by the
    /// screen's first OPEN.
    fn owner(&self, stale: &Handle<Channel>) -> Result<(), &'static str> {
        let gpu = rt::service::connect(self.parent, "gpu").map_err(|_| "connect to gpu")?;
        let (screen, focus) = self.open(&gpu)?;
        if read(stale, 1).err() != Some(Fail::Status(code(REVOKED))) {
            return Err("OPEN of the screen did not revoke the earlier focus");
        }
        rt::println!("input-probe: OPEN gave the owner a session of focus");
        rt::println!("input-probe: send a2");
        self.sleep(KEY_NS);
        let got = read(&focus, MAX_READ).map_err(|_| "READ of the owner's focus")?;
        if got.events() != [Event::key(KEY_A, true), Event::key(KEY_A, false)] {
            return Err("the key did not reach the owner of the screen");
        }
        rt::println!("input-probe: the key reaches the owner of the screen");
        // The screen goes back: the focus goes with it.
        plain_gpu(&screen).map_err(|_| "CLOSE of the screen")?;
        if read(&focus, 1).err() != Some(Fail::Status(code(REVOKED))) {
            return Err("the focus outlived the screen's owner");
        }
        rt::println!("input-probe: send b2");
        self.sleep(KEY_NS);
        let (screen, again) = self.open(&gpu)?;
        let got = read(&again, MAX_READ).map_err(|_| "READ of the next owner's focus")?;
        if got.count != 0 {
            return Err("a key pressed with no owner came to the next one");
        }
        rt::println!("input-probe: send c2");
        self.sleep(KEY_NS);
        let got = read(&again, MAX_READ).map_err(|_| "READ of the next owner")?;
        if got.events() != [Event::key(KEY_C, true), Event::key(KEY_C, false)] {
            return Err("the key did not reach the next owner of the screen");
        }
        if read(&focus, 1).err() != Some(Fail::Status(code(REVOKED))) {
            return Err("the first owner's focus reads again");
        }
        rt::println!("input-probe: with no owner a key goes nowhere, the next owner has the focus");
        drop(screen);
        self.many_owners(&gpu)?;
        // The display service ends: the focus of its last owner ends with
        // it. Its CRASH is never answered; init starts it again.
        let (screen, focus) = self.open(&gpu)?;
        if sys::send(&gpu, &proto_gpu::Method::Crash.header().bytes()).is_ok() {
            return Err("CRASH of the display service was answered");
        }
        let mut revoked = false;
        for _ in 0..50 {
            if read(&focus, 1).err() == Some(Fail::Status(code(REVOKED))) {
                revoked = true;
                break;
            }
            self.sleep(10_000_000);
        }
        if !revoked {
            return Err("the focus outlived the display service");
        }
        rt::println!("input-probe: the end of the display service revokes the focus");
        drop(screen);
        Ok(())
    }
}
