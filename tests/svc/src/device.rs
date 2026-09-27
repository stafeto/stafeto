// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The role `device` (main.rs): a service whose record has the window
//! `rtc` over the PL031 and the binding `rtc-irq` of its line. It sends
//! REGISTER four times: first with a copy of its channel that carries
//! RECEIVE, then with one that lacks DUPLICATE, which init refuses with
//! ACCESS_DENIED; then as a service does (rt::service::register); then
//! once more, which init refuses with BAD_STATE. It maps the window that
//! came readable and writable, reads the PL031's PeriphID0 and PeriphID1
//! through rt::mmio [G34], acknowledges its binding (irq_ack) and looks at
//! it (object_info IRQ), tries a copy of each, and gives what it saw on
//! REPORT (`Report`).

use crate::{FAILED, VERSION, base, method, serve};
use abi::{Access, CHANNEL_RIGHTS, MESSAGE_MAX, Rights};
use proto_init::Method;
use proto_wire::{Reader, Status, Writer};
use rt::handle::{Channel, Interrupt, Memory, Outgoing};
use rt::service::{Answer, Registered, Request, Service, Session};
use rt::startup::Startup;
use rt::{Handle, mmio, sys};

/// Where the device maps its window.
const WINDOW_AT: usize = 0x10_0000_0000;
/// The offsets of PeriphID0 and PeriphID1 in the PL031's page.
const PERIPH_ID: [usize; 2] = [0xFE0, 0xFE4];

/// Flags of a `Report`: the window came, the binding came, the binding is
/// edge-triggered, the window and the binding make copies (DUPLICATE).
pub const WINDOW: u32 = 1;
pub const BINDING: u32 = 2;
pub const EDGE: u32 = 4;
pub const WINDOW_COPIES: u32 = 8;
pub const BINDING_COPIES: u32 = 16;
/// The window mapped readable and writable, and the binding took irq_ack
/// (MANAGE).
pub const WINDOW_WRITES: u32 = 32;
pub const BINDING_ACKS: u32 = 64;

/// What the device saw, the reply to REPORT after its status and 4 zero
/// bytes: the status of each of its REGISTER requests in turn, PeriphID0
/// and PeriphID1 read through the window (0 without it), the line of its
/// binding (0 without it) and the flags.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub statuses: [u32; 4],
    pub ids: [u32; 2],
    pub line: u32,
    pub flags: u32,
}

impl Report {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(Status::Ok.code())?;
        w.u32(0)?;
        let words = self.statuses.iter().chain(&self.ids);
        for &word in words.chain([&self.line, &self.flags]) {
            w.u32(word)?;
        }
        Ok(())
    }

    /// The report in `bytes`, the whole reply: BAD_SIZE unless its status
    /// and the 4 bytes after it are 0 and the seven words follow.
    pub fn read(bytes: &[u8]) -> Result<Report, Status> {
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 || r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let mut words = [0; 8];
        for word in &mut words {
            *word = r.u32()?;
        }
        r.finish()?;
        Ok(Report {
            statuses: [words[0], words[1], words[2], words[3]],
            ids: [words[4], words[5]],
            line: words[6],
            flags: words[7],
        })
    }
}

pub fn run(s: Startup) -> u64 {
    let Ok(channel) = sys::channel_create(base(&s)) else {
        return FAILED;
    };
    let mut report = Report::default();
    report.statuses[0] = with_rights(&s.parent, &channel, CHANNEL_RIGHTS).code();
    let no_copies = Rights::SEND | Rights::NOTIFY | Rights::TRANSFER;
    report.statuses[1] = with_rights(&s.parent, &channel, no_copies).code();
    match rt::service::register(&s.parent, &channel) {
        Ok(mut got) => look(&s, &mut got, &mut report),
        Err(status) => report.statuses[2] = status.code(),
    }
    let again = rt::service::register(&s.parent, &channel).err();
    report.statuses[3] = again.unwrap_or(Status::Ok).code();
    serve(&s, &channel, &mut Device { report })
}

/// REGISTER with a copy of `channel` with `rights`: the status of init's
/// reply.
fn with_rights(parent: &Handle<Channel>, channel: &Handle<Channel>, rights: Rights) -> Status {
    let copy = match sys::handle_duplicate(channel, rights) {
        Ok(copy) => copy,
        Err(e) => return Status::Kernel(e),
    };
    let request = Method::Register.header().bytes();
    match sys::send_handles(parent, &request, [copy.erase()]) {
        Ok(reply) => {
            let mut buffer = [0; MESSAGE_MAX];
            let status = Reader::new(reply.bytes(&mut buffer)).u32();
            status.map_or(Status::BadSize, Status::from_code)
        }
        Err(refused) => Status::Kernel(refused.error),
    }
}

/// Takes the window and the binding REGISTER brought into `report`:
/// PeriphID through the window mapped readable and writable, irq_ack and
/// the line and trigger of the binding. The device holds both until it
/// ends.
fn look(s: &Startup, got: &mut Registered, report: &mut Report) {
    if let Ok(window) = got.take::<Memory>("rtc") {
        report.flags |= WINDOW;
        if sys::handle_duplicate(&window, Rights::MAP_READ).is_ok() {
            report.flags |= WINDOW_COPIES;
        }
        if sys::mem_map(&s.process, &window, 0, 4096, WINDOW_AT, Access::ReadWrite).is_ok() {
            report.flags |= WINDOW_WRITES;
            for (id, offset) in report.ids.iter_mut().zip(PERIPH_ID) {
                // SAFETY: the window maps the PL031's page at WINDOW_AT,
                // readable and writable, as device memory; the IDs are
                // 32-bit registers.
                *id = unsafe { mmio::read32(WINDOW_AT + offset) };
            }
        }
        window.into_raw();
    }
    if let Ok(binding) = got.take::<Interrupt>("rtc-irq") {
        report.flags |= BINDING;
        if sys::handle_duplicate(&binding, Rights::MANAGE).is_ok() {
            report.flags |= BINDING_COPIES;
        }
        if sys::irq_ack(&binding).is_ok() {
            report.flags |= BINDING_ACKS;
        }
        if let Ok(info) = sys::irq_info(&binding) {
            report.line = info.line as u32;
            if info.edge {
                report.flags |= EDGE;
            }
        }
        binding.into_raw();
    }
}

/// The device service and what it saw.
struct Device {
    report: Report,
}

impl Service<1> for Device {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = &[method::REPORT];
    type Data = ();

    fn request(&mut self, _: &mut Session<(), 1>, r: &mut Request<'_>) -> Answer {
        match self.report.write(r.reply()) {
            Ok(()) => Answer::Reply(Outgoing::new()),
            Err(status) => Answer::Status(status),
        }
    }
}
