// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Version 1 of the protocol of the terminal service (5f; spec 2, 2, 3.4
//! and 3.8; XBD chapter 11). The service keeps the terminals: the console
//! (terminal CONSOLE) over the console's driver, its line discipline, its
//! settings (`Termios`, the layout of relibc's struct termios less its
//! line byte) and the reads and writes that wait. A request names its
//! terminal; this version serves the console alone. Every number goes
//! low byte first.
//!
//! - READ_START: body the terminal u32, the count u32 (1 to MAX_READ). A
//!   long operation in two steps (proto_wire::long): READY with at most
//!   the count of bytes, as the discipline gives them (in canonical mode
//!   one line at most, none at an end-of-file), or WAIT k. READ_TAKE: body
//!   k u64, then the body of READ_START again (and, the first time, a
//!   handle with NOTIFY labelled k). READ_CANCEL: body k u64, the
//!   terminal u32: CANCELLED, and no byte is taken.
//! - WRITE_START: body the terminal u32, then 1 to MAX_WRITE bytes, which
//!   go through the output processing of the settings: READY with the
//!   count u32 taken, at least one; WAIT k while the terminal has no room
//!   for the first. WRITE_TAKE: body k u64, then the body of WRITE_START
//!   again; the service keeps no byte of a write that waits, so
//!   WRITE_CANCEL (body k u64, the terminal u32) has no effect.
//! - CLONE: no body. Reply: status and one handle, a new session (SEND,
//!   TRANSFER) of the service's own label for a child of the client (5c).
//! - GET_ATTR: body the terminal u32. Reply: status, `Termios`.
//! - SET_ATTR: body the terminal u32, the action u32 (NOW, DRAIN, FLUSH),
//!   `Termios`. FLUSH discards the input that was not read. Reply: status.
//! - ABANDON: no body: the session's long operations that wait go, as
//!   when the session goes (the threads of an old image at exec). Reply:
//!   status.
//! - DRAIN_START: body the terminal u32 (tcdrain). A long operation in two
//!   steps: READY with no bytes once the service has given the driver all
//!   the output of the terminal, or WAIT k while some is left (output
//!   that is stopped, FLOW, keeps it left). DRAIN_TAKE: body k u64, then
//!   the body of DRAIN_START again (and, the first time, a handle with
//!   NOTIFY labelled k). DRAIN_CANCEL: body k u64, the terminal u32:
//!   CANCELLED.
//! - FLUSH_QUEUES: body the terminal u32, the queue u32 (QUEUE_IN: the
//!   input not read, QUEUE_OUT: the output the driver did not take,
//!   QUEUE_BOTH). The writes and drains that wait look again. Reply:
//!   status.
//! - FLOW: body the terminal u32, the action u32 (FLOW_OUT_OFF stops the
//!   terminal's output, FLOW_OUT_ON lets it go on, FLOW_IN_OFF and
//!   FLOW_IN_ON put the STOP and the START character in the output).
//!   Reply: status. With an enabled STOP or START character and a full
//!   output ring, LIMIT_REACHED (EAGAIN) has no effect; the caller can retry
//!   after room becomes available.
//!
//! The controlling terminal (XBD 11.1.3; 5f, T3). Each request below has
//! the body the terminal u32 (and a word where named) and brings a copy of
//! the caller's identity session (proto_process; NOTIFY, TRANSFER), which
//! the service has the process service vouch for once and again when the
//! record's generation moves; it reads the caller's group and session
//! from the page of the generations. NO_IDENTITY without one it can use.
//! - ACQUIRE (TIOCSCTTY, an open without O_NOCTTY): the terminal becomes
//!   the controlling terminal of the caller's session, the caller's group
//!   its foreground group; PERMISSION when the caller leads no session or
//!   the terminal or the session is taken. Reply: status.
//! - SET_PGRP (tcsetpgrp): the word, a group of the terminal's session,
//!   becomes the foreground group; NOT_CONTROLLING when the terminal is no
//!   controlling terminal of the caller's session, PERMISSION for a group
//!   of no member in that session, INVALID for 0 or a negative number.
//!   Reply: status.
//! - GET_PGRP (tcgetpgrp), GET_SID (tcgetsid): reply status and the
//!   foreground group u32 (i32::MAX with none), or the session u32;
//!   NOT_CONTROLLING as for SET_PGRP.
//! - CONTROLLING (an open of /dev/tty): status 0 when the terminal is the
//!   controlling terminal of the caller's session; NOT_CONTROLLING
//!   otherwise.
//!
//! BAD_TERMINAL for a terminal the service does not have, INVALID for an
//! action past FLUSH, a queue past QUEUE_BOTH or an action past
//! FLOW_IN_ON. A start past the WAITERS operations that wait on a
//! terminal, or past the long operations of a session or of the service,
//! gets LIMIT_REACHED (EAGAIN).

#![cfg_attr(not(test), no_std)]

use abi::MESSAGE_MAX;
use proto_wire::{HEADER_LEN, Header, Reader, Status, Writer};

pub const VERSION: u16 = 1;

/// The terminal of the console.
pub const CONSOLE: u32 = 0;

/// The most bytes one read asks for: a reply of status, READY and bytes.
pub const MAX_READ: usize = MESSAGE_MAX - 8;
/// The most bytes one write carries: WRITE_TAKE's header, key and
/// terminal come before them.
pub const MAX_WRITE: usize = MESSAGE_MAX - HEADER_LEN - 12;
/// {MAX_CANON}: the bytes of one line of canonical input, its delimiter
/// among them (relibc's value).
pub const MAX_CANON: usize = 255;
/// {MAX_INPUT}: the bytes of input a terminal keeps that were not read.
pub const MAX_INPUT: usize = 1024;
/// The reads, writes and drains that wait on one terminal together at most.
pub const WAITERS: usize = 8;

/// ENOTTY: no such terminal.
pub const BAD_TERMINAL: u32 = 801;
/// EINVAL.
pub const INVALID: u32 = 803;
/// EPERM.
pub const PERMISSION: u32 = 804;
/// ENOTTY for the requests of the controlling terminal (ENXIO for an open
/// of /dev/tty).
pub const NOT_CONTROLLING: u32 = 805;
/// No identity the service could vouch for came with the request.
pub const NO_IDENTITY: u32 = 806;
/// What GET_PGRP gives with no foreground group: a number no group has.
pub const NO_FOREGROUND: u32 = i32::MAX as u32;

/// The labels the service gives itself: bit 63, which no label of init
/// has.
pub const OWN: u64 = 1 << 63;

/// SET_ATTR's actions (TCSANOW, TCSADRAIN, TCSAFLUSH).
pub const NOW: u32 = 0;
pub const DRAIN: u32 = 1;
pub const FLUSH: u32 = 2;

/// FLUSH_QUEUES' queues (TCIFLUSH, TCOFLUSH, TCIOFLUSH).
pub const QUEUE_IN: u32 = 0;
pub const QUEUE_OUT: u32 = 1;
pub const QUEUE_BOTH: u32 = 2;

/// FLOW's actions (TCOOFF, TCOON, TCIOFF, TCION).
pub const FLOW_OUT_OFF: u32 = 0;
pub const FLOW_OUT_ON: u32 = 1;
pub const FLOW_IN_OFF: u32 = 2;
pub const FLOW_IN_ON: u32 = 3;

/// The control characters of `Termios::cc` (relibc's Linux values).
pub const NCCS: usize = 32;
pub const VINTR: usize = 0;
pub const VQUIT: usize = 1;
pub const VERASE: usize = 2;
pub const VKILL: usize = 3;
pub const VEOF: usize = 4;
pub const VTIME: usize = 5;
pub const VMIN: usize = 6;
pub const VSTART: usize = 8;
pub const VSTOP: usize = 9;
pub const VSUSP: usize = 10;
pub const VEOL: usize = 11;
pub const VWERASE: usize = 14;
/// _POSIX_VDISABLE: a control character of this value is off.
pub const DISABLED: u8 = 0;

/// The input modes (c_iflag) the discipline acts on.
pub const ISTRIP: u32 = 0o40;
pub const INLCR: u32 = 0o100;
pub const IGNCR: u32 = 0o200;
pub const ICRNL: u32 = 0o400;
/// The output modes (c_oflag) the discipline acts on.
pub const OPOST: u32 = 0o1;
pub const ONLCR: u32 = 0o4;
pub const OCRNL: u32 = 0o10;
/// The local modes (c_lflag).
pub const ISIG: u32 = 0o1;
pub const ICANON: u32 = 0o2;
pub const ECHO: u32 = 0o10;
pub const ECHOE: u32 = 0o20;
pub const ECHOK: u32 = 0o40;
pub const ECHONL: u32 = 0o100;
pub const NOFLSH: u32 = 0o200;
pub const TOSTOP: u32 = 0o400;
pub const ECHOCTL: u32 = 0o1000;
pub const ECHOKE: u32 = 0o4000;
pub const IEXTEN: u32 = 0o100000;
/// The control modes and the speed of a terminal opened afresh: 8 bits,
/// the receiver on, 38400 baud (which the PL011 of QEMU ignores).
pub const CS8_CREAD_B38400: u32 = 0o277;
pub const B38400: u32 = 0o17;

/// The bytes of `Termios` on the wire.
pub const TERMIOS_LEN: usize = 16 + NCCS + 8;

/// The settings of a terminal (XBD 11.2): relibc's struct termios less
/// its line byte, which no POSIX interface names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Termios {
    pub iflag: u32,
    pub oflag: u32,
    pub cflag: u32,
    pub lflag: u32,
    pub cc: [u8; NCCS],
    pub ispeed: u32,
    pub ospeed: u32,
}

impl Default for Termios {
    fn default() -> Termios {
        Termios::opened()
    }
}

impl Termios {
    /// A terminal as it opens: CR to NL in, NL to CR NL out, canonical
    /// input with echo, the visual erase of ECHOE and ECHOKE, control
    /// characters echoed as ^X, and signals; the control characters of
    /// Linux, EOL off.
    pub const fn opened() -> Termios {
        let mut cc = [DISABLED; NCCS];
        cc[VINTR] = 0x03;
        cc[VQUIT] = 0x1c;
        cc[VERASE] = 0x7f;
        cc[VKILL] = 0x15;
        cc[VEOF] = 0x04;
        cc[VTIME] = 0;
        cc[VMIN] = 1;
        cc[VSTART] = 0x11;
        cc[VSTOP] = 0x13;
        cc[VSUSP] = 0x1a;
        cc[VWERASE] = 0x17;
        Termios {
            iflag: ICRNL,
            oflag: OPOST | ONLCR,
            cflag: CS8_CREAD_B38400,
            lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN,
            cc,
            ispeed: B38400,
            ospeed: B38400,
        }
    }

    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        for word in [self.iflag, self.oflag, self.cflag, self.lflag] {
            w.u32(word)?;
        }
        w.bytes(&self.cc)?;
        w.u32(self.ispeed)?;
        w.u32(self.ospeed)
    }

    pub fn read(r: &mut Reader<'_>) -> Result<Termios, Status> {
        let (iflag, oflag, cflag, lflag) = (r.u32()?, r.u32()?, r.u32()?, r.u32()?);
        let mut cc = [0; NCCS];
        cc.copy_from_slice(r.bytes(NCCS)?);
        Ok(Termios {
            iflag,
            oflag,
            cflag,
            lflag,
            cc,
            ispeed: r.u32()?,
            ospeed: r.u32()?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    ReadStart = 1,
    ReadTake = 2,
    ReadCancel = 3,
    WriteStart = 4,
    WriteTake = 5,
    WriteCancel = 6,
    Clone = 7,
    GetAttr = 8,
    SetAttr = 9,
    Abandon = 10,
    DrainStart = 11,
    DrainTake = 12,
    DrainCancel = 13,
    FlushQueues = 14,
    Flow = 15,
    Acquire = 16,
    SetPgrp = 17,
    GetPgrp = 18,
    GetSid = 19,
    Controlling = 20,
    VerifySession = 24,
}

impl Method {
    pub const ALL: [Method; 21] = [
        Method::ReadStart,
        Method::ReadTake,
        Method::ReadCancel,
        Method::WriteStart,
        Method::WriteTake,
        Method::WriteCancel,
        Method::Clone,
        Method::GetAttr,
        Method::SetAttr,
        Method::Abandon,
        Method::DrainStart,
        Method::DrainTake,
        Method::DrainCancel,
        Method::FlushQueues,
        Method::Flow,
        Method::Acquire,
        Method::SetPgrp,
        Method::GetPgrp,
        Method::GetSid,
        Method::Controlling,
        Method::VerifySession,
    ];

    pub const fn number(self) -> u16 {
        self as u16
    }

    pub fn from_number(number: u16) -> Option<Method> {
        Method::ALL.into_iter().find(|m| m.number() == number)
    }

    pub const fn header(self) -> Header {
        Header::new(self.number(), VERSION)
    }
}

pub const METHODS: &[u16] = &[
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 24,
];

/// A request of the controlling terminal (ACQUIRE, SET_PGRP, GET_PGRP,
/// GET_SID, CONTROLLING): its header, the terminal and, for SET_PGRP, the
/// group; the caller sends the copy of its identity with it.
pub fn job(
    method: Method,
    terminal: u32,
    group: Option<u32>,
    w: &mut Writer,
) -> Result<(), Status> {
    if !matches!(
        method,
        Method::Acquire | Method::SetPgrp | Method::GetPgrp | Method::GetSid | Method::Controlling
    ) || (method == Method::SetPgrp) != group.is_some()
    {
        return Err(Status::BadSize);
    }
    method.header().write(w)?;
    w.u32(terminal)?;
    match group {
        Some(g) => w.u32(g),
        None => Ok(()),
    }
}

/// READ_START or READ_TAKE: the key of a take, the terminal and the count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Read {
    pub key: Option<u64>,
    pub terminal: u32,
    pub count: u32,
}

impl Read {
    fn valid(&self) -> bool {
        self.count != 0 && self.count as usize <= MAX_READ && self.key != Some(0)
    }

    /// READ_START without a key, READ_TAKE with one: BAD_SIZE for a count
    /// of 0 or past MAX_READ, or a key of 0.
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        if !self.valid() {
            return Err(Status::BadSize);
        }
        match self.key {
            None => Method::ReadStart.header().write(w)?,
            Some(key) => {
                Method::ReadTake.header().write(w)?;
                w.u64(key)?;
            }
        }
        w.u32(self.terminal)?;
        w.u32(self.count)
    }

    /// The body of READ_START (`take` false) or READ_TAKE.
    pub fn parse(mut body: Reader<'_>, take: bool) -> Result<Read, Status> {
        let key = if take { Some(body.u64()?) } else { None };
        let (terminal, count) = (body.u32()?, body.u32()?);
        body.finish()?;
        let read = Read {
            key,
            terminal,
            count,
        };
        if !read.valid() {
            return Err(Status::BadSize);
        }
        Ok(read)
    }
}

/// WRITE_START or WRITE_TAKE: the key of a take, the terminal and the
/// bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Write<'a> {
    pub key: Option<u64>,
    pub terminal: u32,
    pub bytes: &'a [u8],
}

impl<'a> Write<'a> {
    fn valid(len: usize, key: Option<u64>) -> bool {
        len != 0 && len <= MAX_WRITE && key != Some(0)
    }

    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        if !Write::valid(self.bytes.len(), self.key) {
            return Err(Status::BadSize);
        }
        match self.key {
            None => Method::WriteStart.header().write(w)?,
            Some(key) => {
                Method::WriteTake.header().write(w)?;
                w.u64(key)?;
            }
        }
        w.u32(self.terminal)?;
        w.bytes(self.bytes)
    }

    pub fn parse(mut body: Reader<'a>, take: bool) -> Result<Write<'a>, Status> {
        let key = if take { Some(body.u64()?) } else { None };
        let terminal = body.u32()?;
        let len = body.left();
        if !Write::valid(len, key) {
            return Err(Status::BadSize);
        }
        let bytes = body.bytes(len)?;
        body.finish()?;
        Ok(Write {
            key,
            terminal,
            bytes,
        })
    }
}

/// READ_CANCEL, WRITE_CANCEL or DRAIN_CANCEL: the key and the terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cancel {
    pub key: u64,
    pub terminal: u32,
}

impl Cancel {
    pub fn write(&self, method: Method, w: &mut Writer) -> Result<(), Status> {
        if self.key == 0
            || !matches!(
                method,
                Method::ReadCancel | Method::WriteCancel | Method::DrainCancel
            )
        {
            return Err(Status::BadSize);
        }
        method.header().write(w)?;
        w.u64(self.key)?;
        w.u32(self.terminal)
    }

    pub fn parse(mut body: Reader<'_>) -> Result<Cancel, Status> {
        let (key, terminal) = (body.u64()?, body.u32()?);
        body.finish()?;
        if key == 0 {
            return Err(Status::BadSize);
        }
        Ok(Cancel { key, terminal })
    }
}

/// DRAIN_START or DRAIN_TAKE: the key of a take and the terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Drain {
    pub key: Option<u64>,
    pub terminal: u32,
}

impl Drain {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        match self.key {
            None => Method::DrainStart.header().write(w)?,
            Some(0) => return Err(Status::BadSize),
            Some(key) => {
                Method::DrainTake.header().write(w)?;
                w.u64(key)?;
            }
        }
        w.u32(self.terminal)
    }

    /// The body of DRAIN_START (`take` false) or DRAIN_TAKE: BAD_SIZE for
    /// a key of 0.
    pub fn parse(mut body: Reader<'_>, take: bool) -> Result<Drain, Status> {
        let key = if take { Some(body.u64()?) } else { None };
        let terminal = body.u32()?;
        body.finish()?;
        if key == Some(0) {
            return Err(Status::BadSize);
        }
        Ok(Drain { key, terminal })
    }
}

/// FLUSH_QUEUES (`Method::FlushQueues`) or FLOW (`Method::Flow`): the
/// terminal and one word, the queue or the action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Control {
    pub terminal: u32,
    pub word: u32,
}

impl Control {
    pub fn write(&self, method: Method, w: &mut Writer) -> Result<(), Status> {
        if !matches!(method, Method::FlushQueues | Method::Flow) {
            return Err(Status::BadSize);
        }
        method.header().write(w)?;
        w.u32(self.terminal)?;
        w.u32(self.word)
    }

    pub fn parse(mut body: Reader<'_>) -> Result<Control, Status> {
        let (terminal, word) = (body.u32()?, body.u32()?);
        body.finish()?;
        Ok(Control { terminal, word })
    }
}

/// SET_ATTR: the terminal, the action and the settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetAttr {
    pub terminal: u32,
    pub action: u32,
    pub termios: Termios,
}

impl SetAttr {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        Method::SetAttr.header().write(w)?;
        w.u32(self.terminal)?;
        w.u32(self.action)?;
        self.termios.write(w)
    }

    pub fn parse(mut body: Reader<'_>) -> Result<SetAttr, Status> {
        let (terminal, action) = (body.u32()?, body.u32()?);
        let termios = Termios::read(&mut body)?;
        body.finish()?;
        Ok(SetAttr {
            terminal,
            action,
            termios,
        })
    }
}

/// GET_ATTR of `terminal`.
pub fn get_attr(terminal: u32, w: &mut Writer) -> Result<(), Status> {
    Method::GetAttr.header().write(w)?;
    w.u32(terminal)
}

/// The settings in a reply to GET_ATTR: the status when it is a refusal.
pub fn attr_reply(bytes: &[u8]) -> Result<Termios, Status> {
    let mut r = Reader::new(bytes);
    match Status::from_code(r.u32()?) {
        Status::Ok => {}
        status => return Err(status),
    }
    let termios = Termios::read(&mut r)?;
    r.finish()?;
    Ok(termios)
}

/// The result of a READY write: the count taken.
pub fn written(result: &[u8]) -> Result<u32, Status> {
    let mut r = Reader::new(result);
    let count = r.u32()?;
    r.finish()?;
    Ok(count)
}

/// The numbers of the interface are Linux's (relibc's termios.h and
/// sys/ioctl.h, whose const assertions hold the same on its side).
const _: () = {
    assert!(NCCS == 32 && TERMIOS_LEN == 56);
    assert!(VINTR == 0 && VQUIT == 1 && VERASE == 2 && VKILL == 3 && VEOF == 4);
    assert!(VTIME == 5 && VMIN == 6 && VSTART == 8 && VSTOP == 9);
    assert!(VSUSP == 10 && VEOL == 11 && VWERASE == 14);
    assert!(ISTRIP == 0o40 && INLCR == 0o100 && IGNCR == 0o200 && ICRNL == 0o400);
    assert!(OPOST == 1 && ONLCR == 4 && OCRNL == 0o10);
    assert!(ISIG == 1 && ICANON == 2 && ECHO == 0o10 && ECHOE == 0o20);
    assert!(ECHOK == 0o40 && ECHONL == 0o100 && NOFLSH == 0o200 && TOSTOP == 0o400);
    assert!(ECHOCTL == 0o1000 && ECHOKE == 0o4000 && IEXTEN == 0o100000);
    assert!(B38400 == 0o17 && CS8_CREAD_B38400 == 0o277);
    assert!(NOW == 0 && DRAIN == 1 && FLUSH == 2);
    assert!(QUEUE_IN == 0 && QUEUE_OUT == 1 && QUEUE_BOTH == 2);
    assert!(FLOW_OUT_OFF == 0 && FLOW_OUT_ON == 1 && FLOW_IN_OFF == 2 && FLOW_IN_ON == 3);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_numbers_are_fixed_and_listed() {
        for number in 0..=25u16 {
            let method = Method::from_number(number);
            assert_eq!(method.is_some(), METHODS.contains(&number), "{number}");
            if let Some(m) = method {
                assert_eq!(m.number(), number);
                assert_eq!(m.header(), Header::new(number, VERSION));
            }
        }
        assert_eq!(METHODS.len(), Method::ALL.len());
    }

    #[test]
    fn sizes_fit_a_message() {
        assert_eq!((MAX_READ, MAX_WRITE), (1016, 1004));
        assert_eq!(TERMIOS_LEN, 56);
        const { assert!(MAX_CANON < MAX_INPUT) };
        // SET_ATTR's request fits one message.
        let mut w = Writer::new();
        SetAttr {
            terminal: CONSOLE,
            action: FLUSH,
            termios: Termios::default(),
        }
        .write(&mut w)
        .unwrap();
        assert_eq!(w.as_bytes().len(), HEADER_LEN + 8 + TERMIOS_LEN);
    }

    /// The settings a terminal opens with are those relibc's layer gave
    /// the console before the service (posix-platform's TCGETS): Linux's
    /// values, word for word.
    #[test]
    fn a_terminal_opens_with_the_settings_of_linux() {
        let t = Termios::default();
        assert_eq!(
            (t.iflag, t.oflag, t.cflag, t.lflag),
            (0o400, 0o5, 0o277, 0o105_073)
        );
        assert_eq!(t.cc[..7], [3, 28, 127, 21, 4, 0, 1]);
        assert_eq!((t.cc[VSUSP], t.cc[VEOL], t.cc[VWERASE]), (26, 0, 23));
    }

    #[test]
    fn requests_round_trip() {
        for read in [
            Read {
                key: None,
                terminal: 0,
                count: 1,
            },
            Read {
                key: Some(0x1_0000_0002),
                terminal: 0,
                count: MAX_READ as u32,
            },
        ] {
            let mut w = Writer::new();
            read.write(&mut w).unwrap();
            let body = Reader::new(&w.as_bytes()[HEADER_LEN..]);
            assert_eq!(Read::parse(body, read.key.is_some()), Ok(read));
        }
        for count in [0, MAX_READ as u32 + 1] {
            let read = Read {
                key: None,
                terminal: 0,
                count,
            };
            assert_eq!(read.write(&mut Writer::new()), Err(Status::BadSize));
        }
        let bytes = [b'x'; MAX_WRITE];
        for write in [
            Write {
                key: None,
                terminal: 0,
                bytes: b"a",
            },
            Write {
                key: Some(7),
                terminal: 0,
                bytes: &bytes,
            },
        ] {
            let mut w = Writer::new();
            write.write(&mut w).unwrap();
            assert!(w.as_bytes().len() <= MESSAGE_MAX);
            let body = Reader::new(&w.as_bytes()[HEADER_LEN..]);
            assert_eq!(Write::parse(body, write.key.is_some()), Ok(write));
        }
        let long = [b'x'; MAX_WRITE + 1];
        for bad in [&b""[..], &long] {
            let write = Write {
                key: None,
                terminal: 0,
                bytes: bad,
            };
            assert_eq!(write.write(&mut Writer::new()), Err(Status::BadSize));
        }
        let cancel = Cancel {
            key: 9,
            terminal: 0,
        };
        let mut w = Writer::new();
        cancel.write(Method::ReadCancel, &mut w).unwrap();
        assert_eq!(
            Cancel::parse(Reader::new(&w.as_bytes()[HEADER_LEN..])),
            Ok(cancel)
        );
        assert_eq!(
            cancel.write(Method::Clone, &mut Writer::new()),
            Err(Status::BadSize)
        );
        let mut t = Termios::default();
        t.lflag &= !ICANON;
        t.cc[VMIN] = 3;
        let set = SetAttr {
            terminal: 0,
            action: DRAIN,
            termios: t,
        };
        let mut w = Writer::new();
        set.write(&mut w).unwrap();
        assert_eq!(
            SetAttr::parse(Reader::new(&w.as_bytes()[HEADER_LEN..])),
            Ok(set)
        );
        let mut w = Writer::new();
        w.u32(0).unwrap();
        t.write(&mut w).unwrap();
        assert_eq!(attr_reply(w.as_bytes()), Ok(t));
        let refused = proto_wire::reply(Status::Unknown(BAD_TERMINAL));
        assert_eq!(attr_reply(&refused), Err(Status::Unknown(BAD_TERMINAL)));
        assert_eq!(written(&3u32.to_le_bytes()), Ok(3));
        for drain in [
            Drain {
                key: None,
                terminal: 0,
            },
            Drain {
                key: Some(5),
                terminal: 0,
            },
        ] {
            let mut w = Writer::new();
            drain.write(&mut w).unwrap();
            let body = Reader::new(&w.as_bytes()[HEADER_LEN..]);
            assert_eq!(Drain::parse(body, drain.key.is_some()), Ok(drain));
        }
        let zero = Drain {
            key: Some(0),
            terminal: 0,
        };
        assert_eq!(zero.write(&mut Writer::new()), Err(Status::BadSize));
        let cancel = Cancel {
            key: 4,
            terminal: 0,
        };
        let mut w = Writer::new();
        cancel.write(Method::DrainCancel, &mut w).unwrap();
        assert_eq!(
            Cancel::parse(Reader::new(&w.as_bytes()[HEADER_LEN..])),
            Ok(cancel)
        );
        let control = Control {
            terminal: 0,
            word: QUEUE_BOTH,
        };
        for method in [Method::FlushQueues, Method::Flow] {
            let mut w = Writer::new();
            control.write(method, &mut w).unwrap();
            assert_eq!(
                Control::parse(Reader::new(&w.as_bytes()[HEADER_LEN..])),
                Ok(control)
            );
        }
        assert_eq!(
            control.write(Method::GetAttr, &mut Writer::new()),
            Err(Status::BadSize)
        );
    }
}
