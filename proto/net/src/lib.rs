// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The protocol of the network service (services/netd), proto_wire: the
//! numbers of its methods, which never change once given, its codes and the
//! bodies of its requests. Every number goes low byte first.
//!
//! The numbers of all the methods of the service are fixed here at once.
//! The first stage answers CONFIG, and PING and CRASH in a build with the
//! feature `probe`; the second answers the sockets' methods of TCP and UDP
//! over IPv4, with a loopback. A method of a later stage takes the next free
//! number between 36 and 61. All the numbers are below 64: the steps of the
//! service loop count the methods up to the notice at 64.
//!
//! A socket is a description, one u32 on the wire: the place in the
//! service's table (bits 0-11) and the generation of the place (bits 12-31,
//! never 0). A long operation (CONNECT, ACCEPT, SEND, RECV, WATCH) is in two
//! steps as `proto_wire::long` has it: the start answers READY with the
//! result, or WAIT k; `*_TAKE` repeats the operation by its key k and answers
//! READY, or ARMED. `[k]` below is that u64 key, in a `*_TAKE` alone.
//!
//! | Method | Request | Reply |
//! |---|---|---|
//! | SOCKET (1) | family (u32, INET), kind (u32, STREAM 1 or DGRAM 2), flags (u32, NONBLOCK 1) | status, description |
//! | BIND (2) | description, `Address`; a handle (a copy of the identity session) for a port below 1024 | status |
//! | LISTEN (3) | description, backlog (u32, held to 1..=16) | status |
//! | CONNECT (4), CONNECT_TAKE (5) | [k], description, `Address` | long: READY with no data |
//! | ACCEPT (6), ACCEPT_TAKE (7) | [k], description, flags (u32, NONBLOCK for the new one) | long: READY description, `Address` of the peer |
//! | SEND (8), SEND_TAKE (9) | [k], description, flags (u32, DONTWAIT 2), `Address` (family 0 when connected), then 0..=800 bytes | long: READY bytes taken (u32) |
//! | RECV (10), RECV_TAKE (11) | [k], description, flags (u32, PEEK 1, DONTWAIT 2), most (u32, 1..=800) | long: READY flags (u32, OUT_TRUNC 1), `Address` of the sender, bytes |
//! | SHUTDOWN (12) | description, how (u32: 0 read, 1 write, 2 both) | status |
//! | CLOSE (13), CLOSE_TAKE (35) | [k], description, linger (u32: `CLOSE_MAY_WAIT` when the caller may wait for a `SO_LINGER` close) | long, for a start that answers WAIT; else status |
//! | EXPORT (23) | description | status and one handle: a pass for the description (copy of the service's channel with a label of `PASS`, rights TRANSFER and DUPLICATE) |
//! | ADOPT (24) | the header alone and one handle, a pass | status, description (u32), kind (u32, STREAM or DGRAM) |
//! | GETOPT (14) | description, name (u32) | status, value (u32) |
//! | SETOPT (15) | description, name, value (u32 each) | status |
//! | NAME (16) | description, whose (u32: 0 own, 1 the peer's) | status, `Address` |
//! | WATCH (17), WATCH_TAKE (28), WATCH_CANCEL (29) | `proto_wire::watch` | as the terminal service's |
//! | EPOLL_SET (22) | set (u32, 0 makes a new one), count (u32, 0..=`EPOLL_BATCH`), and for each record: action (u32: ADD 1, MOD 2, DEL 3), description, events (u32, the bits of Linux), label (u32) | status, set (u32), one status word for each record (0 or a code) |
//! | EPOLL_DROP (32) | set | status |
//! | EPOLL_WAIT (33), EPOLL_WAIT_TAKE (34) | [k], set, most (u32, 1..=`EPOLL_MOST`), flags (u32, DONTWAIT 2) | long: READY count (u32), then the pairs (label u32, events u32) |
//! | ABANDON (18) | the header alone | status, how many of the session's long operations are left (u32); the caller asks again until 0 |
//! | CLONE (19) | count (u32, 0..=64), descriptions | status, the birth (u32), one handle: the new session |
//! | CLONE_MORE (20) | the birth (u32, CLONE's reply), count (u32, 1..=64), descriptions | status |
//! | CANCEL (27) | k (u64) | long: CANCELLED |
//! | CONFIG (21) | the header alone | status, `address` (an `Address`, port 0), the prefix length (u32), `gateway` and `dns` (an `Address` each, family 0 when absent), the MAC (6 bytes) and 2 zero bytes; NET_DOWN while there is no address |
//! | PING (62) | an `Address` of port 0 | status, 4 zero bytes, the round-trip time (u64, nanoseconds); NET_DOWN, TIMEOUT after one second of the guest's time, LIMIT_REACHED for a second PING while the first waits |
//! | HOLD (30) | one u32: 1 holds the steps of the stack, 0 lets them go, 2 marks every group of sockets as having work (the effect of a change of address), 3 drops the next frame the stack sends to itself (a test of the timers); only a service built with the feature `probe` has it | status |
//! | PING_WIRE (31) | as PING; the echo request carries 1 472 bytes, a frame of 1 514; only a service built with the feature `probe` has it | as PING |
//! | CRASH (63) | the header alone | none: the service ends with a fault; only a service built with the feature `probe` has it |
//!
//! An address on the wire is the family (u32, INET = 2 for IPv4; 0 for
//! none), the port (u32) and 16 bytes of address, the IPv4 address in the
//! first four.

#![cfg_attr(not(test), no_std)]

pub mod sockets;
pub mod text;

use abi::Error;
use proto_wire::{Header, Reader, Status, Writer};

/// The version of the protocol, in the header of each request.
pub const VERSION: u16 = 1;

/// The methods with their numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Socket = 1,
    Bind = 2,
    Listen = 3,
    Connect = 4,
    ConnectTake = 5,
    Accept = 6,
    AcceptTake = 7,
    Send = 8,
    SendTake = 9,
    Recv = 10,
    RecvTake = 11,
    Shutdown = 12,
    Close = 13,
    GetOpt = 14,
    SetOpt = 15,
    Name = 16,
    Watch = 17,
    Abandon = 18,
    Clone = 19,
    CloneMore = 20,
    Config = 21,
    EpollSet = 22,
    Export = 23,
    Adopt = 24,
    Buffer = 25,
    Claim = 26,
    Cancel = 27,
    WatchTake = 28,
    WatchCancel = 29,
    Hold = 30,
    PingWire = 31,
    EpollDrop = 32,
    EpollWait = 33,
    EpollWaitTake = 34,
    CloseTake = 35,
    Ping = 62,
    Crash = 63,
}

impl Method {
    pub const ALL: [Method; 37] = [
        Method::Socket,
        Method::Bind,
        Method::Listen,
        Method::Connect,
        Method::ConnectTake,
        Method::Accept,
        Method::AcceptTake,
        Method::Send,
        Method::SendTake,
        Method::Recv,
        Method::RecvTake,
        Method::Shutdown,
        Method::Close,
        Method::GetOpt,
        Method::SetOpt,
        Method::Name,
        Method::Watch,
        Method::Abandon,
        Method::Clone,
        Method::CloneMore,
        Method::Config,
        Method::EpollSet,
        Method::Export,
        Method::Adopt,
        Method::Buffer,
        Method::Claim,
        Method::Cancel,
        Method::WatchTake,
        Method::WatchCancel,
        Method::Hold,
        Method::PingWire,
        Method::EpollDrop,
        Method::EpollWait,
        Method::EpollWaitTake,
        Method::CloseTake,
        Method::Ping,
        Method::Crash,
    ];

    pub const fn number(self) -> u16 {
        self as u16
    }

    pub fn from_number(number: u16) -> Option<Method> {
        Method::ALL.into_iter().find(|m| m.number() == number)
    }

    /// The header of a request of this method.
    pub const fn header(self) -> Header {
        Header::new(self.number(), VERSION)
    }
}

/// The codes of the service. Those that mean what a code of the pipe
/// service's sockets means (proto_pipe) have its number; the others follow
/// 723, the last of the sockets' codes, and are free in every protocol.
pub const BAD_FD: u32 = 701;
pub const AGAIN: u32 = 702;
pub const MFILE: u32 = 705;
pub const INVALID: u32 = 706;
pub const IN_USE: u32 = 708;
pub const NOT_CONNECTED: u32 = 709;
pub const CONNECTED: u32 = 710;
pub const REFUSED: u32 = 711;
pub const BAD_TYPE: u32 = 713;
pub const NOT_SUPPORTED: u32 = 714;
pub const NO_ADDRESS: u32 = 715;
pub const TOO_BIG: u32 = 716;
pub const NO_BUFFERS: u32 = 717;
pub const NO_OPTION: u32 = 718;
pub const NOT_SOCKET: u32 = 719;
pub const UNREACHABLE: u32 = 720;
pub const NO_FAMILY: u32 = 721;
pub const NOT_ALLOWED: u32 = 724;
pub const RESET: u32 = 725;
pub const PIPE: u32 = 726;
/// The interface has no address (no lease yet, or the lease was lost).
pub const NET_DOWN: u32 = 727;
pub const TIMEOUT: u32 = 728;
pub const ALREADY: u32 = 729;
pub const IN_PROGRESS: u32 = 730;
/// An interest record that exists already (EPOLL_SET, ADD).
pub const EXISTS: u32 = 731;
/// No such interest record (EPOLL_SET, MOD and DEL).
pub const NO_ENTRY: u32 = 732;
/// A limit of the interest tables: the records of a place, of a set, or of the service.
pub const NO_SPACE: u32 = 733;

/// Every code of the service, for the checks that none repeats and none
/// is a code of the wire (below 512).
pub const CODES: [u32; 27] = [
    BAD_FD,
    AGAIN,
    MFILE,
    INVALID,
    IN_USE,
    NOT_CONNECTED,
    CONNECTED,
    REFUSED,
    BAD_TYPE,
    NOT_SUPPORTED,
    NO_ADDRESS,
    TOO_BIG,
    NO_BUFFERS,
    NO_OPTION,
    NOT_SOCKET,
    UNREACHABLE,
    NO_FAMILY,
    NOT_ALLOWED,
    RESET,
    PIPE,
    NET_DOWN,
    TIMEOUT,
    ALREADY,
    IN_PROGRESS,
    EXISTS,
    NO_ENTRY,
    NO_SPACE,
];

pub const fn code(code: u32) -> Status {
    Status::Unknown(code)
}

/// The refusal of the kernel's LIMIT_REACHED, for a second PING.
pub const LIMIT: Status = Status::Kernel(Error::LimitReached);

/// BAD_VERSION unless the request's header is of this protocol's version.
pub fn check_version(header: Header) -> Result<(), Status> {
    if header.version == VERSION {
        Ok(())
    } else {
        Err(Status::BadVersion)
    }
}

/// The bytes of data one SEND or RECV carries at most: the longest body
/// (SEND_TAKE: header 8, key 8, description 4, flags 4, address 24, data)
/// and the longest reply (RECV: status 4, READY 4, flags 4, address 24,
/// data) stay below MESSAGE_MAX.
pub const DATA_MAX: usize = 800;

/// The values of HOLD's argument.
pub const HOLD_OFF: u32 = 0;
pub const HOLD_ON: u32 = 1;
pub const HOLD_ADDRESS: u32 = 2;
/// The next frame the stack sends to itself goes nowhere (a test of the timers).
pub const HOLD_DROP: u32 = 3;

/// The request HOLD with its argument.
pub fn write_hold(value: u32, w: &mut Writer) -> Result<(), Status> {
    Method::Hold.header().write(w)?;
    w.u32(value)
}

/// The argument of HOLD from `body`: BAD_SIZE unless it is one of the three.
pub fn read_hold(mut body: Reader<'_>) -> Result<u32, Status> {
    let value = body.u32()?;
    body.finish()?;
    match value {
        HOLD_OFF | HOLD_ON | HOLD_ADDRESS | HOLD_DROP => Ok(value),
        _ => Err(Status::BadSize),
    }
}

/// The family of an IPv4 address on the wire.
pub const INET: u32 = 2;
/// The bytes of an address on the wire.
pub const ADDRESS_LEN: usize = 24;

/// An address on the wire: the family, the port and 16 bytes of address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    pub family: u32,
    pub port: u32,
    pub bytes: [u8; 16],
}

impl Address {
    /// No address: the family 0, all zero.
    pub const NONE: Address = Address {
        family: 0,
        port: 0,
        bytes: [0; 16],
    };

    pub const fn v4(ip: [u8; 4], port: u32) -> Address {
        let mut bytes = [0; 16];
        let mut i = 0;
        while i < 4 {
            bytes[i] = ip[i];
            i += 1;
        }
        Address {
            family: INET,
            port,
            bytes,
        }
    }

    /// The IPv4 address, when the family is INET.
    pub const fn ipv4(&self) -> Option<[u8; 4]> {
        if self.family == INET {
            Some([self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3]])
        } else {
            None
        }
    }

    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.family)?;
        w.u32(self.port)?;
        w.bytes(&self.bytes)
    }

    /// The address from `r`: BAD_SIZE when the bytes end, NO_FAMILY for a
    /// family that is neither 0 nor INET, and BAD_SIZE for an address of
    /// the family 0 with any byte or port set, or an IPv4 address with bytes
    /// after its fourth.
    pub fn read(r: &mut Reader<'_>) -> Result<Address, Status> {
        let family = r.u32()?;
        let port = r.u32()?;
        let mut bytes = [0; 16];
        bytes.copy_from_slice(r.bytes(16)?);
        let used = match family {
            0 => 0,
            INET => 4,
            _ => return Err(code(NO_FAMILY)),
        };
        if bytes[used..].iter().any(|&b| b != 0) || (family == 0 && port != 0) {
            return Err(Status::BadSize);
        }
        Ok(Address {
            family,
            port,
            bytes,
        })
    }
}

/// The request PING: the header and the address to ping, port 0.
pub fn write_ping(address: &Address, w: &mut Writer) -> Result<(), Status> {
    Method::Ping.header().write(w)?;
    address.write(w)
}

/// The data of the echo request of PING_WIRE: a full frame of Ethernet (the
/// IPv4 packet of 1 500 bytes holds 20 of header, 8 of ICMP and this).
pub const PING_WIRE_DATA: usize = 1472;

/// The request PING_WIRE (builds with the feature `probe` only): as PING, with
/// an echo request that fills a frame of 1 514 bytes, to measure the cost of
/// a frame of the wire.
pub fn write_ping_wire(address: &Address, w: &mut Writer) -> Result<(), Status> {
    Method::PingWire.header().write(w)?;
    address.write(w)
}

/// The address of PING from `body`, the bytes after the header: BAD_SIZE
/// unless they are one address, NO_FAMILY for an address that is not IPv4,
/// BAD_SIZE for a port other than 0.
pub fn read_ping(mut body: Reader<'_>) -> Result<Address, Status> {
    let address = Address::read(&mut body)?;
    body.finish()?;
    if address.family != INET {
        return Err(code(NO_FAMILY));
    }
    if address.port != 0 {
        return Err(Status::BadSize);
    }
    Ok(address)
}

/// PING's reply: status 0 and the round-trip time in nanoseconds.
pub fn write_ping_reply(nanos: u64, w: &mut Writer) -> Result<(), Status> {
    w.u32(Status::Ok.code())?;
    w.u32(0)?;
    w.u64(nanos)
}

/// The round-trip time of a reply of PING; a refusal is its status alone
/// (8 bytes) and comes back as the error.
pub fn read_ping_reply(reply: &[u8]) -> Result<u64, Status> {
    let mut r = Reader::new(reply);
    let status = Status::from_code(r.u32()?);
    if status != Status::Ok {
        return Err(status);
    }
    if r.u32()? != 0 {
        return Err(Status::BadSize);
    }
    let nanos = r.u64()?;
    r.finish()?;
    Ok(nanos)
}

/// CONFIG's reply after its status: the interface's configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub address: [u8; 4],
    pub prefix: u32,
    pub gateway: Option<[u8; 4]>,
    pub dns: Option<[u8; 4]>,
    pub mac: [u8; 6],
}

impl Config {
    fn optional(ip: Option<[u8; 4]>) -> Address {
        ip.map_or(Address::NONE, |ip| Address::v4(ip, 0))
    }

    /// The reply: status 0 and the fields (the table above).
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(Status::Ok.code())?;
        Address::v4(self.address, 0).write(w)?;
        w.u32(self.prefix)?;
        Config::optional(self.gateway).write(w)?;
        Config::optional(self.dns).write(w)?;
        w.bytes(&self.mac)?;
        w.bytes(&[0; 2])
    }

    /// The configuration of a reply of CONFIG. A refusal is its status
    /// alone (8 bytes) and comes back as the error. BAD_SIZE for any
    /// other layout, a prefix above 32, an address that is not IPv4 or has
    /// a port, or padding that is not zero.
    pub fn read(reply: &[u8]) -> Result<Config, Status> {
        let mut r = Reader::new(reply);
        let status = Status::from_code(r.u32()?);
        if status != Status::Ok {
            return if reply.len() == proto_wire::HEADER_LEN {
                Err(status)
            } else {
                Err(Status::BadSize)
            };
        }
        let address = Address::read(&mut r)?;
        let prefix = r.u32()?;
        let gateway = Address::read(&mut r)?;
        let dns = Address::read(&mut r)?;
        let mut mac = [0; 6];
        mac.copy_from_slice(r.bytes(6)?);
        let pad = r.bytes(2)?;
        r.finish()?;
        let ports = [address.port, gateway.port, dns.port];
        let present = |a: &Address| a.family == 0 || a.family == INET;
        if address.family != INET
            || !(1..=32).contains(&prefix)
            || ports.iter().any(|&p| p != 0)
            || !present(&gateway)
            || !present(&dns)
            || pad != [0, 0]
        {
            return Err(Status::BadSize);
        }
        Ok(Config {
            address: address.ipv4().ok_or(Status::BadSize)?,
            prefix,
            gateway: gateway.ipv4(),
            dns: dns.ipv4(),
            mac,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: Config = Config {
        address: [10, 0, 2, 15],
        prefix: 24,
        gateway: Some([10, 0, 2, 2]),
        dns: Some([10, 0, 2, 3]),
        mac: [0x52, 0x54, 0, 0x12, 0x34, 0x56],
    };

    #[test]
    fn the_methods_keep_their_numbers() {
        let numbers: Vec<_> = Method::ALL.iter().map(|m| m.number()).collect();
        let mut expected: Vec<u16> = (1..=35).collect();
        expected.extend([62, 63]);
        assert_eq!(numbers, expected);
        for m in Method::ALL {
            assert_eq!(Method::from_number(m.number()), Some(m));
        }
        assert_eq!(Method::from_number(0), None);
        assert_eq!(Method::from_number(36), None);
        assert_eq!(Method::from_number(61), None);
        // The steps of the service loop count the methods below the notice.
        assert!(Method::ALL.iter().all(|m| m.number() < 64));
    }

    #[test]
    fn the_codes_agree_with_the_pipe_service_and_are_apart_from_the_wire() {
        use proto_pipe::sock;
        assert_eq!(MFILE, proto_pipe::MFILE);
        assert_eq!(BAD_FD, proto_pipe::BAD_FD);
        assert_eq!(AGAIN, proto_pipe::AGAIN);
        assert_eq!(INVALID, proto_pipe::INVALID);
        assert_eq!(CONNECTED, sock::CONNECTED);
        assert_eq!(BAD_TYPE, sock::BAD_TYPE);
        assert_eq!(NOT_SUPPORTED, sock::NOT_SUPPORTED);
        assert_eq!(NO_ADDRESS, sock::NO_ADDRESS);
        assert_eq!(IN_USE, sock::IN_USE);
        assert_eq!(NOT_CONNECTED, sock::NOT_CONNECTED);
        assert_eq!(REFUSED, sock::REFUSED);
        assert_eq!(TOO_BIG, sock::TOO_BIG);
        assert_eq!(NO_BUFFERS, sock::NO_BUFFERS);
        assert_eq!(NO_OPTION, sock::NO_OPTION);
        assert_eq!(NOT_SOCKET, sock::NOT_SOCKET);
        assert_eq!(UNREACHABLE, sock::UNREACHABLE);
        assert_eq!(NO_FAMILY, sock::NO_FAMILY);
        // The new codes follow the pipe service's last one.
        const { assert!(NOT_ALLOWED > sock::CONNECT_WAIT) };
        for (i, c) in CODES.iter().enumerate() {
            assert!(*c > 512, "above the codes of the wire");
            assert_eq!(code(*c).code(), *c);
            assert_eq!(Status::from_code(*c), Status::Unknown(*c));
            assert!(!CODES[..i].contains(c), "{c} repeats");
        }
        assert_eq!(
            [
                NOT_ALLOWED,
                RESET,
                PIPE,
                NET_DOWN,
                TIMEOUT,
                ALREADY,
                IN_PROGRESS,
                EXISTS,
                NO_ENTRY,
                NO_SPACE
            ],
            [724, 725, 726, 727, 728, 729, 730, 731, 732, 733]
        );
    }

    #[test]
    fn config_round_trips() {
        let mut w = Writer::new();
        SAMPLE.write(&mut w).unwrap();
        assert_eq!(w.as_bytes().len(), 4 + 24 + 4 + 24 + 24 + 8);
        assert_eq!(Config::read(w.as_bytes()), Ok(SAMPLE));
        let bare = Config {
            gateway: None,
            dns: None,
            ..SAMPLE
        };
        let mut w = Writer::new();
        bare.write(&mut w).unwrap();
        assert_eq!(Config::read(w.as_bytes()), Ok(bare));
    }

    #[test]
    fn config_refusals_come_back_as_their_status() {
        let down = proto_wire::reply(code(NET_DOWN));
        assert_eq!(Config::read(&down), Err(code(NET_DOWN)));
    }

    #[test]
    fn config_of_the_wrong_size_is_refused() {
        let mut w = Writer::new();
        SAMPLE.write(&mut w).unwrap();
        let whole = w.as_bytes().to_vec();
        // Short by one byte, and long by one.
        assert_eq!(
            Config::read(&whole[..whole.len() - 1]),
            Err(Status::BadSize)
        );
        let mut long = whole.clone();
        long.push(0);
        assert_eq!(Config::read(&long), Err(Status::BadSize));
        assert_eq!(Config::read(&[]), Err(Status::BadSize));
        // Padding that is not zero, a prefix of 0 and one above 32.
        let mut dirty = whole.clone();
        *dirty.last_mut().unwrap() = 1;
        assert_eq!(Config::read(&dirty), Err(Status::BadSize));
        for prefix in [0u32, 33] {
            let mut bad = whole.clone();
            bad[4 + 24..4 + 28].copy_from_slice(&prefix.to_le_bytes());
            assert_eq!(Config::read(&bad), Err(Status::BadSize), "prefix {prefix}");
        }
    }

    #[test]
    fn ping_round_trips() {
        let target = Address::v4([10, 0, 2, 2], 0);
        let mut w = Writer::new();
        write_ping(&target, &mut w).unwrap();
        let bytes = w.as_bytes();
        assert_eq!(bytes.len(), 8 + ADDRESS_LEN);
        let mut r = Reader::new(bytes);
        let header = Header::read(&mut r).unwrap();
        assert_eq!(header, Method::Ping.header());
        assert_eq!(read_ping(r), Ok(target));
        let mut w = Writer::new();
        write_ping_reply(123_456, &mut w).unwrap();
        assert_eq!(read_ping_reply(w.as_bytes()), Ok(123_456));
        let late = proto_wire::reply(code(TIMEOUT));
        assert_eq!(read_ping_reply(&late), Err(code(TIMEOUT)));
    }

    #[test]
    fn ping_bodies_of_the_wrong_shape_are_refused() {
        let target = Address::v4([10, 0, 2, 2], 0);
        let mut w = Writer::new();
        target.write(&mut w).unwrap();
        let body = w.as_bytes().to_vec();
        assert_eq!(
            read_ping(Reader::new(&body[..ADDRESS_LEN - 1])),
            Err(Status::BadSize)
        );
        let mut long = body.clone();
        long.push(0);
        assert_eq!(read_ping(Reader::new(&long)), Err(Status::BadSize));
        assert_eq!(read_ping(Reader::new(&[])), Err(Status::BadSize));
        // A port, a family of none, an unknown family and bytes past the
        // fourth.
        let mut with_port = body.clone();
        with_port[4] = 7;
        assert_eq!(read_ping(Reader::new(&with_port)), Err(Status::BadSize));
        let mut none = body.clone();
        none[0] = 0;
        assert_eq!(read_ping(Reader::new(&none)), Err(Status::BadSize));
        let mut other = body.clone();
        other[0] = 10;
        assert_eq!(read_ping(Reader::new(&other)), Err(code(NO_FAMILY)));
        let mut wide = body;
        wide[8 + 4] = 1;
        assert_eq!(read_ping(Reader::new(&wide)), Err(Status::BadSize));
    }

    #[test]
    fn hold_round_trips_and_takes_four_values() {
        for value in [HOLD_OFF, HOLD_ON, HOLD_ADDRESS, HOLD_DROP] {
            let mut w = Writer::new();
            write_hold(value, &mut w).unwrap();
            let mut r = Reader::new(w.as_bytes());
            assert_eq!(Header::read(&mut r).unwrap(), Method::Hold.header());
            assert_eq!(read_hold(r), Ok(value));
        }
        assert_eq!(
            read_hold(Reader::new(&4u32.to_le_bytes())),
            Err(Status::BadSize)
        );
        assert_eq!(read_hold(Reader::new(&[1, 0])), Err(Status::BadSize));
    }

    #[test]
    fn a_foreign_version_is_refused() {
        assert_eq!(check_version(Method::Config.header()), Ok(()));
        let other = Header::new(Method::Config.number(), VERSION + 1);
        assert_eq!(check_version(other), Err(Status::BadVersion));
        assert_eq!(check_version(Header::new(21, 0)), Err(Status::BadVersion));
    }

    #[test]
    fn a_request_of_the_header_alone_is_eight_bytes() {
        assert_eq!(Method::Config.header().bytes(), [21, 0, 1, 0, 0, 0, 0, 0]);
        assert_eq!(Method::Crash.header().bytes(), [63, 0, 1, 0, 0, 0, 0, 0]);
    }
}
