// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The file `/etc/netd.conf`, read once at the start of the service.
//!
//! * The file holds at most FILE_MAX bytes and a line at most LINE_MAX.
//! * An empty line and a line whose first character that is no blank is
//!   `#` are skipped.
//! * A line is a key, one or more blanks (spaces or tabs) and a value;
//!   blanks at its end are allowed.
//! * `address A/N`: an IPv4 address in decimal with dots and a prefix
//!   length from 1 to 32. It is required when the file has `gateway` or
//!   `dns`.
//! * `gateway G`: an address inside the network of `address`.
//! * `dns D`: one address.
//! * `address1 A/N`: the address of the second network device, with the same
//!   checks as `address`, and no gateway or name server. With it the second
//!   device runs no DHCP. When `address` is given too, the two are not in
//!   one network. A file for a machine with one device may hold it: it is
//!   kept and not used.
//! * `handover 0` or `handover 1`: parsed and kept; the second device
//!   uses it (a later stage).
//! * A key twice, an unknown key, a word more, a bad address: an error with
//!   the line's number, counted from 1.
//!
//! A file with no `address` line (comments only) means DHCP.

/// The most a file holds, and a line.
pub const FILE_MAX: usize = 1024;
pub const LINE_MAX: usize = 128;

/// An IPv4 address with the length of its network prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    pub address: [u8; 4],
    pub prefix: u8,
}

/// What the file says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    pub address: Option<Cidr>,
    /// The static address of the second device (no gateway, no name
    /// server).
    pub address1: Option<Cidr>,
    pub gateway: Option<[u8; 4]>,
    pub dns: Option<[u8; 4]>,
    pub handover: Option<bool>,
}

/// Why a file is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    FileTooLong,
    LineTooLong,
    NotText,
    UnknownKey,
    KeyTwice,
    NoValue,
    ExtraWord,
    BadAddress,
    BadPrefix,
    BadHandover,
    NeedsAddress,
    GatewayOutside,
    NotUnicast,
    GatewayIsAddress,
    SameNetwork,
}

impl Reason {
    pub const fn text(self) -> &'static str {
        match self {
            Reason::FileTooLong => "the file is longer than 1024 bytes",
            Reason::LineTooLong => "the line is longer than 128 bytes",
            Reason::NotText => "the line is no text",
            Reason::UnknownKey => "unknown key",
            Reason::KeyTwice => "the key is given twice",
            Reason::NoValue => "the key has no value",
            Reason::ExtraWord => "a word more than the value",
            Reason::BadAddress => "bad address",
            Reason::BadPrefix => "bad prefix length",
            Reason::BadHandover => "handover is 0 or 1",
            Reason::NeedsAddress => "gateway and dns need an address line",
            Reason::GatewayOutside => "the gateway is outside the network of the address",
            Reason::NotUnicast => "not a unicast address (0.x.x.x, multicast or broadcast)",
            Reason::GatewayIsAddress => "the gateway is the interface's own address",
            Reason::SameNetwork => "address1 is in the network of address",
        }
    }
}

/// A refused file: the line (from 1; 0 for a fault of the whole file) and
/// the reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub line: usize,
    pub reason: Reason,
}

fn blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn trim(mut s: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = s {
        if !blank(*first) {
            break;
        }
        s = rest;
    }
    while let [rest @ .., last] = s {
        if !blank(*last) && *last != b'\r' {
            break;
        }
        s = rest;
    }
    s
}

/// An IPv4 address in decimal with dots: four numbers of 1 to 3 digits
/// from 0 to 255, no sign and no other character.
pub fn parse_ipv4(text: &[u8]) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut parts = text.split(|&b| b == b'.');
    for slot in &mut out {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 3 || !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let n = part.iter().fold(0u32, |n, &d| n * 10 + u32::from(d - b'0'));
        *slot = u8::try_from(n).ok()?;
    }
    parts.next().is_none().then_some(out)
}

fn parse_cidr(text: &[u8]) -> Result<Cidr, Reason> {
    let slash = text
        .iter()
        .position(|&b| b == b'/')
        .ok_or(Reason::BadPrefix)?;
    let address = parse_ipv4(&text[..slash]).ok_or(Reason::BadAddress)?;
    let digits = &text[slash + 1..];
    if digits.is_empty() || digits.len() > 2 || !digits.iter().all(u8::is_ascii_digit) {
        return Err(Reason::BadPrefix);
    }
    let prefix = digits.iter().fold(0u8, |n, &d| n * 10 + (d - b'0'));
    if !(1..=32).contains(&prefix) {
        return Err(Reason::BadPrefix);
    }
    Ok(Cidr { address, prefix })
}

/// Whether `b` lies in the network of `a`.
pub fn same_network(a: &Cidr, b: [u8; 4]) -> bool {
    let mask = u32::MAX << (32 - u32::from(a.prefix));
    (u32::from_be_bytes(a.address) ^ u32::from_be_bytes(b)) & mask == 0
}

/// Whether `ip` can be the address of a host: not in 0.0.0.0/8 (this
/// network, 0.0.0.0 among it), and below the multicast range 224.0.0.0/4,
/// which holds the reserved block and the broadcast address 255.255.255.255
/// above it. The stack panics on an address that fails this.
pub fn unicast(ip: [u8; 4]) -> bool {
    ip[0] != 0 && ip[0] < 224
}

fn unicast_ip(text: &[u8]) -> Result<[u8; 4], Reason> {
    let ip = parse_ipv4(text).ok_or(Reason::BadAddress)?;
    if unicast(ip) {
        Ok(ip)
    } else {
        Err(Reason::NotUnicast)
    }
}

fn set<T>(slot: &mut Option<T>, value: T) -> Result<(), Reason> {
    if slot.is_some() {
        return Err(Reason::KeyTwice);
    }
    *slot = Some(value);
    Ok(())
}

fn line(settings: &mut Settings, text: &[u8]) -> Result<(), Reason> {
    if text.len() > LINE_MAX {
        return Err(Reason::LineTooLong);
    }
    if core::str::from_utf8(text).is_err() || text.contains(&0) {
        return Err(Reason::NotText);
    }
    let text = trim(text);
    if text.is_empty() || text[0] == b'#' {
        return Ok(());
    }
    let mut words = text.split(|&b| blank(b)).filter(|w| !w.is_empty());
    let key = words.next().ok_or(Reason::NoValue)?;
    let known = matches!(
        key,
        b"address" | b"address1" | b"gateway" | b"dns" | b"handover"
    );
    if !known {
        return Err(Reason::UnknownKey);
    }
    let value = words.next().ok_or(Reason::NoValue)?;
    if words.next().is_some() {
        return Err(Reason::ExtraWord);
    }
    match key {
        b"address" | b"address1" => {
            let cidr = parse_cidr(value)?;
            if !unicast(cidr.address) {
                return Err(Reason::NotUnicast);
            }
            if key == b"address" {
                set(&mut settings.address, cidr)
            } else {
                set(&mut settings.address1, cidr)
            }
        }
        b"gateway" => set(&mut settings.gateway, unicast_ip(value)?),
        b"dns" => set(&mut settings.dns, unicast_ip(value)?),
        _ => {
            let on = match value {
                b"0" => false,
                b"1" => true,
                _ => return Err(Reason::BadHandover),
            };
            set(&mut settings.handover, on)
        }
    }
}

/// The settings in `file`, or the first fault with its line.
pub fn parse(file: &[u8]) -> Result<Settings, Error> {
    if file.len() > FILE_MAX {
        return Err(Error {
            line: 0,
            reason: Reason::FileTooLong,
        });
    }
    let mut settings = Settings::default();
    for (i, text) in file.split(|&b| b == b'\n').enumerate() {
        line(&mut settings, text).map_err(|reason| Error {
            line: i + 1,
            reason,
        })?;
    }
    let Settings {
        address,
        gateway,
        dns,
        ..
    } = settings;
    // Two static addresses in one network would make the stack's routes
    // ambiguous: the second device is for another network.
    if let (Some(a), Some(b)) = (address, settings.address1)
        && same_network(&a, b.address)
    {
        let at = file
            .split(|&b| b == b'\n')
            .position(|l| trim(l).starts_with(b"address1"))
            .map_or(0, |n| n + 1);
        return Err(Error {
            line: at,
            reason: Reason::SameNetwork,
        });
    }
    match (address, gateway, dns) {
        (None, None, None) => {}
        (None, _, _) => {
            return Err(Error {
                line: 0,
                reason: Reason::NeedsAddress,
            });
        }
        (Some(a), Some(g), _) if g == a.address || !same_network(&a, g) => {
            // The line of the gateway, for the message.
            let at = file
                .split(|&b| b == b'\n')
                .position(|l| trim(l).starts_with(b"gateway"))
                .map_or(0, |n| n + 1);
            let reason = if g == a.address {
                Reason::GatewayIsAddress
            } else {
                Reason::GatewayOutside
            };
            return Err(Error { line: at, reason });
        }
        _ => {}
    }
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATIC: &[u8] = b"address 10.0.2.15/24\ngateway 10.0.2.2\ndns 10.0.2.3\n";

    fn fault(file: &[u8]) -> (usize, Reason) {
        let e = parse(file).unwrap_err();
        (e.line, e.reason)
    }

    #[test]
    fn the_probe_file_is_a_static_address() {
        let s = parse(STATIC).unwrap();
        assert_eq!(
            s.address,
            Some(Cidr {
                address: [10, 0, 2, 15],
                prefix: 24
            })
        );
        assert_eq!(s.gateway, Some([10, 0, 2, 2]));
        assert_eq!(s.dns, Some([10, 0, 2, 3]));
        assert_eq!(s.handover, None);
    }

    #[test]
    fn comments_and_blanks_mean_dhcp() {
        assert_eq!(parse(b""), Ok(Settings::default()));
        assert_eq!(
            parse(b"# nothing here\n\n   # nor here\n"),
            Ok(Settings::default())
        );
        assert_eq!(parse(b"  \t \n"), Ok(Settings::default()));
    }

    #[test]
    fn blanks_tabs_and_a_missing_last_newline_are_fine() {
        let s = parse(b"address\t10.1.2.3/8   \r\n\tgateway  10.0.0.1").unwrap();
        assert_eq!(s.address.map(|a| a.prefix), Some(8));
        assert_eq!(s.gateway, Some([10, 0, 0, 1]));
    }

    #[test]
    fn handover_is_zero_or_one() {
        assert_eq!(parse(b"handover 1").unwrap().handover, Some(true));
        assert_eq!(parse(b"handover 0").unwrap().handover, Some(false));
        assert_eq!(fault(b"handover 2"), (1, Reason::BadHandover));
        assert_eq!(fault(b"handover yes"), (1, Reason::BadHandover));
    }

    #[test]
    fn a_fault_names_its_line() {
        assert_eq!(
            fault(b"# c\naddress 10.0.2.15/24\nbogus 1\n"),
            (3, Reason::UnknownKey)
        );
        assert_eq!(
            fault(b"address 10.0.2.15/24\naddress 10.0.2.16/24"),
            (2, Reason::KeyTwice)
        );
        assert_eq!(fault(b"address"), (1, Reason::NoValue));
        assert_eq!(fault(b"address 10.0.2.15/24 extra"), (1, Reason::ExtraWord));
        assert_eq!(fault(b"\n\ndns 1.2.3"), (3, Reason::BadAddress));
    }

    #[test]
    fn addresses_and_prefixes_are_checked() {
        for bad in [
            "10.0.2/24",
            "10.0.2.256/24",
            "10.0.2.15.1/24",
            "a.b.c.d/24",
            "10.0.2.15/",
            "10.0.2.-1/24",
            "+1.0.0.1/8",
            "1.0.0.1 /8",
            "0010.0.0.1/8",
        ] {
            let file = format!("address {bad}");
            assert!(parse(file.as_bytes()).is_err(), "{bad}");
        }
        for bad in [
            "10.0.2.15",
            "10.0.2.15/0",
            "10.0.2.15/33",
            "10.0.2.15/024",
            "10.0.2.15/x",
        ] {
            let file = format!("address {bad}");
            assert_eq!(fault(file.as_bytes()).1, Reason::BadPrefix, "{bad}");
        }
        assert!(parse(b"address 10.0.2.15/32").is_ok());
        assert!(parse(b"address 10.0.2.15/1").is_ok());
    }

    #[test]
    fn gateway_and_dns_need_an_address() {
        assert_eq!(fault(b"gateway 10.0.2.2"), (0, Reason::NeedsAddress));
        assert_eq!(fault(b"dns 10.0.2.3"), (0, Reason::NeedsAddress));
        assert!(parse(b"address 10.0.2.15/24\ndns 8.8.8.8").is_ok());
    }

    #[test]
    fn the_gateway_lies_in_the_network() {
        assert_eq!(
            fault(b"address 10.0.2.15/24\n\ngateway 10.0.3.2"),
            (3, Reason::GatewayOutside)
        );
        assert!(parse(b"address 10.0.2.15/16\ngateway 10.0.3.2").is_ok());
        assert!(parse(b"address 10.0.2.15/32\ngateway 10.0.2.16").is_err());
        assert!(!same_network(
            &Cidr {
                address: [10, 0, 2, 15],
                prefix: 32
            },
            [10, 0, 2, 16]
        ));
    }

    #[test]
    fn addresses_the_stack_would_panic_on_are_refused() {
        for bad in [
            "224.0.0.1/24",
            "239.255.255.255/8",
            "255.255.255.255/32",
            "240.0.0.1/8",
            "0.0.0.0/8",
            "0.1.2.3/24",
        ] {
            let file = format!("address {bad}");
            assert_eq!(fault(file.as_bytes()), (1, Reason::NotUnicast), "{bad}");
        }
        assert_eq!(
            fault(b"address 10.0.2.15/24\ngateway 0.0.0.0"),
            (2, Reason::NotUnicast)
        );
        assert_eq!(
            fault(b"address 10.0.2.15/24\ndns 224.0.0.251"),
            (2, Reason::NotUnicast)
        );
        assert_eq!(
            fault(b"address 10.0.2.15/24\ndns 255.255.255.255"),
            (2, Reason::NotUnicast)
        );
        assert!(parse(b"address 127.0.0.1/8").is_ok());
        assert!(parse(b"address 223.255.255.254/24").is_ok());
    }

    #[test]
    fn address1_is_the_second_devices_and_needs_no_address() {
        let s = parse(b"address1 192.168.64.250/24\n").unwrap();
        assert_eq!(s.address, None);
        assert_eq!(
            s.address1,
            Some(Cidr {
                address: [192, 168, 64, 250],
                prefix: 24
            })
        );
        // Both, in different networks.
        assert!(parse(STATIC).is_ok());
        let both = parse(b"address 10.0.2.15/24\naddress1 10.0.3.15/24").unwrap();
        assert!(both.address.is_some() && both.address1.is_some());
        // The same checks as `address`.
        assert_eq!(fault(b"address1 224.0.0.1/24"), (1, Reason::NotUnicast));
        assert_eq!(fault(b"address1 10.0.3.15"), (1, Reason::BadPrefix));
        assert_eq!(
            fault(b"address1 10.0.3.15/24\naddress1 10.0.3.16/24"),
            (2, Reason::KeyTwice)
        );
        // A gateway or a name server alone still needs `address`.
        assert_eq!(
            fault(b"address1 10.0.3.15/24\ngateway 10.0.3.1"),
            (0, Reason::NeedsAddress)
        );
    }

    #[test]
    fn the_two_static_addresses_are_not_in_one_network() {
        assert_eq!(
            fault(b"address 10.0.2.15/24\n\naddress1 10.0.2.16/24"),
            (3, Reason::SameNetwork)
        );
        assert!(parse(b"address 10.0.2.15/16\naddress1 10.0.3.16/24").is_err());
        assert!(parse(b"address 10.0.2.15/24\naddress1 10.0.3.16/24").is_ok());
    }

    #[test]
    fn the_gateway_is_not_the_address_itself() {
        assert_eq!(
            fault(b"address 10.0.2.15/24\n\ngateway 10.0.2.15"),
            (3, Reason::GatewayIsAddress)
        );
    }

    #[test]
    fn size_limits_hold() {
        let long_line = vec![b'a'; LINE_MAX + 1];
        assert_eq!(fault(&long_line), (1, Reason::LineTooLong));
        let mut comment = b"# ".to_vec();
        comment.resize(LINE_MAX, b'x');
        assert!(parse(&comment).is_ok(), "128 bytes is allowed");
        let mut file = Vec::new();
        while file.len() <= FILE_MAX {
            file.extend_from_slice(b"# padding padding padding padding padding\n");
        }
        assert_eq!(fault(&file), (0, Reason::FileTooLong));
        let exact: Vec<u8> = b"# 0123456789\n"
            .iter()
            .cycle()
            .take(FILE_MAX)
            .copied()
            .collect();
        assert!(parse(&exact).is_ok());
    }

    #[test]
    fn bytes_that_are_no_text_are_refused() {
        assert_eq!(fault(b"address \xff"), (1, Reason::NotText));
        assert_eq!(fault(b"# a\0b"), (1, Reason::NotText));
    }
}
