// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! How the addresses of the network are written in the lines of the service
//! and of its probes.

use core::fmt;

/// An IPv4 address in decimal with dots.
pub struct Ip(pub [u8; 4]);

impl fmt::Display for Ip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.0;
        write!(f, "{a}.{b}.{c}.{d}")
    }
}

/// A MAC address as six pairs of hex digits.
pub struct Mac(pub [u8; 6]);

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_print_as_usual() {
        assert_eq!(format!("{}", Ip([10, 0, 2, 15])), "10.0.2.15");
        assert_eq!(
            format!("{}", Mac([0x52, 0x54, 0, 0x12, 0x34, 0x56])),
            "52:54:00:12:34:56"
        );
    }
}
