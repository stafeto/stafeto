// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the NVMe service decides apart from the controller and the calls: tested on the host.

#![no_std]

/// Whether the service keeps its timer armed: while a command is out, and while the controller
/// is not up (a reset in place runs the bring-up again, one register access a step, and the
/// steps need the timer when no interrupt and no request comes).
pub const fn timer_wanted(inflight: u32, up: bool) -> bool {
    inflight > 0 || !up
}

/// Where the physical addresses of the DMA objects end in the own arguments (two words); the
/// record's own bytes, which hold the identity wanted, follow.
pub const ADDRESS_BYTES: usize = 16;

/// The first byte of the identity wanted in the record's arguments: none, a serial number or the
/// name of the block device EBS gives.
pub const WANT_ANY: u8 = 0;
pub const WANT_SERIAL: u8 = 1;
pub const WANT_EBS_NAME: u8 = 2;

/// Where the serial number lies in Identify Controller, and the vendor specific bytes in which EBS
/// puts the name of the block device ("sdf" or "/dev/sdf", space or zero padded).
pub const SERIAL_AT: usize = 4;
pub const EBS_NAME_AT: usize = 3072;

/// The identity a volume must show before the service serves it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Want {
    /// The block device name EBS stores in Identify Controller bytes 3072..3104.
    EbsName([u8; 32]),
    /// The serial number, Identify Controller bytes 4..24 (QEMU: `serial=`).
    Serial([u8; 20]),
    /// No check: any controller is served.
    Any,
}

impl Want {
    /// The wanted identity from the own arguments of the service (the two addresses, then a kind
    /// byte and the value, zero padded). Absent bytes or kind 0 are `Any`. A kind that is not known,
    /// or a value longer than its field (it would be cut short and match a shorter name), is an
    /// empty serial, which nothing matches.
    pub fn parse(own: &[u8]) -> Want {
        let value = own.get(ADDRESS_BYTES + 1..).unwrap_or(&[]);
        // The padding of the value is zeros: the length is where the last byte that is none lies.
        let value = &value[..value.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1)];
        match own.get(ADDRESS_BYTES).copied() {
            None | Some(WANT_ANY) => Want::Any,
            Some(WANT_SERIAL) if value.len() <= 20 => {
                let mut w = [0; 20];
                w[..value.len()].copy_from_slice(value);
                Want::Serial(w)
            }
            Some(WANT_EBS_NAME) if value.len() <= 32 => {
                let mut w = [0; 32];
                w[..value.len()].copy_from_slice(value);
                Want::EbsName(w)
            }
            Some(_) => Want::Serial([0; 20]),
        }
    }
}

/// The bytes of a field without the padding at its end (spaces and zeros).
fn trimmed(field: &[u8]) -> &[u8] {
    let end = field
        .iter()
        .rposition(|&b| b != b' ' && b != 0)
        .map_or(0, |i| i + 1);
    &field[..end]
}

/// The name of a block device without the leading `/dev/` and the padding.
fn device_name(field: &[u8]) -> &[u8] {
    let name = trimmed(field);
    name.strip_prefix(b"/dev/").unwrap_or(name)
}

/// Whether a volume with this serial number and this vendor specific name is the one wanted.
/// An empty value matches nothing.
pub fn matches(serial: &[u8; 20], vendor_name: &[u8; 32], want: &Want) -> bool {
    if cfg!(feature = "break-nvme-identity") {
        return true;
    }
    match want {
        Want::Any => true,
        Want::Serial(w) => {
            let w = trimmed(w);
            !w.is_empty() && trimmed(serial) == w
        }
        Want::EbsName(w) => {
            let w = device_name(w);
            !w.is_empty() && device_name(vendor_name) == w
        }
    }
}

/// `matches` over the 4096 bytes of Identify Controller.
pub fn identity(id: &[u8; 4096], want: &Want) -> bool {
    let mut serial = [0; 20];
    serial.copy_from_slice(&id[SERIAL_AT..SERIAL_AT + 20]);
    let mut name = [0; 32];
    name.copy_from_slice(&id[EBS_NAME_AT..EBS_NAME_AT + 32]);
    matches(&serial, &name, want)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ebs(name: &[u8], pad: u8) -> [u8; 4096] {
        let mut id = [0u8; 4096];
        id[EBS_NAME_AT..EBS_NAME_AT + 32].fill(pad);
        id[EBS_NAME_AT..EBS_NAME_AT + name.len()].copy_from_slice(name);
        id
    }

    fn want_name(name: &[u8]) -> Want {
        let mut w = [0; 32];
        w[..name.len()].copy_from_slice(name);
        Want::EbsName(w)
    }

    fn want_serial(name: &[u8]) -> Want {
        let mut w = [0; 20];
        w[..name.len()].copy_from_slice(name);
        Want::Serial(w)
    }

    #[test]
    fn the_data_volume_is_found_by_its_ebs_name() {
        let want = want_name(b"sdf");
        assert!(identity(&ebs(b"sdf", b' '), &want));
        assert!(identity(&ebs(b"sdf", 0), &want));
        assert!(identity(&ebs(b"/dev/sdf", b' '), &want));
        assert!(identity(&ebs(b"/dev/sdf", 0), &want));
    }

    #[test]
    fn both_spellings_of_the_wanted_name_are_the_same() {
        let want = want_name(b"/dev/sdf");
        assert!(identity(&ebs(b"sdf", 0), &want));
        assert!(identity(&ebs(b"/dev/sdf", b' '), &want));
    }

    #[test]
    fn the_root_volume_and_other_names_are_left_alone() {
        let want = want_name(b"sdf");
        assert!(!identity(&ebs(b"sda1", b' '), &want));
        assert!(!identity(&ebs(b"/dev/sda1", 0), &want));
        assert!(!identity(&ebs(b"xvda", b' '), &want));
        assert!(!identity(&ebs(b"sdfg", 0), &want));
        assert!(!identity(&ebs(b"sd", 0), &want));
    }

    #[test]
    fn a_blank_name_matches_nothing() {
        assert!(!identity(&ebs(b"", 0), &want_name(b"sdf")));
        assert!(!identity(&ebs(b"", b' '), &want_name(b"sdf")));
        assert!(!identity(&ebs(b"", 0), &want_name(b"")));
        assert!(!identity(&ebs(b"sdf", 0), &want_name(b"")));
    }

    #[test]
    fn the_serial_number_is_compared_whole() {
        let mut id = [0u8; 4096];
        id[SERIAL_AT..SERIAL_AT + 20].fill(b' ');
        id[SERIAL_AT..SERIAL_AT + 12].copy_from_slice(b"stafeto-data");
        assert!(identity(&id, &want_serial(b"stafeto-data")));
        assert!(!identity(&id, &want_serial(b"stafeto-esp")));
        assert!(!identity(&id, &want_serial(b"stafeto-dat")));
        assert!(!identity(&id, &want_serial(b"")));
        assert!(!identity(&[0; 4096], &want_serial(b"")));
    }

    #[test]
    fn any_serves_every_controller() {
        assert!(identity(&[0; 4096], &Want::Any));
    }

    #[test]
    fn the_arguments_say_what_is_wanted() {
        let mut own = [0u8; 16 + 1 + 3];
        own[16] = WANT_EBS_NAME;
        own[17..].copy_from_slice(b"sdf");
        assert_eq!(Want::parse(&own), want_name(b"sdf"));
        own[16] = WANT_SERIAL;
        assert_eq!(Want::parse(&own), want_serial(b"sdf"));
        assert_eq!(Want::parse(&own[..16]), Want::Any);
        assert_eq!(Want::parse(&[]), Want::Any);
        own[16] = 9;
        assert!(!identity(&[0; 4096], &Want::parse(&own)));
    }

    #[test]
    fn a_value_longer_than_its_field_is_refused() {
        let mut own = [b'a'; 16 + 1 + 40];
        own[16] = WANT_SERIAL;
        assert!(!identity(&[b'a'; 4096], &Want::parse(&own[..16 + 1 + 21])));
        assert_eq!(Want::parse(&own[..16 + 1 + 21]), Want::Serial([0; 20]));
        own[16] = WANT_EBS_NAME;
        assert_eq!(Want::parse(&own[..16 + 1 + 32]), want_name(&[b'a'; 32]));
        assert_eq!(Want::parse(&own[..16 + 1 + 33]), Want::Serial([0; 20]));
        // Padding of zeros past the field is no value.
        let mut own = [0u8; 16 + 1 + 40];
        own[16] = WANT_SERIAL;
        own[17..20].copy_from_slice(b"abc");
        assert_eq!(Want::parse(&own), want_serial(b"abc"));
    }

    #[test]
    fn serial_and_name_are_read_from_their_own_places() {
        let mut id = [0u8; 4096];
        id[SERIAL_AT..SERIAL_AT + 3].copy_from_slice(b"sdf");
        assert!(!identity(&id, &want_name(b"sdf")));
    }

    /// The bytes the measurement of a t4g.small gave (`nvme-map.txt` of the fixtures): the name of
    /// the block device, without `/dev/`, padded with spaces to 32 bytes.
    #[test]
    fn the_measured_names_of_ebs_pass_or_fail_the_data_volume_check() {
        let mut sdf = [0x20u8; 32];
        sdf[..3].copy_from_slice(&[0x73, 0x64, 0x66]);
        let mut xvda = [0x20u8; 32];
        xvda[..4].copy_from_slice(&[0x78, 0x76, 0x64, 0x61]);
        let mut id = [0u8; 4096];
        let mut want = [0u8; 32];
        want[..3].copy_from_slice(b"sdf");
        let want = Want::EbsName(want);
        id[EBS_NAME_AT..EBS_NAME_AT + 32].copy_from_slice(&sdf);
        assert!(identity(&id, &want));
        id[EBS_NAME_AT..EBS_NAME_AT + 32].copy_from_slice(&xvda);
        assert!(!identity(&id, &want));
        // The same through the arguments of the record: kind 2 and the name.
        let mut own = [0u8; ADDRESS_BYTES + 4];
        own[ADDRESS_BYTES..].copy_from_slice(b"\x02sdf");
        assert_eq!(Want::parse(&own), want);
    }

    use super::timer_wanted;

    #[test]
    fn the_timer_runs_while_a_command_is_out() {
        assert!(timer_wanted(1, true));
        assert!(timer_wanted(5, true));
    }

    #[test]
    fn the_timer_sleeps_when_the_controller_is_up_and_idle() {
        assert!(!timer_wanted(0, true));
    }

    #[test]
    fn after_a_reset_the_timer_runs_with_no_command_out() {
        // The reset ends every command in work, so none is out while the bring-up goes on.
        assert!(timer_wanted(0, false));
    }
}
