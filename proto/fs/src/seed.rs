// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Initial source admission, snapshots and acknowledgement envelopes.
//! Native admission authenticates the endpoint, source and current record.
use proto_wire::{Reader, Status, Writer};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    pub epoch: u64,
    pub ticket: u64,
    pub label: u64,
}
impl Key {
    fn valid(self) -> bool {
        self.epoch != 0 && self.ticket != 0 && self.label != 0
    }
    pub fn write(self, out: &mut Writer) -> Result<(), Status> {
        if !self.valid() {
            return Err(Status::BadSize);
        }
        out.u64(self.epoch)?;
        out.u64(self.ticket)?;
        out.u64(self.label)
    }
    fn from_reader(input: &mut Reader<'_>) -> Result<Self, Status> {
        let key = Self {
            epoch: input.u64()?,
            ticket: input.u64()?,
            label: input.u64()?,
        };
        if !key.valid() {
            return Err(Status::BadSize);
        }
        Ok(key)
    }
    pub fn read(bytes: &[u8], caps: usize) -> Result<Self, Status> {
        if caps != 0 {
            return Err(Status::BadSize);
        }
        let mut input = Reader::new(bytes);
        let key = Self::from_reader(&mut input)?;
        input.finish()?;
        Ok(key)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum CancelAction {
    Cancel = 0,
    Retire = 1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cancel {
    pub key: Key,
    pub action: CancelAction,
}
impl Cancel {
    pub fn write(self, out: &mut Writer) -> Result<(), Status> {
        self.key.write(out)?;
        out.u32(self.action as u32)?;
        out.u32(0)
    }
    pub fn read(bytes: &[u8], caps: usize) -> Result<Self, Status> {
        if caps != 0 {
            return Err(Status::BadSize);
        }
        let mut input = Reader::new(bytes);
        let key = Key::from_reader(&mut input)?;
        let action = match input.u32()? {
            0 => CancelAction::Cancel,
            1 => CancelAction::Retire,
            _ => return Err(Status::BadSize),
        };
        if input.u32()? != 0 {
            return Err(Status::BadSize);
        }
        input.finish()?;
        Ok(Self { key, action })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum AckAction {
    Creation = 0,
    Retirement = 1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ResultKind {
    Committed = 1,
    Canceled = 2,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ack {
    pub key: Key,
    pub result: ResultKind,
    pub action: AckAction,
}
impl Ack {
    pub fn write(self, out: &mut Writer) -> Result<(), Status> {
        self.key.write(out)?;
        out.u32(self.result as u32)?;
        out.u32(0)?;
        out.u32(self.action as u32)?;
        out.u32(0)
    }
    pub fn read(bytes: &[u8], caps: usize) -> Result<Self, Status> {
        if caps != 0 {
            return Err(Status::BadSize);
        }
        let mut input = Reader::new(bytes);
        let key = Key::from_reader(&mut input)?;
        let result = match input.u32()? {
            1 => ResultKind::Committed,
            2 => ResultKind::Canceled,
            _ => return Err(Status::BadSize),
        };
        if input.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let action = match input.u32()? {
            0 => AckAction::Creation,
            1 => AckAction::Retirement,
            _ => return Err(Status::BadSize),
        };
        if input.u32()? != 0 {
            return Err(Status::BadSize);
        }
        input.finish()?;
        Ok(Self {
            key,
            result,
            action,
        })
    }
}

/// Native and self sources retain a zero receipt; POSIX sources retain the
/// exact current Process receipt. Wire values alone grant no source authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Receipt {
    Native,
    Posix(proto_process::initial_identity::Query),
}
impl Receipt {
    fn write(self, out: &mut Writer) -> Result<(), Status> {
        match self {
            Self::Native => out.bytes(&[0; 40]),
            Self::Posix(query) => query.write(out),
        }
    }
    fn read(input: &mut Reader<'_>) -> Result<Self, Status> {
        let bytes = input.bytes(40)?;
        if bytes.iter().all(|&b| b == 0) {
            return Ok(Self::Native);
        }
        proto_process::initial_identity::Query::read(bytes, 1).map(Self::Posix)
    }
    fn matches(self, key: Key) -> bool {
        match self {
            Self::Native => true,
            Self::Posix(query) => {
                let r = query.receipt;
                r.key.key == key.ticket
                    && r.init_ticket == key.ticket
                    && r.label == key.label
                    && r.key.image == proto_process::IMAGE
            }
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Phase {
    Guarded = 0,
    Offered = 1,
    Staged = 2,
    Bound = 3,
    Canceling = 4,
    Canceled = 5,
    Complete = 6,
    Retiring = 7,
    RetiredCleanupComplete = 8,
    RetiredAcked = 9,
}
impl Phase {
    fn read(value: u32) -> Result<Self, Status> {
        match value {
            0 => Ok(Self::Guarded),
            1 => Ok(Self::Offered),
            2 => Ok(Self::Staged),
            3 => Ok(Self::Bound),
            4 => Ok(Self::Canceling),
            5 => Ok(Self::Canceled),
            6 => Ok(Self::Complete),
            7 => Ok(Self::Retiring),
            8 => Ok(Self::RetiredCleanupComplete),
            9 => Ok(Self::RetiredAcked),
            _ => Err(Status::BadSize),
        }
    }
    fn result(self) -> u32 {
        match self {
            Self::Guarded | Self::Offered | Self::Staged | Self::Bound | Self::Canceling => 0,
            Self::Canceled => 2,
            _ => 1,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub key: Key,
    pub phase: Phase,
    pub receipt: Receipt,
}
impl Snapshot {
    pub fn write(self, out: &mut Writer) -> Result<(), Status> {
        if !self.receipt.matches(self.key) {
            return Err(Status::BadSize);
        }
        out.bytes(&proto_wire::reply(Status::Ok))?;
        self.key.write(out)?;
        out.u32(self.phase as u32)?;
        out.u32(0)?;
        self.receipt.write(out)?;
        out.u32(self.phase.result())?;
        out.u32(0)
    }
    fn decode(bytes: &[u8]) -> Result<Self, Status> {
        let mut input = Reader::new(bytes);
        let status = Status::from_code(input.u32()?);
        if input.u32()? != 0 {
            return Err(Status::BadSize);
        }
        if status != Status::Ok {
            input.finish()?;
            return Err(status);
        }
        let key = Key::from_reader(&mut input)?;
        let phase = Phase::read(input.u32()?)?;
        if input.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let receipt = Receipt::read(&mut input)?;
        if input.u32()? != phase.result() || input.u32()? != 0 || !receipt.matches(key) {
            return Err(Status::BadSize);
        }
        input.finish()?;
        Ok(Self {
            key,
            phase,
            receipt,
        })
    }
    pub fn read_query(bytes: &[u8], caps: usize) -> Result<Self, Status> {
        if caps != 0 {
            return Err(Status::BadSize);
        }
        Self::decode(bytes)
    }
    pub fn read_step(bytes: &[u8], caps: usize) -> Result<Self, Status> {
        if caps > 1 {
            return Err(Status::BadSize);
        }
        let value = match Self::decode(bytes) {
            Ok(value) => value,
            Err(_) if caps != 0 => return Err(Status::BadSize),
            Err(status) => return Err(status),
        };
        if caps != usize::from(value.phase == Phase::Offered) {
            return Err(Status::BadSize);
        }
        Ok(value)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bind {
    pub key: Key,
    pub receipt: Receipt,
}
impl Bind {
    pub fn write(self, out: &mut Writer) -> Result<(), Status> {
        if !self.receipt.matches(self.key) {
            return Err(Status::BadSize);
        }
        self.key.write(out)?;
        self.receipt.write(out)
    }
    pub fn read(bytes: &[u8], caps: usize) -> Result<Self, Status> {
        let mut input = Reader::new(bytes);
        let key = Key::from_reader(&mut input)?;
        let receipt = Receipt::read(&mut input)?;
        input.finish()?;
        if caps != usize::from(matches!(receipt, Receipt::Posix(_))) || !receipt.matches(key) {
            return Err(Status::BadSize);
        }
        Ok(Self { key, receipt })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum BeginMode {
    First = 0,
    RestartCurrent = 1,
}
/// The caller validates the source binding and the genuine Process handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Begin {
    pub key: Key,
    pub mode: BeginMode,
    pub source: proto_process::initial_publication::InitialSource,
    pub name: proto_wire::Name,
    pub receipt: Receipt,
}
impl Begin {
    pub fn write(self, out: &mut Writer) -> Result<(), Status> {
        if !self.receipt.matches(self.key) {
            return Err(Status::BadSize);
        }
        self.key.write(out)?;
        out.u32(self.mode as u32)?;
        out.u32(0)?;
        proto_process::initial_publication::write_source(self.source, out)?;
        out.name(Some(self.name))?;
        self.receipt.write(out)
    }
    pub fn read(bytes: &[u8], caps: usize) -> Result<Self, Status> {
        if caps != 1 {
            return Err(Status::BadSize);
        }
        let mut input = Reader::new(bytes);
        let key = Key::from_reader(&mut input)?;
        let mode = match input.u32()? {
            0 => BeginMode::First,
            1 => BeginMode::RestartCurrent,
            _ => return Err(Status::BadSize),
        };
        if input.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let source = proto_process::initial_publication::read_source(&mut input)?;
        let name = input.name()?.ok_or(Status::BadSize)?;
        let receipt = Receipt::read(&mut input)?;
        input.finish()?;
        if !receipt.matches(key) {
            return Err(Status::BadSize);
        }
        Ok(Self {
            key,
            mode,
            source,
            name,
            receipt,
        })
    }
}

/// The caller authenticates the RAM endpoint and current boot order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seal {
    pub epoch: u64,
    pub order: u64,
}
impl Seal {
    pub fn write(self, out: &mut Writer) -> Result<(), Status> {
        if self.epoch == 0 || self.order == 0 {
            return Err(Status::BadSize);
        }
        out.u64(self.epoch)?;
        out.u64(self.order)
    }
    pub fn read(bytes: &[u8], caps: usize) -> Result<Self, Status> {
        if caps != 0 {
            return Err(Status::BadSize);
        }
        let mut input = Reader::new(bytes);
        let value = Self {
            epoch: input.u64()?,
            order: input.u64()?,
        };
        input.finish()?;
        if value.epoch == 0 || value.order == 0 {
            return Err(Status::BadSize);
        }
        Ok(value)
    }
    pub fn write_reply(self, out: &mut Writer) -> Result<(), Status> {
        out.bytes(&proto_wire::reply(Status::Ok))?;
        self.write(out)
    }
    pub fn read_reply(bytes: &[u8], caps: usize) -> Result<Self, Status> {
        if caps != 0 {
            return Err(Status::BadSize);
        }
        let mut input = Reader::new(bytes);
        let status = Status::from_code(input.u32()?);
        if input.u32()? != 0 {
            return Err(Status::BadSize);
        }
        if status != Status::Ok {
            input.finish()?;
            return Err(status);
        }
        Self::read(input.bytes(16)?, 0).and_then(|value| {
            input.finish()?;
            Ok(value)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn begin_literal_canonical_source_name_receipt_and_one_owner() {
        let mut body = [0; 104];
        body[..24].copy_from_slice(&literal()[..24]);
        body[24] = 1;
        body[32] = 1;
        body[36] = 2;
        body[40..44].copy_from_slice(&[255; 4]);
        body[48..52].copy_from_slice(b"init");
        let expected = Begin {
            key: key(),
            mode: BeginMode::RestartCurrent,
            source: proto_process::initial_publication::InitialSource {
                artifact: 1,
                raw: 2,
                canonical: None,
            },
            name: proto_wire::Name::new(b"init").unwrap(),
            receipt: Receipt::Native,
        };
        assert_eq!(Begin::read(&body, 1), Ok(expected));
        let mut writer = Writer::new();
        expected.write(&mut writer).unwrap();
        assert_eq!(writer.as_bytes(), body);
        for caps in [0, 2, 3, 4] {
            assert_eq!(Begin::read(&body, caps), Err(Status::BadSize));
        }
        for length in 0..104 {
            assert_eq!(Begin::read(&body[..length], 1), Err(Status::BadSize));
        }
        let mut extended = [0; 105];
        extended[..104].copy_from_slice(&body);
        assert_eq!(Begin::read(&extended, 1), Err(Status::BadSize));
        for offset in [24, 28, 44, 53] {
            let mut bad = body;
            bad[offset] = 3;
            assert_eq!(Begin::read(&bad, 1), Err(Status::BadSize));
        }
        let mut bad = body;
        bad[36..40].copy_from_slice(&body[32..36]);
        assert_eq!(Begin::read(&bad, 1), Err(Status::BadSize));
        let mut bad = body;
        bad[32..36].copy_from_slice(&[255; 4]);
        assert_eq!(Begin::read(&bad, 1), Err(Status::BadSize));
        let mut bad = body;
        bad[48..64].fill(0);
        assert_eq!(Begin::read(&bad, 1), Err(Status::BadSize));
        body[24] = 0;
        body[48..64].copy_from_slice(b"0123456789abcdef");
        let first = Begin::read(&body, 1).unwrap();
        assert_eq!(first.mode, BeginMode::First);
        assert_eq!(first.name.as_bytes(), b"0123456789abcdef");
        let receipt = [
            1, 0, 0, 0, 0, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 7, 0, 3, 0, 0, 1, 0, 128, 7, 3, 0, 0,
            1, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0,
        ];
        body[8..16].copy_from_slice(&19u64.to_le_bytes());
        body[16..24].copy_from_slice(&receipt[16..24]);
        body[64..].copy_from_slice(&receipt);
        let posix = Begin::read(&body, 1).unwrap();
        assert!(matches!(posix.receipt, Receipt::Posix(_)));
        let mut writer = Writer::new();
        posix.write(&mut writer).unwrap();
        assert_eq!(writer.as_bytes(), body);
        for offset in [8, 16, 64, 72, 80, 88, 92, 96] {
            let mut bad = body;
            bad[offset] ^= 1;
            assert_eq!(Begin::read(&bad, 1), Err(Status::BadSize));
        }
    }
    #[test]
    fn seal_literal_full_width_and_exact_reply() {
        let body = [
            255, 255, 255, 255, 255, 255, 255, 255, 2, 0, 0, 0, 1, 0, 0, 0,
        ];
        let value = Seal {
            epoch: u64::MAX,
            order: 0x100000002,
        };
        assert_eq!(Seal::read(&body, 0), Ok(value));
        let mut writer = Writer::new();
        value.write(&mut writer).unwrap();
        assert_eq!(writer.as_bytes(), body);
        let mut reply = [0; 24];
        reply[8..].copy_from_slice(&body);
        let mut writer = Writer::new();
        value.write_reply(&mut writer).unwrap();
        assert_eq!(writer.as_bytes(), reply);
        assert_eq!(Seal::read_reply(&reply, 0), Ok(value));
        for caps in 1..=4 {
            assert_eq!(Seal::read(&body, caps), Err(Status::BadSize));
            assert_eq!(Seal::read_reply(&reply, caps), Err(Status::BadSize));
        }
        for length in 0..24 {
            assert_eq!(Seal::read_reply(&reply[..length], 0), Err(Status::BadSize));
        }
        for offset in [0, 8] {
            let mut malformed = body;
            malformed[offset..offset + 8].fill(0);
            assert_eq!(Seal::read(&malformed, 0), Err(Status::BadSize));
        }
        let mut extended = [0; 25];
        extended[..24].copy_from_slice(&reply);
        assert_eq!(Seal::read_reply(&extended, 0), Err(Status::BadSize));
        reply[4] = 1;
        assert_eq!(Seal::read_reply(&reply, 0), Err(Status::BadSize));
        let refusal = proto_wire::reply(Status::Kernel(abi::Error::BadState));
        assert_eq!(
            Seal::read_reply(&refusal, 0),
            Err(Status::Kernel(abi::Error::BadState))
        );
        let mut bad_refusal = [0; 24];
        bad_refusal[..8].copy_from_slice(&refusal);
        assert_eq!(Seal::read_reply(&bad_refusal, 0), Err(Status::BadSize));
    }
    fn literal() -> [u8; 40] {
        // Literal full-width key, committed result and retirement action.
        [
            255, 255, 255, 255, 255, 255, 255, 255, 2, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0,
            128, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        ]
    }
    fn key() -> Key {
        Key {
            epoch: u64::MAX,
            ticket: 0x100000002,
            label: 0x8000000000000003,
        }
    }
    fn native_snapshot() -> [u8; 88] {
        let mut bytes = [0; 88];
        bytes[8..32].copy_from_slice(&literal()[..24]);
        bytes[32] = 8;
        bytes[80] = 1;
        bytes
    }
    #[test]
    fn snapshot_literal_retirement_and_step_offer_caps_are_exact() {
        let bytes = native_snapshot();
        let expected = Snapshot {
            key: key(),
            phase: Phase::RetiredCleanupComplete,
            receipt: Receipt::Native,
        };
        assert_eq!(Snapshot::read_query(&bytes, 0), Ok(expected));
        let mut writer = Writer::new();
        expected.write(&mut writer).unwrap();
        assert_eq!(writer.as_bytes(), bytes);
        for phase in 0..=9u32 {
            let mut wire = bytes;
            wire[32..36].copy_from_slice(&phase.to_le_bytes());
            let result = match phase {
                0..=4 => 0u32,
                5 => 2,
                _ => 1,
            };
            wire[80..84].copy_from_slice(&result.to_le_bytes());
            let snapshot = Snapshot::read_query(&wire, 0).unwrap();
            assert_eq!(snapshot.phase as u32, phase);
            let caps = usize::from(phase == 1);
            assert_eq!(Snapshot::read_step(&wire, caps), Ok(snapshot));
            assert_eq!(Snapshot::read_step(&wire, 1 - caps), Err(Status::BadSize));
            for wrong in [0u32, 1, 2, 3] {
                if wrong != result {
                    let mut bad = wire;
                    bad[80..84].copy_from_slice(&wrong.to_le_bytes());
                    assert!(Snapshot::read_query(&bad, 0).is_err());
                }
            }
        }
        for length in 0..88 {
            assert!(Snapshot::read_query(&bytes[..length], 0).is_err());
        }
        let mut tail = [0; 89];
        tail[..88].copy_from_slice(&bytes);
        assert!(Snapshot::read_query(&tail, 0).is_err());
        for at in [4, 5, 6, 7, 36, 37, 38, 39, 84, 85, 86, 87] {
            let mut bad = bytes;
            bad[at] = 1;
            assert!(Snapshot::read_query(&bad, 0).is_err());
        }
        let mut bad = bytes;
        bad[32] = 10;
        assert!(Snapshot::read_query(&bad, 0).is_err());
        for caps in 1..=4 {
            assert!(Snapshot::read_query(&bytes, caps).is_err());
        }
        let error = proto_wire::reply(Status::Unknown(crate::OPEN_RETIRED));
        assert_eq!(
            Snapshot::read_step(&error, 0),
            Err(Status::Unknown(crate::OPEN_RETIRED))
        );
        assert_eq!(Snapshot::read_step(&error, 1), Err(Status::BadSize));
    }
    #[test]
    fn posix_binding_uses_the_complete_current_receipt() {
        // Independent literal Process schema, Work label, PID, initial image and ticket.
        let querybytes = [
            1, 0, 0, 0, 0, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 7, 0, 3, 0, 0, 1, 0, 128, 7, 3, 0, 0,
            1, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0,
        ];
        let mut bytes = [0; 64];
        bytes[..24].copy_from_slice(&literal()[..24]);
        bytes[8..16].copy_from_slice(&19u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&querybytes[16..24]);
        bytes[24..].copy_from_slice(&querybytes);
        let value = Bind::read(&bytes, 1).unwrap();
        assert_eq!(value.key.ticket, 19);
        let mut writer = Writer::new();
        value.write(&mut writer).unwrap();
        assert_eq!(writer.as_bytes(), bytes);
        assert!(Bind::read(&bytes, 0).is_err());
        assert!(Bind::read(&bytes, 2).is_err());
        for at in [8, 16, 24, 32, 40, 48, 52, 56] {
            let mut bad = bytes;
            bad[at] ^= 1;
            assert!(Bind::read(&bad, 1).is_err());
        }
        let native = Bind {
            key: key(),
            receipt: Receipt::Native,
        };
        let mut writer = Writer::new();
        native.write(&mut writer).unwrap();
        assert_eq!(Bind::read(writer.as_bytes(), 0), Ok(native));
        assert!(Bind::read(writer.as_bytes(), 1).is_err());
        let snapshot = Snapshot {
            key: value.key,
            phase: Phase::Complete,
            receipt: value.receipt,
        };
        let mut writer = Writer::new();
        snapshot.write(&mut writer).unwrap();
        assert_eq!(Snapshot::read_query(writer.as_bytes(), 0), Ok(snapshot));
        let mut wrong = snapshot;
        wrong.key.ticket += 1;
        assert!(wrong.write(&mut Writer::new()).is_err());
    }
    #[test]
    fn terminal_ack_has_full_key_and_new_action_word() {
        let bytes = literal();
        let ack = Ack::read(&bytes, 0).unwrap();
        assert_eq!(
            ack,
            Ack {
                key: key(),
                result: ResultKind::Committed,
                action: AckAction::Retirement
            }
        );
        let mut writer = Writer::new();
        ack.write(&mut writer).unwrap();
        assert_eq!(writer.as_bytes(), bytes);
        assert_eq!(Key::read(&bytes[..24], 0), Ok(key()));
        assert!(Ack::read(&bytes[..32], 0).is_err());
        let mut cancelbytes = [0; 32];
        cancelbytes[..24].copy_from_slice(&bytes[..24]);
        cancelbytes[24] = 1;
        let cancel = Cancel::read(&cancelbytes, 0).unwrap();
        assert_eq!(cancel.action, CancelAction::Retire);
        let mut writer = Writer::new();
        cancel.write(&mut writer).unwrap();
        assert_eq!(writer.as_bytes(), cancelbytes);
    }
    #[test]
    fn cancel_envelope_rejects_legacy_key_only_and_unknown_action() {
        let bytes = literal();
        let mut cancel = [0; 32];
        cancel[..24].copy_from_slice(&bytes[..24]);
        cancel[24] = 1;
        for length in 0..32 {
            assert!(Cancel::read(&cancel[..length], 0).is_err());
        }
        for caps in 1..=4 {
            assert!(Cancel::read(&cancel, caps).is_err());
        }
        let mut tail = [0; 33];
        tail[..32].copy_from_slice(&cancel);
        assert!(Cancel::read(&tail, 0).is_err());
        for at in 28..32 {
            let mut bad = cancel;
            bad[at] = 1;
            assert!(Cancel::read(&bad, 0).is_err());
        }
        for value in [2, u32::MAX] {
            let mut bad = cancel;
            bad[24..28].copy_from_slice(&value.to_le_bytes());
            assert!(Cancel::read(&bad, 0).is_err());
        }
        cancel[24] = 0;
        assert_eq!(
            Cancel::read(&cancel, 0).unwrap().action,
            CancelAction::Cancel
        );
    }
    #[test]
    fn terminal_envelopes_reject_truncation_tail_caps_and_reserved() {
        let bytes = literal();
        for length in 0..40 {
            assert!(Ack::read(&bytes[..length], 0).is_err());
        }
        let mut tail = [0; 41];
        tail[..40].copy_from_slice(&bytes);
        assert!(Ack::read(&tail, 0).is_err());
        for caps in 1..=4 {
            assert!(Ack::read(&bytes, caps).is_err());
            assert!(Key::read(&bytes[..24], caps).is_err());
        }
        for at in [28, 29, 30, 31, 36, 37, 38, 39] {
            let mut bad = bytes;
            bad[at] = 1;
            assert!(Ack::read(&bad, 0).is_err());
        }
        for at in [0, 8, 16] {
            let mut bad = bytes;
            bad[at..at + 8].fill(0);
            assert!(Ack::read(&bad, 0).is_err());
        }
        for result in [0, 3, u32::MAX] {
            let mut bad = bytes;
            bad[24..28].copy_from_slice(&result.to_le_bytes());
            assert!(Ack::read(&bad, 0).is_err());
        }
        for action in [2, u32::MAX] {
            let mut bad = bytes;
            bad[32..36].copy_from_slice(&action.to_le_bytes());
            assert!(Ack::read(&bad, 0).is_err());
        }
        for result in [ResultKind::Committed, ResultKind::Canceled] {
            for action in [AckAction::Creation, AckAction::Retirement] {
                let ack = Ack {
                    key: key(),
                    result,
                    action,
                };
                let mut writer = Writer::new();
                ack.write(&mut writer).unwrap();
                assert_eq!(Ack::read(writer.as_bytes(), 0), Ok(ack));
            }
        }
    }
}
