// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! FIFO broker custody shares the paid preparation table and sixteen session indices.

use proto_fs::{FifoAck, FifoGrant};
use proto_pipe::{BrokerPrepare, NamedTicket};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Pending,
    Acked,
    Cancelled,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub request: FifoGrant,
    pub broker: BrokerPrepare,
    pub phase: Phase,
}
impl Receipt {
    fn inode(&self) -> crate::storage::Token {
        crate::storage::Token {
            slot: self.broker.inode.slot as u16,
            generation: self.broker.inode.generation,
        }
    }
    /// A raw Close of the hidden fd cannot retire this broker's exact inode.
    pub fn retain(&self, storage: &mut crate::Storage<'_>) -> Result<(), u32> {
        storage.pin(self.inode(), crate::storage::Pin::Pending)
    }
    pub fn release(&self, storage: &mut crate::Storage<'_>) -> Result<(), u32> {
        storage.unpin(self.inode(), crate::storage::Pin::Pending)
    }
    pub fn pending(self) -> bool {
        self.phase == Phase::Pending
    }
    pub fn ack(&mut self, ack: FifoAck) -> Result<(), u32> {
        if ack.key != self.request.key
            || ack.ticket_slot != self.broker.ticket.slot
            || ack.ticket_generation != self.broker.ticket.generation
        {
            return Err(proto_fs::PERMISSION);
        }
        match self.phase {
            Phase::Cancelled => Err(proto_fs::OPEN_RETIRED),
            Phase::Pending | Phase::Acked => {
                self.phase = Phase::Acked;
                Ok(())
            }
        }
    }
    pub fn open(&self) -> NamedTicket {
        self.broker.open
    }
}

/// BrokerCancel confirms success with four bytes; refusals use the common
/// eight-byte status header. Neither malformed replies nor errors retire custody.
pub fn cancel_status(bytes: &[u8], handles: usize) -> Result<(), u32> {
    if handles != 0 || bytes.len() < 4 {
        return Err(proto_wire::BAD_SIZE);
    }
    let code = u32::from_le_bytes(bytes[..4].try_into().expect("checked status word"));
    if code == 0 {
        return if bytes.len() == 4 {
            Ok(())
        } else {
            Err(proto_wire::BAD_SIZE)
        };
    }
    if bytes.len() != proto_wire::HEADER_LEN || bytes[4..] != [0; 4] {
        return Err(proto_wire::BAD_SIZE);
    }
    Err(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn broker_cancel_requires_exact_success_and_preserves_canonical_refusal() {
        assert_eq!(cancel_status(&0u32.to_le_bytes(), 0), Ok(()));
        let refusal = proto_wire::reply(proto_wire::Status::Unknown(proto_pipe::BAD_FD));
        assert_eq!(cancel_status(&refusal, 0), Err(proto_pipe::BAD_FD));
        for bad in [b"".as_slice(), &[0; 3], &[0; 5], &[0; 8], &refusal[..4]] {
            assert_eq!(cancel_status(bad, 0), Err(proto_wire::BAD_SIZE));
        }
        assert_eq!(cancel_status(&[0; 4], 1), Err(proto_wire::BAD_SIZE));
        let mut malformed = refusal;
        malformed[4] = 1;
        assert_eq!(cancel_status(&malformed, 0), Err(proto_wire::BAD_SIZE));
    }
    #[test]
    fn ack_replay_transfers_only_exact_generation_custody() {
        let ticket = NamedTicket {
            slot: 1,
            generation: u64::MAX,
        };
        let open = NamedTicket {
            slot: 34,
            generation: 41,
        };
        let request = FifoGrant {
            key: proto_fs::OpenKey {
                slot: open.slot,
                generation: open.generation,
            },
            fd: 3,
            generation: 4,
            ticket_slot: ticket.slot,
            ticket_generation: ticket.generation,
            flags: 0,
        };
        let mut receipt = Receipt {
            request,
            broker: BrokerPrepare {
                ticket,
                client: 77,
                open,
                inode: NamedTicket {
                    slot: 99,
                    generation: 55,
                },
                flags: 0,
            },
            phase: Phase::Pending,
        };
        let ack = FifoAck {
            key: request.key,
            ticket_slot: ticket.slot,
            ticket_generation: ticket.generation,
        };
        assert_eq!(
            receipt.ack(FifoAck {
                ticket_generation: 1,
                ..ack
            }),
            Err(proto_fs::PERMISSION)
        );
        assert!(receipt.pending());
        assert_eq!(receipt.ack(ack), Ok(()));
        assert!(!receipt.pending());
        assert_eq!(receipt.ack(ack), Ok(()));
        receipt.phase = Phase::Cancelled;
        assert_eq!(receipt.ack(ack), Err(proto_fs::OPEN_RETIRED));
    }
}
