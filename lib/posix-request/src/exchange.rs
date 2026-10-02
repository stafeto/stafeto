// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Private file-owner transactions. Replies retain the existing Reply format.
use crate::MESSAGE_MAX;
use proto_wire::{HEADER_LEN, Header, Reader, Status, Writer};
pub const VERSION: u16 = 2;
pub const HEADER_BYTES: usize = HEADER_LEN + 8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exchange<'a> {
    Execute { nonce: u64, request: &'a [u8] },
    Fetch(u64),
    Ack(u64),
}
impl<'a> Exchange<'a> {
    pub fn nonce(self) -> u64 {
        match self {
            Self::Execute { nonce, .. } | Self::Fetch(nonce) | Self::Ack(nonce) => nonce,
        }
    }
    pub fn write(self, out: &mut Writer) -> Result<(), Status> {
        if self.nonce() == 0 {
            return Err(Status::BadSize);
        }
        let method = match self {
            Self::Execute { request, .. } => {
                if request.len() > MESSAGE_MAX - HEADER_BYTES {
                    return Err(Status::BadSize);
                }
                1
            }
            Self::Fetch(_) => 2,
            Self::Ack(_) => 3,
        };
        Header::new(method, VERSION).write(out)?;
        out.u64(self.nonce())?;
        if let Self::Execute { request, .. } = self {
            out.bytes(request)?;
        }
        Ok(())
    }
    pub fn read(bytes: &'a [u8]) -> Result<Self, Status> {
        if bytes.len() > MESSAGE_MAX {
            return Err(Status::BadSize);
        }
        let mut reader = Reader::new(bytes);
        let header = Header::read(&mut reader)?;
        if header.version != VERSION {
            return Err(Status::BadVersion);
        }
        let nonce = reader.u64()?;
        if nonce == 0 {
            return Err(Status::BadSize);
        }
        let value = match header.method {
            1 => Self::Execute {
                nonce,
                request: reader.bytes(reader.left())?,
            },
            2 => Self::Fetch(nonce),
            3 => Self::Ack(nonce),
            _ => return Err(Status::UnknownMethod),
        };
        reader.finish()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transactions_validate_identity_version_and_control_extent() {
        for exchange in [
            Exchange::Execute {
                nonce: 7,
                request: b"request",
            },
            Exchange::Fetch(7),
            Exchange::Ack(7),
        ] {
            let mut writer = Writer::new();
            exchange.write(&mut writer).unwrap();
            assert_eq!(Exchange::read(writer.as_bytes()), Ok(exchange));
            for end in 0..HEADER_BYTES {
                assert!(Exchange::read(&writer.as_bytes()[..end]).is_err());
            }
        }
        for exchange in [
            Exchange::Execute {
                nonce: 0,
                request: b"",
            },
            Exchange::Fetch(0),
            Exchange::Ack(0),
        ] {
            assert_eq!(exchange.write(&mut Writer::new()), Err(Status::BadSize));
        }
        let mut writer = Writer::new();
        Exchange::Ack(1).write(&mut writer).unwrap();
        let original = writer.as_bytes().to_vec();
        for (index, value, error) in [
            (0, 4, Status::UnknownMethod),
            (2, 1, Status::BadVersion),
            (4, 1, Status::BadSize),
            (8, 0, Status::BadSize),
        ] {
            let mut bytes = original.clone();
            bytes[index] = value;
            assert_eq!(Exchange::read(&bytes), Err(error));
        }
        writer.bytes(b"extra").unwrap();
        assert_eq!(Exchange::read(writer.as_bytes()), Err(Status::BadSize));
    }
    #[test]
    fn envelope_keeps_full_reply_and_bounds_the_write_payload() {
        let bytes = [0; crate::MAX_WRITE];
        let mut request = Writer::new();
        crate::Request::Write {
            fd: 3,
            bytes: &bytes,
        }
        .write(&mut request)
        .unwrap();
        let mut wire = Writer::new();
        Exchange::Execute {
            nonce: u64::MAX,
            request: request.as_bytes(),
        }
        .write(&mut wire)
        .unwrap();
        assert_eq!(wire.as_bytes().len(), MESSAGE_MAX);
        let parsed = Exchange::read(wire.as_bytes()).unwrap();
        assert_eq!(parsed.nonce(), u64::MAX);
        let bytes = [0; crate::MAX_WRITE + 1];
        assert_eq!(
            crate::Request::Write {
                fd: 3,
                bytes: &bytes
            }
            .write(&mut Writer::new()),
            Err(Status::BadSize)
        );
        let bytes = [0; MESSAGE_MAX];
        assert_eq!(
            Exchange::Execute {
                nonce: 1,
                request: &bytes
            }
            .write(&mut Writer::new()),
            Err(Status::BadSize)
        );
        let mut writer = Writer::new();
        crate::Reply::Bytes(&bytes[..crate::MAX_READ])
            .write(&mut writer)
            .unwrap();
        assert_eq!(writer.as_bytes().len(), MESSAGE_MAX);
    }
}
