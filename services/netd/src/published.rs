// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The address the instances share: instance 0 runs the DHCP client (or takes the static
//! address of the file) and publishes what it got here, a record of words with one writer
//! under a sequence count; the other instances look at the count at the start of their steps
//! and apply the record to their own interfaces when it moved. The interfaces all have the
//! one MAC address and the one IP address, so a lease that changes is told once and every
//! instance follows on its own thread.

use core::sync::atomic::{AtomicU32, Ordering, fence};

/// The words of a published address: the address, the prefix with the marks of what follows,
/// the gateway and the three name servers (the first is the one `dns` names).
pub const WORDS: usize = 6;

/// A lease as words: no lease is `None`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub address: [u8; 4],
    pub prefix: u8,
    pub gateway: Option<[u8; 4]>,
    pub servers: [Option<[u8; 4]>; 3],
}

const GATEWAY: u32 = 1 << 8;
const SERVER: u32 = 1 << 9;

impl Record {
    fn words(&self) -> [u32; WORDS] {
        let mut meta = u32::from(self.prefix);
        if self.gateway.is_some() {
            meta |= GATEWAY;
        }
        let mut w = [0; WORDS];
        w[0] = u32::from_le_bytes(self.address);
        w[2] = self.gateway.map_or(0, u32::from_le_bytes);
        for (k, s) in self.servers.iter().enumerate() {
            if let Some(s) = s {
                meta |= SERVER << k;
                w[3 + k] = u32::from_le_bytes(*s);
            }
        }
        w[1] = meta;
        w
    }

    fn from_words(w: &[u32; WORDS]) -> Record {
        let meta = w[1];
        Record {
            address: w[0].to_le_bytes(),
            prefix: meta as u8,
            gateway: (meta & GATEWAY != 0).then(|| w[2].to_le_bytes()),
            servers: core::array::from_fn(|k| {
                (meta & (SERVER << k) != 0).then(|| w[3 + k].to_le_bytes())
            }),
        }
    }
}

/// One writer, any number of readers.
pub struct Published {
    /// Even when the record is whole, odd while the writer is in it; the generation is half
    /// of it. Whether there is a lease at all is the lowest bit of the record's own mark.
    seq: AtomicU32,
    present: AtomicU32,
    words: [AtomicU32; WORDS],
}

impl Published {
    pub const fn new() -> Published {
        Published {
            seq: AtomicU32::new(0),
            present: AtomicU32::new(0),
            words: [const { AtomicU32::new(0) }; WORDS],
        }
    }

    /// The generation: it moves each time a record is published.
    pub fn generation(&self) -> u32 {
        self.seq.load(Ordering::Acquire) / 2
    }

    /// Publishes `record` (or none). Only the writer calls it.
    pub fn publish(&self, record: Option<&Record>) {
        let seq = self.seq.load(Ordering::Relaxed);
        self.seq.store(seq.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        self.present
            .store(u32::from(record.is_some()), Ordering::Relaxed);
        if let Some(record) = record {
            for (slot, w) in self.words.iter().zip(record.words()) {
                slot.store(w, Ordering::Relaxed);
            }
        }
        self.seq.store(seq.wrapping_add(2), Ordering::Release);
    }

    /// The generation and the record as of it.
    pub fn read(&self) -> (u32, Option<Record>) {
        loop {
            let before = self.seq.load(Ordering::Acquire);
            if before & 1 != 0 {
                core::hint::spin_loop();
                continue;
            }
            let present = self.present.load(Ordering::Relaxed) != 0;
            let mut w = [0; WORDS];
            for (out, slot) in w.iter_mut().zip(&self.words) {
                *out = slot.load(Ordering::Relaxed);
            }
            fence(Ordering::Acquire);
            if self.seq.load(Ordering::Relaxed) == before {
                return (before / 2, present.then(|| Record::from_words(&w)));
            }
        }
    }
}

impl Default for Published {
    fn default() -> Published {
        Published::new()
    }
}

/// The address the service's instances share.
pub static ADDRESS: Published = Published::new();

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    const LEASE: Record = Record {
        address: [10, 0, 2, 15],
        prefix: 24,
        gateway: Some([10, 0, 2, 2]),
        servers: [Some([10, 0, 2, 3]), Some([8, 8, 8, 8]), None],
    };

    #[test]
    fn a_published_record_reads_back_whole_and_moves_the_generation() {
        let p = Published::new();
        assert_eq!(p.read(), (0, None));
        p.publish(Some(&LEASE));
        assert_eq!(p.read(), (1, Some(LEASE)));
        let bare = Record {
            gateway: None,
            servers: [None; 3],
            ..LEASE
        };
        p.publish(Some(&bare));
        assert_eq!(p.read(), (2, Some(bare)));
        p.publish(None);
        assert_eq!(p.read(), (3, None));
        assert_eq!(p.generation(), 3);
    }

    #[test]
    fn a_reader_never_sees_two_records_mixed() {
        let p = Arc::new(Published::new());
        let stop = Arc::new(AtomicBool::new(false));
        let a = Record {
            address: [1, 1, 1, 1],
            prefix: 8,
            gateway: Some([1, 1, 1, 2]),
            servers: [Some([1, 1, 1, 3]); 3],
        };
        let b = Record {
            address: [2, 2, 2, 2],
            prefix: 16,
            gateway: None,
            servers: [None; 3],
        };
        let reader = {
            let (p, stop) = (p.clone(), stop.clone());
            std::thread::spawn(move || {
                let mut seen = 0u32;
                while !stop.load(Ordering::Relaxed) {
                    if let (_, Some(r)) = p.read() {
                        assert!(r == a || r == b, "torn: {r:?}");
                        seen += 1;
                    }
                }
                seen
            })
        };
        for i in 0..200_000 {
            p.publish(Some(if i % 2 == 0 { &a } else { &b }));
        }
        stop.store(true, Ordering::Relaxed);
        reader.join().unwrap();
    }
}
