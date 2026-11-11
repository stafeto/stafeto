// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Time stamps along the packet path (the feature `on`, which only the
//! images of the measurement turn on). A component (the network service, a
//! process with the stack or the sockets of the layer) keeps a ring of the
//! last `RECORDS` records `(ticks, point, key)`: the ticks of the generic
//! counter (24 MHz on VZ, the same counter on every CPU), a point of the
//! path (the `P_*` numbers) and a key that ties the stages of one request:
//! `frame_key` of a segment with data, the TCP port of the client in its
//! high half and the low half of the sequence number the request ends at
//! (of a segment from the client) or acknowledges (of a segment from the
//! server). The ring is dumped as lines `tr <label> <point> <ticks> <key>`
//! (hexadecimal) when the component is asked, and `cargo xtask net-trace`
//! reads them from the console.

#![no_std]

/// Records in a ring (a power of two).
pub const RECORDS: usize = 1 << 15;

// The points. Switch (the network service), stack of the service, worker.
/// The switch thread got a notification (the key: 1 interrupt, 2 consumer or stack, 3 timer).
pub const P_N_WAKE: u8 = 1;
/// A step of the switch began.
pub const P_N_STEP: u8 = 2;
/// A frame taken off the used ring of the device.
pub const P_N_RX: u8 = 3;
/// The frame put in the ring of a consumer.
pub const P_N_TO_CONSUMER: u8 = 4;
/// The frame handed to the stack thread of the service.
pub const P_N_TO_STACK: u8 = 5;
/// A consumer was woken (its ring was idle).
pub const P_N_CWAKE: u8 = 6;
/// A consumer was not woken (it was running).
pub const P_N_CSKIP: u8 = 7;
/// The switch took a frame off the TX ring of a consumer.
pub const P_N_TX_SEEN: u8 = 8;
/// The stack of the service passed a frame to the switch.
pub const P_N_STK_TX: u8 = 9;
/// A frame put in the queue of sending of the device.
pub const P_N_TX_SUBMIT: u8 = 10;
/// The doorbell of sending rung.
pub const P_N_BELL: u8 = 11;
/// The doorbell of sending skipped (the device asked for none).
pub const P_N_BELL_SKIP: u8 = 12;
/// The stack thread woken by the switch.
pub const P_N_WAKE_STACK: u8 = 13;
/// A step of the stack thread began (the key: its kind).
pub const P_N_STK_BEGIN: u8 = 14;
/// A step of the stack thread ended.
pub const P_N_STK_END: u8 = 15;
/// A request of a client received by the service (the key: the method).
pub const P_N_REQ_BEGIN: u8 = 16;
/// The request answered.
pub const P_N_REQ_END: u8 = 17;
/// The worker's loop woke from its wait (the key: the bits it got).
pub const P_W_WAKE: u8 = 32;
/// The worker took a frame off the ring or the device.
pub const P_W_RX: u8 = 33;
/// The worker put a frame in the queue of sending.
pub const P_W_TX: u8 = 34;
/// The worker rang or poked for the frames put (the doorbell or the poke of the switch).
pub const P_W_KICK: u8 = 35;
/// The worker found its queue empty and went to sleep.
pub const P_W_SLEEP: u8 = 36;
/// The worker, before sleeping, found a frame after all.
pub const P_W_FOUND: u8 = 37;
/// A call of a socket sent to the service by the layer (the key: the request word).
pub const P_C_SEND: u8 = 48;
/// The call returned.
pub const P_C_RET: u8 = 49;
/// `epoll_pwait` entered.
pub const P_C_EPOLL: u8 = 50;
/// `epoll_pwait` returned (the key: the events).
pub const P_C_EPOLL_RET: u8 = 51;

/// The key of a segment of TCP with data in an Ethernet frame: the client's
/// port above, the low half of the end of the request (`from_client`) or of
/// the acknowledgment (from the server) below. None for any other frame.
pub fn frame_key(frame: &[u8], from_client: bool) -> Option<u32> {
    let be16 = |at: usize| {
        Some(u32::from(u16::from_be_bytes([
            *frame.get(at)?,
            *frame.get(at + 1)?,
        ])))
    };
    if frame.get(12..14)? != [0x08, 0x00] || *frame.get(14)? >> 4 != 4 || *frame.get(23)? != 6 {
        return None;
    }
    let ip = 14 + usize::from(*frame.get(14)? & 15) * 4;
    let tcp = usize::from(*frame.get(ip + 12)? >> 4) * 4;
    let data = (be16(16)? as usize).checked_sub(ip - 14 + tcp)?;
    if data == 0 {
        return None;
    }
    let word = |at: usize| Some((be16(at)? << 16) | be16(at + 2)?);
    Some(if from_client {
        (be16(ip)? << 16) | (word(ip + 4)?.wrapping_add(data as u32) & 0xffff)
    } else {
        (be16(ip + 2)? << 16) | (word(ip + 8)? & 0xffff)
    })
}

#[cfg(feature = "on")]
mod on {
    use super::RECORDS;
    use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering::Relaxed};

    static NEXT: AtomicUsize = AtomicUsize::new(0);
    static PTR: AtomicPtr<AtomicU64> = AtomicPtr::new(core::ptr::null_mut());
    #[cfg(feature = "bss")]
    static BSS: [AtomicU64; RECORDS * 2] = [const { AtomicU64::new(0) }; RECORDS * 2];
    const VALID: u64 = 1 << 48;

    /// The words of the ring: `RECORDS * 2` zeroed, from `install` or (feature `bss`) in `.bss`.
    fn ring() -> Option<&'static [AtomicU64]> {
        #[cfg(feature = "bss")]
        return Some(&BSS);
        #[cfg(not(feature = "bss"))]
        {
            let p = PTR.load(Relaxed);
            // SAFETY: `install` took a ring of `RECORDS * 2` words that lives for ever.
            (!p.is_null()).then(|| unsafe { core::slice::from_raw_parts(p, RECORDS * 2) })
        }
    }

    pub fn install(words: *mut u64) {
        PTR.store(words.cast(), Relaxed);
    }

    #[inline(always)]
    pub fn ticks() -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            let t: u64;
            // SAFETY: reading the counter has no side effects.
            unsafe {
                core::arch::asm!("isb", "mrs {}, cntvct_el0", out(reg) t, options(nostack, preserves_flags))
            };
            t
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            0
        }
    }

    pub fn point(id: u8, key: u32) {
        let Some(ring) = ring() else { return };
        let at = (NEXT.fetch_add(1, Relaxed) & (RECORDS - 1)) * 2;
        let now = ticks();
        silence(now, id, key);
        ring[at].store(now, Relaxed);
        ring[at + 1].store(VALID | u64::from(id) << 32 | u64::from(key), Relaxed);
    }

    /// Silences: gaps of more than `GAP` ticks (20 ms) between two records of the component, the
    /// last `GAPS` of them: the end of the gap, its length and the record that ended it.
    const GAP: u64 = 480_000;
    const GAPS: usize = 256;
    static LAST: AtomicU64 = AtomicU64::new(0);
    static GAPN: AtomicUsize = AtomicUsize::new(0);
    static GAP_LOG: [AtomicU64; GAPS * 2] = [const { AtomicU64::new(0) }; GAPS * 2];

    fn silence(now: u64, id: u8, key: u32) {
        let last = LAST.swap(now, Relaxed);
        if last != 0 && now.wrapping_sub(last) > GAP {
            let at = (GAPN.fetch_add(1, Relaxed) % GAPS) * 2;
            GAP_LOG[at].store(now, Relaxed);
            GAP_LOG[at + 1].store(
                now.wrapping_sub(last) << 24 | u64::from(id) << 16 | u64::from(key & 0xffff),
                Relaxed,
            );
        }
    }

    static FROM: AtomicUsize = AtomicUsize::new(usize::MAX);
    static TO: AtomicUsize = AtomicUsize::new(0);

    /// Up to `max` of the records of the dump that goes on (or starts: it begins with the number
    /// of records made, as point 0), oldest first. True when the dump is over.
    pub fn each_part(max: usize, tail: usize, mut f: impl FnMut(u8, u64, u32)) -> bool {
        let Some(ring) = ring() else { return true };
        if FROM.load(Relaxed) == usize::MAX {
            let end = NEXT.load(Relaxed);
            FROM.store(end.saturating_sub(RECORDS.min(tail)), Relaxed);
            TO.store(end, Relaxed);
            f(0, ticks(), end as u32);
            // The silences, oldest first: 0xff the length in ticks, 0xfe the record that ended it.
            for n in GAPN.load(Relaxed).saturating_sub(GAPS)..GAPN.load(Relaxed) {
                let at = (n % GAPS) * 2;
                let (end, word) = (GAP_LOG[at].load(Relaxed), GAP_LOG[at + 1].load(Relaxed));
                f(0xff, end, (word >> 24) as u32);
                f(0xfe, end, (word & 0xff_ffff) as u32);
            }
        }
        let (from, to) = (FROM.load(Relaxed), TO.load(Relaxed));
        let stop = from.saturating_add(max).min(to);
        for n in from..stop {
            let at = (n & (RECORDS - 1)) * 2;
            let meta = ring[at + 1].load(Relaxed);
            if meta & VALID != 0 {
                f((meta >> 32) as u8, ring[at].load(Relaxed), meta as u32);
            }
        }
        FROM.store(if stop >= to { usize::MAX } else { stop }, Relaxed);
        stop >= to
    }
}

/// Gives the ring its storage: `RECORDS * 2` zeroed words that live for ever (a build without
/// the feature `bss`: a process that takes the memory when it makes its first record).
pub fn install(words: *mut u64) {
    #[cfg(feature = "on")]
    on::install(words);
    #[cfg(not(feature = "on"))]
    let _ = words;
}

/// The counter of the clock.
#[inline(always)]
pub fn ticks() -> u64 {
    #[cfg(feature = "on")]
    return on::ticks();
    #[cfg(not(feature = "on"))]
    0
}

/// A record of `id` with `key` now.
#[inline(always)]
pub fn point(id: u8, key: u32) {
    #[cfg(feature = "on")]
    on::point(id, key);
    #[cfg(not(feature = "on"))]
    let _ = (id, key);
}

/// A record of `id` keyed by the segment in `frame` (nothing for a frame without data).
#[inline(always)]
pub fn frame(id: u8, frame: &[u8], from_client: bool) {
    #[cfg(feature = "on")]
    if let Some(key) = frame_key(frame, from_client) {
        on::point(id, key);
    }
    #[cfg(not(feature = "on"))]
    let _ = (id, frame, from_client);
}

#[cfg(feature = "on")]
struct Line {
    bytes: [u8; 80],
    len: usize,
}

#[cfg(feature = "on")]
impl core::fmt::Write for Line {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let end = self.len + s.len();
        self.bytes
            .get_mut(self.len..end)
            .ok_or(core::fmt::Error)?
            .copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Gives the records of the ring, oldest first, to `emit` as lines `tr <label> <point> <ticks>
/// <key>` (hexadecimal, no line end), at most `max` of them in this call; a later call goes on from
/// where this one stopped (`tail`: of the last records at most, when a dump starts). True when the last record has gone (the next call starts a new dump).
/// The first line of a dump is point 0 with the time of the dump and the number of records made.
#[allow(clippy::needless_return)]
pub fn dump_part(label: &str, max: usize, tail: usize, mut emit: impl FnMut(&str)) -> bool {
    #[cfg(feature = "on")]
    {
        let mut say = |id: u8, ticks: u64, key: u64| {
            let mut line = Line {
                bytes: [0; 80],
                len: 0,
            };
            let _ = core::fmt::Write::write_fmt(
                &mut line,
                format_args!("tr {label} {id:x} {ticks:x} {key:x}"),
            );
            if let Ok(text) = core::str::from_utf8(&line.bytes[..line.len]) {
                emit(text);
            }
        };
        return on::each_part(max, tail, |id, ticks, key| say(id, ticks, u64::from(key)));
    }
    #[cfg(not(feature = "on"))]
    {
        let _ = (label, max, tail, &mut emit);
        true
    }
}

/// The last `tail` records (at most the ring) in one call.
pub fn dump(label: &str, tail: usize, emit: impl FnMut(&str)) {
    dump_part(label, usize::MAX, tail, emit);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(from_client: bool, data: usize) -> [u8; 80] {
        let mut f = [0u8; 80];
        f[12] = 8;
        f[14] = 0x45;
        f[16..18].copy_from_slice(&((20 + 20 + data) as u16).to_be_bytes());
        f[23] = 6;
        let (client, server) = (0xc0deu16, 80u16);
        let (s, d) = if from_client {
            (client, server)
        } else {
            (server, client)
        };
        f[34..36].copy_from_slice(&s.to_be_bytes());
        f[36..38].copy_from_slice(&d.to_be_bytes());
        f[38..42].copy_from_slice(&0x0001_fff0u32.to_be_bytes());
        f[42..46].copy_from_slice(&0x0002_0010u32.to_be_bytes());
        f[46] = 0x50;
        f
    }

    #[test]
    fn the_request_and_its_answer_share_a_key() {
        // The request of 0x20 bytes ends at 0x0001_fff0 + 0x20 = 0x0002_0010: the answer acknowledges it.
        assert_eq!(frame_key(&segment(true, 0x20), true), Some(0xc0de_0010));
        assert_eq!(frame_key(&segment(false, 100), false), Some(0xc0de_0010));
    }

    #[test]
    fn a_segment_without_data_has_no_key() {
        assert_eq!(frame_key(&segment(true, 0), true), None);
        assert_eq!(frame_key(&[0; 10], true), None);
    }
}
