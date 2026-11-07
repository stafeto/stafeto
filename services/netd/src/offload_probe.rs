// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Throwaway probe of the offload features (not for merge): which sets the
//! device accepts, what a doorbell costs with one TSO frame against many
//! small ones, and how long the frames it receives are.

use crate::device::{DEVICE, Queue};
use crate::dma::net_at;
use core::sync::atomic::{AtomicU32, Ordering};
use virtio_drivers::transport::{SomeTransport, Transport};
use virtio_net::books::offset;
use virtio_net::open::{MAC, MTU, STATUS};

pub const CSUM: u64 = 1 << 0;
pub const GUEST_CSUM: u64 = 1 << 1;
pub const GUEST_TSO4: u64 = 1 << 7;
pub const GUEST_TSO6: u64 = 1 << 8;
pub const HOST_TSO4: u64 = 1 << 11;
pub const HOST_TSO6: u64 = 1 << 12;
const BASE: u64 = MTU | MAC | STATUS;

const SETS: [(&str, u64); 11] = [
    ("base", 0),
    ("csum+gcsum", CSUM | GUEST_CSUM),
    ("csum", CSUM),
    ("gcsum", GUEST_CSUM),
    ("csum+gcsum+htso4+htso6", CSUM | GUEST_CSUM | HOST_TSO4 | HOST_TSO6),
    ("all6", CSUM | GUEST_CSUM | HOST_TSO4 | HOST_TSO6 | GUEST_TSO4 | GUEST_TSO6),
    ("csum+htso4", CSUM | HOST_TSO4),
    ("csum+gcsum+htso4+htso6+gtso4", CSUM | GUEST_CSUM | HOST_TSO4 | HOST_TSO6 | GUEST_TSO4),
    ("htso4+htso6 without csum", HOST_TSO4 | HOST_TSO6),
    ("gtso4+gtso6 without gcsum", GUEST_TSO4 | GUEST_TSO6),
    ("csum+gcsum+gtso4+gtso6", CSUM | GUEST_CSUM | GUEST_TSO4 | GUEST_TSO6),
];

/// Tries every set, prints the outcome, and returns the extra bits the
/// service then starts with: the set named at build time (`OFFLOAD_SET`),
/// else the widest of the three sets of the note that passed.
pub fn survey(transport: &mut SomeTransport<'static>) -> u64 {
    let mut widest = 0u64;
    let mut named = None;
    let want = option_env!("OFFLOAD_SET");
    for (name, extra) in SETS {
        match virtio_net::open(transport, BASE | extra) {
            Ok(o) => {
                let status = transport.get_status();
                rt::println!(
                    "OFFLOAD set [{name}] extra {extra:#x}: ok, accepted {:#x}, offered {:#x}, status {:?}, link {}, mtu {:?}",
                    o.features,
                    transport.read_device_features(),
                    status,
                    o.link,
                    o.mtu
                );
                if matches!(name, "csum+gcsum" | "csum+gcsum+htso4+htso6" | "all6")
                    && extra.count_ones() >= widest.count_ones()
                {
                    widest = extra;
                }
            }
            Err(e) => rt::println!("OFFLOAD set [{name}] extra {extra:#x}: refused ({e:?})"),
        }
        if want == Some(name) {
            named = Some(extra);
        }
    }
    let chosen = named.unwrap_or(widest);
    rt::println!("OFFLOAD chosen extra {chosen:#x} (OFFLOAD_SET {want:?})");
    chosen
}

fn fold(mut s: u32) -> u16 {
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    s as u16
}

/// Writes the header and a TCP/IPv4 frame of `frame` bytes (Ethernet
/// included) into `buf`; returns the bytes used with the virtio header.
/// Kinds: 0 zero header, 1 NEEDS_CSUM, 2 TSO (pseudo-header sum without
/// the length).
fn build(buf: &mut [u8], frame: usize, mac: [u8; 6], kind: u8) -> usize {
    buf[..12].fill(0);
    let f = &mut buf[12..12 + frame];
    f.fill(0xa5);
    f[0..6].copy_from_slice(&[2, 0, 0, 0, 0, 0x99]);
    f[6..12].copy_from_slice(&mac);
    f[12..14].copy_from_slice(&[8, 0]);
    let ip_len = (frame - 14) as u16;
    f[14] = 0x45;
    f[15] = 0;
    f[16..18].copy_from_slice(&ip_len.to_be_bytes());
    f[18..22].copy_from_slice(&[0, 1, 0x40, 0]);
    f[22] = 64;
    f[23] = 6;
    f[24..26].fill(0);
    let (src, dst) = ([192u8, 168, 64, 2], [192u8, 168, 64, 99]);
    f[26..30].copy_from_slice(&src);
    f[30..34].copy_from_slice(&dst);
    let mut s = 0u32;
    for c in f[14..34].chunks(2) {
        s += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    let ip_sum = !fold(s);
    f[24..26].copy_from_slice(&ip_sum.to_be_bytes());
    f[34..36].copy_from_slice(&5000u16.to_be_bytes());
    f[36..38].copy_from_slice(&5001u16.to_be_bytes());
    f[38..42].copy_from_slice(&1u32.to_be_bytes());
    f[46] = 0x50;
    f[47] = 0x10;
    f[48..50].copy_from_slice(&65535u16.to_be_bytes());
    f[50..54].fill(0);
    if kind != 0 {
        let l4 = if kind == 2 { 0 } else { (frame - 34) as u32 };
        let mut s = 6 + l4;
        for c in src.chunks(2).chain(dst.chunks(2)) {
            s += u32::from(u16::from_be_bytes([c[0], c[1]]));
        }
        f[50..52].copy_from_slice(&fold(s).to_be_bytes());
        buf[0] = 1;
        buf[6..8].copy_from_slice(&34u16.to_le_bytes());
        buf[8..10].copy_from_slice(&16u16.to_le_bytes());
        if kind == 2 {
            buf[1] = 1;
            buf[2..4].copy_from_slice(&54u16.to_le_bytes());
            buf[4..6].copy_from_slice(&1448u16.to_le_bytes());
        }
    }
    12 + frame
}

fn report(name: &str, label: &str, v: &mut [u64], note: &str) {
    v.sort_unstable();
    let n = v.len();
    rt::println!(
        "OFFLOAD bell [{name}] {label} n {n}: min {} med {} max {} ticks (41.67 ns each){note}",
        v[0],
        v[n / 2],
        v[n - 1]
    );
}

/// `frames` frames of `frame` bytes of `kind` under one doorbell, 24
/// rounds, the first 4 a warm-up; false when the device stalled.
fn variant(
    transport: &mut SomeTransport<'static>,
    queue: &mut Queue<DEVICE>,
    mac: [u8; 6],
    name: &str,
    frames: usize,
    frame: usize,
    kind: u8,
) -> bool {
    use rt::time::now;
    const ROUNDS: usize = 24;
    let per = (12 + frame).div_ceil(2048) as u16;
    let mut bell = [0u64; ROUNDS - 4];
    let mut done = [0u64; ROUNDS - 4];
    let mut early = 0u32;
    for round in 0..ROUNDS {
        let mut tokens = [0u16; 16];
        let mut lens = [0usize; 16];
        for k in 0..frames {
            let n = 256 + k as u16 * per;
            // SAFETY: the buffers 256.. of sending belong to the probe while
            // the switch does not exist.
            let buf = unsafe {
                core::slice::from_raw_parts_mut(
                    (net_at(DEVICE) + offset(n)) as *mut u8,
                    per as usize * 2048,
                )
            };
            let used = build(buf, frame, mac, kind);
            lens[k] = used;
            let shared: &[u8] = &buf[..used];
            // SAFETY: not touched until popped below.
            tokens[k] = match unsafe { queue.add(&[shared], &mut []) } {
                Ok(t) => t,
                Err(e) => {
                    rt::println!("OFFLOAD [{name}] add failed {e:?}");
                    return false;
                }
            };
        }
        let t0 = now();
        virtio_net::barrier::ring(transport, 1);
        let t1 = now();
        if queue.can_pop() {
            early += 1;
        }
        let mut got = 0;
        let limit = t0 + 4_800_000; // 200 ms at 24 MHz
        while got < frames {
            if queue.can_pop() {
                virtio_net::barrier::rmb();
                let Some(tok) = queue.peek_used() else {
                    continue;
                };
                let k = tokens[..frames].iter().position(|t| *t == tok).unwrap_or(0);
                let n = 256 + k as u16 * per;
                // SAFETY: the buffer added with this token.
                let buf = unsafe {
                    core::slice::from_raw_parts((net_at(DEVICE) + offset(n)) as *const u8, lens[k])
                };
                // SAFETY: as above.
                let _ = unsafe { queue.pop_used(tok, &[buf], &mut []) };
                got += 1;
            } else if now() > limit {
                rt::println!(
                    "OFFLOAD [{name}] stalled: {got} of {frames} came back in 200 ms; avail_desc {} can_pop {} isr {:#x} status {:?}",
                    queue.available_desc(),
                    queue.can_pop(),
                    transport.ack_interrupt().bits(),
                    transport.get_status()
                );
                return false;
            }
        }
        let t2 = now();
        if round >= 4 {
            bell[round - 4] = t1 - t0;
            done[round - 4] = t2 - t0;
        }
    }
    let note = match early {
        0 => "; used never ready at return",
        ROUNDS_ALL => "; used always ready at return",
        _ => "; used ready at return in some rounds",
    };
    report(name, "ring call", &mut bell, note);
    report(name, "until all used", &mut done, "");
    true
}
const ROUNDS_ALL: u32 = 24;

/// The doorbell test, once the device is live and the switch not started.
pub fn bell_test(
    transport: &mut SomeTransport<'static>,
    queue: &mut Queue<DEVICE>,
    mac: [u8; 6],
    extra: u64,
) {
    queue.set_dev_notify(false);
    rt::println!(
        "OFFLOAD bell test, extra {extra:#x}, frequency {} Hz",
        rt::time::frequency()
    );
    variant(transport, queue, mac, "1 frame 1514, header zero", 1, 1514, 0);
    variant(transport, queue, mac, "8 frames 1514, header zero", 8, 1514, 0);
    variant(transport, queue, mac, "11 frames 1514, header zero", 11, 1514, 0);
    if extra & CSUM != 0 {
        variant(transport, queue, mac, "1 frame 1514, NEEDS_CSUM", 1, 1514, 1);
    }
    if extra & HOST_TSO4 != 0 {
        variant(transport, queue, mac, "1 frame 8192, TSO4", 1, 8192, 2);
        variant(transport, queue, mac, "1 frame 16384, TSO4", 1, 16384, 2);
    }
    rt::println!("OFFLOAD bell test end");
}

static EXTRA: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static MACW: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub fn remember(extra: u64, mac: [u8; 6]) {
    EXTRA.store(extra, Ordering::Relaxed);
    let mut w = [0u8; 8];
    w[..6].copy_from_slice(&mac);
    MACW.store(u64::from_le_bytes(w), Ordering::Relaxed);
}

/// The test with what `remember` kept.
pub fn bell_test_now(transport: &mut SomeTransport<'static>, queue: &mut Queue<DEVICE>) {
    let w = MACW.load(Ordering::Relaxed).to_le_bytes();
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&w[..6]);
    bell_test(transport, queue, mac, EXTRA.load(Ordering::Relaxed));
}

static RX_N: AtomicU32 = AtomicU32::new(0);
static RX_MAX: AtomicU32 = AtomicU32::new(0);
static RX_BIG: AtomicU32 = AtomicU32::new(0);
static RX_NEEDS: AtomicU32 = AtomicU32::new(0);
static RX_VALID: AtomicU32 = AtomicU32::new(0);
static RX_GSO: AtomicU32 = AtomicU32::new(0);

/// A used buffer of receiving: its length and header.
pub fn rx_seen(slice: &[u8], used: usize) {
    let n = RX_N.fetch_add(1, Ordering::Relaxed) + 1;
    let flags = slice[0];
    if flags & 1 != 0 {
        RX_NEEDS.fetch_add(1, Ordering::Relaxed);
    }
    if flags & 2 != 0 {
        RX_VALID.fetch_add(1, Ordering::Relaxed);
    }
    if slice[1] != 0 {
        RX_GSO.fetch_add(1, Ordering::Relaxed);
    }
    if used > 12 + 1514 {
        RX_BIG.fetch_add(1, Ordering::Relaxed);
    }
    let prev = RX_MAX.fetch_max(used as u32, Ordering::Relaxed);
    if used as u32 > prev || n % 128 == 0 {
        rt::println!(
            "OFFLOAD rx n {n} max {} big {} needs_csum {} data_valid {} gso {}; this len {used} flags {flags:#x} gso_type {} hdr_len {} gso_size {}",
            RX_MAX.load(Ordering::Relaxed),
            RX_BIG.load(Ordering::Relaxed),
            RX_NEEDS.load(Ordering::Relaxed),
            RX_VALID.load(Ordering::Relaxed),
            RX_GSO.load(Ordering::Relaxed),
            slice[1],
            u16::from_le_bytes([slice[2], slice[3]]),
            u16::from_le_bytes([slice[4], slice[5]]),
        );
    }
}

// ---------------------------------------------------------------------
// The whole probe: the doorbell test, then a small responder (ARP and a
// TCP sink on port 9000) that counts the frames the device delivers.

const OUR_IP: [u8; 4] = [192, 168, 64, 77];

fn csum(parts: &[&[u8]]) -> u16 {
    let mut s = 0u32;
    let mut odd: Option<u8> = None;
    for part in parts {
        for &b in *part {
            match odd.take() {
                Some(hi) => s += u32::from(u16::from_be_bytes([hi, b])),
                None => odd = Some(b),
            }
        }
    }
    if let Some(hi) = odd {
        s += u32::from(u16::from_be_bytes([hi, 0]));
    }
    !fold(s)
}

struct Sender<'a> {
    tx: &'a mut Queue<DEVICE>,
    out: [(u16, usize); 64],
    next: usize,
}

impl Sender<'_> {
    fn send(&mut self, transport: &mut SomeTransport<'static>, frame: &[u8]) {
        // Take back what the device returned.
        while self.tx.can_pop() {
            virtio_net::barrier::rmb();
            let Some(tok) = self.tx.peek_used() else { break };
            let (n, len) = self.out[usize::from(tok) % 64];
            // SAFETY: the buffer added with this token.
            let buf = unsafe { core::slice::from_raw_parts((net_at(DEVICE) + offset(n)) as *const u8, len) };
            // SAFETY: as above.
            let _ = unsafe { self.tx.pop_used(tok, &[buf], &mut []) };
        }
        let n = 256 + (self.next % 64) as u16;
        self.next += 1;
        // SAFETY: probe-owned transmit buffer.
        let buf = unsafe { core::slice::from_raw_parts_mut((net_at(DEVICE) + offset(n)) as *mut u8, 2048) };
        buf[..12].fill(0);
        buf[12..12 + frame.len()].copy_from_slice(frame);
        let total = 12 + frame.len();
        let shared: &[u8] = &buf[..total];
        // SAFETY: untouched until popped.
        if let Ok(tok) = unsafe { self.tx.add(&[shared], &mut []) } {
            self.out[usize::from(tok) % 64] = (n, total);
            virtio_net::barrier::ring(transport, 1);
        }
    }
}

fn tcp_reply(
    sender: &mut Sender,
    transport: &mut SomeTransport<'static>,
    mac: [u8; 6],
    peer_mac: [u8; 6],
    peer_ip: [u8; 4],
    ports: (u16, u16),
    seq: u32,
    ack: u32,
    flags: u8,
) {
    let mut f = [0u8; 14 + 20 + 24];
    f[0..6].copy_from_slice(&peer_mac);
    f[6..12].copy_from_slice(&mac);
    f[12..14].copy_from_slice(&[8, 0]);
    let opt = flags & 2 != 0;
    let tcp_len: u16 = if opt { 24 } else { 20 };
    let total = 20 + tcp_len;
    f[14] = 0x45;
    f[16..18].copy_from_slice(&total.to_be_bytes());
    f[18..20].copy_from_slice(&[0x12, 0x34]);
    f[20] = 0x40;
    f[22] = 64;
    f[23] = 6;
    f[26..30].copy_from_slice(&OUR_IP);
    f[30..34].copy_from_slice(&peer_ip);
    let c = csum(&[&f[14..34]]);
    f[24..26].copy_from_slice(&c.to_be_bytes());
    f[34..36].copy_from_slice(&ports.0.to_be_bytes());
    f[36..38].copy_from_slice(&ports.1.to_be_bytes());
    f[38..42].copy_from_slice(&seq.to_be_bytes());
    f[42..46].copy_from_slice(&ack.to_be_bytes());
    f[46] = ((tcp_len / 4) as u8) << 4;
    f[47] = flags;
    f[48..50].copy_from_slice(&65535u16.to_be_bytes());
    if opt {
        f[54..58].copy_from_slice(&[2, 4, 0x05, 0xb4]);
    }
    let end = 34 + tcp_len as usize;
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&OUR_IP);
    pseudo[4..8].copy_from_slice(&peer_ip);
    pseudo[9] = 6;
    pseudo[10..12].copy_from_slice(&tcp_len.to_be_bytes());
    let c = csum(&[&pseudo, &f[34..end]]);
    f[50..52].copy_from_slice(&c.to_be_bytes());
    sender.send(transport, &f[..end]);
}

/// Posts the receive buffers, answers ARP and a TCP sink, counts every
/// frame the device delivers; returns after `run_ms` or a FIN and 3 s.
pub fn responder(
    transport: &mut SomeTransport<'static>,
    rx: &mut Queue<DEVICE>,
    tx: &mut Queue<DEVICE>,
    mac: [u8; 6],
    big: bool,
) {
    use rt::time::now;
    // Receive buffers: 7 of 72 KiB when GUEST_TSO needs 65562, else 128 of 2 KiB.
    let (count, slots) = if big { (7usize, 36u16) } else { (128, 1) };
    let blen = slots as usize * 2048;
    let mut tokens = [0u16; 128];
    let post = |rx: &mut Queue<DEVICE>, k: usize, tokens: &mut [u16; 128]| {
        // SAFETY: receive buffers belong to the probe.
        let buf = unsafe {
            core::slice::from_raw_parts_mut((net_at(DEVICE) + offset(k as u16 * slots)) as *mut u8, blen)
        };
        // SAFETY: not read until popped.
        if let Ok(t) = unsafe { rx.add(&[], &mut [buf]) } {
            tokens[usize::from(t) % 128] = k as u16;
        }
    };
    for k in 0..count {
        post(rx, k, &mut tokens);
    }
    virtio_net::barrier::ring(transport, 0);
    let mut sender = Sender { tx, out: [(0, 0); 64], next: 0 };
    let start = now();
    let freq = rt::time::frequency();
    let mut last_rx = start;
    let (mut frames, mut maxlen, mut bigc, mut gso, mut needs, mut valid) = (0u32, 0u32, 0u32, 0u32, 0u32, 0u32);
    let (mut tcp_frames, mut tcp_bytes, mut tcp_big, mut tcp_max_ip) = (0u32, 0u64, 0u32, 0u32);
    let mut next_seq: u32 = 0;
    let (mut synned, mut fin_at) = (false, 0u64);
    let mut last_print = start;
    let mut hist = [0u32; 5];
    let mut flagged = 0u32;
    rt::println!("OFFLOAD responder ready, ip {OUR_IP:?}, big {big}, buffers {count} x {blen}");
    loop {
        let t = now();
        if t - start > 60 * freq || (fin_at != 0 && t - fin_at > 3 * freq) {
            break;
        }
        if t - last_print > 5 * freq {
            last_print = t;
            rt::println!("OFFLOAD rx so far: frames {frames} max {maxlen} big {bigc} gso {gso} needs_csum {needs} data_valid {valid} tcp_frames {tcp_frames} tcp_bytes {tcp_bytes}");
        }
        if !rx.can_pop() {
            continue;
        }
        virtio_net::barrier::rmb();
        let Some(tok) = rx.peek_used() else { continue };
        let k = usize::from(tokens[usize::from(tok) % 128]);
        // SAFETY: the buffer added with this token.
        let buf = unsafe {
            core::slice::from_raw_parts_mut((net_at(DEVICE) + offset(k as u16 * slots)) as *mut u8, blen)
        };
        // SAFETY: as above.
        let used = unsafe { rx.pop_used(tok, &[], &mut [&mut *buf]) }.unwrap_or(0) as usize;
        last_rx = now();
        let _ = last_rx;
        frames += 1;
        let hdr = [buf[0], buf[1]];
        if hdr[0] & 1 != 0 {
            needs += 1;
        }
        if hdr[0] & 2 != 0 {
            valid += 1;
        }
        if hdr[1] != 0 {
            gso += 1;
        }
        if used > 12 + 1514 {
            bigc += 1;
        }
        if used as u32 > maxlen {
            maxlen = used as u32;
            rt::println!(
                "OFFLOAD rx new max {used} (frame {}): flags {:#x} gso_type {} hdr_len {} gso_size {} csum_start {} csum_offset {} num_buffers {}",
                used.saturating_sub(12),
                buf[0],
                buf[1],
                u16::from_le_bytes([buf[2], buf[3]]),
                u16::from_le_bytes([buf[4], buf[5]]),
                u16::from_le_bytes([buf[6], buf[7]]),
                u16::from_le_bytes([buf[8], buf[9]]),
                u16::from_le_bytes([buf[10], buf[11]])
            );
        }
        let f: [u8; 64] = {
            let mut a = [0u8; 64];
            let m = used.saturating_sub(12).min(64);
            a[..m].copy_from_slice(&buf[12..12 + m]);
            a
        };
        let flen = used.saturating_sub(12);
        let mut reply_arp = false;
        if flen >= 42 && f[12..14] == [8, 6] && f[20..22] == [0, 1] && f[38..42] == OUR_IP {
            reply_arp = true;
        }
        let is_tcp = flen >= 54 && f[12..14] == [8, 0] && f[23] == 6 && f[30..34] == OUR_IP;
        let peer_mac: [u8; 6] = f[6..12].try_into().unwrap_or([0; 6]);
        let peer_ip: [u8; 4] = f[26..30].try_into().unwrap_or([0; 4]);
        let (mut seq, mut tflags, mut payload, mut ports) = (0u32, 0u8, 0usize, (0u16, 0u16));
        let mut ip_total = 0u32;
        if is_tcp {
            let ihl = usize::from(f[14] & 15) * 4;
            ip_total = u32::from(u16::from_be_bytes([f[16], f[17]]));
            let t0 = 14 + ihl;
            if t0 + 20 <= 64 {
                ports = (u16::from_be_bytes([f[t0], f[t0 + 1]]), u16::from_be_bytes([f[t0 + 2], f[t0 + 3]]));
                seq = u32::from_be_bytes([f[t0 + 4], f[t0 + 5], f[t0 + 6], f[t0 + 7]]);
                let doff = usize::from(f[t0 + 12] >> 4) * 4;
                tflags = f[t0 + 13];
                payload = flen.saturating_sub(t0 + doff);
            }
        }
        if reply_arp {
            let mut a = [0u8; 42];
            a[0..6].copy_from_slice(&peer_mac);
            a[6..12].copy_from_slice(&mac);
            a[12..14].copy_from_slice(&[8, 6]);
            a[14..20].copy_from_slice(&[0, 1, 8, 0, 6, 4]);
            a[20..22].copy_from_slice(&[0, 2]);
            a[22..28].copy_from_slice(&mac);
            a[28..32].copy_from_slice(&OUR_IP);
            a[32..38].copy_from_slice(&peer_mac);
            a[38..42].copy_from_slice(&f[28..32]);
            sender.send(transport, &a);
        } else if is_tcp && ports.1 == 9000 {
            if tflags & 2 != 0 {
                synned = true;
                next_seq = seq.wrapping_add(1);
                tcp_reply(&mut sender, transport, mac, peer_mac, peer_ip, (9000, ports.0), 1000, next_seq, 0x12);
            } else if synned && tflags & 5 == 0 && payload > 0 {
                let class = match used - 12 {
                    0..=1514 => 0,
                    1515..=4096 => 1,
                    4097..=16384 => 2,
                    16385..=32768 => 3,
                    _ => 4,
                };
                hist[class] += 1;
                if hdr[0] & 3 != 0 {
                    flagged += 1;
                }
                tcp_frames += 1;
                tcp_bytes += payload as u64;
                if used > 12 + 1514 {
                    tcp_big += 1;
                }
                if ip_total > tcp_max_ip {
                    tcp_max_ip = ip_total;
                }
                if seq == next_seq {
                    next_seq = next_seq.wrapping_add(payload as u32);
                }
                tcp_reply(&mut sender, transport, mac, peer_mac, peer_ip, (9000, ports.0), 1001, next_seq, 0x10);
            } else if synned && tflags & 1 != 0 {
                next_seq = next_seq.wrapping_add(1);
                tcp_reply(&mut sender, transport, mac, peer_mac, peer_ip, (9000, ports.0), 1001, next_seq, 0x11);
                fin_at = now();
            }
        }
        post(rx, k, &mut tokens);
        virtio_net::barrier::ring(transport, 0);
    }
    rt::println!(
        "OFFLOAD rx summary: frames {frames} max_used {maxlen} big {bigc} gso {gso} needs_csum {needs} data_valid {valid}; tcp_frames {tcp_frames} tcp_payload_bytes {tcp_bytes} tcp_big {tcp_big} max_ip_total_len {tcp_max_ip}; data frames by frame size: <=1514 {}, <=4096 {}, <=16384 {}, <=32768 {}, more {}; data frames with DATA_VALID or NEEDS_CSUM {flagged}",
        hist[0], hist[1], hist[2], hist[3], hist[4]
    );
}

/// The whole probe; never returns.
pub fn probe_all(
    transport: &mut SomeTransport<'static>,
    mut rx: Queue<DEVICE>,
    mut tx: Queue<DEVICE>,
) -> ! {
    transport.finish_init();
    rx.set_dev_notify(false);
    let w = MACW.load(Ordering::Relaxed).to_le_bytes();
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&w[..6]);
    let extra = EXTRA.load(Ordering::Relaxed);
    bell_test(transport, &mut tx, mac, extra);
    responder(transport, &mut rx, &mut tx, mac, extra & GUEST_TSO4 != 0);
    rt::println!(
        "OFFLOAD probe done, status {:?}",
        transport.get_status()
    );
    loop {
        core::hint::spin_loop();
    }
}
