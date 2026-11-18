// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A SYN scan below the forwarding of the emulator (step 4h of nginx-probe,
//! stafeto/stafeto#439). QEMU's user-mode networking finishes every TCP
//! handshake itself, so a client on the host cannot send a bare SYN, an RST
//! in SYN-RECEIVED, or a SYN on a stale four-tuple. Two filters on the
//! network backend (`n0`, the one `qemu::net` makes) give xtask the frames
//! themselves:
//!
//! - `filter-redirector` (`queue=tx`) takes frames from a chardev socket and
//!   hands them to the guest's device, as if they had come off the wire;
//! - `filter-mirror` (`queue=rx`) copies every frame the guest sends to a
//!   second chardev socket (the guest's traffic to the forwarding goes on as
//!   before).
//!
//! The queue is named from the side of the netdev (the backend, slirp): `tx`
//! holds the packets the netdev sends (to the guest), `rx` the packets sent
//! to the netdev (by the guest) (qemu-options, `-object filter-buffer`). A
//! frame read from `indev` of a filter on `tx` goes on as a packet of the
//! netdev itself, so it reaches the guest (`redirector_to_filter` in
//! net/filter-mirror.c passes it with `nf->netdev` as the sender; on `rx` it
//! passes it with `nf->netdev->peer`, the guest's device, as the sender, so
//! the frame would go to the backend).
//!
//! The sockets are connected right after QEMU starts and the mirror is read
//! for the whole run (frames are dropped unless a scan records them): a
//! chardev server with no client makes QEMU print "filter mirror send
//! failed" on every transmit of the guest.
//!
//! The scanner is a made-up host on the guest's network (`PEER_IP`, `PEER_MAC`)
//! that xtask plays frame by frame (`rawframe`). The forwarding sees the
//! guest's SYN-ACKs to it as segments of no connection and may answer with an
//! RST of its own: the scan counts on none of those, and the counters of the
//! network service tell what happened.

use rawframe::{ACK, Frame, Ip, Mac, RST, SYN, Segment, Unframer};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// The scanner's address on the guest's network (slirp's 10.0.2.0/24; the
/// guest is 10.0.2.15) and its hardware address.
pub const PEER_IP: Ip = [10, 0, 2, 77];
pub const PEER_MAC: Mac = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x4d];
pub const GUEST_IP: Ip = [10, 0, 2, 15];
/// `qemu::NET_MAC`.
const GUEST_MAC: Mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

/// The two sockets of the filters, in `dir`.
pub struct Paths {
    pub inject: PathBuf,
    pub mirror: PathBuf,
}

pub fn paths(dir: &Path) -> Paths {
    Paths {
        inject: dir.join("scan-in.sock"),
        mirror: dir.join("scan-out.sock"),
    }
}

/// The arguments of QEMU that add the two filters to the backend `n0`.
pub fn qemu_args(p: &Paths) -> Vec<String> {
    let _ = std::fs::remove_file(&p.inject);
    let _ = std::fs::remove_file(&p.mirror);
    vec![
        "-chardev".to_owned(),
        format!(
            "socket,id=scan-in,path={},server=on,wait=off",
            p.inject.display()
        ),
        "-chardev".to_owned(),
        format!(
            "socket,id=scan-out,path={},server=on,wait=off",
            p.mirror.display()
        ),
        "-object".to_owned(),
        "filter-redirector,id=scan-f-in,netdev=n0,queue=tx,indev=scan-in".to_owned(),
        "-object".to_owned(),
        "filter-mirror,id=scan-f-out,netdev=n0,queue=rx,outdev=scan-out".to_owned(),
    ]
}

/// What the guest sent that the scan reads: the sequence number of each
/// SYN-ACK, by (the scanner's port, the guest's port).
#[derive(Default)]
struct Seen {
    synacks: HashMap<(u16, u16), u32>,
    /// What the mirror delivered since `forget`: the frames, the first of
    /// them and the first TCP segment described, and whether the guest's ARP
    /// reply (or its own request for the scanner) came.
    frames: usize,
    first: Option<String>,
    first_tcp: Option<String>,
    arp_reply: bool,
    arp_asked: bool,
}

/// A frame in a line: the two hardware addresses and what the frame is.
fn describe(frame: &[u8]) -> String {
    let mac = |m: &[u8]| {
        m.iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    if frame.len() < 14 {
        return format!("{} bytes", frame.len());
    }
    let what = match rawframe::parse(frame) {
        Frame::ArpRequest {
            sender_ip,
            target_ip,
            ..
        } => format!("ARP request {sender_ip:?} asks {target_ip:?}"),
        Frame::ArpReply { sender_ip, .. } => format!("ARP reply from {sender_ip:?}"),
        Frame::Tcp {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            flags,
            ..
        } => format!("TCP {src_ip:?}:{src_port} > {dst_ip:?}:{dst_port} flags {flags:#04x}"),
        Frame::Other => format!("ethertype {:02x}{:02x}", frame[12], frame[13]),
    };
    format!(
        "{} > {} {what} ({} bytes)",
        mac(&frame[6..12]),
        mac(&frame[0..6]),
        frame.len()
    )
}

/// The two sockets, connected, and the thread that reads the guest's frames.
pub struct Tap {
    inject: Arc<Mutex<UnixStream>>,
    seen: Arc<Mutex<Seen>>,
    recording: Arc<AtomicBool>,
    /// Set by the reader when the mirror's stream ended.
    ended: Arc<AtomicBool>,
}

fn connect(role: &str, path: &Path, within: Duration) -> Result<UnixStream, String> {
    let until = Instant::now() + within;
    loop {
        match UnixStream::connect(path) {
            Ok(s) => return Ok(s),
            Err(e) if Instant::now() >= until => {
                return Err(format!(
                    "the {role} socket of the network filters, {}: {e} (QEMU makes it at start)",
                    path.display()
                ));
            }
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
}

impl Tap {
    pub fn connect(p: &Paths) -> Result<Tap, String> {
        let inject = Arc::new(Mutex::new(connect(
            "injection (indev of filter-redirector)",
            &p.inject,
            Duration::from_secs(10),
        )?));
        let mut mirror = connect(
            "mirror (outdev of filter-mirror)",
            &p.mirror,
            Duration::from_secs(10),
        )?;
        let seen = Arc::new(Mutex::new(Seen::default()));
        let recording = Arc::new(AtomicBool::new(false));
        let ended = Arc::new(AtomicBool::new(false));
        let (reply, notes) = (inject.clone(), seen.clone());
        let (on, done) = (recording.clone(), ended.clone());
        thread::spawn(move || {
            let mut stream = Unframer::default();
            let mut buf = vec![0u8; 65536];
            loop {
                let n = match mirror.read(&mut buf) {
                    Ok(0) | Err(_) => {
                        done.store(true, Ordering::SeqCst);
                        return;
                    }
                    Ok(n) => n,
                };
                stream.push(&buf[..n]);
                if !on.load(Ordering::SeqCst) {
                    // Between scans the frames are read and dropped.
                    while stream.pop().is_some() {}
                    continue;
                }
                while let Some(frame) = stream.pop() {
                    {
                        let mut n = notes.lock().unwrap();
                        n.frames += 1;
                        if n.first.is_none() {
                            n.first = Some(describe(&frame));
                        }
                        match rawframe::parse(&frame) {
                            Frame::Tcp { .. } if n.first_tcp.is_none() => {
                                n.first_tcp = Some(describe(&frame));
                            }
                            Frame::ArpReply { sender_ip, .. } if sender_ip == GUEST_IP => {
                                n.arp_reply = true;
                            }
                            Frame::ArpRequest { target_ip, .. } if target_ip == PEER_IP => {
                                n.arp_asked = true;
                            }
                            _ => {}
                        }
                    }
                    match rawframe::parse(&frame) {
                        Frame::ArpRequest {
                            sender_mac,
                            sender_ip,
                            target_ip,
                        } if target_ip == PEER_IP => {
                            let r = rawframe::arp_reply(PEER_MAC, PEER_IP, sender_mac, sender_ip);
                            let _ = reply.lock().unwrap().write_all(&rawframe::framed(&r));
                        }
                        Frame::Tcp {
                            dst_ip,
                            src_port,
                            dst_port,
                            seq,
                            flags,
                            ..
                        } if dst_ip == PEER_IP && flags == SYN | ACK => {
                            notes
                                .lock()
                                .unwrap()
                                .synacks
                                .insert((dst_port, src_port), seq);
                        }
                        _ => {}
                    }
                }
            }
        });
        Ok(Tap {
            inject,
            seen,
            recording,
            ended,
        })
    }

    /// Turns the reading of the guest's frames on or off.
    pub fn record(&self, on: bool) {
        self.recording.store(on, Ordering::SeqCst);
    }

    /// Starts a count of what the mirror delivers.
    pub fn forget(&self) {
        let mut n = self.seen.lock().unwrap();
        n.frames = 0;
        n.first = None;
        n.first_tcp = None;
        n.arp_reply = false;
        n.arp_asked = false;
    }

    /// The frames the mirror delivered since `forget`.
    pub fn frames(&self) -> usize {
        self.seen.lock().unwrap().frames
    }

    /// What the mirror delivered since `forget`, in a line.
    pub fn facts(&self) -> String {
        let n = self.seen.lock().unwrap();
        format!(
            "the mirror delivered {} frames (the first: {}; the first TCP segment: {}); the guest's ARP reply {}, its own ARP request for the scanner {}; the mirror socket {}",
            n.frames,
            n.first.as_deref().unwrap_or("none"),
            n.first_tcp.as_deref().unwrap_or("none"),
            if n.arp_reply { "came" } else { "did not come" },
            if n.arp_asked { "came" } else { "did not come" },
            if self.ended.load(Ordering::SeqCst) {
                "was closed by QEMU"
            } else {
                "is open"
            }
        )
    }

    /// Frames to the guest, in one write (they reach the device together).
    fn send(&self, frames: &[Vec<u8>]) -> Result<(), String> {
        let mut bytes = Vec::new();
        for f in frames {
            bytes.extend_from_slice(&rawframe::framed(f));
        }
        self.inject.lock().unwrap().write_all(&bytes).map_err(|e| {
            format!("writing to the injection socket (indev of filter-redirector): {e}")
        })
    }

    fn synack(&self, port: u16, guest_port: u16) -> Option<u32> {
        self.seen
            .lock()
            .unwrap()
            .synacks
            .get(&(port, guest_port))
            .copied()
    }

    fn synacks(&self) -> usize {
        self.seen.lock().unwrap().synacks.len()
    }
}

fn segment(port: u16, guest_port: u16, seq: u32, ack: u32, flags: u8) -> Vec<u8> {
    Segment {
        src_mac: PEER_MAC,
        dst_mac: GUEST_MAC,
        src_ip: PEER_IP,
        dst_ip: GUEST_IP,
        src_port: port,
        dst_port: guest_port,
        seq,
        ack,
        flags,
    }
    .frame()
}

/// The initial sequence number of the scanner's connection from `port`.
fn isn(port: u16) -> u32 {
    0xffff_0000u32.wrapping_add(u32::from(port).wrapping_mul(7919))
}

fn syn(port: u16, guest_port: u16, isn: u32) -> Vec<u8> {
    segment(port, guest_port, isn, 0, SYN)
}

fn rst(port: u16, guest_port: u16, isn: u32) -> Vec<u8> {
    segment(port, guest_port, isn.wrapping_add(1), 0, RST)
}

/// What a replay did.
#[derive(Debug, Default)]
pub struct Replayed {
    pub syns: usize,
    pub synacks_seen: usize,
    pub handshakes_ended: usize,
}

const SCAN_FIRST: u16 = 30000;

/// The replay: the guest's listeners at `ports` get
///
/// 1. a classic scan: a SYN, then an RST in SYN-RECEIVED for half of the
///    ports and the ACK of the SYN-ACK and an RST after it for the other
///    half (an established connection reset before `accept`);
/// 2. bursts of SYN A, RST A, SYN B in one write (the socket the RST sent
///    back to LISTEN takes B's SYN in the same step as the RST: the stale
///    key), B reset after, one burst in two on the same four-tuple;
/// 3. a flood of SYNs far past the room of the queues, again after more than
///    a second (a half-open socket may be recycled then), then all reset.
pub fn replay(tap: &Tap, ports: &[u16]) -> Result<Replayed, String> {
    let mut done = Replayed::default();
    let mut port = SCAN_FIRST;
    let mut next = || {
        port += 1;
        port
    };
    // The guest learns the scanner's address from this request.
    tap.send(&[rawframe::arp_request(PEER_MAC, PEER_IP, GUEST_IP)])?;
    let until = Instant::now() + Duration::from_secs(1);
    while !tap.seen.lock().unwrap().arp_reply && Instant::now() < until {
        thread::sleep(Duration::from_millis(20));
    }
    let arp_answered = tap.seen.lock().unwrap().arp_reply;

    // 1.
    let mut mine = Vec::new();
    for &gp in ports {
        for i in 0..12 {
            mine.push((next(), gp, i));
        }
    }
    tap.send(
        &mine
            .iter()
            .map(|&(p, gp, _)| syn(p, gp, isn(p)))
            .collect::<Vec<_>>(),
    )?;
    done.syns += mine.len();
    let until = Instant::now() + Duration::from_secs(5);
    while tap.synacks() < mine.len() && Instant::now() < until {
        thread::sleep(Duration::from_millis(50));
    }
    let mut closing = Vec::new();
    for &(p, gp, i) in &mine {
        if i % 2 == 1
            && let Some(server) = tap.synack(p, gp)
        {
            closing.push(segment(
                p,
                gp,
                isn(p).wrapping_add(1),
                server.wrapping_add(1),
                ACK,
            ));
            done.handshakes_ended += 1;
        }
        closing.push(rst(p, gp, isn(p)));
    }
    if done.handshakes_ended == 0 {
        return Err(format!(
            "no SYN-ACK of the guest reached the scanner after 5 s ({} of {} SYNs answered; the ARP request was {} within 1 s); {}",
            tap.synacks(),
            mine.len(),
            if arp_answered {
                "answered"
            } else {
                "not answered"
            },
            tap.facts()
        ));
    }
    tap.send(&closing)?;
    thread::sleep(Duration::from_millis(200));

    // 2.
    for burst in 0..40 {
        let mut frames = Vec::new();
        let mut second = Vec::new();
        for j in 0..8 {
            let gp = ports[(burst + j) % ports.len()];
            let a = next();
            let b = if j % 2 == 0 { a } else { next() };
            let (isn_a, isn_b) = (isn(a), isn(a).wrapping_add(1000));
            frames.push(syn(a, gp, isn_a));
            frames.push(rst(a, gp, isn_a));
            frames.push(syn(b, gp, isn_b));
            second.push(rst(b, gp, isn_b));
            done.syns += 2;
        }
        tap.send(&frames)?;
        thread::sleep(Duration::from_millis(20));
        tap.send(&second)?;
        thread::sleep(Duration::from_millis(20));
    }

    // 3.
    let mut flooded = Vec::new();
    for round in 0..2 {
        let mut frames = Vec::new();
        for &gp in ports {
            for _ in 0..100 {
                let p = next();
                frames.push(syn(p, gp, isn(p)));
                flooded.push((p, gp));
            }
        }
        done.syns += frames.len();
        tap.send(&frames)?;
        thread::sleep(Duration::from_millis(if round == 0 { 1300 } else { 300 }));
    }
    tap.send(
        &flooded
            .iter()
            .map(|&(p, gp)| rst(p, gp, isn(p)))
            .collect::<Vec<_>>(),
    )?;
    thread::sleep(Duration::from_millis(300));
    done.synacks_seen = tap.synacks();
    Ok(done)
}

/// The counters of the accept queues that the network service says on the
/// console (`net: queues ...`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Queues {
    pub syn_dropped: u64,
    pub queue_reaped: u64,
    pub embryo_recycled: u64,
    pub key_stale: u64,
}

fn field(line: &str, name: &str) -> Option<u64> {
    let mut words = line.split_whitespace();
    words.find(|w| *w == name)?;
    words.next()?.parse().ok()
}

/// The counters as the last lines of `lines` say them (zero before any).
pub fn latest(lines: &[String]) -> Queues {
    let mut q = Queues::default();
    for l in lines.iter().filter(|l| l.contains("net: queues ")) {
        for (name, slot) in [
            ("syn_dropped", &mut q.syn_dropped),
            ("queue_reaped", &mut q.queue_reaped),
            ("embryo_recycled", &mut q.embryo_recycled),
            ("key_stale", &mut q.key_stale),
        ] {
            if let Some(n) = field(l, name) {
                *slot = n;
            }
        }
    }
    q
}

/// What the scan must have changed: the SYNs past the room are dropped, the
/// established connections that were reset are reaped, and a SYN that found
/// a socket back in LISTEN with the key of its last connection replaced the
/// key. `embryo_recycled` is for the report: the forwarding's own RSTs may
/// have reset the half-open sockets before the second flood found them.
pub fn judge(before: Queues, after: Queues) -> Result<(), String> {
    let mut missing = Vec::new();
    for (name, b, a) in [
        ("syn_dropped", before.syn_dropped, after.syn_dropped),
        ("queue_reaped", before.queue_reaped, after.queue_reaped),
        ("key_stale", before.key_stale, after.key_stale),
    ] {
        if a <= b {
            missing.push(format!("{name} {b} -> {a}"));
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("the scan did not change: {}", missing.join(", ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &[&str]) -> Vec<String> {
        text.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn the_counters_are_the_last_values_said() {
        let l = lines(&[
            "net: queues syn_dropped 1 queue_reaped 2 embryo_recycled 3",
            "net: queues sockets 9 of 256 demux 4 listen_short 0 key_stale 5 syn_stray 0 orphan_reused 0 set_barred 0",
            "net: listener place 3 port 80 syn_dropped 1 queue_reaped 2 embryo_recycled 3",
            "net: queues syn_dropped 10 queue_reaped 20 embryo_recycled 30",
            "net: queues sockets 9 of 256 demux 4 listen_short 0 key_stale 50 syn_stray 0 orphan_reused 0 set_barred 0",
        ]);
        assert_eq!(
            latest(&l),
            Queues {
                syn_dropped: 10,
                queue_reaped: 20,
                embryo_recycled: 30,
                key_stale: 50
            }
        );
        assert_eq!(latest(&[]), Queues::default());
    }

    #[test]
    fn the_judgement_names_each_counter_that_stood() {
        let before = Queues {
            syn_dropped: 1,
            queue_reaped: 2,
            embryo_recycled: 3,
            key_stale: 4,
        };
        let mut after = Queues {
            syn_dropped: 5,
            queue_reaped: 6,
            embryo_recycled: 3,
            key_stale: 7,
        };
        assert!(judge(before, after).is_ok());
        after.key_stale = 4;
        after.syn_dropped = 1;
        let e = judge(before, after).unwrap_err();
        assert!(
            e.contains("key_stale 4 -> 4") && e.contains("syn_dropped 1 -> 1"),
            "{e}"
        );
        assert!(!e.contains("queue_reaped"), "{e}");
    }

    #[test]
    fn the_isn_differs_by_port_and_the_rst_follows_it() {
        assert_ne!(isn(30001), isn(30002));
        let f = rst(30001, 80, isn(30001));
        let Frame::Tcp { seq, flags, .. } = rawframe::parse(&f) else {
            panic!()
        };
        assert_eq!((seq, flags), (isn(30001).wrapping_add(1), RST));
    }

    #[test]
    fn the_filters_name_the_backend_of_qemu_net() {
        let a = qemu_args(&paths(Path::new("/x"))).join(" ");
        assert!(a.contains("filter-redirector,id=scan-f-in,netdev=n0,queue=tx,indev=scan-in"));
        assert!(a.contains("filter-mirror,id=scan-f-out,netdev=n0,queue=rx,outdev=scan-out"));
        assert!(crate::qemu::net(&[]).join(" ").contains("user,id=n0"));
        assert_eq!(crate::qemu::NET_MAC, "52:54:00:12:34:56");
    }

    #[test]
    fn the_mirror_is_drained_always_and_read_only_while_recording() {
        use std::os::unix::net::UnixListener;
        let dir = std::env::temp_dir().join(format!("sr{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = paths(&dir);
        let (_inject, mirror) = (
            UnixListener::bind(&p.inject).unwrap(),
            UnixListener::bind(&p.mirror).unwrap(),
        );
        let tap = Tap::connect(&p).unwrap();
        let (mut qemu, _) = mirror.accept().unwrap();
        let synack = |port: u16| {
            rawframe::framed(
                &Segment {
                    src_mac: GUEST_MAC,
                    dst_mac: PEER_MAC,
                    src_ip: GUEST_IP,
                    dst_ip: PEER_IP,
                    src_port: 80,
                    dst_port: port,
                    seq: 9,
                    ack: 1,
                    flags: SYN | ACK,
                }
                .frame(),
            )
        };
        let waits = |f: &dyn Fn() -> bool| {
            for _ in 0..100 {
                if f() {
                    return true;
                }
                thread::sleep(Duration::from_millis(20));
            }
            false
        };
        qemu.write_all(&synack(5000)).unwrap();
        thread::sleep(Duration::from_millis(200));
        assert_eq!(tap.synack(5000, 80), None);
        tap.record(true);
        qemu.write_all(&synack(5001)).unwrap();
        assert!(waits(&|| tap.synack(5001, 80) == Some(9)));
        assert_eq!(tap.frames(), 1);
        assert!(
            tap.facts()
                .contains("TCP [10, 0, 2, 15]:80 > [10, 0, 2, 77]:5001"),
            "{}",
            tap.facts()
        );
        qemu.write_all(&rawframe::framed(&rawframe::arp_reply(
            GUEST_MAC, GUEST_IP, PEER_MAC, PEER_IP,
        )))
        .unwrap();
        assert!(waits(&|| tap.facts().contains("ARP reply came")));
        tap.forget();
        assert_eq!(tap.frames(), 0);
        assert_eq!(tap.synack(5000, 80), None);
        drop(qemu);
        assert!(waits(&|| tap.ended.load(Ordering::SeqCst)));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_socket_is_named() {
        let dir = std::env::temp_dir().join(format!("sn{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = paths(&dir);
        let e = connect("mirror", &p.mirror, Duration::from_millis(100)).unwrap_err();
        assert!(
            e.contains("mirror socket") && e.contains("scan-out.sock"),
            "{e}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
