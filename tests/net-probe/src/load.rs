// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The network loads of the frame-time probe (stage of the frame clock), the
//! roles `L` and `K` of the probe:
//!
//! - `L`: a TCP connection through the loopback of the service, 64 KiB there and
//!   64 KiB back, again and again, from the start of the first phase that has the
//!   network load to the end of the last one (the phases are those of
//!   `frame_load::phases`, which every load reads, so it starts and stops with
//!   the others). It prints `net-probe: load rounds N bytes B`.
//! - `K`: a sink for the stream the host sends through a forwarded port in the
//!   hour on HVF (`cargo xtask frame-hour`): it listens on port 7001, takes the
//!   one connection and reads it until the end of the schedule, and prints
//!   `net-probe: sink bytes B`.
//!
//! The letters differ from the plan's `l` and `k`, which are taken by roles of
//! this probe (the listeners, the restart of the service).

use abi::MESSAGE_MAX;
use frame_load::loads::{NET_PIECE, NET_ROUND};
use frame_load::phases::{Phase, Schedule};
use proto_net::sockets::{self, Request};
use proto_net::{AGAIN, Address};

use super::{Probe, is, ready, socket_call};

/// The port of the sink.
const SINK_PORT: u32 = 7001;
/// The loopback ports of the load.
const LOAD_PORT: u32 = 9300;

impl Probe<'_> {
    /// Sleeps until the clock of the guest reaches `deadline` (ns).
    fn sleep_to(&self, deadline: u64) {
        let now = self.now();
        if deadline > now {
            self.sleep(deadline - now);
        }
    }

    /// Role `L`.
    pub(super) fn loopback_load(&self) -> Result<(), &'static str> {
        let schedule = Schedule::DEFAULT;
        let net = self.connect()?;
        // The connection is made before the phase, so the phase has the rounds
        // and nothing of the set-up.
        let listener = self
            .new_socket(&net, sockets::STREAM)
            .map_err(|_| "SOCKET failed")?;
        self.bind(&net, listener, [127, 0, 0, 1], LOAD_PORT)
            .map_err(|_| "BIND failed")?;
        self.plain(
            &net,
            Request::Listen {
                description: listener,
                backlog: 1,
            },
        )
        .map_err(|_| "LISTEN failed")?;
        let client = self
            .new_socket(&net, sockets::STREAM)
            .map_err(|_| "SOCKET failed")?;
        self.connect_wait(&net, client, Address::v4([127, 0, 0, 1], LOAD_PORT))?;
        let mut buffer = [0; MESSAGE_MAX];
        let len = self
            .nonblocking(super::PAUSE_NS, || {
                socket_call(
                    &net,
                    &Request::Accept {
                        key: None,
                        description: listener,
                        flags: sockets::NONBLOCK,
                    },
                    &mut buffer,
                )
                .map(|b| b.len())
            })
            .map_err(|_| "ACCEPT failed")?;
        let (server, _) =
            sockets::read_accepted(ready(&buffer[..len]).map_err(|_| "ACCEPT's reply")?)
                .map_err(|_| "ACCEPT's data")?;
        // The loop runs in the phases that have the load.
        let end = (frame_load::phases::ORDER)
            .iter()
            .filter(|p| p.loads().net)
            .map(|&p| schedule.end_of(p))
            .max()
            .ok_or("no phase has the network load")?;
        let first = schedule
            .next_wanted(0, |p| p.loads().net)
            .ok_or("no phase has the network load")?;
        self.sleep_to(schedule.start_of(first));
        let (mut rounds, mut bytes) = (0u64, 0u64);
        while self.now() < end {
            // Far from the loop's phases the loop sleeps; between two phases that
            // have the load there is none.
            let phase = schedule.at(self.now());
            if !phase.is_some_and(|p: Phase| p.loads().net) {
                break;
            }
            bytes += self.round(&net, client, server)?;
            rounds += 1;
        }
        rt::println!("net-probe: load rounds {rounds} bytes {bytes}");
        self.close(&net, client).map_err(|_| "CLOSE failed")?;
        self.close(&net, server).map_err(|_| "CLOSE failed")?;
        self.close(&net, listener).map_err(|_| "CLOSE failed")?;
        Ok(())
    }

    /// One round: `NET_ROUND` bytes from `from` to `to` in pieces, and the same
    /// back. The bytes that came.
    fn round(
        &self,
        net: &rt::Handle<rt::handle::Channel>,
        client: u32,
        server: u32,
    ) -> Result<u64, &'static str> {
        let mut total = 0u64;
        for (from, to) in [(client, server), (server, client)] {
            let data = [0xA7u8; NET_PIECE];
            let (mut sent, mut taken) = (0usize, 0usize);
            while taken < NET_ROUND {
                if sent < NET_ROUND {
                    let n = (NET_ROUND - sent).min(NET_PIECE);
                    let mut buffer = [0; MESSAGE_MAX];
                    let send = Request::Send {
                        key: None,
                        description: from,
                        flags: 0,
                        address: Address::NONE,
                        data: &data[..n],
                    };
                    match socket_call(net, &send, &mut buffer) {
                        Ok(reply) => {
                            sent += sockets::read_sent(ready(reply).map_err(|_| "SEND's reply")?)
                                .map_err(|_| "SEND's data")?
                                as usize;
                        }
                        Err(fail) if is(&fail, AGAIN) => {}
                        Err(_) => return Err("SEND failed"),
                    }
                }
                let mut buffer = [0; MESSAGE_MAX];
                let recv = Request::Recv {
                    key: None,
                    description: to,
                    flags: 0,
                    most: NET_PIECE as u32,
                };
                match socket_call(net, &recv, &mut buffer) {
                    Ok(reply) => {
                        let data = ready(reply).map_err(|_| "RECV's reply")?;
                        let (_, _, got) =
                            sockets::read_received(data).map_err(|_| "RECV's data")?;
                        taken += got.len();
                    }
                    Err(fail) if is(&fail, AGAIN) => self.sleep(super::PAUSE_NS),
                    Err(_) => return Err("RECV failed"),
                }
            }
            total += taken as u64;
        }
        Ok(total)
    }

    /// Role `K`.
    pub(super) fn sink(&self) -> Result<(), &'static str> {
        let schedule = Schedule::DEFAULT;
        let net = self.connect()?;
        let listener = self
            .new_socket(&net, sockets::STREAM)
            .map_err(|_| "SOCKET failed")?;
        self.bind(&net, listener, [0, 0, 0, 0], SINK_PORT)
            .map_err(|_| "BIND failed")?;
        self.plain(
            &net,
            Request::Listen {
                description: listener,
                backlog: 1,
            },
        )
        .map_err(|_| "LISTEN failed")?;
        let mut buffer = [0; MESSAGE_MAX];
        let len = self
            .nonblocking(super::PAUSE_NS, || {
                socket_call(
                    &net,
                    &Request::Accept {
                        key: None,
                        description: listener,
                        flags: sockets::NONBLOCK,
                    },
                    &mut buffer,
                )
                .map(|b| b.len())
            })
            .map_err(|_| "ACCEPT failed")?;
        let (stream, _) =
            sockets::read_accepted(ready(&buffer[..len]).map_err(|_| "ACCEPT's reply")?)
                .map_err(|_| "ACCEPT's data")?;
        let end = schedule.finish();
        let mut bytes = 0u64;
        while self.now() < end {
            let mut buffer = [0; MESSAGE_MAX];
            let recv = Request::Recv {
                key: None,
                description: stream,
                flags: 0,
                most: 1000,
            };
            match socket_call(&net, &recv, &mut buffer) {
                Ok(reply) => {
                    let data = ready(reply).map_err(|_| "RECV's reply")?;
                    let (_, _, got) = sockets::read_received(data).map_err(|_| "RECV's data")?;
                    if got.is_empty() {
                        break;
                    }
                    bytes += got.len() as u64;
                }
                Err(fail) if is(&fail, AGAIN) => self.sleep(super::PAUSE_NS),
                Err(_) => return Err("RECV failed"),
            }
        }
        rt::println!("net-probe: sink bytes {bytes}");
        self.close(&net, stream).map_err(|_| "CLOSE failed")?;
        self.close(&net, listener).map_err(|_| "CLOSE failed")?;
        Ok(())
    }
}
