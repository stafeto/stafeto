// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The tickets of the fast sockets (spec 6, 3.9): a socket made before the
//! stack runs in the process is a record of this table, under a number from
//! `FAST_BASE + FAST_MAX` up. The record keeps what the stack will need to
//! make the socket: the address, the backlog, the options the programs set
//! and the descriptor flags. A process that makes its listeners before it
//! forks (nginx's main process) hands its children the records with its
//! memory, and each child makes the sockets of the stack at its first call
//! that starts the stack. Nothing here calls the kernel or the stack, so the
//! host tests run it (`xtask`, `fast_events_tests`).

use crate::fast_events::{FAST_TICKETS, SOCKADDR_IN};

const EINVAL: i32 = 22;
const EMFILE: i32 = 24;
const ENOPROTOOPT: i32 = 92;
const EADDRINUSE: i32 = 98;
const ENOMEM: i32 = 12;

const SOL_SOCKET: i32 = 1;
const IPPROTO_TCP: i32 = 6;
pub const SO_REUSEADDR: i32 = 2;
pub const SO_TYPE: i32 = 3;
pub const SO_ERROR: i32 = 4;
pub const SO_SNDBUF: i32 = 7;
pub const SO_RCVBUF: i32 = 8;
pub const SO_KEEPALIVE: i32 = 9;
pub const SO_REUSEPORT: i32 = 15;
pub const TCP_NODELAY: i32 = 1;
pub const TCP_KEEPIDLE: i32 = 4;
pub const TCP_KEEPINTVL: i32 = 5;
pub const TCP_KEEPCNT: i32 = 6;
const SOCK_STREAM: i32 = 1;

/// The options a ticket keeps, (level, name) of Linux; the stack gets them
/// when it makes the socket.
pub const OPTIONS: [(i32, i32); 9] = [
    (SOL_SOCKET, SO_REUSEADDR),
    (SOL_SOCKET, SO_REUSEPORT),
    (SOL_SOCKET, SO_KEEPALIVE),
    (SOL_SOCKET, SO_RCVBUF),
    (SOL_SOCKET, SO_SNDBUF),
    (IPPROTO_TCP, TCP_NODELAY),
    (IPPROTO_TCP, TCP_KEEPIDLE),
    (IPPROTO_TCP, TCP_KEEPINTVL),
    (IPPROTO_TCP, TCP_KEEPCNT),
];
const REUSEPORT: usize = 1;
/// A buffer size the ticket reports when the program set none.
const BUFFER_DEFAULT: i32 = 65_536;

/// `socket` of a ticket not made yet, and one the stack refused.
pub const NOT_MADE: i32 = -1;
pub const REFUSED: i32 = -2;
/// `hold` of a ticket that holds no port with the switch.
pub const NO_HOLD: i32 = -1;

/// One ticket.
#[derive(Clone, Copy)]
pub struct Ticket {
    pub used: bool,
    /// The `sockaddr_in` the program bound, if it did.
    pub address: Option<[u8; SOCKADDR_IN]>,
    /// The backlog of the last `listen`, if there was one.
    pub backlog: Option<i32>,
    pub options: [Option<i32>; OPTIONS.len()],
    pub cloexec: bool,
    pub clofork: bool,
    /// The number of the socket of the stack once it is made, `NOT_MADE`
    /// before, `REFUSED` when the stack refused (then `error` is why).
    pub socket: i32,
    pub error: i32,
    /// The descriptor of the process that holds the port of the bind with
    /// the network service's switch (PORT_HOLD), `NO_HOLD` for none: the
    /// stack's worker joins the group with it, and the descriptor goes with
    /// the ticket.
    #[allow(dead_code)] // read by fastnet.rs, which the host tests of xtask do not build
    pub hold: i32,
}

impl Ticket {
    /// The ticket's SO_REUSEPORT.
    #[allow(dead_code)] // used by fastnet.rs
    pub fn reuseport(&self) -> bool {
        self.options[REUSEPORT].is_some_and(|v| v != 0)
    }

    const FREE: Ticket = Ticket {
        used: false,
        address: None,
        backlog: None,
        options: [None; OPTIONS.len()],
        cloexec: false,
        clofork: false,
        socket: NOT_MADE,
        error: 0,
        hold: NO_HOLD,
    };

    fn option(&self, level: i32, name: i32) -> Option<i32> {
        slot(level, name).and_then(|i| self.options[i])
    }
}

fn slot(level: i32, name: i32) -> Option<usize> {
    OPTIONS.iter().position(|&o| o == (level, name))
}

/// The port and the address of a `sockaddr_in`.
fn port_of(a: &[u8; SOCKADDR_IN]) -> [u8; 2] {
    [a[2], a[3]]
}
fn host_of(a: &[u8; SOCKADDR_IN]) -> [u8; 4] {
    [a[4], a[5], a[6], a[7]]
}

/// The table of the process.
pub struct Tickets {
    pub slots: [Ticket; FAST_TICKETS as usize],
}

impl Tickets {
    pub const fn new() -> Self {
        Tickets {
            slots: [Ticket::FREE; FAST_TICKETS as usize],
        }
    }

    /// A new ticket: its index, EMFILE when all are in use.
    pub fn open(&mut self, cloexec: bool, clofork: bool) -> Result<usize, i32> {
        let at = self.slots.iter().position(|t| !t.used).ok_or(EMFILE)?;
        self.slots[at] = Ticket {
            used: true,
            cloexec,
            clofork,
            ..Ticket::FREE
        };
        Ok(at)
    }

    /// `bind`: the address is kept. EINVAL for a second bind; EADDRINUSE
    /// when another ticket holds an overlapping address and port (the same
    /// address or either one the wildcard) and the two do not both set
    /// `SO_REUSEPORT`. Port 0 is any port and never conflicts.
    pub fn bind(&mut self, at: usize, address: [u8; SOCKADDR_IN]) -> Result<(), i32> {
        if self.slots[at].address.is_some() {
            return Err(EINVAL);
        }
        let port = port_of(&address);
        if port != [0, 0] {
            let mine = self.slots[at].options[REUSEPORT].is_some_and(|v| v != 0);
            for (i, other) in self.slots.iter().enumerate() {
                let Some(held) = other.address.filter(|_| other.used && i != at) else {
                    continue;
                };
                let overlap = port_of(&held) == port
                    && (host_of(&held) == host_of(&address)
                        || host_of(&held) == [0; 4]
                        || host_of(&address) == [0; 4]);
                let theirs = other.options[REUSEPORT].is_some_and(|v| v != 0);
                if overlap && !(mine && theirs) {
                    return Err(EADDRINUSE);
                }
            }
        }
        self.slots[at].address = Some(address);
        Ok(())
    }

    /// `listen`: the backlog is kept, the last call wins.
    pub fn listen(&mut self, at: usize, backlog: i32) {
        self.slots[at].backlog = Some(backlog);
    }

    /// `setsockopt`: the options the table names are kept (an int); the rest
    /// is ENOPROTOOPT, a value shorter than an int EINVAL.
    pub fn set_option(
        &mut self,
        at: usize,
        level: i32,
        name: i32,
        value: &[u8],
    ) -> Result<(), i32> {
        let Some(i) = slot(level, name) else {
            return Err(ENOPROTOOPT);
        };
        let Some(bytes) = value.first_chunk::<4>() else {
            return Err(EINVAL);
        };
        self.slots[at].options[i] = Some(i32::from_ne_bytes(*bytes));
        Ok(())
    }

    /// `getsockopt`: the kept options, `SO_TYPE` and `SO_ERROR`; the value
    /// as an int. ENOPROTOOPT for the rest.
    pub fn option(&self, at: usize, level: i32, name: i32) -> Result<i32, i32> {
        let t = &self.slots[at];
        if level == SOL_SOCKET && name == SO_TYPE {
            return Ok(SOCK_STREAM);
        }
        if level == SOL_SOCKET && name == SO_ERROR {
            return Ok(0);
        }
        if slot(level, name).is_none() {
            return Err(ENOPROTOOPT);
        }
        Ok(t.option(level, name).unwrap_or(
            if level == SOL_SOCKET && (name == SO_RCVBUF || name == SO_SNDBUF) {
                BUFFER_DEFAULT
            } else {
                0
            },
        ))
    }

    /// `getsockname`: the bound address, or the wildcard of port 0.
    pub fn name(&self, at: usize) -> [u8; SOCKADDR_IN] {
        self.slots[at].address.unwrap_or_else(|| {
            let mut a = [0u8; SOCKADDR_IN];
            a[0] = crate::fast_events::AF_INET as u8;
            a
        })
    }

    /// `close`: the ticket is free.
    pub fn close(&mut self, at: usize) {
        self.slots[at] = Ticket::FREE;
    }

    /// The child of a `fork`: the tickets with `FD_CLOFORK` go.
    pub fn after_fork(&mut self) {
        for t in &mut self.slots {
            if t.used && t.clofork {
                *t = Ticket::FREE;
            }
        }
    }

    /// `ENOMEM` of a request nothing here makes: the stack's refusal to make
    /// a socket for a ticket is recorded with `refuse`.
    pub fn refuse(&mut self, at: usize, errno: i32) {
        self.slots[at].socket = REFUSED;
        self.slots[at].error = if errno == 0 { ENOMEM } else { errno };
    }
}

impl Default for Tickets {
    fn default() -> Self {
        Self::new()
    }
}
