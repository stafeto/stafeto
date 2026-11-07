// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The command rings between the stack thread and the switch thread: the
//! stack decides (sessions, the port registry, the blocks, the numbers of
//! consumers and groups) and asks; the switch writes the tables and
//! answers what the stack must know. One writer and one reader on each.

use super::ring::{ConsumerRing, Mem, Violation};
use super::tables::Tables;
use crate::ports::Proto;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU32, Ordering};
use proto_net::switch::Layout;

pub const RING: usize = 64;
/// Commands one step applies at most.
pub const PER_STEP: usize = 4;

/// A ring of `N` values of `T` with one writing thread and one reading
/// thread, as `spsc::Spsc` is for words.
pub struct Queue<T: Copy, const N: usize> {
    head: AtomicU32,
    tail: AtomicU32,
    slots: UnsafeCell<[MaybeUninit<T>; N]>,
}

// SAFETY: one thread writes a slot before it publishes the tail, one reads it before it publishes the head.
unsafe impl<T: Copy + Send, const N: usize> Sync for Queue<T, N> {}

impl<T: Copy, const N: usize> Queue<T, N> {
    pub const fn new() -> Queue<T, N> {
        const { assert!(N.is_power_of_two()) };
        Queue {
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
            slots: UnsafeCell::new([const { MaybeUninit::uninit() }; N]),
        }
    }

    /// False when the ring is full.
    pub fn push(&self, v: T) -> bool {
        let tail = self.tail.load(Ordering::Relaxed);
        if tail.wrapping_sub(self.head.load(Ordering::Acquire)) as usize >= N {
            return false;
        }
        // SAFETY: the slot is the writer's until the tail passes it.
        unsafe {
            (self.slots.get() as *mut MaybeUninit<T>)
                .add(tail as usize % N)
                .write(MaybeUninit::new(v))
        };
        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        true
    }

    pub fn pop(&self) -> Option<T> {
        let head = self.head.load(Ordering::Relaxed);
        if head == self.tail.load(Ordering::Acquire) {
            return None;
        }
        // SAFETY: the writer filled the slot before it moved the tail.
        let v = unsafe {
            (self.slots.get() as *const MaybeUninit<T>)
                .add(head as usize % N)
                .read()
                .assume_init()
        };
        self.head.store(head.wrapping_add(1), Ordering::Release);
        Some(v)
    }
}

impl<T: Copy, const N: usize> Default for Queue<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Stack to switch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// A consumer: its number, generation and block come from the stack's books; the
    /// ring object is mapped at `base` for `Layout::new(rx_slots, tx_slots).total()` bytes.
    Attach {
        consumer: u8,
        generation: u8,
        base: usize,
        rx_slots: u16,
        tx_slots: u16,
        block: u16,
    },
    Detach {
        consumer: u8,
    },
    /// Group `group` (1..=32) holds the ports, or has one more holder.
    Hold {
        group: u8,
        proto: Proto,
        first: u16,
        count: u8,
    },
    Release {
        group: u8,
    },
    Join {
        group: u8,
        consumer: u8,
    },
    Leave {
        group: u8,
        consumer: u8,
    },
    Address {
        ip: [u8; 4],
        prefix: u8,
    },
}

/// Switch to stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Back {
    /// The consumer is out of the tables (also an ATTACH that could not be carried out).
    Detached { consumer: u8, generation: u8 },
    /// The consumer broke a rule of its ring; the stack detaches it.
    Broken { consumer: u8, violation: Violation },
}

pub struct Commands {
    pub to_switch: Queue<Command, RING>,
    pub to_stack: Queue<Back, RING>,
}

impl Commands {
    pub const fn new() -> Commands {
        Commands {
            to_switch: Queue::new(),
            to_stack: Queue::new(),
        }
    }
}

impl Default for Commands {
    fn default() -> Commands {
        Commands::new()
    }
}

/// Applies at most `PER_STEP` commands; returns how many.
pub fn drain(t: &mut Tables, q: &Commands) -> usize {
    t.guard.check();
    let mut n = 0;
    while n < PER_STEP {
        let Some(cmd) = q.to_switch.pop() else { break };
        apply(t, cmd, &q.to_stack);
        n += 1;
    }
    n
}

fn apply(t: &mut Tables, cmd: Command, back: &Queue<Back, RING>) {
    match cmd {
        Command::Attach {
            consumer,
            generation,
            base,
            rx_slots,
            tx_slots,
            block,
        } => {
            let ring = Layout::new(u32::from(rx_slots), u32::from(tx_slots)).map(|l| {
                // SAFETY: the stack mapped the object at `base` for the whole layout, page aligned.
                ConsumerRing::new(unsafe { Mem::new(base as *mut u8, l.total()) }, l)
            });
            if !ring.is_some_and(|r| t.attach(consumer, generation, r, block)) {
                back.push(Back::Detached {
                    consumer,
                    generation,
                });
            }
        }
        Command::Detach { consumer } => {
            if let Some(generation) = t.detach(consumer) {
                back.push(Back::Detached {
                    consumer,
                    generation,
                });
            }
        }
        Command::Hold {
            group,
            proto,
            first,
            count,
        } => {
            t.hold(group, proto, first, count);
        }
        Command::Release { group } => t.release(group),
        Command::Join { group, consumer } => {
            t.join(group, consumer);
        }
        Command::Leave { group, consumer } => t.leave(group, consumer),
        Command::Address { ip, prefix } => (t.own.ip, t.own.prefix) = (ip, prefix),
    }
}

/// Reads every ring's indices once and tells the stack of the rings that broke.
pub fn poll(t: &mut Tables, q: &Commands) {
    t.poll_rings(|consumer, violation| {
        q.to_stack.push(Back::Broken {
            consumer,
            violation,
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::switchlogic::ring::tests::Rig;
    use crate::switchlogic::tables::tests::with;
    use proto_net::switch as sw;

    #[test]
    fn the_queue_keeps_order_and_refuses_when_full() {
        let q = Queue::<u32, 64>::new();
        assert!((0..64).all(|i| q.push(i)));
        assert!(!q.push(64));
        assert_eq!((q.pop(), q.pop()), (Some(0), Some(1)));
        assert!(q.push(64));
        assert_eq!(core::iter::from_fn(|| q.pop()).count(), 63);
    }

    #[test]
    fn a_step_applies_four_commands() {
        with(|t, _| {
            let q = Commands::new();
            for g in 3..=8 {
                assert!(q.to_switch.push(Command::Hold {
                    group: g,
                    proto: Proto::Tcp,
                    first: 100 + u16::from(g),
                    count: 1
                }));
            }
            assert_eq!(drain(t, &q), 4);
            assert!(t.group(6).is_some() && t.group(7).is_none());
            assert_eq!(drain(t, &q), 2);
            assert_eq!(drain(t, &q), 0);
        });
    }

    #[test]
    fn the_stack_changes_the_tables_only_through_the_ring() {
        with(|t, _| {
            let q = Commands::new();
            t.claim();
            q.to_switch.push(Command::Address {
                ip: [10, 1, 1, 1],
                prefix: 16,
            });
            q.to_switch.push(Command::Hold {
                group: 5,
                proto: Proto::Udp,
                first: 99,
                count: 2,
            });
            q.to_switch.push(Command::Join {
                group: 5,
                consumer: 2,
            });
            q.to_switch.push(Command::Leave {
                group: 5,
                consumer: 2,
            });
            q.to_switch.push(Command::Release { group: 5 });
            // A thread other than the switch pushes; the switch applies.
            std::thread::scope(|s| {
                s.spawn(|| {
                    q.to_switch.push(Command::Hold {
                        group: 6,
                        proto: Proto::Tcp,
                        first: 7,
                        count: 1,
                    })
                });
            });
            while drain(t, &q) > 0 {}
            assert_eq!((t.own.ip, t.own.prefix), ([10, 1, 1, 1], 16));
            assert!(t.group(5).is_none() && t.group(6).is_some());
        });
    }

    #[test]
    fn attach_and_detach_answer_with_the_generation() {
        with(|t, _| {
            let q = Commands::new();
            let rig = Rig::new(Layout::DEFAULT);
            let attach = |consumer, block, rx_slots| Command::Attach {
                consumer,
                generation: 9,
                base: rig.buf.as_ptr() as usize,
                rx_slots,
                tx_slots: 512,
                block,
            };
            q.to_switch.push(attach(5, 52224, 2048));
            q.to_switch.push(attach(5, 52224, 2048));
            q.to_switch.push(attach(6, 0, 100));
            q.to_switch.push(Command::Detach { consumer: 5 });
            q.to_switch.push(Command::Detach { consumer: 5 });
            while drain(t, &q) > 0 {}
            let back: Vec<Back> = core::iter::from_fn(|| q.to_stack.pop()).collect();
            assert_eq!(
                back,
                [
                    Back::Detached {
                        consumer: 5,
                        generation: 9
                    },
                    Back::Detached {
                        consumer: 6,
                        generation: 9
                    },
                    Back::Detached {
                        consumer: 5,
                        generation: 9
                    },
                ]
            );
            assert_eq!(
                rig.mem().load(sw::SIZES + 4),
                2048,
                "the sizes are on line 0"
            );
        });
    }

    #[test]
    fn a_broken_ring_is_told_to_the_stack_once() {
        with(|t, rigs| {
            let q = Commands::new();
            rigs[1].mem().store(sw::TX_HEAD, 9999);
            poll(t, &q);
            poll(t, &q);
            assert_eq!(
                q.to_stack.pop(),
                Some(Back::Broken {
                    consumer: 1,
                    violation: Violation::Tx
                })
            );
            assert_eq!(q.to_stack.pop(), None);
            assert!(!t.live(1, 1) && t.live(0, 1));
        });
    }
}
