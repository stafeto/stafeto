// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The command rings between the stack thread and the switch thread: the
//! stack decides (sessions, the port registry, the blocks, the numbers of
//! consumers and groups) and asks; the switch writes the tables and
//! answers what the stack must know. One writer and one reader on each.

use super::ring::{ConsumerRing, Mem, Violation};
use super::tables::{MAX_CONSUMERS, MAX_GROUPS, Tables};
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

    pub fn len(&self) -> usize {
        self.tail
            .load(Ordering::Acquire)
            .wrapping_sub(self.head.load(Ordering::Acquire)) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
        generation: u32,
        base: usize,
        rx_slots: u16,
        tx_slots: u16,
        block: u16,
        /// The raw handle of the consumer's channel (NOTIFY) in the stack's handle table; the
        /// stack keeps it open until it hears `Back::Detached`.
        wake: u64,
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
    /// One holder less. When the last lets go, the group ends (at once, or after its flows
    /// when it has some) and the switch answers with `Back::Freed`.
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
    /// `round` is the sweep's round counter at that moment: its flows are all gone when a
    /// later `Swept` says `round + 2` (`Blocks::detached`).
    Detached {
        consumer: u8,
        generation: u32,
        round: u32,
    },
    /// An ATTACH the switch could not carry out (bad ring memory, number in use): the stack
    /// unmaps the object and gives the number back at once, since no flow was ever made.
    Refused { consumer: u8, generation: u32 },
    /// A HOLD or JOIN the tables refused (the stack's books and the tables disagree).
    Failed { group: u8 },
    /// The sweep finished a pass over the flow table; sent when the round counter moved
    /// (it may skip numbers when the ring was full). The stack hands it to `Blocks::swept`.
    Swept { round: u32 },
    /// The consumer broke a rule of its ring; the stack detaches it.
    Broken { consumer: u8, violation: Violation },
    /// The group is gone from the tables and its ports are free. Exactly one per group that
    /// lost its last holder. The stack keeps the group number and the entry of its port
    /// registry until it hears this: flows of the port can outlive the last holder (a
    /// worker that closed its listening socket still serves its connections), and a new
    /// `bind` of the port before then would get their segments.
    Freed { group: u8 },
}

/// Answers to the stack: pushed, or kept in `Tables::owed` until the ring has room.
fn send(t: &mut Tables, back: &Queue<Back, RING>, b: Back) {
    if !back.push(b) {
        match t.owed.iter_mut().find(|s| s.is_none()) {
            Some(slot) => *slot = Some(b),
            // `drain` applies nothing while an answer is owed, and a ring breaks once.
            None => debug_assert!(false, "more answers owed than there are places"),
        }
    }
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
///
/// While an answer to the stack is owed (its ring was full) nothing is applied, so the
/// owed answers stay few.
pub fn drain(t: &mut Tables, q: &Commands) -> usize {
    t.guard.check();
    let mut n = 0;
    while n < PER_STEP && t.owed.iter().all(Option::is_none) {
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
            wake,
        } => {
            let ring = Layout::new(u32::from(rx_slots), u32::from(tx_slots)).and_then(|l| {
                // SAFETY: the stack mapped the object at `base` for the whole layout, page aligned.
                ConsumerRing::new(unsafe { Mem::new(base as *mut u8, l.total()) }, l)
            });
            if !ring.is_some_and(|r| t.attach(consumer, generation, r, block)) {
                send(
                    t,
                    back,
                    Back::Refused {
                        consumer,
                        generation,
                    },
                );
            } else if let Some(Some(c)) = t.consumers.get_mut(usize::from(consumer)) {
                c.wake = wake;
            }
        }
        Command::Detach { consumer } => {
            if let Some(generation) = t.detach(consumer) {
                let round = t.flows.rounds();
                send(
                    t,
                    back,
                    Back::Detached {
                        consumer,
                        generation,
                        round,
                    },
                );
            }
        }
        Command::Hold {
            group,
            proto,
            first,
            count,
        } => {
            if !t.hold(group, proto, first, count) {
                send(t, back, Back::Failed { group });
            }
        }
        Command::Release { group } => t.release(group),
        Command::Join { group, consumer } => {
            if !t.join(group, consumer) {
                send(t, back, Back::Failed { group });
            }
        }
        Command::Leave { group, consumer } => t.leave(group, consumer),
        Command::Address { ip, prefix } => t.set_address(ip, prefix),
    }
}

/// Reads every ring's indices once and tells the stack of the rings that broke.
pub fn poll(t: &mut Tables, q: &Commands) {
    // Answers the stack's ring had no room for go first.
    for slot in t.owed.iter_mut() {
        if let Some(b) = *slot
            && q.to_stack.push(b)
        {
            *slot = None;
        }
    }
    let mut broke = [None; MAX_CONSUMERS];
    t.poll_rings(|consumer, violation| broke[usize::from(consumer)] = Some(violation));
    for (consumer, v) in broke.iter().enumerate() {
        if let Some(violation) = *v {
            send(
                t,
                &q.to_stack,
                Back::Broken {
                    consumer: consumer as u8,
                    violation,
                },
            );
        }
    }
    let round = t.flows.rounds();
    if round != t.swept_told && q.to_stack.push(Back::Swept { round }) {
        t.swept_told = round;
    }
    // A bit stays until the stack's ring took the answer.
    for group in 1..=MAX_GROUPS as u8 {
        if t.freed & (1 << (group - 1)) != 0 && q.to_stack.push(Back::Freed { group }) {
            t.freed &= !(1 << (group - 1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::switchlogic::ring::tests::Rig;
    use crate::switchlogic::tables::tests::{with, with_flows};
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
                wake: 0,
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
                    Back::Refused {
                        consumer: 5,
                        generation: 9
                    },
                    Back::Refused {
                        consumer: 6,
                        generation: 9
                    },
                    Back::Detached {
                        consumer: 5,
                        generation: 9,
                        round: 0
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
    fn a_freed_group_is_told_once_and_kept_until_the_ring_has_room() {
        with(|t, _| {
            let q = Commands::new();
            q.to_switch.push(Command::Release { group: 1 });
            q.to_switch.push(Command::Release { group: 2 });
            while drain(t, &q) > 0 {}
            for _ in 0..RING - 1 {
                assert!(q.to_stack.push(Back::Freed { group: 9 }));
            }
            poll(t, &q);
            assert_eq!(t.freed, 0b10, "the second does not fit");
            assert_eq!(q.to_stack.pop(), Some(Back::Freed { group: 9 }));
            poll(t, &q);
            poll(t, &q);
            let back: Vec<Back> = core::iter::from_fn(|| q.to_stack.pop()).collect();
            assert_eq!(
                back.iter()
                    .filter(|b| **b == Back::Freed { group: 1 })
                    .count(),
                1
            );
            assert_eq!(
                back.iter()
                    .filter(|b| **b == Back::Freed { group: 2 })
                    .count(),
                1
            );
            assert_eq!(t.freed, 0);
        });
    }

    #[test]
    fn the_sweep_rounds_are_told_with_the_detached_round() {
        with_flows(512, |t, _| {
            let q = Commands::new();
            (0..512 / crate::switchlogic::tables::SWEEP_STEP).for_each(|_| t.sweep());
            poll(t, &q);
            assert_eq!(q.to_stack.pop(), Some(Back::Swept { round: 1 }));
            poll(t, &q);
            assert_eq!(q.to_stack.pop(), None, "told once");
            q.to_switch.push(Command::Detach { consumer: 1 });
            while drain(t, &q) > 0 {}
            assert_eq!(
                q.to_stack.pop(),
                Some(Back::Detached {
                    consumer: 1,
                    generation: 1,
                    round: 1
                })
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

    #[test]
    fn answers_the_ring_could_not_take_are_kept_and_sent_later_and_nothing_applies_meanwhile() {
        with(|t, _| {
            let q = Commands::new();
            // The stack's ring is full of answers.
            for _ in 0..RING {
                assert!(q.to_stack.push(Back::Swept { round: 0 }));
            }
            let rig = Rig::new(Layout::DEFAULT);
            q.to_switch.push(Command::Attach {
                consumer: 1,
                generation: 4,
                base: rig.buf.as_ptr() as usize,
                rx_slots: 100,
                tx_slots: 512,
                block: 0,
                wake: 0,
            });
            q.to_switch.push(Command::Hold {
                group: 9,
                proto: Proto::Tcp,
                first: 99,
                count: 1,
            });
            assert_eq!(drain(t, &q), 1);
            assert!(t.owed.iter().any(Option::is_some), "the refusal is owed");
            assert_eq!(drain(t, &q), 0, "nothing applies while an answer is owed");
            while q.to_stack.pop().is_some() {}
            poll(t, &q);
            assert_eq!(
                q.to_stack.pop(),
                Some(Back::Refused {
                    consumer: 1,
                    generation: 4
                })
            );
            assert_eq!(drain(t, &q), 1, "the hold goes now");
            assert!(t.group(9).is_some());
        });
    }

    #[test]
    fn a_hold_on_a_taken_port_and_a_join_of_nobody_are_told_to_the_stack() {
        with(|t, _| {
            let q = Commands::new();
            // 8080 is group 1's already.
            q.to_switch.push(Command::Hold {
                group: 9,
                proto: Proto::Tcp,
                first: 8080,
                count: 1,
            });
            q.to_switch.push(Command::Join {
                group: 31,
                consumer: 0,
            });
            while drain(t, &q) > 0 {}
            assert_eq!(q.to_stack.pop(), Some(Back::Failed { group: 9 }));
            assert_eq!(q.to_stack.pop(), Some(Back::Failed { group: 31 }));
        });
    }
}
