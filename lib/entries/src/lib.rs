// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The decisions of the entry distributor of `rt` and of the hook of a long
//! jump, over plain numbers. One entry of a thread calls two handlers: the
//! resident handler of the layer first, with its own TLS, then the handler
//! of the program. The record of the thread has one word that says whether a
//! resident call is live, `outer`: the address of the frame of the entry
//! that made the call. The assembly of the distributor and of the hook in
//! relibc follow these functions step by step; the host tests run them.
//!
//! Stacks grow down. A frame is named by its lowest address. A call and
//! everything it calls lie below its frame.
#![no_std]
#![forbid(unsafe_code)]

/// The words of the entry record of a thread, as byte offsets from
/// `abi::msgbuf::ENTRIES` (the kernel never touches the record): the handler
/// of the program, the resident handler of the layer, the TLS of the
/// resident handler, `outer` (the frame of the live resident call, 0 for
/// none), flags, the exit hook, `owed` (nonzero when a nested entry left the
/// handler of the program to the entry of `outer`) and `thread` (a handle of
/// the thread itself with MANAGE, to give a request back to the kernel).
pub const ENTRY_OWN: usize = 0;
pub const ENTRY_RESIDENT: usize = 8;
pub const ENTRY_TLS: usize = 16;
pub const ENTRY_OUTER: usize = 24;
pub const ENTRY_FLAGS: usize = 32;
pub const ENTRY_HOOK: usize = 40;
pub const ENTRY_OWED: usize = 48;
pub const ENTRY_THREAD: usize = 56;
/// The end of the last word. `rt` checks it against `abi::msgbuf::ENTRIES_SIZE`.
pub const ENTRY_WORDS_END: usize = ENTRY_THREAD + 8;

/// Before the resident call of the entry whose frame is `frame`: whether the
/// entry records its frame in `outer` (and so has to clear it afterwards).
/// A nested entry, made while a resident call is live, records nothing.
pub const fn records(outer: u64) -> bool {
    outer == 0
}

/// After the resident call of the entry whose frame is `frame`, which
/// recorded `recorded`: the new `outer`. Only the entry that recorded its
/// frame clears it, and only when the word still holds that frame: a jump
/// may have cleared it for a frame below, and a later entry may have
/// recorded its own.
pub const fn after_resident(outer: u64, frame: u64, recorded: bool) -> u64 {
    if recorded && outer == frame { 0 } else { outer }
}

/// Whether the entry calls the handler of the program: the program has one,
/// and no resident call is live. A nested entry leaves it to the entry that
/// made the live resident call, which calls it after the resident call
/// returns; the nested entry writes `owed` meanwhile (`owes`), so that a jump
/// which abandons the outer entry gives the request back (`jump_returns`).
pub const fn own_runs(own: u64, outer: u64) -> bool {
    own != 0 && outer == 0
}

/// Whether an entry that does not call the handler of the program owes it
/// to the outer entry: the program has a handler and a resident call is
/// live. The entry sets `owed`; the outer entry clears it before it calls
/// the handler of the program.
pub const fn owes(own: u64, outer: u64) -> bool {
    own != 0 && outer != 0
}

/// The place of a frame among the stacks of a thread: `z` is 1 when the stack
/// pointer `sp` lies in the range of the alternate signal stack of the thread,
/// 0 on the main stack. Until `sigaltstack` fills the range, `z` is 0 always.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame {
    pub z: u8,
    pub sp: u64,
}

impl Frame {
    /// A frame on the main stack.
    pub const fn main(sp: u64) -> Self {
        Self { z: 0, sp }
    }
}

/// Whether the frame `inner` lies inside the frame `outer`: it was called by
/// it, directly or through others. The order of the frames of one thread is
/// total. A handler on the alternate stack is entered from the main stack
/// only (`SA_ONSTACK` switches stacks from the main one, a handler on the
/// alternate stack stays on it, and `sigaltstack` refuses to change the
/// stack while the thread is on it), so a frame on the alternate stack lies
/// inside every frame of the main stack, and on one stack the lower address
/// is the inner one. A frame is not inside itself.
pub const fn nested(inner: Frame, outer: Frame) -> bool {
    inner.z > outer.z || (inner.z == outer.z && inner.sp < outer.sp)
}

/// The frame at the stack pointer `sp` when the thread's alternate signal
/// stack covers `alt` (low, high): `z` is 1 inside it.
pub const fn frame_in(sp: u64, alt: Option<(u64, u64)>) -> Frame {
    match alt {
        Some((low, high)) if low <= sp && sp < high => Frame { z: 1, sp },
        _ => Frame::main(sp),
    }
}

/// The frame of the live resident call whose entry frame is `outer`. The
/// entry frame lies at the top of the alternate stack whenever the kernel
/// switched there, but the handler runs on the interrupted stack when it
/// has no SA_ONSTACK: `floor` (not 0) is the stack pointer that handler
/// started with, and it is the frame of the call then.
pub const fn call_frame(outer: u64, floor: u64, alt: Option<(u64, u64)>) -> Frame {
    if floor != 0 {
        frame_in(floor, alt)
    } else {
        frame_in(outer, alt)
    }
}

/// `jump_clears` for frames on two stacks: the word `outer` is cleared when
/// the live resident call (its frame `call`) lies inside the frame of the
/// jump target.
pub const fn jump_clears_frames(outer: u64, call: Frame, target: Frame) -> bool {
    outer != 0 && nested(call, target)
}

/// The hook of a long jump to the stack pointer `target`: whether the
/// word `outer` is cleared. The resident call is abandoned when the target
/// lies above its frame; a target at the frame or below it (a jump inside the
/// handler) keeps the word. The frame of the live resident call is inside the
/// frame of the target (`nested`); the hook of relibc repeats this formula.
pub const fn jump_clears(outer: u64, target: u64) -> bool {
    outer != 0 && nested(Frame::main(outer), Frame::main(target))
}

/// The new `outer` after a long jump to `target`.
pub const fn after_jump(outer: u64, target: u64) -> u64 {
    if jump_clears(outer, target) { 0 } else { outer }
}

/// Whether a long jump to `target` gives a request back to the kernel: it
/// abandons the outer entry (`jump_clears`) while the handler of the program
/// is owed. The request was spent by the nested entry that left the handler
/// to the abandoned one; without a new request the handler would wait for
/// the next event. The hook and `abandon` clear `owed` and ask the kernel
/// for an entry of the thread itself.
pub const fn jump_returns(outer: u64, owed: u64, target: u64) -> bool {
    jump_clears(outer, target) && owed != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A thread's record and the calls the distributor makes, by the same
    /// steps as the assembly.
    struct Thread {
        own: u64,
        resident: u64,
        outer: u64,
        owed: u64,
        own_calls: usize,
        resident_calls: usize,
        /// Requests given back to the kernel by a jump.
        returned: usize,
    }
    impl Thread {
        fn new(own: u64, resident: u64) -> Self {
            Thread {
                own,
                resident,
                outer: 0,
                owed: 0,
                own_calls: 0,
                resident_calls: 0,
                returned: 0,
            }
        }
        /// The hook of a long jump to `target`.
        fn jump(&mut self, target: u64) {
            if self.jump_clear(target) {
                self.jump_settle();
            }
        }
        /// First step of the hook: clear `outer`.
        fn jump_clear(&mut self, target: u64) -> bool {
            let clears = jump_clears(self.outer, target);
            self.outer = after_jump(self.outer, target);
            clears
        }
        /// Second step: take `owed`, and give the request back when it was set.
        fn jump_settle(&mut self) {
            if self.owed != 0 {
                self.owed = 0;
                self.returned += 1;
            }
        }
        /// An entry whose frame is `frame`; `inside` runs during the
        /// resident call and may enter again or jump.
        fn enter(&mut self, frame: u64, inside: impl FnOnce(&mut Thread) -> bool) {
            let mut abandoned = false;
            let mut recorded = false;
            if self.resident != 0 {
                recorded = records(self.outer);
                if recorded {
                    self.outer = frame;
                }
                self.resident_calls += 1;
                abandoned = inside(self);
            }
            if abandoned {
                // The entry was left by a long jump and never resumes.
                return;
            }
            if self.resident != 0 {
                self.outer = after_resident(self.outer, frame, recorded);
            }
            if own_runs(self.own, self.outer) {
                self.owed = 0;
                self.own_calls += 1;
            } else if owes(self.own, self.outer) {
                self.owed = 1;
            }
        }
    }

    #[test]
    fn a_nested_resident_call_does_not_touch_the_word() {
        let mut t = Thread::new(1, 2);
        t.enter(0x9000, |t| {
            assert_eq!(t.outer, 0x9000);
            t.enter(0x8000, |t| {
                assert_eq!(t.outer, 0x9000);
                false
            });
            // The nested entry returned: the word still names the outer frame.
            assert_eq!(t.outer, 0x9000);
            false
        });
        assert_eq!(t.outer, 0);
        assert_eq!(t.resident_calls, 2);
    }

    #[test]
    fn the_program_handler_is_not_called_while_a_resident_call_is_live() {
        let mut t = Thread::new(1, 2);
        t.enter(0x9000, |t| {
            t.enter(0x8000, |_| false);
            assert_eq!(t.own_calls, 0);
            false
        });
        // The outer entry calls it once, after the resident call returned.
        assert_eq!(t.own_calls, 1);
    }

    #[test]
    fn an_entry_without_a_resident_handler_calls_the_program_handler() {
        let mut t = Thread::new(1, 0);
        t.enter(0x9000, |_| false);
        t.enter(0x9000, |_| false);
        assert_eq!((t.own_calls, t.resident_calls, t.outer), (2, 0, 0));
    }

    #[test]
    fn an_entry_without_a_program_handler_calls_only_the_resident_one() {
        let mut t = Thread::new(0, 2);
        t.enter(0x9000, |_| false);
        assert_eq!((t.own_calls, t.resident_calls, t.outer), (0, 1, 0));
    }

    #[test]
    fn a_jump_above_the_outer_frame_clears_the_word() {
        let mut t = Thread::new(1, 2);
        t.enter(0x9000, |t| {
            // A handler leaves by a jump to a target above the frame.
            assert!(jump_clears(t.outer, 0xa000));
            t.outer = after_jump(t.outer, 0xa000);
            true
        });
        assert_eq!(t.outer, 0);
        // The program handler did not run for the abandoned entry.
        assert_eq!(t.own_calls, 0);
        // A later entry calls both handlers.
        t.enter(0x9000, |_| false);
        assert_eq!((t.own_calls, t.resident_calls), (1, 2));
    }

    #[test]
    fn a_nested_entry_then_a_jump_above_the_outer_frame_gives_the_request_back() {
        let mut t = Thread::new(1, 2);
        t.enter(0x9000, |t| {
            // The nested entry spent the request and left the handler of
            // the program to the outer entry.
            t.enter(0x8000, |_| false);
            assert_eq!((t.owed, t.own_calls), (1, 0));
            // The handler leaves by a jump above the outer frame.
            t.jump(0xa000);
            true
        });
        assert_eq!((t.outer, t.owed, t.returned, t.own_calls), (0, 0, 1, 0));
        // The kernel enters again for the request that was given back; the
        // handler of the program runs once.
        t.enter(0x9000, |_| false);
        assert_eq!((t.own_calls, t.owed, t.returned), (1, 0, 1));
    }

    #[test]
    fn a_nested_entry_between_the_two_steps_of_a_jump_pays_the_debt_itself() {
        let mut t = Thread::new(1, 2);
        t.enter(0x9000, |t| {
            assert!(t.jump_clear(0xa000));
            // An entry that nests after `outer` is clear calls the handler
            // of the program, so nothing is owed or given back.
            t.enter(0x8000, |_| false);
            t.jump_settle();
            true
        });
        assert_eq!((t.owed, t.own_calls, t.returned), (0, 1, 0));
    }

    #[test]
    fn a_nested_entry_before_the_jump_leaves_the_debt_to_be_given_back() {
        let mut t = Thread::new(1, 2);
        t.enter(0x9000, |t| {
            t.enter(0x8000, |_| false);
            assert!(t.jump_clear(0xa000));
            t.jump_settle();
            true
        });
        assert_eq!((t.owed, t.own_calls, t.returned), (0, 0, 1));
    }

    #[test]
    fn the_outer_entry_that_returns_clears_the_debt_and_nothing_is_given_back() {
        let mut t = Thread::new(1, 2);
        t.enter(0x9000, |t| {
            t.enter(0x8000, |_| false);
            assert_eq!(t.owed, 1);
            false
        });
        assert_eq!((t.owed, t.own_calls, t.returned), (0, 1, 0));
    }

    #[test]
    fn a_jump_that_keeps_the_outer_frame_keeps_the_debt() {
        let mut t = Thread::new(1, 2);
        t.enter(0x9000, |t| {
            t.enter(0x8000, |_| false);
            t.jump(0x8f00);
            assert_eq!((t.outer, t.owed, t.returned), (0x9000, 1, 0));
            false
        });
        assert_eq!((t.owed, t.own_calls, t.returned), (0, 1, 0));
    }

    #[test]
    fn a_jump_with_no_debt_gives_nothing_back() {
        assert!(!jump_returns(0x9000, 0, 0xa000));
        assert!(!jump_returns(0, 1, 0xa000));
        assert!(!jump_returns(0x9000, 1, 0x9000));
        assert!(jump_returns(0x9000, 1, 0xa000));
        assert!(owes(1, 0x9000));
        assert!(!owes(0, 0x9000));
        assert!(!owes(1, 0));
    }

    #[test]
    fn a_jump_below_the_outer_frame_keeps_the_word() {
        let mut t = Thread::new(1, 2);
        t.enter(0x9000, |t| {
            // The handler set its own jump target below the frame.
            assert!(!jump_clears(t.outer, 0x8f00));
            t.outer = after_jump(t.outer, 0x8f00);
            assert_eq!(t.outer, 0x9000);
            // A nested entry still does not call the program handler.
            t.enter(0x8800, |_| false);
            assert_eq!(t.own_calls, 0);
            false
        });
        assert_eq!(t.own_calls, 1);
        assert_eq!(t.outer, 0);
    }

    #[test]
    fn nested_orders_the_frames_of_a_thread() {
        let main = |sp| Frame { z: 0, sp };
        let alternate = |sp| Frame { z: 1, sp };
        // Both on the main stack: the lower address is the inner frame.
        assert!(nested(main(0x8000), main(0x9000)));
        assert!(!nested(main(0x9000), main(0x8000)));
        assert!(!nested(main(0x9000), main(0x9000)));
        // A frame on the alternate stack lies inside any frame of the main
        // stack, whatever the addresses, and no frame of the main stack lies inside one of the alternate stack.
        assert!(nested(alternate(0x1000), main(0x9000)));
        assert!(nested(alternate(0xf000), main(0x1000)));
        assert!(!nested(main(0x1000), alternate(0xf000)));
        assert!(!nested(main(0x9000), alternate(0x1000)));
        // Both on the alternate stack: the lower address is the inner frame.
        assert!(nested(alternate(0x1000), alternate(0x2000)));
        assert!(!nested(alternate(0x2000), alternate(0x1000)));
        assert!(!nested(alternate(0x2000), alternate(0x2000)));
    }

    #[test]
    fn a_jump_clears_the_word_by_the_order_of_the_frames() {
        for outer in [0x1000_u64, 0x9000, 0xffff_0000] {
            for target in [0x800_u64, 0x1000, 0x9000, 0x9001, 0xffff_0001] {
                assert_eq!(
                    jump_clears(outer, target),
                    nested(Frame::main(outer), Frame::main(target))
                );
            }
        }
    }

    #[test]
    fn a_jump_to_the_frame_address_keeps_the_word() {
        assert!(!jump_clears(0x9000, 0x9000));
        assert_eq!(after_jump(0x9000, 0x9000), 0x9000);
        assert!(jump_clears(0x9000, 0x9001));
    }

    #[test]
    fn a_jump_with_no_live_call_changes_nothing() {
        assert!(!jump_clears(0, 0xffff_0000));
        assert_eq!(after_jump(0, 0xffff_0000), 0);
    }

    #[test]
    fn a_stale_frame_does_not_clear_a_newer_record() {
        // The first entry was abandoned and the word cleared by the jump; a
        // later entry recorded its own frame at the same address. The
        // clearing after the abandoned entry never happens, and the later
        // entry clears its own.
        let mut t = Thread::new(1, 2);
        t.enter(0x9000, |t| {
            t.outer = after_jump(t.outer, 0xa000);
            true
        });
        t.enter(0x9000, |t| {
            assert_eq!(t.outer, 0x9000);
            false
        });
        assert_eq!(t.outer, 0);
        // The step itself: an entry that recorded clears only its own frame.
        assert_eq!(after_resident(0x7000, 0x9000, true), 0x7000);
        assert_eq!(after_resident(0x9000, 0x9000, true), 0);
        assert_eq!(after_resident(0x9000, 0x8000, false), 0x9000);
    }

    #[test]
    fn the_words_of_the_record_follow_one_another() {
        assert_eq!(
            [
                ENTRY_OWN,
                ENTRY_RESIDENT,
                ENTRY_TLS,
                ENTRY_OUTER,
                ENTRY_FLAGS,
                ENTRY_HOOK,
                ENTRY_OWED,
                ENTRY_THREAD
            ],
            [0, 8, 16, 24, 32, 40, 48, 56]
        );
        assert_eq!(ENTRY_WORDS_END, 64);
    }

    #[test]
    fn frames_on_the_alternate_stack_lie_inside_the_main_ones() {
        let alt = Some((0x10_0000, 0x10_4000));
        // A call whose entry frame is on the alternate stack, handler too.
        let call = call_frame(0x10_3000, 0, alt);
        assert_eq!(
            call,
            Frame {
                z: 1,
                sp: 0x10_3000
            }
        );
        // A jump to any main-stack frame leaves it, whatever the addresses.
        for target in [0x8000, 0x7f_0000, 0x10_5000] {
            assert!(jump_clears_frames(0x10_3000, call, frame_in(target, alt)));
        }
        // A jump to a lower place of the alternate stack stays inside.
        assert!(!jump_clears_frames(
            0x10_3000,
            call,
            frame_in(0x10_2000, alt)
        ));
        assert!(jump_clears_frames(
            0x10_3000,
            call,
            frame_in(0x10_3800, alt)
        ));
        // The word is clear: nothing to settle.
        assert!(!jump_clears_frames(0, call, frame_in(0x8000, alt)));
    }
    #[test]
    fn a_handler_without_the_flag_keeps_its_call_on_the_main_stack() {
        let alt = Some((0x10_0000, 0x10_4000));
        // The entry frame is at the top of the alternate stack, the
        // handler started at 0x7000 on the main stack.
        let call = call_frame(0x10_3000, 0x7000, alt);
        assert_eq!(call, Frame::main(0x7000));
        // A jump inside the handler (below its start) keeps the word.
        assert!(!jump_clears_frames(0x10_3000, call, frame_in(0x6800, alt)));
        // A jump above it leaves the call.
        assert!(jump_clears_frames(0x10_3000, call, frame_in(0x9000, alt)));
        // Without an alternate stack the order is the one of the main stack.
        assert_eq!(call_frame(0x9000, 0, None), Frame::main(0x9000));
    }
}
