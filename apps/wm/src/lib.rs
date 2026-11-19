// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the window manager decides, apart from the calls it makes: which
//! window takes the focus when it is made, what a key chord of the manager
//! asks for, and which window a switch gives the focus to. The program
//! (`main.rs`) only reads the manager's ring of the compositor, asks LIST
//! and gives FOCUS (proto_comp). Everything here builds for the host too,
//! where `cargo test -p wm` exercises it.
//!
//! The policy. A window that is made (CREATE) gets the focus and the top
//! place: FOCUS does both. A click is the compositor's: it gives the window
//! under the pointer the focus and the top place itself, so the manager
//! does nothing for a click and the window is never raised twice. The
//! chords are Super and Tab (the next window by number, wrapping), Super,
//! Shift and Tab (the previous one) and Super and Q (the manager ends when
//! the chord is released). The compositor hands the manager the Super keys
//! and the keys pressed under them and no others, so Alt, Ctrl and Shift
//! reach the window with the focus as they did: Doom binds all three, and
//! its Tab is the map. Shift is seen under Super only, so Shift is pressed
//! after Super for the previous window.

#![cfg_attr(not(test), no_std)]

use proto_comp::{CREATE, Event, FOCUSED, KEY, SHOWN, WindowRecord};

/// Linux's key codes of the chords.
pub const KEY_TAB: u16 = 15;
pub const KEY_Q: u16 = 16;
pub const KEY_LEFTSHIFT: u16 = 42;
pub const KEY_RIGHTSHIFT: u16 = 54;
pub const KEY_LEFTMETA: u16 = 125;
pub const KEY_RIGHTMETA: u16 = 126;

/// What an event of the manager's ring asks the program to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// FOCUS of window `id`: it is new.
    Focus(u32),
    /// The next window (`forward`) or the previous one: LIST, `next_focus`,
    /// FOCUS.
    Cycle { forward: bool },
    /// The chord that ends the manager was released.
    Quit,
}

/// The keys of the chords that are down.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Chords {
    /// The Super keys down, one bit each (left, right).
    meta: u8,
    /// The Shift keys down, one bit each. Only the keys pressed under
    /// Super reach the manager, so these are cleared with the last Super.
    shift: u8,
    /// Q was pressed under Super: the manager ends when Super is released.
    quit: bool,
}

impl Chords {
    pub const fn new() -> Chords {
        Chords {
            meta: 0,
            shift: 0,
            quit: false,
        }
    }

    /// Whether a Super key is down.
    pub const fn held(&self) -> bool {
        self.meta != 0
    }

    /// Forgets the keys down: events were lost, so what is down is not
    /// known.
    pub fn reset(&mut self) {
        *self = Chords::new();
    }

    /// The command an event asks for, if any: a window made, or a chord
    /// done. The other events of the ring (a window gone, a key that is no
    /// part of a chord) ask nothing.
    pub fn event(&mut self, e: &Event) -> Option<Command> {
        match e.kind {
            CREATE => Some(Command::Focus(u32::from(e.code))),
            KEY => self.key(e.code, e.value != 0),
            _ => None,
        }
    }

    fn key(&mut self, code: u16, pressed: bool) -> Option<Command> {
        let bit = |n: u8| if pressed { n } else { 0 };
        match code {
            KEY_LEFTMETA | KEY_RIGHTMETA => {
                let n = if code == KEY_LEFTMETA { 1 } else { 2 };
                self.meta = if pressed {
                    self.meta | n
                } else {
                    self.meta & !n
                };
                if self.meta != 0 {
                    return None;
                }
                self.shift = 0;
                core::mem::take(&mut self.quit).then_some(Command::Quit)
            }
            KEY_LEFTSHIFT | KEY_RIGHTSHIFT => {
                let n = if code == KEY_LEFTSHIFT { 1 } else { 2 };
                self.shift = if pressed {
                    self.shift | bit(n)
                } else {
                    self.shift & !n
                };
                None
            }
            KEY_TAB if pressed && self.held() => Some(Command::Cycle {
                forward: self.shift == 0,
            }),
            KEY_Q if pressed && self.held() => {
                self.quit = true;
                None
            }
            _ => None,
        }
    }
}

/// The window a switch gives the focus to: of the windows that are shown,
/// in the order of their numbers, the one after the focused window
/// (`forward`) or before it, wrapping round. None when there is no window
/// to go to: none is shown, or the focused one is the only one shown. With
/// no focused window among the shown, the first (or the last) is taken.
pub fn next_focus(windows: &[WindowRecord], forward: bool) -> Option<u32> {
    let shown = |w: &&WindowRecord| w.flags & SHOWN != 0;
    let current = windows
        .iter()
        .filter(shown)
        .find(|w| w.flags & FOCUSED != 0)
        .map(|w| w.id);
    let first = windows.iter().filter(shown).map(|w| w.id);
    let target = if forward {
        // The least number above the current, else the least of all.
        current
            .and_then(|c| first.clone().filter(|&id| id > c).min())
            .or_else(|| first.min())
    } else {
        current
            .and_then(|c| first.clone().filter(|&id| id < c).max())
            .or_else(|| first.max())
    };
    target.filter(|&id| Some(id) != current)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win(id: u32, flags: u32) -> WindowRecord {
        WindowRecord {
            id,
            flags,
            ..WindowRecord::default()
        }
    }

    fn key(code: u16, pressed: bool) -> Event {
        Event::new(KEY, code, i32::from(pressed))
    }

    #[test]
    fn a_new_window_gets_the_focus() {
        let mut c = Chords::new();
        assert_eq!(c.event(&Event::new(CREATE, 3, 0)), Some(Command::Focus(3)));
        assert_eq!(c.event(&Event::new(proto_comp::CLOSE, 3, 0)), None);
    }

    #[test]
    fn super_and_tab_cycle_and_tab_alone_is_not_a_chord() {
        let mut c = Chords::new();
        assert_eq!(c.event(&key(KEY_TAB, true)), None);
        assert_eq!(c.event(&key(KEY_LEFTMETA, true)), None);
        assert_eq!(
            c.event(&key(KEY_TAB, true)),
            Some(Command::Cycle { forward: true })
        );
        assert_eq!(c.event(&key(KEY_TAB, false)), None);
        // The right Super does as the left does, and Tab again cycles again.
        assert_eq!(c.event(&key(KEY_LEFTMETA, false)), None);
        assert!(!c.held());
        assert_eq!(c.event(&key(KEY_RIGHTMETA, true)), None);
        assert_eq!(
            c.event(&key(KEY_TAB, true)),
            Some(Command::Cycle { forward: true })
        );
    }

    #[test]
    fn two_super_keys_hold_the_modifier_until_both_go() {
        let mut c = Chords::new();
        c.event(&key(KEY_LEFTMETA, true));
        c.event(&key(KEY_RIGHTMETA, true));
        c.event(&key(KEY_LEFTMETA, false));
        assert!(c.held());
        assert_eq!(
            c.event(&key(KEY_TAB, true)),
            Some(Command::Cycle { forward: true })
        );
        c.event(&key(KEY_RIGHTMETA, false));
        assert!(!c.held());
    }

    #[test]
    fn shift_under_super_goes_back_and_is_forgotten_with_super() {
        let mut c = Chords::new();
        c.event(&key(KEY_LEFTMETA, true));
        c.event(&key(KEY_LEFTSHIFT, true));
        assert_eq!(
            c.event(&key(KEY_TAB, true)),
            Some(Command::Cycle { forward: false })
        );
        // Super goes while Shift is down; the manager forgets Shift with
        // Super, and Shift's release, which comes later, changes nothing.
        // The next chord is forward.
        c.event(&key(KEY_LEFTMETA, false));
        assert_eq!(c.event(&key(KEY_LEFTSHIFT, false)), None);
        c.event(&key(KEY_LEFTMETA, true));
        assert_eq!(
            c.event(&key(KEY_TAB, true)),
            Some(Command::Cycle { forward: true })
        );
        // Shift released while Super is held: forward again.
        c.event(&key(KEY_RIGHTSHIFT, true));
        c.event(&key(KEY_RIGHTSHIFT, false));
        assert_eq!(
            c.event(&key(KEY_TAB, true)),
            Some(Command::Cycle { forward: true })
        );
    }

    #[test]
    fn super_and_q_end_the_manager_when_super_is_released() {
        let mut c = Chords::new();
        assert_eq!(c.event(&key(KEY_Q, true)), None);
        c.event(&key(KEY_LEFTMETA, true));
        assert_eq!(c.event(&key(KEY_Q, true)), None);
        assert_eq!(c.event(&key(KEY_Q, false)), None);
        assert_eq!(c.event(&key(KEY_LEFTMETA, false)), Some(Command::Quit));
        // Once: the next Super's release asks nothing.
        c.event(&key(KEY_LEFTMETA, true));
        assert_eq!(c.event(&key(KEY_LEFTMETA, false)), None);
    }

    #[test]
    fn lost_events_forget_the_keys_down() {
        let mut c = Chords::new();
        c.event(&key(KEY_LEFTMETA, true));
        c.event(&key(KEY_Q, true));
        c.reset();
        assert!(!c.held());
        assert_eq!(c.event(&key(KEY_LEFTMETA, true)), None);
        assert_eq!(c.event(&key(KEY_LEFTMETA, false)), None);
    }

    #[test]
    fn the_other_keys_ask_nothing() {
        let mut c = Chords::new();
        c.event(&key(KEY_LEFTMETA, true));
        for code in [30, 56, 29, 57] {
            assert_eq!(c.event(&key(code, true)), None);
        }
        assert_eq!(c.event(&Event::new(proto_comp::MOVE, 0, 0)), None);
    }

    #[test]
    fn the_switch_goes_to_the_next_shown_window_and_wraps() {
        let w = [win(1, SHOWN), win(3, SHOWN | FOCUSED), win(6, SHOWN)];
        assert_eq!(next_focus(&w, true), Some(6));
        assert_eq!(next_focus(&w, false), Some(1));
        let last = [win(1, SHOWN), win(3, SHOWN), win(6, SHOWN | FOCUSED)];
        assert_eq!(next_focus(&last, true), Some(1));
        let first = [win(1, SHOWN | FOCUSED), win(3, SHOWN), win(6, SHOWN)];
        assert_eq!(next_focus(&first, false), Some(6));
    }

    #[test]
    fn the_switch_passes_over_windows_not_shown_and_does_not_depend_on_the_order_of_the_list() {
        // The list comes by depth: the numbers are not in order.
        let w = [
            win(5, SHOWN),
            win(2, 0),
            win(4, SHOWN | FOCUSED),
            win(1, SHOWN),
        ];
        assert_eq!(next_focus(&w, true), Some(5));
        assert_eq!(next_focus(&w, false), Some(1));
        // A hidden or never shown window with the focus counts as none.
        let hidden = [win(1, SHOWN), win(2, FOCUSED), win(3, SHOWN)];
        assert_eq!(next_focus(&hidden, true), Some(1));
        assert_eq!(next_focus(&hidden, false), Some(3));
    }

    #[test]
    fn nothing_to_switch_to_is_none() {
        assert_eq!(next_focus(&[], true), None);
        assert_eq!(next_focus(&[win(1, 0)], true), None);
        assert_eq!(next_focus(&[win(1, SHOWN | FOCUSED)], true), None);
        assert_eq!(next_focus(&[win(1, SHOWN | FOCUSED)], false), None);
        // One shown window without the focus gets it.
        assert_eq!(next_focus(&[win(2, SHOWN)], true), Some(2));
    }
}
