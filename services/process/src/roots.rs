// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The roots of the services whose sessions a loader verifies for a set-ID
//! program (`proto_process::ROOT_TERMINAL` and the others): which Register
//! brings a root, and the table that keeps it. A service registers its root
//! through its notary session, whose label has the mark init gave only to
//! that service; a service that restarts registers again, and the new root
//! replaces the old.

use proto_process::{
    PERMISSION, ROOT_DATA, ROOT_LAYER, ROOT_TERMINAL, ROOTS, UNREGISTERED, root_of,
};

/// What a Register through a notary session asks, by the label and the
/// number of handles it brought.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Registration {
    /// No handles: a copy of the page of the generations.
    Page,
    /// A root of `root`, which sits at `at` among the handles (the terminal
    /// service sends its notice first).
    Root { root: u32, at: usize },
    /// Anything else, which is refused.
    Refused,
}

/// The kind of Register for `label` and `handles`: a session whose label
/// has no mark of a root registers none, and a root comes with the handles
/// of its own shape alone (the terminal's two, the others' one).
pub const fn registration(label: u64, handles: usize) -> Registration {
    if handles == 0 {
        return Registration::Page;
    }
    match root_of(label) {
        Some(ROOT_TERMINAL) if handles == 2 => Registration::Root {
            root: ROOT_TERMINAL,
            at: 1,
        },
        Some(root) if root != ROOT_TERMINAL && handles == 1 => Registration::Root { root, at: 0 },
        _ => Registration::Refused,
    }
}

/// Whether a process may ask for the root of `which` with TakeRoot: the roots of the data file
/// service and of the layer service. The other roots go to the loaders of set-ID programs (LoaderRoot) and to no
/// process, because a session taken from them would carry no identity of the process's own.
pub const fn takeable(which: u32) -> bool {
    which == ROOT_DATA || which == ROOT_LAYER
}

/// The rights of the copy of the root TakeRoot gives: SEND to send the root its two requests, and
/// TRANSFER, which the kernel asks of every handle in a message (a reply without it is refused with
/// ACCESS_DENIED, which the client sees as its status). No DUPLICATE: the process cannot copy it.
/// The root gives only sessions with a vouched identity, so a copy handed on is harmless.
pub const TAKEN_RIGHTS: abi::Rights = abi::Rights::SEND.union(abi::Rights::TRANSFER);

/// The registered roots, by root.
pub struct Roots<H> {
    held: [Option<H>; ROOTS],
}

impl<H> Roots<H> {
    pub const fn new() -> Self {
        Self {
            held: [const { None }; ROOTS],
        }
    }

    /// Keeps `root` for the service of `which`; the one it replaces (the
    /// root of an instance that went) comes back to be let go of.
    pub fn register(&mut self, which: u32, root: H) -> Option<H> {
        self.held.get_mut(which as usize)?.replace(root)
    }

    /// The root TakeRoot gives for `which`: PERMISSION for any root but `ROOT_DATA` and `ROOT_LAYER`, UNREGISTERED
    /// when the service sent none.
    pub fn taken(&self, which: u32) -> Result<&H, u32> {
        if !takeable(which) {
            return Err(PERMISSION);
        }
        self.get(which).ok_or(UNREGISTERED)
    }

    /// The root of the service of `which`, if it registered one.
    pub fn get(&self, which: u32) -> Option<&H> {
        self.held.get(which as usize)?.as_ref()
    }
}

impl<H> Default for Roots<H> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_process::{ENTROPY, NET, NOTARY, PIPE, SET_ID, TERMINAL};

    #[test]
    fn only_a_marked_service_registers_a_root() {
        // A voucher with no mark of a root (the file service has SET_ID, the clock
        // service nothing) registers none.
        for label in [NOTARY | 9, NOTARY | SET_ID | 9] {
            assert_eq!(registration(label, 1), Registration::Refused);
            assert_eq!(registration(label, 2), Registration::Refused);
            assert_eq!(registration(label, 0), Registration::Page);
        }
        // A label that is no notary's, whatever marks it carries.
        assert_eq!(registration(PIPE | 9, 1), Registration::Refused);
        assert_eq!(
            registration(1 << 63 | NOTARY | PIPE, 1),
            Registration::Refused
        );
        // The marked services, each with its own shape.
        for (mark, root) in [
            (PIPE, 1),
            (NET, 2),
            (ENTROPY, 3),
            (proto_process::DATAFS, 4),
            (proto_process::PKG, 5),
            (proto_process::LAYER, 6),
        ] {
            assert_eq!(
                registration(NOTARY | mark | 4, 1),
                Registration::Root { root, at: 0 }
            );
            assert_eq!(registration(NOTARY | mark | 4, 2), Registration::Refused);
        }
        assert_eq!(
            registration(NOTARY | TERMINAL | 4, 2),
            Registration::Root {
                root: ROOT_TERMINAL,
                at: 1
            }
        );
        assert_eq!(
            registration(NOTARY | TERMINAL | 4, 1),
            Registration::Refused
        );
    }

    /// TakeRoot gives the roots of the data file service and of the layer service and refuses
    /// every other root, whether or not its service registered one. (The planted fault: `takeable`
    /// true for `ROOT_NET`.)
    #[test]
    fn take_root_gives_the_data_and_layer_roots_and_no_other() {
        let mut roots = Roots::<u32>::new();
        for which in 0..ROOTS as u32 {
            roots.register(which, 100 + which);
        }
        for which in 0..ROOTS as u32 {
            if which == ROOT_DATA {
                assert_eq!(roots.taken(which), Ok(&104));
            } else if which == ROOT_LAYER {
                assert_eq!(roots.taken(which), Ok(&106));
            } else {
                assert_eq!(roots.taken(which), Err(PERMISSION), "root {which}");
            }
        }
        assert_eq!(roots.taken(proto_process::ROOT_NET), Err(PERMISSION));
        // The package service's root goes to the loaders alone, registered or not.
        assert_eq!(roots.taken(proto_process::ROOT_PKG), Err(PERMISSION));
        assert_eq!(
            Roots::<u32>::new().taken(proto_process::ROOT_PKG),
            Err(PERMISSION)
        );
        assert_eq!(roots.taken(ROOTS as u32), Err(PERMISSION));
        // The data service has not registered: UNREGISTERED and no root.
        let empty = Roots::<u32>::new();
        assert_eq!(empty.taken(ROOT_DATA), Err(UNREGISTERED));
        assert_eq!(empty.taken(ROOT_LAYER), Err(UNREGISTERED));
        assert!(takeable(ROOT_DATA) && takeable(ROOT_LAYER) && !takeable(ROOT_DATA + 1));
    }

    /// The copy TakeRoot puts in its reply can travel: a handle in a message has TRANSFER. (The
    /// planted fault: SEND alone, which the kernel refuses and the first probe of /data met as
    /// status 3.)
    #[test]
    fn the_copy_of_the_root_has_the_rights_to_travel_and_to_send() {
        assert!(TAKEN_RIGHTS.contains(abi::Rights::TRANSFER));
        assert!(TAKEN_RIGHTS.contains(abi::Rights::SEND));
        assert!(!TAKEN_RIGHTS.contains(abi::Rights::DUPLICATE));
    }

    #[test]
    fn a_restarted_service_replaces_its_root() {
        let mut roots = Roots::<u32>::new();
        assert_eq!(roots.get(proto_process::ROOT_PIPES), None);
        assert_eq!(roots.register(proto_process::ROOT_PIPES, 10), None);
        assert_eq!(roots.get(proto_process::ROOT_PIPES), Some(&10));
        // The instance after a restart registers again: its root stands, the
        // old one is handed back.
        assert_eq!(roots.register(proto_process::ROOT_PIPES, 11), Some(10));
        assert_eq!(roots.get(proto_process::ROOT_PIPES), Some(&11));
        // The other roots are untouched, and a root past the table is none.
        assert_eq!(roots.get(proto_process::ROOT_NET), None);
        assert_eq!(roots.register(ROOTS as u32, 1), None);
        assert_eq!(roots.get(ROOTS as u32), None);
    }
}
