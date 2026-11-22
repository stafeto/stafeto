// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! VERIFY_SESSION (proto_pkg): which channel a loader may give a set-ID program as its Packages
//! session. The decision is O(1): the label the kernel reports for the channel (`copy_label` of a
//! copy of the service's own channel, which fails for any other channel) against the clones the
//! service made. A channel that is not the service's has no label here and is replaced by a new
//! clone, so it never receives a request.

use proto_pkg::ROOT;
use proto_wire::clones::Clones;

/// The mark of the labels the service gives itself (CLONE, the root).
pub const OWN: u64 = 1 << 63;
/// The mark of the labels of the notary sessions of the process service.
const NOTARY: u64 = 1 << 62;

/// Whether the channel whose label `label` is (None for a channel that is not a copy of the
/// service's channel) is a live session of a client: an init client's session, whose label is
/// none of the service's own marks, or a clone that is alive (its place holds its label). The root
/// session and the label of a notary are no client's to give.
pub fn genuine<const N: usize, const BITS: u32>(
    clones: &Clones<N, BITS>,
    label: Option<u64>,
) -> bool {
    let Some(label) = label else {
        return false;
    };
    if label == 0 || label == ROOT {
        return false;
    }
    if label & OWN != 0 {
        return clones.place_of(label).is_some();
    }
    label & NOTARY == 0
}

/// Whether a request of `method` may come through the session `label`: VERIFY_SESSION through
/// the root alone, and the root has no other request.
pub fn allowed(label: u64, method: u16) -> bool {
    (label == ROOT) == (method == proto_pkg::Method::VerifySession.number())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_pkg::ROOT_CLONES;

    const CLONES: usize = 8;

    #[test]
    fn a_live_session_of_a_client_verifies() {
        let mut clones = Clones::<CLONES>::new();
        // An init client's session.
        assert!(genuine(&clones, Some(5)));
        // A clone the service made and that is alive.
        let clone = clones.give(OWN, 5).unwrap();
        assert!(genuine(&clones, Some(clone)));
    }

    #[test]
    fn a_forged_channel_does_not_verify() {
        let clones = Clones::<CLONES>::new();
        // A channel that is no copy of the service's has no label here.
        assert!(!genuine(&clones, None));
        assert!(!genuine(&clones, Some(0)));
        // A label that a client made up for a clone finds no place.
        assert!(!genuine(&clones, Some(OWN | 3 << 16 | 2)));
        assert!(!genuine(&clones, Some(OWN | 1)));
    }

    #[test]
    fn a_closed_session_does_not_verify() {
        let mut clones = Clones::<CLONES>::new();
        let clone = clones.give(OWN, 5).unwrap();
        assert!(genuine(&clones, Some(clone)));
        clones.gone(clone);
        assert!(!genuine(&clones, Some(clone)));
        // A new clone of the same place has another label.
        let next = clones.give(OWN, 5).unwrap();
        assert_ne!(next, clone);
        assert!(genuine(&clones, Some(next)));
        assert!(!genuine(&clones, Some(clone)));
    }

    #[test]
    fn the_roots_label_and_a_notary_are_no_client_session() {
        let clones = Clones::<CLONES>::new();
        assert!(!genuine(&clones, Some(ROOT)));
        assert!(!genuine(&clones, Some(1 << 62 | 7)));
    }

    /// The root gives `ROOT_CLONES` clones at most, and the ordinary clients still get theirs.
    #[test]
    fn the_roots_clones_are_bounded() {
        let mut clones = Clones::<{ ROOT_CLONES + 8 }>::new();
        let mut got = 0;
        while clones.give_within(OWN, ROOT, ROOT_CLONES).is_ok() {
            got += 1;
            assert!(got <= ROOT_CLONES + 1);
        }
        assert_eq!(got, ROOT_CLONES);
        assert!(clones.give(OWN, 5).is_ok());
    }

    /// A clone for a genuine session is charged to the session's own label, so the root's full bucket does not touch it.
    #[test]
    fn a_genuine_session_gets_a_clone_charged_to_itself() {
        let mut clones = Clones::<{ ROOT_CLONES + 8 }>::new();
        while clones.give_within(OWN, ROOT, ROOT_CLONES).is_ok() {}
        let mine = clones.give(OWN, 5).unwrap();
        assert!(genuine(&clones, Some(mine)));
        assert!(clones.give(OWN, mine).is_ok());
    }

    #[test]
    fn the_root_takes_verify_session_alone() {
        use proto_pkg::Method;
        let verify = Method::VerifySession.number();
        assert!(allowed(ROOT, verify));
        assert!(!allowed(5, verify));
        assert!(!allowed(OWN | 7, verify));
        for m in Method::ALL {
            if m != Method::VerifySession {
                assert!(!allowed(ROOT, m.number()), "{m:?}");
                assert!(allowed(5, m.number()), "{m:?}");
            }
        }
    }
}
