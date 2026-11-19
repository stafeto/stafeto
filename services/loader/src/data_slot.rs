// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What a set-ID program's session in the slot Data becomes. The loader sends the offered channel
//! to the root of the data file service (VERIFY_SESSION); the root answers with the session itself
//! when it is a live session of the service, and BAD_HANDLE with no handle for any other channel
//! (a channel the parent forged, or a session that died with its instance). The loader never
//! replaces a session: the slot stays empty, and the program takes a session of its own from the
//! root when it uses `/data`, bound to its own identity.

/// The loader's decision on the root's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The session is the service's own: it goes into the slot with its descriptions.
    Keep,
    /// The slot stays empty and the start goes on.
    Empty,
    /// The start is refused (the service gave no answer that means either).
    Refuse,
}

/// The verdict for the status of the root's reply (`None` for a reply too short to read).
pub fn verdict(status: Option<u32>) -> Verdict {
    match status {
        Some(0) => Verdict::Keep,
        Some(proto_data::BAD_HANDLE) => Verdict::Empty,
        _ => Verdict::Refuse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_live_session_stays_and_a_forged_or_dead_one_leaves_the_slot_empty() {
        assert_eq!(verdict(Some(0)), Verdict::Keep);
        // The root's answer for a channel that is no live session of the service.
        assert_eq!(verdict(Some(proto_data::BAD_HANDLE)), Verdict::Empty);
        // Any other answer refuses the start, so no program runs on a verdict nobody gave.
        for status in [
            proto_data::ACCESS,
            proto_data::IS_ROOT,
            proto_data::NOT_READY,
            proto_data::INVALID,
            1,
        ] {
            assert_eq!(verdict(Some(status)), Verdict::Refuse, "{status}");
        }
        assert_eq!(verdict(None), Verdict::Refuse);
    }

    /// The request is the header of VERIFY_SESSION of the data service, which only its root takes.
    #[test]
    fn the_request_is_verify_session_of_the_data_protocol() {
        let header = proto_data::Method::VerifySession.header();
        assert_eq!(header.method, 35);
        assert!(proto_data::Method::VerifySession.is_root_method());
    }
}
