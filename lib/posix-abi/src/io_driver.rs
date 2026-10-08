// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Last-reference exact close remains in its paid hold through reply uncertainty.

use posix_fs::io::{DisposalToken, IoEnd, IoToken, OwnerToken};

pub(crate) struct Pin {
    pub token: IoToken,
    pub owner: OwnerToken,
}
impl Drop for Pin {
    fn drop(&mut self) {
        let end = crate::shared::with_files(|files| {
            files
                .finish_io(self.token, self.owner)
                .map_err(crate::error)
        });
        if let Ok(IoEnd::Cleanup { token, .. }) = end {
            dispose(token);
        }
    }
}

fn dispose(token: DisposalToken) {
    let context =
        crate::shared::with_files(|files| files.disposal_context(token).map_err(crate::error));
    if let Ok(context) = context
        && let Ok(proof) = context.send_once()
    {
        let _ =
            crate::shared::with_files(|files| files.finish_disposal(proof).map_err(crate::error));
    }
}

pub(crate) fn detach(owner: u64) -> bool {
    let Ok(owner) = OwnerToken::new(owner) else {
        return false;
    };
    // Native teardown performs local transitions only; fair helpers pay the RPC.
    crate::owner_detach::run(
        posix_fs::OPEN_MAX,
        || {
            crate::shared::try_with_files(|files| Ok(files.abandon_io_owner(owner).map(|_| None)))
                .map_err(|_| ())
        },
        |_| {},
    )
}

pub(crate) fn help() {
    use core::sync::atomic::{AtomicUsize, Ordering};
    static CURSOR: AtomicUsize = AtomicUsize::new(0);
    #[derive(Clone, Copy)]
    enum Candidate {
        Io(IoToken),
        Disposal(DisposalToken),
    }
    impl Candidate {
        fn slot(self) -> usize {
            match self {
                Self::Io(token) => token.slot(),
                Self::Disposal(token) => token.slot(),
            }
        }
    }
    let candidate = crate::shared::with_files(|files| {
        let cursor = CURSOR.load(Ordering::Relaxed);
        let token = files
            .io_tokens()
            .map(Candidate::Io)
            .chain(files.disposal_tokens().map(Candidate::Disposal))
            .min_by_key(|token| (token.slot() + posix_fs::OPEN_MAX - cursor) % posix_fs::OPEN_MAX);
        if let Some(token) = token {
            CURSOR.store((token.slot() + 1) % posix_fs::OPEN_MAX, Ordering::Relaxed);
        }
        Ok(token)
    });
    match candidate {
        Ok(Some(Candidate::Disposal(token))) => dispose(token),
        Ok(Some(Candidate::Io(token))) => {
            let snapshot =
                crate::shared::with_files(|files| files.io_snapshot(token).map_err(crate::error));
            if let Ok(snapshot) = snapshot {
                let _ = crate::relibc::detach_ended_open_owner(snapshot.owner.value());
            }
        }
        _ => {}
    }
}
