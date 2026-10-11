// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Exact paired disposal survives physical-close errors and departing callers.

use posix_fd::{DisposalToken, IoEnd, IoToken, OwnerToken};

pub(crate) fn finish(token: IoToken, owner: OwnerToken) {
    let ended =
        crate::shared::with_files(|files| files.finish_fifo_io(token, owner).map_err(crate::error));
    if let Ok(IoEnd::Cleanup { token, .. }) = ended {
        dispose(token);
    }
}
pub(crate) fn detach(owner: u64) -> bool {
    let Ok(owner) = OwnerToken::new(owner) else {
        return false;
    };
    crate::shared::try_with_files(|files| {
        while files.abandon_fifo_io_owner(owner).is_some() {}
        Ok(true)
    })
    .unwrap_or(false)
}
pub(crate) fn help() {
    use core::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let start = NEXT.fetch_add(1, Ordering::Relaxed) % posix_fs::OPEN_MAX;
    let token = crate::shared::try_with_files(|files| {
        Ok(files
            .fifo_disposals()
            .find(|token| token.slot() >= start)
            .or_else(|| files.fifo_disposals().next()))
    })
    .ok()
    .flatten();
    if let Some(token) = token {
        dispose(token);
    }
}
/// Exec cannot transfer a pipe session carrying an endpoint with no public fd.
/// Each of the existing thirty-two paid debts gets one exact cleanup attempt.
pub(crate) fn drain_for_exec() -> bool {
    let debts = crate::shared::try_with_files(|files| {
        let mut debts = [None; posix_fs::OPEN_MAX];
        for (index, token) in files.fifo_disposals().enumerate() {
            debts[index] = Some(token);
        }
        Ok(debts)
    });
    let Ok(debts) = debts else {
        return false;
    };
    for token in debts.into_iter().flatten() {
        dispose(token);
    }
    crate::shared::try_with_files(|files| Ok(files.fifo_disposals().next().is_none()))
        .unwrap_or(false)
}
fn dispose(token: DisposalToken) {
    let pending = crate::shared::try_with_files(|files| {
        Ok(files
            .fifo_disposal(token)
            .ok()
            .map(|snapshot| (files.transport(), snapshot.backend)))
    })
    .ok()
    .flatten();
    let Some((transport, target)) = pending else {
        return;
    };
    if transport.release(Some(target)).is_ok() {
        let _ = crate::shared::try_with_files(|files| {
            files.finish_fifo_disposal(token).map_err(crate::error)
        });
    }
}
