// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Host checks of the signal rules of the display library
//! (`lib/posix-abi/src/wfd.rs`): the commit holds a plain futex mutex across
//! the wait for the last frame (a layer lock would keep a signal pending and
//! end the wait at once), and a wait that a signal ended runs again.

use std::fs;
use std::path::Path;

fn wfd() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../lib/posix-abi/src/wfd.rs");
    fs::read_to_string(path).unwrap()
}

#[test]
fn the_commit_lock_is_a_plain_futex_mutex() {
    let text = wfd();
    assert!(text.contains("static COMMIT_LOCK: Lock = Lock::new();"));
    assert!(!text.contains("COMMIT_LOCK: LayerLock"));
}

#[test]
fn the_wait_for_the_last_frame_runs_again_after_a_signal() {
    let text = wfd();
    let send = text.split("fn send(").nth(1).unwrap();
    let send = send.split("\nfn clean(").next().unwrap();
    assert!(
        send.contains("wait_restarting(until, crate::wait::now, || block_until(until, ready))")
    );
    assert!(!send.contains("\n        block_until("));
}

#[test]
fn the_forked_child_makes_the_commit_lock_new() {
    let text = wfd();
    let after = text.split("pub unsafe fn after_fork()").nth(1).unwrap();
    assert!(after.contains("COMMIT_LOCK.reset();"));
}
