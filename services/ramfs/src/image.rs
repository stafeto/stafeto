// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Loading images retain their canonical inode and originating expenditure root.
//! The service prepays their capability and owns an exact retained loader identity.

use crate::{
    Fds, REG, Ram,
    storage::{NONE, Pin, Root, Token},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageHold {
    pub token: Token,
    pub entry: u16,
    pub root: Root,
}

/// The source retains recovery authority for one exact executable proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImagePhase {
    Prepared,
    Ready,
    Retired,
    AbortRequired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageOutcome {
    pub job: u64,
    pub label: u64,
    pub token: Token,
    pub phase: ImagePhase,
}

impl Ram<'_> {
    /// The service validates owner, path proof and execute permission before admission.
    pub fn hold_image(&mut self, fds: &mut Fds, token: Token, entry: u16) -> Result<(), u32> {
        if fds.image_hold.is_some() {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let node = self.storage.node(token)?;
        if node.kind != REG || node.boot == NONE || node.boot != entry {
            return Err(proto_fs::ACCESS_DENIED);
        }
        self.storage.charge_description(fds.root)?;
        if let Err(code) = self.storage.pin(token, Pin::Image) {
            self.storage.release_description(fds.root);
            return Err(code);
        }
        fds.image_hold = Some(ImageHold {
            token,
            entry,
            root: fds.root,
        });
        Ok(())
    }
    /// One exact reference and its root charge are released in the same cleanup step.
    pub fn release_image(&mut self, fds: &mut Fds) -> bool {
        let Some(held) = fds.image_hold.take() else {
            return false;
        };
        self.storage
            .unpin(held.token, Pin::Image)
            .expect("owned image pin");
        self.storage.release_description(held.root);
        true
    }
    pub fn held_image_read(&self, fds: &Fds, offset: u64, out: &mut [u8]) -> Result<usize, u32> {
        let held = fds.image_hold.ok_or(proto_fs::BAD_FD)?;
        self.storage.read(held.token, offset, out)
    }
    pub fn held_image_information(&self, fds: &Fds) -> Result<proto_fs::NodeInfo, u32> {
        self.token_information(fds.image_hold.ok_or(proto_fs::BAD_FD)?.token)
    }
}
