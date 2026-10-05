// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Loading images retain their canonical inode and originating expenditure root.
//! The service prepays their capability and owns an exact retained loader identity.

use crate::{
    Fds, REG, Ram,
    storage::{Pin, Root, Token},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageHold {
    pub token: Token,
    pub entry: u16,
    pub root: Root,
    executable: bool,
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

impl ImageOutcome {
    /// Every attempted notary effect requires canonical loader abort after ambiguity.
    pub fn begin_stage(&mut self) -> Result<(), u32> {
        if self.phase != ImagePhase::Prepared {
            return Err(proto_fs::IMAGE_ABORT_REQUIRED);
        }
        self.phase = ImagePhase::AbortRequired;
        Ok(())
    }
}

/// The canonical notary status reply has two words and carries no capabilities.
pub fn stage_accepted_reply(bytes: &[u8], handles: usize) -> bool {
    bytes == [0; proto_wire::HEADER_LEN] && handles == 0
}

impl Ram<'_> {
    /// The service validates owner, path proof and execute permission before admission.
    pub fn hold_image(&mut self, fds: &mut Fds, token: Token, entry: u16) -> Result<(), u32> {
        if fds.image_hold.is_some() {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        self.hold_image_root(fds, token, entry, fds.root, false)
    }
    /// A verified private source capability supplies this exact retained image.
    /// Fork pays an independent child reference on the originating root.
    pub fn hold_fork_image(&mut self, child: &mut Fds, source: &Fds) -> Result<(), u32> {
        let held = source.image_hold.ok_or(proto_fs::BAD_FD)?;
        if !held.executable || child.image_hold.is_some() {
            return Err(proto_fs::PERMISSION);
        }
        self.hold_image_root(child, held.token, held.entry, held.root, true)
    }
    fn hold_image_root(
        &mut self,
        fds: &mut Fds,
        token: Token,
        entry: u16,
        root: Root,
        executable: bool,
    ) -> Result<(), u32> {
        let node = self.storage.node(token)?;
        if node.kind != REG || node.boot != entry {
            return Err(proto_fs::ACCESS_DENIED);
        }
        self.storage.exec_guard(token)?;
        self.storage.charge_description(root)?;
        if let Err(code) = self.storage.pin(token, Pin::Image) {
            self.storage.release_description(root);
            return Err(code);
        }
        fds.image_hold = Some(ImageHold {
            token,
            entry,
            root,
            executable,
        });
        Ok(())
    }
    /// All preflight checks precede the first trusted execution atime effect.
    pub fn arm_image_execution(
        &mut self,
        fds: &mut Fds,
        token: Token,
        now: proto_fs::Timestamp,
    ) -> Result<bool, u32> {
        let held = fds.image_hold.as_mut().ok_or(proto_fs::BAD_FD)?;
        if held.token != token {
            return Err(proto_fs::STALE_PROOF);
        }
        if held.executable {
            return Ok(false);
        }
        self.storage.exec_guard(token)?;
        let node = self.storage.node_mut(token)?;
        held.executable = true;
        node.times[0] = now;
        Ok(true)
    }
    /// Revoked read authority preserves the executable pin until genuine last-session GONE.
    pub fn release_loading_image(&mut self, fds: &mut Fds) -> bool {
        if fds.image_hold.is_some_and(|held| held.executable) {
            return false;
        }
        self.release_image(fds)
    }
    /// Canonical last-session GONE releases the exact reference and originating root charge.
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
        if matches!(fds.binding, crate::authority::Binding::Cleanup) {
            return Err(proto_fs::PERMISSION);
        }
        let held = fds.image_hold.ok_or(proto_fs::BAD_FD)?;
        self.storage.read(held.token, offset, out)
    }
    pub fn held_image_information(&self, fds: &Fds) -> Result<proto_fs::NodeInfo, u32> {
        if matches!(fds.binding, crate::authority::Binding::Cleanup) {
            return Err(proto_fs::PERMISSION);
        }
        self.token_information(fds.image_hold.ok_or(proto_fs::BAD_FD)?.token)
    }
}
