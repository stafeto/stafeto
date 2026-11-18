// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The device's setup (spec 3): GET_DISPLAY_INFO for the log, then the
//! three resources, each one RESOURCE_CREATE_2D and RESOURCE_ATTACH_BACKING
//! over its object, one command at a time, the next from the interrupt that
//! brings the answer to the one before. Resource 1 is the compositing
//! target over `fb`, 2 the pool over `pool`, 3 the cursor's picture over
//! `cursor`; the numbers are the ids of the sources `proto_gpu` names.

use crate::commands::{FORMAT_B8G8R8A8, FORMAT_B8G8R8X8};
use proto_gpu::{BUFFER_BYTES, CURSOR_SIZE, HEIGHT, SCREEN_BYTES, WIDTH};

/// One resource of the device: its id, format, size in points, and the
/// bytes of its backing, which its object holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resource {
    pub id: u32,
    pub format: u32,
    pub width: u32,
    pub height: u32,
    pub bytes: u32,
}

/// The resources in the order of the setup, which is the order of the
/// objects in init's table after `dma`: `fb`, `pool`, `cursor`.
pub const RESOURCES: [Resource; 3] = [
    Resource {
        id: 1,
        format: FORMAT_B8G8R8X8,
        width: WIDTH,
        height: HEIGHT,
        bytes: SCREEN_BYTES,
    },
    Resource {
        id: 2,
        format: FORMAT_B8G8R8X8,
        width: WIDTH,
        height: HEIGHT,
        bytes: SCREEN_BYTES,
    },
    Resource {
        id: 3,
        format: FORMAT_B8G8R8A8,
        width: CURSOR_SIZE,
        height: CURSOR_SIZE,
        bytes: CURSOR_SIZE * CURSOR_SIZE * 4,
    },
];

/// The bytes of the cursor's object, four pages.
pub const CURSOR_BYTES: u32 = 4 * 4096;

const _: () = assert!(RESOURCES[0].bytes <= BUFFER_BYTES && RESOURCES[1].bytes <= BUFFER_BYTES);
const _: () = assert!(RESOURCES[2].bytes == CURSOR_BYTES);

/// Where the setup stands: the commands go in this order, each from the
/// answer to the one before. `Create` and `Attach` name the index of the
/// resource in RESOURCES.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Setup {
    Info,
    Create(usize),
    Attach(usize),
    Ready,
    /// A command of the setup failed, or could not be sent: no screen to
    /// give.
    Failed,
}

impl Setup {
    /// The state once the command of this one is back; `bad` when it
    /// failed. The info is for the log, so its failure does not stop the
    /// setup; a failed Create or Attach does, and so does any state past
    /// them.
    pub fn after(self, bad: bool) -> Setup {
        match self {
            Setup::Info => Setup::Create(0),
            Setup::Create(_) | Setup::Attach(_) if bad => Setup::Failed,
            Setup::Create(i) => Setup::Attach(i),
            Setup::Attach(i) if i + 1 < RESOURCES.len() => Setup::Create(i + 1),
            Setup::Attach(_) => Setup::Ready,
            Setup::Ready => Setup::Ready,
            Setup::Failed => Setup::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_setup_goes_through_info_and_six_steps_to_ready() {
        let mut state = Setup::Info;
        let mut seen = Vec::new();
        while state != Setup::Ready {
            seen.push(state);
            state = state.after(false);
        }
        assert_eq!(
            seen,
            [
                Setup::Info,
                Setup::Create(0),
                Setup::Attach(0),
                Setup::Create(1),
                Setup::Attach(1),
                Setup::Create(2),
                Setup::Attach(2),
            ]
        );
        // Ready stays ready.
        assert_eq!(Setup::Ready.after(false), Setup::Ready);
    }

    #[test]
    fn a_failed_create_or_attach_stops_the_setup_and_a_failed_info_does_not() {
        assert_eq!(Setup::Info.after(true), Setup::Create(0));
        for state in [
            Setup::Create(0),
            Setup::Attach(0),
            Setup::Create(1),
            Setup::Attach(1),
            Setup::Create(2),
            Setup::Attach(2),
        ] {
            assert_eq!(state.after(true), Setup::Failed, "{state:?}");
        }
        assert_eq!(Setup::Failed.after(false), Setup::Failed);
    }

    #[test]
    fn the_resources_are_the_sources_proto_gpu_names() {
        let ids: Vec<u32> = RESOURCES.iter().map(|r| r.id).collect();
        assert_eq!(ids, [1, 2, 3]);
        assert_eq!(
            [
                proto_gpu::SOURCE_TARGET,
                proto_gpu::SOURCE_POOL,
                proto_gpu::SOURCE_CURSOR
            ],
            [1, 2, 3]
        );
        // The cursor is the 64 by 64 picture QEMU takes, in B8G8R8A8.
        assert_eq!(
            (RESOURCES[2].width, RESOURCES[2].height, RESOURCES[2].format),
            (64, 64, 1)
        );
        for (resource, info) in RESOURCES.iter().zip(proto_gpu::SourceInfo::VIRTIO) {
            assert_eq!(resource.id, info.id);
            assert_eq!(resource.width * 4, info.stride);
            assert_eq!(resource.height, info.height);
        }
    }
}
