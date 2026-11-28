// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The refusals of the service and of the kernel as the errno numbers of
//! `<stafeto/window.h>` (the Linux numbers the C library uses).

use abi::Error;
use proto_wire::Status;

pub const EPERM: i32 = 1;
pub const EINTR: i32 = 4;
pub const EIO: i32 = 5;
pub const EBADF: i32 = 9;
pub const EAGAIN: i32 = 11;
pub const ENOMEM: i32 = 12;
pub const EBUSY: i32 = 16;
pub const ENODEV: i32 = 19;
pub const EINVAL: i32 = 22;
pub const ETIMEDOUT: i32 = 110;

/// The errno of a refusal of the kernel on a channel: the service is gone
/// (ENODEV), the session was closed under the call (EBADF), the kernel is
/// out of memory (ENOMEM), a limit (the service's table is full: EAGAIN),
/// a signal (EINTR); anything else EIO.
pub const fn kernel(error: Error) -> i32 {
    match error {
        Error::PeerClosed => ENODEV,
        Error::BadHandle => EBADF,
        Error::NoMemory => ENOMEM,
        Error::LimitReached => EAGAIN,
        Error::Interrupted => EINTR,
        _ => EIO,
    }
}

/// The errno of the status a request came back with. `proto_comp`'s BUSY
/// is EBUSY (a buffer that is not free, another client's ATTACH under
/// way), INVALID and UNSUPPORTED EINVAL, NOT_ALLOWED EBADF (the session is
/// not a window's), REVOKED and NO_DEVICE ENODEV (the window or the display
/// is gone); `proto_gpu`'s CLEARING (the display is being set up) is EBUSY,
/// its NO_DEVICE and REVOKED ENODEV. Any other status (its IO among them) is
/// EIO.
pub fn status(status: Status) -> i32 {
    use proto_comp::{BUSY, INVALID, NO_DEVICE, NOT_ALLOWED, REVOKED, UNSUPPORTED};
    match status {
        Status::Ok => 0,
        Status::Kernel(error) => kernel(error),
        Status::Unknown(code) => match code {
            BUSY => EBUSY,
            INVALID | UNSUPPORTED => EINVAL,
            NOT_ALLOWED => EBADF,
            REVOKED | NO_DEVICE => ENODEV,
            proto_gpu::CLEARING => EBUSY,
            // The compositor answers DESCRIBE and WINDOW_CREATE with the
            // display driver's codes when it has no screen.
            proto_gpu::NO_DEVICE | proto_gpu::REVOKED => ENODEV,
            _ => EIO,
        },
        _ => EIO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_comp::code;

    #[test]
    fn the_service_refusals_have_their_errno() {
        for (refusal, errno) in [
            (proto_comp::BUSY, EBUSY),
            (proto_comp::INVALID, EINVAL),
            (proto_comp::UNSUPPORTED, EINVAL),
            (proto_comp::NOT_ALLOWED, EBADF),
            (proto_comp::REVOKED, ENODEV),
            (proto_comp::NO_DEVICE, ENODEV),
        ] {
            assert_eq!(status(code(refusal)), errno, "{refusal}");
        }
        assert_eq!(status(proto_gpu::code(proto_gpu::CLEARING)), EBUSY);
        assert_eq!(status(proto_gpu::code(proto_gpu::NO_DEVICE)), ENODEV);
        assert_eq!(status(proto_gpu::code(proto_gpu::REVOKED)), ENODEV);
        assert_eq!(status(proto_gpu::code(proto_gpu::IO)), EIO);
        assert_eq!(status(Status::Ok), 0);
        assert_eq!(status(Status::BadSize), EIO);
        assert_eq!(status(Status::Unknown(7777)), EIO);
    }

    #[test]
    fn the_kernel_refusals_have_their_errno() {
        assert_eq!(status(Status::Kernel(Error::PeerClosed)), ENODEV);
        assert_eq!(status(Status::Kernel(Error::LimitReached)), EAGAIN);
        assert_eq!(status(Status::Kernel(Error::NoMemory)), ENOMEM);
        assert_eq!(kernel(Error::BadHandle), EBADF);
        assert_eq!(kernel(Error::Interrupted), EINTR);
        assert_eq!(kernel(Error::BadState), EIO);
    }
}
