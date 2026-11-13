// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the translation refuses, with the text the loader prints to the
//! firmware's console: a panic of the kernel before it reads the tree is not
//! visible on EC2 (spec 3.2), so every refusal names its cause here.

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A table or the pointer to it is cut short or lies about its length.
    Truncated(&'static str),
    BadSignature(&'static str),
    BadChecksum(&'static str),
    /// A table the kernel needs is absent.
    Missing(&'static str),
    /// A value the kernel cannot work with, and the reason.
    Unsupported(&'static str),
    /// The self-check of the finished tree failed.
    Check(&'static str),
    /// More regions than the kernel's lists hold, even after the merge.
    TooManyRegions(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated(w) => write!(f, "{w}: cut short"),
            Error::BadSignature(w) => write!(f, "{w}: bad signature"),
            Error::BadChecksum(w) => write!(f, "{w}: bad checksum"),
            Error::Missing(w) => write!(f, "{w}: missing"),
            Error::Unsupported(w) => write!(f, "{w}: unsupported"),
            Error::Check(w) => write!(f, "self-check: {w}"),
            Error::TooManyRegions(w) => write!(f, "{w}: too many regions"),
        }
    }
}
