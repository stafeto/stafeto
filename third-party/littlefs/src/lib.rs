//! The C sources of littlefs, kept next to this crate with the change of STAFETO-CHANGES.md (README.md). This crate holds no
//! code of its own: `lib/datafs` compiles `lfs.c` and `lfs_util.c` with the settings of its build
//! and links them. The licence of the sources is BSD-3-Clause (LICENSE.md).

#![no_std]

/// The version of the sources.
pub const VERSION: &str = "2.11.3";
