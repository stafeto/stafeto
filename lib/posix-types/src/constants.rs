// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

pub const S_IFMT: u32 = 61440;
pub const S_IFDIR: u32 = 16384;
pub const S_IFREG: u32 = 32768;
pub const S_IFCHR: u32 = 8192;
pub const S_IFLNK: u32 = 40960;
pub const S_IFBLK: u32 = 24576;
pub const S_IFIFO: u32 = 4096;
pub const S_IFSOCK: u32 = 49152;
pub const S_ISUID: u32 = 2048;
pub const S_ISGID: u32 = 1024;
pub const S_ISVTX: u32 = 512;
pub const S_IRUSR: u32 = 256;
pub const S_IWUSR: u32 = 128;
pub const S_IXUSR: u32 = 64;
pub const S_IRGRP: u32 = 32;
pub const S_IWGRP: u32 = 16;
pub const S_IXGRP: u32 = 8;
pub const S_IROTH: u32 = 4;
pub const S_IWOTH: u32 = 2;
pub const S_IXOTH: u32 = 1;
pub const STAFETO_STAT_SIZE: u32 = 120;
pub const DT_UNKNOWN: u32 = 0;
pub const DT_DIR: u32 = 4;
pub const DT_REG: u32 = 8;
pub const DT_CHR: u32 = 2;
pub const NAME_MAX: u32 = 128;
pub const STAFETO_DIRENT_SIZE: u32 = 144;
