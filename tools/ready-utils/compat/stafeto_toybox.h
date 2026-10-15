// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
// Linux constants toybox's portability layer uses and the system lacks: the
// request of the block device size and the number of renameat2 (AArch64).
// Nothing here is reached by file or iconv.
#ifndef STAFETO_TOYBOX_H
#define STAFETO_TOYBOX_H
#define BLKGETSIZE64 0x80081272
#define SYS_renameat2 276
#endif
