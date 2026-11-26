// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

// What shim.c and implementation.c both name: the bytes the state of a thread
// keeps for pixman's cache of the paths it found (pixman-implementation.c has 8
// entries of an implementation pointer and a fast path record, 56 bytes each;
// implementation.c asserts it fits).
#ifndef PXS_H
#define PXS_H

#define PXS_CACHE_BYTES 1024

#ifdef PXS_HOST_STATE
extern void *pxs_host_state;
#endif

void *pxs_cache(void);
void pxs_worker_enter(void);

#endif
