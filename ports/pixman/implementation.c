// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

// pixman-implementation.c, whole, with the one thing it keeps for each
// thread (the cache of the fast paths it found, PIXMAN_DEFINE_THREAD_LOCAL)
// kept in the record of the calling thread's state (shim.c, pxs_cache) as the
// allocator's arena is. The library is built without thread-local storage
// (PIXMAN_NO_TLS), so its own macros would make one cache for every thread.

#include <pixman-config.h>
#include <stdlib.h>
#include "pixman-private.h"
#include "pxs.h"

#undef PIXMAN_DEFINE_THREAD_LOCAL
#undef PIXMAN_GET_THREAD_LOCAL
#define PIXMAN_DEFINE_THREAD_LOCAL(type, name)
#define PIXMAN_GET_THREAD_LOCAL(name) ((void *) pxs_cache ())

#include "pixman-implementation.c"

_Static_assert (sizeof (cache_t) <= PXS_CACHE_BYTES,
		"the cache of fast paths fits the state record");
