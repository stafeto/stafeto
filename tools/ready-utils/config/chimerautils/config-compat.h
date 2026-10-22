// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
// What chimerautils' meson writes for a C library with strlcpy, strlcat, errc
// and warnc and without strtonum, reallocf, strtoq, fts_open and rpmatch.
#define HAVE_STRLCPY 1
#define HAVE_STRLCAT 1
#define HAVE_ERRC 1
#define HAVE_WARNC 1
