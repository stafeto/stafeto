// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

// The configuration pixman's build would write (pixman/meson.build): the
// portable C paths alone, no threads (PIXMAN_NO_TLS is a flag of the build
// script), no SIMD, no timers.
#define PACKAGE "pixman"
