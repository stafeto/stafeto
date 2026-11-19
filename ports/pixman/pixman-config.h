// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

// The configuration pixman's build would write (pixman/meson.build): the
// portable C paths, no threads (PIXMAN_NO_TLS is a flag of the build
// script), no timers. The build script appends USE_ARM_A64_NEON (the NEON
// paths) unless it builds the portable paths alone.
#define PACKAGE "pixman"
