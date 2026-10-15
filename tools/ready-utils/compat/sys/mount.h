// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
// Declarations toybox includes on Linux and the system lacks: no code.
#ifndef STAFETO_SYS_MOUNT_H
#define STAFETO_SYS_MOUNT_H
#define MS_RDONLY 1
#define MS_REMOUNT 32
int mount(const char *, const char *, const char *, unsigned long, const void *);
int umount2(const char *, int);
#endif
