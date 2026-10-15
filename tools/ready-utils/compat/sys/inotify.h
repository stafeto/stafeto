// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
#ifndef STAFETO_SYS_INOTIFY_H
#define STAFETO_SYS_INOTIFY_H
#include <stdint.h>
struct inotify_event {
	int wd;
	uint32_t mask, cookie, len;
	char name[];
};
#define IN_MODIFY 2
int inotify_init(void);
int inotify_add_watch(int, const char *, uint32_t);
#endif
