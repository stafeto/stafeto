// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
/* The part of Linux's <linux/capability.h> that htop uses to ask the
 * permitted capabilities of a process with the raw capget call. stafeto has
 * no such call: the request fails and htop shows the process as not
 * elevated. */
#ifndef STAFETO_LINUX_CAPABILITY_H
#define STAFETO_LINUX_CAPABILITY_H
#include <stdint.h>
#include <sys/syscall.h>
#define _LINUX_CAPABILITY_VERSION_3 0x20080522
struct __user_cap_header_struct {
    uint32_t version;
    int pid;
};
struct __user_cap_data_struct {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};
#ifndef SYS_capget
#define SYS_capget 90
#endif
#endif
