// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
/* Linux's <sys/statfs.h>, which relibc lacks: htop's SELinux meter asks
 * whether /sys/fs/selinux is mounted with it. stafeto has no such mount and
 * no statfs call: the request fails and the meter shows SELinux as off. */
#ifndef STAFETO_SYS_STATFS_H
#define STAFETO_SYS_STATFS_H
#include <errno.h>
#include <sys/types.h>
/* Linux's value of the read-only flag of statvfs, which relibc's header lacks. */
#ifndef ST_RDONLY
#define ST_RDONLY 1
#endif
struct statfs {
    long f_type;
    long f_bsize;
};
static inline int statfs(const char *path, struct statfs *buf) {
    (void)path;
    (void)buf;
    errno = ENOSYS;
    return -1;
}
#endif
