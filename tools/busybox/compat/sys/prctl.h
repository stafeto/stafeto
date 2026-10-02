// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
/* Linux's <sys/prctl.h>, which relibc lacks: BusyBox names a NOFORK
 * applet's task with it; stafeto has no such name, so the call fails. */
#ifndef STAFETO_SYS_PRCTL_H
#define STAFETO_SYS_PRCTL_H
#include <errno.h>
static inline int prctl(int option, ...) {
    (void)option;
    errno = ENOSYS;
    return -1;
}
#endif
