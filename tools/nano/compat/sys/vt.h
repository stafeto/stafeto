// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
/* Linux's <sys/vt.h>, which relibc lacks: nano asks the terminal whether it
 * is a Linux virtual console with VT_GETSTATE. The console of stafeto is a
 * serial terminal, and its ioctl does not know the request. */
#ifndef STAFETO_SYS_VT_H
#define STAFETO_SYS_VT_H
#define VT_GETSTATE 0x5603
struct vt_stat {
    unsigned short v_active;
    unsigned short v_signal;
    unsigned short v_state;
};
#endif
