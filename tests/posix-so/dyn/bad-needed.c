/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* A bad program: the link adds a second library (libx.so) to its
 * DT_NEEDED. The loader refuses it. */
#include <stdio.h>

extern int libx_value(void);

int main(void) {
    printf("bad-needed: ran %d\n", libx_value());
    return 0;
}
