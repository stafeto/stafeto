/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* A bad program: a strong reference to a name libc.so lacks. The link
 * ran against a stand-in libc.so that has it. The loader refuses it. */
#include <stdio.h>

extern int so_missing(void);

int main(void) {
    printf("bad-symbol: ran %d\n", so_missing());
    return 0;
}
