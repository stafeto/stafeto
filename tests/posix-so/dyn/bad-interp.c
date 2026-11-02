/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* A bad program: it names another dynamic linker (--dynamic-linker=/lib/other.so). The loader refuses it. */
#include <stdio.h>

int main(void) {
    printf("bad-interp: ran\n");
    return 0;
}
