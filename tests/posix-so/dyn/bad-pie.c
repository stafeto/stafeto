/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* A bad program: it is a position-independent executable (-pie). The loader refuses it. */
#include <stdio.h>

int main(void) {
    printf("bad-pie: ran\n");
    return 0;
}
