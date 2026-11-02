/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* A bad program: its code is not position independent (compiled with
 * -fno-pic) and the link allows copy relocations, so environ is copied
 * into the program (R_AARCH64_COPY). The loader refuses it. */
#include <stdio.h>

extern char **environ;

int main(void) {
    printf("bad-copy: ran %d\n", environ != NULL);
    return 0;
}
