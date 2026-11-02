/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* A bad program: a thread-local variable gives it a PT_TLS of its own,
 * which libc.so's TLS (module 0) cannot share. The loader refuses it. */
#include <stdio.h>

static _Thread_local int counter = 5;

int main(void) {
    counter++;
    printf("bad-tls: ran %d\n", counter);
    return 0;
}
