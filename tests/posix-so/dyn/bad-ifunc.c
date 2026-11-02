/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* A bad program: an indirect function gives it an R_AARCH64_IRELATIVE
 * relocation. The loader refuses it. */
#include <stdio.h>

static volatile int choice;
static int one(void) { return 1; }
static int two(void) { return 2; }
/* The resolver reads a variable, so that the compiler cannot fold the call. */
static int (*resolver(void))(void) { return choice ? two : one; }
int chosen(void) __attribute__((ifunc("resolver")));

int main(void) {
    printf("bad-ifunc: ran %d\n", chosen());
    return 0;
}
