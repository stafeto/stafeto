// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

// The few functions of <stdlib.h> that pixman calls. The allocator is the
// arena of shim.c, under names of its own so that it cannot meet another
// malloc in the program.
#pragma once
#include <stddef.h>

void *pxs_malloc(size_t n);
void *pxs_calloc(size_t a, size_t b);
void *pxs_realloc(void *p, size_t n);
void pxs_free(void *p);
#define malloc pxs_malloc
#define calloc pxs_calloc
#define realloc pxs_realloc
#define free pxs_free

void abort(void);
char *getenv(const char *name);
