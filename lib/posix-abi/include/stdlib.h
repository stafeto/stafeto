/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#ifndef STAFETO_STDLIB_H
#define STAFETO_STDLIB_H
#include <stddef.h>
void *malloc(size_t size);
void *calloc(size_t count, size_t size);
void *realloc(void *pointer, size_t size);
void *reallocarray(void *pointer, size_t count, size_t size);
void free(void *pointer);
void *aligned_alloc(size_t alignment, size_t size);
int posix_memalign(void **out, size_t alignment, size_t size);
void qsort(void *base, size_t count, size_t width,
        int (*compare)(const void *, const void *));
void qsort_r(void *base, size_t count, size_t width,
        int (*compare)(const void *, const void *, void *), void *context);
#endif
