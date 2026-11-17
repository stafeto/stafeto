// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

// The few functions of <string.h> that littlefs uses, for the build with no C library.
// memcpy, memset and memcmp come from the Rust runtime, the others from shim.c.
#ifndef DATAFS_STRING_H
#define DATAFS_STRING_H

#include <stddef.h>

void *memcpy(void *dest, const void *src, size_t n);
void *memset(void *dest, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
char *strcpy(char *dest, const char *src);
char *strchr(const char *s, int c);
size_t strspn(const char *s, const char *accept);
size_t strcspn(const char *s, const char *reject);

#endif
