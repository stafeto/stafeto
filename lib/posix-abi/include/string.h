/* SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1 */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#ifndef STAFETO_STRING_H
#define STAFETO_STRING_H
#include <stddef.h>
int strcmp(const char *left, const char *right);
int strcoll(const char *left, const char *right);
size_t strxfrm(char *restrict destination, const char *restrict source, size_t count);
#endif
