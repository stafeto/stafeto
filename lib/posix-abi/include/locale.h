/* SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1 */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#ifndef STAFETO_LOCALE_H
#define STAFETO_LOCALE_H
#include <stddef.h>
#include <stafeto/abi.h>
char *setlocale(int category, const char *locale);
#endif
