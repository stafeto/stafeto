/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#ifndef STAFETO_STDDEF_H
#define STAFETO_STDDEF_H
#define NULL ((void *)0)
#define offsetof(type, member) __builtin_offsetof(type, member)
typedef __SIZE_TYPE__ size_t;
typedef __PTRDIFF_TYPE__ ptrdiff_t;
#endif
