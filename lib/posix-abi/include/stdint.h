/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#ifndef STAFETO_STDINT_H
#define STAFETO_STDINT_H
typedef __INT32_TYPE__ int32_t;
typedef __UINT32_TYPE__ uint32_t;
typedef __INT64_TYPE__ int64_t;
typedef __UINT64_TYPE__ uint64_t;
typedef __INTPTR_TYPE__ intptr_t;
typedef __UINTPTR_TYPE__ uintptr_t;
#define INT64_MAX __INT64_MAX__
#define INT64_C(value) value ## L
#define UINT64_C(value) value ## UL
#define SIZE_MAX __SIZE_MAX__
#endif
