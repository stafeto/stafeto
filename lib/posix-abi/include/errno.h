/* SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1 */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#ifndef STAFETO_ERRNO_H
#define STAFETO_ERRNO_H
#include <stafeto/abi.h>
int *__errno_location(void);
#define errno (*__errno_location())
#endif
