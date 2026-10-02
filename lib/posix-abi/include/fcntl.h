/* SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1 */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#ifndef STAFETO_FCNTL_H
#define STAFETO_FCNTL_H
#include <stafeto/abi.h>
/* ABI 1 supports access mode, O_DIRECTORY and O_CLOEXEC/O_CLOFORK; creation is pending. */
int open(const char *path, int flags, ...);
#endif
