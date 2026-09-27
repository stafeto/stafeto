/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#ifndef STAFETO_FCNTL_H
#define STAFETO_FCNTL_H
#include <stafeto/abi.h>
/* ABI 1 supports access mode and O_CLOEXEC/O_CLOFORK; creation is pending. */
int open(const char *path, int flags, ...);
#endif
