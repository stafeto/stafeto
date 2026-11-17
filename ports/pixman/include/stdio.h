// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

// pixman logs errors and debug lines through these; the shim drops them.
#pragma once
#include <stddef.h>

typedef struct pxs_file FILE;
extern FILE *stderr;
int fprintf(FILE *f, const char *format, ...);
int printf(const char *format, ...);
