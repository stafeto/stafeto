// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
// progs/transform.h as ncurses' Makefile writes it for names without a prefix
// or a suffix.
#ifndef __TRANSFORM_H
#define __TRANSFORM_H 1
#include <progs.priv.h>
extern bool same_program(const char *, const char *);
#define PROG_CAPTOINFO "captoinfo"
#define PROG_INFOTOCAP "infotocap"
#define PROG_CLEAR     "clear"
#define PROG_RESET     "reset"
#define PROG_INIT      "init"
#endif /* __TRANSFORM_H */
