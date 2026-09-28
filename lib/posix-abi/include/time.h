/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#ifndef STAFETO_TIME_H
#define STAFETO_TIME_H
#include <sys/types.h>
struct timespec {
    time_t tv_sec;
    long tv_nsec;
};
#endif
