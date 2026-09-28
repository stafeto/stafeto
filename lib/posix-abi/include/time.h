/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#ifndef STAFETO_TIME_H
#define STAFETO_TIME_H
#include <sys/types.h>
struct timespec {
    time_t tv_sec;
    long tv_nsec;
};
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
int clock_gettime(clockid_t clock, struct timespec *value);
int clock_getres(clockid_t clock, struct timespec *resolution);
int clock_settime(clockid_t clock, const struct timespec *value);
#endif
