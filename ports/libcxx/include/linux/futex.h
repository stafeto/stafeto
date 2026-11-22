/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The two operations of futex(2) that libc++'s std::atomic::wait and
 * notify (libcxx/src/atomic.cpp) use, and the number of the call on AArch64.
 * relibc's syscall() answers this number with the layer's waits by address
 * (src/header/unistd/syscall.rs of the fork). Only tools/build-libcxx.py puts
 * this header on a path; programs never include it. */
#ifndef STAFETO_LINUX_FUTEX_H
#define STAFETO_LINUX_FUTEX_H

#define FUTEX_WAIT_PRIVATE 128
#define FUTEX_WAKE_PRIVATE 129

#ifndef SYS_futex
#define SYS_futex 98
#endif

#endif
