/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#ifndef STAFETO_SYS_TYPES_H
#define STAFETO_SYS_TYPES_H
#include <stddef.h>
#include <stdint.h>
typedef int pid_t;
typedef uint64_t pthread_t;
typedef uint64_t pthread_key_t;
typedef struct { uint64_t __state; } pthread_once_t;
typedef struct {
    uint64_t __magic;
    size_t __stack_size;
    size_t __guard_size;
    int __detached;
    unsigned int __reserved;
} pthread_attr_t;
typedef struct { uint64_t __metadata, __owner, __count; uint32_t __word, __reserved; } pthread_mutex_t;
typedef struct { uint64_t __magic; int __kind; unsigned int __reserved; } pthread_mutexattr_t;
typedef uint64_t dev_t;
typedef uint64_t ino_t;
typedef uint32_t mode_t;
typedef uint64_t nlink_t;
typedef uint32_t uid_t;
typedef uint32_t gid_t;
typedef int64_t time_t;
typedef int clockid_t;
typedef int64_t blkcnt_t;
typedef int64_t blksize_t;
typedef int64_t off_t;
typedef intptr_t ssize_t;
#endif
