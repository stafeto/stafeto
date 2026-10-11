// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
#ifndef LOCK_FULL_EXEC_IO_H
#define LOCK_FULL_EXEC_IO_H
#include <stdint.h>
#include <unistd.h>
/* The caller supplies the corresponding bounded buffer; short I/O never commits. */
static inline int full_exec_io_read(int fd, void *output, unsigned first, unsigned words) {
    if (!output || !words || first >= 352 || words > 352 - first) return -1;
    size_t bytes = words * sizeof(uint64_t);
    return pread(fd, output, bytes, (off_t)(first * sizeof(uint64_t))) != (ssize_t)bytes;
}
static inline int full_exec_io_write(int fd, const void *input, unsigned first, unsigned words) {
    if (!input || !words || first >= 352 || words > 352 - first) return -1;
    size_t bytes = words * sizeof(uint64_t);
    return pwrite(fd, input, bytes, (off_t)(first * sizeof(uint64_t))) != (ssize_t)bytes;
}
#endif
