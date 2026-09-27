// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

extern int32_t stafeto_open(const char *path, size_t length, uint32_t flags);
extern int32_t stafeto_close(uint32_t fd);
extern intptr_t stafeto_read(uint32_t fd, void *buf, size_t count);
extern intptr_t stafeto_write(uint32_t fd, const void *buf, size_t count);
extern int64_t stafeto_seek(uint32_t fd, uint32_t offset);
extern int64_t stafeto_size(uint32_t fd);
extern void stafeto_exit(int status) __attribute__((noreturn));

static int error(int64_t value) {
    if (value >= 0) return 0;
    switch (-value) {
        case 300: errno = ENOENT; break;
        case 301: errno = EBADF; break;
        case 303: errno = ENOSPC; break;
        default: errno = EIO; break;
    }
    return -1;
}

int open(const char *path, int flags, ...) {
    int32_t result = stafeto_open(path, strlen(path), flags & O_ACCMODE);
    if (error(result) != 0) return -1;
    return result;
}

int close(int fd) {
    int32_t result = stafeto_close(fd);
    return error(result);
}

ssize_t read(int fd, void *buf, size_t count) {
    intptr_t result = stafeto_read(fd, buf, count);
    if (error(result) != 0) return -1;
    return result;
}

ssize_t write(int fd, const void *buf, size_t count) {
    intptr_t result = stafeto_write(fd, buf, count);
    if (error(result) != 0) return -1;
    return result;
}

off_t lseek(int fd, off_t offset, int whence) {
    if (whence != SEEK_SET || offset < 0 || (uint64_t)offset > UINT32_MAX) {
        errno = EINVAL;
        return -1;
    }
    int64_t result = stafeto_seek(fd, (uint32_t)offset);
    if (error(result) != 0) return -1;
    return result;
}

int fstat(int fd, struct stat *st) {
    int64_t result = stafeto_size(fd);
    if (error(result) != 0) return -1;
    memset(st, 0, sizeof(*st));
    st->st_mode = S_IFREG | 0644;
    st->st_size = result;
    return 0;
}

void _exit(int status) {
    stafeto_exit(status);
}
