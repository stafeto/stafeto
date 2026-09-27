// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
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
extern int32_t stafeto_dir_read(const char *path, size_t length, uint32_t index,
                                char *name, size_t capacity, uint32_t *kind);
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

/* This single-process probe keeps its working directory in userspace. */
static char current_directory[129] = "/";

static const char *root_path(const char *path, char resolved[129]) {
    if (path == NULL) { errno = EFAULT; return NULL; }
    if (*path == '\0') { errno = ENOENT; return NULL; }
    size_t used = 1;
    if (*path == '/') {
        resolved[0] = '/';
        resolved[1] = '\0';
    } else {
        memcpy(resolved, current_directory, strlen(current_directory) + 1);
        used = strlen(resolved);
    }
    while (*path != '\0') {
        while (*path == '/') path++;
        const char *part = path;
        while (*path != '\0' && *path != '/') path++;
        size_t length = (size_t)(path - part);
        if (length == 0 || (length == 1 && part[0] == '.')) continue;
        if (length == 2 && part[0] == '.' && part[1] == '.') {
            while (used > 1 && resolved[used - 1] != '/') used--;
            if (used > 1) used--;
            resolved[used] = '\0';
            continue;
        }
        size_t separator = used > 1 ? 1 : 0;
        if (used + separator + length >= 129) { errno = ENAMETOOLONG; return NULL; }
        if (separator != 0) resolved[used++] = '/';
        memcpy(resolved + used, part, length);
        used += length;
        resolved[used] = '\0';
    }
    return resolved;
}

char *getcwd(char *buf, size_t size) {
    size_t length = strlen(current_directory) + 1;
    if (buf == NULL) {
        buf = malloc(length);
        if (buf == NULL) return NULL;
        size = length;
    }
    if (size < length) { errno = ERANGE; return NULL; }
    memcpy(buf, current_directory, length);
    return buf;
}

int chdir(const char *path) {
    char resolved[129];
    if (root_path(path, resolved) == NULL) return -1;
    struct stat st;
    if (stat(resolved, &st) != 0) return -1;
    if (!S_ISDIR(st.st_mode)) { errno = ENOTDIR; return -1; }
    memcpy(current_directory, resolved, strlen(resolved) + 1);
    return 0;
}

int open(const char *path, int flags, ...) {
    char resolved[129];
    path = root_path(path, resolved);
    if (path == NULL) return -1;
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

int stat(const char *path, struct stat *st) {
    char resolved[129];
    path = root_path(path, resolved);
    if (path == NULL) return -1;
    if (strcmp(path, "/") == 0 || strcmp(path, ".") == 0 ||
        strcmp(path, "/etc") == 0 || strcmp(path, "/tmp") == 0) {
        memset(st, 0, sizeof(*st));
        st->st_mode = S_IFDIR | 0555;
        return 0;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    int result = fstat(fd, st);
    close(fd);
    return result;
}

int lstat(const char *path, struct stat *st) {
    return stat(path, st);
}

ssize_t readlink(const char *path, char *buf, size_t size) {
    (void)buf;
    (void)size;
    struct stat st;
    if (stat(path, &st) == 0) errno = EINVAL;
    return -1;
}

DIR *opendir(const char *path) {
    char resolved[129];
    path = root_path(path, resolved);
    if (path == NULL) return NULL;
    size_t length = strlen(path);
    if (length >= sizeof(((DIR *)0)->buf)) { errno = ENAMETOOLONG; return NULL; }
    DIR *dir = malloc(sizeof(*dir));
    if (dir == NULL) return NULL;
    uint32_t kind = 0;
    char name[sizeof(dir->dirent.d_name)];
    int32_t result = stafeto_dir_read(path, length, 0, name, sizeof(name) - 1, &kind);
    if (error(result) != 0) { free(dir); return NULL; }
    memset(dir, 0, sizeof(*dir));
    memcpy(dir->buf, path, length + 1);
    return dir;
}

struct dirent *readdir(DIR *dir) {
    uint32_t kind = 0;
    const char *path = dir->buf;
    int32_t result = stafeto_dir_read(path, strlen(path), dir->offset,
                                      dir->dirent.d_name,
                                      sizeof(dir->dirent.d_name) - 1, &kind);
    if (error(result) != 0) return NULL;
    if (result == 0) { errno = 0; return NULL; }
    dir->dirent.d_name[result] = '\0';
    dir->dirent.d_type = kind == 1 ? DT_DIR : DT_REG;
    dir->dirent.d_ino = dir->offset + 1;
    dir->offset++;
    return &dir->dirent;
}

int closedir(DIR *dir) {
    free(dir);
    return 0;
}

void _exit(int status) {
    stafeto_exit(status);
}
