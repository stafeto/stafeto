/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#ifndef STAFETO_DIRENT_H
#define STAFETO_DIRENT_H
#include <sys/types.h>
#include <stafeto/abi.h>
typedef struct stafeto_DIR DIR;
struct dirent {
    ino_t d_ino;
    unsigned char d_type;
    char d_name[NAME_MAX + 1];
};
DIR *opendir(const char *path);
DIR *fdopendir(int fd);
struct dirent *readdir(DIR *dir);
int closedir(DIR *dir);
int dirfd(DIR *dir);
void rewinddir(DIR *dir);
long telldir(DIR *dir);
void seekdir(DIR *dir, long position);
int scandir(const char *path, struct dirent ***namelist,
        int (*select)(const struct dirent *),
        int (*compare)(const struct dirent **, const struct dirent **));
int alphasort(const struct dirent **left, const struct dirent **right);
#endif
