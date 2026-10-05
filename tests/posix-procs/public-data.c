/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#include <sys/stat.h>

/* build.rs compiles every libc call with -fno-builtin. */
static int check_public_data(void) {
    int fd = open("/tmp/public-data", O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (fd < 0) return 1;
    unsigned char input[1012], bytes[1016];
    for (size_t i = 0; i < sizeof(input); ++i) input[i] = (unsigned char)(i * 17);
    if (write(fd, input, sizeof(input)) != (ssize_t)sizeof(input)) return 2;
    if (lseek(fd, 0, SEEK_CUR) != 1012) return 3;
    if (pread(fd, bytes, sizeof(bytes), 0) != 1012 || memcmp(bytes, input, 1012)) return 4;
    if (lseek(fd, 0, SEEK_CUR) != 1012) return 5;
    if (pwrite(fd, "tail", 4, 1012) != 4 || lseek(fd, 0, SEEK_CUR) != 1012) return 6;
    if (pread(fd, bytes, sizeof(bytes), 0) != 1016 || memcmp(bytes + 1012, "tail", 4)) return 7;
    int alias = dup(fd);
    if (alias < 0 || lseek(alias, 8, SEEK_SET) != 8 || read(fd, bytes, 3) != 3) return 8;
    if (memcmp(bytes, input + 8, 3) || lseek(alias, 0, SEEK_CUR) != 11) return 9;
    if (ftruncate(fd, 9) || pread(alias, bytes, sizeof(bytes), 0) != 9) return 10;
    if (memcmp(bytes, input, 9) || ftruncate(alias, 20)) return 11;
    memset(bytes, 255, sizeof(bytes));
    if (pread(fd, bytes, 20, 0) != 20 || memcmp(bytes, input, 9)) return 12;
    for (size_t i = 9; i < 20; ++i) if (bytes[i]) return 13;
    if (write(fd, input, 0) || pread(fd, bytes, 0, 0)) return 14;
    errno = 0;
    if (ftruncate(fd, -1) != -1 || errno != EINVAL) return 15;
    struct stat info;
    if (fstat(fd, &info) || info.st_size != 20) return 16;
    errno = 0;
    if (ftruncate(-1, -1) != -1 || errno != EBADF) return 17;
    int readonly = open("/tmp/public-data", O_RDONLY);
    errno = 0;
    if (readonly < 0 || ftruncate(readonly, 0) != -1 || errno != EBADF) return 18;
    if (fstat(fd, &info) || info.st_size != 20 || close(readonly)) return 19;
    int directory = open("/tmp", O_RDONLY | O_DIRECTORY);
    errno = 0;
    if (directory < 0 || ftruncate(directory, 0) != -1 || errno != EISDIR) return 20;
    if (close(directory) || close(alias) || close(fd)) return 21;
    errno = 0;
    if (ftruncate(fd, 0) != -1 || errno != EBADF) return 22;
    int random = open("/dev/urandom", O_RDWR);
    if (random < 0 || read(random, bytes, 4) != 4 || write(random, input, 4) != 4) return 23;
    errno = 0;
    if (pread(random, bytes, 1, 0) != -1 || errno != ESPIPE) return 24;
    if (close(random)) return 25;
    int ends[2];
    if (pipe(ends) || write(ends[1], "pipe", 4) != 4 || read(ends[0], bytes, 4) != 4) return 26;
    if (memcmp(bytes, "pipe", 4) || close(ends[0]) || close(ends[1])) return 27;
    return 0;
}
