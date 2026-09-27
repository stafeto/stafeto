// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int c_probe(void) {
    FILE *motd = fopen("/etc/motd", "r");
    if (!motd) return 1;
    char text[32] = {0};
    size_t n = fread(text, 1, sizeof(text) - 1, motd);
    if (fclose(motd) != 0 || n != 14 || strcmp(text, "stafeto ramfs\n") != 0) return 2;
    if (open("/absent", O_RDONLY) != -1 || errno != ENOENT) return 3;
    int fd = open("/tmp/probe", O_RDWR);
    if (fd < 0) return 4;
    if (write(fd, "abc", 3) != 3 || lseek(fd, 1, SEEK_SET) != 1 || write(fd, "Z", 1) != 1) return 5;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size != 3 || !S_ISREG(st.st_mode)) return 6;
    if (lseek(fd, 0, SEEK_SET) != 0 || read(fd, text, 3) != 3 || memcmp(text, "aZc", 3) != 0) return 7;
    if (close(fd) != 0) return 8;
    /* Check the RAM session's bounded description limit and errno mapping. */
    int held[32];
    for (size_t i = 0; i < 32; i++) {
        held[i] = open("/etc/motd", O_RDONLY);
        if (held[i] < 0) return 9;
    }
    if (open("/etc/motd", O_RDONLY) != -1 || errno != EMFILE) return 10;
    for (size_t i = 0; i < 32; i++) {
        if (close(held[i]) != 0) return 11;
    }
    fd = open("/etc/motd", O_RDONLY);
    if (fd < 0 || close(fd) != 0) return 12;
    printf("cprobe: Picolibc file IO ok\n");
    fflush(stdout);
    return 0;
}
