/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
int files_loader_abort_sleep(void) {
    const struct timespec delay = {0, 10000000};
    return nanosleep(&delay, NULL);
}
extern int files_image_gates(int fd);
int main(void) {
    int fd = open("/etc/motd", O_RDONLY);
    if (fd < 0) return 1;
    int result = files_image_gates(fd);
    char byte = 0;
    if (result || pread(fd, &byte, 1, 0) != 1 || byte != 's') {
        close(fd);
        return 2;
    }
    if (close(fd)) return 3;
#if IMAGE_GATES_NORMAL
    puts("posix-files: normal SetId gates ok");
#else
    puts("posix-files: actual Take Handoff and ambiguous SetId gates ok");
#endif
    return 0;
}
