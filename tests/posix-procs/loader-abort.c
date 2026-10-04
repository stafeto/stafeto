/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#include <time.h>

extern int files_loader_abort_capture(int fd, int loaded);

int files_loader_abort_sleep(void) {
    const struct timespec delay = {0, 10000000};
    return nanosleep(&delay, NULL);
}

static int files_loader_abort(void) {
    int pid = getpid();
    int fd = open("/etc/motd", O_RDONLY);
    if (fd < 0) return 1;
    int result = files_loader_abort_capture(fd, 0);
    if (!result) result = files_loader_abort_capture(fd, 1);
    char byte = 0;
    if (result || getpid() != pid || pread(fd, &byte, 1, 0) != 1 || byte != 's') {
        close(fd);
        return 2;
    }
    if (close(fd)) return 3;
    puts("posix-files: genuine loader abort releases retained capture ok");
    return 0;
}
