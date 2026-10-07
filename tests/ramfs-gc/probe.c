/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#include <stdio.h>
#include <time.h>
extern int files_gc_binding(void);
int files_gc_sleep(void) {
    const struct timespec pause = {0, 10000000};
    return nanosleep(&pause, NULL);
}
int main(void) {
    int result = files_gc_binding();
    if (result) { printf("ramfs-gc: failed %d\n", result); return 1; }
    puts("ramfs-gc: binding and page reclamation both progress ok");
    return 0;
}
