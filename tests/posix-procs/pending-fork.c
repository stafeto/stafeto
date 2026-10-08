/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
extern int files_pending_begin(int, int);
extern int files_pending_finish(int, int);
extern int files_pending_ack(int, int);
extern int files_pending_child_empty(void);
extern int files_pending_parent_live(void);
static int check_pending_fork(void) {
    int source = open("/etc/motd", O_RDONLY);
    if (source < 0) return 1;
    int target = files_pending_begin(source, 0);
    if (target < 0) return 2;
    pid_t child = fork();
    if (child < 0) return 3;
    if (child == 0) {
        if (files_pending_child_empty()) _exit(1);
        errno = 0;
        if (fcntl(target, F_GETFD) != -1 || errno != EBADF) _exit(2);
        int fresh = open("/etc/motd", O_RDONLY);
        if (fresh < 0 || close(fresh)) _exit(3);
        _exit(0);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 4;
    if (files_pending_parent_live()) return 5;
    if (files_pending_finish(0, -1) || files_pending_ack(0, target)) return 6;
    char bytes[3];
    if (read(target, bytes, 3) != 3 || memcmp(bytes, "sta", 3)) return 7;
    if (close(target) || close(source)) return 8;
    puts("posix-files: fork child discards Pending and preserves parent exact job ok");
    return 0;
}
