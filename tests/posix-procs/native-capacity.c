/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdint.h>
#include <unistd.h>
extern char **environ;
extern int capacity_previous_main(void);
extern int files_capacity_run(int role, int command, int response, int data0, int data1);
int capacity_spawn_factory(int role, int command, int response, int data0, int data1) {
    char c[16], r[16], a[16], b[16];
    snprintf(c, sizeof c, "%d", command); snprintf(r, sizeof r, "%d", response);
    snprintf(a, sizeof a, "%d", data0); snprintf(b, sizeof b, "%d", data1);
    char *av[] = {"/bin/capacity-probe", role == 1 ? "factory-a" : "factory-b", c, r, a, b, NULL};
    pid_t pid; int e = posix_spawn(&pid, av[0], NULL, NULL, av, environ);
    return e ? -e : pid;
}
int capacity_wait_child(int pid, int killed) {
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) return errno;
    if (killed) return WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL ? 0 : EIO;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : EIO;
}
int capacity_stat(int fd, uint64_t out[13]) {
    struct stat s;
    if (fstat(fd, &s)) return errno;
    out[0] = s.st_size; out[1] = s.st_blocks; out[2] = s.st_ino;
    out[3] = s.st_mode; out[4] = s.st_nlink; out[5] = s.st_uid; out[6] = s.st_gid;
    out[7] = s.st_atim.tv_sec; out[8] = s.st_atim.tv_nsec;
    out[9] = s.st_mtim.tv_sec; out[10] = s.st_mtim.tv_nsec;
    out[11] = s.st_ctim.tv_sec; out[12] = s.st_ctim.tv_nsec;
    return 0;
}
int main(int argc, char **argv) {
    int role = argc == 1 && !strcmp(argv[0], "capacity-a") ? 1 :
               argc == 1 && !strcmp(argv[0], "capacity-b") ? 2 :
               argc == 6 && !strcmp(argv[1], "factory-a") ? 3 :
               argc == 6 && !strcmp(argv[1], "factory-b") ? 4 : 0;
    if (!role) return 30;
    int result = files_capacity_run(role, role > 2 ? atoi(argv[2]) : -1,
        role > 2 ? atoi(argv[3]) : -1, role > 2 ? atoi(argv[4]) : -1,
        role > 2 ? atoi(argv[5]) : -1);
    if (result) { printf("capacity: role %d failed errno %d\n", role, result); return 31; }
    if (role == 1) return capacity_previous_main();
    return 0;
}
