/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>
extern char **environ;
extern int files_cleanup_owner(unsigned phase);
extern int files_cleanup_check(unsigned phase);
int main(int argc, char **argv) {
    if (argc == 2 && argv[1][0] >= '0' && argv[1][0] <= '2' && !argv[1][1])
        return files_cleanup_owner((unsigned)(argv[1][0] - '0'));
    for (unsigned phase = 0; phase < 3; ++phase) {
        char value[] = {(char)('0' + phase), 0};
        char *args[] = {"posix-files", value, 0};
        pid_t child; int status;
        if (posix_spawn(&child, "/bin/posix-files", 0, 0, args, environ)) return 20;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 21;
        unsigned attempt;
        for (attempt = 0; attempt < 100; ++attempt) {
            int result = files_cleanup_check(phase);
            if (!result) break;
            if (result != 1) return 22;
            struct timespec pause = {0, 10000000};
            if (nanosleep(&pause, 0)) return 23;
        }
        if (attempt == 100) return 24;
        printf("ramfs-cleanup: owner dead, phase %u, foreign holder retained, resources released\n", phase + 1);
    }
    puts("ramfs-cleanup: ok");
    return 0;
}
