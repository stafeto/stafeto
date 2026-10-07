// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile unsigned copied = 0x13579;
static const unsigned expected = 0x13579;

int main(void) {
    const pid_t original = getpid();
    if (original <= 0 || copied != expected) {
        return 1;
    }
    printf("initial-fork: Init-adopted parent %d before fork\n", original);
    const pid_t child = fork();
    if (child < 0) {
        const int saved = errno;
        printf("initial-fork: fork failed errno %d\n", saved);
        return 10;
    }
    if (child == 0) {
        if (getpid() <= 0 || getpid() == original || getppid() != original || copied != expected) {
            _exit(2);
        }
        copied = 0x24680;
        if (copied != 0x24680) {
            _exit(3);
        }
        printf("initial-fork: child copied initial image\n");
        fflush(stdout);
        _exit(23);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 23) {
        return 4;
    }
    if (getpid() != original || copied != expected) {
        return 5;
    }
    printf("initial-fork: parent retained initial image and reaped child\n");
    return 0;
}
