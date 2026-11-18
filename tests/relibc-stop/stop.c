/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The two POSIX programs of the probe of the stop of the process service
 * (xtask nvme-persist stop-handlers). `handle` takes SIGTERM with a handler,
 * says so and exits with 0. `ignore` ignores SIGTERM and never ends by
 * itself: the process service kills it with SIGKILL after its wait. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t got_term;

static void on_term(int signo) {
    (void)signo;
    got_term = 1;
}

static void set_action(void (*handler)(int)) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL);
}

int main(int argc, char **argv) {
    int ignore = argc >= 2 && strcmp(argv[1], "ignore") == 0;
    set_action(ignore ? SIG_IGN : on_term);
    printf("relibc-stop: %s ready\n", ignore ? "ignorer" : "handler");
    fflush(stdout);
    for (;;) {
        if (got_term) {
            printf("relibc-stop: handler got SIGTERM and exits\n");
            fflush(stdout);
            return 0;
        }
        sleep(1);
    }
}
