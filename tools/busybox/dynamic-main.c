/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The main of the dynamically linked BusyBox of the images (spec 2, 3.12.3;
 * tools/build-libc-so.py programs). It does what the Rust main of
 * tests/busybox does in the applets build: the getty of the dialog, the
 * name `sh`, and BusyBox's dispatcher, which build-busybox.py renames to
 * applets_main. */
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char **environ;
int applets_main(int argc, char **argv);

/* The first argument of the getty that ash-launcher spawns: a session of its
 * own, the console as its controlling terminal on 0, 1 and 2, then
 * `/bin/ash -i`; 126 when a step fails, 127 when the exec does. */
static int getty(void) {
    char *argv[] = {"ash", "-i", NULL};
    if (setsid() < 0) _exit(126);
    int console = open("/dev/console", O_RDWR);
    if (console < 0) _exit(126);
    for (int fd = 0; fd < 3; fd++)
        if (dup2(console, fd) < 0) _exit(126);
    if (console > 2) close(console);
    /* The console is an xterm-compatible terminal; ncurses reads its entry. */
    if (setenv("TERM", "xterm-256color", 1) != 0) _exit(126);
    execve("/bin/ash", argv, environ);
    _exit(127);
}

int main(int argc, char **argv) {
    if (argc > 0 && strcmp(argv[0], "ash-getty") == 0) return getty();
    /* The configuration has no applet named `sh` (the shell is `ash`), and
     * `system`, `popen` and `wordexp` start `/bin/sh` with the name `sh`. */
    if (argc > 0 && (strcmp(argv[0], "sh") == 0 || strcmp(argv[0], "/bin/sh") == 0))
        argv[0] = "ash";
    return applets_main(argc, argv);
}
