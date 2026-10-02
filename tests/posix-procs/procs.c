/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The probe of POSIX processes (5b), stage 1: posix_spawn from the boot
 * image through the process service. The parent spawns a child, which
 * says its PID and its parent's (xtask compares them with the parent's
 * line); a path outside /boot and a name of no record give ENOENT; a
 * second spawn of a record whose child lives EAGAIN; a child that does
 * not load ENOMEM, with no PID; file actions, flags outside SETPGROUP and
 * SETSID, and until process groups come those two too, EINVAL. The first
 * argument picks the role: none for the parent, `child` and `sleep` for
 * the children of the records procs-child and procs-sleeper. */
#include <errno.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* The spawn-flags the process service takes are those of Linux, which
 * relibc's header gives (proto_process::SPAWN_SETPGROUP, SPAWN_SETSID). */
_Static_assert(POSIX_SPAWN_SETPGROUP == 0x02 && POSIX_SPAWN_SETSID == 0x80,
               "the spawn-flags of the process service");

static int failures;

static void expect(const char *what, int got, int want) {
    if (got != want) {
        printf("posix-procs: %s gave %d (%s), not %d\n", what, got, strerror(got), want);
        failures++;
    }
}

static int spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *actions,
                 const posix_spawnattr_t *attr) {
    char *argv[] = {"posix-procs", NULL};
    char *envp[] = {NULL};
    return posix_spawn(pid, path, actions, attr, argv, envp);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "child") == 0) {
        printf("posix-procs: child %d of %d\n", (int)getpid(), (int)getppid());
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "sleep") == 0) {
        for (;;) sleep(60);
    }
    pid_t child = 0;
    int e = spawn(&child, "/boot/procs-child", NULL, NULL);
    expect("spawn of procs-child", e, 0);
    printf("posix-procs: parent %d spawned %d\n", (int)getpid(), (int)child);

    pid_t none = -7;
    expect("spawn of /boot/none", spawn(&none, "/boot/none", NULL, NULL), ENOENT);
    expect("spawn of /bin/procs-child", spawn(&none, "/bin/procs-child", NULL, NULL), ENOENT);
    expect("spawn of the probe's own record", spawn(&none, "/boot/posix-procs", NULL, NULL),
           ENOENT);

    pid_t sleeper = 0;
    expect("spawn of procs-sleeper", spawn(&sleeper, "/boot/procs-sleeper", NULL, NULL), 0);
    expect("a second spawn of procs-sleeper", spawn(&none, "/boot/procs-sleeper", NULL, NULL),
           EAGAIN);

    expect("spawn of procs-big", spawn(&none, "/boot/procs-big", NULL, NULL), ENOMEM);
    expect("no PID for a child that did not load", none, -7);

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addclose(&actions, 1);
    expect("file actions", spawn(&none, "/boot/procs-child", &actions, NULL), EINVAL);
    posix_spawn_file_actions_destroy(&actions);

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK);
    expect("POSIX_SPAWN_SETSIGMASK", spawn(&none, "/boot/procs-child", NULL, &attr), EINVAL);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP);
    expect("POSIX_SPAWN_SETPGROUP before process groups",
           spawn(&none, "/boot/procs-child", NULL, &attr), EINVAL);
    posix_spawnattr_destroy(&attr);
    expect("no PID for a refused spawn", none, -7);

    if (failures == 0) printf("posix-procs: ok\n");
    return failures == 0 ? 0 : 1;
}
