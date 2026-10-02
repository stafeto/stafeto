/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The probe of POSIX processes (5b).
 *
 * Stage 1, posix_spawn from the boot image through the process service:
 * the parent spawns a child, which says its PID and its parent's (xtask
 * compares them with the parent's line); a path outside /boot and a name
 * of no record give ENOENT; a second spawn of a record whose child lives
 * EAGAIN; a child that does not load ENOMEM, with no PID; file actions,
 * flags outside SETPGROUP and SETSID, and until process groups come those
 * two too, EINVAL.
 *
 * Stage 2, zombies and waits: the child is waited for, and the same
 * record spawned again at once; WNOHANG before a child's end gives 0; a
 * signal in waitpid with SA_RESTART waits on, without it EINTR; exit(7)
 * gives WIFEXITED 7, a load from address 0 WIFSIGNALED SIGSEGV; waitid
 * with WNOWAIT leaves the zombie for the next wait; a grandchild whose
 * parent ended sees getppid() 1; a PID that is no child is ECHILD; with
 * the build's limit of four children (feature children-max-4 of the
 * service), a fifth is EAGAIN, zombies counted.
 *
 * Stage 3, kill (the first goal of 5b): SIGTERM to a child without a
 * handler gives WIFSIGNALED SIGTERM, apart from exit(143); SIGKILL ends a
 * child that blocks every signal and spins; a child that catches SIGUSR1
 * exits with 42 from its handler; SIGCHLD comes to sigwaitinfo with the
 * child's PID, CLD_EXITED and its status; a signal to the probe's own
 * process runs its handler before kill returns, and one its main thread
 * blocks goes to the thread that lets it through.
 *
 * The first argument picks the role: none for the parent, else that of
 * the child of a record (`main`). */
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
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

static void pause_ms(long ms) {
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000L};
    while (nanosleep(&t, &t) != 0) {
    }
}

/* Spawns the record `path`; its PID, or -1 after a failure. */
static pid_t start(const char *path) {
    pid_t pid = -1;
    int e = spawn(&pid, path, NULL, NULL);
    if (e != 0) {
        printf("posix-procs: spawn of %s gave %d (%s)\n", path, e, strerror(e));
        failures++;
        return -1;
    }
    return pid;
}

/* Waits for `pid` and checks its end: exited with `code`, or killed by
 * `signal` when it is not 0. */
static void reap(const char *what, pid_t pid, int code, int signal) {
    int status = -1;
    pid_t got = waitpid(pid, &status, 0);
    if (got != pid) {
        printf("posix-procs: waitpid of %s gave %d (%s)\n", what, (int)got, strerror(errno));
        failures++;
        return;
    }
    if (signal == 0 && !(WIFEXITED(status) && WEXITSTATUS(status) == code)) {
        printf("posix-procs: %s ended with status %#x, not exit %d\n", what, status, code);
        failures++;
    }
    if (signal != 0 && !(WIFSIGNALED(status) && WTERMSIG(status) == signal)) {
        printf("posix-procs: %s ended with status %#x, not signal %d\n", what, status, signal);
        failures++;
    }
}

static volatile int handled;
static void on_usr1(int signal) {
    (void)signal;
    handled++;
}

static pthread_t main_thread;
/* Sends SIGUSR1 to the main thread 50 ms after its start. */
static void *poke(void *arg) {
    (void)arg;
    pause_ms(50);
    pthread_kill(main_thread, SIGUSR1);
    return NULL;
}

/* A waitpid of procs-nap, which ends 300 ms after its start, with SIGUSR1
 * in the wait: with SA_RESTART the wait goes on, without it EINTR. */
static void interrupted_wait(int restart) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = on_usr1;
    action.sa_flags = restart ? SA_RESTART : 0;
    sigaction(SIGUSR1, &action, NULL);
    handled = 0;
    pid_t nap = start("/boot/procs-nap");
    pthread_t helper;
    main_thread = pthread_self();
    pthread_create(&helper, NULL, poke, NULL);
    int status = -1;
    pid_t got = waitpid(nap, &status, 0);
    int error = errno;
    pthread_join(helper, NULL);
    if (restart) {
        expect("waitpid with SA_RESTART", got == nap && WIFEXITED(status) && WEXITSTATUS(status) == 3, 1);
    } else {
        expect("waitpid without SA_RESTART", got == -1 && error == EINTR, 1);
        reap("procs-nap after EINTR", nap, 3, 0);
    }
    expect("the handler in the wait", handled, 1);
}

static void exit_42(int signal) {
    (void)signal;
    _exit(42);
}

static volatile pthread_t usr2_thread;
static volatile int usr2_ready, usr2_done;
static void on_usr2(int signal) {
    (void)signal;
    usr2_thread = pthread_self();
    usr2_done = 1;
}
/* Lets SIGUSR2 through and waits until a handler ran. */
static void *usr2_taker(void *arg) {
    (void)arg;
    sigset_t usr2;
    sigemptyset(&usr2);
    sigaddset(&usr2, SIGUSR2);
    pthread_sigmask(SIG_UNBLOCK, &usr2, NULL);
    usr2_ready = 1;
    for (int i = 0; i < 300 && !usr2_done; i++) pause_ms(10);
    return NULL;
}

/* Stage 3: kill and SIGCHLD, with the sleeper of stage 1 alive. */
static void kills(pid_t sleeper) {
    expect("kill of the sleeper", kill(sleeper, SIGTERM), 0);
    reap("the sleeper after SIGTERM", sleeper, 0, SIGTERM);
    expect("kill of a taken child", kill(sleeper, SIGTERM) == -1 && errno == ESRCH, 1);

    pid_t blocker = start("/boot/procs-block");
    pause_ms(100);
    expect("SIGTERM to a child that blocks it", kill(blocker, SIGTERM), 0);
    expect("SIGKILL", kill(blocker, SIGKILL), 0);
    reap("the blocker after SIGKILL", blocker, 0, SIGKILL);

    pid_t catcher = start("/boot/procs-catch");
    pause_ms(100);
    expect("kill of the catcher", kill(catcher, SIGUSR1), 0);
    reap("the catcher", catcher, 42, 0);

    sigset_t chld;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    sigprocmask(SIG_BLOCK, &chld, NULL);
    pid_t seven = start("/boot/procs-exit7");
    siginfo_t info;
    memset(&info, 0, sizeof info);
    expect("sigwaitinfo for SIGCHLD", sigwaitinfo(&chld, &info), SIGCHLD);
    expect("SIGCHLD's si_pid", info.si_pid, (int)seven);
    expect("SIGCHLD's si_code", info.si_code, CLD_EXITED);
    expect("SIGCHLD's si_status", info.si_status, 7);
    reap("procs-exit7 after SIGCHLD", seven, 7, 0);
    sigprocmask(SIG_UNBLOCK, &chld, NULL);

    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = on_usr1;
    action.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &action, NULL);
    handled = 0;
    expect("kill of its own process", kill(getpid(), SIGUSR1), 0);
    expect("its handler before kill returned", handled, 1);

    action.sa_handler = on_usr2;
    sigaction(SIGUSR2, &action, NULL);
    sigset_t usr2;
    sigemptyset(&usr2);
    sigaddset(&usr2, SIGUSR2);
    sigprocmask(SIG_BLOCK, &usr2, NULL);
    pthread_t taker;
    pthread_create(&taker, NULL, usr2_taker, NULL);
    while (!usr2_ready) pause_ms(1);
    expect("kill of SIGUSR2 the main thread blocks", kill(getpid(), SIGUSR2), 0);
    pthread_join(taker, NULL);
    expect("SIGUSR2 on the thread that lets it through", usr2_done && pthread_equal(usr2_thread, taker), 1);
}

/* The roles of the children. */
static int role(const char *name) {
    if (strcmp(name, "child") == 0) {
        printf("posix-procs: child %d of %d\n", (int)getpid(), (int)getppid());
        return 0;
    }
    if (strcmp(name, "sleep") == 0) {
        for (;;) sleep(60);
    }
    if (strcmp(name, "nap") == 0) {
        pause_ms(300);
        return 3;
    }
    if (strcmp(name, "exit7") == 0) return 7;
    if (strcmp(name, "segv") == 0) {
        volatile int *zero = NULL;
        return *zero;
    }
    if (strcmp(name, "middle") == 0) {
        pid_t orphan = start("/boot/procs-orphan");
        return orphan > 0 ? 0 : 1;
    }
    if (strcmp(name, "block") == 0) {
        sigset_t all;
        sigfillset(&all);
        sigprocmask(SIG_BLOCK, &all, NULL);
        for (volatile unsigned long i = 0;; i++) {
        }
    }
    if (strcmp(name, "catch") == 0) {
        struct sigaction action;
        memset(&action, 0, sizeof action);
        action.sa_handler = exit_42;
        sigaction(SIGUSR1, &action, NULL);
        for (;;) sleep(60);
    }
    if (strcmp(name, "orphan") == 0) {
        for (int i = 0; i < 300 && getppid() != 1; i++) pause_ms(10);
        if (getppid() != 1) return 1;
        printf("posix-procs: orphan saw ppid 1\n");
        return 0;
    }
    return 125;
}

/* Stage 2: zombies, waitpid, waitid, orphans and the limit of children,
 * with `child` of stage 1 alive or a zombie and the sleeper alive. */
static void waits(pid_t child) {
    reap("procs-child", child, 0, 0);
    pid_t again = start("/boot/procs-child");
    reap("procs-child spawned again", again, 0, 0);

    pid_t nap = start("/boot/procs-nap");
    int status = -1;
    expect("WNOHANG before the end", (int)waitpid(nap, &status, WNOHANG), 0);
    reap("procs-nap", nap, 3, 0);
    interrupted_wait(1);
    interrupted_wait(0);

    reap("procs-exit7", start("/boot/procs-exit7"), 7, 0);
    reap("procs-segv", start("/boot/procs-segv"), 0, SIGSEGV);

    pid_t seven = start("/boot/procs-exit7");
    siginfo_t info;
    memset(&info, 0, sizeof info);
    expect("waitid WNOWAIT", waitid(P_PID, (id_t)seven, &info, WEXITED | WNOWAIT), 0);
    expect("waitid's si_pid", info.si_pid, (int)seven);
    expect("waitid's si_code", info.si_code, CLD_EXITED);
    expect("waitid's si_status", info.si_status, 7);
    reap("procs-exit7 after WNOWAIT", seven, 7, 0);
    expect("waitpid of a child taken", (int)waitpid(seven, &status, 0) == -1 && errno == ECHILD, 1);

    reap("procs-middle", start("/boot/procs-middle"), 0, 0);
    expect("waitpid of PID 1", (int)waitpid(1, &status, 0) == -1 && errno == ECHILD, 1);
    expect("waitpid of its own PID", (int)waitpid(getpid(), &status, WNOHANG) == -1 && errno == ECHILD, 1);
    expect("waitpid(-1, WNOHANG) with the sleeper alive", (int)waitpid(-1, &status, WNOHANG), 0);

    /* The sleeper and three zombies make four children: a fifth is EAGAIN. */
    pid_t zombies[3] = {start("/boot/procs-exit7"), start("/boot/procs-segv"), start("/boot/procs-child")};
    pause_ms(100);
    pid_t fifth = -7;
    expect("a fifth child", spawn(&fifth, "/boot/procs-nap", NULL, NULL), EAGAIN);
    reap("a zombie procs-exit7", zombies[0], 7, 0);
    reap("a zombie procs-segv", zombies[1], 0, SIGSEGV);
    reap("a zombie procs-child", zombies[2], 0, 0);
}

int main(int argc, char **argv) {
    if (argc > 1) return role(argv[1]);
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

    waits(child);
    kills(sleeper);
    if (failures == 0) printf("posix-procs: ok\n");
    return failures == 0 ? 0 : 1;
}
