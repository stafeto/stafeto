/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The probe of POSIX processes (5b).
 *
 * Stage 1, posix_spawn from the boot image through the process service:
 * the parent spawns a child, which says its PID and its parent's (xtask
 * compares them with the parent's line); a path outside /boot and a name
 * of no record give ENOENT; a second spawn of a record whose child lives
 * EAGAIN; a child that does not load ENOMEM, with no PID; file actions,
 * flags outside SETPGROUP and SETSID EINVAL.
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
 * Stage 4, process groups and sessions: the probe leads a group and a
 * session; three children join a group by POSIX_SPAWN_SETPGROUP, killpg
 * ends them with SIGTERM, and waitpid(-pgid) takes them alone, leaving a
 * zombie of the probe's own group; setpgid of a child that started is
 * EACCES, and a spawn into a group no session has EPERM; kill(0) reaches
 * the probe's group, kill(-1) every process but the probe; children that
 * call setsid and setpgid themselves (role ids) see EPERM for a leader
 * and the new numbers on their page and through the service.
 *
 * Stage 5, credentials and the clock: clock_settime is the clock service's
 * to allow only to an effective UID of 0, which it asks the process
 * service once and remembers with the generation of the credentials. The
 * probe is root; seteuid(65534) takes the right at once (EPERM), seteuid(0)
 * gives it back, and setuid(65534) takes it for good: the call right after
 * a change of the credentials sees the new ones.
 *
 * Stage 6, churn: 1100 children one after the other, so that the
 * identity sessions of the ended do not fill the service's channel.
 *
 * The first argument picks the role: none for the parent, else that of
 * the child of a record (`main`). */
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
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
        printf("posix-procs: %s gave %d (%s), expected %d\n", what, got, strerror(got), want);
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
        printf("posix-procs: %s ended with status %#x, expected exit %d\n", what, status, code);
        failures++;
    }
    if (signal != 0 && !(WIFSIGNALED(status) && WTERMSIG(status) == signal)) {
        printf("posix-procs: %s ended with status %#x, expected signal %d\n", what, status, signal);
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

/* Spawns `path` with the spawn-flags `flags` and the group `group`. */
static int spawn_in(pid_t *pid, const char *path, int flags, pid_t group) {
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, flags);
    posix_spawnattr_setpgroup(&attr, group);
    int e = spawn(pid, path, NULL, &attr);
    posix_spawnattr_destroy(&attr);
    return e;
}

/* The ids a child of `flags` sees (role ids) end with exit 0. */
static void ids_child(int flags, const char *what) {
    pid_t child = -1;
    int e = spawn_in(&child, "/boot/procs-ids", flags, 0);
    expect(what, e, 0);
    if (e == 0) reap(what, child, 0, 0);
}

/* Stage 4: process groups, sessions, killpg, kill(0) and kill(-1). */
static void groups(void) {
    pid_t me = getpid();
    int status = 0;
    expect("the probe leads its group", getpgrp() == me && getpgid(0) == me, 1);
    expect("the probe leads its session", getsid(0) == me && getsid(me) == me, 1);
    expect("setsid of a leader", setsid() == -1 && errno == EPERM, 1);
    expect("setpgid of a session leader", setpgid(0, 0) == -1 && errno == EPERM, 1);
    expect("getpgid of no process", getpgid(99999) == -1 && errno == ESRCH, 1);
    expect("getsid of no process", getsid(99999) == -1 && errno == ESRCH, 1);
    expect("setpgid of no child", setpgid(99999, 0) == -1 && errno == ESRCH, 1);
    expect("setpgid of PID 1", setpgid(1, 0) == -1 && errno == ESRCH, 1);
    expect("setpgid of a negative group", setpgid(0, -1) == -1 && errno == EINVAL, 1);

    /* A group no session has, and both flags, are refused with no child. */
    pid_t none = -7;
    expect("a group that does not exist",
           spawn_in(&none, "/boot/procs-child", POSIX_SPAWN_SETPGROUP, 12345), EPERM);
    expect("SETSID with SETPGROUP",
           spawn_in(&none, "/boot/procs-child", POSIX_SPAWN_SETSID | POSIX_SPAWN_SETPGROUP, 0),
           EPERM);
    expect("no PID for a refused group", none, -7);

    /* A child of the probe's own group; it ends at once and stays a zombie. */
    pid_t seven = start("/boot/procs-exit7");
    expect("a child's group is its parent's", getpgid(seven) == me && getsid(seven) == me, 1);

    /* Three children in a group of their own. */
    pid_t g1 = -1, g2 = -1, g3 = -1;
    expect("a child in a new group",
           spawn_in(&g1, "/boot/procs-sleeper", POSIX_SPAWN_SETPGROUP, 0), 0);
    expect("its group is its PID, its session the probe's", getpgid(g1) == g1 && getsid(g1) == me, 1);
    expect("setpgid of a child that started", setpgid(g1, g1) == -1 && errno == EACCES, 1);
    expect("a child in that group",
           spawn_in(&g2, "/boot/procs-sleep2", POSIX_SPAWN_SETPGROUP, g1), 0);
    expect("a second child in that group",
           spawn_in(&g3, "/boot/procs-catch", POSIX_SPAWN_SETPGROUP, g1), 0);
    expect("the joined groups", getpgid(g2) == g1 && getpgid(g3) == g1, 1);
    pause_ms(100);
    expect("killpg", killpg(g1, SIGTERM), 0);
    int seen = 0;
    for (int i = 0; i < 3; i++) {
        pid_t got = waitpid(-g1, &status, 0);
        int member = got == g1 || got == g2 || got == g3;
        expect("waitpid(-pgid) takes a member", member, 1);
        expect("the member's end", WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM, 1);
        seen += got == g1;
        seen += got == g2;
        seen += got == g3;
    }
    expect("each member once", seen, 3);
    expect("waitpid(-pgid) of a group with no children left",
           waitpid(-g1, &status, WNOHANG) == -1 && errno == ECHILD, 1);
    reap("the zombie of the probe's group, which waitpid(-pgid) left", seven, 7, 0);
    expect("killpg of a group nobody is in", killpg(g1, SIGTERM) == -1 && errno == ESRCH, 1);
    expect("killpg of group 1", killpg(1, SIGTERM) == -1 && errno == EINVAL, 1);

    /* kill(0) reaches the probe's own group, itself and a child. */
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = on_usr1;
    action.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &action, NULL);
    handled = 0;
    pid_t c = start("/boot/procs-catch");
    pause_ms(100);
    expect("kill(0)", kill(0, SIGUSR1), 0);
    expect("the probe's handler before kill(0) returned", handled, 1);
    reap("a child of the probe's group after kill(0)", c, 42, 0);

    /* kill(-1) reaches a child of another group and skips the probe. */
    handled = 0;
    expect("a child in a group of its own",
           spawn_in(&c, "/boot/procs-catch", POSIX_SPAWN_SETPGROUP, 0), 0);
    pause_ms(100);
    expect("kill(-1)", kill(-1, SIGUSR1), 0);
    expect("kill(-1) left the sender out", handled, 0);
    reap("a child of another group after kill(-1)", c, 42, 0);
    expect("kill(-1) with no one else", kill(-1, SIGUSR1) == -1 && errno == ESRCH, 1);
    expect("kill of a group nobody is in", kill(-12345, SIGUSR1) == -1 && errno == ESRCH, 1);

    ids_child(0, "a child that makes its own session");
    ids_child(POSIX_SPAWN_SETPGROUP, "a child that moves between groups");
    ids_child(POSIX_SPAWN_SETSID, "a child that leads a session");
}

/* Stage 5: credentials and the clock service. */
static void clock_rights(void) {
    struct timespec now;
    expect("clock_gettime", clock_gettime(CLOCK_REALTIME, &now), 0);
    expect("clock_settime as root", clock_settime(CLOCK_REALTIME, &now), 0);
    expect("clock_settime again with the credentials unchanged", clock_settime(CLOCK_REALTIME, &now), 0);
    expect("seteuid(65534)", seteuid(65534), 0);
    expect("clock_settime after seteuid(65534)", clock_settime(CLOCK_REALTIME, &now) == -1 && errno == EPERM, 1);
    expect("clock_settime once more", clock_settime(CLOCK_REALTIME, &now) == -1 && errno == EPERM, 1);
    expect("seteuid(0)", seteuid(0), 0);
    expect("clock_settime after seteuid(0)", clock_settime(CLOCK_REALTIME, &now), 0);
    expect("setuid(65534)", setuid(65534), 0);
    expect("clock_settime right after setuid", clock_settime(CLOCK_REALTIME, &now) == -1 && errno == EPERM, 1);
    expect("seteuid(0) of a process that dropped root", seteuid(0) == -1 && errno == EPERM, 1);
}

static void said_atexit(void) { printf("posix-procs: the last thread ran atexit\n"); }

static void *leave_waiter(void *arg) {
    (void)arg;
    sigset_t usr1;
    sigemptyset(&usr1);
    sigaddset(&usr1, SIGUSR1);
    int signal = 0;
    if (sigwait(&usr1, &signal) == 0 && signal == SIGUSR1)
        printf("posix-procs: a thread took SIGUSR1 after main left\n");
    return NULL;
}

/* A child that starts with SIGUSR1 blocked: its main thread leaves, the
 * thread that waits for SIGUSR1 is the router then, and its pthread_exit,
 * the last, ends the process as exit(0) does, atexit handlers included. */
static int leave(void) {
    atexit(said_atexit);
    pthread_t waiter;
    pthread_create(&waiter, NULL, leave_waiter, NULL);
    pthread_exit(NULL);
}

static volatile int info_code = -1, info_pid = -1;
static void on_usr1_info(int signal, siginfo_t *info, void *context) {
    (void)signal;
    (void)context;
    info_code = info->si_code;
    info_pid = info->si_pid;
}

/* Signals that arrive early or with a handler that exits, and a thread that takes a signal after main left. */
static void wave(void) {
    /* A signal right after posix_spawn, before the child bound its entry. */
    pid_t sleeper = start("/boot/procs-sleeper");
    expect("kill right after posix_spawn", kill(sleeper, SIGTERM), 0);
    reap("a sleeper killed at once", sleeper, 0, SIGTERM);

    /* A wait told of a child SA_NOCLDWAIT reaped waits for the next end. */
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = SIG_DFL;
    action.sa_flags = SA_NOCLDWAIT;
    sigaction(SIGCHLD, &action, NULL);
    start("/boot/procs-exit7");
    start("/boot/procs-nap");
    int status = -1;
    expect("waitpid(-1) with SA_NOCLDWAIT", (int)waitpid(-1, &status, 0) == -1 && errno == ECHILD, 1);
    action.sa_flags = 0;
    sigaction(SIGCHLD, &action, NULL);

    /* A handler with SA_SIGINFO sees the sender of a process signal. */
    memset(&action, 0, sizeof action);
    action.sa_sigaction = on_usr1_info;
    action.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &action, NULL);
    expect("kill with SA_SIGINFO", kill(getpid(), SIGUSR1), 0);
    expect("si_code of kill", info_code, SI_USER);
    expect("si_pid of kill", info_pid, (int)getpid());

    /* A child starts with the caller's mask (SIGUSR2 blocked since stage
     * 3) and the parent's SIG_IGN. */
    signal(SIGPIPE, SIG_IGN);
    reap("a child with the mask", start("/boot/procs-child"), 0, 0);
    signal(SIGPIPE, SIG_DFL);

    /* The router after the main thread left, and exit(0) of the last. */
    sigset_t usr1;
    sigemptyset(&usr1);
    sigaddset(&usr1, SIGUSR1);
    sigprocmask(SIG_BLOCK, &usr1, NULL);
    pid_t leaver = start("/boot/procs-child");
    sigprocmask(SIG_UNBLOCK, &usr1, NULL);
    pause_ms(200);
    expect("kill of a child whose main thread left", kill(leaver, SIGUSR1), 0);
    reap("a child whose last thread left", leaver, 0, 0);
}

/* The roles of the children. */
static int role(const char *name) {
    if (strcmp(name, "child") == 0) {
        sigset_t mask;
        sigprocmask(SIG_BLOCK, NULL, &mask);
        if (sigismember(&mask, SIGUSR1)) return leave();
        struct sigaction pipe;
        sigaction(SIGPIPE, NULL, &pipe);
        if (sigismember(&mask, SIGUSR2) && pipe.sa_handler == SIG_IGN)
            printf("posix-procs: a child inherits the mask and SIG_IGN\n");
        printf("posix-procs: child %d of %d\n", (int)getpid(), (int)getppid());
        return 0;
    }
    if (strcmp(name, "sleep") == 0 || strcmp(name, "sleep2") == 0) {
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
    if (strcmp(name, "ids") == 0) {
        pid_t me = getpid(), parent_group = getpgid(getppid());
        if (getsid(0) == me) { /* SETSID: a session and a group of its own */
            if (getpgrp() != me || getpgid(me) != me) return 1;
            if (setpgid(0, 0) != -1 || errno != EPERM) return 2;
            if (setsid() != -1 || errno != EPERM) return 3;
            return 0;
        }
        if (getpgrp() == me) { /* SETPGROUP: a group of its own, in the parent's session */
            if (getsid(0) != getsid(getppid())) return 4;
            if (setsid() != -1 || errno != EPERM) return 5;
            if (setpgid(0, parent_group) != 0 || getpgrp() != parent_group) return 6;
            if (setpgid(0, 0) != 0 || getpgrp() != me) return 7;
            return 0;
        }
        /* Plain: the parent's group and session, so setsid works. */
        if (getpgrp() != parent_group || getsid(0) != getsid(getppid())) return 8;
        if (setsid() != me || getsid(0) != me || getpgrp() != me) return 9;
        if (setpgid(0, 0) != -1 || errno != EPERM) return 10;
        if (setsid() != -1 || errno != EPERM) return 11;
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

/* Stage 6: more children than the service has places for sessions, one
 * after the other (1100; the identity sessions of the ended stay in the
 * service until it receives their ends: its 1024 places fill without it). */
static void churn(void) {
    for (int i = 0; i < 1100; i++) {
        pid_t pid = start("/boot/procs-exit7");
        if (pid < 0) {
            printf("posix-procs: the %dth child did not start\n", i);
            return;
        }
        reap("a child of the churn", pid, 7, 0);
        if (failures) return;
    }
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
    posix_spawnattr_destroy(&attr);
    expect("no PID for a refused spawn", none, -7);

    waits(child);
    kills(sleeper);
    groups();
    churn();
    clock_rights();
    wave();
    if (failures == 0) printf("posix-procs: ok\n");
    return failures == 0 ? 0 : 1;
}
