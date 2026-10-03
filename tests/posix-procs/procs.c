/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The probe of POSIX processes (5b).
 *
 * Stage 1, posix_spawn from the program's file through the loader: the
 * parent spawns a child (/bin/procs-child, this program in the role its
 * second argument names), which says its PID and its parent's (xtask
 * compares them with the parent's line); a second child of the same
 * program lives beside the first.
 *
 * Stage 2, zombies and waits: the child is waited for, and the same
 * role spawned again at once; WNOHANG before a child's end gives 0; a
 * signal in waitpid with SA_RESTART waits on, without it EINTR; exit(7)
 * gives WIFEXITED 7, a load from address 0 WIFSIGNALED SIGSEGV; waitid
 * with WNOWAIT leaves the zombie for the next wait; a grandchild whose
 * parent ended sees getppid() 1; a PID that is no child is ECHILD.
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
 * Stage 7, posix_spawn from files (5c): the loader in the child opens the
 * program through the RAM file service. /bin/ls lists /etc (the first goal
 * of 5c) and is waited for; a child gets argv and envp; ENOENT, EACCES
 * (a file without execute), ENOEXEC (a file that is no program), E2BIG
 * (65 KiB of arguments) and ENOMEM (a program bigger than the child's
 * quota) come from posix_spawn with no PID; POSIX_SPAWN_SETSIGMASK and
 * POSIX_SPAWN_SETSIGDEF reach the child; the child holds no handle of its
 * loader; a process that is no loader gets EPERM from OpenExec. Once the
 * probe is nobody (stage 5): a set-user-ID file of root runs with euid 0
 * in the secure mode, with POSIX_SPAWN_RESETIDS too; after a set-ID file
 * that failed to load, the next child keeps euid 65534; a directory only
 * root may search gives EACCES. A process has 32 children at most, live
 * or zombies: the 33rd is EAGAIN (5b's CHILDREN_MAX, now reached with
 * children from files, each with the parent's quota from the service's
 * pool).
 *
 * The steps mode (the table `table-posix-steps`, under -icount): the
 * longest step of the process service with a crowd of live children
 * (BRANCHES branches with LEAVES leaves each, every one arming the
 * notification of its identity session every 400 ms), through kill(-1),
 * spawn, exec, the ends of all, and a Vouch (an OpenExec of a process that
 * is no loader) with the identity channel full: xtask process-steps reads
 * the lines the service prints for each new longest step.
 *
 * Stage 8, descriptors through posix_spawn (5c): fd 3 with FD_CLOEXEC is
 * closed in the child, fd 4 dup2'd onto itself and fd 5 a copy of it stay
 * open (os-test posix_spawn_file_actions_adddup2); a description the child
 * reads moves the parent's offset; addopen, addclose and addchdir shape
 * the child's descriptors and current directory, the relative path of the
 * program taken from the new one.
 *
 * Stage 9, exec (5c): a child execs /bin/ls of /etc and its parent's
 * waitpid of the same PID sees exit 0; across exec the PID and the PPID
 * stay, argv and envp are the new ones, FD_CLOEXEC closes, an open file
 * keeps its offset, a caught SIGUSR1 is SIG_DFL, an ignored SIGUSR2 stays
 * ignored, the mask stays and a pending SIGHUP of the calling thread is
 * still pending; an exec of a file that is no program returns ENOEXEC
 * with the process, its other thread and its files as they were; an old
 * image that ends before ExecCommit leaves its own status and the new one
 * never runs; ExecCommit with no exec is refused. The window (`windows`):
 * 40 old images that end before ExecCommit, by exit or SIGKILL, and 8
 * execs while another thread spawns give the service's pool back; an exec
 * while threads wait in waitpid and sleep goes on; SpawnCommit before the
 * loader's image is ready is refused. As nobody: an exec of a set-user-ID
 * file of root gives euid 0, the clock's rights at once, and after a
 * set-ID file that failed to load, the next exec keeps euid 65534; the old
 * image of such an exec is killed at ExecCommit and never sets the clock.
 *
 * Stage forks (5d): fork by a full copy, which the child's loader makes.
 * A program init started (this probe) has no segments in its map and gets
 * ENOSYS. The role forkbare makes bare children, which run on the copy
 * with nothing of the layer bound and say what they saw by their status:
 * the parent's .data, heap and stack as they were at the fork, their own
 * copies of them, none of the parent's writes after it, and a page that
 * ignores what the parent ignores from its start, so the SIGUSR2 the
 * parent sends its group while the copy goes on never waits there; the
 * loader leaves no mapping of the parent's objects. A record has 32
 * children of fork at most (the 33rd is EAGAIN), the pool of the service
 * gives no quota past its own (ENOMEM), and a ForkStart that never got
 * its copy takes neither SpawnCommit nor an early ForkCommit, and leaves
 * no zombie after ForkAbort. The role forkfull forks with the layer bound
 * in the child: it sees the parent's PID as its PPID, the parent's memory
 * and its own copies of it, its mask, a caught and an ignored action, and
 * no pending signal of the parent's; it shares the offset of an open file
 * with its parent, keeps a descriptor with FD_CLOEXEC and loses one with
 * FD_CLOFORK; it opens a file, reads both clocks, makes a thread, grows its
 * heap by 1 MiB, signals its parent, forks a grandchild and execs /bin/ls
 * of /etc, whose status its parent's waitpid gets. A SIGINT the parent
 * sends its group while the copy goes on reaches both; pthread_atfork's
 * handlers run in POSIX's order, and vfork is fork. The role forkthreads
 * forks 40 times from a parent whose five other threads churn the heap
 * and files, make threads and hold the layer's locks: the fork stops them
 * all for its copy, and each child has one thread, mallocs, opens a file
 * and takes a mutex. An exec while a thread makes threads parks the
 * newborn ones too. A fork from a second thread gives a child with that
 * one thread, which forks a grandchild; 20 children of fork killed give
 * the service's pool back, and so does a parent that dies in the window
 * of its fork, after Go or after its first Regions. The bare child checks
 * 512 KiB of the parent's heap, past the 64 KiB pieces of the probes'
 * loader (feature small-pieces). Twenty pairs of forks with no wait
 * between them park the other threads twice running; a thread in
 * nanosleep, one in sigsuspend and one in waitpid go on across forks with
 * no EINTR of theirs, and the forked child has no child; a fork waits for
 * relibc's allocator lock a thread holds while its mapping sleeps in the
 * layer. BusyBox ash from its file runs `/bin/ls /etc && exit
 * 3`, which forks.
 *
 * Stage 10: the probe is a record of init's table, and its end is init's
 * line: the probe execs a child's role that exits with 42, and init
 * reports that status (REPLACED), never the old image's 0.
 *
 * The first argument picks the role: none for the parent, else that of
 * a child (`role`). */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stddef.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* The spawn-flags the process service takes are those of Linux, which
 * relibc's header gives (proto_process::SPAWN_SETPGROUP, SPAWN_SETSID). */
_Static_assert(POSIX_SPAWN_SETPGROUP == 0x02 && POSIX_SPAWN_SETSID == 0x80,
               "the spawn-flags of the process service");

static int failures;

/* The layer's probes of 5c (posix-crt, posix-platform). */
void stafeto_start_handles(unsigned long *out);
int stafeto_probe_open_exec(const char *path);
int stafeto_probe_notify_identity(void);
int stafeto_probe_addopen_cloexec(const char *path);
int stafeto_probe_exec_commit(void);
int stafeto_probe_exec_then_exit(const char *path, char *const argv[], int code);
int stafeto_probe_exec_outlive(const char *path, char *const argv[]);
int stafeto_probe_commit_early(int *pid);
int stafeto_probe_loads(void);
int stafeto_probe_fork_bare(int (*child)(void *), void *arg, void (*window)(void));
unsigned long long stafeto_probe_page(int word);
void stafeto_probe_yield(void);
void stafeto_probe_park(void);
int stafeto_probe_fork_abort(int *pid);
unsigned long long stafeto_probe_map_mappings(void);
void stafeto_probe_fork_window(void (*window)(void));
int stafeto_probe_hold(int which, unsigned long long us);
int stafeto_probe_threads(void);
void stafeto_probe_fork_early(void (*window)(void));
void stafeto_probe_mmap_sleep(unsigned long long us);
unsigned long long stafeto_probe_pool(void);
void stafeto_probe_decoy(int on);
size_t stafeto_probe_memory_map(unsigned long long *out, size_t max);
unsigned long long stafeto_probe_memory_used(void);

static void expect(const char *what, int got, int want) {
    if (got != want) {
        printf("posix-procs: %s gave %d (%s), expected %d\n", what, got, strerror(got), want);
        failures++;
    }
}

/* posix_spawn of /bin/procs-child, this program from its file, in the
 * role `role`. */
static int spawn(pid_t *pid, const char *role, const posix_spawn_file_actions_t *actions,
                 const posix_spawnattr_t *attr) {
    char *argv[] = {"posix-procs", (char *)role, NULL};
    char *envp[] = {NULL};
    return posix_spawn(pid, "/bin/procs-child", actions, attr, argv, envp);
}

static void pause_ms(long ms) {
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000L};
    while (nanosleep(&t, &t) != 0) {
    }
}

/* Spawns the child in role `role`; its PID, or -1 after a failure. */
static pid_t start(const char *role) {
    pid_t pid = -1;
    int e = spawn(&pid, role, NULL, NULL);
    if (e != 0) {
        printf("posix-procs: spawn of %s gave %d (%s)\n", role, e, strerror(e));
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
    pid_t nap = start("nap");
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

    pid_t blocker = start("block");
    pause_ms(100);
    expect("SIGTERM to a child that blocks it", kill(blocker, SIGTERM), 0);
    expect("SIGKILL", kill(blocker, SIGKILL), 0);
    reap("the blocker after SIGKILL", blocker, 0, SIGKILL);

    pid_t catcher = start("catch");
    pause_ms(100);
    expect("kill of the catcher", kill(catcher, SIGUSR1), 0);
    reap("the catcher", catcher, 42, 0);

    sigset_t chld;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    sigprocmask(SIG_BLOCK, &chld, NULL);
    pid_t seven = start("exit7");
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

/* Spawns the child in role `role` with the spawn-flags `flags` and the
 * group `group`. */
static int spawn_in(pid_t *pid, const char *role, int flags, pid_t group) {
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, flags);
    posix_spawnattr_setpgroup(&attr, group);
    int e = spawn(pid, role, NULL, &attr);
    posix_spawnattr_destroy(&attr);
    return e;
}

/* The ids a child of `flags` sees (role ids) end with exit 0. */
static void ids_child(int flags, const char *what) {
    pid_t child = -1;
    int e = spawn_in(&child, "ids", flags, 0);
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
           spawn_in(&none, "child", POSIX_SPAWN_SETPGROUP, 12345), EPERM);
    expect("SETSID with SETPGROUP",
           spawn_in(&none, "child", POSIX_SPAWN_SETSID | POSIX_SPAWN_SETPGROUP, 0),
           EPERM);
    expect("no PID for a refused group", none, -7);

    /* A child of the probe's own group; it ends at once and stays a zombie. */
    pid_t seven = start("exit7");
    expect("a child's group is its parent's", getpgid(seven) == me && getsid(seven) == me, 1);

    /* Three children in a group of their own. */
    pid_t g1 = -1, g2 = -1, g3 = -1;
    expect("a child in a new group",
           spawn_in(&g1, "sleep", POSIX_SPAWN_SETPGROUP, 0), 0);
    expect("its group is its PID, its session the probe's", getpgid(g1) == g1 && getsid(g1) == me, 1);
    expect("setpgid of a child that started", setpgid(g1, g1) == -1 && errno == EACCES, 1);
    expect("a child in that group",
           spawn_in(&g2, "sleep2", POSIX_SPAWN_SETPGROUP, g1), 0);
    expect("a second child in that group",
           spawn_in(&g3, "catch", POSIX_SPAWN_SETPGROUP, g1), 0);
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
    pid_t c = start("catch");
    pause_ms(100);
    expect("kill(0)", kill(0, SIGUSR1), 0);
    expect("the probe's handler before kill(0) returned", handled, 1);
    reap("a child of the probe's group after kill(0)", c, 42, 0);

    /* kill(-1) reaches a child of another group and skips the probe. */
    handled = 0;
    expect("a child in a group of its own",
           spawn_in(&c, "catch", POSIX_SPAWN_SETPGROUP, 0), 0);
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
    pid_t sleeper = start("sleep");
    expect("kill right after posix_spawn", kill(sleeper, SIGTERM), 0);
    reap("a sleeper killed at once", sleeper, 0, SIGTERM);

    /* A wait told of a child SA_NOCLDWAIT reaped waits for the next end. */
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = SIG_DFL;
    action.sa_flags = SA_NOCLDWAIT;
    sigaction(SIGCHLD, &action, NULL);
    start("exit7");
    start("nap");
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
    reap("a child with the mask", start("child"), 0, 0);
    signal(SIGPIPE, SIG_DFL);

    /* The router after the main thread left, and exit(0) of the last. */
    sigset_t usr1;
    sigemptyset(&usr1);
    sigaddset(&usr1, SIGUSR1);
    sigprocmask(SIG_BLOCK, &usr1, NULL);
    pid_t leaver = start("child");
    sigprocmask(SIG_UNBLOCK, &usr1, NULL);
    pause_ms(200);
    expect("kill of a child whose main thread left", kill(leaver, SIGUSR1), 0);
    reap("a child whose last thread left", leaver, 0, 0);
}

/* The arguments of a child, for the roles that look at them. */
static int argc_seen;
static char **argv_seen;

static volatile int caught_usr1;
static void on_usr1_exec(int signal) {
    (void)signal;
    caught_usr1 = 1;
}

/* Before exec: a file at offset 3, one with FD_CLOEXEC, SIGUSR1 caught,
 * SIGUSR2 ignored, SIGHUP blocked and pending for this thread. */
static int exec_self(void) {
    int keep = open("/etc/motd", O_RDONLY);
    char three[3];
    if (keep < 0 || read(keep, three, 3) != 3) return 1;
    int gone = open("/etc/motd", O_RDONLY | O_CLOEXEC);
    if (gone < 0) return 2;
    signal(SIGUSR1, on_usr1_exec);
    signal(SIGUSR2, SIG_IGN);
    sigset_t hup;
    sigemptyset(&hup);
    sigaddset(&hup, SIGHUP);
    sigprocmask(SIG_BLOCK, &hup, NULL);
    raise(SIGHUP);
    char k[8], g[8], p[16], pp[16];
    snprintf(k, sizeof k, "%d", keep);
    snprintf(g, sizeof g, "%d", gone);
    snprintf(p, sizeof p, "%d", (int)getpid());
    snprintf(pp, sizeof pp, "%d", (int)getppid());
    char *next[] = {"procs-child", "after", k, g, p, pp, NULL};
    char *env[] = {"X=2", NULL};
    execve("/bin/procs-child", next, env);
    return 100 + errno;
}

/* After exec: what POSIX says stays and what goes. */
static int after_exec(void) {
    int keep = atoi(argv_seen[2]), gone = atoi(argv_seen[3]);
    struct stat st;
    if (getpid() != atoi(argv_seen[4]) || getppid() != atoi(argv_seen[5])) {
        printf("posix-procs: after exec pid %d ppid %d, before %s %s\n", (int)getpid(),
               (int)getppid(), argv_seen[4], argv_seen[5]);
        return 1;
    }
    if (fstat(gone, &st) == 0 || errno != EBADF) return 2;
    if (lseek(keep, 0, SEEK_CUR) != 3) return 3;
    struct sigaction a;
    sigaction(SIGUSR1, NULL, &a);
    if (a.sa_handler != SIG_DFL) return 4;
    sigaction(SIGUSR2, NULL, &a);
    if (a.sa_handler != SIG_IGN) return 5;
    sigset_t mask, pending;
    sigprocmask(SIG_BLOCK, NULL, &mask);
    sigpending(&pending);
    if (!sigismember(&mask, SIGHUP)) return 6;
    if (!sigismember(&pending, SIGHUP)) return 7;
    const char *x = getenv("X");
    if (!x || strcmp(x, "2") != 0) return 8;
    printf("posix-procs: after exec pid %d\n", (int)getpid());
    /* The process ends with the new image's status: 42, never the old one's 0. */
    return 42;
}

static volatile int spins;
static void *spinner(void *arg) {
    (void)arg;
    for (;;) {
        spins++;
        pause_ms(1);
    }
    return NULL;
}

/* An exec that fails comes back with the other thread running and the
 * files as they were. */
static int exec_fail(void) {
    int fd = open("/etc/motd", O_RDONLY);
    pthread_t other;
    if (fd < 0 || pthread_create(&other, NULL, spinner, NULL) != 0) return 1;
    pause_ms(20);
    char *next[] = {"procs-child", "child", NULL};
    char *env[] = {NULL};
    if (execve("/bin/script", next, env) != -1 || errno != ENOEXEC) return 2;
    int before = spins;
    pause_ms(50);
    if (spins == before) return 3;
    char bytes[7];
    if (read(fd, bytes, 7) != 7 || memcmp(bytes, "stafeto", 7) != 0) return 4;
    return 0;
}

/* An exec while other threads wait in long calls: one in waitpid of a
 * child that never ends, one in sleep. The new image kills and reaps that
 * child, a child of the record since before the exec. */
static pid_t busy_child;
static void *busy_wait(void *arg) {
    (void)arg;
    int status;
    waitpid(busy_child, &status, 0);
    return NULL;
}
static void *busy_sleep(void *arg) {
    (void)arg;
    sleep(60);
    return NULL;
}
static int exec_busy(void) {
    busy_child = start("sleep");
    if (busy_child <= 0) return 1;
    pthread_t a, b;
    if (pthread_create(&a, NULL, busy_wait, NULL) != 0) return 2;
    if (pthread_create(&b, NULL, busy_sleep, NULL) != 0) return 3;
    pause_ms(30);
    char pid[16];
    snprintf(pid, sizeof pid, "%d", (int)busy_child);
    char *next[] = {"procs-child", "reapkill", pid, NULL};
    char *env[] = {NULL};
    execve("/bin/procs-child", next, env);
    return 100 + errno;
}

/* An exec while another thread spawns children without end: the loads
 * the old image started and did not commit go with it (the new image may
 * start two at once), and the new image reaps the children that lived
 * until none is left. */
static void *spawner(void *arg) {
    (void)arg;
    char *argv[] = {"procs-child", "exit7", NULL};
    char *envp[] = {NULL};
    for (;;) {
        pid_t pid;
        if (posix_spawn(&pid, "/bin/procs-child", NULL, NULL, argv, envp) == 0)
            waitpid(pid, NULL, 0);
    }
    return NULL;
}
static int exec_spawning(void) {
    pthread_t other;
    if (pthread_create(&other, NULL, spawner, NULL) != 0) return 1;
    /* Each yield lets the spawner run to its next request: the exec comes
     * at another step of a spawn each time. */
    for (int turns = atoi(argv_seen[2]); turns > 0; turns--) sched_yield();
    char *next[] = {"procs-child", "drain", NULL};
    char *env[] = {NULL};
    execve("/bin/procs-child", next, env);
    return 100 + errno;
}

/* The steps mode: BRANCHES children, each with LEAVES children of its
 * own, all armed. */
#ifndef STEPS_BRANCHES
#define STEPS_BRANCHES 7
#endif
#define STEPS_LEAVES 31

static int steps_spawn(pid_t *pid, const char *role, const char *index) {
    char *argv[] = {"procs-child", (char *)role, (char *)index, NULL};
    char *envp[] = {NULL};
    /* The service loads a few children at once (EAGAIN beyond them). */
    int e;
    for (int tries = 0; tries < 5000; tries++) {
        e = posix_spawn(pid, "/bin/procs-child", NULL, NULL, argv, envp);
        if (e != EAGAIN) return e;
        if (tries == 100) printf("posix-procs: steps: 100 EAGAIN of %s\n", role);
        pause_ms(1);
    }
    return e;
}

/* SIGUSR1 arms the notification of this process's identity session, so
 * that the next Vouch takes one more entry. */
static void arm_identity(int signal) {
    (void)signal;
    stafeto_probe_notify_identity();
}

/* The child of the crowd: it arms on each SIGUSR1 and sleeps. */
static void steps_setup(void) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = arm_identity;
    sigaction(SIGUSR1, &action, NULL);
    /* The first request of the child's session of the RAM files takes the
     * place its Clone held (the service keeps 64 of them for children that
     * sent nothing yet). */
    close(open("/etc/motd", O_RDONLY));
}

/* The role stepfork: five forks, each child ends, after the heap grew by
 * 256 KiB (the child's quota is the steps probe's, 1 MiB). */
static int steps_fork(void) {
    char *heap = malloc(256 * 1024);
    if (!heap) return 60;
    memset(heap, 1, 256 * 1024);
    for (int i = 0; i < 5; i++) {
        pid_t pid = fork();
        if (pid == 0) _exit(7);
        if (pid < 0) {
            printf("posix-procs: steps: fork gave %s\n", strerror(errno));
            return 61;
        }
        int status = -1;
        if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 7) return 62;
    }
    free(heap);
    return 0;
}

static int steps_armed(void) {
    steps_setup();
    for (;;) pause_ms(1000);
}

/* A branch: its leaves, a stamp of /tmp/probe at its index, then armed. */
static int steps_branch(void) {
    int index = atoi(argv_seen[2]);
    steps_setup();
    for (int i = 0; i < STEPS_LEAVES; i++) {
        pid_t pid;
        int e = steps_spawn(&pid, "armed", "0");
        if (e != 0) {
            printf("posix-procs: steps: branch %d leaf %d gave %d (%s)\n", index, i, e, strerror(e));
            return 50;
        }
    }
    int fd = open("/tmp/probe", O_WRONLY);
    unsigned char one = 1;
    if (fd < 0 || pwrite(fd, &one, 1, index) != 1) return 90;
    close(fd);
    for (;;) pause_ms(1000);
}

static int steps_run(void) {
    int failed = 0;
    int fd = open("/tmp/probe", O_RDWR);
    unsigned char zeros[STEPS_BRANCHES] = {0};
    if (fd < 0 || pwrite(fd, zeros, sizeof zeros, 0) != (ssize_t)sizeof zeros) return 2;
    pid_t branches[STEPS_BRANCHES];
    for (int b = 0; b < STEPS_BRANCHES; b++) {
        char index[8];
        snprintf(index, sizeof index, "%d", b);
        int e = steps_spawn(&branches[b], "branch", index);
        if (e != 0) {
            printf("posix-procs: steps: branch %d gave %d (%s)\n", b, e, strerror(e));
            return 3;
        }
    }
    /* The probe's own children, up to the 31 it may keep beside the one
     * that comes and goes (the service allows 32 to a process). */
    int own = STEPS_BRANCHES < 7 ? 0 : 31 - STEPS_BRANCHES;
    for (int i = 0; i < own; i++) {
        pid_t pid;
        if (steps_spawn(&pid, "armed", "0") != 0) return 3;
    }
    for (int turns = 0;; turns++) {
        unsigned char stamps[STEPS_BRANCHES] = {0};
        int ready = pread(fd, stamps, sizeof stamps, 0) == (ssize_t)sizeof stamps;
        for (int b = 0; ready && b < STEPS_BRANCHES; b++) ready = stamps[b] == 1;
        if (ready) break;
        if (turns > 6000) {
            printf("posix-procs: steps: the branches did not finish\n");
            return 4;
        }
        pause_ms(10);
    }
    printf("posix-procs: steps %d children live\n", STEPS_BRANCHES * (STEPS_LEAVES + 1) + own);
    /* kill(-1) in a loop: signal 0 and a signal that is ignored by default. */
    for (int i = 0; i < 20; i++) {
        if (kill(-1, 0) != 0 || kill(-1, SIGCHLD) != 0) {
            printf("posix-procs: steps: kill(-1) gave %s\n", strerror(errno));
            failed++;
            break;
        }
    }
    /* spawn, exec and the end of a child, among the crowd. */
    for (int i = 0; i < 5; i++) {
        pid_t pid = -1;
        if (steps_spawn(&pid, "exit7", "0") != 0) return 5;
        reap("a child among the crowd", pid, 7, 0);
        char *exec_argv[] = {"procs-child", "execto", "/bin/procs-child", "exit7", NULL};
        char *envp[] = {NULL};
        if (posix_spawn(&pid, "/bin/procs-child", NULL, NULL, exec_argv, envp) != 0) return 5;
        reap("a child that execs among the crowd", pid, 7, 0);
    }
    /* fork among the crowd, from a child (a program init started cannot
     * fork): ForkStart, the loader's copy and ForkCommit. */
    pid_t forker = -1;
    if (steps_spawn(&forker, "stepfork", "0") != 0) return 5;
    reap("a child that forks among the crowd", forker, 0, 0);
    /* Volleys: SIGUSR1 to the crowd arms every identity session. A change
     * of the credentials moves their generation, and the clock service
     * asks the process service who the caller is again (Vouch) when
     * clock_settime comes: nothing drains the channel before it. */
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0) failed++;
    for (int volley = 0; volley < 5; volley++) {
        pause_ms(1000);
        if (kill(-1, SIGUSR1) != 0) failed++;
        pause_ms(1000);
        if (seteuid(65534) != 0 || seteuid(0) != 0 || clock_settime(CLOCK_REALTIME, &now) != 0)
            failed++;
    }
    /* The ends of all of them wait in the identity channel for the next
     * call that drains it. */
    kill(-1, SIGKILL);
    pid_t last = -1;
    if (steps_spawn(&last, "exit7", "0") != 0) return 7;
    reap("a spawn after the ends", last, 7, 0);
    for (int b = 0; b < STEPS_BRANCHES; b++) {
        int status;
        waitpid(branches[b], &status, 0);
    }
    pause_ms(300);
    failed += failures;
    printf("posix-procs: steps %s\n", failed ? "failed" : "done");
    return failed;
}

/* The layer's memory map (5d, T1): the regions it keeps handles of, three
 * words each (address, pages, access: 1 R, 3 RW, 5 RX). */
#define MAP_MAX 64
#define PAGE 4096ull
static unsigned long long regions[3 * MAP_MAX];

static size_t map_read(void) {
    size_t n = stafeto_probe_memory_map(regions, MAP_MAX);
    return n > MAP_MAX ? MAP_MAX : n;
}

static unsigned long long map_pages(size_t n) {
    unsigned long long pages = 0;
    for (size_t i = 0; i < n; i++) pages += regions[3 * i + 1];
    return pages;
}

/* Three growths of the heap add three regions, each of the pages the
 * layer took, RW, one after the other in the heap's range, and the bytes
 * charged to the process grow by at least those pages. */
static int map_growth(const char *who) {
    size_t before = map_read();
    unsigned long long pages = map_pages(before), used = stafeto_probe_memory_used();
    unsigned long long last_end = 0;
    if (before > 0 && regions[3 * (before - 1)] >= 0x10000000ull)
        last_end = regions[3 * (before - 1)] + regions[3 * (before - 1) + 1] * PAGE;
    void *held[3];
    for (int i = 0; i < 3; i++) {
        held[i] = mmap(NULL, 192 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (held[i] == MAP_FAILED) {
            printf("posix-procs: %s: mmap of 192 KiB gave %d\n", who, errno);
            return 1;
        }
    }
    size_t after = map_read();
    unsigned long long grown = map_pages(after) - pages, charged = stafeto_probe_memory_used() - used;
    if (after != before + 3) {
        printf("posix-procs: %s: %d regions before, %d after three growths\n", who, (int)before,
               (int)after);
        return 2;
    }
    for (size_t i = before; i < after; i++) {
        unsigned long long at = regions[3 * i];
        if (regions[3 * i + 2] != 3 || at % PAGE != 0 || at < 0x10000000ull || at >= 0x20000000ull ||
            (last_end != 0 && at != last_end) || regions[3 * i + 1] < 48) {
            printf("posix-procs: %s: region %d at %llx of %llu pages access %llu\n", who, (int)i, at,
                   regions[3 * i + 1], regions[3 * i + 2]);
            return 3;
        }
        last_end = at + regions[3 * i + 1] * PAGE;
    }
    if (charged < grown * PAGE || charged > (grown + 16) * PAGE) {
        printf("posix-procs: %s: the map grew %llu pages, the process is charged %llu bytes\n", who,
               grown, charged);
        return 4;
    }
    for (int i = 0; i < 3; i++) munmap(held[i], 192 * 1024);
    return 0;
}

/* What a program from a file starts with: its segments (code RX and data
 * RW below the layer's addresses), its stack and its start area, all of
 * them in the map, none past the loader's region or with no pages, and
 * no more pages than the process is charged for. */
static int map_start(void) {
    size_t n = map_read();
    int code = 0, data = 0, stack = 0, area = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned long long at = regions[3 * i], pages = regions[3 * i + 1], access = regions[3 * i + 2];
        if (pages == 0 || at % PAGE != 0 || (access != 1 && access != 3 && access != 5)) return 1;
        if (at + pages * PAGE > 0x0001000000000000ull - 0x1000000ull) return 2;
        if (at < 0x2000000ull && access == 5) code++;
        if (at < 0x2000000ull && access == 3) data++;
        if (at == 0x100000000ull - 64 * 1024 && pages == 16 && access == 3) stack++;
        if (at == 0xF0000000ull && access == 3) area++;
    }
    if (code != 1 || data != 1 || stack != 1 || area != 1) {
        printf("posix-procs: the start map has %d code, %d data, %d stack, %d area of %d\n", code,
               data, stack, area, (int)n);
        return 3;
    }
    if (map_pages(n) * PAGE > stafeto_probe_memory_used()) return 4;
    printf("posix-procs: memory map %d regions %llu pages\n", (int)n, map_pages(n));
    return 0;
}


/* Stage forks (5d): a bare child of fork's copy runs on the copy with
 * nothing of the layer bound, and says what it saw by its exit status. */
static volatile int bare_data = 1234;
static volatile int bare_later;
static volatile int *bare_heap;
/* 512 KiB, past the 64 KiB pieces of the probes' loader: its copy maps the
 * parent's object at offsets into it. */
#define BARE_BIG (512 * 1024 / sizeof(unsigned))
static volatile unsigned *bare_big;

/* The child of `fork_bare`: the parent's .data, heap and stack as they
 * were at the fork, its own copies of them, a page that ignores what the
 * parent ignores from its start (the group's SIGUSR2 of the window never
 * waited there), and none of the parent's writes after the fork. */
static int bare_child(void *arg) {
    volatile int *stack = arg;
    int bad = 0;
    if (bare_data != 5678) bad |= 1;
    if (bare_heap[0] != 0x5a5a || bare_heap[1023] != 0x6b6b) bad |= 2;
    if (*stack != 77) bad |= 4;
    for (unsigned i = 0; i < BARE_BIG; i++)
        if (bare_big[i] != i * 2654435761u) {
            bad |= 128;
            break;
        }
    bare_data = 1;
    bare_heap[0] = 2;
    *stack = 3;
    if (bare_data != 1 || bare_heap[0] != 2 || *stack != 3) bad |= 8;
    unsigned long long usr2 = 1ull << (SIGUSR2 - 1);
    if (!(stafeto_probe_page(1) & usr2)) bad |= 16;
    if (stafeto_probe_page(0) & usr2) bad |= 32;
    for (int i = 0; i < 100; i++) {
        if (bare_later != 0) bad |= 64;
        stafeto_probe_yield();
    }
    return bad;
}

/* The window of `fork_bare`: SIGUSR2 to the group, the child's record
 * among it while it loads. */
static void bare_window(void) { kill(0, SIGUSR2); }

static int bare_park(void *arg) {
    (void)arg;
    stafeto_probe_park();
    return 1;
}

/* Role forkbare: a bare fork in a group of its own, which ignores
 * SIGUSR2. */
static int fork_bare(void) {
    expect("setpgid of forkbare", setpgid(0, 0), 0);
    signal(SIGUSR2, SIG_IGN);
    bare_heap = malloc(4096 * sizeof(int));
    bare_big = malloc(BARE_BIG * sizeof(unsigned));
    for (unsigned i = 0; i < BARE_BIG; i++) bare_big[i] = i * 2654435761u;
    volatile int stack = 77;
    bare_data = 5678;
    bare_heap[0] = 0x5a5a;
    bare_heap[1023] = 0x6b6b;
    int pid = stafeto_probe_fork_bare(bare_child, (void *)&stack, bare_window);
    if (pid <= 0) {
        printf("posix-procs: a bare fork gave %d\n", pid);
        return 1;
    }
    bare_later = 1;
    /* The loader unmapped every piece of the parent's objects. */
    expect("the mappings of the parent's objects", (int)stafeto_probe_map_mappings(), 1);
    int status = -1;
    expect("waitpid of the bare child", waitpid(pid, &status, 0), pid);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        printf("posix-procs: the bare child ended with status %#x\n", status);
        failures++;
    }
    expect("the parent's .data", bare_data, 5678);
    expect("the parent's heap", bare_heap[0], 0x5a5a);
    expect("the parent's stack", stack, 77);
    /* 32 children of the record at once; the 33rd is EAGAIN. */
    int pids[32], live = 0;
    for (; live < 32; live++) {
        pids[live] = stafeto_probe_fork_bare(bare_park, NULL, NULL);
        if (pids[live] <= 0) {
            printf("posix-procs: bare child %d of 32 gave %d\n", live + 1, pids[live]);
            failures++;
            break;
        }
    }
    if (live == 32) expect("a 33rd bare child", stafeto_probe_fork_bare(bare_park, NULL, NULL), -EAGAIN);
    for (int i = 0; i < live; i++) kill(pids[i], SIGKILL);
    for (int i = 0; i < live; i++) reap("one of 32 bare children", pids[i], 0, SIGKILL);
    /* A load of ForkStart that never got its copy: SpawnCommit takes no
     * child of ForkStart, ForkCommit no child whose copy is not ready,
     * and ForkAbort leaves no zombie. */
    int aborted = -1;
    expect("ForkCommit before the copy", stafeto_probe_fork_abort(&aborted), 0);
    expect("a wait for the aborted fork", waitpid(aborted, NULL, WNOHANG), -1);
    expect("its errno", errno, ECHILD);
    if (failures == 0) printf("posix-procs: a bare fork copied the parent\n");
    return failures;
}

/* Role forkpool, while a sleeper of its parent's lives: 31 bare children
 * take the rest of the process service's pool (33 quotas of the probe's,
 * tests/init's table), and the 32nd fork, which the service's limit of
 * children would take, is ENOMEM. */
static int fork_pool(void) {
    int pids[31], live = 0;
    for (; live < 31; live++) {
        pids[live] = stafeto_probe_fork_bare(bare_park, NULL, NULL);
        if (pids[live] <= 0) {
            printf("posix-procs: bare child %d of 31 gave %d\n", live + 1, pids[live]);
            failures++;
            break;
        }
    }
    if (live == 31) expect("a fork past the pool", stafeto_probe_fork_bare(bare_park, NULL, NULL), -ENOMEM);
    for (int i = 0; i < live; i++) kill(pids[i], SIGKILL);
    for (int i = 0; i < live; i++) reap("one of 31 bare children", pids[i], 0, SIGKILL);
    return failures;
}


/* Role forkfull: fork with the layer bound in the child (5d, T3). */
static volatile int full_data = 1234;
static volatile int ints, usr1s, alrms;
static void count_int(int signal) { (void)signal; ints++; }
static void count_usr1(int signal) { (void)signal; usr1s++; }
static void count_alrm(int signal) { (void)signal; alrms++; }
static void full_window(void) { kill(0, SIGINT); }
static void *full_thread(void *arg) { return (char *)arg + 1; }

/* The order of pthread_atfork's handlers: prepare in the opposite order of
 * their establishment, parent and child in it. */
static char order[16];
static int order_len;
static void note(char c) {
    if (order_len < (int)sizeof order - 1) order[order_len++] = c;
}
static void prepare_a(void) { note('A'); }
static void prepare_b(void) { note('B'); }
static void parent_a(void) { note('a'); }
static void parent_b(void) { note('b'); }
static void child_a(void) { note('1'); }
static void child_b(void) { note('2'); }

/* What the child checks before it execs /bin/ls; the count of failures. */
static int full_child(pid_t parent, int fd, int cloexec, int clofork, volatile int *stack) {
    expect("getppid in the child", getppid(), parent);
    expect("the child's own PID", getpid() != parent, 1);
    expect("the handlers' order in the child", strcmp(order, "BA12"), 0);
    expect("the parent's .data", full_data, 5678);
    expect("the parent's stack", *stack, 77);
    full_data = 1;
    *stack = 3;
    sigset_t mask, pending;
    sigprocmask(SIG_BLOCK, NULL, &mask);
    expect("the mask holds SIGUSR1", sigismember(&mask, SIGUSR1), 1);
    expect("the mask holds SIGHUP", sigismember(&mask, SIGHUP), 1);
    sigpending(&pending);
    expect("no pending SIGUSR1 in the child", sigismember(&pending, SIGUSR1), 0);
    struct sigaction action;
    sigaction(SIGUSR1, NULL, &action);
    expect("a caught SIGUSR1 stays caught", action.sa_handler == count_usr1, 1);
    sigaction(SIGUSR2, NULL, &action);
    expect("an ignored SIGUSR2 stays ignored", action.sa_handler == SIG_IGN, 1);
    expect("the group's SIGINT of the window in the child", ints, 1);
    char bytes[16];
    expect("a read of the shared description", (int)read(fd, bytes, 10), 10);
    struct stat st;
    expect("FD_CLOEXEC stays open", fstat(cloexec, &st), 0);
    expect("FD_CLOFORK is closed", fstat(clofork, &st) == -1 ? errno : 0, EBADF);
    /* The child's table has the number of FD_CLOFORK free: the lowest. */
    int motd = open("/etc/motd", O_RDONLY);
    expect("an open in the child takes FD_CLOFORK's number", motd, clofork);
    expect("an open in the child", motd >= 0 && read(motd, bytes, 7) == 7 &&
                                         memcmp(bytes, "stafeto", 7) == 0, 1);
    close(motd);
    struct timespec now;
    expect("CLOCK_REALTIME in the child", clock_gettime(CLOCK_REALTIME, &now), 0);
    expect("CLOCK_MONOTONIC in the child", clock_gettime(CLOCK_MONOTONIC, &now), 0);
    pause_ms(5);
    pthread_t thread;
    void *back = NULL;
    expect("pthread_create in the child", pthread_create(&thread, NULL, full_thread, (void *)41), 0);
    expect("pthread_join in the child", pthread_join(thread, &back), 0);
    expect("the thread's value", back == (void *)42, 1);
    size_t grow = 1024 * 1024;
    char *more = malloc(grow);
    expect("1 MiB more heap in the child", more != NULL, 1);
    if (more) {
        memset(more, 0x5a, grow);
        free(more);
    }
    expect("kill of the parent", kill(parent, SIGALRM), 0);
    /* A grandchild. */
    fflush(stdout);
    pid_t grandchild = fork();
    if (grandchild == 0) _exit(getppid() == getpid() ? 1 : 7);
    int status = -1;
    expect("waitpid of the grandchild", waitpid(grandchild, &status, 0), grandchild);
    expect("the grandchild's status", WIFEXITED(status) ? WEXITSTATUS(status) : -1, 7);
    return failures;
}

static int fork_full(void) {
    expect("setpgid of forkfull", setpgid(0, 0), 0);
    pid_t me = getpid();
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = count_int;
    sigaction(SIGINT, &action, NULL);
    action.sa_handler = count_usr1;
    sigaction(SIGUSR1, &action, NULL);
    /* The child's SIGALRM comes while the parent waits for it. */
    action.sa_handler = count_alrm;
    action.sa_flags = SA_RESTART;
    sigaction(SIGALRM, &action, NULL);
    signal(SIGUSR2, SIG_IGN);
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGUSR1);
    sigaddset(&block, SIGHUP);
    sigprocmask(SIG_BLOCK, &block, NULL);
    raise(SIGUSR1);
    pthread_atfork(prepare_a, parent_a, child_a);
    pthread_atfork(prepare_b, parent_b, child_b);
    int fd = open("/etc/motd", O_RDONLY);
    char bytes[4];
    expect("a read before the fork", (int)read(fd, bytes, 3), 3);
    int cloexec = open("/etc/motd", O_RDONLY | O_CLOEXEC);
    int clofork = open("/etc/motd", O_RDONLY | O_CLOFORK);
    int dupfork = fcntl(fd, F_DUPFD_CLOFORK, 0);
    expect("F_GETFD of O_CLOFORK", fcntl(clofork, F_GETFD), FD_CLOFORK);
    expect("F_SETFD of FD_CLOFORK", fcntl(dupfork, F_SETFD, FD_CLOFORK | FD_CLOEXEC), 0);
    expect("F_GETFD of F_SETFD", fcntl(dupfork, F_GETFD), FD_CLOFORK | FD_CLOEXEC);
    volatile int stack = 77;
    full_data = 5678;
    stafeto_probe_fork_window(full_window);
    fflush(stdout);
    pid_t pid = fork();
    stafeto_probe_fork_window(NULL);
    if (pid == 0) {
        if (full_child(me, fd, cloexec, clofork, &stack) != 0) _exit(1);
        printf("posix-procs: a forked child execs ls\n");
        fflush(stdout);
        char *ls[] = {"ls", "/etc", NULL};
        char *env[] = {"PATH=/bin", NULL};
        execve("/bin/ls", ls, env);
        _exit(100 + errno);
    }
    if (pid < 0) {
        printf("posix-procs: fork gave %d (%s)\n", errno, strerror(errno));
        return 1;
    }
    expect("the handlers' order in the parent", strcmp(order, "BAab"), 0);
    expect("the group's SIGINT of the window in the parent", ints, 1);
    int status = -1;
    expect("waitpid of the forked child", waitpid(pid, &status, 0), pid);
    expect("the forked child's ls", WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
    expect("the shared offset", (int)lseek(fd, 0, SEEK_CUR), 13);
    expect("the child's SIGALRM", alrms, 1);
    expect("the parent's .data after the child", full_data, 5678);
    expect("the parent's stack after the child", stack, 77);
    sigset_t pending;
    sigpending(&pending);
    expect("the parent's pending SIGUSR1", sigismember(&pending, SIGUSR1), 1);
    /* vfork is fork. */
    fflush(stdout);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    pid_t v = vfork();
#pragma clang diagnostic pop
    if (v == 0) _exit(5);
    expect("waitpid of a vfork child", waitpid(v, &status, 0), v);
    expect("the vfork child's status", WIFEXITED(status) ? WEXITSTATUS(status) : -1, 5);
    if (failures == 0) printf("posix-procs: fork with the layer bound\n");
    return failures;
}


/* Role forkthreads: fork from a parent with six more threads, at its
 * level under FIFO, so each yields after a turn, which mallocs with no
 * lock of its own, execs a file that is no program, and
 * churn the heap under a mutex, open and close files, make and join
 * threads, and hold the layer's locks of the heap, the files and a bucket
 * of the table of waits in turn. Each fork stops them all: in its window
 * (between Go and ForkCommit) none of them moves `ticks`. The child has
 * one thread, mallocs, opens a file and takes the mutex, whose
 * pthread_atfork handlers make it the forking thread's. */
static volatile int churn_stop;
static unsigned long ticks;
static pthread_mutex_t churn_mutex = PTHREAD_MUTEX_INITIALIZER;
static int moved_in_window;
static void tick(void) { __atomic_fetch_add(&ticks, 1, __ATOMIC_SEQ_CST); }
static void lock_churn(void) { pthread_mutex_lock(&churn_mutex); }
static void unlock_churn(void) { pthread_mutex_unlock(&churn_mutex); }

static void *churn_heap(void *arg) {
    (void)arg;
    for (unsigned n = 0; !churn_stop; n++) {
        pthread_mutex_lock(&churn_mutex);
        char *p = malloc(64 + n % 8192);
        if (p) memset(p, 1, 64);
        free(p);
        pthread_mutex_unlock(&churn_mutex);
        tick();
        sched_yield();
    }
    return NULL;
}

/* malloc and free with no lock of the probe's: relibc's allocator's own
 * lock is the forking thread's through its handlers. */
static void *churn_malloc(void *arg) {
    (void)arg;
    for (unsigned n = 0; !churn_stop; n++) {
        free(malloc(16 + n % 300000));
        if (n % 64 == 0) {
            tick();
            sched_yield();
        }
    }
    return NULL;
}

static void *churn_files(void *arg) {
    (void)arg;
    while (!churn_stop) {
        int fd = open("/etc/motd", O_RDONLY);
        char b[4];
        if (fd >= 0) {
            read(fd, b, sizeof b);
            close(fd);
        }
        tick();
        sched_yield();
    }
    return NULL;
}

/* exec of a file that is no program: each stops the process, fails and
 * resumes it, between the stops of the forks. */
static void *churn_exec(void *arg) {
    (void)arg;
    char *argv[] = {"data", NULL};
    char *env[] = {NULL};
    while (!churn_stop) {
        execve("/bin/data", argv, env);
        tick();
        sched_yield();
    }
    return NULL;
}

static void *short_thread(void *arg) {
    tick();
    return arg;
}

static void *churn_threads(void *arg) {
    (void)arg;
    while (!churn_stop) {
        pthread_t t;
        if (pthread_create(&t, NULL, short_thread, NULL) == 0) pthread_join(t, NULL);
        tick();
        sched_yield();
    }
    return NULL;
}

static void *hold_locks(void *arg) {
    (void)arg;
    for (int which = 0; !churn_stop; which = (which + 1) % 3) {
        stafeto_probe_hold(which, 2000);
        tick();
        pause_ms(1);
    }
    return NULL;
}

static void threads_window(void) {
    unsigned long before = __atomic_load_n(&ticks, __ATOMIC_SEQ_CST);
    pause_ms(3);
    if (__atomic_load_n(&ticks, __ATOMIC_SEQ_CST) != before) moved_in_window++;
}

static int threads_child(const char *kept) {
    int bad = 0;
    if (stafeto_probe_threads() != 1) bad |= 1;
    char *p = malloc(256 * 1024);
    if (!p) bad |= 2;
    else {
        memset(p, 7, 256 * 1024);
        free(p);
    }
    int fd = open("/etc/motd", O_RDONLY);
    char b[7];
    if (fd < 0 || read(fd, b, 7) != 7 || memcmp(b, "stafeto", 7) != 0) bad |= 4;
    close(fd);
    if (pthread_mutex_lock(&churn_mutex) != 0 || pthread_mutex_unlock(&churn_mutex) != 0) bad |= 8;
    if (strcmp(kept, "kept") != 0) bad |= 16;
    /* relibc's table of threads holds the child's one: a thread comes
     * and goes. */
    pthread_t t;
    void *back = NULL;
    if (pthread_create(&t, NULL, full_thread, (void *)41) != 0 || pthread_join(t, &back) != 0 ||
        back != (void *)42)
        bad |= 32;
    return bad;
}

static int fork_threads(void) {
    pthread_atfork(lock_churn, unlock_churn, unlock_churn);
    char *kept = strdup("kept");
    pthread_t t[6];
    void *(*bodies[6])(void *) = {churn_heap,    churn_malloc, churn_files,
                                  churn_threads, hold_locks,   churn_exec};
    for (int i = 0; i < 6; i++) {
        expect("a churning thread", pthread_create(&t[i], NULL, bodies[i], NULL), 0);
    }
    pause_ms(20);
    stafeto_probe_fork_window(threads_window);
    int forks = 0;
    for (; forks < 40; forks++) {
        fflush(stdout);
        pid_t pid = fork();
        if (pid == 0) _exit(threads_child(kept));
        if (pid < 0) {
            printf("posix-procs: fork %d of a multithreaded parent gave %d\n", forks, errno);
            failures++;
            break;
        }
        int status = -1;
        if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            printf("posix-procs: the child of fork %d ended with status %#x\n", forks, status);
            failures++;
            break;
        }
    }
    stafeto_probe_fork_window(NULL);
    /* Two forks one after the other with no wait between: a thread the
     * first stop parked parks again for the second. */
    for (int i = 0; i < 20 && failures == 0; i++) {
        fflush(stdout);
        pid_t a = fork();
        if (a == 0) _exit(0);
        pid_t b = fork();
        if (b == 0) _exit(0);
        reap("the first of a pair of forks", a, 0, 0);
        reap("the second of a pair of forks", b, 0, 0);
    }
    churn_stop = 1;
    for (int i = 0; i < 6; i++) pthread_join(t[i], NULL);
    expect("threads that moved in a fork's window", moved_in_window, 0);
    if (failures == 0) printf("posix-procs: %d forks of a parent with six threads\n", forks);
    return failures;
}

/* Role execmaking: an exec while another thread makes threads, which
 * start in the window of the exec and park there. */
static int exec_making(void) {
    pthread_t t;
    expect("the maker", pthread_create(&t, NULL, churn_threads, NULL), 0);
    pause_ms(10);
    char *next[] = {"procs-child", "exit7", NULL};
    char *env[] = {NULL};
    execve("/bin/procs-child", next, env);
    return 100 + errno;
}


/* Role forkthread: a fork from a thread other than the main one. The
 * child keeps the caller's place and number, has that one thread, opens
 * a file and forks a grandchild of its own. */
static void *fork_from_thread(void *arg) {
    (void)arg;
    pid_t parent = getpid();
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        int bad = 0;
        if (stafeto_probe_threads() != 1 || getppid() != parent) bad |= 1;
        int fd = open("/etc/motd", O_RDONLY);
        char b[7];
        if (fd < 0 || read(fd, b, 7) != 7) bad |= 2;
        pid_t grandchild = fork();
        if (grandchild == 0) _exit(9);
        int status = -1;
        if (waitpid(grandchild, &status, 0) != grandchild || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 9)
            bad |= 4;
        _exit(bad ? bad : 9);
    }
    int status = -1;
    if (pid < 0 || waitpid(pid, &status, 0) != pid) return (void *)1;
    return (void *)(long)(WIFEXITED(status) ? WEXITSTATUS(status) : 100);
}

static int fork_thread(void) {
    pthread_t t;
    void *got = NULL;
    expect("the forking thread", pthread_create(&t, NULL, fork_from_thread, NULL), 0);
    pthread_join(t, &got);
    expect("the status of the child of a second thread", (int)(long)got, 9);
    return failures;
}

/* Role forkmany: 20 bare children killed give the service's pool back. */
static int fork_many(void) {
    unsigned long long before = stafeto_probe_pool();
    int pids[20], live = 0;
    for (; live < 20; live++) {
        pids[live] = stafeto_probe_fork_bare(bare_park, NULL, NULL);
        if (pids[live] <= 0) break;
    }
    expect("20 bare children", live, 20);
    for (int i = 0; i < live; i++) kill(pids[i], SIGKILL);
    for (int i = 0; i < live; i++) reap("one of 20 bare children", pids[i], 0, SIGKILL);
    expect("the pool after 20 children of fork", stafeto_probe_pool() == before, 1);
    return failures;
}

/* Roles forkdie and forkdieearly: the parent ends by its own SIGKILL in
 * the window of a fork, after Go or after the first Regions; its parent
 * sees the pool come back whole. */
static void die_now(void) { kill(getpid(), SIGKILL); }

static int fork_die(int early) {
    char *big = malloc(600 * 1024);
    if (big) memset(big, 3, 600 * 1024);
    if (early)
        stafeto_probe_fork_early(die_now);
    else
        stafeto_probe_fork_window(die_now);
    fork();
    return 1;
}


/* Role forkwaits: the waits of other threads go on across a fork. A
 * thread in nanosleep of 300 ms gets 0, one in sigsuspend returns only
 * after its handler ran, one in waitpid of a child that naps gets that
 * child's status, and the forked child has no child of its own. */
static volatile int suspend_handled;
static void on_suspend_usr1(int signal) {
    (void)signal;
    suspend_handled++;
}
static void *sleep_300(void *arg) {
    (void)arg;
    struct timespec t = {0, 300 * 1000000L};
    return (void *)(long)nanosleep(&t, NULL);
}
static void *suspend_usr1(void *arg) {
    (void)arg;
    sigset_t none;
    sigemptyset(&none);
    sigsuspend(&none);
    return (void *)(long)suspend_handled;
}
static void *wait_nap(void *arg) {
    pid_t nap = (pid_t)(long)arg;
    int status = -1;
    pid_t got = waitpid(nap, &status, 0);
    return (void *)(long)(got == nap && WIFEXITED(status) ? WEXITSTATUS(status) : -1);
}

static int fork_waits(void) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = on_suspend_usr1;
    sigaction(SIGUSR1, &action, NULL);
    sigset_t usr1;
    sigemptyset(&usr1);
    sigaddset(&usr1, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &usr1, NULL);
    pid_t nap = start("nap");
    pthread_t sleeper, suspender, waiter;
    pthread_create(&sleeper, NULL, sleep_300, NULL);
    pthread_create(&suspender, NULL, suspend_usr1, NULL);
    pthread_create(&waiter, NULL, wait_nap, (void *)(long)nap);
    pause_ms(20);
    for (int i = 0; i < 5; i++) {
        fflush(stdout);
        pid_t pid = fork();
        if (pid == 0) _exit(waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD ? 0 : 1);
        reap("a fork while threads wait", pid, 0, 0);
        pause_ms(10);
    }
    void *got = NULL;
    pthread_join(sleeper, &got);
    expect("nanosleep across forks", (int)(long)got, 0);
    pthread_join(waiter, &got);
    expect("waitpid across forks", (int)(long)got, 3);
    expect("sigsuspend before its signal", suspend_handled, 0);
    pthread_kill(suspender, SIGUSR1);
    pthread_join(suspender, &got);
    expect("sigsuspend returns after its handler", (int)(long)got, 1);
    return failures;
}

/* Role forkmalloc: a thread's malloc holds relibc's allocator lock while
 * its mapping sleeps 300 ms in the layer (outside the layer's sections),
 * and the main thread forks meanwhile: fork's prepare handler waits for
 * the lock, so the malloc is over before the copy, and the child's malloc
 * finds the lock free. */
static volatile int slow_done;
static void *malloc_slowly(void *arg) {
    (void)arg;
    /* After pthread_create of the main thread is over: it mallocs too. */
    pause_ms(20);
    stafeto_probe_mmap_sleep(300000);
    char *p = malloc(1024 * 1024);
    slow_done = 1;
    if (p) memset(p, 1, 1024 * 1024);
    return p;
}

static int fork_malloc(void) {
    pthread_t slow;
    pthread_create(&slow, NULL, malloc_slowly, NULL);
    pause_ms(100);
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        char *p = malloc(64 * 1024);
        _exit(p != NULL ? 0 : 1);
    }
    /* The prepare handler waited for the allocator's lock: the slow
     * malloc was over before the copy. */
    expect("the slow malloc before the copy", slow_done, 1);
    reap("a fork while another thread's malloc waits", pid, 0, 0);
    void *got = NULL;
    pthread_join(slow, &got);
    expect("the slow malloc", got != NULL, 1);
    free(got);
    return failures;
}

/* The roles of the children. */
static int role(const char *name) {
    if (strcmp(name, "steps") == 0) return steps_run();
    if (strcmp(name, "branch") == 0) return steps_branch();
    if (strcmp(name, "armed") == 0) return steps_armed();
    if (strcmp(name, "stepfork") == 0) return steps_fork();
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
    if (strcmp(name, "args") == 0) {
        const char *x = getenv("X");
        printf("posix-procs: args %d [%s] [%s] X=%s\n", argc_seen, argv_seen[2], argv_seen[3],
               x ? x : "(none)");
        return 0;
    }
    if (strcmp(name, "mask") == 0) {
        sigset_t mask;
        sigprocmask(SIG_BLOCK, NULL, &mask);
        return sigismember(&mask, SIGHUP) && !sigismember(&mask, SIGUSR2) ? 0 : 1;
    }
    if (strcmp(name, "default") == 0) {
        struct sigaction pipe;
        sigaction(SIGPIPE, NULL, &pipe);
        return pipe.sa_handler == SIG_DFL ? 0 : 1;
    }
    if (strcmp(name, "handles") == 0) {
        unsigned long handles[2];
        stafeto_start_handles(handles);
        if (handles[0] != handles[1]) {
            printf("posix-procs: %lu handles at the start, %lu named\n", handles[0], handles[1]);
            return 1;
        }
        return 0;
    }
    if (strcmp(name, "forkbare") == 0) return fork_bare();
    if (strcmp(name, "forkpool") == 0) return fork_pool();
    if (strcmp(name, "forkfull") == 0) return fork_full();
    if (strcmp(name, "forkthreads") == 0) return fork_threads();
    if (strcmp(name, "forkthread") == 0) return fork_thread();
    if (strcmp(name, "forkwaits") == 0) return fork_waits();
    if (strcmp(name, "forkmalloc") == 0) return fork_malloc();
    if (strcmp(name, "forkmany") == 0) return fork_many();
    if (strcmp(name, "forkdie") == 0) return fork_die(0);
    if (strcmp(name, "forkdieearly") == 0) return fork_die(1);
    if (strcmp(name, "execmaking") == 0) return exec_making();
    if (strcmp(name, "memmap") == 0) {
        int bad = map_start();
        return bad != 0 ? bad : 10 * map_growth("child");
    }
    if (strcmp(name, "setid") == 0) {
        /* A set-user-ID file of root: the real IDs stay, the secure mode
         * is on, a new file takes a number above 2, and the clock service
         * sees euid 0 with no asking (the page of generations). */
        int fd = open("/etc/motd", O_RDONLY);
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        int ok = getuid() == 65534 && geteuid() == 0 && getauxval(23) == 1 && fd > 2 &&
                 clock_settime(CLOCK_REALTIME, &now) == 0;
        printf("posix-procs: setid uid %d euid %d secure %lu fd %d\n", (int)getuid(),
               (int)geteuid(), getauxval(23), fd);
        return ok ? 0 : 1;
    }
    if (strcmp(name, "nobody") == 0) {
        int ok = getuid() == 65534 && geteuid() == 65534 && getauxval(23) == 0;
        printf("posix-procs: nobody uid %d euid %d\n", (int)getuid(), (int)geteuid());
        return ok ? 0 : 1;
    }
    if (strcmp(name, "fds") == 0) {
        struct stat st;
        if (fstat(3, &st) == 0 || errno != EBADF) return 1;
        if (fstat(4, &st) != 0 || fstat(5, &st) != 0) return 2;
        return 0;
    }
    if (strcmp(name, "read10") == 0) {
        char bytes[10];
        return read(atoi(argv_seen[2]), bytes, sizeof bytes) == 10 ? 0 : 1;
    }
    if (strcmp(name, "opened") == 0) {
        /* fd 7 opened by the action reads the motd; fd 6 was closed. */
        char bytes[7];
        struct stat st;
        if (fstat(6, &st) == 0) return 1;
        if (read(7, bytes, sizeof bytes) != 7 || memcmp(bytes, "stafeto", 7) != 0) return 2;
        return 0;
    }
    if (strcmp(name, "cwd") == 0) {
        char cwd[64];
        if (!getcwd(cwd, sizeof cwd)) return 1;
        printf("posix-procs: the child's directory is %s\n", cwd);
        return strcmp(cwd, "/bin") == 0 ? 0 : 2;
    }
    if (strcmp(name, "execls") == 0) {
        char *ls[] = {"ls", "/etc", NULL};
        char *env[] = {"PATH=/bin", NULL};
        execve("/bin/ls", ls, env);
        return 100 + errno;
    }
    if (strcmp(name, "execself") == 0) return exec_self();
    if (strcmp(name, "after") == 0) return after_exec();
    if (strcmp(name, "execfail") == 0) return exec_fail();
    if (strcmp(name, "execto") == 0) {
        /* exec of the program argv_seen[2] in role argv_seen[3]. */
        char *next[] = {"procs-child", argv_seen[3], NULL};
        char *env[] = {NULL};
        execve(argv_seen[2], next, env);
        return 100 + errno;
    }
    if (strcmp(name, "execjunk") == 0) {
        char *next[] = {"procs-child", "nobody", NULL};
        char *env[] = {NULL};
        if (execve("/bin/setid-junk", next, env) != -1 || errno != ENOEXEC) return 1;
        execve("/bin/procs-child", next, env);
        return 100 + errno;
    }
    if (strcmp(name, "ghostexec") == 0) {
        char *next[] = {"procs-child", "ghost", NULL};
        stafeto_probe_exec_then_exit("/bin/procs-child", next, 7);
        return 1;
    }
    if (strcmp(name, "last") == 0) {
        printf("posix-procs: the last image ran\n");
        return 42;
    }
    if (strcmp(name, "ghostkill") == 0) {
        char *next[] = {"procs-child", "ghost", NULL};
        stafeto_probe_exec_then_exit("/bin/procs-child", next, 137);
        return 1;
    }
    if (strcmp(name, "execoutlive") == 0) {
        /* The old image of an exec of a set-user-ID file of root that
         * outlives its ExecCommit asks the clock to be set (it is killed
         * first); the new image runs the role setid. */
        char *next[] = {"procs-child", "setid", NULL};
        /* The clock service keeps this image's identity for the session,
         * which moves to the new image: it takes the new one's. */
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        if (clock_settime(CLOCK_REALTIME, &now) == 0 || errno != EPERM) return 99;
        stafeto_probe_exec_outlive("/bin/procs-setid", next);
        return 100 + errno;
    }
    if (strcmp(name, "execbusy") == 0) return exec_busy();
    if (strcmp(name, "execspawn") == 0) return exec_spawning();
    if (strcmp(name, "drain") == 0) {
        /* No load of the old image holds a place of the record. */
        int loads = stafeto_probe_loads();
        if (loads != 2) {
            printf("posix-procs: the record took %d loads after its exec\n", loads);
            return 2;
        }
        while (waitpid(-1, NULL, 0) > 0) {
        }
        return errno == ECHILD ? 7 : 1;
    }
    if (strcmp(name, "reapkill") == 0) {
        pid_t pid = atoi(argv_seen[2]);
        int status = -1;
        if (kill(pid, SIGKILL) != 0) return 1;
        if (waitpid(pid, &status, 0) != pid) return 2;
        return WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL ? 7 : 3;
    }
    if (strcmp(name, "ghost") == 0) {
        printf("posix-procs: the image of a dead exec ran\n");
        return 9;
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
        pid_t orphan = start("orphan");
        return orphan > 0 ? 0 : 1;
    }
    if (strcmp(name, "block") == 0) {
        /* It spins at the probe's level, which runs FIFO: each turn yields
         * to the probe, as the processor goes to the first thread ready. */
        sigset_t all;
        sigfillset(&all);
        sigprocmask(SIG_BLOCK, &all, NULL);
        for (;;) sched_yield();
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
    pid_t again = start("child");
    reap("procs-child spawned again", again, 0, 0);

    pid_t nap = start("nap");
    int status = -1;
    expect("WNOHANG before the end", (int)waitpid(nap, &status, WNOHANG), 0);
    reap("procs-nap", nap, 3, 0);
    interrupted_wait(1);
    interrupted_wait(0);

    reap("procs-exit7", start("exit7"), 7, 0);
    reap("procs-segv", start("segv"), 0, SIGSEGV);

    pid_t seven = start("exit7");
    siginfo_t info;
    memset(&info, 0, sizeof info);
    expect("waitid WNOWAIT", waitid(P_PID, (id_t)seven, &info, WEXITED | WNOWAIT), 0);
    expect("waitid's si_pid", info.si_pid, (int)seven);
    expect("waitid's si_code", info.si_code, CLD_EXITED);
    expect("waitid's si_status", info.si_status, 7);
    reap("procs-exit7 after WNOWAIT", seven, 7, 0);
    expect("waitpid of a child taken", (int)waitpid(seven, &status, 0) == -1 && errno == ECHILD, 1);

    reap("procs-middle", start("middle"), 0, 0);
    expect("waitpid of PID 1", (int)waitpid(1, &status, 0) == -1 && errno == ECHILD, 1);
    expect("waitpid of its own PID", (int)waitpid(getpid(), &status, WNOHANG) == -1 && errno == ECHILD, 1);
    expect("waitpid(-1, WNOHANG) with the sleeper alive", (int)waitpid(-1, &status, WNOHANG), 0);
}

/* Stage 6: more children than the service has places for sessions, one
 * after the other (1100; the identity sessions of the ended stay in the
 * service until it receives their ends: its 1024 places fill without it). */
static void churn(void) {
    for (int i = 0; i < 1100; i++) {
        pid_t pid = start("exit7");
        if (pid < 0) {
            printf("posix-procs: the %dth child did not start\n", i);
            return;
        }
        reap("a child of the churn", pid, 7, 0);
        if (failures) return;
    }
}

/* posix_spawn of the file `path` with `argv` and `envp`: the error, the
 * PID in *pid. */
static int spawn_file(pid_t *pid, const char *path, char *const argv[], char *const envp[],
                      const posix_spawnattr_t *attr) {
    return posix_spawn(pid, path, NULL, attr, argv, envp);
}

/* Spawns the file `path` in role `name` and checks it exits with 0. */
static void run_role(const char *path, const char *name, const posix_spawnattr_t *attr) {
    char *argv[] = {"procs-child", (char *)name, NULL};
    char *envp[] = {NULL};
    pid_t pid = -1;
    int e = spawn_file(&pid, path, argv, envp, attr);
    if (e != 0) {
        printf("posix-procs: spawn of %s for %s gave %d (%s)\n", path, name, e, strerror(e));
        failures++;
        return;
    }
    reap(name, pid, 0, 0);
}

/* A spawn that fails with `want`, and leaves no PID. */
static void refused(const char *what, const char *path, char *const argv[], int want) {
    char *envp[] = {NULL};
    pid_t pid = -7;
    expect(what, spawn_file(&pid, path, argv, envp, NULL), want);
    expect(what, pid, -7);
}

/* 32 children from files live at once; the 33rd is EAGAIN. */
static void thirty_two(void) {
    char *argv[] = {"procs-child", "sleep", NULL};
    char *envp[] = {NULL};
    pid_t pids[32];
    int live = 0;
    for (; live < 32; live++) {
        int e = posix_spawn(&pids[live], "/bin/procs-child", NULL, NULL, argv, envp);
        if (e != 0) {
            printf("posix-procs: child %d of 32 gave %d (%s)\n", live + 1, e, strerror(e));
            failures++;
            break;
        }
    }
    pid_t none = -7;
    if (live == 32) {
        expect("a 33rd child", posix_spawn(&none, "/bin/procs-child", NULL, NULL, argv, envp), EAGAIN);
        printf("posix-procs: 32 children live\n");
    }
    for (int i = 0; i < live; i++) kill(pids[i], SIGKILL);
    for (int i = 0; i < live; i++) reap("one of 32 children", pids[i], 0, SIGKILL);
}

/* Stage 7, as root. */
static void files(void) {
    /* An open action makes its descriptor in the parent with FD_CLOEXEC, so
     * that another thread's spawn or exec does not inherit it meanwhile. */
    expect("the parent's descriptor of addopen has FD_CLOEXEC",
           stafeto_probe_addopen_cloexec("/etc/motd"), 1);
    thirty_two();
    /* The first goal of 5c: ls of /etc from a file, waited for. */
    char *ls[] = {"ls", "/etc", NULL};
    char *path_env[] = {"PATH=/bin", NULL};
    pid_t pid = -1;
    expect("spawn of /bin/ls", spawn_file(&pid, "/bin/ls", ls, path_env, NULL), 0);
    int status = -1;
    expect("waitpid of ls", (int)waitpid(pid, &status, 0), (int)pid);
    expect("ls exited 0", WIFEXITED(status) && WEXITSTATUS(status) == 0, 1);
    printf("posix-procs: ls of /etc ended with %#x\n", status);

    char *args[] = {"procs-child", "args", "one two", "three", NULL};
    char *x[] = {"X=1", NULL};
    pid = -1;
    expect("spawn with argv and envp", spawn_file(&pid, "/bin/procs-child", args, x, NULL), 0);
    reap("a child with argv and envp", pid, 0, 0);

    char *child[] = {"procs-child", "child", NULL};
    refused("spawn of /bin/none", "/bin/none", child, ENOENT);
    refused("spawn of a file without execute", "/bin/data", child, EACCES);
    refused("spawn of a file that is no program", "/bin/script", child, ENOEXEC);
    refused("spawn of a program past the quota", "/bin/procs-big", child, ENOMEM);
    refused("spawn of a directory", "/bin", child, EACCES);
    static char big[65 * 1024];
    memset(big, 'a', sizeof big - 1);
    char *huge[] = {"procs-child", big, NULL};
    refused("spawn with 65 KiB of arguments", "/bin/procs-child", huge, E2BIG);

    /* The child's mask is that of the attribute, the caller's aside. */
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    sigset_t mask, own;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR2);
    pthread_sigmask(SIG_BLOCK, &mask, &own);
    sigemptyset(&mask);
    sigaddset(&mask, SIGHUP);
    posix_spawnattr_setsigmask(&attr, &mask);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK);
    run_role("/bin/procs-child", "mask", &attr);
    pthread_sigmask(SIG_SETMASK, &own, NULL);
    signal(SIGPIPE, SIG_IGN);
    sigemptyset(&mask);
    sigaddset(&mask, SIGPIPE);
    posix_spawnattr_setsigdefault(&attr, &mask);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGDEF);
    run_role("/bin/procs-child", "default", &attr);
    posix_spawnattr_destroy(&attr);
    signal(SIGPIPE, SIG_DFL);

    run_role("/bin/procs-child", "handles", NULL);
    /* Condition O2: a channel of the parent's in Start carries no request
     * of the loader, whose own handles come from the service. */
    stafeto_probe_decoy(1);
    run_role("/bin/procs-child", "child", NULL);
    stafeto_probe_decoy(0);
    expect("OpenExec through the probe's own session", stafeto_probe_open_exec("/bin/ls"), EPERM);
}

/* Spawns /bin/procs-child in role `name` with `actions` and checks it
 * exits with 0. */
static void run_with(const char *path, const char *name, const char *arg,
                     const posix_spawn_file_actions_t *actions) {
    char *argv[] = {"procs-child", (char *)name, (char *)arg, NULL};
    char *envp[] = {NULL};
    pid_t pid = -1;
    int e = posix_spawn(&pid, path, actions, NULL, argv, envp);
    if (e != 0) {
        printf("posix-procs: spawn for %s gave %d (%s)\n", name, e, strerror(e));
        failures++;
        return;
    }
    reap(name, pid, 0, 0);
}

/* Stage 8: descriptors through posix_spawn. */
static void descriptors(void) {
    for (int fd = 3; fd < 8; fd++) close(fd);
    int fd3 = open("/etc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int fd4 = dup(fd3);
    expect("open of fd 3", fd3, 3);
    expect("dup to fd 4", fd4, 4);
    expect("FD_CLOEXEC on fd 4", fcntl(fd4, F_SETFD, FD_CLOEXEC), 0);
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, fd4, fd4);
    posix_spawn_file_actions_adddup2(&actions, fd4, 5);
    run_with("/bin/procs-child", "fds", NULL, &actions);
    posix_spawn_file_actions_destroy(&actions);
    close(fd3);
    close(fd4);

    /* The child reads 10 bytes of the description it shares. */
    int motd = open("/etc/motd", O_RDONLY);
    char number[8];
    snprintf(number, sizeof number, "%d", motd);
    run_with("/bin/procs-child", "read10", number, NULL);
    expect("the offset the child moved", (int)lseek(motd, 0, SEEK_CUR), 10);
    close(motd);

    /* addopen at 7, addclose of 6, addchdir with a relative program. */
    int six = open("/etc/motd", O_RDONLY);
    expect("open of fd 6", six >= 0, 1);
    if (six != 6) {
        dup2(six, 6);
        close(six);
    }
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions, 7, "/etc/motd", O_RDONLY, 0);
    posix_spawn_file_actions_addclose(&actions, 6);
    run_with("/bin/procs-child", "opened", NULL, &actions);
    posix_spawn_file_actions_destroy(&actions);
    struct stat st;
    expect("fd 7 of the action stays in the child", fstat(7, &st) == -1 && errno == EBADF, 1);
    expect("fd 6 stays open in the parent", fstat(6, &st), 0);
    close(6);
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addchdir(&actions, "/bin");
    run_with("procs-child", "cwd", NULL, &actions);
    posix_spawn_file_actions_destroy(&actions);
}

/* Stage 9, the window of exec: old images that end before ExecCommit, 20
 * by exit and 20 by their own SIGKILL, and 8 execs while another thread
 * spawns, give the service's pool back; an exec while other threads wait
 * in waitpid and sleep goes on; a SpawnCommit before the loader's image
 * is ready is refused. */
static void windows(void) {
    char *envp[] = {NULL};
    unsigned long long before = stafeto_probe_pool();
    expect("the pool is known", before > 0, 1);
    for (int i = 0; i < 40; i++) {
        int killed = i % 2;
        char *ghost[] = {"procs-child", killed ? "ghostkill" : "ghostexec", NULL};
        pid_t pid = -1;
        int e = posix_spawn(&pid, "/bin/procs-child", NULL, NULL, ghost, envp);
        if (e != 0) {
            printf("posix-procs: spawn of ghost %d gave %d (%s)\n", i, e, strerror(e));
            failures++;
            break;
        }
        reap("an old image that ends before ExecCommit", pid, killed ? 0 : 7,
             killed ? SIGKILL : 0);
    }
    for (int i = 0; i < 8; i++) {
        char turns[8];
        snprintf(turns, sizeof turns, "%d", 3 + 5 * i);
        char *argv[] = {"procs-child", "execspawn", turns, NULL};
        pid_t pid = -1;
        expect("spawn of execspawn", posix_spawn(&pid, "/bin/procs-child", NULL, NULL, argv, envp),
               0);
        reap("an exec while another thread spawns", pid, 7, 0);
    }
    unsigned long long after = stafeto_probe_pool();
    printf("posix-procs: pool %llu before the window, %llu after\n", before, after);
    if (after + 32 * 4096 < before) {
        printf("posix-procs: the window kept %llu bytes of the pool\n", before - after);
        failures++;
    }
    char *busy[] = {"procs-child", "execbusy", NULL};
    pid_t pid = -1;
    expect("spawn of execbusy", posix_spawn(&pid, "/bin/procs-child", NULL, NULL, busy, envp), 0);
    reap("an exec while threads wait", pid, 7, 0);
    int early = -1;
    expect("SpawnCommit before the image is ready", stafeto_probe_commit_early(&early), EIO);
    /* SpawnAbort took the uncommitted child, which leaves no status. */
    expect("a wait for the aborted child", waitpid(early, NULL, WNOHANG), -1);
}

/* Stage 9: exec. */
static void execs(void) {
    run_role("/bin/procs-child", "execls", NULL);
    char *self[] = {"procs-child", "execself", NULL};
    char *none[] = {NULL};
    pid_t pid = -1;
    expect("spawn of execself", posix_spawn(&pid, "/bin/procs-child", NULL, NULL, self, none), 0);
    reap("a child that execs itself", pid, 42, 0);
    run_role("/bin/procs-child", "execfail", NULL);
    char *ghost[] = {"procs-child", "ghostexec", NULL};
    char *envp[] = {NULL};
    pid = -1;
    expect("spawn of ghostexec", posix_spawn(&pid, "/bin/procs-child", NULL, NULL, ghost, envp), 0);
    reap("an old image that ends before ExecCommit", pid, 7, 0);
    expect("ExecCommit with no exec", stafeto_probe_exec_commit(), EIO);
    windows();
}

/* Stage 9 as nobody: set-ID through exec. */
static void execs_nobody(void) {
    char *argv[] = {"procs-child", "execto", "/bin/procs-setid", "setid", NULL};
    char *envp[] = {NULL};
    pid_t pid = -1;
    expect("spawn of execto", posix_spawn(&pid, "/bin/procs-child", NULL, NULL, argv, envp), 0);
    reap("an exec of a set-user-ID file", pid, 0, 0);
    run_role("/bin/procs-child", "execjunk", NULL);
    run_role("/bin/procs-child", "execoutlive", NULL);
}

/* Stage 7 once the probe is nobody: set-ID files. */
static void files_nobody(void) {
    run_role("/bin/procs-setid", "setid", NULL);
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_RESETIDS);
    run_role("/bin/procs-setid", "setid", &attr);
    posix_spawnattr_destroy(&attr);
    /* A set-ID file that the loader opens and cannot load: its SetId goes
     * with the attempt, and the next child of the same place is nobody. */
    char *child[] = {"procs-child", "child", NULL};
    refused("spawn of a set-ID file that is no program", "/bin/setid-junk", child, ENOEXEC);
    run_role("/bin/procs-child", "nobody", NULL);
    refused("spawn under a directory without search", "/sbin/procs-child", child, EACCES);
}

/* The layer's memory map and mmap (5d, T1). */
static void memory(void) {
    /* A shared anonymous mapping must stay shared with a forked child, and
     * the layer has no shared memory: mmap says it does not support it
     * (POSIX mmap, ENOTSUP). No kind at all is EINVAL. */
    void *shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    expect("mmap MAP_SHARED", shared == MAP_FAILED ? errno : 0, ENOTSUP);
    void *none = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS, -1, 0);
    expect("mmap with no kind", none == MAP_FAILED ? errno : 0, EINVAL);
    void *own = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    expect("mmap MAP_PRIVATE", own == MAP_FAILED, 0);
    if (own != MAP_FAILED) munmap(own, 4096);
    /* This program started from init's table, so its map holds the heap's
     * chunks alone. */
    expect("the heap's regions grow with it", map_growth("probe"), 0);
    run_role("/bin/procs-child", "memmap", NULL);
}

/* Stage forks (5d). */
static void forks(void) {
    /* A program init started has no segments in its map. */
    expect("a fork of a program init started", stafeto_probe_fork_bare(bare_park, NULL, NULL), -ENOSYS);
    run_role("/bin/procs-child", "forkbare", NULL);
    run_role("/bin/procs-child", "forkfull", NULL);
    run_role("/bin/procs-child", "forkthreads", NULL);
    run_role("/bin/procs-child", "forkthread", NULL);
    run_role("/bin/procs-child", "forkwaits", NULL);
    run_role("/bin/procs-child", "forkmalloc", NULL);
    run_role("/bin/procs-child", "forkmany", NULL);
    /* A parent that dies in the window of its fork leaves nothing: its
     * loading child and that child's loader go, and the pool is whole. */
    const char *dying[] = {"forkdie", "forkdieearly"};
    for (int i = 0; i < 2; i++) {
        unsigned long long before = stafeto_probe_pool();
        char *argv[] = {"procs-child", (char *)dying[i], NULL};
        char *env[] = {NULL};
        pid_t pid = -1;
        expect(dying[i], posix_spawn(&pid, "/bin/procs-child", NULL, NULL, argv, env), 0);
        reap(dying[i], pid, 0, SIGKILL);
        unsigned long long after = stafeto_probe_pool();
        for (int n = 0; n < 100 && after != before; n++) {
            pause_ms(5);
            after = stafeto_probe_pool();
        }
        if (after != before) {
            printf("posix-procs: the pool after %s: %llu before, %llu after\n", dying[i], before, after);
            failures++;
        }
    }
    char *making[] = {"procs-child", "execmaking", NULL};
    char *none[] = {NULL};
    pid_t maker = -1;
    expect("spawn of execmaking", posix_spawn(&maker, "/bin/procs-child", NULL, NULL, making, none), 0);
    reap("an exec while a thread makes threads", maker, 7, 0);
    /* BusyBox ash from its file (/bin/ls, BusyBox, as `ash`) runs an
     * external program that is not its last command: it forks, and the
     * shell goes on to exit 3 once ls succeeded. */
    char *ash[] = {"ash", "-c", "/bin/ls /etc && exit 3", NULL};
    char *env[] = {"PATH=/bin", NULL};
    pid_t shell = -1;
    expect("spawn of ash -c", posix_spawn(&shell, "/bin/ls", NULL, NULL, ash, env), 0);
    int status = -1;
    if (shell > 0 && waitpid(shell, &status, 0) == shell && WIFEXITED(status) &&
        WEXITSTATUS(status) == 3) {
        printf("posix-procs: ash -c ran /bin/ls\n");
    } else {
        printf("posix-procs: ash -c ended with status %#x\n", status);
        failures++;
    }
    pid_t sleeper = start("sleep");
    run_role("/bin/procs-child", "forkpool", NULL);
    if (sleeper > 0) {
        kill(sleeper, SIGKILL);
        reap("the sleeper of forkpool", sleeper, 0, SIGKILL);
    }
}

int main(int argc, char **argv) {
    argc_seen = argc;
    argv_seen = argv;
    if (argc > 1) return role(argv[1]);
    pid_t child = 0;
    int e = spawn(&child, "child", NULL, NULL);
    expect("spawn of procs-child", e, 0);
    printf("posix-procs: parent %d spawned %d\n", (int)getpid(), (int)child);

    pid_t sleeper = 0;
    expect("spawn of the sleeper", spawn(&sleeper, "sleep", NULL, NULL), 0);
    /* A second child of the program lives beside the first. */
    pid_t second = -1;
    expect("a second sleeper", spawn(&second, "sleep", NULL, NULL), 0);
    expect("two PIDs", second > 0 && second != sleeper, 1);
    expect("kill of the second sleeper", kill(second, SIGKILL), 0);
    reap("the second sleeper", second, 0, SIGKILL);

    printf("posix-procs: stage waits\n");
    waits(child);
    printf("posix-procs: stage kills\n");
    kills(sleeper);
    printf("posix-procs: stage groups\n");
    groups();
    printf("posix-procs: stage churn\n");
    churn();
    printf("posix-procs: stage files\n");
    files();
    printf("posix-procs: stage descriptors\n");
    descriptors();
    printf("posix-procs: stage execs\n");
    execs();
    printf("posix-procs: stage clock_rights\n");
    clock_rights();
    printf("posix-procs: stage files_nobody\n");
    files_nobody();
    printf("posix-procs: stage execs_nobody\n");
    execs_nobody();
    printf("posix-procs: stage memory\n");
    memory();
    printf("posix-procs: stage forks\n");
    forks();
    printf("posix-procs: stage wave\n");
    wave();
    if (failures != 0) return 1;
    printf("posix-procs: ok\n");
    /* Stage 10: this process is a record of init's table, whose end line
     * init reads from the new image: an exec of a child's role that exits
     * with 42 (xtask expects `exit code 42`, never the old image's 0). */
    char *last[] = {"procs-child", "last", NULL};
    char *env[] = {NULL};
    execve("/bin/procs-child", last, env);
    printf("posix-procs: the last exec gave %d (%s)\n", errno, strerror(errno));
    return 1;
}
