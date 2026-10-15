/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* Parks inside the waits on a thread's channel (issue 303).
 *
 * A thread that parks for the stop of a fork or an exec receives from its
 * own channel and takes whatever comes. A wait that made its last check
 * before the park and receives after it has lost the notification of what
 * it waits for. Each case puts one wait there: stafeto_probe_window stops
 * the wait after its last check until the thread parked, and the window of
 * the fork (the stop is on, the thread parked) does what the wait waits
 * for, so the notification comes during the park (the case forks once
 * stafeto_probe_window_reached says the wait stands there). The wait must
 * still end.
 * The cases run one after the other in one process (a program of its own,
 * so that the poll and condition code it needs does not grow the memory of
 * posix-procs, which its checks hold within a budget):
 *
 * - poll: poll on a pipe, a byte written in the window;
 * - fifo: open of a FIFO for reading, a writer opened in the window;
 * - futex: pthread_cond_wait, pthread_cond_signal in the window;
 * - futextimed: pthread_cond_timedwait with a deadline inside the window;
 * - sigwait: sigwait, pthread_kill in the window;
 * - sigsuspend: sigsuspend, a handler that runs in the window (it must
 *   return, not wait for the next signal);
 * - cancel: sigwait, pthread_cancel in the window (the request of
 *   cancellation, its notification and its interrupt, come while parked).
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

void stafeto_probe_window(int site);
int stafeto_probe_window_reached(void);
void stafeto_probe_fork_window(void (*window)(void));

static int failures;

static void pause_ms(long ms) {
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000L};
    while (nanosleep(&t, &t) != 0) {
    }
}

static void expect(const char *what, long got, long want) {
    if (got != want) {
        printf("posix-park: %s gave %ld, expected %ld\n", what, got, want);
        failures++;
    }
}


#define PARK_POLL 1
#define PARK_FIFO 2
#define PARK_FUTEX 3
#define PARK_SIGWAIT 4
#define PARK_SUSPEND 5
#define PARK_CANCEL 6

static volatile int pw_done, pw_result;
static int pw_pipe[2];
static pthread_mutex_t pw_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pw_cond = PTHREAD_COND_INITIALIZER;
static int pw_posted;
static pthread_t pw_waiter;
static const char pw_fifo[] = "/tmp/park-fifo";
static int pw_site;
static int pw_writer = -1;
static long pw_deadline_ms;
static volatile int pw_handled;

static void pw_handler(int sig) {
    (void)sig;
    __atomic_store_n(&pw_handled, 1, __ATOMIC_RELEASE);
}

static void pw_finish(int result) {
    pw_result = result;
    __atomic_store_n(&pw_done, 1, __ATOMIC_RELEASE);
}

static void pw_cancelled(void *arg) {
    (void)arg;
    pw_finish(0);
}

static void *pw_wait(void *arg) {
    (void)arg;
    stafeto_probe_window(pw_site == PARK_CANCEL ? PARK_SIGWAIT : pw_site);
    switch (pw_site) {
    case PARK_POLL: {
        struct pollfd p = {pw_pipe[0], POLLIN, 0};
        pw_finish(poll(&p, 1, -1) == 1 && (p.revents & POLLIN) ? 0 : 1);
        break;
    }
    case PARK_FIFO: {
        int fd = open(pw_fifo, O_RDONLY);
        pw_finish(fd >= 0 ? 0 : 1);
        if (fd >= 0) close(fd);
        break;
    }
    case PARK_FUTEX:
        if (pw_deadline_ms == 0) {
            pthread_mutex_lock(&pw_lock);
            while (!__atomic_load_n(&pw_posted, __ATOMIC_ACQUIRE)) pthread_cond_wait(&pw_cond, &pw_lock);
            pthread_mutex_unlock(&pw_lock);
            pw_finish(0);
        } else {
            struct timespec t;
            clock_gettime(CLOCK_REALTIME, &t);
            t.tv_nsec += pw_deadline_ms * 1000000L;
            t.tv_sec += t.tv_nsec / 1000000000L;
            t.tv_nsec %= 1000000000L;
            pthread_mutex_lock(&pw_lock);
            int e = 0;
            while (e == 0 && !__atomic_load_n(&pw_posted, __ATOMIC_ACQUIRE))
                e = pthread_cond_timedwait(&pw_cond, &pw_lock, &t);
            pthread_mutex_unlock(&pw_lock);
            pw_finish(e == ETIMEDOUT ? 0 : 1);
        }
        break;
    case PARK_SIGWAIT: {
        sigset_t set;
        int sig = 0;
        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        pw_finish(sigwait(&set, &sig) == 0 && sig == SIGUSR1 ? 0 : 1);
        break;
    }
    case PARK_SUSPEND: {
        sigset_t none;
        sigemptyset(&none);
        int r = sigsuspend(&none);
        pw_finish(r == -1 && errno == EINTR && __atomic_load_n(&pw_handled, __ATOMIC_ACQUIRE) ? 0 : 1);
        break;
    }
    case PARK_CANCEL: {
        sigset_t set;
        int sig = 0;
        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        pthread_cleanup_push(pw_cancelled, NULL);
        sigwait(&set, &sig);
        pthread_cleanup_pop(0);
        pw_finish(1);
        break;
    }
    }
    return NULL;
}

static void pw_window(void) {
    switch (pw_site) {
    case PARK_POLL: {
        char byte = 'x';
        if (write(pw_pipe[1], &byte, 1) != 1) failures++;
        break;
    }
    case PARK_FIFO: {
        int fd = open(pw_fifo, O_WRONLY | O_NONBLOCK);
        pw_writer = fd;
        if (fd < 0) {
            printf("posix-park: the writer of the FIFO: errno %d\n", errno);
            failures++;
        }
        break;
    }
    case PARK_FUTEX:
        if (pw_deadline_ms == 0) {
            __atomic_store_n(&pw_posted, 1, __ATOMIC_RELEASE);
            pthread_cond_signal(&pw_cond);
        }
        break;
    case PARK_SIGWAIT:
    case PARK_SUSPEND:
        pthread_kill(pw_waiter, SIGUSR1);
        break;
    case PARK_CANCEL:
        pthread_cancel(pw_waiter);
        break;
    }
    pause_ms(pw_deadline_ms ? 3 * pw_deadline_ms : 60);
}

static int park_wait_role(int site, long deadline_ms, const char *what) {
    pw_site = site;
    pw_deadline_ms = deadline_ms;
    __atomic_store_n(&pw_done, 0, __ATOMIC_RELEASE);
    sigset_t usr1;
    sigemptyset(&usr1);
    sigaddset(&usr1, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &usr1, NULL);
    if (site == PARK_POLL) expect("pipe", pipe(pw_pipe), 0);
    if (site == PARK_FIFO) {
        unlink(pw_fifo);
        expect("mkfifo", mkfifo(pw_fifo, 0600), 0);
    }
    __atomic_store_n(&pw_posted, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&pw_handled, 0, __ATOMIC_RELEASE);
    pthread_create(&pw_waiter, NULL, pw_wait, NULL);
    for (int i = 0; i < 5000 && !stafeto_probe_window_reached(); i++) pause_ms(1);
    expect("the wait reached its site", stafeto_probe_window_reached(), 1);
    fflush(stdout);
    stafeto_probe_fork_window(pw_window);
    pid_t pid = fork();
    if (pid == 0) _exit(0);
    stafeto_probe_fork_window(NULL);
    int status = -1;
    expect("the fork", waitpid(pid, &status, 0), pid);
    expect("the child of the fork", WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
    for (int i = 0; i < 5000 && !__atomic_load_n(&pw_done, __ATOMIC_ACQUIRE); i++) pause_ms(1);
    int done = __atomic_load_n(&pw_done, __ATOMIC_ACQUIRE);
    expect(what, done, 1);
    if (done) {
        expect(what, pw_result, 0);
        pthread_join(pw_waiter, NULL);
        if (pw_writer >= 0) close(pw_writer);
        pw_writer = -1;
        if (!failures) printf("posix-park: a park does not lose the end of %s\n", what);
    }
    return failures;
}

/* A fork needs a program that was loaded from a file: the first process
 * runs the cases in a child that /bin/procs-child starts (this program). */
int main(int argc, char **argv) {
    (void)argv;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = pw_handler;
    sigaction(SIGUSR1, &sa, NULL);
    if (argc == 1) {
        char *child[] = {"posix-park", "run", NULL};
        char *env[] = {NULL};
        pid_t pid = -1;
        expect("spawn", posix_spawn(&pid, "/bin/procs-child", NULL, NULL, child, env), 0);
        int status = -1;
        expect("wait", waitpid(pid, &status, 0), pid);
        expect("the cases", WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
        fflush(stdout);
        return failures != 0;
    }
    if (!failures) park_wait_role(PARK_POLL, 0, "poll");
    if (!failures) park_wait_role(PARK_FIFO, 0, "the open of a FIFO");
    if (!failures) park_wait_role(PARK_FUTEX, 0, "a wait by address");
    if (!failures) park_wait_role(PARK_FUTEX, 60, "a timed wait by address");
    if (!failures) park_wait_role(PARK_SIGWAIT, 0, "sigwait");
    if (!failures) park_wait_role(PARK_SUSPEND, 0, "sigsuspend");
    if (!failures) park_wait_role(PARK_CANCEL, 0, "a cancelled sigwait");
    if (!failures) printf("posix-park: done failures 0\n");
    fflush(stdout);
    return failures != 0;
}
