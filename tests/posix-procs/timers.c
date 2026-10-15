/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* Timers, the alarm, sigqueue and clock (Ф7, services).
 *
 * The role "timers" forks one child per case and reaps it: an exit code
 * names the failed check (0 passes). The process service keeps the timers
 * (one table, one timer of the kernel) and sends their signals through the
 * page of the process as kill does.
 *
 * - sigqueue: the value, SI_QUEUE, the sender's PID and UID reach a handler
 *   and sigwaitinfo; a second occurrence of a waiting signal is EAGAIN and
 *   a taken one leaves room; ESRCH, EINVAL; from another process.
 * - timers: a signal with SI_TIMER and the value of the event; gettime and
 *   settime return the time left and the old setting; absolute times on both
 *   clocks, one in the past; SIGEV_NONE; delete stops the signal and the id
 *   goes; 32 timers a process; a null event; EINVAL for bad arguments.
 * - the overrun counts what came while the signal waited and starts again
 *   with the next signal; eight timers due at once all deliver; an interval
 *   below the least is raised.
 * - the alarm: the seconds left, cancel, SIGALRM ends a process that does not
 *   catch it, an interval timer repeats, ITIMER_VIRTUAL is EINVAL; a pending
 *   alarm and no timer survives exec, none is inherited by fork, and the
 *   table gives back the places of a process that ended.
 * - clock: grows with time, starts again in the child of fork.
 */
#include <sys/time.h>

/* setitimer and getitimer left POSIX in Issue 8 and stay in the library. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#define T_MS 1000000LL

static long long t_now(clockid_t clock) {
    struct timespec t;
    clock_gettime(clock, &t);
    return t.tv_sec * 1000000000LL + t.tv_nsec;
}
static struct timespec t_spec(long long ns) {
    struct timespec t = {.tv_sec = ns / 1000000000LL, .tv_nsec = ns % 1000000000LL};
    return t;
}
static int t_block(int sig) {
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, sig);
    return sigprocmask(SIG_BLOCK, &s, NULL);
}
/* Takes `sig` within `ms`: its number, or -1 with errno. */
static int t_take(int sig, siginfo_t *info, long ms) {
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, sig);
    struct timespec limit = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};
    return sigtimedwait(&s, info, &limit);
}
static struct sigevent t_event(int sig, long value) {
    struct sigevent e;
    memset(&e, 0, sizeof(e));
    e.sigev_notify = SIGEV_SIGNAL;
    e.sigev_signo = sig;
    e.sigev_value.sival_int = (int)value;
    return e;
}
static struct itimerspec t_its(long long value, long long interval) {
    struct itimerspec its = {.it_value = t_spec(value), .it_interval = t_spec(interval)};
    return its;
}

/* The steps mode: a process that sets a timer for the instant in its second
 * argument (CLOCK_MONOTONIC, nanoseconds) and waits for the signal. */
static int steptimer_role(void) {
    char *end;
    long long at = strtoll(argv_seen[2], &end, 10);
    /* After a comma, the signal the timer sends: SIGSTOP or SIGKILL end
     * (or stop) the process itself, the dearest steps of the expiry. */
    int sig = *end == ',' ? atoi(end + 1) : SIGUSR1;
    t_block(SIGUSR1);
    struct sigevent e = t_event(sig, 1);
    timer_t t;
    if (timer_create(CLOCK_MONOTONIC, &e, &t)) return 1;
    struct itimerspec its = t_its(at, 0);
    if (timer_settime(t, TIMER_ABSTIME, &its, NULL)) return 2;
    if (sig != SIGUSR1) {
        sleep(120);
        return 5;
    }
    siginfo_t info;
    if (t_take(SIGUSR1, &info, 120000) != SIGUSR1) return 3;
    return info.si_code == SI_TIMER ? 0 : 4;
}

/* The timer steps of the process service among the crowd (xtask
 * process-steps): three processes and the probe wait for one instant, so
 * that one notice of the kernel's timer sends four signals to four
 * processes; the probe holds a full share of timers and the alarm and
 * queues a signal. */
static int steps_timers(void) {
    pid_t kids[3];
    char at[32];
    long long due = t_now(CLOCK_MONOTONIC) + 6000 * T_MS;
    snprintf(at, sizeof at, "%lld", due);
    for (int i = 0; i < 3; i++)
        if (steps_spawn(&kids[i], "steptimer", at) != 0) return 1;
    /* The probe goes on with the signals it had (the FIFO steps send SIGUSR1). */
    sigset_t saved;
    sigprocmask(SIG_SETMASK, NULL, &saved);
    /* Four processes stop themselves at one instant, four more are killed:
     * the expiry with a call of the kernel and a report to the parent. */
    static const int dear[2] = {SIGSTOP, SIGKILL};
    for (int round = 0; round < 2; round++) {
        pid_t four[4];
        char arg[48];
        snprintf(arg, sizeof arg, "%lld,%d", t_now(CLOCK_MONOTONIC) + 6000 * T_MS, dear[round]);
        for (int i = 0; i < 4; i++)
            if (steps_spawn(&four[i], "steptimer", arg) != 0) return 20;
        for (int i = 0; i < 4; i++) {
            int status = -1;
            if (waitpid(four[i], &status, round == 0 ? WUNTRACED : 0) != four[i]) return 21;
            if (round == 0) {
                if (!WIFSTOPPED(status)) return 22;
                kill(four[i], SIGKILL);
                if (waitpid(four[i], &status, 0) != four[i]) return 23;
            }
            if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) return 24;
        }
    }
    t_block(SIGUSR1);
    t_block(SIGUSR2);
    struct sigevent e = t_event(SIGUSR1, 1);
    timer_t own[32];
    struct itimerspec far = t_its(100000 * T_MS, 50000 * T_MS);
    for (int i = 0; i < 32; i++) {
        if (timer_create(CLOCK_MONOTONIC, &e, &own[i])) return 2;
        if (timer_settime(own[i], 0, &far, NULL)) return 3;
    }
    struct itimerspec soon = t_its(due, 0);
    if (timer_settime(own[0], TIMER_ABSTIME, &soon, NULL)) return 4;
    alarm(1000);
    union sigval v;
    v.sival_int = 1;
    if (sigqueue(getpid(), SIGUSR2, v)) return 5;
    siginfo_t info;
    if (t_take(SIGUSR2, &info, 1000) != SIGUSR2) return 6;
    if (t_take(SIGUSR1, &info, 120000) != SIGUSR1 || info.si_code != SI_TIMER) return 7;
    for (int i = 0; i < 3; i++) {
        int status = -1;
        if (waitpid(kids[i], &status, 0) != kids[i] || !WIFEXITED(status) || WEXITSTATUS(status) != 0) return 8;
    }
    struct itimerspec none = t_its(0, 0);
    for (int i = 0; i < 32; i++) {
        struct itimerspec got;
        if (timer_gettime(own[i], &got) || timer_settime(own[i], 0, &none, NULL) || timer_delete(own[i])) return 9;
    }
    if (alarm(0) == 0) return 10;
    sigprocmask(SIG_SETMASK, &saved, NULL);
    return 0;
}

#if !CHANGE_STEPS
static volatile int t_got;
static siginfo_t t_info;

static void t_nap(long ms) {
    struct timespec d = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};
    while (nanosleep(&d, &d) < 0 && errno == EINTR) {}
}
static void t_handler(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)ctx;
    t_info = *info;
    t_got++;
}
static void t_plain(int sig) {
    (void)sig;
    t_got++;
}
static int t_catch(int sig) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = t_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    return sigaction(sig, &sa, NULL);
}
static int t_c_sigqueue(void) {
    if (t_catch(SIGUSR1)) return 1;
    union sigval v;
    v.sival_int = 1234;
    if (sigqueue(getpid(), SIGUSR1, v)) return 2;
    if (!t_got || t_info.si_signo != SIGUSR1 || t_info.si_code != SI_QUEUE) return 3;
    if (t_info.si_value.sival_int != 1234) return 4;
    if (t_info.si_pid != getpid() || t_info.si_uid != getuid()) return 5;
    t_got = 0;
    v.sival_ptr = (void *)0x123456789abcdef0UL;
    if (sigqueue(getpid(), SIGUSR1, v)) return 6;
    if (!t_got || t_info.si_value.sival_ptr != v.sival_ptr) return 7;
    t_got = 0;
    if (kill(getpid(), SIGUSR1)) return 8;
    if (!t_got || t_info.si_code != SI_USER || t_info.si_value.sival_ptr != NULL) return 9;
    return 0;
}

static int t_c_queue_places(void) {
    if (t_block(SIGUSR1)) return 1;
    union sigval v;
    v.sival_int = 111;
    if (sigqueue(getpid(), SIGUSR1, v)) return 2;
    v.sival_int = 222;
    if (sigqueue(getpid(), SIGUSR1, v) != -1 || errno != EAGAIN) return 3;
    siginfo_t info;
    if (t_take(SIGUSR1, &info, 1000) != SIGUSR1) return 4;
    if (info.si_code != SI_QUEUE || info.si_value.sival_int != 111) return 5;
    v.sival_int = 333;
    if (sigqueue(getpid(), SIGUSR1, v)) return 6;
    if (t_take(SIGUSR1, &info, 1000) != SIGUSR1 || info.si_value.sival_int != 333) return 7;
    /* Nothing is left. */
    if (t_take(SIGUSR1, &info, 20) != -1 || errno != EAGAIN) return 8;
    v.sival_int = 0;
    if (sigqueue(getpid(), 0, v)) return 9;
    if (t_take(SIGUSR1, &info, 20) != -1) return 10;
    if (sigqueue(getpid(), 99, v) != -1 || errno != EINVAL) return 11;
    if (sigqueue(getpid(), -1, v) != -1 || errno != EINVAL) return 12;
    if (sigqueue(0x7ffffff0, SIGUSR1, v) != -1 || errno != ESRCH) return 13;
    return 0;
}

static int t_c_queue_peer(void) {
    int fds[2];
    if (pipe(fds)) return 1;
    pid_t parent = getpid();
    pid_t child = fork();
    if (child < 0) return 2;
    if (child == 0) {
        siginfo_t info;
        t_block(SIGUSR2);
        if (write(fds[1], "r", 1) != 1) _exit(10);
        if (t_take(SIGUSR2, &info, 3000) != SIGUSR2) _exit(11);
        if (info.si_code != SI_QUEUE || info.si_pid != parent) _exit(12);
        if (info.si_value.sival_int != 4242) _exit(13);
        _exit(0);
    }
    char c;
    if (read(fds[0], &c, 1) != 1) return 3;
    union sigval v;
    v.sival_int = 4242;
    if (sigqueue(child, SIGUSR2, v)) return 4;
    int status = -1;
    if (waitpid(child, &status, 0) != child) return 5;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return 20 + (WIFEXITED(status) ? WEXITSTATUS(status) : 99) % 70;
    if (sigqueue(child, SIGUSR2, v) != -1 || errno != ESRCH) return 6;
    return 0;
}

static int t_c_timer_signal(void) {
    if (t_catch(SIGUSR1)) return 1;
    t_block(SIGUSR1);
    struct sigevent e = t_event(SIGUSR1, 77);
    timer_t t;
    if (timer_create(CLOCK_MONOTONIC, &e, &t)) return 2;
    if (timer_getoverrun(t) != 0) return 3;
    struct itimerspec its = t_its(20 * T_MS, 0);
    if (timer_settime(t, 0, &its, NULL)) return 4;
    siginfo_t info;
    if (t_take(SIGUSR1, &info, 2000) != SIGUSR1) return 5;
    if (info.si_code != SI_TIMER) return 6;
    if (info.si_value.sival_int != 77) return 7;
    if (timer_getoverrun(t) != 0) return 8;
    if (timer_gettime(t, &its)) return 9;
    if (its.it_value.tv_sec || its.it_value.tv_nsec || its.it_interval.tv_sec || its.it_interval.tv_nsec) return 10;
    /* Once only. */
    if (t_take(SIGUSR1, &info, 60) != -1) return 11;
    /* The signal reaches a handler too, with the same information. */
    sigset_t none;
    sigemptyset(&none);
    its = t_its(10 * T_MS, 0);
    if (timer_settime(t, 0, &its, NULL)) return 12;
    t_nap(60);
    t_got = 0;
    sigsuspend(&none);
    if (t_got != 1 || t_info.si_code != SI_TIMER || t_info.si_value.sival_int != 77) return 13;
    return timer_delete(t) ? 14 : 0;
}

static int t_c_gettime_settime(void) {
    struct sigevent e = t_event(SIGUSR1, 1);
    timer_t t;
    if (timer_create(CLOCK_MONOTONIC, &e, &t)) return 1;
    struct itimerspec its = t_its(500 * T_MS, 300 * T_MS), old;
    if (timer_settime(t, 0, &its, &old)) return 2;
    if (old.it_value.tv_sec || old.it_value.tv_nsec || old.it_interval.tv_nsec) return 3;
    struct itimerspec now;
    if (timer_gettime(t, &now)) return 4;
    long long left = now.it_value.tv_sec * 1000000000LL + now.it_value.tv_nsec;
    if (left <= 0 || left > 500 * T_MS) return 5;
    if (now.it_interval.tv_sec != 0 || now.it_interval.tv_nsec != 300 * T_MS) return 6;
    t_nap(30);
    struct itimerspec later;
    if (timer_gettime(t, &later)) return 7;
    long long left2 = later.it_value.tv_sec * 1000000000LL + later.it_value.tv_nsec;
    if (left2 >= left || left2 <= 0) return 8;
    its = t_its(900 * T_MS, 0);
    if (timer_settime(t, 0, &its, &old)) return 9;
    if (old.it_interval.tv_nsec != 300 * T_MS || old.it_value.tv_nsec + old.it_value.tv_sec * 1000000000LL > left2) return 10;
    its = t_its(0, 0);
    if (timer_settime(t, 0, &its, &old)) return 11;
    if (old.it_value.tv_sec * 1000000000LL + old.it_value.tv_nsec <= 0) return 12;
    if (timer_gettime(t, &now) || now.it_value.tv_sec || now.it_value.tv_nsec) return 13;
    /* Bad settings. */
    its = t_its(1, 0);
    its.it_value.tv_nsec = 1000000000L;
    if (timer_settime(t, 0, &its, NULL) != -1 || errno != EINVAL) return 14;
    its = t_its(1, 0);
    its.it_interval.tv_nsec = -1;
    if (timer_settime(t, 0, &its, NULL) != -1 || errno != EINVAL) return 15;
    its = t_its(1, 0);
    if (timer_settime(t, 4, &its, NULL) != -1 || errno != EINVAL) return 16;
    its = t_its(1, 0);
    its.it_value.tv_sec = -1;
    if (timer_settime(t, 0, &its, NULL) != -1 || errno != EINVAL) return 17;
    return timer_delete(t) ? 18 : 0;
}

static int t_one_absolute(clockid_t clock, long long ahead_ns) {
    struct sigevent e = t_event(SIGUSR1, 5);
    timer_t t;
    if (timer_create(clock, &e, &t)) return 1;
    /* A time that passed: half of the clock's value, which is positive. */
    long long at = ahead_ns < 0 ? t_now(clock) / 2 : t_now(clock) + ahead_ns;
    struct itimerspec its = t_its(at, 0);
    if (timer_settime(t, TIMER_ABSTIME, &its, NULL)) return 2;
    siginfo_t info;
    long long begun = t_now(CLOCK_MONOTONIC);
    if (t_take(SIGUSR1, &info, 2000) != SIGUSR1) return 3;
    long long took = t_now(CLOCK_MONOTONIC) - begun;
    if (ahead_ns > 0 && took < ahead_ns / 2) return 4;
    if (info.si_code != SI_TIMER) return 5;
    return timer_delete(t) ? 6 : 0;
}
static int t_c_absolute(void) {
    t_block(SIGUSR1);
    int r;
    if ((r = t_one_absolute(CLOCK_MONOTONIC, 40 * T_MS))) return r;
    if ((r = t_one_absolute(CLOCK_REALTIME, 40 * T_MS))) return 10 + r;
    /* A time that passed fires at once. */
    if ((r = t_one_absolute(CLOCK_MONOTONIC, -1000 * T_MS))) return 20 + r;
    if ((r = t_one_absolute(CLOCK_REALTIME, -1000 * T_MS))) return 30 + r;
    return 0;
}

static int t_c_none(void) {
    t_block(SIGUSR1);
    struct sigevent e;
    memset(&e, 0, sizeof(e));
    e.sigev_notify = SIGEV_NONE;
    timer_t t;
    if (timer_create(CLOCK_MONOTONIC, &e, &t)) return 1;
    struct itimerspec its = t_its(20 * T_MS, 0), now;
    if (timer_settime(t, 0, &its, NULL)) return 2;
    if (timer_gettime(t, &now) || (!now.it_value.tv_sec && !now.it_value.tv_nsec)) return 3;
    t_nap(60);
    sigset_t pending;
    sigpending(&pending);
    for (int s = 1; s < 32; s++)
        if (sigismember(&pending, s)) return 4;
    if (timer_gettime(t, &now) || now.it_value.tv_sec || now.it_value.tv_nsec) return 5;
    return timer_delete(t) ? 6 : 0;
}

static int t_c_delete(void) {
    t_block(SIGUSR1);
    struct sigevent e = t_event(SIGUSR1, 1);
    timer_t t;
    if (timer_create(CLOCK_MONOTONIC, &e, &t)) return 1;
    struct itimerspec its = t_its(30 * T_MS, 0);
    if (timer_settime(t, 0, &its, NULL)) return 2;
    if (timer_delete(t)) return 3;
    t_nap(90);
    siginfo_t info;
    if (t_take(SIGUSR1, &info, 10) != -1) return 4;
    if (timer_gettime(t, &its) != -1 || errno != EINVAL) return 5;
    if (timer_delete(t) != -1 || errno != EINVAL) return 6;
    if (timer_getoverrun(t) != -1 || errno != EINVAL) return 7;
    if (timer_settime(t, 0, &its, NULL) != -1 || errno != EINVAL) return 8;
    /* The place is used again and the old id still names nothing. */
    timer_t again;
    if (timer_create(CLOCK_MONOTONIC, &e, &again)) return 9;
    if (again == t) return 10;
    if (timer_gettime(t, &its) != -1 || errno != EINVAL) return 11;
    timer_delete(again);
    /* 32 timers a process. */
    timer_t all[32];
    for (int i = 0; i < 32; i++)
        if (timer_create(CLOCK_MONOTONIC, &e, &all[i])) return 20 + i % 10;
    if (timer_create(CLOCK_MONOTONIC, &e, &again) != -1 || errno != EAGAIN) return 12;
    if (timer_delete(all[5])) return 13;
    if (timer_create(CLOCK_MONOTONIC, &e, &again)) return 14;
    return 0;
}

static int t_c_create_errors(void) {
    struct sigevent e = t_event(SIGUSR1, 1);
    timer_t t;
    if (timer_create(7, &e, &t) != -1 || errno != EINVAL) return 1;
    if (timer_create(CLOCK_MONOTONIC, &e, NULL) != -1 || errno != EINVAL) return 2;
    e.sigev_signo = 0;
    if (timer_create(CLOCK_MONOTONIC, &e, &t) != -1 || errno != EINVAL) return 3;
    e.sigev_signo = 99;
    if (timer_create(CLOCK_MONOTONIC, &e, &t) != -1 || errno != EINVAL) return 4;
    e = t_event(SIGUSR1, 1);
    e.sigev_notify = 7;
    if (timer_create(CLOCK_MONOTONIC, &e, &t) != -1 || errno != EINVAL) return 5;
    if (timer_getoverrun((timer_t)0x1234567) != -1 || errno != EINVAL) return 6;
    struct itimerspec its;
    if (timer_gettime((timer_t)0x100000001, &its) != -1 || errno != EINVAL) return 7;
    /* A null event: SIGALRM, and the timer's number is the value. */
    t_block(SIGALRM);
    if (timer_create(CLOCK_MONOTONIC, NULL, &t)) return 8;
    its = t_its(10 * T_MS, 0);
    if (timer_settime(t, 0, &its, NULL)) return 9;
    siginfo_t info;
    if (t_take(SIGALRM, &info, 2000) != SIGALRM) return 10;
    if (info.si_code != SI_TIMER || info.si_value.sival_int != (int)(uintptr_t)t) return 11;
    return timer_delete(t) ? 12 : 0;
}

static int t_c_overrun(void) {
    t_block(SIGUSR1);
    struct sigevent e = t_event(SIGUSR1, 9);
    timer_t t;
    if (timer_create(CLOCK_MONOTONIC, &e, &t)) return 1;
    struct itimerspec its = t_its(5 * T_MS, 5 * T_MS);
    if (timer_settime(t, 0, &its, NULL)) return 2;
    t_nap(90);
    siginfo_t info;
    if (t_take(SIGUSR1, &info, 1000) != SIGUSR1) return 3;
    /* About 17 expirations met one waiting signal. */
    int first = timer_getoverrun(t);
    if (first < 8) return 10 + first % 80;
    if (timer_getoverrun(t) < first) return 4;
    /* The next signal starts again: its overrun is what came meanwhile. */
    if (t_take(SIGUSR1, &info, 1000) != SIGUSR1) return 5;
    int second = timer_getoverrun(t);
    if (second >= first || second > 4) return 100 + second % 100;
    /* Disarming and setting again forgets the old count. */
    t_nap(40);
    its = t_its(0, 0);
    timer_settime(t, 0, &its, NULL);
    if (timer_getoverrun(t) != 0) return 6;
    return timer_delete(t) ? 7 : 0;
}

static int t_c_burst(void) {
    static const int sigs[8] = {SIGUSR1, SIGUSR2, SIGURG, SIGWINCH, SIGIO, SIGPWR, SIGVTALRM, SIGPROF};
    timer_t timers[8];
    for (int i = 0; i < 8; i++) {
        t_block(sigs[i]);
        struct sigevent e = t_event(sigs[i], 100 + i);
        if (timer_create(CLOCK_MONOTONIC, &e, &timers[i])) return 1;
    }
    /* All eight due at the same instant: the service takes four a step. */
    struct itimerspec its = t_its(t_now(CLOCK_MONOTONIC) + 80 * T_MS, 0);
    for (int i = 0; i < 8; i++)
        if (timer_settime(timers[i], TIMER_ABSTIME, &its, NULL)) return 2;
    for (int i = 0; i < 8; i++) {
        siginfo_t info;
        if (t_take(sigs[i], &info, 3000) != sigs[i]) return 10 + i;
        if (info.si_code != SI_TIMER || info.si_value.sival_int != 100 + i) return 30 + i;
    }
    return 0;
}

static int t_c_least_interval(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = t_plain;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, NULL)) return 1;
    struct sigevent e = t_event(SIGUSR1, 1);
    timer_t t;
    if (timer_create(CLOCK_MONOTONIC, &e, &t)) return 2;
    struct itimerspec its = t_its(T_MS, 1), got;
    if (timer_settime(t, 0, &its, NULL)) return 3;
    if (timer_gettime(t, &got) || got.it_interval.tv_sec || got.it_interval.tv_nsec < 1000) return 4;
    t_got = 0;
    t_nap(200);
    its = t_its(0, 0);
    timer_settime(t, 0, &its, NULL);
    int count = t_got;
    /* One a millisecond at most; a storm of nanoseconds would be thousands. */
    /* A loaded host may run the process late: at least one, and no storm. */
    if (count < 1 || count > 260) return 100 + count % 100;
    return timer_delete(t) ? 5 : 0;
}

static int t_c_alarm(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = t_plain;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGALRM, &sa, NULL)) return 1;
    if (alarm(5) != 0) return 2;
    if (alarm(1) != 5) return 3;
    if (alarm(0) != 1) return 4;
    if (alarm(0) != 0) return 5;
    t_got = 0;
    alarm(1);
    while (!t_got) {
        unsigned left = sleep(5);
        if (!left) break;
    }
    if (t_got != 1) return 6;
    /* A fired alarm leaves nothing. */
    if (alarm(0) != 0) return 7;
    /* A signal that is ignored goes without a trace. */
    signal(SIGALRM, SIG_IGN);
    alarm(1);
    t_nap(1200);
    if (alarm(0) != 0) return 8;
    return 0;
}

static int t_c_alarm_full_table(void) {
    int fds[2];
    if (pipe(fds)) return 1;
    pid_t kids[6];
    struct sigevent e = t_event(SIGUSR1, 1);
    for (int i = 0; i < 6; i++) {
        kids[i] = fork();
        if (kids[i] < 0) return 2;
        if (kids[i] == 0) {
            timer_t t;
            for (int n = 0; n < 32; n++)
                if (timer_create(CLOCK_MONOTONIC, &e, &t)) _exit(10);
            if (write(fds[1], "f", 1) != 1) _exit(11);
            sleep(60);
            _exit(0);
        }
    }
    char c;
    for (int i = 0; i < 6; i++)
        if (read(fds[0], &c, 1) != 1) return 3;
    int result = 0;
    timer_t extra;
    /* The table of 192 places is full ... */
    if (timer_create(CLOCK_MONOTONIC, &e, &extra) != -1 || errno != EAGAIN) result = 4;
    /* ... and the alarm of this process has a place of its own. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = t_plain;
    sigemptyset(&sa.sa_mask);
    if (!result && sigaction(SIGALRM, &sa, NULL)) result = 5;
    t_got = 0;
    if (!result) alarm(1);
    for (int i = 0; !result && !t_got && i < 5; i++) sleep(1);
    if (!result && t_got != 1) result = 6;
    for (int i = 0; i < 6; i++) {
        kill(kids[i], SIGKILL);
        waitpid(kids[i], NULL, 0);
    }
    return result;
}

static int t_c_alarm_kills(void) {
    signal(SIGALRM, SIG_DFL);
    alarm(1);
    pause();
    return 1;
}

static int t_c_itimer(void) {
    t_block(SIGALRM);
    struct itimerval v = {.it_value = {0, 20000}, .it_interval = {0, 20000}}, old, now;
    if (setitimer(ITIMER_REAL, &v, &old)) return 1;
    if (old.it_value.tv_sec || old.it_value.tv_usec) return 2;
    siginfo_t info;
    for (int i = 0; i < 3; i++) {
        if (t_take(SIGALRM, &info, 2000) != SIGALRM) return 3;
        if (info.si_code == SI_USER || info.si_code == SI_QUEUE) return 4;
    }
    if (getitimer(ITIMER_REAL, &now)) return 5;
    if (now.it_interval.tv_sec || now.it_interval.tv_usec != 20000) return 6;
    if (now.it_value.tv_sec || now.it_value.tv_usec <= 0 || now.it_value.tv_usec > 20000) return 7;
    memset(&v, 0, sizeof(v));
    if (setitimer(ITIMER_REAL, &v, &old)) return 8;
    if (old.it_interval.tv_usec != 20000) return 9;
    if (getitimer(ITIMER_REAL, &now) || now.it_value.tv_sec || now.it_value.tv_usec) return 10;
    t_take(SIGALRM, &info, 0);
    t_nap(70);
    if (t_take(SIGALRM, &info, 10) != -1) return 11;
    /* Processor time clocks are not kept. */
    if (setitimer(ITIMER_VIRTUAL, &v, NULL) != -1 || errno != EINVAL) return 12;
    if (setitimer(ITIMER_PROF, &v, NULL) != -1 || errno != EINVAL) return 13;
    if (getitimer(9, &now) != -1 || errno != EINVAL) return 14;
    v.it_value.tv_usec = 1000000;
    if (setitimer(ITIMER_REAL, &v, NULL) != -1 || errno != EINVAL) return 15;
    return 0;
}

static int t_c_sigwaitinfo_alarm(void) {
    t_block(SIGALRM);
    struct itimerval v = {.it_value = {0, 20000}};
    if (setitimer(ITIMER_REAL, &v, NULL)) return 1;
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGALRM);
    siginfo_t info;
    if (sigwaitinfo(&s, &info) != SIGALRM) return 2;
    if (info.si_signo != SIGALRM || info.si_code == SI_USER) return 3;
    return 0;
}

static int t_c_fork(void) {
    struct sigevent e = t_event(SIGUSR1, 1);
    timer_t t;
    if (timer_create(CLOCK_MONOTONIC, &e, &t)) return 1;
    alarm(30);
    pid_t child = fork();
    if (child < 0) return 2;
    if (child == 0) {
        struct itimerspec its;
        if (timer_gettime(t, &its) != -1 || errno != EINVAL) _exit(10);
        if (timer_delete(t) != -1 || errno != EINVAL) _exit(11);
        if (alarm(0) != 0) _exit(12);
        timer_t own;
        if (timer_create(CLOCK_MONOTONIC, &e, &own)) _exit(13);
        _exit(0);
    }
    int status = -1;
    if (waitpid(child, &status, 0) != child) return 3;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return 20 + (WIFEXITED(status) ? WEXITSTATUS(status) : 99) % 70;
    unsigned left = alarm(0);
    if (left < 25 || left > 30) return 4;
    struct itimerspec its;
    if (timer_gettime(t, &its)) return 5;
    return 0;
}

static int t_c_exec(void) {
    struct sigevent e = t_event(SIGUSR1, 1);
    timer_t t;
    if (timer_create(CLOCK_MONOTONIC, &e, &t)) return 1;
    struct itimerspec its = t_its(20000 * T_MS, 0);
    if (timer_settime(t, 0, &its, NULL)) return 2;
    alarm(30);
    char number[32];
    snprintf(number, sizeof(number), "%lu", (unsigned long)t);
    char *next[] = {"procs-child", "timers-exec", number, NULL};
    char *env[] = {NULL};
    execve("/bin/procs-child", next, env);
    return 3;
}
/* The image after the exec of t_c_exec: the timer went, the alarm did not. */
static int timers_exec_role(void) {
    timer_t t = (timer_t)strtoul(argv_seen[2], NULL, 10);
    struct itimerspec its;
    if (timer_gettime(t, &its) != -1 || errno != EINVAL) return 1;
    unsigned left = alarm(0);
    if (left < 25 || left > 30) return 2;
    return 0;
}

static int t_c_exit_gives_back(void) {
    struct sigevent e = t_event(SIGUSR1, 1);
    /* 12 processes with 33 places each are more than the table has. */
    for (int round = 0; round < 12; round++) {
        pid_t child = fork();
        if (child < 0) return 1;
        if (child == 0) {
            timer_t t;
            for (int i = 0; i < 32; i++)
                if (timer_create(CLOCK_MONOTONIC, &e, &t)) _exit(10 + i % 20);
            alarm(60);
            _exit(0);
        }
        int status = -1;
        if (waitpid(child, &status, 0) != child) return 2;
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return 100 + round;
    }
    timer_t t;
    for (int i = 0; i < 32; i++)
        if (timer_create(CLOCK_MONOTONIC, &e, &t)) return 3;
    return 0;
}

static int t_c_clock(void) {
    clock_t a = clock();
    if (a == (clock_t)-1) return 1;
    t_nap(50);
    clock_t b = clock();
    if (b == (clock_t)-1 || b < a + 40000) return 2;
    if (b - a > 5000000) return 3;
    pid_t child = fork();
    if (child < 0) return 4;
    if (child == 0) {
        clock_t c = clock();
        _exit(c != (clock_t)-1 && c < b ? 0 : 1);
    }
    int status = -1;
    if (waitpid(child, &status, 0) != child) return 5;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 6;
}

static int t_c_wait_timer(void) {
    t_block(SIGUSR1);
    struct sigevent e = t_event(SIGUSR1, 31);
    timer_t t;
    if (timer_create(CLOCK_REALTIME, &e, &t)) return 1;
    struct itimerspec its = t_its(20 * T_MS, 0);
    if (timer_settime(t, 0, &its, NULL)) return 2;
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGUSR1);
    siginfo_t info;
    if (sigwaitinfo(&s, &info) != SIGUSR1) return 3;
    if (info.si_code != SI_TIMER || info.si_value.sival_int != 31) return 4;
    its = t_its(20 * T_MS, 0);
    timer_settime(t, 0, &its, NULL);
    if (sigtimedwait(&s, NULL, &(struct timespec){.tv_sec = 2}) != SIGUSR1) return 5;
    return timer_delete(t) ? 6 : 0;
}

static void t_child(const char *what, int (*fn)(void), int code, int sig) {
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        /* The role may run with signals blocked: a case starts with none. */
        sigset_t none;
        sigemptyset(&none);
        sigprocmask(SIG_SETMASK, &none, NULL);
        _exit(fn());
    }
    if (pid < 0) {
        printf("posix-procs: timers: fork for %s gave %d (%s)\n", what, errno, strerror(errno));
        failures++;
        return;
    }
    reap(what, pid, code, sig);
}

static int timers_role(void) {
    t_child("sigqueue reaches a handler with the value", t_c_sigqueue, 0, 0);
    t_child("sigqueue keeps one place a signal", t_c_queue_places, 0, 0);
    t_child("sigqueue to another process", t_c_queue_peer, 0, 0);
    t_child("a timer sends its signal with SI_TIMER and the value", t_c_timer_signal, 0, 0);
    t_child("timer_gettime and timer_settime", t_c_gettime_settime, 0, 0);
    t_child("absolute times, on both clocks and in the past", t_c_absolute, 0, 0);
    t_child("SIGEV_NONE", t_c_none, 0, 0);
    t_child("timer_delete and the limit of timers", t_c_delete, 0, 0);
    t_child("timer_create refuses bad arguments, a null event", t_c_create_errors, 0, 0);
    t_child("timer_getoverrun counts and starts again", t_c_overrun, 0, 0);
    t_child("eight timers due at once", t_c_burst, 0, 0);
    t_child("an interval below the least is raised", t_c_least_interval, 0, 0);
    t_child("alarm", t_c_alarm, 0, 0);
    t_child("the alarm has a place when the table of timers is full", t_c_alarm_full_table, 0, 0);
    t_child("SIGALRM ends a process that does not catch it", t_c_alarm_kills, 0, SIGALRM);
    t_child("setitimer and getitimer", t_c_itimer, 0, 0);
    t_child("sigwaitinfo takes the alarm", t_c_sigwaitinfo_alarm, 0, 0);
    t_child("fork gives no timer and no alarm", t_c_fork, 0, 0);
    t_child("exec keeps the alarm and drops the timers", t_c_exec, 0, 0);
    t_child("the end of a process gives its places back", t_c_exit_gives_back, 0, 0);
    t_child("clock", t_c_clock, 0, 0);
    t_child("sigwaitinfo and sigtimedwait take a timer", t_c_wait_timer, 0, 0);
    if (!failures) printf("posix-procs: timers: sigqueue, timers, alarm, itimer, clock ok\n");
    return failures != 0;
}
#endif
#pragma clang diagnostic pop
