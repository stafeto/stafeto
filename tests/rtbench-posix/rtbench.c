/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
/*
 * rtbench 2: real-time scenarios of a POSIX program, through pthread and
 * POSIX only, so that the same source runs on the Rust POSIX layer and
 * later on relibc. The platform part (src/main.rs) gives the length of
 * the run, the count of kernel calls, the level of a thread, an empty
 * round trip to a service and the console.
 *
 * The program makes rounds of every scenario until the run's seconds
 * passed (one round without them), then prints a row per scenario:
 *
 *   RTB2 <name> n=N min=A p50=B p99=C max=D [calls=K] h=c0,c1,...
 *
 * and at the end the rounds of the hostile load (tests/rtbench-load).
 *
 * in nanoseconds, where ci counts the samples in [2^i, 2^(i+1)) ns (c0
 * also 0) up to the octave of the maximum; p50 and p99 are the upper ends
 * of buckets 1/32 of an octave wide, min and max are exact; calls counts
 * the kernel calls of the process over the n samples. A scenario this
 * layer has no operation for is a row "RTB2 <name> none <why>".
 *
 * Levels: main starts at 30, the process's ceiling is 31 (the helper
 * threads of the layer). The scenarios (S1-S9 of the design of 5a):
 * S1 a mutex without a rival; S2 futex_wake without waiters; S3 a mutex with rivals at 10, 20 and 30
 * and a thread at 25 that spins 20 ms in every 100 ms; S4 malloc/free of
 * 64 B and 4 KiB and dup/close from threads at 10, 20 and 30; S5 from
 * pthread_kill to the first statement of the handler at a thread at 30
 * that (a) sleeps, (b) waits in read of standard input, (c) sleeps while
 * a thread at 25 runs all the time; S6 from the readiness of the data in
 * the service (its counter) to the return of read; S7 the lateness of
 * clock_nanosleep TIMER_ABSTIME with a period of 1 ms; S8 from futex_wake
 * to the return of the futex_wait of a thread at 30, and futex_wake on a
 * word whose bucket holds a waiter on another word; S9 an empty round
 * trip through the loop of a service. The scenarios of 5b, which need the
 * process service and children from a file (/bin/rtbench-posix, the
 * program itself under a role named by its first argument: target,
 * quick, exiter and wait; the children hand their stamps of the shared
 * counter to the parent through offsets of /tmp/probe): S10 from kill() of another
 * process to the first statement of the handler of its main thread, while
 * the target sleeps and while a thread at 25 runs all the time; S11 a
 * waitpid of a zombie that is ready (one round trip), and from the
 * _exit of a child to the return of waitpid of the parent, which holds
 * one write of the child's stamp (an upper bound); S12 killpg to a group
 * of 32, to the last waitpid of its members; S13 posix_spawn from a file
 * to the first statement of the child's main; S14 execve of a child, from
 * the call to the first statement of the new image's main.
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

uint64_t rtbench_seconds(void);
uint64_t rtbench_calls(void);
uint64_t rtbench_counter_check(void);
int rtbench_level(int level);
int rtbench_ping(void);
void rtbench_say(const char *text, size_t length);
uint64_t rtbench_load_rounds(void);
/* Waits by address of the platform (relibc: Pal::futex_wait, futex_wake). */
int rtbench_futex_wait(const uint32_t *word, uint32_t value);
uint32_t rtbench_futex_wake(const uint32_t *word, uint32_t count);
const uint32_t *rtbench_neighbour(const uint32_t *word, const uint32_t *words, size_t count);

#define MAIN_LEVEL 30
#define SENDER_LEVEL 28
#define BUSY_LEVEL 25
#define MS 1000000ULL
#define US 1000ULL

/* --- time ------------------------------------------------------------ */

static uint64_t hz;

static uint64_t ticks(void) {
    uint64_t value;
    __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(value) :: "memory");
    return value;
}

static uint64_t ticks_ns(uint64_t t) {
    return t / hz * 1000000000ULL + t % hz * 1000000000ULL / hz;
}

static uint64_t now_ns(void) {
    return ticks_ns(ticks());
}

static uint64_t monotonic(void) {
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_nsec;
}

static struct timespec spec(uint64_t ns) {
    struct timespec value = { (time_t)(ns / 1000000000ULL), (long)(ns % 1000000000ULL) };
    return value;
}

static void sleep_until(uint64_t deadline) {
    struct timespec at = spec(deadline);
    while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &at, NULL) == EINTR) {
    }
}

static void sleep_ns(uint64_t ns) {
    sleep_until(monotonic() + ns);
}

static void spin_until(uint64_t deadline) {
    while (now_ns() < deadline) {
    }
}

static int load(const int *p) {
    return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

static void store(int *p, int value) {
    __atomic_store_n(p, value, __ATOMIC_RELEASE);
}

/* --- output ---------------------------------------------------------- */

struct line {
    char text[1024];
    size_t length;
};

static void put(struct line *l, const char *text) {
    while (*text && l->length < sizeof(l->text) - 1) l->text[l->length++] = *text++;
}

static void put_number(struct line *l, uint64_t value) {
    char digits[24];
    int count = 0;
    do {
        digits[count++] = (char)('0' + value % 10);
        value /= 10;
    } while (value);
    while (count && l->length < sizeof(l->text) - 1) l->text[l->length++] = digits[--count];
}

static void say(struct line *l) {
    l->text[l->length++] = '\n';
    rtbench_say(l->text, l->length);
    l->length = 0;
}

static void fail(const char *what, int error) {
    struct line l = { .length = 0 };
    put(&l, "RTB2 FAIL ");
    put(&l, what);
    put(&l, " ");
    put_number(&l, (uint64_t)error);
    say(&l);
}

/* --- histograms ------------------------------------------------------ */

/* 32 buckets of one nanosecond, then 32 buckets in each octave from 32. */
#define SUB 32
#define OCTAVES 40
#define BINS (SUB + (OCTAVES - 5) * SUB)

struct histogram {
    uint64_t n, min, max, calls;
    uint64_t bins[BINS];
};

static int octave(uint64_t value) {
    return value < 2 ? 0 : 63 - __builtin_clzll(value);
}

static int bin(uint64_t value) {
    if (value < SUB) return (int)value;
    int e = octave(value);
    if (e >= OCTAVES) return BINS - 1;
    return SUB + (e - 5) * SUB + (int)((value >> (e - 5)) & (SUB - 1));
}

/* The largest value of bin `index`. */
static uint64_t top(int index) {
    if (index < SUB) return (uint64_t)index;
    int e = (index - SUB) / SUB + 5;
    uint64_t sub = (uint64_t)((index - SUB) % SUB);
    return ((SUB + sub + 1) << (e - 5)) - 1;
}

static void record(struct histogram *h, uint64_t value) {
    if (h->n == 0 || value < h->min) h->min = value;
    if (value > h->max) h->max = value;
    h->n++;
    h->bins[bin(value)]++;
}

static void merge(struct histogram *into, const struct histogram *from) {
    if (!from->n) return;
    if (into->n == 0 || from->min < into->min) into->min = from->min;
    if (from->max > into->max) into->max = from->max;
    into->n += from->n;
    into->calls += from->calls;
    for (int i = 0; i < BINS; i++) into->bins[i] += from->bins[i];
}

static uint64_t percentile(const struct histogram *h, uint64_t percent) {
    uint64_t rank = (h->n * percent + 99) / 100, seen = 0;
    if (rank == 0) rank = 1;
    for (int i = 0; i < BINS; i++) {
        seen += h->bins[i];
        if (seen >= rank) return top(i) < h->max ? top(i) : h->max;
    }
    return h->max;
}

static void row(const char *name, const struct histogram *h, int with_calls) {
    struct line l = { .length = 0 };
    put(&l, "RTB2 ");
    put(&l, name);
    put(&l, " n=");
    put_number(&l, h->n);
    put(&l, " min=");
    put_number(&l, h->min);
    put(&l, " p50=");
    put_number(&l, percentile(h, 50));
    put(&l, " p99=");
    put_number(&l, percentile(h, 99));
    put(&l, " max=");
    put_number(&l, h->max);
    if (with_calls) {
        put(&l, " calls=");
        put_number(&l, h->calls);
    }
    put(&l, " h=");
    uint64_t octaves[64] = { 0 };
    for (int i = 0; i < BINS; i++) octaves[octave(top(i))] += h->bins[i];
    int last = octave(h->max);
    for (int i = 0; i <= last; i++) {
        if (i) put(&l, ",");
        put_number(&l, octaves[i]);
    }
    say(&l);
}

static void none(const char *name, const char *why) {
    struct line l = { .length = 0 };
    put(&l, "RTB2 ");
    put(&l, name);
    put(&l, " none ");
    put(&l, why);
    say(&l);
}

/* --- threads --------------------------------------------------------- */

struct worker {
    pthread_t thread;
    int level;
    int stop;
    struct histogram *h;
};

static int start(struct worker *w, void *(*run)(void *), int level, struct histogram *h) {
    w->level = level;
    w->stop = 0;
    w->h = h;
    int error = pthread_create(&w->thread, NULL, run, w);
    if (error) fail("pthread_create", error);
    return error;
}

static int finish(struct worker *w) {
    store(&w->stop, 1);
    int error = pthread_join(w->thread, NULL);
    if (error) fail("pthread_join", error);
    return error;
}

static int enter(struct worker *w) {
    int error = rtbench_level(w->level);
    if (error) fail("level", error);
    return error;
}

/* A thread that spins 20 ms in every 100 ms (S3), or all the time (S5c). */
static int bursts;

static void *busy(void *argument) {
    struct worker *w = argument;
    if (enter(w)) return NULL;
    while (!load(&w->stop)) {
        if (!bursts) continue;
        spin_until(now_ns() + 20 * MS);
        sleep_ns(80 * MS);
    }
    return NULL;
}

/* --- S1: a mutex without a rival -------------------------------------- */

static struct histogram s1;

static int mutex_alone(void) {
    pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
    uint64_t calls = rtbench_calls();
    for (int i = 0; i < 1000; i++) {
        uint64_t t0 = ticks();
        int error = pthread_mutex_lock(&m);
        if (!error) error = pthread_mutex_unlock(&m);
        uint64_t t1 = ticks();
        if (error) {
            fail("S1 mutex", error);
            return error;
        }
        record(&s1, ticks_ns(t1 - t0));
    }
    s1.calls += rtbench_calls() - calls;
    return pthread_mutex_destroy(&m);
}

/* --- S2: futex_wake without waiters ------------------------------------ */

static struct histogram s2;
static uint32_t idle_word;

static int wake_idle(void) {
    uint64_t calls = rtbench_calls();
    for (int i = 0; i < 1000; i++) {
        uint64_t t0 = ticks();
        uint32_t woken = rtbench_futex_wake(&idle_word, 1);
        uint64_t t1 = ticks();
        if (woken) {
            fail("S2 woke", (int)woken);
            return 1;
        }
        record(&s2, ticks_ns(t1 - t0));
    }
    s2.calls += rtbench_calls() - calls;
    return 0;
}

/* --- S8: the slow path of waits by address ---------------------------- */

static struct histogram s8[2];
static uint32_t s8_words[256];
static uint32_t *s8_word;
static volatile uint64_t s8_returned;
static int s8_returns;

static void *s8_waiter(void *argument) {
    struct worker *w = argument;
    if (enter(w)) return NULL;
    while (!load(&w->stop)) {
        while (__atomic_load_n(s8_word, __ATOMIC_ACQUIRE) == 0)
            rtbench_futex_wait(s8_word, 0);
        s8_returned = ticks();
        __atomic_store_n(s8_word, 0, __ATOMIC_RELEASE);
        __atomic_fetch_add(&s8_returns, 1, __ATOMIC_RELEASE);
    }
    return NULL;
}

static int futex_slow(void) {
    s8_word = &s8_words[0];
    const uint32_t *neighbour = rtbench_neighbour(s8_word, s8_words, 256);
    if (!neighbour) {
        fail("S8 no neighbour", 0);
        return 1;
    }
    struct worker waiter;
    /* The waker is below the waiter, which runs at once when woken. */
    int error = rtbench_level(SENDER_LEVEL);
    if (!error) error = start(&waiter, s8_waiter, MAIN_LEVEL, NULL);
    for (int i = 0; i < 100 && !error; i++) {
        sleep_ns(1 * MS);
        /* The waiter waits on s8_word: a wake of its neighbour scans it. */
        uint64_t calls = rtbench_calls();
        uint64_t t0 = ticks();
        rtbench_futex_wake(neighbour, 1);
        uint64_t t1 = ticks();
        s8[1].calls += rtbench_calls() - calls;
        record(&s8[1], ticks_ns(t1 - t0));
        int before = load(&s8_returns);
        t0 = ticks();
        __atomic_store_n(s8_word, 1, __ATOMIC_RELEASE);
        rtbench_futex_wake(s8_word, 1);
        if (load(&s8_returns) == before) {
            fail("S8 the waiter did not run", 0);
            error = 1;
            break;
        }
        record(&s8[0], ticks_ns(s8_returned - t0));
    }
    store(&waiter.stop, 1);
    __atomic_store_n(s8_word, 1, __ATOMIC_RELEASE);
    rtbench_futex_wake(s8_word, 1);
    error |= finish(&waiter);
    error |= rtbench_level(MAIN_LEVEL);
    return error;
}

/* --- S3: a mutex with rivals at 10, 20 and 30 ------------------------- */

static struct histogram s3[3];
static pthread_mutex_t s3_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t s3_epoch;
#define S3_PERIOD (2 * MS)
#define S3_HOLD (50 * US)

static void *rival(void *argument) {
    struct worker *w = argument;
    if (enter(w)) return NULL;
    /* The lowest wakes first and takes the mutex, the higher ones come
     * while it holds it. */
    uint64_t offset = (uint64_t)(w->level / 10 - 1) * 5 * US;
    uint64_t deadline = s3_epoch;
    while (!load(&w->stop)) {
        deadline += S3_PERIOD;
        sleep_until(deadline + offset);
        uint64_t t0 = ticks();
        int error = pthread_mutex_lock(&s3_mutex);
        uint64_t t1 = ticks();
        if (error) {
            fail("S3 lock", error);
            return NULL;
        }
        record(w->h, ticks_ns(t1 - t0));
        spin_until(now_ns() + S3_HOLD);
        pthread_mutex_unlock(&s3_mutex);
    }
    return NULL;
}

static int mutex_rivals(void) {
    struct worker rivals[3], spinner;
    s3_epoch = monotonic();
    bursts = 1;
    if (start(&spinner, busy, BUSY_LEVEL, NULL)) return 1;
    for (int i = 0; i < 3; i++)
        if (start(&rivals[i], rival, 10 * (i + 1), &s3[i])) return 1;
    sleep_ns(500 * MS);
    int error = 0;
    for (int i = 0; i < 3; i++) error |= finish(&rivals[i]);
    error |= finish(&spinner);
    return error;
}

/* --- S4: heap and descriptor table from three threads ----------------- */

static struct histogram s4[3][3];
static int s4_fd;

static void *sections(void *argument) {
    struct worker *w = argument;
    if (enter(w)) return NULL;
    while (!load(&w->stop)) {
        uint64_t t0 = ticks();
        void *small = malloc(64);
        free(small);
        uint64_t t1 = ticks();
        void *page = malloc(4096);
        free(page);
        uint64_t t2 = ticks();
        int copy = dup(s4_fd);
        int closed = copy < 0 ? -1 : close(copy);
        uint64_t t3 = ticks();
        if (!small || !page || closed) {
            fail("S4 call", errno);
            return NULL;
        }
        record(&w->h[0], ticks_ns(t1 - t0));
        record(&w->h[1], ticks_ns(t2 - t1));
        record(&w->h[2], ticks_ns(t3 - t2));
        sleep_ns(100 * US);
    }
    return NULL;
}

static int heap_and_table(void) {
    struct worker workers[3];
    for (int i = 0; i < 3; i++)
        if (start(&workers[i], sections, 10 * (i + 1), s4[i])) return 1;
    sleep_ns(300 * MS);
    int error = 0;
    for (int i = 0; i < 3; i++) error |= finish(&workers[i]);
    return error;
}

/* --- S5: pthread_kill to the first statement of the handler ----------- */

static struct histogram s5[3];
static volatile uint64_t s5_entered;
static int s5_entries;

static void on_signal(int sig) {
    s5_entered = ticks();
    (void)sig;
    __atomic_fetch_add(&s5_entries, 1, __ATOMIC_RELEASE);
}

enum wait { SLEEP, READ };

struct target {
    struct worker w;
    enum wait wait;
};

static void *target(void *argument) {
    struct target *t = argument;
    if (enter(&t->w)) return NULL;
    while (!load(&t->w.stop)) {
        if (t->wait == SLEEP) {
            struct timespec request = spec(10000 * MS), remaining;
            if (nanosleep(&request, &remaining) == 0) {
                fail("S5 sleep without a signal", 0);
                return NULL;
            }
        } else {
            char byte;
            if (read(0, &byte, 1) >= 0 || errno != EINTR) {
                fail("S5 read without a signal", errno);
                return NULL;
            }
        }
    }
    return NULL;
}

/* Sends SIGUSR1 to the target and waits for its handler; records the time
 * from the call to the handler's first statement in `h` unless null. */
static int kill_one(struct target *t, struct histogram *h) {
    int before = load(&s5_entries);
    uint64_t t0 = ticks();
    int error = pthread_kill(t->w.thread, SIGUSR1);
    if (error) {
        fail("pthread_kill", error);
        return error;
    }
    uint64_t limit = now_ns() + 1000 * MS;
    while (load(&s5_entries) == before) {
        if (now_ns() > limit) {
            fail("S5 handler did not run", 0);
            return 1;
        }
    }
    if (h) record(h, ticks_ns(s5_entered - t0));
    return 0;
}

static int signal_scenario(enum wait wait, int spin, struct histogram *h) {
    struct target t = { .wait = wait };
    struct worker spinner;
    bursts = 0;
    if (spin && start(&spinner, busy, BUSY_LEVEL, NULL)) return 1;
    if (start(&t.w, target, MAIN_LEVEL, NULL)) return 1;
    int error = 0;
    for (int i = 0; i < 100 && !error; i++) {
        /* The target, above, waits again before the sender runs. */
        sleep_ns(1 * MS);
        error = kill_one(&t, h);
    }
    store(&t.w.stop, 1);
    sleep_ns(1 * MS);
    error |= kill_one(&t, NULL);
    error |= finish(&t.w);
    if (spin) error |= finish(&spinner);
    return error;
}

static int signals(void) {
    struct sigaction action = { .sa_handler = on_signal, .sa_mask = 0, .sa_flags = 0 };
    if (sigaction(SIGUSR1, &action, NULL)) {
        fail("sigaction", errno);
        return 1;
    }
    /* The sender is below the target and above the busy thread. */
    int error = rtbench_level(SENDER_LEVEL);
    if (!error) error = signal_scenario(SLEEP, 0, &s5[0]);
    if (!error) error = signal_scenario(READ, 0, &s5[1]);
    if (!error) error = signal_scenario(SLEEP, 1, &s5[2]);
    error |= rtbench_level(MAIN_LEVEL);
    return error;
}

/* --- S6: from the readiness of the data to the return of read --------- */

static struct histogram s6;

static int read_ready(void) {
    for (int i = 0; i < 100; i++) {
        char digits[16];
        ssize_t got = read(0, digits, sizeof(digits));
        uint64_t t1 = ticks();
        if (got != (ssize_t)sizeof(digits)) {
            fail("S6 read", got < 0 ? errno : 0);
            return 1;
        }
        uint64_t stamp = 0;
        for (int d = 0; d < 16; d++) {
            char c = digits[d];
            stamp = stamp << 4 | (uint64_t)(c <= '9' ? c - '0' : c - 'a' + 10);
        }
        record(&s6, ticks_ns(t1 - stamp));
    }
    return 0;
}

/* --- S7: clock_nanosleep TIMER_ABSTIME, 1 ms -------------------------- */

static struct histogram s7;
static uint64_t s7_missed;

static int periodic_sleep(void) {
    uint64_t deadline = monotonic();
    for (int i = 0; i < 200; i++) {
        deadline += 1 * MS;
        struct timespec at = spec(deadline);
        int error = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &at, NULL);
        uint64_t now = monotonic();
        if (error) {
            fail("S7 clock_nanosleep", error);
            return error;
        }
        uint64_t late = now > deadline ? now - deadline : 0;
        record(&s7, late);
        s7_missed += late / MS;
        deadline += late / MS * MS;
    }
    return 0;
}

/* --- S9: an empty round trip through the loop of a service ------------ */

static struct histogram s9;

static int service_round_trip(void) {
    uint64_t calls = rtbench_calls();
    for (int i = 0; i < 1000; i++) {
        uint64_t t0 = ticks();
        int error = rtbench_ping();
        uint64_t t1 = ticks();
        if (error) {
            fail("S9 ping", 0);
            return 1;
        }
        record(&s9, ticks_ns(t1 - t0));
    }
    s9.calls += rtbench_calls() - calls;
    return 0;
}

/* --- S10-S13: children from a file ------------------------------------ */

#define STAMP_HANDLER 0
#define STAMP_READY 8
#define STAMP_MAIN 16
#define STAMP_EXEC 24
#define STAMP_EXIT 32
#define GROUP 32

static struct histogram s10[2], s11[2], s12, s13, s14;
static int probe_fd = -1;

static int put_stamp(int fd, off_t offset, uint64_t value) {
    if (lseek(fd, offset, SEEK_SET) < 0) return -1;
    return write(fd, &value, sizeof value) == (ssize_t)sizeof value ? 0 : -1;
}

static uint64_t get_stamp(off_t offset) {
    uint64_t value = 0;
    if (lseek(probe_fd, offset, SEEK_SET) < 0 || read(probe_fd, &value, sizeof value) != (ssize_t)sizeof value)
        return 0;
    return value;
}

static int clear_stamps(void) {
    for (off_t offset = 0; offset < 64; offset += 8)
        if (put_stamp(probe_fd, offset, 0)) {
            fail("clear stamps", errno);
            return 1;
        }
    return 0;
}

/* Spawns /bin/rtbench-posix in role `role`. */
static int spawn_child(pid_t *pid, const char *role, int flags, pid_t group) {
    char *argv[] = { "rtbench-posix", (char *)role, NULL };
    char *envp[] = { NULL };
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, flags);
    posix_spawnattr_setpgroup(&attr, group);
    int error = posix_spawn(pid, "/bin/rtbench-posix", NULL, &attr, argv, envp);
    posix_spawnattr_destroy(&attr);
    if (error) fail(role, error);
    return error;
}

/* The status of `pid` has to be exit 0 (`signal` 0) or that signal. */
static int reaped(pid_t pid, int options, int signal, const char *what) {
    int status = -1;
    pid_t got = waitpid(pid, &status, options);
    if (got == 0) return 0;
    int good = got > 0 && (signal ? WIFSIGNALED(status) && WTERMSIG(status) == signal
                                  : WIFEXITED(status) && WEXITSTATUS(status) == 0);
    if (!good) {
        fail(what, got < 0 ? errno : status);
        return -1;
    }
    return 1;
}

/* Waits until the stamp at `offset` is not 0 (at most 2 s): 0 when it is. */
static int await_stamp(off_t offset, const char *what) {
    uint64_t limit = now_ns() + 2000 * MS;
    while (!get_stamp(offset)) {
        if (now_ns() > limit) {
            fail(what, 0);
            return 1;
        }
        sleep_ns(1 * MS);
    }
    return 0;
}

/* S10: 50 SIGUSR1 to the child of rtbench-target, 5 ms apart. */
static int kill_process(int spin, struct histogram *h) {
    struct worker spinner;
    pid_t pid = -1;
    bursts = 0;
    int error = clear_stamps() || spawn_child(&pid, "target", 0, 0)
            || await_stamp(STAMP_READY, "S10 target did not start");
    if (error) return 1;
    if (spin && start(&spinner, busy, BUSY_LEVEL, NULL)) return 1;
    for (int i = 0; i < 50 && !error; i++) {
        sleep_ns(2 * MS);
        put_stamp(probe_fd, STAMP_HANDLER, 0);
        uint64_t t0 = ticks();
        if (kill(pid, SIGUSR1)) {
            fail("S10 kill", errno);
            error = 1;
            break;
        }
        sleep_ns(3 * MS);
        uint64_t at = get_stamp(STAMP_HANDLER);
        if (at < t0) {
            fail("S10 handler did not run", 0);
            error = 1;
        } else {
            record(h, ticks_ns(at - t0));
        }
    }
    if (spin) error |= finish(&spinner);
    if (kill(pid, SIGTERM)) error = 1;
    return error | (reaped(pid, 0, SIGTERM, "S10 target after SIGTERM") != 1);
}

/* S13 and the first half of S11: 20 children that stamp their main and end. */
static int spawn_and_wait(void) {
    for (int i = 0; i < 20; i++) {
        pid_t pid = -1;
        if (clear_stamps()) return 1;
        uint64_t t0 = ticks();
        if (spawn_child(&pid, "quick", 0, 0)) return 1;
        if (await_stamp(STAMP_MAIN, "S13 child did not start")) return 1;
        record(&s13, ticks_ns(get_stamp(STAMP_MAIN) - t0));
        for (int tries = 0;; tries++) {
            uint64_t t1 = ticks();
            int got = reaped(pid, WNOHANG, 0, "S11 waitpid");
            uint64_t t2 = ticks();
            if (got < 0) return 1;
            if (got) {
                record(&s11[0], ticks_ns(t2 - t1));
                break;
            }
            if (tries > 200) {
                fail("S11 zombie not ready", 0);
                return 1;
            }
            sleep_ns(5 * MS);
        }
    }
    return 0;
}

/* S14: 20 children that stamp the clock, then exec the quick role. */
static int exec_to_main(void) {
    for (int i = 0; i < 20; i++) {
        pid_t pid = -1;
        if (clear_stamps() || spawn_child(&pid, "execer", 0, 0)) return 1;
        if (await_stamp(STAMP_MAIN, "S14 new image did not start")) return 1;
        uint64_t from = get_stamp(STAMP_EXEC), to = get_stamp(STAMP_MAIN);
        if (from == 0 || to < from) {
            fail("S14 stamps", 0);
            return 1;
        }
        record(&s14, ticks_ns(to - from));
        if (reaped(pid, 0, 0, "S14 waitpid of the new image") != 1) return 1;
    }
    return 0;
}

/* S11, the second half: from the stamp before the child's _exit to waitpid. */
static int exit_to_wait(void) {
    for (int i = 0; i < 20; i++) {
        pid_t pid = -1;
        if (clear_stamps() || spawn_child(&pid, "exiter", 0, 0)) return 1;
        int got = reaped(pid, 0, 0, "S11 waitpid of the exiter");
        uint64_t t1 = ticks();
        uint64_t stamp = get_stamp(STAMP_EXIT);
        if (got != 1 || stamp == 0 || stamp > t1) {
            fail("S11 exit stamp", 0);
            return 1;
        }
        record(&s11[1], ticks_ns(t1 - stamp));
    }
    return 0;
}

/* S12: killpg to a group of GROUP children, until the last waitpid. */
static int kill_group(void) {
    pid_t pids[GROUP];
    for (int round = 0; round < 5; round++) {
        for (int i = 0; i < GROUP; i++)
            if (spawn_child(&pids[i], i ? "wait" : "target", POSIX_SPAWN_SETPGROUP, i ? pids[0] : 0)) return 1;
        sleep_ns(100 * MS);
        uint64_t t0 = ticks();
        if (killpg(pids[0], SIGTERM)) {
            fail("S12 killpg", errno);
            return 1;
        }
        for (int i = 0; i < GROUP; i++) {
            int status = -1;
            pid_t got = waitpid(-pids[0], &status, 0);
            if (got <= 0 || !WIFSIGNALED(status) || WTERMSIG(status) != SIGTERM) {
                fail("S12 waitpid of a member", got < 0 ? errno : status);
                return 1;
            }
        }
        record(&s12, ticks_ns(ticks() - t0));
    }
    return 0;
}

static int processes(void) {
    probe_fd = open("/tmp/probe", O_RDWR);
    if (probe_fd < 0) {
        fail("open /tmp/probe", errno);
        return 1;
    }
    int error = rtbench_level(SENDER_LEVEL);
    if (!error) error = kill_process(0, &s10[0]);
    if (!error) error = kill_process(1, &s10[1]);
    if (!error) error = spawn_and_wait();
    if (!error) error = exec_to_main();
    if (!error) error = exit_to_wait();
    if (!error) error = kill_group();
    error |= rtbench_level(MAIN_LEVEL);
    close(probe_fd);
    return error;
}

/* The children: the program with a role as its first argument. */
static volatile uint64_t handler_at;

static void on_target(int signal) {
    handler_at = ticks();
    (void)signal;
}

static void sleep_forever(void) {
    for (;;) {
        struct timespec request = spec(10000 * MS), remaining;
        nanosleep(&request, &remaining);
    }
}

static int child(uint64_t entered, const char *role) {
    int fd = open("/tmp/probe", O_WRONLY);
    if (fd < 0) return 2;
    if (strcmp(role, "quick") == 0) return put_stamp(fd, STAMP_MAIN, entered) ? 3 : 0;
    if (strcmp(role, "execer") == 0) {
        char *argv[] = { "rtbench-posix", "quick", NULL };
        char *envp[] = { NULL };
        put_stamp(fd, STAMP_EXEC, ticks());
        close(fd);
        execve("/bin/rtbench-posix", argv, envp);
        return 5;
    }
    if (strcmp(role, "exiter") == 0) {
        put_stamp(fd, STAMP_EXIT, ticks());
        _exit(0);
    }
    if (strcmp(role, "target") == 0) {
        struct sigaction action = { .sa_handler = on_target, .sa_mask = 0, .sa_flags = 0 };
        if (sigaction(SIGUSR1, &action, NULL) || put_stamp(fd, STAMP_READY, 1)) return 4;
        for (;;) {
            struct timespec request = spec(10000 * MS), remaining;
            nanosleep(&request, &remaining);
            uint64_t at = handler_at;
            if (at) {
                handler_at = 0;
                put_stamp(fd, STAMP_HANDLER, at);
            }
        }
    }
    sleep_forever();
    return 0;
}

/* --- the run ---------------------------------------------------------- */

static int one_round(void) {
    return mutex_alone() || wake_idle() || futex_slow() || mutex_rivals() || heap_and_table() || signals() || read_ready()
            || periodic_sleep() || service_round_trip() || processes();
}

static void report(void) {
    row("s1_mutex_alone", &s1, 1);
    row("s2_futex_wake_idle", &s2, 1);
    row("s3_mutex_rival_10", &s3[0], 0);
    row("s3_mutex_rival_20", &s3[1], 0);
    row("s3_mutex_rival_30", &s3[2], 0);
    static const char *const s4_names[3] = {
        "s4_malloc_free_64", "s4_malloc_free_4k", "s4_dup_close" };
    static struct histogram all[3];
    for (int op = 0; op < 3; op++) {
        for (int i = 0; i < 3; i++) merge(&all[op], &s4[i][op]);
        row(s4_names[op], &all[op], 0);
    }
    row("s5_kill_sleeping", &s5[0], 0);
    row("s5_kill_reading", &s5[1], 0);
    row("s5_kill_busy_25", &s5[2], 0);
    row("s6_read_ready", &s6, 0);
    row("s7_sleep_abs_1ms", &s7, 0);
    row("s8_futex_pair", &s8[0], 0);
    row("s8_futex_bucket_neighbour", &s8[1], 1);
    row("s9_service_round_trip", &s9, 1);
    row("s10_kill_process_sleeping", &s10[0], 0);
    row("s10_kill_process_busy_25", &s10[1], 0);
    row("s11_waitpid_zombie", &s11[0], 0);
    row("s11_exit_to_waitpid", &s11[1], 0);
    row("s12_killpg_group_32", &s12, 0);
    row("s13_spawn_to_main", &s13, 0);
    row("s14_exec_to_main", &s14, 0);
    none("fork_exec_waitpid", "fork comes with 5d");
    none("timer_1ms", "POSIX timers come with 5h");
    none("inheritance_chain", "priority inheritance comes with 5h");
    struct line l = { .length = 0 };
    put(&l, "RTB2 s7_missed ");
    put_number(&l, s7_missed);
    say(&l);
    put(&l, "RTB2 load_rounds ");
    put_number(&l, rtbench_load_rounds());
    say(&l);
}

int main(int argc, char **argv) {
    uint64_t entered = ticks();
    if (argc > 1) return child(entered, argv[1]);
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(hz));
    struct line l = { .length = 0 };
    uint64_t seconds = rtbench_seconds();
    put(&l, "RTB2 START hz=");
    put_number(&l, hz);
    put(&l, " seconds=");
    put_number(&l, seconds);
    say(&l);
    put(&l, "RTB2 calls yield=");
    put_number(&l, rtbench_counter_check());
    say(&l);
    s4_fd = open("/etc/motd", O_RDONLY);
    if (s4_fd < 0) {
        fail("open", errno);
        return 1;
    }
    if (rtbench_level(MAIN_LEVEL)) return 1;
    uint64_t begin = now_ns(), rounds = 0;
    do {
        if (one_round()) return 1;
        rounds++;
        put(&l, "RTB2 round ");
        put_number(&l, rounds);
        say(&l);
    } while (now_ns() - begin < seconds * 1000000000ULL);
    report();
    put(&l, "RTB2 DONE rounds=");
    put_number(&l, rounds);
    say(&l);
    return 0;
}
