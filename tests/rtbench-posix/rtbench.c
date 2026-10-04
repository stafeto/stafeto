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
 * the call to the first statement of the new image's main. The scenarios
 * of 5d (fork; the role forker, a child that measures its own forks and
 * leaves the samples in /tmp/probe, for the heap it grew and the threads
 * it made are its own): S15 fork from the call to the first statement of
 * the child, with the parent's heap at its start size, at 1 MiB and at
 * 8 MiB; S16 fork, exec of a small file and waitpid, to the return of
 * waitpid; S17 fork from the call to the child's first statement with N
 * other threads that sleep or spin (N = 1, 8, 32, 63): the cost of
 * stopping them (the rows of sleepers count the kernel calls of the
 * process, which grow as the stop's cost does); S18 execve with N spinning other threads, to the first
 * statement of the new image's main. The scenarios of 5e (pipes, through
 * the pipe service; the program is built with -fno-builtin): S19 a byte
 * through two pipes to a child (role echo) and back, one round trip of
 * the pair; S20 1 MiB written in writes of 512 B and of 4 KiB to a child
 * (role sink) that reads to the end, from the first write to the sink's
 * stamp at the end of the file, in nanoseconds a MiB; S22 a forker's
 * `ls /etc | cat` (fork, exec of /bin/ls and /bin/cat, two pipes, the read
 * to the end and two waitpid), from before the first pipe to the last
 * waitpid. The time from a write into an empty pipe to the return of the
 * waiting read is half of a round trip of S19 and has no row of its own.
 * The scenarios of 5e' (the generator of the layer, which serves these with
 * no request to a service; the rows count the kernel calls): S23 and S24
 * one getentropy of 32 and of 256 bytes, S25 one read of 4 KiB of
 * /dev/urandom. S26 master write to echo read; S27 master VINTR write to
 * the foreground reader handler at idle and with busy 25; S28 STOP/CONT
 * of 128 kernel threads to verified wait reports; S29 pipe write to poll.
 * S28 setup and all-worker acknowledgements are outside its intervals.
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

uint64_t rtbench_seconds(void);
uint64_t rtbench_calls(void);
int rtbench_io_init(void);
int rtbench_terminals(int enabled);
int rtbench_threads128(void);
int rtbench_resumed128(void);
int rtbench_native_count(void);
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

/* The rows come in a burst that the console's log ring may not hold: a
 * pause after each lets its driver show the one before. */
static void pace(void) {
    sleep_ns(10 * MS);
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
    pace();
}

static void none(const char *name, const char *why) {
    struct line l = { .length = 0 };
    put(&l, "RTB2 ");
    put(&l, name);
    put(&l, " none ");
    put(&l, why);
    say(&l);
    pace();
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

/* Spawns /bin/rtbench-posix with `argv`. */
static int spawn_argv(pid_t *pid, char **argv, int flags, pid_t group) {
    char *envp[] = { NULL };
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, flags);
    posix_spawnattr_setpgroup(&attr, group);
    int error = posix_spawn(pid, "/bin/rtbench-posix", NULL, &attr, argv, envp);
    posix_spawnattr_destroy(&attr);
    if (error) fail(argv[1], error);
    return error;
}

/* Spawns /bin/rtbench-posix in role `role`. */
static int spawn_child(pid_t *pid, const char *role, int flags, pid_t group) {
    char *argv[] = { "rtbench-posix", (char *)role, NULL };
    return spawn_argv(pid, argv, flags, group);
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

/* --- S15-S18: fork ----------------------------------------------------- */

#define FORK_SAMPLES 10
#define EXEC_SAMPLES 5
/* Where the role forker leaves its samples in /tmp/probe, 8 bytes each:
 * FORK_SAMPLES ticks, then the kernel calls its process made in each. */
#define SAMPLES_AT 64
#define CALLS_AT (SAMPLES_AT + 8 * FORK_SAMPLES)
#define THREAD_COUNTS 4

static const int thread_counts[THREAD_COUNTS] = { 1, 8, 32, 63 };
static struct histogram s15[3], s16, s17[2][THREAD_COUNTS], s18[THREAD_COUNTS];

static void sleep_forever(void);

/* The other threads of a forker: asleep, or running below its level and
 * yielding to each other, as the rows were measured. They run round robin
 * (SCHED_OTHER), so a spinner that never yields lets the stop and the
 * child run too, its quantum over. */
static void *stand_by(void *spin) {
    if (spin) {
        rtbench_level(10);
        for (;;) sched_yield();
    }
    sleep_forever();
    return NULL;
}

static void number_text(char *out, uint64_t value) {
    char digits[24];
    int count = 0;
    do {
        digits[count++] = (char)('0' + value % 10);
        value /= 10;
    } while (value);
    while (count) *out++ = digits[--count];
    *out = 0;
}

/* `ls /etc | cat` as a shell does it: two pipes, a fork and an exec for
 * each stage, the output read to its end here, both stages waited for.
 * FORK_SAMPLES times; the ticks and the kernel calls into /tmp/probe. */
static int pipeline(int fd) {
    for (int i = 0; i < FORK_SAMPLES; i++) {
        uint64_t calls = rtbench_calls();
        uint64_t t0 = ticks();
        int up[2], down[2];
        if (pipe2(up, O_CLOEXEC) || pipe2(down, O_CLOEXEC)) return 10;
        char *envp[] = { NULL };
        pid_t lister = fork();
        if (lister == 0) {
            char *ls[] = { "ls", "/etc", NULL };
            if (dup2(up[1], 1) != 1) _exit(11);
            execve("/bin/ls", ls, envp);
            _exit(12);
        }
        pid_t copier = lister < 0 ? -1 : fork();
        if (copier == 0) {
            char *cat[] = { "cat", NULL };
            if (dup2(up[0], 0) != 0 || dup2(down[1], 1) != 1) _exit(13);
            execve("/bin/cat", cat, envp);
            _exit(14);
        }
        if (lister < 0 || copier < 0) return 15;
        close(up[0]);
        close(up[1]);
        close(down[1]);
        char text[256];
        uint64_t total = 0;
        for (;;) {
            ssize_t n = read(down[0], text, sizeof text);
            if (n < 0) return 16;
            if (n == 0) break;
            total += (uint64_t)n;
        }
        close(down[0]);
        int status = -1;
        if (waitpid(lister, &status, 0) != lister || !WIFEXITED(status) || WEXITSTATUS(status) != 0) return 17;
        if (waitpid(copier, &status, 0) != copier || !WIFEXITED(status) || WEXITSTATUS(status) != 0) return 18;
        uint64_t t1 = ticks();
        uint64_t used = rtbench_calls() - calls;
        if (total == 0) return 19;
        if (put_stamp(fd, SAMPLES_AT + 8 * i, t1 - t0) || put_stamp(fd, CALLS_AT + 8 * i, used)) return 8;
    }
    return 0;
}

/* The role forker MODE KIB THREADS SPIN: grows its heap by KIB KiB, makes
 * THREADS other threads (SPIN: they spin), and then, MODE 0: forks
 * FORK_SAMPLES times and leaves the ticks from the call to the child's
 * first statement; MODE 1: the ticks from the call to the return of
 * waitpid for a child that execs /bin/rtbench-posix `true`; MODE 2:
 * execs `quick` (the parent reads the stamps S14 reads); MODE 3: the ticks
 * of `ls /etc | cat` (S22), the pipeline's output read to its end. */
static int forker(uint64_t entered, char **argv) {
    (void)entered;
    int mode = atoi(argv[2]), spin = atoi(argv[5]), threads = atoi(argv[4]);
    size_t bytes = (size_t)atoi(argv[3]) * 1024;
    int fd = open("/tmp/probe", O_RDWR);
    if (fd < 0) return 2;
    probe_fd = fd;
    if (bytes) {
        volatile char *heap = malloc(bytes);
        if (!heap) return 3;
        for (size_t at = 0; at < bytes; at += 4096) heap[at] = 1;
    }
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 32768);
    for (int i = 0; i < threads; i++) {
        pthread_t thread;
        if (pthread_create(&thread, &attr, stand_by, spin ? (void *)1 : NULL)) return 4;
    }
    /* The threads run once, so that each has its entry of signals. */
    if (threads) sleep_ns((uint64_t)(20 + 2 * threads) * MS);
    if (mode == 2) {
        char *quick[] = { "rtbench-posix", "quick", NULL };
        char *envp[] = { NULL };
        put_stamp(fd, STAMP_EXEC, ticks());
        close(fd);
        execve("/bin/rtbench-posix", quick, envp);
        return 5;
    }
    if (mode == 3) return pipeline(fd);
    for (int i = 0; i < FORK_SAMPLES; i++) {
        uint64_t calls = rtbench_calls();
        uint64_t t0 = ticks();
        pid_t pid = fork();
        if (pid == 0) {
            if (mode == 1) {
                char *quiet[] = { "rtbench-posix", "true", NULL };
                char *envp[] = { NULL };
                execve("/bin/rtbench-posix", quiet, envp);
                _exit(5);
            }
            put_stamp(fd, STAMP_MAIN, ticks());
            _exit(0);
        }
        if (pid < 0) return 6;
        int status = -1;
        if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) return 7;
        uint64_t t1 = ticks();
        uint64_t used = rtbench_calls() - calls;
        uint64_t sample = mode == 1 ? t1 - t0 : get_stamp(STAMP_MAIN) - t0;
        if (put_stamp(fd, SAMPLES_AT + 8 * i, sample) || put_stamp(fd, CALLS_AT + 8 * i, used)) return 8;
    }
    return 0;
}

/* One forker in `mode` with a heap of `kib` and `threads` others, its
 * FORK_SAMPLES into `h`. */
static int run_forker(struct histogram *h, int mode, int kib, int threads, int spin) {
    char text[4][24];
    number_text(text[0], (uint64_t)mode);
    number_text(text[1], (uint64_t)kib);
    number_text(text[2], (uint64_t)threads);
    number_text(text[3], (uint64_t)spin);
    char *argv[] = { "rtbench-posix", "forker", text[0], text[1], text[2], text[3], NULL };
    pid_t pid = -1;
    if (clear_stamps() || spawn_argv(&pid, argv, 0, 0)) return 1;
    int got = reaped(pid, 0, 0, "forker");
    if (got != 1) return 1;
    for (int i = 0; i < FORK_SAMPLES; i++) {
        uint64_t sample = get_stamp(SAMPLES_AT + 8 * i);
        if (!sample) {
            fail("forker sample", i);
            return 1;
        }
        record(h, ticks_ns(sample));
        h->calls += get_stamp(CALLS_AT + 8 * i);
    }
    return 0;
}

/* S18: EXEC_SAMPLES forkers that exec with `threads` spinning others. */
static int exec_with_threads(struct histogram *h, int threads) {
    char text[24];
    number_text(text, (uint64_t)threads);
    for (int i = 0; i < EXEC_SAMPLES; i++) {
        char *argv[] = { "rtbench-posix", "forker", "2", "0", text, "1", NULL };
        pid_t pid = -1;
        if (clear_stamps() || spawn_argv(&pid, argv, 0, 0)) return 1;
        if (await_stamp(STAMP_MAIN, "S18 new image did not start")) return 1;
        uint64_t from = get_stamp(STAMP_EXEC), to = get_stamp(STAMP_MAIN);
        if (from == 0 || to < from) {
            fail("S18 stamps", 0);
            return 1;
        }
        record(h, ticks_ns(to - from));
        if (reaped(pid, 0, 0, "S18 waitpid of the new image") != 1) return 1;
    }
    return 0;
}

static int forks(void) {
    static const int heaps[3] = { 0, 1024, 8192 };
    for (int i = 0; i < 3; i++)
        if (run_forker(&s15[i], 0, heaps[i], 0, 0)) return 1;
    if (run_forker(&s16, 1, 0, 0, 0)) return 1;
    for (int i = 0; i < THREAD_COUNTS; i++)
        if (run_forker(&s17[0][i], 0, 0, thread_counts[i], 0)) return 1;
    for (int i = 0; i < THREAD_COUNTS; i++)
        if (run_forker(&s17[1][i], 0, 0, thread_counts[i], 1)) return 1;
    for (int i = 0; i < THREAD_COUNTS; i++)
        if (exec_with_threads(&s18[i], thread_counts[i])) return 1;
    return 0;
}

/* --- S19, S20, S22: pipes ---------------------------------------------- */

#define PIPE_ROUNDS 1000
#define PIPE_MIB (1024 * 1024)
#define PIPE_TRIALS 3
#define PIPE_SIZES 2

static const size_t pipe_chunks[PIPE_SIZES] = { 512, 4096 };
static struct histogram s19, s20[PIPE_SIZES], s22;
static char pipe_data[4096];

/* Spawns /bin/rtbench-posix in `role` with `in` as its standard input and,
 * when `out` is not -1, `out` as its standard output. */
static int spawn_piped(pid_t *pid, const char *role, int in, int out) {
    char *argv[] = { "rtbench-posix", (char *)role, NULL };
    char *envp[] = { NULL };
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    int error = posix_spawn_file_actions_adddup2(&actions, in, 0);
    if (!error && out >= 0) error = posix_spawn_file_actions_adddup2(&actions, out, 1);
    if (!error) error = posix_spawn(pid, "/bin/rtbench-posix", &actions, NULL, argv, envp);
    posix_spawn_file_actions_destroy(&actions);
    if (error) fail(role, error);
    return error;
}

/* S19: 1000 round trips of one byte through two pipes to the role echo. */
static int pipe_ping_pong(void) {
    int up[2], down[2];
    pid_t pid = -1;
    if (pipe2(up, O_CLOEXEC) || pipe2(down, O_CLOEXEC)) {
        fail("S19 pipe", errno);
        return 1;
    }
    int error = spawn_piped(&pid, "echo", up[0], down[1]);
    close(up[0]);
    close(down[1]);
    if (error) return 1;
    char byte = 'x';
    /* The first round trip waits for the child's start. */
    if (write(up[1], &byte, 1) != 1 || read(down[0], &byte, 1) != 1) {
        fail("S19 first byte", errno);
        return 1;
    }
    uint64_t calls = rtbench_calls();
    for (int i = 0; i < PIPE_ROUNDS; i++) {
        uint64_t t0 = ticks();
        ssize_t sent = write(up[1], &byte, 1);
        ssize_t got = read(down[0], &byte, 1);
        uint64_t t1 = ticks();
        if (sent != 1 || got != 1) {
            fail("S19 byte", errno);
            return 1;
        }
        record(&s19, ticks_ns(t1 - t0));
    }
    s19.calls += rtbench_calls() - calls;
    close(up[1]);
    if (read(down[0], &byte, 1) != 0) {
        fail("S19 end of file", errno);
        return 1;
    }
    close(down[0]);
    return reaped(pid, 0, 0, "S19 echo") == 1 ? 0 : 1;
}

/* S20: PIPE_TRIALS times 1 MiB in writes of `chunk` bytes to the role sink,
 * which says it is ready on its standard output and stamps the end of the
 * file. */
static int pipe_throughput(struct histogram *h, size_t chunk) {
    for (int trial = 0; trial < PIPE_TRIALS; trial++) {
        int data[2], ready[2];
        pid_t pid = -1;
        if (clear_stamps()) return 1;
        if (pipe2(data, O_CLOEXEC) || pipe2(ready, O_CLOEXEC)) {
            fail("S20 pipe", errno);
            return 1;
        }
        int error = spawn_piped(&pid, "sink", data[0], ready[1]);
        close(data[0]);
        close(ready[1]);
        char go = 0;
        if (error || read(ready[0], &go, 1) != 1 || go != 'g') {
            fail("S20 sink", errno);
            return 1;
        }
        close(ready[0]);
        uint64_t t0 = ticks();
        for (size_t sent = 0; sent < PIPE_MIB; sent += chunk) {
            if ((size_t)write(data[1], pipe_data, chunk) != chunk) {
                fail("S20 write", errno);
                return 1;
            }
        }
        close(data[1]);
        if (reaped(pid, 0, 0, "S20 sink") != 1) return 1;
        uint64_t end = get_stamp(STAMP_EXIT);
        if (end <= t0) {
            fail("S20 stamp", 0);
            return 1;
        }
        record(h, ticks_ns(end - t0));
    }
    return 0;
}

static int pipes(void) {
    if (pipe_ping_pong()) return 1;
    for (int i = 0; i < PIPE_SIZES; i++)
        if (pipe_throughput(&s20[i], pipe_chunks[i])) return 1;
    /* S22 is made by a forker (role forker, mode 3), as S16 is. */
    return run_forker(&s22, 3, 0, 0, 0);
}

/* --- S23, S24, S25: the generator ---------------------------------------- */

#define RANDOM_SAMPLES 1000
static struct histogram s23, s24, s25;
/* The bytes the samples drew, folded: a run whose reads gave nothing but
 * zeros fails (the reads are compared, so the compiler keeps them). */
static unsigned char random_fold;

/* One getentropy of `size` bytes, RANDOM_SAMPLES times. */
static int entropy_samples(struct histogram *h, size_t size) {
    unsigned char bytes[256];
    /* The first call asks the entropy service for the key. */
    if (getentropy(bytes, size) != 0) {
        fail("S23, S24 getentropy", errno);
        return 1;
    }
    uint64_t calls = rtbench_calls();
    for (int i = 0; i < RANDOM_SAMPLES; i++) {
        uint64_t t0 = ticks();
        int result = getentropy(bytes, size);
        uint64_t t1 = ticks();
        if (result != 0) {
            fail("S23, S24 getentropy", errno);
            return 1;
        }
        random_fold |= bytes[0] | bytes[size - 1];
        record(h, ticks_ns(t1 - t0));
    }
    h->calls += rtbench_calls() - calls;
    return 0;
}

/* One read of 4096 bytes of /dev/urandom, RANDOM_SAMPLES times. */
static int urandom_samples(struct histogram *h) {
    static unsigned char bytes[4096];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        fail("S25 open", errno);
        return 1;
    }
    uint64_t calls = rtbench_calls();
    for (int i = 0; i < RANDOM_SAMPLES; i++) {
        size_t got = 0;
        uint64_t t0 = ticks();
        while (got < sizeof bytes) {
            ssize_t n = read(fd, bytes + got, sizeof bytes - got);
            if (n <= 0) break;
            got += (size_t)n;
        }
        uint64_t t1 = ticks();
        if (got != sizeof bytes) {
            fail("S25 read", errno);
            return 1;
        }
        random_fold |= bytes[0] | bytes[sizeof bytes - 1];
        record(h, ticks_ns(t1 - t0));
    }
    h->calls += rtbench_calls() - calls;
    close(fd);
    return 0;
}

static int generator(void) {
    if (entropy_samples(&s23, 32) || entropy_samples(&s24, 256) || urandom_samples(&s25))
        return 1;
    if (random_fold == 0) {
        fail("S23 all zero bytes", 0);
        return 1;
    }
    return 0;
}


/* --- S26-S29: PTY and job-control paths ------------------------------- */

static struct histogram s26, s27[2], s28[2], s29;
#define STAMP_REQUEST 40
#define STAMP_ACK 48
#define STAMP_NATIVE 56
#define TTY_SAMPLES 100

static int master_open(char name[32]) {
    int master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0 || grantpt(master) || unlockpt(master) || ptsname_r(master, name, 32)) {
        fail("PTY open/grant/unlock/name", errno);
        if (master >= 0) close(master);
        return -1;
    }
    return master;
}

static int pty_echo(void) {
    char name[32], got, consumed;
    int master = master_open(name);
    if (master < 0) return 1;
    int slave = open(name, O_RDWR | O_NOCTTY);
    struct termios settings;
    if (slave < 0 || tcgetattr(slave, &settings)) { fail("S26 slave", errno); return 1; }
    settings.c_lflag &= ~(ICANON | ISIG | ECHOCTL | ECHONL);
    settings.c_lflag |= ECHO;
    settings.c_oflag = 0;
    settings.c_cc[VMIN] = 1; settings.c_cc[VTIME] = 0;
    if (tcsetattr(slave, TCSANOW, &settings)) { fail("S26 raw echo", errno); return 1; }
    for (int i = 0; i < TTY_SAMPLES; i++) {
        char byte = (char)('a' + i % 26);
        uint64_t began = ticks();
        ssize_t written = write(master, &byte, 1);
        ssize_t readback = written == 1 ? read(master, &got, 1) : -1;
        uint64_t ended = ticks();
        if (written != 1 || readback != 1 || got != byte || read(slave, &consumed, 1) != 1 || consumed != byte) {
            fail("S26 echo byte", errno); return 1;
        }
        record(&s26, ticks_ns(ended - began));
    }
    return close(slave) || close(master);
}

static int pty_interrupt(int spin, struct histogram *histogram) {
    char name[32];
    int master = master_open(name);
    if (master < 0) return 1;
    pid_t pid;
    char *argv[] = {"rtbench-posix", "pty-reader", name, NULL};
    if (clear_stamps() || spawn_argv(&pid, argv, 0, 0) || await_stamp(STAMP_READY, "S27 foreground reader")) return 1;
    struct worker spinner;
    bursts = 0;
    if (spin && start(&spinner, busy, BUSY_LEVEL, NULL)) return 1;
    for (int i = 0; i < 50; i++) {
        if (await_stamp(STAMP_READY, "S27 reader wait")) return 1;
        sleep_ns(1 * MS);
        if (put_stamp(probe_fd, STAMP_READY, 0) || put_stamp(probe_fd, STAMP_HANDLER, 0)) return 1;
        char interrupt = 3;
        uint64_t began = ticks();
        if (write(master, &interrupt, 1) != 1 || await_stamp(STAMP_HANDLER, "S27 handler")) return 1;
        uint64_t ended = get_stamp(STAMP_HANDLER);
        if (ended < began) { fail("S27 handler timestamp", 0); return 1; }
        record(histogram, ticks_ns(ended - began));
    }
    if (spin && finish(&spinner)) return 1;
    if (kill(pid, SIGTERM) || reaped(pid, 0, SIGTERM, "S27 reader exit") != 1) return 1;
    return close(master);
}

static void *thread_slot_probe(void *argument) { return argument; }

static int stop_continue128(void) {
    pid_t pid;
    if (clear_stamps() || spawn_child(&pid, "stop128", 0, 0)
        || await_stamp(STAMP_READY, "S28 native threads readiness")) return 1;
    if (get_stamp(STAMP_READY) != 128) { fail("S28 actual kernel count", 0); return 1; }
    uint64_t natives = get_stamp(STAMP_NATIVE);
    if (natives == 0 || natives >= 128) { fail("S28 native count", 0); return 1; }
    /* A fresh kernel thread elsewhere excludes global thread-pool exhaustion. */
    pthread_t spare;
    int error = pthread_create(&spare, NULL, thread_slot_probe, NULL);
    if (error || (error = pthread_join(spare, NULL))) { fail("S28 global thread slot", error); return 1; }
    struct line ready_line = {.length = 0};
    put(&ready_line, "RTB2 S28 ready kernel_threads=128 native_threads="); put_number(&ready_line, natives);
    put(&ready_line, " existing_threads="); put_number(&ready_line, 128 - natives); say(&ready_line);
    for (int i = 0; i < 20; i++) {
        int status;
        uint64_t began = ticks();
        if (kill(pid, SIGSTOP) || waitpid(pid, &status, WUNTRACED) != pid) {
            fail("S28 STOP wait", errno); return 1;
        }
        if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) { fail("S28 STOP report", status); return 1; }
        uint64_t ended = ticks();
        record(&s28[0], ticks_ns(ended - began));
        began = ticks();
        if (kill(pid, SIGCONT) || waitpid(pid, &status, WCONTINUED) != pid) {
            fail("S28 CONT wait", errno); return 1;
        }
        if (!WIFCONTINUED(status)) { fail("S28 CONT report", status); return 1; }
        ended = ticks();
        record(&s28[1], ticks_ns(ended - began));
        /* Every native worker executes after CONT, outside the sample. */
        if (put_stamp(probe_fd, STAMP_ACK, 0) || put_stamp(probe_fd, STAMP_REQUEST, (uint64_t)i + 1)
            || await_stamp(STAMP_ACK, "S28 all workers after CONT") || get_stamp(STAMP_ACK) != 128) return 1;
    }
    return kill(pid, SIGTERM) || reaped(pid, 0, SIGTERM, "S28 native child exit") != 1;
}

struct poll_sample {
    int fd, request, ready, error;
    uint64_t began;
};
static void *poll_writer(void *argument) {
    struct poll_sample *sample = argument;
    if (rtbench_level(SENDER_LEVEL)) { store(&sample->error, 1); return NULL; }
    store(&sample->ready, 1);
    for (int i = 0; i < TTY_SAMPLES; i++) {
        while (load(&sample->request) < i + 1) {
            int error = rtbench_futex_wait((const uint32_t *)&sample->request, (uint32_t)i);
            if (error && error != EAGAIN && error != EINTR) { store(&sample->error, error); return NULL; }
        }
        uint64_t began = ticks();
        __atomic_store_n(&sample->began, began, __ATOMIC_RELEASE);
        if (write(sample->fd, "p", 1) != 1) {
            store(&sample->error, 1); return NULL;
        }
    }
    return NULL;
}
static int pipe_poll(void) {
    int ends[2];
    if (pipe(ends)) { fail("S29 pipe", errno); return 1; }
    if (fcntl(ends[0], F_SETFL, O_NONBLOCK) || rtbench_level(MAIN_LEVEL)) {
        fail("S29 setup", errno); return 1;
    }
    struct poll_sample sample = {.fd = ends[1]};
    pthread_t writer;
    int error = pthread_create(&writer, NULL, poll_writer, &sample);
    if (error) { fail("S29 thread", error); return 1; }
    uint64_t deadline = now_ns() + 2 * 1000 * MS;
    while (!load(&sample.ready) && !load(&sample.error) && now_ns() < deadline) sleep_ns(100 * US);
    if (!load(&sample.ready)) { fail("S29 writer readiness", load(&sample.error)); return 1; }
    for (int i = 0; i < TTY_SAMPLES; i++) {
        struct pollfd fd = {ends[0], POLLIN, 0};
        /* Main 30 reaches the empty pipe's poll wait before writer 28 runs. */
        store(&sample.request, i + 1);
        rtbench_futex_wake((const uint32_t *)&sample.request, 1);
        int result = poll(&fd, 1, 1000);
        uint64_t returned = ticks();
        uint64_t began = __atomic_load_n(&sample.began, __ATOMIC_ACQUIRE);
        char byte;
        if (result != 1) { fail("S29 poll result", result < 0 ? errno : result); return 1; }
        if (fd.revents != POLLIN) { fail("S29 poll events", fd.revents); return 1; }
        if (read(ends[0], &byte, 1) != 1 || byte != 'p') { fail("S29 consumed byte", errno); return 1; }
        if (load(&sample.error) || !began || returned < began) { fail("S29 poll timestamp", 0); return 1; }
        record(&s29, ticks_ns(returned - began));
    }
    error = pthread_join(writer, NULL);
    return error || close(ends[0]) || close(ends[1]) || rtbench_level(SENDER_LEVEL);
}

static int terminals(void) {
    if (rtbench_terminals(1)) { fail("TTY attach", 0); return 1; }
    /* A real console description is held throughout this attachment. */
    int console = open("/dev/console", O_RDWR | O_NOCTTY);
    if (console < 0) { fail("TTY console description", errno); return 1; }
    int error = pty_echo() || pty_interrupt(0, &s27[0]) || pty_interrupt(1, &s27[1])
        || stop_continue128() || pipe_poll();
    error |= close(console);
    error |= rtbench_terminals(0) != 0;
    return error;
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
    if (!error) error = forks();
    if (!error) error = pipes();
    if (!error) error = terminals();
    error |= rtbench_level(MAIN_LEVEL);
    close(probe_fd);
    return error;
}

/* The children: the program with a role as its first argument. */
static volatile uint64_t handler_at;

/* Keep the counter read at entry, before any compiler-generated address load. */
__attribute__((naked)) static void on_pty_target(int signal __attribute__((unused))) {
    __asm__ volatile("isb\n\tmrs x8, cntvct_el0\n\tadrp x9, handler_at\n\t"
        "add x9, x9, :lo12:handler_at\n\tstr x8, [x9]\n\tret");
}

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

static int child(uint64_t entered, char **argv) {
    const char *role = argv[1];
    if (strcmp(role, "true") == 0) return 0;
    if (strcmp(role, "forker") == 0) return forker(entered, argv);
    if (strcmp(role, "echo") == 0) {
        char byte;
        while (read(0, &byte, 1) == 1)
            if (write(1, &byte, 1) != 1) return 2;
        return 0;
    }
    int fd = open("/tmp/probe", O_RDWR);
    if (fd < 0) return 2;
    if (strcmp(role, "sink") == 0) {
        static char buffer[4096];
        uint64_t total = 0;
        if (write(1, "g", 1) != 1) return 2;
        for (;;) {
            ssize_t n = read(0, buffer, sizeof buffer);
            if (n < 0) return 3;
            if (n == 0) break;
            total += (uint64_t)n;
        }
        if (put_stamp(fd, STAMP_EXIT, ticks())) return 4;
        return total == PIPE_MIB ? 0 : 5;
    }
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

    if (strcmp(role, "pty-reader") == 0) {
        struct sigaction action = { .sa_handler = on_pty_target, .sa_mask = 0, .sa_flags = 0 };
        if (setsid() != getpid() || sigaction(SIGINT, &action, NULL)) return 6;
        int slave = open(argv[2], O_RDWR);
        struct termios settings;
        if (slave < 0 || tcgetattr(slave, &settings)) return 7;
        settings.c_lflag &= ~(ICANON | ECHO | ECHONL);
        settings.c_lflag |= ISIG; settings.c_cc[VINTR] = 3;
        settings.c_cc[VMIN] = 1; settings.c_cc[VTIME] = 0;
        if (tcsetattr(slave, TCSANOW, &settings) || tcsetpgrp(slave, getpgrp()) || tcgetsid(slave) != getpid()) return 8;
        for (;;) {
            if (put_stamp(fd, STAMP_READY, 1)) return 9;
            char byte;
            if (read(slave, &byte, 1) != -1 || errno != EINTR || !handler_at) return 10;
            uint64_t at = handler_at; handler_at = 0;
            if (put_stamp(fd, STAMP_HANDLER, at)) return 11;
        }
    }
    if (strcmp(role, "stop128") == 0) {
        int count = rtbench_threads128();
        if (count != 128) { fail("S28 child population", count); put_stamp(fd, STAMP_READY, UINT64_MAX); return 12; }
        if (put_stamp(fd, STAMP_NATIVE, (uint64_t)rtbench_native_count())
            || put_stamp(fd, STAMP_READY, (uint64_t)count)) return 12;
        uint64_t last = 0;
        for (;;) {
            uint64_t request = 0;
            if (pread(fd, &request, sizeof request, STAMP_REQUEST) != (ssize_t)sizeof request) return 13;
            if (request != last) {
                if (rtbench_resumed128() != 128 || put_stamp(fd, STAMP_ACK, 128)) return 14;
                last = request;
            }
            sleep_ns(1 * MS);
        }
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
            || periodic_sleep() || service_round_trip() || generator() || processes();
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
    row("s15_fork_to_child", &s15[0], 1);
    row("s15_fork_heap_1m", &s15[1], 1);
    row("s15_fork_heap_8m", &s15[2], 1);
    row("s16_fork_exec_waitpid", &s16, 0);
    static const char *const sleepers[THREAD_COUNTS] = {
        "s17_fork_sleepers_1", "s17_fork_sleepers_8", "s17_fork_sleepers_32", "s17_fork_sleepers_63" };
    static const char *const spinners[THREAD_COUNTS] = {
        "s17_fork_spinners_1", "s17_fork_spinners_8", "s17_fork_spinners_32", "s17_fork_spinners_63" };
    static const char *const execs[THREAD_COUNTS] = {
        "s18_exec_spinners_1", "s18_exec_spinners_8", "s18_exec_spinners_32", "s18_exec_spinners_63" };
    for (int i = 0; i < THREAD_COUNTS; i++) row(sleepers[i], &s17[0][i], 1);
    for (int i = 0; i < THREAD_COUNTS; i++) row(spinners[i], &s17[1][i], 0);
    for (int i = 0; i < THREAD_COUNTS; i++) row(execs[i], &s18[i], 0);
    row("s19_pipe_ping_pong", &s19, 1);
    row("s20_pipe_1m_w512", &s20[0], 0);
    row("s20_pipe_1m_w4k", &s20[1], 0);
    row("s22_ls_etc_cat", &s22, 1);
    row("s23_getentropy_32", &s23, 1);
    row("s24_getentropy_256", &s24, 1);
    row("s25_urandom_4k", &s25, 1);
    row("s26_pty_echo_byte", &s26, 0);
    row("s27_pty_ctrl_c_idle", &s27[0], 0);
    row("s27_pty_ctrl_c_busy_25", &s27[1], 0);
    row("s28_stop_threads_128", &s28[0], 0);
    row("s28_cont_threads_128", &s28[1], 0);
    row("s29_pipe_write_to_poll", &s29, 0);
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
    if (argc > 1) return child(entered, argv);
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
    if (rtbench_io_init()) { fail("legacy UART initialization", 0); return 1; }
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
