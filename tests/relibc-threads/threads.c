/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* pthreads of relibc over the Rust POSIX layer: creation and join of a
 * full table three times, the end of joinable and detached threads under
 * signals, mutex, condition, rwlock, semaphore and barrier on four
 * threads, one waiter woken per unlock by level, deferred cancellation at
 * its points, siglongjmp out of a handler and out of sigwait, threads
 * detached after their end, and the clock service's page. */
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* From the program's Rust side (src/main.rs). */
int relibc_threads_places(void);
void relibc_threads_collect(void);
unsigned long relibc_threads_heap(void);
int relibc_threads_set_level(int level);
long relibc_threads_realtime(long *seconds, long *nanos);
unsigned long relibc_threads_calls(void);
unsigned long relibc_threads_cancel_window(void);
int relibc_threads_ended(pthread_t thread);

#define FAIL(...) do { printf("relibc-threads: " __VA_ARGS__); printf("\n"); exit(10 + __LINE__ % 80); } while (0)
#define CHECK(cond) do { if (!(cond)) FAIL("check failed at line %d: %s", __LINE__, #cond); } while (0)

static pthread_attr_t small;

static void sleep_ms(long ms) {
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000L};
    while (nanosleep(&t, &t) != 0 && errno == EINTR) {}
}

/* A watchdog: ends the process if a stage hangs. */
static volatile int stage;
static void *watchdog(void *arg) {
    (void)arg;
    int last = -1;
    for (;;) {
        sleep_ms(20000);
        if (stage == last) {
            printf("relibc-threads: watchdog: stage %d hangs\n", stage);
            exit(9);
        }
        last = stage;
    }
    return NULL;
}

/* A: the whole table, three times. */
static void *returns(void *arg) { return arg; }
static void table_rounds(void) {
    enum { THREADS = 63 };
    pthread_t threads[THREADS];
    unsigned long heap = 0;
    for (int round = 0; round < 3; round++) {
        /* The watchdog holds one place: 62 more fill the table. */
        int count = THREADS - 1;
        for (int i = 0; i < count; i++) {
            int status = pthread_create(&threads[i], &small, returns, (void *)(long)(i + 1));
            if (status) FAIL("round %d: create %d: %d", round, i, status);
        }
        pthread_t extra;
        CHECK(pthread_create(&extra, &small, returns, NULL) == EAGAIN);
        for (int i = 0; i < count; i++) {
            void *value;
            CHECK(pthread_join(threads[i], &value) == 0);
            CHECK(value == (void *)(long)(i + 1));
        }
        sleep_ms(20);
        relibc_threads_collect();
        CHECK(relibc_threads_places() == 2);
        if (round == 0) heap = relibc_threads_heap();
        else CHECK(relibc_threads_heap() == heap);
    }
    printf("relibc-threads: table of 64 filled and emptied 3 times, heap %lu\n", heap);
}

/* B: threads end while signals come; a joiner reads a TCB that is not freed. */
static volatile int usr1;
static void count_usr1(int signal) { (void)signal; usr1++; }
static volatile int ending, stop;
/* Runs until told to stop, letting the sender run (one level, FIFO). */
static void *ends_soon(void *arg) {
    while (!stop) sched_yield();
    ending = 1;
    return arg;
}
static void exits_under_signals(void) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = count_usr1;
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
    for (int round = 0; round < 20; round++) {
        pthread_t thread;
        ending = stop = 0;
        CHECK(pthread_create(&thread, &small, ends_soon, (void *)42L) == 0);
        for (int i = 0; i < 20; i++) {
            CHECK(pthread_kill(thread, SIGUSR1) == 0);
            sched_yield();
        }
        /* It leaves while signals keep coming, until its joiner has it. */
        stop = 1;
        while (!ending) {
            CHECK(pthread_kill(thread, SIGUSR1) == 0);
            sched_yield();
        }
        for (int i = 0; i < 50; i++) {
            CHECK(pthread_kill(thread, SIGUSR1) == 0);
            sched_yield();
        }
        void *value;
        CHECK(pthread_join(thread, &value) == 0 && value == (void *)42L);
        ending = stop = 0;
        CHECK(pthread_create(&thread, &small, ends_soon, NULL) == 0);
        CHECK(pthread_detach(thread) == 0);
        for (int i = 0; i < 20; i++) {
            CHECK(pthread_kill(thread, SIGUSR1) == 0);
            sched_yield();
        }
        stop = 1;
        while (!ending) {
            CHECK(pthread_kill(thread, SIGUSR1) == 0);
            sched_yield();
        }
        for (int i = 0; i < 50; i++) {
            CHECK(pthread_kill(thread, SIGUSR1) == 0);
            sched_yield();
        }
    }
    /* A thread that ended and is not joined keeps its TCB while another
     * thread is made (which collects ended threads). */
    pthread_t first, second;
    CHECK(pthread_create(&first, &small, returns, (void *)77L) == 0);
    sleep_ms(20);
    CHECK(pthread_create(&second, &small, returns, (void *)78L) == 0);
    sleep_ms(20);
    pthread_t third;
    CHECK(pthread_create(&third, &small, returns, (void *)79L) == 0);
    void *value;
    CHECK(pthread_join(first, &value) == 0);
    if (value != (void *)77L) FAIL("joined a freed TCB: value %p", value);
    CHECK(pthread_join(second, &value) == 0 && value == (void *)78L);
    CHECK(pthread_join(third, &value) == 0 && value == (void *)79L);
    CHECK(usr1 >= 20 * 2 * 20);
    printf("relibc-threads: joinable and detached threads end under signals, %d handled\n", usr1);
}

/* C: the objects of synchronization on four threads. */
enum { WORKERS = 4, TURNS = 25000 };
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static pthread_rwlock_t table_lock = PTHREAD_RWLOCK_INITIALIZER;
static pthread_barrier_t barrier;
static sem_t tokens;
static long counter, readers_saw, produced, consumed, sem_total;
static void *worker(void *arg) {
    long me = (long)arg;
    for (int i = 0; i < TURNS; i++) {
        pthread_mutex_lock(&lock);
        counter++;
        pthread_mutex_unlock(&lock);
        if (i % 4 == 0) {
            pthread_rwlock_wrlock(&table_lock);
            readers_saw++;
            pthread_rwlock_unlock(&table_lock);
        } else {
            pthread_rwlock_rdlock(&table_lock);
            pthread_rwlock_unlock(&table_lock);
        }
        sem_post(&tokens);
        sem_wait(&tokens);
        __atomic_fetch_add(&sem_total, 1, __ATOMIC_SEQ_CST);
    }
    /* Producer and consumers on one condition. */
    if (me == 0) {
        for (int i = 0; i < 3 * 1000; i++) {
            pthread_mutex_lock(&lock);
            produced++;
            pthread_cond_signal(&changed);
            pthread_mutex_unlock(&lock);
        }
    } else {
        for (int i = 0; i < 1000; i++) {
            pthread_mutex_lock(&lock);
            while (produced == 0) pthread_cond_wait(&changed, &lock);
            produced--;
            consumed++;
            pthread_mutex_unlock(&lock);
        }
    }
    for (int i = 0; i < 100; i++) pthread_barrier_wait(&barrier);
    return NULL;
}
static void synchronization(void) {
    CHECK(pthread_barrier_init(&barrier, NULL, WORKERS) == 0);
    CHECK(sem_init(&tokens, 0, 0) == 0);
    pthread_t threads[WORKERS];
    for (long i = 0; i < WORKERS; i++)
        CHECK(pthread_create(&threads[i], &small, worker, (void *)i) == 0);
    for (int i = 0; i < WORKERS; i++) CHECK(pthread_join(threads[i], NULL) == 0);
    CHECK(counter == WORKERS * TURNS);
    CHECK(readers_saw == WORKERS * TURNS / 4);
    CHECK(sem_total == WORKERS * TURNS);
    CHECK(consumed == 3 * 1000 && produced == 0);
    printf("relibc-threads: mutex, rwlock, semaphore, condition, barrier on %d threads, %d turns\n",
           WORKERS, TURNS);
}

/* D: three waiters at levels 10, 20, 30; each unlock wakes one. */
static pthread_mutex_t contended = PTHREAD_MUTEX_INITIALIZER;
static int order[3], taken;
static volatile int waiting;
static void *waiter(void *arg) {
    int level = (int)(long)arg;
    CHECK(relibc_threads_set_level(level) == 0);
    __atomic_fetch_add(&waiting, 1, __ATOMIC_SEQ_CST);
    pthread_mutex_lock(&contended);
    order[taken++] = level;
    pthread_mutex_unlock(&contended);
    return NULL;
}
static void wake_order(void) {
    pthread_mutex_lock(&contended);
    pthread_t threads[3];
    int levels[3] = {10, 30, 20};
    for (int i = 0; i < 3; i++)
        CHECK(pthread_create(&threads[i], &small, waiter, (void *)(long)levels[i]) == 0);
    while (waiting < 3) sleep_ms(5);
    sleep_ms(20);
    pthread_mutex_unlock(&contended);
    for (int i = 0; i < 3; i++) CHECK(pthread_join(threads[i], NULL) == 0);
    if (order[0] != 30 || order[1] != 20 || order[2] != 10)
        FAIL("wake order %d %d %d", order[0], order[1], order[2]);
    printf("relibc-threads: unlocks woke 30, 20, 10\n");
}

/* E: deferred cancellation at points, with cleanup handlers. */
static volatile int cleaned, started;
static pthread_mutex_t cancel_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t never = PTHREAD_COND_INITIALIZER;
static sem_t empty;
static void unlock_cleanup(void *arg) {
    /* The mutex is held again when a condition wait is cancelled. */
    CHECK(pthread_mutex_unlock((pthread_mutex_t *)arg) == 0);
    cleaned++;
}
static void plain_cleanup(void *arg) { (void)arg; cleaned++; }
static void *in_cond(void *arg) {
    (void)arg;
    pthread_mutex_lock(&cancel_lock);
    pthread_cleanup_push(unlock_cleanup, &cancel_lock);
    started = 1;
    for (;;) pthread_cond_wait(&never, &cancel_lock);
    pthread_cleanup_pop(0);
    return NULL;
}
static void *in_sem(void *arg) {
    (void)arg;
    pthread_cleanup_push(plain_cleanup, NULL);
    started = 1;
    for (;;) sem_wait(&empty);
    pthread_cleanup_pop(0);
    return NULL;
}
static void *in_sleep(void *arg) {
    (void)arg;
    pthread_cleanup_push(plain_cleanup, NULL);
    started = 1;
    struct timespec t = {100, 0};
    nanosleep(&t, NULL);
    pthread_cleanup_pop(0);
    return NULL;
}
static volatile long counted;
static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
/* Takes the gate (no cancellation point), counts, then reaches a point. */
static void *counts(void *arg) {
    (void)arg;
    pthread_mutex_lock(&gate);
    for (long i = 0; i < 3000000; i++) counted++;
    pthread_mutex_unlock(&gate);
    pthread_testcancel();
    return (void *)1L;
}
static void cancel_one(void *(*body)(void *), const char *what) {
    pthread_t thread;
    started = 0;
    int before = cleaned;
    CHECK(pthread_create(&thread, &small, body, NULL) == 0);
    while (!started) sleep_ms(1);
    sleep_ms(10);
    CHECK(pthread_cancel(thread) == 0);
    void *value;
    CHECK(pthread_join(thread, &value) == 0);
    if (value != PTHREAD_CANCELED || cleaned != before + 1)
        FAIL("cancel in %s: value %p, cleanups %d", what, value, cleaned - before);
}
static void cancellation(void) {
    CHECK(sem_init(&empty, 0, 0) == 0);
    cancel_one(in_cond, "pthread_cond_wait");
    CHECK(pthread_mutex_trylock(&cancel_lock) == 0);
    pthread_mutex_unlock(&cancel_lock);
    cancel_one(in_sem, "sem_wait");
    cancel_one(in_sleep, "nanosleep");
    pthread_t thread;
    pthread_mutex_lock(&gate);
    CHECK(pthread_create(&thread, &small, counts, NULL) == 0);
    sleep_ms(10);
    CHECK(pthread_cancel(thread) == 0);
    pthread_mutex_unlock(&gate);
    void *value;
    CHECK(pthread_join(thread, &value) == 0);
    if (value != PTHREAD_CANCELED || counted != 3000000)
        FAIL("counting thread: value %p, counted %ld", value, counted);
    printf("relibc-threads: cancelled in pthread_cond_wait, sem_wait, nanosleep; counting thread at its point\n");
}

/* F: siglongjmp out of a handler, then the signals and the layer go on. */
static sigjmp_buf back;
static volatile int jumped, handled;
static void jump_out(int signal) { (void)signal; siglongjmp(back, 1); }
static void count_handler(int signal) { (void)signal; handled++; }
static pthread_t main_thread;
/* Sends SIGUSR2 to the main thread `arg` times, one each time it sleeps. */
static void *sends(void *arg) {
    for (long i = 0; i < (long)arg; i++) {
        sleep_ms(2);
        CHECK(pthread_kill(main_thread, SIGUSR2) == 0);
    }
    return NULL;
}
static void long_jump(void) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = jump_out;
    CHECK(sigaction(SIGUSR2, &action, NULL) == 0);
    if (sigsetjmp(back, 1) == 0) {
        raise(SIGUSR2);
        FAIL("the handler returned");
    }
    jumped = 1;
    sigset_t mask;
    CHECK(sigprocmask(SIG_SETMASK, NULL, &mask) == 0);
    CHECK(!sigismember(&mask, SIGUSR2));
    action.sa_handler = count_handler;
    CHECK(sigaction(SIGUSR2, &action, NULL) == 0);
    for (int i = 0; i < 100; i++) {
        CHECK(raise(SIGUSR2) == 0);
        void *block = malloc(1000 + i);
        CHECK(block != NULL);
        free(block);
        pthread_mutex_lock(&lock);
        pthread_mutex_unlock(&lock);
    }
    CHECK(handled == 100);
    /* Through the entry of signals: another thread sends while this one
     * sleeps; the handler jumps out of the entry's frame and the sleep. */
    action.sa_handler = jump_out;
    CHECK(sigaction(SIGUSR2, &action, NULL) == 0);
    main_thread = pthread_self();
    /* Static: an automatic variable changed after sigsetjmp is lost. */
    static pthread_t thread;
    if (sigsetjmp(back, 1) == 0) {
        CHECK(pthread_create(&thread, &small, sends, (void *)1L) == 0);
        for (;;) sleep_ms(1000);
    }
    CHECK(pthread_join(thread, NULL) == 0);
    /* The jump left nanosleep's window of cancellation behind: none stays. */
    CHECK(relibc_threads_cancel_window() == 0);
    action.sa_handler = count_handler;
    CHECK(sigaction(SIGUSR2, &action, NULL) == 0);
    CHECK(pthread_create(&thread, &small, sends, (void *)100L) == 0);
    while (handled < 200) {
        struct timespec t = {0, 1000000};
        nanosleep(&t, NULL);
        void *block = malloc(64);
        CHECK(block != NULL);
        free(block);
    }
    CHECK(pthread_join(thread, NULL) == 0);
    printf("relibc-threads: siglongjmp out of a handler and out of an entry, then %d signals handled\n",
           handled);
}

/* H: siglongjmp out of sigwait: the handler of SIGUSR2 jumps out of a
 * sigwait for SIGUSR1; SIGUSR1, unblocked again by the jump, then comes
 * from another thread while main sleeps, with no call to the mask. */
static volatile int usr1_seen;
static void see_usr1(int signal) { (void)signal; usr1_seen++; }
static void *kills(void *arg) {
    sleep_ms(5);
    CHECK(pthread_kill(main_thread, (int)(long)arg) == 0);
    return NULL;
}
static void leave_sigwait(void) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = jump_out;
    CHECK(sigaction(SIGUSR2, &action, NULL) == 0);
    action.sa_handler = see_usr1;
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
    main_thread = pthread_self();
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    static pthread_t thread;
    if (sigsetjmp(back, 1) == 0) {
        CHECK(pthread_sigmask(SIG_BLOCK, &set, NULL) == 0);
        CHECK(pthread_create(&thread, &small, kills, (void *)(long)SIGUSR2) == 0);
        int signal;
        sigwait(&set, &signal);
        FAIL("sigwait returned %d", signal);
    }
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(relibc_threads_cancel_window() == 0);
    CHECK(pthread_create(&thread, &small, kills, (void *)(long)SIGUSR1) == 0);
    struct timespec pause = {0, 50000000};
    nanosleep(&pause, NULL);
    if (usr1_seen != 1) FAIL("SIGUSR1 after the jump out of sigwait came %d times", usr1_seen);
    CHECK(pthread_join(thread, NULL) == 0);
    printf("relibc-threads: siglongjmp out of sigwait leaves no window and no wait behind\n");
}

/* I: threads detached after their end give back their places. */
static void detach_after_end(void) {
    relibc_threads_collect();
    int base = relibc_threads_places();
    for (int i = 0; i < 100; i++) {
        pthread_t thread;
        CHECK(pthread_create(&thread, &small, returns, NULL) == 0);
        /* The thread ends while main sleeps. */
        while (relibc_threads_ended(thread) == 0) sleep_ms(1);
        CHECK(pthread_detach(thread) == 0);
    }
    for (int i = 0; i < 1000 && relibc_threads_places() != base; i++) {
        relibc_threads_collect();
        sleep_ms(1);
    }
    if (relibc_threads_places() != base)
        FAIL("100 threads detached after their end: %d places, %d before", relibc_threads_places(), base);
    printf("relibc-threads: 100 threads detached after their end gave their places back\n");
}

/* G: CLOCK_REALTIME from the clock service's page: a thread at 20 reads it
 * while main at 30 sets the time SETTINGS times, twice each time it wakes,
 * so that the service writes both places while a read is cut; every read
 * must be whole (its time and the generation of its anchor agree), and a
 * read makes no call of the kernel. */
/* Enough settings that a torn read shows on HVF in nearly every run. */
#define SETTINGS 3000
static volatile int setting;
static volatile long torn, reads;
static void *reads_clock(void *arg) {
    (void)arg;
    CHECK(relibc_threads_set_level(20) == 0);
    while (setting) {
        long seconds, nanos;
        long generation = relibc_threads_realtime(&seconds, &nanos);
        CHECK(generation >= 0);
        /* Set number k puts the calendar at k * 10^6 s. */
        if (seconds / 1000000 != generation) torn++;
        reads++;
    }
    return NULL;
}
static void clock_page(void) {
    pthread_t reader;
    setting = 1;
    CHECK(pthread_create(&reader, &small, reads_clock, NULL) == 0);
    for (long k = 1; k <= SETTINGS; k += 2) {
        struct timespec at = {k * 1000000, 0};
        CHECK(clock_settime(CLOCK_REALTIME, &at) == 0);
        at.tv_sec += 1000000;
        CHECK(clock_settime(CLOCK_REALTIME, &at) == 0);
        struct timespec pause = {0, 200000};
        nanosleep(&pause, NULL);
    }
    setting = 0;
    CHECK(pthread_join(reader, NULL) == 0);
    if (torn != 0) FAIL("%ld of %ld reads of the clock page were torn", torn, reads);
    struct timespec now;
    unsigned long before = relibc_threads_calls();
    for (int i = 0; i < 1000; i++) CHECK(clock_gettime(CLOCK_REALTIME, &now) == 0);
    unsigned long calls = relibc_threads_calls() - before;
    CHECK(now.tv_sec / 1000000 == SETTINGS);
    if (calls != 0) FAIL("1000 reads of CLOCK_REALTIME made %lu kernel calls", calls);
    printf("relibc-threads: %ld reads of the clock page during %d settings, none torn; no kernel call to read\n",
           reads, SETTINGS);
}

/* _POSIX_THREAD_ATTR_STACKADDR: a thread started with pthread_attr_setstack
 * runs on that memory (the address of its local is inside it), and
 * pthread_attr_getstack gives the region back; the bytes after the end of
 * the given size stay as they were; a misaligned stack is refused. */
/* A size that is no multiple of a page: a stack rounded up to a page would
 * start the thread beyond the memory it was given. */
#define OWN_STACK (65536 + 64)
#define GUARD_BYTES 4096
static char *own_stack;
static int on_own_stack;

static void *report_stack(void *arg) {
    char local = 0;
    char *at = &local;
    on_own_stack = at >= own_stack && at < own_stack + OWN_STACK;
    return arg;
}

static void stack_address(void) {
    own_stack = malloc(OWN_STACK + GUARD_BYTES);
    CHECK(own_stack != NULL);
    memset(own_stack + OWN_STACK, 0xA5, GUARD_BYTES);
    pthread_attr_t attr;
    CHECK(pthread_attr_init(&attr) == 0);
    CHECK(pthread_attr_setstack(&attr, own_stack, OWN_STACK) == 0);
    void *got_address = NULL;
    size_t got_size = 0;
    CHECK(pthread_attr_getstack(&attr, &got_address, &got_size) == 0);
    CHECK(got_address == own_stack && got_size == OWN_STACK);
    pthread_t thread;
    CHECK(pthread_create(&thread, &attr, report_stack, NULL) == 0);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(on_own_stack == 1);
    for (int i = 0; i < GUARD_BYTES; i++)
        CHECK((unsigned char)own_stack[OWN_STACK + i] == 0xA5);
    /* A misaligned address or end is refused. */
    CHECK(pthread_attr_setstack(&attr, own_stack + 8, OWN_STACK) == EINVAL);
    CHECK(pthread_attr_setstack(&attr, own_stack, OWN_STACK + 8) == EINVAL);
    printf("relibc-threads: a thread ran on the stack given to pthread_attr_setstack\n");
}

int main(void) {
    stack_address();
    CHECK(pthread_attr_init(&small) == 0);
    CHECK(pthread_attr_setstacksize(&small, 65536) == 0);
    pthread_t dog;
    CHECK(pthread_create(&dog, &small, watchdog, NULL) == 0);
    CHECK(pthread_detach(dog) == 0);
    stage = 1;
    table_rounds();
    stage = 2;
    exits_under_signals();
    stage = 3;
    synchronization();
    stage = 4;
    wake_order();
    stage = 5;
    cancellation();
    stage = 6;
    long_jump();
    stage = 7;
    clock_page();
    stage = 8;
    leave_sigwait();
    stage = 9;
    detach_after_end();
    printf("relibc-threads: ok\n");
    return 0;
}
