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
#include <spawn.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
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
 * runs on that memory and gives none of it back. The stack is a mapping of
 * the application next to a second mapping of its own: after the thread ran,
 * ended, was joined and another thread was joined (the layer collects the
 * first one then), every byte of both mappings is as the application left
 * it (an unmapped page reads back as zeros), the thread's TLS was in neither,
 * and the application can unmap both. The size is no multiple of a page, so
 * a size rounded up would reach the pattern after the end. */
#define OWN_STACK (65536 + 64)
#define GUARD_BYTES 4096
#define MAPPED (20 * 4096)
static char *own_stack;
static char *neighbour;
static int on_own_stack;
static int tls_apart;

static void *report_stack(void *arg) {
    char local = 0;
    char *at = &local;
    on_own_stack = at >= own_stack && at < own_stack + OWN_STACK;
    char *tls = (char *)&errno;
    tls_apart = !(tls >= own_stack && tls < own_stack + MAPPED) &&
                !(tls >= neighbour && tls < neighbour + 4 * 4096);
    return arg;
}

static void *report_default(void *arg) {
    return arg;
}

static void stack_address(void) {
    own_stack = mmap(NULL, MAPPED, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(own_stack != MAP_FAILED);
    neighbour = mmap(NULL, 4 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(neighbour != MAP_FAILED);
    /* Two mappings in a row do not overlap. */
    CHECK(neighbour >= own_stack + MAPPED || neighbour + 4 * 4096 <= own_stack);
    memset(own_stack, 0x3C, 4096);
    memset(own_stack + 4096, 0x77, OWN_STACK - 8192);
    memset(own_stack + OWN_STACK, 0xA5, GUARD_BYTES);
    memset(neighbour, 0x5E, 4 * 4096);
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
    CHECK(tls_apart == 1);
    /* Another thread, joined, so that the layer collects the first one; it
     * does so as that thread ends, after its join returned: give it time. */
    pthread_t other;
    CHECK(pthread_create(&other, NULL, report_default, NULL) == 0);
    CHECK(pthread_join(other, NULL) == 0);
    sleep_ms(100);
    for (int i = 0; i < 4096; i++)
        CHECK((unsigned char)own_stack[i] == 0x3C);
    for (int i = 0; i < GUARD_BYTES; i++)
        CHECK((unsigned char)own_stack[OWN_STACK + i] == 0xA5);
    for (int i = 0; i < 4 * 4096; i++)
        CHECK((unsigned char)neighbour[i] == 0x5E);
    /* A misaligned address or end is refused. */
    CHECK(pthread_attr_setstack(&attr, own_stack + 8, OWN_STACK) == EINVAL);
    CHECK(pthread_attr_setstack(&attr, own_stack, OWN_STACK + 8) == EINVAL);
    CHECK(munmap(own_stack, MAPPED) == 0);
    CHECK(munmap(neighbour, 4 * 4096) == 0);
    void *again = malloc(OWN_STACK);
    CHECK(again != NULL);
    memset(again, 0, OWN_STACK);
    free(again);
    printf("relibc-threads: a thread ran on the stack given to pthread_attr_setstack\n");
}

/* H: fflush(NULL) while other threads open and close streams. Main keeps a
 * memory stream with one more byte pending each round, and every round of
 * fflush(NULL) must make all of them visible, however the list of the open
 * streams changes meanwhile: a stream that closes moves the last one into
 * its place in the list, and must neither be freed under the walk nor make
 * it skip a neighbour. */
static volatile int churning;
static void *opens_and_closes(void *arg) {
    (void)arg;
    char buffer[16];
    while (churning) {
        FILE *stream = fmemopen(buffer, sizeof buffer, "w");
        if (stream == NULL) FAIL("fmemopen failed: %d", errno);
        fputc('y', stream);
        if (fclose(stream) != 0) FAIL("fclose failed");
    }
    return NULL;
}
#define FLUSH_ROUNDS 300
static void flush_all_streams(void) {
    char *text = NULL;
    size_t size = 0;
    FILE *kept = open_memstream(&text, &size);
    CHECK(kept != NULL);
    pthread_t threads[3];
    churning = 1;
    for (int i = 0; i < 3; i++)
        CHECK(pthread_create(&threads[i], &small, opens_and_closes, NULL) == 0);
    for (int round = 1; round <= FLUSH_ROUNDS; round++) {
        CHECK(fputc('x', kept) == 'x');
        CHECK(fflush(NULL) == 0);
        if (size != (size_t)round)
            FAIL("fflush(NULL) round %d left %zu bytes visible", round, size);
    }
    churning = 0;
    for (int i = 0; i < 3; i++) CHECK(pthread_join(threads[i], NULL) == 0);
    CHECK(fclose(kept) == 0);
    free(text);
    printf("relibc-threads: %d rounds of fflush(NULL) among streams that open and close ok\n", FLUSH_ROUNDS);
}


/* K: the priorities of POSIX (spec 2, 3.5): the calls of sched.h and the
 * thread attributes, then the mutex protocols against a thread that
 * computes between the holder and the waiter. The process starts at level
 * 30 (priority 32 stands there), so that priority 5, 15, 20 and 25 are the
 * levels 3, 13, 18 and 23. */
static long long now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000000LL + t.tv_nsec;
}
static void burn_until(long long deadline) {
    while (now_ns() < deadline) {}
}
static pthread_t spawn_at(int priority, void *(*body)(void *), void *arg) {
    pthread_attr_t attr;
    struct sched_param param = {priority};
    int policy = -1;
    CHECK(pthread_attr_init(&attr) == 0);
    CHECK(pthread_attr_setstacksize(&attr, 65536) == 0);
    CHECK(pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED) == 0);
    CHECK(pthread_attr_setschedpolicy(&attr, SCHED_FIFO) == 0);
    CHECK(pthread_attr_setschedparam(&attr, &param) == 0);
    pthread_t thread;
    CHECK(pthread_create(&thread, &attr, body, arg) == 0);
    CHECK(pthread_attr_destroy(&attr) == 0);
    /* The new thread has what the attributes gave it. */
    struct sched_param got;
    CHECK(pthread_getschedparam(thread, &policy, &got) == 0);
    CHECK(policy == SCHED_FIFO && got.sched_priority == priority);
    return thread;
}

static void sched_calls(void) {
    CHECK(sched_get_priority_min(SCHED_FIFO) == 1 && sched_get_priority_max(SCHED_FIFO) == 32);
    CHECK(sched_get_priority_min(SCHED_RR) == 1 && sched_get_priority_max(SCHED_RR) == 32);
    CHECK(sched_get_priority_min(SCHED_OTHER) == 0 && sched_get_priority_max(SCHED_OTHER) == 0);
    errno = 0;
    CHECK(sched_get_priority_max(99) == -1 && errno == EINVAL);
    struct timespec quantum;
    CHECK(sched_rr_get_interval(0, &quantum) == 0 && quantum.tv_sec == 0 && quantum.tv_nsec == 4000000);
    CHECK(sched_getscheduler(0) == SCHED_OTHER);
    struct sched_param param = {32};
    CHECK(sched_setscheduler(0, SCHED_FIFO, &param) == SCHED_OTHER);
    CHECK(sched_getscheduler(0) == SCHED_FIFO);
    param.sched_priority = 0;
    CHECK(sched_getparam(0, &param) == 0 && param.sched_priority == 32);
    param.sched_priority = 33;
    errno = 0;
    CHECK(sched_setparam(0, &param) == -1 && errno == EINVAL);
    param.sched_priority = 32;
    errno = 0;
    CHECK(sched_setscheduler(0, SCHED_OTHER, &param) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(sched_getscheduler(-1) == -1 && errno == ESRCH);
    int policy;
    struct sched_param got;
    CHECK(pthread_getschedparam(pthread_self(), &policy, &got) == 0);
    CHECK(policy == SCHED_FIFO && got.sched_priority == 32);
    CHECK(pthread_setschedprio(pthread_self(), 31) == 0);
    CHECK(pthread_getschedparam(pthread_self(), &policy, &got) == 0 && got.sched_priority == 31);
    param.sched_priority = 32;
    CHECK(pthread_setschedparam(pthread_self(), SCHED_RR, &param) == 0);
    CHECK(sched_getscheduler(0) == SCHED_RR);
    CHECK(sched_setscheduler(0, SCHED_FIFO, &param) == SCHED_RR);
    printf("relibc-threads: sched_get_priority_*, sched_setscheduler, sched_getparam and pthread_setschedparam agree\n");
}

/* XSH 2.8.4: a thread whose priority is set by pthread_setschedparam goes
 * to the tail of its list, also at the same priority; pthread_setschedprio
 * at the same priority leaves it where it is. A thread of the caller's own
 * level that is ready runs at the first and not at the second. */
static volatile int equal_ran, equal_go;
static void *equal_thread(void *arg) {
    (void)arg;
    /* The creator waits for this thread to start: it gives the processor
     * back at once, to the creator, which is its equal. */
    while (!equal_go) sched_yield();
    equal_ran = 1;
    return NULL;
}
static void tail_of_the_list(void) {
    struct sched_param param = {32};
    CHECK(pthread_setschedparam(pthread_self(), SCHED_FIFO, &param) == 0);
    equal_ran = equal_go = 0;
    pthread_t t = spawn_at(32, equal_thread, NULL);
    equal_go = 1;
    CHECK(equal_ran == 0);
    CHECK(pthread_setschedprio(pthread_self(), 32) == 0);
    CHECK(equal_ran == 0);
    CHECK(pthread_setschedparam(pthread_self(), SCHED_FIFO, &param) == 0);
    CHECK(equal_ran == 1);
    CHECK(pthread_join(t, NULL) == 0);
    printf("relibc-threads: pthread_setschedparam puts the thread behind an equal one, pthread_setschedprio does not\n");
}

static pthread_mutex_t protocol_mutex[2];
static volatile int holder_has, holder_go, mid_ran, high_done, saw_mid;
static volatile long long go_at, high_got;
static void *holder(void *arg) {
    (void)arg;
    CHECK(pthread_mutex_lock(&protocol_mutex[0]) == 0);
    holder_has = 1;
    while (!holder_go) sched_yield();
    saw_mid = mid_ran;
    CHECK(pthread_mutex_unlock(&protocol_mutex[0]) == 0);
    return NULL;
}
static void *middle(void *arg) {
    mid_ran = 1;
    burn_until(now_ns() + (long long)(long)arg * 1000000LL);
    return NULL;
}
static void *high(void *arg) {
    (void)arg;
    CHECK(pthread_mutex_lock(&protocol_mutex[0]) == 0);
    high_got = now_ns();
    CHECK(pthread_mutex_unlock(&protocol_mutex[0]) == 0);
    high_done = 1;
    return NULL;
}

static void make_mutex(pthread_mutex_t *mutex, int protocol, int ceiling) {
    pthread_mutexattr_t attr;
    CHECK(pthread_mutexattr_init(&attr) == 0);
    CHECK(pthread_mutexattr_setprotocol(&attr, protocol) == 0);
    if (protocol == PTHREAD_PRIO_PROTECT) CHECK(pthread_mutexattr_setprioceiling(&attr, ceiling) == 0);
    CHECK(pthread_mutex_init(mutex, &attr) == 0);
    CHECK(pthread_mutexattr_destroy(&attr) == 0);
}

/* The holder (priority 5) has the mutex, a thread of priority 20 computes
 * for 60 ms, and a thread of priority 25 asks for the mutex. How long the
 * mutex takes to reach the last after the holder may let it go. */
static long long inversion(int protocol) {
    make_mutex(&protocol_mutex[0], protocol, 25);
    holder_has = holder_go = mid_ran = high_done = 0;
    pthread_t h = spawn_at(5, holder, NULL);
    while (!holder_has) sleep_ms(1);
    pthread_t m = spawn_at(20, middle, (void *)60L);
    pthread_t t = spawn_at(25, high, NULL);
    sleep_ms(3);
    go_at = now_ns();
    holder_go = 1;
    CHECK(pthread_join(t, NULL) == 0);
    CHECK(pthread_join(m, NULL) == 0);
    CHECK(pthread_join(h, NULL) == 0);
    CHECK(pthread_mutex_destroy(&protocol_mutex[0]) == 0);
    return high_got - go_at;
}

/* The holder (priority 5) has a mutex of ceiling 25: a thread of priority
 * 15 that becomes ready meanwhile does not run before the holder lets go. */
static sem_t mid_gate;
static void *gated_middle(void *arg) {
    (void)arg;
    CHECK(sem_wait(&mid_gate) == 0);
    mid_ran = 1;
    return NULL;
}
static int ceiling_held(int protocol) {
    make_mutex(&protocol_mutex[0], protocol, 25);
    holder_has = holder_go = mid_ran = saw_mid = 0;
    CHECK(sem_init(&mid_gate, 0, 0) == 0);
    pthread_t m = spawn_at(15, gated_middle, NULL);
    sleep_ms(2);
    pthread_t h = spawn_at(5, holder, NULL);
    while (!holder_has) sleep_ms(1);
    CHECK(sem_post(&mid_gate) == 0);
    sleep_ms(3);
    holder_go = 1;
    CHECK(pthread_join(h, NULL) == 0);
    CHECK(pthread_join(m, NULL) == 0);
    CHECK(sem_destroy(&mid_gate) == 0);
    CHECK(pthread_mutex_destroy(&protocol_mutex[0]) == 0);
    return saw_mid;
}

/* A (priority 5) has M1; B (15) has M2 and asks for M1; C (25) asks for M2;
 * D (20) computes: A has to run at C's level through B. */
static volatile int a_has, b_has;
static void *chain_a(void *arg) {
    (void)arg;
    CHECK(pthread_mutex_lock(&protocol_mutex[0]) == 0);
    a_has = 1;
    while (!holder_go) sched_yield();
    CHECK(pthread_mutex_unlock(&protocol_mutex[0]) == 0);
    return NULL;
}
static void *chain_b(void *arg) {
    (void)arg;
    CHECK(pthread_mutex_lock(&protocol_mutex[1]) == 0);
    b_has = 1;
    CHECK(pthread_mutex_lock(&protocol_mutex[0]) == 0);
    CHECK(pthread_mutex_unlock(&protocol_mutex[0]) == 0);
    CHECK(pthread_mutex_unlock(&protocol_mutex[1]) == 0);
    return NULL;
}
static void *chain_c(void *arg) {
    (void)arg;
    CHECK(pthread_mutex_lock(&protocol_mutex[1]) == 0);
    high_got = now_ns();
    CHECK(pthread_mutex_unlock(&protocol_mutex[1]) == 0);
    return NULL;
}
static long long chain(void) {
    make_mutex(&protocol_mutex[0], PTHREAD_PRIO_INHERIT, 0);
    make_mutex(&protocol_mutex[1], PTHREAD_PRIO_INHERIT, 0);
    a_has = b_has = holder_go = mid_ran = 0;
    pthread_t a = spawn_at(5, chain_a, NULL);
    while (!a_has) sleep_ms(1);
    pthread_t b = spawn_at(15, chain_b, NULL);
    while (!b_has) sleep_ms(1);
    pthread_t d = spawn_at(20, middle, (void *)60L);
    pthread_t c = spawn_at(25, chain_c, NULL);
    sleep_ms(3);
    go_at = now_ns();
    holder_go = 1;
    CHECK(pthread_join(c, NULL) == 0);
    CHECK(pthread_join(d, NULL) == 0);
    CHECK(pthread_join(b, NULL) == 0);
    CHECK(pthread_join(a, NULL) == 0);
    CHECK(pthread_mutex_destroy(&protocol_mutex[0]) == 0);
    CHECK(pthread_mutex_destroy(&protocol_mutex[1]) == 0);
    return high_got - go_at;
}

/* Two threads that wait for each other's mutex: the one that closes the
 * cycle is told EDEADLK. */
static volatile int other_asks;
static void *other_waits(void *arg) {
    (void)arg;
    CHECK(pthread_mutex_lock(&protocol_mutex[1]) == 0);
    other_asks = 1;
    CHECK(pthread_mutex_lock(&protocol_mutex[0]) == 0);
    CHECK(pthread_mutex_unlock(&protocol_mutex[0]) == 0);
    CHECK(pthread_mutex_unlock(&protocol_mutex[1]) == 0);
    return NULL;
}
static void deadlock(void) {
    make_mutex(&protocol_mutex[0], PTHREAD_PRIO_INHERIT, 0);
    make_mutex(&protocol_mutex[1], PTHREAD_PRIO_INHERIT, 0);
    other_asks = 0;
    CHECK(pthread_mutex_lock(&protocol_mutex[0]) == 0);
    pthread_t t = spawn_at(15, other_waits, NULL);
    while (!other_asks) sleep_ms(1);
    sleep_ms(3);
    CHECK(pthread_mutex_lock(&protocol_mutex[1]) == EDEADLK);
    CHECK(pthread_mutex_unlock(&protocol_mutex[0]) == 0);
    CHECK(pthread_join(t, NULL) == 0);
    CHECK(pthread_mutex_destroy(&protocol_mutex[0]) == 0);
    CHECK(pthread_mutex_destroy(&protocol_mutex[1]) == 0);
}

static volatile int spin_has, spin_done;
static pthread_spinlock_t spin;
static void *spin_holder(void *arg) {
    (void)arg;
    CHECK(pthread_spin_lock(&spin) == 0);
    spin_has = 1;
    burn_until(now_ns() + 2000000);
    CHECK(pthread_spin_unlock(&spin) == 0);
    return NULL;
}
static void *spin_waiter(void *arg) {
    (void)arg;
    CHECK(pthread_spin_lock(&spin) == 0);
    spin_done = 1;
    CHECK(pthread_spin_unlock(&spin) == 0);
    return NULL;
}

static volatile int async_started, async_cleaned;
static volatile unsigned long async_past;
static void async_cleanup(void *arg) { (void)arg; async_cleaned = 1; }
static void *async_busy(void *arg) {
    (void)arg;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) == 0);
    CHECK(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL) == 0);
    pthread_cleanup_push(async_cleanup, NULL);
    async_started = 1;
    for (;;) async_past++;
    pthread_cleanup_pop(0);
    return NULL;
}

/* pthread_mutex_setprioceiling takes the mutex at the old ceiling and
 * lets it go at the old one: a thread that does it many times keeps no
 * trace of the ceilings in its slots (it holds at most eight). */
static void *ceiling_changer(void *arg) {
    pthread_mutex_t *mutex = arg;
    int old = 0;
    for (int i = 0; i < 20; i++) {
        int next = 11 + i;
        int e = pthread_mutex_setprioceiling(mutex, next, &old);
        if (e != 0 || old != 10 + i) {
            printf("relibc-threads: setprioceiling round %d gave %d old %d\n", i, e, old);
            return (void *)1;
        }
    }
    /* And the mutex locks and unlocks at the ceiling it has. */
    if (pthread_mutex_lock(mutex) != 0 || pthread_mutex_unlock(mutex) != 0) return (void *)2;
    return NULL;
}

/* XSH pthread_mutex_lock: a thread that locks a mutex it holds deadlocks
 * with PTHREAD_MUTEX_NORMAL (the timed lock says ETIMEDOUT) and is told
 * EDEADLK with PTHREAD_MUTEX_ERRORCHECK, also with inheritance. */
static void relock_own_mutex(void) {
    pthread_mutexattr_t attr;
    pthread_mutex_t mutex;
    CHECK(pthread_mutexattr_init(&attr) == 0);
    CHECK(pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT) == 0);
    CHECK(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_NORMAL) == 0);
    CHECK(pthread_mutex_init(&mutex, &attr) == 0);
    CHECK(pthread_mutex_lock(&mutex) == 0);
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_nsec += 20000000;
    if (deadline.tv_nsec >= 1000000000) { deadline.tv_sec++; deadline.tv_nsec -= 1000000000; }
    CHECK(pthread_mutex_timedlock(&mutex, &deadline) == ETIMEDOUT);
    CHECK(pthread_mutex_unlock(&mutex) == 0);
    CHECK(pthread_mutex_destroy(&mutex) == 0);
    CHECK(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK) == 0);
    CHECK(pthread_mutex_init(&mutex, &attr) == 0);
    CHECK(pthread_mutex_lock(&mutex) == 0);
    CHECK(pthread_mutex_lock(&mutex) == EDEADLK);
    CHECK(pthread_mutex_unlock(&mutex) == 0);
    CHECK(pthread_mutex_destroy(&mutex) == 0);
    CHECK(pthread_mutexattr_destroy(&attr) == 0);
}

/* A mutex of PTHREAD_PRIO_PROTECT may be shared between processes; one of
 * PTHREAD_PRIO_INHERIT may not (ENOTSUP, a limit of this implementation). */
static void shared_protocols(void) {
    pthread_mutexattr_t attr;
    pthread_mutex_t mutex;
    CHECK(pthread_mutexattr_init(&attr) == 0);
    CHECK(pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) == 0);
    CHECK(pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_PROTECT) == 0);
    CHECK(pthread_mutexattr_setprioceiling(&attr, 20) == 0);
    CHECK(pthread_mutex_init(&mutex, &attr) == 0);
    CHECK(pthread_mutex_destroy(&mutex) == 0);
    CHECK(pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT) == 0);
    CHECK(pthread_mutex_init(&mutex, &attr) == ENOTSUP);
    CHECK(pthread_mutexattr_destroy(&attr) == 0);
}

/* A user without privilege: a process that does not exist is ESRCH, not
 * EPERM; a negative step of nice is EPERM; a rise by posix_spawn is EPERM;
 * a lower nice value for setpriority is EACCES. Runs last, as it
 * gives the privilege up. */
static void without_privilege(void) {
    if (geteuid() != 0) return;
    struct sched_param param = {0};
    CHECK(sched_setscheduler(0, SCHED_OTHER, &param) >= 0);
    CHECK(setuid(1000) == 0);
    errno = 0;
    CHECK(sched_getparam(99999, &param) == -1 && errno == ESRCH);
    errno = 0;
    CHECK(sched_getscheduler(99999) == -1 && errno == ESRCH);
    param.sched_priority = 5;
    errno = 0;
    CHECK(sched_setscheduler(99999, SCHED_FIFO, &param) == -1 && errno == ESRCH);
    errno = 0;
    CHECK(nice(-1) == -1 && errno == EPERM);
    errno = 0;
    CHECK(setpriority(PRIO_PROCESS, 0, -3) == -1 && errno == EACCES);
    posix_spawnattr_t spawn;
    CHECK(posix_spawnattr_init(&spawn) == 0);
    CHECK(posix_spawnattr_setflags(&spawn, POSIX_SPAWN_SETSCHEDULER) == 0);
    CHECK(posix_spawnattr_setschedpolicy(&spawn, SCHED_FIFO) == 0);
    param.sched_priority = 8;
    CHECK(posix_spawnattr_setschedparam(&spawn, &param) == 0);
    char *argv[] = {"nothing", NULL};
    char *envp[] = {NULL};
    pid_t pid;
    int spawned = posix_spawn(&pid, "/bin/nothing", NULL, &spawn, argv, envp);
    if (spawned != EPERM) FAIL("posix_spawn with SETSCHEDULER gave %d", spawned);
    CHECK(posix_spawnattr_destroy(&spawn) == 0);
    printf("relibc-threads: without privilege: ESRCH for a process that is none, EPERM for a negative nice and a rise by posix_spawn\n");
}

static void priorities(void) {
    sched_calls();
    tail_of_the_list();
    /* The main thread keeps the top of the levels. */
    long long pi = inversion(PTHREAD_PRIO_INHERIT);
    long long none = inversion(PTHREAD_PRIO_NONE);
    printf("relibc-threads: the waiter of priority 25 gets the mutex %lld us after the holder may let go with inheritance, %lld us without\n",
           pi / 1000, none / 1000);
    CHECK(pi < 15000000LL);
    CHECK(none > 25000000LL);
    CHECK(ceiling_held(PTHREAD_PRIO_PROTECT) == 0);
    CHECK(ceiling_held(PTHREAD_PRIO_NONE) == 1);
    printf("relibc-threads: a thread holding a mutex of ceiling 25 is not preempted by priority 15\n");
    long long through = chain();
    printf("relibc-threads: along a chain of two mutexes the last waiter gets its mutex %lld us after the first holder may let go\n",
           through / 1000);
    CHECK(through < 15000000LL);
    deadlock();
    printf("relibc-threads: a cycle of holders is told EDEADLK\n");
    /* The ceiling of a mutex is its to set, within 1 to 32. */
    pthread_mutex_t ceiling;
    make_mutex(&ceiling, PTHREAD_PRIO_PROTECT, 32);
    int old = 0;
    CHECK(pthread_mutex_getprioceiling(&ceiling, &old) == 0 && old == 32);
    CHECK(pthread_mutex_setprioceiling(&ceiling, 12, &old) == 0 && old == 32);
    CHECK(pthread_mutex_getprioceiling(&ceiling, &old) == 0 && old == 12);
    CHECK(pthread_mutex_setprioceiling(&ceiling, 33, &old) == EINVAL);
    CHECK(pthread_mutex_destroy(&ceiling) == 0);
    /* Replacing the ceiling many times leaves the slots of the thread
     * empty. */
    pthread_mutex_t replaced;
    make_mutex(&replaced, PTHREAD_PRIO_PROTECT, 10);
    pthread_t changer = spawn_at(5, ceiling_changer, &replaced);
    void *changed = (void *)9;
    CHECK(pthread_join(changer, &changed) == 0 && changed == NULL);
    CHECK(pthread_mutex_destroy(&replaced) == 0);
    relock_own_mutex();
    shared_protocols();
    printf("relibc-threads: the ceiling is replaced at the old one, a relock of an own mutex deadlocks or says EDEADLK, PROTECT may be shared\n");
    /* The holder of a spin lock below its waiter lets go: the waiter waits
     * for it where it would only spin. */
    CHECK(pthread_spin_init(&spin, PTHREAD_PROCESS_PRIVATE) == 0);
    spin_has = spin_done = 0;
    pthread_t sh = spawn_at(5, spin_holder, NULL);
    while (!spin_has) sleep_ms(1);
    pthread_t sw = spawn_at(25, spin_waiter, NULL);
    CHECK(pthread_join(sw, NULL) == 0 && spin_done);
    CHECK(pthread_join(sh, NULL) == 0);
    CHECK(pthread_spin_destroy(&spin) == 0);
    printf("relibc-threads: a spin lock held below its waiter is waited for\n");
    /* A thread that computes, with asynchronous cancellation, is cancelled
     * at once. */
    async_started = async_cleaned = 0;
    pthread_t busy = spawn_at(15, async_busy, NULL);
    while (!async_started) sleep_ms(1);
    sleep_ms(2);
    CHECK(pthread_cancel(busy) == 0);
    void *value = NULL;
    CHECK(pthread_join(busy, &value) == 0);
    CHECK(value == PTHREAD_CANCELED && async_cleaned == 1);
    printf("relibc-threads: a busy thread with asynchronous cancellation is cancelled\n");
    without_privilege();
}

/* K: robust mutexes. A thread that ends holding one says EOWNERDEAD to the
 * next owner, even to a thread that waits for it; an owner that unlocks
 * before pthread_mutex_consistent makes it unusable (ENOTRECOVERABLE); one
 * that repairs it first gets it back as an ordinary mutex. */
static pthread_mutex_t robust_lock;
static pthread_mutex_t robust_other;
static volatile int robust_waiter_result = -1;
static void *takes_robust(void *arg) {
    (void)arg;
    return (void *)(long)pthread_mutex_lock(&robust_lock);
}
static void *waits_robust(void *arg) {
    (void)arg;
    robust_waiter_result = pthread_mutex_lock(&robust_lock);
    if (robust_waiter_result == EOWNERDEAD) pthread_mutex_consistent(&robust_lock);
    pthread_mutex_unlock(&robust_lock);
    return NULL;
}
static void robust_mutexes(void) {
    pthread_mutexattr_t attr;
    pthread_t thread, waiter;
    void *value;
    CHECK(pthread_mutexattr_init(&attr) == 0);
    CHECK(pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST) == 0);
    CHECK(pthread_mutex_init(&robust_lock, &attr) == 0);
    CHECK(pthread_mutex_init(&robust_other, &attr) == 0);
    /* A mutex that no owner died on is an ordinary one, and consistent says EINVAL. */
    CHECK(pthread_mutex_lock(&robust_lock) == 0 && pthread_mutex_consistent(&robust_lock) == EINVAL);
    CHECK(pthread_mutex_unlock(&robust_lock) == 0);
    /* The owner ends; the next owner is told, repairs the state and goes on. */
    CHECK(pthread_create(&thread, &small, takes_robust, NULL) == 0);
    CHECK(pthread_join(thread, &value) == 0 && value == NULL);
    CHECK(pthread_mutex_lock(&robust_lock) == EOWNERDEAD);
    CHECK(pthread_mutex_trylock(&robust_lock) == EBUSY);
    CHECK(pthread_mutex_consistent(&robust_lock) == 0 && pthread_mutex_consistent(&robust_lock) == EINVAL);
    CHECK(pthread_mutex_unlock(&robust_lock) == 0);
    CHECK(pthread_mutex_lock(&robust_lock) == 0 && pthread_mutex_unlock(&robust_lock) == 0);
    /* An owner that unlocks without repairing: nobody can lock it again. */
    CHECK(pthread_create(&thread, &small, takes_robust, NULL) == 0);
    CHECK(pthread_join(thread, &value) == 0 && value == NULL);
    CHECK(pthread_mutex_lock(&robust_lock) == EOWNERDEAD);
    CHECK(pthread_mutex_unlock(&robust_lock) == 0);
    CHECK(pthread_mutex_lock(&robust_lock) == ENOTRECOVERABLE);
    CHECK(pthread_mutex_trylock(&robust_lock) == ENOTRECOVERABLE);
    CHECK(pthread_mutex_destroy(&robust_lock) == 0);
    /* A thread that waits when the owner ends is woken with EOWNERDEAD. */
    CHECK(pthread_mutex_init(&robust_lock, &attr) == 0);
    CHECK(pthread_mutex_lock(&robust_lock) == 0);
    robust_waiter_result = -1;
    CHECK(pthread_create(&waiter, &small, waits_robust, NULL) == 0);
    sleep_ms(100);
    CHECK(robust_waiter_result == -1);
    CHECK(pthread_create(&thread, &small, takes_robust, NULL) == 0);
    CHECK(pthread_mutex_unlock(&robust_lock) == 0);
    CHECK(pthread_join(thread, &value) == 0);
    CHECK(pthread_join(waiter, &value) == 0);
    CHECK(robust_waiter_result == 0 || robust_waiter_result == EOWNERDEAD);
    CHECK(pthread_mutex_lock(&robust_other) == 0 && pthread_mutex_unlock(&robust_other) == 0);
    CHECK(pthread_mutex_destroy(&robust_lock) == 0 && pthread_mutex_destroy(&robust_other) == 0);
    CHECK(pthread_mutexattr_destroy(&attr) == 0);
    printf("relibc-threads: robust mutexes: owner death, consistent, not recoverable ok\n");
}

/* A request that came while cancellation was disabled acts as soon as the
 * thread enables it with the asynchronous type, and one that came before the
 * asynchronous type acts when the thread sets it. */
static volatile int late_requested, late_passed;
static void *enables_late(void *arg) {
    int by_type = arg != NULL;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0);
    if (!by_type) CHECK(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL) == 0);
    while (!late_requested) sleep_ms(1);
    if (by_type) {
        CHECK(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) == 0);
        late_passed = 1;
        CHECK(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL) == 0);
    } else {
        late_passed = 1;
        CHECK(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) == 0);
    }
    late_passed = 2;
    return NULL;
}
static void cancel_when_enabled(void) {
    for (long by_type = 0; by_type < 2; by_type++) {
        pthread_t thread;
        void *value;
        late_requested = late_passed = 0;
        CHECK(pthread_create(&thread, &small, enables_late, (void *)by_type) == 0);
        sleep_ms(20);
        CHECK(pthread_cancel(thread) == 0);
        late_requested = 1;
        CHECK(pthread_join(thread, &value) == 0);
        CHECK(value == PTHREAD_CANCELED && late_passed == 1);
    }
    printf("relibc-threads: a request acts when asynchronous cancellation is enabled ok\n");
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
    stage = 10;
    flush_all_streams();
    stage = 11;
    priorities();
    stage = 12;
    robust_mutexes();
    cancel_when_enabled();
    printf("relibc-threads: ok\n");
    return 0;
}
