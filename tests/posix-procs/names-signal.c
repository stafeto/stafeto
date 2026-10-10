/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
/* A real signal in the middle of a long operation on names (spec 2, 3.3 and
 * table 2.4): a rename of a name at the end of a chain of 40
 * directories takes more than eighty steps of the service (a step for each
 * component of the two paths), and a thread that sleeps for a part of that time
 * sends SIGALRM to the thread that renames (the timers of POSIX are not in
 * the layer yet). The handler is installed without SA_RESTART. Three runs:
 *   a. the handler makes operations of its own (mkdir, rmdir): the rename
 *      still ends with 0, never with EINTR, and the handler ran in it;
 *   b. the handler leaves by siglongjmp out of the middle of the rename: the
 *      next operation, made in the frame of the main function, collects the
 *      record (no place stays taken), and exactly one of the two names of the
 *      renamed file exists, so the effect has happened at most once;
 *   c. seventeen such exits in a row, and the next operation passes with no
 *      EAGAIN.
 * The driver's answer to a request the kernel takes back (Interrupted) is
 * tested with the hook of the driver (names_loss.rs and names_fork.rs); the count of such
 * requests in this probe is printed. Included by procs.c, in the role names. */
#include <setjmp.h>

extern int files_names_places_in_use(void);
extern unsigned files_names_interrupted(void);

#define SG_BASE "/tmp/sgd"
#define SG_DEPTH 40
/* The two names of the renamed file, at the end of the chain. */
static char sg_last_path[SG_DEPTH * 2 + 32];
static char sg_new_path[SG_DEPTH * 2 + 32];
#define SG_LAST sg_last_path
#define SG_NEW sg_new_path

#define SG_CHECK(condition)                                                    \
    do {                                                                       \
        if (!(condition)) {                                                    \
            printf("posix-procs: names signal: %s at names-signal.c:%d (errno %d)\n", \
                   #condition, __LINE__, errno);                               \
            return __LINE__;                                                   \
        }                                                                      \
    } while (0)

static sigjmp_buf sg_jump;
static volatile sig_atomic_t sg_in_rename;
static volatile sig_atomic_t sg_leaves;
static volatile sig_atomic_t sg_hits;
static volatile sig_atomic_t sg_handler_bad;
static volatile sig_atomic_t sg_jumps;

static void sg_handler(int signal) {
    (void)signal;
    if (!sg_in_rename) return;
    sg_in_rename = 0;
    sg_hits++;
    if (sg_leaves) siglongjmp(sg_jump, 1);
    /* An operation of the handler inside the operation it interrupted. */
    if (mkdir("/tmp/sgh", 0700) != 0 || rmdir("/tmp/sgh") != 0) sg_handler_bad++;
}

struct sg_sender {
    pthread_t target;
    long delay_us;
};

static void *sg_send(void *argument) {
    struct sg_sender *sender = argument;
    struct timespec delay = {sender->delay_us / 1000000, (sender->delay_us % 1000000) * 1000};
    nanosleep(&delay, NULL);
    pthread_kill(sender->target, SIGALRM);
    return NULL;
}

static int sg_exists(const char *path) {
    struct stat st;
    return lstat(path, &st) == 0;
}

static int sg_one_name(void) {
    return sg_exists(SG_NEW) != sg_exists(SG_LAST);
}

static int sg_plain(void) {
    return sg_exists(SG_NEW) ? rename(SG_NEW, SG_LAST) : rename(SG_LAST, SG_NEW);
}

static long sg_now_us(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec * 1000000L + now.tv_nsec / 1000;
}

/* One rename with a sender that signals after `delay_us`. Returns the result
 * of the rename, or 0 with *left set when the handler left the operation.
 * The sender is joined before the return. */
static int sg_try(long delay_us, int *left, int from_new) {
    struct sg_sender sender = {pthread_self(), delay_us};
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 20480);
    int result = -2;
    *left = 0;
    if (pthread_create(&thread, &attr, sg_send, &sender) != 0) return -3;
    if (sigsetjmp(sg_jump, 1) == 0) {
        sg_in_rename = 1;
        result = from_new ? rename(SG_NEW, SG_LAST) : rename(SG_LAST, SG_NEW);
        sg_in_rename = 0;
    } else {
        *left = 1;
        sg_jumps++;
        result = 0;
    }
    pthread_join(thread, NULL);
    pthread_attr_destroy(&attr);
    return result;
}

/* The chain of directories and the file at its end. */
static int sg_build(void) {
    char path[SG_DEPTH * 2 + 32];
    strcpy(path, SG_BASE);
    SG_CHECK(mkdir(path, 0777) == 0);
    for (int level = 0; level < SG_DEPTH; level++) {
        strcat(path, "/d");
        SG_CHECK(mkdir(path, 0777) == 0);
    }
    snprintf(sg_last_path, sizeof sg_last_path, "%s/f", path);
    snprintf(sg_new_path, sizeof sg_new_path, "%s/n", path);
    int fd = open(sg_last_path, O_WRONLY | O_CREAT, 0644);
    SG_CHECK(fd >= 0 && close(fd) == 0);
    return 0;
}

/* The chain goes. */
static int sg_remove(void) {
    if (sg_exists(SG_NEW)) SG_CHECK(unlink(SG_NEW) == 0);
    if (sg_exists(SG_LAST)) SG_CHECK(unlink(SG_LAST) == 0);
    char path[SG_DEPTH * 2 + 32];
    for (int level = SG_DEPTH; level >= 0; level--) {
        strcpy(path, SG_BASE);
        for (int i = 0; i < level; i++) strcat(path, "/d");
        SG_CHECK(rmdir(path) == 0);
    }
    return 0;
}

static int names_signals(void) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = sg_handler;
    sigemptyset(&action.sa_mask);
    SG_CHECK(sigaction(SIGALRM, &action, NULL) == 0);
    SG_CHECK(sg_build() == 0);
    /* How long a rename takes alone: the calls to lstat are left out. */
    long spent = 0;
    for (int i = 0; i < 4; i++) {
        int from_new = sg_exists(SG_NEW);
        long begin = sg_now_us();
        SG_CHECK((from_new ? rename(SG_NEW, SG_LAST) : rename(SG_LAST, SG_NEW)) == 0);
        spent += sg_now_us() - begin;
    }
    long whole = spent / 4;
    if (whole < 200) whole = 200;
    printf("posix-procs: names signal: a rename takes %ld us\n", whole);

    /* a. Operations in the handler. */
    sg_leaves = 0;
    for (int attempt = 0; attempt < 150 && sg_hits < 3; attempt++) {
        long delay = whole * (attempt % 9 + 1) / 10;
        int left = 0;
        int from_new = sg_exists(SG_NEW);
        int result = sg_try(delay, &left, from_new);
        SG_CHECK(result == 0 && !left);
        SG_CHECK(!sg_handler_bad);
        SG_CHECK(sg_one_name());
    }
    SG_CHECK(sg_hits >= 3);
    SG_CHECK(files_names_places_in_use() == 0);
    /* The kernel takes a request back from the queue of a service only when
     * the request waits there, which one processor and a service of a higher
     * level seldom allow: the count is printed, and 0 is an answer. */
    printf("posix-procs: names signal: %d handlers ran inside a rename that ended with 0, "
           "%u requests taken back by the kernel\n",
           (int)sg_hits, files_names_interrupted());

    /* b and c. Leaving by siglongjmp. Seventeen exits make the sixteen
     * places of the thread run out when nothing collects the records. */
    sg_leaves = 1;
    sg_jumps = 0;
    for (int attempt = 0; attempt < 600 && sg_jumps < 17; attempt++) {
        long delay = whole * (attempt % 9 + 1) / 10;
        int left = 0;
        int from_new = sg_exists(SG_NEW);
        int result = sg_try(delay, &left, from_new);
        SG_CHECK(result == 0);
        if (left && sg_jumps <= 3) {
            /* The next operation, in the main frame, collects the record. */
            SG_CHECK(access(SG_BASE, F_OK) == 0);
            SG_CHECK(files_names_places_in_use() == 0);
            SG_CHECK(sg_one_name());
        }
    }
    SG_CHECK(sg_jumps >= 17);
    SG_CHECK(access(SG_BASE, F_OK) == 0);
    SG_CHECK(files_names_places_in_use() == 0);
    SG_CHECK(sg_one_name());
    sg_leaves = 0;
    for (int i = 0; i < 20; i++) SG_CHECK(sg_plain() == 0);
    SG_CHECK(sg_remove() == 0);
    printf("posix-procs: names signal ok, %d exits by siglongjmp\n", (int)sg_jumps);
    return 0;
}
