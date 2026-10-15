/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The probe of message queues, semaphores and shared memory: the queues of
 * POSIX and XSI, the semaphores of POSIX (named) and XSI, the segments. Each
 * section checks a property and says which line failed. */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("posix-ipc: line %d: %s errno %d\n", __LINE__, #c, errno); fflush(stdout); return 20; } } while (0)
#define RUN(f) do { int r = f(); if (r) return r; printf("posix-ipc: " #f " ok\n"); fflush(stdout); } while (0)

static void pause_ms(long ms) {
    struct timespec t = {0, ms * 1000000L};
    nanosleep(&t, NULL);
}

static long long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static struct timespec after_ms(long ms) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    t.tv_nsec += ms * 1000000L;
    while (t.tv_nsec >= 1000000000L) {
        t.tv_nsec -= 1000000000L;
        t.tv_sec++;
    }
    return t;
}

static int wait_ok(pid_t pid) {
    int status = 0;
    return waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static mqd_t make(const char *name, long maxmsg, long msgsize, int flags) {
    struct mq_attr a;
    memset(&a, 0, sizeof a);
    a.mq_maxmsg = maxmsg;
    a.mq_msgsize = msgsize;
    mq_unlink(name);
    return mq_open(name, O_CREAT | O_EXCL | O_RDWR | flags, 0600, &a);
}

/* The order of a queue, its attributes, its refusals and its names. */
static int mq_order(void) {
    mqd_t q = make("/ipc-order", 4, 4, 0);
    CHECK(q != (mqd_t)-1);
    CHECK(mq_send(q, "aaa", 3, 1) == 0);
    CHECK(mq_send(q, "bbb", 3, 1) == 0);
    CHECK(mq_send(q, "ccc", 3, 7) == 0);
    CHECK(mq_send(q, "ddd", 3, 1) == 0);
    struct mq_attr a;
    CHECK(mq_getattr(q, &a) == 0 && a.mq_curmsgs == 4 && a.mq_maxmsg == 4 && a.mq_msgsize == 4 && a.mq_flags == 0);
    char buf[4];
    unsigned prio = 99;
    errno = 0;
    CHECK(mq_receive(q, buf, 3, &prio) == -1 && errno == EMSGSIZE);
    const char *want = "cabd";
    unsigned prios[4] = {7, 1, 1, 1};
    for (int i = 0; i < 4; i++) {
        CHECK(mq_receive(q, buf, sizeof buf, &prio) == 3);
        CHECK(buf[0] == want[i] && prio == prios[i]);
    }
    /* Too long, a priority out of range, a full queue and an empty one. */
    errno = 0;
    CHECK(mq_send(q, "12345", 5, 0) == -1 && errno == EMSGSIZE);
    errno = 0;
    CHECK(mq_send(q, "x", 1, 40000) == -1 && errno == EINVAL);
    struct mq_attr nb;
    memset(&nb, 0, sizeof nb);
    nb.mq_flags = O_NONBLOCK;
    CHECK(mq_setattr(q, &nb, &a) == 0 && a.mq_flags == 0);
    errno = 0;
    CHECK(mq_receive(q, buf, sizeof buf, NULL) == -1 && errno == EAGAIN);
    for (int i = 0; i < 4; i++) CHECK(mq_send(q, "z", 1, 0) == 0);
    errno = 0;
    CHECK(mq_send(q, "z", 1, 0) == -1 && errno == EAGAIN);
    CHECK(mq_getattr(q, &a) == 0 && (a.mq_flags & O_NONBLOCK) && a.mq_curmsgs == 4);
    /* The names. */
    errno = 0;
    CHECK(mq_open("/ipc-order", O_CREAT | O_EXCL | O_RDWR, 0600, NULL) == (mqd_t)-1 && errno == EEXIST);
    errno = 0;
    CHECK(mq_open("/ipc-none", O_RDWR) == (mqd_t)-1 && errno == ENOENT);
    errno = 0;
    CHECK(mq_open("noslash", O_RDWR) == (mqd_t)-1 && errno == EINVAL);
    errno = 0;
    CHECK(mq_unlink("/ipc-none") == -1 && errno == ENOENT);
    mqd_t same = mq_open("/ipc-order", O_RDONLY);
    CHECK(same != (mqd_t)-1);
    errno = 0;
    CHECK(mq_send(same, "z", 1, 0) == -1 && errno == EBADF);
    /* A queue taken out of its name lives while it is open. */
    CHECK(mq_unlink("/ipc-order") == 0);
    errno = 0;
    CHECK(mq_open("/ipc-order", O_RDWR) == (mqd_t)-1 && errno == ENOENT);
    CHECK(mq_receive(same, buf, sizeof buf, NULL) == 1 && buf[0] == 'z');
    CHECK(mq_close(same) == 0 && mq_close(q) == 0);
    errno = 0;
    CHECK(mq_close(q) == -1 && errno == EBADF);
    errno = 0;
    CHECK(mq_send(q, "z", 1, 0) == -1 && errno == EBADF);
    /* A descriptor of a queue is neither read nor written. */
    q = make("/ipc-order", 1, 1, 0);
    CHECK(q != (mqd_t)-1);
    errno = 0;
    CHECK(read(q, buf, 1) == -1 && errno != 0);
    errno = 0;
    CHECK(write(q, buf, 1) == -1 && errno != 0);
    CHECK(mq_close(q) == 0 && mq_unlink("/ipc-order") == 0);
    /* The sizes asked for. */
    struct mq_attr bad = {.mq_maxmsg = 0, .mq_msgsize = 4};
    errno = 0;
    CHECK(mq_open("/ipc-bad", O_CREAT | O_RDWR, 0600, &bad) == (mqd_t)-1 && errno == EINVAL);
    bad.mq_maxmsg = 100;
    errno = 0;
    CHECK(mq_open("/ipc-bad", O_CREAT | O_RDWR, 0600, &bad) == (mqd_t)-1 && errno == EINVAL);
    return 0;
}

/* Operations that wait, in two processes, and the timed ones. */
static int mq_blocking(void) {
    mqd_t q = make("/ipc-wait", 1, 8, 0);
    CHECK(q != (mqd_t)-1);
    char buf[8];
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        pause_ms(30);
        _exit(mq_send(q, "late", 4, 3) == 0 ? 0 : 1);
    }
    unsigned prio = 0;
    long long began = now_ms();
    CHECK(mq_receive(q, buf, sizeof buf, &prio) == 4 && memcmp(buf, "late", 4) == 0 && prio == 3);
    CHECK(now_ms() - began >= 20);
    CHECK(wait_ok(pid));
    /* A sender waits for room, and a receive in another process makes it. */
    CHECK(mq_send(q, "one", 3, 0) == 0);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        pause_ms(30);
        _exit(mq_receive(q, buf, sizeof buf, NULL) == 3 ? 0 : 1);
    }
    began = now_ms();
    CHECK(mq_send(q, "two", 3, 0) == 0);
    CHECK(now_ms() - began >= 20);
    CHECK(wait_ok(pid));
    CHECK(mq_receive(q, buf, sizeof buf, NULL) == 3 && memcmp(buf, "two", 3) == 0);
    /* The timed receive ends at its time, the timed send too. */
    struct timespec until = after_ms(60);
    began = now_ms();
    errno = 0;
    CHECK(mq_timedreceive(q, buf, sizeof buf, NULL, &until) == -1 && errno == ETIMEDOUT);
    CHECK(now_ms() - began >= 50);
    CHECK(mq_send(q, "full", 4, 0) == 0);
    until = after_ms(40);
    errno = 0;
    CHECK(mq_timedsend(q, "more", 4, 0, &until) == -1 && errno == ETIMEDOUT);
    /* A time that has passed does not matter where the call can go on. */
    until = after_ms(-5);
    CHECK(mq_timedreceive(q, buf, sizeof buf, NULL, &until) == 4);
    CHECK(mq_timedsend(q, "ok", 2, 0, &until) == 0);
    until.tv_nsec = 1000000000L;
    errno = 0;
    CHECK(mq_timedreceive(q, buf, sizeof buf, NULL, &until) == -1 && errno == EINVAL);
    CHECK(mq_close(q) == 0 && mq_unlink("/ipc-wait") == 0);
    return 0;
}

static volatile int alarmed;
static void on_alarm(int s) { (void)s; alarmed++; }

static void *receiver(void *arg) {
    char buf[8];
    mq_receive(*(mqd_t *)arg, buf, sizeof buf, NULL);
    return NULL;
}

/* A signal ends a wait; a cancellation does too. */
static int mq_interrupts(void) {
    mqd_t q = make("/ipc-intr", 1, 8, 0);
    CHECK(q != (mqd_t)-1);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alarm;
    CHECK(sigaction(SIGALRM, &sa, NULL) == 0);
    char buf[8];
    alarmed = 0;
    alarm(1);
    errno = 0;
    CHECK(mq_receive(q, buf, sizeof buf, NULL) == -1 && errno == EINTR && alarmed == 1);
    /* The service lost the operation: a message still goes to the next receive. */
    CHECK(mq_send(q, "back", 4, 0) == 0);
    CHECK(mq_receive(q, buf, sizeof buf, NULL) == 4);
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, receiver, &q) == 0);
    pause_ms(30);
    CHECK(pthread_cancel(thread) == 0);
    void *result = NULL;
    CHECK(pthread_join(thread, &result) == 0 && result == PTHREAD_CANCELED);
    /* The cancelled receive left nothing behind: a message is still there. */
    CHECK(mq_send(q, "kept", 4, 0) == 0);
    CHECK(mq_receive(q, buf, sizeof buf, NULL) == 4 && memcmp(buf, "kept", 4) == 0);
    CHECK(mq_close(q) == 0 && mq_unlink("/ipc-intr") == 0);
    return 0;
}

/* A child gets the descriptors; one that goes gives them back. */
static int mq_fork(void) {
    mqd_t q = make("/ipc-fork", 2, 8, 0);
    CHECK(q != (mqd_t)-1);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) _exit(mq_send(q, "child", 5, 1) == 0 ? 0 : 1);
    CHECK(wait_ok(pid));
    char buf[8];
    CHECK(mq_receive(q, buf, sizeof buf, NULL) == 5 && memcmp(buf, "child", 5) == 0);
    /* The queue is unlinked and the parent closes: the child still holds it. */
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        pause_ms(60);
        _exit(mq_send(q, "alive", 5, 0) == 0 ? 0 : 1);
    }
    mqd_t other = mq_open("/ipc-fork", O_RDONLY);
    CHECK(other != (mqd_t)-1);
    CHECK(mq_unlink("/ipc-fork") == 0);
    CHECK(mq_close(q) == 0);
    CHECK(mq_receive(other, buf, sizeof buf, NULL) == 5 && memcmp(buf, "alive", 5) == 0);
    CHECK(wait_ok(pid));
    CHECK(mq_close(other) == 0);
    /* Processes that go with queues open: the table has room for all. */
    for (int i = 0; i < 20; i++) {
        char name[32];
        snprintf(name, sizeof name, "/ipc-die-%d", i % 3);
        mqd_t d = make(name, 1, 1, 0);
        CHECK(d != (mqd_t)-1);
        pid = fork();
        CHECK(pid >= 0);
        if (pid == 0) _exit(0);
        CHECK(wait_ok(pid));
        CHECK(mq_close(d) == 0 && mq_unlink(name) == 0);
    }
    /* A queue left open by a process that goes is not kept. */
    for (int i = 0; i < 12; i++) {
        pid = fork();
        CHECK(pid >= 0);
        if (pid == 0) {
            mqd_t d = make("/ipc-orphan", 1, 1, 0);
            _exit(d == (mqd_t)-1 || mq_unlink("/ipc-orphan") != 0 ? 1 : 0);
        }
        CHECK(wait_ok(pid));
    }
    mqd_t again = make("/ipc-orphan", 1, 1, 0);
    CHECK(again != (mqd_t)-1);
    CHECK(mq_close(again) == 0 && mq_unlink("/ipc-orphan") == 0);
    return 0;
}

static volatile int got_usr1, got_value;
static void on_usr1(int s, siginfo_t *info, void *context) {
    (void)s; (void)context;
    got_usr1++;
    got_value = info->si_value.sival_int;
}

static volatile int thread_calls;
static void on_thread(union sigval v) { thread_calls += v.sival_int; }

/* The notification: once, for the first message of an empty queue. */
static int mq_notifies(void) {
    mqd_t q = make("/ipc-note", 4, 8, 0);
    CHECK(q != (mqd_t)-1);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_usr1;
    sa.sa_flags = SA_SIGINFO;
    CHECK(sigaction(SIGUSR1, &sa, NULL) == 0);
    sigset_t block, old;
    sigemptyset(&block);
    sigaddset(&block, SIGUSR1);
    CHECK(sigprocmask(SIG_BLOCK, &block, &old) == 0);
    struct sigevent ev;
    memset(&ev, 0, sizeof ev);
    ev.sigev_notify = SIGEV_SIGNAL;
    ev.sigev_signo = SIGUSR1;
    ev.sigev_value.sival_int = 77;
    CHECK(mq_notify(q, &ev) == 0);
    errno = 0;
    CHECK(mq_notify(q, &ev) == -1 && errno == EBUSY);
    got_usr1 = 0;
    CHECK(mq_send(q, "one", 3, 0) == 0);
    sigset_t wait = old;
    sigdelset(&wait, SIGUSR1);
    alarmed = 0;
    struct sigaction al;
    memset(&al, 0, sizeof al);
    al.sa_handler = on_alarm;
    CHECK(sigaction(SIGALRM, &al, NULL) == 0);
    alarm(2);
    while (!got_usr1 && !alarmed) sigsuspend(&wait);
    alarm(0);
    CHECK(got_usr1 == 1 && got_value == 77);
    /* Once only: a second message to a queue with one in it sends nothing. */
    CHECK(mq_send(q, "two", 3, 0) == 0);
    pause_ms(40);
    sigpending(&wait);
    CHECK(!sigismember(&wait, SIGUSR1));
    /* Registered again and removed again: nothing comes. */
    char buf[8];
    CHECK(mq_receive(q, buf, sizeof buf, NULL) == 3 && mq_receive(q, buf, sizeof buf, NULL) == 3);
    CHECK(mq_notify(q, &ev) == 0);
    CHECK(mq_notify(q, NULL) == 0);
    CHECK(mq_send(q, "x", 1, 0) == 0);
    pause_ms(40);
    sigpending(&wait);
    CHECK(!sigismember(&wait, SIGUSR1));
    CHECK(mq_receive(q, buf, sizeof buf, NULL) == 1);
    /* Not while a receiver waits: it takes the message. */
    CHECK(mq_notify(q, &ev) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        pause_ms(50);
        _exit(mq_send(q, "y", 1, 0) == 0 ? 0 : 1);
    }
    struct timespec until = after_ms(2000);
    CHECK(mq_timedreceive(q, buf, sizeof buf, NULL, &until) == 1);
    CHECK(wait_ok(pid));
    pause_ms(40);
    sigpending(&wait);
    CHECK(!sigismember(&wait, SIGUSR1));
    CHECK(mq_notify(q, NULL) == 0);
    /* A function in a thread. */
    memset(&ev, 0, sizeof ev);
    ev.sigev_notify = SIGEV_THREAD;
    ev.sigev_notify_function = on_thread;
    ev.sigev_value.sival_int = 5;
    CHECK(mq_notify(q, &ev) == 0);
    CHECK(mq_send(q, "t", 1, 0) == 0);
    for (int i = 0; i < 100 && thread_calls == 0; i++) pause_ms(20);
    CHECK(thread_calls == 5);
    CHECK(mq_close(q) == 0 && mq_unlink("/ipc-note") == 0);
    CHECK(sigprocmask(SIG_SETMASK, &old, NULL) == 0);
    return 0;
}

struct text {
    long type;
    char text[16];
};

static int msg_basics(void) {
    int id = msgget(IPC_PRIVATE, 0600);
    CHECK(id > 0);
    struct msqid_ds ds;
    CHECK(msgctl(id, IPC_STAT, &ds) == 0);
    CHECK(ds.msg_perm.uid == geteuid() && ds.msg_perm.cuid == geteuid() && ds.msg_perm.gid == getegid());
    CHECK((ds.msg_perm.mode & 0777) == 0600 && ds.msg_qnum == 0 && ds.msg_lspid == 0 && ds.msg_stime == 0);
    /* Types: a given one, the lowest below a bound, the first. */
    struct text m = {3, "three"}, in;
    CHECK(msgsnd(id, &m, 6, 0) == 0);
    m.type = 1; strcpy(m.text, "one");
    CHECK(msgsnd(id, &m, 4, 0) == 0);
    m.type = 2; strcpy(m.text, "two");
    CHECK(msgsnd(id, &m, 4, 0) == 0);
    CHECK(msgctl(id, IPC_STAT, &ds) == 0 && ds.msg_qnum == 3 && ds.msg_lspid == getpid() && ds.msg_stime != 0);
    CHECK(msgrcv(id, &in, sizeof in.text, 2, 0) == 4 && in.type == 2 && strcmp(in.text, "two") == 0);
    CHECK(msgrcv(id, &in, sizeof in.text, -3, 0) == 4 && in.type == 1);
    CHECK(msgrcv(id, &in, sizeof in.text, 0, 0) == 6 && in.type == 3 && strcmp(in.text, "three") == 0);
    CHECK(msgctl(id, IPC_STAT, &ds) == 0 && ds.msg_qnum == 0 && ds.msg_lrpid == getpid() && ds.msg_rtime != 0);
    /* Nothing there, a text that does not fit, the text cut. */
    errno = 0;
    CHECK(msgrcv(id, &in, sizeof in.text, 0, IPC_NOWAIT) == -1 && errno == ENOMSG);
    m.type = 4; strcpy(m.text, "longer");
    CHECK(msgsnd(id, &m, 7, 0) == 0);
    errno = 0;
    CHECK(msgrcv(id, &in, 3, 0, 0) == -1 && errno == E2BIG);
    CHECK(msgrcv(id, &in, 3, 0, MSG_NOERROR) == 3 && memcmp(in.text, "lon", 3) == 0);
    /* Refusals. */
    m.type = 0;
    errno = 0;
    CHECK(msgsnd(id, &m, 1, 0) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(msgsnd(id, &m, 100000, 0) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(msgsnd(id + 1000, &m, 1, 0) == -1 && errno == EINVAL);
    /* A full queue: by the bytes. */
    char big[512 + 8];
    memset(big, 'x', sizeof big);
    *(long *)big = 1;
    int sent = 0;
    for (;;) {
        if (msgsnd(id, big, 512, IPC_NOWAIT) != 0) break;
        sent++;
    }
    CHECK(errno == EAGAIN && sent >= 8 && sent <= 17);
    CHECK(msgctl(id, IPC_RMID, NULL) == 0);
    errno = 0;
    CHECK(msgctl(id, IPC_STAT, &ds) == -1 && errno == EINVAL);
    /* A key finds the same queue. */
    key_t key = 0x4242;
    int a = msgget(key, IPC_CREAT | 0600);
    CHECK(a > 0 && msgget(key, 0) == a);
    errno = 0;
    CHECK(msgget(key, IPC_CREAT | IPC_EXCL | 0600) == -1 && errno == EEXIST);
    CHECK(msgctl(a, IPC_RMID, NULL) == 0);
    errno = 0;
    CHECK(msgget(key, 0) == -1 && errno == ENOENT);
    /* IPC_SET changes the owner and the mode. */
    a = msgget(IPC_PRIVATE, 0600);
    CHECK(a > 0 && msgctl(a, IPC_STAT, &ds) == 0);
    ds.msg_perm.mode = 0640;
    CHECK(msgctl(a, IPC_SET, &ds) == 0 && msgctl(a, IPC_STAT, &ds) == 0 && (ds.msg_perm.mode & 0777) == 0640);
    CHECK(msgctl(a, IPC_RMID, NULL) == 0);
    return 0;
}

static int msg_processes(void) {
    int id = msgget(IPC_PRIVATE, 0600);
    CHECK(id > 0);
    struct text m = {9, "from"}, in;
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        pause_ms(30);
        _exit(msgsnd(id, &m, 5, 0) == 0 ? 0 : 1);
    }
    long long began = now_ms();
    CHECK(msgrcv(id, &in, sizeof in.text, 9, 0) == 5 && strcmp(in.text, "from") == 0);
    CHECK(now_ms() - began >= 20);
    CHECK(wait_ok(pid));
    /* A queue removed under a receiver that waits: EIDRM. */
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        errno = 0;
        ssize_t got = msgrcv(id, &in, sizeof in.text, 0, 0);
        int why = errno;
        if (got != -1 || why != EIDRM) printf("posix-ipc: the waiter got %zd errno %d\n", got, why);
        _exit(got == -1 && why == EIDRM ? 0 : 1);
    }
    pause_ms(40);
    CHECK(msgctl(id, IPC_RMID, NULL) == 0);
    CHECK(wait_ok(pid));
    /* A sender waits for room and a receive in another process makes it. */
    id = msgget(IPC_PRIVATE, 0600);
    CHECK(id > 0);
    char big[512 + 8];
    memset(big, 'x', sizeof big);
    *(long *)big = 1;
    while (msgsnd(id, big, 512, IPC_NOWAIT) == 0) {}
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        pause_ms(30);
        _exit(msgrcv(id, big, 512, 0, 0) == 512 ? 0 : 1);
    }
    CHECK(msgsnd(id, big, 512, 0) == 0);
    CHECK(wait_ok(pid));
    /* Another user: the mode refuses it. */
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        if (setuid(1234) != 0) _exit(2);
        errno = 0;
        int refused = msgsnd(id, big, 1, IPC_NOWAIT) == -1 && errno == EACCES;
        errno = 0;
        refused = refused && msgctl(id, IPC_RMID, NULL) == -1 && errno == EPERM;
        _exit(refused ? 0 : 1);
    }
    CHECK(wait_ok(pid));
    CHECK(msgctl(id, IPC_RMID, NULL) == 0);
    return 0;
}

union semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
};

static int sem_basics(void) {
    int id = semget(IPC_PRIVATE, 3, 0600);
    CHECK(id > 0);
    union semun arg;
    struct semid_ds ds;
    arg.buf = &ds;
    CHECK(semctl(id, 0, IPC_STAT, arg) == 0 && ds.sem_nsems == 3 && ds.sem_perm.uid == geteuid() && ds.sem_otime == 0);
    arg.val = 2;
    CHECK(semctl(id, 0, SETVAL, arg) == 0);
    CHECK(semctl(id, 0, GETVAL) == 2 && semctl(id, 1, GETVAL) == 0);
    /* All or none. */
    struct sembuf two[2] = {{0, -1, 0}, {1, -1, IPC_NOWAIT}};
    errno = 0;
    CHECK(semop(id, two, 2) == -1 && errno == EAGAIN);
    CHECK(semctl(id, 0, GETVAL) == 2);
    arg.val = 1;
    CHECK(semctl(id, 1, SETVAL, arg) == 0);
    CHECK(semop(id, two, 2) == 0 && semctl(id, 0, GETVAL) == 1 && semctl(id, 1, GETVAL) == 0);
    CHECK(semctl(id, 0, GETPID) == getpid());
    arg.buf = &ds;
    CHECK(semctl(id, 0, IPC_STAT, arg) == 0 && ds.sem_otime != 0);
    /* Wait for zero. */
    struct sembuf zero = {1, 0, 0};
    CHECK(semop(id, &zero, 1) == 0);
    struct sembuf nz = {0, 0, IPC_NOWAIT};
    errno = 0;
    CHECK(semop(id, &nz, 1) == -1 && errno == EAGAIN);
    /* Range and number. */
    struct sembuf up = {0, 32767, 0};
    errno = 0;
    CHECK(semop(id, &up, 1) == -1 && errno == ERANGE);
    struct sembuf far = {3, 1, 0};
    errno = 0;
    CHECK(semop(id, &far, 1) == -1 && errno == EFBIG);
    errno = 0;
    CHECK(semget(IPC_PRIVATE, 0, 0600) == -1 && errno == EINVAL);
    arg.val = 40000;
    errno = 0;
    CHECK(semctl(id, 0, SETVAL, arg) == -1 && errno == ERANGE);
    /* All values. */
    unsigned short values[3] = {5, 6, 7}, back[3];
    arg.array = values;
    CHECK(semctl(id, 0, SETALL, arg) == 0);
    arg.array = back;
    CHECK(semctl(id, 0, GETALL, arg) == 0 && back[0] == 5 && back[1] == 6 && back[2] == 7);
    CHECK(semctl(id, 0, IPC_RMID) == 0);
    errno = 0;
    CHECK(semctl(id, 0, GETVAL) == -1 && errno == EINVAL);
    /* A key. */
    int k = semget(0x5151, 2, IPC_CREAT | 0600);
    CHECK(k > 0 && semget(0x5151, 1, 0) == k);
    errno = 0;
    CHECK(semget(0x5151, 5, 0) == -1 && errno == EINVAL);
    CHECK(semctl(k, 0, IPC_RMID) == 0);
    return 0;
}

static int sem_processes(void) {
    int id = semget(IPC_PRIVATE, 1, 0600);
    CHECK(id > 0);
    union semun arg;
    struct sembuf take = {0, -1, 0}, give = {0, 1, 0};
    /* A wait for the semaphore, a count of the waiting, and the release. */
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) _exit(semop(id, &take, 1) == 0 ? 0 : 1);
    pause_ms(40);
    CHECK(semctl(id, 0, GETNCNT) == 1 && semctl(id, 0, GETZCNT) == 0);
    CHECK(semop(id, &give, 1) == 0);
    CHECK(wait_ok(pid));
    CHECK(semctl(id, 0, GETNCNT) == 0 && semctl(id, 0, GETVAL) == 0);
    /* A wait for zero. */
    arg.val = 1;
    CHECK(semctl(id, 0, SETVAL, arg) == 0);
    struct sembuf zero = {0, 0, 0};
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) _exit(semop(id, &zero, 1) == 0 ? 0 : 1);
    pause_ms(40);
    CHECK(semctl(id, 0, GETZCNT) == 1);
    CHECK(semop(id, &take, 1) == 0);
    CHECK(wait_ok(pid));
    /* SEM_UNDO: what a process that goes held is given back. */
    arg.val = 3;
    CHECK(semctl(id, 0, SETVAL, arg) == 0);
    struct sembuf undo = {0, -2, SEM_UNDO};
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) _exit(semop(id, &undo, 1) == 0 && semctl(id, 0, GETVAL) == 1 ? 0 : 1);
    CHECK(wait_ok(pid));
    CHECK(semctl(id, 0, GETVAL) == 3);
    /* A child does not inherit the adjustments of its parent. */
    CHECK(semop(id, &undo, 1) == 0 && semctl(id, 0, GETVAL) == 1);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) _exit(0);
    CHECK(wait_ok(pid));
    CHECK(semctl(id, 0, GETVAL) == 1);
    /* A removed set wakes the waiter with EIDRM. */
    arg.val = 0;
    CHECK(semctl(id, 0, SETVAL, arg) == 0);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        errno = 0;
        _exit(semop(id, &take, 1) == -1 && errno == EIDRM ? 0 : 1);
    }
    pause_ms(40);
    CHECK(semctl(id, 0, IPC_RMID) == 0);
    CHECK(wait_ok(pid));
    return 0;
}

static int shm_basics(void) {
    long page = sysconf(_SC_PAGESIZE);
    int id = shmget(IPC_PRIVATE, 3 * page, 0600);
    CHECK(id > 0);
    struct shmid_ds ds;
    CHECK(shmctl(id, IPC_STAT, &ds) == 0);
    CHECK(ds.shm_segsz == (size_t)(3 * page) && ds.shm_nattch == 0 && ds.shm_cpid == getpid() && ds.shm_lpid == 0);
    CHECK(ds.shm_perm.uid == geteuid() && (ds.shm_perm.mode & 0777) == 0600);
    char *p = shmat(id, NULL, 0);
    CHECK(p != (char *)-1);
    CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 1 && ds.shm_lpid == getpid() && ds.shm_atime != 0);
    memset(p, 'a', 3 * page);
    char *q = shmat(id, NULL, SHM_RDONLY);
    CHECK(q != (char *)-1 && q != p);
    CHECK(q[0] == 'a' && q[3 * page - 1] == 'a');
    p[5] = 'b';
    CHECK(q[5] == 'b');
    /* A child shares the pages (fork copies the attachment). */
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        p[6] = 'c';
        _exit(shmdt(p) == 0 ? 0 : 1);
    }
    CHECK(wait_ok(pid));
    CHECK(p[6] == 'c');
    CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 2);
    CHECK(shmdt(q) == 0);
    CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 1 && ds.shm_dtime != 0);
    errno = 0;
    CHECK(shmdt(q) == -1 && errno == EINVAL);
    /* Removed while attached: the segment stays for those who have it, and
     * no one attaches it anew. */
    CHECK(shmctl(id, IPC_RMID, NULL) == 0);
    CHECK(p[0] == 'a');
    errno = 0;
    CHECK(shmat(id, NULL, 0) == (void *)-1 && errno == EIDRM);
    CHECK(shmdt(p) == 0);
    errno = 0;
    CHECK(shmctl(id, IPC_STAT, &ds) == -1 && errno == EINVAL);
    /* Keys and sizes. */
    int a = shmget(0x6161, page, IPC_CREAT | 0600);
    CHECK(a > 0 && shmget(0x6161, page, 0) == a);
    errno = 0;
    CHECK(shmget(0x6161, 2 * page, 0) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(shmget(0x6161, page, IPC_CREAT | IPC_EXCL) == -1 && errno == EEXIST);
    errno = 0;
    CHECK(shmget(IPC_PRIVATE, 0, 0600) == -1 && errno == EINVAL);
    CHECK(shmctl(a, IPC_RMID, NULL) == 0);
    errno = 0;
    CHECK(shmget(0x6161, page, 0) == -1 && errno == ENOENT);
    return 0;
}

/* Another process attaches a segment by its key, writes, goes; the data stays. */
static int shm_processes(void) {
    long page = sysconf(_SC_PAGESIZE);
    int id = shmget(0x7171, page, IPC_CREAT | 0600);
    CHECK(id > 0);
    char *p = shmat(id, NULL, 0);
    CHECK(p != (char *)-1);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        int mine = shmget(0x7171, page, 0);
        char *c = shmat(mine, NULL, 0);
        if (mine != id || c == (char *)-1) _exit(1);
        strcpy(c, "written by the child");
        _exit(0);
    }
    CHECK(wait_ok(pid));
    CHECK(strcmp(p, "written by the child") == 0);
    /* The child went with its attachment: only the parent's is counted. */
    struct shmid_ds ds;
    CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 1);
    CHECK(shmdt(p) == 0 && shmctl(id, IPC_RMID, NULL) == 0);
    return 0;
}

static int named_semaphores(void) {
    sem_unlink("/ipc-sem");
    sem_t *s = sem_open("/ipc-sem", O_CREAT | O_EXCL, 0600, 1);
    CHECK(s != SEM_FAILED);
    errno = 0;
    CHECK(sem_open("/ipc-sem", O_CREAT | O_EXCL, 0600, 1) == SEM_FAILED && errno == EEXIST);
    sem_t *t = sem_open("/ipc-sem", 0);
    CHECK(t == s);
    int v = -1;
    CHECK(sem_getvalue(s, &v) == 0 && v == 1);
    CHECK(sem_wait(s) == 0 && sem_getvalue(s, &v) == 0 && v == 0);
    errno = 0;
    CHECK(sem_trywait(s) == -1 && errno == EAGAIN);
    struct timespec until = after_ms(50);
    long long began = now_ms();
    errno = 0;
    CHECK(sem_timedwait(s, &until) == -1 && errno == ETIMEDOUT && now_ms() - began >= 40);
    /* Two processes. */
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        pause_ms(30);
        _exit(sem_post(s) == 0 ? 0 : 1);
    }
    CHECK(sem_wait(s) == 0);
    CHECK(wait_ok(pid));
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        sem_t *c = sem_open("/ipc-sem", 0);
        if (c == SEM_FAILED) _exit(2);
        pause_ms(30);
        int r = sem_post(c);
        sem_close(c);
        _exit(r == 0 ? 0 : 1);
    }
    until = after_ms(2000);
    CHECK(sem_timedwait(s, &until) == 0);
    CHECK(wait_ok(pid));
    /* A name by itself: the semaphore lives while it is open. */
    CHECK(sem_post(s) == 0);
    CHECK(sem_unlink("/ipc-sem") == 0);
    errno = 0;
    CHECK(sem_open("/ipc-sem", 0) == SEM_FAILED && errno == ENOENT);
    errno = 0;
    CHECK(sem_unlink("/ipc-sem") == -1 && errno == ENOENT);
    CHECK(sem_wait(s) == 0);
    CHECK(sem_close(t) == 0 && sem_close(s) == 0);
    sem_t *fresh = sem_open("/ipc-sem", O_CREAT, 0600, 0);
    CHECK(fresh != SEM_FAILED && sem_getvalue(fresh, &v) == 0 && v == 0);
    CHECK(sem_close(fresh) == 0 && sem_unlink("/ipc-sem") == 0);
    errno = 0;
    CHECK(sem_open("nameless", O_CREAT, 0600, 0) == SEM_FAILED && errno == EINVAL);
    errno = 0;
    CHECK(sem_open("/ipc-big", O_CREAT, 0600, 40000) == SEM_FAILED && errno == EINVAL);
    /* A process that goes with the semaphore open does not keep it. */
    for (int i = 0; i < 12; i++) {
        pid = fork();
        CHECK(pid >= 0);
        if (pid == 0) {
            sem_t *x = sem_open("/ipc-gone", O_CREAT, 0600, 1);
            _exit(x == SEM_FAILED || sem_unlink("/ipc-gone") != 0 ? 1 : 0);
        }
        CHECK(wait_ok(pid));
    }
    return 0;
}

/* The tables have room for what a root may have, and no more. */
static int limits(void) {
    int ids[16], n = 0;
    for (;; n++) {
        if (n == 16) return 21;
        ids[n] = msgget(IPC_PRIVATE, 0600);
        if (ids[n] < 0) break;
    }
    CHECK(errno == ENOSPC && n >= 4 && n <= 8);
    for (int i = 0; i < n; i++) CHECK(msgctl(ids[i], IPC_RMID, NULL) == 0);
    int one = msgget(IPC_PRIVATE, 0600);
    CHECK(one > 0 && msgctl(one, IPC_RMID, NULL) == 0);
    mqd_t qs[16];
    int m = 0;
    for (;; m++) {
        char name[32];
        snprintf(name, sizeof name, "/ipc-lim-%d", m);
        if (m == 16) return 22;
        qs[m] = make(name, 1, 1, 0);
        if (qs[m] == (mqd_t)-1) break;
    }
    CHECK(errno == ENOSPC && m >= 4 && m <= 8);
    for (int i = 0; i < m; i++) {
        char name[32];
        snprintf(name, sizeof name, "/ipc-lim-%d", i);
        CHECK(mq_close(qs[i]) == 0 && mq_unlink(name) == 0);
    }
    return 0;
}

/* The longest calls, for the steps of the service. */
static int longest_steps(void) {
    mqd_t q = make("/ipc-long", 16, 512, O_NONBLOCK);
    CHECK(q != (mqd_t)-1);
    char big[512];
    memset(big, 'm', sizeof big);
    for (int i = 0; i < 16; i++) CHECK(mq_send(q, big, sizeof big, (unsigned)(i % 5)) == 0);
    for (int i = 0; i < 16; i++) CHECK(mq_receive(q, big, sizeof big, NULL) == 512);
    CHECK(mq_close(q) == 0 && mq_unlink("/ipc-long") == 0);
    int id = semget(IPC_PRIVATE, 8, 0600);
    CHECK(id > 0);
    struct sembuf ops[8];
    for (int i = 0; i < 8; i++) {
        ops[i].sem_num = (unsigned short)i;
        ops[i].sem_op = 2;
        ops[i].sem_flg = SEM_UNDO;
    }
    CHECK(semop(id, ops, 8) == 0);
    CHECK(semctl(id, 0, IPC_RMID) == 0);
    int mq = msgget(IPC_PRIVATE, 0600);
    CHECK(mq > 0);
    struct text m = {1, "x"};
    for (int i = 0; i < 15; i++) {
        m.type = 1 + i % 4;
        CHECK(msgsnd(mq, &m, 2, 0) == 0);
    }
    CHECK(msgrcv(mq, &m, sizeof m.text, 4, 0) == 2);
    CHECK(msgctl(mq, IPC_RMID, NULL) == 0);
    return 0;
}

int main(int argc, char **argv) {
    (void)argv;
    /* A file-loaded image supplies the region map required by fork. */
    if (argc == 1) {
        char *next[] = {"posix-ipc", "loaded", NULL}, *env[] = {NULL};
        execve("/bin/posix-ipc", next, env);
        CHECK(0);
    }
    printf("posix-ipc: start\n");
    fflush(stdout);
    RUN(mq_order);
    RUN(mq_blocking);
    RUN(mq_interrupts);
    RUN(mq_fork);
    RUN(mq_notifies);
    RUN(msg_basics);
    RUN(msg_processes);
    RUN(sem_basics);
    RUN(sem_processes);
    RUN(shm_basics);
    RUN(shm_processes);
    RUN(named_semaphores);
    RUN(limits);
    RUN(longest_steps);
    printf("posix-ipc: ok\n");
    fflush(stdout);
    return 0;
}
