/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The probe of message queues, semaphores and shared memory: the queues of
 * POSIX and XSI, the semaphores of POSIX (named) and XSI, the segments. Each
 * section checks a property and says which line failed. */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/socket.h>
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

/* Waits (a second at most) until the segment is attached `n` times: the
 * attachments of a process that went are let go of in steps of the service. */
static int nattch_is(int id, unsigned long n) {
    struct shmid_ds ds;
    for (int i = 0; i < 100; i++) {
        if (shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == n) return 1;
        pause_ms(10);
    }
    return 0;
}

/* The files of segments in /dev/shm: how many, and the first one's name. */
static int sysv_files(char *first, size_t size) {
    DIR *dir = opendir("/dev/shm");
    int n = 0;
    struct dirent *e;
    if (!dir) return -1;
    while ((e = readdir(dir)) != NULL) {
        if (strncmp(e->d_name, ".sysv", 5) != 0) continue;
        if (n == 0 && first) snprintf(first, size, "/dev/shm/%s", e->d_name);
        n++;
    }
    closedir(dir);
    return n;
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
    /* A child that closes its copy of the descriptor leaves its parent's registration. */
    CHECK(mq_notify(q, &ev) == 0);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) _exit(mq_close(q) == 0 ? 0 : 1);
    CHECK(wait_ok(pid));
    errno = 0;
    CHECK(mq_notify(q, &ev) == -1 && errno == EBUSY);
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
    CHECK(nattch_is(id, 2));
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
    CHECK(nattch_is(id, 1));
    CHECK(shmdt(p) == 0 && shmctl(id, IPC_RMID, NULL) == 0);
    return 0;
}


/* IPC_SET of a segment is the pipe service's: the library changes no file (#344).
 * An unprivileged owner hands a segment to another user, whose uid the file of
 * the segment has when shmctl returns, and who removes it. (The creator that
 * removes a segment after the superuser gave it away is shm_files_of_the_dead.)
 * The services give the file of the segment its new owner. */
static int shm_hand_over(void) {
    long page = sysconf(_SC_PAGESIZE);
    int id = shmget(IPC_PRIVATE, page, 0666);
    CHECK(id > 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        /* The owner (1234) gives the segment to 4321 and cannot remove it. */
        struct shmid_ds ds;
        if (shmctl(id, IPC_STAT, &ds) != 0) _exit(1);
        ds.shm_perm.uid = 1234;
        if (shmctl(id, IPC_SET, &ds) != 0) _exit(2);
        if (setgid(1234) != 0 || setuid(1234) != 0) _exit(3);
        ds.shm_perm.uid = 4321;
        if (shmctl(id, IPC_SET, &ds) != 0) _exit(4);
        errno = 0;
        if (shmctl(id, IPC_RMID, NULL) != -1 || errno != EPERM) _exit(5);
        _exit(0);
    }
    CHECK(wait_ok(pid));
    /* The file of the segment follows the segment when shmctl returns. */
    int owned = 0;
    DIR *dir = opendir("/dev/shm");
    CHECK(dir != NULL);
    for (struct dirent *e; (e = readdir(dir)) != NULL;) {
        char path[96];
        struct stat st;
        if (strncmp(e->d_name, ".sysv", 5) != 0) continue;
        snprintf(path, sizeof path, "/dev/shm/%s", e->d_name);
        if (stat(path, &st) == 0 && st.st_uid == 4321) owned++;
    }
    closedir(dir);
    CHECK(owned == 1);
    /* The new owner removes it. */
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        if (setgid(4321) != 0 || setuid(4321) != 0) _exit(1);
        _exit(shmctl(id, IPC_RMID, NULL) == 0 ? 0 : 2);
    }
    CHECK(wait_ok(pid));
    struct shmid_ds ds;
    errno = 0;
    CHECK(shmctl(id, IPC_STAT, &ds) == -1 && errno == EINVAL);
    return 0;
}

/* Who a caller is comes from the process service, not from the request: the
 * same call changes its answer when the process gives up its rights, and the
 * names of queues and semaphores are the owner's to take away. */
static int identity(void) {
    int id = msgget(IPC_PRIVATE, 0600);
    CHECK(id > 0);
    mqd_t q = make("/ipc-ident", 1, 1, 0);
    CHECK(q != (mqd_t)-1);
    sem_unlink("/ipc-ident-sem");
    sem_t *s = sem_open("/ipc-ident-sem", O_CREAT, 0600, 1);
    CHECK(s != SEM_FAILED);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        struct msqid_ds ds;
        /* As the superuser the queue is open to it. */
        if (msgctl(id, IPC_STAT, &ds) != 0) _exit(1);
        if (setuid(1234) != 0) _exit(2);
        /* The new rights count at once, with no new call to hide behind. */
        errno = 0;
        if (msgctl(id, IPC_STAT, &ds) != -1 || errno != EACCES) _exit(3);
        errno = 0;
        if (msgctl(id, IPC_RMID, NULL) != -1 || errno != EPERM) _exit(4);
        errno = 0;
        if (mq_unlink("/ipc-ident") != -1 || errno != EACCES) _exit(5);
        errno = 0;
        if (sem_unlink("/ipc-ident-sem") != -1 || errno != EACCES) _exit(6);
        errno = 0;
        if (mq_open("/ipc-ident", O_RDWR) != (mqd_t)-1 || errno != EACCES) _exit(7);
        _exit(0);
    }
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status));
    if (WEXITSTATUS(status) != 0) {
        printf("posix-ipc: the child of identity ended with %d\n", WEXITSTATUS(status));
        return 20;
    }
    CHECK(sem_close(s) == 0 && sem_unlink("/ipc-ident-sem") == 0);
    CHECK(mq_close(q) == 0 && mq_unlink("/ipc-ident") == 0);
    CHECK(msgctl(id, IPC_RMID, NULL) == 0);
    return 0;
}

/* The pages of a segment are the segment's: the file belongs to its creator
 * with the mode of the segment, and a freed segment leaves no file, also
 * when the process that held it was killed. */
static int shm_pages(void) {
    long page = sysconf(_SC_PAGESIZE);
    char path[64];
    int before = sysv_files(NULL, 0);
    CHECK(before >= 0);
    int id = shmget(IPC_PRIVATE, page, 0600);
    CHECK(id > 0 && sysv_files(path, sizeof path) == before + 1);
    struct stat st;
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600 && st.st_uid == geteuid());
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        if (setgid(1234) != 0 || setuid(1234) != 0) _exit(2);
        /* Neither the segment nor its file lets another user in. */
        errno = 0;
        if (shmat(id, NULL, 0) != (void *)-1 || errno != EACCES) _exit(3);
        errno = 0;
        if (open(path, O_RDWR) != -1 || errno != EACCES) _exit(4);
        errno = 0;
        if (open(path, O_RDONLY) != -1 || errno != EACCES) _exit(5);
        _exit(0);
    }
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status));
    if (WEXITSTATUS(status) != 0) {
        printf("posix-ipc: the child of shm_pages ended with %d\n", WEXITSTATUS(status));
        return 20;
    }
    CHECK(shmctl(id, IPC_RMID, NULL) == 0);
    CHECK(sysv_files(NULL, 0) == before);
    /* A new mode follows to the file. */
    id = shmget(IPC_PRIVATE, page, 0600);
    CHECK(id > 0 && sysv_files(path, sizeof path) == before + 1);
    struct shmid_ds ds;
    CHECK(shmctl(id, IPC_STAT, &ds) == 0);
    ds.shm_perm.mode = 0644;
    CHECK(shmctl(id, IPC_SET, &ds) == 0);
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0644);
    CHECK(shmctl(id, IPC_RMID, NULL) == 0);
    /* A process killed with the segment attached, after the removal. */
    id = shmget(IPC_PRIVATE, page, 0600);
    CHECK(id > 0);
    int ready[2];
    CHECK(pipe(ready) == 0);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        close(ready[0]);
        if (shmat(id, NULL, 0) == (void *)-1) _exit(1);
        char byte = 'x';
        if (write(ready[1], &byte, 1) != 1) _exit(2);
        for (;;) pause();
    }
    close(ready[1]);
    char byte;
    CHECK(read(ready[0], &byte, 1) == 1);
    close(ready[0]);
    CHECK(nattch_is(id, 1));
    CHECK(shmctl(id, IPC_RMID, NULL) == 0);
    CHECK(sysv_files(NULL, 0) == before + 1);
    CHECK(kill(pid, SIGKILL) == 0 && waitpid(pid, &status, 0) == pid);
    /* The service lets go of the dead one's attachment, and its next answer
     * to this user names the file that is left. */
    int again = -1;
    for (int i = 0; i < 100 && sysv_files(NULL, 0) != before; i++) {
        pause_ms(10);
        again = shmget(IPC_PRIVATE, page, 0600);
        if (again > 0) CHECK(shmctl(again, IPC_RMID, NULL) == 0);
    }
    CHECK(sysv_files(NULL, 0) == before);
    return 0;
}


static unsigned long long name_number(const char *path) {
    const char *dot = strstr(path, ".sysv");
    return dot ? strtoull(dot + 5, NULL, 16) : 0;
}

/* The file of the pages is the segment's own: its name is not to be guessed,
 * a file put in its place is refused, and a new owner or mode reaches the
 * file before the segment (or the change is refused). */
static int shm_names(void) {
    long page = sysconf(_SC_PAGESIZE);
    char first[64], second[64], both[64];
    int before = sysv_files(NULL, 0);
    CHECK(before >= 0);
    /* Names that do not follow one another. */
    int a = shmget(IPC_PRIVATE, page, 0600);
    CHECK(a > 0 && sysv_files(first, sizeof first) == before + 1);
    int b = shmget(IPC_PRIVATE, page, 0600);
    CHECK(b > 0 && sysv_files(NULL, 0) == before + 2);
    DIR *dir = opendir("/dev/shm");
    CHECK(dir != NULL);
    unsigned long long n[2] = {0, 0};
    int k = 0;
    struct dirent *e;
    while ((e = readdir(dir)) != NULL && k < 2)
        if (strncmp(e->d_name, ".sysv", 5) == 0) n[k++] = name_number(e->d_name);
    closedir(dir);
    CHECK(k == 2);
    unsigned long long gap = n[0] > n[1] ? n[0] - n[1] : n[1] - n[0];
    CHECK(gap > 1000000ULL);
    CHECK(shmctl(a, IPC_RMID, NULL) == 0 && shmctl(b, IPC_RMID, NULL) == 0);
    CHECK(sysv_files(NULL, 0) == before);
    /* A file put in the place of the real one. */
    int id = shmget(IPC_PRIVATE, page, 0600);
    CHECK(id > 0 && sysv_files(first, sizeof first) == before + 1);
    snprintf(second, sizeof second, "%s.other", first);
    snprintf(both, sizeof both, "%s.both", first);
    CHECK(unlink(first) == 0);
    int fd = open(first, O_RDWR | O_CREAT | O_EXCL, 0666);
    CHECK(fd >= 0 && ftruncate(fd, page) == 0 && fchown(fd, 1234, 1234) == 0);
    errno = 0;
    CHECK(shmat(id, NULL, 0) == (void *)-1 && errno == EACCES);
    CHECK(fchown(fd, 0, 0) == 0 && fchmod(fd, 0600) == 0);
    /* The right owner and size: the file is taken. */
    void *p = shmat(id, NULL, 0);
    CHECK(p != (void *)-1 && shmdt(p) == 0);
    /* A second link, or another size: refused. */
    CHECK(link(first, second) == 0);
    errno = 0;
    CHECK(shmat(id, NULL, 0) == (void *)-1 && errno == EACCES);
    CHECK(unlink(second) == 0 && ftruncate(fd, page + 1) == 0);
    errno = 0;
    CHECK(shmat(id, NULL, 0) == (void *)-1 && errno == EACCES);
    close(fd);
    CHECK(shmctl(id, IPC_RMID, NULL) == 0);
    unlink(first);
    CHECK(sysv_files(NULL, 0) == before);
    (void)both;
    /* A new owner by the superuser reaches the file; the mode too. */
    id = shmget(IPC_PRIVATE, page, 0600);
    CHECK(id > 0 && sysv_files(first, sizeof first) == before + 1);
    struct shmid_ds ds;
    struct stat st;
    CHECK(shmctl(id, IPC_STAT, &ds) == 0);
    ds.shm_perm.uid = 1234;
    ds.shm_perm.gid = 1234;
    ds.shm_perm.mode = 0640;
    CHECK(shmctl(id, IPC_SET, &ds) == 0);
    CHECK(stat(first, &st) == 0 && st.st_uid == 1234 && st.st_gid == 1234 && (st.st_mode & 0777) == 0640);
    CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_perm.uid == 1234 && (ds.shm_perm.mode & 0777) == 0640);
    CHECK(shmctl(id, IPC_RMID, NULL) == 0);
    /* An owner that is no superuser changes the mode of its segment, and the
     * file follows (giving the segment away is shm_hand_over's). */
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        if (setgid(1234) != 0 || setuid(1234) != 0) _exit(2);
        int mine = shmget(IPC_PRIVATE, page, 0600);
        char path[64];
        if (mine < 0 || sysv_files(path, sizeof path) != before + 1) _exit(3);
        struct shmid_ds d;
        if (shmctl(mine, IPC_STAT, &d) != 0) _exit(4);
        struct stat s2;
        /* A mode it may give, the file follows. */
        d.shm_perm.uid = 1234;
        d.shm_perm.mode = 0640;
        if (shmctl(mine, IPC_SET, &d) != 0) _exit(8);
        if (stat(path, &s2) != 0 || (s2.st_mode & 0777) != 0640) _exit(9);
        _exit(shmctl(mine, IPC_RMID, NULL) == 0 ? 0 : 10);
    }
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status));
    if (WEXITSTATUS(status) != 0) {
        printf("posix-ipc: the child of shm_names ended with %d\n", WEXITSTATUS(status));
        return 20;
    }
    CHECK(sysv_files(NULL, 0) == before);
    return 0;
}

/* A sender that waits for the pool of messages wakes when a message goes,
 * whatever queue it was in. */
static int pool_waits(void) {
    int q[3];
    for (int i = 0; i < 3; i++) {
        q[i] = msgget(IPC_PRIVATE, 0600);
        CHECK(q[i] > 0);
    }
    struct text m = {1, "x"};
    /* Two queues of 16 take the share of this tree. */
    for (int i = 0; i < 2; i++)
        for (int k = 0; k < 16; k++) CHECK(msgsnd(q[i], &m, 1, IPC_NOWAIT) == 0);
    errno = 0;
    CHECK(msgsnd(q[2], &m, 1, IPC_NOWAIT) == -1 && errno == EAGAIN);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        pause_ms(40);
        _exit(msgrcv(q[0], &m, 1, 0, 0) == 1 ? 0 : 1);
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alarm;
    CHECK(sigaction(SIGALRM, &sa, NULL) == 0);
    alarm(3);
    long long began = now_ms();
    int sent = msgsnd(q[2], &m, 1, 0);
    alarm(0);
    CHECK(sent == 0 && now_ms() - began >= 30);
    CHECK(wait_ok(pid));
    for (int i = 0; i < 3; i++) CHECK(msgctl(q[i], IPC_RMID, NULL) == 0);
    return 0;
}

/* A segment attached before fork stays attached in the child: the count
 * grows, and falls when the child goes. */
/* The files of segments whose makers went: twenty creators in a row each make a
 * segment, attach it, remove it and go without detaching, so the service frees
 * it when their session ends and nobody calls it again; no file is left in
 * /dev/shm. A creator that is given away to another owner by the superuser
 * still removes its segment, and the file with it. */
static int shm_files_of_the_dead(void) {
    long page = sysconf(_SC_PAGESIZE);
    int before = sysv_files(NULL, 0);
    CHECK(before >= 0);
    for (int i = 0; i < 20; i++) {
        pid_t pid = fork();
        CHECK(pid >= 0);
        if (pid == 0) {
            int id = shmget(IPC_PRIVATE, page, 0600);
            if (id < 0 || shmat(id, NULL, 0) == (void *)-1) _exit(2);
            _exit(shmctl(id, IPC_RMID, NULL) == 0 ? 0 : 3);
        }
        CHECK(wait_ok(pid));
    }
    int left = -1;
    for (int i = 0; i < 200; i++) {
        left = sysv_files(NULL, 0);
        if (left == before) break;
        pause_ms(10);
    }
    if (left != before) printf("posix-ipc: %d files left of %d\n", left - before, 20);
    CHECK(left == before);
    /* The creator removes what the superuser gave away. */
    int up[2], down[2];
    CHECK(pipe(up) == 0 && pipe(down) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        if (setgid(1234) != 0 || setuid(1234) != 0) _exit(2);
        int id = shmget(IPC_PRIVATE, page, 0600);
        char c;
        if (id < 0 || write(up[1], &id, sizeof id) != sizeof id) _exit(3);
        if (read(down[0], &c, 1) != 1) _exit(4);
        _exit(shmctl(id, IPC_RMID, NULL) == 0 ? 0 : 5);
    }
    int id = -1;
    CHECK(read(up[0], &id, sizeof id) == sizeof id);
    struct shmid_ds ds;
    CHECK(shmctl(id, IPC_STAT, &ds) == 0);
    ds.shm_perm.uid = 77;
    ds.shm_perm.gid = 77;
    CHECK(shmctl(id, IPC_SET, &ds) == 0);
    CHECK(sysv_files(NULL, 0) == before + 1);
    CHECK(write(down[1], "g", 1) == 1);
    CHECK(wait_ok(pid));
    CHECK(sysv_files(NULL, 0) == before);
    close(up[0]); close(up[1]); close(down[0]); close(down[1]);
    return 0;
}

static int shm_fork(void) {
    long page = sysconf(_SC_PAGESIZE);
    int id = shmget(IPC_PRIVATE, page, 0600);
    CHECK(id > 0);
    char *p = shmat(id, NULL, 0);
    CHECK(p != (char *)-1);
    int go[2];
    CHECK(pipe(go) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        struct shmid_ds ds;
        char byte;
        int ok = shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 2;
        if (read(go[0], &byte, 1) != 1) _exit(2);
        _exit(ok ? 0 : 1);
    }
    CHECK(nattch_is(id, 2));
    CHECK(write(go[1], "g", 1) == 1);
    CHECK(wait_ok(pid));
    CHECK(nattch_is(id, 1));
    CHECK(shmdt(p) == 0 && shmctl(id, IPC_RMID, NULL) == 0);
    close(go[0]);
    close(go[1]);
    return 0;
}

#define WAIT_SETS 6
static int wait_sets[WAIT_SETS];

static void *blocked_thread(void *arg) {
    struct sembuf take = {0, -1, 0};
    semop(wait_sets[(uintptr_t)arg % WAIT_SETS], &take, 1);
    return NULL;
}

/* Starts `n` threads, numbered from `first`, that each wait on the semaphore
 * of one set (a set holds eight waiting operations); how many started. */
static int start_blocked(pthread_t *threads, int first, int n) {
    int made = 0;
    for (int i = 0; i < n; i++) {
        if (pthread_create(&threads[i], NULL, blocked_thread, (void *)(uintptr_t)(first + i)) != 0) break;
        made++;
    }
    return made;
}

static int waiting_in_sets(void) {
    int n = 0;
    for (int i = 0; i < WAIT_SETS; i++) n += semctl(wait_sets[i], 0, GETNCNT);
    return n;
}

/* Forty-eight operations wait in the service (three processes with sixteen
 * threads each) while the other calls go on: the pipes and the sockets keep
 * their steps (xtask measures the longest). */
static int many_waits(void) {
    enum { EACH = 16, CHILDREN = 2 };
    for (int i = 0; i < WAIT_SETS; i++) {
        wait_sets[i] = semget(IPC_PRIVATE, 1, 0600);
        CHECK(wait_sets[i] > 0);
    }
    pid_t pids[CHILDREN];
    for (int c = 0; c < CHILDREN; c++) {
        pids[c] = fork();
        CHECK(pids[c] >= 0);
        if (pids[c] == 0) {
            pthread_t threads[EACH];
            int made = start_blocked(threads, (c + 1) * EACH, EACH);
            for (int i = 0; i < made; i++) pthread_join(threads[i], NULL);
            _exit(made == EACH ? 0 : 1);
        }
    }
    pthread_t threads[EACH];
    int made = start_blocked(threads, 0, EACH);
    CHECK(made == EACH);
    int ncnt = 0;
    for (int i = 0; i < 100 && ncnt != 3 * EACH; i++) {
        pause_ms(20);
        ncnt = waiting_in_sets();
    }
    if (ncnt != 3 * EACH) printf("posix-ipc: %d waiting\n", ncnt);
    CHECK(ncnt == 3 * EACH);
    /* Pipes and sockets under that load. */
    int fds[2], sv[2];
    char buf[64];
    CHECK(pipe(fds) == 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    for (int i = 0; i < 20; i++) {
        CHECK(write(fds[1], "pipe", 4) == 4 && read(fds[0], buf, sizeof buf) == 4);
        CHECK(send(sv[0], "sock", 4, 0) == 4 && recv(sv[1], buf, sizeof buf, 0) == 4);
    }
    close(fds[0]); close(fds[1]); close(sv[0]); close(sv[1]);
    /* One wakes, the others stay. */
    struct sembuf give = {0, 1, 0};
    CHECK(semop(wait_sets[0], &give, 1) == 0);
    int after = ncnt;
    for (int i = 0; i < 100 && after != ncnt - 1; i++) {
        pause_ms(20);
        after = waiting_in_sets();
    }
    CHECK(after == ncnt - 1);
    /* The removal wakes all of them. */
    for (int i = 0; i < WAIT_SETS; i++) CHECK(semctl(wait_sets[i], 0, IPC_RMID) == 0);
    for (int i = 0; i < made; i++) CHECK(pthread_join(threads[i], NULL) == 0);
    for (int c = 0; c < CHILDREN; c++) CHECK(wait_ok(pids[c]));
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

#define SEM_WAITERS 12
static sem_t *level_sem;
static volatile int level_started, level_done;
static int level_log[SEM_WAITERS];

static void *level_waiter(void *arg) {
    int priority = (int)(intptr_t)arg;
    level_started++;
    if (sem_wait(level_sem) != 0) return (void *)1;
    int at = __atomic_fetch_add(&level_done, 1, __ATOMIC_SEQ_CST);
    level_log[at] = priority;
    return NULL;
}

/* Twelve threads of twelve priorities wait on one named semaphore (a wait
 * queue of the service used to hold eight): the posts wake them in the order
 * of their priorities, one for each post. A signal ends a wait with EINTR and
 * leaves nothing behind. */
static int sem_waiters(void) {
    static const int priorities[SEM_WAITERS] = {15, 28, 9, 22, 31, 12, 25, 18, 6, 30, 20, 3};
    sem_unlink("/ipc-levels");
    level_sem = sem_open("/ipc-levels", O_CREAT | O_EXCL, 0600, 0);
    CHECK(level_sem != SEM_FAILED);
    pthread_t threads[SEM_WAITERS];
    for (int i = 0; i < SEM_WAITERS; i++) {
        pthread_attr_t attr;
        struct sched_param param = {priorities[i]};
        CHECK(pthread_attr_init(&attr) == 0);
        CHECK(pthread_attr_setstacksize(&attr, 65536) == 0);
        CHECK(pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED) == 0);
        CHECK(pthread_attr_setschedpolicy(&attr, SCHED_FIFO) == 0);
        CHECK(pthread_attr_setschedparam(&attr, &param) == 0);
        CHECK(pthread_create(&threads[i], &attr, level_waiter, (void *)(intptr_t)priorities[i]) == 0);
        CHECK(pthread_attr_destroy(&attr) == 0);
    }
    for (int i = 0; i < 500 && level_started != SEM_WAITERS; i++) pause_ms(10);
    CHECK(level_started == SEM_WAITERS);
    /* All of them are in the service a second later (a slow host needs
     * the time); none has passed. */
    pause_ms(1000);
    CHECK(level_done == 0);
    for (int i = 0; i < SEM_WAITERS; i++) {
        CHECK(sem_post(level_sem) == 0);
        for (int k = 0; k < 200 && level_done != i + 1; k++) pause_ms(5);
        CHECK(level_done == i + 1);
    }
    for (int i = 0; i < SEM_WAITERS; i++) {
        void *result = NULL;
        CHECK(pthread_join(threads[i], &result) == 0 && result == NULL);
    }
    for (int i = 0; i < SEM_WAITERS; i++) {
        int want = 0;
        for (int j = 0; j < SEM_WAITERS; j++) {
            int greater = 0;
            for (int k = 0; k < SEM_WAITERS; k++) greater += priorities[k] > priorities[j];
            if (greater == i) want = priorities[j];
        }
        if (level_log[i] != want) printf("posix-ipc: woke %d at place %d, wanted %d\n", level_log[i], i, want);
        CHECK(level_log[i] == want);
    }
    /* A signal ends the wait, and the post that comes after it is not lost. */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    alarmed = 0;
    sa.sa_handler = on_alarm;
    CHECK(sigaction(SIGALRM, &sa, NULL) == 0);
    alarm(1);
    errno = 0;
    CHECK(sem_wait(level_sem) == -1 && errno == EINTR && alarmed == 1);
    CHECK(sem_post(level_sem) == 0);
    struct timespec until = after_ms(2000);
    CHECK(sem_timedwait(level_sem, &until) == 0);
    int v = -1;
    CHECK(sem_getvalue(level_sem, &v) == 0 && v == 0);
    CHECK(sem_close(level_sem) == 0 && sem_unlink("/ipc-levels") == 0);
    return 0;
}

#define FULL_CHILDREN 5
#define FULL_CHILD 10
#define FULL_PARENT 16
static sem_t *full_sem;

static void *full_waiter(void *arg) {
    (void)arg;
    return sem_wait(full_sem) == 0 ? NULL : (void *)1;
}

static int full_threads(pthread_t *threads, int n) {
    int made = 0;
    for (int i = 0; i < n; i++) {
        pthread_attr_t attr;
        CHECK(pthread_attr_init(&attr) == 0 && pthread_attr_setstacksize(&attr, 65536) == 0);
        int created = pthread_create(&threads[i], &attr, full_waiter, NULL);
        pthread_attr_destroy(&attr);
        if (created != 0) break;
        made++;
    }
    return made;
}

/* As many threads as a tree of processes may have wait on one named
 * semaphore (sixty-six: a tree has room for about as many threads; the
 * table of the service holds 128 waiting operations, 96 for a tree): the
 * other calls go on, and the posts wake them one for each (xtask measures
 * the longest step of the service). */
static int named_waits(void) {
    sem_unlink("/ipc-full");
    full_sem = sem_open("/ipc-full", O_CREAT | O_EXCL, 0600, 0);
    CHECK(full_sem != SEM_FAILED);
    pid_t pids[FULL_CHILDREN];
    for (int c = 0; c < FULL_CHILDREN; c++) {
        pids[c] = fork();
        CHECK(pids[c] >= 0);
        if (pids[c] == 0) {
            pthread_t threads[FULL_CHILD];
            int made = full_threads(threads, FULL_CHILD);
            int bad = made != FULL_CHILD;
            for (int i = 0; i < made; i++) {
                void *result = NULL;
                if (pthread_join(threads[i], &result) != 0 || result != NULL) bad = 1;
            }
            _exit(bad);
        }
    }
    pthread_t threads[FULL_PARENT];
    CHECK(full_threads(threads, FULL_PARENT) == FULL_PARENT);
    pause_ms(600);
    int fds[2], sv[2];
    char buf[64];
    CHECK(pipe(fds) == 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    for (int i = 0; i < 20; i++) {
        CHECK(write(fds[1], "pipe", 4) == 4 && read(fds[0], buf, sizeof buf) == 4);
        CHECK(send(sv[0], "sock", 4, 0) == 4 && recv(sv[1], buf, sizeof buf, 0) == 4);
    }
    close(fds[0]); close(fds[1]); close(sv[0]); close(sv[1]);
    for (int i = 0; i < FULL_PARENT + FULL_CHILDREN * FULL_CHILD; i++) CHECK(sem_post(full_sem) == 0);
    for (int i = 0; i < FULL_PARENT; i++) {
        void *result = NULL;
        CHECK(pthread_join(threads[i], &result) == 0 && result == NULL);
    }
    for (int c = 0; c < FULL_CHILDREN; c++) CHECK(wait_ok(pids[c]));
    int v = -1;
    CHECK(sem_getvalue(full_sem, &v) == 0 && v == 0);
    CHECK(sem_close(full_sem) == 0 && sem_unlink("/ipc-full") == 0);
    return 0;
}

/* A process whose thirty threads were each given the unit of a post is killed
 * while it is stopped, so that none has taken its unit: the service hands the
 * thirty units on, to the twenty waiters of the process that posted and then
 * to the value, one wake in each step (xtask measures the longest step). */
static int sem_session_ends(void) {
    enum { DEAD = 30, LIVE = 20 };
    sem_unlink("/ipc-end");
    full_sem = sem_open("/ipc-end", O_CREAT | O_EXCL, 0600, 0);
    CHECK(full_sem != SEM_FAILED);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        pthread_t threads[DEAD];
        int made = full_threads(threads, DEAD);
        for (int i = 0; i < made; i++) pthread_join(threads[i], NULL);
        _exit(made == DEAD ? 0 : 1);
    }
    pause_ms(1000);
    pthread_t threads[LIVE];
    CHECK(full_threads(threads, LIVE) == LIVE);
    pause_ms(1000);
    CHECK(kill(pid, SIGSTOP) == 0);
    pause_ms(200);
    for (int i = 0; i < DEAD; i++) CHECK(sem_post(full_sem) == 0);
    CHECK(kill(pid, SIGKILL) == 0);
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid && WIFSIGNALED(status));
    for (int i = 0; i < LIVE; i++) {
        void *result = NULL;
        CHECK(pthread_join(threads[i], &result) == 0 && result == NULL);
    }
    int v = -1;
    for (int i = 0; i < 400 && v != DEAD - LIVE; i++) {
        CHECK(sem_getvalue(full_sem, &v) == 0);
        if (v != DEAD - LIVE) pause_ms(10);
    }
    if (v != DEAD - LIVE) printf("posix-ipc: value %d, wanted %d\n", v, DEAD - LIVE);
    CHECK(v == DEAD - LIVE);
    CHECK(sem_close(full_sem) == 0 && sem_unlink("/ipc-end") == 0);
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

/* ---- Waits by address between processes (pshared words in MAP_SHARED) ---- */

#define SH_KIDS 6
struct shared {
    sem_t sem;
    sem_t ping, pong;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    volatile int started, done, flag, count, turn;
    int log[SH_KIDS];
};

/* The shared page: anonymous (after fork the child shares it), or a shared
 * memory object that every process maps by its name. */
static struct shared *shared_page(int named) {
    void *p;
    if (named) {
        shm_unlink("/ipc-shared");
        int fd = shm_open("/ipc-shared", O_CREAT | O_EXCL | O_RDWR, 0600);
        if (fd < 0 || ftruncate(fd, 4096) != 0) return NULL;
        p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        close(fd);
        shm_unlink("/ipc-shared");
    } else {
        p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    }
    if (p == MAP_FAILED) return NULL;
    memset(p, 0, 4096);
    return p;
}

static void set_priority(int priority) {
    struct sched_param param = {priority};
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);
}

/* Six processes of six priorities wait on one semaphore of a shared page: the
 * posts wake them in the order of the priorities, one for each post. */
static int shared_order(int named) {
    static const int priorities[SH_KIDS] = {9, 21, 14, 27, 5, 18};
    struct shared *s = shared_page(named);
    CHECK(s != NULL);
    CHECK(sem_init(&s->sem, 1, 0) == 0);
    pid_t pids[SH_KIDS];
    for (int i = 0; i < SH_KIDS; i++) {
        pids[i] = fork();
        CHECK(pids[i] >= 0);
        if (pids[i] == 0) {
            set_priority(priorities[i]);
            __atomic_fetch_add(&s->started, 1, __ATOMIC_SEQ_CST);
            if (sem_wait(&s->sem) != 0) _exit(1);
            int at = __atomic_fetch_add(&s->done, 1, __ATOMIC_SEQ_CST);
            s->log[at] = priorities[i];
            _exit(0);
        }
    }
    for (int i = 0; i < 500 && s->started != SH_KIDS; i++) pause_ms(10);
    CHECK(s->started == SH_KIDS);
    pause_ms(500);
    CHECK(s->done == 0);
    for (int i = 0; i < SH_KIDS; i++) {
        CHECK(sem_post(&s->sem) == 0);
        for (int k = 0; k < 400 && s->done != i + 1; k++) pause_ms(5);
        CHECK(s->done == i + 1);
        pause_ms(20);
    }
    for (int i = 0; i < SH_KIDS; i++) CHECK(wait_ok(pids[i]));
    for (int i = 0; i < SH_KIDS; i++) {
        int want = 0;
        for (int j = 0; j < SH_KIDS; j++) {
            int greater = 0;
            for (int k = 0; k < SH_KIDS; k++) greater += priorities[k] > priorities[j];
            if (greater == i) want = priorities[j];
        }
        if (s->log[i] != want) printf("posix-ipc: shared woke %d at place %d, wanted %d\n", s->log[i], i, want);
        CHECK(s->log[i] == want);
    }
    CHECK(munmap(s, 4096) == 0);
    return 0;
}

/* The words are handed to and fro between a parent and a child, 100 round
 * trips (the times go to the log). */
static int shared_latency(int named) {
    enum { ROUNDS = 100 };
    struct shared *s = shared_page(named);
    CHECK(s != NULL);
    CHECK(sem_init(&s->ping, 1, 0) == 0 && sem_init(&s->pong, 1, 0) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        for (int i = 0; i < ROUNDS; i++) {
            if (sem_wait(&s->ping) != 0) _exit(1);
            if (sem_post(&s->pong) != 0) _exit(2);
        }
        _exit(0);
    }
    pause_ms(50);
    long long from = now_ms();
    long long worst = 0, best = 1000000000LL;
    for (int i = 0; i < ROUNDS; i++) {
        struct timespec a, b;
        clock_gettime(CLOCK_MONOTONIC, &a);
        CHECK(sem_post(&s->ping) == 0);
        CHECK(sem_wait(&s->pong) == 0);
        clock_gettime(CLOCK_MONOTONIC, &b);
        long long us = ((long long)(b.tv_sec - a.tv_sec) * 1000000000LL + (b.tv_nsec - a.tv_nsec)) / 1000;
        if (us > worst) worst = us;
        if (us < best) best = us;
    }
    long long took = now_ms() - from;
    printf("posix-ipc: shared round trip best %lld us, worst %lld us\n", best, worst);
    CHECK(wait_ok(pid));
    printf("posix-ipc: shared %d round trips in %lld ms\n", ROUNDS, took);
    CHECK(took < 1000);
    CHECK(munmap(s, 4096) == 0);
    return 0;
}

/* A mutex and a condition of a shared page between a parent and four
 * children: they count under the mutex, wait on the condition for the turn
 * and the parent's broadcast ends their wait. */
static int shared_mutex_cond(int named) {
    enum { KIDS = 4, TURNS = 25 };
    struct shared *s = shared_page(named);
    CHECK(s != NULL);
    pthread_mutexattr_t ma;
    pthread_condattr_t ca;
    CHECK(pthread_mutexattr_init(&ma) == 0 && pthread_mutexattr_setpshared(&ma, PTHREAD_PROCESS_SHARED) == 0);
    CHECK(pthread_condattr_init(&ca) == 0 && pthread_condattr_setpshared(&ca, PTHREAD_PROCESS_SHARED) == 0);
    CHECK(pthread_mutex_init(&s->mutex, &ma) == 0 && pthread_cond_init(&s->cond, &ca) == 0);
    pid_t pids[KIDS];
    for (int i = 0; i < KIDS; i++) {
        pids[i] = fork();
        CHECK(pids[i] >= 0);
        if (pids[i] == 0) {
            for (int k = 0; k < TURNS; k++) {
                if (pthread_mutex_lock(&s->mutex) != 0) _exit(1);
                s->count++;
                s->started++;
                while (s->turn <= k)
                    if (pthread_cond_wait(&s->cond, &s->mutex) != 0) _exit(2);
                if (pthread_mutex_unlock(&s->mutex) != 0) _exit(3);
            }
            _exit(0);
        }
    }
    for (int k = 0; k < TURNS; k++) {
        /* All the children counted in turn k and wait on the condition. */
        for (int i = 0; i < 2000; i++) {
            CHECK(pthread_mutex_lock(&s->mutex) == 0);
            int ready = s->started == (k + 1) * KIDS;
            CHECK(pthread_mutex_unlock(&s->mutex) == 0);
            if (ready) break;
            pause_ms(2);
        }
        CHECK(pthread_mutex_lock(&s->mutex) == 0);
        CHECK(s->started == (k + 1) * KIDS);
        s->turn = k + 1;
        CHECK(pthread_cond_broadcast(&s->cond) == 0);
        CHECK(pthread_mutex_unlock(&s->mutex) == 0);
    }
    for (int i = 0; i < KIDS; i++) CHECK(wait_ok(pids[i]));
    CHECK(s->count == KIDS * TURNS);
    /* A timed wait on a condition nobody signals ends at its time. */
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_nsec += 30 * 1000000L;
    if (until.tv_nsec >= 1000000000L) {
        until.tv_nsec -= 1000000000L;
        until.tv_sec++;
    }
    CHECK(pthread_mutex_lock(&s->mutex) == 0);
    CHECK(pthread_cond_timedwait(&s->cond, &s->mutex, &until) == ETIMEDOUT);
    CHECK(pthread_mutex_unlock(&s->mutex) == 0);
    CHECK(munmap(s, 4096) == 0);
    return 0;
}

static void on_shared_alarm(int sig) { (void)sig; }

/* A timed wait ends at its time, a signal ends a wait with EINTR, and a
 * waiter that is killed after a post gave it the unit leaves that unit to
 * the next one. */
static int shared_ends(int named) {
    struct shared *s = shared_page(named);
    CHECK(s != NULL);
    CHECK(sem_init(&s->sem, 1, 0) == 0);
    struct timespec until = after_ms(40);
    errno = 0;
    long long from = now_ms();
    CHECK(sem_timedwait(&s->sem, &until) == -1 && errno == ETIMEDOUT);
    long long took = now_ms() - from;
    CHECK(took >= 30 && took < 400);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_shared_alarm;
    CHECK(sigaction(SIGALRM, &sa, NULL) == 0);
    alarm(1);
    errno = 0;
    CHECK(sem_wait(&s->sem) == -1 && errno == EINTR);
    /* The parent runs above its children: a post does not let the waiter
     * run before the parent has killed it. */
    set_priority(30);
    pid_t pids[2];
    for (int i = 0; i < 2; i++) {
        pids[i] = fork();
        CHECK(pids[i] >= 0);
        if (pids[i] == 0) {
            set_priority(i == 0 ? 20 : 10);
            __atomic_fetch_add(&s->started, 1, __ATOMIC_SEQ_CST);
            if (sem_wait(&s->sem) != 0) _exit(1);
            __atomic_fetch_add(&s->done, 1, __ATOMIC_SEQ_CST);
            _exit(0);
        }
    }
    for (int i = 0; i < 500 && s->started != 2; i++) pause_ms(10);
    CHECK(s->started == 2);
    pause_ms(300);
    CHECK(sem_post(&s->sem) == 0);
    CHECK(kill(pids[0], SIGKILL) == 0);
    int status = 0;
    CHECK(waitpid(pids[0], &status, 0) == pids[0] && WIFSIGNALED(status));
    if (s->done == 0) {
        /* The first was killed before it took the unit: the second gets it. */
        for (int k = 0; k < 400 && s->done == 0; k++) pause_ms(5);
    }
    CHECK(s->done == 1);
    CHECK(wait_ok(pids[1]));
    int v = -1;
    CHECK(sem_getvalue(&s->sem, &v) == 0 && v == 0);
    CHECK(munmap(s, 4096) == 0);
    return 0;
}

extern unsigned stafeto_shared_polls(void);

/* A wait on a word of a shared page goes through the pipe service, which
 * holds it for a process the process service vouches holds the page for
 * writing (an anonymous page carries a key of the process service's, a file
 * the grant of the file service): the wait does not fall back to the poll
 * every millisecond. */
static int shared_keyed(int named) {
    struct shared *s = shared_page(named);
    CHECK(s != NULL);
    CHECK(sem_init(&s->sem, 1, 0) == 0);
    unsigned polls_before = stafeto_shared_polls();
    struct timespec until = after_ms(200);
    CHECK(sem_timedwait(&s->sem, &until) == -1 && errno == ETIMEDOUT);
    unsigned polls = stafeto_shared_polls() - polls_before;
    printf("posix-ipc: shared_keyed: %u polls in a wait of 200 ms\n", polls);
    CHECK(polls == 0);
    /* The same through a post from a forked child, which holds the page too. */
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        pause_ms(100);
        _exit(sem_post(&s->sem) == 0 ? 0 : 1);
    }
    until = after_ms(2000);
    CHECK(sem_timedwait(&s->sem, &until) == 0);
    CHECK(wait_ok(pid));
    CHECK(stafeto_shared_polls() - polls_before == 0);
    CHECK(munmap(s, 4096) == 0);
    return 0;
}

/* A waiter on a word nobody changes uses next to no CPU while it waits. */
static int shared_idle(int named) {
    struct shared *s = shared_page(named);
    CHECK(s != NULL);
    CHECK(sem_init(&s->sem, 1, 0) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        struct rusage a, b;
        getrusage(RUSAGE_SELF, &a);
        struct timespec until = after_ms(300);
        if (sem_timedwait(&s->sem, &until) != -1 || errno != ETIMEDOUT) _exit(1);
        getrusage(RUSAGE_SELF, &b);
        s->count = (int)((b.ru_utime.tv_sec - a.ru_utime.tv_sec + b.ru_stime.tv_sec - a.ru_stime.tv_sec) * 1000000 +
                         (b.ru_utime.tv_usec - a.ru_utime.tv_usec) + (b.ru_stime.tv_usec - a.ru_stime.tv_usec));
        _exit(0);
    }
    CHECK(wait_ok(pid));
    printf("posix-ipc: shared waiter used %d us of CPU in 300 ms\n", s->count);
    CHECK(s->count < 1500);
    CHECK(munmap(s, 4096) == 0);
    return 0;
}


static struct shared *many_page;

static void *many_waiter(void *arg) {
    struct shared *s = many_page;
    (void)arg;
    __atomic_fetch_add(&s->started, 1, __ATOMIC_SEQ_CST);
    if (sem_wait(&s->sem) != 0) return (void *)1;
    __atomic_fetch_add(&s->done, 1, __ATOMIC_SEQ_CST);
    if (pthread_mutex_lock(&s->mutex) != 0) return (void *)2;
    s->count++;
    while (!s->flag)
        if (pthread_cond_wait(&s->cond, &s->mutex) != 0) return (void *)3;
    if (pthread_mutex_unlock(&s->mutex) != 0) return (void *)4;
    __atomic_fetch_add(&s->turn, 1, __ATOMIC_SEQ_CST);
    return NULL;
}

/* A hundred and twenty-six threads of six processes (the table of waiters
 * holds 128, the service's own steps are measured with it full) wait on a semaphore of a shared page;
 * a post wakes one of them. Then they wait on a condition, and a broadcast
 * wakes all (the service wakes a list at a time; xtask measures its longest
 * step). */
static int shared_many(void) {
    enum { EACH = 21, CHILDREN = 5, ALL = EACH * (CHILDREN + 1) };
    many_page = shared_page(0);
    struct shared *s = many_page;
    CHECK(s != NULL);
    pthread_mutexattr_t ma;
    pthread_condattr_t ca;
    CHECK(pthread_mutexattr_init(&ma) == 0 && pthread_mutexattr_setpshared(&ma, PTHREAD_PROCESS_SHARED) == 0);
    CHECK(pthread_condattr_init(&ca) == 0 && pthread_condattr_setpshared(&ca, PTHREAD_PROCESS_SHARED) == 0);
    CHECK(pthread_mutex_init(&s->mutex, &ma) == 0 && pthread_cond_init(&s->cond, &ca) == 0);
    CHECK(sem_init(&s->sem, 1, 0) == 0);
    pid_t pids[CHILDREN];
    for (int c = 0; c < CHILDREN; c++) {
        pids[c] = fork();
        CHECK(pids[c] >= 0);
        if (pids[c] == 0) {
            pthread_t threads[EACH];
            int made = 0;
            for (int i = 0; i < EACH; i++)
                if (pthread_create(&threads[i], NULL, many_waiter, NULL) == 0) made++;
            int bad = made != EACH;
            for (int i = 0; i < made; i++) {
                void *result = NULL;
                if (pthread_join(threads[i], &result) != 0 || result != NULL) bad = 1;
            }
            _exit(bad);
        }
    }
    pthread_t threads[EACH];
    for (int i = 0; i < EACH; i++) CHECK(pthread_create(&threads[i], NULL, many_waiter, NULL) == 0);
    for (int i = 0; i < 3000 && s->started != ALL; i++) pause_ms(10);
    CHECK(s->started == ALL);
    pause_ms(300);
    CHECK(s->done == 0);
    /* A post wakes one. */
    CHECK(sem_post(&s->sem) == 0);
    for (int i = 0; i < 400 && s->done == 0; i++) pause_ms(5);
    pause_ms(100);
    CHECK(s->done == 1);
    for (int i = 1; i < ALL; i++) CHECK(sem_post(&s->sem) == 0);
    for (int i = 0; i < 2000 && s->count != ALL; i++) pause_ms(5);
    CHECK(s->done == ALL && s->count == ALL);
    pause_ms(300);
    CHECK(s->turn == 0);
    CHECK(pthread_mutex_lock(&s->mutex) == 0);
    s->flag = 1;
    CHECK(pthread_cond_broadcast(&s->cond) == 0);
    CHECK(pthread_mutex_unlock(&s->mutex) == 0);
    for (int i = 0; i < EACH; i++) {
        void *result = NULL;
        CHECK(pthread_join(threads[i], &result) == 0 && result == NULL);
    }
    for (int c = 0; c < CHILDREN; c++) CHECK(wait_ok(pids[c]));
    CHECK(s->turn == ALL);
    printf("posix-ipc: shared_many: %u waits fell back to the poll\n", stafeto_shared_polls());
    CHECK(munmap(s, 4096) == 0);
    return 0;
}

/* An error-checking and a recursive mutex of a shared page belong to one
 * thread of one process: a thread of another process, with the same number
 * in its own, does not own it. */
static int shared_owner(int named) {
    struct shared *s = shared_page(named);
    CHECK(s != NULL);
    pthread_mutexattr_t ma;
    CHECK(pthread_mutexattr_init(&ma) == 0 && pthread_mutexattr_setpshared(&ma, PTHREAD_PROCESS_SHARED) == 0);
    CHECK(pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_ERRORCHECK) == 0);
    CHECK(pthread_mutex_init(&s->mutex, &ma) == 0);
    CHECK(pthread_mutex_lock(&s->mutex) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        if (pthread_mutex_unlock(&s->mutex) != EPERM) _exit(1);
        if (pthread_mutex_trylock(&s->mutex) != EBUSY) _exit(2);
        struct timespec until;
        clock_gettime(CLOCK_REALTIME, &until);
        until.tv_nsec += 30 * 1000000L;
        if (until.tv_nsec >= 1000000000L) {
            until.tv_nsec -= 1000000000L;
            until.tv_sec++;
        }
        if (pthread_mutex_timedlock(&s->mutex, &until) != ETIMEDOUT) _exit(3);
        __atomic_store_n(&s->flag, 1, __ATOMIC_SEQ_CST);
        if (pthread_mutex_lock(&s->mutex) != 0) _exit(4);
        if (pthread_mutex_unlock(&s->mutex) != 0) _exit(5);
        _exit(0);
    }
    for (int i = 0; i < 400 && !s->flag; i++) pause_ms(5);
    CHECK(s->flag == 1);
    CHECK(pthread_mutex_lock(&s->mutex) == EDEADLK);
    CHECK(pthread_mutex_unlock(&s->mutex) == 0);
    CHECK(wait_ok(pid));
    CHECK(munmap(s, 4096) == 0);
    return 0;
}
static int shared_anonymous_owner(void) { return shared_owner(0); }
static int shared_named_owner(void) { return shared_owner(1); }

static sem_t *pass_sem;
static volatile int pass_result[2], pass_errno[2], pass_ready;

static void on_pass(int sig) { (void)sig; }

static void *pass_waiter(void *arg) {
    int i = (int)(intptr_t)arg;
    __atomic_fetch_add(&pass_ready, 1, __ATOMIC_SEQ_CST);
    errno = 0;
    pass_result[i] = sem_wait(pass_sem) == 0 ? 1 : -1;
    pass_errno[i] = errno;
    return NULL;
}

/* A post gives its unit to the first waiter; when a signal ends that waiter's
 * wait before it took the unit, the unit goes to the other one. */
static int sem_signal_pass(int shared) {
    struct shared *page = shared ? shared_page(0) : NULL;
    static sem_t own;
    pass_sem = shared ? &page->sem : &own;
    CHECK(sem_init(pass_sem, shared, 0) == 0);
    pass_result[0] = pass_result[1] = 0;
    pass_ready = 0;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_pass;
    CHECK(sigaction(SIGUSR1, &sa, NULL) == 0);
    set_priority(30);
    pthread_t t[2];
    static const int levels[2] = {20, 10};
    for (int i = 0; i < 2; i++) {
        pthread_attr_t attr;
        struct sched_param param = {levels[i]};
        CHECK(pthread_attr_init(&attr) == 0);
        CHECK(pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED) == 0);
        CHECK(pthread_attr_setschedpolicy(&attr, SCHED_FIFO) == 0);
        CHECK(pthread_attr_setschedparam(&attr, &param) == 0);
        CHECK(pthread_create(&t[i], &attr, pass_waiter, (void *)(intptr_t)i) == 0);
        CHECK(pthread_attr_destroy(&attr) == 0);
    }
    for (int i = 0; i < 500 && pass_ready != 2; i++) pause_ms(10);
    CHECK(pass_ready == 2);
    pause_ms(300);
    CHECK(sem_post(pass_sem) == 0);
    CHECK(pthread_kill(t[0], SIGUSR1) == 0);
    for (int i = 0; i < 400 && !(pass_result[0] && pass_result[1]); i++) pause_ms(5);
    /* The first ended with EINTR, or took the unit before the signal; in
     * either case the unit is not left with nobody to take it. */
    CHECK(pass_result[0] != 0);
    if (pass_result[0] < 0) {
        CHECK(pass_errno[0] == EINTR);
        CHECK(pass_result[1] == 1);
    } else {
        CHECK(pass_result[1] == 0);
        CHECK(sem_post(pass_sem) == 0);
    }
    for (int i = 0; i < 2; i++) CHECK(pthread_join(t[i], NULL) == 0);
    return 0;
}
static int sem_signal_pass_private(void) { return sem_signal_pass(0); }
static int sem_signal_pass_shared(void) { return sem_signal_pass(1); }

static int shared_anonymous_order(void) { return shared_order(0); }
static int shared_named_order(void) { return shared_order(1); }
static int shared_anonymous_latency(void) { return shared_latency(0); }
static int shared_named_latency(void) { return shared_latency(1); }
static int shared_anonymous_mutex_cond(void) { return shared_mutex_cond(0); }
static int shared_named_mutex_cond(void) { return shared_mutex_cond(1); }
static int shared_anonymous_ends(void) { return shared_ends(0); }
static int shared_named_ends(void) { return shared_ends(1); }
static int shared_anonymous_idle(void) { return shared_idle(0); }
static int shared_anonymous_keyed(void) { return shared_keyed(0); }
static int shared_named_keyed(void) { return shared_keyed(1); }
static int shared_named_idle(void) { return shared_idle(1); }

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
    RUN(identity);
    RUN(shm_hand_over);
    RUN(shm_pages);
    RUN(shm_names);
    RUN(pool_waits);
    RUN(shm_fork);
    RUN(shm_files_of_the_dead);
    RUN(many_waits);
    RUN(named_semaphores);
    RUN(sem_waiters);
    RUN(named_waits);
    RUN(sem_session_ends);
    RUN(sem_signal_pass_private);
    RUN(sem_signal_pass_shared);
    RUN(shared_anonymous_order);
    RUN(shared_named_order);
    RUN(shared_anonymous_latency);
    RUN(shared_named_latency);
    RUN(shared_anonymous_mutex_cond);
    RUN(shared_named_mutex_cond);
    RUN(shared_anonymous_ends);
    RUN(shared_named_ends);
    RUN(shared_anonymous_idle);
    RUN(shared_anonymous_keyed);
    RUN(shared_anonymous_owner);
    RUN(shared_named_owner);
    RUN(shared_many);
    RUN(shared_named_idle);
    RUN(shared_named_keyed);
    RUN(limits);
    RUN(longest_steps);
    printf("posix-ipc: ok\n");
    fflush(stdout);
    return 0;
}
