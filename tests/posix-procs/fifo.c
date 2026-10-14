/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern unsigned long long stafeto_probe_memory_used(void);
extern unsigned long long stafeto_probe_memory_quota(void);
extern int stafeto_fifo_service_reserve(void);
static int failures;

static void memory(const char *phase) {
    unsigned long long used = stafeto_probe_memory_used();
    unsigned long long quota = stafeto_probe_memory_quota();
    printf("posix-fifo: %s memory %llu pages quota %llu pages\n", phase, used / 4096, quota / 4096);
    if (quota == 0 || used > quota * 9 / 10) {
        puts("posix-fifo: FAIL memory reserve below ten percent");
        ++failures;
    }
}
static volatile sig_atomic_t pipes;

#define CHECK(test) do { if (!(test)) { \
    printf("posix-fifo: FAIL line %d: %s errno %d\n", __LINE__, #test, errno); \
    ++failures; fflush(stdout); _exit(1); \
} } while (0)

static void sigpipe_handler(int signal) {
    (void)signal;
    ++pipes;
}

static int reader(const char *path) {
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    CHECK(fd >= 0);
    return fd;
}

static int writer(const char *path) {
    int fd = open(path, O_WRONLY | O_NONBLOCK);
    CHECK(fd >= 0);
    return fd;
}

static void creation(void) {
    struct stat st;
    mode_t old = umask(0027);
    CHECK(mkfifo("/tmp/fifo-a", 0666) == 0);
    umask(old);
    CHECK(stat("/tmp/fifo-a", &st) == 0);
    CHECK(S_ISFIFO(st.st_mode));
    CHECK((st.st_mode & 0777) == 0640);
    CHECK(st.st_uid == geteuid() && st.st_gid == getegid());
    CHECK(st.st_nlink == 1 && st.st_size == 0);
    errno = 0;
    CHECK(mkfifo("/tmp/fifo-missing/child", 0600) == -1 && errno == ENOENT);
    errno = 0;
    CHECK(mkfifo("/tmp/fifo-a/child", 0600) == -1 && errno == ENOTDIR);
    errno = 0;
    CHECK(mkfifo("/tmp/fifo-a", 0600) == -1 && errno == EEXIST);
    old = umask(0027);
    CHECK(mknod("/tmp/fifo-n", S_IFIFO | 0666, 0) == 0);
    umask(old);
    CHECK(stat("/tmp/fifo-n", &st) == 0 && S_ISFIFO(st.st_mode) && (st.st_mode & 0777) == 0640);
    errno = 0;
    CHECK(mknod("/tmp/fifo-n", S_IFIFO | 0600, 0) == -1 && errno == EEXIST);
    errno = 0;
    CHECK(mknod("/tmp/fifo-missing/child", S_IFIFO | 0600, 0) == -1 && errno == ENOENT);
    errno = 0;
    CHECK(mknod("/tmp/fifo-nc", S_IFCHR | 0600, 0) == -1 && errno == EPERM);
    errno = 0;
    CHECK(mknod("/tmp/fifo-nb", S_IFBLK | 0600, 0) == -1 && errno == EPERM);
    errno = 0;
    CHECK(mknod("/tmp/fifo-nx", 0030000 | 0600, 0) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(stat("/tmp/fifo-nc", &st) == -1 && errno == ENOENT);
    int home = open("/tmp", O_RDONLY | O_DIRECTORY);
    CHECK(home >= 0);
    CHECK(mknodat(home, "fifo-m", S_IFIFO | 0600, 0) == 0);
    CHECK(fstatat(home, "fifo-m", &st, 0) == 0 && S_ISFIFO(st.st_mode));
    CHECK(unlinkat(home, "fifo-m", 0) == 0);
    CHECK(close(home) == 0);
    CHECK(unlink("/tmp/fifo-n") == 0);
    int dir = open("/tmp", O_RDONLY | O_DIRECTORY);
    CHECK(dir >= 0);
    CHECK(mkfifoat(dir, "fifo-b", 0600) == 0);
    CHECK(close(dir) == 0);
    CHECK(seteuid(65534) == 0);
    errno = 0;
    CHECK(open("/tmp/fifo-b", O_RDONLY | O_NONBLOCK) == -1 && errno == EACCES);
    CHECK(seteuid(0) == 0);
    errno = 0;
    CHECK(open("/tmp/fifo-a", O_WRONLY | O_NONBLOCK) == -1 && errno == ENXIO);
    for (int i = 0; i < 17; ++i) {
        errno = 0;
        CHECK(open("/tmp/fifo-a", O_WRONLY | O_NONBLOCK) == -1 && errno == ENXIO);
    }
    errno = 0;
    CHECK(open("/tmp/fifo-a", O_RDWR | O_NONBLOCK) == -1 && errno == EINVAL);
    int r = reader("/tmp/fifo-a");
    char c;
    CHECK(read(r, &c, 1) == 0);
    int w = writer("/tmp/fifo-a");
    CHECK(write(w, "T", 1) == 1);
    int truncating = open("/tmp/fifo-a", O_WRONLY | O_NONBLOCK | O_TRUNC);
    CHECK(truncating >= 0);
    CHECK(read(r, &c, 1) == 1 && c == 'T');
    CHECK(close(truncating) == 0);
    CHECK(fstat(r, &st) == 0 && S_ISFIFO(st.st_mode));
    CHECK(fchmod(r, 0600) == 0);
    CHECK(fstat(w, &st) == 0 && (st.st_mode & 0777) == 0600);
    CHECK(fchown(r, geteuid(), getegid()) == 0);
    struct timespec times[2] = {{123, 456}, {789, 123}};
    CHECK(futimens(r, times) == 0);
    CHECK(fstat(w, &st) == 0 && st.st_atim.tv_sec == 123 && st.st_atim.tv_nsec == 456
        && st.st_mtim.tv_sec == 789 && st.st_mtim.tv_nsec == 123);
    CHECK(fcntl(w, F_SETFL, O_APPEND | O_NONBLOCK) == 0);
    CHECK((fcntl(w, F_GETFL) & (O_APPEND | O_NONBLOCK)) == (O_APPEND | O_NONBLOCK));
    CHECK(close(w) == 0);
    CHECK(close(r) == 0);
    puts("posix-fifo: creation and nonblocking rendezvous ok");
}

struct atomic_writer { char value; int error; };
static void *atomic_writer(void *argument) {
    struct atomic_writer *job = argument;
    int fd = open("/tmp/fifo-a", O_WRONLY);
    if (fd < 0) { job->error = errno; return NULL; }
    char record[512];
    memset(record, job->value, sizeof(record));
    for (int i = 0; i < 8; ++i) {
        if (write(fd, record, sizeof(record)) != (ssize_t)sizeof(record)) {
            job->error = errno ? errno : EIO;
            break;
        }
    }
    if (close(fd) != 0 && job->error == 0) job->error = errno;
    return NULL;
}

static void atomic_records(int r) {
    CHECK(fcntl(r, F_SETFL, 0) == 0);
    struct atomic_writer jobs[2] = {{'A', 0}, {'B', 0}};
    pthread_t threads[2];
    int counts[2] = {0, 0};
    for (int i = 0; i < 2; ++i) CHECK(pthread_create(&threads[i], NULL, atomic_writer, &jobs[i]) == 0);
    for (int i = 0; i < 16; ++i) {
        char record[512];
        CHECK(read(r, record, sizeof(record)) == (ssize_t)sizeof(record));
        CHECK(record[0] == 'A' || record[0] == 'B');
        if (record[0] == 'A') ++counts[0];
        if (record[0] == 'B') ++counts[1];
        for (size_t j = 1; j < sizeof(record); ++j) CHECK(record[j] == record[0]);
    }
    memory("two writers");
    for (int i = 0; i < 2; ++i) {
        CHECK(pthread_join(threads[i], NULL) == 0);
        CHECK(jobs[i].error == 0);
        CHECK(counts[i] == 8);
    }
    CHECK(fcntl(r, F_SETFL, O_NONBLOCK) == 0);
}

static void independent(void) {
    int r = reader("/tmp/fifo-a");
    int other = reader("/tmp/fifo-a");
    int w = writer("/tmp/fifo-a");
    int copy = dup(r);
    CHECK(copy >= 0);
    CHECK(fcntl(r, F_SETFL, 0) == 0);
    CHECK((fcntl(copy, F_GETFL) & O_NONBLOCK) == 0);
    CHECK((fcntl(other, F_GETFL) & O_NONBLOCK) != 0);
    CHECK(fcntl(copy, F_SETFL, O_NONBLOCK) == 0);
    CHECK((fcntl(r, F_GETFL) & O_NONBLOCK) != 0);
    char buffer[512], received[512];
    memset(buffer, 'A', sizeof(buffer));
    CHECK(write(w, buffer, sizeof(buffer)) == (ssize_t)sizeof(buffer));
    CHECK(read(other, received, sizeof(received)) == (ssize_t)sizeof(received));
    CHECK(memcmp(buffer, received, sizeof(buffer)) == 0);
    errno = 0;
    CHECK(read(r, received, 1) == -1 && errno == EAGAIN);
    CHECK(write(w, buffer, 0) == 0);
    for (int i = 0; i < 7; ++i) CHECK(write(w, buffer, 512) == 512);
    CHECK(write(w, buffer, 256) == 256);
    errno = 0;
    CHECK(write(w, buffer, 512) == -1 && errno == EAGAIN);
    for (int i = 0; i < 7; ++i) CHECK(read(r, received, 512) == 512);
    CHECK(read(r, received, 512) == 256);
    atomic_records(r);
    CHECK(close(w) == 0);
    CHECK(read(r, received, 1) == 0);
    w = writer("/tmp/fifo-a");
    CHECK(close(other) == 0);
    CHECK(close(copy) == 0);
    CHECK(close(r) == 0);
    struct sigaction action = {0};
    action.sa_handler = sigpipe_handler;
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGPIPE, &action, NULL) == 0);
    CHECK(write(w, buffer, 0) == 0 && pipes == 0);
    errno = 0;
    CHECK(write(w, buffer, 1) == -1 && errno == EPIPE);
    CHECK(pipes == 1);
    CHECK(close(w) == 0);
    puts("posix-fifo: independent opens, atomic data, EOF and SIGPIPE ok");
}

static void readiness(void) {
    int r = reader("/tmp/fifo-a");
    int w = writer("/tmp/fifo-a");
    struct pollfd item = {r, POLLIN, 0};
    CHECK(poll(&item, 1, 0) == 0 && item.revents == 0);
    CHECK(write(w, "P", 1) == 1);
    CHECK(poll(&item, 1, 0) == 1 && (item.revents & POLLIN));
    fd_set reads;
    FD_ZERO(&reads);
    FD_SET(r, &reads);
    struct timeval timeout = {0, 0};
    CHECK(select(r + 1, &reads, NULL, NULL, &timeout) == 1 && FD_ISSET(r, &reads));
    char c;
    CHECK(read(r, &c, 1) == 1 && c == 'P');
    item.revents = 0;
    CHECK(poll(&item, 1, 1) == 0 && item.revents == 0);
    CHECK(close(w) == 0);
    CHECK(poll(&item, 1, 0) == 1 && (item.revents & POLLHUP));
    CHECK(close(r) == 0);
    struct pollfd many[9];
    for (int i = 0; i < 9; ++i) {
        many[i].fd = reader("/tmp/fifo-a");
        many[i].events = POLLIN;
        many[i].revents = 0;
    }
    w = writer("/tmp/fifo-a");
    CHECK(poll(many, 9, 1) == 0);
    CHECK(write(w, "M", 1) == 1);
    CHECK(poll(many, 9, 0) == 9);
    for (int i = 0; i < 9; ++i) {
        CHECK(many[i].revents & POLLIN);
        CHECK(close(many[i].fd) == 0);
    }
    CHECK(close(w) == 0);
    puts("posix-fifo: poll and select readiness ok");
}

static int opening;
static int opened;
static int open_error;
static volatile sig_atomic_t signals;
extern int stafeto_fifo_waiting(void);

static void user_signal(int signal) {
    (void)signal;
    ++signals;
}

static int waiting(void) {
    struct timespec start, now;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) return 0;
    for (;;) {
        if (stafeto_fifo_waiting()) return 1;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec - start.tv_sec >= 10) return 0;
        struct timespec delay = {0, 1000000};
        nanosleep(&delay, NULL);
    }
}
static void *blocking_reader(void *unused) {
    (void)unused;
    __atomic_store_n(&opening, 1, __ATOMIC_RELEASE);
    opened = open("/tmp/fifo-b", O_RDONLY);
    open_error = errno;
    return NULL;
}

static void rendezvous(void) {
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, blocking_reader, NULL) == 0);
    while (!__atomic_load_n(&opening, __ATOMIC_ACQUIRE)) {
        struct timespec delay = {0, 1000000};
        nanosleep(&delay, NULL);
    }
    int w = open("/tmp/fifo-b", O_WRONLY);
    CHECK(w >= 0);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(opened >= 0);
    CHECK(write(w, "R", 1) == 1);
    char c;
    CHECK(read(opened, &c, 1) == 1 && c == 'R');
    CHECK(close(w) == 0);
    CHECK(close(opened) == 0);
    struct sigaction action = {0};
    action.sa_handler = user_signal;
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
    __atomic_store_n(&opening, 0, __ATOMIC_RELEASE);
    CHECK(pthread_create(&thread, NULL, blocking_reader, NULL) == 0);
    CHECK(waiting());
    memory("pending open");
    CHECK(pthread_kill(thread, SIGUSR1) == 0);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(opened == -1 && open_error == EINTR && signals == 1);
    errno = 0;
    CHECK(open("/tmp/fifo-b", O_WRONLY | O_NONBLOCK) == -1 && errno == ENXIO);

    action.sa_flags = SA_RESTART;
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
    CHECK(pthread_create(&thread, NULL, blocking_reader, NULL) == 0);
    CHECK(waiting());
    CHECK(pthread_kill(thread, SIGUSR1) == 0);
    w = open("/tmp/fifo-b", O_WRONLY);
    CHECK(w >= 0);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(opened >= 0 && signals == 2);
    CHECK(close(w) == 0);
    CHECK(close(opened) == 0);

    CHECK(pthread_create(&thread, NULL, blocking_reader, NULL) == 0);
    CHECK(waiting());
    CHECK(pthread_cancel(thread) == 0);
    void *result = NULL;
    CHECK(pthread_join(thread, &result) == 0);
    CHECK(result == PTHREAD_CANCELED);
    errno = 0;
    CHECK(open("/tmp/fifo-b", O_WRONLY | O_NONBLOCK) == -1 && errno == ENXIO);
    puts("posix-fifo: blocking rendezvous and cancellation ok");
}

#define CROWD 12
static int crowd_started;
static int crowd_open[CROWD];
static int crowd_error[CROWD];
static void *blocking_writer(void *index) {
    int i = (int)(intptr_t)index;
    __atomic_add_fetch(&crowd_started, 1, __ATOMIC_ACQ_REL);
    crowd_open[i] = open("/tmp/fifo-c", O_WRONLY);
    crowd_error[i] = errno;
    return NULL;
}

/* More blocked opens than the eight places of an end's queue of waiters: none fails. */
static void crowd(void) {
    CHECK(mkfifo("/tmp/fifo-c", 0600) == 0);
    pthread_t threads[CROWD];
    for (int i = 0; i < CROWD; i++) {
        crowd_open[i] = -2;
        CHECK(pthread_create(&threads[i], NULL, blocking_writer, (void *)(intptr_t)i) == 0);
    }
    while (__atomic_load_n(&crowd_started, __ATOMIC_ACQUIRE) < CROWD) {
        struct timespec delay = {0, 1000000};
        nanosleep(&delay, NULL);
    }
    struct timespec settle = {0, 50000000};
    nanosleep(&settle, NULL);
    for (int i = 0; i < CROWD; i++) CHECK(crowd_open[i] == -2);
    int r = open("/tmp/fifo-c", O_RDONLY);
    CHECK(r >= 0);
    for (int i = 0; i < CROWD; i++) CHECK(pthread_join(threads[i], NULL) == 0);
    for (int i = 0; i < CROWD; i++) {
        if (crowd_open[i] < 0) printf("posix-fifo: open %d failed, errno %d\n", i, crowd_error[i]);
        CHECK(crowd_open[i] >= 0);
        if (crowd_open[i] >= 0) CHECK(close(crowd_open[i]) == 0);
    }
    CHECK(close(r) == 0);
    CHECK(unlink("/tmp/fifo-c") == 0);
    puts("posix-fifo: twelve blocked opens of one end ok");
}

static void custody(void) {
    int r = reader("/tmp/fifo-a");
    int w = writer("/tmp/fifo-a");
    CHECK(unlink("/tmp/fifo-a") == 0);
    CHECK(mkfifo("/tmp/fifo-a", 0600) == 0);
    int fresh = reader("/tmp/fifo-a");
    CHECK(write(w, "O", 1) == 1);
    char c;
    CHECK(read(fresh, &c, 1) == 0);
    CHECK(read(r, &c, 1) == 1 && c == 'O');
    CHECK(close(fresh) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        char fd[16];
        snprintf(fd, sizeof(fd), "%d", w);
        execl("/bin/procs-child", "procs-child", "fifo-child", fd, (char *)NULL);
        _exit(97);
    }
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(read(r, &c, 1) == 1 && c == 'E');
    CHECK(close(w) == 0);
    CHECK(close(r) == 0);
    CHECK(unlink("/tmp/fifo-a") == 0);
    CHECK(unlink("/tmp/fifo-b") == 0);
    puts("posix-fifo: unlink generation and fork exec custody ok");
}

int main(int argc, char **argv) {
    if (argc == 1) {
        CHECK(stafeto_fifo_service_reserve() == 0);
        pid_t child = -1;
        char *arguments[] = {"procs-child", "fifo-run", NULL};
        char *environment[] = {NULL};
        CHECK(posix_spawn(&child, "/bin/procs-child", NULL, NULL, arguments, environment) == 0);
        int status = 0;
        CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        CHECK(stafeto_fifo_service_reserve() == 0);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "fifo-child") == 0) {
        int fd = atoi(argv[2]);
        struct stat st;
        return fstat(fd, &st) == 0 && S_ISFIFO(st.st_mode) && write(fd, "E", 1) == 1 ? 0 : 96;
    }
    creation();
    independent();
    readiness();
    rendezvous();
    crowd();
    custody();
    memory("complete");
    printf("posix-fifo: done failures %d\n", failures);
    return failures != 0;
}
