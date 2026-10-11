/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* Public FIFO operations run while the process-steps branches remain live. */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

extern int stafeto_fifo_waiting(void);

struct stepfifo_reader {
    int cancel;
    int done;
    int result;
    int error;
};

static unsigned long long stepfifo_now(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (unsigned long long)now.tv_sec * 1000000000ULL + now.tv_nsec;
}

static void stepfifo_pause(void) {
    struct timespec delay = {0, 1000000};
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {}
}

static int stepfifo_wait(struct stepfifo_reader *reader, int waiting) {
    unsigned long long start = stepfifo_now();
    if (!start) return -1;
    do {
        if (waiting ? stafeto_fifo_waiting() > 0
                    : __atomic_load_n(&reader->done, __ATOMIC_ACQUIRE)) return 0;
        stepfifo_pause();
    } while (stepfifo_now() - start < 10000000000ULL);
    return -1;
}

static void stepfifo_signal(int signal) {
    (void)signal;
}

static void *stepfifo_open_reader(void *opaque) {
    struct stepfifo_reader *reader = opaque;
    int fd = open("/tmp/step-fifo", O_RDONLY);
    int error = errno;
    if (reader->cancel) {
        reader->result = fd == -1 && error == EINTR ? 0 : -1;
        reader->error = error;
    } else {
        char byte = 0;
        reader->result = fd >= 0 && read(fd, &byte, 1) == 1 && byte == 'q' ? 0 : -1;
        reader->error = errno;
    }
    if (fd >= 0 && close(fd) != 0) reader->result = -1;
    __atomic_store_n(&reader->done, 1, __ATOMIC_RELEASE);
    return NULL;
}

static int steps_fifo(void) {
    struct sigaction action, previous;
    memset(&action, 0, sizeof action);
    action.sa_handler = stepfifo_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, &previous) != 0) return 1;
    if (mkfifo("/tmp/step-fifo", 0600) != 0) return 2;
    for (int i = 0; i < 17; ++i) {
        errno = 0;
        int fd = open("/tmp/step-fifo", O_WRONLY | O_NONBLOCK);
        if (fd != -1 || errno != ENXIO) {
            if (fd >= 0) close(fd);
            printf("posix-procs: FIFO no-reader attempt %d errno %d\n", i, errno);
            return 3;
        }
    }
    int rd = open("/tmp/step-fifo", O_RDONLY | O_NONBLOCK);
    int wr = open("/tmp/step-fifo", O_WRONLY | O_NONBLOCK);
    char byte = 0;
    struct stat st;
    if (rd < 0 || wr < 0 || fstat(rd, &st) != 0 || !S_ISFIFO(st.st_mode)
        || fcntl(wr, F_GETFL) != (O_WRONLY | O_NONBLOCK)
        || fcntl(wr, F_SETFL, O_APPEND | O_NONBLOCK) != 0
        || fcntl(wr, F_GETFL) != (O_WRONLY | O_APPEND | O_NONBLOCK)
        || write(wr, "p", 1) != 1 || read(rd, &byte, 1) != 1 || byte != 'p'
        || close(wr) != 0 || close(rd) != 0) return 4;

    for (int cancel = 0; cancel <= 1; ++cancel) {
        struct stepfifo_reader reader = {.cancel = cancel};
        pthread_t thread;
        int created = pthread_create(&thread, NULL, stepfifo_open_reader, &reader);
        if (created != 0) return 5;
        int failed = stepfifo_wait(&reader, 1) != 0;
        if (cancel && !failed) failed = pthread_kill(thread, SIGUSR1) != 0;
        if (!cancel || failed) {
            /* A counterpart also rescues a failed assertion before joining. */
            int peer = open("/tmp/step-fifo", O_WRONLY | O_NONBLOCK);
            if (peer < 0 || (!cancel && write(peer, "q", 1) != 1)) failed = 1;
            if (peer >= 0) close(peer);
        }
        if (stepfifo_wait(&reader, 0) != 0) {
            int peer = open("/tmp/step-fifo", O_WRONLY | O_NONBLOCK);
            if (peer >= 0) { write(peer, "q", 1); close(peer); }
            if (stepfifo_wait(&reader, 0) != 0) return 6;
            failed = 1;
        }
        if (pthread_join(thread, NULL) != 0 || reader.result != 0 || failed) {
            printf("posix-procs: FIFO rendezvous cancel %d result %d errno %d\n",
                   cancel, reader.result, reader.error);
            return 7;
        }
    }
    if (unlink("/tmp/step-fifo") != 0 || sigaction(SIGUSR1, &previous, NULL) != 0) return 8;
    puts("posix-procs: FIFO dispatches among branches ok");
    return 0;
}
