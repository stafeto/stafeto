/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The POSIX side of the layer probe (xtask layer-probe). As `layer-user` it looks at the
 * layers the leader attaches and detaches, in steps the leader paces through files of /tmp.
 * With an argument (`now` or `wait`) it is the program a layer holds: it exits with 42,
 * `wait` after /tmp/go appears.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#define BIG_SIZE (256 * 1024)

static unsigned char pattern(size_t i) {
    return (unsigned char)((i ^ (i >> 8) ^ (i >> 16)) & 0xff);
}

static void fail(const char *what) {
    printf("layer-user: failed %s (errno %d)\n", what, errno);
    exit(2);
}

static void check(const char *what, int good) {
    if (!good) {
        fail(what);
    }
}

static void nap(void) {
    struct timespec ts = {0, 10 * 1000 * 1000};
    nanosleep(&ts, NULL);
}

static int exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static void wait_for(const char *path) {
    for (int i = 0; i < 60000; i++) {
        if (exists(path)) {
            return;
        }
        nap();
    }
    printf("layer-user: failed waiting for %s\n", path);
    exit(2);
}

static void touch(const char *path) {
    int fd = open(path, O_CREAT | O_WRONLY, 0644);
    check("create a marker", fd >= 0);
    close(fd);
}

static int hello(int wait) {
    if (wait) {
        wait_for("/tmp/go");
    }
    return 42;
}

static pid_t run_hello(const char *mode) {
    pid_t pid = 0;
    char *argv[] = {"hello", (char *)mode, NULL};
    int err = posix_spawn(&pid, "/layer/bin/hello", NULL, NULL, argv, environ);
    if (err != 0) {
        errno = err;
        fail("posix_spawn of the program of the layer");
    }
    return pid;
}

static void reaped(pid_t pid, int code, const char *what) {
    int status = 0;
    check(what, waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == code);
}

/* Reads `count` bytes of the pattern from `fd` at `offset`. */
static void verify(int fd, size_t offset, size_t count, const char *what) {
    unsigned char buffer[4096];
    size_t done = 0;
    while (done < count) {
        size_t want = count - done < sizeof buffer ? count - done : sizeof buffer;
        ssize_t n = pread(fd, buffer, want, (off_t)(offset + done));
        check(what, n > 0);
        for (ssize_t i = 0; i < n; i++) {
            if (buffer[i] != pattern(offset + done + (size_t)i)) {
                printf("layer-user: %s differs at %zu\n", what, offset + done + (size_t)i);
                exit(2);
            }
        }
        done += (size_t)n;
    }
}

static void look_at_good(void) {
    struct stat st, other;
    check("hello is a regular file", stat("/layer/bin/hello", &st) == 0 && S_ISREG(st.st_mode));
    check("hello mode and owner", (st.st_mode & 0777) == 0755 && st.st_uid == 0 && st.st_gid == 0);
    check("hello link count 2", st.st_nlink == 2);
    check("the hard link is the same file",
          stat("/layer/bin/hi", &other) == 0 && other.st_ino == st.st_ino);
    check("lstat of the link", lstat("/layer/bin/world", &other) == 0 && S_ISLNK(other.st_mode));
    char target[16] = {0};
    check("readlink", readlink("/layer/bin/world", target, sizeof target - 1) == 5
                          && strcmp(target, "hello") == 0);
    int fd = open("/layer/data/big", O_RDONLY);
    check("open big", fd >= 0);
    check("big size", fstat(fd, &st) == 0 && st.st_size == BIG_SIZE);
    verify(fd, 0, BIG_SIZE, "big");
    close(fd);
    char text[32] = {0};
    fd = open("/usr/share/licenses/layer-test/LICENSE", O_RDONLY);
    check("open the license", fd >= 0);
    check("license text", read(fd, text, sizeof text - 1) == 19 && strcmp(text, "layer test license\n") == 0);
    close(fd);
    /* The program of the layer runs. */
    reaped(run_hello("now"), 42, "hello exits with 42");
    /* The names and attributes are read-only; the directories take files. */
    check("chmod of a layer file", chmod("/layer/bin/hello", 0600) == -1 && errno == EROFS);
    check("unlink of a layer file", unlink("/layer/bin/hello") == -1 && errno == EROFS);
    check("rename of a layer file",
          rename("/layer/bin/hello", "/layer/bin/gone") == -1 && errno == EROFS);
    check("write open of a layer file", open("/layer/bin/hello", O_WRONLY) == -1);
    fd = open("/layer/note", O_CREAT | O_WRONLY, 0644);
    check("a file in a directory of a layer", fd >= 0);
    close(fd);
    check("the file of a user goes", unlink("/layer/note") == 0);
}

static int user(void) {
    wait_for("/tmp/good");
    look_at_good();
    touch("/tmp/checked");
    printf("layer-user: good looked at ok\n");

    wait_for("/tmp/phase2");
    int fd = open("/layer/data/big", O_RDONLY);
    check("open big again", fd >= 0);
    verify(fd, 0, 4096, "big head");
    pid_t child = run_hello("wait");
    touch("/tmp/opened");

    wait_for("/tmp/detached");
    struct stat st;
    check("the names are gone", stat("/layer/data/big", &st) == -1 && errno == ENOENT);
    check("the open file has no links", fstat(fd, &st) == 0 && st.st_nlink == 0);
    verify(fd, 0, BIG_SIZE, "big after the detach");
    touch("/tmp/go");
    reaped(child, 42, "the program of a detached layer ends with 42");
    close(fd);
    touch("/tmp/closed");
    printf("layer-user: open file and program after the detach ok\n");

    wait_for("/tmp/phase4");
    long rounds = 0;
    while (!exists("/tmp/stop")) {
        fd = open("/layer/data/big", O_RDONLY);
        check("open big in the loop", fd >= 0);
        verify(fd, 0, BIG_SIZE, "big in the loop");
        close(fd);
        /* A program from a layer is read through the loader: READ_INTO of the service. */
        reaped(run_hello("now"), 42, "hello in the loop");
        rounds++;
    }
    printf("layer-user: read big %ld times beside the attaches ok\n", rounds);
    touch("/tmp/user-ok");
    printf("layer-user: ok\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2) {
        return hello(strcmp(argv[1], "wait") == 0);
    }
    return user();
}
