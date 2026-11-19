/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The probe of the reading paths of /data in the POSIX layer. Built with -fno-builtin; every result
 * is compared. The volume is made offline (xtask data_image::make_posix_volume) and this file knows
 * it by heart:
 *
 *   /pub            0644 0:0       5000 bytes, byte i is (i % 251) + 1
 *   /secret         0600 0:0       100 bytes, salt 2
 *   /mine           0640 1000:100  64 bytes, salt 3
 *   /dir            0755 0:0       a (10 bytes, salt 4), b (11, salt 5), c (12, salt 6), all 0644
 *   /hidden         0700 2000:200  inside (8 bytes, salt 9, 0644, 2000:200)
 *   /many           0755 0:0       f000 to f299, empty, 0644
 *   every time is 1700000000 s; the root of the volume is 0755 0:0
 *
 * Started by init as a POSIX process of the root (user 0) after the data service said READY. The
 * first call under /data takes a session from the process service. The role "child-read" and the
 * role "child-closed" are the program started again by spawn and by exec.
 *
 * Every check prints "posix-data: <name> ok" or "posix-data: <name> FAILED" after the line of the
 * condition that failed, and the next check runs: one boot shows every defect. The end is
 * "posix-data: read checks passed" with no failure.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define DATA_TIME 1700000000L
#define DATA_MANY 300

#define DATA_CHECK(cond)                                                                     \
    do {                                                                                     \
        if (!(cond)) {                                                                       \
            printf("posix-data: check failed at line %d: %s (errno %d)\n", __LINE__, #cond,   \
                   errno);                                                                   \
            return 20;                                                                       \
        }                                                                                    \
    } while (0)

static unsigned char pattern_at(unsigned salt, unsigned long i) {
    return (unsigned char)((i % 251u) + salt);
}

/* Whether buf[0..n) is the file bytes from `offset` for the salt. */
static int pattern_is(const unsigned char *buf, unsigned long offset, unsigned long n, unsigned salt) {
    for (unsigned long i = 0; i < n; i++)
        if (buf[i] != pattern_at(salt, offset + i)) return 0;
    return 1;
}

/* Reads exactly n bytes unless the file ends first; the count read, or -1. */
static long read_up_to(int fd, unsigned char *buf, unsigned long n) {
    unsigned long got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r < 0) return -1;
        if (r == 0) break;
        got += (unsigned long)r;
    }
    return (long)got;
}

static int wait_ok(pid_t pid) {
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) return -1;
    if (!WIFEXITED(status)) return -2;
    return WEXITSTATUS(status);
}

/* ---- the checks of the first role ---- */

static int read_whole(void) {
    unsigned char buf[512];
    int fd = open("/data/pub", O_RDONLY);
    DATA_CHECK(fd >= 0);
    unsigned long total = 0;
    for (;;) {
        ssize_t r = read(fd, buf, sizeof buf);
        DATA_CHECK(r >= 0);
        if (r == 0) break;
        DATA_CHECK(pattern_is(buf, total, (unsigned long)r, 1));
        total += (unsigned long)r;
    }
    DATA_CHECK(total == 5000);
    DATA_CHECK(close(fd) == 0);
    return 0;
}

static int read_by_pread(void) {
    unsigned char buf[200];
    int fd = open("/data/pub", O_RDONLY);
    DATA_CHECK(fd >= 0);
    DATA_CHECK(pread(fd, buf, 100, 1234) == 100);
    DATA_CHECK(pattern_is(buf, 1234, 100, 1));
    DATA_CHECK(lseek(fd, 0, SEEK_CUR) == 0); /* pread leaves the position */
    DATA_CHECK(pread(fd, buf, 100, 4950) == 50);
    DATA_CHECK(pattern_is(buf, 4950, 50, 1));
    DATA_CHECK(pread(fd, buf, 100, 5000) == 0);
    DATA_CHECK(close(fd) == 0);
    return 0;
}

static int seeking(void) {
    unsigned char buf[16];
    int fd = open("/data/pub", O_RDONLY);
    DATA_CHECK(fd >= 0);
    DATA_CHECK(lseek(fd, 4000, SEEK_SET) == 4000);
    DATA_CHECK(read_up_to(fd, buf, 10) == 10 && pattern_is(buf, 4000, 10, 1));
    DATA_CHECK(lseek(fd, -10, SEEK_CUR) == 4000);
    DATA_CHECK(lseek(fd, 0, SEEK_END) == 5000);
    DATA_CHECK(read(fd, buf, sizeof buf) == 0);
    DATA_CHECK(lseek(fd, -100, SEEK_END) == 4900);
    DATA_CHECK(read_up_to(fd, buf, 16) == 16 && pattern_is(buf, 4900, 16, 1));
    errno = 0;
    DATA_CHECK(lseek(fd, -1, SEEK_SET) == -1 && errno == EINVAL);
    DATA_CHECK(close(fd) == 0);
    return 0;
}

static dev_t ram_device;
static dev_t data_device;

static int stat_known(void) {
    struct stat st, again, root;
    DATA_CHECK(stat("/data/pub", &st) == 0);
    DATA_CHECK(S_ISREG(st.st_mode) && (st.st_mode & 07777) == 0644);
    DATA_CHECK(st.st_uid == 0 && st.st_gid == 0);
    DATA_CHECK(st.st_size == 5000);
    DATA_CHECK(st.st_mtime == DATA_TIME && st.st_ctime == DATA_TIME);
    DATA_CHECK(st.st_nlink == 1);
    DATA_CHECK(st.st_ino != 0);
    DATA_CHECK(stat("/data/pub", &again) == 0 && again.st_ino == st.st_ino && again.st_dev == st.st_dev);
    /* The device of the volume is not the RAM file service's. */
    DATA_CHECK(stat("/", &root) == 0);
    DATA_CHECK(st.st_dev != root.st_dev);
    ram_device = root.st_dev;
    data_device = st.st_dev;
    struct stat other;
    DATA_CHECK(stat("/data/dir", &other) == 0 && other.st_dev == st.st_dev);
    return 0;
}

static int fstat_matches(void) {
    struct stat a, b;
    int fd = open("/data/pub", O_RDONLY);
    DATA_CHECK(fd >= 0);
    DATA_CHECK(fstat(fd, &a) == 0 && stat("/data/pub", &b) == 0);
    DATA_CHECK(a.st_ino == b.st_ino && a.st_dev == b.st_dev && a.st_mode == b.st_mode);
    DATA_CHECK(a.st_size == 5000 && a.st_uid == 0 && a.st_mtime == DATA_TIME);
    DATA_CHECK(close(fd) == 0);
    return 0;
}

static int lstat_matches(void) {
    struct stat a, b;
    DATA_CHECK(lstat("/data/pub", &a) == 0 && stat("/data/pub", &b) == 0);
    DATA_CHECK(a.st_ino == b.st_ino && a.st_mode == b.st_mode && a.st_size == b.st_size);
    DATA_CHECK(lstat("/data/dir", &a) == 0 && S_ISDIR(a.st_mode));
    return 0;
}

static int stat_directories(void) {
    struct stat st;
    DATA_CHECK(stat("/data", &st) == 0);
    DATA_CHECK(S_ISDIR(st.st_mode) && (st.st_mode & 07777) == 0755 && st.st_ino == 1);
    DATA_CHECK(st.st_dev == data_device);
    DATA_CHECK(stat("/data/dir", &st) == 0);
    DATA_CHECK(S_ISDIR(st.st_mode) && (st.st_mode & 07777) == 0755 && st.st_uid == 0);
    DATA_CHECK(stat("/data/dir/", &st) == 0 && S_ISDIR(st.st_mode));
    DATA_CHECK(stat("/data/dir/../dir/./a", &st) == 0 && st.st_size == 10);
    return 0;
}

static int stat_owners(void) {
    struct stat st;
    DATA_CHECK(stat("/data/mine", &st) == 0);
    DATA_CHECK(st.st_uid == 1000 && st.st_gid == 100 && (st.st_mode & 07777) == 0640);
    DATA_CHECK(stat("/data/secret", &st) == 0);
    DATA_CHECK(st.st_uid == 0 && (st.st_mode & 07777) == 0600 && st.st_size == 100);
    DATA_CHECK(stat("/data/hidden", &st) == 0);
    DATA_CHECK(st.st_uid == 2000 && st.st_gid == 200 && (st.st_mode & 07777) == 0700);
    DATA_CHECK(stat("/data/hidden/inside", &st) == 0); /* as root: search passes */
    DATA_CHECK(st.st_uid == 2000 && st.st_size == 8);
    return 0;
}

static int readdir_numbers(void) {
    DIR *d = opendir("/data/dir");
    DATA_CHECK(d != NULL);
    int seen_a = 0, seen_b = 0, seen_c = 0, seen_dot = 0, seen_dotdot = 0, others = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        struct stat st;
        char path[64];
        if (strcmp(e->d_name, ".") == 0) {
            DATA_CHECK(stat("/data/dir", &st) == 0 && e->d_ino == st.st_ino);
            seen_dot++;
        } else if (strcmp(e->d_name, "..") == 0) {
            DATA_CHECK(stat("/data", &st) == 0 && e->d_ino == st.st_ino);
            seen_dotdot++;
        } else {
            snprintf(path, sizeof path, "/data/dir/%s", e->d_name);
            DATA_CHECK(stat(path, &st) == 0);
            DATA_CHECK(e->d_ino == st.st_ino && e->d_ino != 0);
            if (strcmp(e->d_name, "a") == 0) seen_a++;
            else if (strcmp(e->d_name, "b") == 0) seen_b++;
            else if (strcmp(e->d_name, "c") == 0) seen_c++;
            else others++;
        }
    }
    DATA_CHECK(seen_a == 1 && seen_b == 1 && seen_c == 1 && seen_dot == 1 && seen_dotdot == 1);
    DATA_CHECK(others == 0);
    DATA_CHECK(closedir(d) == 0);
    return 0;
}

/* Counts the entries of /data/many, each name once: the number, or -1. */
static int count_many(DIR *d, unsigned char *seen) {
    struct dirent *e;
    int total = 0;
    while ((e = readdir(d)) != NULL) {
        total++;
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        if (e->d_name[0] != 'f' || strlen(e->d_name) != 4) return -1;
        int n = (e->d_name[1] - '0') * 100 + (e->d_name[2] - '0') * 10 + (e->d_name[3] - '0');
        if (n < 0 || n >= DATA_MANY || seen[n]) return -1;
        seen[n] = 1;
    }
    return total;
}

static int readdir_many(void) {
    unsigned char seen[DATA_MANY];
    memset(seen, 0, sizeof seen);
    DIR *d = opendir("/data/many");
    DATA_CHECK(d != NULL);
    DATA_CHECK(count_many(d, seen) == DATA_MANY + 2);
    for (int i = 0; i < DATA_MANY; i++) DATA_CHECK(seen[i] == 1);
    DATA_CHECK(closedir(d) == 0);
    return 0;
}

static int rewind_tell_seek(void) {
    unsigned char seen[DATA_MANY];
    DIR *d = opendir("/data/many");
    DATA_CHECK(d != NULL);
    struct dirent *e;
    for (int i = 0; i < 10; i++) DATA_CHECK(readdir(d) != NULL);
    long mark = telldir(d);
    e = readdir(d);
    DATA_CHECK(e != NULL);
    char expected[NAME_MAX + 1];
    strncpy(expected, e->d_name, sizeof expected - 1);
    expected[sizeof expected - 1] = 0;
    for (int i = 0; i < 40; i++) DATA_CHECK(readdir(d) != NULL);
    seekdir(d, mark);
    e = readdir(d);
    DATA_CHECK(e != NULL && strcmp(e->d_name, expected) == 0);
    rewinddir(d);
    memset(seen, 0, sizeof seen);
    DATA_CHECK(count_many(d, seen) == DATA_MANY + 2);
    DATA_CHECK(closedir(d) == 0);
    return 0;
}

static int access_as_root(void) {
    DATA_CHECK(access("/data/pub", F_OK) == 0);
    DATA_CHECK(access("/data/pub", R_OK) == 0);
    DATA_CHECK(access("/data/secret", R_OK) == 0);
    errno = 0;
    DATA_CHECK(access("/data/pub", X_OK) == -1 && errno == EACCES); /* no execute bit at all */
    DATA_CHECK(access("/data/dir", X_OK) == 0);
    errno = 0;
    DATA_CHECK(access("/data/nothing", F_OK) == -1 && errno == ENOENT);
    return 0;
}

/* The scenarios of the child that changes its identity (the number is the argument). */
#define AS_USER_DESCRIPTION 1
#define AS_USER_MODES 2
#define AS_USER_HIDDEN 3

static int as_user_body(int scenario) {
    unsigned char buf[32];
    /* A description opened as root before the change. */
    int held = open("/data/secret", O_RDONLY);
    DATA_CHECK(held >= 0);
    DATA_CHECK(setgid(100) == 0);
    DATA_CHECK(setuid(1000) == 0);
    DATA_CHECK(getuid() == 1000 && geteuid() == 1000);
    if (scenario == AS_USER_DESCRIPTION) {
        /* It keeps its right to read, and a new open of the same file is refused. */
        DATA_CHECK(read_up_to(held, buf, 32) == 32 && pattern_is(buf, 0, 32, 2));
        errno = 0;
        DATA_CHECK(open("/data/secret", O_RDONLY) == -1 && errno == EACCES);
    } else if (scenario == AS_USER_MODES) {
        errno = 0;
        DATA_CHECK(access("/data/secret", R_OK) == -1 && errno == EACCES);
        DATA_CHECK(access("/data/pub", R_OK) == 0);
        DATA_CHECK(access("/data/pub", F_OK) == 0);
        int fd = open("/data/pub", O_RDONLY);
        DATA_CHECK(fd >= 0 && read_up_to(fd, buf, 32) == 32 && pattern_is(buf, 0, 32, 1));
        int mine = open("/data/mine", O_RDONLY); /* the owner of a 0640 file */
        DATA_CHECK(mine >= 0 && read_up_to(mine, buf, 32) == 32 && pattern_is(buf, 0, 32, 3));
        struct stat st;
        DATA_CHECK(stat("/data/secret", &st) == 0 && st.st_uid == 0); /* stat needs search only */
    } else {
        /* A directory of another owner at 0700: the 0644 file inside is not reached. */
        struct stat st;
        errno = 0;
        DATA_CHECK(stat("/data/hidden/inside", &st) == -1 && errno == EACCES);
        errno = 0;
        DATA_CHECK(open("/data/hidden/inside", O_RDONLY) == -1 && errno == EACCES);
        errno = 0;
        DATA_CHECK(access("/data/hidden/inside", R_OK) == -1 && errno == EACCES);
        errno = 0;
        DATA_CHECK(opendir("/data/hidden") == NULL && errno == EACCES);
        DATA_CHECK(stat("/data/hidden", &st) == 0 && st.st_uid == 2000);
    }
    return 0;
}

static int as_user(int scenario) {
    pid_t pid = fork();
    DATA_CHECK(pid >= 0);
    if (pid == 0) _exit(as_user_body(scenario) == 0 ? 0 : 30 + scenario);
    int code = wait_ok(pid);
    if (code != 0) printf("posix-data: the child of scenario %d ended with %d\n", scenario, code);
    DATA_CHECK(code == 0);
    return 0;
}

static int description_survives_setuid(void) { return as_user(AS_USER_DESCRIPTION); }
static int modes_decide_for_user(void) { return as_user(AS_USER_MODES); }
static int closed_directory_hides_file(void) { return as_user(AS_USER_HIDDEN); }

static int chdir_and_relative(void) {
    char cwd[PATH_MAX];
    unsigned char buf[16];
    struct stat st;
    DATA_CHECK(chdir("/data/dir") == 0);
    DATA_CHECK(getcwd(cwd, sizeof cwd) != NULL && strcmp(cwd, "/data/dir") == 0);
    int fd = open("a", O_RDONLY);
    DATA_CHECK(fd >= 0 && read_up_to(fd, buf, 16) == 10 && pattern_is(buf, 0, 10, 4));
    DATA_CHECK(close(fd) == 0);
    DATA_CHECK(stat("b", &st) == 0 && st.st_size == 11);
    DATA_CHECK(stat("../pub", &st) == 0 && st.st_size == 5000);
    DATA_CHECK(chdir("..") == 0);
    DATA_CHECK(getcwd(cwd, sizeof cwd) != NULL && strcmp(cwd, "/data") == 0);
    fd = open("pub", O_RDONLY);
    DATA_CHECK(fd >= 0 && read_up_to(fd, buf, 16) == 16 && pattern_is(buf, 0, 16, 1));
    DATA_CHECK(close(fd) == 0);
    int dfd = open("/data/dir", O_RDONLY | O_DIRECTORY);
    DATA_CHECK(dfd >= 0);
    DATA_CHECK(chdir("/") == 0);
    DATA_CHECK(getcwd(cwd, sizeof cwd) != NULL && strcmp(cwd, "/") == 0);
    DATA_CHECK(fchdir(dfd) == 0);
    DATA_CHECK(getcwd(cwd, sizeof cwd) != NULL && strcmp(cwd, "/data/dir") == 0);
    DATA_CHECK(stat("c", &st) == 0 && st.st_size == 12);
    DATA_CHECK(close(dfd) == 0);
    DATA_CHECK(chdir("/") == 0);
    return 0;
}

static int at_calls(void) {
    unsigned char buf[16];
    struct stat st, plain;
    int dfd = open("/data/dir", O_RDONLY | O_DIRECTORY);
    DATA_CHECK(dfd >= 0);
    int fd = openat(dfd, "b", O_RDONLY);
    DATA_CHECK(fd >= 0 && read_up_to(fd, buf, 16) == 11 && pattern_is(buf, 0, 11, 5));
    DATA_CHECK(close(fd) == 0);
    DATA_CHECK(fstatat(dfd, "c", &st, 0) == 0 && st.st_size == 12);
    DATA_CHECK(stat("/data/dir/c", &plain) == 0 && st.st_ino == plain.st_ino && st.st_ino != 0);
    DATA_CHECK(fstatat(dfd, "../pub", &st, 0) == 0 && st.st_size == 5000);
    DATA_CHECK(faccessat(dfd, "a", R_OK, 0) == 0);
    errno = 0;
    DATA_CHECK(fstatat(dfd, "zzz", &st, 0) == -1 && errno == ENOENT);
    DATA_CHECK(fstatat(AT_FDCWD, "/data/pub", &st, 0) == 0 && st.st_size == 5000);
    DATA_CHECK(close(dfd) == 0);
    return 0;
}

static int fork_shares_position(void) {
    unsigned char buf[100];
    int fd = open("/data/pub", O_RDONLY);
    DATA_CHECK(fd >= 0 && read_up_to(fd, buf, 100) == 100);
    pid_t pid = fork();
    DATA_CHECK(pid >= 0);
    if (pid == 0) {
        /* The child reads through the descriptor it inherited: the bytes after the parent's. */
        int ok = read_up_to(fd, buf, 100) == 100 && pattern_is(buf, 100, 100, 1) &&
                 lseek(fd, 0, SEEK_CUR) == 200;
        _exit(ok ? 0 : 1);
    }
    DATA_CHECK(wait_ok(pid) == 0);
    /* The description is shared: the child's read moved the parent's position too. */
    DATA_CHECK(lseek(fd, 0, SEEK_CUR) == 200);
    DATA_CHECK(read_up_to(fd, buf, 50) == 50 && pattern_is(buf, 200, 50, 1));
    DATA_CHECK(close(fd) == 0);
    return 0;
}

static int spawn_child(const char *role, int fd, long offset, long count, int *code) {
    char fdtext[16], offtext[24], counttext[24];
    snprintf(fdtext, sizeof fdtext, "%d", fd);
    snprintf(offtext, sizeof offtext, "%ld", offset);
    snprintf(counttext, sizeof counttext, "%ld", count);
    char *argv[] = {"posix-data", (char *)role, fdtext, offtext, counttext, NULL};
    pid_t pid = 0;
    if (posix_spawn(&pid, "/bin/posix-data", NULL, NULL, argv, environ) != 0) return -1;
    *code = wait_ok(pid);
    return 0;
}

static int spawn_keeps_descriptor(void) {
    unsigned char buf[100];
    int code = -9;
    int fd = open("/data/pub", O_RDONLY);
    DATA_CHECK(fd >= 0 && read_up_to(fd, buf, 100) == 100);
    DATA_CHECK(spawn_child("child-read", fd, 100, 50, &code) == 0);
    DATA_CHECK(code == 0);
    DATA_CHECK(lseek(fd, 0, SEEK_CUR) == 150); /* the new image read through the same description */
    DATA_CHECK(close(fd) == 0);
    return 0;
}

static int exec_keeps_descriptor(void) {
    unsigned char buf[10];
    int fd = open("/data/pub", O_RDONLY);
    DATA_CHECK(fd >= 0 && read_up_to(fd, buf, 10) == 10);
    pid_t pid = fork();
    DATA_CHECK(pid >= 0);
    if (pid == 0) {
        char fdtext[16];
        snprintf(fdtext, sizeof fdtext, "%d", fd);
        char *argv[] = {"posix-data", "child-read", fdtext, "10", "20", NULL};
        execv("/bin/posix-data", argv);
        _exit(99);
    }
    DATA_CHECK(wait_ok(pid) == 0);
    DATA_CHECK(lseek(fd, 0, SEEK_CUR) == 30);
    DATA_CHECK(close(fd) == 0);
    return 0;
}

static int cloexec_is_closed(void) {
    unsigned char buf[8];
    int code = -9;
    int fd = open("/data/pub", O_RDONLY | O_CLOEXEC);
    DATA_CHECK(fd >= 0);
    DATA_CHECK(spawn_child("child-closed", fd, 0, 0, &code) == 0);
    DATA_CHECK(code == 0);
    DATA_CHECK(read_up_to(fd, buf, 8) == 8 && pattern_is(buf, 0, 8, 1)); /* ours is still open */
    DATA_CHECK(close(fd) == 0);
    return 0;
}

static int writes_are_refused(void) {
    int fd;
    errno = 0;
    DATA_CHECK(open("/data/pub", O_WRONLY) == -1 && errno == EROFS);
    errno = 0;
    DATA_CHECK(open("/data/pub", O_RDWR) == -1 && errno == EROFS);
    errno = 0;
    DATA_CHECK(open("/data/newfile", O_WRONLY | O_CREAT, 0644) == -1 && errno == EROFS);
    fd = open("/data/pub", O_RDONLY);
    DATA_CHECK(fd >= 0);
    errno = 0;
    DATA_CHECK(write(fd, "x", 1) == -1 && errno == EBADF);
    DATA_CHECK(close(fd) == 0);
    errno = 0;
    DATA_CHECK(mkdir("/data/newdir", 0755) == -1 && errno == EROFS);
    errno = 0;
    DATA_CHECK(unlink("/data/pub") == -1 && errno == EROFS);
    errno = 0;
    DATA_CHECK(chmod("/data/pub", 0600) == -1 && errno == EROFS);
    struct stat st;
    DATA_CHECK(stat("/data/pub", &st) == 0 && (st.st_mode & 07777) == 0644 && st.st_size == 5000);
    return 0;
}

static int datax_is_the_ram_service(void) {
    struct stat st, here;
    if (mkdir("/datax", 0755) != 0) DATA_CHECK(errno == EEXIST);
    DATA_CHECK(stat("/datax", &here) == 0 && S_ISDIR(here.st_mode));
    DATA_CHECK(here.st_dev == ram_device);
    DATA_CHECK(here.st_dev != data_device);
    errno = 0;
    DATA_CHECK(stat("/datax/pub", &st) == -1 && errno == ENOENT);
    int fd = open("/datax/f", O_WRONLY | O_CREAT, 0644); /* the RAM service takes writes */
    DATA_CHECK(fd >= 0 && write(fd, "ram", 3) == 3 && close(fd) == 0);
    DATA_CHECK(stat("/datax/f", &st) == 0 && st.st_size == 3 && st.st_dev == ram_device);
    DATA_CHECK(unlink("/datax/f") == 0 && rmdir("/datax") == 0);
    return 0;
}

static int errno_for_bad_paths(void) {
    struct stat st;
    errno = 0;
    DATA_CHECK(stat("/data/nothing", &st) == -1 && errno == ENOENT);
    errno = 0;
    DATA_CHECK(stat("/data/nothing/x", &st) == -1 && errno == ENOENT);
    errno = 0;
    DATA_CHECK(stat("/data/pub/x", &st) == -1 && errno == ENOTDIR); /* a file used as a directory */
    errno = 0;
    DATA_CHECK(stat("/data/pub/", &st) == -1 && errno == ENOTDIR); /* a slash after a file */
    errno = 0;
    DATA_CHECK(open("/data/pub/", O_RDONLY) == -1 && errno == ENOTDIR);
    errno = 0;
    DATA_CHECK(open("/data/dir/zzz", O_RDONLY) == -1 && errno == ENOENT);
    errno = 0;
    DATA_CHECK(open("/data/pub", O_RDONLY | O_DIRECTORY) == -1 && errno == ENOTDIR);
    errno = 0;
    DATA_CHECK(opendir("/data/pub") == NULL && errno == ENOTDIR);
    errno = 0;
    DATA_CHECK(opendir("/data/nothing") == NULL && errno == ENOENT);
    int dfd = open("/data/dir", O_RDONLY | O_DIRECTORY);
    DATA_CHECK(dfd >= 0);
    unsigned char buf[4];
    errno = 0;
    DATA_CHECK(read(dfd, buf, sizeof buf) == -1 && errno == EISDIR);
    DATA_CHECK(close(dfd) == 0);
    return 0;
}

static int statvfs_of_the_volume(void) {
    struct statvfs v;
    DATA_CHECK(statvfs("/data", &v) == 0);
    DATA_CHECK(v.f_bsize == 4096 && v.f_frsize == 4096);
    DATA_CHECK(v.f_blocks > 0 && v.f_bfree <= v.f_blocks && v.f_bavail <= v.f_bfree);
    DATA_CHECK(v.f_namemax == 255);
    int fd = open("/data/pub", O_RDONLY);
    DATA_CHECK(fd >= 0);
    struct statvfs w;
    DATA_CHECK(fstatvfs(fd, &w) == 0 && w.f_blocks == v.f_blocks);
    DATA_CHECK(close(fd) == 0);
    return 0;
}

static int realpath_of_the_volume(void) {
    char out[PATH_MAX];
    DATA_CHECK(realpath("/data/dir/../pub", out) == out && strcmp(out, "/data/pub") == 0);
    DATA_CHECK(realpath("/data/dir/./a", out) == out && strcmp(out, "/data/dir/a") == 0);
    errno = 0;
    DATA_CHECK(realpath("/data/dir/zzz", out) == NULL && errno == ENOENT);
    return 0;
}

static int failures;

static void run_check(const char *name, int (*check)(void)) {
    if (check() == 0) {
        printf("posix-data: %s ok\n", name);
    } else {
        printf("posix-data: %s FAILED\n", name);
        failures++;
    }
}

static int first(void) {
    if (getuid() != 0) {
        printf("posix-data: the probe is not user 0\n");
        return 20;
    }
    run_check("read pub whole", read_whole);
    run_check("pread", read_by_pread);
    run_check("lseek", seeking);
    run_check("stat pub", stat_known);
    run_check("fstat equals stat", fstat_matches);
    run_check("lstat equals stat", lstat_matches);
    run_check("stat directories", stat_directories);
    run_check("stat owners and modes", stat_owners);
    run_check("readdir d_ino equals st_ino", readdir_numbers);
    run_check("readdir 300 entries once", readdir_many);
    run_check("rewinddir telldir seekdir", rewind_tell_seek);
    run_check("access as root", access_as_root);
    run_check("description survives setuid", description_survives_setuid);
    run_check("modes decide for user 1000", modes_decide_for_user);
    run_check("closed directory hides file", closed_directory_hides_file);
    run_check("chdir fchdir relative", chdir_and_relative);
    run_check("openat fstatat faccessat", at_calls);
    run_check("fork shares the position", fork_shares_position);
    run_check("spawn keeps the descriptor", spawn_keeps_descriptor);
    run_check("exec keeps the descriptor", exec_keeps_descriptor);
    run_check("cloexec closed", cloexec_is_closed);
    run_check("writes refused", writes_are_refused);
    run_check("datax is the RAM service", datax_is_the_ram_service);
    run_check("errno for bad paths", errno_for_bad_paths);
    run_check("statvfs", statvfs_of_the_volume);
    run_check("realpath", realpath_of_the_volume);
    if (failures != 0) {
        printf("posix-data: %d checks failed\n", failures);
        return 20;
    }
    printf("posix-data: read checks passed\n");
    return 0;
}

/* The program started again by spawn and by exec: reads `count` bytes at `offset` through the
 * descriptor of its argument, which the first role opened and read up to `offset`. */
static int child_read(char **argv) {
    unsigned char buf[64];
    int fd = atoi(argv[2]);
    long offset = atol(argv[3]), count = atol(argv[4]);
    if (count > (long)sizeof buf) return 2;
    if (read_up_to(fd, buf, (unsigned long)count) != count) return 3;
    return pattern_is(buf, (unsigned long)offset, (unsigned long)count, 1) ? 0 : 4;
}

/* A descriptor made with O_CLOEXEC is not in the new image. */
static int child_closed(char **argv) {
    int fd = atoi(argv[2]);
    errno = 0;
    return fcntl(fd, F_GETFD) == -1 && errno == EBADF ? 0 : 5;
}

int main(int argc, char **argv) {
    if (argc > 4 && strcmp(argv[1], "child-read") == 0) return child_read(argv);
    if (argc > 2 && strcmp(argv[1], "child-closed") == 0) return child_closed(argv);
    return first();
}
