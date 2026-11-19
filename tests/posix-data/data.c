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
 * Started by init as a POSIX process of the root (user 0) after the data service said READY: the
 * launcher role starts /bin/posix-data with posix_spawn (a loader-started process can fork), and that
 * program (role "run") makes the checks. The first call under /data takes a session from the
 * process service. The role "child-read" and the
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

#ifndef DATA_POSIX_MODE
#define DATA_POSIX_MODE "run"
#endif

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

static int spawn_file(const char *file, const char *role, int fd, long offset, long count,
                      int *code) {
    char fdtext[16], offtext[24], counttext[24];
    snprintf(fdtext, sizeof fdtext, "%d", fd);
    snprintf(offtext, sizeof offtext, "%ld", offset);
    snprintf(counttext, sizeof counttext, "%ld", count);
    char *argv[] = {"posix-data", (char *)role, fdtext, offtext, counttext, NULL};
    pid_t pid = 0;
    if (posix_spawn(&pid, file, NULL, NULL, argv, environ) != 0) return -1;
    *code = wait_ok(pid);
    return 0;
}

static int spawn_child(const char *role, int fd, long offset, long count, int *code) {
    return spawn_file("/bin/posix-data", role, fd, offset, count, code);
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

/* A descriptor marked FD_CLOFORK is not the child's. */
static int clofork_stays_with_the_parent(void) {
    unsigned char buf[8];
    int fd = open("/data/pub", O_RDONLY);
    DATA_CHECK(fd >= 0 && fcntl(fd, F_SETFD, FD_CLOFORK) == 0);
    pid_t pid = fork();
    DATA_CHECK(pid >= 0);
    if (pid == 0) {
        errno = 0;
        _exit(read(fd, buf, sizeof buf) == -1 && errno == EBADF ? 0 : 1);
    }
    DATA_CHECK(wait_ok(pid) == 0);
    DATA_CHECK(read_up_to(fd, buf, 8) == 8 && pattern_is(buf, 0, 8, 1));
    DATA_CHECK(close(fd) == 0);
    return 0;
}

/* A set-ID program (the file is owned by user 1000, mode 4755) gets the descriptor and reads it:
 * the loader passes the session of the data service when it is the genuine one. */
static int setid_program_reads_descriptor(void) {
    unsigned char buf[100];
    int code = -9;
    int fd = open("/data/pub", O_RDONLY);
    DATA_CHECK(fd >= 0 && read_up_to(fd, buf, 100) == 100);
    DATA_CHECK(spawn_file("/bin/posix-data-suid", "child-read", fd, 100, 50, &code) == 0);
    DATA_CHECK(code == 0);
    DATA_CHECK(lseek(fd, 0, SEEK_CUR) == 150);
    DATA_CHECK(close(fd) == 0);
    return 0;
}

/* After seteuid the real identity still opens the way (access) and the effective one is refused
 * (faccessat with AT_EACCESS). */
static int real_and_effective_access(void) {
    pid_t pid = fork();
    DATA_CHECK(pid >= 0);
    if (pid == 0) {
        if (seteuid(1000) != 0) _exit(1);
        if (access("/data/secret", R_OK) != 0) _exit(2);
        errno = 0;
        if (faccessat(AT_FDCWD, "/data/secret", R_OK, AT_EACCESS) != -1 || errno != EACCES) _exit(3);
        _exit(0);
    }
    DATA_CHECK(wait_ok(pid) == 0);
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

/* ---- the checks of the write role (a volume made writable by the layer's write paths) ---- */

#include <signal.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>

typedef int (*body_fn)(void);

/* Runs `body` in a child that has changed its ids first (group first, then user): 0 when the body
 * returned 0, the code it ended with otherwise. The child prints its own failures. */
static int as_ids(unsigned uid, unsigned gid, body_fn body) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        if (setgid(gid) != 0 || setuid(uid) != 0) _exit(90);
        _exit(body() == 0 ? 0 : 31);
    }
    return wait_ok(pid);
}

static void pause_ms(unsigned ms) {
    struct timespec t = {(time_t)(ms / 1000), (long)(ms % 1000) * 1000000L};
    nanosleep(&t, NULL);
}

/* Fills buf with `n` bytes of the write pattern of `salt` from `offset`. */
static void make_pattern(unsigned char *buf, unsigned long offset, unsigned long n, unsigned salt) {
    for (unsigned long i = 0; i < n; i++) buf[i] = pattern_at(salt, offset + i);
}

/* Writes the whole of `n` pattern bytes through `fd` (in as many calls as the layer needs). */
static int write_pattern(int fd, unsigned long n, unsigned salt) {
    unsigned char buf[3000];
    unsigned long done = 0;
    while (done < n) {
        unsigned long k = n - done < sizeof buf ? n - done : sizeof buf;
        make_pattern(buf, done, k, salt);
        ssize_t w = write(fd, buf, k);
        if (w <= 0) return -1;
        done += (unsigned long)w;
    }
    return 0;
}

/* Whether the file at `path` is exactly `n` bytes of the pattern of `salt`. */
static int file_is_pattern(const char *path, unsigned long n, unsigned salt) {
    unsigned char buf[2048];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    unsigned long at = 0;
    for (;;) {
        ssize_t r = read(fd, buf, sizeof buf);
        if (r < 0) {
            close(fd);
            return 0;
        }
        if (r == 0) break;
        if (!pattern_is(buf, at, (unsigned long)r, salt)) {
            close(fd);
            return 0;
        }
        at += (unsigned long)r;
    }
    close(fd);
    return at == n;
}

static int umask_and_owner(void) {
    struct stat st;
    mode_t old = umask(027);
    int fd = open("/data/w-umask", O_WRONLY | O_CREAT | O_EXCL, 0666);
    umask(old);
    DATA_CHECK(fd >= 0 && close(fd) == 0);
    DATA_CHECK(stat("/data/w-umask", &st) == 0);
    DATA_CHECK((st.st_mode & 07777) == 0640 && st.st_uid == 0 && st.st_gid == 0);
    DATA_CHECK(S_ISREG(st.st_mode) && st.st_size == 0 && st.st_nlink == 1);
    DATA_CHECK(unlink("/data/w-umask") == 0);
    return 0;
}

static int create_as_user_body(void) {
    struct stat st;
    int fd = open("/data/w-shared/u", O_WRONLY | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0 && close(fd) == 0);
    DATA_CHECK(stat("/data/w-shared/u", &st) == 0);
    DATA_CHECK(st.st_uid == 1000 && st.st_gid == 100);
    DATA_CHECK(mkdir("/data/w-shared/ud", 0755) == 0);
    DATA_CHECK(stat("/data/w-shared/ud", &st) == 0 && st.st_uid == 1000 && S_ISDIR(st.st_mode));
    return 0;
}

static int owner_from_the_effective_uid(void) {
    DATA_CHECK(mkdir("/data/w-shared", 0777) == 0);
    DATA_CHECK(chmod("/data/w-shared", 0777) == 0);
    DATA_CHECK(as_ids(1000, 100, create_as_user_body) == 0);
    DATA_CHECK(rmdir("/data/w-shared/ud") == 0 && unlink("/data/w-shared/u") == 0);
    DATA_CHECK(rmdir("/data/w-shared") == 0);
    return 0;
}

static int write_pwrite_and_read_back(void) {
    unsigned char buf[100];
    int fd = open("/data/w-rw", O_RDWR | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0);
    /* 5000 bytes in one call: several messages of the layer (1,012 bytes at most). */
    unsigned char big[5000];
    make_pattern(big, 0, sizeof big, 3);
    DATA_CHECK(write(fd, big, sizeof big) == (ssize_t)sizeof big);
    DATA_CHECK(lseek(fd, 0, SEEK_CUR) == 5000);
    make_pattern(buf, 0, sizeof buf, 9);
    DATA_CHECK(pwrite(fd, buf, sizeof buf, 1000) == (ssize_t)sizeof buf);
    DATA_CHECK(lseek(fd, 0, SEEK_CUR) == 5000); /* pwrite leaves the position */
    DATA_CHECK(close(fd) == 0);
    unsigned char back[5000];
    fd = open("/data/w-rw", O_RDONLY);
    DATA_CHECK(fd >= 0 && read_up_to(fd, back, sizeof back) == 5000);
    DATA_CHECK(pattern_is(back, 0, 1000, 3));
    DATA_CHECK(pattern_is(back + 1000, 0, 100, 9));
    DATA_CHECK(pattern_is(back + 1100, 1100, 3900, 3));
    DATA_CHECK(close(fd) == 0);
    DATA_CHECK(unlink("/data/w-rw") == 0);
    return 0;
}

#define APPEND_LINES 1000
/* "%c%04d-%.44s\n": a letter, four digits, a dash, 44 characters and the newline. */
#define APPEND_LINE_BYTES 51

/* One process appends APPEND_LINES lines of a letter, each of 51 bytes (one message). */
static int append_lines(const char *path, char letter) {
    int fd = open(path, O_WRONLY | O_APPEND);
    if (fd < 0) return 1;
    for (int i = 0; i < APPEND_LINES; i++) {
        char line[96];
        int n = snprintf(line, sizeof line, "%c%04d-%.44s\n", letter, i,
                         "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJ");
        if (write(fd, line, (size_t)n) != n) return 2;
    }
    return close(fd) == 0 ? 0 : 3;
}

static int append_from_two_processes(void) {
    int fd = open("/data/w-append", O_WRONLY | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0 && close(fd) == 0);
    char *argv[] = {"posix-data", "append-child", "B", NULL};
    pid_t pid = 0;
    DATA_CHECK(posix_spawn(&pid, "/bin/posix-data", NULL, NULL, argv, environ) == 0);
    DATA_CHECK(append_lines("/data/w-append", 'A') == 0);
    DATA_CHECK(wait_ok(pid) == 0);
    /* 2,000 lines of 51 bytes, whole: none cut by the other writer, each number once per letter. */
    static unsigned char seen[2][APPEND_LINES];
    memset(seen, 0, sizeof seen);
    FILE *f = fopen("/data/w-append", "r");
    DATA_CHECK(f != NULL);
    char line[128];
    int lines = 0;
    while (fgets(line, sizeof line, f) != NULL) {
        int number = 0;
        if (strlen(line) != APPEND_LINE_BYTES || (line[0] != 'A' && line[0] != 'B') || line[5] != '-') {
            printf("posix-data: a line is cut or mixed: %.60s\n", line);
            fclose(f);
            return 20;
        }
        for (int k = 1; k <= 4; k++) number = number * 10 + (line[k] - '0');
        DATA_CHECK(number >= 0 && number < APPEND_LINES);
        DATA_CHECK(!seen[line[0] == 'B'][number]);
        seen[line[0] == 'B'][number] = 1;
        lines++;
    }
    fclose(f);
    DATA_CHECK(lines == 2 * APPEND_LINES);
    DATA_CHECK(unlink("/data/w-append") == 0);
    return 0;
}

static int fork_shares_the_write_position(void) {
    int fd = open("/data/w-fork", O_RDWR | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0);
    unsigned char buf[100];
    make_pattern(buf, 0, 100, 4);
    DATA_CHECK(write(fd, buf, 100) == 100);
    pid_t pid = fork();
    DATA_CHECK(pid >= 0);
    if (pid == 0) {
        make_pattern(buf, 100, 100, 4);
        _exit(write(fd, buf, 100) == 100 && lseek(fd, 0, SEEK_CUR) == 200 ? 0 : 1);
    }
    DATA_CHECK(wait_ok(pid) == 0);
    DATA_CHECK(lseek(fd, 0, SEEK_CUR) == 200); /* the child's write moved ours */
    make_pattern(buf, 200, 100, 4);
    DATA_CHECK(write(fd, buf, 100) == 100);
    DATA_CHECK(close(fd) == 0);
    DATA_CHECK(file_is_pattern("/data/w-fork", 300, 4));
    DATA_CHECK(unlink("/data/w-fork") == 0);
    return 0;
}

static int ftruncate_grows_with_zeros(void) {
    unsigned char buf[400];
    int fd = open("/data/w-trunc", O_RDWR | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0 && write_pattern(fd, 300, 5) == 0);
    DATA_CHECK(ftruncate(fd, 10000) == 0);
    struct stat st;
    DATA_CHECK(fstat(fd, &st) == 0 && st.st_size == 10000);
    DATA_CHECK(pread(fd, buf, 400, 200) == 400);
    DATA_CHECK(pattern_is(buf, 200, 100, 5));
    for (int i = 100; i < 400; i++) DATA_CHECK(buf[i] == 0);
    DATA_CHECK(ftruncate(fd, 150) == 0 && fstat(fd, &st) == 0 && st.st_size == 150);
    DATA_CHECK(close(fd) == 0);
    DATA_CHECK(truncate("/data/w-trunc", 20) == 0 && stat("/data/w-trunc", &st) == 0 && st.st_size == 20);
    DATA_CHECK(file_is_pattern("/data/w-trunc", 20, 5));
    /* O_TRUNC empties it; O_APPEND writes at the end whatever the position. */
    fd = open("/data/w-trunc", O_WRONLY | O_TRUNC);
    DATA_CHECK(fd >= 0 && fstat(fd, &st) == 0 && st.st_size == 0 && close(fd) == 0);
    fd = open("/data/w-trunc", O_WRONLY | O_APPEND);
    DATA_CHECK(fd >= 0 && write(fd, "abc", 3) == 3 && lseek(fd, 0, SEEK_SET) == 0 && write(fd, "def", 3) == 3);
    DATA_CHECK(close(fd) == 0 && stat("/data/w-trunc", &st) == 0 && st.st_size == 6);
    DATA_CHECK(unlink("/data/w-trunc") == 0);
    return 0;
}

static int fsync_returns(void) {
    int fd = open("/data/w-sync", O_RDWR | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0 && write_pattern(fd, 2000, 6) == 0);
    DATA_CHECK(fsync(fd) == 0 && fdatasync(fd) == 0);
    DATA_CHECK(close(fd) == 0 && file_is_pattern("/data/w-sync", 2000, 6));
    int sync_fd = open("/data/w-sync", O_WRONLY | O_SYNC);
    DATA_CHECK(sync_fd >= 0 && write(sync_fd, "x", 1) == 1 && close(sync_fd) == 0);
    DATA_CHECK(unlink("/data/w-sync") == 0);
    return 0;
}

static int unlink_while_open(void) {
    unsigned char buf[200];
    struct stat st;
    int fd = open("/data/w-gone", O_RDWR | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0 && write_pattern(fd, 200, 7) == 0);
    DATA_CHECK(unlink("/data/w-gone") == 0);
    DATA_CHECK(fstat(fd, &st) == 0 && st.st_nlink == 0 && st.st_size == 200);
    errno = 0;
    DATA_CHECK(stat("/data/w-gone", &st) == -1 && errno == ENOENT);
    DATA_CHECK(pread(fd, buf, 200, 0) == 200 && pattern_is(buf, 0, 200, 7));
    DATA_CHECK(pwrite(fd, "tail", 4, 200) == 4);
    DATA_CHECK(fstat(fd, &st) == 0 && st.st_size == 204);
    DATA_CHECK(close(fd) == 0);
    /* The name can be made anew, a new file. */
    fd = open("/data/w-gone", O_RDWR | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0 && fstat(fd, &st) == 0 && st.st_size == 0 && close(fd) == 0);
    DATA_CHECK(unlink("/data/w-gone") == 0);
    return 0;
}

static int rename_over_an_open_file(void) {
    unsigned char buf[8];
    int fd = open("/data/w-ra", O_RDWR | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0 && write(fd, "oldbytes", 8) == 8);
    int other = open("/data/w-rb", O_RDWR | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(other >= 0 && write(other, "newbytes", 8) == 8 && close(other) == 0);
    DATA_CHECK(rename("/data/w-rb", "/data/w-ra") == 0);
    DATA_CHECK(pread(fd, buf, 8, 0) == 8 && memcmp(buf, "oldbytes", 8) == 0);
    DATA_CHECK(close(fd) == 0);
    fd = open("/data/w-ra", O_RDONLY);
    DATA_CHECK(fd >= 0 && read(fd, buf, 8) == 8 && memcmp(buf, "newbytes", 8) == 0);
    DATA_CHECK(close(fd) == 0);
    struct stat st;
    errno = 0;
    DATA_CHECK(stat("/data/w-rb", &st) == -1 && errno == ENOENT);
    DATA_CHECK(unlink("/data/w-ra") == 0);
    return 0;
}

static int rename_directories_and_across(void) {
    struct stat st;
    DATA_CHECK(mkdir("/data/w-d1", 0755) == 0 && mkdir("/data/w-d2", 0755) == 0);
    int fd = open("/data/w-d1/f", O_WRONLY | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0 && write(fd, "x", 1) == 1 && close(fd) == 0);
    DATA_CHECK(rename("/data/w-d1/f", "/data/w-d2/g") == 0);
    errno = 0;
    DATA_CHECK(stat("/data/w-d1/f", &st) == -1 && errno == ENOENT);
    DATA_CHECK(stat("/data/w-d2/g", &st) == 0 && st.st_size == 1);
    DATA_CHECK(rename("/data/w-d2", "/data/w-d3") == 0);
    DATA_CHECK(stat("/data/w-d3/g", &st) == 0);
    errno = 0;
    DATA_CHECK(stat("/data/w-d2", &st) == -1 && errno == ENOENT);
    /* A directory into its own subtree is EINVAL. */
    errno = 0;
    DATA_CHECK(rename("/data/w-d3", "/data/w-d3/inner") == -1 && errno == EINVAL);
    /* Across the mount: the RAM file service is another file system. */
    errno = 0;
    DATA_CHECK(rename("/data/w-d3/g", "/tmp/w-moved") == -1 && errno == EXDEV);
    errno = 0;
    DATA_CHECK(rename("/tmp", "/data/w-tmp") == -1 && errno == EXDEV);
    DATA_CHECK(unlink("/data/w-d3/g") == 0 && rmdir("/data/w-d3") == 0 && rmdir("/data/w-d1") == 0);
    return 0;
}

static int rmdir_non_empty_and_cwd(void) {
    char cwd[PATH_MAX];
    DATA_CHECK(mkdir("/data/w-rm", 0755) == 0);
    int fd = open("/data/w-rm/f", O_WRONLY | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0 && close(fd) == 0);
    errno = 0;
    DATA_CHECK(rmdir("/data/w-rm") == -1 && (errno == ENOTEMPTY || errno == EEXIST));
    DATA_CHECK(unlink("/data/w-rm/f") == 0);
    errno = 0;
    DATA_CHECK(unlink("/data/w-rm") == -1 && errno == EISDIR);
    DATA_CHECK(chdir("/data/w-rm") == 0);
    errno = 0;
    DATA_CHECK(rmdir("/data/w-rm") == -1 && errno == EBUSY); /* the current directory */
    DATA_CHECK(getcwd(cwd, sizeof cwd) != NULL && strcmp(cwd, "/data/w-rm") == 0);
    DATA_CHECK(chdir("/") == 0 && rmdir("/data/w-rm") == 0);
    return 0;
}

static int times_and_chmod_of_an_open_file(void) {
    struct stat before, after;
    int fd = open("/data/w-times", O_RDWR | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0 && write(fd, "abc", 3) == 3 && fsync(fd) == 0);
    DATA_CHECK(fstat(fd, &before) == 0);
    pause_ms(1100);
    DATA_CHECK(write(fd, "def", 3) == 3 && fsync(fd) == 0 && fstat(fd, &after) == 0);
    DATA_CHECK(after.st_mtime > before.st_mtime && after.st_ctime >= after.st_mtime);
    before = after;
    pause_ms(1100);
    /* chmod 000: the description opened before keeps its right to write, ctime moves. */
    DATA_CHECK(chmod("/data/w-times", 0000) == 0);
    DATA_CHECK(write(fd, "ghi", 3) == 3);
    DATA_CHECK(fstat(fd, &after) == 0 && (after.st_mode & 07777) == 0000);
    DATA_CHECK(after.st_ctime > before.st_ctime);
    errno = 0;
    DATA_CHECK(open("/data/w-times", O_RDONLY) == 0 || errno == 0); /* root passes whatever the mode */
    DATA_CHECK(close(fd) == 0 && unlink("/data/w-times") == 0);
    return 0;
}

static int chown_by_user_body(void) {
    int fd = open("/data/w-owned", O_WRONLY | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0 && close(fd) == 0);
    errno = 0;
    DATA_CHECK(chown("/data/w-owned", 2000, (gid_t)-1) == -1 && errno == EPERM);
    DATA_CHECK(chown("/data/w-owned", (uid_t)-1, 100) == 0); /* its own group */
    DATA_CHECK(chmod("/data/w-owned", 0600) == 0);
    return 0;
}

static int chown_by_a_user_is_refused(void) {
    DATA_CHECK(mkdir("/data/w-shared", 0777) == 0 && chmod("/data/w-shared", 0777) == 0);
    DATA_CHECK(chmod("/data", 0777) == 0);
    DATA_CHECK(as_ids(1000, 100, chown_by_user_body) == 0);
    struct stat st;
    DATA_CHECK(stat("/data/w-owned", &st) == 0 && st.st_uid == 1000 && (st.st_mode & 07777) == 0600);
    DATA_CHECK(unlink("/data/w-owned") == 0 && rmdir("/data/w-shared") == 0);
    DATA_CHECK(chmod("/data", 0755) == 0);
    return 0;
}

static int sticky_a_body(void) {
    int fd = open("/data/w-sticky/a", O_WRONLY | O_CREAT | O_EXCL, 0644);
    return fd >= 0 && close(fd) == 0 ? 0 : 1;
}

static int sticky_b_body(void) {
    errno = 0;
    DATA_CHECK(unlink("/data/w-sticky/a") == -1 && errno == EPERM);
    errno = 0;
    DATA_CHECK(rename("/data/w-sticky/a", "/data/w-sticky/b") == -1 && errno == EPERM);
    int fd = open("/data/w-sticky/b2", O_WRONLY | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0 && close(fd) == 0);
    DATA_CHECK(unlink("/data/w-sticky/b2") == 0);
    return 0;
}

static int sticky_directory(void) {
    DATA_CHECK(mkdir("/data/w-sticky", 0777) == 0 && chmod("/data/w-sticky", 01777) == 0);
    DATA_CHECK(as_ids(1000, 100, sticky_a_body) == 0);
    DATA_CHECK(as_ids(2000, 200, sticky_b_body) == 0);
    struct stat st;
    DATA_CHECK(stat("/data/w-sticky/a", &st) == 0); /* still there */
    DATA_CHECK(unlink("/data/w-sticky/a") == 0 && rmdir("/data/w-sticky") == 0);
    return 0;
}

static int other_user_cannot_write_body(void) {
    errno = 0;
    DATA_CHECK(open("/data/w-ro", O_WRONLY) == -1 && errno == EACCES);
    errno = 0;
    DATA_CHECK(open("/data/w-ro", O_RDWR | O_TRUNC) == -1 && errno == EACCES);
    errno = 0;
    DATA_CHECK(truncate("/data/w-ro", 0) == -1 && errno == EACCES);
    int fd = open("/data/w-ro", O_RDONLY);
    DATA_CHECK(fd >= 0 && close(fd) == 0);
    errno = 0;
    DATA_CHECK(open("/data/w-ro-dir/x", O_WRONLY | O_CREAT, 0644) == -1 && errno == EACCES);
    errno = 0;
    DATA_CHECK(unlink("/data/w-ro") == -1 && errno == EACCES);
    return 0;
}

static int a_non_owner_cannot_write(void) {
    int fd = open("/data/w-ro", O_WRONLY | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0 && write(fd, "keep", 4) == 4 && close(fd) == 0);
    DATA_CHECK(mkdir("/data/w-ro-dir", 0755) == 0);
    DATA_CHECK(as_ids(1000, 100, other_user_cannot_write_body) == 0);
    struct stat st;
    DATA_CHECK(stat("/data/w-ro", &st) == 0 && st.st_size == 4);
    DATA_CHECK(unlink("/data/w-ro") == 0 && rmdir("/data/w-ro-dir") == 0);
    return 0;
}

static int setuid_then_write_body(void) {
    int fd = open("/data/w-sw", O_WRONLY);
    DATA_CHECK(fd >= 0);
    DATA_CHECK(setuid(1000) == 0);
    /* The description keeps the right it was opened with; a new open is checked by the new identity. */
    DATA_CHECK(write(fd, "after", 5) == 5);
    errno = 0;
    DATA_CHECK(open("/data/w-sw", O_WRONLY) == -1 && errno == EACCES);
    return 0;
}

static int setuid_then_write(void) {
    int fd = open("/data/w-sw", O_WRONLY | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0 && close(fd) == 0);
    pid_t pid = fork();
    DATA_CHECK(pid >= 0);
    if (pid == 0) _exit(setuid_then_write_body() == 0 ? 0 : 31);
    DATA_CHECK(wait_ok(pid) == 0);
    struct stat st;
    DATA_CHECK(stat("/data/w-sw", &st) == 0 && st.st_size == 5);
    DATA_CHECK(unlink("/data/w-sw") == 0);
    return 0;
}

static int child_write(char **argv) {
    int fd = atoi(argv[2]);
    return write(fd, "from the child", 14) == 14 ? 0 : 6;
}

static int setid_program_writes_through_a_descriptor(void) {
    int fd = open("/data/w-suid", O_WRONLY | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0);
    char fdtext[16];
    snprintf(fdtext, sizeof fdtext, "%d", fd);
    char *argv[] = {"posix-data", "child-write", fdtext, NULL};
    pid_t pid = 0;
    DATA_CHECK(posix_spawn(&pid, "/bin/posix-data-suid", NULL, NULL, argv, environ) == 0);
    DATA_CHECK(wait_ok(pid) == 0);
    DATA_CHECK(close(fd) == 0);
    struct stat st;
    DATA_CHECK(stat("/data/w-suid", &st) == 0 && st.st_size == 14);
    DATA_CHECK(unlink("/data/w-suid") == 0);
    return 0;
}

static volatile sig_atomic_t fsize_signals;

static void on_fsize(int sig) {
    (void)sig;
    fsize_signals++;
}

static int fsize_body(void) {
    struct rlimit limit = {1000, 1000};
    unsigned char buf[600];
    DATA_CHECK(signal(SIGXFSZ, on_fsize) != SIG_ERR);
    DATA_CHECK(setrlimit(RLIMIT_FSIZE, &limit) == 0);
    int fd = open("/data/w-fsize", O_WRONLY | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0);
    make_pattern(buf, 0, sizeof buf, 8);
    DATA_CHECK(write(fd, buf, 600) == 600);
    DATA_CHECK(write(fd, buf, 600) == 400); /* the part that fits */
    errno = 0;
    DATA_CHECK(write(fd, buf, 100) == -1 && errno == EFBIG);
    DATA_CHECK(fsize_signals >= 1);
    struct stat st;
    DATA_CHECK(fstat(fd, &st) == 0 && st.st_size == 1000);
    DATA_CHECK(close(fd) == 0);
    return 0;
}

static int fsize_efbig_and_sigxfsz(void) {
    DATA_CHECK(as_ids(0, 0, fsize_body) == 0);
    DATA_CHECK(unlink("/data/w-fsize") == 0);
    return 0;
}

static int refused_forms(void) {
    int fd = open("/data/w-links", O_WRONLY | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0);
    errno = 0;
    DATA_CHECK(link("/data/w-links", "/data/w-links2") == -1 && errno == EMLINK);
    errno = 0;
    DATA_CHECK(symlink("/data/w-links", "/data/w-sym") == -1 && errno == EPERM);
    errno = 0;
    DATA_CHECK(mkfifo("/data/w-fifo", 0644) == -1 && errno == EPERM);
    struct flock lock;
    memset(&lock, 0, sizeof lock);
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    errno = 0;
    DATA_CHECK(fcntl(fd, F_SETLK, &lock) == -1 && errno == ENOLCK);
    DATA_CHECK(close(fd) == 0);
    errno = 0;
    char *argv[] = {"w-links", NULL};
    DATA_CHECK(execv("/data/w-links", argv) == -1 && errno == EACCES);
    errno = 0;
    DATA_CHECK(access("/data/w-links", X_OK) == -1 && errno == EACCES);
    DATA_CHECK(unlink("/data/w-links") == 0);
    return 0;
}

static int child_scm(int sock) {
    char data;
    char control[CMSG_SPACE(sizeof(int))];
    struct iovec iov = {&data, 1};
    struct msghdr msg;
    memset(&msg, 0, sizeof msg);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof control;
    if (recvmsg(sock, &msg, 0) != 1) return 1;
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    if (c == NULL || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS) return 2;
    int fd;
    memcpy(&fd, CMSG_DATA(c), sizeof fd);
    char head[4];
    if (pread(fd, head, 4, 0) != 4 || memcmp(head, "AAAA", 4) != 0) return 3;
    return write(fd, "BBBB", 4) == 4 ? 0 : 4; /* the position is shared: after the parent's bytes */
}

static int scm_rights_of_a_data_descriptor(void) {
    int pair[2];
    DATA_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    int fd = open("/data/w-scm", O_RDWR | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0 && write(fd, "AAAA", 4) == 4);
    pid_t pid = fork();
    DATA_CHECK(pid >= 0);
    if (pid == 0) {
        close(pair[0]);
        _exit(child_scm(pair[1]));
    }
    close(pair[1]);
    char data = 'x';
    char control[CMSG_SPACE(sizeof(int))];
    struct iovec iov = {&data, 1};
    struct msghdr msg;
    memset(&msg, 0, sizeof msg);
    memset(control, 0, sizeof control);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof control;
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof fd);
    DATA_CHECK(sendmsg(pair[0], &msg, 0) == 1);
    DATA_CHECK(wait_ok(pid) == 0);
    DATA_CHECK(close(pair[0]) == 0);
    unsigned char back[8];
    DATA_CHECK(pread(fd, back, 8, 0) == 8 && memcmp(back, "AAAABBBB", 8) == 0);
    DATA_CHECK(lseek(fd, 0, SEEK_CUR) == 8);
    DATA_CHECK(close(fd) == 0 && unlink("/data/w-scm") == 0);
    return 0;
}

/* MKDIR is ENOSPC at the 1,024 directories of a volume (the root and the hidden directory among
 * them), and passes again after a removal. */
static int directory_cap(void) {
    int made = 0;
    char name[40];
    DATA_CHECK(mkdir("/data/w-cap", 0755) == 0);
    for (;; made++) {
        snprintf(name, sizeof name, "/data/w-cap/d%d", made);
        if (mkdir(name, 0755) != 0) break;
    }
    int refused = errno;
    printf("posix-data: the directory cap came after %d more directories (errno %d)\n", made, refused);
    DATA_CHECK(refused == ENOSPC);
    DATA_CHECK(made > 900 && made < 1024);
    /* Files and removals pass at the cap of directories; a removal makes room for one MKDIR. */
    int fd = open("/data/w-cap/file", O_WRONLY | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0 && close(fd) == 0 && unlink("/data/w-cap/file") == 0);
    snprintf(name, sizeof name, "/data/w-cap/d%d", made - 1);
    DATA_CHECK(rmdir(name) == 0);
    DATA_CHECK(mkdir(name, 0755) == 0);
    for (int i = 0; i < made; i++) {
        snprintf(name, sizeof name, "/data/w-cap/d%d", i);
        DATA_CHECK(rmdir(name) == 0);
    }
    DATA_CHECK(rmdir("/data/w-cap") == 0);
    return 0;
}

static int fill_user_body(void) {
    errno = 0;
    int fd = open("/data/w-user", O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) {
        close(fd);
        unlink("/data/w-user");
        return 1;
    }
    return errno == ENOSPC ? 0 : 2;
}

static int fill_user_creates_body(void) {
    int fd = open("/data/w-user", O_WRONLY | O_CREAT, 0644);
    if (fd < 0) return 1;
    int ok = write(fd, "hi", 2) == 2;
    close(fd);
    unlink("/data/w-user");
    return ok ? 0 : 2;
}

/* The reserve: with fewer than 64 free blocks a user other than root gets ENOSPC for a creation
 * and root goes on; a removal gives room back (the count of free blocks catches up with the
 * refresh walk of the service, which comes after a quiet of 2 s). */
static int enospc_at_the_reserve_then_unlink(void) {
    struct statvfs v;
    unsigned char buf[1012];
    DATA_CHECK(chmod("/data", 0777) == 0);
    int fd = open("/data/w-big", O_WRONLY | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0);
    make_pattern(buf, 0, sizeof buf, 1);
    unsigned long calls = 0;
    for (;;) {
        if (calls % 500 == 0) {
            DATA_CHECK(statvfs("/data", &v) == 0);
            /* f_bavail leaves the reserve out: it is 0 when the reserve is reached. */
            if (v.f_bavail <= 4) break;
        }
        ssize_t w = write(fd, buf, sizeof buf);
        DATA_CHECK(w > 0);
        calls++;
    }
    printf("posix-data: the volume reached its reserve after %lu writes\n", calls);
    DATA_CHECK(as_ids(1000, 100, fill_user_body) == 0); /* ENOSPC for a creation by a user */
    errno = 0;
    DATA_CHECK(write(fd, buf, sizeof buf) > 0); /* root goes into the reserve */
    DATA_CHECK(fsync(fd) == 0 && close(fd) == 0);
    DATA_CHECK(unlink("/data/w-big") == 0);
    /* The room comes back when the service has walked the volume (2 s of quiet, then the walk). */
    int back = 0;
    for (int i = 0; i < 40 && !back; i++) {
        pause_ms(3000);
        back = as_ids(1000, 100, fill_user_creates_body) == 0;
    }
    DATA_CHECK(back);
    DATA_CHECK(chmod("/data", 0755) == 0);
    return 0;
}

static int access_w_user_body(void) {
    errno = 0;
    DATA_CHECK(access("/data/w-acc", W_OK) == -1 && errno == EACCES); /* another owner's 0644 file */
    DATA_CHECK(access("/data/w-acc", R_OK) == 0);
    DATA_CHECK(access("/data/w-acc-own", W_OK) == 0); /* its own */
    struct timespec times[2] = {{5, 0}, {6, 0}};
    errno = 0;
    DATA_CHECK(utimensat(AT_FDCWD, "/data/w-acc", times, 0) == -1 && errno == EPERM);
    DATA_CHECK(utimensat(AT_FDCWD, "/data/w-acc-own", times, 0) == 0);
    struct stat st;
    DATA_CHECK(stat("/data/w-acc-own", &st) == 0 && st.st_atime == 5 && st.st_mtime == 6);
    return 0;
}

static int access_w_utimensat_and_o_excl(void) {
    int fd = open("/data/w-acc", O_WRONLY | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0 && close(fd) == 0);
    errno = 0;
    DATA_CHECK(open("/data/w-acc", O_WRONLY | O_CREAT | O_EXCL, 0644) == -1 && errno == EEXIST);
    DATA_CHECK(access("/data/w-acc", W_OK) == 0); /* root writes whatever the mode says */
    DATA_CHECK(chmod("/data", 0777) == 0);
    fd = open("/data/w-acc-own", O_WRONLY | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0 && fchown(fd, 1000, 100) == 0 && close(fd) == 0);
    DATA_CHECK(as_ids(1000, 100, access_w_user_body) == 0);
    struct timespec times[2] = {{7, 0}, {8, 0}};
    fd = open("/data/w-acc", O_RDWR);
    DATA_CHECK(fd >= 0 && futimens(fd, times) == 0);
    struct stat st;
    DATA_CHECK(fstat(fd, &st) == 0 && st.st_mtime == 8 && st.st_atime == 7);
    DATA_CHECK(close(fd) == 0);
    errno = 0;
    DATA_CHECK(mknod("/data/w-node", S_IFCHR | 0600, 0) == -1 && errno == EPERM);
    DATA_CHECK(unlink("/data/w-acc") == 0 && unlink("/data/w-acc-own") == 0);
    DATA_CHECK(chmod("/data", 0755) == 0);
    return 0;
}

static int write_run(void) {
    if (getuid() != 0) {
        printf("posix-data: the probe is not user 0\n");
        return 20;
    }
    run_check("create with umask 027", umask_and_owner);
    run_check("create owner is the effective uid", owner_from_the_effective_uid);
    run_check("write pwrite and read back", write_pwrite_and_read_back);
    run_check("O_APPEND from two processes 2000 lines", append_from_two_processes);
    run_check("fork shares the write position", fork_shares_the_write_position);
    run_check("ftruncate grows with zeros", ftruncate_grows_with_zeros);
    run_check("fsync returns", fsync_returns);
    run_check("unlink while open reads on", unlink_while_open);
    run_check("rename over an open file", rename_over_an_open_file);
    run_check("rename of directories and across", rename_directories_and_across);
    run_check("rmdir non-empty and cwd", rmdir_non_empty_and_cwd);
    run_check("times and chmod of an open file", times_and_chmod_of_an_open_file);
    run_check("chown by 1000", chown_by_a_user_is_refused);
    run_check("sticky directory", sticky_directory);
    run_check("a non-owner cannot write", a_non_owner_cannot_write);
    run_check("setuid then write", setuid_then_write);
    run_check("set-ID program writes through the descriptor", setid_program_writes_through_a_descriptor);
    run_check("fsize EFBIG and SIGXFSZ", fsize_efbig_and_sigxfsz);
    run_check("link symlink lock and exec refused", refused_forms);
    run_check("scm_rights passes a data descriptor", scm_rights_of_a_data_descriptor);
    run_check("access W_OK utimensat and O_EXCL", access_w_utimensat_and_o_excl);
    if (failures != 0) {
        printf("posix-data: %d checks failed\n", failures);
        return 20;
    }
    printf("posix-data: write checks passed\n");
    return 0;
}


/* ---- the crash role and its verifier: files written and synced, a file renamed over another ---- */

#define CRASH_FILES 4
#define CRASH_BYTES (256UL * 1024UL)
#define CRASH_CONFIG 10000UL
#define CRASH_GENERATIONS 3

#ifndef DATA_POSIX_MIN
#define DATA_POSIX_MIN 0
#endif
#ifndef DATA_POSIX_RENAMED
#define DATA_POSIX_RENAMED 0
#endif

/* The machine may be cut at any sector of this role: each file is written, synced and closed, and
 * its line goes out after the sync; then a file is written to a temporary name, synced and renamed
 * over the old one, and its line goes out after the rename. */
static int crash_run(void) {
    char path[48];
    for (int i = 1; i <= CRASH_FILES; i++) {
        snprintf(path, sizeof path, "/data/c%d", i);
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0 || write_pattern(fd, CRASH_BYTES, (unsigned)i) != 0 || fsync(fd) != 0 || close(fd) != 0) {
            printf("posix-data: crash run failed at file %d (errno %d)\n", i, errno);
            return 20;
        }
        printf("posix-data: synced %d\n", i);
    }
    for (int g = 1; g <= CRASH_GENERATIONS; g++) {
        int fd = open("/data/cfg.tmp", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0 || write_pattern(fd, CRASH_CONFIG, 10u + (unsigned)g) != 0 || fsync(fd) != 0 ||
            close(fd) != 0 || rename("/data/cfg.tmp", "/data/cfg") != 0) {
            printf("posix-data: crash run failed at generation %d (errno %d)\n", g, errno);
            return 20;
        }
        printf("posix-data: renamed %d\n", g);
    }
    /* The count of the sectors of this run (the service built for the crash tests prints it for a
     * STATFS). */
    struct statvfs v;
    if (statvfs("/data", &v) != 0) return 20;
    printf("posix-data: crash run finished\n");
    return 0;
}

static int verify_synced_files(void) {
    char path[48];
    struct stat st;
    for (int i = 1; i <= CRASH_FILES; i++) {
        snprintf(path, sizeof path, "/data/c%d", i);
        if (i <= DATA_POSIX_MIN) {
            DATA_CHECK(file_is_pattern(path, CRASH_BYTES, (unsigned)i));
        } else if (stat(path, &st) == 0) {
            /* Not synced when the machine was cut: absent, or the bytes it has are the pattern's. */
            unsigned char buf[2048];
            int fd = open(path, O_RDONLY);
            DATA_CHECK(fd >= 0);
            unsigned long at = 0;
            for (;;) {
                ssize_t r = read(fd, buf, sizeof buf);
                DATA_CHECK(r >= 0);
                if (r == 0) break;
                DATA_CHECK(pattern_is(buf, at, (unsigned long)r, (unsigned)i));
                at += (unsigned long)r;
            }
            DATA_CHECK(close(fd) == 0 && at <= CRASH_BYTES);
        }
    }
    printf("posix-data: after cut synced files whole 1..%d ok\n", DATA_POSIX_MIN);
    return 0;
}

static int verify_renamed_file(void) {
    struct stat st;
    int whole = 0;
    if (stat("/data/cfg", &st) == 0) {
        /* One whole generation, never a mix of two, and not older than the last rename seen. */
        for (int g = CRASH_GENERATIONS; g >= 1 && !whole; g--) {
            if (file_is_pattern("/data/cfg", CRASH_CONFIG, 10u + (unsigned)g)) {
                DATA_CHECK(g >= DATA_POSIX_RENAMED);
                whole = g;
            }
        }
        DATA_CHECK(whole != 0);
    } else {
        DATA_CHECK(DATA_POSIX_RENAMED == 0 && errno == ENOENT);
    }
    printf("posix-data: after cut the renamed file is one whole generation ok\n");
    return 0;
}

static int verify_takes_a_write(void) {
    int fd = open("/data/after-cut", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    DATA_CHECK(fd >= 0 && write_pattern(fd, 5000, 20) == 0 && fsync(fd) == 0 && close(fd) == 0);
    DATA_CHECK(file_is_pattern("/data/after-cut", 5000, 20));
    printf("posix-data: after cut the volume takes a write ok\n");
    return 0;
}

static int verify_run(void) {
    if (verify_synced_files() != 0 || verify_renamed_file() != 0 || verify_takes_a_write() != 0) {
        printf("posix-data: verify failed\n");
        return 20;
    }
    printf("posix-data: verify checks passed\n");
    return 0;
}


/* ---- the restart role: the service ends in the middle and init starts it again ---- */

static int restart_checks_done;

static int restart_stale_descriptor(void) {
    unsigned char buf[100];
    DATA_CHECK(mkdir("/data/rd", 0755) == 0);
    int x = open("/data/rd/x", O_WRONLY | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(x >= 0 && write_pattern(x, 50, 12) == 0 && fsync(x) == 0 && close(x) == 0);
    int fd = open("/data/rst", O_RDWR | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0 && write_pattern(fd, 100, 13) == 0 && fsync(fd) == 0);
    DATA_CHECK(lseek(fd, 0, SEEK_SET) == 0);
    DATA_CHECK(chdir("/data/rd") == 0);
    /* The service ends when it is asked to open the name `.die` (the build for this probe). */
    int dead = open("/data/.die", O_RDONLY);
    if (dead >= 0) {
        printf("posix-data: the service did not end\n");
        return 20;
    }
    /* The new instance takes a few seconds: ask again until a call under /data answers. */
    struct stat st;
    int up = 0;
    for (int i = 0; i < 120 && !up; i++) {
        pause_ms(500);
        up = stat("/data/rst", &st) == 0;
    }
    DATA_CHECK(up);
    errno = 0;
    DATA_CHECK(read(fd, buf, sizeof buf) == -1 && errno == EIO);
    errno = 0;
    DATA_CHECK(pwrite(fd, "x", 1, 0) == -1 && errno == EIO);
    restart_checks_done = fd;
    return 0;
}

static int restart_close_of_a_stale_descriptor(void) {
    DATA_CHECK(restart_checks_done > 0);
    DATA_CHECK(close(restart_checks_done) == 0);
    return 0;
}

static int restart_open_after(void) {
    int fd = open("/data/rst", O_RDWR);
    DATA_CHECK(fd >= 0 && file_is_pattern("/data/rst", 100, 13));
    DATA_CHECK(write(fd, "more", 4) == 4 && fsync(fd) == 0 && close(fd) == 0);
    int made = open("/data/after-restart", O_WRONLY | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(made >= 0 && write(made, "a", 1) == 1 && close(made) == 0);
    return 0;
}

static int restart_current_directory(void) {
    char cwd[PATH_MAX];
    DATA_CHECK(getcwd(cwd, sizeof cwd) != NULL && strcmp(cwd, "/data/rd") == 0);
    int fd = open("x", O_RDONLY); /* relative to the directory the layer opened again */
    DATA_CHECK(fd >= 0 && close(fd) == 0);
    errno = 0;
    DATA_CHECK(rmdir("/data/rd") == -1 && errno == EBUSY);
    DATA_CHECK(chdir("/") == 0);
    return 0;
}

static int restart_run(void) {
    run_check("stale descriptor EIO", restart_stale_descriptor);
    run_check("close of a stale descriptor", restart_close_of_a_stale_descriptor);
    run_check("open after restart", restart_open_after);
    run_check("current directory reopened", restart_current_directory);
    if (failures != 0) {
        printf("posix-data: %d checks failed\n", failures);
        return 20;
    }
    printf("posix-data: restart checks passed\n");
    return 0;
}


/* ---- the throughput role: 64 MiB onto /data and back, as `dd bs=1M` would do it ---- */

#define DD_BYTES (64UL * 1024UL * 1024UL)
#define DD_BLOCK (1024UL * 1024UL)

static unsigned long long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (unsigned long long)t.tv_sec * 1000ULL + (unsigned long long)t.tv_nsec / 1000000ULL;
}

static int dd_there_and_back(void) {
    static unsigned char block[DD_BLOCK];
    int fd = open("/data/dd-64m", O_WRONLY | O_CREAT | O_EXCL, 0644);
    DATA_CHECK(fd >= 0);
    unsigned long long began = now_ms();
    for (unsigned long at = 0; at < DD_BYTES; at += DD_BLOCK) {
        make_pattern(block, at, DD_BLOCK, 14);
        unsigned long done = 0;
        while (done < DD_BLOCK) {
            ssize_t w = write(fd, block + done, DD_BLOCK - done);
            DATA_CHECK(w > 0);
            done += (unsigned long)w;
        }
    }
    DATA_CHECK(fsync(fd) == 0 && close(fd) == 0);
    unsigned long long wrote_ms = now_ms() - began;
    printf("posix-data: dd wrote 64 MiB in %llu ms: %llu KiB/s\n", wrote_ms,
           wrote_ms ? 65536ULL * 1000ULL / wrote_ms : 0ULL);
    fd = open("/data/dd-64m", O_RDONLY);
    DATA_CHECK(fd >= 0);
    began = now_ms();
    for (unsigned long at = 0; at < DD_BYTES; at += DD_BLOCK) {
        DATA_CHECK(read_up_to(fd, block, DD_BLOCK) == (long)DD_BLOCK);
        DATA_CHECK(pattern_is(block, at, DD_BLOCK, 14));
    }
    DATA_CHECK(close(fd) == 0);
    unsigned long long read_ms = now_ms() - began;
    printf("posix-data: dd read 64 MiB in %llu ms: %llu KiB/s\n", read_ms,
           read_ms ? 65536ULL * 1000ULL / read_ms : 0ULL);
    DATA_CHECK(unlink("/data/dd-64m") == 0);
    return 0;
}

static int throughput_run(void) {
    run_check("dd 64 MiB there and back", dd_there_and_back);
    if (failures != 0) {
        printf("posix-data: %d checks failed\n", failures);
        return 20;
    }
    printf("posix-data: throughput checks passed\n");
    return 0;
}

/* The directory cap alone: 1,016 directories made and removed take about 3 million reads of the
 * volume (a removal looks up the pair before its own in the list of every pair). */
static int cap_run(void) {
    run_check("directory cap", directory_cap);
    if (failures != 0) {
        printf("posix-data: %d checks failed\n", failures);
        return 20;
    }
    printf("posix-data: cap checks passed\n");
    return 0;
}

/* The reserve alone: the volume is filled to it in messages of 1,012 bytes (31,000 calls). */
static int full_run(void) {
    run_check("enospc at the reserve then unlink", enospc_at_the_reserve_then_unlink);
    if (failures != 0) {
        printf("posix-data: %d checks failed\n", failures);
        return 20;
    }
    printf("posix-data: full checks passed\n");
    return 0;
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
    run_check("clofork stays with the parent", clofork_stays_with_the_parent);
    run_check("set-ID program reads the descriptor", setid_program_reads_descriptor);
    run_check("real and effective access", real_and_effective_access);
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

/* The program init starts has no code in its map to copy, so it cannot fork (the layer answers
 * ENOSYS); a program the loader starts can. The first role is therefore a launcher: it starts the
 * program from /bin with posix_spawn and passes on how it ended. */
static int launcher(void) {
    /* The role the image was built for: DATA_POSIX_MODE is "run" (the read checks) or the name of
     * another role. */
    char *argv[] = {"posix-data", DATA_POSIX_MODE, NULL};
    pid_t pid = 0;
    int code = posix_spawn(&pid, "/bin/posix-data", NULL, NULL, argv, environ);
    if (code != 0) {
        printf("posix-data: the launcher could not start /bin/posix-data (error %d)\n", code);
        return 20;
    }
    int status = wait_ok(pid);
    if (status != 0) printf("posix-data: the program ended with %d\n", status);
    return status == 0 ? 0 : 20;
}

int main(int argc, char **argv) {
    if (argc > 2 && strcmp(argv[1], "append-child") == 0) return append_lines("/data/w-append", argv[2][0]);
    if (argc > 2 && strcmp(argv[1], "child-write") == 0) return child_write(argv);
    if (argc > 1 && strcmp(argv[1], "write-run") == 0) return write_run();
    if (argc > 1 && strcmp(argv[1], "cap-run") == 0) return cap_run();
    if (argc > 1 && strcmp(argv[1], "throughput-run") == 0) return throughput_run();
    if (argc > 1 && strcmp(argv[1], "restart-run") == 0) return restart_run();
    if (argc > 1 && strcmp(argv[1], "crash-run") == 0) return crash_run();
    if (argc > 1 && strcmp(argv[1], "verify-run") == 0) return verify_run();
    if (argc > 1 && strcmp(argv[1], "full-run") == 0) return full_run();
    if (argc > 4 && strcmp(argv[1], "child-read") == 0) return child_read(argv);
    if (argc > 2 && strcmp(argv[1], "child-closed") == 0) return child_closed(argv);
    if (argc > 1 && strcmp(argv[1], "run") == 0) return first();
    return launcher();
}
