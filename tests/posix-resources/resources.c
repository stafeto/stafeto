/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <setjmp.h>
#include <spawn.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
static int failures;
static volatile sig_atomic_t size_signals;
static sigjmp_buf size_jump;

static void check(const char *what, int good) {
    if (!good) {
        printf("posix-resources: %s failed (errno %d)\n", what, errno);
        failures++;
    }
}
static int reaped(pid_t child, int code) {
    int status = 0;
    return waitpid(child, &status, 0) == child && WIFEXITED(status)
        && WEXITSTATUS(status) == code;
}
static int same_limit(int resource, const struct rlimit *expected) {
    struct rlimit actual;
    return getrlimit(resource, &actual) == 0
        && actual.rlim_cur == expected->rlim_cur
        && actual.rlim_max == expected->rlim_max;
}
static int ram_filesystem(const struct statvfs *fs) {
    return fs->f_bsize == 4096 && fs->f_frsize == 4096
        && fs->f_blocks > 0 && fs->f_files > 0 && fs->f_namemax == 255;
}

static int virtual_filesystem(const struct statvfs *fs) {
    return fs->f_bsize == 4096 && fs->f_frsize == 4096
        && fs->f_blocks == 0 && fs->f_bfree == 0 && fs->f_bavail == 0
        && fs->f_files == 0 && fs->f_ffree == 0 && fs->f_favail == 0
        && fs->f_fsid == 0 && fs->f_flag == 0 && fs->f_namemax == 0;
}

static void metadata_acceptance(void) {
    int before = failures;
    const char *directory = "/tmp/resource-sgid";
    check("setgid directory creation", mkdir(directory, 02775) == 0);
    check("setgid directory mode", chmod(directory, 02775) == 0);
    check("privileged directory chown", chown(directory, 0, 100) == 0);
    struct stat st;
    check("directory chown preserves setgid", stat(directory, &st) == 0
        && (st.st_mode & 07777) == 02775 && st.st_gid == 100);
    check("no-op directory chown", chown(directory, (uid_t)-1, (gid_t)-1) == 0);
    check("no-op directory chown preserves setgid", stat(directory, &st) == 0
        && (st.st_mode & 07777) == 02775 && st.st_gid == 100);
    check("child directory creation", mkdir("/tmp/resource-sgid/child", 0755) == 0);
    check("child inherits directory group and setgid", stat("/tmp/resource-sgid/child", &st) == 0
        && st.st_gid == 100 && (st.st_mode & S_ISGID));
    check("setgid directory opens to others", chmod(directory, 02777) == 0);
    for (int member = 0; member < 2; member++) {
        pid_t creator = fork();
        if (creator == 0) {
            if (setgid(member ? 100 : 200) || setuid(1000)) _exit(40);
            int made = open(member ? "/tmp/resource-sgid/member" : "/tmp/resource-sgid/foreign",
                O_CREAT | O_EXCL | O_WRONLY, 02755);
            if (made < 0) _exit(41);
            close(made);
            if (mkfifo(member ? "/tmp/resource-sgid/member-fifo" : "/tmp/resource-sgid/foreign-fifo",
                    02755)) _exit(42);
            _exit(0);
        }
        check("creator under a set-group-ID directory", creator > 0 && reaped(creator, 0));
    }
    check("file of a foreign group loses set-group-ID", stat("/tmp/resource-sgid/foreign", &st) == 0
        && st.st_gid == 100 && !(st.st_mode & S_ISGID) && (st.st_mode & 0777) == 0755);
    check("fifo of a foreign group loses set-group-ID", stat("/tmp/resource-sgid/foreign-fifo", &st) == 0
        && st.st_gid == 100 && !(st.st_mode & S_ISGID));
    check("file of a member group keeps set-group-ID", stat("/tmp/resource-sgid/member", &st) == 0
        && st.st_gid == 100 && (st.st_mode & S_ISGID));
    check("fifo of a member group keeps set-group-ID", stat("/tmp/resource-sgid/member-fifo", &st) == 0
        && (st.st_mode & S_ISGID));
    check("set-group-ID files cleanup", unlink("/tmp/resource-sgid/foreign") == 0
        && unlink("/tmp/resource-sgid/foreign-fifo") == 0 && unlink("/tmp/resource-sgid/member") == 0
        && unlink("/tmp/resource-sgid/member-fifo") == 0);
    check("setgid child cleanup", rmdir("/tmp/resource-sgid/child") == 0);
    check("setgid directory cleanup", rmdir(directory) == 0);
    struct statvfs fs;
    // This image has no terminal service: /dev/null belongs to RAM,
    // while stdout and pipe descriptors belong to other backends.
    check("RAM device pathname statvfs", statvfs("/dev/null", &fs) == 0
        && ram_filesystem(&fs));
    check("output descriptor statvfs block sizes", fstatvfs(STDOUT_FILENO, &fs) == 0
        && virtual_filesystem(&fs));
    int null = open("/dev/null", O_RDONLY);
    check("null descriptor creation", null >= 0);
    if (null >= 0) {
        check("RAM null descriptor statvfs", fstatvfs(null, &fs) == 0
            && ram_filesystem(&fs));
        close(null);
    }
    int ends[2];
    if (pipe(ends) == 0) {
        check("pipe descriptor statvfs block sizes", fstatvfs(ends[0], &fs) == 0
            && virtual_filesystem(&fs));
        close(ends[0]); close(ends[1]);
    } else check("statvfs pipe creation", 0);
    check("inaccessible PATH directory", mkdir("/tmp/resource-denied", 0700) == 0);
    int file = open("/tmp/resource-denied/procs-child", O_CREAT | O_EXCL | O_WRONLY, 0755);
    check("inaccessible PATH candidate", file >= 0);
    if (file >= 0) close(file);
    pid_t tester = fork();
    if (tester == 0) {
        if (setgid(100) || setuid(1000)) _exit(30);
        char *args[] = {"resources", "f6-path-child", NULL};
        pid_t child;
        if (setenv("PATH", "/tmp/resource-denied:/tmp/resource-missing", 1)) _exit(31);
        if (posix_spawnp(&child, "procs-child", NULL, NULL, args, environ) != EACCES) _exit(32);
        if (setenv("PATH", "/tmp/resource-denied:/bin", 1)) _exit(33);
        if (posix_spawnp(&child, "procs-child", NULL, NULL, args, environ) || !reaped(child, 0)) _exit(34);
        _exit(0);
    }
    check("PATH remembers EACCES and continues to later executable", tester > 0 && reaped(tester, 0));
    check("PATH candidate cleanup", unlink("/tmp/resource-denied/procs-child") == 0);
    check("PATH directory cleanup", rmdir("/tmp/resource-denied") == 0);
    if (failures == before) puts("posix-resources: F6 metadata statvfs and PATH ok");
}

static void acceptance(void) {
    int before = failures;
    check("LINK_MAX reflects the RAM name limit", LINK_MAX == 384);
    check("pathconf LINK_MAX agrees with the header", pathconf("/tmp", _PC_LINK_MAX) == LINK_MAX);
    static const struct { const char *input, *tail; long value; } numbers[] = {
        {"08", "8", 0}, {"09", "9", 0}, {"077x", "x", 63},
        {"0", "", 0}, {"0x", "x", 0}, {"0Xg", "Xg", 0},
        {"0x20z", "z", 32}
    };
    for (unsigned i = 0; i < sizeof numbers / sizeof numbers[0]; i++) {
        char *end;
        errno = EDOM;
        long value = strtol(numbers[i].input, &end, 0);
        check("strtol base zero stops at the first invalid digit", value == numbers[i].value
            && strcmp(end, numbers[i].tail) == 0 && errno == EDOM);
        check("strtoul base zero", strtoul(numbers[i].input, &end, 0) == (unsigned long)numbers[i].value
            && strcmp(end, numbers[i].tail) == 0);
        check("strtoll base zero", strtoll(numbers[i].input, &end, 0) == numbers[i].value
            && strcmp(end, numbers[i].tail) == 0);
        check("strtoull base zero", strtoull(numbers[i].input, &end, 0) == (unsigned long long)numbers[i].value
            && strcmp(end, numbers[i].tail) == 0);
        check("strtoimax base zero", strtoimax(numbers[i].input, &end, 0) == numbers[i].value
            && strcmp(end, numbers[i].tail) == 0);
        check("strtoumax base zero", strtoumax(numbers[i].input, &end, 0) == (uintmax_t)numbers[i].value
            && strcmp(end, numbers[i].tail) == 0);
    }
    char *end;
    check("signed octal prefix", strtol("-08", &end, 0) == 0 && strcmp(end, "8") == 0);
    const char *source = "/tmp/resource-links";
    int fd = open(source, O_CREAT | O_EXCL | O_WRONLY, 0600);
    check("link-limit source", fd >= 0);
    if (fd >= 0) {
        unsigned made = 0;
        char path[64];
        for (; made < (unsigned)LINK_MAX - 1; made++) {
            snprintf(path, sizeof path, "/tmp/resource-link-%u", made);
            if (link(source, path) != 0) break;
        }
        struct stat st;
        check("links reach the advertised limit", made == (unsigned)LINK_MAX - 1
            && fstat(fd, &st) == 0 && st.st_nlink == LINK_MAX);
        for (unsigned i = 0; i < made; i++) {
            snprintf(path, sizeof path, "/tmp/resource-link-%u", i);
            check("link-limit cleanup", unlink(path) == 0);
        }
        close(fd);
        check("link-limit source cleanup", unlink(source) == 0);
    }
    if (failures == before) puts("posix-resources: F6 link limit and integer base ok");
}

static void accounts(void) {
    int before = failures;
    static const struct { const char *name; uid_t uid; gid_t gid; } entries[] = {
        {"root", 0, 0}, {"user", 1000, 100}, {"nobody", 65534, 65534}
    };
    for (unsigned i = 0; i < sizeof entries / sizeof entries[0]; i++) {
        struct passwd *pw = getpwnam(entries[i].name);
        check("account name lookup", pw && pw->pw_uid == entries[i].uid
            && pw->pw_gid == entries[i].gid);
        pw = getpwuid(entries[i].uid);
        check("account ID lookup", pw && strcmp(pw->pw_name, entries[i].name) == 0);
        struct group *gr = getgrnam(entries[i].name);
        check("group name lookup", gr && gr->gr_gid == entries[i].gid);
        gr = getgrgid(entries[i].gid);
        check("group ID lookup", gr && strcmp(gr->gr_name, entries[i].name) == 0);
    }
    struct passwd pw, *pw_result = NULL;
    char pw_buffer[512];
    check("caller-owned password buffer", getpwuid_r(0, &pw, pw_buffer,
        sizeof pw_buffer, &pw_result) == 0 && pw_result == &pw
        && strcmp(pw.pw_name, "root") == 0);
    (void)getpwnam("nobody");
    check("password buffer survives later lookup", pw_result == &pw
        && strcmp(pw.pw_name, "root") == 0);
    pw_result = NULL;
    check("password ERANGE", getpwnam_r("root", &pw, pw_buffer, 1, &pw_result) == ERANGE
        && pw_result == NULL);
    struct group gr, *gr_result = NULL;
    char gr_buffer[512];
    check("caller-owned group buffer", getgrgid_r(0, &gr, gr_buffer,
        sizeof gr_buffer, &gr_result) == 0 && gr_result == &gr
        && strcmp(gr.gr_name, "root") == 0);
    (void)getgrnam("nobody");
    check("group buffer survives later lookup", gr_result == &gr
        && strcmp(gr.gr_name, "root") == 0);
    gr_result = NULL;
    check("group ERANGE", getgrnam_r("root", &gr, gr_buffer, 1, &gr_result) == ERANGE
        && gr_result == NULL);
    check("missing account", getpwnam("missing-resource-user") == NULL);
    check("account prefix is a distinct name", getpwnam("roo") == NULL && getpwnam("root-extra") == NULL);
    check("missing group", getgrnam("missing-resource-group") == NULL);
    check("group prefix is a distinct name", getgrnam("roo") == NULL && getgrnam("root-extra") == NULL);
    gr_result = &gr;
    check("missing group clears caller result", getgrnam_r("missing-resource-group", &gr,
        gr_buffer, sizeof gr_buffer, &gr_result) == 0 && gr_result == NULL);
    char unaligned[513];
    gr_result = NULL;
    check("unaligned caller buffer produces aligned member pointers",
        getgrnam_r("root", &gr, unaligned + 1, sizeof unaligned - 1, &gr_result) == 0
        && gr_result == &gr && (uintptr_t)gr.gr_mem % _Alignof(char *) == 0
        && gr.gr_mem[0] && strcmp(gr.gr_mem[0], "root") == 0 && gr.gr_mem[1] == NULL);
    setpwent();
    unsigned count = 0;
    while (getpwent()) count++;
    endpwent();
    check("password enumeration", count == 3);
    setpwent();
    struct passwd *first = getpwent();
    check("password rewind", first && strcmp(first->pw_name, "root") == 0);
    endpwent();
    setgrent(); count = 0;
    while (getgrent()) count++;
    endgrent();
    check("group enumeration", count == 3);
    setgrent();
    struct group *first_group = getgrent();
    check("group rewind", first_group && strcmp(first_group->gr_name, "root") == 0);
    endgrent();
    check("reported supplementary group capacity", sysconf(_SC_NGROUPS_MAX) == 16);
    gid_t groups[16];
    for (unsigned i = 0; i < 16; i++) groups[i] = 12345;
    int group_count = getgroups(0, NULL);
    check("supplementary group count from actual root credentials", group_count == 1);
    check("zero size does not write", getgroups(0, groups) == group_count && groups[0] == 12345);
    check("supplementary root group", getgroups(16, groups) == group_count && groups[0] == 0);
    errno = 0;
    check("negative group array size", getgroups(-1, groups) == -1 && errno == EINVAL);
    struct stat info;
    check("password database permissions", stat("/etc/passwd", &info) == 0
        && info.st_uid == 0 && (info.st_mode & 0777) == 0644);
    check("group database permissions", stat("/etc/group", &info) == 0
        && info.st_uid == 0 && (info.st_mode & 0777) == 0644);
    if (failures == before) puts("posix-resources: accounts and supplementary groups ok");
}

static void nofile(void) {
    int before = failures;
    struct rlimit saved;
    check("read NOFILE", getrlimit(RLIMIT_NOFILE, &saved) == 0);
    int file = open("/tmp/resource-nofile", O_CREAT | O_TRUNC | O_RDWR, 0600);
    check("NOFILE source", file >= 0);
    if (file < 0) return;
    int high = dup2(file, 20);
    check("existing high descriptor", high == 20);
    struct rlimit small = {8, saved.rlim_max};
    check("set NOFILE8", setrlimit(RLIMIT_NOFILE, &small) == 0 && same_limit(RLIMIT_NOFILE, &small));
    check("sysconf follows current NOFILE", sysconf(_SC_OPEN_MAX) == 8);
    check("existing high descriptor remains usable", write(high, "H", 1) == 1);
    check("same-fd dup2 requires no allocation", dup2(high, high) == high);
    errno = 0;
    check("dup2 ceiling", dup2(file, 8) == -1 && errno == EBADF);
    errno = 0;
    check("dup3 ceiling", dup3(file, 8, 0) == -1 && errno == EBADF);
    errno = 0;
    check("F_DUPFD minimum ceiling", fcntl(file, F_DUPFD, 8) == -1 && errno == EINVAL);
    int opened[32], count = 0;
    while (count < 32) {
        int fd = open("/dev/null", O_RDONLY);
        if (fd < 0) break;
        opened[count++] = fd;
        check("open stays below NOFILE", fd < 8);
    }
    check("NOFILE exhaustion", count == 4 && errno == EMFILE);
    if (count) {
        close(opened[--count]);
        int ends[2] = {-1, -1};
        errno = 0;
        check("pipe refuses partial allocation", pipe(ends) == -1 && errno == EMFILE);
        int last = dup(file);
        check("failed pipe restores vacant descriptor", last == 7);
        if (last >= 0) close(last);
    }
    while (count) close(opened[--count]);
    pid_t child = fork();
    if (child == 0) {
        if (!same_limit(RLIMIT_NOFILE, &small) || write(high, "C", 1) != 1) _exit(1);
        if (setuid(65534)) _exit(2);
        struct rlimit raised = {8, saved.rlim_max + 1};
        errno = 0;
        if (setrlimit(RLIMIT_NOFILE, &raised) != -1 || errno != EPERM
            || !same_limit(RLIMIT_NOFILE, &small)) _exit(3);
        _exit(0);
    }
    check("fork inherits limits and enforces hard-raise privilege", child > 0 && reaped(child, 0));
    struct rlimit infinity = {RLIM_INFINITY, RLIM_INFINITY};
    check("privileged infinity roundtrip", setrlimit(RLIMIT_NOFILE, &infinity) == 0
        && same_limit(RLIMIT_NOFILE, &infinity));
    count = 0;
    while (count < 32) {
        int fd = open("/dev/null", O_RDONLY);
        if (fd < 0) break;
        opened[count++] = fd;
    }
    check("physical capacity remains finite under infinity", count == 27 && errno == EMFILE);
    while (count) close(opened[--count]);
    struct rlimit invalid = {9, 8};
    errno = 0;
    check("invalid limits are atomic", setrlimit(RLIMIT_NOFILE, &invalid) == -1
        && errno == EINVAL && same_limit(RLIMIT_NOFILE, &infinity));
    check("restore NOFILE", setrlimit(RLIMIT_NOFILE, &saved) == 0);
    close(high); close(file);
    struct rlimit core = {0, 0};
    check("CORE zero succeeds", setrlimit(RLIMIT_CORE, &core) == 0 && same_limit(RLIMIT_CORE, &core));
    if (failures == before) puts("posix-resources: NOFILE allocation and inherited limits ok");
}
static void size_handler(int signal) {
    if (signal == SIGXFSZ) size_signals++;
}
static void size_jump_handler(int signal) {
    if (signal == SIGXFSZ) siglongjmp(size_jump, 1);
}
static void fsize(void) {
    int before = failures;
    struct rlimit saved;
    check("read FSIZE", getrlimit(RLIMIT_FSIZE, &saved) == 0);
    int file = open("/tmp/resource-fsize", O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (file < 0) { check("FSIZE source", 0); return; }
    struct sigaction action = {.sa_handler = size_handler};
    sigemptyset(&action.sa_mask);
    struct sigaction previous;
    check("install SIGXFSZ handler", sigaction(SIGXFSZ, &action, &previous) == 0);
    struct rlimit small = {16, saved.rlim_max};
    check("set FSIZE16", setrlimit(RLIMIT_FSIZE, &small) == 0 && same_limit(RLIMIT_FSIZE, &small));
    check("write before limit", write(file, "abcdefghijkl", 12) == 12);
    check("write stops at limit", write(file, "mnopqrst", 8) == 4 && size_signals == 0);
    off_t position = lseek(file, 0, SEEK_CUR);
    errno = 0;
    check("FSIZE EFBIG and signal", write(file, "x", 1) == -1
        && errno == EFBIG && size_signals == 1 && lseek(file, 0, SEEK_CUR) == position);
    struct stat info;
    errno = 0;
    check("ftruncate growth is atomic", ftruncate(file, 17) == -1
        && errno == EFBIG && size_signals == 2 && fstat(file, &info) == 0 && info.st_size == 16);
    errno = 0;
    check("pwrite at limit", pwrite(file, "x", 1, 16) == -1 && errno == EFBIG && size_signals == 3);
    check("shrink is permitted", ftruncate(file, 8) == 0);
    check("partial pwrite", pwrite(file, "ABCD", 4, 15) == 1 && lseek(file, 0, SEEK_CUR) == position);
    check("overwrite inside limit", pwrite(file, "W", 1, 0) == 1);
    sigset_t block, old_mask;
    sigemptyset(&block); sigaddset(&block, SIGXFSZ);
    check("block SIGXFSZ", sigprocmask(SIG_BLOCK, &block, &old_mask) == 0);
    errno = 0;
    check("blocked size limit", pwrite(file, "x", 1, 16) == -1 && errno == EFBIG && size_signals == 3);
    sigset_t pending;
    check("SIGXFSZ remains pending", sigpending(&pending) == 0 && sigismember(&pending, SIGXFSZ) == 1);
    check("unblock delivers SIGXFSZ", sigprocmask(SIG_SETMASK, &old_mask, NULL) == 0 && size_signals == 4);
    int append = open("/tmp/resource-fsize", O_WRONLY | O_APPEND);
    check("append source", append >= 0);
    if (append >= 0) {
        check("append shrink setup", ftruncate(file, 8) == 0);
        check("append uses actual EOF", write(append, "abcdefghijkl", 12) == 8);
        check("zero-byte append", write(append, "", 0) == 0 && size_signals == 4);
        errno = 0;
        check("append at limit signals", write(append, "x", 1) == -1 && errno == EFBIG && size_signals == 5);
        check("concurrent append setup", ftruncate(file, 0) == 0);
        pid_t child = fork();
        if (child == 0) {
            ssize_t amount = write(append, "abcdefghijkl", 12);
            _exit(amount == 12 ? 12 : amount == 4 ? 4 : 1);
        }
        ssize_t amount = write(append, "mnopqrstuvwx", 12);
        int status = 0;
        check("concurrent append obeys one shared limit", child > 0
            && waitpid(child, &status, 0) == child && WIFEXITED(status)
            && amount + WEXITSTATUS(status) == 16
            && fstat(file, &info) == 0 && info.st_size == 16);
        close(append);
    }
    pid_t child = fork();
    if (child == 0) {
        signal(SIGXFSZ, SIG_DFL);
        (void)pwrite(file, "x", 1, 16);
        _exit(7);
    }
    int status = 0;
    check("default SIGXFSZ ends the child", child > 0 && waitpid(child, &status, 0) == child
        && WIFSIGNALED(status) && WTERMSIG(status) == SIGXFSZ);
    int vacant = dup(file);
    check("path truncate fd baseline", vacant >= 0);
    if (vacant >= 0) close(vacant);
    struct sigaction jumping = {.sa_handler = size_jump_handler};
    sigemptyset(&jumping.sa_mask);
    check("path truncate jumping handler", sigaction(SIGXFSZ, &jumping, NULL) == 0);
    for (volatile int attempt = 0; attempt < 4; attempt++) {
        if (sigsetjmp(size_jump, 1) == 0) {
            (void)truncate("/tmp/resource-fsize", 17);
            check("path truncate delivers SIGXFSZ before return", 0);
        }
    }
    int after_jump = dup(file);
    check("path truncate cleans internal fd before signal jump", after_jump == vacant);
    if (after_jump >= 0) close(after_jump);
    check("path truncate refusals preserve file size", fstat(file, &info) == 0 && info.st_size == 16);
    check("restore size handler after jumps", sigaction(SIGXFSZ, &action, NULL) == 0);
    struct rlimit wide = {64, saved.rlim_max};
    check("set FSIZE64", setrlimit(RLIMIT_FSIZE, &wide) == 0);
    check("grow past the later limit", ftruncate(file, 40) == 0);
    check("set FSIZE16 again", setrlimit(RLIMIT_FSIZE, &small) == 0);
    int signals = size_signals;
    check("shrink above the limit succeeds", ftruncate(file, 30) == 0 && size_signals == signals
        && fstat(file, &info) == 0 && info.st_size == 30);
    check("path shrink above the limit succeeds", truncate("/tmp/resource-fsize", 20) == 0
        && size_signals == signals && fstat(file, &info) == 0 && info.st_size == 20);
    errno = 0;
    check("growth above the limit is refused", ftruncate(file, 21) == -1
        && errno == EFBIG && size_signals == signals + 1 && fstat(file, &info) == 0
        && info.st_size == 20);
    struct rlimit infinity = {RLIM_INFINITY, RLIM_INFINITY};
    check("FSIZE infinity roundtrip", setrlimit(RLIMIT_FSIZE, &infinity) == 0
        && same_limit(RLIMIT_FSIZE, &infinity));
    check("restore FSIZE", setrlimit(RLIMIT_FSIZE, &saved) == 0);
    check("restore SIGXFSZ action", sigaction(SIGXFSZ, &previous, NULL) == 0);
    close(file);
    if (failures == before) puts("posix-resources: FSIZE writes append and SIGXFSZ ok");
}

static int copy_image(const char *path) {
    int input = open("/bin/procs-child", O_RDONLY);
    if (input < 0) { printf("posix-resources: ELF input open failed errno %d\n", errno); return -1; }
    int output = open(path, O_CREAT | O_TRUNC | O_RDWR, 0755);
    if (output < 0) { printf("posix-resources: ELF output open failed errno %d\n", errno); close(input); return -1; }
    char bytes[2048];
    ssize_t length;
    while ((length = read(input, bytes, sizeof bytes)) > 0) {
        size_t copied = 0;
        while (copied < (size_t)length) {
            ssize_t wrote = write(output, bytes + copied, (size_t)length - copied);
            if (wrote <= 0) {
                printf("posix-resources: ELF copy write failed at %lu errno %d\n", (unsigned long)copied, errno);
                close(input); close(output); return -1;
            }
            copied += (size_t)wrote;
        }
    }
    close(input);
    if (length < 0 || fchmod(output, 0755)) { printf("posix-resources: ELF read or chmod failed errno %d\n", errno); close(output); return -1; }
    return output;
}
static void fexec_checks(void) {
    int before = failures;
    char *args[] = {"resources", "executed", "0", "-1", "0", NULL};
    errno = 0;
    check("fexecve bad descriptor", fexecve(-1, args, environ) == -1 && errno == EBADF);
    int invalid = open("/tmp/resource-invalid", O_CREAT | O_TRUNC | O_RDWR, 0755);
    if (invalid >= 0) {
        check("invalid ELF fixture", write(invalid, "invalid-ELF", 11) == 11);
        errno = 0;
        check("invalid ELF preserves old descriptor", fexecve(invalid, args, environ) == -1
            && errno == ENOEXEC && fcntl(invalid, F_GETFD) >= 0 && lseek(invalid, 0, SEEK_CUR) == 11);
        close(invalid);
    } else check("invalid ELF fixture open", 0);
    int directory = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (directory >= 0) {
        check("directory exec rejected before commit", fexecve(directory, args, environ) == -1
            && fcntl(directory, F_GETFD) >= 0);
        close(directory);
    }
    int file = copy_image("/tmp/resource-elf");
    check("create executable RAM ELF", file >= 0);
    if (file < 0) return;
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    check("rollback PID lock setup", fcntl(file, F_SETLK, &lock) == 0);
    check("early failure CLOEXEC setup", fcntl(file, F_SETFD, FD_CLOEXEC) == 0);
    check("revoke execute permission", fchmod(file, 0644) == 0);
    errno = 0;
    check("exec rechecks current permission", fexecve(file, args, environ) == -1
        && errno == EACCES && fcntl(file, F_GETFD) == FD_CLOEXEC);
    pid_t rollback_child = fork();
    if (rollback_child == 0) {
        struct flock seen = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
        _exit(fcntl(file, F_GETLK, &seen) == 0 && seen.l_type == F_WRLCK
            && seen.l_pid == getppid() && seen.l_start == 0 && seen.l_len == 1 ? 0 : 23);
    }
    check("failed descriptor exec preserves parent PID locks", rollback_child > 0
        && reaped(rollback_child, 0));
    check("restore execute permission", fchmod(file, 0755) == 0);
    close(file);
    file = open("/tmp/resource-elf", O_WRONLY);
    check("write-only executable descriptor", file >= 0);
    if (file < 0) return;
    check("select nonzero offset", lseek(file, 17, SEEK_SET) == 17);
    struct rlimit saved;
    check("exec limit snapshot", getrlimit(RLIMIT_NOFILE, &saved) == 0);
    struct rlimit small = {12, saved.rlim_max};
    check("exec inheritance limit", setrlimit(RLIMIT_NOFILE, &small) == 0);
    pid_t ofd_child = fork();
    if (ofd_child == 0) {
        close(file);
        int source = open("/tmp/resource-elf", O_WRONLY);
        int observer = open("/tmp/resource-elf", O_RDONLY);
        struct flock ofd = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
        if (source < 0 || observer < 0 || fcntl(source, F_OFD_SETLK, &ofd)
            || fcntl(source, F_SETFD, FD_CLOEXEC)) _exit(24);
        struct flock pid_lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 2, .l_len = 1};
        if (fcntl(source, F_SETLK, &pid_lock)) _exit(27);
        char pid_text[32], fd_text[32], observer_text[32];
        snprintf(pid_text, sizeof pid_text, "%ld", (long)getpid());
        snprintf(fd_text, sizeof fd_text, "%d", source);
        snprintf(observer_text, sizeof observer_text, "%d", observer);
        char *exec_args[] = {"resources", "executed", pid_text, fd_text, "1", observer_text, NULL};
        char *exec_env[] = {"RESOURCE_EXEC_ENV=verified", NULL};
        fexecve(source, exec_args, exec_env);
        _exit(25);
    }
    check("CLOEXEC source releases its final OFD lock before new image", ofd_child > 0
        && reaped(ofd_child, 0));
    check("rename selected inode", rename("/tmp/resource-elf", "/tmp/resource-renamed") == 0);
    check("unlink selected inode", unlink("/tmp/resource-renamed") == 0);
    int replacement = open("/tmp/resource-elf", O_CREAT | O_TRUNC | O_WRONLY, 0755);
    check("replace original pathname", replacement >= 0 && write(replacement, "invalid-ELF", 11) == 11);
    if (replacement >= 0) close(replacement);
    for (int cloexec = 0; cloexec < 2; cloexec++) {
        check("source CLOEXEC flags", fcntl(file, F_SETFD, cloexec ? FD_CLOEXEC : 0) == 0);
        pid_t child = fork();
        if (child == 0) {
            char pid_text[32], fd_text[32], close_text[8];
            snprintf(pid_text, sizeof pid_text, "%ld", (long)getpid());
            snprintf(fd_text, sizeof fd_text, "%d", file);
            snprintf(close_text, sizeof close_text, "%d", cloexec);
            char *exec_args[] = {"resources", "executed", pid_text, fd_text, close_text, NULL};
            char *exec_env[] = {"RESOURCE_EXEC_ENV=verified", NULL};
            fexecve(file, exec_args, exec_env);
            _exit(19);
        }
        check("descriptor-selected exec ignores offset/path and applies CLOEXEC",
            child > 0 && reaped(child, 0));
        check("parent descriptor and offset survive child exec", fcntl(file, F_GETFD) >= 0
            && lseek(file, 0, SEEK_CUR) == 17);
    }
    check("restore exec test limit", setrlimit(RLIMIT_NOFILE, &saved) == 0);
    close(file);
    if (failures == before) puts("posix-resources: fexecve exact inode offset and CLOEXEC ok");
}
int main(int argc, char **argv) {
    if (argc == 1) {
        char *args[] = {"resources", "run", NULL};
        pid_t child;
        int error = posix_spawn(&child, "/bin/procs-child", NULL, NULL, args, environ);
        if (error) { printf("posix-resources: launcher failed %d\n", error); return 1; }
        return reaped(child, 0) ? 0 : 1;
    }
    if ((argc == 5 || argc == 6) && strcmp(argv[1], "executed") == 0) {
        int fd = atoi(argv[3]), closed = atoi(argv[4]);
        struct rlimit limits;
        const char *value = getenv("RESOURCE_EXEC_ENV");
        if (getpid() != (pid_t)strtol(argv[2], NULL, 10) || !value || strcmp(value, "verified")
            || getrlimit(RLIMIT_NOFILE, &limits) || limits.rlim_cur != 12 || getgroups(0, NULL) != 1) return 20;
        errno = 0;
        if (closed) {
            if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) return 21;
            if (argc == 6) {
                struct flock seen = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
                if (fcntl(atoi(argv[5]), F_GETLK, &seen) || seen.l_type != F_UNLCK) return 26;
                seen.l_type = F_WRLCK;
                seen.l_start = 2;
                if (fcntl(atoi(argv[5]), F_OFD_GETLK, &seen) || seen.l_type != F_UNLCK) return 28;
            }
            return 0;
        }
        return fcntl(fd, F_GETFD) >= 0 && lseek(fd, 0, SEEK_CUR) == 17 ? 0 : 22;
    }
    if (argc == 2 && strcmp(argv[1], "f6-path-child") == 0) return 0;
    acceptance();
    metadata_acceptance();
    accounts();
    nofile();
    fsize();
    fexec_checks();
    return failures ? 1 : 0;
}
