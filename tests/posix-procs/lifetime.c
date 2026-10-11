/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* Actual Loaded, spawn, fork, credentials, exec and death transitions. */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef LIFETIME_RULES_ONLY
#define LIFETIME_RULES_ONLY 0
#endif
#ifndef LOCK_CORE_ONLY
#define LOCK_CORE_ONLY 0
#endif
#ifndef PAGE_FRAGMENTS_ONLY
#define PAGE_FRAGMENTS_ONLY 0
#endif
#ifndef LOCK_FIFO_FULL_ONLY
#define LOCK_FIFO_FULL_ONLY 0
#endif

extern void stafeto_probe_loader_bundle(unsigned mode);
extern int process_lifetime(int pid);
extern int ram_lifetime(int pid);
extern int ram_close_event(void);
extern int ram_lock_commands(int pid);
extern int close_driver_receipts(void);
extern int close_driver_full_places(void);
extern int lock_driver_receipts(int fd);
extern void lock_driver_signal_arm(unsigned mode);
extern unsigned lock_driver_signal_disarm(void);
extern void close_driver_jump_arm(int fd);
extern int close_driver_jump_recover(int fd);
static sigjmp_buf close_jump;
static volatile sig_atomic_t close_signal_seen;
static void close_signal(int number) {
    close_signal_seen = number;
    siglongjmp(close_jump, 1);
}
void close_probe_signal_jump(void) { raise(SIGUSR1); }

static int failures;
static void expect(const char *what, int actual, int wanted) {
    if (actual != wanted) {
        printf("PID lifetime: %s: got %d, expected %d, errno %d\n", what, actual, wanted, errno);
        failures++;
    }
}
static void expect_life(const char *what, pid_t pid, int wanted) {
    expect(what, process_lifetime(pid), wanted);
    expect("RAM observes exact PID lifetime", ram_lifetime(pid), wanted);
}
static void reap(pid_t child, int killed) {
    int status = 0;
    expect("wait", waitpid(child, &status, 0), child);
    expect("wait status", killed ? WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL
                                : WIFEXITED(status) && WEXITSTATUS(status) == 0, 1);
    expect_life("dead before wait returns", child, 0);
}

/* Each lifecycle rule uses a public lock and one synchronized child. */
static int lifecycle_set(int fd, int command) {
    struct flock lock = {0};
    lock.l_type = F_WRLCK; lock.l_whence = SEEK_SET; lock.l_len = 1;
    return fcntl(fd, command, &lock);
}
static void lifecycle_query(int fd, int wanted, pid_t owner) {
    struct flock lock = {0};
    lock.l_type = F_WRLCK; lock.l_whence = SEEK_SET; lock.l_len = 1;
    expect("lifecycle GETLK", fcntl(fd, F_GETLK, &lock), 0);
    expect("lifecycle blocker type", lock.l_type, wanted);
    if (wanted != F_UNLCK) expect("lifecycle exact blocker", lock.l_pid, owner);
}
static void lifecycle_child_wait(int ready, int resume) {
    char byte = 'r';
    if (write(ready, &byte, 1) != 1 || read(resume, &byte, 1) != 1) _exit(91);
}
static int lifecycle_exec_image(int argc, char **argv) {
    if (argc != 7) return 92;
    pid_t original = atoi(argv[2]);
    int fd = atoi(argv[3]), alias = atoi(argv[4]);
    int ready = atoi(argv[5]), resume = atoi(argv[6]);
    /* Let the replaced image's exit notification reach the process service. */
    const struct timespec delay = {0, 10000000};
    nanosleep(&delay, NULL);
    expect("exec retained exact PID", getpid(), original);
    expect_life("exec retained PID lifetime", original, 1);
    expect("exec retained descriptor", fcntl(fd, F_GETFD) >= 0, 1);
    if (alias >= 0) {
        errno = 0;
        expect("exec closed CLOEXEC alias", fcntl(alias, F_GETFD), -1);
        expect("exec CLOEXEC alias errno", errno, EBADF);
    }
    lifecycle_child_wait(ready, resume);
    return failures != 0;
}
static void lifecycle_exec(int fd, int alias, int ready, int resume) {
    char pid_text[16], fd_text[16], alias_text[16], ready_text[16], resume_text[16];
    snprintf(pid_text, sizeof pid_text, "%d", getpid());
    snprintf(fd_text, sizeof fd_text, "%d", fd);
    snprintf(alias_text, sizeof alias_text, "%d", alias);
    snprintf(ready_text, sizeof ready_text, "%d", ready);
    snprintf(resume_text, sizeof resume_text, "%d", resume);
    char *args[] = {"procs-child", "lock-exec-observe", pid_text, fd_text,
                    alias_text, ready_text, resume_text, NULL};
    char *env[] = {NULL};
    execve("/bin/procs-child", args, env);
    _exit(93);
}
static int lifecycle_open(const char *path) {
    int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0666);
    expect("open lifecycle file", fd >= 0, 1);
    return fd;
}
static void lifecycle_observe(pid_t child, int fd, int ready[2], int resume[2], int blocked) {
    close(ready[1]); close(resume[0]);
    char byte = 0;
    expect("lifecycle child ready", read(ready[0], &byte, 1), 1);
    expect("lifecycle ready byte", byte, 'r');
    lifecycle_query(fd, blocked ? F_WRLCK : F_UNLCK, child);
    expect("resume lifecycle child", write(resume[1], "c", 1), 1);
    reap(child, 0);
    close(ready[0]); close(resume[1]);
}
static void lifecycle_exec_rule(int cloexec) {
    int fd = lifecycle_open(cloexec ? "/tmp/lock-l3" : "/tmp/lock-l2");
    if (fd < 0) return;
    int ready[2], resume[2];
    if (pipe(ready) || pipe(resume)) { failures++; close(fd); return; }
    pid_t child = fork();
    if (child == 0) {
        close(ready[0]); close(resume[1]);
        if (lifecycle_set(fd, F_SETLK)) _exit(94);
        int alias = -1;
        if (cloexec) {
            alias = dup(fd);
            if (alias < 0 || fcntl(alias, F_SETFD, FD_CLOEXEC)) _exit(95);
        }
        lifecycle_exec(fd, alias, ready[1], resume[0]);
    }
    expect("fork lifecycle exec", child > 0, 1);
    if (child > 0) lifecycle_observe(child, fd, ready, resume, !cloexec);
    close(fd);
    if (!failures) printf("posix-procs: lock L%d exec rule ok\n", cloexec ? 3 : 2);
}
static void lifecycle_exec_failure(void) {
    int fd = lifecycle_open("/tmp/lock-l4");
    if (fd < 0) return;
    int ready[2], resume[2];
    if (pipe(ready) || pipe(resume)) { failures++; close(fd); return; }
    pid_t child = fork();
    if (child == 0) {
        close(ready[0]); close(resume[1]);
        if (lifecycle_set(fd, F_SETLK) || fcntl(fd, F_SETFD, FD_CLOEXEC)) _exit(96);
        char *args[] = {"missing-lock-image", NULL}, *env[] = {NULL};
        errno = 0;
        expect("early exec failure", execve("/no-lock-image", args, env), -1);
        expect("early exec errno", errno, ENOENT);
        expect("early exec retained CLOEXEC", fcntl(fd, F_GETFD), FD_CLOEXEC);
        lifecycle_child_wait(ready[1], resume[0]);
        _exit(failures != 0);
    }
    expect("fork early exec failure", child > 0, 1);
    if (child > 0) lifecycle_observe(child, fd, ready, resume, 1);
    child = fork();
    if (child == 0) {
        if (lifecycle_set(fd, F_SETLK)) _exit(97);
        /* Existing omission mode rejects the moved RAM descriptor bundle. */
        stafeto_probe_loader_bundle(5);
        char *args[] = {"procs-child", "exec", NULL}, *env[] = {NULL};
        execve("/bin/procs-child", args, env);
        _exit(98);
    }
    expect("fork late exec failure", child > 0, 1);
    if (child > 0) {
        int status = 0;
        expect("wait late exec failure", waitpid(child, &status, 0), child);
        expect("late exec exits 127", WIFEXITED(status) ? WEXITSTATUS(status) : -1, 127);
        expect_life("late exec death published", child, 0);
        lifecycle_query(fd, F_UNLCK, 0);
    }
    close(fd);
    if (!failures) puts("posix-procs: lock L4 exec failure boundary ok");
}
static void lifecycle_clofork(void) {
    const char *path = "/tmp/lock-l5";
    int fd = lifecycle_open(path);
    if (fd < 0) return;
    expect("parent OFD lock", lifecycle_set(fd, 37), 0);
    expect("parent CLOFORK descriptor", fcntl(fd, F_SETFD, FD_CLOFORK), 0);
    int ready[2], resume[2];
    if (pipe(ready) || pipe(resume)) { failures++; close(fd); return; }
    pid_t child = fork();
    if (child == 0) {
        close(ready[0]); close(resume[1]);
        errno = 0;
        expect("CLOFORK child has no descriptor", fcntl(fd, F_GETFD), -1);
        expect("CLOFORK child descriptor errno", errno, EBADF);
        int independent = open(path, O_RDWR);
        expect("CLOFORK child independent open", independent >= 0, 1);
        if (independent >= 0) lifecycle_query(independent, F_WRLCK, -1);
        lifecycle_child_wait(ready[1], resume[0]);
        /* The excluded child cannot retain a hidden reference after parent close. */
        if (independent >= 0) { lifecycle_query(independent, F_UNLCK, 0); close(independent); }
        _exit(failures != 0);
    }
    expect("fork CLOFORK child", child > 0, 1);
    close(ready[1]); close(resume[0]);
    if (child > 0) {
        char byte = 0;
        expect("excluded child ready", read(ready[0], &byte, 1), 1);
        lifecycle_query(fd, F_WRLCK, -1);
        expect("parent final OFD close while excluded child lives", close(fd), 0);
        expect("resume excluded child", write(resume[1], "c", 1), 1);
        reap(child, 0);
    } else close(fd);
    close(ready[0]); close(resume[1]);
    fd = open(path, O_RDWR);
    if (fd >= 0) { lifecycle_query(fd, F_UNLCK, 0); close(fd); }
    else failures++;
    if (!failures) puts("posix-procs: lock L5 excluded child preserves OFD ok");
}
static void lifecycle_death(void) {
    int fd = lifecycle_open("/tmp/lock-l6");
    if (fd < 0) return;
    int ready[2], resume[2];
    if (pipe(ready) || pipe(resume)) { failures++; close(fd); return; }
    pid_t child = fork();
    if (child == 0) {
        close(ready[0]); close(resume[1]);
        if (lifecycle_set(fd, F_SETLK)) _exit(99);
        lifecycle_child_wait(ready[1], resume[0]);
        _exit(100);
    }
    expect("fork PID lock death", child > 0, 1);
    close(ready[1]); close(resume[0]);
    if (child > 0) {
        char byte = 0;
        expect("PID lock owner ready", read(ready[0], &byte, 1), 1);
        lifecycle_query(fd, F_WRLCK, child);
        expect("kill PID lock owner", kill(child, SIGKILL), 0);
        reap(child, 1);
        lifecycle_query(fd, F_UNLCK, 0);
    }
    close(ready[0]); close(resume[1]); close(fd);
    if (!failures) puts("posix-procs: lock L6 death precedes wait reply ok");
}
static void public_lock_lifecycles(void) {
    lifecycle_exec_rule(0);
    lifecycle_exec_rule(1);
    lifecycle_exec_failure();
    lifecycle_clofork();
    lifecycle_death();
}


static void public_lock_capacity(void) {
    enum { INODES = 6, SEGMENTS = 64 };
    int files[INODES];
    for (int inode = 0; inode < INODES; inode++) {
        char path[40];
        snprintf(path, sizeof path, "/tmp/inode-lock-capacity-%d", inode);
        files[inode] = lifecycle_open(path);
        if (files[inode] < 0) {
            for (int earlier = 0; earlier < inode; earlier++) close(files[earlier]);
            return;
        }
        for (int segment = 0; segment < SEGMENTS; segment++) {
            struct flock lock = {0};
            lock.l_type = F_WRLCK; lock.l_whence = SEEK_SET;
            lock.l_start = segment * 2; lock.l_len = 1;
            expect("64 segments on each of six inodes", fcntl(files[inode], F_SETLK, &lock), 0);
        }
    }
    struct flock extra = {0};
    extra.l_type = F_WRLCK; extra.l_whence = SEEK_SET;
    extra.l_start = SEGMENTS * 2; extra.l_len = 1;
    errno = 0;
    expect("65th inode segment fails", fcntl(files[0], F_SETLK, &extra), -1);
    expect("65th inode segment errno", errno, ENOLCK);
    for (int segment = 0; segment <= SEGMENTS; segment++) {
        struct flock query = {0};
        query.l_type = F_WRLCK; query.l_whence = SEEK_SET;
        query.l_start = segment * 2; query.l_len = 1;
        /* OFD GET also observes the caller's PID locks. */
        expect("capacity snapshot GET", fcntl(files[0], 36, &query), 0);
        expect("ENOLCK preserves every original segment", query.l_type,
               segment < SEGMENTS ? F_WRLCK : F_UNLCK);
        if (segment < SEGMENTS) {
            expect("capacity snapshot exact PID", query.l_pid, getpid());
            expect("capacity snapshot exact start", (int)query.l_start, segment * 2);
            expect("capacity snapshot exact length", (int)query.l_len, 1);
        }
    }
    struct flock released = {0};
    released.l_type = F_UNLCK; released.l_whence = SEEK_SET; released.l_len = 1;
    expect("release one full-inode segment", fcntl(files[0], F_SETLK, &released), 0);
    expect("reuse released inode segment", fcntl(files[0], F_SETLK, &extra), 0);
    for (int inode = 0; inode < INODES; inode++) expect("close capacity inode", close(files[inode]), 0);
    int check = open("/tmp/inode-lock-capacity-0", O_RDWR);
    expect("reopen capacity inode", check >= 0, 1);
    if (check >= 0) {
        struct flock query = {0};
        query.l_type = F_WRLCK; query.l_whence = SEEK_SET;
        expect("capacity close clears all segments", fcntl(check, F_GETLK, &query), 0);
        expect("capacity inode unlocked after close", query.l_type, F_UNLCK);
        close(check);
    }
    if (!failures) puts("posix-procs: six inodes retain 384 locks, inode64 ENOLCK is atomic and slots reuse ok");
}

/* A compact maximum-inode fixture for genuine dispatch budget measurements. */
static void core_lock_query(int fd, off_t start, off_t length, short kind,
                            off_t blocker_start, off_t blocker_length) {
    struct flock query = {0};
    query.l_type = F_WRLCK; query.l_whence = SEEK_SET;
    query.l_start = start; query.l_len = length;
    struct flock unchanged;
    memcpy(&unchanged, &query, sizeof query);
    expect("core OFD GET input PID is zero", query.l_pid, 0);
    expect("core full-inode public GET", fcntl(fd, 36, &query), 0);
    expect("core exact blocker type", query.l_type, kind);
    if (kind == F_UNLCK) {
        unchanged.l_type = F_UNLCK;
        expect("core unlocked GET changes only type", memcmp(&query, &unchanged, sizeof query), 0);
    } else {
        expect("core exact blocker PID", query.l_pid, getpid());
        expect("core canonical blocker whence", query.l_whence, SEEK_SET);
        expect("core canonical blocker start", query.l_start == blocker_start, 1);
        expect("core canonical blocker length", query.l_len == blocker_length, 1);
    }
}
static void public_lock_core(void) {
    const char *path = "/tmp/full-inode-lock-core";
    int fd = lifecycle_open(path);
    if (fd < 0) return;
    int alias = dup(fd);
    expect("core ordinary-close alias", alias >= 0, 1);
    if (alias < 0) { close(fd); return; }
    for (int segment = 0; segment < 64; segment++) {
        struct flock lock = {0};
        lock.l_type = F_WRLCK; lock.l_whence = SEEK_SET;
        lock.l_start = 4 * segment; lock.l_len = 3;
        expect("core fill64 disjoint records", fcntl(fd, F_SETLK, &lock), 0);
    }
    core_lock_query(fd, 252, 3, F_WRLCK, 252, 3);
    core_lock_query(fd, 255, 1, F_UNLCK, 0, 0);
    core_lock_query(fd, 0, 0, F_WRLCK, 0, 3);
    struct flock replacement = {0};
    replacement.l_type = F_RDLCK; replacement.l_whence = SEEK_SET;
    replacement.l_start = 252; replacement.l_len = 3;
    expect("core replace final record with different kind", fcntl(fd, F_SETLK, &replacement), 0);
    core_lock_query(fd, 252, 3, F_RDLCK, 252, 3);
    struct flock cut = {0};
    cut.l_type = F_UNLCK; cut.l_whence = SEEK_SET;
    cut.l_start = 125; cut.l_len = 1;
    struct flock before;
    memcpy(&before, &cut, sizeof cut);
    errno = 0;
    expect("core split at64 fails atomically", fcntl(fd, F_SETLK, &cut), -1);
    expect("core split capacity errno", errno, ENOLCK);
    expect("core failed SET preserves input", memcmp(&cut, &before, sizeof cut), 0);
    for (int segment = 0; segment < 64; segment++)
        core_lock_query(fd, 4 * segment, 3, segment == 63 ? F_RDLCK : F_WRLCK,
                        4 * segment, 3);
    struct flock free_slot = {0};
    free_slot.l_type = F_UNLCK; free_slot.l_whence = SEEK_SET; free_slot.l_len = 3;
    expect("core free one record", fcntl(fd, F_SETLK, &free_slot), 0);
    core_lock_query(fd, 0, 3, F_UNLCK, 0, 0);
    memcpy(&cut, &before, sizeof cut);
    expect("core split reuses freed capacity", fcntl(fd, F_SETLK, &cut), 0);
    core_lock_query(fd, 124, 1, F_WRLCK, 124, 1);
    core_lock_query(fd, 125, 1, F_UNLCK, 0, 0);
    core_lock_query(fd, 126, 1, F_WRLCK, 126, 1);
    expect("core ordinary alias close releases every PID record", close(alias), 0);
    core_lock_query(fd, 0, 0, F_UNLCK, 0, 0);
    for (int segment = 0; segment < 64; segment++) {
        struct flock lock = {0};
        lock.l_type = F_WRLCK; lock.l_whence = SEEK_SET;
        lock.l_start = 4 * segment; lock.l_len = 3;
        expect("core refill64 before full coalesce", fcntl(fd, F_SETLK, &lock), 0);
    }
    struct flock whole = {0};
    whole.l_type = F_WRLCK; whole.l_whence = SEEK_SET; whole.l_len = 255;
    expect("core coalesces all64 records in one SET", fcntl(fd, F_SETLK, &whole), 0);
    core_lock_query(fd, 0, 1, F_WRLCK, 0, 255);
    core_lock_query(fd, 252, 3, F_WRLCK, 0, 255);
    core_lock_query(fd, 255, 1, F_UNLCK, 0, 0);
    expect("core final descriptor close", close(fd), 0);
    expect("core unlink fixture", unlink(path), 0);
    if (!failures) puts("posix-procs: full inode lock core ok");
}

static void public_lock_commands(void) {
    int fd = open("/tmp/public-lock-fields", O_CREAT | O_TRUNC | O_RDWR, 0666);
    expect("open public lock file", fd >= 0, 1);
    if (fd < 0) return;
    int alias = dup(fd);
    expect("alias public lock file", alias >= 0, 1);
    if (alias < 0) { close(fd); return; }
    expect("seek before accepted relative lock", lseek(fd, 16, SEEK_SET), 16);
    struct flock lock;
    memset(&lock, 0xa5, sizeof lock);
    lock.l_type = F_WRLCK; lock.l_whence = SEEK_CUR;
    lock.l_start = 4; lock.l_len = 8; lock.l_pid = 123;
    struct flock original;
    memcpy(&original, &lock, sizeof lock);
    expect("public PID SET relative", fcntl(fd, F_SETLK, &lock), 0);
    expect("SET preserves all caller fields and padding", memcmp(&lock, &original, sizeof lock), 0);
    expect("accepted lock leaves cursor", lseek(fd, 0, SEEK_CUR), 16);
    memset(&lock, 0, sizeof lock);
    lock.l_type = F_WRLCK; lock.l_whence = SEEK_SET; lock.l_len = 0;
    expect("public OFD GET sees PID blocker", fcntl(alias, 36, &lock), 0);
    expect("PID blocker type", lock.l_type, F_WRLCK);
    expect("PID blocker absolute origin", lock.l_whence, SEEK_SET);
    expect("PID blocker start", lock.l_start, 20);
    expect("PID blocker length", lock.l_len, 8);
    expect("PID blocker genuine identity", lock.l_pid, getpid());
    pid_t child = fork();
    if (child == 0) {
        struct flock query;
        memset(&query, 0, sizeof query);
        query.l_type = F_WRLCK; query.l_whence = SEEK_SET; query.l_len = 0;
        if (fcntl(fd, F_GETLK, &query) || query.l_pid != getppid() || query.l_start != 20)
            _exit(71);
        query.l_type = F_WRLCK; query.l_whence = SEEK_SET; query.l_start = 20;
        query.l_len = 8; query.l_pid = 0;
        struct flock before;
        memcpy(&before, &query, sizeof query);
        if (fcntl(fd, F_SETLK, &query) != -1 || errno != EAGAIN ||
            memcmp(&query, &before, sizeof query)) _exit(72);
        _exit(0);
    }
    expect("fork PID conflict child", child >= 0, 1);
    if (child > 0) {
        int status = 0;
        expect("wait PID conflict child", waitpid(child, &status, 0), child);
        expect("PID conflict child exit", WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
        expect("PID conflict child is dead", process_lifetime(child), 0);
    }
    expect("close alias releases all PID locks", close(alias), 0);
    memset(&lock, 0xa5, sizeof lock);
    lock.l_type = F_WRLCK; lock.l_whence = SEEK_SET;
    lock.l_start = 20; lock.l_len = 8; lock.l_pid = 0;
    memcpy(&original, &lock, sizeof lock);
    expect("public OFD GET after alias close", fcntl(fd, 36, &lock), 0);
    original.l_type = F_UNLCK;
    expect("unlocked GET changes only type", memcmp(&lock, &original, sizeof lock), 0);
    memset(&lock, 0, sizeof lock);
    lock.l_type = F_RDLCK; lock.l_whence = SEEK_SET; lock.l_start = 30; lock.l_len = 0;
    expect("public OFD SET", fcntl(fd, 37, &lock), 0);
    child = fork();
    if (child == 0) {
        struct flock query;
        memset(&query, 0, sizeof query);
        query.l_type = F_WRLCK; query.l_whence = SEEK_SET; query.l_len = 0;
        if (fcntl(fd, 36, &query) || query.l_type != F_UNLCK) _exit(73);
        query.l_type = F_WRLCK;
        if (fcntl(fd, F_GETLK, &query) || query.l_type != F_RDLCK ||
            query.l_start != 30 || query.l_len != 0 || query.l_pid != -1) _exit(74);
        if (close(fd)) _exit(75);
        _exit(0);
    }
    expect("fork OFD inheritance child", child >= 0, 1);
    if (child > 0) {
        int status = 0;
        expect("wait OFD inheritance child", waitpid(child, &status, 0), child);
        expect("OFD inheritance child exit", WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
        expect("OFD inheritance child is dead", process_lifetime(child), 0);
    }
    memset(&lock, 0, sizeof lock);
    lock.l_type = F_WRLCK; lock.l_whence = SEEK_SET; lock.l_len = 0;
    expect("parent OFD survives child close", fcntl(fd, F_GETLK, &lock), 0);
    expect("surviving OFD blocker", lock.l_pid, -1);
    expect("last OFD close", close(fd), 0);
    fd = open("/tmp/public-lock-fields", O_RDWR);
    expect("reopen after OFD retirement", fd >= 0, 1);
    if (fd >= 0) {
        memset(&lock, 0, sizeof lock);
        lock.l_type = F_WRLCK; lock.l_whence = SEEK_SET; lock.l_len = 0;
        expect("last close clears OFD lock", fcntl(fd, F_GETLK, &lock), 0);
        expect("retired OFD is unlocked", lock.l_type, F_UNLCK);
        expect("close reopened file", close(fd), 0);
    }
    expect("invalid lock fd", fcntl(-1, F_GETLK, NULL), -1);
    expect("invalid lock fd errno", errno, EBADF);
    if (!failures) printf("posix-procs: public nonblocking locks, canonical fields, PID close and OFD fork ok\n");
}
static sigjmp_buf lock_jump;
static volatile sig_atomic_t lock_signal_mode;
static volatile sig_atomic_t lock_signal_seen;
static volatile sig_atomic_t lock_signal_error;
static volatile sig_atomic_t lock_worker_fd;
static int lock_async_ready;
static volatile unsigned char *lock_stack_bottom;
static uintptr_t lock_stack_top;
static uintptr_t lock_stack_painted;
static int lock_stack_begin(void) {
    pthread_attr_t actual;
    void *base = NULL;
    size_t size = 0;
    if (pthread_getattr_np(pthread_self(), &actual) ||
        pthread_attr_getstack(&actual, &base, &size) ||
        pthread_attr_destroy(&actual) || size != PTHREAD_STACK_MIN) return -1;
    uintptr_t here;
    __asm__ volatile("mov %0, sp" : "=r"(here));
    lock_stack_bottom = base;
    lock_stack_top = (uintptr_t)base + size;
    lock_stack_painted = here - 512;
    if (lock_stack_painted < (uintptr_t)base || here > lock_stack_top) return -1;
    for (uintptr_t p = (uintptr_t)base; p < lock_stack_painted; p++)
        *(volatile unsigned char *)p = 0xa7;
    return 0;
}
static size_t lock_stack_peak(void) {
    uintptr_t first = (uintptr_t)lock_stack_bottom;
    while (first < lock_stack_painted && *(volatile unsigned char *)first == 0xa7) first++;
    return lock_stack_top - first;
}
static void lock_signal(int number) {
    int saved_errno = errno;
    lock_signal_seen = number;
    if (lock_signal_mode == 2 || lock_signal_mode == 7 || lock_signal_mode == 8)
        siglongjmp(lock_jump, 1);
    struct flock query;
    memset(&query, 0, sizeof query);
    query.l_type = F_WRLCK; query.l_whence = SEEK_SET;
    if (fcntl(lock_worker_fd, F_GETLK, &query) != 0) lock_signal_error = 1;
    if (close(lock_worker_fd) != 0) lock_signal_error = 2;
    errno = saved_errno;
}
void lock_probe_signal(void) { raise(SIGUSR1); }
void lock_probe_signal_async(void) {
    __atomic_store_n(&lock_async_ready, 1, __ATOMIC_RELEASE);
    while (lock_signal_seen != SIGUSR1) __asm__ volatile("yield");
}
static void *lock_async_sender(void *argument) {
    while (!__atomic_load_n(&lock_async_ready, __ATOMIC_ACQUIRE))
        __asm__ volatile("yield");
    return (void *)(uintptr_t)pthread_kill(*(pthread_t *)argument, SIGUSR1);
}
void lock_probe_exit(void) { pthread_exit(NULL); }
static void *lock_small_turn(void *argument) {
    unsigned mode = (unsigned)(uintptr_t)argument;
    if (lock_stack_begin()) return (void *)10;
    int fd = open("/tmp/public-lock-signal", O_CREAT | O_RDWR, 0666);
    lock_worker_fd = fd;
    if (fd < 0) return (void *)1;
    struct flock lock;
    memset(&lock, 0, sizeof lock);
    lock.l_type = F_RDLCK; lock.l_whence = SEEK_SET;
    lock_signal_mode = mode;
    lock_signal_seen = 0;
    lock_signal_error = 0;
    if (sigsetjmp(lock_jump, 1) == 0) {
        lock_driver_signal_arm(mode);
        int result = fcntl(fd, 37, &lock);
        if (mode == 2 || mode == 3 || mode == 7 || mode == 8 || mode == 9) return (void *)2;
        if (mode == 6 && result != 0) return (void *)12;
        if (result != 0 && errno != EBADF) return (void *)3;
        if (lock_signal_seen != SIGUSR1 || lock_signal_error) return (void *)4;
    }
    if (lock_driver_signal_disarm() != 1) return (void *)5;
    if (mode == 2 || mode == 7 || mode == 8) {
        /* Admission must help the abandoned frame before close can fence it. */
        struct flock admission;
        memset(&admission, 0, sizeof admission);
        admission.l_type = F_WRLCK; admission.l_whence = SEEK_SET;
        if (fcntl(fd, F_GETLK, &admission)) return (void *)13;
        if (close(fd) != 0) return (void *)6;
    }
    int reused = open("/tmp/public-lock-signal", O_RDWR);
    if (reused != fd) return (void *)7;
    memset(&lock, 0, sizeof lock);
    lock.l_type = F_WRLCK; lock.l_whence = SEEK_SET;
    if (fcntl(reused, F_GETLK, &lock) || lock.l_type != F_UNLCK) return (void *)8;
    if (close(reused)) return (void *)9;
    size_t peak = lock_stack_peak();
    printf("POSIX lock stack: mode=%u bytes=%zu limit=16384 allocated=%d\n", mode, peak, PTHREAD_STACK_MIN);
    if (peak > 16 * 1024) return (void *)11;
    return NULL;
}
static void *lock_small_worker(void *argument) {
    unsigned mode = (unsigned)(uintptr_t)argument;
    if (mode != 10) return lock_small_turn(argument);
    /* A live owner must recover its own Cleaned frames before departure can help. */
    for (unsigned turn = 0; turn < 20; turn++) {
        void *result = lock_small_turn((void *)(uintptr_t)2);
        if (result != NULL) return result;
    }
    return NULL;
}
static void public_lock_signals(void) {
    struct sigaction action, previous;
    memset(&action, 0, sizeof action);
    action.sa_handler = lock_signal;
    sigemptyset(&action.sa_mask);
    expect("install public lock signal", sigaction(SIGUSR1, &action, &previous), 0);
    pthread_attr_t attributes;
    expect("lock pthread attributes", pthread_attr_init(&attributes), 0);
    expect("lock pthread published minimum", pthread_attr_setstacksize(&attributes, PTHREAD_STACK_MIN), 0);
    for (unsigned turn = 0; turn < 107; turn++) {
        /* Twenty departures and twenty jumps exceed the sixteen Control places.
         * Later phases test signal interruption after the first request. */
        unsigned mode = turn < 4 ? turn + 1 :
                        turn < 24 ? 2 : turn < 44 ? 3 :
                        turn < 45 ? 5 : turn < 46 ? 6 :
                        turn < 66 ? 7 : turn < 86 ? 8 : turn < 106 ? 9 : 10;
        pthread_t thread;
        pthread_t sender;
        void *result = (void *)99;
        __atomic_store_n(&lock_async_ready, 0, __ATOMIC_RELAXED);
        int started = pthread_create(&thread, &attributes, lock_small_worker,
                                     (void *)(uintptr_t)mode);
        expect("start minimum-stack lock worker", started, 0);
        if (started) continue;
        if (mode == 4) {
            int sent = pthread_create(&sender, NULL, lock_async_sender, &thread);
            expect("start asynchronous lock signal sender", sent, 0);
            if (sent) return;
        }
        expect("join minimum-stack lock worker", pthread_join(thread, &result), 0);
        expect("lock worker outcome and 16 KiB depth", (int)(uintptr_t)result, 0);
        if (mode == 4) {
            expect("join asynchronous lock signal sender", pthread_join(sender, &result), 0);
            expect("asynchronous pthread_kill", (int)(uintptr_t)result, 0);
        }
        if (mode == 3 || mode == 9) {
            expect("thread departure reached accepted Start", lock_driver_signal_disarm(), 1);
            expect("departed lock fd is process shared", fcntl(lock_worker_fd, F_GETFD), 0);
            struct flock admission;
            memset(&admission, 0, sizeof admission);
            admission.l_type = F_WRLCK; admission.l_whence = SEEK_SET;
            if (mode == 3)
                expect("admit after departed owner before close", fcntl(lock_worker_fd, F_GETLK, &admission), 0);
            expect("close departed thread lock", close(lock_worker_fd), 0);
        }
    }
    expect("destroy lock pthread attributes", pthread_attr_destroy(&attributes), 0);
    expect("restore public lock signal", sigaction(SIGUSR1, &previous, NULL), 0);
    if (!failures) printf("posix-procs: lock depth within 16 KiB, nested SIGUSR1 close, siglongjmp and thread departure ok\n");
}
#include <stddef.h>
#include "lock-ring.c"
#include "wait-locks.c"
#include "wait-fifo.c"
#include "wait-lifecycle.c"
#include "lock-deadlock.c"
#include "lock-simple-wait.c"
#include "lock-holder.c"
#include "lock-page-fragments.c"
#if LOCK_FIFO_FULL_ONLY
#include "lock-fifo-full.c"
#endif

int main(int argc, char **argv) {
#if LOCK_FIFO_FULL_ONLY
    if (argc > 1 && strcmp(argv[1], "lock-fifo-full-run") == 0)
        return public_lock_fifo_full();
    if (argc <= 1) {
        char *args[] = {"procs-child", "lock-fifo-full-run", NULL}, *env[] = {NULL};
        pid_t child = -1;
        expect("spawn mapped full FIFO supervisor",
               posix_spawn(&child, "/bin/procs-child", NULL, NULL, args, env), 0);
        if (child > 0) reap(child, 0);
        return failures != 0;
    }
#endif
    if (argc > 1 && strcmp(argv[1], "page-fragments-run") == 0)
        return public_lock_page_fragments();
    if (PAGE_FRAGMENTS_ONLY && argc <= 1) {
        char *args[] = {"procs-child", "page-fragments-run", NULL}, *env[] = {NULL};
        pid_t child = -1;
        expect("spawn mapped page fragments supervisor",
               posix_spawn(&child, "/bin/procs-child", NULL, NULL, args, env), 0);
        if (child > 0) reap(child, 0);
        return failures != 0;
    }
    if (argc > 1 && strcmp(argv[1], "lock-holder-run") == 0) {
        public_lock_holders();
        return failures != 0;
    }
    char *core_args[] = {"posix-procs", "lock-core", NULL};
    if (LOCK_CORE_ONLY && argc <= 1) { argc = 2; argv = core_args; }
    if (argc > 1 && strcmp(argv[1], "lock-core") == 0) {
        public_lock_core();
        return failures != 0;
    }
    char *rules_args[] = {"posix-procs", "lifetime-rules", NULL};
    if (LIFETIME_RULES_ONLY && argc <= 1) {
        argc = 2;
        argv = rules_args;
    }
    if (argc > 1 && strcmp(argv[1], "lock-exec-observe") == 0)
        return lifecycle_exec_image(argc, argv);
    if (argc > 1 && strcmp(argv[1], "lifetime-rules-run") == 0) {
        expect_life("lifecycle supervisor PID", getpid(), 1);
        public_lock_lifecycles();
        return failures != 0;
    }
    if (argc > 1 && strcmp(argv[1], "lifetime-rules") == 0) {
        /* The mapped supervisor supplies the region map required by fork. */
        char *args[] = {"procs-child", "lifetime-rules-run", NULL}, *env[] = {NULL};
        pid_t child = -1;
        expect("spawn lifecycle supervisor", posix_spawn(&child, "/bin/procs-child", NULL,
                                                         NULL, args, env), 0);
        if (child > 0) reap(child, 0);
        if (!failures) puts("posix-procs: lock lifecycle rules ok");
        return failures != 0;
    }
    int ring_result;
    if (ring_dispatch(argc, argv, &ring_result)) return ring_result;
    if(argc>1 && strcmp(argv[1],"wait-lifecycle-exec")==0)return public_wait_lifecycle_exec(argc,argv);
    expect_life("running full PID", getpid(), 1);
    if (argc > 1 && strcmp(argv[1], "sleep") == 0) {
        for (;;) pause();
    }
    if (argc > 1 && strcmp(argv[1], "exec") == 0) {
        /* Allow the old image's end notification to arrive before checking. */
        struct timespec delay = {0, 10000000};
        nanosleep(&delay, NULL);
        expect_life("same PID after old image ended", getpid(), 1);
        return failures != 0;
    }
    if (argc == 1) {
        /* Init's raw image has no loader segment map for fork. */
        char *run_argv[] = {"procs-child", "run", NULL};
        char *env[] = {NULL};
        pid_t run = -1;
        expect("spawn mapped supervisor", posix_spawn(&run, "/bin/procs-child", NULL,
                                                     NULL, run_argv, env), 0);
        if (run > 0) reap(run, 0);
        if (!failures) printf("posix-procs: PID lifetime page ok\n");
        return failures != 0;
    }
    expect("drop effective UID", seteuid(65534), 0);
    expect_life("PID lives with changed credentials", getpid(), 1);
    expect("restore effective UID", seteuid(0), 0);
    expect_life("PID lives with restored credentials", getpid(), 1);
    public_lock_lifecycles();
    public_lock_capacity();
    public_lock_commands();
    int receipt_fd = open("/tmp/public-lock-receipts", O_CREAT | O_RDWR, 0666);
    expect("open public lock receipt file", receipt_fd >= 0, 1);
    if (receipt_fd >= 0) {
        expect("public lock lost replies and numeric reuse", lock_driver_receipts(receipt_fd), 0);
        expect("close public lock receipt file", close(receipt_fd), 0);
    }
    public_lock_signals();
    public_wait_locks();
    public_wait_fifo();
    public_wait_lifecycle();
    public_wait_process_exit();
    public_wait_arbitrary_jumps();
    public_wait_pending_rotation();
    public_lock_deadlocks();
    public_simple_wait_graphs();
    public_lock_holders();
    expect("native lock commands and exact custody", ram_lock_commands(getpid()), 0);
    expect("native close receipt and 32-reference birth", ram_close_event(), 0);
    expect("public close receipts and helper reuse", close_driver_receipts(), 0);
    expect("public close with all independent places full", close_driver_full_places(), 0);
    struct sigaction close_action, close_previous;
    memset(&close_action, 0, sizeof close_action);
    close_action.sa_handler = close_signal;
    sigemptyset(&close_action.sa_mask);
    expect("install close signal", sigaction(SIGUSR1, &close_action, &close_previous), 0);
    int close_fd = open("/etc/motd", O_RDONLY);
    expect("open before close signal", close_fd >= 0, 1);
    close_signal_seen = 0;
    if (close_fd >= 0 && sigsetjmp(close_jump, 1) == 0) {
        close_driver_jump_arm(close_fd);
        close(close_fd);
        expect("close signal must leave through siglongjmp", 0, 1);
    }
    expect("genuine close signal", close_signal_seen, SIGUSR1);
    expect("recover physical close after siglongjmp", close_driver_jump_recover(close_fd), 0);
    expect("restore close signal", sigaction(SIGUSR1, &close_previous, NULL), 0);

    char *sleep_argv[] = {"procs-child", "sleep", NULL};
    char *environment[] = {NULL};
    pid_t child = -1;
    expect("spawn", posix_spawn(&child, "/bin/procs-child", NULL, NULL,
                               sleep_argv, environment), 0);
    if (child > 0) {
        expect_life("published at spawn commit", child, 1);
        expect("kill", kill(child, SIGKILL), 0);
        reap(child, 1);
    }
    child = fork();
    if (child < 0) printf("PID lifetime: fork failed errno %d\n", errno);
    if (child == 0) {
        expect_life("published at fork commit", getpid(), 1);
        _exit(failures != 0);
    }
    expect("fork", child > 0, 1);
    if (child > 0) reap(child, 0);
    child = fork();
    if (child < 0) printf("PID lifetime: fork failed errno %d\n", errno);
    if (child == 0) {
        char *exec_argv[] = {"procs-child", "exec", NULL};
        execve("/bin/procs-child", exec_argv, environment);
        _exit(2);
    }
    expect("fork for exec", child > 0, 1);
    if (child > 0) reap(child, 0);
    return failures != 0;
}
