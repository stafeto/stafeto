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
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

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
static void *lock_small_worker(void *argument) {
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
static void public_lock_signals(void) {
    struct sigaction action, previous;
    memset(&action, 0, sizeof action);
    action.sa_handler = lock_signal;
    sigemptyset(&action.sa_mask);
    expect("install public lock signal", sigaction(SIGUSR1, &action, &previous), 0);
    pthread_attr_t attributes;
    expect("lock pthread attributes", pthread_attr_init(&attributes), 0);
    expect("lock pthread published minimum", pthread_attr_setstacksize(&attributes, PTHREAD_STACK_MIN), 0);
    for (unsigned turn = 0; turn < 106; turn++) {
        /* Twenty departures and twenty jumps exceed the sixteen Control places.
         * Later phases test signal interruption after the first request. */
        unsigned mode = turn < 4 ? turn + 1 :
                        turn < 24 ? 2 : turn < 44 ? 3 :
                        turn < 45 ? 5 : turn < 46 ? 6 :
                        turn < 66 ? 7 : turn < 86 ? 8 : 9;
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
int main(int argc, char **argv) {
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
    public_lock_commands();
    int receipt_fd = open("/tmp/public-lock-receipts", O_CREAT | O_RDWR, 0666);
    expect("open public lock receipt file", receipt_fd >= 0, 1);
    if (receipt_fd >= 0) {
        expect("public lock lost replies and numeric reuse", lock_driver_receipts(receipt_fd), 0);
        expect("close public lock receipt file", close(receipt_fd), 0);
    }
    public_lock_signals();
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
