/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
/* Included only by lifetime.c: one real child PID blocker for public WAIT. */
extern void wait_driver_arm(unsigned mode);
extern void wait_driver_disarm(void);
static int wait_ready, wait_continue;
static volatile sig_atomic_t wait_seen;
static size_t wait_peak;
static int wait_fd, wait_command, wait_rc, wait_errno;
void wait_probe_stage(unsigned stage) {
    __atomic_store_n(&wait_ready, (int)stage, __ATOMIC_RELEASE);
    if (stage == 2) {
        while (!__atomic_load_n(&wait_continue, __ATOMIC_ACQUIRE)) sched_yield();
    }
}
static int wait_stage(int stage) {
    struct timespec tick = {0, 1000000};
    for (unsigned n = 0; n < 10000; ++n) {
        if (__atomic_load_n(&wait_ready, __ATOMIC_ACQUIRE) >= stage) return 1;
        nanosleep(&tick, NULL);
    }
    return 0;
}
static void wait_signal(int signal) { wait_seen = signal; }
static void *wait_worker(void *ignored) {
    (void)ignored;
    if (lock_stack_begin()) { wait_rc = 778; return NULL; }
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    errno = 0;
    wait_rc = fcntl(wait_fd, wait_command, &lock);
    wait_errno = errno;
    wait_peak = lock_stack_peak();
    return NULL;
}
static int wait_holder_exchange(int command_fd, int reply_fd, char command) {
    char reply = 0;
    return write(command_fd, &command, 1) == 1 && read(reply_fd, &reply, 1) == 1 && reply == command;
}
static void public_wait_locks(void) {
    int fd = open("/tmp/public-wait-locks", O_CREAT | O_RDWR, 0666);
    expect("open WAIT file", fd >= 0, 1);
    if (fd < 0) return;
    int commands[2], replies[2];
    if (pipe(commands) || pipe(replies)) { expect("WAIT holder pipes", 0, 1); close(fd); return; }
    pid_t holder = fork();
    expect("fork WAIT PID holder", holder >= 0, 1);
    if (holder == 0) {
        close(commands[1]); close(replies[0]);
        char command;
        while (read(commands[0], &command, 1) == 1) {
            if (command == 'Q') _exit(0);
            struct flock lock = {.l_type = command == 'L' ? F_WRLCK : F_UNLCK,
                                 .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
            if (fcntl(fd, F_SETLK, &lock) || write(replies[1], &command, 1) != 1) _exit(91);
        }
        _exit(92);
    }
    close(commands[0]); close(replies[1]);
    if (holder < 0) { close(commands[1]); close(replies[0]); close(fd); return; }
    struct sigaction action = {0}, previous;
    action.sa_handler = wait_signal; sigemptyset(&action.sa_mask);
    pthread_attr_t attributes;
    expect("WAIT pthread attrs", pthread_attr_init(&attributes), 0);
    expect("WAIT actual 64 KiB allocation", pthread_attr_setstacksize(&attributes, PTHREAD_STACK_MIN), 0);
    for (unsigned mode = 1; mode <= 5; ++mode) {
        expect("child establishes genuine conflicting PID lock", wait_holder_exchange(commands[1], replies[0], 'L'), 1);
        action.sa_flags = mode == 3 ? SA_RESTART : 0;
        expect("install WAIT SIGUSR1", sigaction(SIGUSR1, &action, mode == 1 ? &previous : NULL), 0);
        wait_fd = open("/tmp/public-wait-locks", O_RDWR);
        expect("open WAIT source", wait_fd >= 0, 1);
        if (wait_fd < 0) break;
        wait_command = mode == 1 ? 38 : 7;
        wait_rc = 777; wait_errno = 0; wait_seen = 0; wait_peak = 0;
        __atomic_store_n(&wait_ready, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&wait_continue, 0, __ATOMIC_RELEASE);
        wait_driver_arm(mode);
        pthread_t worker;
        int created = pthread_create(&worker, &attributes, wait_worker, NULL);
        expect("create WAIT worker", created, 0);
        if (created) { wait_driver_disarm(); close(wait_fd); break; }
        int reached = wait_stage(1);
        expect("WAIT reached real Sleeping receive", reached, 1);
        /* Allow the worker to enter its actual kernel Receive before intervention. */
        struct timespec settle = {0, 20000000}; nanosleep(&settle, NULL);
        int reused = -1;
        if (mode == 2 || mode == 3) expect("true cross-thread WAIT SIGUSR1", pthread_kill(worker, SIGUSR1), 0);
        if (mode == 4) {
            expect("close genuinely waiting source", close(wait_fd), 0);
            reused = open("/tmp/public-wait-reused", O_CREAT | O_RDWR, 0666);
            expect("WAIT source numeric fd reused", reused, wait_fd);
        }
        if (mode == 1 || mode == 3 || mode == 5 || !reached) {
            expect("child unlock wakes WAIT", wait_holder_exchange(commands[1], replies[0], 'U'), 1);
        }
        if (mode == 5) {
            expect("WAIT strict canonical Complete received", wait_stage(2), 1);
            expect("signal after server Complete", pthread_kill(worker, SIGUSR1), 0);
            __atomic_store_n(&wait_continue, 1, __ATOMIC_RELEASE);
        }
        expect("join WAIT worker", pthread_join(worker, NULL), 0);
        wait_driver_disarm();
        expect("WAIT painted path within 16 KiB", wait_peak > 0 && wait_peak <= 16384, 1);
        printf("posix-procs: WAIT mode %u stack %zu bytes\n", mode, wait_peak);
        expect("WAIT canonical public result", wait_rc, mode == 2 || mode == 4 ? -1 : 0);
        if (mode == 2 || mode == 4) expect("WAIT cancellation errno", wait_errno, mode == 2 ? EINTR : EBADF);
        if (mode == 2 || mode == 3 || mode == 5) expect("real WAIT signal delivered", wait_seen, SIGUSR1);
        if (mode == 2 || mode == 4) expect("unlock still-owned child lock", wait_holder_exchange(commands[1], replies[0], 'U'), 1);
        if (mode == 4) {
            struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_len = 1};
            expect("old WAIT cleanup preserves reused source", fcntl(reused, F_SETLK, &lock), 0);
            expect("close reused WAIT source", close(reused), 0);
        } else expect("close WAIT source", close(wait_fd), 0);
    }
    expect("restore WAIT signal handler", sigaction(SIGUSR1, &previous, NULL), 0);
    expect("destroy WAIT attrs", pthread_attr_destroy(&attributes), 0);
    char quit = 'Q'; expect("stop WAIT holder", write(commands[1], &quit, 1), 1);
    close(commands[1]); close(replies[0]); reap(holder, 0); close(fd);
    if (!failures) printf("posix-procs: true WAIT unlock, SIGUSR1, restart, close/reuse and canonical success ok\n");
}
