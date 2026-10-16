// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
/* Only included by lifetime.c, after wait-locks.c. A wait that ends by a handler that
 * leaves the thread, by a jump, by exec in a forked child or by the death of its
 * process leaves nothing in the service: the holder lets go and takes the range again by
 * a nonblocking SET. An older incompatible waiter would refuse it with EAGAIN, and the
 * holder would end with status 96. */
static int lifecycle_fd, lifecycle_result;
static volatile sig_atomic_t lifecycle_seen;
static sigjmp_buf lifecycle_jump;
static int lifecycle_mode;

static int wait_ghost_free(int command_fd, int reply_fd) {
    return wait_holder_exchange(command_fd, reply_fd, 'U') &&
           wait_holder_exchange(command_fd, reply_fd, 'L');
}
static void lifecycle_signal(int signal) {
    lifecycle_seen = signal;
    if (lifecycle_mode == 1) pthread_exit((void *)1);
    siglongjmp(lifecycle_jump, 1);
}
__attribute__((noinline)) static int lifecycle_deeper_wait(void) {
    volatile unsigned char workspace[256];
    for (unsigned i = 0; i < sizeof workspace; i++) workspace[i] = (unsigned char)i;
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_len = 1};
    int result = fcntl(lifecycle_fd, 7, &lock);
    return workspace[17] == 17 ? result : -2;
}
static void *lifecycle_worker(void *ignored) {
    (void)ignored;
    if (lock_stack_begin()) { lifecycle_result = 778; return NULL; }
    if (lifecycle_mode == 2 && sigsetjmp(lifecycle_jump, 1)) {
        lifecycle_result = 779;
        return (void *)(uintptr_t)(lock_stack_peak() <= 16384 ? 2 : 3);
    }
    lifecycle_result = lifecycle_deeper_wait();
    return NULL;
}
static void lifecycle_reap(pid_t child) {
    int status = 0;
    expect("lifecycle waitpid", waitpid(child, &status, 0), child);
    expect("lifecycle normal exit", WIFEXITED(status) && WEXITSTATUS(status) == 0, 1);
}
/* The image that a forked child executes. */
int public_wait_lifecycle_exec(int argc, char **argv) {
    if (argc != 3) return 71;
    int fd = atoi(argv[2]);
    if (fcntl(fd, F_GETFD) < 0) return 73;
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_len = 1};
    if (fcntl(fd, F_GETLK, &lock) || lock.l_type != F_UNLCK) return 74;
    if (fcntl(fd, F_SETLK, &lock) || close(fd)) return 75;
    return 0;
}
static void lifecycle_holder(int commands[2], int replies[2], pid_t *holder, const char *path) {
    if (pipe(commands) || pipe(replies)) { expect("lifecycle pipes", 0, 1); *holder = -1; return; }
    *holder = fork();
    expect("fork lifecycle holder", *holder >= 0, 1);
    if (*holder == 0) {
        close(commands[1]); close(replies[0]);
        char command;
        while (read(commands[0], &command, 1) == 1) {
            if (command == 'Q') _exit(0);
            struct flock lock = {.l_type = command == 'L' ? F_WRLCK : F_UNLCK,
                                 .l_whence = SEEK_SET, .l_len = 1};
            if (fcntl(lifecycle_fd, F_SETLK, &lock) || write(replies[1], &command, 1) != 1) _exit(96);
        }
        _exit(97);
    }
    close(commands[0]); close(replies[1]);
    (void)path;
}
static void lifecycle_stop(int commands[2], int replies[2], pid_t holder) {
    char quit = 'Q';
    expect("stop lifecycle holder", write(commands[1], &quit, 1), 1);
    close(commands[1]); close(replies[0]);
    lifecycle_reap(holder);
}
/* A thread that waits is ended by its own handler (mode 1), or the handler jumps
 * out of the wait (mode 2); twenty turns exceed the sixteen places of the service. */
static void lifecycle_turns(unsigned mode) {
    int commands[2], replies[2];
    pid_t holder;
    lifecycle_fd = open("/tmp/public-wait-lifecycle", O_CREAT | O_RDWR, 0666);
    expect("open lifecycle source", lifecycle_fd >= 0, 1);
    if (lifecycle_fd < 0) return;
    lifecycle_holder(commands, replies, &holder, NULL);
    if (holder < 0) { close(lifecycle_fd); return; }
    expect("lifecycle genuine PID blocker", wait_holder_exchange(commands[1], replies[0], 'L'), 1);
    struct sigaction action = {0}, previous;
    action.sa_handler = lifecycle_signal; sigemptyset(&action.sa_mask);
    expect("lifecycle handler", sigaction(SIGUSR1, &action, &previous), 0);
    pthread_attr_t attr;
    expect("lifecycle attrs", pthread_attr_init(&attr), 0);
    expect("lifecycle 64 KiB", pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN), 0);
    lifecycle_mode = (int)mode;
    for (unsigned turn = 0; turn < 20; turn++) {
        lifecycle_seen = 0; lifecycle_result = 777;
        __atomic_store_n(&wait_ready, 0, __ATOMIC_RELEASE);
        wait_driver_arm(1);
        pthread_t worker;
        int created = pthread_create(&worker, &attr, lifecycle_worker, NULL);
        expect("create lifecycle worker", created, 0);
        if (created) { wait_driver_disarm(); break; }
        expect("lifecycle worker sleeps in the wait", wait_stage(1), 1);
        struct timespec settle = {0, 20000000}; nanosleep(&settle, NULL);
        expect("signal to the waiting thread", pthread_kill(worker, SIGUSR1), 0);
        void *result = NULL;
        expect("join lifecycle worker", pthread_join(worker, &result), 0);
        expect("handler ran", lifecycle_seen, SIGUSR1);
        expect("worker ended as the mode says", (int)(uintptr_t)result, mode == 1 ? 1 : 2);
        expect("the wait did not return", lifecycle_result, mode == 1 ? 777 : 779);
        wait_driver_disarm();
        expect("no waiter is left in the service", wait_ghost_free(commands[1], replies[0]), 1);
        if (failures) break;
    }
    expect("restore lifecycle handler", sigaction(SIGUSR1, &previous, NULL), 0);
    expect("destroy lifecycle attrs", pthread_attr_destroy(&attr), 0);
    lifecycle_stop(commands, replies, holder);
    expect("close lifecycle source", close(lifecycle_fd), 0);
}
static void *lifecycle_plain_worker(void *ignored) {
    (void)ignored;
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_len = 1};
    lifecycle_result = fcntl(lifecycle_fd, 7, &lock);
    return NULL;
}
static void public_wait_lifecycle(void) {
    lifecycle_turns(1);
    /* A thread waits; a forked child closes the number, reuses it and executes. */
    int commands[2], replies[2];
    pid_t holder;
    lifecycle_fd = open("/tmp/public-wait-lifecycle", O_CREAT | O_RDWR, 0666);
    expect("open lifecycle source", lifecycle_fd >= 0, 1);
    if (lifecycle_fd < 0) return;
    lifecycle_holder(commands, replies, &holder, NULL);
    if (holder < 0) { close(lifecycle_fd); return; }
    expect("lifecycle genuine PID blocker", wait_holder_exchange(commands[1], replies[0], 'L'), 1);
    lifecycle_result = 777;
    __atomic_store_n(&wait_ready, 0, __ATOMIC_RELEASE);
    wait_driver_arm(1);
    pthread_t worker;
    int created = pthread_create(&worker, NULL, lifecycle_plain_worker, NULL);
    expect("create fork wait owner", created, 0);
    if (!created) {
        expect("fork parent waits", wait_stage(1), 1);
        pid_t child = fork();
        expect("fork while another thread waits", child >= 0, 1);
        if (child == 0) {
            if (close(lifecycle_fd)) _exit(76);
            int reused = open("/tmp/public-wait-lifecycle-reused", O_CREAT | O_RDWR, 0666);
            if (reused != lifecycle_fd) _exit(77);
            char number[24];
            snprintf(number, sizeof number, "%d", reused);
            char *arguments[] = {"procs-child", "wait-lifecycle-exec", number, NULL};
            char *environment[] = {NULL};
            execve("/bin/procs-child", arguments, environment);
            _exit(78);
        }
        if (child > 0) lifecycle_reap(child);
        expect("the parent still waits", lifecycle_result, 777);
        expect("unlock wakes the surviving parent wait", wait_holder_exchange(commands[1], replies[0], 'U'), 1);
        expect("join surviving fork parent", pthread_join(worker, NULL), 0);
        expect("parent wait succeeded", lifecycle_result, 0);
    }
    wait_driver_disarm();
    lifecycle_stop(commands, replies, holder);
    expect("close lifecycle source", close(lifecycle_fd), 0);
    if (!failures) printf("posix-procs: WAIT thread end, fork with exec in the child and slot reuse ok\n");
}
/* A process dies with a thread in the wait. */
void public_wait_process_exit(void) {
    int commands[2], replies[2];
    pid_t holder;
    lifecycle_fd = open("/tmp/public-wait-process-exit", O_CREAT | O_RDWR, 0666);
    expect("open process-exit source", lifecycle_fd >= 0, 1);
    if (lifecycle_fd < 0) return;
    lifecycle_holder(commands, replies, &holder, NULL);
    if (holder < 0) { close(lifecycle_fd); return; }
    expect("process-exit blocker", wait_holder_exchange(commands[1], replies[0], 'L'), 1);
    for (unsigned turn = 0; turn < 2; turn++) {
        int control[2], ready[2];
        if (pipe(control) || pipe(ready)) { expect("process-exit pipes", 0, 1); break; }
        pid_t peer = fork();
        expect("fork waiting process", peer >= 0, 1);
        if (peer == 0) {
            close(control[1]); close(ready[0]);
            __atomic_store_n(&wait_ready, 0, __ATOMIC_RELEASE);
            wait_driver_arm(1);
            pthread_t worker;
            if (pthread_create(&worker, NULL, lifecycle_plain_worker, NULL)) _exit(84);
            if (!wait_stage(1)) _exit(85);
            struct timespec settle = {0, 20000000}; nanosleep(&settle, NULL);
            char ok = 'W';
            if (write(ready[1], &ok, 1) != 1) _exit(86);
            char permission = 0;
            if (read(control[0], &permission, 1) != 1 || permission != 'E') _exit(87);
            _exit(0);
        }
        close(control[0]); close(ready[1]);
        if (peer < 0) { close(control[1]); close(ready[0]); break; }
        char accepted = 0;
        expect("the child waits in the service", read(ready[0], &accepted, 1), 1);
        expect("ready marker", accepted, 'W');
        expect("let the child exit", write(control[1], "E", 1), 1);
        close(control[1]); close(ready[0]);
        lifecycle_reap(peer);
        expect("no waiter is left by the dead process", wait_ghost_free(commands[1], replies[0]), 1);
        if (failures) break;
    }
    lifecycle_stop(commands, replies, holder);
    expect("close process-exit source", close(lifecycle_fd), 0);
    if (!failures) printf("posix-procs: pending WAIT of a dead process leaves nothing in the service ok\n");
}
void public_wait_arbitrary_jumps(void) {
    lifecycle_turns(2);
    if (!failures) printf("posix-procs: WAIT left by a jump from the handler, twenty turns ok\n");
}
