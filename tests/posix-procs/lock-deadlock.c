/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
/* Included only by lifetime.c. All lock results are genuine public fcntl calls. */
extern void deadlock_probe_arm(void);
extern void deadlock_probe_disarm(void);
static int deadlock_notice_fd = -1;
static int deadlock_ready, deadlock_done;
static int deadlock_a, deadlock_b, deadlock_ofd, deadlock_rc, deadlock_errno;
void deadlock_wait_sleeping(void) {
    if (deadlock_notice_fd >= 0) {
        char sleeping = 'S';
        if (write(deadlock_notice_fd, &sleeping, 1) != 1) _exit(111);
    } else __atomic_store_n(&deadlock_ready, 1, __ATOMIC_RELEASE);
}
static int deadlock_lock(int fd, int command, short type) {
    struct flock lock = {.l_type = type, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    return fcntl(fd, command, &lock);
}
static int deadlock_flag(int *flag) {
    struct timespec tick = {0, 10000000};
    for (unsigned turn = 0; turn < 300; ++turn) {
        if (__atomic_load_n(flag, __ATOMIC_ACQUIRE)) return 1;
        nanosleep(&tick, NULL);
    }
    return __atomic_load_n(flag, __ATOMIC_ACQUIRE) != 0;
}
/* The reader was made nonblocking before fork: no fixture read can hold the coordinator. */
static int deadlock_byte(int fd, char *byte) {
    struct timespec tick = {0, 10000000};
    for (unsigned turn = 0; turn < 300; ++turn) {
        ssize_t got = read(fd, byte, 1);
        if (got == 1) return 1;
        if (!got || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) return 0;
        nanosleep(&tick, NULL);
    }
    return 0;
}
static void deadlock_signal(int signal) { (void)signal; }
static void *deadlock_worker(void *ignored) {
    (void)ignored;
    errno = 0;
    deadlock_rc = deadlock_lock(deadlock_b, F_SETLKW, F_WRLCK);
    deadlock_errno = errno;
    if (!deadlock_ofd) expect("PID cycle parent releases A", deadlock_lock(deadlock_a, F_SETLK, F_UNLCK), 0);
    if (!deadlock_rc) expect("cycle parent releases acquired B", deadlock_lock(deadlock_b, F_SETLK, F_UNLCK), 0);
    __atomic_store_n(&deadlock_done, 1, __ATOMIC_RELEASE);
    return NULL;
}
static void deadlock_child(int inherited_a, int inherited_b, int inherited_anchor, int read_end, int report, int ofd) {
    close(read_end); close(inherited_a); close(inherited_b);
    if (inherited_anchor >= 0) close(inherited_anchor);
    int a = open("/tmp/deadlock-a", O_RDWR), b = open("/tmp/deadlock-b", O_RDWR);
    int anchor = ofd ? open("/tmp/deadlock-d", O_CREAT | O_RDWR, 0666) : -1;
    /* Establish real local PID life without a conflict on either cycle inode. */
    if (ofd && (anchor < 0 || deadlock_lock(anchor, F_SETLK, F_WRLCK))) _exit(118);
    int command = ofd ? 37 : F_SETLK;
    if (a < 0 || b < 0 || deadlock_lock(b, command, F_WRLCK)) _exit(112);
    char held = 'B';
    if (write(report, &held, 1) != 1) _exit(113);
    deadlock_notice_fd = report;
    deadlock_probe_arm();
    errno = 0;
    int result = deadlock_lock(a, F_SETLKW, F_WRLCK), error = errno;
    deadlock_probe_disarm();
    if (deadlock_lock(b, command, F_UNLCK)) _exit(114);
    if (!result && deadlock_lock(a, F_SETLK, F_UNLCK)) _exit(115);
    char outcome = !result ? 'O' : error == EDEADLK ? 'D' : 'X';
    if (write(report, &outcome, 1) != 1) _exit(116);
    close(a); close(b); if (anchor >= 0) close(anchor); close(report);
    _exit(outcome == 'X' ? 117 : 0);
}
static void deadlock_case(int ofd) {
    int a = open("/tmp/deadlock-a", O_CREAT | O_RDWR, 0666);
    int b = open("/tmp/deadlock-b", O_CREAT | O_RDWR, 0666);
    expect("open genuine deadlock files", a >= 0 && b >= 0, 1);
    if (a < 0 || b < 0) { if (a >= 0) close(a); if (b >= 0) close(b); return; }
    int command = ofd ? 37 : F_SETLK;
    expect("parent publishes actual A blocker", deadlock_lock(a, command, F_WRLCK), 0);
    int anchor = ofd ? open("/tmp/deadlock-c", O_CREAT | O_RDWR, 0666) : -1;
    if (ofd) {
        expect("parent unrelated real PID anchor", anchor >= 0 && deadlock_lock(anchor, F_SETLK, F_WRLCK) == 0, 1);
        if (anchor < 0) { close(a); close(b); return; }
    }
    int reports[2];
    if (pipe(reports)) { expect("deadlock report pipe", 0, 1); close(a); close(b); if (anchor >= 0) close(anchor); return; }
    expect("finite deadlock report reads", fcntl(reports[0], F_SETFL, O_NONBLOCK), 0);
    pid_t child = fork();
    if (!child) deadlock_child(a, b, anchor, reports[0], reports[1], ofd);
    expect("actual deadlock child PID", child > 0, 1);
    close(reports[1]);
    if (child < 0) { close(reports[0]); close(a); close(b); if (anchor >= 0) close(anchor); return; }
    expect("distinct real PID", child != getpid(), 1);
    expect("deadlock child true Page live", process_lifetime(child), 1);
    char byte = 0;
    int held = deadlock_byte(reports[0], &byte) && byte == 'B';
    expect("child publishes actual B blocker", held, 1);
    int sleeping = held && deadlock_byte(reports[0], &byte) && byte == 'S';
    expect("child WAIT genuinely Sleeping", sleeping, 1);
    deadlock_a = a; deadlock_b = b; deadlock_ofd = ofd;
    deadlock_rc = 777; deadlock_errno = 0; deadlock_notice_fd = -1;
    __atomic_store_n(&deadlock_ready, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&deadlock_done, 0, __ATOMIC_RELEASE);
    deadlock_probe_arm();
    pthread_t worker;
    int created = sleeping ? pthread_create(&worker, NULL, deadlock_worker, NULL) : EIO;
    expect("create parent PID WAIT worker", created, 0);
    if (!created) {
        if (ofd) {
            int reached = deadlock_flag(&deadlock_ready);
            expect("OFD-only blockers leave both PID WAITs Sleeping", reached, 1);
            /* Give the bounded proof real turns with the OFD holds unchanged. */
            struct timespec proof_window = {0, 600000000};
            nanosleep(&proof_window, NULL);
            expect("OFD-only cycle cannot finish before real unlock",
                   __atomic_load_n(&deadlock_done, __ATOMIC_ACQUIRE), 0);
            expect("main explicitly removes OFD A blocker", deadlock_lock(a, 37, F_UNLCK), 0);
        }
        int finished = deadlock_flag(&deadlock_done);
        expect("finite real deadlock resolution", finished, 1);
        if (!finished) {
            /* Break a proof-disabled cycle, preserving the failed assertion above. */
            expect("timeout removes actual A blocker", deadlock_lock(a, command, F_UNLCK), 0);
            finished = deadlock_flag(&deadlock_done);
            if (!finished) {
                expect("cancel stalled worker with real signal", pthread_kill(worker, SIGUSR1), 0);
                kill(child, SIGKILL);
            }
        }
        expect("join deadlock worker", pthread_join(worker, NULL), 0);
    } else {
        deadlock_lock(a, command, F_UNLCK);
        kill(child, SIGKILL);
    }
    deadlock_probe_disarm();
    int reported = deadlock_byte(reports[0], &byte);
    expect("child reports genuine canonical result", reported, 1);
    if (!created && reported) {
        if (ofd) {
            expect("OFD blocker cannot synthesize PID EDEADLK", deadlock_rc, 0);
            expect("child OFD-blocked PID WAIT succeeds", byte, 'O');
        } else {
            int parent_deadlock = deadlock_rc == -1 && deadlock_errno == EDEADLK;
            int parent_success = deadlock_rc == 0;
            expect("exactly one actual PID cycle EDEADLK", (parent_deadlock && byte == 'O') || (parent_success && byte == 'D'), 1);
        }
    }
    close(reports[0]);
    int status = 0;
    expect("wait real deadlock child", waitpid(child, &status, 0), child);
    expect("deadlock child completed normally", WIFEXITED(status) && WEXITSTATUS(status) == 0, 1);
    expect("deadlock child true Page dead", process_lifetime(child), 0);
    expect("close deadlock A", close(a), 0); expect("close deadlock B", close(b), 0);
    if (anchor >= 0) expect("close unrelated PID anchor", close(anchor), 0);
    unlink("/tmp/deadlock-a"); unlink("/tmp/deadlock-b");
    unlink("/tmp/deadlock-c"); unlink("/tmp/deadlock-d");
}
static void public_lock_deadlocks(void) {
    int before = failures;
    struct sigaction action = {0}, previous;
    action.sa_handler = deadlock_signal; sigemptyset(&action.sa_mask);
    expect("install finite deadlock cancellation signal", sigaction(SIGUSR1, &action, &previous), 0);
    deadlock_case(0);
    deadlock_case(1);
    expect("restore deadlock cancellation signal", sigaction(SIGUSR1, &previous, NULL), 0);
    if (failures == before) printf("posix-procs: genuine PID cycle EDEADLK and OFD noncycle ok\n");
}
