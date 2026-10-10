/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
/* Separate profile: four init Create roots, four genuine waiting PIDs each. */
extern void ring_probe_arm(void);
extern void ring_probe_disarm(void);
extern int ring_identity(unsigned target, unsigned output[11]);
struct ring_record { unsigned pid, root, generation; char phase; };
static unsigned ring_index;
static int ring_a = -1, ring_b = -1, ring_done;
static int ring_rc, ring_errno;
static void ring_path(char *path, size_t size, const char *kind, unsigned index) {
    snprintf(path, size, "/tmp/lock-ring-%s-%u", kind, index);
}
static int ring_set(int fd, int command, short type) {
    struct flock lock = {.l_type = type, .l_whence = SEEK_SET, .l_len = 1};
    return fcntl(fd, command, &lock);
}
static int ring_phase(unsigned index, char phase) {
    char path[64]; ring_path(path, sizeof(path), "state", index);
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    int ok = pwrite(fd, &phase, 1, offsetof(struct ring_record, phase)) == 1;
    close(fd); return ok ? 0 : -1;
}
void ring_wait_sleeping(void) {
    if (ring_phase(ring_index, 'S')) _exit(121);
}
static int ring_read(unsigned index, struct ring_record *record) {
    char path[64]; ring_path(path, sizeof(path), "state", index);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    int ok = read(fd, record, sizeof(*record)) == (ssize_t)sizeof(*record);
    close(fd); return ok;
}
static int ring_gate(const char *path) {
    struct timespec tick = {0, 10000000};
    for (unsigned n = 0; n < 300; ++n) {
        int fd = open(path, O_RDONLY);
        if (fd >= 0) { close(fd); return 1; }
        nanosleep(&tick, NULL);
    }
    return 0;
}
static int ring_publish(const char *path) {
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0666);
    if (fd < 0) return -1;
    int ok = fchmod(fd, 0666) == 0; close(fd); return ok ? 0 : -1;
}
static int ring_setup(unsigned index) {
    ring_index = index;
    unsigned actual[11];
    int observed = ring_identity((unsigned)getpid(), actual);
    if (observed || actual[0] != (unsigned)getpid() || !actual[1]) {
        printf("posix-procs: ring setup identity index=%u rc=%d errno=%d\n", index, observed, errno);
        return -1;
    }
    char path[64]; ring_path(path, sizeof(path), "file", index);
    ring_a = open(path, O_RDWR);
    ring_path(path, sizeof(path), "file", (index + 1) % 16);
    ring_b = open(path, O_RDWR);
    if (ring_a < 0 || ring_b < 0 || ring_set(ring_a, F_SETLK, F_WRLCK)) {
        printf("posix-procs: ring setup lock index=%u a=%d b=%d errno=%d\n", index, ring_a, ring_b, errno);
        return -1;
    }
    struct ring_record record = {.pid = actual[0], .root = actual[2], .generation = actual[3], .phase = 'H'};
    ring_path(path, sizeof(path), "state", index);
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0666);
    if (fd < 0) { printf("posix-procs: ring setup metadata open index=%u errno=%d\n", index, errno); return -1; }
    int ok = fchmod(fd, 0666) == 0 && write(fd, &record, sizeof(record)) == (ssize_t)sizeof(record);
    if (!ok) printf("posix-procs: ring setup metadata write index=%u errno=%d\n", index, errno);
    close(fd); return ok ? 0 : -1;
}
static int ring_wait(void) {
    if (!ring_gate(ring_index == 15 ? "/tmp/lock-ring-last" : "/tmp/lock-ring-start")) return -1;
    ring_probe_arm(); errno = 0;
    ring_rc = ring_set(ring_b, F_SETLKW, F_WRLCK); ring_errno = errno;
    ring_probe_disarm();
    char phase = !ring_rc ? 'O' : ring_errno == EDEADLK ? 'D' : 'X';
    if (ring_set(ring_a, F_SETLK, F_UNLCK)) phase = 'X';
    if (!ring_rc && ring_set(ring_b, F_SETLK, F_UNLCK)) phase = 'X';
    if (ring_phase(ring_index, phase)) phase = 'X';
    close(ring_a); close(ring_b); ring_a = ring_b = -1;
    __atomic_store_n(&ring_done, 1, __ATOMIC_RELEASE);
    return phase == 'X' ? -1 : 0;
}
static void *ring_worker(void *unused) { (void)unused; ring_wait(); return NULL; }
static int ring_barrier(char wanted, unsigned count) {
    struct timespec tick = {0, 10000000};
    for (unsigned n = 0; n < 300; ++n) {
        unsigned got = 0;
        for (unsigned i = 0; i < count; ++i) {
            struct ring_record record;
            if (ring_read(i, &record) && record.phase == wanted) ++got;
        }
        if (got == count) return 1;
        nanosleep(&tick, NULL);
    }
    return 0;
}
static void ring_signal(int sig) { (void)sig; }
static int ring_coordinator(void) {
    int bad = 0;
    if (!ring_barrier('H', 16)) return -1;
    struct ring_record records[16];
    unsigned roots[4], generations[4];
    for (unsigned i = 0; i < 16; ++i) {
        unsigned actual[11];
        if (!ring_read(i, &records[i]) || ring_identity(records[i].pid, actual) || !actual[1]) return -1;
        for (unsigned j = 0; j < i; ++j) if (records[i].pid == records[j].pid) return -1;
        if (i % 4 == 0) {
            roots[i / 4] = records[i].root; generations[i / 4] = records[i].generation;
            for (unsigned j = 0; j < i / 4; ++j)
                if (roots[j] == roots[i / 4] && generations[j] == generations[i / 4]) return -1;
        } else if (records[i].root != roots[i / 4] || records[i].generation != generations[i / 4]) return -1;
    }
    for (unsigned i = 0; i < 4; ++i)
        printf("posix-procs: ring16 payer family=%u root=%u generation=%u\n", i, roots[i], generations[i]);
    if (ring_publish("/tmp/lock-ring-start")) return -1;
    pthread_t worker;
    if (pthread_create(&worker, NULL, ring_worker, NULL)) return -1;
    if (!ring_barrier('S', 15) || ring_publish("/tmp/lock-ring-last")) bad = 1;
    struct timespec tick = {0, 10000000};
    unsigned succeeded = 0, deadlocked = 0, done = 0;
    for (unsigned n = 0; n < 300; ++n) {
        succeeded = deadlocked = done = 0;
        for (unsigned i = 0; i < 16; ++i) {
            struct ring_record record;
            if (!ring_read(i, &record)) continue;
            if (record.phase == 'O') { ++succeeded; ++done; }
            else if (record.phase == 'D') { ++deadlocked; ++done; }
            else if (record.phase == 'X') { bad = 1; ++done; }
        }
        if (done == 16) break;
        nanosleep(&tick, NULL);
    }
    if (done != 16) {
        bad = 1;
        printf("posix-procs: FAIL real ring16 finite resolution, completed %u\n", done);
        if (ring_a >= 0) ring_set(ring_a, F_SETLK, F_UNLCK);
        for (unsigned n = 0; n < 300 && !__atomic_load_n(&ring_done, __ATOMIC_ACQUIRE); ++n) nanosleep(&tick, NULL);
        if (!__atomic_load_n(&ring_done, __ATOMIC_ACQUIRE)) {
            pthread_kill(worker, SIGUSR1);
            for (unsigned i = 1; i < 16; ++i) kill((pid_t)records[i].pid, SIGKILL);
        }
    }
    if (pthread_join(worker, NULL)) bad = 1;
    unsigned actual[11] = {0};
    for (unsigned n = 0; n < 1024; ++n) {
        if (ring_identity((unsigned)getpid(), actual)) { bad = 1; break; }
        if (actual[10]) break;
    }
    if (actual[5] != 16 || actual[6] != 16 || actual[7] != 16 || actual[8] > 20410 || actual[9] > 8 || !actual[8] || !actual[10] || actual[10] > 48 * 1024) bad = 1;
    printf("posix-procs: ring16 result deadlock=%u success=%u vertices=%u registrations=%u watches=%u ticks=%u visited=%u stack=%u free=%u\n",
           deadlocked, succeeded, actual[5], actual[6], actual[7], actual[8], actual[9], actual[10], actual[4]);
    if (deadlocked != 1 || succeeded != 15) bad = 1;
    return bad ? -1 : 0;
}
static int ring_run(unsigned family) {
    if (!family) {
        for (unsigned i = 0; i < 16; ++i) {
            char path[64]; ring_path(path, sizeof(path), "file", i);
            if (ring_publish(path)) { printf("posix-procs: ring create file index=%u errno=%d\n", i, errno); return 1; }
        }
        if (ring_publish("/tmp/lock-ring-files-ready")) { printf("posix-procs: ring create ready errno=%d\n", errno); return 1; }
    } else if (!ring_gate("/tmp/lock-ring-files-ready")) { printf("posix-procs: ring files-ready timeout family=%u errno=%d\n", family, errno); return 1; }
    struct sigaction action = {0}; action.sa_handler = ring_signal; sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, NULL)) return 1;
    pid_t children[3];
    for (unsigned i = 0; i < 3; ++i) {
        children[i] = fork();
        if (children[i] < 0) { printf("posix-procs: ring fork family=%u child=%u errno=%d\n", family, i, errno); return 1; }
        if (!children[i]) {
            if (ring_setup(4 * family + i + 1)) { fflush(stdout); _exit(123); }
            _exit(ring_wait() ? 124 : 0);
        }
    }
    if (ring_setup(4 * family)) return 1;
    int bad = family ? ring_wait() : ring_coordinator();
    for (unsigned i = 0; i < 3; ++i) {
        int status = 0;
        if (waitpid(children[i], &status, 0) != children[i] || !WIFEXITED(status) || WEXITSTATUS(status)) bad = 1;
        if (process_lifetime(children[i]) != 0) bad = 1;
    }
    if (!bad) printf("posix-procs: genuine ring16 family %u ok\n", family);
    return bad ? 1 : 0;
}
static int ring_dispatch(int argc, char **argv, int *result) {
    if (argc != 3 || (strcmp(argv[1], "ring-launch") && strcmp(argv[1], "ring-run"))) return 0;
    unsigned family = (unsigned)(argv[2][0] - '0');
    if (family > 3 || argv[2][1]) { *result = 1; return 1; }
    if (!strcmp(argv[1], "ring-run")) { *result = ring_run(family); return 1; }
    char *run_argv[] = {"procs-child", "ring-run", argv[2], NULL}, *env[] = {NULL};
    pid_t child = -1; int status = 0;
    int spawned = posix_spawn(&child, "/bin/procs-child", NULL, NULL, run_argv, env);
    if (spawned) { printf("posix-procs: ring launch spawn family=%u rc=%d errno=%d\n", family, spawned, errno); *result = 1; }
    else if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) {
        printf("posix-procs: ring launch child family=%u pid=%d status=%d errno=%d\n", family, child, status, errno); *result = 1;
    } else {
        int live = process_lifetime(child);
        if (live) printf("posix-procs: ring launch dead Page family=%u rc=%d\n", family, live);
        *result = live != 0;
    }
    return 1;
}
