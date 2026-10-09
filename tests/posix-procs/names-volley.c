/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
/* The operations on names in the steps mode (xtask process-steps), before the
 * crowd: a path of 32 links, the rename of a directory under a chain 64 deep,
 * getcwd at depth 64, the rmdir with a full table of names, a volley of 112
 * long renames from sixteen processes of seven threads, and a long rmdir
 * against a client that changes the times of its own file in a loop. The
 * service prints its longest steps itself; this file prints the cost of each
 * operation alone (requests of the layer to the service, and ticks of the
 * counter), the volley's most repeats of JOBS_FULL of one thread, most
 * restarts of one rename and longest rename, and the restarts of the long
 * rmdir. Included by procs.c. */

extern void files_volley_start(void);
extern void files_volley_stop(void);
extern unsigned files_volley_requests(void);
extern unsigned long long files_volley_ticks(void);
extern unsigned long long files_volley_frequency(void);
extern unsigned files_volley_restarts(int op);
extern unsigned files_volley_full_repeats(void);

#define VZ "/tmp/vz"
#define VZ_PAD 120
/* A spawned process creates seven threads (the eighth gives EAGAIN: the
 * quota of the process in the steps mode, STEPS_QUOTA, 429 pages), so 112
 * renames take sixteen processes. */
#define VZ_PROCESSES 16
#define VZ_THREADS 7
#define VZ_DEPTH 64
/* The numbers of ChangeOp. */
#define VZ_OP_UNLINK 1
#define VZ_OP_RENAME 3

#define VZ_CHECK(condition)                                                    \
    do {                                                                       \
        if (!(condition)) {                                                    \
            printf("posix-procs: volley: %s at names-volley.c:%d (errno %d)\n", \
                   #condition, __LINE__, errno);                               \
            return __LINE__;                                                   \
        }                                                                      \
    } while (0)

static unsigned vz_requests0;
static unsigned long long vz_ticks0;

static void vz_mark(void) {
    vz_requests0 = files_volley_requests();
    vz_ticks0 = files_volley_ticks();
}

/* The cost of what ran since the mark, alone in the system. */
static void vz_line(const char *what) {
    unsigned requests = files_volley_requests() - vz_requests0;
    unsigned long long ticks = files_volley_ticks() - vz_ticks0;
    printf("posix-procs: names time %s: %u requests, %llu ticks\n", what, requests, ticks);
}

static unsigned long long vz_now_ns(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (unsigned long long)now.tv_sec * 1000000000ull + (unsigned long long)now.tv_nsec;
}

/* The path of the chain `VZ_DEPTH` deep: /tmp/vz/b/x/x/..., `levels` of them. */
static void vz_deep(char *path, int levels) {
    strcpy(path, VZ "/b");
    for (int i = 1; i < levels; i++) strcat(path, "/x");
}

static int vz_create(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT, 0600);
    if (fd < 0) return -1;
    return close(fd);
}

static int vz_deep_build(void) {
    char path[600];
    for (int levels = 1; levels <= VZ_DEPTH; levels++) {
        vz_deep(path, levels);
        VZ_CHECK(mkdir(path, 0755) == 0);
    }
    return 0;
}

static int vz_deep_remove(void) {
    char path[600];
    for (int levels = VZ_DEPTH; levels >= 1; levels--) {
        vz_deep(path, levels);
        VZ_CHECK(rmdir(path) == 0);
    }
    return 0;
}

/* The times of the quiet operations, and the paths that cost many steps. */
static int vz_quiet(void) {
    char deep[600], moved[700], here[700];
    VZ_CHECK(vz_create(VZ "/p0") == 0);
    for (int i = 1; i < VZ_PAD; i++) {
        char name[40];
        snprintf(name, sizeof name, VZ "/p%d", i);
        VZ_CHECK(link(VZ "/p0", name) == 0);
    }
    /* A path whose component is missing. */
    vz_mark();
    errno = 0;
    VZ_CHECK(access(VZ "/missing/x", F_OK) == -1 && errno == ENOENT);
    vz_line("a missing component");
    VZ_CHECK(vz_create("/tmp/a") == 0);
    vz_mark();
    VZ_CHECK(unlink("/tmp/a") == 0);
    vz_line("unlink /tmp/a");
    VZ_CHECK(mkdir(VZ "/e", 0755) == 0);
    vz_mark();
    VZ_CHECK(rmdir(VZ "/e") == 0);
    vz_line("rmdir");
    /* Thirty-two links in one path pass, the thirty-third is ELOOP. */
    VZ_CHECK(symlink("p0", VZ "/s0") == 0);
    for (int i = 1; i <= 32; i++) {
        char target[16], name[40];
        snprintf(target, sizeof target, "s%d", i - 1);
        snprintf(name, sizeof name, VZ "/s%d", i);
        VZ_CHECK(symlink(target, name) == 0);
    }
    vz_mark();
    VZ_CHECK(access(VZ "/s31", F_OK) == 0);
    vz_line("a path of 32 links");
    errno = 0;
    VZ_CHECK(access(VZ "/s32", F_OK) == -1 && errno == ELOOP);
    for (int i = 32; i >= 0; i--) {
        char name[40];
        snprintf(name, sizeof name, VZ "/s%d", i);
        VZ_CHECK(unlink(name) == 0);
    }
    /* A directory under a chain 64 deep: the check that the target is no
     * descendant of it walks to the root one ancestor in a step. */
    VZ_CHECK(vz_deep_build() == 0);
    vz_deep(deep, VZ_DEPTH);
    VZ_CHECK(mkdir(VZ "/a", 0755) == 0);
    snprintf(moved, sizeof moved, "%s/a", deep);
    vz_mark();
    VZ_CHECK(rename(VZ "/a", moved) == 0);
    vz_line("rename of a directory under a chain 64 deep");
    VZ_CHECK(access(VZ "/a", F_OK) == -1 && access(moved, F_OK) == 0);
    VZ_CHECK(rename(moved, VZ "/a") == 0);
    VZ_CHECK(rmdir(VZ "/a") == 0);
    /* getcwd at depth 64: the path back to the root, one step an ancestor. */
    vz_mark();
    VZ_CHECK(chdir(deep) == 0);
    vz_line("chdir to depth 64");
    vz_mark();
    VZ_CHECK(getcwd(here, sizeof here) == here);
    vz_line("getcwd at depth 64");
    VZ_CHECK(strcmp(here, deep) == 0);
    VZ_CHECK(chdir("/") == 0);
    VZ_CHECK(vz_deep_remove() == 0);
    return 0;
}

/* The long rmdir against the flood of utimensat. */
static volatile int vz_flood_stop;
static volatile int vz_rmdir_result = -2;
static volatile int vz_rmdir_done;
static unsigned long long vz_rmdir_ticks;

static void *vz_flood(void *unused) {
    struct timespec times[2] = {{0, UTIME_NOW}, {0, UTIME_NOW}};
    while (!vz_flood_stop) {
        if (utimensat(AT_FDCWD, VZ "/p0", times, 0) != 0) {
            vz_flood_stop = 2;
            break;
        }
    }
    return unused;
}

static void *vz_long_rmdir(void *unused) {
    unsigned long long begin = files_volley_ticks();
    vz_rmdir_result = rmdir(VZ "/e");
    vz_rmdir_ticks = files_volley_ticks() - begin;
    vz_rmdir_done = 1;
    return unused;
}

static int vz_starvation(void) {
    /* Names until the table of the root is full. */
    VZ_CHECK(mkdir(VZ "/e", 0755) == 0);
    int made = 0;
    for (;; made++) {
        char name[40];
        snprintf(name, sizeof name, VZ "/q%d", made);
        if (link(VZ "/p0", name) != 0) break;
    }
    int refused = errno;
    printf("posix-procs: names: the table is full after %d more names (errno %d)\n", made, refused);
    VZ_CHECK(made > 150);
    /* A full table: removing an empty directory looks at every name. */
    vz_mark();
    VZ_CHECK(rmdir(VZ "/e") == 0);
    vz_line("rmdir with a full table");
    VZ_CHECK(mkdir(VZ "/e", 0755) == 0);
    files_volley_start();
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 65536);
    pthread_t flood, remover;
    unsigned long long begin = vz_now_ns();
    VZ_CHECK(pthread_create(&flood, &attr, vz_flood, NULL) == 0);
    VZ_CHECK(pthread_create(&remover, &attr, vz_long_rmdir, NULL) == 0);
    while (!vz_rmdir_done && vz_now_ns() - begin < 10000000000ull) {
        struct timespec delay = {0, 20000000};
        nanosleep(&delay, NULL);
    }
    int within = vz_rmdir_done;
    /* The flood ends so that the rmdir can end; the line tells both. */
    vz_flood_stop = vz_flood_stop ? vz_flood_stop : 1;
    VZ_CHECK(pthread_join(flood, NULL) == 0);
    VZ_CHECK(pthread_join(remover, NULL) == 0);
    VZ_CHECK(vz_flood_stop == 1);
    VZ_CHECK(vz_rmdir_result == 0);
    printf("posix-procs: names starvation: rmdir in a table of %d names against a loop of utimensat: "
           "%u restarts, finished within 10 s: %s, took %llu ticks\n",
           made + VZ_PAD, files_volley_restarts(VZ_OP_UNLINK), within ? "yes" : "no", vz_rmdir_ticks);
    for (int i = 0; i < made; i++) {
        char name[40];
        snprintf(name, sizeof name, VZ "/q%d", i);
        VZ_CHECK(unlink(name) == 0);
    }
    return 0;
}

/* The volley: a thread of a process renames one name when the time comes. */
struct vz_thread {
    int index;
    unsigned long long start;
    int result;
    unsigned long long ticks;
};

static void *vz_rename_thread(void *argument) {
    struct vz_thread *work = argument;
    char from[40], to[40];
    snprintf(from, sizeof from, VZ "/f%03d", work->index);
    snprintf(to, sizeof to, VZ "/g%03d", work->index);
    while (vz_now_ns() < work->start) {
        struct timespec delay = {0, 1000000};
        nanosleep(&delay, NULL);
    }
    unsigned long long begin = files_volley_ticks();
    work->result = rename(from, to) == 0 ? 0 : errno;
    work->ticks = files_volley_ticks() - begin;
    return NULL;
}

static volatile int vz_hold;

static void *vz_idle(void *unused) {
    while (!vz_hold) {
        struct timespec delay = {0, 1000000};
        nanosleep(&delay, NULL);
    }
    return unused;
}

/* What one thread costs the quota of its process: the bytes charged before
 * and after the creation of a thread with a stack of 20480 bytes (the block
 * of the thread, its TLS and the stack), alone in the process. */
static int vz_thread_cost(void) {
    enum { COUNT = 3 };
    pthread_t threads[COUNT];
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 20480);
    vz_hold = 0;
    unsigned long long first = 0, last = 0, total = 0;
    for (int i = 0; i < COUNT; i++) {
        unsigned long long before = stafeto_probe_memory_used();
        VZ_CHECK(pthread_create(&threads[i], &attr, vz_idle, NULL) == 0);
        unsigned long long cost = stafeto_probe_memory_used() - before;
        if (i == 0) first = cost;
        last = cost;
        total += cost;
    }
    vz_hold = 1;
    for (int i = 0; i < COUNT; i++) VZ_CHECK(pthread_join(threads[i], NULL) == 0);
    printf("posix-procs: names thread cost: %llu bytes (%llu pages) for the first thread, %llu bytes the last, "
           "%llu bytes for %d, stack 20480 bytes\n",
           first, first / 4096, last, total, (int)COUNT);
    return 0;
}

/* The role of a process of the volley: seven threads. The process writes to
 * /tmp/probe, at VZ_REPEATS + VZ_RECORD * process, the most repeats of
 * JOBS_FULL one of them made (4 bytes), the most restarts of the resolution
 * one rename reported (4 bytes) and the longest rename in ticks (8 bytes),
 * and exits with 0, or 100 and more for a failure. */
#define VZ_REPEATS 64
#define VZ_RECORD 16
static int vz_child(void) {
    int process = atoi(argv_seen[2]);
    unsigned long long start = strtoull(argv_seen[3], NULL, 10);
    struct vz_thread work[VZ_THREADS];
    pthread_t threads[VZ_THREADS];
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 20480);
    for (int i = 0; i < VZ_THREADS; i++) {
        work[i] = (struct vz_thread){process * VZ_THREADS + i, start, -1, 0};
        int e = pthread_create(&threads[i], &attr, vz_rename_thread, &work[i]);
        if (e != 0) {
            printf("posix-procs: volley: thread %d of process %d gave %d\n", i, process, e);
            return 101;
        }
    }
    /* The eighth thread does not fit the quota of the process: the lack of a
     * resource for a thread is EAGAIN (XSH pthread_create), the code a pool
     * of threads retries on. */
    {
        pthread_t eighth;
        vz_hold = 1;
        int e = pthread_create(&eighth, &attr, vz_idle, NULL);
        if (e != EAGAIN) {
            printf("posix-procs: volley: the eighth thread of process %d gave %d, wanted EAGAIN\n", process, e);
            if (e == 0) pthread_join(eighth, NULL);
            return 105;
        }
    }
    unsigned long long longest = 0;
    for (int i = 0; i < VZ_THREADS; i++) {
        if (pthread_join(threads[i], NULL) != 0) return 102;
        if (work[i].ticks > longest) longest = work[i].ticks;
        if (work[i].result != 0) {
            printf("posix-procs: volley: rename %d gave %d\n", work[i].index, work[i].result);
            return 103;
        }
    }
    unsigned numbers[2] = {files_volley_full_repeats(), files_volley_restarts(VZ_OP_RENAME)};
    unsigned char bytes[VZ_RECORD];
    memcpy(bytes, numbers, sizeof numbers);
    memcpy(bytes + sizeof numbers, &longest, sizeof longest);
    int fd = open("/tmp/probe", O_WRONLY);
    if (fd < 0 || pwrite(fd, bytes, VZ_RECORD, VZ_REPEATS + VZ_RECORD * process) != VZ_RECORD || close(fd))
        return 104;
    return 0;
}

static int vz_volley(void) {
    int total = VZ_PROCESSES * VZ_THREADS;
    for (int i = 0; i < total; i++) {
        char name[40];
        snprintf(name, sizeof name, VZ "/f%03d", i);
        VZ_CHECK(link(VZ "/p0", name) == 0);
    }
    files_volley_start();
    unsigned long long begin = files_volley_ticks();
    char stamp[24];
    snprintf(stamp, sizeof stamp, "%llu", vz_now_ns() + 2000000000ull);
    pid_t children[VZ_PROCESSES];
    for (int p = 0; p < VZ_PROCESSES; p++) {
        char index[8];
        snprintf(index, sizeof index, "%d", p);
        char *argv[] = {"procs-child", "volley", index, stamp, NULL};
        char *envp[] = {NULL};
        int e = EAGAIN;
        for (int tries = 0; tries < 5000 && e == EAGAIN; tries++) {
            e = posix_spawn(&children[p], "/bin/procs-child", NULL, NULL, argv, envp);
            if (e == EAGAIN) pause_ms(1);
        }
        VZ_CHECK(e == 0);
    }
    unsigned most = 0, most_restarts = 0;
    unsigned long long longest = 0;
    int probe = open("/tmp/probe", O_RDWR);
    VZ_CHECK(probe >= 0);
    for (int p = 0; p < VZ_PROCESSES; p++) {
        int status = 0;
        VZ_CHECK(waitpid(children[p], &status, 0) == children[p]);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
            printf("posix-procs: volley: process %d ended with status 0x%x\n", p, status);
        VZ_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        unsigned char bytes[VZ_RECORD];
        VZ_CHECK(pread(probe, bytes, VZ_RECORD, VZ_REPEATS + VZ_RECORD * p) == VZ_RECORD);
        unsigned numbers[2];
        unsigned long long ticks_of_process;
        memcpy(numbers, bytes, sizeof numbers);
        memcpy(&ticks_of_process, bytes + sizeof numbers, sizeof ticks_of_process);
        if (numbers[0] > most) most = numbers[0];
        if (numbers[1] > most_restarts) most_restarts = numbers[1];
        if (ticks_of_process > longest) longest = ticks_of_process;
    }
    VZ_CHECK(close(probe) == 0);
    unsigned long long ticks = files_volley_ticks() - begin;
    files_volley_stop();
    for (int i = 0; i < total; i++) {
        char from[40], to[40];
        snprintf(from, sizeof from, VZ "/f%03d", i);
        snprintf(to, sizeof to, VZ "/g%03d", i);
        VZ_CHECK(access(from, F_OK) == -1 && access(to, F_OK) == 0);
        VZ_CHECK(unlink(to) == 0);
    }
    printf("posix-procs: names volley: %d processes of %d threads, %d renames, all done, "
           "the most repeats of JOBS_FULL of one thread %u, the most restarts of one rename %u, "
           "the longest rename %llu ticks, %llu ticks\n",
           VZ_PROCESSES, VZ_THREADS, total, most, most_restarts, longest, ticks);
    return 0;
}

static int names_volley(void) {
    int failed;
    VZ_CHECK(mkdir(VZ, 0777) == 0);
    files_volley_start();
    failed = vz_thread_cost();
    if (!failed) failed = vz_quiet();
    if (!failed) failed = vz_starvation();
    if (!failed) failed = vz_volley();
    files_volley_stop();
    if (failed) return failed;
    for (int i = 0; i < VZ_PAD; i++) {
        char name[40];
        snprintf(name, sizeof name, VZ "/p%d", i);
        VZ_CHECK(unlink(name) == 0);
    }
    VZ_CHECK(rmdir(VZ) == 0);
    printf("posix-procs: names volley ok\n");
    return 0;
}
