/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
/* The operations on names in the steps mode (xtask process-steps), before the
 * crowd: a path of 32 links, the rename of a directory under a chain 64 deep,
 * getcwd at depth 64, the rmdir with a full table of names, a volley of 112
 * long renames from sixteen processes of seven threads (once in a common
 * directory, once with a directory for each process), and a long rmdir
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
extern int files_volley_read_dir_index(const char *path, unsigned index);

#include <dirent.h>

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
#define VZ_OP_ACCESS 10
#define VZ_OP_PATH 12

#define VZ_CHECK(condition)                                                    \
    do {                                                                       \
        if (!(condition)) {                                                    \
            printf("posix-procs: volley: %s at names-volley.c:%d (errno %d)\n", \
                   #condition, __LINE__, errno);                               \
            return __LINE__;                                                   \
        }                                                                      \
    } while (0)

/* The parent slot used by the service's name hash is exposed by st_ino. */
static unsigned vz_name_bucket(unsigned slot, const char *name) {
    unsigned hash = 0x811c9dc5u ^ slot;
    for (; *name; name++) hash = (hash ^ (unsigned char)*name) * 0x01000193u;
    return (hash ^ (hash >> 15)) & 2047u;
}

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

/* The longest walks of a listing (the worry of 5i-5b step 1): the list of the
 * names of a directory is walked from its head when the hint of a position is
 * stale, by a seek to a late position, and by the call of the service that
 * counts the entries from the head. The service prints its longest steps; this
 * only builds the worst states and counts the entries it walked. */
static int vz_count_entries(const char *path, long *late) {
    DIR *dir = opendir(path);
    if (dir == NULL) return 0;
    long count = 0, before_last = -1, previous = -1;
    struct dirent *entry;
    while (1) {
        long here = telldir(dir);
        entry = readdir(dir);
        if (entry == NULL) break;
        count++;
        before_last = previous;
        previous = here;
    }
    *late = before_last;
    VZ_CHECK(closedir(dir) == 0);
    return (int)count;
}

/* A seek to the position before the last entry after a listing to the end
 * (the hint is the last entry, so it does not match), then one readdir: the
 * service walks the list from the head to that position. The call by index of
 * the service walks the same list to the entry before the last. */
static int vz_stale_seek(const char *path, const char *what) {
    DIR *dir = opendir(path);
    VZ_CHECK(dir != NULL);
    static long positions[1100];
    int count = 0;
    while (count < 1100) {
        positions[count] = telldir(dir);
        if (readdir(dir) == NULL) break;
        count++;
    }
    VZ_CHECK(count > 2 && count < 1100);
    for (int round = 0; round < 3; round++) {
        seekdir(dir, positions[count - 1]);
        VZ_CHECK(readdir(dir) != NULL);
        /* To the end again, so that the hint is the last entry. */
        while (readdir(dir) != NULL) {}
    }
    VZ_CHECK(closedir(dir) == 0);
    /* The call by index serves the first 258 entries (the two dots and 256 names) and
     * refuses the rest: the longest it walks, and the first it refuses. */
    int served = count - 1 < 258 ? count - 1 : 258;
    VZ_CHECK(files_volley_read_dir_index(path, (unsigned)served) > 0);
    if (count > 259) VZ_CHECK(files_volley_read_dir_index(path, 259) < 0);
    printf("posix-procs: names listing: %s, %d entries, a seek to the last but one and a call by index\n",
           what, count);
    return 0;
}

/* The directory of the image with the most names, with the names the table
 * can still take added to it, then the common directory of the probe filled
 * the same way: the lists of the longest walks. */
static int vz_listing(void) {
    const char *candidates[] = {"/", "/bin", "/etc", "/usr", "/usr/bin", "/lib", "/sbin", "/dev"};
    const char *biggest = NULL;
    int most = 0;
    for (unsigned i = 0; i < sizeof candidates / sizeof candidates[0]; i++) {
        long late;
        int count = vz_count_entries(candidates[i], &late);
        printf("posix-procs: names listing: %s has %d entries\n", candidates[i], count);
        if (count > most) {
            most = count;
            biggest = candidates[i];
        }
    }
    VZ_CHECK(biggest != NULL);
    const char *places[2] = {biggest, VZ};
    for (int place = 0; place < 2; place++) {
        int made = 0;
        for (;; made++) {
            char name[80];
            snprintf(name, sizeof name, "%s/z%d", places[place], made);
            if (link(VZ "/p0", name) != 0) break;
        }
        if (made <= 100) printf("posix-procs: names listing: %s took %d names, errno %d\n", places[place], made, errno);
        VZ_CHECK(made > 100);
        VZ_CHECK(vz_stale_seek(places[place], place == 0 ? "the biggest directory of the image" : "the common directory") == 0);
        for (int i = 0; i < made; i++) {
            char name[80];
            snprintf(name, sizeof name, "%s/z%d", places[place], i);
            VZ_CHECK(unlink(name) == 0);
        }
    }
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
    unsigned long long quiet_ticks = files_volley_ticks() - vz_ticks0;
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
           "%u restarts, finished within 10 s: %s, took %llu ticks, alone %llu ticks\n",
           made + VZ_PAD, files_volley_restarts(VZ_OP_UNLINK), within ? "yes" : "no", vz_rmdir_ticks,
           quiet_ticks);
    for (int i = 0; i < made; i++) {
        char name[40];
        snprintf(name, sizeof name, VZ "/q%d", i);
        VZ_CHECK(unlink(name) == 0);
    }
    return 0;
}

/* One long operation against a client that changes the tree in a loop (the
 * lines G2 to G5 of the plan; the long rmdir of the line G1 is below). The
 * operation runs alone first, then against the flood; the line says the
 * restarts the service gave it (the most of its kind), whether it ended
 * within ten seconds, its result and the ticks of both runs. */
static volatile int vz_scene_flood_mode;
static volatile int vz_scene_long_mode;
static volatile int vz_scene_result = -2;
static volatile int vz_scene_done;
static unsigned long long vz_scene_ticks;
static char vz_scene_moved[700];
static char vz_scene_deep[600];
static char vz_collision_path[80];

static void *vz_scene_flood(void *unused) {
    struct timespec times[2] = {{0, UTIME_NOW}, {0, UTIME_NOW}};
    int flip = 0;
    while (!vz_flood_stop) {
        int bad = 0;
        switch (vz_scene_flood_mode) {
        case 1: /* a name made and removed in another directory */ {
            int fd = open(VZ "/fd/x", O_WRONLY | O_CREAT, 0600);
            if (fd < 0) bad = 1;
            else {
                close(fd);
                if (unlink(VZ "/fd/x") != 0) bad = 1;
            }
            break;
        }
        case 5: /* a name in another directory, in the source's bucket */ {
            int fd = open(vz_collision_path, O_WRONLY | O_CREAT, 0600);
            if (fd < 0) bad = 1;
            else { close(fd); bad = unlink(vz_collision_path) != 0; }
            break;
        }
        case 2: /* the mode of a file in a loop */
            flip ^= 1;
            bad = chmod(VZ "/p0", flip ? 0600 : 0644) != 0;
            break;
        case 3: /* the name the operation renames over, made and removed in the same directory */ {
            int fd = open(VZ "/n", O_WRONLY | O_CREAT, 0600);
            if (fd >= 0) close(fd);
            unlink(VZ "/n");
            break;
        }
        case 4: /* directories that move */
            if (rename(VZ "/m1", VZ "/m2") != 0 && rename(VZ "/m2", VZ "/m1") != 0) bad = 1;
            break;
        default:
            bad = utimensat(AT_FDCWD, VZ "/p0", times, 0) != 0;
        }
        if (bad) {
            vz_flood_stop = 2;
            break;
        }
    }
    return unused;
}

static int vz_scene_operation(void) {
    char buffer[700];
    switch (vz_scene_long_mode) {
    case 1: return access(VZ "/s31", F_OK);
    case 2: return rename(VZ "/a", vz_scene_moved);
    case 3: return rename(VZ "/m", VZ "/n");
    case 4: return realpath(vz_scene_deep, buffer) == NULL ? -1 : 0;
    }
    return -3;
}

static void *vz_scene_long(void *unused) {
    unsigned long long begin = files_volley_ticks();
    vz_scene_result = vz_scene_operation() == 0 ? 0 : errno;
    vz_scene_ticks = files_volley_ticks() - begin;
    vz_scene_done = 1;
    return unused;
}

/* The operation `long_mode` against the flood `flood_mode`; `op` is the
 * number of its kind of ChangeOp, `tag` the line of the plan. */
static int vz_scene(const char *tag, const char *what, int flood_mode, int long_mode, int op) {
    /* Alone. */
    vz_scene_long_mode = long_mode;
    unsigned long long alone_begin = files_volley_ticks();
    int alone = vz_scene_operation();
    unsigned long long alone_ticks = files_volley_ticks() - alone_begin;
    VZ_CHECK(alone == 0);
    /* Back to the start when the operation moved something. */
    if (long_mode == 2) VZ_CHECK(rename(vz_scene_moved, VZ "/a") == 0);
    if (long_mode == 3) {
        VZ_CHECK(rename(VZ "/n", VZ "/m") == 0);
    }
    files_volley_start();
    vz_flood_stop = 0;
    vz_scene_flood_mode = flood_mode;
    vz_scene_done = 0;
    vz_scene_result = -2;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 65536);
    pthread_t flood, runner;
    unsigned long long begin = vz_now_ns();
    VZ_CHECK(pthread_create(&flood, &attr, vz_scene_flood, NULL) == 0);
    /* The flood is in its loop before the operation starts. */
    pause_ms(20);
    VZ_CHECK(pthread_create(&runner, &attr, vz_scene_long, NULL) == 0);
    while (!vz_scene_done && vz_now_ns() - begin < 10000000000ull) {
        struct timespec delay = {0, 20000000};
        nanosleep(&delay, NULL);
    }
    int within = vz_scene_done;
    vz_flood_stop = vz_flood_stop ? vz_flood_stop : 1;
    VZ_CHECK(pthread_join(flood, NULL) == 0);
    VZ_CHECK(pthread_join(runner, NULL) == 0);
    VZ_CHECK(vz_flood_stop == 1);
    printf("posix-procs: names interference %s: %s: %u restarts, finished within 10 s: %s, "
           "result %d, took %llu ticks, alone %llu ticks\n",
           tag, what, files_volley_restarts(op), within ? "yes" : "no", vz_scene_result,
           vz_scene_ticks, alone_ticks);
    files_volley_stop();
    /* Back where it was, when the operation moved something. */
    if (long_mode == 2 && access(vz_scene_moved, F_OK) == 0) VZ_CHECK(rename(vz_scene_moved, VZ "/a") == 0);
    return 0;
}

/* G2 to G5. */
static int vz_scenes(void) {
    /* G2: a path of 32 links against a name made and removed in another directory. */
    VZ_CHECK(mkdir(VZ "/fd", 0755) == 0);
    VZ_CHECK(symlink("p0", VZ "/s0") == 0);
    for (int i = 1; i <= 31; i++) {
        char target[16], name[40];
        snprintf(target, sizeof target, "s%d", i - 1);
        snprintf(name, sizeof name, VZ "/s%d", i);
        VZ_CHECK(symlink(target, name) == 0);
    }
    VZ_CHECK(vz_scene("G2", "a path of 32 links against a name made and removed in another directory", 1, 1,
                      VZ_OP_ACCESS) == 0);
    for (int i = 31; i >= 0; i--) {
        char name[40];
        snprintf(name, sizeof name, VZ "/s%d", i);
        VZ_CHECK(unlink(name) == 0);
    }
    VZ_CHECK(rmdir(VZ "/fd") == 0);
    /* G3: the rename of a directory under a chain 64 deep against the mode of a file. */
    VZ_CHECK(vz_deep_build() == 0);
    vz_deep(vz_scene_deep, VZ_DEPTH);
    snprintf(vz_scene_moved, sizeof vz_scene_moved, "%s/a", vz_scene_deep);
    VZ_CHECK(mkdir(VZ "/a", 0755) == 0);
    VZ_CHECK(mkdir(VZ "/fd", 0755) == 0);
    struct stat parent, other;
    VZ_CHECK(stat(VZ, &parent) == 0 && stat(VZ "/fd", &other) == 0);
    unsigned wanted = vz_name_bucket((unsigned)parent.st_ino - 1u, "a");
    for (unsigned i = 0;; i++) {
        char leaf[40];
        snprintf(leaf, sizeof leaf, "collision%u", i);
        if (vz_name_bucket((unsigned)other.st_ino - 1u, leaf) == wanted) {
            snprintf(vz_collision_path, sizeof vz_collision_path, VZ "/fd/%s", leaf);
            break;
        }
    }
    VZ_CHECK(vz_scene("G2b", "a rename against a colliding name in another directory", 5, 2, VZ_OP_RENAME) == 0);
    VZ_CHECK(rmdir(VZ "/fd") == 0);
    VZ_CHECK(vz_scene("G3", "the rename of a directory under a chain 64 deep against chmod of a file", 2, 2,
                      VZ_OP_RENAME) == 0);
    VZ_CHECK(rmdir(VZ "/a") == 0);
    /* G4: a rename against a client that makes and removes the name it renames over, in the same directory. */
    VZ_CHECK(vz_create(VZ "/m") == 0);
    VZ_CHECK(vz_scene("G4", "a rename over a name that is made and removed in the same directory", 3, 3,
                      VZ_OP_RENAME) == 0);
    unlink(VZ "/m");
    unlink(VZ "/n");
    /* G5: the path of a directory 64 deep against directories that move. */
    VZ_CHECK(mkdir(VZ "/m1", 0755) == 0);
    VZ_CHECK(vz_scene("G5", "the canonical path of a directory 64 deep against directories that move", 4, 4,
                      VZ_OP_PATH) == 0);
    VZ_CHECK(rmdir(VZ "/m1") == 0 || rmdir(VZ "/m2") == 0);
    VZ_CHECK(vz_deep_remove() == 0);
    return 0;
}

/* The volley: a thread of a process renames one name when the time comes. */
struct vz_thread {
    int index;
    unsigned long long start;
    int result;
    unsigned long long ticks;
    /* The directory of the thread's names, or -1 for the common one. */
    int directory;
};

/* The name /tmp/vz/<kind><index>, or /tmp/vz/d<directory>/<kind><index>. */
static void vz_volley_name(char *name, size_t size, int directory, char kind, int index) {
    if (directory < 0) snprintf(name, size, VZ "/%c%03d", kind, index);
    else snprintf(name, size, VZ "/d%02d/%c%03d", directory, kind, index);
}

static void *vz_rename_thread(void *argument) {
    struct vz_thread *work = argument;
    char from[40], to[40];
    vz_volley_name(from, sizeof from, work->directory, 'f', work->index);
    vz_volley_name(to, sizeof to, work->directory, 'g', work->index);
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
    /* A fifth argument "d" gives the process a directory of its own. */
    int directory = argc_seen > 4 && argv_seen[4][0] == 'd' ? process : -1;
    struct vz_thread work[VZ_THREADS];
    pthread_t threads[VZ_THREADS];
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 20480);
    for (int i = 0; i < VZ_THREADS; i++) {
        work[i] = (struct vz_thread){process * VZ_THREADS + i, start, -1, 0, directory};
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

/* The volley of 112 renames. With `per_directory` each process renames in a
 * directory of its own, so that the renames of two processes share no
 * parent and the common table of the places is what they wait for. */
static int vz_volley(int per_directory) {
    int total = VZ_PROCESSES * VZ_THREADS;
    if (per_directory) {
        for (int p = 0; p < VZ_PROCESSES; p++) {
            char name[40];
            snprintf(name, sizeof name, VZ "/d%02d", p);
            VZ_CHECK(mkdir(name, 0755) == 0);
        }
    }
    for (int i = 0; i < total; i++) {
        char name[40];
        vz_volley_name(name, sizeof name, per_directory ? i / VZ_THREADS : -1, 'f', i);
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
        char *argv[] = {"procs-child", "volley", index, stamp, per_directory ? "d" : NULL, NULL};
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
        int directory = per_directory ? i / VZ_THREADS : -1;
        vz_volley_name(from, sizeof from, directory, 'f', i);
        vz_volley_name(to, sizeof to, directory, 'g', i);
        VZ_CHECK(access(from, F_OK) == -1 && access(to, F_OK) == 0);
        VZ_CHECK(unlink(to) == 0);
    }
    if (per_directory) {
        for (int p = 0; p < VZ_PROCESSES; p++) {
            char name[40];
            snprintf(name, sizeof name, VZ "/d%02d", p);
            VZ_CHECK(rmdir(name) == 0);
        }
    }
    printf("posix-procs: names volley%s: %d processes of %d threads, %d renames, all done, "
           "the most repeats of JOBS_FULL of one thread %u, the most restarts of one rename %u, "
           "the longest rename %llu ticks, %llu ticks\n",
           per_directory ? " in directories" : "", VZ_PROCESSES, VZ_THREADS, total, most, most_restarts,
           longest, ticks);
    return 0;
}

static int names_volley(void) {
    int failed;
    VZ_CHECK(mkdir(VZ, 0777) == 0);
    files_volley_start();
    failed = vz_thread_cost();
    if (!failed) failed = vz_quiet();
    if (!failed) failed = vz_listing();
    if (!failed) failed = vz_starvation();
    if (!failed) failed = vz_scenes();
    if (!failed) failed = vz_volley(0);
    if (!failed) failed = vz_volley(1);
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

/* A second root waits for the gate before publishing its 250 names. */
int files_bounds_fill(int stage) {
    if (stage == -2) {
        while (access("/tmp/bp-go", F_OK)) pause_ms(1);
    }
    struct stat st;
    if (stat("/tmp/bp", &st)) return 1;
    unsigned slot = (unsigned)st.st_ino - 1u;
    unsigned wanted = vz_name_bucket(slot, "pending");
    if (stage == -1) {
        int fd = open("/tmp/bp/target", O_WRONLY | O_CREAT, 0600);
        if (fd < 0 || close(fd) || chmod("/tmp/bp", 0777)) return 2;
        return 0;
    }
    if (stage == 0) {
        int fd = open("/tmp/bp-go", O_WRONLY | O_CREAT, 0600);
        if (fd < 0 || close(fd)) return 8;
    }
    int begin = stage == 0 ? 250 : 0;
    int end = stage == -2 ? 250 : 500;
    int made = 0;
    for (unsigned i = 0; made < end; i++) {
        char leaf[40], path[64];
        snprintf(leaf, sizeof leaf, "late%u", i);
        if (vz_name_bucket(slot, leaf) == wanted) continue;
        if (made++ < begin) continue;
        snprintf(path, sizeof path, "/tmp/bp/%s", leaf);
        if (stage == 1 ? unlink(path) : link("/tmp/bp/target", path)) {
            printf("posix-procs: bounds: name %d stage %d errno %d\n", made, stage, errno);
            return 4;
        }
    }
    if (stage == 0) {
        while (access("/tmp/bp-done", F_OK)) pause_ms(1);
        if (unlink("/tmp/bp-done")) return 5;
    } else if (stage == 1 && (unlink("/tmp/bp/target") || unlink("/tmp/bp-go"))) return 6;
    else if (stage == -2) {
        int fd = open("/tmp/bp-done", O_WRONLY | O_CREAT, 0600);
        if (fd < 0 || close(fd)) return 9;
    }
    return 0;
}
