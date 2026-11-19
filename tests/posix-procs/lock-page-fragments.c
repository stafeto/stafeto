/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* Public fragmentation makes one full inode retain 64 distinct paid pages.
 * Fork preserves the exact expenditure root. Each round adds a target lock
 * first, then fills its page with 63 locks on a separate inode. Three workers
 * retain 22/21/21 filler descriptors until all pages exist. Ordinary numeric
 * closes remove the fillers; killing the target owner makes all 64 remaining
 * records dead together. The service uses its normal allocator and sweep. */
#include <sys/statvfs.h>

extern int ring_identity(unsigned target, unsigned *words);
enum { PF_WORKERS = 3, PF_CHILDREN = 4, PF_PAGES = 64, PF_FILL = 63 };
struct pf_child { int command[2], reply[2]; pid_t pid; };
struct pf_command { unsigned operation, page; };

static long long pf_now(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return (long long)now.tv_sec * 1000000000LL + now.tv_nsec;
}
/* Every pipe read has a finite ten-second deadline, including failed children. */
static int pf_receive(int fd, void *output, size_t length) {
    unsigned char *bytes = output;
    long long start = pf_now();
    if (start < 0) return -1;
    for (size_t done = 0; done < length;) {
        ssize_t got = read(fd, bytes + done, length - done);
        if (got > 0) { done += (size_t)got; continue; }
        if (got == 0 || (errno != EAGAIN && errno != EINTR)) return -1;
        if (pf_now() - start >= 10000000000LL) return -1;
        const struct timespec delay = {0, 1000000};
        nanosleep(&delay, NULL);
    }
    return 0;
}
static int pf_lock(int fd, unsigned index) {
    struct flock lock = {0};
    lock.l_type = F_WRLCK; lock.l_whence = SEEK_SET;
    lock.l_start = 2 * index; lock.l_len = 1;
    return fcntl(fd, F_SETLK, &lock);
}
static void pf_run_child(struct pf_child *children, unsigned role, int target) {
    int input = children[role].command[0], output = children[role].reply[1];
    for (unsigned i = 0; i < PF_CHILDREN; i++) {
        if (children[i].command[0] != input) close(children[i].command[0]);
        close(children[i].command[1]);
        close(children[i].reply[0]);
        if (children[i].reply[1] != output) close(children[i].reply[1]);
    }
    if (role < PF_WORKERS) close(target);
    if (fcntl(input, F_SETFL, O_NONBLOCK)) _exit(81);
    unsigned identity[5] = {0};
    if (ring_identity((unsigned)getpid(), identity)
        || write(output, identity, sizeof identity) != sizeof identity) _exit(82);
    int fillers[22];
    for (unsigned i = 0; i < 22; i++) fillers[i] = -1;
    for (;;) {
        struct pf_command command;
        if (pf_receive(input, &command, sizeof command)) _exit(83);
        int result = 0;
        if (command.operation == 1 && command.page < PF_PAGES) {
            if (role == PF_WORKERS) {
                result = pf_lock(target, command.page);
            } else if (command.page % PF_WORKERS == role) {
                char path[48];
                snprintf(path, sizeof path, "/tmp/lock-fragment-%u", command.page);
                int fd = open(path, O_CREAT | O_RDWR | O_EXCL, 0666);
                if (fd < 0) result = -1;
                else {
                    fillers[command.page / PF_WORKERS] = fd;
                    for (unsigned i = 0; i < PF_FILL && !result; i++)
                        result = pf_lock(fd, i);
                }
            } else result = -1;
        } else if (command.operation == 3 && role == PF_WORKERS) {
            /* The live owner unlocks the whole file with one request. */
            struct flock all = {0};
            all.l_type = F_UNLCK; all.l_whence = SEEK_SET;
            all.l_start = 0; all.l_len = 0;
            result = fcntl(target, F_SETLK, &all);
        } else if (command.operation == 4 && role == PF_WORKERS) {
            /* The live owner closes the descriptor that owns its locks. */
            result = close(target);
        } else if (command.operation == 2 && role < PF_WORKERS) {
            for (unsigned i = 0; i < 22; i++) {
                if (fillers[i] >= 0 && close(fillers[i])) result = -1;
                fillers[i] = -1;
            }
        } else result = -1;
        if (write(output, &result, sizeof result) != sizeof result) _exit(84);
        if (result) _exit(85);
    }
}
static int pf_exchange(struct pf_child *child, unsigned operation, unsigned page) {
    struct pf_command command = {operation, page};
    int result = -1;
    if (write(child->command[1], &command, sizeof command) != sizeof command
        || pf_receive(child->reply[0], &result, sizeof result)) return -1;
    return result;
}
/* The file service keeps sweeping while records exist. Its maintenance must
 * leave the processor to the clients: a one-millisecond sleep of a client
 * ends within a bounded delay however long the records have been held. */
static int pf_sleep_latency(void) {
    for (unsigned i = 0; i < 8; i++) {
        long long start = pf_now();
        const struct timespec delay = {0, 1000000};
        if (start < 0 || nanosleep(&delay, NULL)) return -1;
        long long end = pf_now();
        if (end < 0 || end - start > 100000000LL) return -1;
    }
    return 0;
}
static int pf_pages(int target, unsigned long long *pages) {
    struct statvfs usage;
    if (fstatvfs(target, &usage) || usage.f_frsize != 4096) return -1;
    *pages = usage.f_bfree;
    return 0;
}
static int pf_wait(pid_t pid, int killed) {
    long long start = pf_now();
    if (start < 0) return -1;
    for (;;) {
        int status = 0;
        pid_t result = waitpid(pid, &status, WNOHANG);
        if (result == pid)
            return killed && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL ? 0 : -1;
        if (result < 0 || pf_now() - start >= 10000000000LL) return -1;
        const struct timespec delay = {0, 1000000};
        nanosleep(&delay, NULL);
    }
}
struct pf_world {
    struct pf_child children[PF_CHILDREN];
    int target;
    unsigned own[5];
    unsigned long long baseline;
};
static void pf_init(struct pf_world *w) {
    w->target = -1;
    w->baseline = 0;
    for (unsigned i = 0; i < PF_CHILDREN; i++) {
        w->children[i].pid = -1;
        for (unsigned j = 0; j < 2; j++)
            w->children[i].command[j] = w->children[i].reply[j] = -1;
    }
}
/* Ends the children, closes the pipes and the target, removes the files: nonzero when
 * a child did not end by the kill. */
static int pf_release(struct pf_world *w) {
    int failed = 0;
    for (unsigned i = 0; i < PF_CHILDREN; i++) {
        if (w->children[i].pid > 0) {
            kill(w->children[i].pid, SIGKILL);
            if (pf_wait(w->children[i].pid, 1)) failed = 1;
            w->children[i].pid = -1;
        }
        for (unsigned j = 0; j < 2; j++) {
            if (w->children[i].command[j] >= 0) close(w->children[i].command[j]);
            if (w->children[i].reply[j] >= 0) close(w->children[i].reply[j]);
            w->children[i].command[j] = w->children[i].reply[j] = -1;
        }
    }
    if (w->target >= 0) close(w->target);
    w->target = -1;
    for (unsigned page = 0; page < PF_PAGES; page++) {
        char path[48];
        snprintf(path, sizeof path, "/tmp/lock-fragment-%u", page);
        if (unlink(path) && errno != ENOENT) failed = 1;
    }
    if (unlink("/tmp/lock-fragment-target") && errno != ENOENT) failed = 1;
    return failed;
}
#define PF_CHECK(condition) do { if (!(condition)) { \
    printf("posix-procs: fragmented lock pages failed line=%d errno=%d\n", __LINE__, errno); \
    failed = 1; goto cleanup; } } while (0)
/* The public recipe: the target owner (the child PF_WORKERS) locks one record on each of
 * 64 pages, three workers fill the pages and then close their fillers. On return the
 * target inode holds 64 records, each alone on its own paid page. */
static int pf_build(struct pf_world *w) {
    struct pf_child *children = w->children;
    int failed = 0;
    unsigned long long retained = 0;
    w->target = open("/tmp/lock-fragment-target", O_CREAT | O_RDWR | O_EXCL, 0666);
    PF_CHECK(w->target >= 0);
    PF_CHECK(ring_identity((unsigned)getpid(), w->own) == 0 && w->own[1] == 1);
    for (unsigned i = 0; i < PF_CHILDREN; i++) {
        PF_CHECK(pipe(children[i].command) == 0 && pipe(children[i].reply) == 0);
    }
    for (unsigned i = 0; i < PF_CHILDREN; i++) {
        children[i].pid = fork();
        if (children[i].pid == 0) pf_run_child(children, i, w->target);
        PF_CHECK(children[i].pid > 0);
    }
    for (unsigned i = 0; i < PF_CHILDREN; i++) {
        close(children[i].command[0]); children[i].command[0] = -1;
        close(children[i].reply[1]); children[i].reply[1] = -1;
        PF_CHECK(fcntl(children[i].reply[0], F_SETFL, O_NONBLOCK) == 0);
        unsigned identity[5];
        PF_CHECK(pf_receive(children[i].reply[0], identity, sizeof identity) == 0);
        PF_CHECK(identity[0] == (unsigned)children[i].pid && identity[1] == 1
                 && identity[2] == w->own[2] && identity[3] == w->own[3]);
    }
    PF_CHECK(pf_pages(w->target, &w->baseline) == 0);
    for (unsigned page = 0; page < PF_PAGES; page++) {
        PF_CHECK(pf_exchange(&children[PF_WORKERS], 1, page) == 0);
        PF_CHECK(pf_exchange(&children[page % PF_WORKERS], 1, page) == 0);
        if (page % 16 == 15) PF_CHECK(pf_sleep_latency() == 0);
    }
    for (unsigned worker = 0; worker < PF_WORKERS; worker++)
        PF_CHECK(pf_exchange(&children[worker], 2, 0) == 0);
    PF_CHECK(pf_pages(w->target, &retained) == 0 && w->baseline == retained + PF_PAGES);
    return 0;
cleanup:
    return failed;
}
/* The same 64 records on 64 pages, held by a live owner, released in one request: the owner
 * unlocks the whole file (operation 3) or closes the descriptor of the locks (operation 4,
 * the last close of the description). The markers bound the steps of the file service that
 * belong to the case. */
static int pf_live_release(unsigned operation, const char *name) {
    struct pf_world w;
    int failed = 0;
    pf_init(&w);
    PF_CHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
    PF_CHECK(pf_build(&w) == 0);
    PF_CHECK(pf_sleep_latency() == 0);
    if (operation == 4) {
        /* The owner's close is then the last close of the description. */
        PF_CHECK(close(w.target) == 0);
        w.target = -1;
    }
    printf("posix-procs: fragmented lock pages %s: begin, 64 paid pages, 64 records of a live PID=%d\n",
           name, w.children[PF_WORKERS].pid);
    PF_CHECK(pf_exchange(&w.children[PF_WORKERS], operation, 0) == 0);
    /* The line of the step goes out after its reply: leave time for it before the end marker. */
    PF_CHECK(pf_sleep_latency() == 0);
    {
        long long start = pf_now();
        unsigned long long now = 0;
        PF_CHECK(start >= 0);
        /* The pages are counted by a descriptor of the parent that stays open (or by a new one). */
        int probe = w.target >= 0 ? w.target : open("/tmp/lock-fragment-target", O_RDWR);
        PF_CHECK(probe >= 0);
        do {
            PF_CHECK(pf_pages(probe, &now) == 0);
            if (now == w.baseline) break;
            PF_CHECK(pf_now() - start < 10000000000LL);
            const struct timespec delay = {0, 1000000};
            nanosleep(&delay, NULL);
        } while (1);
        if (probe != w.target) close(probe);
    }
    printf("posix-procs: fragmented lock pages %s: end, all 64 pages released\n", name);
cleanup:
    if (pf_release(&w)) failed = 1;
    return failed;
}
static int public_lock_page_fragments(void) {
    struct pf_world w;
    int failed = 0;
    pf_init(&w);
    /* The two releases by a live owner come first: their steps are then new longest steps of
     * their kinds and the console tells them. */
    if (pf_live_release(3, "unlock of the whole file")) return 1;
    if (pf_live_release(4, "close of the descriptor")) return 1;
    PF_CHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
    PF_CHECK(pf_build(&w) == 0);
    printf("posix-procs: fragmented lock pages ready: 64 paid pages, 64 records, PID=%d root=%u:%u\n",
           w.children[PF_WORKERS].pid, w.own[2], w.own[3]);
    PF_CHECK(kill(w.children[PF_WORKERS].pid, SIGKILL) == 0);
    PF_CHECK(pf_wait(w.children[PF_WORKERS].pid, 1) == 0);
    PF_CHECK(process_lifetime(w.children[PF_WORKERS].pid) == 0);
    /* A request that sets finds all 64 records dead: its step is the longest
     * the file service has for a full inode of dead records. */
    {
        struct flock set = {0};
        set.l_type = F_WRLCK; set.l_whence = SEEK_SET;
        set.l_start = 1000; set.l_len = 1;
        PF_CHECK(fcntl(w.target, F_SETLK, &set) == 0);
        set.l_type = F_UNLCK;
        PF_CHECK(fcntl(w.target, F_SETLK, &set) == 0);
    }
    unsigned dead[5];
    PF_CHECK(ring_identity((unsigned)w.children[PF_WORKERS].pid, dead) == 0 && dead[1] == 0);
    w.children[PF_WORKERS].pid = -1;
    struct flock query = {0};
    query.l_type = F_WRLCK; query.l_whence = SEEK_SET;
    PF_CHECK(fcntl(w.target, F_GETLK, &query) == 0 && query.l_type == F_UNLCK);
    long long start = pf_now();
    PF_CHECK(start >= 0);
    do {
        unsigned long long final = 0;
        PF_CHECK(pf_pages(w.target, &final) == 0);
        if (final == w.baseline) break;
        PF_CHECK(pf_now() - start < 10000000000LL);
        const struct timespec delay = {0, 1000000};
        nanosleep(&delay, NULL);
    } while (1);
    puts("posix-procs: fragmented lock pages: 64 paid pages, 64 target records, one PID death, all pages reclaimed");
cleanup:
    if (pf_release(&w)) failed = 1;
    return failed;
}
#undef PF_CHECK
