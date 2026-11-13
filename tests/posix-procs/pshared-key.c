/* A wait or wake by address on a shared word is the right of a process that
 * holds the object (#525).
 *
 * The role "pshkey" is the owner V. It maps an anonymous shared page with a
 * process-shared semaphore, forks a waiter V' (sem_timedwait of 2 s) and
 * spawns a process A of its own that holds no object of the page. A reads the
 * word's key, which any process can derive (the PID of V in /proc and a
 * counter, or the device and inode of a file), and sends the waits and wakes
 * the layer would not send, at the highest level, straight to the pipe
 * service through the probe functions of the layer. The service refuses
 * them all (EPERM), so the single post of V reaches V', which wakes at once.
 * The parts, each by a role of A ("pshthief"):
 *
 * - an anonymous page: A waits (level 255) and wakes: EPERM both; one post
 *   of V wakes V' before its deadline (a service that took A's wait gives the
 *   post to A, the highest, and V' times out);
 * - a file of /dev/shm that A opens for reading only and maps: EPERM, the
 *   right of a reader is none (a wake by a reader is always spurious);
 * - a named semaphore that A has not opened: sem_wait and sem_post by its
 *   number are EPERM, and the unit is still there for V;
 * - a forked child that unmaps the page: its wait on the same key before is
 *   held (it holds the page through the fork), after the munmap it is EPERM
 *   (the process service raised the generation of its record, so the pipe
 *   service asked again).
 */

#include <semaphore.h>
#include <sys/ipc.h>
#include <sys/shm.h>

extern int stafeto_probe_wait_word(unsigned long address, unsigned long long *out);
extern int stafeto_probe_addr_wait(unsigned long long kind, unsigned long long key,
                                   unsigned long long offset, unsigned long long level,
                                   unsigned long long ms);
extern long long stafeto_probe_addr_wake(unsigned long long kind, unsigned long long key,
                                         unsigned long long offset, unsigned long long count);
extern unsigned long long stafeto_probe_nsem_open(const char *name);
extern int stafeto_probe_nsem_wait(unsigned long long id, unsigned long long level,
                                   unsigned long long ms);
extern int stafeto_probe_nsem_post(unsigned long long id);
extern unsigned long long stafeto_probe_share_key(unsigned long long device, unsigned long long inode);

static struct timespec pk_after_ms(long ms) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    t.tv_sec += ms / 1000;
    t.tv_nsec += (ms % 1000) * 1000000L;
    if (t.tv_nsec >= 1000000000L) {
        t.tv_sec++;
        t.tv_nsec -= 1000000000L;
    }
    return t;
}

/* A spawns as the role "pshthief" with the mode and its arguments. */
static pid_t pk_thief(const char *mode, unsigned long long a, unsigned long long b,
                      unsigned long long c, const char *path) {
    char number[3][24];
    snprintf(number[0], sizeof number[0], "%llu", a);
    snprintf(number[1], sizeof number[1], "%llu", b);
    snprintf(number[2], sizeof number[2], "%llu", c);
    char *argv[] = {"procs-child", "pshthief", (char *)mode, number[0], number[1], number[2],
                    (char *)path, NULL};
    char *envp[] = {NULL};
    pid_t pid = -1;
    int e = posix_spawn(&pid, "/bin/procs-child", NULL, NULL, argv, envp);
    if (e != 0) {
        printf("posix-procs: spawn of the thief gave %d (%s)\n", e, strerror(e));
        failures++;
        return -1;
    }
    return pid;
}

/* The thief: what the services do with a process that names a key. The
 * exit code names the check that failed. */
static int pk_thief_role(void) {
    if (argc_seen < 7) return 1;
    unsigned long long a = strtoull(argv_seen[3], NULL, 10);
    unsigned long long b = strtoull(argv_seen[4], NULL, 10);
    unsigned long long c = strtoull(argv_seen[5], NULL, 10);
    const char *mode = argv_seen[2];
    if (strcmp(mode, "word") == 0) {
        /* a kind, b key, c offset */
        if (stafeto_probe_addr_wait(a, b, c, 255, 3000) != EPERM) return 10;
        if (stafeto_probe_addr_wake(a, b, c, 4) != -EPERM) return 11;
        return 0;
    }
    if (strcmp(mode, "file") == 0) {
        /* The file's own key, as stat gives its device and inode. */
        int fd = open(argv_seen[6], O_RDONLY);
        if (fd < 0) return 20;
        struct stat st;
        if (fstat(fd, &st) != 0) return 21;
        void *p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
        if (p == MAP_FAILED) return 22;
        unsigned long long key = stafeto_probe_share_key(st.st_dev, st.st_ino);
        /* What the layer shows for a word it may not write: no key. */
        unsigned long long w[3];
        if (stafeto_probe_wait_word((unsigned long)p, w) == 0) return 23;
        if (stafeto_probe_addr_wait(0, key, 0, 255, 3000) != EPERM) return 24;
        if (stafeto_probe_addr_wake(0, key, 0, 4) != -EPERM) return 25;
        return 0;
    }
    if (strcmp(mode, "nsem") == 0) {
        /* The number comes through the pipe a (the descriptor), once the
         * owner has opened the semaphore; this process opened nothing. */
        unsigned long long id = 0;
        if (read((int)a, &id, sizeof id) != (ssize_t)sizeof id || id == 0) return 32;
        a = id;
        int waited = stafeto_probe_nsem_wait(a, 255, 3000);
        if (waited != EPERM) {
            printf("posix-procs: the unopened semaphore %llu: sem_wait gave %d\n", a, waited);
            return 30;
        }
        int posted = stafeto_probe_nsem_post(a);
        if (posted != EPERM) {
            printf("posix-procs: the unopened semaphore %llu: sem_post gave %d\n", a, posted);
            return 31;
        }
        return 0;
    }
    return 2;
}

/* A forked child that held the page: its wait on the key is held, then it
 * unmaps the page and the same wait is refused. */
static int pk_unmapper(void *page, size_t size, const unsigned long long word[3]) {
    /* A wake that finds nobody is an answer, after which the session no longer
     * brings its identity, and the right of the child stands in the pipe
     * service's memory of the session. */
    if (stafeto_probe_addr_wake(word[0], word[1], word[2], 1) != 0) return 43;
    if (stafeto_probe_addr_wait(word[0], word[1], word[2], 5, 100) != ETIMEDOUT) return 40;
    if (munmap(page, size) != 0) return 41;
    if (stafeto_probe_addr_wait(word[0], word[1], word[2], 5, 100) != EPERM) return 42;
    return 0;
}

static int pk_owner_role(void) {
    int before = failures;
    /* A named semaphore that a process has not opened. The thief is spawned
     * before the semaphore is opened: a child of posix_spawn starts with the
     * descriptions of its parent's session until its first request, so only a
     * process that is none of V's children shows the thief. */
    int numbers[2];
    expect("pipe for the number", pipe(numbers), 0);
    pid_t other = pk_thief("nsem", (unsigned long long)numbers[0], 0, 0, "");
    pause_ms(100);
    unsigned long long id = stafeto_probe_nsem_open("/pshkey-sem");
    expect("sem_open by number", id != 0, 1);
    expect("the number goes to the thief", write(numbers[1], &id, sizeof id), (int)sizeof id);
    if (other > 0) reap("the process that did not open the semaphore", other, 0, 0);
    if (id != 0) {
        /* The unit is still the owner's. */
        expect("the unit stays", stafeto_probe_nsem_wait(id, 5, 500), 0);
        sem_unlink("/pshkey-sem");
    }
    close(numbers[0]);
    close(numbers[1]);

    /* The anonymous page. */
    sem_t *sem = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    expect("the anonymous shared page", sem != MAP_FAILED, 1);
    if (sem == MAP_FAILED) return 1;
    expect("sem_init of the shared page", sem_init(sem, 1, 0), 0);
    unsigned long long word[3] = {0, 0, 0};
    expect("the key of the word", stafeto_probe_wait_word((unsigned long)sem, word), 0);
    expect("an anonymous word has the kind 1", word[0] == 1 && word[1] != 0, 1);
    /* The owner's own wait is held by the service: a deadline, no refusal. */
    expect("the owner waits by address", stafeto_probe_addr_wait(word[0], word[1], word[2], 5, 50),
           ETIMEDOUT);
    pid_t waiter = fork();
    if (waiter == 0) {
        struct timespec until = pk_after_ms(2500);
        if (sem_timedwait(sem, &until) == 0) _exit(0);
        _exit(errno == ETIMEDOUT ? 10 : 11);
    }
    expect("fork of the waiter", waiter > 0, 1);
    pause_ms(300);
    pid_t thief = pk_thief("word", word[0], word[1], word[2], "");
    pause_ms(400);
    expect("sem_post of the owner", sem_post(sem), 0);
    /* The waiter wakes at once with the unit, long before its deadline. */
    reap("the waiter of the shared page", waiter, 0, 0);
    if (thief > 0) reap("the thief of the anonymous page", thief, 0, 0);

    /* A file of /dev/shm that a reader maps. */
    shm_unlink("/pshkey-file");
    int fd = shm_open("/pshkey-file", O_CREAT | O_EXCL | O_RDWR, 0644);
    expect("shm_open of the file", fd >= 0, 1);
    if (fd >= 0) {
        expect("ftruncate of the file", ftruncate(fd, 4096), 0);
        void *file = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        expect("the owner maps the file", file != MAP_FAILED, 1);
        pid_t reader = pk_thief("file", 0, 0, 0, "/dev/shm/pshkey-file");
        if (reader > 0) reap("the reader of the file", reader, 0, 0);
        if (file != MAP_FAILED) munmap(file, 4096);
        close(fd);
        shm_unlink("/pshkey-file");
    }

    /* An XSI segment goes the same way: its file in /dev/shm is mapped through
     * the table of the process service, so a wait on its words is held. */
    int segment = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    expect("shmget", segment >= 0, 1);
    if (segment >= 0) {
        void *at = shmat(segment, NULL, 0);
        expect("shmat", at != (void *)-1, 1);
        if (at != (void *)-1) {
            unsigned long long seg[3] = {0, 0, 0};
            expect("the segment's word has a key", stafeto_probe_wait_word((unsigned long)at, seg), 0);
            expect("the segment's key is a file's", seg[0] == 0 && seg[1] != 0, 1);
            expect("the holder of the segment waits by address",
                   stafeto_probe_addr_wait(seg[0], seg[1], seg[2], 5, 50), ETIMEDOUT);
            expect("shmdt", shmdt(at), 0);
        }
        expect("shmctl IPC_RMID", shmctl(segment, IPC_RMID, NULL), 0);
    }

    /* A forked child that unmaps the page. */
    pid_t unmapper = fork();
    if (unmapper == 0) _exit(pk_unmapper(sem, 4096, word));
    expect("fork of the unmapper", unmapper > 0, 1);
    if (unmapper > 0) reap("the child that unmaps the page", unmapper, 0, 0);
    munmap(sem, 4096);
    if (failures == before) printf("posix-procs: pshared keys: the thief, the reader, the named semaphore and the unmapped page refused\n");
    return failures != before;
}
