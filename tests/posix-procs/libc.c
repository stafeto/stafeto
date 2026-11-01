/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* Cases of relibc itself (step 6, part 1).
 *
 * The role "libc" forks one child per case and reaps it, as the role
 * "timers" does: an exit code names the failed check (0 passes).
 *
 * - exit: two threads write fixed lines into one FILE and the main thread
 *   calls exit: the file ends with a whole line, however the exit lands (#320).
 * - fclose with a write that failed, among threads that flush all streams and
 *   open files, leaves nothing for a file that takes the number (#327).
 * - execvp, execlp and posix_spawnp run a file that is no program with the
 *   shell, execv does not (#375).
 * - aio_cancel and timer_gettime in a child of fork do not wait for a lock
 *   that a thread of the parent held at the fork (#376).
 * - stdatomic.h, the C11 operations of the header, in Clang (#203).
 * - streams over memory use no descriptor and no file: fmemopen and
 *   open_memstream work when the descriptors are all used up, fileno says
 *   EBADF (#285).
 */
#include <aio.h>
#include <stdatomic.h>
#include <stdint.h>

extern char **environ;

#if !CHANGE_STEPS

static void lc_nap(long ms) {
    struct timespec d = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};
    while (nanosleep(&d, &d) < 0 && errno == EINTR) {}
}

/* The text of a file, up to `size` bytes; its length, or -1. */
static long lc_slurp(const char *path, char *out, size_t size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    long got = 0;
    for (;;) {
        ssize_t n = read(fd, out + got, size - (size_t)got);
        if (n <= 0) break;
        got += n;
    }
    close(fd);
    return got;
}

/* A child that must end within `ms` milliseconds: waits for it with WNOHANG
 * and kills it when the time is up (a hang is a failure that the probe reports).
 * Returns its exit status, or -1 for a kill or a status that is no exit. */
static int lc_wait(pid_t pid, long ms) {
    int status = 0;
    for (long waited = 0; waited <= ms; waited += 5) {
        pid_t got = waitpid(pid, &status, WNOHANG);
        if (got == pid) return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        if (got < 0) return -1;
        lc_nap(5);
    }
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
    return -1;
}

/* ---- #320: exit with writers running ---- */
#define LC_EXIT_LINE 39
#define LC_EXIT_ROUNDS 20
static const char lc_filler[] = "0123456789abcdefghijklmnopqrstuvwxyz!";
static FILE *lc_exit_stream;
static void *lc_writes_lines(void *arg) {
    char id = (char)(intptr_t)arg;
    for (int i = 0; i < 3000; i++) {
        flockfile(lc_exit_stream);
        putc_unlocked(id, lc_exit_stream);
        for (int j = 0; lc_filler[j] != 0; j++) putc_unlocked(lc_filler[j], lc_exit_stream);
        putc_unlocked('\n', lc_exit_stream);
        funlockfile(lc_exit_stream);
    }
    return NULL;
}
static int lc_exit_whole_lines(void) {
    char path[32];
    for (int round = 0; round < LC_EXIT_ROUNDS; round++) {
        snprintf(path, sizeof path, "/tmp/exit-%d", round);
        pid_t child = fork();
        if (child < 0) return 1;
        if (child == 0) {
            lc_exit_stream = fopen(path, "w");
            if (lc_exit_stream == NULL) _exit(2);
            pthread_t writer[2];
            for (int i = 0; i < 2; i++)
                if (pthread_create(&writer[i], NULL, lc_writes_lines, (void *)(intptr_t)('A' + i)) != 0) _exit(3);
            lc_nap(10 + round % 7);
            exit(0);
        }
        if (lc_wait(child, 10000) != 0) return 4;
        FILE *in = fopen(path, "r");
        if (in == NULL) return 5;
        char line[LC_EXIT_LINE + 2];
        long lines = 0;
        for (;;) {
            size_t got = fread(line, 1, LC_EXIT_LINE, in);
            if (got == 0) break;
            if (got != LC_EXIT_LINE || (line[0] != 'A' && line[0] != 'B') || line[LC_EXIT_LINE - 1] != '\n' ||
                memcmp(line + 1, lc_filler, LC_EXIT_LINE - 2) != 0) {
                printf("posix-procs: libc: round %d: line %ld is torn (%zu bytes)\n", round, lines, got);
                fclose(in);
                return 6;
            }
            lines++;
        }
        fclose(in);
        unlink(path);
        if (lines == 0) return 7;
    }
    return 0;
}

/* ---- #327: fclose of a stream whose write failed, and fflush(NULL) ---- */
static volatile int lc_stop, lc_foreign;
static void *lc_flusher(void *arg) {
    char path[32];
    snprintf(path, sizeof path, "/tmp/fclose-b%d", (int)(intptr_t)arg);
    while (!lc_stop) {
        int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) continue;
        fflush(NULL);
        off_t size = lseek(fd, 0, SEEK_END);
        if (size != 0) lc_foreign = (int)size;
        close(fd);
        sched_yield();
    }
    return NULL;
}
static int lc_fclose_flush(void) {
    int made = open("/tmp/fclose-a", O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (made < 0) return 1;
    close(made);
    pthread_t flusher[3];
    for (int i = 0; i < 3; i++)
        if (pthread_create(&flusher[i], NULL, lc_flusher, (void *)(intptr_t)i)) return 2;
    for (int round = 0; round < 3000 && !lc_foreign; round++) {
        /* A descriptor open for reading only, with a stream for writing: the
         * flush of "FOREIGN" fails (EBADF) and the bytes stay in the buffer. */
        int fd = open("/tmp/fclose-a", O_RDONLY);
        if (fd < 0) return 3;
        FILE *stream = fdopen(fd, "w");
        if (stream == NULL) return 4;
        fputs("FOREIGN", stream);
        fclose(stream);
    }
    lc_stop = 1;
    for (int i = 0; i < 3; i++) pthread_join(flusher[i], NULL);
    if (lc_foreign) {
        printf("posix-procs: libc: a file got %d bytes of a stream that was closed\n", lc_foreign);
        return 5;
    }
    unlink("/tmp/fclose-a");
    return 0;
}

/* ---- #375: a file that is no program runs with the shell ---- */
static int lc_shell_present(void) {
    if (access("/bin/sh", X_OK) == 0) return 1;
    /* The image has BusyBox under other names: sh is ash by argv[0]. */
    return symlink("/bin/ls", "/bin/sh") == 0 && access("/bin/sh", X_OK) == 0;
}
static int lc_exec_script(int how) {
    if (!lc_shell_present()) return 1;
    mkdir("/tmp/sbin", 0755);
    int fd = open("/tmp/sbin/greet", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) return 2;
    static const char text[] = "echo ran-$0-$1\n";
    if (write(fd, text, sizeof text - 1) != (ssize_t)sizeof text - 1) return 3;
    close(fd);
    if (chmod("/tmp/sbin/greet", 0755)) return 4;
    setenv("PATH", "/tmp/sbin:/bin", 1);
    /* The output goes to a file, which the parent reads. */
    int out = open("/tmp/greet-out", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0 || dup2(out, 1) != 1) return 5;
    if (how == 0) {
        execvp("greet", (char *[]){"greet", "arg", NULL});
    } else if (how == 1) {
        execlp("greet", "greet", "arg", (char *)NULL);
    } else if (how == 2) {
        pid_t pid;
        char *argv[] = {"greet", "arg", NULL};
        if (posix_spawnp(&pid, "greet", NULL, NULL, argv, environ) != 0) return 6;
        int status;
        if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) return 7;
        return 0;
    } else {
        /* execv of the same file stays ENOEXEC. */
        execv("/tmp/sbin/greet", (char *[]){"greet", NULL});
        return errno == ENOEXEC ? 0 : 8;
    }
    return 9;
}
static int lc_exec_in_child(int how) {
    pid_t pid = fork();
    if (pid < 0) return 1;
    if (pid == 0) _exit(lc_exec_script(how));
    int status = lc_wait(pid, 20000);
    if (status != 0) {
        printf("posix-procs: libc: the exec case %d ended with %d\n", how, status);
        return 2;
    }
    if (how == 3) return 0;
    char text[64];
    long got = lc_slurp("/tmp/greet-out", text, sizeof text - 1);
    if (got <= 0) return 3;
    text[got] = 0;
    /* $0 is the file, $1 the first argument after it. */
    if (strstr(text, "ran-/tmp/sbin/greet-arg") == NULL) {
        printf("posix-procs: libc: the script said \"%s\"\n", text);
        return 4;
    }
    return 0;
}
static int lc_execvp_script(void) { return lc_exec_in_child(0); }
static int lc_execlp_script(void) { return lc_exec_in_child(1); }
static int lc_spawnp_script(void) { return lc_exec_in_child(2); }
static int lc_execv_script(void) { return lc_exec_in_child(3); }

/* ---- #376: aio and the timers of SIGEV_THREAD after fork ---- */
static volatile int lc_aio_stop;
static int lc_aio_fd;
static timer_t lc_aio_timer;
/* A thread that submits a request over and over: a request on a descriptor
 * with no lane makes a thread under the lock of the lanes, so that lock is held
 * for a long time, and a fork in that time copies it locked. */
static void *lc_aio_spinner(void *arg) {
    (void)arg;
    static char byte = 'x';
    int mine = dup(lc_aio_fd);
    struct aiocb cb;
    while (!lc_aio_stop && mine >= 0) {
        memset(&cb, 0, sizeof cb);
        cb.aio_fildes = mine;
        cb.aio_buf = &byte;
        cb.aio_nbytes = 1;
        if (aio_write(&cb) != 0) continue;
        while (aio_error(&cb) == EINPROGRESS) sched_yield();
        aio_return(&cb);
        struct itimerspec left;
        timer_gettime(lc_aio_timer, &left);
    }
    return NULL;
}
static void lc_timer_fired(union sigval value) { (void)value; }
static int lc_fork_locks(void) {
    lc_aio_fd = open("/tmp/aio-fork", O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (lc_aio_fd < 0) return 1;
    struct sigevent event;
    memset(&event, 0, sizeof event);
    event.sigev_notify = SIGEV_THREAD;
    event.sigev_notify_function = lc_timer_fired;
    /* A timer on processor time: its helper and timer_gettime read the clock of the
     * process through the layer while they hold the lock of the timer. */
    if (timer_create(CLOCK_PROCESS_CPUTIME_ID, &event, &lc_aio_timer)) return 2;
    struct itimerspec every = {.it_interval = {5, 0}, .it_value = {5, 0}};
    if (timer_settime(lc_aio_timer, 0, &every, NULL)) return 3;
    pthread_t spinner[2];
    for (int i = 0; i < 2; i++)
        if (pthread_create(&spinner[i], NULL, lc_aio_spinner, NULL)) return 4;
    for (int round = 0; round < 200; round++) {
        pid_t child = fork();
        if (child < 0) return 5;
        if (child == 0) {
            struct itimerspec left;
            aio_cancel(lc_aio_fd, NULL);
            timer_gettime(lc_aio_timer, &left);
            _exit(0);
        }
        if (lc_wait(child, 5000) != 0) {
            printf("posix-procs: libc: the child of fork %d did not end with 0\n", round);
            lc_aio_stop = 1;
            return 6;
        }
    }
    lc_aio_stop = 1;
    for (int i = 0; i < 2; i++) pthread_join(spinner[i], NULL);
    return 0;
}

/* ---- #203: stdatomic.h ---- */
static int lc_atomics(void) {
    atomic_int counter = ATOMIC_VAR_INIT(1);
    atomic_store(&counter, 2);
    if (atomic_load(&counter) != 2) return 1;
    if (atomic_exchange(&counter, 3) != 2 || atomic_load(&counter) != 3) return 2;
    int expected = 3;
    if (!atomic_compare_exchange_strong(&counter, &expected, 10) || atomic_load(&counter) != 10) return 3;
    expected = 3;
    if (atomic_compare_exchange_strong(&counter, &expected, 11) || expected != 10) return 4;
    if (atomic_fetch_add(&counter, 5) != 10 || atomic_load(&counter) != 15) return 5;
    if (atomic_fetch_sub(&counter, 4) != 15 || atomic_fetch_or(&counter, 0x100) != 11) return 6;
    if (atomic_fetch_and(&counter, 0xff) != 0x10b || atomic_fetch_xor(&counter, 1) != 11) return 7;
    if (atomic_load_explicit(&counter, memory_order_acquire) != 10) return 8;
    atomic_flag flag = ATOMIC_FLAG_INIT;
    if (atomic_flag_test_and_set(&flag) || !atomic_flag_test_and_set(&flag)) return 9;
    atomic_flag_clear(&flag);
    if (atomic_flag_test_and_set(&flag)) return 10;
    atomic_thread_fence(memory_order_seq_cst);
    atomic_long wide = 1;
    if (atomic_fetch_add_explicit(&wide, 1L << 40, memory_order_relaxed) != 1) return 11;
    return atomic_load(&wide) == (1L << 40) + 1 && atomic_is_lock_free(&wide) ? 0 : 12;
}

/* ---- #285: streams over memory have no descriptor ---- */
static int lc_memory_streams(void) {
    /* Every descriptor is used up: a stream over memory needs none. */
    int used[128], count = 0;
    for (;;) {
        int fd = open("/dev/null", O_RDONLY);
        if (fd < 0) break;
        used[count++] = fd;
        if (count == 128) break;
    }
    int result = 0;
    char buffer[16] = "hello memory";
    FILE *in = fmemopen(buffer, sizeof buffer, "r");
    if (in == NULL) {
        printf("posix-procs: libc: fmemopen with no descriptor left gave errno %d\n", errno);
        result = 1;
        goto end;
    }
    errno = 0;
    if (fileno(in) != -1 || errno != EBADF) result = 2;
    char got[8] = "";
    if (fread(got, 1, 5, in) != 5 || memcmp(got, "hello", 5) != 0) result = 3;
    if (fseek(in, 6, SEEK_SET) != 0 || ftell(in) != 6) result = 4;
    if (fread(got, 1, 6, in) != 6 || memcmp(got, "memory", 6) != 0) result = 5;
    if (fseek(in, -3, SEEK_END) != 0 || ftell(in) != 13) result = 6;
    fclose(in);
    char *text = NULL;
    size_t size = 0;
    FILE *out = open_memstream(&text, &size);
    if (out == NULL) {
        result = 7;
        goto end;
    }
    if (fputs("abc", out) < 0 || fflush(out) != 0 || size != 3 || strcmp(text, "abc") != 0) result = 8;
    /* The size is the position when that is before the end: "aX". */
    if (fseek(out, 1, SEEK_SET) != 0 || fputc('X', out) == EOF || fflush(out) != 0) result = 9;
    if (size != 2 || strcmp(text, "aX") != 0) result = 10;
    if (fseek(out, 0, SEEK_END) != 0 || fputs("def", out) < 0 || fclose(out) != 0) result = 11;
    if (size != 6 || strcmp(text, "aXcdef") != 0) result = 12;
    free(text);
end:
    for (int i = 0; i < count; i++) close(used[i]);
    return result;
}

static void lc_child(const char *what, int (*fn)(void)) {
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        sigset_t none;
        sigemptyset(&none);
        sigprocmask(SIG_SETMASK, &none, NULL);
        int code = fn();
        fflush(stdout);
        _exit(code);
    }
    if (pid < 0) {
        printf("posix-procs: libc: fork for %s gave %d (%s)\n", what, errno, strerror(errno));
        failures++;
        return;
    }
    reap(what, pid, 0, 0);
}

static int libc_role(void) {
    lc_child("exit flushes streams written by two threads in whole lines", lc_exit_whole_lines);
    lc_child("fclose of a stream whose write failed leaves nothing for fflush(NULL)", lc_fclose_flush);
    lc_child("execvp runs a file that is no program with the shell", lc_execvp_script);
    lc_child("execlp runs a file that is no program with the shell", lc_execlp_script);
    lc_child("posix_spawnp runs a file that is no program with the shell", lc_spawnp_script);
    lc_child("execv of a file that is no program stays ENOEXEC", lc_execv_script);
    lc_child("a child of fork does not wait for the locks of aio and of timers", lc_fork_locks);
    lc_child("stdatomic.h in Clang", lc_atomics);
    lc_child("streams over memory use no descriptor", lc_memory_streams);
    if (!failures) printf("posix-procs: libc: exit, fclose, exec of scripts, fork locks, atomics, memory streams ok\n");
    return failures != 0;
}
#endif
