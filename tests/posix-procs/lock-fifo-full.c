/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
/* Genuine 64-entry FIFO followed by a full 64-record inode scan. */
extern int lock_fifo_full_waiters(void);
static int full_fifo_fd;
static pid_t full_fifo_holder;
int lock_fifo_full_control(void) {
    struct flock query = {0};
    query.l_type = F_WRLCK; query.l_whence = SEEK_SET; query.l_len = 127;
    if (fcntl(full_fifo_fd, F_OFD_GETLK, &query) || query.l_type != F_RDLCK
        || query.l_pid != full_fifo_holder || query.l_start != 0 || query.l_len != 1) return 1;
    struct flock set = {0};
    set.l_type = F_RDLCK; set.l_whence = SEEK_SET; set.l_len = 127;
    struct flock before = set;
    errno = 0;
    if (fcntl(full_fifo_fd, F_OFD_SETLK, &set) != -1 || errno != ENOLCK
        || memcmp(&before, &set, sizeof set)) return 2;
    puts("posix-procs: full lock FIFO: 64 compatible queued OFDs, 64 held PID records, GET canonical and SET ENOLCK atomic");
    return 0;
}
static int public_lock_fifo_full(void) {
    int commands[2] = {-1,-1}, replies[2] = {-1,-1};
    int failed = 0;
    full_fifo_holder = -1;
    full_fifo_fd = open("/tmp/lock-fifo-full", O_CREAT | O_EXCL | O_RDWR, 0666);
    if (full_fifo_fd < 0 || pipe(commands) || pipe(replies)) { failed = 1; goto cleanup; }
    full_fifo_holder = fork();
    if (full_fifo_holder == 0) {
        close(commands[1]); close(replies[0]);
        for (unsigned i = 0; i < 64; i++) {
            struct flock lock = {0};
            lock.l_type = F_RDLCK; lock.l_whence = SEEK_SET;
            lock.l_start = 2 * i; lock.l_len = 1;
            if (fcntl(full_fifo_fd, F_SETLK, &lock)) _exit(86);
        }
        char ready = 'r', stop;
        if (write(replies[1], &ready, 1) != 1 || read(commands[0], &stop, 1) != 1) _exit(87);
        _exit(0);
    }
    if (full_fifo_holder < 0) { failed = 1; goto cleanup; }
    close(commands[0]); commands[0] = -1;
    close(replies[1]); replies[1] = -1;
    if (fcntl(replies[0], F_SETFL, O_NONBLOCK)) { failed = 1; goto cleanup; }
    char ready = 0;
    if (pf_receive(replies[0], &ready, 1) || ready != 'r') { failed = 1; goto cleanup; }
    int result = lock_fifo_full_waiters();
    if (result) {
        printf("posix-procs: full lock FIFO failed code=%d errno=%d\n", result, errno);
        failed = 1;
    }
cleanup:
    if (full_fifo_holder > 0) {
        kill(full_fifo_holder, SIGKILL);
        if (pf_wait(full_fifo_holder, 1)) failed = 1;
    }
    if (full_fifo_fd >= 0) close(full_fifo_fd);
    for (unsigned i = 0; i < 2; i++) {
        if (commands[i] >= 0) close(commands[i]);
        if (replies[i] >= 0) close(replies[i]);
    }
    if (unlink("/tmp/lock-fifo-full") && errno != ENOENT) failed = 1;
    return failed;
}
