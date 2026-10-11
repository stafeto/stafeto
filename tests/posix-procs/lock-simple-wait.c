/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
/* Included by lifetime.c after the basic public deadlock fixture. */
struct simple_wait_request { int fd, result, error; };
static int simple_wait_done;
static void *simple_wait_worker(void *argument) {
    struct simple_wait_request *request = argument;
    errno = 0;
    request->result = deadlock_lock(request->fd, F_SETLKW, F_WRLCK);
    request->error = errno;
    if (!request->result) deadlock_lock(request->fd, F_SETLK, F_UNLCK);
    __atomic_store_n(&simple_wait_done, 1, __ATOMIC_RELEASE);
    return NULL;
}
static void simple_wait_report(int report, char byte) {
    if (write(report, &byte, 1) != 1) _exit(121);
}
static void simple_wait_expect_byte(int report, char wanted, const char *message) {
    char byte = 0;
    expect(message, deadlock_byte(report, &byte) && byte == wanted, 1);
}
static int simple_wait_pipe(int ends[2]) {
    if (pipe(ends)) { failures++; return 0; }
    expect("bounded multi-edge pipe", fcntl(ends[0], F_SETFL, O_NONBLOCK), 0);
    return 1;
}
static void simple_wait_hold_child(int inherited[3], const char *path, int command,
                                   int report, short type) {
    for (int i = 0; i < 3; i++) if (inherited[i] >= 0) close(inherited[i]);
    int fd = open(path, O_RDWR);
    if (fd < 0 || deadlock_lock(fd, F_SETLK, type)) _exit(122);
    simple_wait_report(report, 'H');
    char byte = 0;
    /* Only the coordinator decides when this non-waiting holder releases. */
    if (read(command, &byte, 1) != 1 || byte != 'Q') _exit(123);
    if (deadlock_lock(fd, F_SETLK, F_UNLCK)) _exit(124);
    close(fd);
    simple_wait_report(report, 'F');
    _exit(0);
}
static void simple_wait_query_child(int inherited[3], const char *a_path,
                                    const char *b_path, const char *d_path,
                                    int command, int report, int two_waiters) {
    for (int i = 0; i < 3; i++) if (inherited[i] >= 0) close(inherited[i]);
    int a = open(a_path, O_RDWR), b = open(b_path, O_RDWR);
    if (a < 0 || b < 0 || deadlock_lock(a, F_SETLK, two_waiters ? F_WRLCK : F_RDLCK)) _exit(125);
    simple_wait_report(report, 'A');
    deadlock_notice_fd = report;
    if (!two_waiters) {
        deadlock_probe_arm();
        int result = deadlock_lock(b, F_SETLKW, F_WRLCK);
        deadlock_probe_disarm();
        if (result || deadlock_lock(b, F_SETLK, F_UNLCK)) _exit(126);
    } else {
        int d = open(d_path, O_RDWR);
        if (d < 0) _exit(127);
        struct simple_wait_request first = {d, 777, 0}, second = {b, 777, 0};
        pthread_t workers[2];
        deadlock_probe_arm();
        if (pthread_create(&workers[0], NULL, simple_wait_worker, &first)) _exit(128);
        char byte = 0;
        if (read(command, &byte, 1) != 1 || byte != 'N') _exit(129);
        deadlock_probe_arm();
        if (pthread_create(&workers[1], NULL, simple_wait_worker, &second)) _exit(130);
        if (pthread_join(workers[0], NULL) || pthread_join(workers[1], NULL)
            || first.result || second.result) _exit(131);
        deadlock_probe_disarm();
        close(d);
    }
    if (deadlock_lock(a, F_SETLK, F_UNLCK)) _exit(132);
    close(a); close(b);
    simple_wait_report(report, 'F');
    _exit(0);
}
static void simple_wait_graph(int two_waiters) {
    char a_path[40], b_path[40], d_path[40];
    snprintf(a_path, sizeof a_path, "/tmp/simple-edge-%d-a", two_waiters);
    snprintf(b_path, sizeof b_path, "/tmp/simple-edge-%d-b", two_waiters);
    snprintf(d_path, sizeof d_path, "/tmp/simple-edge-%d-d", two_waiters);
    int files[3] = {lifecycle_open(a_path), lifecycle_open(b_path), lifecycle_open(d_path)};
    if (files[0] < 0 || files[1] < 0 || files[2] < 0) {
        for (int i = 0; i < 3; i++) if (files[i] >= 0) close(files[i]);
        return;
    }
    expect("multi-edge caller holds B", deadlock_lock(files[1], F_SETLK, F_WRLCK), 0);
    int holder_commands[2], holder_reports[2], query_commands[2], query_reports[2];
    if (pipe(holder_commands) || !simple_wait_pipe(holder_reports)
        || pipe(query_commands) || !simple_wait_pipe(query_reports)) {
        failures++;
        for (int i = 0; i < 3; i++) close(files[i]);
        return;
    }
    pid_t holder = fork();
    if (holder == 0) simple_wait_hold_child(files, two_waiters ? d_path : a_path,
                                          holder_commands[0], holder_reports[1],
                                          two_waiters ? F_WRLCK : F_RDLCK);
    expect("fork first multi-edge holder", holder > 0, 1);
    if (holder < 0) goto finish;
    simple_wait_expect_byte(holder_reports[0], 'H', "first blocker precedes cyclic blocker");
    pid_t query = fork();
    if (query == 0) simple_wait_query_child(files, a_path, b_path, d_path,
                                          query_commands[0], query_reports[1], two_waiters);
    expect("fork cyclic multi-edge owner", query > 0, 1);
    if (query < 0) {
        write(holder_commands[1], "Q", 1);
        reap(holder, 0);
        goto finish;
    }
    simple_wait_expect_byte(query_reports[0], 'A', "cyclic owner publishes A");
    simple_wait_expect_byte(query_reports[0], 'S', "first genuine owner WAIT sleeps");
    if (two_waiters) {
        expect("start second WAIT of same PID", write(query_commands[1], "N", 1), 1);
        simple_wait_expect_byte(query_reports[0], 'S', "second genuine owner WAIT sleeps");
    }
    struct simple_wait_request request = {files[0], 777, 0};
    __atomic_store_n(&simple_wait_done, 0, __ATOMIC_RELEASE);
    pthread_t worker;
    int created = pthread_create(&worker, NULL, simple_wait_worker, &request);
    expect("start cycle-closing WAIT", created, 0);
    if (!created) {
        int finished = deadlock_flag(&simple_wait_done);
        expect("multi-edge cycle resolves before releasing blockers", finished, 1);
        if (finished) {
            expect("multi-edge cycle returns EDEADLK", request.result, -1);
            expect("multi-edge cycle errno", request.error, EDEADLK);
        }
    }
    /* Real unlocks also recover a deliberately broken detector without hanging. */
    expect("release B after cycle verdict", deadlock_lock(files[1], F_SETLK, F_UNLCK), 0);
    expect("release non-cyclic holder", write(holder_commands[1], "Q", 1), 1);
    if (!created && !deadlock_flag(&simple_wait_done)) {
        expect("cycle-closing WAIT finishes after cleanup", 0, 1);
        pthread_kill(worker, SIGUSR1);
        kill(query, SIGKILL);
        kill(holder, SIGKILL);
    }
    if (!created) expect("join cycle-closing WAIT", pthread_join(worker, NULL), 0);
    char completed = 0;
    if (!deadlock_byte(query_reports[0], &completed) || completed != 'F') {
        expect("cyclic owner finishes after real unlock", 0, 1);
        kill(query, SIGKILL);
    }
    if (!deadlock_byte(holder_reports[0], &completed) || completed != 'F') {
        expect("non-cyclic holder finishes after command", 0, 1);
        kill(holder, SIGKILL);
    }
    reap(query, 0); reap(holder, 0);
finish:
    for (int i = 0; i < 3; i++) close(files[i]);
    close(holder_commands[0]); close(holder_commands[1]);
    close(holder_reports[0]); close(holder_reports[1]);
    close(query_commands[0]); close(query_commands[1]);
    close(query_reports[0]); close(query_reports[1]);
    unlink(a_path); unlink(b_path); unlink(d_path);
}
static void public_simple_wait_graphs(void) {
    int before = failures;
    struct sigaction action = {0}, previous;
    action.sa_handler = deadlock_signal;
    sigemptyset(&action.sa_mask);
    expect("install finite multi-edge cancellation signal", sigaction(SIGUSR1, &action, &previous), 0);
    simple_wait_graph(0);
    simple_wait_graph(1);
    expect("restore multi-edge cancellation signal", sigaction(SIGUSR1, &previous, NULL), 0);
    if (failures == before) puts("posix-procs: PID deadlock explores every reader and every waiter ok");
}
