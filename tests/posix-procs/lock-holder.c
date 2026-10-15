/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
/* Included by lifetime.c after lock-simple-wait.c. */
struct holder_upgrade { int fd, result, error; };
static int holder_done;
static void *holder_upgrade_worker(void *argument) {
    struct holder_upgrade *request = argument;
    errno = 0;
    request->result = deadlock_lock(request->fd, F_SETLKW, F_WRLCK);
    request->error = errno;
    __atomic_store_n(&holder_done, 1, __ATOMIC_RELEASE);
    return NULL;
}
static void holder_writer_child(int inherited, const char *path, int report, int ofd) {
    close(inherited);
    int fd = open(path, O_RDWR);
    if (fd < 0) _exit(141);
    deadlock_notice_fd = report;
    deadlock_probe_arm();
    int result = deadlock_lock(fd, ofd ? 38 : F_SETLKW, F_WRLCK);
    deadlock_probe_disarm();
    if (result) _exit(142);
    simple_wait_report(report, 'D');
    if (deadlock_lock(fd, ofd ? 37 : F_SETLK, F_UNLCK)) _exit(143);
    close(fd);
    _exit(0);
}
static void holder_case(int ofd, int third_reader) {
    char path[40];
    snprintf(path, sizeof path, "/tmp/holder-%d-%d", ofd, third_reader);
    int fd = lifecycle_open(path);
    if (fd < 0) return;
    expect("holder acquires initial reader", deadlock_lock(fd, F_SETLK, F_RDLCK), 0);
    int reports[2], commands[2], third_reports[2], upgrade_reports[2];
    if (!simple_wait_pipe(reports) || pipe(commands)
        || !simple_wait_pipe(third_reports) || !simple_wait_pipe(upgrade_reports)) {
        failures++;
        close(fd);
        unlink(path);
        return;
    }
    pid_t third = -1;
    if (third_reader) {
        third = fork();
        if (!third) {
            int inherited[3] = {fd, -1, -1};
            simple_wait_hold_child(inherited, path, commands[0], third_reports[1], F_RDLCK);
        }
        expect("fork independent reader", third > 0, 1);
        if (third > 0) simple_wait_expect_byte(third_reports[0], 'H', "independent reader holds before writer");
    }
    pid_t writer = fork();
    if (!writer) holder_writer_child(fd, path, reports[1], ofd);
    expect("fork queued holder-test writer", writer > 0, 1);
    if (writer > 0) simple_wait_expect_byte(reports[0], 'S', "writer genuinely sleeps behind held reader");
    struct flock query = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_len = 1};
    expect("holder GETLK examines held locks", fcntl(fd, F_GETLK, &query), 0);
    expect("holder GETLK ignores queued writer", query.l_type, third_reader ? F_RDLCK : F_UNLCK);
    expect("holder repeat remains compatible", deadlock_lock(fd, F_SETLK, F_RDLCK), 0);
    struct flock extension = {.l_type = F_RDLCK, .l_whence = SEEK_SET, .l_len = 2};
    expect("holder extends reader past queued writer", fcntl(fd, F_SETLK, &extension), 0);
    if (!third_reader) {
        expect("nonblocking holder upgrade ignores queue", deadlock_lock(fd, F_SETLK, F_WRLCK), 0);
        expect("holder downgrades before blocking upgrade", deadlock_lock(fd, F_SETLK, F_RDLCK), 0);
    }
    struct holder_upgrade request = {fd, 777, 0};
    __atomic_store_n(&holder_done, 0, __ATOMIC_RELEASE);
    deadlock_notice_fd = upgrade_reports[1];
    if (third_reader) deadlock_probe_arm();
    pthread_t worker;
    int created = pthread_create(&worker, NULL, holder_upgrade_worker, &request);
    expect("start blocking holder conversion", created, 0);
    if (third_reader && third > 0) {
        if (!created) simple_wait_expect_byte(upgrade_reports[0], 'S', "conversion sleeps on independent held reader");
        expect("release independent held reader", write(commands[1], "Q", 1), 1);
        simple_wait_expect_byte(third_reports[0], 'F', "independent held reader releases");
        reap(third, 0);
    }
    if (!created) {
        int done = deadlock_flag(&holder_done);
        expect("holder conversion finishes while writer remains queued", done, 1);
        if (done) {
            expect("holder conversion succeeds", request.result, 0);
            expect("successful conversion errno", request.error, 0);
        }
        char byte;
        errno = 0;
        expect("writer has not acquired before holder unlock", read(reports[0], &byte, 1), -1);
        expect("writer report remains pending", errno, EAGAIN);
        if (!done) {
            if (writer > 0) kill(writer, SIGKILL);
            pthread_kill(worker, SIGUSR1);
        }
        expect("release converted holder", deadlock_lock(fd, F_SETLK, F_UNLCK), 0);
        expect("join bounded holder conversion", pthread_join(worker, NULL), 0);
        deadlock_probe_disarm();
        if (!done && writer > 0) { reap(writer, 1); writer = -1; }
    } else deadlock_lock(fd, F_SETLK, F_UNLCK);
    if (writer > 0) {
        char byte = 0;
        int completed = deadlock_byte(reports[0], &byte) && byte == 'D';
        expect("queued writer completes after holder unlock", completed, 1);
        if (!completed) kill(writer, SIGKILL);
        reap(writer, !completed);
    }
    deadlock_notice_fd = -1;
    close(fd);
    close(reports[0]); close(reports[1]);
    close(commands[0]); close(commands[1]);
    close(third_reports[0]); close(third_reports[1]);
    close(upgrade_reports[0]); close(upgrade_reports[1]);
    unlink(path);
}
extern int record_locks_none(void);
/* The close of an alias asks the service only while the process may hold a record lock. */
static void holder_warm_alias_closes(int fd) {
    for (int i = 0; i < 2; i++) {
        int alias = dup(fd);
        if (alias < 0 || close(alias)) failures++;
    }
}
/* A second process takes the write lock on the file: 0 when it is free. */
static int holder_rival_locks(const char *path) {
    pid_t rival = fork();
    if (!rival) {
        int fd = open(path, O_RDWR);
        _exit(fd < 0 ? 2 : deadlock_lock(fd, F_SETLK, F_WRLCK) ? 1 : 0);
    }
    int status = -1;
    if (rival < 0 || waitpid(rival, &status, 0) != rival || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}
static void holder_alias_knowledge(void) {
    const char *path = "/tmp/holder-knowledge";
    int fd = lifecycle_open(path);
    if (fd < 0) return;
    holder_warm_alias_closes(fd);
    expect("alias closes learn that no record lock is held", record_locks_none(), 1);
    expect("lock command takes a record lock", deadlock_lock(fd, F_SETLK, F_WRLCK), 0);
    expect("lock command forgets that none is held", record_locks_none(), 0);
    expect("rival is refused while the lock is held", holder_rival_locks(path), 1);
    int alias = dup(fd);
    expect("alias for the lock release", alias >= 0, 1);
    expect("close of an alias asks the service and releases the lock", close(alias), 0);
    expect("rival takes the file once the alias is closed", holder_rival_locks(path), 0);
    holder_warm_alias_closes(fd);
    expect("alias closes learn it again after the release", record_locks_none(), 1);
    /* A lock on another file keeps the answer "not none" through closes of aliases of this one. */
    const char *other_path = "/tmp/holder-knowledge-other";
    int other = lifecycle_open(other_path);
    if (other >= 0) {
        expect("lock on the other file", deadlock_lock(other, F_SETLK, F_WRLCK), 0);
        holder_warm_alias_closes(fd);
        expect("a lock on another file keeps the process asking", record_locks_none(), 0);
        int other_alias = dup(other);
        expect("alias of the other file", other_alias >= 0, 1);
        expect("close of its alias releases its lock", close(other_alias), 0);
        expect("rival takes the other file", holder_rival_locks(other_path), 0);
        close(other);
        unlink(other_path);
    }
    close(fd);
    unlink(path);
}
static void holder_close_case(int replacement) {
    const char *path = replacement ? "/tmp/holder-dup2-a" : "/tmp/holder-alias-a";
    int fd = lifecycle_open(path), other = lifecycle_open("/tmp/holder-dup2-b");
    if (fd < 0 || other < 0) {
        if (fd >= 0) close(fd);
        if (other >= 0) close(other);
        return;
    }
    holder_warm_alias_closes(fd);
    int alias = dup(fd), reports[2];
    expect("retain alias for public close release", alias >= 0, 1);
    if (alias < 0 || !simple_wait_pipe(reports)) { close(fd); close(other); return; }
    expect("parent PID owns lock before alias close", deadlock_lock(fd, F_SETLK, F_WRLCK), 0);
    pid_t writer = fork();
    if (!writer) {
        close(alias); close(other);
        holder_writer_child(fd, path, reports[1], 0);
    }
    expect("fork actual waiter for alias close", writer > 0, 1);
    if (writer > 0) simple_wait_expect_byte(reports[0], 'S', "actual waiter sleeps before alias close");
    if (replacement) {
        expect("dup2 replacement closes target inode", dup2(other, fd), fd);
    } else {
        expect("ordinary alias close releases PID locks", close(alias), 0);
        alias = -1;
    }
    if (writer > 0) {
        char byte = 0;
        int completed = deadlock_byte(reports[0], &byte) && byte == 'D';
        expect("alias close wakes genuine PID waiter", completed, 1);
        if (!completed) kill(writer, SIGKILL);
        reap(writer, !completed);
    }
    if (alias >= 0) close(alias);
    close(fd); close(other);
    close(reports[0]); close(reports[1]);
    unlink(path); unlink("/tmp/holder-dup2-b");
}
static void public_lock_holders(void) {
    int before = failures;
    struct sigaction action = {0}, previous;
    action.sa_handler = deadlock_signal;
    sigemptyset(&action.sa_mask);
    expect("install holder conversion cancellation", sigaction(SIGUSR1, &action, &previous), 0);
    holder_case(0, 0);
    holder_case(1, 0);
    holder_case(0, 1);
    holder_alias_knowledge();
    holder_close_case(1);
    holder_close_case(0);
    expect("restore holder conversion signal", sigaction(SIGUSR1, &previous, NULL), 0);
    if (failures == before) puts("posix-procs: holder conversions bypass queued PID and OFD writers ok");
}
