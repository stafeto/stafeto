/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
/* Included by tty.c for a quiet measurement with sixteen live clients. */
extern int stafeto_terminal_control_stats(void);
extern int stafeto_terminal_controlling(int fd);

static int quiet_controls(int fd, pid_t group, pid_t sid, int leader) {
    if (leader) CHECK(ioctl(fd, TIOCSCTTY, 0) == 0);
    else {
        errno = 0;
        CHECK(ioctl(fd, TIOCSCTTY, 0) == -1 && errno == EPERM);
    }
    CHECK(tcsetpgrp(fd, group) == 0);
    CHECK(tcgetpgrp(fd) == group && tcgetsid(fd) == sid);
    CHECK(stafeto_terminal_controlling(fd) == 0);
    int current = open("/dev/tty", O_RDWR | O_NOCTTY);
    CHECK(current >= 0 && close(current) == 0);
    return 0;
}

static int quiet_leader(void) {
    CHECK(setsid() == getpid());
    CHECK(signal(SIGHUP, SIG_IGN) != SIG_ERR);
    int master = posix_openpt(O_RDWR | O_NOCTTY);
    CHECK(master >= 0 && grantpt(master) == 0 && unlockpt(master) == 0);
    char name[64];
    CHECK(ptsname_r(master, name, sizeof name) == 0);
    int slave = open(name, O_RDWR | O_NOCTTY);
    CHECK(slave >= 0);
    /* Eight waiting readers per pipe: two gates for fifteen workers. */
    int ready[2], start[2][2], done[2][2];
    CHECK(pipe(ready) == 0);
    for (int i = 0; i < 2; ++i) CHECK(pipe(start[i]) == 0 && pipe(done[i]) == 0);
    pid_t children[15], group = getpgrp(), sid = getsid(0);
    for (int phase = 0; phase < 2; ++phase) {
        for (int i = 0; i < 15; ++i) {
            children[i] = fork();
            CHECK(children[i] >= 0);
            if (children[i] == 0) {
                int fd = open(name, O_RDWR | O_NOCTTY);
                if (fd < 0 || write(ready[1], "r", 1) != 1) _exit(41);
                char byte;
                if (read(start[i / 8][0], &byte, 1) != 1) _exit(42);
                int result;
                if (phase == 0) {
                    /* The accepted late-attach rule preserves these members' None. */
                    errno = 0;
                    result = !(ioctl(fd, TIOCSCTTY, 0) == -1 && errno == EPERM);
                    errno = 0;
                    result |= !(tcgetsid(fd) == -1 && errno == ENOTTY);
                } else result = quiet_controls(fd, group, sid, 0);
                if (write(ready[1], result ? "e" : "d", 1) != 1 || read(done[i / 8][0], &byte, 1) != 1) _exit(44);
                _exit(result ? 43 : 0);
            }
        }
        char byte;
        for (int i = 0; i < 15; ++i) CHECK(read(ready[0], &byte, 1) == 1 && byte == 'r');
        /* The first Acquire has its complete service effect with all clients live. */
        CHECK(ioctl(slave, TIOCSCTTY, 0) == 0 && tcgetsid(slave) == getpid());
        /* Every worker remains alive until after all maxima have been read. */
        for (int i = 0; i < 15; ++i) CHECK(write(start[i / 8][1], "s", 1) == 1);
        for (int i = 0; i < 15; ++i) CHECK(read(ready[0], &byte, 1) == 1 && byte == 'd');
        CHECK(quiet_controls(slave, group, sid, 1) == 0);
        if (phase == 1) CHECK(stafeto_terminal_control_stats() == 0);
        for (int i = 0; i < 15; ++i) CHECK(write(done[i / 8][1], "x", 1) == 1);
        for (int i = 0; i < 15; ++i) {
            int status;
            CHECK(waitpid(children[i], &status, 0) == children[i]);
            CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        }
    }
    for (int i = 0; i < 2; ++i) {
        CHECK(close(ready[i]) == 0);
        for (int gate = 0; gate < 2; ++gate) CHECK(close(start[gate][i]) == 0 && close(done[gate][i]) == 0);
    }
    CHECK(close(slave) == 0 && close(master) == 0);
    say("posix-tty: quiet controls sixteen clients ok\n");
    return 0;
}

static int quiet_run(void) {
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) _exit(quiet_leader());
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status));
    return WEXITSTATUS(status);
}
