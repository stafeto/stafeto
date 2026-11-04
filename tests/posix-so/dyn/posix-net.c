// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

/*
 * The checks of the descriptors and sockets of a process that serves many
 * (stage P4a of subproject 6): a table of 1 024 descriptors, the limit,
 * the lowest free number, 1 000 sockets, a fork and an exec with many
 * descriptors, and the buffers of the sockets by their place in the service.
 * Run as a dynamic program of the image with the network service:
 *
 *   posix-net ADDRESS            every check, a line `posix-net: NAME ok` each
 *   posix-net exec-child N...    the image after `exec` in the check `exec-64`:
 *                                every number named is open and does not close
 *                                on exec
 *   posix-net spawn-child FD     the image of the check `spawn-high`: FD is open
 *
 * A failure prints `posix-net: NAME failed: WHAT errno N` and the exit code
 * is 1. Built with -fno-builtin; every result is compared.
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <time.h>
#include <unistd.h>

extern char **environ;
static const char *check = "start";
static const char *self = "/bin/posix-net";

static void fail(const char *what)
{
	printf("posix-net: %s failed: %s errno %d\n", check, what, errno);
	fflush(stdout);
	_exit(1);
}

#define REQUIRE(cond) do { if (!(cond)) fail(#cond); } while (0)

#define LOOPBACK 0x7f000001u

static struct sockaddr_in at(uint32_t ip, int port)
{
	struct sockaddr_in a;
	memset(&a, 0, sizeof a);
	a.sin_family = AF_INET;
	a.sin_port = htons((uint16_t)port);
	a.sin_addr.s_addr = htonl(ip);
	return a;
}

static long now_ms(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

/* A listener on the loopback and a port of the service's choosing. */
static int listener(int backlog, int *port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	REQUIRE(fd >= 0);
	struct sockaddr_in a = at(LOOPBACK, 0);
	REQUIRE(bind(fd, (struct sockaddr *)&a, sizeof a) == 0);
	REQUIRE(listen(fd, backlog) == 0);
	socklen_t len = sizeof a;
	REQUIRE(getsockname(fd, (struct sockaddr *)&a, &len) == 0);
	*port = ntohs(a.sin_port);
	return fd;
}

/* One connection on the loopback through `lis`: the two ends. */
static void pair(int lis, int port, int *client, int *server)
{
	int c = socket(AF_INET, SOCK_STREAM, 0);
	REQUIRE(c >= 0);
	struct sockaddr_in a = at(LOOPBACK, port);
	REQUIRE(connect(c, (struct sockaddr *)&a, sizeof a) == 0);
	int s = accept(lis, NULL, NULL);
	REQUIRE(s >= 0);
	*client = c;
	*server = s;
}

/* A byte each way, both read. */
static void exchange(int c, int s, char tag)
{
	char got = 0;
	REQUIRE(send(c, &tag, 1, 0) == 1);
	REQUIRE(recv(s, &got, 1, 0) == 1 && got == tag);
	char back = (char)(tag ^ 0x55);
	REQUIRE(send(s, &back, 1, 0) == 1);
	REQUIRE(recv(c, &got, 1, 0) == 1 && got == back);
}

static int wait_exit(pid_t child)
{
	int status = 0;
	REQUIRE(waitpid(child, &status, 0) == child);
	REQUIRE(WIFEXITED(status));
	return WEXITSTATUS(status);
}

/* Closes the descriptors from `first` up that this program opened. */
static void close_from(int first)
{
	for (int fd = first; fd < 1024; fd++)
		close(fd);
}

/* The limit as getrlimit and sysconf say it, and a hard limit that only the
 * privileged may raise. */
static void limits(void)
{
	struct rlimit r;
	REQUIRE(getrlimit(RLIMIT_NOFILE, &r) == 0);
	REQUIRE(r.rlim_cur == 1024 && r.rlim_max == 1024);
	REQUIRE(sysconf(_SC_OPEN_MAX) == (long)r.rlim_cur);
	pid_t child = fork();
	REQUIRE(child >= 0);
	if (child == 0) {
		if (setgid(1000) != 0 || setuid(1000) != 0)
			_exit(2);
		struct rlimit up = { 1024, 2048 };
		errno = 0;
		if (setrlimit(RLIMIT_NOFILE, &up) != -1 || errno != EPERM)
			_exit(3);
		_exit(0);
	}
	REQUIRE(wait_exit(child) == 0);
}

/* A soft limit of 100: the hundred and first descriptor is refused. */
static void nofile_low(void)
{
	struct rlimit saved, low;
	REQUIRE(getrlimit(RLIMIT_NOFILE, &saved) == 0);
	low = saved;
	low.rlim_cur = 100;
	REQUIRE(setrlimit(RLIMIT_NOFILE, &low) == 0);
	int made = 3;
	for (;;) {
		int fd = dup(1);
		if (fd < 0)
			break;
		REQUIRE(fd == made);
		made++;
		REQUIRE(made <= 101);
	}
	REQUIRE(errno == EMFILE);
	REQUIRE(made == 100);
	for (int fd = 3; fd < made; fd++)
		REQUIRE(close(fd) == 0);
	REQUIRE(setrlimit(RLIMIT_NOFILE, &saved) == 0);
}

/* 1 000 descriptors and the one at 1 023: the lowest free number each time. */
static void fds_1000(void)
{
	for (int i = 0; i < 1000; i++)
		REQUIRE(dup(1) == 3 + i);
	REQUIRE(dup2(1, 1023) == 1023);
	REQUIRE(dup(1) == 1003);
	REQUIRE(close(500) == 0);
	REQUIRE(dup(1) == 500);
	REQUIRE(close(1003) == 0);
	REQUIRE(close(3) == 0);
	REQUIRE(dup(1) == 3);
	/* The table is full up to its limit but for the numbers between. */
	for (int fd = 1004; fd < 1023; fd++)
		REQUIRE(dup2(1, fd) == fd);
	REQUIRE(dup(1) == 1003);
	errno = 0;
	REQUIRE(dup(1) == -1 && errno == EMFILE);
	errno = 0;
	REQUIRE(dup2(1, 1024) == -1 && errno == EBADF);
	close_from(3);
}

/* 500 connections on the loopback: 1 000 sockets alive at once. */
static void sockets_1000(void)
{
	int port;
	int lis = listener(8, &port);
	static int client[500], server[500];
	for (int i = 0; i < 500; i++)
		pair(lis, port, &client[i], &server[i]);
	for (int i = 0; i < 500; i++)
		exchange(client[i], server[i], (char)('a' + i % 26));
	/* All of them are alive after the traffic of the others. */
	for (int i = 0; i < 500; i += 7)
		exchange(server[i], client[i], (char)('A' + i % 26));
	for (int i = 0; i < 500; i++) {
		REQUIRE(close(client[i]) == 0);
		REQUIRE(close(server[i]) == 0);
	}
	REQUIRE(close(lis) == 0);
}

/* A fork of a process with 900 descriptors: the child has them all, and
 * writes into pairs whose descriptors are beyond the first 64. */
static void fork_900(void)
{
	int port;
	int lis = listener(8, &port);
	static int client[100], server[100];
	for (int i = 0; i < 100; i++)
		pair(lis, port, &client[i], &server[i]);
	int used = 3 + 1 + 200;
	int copies = 900 - used;
	for (int i = 0; i < copies; i++)
		REQUIRE(dup(client[0]) >= 0);
	/* The pairs the child writes into: the last ones, far past 64. */
	long began = now_ms();
	pid_t child = fork();
	REQUIRE(child >= 0);
	if (child == 0) {
		int bad = 0;
		for (int fd = 0; fd < 900; fd++)
			if (fcntl(fd, F_GETFD) < 0)
				bad++;
		if (bad != 0)
			_exit(2);
		for (int i = 90; i < 100; i++) {
			char b = (char)('0' + i % 10);
			if (send(client[i], &b, 1, 0) != 1)
				_exit(3);
		}
		_exit(0);
	}
	/* The child ends first, so a child that lacks the descriptors fails at its
	 * exit status. */
	REQUIRE(wait_exit(child) == 0);
	long took = now_ms() - began;
	for (int i = 90; i < 100; i++) {
		char got = 0;
		REQUIRE(recv(server[i], &got, 1, 0) == 1 && got == (char)('0' + i % 10));
	}
	printf("posix-net: fork-900 took %ld ms\n", took);
	close_from(3);
}

/* Descriptors with FD_CLOFORK are not the child's, whatever their number. */
static void clofork_many(void)
{
	int made[500];
	for (int i = 0; i < 500; i++) {
		made[i] = dup(1);
		REQUIRE(made[i] >= 0);
		REQUIRE(fcntl(made[i], F_SETFD, FD_CLOFORK) == 0);
	}
	int keep = dup(1);
	REQUIRE(keep >= 0);
	pid_t child = fork();
	REQUIRE(child >= 0);
	if (child == 0) {
		for (int i = 0; i < 500; i++) {
			errno = 0;
			if (fcntl(made[i], F_GETFD) != -1 || errno != EBADF)
				_exit(2);
		}
		if (fcntl(keep, F_GETFD) < 0)
			_exit(3);
		_exit(0);
	}
	REQUIRE(wait_exit(child) == 0);
	close_from(3);
}

/* The new image of `exec-64`: the numbers are open, and none closes on exec. */
static int exec_child(int argc, char **argv)
{
	check = "exec-child";
	for (int i = 2; i < argc; i++) {
		int fd = atoi(argv[i]);
		int flags = fcntl(fd, F_GETFD);
		REQUIRE(flags >= 0);
		REQUIRE((flags & FD_CLOEXEC) == 0);
	}
	return 0;
}

/* More than 64 descriptors that stay open across an exec: ENOMEM and the
 * process is whole; 64, with numbers up to 1 000: the new image has them. */
static void exec_64(void)
{
	/* 65 without FD_CLOEXEC: the three of the console and 62 copies. */
	for (int i = 0; i < 62; i++)
		REQUIRE(dup(1) == 3 + i);
	char *plain[] = { (char *)self, (char *)"none", NULL };
	errno = 0;
	REQUIRE(execve(self, plain, environ) == -1 && errno == ENOMEM);
	for (int fd = 0; fd < 65; fd++)
		REQUIRE(fcntl(fd, F_GETFD) >= 0);
	close_from(3);
	/* 65 different sockets: the table holds 64 of them for a call, and exec
	 * still answers ENOMEM with every descriptor alive. */
	for (int i = 0; i < 65; i++)
		REQUIRE(socket(AF_INET, SOCK_DGRAM, 0) == 3 + i);
	errno = 0;
	REQUIRE(execve(self, plain, environ) == -1 && errno == ENOMEM);
	for (int fd = 3; fd < 68; fd++)
		REQUIRE(fcntl(fd, F_GETFD) >= 0);
	close_from(3);
	/* 64: the console's three and 61 numbers spread up to 976. */
	char *args[70];
	char text[61][8];
	args[0] = (char *)self;
	args[1] = (char *)"exec-child";
	int argn = 2;
	for (int i = 1; i <= 61; i++) {
		int fd = i * 16;
		REQUIRE(dup2(1, fd) == fd);
		snprintf(text[i - 1], sizeof text[0], "%d", fd);
		args[argn++] = text[i - 1];
	}
	args[argn] = NULL;
	/* Others with FD_CLOEXEC do not count. */
	for (int i = 0; i < 200; i++) {
		int fd = dup(1);
		REQUIRE(fd >= 0);
		REQUIRE(fcntl(fd, F_SETFD, FD_CLOEXEC) == 0);
	}
	pid_t child = fork();
	REQUIRE(child >= 0);
	if (child == 0) {
		execve(self, args, environ);
		_exit(127);
	}
	REQUIRE(wait_exit(child) == 0);
	close_from(3);
}

static int spawn_child(int fd)
{
	check = "spawn-child";
	int flags = fcntl(fd, F_GETFD);
	REQUIRE(flags >= 0);
	char b = 'x';
	REQUIRE(write(fd, &b, 1) == 1);
	return 0;
}

/* posix_spawn with an action that puts a descriptor at number 900. */
static void spawn_high(void)
{
	int fds[2];
	REQUIRE(pipe(fds) == 0);
	posix_spawn_file_actions_t a;
	REQUIRE(posix_spawn_file_actions_init(&a) == 0);
	REQUIRE(posix_spawn_file_actions_adddup2(&a, fds[1], 900) == 0);
	char number[] = "900";
	char *args[] = { (char *)self, (char *)"spawn-child", number, NULL };
	pid_t child;
	REQUIRE(posix_spawn(&child, self, &a, NULL, args, environ) == 0);
	char got = 0;
	REQUIRE(read(fds[0], &got, 1) == 1 && got == 'x');
	REQUIRE(wait_exit(child) == 0);
	posix_spawn_file_actions_destroy(&a);
	close(fds[0]);
	close(fds[1]);
}

/* The sockets of the first 256 places of the service have the full buffers;
 * those past them have 4 KiB. Places are given from the lowest, so the check
 * runs before the sockets of the others fill the table (a closed stream keeps
 * its place for a while). */
static void rcvbuf_tiers(void)
{
	int fds[300];
	for (int i = 0; i < 300; i++) {
		fds[i] = socket(AF_INET, SOCK_DGRAM, 0);
		REQUIRE(fds[i] >= 0);
	}
	int value = 0;
	socklen_t len = sizeof value;
	REQUIRE(getsockopt(fds[0], SOL_SOCKET, SO_RCVBUF, &value, &len) == 0);
	REQUIRE(value >= 16384);
	len = sizeof value;
	REQUIRE(getsockopt(fds[299], SOL_SOCKET, SO_RCVBUF, &value, &len) == 0);
	REQUIRE(value == 4096);
	len = sizeof value;
	REQUIRE(getsockopt(fds[299], SOL_SOCKET, SO_SNDBUF, &value, &len) == 0);
	REQUIRE(value == 4096);
	for (int i = 0; i < 300; i++)
		REQUIRE(close(fds[i]) == 0);
}

/* 700 datagram sockets bound to port 0 take 700 ports in a row; then 100
 * binds of port 0 and 100 connects to other ports (each end has its own place
 * in the range) all find a free port, though the service tries 64 candidates
 * of its own before it looks for a free one. */
static void ephemeral_block(void)
{
	static int held[700];
	for (int i = 0; i < 700; i++) {
		held[i] = socket(AF_INET, SOCK_DGRAM, 0);
		REQUIRE(held[i] >= 0);
		struct sockaddr_in a = at(LOOPBACK, 0);
		REQUIRE(bind(held[i], (struct sockaddr *)&a, sizeof a) == 0);
	}
	static int more[200];
	for (int i = 0; i < 100; i++) {
		more[i] = socket(AF_INET, SOCK_DGRAM, 0);
		REQUIRE(more[i] >= 0);
		struct sockaddr_in a = at(LOOPBACK, 0);
		REQUIRE(bind(more[i], (struct sockaddr *)&a, sizeof a) == 0);
	}
	for (int i = 100; i < 200; i++) {
		more[i] = socket(AF_INET, SOCK_DGRAM, 0);
		REQUIRE(more[i] >= 0);
		struct sockaddr_in a = at(LOOPBACK, 9000 + 7 * i);
		REQUIRE(connect(more[i], (struct sockaddr *)&a, sizeof a) == 0);
	}
	for (int i = 0; i < 200; i++)
		REQUIRE(close(more[i]) == 0);
	for (int i = 0; i < 700; i++)
		REQUIRE(close(held[i]) == 0);
}

/* A server that restarts: with 450 accepted connections on its port, a new
 * socket with SO_REUSEADDR binds the port the listener left. */
static void bind_reuse_accepted(void)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	REQUIRE(fd >= 0);
	int one = 1;
	REQUIRE(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) == 0);
	struct sockaddr_in a = at(LOOPBACK, 0);
	REQUIRE(bind(fd, (struct sockaddr *)&a, sizeof a) == 0);
	REQUIRE(listen(fd, 8) == 0);
	socklen_t len = sizeof a;
	REQUIRE(getsockname(fd, (struct sockaddr *)&a, &len) == 0);
	int port = ntohs(a.sin_port);
	static int client[450], server[450];
	for (int i = 0; i < 450; i++)
		pair(fd, port, &client[i], &server[i]);
	REQUIRE(close(fd) == 0);
	int again = socket(AF_INET, SOCK_STREAM, 0);
	REQUIRE(again >= 0);
	REQUIRE(setsockopt(again, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) == 0);
	struct sockaddr_in b = at(LOOPBACK, port);
	REQUIRE(bind(again, (struct sockaddr *)&b, sizeof b) == 0);
	REQUIRE(listen(again, 8) == 0);
	REQUIRE(close(again) == 0);
	for (int i = 0; i < 450; i++) {
		REQUIRE(close(client[i]) == 0);
		REQUIRE(close(server[i]) == 0);
	}
}

static const struct {
	const char *name;
	void (*run)(void);
} CHECKS[] = {
	{ "limits", limits },
	{ "nofile-low", nofile_low },
	{ "rcvbuf-tiers", rcvbuf_tiers },
	{ "fds-1000", fds_1000 },
	{ "fork-900", fork_900 },
	{ "clofork-many", clofork_many },
	{ "exec-64", exec_64 },
	{ "spawn-high", spawn_high },
	{ "sockets-1000", sockets_1000 },
	{ "ephemeral-block", ephemeral_block },
	{ "bind-reuse-accepted", bind_reuse_accepted },
};

int main(int argc, char **argv)
{
	if (argc >= 2 && strcmp(argv[1], "exec-child") == 0)
		return exec_child(argc, argv);
	if (argc >= 3 && strcmp(argv[1], "spawn-child") == 0)
		return spawn_child(atoi(argv[2]));
	if (argc != 2) {
		printf("posix-net: usage: posix-net ADDRESS\n");
		return 2;
	}
	int count = (int)(sizeof CHECKS / sizeof CHECKS[0]);
	for (int i = 0; i < count; i++) {
		check = CHECKS[i].name;
		CHECKS[i].run();
		printf("posix-net: %s ok\n", CHECKS[i].name);
		fflush(stdout);
	}
	printf("posix-net: %d checks ok\n", count);
	return 0;
}
