// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

/*
 * The checks of the descriptors and sockets of a process that serves many
 * (stage P4a of subproject 6): a table of 1 024 descriptors, the limit,
 * the lowest free number, 1 000 sockets, a fork and an exec with many
 * descriptors, and the buffers of the sockets by their place in the service;
 * epoll, and poll and select over more than 64 descriptors.
 * Run as a dynamic program of the image with the network service:
 *
 *   posix-net ADDRESS            every check, a line `posix-net: NAME ok` each
 *   posix-net ADDRESS NAME       the one check NAME (to find the cause of a failure)
 *   posix-net exec-child N...    the image after `exec` in the check `exec-64`:
 *                                every number named is open and does not close
 *                                on exec
 *   posix-net spawn-child FD     the image of the check `spawn-high`: FD is open
 *   posix-net epoll-child FD     the image of the check `epoll-exec`: FD is not open
 *   posix-net buffer-exec-child N the image of the check `buffer-exec`: the
 *                                service holds N shared buffers
 *   posix-net stat               the shared buffers of the network service
 *   posix-net readfile PATH N    N reads of the file PATH by pread in 32 KiB
 *                                pieces: the time of one read of the file
 *
 * A failure prints `posix-net: NAME failed: WHAT errno N` and the exit code
 * is 1. Built with -fno-builtin; every result is compared.
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <time.h>
#include <unistd.h>
#include <stafeto/fast.h>

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

static void pause_ms(long ms)
{
	struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
	nanosleep(&t, NULL);
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
	if (WEXITSTATUS(status) != 0)
		printf("posix-net: %s note: a child ended with %d\n", check, WEXITSTATUS(status));
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

/* ------------------------------------------------------------------ epoll */

static void nonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL);
	REQUIRE(flags >= 0);
	REQUIRE(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
}

static int ep_new(void)
{
	int ep = epoll_create1(0);
	REQUIRE(ep >= 0);
	return ep;
}

static void ep_do(int ep, int op, int fd, uint32_t events, uint64_t data)
{
	struct epoll_event e;
	memset(&e, 0, sizeof e);
	e.events = events;
	e.data.u64 = data;
	REQUIRE(epoll_ctl(ep, op, fd, &e) == 0);
}

static void ep_add(int ep, int fd, uint32_t events, uint64_t data)
{
	ep_do(ep, EPOLL_CTL_ADD, fd, events, data);
}

/* The events of one wait; at most 64 of them come at once. */
static int ep_wait(int ep, struct epoll_event *out, int ms)
{
	return epoll_wait(ep, out, 64, ms);
}

/* Reads until the descriptor has nothing (EAGAIN). */
static void drain(int fd)
{
	char buf[256];
	for (;;) {
		ssize_t n = read(fd, buf, sizeof buf);
		if (n < 0) {
			REQUIRE(errno == EAGAIN);
			return;
		}
		REQUIRE(n > 0);
	}
}

/* Waits for `want` events in all, each token once (a token is below `size`);
 * `seen` counts the tokens. Fails after `ms`. */
static void collect(int ep, int want, unsigned char *seen, int size, int ms)
{
	struct epoll_event ev[64];
	int total = 0;
	long end = now_ms() + ms;
	while (total < want) {
		long left = end - now_ms();
		if (left <= 0) {
			printf("posix-net: %s failed: %d of %d events came\n", check, total, want);
			for (int i = 0; i < size; i++)
				if (!seen[i])
					printf("posix-net: missing %d\n", i);
			fflush(stdout);
		}
		REQUIRE(left > 0);
		int n = ep_wait(ep, ev, (int)left);
		REQUIRE(n >= 0);
		for (int i = 0; i < n; i++) {
			uint64_t token = ev[i].data.u64;
			REQUIRE(token < (uint64_t)size);
			REQUIRE(seen[token] == 0);
			seen[token] = 1;
			total++;
		}
	}
	REQUIRE(total == want);
}

static void epoll_basic(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	int ep = epoll_create1(EPOLL_CLOEXEC);
	REQUIRE(ep >= 0);
	REQUIRE((fcntl(ep, F_GETFD) & FD_CLOEXEC) != 0);
	struct stat st;
	REQUIRE(fstat(ep, &st) == 0 && (st.st_mode & 0777) == 0600);
	struct epoll_event ev[64];
	ep_add(ep, s, EPOLLIN, 41);
	ep_add(ep, c, EPOLLOUT, 42);
	/* The client is writable at once, the server has nothing to read. */
	REQUIRE(ep_wait(ep, ev, 0) == 1);
	REQUIRE(ev[0].data.u64 == 42 && (ev[0].events & EPOLLOUT));
	REQUIRE(send(c, "a", 1, 0) == 1);
	int n = ep_wait(ep, ev, 2000);
	REQUIRE(n >= 1);
	int found = 0;
	for (int i = 0; i < n; i++)
		if (ev[i].data.u64 == 41) {
			REQUIRE(ev[i].events & EPOLLIN);
			found = 1;
		}
	REQUIRE(found);
	/* MOD changes the data word, DEL ends the reports. */
	ep_do(ep, EPOLL_CTL_MOD, s, EPOLLIN, 43);
	found = 0;
	n = ep_wait(ep, ev, 0);
	for (int i = 0; i < n; i++)
		if (ev[i].data.u64 == 43)
			found = 1;
	REQUIRE(found);
	REQUIRE(epoll_ctl(ep, EPOLL_CTL_DEL, s, NULL) == 0);
	REQUIRE(epoll_ctl(ep, EPOLL_CTL_DEL, c, NULL) == 0);
	REQUIRE(ep_wait(ep, ev, 100) == 0);
	REQUIRE(close(ep) == 0);
	REQUIRE(close(c) == 0 && close(s) == 0 && close(lis) == 0);
}

/* 100 connections and a socket of AF_UNIX in one set, by edge: every event
 * comes once, twice over. */
static void epoll_200(void)
{
	int port, lis = listener(4, &port);
	static int client[100], server[100];
	static unsigned char seen[101];
	int ep = ep_new();
	int u[2];
	REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, u) == 0);
	nonblock(u[0]);
	for (int i = 0; i < 100; i++) {
		pair(lis, port, &client[i], &server[i]);
		nonblock(server[i]);
		ep_add(ep, server[i], EPOLLIN | EPOLLET, (uint64_t)i);
	}
	ep_add(ep, u[0], EPOLLIN | EPOLLET, 100);
	struct epoll_event ev[64];
	REQUIRE(ep_wait(ep, ev, 0) == 0);
	for (int round = 0; round < 2; round++) {
		memset(seen, 0, sizeof seen);
		for (int i = 0; i < 100; i++)
			REQUIRE(send(client[i], "x", 1, 0) == 1);
		REQUIRE(write(u[1], "y", 1) == 1);
		collect(ep, 101, seen, 101, 10000);
		/* By edge nothing comes again. */
		REQUIRE(ep_wait(ep, ev, 200) == 0);
		for (int i = 0; i < 100; i++)
			drain(server[i]);
		drain(u[0]);
	}
	for (int i = 0; i < 100; i++) {
		REQUIRE(close(client[i]) == 0);
		REQUIRE(close(server[i]) == 0);
	}
	REQUIRE(close(u[0]) == 0 && close(u[1]) == 0 && close(ep) == 0 && close(lis) == 0);
}

/* By level a socket with bytes is reported again and again, and not once
 * they are read. */
static void epoll_lt(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	int ep = ep_new();
	struct epoll_event ev[64];
	ep_add(ep, s, EPOLLIN, 7);
	REQUIRE(ep_wait(ep, ev, 0) == 0);
	REQUIRE(send(c, "ab", 2, 0) == 2);
	REQUIRE(ep_wait(ep, ev, 2000) == 1 && ev[0].data.u64 == 7);
	REQUIRE(ep_wait(ep, ev, 0) == 1 && ev[0].data.u64 == 7);
	char buf[2];
	REQUIRE(recv(s, buf, 1, 0) == 1);
	REQUIRE(ep_wait(ep, ev, 0) == 1);
	REQUIRE(recv(s, buf, 1, 0) == 1);
	/* Nothing left: no false report, and a read finds nothing. */
	REQUIRE(ep_wait(ep, ev, 0) == 0);
	REQUIRE(recv(s, buf, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
	REQUIRE(close(c) == 0 && close(s) == 0 && close(ep) == 0 && close(lis) == 0);
}

/* By edge a report comes with new bytes, and the bytes left bring none. */
static void epoll_et(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	nonblock(s);
	int ep = ep_new();
	struct epoll_event ev[64];
	ep_add(ep, s, EPOLLIN | EPOLLET, 9);
	REQUIRE(ep_wait(ep, ev, 0) == 0);
	REQUIRE(send(c, "a", 1, 0) == 1);
	REQUIRE(ep_wait(ep, ev, 2000) == 1 && ev[0].data.u64 == 9);
	REQUIRE(ep_wait(ep, ev, 200) == 0);
	REQUIRE(send(c, "b", 1, 0) == 1);
	REQUIRE(ep_wait(ep, ev, 2000) == 1 && ev[0].data.u64 == 9);
	/* Two bytes wait; one is read; no new bytes, no report. */
	char buf[2];
	REQUIRE(recv(s, buf, 1, 0) == 1);
	REQUIRE(ep_wait(ep, ev, 200) == 0);
	drain(s);
	REQUIRE(ep_wait(ep, ev, 100) == 0);
	REQUIRE(close(c) == 0 && close(s) == 0 && close(ep) == 0 && close(lis) == 0);
}

/* A pipe by edge: the second message wakes the wait after the reader found
 * nothing (EAGAIN). */
static void epoll_et_pipe(void)
{
	int p[2];
	REQUIRE(pipe(p) == 0);
	nonblock(p[0]);
	int ep = ep_new();
	struct epoll_event ev[64];
	ep_add(ep, p[0], EPOLLIN | EPOLLET, 5);
	REQUIRE(write(p[1], "one", 3) == 3);
	REQUIRE(ep_wait(ep, ev, 2000) == 1 && ev[0].data.u64 == 5);
	REQUIRE(ep_wait(ep, ev, 100) == 0);
	drain(p[0]);
	REQUIRE(write(p[1], "two", 3) == 3);
	REQUIRE(ep_wait(ep, ev, 2000) == 1 && ev[0].data.u64 == 5);
	drain(p[0]);
	/* A socket pair of AF_UNIX the same way. */
	int u[2];
	REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, u) == 0);
	nonblock(u[0]);
	ep_add(ep, u[0], EPOLLIN | EPOLLET, 6);
	REQUIRE(write(u[1], "m1", 2) == 2);
	REQUIRE(ep_wait(ep, ev, 2000) == 1 && ev[0].data.u64 == 6);
	drain(u[0]);
	REQUIRE(write(u[1], "m2", 2) == 2);
	REQUIRE(ep_wait(ep, ev, 2000) == 1 && ev[0].data.u64 == 6);
	REQUIRE(close(p[0]) == 0 && close(p[1]) == 0 && close(ep) == 0);
	REQUIRE(close(u[0]) == 0 && close(u[1]) == 0);
}

static void epoll_oneshot(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	int ep = ep_new();
	struct epoll_event ev[64];
	ep_add(ep, s, EPOLLIN | EPOLLONESHOT, 3);
	REQUIRE(send(c, "a", 1, 0) == 1);
	REQUIRE(ep_wait(ep, ev, 2000) == 1 && ev[0].data.u64 == 3);
	/* The bytes are still there, and the record is off. */
	REQUIRE(ep_wait(ep, ev, 200) == 0);
	ep_do(ep, EPOLL_CTL_MOD, s, EPOLLIN | EPOLLONESHOT, 4);
	REQUIRE(ep_wait(ep, ev, 2000) == 1 && ev[0].data.u64 == 4);
	REQUIRE(ep_wait(ep, ev, 200) == 0);
	/* A pipe the same way. */
	int p[2];
	REQUIRE(pipe(p) == 0);
	ep_add(ep, p[0], EPOLLIN | EPOLLONESHOT, 8);
	REQUIRE(write(p[1], "x", 1) == 1);
	REQUIRE(ep_wait(ep, ev, 2000) == 1 && ev[0].data.u64 == 8);
	REQUIRE(ep_wait(ep, ev, 200) == 0);
	REQUIRE(close(p[0]) == 0 && close(p[1]) == 0);
	REQUIRE(close(c) == 0 && close(s) == 0 && close(ep) == 0 && close(lis) == 0);
}

/* A number that closed is no longer reported, and its record does not
 * name the socket that takes the number. */
static void epoll_close(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	int ep = ep_new();
	struct epoll_event ev[64];
	ep_add(ep, s, EPOLLIN, 1);
	/* The description lives on in a copy, and the number closes. */
	int d = dup(s);
	REQUIRE(d >= 0);
	REQUIRE(close(s) == 0);
	REQUIRE(send(c, "a", 1, 0) == 1);
	REQUIRE(ep_wait(ep, ev, 300) == 0);
	errno = 0;
	REQUIRE(epoll_ctl(ep, EPOLL_CTL_DEL, s, NULL) == -1 && errno == EBADF);
	/* The copy of the description is another number: it can be added, and
	 * the byte that came is reported for it. */
	ep_add(ep, d, EPOLLIN, 3);
	REQUIRE(ep_wait(ep, ev, 2000) == 1 && ev[0].data.u64 == 3);
	REQUIRE(epoll_ctl(ep, EPOLL_CTL_DEL, d, NULL) == 0);
	/* The lowest number is s again, a new socket's. */
	int n = socket(AF_INET, SOCK_STREAM, 0);
	REQUIRE(n == s);
	struct sockaddr_in a = at(LOOPBACK, port);
	REQUIRE(connect(n, (struct sockaddr *)&a, sizeof a) == 0);
	int peer = accept(lis, NULL, NULL);
	REQUIRE(peer >= 0);
	REQUIRE(send(peer, "b", 1, 0) == 1);
	struct pollfd pf = { n, POLLIN, 0 };
	REQUIRE(poll(&pf, 1, 2000) == 1);
	REQUIRE(ep_wait(ep, ev, 300) == 0);
	/* No record of the old number is in the way of the new one. */
	ep_add(ep, n, EPOLLIN, 2);
	REQUIRE(ep_wait(ep, ev, 2000) == 1 && ev[0].data.u64 == 2);
	REQUIRE(close(n) == 0);
	/* Sockets that come and go on the same numbers and places leave no
	 * records behind. */
	for (int k = 0; k < 40; k++) {
		int cc = socket(AF_INET, SOCK_STREAM, 0);
		REQUIRE(cc >= 0);
		REQUIRE(connect(cc, (struct sockaddr *)&a, sizeof a) == 0);
		int ss = accept(lis, NULL, NULL);
		REQUIRE(ss >= 0);
		ep_add(ep, ss, EPOLLIN, (uint64_t)(100 + k));
		REQUIRE(close(ss) == 0);
		REQUIRE(close(cc) == 0);
	}
	REQUIRE(close(peer) == 0 && close(d) == 0 && close(c) == 0);
	REQUIRE(close(ep) == 0 && close(lis) == 0);
}

/* The child of a fork has the epoll descriptor but not the set: EBADF; its
 * close succeeds; the parent's wait goes on. */
static void epoll_fork(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	int ep = ep_new();
	struct epoll_event ev[64];
	ep_add(ep, s, EPOLLIN, 12);
	pid_t child = fork();
	REQUIRE(child >= 0);
	if (child == 0) {
		int bad = 0;
		errno = 0;
		if (epoll_wait(ep, ev, 8, 0) != -1 || errno != EBADF)
			bad |= 1;
		errno = 0;
		struct epoll_event e = { EPOLLIN, { .u64 = 1 } };
		if (epoll_ctl(ep, EPOLL_CTL_ADD, c, &e) != -1 || errno != EBADF)
			bad |= 2;
		if (close(ep) != 0)
			bad |= 4;
		/* The parent is waiting: this byte wakes it. */
		if (send(c, "z", 1, 0) != 1)
			bad |= 8;
		_exit(bad);
	}
	REQUIRE(ep_wait(ep, ev, 10000) == 1 && ev[0].data.u64 == 12);
	REQUIRE(wait_exit(child) == 0);
	REQUIRE(close(c) == 0 && close(s) == 0 && close(ep) == 0 && close(lis) == 0);
}

static int epoll_child(int fd)
{
	errno = 0;
	if (fcntl(fd, F_GETFD) != -1 || errno != EBADF)
		return 1;
	/* The number is free: the next descriptor takes it. */
	int p[2];
	if (pipe(p) != 0 || p[0] > fd)
		return 2;
	return 0;
}

/* An epoll descriptor closes at exec whatever its flags: the number is free
 * in the new image. */
static void epoll_exec(void)
{
	int ep = ep_new();
	char number[16];
	snprintf(number, sizeof number, "%d", ep);
	pid_t child = fork();
	REQUIRE(child >= 0);
	if (child == 0) {
		char *argv[] = { (char *)self, "epoll-child", number, NULL };
		execv(self, argv);
		_exit(99);
	}
	REQUIRE(wait_exit(child) == 0);
	REQUIRE(close(ep) == 0);
}

static void epoll_errors(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	int ep = ep_new();
	struct epoll_event e = { EPOLLIN, { .u64 = 1 } };
	ep_add(ep, s, EPOLLIN, 1);
	errno = 0;
	REQUIRE(epoll_ctl(ep, EPOLL_CTL_ADD, s, &e) == -1 && errno == EEXIST);
	errno = 0;
	REQUIRE(epoll_ctl(ep, EPOLL_CTL_MOD, c, &e) == -1 && errno == ENOENT);
	errno = 0;
	REQUIRE(epoll_ctl(ep, EPOLL_CTL_DEL, c, NULL) == -1 && errno == ENOENT);
	int file = open(self, O_RDONLY);
	REQUIRE(file >= 0);
	errno = 0;
	REQUIRE(epoll_ctl(ep, EPOLL_CTL_ADD, file, &e) == -1 && errno == EPERM);
	/* EPOLLEXCLUSIVE: an ADD with the bits Linux allows with it goes (nginx
	 * adds its listening sockets so); MOD and other bits are EINVAL. */
	struct epoll_event ex = { EPOLLIN | EPOLLEXCLUSIVE, { .u64 = 1 } };
	REQUIRE(epoll_ctl(ep, EPOLL_CTL_ADD, c, &ex) == 0);
	errno = 0;
	REQUIRE(epoll_ctl(ep, EPOLL_CTL_MOD, c, &ex) == -1 && errno == EINVAL);
	REQUIRE(epoll_ctl(ep, EPOLL_CTL_DEL, c, NULL) == 0);
	struct epoll_event bad = { EPOLLIN | EPOLLEXCLUSIVE | EPOLLONESHOT, { .u64 = 1 } };
	errno = 0;
	REQUIRE(epoll_ctl(ep, EPOLL_CTL_ADD, c, &bad) == -1 && errno == EINVAL);
	bad.events = EPOLLIN | EPOLLEXCLUSIVE | EPOLLRDHUP;
	errno = 0;
	REQUIRE(epoll_ctl(ep, EPOLL_CTL_ADD, c, &bad) == -1 && errno == EINVAL);
	errno = 0;
	REQUIRE(epoll_ctl(ep, EPOLL_CTL_ADD, ep, &e) == -1 && errno == EINVAL);
	int ep2 = ep_new();
	errno = 0;
	REQUIRE(epoll_ctl(ep, EPOLL_CTL_ADD, ep2, &e) == -1 && errno == EINVAL);
	errno = 0;
	REQUIRE(epoll_ctl(ep, EPOLL_CTL_ADD, 999, &e) == -1 && errno == EBADF);
	errno = 0;
	REQUIRE(epoll_ctl(s, EPOLL_CTL_ADD, c, &e) == -1 && errno == EINVAL);
	errno = 0;
	REQUIRE(epoll_ctl(ep, 9, c, &e) == -1 && errno == EINVAL);
	errno = 0;
	REQUIRE(epoll_wait(ep, &e, 0, 0) == -1 && errno == EINVAL);
	errno = 0;
	REQUIRE(epoll_create1(1) == -1 && errno == EINVAL);
	REQUIRE(close(file) == 0 && close(ep2) == 0 && close(ep) == 0);
	REQUIRE(close(c) == 0 && close(s) == 0 && close(lis) == 0);
}

static void epoll_rdhup(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	int ep = ep_new();
	struct epoll_event ev[64];
	ep_add(ep, s, EPOLLIN | EPOLLRDHUP, 1);
	REQUIRE(ep_wait(ep, ev, 0) == 0);
	REQUIRE(shutdown(c, SHUT_WR) == 0);
	REQUIRE(ep_wait(ep, ev, 2000) == 1);
	REQUIRE((ev[0].events & EPOLLRDHUP) && (ev[0].events & EPOLLIN));
	REQUIRE(close(c) == 0 && close(s) == 0 && close(ep) == 0 && close(lis) == 0);
}

/* A reset is an error of the socket, once. */
static void epoll_err_rst(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	int ep = ep_new();
	struct epoll_event ev[64];
	ep_add(ep, c, EPOLLIN, 1);
	REQUIRE(send(c, "x", 1, 0) == 1);
	struct pollfd pf = { s, POLLIN, 0 };
	REQUIRE(poll(&pf, 1, 2000) == 1);
	/* The server closes with a byte unread: the client is reset. */
	REQUIRE(close(s) == 0);
	REQUIRE(ep_wait(ep, ev, 5000) == 1);
	REQUIRE(ev[0].events & EPOLLERR);
	int err = 0;
	socklen_t len = sizeof err;
	REQUIRE(getsockopt(c, SOL_SOCKET, SO_ERROR, &err, &len) == 0);
	REQUIRE(err == ECONNRESET);
	len = sizeof err;
	REQUIRE(getsockopt(c, SOL_SOCKET, SO_ERROR, &err, &len) == 0);
	REQUIRE(err == 0);
	REQUIRE(close(c) == 0 && close(ep) == 0 && close(lis) == 0);
}

static volatile int alarms;

static void on_alarm(int sig)
{
	(void)sig;
	alarms++;
}

/* A signal ends the wait with EINTR even with SA_RESTART; the mask of
 * epoll_pwait holds one back for the time of the wait. */
static void epoll_signal(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_alarm;
	sa.sa_flags = SA_RESTART;
	sigemptyset(&sa.sa_mask);
	REQUIRE(sigaction(SIGALRM, &sa, NULL) == 0);
	int ep = ep_new();
	int p[2];
	REQUIRE(pipe(p) == 0);
	ep_add(ep, p[0], EPOLLIN, 1);
	struct epoll_event ev[4];
	alarms = 0;
	alarm(1);
	errno = 0;
	long began = now_ms();
	REQUIRE(epoll_wait(ep, ev, 4, 8000) == -1 && errno == EINTR);
	REQUIRE(alarms == 1 && now_ms() - began < 6000);
	/* The signal is blocked; the mask of epoll_pwait lets it in for the
	 * time of the wait, and the blocked mask is back after. */
	sigset_t held, empty, after;
	sigemptyset(&held);
	sigaddset(&held, SIGALRM);
	sigemptyset(&empty);
	REQUIRE(sigprocmask(SIG_BLOCK, &held, NULL) == 0);
	alarm(1);
	errno = 0;
	REQUIRE(epoll_pwait(ep, ev, 4, 8000, &empty) == -1 && errno == EINTR);
	REQUIRE(alarms == 2);
	REQUIRE(sigprocmask(SIG_SETMASK, NULL, &after) == 0 && sigismember(&after, SIGALRM) == 1);
	/* And without the mask the same signal waits until it is unblocked. */
	alarm(1);
	REQUIRE(epoll_wait(ep, ev, 4, 1500) == 0);
	REQUIRE(alarms == 2);
	REQUIRE(sigprocmask(SIG_UNBLOCK, &held, NULL) == 0);
	for (int i = 0; i < 100 && alarms < 3; i++)
		pause_ms(20);
	REQUIRE(alarms == 3);
	sa.sa_handler = SIG_DFL;
	REQUIRE(sigaction(SIGALRM, &sa, NULL) == 0);
	REQUIRE(close(p[0]) == 0 && close(p[1]) == 0 && close(ep) == 0);
}

/* The wait of a set whose list of ready records holds 500 that report
 * nothing now (their bytes were read; more than the start and the take of a wait look at, 2 * 128): the byte that comes for the last of
 * them wakes the wait. */
static void epoll_stale_list(void)
{
	int port, lis = listener(4, &port);
	static int client[500], server[500];
	int ep = ep_new();
	for (int i = 0; i < 500; i++) {
		pair(lis, port, &client[i], &server[i]);
		nonblock(server[i]);
		ep_add(ep, server[i], EPOLLIN, (uint64_t)i);
		REQUIRE(send(client[i], "x", 1, 0) == 1);
	}
	struct epoll_event ev[64];
	static unsigned char seen[500];
	int total = 0, last = -1;
	long end = now_ms() + 50000;
	while (total < 500) {
		REQUIRE(now_ms() < end);
		int n = ep_wait(ep, ev, 1000);
		REQUIRE(n >= 0);
		for (int i = 0; i < n; i++) {
			if (!seen[ev[i].data.u64]) {
				seen[ev[i].data.u64] = 1;
				total++;
			}
			last = (int)ev[i].data.u64;
		}
	}
	for (int i = 0; i < 500; i++)
		drain(server[i]);
	/* The last record reported is the last in the list. */
	REQUIRE(last >= 0);
	REQUIRE(send(client[last], "y", 1, 0) == 1);
	long began = now_ms();
	int n = ep_wait(ep, ev, 5000);
	REQUIRE(n == 1 && ev[0].data.u64 == (uint64_t)last);
	REQUIRE(now_ms() - began < 1000);
	for (int i = 0; i < 500; i++) {
		REQUIRE(close(client[i]) == 0);
		REQUIRE(close(server[i]) == 0);
	}
	REQUIRE(close(ep) == 0 && close(lis) == 0);
}

/* A record by edge for IN and OUT: OUT comes once, and a byte brings IN
 * alone; a write to a full buffer, drained by the peer, brings OUT again. */
static void epoll_et_inout(void)
{
	int u[2];
	REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, u) == 0);
	nonblock(u[0]);
	int ep = ep_new();
	struct epoll_event ev[64];
	ep_add(ep, u[0], EPOLLIN | EPOLLOUT | EPOLLET, 1);
	REQUIRE(ep_wait(ep, ev, 2000) == 1 && ev[0].events == EPOLLOUT);
	REQUIRE(write(u[1], "b", 1) == 1);
	REQUIRE(ep_wait(ep, ev, 2000) == 1 && ev[0].events == EPOLLIN);
	REQUIRE(ep_wait(ep, ev, 200) == 0);
	drain(u[0]);
	/* A socket of the service the same way: fill, drain, one OUT. */
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	nonblock(c);
	nonblock(s);
	ep_add(ep, c, EPOLLIN | EPOLLOUT | EPOLLET, 2);
	REQUIRE(ep_wait(ep, ev, 2000) == 1 && ev[0].data.u64 == 2 && ev[0].events == EPOLLOUT);
	static char block[800];
	memset(block, 'f', sizeof block);
	/* Write until EAGAIN; room that came while the buffer filled is reported
	 * (once) and written again, until a write finds none and all is quiet. */
	int quiet = 0;
	for (int round = 0; round < 30 && !quiet; round++) {
		for (;;) {
			ssize_t n = send(c, block, sizeof block, 0);
			if (n < 0) {
				REQUIRE(errno == EAGAIN);
				break;
			}
		}
		quiet = ep_wait(ep, ev, 300) == 0;
	}
	REQUIRE(quiet);
	drain(s);
	REQUIRE(ep_wait(ep, ev, 3000) == 1 && ev[0].data.u64 == 2 && (ev[0].events & EPOLLOUT));
	REQUIRE(ep_wait(ep, ev, 300) == 0);
	REQUIRE(close(c) == 0 && close(s) == 0 && close(lis) == 0);
	REQUIRE(close(u[0]) == 0 && close(u[1]) == 0 && close(ep) == 0);
}

/* A listening socket in a set: two connections are one report by level,
 * and none once both are accepted. */
static void epoll_listener(void)
{
	int port, lis = listener(4, &port);
	int ep = ep_new();
	struct epoll_event ev[64];
	ep_add(ep, lis, EPOLLIN, 1);
	REQUIRE(ep_wait(ep, ev, 0) == 0);
	struct sockaddr_in a = at(LOOPBACK, port);
	int c1 = socket(AF_INET, SOCK_STREAM, 0);
	int c2 = socket(AF_INET, SOCK_STREAM, 0);
	REQUIRE(c1 >= 0 && c2 >= 0);
	REQUIRE(connect(c1, (struct sockaddr *)&a, sizeof a) == 0);
	REQUIRE(connect(c2, (struct sockaddr *)&a, sizeof a) == 0);
	REQUIRE(ep_wait(ep, ev, 2000) == 1 && ev[0].data.u64 == 1 && (ev[0].events & EPOLLIN));
	int s1 = accept(lis, NULL, NULL);
	REQUIRE(s1 >= 0);
	REQUIRE(ep_wait(ep, ev, 2000) == 1);
	int s2 = accept(lis, NULL, NULL);
	REQUIRE(s2 >= 0);
	REQUIRE(ep_wait(ep, ev, 300) == 0);
	REQUIRE(close(c1) == 0 && close(c2) == 0 && close(s1) == 0 && close(s2) == 0);
	REQUIRE(close(ep) == 0 && close(lis) == 0);
}

static int thread_ep;
static int thread_events;
static int thread_errno;

static void *thread_waiter(void *arg)
{
	(void)arg;
	struct epoll_event ev[8];
	thread_events = epoll_wait(thread_ep, ev, 8, 5000);
	thread_errno = errno;
	return NULL;
}

/* One thread waits while another adds a socket that is ready already: the
 * event reaches the waiter (it is not lost between the add and its answer). */
static void epoll_threads(void)
{
	int port, lis = listener(4, &port);
	thread_ep = ep_new();
	for (int round = 0; round < 40; round++) {
		int c, s;
		pair(lis, port, &c, &s);
		REQUIRE(send(c, "t", 1, 0) == 1);
		struct pollfd pf = { s, POLLIN, 0 };
		REQUIRE(poll(&pf, 1, 2000) == 1);
		pthread_t waiter;
		thread_events = -2;
		REQUIRE(pthread_create(&waiter, NULL, thread_waiter, NULL) == 0);
		pause_ms(round % 4);
		ep_add(thread_ep, s, EPOLLIN | EPOLLET, (uint64_t)round);
		REQUIRE(pthread_join(waiter, NULL) == 0);
		if (thread_events != 1) {
			/* The add reported it, or the wait did: one of them has it. */
			struct epoll_event ev[8];
			printf("posix-net: epoll-threads failed: the waiter got %d, errno %d\n", thread_events, thread_errno);
			REQUIRE(thread_events == 0 || thread_events == -1);
			REQUIRE(ep_wait(thread_ep, ev, 0) == 0);
			fail("an event of an add was lost");
		}
		REQUIRE(epoll_ctl(thread_ep, EPOLL_CTL_DEL, s, NULL) == 0);
		REQUIRE(close(c) == 0 && close(s) == 0);
	}
	REQUIRE(close(thread_ep) == 0 && close(lis) == 0);
}

/* The writer of wait-churn: bytes on a socket of the network service and on a
 * socket of the pipe service at odd moments, so that the answers to the waits
 * of the main thread come late, from the other CPU. */
static volatile int churn_stop;
static int churn_tcp, churn_unix;

static void *churn_writer(void *arg)
{
	(void)arg;
	for (unsigned n = 0; !churn_stop; n++) {
		struct timespec t = { 0, (long)(n % 4) * 100000L };
		nanosleep(&t, NULL);
		(void)send(churn_tcp, "t", 1, MSG_DONTWAIT);
		(void)send(churn_unix, "u", 1, MSG_DONTWAIT);
	}
	return NULL;
}

/* Many waits with short timeouts while answers come late: every poll, select
 * and epoll_wait leaves its notification sessions behind on the thread's
 * channel, and with 1 024 places taken the next wait failed with EAGAIN
 * (stafeto-design#569). None may fail. */
static void wait_churn(void)
{
	int port, lis = listener(4, &port);
	int c, s, u[2];
	pair(lis, port, &c, &s);
	REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, u) == 0);
	nonblock(s);
	nonblock(u[1]);
	int ep = ep_new();
	ep_add(ep, s, EPOLLIN, 1);
	ep_add(ep, u[1], EPOLLIN, 2);
	churn_tcp = c;
	churn_unix = u[0];
	churn_stop = 0;
	pthread_t writer;
	REQUIRE(pthread_create(&writer, NULL, churn_writer, NULL) == 0);
	char buf[256];
	for (int i = 0; i < 4000; i++) {
		int n = -1;
		switch (i % 3) {
		case 0: {
			struct pollfd pf[2] = { { s, POLLIN, 0 }, { u[1], POLLIN, 0 } };
			n = poll(pf, 2, 1);
			break;
		}
		case 1: {
			struct epoll_event ev[8];
			n = epoll_wait(ep, ev, 8, 1);
			break;
		}
		default: {
			fd_set rd;
			FD_ZERO(&rd);
			FD_SET(s, &rd);
			FD_SET(u[1], &rd);
			struct timeval tv = { 0, 1000 };
			n = select((s > u[1] ? s : u[1]) + 1, &rd, NULL, NULL, &tv);
			break;
		}
		}
		if (n < 0) {
			printf("posix-net: wait-churn failed at wait %d: errno %d\n", i, errno);
			fflush(stdout);
		}
		REQUIRE(n >= 0);
		while (recv(s, buf, sizeof buf, MSG_DONTWAIT) > 0)
			;
		while (recv(u[1], buf, sizeof buf, MSG_DONTWAIT) > 0)
			;
	}
	churn_stop = 1;
	REQUIRE(pthread_join(writer, NULL) == 0);
	REQUIRE(close(ep) == 0 && close(c) == 0 && close(s) == 0);
	REQUIRE(close(u[0]) == 0 && close(u[1]) == 0 && close(lis) == 0);
}

#define PAIRS 500
static int cl[PAIRS], sv[PAIRS];

/* PAIRS connections through one listener. */
static void many_pairs(void)
{
	int port, lis = listener(4, &port);
	for (int i = 0; i < PAIRS; i++)
		pair(lis, port, &cl[i], &sv[i]);
	REQUIRE(close(lis) == 0);
}

static void close_pairs(void)
{
	for (int i = 0; i < PAIRS; i++) {
		REQUIRE(close(cl[i]) == 0);
		REQUIRE(close(sv[i]) == 0);
	}
}

/* A poll of 1 000 descriptors goes through the service's engine. */
static void poll_1000(void)
{
	many_pairs();
	static struct pollfd fds[2 * PAIRS];
	for (int i = 0; i < PAIRS; i++) {
		fds[2 * i] = (struct pollfd){ cl[i], POLLIN, 0 };
		fds[2 * i + 1] = (struct pollfd){ sv[i], POLLIN, 0 };
	}
	REQUIRE(poll(fds, 2 * PAIRS, 0) == 0);
	for (int i = 0; i < 10; i++)
		REQUIRE(send(cl[i * 50], "x", 1, 0) == 1);
	/* The bytes cross the loopback: wait until all ten are in. */
	long began = now_ms();
	int ready = 0;
	while (ready < 10 && now_ms() - began < 5000) {
		for (int i = 0; i < 2 * PAIRS; i++)
			fds[i].revents = 0;
		ready = poll(fds, 2 * PAIRS, 1000);
		REQUIRE(ready >= 0);
	}
	long took = now_ms() - began;
	REQUIRE(ready == 10);
	for (int i = 0; i < 2 * PAIRS; i++) {
		int want = (i % 2 == 1 && (i / 2) % 50 == 0);
		REQUIRE((fds[i].revents != 0) == want);
		if (want)
			REQUIRE(fds[i].revents == POLLIN);
	}
	printf("posix-net: poll-1000 took %ld ms\n", took);
	/* Every socket can send. */
	for (int i = 0; i < 2 * PAIRS; i++) {
		fds[i].events = POLLOUT;
		fds[i].revents = 0;
	}
	REQUIRE(poll(fds, 2 * PAIRS, 1000) == 2 * PAIRS);
	for (int i = 0; i < 2 * PAIRS; i++)
		REQUIRE(fds[i].revents == POLLOUT);
	/* A descriptor that is no descriptor, and a number twice. */
	fds[0] = (struct pollfd){ 1020, POLLIN, 0 };
	fds[1] = (struct pollfd){ sv[0], POLLIN, 0 };
	fds[2] = (struct pollfd){ sv[0], POLLOUT, 0 };
	for (int i = 3; i < 2 * PAIRS; i++)
		fds[i] = (struct pollfd){ -1, 0, 0 };
	REQUIRE(poll(fds, 2 * PAIRS, 1000) == 3);
	REQUIRE(fds[0].revents == POLLNVAL && fds[1].revents == POLLIN && fds[2].revents == POLLOUT);
	/* Two numbers of one description. */
	int copy = dup(sv[0]);
	REQUIRE(copy >= 0);
	fds[0] = (struct pollfd){ sv[0], POLLIN, 0 };
	fds[1] = (struct pollfd){ copy, POLLIN | POLLOUT, 0 };
	fds[2] = (struct pollfd){ -1, 0, 0 };
	REQUIRE(poll(fds, 2 * PAIRS, 1000) == 2);
	REQUIRE(fds[0].revents == POLLIN && fds[1].revents == (POLLIN | POLLOUT));
	REQUIRE(close(copy) == 0);
	close_pairs();
}

static void select_high(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	REQUIRE(dup2(s, 900) == 900);
	fd_set rd;
	struct timeval none = { 0, 0 };
	FD_ZERO(&rd);
	FD_SET(900, &rd);
	REQUIRE(select(901, &rd, NULL, NULL, &none) == 0);
	REQUIRE(send(c, "a", 1, 0) == 1);
	struct timeval first = { 2, 0 };
	FD_ZERO(&rd);
	FD_SET(900, &rd);
	REQUIRE(select(901, &rd, NULL, NULL, &first) == 1 && FD_ISSET(900, &rd));
	/* More than 64 named: seventy sockets and the high number. */
	static int a[35], b[35];
	for (int i = 0; i < 35; i++)
		pair(lis, port, &a[i], &b[i]);
	REQUIRE(send(a[20], "q", 1, 0) == 1);
	struct timeval wait = { 3, 0 };
	FD_ZERO(&rd);
	for (int i = 0; i < 35; i++) {
		FD_SET(a[i], &rd);
		FD_SET(b[i], &rd);
	}
	FD_SET(900, &rd);
	int n = select(901, &rd, NULL, NULL, &wait);
	REQUIRE(n == 2);
	REQUIRE(FD_ISSET(b[20], &rd) && FD_ISSET(900, &rd));
	for (int i = 0; i < 35; i++) {
		REQUIRE(close(a[i]) == 0);
		REQUIRE(close(b[i]) == 0);
	}
	REQUIRE(close(900) == 0 && close(c) == 0 && close(s) == 0 && close(lis) == 0);
}

/* The bytes ready to read of a stream, and the next datagram's length. */
static void fionread(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	int n = -1;
	REQUIRE(ioctl(s, FIONREAD, &n) == 0 && n == 0);
	static char block[4096];
	memset(block, 'k', sizeof block);
	REQUIRE(send(c, block, sizeof block, MSG_WAITALL) == (ssize_t)sizeof block);
	long end = now_ms() + 5000;
	for (;;) {
		REQUIRE(ioctl(s, FIONREAD, &n) == 0);
		if (n == 4096 || now_ms() > end)
			break;
		pause_ms(10);
	}
	REQUIRE(n == 4096);
	char buf[100];
	REQUIRE(recv(s, buf, sizeof buf, 0) == (ssize_t)sizeof buf);
	REQUIRE(ioctl(s, FIONREAD, &n) == 0 && n == 4096 - 100);
	int u1 = socket(AF_INET, SOCK_DGRAM, 0);
	int u2 = socket(AF_INET, SOCK_DGRAM, 0);
	REQUIRE(u1 >= 0 && u2 >= 0);
	struct sockaddr_in a = at(LOOPBACK, 0);
	REQUIRE(bind(u2, (struct sockaddr *)&a, sizeof a) == 0);
	socklen_t len = sizeof a;
	REQUIRE(getsockname(u2, (struct sockaddr *)&a, &len) == 0);
	REQUIRE(ioctl(u2, FIONREAD, &n) == 0 && n == 0);
	REQUIRE(sendto(u1, block, 300, 0, (struct sockaddr *)&a, sizeof a) == 300);
	end = now_ms() + 5000;
	for (;;) {
		REQUIRE(ioctl(u2, FIONREAD, &n) == 0);
		if (n == 300 || now_ms() > end)
			break;
		pause_ms(10);
	}
	REQUIRE(n == 300);
	REQUIRE(recv(u2, block, sizeof block, 0) == 300);
	REQUIRE(ioctl(u2, FIONREAD, &n) == 0 && n == 0);
	int p[2];
	REQUIRE(pipe(p) == 0);
	errno = 0;
	REQUIRE(ioctl(p[0], FIONREAD, &n) == -1 && errno == ENOTTY);
	REQUIRE(close(p[0]) == 0 && close(p[1]) == 0);
	REQUIRE(close(u1) == 0 && close(u2) == 0);
	REQUIRE(close(c) == 0 && close(s) == 0 && close(lis) == 0);
}

/* 1 000 sockets in one set: each gets a byte from its peer and every event
 * comes. The time from the writes to the last event is printed. */
static void epoll_1000(void)
{
	many_pairs();
	static unsigned char seen[2 * PAIRS];
	int ep = ep_new();
	for (int i = 0; i < PAIRS; i++) {
		nonblock(cl[i]);
		nonblock(sv[i]);
		ep_add(ep, cl[i], EPOLLIN | EPOLLET, (uint64_t)(2 * i));
		ep_add(ep, sv[i], EPOLLIN | EPOLLET, (uint64_t)(2 * i + 1));
	}
	struct epoll_event ev[64];
	REQUIRE(ep_wait(ep, ev, 0) == 0);
	long began = now_ms();
	for (int i = 0; i < PAIRS; i++) {
		REQUIRE(send(cl[i], "c", 1, 0) == 1);
		REQUIRE(send(sv[i], "s", 1, 0) == 1);
	}
	collect(ep, 2 * PAIRS, seen, 2 * PAIRS, 60000);
	long took = now_ms() - began;
	REQUIRE(ep_wait(ep, ev, 200) == 0);
	printf("posix-net: epoll-1000 took %ld ms\n", took);
	REQUIRE(close(ep) == 0);
	close_pairs();
}


/* ---- stage P4a-3: servers and SCM_RIGHTS ---- */

#define SO_STAFETO_PASSES 0x7350

/* The handles of passes the pipe service holds, as `fd` (a socket of AF_UNIX)
 * tells. */
static int passes_held(int fd)
{
	int value = -1;
	socklen_t len = sizeof value;
	REQUIRE(getsockopt(fd, SOL_SOCKET, SO_STAFETO_PASSES, &value, &len) == 0);
	return value;
}

/* Waits until the pass count seen through `fd` is `want` (the handles of
 * messages whose socket went close in steps of their own). */
static void passes_become(int fd, int want, long ms)
{
	long end = now_ms() + ms;
	while (passes_held(fd) != want) {
		REQUIRE(now_ms() < end);
		pause_ms(10);
	}
}

/* Whether the peer `c` of a socket sees the end of the stream: its other
 * end was closed by every holder (`ms` to see it). */
static int sees_end(int c, long ms)
{
	struct pollfd pf = { c, POLLIN, 0 };
	if (poll(&pf, 1, (int)ms) != 1)
		return 0;
	char b;
	return recv(c, &b, 1, 0) == 0;
}

/* Sends the descriptors `fds` (n of them) in one message of one byte. */
static ssize_t send_fds(int u, const int *fds, int n)
{
	char data = 'm';
	struct iovec iov = { &data, 1 };
	char ctl[CMSG_SPACE(sizeof(int) * 8)];
	memset(ctl, 0, sizeof ctl);
	struct msghdr m;
	memset(&m, 0, sizeof m);
	m.msg_iov = &iov;
	m.msg_iovlen = 1;
	m.msg_control = ctl;
	m.msg_controllen = CMSG_SPACE(sizeof(int) * n);
	struct cmsghdr *h = CMSG_FIRSTHDR(&m);
	h->cmsg_level = SOL_SOCKET;
	h->cmsg_type = SCM_RIGHTS;
	h->cmsg_len = CMSG_LEN(sizeof(int) * n);
	memcpy(CMSG_DATA(h), fds, sizeof(int) * n);
	return sendmsg(u, &m, 0);
}

/* Receives one message into `fds` (room for `room`); the count, -1 on an
 * error; `flags` gets msg_flags. */
static int recv_fds(int u, int *fds, int room, int *flags)
{
	char data;
	struct iovec iov = { &data, 1 };
	char ctl[CMSG_SPACE(sizeof(int) * 8)];
	memset(ctl, 0, sizeof ctl);
	struct msghdr m;
	memset(&m, 0, sizeof m);
	m.msg_iov = &iov;
	m.msg_iovlen = 1;
	m.msg_control = ctl;
	/* Room for exactly `room` descriptors: CMSG_SPACE would pad to one more. */
	m.msg_controllen = CMSG_LEN(sizeof(int) * room);
	if (recvmsg(u, &m, 0) != 1)
		return -1;
	if (flags)
		*flags = m.msg_flags;
	struct cmsghdr *h = CMSG_FIRSTHDR(&m);
	if (!h)
		return 0;
	REQUIRE(h->cmsg_level == SOL_SOCKET && h->cmsg_type == SCM_RIGHTS);
	int n = (int)((h->cmsg_len - CMSG_LEN(0)) / sizeof(int));
	memcpy(fds, CMSG_DATA(h), sizeof(int) * n);
	return n;
}

/* A second `listen` with a larger backlog builds the queue up to it: six
 * connections complete with nobody accepting. */
static void listen_again(void)
{
	int port, lis = listener(1, &port);
	REQUIRE(listen(lis, 6) == 0);
	struct sockaddr_in a = at(LOOPBACK, port);
	int c[6];
	for (int i = 0; i < 6; i++) {
		c[i] = socket(AF_INET, SOCK_STREAM, 0);
		REQUIRE(c[i] >= 0);
		nonblock(c[i]);
		errno = 0;
		REQUIRE(connect(c[i], (struct sockaddr *)&a, sizeof a) == -1 && errno == EINPROGRESS);
	}
	for (int i = 0; i < 6; i++) {
		struct pollfd pf = { c[i], POLLOUT, 0 };
		REQUIRE(poll(&pf, 1, 700) == 1 && (pf.revents & POLLOUT) && !(pf.revents & (POLLERR | POLLHUP)));
	}
	int s[6];
	for (int i = 0; i < 6; i++) {
		s[i] = accept(lis, NULL, NULL);
		REQUIRE(s[i] >= 0);
	}
	for (int i = 0; i < 6; i++)
		REQUIRE(close(c[i]) == 0 && close(s[i]) == 0);
	REQUIRE(close(lis) == 0);
}

/* A SYN to a full queue is dropped without a reset: the second
 * connect stays under way and goes through once an accept makes room. */
static void syn_full(void)
{
	int port, lis = listener(1, &port);
	struct sockaddr_in a = at(LOOPBACK, port);
	int c1 = socket(AF_INET, SOCK_STREAM, 0);
	int c2 = socket(AF_INET, SOCK_STREAM, 0);
	REQUIRE(c1 >= 0 && c2 >= 0);
	REQUIRE(connect(c1, (struct sockaddr *)&a, sizeof a) == 0);
	nonblock(c2);
	errno = 0;
	REQUIRE(connect(c2, (struct sockaddr *)&a, sizeof a) == -1 && errno == EINPROGRESS);
	/* No reset: nothing is reported on c2 for a while. */
	struct pollfd pf = { c2, POLLOUT, 0 };
	REQUIRE(poll(&pf, 1, 400) == 0);
	int err = -1;
	socklen_t len = sizeof err;
	REQUIRE(getsockopt(c2, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0);
	int s1 = accept(lis, NULL, NULL);
	REQUIRE(s1 >= 0);
	/* The SYN comes again and finds room. */
	pf.revents = 0;
	REQUIRE(poll(&pf, 1, 8000) == 1 && (pf.revents & POLLOUT) && !(pf.revents & POLLERR));
	int s2 = accept(lis, NULL, NULL);
	REQUIRE(s2 >= 0);
	exchange(c2, s2, 'w');
	REQUIRE(close(c1) == 0 && close(c2) == 0 && close(s1) == 0 && close(s2) == 0);
	REQUIRE(close(lis) == 0);
}

/* A new connection on the four of a connection the server closed first (in
 * TIME-WAIT) is accepted at once. */
static void timewait_syn(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	struct sockaddr_in me;
	socklen_t len = sizeof me;
	REQUIRE(getsockname(c, (struct sockaddr *)&me, &len) == 0);
	exchange(c, s, 'a');
	/* The server closes first and stays in TIME-WAIT; the client follows. */
	REQUIRE(close(s) == 0);
	REQUIRE(sees_end(c, 3000));
	REQUIRE(close(c) == 0);
	pause_ms(100);
	int c2 = socket(AF_INET, SOCK_STREAM, 0);
	REQUIRE(c2 >= 0);
	int one = 1;
	REQUIRE(setsockopt(c2, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) == 0);
	REQUIRE(bind(c2, (struct sockaddr *)&me, sizeof me) == 0);
	struct sockaddr_in a = at(LOOPBACK, port);
	nonblock(c2);
	long began = now_ms();
	errno = 0;
	REQUIRE(connect(c2, (struct sockaddr *)&a, sizeof a) == -1 && errno == EINPROGRESS);
	struct pollfd pf = { c2, POLLOUT, 0 };
	REQUIRE(poll(&pf, 1, 800) == 1 && (pf.revents & POLLOUT) && !(pf.revents & POLLERR));
	REQUIRE(now_ms() - began < 800);
	int s2 = accept(lis, NULL, NULL);
	REQUIRE(s2 >= 0);
	exchange(c2, s2, 'b');
	REQUIRE(close(c2) == 0 && close(s2) == 0 && close(lis) == 0);
}

/* A listener of the group of SO_REUSEPORT in a child: it accepts what the
 * circle of the group gives it and reports each with its index on `report`; it
 * ends after a quiet second. */
static void group_member(int index, int port, int report, int ready)
{
	int lis = socket(AF_INET, SOCK_STREAM, 0);
	if (lis < 0)
		_exit(10);
	int one = 1;
	if (setsockopt(lis, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one) != 0)
		_exit(11);
	struct sockaddr_in a = at(INADDR_ANY, port);
	if (bind(lis, (struct sockaddr *)&a, sizeof a) != 0)
		_exit(12);
	if (listen(lis, 16) != 0)
		_exit(13);
	char r = 'R';
	if (write(ready, &r, 1) != 1)
		_exit(14);
	for (;;) {
		struct pollfd pf = { lis, POLLIN, 0 };
		int n = poll(&pf, 1, 1500);
		if (n == 0)
			_exit(0);
		if (n < 0)
			_exit(15);
		int s = accept(lis, NULL, NULL);
		if (s < 0)
			_exit(16);
		char tag = (char)index;
		if (write(report, &tag, 1) != 1)
			_exit(17);
		/* The connection stays open until the child ends. */
	}
}

/* Four processes listen on one port; 256 connections from different ports
 * are shared out evenly: the service names the next member of the circle that
 * has room, so each gets 64 and a share is never outside 48..80 (a quarter
 * either way). The connections stay open until the end: 256 clients, 256
 * accepted and 64 sockets of the queues. */
static void reuseport_4(void)
{
	enum { CONNS = 256 };
	int ready[2], report[2];
	REQUIRE(pipe(ready) == 0 && pipe(report) == 0);
	int port = 18090;
	pid_t kids[4];
	for (int i = 0; i < 4; i++) {
		kids[i] = fork();
		REQUIRE(kids[i] >= 0);
		if (kids[i] == 0) {
			close(ready[0]);
			close(report[0]);
			group_member(i, port, report[1], ready[1]);
		}
	}
	/* The parent keeps no write end: a member that ended early ends the read. */
	REQUIRE(close(ready[1]) == 0 && close(report[1]) == 0);
	for (int i = 0; i < 4; i++) {
		char r = 0;
		if (read(ready[0], &r, 1) != 1 || r != 'R') {
			for (int k = 0; k < 4; k++) {
				int status = 0;
				if (waitpid(kids[k], &status, WNOHANG) == kids[k])
					printf("posix-net: reuseport-4 note: member %d ended with %d\n", k, WEXITSTATUS(status));
			}
			fail("a member of the group is not listening");
		}
	}
	struct sockaddr_in a = at(LOOPBACK, port);
	int c[CONNS];
	long began = now_ms();
	for (int i = 0; i < CONNS; i++) {
		c[i] = socket(AF_INET, SOCK_STREAM, 0);
		REQUIRE(c[i] >= 0);
		REQUIRE(connect(c[i], (struct sockaddr *)&a, sizeof a) == 0);
		long at_ms = now_ms() - began;
		if (at_ms > 500 && i % 16 == 0)
			printf("posix-net: reuseport-4 note: connect %d done at %ld ms\n", i, at_ms);
	}
	int count[4] = { 0, 0, 0, 0 };
	for (int i = 0; i < CONNS; i++) {
		char tag = 99;
		if (read(report[0], &tag, 1) != 1) {
			printf("posix-net: reuseport-4 note: got %d of %d reports (%d %d %d %d) at %ld ms\n", i, CONNS,
			       count[0], count[1], count[2], count[3], now_ms() - began);
			for (int k = 0; k < 4; k++) {
				int status = 0;
				if (waitpid(kids[k], &status, WNOHANG) == kids[k])
					printf("posix-net: reuseport-4 note: member %d ended with %d\n", k, WEXITSTATUS(status));
			}
			fail("a connection was not accepted");
		}
		REQUIRE(tag >= 0 && tag < 4);
		count[(int)tag]++;
	}
	printf("posix-net: reuseport-4 note: shares %d %d %d %d\n", count[0], count[1], count[2], count[3]);
	for (int i = 0; i < 4; i++)
		REQUIRE(count[i] >= 48 && count[i] <= 80);
	for (int i = 0; i < 4; i++)
		REQUIRE(wait_exit(kids[i]) == 0);
	for (int i = 0; i < CONNS; i++)
		REQUIRE(close(c[i]) == 0);
	REQUIRE(close(ready[0]) == 0 && close(report[0]) == 0);
}

/* A listening description of the group, the way a reload of nginx hands it on:
 * the process that made it forks a successor that inherits the description
 * and ends at once, with nothing taken from the queue. The successor of
 * member 3 starts to accept 1.5 s late (its queue is only 2 long and fills:
 * the circle skips it), the others at once. A successor must accept a
 * connection within 2 s of its first `accept`; it reports each on `report`
 * and 100 + index when it waited in vain, and ends after a quiet second. */
static void handoff_successor(int index, int lis, int report)
{
	if (index == 3)
		pause_ms(1500);
	int first = 1;
	for (;;) {
		struct pollfd pf = { lis, POLLIN, 0 };
		int n = poll(&pf, 1, first ? 2000 : 1000);
		if (n == 0) {
			char bad = (char)(100 + index);
			if (first && write(report, &bad, 1) != 1)
				_exit(30);
			_exit(first ? 31 : 0);
		}
		if (n < 0)
			_exit(32);
		int s = accept(lis, NULL, NULL);
		if (s < 0)
			_exit(33);
		first = 0;
		char tag = (char)index;
		if (write(report, &tag, 1) != 1)
			_exit(34);
	}
}

static void handoff_report(int report, int seen[4], int *bad)
{
	for (;;) {
		struct pollfd pf = { report, POLLIN, 0 };
		if (poll(&pf, 1, 0) != 1)
			return;
		char tag = 0;
		if (read(report, &tag, 1) != 1)
			return;
		if (tag >= 100)
			(*bad)++;
		else if (tag >= 0 && tag < 4)
			seen[(int)tag]++;
	}
}

/* One connection every 50 ms reaches every successor within 2 s, and a fifth
 * description that joins the group gets one within 2 s as well. */
static void reuseport_handoff(void)
{
	enum { FIRST = 40, SECOND = 40 };
	int ready[2], report[2];
	REQUIRE(pipe(ready) == 0 && pipe(report) == 0);
	int port = 18092;
	for (int i = 0; i < 4; i++) {
		pid_t maker = fork();
		REQUIRE(maker >= 0);
		if (maker == 0) {
			close(ready[0]);
			close(report[0]);
			int lis = socket(AF_INET, SOCK_STREAM, 0);
			int one = 1;
			if (lis < 0 || setsockopt(lis, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one) != 0)
				_exit(10);
			struct sockaddr_in any = at(INADDR_ANY, port);
			if (bind(lis, (struct sockaddr *)&any, sizeof any) != 0)
				_exit(12);
			if (listen(lis, i == 3 ? 2 : 16) != 0)
				_exit(13);
			pid_t successor = fork();
			if (successor < 0)
				_exit(14);
			if (successor == 0) {
				close(ready[1]);
				handoff_successor(i, lis, report[1]);
			}
			char r = 'R';
			if (write(ready[1], &r, 1) != 1)
				_exit(15);
			_exit(0);
		}
		REQUIRE(wait_exit(maker) == 0);
	}
	REQUIRE(close(ready[1]) == 0);
	char r[4];
	REQUIRE(read(ready[0], r, 4) == 4);
	REQUIRE(close(ready[0]) == 0);
	REQUIRE(close(report[1]) == 0);
	struct sockaddr_in a = at(LOOPBACK, port);
	int seen[4] = { 0, 0, 0, 0 }, bad = 0;
	int c[FIRST + SECOND];
	for (int i = 0; i < FIRST; i++) {
		c[i] = socket(AF_INET, SOCK_STREAM, 0);
		REQUIRE(c[i] >= 0);
		long t = now_ms();
		REQUIRE(connect(c[i], (struct sockaddr *)&a, sizeof a) == 0);
		/* A SYN that met a full queue waits for its second try. */
		if (now_ms() - t > 800)
			fail("a connection waited for a queue nobody takes from");
		handoff_report(report[0], seen, &bad);
		pause_ms(50);
	}
	/* The fifth description joins the group. */
	int fifth = socket(AF_INET, SOCK_STREAM, 0);
	int one = 1;
	REQUIRE(fifth >= 0 && setsockopt(fifth, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one) == 0);
	struct sockaddr_in any = at(INADDR_ANY, port);
	REQUIRE(bind(fifth, (struct sockaddr *)&any, sizeof any) == 0);
	REQUIRE(listen(fifth, 16) == 0);
	REQUIRE(fcntl(fifth, F_SETFL, O_NONBLOCK) == 0);
	long joined = now_ms();
	long got_fifth = -1;
	for (int i = FIRST; i < FIRST + SECOND; i++) {
		c[i] = socket(AF_INET, SOCK_STREAM, 0);
		REQUIRE(c[i] >= 0);
		long t = now_ms();
		REQUIRE(connect(c[i], (struct sockaddr *)&a, sizeof a) == 0);
		if (now_ms() - t > 800)
			fail("a connection waited for a queue nobody takes from");
		int s = accept(fifth, NULL, NULL);
		if (s >= 0) {
			if (got_fifth < 0)
				got_fifth = now_ms() - joined;
			REQUIRE(close(s) == 0);
		}
		handoff_report(report[0], seen, &bad);
		pause_ms(50);
	}
	printf("posix-net: reuseport-handoff note: successors %d %d %d %d, the fifth at %ld ms\n", seen[0], seen[1],
	       seen[2], seen[3], got_fifth);
	REQUIRE(got_fifth >= 0 && got_fifth <= 2000);
	/* The successors end after a quiet second; the pipe ends then. */
	for (;;) {
		struct pollfd pf = { report[0], POLLIN, 0 };
		if (poll(&pf, 1, 4000) != 1)
			fail("the successors did not end");
		char tag;
		ssize_t n = read(report[0], &tag, 1);
		if (n == 0)
			break;
		REQUIRE(n == 1);
		if (tag >= 100)
			bad++;
		else if (tag >= 0 && tag < 4)
			seen[(int)tag]++;
	}
	REQUIRE(bad == 0);
	for (int i = 0; i < 4; i++)
		REQUIRE(seen[i] >= 1);
	for (int i = 0; i < FIRST + SECOND; i++)
		REQUIRE(close(c[i]) == 0);
	REQUIRE(close(fifth) == 0 && close(report[0]) == 0);
}

/* A member of a group that accepts and closes, over and over: the sets of
 * places its queue sockets stood in go back to the service each time, so the
 * 320 sets last through 400 rounds (a set that stayed with a dead member would
 * run out and `listen` would fail). */
static void reuseport_churn(void)
{
	int one = 1;
	for (int i = 0; i < 400; i++) {
		int port = 19000 + i;
		int lis = socket(AF_INET, SOCK_STREAM, 0);
		REQUIRE(lis >= 0);
		REQUIRE(setsockopt(lis, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one) == 0);
		struct sockaddr_in any = at(INADDR_ANY, port);
		REQUIRE(bind(lis, (struct sockaddr *)&any, sizeof any) == 0);
		REQUIRE(listen(lis, 1) == 0);
		struct sockaddr_in a = at(LOOPBACK, port);
		int c = socket(AF_INET, SOCK_STREAM, 0);
		REQUIRE(c >= 0);
		REQUIRE(connect(c, (struct sockaddr *)&a, sizeof a) == 0);
		int s = accept(lis, NULL, NULL);
		REQUIRE(s >= 0);
		REQUIRE(close(c) == 0 && close(s) == 0 && close(lis) == 0);
	}
}

/* The port of a group is held by one user: a process of another user that asks
 * for the same port is refused, and so is one that did not ask for sharing. */
static void reuseport_uid(void)
{
	int one = 1;
	int lis = socket(AF_INET, SOCK_STREAM, 0);
	REQUIRE(lis >= 0);
	REQUIRE(setsockopt(lis, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one) == 0);
	struct sockaddr_in a = at(INADDR_ANY, 18091);
	REQUIRE(bind(lis, (struct sockaddr *)&a, sizeof a) == 0);
	REQUIRE(listen(lis, 4) == 0);
	/* The option after bind is refused. */
	int late = socket(AF_INET, SOCK_STREAM, 0);
	REQUIRE(late >= 0);
	struct sockaddr_in other = at(INADDR_ANY, 0);
	REQUIRE(bind(late, (struct sockaddr *)&other, sizeof other) == 0);
	errno = 0;
	REQUIRE(setsockopt(late, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one) == -1 && errno == EINVAL);
	REQUIRE(close(late) == 0);
	/* The same user may join. */
	int mate = socket(AF_INET, SOCK_STREAM, 0);
	REQUIRE(mate >= 0);
	REQUIRE(setsockopt(mate, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one) == 0);
	REQUIRE(bind(mate, (struct sockaddr *)&a, sizeof a) == 0);
	/* One that did not ask for sharing may not. */
	int plain = socket(AF_INET, SOCK_STREAM, 0);
	REQUIRE(plain >= 0);
	errno = 0;
	REQUIRE(bind(plain, (struct sockaddr *)&a, sizeof a) == -1 && errno == EADDRINUSE);
	pid_t kid = fork();
	REQUIRE(kid >= 0);
	if (kid == 0) {
		if (setuid(1000) != 0)
			_exit(20);
		int s = socket(AF_INET, SOCK_STREAM, 0);
		if (s < 0)
			_exit(21);
		int on = 1;
		if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on) != 0)
			_exit(22);
		errno = 0;
		if (bind(s, (struct sockaddr *)&a, sizeof a) != -1 || errno != EADDRINUSE)
			_exit(23);
		/* An address that only overlaps is the same: the rule is the user's. */
		struct sockaddr_in lo = at(LOOPBACK, 18091);
		int t = socket(AF_INET, SOCK_STREAM, 0);
		if (t < 0 || setsockopt(t, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on) != 0)
			_exit(24);
		errno = 0;
		if (bind(t, (struct sockaddr *)&lo, sizeof lo) != -1 || errno != EADDRINUSE)
			_exit(25);
		_exit(0);
	}
	REQUIRE(wait_exit(kid) == 0);
	REQUIRE(close(lis) == 0 && close(mate) == 0 && close(plain) == 0);
}

/* SO_LINGER with a time of 0: the close resets the connection. */
static void linger_0(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	struct linger l = { 1, 0 };
	REQUIRE(setsockopt(s, SOL_SOCKET, SO_LINGER, &l, sizeof l) == 0);
	struct linger back = { 0, 7 };
	socklen_t len = sizeof back;
	REQUIRE(getsockopt(s, SOL_SOCKET, SO_LINGER, &back, &len) == 0);
	REQUIRE(len == sizeof back && back.l_onoff != 0 && back.l_linger == 0);
	exchange(c, s, 'l');
	REQUIRE(close(s) == 0);
	struct pollfd pf = { c, POLLIN, 0 };
	REQUIRE(poll(&pf, 1, 3000) == 1);
	char buf[8];
	errno = 0;
	REQUIRE(recv(c, buf, sizeof buf, 0) == -1 && errno == ECONNRESET);
	REQUIRE(close(c) == 0 && close(lis) == 0);
}

static int linger_peer;
static volatile ssize_t linger_total;

static void *late_reader(void *arg)
{
	(void)arg;
	pause_ms(450);
	char buf[2048];
	ssize_t total = 0;
	for (;;) {
		ssize_t n = recv(linger_peer, buf, sizeof buf, 0);
		if (n <= 0)
			break;
		total += n;
	}
	linger_total = total;
	return NULL;
}

/* A close with a linger time waits until the peer has taken what was sent:
 * the peer is a socket in the small tier (a window of 4 KiB) that reads late. */
static void linger_wait(void)
{
	int port, lis = listener(4, &port);
	int junk[300];
	for (int i = 0; i < 300; i++) {
		junk[i] = socket(AF_INET, SOCK_DGRAM, 0);
		REQUIRE(junk[i] >= 0);
	}
	int c, s;
	pair(lis, port, &c, &s);
	int win = 0;
	socklen_t len = sizeof win;
	REQUIRE(getsockopt(c, SOL_SOCKET, SO_RCVBUF, &win, &len) == 0 && win == 4096);
	struct linger l = { 1, 10 };
	REQUIRE(setsockopt(s, SOL_SOCKET, SO_LINGER, &l, sizeof l) == 0);
	static char block[16384];
	memset(block, 'L', sizeof block);
	linger_peer = c;
	linger_total = -1;
	pthread_t reader;
	REQUIRE(pthread_create(&reader, NULL, late_reader, NULL) == 0);
	REQUIRE(send(s, block, sizeof block, MSG_WAITALL) == (ssize_t)sizeof block);
	long began = now_ms();
	REQUIRE(close(s) == 0);
	long took = now_ms() - began;
	printf("posix-net: linger-wait took %ld ms\n", took);
	REQUIRE(took >= 250 && took < 5000);
	REQUIRE(pthread_join(reader, NULL) == 0);
	REQUIRE(linger_total == (ssize_t)sizeof block);
	REQUIRE(close(c) == 0);
	for (int i = 0; i < 300; i++)
		REQUIRE(close(junk[i]) == 0);
	REQUIRE(close(lis) == 0);
}

/* SO_RCVTIMEO: a receive and an accept end with EAGAIN after the time. */
static void rcvtimeo(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	struct timeval tv = { 0, 200000 };
	REQUIRE(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) == 0);
	struct timeval back = { 9, 9 };
	socklen_t len = sizeof back;
	REQUIRE(getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &back, &len) == 0);
	REQUIRE(len == sizeof back && back.tv_sec == 0 && back.tv_usec == 200000);
	char buf[8];
	long began = now_ms();
	errno = 0;
	REQUIRE(recv(s, buf, sizeof buf, 0) == -1 && errno == EAGAIN);
	long took = now_ms() - began;
	printf("posix-net: rcvtimeo took %ld ms\n", took);
	REQUIRE(took >= 190 && took <= 700);
	/* Data that comes before the time is read. */
	REQUIRE(send(c, "d", 1, 0) == 1);
	REQUIRE(recv(s, buf, sizeof buf, 0) == 1);
	/* The time goes with the description: the listener's too. */
	REQUIRE(setsockopt(lis, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) == 0);
	began = now_ms();
	errno = 0;
	REQUIRE(accept(lis, NULL, NULL) == -1 && errno == EAGAIN);
	took = now_ms() - began;
	REQUIRE(took >= 190 && took <= 700);
	/* No time: the receive waits (a late byte arrives). */
	struct timeval none = { 0, 0 };
	REQUIRE(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &none, sizeof none) == 0);
	REQUIRE(close(c) == 0);
	REQUIRE(recv(s, buf, sizeof buf, 0) == 0);
	REQUIRE(close(s) == 0 && close(lis) == 0);
}

/* SO_SNDTIMEO: a send into a full buffer ends with EAGAIN after the time. */
static void sndtimeo(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	struct timeval tv = { 0, 200000 };
	REQUIRE(setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv) == 0);
	static char block[1024];
	memset(block, 'S', sizeof block);
	long total = 0;
	long began = 0;
	for (;;) {
		began = now_ms();
		ssize_t n = send(c, block, sizeof block, 0);
		if (n < 0) {
			REQUIRE(errno == EAGAIN);
			break;
		}
		total += n;
		REQUIRE(total < 200000);
	}
	long took = now_ms() - began;
	printf("posix-net: sndtimeo took %ld ms after %ld bytes\n", took, total);
	REQUIRE(total >= 16384);
	REQUIRE(took >= 190 && took <= 800);
	REQUIRE(close(c) == 0 && close(s) == 0 && close(lis) == 0);
}

/* accept4 and socket with SOCK_CLOFORK: the descriptor is not the child's. */
static void accept_clofork(void)
{
	int port, lis = listener(4, &port);
	struct sockaddr_in a = at(LOOPBACK, port);
	int c = socket(AF_INET, SOCK_STREAM, 0);
	REQUIRE(c >= 0);
	REQUIRE(connect(c, (struct sockaddr *)&a, sizeof a) == 0);
	int s = accept4(lis, NULL, NULL, SOCK_CLOFORK);
	REQUIRE(s >= 0);
	int flags = fcntl(s, F_GETFD);
	REQUIRE(flags >= 0 && (flags & FD_CLOFORK) && !(flags & FD_CLOEXEC));
	int plain = socket(AF_INET, SOCK_STREAM | SOCK_CLOFORK | SOCK_CLOEXEC, 0);
	REQUIRE(plain >= 0);
	flags = fcntl(plain, F_GETFD);
	REQUIRE(flags >= 0 && (flags & FD_CLOFORK) && (flags & FD_CLOEXEC));
	pid_t kid = fork();
	REQUIRE(kid >= 0);
	if (kid == 0) {
		errno = 0;
		if (fcntl(s, F_GETFD) != -1 || errno != EBADF)
			_exit(30);
		if (fcntl(plain, F_GETFD) != -1 || errno != EBADF)
			_exit(31);
		if (fcntl(lis, F_GETFD) < 0)
			_exit(32);
		_exit(0);
	}
	REQUIRE(wait_exit(kid) == 0);
	exchange(c, s, 'f');
	REQUIRE(close(c) == 0 && close(s) == 0 && close(plain) == 0 && close(lis) == 0);
}

/* A socket of TCP goes to another process in a message of AF_UNIX; the child
 * adds to the stream and the peer reads both parts in order. */
static void scm_net(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	int u[2];
	REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, u) == 0);
	REQUIRE(passes_held(u[0]) == 0);
	pid_t kid = fork();
	REQUIRE(kid >= 0);
	if (kid == 0) {
		close(u[0]);
		close(s);
		close(c);
		close(lis);
		int got[4];
		int fl = 0;
		int n = recv_fds(u[1], got, 4, &fl);
		if (n != 1) {
			printf("posix-net: scm-net note: the child received %d, flags %d, errno %d\n", n, fl, errno);
			fflush(stdout);
			_exit(40);
		}
		if (write(got[0], "cd", 2) != 2)
			_exit(41);
		/* The pass is spent: the service holds none. */
		int value = -1;
		socklen_t len = sizeof value;
		if (getsockopt(u[1], SOL_SOCKET, SO_STAFETO_PASSES, &value, &len) != 0 || value != 0)
			_exit(42);
		close(got[0]);
		_exit(0);
	}
	close(u[1]);
	REQUIRE(send(s, "ab", 2, 0) == 2);
	REQUIRE(send_fds(u[0], &s, 1) == 1);
	REQUIRE(passes_held(u[0]) <= 1);
	REQUIRE(close(s) == 0);
	REQUIRE(wait_exit(kid) == 0);
	char buf[8];
	ssize_t got = 0;
	while (got < 4) {
		struct pollfd pf = { c, POLLIN, 0 };
		REQUIRE(poll(&pf, 1, 3000) == 1);
		ssize_t n = recv(c, buf + got, sizeof buf - got, 0);
		REQUIRE(n > 0);
		got += n;
	}
	REQUIRE(got == 4 && memcmp(buf, "abcd", 4) == 0);
	/* Both holders let go: the peer sees the end. */
	REQUIRE(sees_end(c, 3000));
	passes_become(u[0], 0, 3000);
	REQUIRE(close(c) == 0 && close(u[0]) == 0 && close(lis) == 0);
}

/* Five sockets in one message are too many; four go. */
static void scm_five(void)
{
	int port, lis = listener(8, &port);
	int c[5], s[5];
	for (int i = 0; i < 5; i++)
		pair(lis, port, &c[i], &s[i]);
	int u[2];
	REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, u) == 0);
	errno = 0;
	REQUIRE(send_fds(u[0], s, 5) == -1 && errno == ETOOMANYREFS);
	REQUIRE(passes_held(u[0]) == 0);
	/* The refusal left the sockets alone. */
	for (int i = 0; i < 5; i++)
		exchange(c[i], s[i], (char)('0' + i));
	REQUIRE(send_fds(u[0], s, 4) == 1);
	int got[8], flags = 0;
	REQUIRE(recv_fds(u[1], got, 8, &flags) == 4 && !(flags & MSG_CTRUNC));
	for (int i = 0; i < 4; i++) {
		REQUIRE(write(got[i], "k", 1) == 1);
		char b = 0;
		REQUIRE(recv(c[i], &b, 1, 0) == 1 && b == 'k');
		REQUIRE(close(got[i]) == 0);
	}
	for (int i = 0; i < 5; i++)
		REQUIRE(close(c[i]) == 0 && close(s[i]) == 0);
	REQUIRE(close(u[0]) == 0 && close(u[1]) == 0 && close(lis) == 0);
}

/* A pipe, a socket of TCP and a pipe in one message come in that order. */
static void scm_mixed(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	int p[2], u[2];
	REQUIRE(pipe(p) == 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, u) == 0);
	int out[3] = { p[0], s, p[1] };
	REQUIRE(send_fds(u[0], out, 3) == 1);
	int got[8];
	REQUIRE(recv_fds(u[1], got, 8, NULL) == 3);
	struct stat st;
	REQUIRE(fstat(got[0], &st) == 0 && S_ISFIFO(st.st_mode));
	REQUIRE(fstat(got[1], &st) == 0 && S_ISSOCK(st.st_mode));
	REQUIRE(fstat(got[2], &st) == 0 && S_ISFIFO(st.st_mode));
	/* The first is the read end and the third the write end of the pipe. */
	REQUIRE(write(p[1], "y", 1) == 1);
	char b = 0;
	REQUIRE(read(got[0], &b, 1) == 1 && b == 'y');
	REQUIRE(write(got[2], "x", 1) == 1);
	REQUIRE(read(p[0], &b, 1) == 1 && b == 'x');
	/* The second is the socket: it reaches the peer. */
	REQUIRE(write(got[1], "t", 1) == 1);
	REQUIRE(recv(c, &b, 1, 0) == 1 && b == 't');
	for (int i = 0; i < 3; i++)
		REQUIRE(close(got[i]) == 0);
	REQUIRE(close(p[0]) == 0 && close(p[1]) == 0 && close(s) == 0 && close(c) == 0);
	REQUIRE(close(u[0]) == 0 && close(u[1]) == 0 && close(lis) == 0);
}

static int wait_sender;
static int wait_socket;
static volatile int wait_done;
static volatile ssize_t wait_result;

static void *scm_sender(void *arg)
{
	(void)arg;
	wait_result = send_fds(wait_sender, &wait_socket, 1);
	wait_done = 1;
	return NULL;
}

/* The buffer of messages with descriptions is full: a send with a socket
 * waits, holding the pass, until the reader takes a message. */
static void scm_wait(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	int u[2];
	REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, u) == 0);
	int p[2];
	REQUIRE(pipe(p) == 0);
	/* Four messages with a description fill what a socket holds. */
	for (int i = 0; i < 4; i++)
		REQUIRE(send_fds(u[0], &p[0], 1) == 1);
	REQUIRE(passes_held(u[0]) == 0);
	wait_sender = u[0];
	wait_socket = s;
	wait_done = 0;
	wait_result = -2;
	pthread_t sender;
	REQUIRE(pthread_create(&sender, NULL, scm_sender, NULL) == 0);
	pause_ms(400);
	REQUIRE(wait_done == 0);
	/* The send that waits holds the pass. */
	REQUIRE(passes_held(u[0]) == 1);
	int got[4];
	REQUIRE(recv_fds(u[1], got, 4, NULL) == 1);
	REQUIRE(close(got[0]) == 0);
	long end = now_ms() + 3000;
	while (!wait_done) {
		REQUIRE(now_ms() < end);
		pause_ms(10);
	}
	REQUIRE(pthread_join(sender, NULL) == 0);
	REQUIRE(wait_result == 1);
	for (int i = 0; i < 3; i++) {
		REQUIRE(recv_fds(u[1], got, 4, NULL) == 1);
		REQUIRE(close(got[0]) == 0);
	}
	REQUIRE(recv_fds(u[1], got, 4, NULL) == 1);
	REQUIRE(write(got[0], "z", 1) == 1);
	char b = 0;
	REQUIRE(recv(c, &b, 1, 0) == 1 && b == 'z');
	REQUIRE(close(got[0]) == 0 && close(s) == 0);
	passes_become(u[0], 0, 3000);
	REQUIRE(sees_end(c, 3000));
	REQUIRE(close(c) == 0 && close(p[0]) == 0 && close(p[1]) == 0);
	REQUIRE(close(u[0]) == 0 && close(u[1]) == 0 && close(lis) == 0);
}

/* The process that was to receive a socket ends without reading: the socket
 * goes with its message, and the peer sees the end. */
static void scm_dead_receiver(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	int u[2], gate[2];
	REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, u) == 0 && pipe(gate) == 0);
	pid_t kid = fork();
	REQUIRE(kid >= 0);
	if (kid == 0) {
		close(u[0]);
		close(gate[1]);
		close(s);
		close(c);
		close(lis);
		char b;
		/* Waits for the word, then ends without reading its socket. */
		if (read(gate[0], &b, 1) != 1)
			_exit(50);
		_exit(0);
	}
	close(u[1]);
	close(gate[0]);
	int before = passes_held(u[0]);
	REQUIRE(before == 0);
	REQUIRE(send_fds(u[0], &s, 1) == 1);
	REQUIRE(passes_held(u[0]) == 1);
	REQUIRE(close(s) == 0);
	/* The description lives in the message: no end seen. */
	REQUIRE(!sees_end(c, 300));
	REQUIRE(write(gate[1], "g", 1) == 1);
	REQUIRE(wait_exit(kid) == 0);
	passes_become(u[0], before, 3000);
	REQUIRE(sees_end(c, 3000));
	REQUIRE(close(c) == 0 && close(u[0]) == 0 && close(gate[1]) == 0 && close(lis) == 0);
}

/* The socket that holds a message with a socket closes: the pass goes. */
static void scm_close_socket(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	int u[2];
	REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, u) == 0);
	int before = passes_held(u[0]);
	REQUIRE(send_fds(u[0], &s, 1) == 1);
	REQUIRE(passes_held(u[0]) == before + 1);
	REQUIRE(close(s) == 0);
	REQUIRE(!sees_end(c, 300));
	REQUIRE(close(u[1]) == 0);
	passes_become(u[0], before, 3000);
	REQUIRE(sees_end(c, 3000));
	REQUIRE(close(c) == 0 && close(u[0]) == 0 && close(lis) == 0);
}

/* A control buffer with room for one of two sockets: MSG_CTRUNC, one
 * descriptor, and the other socket is gone (its peer sees the end). */
static void scm_ctrunc(void)
{
	int port, lis = listener(4, &port);
	int c[2], s[2];
	for (int i = 0; i < 2; i++)
		pair(lis, port, &c[i], &s[i]);
	int u[2];
	REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, u) == 0);
	REQUIRE(send_fds(u[0], s, 2) == 1);
	REQUIRE(close(s[0]) == 0 && close(s[1]) == 0);
	int got[4], flags = 0;
	REQUIRE(recv_fds(u[1], got, 1, &flags) == 1);
	REQUIRE(flags & MSG_CTRUNC);
	REQUIRE(write(got[0], "1", 1) == 1);
	char b = 0;
	REQUIRE(recv(c[0], &b, 1, 0) == 1 && b == '1');
	REQUIRE(sees_end(c[1], 3000));
	REQUIRE(!sees_end(c[0], 200));
	passes_become(u[0], 0, 3000);
	REQUIRE(close(got[0]) == 0);
	REQUIRE(sees_end(c[0], 3000));
	for (int i = 0; i < 2; i++)
		REQUIRE(close(c[i]) == 0);
	REQUIRE(close(u[0]) == 0 && close(u[1]) == 0 && close(lis) == 0);
}

static void on_retry_alarm(int sig)
{
	(void)sig;
}

/* A send with a socket that waits is ended by a signal: the passes it held go,
 * and the same send made again (the library exports the socket again) goes
 * through once the reader has taken a message. */
static void scm_retry(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	int u[2], p[2];
	REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, u) == 0 && pipe(p) == 0);
	for (int i = 0; i < 4; i++)
		REQUIRE(send_fds(u[0], &p[0], 1) == 1);
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_retry_alarm;
	REQUIRE(sigaction(SIGALRM, &sa, NULL) == 0);
	alarm(1);
	errno = 0;
	REQUIRE(send_fds(u[0], &s, 1) == -1 && errno == EINTR);
	/* The handles the cancelled send held close in steps of the service. */
	passes_become(u[0], 0, 3000);
	REQUIRE(!sees_end(c, 200));
	int got[4];
	REQUIRE(recv_fds(u[1], got, 4, NULL) == 1);
	REQUIRE(close(got[0]) == 0);
	REQUIRE(send_fds(u[0], &s, 1) == 1);
	for (int i = 0; i < 3; i++) {
		REQUIRE(recv_fds(u[1], got, 4, NULL) == 1);
		REQUIRE(close(got[0]) == 0);
	}
	REQUIRE(recv_fds(u[1], got, 4, NULL) == 1);
	REQUIRE(write(got[0], "r", 1) == 1);
	char b = 0;
	REQUIRE(recv(c, &b, 1, 0) == 1 && b == 'r');
	REQUIRE(close(got[0]) == 0 && close(s) == 0);
	REQUIRE(sees_end(c, 3000));
	REQUIRE(close(c) == 0 && close(p[0]) == 0 && close(p[1]) == 0);
	REQUIRE(close(u[0]) == 0 && close(u[1]) == 0 && close(lis) == 0);
}

/* A root (a program and its children) holds eight passes at once: a ninth is
 * ENOBUFS, whichever of its processes sends it. */
static void scm_root(void)
{
	int port, lis = listener(16, &port);
	int c[10], s[10];
	for (int i = 0; i < 10; i++)
		pair(lis, port, &c[i], &s[i]);
	int u[2];
	REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, u) == 0);
	REQUIRE(send_fds(u[0], s, 4) == 1);
	REQUIRE(send_fds(u[0], s + 4, 4) == 1);
	REQUIRE(passes_held(u[0]) == 8);
	errno = 0;
	REQUIRE(send_fds(u[0], s + 8, 1) == -1 && errno == ENOBUFS);
	REQUIRE(passes_held(u[0]) == 8);
	/* The children of the root share its eight. */
	int v[2];
	REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, v) == 0);
	pid_t kid = fork();
	REQUIRE(kid >= 0);
	if (kid == 0) {
		close(u[0]);
		close(u[1]);
		errno = 0;
		if (send_fds(v[0], s + 9, 1) != -1 || errno != ENOBUFS)
			_exit(60);
		_exit(0);
	}
	REQUIRE(wait_exit(kid) == 0);
	/* The reader takes both messages: the places come back. */
	int got[4];
	for (int i = 0; i < 2; i++) {
		REQUIRE(recv_fds(u[1], got, 4, NULL) == 4);
		for (int k = 0; k < 4; k++)
			REQUIRE(close(got[k]) == 0);
	}
	for (int i = 0; i < 10; i++)
		REQUIRE(close(s[i]) == 0);
	passes_become(u[0], 0, 3000);
	REQUIRE(send_fds(u[0], &c[0], 1) == 1);
	REQUIRE(recv_fds(u[1], got, 4, NULL) == 1);
	REQUIRE(close(got[0]) == 0);
	for (int i = 0; i < 10; i++)
		REQUIRE(close(c[i]) == 0);
	REQUIRE(close(u[0]) == 0 && close(u[1]) == 0 && close(v[0]) == 0 && close(v[1]) == 0);
	REQUIRE(close(lis) == 0);
}

static int depart_u;
static int depart_sock[8];

static void *depart_sender(void *arg)
{
	int k = (int)(intptr_t)arg;
	send_fds(depart_u, depart_sock + 4 * k, 4);
	return NULL;
}

/* A process ends with two sends of four sockets each waiting: the handles
 * they held go in steps, and the peers of the eight sockets see the end. */
static void scm_depart(void)
{
	int port, lis = listener(16, &port);
	int c[8], s[8];
	int u[2], p[2], gate[2];
	for (int i = 0; i < 8; i++)
		pair(lis, port, &c[i], &s[i]);
	REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, u) == 0 && pipe(p) == 0 && pipe(gate) == 0);
	pid_t kid = fork();
	REQUIRE(kid >= 0);
	if (kid == 0) {
		close(gate[1]);
		for (int i = 0; i < 4; i++)
			if (send_fds(u[0], &p[0], 1) != 1)
				_exit(70);
		depart_u = u[0];
		memcpy(depart_sock, s, sizeof s);
		pthread_t t[2];
		for (int k = 0; k < 2; k++)
			if (pthread_create(&t[k], NULL, depart_sender, (void *)(intptr_t)k) != 0)
				_exit(71);
		char b;
		if (read(gate[0], &b, 1) != 1)
			_exit(72);
		_exit(0);
	}
	close(gate[0]);
	for (int i = 0; i < 8; i++)
		REQUIRE(close(s[i]) == 0);
	/* Both sends wait with their eight handles. */
	long end = now_ms() + 3000;
	while (passes_held(u[1]) != 8) {
		REQUIRE(now_ms() < end);
		pause_ms(10);
	}
	REQUIRE(write(gate[1], "g", 1) == 1);
	REQUIRE(wait_exit(kid) == 0);
	passes_become(u[1], 0, 5000);
	for (int i = 0; i < 8; i++)
		REQUIRE(sees_end(c[i], 3000));
	for (int i = 0; i < 8; i++)
		REQUIRE(close(c[i]) == 0);
	REQUIRE(close(u[0]) == 0 && close(u[1]) == 0 && close(p[0]) == 0 && close(p[1]) == 0);
	REQUIRE(close(gate[1]) == 0 && close(lis) == 0);
}

static int excl_ep[2];
static volatile int excl_woke;

static void *excl_waiter(void *arg)
{
	int k = (int)(intptr_t)arg;
	struct epoll_event ev[4];
	int n = epoll_wait(excl_ep[k], ev, 4, 2500);
	if (n == 1)
		excl_woke++;
	return NULL;
}

/* Two sets wait on one listening socket with EPOLLEXCLUSIVE: one connection
 * wakes one of them, the next wakes the other. */
static void epoll_exclusive(void)
{
	int port, lis = listener(4, &port);
	for (int i = 0; i < 2; i++) {
		excl_ep[i] = ep_new();
		ep_add(excl_ep[i], lis, EPOLLIN | EPOLLEXCLUSIVE, (uint64_t)i);
	}
	excl_woke = 0;
	pthread_t t[2];
	for (int i = 0; i < 2; i++)
		REQUIRE(pthread_create(&t[i], NULL, excl_waiter, (void *)(intptr_t)i) == 0);
	pause_ms(300);
	struct sockaddr_in a = at(LOOPBACK, port);
	int c1 = socket(AF_INET, SOCK_STREAM, 0);
	REQUIRE(c1 >= 0);
	REQUIRE(connect(c1, (struct sockaddr *)&a, sizeof a) == 0);
	pause_ms(600);
	if (excl_woke != 1)
		printf("posix-net: epoll-exclusive note: %d sets woke after the first connection\n", excl_woke);
	REQUIRE(excl_woke == 1);
	int c2 = socket(AF_INET, SOCK_STREAM, 0);
	REQUIRE(c2 >= 0);
	REQUIRE(connect(c2, (struct sockaddr *)&a, sizeof a) == 0);
	for (int i = 0; i < 2; i++)
		REQUIRE(pthread_join(t[i], NULL) == 0);
	if (excl_woke != 2)
		printf("posix-net: epoll-exclusive note: %d sets woke after the second connection\n", excl_woke);
	REQUIRE(excl_woke == 2);
	REQUIRE(close(c1) == 0 && close(c2) == 0);
	for (int i = 0; i < 2; i++)
		REQUIRE(close(excl_ep[i]) == 0);
	REQUIRE(close(lis) == 0);
}

/* ---------------------------------------------------------------- stage P4b-1:
 * the shared buffer with the network service, the owner of a socket's
 * signals and RDHUP of AF_UNIX. */

#define SO_STAFETO_BUFFERS 0x7351
#define SO_STAFETO_BUFFERED 0x7352

/* The byte at `i` of the streams of these checks. */
static unsigned char stream_byte(size_t i, unsigned salt)
{
	return (unsigned char)(i * 7u + (i >> 9) + salt);
}

static void fill(unsigned char *p, size_t from, size_t n, unsigned salt)
{
	for (size_t k = 0; k < n; k++)
		p[k] = stream_byte(from + k, salt);
}

/* Whether `n` bytes at `p` are the stream's from `from`. */
static int same(const unsigned char *p, size_t from, size_t n, unsigned salt)
{
	for (size_t k = 0; k < n; k++)
		if (p[k] != stream_byte(from + k, salt))
			return 0;
	return 1;
}

/* SO_STAFETO_BUFFERS (the sessions with a buffer, bits 0-15) or
 * SO_STAFETO_BUFFERED (KiB) through socket `fd`. */
static unsigned buffers_word(int fd, int name)
{
	unsigned value = 0;
	socklen_t len = sizeof value;
	REQUIRE(getsockopt(fd, SOL_SOCKET, name, &value, &len) == 0 && len == 4);
	return value;
}

/* A socket of the service to ask the two options through. */
static unsigned buffers_now(int name)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	REQUIRE(fd >= 0);
	unsigned value = buffers_word(fd, name);
	REQUIRE(close(fd) == 0);
	return value;
}

/* A reader of a stream on its own thread: `want` bytes in pieces of
 * `piece`, a pause of `pause_ms` after each, checked against `salt`. */
struct reader {
	int fd;
	size_t want;
	size_t piece;
	long pause_ms;
	unsigned salt;
	size_t got;
	int bad;
	int error;
};

/* The places the readers read into, one for each of four at once. */
static unsigned char read_space[4][16384];
static pthread_mutex_t read_space_lock = PTHREAD_MUTEX_INITIALIZER;
static int read_space_used[4];

static void *read_all(void *arg)
{
	struct reader *r = arg;
	int slot = -1;
	pthread_mutex_lock(&read_space_lock);
	for (int i = 0; i < 4 && slot < 0; i++)
		if (!read_space_used[i]) {
			read_space_used[i] = 1;
			slot = i;
		}
	pthread_mutex_unlock(&read_space_lock);
	if (slot < 0) {
		r->bad = 1;
		shutdown(r->fd, SHUT_RDWR);
		return NULL;
	}
	unsigned char *chunk = read_space[slot];
	while (r->got < r->want) {
		size_t ask = r->piece < sizeof read_space[0] ? r->piece : sizeof read_space[0];
		ssize_t n = recv(r->fd, chunk, ask, 0);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			r->error = n < 0 ? errno : -1;
			break;
		}
		if (!same(chunk, r->got, (size_t)n, r->salt))
			r->bad = 1;
		r->got += (size_t)n;
		if (r->pause_ms)
			pause_ms(r->pause_ms);
	}
	/* A reader that stops lets its sender go. */
	if (r->got < r->want)
		shutdown(r->fd, SHUT_RDWR);
	pthread_mutex_lock(&read_space_lock);
	read_space_used[slot] = 0;
	pthread_mutex_unlock(&read_space_lock);
	return NULL;
}

/* 64 KiB one way with one blocking send; the reader takes them on a thread. */
static void buffer_send(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	static unsigned char out[65536];
	fill(out, 0, sizeof out, 1);
	unsigned before = buffers_word(c, SO_STAFETO_BUFFERED);
	struct reader r = { s, sizeof out, 4096, 0, 1, 0, 0, 0 };
	pthread_t t;
	REQUIRE(pthread_create(&t, NULL, read_all, &r) == 0);
	long began = now_ms();
	REQUIRE(send(c, out, sizeof out, 0) == (ssize_t)sizeof out);
	REQUIRE(pthread_join(t, NULL) == 0);
	long took = now_ms() - began;
	REQUIRE(r.got == sizeof out && !r.bad);
	printf("posix-net: buffer-send took %ld ms\n", took);
	unsigned after = buffers_word(c, SO_STAFETO_BUFFERED);
	REQUIRE(after - before >= 64);
	REQUIRE(close(c) == 0 && close(s) == 0 && close(lis) == 0);
}

struct writer {
	int fd;
	size_t total;
	size_t piece;
	unsigned salt;
	int bad;
};

static void *write_all(void *arg)
{
	struct writer *w = arg;
	unsigned char chunk[4096];
	size_t done = 0;
	if (w->piece > sizeof chunk) {
		w->bad = 1;
		return NULL;
	}
	while (done < w->total) {
		size_t n = w->total - done < w->piece ? w->total - done : w->piece;
		fill(chunk, done, n, w->salt);
		ssize_t sent = send(w->fd, chunk, n, 0);
		if (sent <= 0) {
			w->bad = 1;
			break;
		}
		done += (size_t)sent;
	}
	return NULL;
}

/* 64 KiB in one recv with MSG_WAITALL. */
static void buffer_recv(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	static unsigned char in[65536];
	struct writer w = { c, sizeof in, 3000, 2, 0 };
	pthread_t t;
	REQUIRE(pthread_create(&t, NULL, write_all, &w) == 0);
	REQUIRE(recv(s, in, sizeof in, MSG_WAITALL) == (ssize_t)sizeof in);
	/* The bytes before the join: a wrong count leaves the writer waiting. */
	REQUIRE(same(in, 0, sizeof in, 2));
	REQUIRE(pthread_join(t, NULL) == 0);
	REQUIRE(!w.bad);
	REQUIRE(close(c) == 0 && close(s) == 0 && close(lis) == 0);
}

/* A non-blocking send of 256 KiB takes what the socket has room for; the
 * edge of EPOLLOUT comes when the reader makes room, and all of it arrives. */
static void buffer_nonblock(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	REQUIRE(fcntl(c, F_SETFL, fcntl(c, F_GETFL) | O_NONBLOCK) == 0);
	static unsigned char out[262144];
	static unsigned char in[16384];
	fill(out, 0, sizeof out, 3);
	int ep = ep_new();
	struct epoll_event ev[4];
	ep_add(ep, c, EPOLLOUT | EPOLLET, 7);
	REQUIRE(ep_wait(ep, ev, 2000) == 1 && (ev[0].events & EPOLLOUT));
	ssize_t first = send(c, out, sizeof out, 0);
	REQUIRE(first > 0 && first < (ssize_t)sizeof out);
	REQUIRE(send(c, out + first, sizeof out - (size_t)first, 0) == -1 && errno == EAGAIN);
	size_t sent = (size_t)first, got = 0;
	long end = now_ms() + 20000;
	while (got < sizeof out) {
		REQUIRE(now_ms() < end);
		ssize_t n = recv(s, in, sizeof in, MSG_DONTWAIT);
		if (n > 0) {
			REQUIRE(same(in, got, (size_t)n, 3));
			got += (size_t)n;
		}
		if (sent < sizeof out) {
			if (n <= 0)
				pause_ms(1);
			if (ep_wait(ep, ev, 0) == 1) {
				REQUIRE(ev[0].events & EPOLLOUT);
				ssize_t more = send(c, out + sent, sizeof out - sent, 0);
				REQUIRE(more > 0 || errno == EAGAIN);
				if (more > 0)
					sent += (size_t)more;
			}
		} else if (n <= 0) {
			pause_ms(1);
		}
	}
	REQUIRE(sent == sizeof out);
	REQUIRE(close(c) == 0 && close(s) == 0 && close(ep) == 0 && close(lis) == 0);
}

/* A header of 200 bytes and a body of 64 KiB in one writev: in order, and
 * through the buffer. */
static void buffer_writev(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	static unsigned char whole[200 + 65536];
	fill(whole, 0, sizeof whole, 4);
	struct iovec iov[2] = { { whole, 200 }, { whole + 200, 65536 } };
	unsigned before = buffers_word(c, SO_STAFETO_BUFFERED);
	struct reader r = { s, sizeof whole, 700, 0, 4, 0, 0, 0 };
	pthread_t t;
	REQUIRE(pthread_create(&t, NULL, read_all, &r) == 0);
	REQUIRE(writev(c, iov, 2) == (ssize_t)sizeof whole);
	REQUIRE(pthread_join(t, NULL) == 0);
	REQUIRE(r.got == sizeof whole && !r.bad);
	/* The reader read by messages (700 bytes): the counter grew by the send. */
	REQUIRE(buffers_word(c, SO_STAFETO_BUFFERED) - before >= 64);
	/* Eight parts of 700 bytes, each small enough for a message: as one
	 * send of 5 600 bytes they go through the buffer, part by part none
	 * would. */
	struct iovec small[8];
	for (int i = 0; i < 8; i++) {
		small[i].iov_base = whole + 700 * i;
		small[i].iov_len = 700;
	}
	before = buffers_word(c, SO_STAFETO_BUFFERED);
	r = (struct reader){ s, 5600, 700, 0, 4, 0, 0, 0 };
	REQUIRE(pthread_create(&t, NULL, read_all, &r) == 0);
	REQUIRE(writev(c, small, 8) == 5600);
	REQUIRE(pthread_join(t, NULL) == 0);
	REQUIRE(r.got == 5600 && !r.bad);
	REQUIRE(buffers_word(c, SO_STAFETO_BUFFERED) - before >= 5);
	REQUIRE(close(c) == 0 && close(s) == 0 && close(lis) == 0);
}

struct sender {
	int fd;
	int bad;
	ssize_t sent;
	int error;
};

/* The bytes the four senders of `buffer-threads` send (salt 10). */
static unsigned char quarter[262144];

static void *send_quarter(void *arg)
{
	struct sender *x = arg;
	x->sent = send(x->fd, quarter, sizeof quarter, MSG_NOSIGNAL);
	x->error = errno;
	if (x->sent != (ssize_t)sizeof quarter)
		x->bad = 1;
	return NULL;
}

/* Four threads send 256 KiB each into four sockets to slow readers. */
static void buffer_threads(void)
{
	int port, lis = listener(8, &port);
	int c[4], s[4];
	pthread_t ts[4], tr[4];
	struct sender x[4];
	struct reader r[4];
	fill(quarter, 0, sizeof quarter, 10);
	for (int i = 0; i < 4; i++) {
		pair(lis, port, &c[i], &s[i]);
		x[i] = (struct sender){ c[i], 0, 0, 0 };
		r[i] = (struct reader){ s[i], 262144, 8192, 1, 10, 0, 0, 0 };
	}
	for (int i = 0; i < 4; i++) {
		REQUIRE(pthread_create(&tr[i], NULL, read_all, &r[i]) == 0);
		REQUIRE(pthread_create(&ts[i], NULL, send_quarter, &x[i]) == 0);
	}
	for (int i = 0; i < 4; i++) {
		REQUIRE(pthread_join(ts[i], NULL) == 0 && pthread_join(tr[i], NULL) == 0);
		if (x[i].bad || r[i].got != 262144 || r[i].bad)
			printf("posix-net: buffer-threads note: %d sent %ld errno %d, read %lu errno %d bad %d\n",
			       i, (long)x[i].sent, x[i].error, (unsigned long)r[i].got, r[i].error, r[i].bad);
		REQUIRE(!x[i].bad && r[i].got == 262144 && !r[i].bad);
		REQUIRE(close(c[i]) == 0 && close(s[i]) == 0);
	}
	REQUIRE(close(lis) == 0);
}

/* A forked child has no buffer of the parent's: it sends 64 KiB and the
 * service has one buffer more, its own. */
static void buffer_fork(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	static unsigned char out[65536];
	/* The parent has its buffer (the checks before took it). */
	fill(out, 0, sizeof out, 5);
	struct reader warm = { s, sizeof out, 16384, 0, 5, 0, 0, 0 };
	pthread_t t;
	REQUIRE(pthread_create(&t, NULL, read_all, &warm) == 0);
	REQUIRE(send(c, out, sizeof out, 0) == (ssize_t)sizeof out);
	REQUIRE(pthread_join(t, NULL) == 0 && !warm.bad);
	unsigned base = buffers_word(c, SO_STAFETO_BUFFERS) & 0xFFFF;
	struct reader r = { s, sizeof out, 16384, 0, 6, 0, 0, 0 };
	REQUIRE(pthread_create(&t, NULL, read_all, &r) == 0);
	pid_t kid = fork();
	REQUIRE(kid >= 0);
	if (kid == 0) {
		fill(out, 0, sizeof out, 6);
		if (send(c, out, sizeof out, 0) != (ssize_t)sizeof out)
			_exit(71);
		unsigned now = buffers_word(c, SO_STAFETO_BUFFERS) & 0xFFFF;
		_exit(now == base + 1 ? 0 : 72);
	}
	REQUIRE(wait_exit(kid) == 0);
	REQUIRE(pthread_join(t, NULL) == 0);
	REQUIRE(r.got == sizeof out && !r.bad);
	REQUIRE(close(c) == 0 && close(s) == 0 && close(lis) == 0);
}

/* A stream through the loopback of this process, 64 KiB through it, and the
 * buffers of the service after. */
static unsigned send_own_64k(void)
{
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	static unsigned char out[65536];
	fill(out, 0, sizeof out, 8);
	struct reader r = { s, sizeof out, 700, 0, 8, 0, 0, 0 };
	pthread_t t;
	REQUIRE(pthread_create(&t, NULL, read_all, &r) == 0);
	REQUIRE(send(c, out, sizeof out, 0) == (ssize_t)sizeof out);
	REQUIRE(pthread_join(t, NULL) == 0 && r.got == sizeof out && !r.bad);
	unsigned now = buffers_word(c, SO_STAFETO_BUFFERS) & 0xFFFF;
	REQUIRE(close(c) == 0 && close(s) == 0 && close(lis) == 0);
	return now;
}

/* The image after `exec` in `buffer-exec`: the service let the old image's
 * buffer go, and this image takes its own at its first large send. */
static int buffer_exec_child(unsigned base)
{
	check = "buffer-exec";
	unsigned after_exec = buffers_now(SO_STAFETO_BUFFERS) & 0xFFFF;
	if (after_exec != base) {
		printf("posix-net: buffer-exec failed: %u buffers after exec, %u before the child's errno 0\n",
		       after_exec, base);
		return 73;
	}
	return send_own_64k() == base + 1 ? 0 : 74;
}

/* A process with a buffer runs `exec` of itself. */
static void buffer_exec(void)
{
	unsigned base = buffers_now(SO_STAFETO_BUFFERS) & 0xFFFF;
	pid_t kid = fork();
	REQUIRE(kid >= 0);
	if (kid == 0) {
		if (send_own_64k() != base + 1)
			_exit(75);
		char number[16];
		snprintf(number, sizeof number, "%u", base);
		char *args[] = { (char *)self, "buffer-exec-child", number, NULL };
		execve(self, args, environ);
		_exit(76);
	}
	REQUIRE(wait_exit(kid) == 0);
}

static volatile sig_atomic_t interrupted;
static void on_usr1(int sig)
{
	(void)sig;
	interrupted = 1;
}

struct poke {
	pthread_t target;
	long after_ms;
};

static void *poke_later(void *arg)
{
	struct poke *p = arg;
	pause_ms(p->after_ms);
	pthread_kill(p->target, SIGUSR1);
	return NULL;
}

/* The reader of `buffer-signal`: nothing until the signal came, so that the
 * send waits for room when it comes, then everything. */
static void *read_after_signal(void *arg)
{
	while (!interrupted)
		pause_ms(5);
	return read_all(arg);
}

/* A signal without SA_RESTART in the middle of a blocking send of 1 MiB:
 * the count of the bytes that went, and a second send takes the rest. */
static void buffer_signal(void)
{
	struct sigaction sa, old;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_usr1;
	REQUIRE(sigaction(SIGUSR1, &sa, &old) == 0);
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	static unsigned char out[1048576];
	fill(out, 0, sizeof out, 9);
	struct reader r = { s, sizeof out, 16384, 0, 9, 0, 0, 0 };
	pthread_t tr, tp;
	struct poke p = { pthread_self(), 150 };
	interrupted = 0;
	REQUIRE(pthread_create(&tr, NULL, read_after_signal, &r) == 0);
	REQUIRE(pthread_create(&tp, NULL, poke_later, &p) == 0);
	ssize_t first = send(c, out, sizeof out, 0);
	REQUIRE(pthread_join(tp, NULL) == 0);
	REQUIRE(interrupted);
	REQUIRE(first > 0 && first < (ssize_t)sizeof out);
	REQUIRE(send(c, out + first, sizeof out - (size_t)first, 0) ==
		(ssize_t)(sizeof out - (size_t)first));
	REQUIRE(pthread_join(tr, NULL) == 0);
	REQUIRE(r.got == sizeof out && !r.bad);
	REQUIRE(sigaction(SIGUSR1, &old, NULL) == 0);
	REQUIRE(close(c) == 0 && close(s) == 0 && close(lis) == 0);
}

#ifndef F_SETOWN
#error "relibc has no F_SETOWN"
#endif
#ifndef TCP_CORK
#include <netinet/tcp.h>
#endif

/* F_SETOWN and F_GETOWN on a socket of the pipe service and one of the
 * network service, FIOASYNC and FIONBIO on the first. */
/* The second network device goes to a program only where /etc/netd.conf
 * says `handover 1`: in this image (one device, no such line) the claim of
 * the superuser is EPERM, before the service looks for the device (which
 * would answer ENODEV). */
static void fast_claim_off(void)
{
	struct stafeto_fast_claim c;
	errno = 0;
	REQUIRE(stafeto_fast_claim(&c, STAFETO_FAST_ONCE) == -1 && errno == EPERM);
}

static void fsetown(void)
{
	int u[2];
	REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, u) == 0);
	int n = socket(AF_INET, SOCK_STREAM, 0);
	REQUIRE(n >= 0);
	int fds[2] = { u[0], n };
	for (int i = 0; i < 2; i++) {
		REQUIRE(fcntl(fds[i], F_GETOWN) == 0);
		REQUIRE(fcntl(fds[i], F_SETOWN, getpid()) == 0);
		REQUIRE(fcntl(fds[i], F_GETOWN) == getpid());
	}
	/* The owner belongs to its descriptor. */
	REQUIRE(fcntl(u[1], F_GETOWN) == 0);
	int on = 1;
	REQUIRE(ioctl(u[0], FIOASYNC, &on) == 0);
	REQUIRE(ioctl(u[0], FIONBIO, &on) == 0);
	REQUIRE(fcntl(u[0], F_GETFL) & O_NONBLOCK);
	char byte;
	REQUIRE(recv(u[0], &byte, 1, 0) == -1 && errno == EAGAIN);
	/* A file has no owner of signals. */
	int p[2];
	REQUIRE(pipe(p) == 0);
	REQUIRE(fcntl(p[0], F_SETOWN, getpid()) == -1 && errno == EINVAL);
	REQUIRE(ioctl(p[0], FIOASYNC, &on) == -1 && errno == ENOTTY);
	/* TCP_CORK is known and not taken. */
	REQUIRE(setsockopt(n, IPPROTO_TCP, TCP_CORK, &on, sizeof on) == -1 && errno == ENOPROTOOPT);
	REQUIRE(close(u[0]) == 0 && close(u[1]) == 0 && close(n) == 0);
	REQUIRE(close(p[0]) == 0 && close(p[1]) == 0);
	/* A descriptor that closed lets its record go: the number again has none. */
	REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, u) == 0);
	REQUIRE(fcntl(u[0], F_GETOWN) == 0);
	REQUIRE(close(u[0]) == 0 && close(u[1]) == 0);
}

/* nginx's own check of EPOLLRDHUP: a pair of AF_UNIX, one end closed; and
 * POLLRDHUP of poll on the other. */
static void epoll_rdhup_unix(void)
{
	int u[2];
	REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, u) == 0);
	int ep = ep_new();
	struct epoll_event ee;
	ee.events = EPOLLET | EPOLLIN | EPOLLRDHUP;
	ee.data.u64 = 0;
	REQUIRE(epoll_ctl(ep, EPOLL_CTL_ADD, u[0], &ee) == 0);
	REQUIRE(close(u[1]) == 0);
	long began = now_ms();
	REQUIRE(epoll_wait(ep, &ee, 1, 1000) == 1);
	REQUIRE(now_ms() - began < 1000);
	REQUIRE((ee.events & EPOLLRDHUP) && (ee.events & EPOLLIN));
	struct pollfd pf = { u[0], POLLIN | POLLRDHUP, 0 };
	REQUIRE(poll(&pf, 1, 1000) == 1 && (pf.revents & POLLRDHUP));
	/* Not asked for, not given. */
	pf.events = POLLIN;
	REQUIRE(poll(&pf, 1, 1000) == 1 && !(pf.revents & POLLRDHUP));
	REQUIRE(close(u[0]) == 0 && close(ep) == 0);
	/* POLLRDHUP of a stream of the network service. */
	int port, lis = listener(4, &port);
	int c, s;
	pair(lis, port, &c, &s);
	REQUIRE(shutdown(c, SHUT_WR) == 0);
	struct pollfd pn = { s, POLLRDHUP, 0 };
	REQUIRE(poll(&pn, 1, 2000) == 1 && (pn.revents & POLLRDHUP));
	REQUIRE(close(c) == 0 && close(s) == 0 && close(lis) == 0);
}

/* `posix-net stat`: the two options of the shared buffers. */
static int stat_buffers(void)
{
	unsigned buffers = buffers_now(SO_STAFETO_BUFFERS);
	unsigned kib = buffers_now(SO_STAFETO_BUFFERED);
	printf("posix-net: buffers %u limit %u buffered %u KiB\n", buffers & 0xFFFF, buffers >> 16, kib);
	return 0;
}

/* `posix-net readfile PATH N`: N reads of the whole file PATH by pread in
 * pieces of 32 KiB, as nginx reads a file it sends (output_buffers 32k);
 * prints the time of one read of the file, the shortest and the longest. */
static int readfile(const char *path, int rounds)
{
	static char piece[32 * 1024];
	int fd = open(path, O_RDONLY);
	if (fd < 0 || rounds < 1) {
		printf("posix-net: readfile %s: %s\n", path, fd < 0 ? strerror(errno) : "no rounds");
		return 1;
	}
	long long total = 0, least = -1, most = 0, bytes = 0;
	for (int r = 0; r < rounds; r++) {
		struct timespec a, b;
		clock_gettime(CLOCK_MONOTONIC, &a);
		off_t at = 0;
		for (;;) {
			ssize_t n = pread(fd, piece, sizeof piece, at);
			if (n < 0) {
				printf("posix-net: readfile %s: pread at %lld: %s\n", path, (long long)at,
				       strerror(errno));
				return 1;
			}
			if (n == 0)
				break;
			at += n;
		}
		clock_gettime(CLOCK_MONOTONIC, &b);
		long long ns = (b.tv_sec - a.tv_sec) * 1000000000LL + (b.tv_nsec - a.tv_nsec);
		total += ns;
		least = least < 0 || ns < least ? ns : least;
		most = ns > most ? ns : most;
		bytes = at;
	}
	close(fd);
	printf("posix-net: readfile %lld bytes %d rounds mean %lld us least %lld us most %lld us\n",
	       bytes, rounds, total / rounds / 1000, least / 1000, most / 1000);
	return 0;
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
	{ "epoll-basic", epoll_basic },
	{ "epoll-200", epoll_200 },
	{ "epoll-lt", epoll_lt },
	{ "epoll-et", epoll_et },
	{ "epoll-et-pipe", epoll_et_pipe },
	{ "epoll-oneshot", epoll_oneshot },
	{ "epoll-close", epoll_close },
	{ "epoll-fork", epoll_fork },
	{ "epoll-exec", epoll_exec },
	{ "epoll-errors", epoll_errors },
	{ "epoll-rdhup", epoll_rdhup },
	{ "epoll-err-rst", epoll_err_rst },
	{ "epoll-signal", epoll_signal },
	{ "epoll-stale-list", epoll_stale_list },
	{ "epoll-et-inout", epoll_et_inout },
	{ "epoll-listener", epoll_listener },
	{ "epoll-threads", epoll_threads },
	{ "poll-1000", poll_1000 },
	{ "select-high", select_high },
	{ "fionread", fionread },
	{ "epoll-1000", epoll_1000 },
	{ "listen-again", listen_again },
	{ "syn-full", syn_full },
	{ "timewait-syn", timewait_syn },
	{ "reuseport-4", reuseport_4 },
	{ "reuseport-handoff", reuseport_handoff },
	{ "reuseport-churn", reuseport_churn },
	{ "reuseport-uid", reuseport_uid },
	{ "linger-0", linger_0 },
	{ "linger-wait", linger_wait },
	{ "rcvtimeo", rcvtimeo },
	{ "sndtimeo", sndtimeo },
	{ "accept-clofork", accept_clofork },
	{ "scm-net", scm_net },
	{ "scm-five", scm_five },
	{ "scm-mixed", scm_mixed },
	{ "scm-wait", scm_wait },
	{ "scm-dead-receiver", scm_dead_receiver },
	{ "scm-close-socket", scm_close_socket },
	{ "scm-ctrunc", scm_ctrunc },
	{ "scm-retry", scm_retry },
	{ "scm-root", scm_root },
	{ "scm-depart", scm_depart },
	{ "epoll-exclusive", epoll_exclusive },
	{ "buffer-send", buffer_send },
	{ "buffer-recv", buffer_recv },
	{ "buffer-nonblock", buffer_nonblock },
	{ "buffer-writev", buffer_writev },
	{ "buffer-threads", buffer_threads },
	{ "buffer-fork", buffer_fork },
	{ "buffer-exec", buffer_exec },
	{ "buffer-signal", buffer_signal },
	{ "fsetown", fsetown },
	{ "epoll-rdhup-unix", epoll_rdhup_unix },
	{ "fast-claim-off", fast_claim_off },
	{ "wait-churn", wait_churn },
};

int main(int argc, char **argv)
{
	if (argc >= 2 && strcmp(argv[1], "exec-child") == 0)
		return exec_child(argc, argv);
	if (argc >= 3 && strcmp(argv[1], "spawn-child") == 0)
		return spawn_child(atoi(argv[2]));
	if (argc >= 3 && strcmp(argv[1], "epoll-child") == 0)
		return epoll_child(atoi(argv[2]));
	if (argc >= 3 && strcmp(argv[1], "buffer-exec-child") == 0)
		return buffer_exec_child((unsigned)atoi(argv[2]));
	if (argc == 2 && strcmp(argv[1], "stat") == 0)
		return stat_buffers();
	if (argc == 4 && strcmp(argv[1], "readfile") == 0)
		return readfile(argv[2], atoi(argv[3]));
	if (argc != 2 && argc != 3) {
		printf("posix-net: usage: posix-net ADDRESS [NAME]\n");
		return 2;
	}
	int count = (int)(sizeof CHECKS / sizeof CHECKS[0]);
	int ran = 0;
	for (int i = 0; i < count; i++) {
		if (argc == 3 && strcmp(argv[2], CHECKS[i].name) != 0)
			continue;
		check = CHECKS[i].name;
		CHECKS[i].run();
		printf("posix-net: %s ok\n", CHECKS[i].name);
		fflush(stdout);
		ran++;
	}
	printf("posix-net: %d checks ok\n", ran);
	return 0;
}
