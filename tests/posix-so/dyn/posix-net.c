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
 *   posix-net exec-child N...    the image after `exec` in the check `exec-64`:
 *                                every number named is open and does not close
 *                                on exec
 *   posix-net spawn-child FD     the image of the check `spawn-high`: FD is open
 *   posix-net epoll-child FD     the image of the check `epoll-exec`: FD is not open
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
			printf("posix-net: %s: %d of %d events came\n", check, total, want);
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
	struct epoll_event ex = { EPOLLIN | EPOLLEXCLUSIVE, { .u64 = 1 } };
	errno = 0;
	REQUIRE(epoll_ctl(ep, EPOLL_CTL_ADD, c, &ex) == -1 && errno == EINVAL);
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
	{ "poll-1000", poll_1000 },
	{ "select-high", select_high },
	{ "fionread", fionread },
	{ "epoll-1000", epoll_1000 },
};

int main(int argc, char **argv)
{
	if (argc >= 2 && strcmp(argv[1], "exec-child") == 0)
		return exec_child(argc, argv);
	if (argc >= 3 && strcmp(argv[1], "spawn-child") == 0)
		return spawn_child(atoi(argv[2]));
	if (argc >= 3 && strcmp(argv[1], "epoll-child") == 0)
		return epoll_child(atoi(argv[2]));
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
