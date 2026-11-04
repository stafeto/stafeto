/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The probe of the sockets of the network service (sub-project 6, stage 1;
 * services/netd), a dynamic program on libc.so that `cargo xtask net-curl`
 * starts from the shell of boot-net.img as `net-sock ADDRESS [COMMAND]`.
 * ADDRESS is the guest's own address (the line `net: lease` names it).
 *
 * With no COMMAND it runs every check in order and prints
 * `net-sock: NAME ok` for each, then `net-sock: N checks ok`; the first
 * failure prints `net-sock: NAME failed: WHAT errno N` and the exit code is 1.
 * The commands for the host:
 *
 *   udp-echo PORT              waits for one datagram on 0.0.0.0:PORT, sends
 *                              it back to its sender, prints `net-sock: udp
 *                              echo ok`
 *   udp-send ADDR PORT TEXT    sends TEXT as one datagram
 *   exec-child FD              the program after `exec` in the check `exec`:
 *                              writes `exec` to the inherited socket FD
 *   bind-child PORT FD         the new image of `cloexec-exec`: FD is closed
 *                              and PORT can be bound
 *
 * Built with -fno-builtin; every result is compared.
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <spawn.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <time.h>
#include <unistd.h>

extern char **environ;
static const char *check = "start";
static uint32_t own;

static void fail(const char *what)
{
	printf("net-sock: %s failed: %s errno %d\n", check, what, errno);
	fflush(stdout);
	_exit(1);
}

#define REQUIRE(cond) do { if (!(cond)) fail(#cond); } while (0)

/* A socket address from host-order `ip` and `port`. */
static struct sockaddr_in at(uint32_t ip, int port)
{
	struct sockaddr_in a;
	memset(&a, 0, sizeof a);
	a.sin_family = AF_INET;
	a.sin_port = htons((uint16_t)port);
	a.sin_addr.s_addr = htonl(ip);
	return a;
}

static uint32_t parse(const char *text)
{
	uint32_t ip = 0;
	for (int part = 0; part < 4; part++) {
		uint32_t n = 0;
		while (*text >= '0' && *text <= '9')
			n = n * 10 + (uint32_t)(*text++ - '0');
		ip = ip << 8 | (n & 255);
		if (*text == '.')
			text++;
	}
	return ip;
}

#define LOOPBACK 0x7f000001u

static void pause_ms(int ms)
{
	struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
	nanosleep(&t, NULL);
}

static int port_of(int fd)
{
	struct sockaddr_in a;
	socklen_t len = sizeof a;
	memset(&a, 0, sizeof a);
	if (getsockname(fd, (struct sockaddr *)&a, &len) != 0)
		fail("getsockname");
	return ntohs(a.sin_port);
}

static int stream(void)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		fail("socket stream");
	return fd;
}

static int datagram(void)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		fail("socket datagram");
	return fd;
}

/* A listener on `ip` and a port of the service's choosing: its port. */
static int listener(uint32_t ip, int *port)
{
	int fd = stream();
	struct sockaddr_in a = at(ip, 0);
	if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0)
		fail("bind listener");
	if (listen(fd, 8) != 0)
		fail("listen");
	*port = port_of(fd);
	return fd;
}

static int accept_one(int listening)
{
	struct pollfd p = { listening, POLLIN, 0 };
	if (poll(&p, 1, 10000) != 1)
		fail("no connection to accept");
	int fd = accept(listening, NULL, NULL);
	if (fd < 0)
		fail("accept");
	return fd;
}

static int connect_to(uint32_t ip, int port)
{
	int fd = stream();
	struct sockaddr_in a = at(ip, port);
	if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0)
		fail("connect");
	return fd;
}

/* A connected pair on `ip`: the connecting socket `*client`, the accepted
 * one `*server`, the listener closed. */
static void pair(uint32_t ip, int *client, int *server)
{
	int port;
	int l = listener(ip, &port);
	*client = connect_to(ip, port);
	*server = accept_one(l);
	close(l);
}

static void write_all(int fd, const char *bytes, int n)
{
	int done = 0;
	while (done < n) {
		ssize_t k = send(fd, bytes + done, (size_t)(n - done), 0);
		if (k <= 0)
			fail("write_all");
		done += (int)k;
	}
}

/* Reads `n` bytes, stopping early only at the end of the stream; waits 10 s
 * for each piece. */
static int read_all(int fd, char *bytes, int n)
{
	int done = 0;
	while (done < n) {
		struct pollfd p = { fd, POLLIN, 0 };
		if (poll(&p, 1, 10000) != 1)
			fail("read_all timed out");
		ssize_t k = recv(fd, bytes + done, (size_t)(n - done), 0);
		if (k < 0)
			fail("read_all");
		if (k == 0)
			break;
		done += (int)k;
	}
	return done;
}

static void fill(char *bytes, int n, int seed)
{
	for (int i = 0; i < n; i++)
		bytes[i] = (char)('a' + (i * 7 + seed) % 26);
}

static void exchange(int a, int b)
{
	char out[1000], in[1000];
	fill(out, 1000, 1);
	write_all(a, out, 1000);
	REQUIRE(read_all(b, in, 1000) == 1000);
	REQUIRE(memcmp(out, in, 1000) == 0);
	fill(out, 1000, 5);
	write_all(b, out, 1000);
	REQUIRE(read_all(a, in, 1000) == 1000);
	REQUIRE(memcmp(out, in, 1000) == 0);
}

static void tcp_on(uint32_t ip)
{
	int c, s;
	pair(ip, &c, &s);
	exchange(c, s);
	close(c);
	close(s);
}

static void tcp_loop(void) { tcp_on(LOOPBACK); }
static void tcp_own(void) { tcp_on(own); }

static void udp_on(uint32_t ip)
{
	int s = datagram(), c = datagram();
	struct sockaddr_in a = at(ip, 0), from;
	socklen_t len = sizeof from;
	char buf[64];
	REQUIRE(bind(s, (struct sockaddr *)&a, sizeof a) == 0);
	a = at(ip, port_of(s));
	REQUIRE(sendto(c, "ping", 4, 0, (struct sockaddr *)&a, sizeof a) == 4);
	struct pollfd p = { s, POLLIN, 0 };
	REQUIRE(poll(&p, 1, 10000) == 1);
	memset(&from, 0, sizeof from);
	REQUIRE(recvfrom(s, buf, sizeof buf, 0, (struct sockaddr *)&from, &len) == 4);
	REQUIRE(memcmp(buf, "ping", 4) == 0);
	REQUIRE(from.sin_family == AF_INET && ntohs(from.sin_port) != 0);
	REQUIRE(sendto(s, "pong", 4, 0, (struct sockaddr *)&from, len) == 4);
	p.fd = c;
	REQUIRE(poll(&p, 1, 10000) == 1);
	REQUIRE(recv(c, buf, sizeof buf, 0) == 4);
	REQUIRE(memcmp(buf, "pong", 4) == 0);
	close(s);
	close(c);
}

static void udp_loop(void)
{
	udp_on(LOOPBACK);
	udp_on(own);
}

static void ephemeral(void)
{
	int fd = stream();
	struct sockaddr_in a = at(0, 0);
	REQUIRE(bind(fd, (struct sockaddr *)&a, sizeof a) == 0);
	int port = port_of(fd);
	REQUIRE(port >= 49152 && port <= 65535);
	close(fd);
}

static void in_use(void)
{
	int one = stream(), two = stream();
	struct sockaddr_in a = at(LOOPBACK, 0);
	REQUIRE(bind(one, (struct sockaddr *)&a, sizeof a) == 0);
	a = at(LOOPBACK, port_of(one));
	errno = 0;
	REQUIRE(bind(two, (struct sockaddr *)&a, sizeof a) == -1);
	REQUIRE(errno == EADDRINUSE);
	int wide = stream(), narrow = stream();
	struct sockaddr_in w = at(0, 0);
	REQUIRE(bind(wide, (struct sockaddr *)&w, sizeof w) == 0);
	struct sockaddr_in n = at(LOOPBACK, port_of(wide));
	errno = 0;
	REQUIRE(bind(narrow, (struct sockaddr *)&n, sizeof n) == -1);
	REQUIRE(errno == EADDRINUSE);
	close(one);
	close(two);
	close(wide);
	close(narrow);
}

/* The server closes first, so its port stays with a connection that ends:
 * a new bind needs SO_REUSEADDR. */
static void reuse(void)
{
	int port;
	int l = listener(LOOPBACK, &port);
	int c = connect_to(LOOPBACK, port);
	int s = accept_one(l);
	close(l);
	close(s);
	char byte;
	REQUIRE(read_all(c, &byte, 1) == 0);
	close(c);
	int again = stream();
	struct sockaddr_in a = at(LOOPBACK, port);
	errno = 0;
	REQUIRE(bind(again, (struct sockaddr *)&a, sizeof a) == -1);
	REQUIRE(errno == EADDRINUSE);
	int on = 1;
	REQUIRE(setsockopt(again, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on) == 0);
	REQUIRE(bind(again, (struct sockaddr *)&a, sizeof a) == 0);
	REQUIRE(listen(again, 4) == 0);
	close(again);
}

static void privileged(void)
{
	pid_t child = fork();
	REQUIRE(child >= 0);
	if (child == 0) {
		int fd = stream();
		struct sockaddr_in a = at(0, 80);
		if (setuid(1000) != 0)
			_exit(2);
		errno = 0;
		if (bind(fd, (struct sockaddr *)&a, sizeof a) != -1 || errno != EACCES)
			_exit(3);
		_exit(0);
	}
	int status = 0;
	REQUIRE(waitpid(child, &status, 0) == child);
	REQUIRE(WIFEXITED(status));
	errno = WEXITSTATUS(status);
	REQUIRE(WEXITSTATUS(status) == 0);
	int fd = stream();
	struct sockaddr_in a = at(0, 81);
	REQUIRE(bind(fd, (struct sockaddr *)&a, sizeof a) == 0);
	close(fd);
}

static void refused(void)
{
	int fd = stream();
	struct sockaddr_in a = at(LOOPBACK, 1);
	errno = 0;
	REQUIRE(connect(fd, (struct sockaddr *)&a, sizeof a) == -1);
	REQUIRE(errno == ECONNREFUSED);
	close(fd);
}

static void fork_check(void)
{
	int c, s;
	pair(LOOPBACK, &c, &s);
	pid_t child = fork();
	REQUIRE(child >= 0);
	if (child == 0) {
		if (send(s, "child", 5, 0) != 5)
			_exit(2);
		_exit(0);
	}
	char buf[8];
	REQUIRE(read_all(c, buf, 5) == 5);
	REQUIRE(memcmp(buf, "child", 5) == 0);
	int status = 0;
	REQUIRE(waitpid(child, &status, 0) == child);
	REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	REQUIRE(send(s, "parent", 6, 0) == 6);
	REQUIRE(read_all(c, buf, 6) == 6);
	REQUIRE(memcmp(buf, "parent", 6) == 0);
	close(c);
	close(s);
}

static void exec_check(void)
{
	int c, s;
	pair(LOOPBACK, &c, &s);
	pid_t child = fork();
	REQUIRE(child >= 0);
	if (child == 0) {
		char number[16], address[32];
		snprintf(number, sizeof number, "%d", s);
		snprintf(address, sizeof address, "%u.%u.%u.%u", own >> 24, (own >> 16) & 255,
			 (own >> 8) & 255, own & 255);
		close(c);
		char *args[] = { "net-sock", address, "exec-child", number, NULL };
		execv("/bin/net-sock", args);
		_exit(2);
	}
	char buf[8];
	REQUIRE(read_all(c, buf, 4) == 4);
	REQUIRE(memcmp(buf, "exec", 4) == 0);
	int status = 0;
	REQUIRE(waitpid(child, &status, 0) == child);
	REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	close(c);
	close(s);
}

static void poll_mixed(void)
{
	int c, s, fds[2];
	pair(LOOPBACK, &c, &s);
	REQUIRE(pipe(fds) == 0);
	struct pollfd p[2] = { { s, POLLIN, 0 }, { fds[0], POLLIN, 0 } };
	REQUIRE(poll(p, 2, 0) == 0);
	REQUIRE(write(fds[1], "x", 1) == 1);
	p[0].revents = p[1].revents = 0;
	REQUIRE(poll(p, 2, 5000) == 1);
	REQUIRE(p[0].revents == 0 && (p[1].revents & POLLIN));
	char byte;
	REQUIRE(read(fds[0], &byte, 1) == 1);
	REQUIRE(send(c, "y", 1, 0) == 1);
	p[0].revents = p[1].revents = 0;
	REQUIRE(poll(p, 2, 5000) == 1);
	REQUIRE((p[0].revents & POLLIN) && p[1].revents == 0);
	REQUIRE(recv(s, &byte, 1, 0) == 1);
	struct pollfd out = { s, POLLOUT, 0 };
	REQUIRE(poll(&out, 1, 0) == 1 && (out.revents & POLLOUT));
	close(fds[0]);
	close(fds[1]);
	close(c);
	close(s);
}

static void nonblock_connect(void)
{
	int port;
	int l = listener(LOOPBACK, &port);
	int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	REQUIRE(fd >= 0);
	struct sockaddr_in a = at(LOOPBACK, port);
	errno = 0;
	REQUIRE(connect(fd, (struct sockaddr *)&a, sizeof a) == -1);
	REQUIRE(errno == EINPROGRESS);
	struct pollfd p = { fd, POLLOUT, 0 };
	REQUIRE(poll(&p, 1, 10000) == 1);
	REQUIRE(p.revents & POLLOUT);
	int error = -1;
	socklen_t len = sizeof error;
	REQUIRE(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0);
	REQUIRE(error == 0);
	errno = 0;
	REQUIRE(connect(fd, (struct sockaddr *)&a, sizeof a) == -1);
	REQUIRE(errno == EISCONN);
	int s = accept_one(l);
	close(s);
	close(fd);
	close(l);
}

static void accept_again(void)
{
	int port;
	int l = listener(LOOPBACK, &port);
	int flags = fcntl(l, F_GETFL);
	REQUIRE(flags >= 0 && !(flags & O_NONBLOCK));
	REQUIRE(fcntl(l, F_SETFL, flags | O_NONBLOCK) == 0);
	REQUIRE(fcntl(l, F_GETFL) & O_NONBLOCK);
	errno = 0;
	REQUIRE(accept(l, NULL, NULL) == -1);
	REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK);
	close(l);
}

static volatile int alarms;

static void on_alarm(int sig)
{
	(void)sig;
	alarms++;
}

static void handler(int flags)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_alarm;
	sa.sa_flags = flags;
	sigemptyset(&sa.sa_mask);
	REQUIRE(sigaction(SIGALRM, &sa, NULL) == 0);
}

/* connect to an address nobody answers for: the alarm ends the wait with
 * EINTR whether or not the handler restarts calls, and the handshake goes
 * on (N47). */
static void connect_eintr(void)
{
	struct sockaddr_in a = at(0x0a000263u, 80);
	handler(0);
	int fd = stream();
	alarms = 0;
	alarm(1);
	errno = 0;
	REQUIRE(connect(fd, (struct sockaddr *)&a, sizeof a) == -1);
	REQUIRE(errno == EINTR && alarms == 1);
	errno = 0;
	REQUIRE(connect(fd, (struct sockaddr *)&a, sizeof a) == -1);
	REQUIRE(errno == EALREADY);
	close(fd);
	handler(SA_RESTART);
	fd = stream();
	alarms = 0;
	alarm(1);
	errno = 0;
	REQUIRE(connect(fd, (struct sockaddr *)&a, sizeof a) == -1);
	REQUIRE(errno == EINTR && alarms == 1);
	close(fd);
}

static void recv_eintr(void)
{
	int c, s;
	pair(LOOPBACK, &c, &s);
	char buf[8];
	handler(0);
	alarms = 0;
	alarm(1);
	errno = 0;
	REQUIRE(recv(c, buf, sizeof buf, 0) == -1);
	REQUIRE(errno == EINTR && alarms == 1);
	handler(SA_RESTART);
	pid_t child = fork();
	REQUIRE(child >= 0);
	if (child == 0) {
		pause_ms(2000);
		if (send(s, "late!", 5, 0) != 5)
			_exit(2);
		_exit(0);
	}
	alarms = 0;
	alarm(1);
	REQUIRE(recv(c, buf, sizeof buf, 0) == 5);
	REQUIRE(alarms == 1);
	REQUIRE(memcmp(buf, "late!", 5) == 0);
	int status = 0;
	REQUIRE(waitpid(child, &status, 0) == child);
	REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	close(c);
	close(s);
}

static volatile int pipes;

static void on_pipe(int sig)
{
	(void)sig;
	pipes++;
}

/* The server closes, then the client sends until a send fails: with `unread`
 * the server holds a byte nobody read (its close resets the connection); without
 * it the first send reaches a closed socket, which resets the connection. One
 * ECONNRESET may come, then EPIPE with one SIGPIPE for each. */
static void epipe_with(int unread)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_pipe;
	sigemptyset(&sa.sa_mask);
	REQUIRE(sigaction(SIGPIPE, &sa, NULL) == 0);
	pipes = 0;
	int c, s;
	pair(LOOPBACK, &c, &s);
	if (unread) {
		REQUIRE(send(c, "u", 1, 0) == 1);
		struct pollfd waiting = { s, POLLIN, 0 };
		REQUIRE(poll(&waiting, 1, 5000) == 1);
	}
	close(s);
	int resets = 0, broken = 0;
	for (int i = 0; i < 200 && broken < 2; i++) {
		pause_ms(10);
		errno = 0;
		if (send(c, "x", 1, 0) == 1)
			continue;
		if (errno == ECONNRESET) {
			resets++;
			REQUIRE(resets == 1);
		} else {
			REQUIRE(errno == EPIPE);
			broken++;
		}
	}
	REQUIRE(broken == 2);
	REQUIRE(pipes == broken);
	errno = 0;
	REQUIRE(send(c, "x", 1, MSG_NOSIGNAL) == -1);
	REQUIRE(errno == EPIPE && pipes == broken);
	close(c);
}

static void epipe(void) { epipe_with(0); }
static void epipe_unread(void) { epipe_with(1); }

static void msgsize(void)
{
	int s = datagram(), c = datagram();
	struct sockaddr_in a = at(LOOPBACK, 0);
	char big[801];
	fill(big, 801, 3);
	REQUIRE(bind(s, (struct sockaddr *)&a, sizeof a) == 0);
	a = at(LOOPBACK, port_of(s));
	errno = 0;
	REQUIRE(sendto(c, big, 801, 0, (struct sockaddr *)&a, sizeof a) == -1);
	REQUIRE(errno == EMSGSIZE);
	REQUIRE(sendto(c, big, 800, 0, (struct sockaddr *)&a, sizeof a) == 800);
	char in[801];
	struct pollfd p = { s, POLLIN, 0 };
	REQUIRE(poll(&p, 1, 10000) == 1);
	REQUIRE(recv(s, in, sizeof in, 0) == 800);
	REQUIRE(memcmp(in, big, 800) == 0);
	close(s);
	close(c);
}

static void inet6(void)
{
	errno = 0;
	REQUIRE(socket(AF_INET6, SOCK_STREAM, 0) == -1);
	REQUIRE(errno == EAFNOSUPPORT);
}

static void close_flush(void)
{
	enum { TOTAL = 65536 };
	int c, s;
	pair(LOOPBACK, &c, &s);
	pid_t child = fork();
	REQUIRE(child >= 0);
	if (child == 0) {
		char piece[1024];
		fill(piece, sizeof piece, 9);
		for (int sent = 0; sent < TOTAL; sent += (int)sizeof piece)
			write_all(s, piece, sizeof piece);
		close(s);
		_exit(0);
	}
	close(s);
	char buf[2048], piece[1024];
	fill(piece, sizeof piece, 9);
	int total = 0;
	for (;;) {
		int k = read_all(c, buf, sizeof buf);
		if (k == 0)
			break;
		for (int i = 0; i < k; i++)
			if (buf[i] != piece[(total + i) % 1024])
				fail("the bytes differ");
		total += k;
	}
	REQUIRE(total == TOTAL);
	int status = 0;
	REQUIRE(waitpid(child, &status, 0) == child);
	REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	close(c);
}

static void names(void)
{
	int c, s;
	pair(LOOPBACK, &c, &s);
	struct sockaddr_in cl, cp, sl, sp;
	socklen_t len;
	len = sizeof cl;
	REQUIRE(getsockname(c, (struct sockaddr *)&cl, &len) == 0 && len == sizeof cl);
	len = sizeof cp;
	REQUIRE(getpeername(c, (struct sockaddr *)&cp, &len) == 0);
	len = sizeof sl;
	REQUIRE(getsockname(s, (struct sockaddr *)&sl, &len) == 0);
	len = sizeof sp;
	REQUIRE(getpeername(s, (struct sockaddr *)&sp, &len) == 0);
	REQUIRE(cl.sin_addr.s_addr == sp.sin_addr.s_addr && cl.sin_port == sp.sin_port);
	REQUIRE(cp.sin_addr.s_addr == sl.sin_addr.s_addr && cp.sin_port == sl.sin_port);
	REQUIRE(ntohl(cp.sin_addr.s_addr) == LOOPBACK);
	REQUIRE(cl.sin_port != cp.sin_port);
	close(c);
	close(s);
}

static void fstat_check(void)
{
	int fd = stream();
	struct stat st;
	REQUIRE(fstat(fd, &st) == 0);
	REQUIRE(S_ISSOCK(st.st_mode));
	errno = 0;
	REQUIRE(lseek(fd, 0, SEEK_SET) == -1);
	REQUIRE(errno == ESPIPE);
	close(fd);
}

static void nonblock_refused(void)
{
	int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	REQUIRE(fd >= 0);
	struct sockaddr_in a = at(LOOPBACK, 1);
	errno = 0;
	REQUIRE(connect(fd, (struct sockaddr *)&a, sizeof a) == -1);
	REQUIRE(errno == EINPROGRESS || errno == ECONNREFUSED);
	/* No event asked for: the error comes all the same. */
	struct pollfd p = { fd, 0, 0 };
	REQUIRE(poll(&p, 1, 10000) == 1);
	REQUIRE(p.revents & POLLERR);
	int error = -1;
	socklen_t len = sizeof error;
	REQUIRE(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0);
	REQUIRE(error == ECONNREFUSED);
	error = -1;
	REQUIRE(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0);
	REQUIRE(error == 0);
	close(fd);
}

static void hangup(void)
{
	int c, s;
	pair(LOOPBACK, &c, &s);
	REQUIRE(send(c, "u", 1, 0) == 1);
	struct pollfd waiting = { s, POLLIN, 0 };
	REQUIRE(poll(&waiting, 1, 5000) == 1);
	close(s);
	/* The server closed with a byte unread: a reset, and POLLHUP unasked. */
	struct pollfd p = { c, 0, 0 };
	REQUIRE(poll(&p, 1, 10000) == 1);
	REQUIRE(p.revents & POLLHUP);
	close(c);
}

static void spawn_socket(void)
{
	int c, s;
	pair(LOOPBACK, &c, &s);
	char number[16], address[32];
	snprintf(number, sizeof number, "%d", s);
	snprintf(address, sizeof address, "%u.%u.%u.%u", own >> 24, (own >> 16) & 255,
		 (own >> 8) & 255, own & 255);
	char *args[] = { "net-sock", address, "exec-child", number, NULL };
	pid_t child;
	REQUIRE(posix_spawn(&child, "/bin/net-sock", NULL, NULL, args, environ) == 0);
	char buf[8];
	REQUIRE(read_all(c, buf, 4) == 4);
	REQUIRE(memcmp(buf, "exec", 4) == 0);
	int status = 0;
	REQUIRE(waitpid(child, &status, 0) == child);
	REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	close(c);
	close(s);
}

/* A socket made with SOCK_CLOEXEC is gone in the new image, and its port is
 * free there. */
static void cloexec_exec(void)
{
	int port;
	int l = stream();
	struct sockaddr_in a = at(LOOPBACK, 0);
	REQUIRE(bind(l, (struct sockaddr *)&a, sizeof a) == 0);
	port = port_of(l);
	close(l);
	l = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	REQUIRE(l >= 0);
	a = at(LOOPBACK, port);
	REQUIRE(bind(l, (struct sockaddr *)&a, sizeof a) == 0);
	REQUIRE(listen(l, 4) == 0);
	REQUIRE(fcntl(l, F_GETFD) & FD_CLOEXEC);
	pid_t child = fork();
	REQUIRE(child >= 0);
	if (child == 0) {
		char number[16], text[16], address[32];
		snprintf(number, sizeof number, "%d", l);
		snprintf(text, sizeof text, "%d", port);
		snprintf(address, sizeof address, "%u.%u.%u.%u", own >> 24, (own >> 16) & 255,
			 (own >> 8) & 255, own & 255);
		char *args[] = { "net-sock", address, "bind-child", text, number, NULL };
		execv("/bin/net-sock", args);
		_exit(2);
	}
	close(l);
	int status = 0;
	REQUIRE(waitpid(child, &status, 0) == child);
	REQUIRE(WIFEXITED(status));
	errno = WEXITSTATUS(status);
	REQUIRE(WEXITSTATUS(status) == 0);
}

/* The new image of cloexec_exec: the descriptor is closed, and the port can
 * be bound once the old image's description is gone (the parent let go of
 * its own at once). */
static int bind_child(int port, int fd)
{
	check = "bind-child";
	errno = 0;
	REQUIRE(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
	for (int tries = 0; tries < 30; tries++) {
		int again = stream();
		struct sockaddr_in a = at(LOOPBACK, port);
		if (bind(again, (struct sockaddr *)&a, sizeof a) == 0) {
			close(again);
			return 0;
		}
		REQUIRE(errno == EADDRINUSE);
		close(again);
		pause_ms(100);
	}
	REQUIRE(0 && "the port stayed in use");
	return 1;
}

static void clofork(void)
{
	int c, s;
	pair(LOOPBACK, &c, &s);
	REQUIRE(fcntl(s, F_SETFD, FD_CLOFORK) == 0);
	REQUIRE(fcntl(s, F_GETFD) & FD_CLOFORK);
	pid_t child = fork();
	REQUIRE(child >= 0);
	if (child == 0) {
		errno = 0;
		if (send(s, "x", 1, 0) != -1 || errno != EBADF)
			_exit(2);
		_exit(0);
	}
	int status = 0;
	REQUIRE(waitpid(child, &status, 0) == child);
	REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	exchange(c, s);
	close(c);
	close(s);
}

static void peek_waitall(void)
{
	int c, s;
	pair(LOOPBACK, &c, &s);
	REQUIRE(send(c, "abcdef", 6, 0) == 6);
	struct pollfd p = { s, POLLIN, 0 };
	REQUIRE(poll(&p, 1, 5000) == 1);
	pause_ms(50);
	char buf[16];
	REQUIRE(recv(s, buf, 4, MSG_PEEK | MSG_WAITALL) == 4);
	REQUIRE(memcmp(buf, "abcd", 4) == 0);
	/* More asked than queued: what is there, once. */
	REQUIRE(recv(s, buf, 10, MSG_PEEK | MSG_WAITALL) == 6);
	REQUIRE(memcmp(buf, "abcdef", 6) == 0);
	REQUIRE(recv(s, buf, 6, MSG_WAITALL) == 6);
	REQUIRE(memcmp(buf, "abcdef", 6) == 0);
	close(c);
	close(s);
}

static const struct {
	const char *name;
	void (*run)(void);
} CHECKS[] = {
	{ "tcp-loop", tcp_loop },
	{ "tcp-own", tcp_own },
	{ "udp-loop", udp_loop },
	{ "ephemeral", ephemeral },
	{ "in-use", in_use },
	{ "reuse", reuse },
	{ "privileged", privileged },
	{ "refused", refused },
	{ "fork", fork_check },
	{ "exec", exec_check },
	{ "poll-mixed", poll_mixed },
	{ "nonblock-connect", nonblock_connect },
	{ "accept-again", accept_again },
	{ "connect-eintr", connect_eintr },
	{ "recv-eintr", recv_eintr },
	{ "epipe", epipe },
	{ "msgsize", msgsize },
	{ "inet6", inet6 },
	{ "close-flush", close_flush },
	{ "names", names },
	{ "fstat", fstat_check },
	{ "nonblock-refused", nonblock_refused },
	{ "hangup", hangup },
	{ "spawn-socket", spawn_socket },
	{ "cloexec-exec", cloexec_exec },
	{ "clofork", clofork },
	{ "epipe-unread", epipe_unread },
	{ "peek-waitall", peek_waitall },
};

static int udp_echo(int port)
{
	int fd = datagram();
	struct sockaddr_in a = at(0, port), from;
	socklen_t len = sizeof from;
	char buf[800];
	check = "udp-echo";
	REQUIRE(bind(fd, (struct sockaddr *)&a, sizeof a) == 0);
	ssize_t n = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &len);
	REQUIRE(n > 0);
	REQUIRE(sendto(fd, buf, (size_t)n, 0, (struct sockaddr *)&from, len) == n);
	printf("net-sock: udp echo ok\n");
	return 0;
}

static int udp_send(const char *ip, int port, const char *text)
{
	int fd = datagram();
	struct sockaddr_in a = at(parse(ip), port);
	check = "udp-send";
	REQUIRE(sendto(fd, text, strlen(text), 0, (struct sockaddr *)&a, sizeof a) == (ssize_t)strlen(text));
	printf("net-sock: udp send ok\n");
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		printf("usage: net-sock ADDRESS [COMMAND]\n");
		return 2;
	}
	own = parse(argv[1]);
	if (argc >= 3 && strcmp(argv[2], "udp-echo") == 0 && argc == 4)
		return udp_echo(atoi(argv[3]));
	if (argc >= 3 && strcmp(argv[2], "udp-send") == 0 && argc == 6)
		return udp_send(argv[3], atoi(argv[4]), argv[5]);
	if (argc >= 3 && strcmp(argv[2], "bind-child") == 0 && argc == 5)
		return bind_child(atoi(argv[3]), atoi(argv[4]));
	if (argc >= 3 && strcmp(argv[2], "exec-child") == 0 && argc == 4) {
		check = "exec-child";
		REQUIRE(send(atoi(argv[3]), "exec", 4, 0) == 4);
		return 0;
	}
	if (argc != 2) {
		printf("net-sock: unknown command %s\n", argv[2]);
		return 2;
	}
	int count = (int)(sizeof CHECKS / sizeof CHECKS[0]);
	for (int i = 0; i < count; i++) {
		check = CHECKS[i].name;
		CHECKS[i].run();
		printf("net-sock: %s ok\n", CHECKS[i].name);
		fflush(stdout);
	}
	printf("net-sock: %d checks ok\n", count);
	return 0;
}
