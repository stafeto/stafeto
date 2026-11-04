/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The probe of the resolver of the C library (sub-project 6, stage 3), a
 * dynamic program on libc.so that `cargo xtask net-wget` starts from the
 * shell of boot-net.img.
 *
 *   net-dns checks                 every check below, in order
 *   net-dns first-contact A B PORT one datagram to A:9, then a TCP connect
 *                                  to B:PORT, and the time of the connect
 *   net-dns resolve NAME           the IPv4 addresses getaddrinfo gives
 *
 * The checks save /etc/resolv.conf, make it name 127.0.0.1, and fork a
 * name server of their own: a scenario per check on UDP 127.0.0.1:53 (and a
 * second socket on port 5353 that forges replies). The parent resolves
 * "t.test" through getaddrinfo and measures the time. Replies that must be
 * discarded carry 10.9.9.9; the right answer is 10.1.2.3. Every check prints
 * `net-dns: NAME ok`, then `net-dns: N checks ok`; the first failure prints
 * `net-dns: NAME failed: WHAT` and the exit code is 1.
 *
 * Built with -fno-builtin; every result is compared.
 */
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <time.h>
#include <unistd.h>

static const char *check = "start";
static void server_stop(void);
static void restore(void);
static int failing;

static void fail(const char *what)
{
	printf("net-dns: %s failed: %s errno %d\n", check, what, errno);
	fflush(stdout);
	if (!failing) {
		failing = 1;
		server_stop();
		restore();
	}
	_exit(1);
}

#define REQUIRE(cond) do { if (!(cond)) fail(#cond); } while (0)

static void on_alarm(int sig)
{
	(void)sig;
	errno = 0;
	fail("no end in time");
}

static long now_ms(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
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

static struct sockaddr_in at(uint32_t ip, int port)
{
	struct sockaddr_in a;
	memset(&a, 0, sizeof a);
	a.sin_family = AF_INET;
	a.sin_port = htons((uint16_t)port);
	a.sin_addr.s_addr = htonl(ip);
	return a;
}

#define LOOPBACK 0x7f000001u
#define RESOLV "/etc/resolv.conf"

/* ---- the file ---- */

static char saved[256];
static int saved_len = -1;

static void file_read(char *buf, int size, int *len)
{
	int fd = open(RESOLV, O_RDONLY);
	if (fd < 0) {
		*len = -1;
		return;
	}
	ssize_t n = read(fd, buf, (size_t)size);
	close(fd);
	*len = n < 0 ? -1 : (int)n;
}

static void file_write(const char *text, int len)
{
	int fd = open(RESOLV, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	REQUIRE(fd >= 0);
	REQUIRE(write(fd, text, (size_t)len) == len);
	close(fd);
}

static void resolv_is(const char *text)
{
	file_write(text, (int)strlen(text));
}

static void restore(void)
{
	if (saved_len >= 0)
		file_write(saved, saved_len);
}

/* ---- the name server of the checks ---- */

enum {
	S_ANSWER = 'a', S_ID = 'i', S_SOURCE = 's', S_QUESTION = 'q', S_RETRY = 'r',
	S_SERVFAIL = 'f', S_NXDOMAIN = 'n', S_NODATA = 'd', S_SILENT = 't', S_LOOP = 'l',
};

static const uint8_t RIGHT[4] = { 10, 1, 2, 3 };
static const uint8_t WRONG[4] = { 10, 9, 9, 9 };

/* A reply to the query `q` (its question ends at `qend`). `id` is the
 * number it carries; `other` replaces the name of the question; `loop`
 * makes the name of the answer a pointer to itself. */
static size_t build(uint8_t *out, const uint8_t *q, size_t qend, unsigned id, int rcode,
		    int answers, const uint8_t *address, int other, int loop)
{
	size_t n = 0;
	out[n++] = (uint8_t)(id >> 8);
	out[n++] = (uint8_t)id;
	out[n++] = 0x81;
	out[n++] = (uint8_t)(0x80 | rcode);
	out[n++] = 0; out[n++] = 1;
	out[n++] = 0; out[n++] = (uint8_t)answers;
	out[n++] = 0; out[n++] = 0; out[n++] = 0; out[n++] = 0;
	if (other) {
		static const uint8_t name[] = { 5, 'o', 't', 'h', 'e', 'r', 4, 't', 'e', 's', 't', 0 };
		memcpy(out + n, name, sizeof name);
		n += sizeof name;
		memcpy(out + n, q + qend - 4, 4);
		n += 4;
	} else {
		memcpy(out + n, q + 12, qend - 12);
		n += qend - 12;
	}
	if (answers) {
		size_t here = n;
		out[n++] = 0xC0;
		out[n++] = loop ? (uint8_t)here : 12;
		out[n++] = 0; out[n++] = 1;
		out[n++] = 0; out[n++] = 1;
		out[n++] = 0; out[n++] = 0; out[n++] = 0; out[n++] = 60;
		out[n++] = 0; out[n++] = 4;
		memcpy(out + n, address, 4);
		n += 4;
	}
	return n;
}

static void put(int s, const uint8_t *buf, size_t n, const struct sockaddr_in *to)
{
	sendto(s, buf, n, 0, (const struct sockaddr *)to, sizeof *to);
}

/* The child: answers on 53 as the scenario says, counts the queries. */
static void responder(int rd, int wr, int s53, int s5353)
{
	int scenario = S_ANSWER;
	unsigned count = 0;
	uint8_t q[512], r[512];
	for (;;) {
		struct pollfd p[3] = {
			{ rd, POLLIN, 0 }, { s53, POLLIN, 0 }, { s5353, POLLIN, 0 },
		};
		if (poll(p, 3, -1) < 0)
			continue;
		if (p[0].revents) {
			char c;
			if (read(rd, &c, 1) != 1)
				_exit(0);
			if (c == 'Q') {
				uint8_t n = (uint8_t)count;
				write(wr, &n, 1);
			} else {
				scenario = c;
				count = 0;
			}
		}
		if (p[2].revents) {
			struct sockaddr_in junk;
			socklen_t len = sizeof junk;
			recvfrom(s5353, q, sizeof q, 0, (struct sockaddr *)&junk, &len);
		}
		if (!p[1].revents)
			continue;
		struct sockaddr_in from;
		socklen_t len = sizeof from;
		ssize_t got = recvfrom(s53, q, sizeof q, 0, (struct sockaddr *)&from, &len);
		if (got < 13)
			continue;
		size_t qend = 12;
		while (qend < (size_t)got && q[qend])
			qend += (size_t)q[qend] + 1;
		qend += 5;
		if (qend > (size_t)got)
			continue;
		unsigned id = (unsigned)q[0] << 8 | q[1];
		count++;
		size_t n;
		switch (scenario) {
		case S_SILENT:
			break;
		case S_RETRY:
			if (count >= 2) {
				n = build(r, q, qend, id, 0, 1, RIGHT, 0, 0);
				put(s53, r, n, &from);
			}
			break;
		case S_ID:
			n = build(r, q, qend, id ^ 0xFFFFu, 0, 1, WRONG, 0, 0);
			put(s53, r, n, &from);
			n = build(r, q, qend, id, 0, 1, RIGHT, 0, 0);
			put(s53, r, n, &from);
			break;
		case S_SOURCE:
			n = build(r, q, qend, id, 0, 1, WRONG, 0, 0);
			put(s5353, r, n, &from);
			n = build(r, q, qend, id, 0, 1, RIGHT, 0, 0);
			put(s53, r, n, &from);
			break;
		case S_QUESTION:
			n = build(r, q, qend, id, 0, 1, WRONG, 1, 0);
			put(s53, r, n, &from);
			n = build(r, q, qend, id, 0, 1, RIGHT, 0, 0);
			put(s53, r, n, &from);
			break;
		case S_SERVFAIL:
			if (count == 1)
				n = build(r, q, qend, id, 2, 0, RIGHT, 0, 0);
			else
				n = build(r, q, qend, id, 0, 1, RIGHT, 0, 0);
			put(s53, r, n, &from);
			break;
		case S_NXDOMAIN:
			n = build(r, q, qend, id, 3, 0, RIGHT, 0, 0);
			put(s53, r, n, &from);
			break;
		case S_NODATA:
			n = build(r, q, qend, id, 0, 0, RIGHT, 0, 0);
			put(s53, r, n, &from);
			break;
		case S_LOOP:
			n = build(r, q, qend, id, 0, 1, RIGHT, 0, 1);
			put(s53, r, n, &from);
			break;
		default:
			n = build(r, q, qend, id, 0, 1, RIGHT, 0, 0);
			put(s53, r, n, &from);
			break;
		}
	}
}

static int to_child = -1, from_child = -1;
static pid_t server = -1;

static void server_start(void)
{
	int up[2], down[2];
	REQUIRE(pipe(up) == 0 && pipe(down) == 0);
	pid_t pid = fork();
	REQUIRE(pid >= 0);
	if (pid == 0) {
		int s53 = socket(AF_INET, SOCK_DGRAM, 0);
		int s5353 = socket(AF_INET, SOCK_DGRAM, 0);
		struct sockaddr_in a = at(LOOPBACK, 53), b = at(LOOPBACK, 5353);
		if (s53 < 0 || s5353 < 0 || bind(s53, (struct sockaddr *)&a, sizeof a) != 0
		    || bind(s5353, (struct sockaddr *)&b, sizeof b) != 0) {
			printf("net-dns: the name server could not bind errno %d\n", errno);
			fflush(stdout);
			_exit(1);
		}
		write(down[1], "R", 1);
		responder(up[0], down[1], s53, s5353);
	}
	close(up[0]);
	close(down[1]);
	to_child = up[1];
	from_child = down[0];
	server = pid;
	char c = 0;
	REQUIRE(read(from_child, &c, 1) == 1 && c == 'R');
}

static void server_stop(void)
{
	if (server > 0) {
		kill(server, SIGKILL);
		waitpid(server, NULL, 0);
		server = -1;
	}
}

static void scenario(int s)
{
	char c = (char)s;
	REQUIRE(write(to_child, &c, 1) == 1);
}

static int queries(void)
{
	uint8_t n = 0;
	REQUIRE(write(to_child, "Q", 1) == 1);
	REQUIRE(read(from_child, &n, 1) == 1);
	return n;
}

/* ---- the lookups ---- */

/* getaddrinfo of "t.test": the code, the first address, the time. */
static int ask(const char *name, uint8_t *address, long *ms)
{
	struct addrinfo hints, *list = NULL;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	long began = now_ms();
	int code = getaddrinfo(name, NULL, &hints, &list);
	*ms = now_ms() - began;
	if (code == 0) {
		struct sockaddr_in *a = (struct sockaddr_in *)list->ai_addr;
		memcpy(address, &a->sin_addr, 4);
		freeaddrinfo(list);
	}
	return code;
}

static void want_right(int code, const uint8_t *address)
{
	REQUIRE(code == 0);
	REQUIRE(memcmp(address, RIGHT, 4) == 0);
}

static void c_answer(void)
{
	uint8_t a[4]; long ms;
	scenario(S_ANSWER);
	want_right(ask("t.test", a, &ms), a);
	REQUIRE(ms < 1000);
}

static void c_id(void)
{
	uint8_t a[4]; long ms;
	scenario(S_ID);
	want_right(ask("t.test", a, &ms), a);
	REQUIRE(ms < 1000);
}

static void c_source(void)
{
	uint8_t a[4]; long ms;
	scenario(S_SOURCE);
	want_right(ask("t.test", a, &ms), a);
	REQUIRE(queries() == 1);
}

static void c_question(void)
{
	uint8_t a[4]; long ms;
	scenario(S_QUESTION);
	want_right(ask("t.test", a, &ms), a);
}

static void c_retry(void)
{
	uint8_t a[4]; long ms;
	scenario(S_RETRY);
	want_right(ask("t.test", a, &ms), a);
	REQUIRE(ms >= 4500 && ms <= 6500);
	REQUIRE(queries() == 2);
}

static void c_servfail(void)
{
	uint8_t a[4]; long ms;
	scenario(S_SERVFAIL);
	want_right(ask("t.test", a, &ms), a);
	REQUIRE(ms < 1000);
	REQUIRE(queries() == 2);
}

static void c_nxdomain(void)
{
	uint8_t a[4]; long ms;
	scenario(S_NXDOMAIN);
	REQUIRE(ask("t.test", a, &ms) == EAI_NONAME);
	REQUIRE(queries() == 1);
}

static void c_nodata(void)
{
	uint8_t a[4]; long ms;
	scenario(S_NODATA);
	REQUIRE(ask("t.test", a, &ms) == EAI_NONAME);
}

static void c_timeout(void)
{
	uint8_t a[4]; long ms;
	scenario(S_SILENT);
	REQUIRE(ask("t.test", a, &ms) == EAI_AGAIN);
	REQUIRE(ms >= 9500 && ms <= 11000);
	REQUIRE(queries() == 2);
}

static void c_loop(void)
{
	uint8_t a[4]; long ms;
	scenario(S_LOOP);
	REQUIRE(ask("t.test", a, &ms) == EAI_FAIL);
	REQUIRE(ms < 1000);
}

static void c_parse(void)
{
	uint8_t a[4]; long ms;
	resolv_is("# c\n; c\nnameserver ::1\nnameserver\t127.0.0.1\n");
	scenario(S_ANSWER);
	want_right(ask("t.test", a, &ms), a);
	resolv_is("nameserver 127.0.0.1\n");
}

static int open_descriptors(void)
{
	int n = 0;
	for (int fd = 0; fd < 256; fd++)
		if (fcntl(fd, F_GETFD) != -1)
			n++;
	return n;
}

static void c_leak(void)
{
	uint8_t a[4]; long ms;
	scenario(S_ANSWER);
	int before = open_descriptors();
	for (int i = 0; i < 32; i++)
		want_right(ask("t.test", a, &ms), a);
	REQUIRE(open_descriptors() == before);
}

/* A name that cannot be asked (a label past 63 bytes, an empty label)
 * is EAI_NONAME at once, and no query goes out. */
static void c_badname(void)
{
	static char big[400];
	uint8_t a[4]; long ms;
	memset(big, 'a', sizeof big);
	strcpy(big + 300, ".com");
	scenario(S_ANSWER);
	REQUIRE(ask(big, a, &ms) == EAI_NONAME);
	REQUIRE(ms < 1000);
	REQUIRE(ask("a..test", a, &ms) == EAI_NONAME);
	REQUIRE(ms < 1000);
	REQUIRE(queries() == 0);
}

static const struct {
	const char *name;
	void (*run)(void);
} CHECKS[] = {
	{ "answer", c_answer },
	{ "id", c_id },
	{ "source", c_source },
	{ "question", c_question },
	{ "retry", c_retry },
	{ "servfail", c_servfail },
	{ "nxdomain", c_nxdomain },
	{ "nodata", c_nodata },
	{ "timeout", c_timeout },
	{ "loop", c_loop },
	{ "parse", c_parse },
	{ "leak", c_leak },
	{ "badname", c_badname },
};

static int checks(void)
{
	int count = (int)(sizeof CHECKS / sizeof CHECKS[0]);
	file_read(saved, (int)sizeof saved, &saved_len);
	check = "setup";
	resolv_is("nameserver 127.0.0.1\n");
	server_start();
	for (int i = 0; i < count; i++) {
		check = CHECKS[i].name;
		alarm(40);
		CHECKS[i].run();
		alarm(0);
		printf("net-dns: %s ok\n", CHECKS[i].name);
		fflush(stdout);
	}
	server_stop();
	restore();
	printf("net-dns: %d checks ok\n", count);
	return 0;
}

/* ---- the commands for the steps of the probe ---- */

static int first_contact(const char *a, const char *b, int port)
{
	check = "first-contact";
	int u = socket(AF_INET, SOCK_DGRAM, 0);
	REQUIRE(u >= 0);
	struct sockaddr_in to = at(parse(a), 9);
	REQUIRE(sendto(u, "x", 1, 0, (struct sockaddr *)&to, sizeof to) == 1);
	int t = socket(AF_INET, SOCK_STREAM, 0);
	REQUIRE(t >= 0);
	struct sockaddr_in peer = at(parse(b), port);
	long began = now_ms();
	REQUIRE(connect(t, (struct sockaddr *)&peer, sizeof peer) == 0);
	printf("net-dns: first-contact connect %ld ms\n", now_ms() - began);
	return 0;
}

static int resolve(const char *name)
{
	struct addrinfo hints, *list = NULL;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	int code = getaddrinfo(name, NULL, &hints, &list);
	if (code != 0) {
		printf("net-dns: resolve failed: %s\n", gai_strerror(code));
		return 1;
	}
	for (struct addrinfo *p = list; p; p = p->ai_next) {
		uint8_t *b = (uint8_t *)&((struct sockaddr_in *)p->ai_addr)->sin_addr;
		printf("net-dns: resolved %d.%d.%d.%d\n", b[0], b[1], b[2], b[3]);
	}
	freeaddrinfo(list);
	return 0;
}

int main(int argc, char **argv)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_alarm;
	sigaction(SIGALRM, &sa, NULL);
	if (argc == 2 && strcmp(argv[1], "checks") == 0)
		return checks();
	if (argc == 5 && strcmp(argv[1], "first-contact") == 0)
		return first_contact(argv[2], argv[3], atoi(argv[4]));
	if (argc == 3 && strcmp(argv[1], "resolve") == 0)
		return resolve(argv[2]);
	printf("usage: net-dns checks | first-contact A B PORT | resolve NAME\n");
	return 2;
}
