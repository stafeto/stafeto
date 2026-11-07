// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

/*
 * A consumer of the network service's switch with no stack of its own
 * (stage Sh4b2): it attaches (<stafeto/fast.h>), drives the ring with
 * vnet_port_* (vnet.h) and sends frames the switch must refuse. Each mode
 * says how many frames of TX the switch refused (the counter of line 9 of
 * the ring, `tx_refused`), so that a probe of the host compares it with
 * what it expects and with the capture of the wire: a refused frame never
 * reaches the wire.
 *
 *   switch-probe attach          attach, print the answer, leave
 *   switch-probe refuse          every refusal below, then a good frame
 *   switch-probe MODE            one of: foreign-sport foreign-ip
 *                                foreign-mac rst-foreign icmp fragment
 *                                long flags syn-ok
 *   switch-probe broken-tx       publish a TX head beyond the ring: the
 *                                switch breaks the ring and tells (`broken ok`)
 *   switch-probe broken-fill     the same with FILL
 *   switch-probe hold PORT       hold TCP PORT, join, and wait 2 s (the group
 *                                is live: `joined ok`)
 *   switch-probe hold-nobody     drop to nobody (65534) and hold TCP 81:
 *                                `hold-nobody ok` for the refusal (EACCES)
 *   switch-probe join-bad        JOIN with a descriptor that holds no port:
 *                                `join-bad ok` for the refusal
 *   switch-probe saturate SECS   keep TX full of entries the switch refuses for SECS
 *                                seconds, so that the switch has work at every step:
 *                                `saturate ok N` (N entries written); it runs on CPUs 1 to 3
 *   switch-probe spin SECS       count the iterations of a loop for SECS seconds on CPU 0, a
 *                                level below the switch, and say them per 100 ms
 *                                (`spin rate N`): the share of CPU 0 the levels below the
 *                                switch get is this rate in a flood against the rate of a
 *                                quiet system
 *
 * Lines: `switch-probe: attached c N g G addr A/P mac M block F+C`,
 * `switch-probe: MODE refused K` (K frames refused by the switch since the
 * line before), `switch-probe: counters rx_full N tx_refused M`,
 * `switch-probe: broken ok`. A failure prints `switch-probe: WHAT failed
 * errno N` and the exit code is 1. Built with -fno-builtin.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <vnet.h>

#define ETH 14
#define PAGE 4096u
/* The layout of proto_net::switch with the default sizes (1024 and 256). */
#define LINE 64u
#define TX_HEAD_AT (5 * LINE)
#define TX_TAIL_AT (6 * LINE)
#define FILL_HEAD_AT (1 * LINE)
#define FILL_TAIL_AT (2 * LINE)
#define TX_AT (4 * PAGE)
#define TX_CELLS_AT (517u * PAGE)
#define CELL 2048u
#define TX_SLOTS 256u
#define WAKE_BROKEN 2u

static struct stafeto_fast_claim claim;
static uint8_t *ring;
/* The entries of TX the program wrote (the index of the next). */
static uint32_t sent;
static uint16_t block_first;

static void fail(const char *what)
{
	printf("switch-probe: %s failed errno %d\n", what, errno);
	fflush(stdout);
	_exit(1);
}

#define REQUIRE(cond) do { if (!(cond)) fail(#cond); } while (0)

static void put16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static volatile uint32_t *word(uint32_t at)
{
	return (volatile uint32_t *)(ring + at);
}

static void pause_ms(unsigned ms)
{
	struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };

	nanosleep(&ts, NULL);
}

static uint32_t refused_count(void)
{
	uint32_t c[2] = { 0, 0 };

	vnet_port_counters(c);
	return c[1];
}

/* The header of an Ethernet frame from `src` (the shared MAC, or another) to a
 * unicast address that is no host's. */
static unsigned eth(uint8_t *f, const uint8_t *src, uint16_t type)
{
	static const uint8_t dst[6] = { 2, 0, 0, 0, 0, 0x99 };

	memcpy(f, dst, 6);
	memcpy(f + 6, src, 6);
	put16(f + 12, type);
	return ETH;
}

/* An IPv4 header of 20 bytes and `payload` bytes after it. */
static unsigned ipv4(uint8_t *f, const uint8_t *src_ip, uint8_t proto, unsigned payload, uint16_t frag)
{
	static const uint8_t dst_ip[4] = { 203, 0, 113, 9 };

	memset(f, 0, 20);
	f[0] = 0x45;
	put16(f + 2, (uint16_t)(20 + payload));
	put16(f + 6, frag);
	f[8] = 64;
	f[9] = proto;
	memcpy(f + 12, src_ip, 4);
	memcpy(f + 16, dst_ip, 4);
	return 20;
}

/* A TCP header: ports, flags, no options. */
static void tcp(uint8_t *t, uint16_t sport, uint16_t dport, uint8_t flags)
{
	memset(t, 0, 20);
	put16(t, sport);
	put16(t + 2, dport);
	t[12] = 5 << 4;
	t[13] = flags;
	put16(t + 14, 8192);
}

/* A frame of the mode into `f`; its length. */
static unsigned build(const char *mode, uint8_t *f)
{
	const uint8_t *mac = claim.config.mac;
	const uint8_t *ip = claim.config.address;
	static const uint8_t other_mac[6] = { 2, 0, 0, 0, 0, 0x77 };
	static const uint8_t other_ip[4] = { 198, 51, 100, 7 };
	unsigned n;

	memset(f, 0, 1600);
	if (!strcmp(mode, "foreign-mac")) {
		n = eth(f, other_mac, 0x0800);
		n += ipv4(f + n, ip, 6, 20, 0x4000);
		tcp(f + n, block_first, 80, 0x02);
		return n + 20;
	}
	n = eth(f, mac, 0x0800);
	if (!strcmp(mode, "foreign-ip")) {
		n += ipv4(f + n, other_ip, 6, 20, 0x4000);
		tcp(f + n, block_first, 80, 0x02);
		return n + 20;
	}
	if (!strcmp(mode, "icmp")) {
		n += ipv4(f + n, ip, 1, 8, 0x4000);
		f[n] = 8;
		return n + 8;
	}
	if (!strcmp(mode, "fragment")) {
		n += ipv4(f + n, ip, 6, 20, 0x2000);
		tcp(f + n, block_first, 80, 0x02);
		return n + 20;
	}
	if (!strcmp(mode, "long")) {
		n += ipv4(f + n, ip, 6, 1515 - ETH - 20, 0x4000);
		tcp(f + n, block_first, 80, 0x10);
		return 1515;
	}
	n += ipv4(f + n, ip, 6, 20, 0x4000);
	if (!strcmp(mode, "foreign-sport")) {
		tcp(f + n, 5, 80, 0x02);
	} else if (!strcmp(mode, "rst-foreign")) {
		/* A RST from a port of the block on a four-tuple that is no flow. */
		tcp(f + n, block_first, 80, 0x04);
	} else {
		/* syn-ok and flags: a SYN from the block. */
		tcp(f + n, block_first, 80, 0x02);
	}
	return n + 20;
}

/* One frame through the ring; `flags` other than 0 goes in the entry itself. */
static void send_frame(const uint8_t *f, unsigned len, uint16_t flags)
{
	if (flags == 0 && len <= 1514) {
		uint8_t *cell = vnet_port_tx_cell();

		REQUIRE(cell != NULL);
		memcpy(cell, f, len);
		vnet_port_tx_submit(len);
		sent++;
		if (vnet_port_tx_flush())
			stafeto_fast_poke();
		return;
	}
	/* An entry the library will not write: the program writes it, in the
	 * cell of its index. */
	uint32_t i = sent;
	volatile uint32_t *entry = word(TX_AT + (i % TX_SLOTS) * 8);

	memcpy(ring + TX_CELLS_AT + (i % TX_SLOTS) * CELL, f, len > CELL ? CELL : len);
	entry[0] = (uint32_t)len | (uint32_t)flags << 16;
	entry[1] = 0;
	sent++;
	__atomic_store_n(word(TX_HEAD_AT), sent, __ATOMIC_RELEASE);
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
	stafeto_fast_poke();
}

static void send_mode(const char *mode)
{
	uint8_t f[1600];
	uint32_t before = refused_count();
	unsigned len = build(mode, f);

	send_frame(f, len, !strcmp(mode, "flags") ? 1 : 0);
	pause_ms(150);
	printf("switch-probe: %s refused %u\n", mode, refused_count() - before);
	fflush(stdout);
}

/* Entries the switch refuses (flags it does not know), written as fast as TX has room, for
 * `secs` seconds. The switch always finds the next entry waiting, so it never rests unless it
 * stops by its own rule. */
static void saturate(unsigned secs)
{
	struct timespec t0, t;
	uint64_t entries = 0;
	uint8_t f[64];

	memset(f, 0, sizeof f);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (;;) {
		uint32_t tail = __atomic_load_n(word(TX_TAIL_AT), __ATOMIC_ACQUIRE);

		if (sent - tail < TX_SLOTS) {
			uint32_t i = sent;
			volatile uint32_t *entry = word(TX_AT + (i % TX_SLOTS) * 8);

			memcpy(ring + TX_CELLS_AT + (i % TX_SLOTS) * CELL, f, sizeof f);
			entry[0] = (uint32_t)sizeof f | 1u << 16;
			entry[1] = 0;
			sent++;
			entries++;
			__atomic_store_n(word(TX_HEAD_AT), sent, __ATOMIC_RELEASE);
			if ((entries & 31) == 1) {
				__atomic_thread_fence(__ATOMIC_SEQ_CST);
				stafeto_fast_poke();
			}
		}
		if ((entries & 1023) == 0) {
			clock_gettime(CLOCK_MONOTONIC, &t);
			if (t.tv_sec - t0.tv_sec >= (time_t)secs)
				break;
		}
	}
	printf("switch-probe: saturate ok %llu\n", (unsigned long long)entries);
	fflush(stdout);
}

/* The program runs on the CPUs of `mask` (bit n for CPU n). */
static void pin(unsigned mask)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	for (unsigned n = 0; n < 8; n++)
		if (mask >> n & 1)
			CPU_SET(n, &set);
	if (sched_setaffinity(0, sizeof set, &set) != 0)
		fail("sched_setaffinity");
}

/* A loop that counts its iterations for `secs` seconds on CPU 0; what it gets of that CPU
 * is its rate. The clock is read every 4 096 iterations, so a starved loop takes longer than
 * `secs` to end, and the rate is the iterations over the time they took. */
static void spin(unsigned secs)
{
	struct timespec t0, t;
	volatile uint64_t acc = 0;
	uint64_t iterations = 0, ns;

	pin(1);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (;;) {
		for (unsigned i = 0; i < 4096; i++)
			acc += i;
		iterations += 4096;
		clock_gettime(CLOCK_MONOTONIC, &t);
		ns = (uint64_t)(t.tv_sec - t0.tv_sec) * 1000000000ull + (uint64_t)(t.tv_nsec - t0.tv_nsec);
		if (ns >= (uint64_t)secs * 1000000000ull)
			break;
	}
	printf("switch-probe: spin rate %llu\n", (unsigned long long)(iterations * 100000000ull / ns));
	fflush(stdout);
}

static void counters(void)
{
	uint32_t c[2] = { 0, 0 };

	vnet_port_counters(c);
	printf("switch-probe: counters rx_full %u tx_refused %u\n", c[0], c[1]);
	fflush(stdout);
}

/* Waits up to `ms` for a notification with one of `bits`. */
static int wait_bits(uint32_t bits, unsigned ms)
{
	uint64_t until_ns = (uint64_t)ms * 1000000ull;

	while (until_ns > 0) {
		uint32_t got = 0;
		uint64_t step = until_ns > 50000000ull ? 50000000ull : until_ns;

		if (stafeto_fast_wait(step, &got) == 0 && (got & bits))
			return 1;
		until_ns -= step;
	}
	return 0;
}

static void broken(int fill)
{
	/* An index far ahead of the entries there are: the rule of the layout
	 * (head minus tail at most the size) fails at the next step. */
	if (fill)
		*word(FILL_HEAD_AT) = *word(FILL_TAIL_AT) + 100000u;
	else
		*word(TX_HEAD_AT) = *word(TX_TAIL_AT) + 100000u;
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
	stafeto_fast_poke();
	if (wait_bits(WAKE_BROKEN, 2000))
		printf("switch-probe: broken ok\n");
	else
		printf("switch-probe: broken missing\n");
	fflush(stdout);
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "attach";
	static const char *const refusals[] = {
		"foreign-sport", "foreign-ip", "foreign-mac", "rst-foreign",
		"icmp", "fragment", "long", "flags",
	};
	const struct stafeto_fast_config *c;
	int hold = -1;

	if (!strcmp(mode, "spin") && argc > 2) {
		spin((unsigned)atoi(argv[2]));
		return 0;
	}
	if (!strcmp(mode, "saturate"))
		pin(0xe);
	REQUIRE(stafeto_fast_attach(&claim) == 0);
	REQUIRE(claim.kind == STAFETO_FAST_PORT);
	c = &claim.config;
	block_first = (uint16_t)claim.snapshot[4];
	REQUIRE(vnet_port_open((void *)(uintptr_t)claim.window, claim.snapshot[2], claim.snapshot[3]) == 0);
	ring = (uint8_t *)(uintptr_t)claim.window;
	printf("switch-probe: attached c %u g %u addr %u.%u.%u.%u/%u mac %02x:%02x:%02x:%02x:%02x:%02x block %u+%u\n",
	       claim.snapshot[0], claim.snapshot[1], c->address[0], c->address[1], c->address[2],
	       c->address[3], c->prefix, c->mac[0], c->mac[1], c->mac[2], c->mac[3], c->mac[4],
	       c->mac[5], claim.snapshot[4], claim.snapshot[5]);
	fflush(stdout);
	if (!strcmp(mode, "attach")) {
		counters();
	} else if (!strcmp(mode, "refuse")) {
		/* The frames the library writes first, then the entries the program
		 * writes itself (long, flags), which the library's index does not
		 * follow. */
		for (unsigned i = 0; i < 6; i++)
			send_mode(refusals[i]);
		send_mode("syn-ok");
		send_mode("long");
		send_mode("flags");
		counters();
	} else if (!strcmp(mode, "saturate") && argc > 2) {
		saturate((unsigned)atoi(argv[2]));
	} else if (!strcmp(mode, "broken-tx") || !strcmp(mode, "broken-fill")) {
		broken(mode[7] == 'f');
	} else if (!strcmp(mode, "hold") && argc > 2) {
		hold = stafeto_fast_port_hold((unsigned)atoi(argv[2]), 1);
		REQUIRE(hold >= 0);
		REQUIRE(stafeto_fast_port_join(hold) == 0);
		printf("switch-probe: joined ok\n");
		fflush(stdout);
		pause_ms(2000);
	} else if (!strcmp(mode, "hold-top")) {
		/* The last port of the range: the blocks of temporary ports sit at the top, so a
		 * block over it makes the hold "in use"; with none, the hold is made. Either way
		 * no wrapped port is held (port 2080 is still free after it). */
		int top = stafeto_fast_port_hold(65535, 0);
		int e = errno;

		if (top < 0 && e != EADDRINUSE) {
			printf("switch-probe: hold-top failed errno %d\n", e);
		} else {
			hold = stafeto_fast_port_hold(2080, 0);
			if (hold >= 0 && stafeto_fast_port_join(hold) == 0)
				printf("switch-probe: hold-top ok %s\n", top < 0 ? "in use" : "held");
			else
				printf("switch-probe: hold-top then 2080 failed errno %d\n", errno);
		}
		fflush(stdout);
	} else if (!strcmp(mode, "reuse-a") && argc > 2) {
		/* A consumer whose ring broke keeps its session. Once its number is a new
		 * consumer's (reuse-b), its JOIN and its close of the description (LEAVE)
		 * reach nothing of the new one. */
		hold = stafeto_fast_port_hold((unsigned)atoi(argv[2]), 1);
		REQUIRE(hold >= 0);
		REQUIRE(stafeto_fast_port_join(hold) == 0);
		broken(0);
		pause_ms(6000);
		if (stafeto_fast_port_join(hold) != 0)
			printf("switch-probe: reuse-a stale join refused errno %d\n", errno);
		else
			printf("switch-probe: reuse-a stale join accepted\n");
		close(hold);
		printf("switch-probe: reuse-a closed\n");
		fflush(stdout);
		pause_ms(1000);
	} else if (!strcmp(mode, "reuse-b") && argc > 2) {
		hold = stafeto_fast_port_hold((unsigned)atoi(argv[2]), 1);
		REQUIRE(hold >= 0);
		REQUIRE(stafeto_fast_port_join(hold) == 0);
		printf("switch-probe: reuse-b joined\n");
		fflush(stdout);
		pause_ms(5000);
	} else if (!strcmp(mode, "hold-block")) {
		/* A port inside the block of this consumer's temporary ports is not for a
		 * group: PORT_HOLD answers "in use" and leaves no group in the books. */
		hold = stafeto_fast_port_hold(block_first + 10u, 1);
		if (hold < 0 && errno == EADDRINUSE)
			printf("switch-probe: hold-block ok\n");
		else
			printf("switch-probe: hold-block held %d errno %d\n", hold, errno);
		fflush(stdout);
	} else if (!strcmp(mode, "hold-nobody")) {
		/* Below 1024 only the superuser holds a port: PORT_HOLD vouches for
		 * the user the process has when it asks. */
		REQUIRE(setuid(65534) == 0);
		hold = stafeto_fast_port_hold(81, 1);
		if (hold < 0 && errno == EACCES)
			printf("switch-probe: hold-nobody ok\n");
		else
			printf("switch-probe: hold-nobody held %d errno %d\n", hold, errno);
		fflush(stdout);
	} else if (!strcmp(mode, "join-bad")) {
		/* A socket of the service holds no port: JOIN with it is refused. */
		int s = socket(AF_INET, SOCK_STREAM, 0);

		REQUIRE(s >= 0);
		if (stafeto_fast_port_join(s) != 0)
			printf("switch-probe: join-bad ok errno %d\n", errno);
		else
			printf("switch-probe: join-bad accepted\n");
		fflush(stdout);
	} else {
		send_mode(mode);
		counters();
	}
	return 0;
}
