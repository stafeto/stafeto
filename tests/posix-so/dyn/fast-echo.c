// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

/*
 * The echo of UDP on the second network device, owned by this program
 * (stage P6a of subproject 6): it claims the device from the network
 * service (<stafeto/fast.h>) and drives it with libvirtio_net.a (vnet.h),
 * with no stack of its own. It answers ARP for the second address, the
 * echo of ICMP, and every UDP datagram to PORT with the same bytes; it
 * passes the server's DHCP messages and the ARP replies for the second
 * address to the network service through the bypass ring, and puts on the
 * wire what the service sends back that way (the lease of the second
 * address stays the service's).
 *
 *   fast-echo PORT            claim, then echo until killed
 *   fast-echo PORT --flood    the same, after 16 frames of DHCP in the
 *                             bypass ring at once (the bound of the step)
 *   fast-echo PORT --once     claim without waiting: `busy ok` when another
 *                             process owns the device
 *   fast-echo PORT --as UID   setuid(UID), then claim: `refused ok` for EPERM
 *   fast-echo PORT --rules    claim, then fork and execve fail with EPERM and
 *                             munmap and mprotect of the mappings with EINVAL
 *   fast-echo PORT --retry    a claim refused while another owns the device,
 *                             then tries until it is free (`retry ok`), then
 *                             echo
 *   fast-echo PORT --idle MS  (with any of the above that echoes) the wait of
 *                             an idle owner lasts MS milliseconds, so only
 *                             the device's interrupt wakes it in time; a UDP
 *                             datagram that starts with `RACE` makes the
 *                             owner stay away from the queue for 200 ms
 *                             before it turns the interrupts on
 *   fast-echo PORT --crash    ask the network service of the probe's image
 *                             to fault (`crash sent`), claiming nothing
 *
 * Lines: `fast-echo: claimed A/N mac M`, `fast-echo: address A/N` when the
 * service says the address changed, `fast-echo: lost` when the device was
 * taken away (the program ends with 2). A failure prints `fast-echo: WHAT
 * failed errno N` and the exit code is 1. Built with -fno-builtin; every
 * result is compared.
 */

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <vnet.h>

extern char **environ;
extern int stafeto_fast_probe_crash(void);

#define ETH 14
#define BURST 32
#define WAIT_NS 10000000ull
#define RACE_GAP_NS 200000000ull

static uint8_t own_ip[4];
static uint8_t own_mac[6];
static uint16_t port;
static unsigned long echoed;
static unsigned long frames_seen;
static int first_seen;
static unsigned long wait_ns = WAIT_NS;
/* `--idle`: the owner of the probe's image, which stays away from its queue
 * when asked, once, before it turns the interrupts on. */
static int idle_mode;
static int race_gap;

static void fail(const char *what)
{
	printf("fast-echo: %s failed errno %d\n", what, errno);
	fflush(stdout);
	_exit(1);
}

#define REQUIRE(cond) do { if (!(cond)) fail(#cond); } while (0)

static uint16_t be16(const uint8_t *p)
{
	return (uint16_t)(p[0] << 8 | p[1]);
}

static void put16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static int same(const uint8_t *a, const uint8_t *b, size_t n)
{
	return memcmp(a, b, n) == 0;
}

static void say_address(const char *what, const struct stafeto_fast_config *c)
{
	printf("fast-echo: %s %u.%u.%u.%u/%u mac %02x:%02x:%02x:%02x:%02x:%02x\n", what,
	       c->address[0], c->address[1], c->address[2], c->address[3], c->prefix,
	       c->mac[0], c->mac[1], c->mac[2], c->mac[3], c->mac[4], c->mac[5]);
	fflush(stdout);
}

/* The IPv4 header of a frame: its length, or 0 when the frame holds no
 * whole, unfragmented IPv4 datagram. */
static unsigned ipv4(const uint8_t *f, uint32_t len)
{
	if (len < ETH + 20 || f[12] != 0x08 || f[13] != 0x00 || f[14] >> 4 != 4)
		return 0;
	unsigned header = (f[14] & 0x0f) * 4u;
	unsigned total = be16(f + ETH + 2);
	if (header < 20 || total < header || ETH + total > len || (be16(f + ETH + 6) & 0x3fff) != 0)
		return 0;
	return header;
}

/* A frame to send: a buffer of the pool with `len` bytes of `frame`. */
static void send_copy(const uint8_t *frame, uint32_t len, uint8_t **out)
{
	uint32_t buf = vnet_buf_take();
	if (buf == VNET_NONE) {
		*out = NULL;
		return;
	}
	uint8_t *to = vnet_buf_ptr(buf);
	vnet_copy(to, frame, len);
	*out = to;
	if (vnet_tx(buf, (uint16_t)len) != 0)
		vnet_rx_return(buf);
}

/* The reply to an ARP request for the second address (RFC 826). */
static void arp_reply(const uint8_t *f)
{
	uint8_t r[60];
	memset(r, 0, sizeof r);
	memcpy(r, f + 6, 6);
	memcpy(r + 6, own_mac, 6);
	r[12] = 0x08;
	r[13] = 0x06;
	const uint8_t head[8] = { 0, 1, 8, 0, 6, 4, 0, 2 };
	memcpy(r + ETH, head, 8);
	memcpy(r + 22, own_mac, 6);
	memcpy(r + 28, own_ip, 4);
	memcpy(r + 32, f + 22, 6);
	memcpy(r + 38, f + 28, 4);
	uint8_t *sent;
	send_copy(r, sizeof r, &sent);
}

/* The same frame back to its sender: the hardware and IP addresses swapped,
 * and the ports of UDP, or the type of an ICMP echo request made a reply. */
static void echo(const uint8_t *f, uint32_t len, unsigned header, int icmp)
{
	if (!icmp && !first_seen && len > ETH + header + 8) {
		/* The first datagram of the port: its first byte numbers it, which
		 * tells a loss before the program from a loss after it. */
		first_seen = 1;
		printf("fast-echo: first datagram byte %u after %lu frames\n", f[ETH + header + 8], frames_seen);
		fflush(stdout);
	}
	uint32_t buf = vnet_buf_take();
	if (buf == VNET_NONE)
		return;
	uint8_t *r = vnet_buf_ptr(buf);
	uint32_t total = ETH + be16(f + ETH + 2);
	vnet_copy(r, f, total < len ? total : len);
	memcpy(r, f + 6, 6);
	memcpy(r + 6, own_mac, 6);
	memcpy(r + ETH + 12, f + ETH + 16, 4);
	memcpy(r + ETH + 16, f + ETH + 12, 4);
	r[ETH + 8] = 64;
	uint8_t *l4 = r + ETH + header;
	if (icmp) {
		l4[0] = 0;
	} else {
		memcpy(l4, f + ETH + header + 2, 2);
		memcpy(l4 + 2, f + ETH + header, 2);
	}
	vnet_fill_sums(r, total);
	if (vnet_tx(buf, (uint16_t)total) != 0)
		vnet_rx_return(buf);
	else
		echoed++;
	if (idle_mode && !icmp && be16(f + ETH + 2) >= header + 8 + 4 && memcmp(f + ETH + header + 8, "RACE", 4) == 0)
		race_gap = 1;
}

/* What the service's interface of the second device may get from the wire:
 * a server's DHCP message (UDP from 67 to 68), and an ARP reply for the
 * second address. */
static int for_service(const uint8_t *f, uint32_t len, unsigned header)
{
	if (header)
		return f[ETH + 9] == 17 && be16(f + ETH + header) == 67 && be16(f + ETH + header + 2) == 68;
	return len >= 42 && f[12] == 0x08 && f[13] == 0x06 && f[ETH + 7] == 2 && same(f + 38, own_ip, 4);
}

/* One frame of the device. Gives 1 when it went to the service. */
static int frame(const uint8_t *f, uint32_t len)
{
	frames_seen++;
	unsigned header = ipv4(f, len);
	if (for_service(f, len, header))
		return vnet_bypass_push(f, len);
	if (!header) {
		if (len >= 42 && f[12] == 0x08 && f[13] == 0x06 && f[ETH + 7] == 1 && same(f + 38, own_ip, 4))
			arp_reply(f);
		return 0;
	}
	if (!same(f + ETH + 16, own_ip, 4))
		return 0;
	const uint8_t *l4 = f + ETH + header;
	if (f[ETH + 9] == 17 && be16(f + ETH + 2) >= header + 8 && be16(l4 + 2) == port)
		echo(f, len, header, 0);
	else if (f[ETH + 9] == 1 && be16(f + ETH + 2) >= header + 8 && l4[0] == 8)
		echo(f, len, header, 1);
	return 0;
}

/* The frames the service sends through the bypass ring go to the wire once
 * they look like what its interface may send: from the device's MAC, ARP
 * or a client's DHCP message (UDP from 68 to 67). */
static void from_service(void)
{
	uint8_t f[1514];
	size_t len;
	while ((len = vnet_bypass_pop(f, sizeof f)) != 0) {
		if (len < ETH || !same(f + 6, own_mac, 6))
			continue;
		unsigned header = ipv4(f, (uint32_t)len);
		int arp = f[12] == 0x08 && f[13] == 0x06;
		int dhcp = header && f[ETH + 9] == 17 && be16(f + ETH + header) == 68 &&
			   be16(f + ETH + header + 2) == 67;
		if (!arp && !dhcp)
			continue;
		uint8_t *sent;
		send_copy(f, (uint32_t)len, &sent);
	}
}

/* 16 frames of DHCP to the second address in the ring at once, which the
 * service takes two a step (`--flood`). */
static void flood(void)
{
	uint8_t f[342];
	memset(f, 0, sizeof f);
	memcpy(f, own_mac, 6);
	f[12] = 0x08;
	f[14] = 0x45;
	put16(f + ETH + 2, sizeof f - ETH);
	f[ETH + 8] = 64;
	f[ETH + 9] = 17;
	memcpy(f + ETH + 16, own_ip, 4);
	put16(f + ETH + 20, 67);
	put16(f + ETH + 22, 68);
	put16(f + ETH + 24, sizeof f - ETH - 20);
	vnet_fill_sums(f, sizeof f);
	int pushed = 0;
	for (int i = 0; i < 16; i++)
		pushed += vnet_bypass_push(f, sizeof f);
	REQUIRE(pushed == 16);
	int taken = stafeto_fast_kick(16);
	REQUIRE(taken >= 1 && taken <= 16);
	printf("fast-echo: flood taken %d\n", taken);
	fflush(stdout);
}

/* The rules of a process that holds the device (`--rules`). */
static int rules(const struct stafeto_fast_claim *c)
{
	errno = 0;
	REQUIRE(fork() == -1 && errno == EPERM);
	printf("fast-echo: fast-fork ok\n");
	char *argv[] = { "fast-echo", NULL };
	errno = 0;
	REQUIRE(execve("/bin/fast-echo", argv, environ) == -1 && errno == EPERM);
	printf("fast-echo: fast-exec ok\n");
	void *window = (void *)(uintptr_t)(c->window & ~(uint64_t)4095);
	errno = 0;
	REQUIRE(munmap(window, 4096) == -1 && errno == EINVAL);
	errno = 0;
	REQUIRE(munmap((void *)(uintptr_t)c->objects[1].va, 4096) == -1 && errno == EINVAL);
	errno = 0;
	REQUIRE(mprotect((void *)(uintptr_t)c->ring, 4096, PROT_READ) == -1 && errno == EINVAL);
	printf("fast-echo: fast-unmap ok\n");
	fflush(stdout);
	return 0;
}

static long now_ms(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

/* A claim refused while another process owns the device, then tries until
 * the device is free (`--retry`), with no wait on the thread's channel in
 * between: the service's notification of the claim that got the device is
 * the only one `stafeto_fast_wait` gives, so the departure of a refused
 * try never reads as the end of the service. */
static void retry(struct stafeto_fast_claim *c)
{
	errno = 0;
	REQUIRE(stafeto_fast_claim(c, STAFETO_FAST_ONCE) == -1 && errno == EBUSY);
	printf("fast-echo: retry busy\n");
	fflush(stdout);
	long start = now_ms();
	while (stafeto_fast_claim(c, STAFETO_FAST_ONCE) != 0) {
		REQUIRE(errno == EBUSY);
		REQUIRE(now_ms() - start < 60000);
		long until = now_ms() + 100;
		while (now_ms() < until)
			;
	}
	uint32_t bits = 0;
	errno = 0;
	int waited = stafeto_fast_wait(0, &bits);
	REQUIRE(waited == 0 || errno == ETIMEDOUT);
	REQUIRE((bits & STAFETO_FAST_GONE) == 0);
	printf("fast-echo: retry ok\n");
	fflush(stdout);
}

static int run(void)
{
	struct vnet_buf got[BURST];
	int waiting = 0;
	for (;;) {
		int n = vnet_rx_burst(got, BURST);
		REQUIRE(n >= 0);
		int pushed = 0;
		for (int i = 0; i < n; i++) {
			pushed += frame(got[i].frame, got[i].len);
			vnet_rx_return(got[i].buf);
		}
		if (pushed > 0)
			REQUIRE(stafeto_fast_kick((uint32_t)pushed) >= 0);
		from_service();
		vnet_tx_kick();
		REQUIRE(vnet_tx_reclaim() >= 0);
		if (n > 0) {
			if (waiting) {
				vnet_notify(0);
				waiting = 0;
			}
			continue;
		}
		if (!waiting) {
			/* Interrupts on, then a look at the queue once more: a frame
			 * that came in between brings no interrupt. */
			if (race_gap) {
				struct timespec gap = { 0, RACE_GAP_NS };
				nanosleep(&gap, NULL);
				race_gap = 0;
			}
			vnet_notify(1);
			waiting = 1;
			continue;
		}
		uint32_t bits = 0;
		if (stafeto_fast_wait(wait_ns, &bits) != 0 && errno != ETIMEDOUT && errno != EINTR)
			fail("stafeto_fast_wait");
		if (bits & STAFETO_FAST_ADDRESS) {
			struct stafeto_fast_config c;
			if (stafeto_fast_config(&c) == 0) {
				memcpy(own_ip, c.address, 4);
				say_address("address", &c);
			}
		}
		/* The service let go of its notifications (it ended or took the
		 * device back), or the device was reset under the program. A new
		 * service may have started the device again by now, so the device's
		 * status alone does not tell. */
		if ((bits & STAFETO_FAST_GONE) || vnet_lost()) {
			printf("fast-echo: lost after %lu echoes\n", echoed);
			fflush(stdout);
			return 2;
		}
	}
}

int main(int argc, char **argv)
{
	if (argc < 2 || argc > 6) {
		printf("fast-echo: usage: fast-echo PORT [--flood|--once|--rules|--retry|--crash|--as UID] [--idle MS]\n");
		return 2;
	}
	port = (uint16_t)atoi(argv[1]);
	for (int i = 2; i + 1 < argc; i++) {
		if (strcmp(argv[i], "--idle") == 0) {
			wait_ns = (unsigned long)atoi(argv[i + 1]) * 1000000ul;
			idle_mode = 1;
			for (int j = i; j + 2 < argc; j++)
				argv[j] = argv[j + 2];
			argc -= 2;
			break;
		}
	}
	const char *mode = argc >= 3 ? argv[2] : "";
	struct stafeto_fast_claim c;
	if (strcmp(mode, "--crash") == 0) {
		int sent = stafeto_fast_probe_crash();
		printf("fast-echo: crash sent %d\n", sent);
		return 0;
	}
	if (strcmp(mode, "--as") == 0) {
		REQUIRE(argc == 4);
		REQUIRE(setuid((uid_t)atoi(argv[3])) == 0);
		errno = 0;
		REQUIRE(stafeto_fast_claim(&c, 0) == -1 && errno == EPERM);
		printf("fast-echo: refused ok\n");
		return 0;
	}
	if (strcmp(mode, "--once") == 0) {
		errno = 0;
		int claimed = stafeto_fast_claim(&c, STAFETO_FAST_ONCE);
		REQUIRE(claimed == -1 && errno == EBUSY);
		printf("fast-echo: busy ok\n");
		return 0;
	}
	if (strcmp(mode, "--retry") == 0) {
		retry(&c);
	} else if (stafeto_fast_claim(&c, 0) != 0) {
		fail("stafeto_fast_claim");
	}
	REQUIRE(c.kind == STAFETO_FAST_MMIO || c.kind == STAFETO_FAST_PCI);
	REQUIRE(c.objects[0].uncached == 1 && c.objects[1].pages == 1024 && c.ring != 0);
	memcpy(own_ip, c.config.address, 4);
	memcpy(own_mac, c.config.mac, 6);
	if (strcmp(mode, "--rules") == 0)
		return rules(&c);
	int opened = vnet_open(&c);
	if (opened != 0) {
		printf("fast-echo: vnet_open failed %d\n", opened);
		return 1;
	}
	say_address("claimed", &c.config);
	if (strcmp(mode, "--flood") == 0)
		flood();
	return run();
}
