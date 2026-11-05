/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
 *
 * `fstack-probe device`: the TCP/IP stack of FreeBSD 15 (F-Stack) on the
 * second network device of stafeto, driven through the claim of the device
 * (<stafeto/fast.h>) and libvirtio_net.a (cargo xtask fstack-probe device).
 *
 * The program claims the device, gives the claim to the host layer
 * (ff_stafeto_attach) and starts the stack; its address is the static
 * address1 of /etc/netd.conf. Then it serves from the run loop of the layer:
 *
 *   UDP 7    the datagram back to its sender; the datagram `?stats` gets the
 *            layer's counters as `key=value` words, `?stop` ends the program
 *   TCP 80   any request (up to the empty line) gets the page: a head and
 *            1 MiB of a fixed pattern (page_byte), then the connection closes
 *
 * `fstack-probe device flood` first puts 16 frames of DHCP in the bypass
 * ring at once (the bound of the network service's step).
 * `fstack-probe device hold` accepts the connections of TCP 80 and never
 * reads them, so each segment a client sends stays in a socket's queue and
 * keeps its buffer of the device (the free-buffer threshold of the layer).
 *
 * Built with -fno-builtin; every result is compared. Lines are
 * `fstack-probe: ...`; a failure ends the program with 1.
 */

#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <stafeto/fast.h>
#include <vnet.h>

#include "ff_api.h"
#include "ff_stafeto.h"

#define CONF "/etc/fstack.ini"
#define UDP_PORT 7
#define TCP_PORT 80
#define PAGE_BYTES (1u << 20)
#define MAX_CONNECTIONS 64
#define MAX_HELD 8192
#define ETH 14

enum { MODE_SERVE, MODE_FLOOD, MODE_HOLD };

struct connection {
    int fd;
    char seen[4];
    unsigned asked, head_sent, body_sent;
};

static int mode;
static int udp_fd = -1, tcp_fd = -1;
static struct connection connections[MAX_CONNECTIONS];
static int held[MAX_HELD];
static int held_count;
static unsigned long accepted, served, echoed;
static unsigned char page[PAGE_BYTES];
static char head[128];
static int head_len;

static uint64_t
now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void
fail(const char *what)
{
    printf("fstack-probe: check failed: %s (errno %d)\n", what, errno);
    fflush(stdout);
    _exit(1);
}

#define REQUIRE(cond) do { if (!(cond)) fail(#cond); } while (0)

/* Byte i of the page: xtask computes the same. */
static unsigned char
page_byte(unsigned i)
{
    return (unsigned char)(i * 7u + (i >> 8) + (i >> 16));
}

static void
nonblocking(int fd)
{
    int on = 1;

    REQUIRE(ff_ioctl(fd, FIONBIO, &on) == 0);
}

static int
open_udp(int port)
{
    struct sockaddr_in a;
    int fd = ff_socket(AF_INET, SOCK_DGRAM, 0);

    REQUIRE(fd >= 0);
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    REQUIRE(ff_bind(fd, (struct linux_sockaddr *)&a, sizeof(a)) == 0);
    nonblocking(fd);
    return fd;
}

static int
open_tcp(int port)
{
    struct sockaddr_in a;
    int on = 1, fd = ff_socket(AF_INET, SOCK_STREAM, 0);

    REQUIRE(fd >= 0);
    REQUIRE(ff_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == 0);
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    REQUIRE(ff_bind(fd, (struct linux_sockaddr *)&a, sizeof(a)) == 0);
    REQUIRE(ff_listen(fd, 1024) == 0);
    nonblocking(fd);
    return fd;
}

static int
stats_text(char *out, size_t cap)
{
    struct ff_stafeto_device_stats s;
    unsigned long long frames_in, frames_out;

    ff_stafeto_device_stats(&s);
    frames_in = s.rx_frames ? s.rx_frames : 1;
    frames_out = s.tx_frames ? s.tx_frames : 1;
    return snprintf(out, cap,
        "rx=%llu zero_copy=%llu copied=%llu bypass=%llu bypass_full=%llu no_mbuf=%llu "
        "tx=%llu tx_no_buffer=%llu tx_full=%llu tx_long=%llu tx_bypass=%llu foreign=%llu "
        "rx_layer_ticks=%llu rx_input_ticks=%llu tx_send_ticks=%llu "
        "rx_layer_per_frame=%llu rx_input_per_frame=%llu tx_per_frame=%llu "
        "kicks=%llu sleeps=%llu found_work=%llu notifications=%llu freq=%llu "
        "free_low=%u free_now=%u accepted=%lu served=%lu echoed=%lu held=%d",
        (unsigned long long)s.rx_frames, (unsigned long long)s.rx_zero_copy,
        (unsigned long long)s.rx_copied, (unsigned long long)s.rx_bypass,
        (unsigned long long)s.rx_bypass_full, (unsigned long long)s.rx_no_mbuf,
        (unsigned long long)s.tx_frames, (unsigned long long)s.tx_no_buffer,
        (unsigned long long)s.tx_full, (unsigned long long)s.tx_long,
        (unsigned long long)s.tx_bypass, (unsigned long long)s.tx_foreign,
        (unsigned long long)s.rx_layer_ticks, (unsigned long long)s.rx_input_ticks,
        (unsigned long long)s.tx_send_ticks,
        (unsigned long long)(s.rx_layer_ticks / frames_in),
        (unsigned long long)(s.rx_input_ticks / frames_in),
        (unsigned long long)(s.tx_send_ticks / frames_out), (unsigned long long)s.kicks,
        (unsigned long long)s.sleeps, (unsigned long long)s.sleeps_found_work,
        (unsigned long long)s.notifications, (unsigned long long)s.ticks_per_second,
        s.free_low, s.free_now, accepted, served, echoed, held_count);
}

/* The datagrams of port 7: the echo, and the two commands. */
static int
serve_udp(void)
{
    static char buf[2048];
    int work = 0, n;

    for (n = 0; n < 32; n++) {
        struct sockaddr_in from;
        socklen_t flen = sizeof(from);
        ssize_t got = ff_recvfrom(udp_fd, buf, sizeof(buf), 0,
            (struct linux_sockaddr *)&from, &flen);

        if (got < 0) {
            REQUIRE(errno == EAGAIN);
            break;
        }
        work = 1;
        if (got == 6 && memcmp(buf, "?stats", 6) == 0) {
            static char text[1400];
            int len = stats_text(text, sizeof(text));

            printf("fstack-probe: stats %s\n", text);
            fflush(stdout);
            if (len > (int)sizeof(text) - 1)
                len = (int)sizeof(text) - 1;
            ff_sendto(udp_fd, text, (size_t)len, 0, (struct linux_sockaddr *)&from, flen);
            continue;
        }
        if (got == 5 && memcmp(buf, "?stop", 5) == 0) {
            printf("fstack-probe: stop\n");
            fflush(stdout);
            ff_stop_run();
            continue;
        }
        if (ff_sendto(udp_fd, buf, (size_t)got, 0, (struct linux_sockaddr *)&from, flen) == got)
            echoed++;
    }
    return work;
}

static void
drop(struct connection *c)
{
    ff_close(c->fd);
    memset(c, 0, sizeof(*c));
    c->fd = -1;
}

/* One connection: read up to the empty line, then write the head and the
 * page as far as the stack takes it, and close at the end. */
static int
serve_connection(struct connection *c)
{
    int work = 0;

    if (!c->asked) {
        char buf[512];
        ssize_t got = ff_read(c->fd, buf, sizeof(buf));
        ssize_t i;

        if (got == 0) {
            drop(c);
            return 1;
        }
        if (got < 0) {
            if (errno == EAGAIN)
                return 0;
            drop(c);
            return 1;
        }
        work = 1;
        for (i = 0; i < got; i++) {
            memmove(c->seen, c->seen + 1, 3);
            c->seen[3] = buf[i];
            if (memcmp(c->seen, "\r\n\r\n", 4) == 0)
                c->asked = 1;
        }
        if (!c->asked)
            return work;
    }
    while (c->head_sent < (unsigned)head_len) {
        ssize_t w = ff_write(c->fd, head + c->head_sent, (size_t)head_len - c->head_sent);

        if (w < 0) {
            if (errno == EAGAIN)
                return work;
            drop(c);
            return 1;
        }
        c->head_sent += (unsigned)w;
        work = 1;
    }
    while (c->body_sent < PAGE_BYTES) {
        unsigned left = PAGE_BYTES - c->body_sent;
        ssize_t w = ff_write(c->fd, page + c->body_sent, left > 65536 ? 65536 : left);

        if (w < 0) {
            if (errno == EAGAIN)
                return work;
            drop(c);
            return 1;
        }
        c->body_sent += (unsigned)w;
        work = 1;
    }
    served++;
    drop(c);
    return 1;
}

static int
serve_tcp(void)
{
    int work = 0, i;

    for (;;) {
        int fd = ff_accept(tcp_fd, NULL, NULL);

        if (fd < 0) {
            REQUIRE(errno == EAGAIN);
            break;
        }
        work = 1;
        accepted++;
        nonblocking(fd);
        if (mode == MODE_HOLD) {
            if (held_count < MAX_HELD)
                held[held_count++] = fd;
            else
                ff_close(fd);
            continue;
        }
        for (i = 0; i < MAX_CONNECTIONS; i++) {
            if (connections[i].fd <= 0) {
                memset(&connections[i], 0, sizeof(connections[i]));
                connections[i].fd = fd;
                break;
            }
        }
        if (i == MAX_CONNECTIONS)
            ff_close(fd);
    }
    for (i = 0; i < MAX_CONNECTIONS; i++)
        if (connections[i].fd > 0)
            work |= serve_connection(&connections[i]);
    return work;
}

static int
serve(void *arg)
{
    (void)arg;
    return serve_udp() | serve_tcp();
}

/* 16 frames of DHCP to the stack's address in the bypass ring at once,
 * which the network service takes two a step. */
static void
flood(const struct stafeto_fast_claim *c)
{
    uint8_t f[342];
    int pushed = 0, i, taken;

    memset(f, 0, sizeof(f));
    memcpy(f, c->config.mac, 6);
    f[12] = 0x08;
    f[14] = 0x45;
    f[ETH + 2] = (uint8_t)((sizeof(f) - ETH) >> 8);
    f[ETH + 3] = (uint8_t)(sizeof(f) - ETH);
    f[ETH + 8] = 64;
    f[ETH + 9] = 17;
    memcpy(f + ETH + 16, c->config.address, 4);
    f[ETH + 21] = 67;
    f[ETH + 23] = 68;
    f[ETH + 24] = (uint8_t)((sizeof(f) - ETH - 20) >> 8);
    f[ETH + 25] = (uint8_t)(sizeof(f) - ETH - 20);
    vnet_fill_sums(f, sizeof(f));
    for (i = 0; i < 16; i++)
        pushed += vnet_bypass_push(f, sizeof(f));
    REQUIRE(pushed == 16);
    taken = stafeto_fast_kick(16);
    REQUIRE(taken >= 1 && taken <= 16);
    printf("fstack-probe: flood taken %d\n", taken);
    fflush(stdout);
}

int
fstack_device_main(int argc, char **argv)
{
    char *args[] = { "fstack-probe", "--conf", CONF, NULL };
    struct stafeto_fast_claim claim;
    uint64_t started;
    unsigned i;

    mode = MODE_SERVE;
    if (argc > 2 && strcmp(argv[2], "flood") == 0)
        mode = MODE_FLOOD;
    else if (argc > 2 && strcmp(argv[2], "hold") == 0)
        mode = MODE_HOLD;
    for (i = 0; i < PAGE_BYTES; i++)
        page[i] = page_byte(i);
    head_len = snprintf(head, sizeof(head),
        "HTTP/1.1 200 OK\r\nContent-Length: %u\r\nConnection: close\r\n\r\n", PAGE_BYTES);
    for (i = 0; i < MAX_CONNECTIONS; i++)
        connections[i].fd = -1;
    started = now_ms();
    if (stafeto_fast_claim(&claim, 0) != 0)
        fail("stafeto_fast_claim");
    REQUIRE(ff_stafeto_attach(&claim) == 0);
    if (ff_init(3, args) != 0) {
        printf("fstack-probe: check failed: ff_init\n");
        return 1;
    }
    printf("fstack-probe: device up %u.%u.%u.%u/%u mac %02x:%02x:%02x:%02x:%02x:%02x "
        "(the claim and ff_init took %llu ms)\n",
        claim.config.address[0], claim.config.address[1], claim.config.address[2],
        claim.config.address[3], claim.config.prefix, claim.config.mac[0],
        claim.config.mac[1], claim.config.mac[2], claim.config.mac[3], claim.config.mac[4],
        claim.config.mac[5], (unsigned long long)(now_ms() - started));
    udp_fd = open_udp(UDP_PORT);
    tcp_fd = open_tcp(TCP_PORT);
    if (mode == MODE_FLOOD)
        flood(&claim);
    printf("fstack-probe: device serving\n");
    fflush(stdout);
    ff_run(serve, NULL);
    if (ff_stafeto_device_lost()) {
        printf("fstack-probe: device lost\n");
        return 2;
    }
    {
        char text[1400];

        stats_text(text, sizeof(text));
        printf("fstack-probe: device ended %s\n", text);
    }
    return 0;
}
