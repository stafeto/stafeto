/* SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1 */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The driver of the Virtio network device for a program that claimed the
 * second device (<stafeto/fast.h>), as the static library libvirtio_net.a.
 * The process has one device: two queues and 8 192 buffers of 2 KiB in one
 * pool that receiving and sending share. The functions are for one thread.
 */
#ifndef _VNET_H
#define _VNET_H

#include <stddef.h>
#include <stdint.h>
#include <stafeto/fast.h>

#ifdef __cplusplus
extern "C" {
#endif

/* No buffer. */
#define VNET_NONE 0xffffffffu

/* A received frame: its buffer, its length, where it starts. */
struct vnet_buf {
    uint32_t buf, len;
    void *frame;
};

/* Opens the device of the claim: the reset, the features (MTU, MAC,
 * STATUS), the queues, the queue of receiving full. 0, or negative. */
int vnet_open(const struct stafeto_fast_claim *c);

/* Up to n received frames into out: the count (-1 when the device broke
 * the protocol). Each frame's buffer is the program's until
 * vnet_rx_return; the queue of receiving gets free buffers of the pool
 * first. */
int vnet_rx_burst(struct vnet_buf *out, int n);
void vnet_rx_return(uint32_t buf);

/* A free buffer for a frame to send (VNET_NONE when there is none), and
 * where its frame starts. */
uint32_t vnet_buf_take(void);
void *vnet_buf_ptr(uint32_t buf);

/* How many buffers the pool holds free (those in the queues and in the
 * program's hands are not among them). */
uint32_t vnet_buf_free(void);

/* The frame of len bytes in buf into the queue of sending, without the
 * doorbell: 0, or -1 (the queue is full; the buffer stays the program's).
 * The doorbell, and the buffers the device sent back to the pool (their
 * count). */
int vnet_tx(uint32_t buf, uint16_t len);
void vnet_tx_kick(void);
int vnet_tx_reclaim(void);

/* The device's interrupts for received frames on (1) or off (0). After 1,
 * look at the queue once more: a frame that came in between brings none. */
void vnet_notify(int on);

/* 1 when the queue of receiving holds a frame now (a look, nothing taken). */
int vnet_rx_pending(void);

/* The doorbells so far, for the report: out[0] the passes of receiving that
 * gave buffers (one doorbell each before the batching), out[1] the doorbells
 * of receiving, out[2] those of sending. */
void vnet_bells(uint64_t *out);

/* 1 when the device was taken away (reset under the program: the network
 * service ended). The program stops touching it and ends. */
int vnet_lost(void);

/* The IPv4 header sum and the TCP or UDP sum of a frame. */
void vnet_fill_sums(void *frame, size_t len);

/* A copy that reads and writes 64 bytes a turn at any alignment. */
void *vnet_copy(void *dst, const void *src, size_t n);

/* The bypass ring: a frame to the network service (1, or 0 when the ring
 * is full; stafeto_fast_kick tells the service), and the next frame from
 * it (its length, or 0). */
int vnet_bypass_push(const void *frame, size_t len);
size_t vnet_bypass_pop(void *frame, size_t cap);

/*
 * The consumer side of the network service's switch (the ring of
 * <proto_net::switch>): the program attached (stafeto_fast_attach) and the
 * ring object is mapped at the address the attach gave. The functions are
 * for one thread and make no call of the kernel: vnet_port_tx_flush says
 * whether the switch sleeps, and the caller then pokes it
 * (stafeto_fast_poke).
 */

/* A frame the switch delivered: its cell, its length, the DONE flags
 * (1: a copy of an ARP reply for every consumer; 2: an ICMP error; 4: a packet of the
 * loopback network from another stack, to be taken in at lo0; 0x100: the sum of the TCP
 * segment is good, the device checked it or the frame never left the service, so the
 * stack need not), and where it starts. */
struct vnet_port_rx {
    uint32_t cell, len, flags, pad;
    void *frame;
};

/* Opens the consumer over the mapped ring: FILL gets every cell of
 * receiving. 0, or -1 for sizes the layout does not allow. */
int vnet_port_open(void *ring, uint32_t rx_slots, uint32_t tx_slots);

/* Up to n (at most 32) delivered frames: the count, or -1 when the ring broke
 * a rule. A frame's cell is the program's until vnet_port_rx_return. */
int vnet_port_rx_burst(struct vnet_port_rx *out, int n);
void vnet_port_rx_return(uint32_t cell);

/* The cells of FILL the switch has not taken yet. */
uint32_t vnet_port_fill_free(void);

/* Where the next frame to send is built (NULL when TX is full), and the
 * entry for it (the length, at most 1514; flags and spare are 0). The
 * entries are published by vnet_port_tx_flush, which gives 1 when the
 * switch sleeps and must be poked. */
uint8_t *vnet_port_tx_cell(void);
void vnet_port_tx_submit(uint32_t len);
int vnet_port_tx_flush(void);

/* The entry for the frame in the cell is a segment of TCP in IPv4 whose sum is not
 * computed (flag 1): the switch writes the sum of the pseudo-header from the frame it
 * checked and has the device complete the rest (UDP, ICMP and the header of IPv4 keep
 * their software sums). */
void vnet_port_tx_submit_sum(uint32_t len);

/* The entry for the packet in the cell is a packet of the loopback network (flag 4): both its
 * addresses are in 127.0.0.0/8 and its port is no port of this stack's; the switch routes it. */
void vnet_port_tx_submit_loop(uint32_t len);

/* 1 when DONE holds a frame. */
int vnet_port_work(void);

/* Before waiting: the idle flag, a full barrier, one more look at DONE (1
 * when a frame is there and the flag is cleared). After the wait: clears
 * the flag. */
int vnet_port_sleep_begin(void);
void vnet_port_sleep_end(void);

/* 1 when DONE holds an entry now (a look, nothing taken). */
int vnet_port_rx_pending(void);

/* The switch's counters: out[0] frames dropped for a full ring, out[1]
 * frames of TX refused. */
void vnet_port_counters(uint32_t *out);

#ifdef __cplusplus
}
#endif

#endif
