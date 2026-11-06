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

#ifdef __cplusplus
}
#endif

#endif
