/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
 *
 * The names of the host layer of F-Stack on stafeto (ff_stafeto_if.c) that
 * a program calls besides ff_api.h.
 */
#ifndef _FF_STAFETO_H
#define _FF_STAFETO_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stafeto_fast_claim;

/*
 * Gives the layer the claim of the second network device
 * (stafeto_fast_claim, <stafeto/fast.h>) before ff_init: the stack then has
 * that device as its interface, with the claim's address, and drives it
 * with libvirtio_net.a. Without a claim the stack has its loopback alone.
 * A claim of kind STAFETO_FAST_PORT is an attach to the service's switch:
 * the interface is the consumer's ring (vnet_port_*) with the shared
 * address. 0, or -1 (a second call).
 */
int ff_stafeto_attach(const struct stafeto_fast_claim *claim);

/* One step of the stack: the clock ticks that are due, the frames of the
 * device, the work of the stack's software interrupts, the frames to send.
 * Gives the units of work done, 0 when it found everything idle. */
int ff_stafeto_pass(void);

/* The time to the next clock tick in nanoseconds, 0 when it is due. */
uint64_t ff_stafeto_next_tick_ns(void);

/*
 * Idle until the work is back: at most `max_ns` and not past the next clock
 * tick. With a device it turns the device's interrupts on, steps the stack
 * once more (a frame that came in between brings no interrupt) and waits
 * for the network service's notification. Gives 1 when the second look found
 * work and it did not wait, else 0.
 */
int ff_stafeto_sleep(uint64_t max_ns);

/*
 * The only place the layer reads the service's notifications is
 * ff_stafeto_sleep and the look once per clock tick; both bank the bits
 * (STAFETO_FAST_*) with this function. A program that receives on the
 * thread's channel itself (the POSIX layer's epoll) gives the bits of the
 * claim's notifications to it the same way.
 */
void ff_stafeto_absorb(uint32_t bits);

/* The wake flag of the device on (full barrier inside) or off: the
 * device's interrupts, or the idle flag of the switch's ring. */
void ff_stafeto_notify(int on);

/* 1 when the device was taken away: the layer stops using it, and
 * ff_run ends. */
int ff_stafeto_device_lost(void);

/* The layer's measures of the device (counters; costs in ticks of the
 * counter CNTVCT_EL0, frequency in `ticks_per_second`). */
struct ff_stafeto_device_stats {
    uint64_t ticks_per_second;
    uint64_t rx_frames, rx_zero_copy, rx_copied, rx_bypass, rx_bypass_full, rx_no_mbuf;
    uint64_t tx_frames, tx_no_buffer, tx_full, tx_long, tx_bypass, tx_foreign, tx_waited;
    uint64_t rx_layer_ticks, rx_input_ticks, tx_send_ticks;
    uint64_t kicks, sleeps, sleeps_found_work, notifications;
    /* Sleeps of the program's loop that ended by the deadline with a frame in the ring
     * already when they ended (the frame waited through the sleep). */
    uint64_t deadline_found;
    uint32_t free_low, free_now;
    uint64_t bell_rx_passes, bell_rx, bell_tx;
    /* TCP segments sent without their sum (TX_SUM), and frames received whose sum the
     * switch said was good (DONE_SUM_OK). */
    uint64_t tx_sum, rx_sum_ok;
    /* Frames of TCP handed to the device whole, to be cut into segments (TX_TSO). */
    uint64_t tx_tso;
};
void ff_stafeto_device_stats(struct ff_stafeto_device_stats *out);

#ifdef __cplusplus
}
#endif

#endif
