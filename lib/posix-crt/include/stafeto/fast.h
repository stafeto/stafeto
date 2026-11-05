/* SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1 */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The second network device in the hands of one program: an extension of
 * the system outside POSIX, which libc.so exports. A process whose
 * effective user is the superuser claims the whole device from the network
 * service when /etc/netd.conf says `handover 1`; the library of the device
 * (`vnet.h`, libvirtio_net.a) drives it from the claim. The network service
 * keeps the device's line and the DHCP client of the second address, which
 * talk to the program through the notifications of stafeto_fast_wait and
 * the bypass ring.
 *
 * The program writes physical addresses into the device's descriptors, and
 * the device has no IOMMU: it is as trusted as the network service. The
 * device goes back to the service when the process ends (or closes its
 * session with the service). While the claim lives, fork and exec fail
 * with EPERM, and munmap, mprotect and mremap of the mapped window and
 * objects fail with EINVAL.
 */
#ifndef _STAFETO_FAST_H
#define _STAFETO_FAST_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* An object of the device: where the process maps it, where it lies for
 * the device, its pages, and whether it is mapped uncached (the queues). */
struct stafeto_fast_object {
    uint64_t va, pa;
    uint32_t pages, uncached;
};

/* The second address: the lease, or the static address of netd.conf. A
 * gateway or name server of zeros is none. */
struct stafeto_fast_config {
    uint8_t address[4], gateway[4], dns[4], mac[6];
    uint8_t prefix, pad;
};

#define STAFETO_FAST_MMIO 1
#define STAFETO_FAST_PCI 2

struct stafeto_fast_claim {
    uint32_t kind, pad;
    /* The transport's registers (MMIO), or BAR 0 of the function (PCI). */
    uint64_t window, window_len;
    /* The queues' object (8 pages, uncached), then four of 4 MiB for the
     * buffers of the frames. */
    struct stafeto_fast_object objects[5];
    /* The bypass ring (17 pages). */
    uint64_t ring;
    /* PCI: the sizes of the BARs and the configuration space of the
     * function, which the process cannot read itself. */
    uint64_t bar_sizes[6];
    uint32_t snapshot[64];
    struct stafeto_fast_config config;
};

_Static_assert(sizeof(struct stafeto_fast_claim) == 480, "the layout of the claim");

/* The bits stafeto_fast_wait gives: the device's interrupt came (the
 * service read its status), a frame waits in the bypass ring, the second
 * address changed (stafeto_fast_config tells it), the link changed. */
#define STAFETO_FAST_INTERRUPT 1u
#define STAFETO_FAST_RING 2u
#define STAFETO_FAST_ADDRESS 4u
#define STAFETO_FAST_CONFIG 8u
/* The service let go of the notifications: it ended (vnet_lost then says
 * whether the device went), or it took the device back. */
#define STAFETO_FAST_GONE 16u

/* Flags of stafeto_fast_claim: fail with EBUSY at once while the device has
 * an owner, without the wait. */
#define STAFETO_FAST_ONCE 1u

/* Claims the second device, maps it and describes it in *out. Waits while
 * the service has no address yet (up to 20 s) and while another process
 * owns the device or it comes back from one (up to 30 s; not with
 * STAFETO_FAST_ONCE). 0, or -1 with errno:
 *   EPERM   not the superuser, or netd.conf has no `handover 1`;
 *   EBUSY   the device has an owner (or the process claimed it already);
 *   ENETDOWN the second device has no address;
 *   ENODEV  no network service, or no second device;
 *   ENOMEM  the ring or the mappings do not fit;
 *   EINVAL  out is null;
 *   EIO     the service answered in a way the layer does not know.
 * The thread that claims is the one that waits: the service notifies its
 * channel. */
int stafeto_fast_claim(struct stafeto_fast_claim *out, unsigned flags);

/* Waits for the service's notification up to timeout_ns nanoseconds (0:
 * only looks) and gives its bits (several may come together). 0, or -1
 * with errno: ETIMEDOUT, EINTR (a signal), EBADF (no claim). */
int stafeto_fast_wait(uint64_t timeout_ns, uint32_t *bits);

/* Tells the service that `count` frames (1 to 16) wait in the bypass ring
 * to it: the frames it took in this step, or -1 with errno: EPROTO when the
 * service found the ring's indices broken (it takes nothing from the ring
 * any more and says `net: bypass broken`; the device stays the program's
 * until it ends), EINVAL for a count out of range, EBADF without a claim. */
int stafeto_fast_kick(uint32_t count);

/* The second address as the service knows it now. 0, or -1 with errno
 * (ENETDOWN while there is none). */
int stafeto_fast_config(struct stafeto_fast_config *out);

#ifdef __cplusplus
}
#endif

#endif
