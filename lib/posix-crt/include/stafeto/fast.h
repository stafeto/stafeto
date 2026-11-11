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

#include <stddef.h>
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
/* An attach to the network service's switch (stafeto_fast_attach): there is
 * no device. The fields of the claim hold: window, window_len: the ring
 * object (the consumer's own, mapped read and write); snapshot[0..7]: the
 * consumer's number, its generation, rx_slots, tx_slots, the first port of
 * the block of ephemeral ports, how many there are, and 1 when the device
 * completes the TCP sums (the stack may then send segments with TX_SUM), else 0; config: the shared
 * address of the service's device (the MAC and the lease); the rest is 0. */
#define STAFETO_FAST_PORT 3

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
/* The service let go of the notifications: it ended (a restarted service
 * may have started the device again, so the device's status may look
 * alive), or it took the device back. The program stops using the device
 * when it sees this bit. */
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
 * channel. A claim that fails after the service gave the device (while the
 * objects are mapped) leaves the device with the process until the process
 * ends: another claim says EBUSY, fork and execve stay refused. */
int stafeto_fast_claim(struct stafeto_fast_claim *out, unsigned flags);

/* Attaches to the network service's switch: makes the ring object, sends
 * ATTACH, maps the ring, and describes it in *out as a claim of kind
 * STAFETO_FAST_PORT. The service notifies the calling thread's channel
 * (stafeto_fast_wait; the bits are 1: frames in the ring, 2: the ring
 * broke, 4: the address changed, 8 or 16: the service let go of the
 * consumer). Waits while the service has no address (up to 20 s). 0, or -1
 * with errno: EAGAIN the service has no switch (a build or a netd.conf
 * without `switch N`): the caller may use stafeto_fast_claim; ENOMEM no
 * room for the ring or the places of the switch are all taken (EBUSY);
 * ENETDOWN, ENODEV, EBUSY (the process attached already), EIO. A process
 * that attached cannot fork or exec, as with a claim. */
int stafeto_fast_attach(struct stafeto_fast_claim *out);

/* Holds TCP `port` with the switch (PORT_HOLD; below 1024 the process must
 * be the superuser) and gives the descriptor of the hold; the programs of the
 * stack do this through bind. -1 with errno: EADDRINUSE, EACCES, ENOMEM (no
 * group), ENOSYS (no switch). stafeto_fast_port_join makes the attached
 * consumer a member of the port's group (EBADF or EINVAL for a descriptor
 * that holds no port, EINVAL without an attach). */
int stafeto_fast_port_hold(unsigned port, int reuseport);

/* 1 when `port` belongs to this process's own stack: a port it holds with the switch, or one
 * of its consumer's block of temporary ports; else 0. A packet of the loopback network for a
 * port that is not its own goes out through the ring (the switch routes it). */
int stafeto_fast_own_port(unsigned port);
int stafeto_fast_port_join(int fd);

/* Tells the switch's thread that frames wait in the ring's TX (the switch
 * sleeps: vnet_port_tx_flush gave 1). 0, or -1 with errno (EBADF without
 * an attach). */
int stafeto_fast_poke(void);

/* Waits for the service's notification up to timeout_ns nanoseconds (0:
 * only looks) and gives its bits (several may come together). A bit that
 * another wait of the same thread (poll, select, a lock, a sleep) took off
 * the thread's channel is kept and comes with the first call after; each
 * bit goes to one call. 0, or -1 with errno: ETIMEDOUT, EINTR (a signal),
 * EBADF (no claim). */
int stafeto_fast_wait(uint64_t timeout_ns, uint32_t *bits);

/* The counters of the sleeps of the loop of epoll_pwait: out[0] sleeps, out[1]
 * wakes by a notification of the service, out[2] wakes by the deadline (no
 * notification), out[3] wakes by the deadline whose first look found events
 * (a frame waited and nothing told the thread). */
void stafeto_fast_wake_counts(uint64_t out[4]);

/* Tells the service that `count` frames (1 to 16) wait in the bypass ring
 * to it: the frames it took in this step, or -1 with errno: EPROTO when the
 * service found the ring's indices broken (it takes nothing from the ring
 * any more and says `net: bypass broken`; the device stays the program's
 * until it ends), EINVAL for a count out of range, EBADF without a claim. */
int stafeto_fast_kick(uint32_t count);

/* The second address as the service knows it now. 0, or -1 with errno
 * (ENETDOWN while there is none). */
int stafeto_fast_config(struct stafeto_fast_config *out);

/* The bits that another wait of the claiming thread took off its channel
 * and the bank holds, taken (each bit goes to one taker): what a program
 * that waits on the thread's channel itself gives to its own stack. 0 with
 * none, and without a claim. */
uint32_t stafeto_fast_take_pending(void);

/* 1 once the service let go of the notifications (STAFETO_FAST_GONE came to
 * any wait), whoever took the bit; sticky until the process ends. */
int stafeto_fast_lost(void);

/*
 * The stack in the process (F-Stack, with libvirtio_net.a) as sockets of
 * the C library. A program that carries the stack registers this table once,
 * from a constructor of its own (the constructors of libc.so run first and
 * the layer's statics are ready), and from then on every
 * socket(AF_INET, SOCK_STREAM, ...) of the process is a socket of the stack.
 * Before the stack runs a socket is a ticket (numbers from 1310720 up, 16
 * of them): the layer keeps its address, backlog and options, so that a
 * process that opens its listeners and forks (nginx's main process) hands each
 * child the listeners, and the child's stack makes the sockets. The layer
 * starts the stack at the first epoll_ctl, accept or connect: it claims the
 * second device (stafeto_fast_claim; its pause between tries is not ended
 * by a signal, since those calls have no EINTR), calls `start`, and makes the
 * sockets of the tickets. fork is allowed while the process has tickets only
 * (the child's tickets with FD_CLOFORK are closed), exec is allowed too and
 * passes no ticket on. The sockets of the stack have numbers from
 * 1048576 up and are non-blocking from birth: accept, accept4, read, write,
 * readv, writev, send, recv, sendmsg, recvmsg, connect, bind, listen, close,
 * shutdown, getsockopt, setsockopt, getsockname, getpeername, fcntl
 * (O_NONBLOCK stays on; FD_CLOEXEC and FD_CLOFORK read as set), ioctl
 * (FIONBIO 1, FIONREAD) and fstat work; epoll_ctl takes them with the
 * events EPOLLIN, EPOLLOUT, EPOLLRDHUP, EPOLLET and EPOLLONESHOT, and
 * epoll_pwait on such an instance drives the stack (a step of it, the
 * events, a sleep of at most 10 ms with the device's interrupts on).
 * poll, select, dup, dup2, dup3, F_DUPFD, descriptor passing and
 * clearing O_NONBLOCK are refused (EINVAL, EOPNOTSUPP). A process that
 * holds the stack cannot fork or exec.
 *
 * Every function answers a count not below zero, or the negated errno of
 * Linux (ENOBUFS, ENETDOWN and EMSGSIZE of the send path among them).
 * Addresses are the structures of Linux. `kevent` takes and gives the
 * 64-byte struct kevent of FreeBSD, with a time of zero. The layer calls the
 * functions one at a time (a lock of its own is held), and reaches the stack
 * through the table alone: libc.so names nothing of the program.
 *
 * STAFETO_FAST_ADDRESS is only printed by the stack: a lease of the second
 * address is renewed at the same address (a new address is not supported).
 */
#define STAFETO_FAST_TABLE_VERSION 1
/* The process ends with status 2 when the service lets go of the device (the
 * loop of epoll_pwait sees it at the next turn, at most one clock tick after
 * the service ends), after a line on the console. nginx's main process does
 * not start a new worker for status 2. Without the flag epoll_pwait answers
 * ENETDOWN. */
#define STAFETO_FAST_EXIT_ON_LOSS 1u

struct stafeto_fast_table {
    uint32_t version;
    uint32_t flags;
    /* The claim has been made: attach the device and start the stack. */
    int (*start)(const struct stafeto_fast_claim *);
    /* One step of the stack (clock ticks, frames, software interrupts, the
     * doorbell): the units of work done, 0 when idle. */
    int (*pass)(void);
    /* Nanoseconds to the next clock tick, 0 when due. */
    uint64_t (*next_tick_ns)(void);
    /* The device's interrupts on (with a full barrier) or off. */
    void (*notify)(int on);
    /* The bits of STAFETO_FAST_* that the layer took off the channel. */
    void (*absorb)(uint32_t bits);
    int (*socket)(int, int, int);
    int (*bind)(int, const void *, uint32_t);
    int (*listen)(int, int);
    int (*accept4)(int, void *, uint32_t *, int);
    int (*connect)(int, const void *, uint32_t);
    long (*read)(int, void *, size_t);
    long (*write)(int, const void *, size_t);
    long (*readv)(int, const void *, int);
    long (*writev)(int, const void *, int);
    long (*recvfrom)(int, void *, size_t, int, void *, uint32_t *);
    long (*sendto)(int, const void *, size_t, int, const void *, uint32_t);
    long (*recvmsg)(int, void *, int);
    long (*sendmsg)(int, const void *, int);
    int (*close)(int);
    int (*shutdown)(int, int);
    int (*getsockopt)(int, int, int, void *, uint32_t *);
    int (*setsockopt)(int, int, int, const void *, uint32_t);
    int (*getsockname)(int, void *, uint32_t *);
    int (*getpeername)(int, void *, uint32_t *);
    int (*ioctl)(int, unsigned long, void *);
    int (*kqueue)(void);
    /* The time is always zero. */
    int (*kevent)(int, const void *, int, void *, int);
};

_Static_assert(sizeof(struct stafeto_fast_table) == 8 + 27 * sizeof(void *),
    "the layout of the table");

/* Registers the table (a copy is kept): 0, or -1 with errno: EINVAL for a
 * version or flag the layer does not know, a null function or a null
 * table; EBUSY when a table is registered already. */
int stafeto_fast_register(const struct stafeto_fast_table *table);

#ifdef __cplusplus
}
#endif

#endif
