/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#ifndef STAFETO_SIGNAL_H
#define STAFETO_SIGNAL_H
#include <stdint.h>
#include <sys/types.h>
#include <stafeto/abi.h>
typedef int sig_atomic_t;
typedef uint64_t sigset_t;
struct sigaction {
    void (*sa_handler)(int);
    sigset_t sa_mask;
    int sa_flags;
};
#define SIG_DFL ((void (*)(int))0)
#define SIG_IGN ((void (*)(int))1)
#define SIG_ERR ((void (*)(int))-1)
int sigemptyset(sigset_t *set);
int sigfillset(sigset_t *set);
int sigaddset(sigset_t *set, int sig);
int sigdelset(sigset_t *set, int sig);
int sigismember(const sigset_t *set, int sig);
int sigaction(int sig, const struct sigaction *restrict act, struct sigaction *restrict old);
void (*signal(int sig, void (*handler)(int)))(int);
int pthread_sigmask(int how, const sigset_t *restrict set, sigset_t *restrict old);
int sigprocmask(int how, const sigset_t *restrict set, sigset_t *restrict old);
int sigpending(sigset_t *set);
int pthread_kill(pthread_t thread, int sig);
int raise(int sig);
#endif
