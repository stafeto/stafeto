/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#ifndef STAFETO_SIGNAL_H
#define STAFETO_SIGNAL_H
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <time.h>
#include <stafeto/abi.h>
typedef int sig_atomic_t;
typedef uint64_t sigset_t;
union sigval {
    int sival_int;
    void *sival_ptr;
};
typedef struct {
    int si_signo;
    int si_errno;
    int si_code;
    pid_t si_pid;
    uid_t si_uid;
    int si_status;
    void *si_addr;
    union sigval si_value;
} siginfo_t;
typedef struct {
    void *ss_sp;
    size_t ss_size;
    int ss_flags;
} stack_t;
/* Register fields are stafeto-specific AArch64 ABI extensions. */
typedef struct {
    uint64_t registers[31];
    uint64_t sp, pc, pstate;
    __uint128_t vectors[32];
    uint64_t fpcr, fpsr;
} mcontext_t;
typedef struct ucontext {
    struct ucontext *uc_link;
    sigset_t uc_sigmask;
    stack_t uc_stack;
    mcontext_t uc_mcontext;
} ucontext_t;
struct sigaction {
    union {
        void (*sa_handler)(int);
        void (*sa_sigaction)(int, siginfo_t *, void *);
    };
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
int sigwait(const sigset_t *restrict set, int *restrict sig);
int sigwaitinfo(const sigset_t *restrict set, siginfo_t *restrict info);
int sigtimedwait(const sigset_t *restrict set, siginfo_t *restrict info,
                 const struct timespec *restrict timeout);
#endif
