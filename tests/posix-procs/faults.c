/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* Faults as signals, and the alternate signal stack.
 *
 * The role "faults" forks one child per case and reaps it: an exit code
 * names the failed check (0 passes), a signal is the expected end.
 *
 * - sigaltstack: the state, ENOMEM below MINSIGSTKSZ, EINVAL for flags, the
 *   stack as a handler sees it (SS_ONSTACK) and EPERM while on it.
 * - Recursion into the end of the main stack: with an alternate stack the
 *   SIGSEGV handler runs on it (its locals lie in the range) and leaves by
 *   siglongjmp, and the child exits 0; without one the child ends by
 *   SIGSEGV (the kernel killed it before the layer caught faults).
 * - A signal inside that handler enters below its frame on the alternate
 *   stack and leaves the outer locals whole.
 * - A handler without SA_ONSTACK entered at the top of the alternate stack
 *   runs on the interrupted stack, and a signal with SA_ONSTACK inside it
 *   neither treads on the frame of the dispatcher nor on the outer handler.
 * - Nested handlers on the alternate stack (#293): a stack of 36 KiB holds
 *   handler B off the stack, A on it and C on it that jumps into A; one of
 *   20 KiB ends the process by SIGSEGV as soon as the delivery would leave
 *   less than 4 KiB, with nothing trodden on.
 * - Levels of handlers off the stack (#287): a jump from E, inside B, into B
 *   leaves B's frames whole for the next SA_ONSTACK signal; a jump from E
 *   into the main code leaves the whole stack to the next one.
 * - A child of fork made in a handler off the stack takes SA_ONSTACK signals
 *   under the live frames (#286).
 * - A stack of MINSIGSTKSZ bytes serves a handler with a 2 KiB array (#289).
 * - The classes of the syndrome: an undefined instruction is SIGILL, a
 *   breakpoint SIGTRAP, a misaligned exclusive SIGBUS, a load from an
 *   unmapped address SIGSEGV with SEGV_MAPERR and its address, a write to
 *   code SEGV_ACCERR; each reaches a handler with si_addr and ends the
 *   child by the signal without one. A blocked signal ends the child, a
 *   fault inside the handler of another fault enters its own handler.
 */
#include <setjmp.h>
#include <pthread.h>
#include <sys/mman.h>

_Static_assert(MINSIGSTKSZ >= 1904 + 4096, "the stack holds the entry frame and the delivery");

#define F_STACK 65536
/* Mapped by the role (a static array would charge every role of this program
 * with its pages, and the quota probes of the names count them). */
static char *f_area;
static sigjmp_buf f_env;
static volatile int f_stage;
static volatile unsigned long f_where[4];

#define F_CTX_PC(ctx) (*(unsigned long *)((char *)(ctx) + 440))

static int f_on_alt(void) {
    stack_t o;
    if (sigaltstack(NULL, &o)) return -1;
    return (o.ss_flags & SS_ONSTACK) != 0;
}
static int f_in_alt(const volatile void *p) {
    return (const volatile char *)p >= f_area && (const volatile char *)p < f_area + F_STACK;
}
static int f_set_alt(void) {
    stack_t ss = {.ss_sp = f_area, .ss_size = F_STACK, .ss_flags = 0};
    return sigaltstack(&ss, NULL);
}
static int f_catch(int sig, void (*h)(int, siginfo_t *, void *), int flags) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = h;
    sa.sa_flags = flags | SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    return sigaction(sig, &sa, NULL);
}

static void f_h_eperm(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    stack_t other = {.ss_sp = f_area, .ss_size = F_STACK / 2, .ss_flags = 0};
    f_stage = 1;
    if (!f_on_alt()) f_stage = 90;
    if (sigaltstack(&other, NULL) != -1 || errno != EPERM) f_stage = 91;
}

static int f_api(void) {
    stack_t ss, old;
    if (sigaltstack(NULL, &old)) return 1;
    if (old.ss_flags != SS_DISABLE) return 2;
    ss.ss_sp = f_area;
    ss.ss_size = MINSIGSTKSZ - 1;
    ss.ss_flags = 0;
    if (sigaltstack(&ss, NULL) != -1 || errno != ENOMEM) return 3;
    ss.ss_size = F_STACK;
    ss.ss_flags = 4;
    if (sigaltstack(&ss, NULL) != -1 || errno != EINVAL) return 4;
    ss.ss_flags = 0;
    if (sigaltstack(&ss, &old)) return 5;
    if (old.ss_flags != SS_DISABLE) return 6;
    memset(&old, 0, sizeof(old));
    if (sigaltstack(NULL, &old) || old.ss_sp != f_area || old.ss_size != F_STACK || old.ss_flags != 0) return 7;
    if (f_catch(SIGUSR1, f_h_eperm, SA_ONSTACK)) return 8;
    raise(SIGUSR1);
    if (f_stage != 1) return 10 + f_stage;
    ss.ss_flags = SS_DISABLE;
    if (sigaltstack(&ss, &old) || old.ss_sp != f_area) return 9;
    if (sigaltstack(NULL, &old) || old.ss_flags != SS_DISABLE) return 12;
    return 0;
}

static void f_h_segv(int sig, siginfo_t *info, void *ctx) {
    (void)ctx;
    volatile char here = 0;
    f_stage = 2;
    if (!f_in_alt(&here)) f_stage = 90;
    else if (f_on_alt() != 1) f_stage = 91;
    else if (sig != SIGSEGV || info->si_signo != SIGSEGV
             || (info->si_code != SEGV_MAPERR && info->si_code != SEGV_ACCERR)) f_stage = 92;
    siglongjmp(f_env, 1);
}

static volatile int f_limit; /* 0: no end but the stack's */
static int f_recurse(int n) {
    volatile char buf[2048];
    if (f_limit && n > f_limit) return n;
    buf[0] = (char)n;
    buf[2047] = (char)n;
    return n + f_recurse(n + 1) + buf[0] + buf[2047];
}

/* The end of the stack, caught on the alternate stack. */
static int f_overflow_caught(void) {
    if (f_set_alt()) return 1;
    if (f_catch(SIGSEGV, f_h_segv, SA_ONSTACK)) return 2;
    /* Three times: the jump out of the handler on the alternate stack leaves
     * no entry of the thread behind (the frames of both stacks are told apart). */
    for (int round = 0; round < 3; round++) {
        f_stage = 0;
        if (sigsetjmp(f_env, 1) == 0) {
            int r = f_recurse(0);
            return 3 + (r & 1);
        }
        /* The jump left the alternate stack: the mask is back and so is the state. */
        if (f_on_alt() != 0) return 4;
        if (f_stage != 2) return 20 + f_stage % 70;
    }
    return 0;
}

/* A child of fork keeps the alternate stack: the layer asks the kernel for it
 * again, and the child's overflow is caught on it. */
static int f_forked_alt(void) {
    if (f_set_alt()) return 1;
    if (f_catch(SIGSEGV, f_h_segv, SA_ONSTACK)) return 2;
    pid_t pid = fork();
    if (pid < 0) return 3;
    if (pid == 0) {
        stack_t o;
        if (sigaltstack(NULL, &o) || o.ss_sp != f_area || o.ss_size != F_STACK || o.ss_flags != 0) _exit(4);
        f_stage = 0;
        if (sigsetjmp(f_env, 1) == 0) {
            int r = f_recurse(0);
            _exit(5 + (r & 1));
        }
        _exit(f_stage == 2 ? 0 : 20 + f_stage % 70);
    }
    int status = -1;
    if (waitpid(pid, &status, 0) != pid) return 7;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 100 + WTERMSIG(status);
}

/* The handler on the alternate stack runs out of it: the fault finds the
 * stack pointer below the range, the kernel would start over at the top on
 * the live frames, and the layer ends the process by SIGSEGV. */
static void f_h_deep(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    (void)f_recurse(0);
}
static int f_alt_overflow(void) {
    char *region = mmap(NULL, F_STACK + 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) return 1;
    /* A hole below the stack. */
    if (munmap(region, 4096)) return 2;
    stack_t ss = {.ss_sp = region + 4096, .ss_size = F_STACK, .ss_flags = 0};
    if (sigaltstack(&ss, NULL)) return 3;
    if (f_catch(SIGSEGV, f_h_deep, SA_ONSTACK | SA_NODEFER)) return 4;
    *(volatile int *)0x10 = 1;
    return 5;
}

/* The same without an alternate stack, and no handler: the signal ends it. */
static int f_overflow_default(void) {
    return f_recurse(0) & 1;
}

static void f_h_inner(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    volatile unsigned char junk[1536];
    for (unsigned i = 0; i < sizeof(junk); i++) junk[i] = 0xEE;
    f_where[1] = (unsigned long)&junk[0];
    if (!f_in_alt(&junk[0])) f_stage = 93;
}
static void f_h_outer(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    volatile unsigned char sentinel[512];
    for (unsigned i = 0; i < sizeof(sentinel); i++) sentinel[i] = 0x5A;
    f_where[0] = (unsigned long)&sentinel[0];
    f_stage = 2;
    raise(SIGUSR1);
    for (unsigned i = 0; i < sizeof(sentinel); i++)
        if (sentinel[i] != 0x5A) f_stage = 94;
    if (!(f_where[1] != 0 && f_where[1] < f_where[0])) f_stage = 95;
    siglongjmp(f_env, 1);
}

/* A signal inside the handler on the alternate stack enters below its frame. */
static int f_nested_on_alt(void) {
    if (f_set_alt()) return 1;
    if (f_catch(SIGSEGV, f_h_outer, SA_ONSTACK | SA_NODEFER)) return 2;
    if (f_catch(SIGUSR1, f_h_inner, SA_ONSTACK)) return 3;
    if (sigsetjmp(f_env, 1) == 0) {
        *(volatile int *)0x10 = 1;
        return 4;
    }
    return f_stage == 2 ? 0 : 20 + f_stage % 70;
}

static volatile unsigned f_sum;
static volatile int f_mode;
static void f_h_b(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    /* A big frame treads on whatever lies at the top of the alternate stack. */
    volatile unsigned char junk[3072];
    for (unsigned i = 0; i < sizeof(junk); i++) junk[i] = 0xEE;
    /* With SA_ONSTACK on the alternate stack, under the frames of the
     * outer entry; without, on the interrupted stack as the outer handler. */
    if (f_in_alt(&junk[0]) != (f_mode == 2)) f_stage = 93;
    if (f_on_alt() != (f_mode == 2)) f_stage = 96;
    f_stage++;
}
static void f_h_a(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    volatile unsigned char sentinel[256];
    for (unsigned i = 0; i < sizeof(sentinel); i++) sentinel[i] = 0x33;
    /* Without SA_ONSTACK: on the interrupted stack, though the entry frame is
     * at the top of the alternate stack. */
    if (f_in_alt(&sentinel[0])) f_stage = 97;
    if (f_on_alt() != 0) f_stage = 98;
    f_stage = 1;
    if (f_mode) raise(SIGUSR2);
    else f_stage = 2;
    for (unsigned i = 0; i < sizeof(sentinel); i++)
        if (sentinel[i] != 0x33) f_stage = 99;
    if (f_stage == 2) f_stage = 3;
}

/* Item 4 of the check of the kernel: a handler without SA_ONSTACK, an
 * SA_ONSTACK signal in it, both return. */
static int f_off_stack_nested(void);
static int f_off_stack_plain(void) { f_mode = 0; return f_off_stack_nested(); }
static int f_off_stack_both(void) { f_mode = 1; return f_off_stack_nested(); }
static int f_off_stack_on(void) { f_mode = 2; return f_off_stack_nested(); }
static int f_off_stack_nested(void) {
    if (f_set_alt()) return 1;
    if (f_catch(SIGUSR1, f_h_a, 0)) return 2;
    if (f_catch(SIGUSR2, f_h_b, f_mode == 2 ? SA_ONSTACK : 0)) return 3;
    unsigned sum = 0;
    for (unsigned round = 0; round < 8; round++) {
        f_stage = 0;
        unsigned mine = 0x1234 + round;
        raise(SIGUSR1);
        if (f_stage != 3) return 10 + f_stage % 90;
        sum += mine;
        /* The registers of the interrupted code came back whole. */
        if (mine != 0x1234 + round) return 5;
    }
    f_sum = sum;
    return sum == 8 * 0x1234 + 28 ? 0 : 6;
}

/* 100 jumps out of a handler without SA_ONSTACK entered at the top of the
 * alternate stack: each leaves the kernel's range whole, and the stack still
 * serves a handler with SA_ONSTACK at the end. */
static void f_h_jump(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    siglongjmp(f_env, 1);
}
static void f_h_last(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    volatile char here = 0;
    f_stage = f_in_alt(&here) && f_on_alt() == 1 ? 2 : 90;
}
static int f_many_jumps(void) {
    if (f_set_alt()) return 1;
    if (f_catch(SIGUSR1, f_h_jump, 0)) return 2;
    if (f_catch(SIGUSR2, f_h_last, SA_ONSTACK)) return 3;
    for (int i = 0; i < 100; i++) {
        if (sigsetjmp(f_env, 1) == 0) {
            raise(SIGUSR1);
            return 4;
        }
    }
    f_stage = 0;
    raise(SIGUSR2);
    return f_stage == 2 ? 0 : 20 + f_stage % 70;
}

/* A plain handler (no SA_SIGINFO) without SA_ONSTACK raises a signal whose
 * plain handler has SA_ONSTACK: no entry of the kernel serves it, and the
 * stack it takes lies under the live frame of the first entry. */
static void f_h_plain_on(int sig) {
    (void)sig;
    volatile unsigned char junk[3072];
    for (unsigned i = 0; i < sizeof(junk); i++) junk[i] = 0xEE;
    f_stage = f_in_alt(&junk[0]) ? 2 : 90;
}
static void f_h_plain_off(int sig) {
    (void)sig;
    raise(SIGUSR2);
}
static void f_h_info_off(int sig, siginfo_t *info, void *ctx) {
    (void)info; (void)ctx;
    f_h_plain_off(sig);
}
static int f_plain_on_in_off(void) {
    if (f_set_alt()) return 1;
    /* The outer handler has SA_SIGINFO, so that its entry comes to the top
     * of the alternate stack; the inner one is plain. */
    if (f_catch(SIGUSR1, f_h_info_off, 0)) return 2;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = f_h_plain_on;
    sa.sa_flags = SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR2, &sa, NULL)) return 3;
    f_stage = 0;
    raise(SIGUSR1);
    return f_stage == 2 ? 0 : 20 + f_stage % 70;
}

/* The alternate stack above the main stack (a buffer in a frame of the
 * caller): a handler off the stack runs below it. Inside that handler B a
 * handler A with SA_ONSTACK jumps within its own frame, A
 * returns, and a further SA_ONSTACK signal D must still start under the live
 * frame of B's entry, not at the top of the stack. */
static sigjmp_buf f_env2;
static void f_h_c(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    siglongjmp(f_env2, 1);
}
static void f_h_a2(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    if (f_mode >= 1) {
        if (sigsetjmp(f_env2, 1) == 0) siglongjmp(f_env2, 1);
    }
    f_stage++;
}
static void f_h_d(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    volatile unsigned char junk[3072];
    for (unsigned i = 0; i < sizeof(junk); i++) junk[i] = 0xEE;
    f_stage++;
}
static void f_h_b2(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    volatile unsigned char sentinel[128];
    for (unsigned i = 0; i < sizeof(sentinel); i++) sentinel[i] = 0x44;
    raise(SIGUSR2);
    if (f_mode >= 2) raise(SIGPIPE);
    for (unsigned i = 0; i < sizeof(sentinel); i++)
        if (sentinel[i] != 0x44) f_stage = 99;
    f_stage++;
}
static int f_high_alt_run(char *area, size_t size) {
    stack_t ss = {.ss_sp = area, .ss_size = size, .ss_flags = 0};
    if (area && sigaltstack(&ss, NULL)) return 1;
    if (f_catch(SIGUSR1, f_h_b2, 0) || f_catch(SIGUSR2, f_h_a2, SA_ONSTACK)
        || f_catch(SIGALRM, f_h_c, SA_ONSTACK) || f_catch(SIGPIPE, f_h_d, SA_ONSTACK)) return 2;
    f_stage = 0;
    raise(SIGUSR1);
    /* A returned (1), D ran (2), B finished (3). */
    return f_stage == (f_mode >= 2 ? 3 : 2) ? 0 : 20 + f_stage % 70;
}
static int f_high_alt(void) {
    char area[28672] __attribute__((aligned(16)));
    return f_high_alt_run(area, sizeof(area));
}
static int f_high_noalt(void) { f_mode = 1; return f_high_alt_run(NULL, 0); }
static int f_high_alt_0(void) { f_mode = 0; return f_high_alt(); }
static int f_high_alt_1(void) { f_mode = 1; return f_high_alt(); }
static int f_high_alt_2(void) { f_mode = 2; return f_high_alt(); }


/* #293: B (SA_SIGINFO, no SA_ONSTACK) raises A (SA_ONSTACK) that sets a jump
 * point and raises C (SA_ONSTACK), and C jumps into A. Every level costs
 * about 13 KiB of the alternate stack. */
static void f_h_a3(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    if (sigsetjmp(f_env2, 1) == 0) raise(SIGALRM);
    f_stage++;
}
static int f_nested_run(char *area, size_t size) {
    stack_t ss = {.ss_sp = area, .ss_size = size, .ss_flags = 0};
    if (sigaltstack(&ss, NULL)) return 1;
    if (f_catch(SIGUSR1, f_h_b2, 0) || f_catch(SIGUSR2, f_h_a3, SA_ONSTACK)
        || f_catch(SIGALRM, f_h_c, SA_ONSTACK)) return 2;
    f_mode = 0;
    f_stage = 0;
    raise(SIGUSR1);
    return f_stage == 2 ? 0 : 20 + f_stage % 70;
}
/* Without the jump: C returns. */
static void f_h_ret(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    f_where[2] = 1;
}
static void f_h_a4(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    raise(SIGALRM);
    f_stage++;
}
static int f_nested_28k_plain(void) {
    char area[28672] __attribute__((aligned(16)));
    stack_t ss = {.ss_sp = area, .ss_size = sizeof(area), .ss_flags = 0};
    if (sigaltstack(&ss, NULL)) return 1;
    if (f_catch(SIGUSR1, f_h_b2, 0) || f_catch(SIGUSR2, f_h_a4, SA_ONSTACK)
        || f_catch(SIGALRM, f_h_ret, SA_ONSTACK)) return 2;
    f_mode = 0;
    f_stage = 0;
    raise(SIGUSR1);
    return f_stage == 2 ? 0 : 20 + f_stage % 70;
}
static int f_nested_36k(void) {
    char area[36864] __attribute__((aligned(16)));
    return f_nested_run(area, sizeof(area));
}
static int f_nested_20k(void) {
    char area[20480] __attribute__((aligned(16)));
    return f_nested_run(area, sizeof(area));
}

/* #287: levels. B (SA_SIGINFO, off the stack) sets a jump point and raises E
 * (off the stack), which jumps into B; B then raises H (on the stack) that
 * treads 3 KiB, and B returns. With one pair of fields for the levels the
 * jump from E took B's level with it, H started at the top over B's frame and
 * B's return was corrupted. */
static sigjmp_buf f_env_b;
static volatile unsigned long f_h_at;
static void f_h_e(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    siglongjmp(f_env_b, 1);
}
static void f_h_tread(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    volatile unsigned char junk[3072];
    for (unsigned i = 0; i < sizeof(junk); i++) junk[i] = 0xEE;
    f_h_at = (unsigned long)&junk[0];
    f_stage++;
}
static void f_h_lb(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    volatile unsigned char sentinel[128];
    for (unsigned i = 0; i < sizeof(sentinel); i++) sentinel[i] = 0x66;
    if (sigsetjmp(f_env_b, 1) == 0) {
        raise(SIGUSR2);
        f_stage = 80;
    }
    f_stage++;
    raise(SIGALRM);
    for (unsigned i = 0; i < sizeof(sentinel); i++)
        if (sentinel[i] != 0x66) f_stage = 99;
}
static int f_levels_into_b(void) {
    if (f_set_alt()) return 1;
    if (f_catch(SIGUSR1, f_h_lb, 0) || f_catch(SIGUSR2, f_h_e, 0)
        || f_catch(SIGALRM, f_h_tread, SA_ONSTACK)) return 2;
    f_stage = 0;
    raise(SIGUSR1);
    /* B after the jump (1), H (2). */
    return f_stage == 2 ? 0 : 20 + f_stage % 70;
}

/* The same with a jump from E into the main code: both levels go, and the next
 * SA_ONSTACK signal starts at the top of the alternate stack. */
static void f_h_lb2(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    raise(SIGUSR2);
    f_stage = 80;
}
static void f_h_e2(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    siglongjmp(f_env, 1);
}
static int f_levels_to_main(void) {
    if (f_set_alt()) return 1;
    if (f_catch(SIGUSR1, f_h_lb2, 0) || f_catch(SIGUSR2, f_h_e2, 0)
        || f_catch(SIGALRM, f_h_tread, SA_ONSTACK)) return 2;
    /* Where the handler of an SA_ONSTACK signal of the main code starts. */
    f_stage = 0;
    raise(SIGALRM);
    unsigned long first = f_h_at;
    if (f_stage != 1 || !f_in_alt((void *)first)) return 5;
    f_stage = 0;
    f_h_at = 0;
    if (sigsetjmp(f_env, 1) == 0) {
        raise(SIGUSR1);
        return 3;
    }
    if (f_on_alt() != 0) return 4;
    raise(SIGALRM);
    if (f_stage != 1) return 20 + f_stage % 70;
    /* The same place: no level of the jump's two is left to cut the range. */
    return f_h_at == first ? 0 : 6;
}

/* #286: a child of fork made in a handler off the stack. */
static volatile pid_t f_fork_pid;
static void f_h_fork(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    f_fork_pid = fork();
    if (f_fork_pid == 0) raise(SIGALRM);
}
static int f_fork_in_handler(void) {
    if (f_set_alt()) return 1;
    if (f_catch(SIGUSR1, f_h_fork, 0) || f_catch(SIGALRM, f_h_d, SA_ONSTACK)) return 2;
    f_stage = 0;
    f_fork_pid = -2;
    raise(SIGUSR1);
    if (f_fork_pid == 0) _exit(f_stage == 1 ? 0 : 10 + f_stage % 70);
    if (f_fork_pid < 0) return 3;
    int status = -1;
    if (waitpid(f_fork_pid, &status, 0) != f_fork_pid) return 4;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 100 + WTERMSIG(status);
}

/* #289: a stack of MINSIGSTKSZ bytes with a hole below it serves a handler
 * with a 2 KiB array, and at least 2 KiB of it stay untouched. */
static volatile int f_array_ok;
static void f_h_array(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    volatile unsigned char array[2048];
    for (unsigned i = 0; i < sizeof(array); i++) array[i] = (unsigned char)i;
    f_array_ok = array[2047] == (unsigned char)2047;
}
static int f_minimum_stack(void) {
    char *region = mmap(NULL, MINSIGSTKSZ + 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) return 1;
    if (mprotect(region, 4096, PROT_NONE)) return 2;
    unsigned char *low = (unsigned char *)region + 4096;
    memset(low, 0xA5, MINSIGSTKSZ);
    stack_t ss = {.ss_sp = low, .ss_size = MINSIGSTKSZ, .ss_flags = 0};
    if (sigaltstack(&ss, NULL)) return 3;
    if (f_catch(SIGUSR1, f_h_array, SA_ONSTACK)) return 4;
    f_array_ok = 0;
    raise(SIGUSR1);
    if (!f_array_ok) return 5;
    unsigned untouched = 0;
    while (untouched < MINSIGSTKSZ && low[untouched] == 0xA5) untouched++;
    printf("posix-procs: faults: a stack of MINSIGSTKSZ leaves %u bytes untouched under a 2 KiB handler\n", untouched);
    return untouched >= 2048 ? 0 : 6;
}

static volatile int f_code, f_signo;
static volatile unsigned long f_addr, f_pc;
static void f_h_class(int sig, siginfo_t *info, void *ctx) {
    f_signo = info->si_signo;
    f_code = info->si_code;
    f_addr = (unsigned long)info->si_addr;
    f_pc = F_CTX_PC(ctx);
    if (sig != info->si_signo) f_signo = -1;
    siglongjmp(f_env, 1);
}

static int f_one(int sig, int code, unsigned long addr, int kind) {
    if (f_catch(sig, f_h_class, 0)) return 1;
    f_signo = 0;
    if (sigsetjmp(f_env, 1) == 0) {
        unsigned char word[32] __attribute__((aligned(16)));
        switch (kind) {
        case 0: __asm__ volatile("udf #0"); break;
        case 1: __asm__ volatile("brk #7"); break;
        case 2: __asm__ volatile("ldxr w9, [%0]" ::"r"(word + 14) : "x9", "memory"); break;
        case 3: (void)*(volatile int *)0x10; break;
        case 4: *(volatile unsigned char *)(void *)f_one = 0; break;
        }
        return 2;
    }
    if (f_signo != sig) return 3;
    if (f_code != code) return 4;
    if (addr != 0 && f_addr != addr) return 5;
    if (addr == 0 && kind <= 1 && f_addr != f_pc) return 6;
    return 0;
}

static int f_classes(void) {
    int r;
    if ((r = f_one(SIGILL, ILL_ILLOPC, 0, 0))) return 10 + r;
    if ((r = f_one(SIGTRAP, TRAP_BRKPT, 0, 1))) return 20 + r;
    if ((r = f_one(SIGBUS, BUS_ADRALN, 0, 2))) return 30 + r;
    if ((r = f_one(SIGSEGV, SEGV_MAPERR, 0x10, 3))) return 40 + r;
    if ((r = f_one(SIGSEGV, SEGV_ACCERR, (unsigned long)f_one, 4))) return 50 + r;
    return 0;
}

static int f_default_udf(void) { __asm__ volatile("udf #0"); return 0; }
static int f_default_brk(void) { __asm__ volatile("brk #1"); return 0; }
static int f_default_bus(void) {
    unsigned char word[32] __attribute__((aligned(16)));
    __asm__ volatile("ldxr w9, [%0]" ::"r"(word + 14) : "x9", "memory");
    return 0;
}
static int f_default_null(void) { return *(volatile int *)0; }
static int f_blocked(void) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGSEGV);
    if (sigprocmask(SIG_BLOCK, &set, NULL)) return 1;
    if (f_catch(SIGSEGV, f_h_class, 0)) return 2;
    return *(volatile int *)0;
}

static void f_h_outer_fault(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)ctx;
    unsigned long first = (unsigned long)info->si_addr;
    f_stage = 1;
    __asm__ volatile("udf #0");
    f_stage = 80;
    (void)first;
}
static void f_h_nested_ill(int sig, siginfo_t *info, void *ctx) {
    (void)ctx;
    /* The cause is the nested one. */
    f_stage = (sig == SIGILL && info->si_signo == SIGILL && info->si_code == ILL_ILLOPC) ? 2 : 81;
    siglongjmp(f_env, 1);
}

/* A fault inside the handler of another fault enters its own handler; the
 * cause of the first (ESR, FAR) does not leak into the second. */
static int f_fault_in_fault(void) {
    if (f_catch(SIGSEGV, f_h_outer_fault, SA_NODEFER)) return 1;
    if (f_catch(SIGILL, f_h_nested_ill, 0)) return 2;
    f_stage = 0;
    if (sigsetjmp(f_env, 1) == 0) {
        *(volatile int *)0x20 = 1;
        return 3;
    }
    return f_stage == 2 ? 0 : 20 + f_stage % 70;
}

/* The guard of a thread's stack is a hole below it. */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static char *g_base;
static size_t g_size, g_guard;
static volatile int g_ready;

static void g_note(void) {
    pthread_attr_t attr;
    void *base;
    if (pthread_getattr_np(pthread_self(), &attr) || pthread_attr_getstack(&attr, &base, &g_size)
        || pthread_attr_getguardsize(&attr, &g_guard))
        _exit(90);
    g_base = base;
}
/* Writes the lowest word of its stack (allowed), then `below` bytes under it. */
static size_t g_below;
static void *g_writer(void *arg) {
    (void)arg;
    g_note();
    *(volatile char *)g_base = 1;
    if (g_guard < g_below || g_guard == 0) _exit(91);
    *(volatile char *)(g_base - g_below) = 1;
    return (void *)1;
}
static int g_thread_run(size_t guard, size_t below) {
    pthread_attr_t attr;
    pthread_t t;
    pthread_attr_init(&attr);
    pthread_attr_setguardsize(&attr, guard);
    g_below = below;
    if (pthread_create(&t, &attr, g_writer, NULL)) return 1;
    pthread_join(t, NULL);
    return 2; /* the write went through */
}
static int g_one_page(void) { return g_thread_run(4096, 1); }
static int g_sixteen_pages(void) { return g_thread_run(16 * 4096, 16 * 4096); }
static int g_top_of_hole(void) { return g_thread_run(4096, 4096); }
static void *g_parked(void *arg) {
    (void)arg;
    g_note();
    g_ready = 1;
    pthread_mutex_lock(&g_lock);
    pthread_mutex_unlock(&g_lock);
    return NULL;
}
/* A live thread of the parent keeps its guard in a child of fork: the
 * stack is there, the hole below it is not. */
static int g_forked_hole(void) {
    pthread_t t;
    pthread_mutex_lock(&g_lock);
    g_ready = 0;
    if (pthread_create(&t, NULL, g_parked, NULL)) return 1;
    while (!g_ready) sched_yield();
    char *base = g_base;
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        *(volatile char *)base = 1; /* its stack: mapped */
        *(volatile char *)(base - 8) = 1; /* its guard: SIGSEGV */
        _exit(3);
    }
    pthread_mutex_unlock(&g_lock);
    pthread_join(t, NULL);
    if (pid < 0) return 2;
    int st = 0;
    if (waitpid(pid, &st, 0) != pid) return 3;
    return WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV ? 0 : 4;
}

static void f_child(const char *what, int (*fn)(void), int code, int sig) {
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        /* The role may run with signals blocked: a case starts with none. */
        sigset_t none;
        sigemptyset(&none);
        sigprocmask(SIG_SETMASK, &none, NULL);
        _exit(fn());
    }
    if (pid < 0) {
        printf("posix-procs: faults: fork for %s gave %d (%s)\n", what, errno, strerror(errno));
        failures++;
        return;
    }
    reap(what, pid, code, sig);
}

static int faults_role(void) {
    f_area = mmap(NULL, F_STACK, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (f_area == MAP_FAILED) {
        printf("posix-procs: faults: no memory for the alternate stack (%s)\n", strerror(errno));
        return 1;
    }
    f_child("sigaltstack state and errors", f_api, 0, 0);
    f_child("overflow caught on the alternate stack", f_overflow_caught, 0, 0);
    f_child("overflow in a child of fork with the alternate stack", f_forked_alt, 0, 0);
    f_child("overflow of the alternate stack itself", f_alt_overflow, 0, SIGSEGV);
    f_child("overflow without an alternate stack", f_overflow_default, 0, SIGSEGV);
    f_child("a signal inside the handler on the alternate stack", f_nested_on_alt, 0, 0);
    f_child("100 jumps out of a handler off the alternate stack", f_many_jumps, 0, 0);
    f_child("jump inside, no alternate stack", f_high_noalt, 0, 0);
    f_child("high stack, plain", f_high_alt_0, 0, 0);
    f_child("high stack, jump inside", f_high_alt_1, 0, 0);
    f_child("high stack, jump and a further signal", f_high_alt_2, 0, 0);
    f_child("a plain SA_ONSTACK signal inside a handler off the stack", f_plain_on_in_off, 0, 0);
    f_child("a handler off the alternate stack", f_off_stack_plain, 0, 0);
    f_child("a handler off the alternate stack with a signal off it", f_off_stack_both, 0, 0);
    f_child("a handler off the alternate stack with a signal on it", f_off_stack_on, 0, 0);
    f_child("nested handlers on 36 KiB of the alternate stack", f_nested_36k, 0, 0);
    f_child("nested handlers on 20 KiB of the alternate stack end the process", f_nested_20k, 0, SIGSEGV);
    f_child("nested handlers on 28 KiB end the process before C can tread", f_nested_28k_plain, 0, SIGSEGV);
    f_child("a jump from a handler into the handler it was called in", f_levels_into_b, 0, 0);
    f_child("a jump from a handler into the main code takes both levels off", f_levels_to_main, 0, 0);
    f_child("fork in a handler off the alternate stack", f_fork_in_handler, 0, 0);
    f_child("a handler with a 2 KiB array on MINSIGSTKSZ", f_minimum_stack, 0, 0);
    f_child("classes of faults reach handlers", f_classes, 0, 0);
    f_child("undefined instruction without a handler", f_default_udf, 0, SIGILL);
    f_child("breakpoint without a handler", f_default_brk, 0, SIGTRAP);
    f_child("misaligned exclusive without a handler", f_default_bus, 0, SIGBUS);
    f_child("load from address 0 without a handler", f_default_null, 0, SIGSEGV);
    f_child("blocked SIGSEGV ends the process", f_blocked, 0, SIGSEGV);
    f_child("a fault inside the handler of a fault", f_fault_in_fault, 0, 0);
    f_child("a write into the guard of a thread's stack", g_one_page, 0, SIGSEGV);
    f_child("a write 16 pages down in a guard of 16 pages", g_sixteen_pages, 0, SIGSEGV);
    f_child("a write at the top of the guard", g_top_of_hole, 0, SIGSEGV);
    f_child("a child of fork has the guard of its parent's thread", g_forked_hole, 0, 0);
    if (!failures) printf("posix-procs: faults: sigaltstack, SA_ONSTACK, classes of faults, nesting ok\n");
    return failures != 0;
}
