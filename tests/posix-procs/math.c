/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

#include <errno.h>
#include <fenv.h>
#include <float.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#pragma STDC FENV_ACCESS ON

_Static_assert(sizeof(long double) == 16, "AArch64 long double uses binary128");
_Static_assert(LDBL_MANT_DIG == 113, "long double header must describe binary128");

#define CHECK(test) do { if (!(test)) { \
    printf("posix-math: FAIL line %d: %s errno %d\n", __LINE__, #test, errno); \
    fflush(stdout); _exit(1); \
} } while (0)

static void scalar(void) {
    volatile float f = 9.0f;
    volatile double d = 9.0;
    volatile long double l = 9.0L;
    CHECK(sqrtf(f) == 3.0f && sqrt(d) == 3.0 && sqrtl(l) == 3.0L);
    CHECK(fabsf(sinf(0.5f) - 0.47942554f) < 0x1p-22f);
    CHECK(fabs(sin(0.5) - 0.479425538604203) < 0x1p-50);
    CHECK(fabsl(sinl(0.5L) - 0.479425538604203000273287935215571388L) < 0x1p-108L);
    volatile long double extra = 0x1p-60L;
    volatile long double root = 1.0L + extra;
    volatile long double square = root * root;
    CHECK(sqrtl(square) == root && sqrtl(square) != (long double)sqrt((double)square));
    CHECK(ldexpl(1.0L, 100) + 1.0L != ldexpl(1.0L, 100));
    CHECK(powl(2.0L, 3.0L) == 8.0L && expl(0.0L) == 1.0L && logl(1.0L) == 0.0L);
    /* The product's low bits survive only a genuinely fused operation. */
    volatile float af = 1.0f + 0x1p-13f, bf = 1.0f - 0x1p-13f;
    volatile double ad = 1.0 + 0x1p-27, bd = 1.0 - 0x1p-27;
    volatile long double al = 1.0L + 0x1p-57L, bl = 1.0L - 0x1p-57L;
    CHECK(fmaf(af, bf, -1.0f) == -0x1p-26f);
    CHECK(fma(ad, bd, -1.0) == -0x1p-54);
    CHECK(fmal(al, bl, -1.0L) == -0x1p-114L);
    puts("posix-math: float double and binary128 long double ok");
}

static void special(void) {
    volatile float zf = -0.0f;
    volatile double zd = -0.0;
    volatile long double zl = -0.0L;
    CHECK(signbit(sqrtf(zf)) && signbit(sqrt(zd)) && signbit(sqrtl(zl)));
    CHECK(signbit(copysignf(1.0f, zf)) && signbit(copysign(1.0, zd)) && signbit(copysignl(1.0L, zl)));
    CHECK(!signbit(fabsf(zf)) && !signbit(fabs(zd)) && !signbit(fabsl(zl)));
    CHECK(isnan(nanf("")) && isnan(nan("")) && isnan(nanl("")));
    CHECK(isinf(INFINITY) && !signbit(INFINITY));
    puts("posix-math: NaN and signed zero ok");
}

static double rounded(double x) {
    volatile double value = x;
    return rint(value);
}

static void environment(void) {
    CHECK(math_errhandling == MATH_ERREXCEPT);
    fenv_t saved;
    CHECK(fegetenv(&saved) == 0);
    const int modes[] = {FE_TONEAREST, FE_TOWARDZERO, FE_UPWARD, FE_DOWNWARD};
    const int rounds[] = {1, 0, 2, 3};
    const double positive[] = {2.0, 1.0, 2.0, 1.0};
    const double negative[] = {-2.0, -1.0, -1.0, -2.0};
    for (unsigned i = 0; i < 4; ++i) {
        CHECK(fesetround(modes[i]) == 0 && fegetround() == modes[i]);
        CHECK(FLT_ROUNDS == rounds[i]);
        CHECK(rounded(1.5) == positive[i] && rounded(-1.5) == negative[i]);
        CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);
        volatile double half = 1.5;
        CHECK(nearbyint(half) == positive[i]);
        CHECK((fetestexcept(FE_INEXACT) & FE_INEXACT) == 0);
        CHECK(rounded(half) == positive[i]);
        CHECK((fetestexcept(FE_INEXACT) & FE_INEXACT) != 0);
    }
    CHECK(fesetround(FE_TONEAREST) == 0 && feclearexcept(FE_ALL_EXCEPT) == 0);
    volatile double pole_zero = 0.0;
    volatile double logarithm = log(pole_zero);
    CHECK(isinf(logarithm) && signbit(logarithm));
    CHECK((fetestexcept(FE_DIVBYZERO) & FE_DIVBYZERO) != 0);
    CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);
    volatile double positive_exponent = 13.37;
    volatile double zero_power = pow(pole_zero, positive_exponent);
    CHECK(zero_power == 0.0 && !signbit(zero_power));
    CHECK((fetestexcept(FE_DIVBYZERO) & FE_DIVBYZERO) == 0);
    CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);
    volatile double negative_one = -1.0;
    CHECK(isnan(sqrt(negative_one)));
    CHECK((fetestexcept(FE_INVALID) & FE_INVALID) != 0);
    CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);
    volatile double one = 1.0, zero = 0.0;
    volatile double infinity = one / zero;
    CHECK(isinf(infinity) && !signbit(infinity));
    CHECK((fetestexcept(FE_DIVBYZERO) & FE_DIVBYZERO) != 0);
    fexcept_t flag;
    CHECK(fegetexceptflag(&flag, FE_DIVBYZERO) == 0);
    CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);
    CHECK(fesetexceptflag(&flag, FE_DIVBYZERO) == 0);
    CHECK(fetestexcept(FE_ALL_EXCEPT) == FE_DIVBYZERO);
    fenv_t held;
    CHECK(feholdexcept(&held) == 0 && fetestexcept(FE_ALL_EXCEPT) == 0);
    CHECK(feraiseexcept(FE_INVALID) == 0 && feupdateenv(&held) == 0);
    CHECK(fetestexcept(FE_INVALID | FE_DIVBYZERO) == (FE_INVALID | FE_DIVBYZERO));
    CHECK(fesetenv(&saved) == 0);
    puts("posix-math: rounding and exceptions ok");
}

static unsigned turn;
static unsigned started;
static unsigned failed;

static int pause_turn(unsigned wanted) {
    const struct timespec delay = {0, 1000000};
    for (unsigned i = 0; i < 10000; ++i) {
        if (__atomic_load_n(&turn, __ATOMIC_ACQUIRE) == wanted)
            return 1;
        if (__atomic_load_n(&failed, __ATOMIC_RELAXED))
            return 0;
        if (nanosleep(&delay, NULL) != 0 && errno != EINTR)
            return 0;
    }
    return 0;
}

static void *worker(void *argument) {
    unsigned id = (unsigned)(unsigned long)argument;
    const int mode = id == 0 ? FE_UPWARD : FE_DOWNWARD;
    const int flag = id == 0 ? FE_INVALID : FE_DIVBYZERO;
    /* A new thread receives its creator's environment before changing it. */
    if (fegetround() != FE_TOWARDZERO || fetestexcept(FE_ALL_EXCEPT) != FE_OVERFLOW)
        goto fail;
    if (fesetround(mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0 || feraiseexcept(flag) != 0)
        goto fail;
    __atomic_fetch_add(&started, 1, __ATOMIC_RELEASE);
    for (unsigned i = 0; i < 32; ++i) {
        if (!pause_turn(2 * i + id))
            goto fail;
        if (fegetround() != mode || fetestexcept(FE_ALL_EXCEPT) != flag)
            goto fail;
        /* nearbyint checks the retained mode without adding an exception. */
        volatile double half = 1.5;
        if (nearbyint(half) != (id == 0 ? 2.0 : 1.0) || fetestexcept(FE_ALL_EXCEPT) != flag)
            goto fail;
        __atomic_store_n(&turn, 2 * i + id + 1, __ATOMIC_RELEASE);
    }
    return NULL;
fail:
    __atomic_store_n(&failed, 1, __ATOMIC_RELEASE);
    return (void *)1;
}

static void threads(void) {
    fenv_t saved;
    CHECK(fegetenv(&saved) == 0);
    CHECK(fesetround(FE_TOWARDZERO) == 0 && feclearexcept(FE_ALL_EXCEPT) == 0);
    CHECK(feraiseexcept(FE_OVERFLOW) == 0);
    pthread_t workers[2];
    CHECK(pthread_create(&workers[0], NULL, worker, (void *)0) == 0);
    CHECK(pthread_create(&workers[1], NULL, worker, (void *)1) == 0);
    for (unsigned i = 0; i < 2; ++i) {
        void *result = (void *)1;
        CHECK(pthread_join(workers[i], &result) == 0 && result == NULL);
    }
    CHECK(__atomic_load_n(&started, __ATOMIC_ACQUIRE) == 2);
    CHECK(__atomic_load_n(&turn, __ATOMIC_ACQUIRE) == 64);
    CHECK(!__atomic_load_n(&failed, __ATOMIC_ACQUIRE));
    CHECK(fegetround() == FE_TOWARDZERO && fetestexcept(FE_ALL_EXCEPT) == FE_OVERFLOW);
    CHECK(fesetenv(&saved) == 0);
    puts("posix-math: thread floating-point isolation ok");
}

int main(void) {
    CHECK(fesetenv(FE_DFL_ENV) == 0);
    scalar();
    special();
    environment();
    threads();
    puts("posix-math: done failures 0");
    return 0;
}
