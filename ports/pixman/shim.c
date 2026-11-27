// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

// What pixman asks of a C library, for the composition service (a program
// with no C library). The allocator is a first-fit arena over a static
// buffer: the service allocates a few hundred bytes per image and per
// implementation table, once, and each of its two threads has an arena of its own. The functions
// of <math.h> that the gradients and the filters use are the CPU's square
// root, absolute value and rounding; the ones the service never reaches
// (the conical gradient, the Gaussian filter) end the program.
//
// Built with -fno-builtin and -fno-math-errno (tools/build-pixman.py): the
// functions below must not turn into calls to themselves.

#include <stddef.h>
#include <stdint.h>

#include "pxs.h"

#define ARENA_BYTES (32 * 1024)
// The worker draws one source and one target at a time through its own
// table of images, so its arena is half of the service's.
#define WORKER_ARENA_BYTES (16 * 1024)
#define ALIGN 16

struct block {
    size_t size; // the bytes after the header
    size_t free; // 1 when the block is free
};

#define HEADER ((sizeof(struct block) + ALIGN - 1) & ~(size_t)(ALIGN - 1))

// The small blocks (up to SMALL_MAX bytes) a free gives back are kept for the
// next allocation of their size, one list for each multiple of ALIGN: a block of
// the transform a drawing sets on an image, or of a solid colour made for one call,
// is made and given back with every operation, and the first fit walk of the
// arena (every block of the images kept, about a hundred) and the joining of the
// free blocks after it cost thousands of ticks for each. A kept block is marked 2
// and is not joined or split; the arena's walk passes it.
#define SMALL_MAX 512

// The state of pixman that a call changes, one record for each thread that
// calls it: the arena the allocator serves from, its lists of small blocks, and
// the cache of the paths found (pixman-implementation.c, through pxs_cache). The
// main thread uses `main_state`. The worker's thread points TPIDR_EL0 at
// `worker_state` (pxs_worker_enter) and uses that: the two threads share no
// state that a call writes, so the one of the lower level may be preempted
// anywhere in a call. The tables of the implementations are made by the main
// thread before the worker starts and are read alone after that.
struct pxs_state {
    unsigned char *arena;
    size_t size;
    int started;
    struct block *kept[SMALL_MAX / ALIGN + 1];
    unsigned char cache[PXS_CACHE_BYTES] __attribute__((aligned(ALIGN)));
};

static unsigned char main_arena[ARENA_BYTES] __attribute__((aligned(ALIGN)));
static unsigned char worker_arena[WORKER_ARENA_BYTES] __attribute__((aligned(ALIGN)));
static struct pxs_state main_state = {main_arena, ARENA_BYTES};
static struct pxs_state worker_state = {worker_arena, WORKER_ARENA_BYTES};

static struct pxs_state *state(void)
{
#ifdef PXS_HOST_STATE
    return pxs_host_state == (void *)&worker_state ? &worker_state : &main_state;
#else
    uintptr_t t;
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(t));
    return t == (uintptr_t)&worker_state ? &worker_state : &main_state;
#endif
}

void pxs_worker_enter(void)
{
#ifdef PXS_HOST_STATE
    pxs_host_state = (void *)&worker_state;
#else
    __asm__ volatile("msr tpidr_el0, %0" : : "r"((uintptr_t)&worker_state));
#endif
}

void *pxs_cache(void)
{
    return state()->cache;
}

static struct block *next(struct pxs_state *s, struct block *b)
{
    unsigned char *p = (unsigned char *)b + HEADER + b->size;
    return p >= s->arena + s->size ? 0 : (struct block *)p;
}

static void start(struct pxs_state *s)
{
    struct block *b = (struct block *)s->arena;
    b->size = s->size - HEADER;
    b->free = 1;
    s->started = 1;
}

void *pxs_malloc(size_t n)
{
    struct pxs_state *s = state();
    if (!s->started)
        start(s);
    n = (n + ALIGN - 1) & ~(size_t)(ALIGN - 1);
    if (n == 0)
        n = ALIGN;
    if (n <= SMALL_MAX && s->kept[n / ALIGN]) {
        struct block *b = s->kept[n / ALIGN];
        s->kept[n / ALIGN] = *(struct block **)((unsigned char *)b + HEADER);
        b->free = 0;
        return (unsigned char *)b + HEADER;
    }
    for (struct block *b = (struct block *)s->arena; b; b = next(s, b)) {
        if (b->free != 1 || b->size < n)
            continue;
        if (b->size >= n + HEADER + ALIGN) {
            struct block *rest = (struct block *)((unsigned char *)b + HEADER + n);
            rest->size = b->size - n - HEADER;
            rest->free = 1;
            b->size = n;
        }
        b->free = 0;
        return (unsigned char *)b + HEADER;
    }
    return 0;
}

// A block goes back to the arena it was made in: a thread frees what it made
// (the images of a thread's own table), and a pointer of the other arena is
// ignored, so a mistake of a caller leaks a block and never corrupts a list.
void pxs_free(void *p)
{
    struct pxs_state *s = state();
    if (!p)
        return;
    if ((unsigned char *)p < s->arena || (unsigned char *)p >= s->arena + s->size)
        return;
    struct block *b = (struct block *)((unsigned char *)p - HEADER);
    if (b->size <= SMALL_MAX) {
        *(struct block **)p = s->kept[b->size / ALIGN];
        s->kept[b->size / ALIGN] = b;
        b->free = 2;
        return;
    }
    b->free = 1;
    // Join every run of free blocks. A block freed before its neighbour does
    // not join it backwards (the blocks have no link to the one before), so
    // joining only the blocks that follow the one freed leaves free blocks side by
    // side for good, and the walk of `pxs_malloc` grows with them.
    for (struct block *c = (struct block *)s->arena; c; c = next(s, c))
        while (c->free == 1) {
            struct block *n = next(s, c);
            if (!n || n->free != 1)
                break;
            c->size += HEADER + n->size;
        }
}

void *pxs_calloc(size_t a, size_t b)
{
    if (b && a > (size_t)-1 / b)
        return 0;
    size_t n = a * b;
    unsigned char *p = pxs_malloc(n);
    for (size_t i = 0; p && i < n; i++)
        p[i] = 0;
    return p;
}

void *pxs_realloc(void *p, size_t n)
{
    if (!p)
        return pxs_malloc(n);
    struct block *b = (struct block *)((unsigned char *)p - HEADER);
    if (b->size >= n)
        return p;
    unsigned char *q = pxs_malloc(n);
    if (!q)
        return 0;
    for (size_t i = 0; i < b->size; i++)
        q[i] = ((unsigned char *)p)[i];
    pxs_free(p);
    return q;
}

void abort(void)
{
    __builtin_trap();
}

char *getenv(const char *name)
{
    (void)name;
    return 0;
}

struct pxs_file { int unused; };
static struct pxs_file the_stderr;
struct pxs_file *stderr = &the_stderr;

int fprintf(struct pxs_file *f, const char *format, ...)
{
    (void)f;
    (void)format;
    return 0;
}

int printf(const char *format, ...)
{
    (void)format;
    return 0;
}

size_t strlen(const char *s)
{
    size_t n = 0;
    while (s[n])
        n++;
    return n;
}

char *strchr(const char *s, int c)
{
    for (;; s++) {
        if (*s == (char)c)
            return (char *)s;
        if (!*s)
            return 0;
    }
}

int strncmp(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i])
            return (unsigned char)a[i] - (unsigned char)b[i];
        if (!a[i])
            return 0;
    }
    return 0;
}

// memset for pixman's general path, which clears three scanline buffers of
// 8 KiB on its stack before every operation it makes (pixman-general.c). The
// word loop of the compiler's own version took 12 000 ticks for that, a call
// of the general path; 64 bytes a step (four 16-byte stores) takes about a
// fifth. The vector type compiles to stores of the SIMD registers, which the
// service already uses (pixman's NEON paths).
typedef unsigned char byte16 __attribute__((vector_size(16)));

void *memset(void *dst, int c, size_t n)
{
    unsigned char *p = dst;
    unsigned char b = (unsigned char)c;
    if (n >= 64) {
        byte16 v = {b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b};
        while ((uintptr_t)p & 15) {
            *p++ = b;
            n--;
        }
        for (; n >= 64; n -= 64, p += 64) {
            ((byte16 *)p)[0] = v;
            ((byte16 *)p)[1] = v;
            ((byte16 *)p)[2] = v;
            ((byte16 *)p)[3] = v;
        }
    }
    while (n--)
        *p++ = b;
    return dst;
}

double sqrt(double x) { return __builtin_sqrt(x); }
float sqrtf(float x) { return __builtin_sqrtf(x); }
double fabs(double x) { return __builtin_fabs(x); }
double floor(double x) { return __builtin_floor(x); }
double ceil(double x) { return __builtin_ceil(x); }
double exp(double x) { (void)x; __builtin_trap(); }
double sin(double x) { (void)x; __builtin_trap(); }
double atan2(double y, double x) { (void)y; (void)x; __builtin_trap(); }

// The two files of pixman the build leaves out (tools/build-pixman.py): the
// combiners of the wide formats, which stay unset (an image of a wide format
// is never made), and the accessors, which no image has.
struct pixman_implementation;
void _pixman_setup_combiner_functions_float(struct pixman_implementation *imp)
{
    (void)imp;
}

void _pixman_bits_image_setup_accessors_accessors(void *image)
{
    (void)image;
    __builtin_trap();
}
