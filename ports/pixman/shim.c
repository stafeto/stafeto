// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

// What pixman asks of a C library, for the composition service (a program
// with no C library). The allocator is a first-fit arena over a static
// buffer: the service allocates a few hundred bytes per image and per
// implementation table, once, and the service is one thread. The functions
// of <math.h> that the gradients and the filters use are the CPU's square
// root, absolute value and rounding; the ones the service never reaches
// (the conical gradient, the Gaussian filter) end the program.
//
// Built with -fno-builtin and -fno-math-errno (tools/build-pixman.py): the
// functions below must not turn into calls to themselves.

#include <stddef.h>
#include <stdint.h>

#define ARENA_BYTES (32 * 1024)
#define ALIGN 16

struct block {
    size_t size; // the bytes after the header
    size_t free; // 1 when the block is free
};

static unsigned char arena[ARENA_BYTES] __attribute__((aligned(ALIGN)));
static int started;

#define HEADER ((sizeof(struct block) + ALIGN - 1) & ~(size_t)(ALIGN - 1))

static struct block *next(struct block *b)
{
    unsigned char *p = (unsigned char *)b + HEADER + b->size;
    return p >= arena + ARENA_BYTES ? 0 : (struct block *)p;
}

static void start(void)
{
    struct block *b = (struct block *)arena;
    b->size = ARENA_BYTES - HEADER;
    b->free = 1;
    started = 1;
}

void *pxs_malloc(size_t n)
{
    if (!started)
        start();
    n = (n + ALIGN - 1) & ~(size_t)(ALIGN - 1);
    if (n == 0)
        n = ALIGN;
    for (struct block *b = (struct block *)arena; b; b = next(b)) {
        if (!b->free || b->size < n)
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

void pxs_free(void *p)
{
    if (!p)
        return;
    struct block *b = (struct block *)((unsigned char *)p - HEADER);
    b->free = 1;
    // Join every run of free blocks. A block freed before its neighbour does
    // not join it backwards (the blocks have no link to the one before), so
    // joining only the blocks that follow the one freed leaves free blocks side by
    // side for good, and the walk of `pxs_malloc` grows with them.
    for (struct block *c = (struct block *)arena; c; c = next(c))
        while (c->free) {
            struct block *n = next(c);
            if (!n || !n->free)
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
