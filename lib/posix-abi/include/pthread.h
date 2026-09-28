/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#ifndef STAFETO_PTHREAD_H
#define STAFETO_PTHREAD_H
#include <stddef.h>
#include <stdint.h>
#include <stafeto/abi.h>
typedef uint64_t pthread_t;
typedef struct {
    uint64_t __magic;
    size_t __stack_size;
    size_t __guard_size;
    int __detached;
    unsigned int __reserved;
} pthread_attr_t;
int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
        void *(*start)(void *), void *argument);
pthread_t pthread_self(void);
int pthread_equal(pthread_t first, pthread_t second);
int pthread_join(pthread_t thread, void **value);
int pthread_detach(pthread_t thread);
_Noreturn void pthread_exit(void *value);
int pthread_attr_init(pthread_attr_t *attr);
int pthread_attr_destroy(pthread_attr_t *attr);
int pthread_attr_setstacksize(pthread_attr_t *attr, size_t size);
int pthread_attr_getstacksize(const pthread_attr_t *attr, size_t *size);
int pthread_attr_setguardsize(pthread_attr_t *attr, size_t size);
int pthread_attr_getguardsize(const pthread_attr_t *attr, size_t *size);
int pthread_attr_setdetachstate(pthread_attr_t *attr, int state);
int pthread_attr_getdetachstate(const pthread_attr_t *attr, int *state);
#define PTHREAD_CANCELED ((void *)-1)
int pthread_cancel(pthread_t thread);
int pthread_setcancelstate(int state, int *oldstate);
int pthread_setcanceltype(int type, int *oldtype);
void pthread_testcancel(void);
struct __stafeto_cleanup_buffer {
    struct __stafeto_cleanup_buffer *__next;
    void (*__routine)(void *);
    void *__argument;
};
void __stafeto_cleanup_push(struct __stafeto_cleanup_buffer *buffer,
        void (*routine)(void *), void *argument);
void __stafeto_cleanup_pop(struct __stafeto_cleanup_buffer *buffer, int execute);
#define pthread_cleanup_push(routine, argument) do { \
    struct __stafeto_cleanup_buffer __stafeto_cleanup; \
    __stafeto_cleanup_push(&__stafeto_cleanup, (routine), (argument));
#define pthread_cleanup_pop(execute) \
    __stafeto_cleanup_pop(&__stafeto_cleanup, (execute)); \
} while (0)
#endif
