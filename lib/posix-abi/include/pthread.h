/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#ifndef STAFETO_PTHREAD_H
#define STAFETO_PTHREAD_H
#include <stddef.h>
#include <stdint.h>
#include <stafeto/abi.h>
#include <sys/types.h>
#include <time.h>
#define PTHREAD_MUTEX_INITIALIZER { 0x53544d5800000003ULL, 0, 0, 0 }
int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
int pthread_mutex_destroy(pthread_mutex_t *mutex);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_trylock(pthread_mutex_t *mutex);
int pthread_mutex_timedlock(pthread_mutex_t *mutex, const struct timespec *deadline);
int pthread_mutex_clocklock(pthread_mutex_t *mutex, clockid_t clock, const struct timespec *deadline);
int pthread_mutex_unlock(pthread_mutex_t *mutex);
int pthread_mutexattr_init(pthread_mutexattr_t *attr);
int pthread_mutexattr_destroy(pthread_mutexattr_t *attr);
int pthread_mutexattr_gettype(const pthread_mutexattr_t *attr, int *type);
int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type);
#define PTHREAD_ONCE_INIT { 0 }
int pthread_once(pthread_once_t *control, void (*routine)(void));
int pthread_key_create(pthread_key_t *key, void (*destructor)(void *));
int pthread_key_delete(pthread_key_t key);
void *pthread_getspecific(pthread_key_t key);
int pthread_setspecific(pthread_key_t key, const void *value);
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
