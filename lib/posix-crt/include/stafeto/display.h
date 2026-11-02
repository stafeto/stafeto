/* SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1 */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The screen and the keys of stafeto: an extension of the system outside
 * POSIX, which libc.so exports. A program opens the screen, writes points in
 * the buffer it gets, shows a rectangle of them and reads the keys of the
 * keyboard. One process owns the screen at a time.
 *
 * The screen is 640 by 400 points, XRGB8888 (a point is the 32-bit word
 * 0x00RRGGBB, stored low byte first), `stride` bytes a line. The buffer is
 * not copied by fork (a child reads and writes nothing there), and it goes
 * with stafeto_display_close, exec and the end of the process, which give
 * the screen back.
 */
#ifndef _STAFETO_DISPLAY_H
#define _STAFETO_DISPLAY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STAFETO_FORMAT_XRGB8888 1

struct stafeto_display {
    uint32_t width, height, stride, format;
    void *pixels;
};

/* A key event as Linux's struct input_event carries it, less the time:
 * type is 1 (EV_KEY), code the Linux key code, value 0 for the release
 * and 1 for the press. The service passes no value 2 (the repeat of a
 * held key): a program that wants repeats makes them itself. */
struct stafeto_key {
    uint16_t type, code;
    int32_t value;
};

/* Opens the screen and describes it. 0, or -1 with errno:
 *   EBUSY   another process has the screen;
 *   ENODEV  the process has no display service (an image without one, a
 *           set-ID program, a service that ended or started again) or the
 *           device did not answer;
 *   ENOMEM  the buffer does not fit the address space;
 *   EINTR   a signal ended the wait for a screen that is being cleared.
 *   EIO     the service answered in a way the layer does not know;
 *   EAGAIN  the display service has no room for another session;
 *   EINVAL  d is null.
 * A process that has the screen gets the same description again; a thread
 * that calls while another thread of the process is still opening gets
 * EBUSY. */
int stafeto_display_open(struct stafeto_display *d);

/* Shows the rectangle (x, y, w, h) of points and returns when the device
 * showed it. 0, or -1 with errno:
 *   EBADF   the process has not opened the screen;
 *   EINVAL  the rectangle is empty or outside the screen;
 *   ENODEV  the display service ended or took the screen away;
 *   EIO     the device or the service failed;
 *   EAGAIN  another flush of the process already waits behind one.
 * A signal does not end the wait (as with SA_RESTART), so there is no
 * EINTR. */
int stafeto_display_flush(int x, int y, int w, int h);

/* Reads up to max key events (at most 120 at a time) without waiting:
 * the count, 0 for none; or -1 with errno:
 *   EBADF   the process has not opened the screen;
 *   EINVAL  k is null or max is not positive;
 *   ENODEV  the screen has no keyboard (an image without the input
 *           service) or the service ended;
 *   EIO     the service answered in a way the layer does not know. */
int stafeto_input_read(struct stafeto_key *k, int max);

/* Closes the screen: the buffer goes and the screen is free again. 0, or
 * -1 with errno EBADF when the process has not opened the screen. */
int stafeto_display_close(void);

/* The calls are safe in several threads, except that the result of
 * stafeto_display_flush and stafeto_input_read at the same time as
 * stafeto_display_close in another thread is undefined, as with close(fd)
 * of a descriptor in use (EBADF is the likely answer). The functions may be
 * called from a signal handler: a flush there does not hang, an open
 * during another thread's open is EBUSY. */

#ifdef __cplusplus
}
#endif

#endif
