/* SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1 */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The windows of the composition service: a program makes a window of a
 * place and a size inside the screen, draws in one of one to three buffers
 * of its own and posts the buffer with the rectangles it changed. The
 * service puts the windows together and tells the program, by a bit on the
 * window's channel, that a buffer is free again and that events (keys, the
 * pointer, the focus) wait. This is the second revision of the display
 * interface; <stafeto/display.h> is the first.
 *
 * The functions live in a static library the program links (the feature
 * `window` of the Rust crate posix-crt), outside libc.so, and the header is
 * outside the headers of the libc sysroot: a program that includes it has
 * its own copy of the layer's session with the display service. A process
 * has one window at a time (its number is 0); the number is in every call
 * so that a later revision of the library can lift the limit with no change
 * of the functions.
 *
 * The size of the screen is what stafeto_screen_describe says. A point is a
 * 32-bit word stored low byte first: 0xXXRRGGBB (XRGB8888: the top byte is
 * ignored) or 0xAARRGGBB with the colour already multiplied by the alpha
 * (ARGB8888, laid over what is below). The buffers are ordinary memory of
 * the process, `stride` bytes a line. A fork leaves them out of the child:
 * after a fork the child's pixels[] point at nothing and must not be used,
 * and the child has no window. The window and its buffers go with
 * stafeto_window_close, exec and the end of the process.
 *
 * The window's size is fixed for its life (the protocol has no resize). A
 * window manager, when the image has one, may move the window, hide it and
 * give it the focus; the window learns of its focus from
 * STAFETO_WINDOW_EVENT_FOCUS_IN and _FOCUS_OUT events.
 *
 * Every function returns 0, a count, a mask or the window's number, or -1
 * with errno, as <stafeto/display.h> does (stafeto_window_free_buffers
 * cannot fail). Times are nanoseconds on CLOCK_MONOTONIC. A signal with a
 * handler ends stafeto_window_wait with EINTR whatever SA_RESTART says; the
 * other functions go on after a signal. Only stafeto_window_free_buffers may
 * be called from a signal handler.
 */
#ifndef _STAFETO_WINDOW_H
#define _STAFETO_WINDOW_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The formats of a point (the format argument of stafeto_window_open, the
 * format of struct stafeto_screen and of struct stafeto_window). */
#define STAFETO_WINDOW_XRGB8888 1
#define STAFETO_WINDOW_ARGB8888 3

/* The most buffers of a window, the most rectangles the service takes in
 * one post (the library merges more, see stafeto_window_post), and the most
 * events one stafeto_window_events call returns. */
#define STAFETO_WINDOW_BUFFERS_MAX 3
#define STAFETO_WINDOW_RECTS_MAX 4
#define STAFETO_WINDOW_EVENTS_MAX 32

/* The bits stafeto_window_wait returns and stafeto_window_free_buffers
 * gives (as a mask of buffers): STAFETO_WINDOW_BUFFER(k) says buffer k (0 to
 * 2) is free, and STAFETO_WINDOW_EVENTS says events came. */
#define STAFETO_WINDOW_BUFFER(k) (1u << (k))
#define STAFETO_WINDOW_EVENTS (1u << 3)

/* The flag of stafeto_window_events: events were dropped (the ring of 64
 * overflowed) since the call before. */
#define STAFETO_WINDOW_EVENTS_LOST 1u

/* The kinds of an event (struct stafeto_window_event, field kind). */
#define STAFETO_WINDOW_EVENT_KEY 1
#define STAFETO_WINDOW_EVENT_MOVE 2
#define STAFETO_WINDOW_EVENT_BUTTON 3
#define STAFETO_WINDOW_EVENT_FOCUS_IN 4
#define STAFETO_WINDOW_EVENT_FOCUS_OUT 5

/* The size of the screen and its format, as stafeto_screen_describe gives
 * them. flags and reserved are 0 in this revision. */
struct stafeto_screen {
    uint32_t width, height, format, flags;
    uint32_t reserved[4];
};

/* A window as stafeto_window_open made it: its size, the bytes of a line,
 * the format, the number of buffers and where each lies in the process.
 * pixels[k] for k below `buffers` points at height * stride bytes: the
 * program may write them while buffer k is free and read them at any time.
 * The other elements are null. reserved is 0. */
struct stafeto_window {
    uint32_t width, height, stride, format, buffers, reserved;
    void *pixels[STAFETO_WINDOW_BUFFERS_MAX];
};

/* A rectangle of points in the window's own coordinates. */
struct stafeto_rect {
    int32_t x, y, w, h;
};

/* An event of the window. KEY: code is Linux's key code, value 1 for the
 * press and 0 for the release (no repeat). MOVE: x and y are the pointer's
 * place in the window's coordinates. BUTTON: code is the button (Linux's
 * BTN_LEFT, 0x110, and the others), value as a key's, x and y as a
 * MOVE's. FOCUS_IN and FOCUS_OUT carry no number. The 16 bytes are the
 * service's own event. */
struct stafeto_window_event {
    uint16_t kind, code;
    int32_t value, x, y;
};

/* The layouts the library's Rust side holds too. */
#if defined(__cplusplus) && __cplusplus >= 201103L
#define STAFETO_WINDOW_ASSERT(c) static_assert(c, #c)
#elif !defined(__cplusplus) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define STAFETO_WINDOW_ASSERT(c) _Static_assert(c, #c)
#else
/* Before C11 and C++11: an array of size -1 does not compile. One typedef
 * for each line, so each assertion has a name of its own. */
#define STAFETO_WINDOW_JOIN_(a, b) a##b
#define STAFETO_WINDOW_JOIN(a, b) STAFETO_WINDOW_JOIN_(a, b)
#define STAFETO_WINDOW_ASSERT(c) \
    typedef char STAFETO_WINDOW_JOIN(stafeto_window_assert_, __LINE__)[(c) ? 1 : -1]
#endif
STAFETO_WINDOW_ASSERT(sizeof(struct stafeto_screen) == 32);
STAFETO_WINDOW_ASSERT(offsetof(struct stafeto_screen, height) == 4);
STAFETO_WINDOW_ASSERT(offsetof(struct stafeto_screen, format) == 8);
STAFETO_WINDOW_ASSERT(offsetof(struct stafeto_screen, flags) == 12);
STAFETO_WINDOW_ASSERT(offsetof(struct stafeto_screen, reserved) == 16);
STAFETO_WINDOW_ASSERT(sizeof(struct stafeto_window) == 48);
STAFETO_WINDOW_ASSERT(offsetof(struct stafeto_window, height) == 4);
STAFETO_WINDOW_ASSERT(offsetof(struct stafeto_window, stride) == 8);
STAFETO_WINDOW_ASSERT(offsetof(struct stafeto_window, format) == 12);
STAFETO_WINDOW_ASSERT(offsetof(struct stafeto_window, buffers) == 16);
STAFETO_WINDOW_ASSERT(offsetof(struct stafeto_window, reserved) == 20);
STAFETO_WINDOW_ASSERT(offsetof(struct stafeto_window, pixels) == 24);
STAFETO_WINDOW_ASSERT(sizeof(struct stafeto_rect) == 16);
STAFETO_WINDOW_ASSERT(sizeof(struct stafeto_window_event) == 16);
STAFETO_WINDOW_ASSERT(offsetof(struct stafeto_window_event, code) == 2);
STAFETO_WINDOW_ASSERT(offsetof(struct stafeto_window_event, value) == 4);
STAFETO_WINDOW_ASSERT(offsetof(struct stafeto_window_event, x) == 8);
STAFETO_WINDOW_ASSERT(offsetof(struct stafeto_window_event, y) == 12);
#undef STAFETO_WINDOW_ASSERT
#undef STAFETO_WINDOW_JOIN
#undef STAFETO_WINDOW_JOIN_

/* Describes the screen. 0, or -1 with errno:
 *   ENODEV  the process has no display service (an image without one, a
 *           service that ended or started again) or the device did not
 *           answer;
 *   EINVAL  s is null;
 *   EBUSY   the display is still being set up after the library's tries
 *           (half a second);
 *   EINTR   a signal ended a wait for a display that is being set up;
 *   EIO     the service answered in a way the layer does not know. */
int stafeto_screen_describe(struct stafeto_screen *s);

/* Makes a window of w by h points at (x, y) of the screen, with `buffers`
 * (1 to 3) buffers of the given format, and describes it in *out. flags is
 * 0 (EINVAL otherwise). The buffers are zero. All of them are free. The
 * window shows once the first post is taken into a frame. With one buffer
 * the window shows one picture: its buffer never comes back. A program that
 * draws again uses two or three. Returns the window's number (0), or -1
 * with errno:
 *   ENODEV  as stafeto_screen_describe;
 *   EBUSY   the process has a window already, or the service is busy with
 *           another client's buffers and stayed so for half a second;
 *   EINVAL  the window is not inside the screen or is empty, the format is
 *           not one above, buffers is not 1 to 3, a buffer would be more
 *           than 1 MiB, flags is not 0, or out is null;
 *   ENOMEM  the buffers do not fit the address space or the process's
 *           memory;
 *   EAGAIN  the service has no room for another window;
 *   EINTR   a signal ended a wait for a display that is being set up or
 *           for the service;
 *   EIO     the service answered in a way the layer does not know.
 * On any failure the process has no window and nothing of it remains. The
 * pixel memory of a window is the process's own and the service only reads
 * it, so no cache maintenance is needed. The window's size does not
 * change. */
int stafeto_window_open(int x, int y, int w, int h, uint32_t format,
                        uint32_t buffers, uint32_t flags,
                        struct stafeto_window *out);

/* Posts buffer `buffer` of window `win`: the service shows it in its next
 * frame. r points at `count` rectangles in the window's coordinates that
 * cover every point differing from what the screen shows of this window now
 * (the buffer posted before). The service may copy more than the rectangles
 * (this revision copies their bounding box) and keeps what the screen shows
 * outside what it copied. count 0 (r may be null) means the whole window.
 * Up to 4 rectangles go to the service as they are; 5 or more are merged
 * into one, their bounding box. Each must be inside the window. While
 * posted, the buffer is the service's: the program may read it and does not
 * write it, until its bit says it is free (stafeto_window_wait). The latest
 * post wins: a buffer posted and not yet taken into a frame is replaced by
 * a later post and is free again at once, so its bit may already be there
 * when the call returns. 0, or -1 with errno:
 *   EBADF   win is not the window's number or the window was closed;
 *   EBUSY   the buffer is not free by the library's account (it was posted
 *           and no bit said it is free again);
 *   EINVAL  buffer is not below the number of buffers, a rectangle is
 *           empty or outside the window, or r is null with count above 0;
 *   ENODEV  the service ended or took the window away;
 *   EIO     the service answered in a way the layer does not know.
 * The call takes the bits that wait on the window's channel (before and
 * after the request). It keeps them: the next stafeto_window_wait returns
 * them at once, and a wait sleeping in another thread is woken. */
int stafeto_window_post(int win, uint32_t buffer, const struct stafeto_rect *r,
                        uint32_t count);

/* The buffers the library counts free, as a mask of STAFETO_WINDOW_BUFFER(k)
 * bits: all of them after stafeto_window_open, a buffer leaves the mask when
 * posted and returns when the service's bit for it came. The mask changes
 * only in stafeto_window_wait and stafeto_window_post. No call to the
 * service. 0 for a win that is not open. */
uint32_t stafeto_window_free_buffers(int win);

/* Waits for a bit of the service on the window's own channel, at most
 * timeout_ns nanoseconds (0 looks without waiting, UINT64_MAX waits with no
 * limit), and returns in *bits (null is allowed) the bits that came since
 * the last call: STAFETO_WINDOW_BUFFER(k) bits and STAFETO_WINDOW_EVENTS.
 * Every bit the service sends is returned by exactly one call of this
 * function; the bits stafeto_window_post took are kept and returned by the
 * next call at once. The buffer bits are applied to the mask of
 * stafeto_window_free_buffers before the call returns. A bit says that
 * something happened since the last call. The state is the mask: a program
 * that wants buffer k waits while the mask lacks STAFETO_WINDOW_BUFFER(k).
 * Returns 0 when at least one bit is there; or -1 with errno:
 *   ETIMEDOUT  no bit came in time;
 *   EINTR      a signal with a handler ran during the wait;
 *   EBADF      win is not the window's number;
 *   ENODEV     the service ended (known from an earlier call; see below);
 *   EBUSY      another thread of the process is waiting on the window;
 *   EIO        the kernel refused the wait.
 * A wait does not learn of the service's end by itself: the check runs at
 * entry, so a wait that is under way when the service ends returns only when
 * a bit or its time comes, and a later call (post, events) is what finds the
 * service gone. A program should use a finite timeout.
 * A later descriptor for poll will only add a way to sleep;
 * stafeto_window_wait(win, 0, &bits) stays the call that takes the bits. */
int stafeto_window_wait(int win, uint64_t timeout_ns, uint32_t *bits);

/* Takes up to max events of the window's ring without waiting: the count,
 * 0 for none. A max above STAFETO_WINDOW_EVENTS_MAX takes that many. The
 * bit STAFETO_WINDOW_EVENTS says that events came; a program takes them
 * until a call returns fewer than max. *flags (null is allowed) gets
 * STAFETO_WINDOW_EVENTS_LOST when the ring dropped older events. -1 with
 * errno:
 *   EBADF   win is not the window's number;
 *   EINVAL  e is null or max is not positive;
 *   EBUSY   another thread of the process is taking events;
 *   ENODEV  the service ended or took the window away;
 *   EIO     the service answered in a way the layer does not know. */
int stafeto_window_events(int win, struct stafeto_window_event *e, int max,
                          uint32_t *flags);

/* A helper for probes and screenshots: waits until the frame of the last
 * post is on the screen, that is, the service has shown a frame since and
 * is making none. It looks at the service every 2 ms, so it costs a call to
 * the service each time. A program that draws does not use it. 0, or -1
 * with errno:
 *   ETIMEDOUT  not shown within timeout_ns;
 *   EBADF      win is not the window's number;
 *   ENODEV     the service ended;
 *   EIO        the service answered in a way the layer does not know. */
int stafeto_window_shown(int win, uint64_t timeout_ns);

/* Closes the window: the service forgets it (its place is painted again in
 * the next frame), the buffers leave the process and the channel and the
 * timer of the window close. 0, or -1 with errno EBADF when win is not the
 * window's number. */
int stafeto_window_close(int win);

/* The calls are safe in several threads, except that one thread at a time
 * may wait (stafeto_window_wait; the second gets EBUSY), one at a time may
 * take events (the second gets EBUSY), and a call at the same time as
 * stafeto_window_close in another thread is undefined (EBADF is the likely
 * answer). */

#ifdef __cplusplus
}
#endif

#endif
