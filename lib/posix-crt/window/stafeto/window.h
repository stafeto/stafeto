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
 * The screen is 640 by 400 points. A point is a 32-bit word stored low byte
 * first: 0x00RRGGBB (XRGB8888, opaque) or 0xAARRGGBB with the colour
 * already multiplied by the alpha (ARGB8888, laid over what is below).
 * The buffers are ordinary memory of the process, `stride` bytes a line, and
 * they are not copied by fork: a child has no window. The window and its
 * buffers go with stafeto_window_close, exec and the end of the process.
 *
 * Every function returns 0 or a count (or the window's number), or -1 with
 * errno, as <stafeto/display.h> does.
 */
#ifndef _STAFETO_WINDOW_H
#define _STAFETO_WINDOW_H

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

/* The bits stafeto_window_wait returns and stafeto_window_free gives:
 * STAFETO_WINDOW_BUFFER(k) says buffer k (0 to 2) is free, and
 * STAFETO_WINDOW_EVENTS says the window's ring holds events to take. */
#define STAFETO_WINDOW_BUFFER(k) (1u << (k))
#define STAFETO_WINDOW_EVENTS (1u << 3)

/* The flag of stafeto_window_events: events were dropped (the ring of 64
 * overflowed) since the call before. */
#define STAFETO_EVENTS_LOST 1u

/* The kinds of an event (struct stafeto_window_event, field kind). */
#define STAFETO_EVENT_KEY 1
#define STAFETO_EVENT_MOVE 2
#define STAFETO_EVENT_BUTTON 3
#define STAFETO_EVENT_FOCUS_IN 4
#define STAFETO_EVENT_FOCUS_OUT 5

/* The size of the screen and its format, as stafeto_screen_describe gives
 * them. flags is 0 in this revision. */
struct stafeto_screen {
    uint32_t width, height, format, flags;
};

/* A window as stafeto_window_open made it: its size, the bytes of a line,
 * the format, the number of buffers and where each lies in the process.
 * pixels[k] for k below `buffers` points at height * stride bytes the
 * program may read and write while buffer k is free; the other elements are
 * null. reserved is 0. */
struct stafeto_window {
    uint32_t width, height, stride, format, buffers, reserved;
    void *pixels[3];
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

#ifdef __cplusplus
#define STAFETO_WINDOW_ASSERT(c) static_assert(c, #c)
#else
#define STAFETO_WINDOW_ASSERT(c) _Static_assert(c, #c)
#endif
STAFETO_WINDOW_ASSERT(sizeof(struct stafeto_screen) == 16);
STAFETO_WINDOW_ASSERT(sizeof(struct stafeto_window) == 48);
STAFETO_WINDOW_ASSERT(__builtin_offsetof(struct stafeto_window, pixels) == 24);
STAFETO_WINDOW_ASSERT(sizeof(struct stafeto_rect) == 16);
STAFETO_WINDOW_ASSERT(sizeof(struct stafeto_window_event) == 16);
STAFETO_WINDOW_ASSERT(__builtin_offsetof(struct stafeto_window_event, value) == 4);
STAFETO_WINDOW_ASSERT(__builtin_offsetof(struct stafeto_window_event, x) == 8);
STAFETO_WINDOW_ASSERT(__builtin_offsetof(struct stafeto_window_event, y) == 12);
#undef STAFETO_WINDOW_ASSERT

/* Describes the screen. 0, or -1 with errno:
 *   ENODEV  the process has no display service (an image without one, a
 *           service that ended or started again) or the device did not
 *           answer;
 *   EINVAL  s is null;
 *   EIO     the service answered in a way the layer does not know. */
int stafeto_screen_describe(struct stafeto_screen *s);

/* Makes a window of w by h points at (x, y) of the screen, with `buffers`
 * (1 to 3) buffers of the given format, and describes it in *out. The
 * buffers are zero. The window shows once the first post is taken into a
 * frame. Returns the window's number (0), or -1 with errno:
 *   ENODEV  as stafeto_screen_describe;
 *   EBUSY   the process has a window already, or the service is busy with
 *           another client's buffers and stayed so for half a second;
 *   EINVAL  the window is not inside the screen or is empty, the format is
 *           not one above, buffers is not 1 to 3, a buffer would be more
 *           than 1 MiB, or out is null;
 *   ENOMEM  the buffers do not fit the address space or the process's
 *           memory;
 *   EAGAIN  the service has no room for another window (32 contexts, 64
 *           windows);
 *   EINTR   a signal ended a wait for a display that is being set up;
 *   EIO     the service answered in a way the layer does not know.
 * The pixel memory of a window is the process's own and the service only
 * reads it, so no cache maintenance is needed. The window's place and size
 * do not change. */
int stafeto_window_open(int x, int y, int w, int h, uint32_t format,
                        unsigned buffers, struct stafeto_window *out);

/* Posts buffer `buffer` of window `win`: the service shows it in its next
 * frame. r points at `count` rectangles in the window's coordinates that
 * cover every point differing from what the screen shows of this window now
 * (the buffer posted before). The service copies the bounding box of the
 * rectangles and keeps what the screen shows outside it. count 0 (r may be
 * null) means the whole window. Up to 4 rectangles go to the service as
 * they are; 5 or more are merged into one, their bounding box. Each must be
 * inside the window. The buffer is the service's until a bit says it is
 * free (stafeto_window_wait): the program leaves it alone. The latest post
 * wins: a buffer posted and not yet taken into a frame is replaced by a
 * later post and is free again at once. 0, or -1 with errno:
 *   EBADF   win is not the window's number or the window was closed;
 *   EBUSY   the buffer is not free by the library's account (it was posted
 *           and no bit said it is free again);
 *   EINVAL  buffer is not below the number of buffers, a rectangle is
 *           empty or outside the window, or r is null with count above 0;
 *   ENODEV  the service ended or took the window away;
 *   EIO     the service answered in a way the layer does not know. */
int stafeto_window_post(int win, unsigned buffer, const struct stafeto_rect *r,
                        unsigned count);

/* The buffers the library counts free, as a mask of STAFETO_WINDOW_BUFFER(k)
 * bits: all of them after stafeto_window_open, a buffer leaves the mask when
 * posted and returns when the service's bit for it came (see
 * stafeto_window_wait; stafeto_window_post also takes the bits that already
 * wait on the channel). No call to the service. 0 for a win that is not
 * open. */
unsigned stafeto_window_free(int win);

/* Waits for a bit of the service on the window's own channel, at most
 * timeout_ns nanoseconds (0 looks without waiting, UINT64_MAX waits with no
 * limit), and returns in *bits (null is allowed) the bits that came since
 * the last call: STAFETO_WINDOW_BUFFER(k) bits and STAFETO_WINDOW_EVENTS.
 * The buffer bits are applied to the account of stafeto_window_free before
 * the call returns. Returns 0 when at least one bit is there; or -1 with
 * errno:
 *   ETIMEDOUT  no bit came in time;
 *   EINTR      a signal with a handler ran during the wait;
 *   EBADF      win is not the window's number;
 *   ENODEV     the service ended;
 *   EBUSY      another thread of the process is waiting on the window;
 *   EIO        the kernel refused the wait. */
int stafeto_window_wait(int win, uint64_t timeout_ns, uint32_t *bits);

/* Takes up to max (at most 32) events of the window's ring without waiting:
 * the count, 0 for none. *flags (null is allowed) gets
 * STAFETO_EVENTS_LOST when the ring dropped older events. -1 with errno:
 *   EBADF   win is not the window's number;
 *   EINVAL  e is null or max is not positive;
 *   ENODEV  the service ended or took the window away;
 *   EIO     the service answered in a way the layer does not know. */
int stafeto_window_events(int win, struct stafeto_window_event *e, int max,
                          unsigned *flags);

/* Waits until the frame of the last post is on the screen: the service has
 * shown a frame since and is not making one (the probes and the
 * screenshot want this; a program that draws does not). It looks at the
 * service every 2 ms, so it costs a call to the service each time. 0, or -1
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
 * may wait (stafeto_window_wait; the second gets EBUSY) and that a call at
 * the same time as stafeto_window_close in another thread is undefined (EBADF
 * is the likely answer). stafeto_window_wait ends with EINTR when a signal
 * with a handler arrives, after the handler ran; the other calls go on after
 * a signal. */

#ifdef __cplusplus
}
#endif

#endif
