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
 * has up to STAFETO_WINDOWS_MAX windows, numbered from 0: a new window takes
 * the lowest number that is free, and the number is in every call. All the
 * windows of a process share one channel to the service; the label the
 * service sends with each notification says which window it is for, and
 * stafeto_windows_wait waits across all of them.
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
 * A window made with STAFETO_WINDOW_RESIZABLE has buffers that hold the whole
 * screen, and stafeto_window_resize changes its size inside what its buffers
 * hold (stafeto_window_capacity). A window without the flag holds its own
 * size, and it may be made smaller and grown back. A window manager, when
 * the image has one, may move the window, hide it, give it the focus, ask it
 * to change size (CONFIGURE) and ask it to close (CLOSE_REQUEST); the window
 * learns of these from events. A window gives its title and the kind of its
 * program to the manager with stafeto_window_set_title and _set_app_id.
 *
 * A program skips the events whose kind it does not know: later revisions of
 * the service add kinds (the list below grows).
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
/* A window of 8 bits an alpha, a byte a point and a line (stride) of the
 * width rounded up to a multiple of 4: the mask of an element of a scene
 * (OpenWF Composition's mask). It is never shown on the screen by itself. */
#define STAFETO_WINDOW_A8 4

/* The most windows of a process. */
#define STAFETO_WINDOWS_MAX 8

/* The flag of stafeto_window_open: the window's buffers hold the whole
 * screen (at most 1 MiB each), so that stafeto_window_resize can grow it to
 * the screen's size. The stride of such a window is the screen's line. */
#define STAFETO_WINDOW_RESIZABLE 1u

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
/* Returned by stafeto_windows_wait alone, for a window the service took
 * away or ended: the window's element of the bits array has it, and the
 * calls on that window return ENODEV. */
#define STAFETO_WINDOW_GONE (1u << 4)

/* The flag of stafeto_window_events: events were dropped (the ring of 64
 * overflowed) since the call before. */
#define STAFETO_WINDOW_EVENTS_LOST 1u

/* The kinds of an event (struct stafeto_window_event, field kind). */
#define STAFETO_WINDOW_EVENT_KEY 1
#define STAFETO_WINDOW_EVENT_MOVE 2
#define STAFETO_WINDOW_EVENT_BUTTON 3
#define STAFETO_WINDOW_EVENT_FOCUS_IN 4
#define STAFETO_WINDOW_EVENT_FOCUS_OUT 5
/* The manager asks for a size: code holds the state bits below, value is
 * the serial to give back to stafeto_window_resize, x and y are the width
 * and height asked for (0 and 0: the program chooses). The program may
 * answer with another size inside its capacity, or not answer. */
#define STAFETO_WINDOW_EVENT_CONFIGURE 8
/* The manager asks the window to close. The program decides. No fields. */
#define STAFETO_WINDOW_EVENT_CLOSE_REQUEST 9

/* The state bits of a CONFIGURE event's code. */
#define STAFETO_WINDOW_STATE_MAXIMIZED 1u
#define STAFETO_WINDOW_STATE_FULLSCREEN 2u
#define STAFETO_WINDOW_STATE_RESIZING 4u

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
 * The other elements are null. generation is 1 for the first window a
 * process opens and grows with each window it opens after: a window closed
 * and opened again under the same number has another generation. */
struct stafeto_window {
    uint32_t width, height, stride, format, buffers, generation;
    void *pixels[STAFETO_WINDOW_BUFFERS_MAX];
};

/* A rectangle of points in the window's own coordinates. */
struct stafeto_rect {
    int32_t x, y, w, h;
};

/* An event of the window. A kind the program does not know is skipped. KEY: code is Linux's key code, value 1 for the
 * press and 0 for the release (no repeat). MOVE: x and y are the pointer's
 * place in the window's coordinates. BUTTON: code is the button (Linux's
 * BTN_LEFT, 0x110, and the others), value as a key's, x and y as a
 * MOVE's. FOCUS_IN and FOCUS_OUT carry no number. CONFIGURE and
 * CLOSE_REQUEST are described above. The 16 bytes are the service's own
 * event. */
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
STAFETO_WINDOW_ASSERT(offsetof(struct stafeto_window, generation) == 20);
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
 * 0 or STAFETO_WINDOW_RESIZABLE (EINVAL otherwise). The buffers are zero.
 * All of them are free. The
 * window shows once the first post is taken into a frame. With one buffer
 * the window shows one picture: its buffer never comes back. A program that
 * draws again uses two or three. Returns the window's number (the lowest free
 * one, from 0), or -1
 * with errno:
 *   ENODEV  as stafeto_screen_describe;
 *   EBUSY   the service is busy with another client's buffers and stayed so
 *           for half a second;
 *   EINVAL  the window is not inside the screen or is empty, the format is
 *           not one above, buffers is not 1 to 3, a buffer would be more
 *           than 1 MiB, flags is not one above, or out is null;
 *   ENOMEM  the buffers do not fit the address space or the process's
 *           memory;
 *   EAGAIN  the process has STAFETO_WINDOWS_MAX windows, or the service has
 *           no room for another window (it limits the windows of a process);
 *   EINTR   a signal ended a wait for a display that is being set up or
 *           for the service;
 *   EIO     the service answered in a way the layer does not know.
 * On any failure the window is not made and nothing of it remains. The
 * pixel memory of a window is the process's own and the service only reads
 * it, so no cache maintenance is needed. The window's size changes only with
 * stafeto_window_resize. */
int stafeto_window_open(int x, int y, int w, int h, uint32_t format,
                        uint32_t buffers, uint32_t flags,
                        struct stafeto_window *out);

/* Describes the open window `win` in *out as stafeto_window_open did: the
 * size, the bytes of a line, the format, the number of buffers and where each
 * buffer lies. A library that draws into a window another part of the program
 * opened (the EGL platform of stafeto) learns its shape here. 0, or -1 with
 * errno:
 *   EBADF   win is not the window's number or the window was closed;
 *   EINVAL  out is null.
 * The values are those of the window that is open now: a window closed and
 * opened again may have the same number and has another generation. No call
 * to the service. The size is the one of the last stafeto_window_resize the
 * library took. */
int stafeto_window_info(int win, struct stafeto_window *out);

/* Posts buffer `buffer` of window `win`: the service shows it in its next
 * frame. r points at `count` rectangles in the window's coordinates that
 * cover every point differing from what the screen shows of this window now
 * (the buffer posted before). The service may copy more than the rectangles
 * (this revision copies their bounding box) and keeps what the screen shows
 * outside what it copied. count 0 (r may be null) means the whole window.
 * Up to 4 rectangles go to the service as they are; 5 or more are merged
 * into one, their bounding box. Each must be inside the window, in the size
 * of the last stafeto_window_resize. While
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

/* Waits for a bit of the service for window `win` on the process's channel, at most
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
 *   EBUSY      another thread of the process is waiting for bits in
 *              stafeto_window_wait or stafeto_windows_wait (a thread in stafeto_window_wait_free is
 *              no reason for it: this call then takes what waits on the
 *              channel without blocking and pauses a millisecond between
 *              looks, so a poll with a timeout of 0 answers at once);
 *   EIO        the kernel refused the wait.
 * A window closed by another thread during the wait is EBADF.
 * The service's end wakes a wait that is under way (the kernel tells the
 * window's channel when the service's last copy of it goes), and the wait
 * returns ENODEV; a call that finds the service gone (post, events) does
 * too.
 * A later descriptor for poll will only add a way to sleep;
 * stafeto_window_wait(win, 0, &bits) stays the call that takes the bits. */
int stafeto_window_wait(int win, uint64_t timeout_ns, uint32_t *bits);

/* Waits for bits of any window of the process, at most timeout_ns
 * nanoseconds (0 looks without waiting, UINT64_MAX waits with no limit).
 * bits (null is allowed) points to STAFETO_WINDOWS_MAX words: bits[k] gets
 * the bits that came for window k since the last call that took them (each
 * bit is returned by one call of this function or of stafeto_window_wait),
 * 0 for a window with none or none open. A window the service took away has
 * STAFETO_WINDOW_GONE in its word, and keeps it until the window is closed (a
 * program closes such a window). A window closed in another thread ends a wait
 * on that window with EBADF.
 * The buffer bits are applied to the masks of stafeto_window_free_buffers
 * before the call returns. Returns the mask of the windows that have bits
 * (bit k for window k; bit 30, STAFETO_MANAGER_EVENTS of <stafeto/manager.h>,
 * says the manager's ring of a process that subscribed has events; the result
 * is never negative, and only -1 is a failure), or -1 with errno:
 *   ETIMEDOUT  no bit came in time;
 *   EINTR      a signal with a handler ran during the wait;
 *   EBADF      the process has no window and no manager's subscription;
 *   EBUSY      another thread of the process is waiting for bits (in this
 *              function or in stafeto_window_wait);
 *   EIO        the kernel refused the wait. */
int stafeto_windows_wait(uint64_t timeout_ns, uint32_t *bits);

/* Waits until a buffer of `mask` (a mask of STAFETO_WINDOW_BUFFER(k) bits) is
 * free by the library's account, at most timeout_ns nanoseconds (0 looks
 * without waiting, UINT64_MAX waits with no limit), and gives in *free (null
 * is allowed) the free buffers among them. It takes no bit away from
 * stafeto_window_wait: the bits the service sent, the events bit among them,
 * stay for the next call of that function, which a thread asleep in it is woken
 * for. One thread at a time sleeps in the wait of the channel. While a thread
 * is in stafeto_window_wait, this function takes what waits on the channel
 * without blocking and pauses a millisecond between looks, so it does not
 * depend on that thread running; and the other way round (see
 * stafeto_window_wait).
 * 0 when a buffer of the mask is free, or -1 with errno:
 *   ETIMEDOUT  none was free in time;
 *   EINTR      a signal with a handler ran during the wait;
 *   EINVAL     mask is 0 or names a bit that is no buffer of the window (the
 *              events bit, or a buffer past the window's `buffers`);
 *   EBADF      win is not the window's number;
 *   ENODEV     the service ended;
 *   EIO        the kernel refused the wait. */
int stafeto_window_wait_free(int win, uint32_t mask, uint64_t timeout_ns,
                             uint32_t *free);

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

/* Gives the window a title and the kind of its program (an application
 * id), each a string of at most 64 bytes of UTF-8. A window manager shows
 * them. 0, or -1 with errno:
 *   EBADF   win is not an open window;
 *   EINVAL  the string is null, longer than 64 bytes or not UTF-8 (the
 *           service judges that);
 *   ENODEV  the service ended or took the window away;
 *   EIO     the service answered in a way the layer does not know. */
int stafeto_window_set_title(int win, const char *title);
int stafeto_window_set_app_id(int win, const char *app_id);

/* The most width and height stafeto_window_resize takes for the window: for
 * a window made with STAFETO_WINDOW_RESIZABLE the screen's size (less when
 * a buffer of 1 MiB does not hold the screen); for another window the width
 * of its line and the lines the pages of its buffers hold (a little over its
 * height); 0 and 0 for a mask (STAFETO_WINDOW_A8). 0, or -1 with errno EBADF
 * when win is not an open window. w and h
 * may be null. No call to the service. */
int stafeto_window_capacity(int win, uint32_t *w, uint32_t *h);

/* Changes the size of the window to w by h: the size of the next post (the
 * service shows the old buffer in the old size until a frame takes the
 * posted one, and a second resize before that post replaces the first). The
 * window keeps its place, so it grows and shrinks at its right and bottom
 * edges. serial is the serial of the CONFIGURE event this answers, or 0. The
 * rectangles of the next post are in the new size, and so is the size
 * stafeto_window_info gives (the stride stays). 0, or -1 with errno:
 *   EBADF   win is not an open window;
 *   EINVAL  w or h is 0 or past the capacity, the window is a mask
 *           (STAFETO_WINDOW_A8), or the service refused the size (the
 *           window would reach outside the screen, or serial is not that of
 *           the last CONFIGURE the service gave);
 *   EPERM   the service does not let this window change size (a scene shows
 *           the windows);
 *   ENODEV  the service ended or took the window away;
 *   EIO     the service answered in a way the layer does not know. */
int stafeto_window_resize(int win, uint32_t w, uint32_t h, uint32_t serial);

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
 * the next frame) and the buffers leave the process; the channel and the
 * timer close with the last window. 0, or -1 with errno EBADF when win is
 * not an open window's number. */
int stafeto_window_close(int win);

/* The calls are safe in several threads, except that one thread at a time
 * may wait (stafeto_window_wait or stafeto_windows_wait, for all windows
 * together; the second gets EBUSY), one at a time may take the events of a
 * window (the second gets EBUSY), and a call at the same time as
 * stafeto_window_close in another thread is undefined (EBADF is the likely
 * answer). */

#ifdef __cplusplus
}
#endif

#endif
