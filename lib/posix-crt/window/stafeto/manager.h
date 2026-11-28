/* SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1 */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The window manager's calls on the composition service. The service puts
 * the windows on the screen and hands the manager the decisions: where a
 * window is, which is on top, which has the keyboard's focus, how big it
 * is, whether it is shown, and when it is asked to close. A manager lists
 * the windows, reads the events of its ring (a window made or gone, a new
 * title, a new size, and the keys the service does not route to a window),
 * and answers with the calls below. This header goes with
 * <stafeto/window.h>, in the same static library, and a manager may open
 * windows of its own with the calls of that header (its panel, the frames
 * of the windows it manages), and tie them to a window of a client with
 * stafeto_manager_link.
 *
 * A process is a manager only when the init table gives its session the
 * manager's mark (a table of an image names the program); the service
 * answers every other session, a child's clone of the manager's among
 * them, with EPERM at stafeto_manager_subscribe. One session holds the
 * subscription at a time. A manager never calls exec: the session and its
 * mark move with the process image, so exec returns EPERM in a process that
 * has subscribed.
 *
 * Windows are named by the id the service gave them: the `value` of the
 * CREATE and CLOSE events, the `id` of a listed window, and
 * stafeto_window_id for a window of the manager's own. An id of a window
 * that went is refused with EINVAL; that is a race the manager expects and
 * goes on from.
 *
 * Every function returns 0, a count, or -1 with errno. Besides the errno
 * each lists:
 *   EPERM   (the calls after the subscription) a property of the window the
 *           call names, listed with each call, or the service refusing the
 *           manager's calls because a scene's holder has subscribed or
 *           committed a scene (the scene is then the one manager);
 *   EBADF   (every call but stafeto_manager_subscribe and
 *           stafeto_window_id) the process has not subscribed;
 *   ENODEV  the service ended;
 *   EIO     the service answered in a way the layer does not know.
 */
#ifndef _STAFETO_MANAGER_H
#define _STAFETO_MANAGER_H

#include <stddef.h>
#include <stdint.h>

#include <stafeto/window.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The most windows stafeto_manager_list gives. */
#define STAFETO_MANAGER_WINDOWS_MAX 16

/* The bit of the mask stafeto_windows_wait returns when the manager's ring
 * has events (bit k of the mask is window k). The program takes the events
 * with stafeto_manager_events until a call returns fewer than max. */
#define STAFETO_MANAGER_EVENTS (1u << 30)

/* The kinds of an event of the manager's ring, besides the key, pointer and
 * focus kinds of <stafeto/window.h> (the keys the service does not route to
 * a window, the Super chords among them, come here as KEY events).
 *   CREATE   a window was made: value is its id, code its place;
 *   CLOSE    a window went: value is its id, code its place;
 *   TITLE    a text of a window changed: value is the id, x says which
 *            (STAFETO_MANAGER_TITLE or _APP_ID); the text is in
 *            stafeto_manager_info, and one TITLE of each text waits in the
 *            ring at a time;
 *   RESIZED  a window took a buffer of another size: value is the id, x and
 *            y the width and height. */
#define STAFETO_MANAGER_EVENT_CREATE 6
#define STAFETO_MANAGER_EVENT_CLOSE 7
#define STAFETO_MANAGER_EVENT_TITLE 10
#define STAFETO_MANAGER_EVENT_RESIZED 11
#define STAFETO_MANAGER_TITLE 1
#define STAFETO_MANAGER_APP_ID 2

/* The flags of a listed window. */
#define STAFETO_MANAGER_SHOWN 1u
#define STAFETO_MANAGER_FOCUSED 2u

/* The flags of stafeto_manager_info. LEGACY: a window of the first revision
 * (<stafeto/display.h>), which has no title and cannot be resized. ARGB: the
 * window's points carry an alpha. LEADER: a window of the manager follows
 * it. FOLLOWER: the window follows another. OWN: a window of the manager's
 * own session. */
#define STAFETO_MANAGER_INFO_LEGACY 1u
#define STAFETO_MANAGER_INFO_ARGB 2u
#define STAFETO_MANAGER_INFO_LEADER 4u
#define STAFETO_MANAGER_INFO_FOLLOWER 8u
#define STAFETO_MANAGER_INFO_OWN 16u

/* The follower that stafeto_manager_link takes to break a link. */
#define STAFETO_MANAGER_NO_WINDOW 0xFFFFFFFFu

/* A window of the list: its id, place and size in points, the flags and its
 * place in the order of depth (0 is the lowest). */
struct stafeto_manager_window {
    uint32_t id, x, y, w, h, flags, depth;
};

/* What stafeto_manager_info says of a window: the flags, the most size it
 * can be asked for (0 by 0 before its buffers are attached) and its two
 * texts as C strings. */
struct stafeto_manager_info {
    uint32_t flags, cap_w, cap_h;
    char title[65];
    char app_id[65];
    uint8_t reserved[2];
};

#if defined(__cplusplus) && __cplusplus >= 201103L
#define STAFETO_MANAGER_ASSERT(c) static_assert(c, #c)
#elif !defined(__cplusplus) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define STAFETO_MANAGER_ASSERT(c) _Static_assert(c, #c)
#else
#define STAFETO_MANAGER_JOIN_(a, b) a##b
#define STAFETO_MANAGER_JOIN(a, b) STAFETO_MANAGER_JOIN_(a, b)
#define STAFETO_MANAGER_ASSERT(c) \
    typedef char STAFETO_MANAGER_JOIN(stafeto_manager_assert_, __LINE__)[(c) ? 1 : -1]
#endif
STAFETO_MANAGER_ASSERT(sizeof(struct stafeto_manager_window) == 28);
STAFETO_MANAGER_ASSERT(offsetof(struct stafeto_manager_window, x) == 4);
STAFETO_MANAGER_ASSERT(offsetof(struct stafeto_manager_window, y) == 8);
STAFETO_MANAGER_ASSERT(offsetof(struct stafeto_manager_window, w) == 12);
STAFETO_MANAGER_ASSERT(offsetof(struct stafeto_manager_window, h) == 16);
STAFETO_MANAGER_ASSERT(offsetof(struct stafeto_manager_window, flags) == 20);
STAFETO_MANAGER_ASSERT(offsetof(struct stafeto_manager_window, depth) == 24);
STAFETO_MANAGER_ASSERT(sizeof(struct stafeto_manager_info) == 144);
STAFETO_MANAGER_ASSERT(offsetof(struct stafeto_manager_info, cap_w) == 4);
STAFETO_MANAGER_ASSERT(offsetof(struct stafeto_manager_info, cap_h) == 8);
STAFETO_MANAGER_ASSERT(offsetof(struct stafeto_manager_info, title) == 12);
STAFETO_MANAGER_ASSERT(offsetof(struct stafeto_manager_info, app_id) == 77);
STAFETO_MANAGER_ASSERT(offsetof(struct stafeto_manager_info, reserved) == 142);
#undef STAFETO_MANAGER_ASSERT
#undef STAFETO_MANAGER_JOIN
#undef STAFETO_MANAGER_JOIN_

/* Subscribes the process to the manager's ring: the service tells the
 * process's channel when the ring has events, and stafeto_windows_wait
 * returns STAFETO_MANAGER_EVENTS for it (a manager with no window of its own
 * may call stafeto_windows_wait too). The service tells a CREATE for each
 * window it has already, so a manager that starts late learns of them from
 * its ring (stafeto_manager_list shows them at once). The ring holds 64
 * events, the oldest dropped past that (the LOST flag of
 * stafeto_manager_events). With a manager subscribed, the service gives a new
 * window neither the focus nor the top place: the manager decides with
 * stafeto_manager_focus. 0, or -1 with errno:
 *   EPERM   the session is not the manager's;
 *   EBUSY   the process subscribed already, or another session holds the
 *           subscription (a manager that restarts gets this until the
 *           service has seen the old session go: it tries again);
 *   ENODEV  the process has no display service, or the service ended;
 *   ENOMEM  the process has no room for the channel. */
int stafeto_manager_subscribe(void);

/* Takes up to max events of the manager's ring without waiting: the count,
 * 0 for none (a count below max means the ring is empty). A max above
 * STAFETO_WINDOW_EVENTS_MAX takes that many per service call and goes on.
 * *flags (null is allowed) gets STAFETO_WINDOW_EVENTS_LOST when the ring
 * dropped events. A program skips the kinds it does not know. -1 with errno:
 *   EINVAL  e is null or max is not positive;
 *   EBUSY   another thread is taking the manager's events. */
int stafeto_manager_events(struct stafeto_window_event *e, int max, uint32_t *flags);

/* Lists up to max windows, the lowest in the order of depth first: the
 * count. max of STAFETO_MANAGER_WINDOWS_MAX holds them all. EINVAL when w is
 * null or max is not positive. */
int stafeto_manager_list(struct stafeto_manager_window *w, int max);

/* Describes window id in *out. EINVAL when out is null or no window has the
 * id. */
int stafeto_manager_info(uint32_t id, struct stafeto_manager_info *out);

/* Moves window id so that its top left point is (x, y). A follower of the
 * window moves by the same offset. EINVAL when no window has the id, or the
 * window or its follower would reach outside the screen (nothing moves then).
 * EPERM also for a window of the first revision, which is never moved. */
int stafeto_manager_move(uint32_t id, uint32_t x, uint32_t y);

/* Puts window id on top of the others (its follower directly below it). A
 * window of the manager's own that has no leader stays above the others of
 * other sessions. EINVAL when no window has the id. */
int stafeto_manager_raise(uint32_t id);

/* Gives window id the keyboard's focus and the top place. The focus of a
 * follower goes to its leader (a follower never has it). EINVAL when no
 * window has the id. */
int stafeto_manager_focus(uint32_t id);

/* Shows (shown not 0) or hides window id and its follower. EINVAL when no
 * window has the id. */
int stafeto_manager_visible(uint32_t id, int shown);

/* Asks window id for w by h points and the state bits of
 * STAFETO_WINDOW_STATE_* (0 by 0 leaves the size to the program). The window
 * gets a CONFIGURE event with a serial and may answer with
 * stafeto_window_resize; the manager is told of the new size by RESIZED when a
 * frame takes the window's next buffer. The window keeps its place (it grows
 * and shrinks at its right and bottom edges); the service refuses the
 * client's answer if the window would reach outside the screen. EINVAL when
 * no window has the id, a side is past the screen's (and past 65535), only
 * one side is 0, or a state bit is unknown. EPERM for a window of the first
 * revision and for a mask (STAFETO_WINDOW_A8). */
int stafeto_manager_configure(uint32_t id, uint32_t w, uint32_t h, uint32_t states);

/* Asks window id to close itself (the window gets a CLOSE_REQUEST event and
 * decides). The manager is told of the window's end by a CLOSE event. EPERM
 * for a window of the first revision, which cannot be asked to close. */
int stafeto_manager_close(uint32_t id);

/* Ties window follower, one of the manager's own windows, to window leader of
 * a client, with the offset they have now: the service moves, raises, hides
 * and shows the two as one in a single frame, and the follower lies directly
 * below the leader (a frame around it, for one). STAFETO_MANAGER_NO_WINDOW
 * for follower breaks the link of leader. The link ends when the leader
 * goes. EINVAL when no window has an id or the follower is not the
 * manager's own. */
int stafeto_manager_link(uint32_t leader, uint32_t follower);

/* The id of the process's open window win (what the manager's events and
 * the calls above name windows by): lets a manager tell its own windows from
 * the others in a list and in the CREATE events. 0, or -1 with errno EBADF
 * when win is not an open window and EINVAL when id is null. No call to the
 * service. */
int stafeto_window_id(int win, uint32_t *id);

#ifdef __cplusplus
}
#endif

#endif
