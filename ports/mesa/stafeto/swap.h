/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The arithmetic of eglSwapBuffers on a window of stafeto: which part of a
 * window's buffer a swap must copy, which rectangles the swap posts, and the
 * copy of the rows. No call of Mesa, EGL or the window library is made here,
 * so the functions are tested on the host (swap_test.c).
 *
 * A window has two or three buffers. The frame of a swap goes to a free one
 * (the buffer of an earlier frame), and the program draws only what changed,
 * so a buffer must be brought up to date with every change since the swap that
 * last filled it: the history keeps for each buffer the bounding box of the
 * damage that came after its last copy. The first copy of a buffer is the
 * whole window. A rectangle is in the window's own coordinates (x to the
 * right, y down from the top); the rectangles of eglSwapBuffersWithDamage are
 * in the surface's (y up from the bottom) and are turned by swap_rect_from_gl.
 */
#ifndef STAFETO_SWAP_H
#define STAFETO_SWAP_H

#include <stddef.h>

#define SWAP_BUFFERS_MAX 3
/* The most rectangles one POST takes; more are merged into their bounding box. */
#define SWAP_POST_MAX 4

struct swap_rect {
	int x, y, w, h;
};

/* A rectangle with no point (w or h not above 0). */
int swap_rect_empty(struct swap_rect r);
/* The bounding box of two rectangles; an empty one counts for nothing. */
struct swap_rect swap_rect_union(struct swap_rect a, struct swap_rect b);
/* The part of r inside a window of width by height points (empty if none). */
struct swap_rect swap_rect_clip(struct swap_rect r, int width, int height);
/* The rectangle of the surface's coordinates (origin at the lower left, as EGL
 * and GL give them) in the window's (origin at the upper left). */
struct swap_rect swap_rect_from_gl(struct swap_rect r, int height);

struct swap_history {
	int width, height;
	unsigned buffers;
	/* What each buffer lacks of the newest frame, as a bounding box. */
	struct swap_rect pending[SWAP_BUFFERS_MAX];
	/* A frame was posted since the window opened or the history was reset. */
	int posted;
};

/* The history of a window of width by height points with `buffers` buffers
 * (1 to SWAP_BUFFERS_MAX): every buffer lacks the whole window. */
void swap_history_init(struct swap_history *h, int width, int height, unsigned buffers);
/* Forgets what the buffers hold: the next swap copies the whole window and
 * posts it. A failed post ends here. */
void swap_history_reset(struct swap_history *h);

struct swap_plan {
	/* What to copy into the buffer (empty: nothing). */
	struct swap_rect copy;
	/* The rectangles to post, in the window's coordinates; none means the
	 * whole window (the first frame). */
	struct swap_rect post[SWAP_POST_MAX];
	unsigned post_count;
};

/* The plan of a swap into `buffer`. `rects` is n rectangles of the surface's
 * coordinates as four ints each (x, y, width, height), the damage of the
 * frame; n 0 (or rects null) says the whole surface changed. Rectangles are
 * clipped to the window and empty ones dropped; up to SWAP_POST_MAX of what is
 * left are posted as they are, more are posted as their bounding box, and a
 * damage that clips to nothing is posted as one point (a post with no
 * rectangle would mean the whole window). The other buffers take the damage
 * into what they lack, and `buffer` lacks nothing after the copy. */
void swap_plan_make(struct swap_history *h, unsigned buffer, const int *rects, int n,
		    struct swap_plan *plan);

/* Copies the points of `region` (the window's coordinates) that the source
 * covers. The source is a picture of src_w by src_h points whose upper left
 * is at (src_x, src_y) of the window, src_stride bytes a row, rows from the
 * top, bpp bytes a point; flip reads its rows from the bottom up. The
 * destination is the window's buffer of dst_w by dst_h points, dst_stride
 * bytes a row. Returns the number of points copied. */
long swap_blit(unsigned char *dst, size_t dst_stride, int dst_w, int dst_h,
	       const unsigned char *src, size_t src_stride, int src_x, int src_y, int src_w, int src_h,
	       unsigned bpp, int flip, struct swap_rect region);

#endif
