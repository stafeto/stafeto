/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The arithmetic of eglSwapBuffers on a window of stafeto (swap.h). */

#include <string.h>

#include "swap.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

int swap_rect_empty(struct swap_rect r)
{
	return r.w <= 0 || r.h <= 0;
}

struct swap_rect swap_rect_union(struct swap_rect a, struct swap_rect b)
{
	if (swap_rect_empty(a))
		return swap_rect_empty(b) ? (struct swap_rect){0, 0, 0, 0} : b;
	if (swap_rect_empty(b))
		return a;
	/* Sums in long long: a rectangle from a program may reach the ends of int. */
	long long x0 = MIN(a.x, b.x), y0 = MIN(a.y, b.y);
	long long x1 = MAX((long long)a.x + a.w, (long long)b.x + b.w);
	long long y1 = MAX((long long)a.y + a.h, (long long)b.y + b.h);
	return (struct swap_rect){(int)x0, (int)y0, (int)(x1 - x0), (int)(y1 - y0)};
}

struct swap_rect swap_rect_clip(struct swap_rect r, int width, int height)
{
	if (swap_rect_empty(r) || width <= 0 || height <= 0)
		return (struct swap_rect){0, 0, 0, 0};
	long long x0 = MAX(r.x, 0), y0 = MAX(r.y, 0);
	long long x1 = MIN((long long)r.x + r.w, width), y1 = MIN((long long)r.y + r.h, height);
	if (x1 <= x0 || y1 <= y0)
		return (struct swap_rect){0, 0, 0, 0};
	return (struct swap_rect){(int)x0, (int)y0, (int)(x1 - x0), (int)(y1 - y0)};
}

struct swap_rect swap_rect_from_gl(struct swap_rect r, int height)
{
	if (swap_rect_empty(r))
		return (struct swap_rect){0, 0, 0, 0};
	long long y = (long long)height - ((long long)r.y + r.h);
	/* A rectangle far outside the surface stays outside: clamp into int. */
	y = MAX(y, -2147483647LL);
	y = MIN(y, 2147483647LL);
	return (struct swap_rect){r.x, (int)y, r.w, r.h};
}

void swap_history_reset(struct swap_history *h)
{
	for (unsigned k = 0; k < SWAP_BUFFERS_MAX; k++)
		h->pending[k] = k < h->buffers ? (struct swap_rect){0, 0, h->width, h->height}
					       : (struct swap_rect){0, 0, 0, 0};
	h->posted = 0;
}

void swap_history_init(struct swap_history *h, int width, int height, unsigned buffers)
{
	h->width = width;
	h->height = height;
	h->buffers = MIN(buffers, SWAP_BUFFERS_MAX);
	swap_history_reset(h);
}

void swap_plan_make(struct swap_history *h, unsigned buffer, const int *rects, int n,
		    struct swap_plan *plan)
{
	struct swap_rect whole = {0, 0, h->width, h->height};
	struct swap_rect box = {0, 0, 0, 0};
	struct swap_rect kept[SWAP_POST_MAX];
	int kept_count = 0, merged = 0;

	memset(plan, 0, sizeof *plan);
	if (rects == NULL || n <= 0) {
		box = whole;
		/* The whole window changed: there is no use in naming rectangles. */
	} else {
		for (int i = 0; i < n; i++) {
			struct swap_rect r = {rects[4 * i], rects[4 * i + 1], rects[4 * i + 2],
					      rects[4 * i + 3]};
			r = swap_rect_clip(swap_rect_from_gl(r, h->height), h->width, h->height);
			if (swap_rect_empty(r))
				continue;
			box = swap_rect_union(box, r);
			if (kept_count < SWAP_POST_MAX)
				kept[kept_count] = r;
			else
				merged = 1;
			kept_count++;
		}
	}
	/* The buffers that are not filled now lack this frame's change. */
	for (unsigned k = 0; k < h->buffers; k++)
		if (k != buffer)
			h->pending[k] = swap_rect_union(h->pending[k], box);
	if (buffer < h->buffers) {
		plan->copy = swap_rect_union(h->pending[buffer], box);
		h->pending[buffer] = (struct swap_rect){0, 0, 0, 0};
	} else {
		plan->copy = box;
	}
	/* The post. The first frame is the whole window (the service has nothing
	 * of it yet). */
	if (!h->posted || rects == NULL || n <= 0) {
		plan->post_count = 0;
	} else if (kept_count == 0) {
		plan->post[0] = (struct swap_rect){0, 0, 1, 1};
		plan->post_count = 1;
	} else if (merged) {
		plan->post[0] = box;
		plan->post_count = 1;
	} else {
		for (int i = 0; i < kept_count; i++)
			plan->post[i] = kept[i];
		plan->post_count = (unsigned)kept_count;
	}
	h->posted = 1;
}

long swap_blit(unsigned char *dst, size_t dst_stride, int dst_w, int dst_h,
	       const unsigned char *src, size_t src_stride, int src_x, int src_y, int src_w, int src_h,
	       unsigned bpp, int flip, struct swap_rect region)
{
	struct swap_rect covered = {src_x, src_y, src_w, src_h};
	struct swap_rect r = swap_rect_clip(region, dst_w, dst_h);
	long points = 0;

	if (swap_rect_empty(r) || swap_rect_empty(covered) || bpp == 0)
		return 0;
	/* The part of the region the source covers. */
	long long x0 = MAX(r.x, covered.x), y0 = MAX(r.y, covered.y);
	long long x1 = MIN((long long)r.x + r.w, (long long)covered.x + covered.w);
	long long y1 = MIN((long long)r.y + r.h, (long long)covered.y + covered.h);
	if (x1 <= x0 || y1 <= y0)
		return 0;
	for (long long y = y0; y < y1; y++) {
		long long row = y - covered.y;
		if (flip)
			row = (long long)covered.h - 1 - row;
		const unsigned char *from = src + (size_t)row * src_stride + (size_t)(x0 - covered.x) * bpp;
		unsigned char *to = dst + (size_t)y * dst_stride + (size_t)x0 * bpp;
		memcpy(to, from, (size_t)(x1 - x0) * bpp);
		points += (long)(x1 - x0);
	}
	return points;
}

int swap_window_matches_readback(const unsigned char *window, size_t window_stride,
				 const unsigned char *rgba, int w, int h)
{
	for (int y = 0; y < h; y++) {
		const unsigned char *from = window + (size_t)y * window_stride;
		const unsigned char *to = rgba + ((size_t)(h - 1 - y) * (size_t)w) * 4;
		for (int x = 0; x < w; x++) {
			if (from[x * 4 + 2] != to[x * 4] || from[x * 4 + 1] != to[x * 4 + 1] ||
			    from[x * 4] != to[x * 4 + 2])
				return 0;
		}
	}
	return 1;
}

int swap_readback_is_symmetric(const unsigned char *rgba, int w, int h)
{
	for (int y = 0; y < h / 2; y++) {
		const unsigned char *top = rgba + (size_t)y * (size_t)w * 4;
		const unsigned char *bottom = rgba + (size_t)(h - 1 - y) * (size_t)w * 4;
		if (memcmp(top, bottom, (size_t)w * 4) != 0)
			return 0;
	}
	return 1;
}
