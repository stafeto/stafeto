/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* Host tests of swap.c: tools/test_build_mesa.py builds and runs this file.
 * Each test prints "ok <name>"; the first failure prints the line and exits 1. */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "swap.h"

static int failures;
static const char *current;

#define CHECK(cond)                                                                    \
	do {                                                                           \
		if (!(cond)) {                                                         \
			printf("FAIL %s: line %d: %s\n", current, __LINE__, #cond);   \
			failures++;                                                    \
			return;                                                        \
		}                                                                      \
	} while (0)

#define RECT_IS(r, X, Y, W, H) ((r).x == (X) && (r).y == (Y) && (r).w == (W) && (r).h == (H))

static void test_empty_rectangles(void)
{
	CHECK(swap_rect_empty((struct swap_rect){0, 0, 0, 5}));
	CHECK(swap_rect_empty((struct swap_rect){0, 0, 5, 0}));
	CHECK(swap_rect_empty((struct swap_rect){3, 3, -1, 5}));
	CHECK(!swap_rect_empty((struct swap_rect){-4, -4, 1, 1}));
}

static void test_union_ignores_empty(void)
{
	struct swap_rect a = {10, 20, 5, 6}, none = {0, 0, 0, 0};
	CHECK(RECT_IS(swap_rect_union(a, none), 10, 20, 5, 6));
	CHECK(RECT_IS(swap_rect_union(none, a), 10, 20, 5, 6));
	CHECK(swap_rect_empty(swap_rect_union(none, none)));
}

static void test_union_is_the_bounding_box(void)
{
	struct swap_rect u = swap_rect_union((struct swap_rect){0, 0, 2, 2}, (struct swap_rect){8, 9, 2, 1});
	CHECK(RECT_IS(u, 0, 0, 10, 10));
	u = swap_rect_union((struct swap_rect){5, 5, 10, 10}, (struct swap_rect){6, 6, 2, 2});
	CHECK(RECT_IS(u, 5, 5, 10, 10));
}

static void test_clip_keeps_what_is_inside(void)
{
	CHECK(RECT_IS(swap_rect_clip((struct swap_rect){10, 10, 20, 20}, 100, 100), 10, 10, 20, 20));
	CHECK(RECT_IS(swap_rect_clip((struct swap_rect){0, 0, 100, 100}, 100, 100), 0, 0, 100, 100));
}

static void test_clip_cuts_the_edges(void)
{
	CHECK(RECT_IS(swap_rect_clip((struct swap_rect){-5, -5, 20, 20}, 100, 100), 0, 0, 15, 15));
	CHECK(RECT_IS(swap_rect_clip((struct swap_rect){90, 95, 50, 50}, 100, 100), 90, 95, 10, 5));
}

static void test_clip_drops_what_is_outside(void)
{
	CHECK(swap_rect_empty(swap_rect_clip((struct swap_rect){100, 0, 10, 10}, 100, 100)));
	CHECK(swap_rect_empty(swap_rect_clip((struct swap_rect){-10, 0, 10, 10}, 100, 100)));
	CHECK(swap_rect_empty(swap_rect_clip((struct swap_rect){0, 0, 10, 10}, 0, 100)));
}

static void test_clip_survives_the_ends_of_int(void)
{
	struct swap_rect r = swap_rect_clip((struct swap_rect){INT_MAX - 1, 0, INT_MAX, 10}, 100, 100);
	CHECK(swap_rect_empty(r));
	r = swap_rect_clip((struct swap_rect){INT_MIN, INT_MIN, INT_MAX, INT_MAX}, 100, 100);
	CHECK(swap_rect_empty(r));
	r = swap_rect_clip((struct swap_rect){-1, -1, INT_MAX, INT_MAX}, 100, 100);
	CHECK(RECT_IS(r, 0, 0, 100, 100));
}

static void test_gl_rectangle_is_turned_over(void)
{
	/* The row 0 of GL is the bottom: a 10-high rectangle at y 0 of a window 100 high is the last 10 rows. */
	CHECK(RECT_IS(swap_rect_from_gl((struct swap_rect){4, 0, 20, 10}, 100), 4, 90, 20, 10));
	/* The top rows of the window are the highest of GL. */
	CHECK(RECT_IS(swap_rect_from_gl((struct swap_rect){0, 95, 5, 5}, 100), 0, 0, 5, 5));
	/* The whole surface stays the whole surface. */
	CHECK(RECT_IS(swap_rect_from_gl((struct swap_rect){0, 0, 640, 400}, 400), 0, 0, 640, 400));
}

static void test_gl_rectangle_twice_is_itself(void)
{
	struct swap_rect r = {7, 13, 9, 21};
	struct swap_rect back = swap_rect_from_gl(swap_rect_from_gl(r, 120), 120);
	CHECK(RECT_IS(back, 7, 13, 9, 21));
}

static void test_gl_rectangle_outside_stays_outside(void)
{
	struct swap_rect r = swap_rect_clip(swap_rect_from_gl((struct swap_rect){0, 100, 10, 10}, 100), 100, 100);
	CHECK(swap_rect_empty(r));
	r = swap_rect_clip(swap_rect_from_gl((struct swap_rect){0, INT_MAX - 5, 10, INT_MAX}, 100), 100, 100);
	CHECK(swap_rect_empty(r));
	r = swap_rect_clip(swap_rect_from_gl((struct swap_rect){0, INT_MIN, 10, 20}, 100), 100, 100);
	CHECK(swap_rect_empty(r));
}

static void test_a_new_history_lacks_the_whole_window(void)
{
	struct swap_history h;
	swap_history_init(&h, 64, 32, 3);
	for (unsigned k = 0; k < 3; k++)
		CHECK(RECT_IS(h.pending[k], 0, 0, 64, 32));
	CHECK(!h.posted);
	swap_history_init(&h, 64, 32, 2);
	CHECK(swap_rect_empty(h.pending[2]));
	swap_history_init(&h, 64, 32, 9);
	CHECK(h.buffers == SWAP_BUFFERS_MAX);
}

static void test_the_first_frame_copies_and_posts_the_whole_window(void)
{
	struct swap_history h;
	struct swap_plan p;
	const int small[4] = {10, 10, 4, 4};
	swap_history_init(&h, 64, 32, 2);
	swap_plan_make(&h, 0, small, 1, &p);
	CHECK(RECT_IS(p.copy, 0, 0, 64, 32));
	CHECK(p.post_count == 0);
}

static void test_a_swap_without_damage_posts_the_whole_window(void)
{
	struct swap_history h;
	struct swap_plan p;
	swap_history_init(&h, 64, 32, 2);
	swap_plan_make(&h, 0, NULL, 0, &p);
	swap_plan_make(&h, 1, NULL, 0, &p);
	swap_plan_make(&h, 0, NULL, 0, &p);
	CHECK(RECT_IS(p.copy, 0, 0, 64, 32));
	CHECK(p.post_count == 0);
}

static void test_two_buffers_copy_the_damage_of_two_frames(void)
{
	struct swap_history h;
	struct swap_plan p;
	/* In GL's rows: y 0 of a window 32 high is the window's row 28 for a 4-high rectangle. */
	const int first[4] = {0, 0, 4, 4}, second[4] = {60, 28, 4, 4}, third[4] = {30, 14, 2, 2};
	swap_history_init(&h, 64, 32, 2);
	swap_plan_make(&h, 0, NULL, 0, &p);   /* frame 1 into buffer 0: all */
	swap_plan_make(&h, 1, NULL, 0, &p);   /* frame 2 into buffer 1: all */
	swap_plan_make(&h, 0, first, 1, &p);  /* frame 3 into buffer 0 */
	/* Buffer 0 held frame 1 and lacks the damage of frame 2 (all) and frame 3. */
	CHECK(RECT_IS(p.copy, 0, 0, 64, 32));
	swap_plan_make(&h, 1, second, 1, &p); /* frame 4 into buffer 1 */
	/* Buffer 1 held frame 2 and lacks frame 3 (first, at the window's row 28) and frame 4 (second, row 0). */
	CHECK(RECT_IS(p.copy, 0, 0, 64, 32));
	swap_plan_make(&h, 0, third, 1, &p);  /* frame 5 into buffer 0 */
	/* Buffer 0 held frame 3 and lacks frame 4 (60..64, rows 0..4) and frame 5 (30..32, rows 16..18). */
	CHECK(RECT_IS(p.copy, 30, 0, 34, 18));
	CHECK(p.post_count == 1 && RECT_IS(p.post[0], 30, 16, 2, 2));
}

static void test_three_buffers_lack_three_frames(void)
{
	struct swap_history h;
	struct swap_plan p;
	/* In the window's rows (32 high): a is (0,2,2,2), b is (10,10,2,2), c is (20,20,2,2). */
	const int a[4] = {0, 28, 2, 2}, b[4] = {10, 20, 2, 2}, c[4] = {20, 10, 2, 2};
	swap_history_init(&h, 64, 32, 3);
	for (unsigned k = 0; k < 3; k++)
		swap_plan_make(&h, k, NULL, 0, &p);
	swap_plan_make(&h, 0, a, 1, &p);
	CHECK(RECT_IS(p.copy, 0, 0, 64, 32));
	swap_plan_make(&h, 1, b, 1, &p);
	CHECK(RECT_IS(p.copy, 0, 0, 64, 32));
	/* Buffer 2 held the last whole frame and lacks a, b and c. */
	swap_plan_make(&h, 2, c, 1, &p);
	CHECK(RECT_IS(p.copy, 0, 2, 22, 20));
	/* Buffer 0 held frame a and lacks b and c. */
	swap_plan_make(&h, 0, NULL, 0, &p);
	CHECK(RECT_IS(p.copy, 0, 0, 64, 32));
}

static void test_a_buffer_lacks_nothing_after_its_copy(void)
{
	struct swap_history h;
	struct swap_plan p;
	const int r[4] = {0, 0, 4, 4};
	swap_history_init(&h, 64, 32, 2);
	swap_plan_make(&h, 0, NULL, 0, &p);
	CHECK(swap_rect_empty(h.pending[0]));
	swap_plan_make(&h, 1, NULL, 0, &p);
	swap_plan_make(&h, 0, r, 1, &p);
	CHECK(swap_rect_empty(h.pending[0]));
	CHECK(!swap_rect_empty(h.pending[1]));
}

static void test_up_to_four_rectangles_are_posted_as_they_are(void)
{
	struct swap_history h;
	struct swap_plan p;
	const int rs[16] = {0, 0, 2, 2, 10, 0, 2, 2, 20, 0, 2, 2, 30, 0, 2, 2};
	swap_history_init(&h, 64, 32, 2);
	swap_plan_make(&h, 0, NULL, 0, &p);
	swap_plan_make(&h, 1, rs, 4, &p);
	CHECK(p.post_count == 4);
	CHECK(RECT_IS(p.post[0], 0, 30, 2, 2));
	CHECK(RECT_IS(p.post[3], 30, 30, 2, 2));
}

static void test_more_than_four_rectangles_are_posted_as_their_box(void)
{
	struct swap_history h;
	struct swap_plan p;
	const int rs[20] = {0, 0, 2, 2, 10, 0, 2, 2, 20, 0, 2, 2, 30, 0, 2, 2, 40, 10, 2, 2};
	swap_history_init(&h, 64, 32, 2);
	swap_plan_make(&h, 0, NULL, 0, &p);
	swap_plan_make(&h, 1, rs, 5, &p);
	CHECK(p.post_count == 1);
	CHECK(RECT_IS(p.post[0], 0, 20, 42, 12));
}

static void test_empty_and_outside_rectangles_are_dropped(void)
{
	struct swap_history h;
	struct swap_plan p;
	const int rs[12] = {0, 0, 0, 5, 100, 100, 5, 5, 4, 4, 2, 2};
	swap_history_init(&h, 64, 32, 2);
	swap_plan_make(&h, 0, NULL, 0, &p);
	swap_plan_make(&h, 1, rs, 3, &p);
	CHECK(p.post_count == 1);
	CHECK(RECT_IS(p.post[0], 4, 26, 2, 2));
}

static void test_a_damage_of_nothing_posts_one_point(void)
{
	struct swap_history h;
	struct swap_plan p;
	const int rs[4] = {0, 0, 0, 0};
	swap_history_init(&h, 64, 32, 2);
	swap_plan_make(&h, 0, NULL, 0, &p);
	swap_plan_make(&h, 1, NULL, 0, &p);
	swap_plan_make(&h, 0, rs, 1, &p);
	CHECK(p.post_count == 1);
	CHECK(RECT_IS(p.post[0], 0, 0, 1, 1));
	/* Buffer 0 still copies what the swaps since its last copy changed. */
	CHECK(RECT_IS(p.copy, 0, 0, 64, 32));
	/* Buffer 1 was copied whole at its swap and no frame has changed anything since. */
	swap_plan_make(&h, 1, rs, 1, &p);
	CHECK(swap_rect_empty(p.copy));
	swap_plan_make(&h, 0, rs, 1, &p);
	CHECK(swap_rect_empty(p.copy));
}

static void test_reset_makes_the_next_swap_whole(void)
{
	struct swap_history h;
	struct swap_plan p;
	const int r[4] = {0, 0, 4, 4};
	swap_history_init(&h, 64, 32, 2);
	swap_plan_make(&h, 0, NULL, 0, &p);
	swap_plan_make(&h, 1, NULL, 0, &p);
	swap_plan_make(&h, 0, r, 1, &p);
	CHECK(p.post_count == 1);
	swap_history_reset(&h);
	swap_plan_make(&h, 1, r, 1, &p);
	CHECK(RECT_IS(p.copy, 0, 0, 64, 32));
	CHECK(p.post_count == 0);
}

static void test_a_buffer_beyond_the_window_copies_the_damage_only(void)
{
	struct swap_history h;
	struct swap_plan p;
	const int r[4] = {1, 1, 3, 3};
	swap_history_init(&h, 64, 32, 2);
	swap_plan_make(&h, 7, r, 1, &p);
	CHECK(RECT_IS(p.copy, 1, 28, 3, 3));
}

static void fill(unsigned char *p, size_t n, unsigned char v)
{
	memset(p, v, n);
}

static void test_blit_copies_the_rows_of_the_region(void)
{
	unsigned char src[4 * 4 * 4], dst[4 * 4 * 4];
	for (int i = 0; i < 16; i++)
		for (int b = 0; b < 4; b++)
			src[i * 4 + b] = (unsigned char)(i + 1);
	fill(dst, sizeof dst, 0);
	long n = swap_blit(dst, 16, 4, 4, src, 16, 0, 0, 4, 4, 4, 0, (struct swap_rect){1, 1, 2, 2});
	CHECK(n == 4);
	CHECK(dst[(1 * 4 + 1) * 4] == 6 && dst[(1 * 4 + 2) * 4] == 7);
	CHECK(dst[(2 * 4 + 1) * 4] == 10 && dst[(2 * 4 + 2) * 4] == 11);
	CHECK(dst[0] == 0 && dst[(3 * 4 + 3) * 4] == 0 && dst[(1 * 4 + 3) * 4] == 0);
}

static void test_blit_with_flip_reads_the_rows_from_the_bottom(void)
{
	unsigned char src[4 * 4], dst[4 * 4];
	for (int row = 0; row < 4; row++)
		fill(src + row * 4, 4, (unsigned char)(row + 1));
	fill(dst, sizeof dst, 0);
	CHECK(swap_blit(dst, 4, 4, 4, src, 4, 0, 0, 4, 4, 1, 1, (struct swap_rect){0, 0, 4, 4}) == 16);
	CHECK(dst[0] == 4 && dst[4] == 3 && dst[8] == 2 && dst[12] == 1);
}

static void test_blit_flip_of_a_part_keeps_the_rows_of_the_part(void)
{
	unsigned char src[4 * 4], dst[4 * 4];
	for (int row = 0; row < 4; row++)
		fill(src + row * 4, 4, (unsigned char)(row + 1));
	fill(dst, sizeof dst, 0);
	/* The window's row 0 is the source's last row: 4. */
	CHECK(swap_blit(dst, 4, 4, 4, src, 4, 0, 0, 4, 4, 1, 1, (struct swap_rect){0, 0, 4, 1}) == 4);
	CHECK(dst[0] == 4 && dst[4] == 0);
}

static void test_blit_stops_at_the_sources_edge(void)
{
	/* The source is wider than the window (the pitch of the buffer is rounded up) and
	 * the window is wider than a source that is a sub-image. */
	unsigned char src[8 * 2], dst[4 * 2];
	fill(src, sizeof src, 9);
	fill(dst, sizeof dst, 0);
	CHECK(swap_blit(dst, 4, 4, 2, src, 8, 0, 0, 8, 2, 1, 0, (struct swap_rect){0, 0, 4, 2}) == 8);
	fill(dst, sizeof dst, 0);
	CHECK(swap_blit(dst, 4, 4, 2, src, 2, 1, 0, 2, 2, 1, 0, (struct swap_rect){0, 0, 4, 2}) == 4);
	CHECK(dst[0] == 0 && dst[1] == 9 && dst[2] == 9 && dst[3] == 0);
}

static void test_blit_of_nothing_copies_nothing(void)
{
	unsigned char src[16], dst[16];
	fill(src, sizeof src, 1);
	fill(dst, sizeof dst, 0);
	CHECK(swap_blit(dst, 4, 4, 4, src, 4, 0, 0, 4, 4, 1, 0, (struct swap_rect){0, 0, 0, 0}) == 0);
	CHECK(swap_blit(dst, 4, 4, 4, src, 4, 0, 0, 4, 4, 1, 0, (struct swap_rect){9, 9, 2, 2}) == 0);
	CHECK(swap_blit(dst, 4, 4, 4, src, 4, 0, 0, 4, 4, 0, 0, (struct swap_rect){0, 0, 4, 4}) == 0);
	CHECK(dst[0] == 0 && dst[15] == 0);
}

static void test_blit_clips_the_region_to_the_destination(void)
{
	unsigned char src[8 * 8], dst[4 * 4];
	fill(src, sizeof src, 5);
	fill(dst, sizeof dst, 0);
	CHECK(swap_blit(dst, 4, 4, 4, src, 8, 0, 0, 8, 8, 1, 0, (struct swap_rect){-3, -3, 20, 20}) == 16);
	CHECK(dst[0] == 5 && dst[15] == 5);
}

/* A picture as the driver keeps it (rows from the top, blue green red x) and its readback
 * (red green blue alpha, rows from the bottom up). */
static void make_picture(unsigned char *top_down, unsigned char *readback, int w, int h)
{
	for (int y = 0; y < h; y++)
		for (int x = 0; x < w; x++) {
			unsigned char r = (unsigned char)(x * 7 + y * 3), g = (unsigned char)(y * 11),
				      b = (unsigned char)(x * 5);
			unsigned char *p = top_down + ((size_t)y * w + x) * 4;
			unsigned char *q = readback + ((size_t)(h - 1 - y) * w + x) * 4;
			p[0] = b; p[1] = g; p[2] = r; p[3] = 0;
			q[0] = r; q[1] = g; q[2] = b; q[3] = 255;
		}
}

static void test_a_copy_that_keeps_the_rows_matches_the_readback(void)
{
	enum { W = 8, H = 6 };
	unsigned char top_down[W * H * 4], readback[W * H * 4], window[W * H * 4];
	make_picture(top_down, readback, W, H);
	memset(window, 0, sizeof window);
	CHECK(swap_blit(window, W * 4, W, H, top_down, W * 4, 0, 0, W, H, 4, 0,
			(struct swap_rect){0, 0, W, H}) == W * H);
	CHECK(swap_window_matches_readback(window, W * 4, readback, W, H));
	CHECK(!swap_readback_is_symmetric(readback, W, H));
}

static void test_a_copy_that_flips_the_rows_fails_the_readback_check(void)
{
	enum { W = 8, H = 6 };
	unsigned char top_down[W * H * 4], readback[W * H * 4], window[W * H * 4];
	make_picture(top_down, readback, W, H);
	memset(window, 0, sizeof window);
	/* The planted fault: flip = 1 in the copy. */
	CHECK(swap_blit(window, W * 4, W, H, top_down, W * 4, 0, 0, W, H, 4, 1,
			(struct swap_rect){0, 0, W, H}) == W * H);
	CHECK(!swap_window_matches_readback(window, W * 4, readback, W, H));
}

static void test_a_symmetric_picture_is_told_from_the_rest(void)
{
	enum { W = 4, H = 4 };
	unsigned char rgba[W * H * 4];
	for (int y = 0; y < H; y++)
		for (int x = 0; x < W * 4; x++)
			rgba[y * W * 4 + x] = (unsigned char)(y < H / 2 ? y : H - 1 - y);
	CHECK(swap_readback_is_symmetric(rgba, W, H));
	rgba[0] ^= 1;
	CHECK(!swap_readback_is_symmetric(rgba, W, H));
}

struct test {
	const char *name;
	void (*run)(void);
};

#define T(f) {#f, f}

int main(void)
{
	static const struct test tests[] = {
		T(test_empty_rectangles),
		T(test_union_ignores_empty),
		T(test_union_is_the_bounding_box),
		T(test_clip_keeps_what_is_inside),
		T(test_clip_cuts_the_edges),
		T(test_clip_drops_what_is_outside),
		T(test_clip_survives_the_ends_of_int),
		T(test_gl_rectangle_is_turned_over),
		T(test_gl_rectangle_twice_is_itself),
		T(test_gl_rectangle_outside_stays_outside),
		T(test_a_new_history_lacks_the_whole_window),
		T(test_the_first_frame_copies_and_posts_the_whole_window),
		T(test_a_swap_without_damage_posts_the_whole_window),
		T(test_two_buffers_copy_the_damage_of_two_frames),
		T(test_three_buffers_lack_three_frames),
		T(test_a_buffer_lacks_nothing_after_its_copy),
		T(test_up_to_four_rectangles_are_posted_as_they_are),
		T(test_more_than_four_rectangles_are_posted_as_their_box),
		T(test_empty_and_outside_rectangles_are_dropped),
		T(test_a_damage_of_nothing_posts_one_point),
		T(test_reset_makes_the_next_swap_whole),
		T(test_a_buffer_beyond_the_window_copies_the_damage_only),
		T(test_blit_copies_the_rows_of_the_region),
		T(test_blit_with_flip_reads_the_rows_from_the_bottom),
		T(test_blit_flip_of_a_part_keeps_the_rows_of_the_part),
		T(test_blit_stops_at_the_sources_edge),
		T(test_blit_of_nothing_copies_nothing),
		T(test_blit_clips_the_region_to_the_destination),
		T(test_a_copy_that_keeps_the_rows_matches_the_readback),
		T(test_a_copy_that_flips_the_rows_fails_the_readback_check),
		T(test_a_symmetric_picture_is_told_from_the_rest),
	};
	for (size_t i = 0; i < sizeof tests / sizeof tests[0]; i++) {
		int before = failures;
		current = tests[i].name;
		tests[i].run();
		if (failures == before)
			printf("ok %s\n", tests[i].name);
	}
	return failures ? 1 : 0;
}
