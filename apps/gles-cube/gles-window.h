/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The window mode of the cube (`gles-cube --window`), included by gles-cube.c
 * when it is built for stafeto (-DSTAFETO_WINDOW): the window of the
 * composition service (<stafeto/window.h>) as an EGL window surface on the
 * platform of stafeto (docs/egl.md).
 *
 * window_launch starts the copy that draws (a program init starts cannot
 * fork, the copy of a spawn can, as tests/posix-window does). The copy checks
 * the API first (a display not initialized, the format of the window against
 * the configuration, a handle that is no window, a second surface over one
 * window, the swap behaviour and the swap interval, a swap with no current
 * context, a swap in a forked child, two threads with two contexts), then
 * draws the frames of the cube, swaps each one (the interval alternates 1 and
 * 0) and twice stops (at the third frame, "window crc", and at the last, "last
 * crc") to print the CRC-32 of the screen it should show: the host takes QEMU's
 * screenshot while the program sleeps and compares.
 */

#include <errno.h>
#include <pthread.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <EGL/eglext.h>
#include <stafeto/window.h>

#include "swap.h"

extern char **environ;

#define SCREEN_W 640
#define SCREEN_H 400
#define SECOND 1000000000ull
#define WINDOW_BUFFERS 3

static int window_number = -1;
static struct stafeto_window window_shape;

/* The error the call before left, and that it is the wanted one. */
#define CHECK_ERROR(wanted)                                                              \
	do {                                                                             \
		EGLint got_ = eglGetError();                                             \
		if (got_ != (wanted)) {                                                  \
			printf("gles-cube: check failed at line %d: error 0x%x, 0x%x wanted\n", \
			       __LINE__, (unsigned)got_, (unsigned)(wanted));            \
			exit(1);                                                         \
		}                                                                        \
	} while (0)

/* Starts the copy of this program that draws, and ends with its status. */
static int window_launch(int argc, char **argv)
{
	char *args[16];
	pid_t pid = 0;
	int status = 0;
	int n = 0;
	args[n++] = (char *)"gles-cube";
	args[n++] = (char *)"--window-run";
	for (int i = 1; i < argc && n < 14; i++)
		if (strcmp(argv[i], "--window") != 0)
			args[n++] = argv[i];
	args[n] = NULL;
	int spawned = posix_spawn(&pid, "/bin/gles-cube", NULL, NULL, args, environ);
	if (spawned != 0) {
		printf("gles-cube: the drawing copy did not start: error %d\n", spawned);
		return 1;
	}
	CHECK(waitpid(pid, &status, 0) == pid);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		printf("gles-cube: the drawing copy ended with status 0x%x\n", (unsigned)status);
		return 1;
	}
	return 0;
}

/* A display that is not initialized answers EGL_NOT_INITIALIZED. */
static void window_before_initialize(EGLDisplay display)
{
	EGLint count = 0;
	CHECK(eglGetConfigs(display, NULL, 0, &count) == EGL_FALSE);
	CHECK_ERROR(EGL_NOT_INITIALIZED);
	printf("gles-cube: api a display not initialized answers EGL_NOT_INITIALIZED\n");
}

static EGLint config_value(EGLDisplay display, EGLConfig config, EGLint attribute);

/* The first configuration of windows and OpenGL ES 2 with 8 bits of each
 * colour, `alpha` bits of alpha and a 16-bit depth buffer: eglChooseConfig
 * leaves the order of formats that match to the implementation, and the
 * program wants one of them. */
static EGLConfig window_choose(EGLDisplay display, EGLint alpha)
{
	EGLConfig all[64];
	EGLint count = 0;
	CHECK(eglGetConfigs(display, all, 64, &count) == EGL_TRUE);
	for (EGLint i = 0; i < count; i++) {
		if ((config_value(display, all[i], EGL_SURFACE_TYPE) & EGL_WINDOW_BIT) &&
		    (config_value(display, all[i], EGL_RENDERABLE_TYPE) & EGL_OPENGL_ES2_BIT) &&
		    config_value(display, all[i], EGL_RED_SIZE) == 8 &&
		    config_value(display, all[i], EGL_GREEN_SIZE) == 8 &&
		    config_value(display, all[i], EGL_BLUE_SIZE) == 8 &&
		    config_value(display, all[i], EGL_ALPHA_SIZE) == alpha &&
		    config_value(display, all[i], EGL_DEPTH_SIZE) == 16)
			return all[i];
	}
	CHECK(0);
	return NULL;
}

static EGLint config_value(EGLDisplay display, EGLConfig config, EGLint attribute)
{
	EGLint value = -1;
	CHECK(eglGetConfigAttrib(display, config, attribute, &value) == EGL_TRUE);
	return value;
}

/* The window of the window mode: size by size at the middle of the screen,
 * XRGB8888, three buffers. Its surface, with the refusals of the platform
 * checked on the way; *config is the configuration of the surface. */
static EGLSurface window_surface(EGLDisplay display, int size, EGLConfig *config)
{
	struct stafeto_screen screen;
	CHECK(stafeto_screen_describe(&screen) == 0);
	CHECK(screen.width == SCREEN_W && screen.height == SCREEN_H);
	CHECK(size <= (int)screen.height);
	window_number = stafeto_window_open((SCREEN_W - size) / 2, (SCREEN_H - size) / 2, size, size,
					    STAFETO_WINDOW_XRGB8888, WINDOW_BUFFERS, 0, &window_shape);
	CHECK(window_number == 0);
	CHECK(window_shape.width == (uint32_t)size && window_shape.buffers == WINDOW_BUFFERS);

	/* The configurations: every one names the format of the window it takes. */
	EGLConfig all[64];
	EGLint count = 0;
	CHECK(eglGetConfigs(display, all, 64, &count) == EGL_TRUE);
	CHECK(count > 0);
	for (EGLint i = 0; i < count; i++) {
		EGLint visual = config_value(display, all[i], EGL_NATIVE_VISUAL_ID);
		CHECK(visual == STAFETO_WINDOW_XRGB8888 || visual == STAFETO_WINDOW_ARGB8888);
		CHECK(config_value(display, all[i], EGL_SAMPLES) == 0);
		CHECK(config_value(display, all[i], EGL_MAX_SWAP_INTERVAL) == 1);
		CHECK(config_value(display, all[i], EGL_MIN_SWAP_INTERVAL) == 0);
	}
	*config = window_choose(display, 0);
	CHECK(config_value(display, *config, EGL_NATIVE_VISUAL_ID) == STAFETO_WINDOW_XRGB8888);
	EGLint types = config_value(display, *config, EGL_SURFACE_TYPE);
	CHECK((types & EGL_WINDOW_BIT) && (types & EGL_PBUFFER_BIT) &&
	      (types & EGL_SWAP_BEHAVIOR_PRESERVED_BIT));
	CHECK(!(types & EGL_PIXMAP_BIT));
	printf("gles-cube: api %d configurations name the format of a window, the one chosen is XRGB8888\n",
	       (int)count);

	/* A configuration of the other format does not match this window. */
	EGLConfig other = window_choose(display, 8);
	CHECK(config_value(display, other, EGL_NATIVE_VISUAL_ID) == STAFETO_WINDOW_ARGB8888);
	CHECK(eglCreateWindowSurface(display, other, (EGLNativeWindowType)(window_number + 1), NULL) ==
	      EGL_NO_SURFACE);
	CHECK_ERROR(EGL_BAD_MATCH);
	/* No window has the handle 0 (the number plus 1 is the handle) or a number nobody made. */
	CHECK(eglCreateWindowSurface(display, *config, (EGLNativeWindowType)0, NULL) == EGL_NO_SURFACE);
	CHECK_ERROR(EGL_BAD_NATIVE_WINDOW);
	CHECK(eglCreateWindowSurface(display, *config, (EGLNativeWindowType)6, NULL) == EGL_NO_SURFACE);
	CHECK_ERROR(EGL_BAD_NATIVE_WINDOW);
	/* A pixmap has no place here. */
	CHECK(eglCreatePixmapSurface(display, *config, (EGLNativePixmapType)1, NULL) == EGL_NO_SURFACE);
	EGLint pixmap_error = eglGetError();
	CHECK(pixmap_error == EGL_BAD_MATCH || pixmap_error == EGL_BAD_NATIVE_PIXMAP ||
	      pixmap_error == EGL_BAD_ALLOC);
	printf("gles-cube: api a window of another format, the handles 0 and 6 and a pixmap are refused\n");

	EGLSurface surface =
		eglCreateWindowSurface(display, *config, (EGLNativeWindowType)(window_number + 1), NULL);
	CHECK(surface != EGL_NO_SURFACE);
	/* One surface for a window. */
	CHECK(eglCreateWindowSurface(display, *config, (EGLNativeWindowType)(window_number + 1), NULL) ==
	      EGL_NO_SURFACE);
	CHECK_ERROR(EGL_BAD_ALLOC);
	EGLint width = 0, height = 0;
	CHECK(eglQuerySurface(display, surface, EGL_WIDTH, &width) == EGL_TRUE);
	CHECK(eglQuerySurface(display, surface, EGL_HEIGHT, &height) == EGL_TRUE);
	CHECK(width == size && height == size);
	printf("gles-cube: api the surface is %d by %d, a second one over the window is EGL_BAD_ALLOC\n",
	       (int)width, (int)height);
	return surface;
}

/* What the second thread does: its own pbuffer and context, a clear read back. */
struct other_thread {
	EGLDisplay display;
	EGLConfig config;
	int result;
};

static void *other_thread_main(void *argument)
{
	struct other_thread *t = argument;
	static const EGLint context_attributes[] = {EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE};
	static const EGLint pbuffer_attributes[] = {EGL_WIDTH, 16, EGL_HEIGHT, 16, EGL_NONE};
	uint8_t pixel[4] = {0, 0, 0, 0};
	t->result = 1;
	/* The current context is a thread's own: this one has none. */
	if (eglGetCurrentContext() != EGL_NO_CONTEXT)
		return NULL;
	if (eglBindAPI(EGL_OPENGL_ES_API) != EGL_TRUE)
		return NULL;
	EGLSurface surface = eglCreatePbufferSurface(t->display, t->config, pbuffer_attributes);
	EGLContext context = eglCreateContext(t->display, t->config, EGL_NO_CONTEXT, context_attributes);
	if (surface == EGL_NO_SURFACE || context == EGL_NO_CONTEXT)
		return NULL;
	if (eglMakeCurrent(t->display, surface, surface, context) != EGL_TRUE)
		return NULL;
	glClearColor(0.0f, 1.0f, 0.0f, 1.0f);
	glClear(GL_COLOR_BUFFER_BIT);
	glReadPixels(3, 3, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, pixel);
	if (pixel[0] != 0 || pixel[1] != 255 || pixel[2] != 0)
		return NULL;
	if (eglMakeCurrent(t->display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT) != EGL_TRUE)
		return NULL;
	if (eglDestroyContext(t->display, context) != EGL_TRUE ||
	    eglDestroySurface(t->display, surface) != EGL_TRUE)
		return NULL;
	/* A thread that used EGL ends with eglReleaseThread. */
	if (eglReleaseThread() != EGL_TRUE)
		return NULL;
	t->result = 0;
	return NULL;
}

/* A second thread and the window surface: step 0, the surface is current in
 * the main thread and the thread cannot take it (EGL_BAD_ACCESS); step 1, the
 * main thread has released it, and the thread makes it current, draws, swaps
 * and lets go. */
struct surface_thread {
	EGLDisplay display;
	EGLConfig config;
	EGLSurface surface;
	int step;
	int result;
};

static void *surface_thread_main(void *argument)
{
	struct surface_thread *t = argument;
	static const EGLint context_attributes[] = {EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE};
	t->result = 1;
	if (eglBindAPI(EGL_OPENGL_ES_API) != EGL_TRUE)
		return NULL;
	EGLContext context = eglCreateContext(t->display, t->config, EGL_NO_CONTEXT, context_attributes);
	if (context == EGL_NO_CONTEXT)
		return NULL;
	if (t->step == 0) {
		if (eglMakeCurrent(t->display, t->surface, t->surface, context) != EGL_FALSE ||
		    eglGetError() != EGL_BAD_ACCESS)
			return NULL;
	} else {
		if (eglMakeCurrent(t->display, t->surface, t->surface, context) != EGL_TRUE)
			return NULL;
		glClearColor(0.2f, 0.4f, 0.6f, 1.0f);
		glClear(GL_COLOR_BUFFER_BIT);
		if (eglSwapBuffers(t->display, t->surface) != EGL_TRUE)
			return NULL;
		if (eglMakeCurrent(t->display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT) != EGL_TRUE)
			return NULL;
	}
	if (eglDestroyContext(t->display, context) != EGL_TRUE || eglReleaseThread() != EGL_TRUE)
		return NULL;
	t->result = 0;
	return NULL;
}

/* A thread asleep in stafeto_window_wait for as long as it takes, while the
 * main thread swaps: the swaps leave it its bits. */
struct waiter {
	uint32_t seen;
	int wakeups;
	int stop;
	int result;
};

static void *waiter_main(void *argument)
{
	struct waiter *w = argument;
	w->result = 1;
	for (;;) {
		uint32_t bits = 0;
		if (stafeto_window_wait(window_number, UINT64_MAX, &bits) != 0) {
			w->result = errno ? errno : 2;
			return NULL;
		}
		__atomic_or_fetch(&w->seen, bits, __ATOMIC_SEQ_CST);
		__atomic_add_fetch(&w->wakeups, 1, __ATOMIC_SEQ_CST);
		if (__atomic_load_n(&w->stop, __ATOMIC_SEQ_CST))
			break;
	}
	w->result = 0;
	return NULL;
}

/* The checks that need the context current: the surface's behaviour and
 * intervals, a swap with no current context, a swap in a forked child and two
 * threads with two contexts. The surface and the context are current on return. */
static void window_api_checks(EGLDisplay display, EGLSurface surface, EGLConfig config, int size)
{
	EGLContext context = eglGetCurrentContext();
	CHECK(context != EGL_NO_CONTEXT);
	(void)size;

	/* The swap behaviour: the window keeps its frame, so both values are taken. */
	EGLint behavior = 0;
	CHECK(eglSurfaceAttrib(display, surface, EGL_SWAP_BEHAVIOR, EGL_BUFFER_PRESERVED) == EGL_TRUE);
	CHECK(eglQuerySurface(display, surface, EGL_SWAP_BEHAVIOR, &behavior) == EGL_TRUE);
	CHECK(behavior == EGL_BUFFER_PRESERVED);
	CHECK(eglSurfaceAttrib(display, surface, EGL_SWAP_BEHAVIOR, EGL_BUFFER_DESTROYED) == EGL_TRUE);
	/* The swap interval 0 and 1; more is held to the configuration's 1. */
	CHECK(eglSwapInterval(display, 0) == EGL_TRUE);
	CHECK(eglSwapInterval(display, 1) == EGL_TRUE);
	CHECK(eglSwapInterval(display, 2) == EGL_TRUE);
	printf("gles-cube: api swap behaviour preserved or destroyed, swap interval 0, 1 and 2 (held to 1)\n");

	/* No current context: the surface is not bound to one. */
	CHECK(eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT) == EGL_TRUE);
	CHECK(eglSwapBuffers(display, surface) == EGL_FALSE);
	CHECK_ERROR(EGL_BAD_SURFACE);
	CHECK(eglMakeCurrent(display, surface, surface, context) == EGL_TRUE);
	printf("gles-cube: api a swap of a surface that is not current is EGL_BAD_SURFACE\n");

	/* A child of fork has no window: its swap is EGL_BAD_SURFACE. */
	pid_t pid = fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		EGLBoolean swapped = eglSwapBuffers(display, surface);
		EGLint error = eglGetError();
		_exit(swapped == EGL_FALSE && error == EGL_BAD_SURFACE ? 0 : 3);
	}
	int status = 0;
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	printf("gles-cube: api a swap in a forked child is EGL_BAD_SURFACE\n");

	/* Two threads, two contexts. */
	struct other_thread other = {display, config, 99};
	pthread_t thread;
	pthread_attr_t attr;
	CHECK(pthread_attr_init(&attr) == 0);
	CHECK(pthread_attr_setstacksize(&attr, 512 * 1024) == 0);
	CHECK(pthread_create(&thread, &attr, other_thread_main, &other) == 0);
	CHECK(pthread_join(thread, NULL) == 0);
	CHECK(other.result == 0);
	CHECK(eglGetCurrentContext() == context);
	printf("gles-cube: api a second thread made its own pbuffer and context and drew\n");

	/* The window surface in another thread: not while this one holds it. */
	struct surface_thread moved = {display, config, surface, 0, 99};
	CHECK(pthread_create(&thread, &attr, surface_thread_main, &moved) == 0);
	CHECK(pthread_join(thread, NULL) == 0);
	CHECK(moved.result == 0);
	/* ... and after this one let it go, the other draws and swaps, and this one takes it back. */
	CHECK(eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT) == EGL_TRUE);
	moved.step = 1;
	moved.result = 99;
	CHECK(pthread_create(&thread, &attr, surface_thread_main, &moved) == 0);
	CHECK(pthread_join(thread, NULL) == 0);
	CHECK(moved.result == 0);
	CHECK(eglMakeCurrent(display, surface, surface, context) == EGL_TRUE);
	glClearColor(0.6f, 0.4f, 0.2f, 1.0f);
	glClear(GL_COLOR_BUFFER_BIT);
	CHECK(eglSwapBuffers(display, surface) == EGL_TRUE);
	printf("gles-cube: api a surface current in one thread is EGL_BAD_ACCESS in another and moves between threads\n");

	/* A thread asleep in stafeto_window_wait gets its own bits while this one swaps. */
	struct waiter waiter = {0, 0, 0, 99};
	CHECK(pthread_create(&thread, &attr, waiter_main, &waiter) == 0);
	struct timespec asleep = {0, 200000000};
	nanosleep(&asleep, NULL);
	for (int i = 0; i < 6; i++) {
		CHECK(eglSwapInterval(display, i % 2 ? 0 : 1) == EGL_TRUE);
		glClearColor(0.1f * (float)i, 0.2f, 0.3f, 1.0f);
		glClear(GL_COLOR_BUFFER_BIT);
		CHECK(eglSwapBuffers(display, surface) == EGL_TRUE);
	}
	/* One swap more, after the stop is set, ends the wait with the bits it makes. */
	__atomic_store_n(&waiter.stop, 1, __ATOMIC_SEQ_CST);
	CHECK(eglSwapInterval(display, 1) == EGL_TRUE);
	CHECK(eglSwapBuffers(display, surface) == EGL_TRUE);
	CHECK(pthread_join(thread, NULL) == 0);
	CHECK(waiter.result == 0);
	CHECK(waiter.wakeups >= 1);
	CHECK(waiter.seen & (STAFETO_WINDOW_BUFFER(0) | STAFETO_WINDOW_BUFFER(1) | STAFETO_WINDOW_BUFFER(2)));
	/* The events the window has were not eaten by the swaps: their bit reached the thread. */
	struct stafeto_window_event events[STAFETO_WINDOW_EVENTS_MAX];
	int count = stafeto_window_events(window_number, events, STAFETO_WINDOW_EVENTS_MAX, NULL);
	CHECK(count >= 0);
	CHECK(count == 0 || (waiter.seen & STAFETO_WINDOW_EVENTS));
	printf("gles-cube: api a thread asleep in stafeto_window_wait got the bits of the swaps and the events bit stayed for it\n");
	CHECK(pthread_attr_destroy(&attr) == 0);
}

static uint32_t crc_byte(uint32_t crc, uint8_t b)
{
	return crc_table[(crc ^ b) & 0xFF] ^ (crc >> 8);
}

/* The CRC-32 of the screen with the window's buffer `shown` over black, as
 * the host takes it from a screenshot: R, G, B of each point, by rows. */
static uint32_t screen_crc(unsigned shown)
{
	uint32_t crc = 0xFFFFFFFFu;
	const int x0 = (SCREEN_W - (int)window_shape.width) / 2;
	const int y0 = (SCREEN_H - (int)window_shape.height) / 2;
	for (int y = 0; y < SCREEN_H; y++) {
		for (int x = 0; x < SCREEN_W; x++) {
			uint32_t p = 0;
			if (x >= x0 && x < x0 + (int)window_shape.width && y >= y0 &&
			    y < y0 + (int)window_shape.height) {
				const uint8_t *row = (const uint8_t *)window_shape.pixels[shown] +
						     (size_t)(y - y0) * window_shape.stride;
				p = ((const uint32_t *)row)[x - x0];
			}
			crc = crc_byte(crc, (uint8_t)(p >> 16));
			crc = crc_byte(crc, (uint8_t)(p >> 8));
			crc = crc_byte(crc, (uint8_t)p);
		}
	}
	return ~crc;
}

/* The buffer the service shows once the last post is on the screen: the only
 * one the library does not count free. */
static unsigned shown_buffer(void)
{
	uint32_t bits = 0;
	CHECK(stafeto_window_shown(window_number, 120 * SECOND) == 0);
	/* The bits that came since the last wait free the replaced buffers. */
	if (stafeto_window_wait(window_number, 0, &bits) != 0)
		CHECK(errno == ETIMEDOUT);
	uint32_t free = stafeto_window_free_buffers(window_number);
	uint32_t all = (1u << window_shape.buffers) - 1;
	uint32_t held = all & ~free;
	CHECK(held != 0 && (held & (held - 1)) == 0);
	for (unsigned k = 0; k < window_shape.buffers; k++)
		if (held == (1u << k))
			return k;
	CHECK(0);
	return 0;
}

/* Swaps the frame just drawn (the interval alternates 1 and 0). At the third
 * frame the window must hold the rows of `pixels`, the frame read back before
 * the swap, mirrored (glReadPixels gives rows from the bottom, the window has
 * them from the top), and the frame must not be its own mirror, so that the
 * check can tell the two orders apart. At the third and the last frame it
 * prints the CRC of the screen after a pause for QEMU's screenshot. */
static void window_present(EGLDisplay display, EGLSurface surface, int frame, int frames,
			   const uint8_t *pixels, int size)
{
	struct timespec pause = {2, 500000000};
	long long started = now_ms();
	CHECK(eglSwapInterval(display, frame % 2 ? 0 : 1) == EGL_TRUE);
	CHECK(eglSwapBuffers(display, surface) == EGL_TRUE);
	printf("gles-cube: time swap %d (interval %d) %lld ms\n", frame, frame % 2 ? 0 : 1,
	       now_ms() - started);
	if (frame == frames / 3 || frame == frames - 1) {
		unsigned shown = shown_buffer();
		if (frame == frames / 3) {
			CHECK(swap_window_matches_readback((const unsigned char *)window_shape.pixels[shown],
							   window_shape.stride, pixels, size, size));
			CHECK(!swap_readback_is_symmetric(pixels, size, size));
			printf("gles-cube: api the window shows the rows of the frame read back from the bottom up, and the frame is no mirror of itself\n");
		}
		printf("gles-cube: %s crc %08x\n", frame == frames - 1 ? "last" : "window",
		       (unsigned)screen_crc(shown));
		fflush(stdout);
		nanosleep(&pause, NULL);
	}
}

/* Four frames each of which clears a rectangle under the scissor test and is
 * swapped with eglSwapBuffersWithDamageKHR over that rectangle: the buffer of
 * the window the swap takes lacks what the swaps since its last fill changed,
 * and after each swap the whole window must equal the frame read back. */
static void window_damage_swaps(EGLDisplay display, EGLSurface surface, uint8_t *pixels, int size)
{
	static const float COLOURS[4][3] = {{1, 0, 1}, {0, 1, 1}, {1, 1, 0}, {1, 0.5f, 0}};
	const char *extensions = eglQueryString(display, EGL_EXTENSIONS);
	CHECK(extensions != NULL && strstr(extensions, "EGL_KHR_swap_buffers_with_damage") != NULL);
	PFNEGLSWAPBUFFERSWITHDAMAGEKHRPROC swap_with_damage =
		(PFNEGLSWAPBUFFERSWITHDAMAGEKHRPROC)eglGetProcAddress("eglSwapBuffersWithDamageKHR");
	CHECK(swap_with_damage != NULL);
	for (int i = 0; i < 4; i++) {
		/* In the surface's coordinates: from the lower left. */
		EGLint rect[4] = {size / 8 + i * size / 8, size / 4 + (i % 2) * size / 4, size / 4, size / 8};
		glEnable(GL_SCISSOR_TEST);
		glScissor(rect[0], rect[1], rect[2], rect[3]);
		glClearColor(COLOURS[i][0], COLOURS[i][1], COLOURS[i][2], 1.0f);
		glClear(GL_COLOR_BUFFER_BIT);
		glDisable(GL_SCISSOR_TEST);
		memset(pixels, 0xA5, (size_t)size * size * 4);
		glReadPixels(0, 0, size, size, GL_RGBA, GL_UNSIGNED_BYTE, pixels);
		CHECK(glGetError() == GL_NO_ERROR);
		CHECK(swap_with_damage(display, surface, rect, 1) == EGL_TRUE);
		unsigned shown = shown_buffer();
		CHECK(swap_window_matches_readback((const unsigned char *)window_shape.pixels[shown],
						   window_shape.stride, pixels, size, size));
	}
	printf("gles-cube: api four swaps with damage over a cleared rectangle left the window equal to the frame\n");
}

/* The end of the window mode: eglTerminate with the surface and the context
 * still current marks them for deletion; a swap then finds the display not
 * initialized, and eglReleaseThread lets go of them. The window outlives its
 * surface: it is closed after, or, with --hold, kept for the holder of a scene. */
static void window_terminate(EGLDisplay display, EGLSurface surface, int hold_fd)
{
	CHECK(eglTerminate(display) == EGL_TRUE);
	CHECK(eglSwapBuffers(display, surface) == EGL_FALSE);
	CHECK_ERROR(EGL_NOT_INITIALIZED);
	CHECK(eglReleaseThread() == EGL_TRUE);
	printf("gles-cube: api eglTerminate with the surface current, a swap after it is EGL_NOT_INITIALIZED and eglReleaseThread lets go\n");
	if (hold_fd >= 0) {
		/* The window stays as the last swap left it: its CRC, the byte for the
		 * holder of the scene, and a sleep until the holder kills the program. */
		printf("gles-cube: held crc %08x\n", (unsigned)screen_crc(shown_buffer()));
		fflush(stdout);
		char byte = 'h';
		CHECK(write(hold_fd, &byte, 1) == 1);
		for (;;) {
			struct timespec forever = {3600, 0};
			nanosleep(&forever, NULL);
		}
	}
	CHECK(stafeto_window_close(window_number) == 0);
	window_number = -1;
}

