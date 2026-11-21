/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The scene demo of stafeto, a C program on OpenWF Composition 1.0
 * (<WF/wfc.h>, the library libWFC of the static feature `wfc`).
 *
 * Started by init with the scene's session of the composition service, the
 * program starts two producers (/bin/wfc-producer a and b), each a window with
 * a fixed pattern, makes a window of A8 for a mask and draws a disc in it, and
 * finds the numbers of the three windows with wfcNextStreamSTAFETO. It makes a
 * source of each pattern and the mask, and three elements it sets to the two
 * scenes in turn, A and B, which differ in places, quarter turns, the filter
 * (none and the faster one), the kind of transparency (a global alpha, a mask,
 * both) and the background. The elements keep to what the service's prices make
 * cheap: a stretch, a flip or the bilinear filter make every band of a frame a
 * few points wide, and a frame takes seconds (see docs/openwf.md). With --probe it checks the API,
 * commits the scenes 100 times in turn, each composed on request (the context
 * is inactive) and its number printed, and then activates the context and
 * changes the scene 100 times without waiting. The host (tools/wfc-ref)
 * draws both scenes point by point from the same calls and `cargo xtask
 * wfc-probe` compares QEMU's screenshots with its CRCs. --quick leaves out the
 * pauses the host takes its screenshots in. Without --probe the demo shows
 * the scenes in turn for ever.
 *
 * The scenes' numbers are the ones of tools/wfc-ref/src/lib.rs. Built with
 * -fno-builtin; every result is compared.
 */

#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <WF/wfc.h>
#include <WF/wfcext_stafeto.h>
#include <stafeto/window.h>

extern char **environ;

#define CHECK(cond)                                                                    \
    do {                                                                               \
        if (!(cond)) {                                                                 \
            printf("wfc-demo: check failed at line %d: %s (errno %d, error %x)\n",     \
                   __LINE__, #cond, errno, (unsigned)last_error());                    \
            return 20;                                                                 \
        }                                                                              \
    } while (0)

#define COMMITS 100
#define CHANGES 100

static WFCDevice dev;
static WFCContext ctx;
static int quick;

static WFCErrorCode last_error(void) { return dev ? wfcGetError(dev) : WFC_ERROR_NONE; }

static void pause_ns(long ns) {
    struct timespec t = {ns / 1000000000L, ns % 1000000000L};
    nanosleep(&t, NULL);
}

/* The pause the host takes its screenshot in. */
static void snapshot_pause(void) {
    if (!quick) pause_ns(400000000L);
}

/* The mask's byte at (x, y): a disc with a half ring (mask of wfc-ref). */
static uint32_t mask_value(int x, int y) {
    int dx = x - 80, dy = y - 50, d2 = dx * dx + dy * dy;
    if (d2 <= 40 * 40) return 255;
    if (d2 <= 50 * 50) return 128;
    return 0;
}

/* One element as a scene sets it (SCENES of tools/wfc-ref). */
struct spec {
    int window;           /* 0 the first pattern, 1 the second */
    float src[4];
    WFCint rotation;
    int flip;
    WFCint filter;
    WFCint transparency;
    WFCint alpha;
    int mask;
    WFCint dst[4];
};

static const struct spec scene_a[3] = {
    {0, {0, 0, 100, 200}, WFC_ROTATION_90, 0, WFC_SCALE_FILTER_NONE, 0, 255, 0, {20, 20, 200, 100}},
    {1, {0, 0, 160, 100}, WFC_ROTATION_0, 0, WFC_SCALE_FILTER_FASTER,
     WFC_TRANSPARENCY_ELEMENT_GLOBAL_ALPHA | WFC_TRANSPARENCY_MASK, 200, 1, {300, 150, 160, 100}},
    {0, {10, 20, 60, 120}, WFC_ROTATION_0, 0, WFC_SCALE_FILTER_NONE,
     WFC_TRANSPARENCY_ELEMENT_GLOBAL_ALPHA, 128, 0, {40, 230, 60, 120}},
};

static const struct spec scene_b[3] = {
    {0, {20, 30, 60, 120}, WFC_ROTATION_90, 0, WFC_SCALE_FILTER_NONE, 0, 255, 0, {200, 40, 120, 60}},
    {1, {0, 0, 160, 100}, WFC_ROTATION_0, 0, WFC_SCALE_FILTER_NONE, WFC_TRANSPARENCY_MASK, 255, 1,
     {20, 200, 160, 100}},
    {0, {0, 0, 100, 200}, WFC_ROTATION_0, 0, WFC_SCALE_FILTER_NONE,
     WFC_TRANSPARENCY_ELEMENT_GLOBAL_ALPHA, 255, 0, {460, 150, 100, 200}},
};

#define BG_A 0x203040FF
#define BG_B 0x402010FF

static WFCNativeStreamType id_a, id_b, id_m;
static WFCSource source[2];
static WFCMask mask;
static WFCElement element[3];
static pid_t pid_a, pid_b;

static void apply(int k) {
    const struct spec *scene = (k % 2 == 0) ? scene_a : scene_b;
    wfcSetContextAttribi(dev, ctx, WFC_CONTEXT_BG_COLOR, (WFCint)((k % 2 == 0) ? BG_A : BG_B));
    for (int i = 0; i < 3; i++) {
        const struct spec *s = &scene[i];
        wfcSetElementAttribi(dev, element[i], WFC_ELEMENT_SOURCE, (WFCint)source[s->window]);
        wfcSetElementAttribfv(dev, element[i], WFC_ELEMENT_SOURCE_RECTANGLE, 4, s->src);
        wfcSetElementAttribiv(dev, element[i], WFC_ELEMENT_DESTINATION_RECTANGLE, 4, s->dst);
        wfcSetElementAttribi(dev, element[i], WFC_ELEMENT_SOURCE_ROTATION, s->rotation);
        wfcSetElementAttribi(dev, element[i], WFC_ELEMENT_SOURCE_FLIP, s->flip);
        wfcSetElementAttribi(dev, element[i], WFC_ELEMENT_SOURCE_SCALE_FILTER, s->filter);
        wfcSetElementAttribi(dev, element[i], WFC_ELEMENT_TRANSPARENCY_TYPES, s->transparency);
        wfcSetElementAttribi(dev, element[i], WFC_ELEMENT_GLOBAL_ALPHA, s->alpha);
        wfcSetElementAttribi(dev, element[i], WFC_ELEMENT_MASK, s->mask ? (WFCint)mask : 0);
    }
}

/* The calls that a device that is not there, and arguments that are none,
 * refuse in the ways the specification says. */
static int before_the_device(void) {
    WFCint ids[2] = {0, 0};
    CHECK(wfcGetError(7) == WFC_ERROR_BAD_DEVICE);
    CHECK(wfcEnumerateDevices(NULL, 0, NULL) == 1);
    CHECK(wfcEnumerateDevices(ids, 2, NULL) == 1 && ids[0] != WFC_DEFAULT_DEVICE_ID);
    WFCint on_screen[] = {WFC_DEVICE_FILTER_SCREEN_NUMBER, 0, WFC_NONE};
    CHECK(wfcEnumerateDevices(NULL, 0, on_screen) == 1);
    on_screen[1] = 3;
    CHECK(wfcEnumerateDevices(NULL, 0, on_screen) == 0);
    CHECK(wfcCreateDevice(55, NULL) == WFC_INVALID_HANDLE);
    WFCint bad_attribs[] = {1, 1, WFC_NONE};
    CHECK(wfcCreateDevice(WFC_DEFAULT_DEVICE_ID, bad_attribs) == WFC_INVALID_HANDLE);
    CHECK(wfcCreateOnScreenContext(7, 0, NULL) == WFC_INVALID_HANDLE);
    CHECK(wfcGetDeviceAttribi(7, WFC_DEVICE_ID) == 0);
    printf("wfc-demo: the calls before a device are refused as the specification says\n");
    return 0;
}

static int describe_device(void) {
    const char *list[4];
    WFCDevice second;
    dev = wfcCreateDevice(WFC_DEFAULT_DEVICE_ID, NULL);
    CHECK(dev != WFC_INVALID_HANDLE);
    CHECK(wfcGetError(dev) == WFC_ERROR_NONE);
    CHECK(wfcGetDeviceAttribi(dev, WFC_DEVICE_ID) == 1);
    CHECK(wfcGetDeviceAttribi(dev, WFC_DEVICE_CLASS) == WFC_DEVICE_CLASS_FULLY_CAPABLE);
    CHECK(wfcGetDeviceAttribi(dev, 0x9999) == 0);
    CHECK(wfcGetError(dev) == WFC_ERROR_BAD_ATTRIBUTE);
    CHECK(wfcGetError(dev) == WFC_ERROR_NONE);
    CHECK(wfcGetStrings(dev, WFC_VENDOR, NULL, 0) == 1);
    CHECK(wfcGetStrings(dev, WFC_VENDOR, list, 4) == 1 && strcmp(list[0], "stafeto") == 0);
    CHECK(wfcGetStrings(dev, WFC_VERSION, list, 4) == 1 && strcmp(list[0], "1.0") == 0);
    CHECK(wfcGetStrings(dev, 0x1, list, 4) == 0);
    CHECK(wfcGetError(dev) == WFC_ERROR_ILLEGAL_ARGUMENT);
    CHECK(wfcIsExtensionSupported(dev, "WFC_STAFETO_stream") == WFC_TRUE);
    CHECK(wfcIsExtensionSupported(dev, "WFC_EXT_other") == WFC_FALSE);
    /* A second device has a state of its own (specification 4.3). */
    second = wfcCreateDevice(WFC_DEFAULT_DEVICE_ID, NULL);
    CHECK(second != WFC_INVALID_HANDLE && second != dev);
    CHECK(wfcGetError(second) == WFC_ERROR_NONE);
    CHECK(wfcDestroyDevice(second) == WFC_ERROR_NONE);
    CHECK(wfcGetError(second) == WFC_ERROR_BAD_DEVICE);
    CHECK(wfcGetError(dev) == WFC_ERROR_NONE);
    printf("wfc-demo: the device is made, described, and a second one has its own state\n");
    return 0;
}

static int context_checks(void) {
    WFCfloat bg[4] = {9, 9, 9, 9};
    WFCDevice second;
    ctx = wfcCreateOnScreenContext(dev, WFC_DEFAULT_SCREEN_NUMBER, NULL);
    CHECK(ctx != WFC_INVALID_HANDLE);
    CHECK(wfcCreateOnScreenContext(dev, WFC_DEFAULT_SCREEN_NUMBER, NULL) == WFC_INVALID_HANDLE);
    CHECK(wfcGetError(dev) == WFC_ERROR_IN_USE);
    second = wfcCreateDevice(WFC_DEFAULT_DEVICE_ID, NULL);
    CHECK(second != WFC_INVALID_HANDLE);
    CHECK(wfcCreateOnScreenContext(second, 0, NULL) == WFC_INVALID_HANDLE);
    CHECK(wfcGetError(second) == WFC_ERROR_IN_USE);
    CHECK(wfcCreateOffScreenContext(dev, 1, NULL) == WFC_INVALID_HANDLE);
    CHECK(wfcGetError(dev) == WFC_ERROR_UNSUPPORTED);
    CHECK(wfcDestroyDevice(second) == WFC_ERROR_NONE);
    CHECK(wfcGetContextAttribi(dev, ctx, WFC_CONTEXT_TYPE) == WFC_CONTEXT_TYPE_ON_SCREEN);
    CHECK(wfcGetContextAttribi(dev, ctx, WFC_CONTEXT_TARGET_WIDTH) == 640);
    CHECK(wfcGetContextAttribi(dev, ctx, WFC_CONTEXT_TARGET_HEIGHT) == 400);
    CHECK(wfcGetContextAttribi(dev, ctx, WFC_CONTEXT_ROTATION) == WFC_ROTATION_0);
    CHECK(wfcGetContextAttribi(dev, ctx, WFC_CONTEXT_LOWEST_ELEMENT) == 0);
    wfcGetContextAttribfv(dev, ctx, WFC_CONTEXT_BG_COLOR, 4, bg);
    CHECK(bg[0] == 0 && bg[1] == 0 && bg[2] == 0 && bg[3] == 1);
    wfcSetContextAttribi(dev, ctx, WFC_CONTEXT_TYPE, 1);
    CHECK(wfcGetError(dev) == WFC_ERROR_BAD_ATTRIBUTE);
    wfcSetContextAttribi(dev, ctx, WFC_CONTEXT_ROTATION, 90);
    CHECK(wfcGetError(dev) == WFC_ERROR_ILLEGAL_ARGUMENT);
    wfcSetContextAttribi(dev, ctx, WFC_CONTEXT_BG_COLOR, 0x10203040);
    CHECK(wfcGetError(dev) == WFC_ERROR_ILLEGAL_ARGUMENT);
    wfcGetContextAttribi(dev, 77, WFC_CONTEXT_TYPE);
    CHECK(wfcGetError(dev) == WFC_ERROR_BAD_HANDLE);
    printf("wfc-demo: the context is made, a second one is in use, its attributes are as the specification says\n");
    return 0;
}

static pid_t start_producer(const char *role) {
    char *argv[] = {"wfc-producer", (char *)role, NULL};
    pid_t pid = 0;
    if (posix_spawn(&pid, "/bin/wfc-producer", NULL, NULL, argv, environ) != 0) return -1;
    return pid;
}

static int next_stream(WFCNativeStreamType *out) {
    WFCint got = wfcNextStreamSTAFETO(dev, 30000, out);
    return got == 1 ? 0 : 1;
}

/* The producers' windows and the mask's window, found by their numbers. */
static int streams_and_sources(void) {
    struct stafeto_window w;
    WFCNativeStreamType nothing = 0;
    CHECK(wfcNextStreamSTAFETO(dev, 0, &nothing) == 0);
    CHECK(wfcNextStreamSTAFETO(dev, 0, NULL) == -1);
    CHECK(wfcGetError(dev) == WFC_ERROR_ILLEGAL_ARGUMENT);
    pid_a = start_producer("a");
    CHECK(pid_a > 0);
    CHECK(next_stream(&id_a) == 0);
    pid_b = start_producer("b");
    CHECK(pid_b > 0);
    CHECK(next_stream(&id_b) == 0);
    CHECK(stafeto_window_open(0, 0, 160, 100, STAFETO_WINDOW_A8, 1, 0, &w) == 0);
    CHECK(w.width == 160 && w.height == 100 && w.pixels[0] != NULL);
    for (int y = 0; y < 100; y++) {
        uint8_t *row = (uint8_t *)w.pixels[0] + (size_t)y * w.stride;
        for (int x = 0; x < 160; x++) row[x] = (uint8_t)mask_value(x, y);
    }
    {
        struct stafeto_rect whole = {0, 0, 160, 100};
        CHECK(stafeto_window_post(0, 0, &whole, 1) == 0);
    }
    CHECK(next_stream(&id_m) == 0);
    CHECK(id_a != id_b && id_a != id_m && id_b != id_m);
    /* The producers drew before the demo goes on. */
    pause_ns(700000000L);
    source[0] = wfcCreateSourceFromStream(dev, ctx, id_a, NULL);
    CHECK(source[0] != WFC_INVALID_HANDLE);
    source[1] = wfcCreateSourceFromStream(dev, ctx, id_b, NULL);
    CHECK(source[1] != WFC_INVALID_HANDLE && source[1] != source[0]);
    mask = wfcCreateMaskFromStream(dev, ctx, id_m, NULL);
    CHECK(mask != WFC_INVALID_HANDLE);
    CHECK(wfcCreateSourceFromStream(dev, ctx, id_a + 1000, NULL) == WFC_INVALID_HANDLE);
    CHECK(wfcGetError(dev) == WFC_ERROR_ILLEGAL_ARGUMENT);
    printf("wfc-demo: the windows of the producers and of the mask are found by wfcNextStreamSTAFETO, the sources and the mask are made\n");
    return 0;
}

static int elements_and_order(void) {
    WFCint rect[4] = {0, 0, 0, 0};
    WFCfloat src[4] = {1, 1, 1, 1};
    for (int i = 0; i < 3; i++) {
        element[i] = wfcCreateElement(dev, ctx, NULL);
        CHECK(element[i] != WFC_INVALID_HANDLE);
    }
    /* The defaults of an element (specification 7.1, table 4). */
    wfcGetElementAttribiv(dev, element[0], WFC_ELEMENT_DESTINATION_RECTANGLE, 4, rect);
    CHECK(rect[0] == 0 && rect[1] == 0 && rect[2] == 0 && rect[3] == 0);
    wfcGetElementAttribfv(dev, element[0], WFC_ELEMENT_SOURCE_RECTANGLE, 4, src);
    CHECK(src[0] == 0 && src[1] == 0 && src[2] == 0 && src[3] == 0);
    CHECK(wfcGetElementAttribi(dev, element[0], WFC_ELEMENT_SOURCE) == 0);
    CHECK(wfcGetElementAttribi(dev, element[0], WFC_ELEMENT_SOURCE_ROTATION) == WFC_ROTATION_0);
    CHECK(wfcGetElementAttribi(dev, element[0], WFC_ELEMENT_SOURCE_SCALE_FILTER) == WFC_SCALE_FILTER_NONE);
    CHECK(wfcGetElementAttribf(dev, element[0], WFC_ELEMENT_GLOBAL_ALPHA) == 1.0f);
    /* The refusals. */
    wfcSetElementAttribi(dev, element[0], WFC_ELEMENT_DESTINATION_RECTANGLE, 1);
    CHECK(wfcGetError(dev) == WFC_ERROR_BAD_ATTRIBUTE);
    wfcSetElementAttribi(dev, element[0], WFC_ELEMENT_TRANSPARENCY_TYPES, 6);
    CHECK(wfcGetError(dev) == WFC_ERROR_ILLEGAL_ARGUMENT);
    wfcSetElementAttribi(dev, element[0], WFC_ELEMENT_SOURCE, (WFCint)mask);
    CHECK(wfcGetError(dev) == WFC_ERROR_ILLEGAL_ARGUMENT);
    rect[2] = -1;
    wfcSetElementAttribiv(dev, element[0], WFC_ELEMENT_DESTINATION_RECTANGLE, 4, rect);
    CHECK(wfcGetError(dev) == WFC_ERROR_ILLEGAL_ARGUMENT);
    wfcSetElementAttribi(dev, 9999, WFC_ELEMENT_SOURCE_FLIP, 1);
    CHECK(wfcGetError(dev) == WFC_ERROR_BAD_HANDLE);
    /* The order: each element above the one before it. */
    wfcInsertElement(dev, element[0], WFC_INVALID_HANDLE);
    wfcInsertElement(dev, element[1], element[0]);
    wfcInsertElement(dev, element[2], element[1]);
    CHECK(wfcGetError(dev) == WFC_ERROR_NONE);
    CHECK(wfcGetContextAttribi(dev, ctx, WFC_CONTEXT_LOWEST_ELEMENT) == (WFCint)element[0]);
    CHECK(wfcGetElementAbove(dev, element[0]) == element[1]);
    CHECK(wfcGetElementAbove(dev, element[2]) == WFC_INVALID_HANDLE);
    CHECK(wfcGetElementBelow(dev, element[2]) == element[1]);
    CHECK(wfcGetElementBelow(dev, element[0]) == WFC_INVALID_HANDLE);
    CHECK(wfcGetError(dev) == WFC_ERROR_NONE);
    wfcInsertElement(dev, element[0], 9999);
    CHECK(wfcGetError(dev) == WFC_ERROR_BAD_HANDLE);
    printf("wfc-demo: the elements are made, ordered and refused as the specification says\n");
    return 0;
}

/* A spawned child holds no scene: its session is a clone with no mark, so it
 * makes no device. */
static int child_has_no_device(void) {
    char *argv[] = {"wfc-demo", "child", NULL};
    pid_t pid = 0;
    int status = 0;
    int rc = posix_spawn(&pid, "/bin/wfc-demo", NULL, NULL, argv, environ);
    if (rc != 0) printf("wfc-demo: posix_spawn of the child gave %d\n", rc);
    CHECK(rc == 0);
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    printf("wfc-demo: a spawned child has no device\n");
    return 0;
}

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

static int commits(int count) {
    for (int k = 0; count < 0 || k < count; k++) {
        long t0 = now_ms();
        apply(k);
        CHECK(wfcGetError(dev) == WFC_ERROR_NONE);
        long t1 = now_ms();
        wfcCommit(dev, ctx, WFC_TRUE);
        CHECK(wfcGetError(dev) == WFC_ERROR_NONE);
        long t2 = now_ms();
        wfcCompose(dev, ctx, WFC_TRUE);
        CHECK(wfcGetError(dev) == WFC_ERROR_NONE);
        long t3 = now_ms();
        if (k < 4)
            printf("wfc-demo: took, milliseconds: set %ld, commit %ld, compose %ld\n", t1 - t0,
                   t2 - t1, t3 - t2);
        if (count >= 0) {
            printf("wfc-demo: commit %d scene %c\n", k, (k % 2 == 0) ? 'A' : 'B');
            fflush(stdout);
            snapshot_pause();
        } else {
            pause_ns(1000000000L);
        }
    }
    printf("wfc-demo: %d commits of scenes A and B, each composed on request\n", count);
    return 0;
}

/* The active context composes by itself: the scene changes with no wait, the
 * host takes screenshots of it meanwhile, each one of the two scenes. */
static int changes(int count) {
    wfcActivate(dev, ctx);
    CHECK(wfcGetError(dev) == WFC_ERROR_NONE);
    wfcCompose(dev, ctx, WFC_TRUE);
    CHECK(wfcGetError(dev) == WFC_ERROR_UNSUPPORTED);
    printf("wfc-demo: auto begin\n");
    fflush(stdout);
    pause_ns(quick ? 0L : 100000000L);
    for (int k = 0; k < count; k++) {
        apply(k + 1);
        CHECK(wfcGetError(dev) == WFC_ERROR_NONE);
        wfcCommit(dev, ctx, WFC_FALSE);
        CHECK(wfcGetError(dev) == WFC_ERROR_NONE);
        pause_ns(quick ? 0L : 40000000L);
    }
    pause_ns(quick ? 0L : 100000000L);
    printf("wfc-demo: auto end\n");
    fflush(stdout);
    wfcDeactivate(dev, ctx);
    CHECK(wfcGetError(dev) == WFC_ERROR_NONE);
    printf("wfc-demo: %d scene changes of the active context\n", count);
    return 0;
}

static int finish(void) {
    int status = 0;
    kill(pid_a, SIGKILL);
    kill(pid_b, SIGKILL);
    waitpid(pid_a, &status, 0);
    waitpid(pid_b, &status, 0);
    wfcDestroyElement(dev, element[0]);
    CHECK(wfcGetError(dev) == WFC_ERROR_NONE);
    wfcDestroyElement(dev, element[0]);
    CHECK(wfcGetError(dev) == WFC_ERROR_BAD_HANDLE);
    wfcDestroySource(dev, source[0]);
    wfcDestroyMask(dev, mask);
    CHECK(wfcGetError(dev) == WFC_ERROR_NONE);
    wfcDestroyContext(dev, ctx);
    CHECK(wfcGetError(dev) == WFC_ERROR_NONE);
    wfcCommit(dev, ctx, WFC_FALSE);
    CHECK(wfcGetError(dev) == WFC_ERROR_BAD_HANDLE);
    CHECK(wfcDestroyDevice(dev) == WFC_ERROR_NONE);
    CHECK(wfcGetError(dev) == WFC_ERROR_BAD_DEVICE);
    CHECK(wfcDestroyDevice(dev) == WFC_ERROR_BAD_DEVICE);
    CHECK(stafeto_window_close(0) == 0);
    printf("wfc-demo: the device is destroyed and its handles are gone\n");
    return 0;
}

static int run_scene(int probe) {
    CHECK(before_the_device() == 0);
    CHECK(describe_device() == 0);
    CHECK(context_checks() == 0);
    CHECK(streams_and_sources() == 0);
    CHECK(elements_and_order() == 0);
    if (probe) CHECK(child_has_no_device() == 0);
    if (!probe) return commits(-1);
    CHECK(commits(COMMITS) == 0);
    CHECK(changes(CHANGES) == 0);
    CHECK(finish() == 0);
    return 0;
}

int main(int argc, char **argv) {
    int probe = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--probe") == 0) probe = 1;
        else if (strcmp(argv[i], "--quick") == 0) quick = 1;
        else if (strcmp(argv[i], "child") == 0) {
            /* The session of a spawned child is a clone with no scene mark. */
            return wfcCreateDevice(WFC_DEFAULT_DEVICE_ID, NULL) == WFC_INVALID_HANDLE ? 0 : 21;
        }
    }
    int status = run_scene(probe);
    if (status == 0 && probe) printf("wfc-demo: ok\n");
    return status;
}
