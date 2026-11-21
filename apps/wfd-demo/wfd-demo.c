/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The display demo of stafeto, a C program on OpenWF Display 1.0
 * (<WF/wfd.h>, the library libdisplay of the static feature `wfd`).
 *
 * It takes the screen through the display driver (no composition service in
 * the image), draws pictures in the two buffers of the screen the driver
 * gives, the compositing target and the pool buffer, and binds them to the
 * primary pipeline in turn, each time to the one the screen does not show.
 * A picture of a cursor lies in the third source, bound to the cursor
 * pipeline, which moves without a frame. Without arguments the demo goes on
 * for ever (an animation to watch in the window of QEMU); with --probe it
 * checks the API and does 100 frames and 100 moves of the cursor, and prints
 * the CRC-32 of each frame's points (R, G, B, row after row) for the host to
 * compare with its own and with QEMU's screenshot. --quick leaves out the
 * pauses the host takes its screenshots in.
 *
 * Started by init, the program starts its own file once (/bin/wfd-demo run
 * ...), the copy that can fork. Built with -fno-builtin; every result is
 * compared.
 */

#include <errno.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <WF/wfd.h>
#include <WF/wfdext_stafeto.h>

extern char **environ;

#define CHECK(cond)                                                                    \
    do {                                                                               \
        if (!(cond)) {                                                                 \
            printf("wfd-demo: check failed at line %d: %s (errno %d, error %x)\n",     \
                   __LINE__, #cond, errno, (unsigned)last_error());                    \
            return 20;                                                                 \
        }                                                                              \
    } while (0)

#define SCREEN_W 640
#define SCREEN_H 400
#define CURSOR 64
#define FRAMES 100
#define MOVES 100
#define SECOND 1000000000ull
#define WITHIN (20 * SECOND)

/* The bar that grows with the frame's number: 6 points for each. */
#define BAR_Y 8
#define BAR_H 16

static WFDDevice dev;
static int quick;

static WFDErrorCode last_error(void) { return dev ? wfdGetError(dev) : WFD_ERROR_NONE; }

static uint32_t crc_table[256];

static void crc_init(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
        crc_table[i] = c;
    }
}

static uint32_t crc_byte(uint32_t crc, uint8_t b) { return crc_table[(crc ^ b) & 0xFF] ^ (crc >> 8); }

/* The picture of frame k: a gradient that moves with k and a bar. The host
 * has the same function (xtask/src/wfd.rs). */
static uint32_t pattern(int k, int x, int y) {
    if (y >= BAR_Y && y < BAR_Y + BAR_H && x < (k + 1) * 6) return 0x00FFFFFFu;
    uint32_t r = (uint32_t)((x * 255 / (SCREEN_W - 1) + 3 * k) & 0xFF);
    uint32_t g = (uint32_t)((y * 255 / (SCREEN_H - 1) + 5 * k) & 0xFF);
    uint32_t b = (uint32_t)(((x ^ y) + k) & 0xFF);
    return r << 16 | g << 8 | b;
}

/* Draws frame k in the stream and gives the CRC-32 of its points. */
static uint32_t draw(const struct stafeto_wfd_stream *s, int k) {
    uint32_t crc = 0xFFFFFFFFu;
    for (int y = 0; y < SCREEN_H; y++) {
        uint32_t *row = (uint32_t *)((char *)s->pixels + (size_t)y * s->stride);
        for (int x = 0; x < SCREEN_W; x++) {
            uint32_t p = pattern(k, x, y);
            row[x] = p;
            crc = crc_byte(crc, (uint8_t)(p >> 16));
            crc = crc_byte(crc, (uint8_t)(p >> 8));
            crc = crc_byte(crc, (uint8_t)p);
        }
    }
    return ~crc;
}

/* The cursor picture: a disc of orange at three quarters of opacity inside a
 * white ring, points multiplied by their alpha (0xAARRGGBB). */
static void draw_cursor(const struct stafeto_wfd_stream *s) {
    for (int y = 0; y < CURSOR; y++) {
        uint32_t *row = (uint32_t *)((char *)s->pixels + (size_t)y * s->stride);
        for (int x = 0; x < CURSOR; x++) {
            int dx = x - CURSOR / 2, dy = y - CURSOR / 2, d2 = dx * dx + dy * dy;
            uint32_t p = 0;
            if (d2 <= 28 * 28)
                p = 0xC0u << 24 | 0xC0u << 16 | 0x60u << 8;
            else if (d2 <= 31 * 31)
                p = 0xFFFFFFFFu;
            row[x] = p;
        }
    }
}

/* The place of the cursor's picture for move j; the host has the same. */
static void place(int j, int *x, int *y) {
    *x = 20 + (j * 5) % 560;
    *y = 20 + (j * 3) % 310;
}

static void pause_ns(long ns) {
    struct timespec t = {ns / 1000000000L, ns % 1000000000L};
    nanosleep(&t, NULL);
}

/* The pause the host takes its screenshot in. */
static void snapshot_pause(void) {
    if (!quick) pause_ns(400000000L);
}

static void set_rect(WFDPipeline p, WFDPipelineConfigAttrib a, WFDint x, WFDint y, WFDint w,
                     WFDint h) {
    WFDint r[4] = {x, y, w, h};
    wfdSetPipelineAttribiv(dev, p, a, 4, r);
}

static WFDint get_i(WFDPipeline p, WFDPipelineConfigAttrib a) {
    return wfdGetPipelineAttribi(dev, p, a);
}

/* The calls that a device that is not there, and arguments that are none,
 * refuse in the ways the specification says. */
static int before_the_device(void) {
    WFDint ids[2] = {0, 0};
    CHECK(wfdGetError(7) == WFD_ERROR_BAD_DEVICE);
    CHECK(wfdEnumerateDevices(NULL, 0, NULL) == 1);
    CHECK(wfdEnumerateDevices(ids, 2, NULL) == 1 && ids[0] != WFD_DEFAULT_DEVICE_ID);
    WFDint with_port[] = {WFD_DEVICE_FILTER_PORT_ID, 1, WFD_NONE};
    CHECK(wfdEnumerateDevices(NULL, 0, with_port) == 1);
    with_port[1] = 9;
    CHECK(wfdEnumerateDevices(NULL, 0, with_port) == 0);
    CHECK(wfdCreateDevice(55, NULL) == WFD_INVALID_HANDLE);
    WFDint bad_attribs[] = {1, 1, WFD_NONE};
    CHECK(wfdCreateDevice(WFD_DEFAULT_DEVICE_ID, bad_attribs) == WFD_INVALID_HANDLE);
    CHECK(wfdGetPortAttribi(7, 1, WFD_PORT_ID) == 0);
    return 0;
}

static int describe_device(void) {
    const char *list[4];
    dev = wfdCreateDevice(WFD_DEFAULT_DEVICE_ID, NULL);
    CHECK(dev != WFD_INVALID_HANDLE);
    CHECK(wfdCreateDevice(WFD_DEFAULT_DEVICE_ID, NULL) == WFD_INVALID_HANDLE);
    CHECK(wfdGetError(dev) == WFD_ERROR_NONE);
    CHECK(wfdGetDeviceAttribi(dev, WFD_DEVICE_ID) == 1);
    wfdSetDeviceAttribi(dev, WFD_DEVICE_ID, 2);
    CHECK(wfdGetError(dev) == WFD_ERROR_BAD_ATTRIBUTE);
    CHECK(wfdGetError(dev) == WFD_ERROR_NONE);
    CHECK(wfdGetStrings(dev, WFD_VENDOR, NULL, 0) == 1);
    CHECK(wfdGetStrings(dev, WFD_VENDOR, list, 4) == 1 && strcmp(list[0], "stafeto") == 0);
    CHECK(wfdGetStrings(dev, WFD_VERSION, list, 4) == 1 && strcmp(list[0], "1.0") == 0);
    CHECK(wfdGetStrings(dev, WFD_EXTENSIONS, list, 4) == 2);
    CHECK(wfdIsExtensionSupported(dev, "WFD_STAFETO_stream") == WFD_TRUE);
    CHECK(wfdIsExtensionSupported(dev, "WFD_EXT_nothing") == WFD_FALSE);
    CHECK(wfdGetStrings(dev, (WFDStringID)0x7510, list, 4) == 0);
    CHECK(wfdGetError(dev) == WFD_ERROR_ILLEGAL_ARGUMENT);
    printf("wfd-demo: the device is made once, described, and its calls are checked\n");
    return 0;
}

static WFDPort port;
static WFDPipeline primary, cursor;

static int describe_port_and_pipelines(void) {
    WFDint ids[4];
    WFDPortMode modes[2];
    WFDint two[2];
    WFDfloat rate;
    CHECK(wfdEnumeratePorts(dev, NULL, 0, NULL) == 1);
    CHECK(wfdEnumeratePorts(dev, ids, 4, NULL) == 1 && ids[0] == 1);
    port = wfdCreatePort(dev, 1, NULL);
    CHECK(port != WFD_INVALID_HANDLE);
    CHECK(wfdCreatePort(dev, 1, NULL) == WFD_INVALID_HANDLE);
    CHECK(wfdGetError(dev) == WFD_ERROR_IN_USE);
    CHECK(wfdGetPortModes(dev, port, NULL, 0) == 1);
    CHECK(wfdGetPortModes(dev, port, modes, 2) == 1);
    CHECK(wfdGetCurrentPortMode(dev, port) == modes[0]);
    CHECK(wfdGetPortModeAttribi(dev, port, modes[0], WFD_PORT_MODE_WIDTH) == SCREEN_W);
    CHECK(wfdGetPortModeAttribi(dev, port, modes[0], WFD_PORT_MODE_HEIGHT) == SCREEN_H);
    rate = wfdGetPortModeAttribf(dev, port, modes[0], WFD_PORT_MODE_REFRESH_RATE);
    CHECK(rate > 59.5f && rate < 60.5f);
    wfdGetPortAttribiv(dev, port, WFD_PORT_NATIVE_RESOLUTION, 2, two);
    CHECK(two[0] == SCREEN_W && two[1] == SCREEN_H);
    CHECK(wfdGetPortAttribi(dev, port, WFD_PORT_POWER_MODE) == WFD_POWER_MODE_ON);
    wfdSetPortAttribi(dev, port, WFD_PORT_POWER_MODE, WFD_POWER_MODE_OFF);
    CHECK(wfdGetError(dev) == WFD_ERROR_ILLEGAL_ARGUMENT);
    wfdSetPortAttribi(dev, port, WFD_PORT_ROTATION, 90);
    CHECK(wfdGetError(dev) == WFD_ERROR_ILLEGAL_ARGUMENT);
    CHECK(wfdGetPortAttribi(dev, port, WFD_PORT_PIPELINE_ID_COUNT) == 2);
    CHECK(wfdGetPortAttribi(dev, port, WFD_PORT_NATIVE_RESOLUTION) == 0);
    CHECK(wfdGetError(dev) == WFD_ERROR_BAD_ATTRIBUTE);
    CHECK(wfdGetDisplayDataFormats(dev, port, NULL, 0) == 0);
    printf("wfd-demo: the port has one mode of 640 by 400 at 60 hertz and its power is on\n");

    CHECK(wfdEnumeratePipelines(dev, NULL, 0, NULL) == 2);
    CHECK(wfdEnumeratePipelines(dev, ids, 4, NULL) == 2 && ids[0] == 1 && ids[1] == 2);
    primary = wfdCreatePipeline(dev, 1, NULL);
    cursor = wfdCreatePipeline(dev, 2, NULL);
    CHECK(primary != WFD_INVALID_HANDLE && cursor != WFD_INVALID_HANDLE && primary != cursor);
    CHECK(wfdCreatePipeline(dev, 2, NULL) == WFD_INVALID_HANDLE);
    CHECK(wfdGetError(dev) == WFD_ERROR_IN_USE);
    CHECK(wfdGetPipelineLayerOrder(dev, port, primary) == 1);
    CHECK(wfdGetPipelineLayerOrder(dev, port, cursor) == 2);
    wfdGetPipelineAttribiv(dev, primary, WFD_PIPELINE_MAX_SOURCE_SIZE, 2, two);
    CHECK(two[0] == SCREEN_W && two[1] == SCREEN_H);
    wfdGetPipelineAttribiv(dev, cursor, WFD_PIPELINE_MAX_SOURCE_SIZE, 2, two);
    CHECK(two[0] == CURSOR && two[1] == CURSOR);
    CHECK(get_i(primary, WFD_PIPELINE_PORTID) == 1);
    CHECK(get_i(cursor, WFD_PIPELINE_ROTATION_SUPPORT) == WFD_ROTATION_SUPPORT_NONE);
    CHECK(wfdGetPipelineTransparency(dev, primary, NULL, 0) == 0);
    CHECK(wfdGetPipelineTransparency(dev, cursor, NULL, 0) == 1);
    WFDbitfield trans[2];
    CHECK(wfdGetPipelineTransparency(dev, cursor, trans, 2) == 1);
    CHECK(trans[0] == WFD_TRANSPARENCY_SOURCE_ALPHA);
    wfdSetPipelineAttribi(dev, cursor, WFD_PIPELINE_TRANSPARENCY_ENABLE, WFD_TRANSPARENCY_MASK);
    CHECK(wfdGetError(dev) == WFD_ERROR_ILLEGAL_ARGUMENT);
    wfdSetPipelineAttribi(dev, primary, WFD_PIPELINE_ROTATION, 90);
    CHECK(wfdGetError(dev) == WFD_ERROR_ILLEGAL_ARGUMENT);
    wfdSetPipelineAttribi(dev, primary, WFD_PIPELINE_LAYER, 5);
    CHECK(wfdGetError(dev) == WFD_ERROR_BAD_ATTRIBUTE);
    printf("wfd-demo: the pipelines are the primary one and the cursor, with their layers and limits\n");
    return 0;
}

static const struct stafeto_wfd_stream *target, *pool, *picture;
static WFDSource src_target, src_pool, src_cursor;

static int streams_and_sources(void) {
    CHECK(wfdStafetoStream(dev, 9) == NULL);
    CHECK(wfdGetError(dev) == WFD_ERROR_ILLEGAL_ARGUMENT);
    target = wfdStafetoStream(dev, STAFETO_WFD_STREAM_TARGET);
    pool = wfdStafetoStream(dev, STAFETO_WFD_STREAM_POOL);
    picture = wfdStafetoStream(dev, STAFETO_WFD_STREAM_CURSOR);
    CHECK(target != NULL && pool != NULL && picture != NULL);
    CHECK(wfdStafetoStream(dev, STAFETO_WFD_STREAM_POOL) == pool);
    CHECK(target->width == SCREEN_W && target->height == SCREEN_H && target->stride == 2560);
    CHECK(pool->width == SCREEN_W && pool->height == SCREEN_H && pool->stride == 2560);
    CHECK(target->format == STAFETO_WFD_XRGB8888 && pool->format == STAFETO_WFD_XRGB8888);
    CHECK(picture->width == CURSOR && picture->height == CURSOR && picture->stride == 256);
    CHECK(picture->format == STAFETO_WFD_ARGB8888);
    CHECK(target->pixels != NULL && pool->pixels != NULL && picture->pixels != NULL);
    CHECK(target->pixels != pool->pixels && target->id != pool->id);

    /* A source for a stream the pipeline cannot show is refused. */
    CHECK(wfdCreateSourceFromStream(dev, primary, picture, NULL) == WFD_INVALID_HANDLE);
    CHECK(wfdGetError(dev) == WFD_ERROR_NOT_SUPPORTED);
    CHECK(wfdCreateSourceFromStream(dev, cursor, pool, NULL) == WFD_INVALID_HANDLE);
    CHECK(wfdGetError(dev) == WFD_ERROR_NOT_SUPPORTED);
    CHECK(wfdCreateSourceFromStream(dev, primary, (WFDNativeStreamType)&crc_table, NULL) ==
          WFD_INVALID_HANDLE);
    CHECK(wfdGetError(dev) == WFD_ERROR_ILLEGAL_ARGUMENT);
    CHECK(wfdCreateMaskFromStream(dev, primary, pool, NULL) == WFD_INVALID_HANDLE);
    CHECK(wfdGetError(dev) == WFD_ERROR_NOT_SUPPORTED);
    CHECK(wfdCreateSourceFromImage(dev, primary, NULL, NULL) == WFD_INVALID_HANDLE);
    CHECK(wfdGetError(dev) == WFD_ERROR_NOT_SUPPORTED);

    src_target = wfdCreateSourceFromStream(dev, primary, target, NULL);
    src_pool = wfdCreateSourceFromStream(dev, primary, pool, NULL);
    src_cursor = wfdCreateSourceFromStream(dev, cursor, picture, NULL);
    CHECK(src_target != WFD_INVALID_HANDLE && src_pool != WFD_INVALID_HANDLE);
    CHECK(src_cursor != WFD_INVALID_HANDLE && src_target != src_pool);

    /* The region of a stream is none. */
    WFDRect region = {0, 0, 10, 10};
    wfdBindSourceToPipeline(dev, primary, src_pool, WFD_TRANSITION_AT_VSYNC, &region);
    CHECK(wfdGetError(dev) == WFD_ERROR_ILLEGAL_ARGUMENT);
    wfdBindSourceToPipeline(dev, primary, src_cursor, WFD_TRANSITION_AT_VSYNC, NULL);
    CHECK(wfdGetError(dev) == WFD_ERROR_ILLEGAL_ARGUMENT);

    /* The primary pipeline takes the whole screen and nothing else. */
    set_rect(primary, WFD_PIPELINE_DESTINATION_RECTANGLE, 0, 0, 320, 200);
    wfdBindSourceToPipeline(dev, primary, src_pool, WFD_TRANSITION_AT_VSYNC, NULL);
    wfdDeviceCommit(dev, WFD_COMMIT_ENTIRE_DEVICE, WFD_INVALID_HANDLE);
    CHECK(wfdGetError(dev) == WFD_ERROR_NOT_SUPPORTED);
    WFDint r[4];
    wfdGetPipelineAttribiv(dev, primary, WFD_PIPELINE_DESTINATION_RECTANGLE, 4, r);
    CHECK(r[0] == 0 && r[1] == 0 && r[2] == SCREEN_W && r[3] == SCREEN_H);
    wfdDeviceCommit(dev, WFD_COMMIT_ENTIRE_PORT, port + 100);
    CHECK(wfdGetError(dev) == WFD_ERROR_BAD_HANDLE);
    printf("wfd-demo: the streams of the driver are described and the sources made of them\n");
    return 0;
}

static int fork_has_no_device(void) {
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        /* The parent's device is not the child's: the handle names nothing,
         * no description of a stream is given, and the screen is the
         * parent's. */
        if (wfdGetError(dev) != WFD_ERROR_BAD_DEVICE) _exit(31);
        if (wfdStafetoStream(dev, 0) != NULL) _exit(32);
        if (wfdCreateDevice(WFD_DEFAULT_DEVICE_ID, NULL) != WFD_INVALID_HANDLE) _exit(33);
        _exit(0);
    }
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        printf("wfd-demo: the child ended with status %d\n",
               WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(wfdGetError(dev) == WFD_ERROR_NONE);
    printf("wfd-demo: a forked child has no device\n");
    return 0;
}

static WFDEvent event;

/* Waits for the bind event of `pipe` that completes the commit before. */
static int bind_completed(WFDPipeline pipe_handle, WFDint pipe_id, WFDSource before) {
    WFDEventType t = wfdDeviceEventWait(dev, event, WITHIN);
    CHECK(t == WFD_EVENT_PIPELINE_BIND_SOURCE_COMPLETE);
    CHECK(wfdGetEventAttribi(dev, event, WFD_EVENT_TYPE) == WFD_EVENT_PIPELINE_BIND_SOURCE_COMPLETE);
    CHECK(wfdGetEventAttribi(dev, event, WFD_EVENT_PIPELINE_BIND_PIPELINE_ID) == pipe_id);
    CHECK((WFDSource)wfdGetEventAttribi(dev, event, WFD_EVENT_PIPELINE_BIND_SOURCE) == before);
    CHECK(wfdGetEventAttribi(dev, event, WFD_EVENT_PIPELINE_BIND_QUEUE_OVERFLOW) == 0);
    (void)pipe_handle;
    return 0;
}

static int show_cursor(void) {
    WFDint queue[] = {WFD_EVENT_PIPELINE_BIND_QUEUE_SIZE, 16, WFD_NONE};
    event = wfdCreateEvent(dev, queue);
    CHECK(event != WFD_INVALID_HANDLE);
    CHECK(wfdGetEventAttribi(dev, event, WFD_EVENT_PIPELINE_BIND_QUEUE_SIZE) == 16);
    CHECK(wfdGetEventAttribi(dev, event, WFD_EVENT_TYPE) == WFD_EVENT_NONE);
    /* Nothing yet: a wait of no time ends at once. */
    CHECK(wfdDeviceEventWait(dev, event, 0) == WFD_EVENT_NONE);

    draw_cursor(picture);
    set_rect(cursor, WFD_PIPELINE_SOURCE_RECTANGLE, 0, 0, CURSOR, CURSOR);
    set_rect(cursor, WFD_PIPELINE_DESTINATION_RECTANGLE, 10, 10, CURSOR, CURSOR);
    wfdSetPipelineAttribi(dev, cursor, WFD_PIPELINE_TRANSPARENCY_ENABLE, WFD_TRANSPARENCY_SOURCE_ALPHA);
    CHECK(wfdGetError(dev) == WFD_ERROR_NONE);
    wfdBindSourceToPipeline(dev, cursor, src_cursor, WFD_TRANSITION_AT_VSYNC, NULL);
    wfdDeviceCommit(dev, WFD_COMMIT_PIPELINE, cursor);
    CHECK(wfdGetError(dev) == WFD_ERROR_NONE);
    CHECK(bind_completed(cursor, 2, WFD_INVALID_HANDLE) == 0);
    printf("wfd-demo: the cursor picture is bound and its event completes\n");
    return 0;
}

static int frames(int count) {
    WFDSource before = WFD_INVALID_HANDLE;
    for (int k = 0; count < 0 || k < count; k++) {
        const struct stafeto_wfd_stream *free_stream = (k % 2 == 0) ? pool : target;
        WFDSource source = (k % 2 == 0) ? src_pool : src_target;
        uint32_t crc = draw(free_stream, k);
        wfdBindSourceToPipeline(dev, primary, source, WFD_TRANSITION_AT_VSYNC, NULL);
        wfdDeviceCommit(dev, WFD_COMMIT_PIPELINE, primary);
        CHECK(wfdGetError(dev) == WFD_ERROR_NONE);
        CHECK(bind_completed(primary, 1, before) == 0);
        before = source;
        if (count >= 0) {
            printf("wfd-demo: frame %d crc %08x\n", k, crc);
            fflush(stdout);
            snapshot_pause();
        } else {
            int x, y;
            place(k % MOVES, &x, &y);
            set_rect(cursor, WFD_PIPELINE_DESTINATION_RECTANGLE, x, y, CURSOR, CURSOR);
            wfdDeviceCommit(dev, WFD_COMMIT_PIPELINE, cursor);
            pause_ns(30000000L);
        }
    }
    printf("wfd-demo: %d frames, each completed its bind event with the source before it\n", count);
    return 0;
}

static int moves(int count) {
    for (int j = 0; j < count; j++) {
        int x, y;
        place(j, &x, &y);
        set_rect(cursor, WFD_PIPELINE_DESTINATION_RECTANGLE, x, y, CURSOR, CURSOR);
        wfdDeviceCommit(dev, WFD_COMMIT_PIPELINE, cursor);
        CHECK(wfdGetError(dev) == WFD_ERROR_NONE);
        /* A move is no transition: no bind event comes for it. */
        pause_ns(quick ? 0L : 20000000L);
    }
    printf("wfd-demo: the cursor moved %d times\n", count);
    return 0;
}

static int finish(void) {
    wfdDestroyEvent(dev, event);
    CHECK(wfdGetError(dev) == WFD_ERROR_NONE);
    wfdDestroyEvent(dev, event);
    CHECK(wfdGetError(dev) == WFD_ERROR_BAD_HANDLE);
    CHECK(wfdDestroyDevice(dev) == WFD_ERROR_NONE);
    CHECK(wfdGetError(dev) == WFD_ERROR_BAD_DEVICE);
    CHECK(wfdCreateEvent(dev, NULL) == WFD_INVALID_HANDLE);
    CHECK(wfdDestroyDevice(dev) == WFD_ERROR_BAD_DEVICE);
    printf("wfd-demo: the device is destroyed and its handles are gone\n");
    return 0;
}

static int run_role(int probe) {
    crc_init();
    if (probe) {
        CHECK(before_the_device() == 0);
    }
    CHECK(describe_device() == 0);
    CHECK(describe_port_and_pipelines() == 0);
    CHECK(streams_and_sources() == 0);
    if (probe) {
        CHECK(fork_has_no_device() == 0);
    }
    CHECK(show_cursor() == 0);
    if (!probe) return frames(-1);
    CHECK(frames(FRAMES) == 0);
    CHECK(moves(MOVES) == 0);
    CHECK(finish() == 0);
    return 0;
}

/* The copy that is started: the arguments after "run" are the demo's. */
static int first(int probe, int is_quick) {
    char *argv[5] = {"wfd-demo", "run", NULL, NULL, NULL};
    int n = 2;
    pid_t pid = 0;
    int status = 0;
    if (probe) argv[n++] = "--probe";
    if (is_quick) argv[n++] = "--quick";
    CHECK(posix_spawn(&pid, "/bin/wfd-demo", NULL, NULL, argv, environ) == 0);
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 0;
}

int main(int argc, char **argv) {
    int probe = 0, run = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--probe") == 0) probe = 1;
        else if (strcmp(argv[i], "--quick") == 0) quick = 1;
        else if (strcmp(argv[i], "run") == 0) run = 1;
    }
    if (run) return run_role(probe);
    int status = first(probe, quick);
    if (status == 0) printf("wfd-demo: ok\n");
    return status;
}
