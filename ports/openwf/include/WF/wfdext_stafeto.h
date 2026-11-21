/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The extensions of stafeto to OpenWF Display 1.0, named as the
 * specification's section 6 has it: WFD_STAFETO_stream and
 * WFD_STAFETO_cursor. wfdIsExtensionSupported answers for them and
 * wfdGetStrings(WFD_EXTENSIONS) lists them.
 *
 * The specification leaves the creation of streams to the platform. On this
 * display the streams are the three sources of the driver: the compositing
 * target (the buffer the screen is opened with), the pool buffer and the
 * cursor picture. wfdStafetoStream gives the description of one, with the
 * address of its points in the process; the program draws there and makes a
 * WFDSource of the description with wfdCreateSourceFromStream.
 *
 * A pixel is a 32-bit word stored low byte first. The target and the pool
 * are 0x00RRGGBB (STAFETO_WFD_XRGB8888, the top byte is ignored), the
 * cursor picture 0xAARRGGBB with the colours already multiplied by the alpha
 * (STAFETO_WFD_ARGB8888). stride is the bytes of a line.
 *
 * The functions live in a static library the program links (the feature
 * `wfd` of the Rust crate posix-crt), outside libc.so; this header and the
 * others of <WF/> lie outside the headers of the libc sysroot.
 */
#ifndef WFDEXT_STAFETO_H_
#define WFDEXT_STAFETO_H_

#include <WF/wfd.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WFD_STAFETO_stream 1
#define WFD_STAFETO_cursor 1

#define STAFETO_WFD_XRGB8888 1
#define STAFETO_WFD_ARGB8888 3

/* The kinds of wfdStafetoStream. */
#define STAFETO_WFD_STREAM_TARGET 0
#define STAFETO_WFD_STREAM_POOL 1
#define STAFETO_WFD_STREAM_CURSOR 2

/* A stream of the driver: its id, its size, the bytes of a line, the format
 * and the address of its points (height * stride bytes). The description
 * stays valid until the device is destroyed; the points may be written
 * while the source made of the stream is not the one the display shows. */
struct stafeto_wfd_stream {
    uint32_t id, width, height, stride, format, reserved;
    void *pixels;
};

/* The layout the library's Rust side holds too. */
#if defined(__cplusplus) && __cplusplus >= 201103L
#define STAFETO_WFD_ASSERT(c) static_assert(c, #c)
#elif !defined(__cplusplus) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define STAFETO_WFD_ASSERT(c) _Static_assert(c, #c)
#else
#define STAFETO_WFD_JOIN2(a, b) a##b
#define STAFETO_WFD_JOIN(a, b) STAFETO_WFD_JOIN2(a, b)
#define STAFETO_WFD_ASSERT(c) \
    typedef char STAFETO_WFD_JOIN(stafeto_wfd_assert_, __LINE__)[(c) ? 1 : -1]
#endif

STAFETO_WFD_ASSERT(offsetof(struct stafeto_wfd_stream, width) == 4);
STAFETO_WFD_ASSERT(offsetof(struct stafeto_wfd_stream, stride) == 12);
STAFETO_WFD_ASSERT(offsetof(struct stafeto_wfd_stream, pixels) == 24);
STAFETO_WFD_ASSERT(sizeof(struct stafeto_wfd_stream) == 32);

/* The description of the stream `kind` (STAFETO_WFD_STREAM_*) of `device`,
 * made on the first call. NULL for a kind that is none
 * (WFD_ERROR_ILLEGAL_ARGUMENT), for a source the driver does not give
 * (WFD_ERROR_OUT_OF_MEMORY) and for a handle that is no device (no error
 * stored). */
WFD_API_CALL const struct stafeto_wfd_stream *WFD_APIENTRY
    wfdStafetoStream(WFDDevice device, WFDint kind) WFD_APIEXIT;

/* The point of the cursor picture that the destination rectangle's place
 * names to the display (the pointer's hot spot, 0, 0 until it is set). The
 * pipeline must be the cursor pipeline and the point inside its picture
 * (WFD_ERROR_ILLEGAL_ARGUMENT otherwise). The change is cached until
 * wfdDeviceCommit. */
WFD_API_CALL void WFD_APIENTRY
    wfdStafetoSetCursorHotSpot(WFDDevice device, WFDPipeline pipeline, WFDint x,
                               WFDint y) WFD_APIEXIT;

#ifdef __cplusplus
}
#endif

#endif /* WFDEXT_STAFETO_H_ */
