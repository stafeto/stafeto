/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The platform types of OpenWF Display 1.0 on stafeto: the one header of
 * the three that the specification leaves to the platform. It names the
 * types of <WF/wfd.h> with the sizes the specification gives them, and the
 * two values of the boolean that wfd.h takes from <KHR/khrplatform.h>, so
 * that no header of Khronos besides wfd.h and wfdext.h is needed.
 *
 * WFDNativeStreamType is a pointer to the description of a source of the
 * display driver (struct stafeto_wfd_stream of <WF/wfdext_stafeto.h>), which
 * wfdStafetoStream gives. The streams of the platform are the compositing
 * target, the pool buffer and the cursor picture of the driver; the library
 * keeps the three descriptions, and a pointer that is none of them is not a
 * valid stream. The EGL types are opaque pointers: the library has no EGL,
 * so the functions that take an image or a sync object answer
 * WFD_ERROR_NOT_SUPPORTED.
 */
#ifndef _WFDPLATFORM_H_
#define _WFDPLATFORM_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WFD_API_CALL
#define WFD_API_CALL
#endif

#ifndef WFD_APIENTRY
#define WFD_APIENTRY
#endif

#ifndef WFD_APIEXIT
#define WFD_APIEXIT
#endif

/* wfd.h takes the values of WFDboolean from the names of an older
 * <KHR/khrplatform.h>, which the current one of the registry no longer has. */
#ifndef KHR_BOOLEAN_TRUE
#define KHR_BOOLEAN_TRUE 1
#define KHR_BOOLEAN_FALSE 0
#endif

typedef uint8_t WFDuint8;
typedef int32_t WFDint;
typedef float WFDfloat;
typedef uint32_t WFDbitfield;
typedef uint32_t WFDHandle;
typedef uint64_t WFDtime;

#define WFD_FOREVER (0xFFFFFFFFFFFFFFFFull)

typedef void *WFDEGLDisplay;
typedef void *WFDEGLSync;
typedef void *WFDEGLImage;

struct stafeto_wfd_stream;
typedef const struct stafeto_wfd_stream *WFDNativeStreamType;

#define WFD_INVALID_SYNC ((WFDEGLSync)0)

#ifdef __cplusplus
}
#endif

#endif /* _WFDPLATFORM_H_ */
