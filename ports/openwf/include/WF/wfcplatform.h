/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The platform types of OpenWF Composition 1.0 on stafeto: the one header of
 * the three that the specification leaves to the platform. The header of the
 * Khronos registry includes <KHR/khrplatform.h> and <EGL/egl.h>, which this
 * system does not have; this one names the same types with the sizes the
 * specification gives them, from <stdint.h>, and the two values of the
 * boolean that wfc.h takes from <KHR/khrplatform.h>. The lines that differ
 * from the registry's header are the two includes (replaced by <stddef.h> and
 * <stdint.h>), the three API macros (empty: there is no export decoration),
 * the type definitions (from <stdint.h>), the definition of WFCEGLDisplay and
 * of WFCNativeStreamType, and the KHR_BOOLEAN_* values below. wfc.h and
 * wfcext.h are the registry's, unedited.
 *
 * WFCNativeStreamType is the number of a window of the composition service,
 * the same number WINDOW_CREATE answers and wfcNextStreamSTAFETO of
 * <WF/wfcext_stafeto.h> gives for the next window made. The EGL types are
 * opaque pointers: the library has no EGL, so wfcFence answers
 * WFC_ERROR_ILLEGAL_ARGUMENT.
 */
#ifndef _WFCPLATFORM_H_
#define _WFCPLATFORM_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WFC_API_CALL
#define WFC_API_CALL
#endif

#ifndef WFC_APIENTRY
#define WFC_APIENTRY
#endif

#ifndef WFC_APIEXIT
#define WFC_APIEXIT
#endif

#ifndef WFC_DEFAULT_SCREEN_NUMBER
#define WFC_DEFAULT_SCREEN_NUMBER (0)
#endif

/* wfc.h takes the values of WFCboolean from the names of an older
 * <KHR/khrplatform.h>, which the current one of the registry no longer has. */
#ifndef KHR_BOOLEAN_TRUE
#define KHR_BOOLEAN_TRUE 1
#define KHR_BOOLEAN_FALSE 0
#endif

typedef int32_t WFCint;
typedef float WFCfloat;
typedef uint32_t WFCbitfield;
typedef uint32_t WFCHandle;

typedef void *WFCEGLDisplay;
typedef void *WFCEGLSync;
typedef WFCHandle WFCNativeStreamType;

#ifdef __cplusplus
}
#endif

#endif /* _WFCPLATFORM_H_ */
