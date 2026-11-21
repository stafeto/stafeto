/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The extension of stafeto to OpenWF Composition 1.0, named as the
 * specification's section 10.1 has it: WFC_STAFETO_stream, with the function
 * wfcNextStreamSTAFETO. wfcIsExtensionSupported answers for the name and
 * wfcGetStrings(WFC_EXTENSIONS) lists it.
 *
 * The specification leaves the creation of streams to the platform. Here a
 * stream is a window of the composition service, and its WFCNativeStreamType
 * is the window's number. The producer makes the window; the program that
 * holds the scene learns its number from wfcNextStreamSTAFETO and makes a
 * WFCSource or a WFCMask of it (a window of the format A8 is a mask only).
 *
 * WFCint wfcNextStreamSTAFETO(WFCDevice dev, WFCint timeoutMs,
 *                             WFCNativeStreamType *stream);
 *
 * Waits for a window to be made, no longer than timeoutMs milliseconds, and
 * writes its number to *stream. Returns 1 when it wrote a number, 0 when the
 * time ran out or a signal ended the wait, and -1 when the call failed: the
 * device is no device or has lost the service (the error is the device's,
 * WFC_ERROR_BAD_DEVICE), another thread waits (WFC_ERROR_BUSY), or stream is
 * null (WFC_ERROR_ILLEGAL_ARGUMENT). Windows made before the call count, up
 * to 32 of them. Only the windows' creation is taken from the scene's ring of
 * events; its other events are dropped.
 *
 * None of the functions of <WF/wfc.h> or this header is async-signal-safe
 * (XSH 2.4.3). Calling one from a signal handler that interrupted a call of
 * the library, or leaving a call with siglongjmp, is undefined. A signal that
 * arrives while wfcCommit or wfcCompose waits runs its handler and the wait
 * goes on, as a call restarted under SA_RESTART; wfcNextStreamSTAFETO ends
 * with 0 when a signal interrupts it.
 *
 * The function lives in a static library the program links (the feature
 * `wfc` of the Rust crate posix-crt), outside libc.so; this header and the
 * others of <WF/> lie outside the headers of the libc sysroot.
 */
#ifndef WFCEXT_STAFETO_H_
#define WFCEXT_STAFETO_H_

#include <WF/wfc.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WFC_STAFETO_stream 1

WFC_API_CALL WFCint WFC_APIENTRY
    wfcNextStreamSTAFETO(WFCDevice dev, WFCint timeoutMs,
        WFCNativeStreamType *stream) WFC_APIEXIT;

#ifdef __cplusplus
}
#endif

#endif /* WFCEXT_STAFETO_H_ */
