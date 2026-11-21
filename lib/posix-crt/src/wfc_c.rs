// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The C functions of OpenWF Composition 1.0 (`<WF/wfc.h>`, the header of the
//! Khronos registry in `ports/openwf/include/WF`), behind the feature `wfc`: a
//! statically linked program turns it on, and libc.so is built without it.
//! Each function is a call of the rules (the crate `wfc`) on the device the
//! handle names (`posix_abi::wfc`), under that device's lock; the errors are
//! the device's own, read with `wfcGetError`, so no function sets errno. The
//! function of the extension is `wfcNextStreamSTAFETO`
//! (`<WF/wfcext_stafeto.h>`).

use core::ffi::{c_char, c_void};
use posix_abi::wfc as layer;
use wfc::consts::*;
use wfc::{StreamInfo, Wfc};

/// The rules' device `dev` and the service, with the default of the return
/// type when the handle is no device.
fn on<R: Default>(dev: u32, f: impl FnOnce(&mut Wfc, &mut layer::Transport) -> R) -> R {
    layer::with(dev, f).unwrap_or_default()
}

/// The pairs of an attribute list, up to its WFC_NONE (at most 32 pairs).
///
/// # Safety
/// `p` is null or the start of a list that ends with WFC_NONE.
unsafe fn pairs<'a>(p: *const i32) -> &'a [i32] {
    if p.is_null() {
        return &[];
    }
    let mut n = 0;
    // SAFETY: the list is terminated; the scan stops at 64 numbers all the same.
    unsafe {
        while n < 64 && *p.add(n) != 0 {
            n += 2;
        }
        core::slice::from_raw_parts(p, n.min(64))
    }
}

/// `count` numbers at `p` (at most 16), None for null.
///
/// # Safety
/// `p` is null or points to `count` readable numbers when `count` is 1..=16.
unsafe fn input<'a, T>(p: *const T, count: i32) -> Option<&'a [T]> {
    if p.is_null() {
        None
    } else {
        // SAFETY: the caller gives `count` elements.
        Some(unsafe { core::slice::from_raw_parts(p, count.clamp(0, 16) as usize) })
    }
}

/// As `input` for a writable array.
///
/// # Safety
/// `p` is null or points to `count` writable numbers when `count` is 1..=16.
unsafe fn output<'a, T>(p: *mut T, count: i32) -> Option<&'a mut [T]> {
    if p.is_null() {
        None
    } else {
        // SAFETY: the caller gives `count` elements.
        Some(unsafe { core::slice::from_raw_parts_mut(p, count.clamp(0, 16) as usize) })
    }
}

// ---------------------------------------------------------------- the device

/// `wfcEnumerateDevices`.
///
/// # Safety
/// `ids` is null or has room for `count` numbers; `filter` is null or ends
/// with WFC_NONE.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfcEnumerateDevices(ids: *mut i32, count: i32, filter: *const i32) -> i32 {
    // SAFETY: the caller's arrays.
    let (filter, out) = unsafe { (pairs(filter), output(ids, count.min(1))) };
    if !ids.is_null() && count <= 0 {
        return 0;
    }
    if !layer::available() {
        return 0;
    }
    Wfc::enumerate_devices(out, filter)
}

/// `wfcCreateDevice`.
///
/// # Safety
/// `attribs` is null or ends with WFC_NONE.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfcCreateDevice(id: i32, attribs: *const i32) -> u32 {
    // SAFETY: the caller's list.
    if (id != 0 && id != wfc::DEVICE) || !unsafe { pairs(attribs) }.is_empty() {
        return 0;
    }
    layer::create().unwrap_or(0)
}

/// `wfcGetError`: BAD_DEVICE for a handle that is no device.
#[unsafe(no_mangle)]
pub extern "C" fn wfcGetError(dev: u32) -> i32 {
    layer::with(dev, |w, _| w.get_error(dev)).unwrap_or(ERROR_BAD_DEVICE)
}

/// `wfcGetDeviceAttribi`.
#[unsafe(no_mangle)]
pub extern "C" fn wfcGetDeviceAttribi(dev: u32, attrib: i32) -> i32 {
    on(dev, |w, _| w.device_attrib(dev, attrib))
}

/// `wfcDestroyDevice`.
#[unsafe(no_mangle)]
pub extern "C" fn wfcDestroyDevice(dev: u32) -> i32 {
    layer::destroy(dev)
}

/// `wfcGetStrings`.
///
/// # Safety
/// `strings` is null or has room for `count` pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfcGetStrings(
    dev: u32,
    name: i32,
    strings: *mut *const c_char,
    count: i32,
) -> i32 {
    let Some(list) = on(dev, |w, _| w.strings(dev, name, count)) else {
        return 0;
    };
    if strings.is_null() {
        return list.len() as i32;
    }
    let n = list.len().min(count.max(0) as usize);
    for (i, s) in list.iter().take(n).enumerate() {
        // SAFETY: the caller's array has `count` places.
        unsafe { *strings.add(i) = s.as_ptr().cast() };
    }
    n as i32
}

/// `wfcIsExtensionSupported`.
///
/// # Safety
/// `string` is null or a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfcIsExtensionSupported(dev: u32, string: *const c_char) -> u32 {
    if string.is_null() {
        return 0;
    }
    let mut name = [0u8; 64];
    let string = string.cast::<u8>();
    let mut n = 0;
    // SAFETY: the string is terminated; the copy stops at the room's end.
    unsafe {
        while n < name.len() && *string.add(n) != 0 {
            name[n] = *string.add(n);
            n += 1;
        }
        if n == name.len() && *string.add(n) != 0 {
            return 0;
        }
    }
    u32::from(on(dev, |w, _| w.is_extension_supported(dev, &name[..n])))
}

/// `wfcNextStreamSTAFETO`: 1 and the number of a window made, 0 when the time
/// ran out or a signal ended the wait, -1 on an error of the device.
///
/// # Safety
/// `stream` is null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfcNextStreamSTAFETO(dev: u32, timeout_ms: i32, stream: *mut u32) -> i32 {
    if stream.is_null() {
        on(dev, |w, _| w.refuse(dev, ERROR_ILLEGAL_ARGUMENT));
        return -1;
    }
    let mut id = 0;
    let got = layer::next_stream(dev, timeout_ms, &mut id);
    if got == 1 {
        // SAFETY: the caller's pointer.
        unsafe { *stream = id };
    }
    got
}

// ------------------------------------------------------------------ contexts

/// `wfcCreateOnScreenContext`.
///
/// # Safety
/// `attribs` is null or ends with WFC_NONE.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfcCreateOnScreenContext(
    dev: u32,
    screen: i32,
    attribs: *const i32,
) -> u32 {
    // SAFETY: the caller's list.
    let list = unsafe { pairs(attribs) };
    on(dev, |w, s| w.create_on_screen_context(dev, screen, list, s))
}

/// `wfcCreateOffScreenContext`.
///
/// # Safety
/// `attribs` is null or ends with WFC_NONE.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfcCreateOffScreenContext(
    dev: u32,
    stream: u32,
    attribs: *const i32,
) -> u32 {
    // SAFETY: the caller's list.
    let list = unsafe { pairs(attribs) };
    on(dev, |w, _| w.create_off_screen_context(dev, stream, list))
}

/// `wfcCommit`.
#[unsafe(no_mangle)]
pub extern "C" fn wfcCommit(dev: u32, ctx: u32, wait: u32) {
    on(dev, |w, s| w.commit(dev, ctx, wait != 0, s));
}

/// `wfcGetContextAttribi`.
#[unsafe(no_mangle)]
pub extern "C" fn wfcGetContextAttribi(dev: u32, ctx: u32, attrib: i32) -> i32 {
    on(dev, |w, _| w.context_attrib_i(dev, ctx, attrib))
}

/// `wfcGetContextAttribfv`.
///
/// # Safety
/// `values` is null or has room for `count` numbers when `count` is 1..=16.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfcGetContextAttribfv(
    dev: u32,
    ctx: u32,
    attrib: i32,
    count: i32,
    values: *mut f32,
) {
    // SAFETY: the caller's array.
    let out = unsafe { output(values, count) };
    on(dev, |w, _| w.context_attrib_fv(dev, ctx, attrib, out));
}

/// `wfcSetContextAttribi`.
#[unsafe(no_mangle)]
pub extern "C" fn wfcSetContextAttribi(dev: u32, ctx: u32, attrib: i32, value: i32) {
    on(dev, |w, _| w.set_context_attrib_i(dev, ctx, attrib, value));
}

/// `wfcSetContextAttribfv`.
///
/// # Safety
/// `values` is null or has `count` numbers when `count` is 1..=16.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfcSetContextAttribfv(
    dev: u32,
    ctx: u32,
    attrib: i32,
    count: i32,
    values: *const f32,
) {
    // SAFETY: the caller's array.
    let given = unsafe { input(values, count) };
    on(dev, |w, _| w.set_context_attrib_fv(dev, ctx, attrib, given));
}

/// `wfcDestroyContext`.
#[unsafe(no_mangle)]
pub extern "C" fn wfcDestroyContext(dev: u32, ctx: u32) {
    on(dev, |w, s| w.destroy_context(dev, ctx, s));
}

// ------------------------------------------------------ sources and masks

/// `wfcCreateSourceFromStream`: the stream is the number of a window.
///
/// # Safety
/// `attribs` is null or ends with WFC_NONE.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfcCreateSourceFromStream(
    dev: u32,
    ctx: u32,
    stream: u32,
    attribs: *const i32,
) -> u32 {
    // SAFETY: the caller's list.
    let list = unsafe { pairs(attribs) };
    let info: Option<StreamInfo> = layer::stream_info(stream);
    on(dev, |w, _| {
        w.create_source_from_stream(dev, ctx, info, list)
    })
}

/// `wfcDestroySource`.
#[unsafe(no_mangle)]
pub extern "C" fn wfcDestroySource(dev: u32, src: u32) {
    on(dev, |w, _| w.destroy_source(dev, src));
}

/// `wfcCreateMaskFromStream`.
///
/// # Safety
/// `attribs` is null or ends with WFC_NONE.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfcCreateMaskFromStream(
    dev: u32,
    ctx: u32,
    stream: u32,
    attribs: *const i32,
) -> u32 {
    // SAFETY: the caller's list.
    let list = unsafe { pairs(attribs) };
    let info: Option<StreamInfo> = layer::stream_info(stream);
    on(dev, |w, _| w.create_mask_from_stream(dev, ctx, info, list))
}

/// `wfcDestroyMask`.
#[unsafe(no_mangle)]
pub extern "C" fn wfcDestroyMask(dev: u32, mask: u32) {
    on(dev, |w, _| w.destroy_mask(dev, mask));
}

// ----------------------------------------------------------------- elements

/// `wfcCreateElement`.
///
/// # Safety
/// `attribs` is null or ends with WFC_NONE.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfcCreateElement(dev: u32, ctx: u32, attribs: *const i32) -> u32 {
    // SAFETY: the caller's list.
    let list = unsafe { pairs(attribs) };
    on(dev, |w, _| w.create_element(dev, ctx, list))
}

/// `wfcGetElementAttribi`.
#[unsafe(no_mangle)]
pub extern "C" fn wfcGetElementAttribi(dev: u32, element: u32, attrib: i32) -> i32 {
    on(dev, |w, _| w.element_attrib_i(dev, element, attrib))
}

/// `wfcGetElementAttribf`.
#[unsafe(no_mangle)]
pub extern "C" fn wfcGetElementAttribf(dev: u32, element: u32, attrib: i32) -> f32 {
    on(dev, |w, _| w.element_attrib_f(dev, element, attrib))
}

/// `wfcGetElementAttribiv`.
///
/// # Safety
/// `values` is null or has room for `count` numbers when `count` is 1..=16.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfcGetElementAttribiv(
    dev: u32,
    element: u32,
    attrib: i32,
    count: i32,
    values: *mut i32,
) {
    // SAFETY: the caller's array.
    let out = unsafe { output(values, count) };
    on(dev, |w, _| w.element_attrib_iv(dev, element, attrib, out));
}

/// `wfcGetElementAttribfv`.
///
/// # Safety
/// `values` is null or has room for `count` numbers when `count` is 1..=16.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfcGetElementAttribfv(
    dev: u32,
    element: u32,
    attrib: i32,
    count: i32,
    values: *mut f32,
) {
    // SAFETY: the caller's array.
    let out = unsafe { output(values, count) };
    on(dev, |w, _| w.element_attrib_fv(dev, element, attrib, out));
}

/// `wfcSetElementAttribi`.
#[unsafe(no_mangle)]
pub extern "C" fn wfcSetElementAttribi(dev: u32, element: u32, attrib: i32, value: i32) {
    on(dev, |w, _| {
        w.set_element_attrib_i(dev, element, attrib, value)
    });
}

/// `wfcSetElementAttribf`.
#[unsafe(no_mangle)]
pub extern "C" fn wfcSetElementAttribf(dev: u32, element: u32, attrib: i32, value: f32) {
    on(dev, |w, _| {
        w.set_element_attrib_f(dev, element, attrib, value)
    });
}

/// `wfcSetElementAttribiv`.
///
/// # Safety
/// `values` is null or has `count` numbers when `count` is 1..=16.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfcSetElementAttribiv(
    dev: u32,
    element: u32,
    attrib: i32,
    count: i32,
    values: *const i32,
) {
    // SAFETY: the caller's array.
    let given = unsafe { input(values, count) };
    on(dev, |w, _| {
        w.set_element_attrib_iv(dev, element, attrib, given)
    });
}

/// `wfcSetElementAttribfv`.
///
/// # Safety
/// `values` is null or has `count` numbers when `count` is 1..=16.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfcSetElementAttribfv(
    dev: u32,
    element: u32,
    attrib: i32,
    count: i32,
    values: *const f32,
) {
    // SAFETY: the caller's array.
    let given = unsafe { input(values, count) };
    on(dev, |w, _| {
        w.set_element_attrib_fv(dev, element, attrib, given)
    });
}

/// `wfcInsertElement`.
#[unsafe(no_mangle)]
pub extern "C" fn wfcInsertElement(dev: u32, element: u32, subordinate: u32) {
    on(dev, |w, _| w.insert_element(dev, element, subordinate));
}

/// `wfcRemoveElement`.
#[unsafe(no_mangle)]
pub extern "C" fn wfcRemoveElement(dev: u32, element: u32) {
    on(dev, |w, _| w.remove_element(dev, element));
}

/// `wfcGetElementAbove`.
#[unsafe(no_mangle)]
pub extern "C" fn wfcGetElementAbove(dev: u32, element: u32) -> u32 {
    on(dev, |w, _| w.element_above(dev, element))
}

/// `wfcGetElementBelow`.
#[unsafe(no_mangle)]
pub extern "C" fn wfcGetElementBelow(dev: u32, element: u32) -> u32 {
    on(dev, |w, _| w.element_below(dev, element))
}

/// `wfcDestroyElement`.
#[unsafe(no_mangle)]
pub extern "C" fn wfcDestroyElement(dev: u32, element: u32) {
    on(dev, |w, _| w.destroy_element(dev, element));
}

// ---------------------------------------------------------------- rendering

/// `wfcActivate`.
#[unsafe(no_mangle)]
pub extern "C" fn wfcActivate(dev: u32, ctx: u32) {
    on(dev, |w, s| w.activate(dev, ctx, s));
}

/// `wfcDeactivate`.
#[unsafe(no_mangle)]
pub extern "C" fn wfcDeactivate(dev: u32, ctx: u32) {
    on(dev, |w, s| w.deactivate(dev, ctx, s));
}

/// `wfcCompose`.
#[unsafe(no_mangle)]
pub extern "C" fn wfcCompose(dev: u32, ctx: u32, wait: u32) {
    on(dev, |w, s| w.compose(dev, ctx, wait != 0, s));
}

/// `wfcFence`: ILLEGAL_ARGUMENT, there is no EGL display to pass.
#[unsafe(no_mangle)]
pub extern "C" fn wfcFence(dev: u32, ctx: u32, _display: *mut c_void, _sync: *mut c_void) {
    on(dev, |w, _| w.fence(dev, ctx));
}
