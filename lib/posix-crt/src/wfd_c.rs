// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The C functions of OpenWF Display 1.0 (`<WF/wfd.h>`, the header of the
//! Khronos registry in `ports/openwf/include/WF`), behind the feature `wfd`: a
//! statically linked program turns it on, and libc.so is built without it.
//! Each function is a call of the rules (the crate `wfd`) on the process's
//! device (`posix_abi::wfd`); the errors are the device's own, read with
//! `wfdGetError`, so no function sets errno. The two functions of the
//! extensions are `wfdStafetoStream` and `wfdStafetoSetCursorHotSpot`
//! (`<WF/wfdext_stafeto.h>`).

use core::ffi::{c_char, c_void};
use posix_abi::wfd as layer;
use wfd::Wfd;
use wfd::consts::*;

/// `WFDRect`.
#[repr(C)]
pub struct Rect {
    offset_x: i32,
    offset_y: i32,
    width: i32,
    height: i32,
}

const _: () = assert!(core::mem::size_of::<Rect>() == 16);
const _: () = assert!(core::mem::size_of::<layer::Stream>() == 32);

/// The rules' device, with the default of the return type when the process
/// has none.
fn on<R: Default>(f: impl FnOnce(&mut Wfd) -> R) -> R {
    layer::with(f).unwrap_or_default()
}

/// The pairs of an attribute list, up to its WFD_NONE (at most 32 pairs).
///
/// # Safety
/// `p` is null or the start of a list that ends with WFD_NONE.
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

/// `wfdGetStrings`.
///
/// # Safety
/// `strings` is null or has room for `count` pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfdGetStrings(
    device: u32,
    name: i32,
    strings: *mut *const c_char,
    count: i32,
) -> i32 {
    let Some(list) = on(|w| w.strings(device, name, count)) else {
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

/// `wfdIsExtensionSupported`.
///
/// # Safety
/// `string` is null or a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfdIsExtensionSupported(device: u32, string: *const c_char) -> u32 {
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
    u32::from(on(|w| w.is_extension_supported(device, &name[..n])))
}

/// `wfdGetError`: BAD_DEVICE for a handle that is no device.
#[unsafe(no_mangle)]
pub extern "C" fn wfdGetError(device: u32) -> i32 {
    layer::with(|w| w.get_error(device)).unwrap_or(ERROR_BAD_DEVICE)
}

/// `wfdEnumerateDevices`.
///
/// # Safety
/// `ids` is null or has room for `count` numbers; `filter` is null or ends
/// with WFD_NONE.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfdEnumerateDevices(ids: *mut i32, count: i32, filter: *const i32) -> i32 {
    // SAFETY: the caller's arrays.
    let (filter, out) = unsafe { (pairs(filter), output(ids, count.min(1))) };
    if !ids.is_null() && count <= 0 {
        return 0;
    }
    Wfd::enumerate_devices(out, filter)
}

/// `wfdCreateDevice`: the process's screen, made once.
///
/// # Safety
/// `attribs` is null or ends with WFD_NONE.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfdCreateDevice(id: i32, attribs: *const i32) -> u32 {
    // SAFETY: the caller's list.
    if !Wfd::device_id_valid(id) || !unsafe { pairs(attribs) }.is_empty() {
        return 0;
    }
    layer::create().unwrap_or(0)
}

/// `wfdDestroyDevice`.
#[unsafe(no_mangle)]
pub extern "C" fn wfdDestroyDevice(device: u32) -> i32 {
    if layer::device() != device || device == 0 {
        return ERROR_BAD_DEVICE;
    }
    layer::destroy(device);
    ERROR_NONE
}

/// `wfdDeviceCommit`.
#[unsafe(no_mangle)]
pub extern "C" fn wfdDeviceCommit(device: u32, kind: i32, handle: u32) {
    layer::commit(device, kind, handle);
}

/// `wfdGetDeviceAttribi`.
#[unsafe(no_mangle)]
pub extern "C" fn wfdGetDeviceAttribi(device: u32, attrib: i32) -> i32 {
    on(|w| w.get_device_attrib(device, attrib))
}

/// `wfdSetDeviceAttribi`.
#[unsafe(no_mangle)]
pub extern "C" fn wfdSetDeviceAttribi(device: u32, attrib: i32, value: i32) {
    on(|w| w.set_device_attrib(device, attrib, value));
}

/// `wfdCreateEvent`.
///
/// # Safety
/// `attribs` is null or ends with WFD_NONE.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfdCreateEvent(device: u32, attribs: *const i32) -> u32 {
    // SAFETY: the caller's list.
    let list = unsafe { pairs(attribs) };
    on(|w| w.create_event(device, list))
}

/// `wfdDestroyEvent`: a thread that waits on the container is woken.
#[unsafe(no_mangle)]
pub extern "C" fn wfdDestroyEvent(device: u32, event: u32) {
    on(|w| w.destroy_event(device, event));
    layer::wake();
}

/// `wfdGetEventAttribi`.
#[unsafe(no_mangle)]
pub extern "C" fn wfdGetEventAttribi(device: u32, event: u32, attrib: i32) -> i32 {
    on(|w| w.get_event_attrib(device, event, attrib))
}

/// `wfdDeviceEventAsync`: needs EGL, which the library has not.
#[unsafe(no_mangle)]
pub extern "C" fn wfdDeviceEventAsync(
    device: u32,
    _event: u32,
    _display: *mut c_void,
    _sync: *mut c_void,
) {
    on(|w| w.refuse(device, ERROR_NOT_SUPPORTED));
}

/// `wfdDeviceEventWait`.
#[unsafe(no_mangle)]
pub extern "C" fn wfdDeviceEventWait(device: u32, event: u32, timeout: u64) -> i32 {
    if layer::device() != device || device == 0 {
        return EVENT_INVALID;
    }
    layer::event_wait(device, event, timeout)
}

/// `wfdDeviceEventFilter`.
///
/// # Safety
/// `filter` is null or ends with WFD_NONE.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfdDeviceEventFilter(device: u32, event: u32, filter: *const i32) {
    let mut list = [0; 16];
    let mut n = 0;
    if !filter.is_null() {
        // SAFETY: the list is terminated; the copy stops at 16 entries.
        unsafe {
            while n < list.len() && *filter.add(n) != 0 {
                list[n] = *filter.add(n);
                n += 1;
            }
        }
    }
    let given = (!filter.is_null()).then_some(&list[..n]);
    on(|w| w.device_event_filter(device, event, given));
}

/// `wfdEnumeratePorts`.
///
/// # Safety
/// `ids` is null or has room for `count` numbers; `filter` ends with WFD_NONE.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfdEnumeratePorts(
    device: u32,
    ids: *mut i32,
    count: i32,
    filter: *const i32,
) -> i32 {
    // SAFETY: the caller's arrays.
    let (filter, out) = unsafe { (pairs(filter), output(ids, count.min(1))) };
    let out = out
        .filter(|_| count > 0)
        .or_else(|| (!ids.is_null()).then_some(&mut []));
    on(|w| w.enumerate_ports(device, out, filter))
}

/// `wfdCreatePort`.
///
/// # Safety
/// `attribs` is null or ends with WFD_NONE.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfdCreatePort(device: u32, id: i32, attribs: *const i32) -> u32 {
    // SAFETY: the caller's list.
    let list = unsafe { pairs(attribs) };
    on(|w| w.create_port(device, id, list))
}

/// `wfdDestroyPort`.
#[unsafe(no_mangle)]
pub extern "C" fn wfdDestroyPort(device: u32, port: u32) {
    on(|w| w.destroy_port(device, port));
}

/// `wfdGetPortModes`.
///
/// # Safety
/// `modes` is null or has room for `count` handles.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfdGetPortModes(
    device: u32,
    port: u32,
    modes: *mut u32,
    count: i32,
) -> i32 {
    // SAFETY: the caller's array.
    let out = unsafe { output(modes, count.min(1)) };
    let out = out
        .filter(|_| count > 0)
        .or_else(|| (!modes.is_null()).then_some(&mut []));
    on(|w| w.get_port_modes(device, port, out))
}

/// `wfdGetPortModeAttribi`.
#[unsafe(no_mangle)]
pub extern "C" fn wfdGetPortModeAttribi(device: u32, port: u32, mode: u32, attrib: i32) -> i32 {
    on(|w| w.get_port_mode_attrib(device, port, mode, attrib))
}

/// `wfdGetPortModeAttribf`.
#[unsafe(no_mangle)]
pub extern "C" fn wfdGetPortModeAttribf(device: u32, port: u32, mode: u32, attrib: i32) -> f32 {
    on(|w| w.get_port_mode_attrib_f(device, port, mode, attrib))
}

/// `wfdSetPortMode`.
#[unsafe(no_mangle)]
pub extern "C" fn wfdSetPortMode(device: u32, port: u32, mode: u32) {
    on(|w| w.set_port_mode(device, port, mode));
}

/// `wfdGetCurrentPortMode`.
#[unsafe(no_mangle)]
pub extern "C" fn wfdGetCurrentPortMode(device: u32, port: u32) -> u32 {
    on(|w| w.get_current_port_mode(device, port))
}

/// `wfdGetPortAttribi`.
#[unsafe(no_mangle)]
pub extern "C" fn wfdGetPortAttribi(device: u32, port: u32, attrib: i32) -> i32 {
    on(|w| w.get_port_attrib(device, port, attrib))
}

/// `wfdGetPortAttribf`.
#[unsafe(no_mangle)]
pub extern "C" fn wfdGetPortAttribf(device: u32, port: u32, attrib: i32) -> f32 {
    on(|w| w.get_port_attrib_f(device, port, attrib))
}

/// `wfdGetPortAttribiv`.
///
/// # Safety
/// `value` is null or has room for `count` numbers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfdGetPortAttribiv(
    device: u32,
    port: u32,
    attrib: i32,
    count: i32,
    value: *mut i32,
) {
    // SAFETY: the caller's array.
    let out = unsafe { output(value, count) };
    on(|w| w.get_port_attrib_iv(device, port, attrib, count, out));
}

/// `wfdGetPortAttribfv`.
///
/// # Safety
/// `value` is null or has room for `count` numbers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfdGetPortAttribfv(
    device: u32,
    port: u32,
    attrib: i32,
    count: i32,
    value: *mut f32,
) {
    // SAFETY: the caller's array.
    let out = unsafe { output(value, count) };
    on(|w| w.get_port_attrib_fv(device, port, attrib, count, out));
}

/// `wfdSetPortAttribi`.
#[unsafe(no_mangle)]
pub extern "C" fn wfdSetPortAttribi(device: u32, port: u32, attrib: i32, value: i32) {
    on(|w| w.set_port_attrib(device, port, attrib, value));
}

/// `wfdSetPortAttribf`.
#[unsafe(no_mangle)]
pub extern "C" fn wfdSetPortAttribf(device: u32, port: u32, attrib: i32, value: f32) {
    on(|w| w.set_port_attrib_f(device, port, attrib, value));
}

/// `wfdSetPortAttribiv`.
///
/// # Safety
/// `value` is null or has `count` numbers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfdSetPortAttribiv(
    device: u32,
    port: u32,
    attrib: i32,
    count: i32,
    value: *const i32,
) {
    // SAFETY: the caller's array.
    let given = unsafe { input(value, count) };
    on(|w| w.set_port_attrib_iv(device, port, attrib, count, given));
}

/// `wfdSetPortAttribfv`.
///
/// # Safety
/// `value` is null or has `count` numbers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfdSetPortAttribfv(
    device: u32,
    port: u32,
    attrib: i32,
    count: i32,
    value: *const f32,
) {
    // SAFETY: the caller's array.
    let given = unsafe { input(value, count) };
    on(|w| w.set_port_attrib_fv(device, port, attrib, count, given));
}

/// `wfdBindPipelineToPort`.
#[unsafe(no_mangle)]
pub extern "C" fn wfdBindPipelineToPort(device: u32, port: u32, pipeline: u32) {
    on(|w| w.bind_pipeline_to_port(device, port, pipeline));
}

/// `wfdGetDisplayDataFormats`.
///
/// # Safety
/// `formats` is null or has room for `count` numbers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfdGetDisplayDataFormats(
    device: u32,
    port: u32,
    formats: *mut i32,
    count: i32,
) -> i32 {
    // SAFETY: the caller's array.
    let out = unsafe { output(formats, count.min(1)) };
    let out = out
        .filter(|_| count > 0)
        .or_else(|| (!formats.is_null()).then_some(&mut []));
    on(|w| w.get_display_data_formats(device, port, out))
}

/// `wfdGetDisplayData`: the display has none.
#[unsafe(no_mangle)]
pub extern "C" fn wfdGetDisplayData(
    device: u32,
    port: u32,
    format: i32,
    _data: *mut u8,
    _count: i32,
) -> i32 {
    on(|w| w.get_display_data(device, port, format))
}

/// `wfdEnumeratePipelines`.
///
/// # Safety
/// `ids` is null or has room for `count` numbers; `filter` ends with WFD_NONE.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfdEnumeratePipelines(
    device: u32,
    ids: *mut i32,
    count: i32,
    filter: *const i32,
) -> i32 {
    // SAFETY: the caller's arrays; at most 16 entries are written.
    let (filter, out) = unsafe { (pairs(filter), output(ids, count)) };
    let out = out
        .filter(|_| count > 0)
        .or_else(|| (!ids.is_null()).then_some(&mut []));
    on(|w| w.enumerate_pipelines(device, out, filter))
}

/// `wfdCreatePipeline`.
///
/// # Safety
/// `attribs` is null or ends with WFD_NONE.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfdCreatePipeline(device: u32, id: i32, attribs: *const i32) -> u32 {
    // SAFETY: the caller's list.
    let list = unsafe { pairs(attribs) };
    on(|w| w.create_pipeline(device, id, list))
}

/// `wfdDestroyPipeline`.
#[unsafe(no_mangle)]
pub extern "C" fn wfdDestroyPipeline(device: u32, pipeline: u32) {
    on(|w| w.destroy_pipeline(device, pipeline));
}

/// `wfdCreateSourceFromImage`: an image needs EGL, which the library has not.
#[unsafe(no_mangle)]
pub extern "C" fn wfdCreateSourceFromImage(
    device: u32,
    _pipeline: u32,
    _image: *mut c_void,
    _attribs: *const i32,
) -> u32 {
    on(|w| w.refuse(device, ERROR_NOT_SUPPORTED));
    0
}

/// `wfdCreateSourceFromStream`: `stream` is the descriptor `wfdStafetoStream`
/// gave.
///
/// # Safety
/// `attribs` is null or ends with WFD_NONE.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfdCreateSourceFromStream(
    device: u32,
    pipeline: u32,
    stream: *const layer::Stream,
    attribs: *const i32,
) -> u32 {
    // SAFETY: the caller's list.
    let list = unsafe { pairs(attribs) };
    let id = layer::stream_id(stream);
    on(|w| w.create_source_from_stream(device, pipeline, id, list))
}

/// `wfdDestroySource`.
#[unsafe(no_mangle)]
pub extern "C" fn wfdDestroySource(device: u32, source: u32) {
    on(|w| w.destroy_source(device, source));
}

/// `wfdCreateMaskFromImage`: an image needs EGL, which the library has not.
#[unsafe(no_mangle)]
pub extern "C" fn wfdCreateMaskFromImage(
    device: u32,
    _pipeline: u32,
    _image: *mut c_void,
    _attribs: *const i32,
) -> u32 {
    on(|w| w.refuse(device, ERROR_NOT_SUPPORTED));
    0
}

/// `wfdCreateMaskFromStream`: the pipelines have no masks.
///
/// # Safety
/// `attribs` is null or ends with WFD_NONE.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfdCreateMaskFromStream(
    device: u32,
    pipeline: u32,
    _stream: *const layer::Stream,
    attribs: *const i32,
) -> u32 {
    // SAFETY: the caller's list.
    let list = unsafe { pairs(attribs) };
    on(|w| w.create_mask_from_stream(device, pipeline, list))
}

/// `wfdDestroyMask`.
#[unsafe(no_mangle)]
pub extern "C" fn wfdDestroyMask(device: u32, mask: u32) {
    on(|w| w.destroy_mask(device, mask));
}

/// `wfdBindSourceToPipeline`: a stream has no region.
///
/// # Safety
/// `region` is null or points to a `WFDRect`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfdBindSourceToPipeline(
    device: u32,
    pipeline: u32,
    source: u32,
    transition: i32,
    region: *const Rect,
) {
    on(|w| w.bind_source_to_pipeline(device, pipeline, source, transition, !region.is_null()));
}

/// `wfdBindMaskToPipeline`.
#[unsafe(no_mangle)]
pub extern "C" fn wfdBindMaskToPipeline(device: u32, pipeline: u32, mask: u32, transition: i32) {
    on(|w| w.bind_mask_to_pipeline(device, pipeline, mask, transition));
}

/// `wfdGetPipelineAttribi`.
#[unsafe(no_mangle)]
pub extern "C" fn wfdGetPipelineAttribi(device: u32, pipeline: u32, attrib: i32) -> i32 {
    on(|w| w.get_pipeline_attrib(device, pipeline, attrib))
}

/// `wfdGetPipelineAttribf`.
#[unsafe(no_mangle)]
pub extern "C" fn wfdGetPipelineAttribf(device: u32, pipeline: u32, attrib: i32) -> f32 {
    on(|w| w.get_pipeline_attrib_f(device, pipeline, attrib))
}

/// `wfdGetPipelineAttribiv`.
///
/// # Safety
/// `value` is null or has room for `count` numbers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfdGetPipelineAttribiv(
    device: u32,
    pipeline: u32,
    attrib: i32,
    count: i32,
    value: *mut i32,
) {
    // SAFETY: the caller's array.
    let out = unsafe { output(value, count) };
    on(|w| w.get_pipeline_attrib_iv(device, pipeline, attrib, count, out));
}

/// `wfdGetPipelineAttribfv`.
///
/// # Safety
/// `value` is null or has room for `count` numbers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfdGetPipelineAttribfv(
    device: u32,
    pipeline: u32,
    attrib: i32,
    count: i32,
    value: *mut f32,
) {
    // SAFETY: the caller's array.
    let out = unsafe { output(value, count) };
    on(|w| w.get_pipeline_attrib_fv(device, pipeline, attrib, count, out));
}

/// `wfdSetPipelineAttribi`.
#[unsafe(no_mangle)]
pub extern "C" fn wfdSetPipelineAttribi(device: u32, pipeline: u32, attrib: i32, value: i32) {
    on(|w| w.set_pipeline_attrib(device, pipeline, attrib, value));
}

/// `wfdSetPipelineAttribf`.
#[unsafe(no_mangle)]
pub extern "C" fn wfdSetPipelineAttribf(device: u32, pipeline: u32, attrib: i32, value: f32) {
    on(|w| w.set_pipeline_attrib_f(device, pipeline, attrib, value));
}

/// `wfdSetPipelineAttribiv`.
///
/// # Safety
/// `value` is null or has `count` numbers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfdSetPipelineAttribiv(
    device: u32,
    pipeline: u32,
    attrib: i32,
    count: i32,
    value: *const i32,
) {
    // SAFETY: the caller's array.
    let given = unsafe { input(value, count) };
    on(|w| w.set_pipeline_attrib_iv(device, pipeline, attrib, count, given));
}

/// `wfdSetPipelineAttribfv`.
///
/// # Safety
/// `value` is null or has `count` numbers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfdSetPipelineAttribfv(
    device: u32,
    pipeline: u32,
    attrib: i32,
    count: i32,
    value: *const f32,
) {
    // SAFETY: the caller's array.
    let given = unsafe { input(value, count) };
    on(|w| w.set_pipeline_attrib_fv(device, pipeline, attrib, count, given));
}

/// `wfdGetPipelineTransparency`.
///
/// # Safety
/// `trans` is null or has room for `count` numbers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wfdGetPipelineTransparency(
    device: u32,
    pipeline: u32,
    trans: *mut u32,
    count: i32,
) -> i32 {
    // SAFETY: the caller's array.
    let out = unsafe { output(trans, count) };
    let out = out
        .filter(|_| count > 0)
        .or_else(|| (!trans.is_null()).then_some(&mut []));
    on(|w| w.get_pipeline_transparency(device, pipeline, out))
}

/// `wfdSetPipelineTSColor`: the colour of a transparent source is not
/// supported.
#[unsafe(no_mangle)]
pub extern "C" fn wfdSetPipelineTSColor(
    device: u32,
    pipeline: u32,
    format: i32,
    count: i32,
    color: *const c_void,
) {
    on(|w| w.set_pipeline_ts_color(device, pipeline, format, count, color.is_null()));
}

/// `wfdGetPipelineLayerOrder`.
#[unsafe(no_mangle)]
pub extern "C" fn wfdGetPipelineLayerOrder(device: u32, port: u32, pipeline: u32) -> i32 {
    on(|w| w.get_pipeline_layer_order(device, port, pipeline))
}

/// The extension `WFD_STAFETO_stream`: the stream of the driver's source
/// `kind` (0 the compositing target, 1 the pool, 2 the cursor picture), with
/// its address, as `struct stafeto_wfd_stream`. Null for a device that is
/// none (no error stored) or a kind that is none (ILLEGAL_ARGUMENT).
#[unsafe(no_mangle)]
pub extern "C" fn wfdStafetoStream(device: u32, kind: i32) -> *const layer::Stream {
    if layer::device() != device || device == 0 {
        return core::ptr::null();
    }
    if !(0..=2).contains(&kind) {
        on(|w| w.refuse(device, ERROR_ILLEGAL_ARGUMENT));
        return core::ptr::null();
    }
    match layer::stream(device, kind) {
        Some(stream) => stream,
        None => {
            on(|w| w.refuse(device, ERROR_OUT_OF_MEMORY));
            core::ptr::null()
        }
    }
}

/// The extension `WFD_STAFETO_cursor`: the hot spot of the cursor picture.
#[unsafe(no_mangle)]
pub extern "C" fn wfdStafetoSetCursorHotSpot(device: u32, pipeline: u32, x: i32, y: i32) {
    on(|w| w.set_cursor_hot_spot(device, pipeline, x, y));
}
