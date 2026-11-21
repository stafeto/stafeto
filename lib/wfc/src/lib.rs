// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! An OpenWF Composition 1.0 device over the scene session of the
//! composition service of stafeto (`proto_comp`), as logic with no kernel
//! call in it, so that the host tests it. The layer that makes the calls is
//! the C binding of the next step. `CLAUSES.md` is the table of functions,
//! states and clauses this crate is built and tested against.
//!
//! Every attribute, element, source, mask and the order of the scene is
//! cached here until `commit`, which builds the scene record bottom up (the
//! context rotation folded into each element) and gives it to the
//! [`Service`]. Only `commit`, `activate`, `deactivate`, `compose` and the
//! destroying of a context reach the service. The functions take the device
//! handle first, as the API does; a handle that is no device has no effect
//! and stores no error (specification 2.11).

#![cfg_attr(not(test), no_std)]

pub mod consts;
#[cfg(test)]
mod tests;

use consts::*;
use core::sync::atomic::{AtomicU32, Ordering};
use proto_comp::{
    ACTIVE, ASK_COMMITTED, ASK_COMPOSED, BILINEAR, COMMITTED_BIT, COMPOSED_BIT, Element, FORMAT_A8,
    MAX_ELEMENTS, MIRROR, NEAREST, NO_WINDOW, SceneCommit, TRANSPARENCY_MASK, transparency_allowed,
};
use proto_wire::Status;

/// The id of the device.
pub const DEVICE: i32 = 1;
/// The most sources and masks a device holds (the windows of the service).
pub const MAX_SOURCES: usize = 8;
pub const MAX_MASKS: usize = 8;
/// The most elements a device holds: what one SCENE_COMMIT carries.
pub const MAX_ELEMS: usize = MAX_ELEMENTS;

pub const VENDOR_NAME: &[u8] = b"stafeto\0";
pub const RENDERER_NAME: &[u8] = b"stafeto-compositor\0";
pub const VERSION_NAME: &[u8] = b"1.0\0";
pub const EXTENSION_STREAM: &[u8] = b"WFC_STAFETO_stream\0";
const EXTENSION_LIST: [&[u8]; 1] = [EXTENSION_STREAM];
const VENDOR_LIST: [&[u8]; 1] = [VENDOR_NAME];
const RENDERER_LIST: [&[u8]; 1] = [RENDERER_NAME];
const VERSION_LIST: [&[u8]; 1] = [VERSION_NAME];

/// What the layer below tells the device at its creation.
#[derive(Clone, Copy, Debug)]
pub struct Setup {
    pub width: u32,
    pub height: u32,
}

impl Setup {
    /// The screen of QEMU's virtio-gpu.
    pub const VIRTIO: Setup = Setup {
        width: 640,
        height: 400,
    };
}

/// What the layer above knows of a stream (a window of the service): its id,
/// its size and its format (`proto_comp::FORMAT_*`). Both never change
/// (specification 2.8.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamInfo {
    pub id: u32,
    pub width: u32,
    pub height: u32,
    pub format: u32,
}

/// The service the calls that reach it go through. Each method of a request
/// returns the status the service answered with.
pub trait Service {
    fn scene_commit(&mut self, commit: &SceneCommit) -> Result<(), Status>;
    fn scene_compose(&mut self, flags: u32) -> Result<(), Status>;
    /// Blocks until the bit of the scene's channel is set.
    fn wait(&mut self, bit: u64) -> Result<(), Status>;
    /// Forgets the bit, if it is set.
    fn clear(&mut self, bit: u64);
    /// Blocks until the service may have moved on, at most one frame.
    fn pause(&mut self) -> Result<(), Status>;
    /// Takes the one screen: false when it is taken (by any device).
    fn claim_screen(&mut self) -> bool;
    fn release_screen(&mut self);
}

// ------------------------------------------------------- the pure functions

fn floor64(x: f64) -> f64 {
    let t = x as i64 as f64;
    if t > x { t - 1.0 } else { t }
}

/// A float of the API as 16.16, rounded to the nearest, saturating at the
/// ends of the `i32`; NaN is 0.
pub fn to_fixed(x: f32) -> i32 {
    let v = floor64(f64::from(x) * 65536.0 + 0.5);
    v.clamp(f64::from(i32::MIN), f64::from(i32::MAX)) as i32
}

/// A float in 0 to 1 as 0 to 255, rounded to the nearest and clamped; NaN is 0.
pub fn to_alpha(x: f32) -> u32 {
    if x.is_nan() {
        return 0;
    }
    let v = floor64(f64::from(x.clamp(0.0, 1.0)) * 255.0 + 0.5);
    v as u32
}

/// A rectangle of floats as 16.16.
pub fn rect_to_fixed(r: [f32; 4]) -> [i32; 4] {
    [
        to_fixed(r[0]),
        to_fixed(r[1]),
        to_fixed(r[2]),
        to_fixed(r[3]),
    ]
}

/// The orientation of the record for an element rotated by `rotation` quarter
/// turns clockwise after a flip (top to bottom) when `flip` is set, under a
/// context rotated by `ctx` quarter turns: the record's rotation, then
/// whether it reflects about the vertical axis. See `CLAUSES.md` section 5.
pub fn fold(rotation: u32, flip: bool, ctx: u32) -> (u32, bool) {
    let sum = (rotation + ctx) % 4;
    if flip {
        ((6 - sum) % 4, true)
    } else {
        (sum, false)
    }
}

/// A rectangle (`x`, `y`, `w`, `h`) of the context's coordinates in the
/// target's, for the context rotated by `ctx` quarter turns clockwise and a
/// target of `width` by `height`.
pub fn fold_rect(r: [i32; 4], ctx: u32, width: i32, height: i32) -> [i32; 4] {
    let [x, y, w, h] = r;
    match ctx % 4 {
        0 => [x, y, w, h],
        1 => [width - y - h, x, h, w],
        2 => [width - x - w, height - y - h, w, h],
        _ => [y, height - x - w, h, w],
    }
}

fn floor(x: f32) -> f32 {
    floor64(f64::from(x)) as f32
}

fn quarter(rotation: i32) -> Option<u32> {
    match rotation {
        ROTATION_0 => Some(0),
        ROTATION_90 => Some(1),
        ROTATION_180 => Some(2),
        ROTATION_270 => Some(3),
        _ => None,
    }
}

/// The error a refusal of the service comes to (`CLAUSES.md` 4.2).
pub fn translate(status: Status) -> i32 {
    use abi::Error;
    match status {
        Status::Kernel(Error::LimitReached | Error::NoMemory) => ERROR_OUT_OF_MEMORY,
        Status::Kernel(Error::PeerClosed | Error::BadHandle) => ERROR_BAD_DEVICE,
        Status::Kernel(_) => ERROR_BAD_DEVICE,
        Status::BadSize => ERROR_ILLEGAL_ARGUMENT,
        Status::BadVersion | Status::UnknownMethod => ERROR_BAD_DEVICE,
        Status::Unknown(c) => match c {
            proto_comp::NOT_ALLOWED | proto_comp::INVALID => ERROR_ILLEGAL_ARGUMENT,
            proto_comp::BUSY => ERROR_BUSY,
            proto_comp::UNSUPPORTED => ERROR_UNSUPPORTED,
            _ => ERROR_BAD_DEVICE,
        },
        Status::Ok => ERROR_NONE,
    }
}

fn is_busy(s: Status) -> bool {
    s == Status::Unknown(proto_comp::BUSY)
}

// ------------------------------------------------------------------- state

static NEXT_HANDLE: AtomicU32 = AtomicU32::new(1);

fn new_handle() -> u32 {
    NEXT_HANDLE.fetch_add(1, Ordering::Relaxed)
}

#[derive(Clone, Copy)]
struct Ctx {
    handle: u32,
    rotation: i32,
    bg: [f32; 4],
    active: bool,
    committed: SceneCommit,
    compose_pending: bool,
}

#[derive(Clone, Copy)]
struct Elem {
    handle: u32,
    dst: [i32; 4],
    source: u32,
    src: [f32; 4],
    flip: bool,
    rotation: i32,
    filter: i32,
    transparency: u32,
    alpha: f32,
    mask: u32,
}

impl Elem {
    fn new() -> Elem {
        Elem {
            handle: new_handle(),
            dst: [0; 4],
            source: 0,
            src: [0.0; 4],
            flip: false,
            rotation: ROTATION_0,
            filter: SCALE_FILTER_NONE,
            transparency: 0,
            alpha: 1.0,
            mask: 0,
        }
    }
}

/// A source or a mask.
#[derive(Clone, Copy)]
struct Img {
    handle: u32,
    id: u32,
    width: u32,
    height: u32,
    alive: bool,
}

/// A device of OpenWF Composition.
pub struct Wfc {
    setup: Setup,
    device: u32,
    error: i32,
    lost: bool,
    ctx: Option<Ctx>,
    elems: [Option<Elem>; MAX_ELEMS],
    order: [u32; MAX_ELEMS],
    order_len: usize,
    sources: [Option<Img>; MAX_SOURCES],
    masks: [Option<Img>; MAX_MASKS],
}

fn empty_scene() -> SceneCommit {
    SceneCommit {
        flags: 0,
        bg: 0xFF00_0000,
        count: 0,
        elements: [Element::NONE; MAX_ELEMENTS],
    }
}

fn find_img(t: &[Option<Img>], handle: u32) -> Option<&Img> {
    t.iter().flatten().find(|i| i.handle == handle)
}

/// Whether an attribute list is empty (none is valid: 2.9).
fn list_empty(list: &[i32]) -> bool {
    list.first().is_none_or(|&a| a == 0)
}

impl Wfc {
    // ---------------------------------------------------------------- devices

    /// `wfcEnumerateDevices` (4.2): the ids written to `ids` and their total.
    pub fn enumerate_devices(ids: Option<&mut [i32]>, filter: &[i32]) -> i32 {
        let mut seen = false;
        let mut i = 0;
        while i < filter.len() && filter[i] != 0 {
            let value = filter.get(i + 1).copied();
            if filter[i] != DEVICE_FILTER_SCREEN_NUMBER || seen || value != Some(0) {
                return 0;
            }
            seen = true;
            i += 2;
        }
        if let Some(ids) = ids {
            if ids.is_empty() {
                return 0;
            }
            ids[0] = DEVICE;
        }
        1
    }

    /// `wfcCreateDevice` (4.3): a device, or None for an id that is none of
    /// the device's or an attribute list that is not empty.
    pub fn create_device(id: i32, attribs: &[i32], setup: Setup) -> Option<Wfc> {
        if (id != 0 && id != DEVICE) || !list_empty(attribs) {
            return None;
        }
        Some(Wfc {
            setup,
            device: new_handle(),
            error: ERROR_NONE,
            lost: false,
            ctx: None,
            elems: [None; MAX_ELEMS],
            order: [0; MAX_ELEMS],
            order_len: 0,
            sources: [None; MAX_SOURCES],
            masks: [None; MAX_MASKS],
        })
    }

    /// The device's handle.
    pub fn device(&self) -> u32 {
        self.device
    }

    fn raise(&mut self, error: i32) {
        if self.error == ERROR_NONE {
            self.error = error;
        }
    }

    fn is(&self, dev: u32) -> bool {
        dev != 0 && dev == self.device
    }

    /// Stores `error` for a call the layer above could not make; no effect
    /// for a handle that is no device.
    pub fn refuse(&mut self, dev: u32, error: i32) {
        if self.is(dev) {
            self.raise(error);
        }
    }

    /// Whether the device still has its service (`false` once a refusal said
    /// it is gone).
    pub fn is_lost(&self) -> bool {
        self.lost
    }

    fn fail(&mut self, status: Status) {
        let e = translate(status);
        if e == ERROR_BAD_DEVICE {
            self.lost = true;
        }
        self.raise(e);
    }

    /// `wfcGetError` (2.11).
    pub fn get_error(&mut self, dev: u32) -> i32 {
        if !self.is(dev) {
            return ERROR_BAD_DEVICE;
        }
        core::mem::replace(&mut self.error, ERROR_NONE)
    }

    /// `wfcGetDeviceAttribi` (4.4).
    pub fn device_attrib(&mut self, dev: u32, attrib: i32) -> i32 {
        if !self.is(dev) {
            return 0;
        }
        match attrib {
            DEVICE_CLASS => DEVICE_CLASS_FULLY_CAPABLE,
            DEVICE_ID => DEVICE,
            _ => {
                self.raise(ERROR_BAD_ATTRIBUTE);
                0
            }
        }
    }

    /// `wfcDestroyDevice` (4.5): the result of the call.
    pub fn destroy_device(&mut self, dev: u32, svc: &mut impl Service) -> i32 {
        if !self.is(dev) {
            return ERROR_BAD_DEVICE;
        }
        if let Some(ctx) = self.ctx.map(|c| c.handle) {
            self.destroy_context(dev, ctx, svc);
        }
        self.device = 0;
        self.elems = [None; MAX_ELEMS];
        self.sources = [None; MAX_SOURCES];
        self.masks = [None; MAX_MASKS];
        self.order_len = 0;
        ERROR_NONE
    }

    /// `wfcGetStrings` (10.3.2): the strings for `name`, which the caller
    /// copies as far as `count` allows. None for an invalid device (no error)
    /// or name or a negative count (ILLEGAL_ARGUMENT).
    pub fn strings(&mut self, dev: u32, name: i32, count: i32) -> Option<&'static [&'static [u8]]> {
        if !self.is(dev) {
            return None;
        }
        let list: &'static [&'static [u8]] = match name {
            VENDOR => &VENDOR_LIST,
            RENDERER => &RENDERER_LIST,
            VERSION => &VERSION_LIST,
            EXTENSIONS => &EXTENSION_LIST,
            _ => {
                self.raise(ERROR_ILLEGAL_ARGUMENT);
                return None;
            }
        };
        if count < 0 {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return None;
        }
        Some(list)
    }

    /// `wfcIsExtensionSupported` (10.3.2); `name` may end with a NUL.
    pub fn is_extension_supported(&mut self, dev: u32, name: &[u8]) -> bool {
        if !self.is(dev) {
            return false;
        }
        let name = name.strip_suffix(&[0]).unwrap_or(name);
        EXTENSION_LIST
            .iter()
            .any(|e| e.strip_suffix(&[0]).unwrap_or(e) == name)
    }

    /// The check of the extension `wfcNextStreamSTAFETO`: BAD_DEVICE once the
    /// service is lost. True when the layer above may go on.
    pub fn stream_allowed(&mut self, dev: u32) -> bool {
        if !self.is(dev) {
            return false;
        }
        if self.lost {
            self.raise(ERROR_BAD_DEVICE);
            return false;
        }
        true
    }

    // --------------------------------------------------------------- contexts

    fn ctx_ok(&mut self, ctx: u32) -> bool {
        if self.ctx.is_some_and(|c| c.handle == ctx) {
            true
        } else {
            self.raise(ERROR_BAD_HANDLE);
            false
        }
    }

    /// `wfcCreateOnScreenContext` (5.2); 0 on error.
    pub fn create_on_screen_context(
        &mut self,
        dev: u32,
        screen: i32,
        attribs: &[i32],
        svc: &mut impl Service,
    ) -> u32 {
        if !self.is(dev) {
            return 0;
        }
        if screen != 0 {
            self.raise(ERROR_UNSUPPORTED);
            return 0;
        }
        if !list_empty(attribs) {
            self.raise(ERROR_BAD_ATTRIBUTE);
            return 0;
        }
        if self.ctx.is_some() || !svc.claim_screen() {
            self.raise(ERROR_IN_USE);
            return 0;
        }
        let handle = new_handle();
        self.ctx = Some(Ctx {
            handle,
            rotation: ROTATION_0,
            bg: [0.0, 0.0, 0.0, 1.0],
            active: false,
            committed: empty_scene(),
            compose_pending: false,
        });
        handle
    }

    /// `wfcCreateOffScreenContext` (5.3): UNSUPPORTED, `CLAUSES.md` decision 10.
    pub fn create_off_screen_context(&mut self, dev: u32, _stream: u32, attribs: &[i32]) -> u32 {
        if !self.is(dev) {
            return 0;
        }
        if !list_empty(attribs) {
            self.raise(ERROR_BAD_ATTRIBUTE);
        } else {
            self.raise(ERROR_UNSUPPORTED);
        }
        0
    }

    /// `wfcDestroyContext` (5.7).
    pub fn destroy_context(&mut self, dev: u32, ctx: u32, svc: &mut impl Service) {
        if !self.is(dev) || !self.ctx_ok(ctx) {
            return;
        }
        let c = self.ctx.expect("checked");
        if !self.lost {
            if c.compose_pending
                && let Err(s) = svc.wait(COMPOSED_BIT)
            {
                self.fail(s);
            }
            if c.active
                && !self.lost
                && let Err(s) = svc.scene_commit(&SceneCommit {
                    flags: 0,
                    ..c.committed
                })
            {
                self.fail(s);
            }
        }
        svc.release_screen();
        self.ctx = None;
        self.elems = [None; MAX_ELEMS];
        self.sources = [None; MAX_SOURCES];
        self.masks = [None; MAX_MASKS];
        self.order_len = 0;
    }

    /// `wfcGetContextAttribi` (5.5).
    pub fn context_attrib_i(&mut self, dev: u32, ctx: u32, attrib: i32) -> i32 {
        if !self.is(dev) || !self.ctx_ok(ctx) {
            return 0;
        }
        let c = self.ctx.expect("checked");
        match attrib {
            CONTEXT_TYPE => CONTEXT_TYPE_ON_SCREEN,
            CONTEXT_TARGET_WIDTH => self.setup.width as i32,
            CONTEXT_TARGET_HEIGHT => self.setup.height as i32,
            CONTEXT_LOWEST_ELEMENT => {
                if self.order_len > 0 {
                    self.order[0] as i32
                } else {
                    0
                }
            }
            CONTEXT_ROTATION => c.rotation,
            CONTEXT_BG_COLOR => {
                let [r, g, b, a] = c.bg.map(to_alpha);
                ((r << 24) | (g << 16) | (b << 8) | a) as i32
            }
            _ => {
                self.raise(ERROR_BAD_ATTRIBUTE);
                0
            }
        }
    }

    /// `wfcGetContextAttribfv` (5.5): only the background colour.
    pub fn context_attrib_fv(&mut self, dev: u32, ctx: u32, attrib: i32, out: Option<&mut [f32]>) {
        if !self.is(dev) || !self.ctx_ok(ctx) {
            return;
        }
        if attrib != CONTEXT_BG_COLOR {
            self.raise(ERROR_BAD_ATTRIBUTE);
            return;
        }
        match out {
            Some(out) if out.len() == 4 => {
                out.copy_from_slice(&self.ctx.expect("checked").bg);
            }
            _ => self.raise(ERROR_ILLEGAL_ARGUMENT),
        }
    }

    /// `wfcSetContextAttribi` (5.6).
    pub fn set_context_attrib_i(&mut self, dev: u32, ctx: u32, attrib: i32, value: i32) {
        if !self.is(dev) || !self.ctx_ok(ctx) {
            return;
        }
        match attrib {
            CONTEXT_ROTATION => {
                if quarter(value).is_none() {
                    self.raise(ERROR_ILLEGAL_ARGUMENT);
                } else if let Some(c) = &mut self.ctx {
                    c.rotation = value;
                }
            }
            CONTEXT_BG_COLOR => {
                let v = value as u32;
                if v & 0xFF != 0xFF {
                    self.raise(ERROR_ILLEGAL_ARGUMENT);
                } else if let Some(c) = &mut self.ctx {
                    c.bg = [
                        (v >> 24) as f32 / 255.0,
                        ((v >> 16) & 0xFF) as f32 / 255.0,
                        ((v >> 8) & 0xFF) as f32 / 255.0,
                        1.0,
                    ];
                }
            }
            CONTEXT_TYPE
            | CONTEXT_TARGET_WIDTH
            | CONTEXT_TARGET_HEIGHT
            | CONTEXT_LOWEST_ELEMENT => self.raise(ERROR_BAD_ATTRIBUTE),
            _ => self.raise(ERROR_BAD_ATTRIBUTE),
        }
    }

    /// `wfcSetContextAttribfv` (5.6): only the background colour.
    pub fn set_context_attrib_fv(
        &mut self,
        dev: u32,
        ctx: u32,
        attrib: i32,
        values: Option<&[f32]>,
    ) {
        if !self.is(dev) || !self.ctx_ok(ctx) {
            return;
        }
        if attrib != CONTEXT_BG_COLOR {
            self.raise(ERROR_BAD_ATTRIBUTE);
            return;
        }
        match values {
            Some(v) if v.len() == 4 && v.iter().all(|x| (0.0..=1.0).contains(x)) && v[3] == 1.0 => {
                if let Some(c) = &mut self.ctx {
                    c.bg.copy_from_slice(v);
                }
            }
            _ => self.raise(ERROR_ILLEGAL_ARGUMENT),
        }
    }

    // ------------------------------------------------------ sources and masks

    fn create_img(&mut self, dev: u32, ctx: u32, stream: Option<StreamInfo>, mask: bool) -> u32 {
        if !self.is(dev) || !self.ctx_ok(ctx) {
            return 0;
        }
        if self.lost {
            self.raise(ERROR_BAD_DEVICE);
            return 0;
        }
        let Some(info) = stream else {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return 0;
        };
        if (info.format == FORMAT_A8) != mask {
            self.raise(ERROR_UNSUPPORTED);
            return 0;
        }
        let table = if mask {
            &mut self.masks[..]
        } else {
            &mut self.sources[..]
        };
        let Some(slot) = table.iter_mut().find(|s| s.is_none()) else {
            self.raise(ERROR_OUT_OF_MEMORY);
            return 0;
        };
        let handle = new_handle();
        *slot = Some(Img {
            handle,
            id: info.id,
            width: info.width,
            height: info.height,
            alive: true,
        });
        handle
    }

    /// `wfcCreateSourceFromStream` (6.1.1); 0 on error. `stream` is what the
    /// layer above found of the stream (None for one that does not exist).
    pub fn create_source_from_stream(
        &mut self,
        dev: u32,
        ctx: u32,
        stream: Option<StreamInfo>,
        attribs: &[i32],
    ) -> u32 {
        self.create_image(dev, ctx, stream, attribs, false)
    }

    /// `wfcCreateMaskFromStream` (6.2.1); 0 on error.
    pub fn create_mask_from_stream(
        &mut self,
        dev: u32,
        ctx: u32,
        stream: Option<StreamInfo>,
        attribs: &[i32],
    ) -> u32 {
        self.create_image(dev, ctx, stream, attribs, true)
    }

    fn create_image(
        &mut self,
        dev: u32,
        ctx: u32,
        stream: Option<StreamInfo>,
        attribs: &[i32],
        mask: bool,
    ) -> u32 {
        if self.is(dev) && self.ctx.is_some_and(|c| c.handle == ctx) && !list_empty(attribs) {
            self.raise(ERROR_BAD_ATTRIBUTE);
            return 0;
        }
        self.create_img(dev, ctx, stream, mask)
    }

    fn destroy_img(&mut self, dev: u32, handle: u32, mask: bool) {
        if !self.is(dev) {
            return;
        }
        let table = if mask {
            &mut self.masks[..]
        } else {
            &mut self.sources[..]
        };
        match table
            .iter_mut()
            .flatten()
            .find(|i| i.alive && i.handle == handle)
        {
            Some(i) => i.alive = false,
            None => self.raise(ERROR_BAD_HANDLE),
        }
        self.collect();
    }

    /// `wfcDestroySource` (6.1.2).
    pub fn destroy_source(&mut self, dev: u32, source: u32) {
        self.destroy_img(dev, source, false);
    }

    /// `wfcDestroyMask` (6.2.2).
    pub fn destroy_mask(&mut self, dev: u32, mask: u32) {
        self.destroy_img(dev, mask, true);
    }

    /// Frees the slots of dead sources and masks no element refers to.
    fn collect(&mut self) {
        let elems = self.elems;
        let used = |h: u32, f: fn(&Elem) -> u32| elems.iter().flatten().any(|e| f(e) == h);
        for s in &mut self.sources {
            if s.is_some_and(|i| !i.alive && !used(i.handle, |e| e.source)) {
                *s = None;
            }
        }
        for s in &mut self.masks {
            if s.is_some_and(|i| !i.alive && !used(i.handle, |e| e.mask)) {
                *s = None;
            }
        }
    }

    fn live_source(&self, h: u32) -> bool {
        self.sources
            .iter()
            .flatten()
            .any(|i| i.alive && i.handle == h)
    }

    fn live_mask(&self, h: u32) -> bool {
        self.masks
            .iter()
            .flatten()
            .any(|i| i.alive && i.handle == h)
    }

    // --------------------------------------------------------------- elements

    /// `wfcCreateElement` (7.2); 0 on error.
    pub fn create_element(&mut self, dev: u32, ctx: u32, attribs: &[i32]) -> u32 {
        if !self.is(dev) || !self.ctx_ok(ctx) {
            return 0;
        }
        if !list_empty(attribs) {
            self.raise(ERROR_BAD_ATTRIBUTE);
            return 0;
        }
        let Some(slot) = self.elems.iter_mut().find(|e| e.is_none()) else {
            self.raise(ERROR_OUT_OF_MEMORY);
            return 0;
        };
        let e = Elem::new();
        *slot = Some(e);
        e.handle
    }

    fn find(&mut self, dev: u32, element: u32) -> Option<usize> {
        if !self.is(dev) {
            return None;
        }
        let at = self
            .elems
            .iter()
            .position(|e| e.is_some_and(|e| e.handle == element));
        if at.is_none() {
            self.raise(ERROR_BAD_HANDLE);
        }
        at
    }

    fn elem(&mut self, at: usize) -> &mut Elem {
        self.elems[at].as_mut().expect("found")
    }

    fn in_scene(&self, element: u32) -> Option<usize> {
        self.order[..self.order_len]
            .iter()
            .position(|&h| h == element)
    }

    /// `wfcGetElementAttribi` (7.3).
    pub fn element_attrib_i(&mut self, dev: u32, element: u32, attrib: i32) -> i32 {
        let Some(at) = self.find(dev, element) else {
            return 0;
        };
        let e = *self.elem(at);
        match attrib {
            ELEMENT_SOURCE => e.source as i32,
            ELEMENT_SOURCE_FLIP => i32::from(e.flip),
            ELEMENT_SOURCE_ROTATION => e.rotation,
            ELEMENT_SOURCE_SCALE_FILTER => e.filter,
            ELEMENT_TRANSPARENCY_TYPES => e.transparency as i32,
            ELEMENT_GLOBAL_ALPHA => to_alpha(e.alpha) as i32,
            ELEMENT_MASK => e.mask as i32,
            _ => {
                self.raise(ERROR_BAD_ATTRIBUTE);
                0
            }
        }
    }

    /// `wfcGetElementAttribf` (7.3).
    pub fn element_attrib_f(&mut self, dev: u32, element: u32, attrib: i32) -> f32 {
        let Some(at) = self.find(dev, element) else {
            return 0.0;
        };
        if attrib != ELEMENT_GLOBAL_ALPHA {
            self.raise(ERROR_BAD_ATTRIBUTE);
            return 0.0;
        }
        self.elem(at).alpha
    }

    /// `wfcGetElementAttribiv` (7.3).
    pub fn element_attrib_iv(
        &mut self,
        dev: u32,
        element: u32,
        attrib: i32,
        out: Option<&mut [i32]>,
    ) {
        let Some(at) = self.find(dev, element) else {
            return;
        };
        let e = *self.elem(at);
        let values: [i32; 4] = match attrib {
            ELEMENT_DESTINATION_RECTANGLE => e.dst,
            ELEMENT_SOURCE_RECTANGLE => e.src.map(|x| floor(x) as i32),
            _ => {
                self.raise(ERROR_BAD_ATTRIBUTE);
                return;
            }
        };
        match out {
            Some(out) if out.len() == 4 => out.copy_from_slice(&values),
            _ => self.raise(ERROR_ILLEGAL_ARGUMENT),
        }
    }

    /// `wfcGetElementAttribfv` (7.3).
    pub fn element_attrib_fv(
        &mut self,
        dev: u32,
        element: u32,
        attrib: i32,
        out: Option<&mut [f32]>,
    ) {
        let Some(at) = self.find(dev, element) else {
            return;
        };
        let e = *self.elem(at);
        let values: [f32; 4] = match attrib {
            ELEMENT_DESTINATION_RECTANGLE => e.dst.map(|x| x as f32),
            ELEMENT_SOURCE_RECTANGLE => e.src,
            _ => {
                self.raise(ERROR_BAD_ATTRIBUTE);
                return;
            }
        };
        match out {
            Some(out) if out.len() == 4 => out.copy_from_slice(&values),
            _ => self.raise(ERROR_ILLEGAL_ARGUMENT),
        }
    }

    /// `wfcSetElementAttribi` (7.4).
    pub fn set_element_attrib_i(&mut self, dev: u32, element: u32, attrib: i32, value: i32) {
        let Some(at) = self.find(dev, element) else {
            return;
        };
        let v = value as u32;
        let ok = match attrib {
            ELEMENT_SOURCE => {
                let ok = v == 0 || self.live_source(v);
                if ok {
                    self.elem(at).source = v;
                }
                ok
            }
            ELEMENT_MASK => {
                let ok = v == 0 || self.live_mask(v);
                if ok {
                    self.elem(at).mask = v;
                }
                ok
            }
            ELEMENT_SOURCE_FLIP => {
                self.elem(at).flip = value != 0;
                true
            }
            ELEMENT_SOURCE_ROTATION => {
                let ok = quarter(value).is_some();
                if ok {
                    self.elem(at).rotation = value;
                }
                ok
            }
            ELEMENT_SOURCE_SCALE_FILTER => {
                let ok = matches!(
                    value,
                    SCALE_FILTER_NONE | SCALE_FILTER_FASTER | SCALE_FILTER_BETTER
                );
                if ok {
                    self.elem(at).filter = value;
                }
                ok
            }
            ELEMENT_TRANSPARENCY_TYPES => {
                let ok = transparency_allowed(v);
                if ok {
                    self.elem(at).transparency = v;
                }
                ok
            }
            ELEMENT_GLOBAL_ALPHA => {
                let ok = (0..=255).contains(&value);
                if ok {
                    self.elem(at).alpha = value as f32 / 255.0;
                }
                ok
            }
            _ => {
                self.raise(ERROR_BAD_ATTRIBUTE);
                return;
            }
        };
        if !ok {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
        }
        self.collect();
    }

    /// `wfcSetElementAttribf` (7.4).
    pub fn set_element_attrib_f(&mut self, dev: u32, element: u32, attrib: i32, value: f32) {
        let Some(at) = self.find(dev, element) else {
            return;
        };
        if attrib != ELEMENT_GLOBAL_ALPHA {
            self.raise(ERROR_BAD_ATTRIBUTE);
        } else if (0.0..=1.0).contains(&value) {
            self.elem(at).alpha = value;
        } else {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
        }
    }

    /// `wfcSetElementAttribiv` (7.4).
    pub fn set_element_attrib_iv(
        &mut self,
        dev: u32,
        element: u32,
        attrib: i32,
        values: Option<&[i32]>,
    ) {
        let Some(at) = self.find(dev, element) else {
            return;
        };
        if attrib != ELEMENT_DESTINATION_RECTANGLE && attrib != ELEMENT_SOURCE_RECTANGLE {
            self.raise(ERROR_BAD_ATTRIBUTE);
            return;
        }
        let Some(v) = values.and_then(|v| <[i32; 4]>::try_from(v).ok()) else {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return;
        };
        // Checked as integers: above 2^24 an `f32` would round the value.
        let max = i64::from(MAX_INT);
        if v.iter().any(|&x| i64::from(x).abs() > max) {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return;
        }
        if attrib == ELEMENT_DESTINATION_RECTANGLE {
            self.set_dst(at, v.map(|x| x as f32));
        } else {
            self.set_src(at, v.map(|x| x as f32));
        }
    }

    /// `wfcSetElementAttribfv` (7.4).
    pub fn set_element_attrib_fv(
        &mut self,
        dev: u32,
        element: u32,
        attrib: i32,
        values: Option<&[f32]>,
    ) {
        let Some(at) = self.find(dev, element) else {
            return;
        };
        if attrib != ELEMENT_DESTINATION_RECTANGLE && attrib != ELEMENT_SOURCE_RECTANGLE {
            self.raise(ERROR_BAD_ATTRIBUTE);
            return;
        }
        let Some(v) = values.and_then(|v| <[f32; 4]>::try_from(v).ok()) else {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return;
        };
        if attrib == ELEMENT_DESTINATION_RECTANGLE {
            self.set_dst(at, v);
        } else {
            self.set_src(at, v);
        }
    }

    fn set_dst(&mut self, at: usize, v: [f32; 4]) {
        let max = MAX_INT as f32;
        if v.iter().any(|x| !(-max..=max).contains(x)) {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return;
        }
        let r = v.map(|x| floor(x) as i32);
        if r[2] < 0 || r[3] < 0 {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return;
        }
        self.elem(at).dst = r;
    }

    fn set_src(&mut self, at: usize, v: [f32; 4]) {
        let max = MAX_INT as f32;
        if v.iter().any(|x| !(0.0..=max).contains(x)) {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return;
        }
        self.elem(at).src = v;
    }

    /// `wfcInsertElement` (7.5.1).
    pub fn insert_element(&mut self, dev: u32, element: u32, subordinate: u32) {
        let Some(_) = self.find(dev, element) else {
            return;
        };
        if subordinate != 0 && self.find(dev, subordinate).is_none() {
            return;
        }
        if subordinate == 0 {
            self.take_out(element);
            self.order.copy_within(0..self.order_len, 1);
            self.order[0] = element;
            self.order_len += 1;
            return;
        }
        if self.in_scene(subordinate).is_none() {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return;
        }
        if subordinate == element {
            return;
        }
        self.take_out(element);
        let above = self.in_scene(subordinate).expect("in scene") + 1;
        self.order.copy_within(above..self.order_len, above + 1);
        self.order[above] = element;
        self.order_len += 1;
    }

    fn take_out(&mut self, element: u32) {
        if let Some(at) = self.in_scene(element) {
            self.order.copy_within(at + 1..self.order_len, at);
            self.order_len -= 1;
        }
    }

    /// `wfcRemoveElement` (7.5.2).
    pub fn remove_element(&mut self, dev: u32, element: u32) {
        if self.find(dev, element).is_some() {
            self.take_out(element);
        }
    }

    fn neighbour(&mut self, dev: u32, element: u32, above: bool) -> u32 {
        if self.find(dev, element).is_none() {
            return 0;
        }
        let Some(at) = self.in_scene(element) else {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return 0;
        };
        if above {
            self.order[..self.order_len]
                .get(at + 1)
                .copied()
                .unwrap_or(0)
        } else if at == 0 {
            0
        } else {
            self.order[at - 1]
        }
    }

    /// `wfcGetElementAbove` (7.5.3).
    pub fn element_above(&mut self, dev: u32, element: u32) -> u32 {
        self.neighbour(dev, element, true)
    }

    /// `wfcGetElementBelow` (7.5.3).
    pub fn element_below(&mut self, dev: u32, element: u32) -> u32 {
        self.neighbour(dev, element, false)
    }

    /// `wfcDestroyElement` (7.6).
    pub fn destroy_element(&mut self, dev: u32, element: u32) {
        if let Some(at) = self.find(dev, element) {
            self.take_out(element);
            self.elems[at] = None;
            self.collect();
        }
    }

    // ------------------------------------------------------ commit and render

    /// The record `commit` sends, or the error that stops it.
    fn build(&self, ctx: &Ctx) -> Result<SceneCommit, i32> {
        let (w, h) = (self.setup.width as i32, self.setup.height as i32);
        let c = quarter(ctx.rotation).unwrap_or(0);
        let mut out = SceneCommit {
            flags: 0,
            bg: {
                let [r, g, b, _] = ctx.bg.map(to_alpha);
                0xFF00_0000 | (r << 16) | (g << 8) | b
            },
            count: 0,
            elements: [Element::NONE; MAX_ELEMENTS],
        };
        for &handle in &self.order[..self.order_len] {
            let e = self
                .elems
                .iter()
                .flatten()
                .find(|e| e.handle == handle)
                .expect("ordered");
            let source = find_img(&self.sources, e.source);
            let mask = find_img(&self.masks, e.mask);
            // Consistency (5.4, 7.1.3, 7.1.9), in floats.
            if let Some(s) = source
                && (e.src[0] + e.src[2] > s.width as f32 || e.src[1] + e.src[3] > s.height as f32)
            {
                return Err(ERROR_INCONSISTENCY);
            }
            if let Some(m) = mask
                && (e.dst[2] != m.width as i32 || e.dst[3] != m.height as i32)
            {
                return Err(ERROR_INCONSISTENCY);
            }
            let Some(s) = source else {
                continue;
            };
            let mut r = rect_to_fixed(e.src);
            // Trim to the edge of the window in 16.16, then drop a zero side.
            r[2] = r[2]
                .min((s.width as i32).saturating_mul(65536).saturating_sub(r[0]))
                .max(0);
            r[3] = r[3]
                .min((s.height as i32).saturating_mul(65536).saturating_sub(r[1]))
                .max(0);
            if r[2] == 0 || r[3] == 0 || e.dst[2] == 0 || e.dst[3] == 0 {
                continue;
            }
            let (orient, mirror) = fold(quarter(e.rotation).unwrap_or(0), e.flip, c);
            let d = fold_rect(e.dst, c, w, h);
            let mut t = e.transparency;
            let mask_id = match mask {
                Some(m) if t & TRANSPARENCY_MASK != 0 => m.id,
                _ => {
                    t &= !TRANSPARENCY_MASK;
                    NO_WINDOW
                }
            };
            out.elements[out.count as usize] = Element {
                source: s.id,
                mask: mask_id,
                sx: r[0],
                sy: r[1],
                sw: r[2],
                sh: r[3],
                dx: d[0],
                dy: d[1],
                dw: d[2],
                dh: d[3],
                orient: orient | if mirror { MIRROR } else { 0 },
                filter: if e.filter == SCALE_FILTER_BETTER {
                    BILINEAR
                } else {
                    NEAREST
                },
                transparency: t,
                alpha: to_alpha(e.alpha),
            };
            out.count += 1;
        }
        Ok(out)
    }

    /// `wfcCommit` (5.4).
    pub fn commit(&mut self, dev: u32, ctx: u32, wait: bool, svc: &mut impl Service) {
        if !self.is(dev) || !self.ctx_ok(ctx) {
            return;
        }
        if self.lost {
            self.raise(ERROR_BAD_DEVICE);
            return;
        }
        let c = self.ctx.expect("checked");
        let mut record = match self.build(&c) {
            Ok(r) => r,
            Err(e) => {
                self.raise(e);
                return;
            }
        };
        let accepted = SceneCommit { ..record };
        record.flags = (if c.active { ACTIVE } else { 0 }) | if wait { ASK_COMMITTED } else { 0 };
        loop {
            if wait {
                svc.clear(COMMITTED_BIT);
            }
            match svc.scene_commit(&record) {
                Ok(()) => break,
                Err(s) if wait && is_busy(s) => {
                    if let Err(s) = svc.pause() {
                        self.fail(s);
                        return;
                    }
                }
                Err(s) => {
                    self.fail(s);
                    return;
                }
            }
        }
        if let Some(c) = &mut self.ctx {
            c.committed = accepted;
        }
        if wait && let Err(s) = svc.wait(COMMITTED_BIT) {
            self.fail(s);
        }
    }

    fn set_active(&mut self, dev: u32, ctx: u32, active: bool, svc: &mut impl Service) {
        if !self.is(dev) || !self.ctx_ok(ctx) {
            return;
        }
        if self.lost {
            self.raise(ERROR_BAD_DEVICE);
            return;
        }
        let c = self.ctx.expect("checked");
        if c.active == active {
            return;
        }
        let flags = if active { ACTIVE } else { 0 };
        match svc.scene_commit(&SceneCommit {
            flags,
            ..c.committed
        }) {
            Ok(()) => {
                if let Some(c) = &mut self.ctx {
                    c.active = active;
                }
            }
            Err(s) => self.fail(s),
        }
    }

    /// `wfcActivate` (8.1).
    pub fn activate(&mut self, dev: u32, ctx: u32, svc: &mut impl Service) {
        self.set_active(dev, ctx, true, svc);
    }

    /// `wfcDeactivate` (8.2).
    pub fn deactivate(&mut self, dev: u32, ctx: u32, svc: &mut impl Service) {
        self.set_active(dev, ctx, false, svc);
    }

    /// `wfcCompose` (8.3).
    pub fn compose(&mut self, dev: u32, ctx: u32, wait: bool, svc: &mut impl Service) {
        if !self.is(dev) || !self.ctx_ok(ctx) {
            return;
        }
        if self.lost {
            self.raise(ERROR_BAD_DEVICE);
            return;
        }
        let c = self.ctx.expect("checked");
        if c.active {
            self.raise(ERROR_UNSUPPORTED);
            return;
        }
        loop {
            if wait || !c.compose_pending {
                svc.clear(COMPOSED_BIT);
            }
            match svc.scene_compose(ASK_COMPOSED) {
                Ok(()) => break,
                Err(s) if wait && is_busy(s) => {
                    if let Err(s) = svc.pause() {
                        self.fail(s);
                        return;
                    }
                }
                Err(s) => {
                    self.fail(s);
                    return;
                }
            }
        }
        if c.compose_pending && !wait {
            // The earlier frame is over, so its bit is stale.
            svc.clear(COMPOSED_BIT);
        }
        if let Some(c) = &mut self.ctx {
            c.compose_pending = true;
        }
        if wait {
            match svc.wait(COMPOSED_BIT) {
                Ok(()) => {
                    if let Some(c) = &mut self.ctx {
                        c.compose_pending = false;
                    }
                }
                Err(s) => self.fail(s),
            }
        }
    }

    /// `wfcFence` (9): ILLEGAL_ARGUMENT, there is no EGL display to pass.
    pub fn fence(&mut self, dev: u32, ctx: u32) {
        if self.is(dev) && self.ctx_ok(ctx) {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
        }
    }
}
