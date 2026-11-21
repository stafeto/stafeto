// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! An OpenWF Display 1.0 device over the display service of stafeto
//! (`proto_gpu` revision 3), as logic with no kernel call in it, so that the
//! host tests it. The layer that makes the calls is `posix_abi::wfd`, and
//! the C functions of `<WF/wfd.h>` are `posix_crt`'s `wfd_c.rs`.
//!
//! The device has one port (id 1) with one mode and the pipelines the
//! service reports (PIPELINES): on virtio-gpu pipeline 1 is the primary one
//! (the whole screen, layer 1) and pipeline 2 the cursor (a picture of 64 by
//! 64 points, layer 2). The state follows section 7 of the specification
//! (pre-configuration): the port mode is set, the power mode is ON, both
//! pipelines are bound to the port, and the primary pipeline shows the
//! compositing target. Everything a call changes is cached until
//! `commit`, which turns the changes of the pipelines into one LAYERS
//! request (`Commit`): the layer above sends it and reports the reply
//! (`finish_commit`).
//!
//! The rules the tables of the specification give for each function (the
//! errors, the defaults, the accessors an attribute allows) are the
//! methods' bodies; the tests name the section they check.

#![cfg_attr(not(test), no_std)]

pub mod consts;
#[cfg(test)]
mod tests;

use consts::*;
use proto_gpu::{
    LayerRow, Layers, MAX_PIPELINES, PIPELINE_CURSOR, PIPELINE_FULL_SCREEN, PIPELINE_HOT_SPOT,
    Pipeline, Pipelines, Rect, SourceInfo,
};

/// The id of the device and of its port.
pub const DEVICE: i32 = 1;
pub const PORT: i32 = 1;

/// The most sources, event containers and queued events the device holds.
pub const MAX_SOURCES: usize = 8;
pub const MAX_EVENTS: usize = 4;
pub const QUEUE_MAX: usize = 128;

/// The strings of `wfdGetStrings`, NUL-terminated.
pub const VENDOR_NAME: &[u8] = b"stafeto\0";
pub const RENDERER_NAME: &[u8] = b"virtio-gpu\0";
pub const VERSION_NAME: &[u8] = b"1.0\0";
pub const EXTENSION_STREAM: &[u8] = b"WFD_STAFETO_stream\0";
pub const EXTENSION_CURSOR: &[u8] = b"WFD_STAFETO_cursor\0";
const EXTENSION_LIST: [&[u8]; 2] = [EXTENSION_STREAM, EXTENSION_CURSOR];
const VENDOR_LIST: [&[u8]; 1] = [VENDOR_NAME];
const RENDERER_LIST: [&[u8]; 1] = [RENDERER_NAME];
const VERSION_LIST: [&[u8]; 1] = [VERSION_NAME];

/// What the layer below tells the device at its creation.
#[derive(Clone, Copy, Debug)]
pub struct Setup {
    pub width: u32,
    pub height: u32,
    /// The refresh rate of the one mode in hertz: the device tells none, the
    /// image's setting says.
    pub refresh_hz: u32,
    pub pipelines: Pipelines,
    pub sources: [SourceInfo; 3],
}

impl Setup {
    /// The device of QEMU's virtio-gpu at 60 hertz.
    pub const VIRTIO: Setup = Setup {
        width: proto_gpu::WIDTH,
        height: proto_gpu::HEIGHT,
        refresh_hz: 60,
        pipelines: Pipelines::VIRTIO,
        sources: SourceInfo::VIRTIO,
    };
}

/// The configuration of a pipeline that commit applies together.
#[derive(Clone, Copy, Debug, PartialEq)]
struct PipeCfg {
    src: [f32; 4],
    dst: [f32; 4],
    flip: bool,
    mirror: bool,
    rotation: i32,
    filter: i32,
    transparency: u32,
    alpha: f32,
    hot: (u32, u32),
}

impl PipeCfg {
    const DEFAULT: PipeCfg = PipeCfg {
        src: [0.0; 4],
        dst: [0.0; 4],
        flip: false,
        mirror: false,
        rotation: 0,
        filter: SCALE_FILTER_NONE,
        transparency: TRANSPARENCY_NONE,
        alpha: 1.0,
        hot: (0, 0),
    };
}

/// A binding: the source's handle (0 for the pre-configured one) and the
/// service's id of the source.
type Binding = (u32, u32);

#[derive(Clone, Copy, Debug)]
struct Pipe {
    rec: Pipeline,
    /// The handle of the pipeline made for direct use, 0 for none.
    handle: u32,
    cached: PipeCfg,
    committed: PipeCfg,
    /// The binding the display has now.
    bound: Option<Binding>,
    /// A bind call since the last commit: Some(None) unbinds.
    pending: Option<Option<Binding>>,
    /// Whether the display shows something of the pipeline now (a cursor
    /// that was hidden has a binding and shows nothing).
    shown: bool,
}

#[derive(Clone, Copy, Debug)]
struct Source {
    handle: u32,
    /// The pipeline's id the source was made for.
    pipeline: u32,
    /// The service's id of the source.
    id: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Queued {
    kind: i32,
    pipeline: u32,
    source: u32,
    overflow: bool,
}

const NO_EVENT: Queued = Queued {
    kind: EVENT_NONE,
    pipeline: 0,
    source: 0,
    overflow: false,
};

#[derive(Clone, Copy)]
struct Container {
    handle: u32,
    cap: usize,
    /// The bits of the event types that pass: bit k for `EVENT_INVALID + k`.
    filter: u32,
    waiting: bool,
    last: Queued,
    head: usize,
    len: usize,
    queue: [Queued; QUEUE_MAX],
}

/// What `event_poll` found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Poll {
    /// The event of this type came out of the queue.
    Event(i32),
    /// The queue is empty.
    Empty,
    /// The container or the device is gone.
    Gone,
}

/// One LAYERS request the layer above sends, and what completes when it is
/// answered.
#[derive(Clone, Copy, Debug)]
pub struct Commit {
    pub layers: Option<Layers>,
    /// The request has a primary row: the frame's bit completes it.
    pub frame: bool,
    done: Done,
    /// The pipelines the call covered.
    scope: [bool; MAX_PIPELINES],
    /// What the display shows of a pipeline after the request, for those it
    /// has a row of.
    shown: [Option<bool>; MAX_PIPELINES],
}

/// The bindings a commit completes: the pipeline's id and the handle of the
/// source it had.
type Done = [Option<(u32, u32)>; proto_gpu::MAX_LAYERS];

/// A device of OpenWF Display.
pub struct Wfd {
    setup: Setup,
    next: u32,
    device: u32,
    error: i32,
    port: u32,
    mode: u32,
    pipes: [Option<Pipe>; MAX_PIPELINES],
    sources: [Option<Source>; MAX_SOURCES],
    available: [bool; 3],
    /// The background colour of the port (it has no effect: the primary
    /// pipeline fills the port).
    background: [f32; 3],
    events: [Option<Container>; MAX_EVENTS],
    /// The pipelines whose completion waits for the frame's bit.
    awaiting: Option<Done>,
}

fn floor(x: f32) -> i32 {
    let t = x as i32;
    if (t as f32) > x { t - 1 } else { t }
}

fn round(x: f32) -> i32 {
    floor(x + 0.5)
}

/// Whether `x` is finite and inside the range the API takes.
fn in_range(x: f32) -> bool {
    (-(MAX_INT as f32)..=MAX_INT as f32).contains(&x)
}

fn bit(kind: i32) -> u32 {
    1 << (kind - EVENT_INVALID) as u32
}

impl Wfd {
    pub fn new(setup: Setup) -> Wfd {
        let mut pipes = [None; MAX_PIPELINES];
        for (slot, rec) in pipes.iter_mut().zip(setup.pipelines.as_slice()) {
            let primary = rec.has(PIPELINE_FULL_SCREEN);
            let mut cfg = PipeCfg::DEFAULT;
            if primary {
                // The pre-configured pipeline shows the target at the size of
                // the screen (specification, section 7).
                cfg.src = [0.0, 0.0, setup.width as f32, setup.height as f32];
                cfg.dst = cfg.src;
            }
            *slot = Some(Pipe {
                rec: *rec,
                handle: 0,
                cached: cfg,
                committed: cfg,
                bound: primary.then_some((0, proto_gpu::SOURCE_TARGET)),
                pending: None,
                shown: primary,
            });
        }
        let mut wfd = Wfd {
            setup,
            next: 1,
            device: 0,
            error: ERROR_NONE,
            port: 0,
            mode: 0,
            pipes,
            sources: [None; MAX_SOURCES],
            available: [true, false, false],
            background: [0.0; 3],
            events: [None; MAX_EVENTS],
            awaiting: None,
        };
        wfd.device = wfd.handle();
        wfd.mode = wfd.handle();
        wfd
    }

    fn handle(&mut self) -> u32 {
        let h = self.next;
        self.next += 1;
        h
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

    /// Whether `dev` is the device. A call with another handle has no effect
    /// and stores no error (2.11).
    fn is(&self, dev: u32) -> bool {
        dev == self.device
    }

    // ---------------------------------------------------------------- devices

    /// `wfdEnumerateDevices` (3.1): the ids written to `ids` and their total.
    /// A filter other than the empty one and the port id of the port returns
    /// no device.
    pub fn enumerate_devices(ids: Option<&mut [i32]>, filter: &[i32]) -> i32 {
        let mut pass = true;
        for pair in filter.chunks(2) {
            let (attrib, value) = (pair[0], pair.get(1).copied().unwrap_or(0));
            if attrib != DEVICE_FILTER_PORT_ID || pair.len() < 2 {
                return 0;
            }
            if value != WFD_INVALID && value != PORT {
                pass = false;
            }
        }
        if !pass {
            return 0;
        }
        if let Some(ids) = ids {
            if ids.is_empty() {
                return 0;
            }
            ids[0] = DEVICE;
        }
        1
    }

    /// Whether `id` is what `wfdCreateDevice` takes (3.2): the default or the
    /// device's own.
    pub fn device_id_valid(id: i32) -> bool {
        id == 0 || id == DEVICE
    }

    /// `wfdGetError` (2.11): the oldest error since the last call, and it
    /// clears. BAD_DEVICE for a handle that is no device.
    pub fn get_error(&mut self, dev: u32) -> i32 {
        if !self.is(dev) {
            return ERROR_BAD_DEVICE;
        }
        core::mem::replace(&mut self.error, ERROR_NONE)
    }

    /// `wfdGetStrings` (6.3.2): the strings for `name`, which the caller
    /// copies as far as `count` allows. None for an invalid device (no
    /// error) or name (ILLEGAL_ARGUMENT); a negative `count` is
    /// ILLEGAL_ARGUMENT too.
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

    /// `wfdIsExtensionSupported` (6.3.2): `name` is without its NUL.
    pub fn is_extension_supported(&self, dev: u32, name: &[u8]) -> bool {
        self.is(dev) && EXTENSION_LIST.iter().any(|e| &e[..e.len() - 1] == name)
    }

    /// `wfdGetDeviceAttribi` (3.5.2): the id is the one attribute.
    pub fn get_device_attrib(&mut self, dev: u32, attrib: i32) -> i32 {
        if !self.is(dev) {
            return 0;
        }
        if attrib == DEVICE_ID {
            return DEVICE;
        }
        self.raise(ERROR_BAD_ATTRIBUTE);
        0
    }

    /// `wfdSetDeviceAttribi` (3.5.3): the id is read-only, any other
    /// attribute is none.
    pub fn set_device_attrib(&mut self, dev: u32, _attrib: i32, _value: i32) {
        if self.is(dev) {
            self.raise(ERROR_BAD_ATTRIBUTE);
        }
    }

    // ------------------------------------------------------------------ ports

    fn port_ok(&mut self, port: u32) -> bool {
        if self.port != 0 && port == self.port {
            return true;
        }
        self.raise(ERROR_BAD_HANDLE);
        false
    }

    /// `wfdEnumeratePorts` (4.1). `ids` is None for a NULL array; a non-NULL
    /// one of no room is ILLEGAL_ARGUMENT.
    pub fn enumerate_ports(&mut self, dev: u32, ids: Option<&mut [i32]>, filter: &[i32]) -> i32 {
        if !self.is(dev) {
            return 0;
        }
        if ids.as_ref().is_some_and(|i| i.is_empty()) {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return 0;
        }
        // No filter attribute is defined.
        if !filter.is_empty() {
            return 0;
        }
        if let Some(ids) = ids {
            ids[0] = PORT;
        }
        1
    }

    /// `wfdCreatePort` (4.2): the handle, 0 for a failure.
    pub fn create_port(&mut self, dev: u32, id: i32, attribs: &[i32]) -> u32 {
        if !self.is(dev) {
            return 0;
        }
        if !attribs.is_empty() {
            self.raise(ERROR_BAD_ATTRIBUTE);
            return 0;
        }
        if id != PORT {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return 0;
        }
        if self.port != 0 {
            self.raise(ERROR_IN_USE);
            return 0;
        }
        self.port = self.handle();
        self.port
    }

    /// `wfdDestroyPort` (4.3).
    pub fn destroy_port(&mut self, dev: u32, port: u32) {
        if self.is(dev) && self.port_ok(port) {
            self.port = 0;
        }
    }

    /// `wfdGetPortModes` (4.4.2): the one mode.
    pub fn get_port_modes(&mut self, dev: u32, port: u32, modes: Option<&mut [u32]>) -> i32 {
        if !self.is(dev) || !self.port_ok(port) {
            return 0;
        }
        match modes {
            None => 1,
            Some([]) => {
                self.raise(ERROR_ILLEGAL_ARGUMENT);
                0
            }
            Some(m) => {
                m[0] = self.mode;
                1
            }
        }
    }

    /// The checks every mode call makes: the device, the port, the mode.
    fn mode_ok(&mut self, dev: u32, port: u32, mode: u32) -> bool {
        if !self.is(dev) || !self.port_ok(port) {
            return false;
        }
        if mode != self.mode {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return false;
        }
        true
    }

    /// `wfdGetPortModeAttribi` (4.4.3).
    pub fn get_port_mode_attrib(&mut self, dev: u32, port: u32, mode: u32, attrib: i32) -> i32 {
        if !self.mode_ok(dev, port, mode) {
            return 0;
        }
        match attrib {
            PORT_MODE_WIDTH => self.setup.width as i32,
            PORT_MODE_HEIGHT => self.setup.height as i32,
            PORT_MODE_REFRESH_RATE => self.setup.refresh_hz as i32,
            PORT_MODE_FLIP_MIRROR_SUPPORT | PORT_MODE_INTERLACED => 0,
            PORT_MODE_ROTATION_SUPPORT => ROTATION_SUPPORT_NONE,
            _ => {
                self.raise(ERROR_BAD_ATTRIBUTE);
                0
            }
        }
    }

    /// `wfdGetPortModeAttribf` (4.4.3): the refresh rate is the one float
    /// attribute; the others have no float accessor.
    pub fn get_port_mode_attrib_f(&mut self, dev: u32, port: u32, mode: u32, attrib: i32) -> f32 {
        if !self.mode_ok(dev, port, mode) {
            return 0.0;
        }
        if attrib == PORT_MODE_REFRESH_RATE {
            return self.setup.refresh_hz as f32;
        }
        self.raise(ERROR_BAD_ATTRIBUTE);
        0.0
    }

    /// `wfdSetPortMode` (4.4.4): the mode is the one there is.
    pub fn set_port_mode(&mut self, dev: u32, port: u32, mode: u32) {
        self.mode_ok(dev, port, mode);
    }

    /// `wfdGetCurrentPortMode` (4.4.5): the mode is pre-configured (7).
    pub fn get_current_port_mode(&mut self, dev: u32, port: u32) -> u32 {
        if !self.is(dev) || !self.port_ok(port) {
            return 0;
        }
        self.mode
    }

    fn port_attrib_ok(&mut self, dev: u32, port: u32) -> bool {
        self.is(dev) && self.port_ok(port)
    }

    /// `wfdGetPortAttribi` (4.5.2).
    pub fn get_port_attrib(&mut self, dev: u32, port: u32, attrib: i32) -> i32 {
        if !self.port_attrib_ok(dev, port) {
            return 0;
        }
        match attrib {
            PORT_ID => PORT,
            PORT_TYPE => PORT_TYPE_INTERNAL,
            PORT_DETACHABLE => 0,
            PORT_ATTACHED | PORT_FILL_PORT_AREA => 1,
            PORT_FLIP | PORT_MIRROR | PORT_ROTATION | PORT_PROTECTION_ENABLE => 0,
            PORT_POWER_MODE => POWER_MODE_ON,
            PORT_PARTIAL_REFRESH_SUPPORT | PORT_PARTIAL_REFRESH_ENABLE => PARTIAL_REFRESH_NONE,
            PORT_PIPELINE_ID_COUNT => self.setup.pipelines.as_slice().len() as i32,
            // The background colour as 0xRRGGBBFF.
            PORT_BACKGROUND_COLOR => {
                let c = |i: usize| round(self.background[i].clamp(0.0, 1.0) * 255.0) as u32;
                ((c(0) << 24) | (c(1) << 16) | (c(2) << 8) | 0xFF) as i32
            }
            _ => {
                self.raise(ERROR_BAD_ATTRIBUTE);
                0
            }
        }
    }

    /// `wfdGetPortAttribf` (4.5.2): the gamma is the one float.
    pub fn get_port_attrib_f(&mut self, dev: u32, port: u32, attrib: i32) -> f32 {
        if !self.port_attrib_ok(dev, port) {
            return 0.0;
        }
        if attrib == PORT_GAMMA {
            return 1.0;
        }
        self.raise(ERROR_BAD_ATTRIBUTE);
        0.0
    }

    /// The count and the check of a vector call: `Some(n)` when `attrib` has
    /// `n` elements in the accessor's kind (`floats`).
    fn port_vector(&mut self, attrib: i32, floats: bool) -> Option<usize> {
        let n = match (attrib, floats) {
            (PORT_NATIVE_RESOLUTION | PORT_PARTIAL_REFRESH_MAXIMUM, false) => 2,
            (PORT_PARTIAL_REFRESH_RECTANGLE, false) => 4,
            (PORT_BACKGROUND_COLOR, _) => 3,
            (PORT_PHYSICAL_SIZE | PORT_GAMMA_RANGE, true) => 2,
            (PORT_BINDABLE_PIPELINE_IDS, false) => self.setup.pipelines.as_slice().len(),
            _ => {
                self.raise(ERROR_BAD_ATTRIBUTE);
                return None;
            }
        };
        Some(n)
    }

    /// `wfdGetPortAttribiv` (4.5.2).
    pub fn get_port_attrib_iv(
        &mut self,
        dev: u32,
        port: u32,
        attrib: i32,
        count: i32,
        value: Option<&mut [i32]>,
    ) {
        if !self.port_attrib_ok(dev, port) {
            return;
        }
        let Some(n) = self.port_vector(attrib, false) else {
            return;
        };
        let Some(value) = value.filter(|_| count == n as i32) else {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return;
        };
        match attrib {
            PORT_NATIVE_RESOLUTION => {
                value[..2].copy_from_slice(&[self.setup.width as i32, self.setup.height as i32])
            }
            PORT_BINDABLE_PIPELINE_IDS => {
                for (v, p) in value.iter_mut().zip(self.setup.pipelines.as_slice()) {
                    *v = p.id as i32;
                }
            }
            PORT_BACKGROUND_COLOR => {
                for (v, c) in value.iter_mut().zip(self.background) {
                    *v = round(c.clamp(0.0, 1.0) * 255.0);
                }
            }
            _ => value[..n].fill(0),
        }
    }

    /// `wfdGetPortAttribfv` (4.5.2).
    pub fn get_port_attrib_fv(
        &mut self,
        dev: u32,
        port: u32,
        attrib: i32,
        count: i32,
        value: Option<&mut [f32]>,
    ) {
        if !self.port_attrib_ok(dev, port) {
            return;
        }
        let Some(n) = self.port_vector(attrib, true) else {
            return;
        };
        let Some(value) = value.filter(|_| count == n as i32) else {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return;
        };
        match attrib {
            PORT_GAMMA_RANGE => value[..2].copy_from_slice(&[1.0, 1.0]),
            PORT_BACKGROUND_COLOR => value[..3].copy_from_slice(&self.background),
            _ => value[..n].fill(0.0),
        }
    }

    /// `wfdSetPortAttribi` (4.5.3): the writable attributes of a port that
    /// can do none of them take their one value only.
    pub fn set_port_attrib(&mut self, dev: u32, port: u32, attrib: i32, value: i32) {
        if !self.port_attrib_ok(dev, port) {
            return;
        }
        let ok = match attrib {
            // No flip, mirror, rotation or protection.
            PORT_FLIP | PORT_MIRROR | PORT_ROTATION | PORT_PROTECTION_ENABLE => value == 0,
            PORT_PARTIAL_REFRESH_ENABLE => value == PARTIAL_REFRESH_NONE,
            // A display that cannot be turned off stays on.
            PORT_POWER_MODE => value == POWER_MODE_ON,
            // 0xRRGGBBFF: the low byte is 255 when written.
            PORT_BACKGROUND_COLOR => {
                let v = value as u32;
                let low = v & 0xFF == 0xFF;
                if low {
                    for (i, c) in self.background.iter_mut().enumerate() {
                        *c = ((v >> (24 - 8 * i)) & 0xFF) as f32 / 255.0;
                    }
                }
                low
            }
            _ => {
                self.raise(ERROR_BAD_ATTRIBUTE);
                return;
            }
        };
        if !ok {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
        }
    }

    /// `wfdSetPortAttribf` (4.5.3): the gamma, whose range is [1, 1].
    pub fn set_port_attrib_f(&mut self, dev: u32, port: u32, attrib: i32, value: f32) {
        if !self.port_attrib_ok(dev, port) {
            return;
        }
        if attrib != PORT_GAMMA {
            self.raise(ERROR_BAD_ATTRIBUTE);
        } else if value != 1.0 {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
        }
    }

    /// `wfdSetPortAttribiv` (4.5.3): the colour as three bytes, the partial
    /// refresh rectangle (which only empty values suit).
    pub fn set_port_attrib_iv(
        &mut self,
        dev: u32,
        port: u32,
        attrib: i32,
        count: i32,
        value: Option<&[i32]>,
    ) {
        if !self.port_attrib_ok(dev, port) {
            return;
        }
        if !matches!(
            attrib,
            PORT_BACKGROUND_COLOR | PORT_PARTIAL_REFRESH_RECTANGLE
        ) {
            self.raise(ERROR_BAD_ATTRIBUTE);
            return;
        }
        let n = if attrib == PORT_BACKGROUND_COLOR {
            3
        } else {
            4
        };
        let Some(value) = value.filter(|_| count == n) else {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return;
        };
        let ok = if attrib == PORT_BACKGROUND_COLOR {
            value[..3].iter().all(|c| (0..=255).contains(c))
        } else {
            value[..4].iter().all(|c| *c == 0)
        };
        if !ok {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
        } else if attrib == PORT_BACKGROUND_COLOR {
            for (to, from) in self.background.iter_mut().zip(value) {
                *to = *from as f32 / 255.0;
            }
        }
    }

    /// `wfdSetPortAttribfv` (4.5.3): the colour as three floats of [0, 1].
    pub fn set_port_attrib_fv(
        &mut self,
        dev: u32,
        port: u32,
        attrib: i32,
        count: i32,
        value: Option<&[f32]>,
    ) {
        if !self.port_attrib_ok(dev, port) {
            return;
        }
        if attrib != PORT_BACKGROUND_COLOR {
            self.raise(ERROR_BAD_ATTRIBUTE);
            return;
        }
        let Some(value) = value.filter(|_| count == 3) else {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return;
        };
        if !value[..3].iter().all(|c| (0.0..=1.0).contains(c)) {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
        } else {
            self.background.copy_from_slice(&value[..3]);
        }
    }

    /// `wfdBindPipelineToPort` (4.6): both pipelines are bound to the one
    /// port already, so a valid call changes nothing.
    pub fn bind_pipeline_to_port(&mut self, dev: u32, port: u32, pipeline: u32) {
        if !self.is(dev) || !self.port_ok(port) {
            return;
        }
        if self.pipe_index(pipeline).is_none() {
            self.raise(ERROR_BAD_HANDLE);
        }
    }

    /// `wfdGetDisplayDataFormats` (4.7.1): the display has no data.
    pub fn get_display_data_formats(
        &mut self,
        dev: u32,
        port: u32,
        formats: Option<&mut [i32]>,
    ) -> i32 {
        if !self.is(dev) || !self.port_ok(port) {
            return 0;
        }
        if formats.is_some_and(|f| f.is_empty()) {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
        }
        0
    }

    /// `wfdGetDisplayData` (4.7.2): no format is valid for the port.
    pub fn get_display_data(&mut self, dev: u32, port: u32, _format: i32) -> i32 {
        if self.is(dev) && self.port_ok(port) {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
        }
        0
    }

    // -------------------------------------------------------------- pipelines

    fn pipe_index(&self, handle: u32) -> Option<usize> {
        if handle == 0 {
            return None;
        }
        self.pipes
            .iter()
            .position(|p| p.as_ref().is_some_and(|p| p.handle == handle))
    }

    /// The pipeline of `handle`, or BAD_HANDLE.
    fn pipe_of(&mut self, handle: u32) -> Option<usize> {
        let found = self.pipe_index(handle);
        if found.is_none() {
            self.raise(ERROR_BAD_HANDLE);
        }
        found
    }

    fn pipe(&self, at: usize) -> &Pipe {
        self.pipes[at].as_ref().expect("a pipeline of the table")
    }

    fn pipe_mut(&mut self, at: usize) -> &mut Pipe {
        self.pipes[at].as_mut().expect("a pipeline of the table")
    }

    /// `wfdEnumeratePipelines` (5.2).
    pub fn enumerate_pipelines(
        &mut self,
        dev: u32,
        ids: Option<&mut [i32]>,
        filter: &[i32],
    ) -> i32 {
        if !self.is(dev) {
            return 0;
        }
        if ids.as_ref().is_some_and(|i| i.is_empty()) {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return 0;
        }
        if !filter.is_empty() {
            return 0;
        }
        let list = self.setup.pipelines.as_slice();
        if let Some(ids) = ids {
            for (to, p) in ids.iter_mut().zip(list) {
                *to = p.id as i32;
            }
            return ids.len().min(list.len()) as i32;
        }
        list.len() as i32
    }

    /// `wfdCreatePipeline` (5.3).
    pub fn create_pipeline(&mut self, dev: u32, id: i32, attribs: &[i32]) -> u32 {
        if !self.is(dev) {
            return 0;
        }
        if !attribs.is_empty() {
            self.raise(ERROR_BAD_ATTRIBUTE);
            return 0;
        }
        let Some(at) = self
            .pipes
            .iter()
            .position(|p| p.as_ref().is_some_and(|p| p.rec.id as i32 == id))
        else {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return 0;
        };
        if self.pipe(at).handle != 0 {
            self.raise(ERROR_IN_USE);
            return 0;
        }
        let handle = self.handle();
        self.pipe_mut(at).handle = handle;
        handle
    }

    /// `wfdDestroyPipeline` (5.4): the pipeline's sources go with it and its
    /// cached changes are dropped; the display keeps what it shows.
    pub fn destroy_pipeline(&mut self, dev: u32, pipeline: u32) {
        if !self.is(dev) {
            return;
        }
        let Some(at) = self.pipe_of(pipeline) else {
            return;
        };
        let id = self.pipe(at).rec.id;
        for s in self.sources.iter_mut() {
            if s.is_some_and(|s| s.pipeline == id) {
                *s = None;
            }
        }
        let p = self.pipe_mut(at);
        p.handle = 0;
        p.cached = p.committed;
        p.pending = None;
    }

    /// The layer of a pipeline: 1 for the lowest (5.7.1.2).
    fn layer(&self, at: usize) -> i32 {
        let depth = self.pipe(at).rec.depth;
        1 + self
            .pipes
            .iter()
            .flatten()
            .filter(|p| p.rec.depth < depth)
            .count() as i32
    }

    /// `wfdGetPipelineLayerOrder` (5.9).
    pub fn get_pipeline_layer_order(&mut self, dev: u32, port: u32, pipeline: u32) -> i32 {
        if !self.is(dev) {
            return 0;
        }
        let port_ok = self.port_ok(port);
        let pipe = self.pipe_of(pipeline);
        match (port_ok, pipe) {
            (true, Some(at)) => self.layer(at),
            _ => 0,
        }
    }

    /// `wfdGetPipelineAttribi` (5.7.2).
    pub fn get_pipeline_attrib(&mut self, dev: u32, pipeline: u32, attrib: i32) -> i32 {
        if !self.is(dev) {
            return 0;
        }
        let Some(at) = self.pipe_of(pipeline) else {
            return 0;
        };
        let p = *self.pipe(at);
        match attrib {
            PIPELINE_ID => p.rec.id as i32,
            PIPELINE_PORTID => PORT,
            PIPELINE_LAYER => self.layer(at),
            PIPELINE_SHAREABLE | PIPELINE_DIRECT_REFRESH => 0,
            PIPELINE_FLIP => p.cached.flip as i32,
            PIPELINE_MIRROR => p.cached.mirror as i32,
            PIPELINE_ROTATION_SUPPORT => ROTATION_SUPPORT_NONE,
            PIPELINE_ROTATION => p.cached.rotation,
            PIPELINE_SCALE_FILTER => p.cached.filter,
            PIPELINE_TRANSPARENCY_ENABLE => p.cached.transparency as i32,
            PIPELINE_GLOBAL_ALPHA => round(p.cached.alpha.clamp(0.0, 1.0) * 255.0),
            _ => {
                self.raise(ERROR_BAD_ATTRIBUTE);
                0
            }
        }
    }

    /// `wfdGetPipelineAttribf` (5.7.2): the global alpha.
    pub fn get_pipeline_attrib_f(&mut self, dev: u32, pipeline: u32, attrib: i32) -> f32 {
        if !self.is(dev) {
            return 0.0;
        }
        let Some(at) = self.pipe_of(pipeline) else {
            return 0.0;
        };
        if attrib == PIPELINE_GLOBAL_ALPHA {
            return self.pipe(at).cached.alpha;
        }
        self.raise(ERROR_BAD_ATTRIBUTE);
        0.0
    }

    /// The elements of a pipeline vector attribute that the accessor allows.
    fn pipe_vector(&mut self, attrib: i32, floats: bool) -> Option<usize> {
        match (attrib, floats) {
            (PIPELINE_MAX_SOURCE_SIZE, _) => Some(2),
            (PIPELINE_SOURCE_RECTANGLE | PIPELINE_DESTINATION_RECTANGLE, _) => Some(4),
            (PIPELINE_SCALE_RANGE, true) => Some(2),
            _ => {
                self.raise(ERROR_BAD_ATTRIBUTE);
                None
            }
        }
    }

    /// `wfdGetPipelineAttribiv` (5.7.2): sizes and rectangles; the integer
    /// is the floor of the float.
    pub fn get_pipeline_attrib_iv(
        &mut self,
        dev: u32,
        pipeline: u32,
        attrib: i32,
        count: i32,
        value: Option<&mut [i32]>,
    ) {
        if !self.is(dev) {
            return;
        }
        let Some(at) = self.pipe_of(pipeline) else {
            return;
        };
        let Some(n) = self.pipe_vector(attrib, false) else {
            return;
        };
        let Some(value) = value.filter(|_| count == n as i32) else {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return;
        };
        let p = *self.pipe(at);
        match attrib {
            PIPELINE_MAX_SOURCE_SIZE => {
                value[..2].copy_from_slice(&[p.rec.max_w as i32, p.rec.max_h as i32])
            }
            PIPELINE_SOURCE_RECTANGLE => {
                for (v, f) in value.iter_mut().zip(p.cached.src) {
                    *v = floor(f);
                }
            }
            _ => {
                for (v, f) in value.iter_mut().zip(p.cached.dst) {
                    *v = floor(f);
                }
            }
        }
    }

    /// `wfdGetPipelineAttribfv` (5.7.2).
    pub fn get_pipeline_attrib_fv(
        &mut self,
        dev: u32,
        pipeline: u32,
        attrib: i32,
        count: i32,
        value: Option<&mut [f32]>,
    ) {
        if !self.is(dev) {
            return;
        }
        let Some(at) = self.pipe_of(pipeline) else {
            return;
        };
        let Some(n) = self.pipe_vector(attrib, true) else {
            return;
        };
        let Some(value) = value.filter(|_| count == n as i32) else {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return;
        };
        let p = *self.pipe(at);
        match attrib {
            PIPELINE_MAX_SOURCE_SIZE => {
                value[..2].copy_from_slice(&[p.rec.max_w as f32, p.rec.max_h as f32])
            }
            PIPELINE_SCALE_RANGE => value[..2].copy_from_slice(&[1.0, 1.0]),
            PIPELINE_SOURCE_RECTANGLE => value[..4].copy_from_slice(&p.cached.src),
            _ => value[..4].copy_from_slice(&p.cached.dst),
        }
    }

    /// The transparency features a pipeline has (5.8): the cursor's picture
    /// carries its alpha; the primary pipeline has none.
    fn transparency_list(&self, at: usize) -> &'static [u32] {
        if self.pipe(at).rec.kind == proto_gpu::KIND_CURSOR {
            &[TRANSPARENCY_SOURCE_ALPHA]
        } else {
            &[]
        }
    }

    /// `wfdGetPipelineTransparency` (5.8.2).
    pub fn get_pipeline_transparency(
        &mut self,
        dev: u32,
        pipeline: u32,
        trans: Option<&mut [u32]>,
    ) -> i32 {
        if !self.is(dev) {
            return 0;
        }
        let Some(at) = self.pipe_of(pipeline) else {
            return 0;
        };
        let list = self.transparency_list(at);
        match trans {
            None => list.len() as i32,
            Some([]) => {
                self.raise(ERROR_ILLEGAL_ARGUMENT);
                0
            }
            Some(t) => {
                for (to, f) in t.iter_mut().zip(list) {
                    *to = *f;
                }
                t.len().min(list.len()) as i32
            }
        }
    }

    /// `wfdSetPipelineAttribi` (5.7.3).
    pub fn set_pipeline_attrib(&mut self, dev: u32, pipeline: u32, attrib: i32, value: i32) {
        if !self.is(dev) {
            return;
        }
        let Some(at) = self.pipe_of(pipeline) else {
            return;
        };
        let list = self.transparency_list(at);
        let ok = match attrib {
            // No flip, mirror or rotation.
            PIPELINE_FLIP | PIPELINE_MIRROR | PIPELINE_ROTATION => value == 0,
            PIPELINE_SCALE_FILTER => {
                matches!(
                    value,
                    SCALE_FILTER_NONE | SCALE_FILTER_FASTER | SCALE_FILTER_BETTER
                ) && {
                    self.pipe_mut(at).cached.filter = value;
                    true
                }
            }
            PIPELINE_TRANSPARENCY_ENABLE => {
                let v = value as u32;
                (value >= 0 && (v == TRANSPARENCY_NONE || list.contains(&v))) && {
                    self.pipe_mut(at).cached.transparency = v;
                    true
                }
            }
            PIPELINE_GLOBAL_ALPHA => {
                (0..=255).contains(&value) && {
                    self.pipe_mut(at).cached.alpha = value as f32 / 255.0;
                    true
                }
            }
            _ => {
                self.raise(ERROR_BAD_ATTRIBUTE);
                return;
            }
        };
        if !ok {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
        }
    }

    /// `wfdSetPipelineAttribf` (5.7.3): the global alpha as a float.
    pub fn set_pipeline_attrib_f(&mut self, dev: u32, pipeline: u32, attrib: i32, value: f32) {
        if !self.is(dev) {
            return;
        }
        let Some(at) = self.pipe_of(pipeline) else {
            return;
        };
        if attrib != PIPELINE_GLOBAL_ALPHA {
            self.raise(ERROR_BAD_ATTRIBUTE);
        } else if !(0.0..=1.0).contains(&value) {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
        } else {
            self.pipe_mut(at).cached.alpha = value;
        }
    }

    /// `wfdSetPipelineAttribiv` (5.7.3): the rectangles.
    pub fn set_pipeline_attrib_iv(
        &mut self,
        dev: u32,
        pipeline: u32,
        attrib: i32,
        count: i32,
        value: Option<&[i32]>,
    ) {
        let mut f = [0.0f32; 4];
        let given = value.map(|v| {
            for (to, from) in f.iter_mut().zip(v) {
                *to = *from as f32;
            }
            &f[..v.len().min(4)]
        });
        self.set_rect(dev, pipeline, attrib, count, given);
    }

    /// `wfdSetPipelineAttribfv` (5.7.3): the rectangles; the integer reading
    /// back is the floor.
    pub fn set_pipeline_attrib_fv(
        &mut self,
        dev: u32,
        pipeline: u32,
        attrib: i32,
        count: i32,
        value: Option<&[f32]>,
    ) {
        self.set_rect(dev, pipeline, attrib, count, value);
    }

    fn set_rect(
        &mut self,
        dev: u32,
        pipeline: u32,
        attrib: i32,
        count: i32,
        value: Option<&[f32]>,
    ) {
        if !self.is(dev) {
            return;
        }
        let Some(at) = self.pipe_of(pipeline) else {
            return;
        };
        if !matches!(
            attrib,
            PIPELINE_SOURCE_RECTANGLE | PIPELINE_DESTINATION_RECTANGLE
        ) {
            self.raise(ERROR_BAD_ATTRIBUTE);
            return;
        }
        let Some(value) = value.filter(|v| count == 4 && v.len() >= 4) else {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return;
        };
        if !value[..4].iter().all(|v| in_range(*v)) {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return;
        }
        let mut rect = [0.0; 4];
        rect.copy_from_slice(&value[..4]);
        let p = self.pipe_mut(at);
        if attrib == PIPELINE_SOURCE_RECTANGLE {
            p.cached.src = rect;
        } else {
            p.cached.dst = rect;
        }
    }

    /// `wfdSetPipelineTSColor` (5.8.3): source colour transparency is not
    /// supported.
    pub fn set_pipeline_ts_color(
        &mut self,
        dev: u32,
        pipeline: u32,
        format: i32,
        count: i32,
        null: bool,
    ) {
        if !self.is(dev) {
            return;
        }
        if self.pipe_of(pipeline).is_none() {
            return;
        }
        let known = matches!(
            format,
            TSC_FORMAT_UINT8_RGB_8_8_8_LINEAR | TSC_FORMAT_UINT8_RGB_5_6_5_LINEAR
        );
        if !known || null || count != 3 {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
        } else {
            self.raise(ERROR_NOT_SUPPORTED);
        }
    }

    /// The hot spot of the cursor picture (the extension `WFD_STAFETO_cursor`):
    /// the point of the picture that the destination rectangle's place names
    /// for the service. ILLEGAL_ARGUMENT outside the picture or for a
    /// pipeline without a hot spot.
    pub fn set_cursor_hot_spot(&mut self, dev: u32, pipeline: u32, x: i32, y: i32) {
        if !self.is(dev) {
            return;
        }
        let Some(at) = self.pipe_of(pipeline) else {
            return;
        };
        let rec = self.pipe(at).rec;
        let inside = x >= 0 && y >= 0 && (x as u32) < rec.max_w && (y as u32) < rec.max_h;
        if !rec.has(PIPELINE_HOT_SPOT) || !inside {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return;
        }
        self.pipe_mut(at).cached.hot = (x as u32, y as u32);
    }

    // ---------------------------------------------------------------- sources

    /// The layer below made the stream `id` (1 target, 2 pool, 3 cursor
    /// picture) available: sources can be made from it. The target is
    /// always there.
    pub fn make_available(&mut self, id: u32) {
        if let Some(a) = self.available.get_mut(id as usize - 1) {
            *a = true;
        }
    }

    /// `wfdCreateSourceFromStream` (5.5.1.1): `stream` is the service's id of
    /// the source; `attribs` is the attribute list without its end.
    pub fn create_source_from_stream(
        &mut self,
        dev: u32,
        pipeline: u32,
        stream: u32,
        attribs: &[i32],
    ) -> u32 {
        if !self.is(dev) {
            return 0;
        }
        let Some(at) = self.pipe_of(pipeline) else {
            return 0;
        };
        if !attribs.is_empty() {
            self.raise(ERROR_BAD_ATTRIBUTE);
            return 0;
        }
        let info = self.setup.sources.iter().copied().find(|s| s.id == stream);
        let Some(info) = info.filter(|s| self.available[s.id as usize - 1]) else {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return 0;
        };
        let rec = self.pipe(at).rec;
        if !info.suits(&rec) {
            self.raise(ERROR_NOT_SUPPORTED);
            return 0;
        }
        let Some(slot) = self.sources.iter().position(Option::is_none) else {
            self.raise(ERROR_OUT_OF_MEMORY);
            return 0;
        };
        let handle = self.handle();
        self.sources[slot] = Some(Source {
            handle,
            pipeline: rec.id,
            id: info.id,
        });
        handle
    }

    /// `wfdDestroySource` (5.5.1.2): a binding of the source keeps the
    /// display's picture until another replaces it.
    pub fn destroy_source(&mut self, dev: u32, source: u32) {
        if !self.is(dev) {
            return;
        }
        match self
            .sources
            .iter()
            .position(|s| s.is_some_and(|s| s.handle == source))
        {
            Some(i) => self.sources[i] = None,
            None => self.raise(ERROR_BAD_HANDLE),
        }
    }

    /// `wfdCreateMaskFromStream` (5.5.2.1): the pipelines have no masks.
    pub fn create_mask_from_stream(&mut self, dev: u32, pipeline: u32, attribs: &[i32]) -> u32 {
        if !self.is(dev) || self.pipe_of(pipeline).is_none() {
            return 0;
        }
        if !attribs.is_empty() {
            self.raise(ERROR_BAD_ATTRIBUTE);
        } else {
            self.raise(ERROR_NOT_SUPPORTED);
        }
        0
    }

    /// `wfdDestroyMask` (5.5.2.2): no mask is valid.
    pub fn destroy_mask(&mut self, dev: u32, _mask: u32) {
        if self.is(dev) {
            self.raise(ERROR_BAD_HANDLE);
        }
    }

    /// `wfdBindSourceToPipeline` (5.6.2): cached until the commit. `region`
    /// must be NULL for a stream (`has_region`).
    pub fn bind_source_to_pipeline(
        &mut self,
        dev: u32,
        pipeline: u32,
        source: u32,
        transition: i32,
        has_region: bool,
    ) {
        if !self.is(dev) {
            return;
        }
        let Some(at) = self.pipe_of(pipeline) else {
            return;
        };
        let found = self
            .sources
            .iter()
            .flatten()
            .copied()
            .find(|s| s.handle == source);
        let bad = !matches!(transition, TRANSITION_IMMEDIATE | TRANSITION_AT_VSYNC)
            || (source != 0 && found.is_none())
            || found.is_some_and(|s| s.pipeline != self.pipe(at).rec.id)
            || has_region;
        if bad {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return;
        }
        // Only the last bind call before a commit counts.
        self.pipe_mut(at).pending = Some(found.map(|s| (s.handle, s.id)));
    }

    /// `wfdBindMaskToPipeline` (5.6.3): only the empty handle, which
    /// releases nothing.
    pub fn bind_mask_to_pipeline(&mut self, dev: u32, pipeline: u32, mask: u32, transition: i32) {
        if !self.is(dev) || self.pipe_of(pipeline).is_none() {
            return;
        }
        if mask != 0 || !matches!(transition, TRANSITION_IMMEDIATE | TRANSITION_AT_VSYNC) {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
        }
    }

    // ---------------------------------------------------------------- commit

    /// The size of the screen in points.
    fn screen(&self) -> (f32, f32) {
        (self.setup.width as f32, self.setup.height as f32)
    }

    /// What the cached configuration of the pipeline at `at` asks the
    /// display for after the commit, or the error of the specification (3.4).
    fn check_pipe(&self, at: usize) -> Result<Option<Binding>, i32> {
        let p = self.pipe(at);
        let target = match p.pending {
            Some(b) => b,
            None => p.bound,
        };
        let (w, h) = self.screen();
        let rect_in = |r: [f32; 4], bw: f32, bh: f32| {
            r[0] >= 0.0 && r[1] >= 0.0 && r[0] + r[2] <= bw && r[1] + r[3] <= bh
        };
        let empty = |r: [f32; 4]| r[2] <= 0.0 || r[3] <= 0.0;
        let cfg = p.cached;
        if p.rec.has(PIPELINE_FULL_SCREEN) {
            // A pipeline of the whole picture: never off, never partial.
            let Some(_) = target else {
                return Err(ERROR_NOT_SUPPORTED);
            };
            if empty(cfg.src) || empty(cfg.dst) {
                return Err(ERROR_NOT_SUPPORTED);
            }
            if !rect_in(cfg.src, p.rec.max_w as f32, p.rec.max_h as f32) || !rect_in(cfg.dst, w, h)
            {
                return Err(ERROR_INCONSISTENCY);
            }
            let whole = [0.0, 0.0, w, h];
            if cfg.src != whole || cfg.dst != whole {
                return Err(ERROR_NOT_SUPPORTED);
            }
            return Ok(target);
        }
        // A cursor: a picture of its own size, placed whole on the screen,
        // blended by its alpha.
        let Some(_) = target else {
            return Ok(None);
        };
        if empty(cfg.src) || empty(cfg.dst) {
            // A disabled pipeline has no effect on the output.
            return Ok(None);
        }
        let (mw, mh) = (p.rec.max_w as f32, p.rec.max_h as f32);
        if !rect_in(cfg.src, mw, mh) || !rect_in(cfg.dst, w, h) {
            return Err(ERROR_INCONSISTENCY);
        }
        if cfg.src != [0.0, 0.0, mw, mh] || cfg.dst[2] != mw || cfg.dst[3] != mh {
            return Err(ERROR_NOT_SUPPORTED);
        }
        if cfg.transparency != TRANSPARENCY_SOURCE_ALPHA {
            return Err(ERROR_NOT_SUPPORTED);
        }
        Ok(target)
    }

    /// `wfdDeviceCommit` (3.4), the part before the service is asked: the
    /// LAYERS request for the pipelines the call covers. None when the call
    /// failed (the error is stored and the cached changes of the covered
    /// pipelines are dropped, as the specification clears them in all cases)
    /// and the `Commit` otherwise, whose `layers` is None when nothing
    /// changed on the display. The layer above sends the request and tells
    /// `finish_commit` how it went.
    pub fn commit(&mut self, dev: u32, kind: i32, handle: u32) -> Option<Commit> {
        if !self.is(dev) {
            return None;
        }
        if !matches!(
            kind,
            COMMIT_ENTIRE_DEVICE | COMMIT_ENTIRE_PORT | COMMIT_PIPELINE
        ) {
            self.raise(ERROR_ILLEGAL_ARGUMENT);
            return None;
        }
        let only = match kind {
            COMMIT_ENTIRE_DEVICE if handle != 0 => {
                self.raise(ERROR_BAD_HANDLE);
                return None;
            }
            COMMIT_ENTIRE_PORT if self.port == 0 || handle != self.port => {
                self.raise(ERROR_BAD_HANDLE);
                return None;
            }
            COMMIT_PIPELINE => Some(self.pipe_of(handle)?),
            _ => None,
        };
        let mut scope = [false; MAX_PIPELINES];
        for (at, in_scope) in scope.iter_mut().enumerate() {
            *in_scope = self.pipes[at].is_some() && only.is_none_or(|o| o == at);
        }
        let mut rows = [LayerRow::off(0); proto_gpu::MAX_LAYERS];
        let mut n = 0;
        let mut frame = false;
        let mut done: Done = [None; proto_gpu::MAX_LAYERS];
        let mut shown = [None; MAX_PIPELINES];
        let mut d = 0;
        let mut error = ERROR_NONE;
        for at in (0..MAX_PIPELINES).filter(|at| scope[*at]) {
            let after = match self.check_pipe(at) {
                Ok(b) => b,
                Err(e) => {
                    if error == ERROR_NONE {
                        error = e;
                    }
                    continue;
                }
            };
            let p = *self.pipe(at);
            if p.pending.is_some() {
                if d == done.len() {
                    error = ERROR_NOT_SUPPORTED;
                    continue;
                }
                done[d] = Some((p.rec.id, p.bound.map_or(0, |b| b.0)));
                d += 1;
            }
            let row = self.row_of(&p, after);
            let Some(row) = row else { continue };
            if n == rows.len() {
                error = ERROR_NOT_SUPPORTED;
                continue;
            }
            frame |= p.rec.has(PIPELINE_FULL_SCREEN);
            shown[at] = Some(row.source != 0);
            rows[n] = row;
            n += 1;
        }
        let layers = if error != ERROR_NONE || n == 0 {
            None
        } else {
            match Layers::new(&rows[..n]) {
                Ok(l)
                    if l.check(self.setup.pipelines.as_slice(), &self.setup.sources)
                        .is_ok() =>
                {
                    Some(l)
                }
                _ => {
                    error = ERROR_NOT_SUPPORTED;
                    None
                }
            }
        };
        if error != ERROR_NONE {
            self.raise(error);
            self.drop_cache(&scope);
            return None;
        }
        Some(Commit {
            layers,
            frame,
            done,
            scope,
            shown,
        })
    }

    /// The row a pipeline needs after the commit, None when the display has
    /// nothing to be told: `after` is what the pipeline shows then.
    fn row_of(&self, p: &Pipe, after: Option<Binding>) -> Option<LayerRow> {
        if p.rec.has(PIPELINE_FULL_SCREEN) {
            // A bind call shows the source again: the changed area is the
            // whole picture (a stream has no region).
            return match (p.pending, after) {
                (Some(_), Some((_, id))) => Some(LayerRow::primary(
                    p.rec.id,
                    id,
                    Some(Rect {
                        x: 0,
                        y: 0,
                        w: self.setup.width,
                        h: self.setup.height,
                    }),
                )),
                _ => None,
            };
        }
        let moved = p.cached.dst != p.committed.dst || p.cached.hot != p.committed.hot;
        if p.pending.is_none() && !moved {
            return None;
        }
        match after {
            Some((_, id)) => {
                let (hx, hy) = p.cached.hot;
                let x = (p.cached.dst[0] as i64 + i64::from(hx)) as i32;
                let y = (p.cached.dst[1] as i64 + i64::from(hy)) as i32;
                let mut row = LayerRow::cursor(p.rec.id, id, x, y, (hx, hy));
                if p.pending.is_some() {
                    // The picture is sent again.
                    row.dw = p.rec.max_w;
                    row.dh = p.rec.max_h;
                }
                Some(row)
            }
            None => p.shown.then(|| LayerRow::off(p.rec.id)),
        }
    }

    fn drop_cache(&mut self, scope: &[bool; MAX_PIPELINES]) {
        for (p, in_scope) in self.pipes.iter_mut().zip(scope) {
            if let (Some(p), true) = (p.as_mut(), *in_scope) {
                p.cached = p.committed;
                p.pending = None;
            }
        }
    }

    /// The service answered the request of `commit` (`Ok`) or refused it
    /// with the error of the specification. A request with a primary row
    /// completes its bindings with the frame's bit (`frame_done`); one
    /// without completes them now.
    pub fn finish_commit(&mut self, commit: &Commit, result: Result<(), i32>) {
        if let Err(error) = result {
            self.raise(error);
            self.drop_cache(&commit.scope);
            return;
        }
        for (at, p) in self.pipes.iter_mut().enumerate() {
            if let (Some(p), true) = (p.as_mut(), commit.scope[at]) {
                if let Some(b) = p.pending.take() {
                    p.bound = b;
                }
                if let Some(shown) = commit.shown[at] {
                    p.shown = shown;
                }
                p.committed = p.cached;
            }
        }
        if commit.frame {
            self.awaiting = Some(commit.done);
        } else {
            self.complete(commit.done);
        }
    }

    /// Whether a frame's bit is awaited.
    pub fn frame_pending(&self) -> bool {
        self.awaiting.is_some()
    }

    /// The bit of the frame came (`FRAME_SHOWN` or `FRAME_FAILED`): the
    /// bindings of the request complete.
    pub fn frame_done(&mut self) {
        if let Some(done) = self.awaiting.take() {
            self.complete(done);
        }
    }

    fn complete(&mut self, done: Done) {
        for (pipeline, source) in done.into_iter().flatten() {
            let queued = Queued {
                kind: EVENT_PIPELINE_BIND_SOURCE_COMPLETE,
                pipeline,
                source,
                overflow: false,
            };
            for c in self.events.iter_mut().flatten() {
                if c.cap == 0 || c.filter & bit(queued.kind) == 0 {
                    continue;
                }
                if c.len == c.cap {
                    let last = (c.head + c.len - 1) % QUEUE_MAX;
                    c.queue[last].overflow = true;
                } else {
                    let at = (c.head + c.len) % QUEUE_MAX;
                    c.queue[at] = queued;
                    c.len += 1;
                }
            }
        }
    }

    // ----------------------------------------------------------------- events

    fn event_index(&self, handle: u32) -> Option<usize> {
        if handle == 0 {
            return None;
        }
        self.events
            .iter()
            .position(|c| c.as_ref().is_some_and(|c| c.handle == handle))
    }

    fn event_of(&mut self, handle: u32) -> Option<usize> {
        let found = self.event_index(handle);
        if found.is_none() {
            self.raise(ERROR_BAD_HANDLE);
        }
        found
    }

    /// The default depth of a bind queue (3.6.5.5): the refresh rate of the
    /// port times the pipelines.
    pub fn default_queue(&self) -> usize {
        self.setup.refresh_hz as usize * self.setup.pipelines.as_slice().len()
    }

    /// `wfdCreateEvent` (3.6.1.1): `attribs` is the attribute list without
    /// its end. A queue size of 0 or less turns the bind events off; a size
    /// above `QUEUE_MAX` is that.
    pub fn create_event(&mut self, dev: u32, attribs: &[i32]) -> u32 {
        if !self.is(dev) {
            return 0;
        }
        let mut cap = self.default_queue().min(QUEUE_MAX);
        for pair in attribs.chunks(2) {
            if pair[0] != EVENT_PIPELINE_BIND_QUEUE_SIZE || pair.len() < 2 {
                self.raise(ERROR_BAD_ATTRIBUTE);
                return 0;
            }
            cap = pair[1].clamp(0, QUEUE_MAX as i32) as usize;
        }
        let Some(slot) = self.events.iter().position(Option::is_none) else {
            self.raise(ERROR_OUT_OF_MEMORY);
            return 0;
        };
        let handle = self.handle();
        self.events[slot] = Some(Container {
            handle,
            cap,
            filter: !0,
            waiting: false,
            last: NO_EVENT,
            head: 0,
            len: 0,
            queue: [NO_EVENT; QUEUE_MAX],
        });
        handle
    }

    /// `wfdDestroyEvent` (3.6.1.2).
    pub fn destroy_event(&mut self, dev: u32, event: u32) {
        if !self.is(dev) {
            return;
        }
        if let Some(at) = self.event_of(event) {
            self.events[at] = None;
        }
    }

    /// `wfdGetEventAttribi` (3.6.1.3): the attributes of the last event
    /// retrieved are valid for its type only.
    pub fn get_event_attrib(&mut self, dev: u32, event: u32, attrib: i32) -> i32 {
        if !self.is(dev) {
            return 0;
        }
        let Some(at) = self.event_of(event) else {
            return 0;
        };
        let c = self.events[at].as_ref().expect("an event container");
        let last = c.last;
        match attrib {
            EVENT_PIPELINE_BIND_QUEUE_SIZE => c.cap as i32,
            EVENT_TYPE => last.kind,
            EVENT_PIPELINE_BIND_PIPELINE_ID
            | EVENT_PIPELINE_BIND_SOURCE
            | EVENT_PIPELINE_BIND_MASK
            | EVENT_PIPELINE_BIND_QUEUE_OVERFLOW => {
                if last.kind != EVENT_PIPELINE_BIND_SOURCE_COMPLETE
                    && last.kind != EVENT_PIPELINE_BIND_MASK_COMPLETE
                {
                    self.raise(ERROR_ILLEGAL_ARGUMENT);
                    return 0;
                }
                match attrib {
                    EVENT_PIPELINE_BIND_PIPELINE_ID => last.pipeline as i32,
                    EVENT_PIPELINE_BIND_SOURCE => last.source as i32,
                    EVENT_PIPELINE_BIND_MASK => 0,
                    _ => last.overflow as i32,
                }
            }
            EVENT_PORT_ATTACH_PORT_ID | EVENT_PORT_ATTACH_STATE | EVENT_PORT_PROTECTION_PORT_ID => {
                self.raise(ERROR_ILLEGAL_ARGUMENT);
                0
            }
            _ => {
                self.raise(ERROR_BAD_ATTRIBUTE);
                0
            }
        }
    }

    /// `wfdDeviceEventFilter` (3.6.4): `filter` is the list without its end,
    /// None for NULL.
    pub fn device_event_filter(&mut self, dev: u32, event: u32, filter: Option<&[i32]>) {
        if !self.is(dev) {
            return;
        }
        let Some(at) = self.event_of(event) else {
            return;
        };
        let mut bits = !0;
        if let Some(list) = filter {
            let valid = |k: i32| (EVENT_NONE..=EVENT_PIPELINE_BIND_MASK_COMPLETE).contains(&k);
            if !list.iter().all(|k| valid(*k)) {
                self.raise(ERROR_ILLEGAL_ARGUMENT);
                return;
            }
            // NONE and DESTROYED cannot be filtered out.
            bits = bit(EVENT_NONE) | bit(EVENT_DESTROYED);
            for k in list {
                bits |= bit(*k);
            }
        }
        self.events[at].as_mut().expect("an event container").filter = bits;
    }

    /// `wfdDeviceEventWait` (3.6.3): the wait begins. NOT_SUPPORTED when a
    /// thread already waits on the container, BAD_HANDLE for a handle that is
    /// none; false then.
    pub fn begin_wait(&mut self, dev: u32, event: u32) -> bool {
        if !self.is(dev) {
            return false;
        }
        let Some(at) = self.event_of(event) else {
            return false;
        };
        let c = self.events[at].as_mut().expect("an event container");
        if c.waiting {
            self.raise(ERROR_NOT_SUPPORTED);
            return false;
        }
        c.waiting = true;
        true
    }

    /// The wait ends.
    pub fn end_wait(&mut self, event: u32) {
        if let Some(at) = self.event_index(event) {
            self.events[at]
                .as_mut()
                .expect("an event container")
                .waiting = false;
        }
    }

    /// The next queued event of the container; the last event's attributes
    /// are those of it. A container that is gone is `Gone`.
    pub fn event_poll(&mut self, event: u32) -> Poll {
        let Some(at) = self.event_index(event) else {
            return Poll::Gone;
        };
        let c = self.events[at].as_mut().expect("an event container");
        if c.len == 0 {
            c.last = NO_EVENT;
            return Poll::Empty;
        }
        c.last = c.queue[c.head];
        c.head = (c.head + 1) % QUEUE_MAX;
        c.len -= 1;
        Poll::Event(c.last.kind)
    }

    /// The wait timed out: the last event is NONE.
    pub fn event_timed_out(&mut self, event: u32) {
        if let Some(at) = self.event_index(event) {
            self.events[at].as_mut().expect("an event container").last = NO_EVENT;
        }
    }
}

/// The empty port id and handle.
const WFD_INVALID: i32 = 0;

/// The id of the cursor pipeline and of the primary one, for the layers
/// above.
pub const CURSOR_PIPELINE: u32 = PIPELINE_CURSOR;
pub const PRIMARY_PIPELINE: u32 = proto_gpu::PIPELINE_PRIMARY;
