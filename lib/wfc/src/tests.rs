// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The rules of OpenWF Composition 1.0 for the device over the scene session,
//! one test for a clause of the specification; the number in a name (`s5_4`
//! is section 5.4) or in the first comment is the clause, `CLAUSES.md` the
//! table.

use super::*;
use abi::Error;
use proto_comp::{FORMAT_ARGB8888, FORMAT_XRGB8888, meaning};

#[derive(Debug, Clone, PartialEq)]
enum Ev {
    Commit(Box<SceneCommit>),
    Compose(u32),
    Wait(u64),
    Clear(u64),
    Pause,
}

#[derive(Default)]
struct Fake {
    log: Vec<Ev>,
    commit_refusals: Vec<Status>,
    compose_refusals: Vec<Status>,
    wait_refusal: Option<Status>,
    wait_once: Vec<Status>,
    bits: u64,
    set_on_compose: bool,
    strict_wait: bool,
    pause_refusal: Option<Status>,
    claimed: bool,
}

impl Service for Fake {
    fn scene_commit(&mut self, c: &SceneCommit) -> Result<(), Status> {
        self.log.push(Ev::Commit(Box::new(*c)));
        match self.commit_refusals.is_empty() {
            true => Ok(()),
            false => Err(self.commit_refusals.remove(0)),
        }
    }
    fn scene_compose(&mut self, flags: u32) -> Result<(), Status> {
        self.log.push(Ev::Compose(flags));
        if self.set_on_compose {
            // The service sets the bit of the frame before its answer.
            self.bits |= COMPOSED_BIT;
        }
        match self.compose_refusals.is_empty() {
            true => Ok(()),
            false => Err(self.compose_refusals.remove(0)),
        }
    }
    fn wait(&mut self, bit: u64) -> Result<(), Status> {
        self.log.push(Ev::Wait(bit));
        if !self.wait_once.is_empty() {
            return Err(self.wait_once.remove(0));
        }
        assert!(!self.strict_wait || self.bits & bit != 0, "wait would hang");
        self.wait_refusal.map_or(Ok(()), Err)
    }
    fn clear(&mut self, bit: u64) {
        self.log.push(Ev::Clear(bit));
        self.bits &= !bit;
    }
    fn pause(&mut self) -> Result<(), Status> {
        self.log.push(Ev::Pause);
        self.pause_refusal.map_or(Ok(()), Err)
    }
    fn claim_screen(&mut self) -> bool {
        !core::mem::replace(&mut self.claimed, true)
    }
    fn release_screen(&mut self) {
        self.claimed = false;
    }
}

impl Fake {
    fn commits(&self) -> Vec<SceneCommit> {
        self.log
            .iter()
            .filter_map(|e| match e {
                Ev::Commit(c) => Some(**c),
                _ => None,
            })
            .collect()
    }
    fn last(&self) -> SceneCommit {
        *self.commits().last().expect("a commit")
    }
}

const BUSY: Status = Status::Unknown(proto_comp::BUSY);

struct Rig {
    w: Wfc,
    svc: Fake,
    dev: u32,
    ctx: u32,
}

fn rig() -> Rig {
    let mut w = Wfc::create_device(0, &[], Setup::VIRTIO).unwrap();
    let mut svc = Fake::default();
    let dev = w.device();
    let ctx = w.create_on_screen_context(dev, 0, &[], &mut svc);
    assert!(ctx != 0);
    Rig { w, svc, dev, ctx }
}

fn info(id: u32, width: u32, height: u32) -> StreamInfo {
    StreamInfo {
        id,
        width,
        height,
        format: FORMAT_XRGB8888,
    }
}

impl Rig {
    fn err(&mut self) -> i32 {
        self.w.get_error(self.dev)
    }
    fn source(&mut self, id: u32, width: u32, height: u32) -> u32 {
        let h = self.w.create_source_from_stream(
            self.dev,
            self.ctx,
            Some(info(id, width, height)),
            &[],
        );
        assert!(h != 0, "error {:#x}", self.err());
        h
    }
    fn mask(&mut self, id: u32, width: u32, height: u32) -> u32 {
        let s = StreamInfo {
            format: FORMAT_A8,
            ..info(id, width, height)
        };
        let h = self
            .w
            .create_mask_from_stream(self.dev, self.ctx, Some(s), &[]);
        assert!(h != 0, "error {:#x}", self.err());
        h
    }
    fn element(&mut self) -> u32 {
        let e = self.w.create_element(self.dev, self.ctx, &[]);
        assert!(e != 0);
        e
    }
    fn set_i(&mut self, e: u32, a: i32, v: i32) {
        self.w.set_element_attrib_i(self.dev, e, a, v);
    }
    fn dst(&mut self, e: u32, r: [i32; 4]) {
        self.w
            .set_element_attrib_iv(self.dev, e, ELEMENT_DESTINATION_RECTANGLE, Some(&r));
        assert_eq!(self.err(), 0);
    }
    fn src_rect(&mut self, e: u32, r: [f32; 4]) {
        self.w
            .set_element_attrib_fv(self.dev, e, ELEMENT_SOURCE_RECTANGLE, Some(&r));
        assert_eq!(self.err(), 0);
    }
    /// An element showing a 100 by 100 source at (10, 20), inserted on top.
    fn shown(&mut self, id: u32) -> u32 {
        let s = self.source(id, 100, 100);
        let e = self.element();
        self.set_i(e, ELEMENT_SOURCE, s as i32);
        self.src_rect(e, [0.0, 0.0, 100.0, 100.0]);
        self.dst(e, [10, 20, 100, 100]);
        let top = self.w.element_below(self.dev, e);
        let _ = self.err();
        let _ = top;
        let above = self.order_top();
        self.w.insert_element(self.dev, e, above);
        assert_eq!(self.err(), 0);
        e
    }
    fn order_top(&self) -> u32 {
        if self.w.order_len == 0 {
            0
        } else {
            self.w.order[self.w.order_len - 1]
        }
    }
    fn commit(&mut self) {
        self.w.commit(self.dev, self.ctx, false, &mut self.svc);
    }
    fn order(&self) -> Vec<u32> {
        self.w.order[..self.w.order_len].to_vec()
    }
}

// ------------------------------------------------------------ 4: the device

#[test]
fn s4_2_enumerate_counts_the_one_device() {
    assert_eq!(Wfc::enumerate_devices(None, &[]), 1);
    let mut ids = [0; 4];
    assert_eq!(Wfc::enumerate_devices(Some(&mut ids), &[0]), 1);
    assert_eq!(ids[0], DEVICE);
}

#[test]
fn s4_2_enumerate_screen_filter() {
    let f = DEVICE_FILTER_SCREEN_NUMBER;
    assert_eq!(Wfc::enumerate_devices(None, &[f, 0, 0]), 1);
    assert_eq!(Wfc::enumerate_devices(None, &[f, 1, 0]), 0);
}

#[test]
fn s4_2_1_enumerate_bad_attribute_or_repeat_is_empty() {
    let f = DEVICE_FILTER_SCREEN_NUMBER;
    assert_eq!(Wfc::enumerate_devices(None, &[0x1234, 0, 0]), 0);
    assert_eq!(Wfc::enumerate_devices(None, &[f, 0, f, 0, 0]), 0);
}

#[test]
fn s4_2_enumerate_empty_or_negative_buffer_writes_nothing() {
    let mut ids: [i32; 0] = [];
    assert_eq!(Wfc::enumerate_devices(Some(&mut ids), &[]), 0);
}

#[test]
fn s4_3_create_device_ids() {
    assert!(Wfc::create_device(0, &[], Setup::VIRTIO).is_some());
    assert!(Wfc::create_device(DEVICE, &[], Setup::VIRTIO).is_some());
    assert!(Wfc::create_device(7, &[], Setup::VIRTIO).is_none());
}

#[test]
fn s4_3_create_device_with_attributes_fails() {
    assert!(Wfc::create_device(0, &[5, 5, 0], Setup::VIRTIO).is_none());
    assert!(Wfc::create_device(0, &[0], Setup::VIRTIO).is_some());
}

#[test]
fn s4_3_two_devices_have_their_own_state() {
    let mut a = rig();
    let mut b = Wfc::create_device(0, &[], Setup::VIRTIO).unwrap();
    assert_ne!(a.dev, b.device());
    let bd = b.device();
    // Section 5.2: one context per screen, whichever device asks.
    assert_eq!(b.create_on_screen_context(bd, 0, &[], &mut a.svc), 0);
    assert_eq!(b.get_error(bd), ERROR_IN_USE);
    assert_eq!(a.err(), 0);
}

#[test]
fn s4_3_handles_of_another_device_are_bad_handles() {
    let mut a = rig();
    let e = a.element();
    let mut b = Wfc::create_device(0, &[], Setup::VIRTIO).unwrap();
    let bd = b.device();
    b.set_element_attrib_i(bd, e, ELEMENT_SOURCE_FLIP, 1);
    assert_eq!(b.get_error(bd), ERROR_BAD_HANDLE);
    b.commit(bd, a.ctx, false, &mut a.svc);
    assert_eq!(b.get_error(bd), ERROR_BAD_HANDLE);
    // A's own handle used with B's device handle is a call on no device of A.
    a.w.set_element_attrib_i(bd, e, ELEMENT_SOURCE_FLIP, 1);
    assert_eq!(a.err(), 0);
}

#[test]
fn s4_1_device_attributes() {
    let mut r = rig();
    assert_eq!(
        r.w.device_attrib(r.dev, DEVICE_CLASS),
        DEVICE_CLASS_FULLY_CAPABLE
    );
    assert_eq!(r.w.device_attrib(r.dev, DEVICE_ID), DEVICE);
    assert_eq!(r.err(), 0);
}

#[test]
fn s4_4_device_attribute_bad() {
    let mut r = rig();
    r.w.device_attrib(r.dev, 0x9999);
    assert_eq!(r.err(), ERROR_BAD_ATTRIBUTE);
}

#[test]
fn s4_5_destroy_device() {
    let mut r = rig();
    let e = r.element();
    assert_eq!(r.w.destroy_device(r.dev, &mut r.svc), ERROR_NONE);
    assert_eq!(r.w.destroy_device(r.dev, &mut r.svc), ERROR_BAD_DEVICE);
    assert_eq!(r.w.get_error(r.dev), ERROR_BAD_DEVICE);
    assert!(!r.svc.claimed);
    let _ = e;
}

#[test]
fn s4_5_destroy_device_closes_the_context_like_destroy_context() {
    let mut r = rig();
    r.w.activate(r.dev, r.ctx, &mut r.svc);
    r.w.destroy_device(r.dev, &mut r.svc);
    assert_eq!(r.svc.last().flags, 0);
}

#[test]
fn s10_3_2_strings() {
    let mut r = rig();
    assert_eq!(r.w.strings(r.dev, VENDOR, 1).unwrap(), &[VENDOR_NAME]);
    assert_eq!(r.w.strings(r.dev, VERSION, 1).unwrap(), &[VERSION_NAME]);
    assert_eq!(r.w.strings(r.dev, RENDERER, 1).unwrap().len(), 1);
    assert_eq!(r.w.strings(r.dev, EXTENSIONS, 1).unwrap().len(), 1);
    assert_eq!(r.err(), 0);
}

#[test]
fn s10_3_2_strings_bad_name_or_count() {
    let mut r = rig();
    assert!(r.w.strings(r.dev, 0x1, 1).is_none());
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
    assert!(r.w.strings(r.dev, VENDOR, -1).is_none());
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
    assert!(r.w.strings(0xdead, VENDOR, 1).is_none());
    assert_eq!(r.err(), 0);
}

#[test]
fn s10_3_2_extension_supported() {
    let mut r = rig();
    assert!(r.w.is_extension_supported(r.dev, b"WFC_STAFETO_stream"));
    assert!(r.w.is_extension_supported(r.dev, b"WFC_STAFETO_stream\0"));
    assert!(!r.w.is_extension_supported(r.dev, b"WFC_EXT_other"));
    assert!(!r.w.is_extension_supported(0xdead, b"WFC_STAFETO_stream"));
}

// ------------------------------------------------------------ 2.11: errors

#[test]
fn s2_11_error_starts_none() {
    let mut r = rig();
    assert_eq!(r.err(), ERROR_NONE);
}

#[test]
fn s2_11_get_error_clears() {
    let mut r = rig();
    r.w.device_attrib(r.dev, 0x9999);
    assert_eq!(r.err(), ERROR_BAD_ATTRIBUTE);
    assert_eq!(r.err(), ERROR_NONE);
}

#[test]
fn s2_11_oldest_error_is_kept() {
    let mut r = rig();
    r.w.device_attrib(r.dev, 0x9999);
    r.w.set_context_attrib_i(r.dev, 0xdead, CONTEXT_ROTATION, ROTATION_0);
    assert_eq!(r.err(), ERROR_BAD_ATTRIBUTE);
    assert_eq!(r.err(), ERROR_NONE);
}

#[test]
fn s2_11_invalid_device_is_bad_device_and_stores_nothing() {
    let mut r = rig();
    assert_eq!(r.w.get_error(0), ERROR_BAD_DEVICE);
    assert_eq!(r.w.get_error(r.dev + 1000), ERROR_BAD_DEVICE);
    assert_eq!(r.err(), ERROR_NONE);
}

#[test]
fn s2_11_calls_on_an_invalid_device_have_no_effect() {
    let mut r = rig();
    let e = r.element();
    r.w.set_element_attrib_i(0xdead, e, ELEMENT_SOURCE_FLIP, 1);
    assert_eq!(r.w.element_attrib_i(0xdead, e, ELEMENT_SOURCE_FLIP), 0);
    r.w.commit(0xdead, r.ctx, false, &mut r.svc);
    assert_eq!(r.w.create_element(0xdead, r.ctx, &[]), 0);
    assert_eq!(r.err(), ERROR_NONE);
    assert_eq!(r.w.element_attrib_i(r.dev, e, ELEMENT_SOURCE_FLIP), 0);
    assert!(r.svc.log.is_empty());
}

#[test]
fn s2_11_failing_call_changes_nothing() {
    let mut r = rig();
    let e = r.element();
    r.set_i(e, ELEMENT_SOURCE_ROTATION, ROTATION_90);
    r.set_i(e, ELEMENT_SOURCE_ROTATION, 5);
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
    assert_eq!(
        r.w.element_attrib_i(r.dev, e, ELEMENT_SOURCE_ROTATION),
        ROTATION_90
    );
}

// ----------------------------------------------------------- 5: the context

#[test]
fn s5_2_create_context_screens() {
    let mut w = Wfc::create_device(0, &[], Setup::VIRTIO).unwrap();
    let mut svc = Fake::default();
    let dev = w.device();
    assert_eq!(w.create_on_screen_context(dev, 1, &[], &mut svc), 0);
    assert_eq!(w.get_error(dev), ERROR_UNSUPPORTED);
    assert!(!svc.claimed);
    assert!(w.create_on_screen_context(dev, 0, &[], &mut svc) != 0);
    assert!(svc.claimed);
}

#[test]
fn s5_2_second_context_is_in_use() {
    let mut r = rig();
    assert_eq!(r.w.create_on_screen_context(r.dev, 0, &[], &mut r.svc), 0);
    assert_eq!(r.err(), ERROR_IN_USE);
}

#[test]
fn s5_2_context_attribute_list_must_be_empty() {
    let mut w = Wfc::create_device(0, &[], Setup::VIRTIO).unwrap();
    let mut svc = Fake::default();
    let dev = w.device();
    assert_eq!(w.create_on_screen_context(dev, 0, &[9, 9, 0], &mut svc), 0);
    assert_eq!(w.get_error(dev), ERROR_BAD_ATTRIBUTE);
    assert!(!svc.claimed);
}

#[test]
fn s5_3_off_screen_context_is_unsupported() {
    let mut r = rig();
    assert_eq!(r.w.create_off_screen_context(r.dev, 5, &[]), 0);
    assert_eq!(r.err(), ERROR_UNSUPPORTED);
}

#[test]
fn s5_1_context_defaults() {
    let mut r = rig();
    let (d, c) = (r.dev, r.ctx);
    assert_eq!(
        r.w.context_attrib_i(d, c, CONTEXT_TYPE),
        CONTEXT_TYPE_ON_SCREEN
    );
    assert_eq!(r.w.context_attrib_i(d, c, CONTEXT_ROTATION), ROTATION_0);
    assert_eq!(r.w.context_attrib_i(d, c, CONTEXT_LOWEST_ELEMENT), 0);
    let mut bg = [9.0; 4];
    r.w.context_attrib_fv(d, c, CONTEXT_BG_COLOR, Some(&mut bg));
    assert_eq!(bg, [0.0, 0.0, 0.0, 1.0]);
    assert_eq!(r.err(), 0);
}

#[test]
fn s5_1_2_target_size() {
    let mut r = rig();
    let (d, c) = (r.dev, r.ctx);
    assert_eq!(r.w.context_attrib_i(d, c, CONTEXT_TARGET_WIDTH), 640);
    assert_eq!(r.w.context_attrib_i(d, c, CONTEXT_TARGET_HEIGHT), 400);
    r.w.set_context_attrib_i(d, c, CONTEXT_ROTATION, ROTATION_90);
    assert_eq!(r.w.context_attrib_i(d, c, CONTEXT_TARGET_WIDTH), 640);
}

#[test]
fn s5_6_read_only_context_attributes() {
    let mut r = rig();
    for a in [
        CONTEXT_TYPE,
        CONTEXT_TARGET_WIDTH,
        CONTEXT_TARGET_HEIGHT,
        CONTEXT_LOWEST_ELEMENT,
        0x9999,
    ] {
        r.w.set_context_attrib_i(r.dev, r.ctx, a, 1);
        assert_eq!(r.err(), ERROR_BAD_ATTRIBUTE, "{a:#x}");
    }
}

#[test]
fn s5_1_4_rotation_values() {
    let mut r = rig();
    for v in [ROTATION_0, ROTATION_90, ROTATION_180, ROTATION_270] {
        r.w.set_context_attrib_i(r.dev, r.ctx, CONTEXT_ROTATION, v);
        assert_eq!(r.w.context_attrib_i(r.dev, r.ctx, CONTEXT_ROTATION), v);
    }
    r.w.set_context_attrib_i(r.dev, r.ctx, CONTEXT_ROTATION, 90);
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
    assert_eq!(
        r.w.context_attrib_i(r.dev, r.ctx, CONTEXT_ROTATION),
        ROTATION_270
    );
}

#[test]
fn s5_1_5_background_by_integer() {
    let mut r = rig();
    r.w.set_context_attrib_i(r.dev, r.ctx, CONTEXT_BG_COLOR, 0x1020_30FFu32 as i32);
    assert_eq!(r.err(), 0);
    let v = r.w.context_attrib_i(r.dev, r.ctx, CONTEXT_BG_COLOR) as u32;
    assert_eq!(v, 0x1020_30FF);
}

#[test]
fn s5_1_5_background_alpha_must_be_opaque() {
    let mut r = rig();
    r.w.set_context_attrib_i(r.dev, r.ctx, CONTEXT_BG_COLOR, 0x1020_307F);
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
    r.w.set_context_attrib_fv(r.dev, r.ctx, CONTEXT_BG_COLOR, Some(&[0.1, 0.2, 0.3, 0.5]));
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
}

#[test]
fn s5_1_5_background_by_float_round_trips() {
    let mut r = rig();
    let v = [0.25, 0.5, 0.125, 1.0];
    r.w.set_context_attrib_fv(r.dev, r.ctx, CONTEXT_BG_COLOR, Some(&v));
    assert_eq!(r.err(), 0);
    let mut out = [0.0; 4];
    r.w.context_attrib_fv(r.dev, r.ctx, CONTEXT_BG_COLOR, Some(&mut out));
    assert_eq!(out, v);
}

#[test]
fn s5_6_background_range_count_and_null() {
    let mut r = rig();
    for bad in [
        Some(&[1.5, 0.0, 0.0, 1.0][..]),
        Some(&[-0.1, 0.0, 0.0, 1.0][..]),
        Some(&[f32::NAN, 0.0, 0.0, 1.0][..]),
        Some(&[0.0, 0.0, 1.0][..]),
        None,
    ] {
        r.w.set_context_attrib_fv(r.dev, r.ctx, CONTEXT_BG_COLOR, bad);
        assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
    }
    r.w.set_context_attrib_fv(r.dev, r.ctx, CONTEXT_ROTATION, Some(&[0.0; 4]));
    assert_eq!(r.err(), ERROR_BAD_ATTRIBUTE);
}

#[test]
fn s5_5_context_float_getter_rules() {
    let mut r = rig();
    let mut one = [0.0; 1];
    r.w.context_attrib_fv(r.dev, r.ctx, CONTEXT_BG_COLOR, Some(&mut one));
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
    r.w.context_attrib_fv(r.dev, r.ctx, CONTEXT_BG_COLOR, None);
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
    let mut four = [0.0; 4];
    r.w.context_attrib_fv(r.dev, r.ctx, CONTEXT_TYPE, Some(&mut four));
    assert_eq!(r.err(), ERROR_BAD_ATTRIBUTE);
}

#[test]
fn s5_5_bad_context_handle() {
    let mut r = rig();
    r.w.context_attrib_i(r.dev, r.ctx + 99, CONTEXT_TYPE);
    assert_eq!(r.err(), ERROR_BAD_HANDLE);
    r.w.set_context_attrib_i(r.dev, 0, CONTEXT_ROTATION, ROTATION_0);
    assert_eq!(r.err(), ERROR_BAD_HANDLE);
}

#[test]
fn s5_1_3_lowest_element_follows_the_order() {
    let mut r = rig();
    let a = r.element();
    let b = r.element();
    r.w.insert_element(r.dev, a, 0);
    r.w.insert_element(r.dev, b, 0);
    assert_eq!(
        r.w.context_attrib_i(r.dev, r.ctx, CONTEXT_LOWEST_ELEMENT),
        b as i32
    );
}

#[test]
fn s5_7_destroy_context_invalidates_its_resources() {
    let mut r = rig();
    let e = r.element();
    let s = r.source(1, 10, 10);
    r.w.destroy_context(r.dev, r.ctx, &mut r.svc);
    assert_eq!(r.err(), 0);
    assert!(!r.svc.claimed);
    r.w.element_attrib_i(r.dev, e, ELEMENT_SOURCE);
    assert_eq!(r.err(), ERROR_BAD_HANDLE);
    r.w.destroy_source(r.dev, s);
    assert_eq!(r.err(), ERROR_BAD_HANDLE);
    r.w.destroy_context(r.dev, r.ctx, &mut r.svc);
    assert_eq!(r.err(), ERROR_BAD_HANDLE);
}

#[test]
fn s5_7_a_new_context_can_follow() {
    let mut r = rig();
    r.w.destroy_context(r.dev, r.ctx, &mut r.svc);
    assert!(r.w.create_on_screen_context(r.dev, 0, &[], &mut r.svc) != 0);
}

#[test]
fn s5_7_destroy_active_context_deactivates_first() {
    let mut r = rig();
    r.w.activate(r.dev, r.ctx, &mut r.svc);
    r.w.destroy_context(r.dev, r.ctx, &mut r.svc);
    assert_eq!(r.svc.commits().len(), 2);
    assert_eq!(r.svc.last().flags, 0);
}

#[test]
fn s5_7_destroy_waits_for_a_pending_compose() {
    let mut r = rig();
    r.w.compose(r.dev, r.ctx, false, &mut r.svc);
    r.svc.log.clear();
    r.w.destroy_context(r.dev, r.ctx, &mut r.svc);
    assert_eq!(r.svc.log, vec![Ev::Wait(COMPOSED_BIT)]);
}

#[test]
fn s5_7_destroy_after_waited_compose_does_not_wait() {
    let mut r = rig();
    r.w.compose(r.dev, r.ctx, true, &mut r.svc);
    r.svc.log.clear();
    r.w.destroy_context(r.dev, r.ctx, &mut r.svc);
    assert!(r.svc.log.is_empty());
}

#[test]
fn s5_7_destroy_context_on_a_lost_device_drops_silently() {
    let mut r = rig();
    r.w.activate(r.dev, r.ctx, &mut r.svc);
    r.svc
        .commit_refusals
        .push(Status::Kernel(Error::PeerClosed));
    r.commit();
    assert_eq!(r.err(), ERROR_BAD_DEVICE);
    r.svc.log.clear();
    r.w.destroy_context(r.dev, r.ctx, &mut r.svc);
    assert_eq!(r.err(), 0);
    assert!(r.svc.log.is_empty());
    assert!(r.w.ctx.is_none());
}

// ------------------------------------------------ 6: sources and masks

#[test]
fn s6_1_1_source_creation() {
    let mut r = rig();
    let a = r.source(3, 64, 32);
    let b = r.source(3, 64, 32);
    assert_ne!(a, b);
    assert_eq!(r.err(), 0);
}

#[test]
fn s6_1_1_source_of_no_stream_is_illegal() {
    let mut r = rig();
    assert_eq!(r.w.create_source_from_stream(r.dev, r.ctx, None, &[]), 0);
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
}

#[test]
fn s6_1_1_source_from_an_a8_window_is_unsupported() {
    let mut r = rig();
    let s = StreamInfo {
        format: FORMAT_A8,
        ..info(1, 4, 4)
    };
    assert_eq!(r.w.create_source_from_stream(r.dev, r.ctx, Some(s), &[]), 0);
    assert_eq!(r.err(), ERROR_UNSUPPORTED);
    let s = StreamInfo {
        format: FORMAT_ARGB8888,
        ..info(1, 4, 4)
    };
    assert!(r.w.create_source_from_stream(r.dev, r.ctx, Some(s), &[]) != 0);
}

#[test]
fn s6_2_1_mask_needs_an_a8_window() {
    let mut r = rig();
    assert_eq!(
        r.w.create_mask_from_stream(r.dev, r.ctx, Some(info(1, 4, 4)), &[]),
        0
    );
    assert_eq!(r.err(), ERROR_UNSUPPORTED);
    assert!(r.mask(2, 4, 4) != 0);
}

#[test]
fn s6_1_1_source_limit_is_out_of_memory() {
    let mut r = rig();
    for i in 0..MAX_SOURCES as u32 {
        r.source(i, 4, 4);
    }
    assert_eq!(
        r.w.create_source_from_stream(r.dev, r.ctx, Some(info(9, 4, 4)), &[]),
        0
    );
    assert_eq!(r.err(), ERROR_OUT_OF_MEMORY);
}

#[test]
fn s6_1_1_bad_context_and_attribute_list() {
    let mut r = rig();
    assert_eq!(
        r.w.create_source_from_stream(r.dev, r.ctx + 50, Some(info(1, 4, 4)), &[]),
        0
    );
    assert_eq!(r.err(), ERROR_BAD_HANDLE);
    assert_eq!(
        r.w.create_source_from_stream(r.dev, r.ctx, Some(info(1, 4, 4)), &[7, 7, 0]),
        0
    );
    assert_eq!(r.err(), ERROR_BAD_ATTRIBUTE);
    assert_eq!(r.w.create_mask_from_stream(r.dev, r.ctx, None, &[]), 0);
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
}

#[test]
fn s6_1_2_destroy_source_invalidates_the_handle() {
    let mut r = rig();
    let s = r.source(1, 4, 4);
    r.w.destroy_source(r.dev, s);
    assert_eq!(r.err(), 0);
    r.w.destroy_source(r.dev, s);
    assert_eq!(r.err(), ERROR_BAD_HANDLE);
}

#[test]
fn s6_1_2_attached_source_lives_until_detached() {
    let mut r = rig();
    let s = r.source(1, 100, 100);
    let e = r.element();
    r.set_i(e, ELEMENT_SOURCE, s as i32);
    r.w.destroy_source(r.dev, s);
    // The element still shows it, and the slot is still taken.
    assert_eq!(r.w.element_attrib_i(r.dev, e, ELEMENT_SOURCE), s as i32);
    assert_eq!(r.w.sources.iter().flatten().count(), 1);
    r.set_i(e, ELEMENT_SOURCE, 0);
    assert_eq!(r.w.sources.iter().flatten().count(), 0);
    // A dead source cannot be attached again.
    r.set_i(e, ELEMENT_SOURCE, s as i32);
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
}

#[test]
fn s6_1_2_destroying_the_element_frees_a_dead_source() {
    let mut r = rig();
    let s = r.source(1, 10, 10);
    let e = r.element();
    r.set_i(e, ELEMENT_SOURCE, s as i32);
    r.w.destroy_source(r.dev, s);
    r.w.destroy_element(r.dev, e);
    assert_eq!(r.w.sources.iter().flatten().count(), 0);
}

#[test]
fn s6_2_2_destroy_mask() {
    let mut r = rig();
    let m = r.mask(1, 4, 4);
    let e = r.element();
    r.set_i(e, ELEMENT_MASK, m as i32);
    r.w.destroy_mask(r.dev, m);
    assert_eq!(r.err(), 0);
    assert_eq!(r.w.masks.iter().flatten().count(), 1);
    r.w.destroy_mask(r.dev, m);
    assert_eq!(r.err(), ERROR_BAD_HANDLE);
    r.set_i(e, ELEMENT_MASK, 0);
    assert_eq!(r.w.masks.iter().flatten().count(), 0);
}

#[test]
fn s6_1_2_a_mask_handle_is_no_source() {
    let mut r = rig();
    let m = r.mask(1, 4, 4);
    r.w.destroy_source(r.dev, m);
    assert_eq!(r.err(), ERROR_BAD_HANDLE);
    let e = r.element();
    r.set_i(e, ELEMENT_SOURCE, m as i32);
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
}

// ------------------------------------------------------------ 7: elements

#[test]
fn s7_1_defaults_of_every_attribute() {
    let mut r = rig();
    let e = r.element();
    let d = r.dev;
    let mut ints = [9; 4];
    r.w.element_attrib_iv(d, e, ELEMENT_DESTINATION_RECTANGLE, Some(&mut ints));
    assert_eq!(ints, [0; 4]);
    let mut fl = [9.0; 4];
    r.w.element_attrib_fv(d, e, ELEMENT_SOURCE_RECTANGLE, Some(&mut fl));
    assert_eq!(fl, [0.0; 4]);
    assert_eq!(r.w.element_attrib_i(d, e, ELEMENT_SOURCE), 0);
    assert_eq!(r.w.element_attrib_i(d, e, ELEMENT_SOURCE_FLIP), 0);
    assert_eq!(
        r.w.element_attrib_i(d, e, ELEMENT_SOURCE_ROTATION),
        ROTATION_0
    );
    assert_eq!(
        r.w.element_attrib_i(d, e, ELEMENT_SOURCE_SCALE_FILTER),
        SCALE_FILTER_NONE
    );
    assert_eq!(r.w.element_attrib_i(d, e, ELEMENT_TRANSPARENCY_TYPES), 0);
    assert_eq!(r.w.element_attrib_f(d, e, ELEMENT_GLOBAL_ALPHA), 1.0);
    assert_eq!(r.w.element_attrib_i(d, e, ELEMENT_GLOBAL_ALPHA), 255);
    assert_eq!(r.w.element_attrib_i(d, e, ELEMENT_MASK), 0);
    assert_eq!(r.err(), 0);
}

#[test]
fn s7_2_new_element_is_outside_the_scene() {
    let mut r = rig();
    let e = r.element();
    assert!(r.order().is_empty());
    assert_eq!(r.w.element_above(r.dev, e), 0);
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
}

#[test]
fn s7_2_create_element_bad_context_and_list() {
    let mut r = rig();
    assert_eq!(r.w.create_element(r.dev, r.ctx + 9, &[]), 0);
    assert_eq!(r.err(), ERROR_BAD_HANDLE);
    assert_eq!(r.w.create_element(r.dev, r.ctx, &[1, 1, 0]), 0);
    assert_eq!(r.err(), ERROR_BAD_ATTRIBUTE);
}

#[test]
fn s7_2_element_limit_is_out_of_memory() {
    let mut r = rig();
    for _ in 0..MAX_ELEMS {
        r.element();
    }
    assert_eq!(r.w.create_element(r.dev, r.ctx, &[]), 0);
    assert_eq!(r.err(), ERROR_OUT_OF_MEMORY);
}

#[test]
fn s7_2_destroying_an_element_frees_its_place() {
    let mut r = rig();
    let first = r.element();
    for _ in 1..MAX_ELEMS {
        r.element();
    }
    r.w.destroy_element(r.dev, first);
    assert!(r.w.create_element(r.dev, r.ctx, &[]) != 0);
}

#[test]
fn s7_3_accessor_matrix() {
    let mut r = rig();
    let (d, e) = (r.dev, r.element());
    // Integer getter on a rectangle, float getter on an integer attribute.
    r.w.element_attrib_i(d, e, ELEMENT_DESTINATION_RECTANGLE);
    assert_eq!(r.err(), ERROR_BAD_ATTRIBUTE);
    r.w.element_attrib_i(d, e, ELEMENT_SOURCE_RECTANGLE);
    assert_eq!(r.err(), ERROR_BAD_ATTRIBUTE);
    r.w.element_attrib_f(d, e, ELEMENT_SOURCE);
    assert_eq!(r.err(), ERROR_BAD_ATTRIBUTE);
    let mut four = [0; 4];
    r.w.element_attrib_iv(d, e, ELEMENT_SOURCE, Some(&mut four));
    assert_eq!(r.err(), ERROR_BAD_ATTRIBUTE);
    r.w.element_attrib_i(d, e, 0x9999);
    assert_eq!(r.err(), ERROR_BAD_ATTRIBUTE);
}

#[test]
fn s7_4_setter_accessor_matrix() {
    let mut r = rig();
    let e = r.element();
    r.set_i(e, ELEMENT_DESTINATION_RECTANGLE, 1);
    assert_eq!(r.err(), ERROR_BAD_ATTRIBUTE);
    r.w.set_element_attrib_f(r.dev, e, ELEMENT_SOURCE_ROTATION, 1.0);
    assert_eq!(r.err(), ERROR_BAD_ATTRIBUTE);
    r.w.set_element_attrib_iv(r.dev, e, ELEMENT_GLOBAL_ALPHA, Some(&[1; 4]));
    assert_eq!(r.err(), ERROR_BAD_ATTRIBUTE);
    r.w.set_element_attrib_fv(r.dev, e, ELEMENT_MASK, Some(&[1.0; 4]));
    assert_eq!(r.err(), ERROR_BAD_ATTRIBUTE);
}

#[test]
fn s7_3_count_and_null() {
    let mut r = rig();
    let e = r.element();
    let mut three = [0; 3];
    r.w.element_attrib_iv(r.dev, e, ELEMENT_DESTINATION_RECTANGLE, Some(&mut three));
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
    r.w.element_attrib_fv(r.dev, e, ELEMENT_SOURCE_RECTANGLE, None);
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
    r.w.set_element_attrib_iv(r.dev, e, ELEMENT_DESTINATION_RECTANGLE, Some(&[1, 2, 3]));
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
    r.w.set_element_attrib_fv(r.dev, e, ELEMENT_SOURCE_RECTANGLE, None);
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
}

#[test]
fn s7_1_1_destination_rectangle_limits() {
    let mut r = rig();
    let e = r.element();
    for bad in [
        [0, 0, -1, 5],
        [0, 0, 5, -1],
        [MAX_INT + 1, 0, 1, 1],
        [0, 0, MAX_INT + 1, 1],
    ] {
        r.w.set_element_attrib_iv(r.dev, e, ELEMENT_DESTINATION_RECTANGLE, Some(&bad));
        assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT, "{bad:?}");
    }
    r.dst(e, [-50, -60, 700, 500]);
    r.dst(e, [MAX_INT, -MAX_INT, 0, 0]);
}

#[test]
fn s7_1_1_destination_by_float_is_floored() {
    let mut r = rig();
    let e = r.element();
    r.w.set_element_attrib_fv(
        r.dev,
        e,
        ELEMENT_DESTINATION_RECTANGLE,
        Some(&[1.9, -0.5, 10.99, 3.0]),
    );
    let mut out = [0; 4];
    r.w.element_attrib_iv(r.dev, e, ELEMENT_DESTINATION_RECTANGLE, Some(&mut out));
    assert_eq!(out, [1, -1, 10, 3]);
}

#[test]
fn s7_1_1_destination_float_negative_size_after_floor() {
    let mut r = rig();
    let e = r.element();
    r.w.set_element_attrib_fv(
        r.dev,
        e,
        ELEMENT_DESTINATION_RECTANGLE,
        Some(&[0.0, 0.0, -0.5, 1.0]),
    );
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
}

#[test]
fn s7_1_3_source_rectangle_round_trips_by_float() {
    let mut r = rig();
    let e = r.element();
    let v = [0.25, 1.5, 7.125, 0.001];
    r.src_rect(e, v);
    let mut out = [0.0; 4];
    r.w.element_attrib_fv(r.dev, e, ELEMENT_SOURCE_RECTANGLE, Some(&mut out));
    assert_eq!(out, v);
    let mut ints = [0; 4];
    r.w.element_attrib_iv(r.dev, e, ELEMENT_SOURCE_RECTANGLE, Some(&mut ints));
    assert_eq!(ints, [0, 1, 7, 0]);
}

#[test]
fn s7_1_3_source_rectangle_by_integer() {
    let mut r = rig();
    let e = r.element();
    r.w.set_element_attrib_iv(r.dev, e, ELEMENT_SOURCE_RECTANGLE, Some(&[1, 2, 3, 4]));
    assert_eq!(r.err(), 0);
    let mut out = [0.0; 4];
    r.w.element_attrib_fv(r.dev, e, ELEMENT_SOURCE_RECTANGLE, Some(&mut out));
    assert_eq!(out, [1.0, 2.0, 3.0, 4.0]);
}

#[test]
fn s7_1_3_source_rectangle_no_negative_value() {
    let mut r = rig();
    let e = r.element();
    for bad in [
        [-1.0, 0.0, 1.0, 1.0],
        [0.0, 0.0, -1.0, 1.0],
        [0.0, 0.0, f32::NAN, 1.0],
        [0.0, 0.0, 1.0e9, 1.0],
    ] {
        r.w.set_element_attrib_fv(r.dev, e, ELEMENT_SOURCE_RECTANGLE, Some(&bad));
        assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
    }
}

#[test]
fn s7_1_4_flip_is_a_boolean() {
    let mut r = rig();
    let e = r.element();
    r.set_i(e, ELEMENT_SOURCE_FLIP, 1);
    assert_eq!(r.w.element_attrib_i(r.dev, e, ELEMENT_SOURCE_FLIP), 1);
    r.set_i(e, ELEMENT_SOURCE_FLIP, 7);
    assert_eq!(r.w.element_attrib_i(r.dev, e, ELEMENT_SOURCE_FLIP), 1);
    r.set_i(e, ELEMENT_SOURCE_FLIP, 0);
    assert_eq!(r.w.element_attrib_i(r.dev, e, ELEMENT_SOURCE_FLIP), 0);
    assert_eq!(r.err(), 0);
}

#[test]
fn s7_1_5_source_rotation_values() {
    let mut r = rig();
    let e = r.element();
    for v in [ROTATION_90, ROTATION_180, ROTATION_270, ROTATION_0] {
        r.set_i(e, ELEMENT_SOURCE_ROTATION, v);
        assert_eq!(r.w.element_attrib_i(r.dev, e, ELEMENT_SOURCE_ROTATION), v);
    }
    r.set_i(e, ELEMENT_SOURCE_ROTATION, 0);
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
}

#[test]
fn s7_1_6_scale_filter_values() {
    let mut r = rig();
    let e = r.element();
    for v in [SCALE_FILTER_FASTER, SCALE_FILTER_BETTER, SCALE_FILTER_NONE] {
        r.set_i(e, ELEMENT_SOURCE_SCALE_FILTER, v);
        assert_eq!(
            r.w.element_attrib_i(r.dev, e, ELEMENT_SOURCE_SCALE_FILTER),
            v
        );
    }
    r.set_i(e, ELEMENT_SOURCE_SCALE_FILTER, 0x7150);
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
}

#[test]
fn s7_1_7_transparency_patterns() {
    let mut r = rig();
    let e = r.element();
    let allowed = [0, 1, 2, 4, 3, 5];
    for v in 0..16 {
        r.set_i(e, ELEMENT_TRANSPARENCY_TYPES, v);
        if allowed.contains(&v) {
            assert_eq!(r.err(), 0, "{v}");
            assert_eq!(
                r.w.element_attrib_i(r.dev, e, ELEMENT_TRANSPARENCY_TYPES),
                v
            );
        } else {
            assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT, "{v}");
        }
    }
}

#[test]
fn s7_1_8_global_alpha_integer_and_float() {
    let mut r = rig();
    let e = r.element();
    r.set_i(e, ELEMENT_GLOBAL_ALPHA, 51);
    assert_eq!(
        r.w.element_attrib_f(r.dev, e, ELEMENT_GLOBAL_ALPHA),
        51.0 / 255.0
    );
    assert_eq!(r.w.element_attrib_i(r.dev, e, ELEMENT_GLOBAL_ALPHA), 51);
    r.w.set_element_attrib_f(r.dev, e, ELEMENT_GLOBAL_ALPHA, 0.5);
    assert_eq!(r.w.element_attrib_f(r.dev, e, ELEMENT_GLOBAL_ALPHA), 0.5);
    assert_eq!(r.w.element_attrib_i(r.dev, e, ELEMENT_GLOBAL_ALPHA), 128);
    assert_eq!(r.err(), 0);
}

#[test]
fn s7_1_8_global_alpha_range() {
    let mut r = rig();
    let e = r.element();
    r.set_i(e, ELEMENT_GLOBAL_ALPHA, 256);
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
    r.set_i(e, ELEMENT_GLOBAL_ALPHA, -1);
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
    r.w.set_element_attrib_f(r.dev, e, ELEMENT_GLOBAL_ALPHA, 1.5);
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
    r.w.set_element_attrib_f(r.dev, e, ELEMENT_GLOBAL_ALPHA, f32::NAN);
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
}

#[test]
fn s7_4_bad_element_handle() {
    let mut r = rig();
    r.set_i(0, ELEMENT_SOURCE_FLIP, 1);
    assert_eq!(r.err(), ERROR_BAD_HANDLE);
    r.w.element_attrib_f(r.dev, r.ctx, ELEMENT_GLOBAL_ALPHA);
    assert_eq!(r.err(), ERROR_BAD_HANDLE);
}

#[test]
fn s7_1_2_source_attribute_takes_a_live_source() {
    let mut r = rig();
    let s = r.source(1, 4, 4);
    let e = r.element();
    r.set_i(e, ELEMENT_SOURCE, s as i32);
    assert_eq!(r.w.element_attrib_i(r.dev, e, ELEMENT_SOURCE), s as i32);
    r.set_i(e, ELEMENT_SOURCE, 12345);
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
}

// ---------------------------------------------------------- 7.5: ordering

#[test]
fn s7_5_1_insert_with_no_subordinate_goes_to_the_bottom() {
    let mut r = rig();
    let (a, b, c) = (r.element(), r.element(), r.element());
    r.w.insert_element(r.dev, a, 0);
    r.w.insert_element(r.dev, b, 0);
    r.w.insert_element(r.dev, c, 0);
    assert_eq!(r.order(), vec![c, b, a]);
}

#[test]
fn s7_5_1_insert_above_the_subordinate() {
    let mut r = rig();
    let (a, b, c) = (r.element(), r.element(), r.element());
    r.w.insert_element(r.dev, a, 0);
    r.w.insert_element(r.dev, b, a);
    r.w.insert_element(r.dev, c, a);
    assert_eq!(r.order(), vec![a, c, b]);
    assert_eq!(r.err(), 0);
}

#[test]
fn s7_5_1_reinsert_moves_the_element() {
    let mut r = rig();
    let (a, b, c) = (r.element(), r.element(), r.element());
    r.w.insert_element(r.dev, a, 0);
    r.w.insert_element(r.dev, b, a);
    r.w.insert_element(r.dev, c, b);
    r.w.insert_element(r.dev, a, c);
    assert_eq!(r.order(), vec![b, c, a]);
    r.w.insert_element(r.dev, c, 0);
    assert_eq!(r.order(), vec![c, b, a]);
}

#[test]
fn s7_5_1_insert_above_itself_has_no_effect() {
    let mut r = rig();
    let (a, b) = (r.element(), r.element());
    r.w.insert_element(r.dev, a, 0);
    r.w.insert_element(r.dev, b, a);
    r.w.insert_element(r.dev, a, a);
    assert_eq!(r.order(), vec![a, b]);
    assert_eq!(r.err(), 0);
}

#[test]
fn s7_5_1_subordinate_outside_the_scene_is_illegal() {
    let mut r = rig();
    let (a, b) = (r.element(), r.element());
    r.w.insert_element(r.dev, a, b);
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
    r.w.insert_element(r.dev, a, a);
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
    assert!(r.order().is_empty());
}

#[test]
fn s7_5_1_bad_handles_in_insert() {
    let mut r = rig();
    let a = r.element();
    r.w.insert_element(r.dev, 999, 0);
    assert_eq!(r.err(), ERROR_BAD_HANDLE);
    r.w.insert_element(r.dev, a, 999);
    assert_eq!(r.err(), ERROR_BAD_HANDLE);
}

#[test]
fn s7_5_1_subordinate_of_another_device_is_a_bad_handle() {
    let mut r = rig();
    let mut other = Wfc::create_device(0, &[], Setup::VIRTIO).unwrap();
    let od = other.device();
    let mut svc = Fake::default();
    let oc = other.create_on_screen_context(od, 0, &[], &mut svc);
    let foreign = other.create_element(od, oc, &[]);
    let a = r.element();
    r.w.insert_element(r.dev, a, foreign);
    assert_eq!(r.err(), ERROR_BAD_HANDLE);
}

#[test]
fn s7_5_2_remove_element() {
    let mut r = rig();
    let (a, b) = (r.element(), r.element());
    r.w.insert_element(r.dev, a, 0);
    r.w.insert_element(r.dev, b, a);
    r.w.remove_element(r.dev, a);
    assert_eq!(r.order(), vec![b]);
    r.w.remove_element(r.dev, a);
    assert_eq!(r.err(), 0);
    r.w.remove_element(r.dev, 999);
    assert_eq!(r.err(), ERROR_BAD_HANDLE);
}

#[test]
fn s7_5_3_above_and_below() {
    let mut r = rig();
    let (a, b, c) = (r.element(), r.element(), r.element());
    r.w.insert_element(r.dev, a, 0);
    r.w.insert_element(r.dev, b, a);
    r.w.insert_element(r.dev, c, b);
    assert_eq!(r.w.element_above(r.dev, a), b);
    assert_eq!(r.w.element_above(r.dev, b), c);
    assert_eq!(r.w.element_above(r.dev, c), 0);
    assert_eq!(r.w.element_below(r.dev, c), b);
    assert_eq!(r.w.element_below(r.dev, a), 0);
    assert_eq!(r.err(), 0);
}

#[test]
fn s7_5_3_above_of_a_stranger_is_illegal_and_bad_handle_is_bad() {
    let mut r = rig();
    let a = r.element();
    assert_eq!(r.w.element_below(r.dev, a), 0);
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
    r.w.element_above(r.dev, 4242);
    assert_eq!(r.err(), ERROR_BAD_HANDLE);
}

#[test]
fn s7_6_destroy_element_leaves_the_scene() {
    let mut r = rig();
    let (a, b) = (r.element(), r.element());
    r.w.insert_element(r.dev, a, 0);
    r.w.insert_element(r.dev, b, a);
    r.w.destroy_element(r.dev, a);
    assert_eq!(r.order(), vec![b]);
    r.w.destroy_element(r.dev, a);
    assert_eq!(r.err(), ERROR_BAD_HANDLE);
}

#[test]
fn s7_6_destroy_does_not_touch_the_committed_scene_until_commit() {
    let mut r = rig();
    let e = r.shown(1);
    r.commit();
    r.w.destroy_element(r.dev, e);
    assert_eq!(r.w.ctx.unwrap().committed.count, 1);
    r.commit();
    assert_eq!(r.w.ctx.unwrap().committed.count, 0);
}

// ------------------------------------------------------------- 5.4: commit

#[test]
fn s5_4_empty_commit_sends_an_empty_scene() {
    let mut r = rig();
    r.commit();
    let c = r.svc.last();
    assert_eq!((c.flags, c.count, c.bg), (0, 0, 0xFF00_0000));
}

#[test]
fn s5_4_record_is_bottom_up() {
    let mut r = rig();
    let a = r.shown(10);
    let b = r.shown(11);
    r.w.insert_element(r.dev, b, 0); // b to the bottom
    let _ = a;
    r.commit();
    let c = r.svc.last();
    assert_eq!(c.count, 2);
    assert_eq!((c.elements[0].source, c.elements[1].source), (11, 10));
}

#[test]
fn s5_4_record_fields() {
    let mut r = rig();
    let e = r.shown(7);
    r.set_i(e, ELEMENT_GLOBAL_ALPHA, 100);
    r.set_i(e, ELEMENT_TRANSPARENCY_TYPES, 1);
    r.src_rect(e, [2.5, 4.0, 50.0, 25.25]);
    r.commit();
    let m = r.svc.last().elements[0];
    assert_eq!(m.source, 7);
    assert_eq!(m.mask, NO_WINDOW);
    assert_eq!((m.sx, m.sy, m.sw, m.sh), (163840, 262144, 3276800, 1654784));
    assert_eq!((m.dx, m.dy, m.dw, m.dh), (10, 20, 100, 100));
    assert_eq!(
        (m.orient, m.filter, m.transparency, m.alpha),
        (0, 0, 1, 100)
    );
}

#[test]
fn s7_1_6_filter_map() {
    let mut r = rig();
    let e = r.shown(1);
    for (v, want) in [
        (SCALE_FILTER_NONE, NEAREST),
        (SCALE_FILTER_FASTER, NEAREST),
        (SCALE_FILTER_BETTER, BILINEAR),
    ] {
        r.set_i(e, ELEMENT_SOURCE_SCALE_FILTER, v);
        r.commit();
        assert_eq!(r.svc.last().elements[0].filter, want);
    }
}

#[test]
fn s5_1_5_background_is_premultiplied_and_opaque() {
    let mut r = rig();
    r.w.set_context_attrib_i(r.dev, r.ctx, CONTEXT_BG_COLOR, 0x1020_30FFu32 as i32);
    r.commit();
    assert_eq!(r.svc.last().bg, 0xFF10_2030);
}

#[test]
fn s7_1_1_elements_that_draw_nothing_are_left_out() {
    let mut r = rig();
    let s = r.source(1, 100, 100);
    // No source at all.
    let none = r.element();
    r.dst(none, [0, 0, 10, 10]);
    r.src_rect(none, [0.0, 0.0, 10.0, 10.0]);
    r.w.insert_element(r.dev, none, 0);
    // Zero destination.
    let zd = r.element();
    r.set_i(zd, ELEMENT_SOURCE, s as i32);
    r.src_rect(zd, [0.0, 0.0, 10.0, 10.0]);
    r.w.insert_element(r.dev, zd, none);
    // Zero source (the default rectangle).
    let zs = r.element();
    r.set_i(zs, ELEMENT_SOURCE, s as i32);
    r.dst(zs, [0, 0, 10, 10]);
    r.w.insert_element(r.dev, zs, zd);
    r.commit();
    assert_eq!(r.err(), 0);
    assert_eq!(r.svc.last().count, 0);
}

#[test]
fn s7_1_3_zero_side_after_rounding_is_left_out() {
    let mut r = rig();
    let e = r.shown(1);
    r.src_rect(e, [0.0, 0.0, 1.0e-6, 50.0]);
    r.commit();
    assert_eq!(r.err(), 0);
    assert_eq!(r.svc.last().count, 0);
}

/// Two floats near 50 whose sum in `f32` is exactly 100 and whose 16.16
/// roundings (both up) add to one unit more than the window.
fn edge_pair() -> (f32, f32) {
    let ulp = 2f32.powi(-18);
    (50.0 + 2.0 * ulp, 50.0 - 2.0 * ulp)
}

#[test]
fn s7_1_3_source_rectangle_is_trimmed_at_the_window_edge() {
    let (a, b) = edge_pair();
    assert_eq!(a + b, 100.0);
    assert!(to_fixed(a) + to_fixed(b) > 100 * 65536, "needs the trim");
    let mut r = rig();
    let e = r.shown(1);
    r.src_rect(e, [a, 0.0, b, 100.0]);
    r.commit();
    assert_eq!(r.err(), 0);
    let m = r.svc.last().elements[0];
    assert_eq!(m.sx + m.sw, 100 * 65536);
    assert_eq!(m.sw, 100 * 65536 - to_fixed(a));
}

#[test]
fn s7_1_3_source_rectangle_is_trimmed_at_the_bottom_edge() {
    let (a, b) = edge_pair();
    let mut r = rig();
    let e = r.shown(1);
    r.src_rect(e, [0.0, a, 100.0, b]);
    r.commit();
    assert_eq!(r.err(), 0);
    let m = r.svc.last().elements[0];
    assert_eq!(m.sy + m.sh, 100 * 65536);
    assert_eq!(m.sh, 100 * 65536 - to_fixed(a));
}

#[test]
fn s7_1_3_trim_can_bring_a_side_to_zero() {
    let mut r = rig();
    let e = r.shown(1);
    // The rectangle starts at the edge: its width is tiny and the trim leaves 0.
    r.src_rect(e, [99.999_99, 0.0, 0.000_01, 100.0]);
    r.commit();
    assert_eq!(r.err(), 0);
    let c = r.svc.last();
    for m in c.elements() {
        assert!(m.sw > 0 && m.sx + m.sw <= 100 * 65536);
    }
    let e2 = r.shown(2);
    r.src_rect(e2, [100.0, 0.0, 0.0, 100.0]);
    r.commit();
    assert_eq!(r.err(), 0);
}

#[test]
fn s5_4_source_rectangle_outside_the_source_is_inconsistent() {
    let mut r = rig();
    let e = r.shown(1);
    r.src_rect(e, [60.0, 0.0, 50.0, 10.0]);
    r.commit();
    assert_eq!(r.err(), ERROR_INCONSISTENCY);
    assert!(r.svc.commits().is_empty());
    r.src_rect(e, [0.0, 95.0, 10.0, 6.0]);
    r.commit();
    assert_eq!(r.err(), ERROR_INCONSISTENCY);
}

#[test]
fn s5_4_exactly_the_whole_source_is_consistent() {
    let mut r = rig();
    r.shown(1);
    r.commit();
    assert_eq!(r.err(), 0);
    assert_eq!(r.svc.last().elements[0].sw, 100 * 65536);
}

#[test]
fn s5_4_inconsistency_leaves_the_committed_scene() {
    let mut r = rig();
    let e = r.shown(1);
    r.commit();
    r.src_rect(e, [60.0, 0.0, 50.0, 10.0]);
    r.commit();
    assert_eq!(r.err(), ERROR_INCONSISTENCY);
    assert_eq!(r.w.ctx.unwrap().committed.elements[0].sw, 100 * 65536);
}

#[test]
fn s5_4_elements_outside_the_scene_are_not_checked() {
    let mut r = rig();
    let s = r.source(1, 10, 10);
    let e = r.element();
    r.set_i(e, ELEMENT_SOURCE, s as i32);
    r.src_rect(e, [0.0, 0.0, 99.0, 99.0]);
    r.commit();
    assert_eq!(r.err(), 0);
}

#[test]
fn s7_1_9_mask_size_must_match_the_destination() {
    let mut r = rig();
    let e = r.shown(1);
    let m = r.mask(2, 50, 50);
    r.set_i(e, ELEMENT_MASK, m as i32);
    r.set_i(e, ELEMENT_TRANSPARENCY_TYPES, 4);
    r.commit();
    assert_eq!(r.err(), ERROR_INCONSISTENCY);
    assert!(r.svc.commits().is_empty());
    r.dst(e, [10, 20, 50, 50]);
    r.commit();
    assert_eq!(r.err(), 0);
    assert_eq!(r.svc.last().elements[0].mask, 2);
}

#[test]
fn s7_1_9_mask_size_is_checked_even_without_the_transparency_bit() {
    let mut r = rig();
    let e = r.shown(1);
    let m = r.mask(2, 50, 50);
    r.set_i(e, ELEMENT_MASK, m as i32);
    r.commit();
    assert_eq!(r.err(), ERROR_INCONSISTENCY);
}

#[test]
fn s7_1_9_mask_bit_without_a_mask_is_no_masking() {
    let mut r = rig();
    let e = r.shown(1);
    r.set_i(e, ELEMENT_TRANSPARENCY_TYPES, 4);
    r.commit();
    let m = r.svc.last().elements[0];
    assert_eq!((m.transparency, m.mask), (0, NO_WINDOW));
    r.set_i(e, ELEMENT_TRANSPARENCY_TYPES, 5);
    r.commit();
    assert_eq!(r.svc.last().elements[0].transparency, 1);
}

#[test]
fn s7_1_7_mask_is_named_only_with_its_bit() {
    let mut r = rig();
    let e = r.shown(1);
    let m = r.mask(2, 100, 100);
    r.set_i(e, ELEMENT_MASK, m as i32);
    r.commit();
    assert_eq!(r.svc.last().elements[0].mask, NO_WINDOW);
    r.set_i(e, ELEMENT_TRANSPARENCY_TYPES, 5);
    r.commit();
    let rec = r.svc.last().elements[0];
    assert_eq!((rec.mask, rec.transparency), (2, 5));
}

#[test]
fn s5_4_commit_keeps_the_pending_state() {
    let mut r = rig();
    let e = r.shown(1);
    r.commit();
    assert_eq!(r.order(), vec![e]);
    assert!(r.w.element_attrib_i(r.dev, e, ELEMENT_SOURCE) != 0);
}

#[test]
fn s5_4_commit_wait_asks_committed_and_waits() {
    let mut r = rig();
    r.w.commit(r.dev, r.ctx, true, &mut r.svc);
    assert_eq!(r.svc.last().flags, ASK_COMMITTED);
    assert_eq!(r.svc.log.last(), Some(&Ev::Wait(COMMITTED_BIT)));
}

#[test]
fn s5_4_commit_without_wait_does_not_wait() {
    let mut r = rig();
    r.commit();
    assert_eq!(r.svc.last().flags, 0);
    assert!(!r.svc.log.iter().any(|e| matches!(e, Ev::Wait(_))));
}

#[test]
fn s5_4_commit_wait_clears_a_stale_bit_before_sending() {
    let mut r = rig();
    r.w.commit(r.dev, r.ctx, true, &mut r.svc);
    assert!(matches!(r.svc.log[0], Ev::Clear(COMMITTED_BIT)));
    assert!(matches!(r.svc.log[1], Ev::Commit(_)));
}

#[test]
fn s5_4_commit_carries_the_active_flag() {
    let mut r = rig();
    r.w.activate(r.dev, r.ctx, &mut r.svc);
    r.commit();
    assert_eq!(r.svc.last().flags, ACTIVE);
}

#[test]
fn s5_4_refused_commit_keeps_the_old_committed_scene() {
    let mut r = rig();
    let e = r.shown(1);
    r.commit();
    r.w.destroy_element(r.dev, e);
    r.svc
        .commit_refusals
        .push(Status::Unknown(proto_comp::NOT_ALLOWED));
    r.commit();
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
    assert_eq!(r.w.ctx.unwrap().committed.count, 1);
}

#[test]
fn s5_4_commit_bad_context() {
    let mut r = rig();
    r.w.commit(r.dev, r.ctx + 1, false, &mut r.svc);
    assert_eq!(r.err(), ERROR_BAD_HANDLE);
    assert!(r.svc.log.is_empty());
}

// ------------------------------------------------------ the rotation fold

/// The point of the source a target pixel takes, built straight from the
/// pipeline of specification 3: undo the context rotation, then the element's
/// own rotation, then the flip.
fn reference(
    (tx, ty): (i32, i32),
    ctx: u32,
    rot: u32,
    flip: bool,
    src: [f64; 4],
    dst: [i32; 4],
    (tw, th): (i32, i32),
) -> Option<(f64, f64)> {
    let (px, py) = (f64::from(tx) + 0.5, f64::from(ty) + 0.5);
    let (tw, th) = (f64::from(tw), f64::from(th));
    // Target to context coordinates (clockwise rotation undone).
    let (x, y) = match ctx % 4 {
        0 => (px, py),
        1 => (py, tw - px),
        2 => (tw - px, th - py),
        _ => (th - py, px),
    };
    let (u, v) = (
        (x - f64::from(dst[0])) / f64::from(dst[2]),
        (y - f64::from(dst[1])) / f64::from(dst[3]),
    );
    if !(0.0..1.0).contains(&u) || !(0.0..1.0).contains(&v) {
        return None;
    }
    let (mut u, mut v) = (u, v);
    for _ in 0..rot {
        (u, v) = (v, 1.0 - u);
    }
    if flip {
        v = 1.0 - v;
    }
    Some((src[0] + u * src[2], src[1] + v * src[3]))
}

fn folded_element(ctx: u32, rot: u32, flip: bool, dst: [i32; 4]) -> Element {
    let (o, m) = fold(rot, flip, ctx);
    let d = fold_rect(dst, ctx, 640, 400);
    Element {
        source: 1,
        mask: NO_WINDOW,
        sx: 3 << 16,
        sy: 5 << 16,
        sw: 40 << 16,
        sh: 20 << 16,
        dx: d[0],
        dy: d[1],
        dw: d[2],
        dh: d[3],
        orient: o | if m { MIRROR } else { 0 },
        filter: NEAREST,
        transparency: 0,
        alpha: 255,
    }
}

fn check_fold(ctx: u32, rot: u32, flip: bool, dst: [i32; 4]) {
    let e = folded_element(ctx, rot, flip, dst);
    let src = [3.0, 5.0, 40.0, 20.0];
    for ty in (0..400).step_by(7) {
        for tx in (0..640).step_by(7) {
            let want = reference((tx, ty), ctx, rot, flip, src, dst, (640, 400));
            let got = meaning::source_at(&e, tx, ty);
            match (want, got) {
                (None, None) => {}
                (Some((wx, wy)), Some((gx, gy))) => {
                    assert!(
                        (wx - gx as f64 / 65536.0).abs() < 0.01
                            && (wy - gy as f64 / 65536.0).abs() < 0.01,
                        "ctx {ctx} rot {rot} flip {flip} at ({tx},{ty}): {wx},{wy} vs {gx},{gy}"
                    );
                }
                _ => panic!("coverage differs at ({tx},{ty}) ctx {ctx} rot {rot} flip {flip}"),
            }
        }
    }
}

#[test]
fn s5_1_4_fold_rect_corners_for_the_four_rotations() {
    // A 10 by 20 rectangle at the top-left, then at the bottom-right corner.
    assert_eq!(fold_rect([0, 0, 10, 20], 0, 640, 400), [0, 0, 10, 20]);
    assert_eq!(fold_rect([0, 0, 10, 20], 1, 640, 400), [620, 0, 20, 10]);
    assert_eq!(fold_rect([0, 0, 10, 20], 2, 640, 400), [630, 380, 10, 20]);
    assert_eq!(fold_rect([0, 0, 10, 20], 3, 640, 400), [0, 390, 20, 10]);
    // The whole context view fills the target.
    assert_eq!(fold_rect([0, 0, 400, 640], 1, 640, 400), [0, 0, 640, 400]);
    assert_eq!(fold_rect([0, 0, 400, 640], 3, 640, 400), [0, 0, 640, 400]);
}

#[test]
fn s5_1_4_fold_matches_the_pipeline_without_flip() {
    for c in 0..4 {
        for r in 0..4 {
            let dst = if c % 2 == 1 {
                [30, 50, 160, 90]
            } else {
                [30, 50, 220, 90]
            };
            check_fold(c, r, false, dst);
        }
    }
}

#[test]
fn s7_1_4_fold_matches_the_pipeline_with_flip() {
    for c in 0..4 {
        for r in 0..4 {
            let dst = if c % 2 == 1 {
                [30, 50, 160, 90]
            } else {
                [30, 50, 220, 90]
            };
            check_fold(c, r, true, dst);
        }
    }
}

#[test]
fn s7_1_4_flip_with_context_rotation_90_tells_the_formulas_apart() {
    // Element rotation 0, context rotation 90, flip: (1,0) goes to (0,1) and
    // (0,0) stays at (0,0) in a 2 by 2 source. The wrong formula with
    // q = r + c + 2 gives (1,0) at (1,0).
    let (o, m) = fold(0, true, 1);
    assert_eq!((o, m), (1, true));
    // Source point (x, y) of a 2 by 2 image, as a unit square corner: rotate
    // clockwise by `o` quarter turns, then reflect about the vertical axis.
    let place = |o: u32, m: bool, p: (i32, i32)| {
        let (x, y) = (0..o).fold(p, |(x, y), _| (1 - y, x));
        if m { (1 - x, y) } else { (x, y) }
    };
    assert_eq!(place(o, m, (1, 0)), (0, 1));
    assert_eq!(place(o, m, (0, 0)), (0, 0));
    // The wrong formula q = r + c + 2 (rotation 3, then the reflection).
    assert_eq!(place(3, true, (1, 0)), (1, 0));
}

#[test]
fn s5_1_4_fold_table_of_sixteen() {
    // (element rotation, context rotation) to (rotation, mirror), no flip,
    // and with the flip.
    for r in 0..4 {
        for c in 0..4 {
            assert_eq!(fold(r, false, c), ((r + c) % 4, false));
            assert_eq!(fold(r, true, c), ((6 - (r + c) % 4) % 4, true));
        }
    }
}

#[test]
fn s5_1_4_commit_folds_rotation_into_every_element() {
    let mut r = rig();
    let e = r.shown(1);
    r.set_i(e, ELEMENT_SOURCE_ROTATION, ROTATION_90);
    r.set_i(e, ELEMENT_SOURCE_FLIP, 1);
    r.w.set_context_attrib_i(r.dev, r.ctx, CONTEXT_ROTATION, ROTATION_270);
    r.commit();
    let m = r.svc.last().elements[0];
    let (o, mir) = fold(1, true, 3);
    assert_eq!(m.orient, o | if mir { MIRROR } else { 0 });
    let d = fold_rect([10, 20, 100, 100], 3, 640, 400);
    assert_eq!([m.dx, m.dy, m.dw, m.dh], d);
}

#[test]
fn s5_1_4_fold_270_sign() {
    // A rectangle at the top-left of the context view turns to the bottom-left
    // of the target for 270 degrees clockwise.
    let d = fold_rect([0, 0, 50, 30], 3, 640, 400);
    assert_eq!(d, [0, 350, 30, 50]);
}

// -------------------------------------------------- 8: activation and compose

#[test]
fn s8_context_is_inactive_at_creation() {
    let r = rig();
    assert!(!r.w.ctx.unwrap().active);
    assert!(r.svc.log.is_empty());
}

#[test]
fn s8_1_activate_sends_the_committed_scene() {
    let mut r = rig();
    r.shown(1);
    r.commit();
    r.shown(2); // pending only
    r.w.activate(r.dev, r.ctx, &mut r.svc);
    let c = r.svc.last();
    assert_eq!((c.flags, c.count), (ACTIVE, 1));
    assert_eq!(c.elements[0].source, 1);
}

#[test]
fn s8_1_activate_twice_sends_once() {
    let mut r = rig();
    r.w.activate(r.dev, r.ctx, &mut r.svc);
    r.w.activate(r.dev, r.ctx, &mut r.svc);
    assert_eq!(r.svc.commits().len(), 1);
}

#[test]
fn s8_1_activate_does_not_wait() {
    let mut r = rig();
    r.w.activate(r.dev, r.ctx, &mut r.svc);
    assert_eq!(r.svc.log.len(), 1);
    assert_eq!(r.svc.last().flags & ASK_COMMITTED, 0);
}

#[test]
fn s8_2_deactivate_sends_the_same_scene_inactive() {
    let mut r = rig();
    r.shown(1);
    r.commit();
    r.w.activate(r.dev, r.ctx, &mut r.svc);
    r.w.deactivate(r.dev, r.ctx, &mut r.svc);
    let c = r.svc.last();
    assert_eq!((c.flags, c.count), (0, 1));
    r.w.deactivate(r.dev, r.ctx, &mut r.svc);
    assert_eq!(r.svc.commits().len(), 3);
}

#[test]
fn s8_activate_bad_context_and_refusal() {
    let mut r = rig();
    r.w.activate(r.dev, 77, &mut r.svc);
    assert_eq!(r.err(), ERROR_BAD_HANDLE);
    r.svc
        .commit_refusals
        .push(Status::Unknown(proto_comp::UNSUPPORTED));
    r.w.activate(r.dev, r.ctx, &mut r.svc);
    assert_eq!(r.err(), ERROR_UNSUPPORTED);
    assert!(!r.w.ctx.unwrap().active);
}

#[test]
fn s8_3_compose_asks_for_composed() {
    let mut r = rig();
    r.w.compose(r.dev, r.ctx, false, &mut r.svc);
    assert!(r.svc.log.contains(&Ev::Compose(ASK_COMPOSED)));
    assert!(!r.svc.log.iter().any(|e| matches!(e, Ev::Wait(_))));
}

#[test]
fn s8_3_compose_wait_waits_for_composed() {
    let mut r = rig();
    r.w.compose(r.dev, r.ctx, true, &mut r.svc);
    assert_eq!(r.svc.log.last(), Some(&Ev::Wait(COMPOSED_BIT)));
    assert_eq!(r.err(), 0);
}

#[test]
fn s8_3_compose_on_an_active_context_is_unsupported() {
    let mut r = rig();
    r.w.activate(r.dev, r.ctx, &mut r.svc);
    r.svc.log.clear();
    r.w.compose(r.dev, r.ctx, true, &mut r.svc);
    assert_eq!(r.err(), ERROR_UNSUPPORTED);
    assert!(r.svc.log.is_empty());
}

#[test]
fn s8_3_busy_without_wait_is_the_result() {
    let mut r = rig();
    r.svc.compose_refusals.push(BUSY);
    r.w.compose(r.dev, r.ctx, false, &mut r.svc);
    assert_eq!(r.err(), ERROR_BUSY);
    assert!(!r.svc.log.contains(&Ev::Pause));
}

#[test]
fn s8_3_busy_with_wait_is_waited_out_after_clearing_a_stale_bit() {
    let mut r = rig();
    r.svc.compose_refusals.push(BUSY);
    r.svc.compose_refusals.push(BUSY);
    r.w.compose(r.dev, r.ctx, true, &mut r.svc);
    assert_eq!(r.err(), 0);
    use Ev::*;
    assert_eq!(
        r.svc.log,
        vec![
            Clear(COMPOSED_BIT),
            Compose(ASK_COMPOSED),
            Pause,
            Clear(COMPOSED_BIT),
            Compose(ASK_COMPOSED),
            Pause,
            Clear(COMPOSED_BIT),
            Compose(ASK_COMPOSED),
            Wait(COMPOSED_BIT),
        ]
    );
}

#[test]
fn s8_3_compose_wait_after_an_unwaited_compose_never_fails_with_busy() {
    let mut r = rig();
    r.w.compose(r.dev, r.ctx, false, &mut r.svc);
    r.svc.compose_refusals.push(BUSY);
    r.w.compose(r.dev, r.ctx, true, &mut r.svc);
    assert_eq!(r.err(), 0);
    // The wait is for the second frame: the bit was cleared just before it was sent.
    let log = &r.svc.log;
    let last_send = log
        .iter()
        .rposition(|e| matches!(e, Ev::Compose(_)))
        .unwrap();
    assert_eq!(log[last_send - 1], Ev::Clear(COMPOSED_BIT));
    assert_eq!(log[last_send + 1], Ev::Wait(COMPOSED_BIT));
}

#[test]
fn s8_3_pause_failure_loses_the_device() {
    let mut r = rig();
    r.svc.compose_refusals.push(BUSY);
    r.svc.pause_refusal = Some(Status::Kernel(Error::PeerClosed));
    r.w.compose(r.dev, r.ctx, true, &mut r.svc);
    assert_eq!(r.err(), ERROR_BAD_DEVICE);
    assert!(r.w.is_lost());
}

#[test]
fn s8_3_wait_failure_is_reported() {
    let mut r = rig();
    r.svc.wait_refusal = Some(Status::Kernel(Error::PeerClosed));
    r.w.compose(r.dev, r.ctx, true, &mut r.svc);
    assert_eq!(r.err(), ERROR_BAD_DEVICE);
}

#[test]
fn s5_4_commit_after_a_failed_wait_clears_again() {
    let mut r = rig();
    r.svc.wait_refusal = Some(Status::Unknown(proto_comp::UNSUPPORTED));
    r.w.commit(r.dev, r.ctx, true, &mut r.svc);
    assert_eq!(r.err(), ERROR_UNSUPPORTED);
    r.svc.wait_refusal = None;
    r.svc.log.clear();
    r.w.commit(r.dev, r.ctx, true, &mut r.svc);
    assert!(matches!(r.svc.log[0], Ev::Clear(COMMITTED_BIT)));
}

#[test]
fn s9_fence_is_illegal_argument() {
    let mut r = rig();
    r.w.fence(r.dev, r.ctx);
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
    r.w.fence(r.dev, 99);
    assert_eq!(r.err(), ERROR_BAD_HANDLE);
}

#[test]
fn s9_fence_works_on_a_lost_device_without_the_service() {
    let mut r = rig();
    r.svc
        .commit_refusals
        .push(Status::Kernel(Error::PeerClosed));
    r.commit();
    let _ = r.err();
    r.w.fence(r.dev, r.ctx);
    assert_eq!(r.err(), ERROR_ILLEGAL_ARGUMENT);
}

// ------------------------------------------------- refusals of the service

fn refuse_commit(status: Status) -> i32 {
    let mut r = rig();
    r.svc.commit_refusals.push(status);
    r.commit();
    r.err()
}

#[test]
fn p5_4_limit_reached_is_out_of_memory() {
    assert_eq!(
        refuse_commit(Status::Kernel(Error::LimitReached)),
        ERROR_OUT_OF_MEMORY
    );
}

#[test]
fn p5_4_not_allowed_is_illegal_argument() {
    assert_eq!(
        refuse_commit(Status::Unknown(proto_comp::NOT_ALLOWED)),
        ERROR_ILLEGAL_ARGUMENT
    );
}

#[test]
fn p5_4_busy_is_busy() {
    assert_eq!(refuse_commit(BUSY), ERROR_BUSY);
}

#[test]
fn p5_4_unsupported_is_unsupported() {
    assert_eq!(
        refuse_commit(Status::Unknown(proto_comp::UNSUPPORTED)),
        ERROR_UNSUPPORTED
    );
}

#[test]
fn p5_4_peer_closed_is_bad_device() {
    assert_eq!(
        refuse_commit(Status::Kernel(Error::PeerClosed)),
        ERROR_BAD_DEVICE
    );
}

#[test]
fn p5_4_invalid_after_our_own_checks_is_illegal_argument() {
    assert_eq!(
        refuse_commit(Status::Unknown(proto_comp::INVALID)),
        ERROR_ILLEGAL_ARGUMENT
    );
    assert_eq!(refuse_commit(Status::BadSize), ERROR_ILLEGAL_ARGUMENT);
}

#[test]
fn p5_4_protocol_mismatch_is_bad_device() {
    assert_eq!(refuse_commit(Status::BadVersion), ERROR_BAD_DEVICE);
    assert_eq!(refuse_commit(Status::UnknownMethod), ERROR_BAD_DEVICE);
}

#[test]
fn p5_4_commit_busy_with_wait_is_retried() {
    let mut r = rig();
    r.svc.commit_refusals.push(BUSY);
    r.w.commit(r.dev, r.ctx, true, &mut r.svc);
    assert_eq!(r.err(), 0);
    assert_eq!(r.svc.commits().len(), 2);
    assert!(r.svc.log.contains(&Ev::Pause));
}

#[test]
fn p5_4_lost_device_answers_bad_device_from_each_calling_function() {
    let mut r = rig();
    let s = r.source(1, 8, 8);
    let _ = s;
    r.svc
        .commit_refusals
        .push(Status::Kernel(Error::PeerClosed));
    r.commit();
    assert_eq!(r.err(), ERROR_BAD_DEVICE);
    r.svc.log.clear();
    r.commit();
    assert_eq!(r.err(), ERROR_BAD_DEVICE);
    r.w.activate(r.dev, r.ctx, &mut r.svc);
    assert_eq!(r.err(), ERROR_BAD_DEVICE);
    r.w.deactivate(r.dev, r.ctx, &mut r.svc);
    // Already inactive: no message and no error is needed, but the loss shows.
    assert_eq!(r.err(), ERROR_BAD_DEVICE);
    r.w.compose(r.dev, r.ctx, false, &mut r.svc);
    assert_eq!(r.err(), ERROR_BAD_DEVICE);
    assert_eq!(
        r.w.create_source_from_stream(r.dev, r.ctx, Some(info(2, 4, 4)), &[]),
        0
    );
    assert_eq!(r.err(), ERROR_BAD_DEVICE);
    assert_eq!(
        r.w.create_mask_from_stream(
            r.dev,
            r.ctx,
            Some(StreamInfo {
                format: FORMAT_A8,
                ..info(3, 4, 4)
            }),
            &[]
        ),
        0
    );
    assert_eq!(r.err(), ERROR_BAD_DEVICE);
    assert!(!r.w.stream_allowed(r.dev));
    assert_eq!(r.err(), ERROR_BAD_DEVICE);
    assert!(r.svc.log.is_empty());
}

#[test]
fn p5_4_lost_device_still_answers_from_the_cache() {
    let mut r = rig();
    r.svc
        .commit_refusals
        .push(Status::Kernel(Error::PeerClosed));
    r.commit();
    let _ = r.err();
    let e = r.element();
    r.set_i(e, ELEMENT_GLOBAL_ALPHA, 9);
    assert_eq!(r.w.element_attrib_i(r.dev, e, ELEMENT_GLOBAL_ALPHA), 9);
    assert_eq!(r.err(), 0);
}

#[test]
fn p5_4_stream_allowed_when_the_service_is_there() {
    let mut r = rig();
    assert!(r.w.stream_allowed(r.dev));
    assert!(!r.w.stream_allowed(0));
    assert_eq!(r.err(), 0);
}

// ------------------------------------------------------- pure functions

#[test]
fn p5_4_to_fixed_rounds_to_nearest() {
    assert_eq!(to_fixed(0.0), 0);
    assert_eq!(to_fixed(1.0), 65536);
    assert_eq!(to_fixed(0.5), 32768);
    assert_eq!(to_fixed(1.0 / 131072.0), 1); // half a unit rounds up
    assert_eq!(to_fixed(0.4 / 65536.0), 0);
    assert_eq!(to_fixed(0.6 / 65536.0), 1);
    assert_eq!(to_fixed(-0.25), -16384);
}

#[test]
fn p5_4_to_fixed_saturates() {
    assert_eq!(to_fixed(1.0e9), i32::MAX);
    assert_eq!(to_fixed(-1.0e9), i32::MIN);
    assert_eq!(to_fixed(f32::NAN), 0);
}

#[test]
fn p5_4_to_alpha_rounds_to_nearest_and_clamps() {
    assert_eq!(to_alpha(0.0), 0);
    assert_eq!(to_alpha(1.0), 255);
    assert_eq!(to_alpha(0.5), 128);
    assert_eq!(to_alpha(0.498), 127);
    assert_eq!(to_alpha(2.0), 255);
    assert_eq!(to_alpha(-1.0), 0);
    assert_eq!(to_alpha(f32::NAN), 0);
}

#[test]
fn p5_4_alpha_round_trips_through_the_integer() {
    for v in 0..=255 {
        assert_eq!(to_alpha(v as f32 / 255.0), v);
    }
}

#[test]
fn p5_4_rect_to_fixed() {
    assert_eq!(
        rect_to_fixed([1.0, 2.5, 0.0, 3.0]),
        [65536, 163840, 0, 196608]
    );
}

#[test]
fn p5_4_translate_table() {
    assert_eq!(translate(Status::Ok), ERROR_NONE);
    assert_eq!(
        translate(Status::Kernel(Error::NoMemory)),
        ERROR_OUT_OF_MEMORY
    );
    assert_eq!(
        translate(Status::Unknown(proto_comp::NO_DEVICE)),
        ERROR_BAD_DEVICE
    );
    assert_eq!(
        translate(Status::Unknown(proto_comp::REVOKED)),
        ERROR_BAD_DEVICE
    );
    assert_eq!(
        translate(Status::Kernel(Error::BadHandle)),
        ERROR_BAD_DEVICE
    );
}

// ------------------------------------------------------- the review's cases

#[test]
fn s8_3_two_unwaited_composes_then_destroy_does_not_hang() {
    // The service sets COMPOSED before it answers; the library must not erase it.
    let mut r = rig();
    r.svc.set_on_compose = true;
    r.svc.strict_wait = true;
    r.w.compose(r.dev, r.ctx, false, &mut r.svc);
    r.w.compose(r.dev, r.ctx, false, &mut r.svc);
    assert_eq!(r.err(), 0);
    r.w.destroy_context(r.dev, r.ctx, &mut r.svc);
    assert_eq!(r.err(), 0);
    assert!(r.w.ctx.is_none());
}

#[test]
fn s8_3_destroy_device_after_unwaited_composes_does_not_hang() {
    let mut r = rig();
    r.svc.set_on_compose = true;
    r.svc.strict_wait = true;
    for _ in 0..3 {
        r.w.compose(r.dev, r.ctx, false, &mut r.svc);
    }
    assert_eq!(r.w.destroy_device(r.dev, &mut r.svc), ERROR_NONE);
}

#[test]
fn s8_3_clear_goes_before_every_send() {
    let mut r = rig();
    r.w.compose(r.dev, r.ctx, false, &mut r.svc);
    r.w.compose(r.dev, r.ctx, false, &mut r.svc);
    let log = &r.svc.log;
    for (i, e) in log.iter().enumerate() {
        if matches!(e, Ev::Compose(_)) {
            assert_eq!(log[i - 1], Ev::Clear(COMPOSED_BIT));
        }
    }
    assert!(!matches!(log.last(), Some(Ev::Clear(_))));
}

#[test]
fn s8_3_failed_compose_wait_leaves_the_compose_pending() {
    let mut r = rig();
    r.svc
        .wait_once
        .push(Status::Unknown(proto_comp::UNSUPPORTED));
    r.w.compose(r.dev, r.ctx, true, &mut r.svc);
    assert_eq!(r.err(), ERROR_UNSUPPORTED);
    assert!(r.w.ctx.unwrap().compose_pending);
    r.svc.log.clear();
    r.w.destroy_context(r.dev, r.ctx, &mut r.svc);
    assert_eq!(r.svc.log, vec![Ev::Wait(COMPOSED_BIT)]);
}

#[test]
fn s8_3_refused_compose_does_not_leave_a_wait_that_never_ends() {
    let mut r = rig();
    r.w.compose(r.dev, r.ctx, false, &mut r.svc);
    r.svc
        .compose_refusals
        .push(Status::Unknown(proto_comp::UNSUPPORTED));
    r.w.compose(r.dev, r.ctx, false, &mut r.svc);
    assert_eq!(r.err(), ERROR_UNSUPPORTED);
    assert!(!r.w.ctx.unwrap().compose_pending);
}

#[test]
fn s8_3_busy_without_wait_keeps_the_earlier_compose_pending() {
    let mut r = rig();
    r.w.compose(r.dev, r.ctx, false, &mut r.svc);
    r.svc.compose_refusals.push(BUSY);
    r.w.compose(r.dev, r.ctx, false, &mut r.svc);
    assert_eq!(r.err(), ERROR_BUSY);
    assert!(r.w.ctx.unwrap().compose_pending);
}

#[test]
fn s8_3_busy_that_never_ends_with_wait_is_bounded() {
    let mut r = rig();
    for _ in 0..100 {
        r.svc.compose_refusals.push(BUSY);
    }
    r.w.compose(r.dev, r.ctx, true, &mut r.svc);
    assert_eq!(r.err(), ERROR_BAD_DEVICE);
    assert!(!r.w.is_lost());
    let sends = r
        .svc
        .log
        .iter()
        .filter(|e| matches!(e, Ev::Compose(_)))
        .count();
    assert_eq!(sends, MAX_TRIES as usize);
}

#[test]
fn s5_4_commit_busy_that_never_ends_with_wait_is_bounded() {
    let mut r = rig();
    for _ in 0..100 {
        r.svc.commit_refusals.push(BUSY);
    }
    r.w.commit(r.dev, r.ctx, true, &mut r.svc);
    assert_eq!(r.err(), ERROR_BAD_DEVICE);
    assert_eq!(r.svc.commits().len(), MAX_TRIES as usize);
}

#[test]
fn s5_4_commit_busy_without_wait_is_the_result() {
    // The service answers BUSY on SCENE_COMMIT too (spec 5.4 allows it).
    let mut r = rig();
    r.svc.commit_refusals.push(BUSY);
    r.commit();
    assert_eq!(r.err(), ERROR_BUSY);
    assert_eq!(r.svc.commits().len(), 1);
}

#[test]
fn p5_4_interrupted_request_is_sent_again_and_the_device_stays() {
    let mut r = rig();
    r.svc
        .commit_refusals
        .push(Status::Kernel(Error::Interrupted));
    r.svc
        .commit_refusals
        .push(Status::Kernel(Error::WouldBlock));
    r.commit();
    assert_eq!(r.err(), 0);
    assert_eq!(r.svc.commits().len(), 3);
    assert!(!r.w.is_lost());
}

#[test]
fn p5_4_transient_that_never_ends_is_busy_not_lost() {
    let mut r = rig();
    for _ in 0..100 {
        r.svc
            .commit_refusals
            .push(Status::Kernel(Error::WouldBlock));
    }
    r.commit();
    assert_eq!(r.err(), ERROR_BUSY);
    assert!(!r.w.is_lost());
    assert_eq!(translate(Status::Kernel(Error::Interrupted)), ERROR_BUSY);
}

#[test]
fn p5_4_interrupted_wait_waits_again() {
    let mut r = rig();
    r.svc.wait_once.push(Status::Kernel(Error::Interrupted));
    r.w.commit(r.dev, r.ctx, true, &mut r.svc);
    assert_eq!(r.err(), 0);
    let waits = r
        .svc
        .log
        .iter()
        .filter(|e| matches!(e, Ev::Wait(_)))
        .count();
    assert_eq!(waits, 2);
    assert!(!r.w.is_lost());
}

#[test]
fn p5_4_interrupted_pause_is_not_a_loss() {
    let mut r = rig();
    r.svc.compose_refusals.push(BUSY);
    r.svc.pause_refusal = Some(Status::Kernel(Error::Interrupted));
    r.w.compose(r.dev, r.ctx, true, &mut r.svc);
    assert!(!r.w.is_lost());
}

#[test]
fn p5_4_handle_counter_stops_at_the_largest() {
    let c = AtomicU32::new(1);
    assert_eq!(next_from(&c), Some(1));
    assert_eq!(next_from(&c), Some(2));
    let c = AtomicU32::new(u32::MAX - 1);
    assert_eq!(next_from(&c), Some(u32::MAX - 1));
    assert_eq!(next_from(&c), None);
    assert_eq!(next_from(&c), None);
    // Never 0, so never WFC_INVALID_HANDLE.
    assert_eq!(c.load(Ordering::Relaxed), u32::MAX);
}

#[test]
fn p5_4_fold_survives_any_input() {
    for r in [0, 3, 4, u32::MAX] {
        for c in [0, 3, 4, u32::MAX] {
            let (o, _) = fold(r, true, c);
            assert!(o < 4);
            assert!(fold(r, false, c).0 < 4);
        }
    }
    for c in 0..4 {
        let _ = fold_rect(
            [i32::MIN, i32::MAX, i32::MAX, i32::MIN],
            c,
            i32::MIN,
            i32::MAX,
        );
    }
}

#[test]
fn p5_4_create_context_on_a_lost_device_does_not_take_the_screen() {
    let mut r = rig();
    r.svc
        .commit_refusals
        .push(Status::Kernel(Error::PeerClosed));
    r.commit();
    let _ = r.err();
    r.w.destroy_context(r.dev, r.ctx, &mut r.svc);
    assert!(!r.svc.claimed);
    assert_eq!(r.w.create_on_screen_context(r.dev, 0, &[], &mut r.svc), 0);
    assert_eq!(r.err(), ERROR_BAD_DEVICE);
    assert!(!r.svc.claimed);
}

#[test]
fn s6_1_1_unknown_format_is_taken_for_a_source_and_a_mask() {
    let mut r = rig();
    let s = StreamInfo {
        format: FORMAT_UNKNOWN,
        ..info(1, 4, 4)
    };
    assert!(r.w.create_source_from_stream(r.dev, r.ctx, Some(s), &[]) != 0);
    assert!(r.w.create_mask_from_stream(r.dev, r.ctx, Some(s), &[]) != 0);
    assert_eq!(r.err(), 0);
}
