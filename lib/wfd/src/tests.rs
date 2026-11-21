// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The rules of OpenWF Display 1.0 for the device of virtio-gpu, one test
//! for a clause of the specification; the number in a name is the section.

use super::*;
use proto_gpu::{PIPELINE_PRIMARY, SOURCE_CURSOR, SOURCE_POOL, SOURCE_TARGET};

struct Rig {
    wfd: Wfd,
    dev: u32,
    port: u32,
    primary: u32,
    cursor: u32,
}

fn rig() -> Rig {
    let mut wfd = Wfd::new(Setup::VIRTIO);
    let dev = wfd.device();
    let port = wfd.create_port(dev, PORT, &[]);
    let primary = wfd.create_pipeline(dev, 1, &[]);
    let cursor = wfd.create_pipeline(dev, 2, &[]);
    assert!(port != 0 && primary != 0 && cursor != 0);
    wfd.make_available(SOURCE_POOL);
    wfd.make_available(SOURCE_CURSOR);
    Rig {
        wfd,
        dev,
        port,
        primary,
        cursor,
    }
}

impl Rig {
    fn error(&mut self) -> i32 {
        self.wfd.get_error(self.dev)
    }

    fn source(&mut self, pipeline: u32, id: u32) -> u32 {
        let h = self
            .wfd
            .create_source_from_stream(self.dev, pipeline, id, &[]);
        assert!(h != 0, "error {:#x}", self.error());
        h
    }

    fn bind(&mut self, pipeline: u32, source: u32) {
        self.wfd
            .bind_source_to_pipeline(self.dev, pipeline, source, TRANSITION_AT_VSYNC, false);
        assert_eq!(self.error(), ERROR_NONE);
    }

    fn commit(&mut self) -> Option<Commit> {
        self.wfd.commit(self.dev, COMMIT_ENTIRE_DEVICE, 0)
    }

    fn show_cursor(&mut self) -> u32 {
        let src = self.source(self.cursor, SOURCE_CURSOR);
        self.wfd.set_pipeline_attrib_iv(
            self.dev,
            self.cursor,
            PIPELINE_SOURCE_RECTANGLE,
            4,
            Some(&[0, 0, 64, 64]),
        );
        self.wfd.set_pipeline_attrib_iv(
            self.dev,
            self.cursor,
            PIPELINE_DESTINATION_RECTANGLE,
            4,
            Some(&[10, 20, 64, 64]),
        );
        self.wfd.set_pipeline_attrib(
            self.dev,
            self.cursor,
            PIPELINE_TRANSPARENCY_ENABLE,
            TRANSPARENCY_SOURCE_ALPHA as i32,
        );
        self.bind(self.cursor, src);
        assert_eq!(self.error(), ERROR_NONE);
        src
    }
}

fn row_of(commit: &Commit, pipeline: u32) -> LayerRow {
    *commit
        .layers
        .as_ref()
        .expect("a request")
        .rows()
        .iter()
        .find(|r| r.pipeline == pipeline)
        .expect("a row of the pipeline")
}

// ------------------------------------------------------------ 2.11 and 3.1-3.3

#[test]
fn s2_11_an_invalid_device_has_no_effect_and_stores_no_error() {
    let mut r = rig();
    let bad = r.dev + 100;
    assert_eq!(r.wfd.create_port(bad, PORT, &[]), 0);
    r.wfd.set_device_attrib(bad, DEVICE_ID, 3);
    assert_eq!(r.wfd.get_device_attrib(bad, DEVICE_ID), 0);
    assert_eq!(r.error(), ERROR_NONE);
    assert_eq!(r.wfd.get_error(bad), ERROR_BAD_DEVICE);
}

#[test]
fn s2_11_the_oldest_error_is_kept_until_it_is_read_and_then_cleared() {
    let mut r = rig();
    r.wfd.get_device_attrib(r.dev, 0x1234);
    r.wfd.create_port(r.dev, 77, &[]);
    assert_eq!(r.error(), ERROR_BAD_ATTRIBUTE);
    assert_eq!(r.error(), ERROR_NONE);
}

#[test]
fn s3_1_enumeration_gives_the_one_device_and_filters_by_port() {
    let mut ids = [0];
    assert_eq!(Wfd::enumerate_devices(Some(&mut ids), &[]), 1);
    assert_eq!(ids, [DEVICE]);
    assert_eq!(Wfd::enumerate_devices(None, &[]), 1);
    assert_eq!(
        Wfd::enumerate_devices(None, &[DEVICE_FILTER_PORT_ID, PORT]),
        1
    );
    assert_eq!(
        Wfd::enumerate_devices(None, &[DEVICE_FILTER_PORT_ID, 0]),
        1,
        "the invalid port id filters nothing"
    );
    assert_eq!(Wfd::enumerate_devices(None, &[DEVICE_FILTER_PORT_ID, 9]), 0);
    assert_eq!(Wfd::enumerate_devices(None, &[0x7777, 1]), 0);
    assert_eq!(Wfd::enumerate_devices(Some(&mut []), &[]), 0);
}

#[test]
fn s3_2_the_default_device_and_the_device_id_are_valid() {
    assert!(Wfd::device_id_valid(0));
    assert!(Wfd::device_id_valid(DEVICE));
    assert!(!Wfd::device_id_valid(2));
    assert!(!Wfd::device_id_valid(-1));
}

#[test]
fn s3_5_the_device_has_one_read_only_attribute() {
    let mut r = rig();
    assert_eq!(r.wfd.get_device_attrib(r.dev, DEVICE_ID), DEVICE);
    assert_ne!(DEVICE, 0, "the id is not the default device id");
    r.wfd.set_device_attrib(r.dev, DEVICE_ID, 5);
    assert_eq!(r.error(), ERROR_BAD_ATTRIBUTE);
    r.wfd.get_device_attrib(r.dev, PORT_ID);
    assert_eq!(r.error(), ERROR_BAD_ATTRIBUTE);
}

#[test]
fn s6_3_the_strings_name_the_implementation() {
    let mut r = rig();
    assert_eq!(r.wfd.strings(r.dev, VENDOR, 1), Some(&[VENDOR_NAME][..]));
    assert_eq!(r.wfd.strings(r.dev, VERSION, 1), Some(&[VERSION_NAME][..]));
    assert_eq!(r.wfd.strings(r.dev, RENDERER, 1).map(|l| l.len()), Some(1));
    assert_eq!(
        r.wfd.strings(r.dev, EXTENSIONS, 0).map(|l| l.len()),
        Some(2)
    );
    assert_eq!(r.error(), ERROR_NONE);
    assert_eq!(r.wfd.strings(r.dev, 0x7504, 1), None);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    assert_eq!(r.wfd.strings(r.dev, VENDOR, -1), None);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    assert_eq!(r.wfd.strings(r.dev + 1, VENDOR, 1), None);
    assert_eq!(r.error(), ERROR_NONE);
}

#[test]
fn s6_3_the_extensions_are_found_by_name() {
    let r = rig();
    assert!(r.wfd.is_extension_supported(r.dev, b"WFD_STAFETO_stream"));
    assert!(r.wfd.is_extension_supported(r.dev, b"WFD_STAFETO_cursor"));
    assert!(!r.wfd.is_extension_supported(r.dev, b"WFD_STAFETO_other"));
    assert!(
        !r.wfd
            .is_extension_supported(r.dev + 1, b"WFD_STAFETO_stream")
    );
}

// ---------------------------------------------------------------------- ports

#[test]
fn s4_1_one_port_is_enumerated_and_a_filter_leaves_none() {
    let mut r = rig();
    let mut ids = [0; 3];
    assert_eq!(r.wfd.enumerate_ports(r.dev, Some(&mut ids), &[]), 1);
    assert_eq!(ids[0], PORT);
    assert_eq!(r.wfd.enumerate_ports(r.dev, None, &[]), 1);
    assert_eq!(r.wfd.enumerate_ports(r.dev, None, &[1, 2]), 0);
    assert_eq!(r.wfd.enumerate_ports(r.dev, Some(&mut []), &[]), 0);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
}

#[test]
fn s4_2_a_port_is_made_once_and_remade_after_it_is_destroyed() {
    let mut wfd = Wfd::new(Setup::VIRTIO);
    let dev = wfd.device();
    assert_eq!(wfd.create_port(dev, 9, &[]), 0);
    assert_eq!(wfd.get_error(dev), ERROR_ILLEGAL_ARGUMENT);
    assert_eq!(wfd.create_port(dev, PORT, &[WFD_NONE_ATTRIB, 1]), 0);
    assert_eq!(wfd.get_error(dev), ERROR_BAD_ATTRIBUTE);
    let port = wfd.create_port(dev, PORT, &[]);
    assert_ne!(port, 0);
    assert_eq!(wfd.create_port(dev, PORT, &[]), 0);
    assert_eq!(wfd.get_error(dev), ERROR_IN_USE);
    wfd.destroy_port(dev, port);
    assert_eq!(wfd.get_error(dev), ERROR_NONE);
    let again = wfd.create_port(dev, PORT, &[]);
    assert!(again != 0 && again != port, "the handle is a new one");
    wfd.destroy_port(dev, port);
    assert_eq!(wfd.get_error(dev), ERROR_BAD_HANDLE);
}

/// An attribute no port or pipeline attribute list has.
const WFD_NONE_ATTRIB: i32 = 0x1111;

#[test]
fn s4_4_the_port_has_one_mode_with_the_size_and_the_rate() {
    let mut r = rig();
    let mut modes = [0u32; 2];
    assert_eq!(r.wfd.get_port_modes(r.dev, r.port, None), 1);
    assert_eq!(r.wfd.get_port_modes(r.dev, r.port, Some(&mut modes)), 1);
    let mode = modes[0];
    let at = |r: &mut Rig, a| r.wfd.get_port_mode_attrib(r.dev, r.port, mode, a);
    assert_eq!(at(&mut r, PORT_MODE_WIDTH), 640);
    assert_eq!(at(&mut r, PORT_MODE_HEIGHT), 400);
    assert_eq!(at(&mut r, PORT_MODE_REFRESH_RATE), 60);
    assert_eq!(
        r.wfd
            .get_port_mode_attrib_f(r.dev, r.port, mode, PORT_MODE_REFRESH_RATE),
        60.0
    );
    assert_eq!(at(&mut r, PORT_MODE_FLIP_MIRROR_SUPPORT), 0);
    assert_eq!(
        at(&mut r, PORT_MODE_ROTATION_SUPPORT),
        ROTATION_SUPPORT_NONE
    );
    assert_eq!(at(&mut r, PORT_MODE_INTERLACED), 0);
    assert_eq!(r.error(), ERROR_NONE);
    at(&mut r, PORT_ID);
    assert_eq!(r.error(), ERROR_BAD_ATTRIBUTE);
    r.wfd
        .get_port_mode_attrib_f(r.dev, r.port, mode, PORT_MODE_WIDTH);
    assert_eq!(r.error(), ERROR_BAD_ATTRIBUTE);
    r.wfd
        .get_port_mode_attrib(r.dev, r.port, mode + 50, PORT_MODE_WIDTH);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    r.wfd
        .get_port_mode_attrib(r.dev, r.port + 50, mode, PORT_MODE_WIDTH);
    assert_eq!(r.error(), ERROR_BAD_HANDLE);
    assert_eq!(r.wfd.get_port_modes(r.dev, r.port, Some(&mut [])), 0);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
}

#[test]
fn s4_4_and_7_the_mode_is_set_before_the_port_is_made() {
    let mut r = rig();
    let mut modes = [0u32; 1];
    r.wfd.get_port_modes(r.dev, r.port, Some(&mut modes));
    assert_eq!(r.wfd.get_current_port_mode(r.dev, r.port), modes[0]);
    r.wfd.set_port_mode(r.dev, r.port, modes[0]);
    assert_eq!(r.error(), ERROR_NONE);
    r.wfd.set_port_mode(r.dev, r.port, modes[0] + 9);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    assert_eq!(r.wfd.get_current_port_mode(r.dev, r.port + 9), 0);
    assert_eq!(r.error(), ERROR_BAD_HANDLE);
}

#[test]
fn s4_5_the_read_only_attributes_of_the_port() {
    let mut r = rig();
    let g = |r: &mut Rig, a| r.wfd.get_port_attrib(r.dev, r.port, a);
    assert_eq!(g(&mut r, PORT_ID), PORT);
    assert_eq!(g(&mut r, PORT_TYPE), PORT_TYPE_INTERNAL);
    assert_eq!(g(&mut r, PORT_DETACHABLE), 0);
    assert_eq!(g(&mut r, PORT_ATTACHED), 1);
    assert_eq!(g(&mut r, PORT_FILL_PORT_AREA), 1);
    assert_eq!(
        g(&mut r, PORT_PARTIAL_REFRESH_SUPPORT),
        PARTIAL_REFRESH_NONE
    );
    assert_eq!(g(&mut r, PORT_PIPELINE_ID_COUNT), 2);
    assert_eq!(r.error(), ERROR_NONE);
    let mut size = [0; 2];
    r.wfd
        .get_port_attrib_iv(r.dev, r.port, PORT_NATIVE_RESOLUTION, 2, Some(&mut size));
    assert_eq!(size, [640, 400]);
    let mut mm = [9.0; 2];
    r.wfd
        .get_port_attrib_fv(r.dev, r.port, PORT_PHYSICAL_SIZE, 2, Some(&mut mm));
    assert_eq!(mm, [0.0, 0.0]);
    let mut gamma = [0.0; 2];
    r.wfd
        .get_port_attrib_fv(r.dev, r.port, PORT_GAMMA_RANGE, 2, Some(&mut gamma));
    assert_eq!(gamma, [1.0, 1.0]);
    assert_eq!(r.wfd.get_port_attrib_f(r.dev, r.port, PORT_GAMMA), 1.0);
    assert_eq!(r.error(), ERROR_NONE);
}

#[test]
fn s4_5_a_port_attribute_refuses_an_accessor_it_does_not_allow() {
    let mut r = rig();
    let mut one = [0];
    // A vector attribute with the integer accessor, a scalar with the vector.
    r.wfd.get_port_attrib(r.dev, r.port, PORT_NATIVE_RESOLUTION);
    assert_eq!(r.error(), ERROR_BAD_ATTRIBUTE);
    r.wfd
        .get_port_attrib_iv(r.dev, r.port, PORT_ID, 1, Some(&mut one));
    assert_eq!(r.error(), ERROR_BAD_ATTRIBUTE);
    r.wfd.get_port_attrib(r.dev, r.port, PORT_GAMMA);
    assert_eq!(r.error(), ERROR_BAD_ATTRIBUTE);
    r.wfd.get_port_attrib_f(r.dev, r.port, PORT_ID);
    assert_eq!(r.error(), ERROR_BAD_ATTRIBUTE);
    // Read-only attributes cannot be set.
    r.wfd.set_port_attrib(r.dev, r.port, PORT_ID, 3);
    assert_eq!(r.error(), ERROR_BAD_ATTRIBUTE);
    r.wfd
        .set_port_attrib_iv(r.dev, r.port, PORT_NATIVE_RESOLUTION, 2, Some(&[1, 1]));
    assert_eq!(r.error(), ERROR_BAD_ATTRIBUTE);
    r.wfd
        .set_port_attrib_fv(r.dev, r.port, PORT_GAMMA_RANGE, 2, Some(&[1.0, 1.0]));
    assert_eq!(r.error(), ERROR_BAD_ATTRIBUTE);
    r.wfd.set_port_attrib_f(r.dev, r.port, PORT_ID, 1.0);
    assert_eq!(r.error(), ERROR_BAD_ATTRIBUTE);
}

#[test]
fn s4_5_a_vector_call_needs_an_array_and_the_right_count() {
    let mut r = rig();
    let mut two = [0; 2];
    r.wfd
        .get_port_attrib_iv(r.dev, r.port, PORT_NATIVE_RESOLUTION, 3, Some(&mut two));
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    r.wfd
        .get_port_attrib_iv(r.dev, r.port, PORT_NATIVE_RESOLUTION, 2, None);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    let mut ids = [0; 2];
    r.wfd
        .get_port_attrib_iv(r.dev, r.port, PORT_BINDABLE_PIPELINE_IDS, 2, Some(&mut ids));
    assert_eq!(ids, [1, 2]);
    r.wfd
        .get_port_attrib_iv(r.dev, r.port, PORT_BINDABLE_PIPELINE_IDS, 1, Some(&mut ids));
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
}

#[test]
fn s4_5_1_7_the_background_colour_reads_back_as_written() {
    let mut r = rig();
    assert_eq!(
        r.wfd.get_port_attrib(r.dev, r.port, PORT_BACKGROUND_COLOR),
        0xFF
    );
    r.wfd
        .set_port_attrib(r.dev, r.port, PORT_BACKGROUND_COLOR, 0x2040_80FFu32 as i32);
    assert_eq!(r.error(), ERROR_NONE);
    assert_eq!(
        r.wfd.get_port_attrib(r.dev, r.port, PORT_BACKGROUND_COLOR) as u32,
        0x2040_80FF
    );
    let mut rgb = [0; 3];
    r.wfd
        .get_port_attrib_iv(r.dev, r.port, PORT_BACKGROUND_COLOR, 3, Some(&mut rgb));
    assert_eq!(rgb, [0x20, 0x40, 0x80]);
    r.wfd.set_port_attrib_fv(
        r.dev,
        r.port,
        PORT_BACKGROUND_COLOR,
        3,
        Some(&[1.0, 0.0, 0.5]),
    );
    let mut f = [0.0; 3];
    r.wfd
        .get_port_attrib_fv(r.dev, r.port, PORT_BACKGROUND_COLOR, 3, Some(&mut f));
    assert_eq!(f, [1.0, 0.0, 0.5]);
    // The low byte is 255 when written; the floats are in [0, 1].
    r.wfd
        .set_port_attrib(r.dev, r.port, PORT_BACKGROUND_COLOR, 0x1122_3300);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    r.wfd.set_port_attrib_fv(
        r.dev,
        r.port,
        PORT_BACKGROUND_COLOR,
        3,
        Some(&[1.5, 0.0, 0.0]),
    );
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    r.wfd
        .set_port_attrib_iv(r.dev, r.port, PORT_BACKGROUND_COLOR, 3, Some(&[256, 0, 0]));
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
}

#[test]
fn s4_5_1_11_the_power_mode_is_on_and_stays() {
    let mut r = rig();
    assert_eq!(
        r.wfd.get_port_attrib(r.dev, r.port, PORT_POWER_MODE),
        POWER_MODE_ON
    );
    r.wfd
        .set_port_attrib(r.dev, r.port, PORT_POWER_MODE, POWER_MODE_ON);
    assert_eq!(r.error(), ERROR_NONE);
    for mode in [
        POWER_MODE_OFF,
        POWER_MODE_SUSPEND,
        POWER_MODE_LIMITED_USE,
        5,
    ] {
        r.wfd.set_port_attrib(r.dev, r.port, PORT_POWER_MODE, mode);
        assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT, "{mode:#x}");
    }
    assert_eq!(
        r.wfd.get_port_attrib(r.dev, r.port, PORT_POWER_MODE),
        POWER_MODE_ON
    );
}

#[test]
fn s4_5_1_what_the_port_cannot_do_is_out_of_range() {
    let mut r = rig();
    for attrib in [
        PORT_FLIP,
        PORT_MIRROR,
        PORT_ROTATION,
        PORT_PROTECTION_ENABLE,
    ] {
        r.wfd.set_port_attrib(r.dev, r.port, attrib, 0);
        assert_eq!(r.error(), ERROR_NONE);
        r.wfd.set_port_attrib(r.dev, r.port, attrib, 1);
        assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT, "{attrib:#x}");
        r.wfd.set_port_attrib(r.dev, r.port, attrib, 90);
        assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT, "{attrib:#x}");
    }
    r.wfd.set_port_attrib(
        r.dev,
        r.port,
        PORT_PARTIAL_REFRESH_ENABLE,
        PARTIAL_REFRESH_BOTH,
    );
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    r.wfd.set_port_attrib(
        r.dev,
        r.port,
        PORT_PARTIAL_REFRESH_ENABLE,
        PARTIAL_REFRESH_NONE,
    );
    assert_eq!(r.error(), ERROR_NONE);
    r.wfd.set_port_attrib_f(r.dev, r.port, PORT_GAMMA, 2.2);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    r.wfd.set_port_attrib_f(r.dev, r.port, PORT_GAMMA, 1.0);
    assert_eq!(r.error(), ERROR_NONE);
    r.wfd.set_port_attrib_iv(
        r.dev,
        r.port,
        PORT_PARTIAL_REFRESH_RECTANGLE,
        4,
        Some(&[0, 0, 10, 10]),
    );
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
}

#[test]
fn s4_6_binding_a_pipeline_to_the_port_checks_the_handles() {
    let mut r = rig();
    r.wfd.bind_pipeline_to_port(r.dev, r.port, r.primary);
    assert_eq!(r.error(), ERROR_NONE);
    r.wfd.bind_pipeline_to_port(r.dev, r.port, r.primary + 99);
    assert_eq!(r.error(), ERROR_BAD_HANDLE);
    r.wfd.bind_pipeline_to_port(r.dev, r.port + 99, r.primary);
    assert_eq!(r.error(), ERROR_BAD_HANDLE);
}

#[test]
fn s4_7_the_display_has_no_data() {
    let mut r = rig();
    assert_eq!(r.wfd.get_display_data_formats(r.dev, r.port, None), 0);
    assert_eq!(
        r.wfd
            .get_display_data_formats(r.dev, r.port, Some(&mut [0; 2])),
        0
    );
    assert_eq!(r.error(), ERROR_NONE);
    r.wfd.get_display_data_formats(r.dev, r.port, Some(&mut []));
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    assert_eq!(
        r.wfd
            .get_display_data(r.dev, r.port, DISPLAY_DATA_FORMAT_NONE),
        0
    );
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
}

// ------------------------------------------------------------------ pipelines

#[test]
fn s5_2_the_pipelines_are_those_of_the_service_in_its_order() {
    let mut r = rig();
    let mut ids = [0; 4];
    assert_eq!(r.wfd.enumerate_pipelines(r.dev, Some(&mut ids), &[]), 2);
    assert_eq!(&ids[..2], &[1, 2]);
    assert_eq!(r.wfd.enumerate_pipelines(r.dev, None, &[]), 2);
    assert_eq!(
        r.wfd.enumerate_pipelines(r.dev, Some(&mut ids[..1]), &[]),
        1
    );
    assert_eq!(r.wfd.enumerate_pipelines(r.dev, None, &[1, 1]), 0);
    assert_eq!(r.wfd.enumerate_pipelines(r.dev, Some(&mut []), &[]), 0);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
}

#[test]
fn s5_3_a_pipeline_is_made_once_and_then_it_is_in_use() {
    let mut wfd = Wfd::new(Setup::VIRTIO);
    let dev = wfd.device();
    assert_eq!(wfd.create_pipeline(dev, 7, &[]), 0);
    assert_eq!(wfd.get_error(dev), ERROR_ILLEGAL_ARGUMENT);
    assert_eq!(wfd.create_pipeline(dev, 1, &[1, 1]), 0);
    assert_eq!(wfd.get_error(dev), ERROR_BAD_ATTRIBUTE);
    let p = wfd.create_pipeline(dev, 1, &[]);
    assert_ne!(p, 0);
    assert_eq!(wfd.create_pipeline(dev, 1, &[]), 0);
    assert_eq!(wfd.get_error(dev), ERROR_IN_USE);
    wfd.destroy_pipeline(dev, p);
    assert_eq!(wfd.get_error(dev), ERROR_NONE);
    wfd.destroy_pipeline(dev, p);
    assert_eq!(wfd.get_error(dev), ERROR_BAD_HANDLE);
    assert_ne!(wfd.create_pipeline(dev, 1, &[]), 0);
}

#[test]
fn s5_7_1_the_pipelines_report_their_place_and_limits() {
    let mut r = rig();
    let (p, c) = (r.primary, r.cursor);
    let g = |r: &mut Rig, p, a| r.wfd.get_pipeline_attrib(r.dev, p, a);
    assert_eq!(g(&mut r, p, PIPELINE_ID), 1);
    assert_eq!(g(&mut r, c, PIPELINE_ID), 2);
    assert_eq!(g(&mut r, p, PIPELINE_PORTID), PORT);
    assert_eq!(g(&mut r, p, PIPELINE_LAYER), 1);
    assert_eq!(g(&mut r, c, PIPELINE_LAYER), 2);
    assert_eq!(g(&mut r, p, PIPELINE_SHAREABLE), 0);
    assert_eq!(g(&mut r, p, PIPELINE_DIRECT_REFRESH), 0);
    assert_eq!(
        g(&mut r, p, PIPELINE_ROTATION_SUPPORT),
        ROTATION_SUPPORT_NONE
    );
    assert_eq!(r.error(), ERROR_NONE);
    let mut size = [0; 2];
    r.wfd
        .get_pipeline_attrib_iv(r.dev, p, PIPELINE_MAX_SOURCE_SIZE, 2, Some(&mut size));
    assert_eq!(size, [640, 400]);
    r.wfd
        .get_pipeline_attrib_iv(r.dev, c, PIPELINE_MAX_SOURCE_SIZE, 2, Some(&mut size));
    assert_eq!(size, [64, 64]);
    let mut range = [0.0; 2];
    r.wfd
        .get_pipeline_attrib_fv(r.dev, p, PIPELINE_SCALE_RANGE, 2, Some(&mut range));
    assert_eq!(range, [1.0, 1.0], "no scaling");
    assert_eq!(r.wfd.get_pipeline_layer_order(r.dev, r.port, c), 2);
    assert_eq!(r.wfd.get_pipeline_layer_order(r.dev, r.port + 9, c), 0);
    assert_eq!(r.error(), ERROR_BAD_HANDLE);
    assert_eq!(r.error(), ERROR_NONE);
}

#[test]
fn s5_7_1_the_defaults_of_a_pipeline_that_is_off_and_of_the_pre_configured_one() {
    let mut r = rig();
    let (p, c) = (r.primary, r.cursor);
    let mut rect = [9; 4];
    r.wfd
        .get_pipeline_attrib_iv(r.dev, c, PIPELINE_SOURCE_RECTANGLE, 4, Some(&mut rect));
    assert_eq!(rect, [0, 0, 0, 0]);
    r.wfd
        .get_pipeline_attrib_iv(r.dev, c, PIPELINE_DESTINATION_RECTANGLE, 4, Some(&mut rect));
    assert_eq!(rect, [0, 0, 0, 0]);
    // The primary pipeline shows the target, as section 7 allows.
    r.wfd
        .get_pipeline_attrib_iv(r.dev, p, PIPELINE_DESTINATION_RECTANGLE, 4, Some(&mut rect));
    assert_eq!(rect, [0, 0, 640, 400]);
    for pipe in [p, c] {
        let g = |r: &mut Rig, a| r.wfd.get_pipeline_attrib(r.dev, pipe, a);
        assert_eq!(g(&mut r, PIPELINE_FLIP), 0);
        assert_eq!(g(&mut r, PIPELINE_MIRROR), 0);
        assert_eq!(g(&mut r, PIPELINE_ROTATION), 0);
        assert_eq!(g(&mut r, PIPELINE_SCALE_FILTER), SCALE_FILTER_NONE);
        assert_eq!(g(&mut r, PIPELINE_TRANSPARENCY_ENABLE), 0);
        assert_eq!(g(&mut r, PIPELINE_GLOBAL_ALPHA), 255);
        assert_eq!(
            r.wfd
                .get_pipeline_attrib_f(r.dev, pipe, PIPELINE_GLOBAL_ALPHA),
            1.0
        );
    }
    assert_eq!(r.error(), ERROR_NONE);
}

#[test]
fn s5_7_1_6_a_rectangle_reads_back_as_written_and_floors_as_an_integer() {
    let mut r = rig();
    let c = r.cursor;
    r.wfd.set_pipeline_attrib_fv(
        r.dev,
        c,
        PIPELINE_DESTINATION_RECTANGLE,
        4,
        Some(&[1.5, 2.25, 64.0, 64.0]),
    );
    assert_eq!(r.error(), ERROR_NONE);
    let mut f = [0.0; 4];
    r.wfd
        .get_pipeline_attrib_fv(r.dev, c, PIPELINE_DESTINATION_RECTANGLE, 4, Some(&mut f));
    assert_eq!(f, [1.5, 2.25, 64.0, 64.0]);
    let mut i = [0; 4];
    r.wfd
        .get_pipeline_attrib_iv(r.dev, c, PIPELINE_DESTINATION_RECTANGLE, 4, Some(&mut i));
    assert_eq!(i, [1, 2, 64, 64]);
    r.wfd.set_pipeline_attrib_fv(
        r.dev,
        c,
        PIPELINE_SOURCE_RECTANGLE,
        4,
        Some(&[-1.5, 0.0, 1.0, 1.0]),
    );
    r.wfd
        .get_pipeline_attrib_iv(r.dev, c, PIPELINE_SOURCE_RECTANGLE, 4, Some(&mut i));
    assert_eq!(i, [-2, 0, 1, 1], "the floor of a negative value");
}

#[test]
fn s5_7_3_a_rectangle_call_checks_count_range_and_array() {
    let mut r = rig();
    let c = r.cursor;
    r.wfd
        .set_pipeline_attrib_iv(r.dev, c, PIPELINE_SOURCE_RECTANGLE, 3, Some(&[0, 0, 1]));
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    r.wfd
        .set_pipeline_attrib_iv(r.dev, c, PIPELINE_SOURCE_RECTANGLE, 4, None);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    r.wfd.set_pipeline_attrib_iv(
        r.dev,
        c,
        PIPELINE_SOURCE_RECTANGLE,
        4,
        Some(&[0, 0, 1 << 25, 1]),
    );
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    r.wfd.set_pipeline_attrib_fv(
        r.dev,
        c,
        PIPELINE_SOURCE_RECTANGLE,
        4,
        Some(&[0.0, 0.0, f32::NAN, 1.0]),
    );
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    r.wfd
        .set_pipeline_attrib_iv(r.dev, c, PIPELINE_MAX_SOURCE_SIZE, 2, Some(&[1, 1]));
    assert_eq!(r.error(), ERROR_BAD_ATTRIBUTE);
    r.wfd
        .set_pipeline_attrib(r.dev, c, PIPELINE_SOURCE_RECTANGLE, 1);
    assert_eq!(r.error(), ERROR_BAD_ATTRIBUTE);
}

#[test]
fn s5_7_1_what_the_pipeline_cannot_do_is_out_of_range() {
    let mut r = rig();
    let p = r.primary;
    for attrib in [PIPELINE_FLIP, PIPELINE_MIRROR, PIPELINE_ROTATION] {
        r.wfd.set_pipeline_attrib(r.dev, p, attrib, 0);
        assert_eq!(r.error(), ERROR_NONE);
        r.wfd.set_pipeline_attrib(r.dev, p, attrib, 1);
        assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT, "{attrib:#x}");
    }
    for read_only in [
        PIPELINE_ID,
        PIPELINE_PORTID,
        PIPELINE_LAYER,
        PIPELINE_ROTATION_SUPPORT,
    ] {
        r.wfd.set_pipeline_attrib(r.dev, p, read_only, 1);
        assert_eq!(r.error(), ERROR_BAD_ATTRIBUTE, "{read_only:#x}");
    }
}

#[test]
fn s5_7_1_10_the_filter_takes_the_three_values() {
    let mut r = rig();
    let p = r.primary;
    for f in [SCALE_FILTER_NONE, SCALE_FILTER_FASTER, SCALE_FILTER_BETTER] {
        r.wfd
            .set_pipeline_attrib(r.dev, p, PIPELINE_SCALE_FILTER, f);
        assert_eq!(r.error(), ERROR_NONE);
        assert_eq!(
            r.wfd.get_pipeline_attrib(r.dev, p, PIPELINE_SCALE_FILTER),
            f
        );
    }
    r.wfd
        .set_pipeline_attrib(r.dev, p, PIPELINE_SCALE_FILTER, 0x7763);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
}

#[test]
fn s5_7_1_13_the_global_alpha_is_a_float_and_a_byte() {
    let mut r = rig();
    let p = r.primary;
    r.wfd
        .set_pipeline_attrib(r.dev, p, PIPELINE_GLOBAL_ALPHA, 128);
    assert_eq!(
        r.wfd.get_pipeline_attrib(r.dev, p, PIPELINE_GLOBAL_ALPHA),
        128
    );
    let f = r.wfd.get_pipeline_attrib_f(r.dev, p, PIPELINE_GLOBAL_ALPHA);
    assert!((f - 128.0 / 255.0).abs() < 1e-6);
    r.wfd
        .set_pipeline_attrib_f(r.dev, p, PIPELINE_GLOBAL_ALPHA, 0.25);
    assert_eq!(
        r.wfd.get_pipeline_attrib_f(r.dev, p, PIPELINE_GLOBAL_ALPHA),
        0.25
    );
    assert_eq!(
        r.wfd.get_pipeline_attrib(r.dev, p, PIPELINE_GLOBAL_ALPHA),
        64
    );
    assert_eq!(r.error(), ERROR_NONE);
    r.wfd
        .set_pipeline_attrib(r.dev, p, PIPELINE_GLOBAL_ALPHA, 256);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    r.wfd
        .set_pipeline_attrib(r.dev, p, PIPELINE_GLOBAL_ALPHA, -1);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    r.wfd
        .set_pipeline_attrib_f(r.dev, p, PIPELINE_GLOBAL_ALPHA, 1.5);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    r.wfd
        .set_pipeline_attrib_f(r.dev, p, PIPELINE_SCALE_FILTER, 1.0);
    assert_eq!(r.error(), ERROR_BAD_ATTRIBUTE);
}

#[test]
fn s5_8_the_transparency_lists_and_what_enabling_accepts() {
    let mut r = rig();
    let (p, c) = (r.primary, r.cursor);
    assert_eq!(r.wfd.get_pipeline_transparency(r.dev, p, None), 0);
    assert_eq!(r.wfd.get_pipeline_transparency(r.dev, c, None), 1);
    let mut list = [0u32; 3];
    assert_eq!(
        r.wfd.get_pipeline_transparency(r.dev, c, Some(&mut list)),
        1
    );
    assert_eq!(list[0], TRANSPARENCY_SOURCE_ALPHA);
    assert_eq!(r.wfd.get_pipeline_transparency(r.dev, c, Some(&mut [])), 0);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    // None is always allowed; a feature the list has; nothing else.
    for pipe in [p, c] {
        r.wfd
            .set_pipeline_attrib(r.dev, pipe, PIPELINE_TRANSPARENCY_ENABLE, 0);
        assert_eq!(r.error(), ERROR_NONE);
    }
    r.wfd.set_pipeline_attrib(
        r.dev,
        c,
        PIPELINE_TRANSPARENCY_ENABLE,
        TRANSPARENCY_SOURCE_ALPHA as i32,
    );
    assert_eq!(r.error(), ERROR_NONE);
    r.wfd.set_pipeline_attrib(
        r.dev,
        p,
        PIPELINE_TRANSPARENCY_ENABLE,
        TRANSPARENCY_SOURCE_ALPHA as i32,
    );
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    for bad in [
        TRANSPARENCY_GLOBAL_ALPHA,
        TRANSPARENCY_MASK,
        TRANSPARENCY_SOURCE_COLOR,
        6,
    ] {
        r.wfd
            .set_pipeline_attrib(r.dev, c, PIPELINE_TRANSPARENCY_ENABLE, bad as i32);
        assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT, "{bad}");
    }
}

#[test]
fn s5_8_3_the_source_colour_is_not_supported() {
    let mut r = rig();
    let p = r.primary;
    r.wfd
        .set_pipeline_ts_color(r.dev, p, TSC_FORMAT_UINT8_RGB_8_8_8_LINEAR, 3, false);
    assert_eq!(r.error(), ERROR_NOT_SUPPORTED);
    r.wfd.set_pipeline_ts_color(r.dev, p, 0x7792, 3, false);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    r.wfd
        .set_pipeline_ts_color(r.dev, p, TSC_FORMAT_UINT8_RGB_5_6_5_LINEAR, 2, false);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    r.wfd
        .set_pipeline_ts_color(r.dev, p, TSC_FORMAT_UINT8_RGB_5_6_5_LINEAR, 3, true);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    r.wfd
        .set_pipeline_ts_color(r.dev, p + 40, TSC_FORMAT_UINT8_RGB_5_6_5_LINEAR, 3, false);
    assert_eq!(r.error(), ERROR_BAD_HANDLE);
}

#[test]
fn s5_7_a_pipeline_call_with_a_bad_handle_is_bad_handle() {
    let mut r = rig();
    let bad = r.primary + 77;
    r.wfd.get_pipeline_attrib(r.dev, bad, PIPELINE_ID);
    assert_eq!(r.error(), ERROR_BAD_HANDLE);
    r.wfd.set_pipeline_attrib(r.dev, bad, PIPELINE_FLIP, 0);
    assert_eq!(r.error(), ERROR_BAD_HANDLE);
    r.wfd
        .get_pipeline_attrib_f(r.dev, bad, PIPELINE_GLOBAL_ALPHA);
    assert_eq!(r.error(), ERROR_BAD_HANDLE);
    assert_eq!(r.wfd.get_pipeline_transparency(r.dev, bad, None), 0);
    assert_eq!(r.error(), ERROR_BAD_HANDLE);
    r.wfd.get_pipeline_attrib(r.dev, r.primary, 0x7000);
    assert_eq!(r.error(), ERROR_BAD_ATTRIBUTE);
}

// ------------------------------------------------------------------- sources

#[test]
fn s5_5_1_a_source_is_made_from_a_stream_that_suits_the_pipeline() {
    let mut r = rig();
    let (p, c) = (r.primary, r.cursor);
    assert_ne!(r.source(p, SOURCE_TARGET), 0);
    assert_ne!(r.source(p, SOURCE_POOL), 0);
    assert_ne!(r.source(c, SOURCE_CURSOR), 0);
    // A picture of the wrong size or format is valid but not suitable.
    assert_eq!(
        r.wfd.create_source_from_stream(r.dev, c, SOURCE_POOL, &[]),
        0
    );
    assert_eq!(r.error(), ERROR_NOT_SUPPORTED);
    assert_eq!(
        r.wfd
            .create_source_from_stream(r.dev, p, SOURCE_CURSOR, &[]),
        0
    );
    assert_eq!(r.error(), ERROR_NOT_SUPPORTED);
    // A stream that is none.
    assert_eq!(r.wfd.create_source_from_stream(r.dev, p, 9, &[]), 0);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    assert_eq!(r.wfd.create_source_from_stream(r.dev, p, 0, &[]), 0);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    assert_eq!(
        r.wfd
            .create_source_from_stream(r.dev, p + 40, SOURCE_POOL, &[]),
        0
    );
    assert_eq!(r.error(), ERROR_BAD_HANDLE);
    assert_eq!(
        r.wfd
            .create_source_from_stream(r.dev, p, SOURCE_POOL, &[3, 1]),
        0
    );
    assert_eq!(r.error(), ERROR_BAD_ATTRIBUTE);
}

#[test]
fn s5_5_1_a_stream_the_layer_below_has_not_made_is_not_a_stream() {
    let mut wfd = Wfd::new(Setup::VIRTIO);
    let dev = wfd.device();
    let p = wfd.create_pipeline(dev, 1, &[]);
    assert_eq!(wfd.create_source_from_stream(dev, p, SOURCE_POOL, &[]), 0);
    assert_eq!(wfd.get_error(dev), ERROR_ILLEGAL_ARGUMENT);
    wfd.make_available(SOURCE_POOL);
    assert_ne!(wfd.create_source_from_stream(dev, p, SOURCE_POOL, &[]), 0);
}

#[test]
fn s5_5_1_each_source_of_one_stream_has_a_handle_of_its_own() {
    let mut r = rig();
    let a = r.source(r.primary, SOURCE_POOL);
    let b = r.source(r.primary, SOURCE_POOL);
    assert_ne!(a, b);
    r.wfd.destroy_source(r.dev, a);
    assert_eq!(r.error(), ERROR_NONE);
    r.wfd.destroy_source(r.dev, a);
    assert_eq!(r.error(), ERROR_BAD_HANDLE);
}

#[test]
fn s5_5_1_there_is_room_for_eight_sources() {
    let mut r = rig();
    for _ in 0..MAX_SOURCES {
        r.source(r.primary, SOURCE_POOL);
    }
    assert_eq!(
        r.wfd
            .create_source_from_stream(r.dev, r.primary, SOURCE_POOL, &[]),
        0
    );
    assert_eq!(r.error(), ERROR_OUT_OF_MEMORY);
}

#[test]
fn s5_4_destroying_a_pipeline_invalidates_its_sources() {
    let mut r = rig();
    let s = r.source(r.primary, SOURCE_POOL);
    let keep = r.source(r.cursor, SOURCE_CURSOR);
    r.wfd.destroy_pipeline(r.dev, r.primary);
    r.wfd.destroy_source(r.dev, s);
    assert_eq!(r.error(), ERROR_BAD_HANDLE);
    r.wfd.destroy_source(r.dev, keep);
    assert_eq!(r.error(), ERROR_NONE);
}

#[test]
fn s5_5_2_the_pipelines_have_no_masks() {
    let mut r = rig();
    assert_eq!(r.wfd.create_mask_from_stream(r.dev, r.primary, &[]), 0);
    assert_eq!(r.error(), ERROR_NOT_SUPPORTED);
    assert_eq!(r.wfd.create_mask_from_stream(r.dev, r.primary + 70, &[]), 0);
    assert_eq!(r.error(), ERROR_BAD_HANDLE);
    r.wfd.destroy_mask(r.dev, 5);
    assert_eq!(r.error(), ERROR_BAD_HANDLE);
    r.wfd
        .bind_mask_to_pipeline(r.dev, r.primary, 0, TRANSITION_IMMEDIATE);
    assert_eq!(r.error(), ERROR_NONE);
    r.wfd
        .bind_mask_to_pipeline(r.dev, r.primary, 5, TRANSITION_IMMEDIATE);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
}

#[test]
fn s5_6_2_a_bind_call_checks_the_transition_the_source_and_the_region() {
    let mut r = rig();
    let (p, c) = (r.primary, r.cursor);
    let s = r.source(p, SOURCE_POOL);
    let cs = r.source(c, SOURCE_CURSOR);
    r.wfd.bind_source_to_pipeline(r.dev, p, s, 0x77E0, false);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT, "INVALID transition");
    r.wfd
        .bind_source_to_pipeline(r.dev, p, s + 90, TRANSITION_IMMEDIATE, false);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT, "not a source");
    r.wfd
        .bind_source_to_pipeline(r.dev, p, cs, TRANSITION_IMMEDIATE, false);
    assert_eq!(
        r.error(),
        ERROR_ILLEGAL_ARGUMENT,
        "made for another pipeline"
    );
    r.wfd
        .bind_source_to_pipeline(r.dev, p, s, TRANSITION_IMMEDIATE, true);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT, "a region of a stream");
    r.wfd
        .bind_source_to_pipeline(r.dev, p + 40, s, TRANSITION_IMMEDIATE, false);
    assert_eq!(r.error(), ERROR_BAD_HANDLE);
    r.wfd
        .bind_source_to_pipeline(r.dev, p, s, TRANSITION_IMMEDIATE, false);
    r.wfd
        .bind_source_to_pipeline(r.dev, p, 0, TRANSITION_AT_VSYNC, false);
    assert_eq!(
        r.error(),
        ERROR_NONE,
        "the empty source releases the binding"
    );
}

// ------------------------------------------------------------------- commits

#[test]
fn s3_4_a_commit_with_nothing_changed_asks_the_display_for_nothing() {
    let mut r = rig();
    let c = r.commit().expect("a commit");
    assert!(c.layers.is_none() && !c.frame);
    assert_eq!(r.error(), ERROR_NONE);
}

#[test]
fn s3_4_binding_the_pool_gives_a_primary_row_for_the_whole_screen() {
    let mut r = rig();
    let pool = r.source(r.primary, SOURCE_POOL);
    r.bind(r.primary, pool);
    let c = r.commit().expect("a commit");
    assert!(c.frame);
    let row = row_of(&c, PIPELINE_PRIMARY);
    assert_eq!(row.source, SOURCE_POOL);
    assert_eq!(row.area(), Some(Rect::SCREEN));
    assert_eq!(c.layers.as_ref().unwrap().rows().len(), 1);
    assert_eq!(c.layers.as_ref().unwrap().check_virtio(), Ok(()));
}

#[test]
fn s5_6_4_only_the_last_bind_call_before_a_commit_counts() {
    let mut r = rig();
    let pool = r.source(r.primary, SOURCE_POOL);
    let target = r.source(r.primary, SOURCE_TARGET);
    r.bind(r.primary, pool);
    r.bind(r.primary, target);
    let c = r.commit().expect("a commit");
    assert_eq!(row_of(&c, PIPELINE_PRIMARY).source, SOURCE_TARGET);
}

#[test]
fn s3_4_binding_the_source_that_is_bound_shows_it_again() {
    let mut r = rig();
    let pool = r.source(r.primary, SOURCE_POOL);
    r.bind(r.primary, pool);
    let c = r.commit().expect("commit");
    r.wfd.finish_commit(&c, Ok(()));
    r.bind(r.primary, pool);
    let c = r.commit().expect("commit");
    let row = row_of(&c, PIPELINE_PRIMARY);
    assert_eq!((row.source, row.area()), (SOURCE_POOL, Some(Rect::SCREEN)));
}

#[test]
fn s3_4_the_primary_pipeline_is_never_off_and_never_partial() {
    let mut r = rig();
    let p = r.primary;
    r.wfd
        .bind_source_to_pipeline(r.dev, p, 0, TRANSITION_IMMEDIATE, false);
    assert!(r.commit().is_none());
    assert_eq!(r.error(), ERROR_NOT_SUPPORTED);
    // The failed commit dropped the cached bind.
    assert!(r.commit().is_some());
    r.wfd.set_pipeline_attrib_iv(
        r.dev,
        p,
        PIPELINE_DESTINATION_RECTANGLE,
        4,
        Some(&[0, 0, 320, 200]),
    );
    assert!(r.commit().is_none());
    assert_eq!(r.error(), ERROR_NOT_SUPPORTED, "no scaling");
    r.wfd.set_pipeline_attrib_iv(
        r.dev,
        p,
        PIPELINE_DESTINATION_RECTANGLE,
        4,
        Some(&[0, 0, 0, 0]),
    );
    assert!(r.commit().is_none());
    assert_eq!(
        r.error(),
        ERROR_NOT_SUPPORTED,
        "a disabled primary pipeline"
    );
    r.wfd.set_pipeline_attrib_iv(
        r.dev,
        p,
        PIPELINE_DESTINATION_RECTANGLE,
        4,
        Some(&[10, 0, 640, 400]),
    );
    assert!(r.commit().is_none());
    assert_eq!(r.error(), ERROR_INCONSISTENCY, "outside the port");
    r.wfd.set_pipeline_attrib_iv(
        r.dev,
        p,
        PIPELINE_SOURCE_RECTANGLE,
        4,
        Some(&[0, 0, 641, 400]),
    );
    assert!(r.commit().is_none());
    assert_eq!(r.error(), ERROR_INCONSISTENCY, "outside the source");
}

#[test]
fn s3_4_a_failed_commit_clears_the_cache_in_all_cases() {
    let mut r = rig();
    let p = r.primary;
    r.wfd.set_pipeline_attrib_iv(
        r.dev,
        p,
        PIPELINE_DESTINATION_RECTANGLE,
        4,
        Some(&[0, 0, 10, 10]),
    );
    assert!(r.commit().is_none());
    assert_eq!(r.error(), ERROR_NOT_SUPPORTED);
    let mut rect = [0; 4];
    r.wfd
        .get_pipeline_attrib_iv(r.dev, p, PIPELINE_DESTINATION_RECTANGLE, 4, Some(&mut rect));
    assert_eq!(rect, [0, 0, 640, 400]);
}

#[test]
fn s3_4_a_commit_names_what_it_covers() {
    let mut r = rig();
    assert!(r.wfd.commit(r.dev, 0x7553, 0).is_none());
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    assert!(r.wfd.commit(r.dev, COMMIT_ENTIRE_DEVICE, r.port).is_none());
    assert_eq!(r.error(), ERROR_BAD_HANDLE);
    assert!(r.wfd.commit(r.dev, COMMIT_ENTIRE_PORT, r.primary).is_none());
    assert_eq!(r.error(), ERROR_BAD_HANDLE);
    assert!(r.wfd.commit(r.dev, COMMIT_PIPELINE, r.port).is_none());
    assert_eq!(r.error(), ERROR_BAD_HANDLE);
    assert!(r.wfd.commit(r.dev, COMMIT_ENTIRE_PORT, r.port).is_some());
    assert!(r.wfd.commit(r.dev, COMMIT_PIPELINE, r.cursor).is_some());
    assert!(r.wfd.commit(r.dev + 1, COMMIT_ENTIRE_DEVICE, 0).is_none());
    assert_eq!(r.error(), ERROR_NONE);
}

#[test]
fn s3_4_a_pipeline_commit_leaves_the_other_pipelines_changes_cached() {
    let mut r = rig();
    let pool = r.source(r.primary, SOURCE_POOL);
    r.bind(r.primary, pool);
    r.show_cursor();
    let c = r
        .wfd
        .commit(r.dev, COMMIT_PIPELINE, r.cursor)
        .expect("commit");
    assert!(!c.frame);
    assert_eq!(c.layers.as_ref().unwrap().rows().len(), 1);
    r.wfd.finish_commit(&c, Ok(()));
    // The pool is still waiting for its own commit.
    let c = r.commit().expect("commit");
    assert!(c.frame);
    assert_eq!(row_of(&c, PIPELINE_PRIMARY).source, SOURCE_POOL);
    assert_eq!(
        c.layers.as_ref().unwrap().rows().len(),
        1,
        "the cursor is done"
    );
}

#[test]
fn s5_7_1_the_cursor_row_carries_the_place_of_the_hot_spot() {
    let mut r = rig();
    r.show_cursor();
    r.wfd.set_cursor_hot_spot(r.dev, r.cursor, 5, 7);
    assert_eq!(r.error(), ERROR_NONE);
    let c = r.commit().expect("commit");
    assert!(!c.frame, "a cursor alone makes no frame");
    let row = row_of(&c, 2);
    assert_eq!(
        (row.x, row.y),
        (10 + 5, 20 + 7),
        "the place is the hot spot's, which the corner does not give"
    );
    assert_eq!((row.hot_x, row.hot_y), (5, 7));
    assert_eq!(row.source, SOURCE_CURSOR);
    assert_eq!(
        row.area(),
        Some(Rect {
            x: 0,
            y: 0,
            w: 64,
            h: 64
        })
    );
    assert_eq!(c.layers.as_ref().unwrap().check_virtio(), Ok(()));
}

#[test]
fn s5_7_1_a_move_is_a_row_without_a_changed_area() {
    let mut r = rig();
    r.show_cursor();
    let c = r.commit().expect("commit");
    r.wfd.finish_commit(&c, Ok(()));
    r.wfd.set_pipeline_attrib_iv(
        r.dev,
        r.cursor,
        PIPELINE_DESTINATION_RECTANGLE,
        4,
        Some(&[300, 100, 64, 64]),
    );
    let c = r.commit().expect("commit");
    let row = row_of(&c, 2);
    assert_eq!((row.x, row.y, row.source), (300, 100, SOURCE_CURSOR));
    assert_eq!(row.area(), None);
    r.wfd.finish_commit(&c, Ok(()));
    // Nothing changed: no request.
    assert!(r.commit().unwrap().layers.is_none());
}

#[test]
fn s5_7_1_the_cursor_is_hidden_by_an_empty_rectangle_or_an_unbind() {
    let mut r = rig();
    r.show_cursor();
    let c = r.commit().expect("commit");
    r.wfd.finish_commit(&c, Ok(()));
    r.wfd.set_pipeline_attrib_iv(
        r.dev,
        r.cursor,
        PIPELINE_DESTINATION_RECTANGLE,
        4,
        Some(&[0, 0, 0, 0]),
    );
    let c = r.commit().expect("commit");
    let row = row_of(&c, 2);
    assert_eq!(row, LayerRow::off(2));
    r.wfd.finish_commit(&c, Ok(()));
    // Unbound after it was hidden: nothing to tell.
    r.wfd
        .bind_source_to_pipeline(r.dev, r.cursor, 0, TRANSITION_IMMEDIATE, false);
    assert!(r.commit().unwrap().layers.is_none());
}

#[test]
fn s5_7_1_the_cursor_picture_is_blended_by_its_alpha_whole_and_on_the_port() {
    let mut r = rig();
    let c = r.cursor;
    let src = r.source(c, SOURCE_CURSOR);
    r.bind(c, src);
    r.wfd.set_pipeline_attrib_iv(
        r.dev,
        c,
        PIPELINE_SOURCE_RECTANGLE,
        4,
        Some(&[0, 0, 64, 64]),
    );
    r.wfd.set_pipeline_attrib_iv(
        r.dev,
        c,
        PIPELINE_DESTINATION_RECTANGLE,
        4,
        Some(&[1, 1, 64, 64]),
    );
    assert!(r.commit().is_none());
    assert_eq!(
        r.error(),
        ERROR_NOT_SUPPORTED,
        "no source alpha: the hardware blends"
    );
    r.bind(c, src);
    r.wfd.set_pipeline_attrib(
        r.dev,
        c,
        PIPELINE_TRANSPARENCY_ENABLE,
        TRANSPARENCY_SOURCE_ALPHA as i32,
    );
    r.wfd.set_pipeline_attrib_iv(
        r.dev,
        c,
        PIPELINE_SOURCE_RECTANGLE,
        4,
        Some(&[0, 0, 64, 64]),
    );
    r.wfd.set_pipeline_attrib_iv(
        r.dev,
        c,
        PIPELINE_DESTINATION_RECTANGLE,
        4,
        Some(&[1, 1, 32, 32]),
    );
    assert!(r.commit().is_none());
    assert_eq!(r.error(), ERROR_NOT_SUPPORTED, "no scaling");
}

#[test]
fn s5_7_1_11_a_cursor_that_leaves_the_port_is_inconsistent() {
    let mut r = rig();
    let c = r.cursor;
    let src = r.source(c, SOURCE_CURSOR);
    for rect in [[600, 0, 64, 64], [0, 350, 64, 64], [-1, 0, 64, 64]] {
        r.bind(c, src);
        r.wfd.set_pipeline_attrib_iv(
            r.dev,
            c,
            PIPELINE_SOURCE_RECTANGLE,
            4,
            Some(&[0, 0, 64, 64]),
        );
        r.wfd
            .set_pipeline_attrib_iv(r.dev, c, PIPELINE_DESTINATION_RECTANGLE, 4, Some(&rect));
        r.wfd.set_pipeline_attrib(
            r.dev,
            c,
            PIPELINE_TRANSPARENCY_ENABLE,
            TRANSPARENCY_SOURCE_ALPHA as i32,
        );
        assert!(r.commit().is_none(), "{rect:?}");
        assert_eq!(r.error(), ERROR_INCONSISTENCY, "{rect:?}");
    }
}

#[test]
fn s3_4_one_request_holds_the_rows_of_both_pipelines() {
    let mut r = rig();
    let pool = r.source(r.primary, SOURCE_POOL);
    r.bind(r.primary, pool);
    r.show_cursor();
    let c = r.commit().expect("commit");
    let rows = c.layers.as_ref().unwrap().rows();
    assert_eq!(rows.len(), 2);
    assert_eq!(c.layers.as_ref().unwrap().check_virtio(), Ok(()));
    assert!(c.frame);
}

#[test]
fn s3_4_a_refusal_of_the_service_is_the_error_and_drops_the_cache() {
    let mut r = rig();
    let pool = r.source(r.primary, SOURCE_POOL);
    r.bind(r.primary, pool);
    let c = r.commit().expect("commit");
    r.wfd.finish_commit(&c, Err(ERROR_BUSY));
    assert_eq!(r.error(), ERROR_BUSY);
    assert!(!r.wfd.frame_pending());
    // The binding is gone from the cache, and the display still shows the
    // target: nothing to send.
    assert!(r.commit().unwrap().layers.is_none());
}

// -------------------------------------------------------------------- events

fn finish(r: &mut Rig, c: &Commit) {
    r.wfd.finish_commit(c, Ok(()));
}

#[test]
fn s3_6_5_5_a_frame_commit_completes_with_the_frames_bit() {
    let mut r = rig();
    let ev = r.wfd.create_event(r.dev, &[]);
    let pool = r.source(r.primary, SOURCE_POOL);
    r.bind(r.primary, pool);
    let c = r.commit().expect("commit");
    finish(&mut r, &c);
    assert!(r.wfd.frame_pending());
    assert_eq!(r.wfd.event_poll(ev), Poll::Empty, "not before the bit");
    r.wfd.frame_done();
    assert!(!r.wfd.frame_pending());
    assert_eq!(
        r.wfd.event_poll(ev),
        Poll::Event(EVENT_PIPELINE_BIND_SOURCE_COMPLETE)
    );
    let g = |r: &mut Rig, a| r.wfd.get_event_attrib(r.dev, ev, a);
    assert_eq!(g(&mut r, EVENT_TYPE), EVENT_PIPELINE_BIND_SOURCE_COMPLETE);
    assert_eq!(g(&mut r, EVENT_PIPELINE_BIND_PIPELINE_ID), 1);
    assert_eq!(
        g(&mut r, EVENT_PIPELINE_BIND_SOURCE),
        0,
        "the bound before had no handle"
    );
    assert_eq!(g(&mut r, EVENT_PIPELINE_BIND_QUEUE_OVERFLOW), 0);
    assert_eq!(g(&mut r, EVENT_PIPELINE_BIND_MASK), 0);
    assert_eq!(r.error(), ERROR_NONE);
    assert_eq!(r.wfd.event_poll(ev), Poll::Empty);
    assert_eq!(g(&mut r, EVENT_TYPE), EVENT_NONE);
}

#[test]
fn s3_6_5_5_the_event_names_the_source_that_was_bound_before() {
    let mut r = rig();
    let ev = r.wfd.create_event(r.dev, &[]);
    let pool = r.source(r.primary, SOURCE_POOL);
    let target = r.source(r.primary, SOURCE_TARGET);
    r.bind(r.primary, pool);
    let c = r.commit().unwrap();
    finish(&mut r, &c);
    r.wfd.frame_done();
    r.bind(r.primary, target);
    let c = r.commit().unwrap();
    finish(&mut r, &c);
    r.wfd.frame_done();
    assert_eq!(
        r.wfd.event_poll(ev),
        Poll::Event(EVENT_PIPELINE_BIND_SOURCE_COMPLETE)
    );
    assert_eq!(
        r.wfd
            .get_event_attrib(r.dev, ev, EVENT_PIPELINE_BIND_SOURCE),
        0
    );
    assert_eq!(
        r.wfd.event_poll(ev),
        Poll::Event(EVENT_PIPELINE_BIND_SOURCE_COMPLETE)
    );
    assert_eq!(
        r.wfd
            .get_event_attrib(r.dev, ev, EVENT_PIPELINE_BIND_SOURCE) as u32,
        pool,
        "the pool was bound before"
    );
}

#[test]
fn s3_6_5_5_a_cursor_commit_completes_at_once() {
    let mut r = rig();
    let ev = r.wfd.create_event(r.dev, &[]);
    r.show_cursor();
    let c = r.commit().unwrap();
    finish(&mut r, &c);
    assert!(!r.wfd.frame_pending());
    assert_eq!(
        r.wfd.event_poll(ev),
        Poll::Event(EVENT_PIPELINE_BIND_SOURCE_COMPLETE)
    );
    assert_eq!(
        r.wfd
            .get_event_attrib(r.dev, ev, EVENT_PIPELINE_BIND_PIPELINE_ID),
        2
    );
}

#[test]
fn s3_6_1_3_1_the_queue_size_is_set_at_creation_and_zero_turns_the_events_off() {
    let mut r = rig();
    let a = r
        .wfd
        .create_event(r.dev, &[EVENT_PIPELINE_BIND_QUEUE_SIZE, 1]);
    let off = r
        .wfd
        .create_event(r.dev, &[EVENT_PIPELINE_BIND_QUEUE_SIZE, 0]);
    let dflt = r.wfd.create_event(r.dev, &[]);
    assert_eq!(
        r.wfd
            .get_event_attrib(r.dev, a, EVENT_PIPELINE_BIND_QUEUE_SIZE),
        1
    );
    assert_eq!(
        r.wfd
            .get_event_attrib(r.dev, off, EVENT_PIPELINE_BIND_QUEUE_SIZE),
        0
    );
    // 60 hertz times two pipelines.
    assert_eq!(
        r.wfd
            .get_event_attrib(r.dev, dflt, EVENT_PIPELINE_BIND_QUEUE_SIZE),
        120
    );
    for _ in 0..3 {
        r.show_cursor();
        let c = r.commit().unwrap();
        finish(&mut r, &c);
    }
    assert_eq!(r.wfd.event_poll(off), Poll::Empty);
    assert_eq!(
        r.wfd.event_poll(a),
        Poll::Event(EVENT_PIPELINE_BIND_SOURCE_COMPLETE)
    );
    assert_eq!(
        r.wfd
            .get_event_attrib(r.dev, a, EVENT_PIPELINE_BIND_QUEUE_OVERFLOW),
        1
    );
    assert_eq!(
        r.wfd.event_poll(a),
        Poll::Empty,
        "the full queue dropped the rest"
    );
}

#[test]
fn s3_6_1_1_an_event_container_takes_only_the_queue_size_attribute() {
    let mut r = rig();
    assert_eq!(r.wfd.create_event(r.dev, &[EVENT_TYPE, 1]), 0);
    assert_eq!(r.error(), ERROR_BAD_ATTRIBUTE);
    let mut made = 0;
    for _ in 0..MAX_EVENTS {
        made += i32::from(r.wfd.create_event(r.dev, &[]) != 0);
    }
    assert_eq!(made, MAX_EVENTS as i32);
    assert_eq!(r.wfd.create_event(r.dev, &[]), 0);
    assert_eq!(r.error(), ERROR_OUT_OF_MEMORY);
}

#[test]
fn s3_6_1_2_a_container_is_destroyed_once() {
    let mut r = rig();
    let ev = r.wfd.create_event(r.dev, &[]);
    r.wfd.destroy_event(r.dev, ev);
    assert_eq!(r.error(), ERROR_NONE);
    r.wfd.destroy_event(r.dev, ev);
    assert_eq!(r.error(), ERROR_BAD_HANDLE);
    assert_eq!(r.wfd.event_poll(ev), Poll::Gone);
}

#[test]
fn s3_6_1_3_an_attribute_that_does_not_belong_to_the_last_event_is_illegal() {
    let mut r = rig();
    let ev = r.wfd.create_event(r.dev, &[]);
    assert_eq!(r.wfd.get_event_attrib(r.dev, ev, EVENT_TYPE), EVENT_NONE);
    r.wfd
        .get_event_attrib(r.dev, ev, EVENT_PIPELINE_BIND_PIPELINE_ID);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    r.wfd.get_event_attrib(r.dev, ev, EVENT_PORT_ATTACH_PORT_ID);
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    r.wfd.get_event_attrib(r.dev, ev, 0x75FF);
    assert_eq!(r.error(), ERROR_BAD_ATTRIBUTE);
    r.wfd.get_event_attrib(r.dev, ev + 80, EVENT_TYPE);
    assert_eq!(r.error(), ERROR_BAD_HANDLE);
}

#[test]
fn s3_6_4_a_filter_keeps_the_listed_events_and_always_none_and_destroyed() {
    let mut r = rig();
    let ev = r.wfd.create_event(r.dev, &[]);
    r.wfd
        .device_event_filter(r.dev, ev, Some(&[EVENT_PORT_ATTACH_DETACH]));
    assert_eq!(r.error(), ERROR_NONE);
    r.show_cursor();
    let c = r.commit().unwrap();
    finish(&mut r, &c);
    assert_eq!(
        r.wfd.event_poll(ev),
        Poll::Empty,
        "the bind event is filtered out"
    );
    r.wfd
        .device_event_filter(r.dev, ev, Some(&[EVENT_PIPELINE_BIND_SOURCE_COMPLETE]));
    r.bind(r.cursor, 0);
    r.wfd
        .bind_source_to_pipeline(r.dev, r.cursor, 0, TRANSITION_IMMEDIATE, false);
    let c = r.commit().unwrap();
    finish(&mut r, &c);
    assert_eq!(
        r.wfd.event_poll(ev),
        Poll::Event(EVENT_PIPELINE_BIND_SOURCE_COMPLETE)
    );
    // NULL means no filtering.
    r.wfd.device_event_filter(r.dev, ev, None);
    assert_eq!(r.error(), ERROR_NONE);
    r.wfd.device_event_filter(r.dev, ev, Some(&[EVENT_INVALID]));
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    r.wfd.device_event_filter(r.dev, ev, Some(&[0x1234]));
    assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT);
    r.wfd.device_event_filter(r.dev, ev + 80, None);
    assert_eq!(r.error(), ERROR_BAD_HANDLE);
}

#[test]
fn s3_6_3_only_one_thread_waits_on_a_container() {
    let mut r = rig();
    let ev = r.wfd.create_event(r.dev, &[]);
    assert!(r.wfd.begin_wait(r.dev, ev));
    assert!(!r.wfd.begin_wait(r.dev, ev));
    assert_eq!(r.error(), ERROR_NOT_SUPPORTED);
    r.wfd.end_wait(ev);
    assert!(r.wfd.begin_wait(r.dev, ev));
    assert!(!r.wfd.begin_wait(r.dev, ev + 80));
    assert_eq!(r.error(), ERROR_BAD_HANDLE);
    r.wfd.event_timed_out(ev);
    assert_eq!(r.wfd.get_event_attrib(r.dev, ev, EVENT_TYPE), EVENT_NONE);
}

#[test]
fn s3_6_5_5_every_container_gets_the_event() {
    let mut r = rig();
    let a = r.wfd.create_event(r.dev, &[]);
    let b = r.wfd.create_event(r.dev, &[]);
    r.show_cursor();
    let c = r.commit().unwrap();
    finish(&mut r, &c);
    assert_eq!(
        r.wfd.event_poll(a),
        Poll::Event(EVENT_PIPELINE_BIND_SOURCE_COMPLETE)
    );
    assert_eq!(
        r.wfd.event_poll(b),
        Poll::Event(EVENT_PIPELINE_BIND_SOURCE_COMPLETE)
    );
}

// ---------------------------------------------------------------- the cursor

#[test]
fn the_hot_spot_is_a_point_of_the_picture() {
    let mut r = rig();
    r.wfd.set_cursor_hot_spot(r.dev, r.cursor, 63, 63);
    assert_eq!(r.error(), ERROR_NONE);
    for (x, y) in [(64, 0), (0, 64), (-1, 0), (0, -1)] {
        r.wfd.set_cursor_hot_spot(r.dev, r.cursor, x, y);
        assert_eq!(r.error(), ERROR_ILLEGAL_ARGUMENT, "{x},{y}");
    }
    r.wfd.set_cursor_hot_spot(r.dev, r.primary, 0, 0);
    assert_eq!(
        r.error(),
        ERROR_ILLEGAL_ARGUMENT,
        "the primary pipeline has none"
    );
    r.wfd.set_cursor_hot_spot(r.dev, r.cursor + 90, 0, 0);
    assert_eq!(r.error(), ERROR_BAD_HANDLE);
}

#[test]
fn a_changed_hot_spot_alone_is_a_row_without_a_picture() {
    let mut r = rig();
    r.show_cursor();
    let c = r.commit().unwrap();
    finish(&mut r, &c);
    r.wfd.set_cursor_hot_spot(r.dev, r.cursor, 3, 4);
    let c = r.commit().unwrap();
    let row = row_of(&c, 2);
    assert_eq!((row.x, row.y, row.hot_x, row.hot_y), (13, 24, 3, 4));
    assert_eq!(row.area(), None);
}
