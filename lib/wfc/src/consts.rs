// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The numbers of `<WF/wfc.h>` that the rules use, under the header's names
//! without the prefix `WFC_`.

pub const ERROR_NONE: i32 = 0;
pub const ERROR_OUT_OF_MEMORY: i32 = 0x7001;
pub const ERROR_ILLEGAL_ARGUMENT: i32 = 0x7002;
pub const ERROR_UNSUPPORTED: i32 = 0x7003;
pub const ERROR_BAD_ATTRIBUTE: i32 = 0x7004;
pub const ERROR_IN_USE: i32 = 0x7005;
pub const ERROR_BUSY: i32 = 0x7006;
pub const ERROR_BAD_DEVICE: i32 = 0x7007;
pub const ERROR_BAD_HANDLE: i32 = 0x7008;
pub const ERROR_INCONSISTENCY: i32 = 0x7009;

pub const DEVICE_FILTER_SCREEN_NUMBER: i32 = 0x7020;
pub const DEVICE_CLASS: i32 = 0x7030;
pub const DEVICE_ID: i32 = 0x7031;
pub const DEVICE_CLASS_FULLY_CAPABLE: i32 = 0x7040;

pub const CONTEXT_TYPE: i32 = 0x7051;
pub const CONTEXT_TARGET_HEIGHT: i32 = 0x7052;
pub const CONTEXT_TARGET_WIDTH: i32 = 0x7053;
pub const CONTEXT_LOWEST_ELEMENT: i32 = 0x7054;
pub const CONTEXT_ROTATION: i32 = 0x7061;
pub const CONTEXT_BG_COLOR: i32 = 0x7062;
pub const CONTEXT_TYPE_ON_SCREEN: i32 = 0x7071;

pub const ROTATION_0: i32 = 0x7081;
pub const ROTATION_90: i32 = 0x7082;
pub const ROTATION_180: i32 = 0x7083;
pub const ROTATION_270: i32 = 0x7084;

pub const ELEMENT_DESTINATION_RECTANGLE: i32 = 0x7101;
pub const ELEMENT_SOURCE: i32 = 0x7102;
pub const ELEMENT_SOURCE_RECTANGLE: i32 = 0x7103;
pub const ELEMENT_SOURCE_FLIP: i32 = 0x7104;
pub const ELEMENT_SOURCE_ROTATION: i32 = 0x7105;
pub const ELEMENT_SOURCE_SCALE_FILTER: i32 = 0x7106;
pub const ELEMENT_TRANSPARENCY_TYPES: i32 = 0x7107;
pub const ELEMENT_GLOBAL_ALPHA: i32 = 0x7108;
pub const ELEMENT_MASK: i32 = 0x7109;

pub const SCALE_FILTER_NONE: i32 = 0x7151;
pub const SCALE_FILTER_FASTER: i32 = 0x7152;
pub const SCALE_FILTER_BETTER: i32 = 0x7153;

pub const VENDOR: i32 = 0x7200;
pub const RENDERER: i32 = 0x7201;
pub const VERSION: i32 = 0x7202;
pub const EXTENSIONS: i32 = 0x7203;

/// The largest magnitude of an integer or a float the API takes (2^24).
pub const MAX_INT: i32 = 16_777_216;
