// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The pixel operations of pixman for the composition service: a copy and an
//! "over" of a rectangle of one surface onto another, and a fill. The
//! compositing itself is pixman's (tools/build-pixman.py builds its portable
//! C paths); this file is the glue, which wraps the memory of a buffer in
//! a pixman image for the length of one call.
//!
//! A surface is 32 bits to the point: XRGB8888 (the top byte unused, the
//! point opaque) or ARGB8888 with the colour already multiplied by the
//! alpha, the formats of the protocol of the service. On a target that is not
//! a program of stafeto the crate is empty.

#![no_std]

/// The format of a surface's points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// Opaque: the top byte is not read.
    Xrgb8888,
    /// The colour is premultiplied by the alpha in the top byte.
    Argb8888,
}

#[cfg(target_os = "none")]
mod imp {
    use super::Format;
    use core::ffi::c_void;

    // pixman.h: PIXMAN_FORMAT (bpp, type, a, r, g, b) with the type ARGB 2.
    const A8R8G8B8: u32 = 0x2002_8888;
    const X8R8G8B8: u32 = 0x2002_0888;
    // pixman_op_t: PIXMAN_OP_SRC and PIXMAN_OP_OVER.
    const OP_SRC: i32 = 1;
    const OP_OVER: i32 = 3;

    unsafe extern "C" {
        fn pixman_image_create_bits(
            format: u32,
            width: i32,
            height: i32,
            bits: *mut u32,
            rowstride_bytes: i32,
        ) -> *mut c_void;
        fn pixman_image_unref(image: *mut c_void) -> i32;
        fn pixman_image_composite32(
            op: i32,
            src: *mut c_void,
            mask: *mut c_void,
            dest: *mut c_void,
            src_x: i32,
            src_y: i32,
            mask_x: i32,
            mask_y: i32,
            dest_x: i32,
            dest_y: i32,
            width: i32,
            height: i32,
        );
        fn pixman_fill(
            bits: *mut u32,
            stride: i32,
            bpp: i32,
            x: i32,
            y: i32,
            width: i32,
            height: i32,
            filler: u32,
        ) -> i32;
    }

    const fn code(format: Format) -> u32 {
        match format {
            Format::Xrgb8888 => X8R8G8B8,
            Format::Argb8888 => A8R8G8B8,
        }
    }

    /// A pixman image over `bytes`: `width` by `height` points of `stride`
    /// bytes a line. None when pixman refuses (no memory in its arena).
    struct Image(*mut c_void);

    impl Image {
        fn new(
            format: Format,
            width: u32,
            height: u32,
            stride: u32,
            bytes: *mut u8,
        ) -> Option<Image> {
            // SAFETY: pixman reads the arguments; the bits are not owned by
            // the image, which the caller drops before the bytes go.
            let image = unsafe {
                pixman_image_create_bits(
                    code(format),
                    width as i32,
                    height as i32,
                    bytes.cast::<u32>(),
                    stride as i32,
                )
            };
            (!image.is_null()).then_some(Image(image))
        }
    }

    impl Drop for Image {
        fn drop(&mut self) {
            // SAFETY: the image came from `pixman_image_create_bits` and is
            // dropped once.
            unsafe { pixman_image_unref(self.0) };
        }
    }

    /// `op` of the `w` by `h` points at (`sx`, `sy`) of `src` onto
    /// (`dx`, `dy`) of `dst`; false when pixman could not make its images.
    #[allow(clippy::too_many_arguments)]
    pub fn composite(
        over: bool,
        dst: (&mut [u8], Format, u32, u32, u32),
        src: (&[u8], Format, u32, u32, u32),
        at: (u32, u32, u32, u32),
        size: (u32, u32),
    ) -> bool {
        let (dbytes, dformat, dstride, dwidth, dheight) = dst;
        let (sbytes, sformat, sstride, swidth, sheight) = src;
        let (sx, sy, dx, dy) = at;
        let Some(d) = Image::new(dformat, dwidth, dheight, dstride, dbytes.as_mut_ptr()) else {
            return false;
        };
        // The source is only read: pixman takes a mutable pointer for both.
        let Some(s) = Image::new(
            sformat,
            swidth,
            sheight,
            sstride,
            sbytes.as_ptr().cast_mut(),
        ) else {
            return false;
        };
        // SAFETY: both images wrap memory that outlives the call, and the
        // rectangles lie inside them (the caller's contract).
        unsafe {
            pixman_image_composite32(
                if over { OP_OVER } else { OP_SRC },
                s.0,
                core::ptr::null_mut(),
                d.0,
                sx as i32,
                sy as i32,
                0,
                0,
                dx as i32,
                dy as i32,
                size.0 as i32,
                size.1 as i32,
            );
        }
        true
    }

    pub fn fill(dst: &mut [u8], stride: u32, x: u32, y: u32, w: u32, h: u32, value: u32) {
        // SAFETY: the rectangle lies inside the buffer (the caller's
        // contract); `stride` is in 32-bit words for pixman_fill.
        unsafe {
            pixman_fill(
                dst.as_mut_ptr().cast::<u32>(),
                (stride / 4) as i32,
                32,
                x as i32,
                y as i32,
                w as i32,
                h as i32,
                value,
            );
        }
    }
}

/// A surface to draw on.
#[cfg(target_os = "none")]
pub struct Target<'a> {
    pub bytes: &'a mut [u8],
    pub format: Format,
    pub stride: u32,
    pub width: u32,
    pub height: u32,
}

/// A surface to read from.
#[cfg(target_os = "none")]
#[derive(Clone, Copy)]
pub struct Source<'a> {
    pub bytes: &'a [u8],
    pub format: Format,
    pub stride: u32,
    pub width: u32,
    pub height: u32,
}

/// The `w` by `h` points at (`sx`, `sy`) of `src` replace those at
/// (`dx`, `dy`) of `dst` (pixman's SRC), or, with `over`, lie over them
/// (OVER, premultiplied). The rectangles must lie inside the surfaces.
/// False when pixman could not make its images.
#[cfg(target_os = "none")]
pub fn composite(
    over: bool,
    dst: &mut Target<'_>,
    src: Source<'_>,
    (sx, sy): (u32, u32),
    (dx, dy): (u32, u32),
    (w, h): (u32, u32),
) -> bool {
    imp::composite(
        over,
        (dst.bytes, dst.format, dst.stride, dst.width, dst.height),
        (src.bytes, src.format, src.stride, src.width, src.height),
        (sx, sy, dx, dy),
        (w, h),
    )
}

/// The rectangle of `dst` takes the colour `value` (an XRGB8888 point).
#[cfg(target_os = "none")]
pub fn fill(dst: &mut Target<'_>, x: u32, y: u32, w: u32, h: u32, value: u32) {
    imp::fill(dst.bytes, dst.stride, x, y, w, h, value);
}
