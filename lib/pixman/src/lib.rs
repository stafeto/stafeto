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
    /// The images kept: the screen's, the pointer's picture and the buffers
    /// of the windows in use (three buffers of each of eight windows is more
    /// than a frame touches at once).
    const KEPT: usize = 16;

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

    /// What identifies an image: the memory it wraps and how it reads it.
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Key {
        bytes: usize,
        format: Format,
        stride: u32,
        width: u32,
        height: u32,
    }

    /// A pixman image over memory. It does not own the pixels.
    struct Image(*mut c_void);

    impl Drop for Image {
        fn drop(&mut self) {
            // SAFETY: the image came from `pixman_image_create_bits` and is
            // dropped once.
            unsafe { pixman_image_unref(self.0) };
        }
    }

    /// The images of the surfaces the service composes with, kept from one
    /// call to the next: making and dropping a pair of images costs more
    /// ticks than the points of a band of a window. A surface is told by its
    /// address and shape; the oldest image goes when the table is full. The
    /// memory an image wraps is only read or written in a call, so a surface
    /// whose memory is gone is harmless until the service names it again.
    pub struct Images {
        kept: [Option<(Key, Image)>; KEPT],
        next: usize,
    }

    impl Images {
        pub const fn new() -> Images {
            Images {
                kept: [const { None }; KEPT],
                next: 0,
            }
        }

        /// The image of `key`, made when it is not kept. None when pixman
        /// refuses (no memory in its arena).
        fn image(&mut self, key: Key) -> Option<*mut c_void> {
            if let Some((_, image)) = self.kept.iter().flatten().find(|(k, _)| *k == key) {
                return Some(image.0);
            }
            // SAFETY: pixman reads the arguments; the bits are not owned by
            // the image, which is dropped (with the table) before the
            // service ends and is never used on memory the service unmapped.
            let image = unsafe {
                pixman_image_create_bits(
                    code(key.format),
                    key.width as i32,
                    key.height as i32,
                    key.bytes as *mut u32,
                    key.stride as i32,
                )
            };
            if image.is_null() {
                return None;
            }
            let at = self.next;
            self.next = (self.next + 1) % KEPT;
            self.kept[at] = Some((key, Image(image)));
            Some(image)
        }
    }

    impl Default for Images {
        fn default() -> Images {
            Images::new()
        }
    }

    /// Whether a surface of `width` by `height` points of `stride` bytes a
    /// line lies inside `len` bytes at `at`, with points of 4 bytes on a
    /// 4-byte boundary.
    fn shaped(at: usize, len: usize, stride: u32, width: u32, height: u32) -> bool {
        width > 0
            && height > 0
            && at.is_multiple_of(4)
            && stride.is_multiple_of(4)
            && u64::from(stride) >= u64::from(width) * 4
            && u64::from(stride) * u64::from(height) <= len as u64
            && i32::try_from(stride).is_ok()
            && i32::try_from(width).is_ok()
            && i32::try_from(height).is_ok()
    }

    /// Whether the rectangle at (`x`, `y`) of `w` by `h` lies inside a
    /// surface of `width` by `height`.
    fn inside(x: u32, y: u32, w: u32, h: u32, width: u32, height: u32) -> bool {
        w > 0
            && h > 0
            && u64::from(x) + u64::from(w) <= u64::from(width)
            && u64::from(y) + u64::from(h) <= u64::from(height)
    }

    /// `op` of the `w` by `h` points at (`sx`, `sy`) of `src` onto
    /// (`dx`, `dy`) of `dst`; false when a surface is not what its bytes
    /// hold or the rectangles are not inside them, and when pixman could not
    /// make its images: nothing is drawn then.
    pub fn composite(
        images: &mut Images,
        over: bool,
        dst: (&mut [u8], Format, u32, u32, u32),
        src: (&[u8], Format, u32, u32, u32),
        at: (u32, u32, u32, u32),
        size: (u32, u32),
    ) -> bool {
        let (dbytes, dformat, dstride, dwidth, dheight) = dst;
        let (sbytes, sformat, sstride, swidth, sheight) = src;
        let (sx, sy, dx, dy) = at;
        if !shaped(
            dbytes.as_ptr() as usize,
            dbytes.len(),
            dstride,
            dwidth,
            dheight,
        ) || !shaped(
            sbytes.as_ptr() as usize,
            sbytes.len(),
            sstride,
            swidth,
            sheight,
        ) || !inside(sx, sy, size.0, size.1, swidth, sheight)
            || !inside(dx, dy, size.0, size.1, dwidth, dheight)
        {
            return false;
        }
        let Some(d) = images.image(Key {
            bytes: dbytes.as_mut_ptr() as usize,
            format: dformat,
            stride: dstride,
            width: dwidth,
            height: dheight,
        }) else {
            return false;
        };
        let Some(s) = images.image(Key {
            bytes: sbytes.as_ptr() as usize,
            format: sformat,
            stride: sstride,
            width: swidth,
            height: sheight,
        }) else {
            return false;
        };
        // SAFETY: both images wrap memory that the checks above show holds
        // the surfaces, which outlives the call, and the rectangles lie
        // inside them.
        unsafe {
            pixman_image_composite32(
                if over { OP_OVER } else { OP_SRC },
                s,
                core::ptr::null_mut(),
                d,
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

    /// The rectangle takes `value`; false (and nothing is drawn) when the
    /// surface is not what its bytes hold or the rectangle is not inside it.
    pub fn fill(
        dst: &mut [u8],
        stride: u32,
        (width, height): (u32, u32),
        (x, y, w, h): (u32, u32, u32, u32),
        value: u32,
    ) -> bool {
        if !shaped(dst.as_ptr() as usize, dst.len(), stride, width, height)
            || !inside(x, y, w, h, width, height)
        {
            return false;
        }
        // SAFETY: the checks above show the rectangle is inside the
        // buffer; `stride` is in 32-bit words for pixman_fill.
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
        true
    }
}

#[cfg(target_os = "none")]
pub use imp::Images;

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
/// False, with nothing drawn, when a surface is not what its bytes hold, a
/// rectangle is not inside them, or pixman could not make its images.
#[cfg(target_os = "none")]
pub fn composite(
    images: &mut Images,
    over: bool,
    dst: &mut Target<'_>,
    src: Source<'_>,
    (sx, sy): (u32, u32),
    (dx, dy): (u32, u32),
    (w, h): (u32, u32),
) -> bool {
    imp::composite(
        images,
        over,
        (dst.bytes, dst.format, dst.stride, dst.width, dst.height),
        (src.bytes, src.format, src.stride, src.width, src.height),
        (sx, sy, dx, dy),
        (w, h),
    )
}

/// The rectangle of `dst` takes the colour `value` (an XRGB8888 point);
/// false when it is not inside the surface.
#[cfg(target_os = "none")]
pub fn fill(dst: &mut Target<'_>, x: u32, y: u32, w: u32, h: u32, value: u32) -> bool {
    imp::fill(
        dst.bytes,
        dst.stride,
        (dst.width, dst.height),
        (x, y, w, h),
        value,
    )
}
