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
//! alpha, the formats of the protocol of the service; or 8 bits to the point,
//! A8, an alpha alone (a mask). `composite_element` draws a source through a
//! transform (a stretch, a turn by quarter turns, a reflection) with the
//! nearest point or the bilinear mean, and a mask or a global alpha. On a
//! target that is not a program of stafeto the crate is empty.

#![no_std]

pub mod kept;

/// The format of a surface's points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// Opaque: the top byte is not read.
    Xrgb8888,
    /// The colour is premultiplied by the alpha in the top byte.
    Argb8888,
    /// An alpha alone, a byte to the point.
    A8,
}

/// How a transformed source is sampled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Filter {
    /// The point the centre of the target's point falls in.
    Nearest,
    /// The mean of the four points around it, weighted by the distance.
    Bilinear,
}

/// The affine map from the target's points to the source's, in 16.16 numbers:
/// `[a, b, c, d, e, f]` takes (x, y) to (a x + b y + c, d x + e y + f), the
/// coordinates of a point being those of its centre.
pub type Matrix = [i32; 6];

/// The largest area a mask of `Mask::Product` is made for.
pub const WORK_W: u32 = 640;
pub const WORK_H: u32 = 16;

#[cfg(target_os = "none")]
mod imp {
    use super::{Filter, Format, Mask, Matrix, WORK_H, WORK_W};
    use crate::kept::Kept;
    use core::ffi::c_void;

    // pixman.h: PIXMAN_FORMAT (bpp, type, a, r, g, b) with the type ARGB 2.
    const A8R8G8B8: u32 = 0x2002_8888;
    const X8R8G8B8: u32 = 0x2002_0888;
    // The type A with 8 bits of alpha in 8 bits to the point.
    const A8: u32 = 0x0801_8000;
    // pixman_op_t: PIXMAN_OP_SRC and PIXMAN_OP_OVER.
    const OP_SRC: i32 = 1;
    const OP_OVER: i32 = 3;
    // pixman_filter_t: PIXMAN_FILTER_GOOD (an image's own, which a transform
    // the service never sets leaves alone), NEAREST and BILINEAR.
    const FILTER_GOOD: i32 = 1;
    const FILTER_NEAREST: i32 = 3;
    const FILTER_BILINEAR: i32 = 4;
    // pixman_repeat_t: PIXMAN_REPEAT_NONE and PIXMAN_REPEAT_PAD (the points
    // outside a source are its edge's: a bilinear mean at the edge does not
    // blend with transparent black).
    const REPEAT_NONE: i32 = 0;
    const REPEAT_PAD: i32 = 2;
    /// The images kept: the screen's, the pointer's picture, the pool of the
    /// window of the first revision and the buffers of the windows: three buffers
    /// of each of sixteen windows, 48, are all the service can hold at once, 51 in
    /// all. A table smaller than the buffers a frame names in turn (sixteen windows
    /// of two buffers and the screen are 33) makes every operation of a band
    /// make an image again and drop another, which costs a band thousands of ticks
    /// and fragments the arena.
    /// The table is `kept::Kept`: the lookup of a surface the caller numbers is one
    /// comparison when the slot it was last found in still holds it.
    pub const KEPT: usize = 64;
    /// The hints: 0 is the target of the operations, 1 to HINTS - 1 the sources by
    /// the numbers their caller gives them (`NO_HINT` is none).
    pub const HINTS: usize = 64;
    pub const DST_HINT: usize = 0;
    pub const NO_HINT: usize = usize::MAX;

    /// The hint of a source the caller numbers `n`: none when `n` is out of range.
    const fn src_hint(n: usize) -> usize {
        if n < HINTS - 1 { n + 1 } else { NO_HINT }
    }

    unsafe extern "C" {
        fn pixman_image_create_bits(
            format: u32,
            width: i32,
            height: i32,
            bits: *mut u32,
            rowstride_bytes: i32,
        ) -> *mut c_void;
        fn pixman_image_unref(image: *mut c_void) -> i32;
        fn pixman_image_set_transform(image: *mut c_void, transform: *const [[i32; 3]; 3]) -> i32;
        fn pixman_image_set_filter(
            image: *mut c_void,
            filter: i32,
            params: *const i32,
            n_params: i32,
        ) -> i32;
        fn pixman_image_set_repeat(image: *mut c_void, repeat: i32);
        fn pixman_image_create_solid_fill(color: *const [u16; 4]) -> *mut c_void;
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
            Format::A8 => A8,
        }
    }

    /// The bytes of a point.
    const fn bytes_of(format: Format) -> u32 {
        match format {
            Format::A8 => 1,
            _ => 4,
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
        kept: Kept<Key, Image, KEPT, HINTS>,
        made: u32,
        /// The image over the work band (`WORK`), made once and kept.
        work: Option<Image>,
    }

    impl Images {
        pub const fn new() -> Images {
            Images {
                kept: Kept::new(),
                made: 0,
                work: None,
            }
        }

        /// The images made so far (a use of a surface the table does not
        /// keep makes one, which costs a few thousand ticks for eight).
        pub fn made(&self) -> u32 {
            self.made
        }

        /// The entries of the table compared in all (0 without the feature
        /// `scan-count`).
        pub fn scanned(&self) -> u32 {
            self.kept.scanned()
        }

        /// The image over the work band: A8, WORK_W by WORK_H points, made the
        /// first time and kept. None when pixman refuses.
        pub(crate) fn work_image(&mut self) -> Option<*mut c_void> {
            if self.work.is_none() {
                // SAFETY: the band is static memory of the program, WORK_W bytes
                // a line, WORK_H lines, which outlives the image.
                let image = unsafe {
                    pixman_image_create_bits(
                        A8,
                        WORK_W as i32,
                        WORK_H as i32,
                        WORK.0.get().cast::<u32>(),
                        WORK_W as i32,
                    )
                };
                if image.is_null() {
                    return None;
                }
                self.work = Some(Image(image));
            }
            self.work.as_ref().map(|i| i.0)
        }

        /// The image of `key`, made when it is not kept. `hint` is the number of
        /// the surface in the caller's own naming (`DST_HINT`, or `SRC_HINT` and
        /// the caller's number): the table remembers the slot each was found in,
        /// and a lookup is one comparison when the slot still holds the key. None
        /// when pixman refuses (no memory in its arena).
        fn image(&mut self, key: Key, hint: usize) -> Option<*mut c_void> {
            if let Some(slot) = self.kept.find(&key, hint) {
                return self.kept.value(slot).map(|image| image.0);
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
            self.made = self.made.wrapping_add(1);
            self.kept.insert(key, Image(image), hint);
            Some(image)
        }
    }

    impl Default for Images {
        fn default() -> Images {
            Images::new()
        }
    }

    /// Whether a surface of `width` by `height` points of `stride` bytes a
    /// line lies inside `len` bytes at `at`, with its lines on a 4-byte
    /// boundary (pixman reads its memory in words) and `bytes` to the point.
    fn shaped(at: usize, len: usize, stride: u32, size: (u32, u32), bytes: u32) -> bool {
        let (width, height) = size;
        width > 0
            && height > 0
            && at.is_multiple_of(4)
            && stride.is_multiple_of(4)
            && u64::from(stride) >= u64::from(width) * u64::from(bytes)
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
        hint: usize,
    ) -> bool {
        let (dbytes, dformat, dstride, dwidth, dheight) = dst;
        let (sbytes, sformat, sstride, swidth, sheight) = src;
        let (sx, sy, dx, dy) = at;
        if !shaped(
            dbytes.as_ptr() as usize,
            dbytes.len(),
            dstride,
            (dwidth, dheight),
            bytes_of(dformat),
        ) || !shaped(
            sbytes.as_ptr() as usize,
            sbytes.len(),
            sstride,
            (swidth, sheight),
            bytes_of(sformat),
        ) || !inside(sx, sy, size.0, size.1, swidth, sheight)
            || !inside(dx, dy, size.0, size.1, dwidth, dheight)
        {
            return false;
        }
        let Some(d) = images.image(
            Key {
                bytes: dbytes.as_mut_ptr() as usize,
                format: dformat,
                stride: dstride,
                width: dwidth,
                height: dheight,
            },
            DST_HINT,
        ) else {
            return false;
        };
        let Some(s) = images.image(
            Key {
                bytes: sbytes.as_ptr() as usize,
                format: sformat,
                stride: sstride,
                width: swidth,
                height: sheight,
            },
            src_hint(hint),
        ) else {
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

    /// The work band of `Mask::Product` and of `product`: an A8 surface of WORK_H
    /// lines of WORK_W bytes, in the program's own memory (the service has one
    /// thread; `Mask::Product` uses the band inside one call, `product` and
    /// `Mask::Work` in two steps of a band, with nothing else made between them).
    struct Work(core::cell::UnsafeCell<[u32; (WORK_W * WORK_H / 4) as usize]>);

    // SAFETY: the band is touched only inside `element` and `product`, by the
    // one thread of the service.
    unsafe impl Sync for Work {}

    static WORK: Work = Work(core::cell::UnsafeCell::new(
        [0; (WORK_W * WORK_H / 4) as usize],
    ));

    /// What a transformed source is drawn with: the map from the target's
    /// points to the source's, how it is sampled, and the mask.
    pub struct Spec<'a> {
        pub over: bool,
        pub matrix: Option<Matrix>,
        /// Where the area's first point is in the source when there is no matrix.
        pub from: (u32, u32),
        pub filter: Filter,
        pub mask: Mask<'a>,
    }

    /// A mask image made for one call, dropped after it.
    struct Made(*mut c_void);

    impl Drop for Made {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: made by pixman, dropped once.
                unsafe { pixman_image_unref(self.0) };
            }
        }
    }

    /// `composite`, with a source that is drawn through `spec.matrix` (the map
    /// of the target's points to the source's: pixman applies it to the centre
    /// of each point of the area), sampled as `spec.filter` says, and with
    /// the mask. The points outside the source are its edge's. The area is
    /// the `size` points at `at` of the target; the transform takes the
    /// target's own coordinates. False, with nothing drawn, when a surface is
    /// not what its bytes hold, the area is not inside the target, the work
    /// band is too small for the mask, or pixman could not make an image.
    pub fn element(
        images: &mut Images,
        dst: (&mut [u8], Format, u32, u32, u32),
        src: (&[u8], Format, u32, u32, u32),
        hint: usize,
        spec: &Spec<'_>,
        at: (u32, u32),
        size: (u32, u32),
    ) -> bool {
        let (dbytes, dformat, dstride, dwidth, dheight) = dst;
        let (sbytes, sformat, sstride, swidth, sheight) = src;
        if !shaped(
            dbytes.as_ptr() as usize,
            dbytes.len(),
            dstride,
            (dwidth, dheight),
            bytes_of(dformat),
        ) || !shaped(
            sbytes.as_ptr() as usize,
            sbytes.len(),
            sstride,
            (swidth, sheight),
            bytes_of(sformat),
        ) || !inside(at.0, at.1, size.0, size.1, dwidth, dheight)
        {
            return false;
        }
        let Some(d) = images.image(
            Key {
                bytes: dbytes.as_mut_ptr() as usize,
                format: dformat,
                stride: dstride,
                width: dwidth,
                height: dheight,
            },
            DST_HINT,
        ) else {
            return false;
        };
        let Some(s) = images.image(
            Key {
                bytes: sbytes.as_ptr() as usize,
                format: sformat,
                stride: sstride,
                width: swidth,
                height: sheight,
            },
            src_hint(hint),
        ) else {
            return false;
        };
        // The mask: an image, and where its first point is.
        let mut mask_at = (0, 0);
        let mut owned = Made(core::ptr::null_mut());
        let mut plane = core::ptr::null_mut();
        match spec.mask {
            Mask::None => {}
            Mask::Alpha(a) => {
                let alpha = u16::from(a) * 257;
                let color = [0u16, 0, 0, alpha];
                // SAFETY: the colour is read in the call.
                owned = Made(unsafe { pixman_image_create_solid_fill(&color) });
                if owned.0.is_null() {
                    return false;
                }
            }
            Mask::Work => {
                let Some(m) = images.work_image() else {
                    return false;
                };
                plane = m;
                mask_at = (0, 0);
            }
            Mask::Plane { source, at } | Mask::Product { source, at, .. } => {
                if source.format != Format::A8
                    || !shaped(
                        source.bytes.as_ptr() as usize,
                        source.bytes.len(),
                        source.stride,
                        (source.width, source.height),
                        1,
                    )
                    || !inside(at.0, at.1, size.0, size.1, source.width, source.height)
                {
                    return false;
                }
                let Some(m) = images.image(
                    Key {
                        bytes: source.bytes.as_ptr() as usize,
                        format: Format::A8,
                        stride: source.stride,
                        width: source.width,
                        height: source.height,
                    },
                    src_hint(source.hint),
                ) else {
                    return false;
                };
                plane = m;
                mask_at = at;
            }
        }
        if let Mask::Product { alpha, .. } = spec.mask {
            if size.0 > WORK_W || size.1 > WORK_H {
                return false;
            }
            // SAFETY: the band is this call's alone (see `Work`); it is
            // WORK_W bytes a line, and the image covers `size` of it.
            owned = Made(unsafe {
                pixman_image_create_bits(
                    A8,
                    size.0 as i32,
                    size.1 as i32,
                    WORK.0.get().cast::<u32>(),
                    WORK_W as i32,
                )
            });
            let color = [0u16, 0, 0, u16::from(alpha) * 257];
            // SAFETY: the colour is read in the call.
            let solid = Made(unsafe { pixman_image_create_solid_fill(&color) });
            if owned.0.is_null() || solid.0.is_null() {
                return false;
            }
            // The alpha times the mask, in the work band: the colour is nothing
            // (an A8 target keeps the alpha of what SRC makes).
            // SAFETY: images made above; the rectangle is inside the band's.
            unsafe {
                pixman_image_composite32(
                    OP_SRC,
                    solid.0,
                    plane,
                    owned.0,
                    0,
                    0,
                    mask_at.0 as i32,
                    mask_at.1 as i32,
                    0,
                    0,
                    size.0 as i32,
                    size.1 as i32,
                );
            }
            plane = owned.0;
            mask_at = (0, 0);
        } else if !owned.0.is_null() {
            plane = owned.0;
        }
        if let Some([a, b, c, e, f, g]) = spec.matrix {
            let matrix = [[a, b, c], [e, f, g], [0, 0, 1 << 16]];
            // SAFETY: the image is pixman's; the matrix is copied.
            unsafe {
                pixman_image_set_transform(s, &matrix);
                pixman_image_set_filter(
                    s,
                    match spec.filter {
                        Filter::Nearest => FILTER_NEAREST,
                        Filter::Bilinear => FILTER_BILINEAR,
                    },
                    core::ptr::null(),
                    0,
                );
                pixman_image_set_repeat(s, REPEAT_PAD);
            }
        }
        // The transform takes the target's own coordinates; with none, the
        // source's first point of the area is `spec.from`.
        let from = if spec.matrix.is_some() { at } else { spec.from };
        // SAFETY: the images wrap memory the checks above show holds the
        // surfaces, which outlives the call; the area is inside the target.
        unsafe {
            pixman_image_composite32(
                if spec.over { OP_OVER } else { OP_SRC },
                s,
                plane,
                d,
                from.0 as i32,
                from.1 as i32,
                mask_at.0 as i32,
                mask_at.1 as i32,
                at.0 as i32,
                at.1 as i32,
                size.0 as i32,
                size.1 as i32,
            );
            if spec.matrix.is_some() {
                // The image is kept: the next plain drawing finds it as it was.
                pixman_image_set_transform(s, core::ptr::null());
                pixman_image_set_filter(s, FILTER_GOOD, core::ptr::null(), 0);
                pixman_image_set_repeat(s, REPEAT_NONE);
            }
        }
        true
    }

    /// The first step of a stretched element with a mask and an alpha: the mask
    /// (`size` points from `at` of the A8 surface `mask`) times `alpha` goes to the
    /// work band at its corner (pixman's SRC of a solid colour through the mask), for
    /// `Mask::Work` to read. False, with nothing made, when the surface is not what
    /// its bytes hold, the area is not inside it, the band is too small, or pixman
    /// could not make an image.
    pub fn product(
        images: &mut Images,
        mask: (&[u8], u32, u32, u32, usize),
        at: (u32, u32),
        alpha: u8,
        size: (u32, u32),
    ) -> bool {
        let (bytes, stride, width, height, hint) = mask;
        if size.0 > WORK_W
            || size.1 > WORK_H
            || !shaped(
                bytes.as_ptr() as usize,
                bytes.len(),
                stride,
                (width, height),
                1,
            )
            || !inside(at.0, at.1, size.0, size.1, width, height)
        {
            return false;
        }
        let Some(m) = images.image(
            Key {
                bytes: bytes.as_ptr() as usize,
                format: Format::A8,
                stride,
                width,
                height,
            },
            src_hint(hint),
        ) else {
            return false;
        };
        let Some(work) = images.work_image() else {
            return false;
        };
        let color = [0u16, 0, 0, u16::from(alpha) * 257];
        // SAFETY: the colour is read in the call.
        let solid = Made(unsafe { pixman_image_create_solid_fill(&color) });
        if solid.0.is_null() {
            return false;
        }
        // SAFETY: images made above; the rectangle is inside the band's.
        unsafe {
            pixman_image_composite32(
                OP_SRC,
                solid.0,
                m,
                work,
                0,
                0,
                at.0 as i32,
                at.1 as i32,
                0,
                0,
                size.0 as i32,
                size.1 as i32,
            );
        }
        true
    }

    /// The image of a source surface is made (when the table does not keep
    /// it), so that the first operation that reads it, in a band, does not
    /// pay for it. False when the surface is not what its bytes hold or
    /// pixman refuses.
    pub fn prepare(images: &mut Images, src: (&[u8], Format, u32, u32, u32), hint: usize) -> bool {
        let (sbytes, sformat, sstride, swidth, sheight) = src;
        if !shaped(
            sbytes.as_ptr() as usize,
            sbytes.len(),
            sstride,
            (swidth, sheight),
            bytes_of(sformat),
        ) {
            return false;
        }
        images
            .image(
                Key {
                    bytes: sbytes.as_ptr() as usize,
                    format: sformat,
                    stride: sstride,
                    width: swidth,
                    height: sheight,
                },
                src_hint(hint),
            )
            .is_some()
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
        if !shaped(dst.as_ptr() as usize, dst.len(), stride, (width, height), 4)
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
use imp::Spec;
#[cfg(target_os = "none")]
pub use imp::{HINTS, Images, KEPT, NO_HINT};

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
    /// The surface's number in the caller's own naming, from 0 to `HINTS` - 2 (or
    /// `NO_HINT`): the table of images remembers where it found the image of the
    /// surface, and a later lookup is one comparison.
    pub hint: usize,
}

#[cfg(target_os = "none")]
/// What a drawing is multiplied by, besides the source's own alpha.
#[derive(Clone, Copy)]
pub enum Mask<'a> {
    None,
    /// One alpha for every point, 0 to 255.
    Alpha(u8),
    /// An A8 surface, whose point at `at` goes with the first point drawn.
    Plane {
        source: Source<'a>,
        at: (u32, u32),
    },
    /// The work band as the first step (`product`) made it: the mask of an
    /// element whose mask and alpha were multiplied before.
    Work,
    /// The A8 surface times an alpha, made in the work band (at most `WORK_W`
    /// by `WORK_H` points).
    Product {
        source: Source<'a>,
        at: (u32, u32),
        alpha: u8,
    },
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
        src.hint,
    )
}

/// The first step of a stretched element with a mask and an alpha (`Mask::Work` is
/// the second): the A8 `mask`'s `size` points from `at` times `alpha` go to the
/// work band. False, with nothing made, when the mask is not what its bytes hold,
/// the area is not inside it, or the band is too small.
#[cfg(target_os = "none")]
pub fn product(
    images: &mut Images,
    mask: Source<'_>,
    at: (u32, u32),
    alpha: u8,
    size: (u32, u32),
) -> bool {
    if mask.format != Format::A8 {
        return false;
    }
    imp::product(
        images,
        (mask.bytes, mask.stride, mask.width, mask.height, mask.hint),
        at,
        alpha,
        size,
    )
}

/// The calling thread becomes the worker's: from here on the state pixman keeps
/// between calls (the arena it allocates from, the cache of the paths it found) is
/// the worker's own, and the thread shares none that a call writes with the
/// thread that made the tables (ports/pixman/shim.c). Called once, by the worker,
/// before its first call of pixman.
#[cfg(target_os = "none")]
pub fn worker_enter() {
    unsafe extern "C" {
        fn pxs_worker_enter();
    }
    // SAFETY: the function sets TPIDR_EL0 of the calling thread, which nothing
    // else of the service reads.
    unsafe { pxs_worker_enter() }
}

/// The image over the work band (`product`, `Mask::Work`) is made now and kept,
/// so that no band pays for it. False when pixman refuses.
#[cfg(target_os = "none")]
pub fn prepare_work(images: &mut Images) -> bool {
    images.work_image().is_some()
}

/// The image of `src` is made now when the table does not keep it (see
/// `Images::image`): the cost of a surface's first use goes where the
/// caller puts it. False when the surface is not what its bytes hold.
#[cfg(target_os = "none")]
pub fn prepare(images: &mut Images, src: Source<'_>) -> bool {
    imp::prepare(
        images,
        (src.bytes, src.format, src.stride, src.width, src.height),
        src.hint,
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

/// The `w` by `h` points at (`x`, `y`) of `dst` take `src` drawn through
/// `matrix` (the map of the target's points, by their centres, to the
/// source's, 16.16; None for the source's points as they are, the point at
/// `from` of the source going to (`x`, `y`)), sampled by `filter`, with
/// `mask`: replacing what is there, or, with `over`, laid over it
/// (premultiplied). The points of the source outside it are its edge's. A
/// source of XRGB8888 is opaque, and an ARGB8888 one has the alpha it says.
/// False, with nothing drawn, when a surface is not what its bytes hold, the
/// area is not inside the target, or pixman could not make its images.
#[cfg(target_os = "none")]
#[allow(clippy::too_many_arguments)]
pub fn composite_element(
    images: &mut Images,
    over: bool,
    dst: &mut Target<'_>,
    src: Source<'_>,
    matrix: Option<Matrix>,
    from: (u32, u32),
    filter: Filter,
    mask: Mask<'_>,
    (x, y): (u32, u32),
    (w, h): (u32, u32),
) -> bool {
    imp::element(
        images,
        (dst.bytes, dst.format, dst.stride, dst.width, dst.height),
        (src.bytes, src.format, src.stride, src.width, src.height),
        src.hint,
        &Spec {
            over,
            matrix,
            from,
            filter,
            mask,
        },
        (x, y),
        (w, h),
    )
}
