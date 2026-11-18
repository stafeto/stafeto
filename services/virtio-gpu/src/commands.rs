// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The commands of the Virtio GPU in 2D mode (Virtio 1.2, 5.7.6) the
//! service sends over the control queue, and the parts of the answers it
//! reads. Each command is a header of 24 bytes and its body, all numbers
//! low byte first, written into the buffer the device reads; the answer
//! is a header (`OK_NODATA`), or for GET_DISPLAY_INFO the header and 16
//! modes. The service uses six commands of the control queue, no 3D, and
//! the two commands of the cursor queue (Virtio 1.3, 5.7.6.10), whose chain
//! the device returns with no answer at all.

use proto_gpu::Rect;

/// The bytes of the header of a command and of an answer without data.
pub const HEADER: usize = 24;
/// The bytes of the longest command: TRANSFER_TO_HOST_2D, and the two
/// commands of the cursor queue, `struct virtio_gpu_update_cursor`
/// (Virtio 1.3, 5.7.6.10: the header, `pos` of 16 bytes, `resource_id`,
/// `hot_x`, `hot_y`, a padding word).
pub const COMMAND_MAX: usize = 56;
/// The bytes of a command of the cursor queue.
pub const CURSOR_COMMAND: usize = 56;
/// The bytes of the answer to GET_DISPLAY_INFO: the header and 16 modes of
/// 24 bytes.
pub const INFO_REPLY: usize = HEADER + 16 * 24;

/// The types of the commands.
pub const GET_DISPLAY_INFO: u32 = 0x0100;
pub const RESOURCE_CREATE_2D: u32 = 0x0101;
pub const SET_SCANOUT: u32 = 0x0103;
pub const RESOURCE_FLUSH: u32 = 0x0104;
pub const TRANSFER_TO_HOST_2D: u32 = 0x0105;
pub const RESOURCE_ATTACH_BACKING: u32 = 0x0106;
/// The commands of the cursor queue (Virtio 1.3, 5.7.2 and 5.7.6.10).
pub const CMD_UPDATE_CURSOR: u32 = 0x0300;
pub const CMD_MOVE_CURSOR: u32 = 0x0301;

/// The types of the answers: success without and with data. Every type
/// from 0x1200 is an error.
pub const OK_NODATA: u32 = 0x1100;
pub const OK_DISPLAY_INFO: u32 = 0x1101;
pub const ERR_FROM: u32 = 0x1200;

/// The format of the resource, B8G8R8X8_UNORM: the bytes B, G, R, X in
/// memory, the word 0x00RRGGBB.
pub const FORMAT_B8G8R8X8: u32 = 2;
/// The format of the cursor's picture, B8G8R8A8_UNORM: the bytes B, G, R,
/// A in memory, the word 0xAARRGGBB.
pub const FORMAT_B8G8R8A8: u32 = 1;
/// The flag of a request header that asks the device to finish the
/// command before it answers the next ones of the queue (Virtio 1.3,
/// 5.7.6.5); the answer carries it and the `fence_id` back.
pub const FLAG_FENCE: u32 = 1;
/// The resource of the screen, and the one scanout of the device.
pub const RESOURCE: u32 = 1;
pub const SCANOUT: u32 = 0;
/// The resource ID that takes a scanout off.
pub const NO_RESOURCE: u32 = 0;

/// Writes `value` at byte `at` of `out`, low byte first.
fn put(out: &mut [u8], at: usize, value: u64, bytes: usize) {
    out[at..at + bytes].copy_from_slice(&value.to_le_bytes()[..bytes]);
}

/// The header of a command: the type, and zero flags, fence, context and
/// ring. The rest of the `len` bytes of the buffer is zeroed, so that no
/// byte of an earlier command stays in a padding the device reads.
fn header(out: &mut [u8], kind: u32, len: usize) {
    out[..len].fill(0);
    put(out, 0, u64::from(kind), 4);
}

/// The rectangle of a command at byte `at`: x, y, width, height.
fn rect(out: &mut [u8], at: usize, r: &Rect) {
    put(out, at, u64::from(r.x), 4);
    put(out, at + 4, u64::from(r.y), 4);
    put(out, at + 8, u64::from(r.w), 4);
    put(out, at + 12, u64::from(r.h), 4);
}

/// GET_DISPLAY_INFO: the header alone. Returns the bytes written.
pub fn get_display_info(out: &mut [u8]) -> usize {
    header(out, GET_DISPLAY_INFO, HEADER);
    HEADER
}

/// RESOURCE_CREATE_2D: the ID, the format and the size in points.
pub fn resource_create_2d(out: &mut [u8], id: u32, format: u32, width: u32, height: u32) -> usize {
    header(out, RESOURCE_CREATE_2D, HEADER + 16);
    put(out, 24, u64::from(id), 4);
    put(out, 28, u64::from(format), 4);
    put(out, 32, u64::from(width), 4);
    put(out, 36, u64::from(height), 4);
    HEADER + 16
}

/// RESOURCE_ATTACH_BACKING with one entry: the resource's memory is the
/// `len` bytes at the physical address `addr`. The command and the entry
/// lie together, one buffer of 48 bytes.
pub fn attach_backing(out: &mut [u8], id: u32, addr: u64, len: u32) -> usize {
    header(out, RESOURCE_ATTACH_BACKING, HEADER + 8 + 16);
    put(out, 24, u64::from(id), 4);
    put(out, 28, 1, 4);
    put(out, 32, addr, 8);
    put(out, 40, u64::from(len), 4);
    HEADER + 8 + 16
}

/// SET_SCANOUT: scanout `scanout` shows the rectangle `r` of resource
/// `resource`; the resource 0 turns the scanout off.
pub fn set_scanout(out: &mut [u8], r: &Rect, scanout: u32, resource: u32) -> usize {
    header(out, SET_SCANOUT, HEADER + 24);
    rect(out, 24, r);
    put(out, 40, u64::from(scanout), 4);
    put(out, 44, u64::from(resource), 4);
    HEADER + 24
}

/// TRANSFER_TO_HOST_2D: the host copies the rectangle `r` of resource
/// `resource` from the guest's memory. `offset` is where in the resource's
/// backing the rectangle's first point lies, `y * stride + x * 4`, from
/// which the host reads each line `stride` bytes after the last.
pub fn transfer_to_host_2d(out: &mut [u8], r: &Rect, resource: u32) -> usize {
    header(out, TRANSFER_TO_HOST_2D, COMMAND_MAX);
    rect(out, 24, r);
    put(out, 40, r.offset(), 8);
    put(out, 48, u64::from(resource), 4);
    COMMAND_MAX
}

/// TRANSFER_TO_HOST_2D of the rectangle `r` of resource `resource` whose
/// backing has a stride of `stride` bytes, with the fence flag and
/// `fence_id` in the header: the device finishes the transfer before it
/// takes the next command (Virtio 1.3, 5.7.6.5), which a cursor's picture
/// needs before UPDATE_CURSOR (5.7.6.6).
pub fn transfer_fenced(
    out: &mut [u8],
    r: &Rect,
    stride: u32,
    resource: u32,
    fence_id: u64,
) -> usize {
    header(out, TRANSFER_TO_HOST_2D, COMMAND_MAX);
    put(out, 4, u64::from(FLAG_FENCE), 4);
    put(out, 8, fence_id, 8);
    rect(out, 24, r);
    put(
        out,
        40,
        u64::from(r.y) * u64::from(stride) + u64::from(r.x) * 4,
        8,
    );
    put(out, 48, u64::from(resource), 4);
    COMMAND_MAX
}

/// The command of the cursor queue, `struct virtio_gpu_update_cursor`
/// (Virtio 1.3, 5.7.6.10): the header, `pos` (`scanout_id`, `x`, `y`, a
/// padding word, bytes 24 to 39), `resource_id` (40), `hot_x` (44),
/// `hot_y` (48) and a padding word (52).
fn cursor_command(
    out: &mut [u8],
    kind: u32,
    (x, y): (u32, u32),
    resource: u32,
    (hot_x, hot_y): (u32, u32),
) -> usize {
    header(out, kind, CURSOR_COMMAND);
    put(out, 24, u64::from(SCANOUT), 4);
    put(out, 28, u64::from(x), 4);
    put(out, 32, u64::from(y), 4);
    put(out, 40, u64::from(resource), 4);
    put(out, 44, u64::from(hot_x), 4);
    put(out, 48, u64::from(hot_y), 4);
    CURSOR_COMMAND
}

/// UPDATE_CURSOR: the cursor takes its picture from `resource` (0 turns
/// the cursor off), whose hot spot is at (`hot_x`, `hot_y`), and moves to
/// `pos`.
pub fn update_cursor(out: &mut [u8], pos: (u32, u32), resource: u32, hot: (u32, u32)) -> usize {
    cursor_command(out, CMD_UPDATE_CURSOR, pos, resource, hot)
}

/// MOVE_CURSOR: the cursor moves to `pos`. The specification says the
/// other fields are ignored, but QEMU ends every cursor command, a move
/// too, with `qemu_console_set_mouse(.., x, y, resource_id)`, whose last
/// argument turns the pointer on or off: a move that carries resource 0
/// hides the cursor. A move therefore carries the resource of the picture
/// the cursor shows, as the Linux driver's does.
pub fn move_cursor(out: &mut [u8], pos: (u32, u32), resource: u32) -> usize {
    cursor_command(out, CMD_MOVE_CURSOR, pos, resource, (0, 0))
}

/// RESOURCE_FLUSH: the host shows the rectangle `r` of resource
/// `resource`.
pub fn resource_flush(out: &mut [u8], r: &Rect, resource: u32) -> usize {
    header(out, RESOURCE_FLUSH, HEADER + 24);
    rect(out, 24, r);
    put(out, 40, u64::from(resource), 4);
    HEADER + 24
}

/// The type of an answer, the first word of its header.
pub fn answer_type(answer: &[u8]) -> u32 {
    answer
        .get(..4)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

/// Whether an answer of type `kind` and `len` bytes (as far as the device
/// wrote) is the success of its command: OK_DISPLAY_INFO with the first
/// mode for GET_DISPLAY_INFO (`info`), OK_NODATA with a whole header for
/// any other.
pub fn succeeded(kind: u32, len: usize, info: bool) -> bool {
    if info {
        kind == OK_DISPLAY_INFO && len >= HEADER + 24
    } else {
        kind == OK_NODATA && len >= HEADER
    }
}

/// The mode of the first scanout of an answer to GET_DISPLAY_INFO: its
/// width and height and whether it is enabled; None unless the answer is
/// OK_DISPLAY_INFO and long enough. The service only logs it.
pub fn first_mode(answer: &[u8]) -> Option<(u32, u32, bool)> {
    if answer_type(answer) != OK_DISPLAY_INFO || answer.len() < HEADER + 24 {
        return None;
    }
    let word = |at: usize| {
        answer
            .get(at..at + 4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
    };
    Some((
        word(HEADER + 8)?,
        word(HEADER + 12)?,
        word(HEADER + 16)? != 0,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"))
    }

    fn quad(b: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(b[at..at + 8].try_into().expect("8 bytes"))
    }

    #[test]
    fn the_command_numbers_are_the_specs() {
        assert_eq!(GET_DISPLAY_INFO, 0x0100);
        assert_eq!(RESOURCE_CREATE_2D, 0x0101);
        assert_eq!(SET_SCANOUT, 0x0103);
        assert_eq!(RESOURCE_FLUSH, 0x0104);
        assert_eq!(TRANSFER_TO_HOST_2D, 0x0105);
        assert_eq!(RESOURCE_ATTACH_BACKING, 0x0106);
        assert_eq!(OK_NODATA, 0x1100);
        assert_eq!(OK_DISPLAY_INFO, 0x1101);
    }

    #[test]
    fn the_cursor_command_numbers_are_the_specs() {
        assert_eq!(CMD_UPDATE_CURSOR, 0x0300);
        assert_eq!(CMD_MOVE_CURSOR, 0x0301);
        assert_eq!(FORMAT_B8G8R8A8, 1);
        assert_eq!(FLAG_FENCE, 1);
        assert_eq!(CURSOR_COMMAND, 56);
    }

    #[test]
    fn update_cursor_has_the_layout_of_the_spec() {
        // Virtio 1.3, 5.7.6.10: hdr 0..24, pos.scanout_id 24, pos.x 28,
        // pos.y 32, pos.padding 36, resource_id 40, hot_x 44, hot_y 48,
        // padding 52.
        let mut b = [0xFF; COMMAND_MAX];
        assert_eq!(update_cursor(&mut b, (100, 200), 3, (7, 9)), 56);
        assert_eq!(word(&b, 0), 0x0300);
        assert!(b[4..24].iter().all(|&x| x == 0), "flags, fence, ctx, ring");
        assert_eq!(word(&b, 24), 0, "scanout_id");
        assert_eq!(word(&b, 28), 100, "pos.x");
        assert_eq!(word(&b, 32), 200, "pos.y");
        assert_eq!(word(&b, 36), 0, "pos.padding");
        assert_eq!(word(&b, 40), 3, "resource_id");
        assert_eq!(word(&b, 44), 7, "hot_x");
        assert_eq!(word(&b, 48), 9, "hot_y");
        assert_eq!(word(&b, 52), 0, "padding");
    }

    #[test]
    fn move_cursor_has_the_place_and_the_resource_of_the_picture() {
        let mut b = [0xFF; COMMAND_MAX];
        assert_eq!(move_cursor(&mut b, (639, 399), 3), 56);
        assert_eq!(word(&b, 0), 0x0301);
        assert_eq!([word(&b, 28), word(&b, 32)], [639, 399]);
        // QEMU turns the pointer on or off by the resource of every cursor
        // command: a move with resource 0 would hide it.
        assert_eq!(word(&b, 40), 3, "resource_id");
        assert!(b[44..56].iter().all(|&x| x == 0));
        // A turn off is an UPDATE with resource 0.
        update_cursor(&mut b, (0, 0), 0, (0, 0));
        assert_eq!(word(&b, 40), 0);
    }

    #[test]
    fn a_fenced_transfer_has_the_flag_and_the_id_in_its_header() {
        let mut b = [0xFF; COMMAND_MAX];
        let r = Rect {
            x: 0,
            y: 0,
            w: 64,
            h: 64,
        };
        assert_eq!(
            transfer_fenced(&mut b, &r, 256, 3, 0x1122_3344_5566_7788),
            56
        );
        assert_eq!(word(&b, 0), 0x0105);
        assert_eq!(word(&b, 4), 1, "flags: FENCE");
        assert_eq!(quad(&b, 8), 0x1122_3344_5566_7788, "fence_id");
        assert_eq!(word(&b, 16), 0, "ctx_id");
        assert_eq!([word(&b, 32), word(&b, 36)], [64, 64]);
        assert_eq!(quad(&b, 40), 0);
        assert_eq!(word(&b, 48), 3);
        // The stride of the resource's own backing gives the offset.
        let inner = Rect {
            x: 2,
            y: 3,
            w: 1,
            h: 1,
        };
        transfer_fenced(&mut b, &inner, 256, 3, 1);
        assert_eq!(quad(&b, 40), 3 * 256 + 8);
        // The plain transfer has no fence.
        transfer_to_host_2d(&mut b, &Rect::SCREEN, RESOURCE);
        assert_eq!(word(&b, 4), 0);
        assert_eq!(quad(&b, 8), 0);
    }

    #[test]
    fn a_header_is_24_bytes_with_the_type_alone() {
        let mut b = [0xFF; COMMAND_MAX];
        assert_eq!(get_display_info(&mut b), 24);
        assert_eq!(word(&b, 0), 0x0100);
        assert!(b[4..24].iter().all(|&x| x == 0));
        // The bytes past the command are not touched.
        assert!(b[24..].iter().all(|&x| x == 0xFF));
    }

    #[test]
    fn create_carries_id_format_and_size() {
        let mut b = [0xFF; COMMAND_MAX];
        assert_eq!(resource_create_2d(&mut b, 1, FORMAT_B8G8R8X8, 640, 400), 40);
        assert_eq!(word(&b, 0), 0x0101);
        assert_eq!(
            [word(&b, 24), word(&b, 28), word(&b, 32), word(&b, 36)],
            [1, 2, 640, 400]
        );
    }

    #[test]
    fn attach_has_one_entry_after_the_command() {
        let mut b = [0xFF; COMMAND_MAX];
        assert_eq!(attach_backing(&mut b, 1, 0x4010_0000, 1_024_000), 48);
        assert_eq!(word(&b, 0), 0x0106);
        assert_eq!(word(&b, 24), 1, "resource");
        assert_eq!(word(&b, 28), 1, "one entry");
        assert_eq!(quad(&b, 32), 0x4010_0000, "address");
        assert_eq!(word(&b, 40), 1_024_000, "length");
        assert_eq!(word(&b, 44), 0, "padding");
    }

    #[test]
    fn scanout_names_the_rectangle_the_scanout_and_the_resource() {
        let mut b = [0xFF; COMMAND_MAX];
        assert_eq!(set_scanout(&mut b, &Rect::SCREEN, SCANOUT, RESOURCE), 48);
        assert_eq!(word(&b, 0), 0x0103);
        assert_eq!(
            [word(&b, 24), word(&b, 28), word(&b, 32), word(&b, 36)],
            [0, 0, 640, 400]
        );
        assert_eq!([word(&b, 40), word(&b, 44)], [0, 1]);
        set_scanout(&mut b, &Rect::SCREEN, SCANOUT, NO_RESOURCE);
        assert_eq!(word(&b, 44), 0, "resource 0 takes the scanout off");
    }

    #[test]
    fn transfer_offsets_are_y_stride_plus_x_4() {
        let mut b = [0xFF; COMMAND_MAX];
        let corners_and_middle = [
            (Rect::SCREEN, 0),
            (
                Rect {
                    x: 639,
                    y: 0,
                    w: 1,
                    h: 1,
                },
                2556,
            ),
            (
                Rect {
                    x: 0,
                    y: 399,
                    w: 1,
                    h: 1,
                },
                399 * 2560,
            ),
            (
                Rect {
                    x: 639,
                    y: 399,
                    w: 1,
                    h: 1,
                },
                1_024_000 - 4,
            ),
            (
                Rect {
                    x: 320,
                    y: 200,
                    w: 10,
                    h: 10,
                },
                200 * 2560 + 320 * 4,
            ),
            (
                Rect {
                    x: 100,
                    y: 50,
                    w: 200,
                    h: 100,
                },
                50 * 2560 + 400,
            ),
        ];
        for (r, offset) in corners_and_middle {
            assert_eq!(transfer_to_host_2d(&mut b, &r, RESOURCE), 56);
            assert_eq!(word(&b, 0), 0x0105);
            assert_eq!(
                [word(&b, 24), word(&b, 28), word(&b, 32), word(&b, 36)],
                [r.x, r.y, r.w, r.h]
            );
            assert_eq!(quad(&b, 40), offset, "{r:?}");
            assert_eq!(word(&b, 48), 1);
            assert_eq!(word(&b, 52), 0);
        }
    }

    #[test]
    fn flush_names_the_rectangle_and_the_resource() {
        let mut b = [0xFF; COMMAND_MAX];
        let r = Rect {
            x: 1,
            y: 2,
            w: 3,
            h: 4,
        };
        assert_eq!(resource_flush(&mut b, &r, RESOURCE), 48);
        assert_eq!(word(&b, 0), 0x0104);
        assert_eq!(
            [word(&b, 24), word(&b, 28), word(&b, 32), word(&b, 36)],
            [1, 2, 3, 4]
        );
        assert_eq!([word(&b, 40), word(&b, 44)], [1, 0]);
    }

    #[test]
    fn a_command_clears_what_an_earlier_one_left() {
        let mut b = [0xFF; COMMAND_MAX];
        transfer_to_host_2d(&mut b, &Rect::SCREEN, RESOURCE);
        resource_flush(&mut b, &Rect::SCREEN, RESOURCE);
        // The padding of FLUSH, which TRANSFER wrote an offset into; the
        // device reads 48 bytes of it and no more.
        assert!(b[44..48].iter().all(|&x| x == 0));
    }

    #[test]
    fn answers_are_judged_by_their_type() {
        assert!(succeeded(OK_NODATA, HEADER, false));
        assert!(succeeded(OK_DISPLAY_INFO, INFO_REPLY, true));
        assert!(!succeeded(0, HEADER, false) && !succeeded(ERR_FROM, HEADER, false));
        assert!(!succeeded(0x1203, HEADER, false));
        // The type must be the command's, and the answer long enough.
        assert!(!succeeded(OK_DISPLAY_INFO, INFO_REPLY, false));
        assert!(!succeeded(OK_NODATA, HEADER, true));
        assert!(!succeeded(OK_NODATA, HEADER - 1, false));
        assert!(!succeeded(OK_DISPLAY_INFO, HEADER + 23, true));
        assert_eq!(answer_type(&OK_NODATA.to_le_bytes()), OK_NODATA);
        assert_eq!(answer_type(&[1, 2]), 0);
    }

    #[test]
    fn the_first_mode_is_read_from_the_info() {
        let mut a = [0; INFO_REPLY];
        a[..4].copy_from_slice(&OK_DISPLAY_INFO.to_le_bytes());
        a[32..36].copy_from_slice(&640u32.to_le_bytes());
        a[36..40].copy_from_slice(&400u32.to_le_bytes());
        a[40..44].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(first_mode(&a), Some((640, 400, true)));
        assert_eq!(first_mode(&a[..40]), None);
        a[..4].copy_from_slice(&OK_NODATA.to_le_bytes());
        assert_eq!(first_mode(&a), None);
    }
}
