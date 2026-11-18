// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What a LAYERS request makes the driver do (`proto_gpu` revision 3),
//! apart from the device and the calls: the work of a frame on the primary
//! pipeline (`frame`) and the machine of the cursor pipeline (`Cursor`).
//! The order of the device's commands is the point of both, and the host
//! tests pin it.
//!
//! A frame is up to three chains of the control queue added as one job.
//! The device handles the control queue in order and synchronously for
//! 2D (Virtio 1.3, 5.7.6.5), so a transfer of a new source, the scanout
//! switch and the flush that follow it show the new source with no blank
//! frame in between: the scanout never points at a resource whose host
//! image is stale.
//!
//! The cursor takes its points from the resource only on its update
//! command (5.7.6.6, 5.7.6.10), and the resource must be transferred first
//! with the fence flag, so the update waits for the answer to that
//! transfer. The cursor queue holds one chain at a time; a place that
//! comes while a chain is out waits, and only the last one is sent when the
//! chain returns.

use proto_gpu::Rect;

/// One command of a frame's work. The resource is the frame's source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// TRANSFER_TO_HOST_2D of the rectangle.
    Transfer(Rect),
    /// SET_SCANOUT of the whole screen to the source.
    Scanout,
    /// RESOURCE_FLUSH of the rectangle.
    Flush(Rect),
}

/// The work of a frame: up to three commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    /// The source the frame shows, which is the device's resource.
    pub source: u32,
    steps: [Step; 3],
    len: usize,
}

impl Frame {
    /// The commands in the order the device gets them.
    pub fn steps(&self) -> &[Step] {
        &self.steps[..self.len]
    }
}

/// The work of a frame that shows `source` when `bound` is what the
/// scanout shows now (0: not known). A new source is transferred whole
/// before the scanout switches to it, and the whole screen is flushed after
/// it: the area that changed does not matter, the host's image of the new
/// source may be stale. The bound source transfers and flushes the changed
/// `area` alone; with no changed area only the flush goes.
pub fn frame(bound: u32, source: u32, area: Option<Rect>) -> Frame {
    if bound != source {
        return Frame {
            source,
            steps: [
                Step::Transfer(Rect::SCREEN),
                Step::Scanout,
                Step::Flush(Rect::SCREEN),
            ],
            len: 3,
        };
    }
    match area {
        Some(area) => Frame {
            source,
            steps: [Step::Transfer(area), Step::Flush(area), Step::Scanout],
            len: 2,
        },
        None => Frame {
            source,
            steps: [Step::Flush(Rect::SCREEN), Step::Scanout, Step::Scanout],
            len: 1,
        },
    }
}

/// A command for the cursor queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Send {
    /// UPDATE_CURSOR: the picture of `resource` (0 hides the cursor), its
    /// hot spot, the place.
    Update {
        resource: u32,
        place: (u32, u32),
        hot: (u32, u32),
    },
    /// MOVE_CURSOR, with the resource of the picture the cursor shows: the
    /// device takes the resource of every cursor command as the pointer's
    /// on flag.
    Move { place: (u32, u32), resource: u32 },
}

/// A row of LAYERS for the cursor pipeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    /// The source; 0 hides the cursor.
    pub source: u32,
    pub place: (u32, u32),
    pub hot: (u32, u32),
    /// Whether points of the picture changed (`dw` is not 0).
    pub changed: bool,
}

/// Where the host's picture of the cursor stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Image {
    /// The host has the source's points as they are, or none is wanted.
    Current,
    /// A fenced transfer of the whole picture is due.
    Needed,
    /// The transfer is with the device.
    InFlight,
}

/// The cursor pipeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    /// The source of the latest row: 0 hidden.
    source: u32,
    place: (u32, u32),
    hot: (u32, u32),
    image: Image,
    /// A row asked for a transfer while one was with the device: when it
    /// returns, another is due.
    again: bool,
    /// An update with a resource other than 0 went out and no hide since.
    shown: bool,
    /// The host's picture is not known to be the source's: a transfer
    /// failed. The next row with that source makes a transfer due again.
    stale: bool,
    /// A chain is in the cursor queue.
    out: bool,
    /// The command that waits for the chain to return.
    next: Option<Send>,
}

impl Default for Cursor {
    fn default() -> Cursor {
        Cursor::new()
    }
}

impl Cursor {
    pub const fn new() -> Cursor {
        Cursor {
            source: 0,
            place: (0, 0),
            hot: (0, 0),
            image: Image::Current,
            again: false,
            shown: false,
            stale: false,
            out: false,
            next: None,
        }
    }

    /// Whether a chain is in the cursor queue.
    pub fn is_out(&self) -> bool {
        self.out
    }

    /// The command to send now, or None when the chain is out (the
    /// command waits, merged with what waits) or a send is not due.
    fn push(&mut self, send: Send) -> Option<Send> {
        if let Send::Update { resource, .. } = send {
            self.shown = resource != 0;
        }
        if !self.out {
            self.out = true;
            return Some(send);
        }
        self.next = Some(match (self.next, send) {
            // A move after an update that waits is the update at the new
            // place.
            (Some(Send::Update { resource, hot, .. }), Send::Move { place, .. }) => Send::Update {
                resource,
                place,
                hot,
            },
            (_, send) => send,
        });
        None
    }

    /// A LAYERS row for the cursor pipeline: the command to send now, if
    /// any. A new source, or points that changed, make a transfer due
    /// (`transfer_due`) and send nothing yet: the update goes only after the
    /// transfer returned (`transfer_done`). A place with nothing else is a
    /// move, or, while a transfer is due, a new place for the update that
    /// comes after it. Source 0 hides the cursor.
    pub fn row(&mut self, row: Row) -> Option<Send> {
        if row.source == 0 {
            self.source = 0;
            self.again = false;
            if self.image == Image::Needed {
                self.image = Image::Current;
            }
            return if self.shown {
                self.push(Send::Update {
                    resource: 0,
                    place: (0, 0),
                    hot: (0, 0),
                })
            } else {
                None
            };
        }
        let rebind = row.source != self.source || row.changed || self.stale;
        let hot_changed = row.hot != self.hot;
        self.source = row.source;
        self.place = row.place;
        self.hot = row.hot;
        if rebind {
            self.stale = false;
            match self.image {
                Image::InFlight => self.again = true,
                _ => self.image = Image::Needed,
            }
            return None;
        }
        if self.image != Image::Current {
            // The update after the transfer takes this place and hot spot.
            return None;
        }
        if hot_changed {
            // The device takes the hot spot only on an update: no points
            // changed, so no transfer.
            self.push(Send::Update {
                resource: row.source,
                place: row.place,
                hot: row.hot,
            })
        } else {
            self.push(Send::Move {
                place: row.place,
                resource: row.source,
            })
        }
    }

    /// The resource a fenced transfer is due for, if one is.
    pub fn transfer_due(&self) -> Option<u32> {
        (self.image == Image::Needed && self.source != 0).then_some(self.source)
    }

    /// The transfer went into the control queue.
    pub fn transfer_started(&mut self) {
        if self.image == Image::Needed {
            self.image = Image::InFlight;
        }
    }

    /// The device answered the transfer (`ok`: it did not fail): the update
    /// that shows the picture, to send now if the cursor queue is free.
    /// Nothing when a newer row made another transfer due, when the cursor
    /// was hidden meanwhile, or when the transfer failed.
    pub fn transfer_done(&mut self, ok: bool) -> Option<Send> {
        if self.image != Image::InFlight {
            return None;
        }
        self.image = Image::Current;
        if core::mem::take(&mut self.again) {
            self.image = Image::Needed;
            return None;
        }
        if !ok {
            // The host's picture is not the source's: the next row with this
            // source asks for the transfer again.
            self.stale = true;
            return None;
        }
        if self.source == 0 {
            return None;
        }
        self.push(Send::Update {
            resource: self.source,
            place: self.place,
            hot: self.hot,
        })
    }

    /// The device returned the chain of the cursor queue: the command that
    /// waited, to send now.
    pub fn chain_returned(&mut self) -> Option<Send> {
        self.out = false;
        let next = self.next.take()?;
        self.out = true;
        Some(next)
    }

    /// A send failed at the queue: nothing is out and nothing waits.
    pub fn abandoned(&mut self) {
        self.out = false;
        self.next = None;
    }

    /// The owner left: the cursor is hidden for the next one (the command
    /// to send, if the device shows it) and every row is forgotten. A
    /// transfer that is with the device returns to nothing.
    pub fn release(&mut self) -> Option<Send> {
        let was_shown = self.shown;
        let in_flight = self.image == Image::InFlight;
        // What waited for the chain is the old owner's: the hide replaces it.
        *self = Cursor {
            out: self.out,
            image: if in_flight {
                Image::InFlight
            } else {
                Image::Current
            },
            ..Cursor::new()
        };
        if was_shown {
            self.push(Send::Update {
                resource: 0,
                place: (0, 0),
                hot: (0, 0),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLACE: (u32, u32) = (100, 50);

    fn row(source: u32, place: (u32, u32), changed: bool) -> Row {
        Row {
            source,
            place,
            hot: (0, 0),
            changed,
        }
    }

    fn update(place: (u32, u32)) -> Send {
        Send::Update {
            resource: 3,
            place,
            hot: (0, 0),
        }
    }

    /// Binds source 3 and brings the machine to the shown cursor, the
    /// chain returned.
    fn shown() -> Cursor {
        let mut c = Cursor::new();
        assert_eq!(c.row(row(3, PLACE, false)), None);
        assert_eq!(c.transfer_due(), Some(3));
        c.transfer_started();
        assert_eq!(c.transfer_done(true), Some(update(PLACE)));
        assert_eq!(c.chain_returned(), None);
        c
    }

    #[test]
    fn a_new_source_is_three_chains_transfer_then_scanout_then_flush() {
        let f = frame(1, 2, Some(Rect::SCREEN));
        assert_eq!(f.source, 2);
        assert_eq!(
            f.steps(),
            [
                Step::Transfer(Rect::SCREEN),
                Step::Scanout,
                Step::Flush(Rect::SCREEN)
            ]
        );
        // The changed area does not matter to a new source.
        let small = Rect {
            x: 1,
            y: 2,
            w: 3,
            h: 4,
        };
        assert_eq!(frame(1, 2, Some(small)).steps(), f.steps());
        assert_eq!(frame(2, 1, None).steps().len(), 3);
        // A source that is not known (0) is a new source for any.
        assert_eq!(frame(0, 1, None).steps().len(), 3);
    }

    #[test]
    fn the_same_binding_is_two_chains_transfer_then_flush_of_the_area() {
        let area = Rect {
            x: 10,
            y: 20,
            w: 30,
            h: 40,
        };
        let f = frame(2, 2, Some(area));
        assert_eq!(f.steps(), [Step::Transfer(area), Step::Flush(area)]);
        // No scanout command in a frame of the bound source.
        assert!(!f.steps().contains(&Step::Scanout));
        // No changed area: the flush alone.
        assert_eq!(frame(1, 1, None).steps(), [Step::Flush(Rect::SCREEN)]);
    }

    #[test]
    fn a_move_while_the_cursor_queue_is_busy_merges_into_one() {
        let mut c = shown();
        // The first move goes out; the chain is out.
        assert_eq!(
            c.row(row(3, (1, 1), false)),
            Some(Send::Move {
                place: (1, 1),
                resource: 3
            })
        );
        assert!(c.is_out());
        // Three more wait and keep the last place alone.
        for place in [(2, 2), (3, 3), (4, 4)] {
            assert_eq!(c.row(row(3, place, false)), None);
        }
        assert_eq!(
            c.chain_returned(),
            Some(Send::Move {
                place: (4, 4),
                resource: 3
            })
        );
        // That one is out, nothing else waits.
        assert_eq!(c.chain_returned(), None);
        assert!(!c.is_out());
    }

    #[test]
    fn a_cursor_bound_before_its_transfer_returned_sends_no_update() {
        let mut c = Cursor::new();
        assert_eq!(c.row(row(3, PLACE, false)), None);
        // The transfer is due, queued, started: no update in all that time,
        // and a move only changes the place the update will have.
        assert_eq!(c.transfer_due(), Some(3));
        assert_eq!(c.row(row(3, (7, 8), false)), None);
        c.transfer_started();
        assert_eq!(c.transfer_due(), None);
        assert_eq!(c.row(row(3, (9, 10), false)), None);
        assert!(!c.is_out());
        // The update comes with the transfer's return, at the last place.
        assert_eq!(c.transfer_done(true), Some(update((9, 10))));
    }

    #[test]
    fn a_failed_transfer_or_a_hide_during_it_sends_no_update() {
        let mut c = Cursor::new();
        c.row(row(3, PLACE, false));
        c.transfer_started();
        assert_eq!(c.transfer_done(false), None);
        let mut c = Cursor::new();
        c.row(row(3, PLACE, false));
        c.transfer_started();
        assert_eq!(c.row(row(0, (0, 0), false)), None);
        assert_eq!(c.transfer_done(true), None);
    }

    #[test]
    fn changed_points_transfer_the_picture_again_before_the_update() {
        let mut c = shown();
        assert_eq!(c.row(row(3, PLACE, true)), None);
        assert_eq!(c.transfer_due(), Some(3));
        c.transfer_started();
        // A second change while the transfer is with the device makes
        // another one due, and the update waits for that one.
        assert_eq!(c.row(row(3, PLACE, true)), None);
        assert_eq!(c.transfer_done(true), None);
        assert_eq!(c.transfer_due(), Some(3));
        c.transfer_started();
        assert_eq!(c.transfer_done(true), Some(update(PLACE)));
    }

    #[test]
    fn an_update_that_waits_takes_the_newest_place() {
        let mut c = shown();
        assert_eq!(
            c.row(row(3, (1, 1), false)),
            Some(Send::Move {
                place: (1, 1),
                resource: 3
            })
        );
        c.row(row(3, PLACE, true));
        c.transfer_started();
        // The chain is still out when the transfer returns: the update waits,
        // a move merges into it.
        assert_eq!(c.transfer_done(true), None);
        assert_eq!(c.row(row(3, (5, 6), false)), None);
        assert_eq!(c.chain_returned(), Some(update((5, 6))));
    }

    #[test]
    fn source_zero_hides_and_a_hidden_cursor_hides_no_more() {
        let mut c = shown();
        let hide = Send::Update {
            resource: 0,
            place: (0, 0),
            hot: (0, 0),
        };
        assert_eq!(c.row(row(0, (0, 0), false)), Some(hide));
        assert_eq!(c.chain_returned(), None);
        assert_eq!(c.row(row(0, (0, 0), false)), None);
        assert!(!c.is_out());
    }

    #[test]
    fn the_owner_leaving_hides_the_cursor_and_forgets_the_rows() {
        let mut c = shown();
        assert_eq!(
            c.release(),
            Some(Send::Update {
                resource: 0,
                place: (0, 0),
                hot: (0, 0)
            })
        );
        assert_eq!(c.chain_returned(), None);
        // The next owner binds again from nothing.
        assert_eq!(c.row(row(3, PLACE, false)), None);
        assert_eq!(c.transfer_due(), Some(3));
        // A cursor never shown has nothing to hide.
        assert_eq!(Cursor::new().release(), None);
    }

    #[test]
    fn a_move_carries_the_resource_of_the_picture_and_never_resource_0() {
        let mut c = shown();
        for place in [(1, 1), (2, 2), (3, 3)] {
            if let Some(Send::Move { resource, .. }) = c.row(row(3, place, false)) {
                assert_eq!(resource, 3);
            }
        }
        assert_eq!(
            c.chain_returned(),
            Some(Send::Move {
                place: (3, 3),
                resource: 3
            })
        );
    }

    #[test]
    fn a_new_hot_spot_alone_is_an_update_with_no_transfer() {
        let mut c = shown();
        let mut r = row(3, (5, 6), false);
        r.hot = (4, 2);
        assert_eq!(
            c.row(r),
            Some(Send::Update {
                resource: 3,
                place: (5, 6),
                hot: (4, 2)
            })
        );
        assert_eq!(c.transfer_due(), None, "the points did not change");
        // The same hot spot again is a move.
        assert_eq!(c.chain_returned(), None);
        assert_eq!(
            c.row(r),
            Some(Send::Move {
                place: (5, 6),
                resource: 3
            })
        );
        // While a transfer is due the hot spot joins the update that follows.
        let mut c = shown();
        c.row(row(3, PLACE, true));
        let mut r = row(3, PLACE, false);
        r.hot = (1, 1);
        assert_eq!(c.row(r), None);
        c.transfer_started();
        assert_eq!(
            c.transfer_done(true),
            Some(Send::Update {
                resource: 3,
                place: PLACE,
                hot: (1, 1)
            })
        );
    }

    #[test]
    fn a_failed_transfer_is_tried_again_by_the_next_row_of_the_source() {
        let mut c = Cursor::new();
        c.row(row(3, PLACE, false));
        c.transfer_started();
        assert_eq!(c.transfer_done(false), None);
        assert_eq!(c.transfer_due(), None);
        // The next row with the same source, a plain place, makes the
        // transfer due again, and nothing is sent before it returns.
        assert_eq!(c.row(row(3, (8, 9), false)), None);
        assert_eq!(c.transfer_due(), Some(3));
        c.transfer_started();
        assert_eq!(c.transfer_done(true), Some(update((8, 9))));
        // After that a place is a move again.
        c.chain_returned();
        assert!(matches!(
            c.row(row(3, (1, 1), false)),
            Some(Send::Move { .. })
        ));
    }

    #[test]
    fn a_command_that_waited_for_the_chain_does_not_outlive_its_owner() {
        let mut c = shown();
        c.row(row(3, (1, 1), false));
        c.row(row(3, (2, 2), false));
        // A move waits; the owner leaves: the hide is what is sent next.
        assert_eq!(c.release(), None, "the chain is out, the hide waits");
        assert_eq!(
            c.chain_returned(),
            Some(Send::Update {
                resource: 0,
                place: (0, 0),
                hot: (0, 0)
            })
        );
    }

    #[test]
    fn a_send_that_failed_frees_the_queue() {
        let mut c = shown();
        c.row(row(3, (1, 1), false));
        c.row(row(3, (2, 2), false));
        c.abandoned();
        assert!(!c.is_out());
        assert_eq!(c.chain_returned(), None);
    }
}
