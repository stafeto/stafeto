// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The merged listing of a directory that has a name in the layer of the user (section 4 and the
//! decision 7 of the split): the descriptions of the service are served in two stages.
//!
//! Stage 0 lists `.`, `..` and the names of the layer from the index, with no call: the marks of
//! deletion (`.wh.<name>`) and the opaque marker are not names, so no program sees them. Stage 1
//! lists the entries of the same directory of the lower set, read through the RAM file service's
//! `READ_DIR_FD` of the service's session, and drops an entry the index has a name or a mark for
//! (the layer of the user shadows or deletes it); a directory with the opaque marker has no
//! stage 1. A request takes at most `LOWER_PER_READDIR` entries of the lower set, kept or dropped,
//! so the cost of a step does not depend on how many names the layer deletes. The position of a
//! description is (stage, position in the stage): in stage 0 the number of the slot of the index
//! after the last entry given plus two (positions 0 and 1 are `.` and `..`), in stage 1 the number
//! of entries of the lower set taken so far.

use crate::descriptions::Position;
use crate::index::{Index, Kind, NextChild, OPAQUE};
use crate::volume::{Lower, R};
use proto_fs::names::{DirEntry, DirReply, ENTRY_HEAD, LOWER_PER_READDIR, NAME_MAX, cursor};
use proto_wire::Status;

/// What a reply of a listing says besides its entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Listed {
    pub more: bool,
    pub cursor: u64,
}

/// The slots of the index one request looks at in the first stage: 512 slots cost about 7,000
/// ticks under `-icount` (14 for a slot, measured), under 0.9 B with the rest of the step.
pub const SLOTS_PER_READDIR: usize = 512;

const DIRECTORY: u32 = 1;
const REGULAR: u32 = 2;

fn room(reply: &DirReply) -> bool {
    reply.len() + ENTRY_HEAD + NAME_MAX <= abi::MESSAGE_MAX
}

/// The number of the directory `id` and that of its parent, for `.` and `..`.
fn numbers(index: &Index, id: u32) -> (u64, u64) {
    let number = |id: u32| {
        if id == 0 {
            index.root.number
        } else {
            index.entry(id).map_or(0, |e| e.number)
        }
    };
    let parent = index.entry(id).map_or(0, |e| e.parent());
    (number(id), number(parent))
}

/// Serves one READ_DIR: entries are pushed to `reply`, `position` and `lower` are advanced.
pub fn read_dir<L: Lower>(
    index: &Index,
    lower: &mut L,
    dir: u32,
    position: &mut Position,
    open: &mut Option<L::Dir>,
    reply: &mut DirReply,
) -> R<Listed> {
    if position.stage == 0 {
        let (here, above) = numbers(index, dir);
        while position.at < 2 && room(reply) {
            let (name, ino) = if position.at == 0 {
                (&b"."[..], here)
            } else {
                (&b".."[..], above)
            };
            reply
                .push(&DirEntry {
                    ino,
                    kind: DIRECTORY,
                    name,
                })
                .map_err(|_| Status::BadSize)?;
            position.at += 1;
        }
        if position.at < 2 {
            return Ok(listed(position, true));
        }
        let mut budget = SLOTS_PER_READDIR;
        while room(reply) {
            let from = (position.at - 2) as usize;
            match index.next_child(dir, from, &mut budget) {
                NextChild::End => {
                    // The names of the layer are done.
                    *position = Position { stage: 1, at: 0 };
                    break;
                }
                NextChild::Continue(next) => {
                    // The slots this request may look at are used up: the next one goes on.
                    position.at = next as u32 + 2;
                    break;
                }
                NextChild::Found(next, id) => {
                    position.at = next as u32 + 2;
                    let Some(e) = index.entry(id) else { continue };
                    let kind = match e.kind {
                        Kind::Whiteout | Kind::Empty => continue,
                        Kind::Dir => DIRECTORY,
                        Kind::File => REGULAR,
                    };
                    let name = index.name(id).unwrap_or(&[]);
                    reply
                        .push(&DirEntry {
                            ino: e.number,
                            kind,
                            name,
                        })
                        .map_err(|_| Status::BadSize)?;
                }
            }
        }
        if position.stage == 0 {
            return Ok(listed(position, true));
        }
    }
    // Stage 1: the lower set, unless the directory is opaque.
    if index.flags(dir) & OPAQUE != 0 {
        return Ok(listed(position, false));
    }
    if open.is_none() {
        let mut path = [0u8; 512];
        let n = index.path_of(dir, &mut path).ok_or(Status::BadSize)?;
        match lower.open_dir(&path[..n]) {
            Ok(mut d) => {
                // Back to the position a seek or an earlier request left.
                let mut name = [0u8; 256];
                for _ in 0..position.at {
                    if lower.next(&mut d, &mut name)?.is_none() {
                        break;
                    }
                }
                *open = Some(d);
            }
            // The directory is only in the layer of the user: nothing below it.
            Err(Status::Unknown(proto_fs::NO_ENTRY | proto_fs::NOT_DIRECTORY)) => {
                return Ok(listed(position, false));
            }
            Err(e) => return Err(e),
        }
    }
    let Some(d) = open.as_mut() else {
        return Ok(listed(position, false));
    };
    let mut taken = 0;
    let mut name = [0u8; 256];
    while taken < LOWER_PER_READDIR && room(reply) {
        let Some((ino, kind, len)) = lower.next(d, &mut name)? else {
            return Ok(listed(position, false));
        };
        taken += 1;
        position.at += 1;
        let name = &name[..len];
        if name == b"." || name == b".." {
            continue;
        }
        if cfg!(not(feature = "break-layerd-whiteout")) && index.lookup(dir, name).is_some() {
            continue;
        }
        reply
            .push(&DirEntry { ino, kind, name })
            .map_err(|_| Status::BadSize)?;
    }
    Ok(listed(position, true))
}

fn listed(position: &Position, more: bool) -> Listed {
    Listed {
        more,
        cursor: cursor(position.stage, position.at),
    }
}

/// Puts a description back at the start: a seek to the cursor 0.
pub fn rewind<L: Lower>(
    lower: &mut L,
    position: &mut Position,
    open: &mut Option<L::Dir>,
) -> R<()> {
    seek(lower, position, open, 0)
}

/// Puts a description at a cursor a reply gave. A stage other than 0 and 1 is INVALID_ARGUMENT.
pub fn seek<L: Lower>(
    lower: &mut L,
    position: &mut Position,
    open: &mut Option<L::Dir>,
    cursor: u64,
) -> R<()> {
    let (stage, at) = proto_fs::names::split_cursor(cursor);
    if stage > 1 {
        return Err(Status::from_code(proto_fs::INVALID_ARGUMENT));
    }
    // The lower directory is read again from its start up to `at`, when the next request asks.
    if let Some(d) = open.take() {
        lower.close_dir(d);
    }
    *position = Position { stage, at };
    Ok(())
}
