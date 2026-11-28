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
//! stage 1. A request takes at most `LOWER_PER_STEP` entries of the lower set, kept or dropped,
//! so the cost of a step does not depend on how many names the layer deletes; the open of the
//! lower directory and the replay to a position a seek left are requests of their own. The position of a
//! description is (stage, position in the stage): in stage 0 the number of the slot of the index
//! after the last entry given plus two (positions 0 and 1 are `.` and `..`), in stage 1 the number
//! of entries of the lower set taken so far. A reply with `more` and no entry always moved the
//! position on (the slots it looked at, or the lower entries it took and dropped), so a program
//! that asks again reaches the end.

use crate::descriptions::Position;
use crate::index::{Index, Kind, NextChild};
use crate::volume::{Lower, R};
use proto_fs::names::{DirEntry, DirReply, ENTRY_HEAD, LOWER_PER_READDIR, NAME_MAX, cursor};
use proto_wire::Status;

/// What a reply of a listing says besides its entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Listed {
    pub more: bool,
    pub cursor: u64,
}

/// The entries of the list of a directory one request looks at in the first stage (a mark of
/// deletion is looked at and dropped): about 57 ticks under `-icount` for each (the walk of the
/// list, the checks of the entry), measured on a directory of 2,000 marks, where 384 took 22,000;
/// the entries of a reply (up to 46 of the message's 1 KiB) cost about 9,000 more, so 96 keep a
/// request under 0.9 B with the rest of the step.
pub const SLOTS_PER_READDIR: usize = if cfg!(feature = "break-layerd-slots") {
    4096
} else {
    96
};

/// The entries of the lower set one request reads, kept, dropped or replayed (never more than
/// `LOWER_PER_READDIR`, which the protocol allows in a reply): each is a round trip to the RAM file
/// service, about 3,000 ticks of the service's own time under `-icount`.
pub const LOWER_PER_STEP: usize = 4;
const _: () = assert!(LOWER_PER_STEP <= LOWER_PER_READDIR);

/// The descriptions whose lower directory is being opened at once. Each holds a path job of the
/// session of the service with the RAM file service, which has `proto_fs::SESSION_PREPARATIONS`
/// (16) of them for everything the session holds: a change job holds one while it resolves a
/// lower path, `JOBS` of them at most, and `MARGIN` stay free for the others the session may hold
/// (a binding, a refresh). The listings get the rest.
pub const LISTINGS_RESOLVING: u32 =
    (proto_fs::SESSION_PREPARATIONS - crate::jobs::JOBS - MARGIN) as u32;
/// The preparations of the session that neither jobs nor listings take.
pub const MARGIN: usize = 4;
/// The descriptions one session has being opened at once: a client that opens many directories
/// cannot take the places of the others, whose opens only advance when they ask.
pub const LISTINGS_PER_SESSION: usize = 1;
const _: () = assert!(LISTINGS_RESOLVING >= 1);
const _: () = assert!(
    LISTINGS_RESOLVING as usize + crate::jobs::JOBS + MARGIN <= proto_fs::SESSION_PREPARATIONS
);

const DIRECTORY: u32 = 1;
const REGULAR: u32 = 2;
const SYMLINK: u32 = 5;

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
    let parent = index.parent_of(id);
    (number(id), number(parent))
}

/// Serves one READ_DIR: entries are pushed to `reply`, `position` and `lower` are advanced.
#[allow(clippy::too_many_arguments)]
pub fn read_dir<L: Lower>(
    index: &Index,
    lower: &mut L,
    dir: u32,
    hidden: bool,
    position: &mut Position,
    open: &mut Option<L::Dir>,
    opening: &mut bool,
    resolving: &mut u32,
    mine: usize,
    replayed: &mut u32,
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
        let key = index.dir_key(dir);
        // A name is taken while it fits: the room is asked for the name at hand, so a reply is
        // full of short names (46 of six bytes in the message's 1 KiB).
        while reply.len() + ENTRY_HEAD < abi::MESSAGE_MAX {
            let from = (position.at - 2) as usize;
            let found = match key {
                Some(key) => index.next_child_of(key, from, &mut budget),
                None => NextChild::End,
            };
            match found {
                NextChild::End => {
                    // The names of the layer are done.
                    *position = Position { stage: 1, at: 0 };
                    break;
                }
                NextChild::Continue(next) => {
                    // The entries this request may look at are used up: the next one goes on.
                    position.at = next as u32 + 2;
                    break;
                }
                NextChild::Found(next, id) => {
                    let Some(e) = index.entry(id) else {
                        position.at = next as u32 + 2;
                        continue;
                    };
                    let kind = match e.kind {
                        Kind::Whiteout | Kind::Empty | Kind::Gone => {
                            position.at = next as u32 + 2;
                            continue;
                        }
                        Kind::Dir => DIRECTORY,
                        Kind::File => REGULAR,
                        Kind::Link => SYMLINK,
                    };
                    let name = index.name(id).unwrap_or(&[]);
                    if reply.len() + ENTRY_HEAD + name.len() > abi::MESSAGE_MAX {
                        // It does not fit: the next request starts with it.
                        break;
                    }
                    position.at = next as u32 + 2;
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
        // The end of the names of the layer is the end of the request too: the lower set starts
        // with a request of its own.
        return Ok(listed(position, true));
    }
    // Stage 1: the lower set, unless the directory is opaque.
    if hidden {
        return Ok(listed(position, false));
    }
    // The open of the lower directory, the replay to the position a seek or an earlier request
    // left, and the entries themselves are steps of their own: each costs round trips to the RAM
    // file service, and a request does one of them. The open is made in as many requests as the
    // RAM file service has steps for the path (`Lower::open_dir_poll`), and no more than
    // `LISTINGS_RESOLVING` descriptions are in it at once, so that the preparations of the session
    // of the service (96 in the RAM file service) are never all taken by listings. A reply of
    // these has `more` and no entry; the position does not move, the state of the description
    // does.
    if open.is_none() {
        // No place: busy, which the client answers by waiting a little and asking again (the
        // library of the C programs does so for STARTING); a reply with `more` and no entry is
        // for the steps that make progress.
        if *resolving >= LISTINGS_RESOLVING || mine >= LISTINGS_PER_SESSION {
            return Err(Status::Unknown(proto_layer::STARTING));
        }
        let mut path = [0u8; 512];
        let n = index.path_of(dir, &mut path).ok_or(Status::BadSize)?;
        return match lower.open_dir_start(&path[..n]) {
            Ok(d) => {
                *open = Some(d);
                *opening = true;
                *resolving += 1;
                *replayed = 0;
                Ok(listed(position, true))
            }
            // The directory is only in the layer of the user: nothing below it.
            Err(Status::Unknown(proto_fs::NO_ENTRY | proto_fs::NOT_DIRECTORY)) => {
                Ok(listed(position, false))
            }
            // The session has no path job free: busy.
            Err(Status::Unknown(proto_fs::TOO_MANY_OPEN_FILES)) => {
                Err(Status::Unknown(proto_layer::STARTING))
            }
            Err(e) => Err(e),
        };
    }
    if *opening {
        let Some(d) = open.as_mut() else {
            return Ok(listed(position, false));
        };
        return match lower.open_dir_poll(d) {
            Ok(done) => {
                if done {
                    *opening = false;
                    *resolving -= 1;
                }
                Ok(listed(position, true))
            }
            Err(e) => {
                if let Some(d) = open.take() {
                    lower.close_dir(d);
                }
                *opening = false;
                *resolving -= 1;
                match e {
                    Status::Unknown(proto_fs::NO_ENTRY | proto_fs::NOT_DIRECTORY) => {
                        Ok(listed(position, false))
                    }
                    e => Err(e),
                }
            }
        };
    }
    let Some(d) = open.as_mut() else {
        return Ok(listed(position, false));
    };
    let mut name = [0u8; 256];
    if *replayed < position.at {
        let mut steps = 0;
        while *replayed < position.at && steps < LOWER_PER_STEP {
            if lower.next(d, &mut name)?.is_none() {
                // The directory is shorter than the position said: nothing more below it.
                return Ok(listed(position, false));
            }
            *replayed += 1;
            steps += 1;
        }
        return Ok(listed(position, true));
    }
    let mut taken = 0;
    let key = index.dir_key(dir);
    while taken < LOWER_PER_STEP && room(reply) {
        let Some((ino, kind, len)) = lower.next(d, &mut name)? else {
            return Ok(listed(position, false));
        };
        taken += 1;
        position.at += 1;
        *replayed += 1;
        let name = &name[..len];
        if name == b"." || name == b".." {
            continue;
        }
        if cfg!(not(feature = "break-layerd-whiteout"))
            && key.is_some_and(|key| index.lookup_in(key, name).is_some())
        {
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
    opening: &mut bool,
    resolving: &mut u32,
    replayed: &mut u32,
) -> R<()> {
    seek(
        lower,
        position,
        Position::default(),
        open,
        opening,
        resolving,
        replayed,
        0,
    )
}

/// Puts a description at a cursor a reply gave. A stage other than 0 and 1 is INVALID_ARGUMENT, and
/// so is a position past `given`, the furthest the replies of this description have gone: the
/// cursor of a reply is what the service names, and a number the replies never gave points into
/// the table or the lower directory at a place nobody asked to see.
#[allow(clippy::too_many_arguments)]
pub fn seek<L: Lower>(
    lower: &mut L,
    position: &mut Position,
    given: Position,
    open: &mut Option<L::Dir>,
    opening: &mut bool,
    resolving: &mut u32,
    replayed: &mut u32,
    cursor: u64,
) -> R<()> {
    let (stage, at) = proto_fs::names::split_cursor(cursor);
    let wanted = Position { stage, at };
    if stage > 1 || wanted > given {
        return Err(Status::from_code(proto_fs::INVALID_ARGUMENT));
    }
    // The lower directory is read again from its start up to `at`, when the next request asks.
    if let Some(d) = open.take() {
        lower.close_dir(d);
        if *opening {
            *resolving -= 1;
        }
    }
    *opening = false;
    *replayed = 0;
    *position = wanted;
    Ok(())
}
