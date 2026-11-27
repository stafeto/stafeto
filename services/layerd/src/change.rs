// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The changes of names of the layered root (step C3 part C): create, write, `mkdir`, `unlink`,
//! `rmdir`, `rename`, `symlink`, `chmod`, `chown`, `utimensat` and `truncate` of the names of the
//! layer of the user, over the data volume. The rules (section 2 of the decision and part C of the
//! split):
//!
//! - A change acts on the live layer. A name the layer does not hold is made in the layer, and a
//!   directory of the lower set that a new name lies in is made in the layer first, with the owner,
//!   group and mode the lower directory has (no content: a directory of the layer lists the lower
//!   one too). A file, a directory or a link is prepared in `work/` (made, given its owner and mode)
//!   and then renamed into the layer, so the name appears with its attributes in one step.
//! - A file the service creates has the number `UPPER_INO_TAG | n`: the counter of COMPOSITION,
//!   which is written back in blocks (`INO_BLOCK`), so a number is never used twice.
//! - `unlink` and `rmdir` of a name the lower set has make the mark of deletion `.wh.<name>` (a file
//!   made in `work/` and renamed in, before the name of the layer goes, so a cut leaves the name or
//!   the name deleted and never the lower one showing through); the mark of a name that comes back
//!   goes after the new name is there, and a directory that replaces a lower one is opaque (the
//!   file `.wh..wh..opq`).
//! - A symbolic link is the file `.wh..wh.lnk.<name>` whose bytes are the target (littlefs has
//!   none); the walk of a path expands it by a redirect that routes by the path.
//! - `rename` moves a name of the layer inside the layer; a name of the lower set, and a directory
//!   of the layer that has a lower one under it, are CROSS_DEVICE until the copy up. `link` is
//!   TOO_MANY_LINKS: the volume has no links.
//! - Writes to a name of the lower set (an open for writing, `truncate`, `chmod`, `chown`,
//!   `utimensat`) are READ_ONLY_FILESYSTEM until the copy up.
//! - The rights are `posix_perm`'s: search on the directories of the path, write and search on the
//!   directory a name is made or removed in, the sticky bit, the owner and group of a new name, the
//!   rights of `chmod`, `chown` and `utimensat`. The service is user 0 on the volume, so it checks
//!   every right itself and gives a new name its owner with CHOWN.
//! - The names `.wh.*` are the layer's own: a change that names one is INVALID_ARGUMENT, and a path
//!   whose volume path would pass `proto_data::MAX_PATH` is NAME_TOO_LONG.
//!
//! The paths of CHANGE are canonical: the POSIX layer resolves the links of the directory part
//! first. A link of the layer in the directory part is answered with a redirect that routes by the
//! path (`Redirect.index` says which of the two paths), and a link of the lower set there is
//! answered with a redirect to the RAM file service (`Redirect.index` again): the client resolves
//! the directory part there (its canonical path) and asks again. An open that creates meets such a
//! link as the same redirect, which the RAM file service expands itself.
//!
//! A change is a job of the loop (`changejob`): its walk, its calls and its checks go in steps, and
//! this module keeps what they share.

use crate::index::Kind;
use crate::names::{Core, Walked, from_volume, st};
use crate::scan::WHITEOUT_PREFIX;
use crate::volume::{Lower, LowerStat, R, Volume};
use posix_perm::{Denial, EXEC, WRITE, permits};
use proto_fs::{MAX_PATH, Redirect};
use proto_wire::{Status, Writer};

/// The numbers the counter of COMPOSITION reserves in one write.
pub(crate) const INO_BLOCK: u64 = 256;
/// The mode of a symbolic link, as on Linux.
pub(crate) const LINK_MODE: u32 = 0o777;

/// What the changes keep between requests.
#[derive(Default)]
pub struct Writes {
    /// The number of the next name in `work/`.
    pub(crate) work: u32,
    /// The next number of a file the service creates, and the end of the block COMPOSITION holds.
    pub(crate) ino_next: u64,
    pub(crate) ino_limit: u64,
    pub(crate) started: bool,
}

/// Why a change did not complete as a plain status.
#[derive(Debug)]
pub(crate) enum Stop {
    Status(Status),
    /// A link of the layer in the path `which` (0 the first path, 1 the second): the component
    /// `start..end` of the plain path is the link with the entry `id`.
    Link {
        which: u32,
        start: usize,
        end: usize,
    },
    /// A link of the lower set in the directory part of the path.
    LowerLink {
        which: u32,
    },
}

impl From<Status> for Stop {
    fn from(s: Status) -> Stop {
        Stop::Status(s)
    }
}

pub(crate) type F<T> = Result<T, Stop>;

pub(crate) fn denial(denied: Denial) -> Status {
    st(match denied {
        Denial::Access => proto_fs::ACCESS_DENIED,
        Denial::Permission => proto_fs::PERMISSION,
    })
}

/// Whether the caller may remove `victim` from `parent`: write and search on the directory and the
/// sticky rule (the break leaves the sticky rule out).
pub(crate) fn removal_allowed(
    who: posix_perm::Identity<'_>,
    parent: &posix_perm::Attr,
    victim: &posix_perm::Attr,
) -> Result<(), Status> {
    if cfg!(feature = "break-layerd-sticky") {
        return if permits(who, parent, WRITE | EXEC) {
            Ok(())
        } else {
            Err(denial(Denial::Access))
        };
    }
    posix_perm::remove_allowed(who, parent, victim).map_err(denial)
}

pub(crate) fn fail<T>(code: u32) -> F<T> {
    Err(Stop::Status(st(code)))
}

/// A plain path split into the directory part and the last name.
pub(crate) struct Parts {
    pub(crate) parent_len: usize,
    pub(crate) leaf_at: usize,
    pub(crate) len: usize,
    pub(crate) trailing: bool,
}

/// The directory part and the name of a plain path: INVALID_ARGUMENT for a `..` or a `.` name
/// (the paths of a change are canonical), BUSY for the root.
pub(crate) fn split(path: &[u8]) -> F<Parts> {
    let trailing = path.len() > 1 && path.ends_with(b"/");
    let trimmed = if trailing {
        &path[..path.len() - 1]
    } else {
        path
    };
    if trimmed == b"/" {
        return fail(proto_fs::BUSY);
    }
    if trimmed.split(|&b| b == b'/').any(|part| part == b"..") {
        return fail(proto_fs::INVALID_ARGUMENT);
    }
    let at = trimmed.iter().rposition(|&b| b == b'/').unwrap_or(0);
    Ok(Parts {
        parent_len: if at == 0 { 1 } else { at },
        leaf_at: at + 1,
        len: trimmed.len(),
        trailing,
    })
}

/// A name the layer keeps for itself.
pub(crate) fn reserved(leaf: &[u8]) -> bool {
    leaf.starts_with(WHITEOUT_PREFIX)
}

/// The directory a lower walk is in, with what it found about a name below it.
pub(crate) struct Parent {
    /// The directory of the layer, when the path of the directory part is there.
    pub(crate) up: Option<u32>,
    pub(crate) attr: posix_perm::Attr,
    /// The lower set shows through the directory.
    pub(crate) visible: bool,
}

/// What the merged view has at a name.
#[derive(Clone, Copy)]
pub(crate) enum Leaf {
    /// Nothing: the name is new, or the lower set has it and a mark of the layer hides it.
    Missing {
        hidden: bool,
        /// The lower set has a directory there (hidden).
        lower_dir: bool,
    },
    Upper {
        id: u32,
        kind: Kind,
        /// What the lower set has under the same name, when it shows through.
        lower: Option<LowerStat>,
    },
    Lower(LowerStat),
}

impl<V: Volume, L: Lower> Core<'_, V, L> {
    // ------------------------------------------------------------------ small things

    pub(crate) fn lower_stat(&mut self, path: &[u8]) -> F<Option<LowerStat>> {
        match self.lower.stat(path, false) {
            Ok(s) => Ok(Some(s)),
            Err(Status::Unknown(proto_fs::NO_ENTRY | proto_fs::NOT_DIRECTORY)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// The next name in `work/`: its number and its path.
    pub(crate) fn work_path(&mut self) -> (u32, [u8; 40], usize) {
        self.writes.work = self.writes.work.wrapping_add(1);
        let n = self.writes.work;
        let (out, len) = Self::work_path_of(n);
        (n, out, len)
    }

    /// The path of the name number `n` in `work/`.
    pub(crate) fn work_path_of(n: u32) -> ([u8; 40], usize) {
        let mut out = [0u8; 40];
        let head = b"/.layers/work/";
        out[..head.len()].copy_from_slice(head);
        let mut digits = [0u8; 10];
        let mut v = n;
        let mut k = 0;
        loop {
            digits[k] = b'0' + (v % 10) as u8;
            v /= 10;
            k += 1;
            if v == 0 {
                break;
            }
        }
        for i in 0..k {
            out[head.len() + i] = digits[k - 1 - i];
        }
        (out, head.len() + k)
    }

    /// The text of the link `id` (the bytes of its file) in `out`.
    pub(crate) fn link_text(&mut self, id: u32, out: &mut [u8; 512]) -> R<usize> {
        let mut vp = [0u8; 512];
        let n = self.vpath(id, &mut vp)?;
        self.read_file(&vp[..n], out).map_err(from_volume)
    }

    /// The reply for a path that meets the link `id` at `start..end`: a redirect that routes by
    /// the path, with the text of the link where the component stood.
    pub(crate) fn link_redirect(
        &mut self,
        walked: &Walked,
        id: u32,
        start: usize,
        end: usize,
        w: &mut Writer,
    ) -> R<()> {
        self.write_link_redirect(0, walked.path(), id, start, end, w)
    }

    pub(crate) fn write_link_redirect(
        &mut self,
        which: u32,
        path: &[u8],
        id: u32,
        start: usize,
        end: usize,
        w: &mut Writer,
    ) -> R<()> {
        let mut text = [0u8; 512];
        let len = self.link_text(id, &mut text)?;
        Self::link_redirect_text(which, path, &text[..len], start, end, w)
    }

    /// The redirect that routes by the path for the link at `start..end` of `path` whose text is
    /// `text`.
    pub(crate) fn link_redirect_text(
        which: u32,
        path: &[u8],
        text: &[u8],
        start: usize,
        end: usize,
        w: &mut Writer,
    ) -> R<()> {
        if text.is_empty() {
            return Err(st(proto_fs::NO_ENTRY));
        }
        let (head, rest) = (&path[..start], &path[end..]);
        let absolute = text[0] == b'/';
        let total = if absolute { 0 } else { head.len() } + text.len() + rest.len();
        if total > MAX_PATH {
            return Err(st(proto_fs::NAME_TOO_LONG));
        }
        let mut out = [0u8; MAX_PATH];
        let mut at = 0;
        if !absolute {
            out[..head.len()].copy_from_slice(head);
            at = head.len();
        }
        out[at..at + text.len()].copy_from_slice(text);
        at += text.len();
        out[at..at + rest.len()].copy_from_slice(rest);
        Redirect {
            target: proto_fs::REDIRECT_BY_PATH,
            index: which,
            links: 1,
            path: &out[..total],
        }
        .write(w)
    }
}
