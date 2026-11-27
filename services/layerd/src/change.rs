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
//! INVALID_ARGUMENT (an open that creates meets it as a redirect to the RAM file service, which
//! expands it).

use crate::index::{Fields, HAS_CHILDREN, Kind, NAME_MAX, NextChild, OPAQUE, UNSCANNED};
use crate::lookup::{Outcome, STEP, Step, Walk, normalize};
use crate::names::{Client, Core, Done, Walked, attr_of, from_volume, st};
use crate::scan::{LINK_PREFIX, OPAQUE_NAME, WHITEOUT_PREFIX};
use crate::volume::{Lower, LowerStat, R, Volume};
use posix_perm::{Created, Denial, EXEC, TimesRequest, WRITE, permits};
use proto_data as d;
use proto_fs::names::{self as n, Change, ChangeOp, OpenAnswer, UPPER_INO_TAG};
use proto_fs::{MAX_PATH, Redirect};
use proto_wire::{Status, Writer};

/// The numbers the counter of COMPOSITION reserves in one write.
const INO_BLOCK: u64 = 256;
/// The mode of a symbolic link, as on Linux.
const LINK_MODE: u32 = 0o777;

/// What the changes keep between requests.
#[derive(Default)]
pub struct Writes {
    /// The number of the next name in `work/`.
    work: u32,
    /// The next number of a file the service creates, and the end of the block COMPOSITION holds.
    ino_next: u64,
    ino_limit: u64,
    started: bool,
}

/// Why a change did not complete as a plain status.
#[derive(Debug)]
pub(crate) enum Stop {
    Status(Status),
    /// A link of the layer in the path `which` (0 the first path, 1 the second): the component
    /// `start..end` of the plain path is the link with the entry `id`.
    Link {
        which: u32,
        id: u32,
        start: usize,
        end: usize,
    },
    /// A link of the lower set in the directory part of the path.
    LowerLink,
}

impl From<Status> for Stop {
    fn from(s: Status) -> Stop {
        Stop::Status(s)
    }
}

type F<T> = Result<T, Stop>;

fn denial(denied: Denial) -> Status {
    st(match denied {
        Denial::Access => proto_fs::ACCESS_DENIED,
        Denial::Permission => proto_fs::PERMISSION,
    })
}

fn fail<T>(code: u32) -> F<T> {
    Err(Stop::Status(st(code)))
}

/// A plain path split into the directory part and the last name.
struct Parts {
    parent_len: usize,
    leaf_at: usize,
    len: usize,
    trailing: bool,
}

fn plain(path: &[u8]) -> ([u8; 512], usize) {
    let mut buf = [0u8; 512];
    let len = normalize(path, &mut buf);
    (buf, len)
}

/// The directory part and the name of a plain path: INVALID_ARGUMENT for a `..` or a `.` name
/// (the paths of a change are canonical), BUSY for the root.
fn split(path: &[u8]) -> F<Parts> {
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
fn reserved(leaf: &[u8]) -> bool {
    leaf.starts_with(WHITEOUT_PREFIX)
}

/// The directory a lower walk is in, with what it found about a name below it.
struct Parent {
    /// The directory of the layer, when the path of the directory part is there.
    up: Option<u32>,
    attr: posix_perm::Attr,
    /// The lower set shows through the directory.
    visible: bool,
    /// The deepest directory of the layer on the way, and where the first name the layer does
    /// not hold starts in the path.
    deepest: u32,
    miss: usize,
}

/// What the merged view has at a name.
#[derive(Clone, Copy)]
enum Leaf {
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

    fn lower_stat(&mut self, path: &[u8]) -> F<Option<LowerStat>> {
        match self.lower.stat(path, false) {
            Ok(s) => Ok(Some(s)),
            Err(Status::Unknown(proto_fs::NO_ENTRY | proto_fs::NOT_DIRECTORY)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Whether the lower set shows through the directory `id` of the layer: no directory of it,
    /// and none above, is opaque.
    fn lower_visible(&self, id: u32) -> bool {
        let mut at = id;
        loop {
            if self.index.flags(at) & OPAQUE != 0 {
                return false;
            }
            if at == 0 {
                return true;
            }
            if self.index.entry(at).is_none() {
                return false;
            }
            at = self.index.parent_of(at);
        }
    }

    /// The path of the name `name` in the directory `parent` of the layer on the volume; a link
    /// is the file that holds it. NAME_TOO_LONG past the volume's limit.
    fn child_path(&self, parent: u32, name: &[u8], link: bool) -> R<([u8; 512], usize)> {
        let mut out = [0u8; 512];
        let n = self.vpath(parent, &mut out)?;
        let prefix: &[u8] = if link { LINK_PREFIX } else { b"" };
        let total = n + 1 + prefix.len() + name.len();
        if total > d::MAX_PATH {
            return Err(st(proto_fs::NAME_TOO_LONG));
        }
        out[n] = b'/';
        out[n + 1..n + 1 + prefix.len()].copy_from_slice(prefix);
        out[n + 1 + prefix.len()..total].copy_from_slice(name);
        Ok((out, total))
    }

    /// The next name in `work/`.
    fn work_path(&mut self) -> ([u8; 40], usize) {
        self.writes.work = self.writes.work.wrapping_add(1);
        let mut out = [0u8; 40];
        let head = b"/.layers/work/";
        out[..head.len()].copy_from_slice(head);
        let mut digits = [0u8; 10];
        let mut v = self.writes.work;
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

    /// The next number of a file the layer makes (the tag and the counter), writing COMPOSITION
    /// back when the block is used up.
    fn alloc_ino(&mut self) -> R<u64> {
        if !self.writes.started {
            self.writes.ino_next = self.composition.ino;
            self.writes.ino_limit = self.composition.ino;
            self.writes.started = true;
        }
        if self.writes.ino_next >= self.writes.ino_limit {
            let limit = self.writes.ino_next + INO_BLOCK;
            if limit >= UPPER_INO_TAG {
                return Err(st(proto_fs::NO_SPACE));
            }
            let mut next = self.composition;
            next.ino = limit;
            self.commit_composition(&next)?;
            self.composition = next;
            self.writes.ino_limit = limit;
        }
        let n = self.writes.ino_next;
        self.writes.ino_next += 1;
        Ok(UPPER_INO_TAG | n)
    }

    /// COMPOSITION written under a temporary name, synced and renamed over the old one.
    fn commit_composition(&mut self, c: &crate::composition::Composition) -> R<()> {
        let mut text = [0u8; crate::composition::MAX_TEXT];
        let len = c.render(&mut text);
        let h = self.volume.open(
            crate::names::COMPOSITION_TMP,
            d::WRITE | d::CREATE | d::TRUNCATE,
            0o600,
        )?;
        let written = (|| {
            let mut at = 0;
            while at < len {
                let k = self.volume.write(h, &text[at..len])?;
                if k == 0 {
                    return Err(st(d::NO_SPACE));
                }
                at += k;
            }
            self.volume.fsync(h)
        })();
        let closed = self.volume.close(h);
        written.and(closed).map_err(from_volume)?;
        self.volume
            .rename(crate::names::COMPOSITION_TMP, crate::names::COMPOSITION)
            .map_err(from_volume)
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

    fn write_link_redirect(
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
        if len == 0 {
            return Err(st(proto_fs::NO_ENTRY));
        }
        let text = &text[..len];
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

    // ------------------------------------------------------------------ the walk of a change

    /// The directory part `path[..parent_len]` of a path: the directory of the layer it is, or the
    /// lower directories that it is made of below the deepest directory of the layer.
    fn find_parent(
        &mut self,
        c: &Client<'_>,
        which: u32,
        path: &[u8],
        parent_len: usize,
    ) -> F<Parent> {
        let parent = &path[..parent_len];
        let who = c.who.identity(false);
        let mut walk = Walk::new(parent);
        let outcome = loop {
            if let Step::Done(o) = walk.advance(self.index, who, STEP) {
                break o;
            }
        };
        match outcome {
            Outcome::Upper(id) => {
                let attr = self
                    .index
                    .attr(id)
                    .ok_or_else(|| Stop::Status(st(proto_fs::NOT_DIRECTORY)))?;
                Ok(Parent {
                    up: Some(id),
                    attr,
                    visible: self.lower_visible(id),
                    deepest: id,
                    miss: 0,
                })
            }
            Outcome::Lower => {
                let (cur, start) = walk.missed();
                if !self.lower_visible(cur) {
                    return fail(proto_fs::NO_ENTRY);
                }
                let mut pos = start;
                let mut last = None;
                while pos < parent.len() {
                    let end = parent[pos..]
                        .iter()
                        .position(|&b| b == b'/')
                        .map_or(parent.len(), |i| pos + i);
                    let Some(ls) = self.lower_stat(&parent[..end])? else {
                        return fail(proto_fs::NO_ENTRY);
                    };
                    match ls.kind {
                        1 => {}
                        5 => return Err(Stop::LowerLink),
                        _ => return fail(proto_fs::NOT_DIRECTORY),
                    }
                    let attr = posix_perm::Attr {
                        kind: posix_perm::Kind::Directory,
                        mode: ls.mode & 0o7777,
                        uid: ls.uid,
                        gid: ls.gid,
                    };
                    if !permits(who, &attr, EXEC) {
                        return fail(proto_fs::ACCESS_DENIED);
                    }
                    last = Some(attr);
                    pos = end + 1;
                }
                let attr = last.ok_or_else(|| Stop::Status(st(proto_fs::NO_ENTRY)))?;
                Ok(Parent {
                    up: None,
                    attr,
                    visible: true,
                    deepest: cur,
                    miss: start,
                })
            }
            Outcome::Link { id, start, end } => Err(Stop::Link {
                which,
                id,
                start,
                end,
            }),
            Outcome::PassThrough { .. } => fail(proto_fs::CROSS_DEVICE),
            other => Err(Stop::Status(Self::refusal(other))),
        }
    }

    /// What the merged view has at `leaf` in the directory `p` (the path of the directory is
    /// `parent`).
    fn leaf_state(&mut self, p: &Parent, parent: &[u8], leaf: &[u8]) -> F<Leaf> {
        let mut full = [0u8; 512];
        let mut n = parent.len();
        full[..n].copy_from_slice(parent);
        if parent != b"/" {
            full[n] = b'/';
            n += 1;
        }
        full[n..n + leaf.len()].copy_from_slice(leaf);
        n += leaf.len();
        let full = &full[..n];
        let mut hidden = false;
        if let Some(pid) = p.up
            && let Some((id, e)) = self.index.lookup(pid, leaf)
        {
            let (kind, flags) = (e.kind, e.flags);
            match kind {
                Kind::Whiteout => hidden = true,
                Kind::File | Kind::Dir | Kind::Link => {
                    let shows = p.visible && !(kind == Kind::Dir && flags & OPAQUE != 0);
                    let lower = if shows { self.lower_stat(full)? } else { None };
                    return Ok(Leaf::Upper { id, kind, lower });
                }
                _ => {}
            }
        }
        let seen = if p.visible {
            self.lower_stat(full)?
        } else {
            None
        };
        Ok(match (hidden, seen) {
            (true, s) => Leaf::Missing {
                hidden: true,
                lower_dir: s.is_some_and(|s| s.kind == 1),
            },
            (false, Some(s)) => Leaf::Lower(s),
            (false, None) => Leaf::Missing {
                hidden: false,
                lower_dir: false,
            },
        })
    }

    /// The directory of the layer for the directory part `parent` of a path: the one the walk
    /// found, or one made for each lower directory on the way (owner, group and mode of the
    /// lower one).
    fn ensure_parent(&mut self, p: &Parent, parent: &[u8]) -> R<u32> {
        if let Some(id) = p.up {
            return Ok(id);
        }
        let mut cur = p.deepest;
        let mut pos = p.miss;
        while pos < parent.len() {
            let end = parent[pos..]
                .iter()
                .position(|&b| b == b'/')
                .map_or(parent.len(), |i| pos + i);
            let ls = match self.lower.stat(&parent[..end], false) {
                Ok(s) if s.kind == 1 => s,
                Ok(_) => return Err(st(proto_fs::NOT_DIRECTORY)),
                Err(e) => return Err(e),
            };
            let own = Created {
                uid: ls.uid,
                gid: ls.gid,
                mode: ls.mode & 0o7777,
            };
            cur = self.put_dir(cur, &parent[pos..end], own, false)?;
            pos = end + 1;
        }
        Ok(cur)
    }

    // ------------------------------------------------------------------ making things

    fn scrub(&mut self, path: &[u8], dir: bool) {
        if dir {
            let _ = self.remove_inside(path, 0);
            let _ = self.volume.rmdir(path);
        } else {
            let _ = self.volume.unlink(path);
        }
    }

    /// A directory `name` in `parent`, prepared in `work/` and renamed in; opaque when `opaque`.
    fn put_dir(&mut self, parent: u32, name: &[u8], own: Created, opaque: bool) -> R<u32> {
        let Created { uid, gid, mode } = own;
        let (live, live_len) = self.child_path(parent, name, false)?;
        let (work, work_len) = self.work_path();
        let (work, live) = (&work[..work_len], &live[..live_len]);
        self.volume.mkdir(work, 0o700).map_err(from_volume)?;
        let made = (|| {
            if opaque {
                let mut marker = [0u8; 80];
                marker[..work.len()].copy_from_slice(work);
                marker[work.len()] = b'/';
                let end = work.len() + 1 + OPAQUE_NAME.len();
                marker[work.len() + 1..end].copy_from_slice(OPAQUE_NAME);
                let h =
                    self.volume
                        .open(&marker[..end], d::WRITE | d::CREATE | d::EXCLUSIVE, 0o600)?;
                self.volume.close(h)?;
            }
            self.volume.chown(work, uid, gid)?;
            self.volume.chmod(work, mode)?;
            self.volume.rename(work, live)?;
            self.volume.stat(live)
        })();
        let stat = match made {
            Ok(stat) => stat,
            Err(e) => {
                self.scrub(work, true);
                return Err(from_volume(e));
            }
        };
        let fields = Fields {
            kind: Kind::Dir,
            layer: self.composition.live().number,
            number: stat.ino,
            uid,
            gid,
            mode: mode as u16,
        };
        match self.index.insert(parent, name, fields) {
            Ok(id) => {
                self.index.set_flags(id, 0, UNSCANNED);
                if opaque {
                    self.index.set_flags(id, OPAQUE, 0);
                }
                Ok(id)
            }
            Err(_) => {
                self.scrub(live, true);
                Err(st(proto_fs::NO_SPACE))
            }
        }
    }

    /// A file or a link `name` in `parent` with `text` for its bytes, prepared in `work/`.
    fn put_file(
        &mut self,
        parent: u32,
        name: &[u8],
        kind: Kind,
        own: Created,
        text: &[u8],
    ) -> R<u32> {
        let Created { uid, gid, mode } = own;
        let link = kind == Kind::Link;
        let (live, live_len) = self.child_path(parent, name, link)?;
        let ino = self.alloc_ino()?;
        let (work, work_len) = self.work_path();
        let (work, live) = (&work[..work_len], &live[..live_len]);
        let h = self
            .volume
            .open_numbered(work, d::WRITE | d::CREATE | d::EXCLUSIVE, 0o600, ino)
            .map_err(from_volume)?;
        let made = (|| {
            let mut at = 0;
            while at < text.len() {
                let k = self.volume.write(h, &text[at..])?;
                if k == 0 {
                    return Err(st(d::NO_SPACE));
                }
                at += k;
            }
            if link {
                self.volume.fsync(h)?;
            }
            Ok(())
        })();
        let closed = self.volume.close(h);
        let done = made.and(closed).and_then(|()| {
            self.volume.chown(work, uid, gid)?;
            self.volume.chmod(work, mode)?;
            self.volume.rename(work, live)
        });
        if let Err(e) = done {
            self.scrub(work, false);
            return Err(from_volume(e));
        }
        let fields = Fields {
            kind,
            layer: self.composition.live().number,
            number: ino,
            uid,
            gid,
            mode: mode as u16,
        };
        match self.index.insert(parent, name, fields) {
            Ok(id) => Ok(id),
            Err(_) => {
                self.scrub(live, false);
                Err(st(proto_fs::NO_SPACE))
            }
        }
    }

    /// The file `.wh.<name>` in `parent` (the volume only: the caller changes the index).
    fn put_mark(&mut self, parent: u32, name: &[u8]) -> R<()> {
        if name.len() + WHITEOUT_PREFIX.len() > NAME_MAX {
            return Err(st(proto_fs::NAME_TOO_LONG));
        }
        let mut mark = [0u8; NAME_MAX];
        mark[..WHITEOUT_PREFIX.len()].copy_from_slice(WHITEOUT_PREFIX);
        mark[WHITEOUT_PREFIX.len()..WHITEOUT_PREFIX.len() + name.len()].copy_from_slice(name);
        let mark = &mark[..WHITEOUT_PREFIX.len() + name.len()];
        let (live, live_len) = self.child_path(parent, mark, false)?;
        let (work, work_len) = self.work_path();
        let (work, live) = (&work[..work_len], &live[..live_len]);
        let h = self
            .volume
            .open(work, d::WRITE | d::CREATE | d::EXCLUSIVE, 0o600)
            .map_err(from_volume)?;
        let closed = self.volume.close(h);
        let done = closed.and_then(|()| self.volume.rename(work, live));
        if let Err(e) = done {
            self.scrub(work, false);
            return Err(from_volume(e));
        }
        Ok(())
    }

    /// The mark `.wh.<name>` of `parent` goes (it stayed under a name that is there again).
    fn drop_mark(&mut self, parent: u32, name: &[u8]) {
        let mut mark = [0u8; NAME_MAX];
        let total = WHITEOUT_PREFIX.len() + name.len();
        if total > NAME_MAX {
            return;
        }
        mark[..WHITEOUT_PREFIX.len()].copy_from_slice(WHITEOUT_PREFIX);
        mark[WHITEOUT_PREFIX.len()..total].copy_from_slice(name);
        if let Ok((live, n)) = self.child_path(parent, &mark[..total], false) {
            let _ = self.volume.unlink(&live[..n]);
        }
    }

    /// The directory `id` of the layer, whose contents are marks alone, leaves the layer: it is
    /// renamed into `work/` (the removal is one step) and emptied there.
    fn retire_dir(&mut self, id: u32) -> R<()> {
        let mut vp = [0u8; 512];
        let n = self.vpath(id, &mut vp)?;
        let (gone, gone_len) = self.work_path();
        let gone = &gone[..gone_len];
        self.volume.rename(&vp[..n], gone).map_err(from_volume)?;
        if self.index.flags(id) & HAS_CHILDREN != 0 {
            self.index.remove_children(id);
        }
        self.index.remove(id);
        self.table.forget(id);
        self.scrub(gone, true);
        Ok(())
    }

    /// Whether the directory is empty in the merged view: no name of the layer that is not a mark,
    /// and no lower name that a mark does not hide.
    fn merged_empty(&mut self, up: Option<u32>, path: &[u8], lower_dir: bool) -> R<bool> {
        if let Some(id) = up {
            let mut pos = 0;
            let mut budget = usize::MAX;
            loop {
                match self.index.next_child(id, pos, &mut budget) {
                    NextChild::Found(next, child) => {
                        if self
                            .index
                            .entry(child)
                            .is_some_and(|e| e.kind != Kind::Whiteout)
                        {
                            return Ok(false);
                        }
                        pos = next;
                    }
                    NextChild::Continue(next) => pos = next,
                    NextChild::End => break,
                }
            }
        }
        if !lower_dir || up.is_some_and(|id| self.index.flags(id) & OPAQUE != 0) {
            return Ok(true);
        }
        let mut dir = match self.lower.open_dir(path) {
            Ok(dir) => dir,
            Err(Status::Unknown(proto_fs::NO_ENTRY | proto_fs::NOT_DIRECTORY)) => return Ok(true),
            Err(e) => return Err(e),
        };
        let mut name = [0u8; 256];
        let mut empty = true;
        let result = loop {
            match self.lower.next(&mut dir, &mut name) {
                Ok(Some((_, _, len))) => {
                    let found = &name[..len];
                    if found == b"." || found == b".." {
                        continue;
                    }
                    let hidden = up.is_some_and(|id| {
                        self.index
                            .lookup(id, found)
                            .is_some_and(|(_, e)| e.kind == Kind::Whiteout)
                    });
                    if !hidden {
                        empty = false;
                        break Ok(());
                    }
                }
                Ok(None) => break Ok(()),
                Err(e) => break Err(e),
            }
        };
        self.lower.close_dir(dir);
        result.map(|()| empty)
    }

    // ------------------------------------------------------------------ OPEN

    /// An OPEN with CREATE at a name the layer does not hold: the file is made unless the lower
    /// set has it. None when the name is the lower set's to open for reading (the caller goes on).
    pub(crate) fn create_and_open(
        &mut self,
        c: &Client<'_>,
        flags: u32,
        walked: &Walked,
        w: &mut Writer,
    ) -> R<Option<Done<V::Pass>>> {
        match self.create_inner(c, flags, walked.path(), walked.trailing, w) {
            Ok(done) => Ok(done),
            Err(Stop::Status(s)) => Err(s),
            Err(Stop::Link {
                which,
                id,
                start,
                end,
            }) => self
                .write_link_redirect(which, walked.path(), id, start, end, w)
                .map(|()| Some(Done::Written)),
            Err(Stop::LowerLink) => Self::redirect(walked.path(), proto_fs::REDIRECT_RAM, w)
                .map(|()| Some(Done::Written)),
        }
    }

    fn create_inner(
        &mut self,
        c: &Client<'_>,
        flags: u32,
        path: &[u8],
        trailing: bool,
        w: &mut Writer,
    ) -> F<Option<Done<V::Pass>>> {
        let parts = split(path)?;
        if trailing {
            return fail(proto_fs::IS_DIRECTORY);
        }
        let leaf = &path[parts.leaf_at..parts.len];
        let parent = &path[..parts.parent_len];
        if reserved(leaf) {
            return fail(proto_fs::INVALID_ARGUMENT);
        }
        let p = self.find_parent(c, 0, path, parts.parent_len)?;
        let who = c.who.identity(false);
        let hidden = match self.leaf_state(&p, parent, leaf)? {
            Leaf::Upper { .. } => return fail(proto_fs::ALREADY_EXISTS),
            Leaf::Lower(ls) => {
                if flags & proto_fs::EXCLUSIVE != 0 {
                    return fail(proto_fs::ALREADY_EXISTS);
                }
                if ls.kind == 5 && flags & proto_fs::NO_FOLLOW == 0 {
                    return Err(Stop::LowerLink);
                }
                if n::open_writes(flags) {
                    return fail(proto_fs::READ_ONLY_FILESYSTEM);
                }
                return Ok(None);
            }
            Leaf::Missing { hidden, .. } => hidden,
        };
        if !permits(who, &p.attr, WRITE | EXEC) {
            return fail(proto_fs::ACCESS_DENIED);
        }
        // The path must fit the volume before anything is made for it.
        self.child_path(0, &path[1..parts.len], false)?;
        let created = posix_perm::creation(
            who,
            &p.attr,
            posix_perm::Kind::File,
            n::permissions_of(flags),
            0,
        );
        let dir = self.ensure_parent(&p, parent)?;
        let id = self.put_file(dir, leaf, Kind::File, created, b"")?;
        if hidden {
            self.drop_mark(dir, leaf);
        }
        let pass = self.open_file(c, flags, id, false)?;
        OpenAnswer::Pass.write(w).map_err(Stop::Status)?;
        Ok(Some(Done::Pass(pass)))
    }

    /// The pass of the file `id` of the layer opened as `flags` say: the right to read and to
    /// write is checked (`check`) on the attributes the volume keeps.
    pub(crate) fn open_file(
        &mut self,
        c: &Client<'_>,
        flags: u32,
        id: u32,
        check: bool,
    ) -> R<V::Pass> {
        let mut vp = [0u8; 512];
        let len = self.vpath(id, &mut vp)?;
        let access = flags & 3;
        let writes = n::open_writes(flags);
        let reads = access != proto_fs::WRITE_ONLY;
        if check {
            let stat = self.volume.stat(&vp[..len]).map_err(from_volume)?;
            let mut bits = 0;
            if reads {
                bits |= posix_perm::READ;
            }
            if writes {
                bits |= WRITE;
            }
            if !permits(c.who.identity(false), &attr_of(&stat), bits) {
                return Err(st(proto_fs::ACCESS_DENIED));
            }
        }
        let mut wire = 0;
        if reads {
            wire |= d::READ;
        }
        if writes {
            wire |= d::WRITE;
            if flags & proto_fs::TRUNCATE != 0 {
                wire |= d::TRUNCATE;
            }
            if flags & proto_fs::APPEND != 0 {
                wire |= d::APPEND;
            }
        }
        let handle = self.volume.open(&vp[..len], wire, 0).map_err(from_volume)?;
        let pass = self.volume.export(handle);
        let _ = self.volume.close(handle);
        pass.map_err(from_volume)
    }

    // ------------------------------------------------------------------ CHANGE

    /// CHANGE: the operation of the request on the layer. A reply that carries a redirect is
    /// written to `w`.
    pub fn change(&mut self, c: &Client<'_>, req: &Change<'_>, w: &mut Writer) -> R<()> {
        self.gate()?;
        let result = match req.op {
            ChangeOp::Mkdir => self.op_mkdir(c, req),
            ChangeOp::Unlink => self.op_remove(c, req, false),
            ChangeOp::Rmdir => self.op_remove(c, req, true),
            ChangeOp::Rename => self.op_rename(c, req),
            ChangeOp::Symlink => self.op_symlink(c, req),
            ChangeOp::Link => fail(proto_fs::TOO_MANY_LINKS),
            ChangeOp::Chmod | ChangeOp::Chown | ChangeOp::Utimens | ChangeOp::Truncate => {
                self.op_attributes(c, req)
            }
        };
        match result {
            Ok(()) => w.u32(0),
            Err(Stop::Status(s)) => Err(s),
            Err(Stop::Link {
                which,
                id,
                start,
                end,
            }) => {
                let (buf, len) = plain(if which == 0 { req.first } else { req.second });
                self.write_link_redirect(which, &buf[..len], id, start, end, w)
            }
            Err(Stop::LowerLink) => Err(st(proto_fs::INVALID_ARGUMENT)),
        }
    }

    fn op_mkdir(&mut self, c: &Client<'_>, req: &Change<'_>) -> F<()> {
        let (buf, len) = plain(req.first);
        let path = &buf[..len];
        if path == b"/" {
            return fail(proto_fs::ALREADY_EXISTS);
        }
        let parts = split(path)?;
        let leaf = &path[parts.leaf_at..parts.len];
        let parent = &path[..parts.parent_len];
        if reserved(leaf) {
            return fail(proto_fs::INVALID_ARGUMENT);
        }
        let p = self.find_parent(c, 0, path, parts.parent_len)?;
        let (hidden, lower_dir) = match self.leaf_state(&p, parent, leaf)? {
            Leaf::Missing { hidden, lower_dir } => (hidden, lower_dir),
            _ => return fail(proto_fs::ALREADY_EXISTS),
        };
        let who = c.who.identity(false);
        if !permits(who, &p.attr, WRITE | EXEC) {
            return fail(proto_fs::ACCESS_DENIED);
        }
        self.child_path(0, &path[1..parts.len], false)?;
        let created = posix_perm::creation(
            who,
            &p.attr,
            posix_perm::Kind::Directory,
            (req.a & 0o7777) as u32,
            0,
        );
        let dir = self.ensure_parent(&p, parent)?;
        self.put_dir(dir, leaf, created, lower_dir)?;
        if hidden {
            self.drop_mark(dir, leaf);
        }
        Ok(())
    }

    fn op_symlink(&mut self, c: &Client<'_>, req: &Change<'_>) -> F<()> {
        let (buf, len) = plain(req.first);
        let path = &buf[..len];
        let parts = split(path)?;
        let leaf = &path[parts.leaf_at..parts.len];
        let parent = &path[..parts.parent_len];
        if reserved(leaf) {
            return fail(proto_fs::INVALID_ARGUMENT);
        }
        if leaf.len() + LINK_PREFIX.len() > NAME_MAX || req.second.len() > MAX_PATH {
            return fail(proto_fs::NAME_TOO_LONG);
        }
        if parts.trailing {
            return fail(proto_fs::NO_ENTRY);
        }
        let p = self.find_parent(c, 0, path, parts.parent_len)?;
        let hidden = match self.leaf_state(&p, parent, leaf)? {
            Leaf::Missing { hidden, .. } => hidden,
            _ => return fail(proto_fs::ALREADY_EXISTS),
        };
        let who = c.who.identity(false);
        if !permits(who, &p.attr, WRITE | EXEC) {
            return fail(proto_fs::ACCESS_DENIED);
        }
        self.child_path(0, &path[1..parts.len], true)?;
        let created = posix_perm::creation(who, &p.attr, posix_perm::Kind::File, LINK_MODE, 0);
        let dir = self.ensure_parent(&p, parent)?;
        let created = Created {
            mode: LINK_MODE,
            ..created
        };
        self.put_file(dir, leaf, Kind::Link, created, req.second)?;
        if hidden {
            self.drop_mark(dir, leaf);
        }
        Ok(())
    }

    /// `unlink` (`dir` false) and `rmdir` (`dir` true).
    fn op_remove(&mut self, c: &Client<'_>, req: &Change<'_>, dir: bool) -> F<()> {
        let (buf, len) = plain(req.first);
        let path = &buf[..len];
        let parts = split(path)?;
        let leaf = &path[parts.leaf_at..parts.len];
        let parent = &path[..parts.parent_len];
        if reserved(leaf) {
            return fail(proto_fs::INVALID_ARGUMENT);
        }
        let full = &path[..parts.len];
        let p = self.find_parent(c, 0, path, parts.parent_len)?;
        let who = c.who.identity(false);
        let state = self.leaf_state(&p, parent, leaf)?;
        match state {
            Leaf::Missing { .. } => fail(proto_fs::NO_ENTRY),
            Leaf::Lower(ls) => {
                let is_dir = ls.kind == 1;
                if is_dir && !dir {
                    return fail(proto_fs::IS_DIRECTORY);
                }
                if !is_dir && (dir || parts.trailing) {
                    return fail(proto_fs::NOT_DIRECTORY);
                }
                let victim = posix_perm::Attr {
                    kind: if is_dir {
                        posix_perm::Kind::Directory
                    } else {
                        posix_perm::Kind::File
                    },
                    mode: ls.mode & 0o7777,
                    uid: ls.uid,
                    gid: ls.gid,
                };
                posix_perm::remove_allowed(who, &p.attr, &victim).map_err(denial)?;
                if is_dir && !self.merged_empty(None, full, true)? {
                    return fail(proto_fs::NOT_EMPTY);
                }
                let up = self.ensure_parent(&p, parent)?;
                self.put_mark(up, leaf)?;
                self.index_mark(up, leaf)
            }
            Leaf::Upper { id, kind, lower } => {
                let is_dir = kind == Kind::Dir;
                if is_dir && !dir {
                    return fail(proto_fs::IS_DIRECTORY);
                }
                if !is_dir && (dir || parts.trailing) {
                    return fail(proto_fs::NOT_DIRECTORY);
                }
                let victim = if is_dir {
                    self.index
                        .attr(id)
                        .ok_or_else(|| Stop::Status(st(proto_fs::NOT_DIRECTORY)))?
                } else {
                    let mut vp = [0u8; 512];
                    let n = self.vpath(id, &mut vp)?;
                    attr_of(&self.volume.stat(&vp[..n]).map_err(from_volume)?)
                };
                posix_perm::remove_allowed(who, &p.attr, &victim).map_err(denial)?;
                let up = p.up.ok_or_else(|| Stop::Status(st(proto_fs::NO_ENTRY)))?;
                if is_dir
                    && !self.merged_empty(Some(id), full, lower.is_some_and(|s| s.kind == 1))?
                {
                    return fail(proto_fs::NOT_EMPTY);
                }
                let marked = lower.is_some();
                if marked {
                    self.put_mark(up, leaf)?;
                }
                if is_dir {
                    self.retire_dir(id)?;
                } else {
                    let mut vp = [0u8; 512];
                    let n = self.vpath(id, &mut vp)?;
                    self.volume.unlink(&vp[..n]).map_err(from_volume)?;
                    self.index.remove(id);
                }
                if marked {
                    self.index_mark(up, leaf)?;
                }
                Ok(())
            }
        }
    }

    /// The index holds the mark of deletion of `name` in `parent`.
    fn index_mark(&mut self, parent: u32, name: &[u8]) -> F<()> {
        let fields = Fields {
            kind: Kind::Whiteout,
            layer: self.composition.live().number,
            number: 0,
            uid: 0,
            gid: 0,
            mode: 0,
        };
        match self.index.insert(parent, name, fields) {
            Ok(_) => Ok(()),
            Err(_) => fail(proto_fs::NO_SPACE),
        }
    }

    fn op_rename(&mut self, c: &Client<'_>, req: &Change<'_>) -> F<()> {
        let (abuf, alen) = plain(req.first);
        let (bbuf, blen) = plain(req.second);
        let (a_path, b_path) = (&abuf[..alen], &bbuf[..blen]);
        let a = split(a_path)?;
        let b = split(b_path)?;
        let (a_leaf, b_leaf) = (&a_path[a.leaf_at..a.len], &b_path[b.leaf_at..b.len]);
        if reserved(a_leaf) || reserved(b_leaf) {
            return fail(proto_fs::INVALID_ARGUMENT);
        }
        let (a_parent, b_parent) = (&a_path[..a.parent_len], &b_path[..b.parent_len]);
        let who = c.who.identity(false);
        let pa = self.find_parent(c, 0, a_path, a.parent_len)?;
        let (src_id, src_kind, src_lower) = match self.leaf_state(&pa, a_parent, a_leaf)? {
            Leaf::Missing { .. } => return fail(proto_fs::NO_ENTRY),
            Leaf::Lower(_) => return fail(proto_fs::CROSS_DEVICE),
            Leaf::Upper { id, kind, lower } => (id, kind, lower),
        };
        let src_is_dir = src_kind == Kind::Dir;
        // A directory with a lower one under it moves with it, which waits for the copy up.
        if src_is_dir && src_lower.is_some_and(|s| s.kind == 1) {
            return fail(proto_fs::CROSS_DEVICE);
        }
        if (a.trailing || b.trailing) && !src_is_dir {
            return fail(proto_fs::NOT_DIRECTORY);
        }
        let a_full = &a_path[..a.len];
        let b_full = &b_path[..b.len];
        if a_full == b_full {
            return Ok(());
        }
        if src_is_dir && b_full.starts_with(a_full) && b_full.get(a_full.len()) == Some(&b'/') {
            return fail(proto_fs::INVALID_ARGUMENT);
        }
        let pb = self.find_parent(c, 1, b_path, b.parent_len)?;
        let dst = self.leaf_state(&pb, b_parent, b_leaf)?;
        let src_parent = pa.up.ok_or_else(|| Stop::Status(st(proto_fs::NO_ENTRY)))?;
        self.child_path(0, &b_path[1..b.len], src_kind == Kind::Link)?;
        // The attributes the rules read: the source, and the name it lands on.
        let src_attr = if src_is_dir {
            self.index
                .attr(src_id)
                .ok_or_else(|| Stop::Status(st(proto_fs::NOT_DIRECTORY)))?
        } else {
            let mut vp = [0u8; 512];
            let n = self.vpath(src_id, &mut vp)?;
            attr_of(&self.volume.stat(&vp[..n]).map_err(from_volume)?)
        };
        let lower_attr = |ls: &LowerStat| posix_perm::Attr {
            kind: if ls.kind == 1 {
                posix_perm::Kind::Directory
            } else {
                posix_perm::Kind::File
            },
            mode: ls.mode & 0o7777,
            uid: ls.uid,
            gid: ls.gid,
        };
        let (dst_attr, dst_is_dir, dst_up, dst_lower_dir) = match dst {
            Leaf::Missing { lower_dir, .. } => (None, false, None, lower_dir),
            Leaf::Lower(ls) => (Some(lower_attr(&ls)), ls.kind == 1, None, ls.kind == 1),
            Leaf::Upper { id, kind, lower } => {
                let attr = if kind == Kind::Dir {
                    self.index
                        .attr(id)
                        .ok_or_else(|| Stop::Status(st(proto_fs::NOT_DIRECTORY)))?
                } else {
                    let mut vp = [0u8; 512];
                    let n = self.vpath(id, &mut vp)?;
                    attr_of(&self.volume.stat(&vp[..n]).map_err(from_volume)?)
                };
                (
                    Some(attr),
                    kind == Kind::Dir,
                    Some((id, kind)),
                    lower.is_some_and(|s| s.kind == 1),
                )
            }
        };
        if dst_attr.is_some() {
            if src_is_dir && !dst_is_dir {
                return fail(proto_fs::NOT_DIRECTORY);
            }
            if !src_is_dir && dst_is_dir {
                return fail(proto_fs::IS_DIRECTORY);
            }
        }
        if dst_is_dir {
            let lower_dir = match dst {
                Leaf::Lower(_) => true,
                Leaf::Upper { lower, .. } => lower.is_some_and(|s| s.kind == 1),
                Leaf::Missing { .. } => false,
            };
            let up = dst_up.map(|(id, _)| id);
            if !self.merged_empty(up, b_full, lower_dir)? {
                return fail(proto_fs::NOT_EMPTY);
            }
        }
        let same_parent = pb.up.is_some() && pb.up == pa.up;
        posix_perm::rename_allowed(
            who,
            &pa.attr,
            &src_attr,
            &pb.attr,
            dst_attr.as_ref(),
            same_parent,
        )
        .map_err(denial)?;
        // The checks are done: make what the new name needs.
        let to = self.ensure_parent(&pb, b_parent)?;
        let mut old_dst = None;
        if let Some((id, kind)) = dst_up {
            if kind == Kind::Dir {
                self.retire_dir(id)?;
            } else {
                let mut vp = [0u8; 512];
                let n = self.vpath(id, &mut vp)?;
                old_dst = Some((vp, n, id, kind));
            }
        }
        if src_is_dir && dst_lower_dir && self.index.flags(src_id) & OPAQUE == 0 {
            self.mark_opaque(src_id)?;
        }
        if src_lower.is_some() {
            self.put_mark(src_parent, a_leaf)?;
        }
        let mut old_vp = [0u8; 512];
        let old_len = self.vpath(src_id, &mut old_vp)?;
        let (new_vp, new_len) = self.child_path(to, b_leaf, src_kind == Kind::Link)?;
        self.volume
            .rename(&old_vp[..old_len], &new_vp[..new_len])
            .map_err(from_volume)?;
        if let Some((vp, n, id, kind)) = old_dst {
            // A file of the other sort (a link and a file) is not replaced by the rename.
            if (kind == Kind::Link) != (src_kind == Kind::Link) {
                let _ = self.volume.unlink(&vp[..n]);
            }
            self.index.remove(id);
        }
        if let Leaf::Missing { hidden: true, .. } = dst {
            if let Some((mark, _)) = self.index.lookup(to, b_leaf) {
                self.index.remove(mark);
            }
            self.drop_mark(to, b_leaf);
        }
        let new = self
            .index
            .move_to(src_id, to, b_leaf)
            .map_err(|_| Stop::Status(st(proto_fs::NO_SPACE)))?;
        if src_is_dir {
            self.table.retarget(src_id, new);
        }
        if src_lower.is_some() {
            self.index_mark(src_parent, a_leaf)?;
        }
        Ok(())
    }

    /// The directory `id` of the layer becomes opaque: the file `.wh..wh..opq` in it.
    fn mark_opaque(&mut self, id: u32) -> F<()> {
        let (marker, n) = self.child_path(id, OPAQUE_NAME, false)?;
        let h = self
            .volume
            .open(&marker[..n], d::WRITE | d::CREATE, 0o600)
            .map_err(from_volume)?;
        let _ = self.volume.close(h);
        self.index.set_flags(id, OPAQUE, 0);
        Ok(())
    }

    /// `chmod`, `chown`, `utimensat` and `truncate` of a name of the layer; a name of the lower set
    /// is READ_ONLY_FILESYSTEM until the copy up. The path is canonical, links included.
    fn op_attributes(&mut self, c: &Client<'_>, req: &Change<'_>) -> F<()> {
        let walked = self.walk(c, req.first, false, true);
        let id = match walked.outcome {
            Outcome::Upper(id) => id,
            Outcome::Link { id, start, end } => {
                return Err(Stop::Link {
                    which: 0,
                    id,
                    start,
                    end,
                });
            }
            Outcome::Lower => {
                return match self.lower_stat(walked.path())? {
                    Some(_) => fail(proto_fs::READ_ONLY_FILESYSTEM),
                    None => fail(proto_fs::NO_ENTRY),
                };
            }
            Outcome::PassThrough { .. } => return fail(proto_fs::CROSS_DEVICE),
            other => return Err(Stop::Status(Self::refusal(other))),
        };
        let who = c.who.identity(false);
        let kind = if id == 0 {
            Kind::Dir
        } else {
            self.index.entry(id).map_or(Kind::File, |e| e.kind)
        };
        let mut vp = [0u8; 512];
        let n = self.vpath(id, &mut vp)?;
        let path = &vp[..n];
        let stat = self.volume.stat(path).map_err(from_volume)?;
        let attr = if kind == Kind::Dir {
            self.index
                .attr(id)
                .ok_or_else(|| Stop::Status(st(proto_fs::NOT_DIRECTORY)))?
        } else {
            attr_of(&stat)
        };
        match req.op {
            ChangeOp::Chmod => {
                if kind == Kind::Link {
                    return fail(proto_fs::NOT_SUPPORTED);
                }
                let mode = posix_perm::chmod_result(who, &attr, (req.a & 0o7777) as u32)
                    .map_err(denial)?;
                self.volume.chmod(path, mode).map_err(from_volume)?;
                if kind == Kind::Dir {
                    self.index
                        .set_attr(id, stat.ino, attr.uid, attr.gid, mode as u16);
                }
            }
            ChangeOp::Chown => {
                let keep = |v: u64| (v as u32 != u32::MAX).then_some(v as u32);
                let (uid, gid) = (keep(req.a), keep(req.b));
                let owned = posix_perm::chown_result(who, &attr, uid, gid).map_err(denial)?;
                self.volume
                    .chown(path, uid.unwrap_or(d::UID_KEEP), gid.unwrap_or(d::UID_KEEP))
                    .map_err(from_volume)?;
                if kind == Kind::Dir {
                    self.index
                        .set_attr(id, stat.ino, owned.uid, owned.gid, owned.mode as u16);
                }
            }
            ChangeOp::Utimens => {
                if kind == Kind::Link {
                    return fail(proto_fs::NOT_SUPPORTED);
                }
                let (atime, mtime) = (req.a as i64, req.b as i64);
                let request = match (atime, mtime) {
                    (d::UTIME_OMIT, d::UTIME_OMIT) => TimesRequest::Omit,
                    (d::UTIME_NOW, d::UTIME_NOW) => TimesRequest::Now,
                    _ => TimesRequest::Explicit,
                };
                posix_perm::utimens_allowed(who, &attr, request).map_err(denial)?;
                self.volume
                    .utimens(path, atime, mtime)
                    .map_err(from_volume)?;
            }
            ChangeOp::Truncate => {
                if kind == Kind::Dir {
                    return fail(proto_fs::IS_DIRECTORY);
                }
                if !permits(who, &attr, WRITE) {
                    return fail(proto_fs::ACCESS_DENIED);
                }
                let h = self.volume.open(path, d::WRITE, 0).map_err(from_volume)?;
                let cut = self.volume.truncate(h, req.a);
                let _ = self.volume.close(h);
                cut.map_err(from_volume)?;
            }
            _ => return fail(proto_fs::INVALID_ARGUMENT),
        }
        Ok(())
    }
}
