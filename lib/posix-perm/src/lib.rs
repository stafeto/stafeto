// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The file permission rules of POSIX.1-2024 as pure functions, `no_std`, no state.
//!
//! The file services (ramfs, datafs) own their stores and their way to learn who asks; they
//! describe the caller as an [`Identity`] and the file as an [`Attr`] and ask this crate for the
//! decision. One crate holds the rules so that two services cannot drift apart on a change.
//!
//! References are to POSIX.1-2024 (IEEE Std 1003.1-2024): XBD 4.7 "File Access Permissions",
//! XSH `chmod()`, `chown()`, `access()`, `futimens()`, `open()`, `mkdir()`, `unlink()`,
//! `rename()` and `write()`.
//!
//! Rules kept here:
//!
//! - A caller whose user ID is the file's owner uses the owner class only; otherwise a caller
//!   whose group ID (or one of whose supplementary groups) is the file's group uses the group
//!   class only; otherwise the other class (XBD 4.7). A class that lacks a bit never falls back
//!   to a wider class.
//! - User ID 0 passes read, write and search. Execute on a file that is not a directory needs at
//!   least one execute bit in the mode (XBD 4.7, "appropriate privileges" and "execute permission").
//! - A new object belongs to the caller's user. Its group is the caller's group, or the group of
//!   the parent when the parent has the set-group-ID bit; a new directory under such a parent
//!   keeps the bit. A new non-directory whose group the creator is not a member of loses its
//!   own set-group-ID bit (XSH `open()`, `mkdir()`). The mode takes the file creation mask.
//! - Removing an entry needs write and search on its directory. In a directory with the sticky bit
//!   it also needs the user to own the entry or the directory, or to be user ID 0 (XBD 4.5
//!   "Directory Protection", XSH `unlink()`, `rename()`). Renaming applies this to the source
//!   directory, adds write and search on the destination directory, applies the sticky rule to
//!   an existing target there, and for a directory that moves to another parent also needs write
//!   permission on the moving directory itself, because its `..` entry changes ([`remove_allowed`],
//!   [`rename_allowed`]).
//! - `chmod` needs the owner or user ID 0; a caller outside the file's group loses the
//!   set-group-ID bit it asked for (XSH `chmod()`).
//! - `chown` changes the owner only for user ID 0; the owner may change the group to the
//!   caller's own group or one of its supplementary groups (`_POSIX_CHOWN_RESTRICTED`, XSH
//!   `chown()`). A change clears the set-user-ID and set-group-ID bits of a non-directory;
//!   a directory keeps them so that group inheritance holds. A successful write clears them
//!   too ([`mode_after_write`], XSH `write()`).
//! - Choices that POSIX leaves to the implementation: `chown` clears the set-user-ID and
//!   set-group-ID bits of a non-directory for every caller, a privileged one included; `chmod`
//!   clears the set-group-ID bit (of a directory too) when the caller is outside the file's
//!   group; a write clears both bits; the owner may name the file's present group in `chown`
//!   whether or not it belongs to that group, because nothing changes.
//! - `futimens` with two "now" values needs the owner or write permission; two "omit" values
//!   need nothing; any other combination needs the owner or user ID 0 (XSH `futimens()`).
//! - `access` checks with the real IDs unless asked for the effective ones (XSH `access()`,
//!   `faccessat()` with `AT_EACCESS`).

#![no_std]

/// Read permission bit of a request (the value of `R_OK`).
pub const READ: u32 = 4;
/// Write permission bit of a request (the value of `W_OK`).
pub const WRITE: u32 = 2;
/// Execute or search permission bit of a request (the value of `X_OK`).
pub const EXEC: u32 = 1;
/// The set-user-ID mode bit.
pub const S_ISUID: u32 = 0o4000;
/// The set-group-ID mode bit.
pub const S_ISGID: u32 = 0o2000;
/// The sticky mode bit.
pub const S_ISVTX: u32 = 0o1000;
/// The permission bits and the three special bits of a mode.
pub const MODE_MASK: u32 = 0o7777;

/// Who asks: the user, the group and the supplementary groups.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity<'a> {
    pub uid: u32,
    pub gid: u32,
    pub groups: &'a [u32],
}

/// The identifiers of a process, from which a check picks the real or the effective pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ids {
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    pub egid: u32,
}

/// What a file is, as far as the rules care.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Directory,
    /// Regular files and every other kind.
    File,
}

/// The attributes the rules read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attr {
    pub kind: Kind,
    /// The permission bits and the special bits (`MODE_MASK`).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

/// The attributes of a new object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Created {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

/// What a change of owner and group leaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owned {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

/// Why a check failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denial {
    /// The caller lacks the permission bits: `EACCES`.
    Access,
    /// The caller lacks the standing (owner or user ID 0): `EPERM`.
    Permission,
}

/// What a `futimens` or `utimensat` call asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimesRequest {
    /// Both times omitted (`UTIME_OMIT`).
    Omit,
    /// Both times the present moment (`UTIME_NOW`).
    Now,
    /// Any other combination.
    Explicit,
}

impl<'a> Identity<'a> {
    #[inline]
    pub fn new(uid: u32, gid: u32, groups: &'a [u32]) -> Self {
        Self { uid, gid, groups }
    }

    /// The real pair when `real`, the effective pair otherwise.
    #[inline]
    pub fn of(ids: Ids, groups: &'a [u32], real: bool) -> Self {
        Self {
            uid: if real { ids.uid } else { ids.euid },
            gid: if real { ids.gid } else { ids.egid },
            groups,
        }
    }

    /// Whether the caller is a member of `gid`.
    #[inline]
    pub fn in_group(&self, gid: u32) -> bool {
        self.gid == gid || self.groups.contains(&gid)
    }
}

/// The access decision for `bits` (any of `READ`, `WRITE`, `EXEC`) by class (XBD 4.7).
#[inline]
pub fn permits(id: Identity<'_>, attr: &Attr, bits: u32) -> bool {
    if id.uid == 0 {
        return bits & EXEC == 0 || attr.kind == Kind::Directory || attr.mode & 0o111 != 0;
    }
    // The owner class applies to the owner alone, the group class to a member of the group
    // who is not the owner, the other class to everyone else (XBD 4.7).
    let class = if id.uid == attr.uid {
        attr.mode >> 6
    } else if id.in_group(attr.gid) {
        attr.mode >> 3
    } else {
        attr.mode
    };
    class & bits == bits
}

/// Whether the sticky bit of `parent` lets the caller remove or rename the entry `victim`.
#[inline]
pub fn sticky_allows(id: Identity<'_>, parent: &Attr, victim: &Attr) -> bool {
    parent.mode & S_ISVTX == 0 || id.uid == 0 || id.uid == parent.uid || id.uid == victim.uid
}

/// The attributes of a new object of `kind` in `parent`; `mode` is the requested mode and
/// `umask` the file creation mask of the process.
pub fn creation(id: Identity<'_>, parent: &Attr, kind: Kind, mode: u32, umask: u32) -> Created {
    let gid = if parent.mode & S_ISGID != 0 {
        parent.gid
    } else {
        id.gid
    };
    let mut mode = (mode & MODE_MASK & !(umask & 0o777))
        | if kind == Kind::Directory {
            parent.mode & S_ISGID
        } else {
            0
        };
    if kind != Kind::Directory && id.uid != 0 && !id.in_group(gid) {
        mode &= !S_ISGID;
    }
    Created {
        mode,
        uid: id.uid,
        gid,
    }
}

/// Whether the caller may remove the entry `victim` from `parent` (XSH `unlink()`, `rmdir()`):
/// [`Denial::Access`] without write and search on the parent, [`Denial::Permission`] when the
/// sticky bit of the parent forbids it.
#[inline]
pub fn remove_allowed(id: Identity<'_>, parent: &Attr, victim: &Attr) -> Result<(), Denial> {
    if !permits(id, parent, WRITE | EXEC) {
        return Err(Denial::Access);
    }
    if !sticky_allows(id, parent, victim) {
        return Err(Denial::Permission);
    }
    Ok(())
}

/// Whether the caller may put an entry in `to_parent`, over `target` when one exists there:
/// write and search on the parent, and the sticky rule for the target it replaces.
#[inline]
pub fn place_allowed(
    id: Identity<'_>,
    to_parent: &Attr,
    target: Option<&Attr>,
) -> Result<(), Denial> {
    if !permits(id, to_parent, WRITE | EXEC) {
        return Err(Denial::Access);
    }
    if let Some(target) = target
        && !sticky_allows(id, to_parent, target)
    {
        return Err(Denial::Permission);
    }
    Ok(())
}

/// Whether the caller may move `source` from `from_parent` to `to_parent` over `target`
/// (XSH `rename()`): the rules of [`remove_allowed`] for the source and of [`place_allowed`] for
/// the destination, and for a directory that changes its parent (`same_parent` false) write
/// permission on the directory itself, as its `..` entry changes.
pub fn rename_allowed(
    id: Identity<'_>,
    from_parent: &Attr,
    source: &Attr,
    to_parent: &Attr,
    target: Option<&Attr>,
    same_parent: bool,
) -> Result<(), Denial> {
    remove_allowed(id, from_parent, source)?;
    place_allowed(id, to_parent, target)?;
    if source.kind == Kind::Directory && !same_parent && !permits(id, source, WRITE) {
        return Err(Denial::Access);
    }
    Ok(())
}

/// The mode a `chmod` to `requested` leaves, or the refusal.
pub fn chmod_result(id: Identity<'_>, attr: &Attr, requested: u32) -> Result<u32, Denial> {
    if id.uid != 0 && id.uid != attr.uid {
        return Err(Denial::Permission);
    }
    let mut mode = requested & MODE_MASK;
    if id.uid != 0 && !id.in_group(attr.gid) {
        mode &= !S_ISGID;
    }
    Ok(mode)
}

/// Whether the caller may change the owner and group of `attr` to the given values, `None`
/// meaning "leave as is" (XSH `chown()`, `_POSIX_CHOWN_RESTRICTED`).
pub fn chown_allowed(id: Identity<'_>, attr: &Attr, uid: Option<u32>, gid: Option<u32>) -> bool {
    if id.uid == 0 {
        return true;
    }
    id.uid == attr.uid
        && uid.is_none_or(|u| u == attr.uid)
        && gid.is_none_or(|g| g == attr.gid || id.in_group(g))
}

/// The owner, group and mode a `chown` leaves, or the refusal. A non-directory loses its
/// set-user-ID and set-group-ID bits; a directory keeps them.
pub fn chown_result(
    id: Identity<'_>,
    attr: &Attr,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<Owned, Denial> {
    if !chown_allowed(id, attr, uid, gid) {
        return Err(Denial::Permission);
    }
    let mode = if attr.kind == Kind::Directory {
        attr.mode
    } else {
        attr.mode & !(S_ISUID | S_ISGID)
    };
    Ok(Owned {
        mode,
        uid: uid.unwrap_or(attr.uid),
        gid: gid.unwrap_or(attr.gid),
    })
}

/// The mode after a successful write to a file: the set-ID bits are cleared (XSH `write()`).
#[inline]
pub fn mode_after_write(mode: u32) -> u32 {
    mode & !(S_ISUID | S_ISGID)
}

/// The rule of `futimens` and `utimensat` (XSH `futimens()`). Two "now" values that fail give
/// [`Denial::Access`]; every other failure gives [`Denial::Permission`].
pub fn utimens_allowed(id: Identity<'_>, attr: &Attr, request: TimesRequest) -> Result<(), Denial> {
    let owner = id.uid == 0 || id.uid == attr.uid;
    match request {
        TimesRequest::Omit => Ok(()),
        _ if owner => Ok(()),
        TimesRequest::Now if permits(id, attr, WRITE) => Ok(()),
        TimesRequest::Now => Err(Denial::Access),
        TimesRequest::Explicit => Err(Denial::Permission),
    }
}

/// The decision of `access` and `faccessat`: `bits` is any of `READ`, `WRITE`, `EXEC`, or 0
/// for the existence check (the caller rejects other bits); `real` picks the real IDs (`access`), otherwise the effective ones
/// (`AT_EACCESS`).
pub fn access(ids: Ids, groups: &[u32], attr: &Attr, bits: u32, real: bool) -> Result<(), Denial> {
    if permits(Identity::of(ids, groups, real), attr, bits) {
        Ok(())
    } else {
        Err(Denial::Access)
    }
}

#[cfg(test)]
mod tests;
