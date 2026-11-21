// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The account files of stafeto: `/etc/passwd`, `/etc/group` and `/etc/shadow` of the image, and
//! the copies of them that `datakey` keeps on the data volume. At each boot the service merges the
//! two sets with `merge`, and the result goes into the RAM file service. The merge is the one
//! place that decides what a volume may bring:
//!
//! - An account of the image keeps its name, its user and group number, and the fields of its
//!   passwd line (the home of `user` may be named by the caller, with a volume). From the volume it
//!   takes the whole line of `/etc/shadow` (so a password set with `passwd root` stays) and the
//!   member list of each image group.
//! - An account of the volume that the image lacks is accepted when its user number is 1000 or
//!   more and not 65534, no account of the image or accepted before it has that number, and its
//!   group exists. A group of the volume that the image lacks needs a group number of 1000 or more
//!   and not 65534 that nobody else has. What is refused is reported once, by name.
//! - An account or group of the image that the volume lacks is added, with the shadow line of the
//!   image (locked), so a new image brings its own accounts back and a deleted one returns
//!   locked.
//! - An entry of the volume with number 0 under any name but `root` is never accepted (it would
//!   need a number below 1000 and the image holds the only such entries). A line that does not
//!   have 7 fields (passwd), 4 (group) or 9 (shadow), or has a name that is not
//!   `[a-z_][a-z0-9_-]*` of 32 characters at most, or a control character, is dropped.
//! - The first field of every shadow line the merge gives is a lock or a hash: an empty field
//!   becomes `!`, and an account with no line gets `!`.
//!
//! No allocator: the inputs are slices and the outputs are the fixed buffers of `Merged`.

#![no_std]

#[cfg(test)]
extern crate std;

/// The largest file the merge reads or gives, in bytes.
pub const FILE_MAX: usize = 4096;
/// The most accounts (and groups) the merge keeps.
pub const ENTRIES_MAX: usize = 48;
/// The longest name.
pub const NAME_MAX: usize = 32;
/// The longest hash or other field.
const FIELD_MAX: usize = 256;

/// The three files of a set.
#[derive(Clone, Copy, Default)]
pub struct Files<'a> {
    pub passwd: &'a [u8],
    pub group: &'a [u8],
    pub shadow: &'a [u8],
}

/// A file of the result.
pub struct Buf {
    bytes: [u8; FILE_MAX],
    len: usize,
    /// The result did not fit and an entry was left out.
    pub full: bool,
}

impl Buf {
    const fn new() -> Buf {
        Buf {
            bytes: [0; FILE_MAX],
            len: 0,
            full: false,
        }
    }

    /// The bytes written.
    pub fn data(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Whether `parts` fit after what is there: they are all written or none is.
    fn push(&mut self, parts: &[&[u8]]) -> bool {
        let total: usize = parts.iter().map(|p| p.len()).sum();
        if self.len + total > FILE_MAX {
            self.full = true;
            return false;
        }
        for part in parts {
            self.bytes[self.len..self.len + part.len()].copy_from_slice(part);
            self.len += part.len();
        }
        true
    }
}

/// The three files the merge gives.
pub struct Merged {
    pub passwd: Buf,
    pub group: Buf,
    pub shadow: Buf,
}

impl Merged {
    pub const fn new() -> Merged {
        Merged {
            passwd: Buf::new(),
            group: Buf::new(),
            shadow: Buf::new(),
        }
    }
}

impl Default for Merged {
    fn default() -> Merged {
        Merged::new()
    }
}

/// Why an entry of the volume was left out.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reason {
    /// The line is not well formed (the number of fields, the name or a number).
    Malformed,
    /// The user number is under 1000, or 65534.
    UidRange,
    /// The group number is under 1000, or 65534.
    GidRange,
    /// Another account or group has the number.
    NumberTaken,
    /// The name is taken (twice on the volume).
    NameTaken,
    /// The account's group is in no group.
    NoGroup,
    /// The result is full.
    Full,
}

/// One entry left out: the kind of file, the name (as far as it was read) and the reason.
pub struct Note<'a> {
    pub file: &'static str,
    pub name: &'a [u8],
    pub reason: Reason,
}

/// A passwd line read.
#[derive(Clone, Copy)]
struct Pw<'a> {
    name: &'a [u8],
    uid: u32,
    gid: u32,
    gecos: &'a [u8],
    home: &'a [u8],
    shell: &'a [u8],
}

/// A group line read.
#[derive(Clone, Copy)]
struct Gr<'a> {
    name: &'a [u8],
    gid: u32,
    members: &'a [u8],
}

/// A shadow line read: the whole line without its newline, and the first field's place.
#[derive(Clone, Copy)]
struct Sh<'a> {
    name: &'a [u8],
    hash: &'a [u8],
    /// The fields after the hash, from the third to the ninth, with their colons.
    rest: &'a [u8],
}

fn lines(file: &[u8]) -> impl Iterator<Item = &[u8]> {
    file.split(|&b| b == b'\n').filter(|l| !l.is_empty())
}

/// The fields of a line, or None when there are more than `N`.
fn fields<const N: usize>(line: &[u8]) -> Option<([&[u8]; N], usize)> {
    let mut out: [&[u8]; N] = [&[]; N];
    let mut count = 0;
    for field in line.split(|&b| b == b':') {
        if count == N {
            return None;
        }
        out[count] = field;
        count += 1;
    }
    Some((out, count))
}

/// A name of `[a-z_][a-z0-9_-]*`, 32 characters at most.
pub fn valid_name(name: &[u8]) -> bool {
    let Some((&first, rest)) = name.split_first() else {
        return false;
    };
    name.len() <= NAME_MAX
        && (first.is_ascii_lowercase() || first == b'_')
        && rest
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// A field with no control character and no colon (the split took the colons already), short.
fn plain(field: &[u8]) -> bool {
    field.len() <= FIELD_MAX && field.iter().all(|&b| b >= 0x20 && b != 0x7f)
}

fn number(field: &[u8]) -> Option<u32> {
    if field.is_empty() || field.len() > 10 || !field.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut value: u64 = 0;
    for &b in field {
        value = value * 10 + u64::from(b - b'0');
    }
    // 4294967295 is -1 in the C types.
    u32::try_from(value).ok().filter(|&v| v != u32::MAX)
}

fn passwd_line(line: &[u8]) -> Option<Pw<'_>> {
    let (f, count) = fields::<7>(line)?;
    if count != 7
        || !valid_name(f[0])
        || f[1] != b"x"
        || !(plain(f[4]) && plain(f[5]) && plain(f[6]))
        || f[5].len() > 128
        || f[6].len() > 64
        || (!f[5].is_empty() && f[5][0] != b'/')
        || (!f[6].is_empty() && f[6][0] != b'/')
    {
        return None;
    }
    Some(Pw {
        name: f[0],
        uid: number(f[2])?,
        gid: number(f[3])?,
        gecos: f[4],
        home: f[5],
        shell: f[6],
    })
}

fn group_line(line: &[u8]) -> Option<Gr<'_>> {
    let (f, count) = fields::<4>(line)?;
    if count != 4 || !valid_name(f[0]) || f[1] != b"x" || !plain(f[3]) {
        return None;
    }
    Some(Gr {
        name: f[0],
        gid: number(f[2])?,
        members: f[3],
    })
}

fn shadow_line(line: &[u8]) -> Option<Sh<'_>> {
    let (f, count) = fields::<9>(line)?;
    if count != 9 || !valid_name(f[0]) || !plain(f[1]) || f[1].contains(&b' ') {
        return None;
    }
    // The numeric fields are digits or empty.
    if !f[2..8]
        .iter()
        .all(|x| x.len() <= 10 && x.iter().all(u8::is_ascii_digit))
        || !f[8].is_empty() && !f[8].iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    // `rest` runs from the colon after the hash to the end of the line.
    let rest = &line[f[0].len() + 1 + f[1].len()..];
    Some(Sh {
        name: f[0],
        hash: f[1],
        rest,
    })
}

/// The decimal digits of `n`.
fn decimal(n: u32, buf: &mut [u8; 10]) -> &[u8] {
    let mut at = buf.len();
    let mut n = n;
    loop {
        at -= 1;
        buf[at] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    &buf[at..]
}

/// What `merge` is given besides the two sets.
#[derive(Clone, Copy, Default)]
pub struct Options<'a> {
    /// The home an image account gets in the result: `(name, home)`. A boot with a data volume
    /// puts the home of `user` there.
    pub home: Option<(&'a [u8], &'a [u8])>,
}

/// The first line of `file` that `read` takes and whose name is `name`.
fn find<'a, T: Copy>(
    file: &'a [u8],
    name: &[u8],
    read: impl Fn(&'a [u8]) -> Option<T>,
    name_of: impl Fn(&T) -> &'a [u8],
) -> Option<T> {
    lines(file).filter_map(&read).find(|x| name_of(x) == name)
}

/// Merges the files of the image with those of the volume into `out`; `note` hears what the
/// volume brought that was refused.
pub fn merge(
    image: &Files<'_>,
    volume: &Files<'_>,
    options: &Options<'_>,
    out: &mut Merged,
    note: &mut dyn FnMut(Note<'_>),
) {
    // The groups: those of the image, with the members of the volume's line of the same name.
    let mut gids = [0u32; ENTRIES_MAX];
    let mut group_count = 0;
    for g in lines(image.group).filter_map(group_line) {
        if group_count == ENTRIES_MAX {
            break;
        }
        let from_volume = find(volume.group, g.name, group_line, |x| x.name);
        let members = from_volume.map_or(g.members, |v| v.members);
        if write_group(&mut out.group, g.name, g.gid, members) {
            gids[group_count] = g.gid;
            group_count += 1;
        }
    }
    let image_groups = group_count;
    for g in lines(volume.group) {
        let Some(g) = group_line(g) else {
            note(Note {
                file: "group",
                name: g.split(|&b| b == b':').next().unwrap_or(&[]),
                reason: Reason::Malformed,
            });
            continue;
        };
        if find(image.group, g.name, group_line, |x| x.name).is_some() {
            continue;
        }
        let mut refuse = |reason| {
            note(Note {
                file: "group",
                name: g.name,
                reason,
            })
        };
        if g.gid < 1000 || g.gid == 65534 {
            refuse(Reason::GidRange);
        } else if gids[..group_count].contains(&g.gid) {
            refuse(Reason::NumberTaken);
        } else if group_count == ENTRIES_MAX {
            refuse(Reason::Full);
        } else if find(volume.group, g.name, group_line, |x| x.name)
            .is_some_and(|first| first.gid != g.gid)
        {
            // The name is twice on the volume with two numbers: the first line is the one.
            refuse(Reason::NameTaken);
        } else if write_group(&mut out.group, g.name, g.gid, g.members) {
            gids[group_count] = g.gid;
            group_count += 1;
        } else {
            refuse(Reason::Full);
        }
    }
    let _ = image_groups;

    // The accounts: those of the image, then the volume's that are fit.
    let mut uids = [0u32; ENTRIES_MAX];
    let mut names: [&[u8]; ENTRIES_MAX] = [&[]; ENTRIES_MAX];
    let mut from_image = [false; ENTRIES_MAX];
    let mut count = 0;
    for p in lines(image.passwd).filter_map(passwd_line) {
        if count == ENTRIES_MAX {
            break;
        }
        let home = match options.home {
            Some((name, home)) if name == p.name => home,
            _ => p.home,
        };
        if write_passwd(&mut out.passwd, &Pw { home, ..p }) {
            uids[count] = p.uid;
            names[count] = p.name;
            from_image[count] = true;
            count += 1;
        }
    }
    for line in lines(volume.passwd) {
        let Some(p) = passwd_line(line) else {
            note(Note {
                file: "passwd",
                name: line.split(|&b| b == b':').next().unwrap_or(&[]),
                reason: Reason::Malformed,
            });
            continue;
        };
        if names[..count].contains(&p.name) {
            // An account of the image, or a name the volume holds twice: the first stays.
            if !from_image[names[..count]
                .iter()
                .position(|n| *n == p.name)
                .unwrap_or(0)]
            {
                note(Note {
                    file: "passwd",
                    name: p.name,
                    reason: Reason::NameTaken,
                });
            }
            continue;
        }
        let mut refuse = |reason| {
            note(Note {
                file: "passwd",
                name: p.name,
                reason,
            })
        };
        if p.uid < 1000 || p.uid == 65534 {
            refuse(Reason::UidRange);
        } else if uids[..count].contains(&p.uid) {
            refuse(Reason::NumberTaken);
        } else if !gids[..group_count].contains(&p.gid) {
            refuse(Reason::NoGroup);
        } else if count == ENTRIES_MAX || !write_passwd(&mut out.passwd, &p) {
            refuse(Reason::Full);
        } else {
            uids[count] = p.uid;
            names[count] = p.name;
            count += 1;
        }
    }

    // The shadow lines, one for each account in the order of the passwd file.
    for (i, name) in names[..count].iter().enumerate() {
        let line = find(volume.shadow, name, shadow_line, |x| x.name).or_else(|| {
            find(image.shadow, name, shadow_line, |x| x.name).filter(|_| from_image[i])
        });
        let hash: &[u8] = match line {
            Some(l) if !l.hash.is_empty() => l.hash,
            _ => b"!",
        };
        let rest: &[u8] = line.map_or(b":20000:0:99999:7:::", |l| l.rest);
        out.shadow.push(&[name, b":", hash, rest, b"\n"]);
    }
}

fn write_passwd(buf: &mut Buf, p: &Pw<'_>) -> bool {
    let (mut u, mut g) = ([0u8; 10], [0u8; 10]);
    let uid = decimal(p.uid, &mut u);
    let gid = decimal(p.gid, &mut g);
    buf.push(&[
        p.name, b":x:", uid, b":", gid, b":", p.gecos, b":", p.home, b":", p.shell, b"\n",
    ])
}

fn write_group(buf: &mut Buf, name: &[u8], gid: u32, members: &[u8]) -> bool {
    let mut g = [0u8; 10];
    let gid = decimal(gid, &mut g);
    // The members: the valid names of the list, in order.
    let mut kept = [0u8; 512];
    let mut len = 0;
    for member in members.split(|&b| b == b',').filter(|m| valid_name(m)) {
        let need = member.len() + usize::from(len > 0);
        if len + need > kept.len() {
            break;
        }
        if len > 0 {
            kept[len] = b',';
            len += 1;
        }
        kept[len..len + member.len()].copy_from_slice(member);
        len += member.len();
    }
    buf.push(&[name, b":x:", gid, b":", &kept[..len], b"\n"])
}

#[cfg(test)]
mod tests;
