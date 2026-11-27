// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The walk of a path through the index (sections 4 and 5.1): a probe for each component. `STEP`
//! (16) components is the measure of the walk's work: a step of the walk takes that many, and the
//! whole path runs in one request of the service (a path of 253 components is 16 steps of the walk
//! in one request). The walk decides which service the path belongs to:
//!
//! - a name of the layer of the user (`Upper`): a directory or a file of the live layer;
//! - the mark of deletion of a name, or a name below an opaque directory that the layer does not
//!   hold (`Absent`): ENOENT, whatever the lower set has;
//! - a name the index does not hold (`Lower`): the whole path goes to the RAM file service, which
//!   checks the rights on the lower attributes;
//! - a name below the root that `PASS_THROUGH` lists (`PassThrough`).
//!
//! A path is made plain before the walk (`normalize`): `.` and empty components go and `..` stays.
//! The walk takes a `..` in the index (the parent of a directory of the layer is exact), and a path
//! that leaves the index (the first lower name, or a name the root passes through) goes whole to the
//! RAM file service, which answers a `..` and the expansion of a link with a redirect that routes by
//! the path (its `layered` argument), so a `..` after a lower symbolic link to a directory is the
//! parent of the link's target, and a path that leaves the lower set by a `..` meets the marks and
//! the search checks of the layer. The POSIX layer still makes a path of a program simple, by text,
//! before it sends it (as for every service); a `..` that follows a link there is the parent of the
//! name of the link.
//!
//! A symbolic link of the layer (`Kind::Link`) in the middle of a path, or at the end when the call
//! follows links, ends the walk with `Outcome::Link`: the service answers a redirect that routes by
//! the path with the link's text where the component stood.
//!
//! Each directory of the layer the walk goes through is checked for the right to search with
//! `posix_perm::permits` on the attributes the index keeps (`Denied` is EACCES). The service checks
//! the directories of its own layer only; the lower directories are the RAM file service's to check
//! after the redirect, and a path is open when both pass (a directory the layer of the user opened
//! with `chmod` wider than its lower one stays closed, section 4 of the decision).

use crate::index::{Index, Kind, OPAQUE};
use posix_perm::{EXEC, Identity, permits};

/// The components one step of the walk takes: a measure of its work.
pub const STEP: usize = 16;

/// The path made plain: `.` and empty components dropped, `..` kept, and a slash at the end kept
/// when the path ended with a slash, `.` or `..` (a directory is meant). The bytes at the start of
/// `out` and their count; the result is never longer than `path`, so 512 bytes hold every path of
/// the protocol.
pub fn normalize(path: &[u8], out: &mut [u8; 512]) -> usize {
    normalize_dots(path, out).0
}

/// `normalize`, and whether a `..` component is in the plain path (it then does not name the chain
/// of the entry it leads to).
pub fn normalize_dots(path: &[u8], out: &mut [u8; 512]) -> (usize, bool) {
    // A path that is plain already (no empty component, no `.` or `..`) is itself: one pass over
    // its bytes and a copy, where the general walk over its components costs 35 ticks a byte
    // under -icount (17,000 for a path of 253 components).
    if path.len() <= out.len() && is_plain(path) {
        out[..path.len()].copy_from_slice(path);
        return (path.len(), false);
    }
    normalize_slow(path, out)
}

/// Whether `path` is absolute and has no `//`, no `.` and no `..` component: `normalize` of it is
/// the path itself (a slash at its end stays).
fn is_plain(path: &[u8]) -> bool {
    if path.first() != Some(&b'/') {
        return false;
    }
    let n = path.len();
    for (i, &b) in path.iter().enumerate() {
        if b != b'/' {
            continue;
        }
        // The component that follows this slash.
        match path.get(i + 1) {
            Some(b'/') => return false,
            Some(b'.') => match path.get(i + 2) {
                None | Some(b'/') => return false,
                Some(b'.') if i + 3 >= n || path[i + 3] == b'/' => return false,
                _ => {}
            },
            _ => {}
        }
    }
    true
}

fn normalize_slow(path: &[u8], out: &mut [u8; 512]) -> (usize, bool) {
    let mut dotted = false;
    let mut len = 0;
    let mut last: &[u8] = b"";
    for part in path.split(|&b| b == b'/') {
        match part {
            b"" => continue,
            b"." => {}
            name => {
                dotted |= name == b"..";
                if len + 1 + name.len() <= out.len() {
                    out[len] = b'/';
                    out[len + 1..len + 1 + name.len()].copy_from_slice(name);
                    len += 1 + name.len();
                }
            }
        }
        last = part;
    }
    if len == 0 {
        out[0] = b'/';
        return (1, dotted);
    }
    let directory = path.last() == Some(&b'/') || last == b"." || last == b"..";
    if directory && len < out.len() {
        out[len] = b'/';
        len += 1;
    }
    (len, dotted)
}

/// The components of a plain path (`normalize`): the names between its slashes.
pub fn components(plain: &[u8]) -> usize {
    plain
        .split(|&b| b == b'/')
        .filter(|p| !p.is_empty())
        .count()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The id of a name of the layer: 0 is the root of the layer, any other the entry's id.
    Upper(u32),
    /// A symbolic link of the layer: its id, and the bytes of the path where its component starts
    /// and ends.
    Link {
        id: u32,
        start: usize,
        end: usize,
    },
    Lower,
    PassThrough {
        data: bool,
    },
    Absent,
    /// A component that is no directory has a name after it.
    NotDir,
    Denied,
    NameTooLong,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    More,
    Done(Outcome),
}

/// The directories deep a walk carries the bit of: a path holds at most 253 components.
const HIDDEN_DEPTH: usize = 256;

/// Whether the lower set shows through the directory a walk is in: the bit of the directory
/// (set when it or a directory above it is opaque) and the bits of the directories above it, which
/// a `..` goes back to. A walk carries it from one step to the next, so that the question
/// costs no look at the index above the directory.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Hidden {
    bits: [u64; HIDDEN_DEPTH / 64],
    depth: u16,
    now: bool,
    started: bool,
}

impl Hidden {
    pub const fn new() -> Hidden {
        Hidden {
            bits: [0; HIDDEN_DEPTH / 64],
            depth: 0,
            now: false,
            started: false,
        }
    }

    fn push(&mut self) {
        let at = usize::from(self.depth);
        if at < HIDDEN_DEPTH {
            let (word, bit) = (at / 64, at % 64);
            self.bits[word] = (self.bits[word] & !(1 << bit)) | (u64::from(self.now) << bit);
            self.depth += 1;
        }
    }

    fn pop(&mut self) {
        if self.depth > 0 {
            self.depth -= 1;
            let at = usize::from(self.depth);
            self.now = self.bits[at / 64] >> (at % 64) & 1 != 0;
        }
    }
}

pub struct Walk<'p> {
    path: &'p [u8],
    pos: usize,
    cur: u32,
    hidden: Hidden,
    /// The bit of the directory the outcome names (see `hidden`).
    result: bool,
    /// A link at the end of the path is followed.
    follow: bool,
    /// Where a walk that ended with `Outcome::Lower` stopped: the directory of the layer and the
    /// place of the first name it does not hold.
    miss: (u32, usize),
}

impl<'p> Walk<'p> {
    /// A walk of the absolute `path`.
    pub fn new(path: &'p [u8]) -> Walk<'p> {
        Walk {
            path,
            pos: 0,
            cur: 0,
            hidden: Hidden::default(),
            result: false,
            follow: true,
            miss: (0, 0),
        }
    }

    /// A link at the end of the path is not followed (lstat, readlink, the leaf of a removal).
    pub fn no_follow(mut self) -> Walk<'p> {
        self.follow = false;
        self
    }

    /// The directory of the layer a walk that ended with `Outcome::Lower` was in, and where in
    /// the path the first name the layer does not hold starts.
    pub fn missed(&self) -> (u32, usize) {
        self.miss
    }

    /// A walk of `path` that went on to the byte `pos` of it, in the directory `cur`: the state a
    /// walk of several requests keeps (`pos` and `cur` of an earlier one of the same path).
    pub fn resume(path: &'p [u8], pos: usize, cur: u32, hidden: Hidden) -> Walk<'p> {
        Walk {
            path,
            pos,
            cur,
            hidden,
            result: false,
            follow: true,
            miss: (0, 0),
        }
    }

    /// Where the walk stands: the byte of the path and the directory it has reached.
    pub fn state(&self) -> (usize, u32, Hidden) {
        (self.pos, self.cur, self.hidden)
    }

    /// Whether the lower set is hidden from the directory the outcome names (an outcome of the
    /// layer: the directory itself and the ones above it; a miss: the directory the name is
    /// missing from).
    pub fn hidden(&self) -> bool {
        self.result
    }

    /// Whether the path ends with a slash: the name must be a directory.
    pub fn trailing_slash(&self) -> bool {
        self.path.len() > 1 && self.path.ends_with(b"/")
    }

    /// Takes at most `budget` components (`STEP`).
    pub fn advance(&mut self, index: &Index, who: Identity<'_>, budget: usize) -> Step {
        if !self.hidden.started {
            self.hidden.started = true;
            self.hidden.now = index.flags(0) & OPAQUE != 0;
        }
        for _ in 0..budget {
            // The next component: skip slashes, read the name.
            while self.pos < self.path.len() && self.path[self.pos] == b'/' {
                self.pos += 1;
            }
            if self.pos >= self.path.len() {
                self.result = self.hidden.now;
                return Step::Done(Outcome::Upper(self.cur));
            }
            let start = self.pos;
            while self.pos < self.path.len() && self.path[self.pos] != b'/' {
                self.pos += 1;
            }
            let name = &self.path[start..self.pos];
            let last = self.path[self.pos..].iter().all(|&b| b == b'/');
            if name == b"." {
                continue;
            }
            if name.len() > crate::index::NAME_MAX {
                return Step::Done(Outcome::NameTooLong);
            }
            if !cfg!(feature = "break-layerd-search") {
                let Some(attr) = index.attr(self.cur) else {
                    return Step::Done(Outcome::NotDir);
                };
                if !permits(who, &attr, EXEC) {
                    return Step::Done(Outcome::Denied);
                }
            }
            if name == b".." {
                self.cur = index.parent_of(self.cur);
                self.hidden.pop();
                continue;
            }
            if self.cur == 0 && proto_fs::names::PASS_THROUGH.contains(&name) {
                return Step::Done(Outcome::PassThrough {
                    data: name == b"data",
                });
            }
            match index.lookup(self.cur, name) {
                Some((_, e)) if e.kind == Kind::Whiteout => return Step::Done(Outcome::Absent),
                Some((id, e))
                    if e.kind == Kind::Link && (!last || self.follow || self.trailing_slash()) =>
                {
                    return Step::Done(Outcome::Link {
                        id,
                        start,
                        end: self.pos,
                    });
                }
                Some((id, e)) if last => {
                    self.result = self.hidden.now || e.flags & OPAQUE != 0;
                    return Step::Done(if e.kind == Kind::File && self.trailing_slash() {
                        Outcome::NotDir
                    } else {
                        Outcome::Upper(id)
                    });
                }
                Some((id, e)) if e.kind == Kind::Dir => {
                    self.hidden.push();
                    self.hidden.now |= e.flags & OPAQUE != 0;
                    self.cur = id;
                }
                Some(_) => return Step::Done(Outcome::NotDir),
                None if self.hidden.now => {
                    self.result = true;
                    return Step::Done(Outcome::Absent);
                }
                None => {
                    self.result = false;
                    self.miss = (self.cur, start);
                    return Step::Done(Outcome::Lower);
                }
            }
        }
        Step::More
    }

    /// The whole walk, step after step; the number of steps it took.
    pub fn run(mut self, index: &Index, who: Identity<'_>) -> (Outcome, usize) {
        let mut steps = 0;
        loop {
            steps += 1;
            if let Step::Done(outcome) = self.advance(index, who, STEP) {
                return (outcome, steps);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{Fields, OPAQUE};
    use std::boxed::Box;

    fn who(uid: u32) -> Identity<'static> {
        Identity::new(uid, uid, &[])
    }

    fn fields(kind: Kind, mode: u16, uid: u32) -> Fields {
        Fields {
            kind,
            layer: 0,
            number: 1,
            uid,
            gid: uid,
            mode,
        }
    }

    /// /etc (0755), /etc/hostname, /etc/.wh. for motd, /priv (0700 root) with /priv/x,
    /// /opaque (opaque) with /opaque/inside, /file.
    fn world() -> Box<Index> {
        let mut ix = crate::index::boxed();
        ix.root.mode = 0o755;
        let etc = ix.insert(0, b"etc", fields(Kind::Dir, 0o755, 0)).unwrap();
        ix.insert(etc, b"hostname", fields(Kind::File, 0o644, 0))
            .unwrap();
        ix.insert(etc, b"motd", fields(Kind::Whiteout, 0, 0))
            .unwrap();
        let private = ix.insert(0, b"priv", fields(Kind::Dir, 0o700, 0)).unwrap();
        ix.insert(private, b"x", fields(Kind::File, 0o600, 0))
            .unwrap();
        let opaque = ix
            .insert(0, b"opaque", fields(Kind::Dir, 0o755, 0))
            .unwrap();
        ix.set_flags(opaque, OPAQUE, 0);
        ix.insert(opaque, b"inside", fields(Kind::File, 0o644, 0))
            .unwrap();
        ix.insert(0, b"file", fields(Kind::File, 0o644, 0)).unwrap();
        ix
    }

    fn walk(ix: &Index, path: &[u8], uid: u32) -> Outcome {
        Walk::new(path).run(ix, who(uid)).0
    }

    fn id(ix: &Index, parent: u32, name: &[u8]) -> u32 {
        ix.lookup(parent, name).unwrap().0
    }

    fn plain(path: &[u8]) -> std::vec::Vec<u8> {
        let mut out = [0u8; 512];
        let n = normalize(path, &mut out);
        out[..n].to_vec()
    }

    #[test]
    fn the_hidden_bit_goes_down_with_the_walk_up_with_dots_and_across_resumed_steps() {
        let ix = world();
        let hidden_after = |path: &[u8], budget: usize| {
            // One component at a time: the state a job keeps between its steps.
            let (mut pos, mut cur, mut bits) = (0, 0, Hidden::default());
            loop {
                let mut w = Walk::resume(path, pos, cur, bits);
                let step = w.advance(&ix, who(0), budget);
                (pos, cur, bits) = w.state();
                if let Step::Done(o) = step {
                    return (o, w.hidden());
                }
            }
        };
        let etc = id(&ix, 0, b"etc");
        let opaque = id(&ix, 0, b"opaque");
        for budget in [1, 2, 8] {
            assert_eq!(hidden_after(b"/etc/zz", budget), (Outcome::Lower, false));
            assert_eq!(hidden_after(b"/opaque/zz", budget), (Outcome::Absent, true));
            assert_eq!(
                hidden_after(b"/opaque", budget),
                (Outcome::Upper(opaque), true)
            );
            assert_eq!(hidden_after(b"/etc", budget), (Outcome::Upper(etc), false));
            // Out of the opaque directory by `..`: the lower set shows through again.
            assert_eq!(
                hidden_after(b"/opaque/../etc/zz", budget),
                (Outcome::Lower, false)
            );
            assert_eq!(
                hidden_after(b"/etc/../opaque/zz", budget),
                (Outcome::Absent, true)
            );
        }
    }

    #[test]
    fn a_path_is_made_plain_before_the_walk() {
        for (path, want) in [
            ("/", "/"),
            ("//", "/"),
            ("/a/b", "/a/b"),
            ("/a//b/./c", "/a/b/c"),
            ("/a/b/..", "/a/b/../"),
            ("/a/b/../c", "/a/b/../c"),
            ("/bin/../etc/x", "/bin/../etc/x"),
            ("/..", "/../"),
            ("/a/", "/a/"),
            ("/a/.", "/a/"),
            ("/a/./", "/a/"),
            ("/tmp/..", "/tmp/../"),
        ] {
            assert_eq!(plain(path.as_bytes()), want.as_bytes(), "{path}");
        }
        // Never longer than the path.
        let long: std::vec::Vec<u8> = (0..255).flat_map(|_| *b"/a").collect();
        assert!(plain(&long).len() <= long.len());
    }

    #[test]
    fn a_dot_dot_after_a_lower_name_ends_the_walk_there_and_one_before_it_is_exact() {
        let ix = world();
        // The walk stops at the first name of the lower set (the RAM file service answers the
        // `..` after it with a redirect that routes by the path) and at a name the root passes
        // through.
        assert_eq!(walk(&ix, b"/bin/../etc/motd", 0), Outcome::Lower);
        assert_eq!(walk(&ix, b"/bin/../priv/x", 1000), Outcome::Lower);
        assert_eq!(
            walk(&ix, b"/tmp/../etc/motd", 0),
            Outcome::PassThrough { data: false }
        );
        // Through the layer the parent is exact: the marks and the search checks hold.
        assert_eq!(walk(&ix, b"/etc/../etc/motd", 0), Outcome::Absent);
        assert_eq!(walk(&ix, b"/etc/../priv/x", 1000), Outcome::Denied);
        assert!(matches!(
            walk(&ix, b"/etc/../etc/hostname", 0),
            Outcome::Upper(_)
        ));
    }

    #[test]
    fn names_of_the_layer_are_upper_and_the_rest_goes_whole_to_the_lower_set() {
        let ix = world();
        let etc = id(&ix, 0, b"etc");
        assert_eq!(walk(&ix, b"/", 1000), Outcome::Upper(0));
        assert_eq!(walk(&ix, b"/etc", 1000), Outcome::Upper(etc));
        assert_eq!(walk(&ix, b"//etc/./", 1000), Outcome::Upper(etc));
        assert_eq!(
            walk(&ix, b"/etc/hostname", 1000),
            Outcome::Upper(id(&ix, etc, b"hostname"))
        );
        assert_eq!(walk(&ix, b"/bin/ls", 1000), Outcome::Lower);
        assert_eq!(walk(&ix, b"/etc/passwd", 1000), Outcome::Lower);
        assert_eq!(walk(&ix, b"/etc/../bin/ls", 1000), Outcome::Lower);
        assert_eq!(walk(&ix, b"/etc/..", 1000), Outcome::Upper(0));
        assert_eq!(walk(&ix, b"/..", 1000), Outcome::Upper(0));
        assert_eq!(
            walk(&ix, b"/etc/../etc/hostname", 1000),
            walk(&ix, b"/etc/hostname", 1000)
        );
    }

    #[test]
    fn a_mark_of_deletion_and_an_opaque_directory_hide_the_lower_set() {
        let ix = world();
        assert_eq!(walk(&ix, b"/etc/motd", 0), Outcome::Absent);
        assert_eq!(walk(&ix, b"/etc/motd/x", 0), Outcome::Absent);
        assert_eq!(walk(&ix, b"/opaque/lower-name", 0), Outcome::Absent);
        assert!(matches!(walk(&ix, b"/opaque/inside", 0), Outcome::Upper(_)));
        // The directory above the opaque one is not opaque.
        assert_eq!(walk(&ix, b"/other", 0), Outcome::Lower);
    }

    #[test]
    fn a_directory_closed_to_the_caller_is_denied_and_the_superuser_passes() {
        let ix = world();
        assert_eq!(walk(&ix, b"/priv/x", 1000), Outcome::Denied);
        assert_eq!(walk(&ix, b"/priv/nothing", 1000), Outcome::Denied);
        assert!(matches!(walk(&ix, b"/priv/x", 0), Outcome::Upper(_)));
        // The directory itself can be named: only the search of its contents is checked.
        assert!(matches!(walk(&ix, b"/priv", 1000), Outcome::Upper(_)));
        // The root of the layer is checked too.
        let mut closed = world();
        closed.root.mode = 0o700;
        assert_eq!(walk(&closed, b"/etc", 1000), Outcome::Denied);
        assert_eq!(walk(&closed, b"/", 1000), Outcome::Upper(0));
    }

    #[test]
    fn a_file_with_a_name_after_it_is_not_a_directory() {
        let ix = world();
        assert_eq!(walk(&ix, b"/file/x", 0), Outcome::NotDir);
        assert_eq!(walk(&ix, b"/file/", 0), Outcome::NotDir);
        assert_eq!(walk(&ix, b"/file/.", 0), Outcome::NotDir);
        assert!(matches!(walk(&ix, b"/file", 0), Outcome::Upper(_)));
        assert_eq!(
            walk(&ix, &[b"/".as_slice(), &[b'a'; 256]].concat(), 0),
            Outcome::NameTooLong
        );
    }

    #[test]
    fn the_names_the_root_passes_through_never_reach_the_index() {
        let mut ix = world();
        ix.insert(0, b"tmp", fields(Kind::Dir, 0o755, 0)).unwrap();
        assert_eq!(
            walk(&ix, b"/data/x", 0),
            Outcome::PassThrough { data: true }
        );
        assert_eq!(walk(&ix, b"/tmp", 0), Outcome::PassThrough { data: false });
        assert_eq!(
            walk(&ix, b"/etc/../run/x", 0),
            Outcome::PassThrough { data: false }
        );
        assert_eq!(walk(&ix, b"/etc/tmp", 0), Outcome::Lower);
    }

    /// The fast path of `normalize` gives what the walk over the components gives, for plain paths
    /// and for the ones with dots, slashes and a slash at the end.
    #[test]
    fn a_plain_path_is_normalized_as_the_general_walk_does() {
        let paths: [&[u8]; 22] = [
            b"/",
            b"/a",
            b"/a/",
            b"/a/b/c",
            b"/a/b/c/",
            b"//a",
            b"/a//b",
            b"/a/./b",
            b"/a/.",
            b"/a/..",
            b"/a/../b",
            b"/a/b/..",
            b"/.a/..b/c.",
            b"/a/.../b",
            b"/..",
            b"/../a",
            b"/a/b/../../..",
            b"a/b",
            b"",
            b"/a/b/./",
            b"/.hidden",
            b"/a/..b",
        ];
        for path in paths {
            let (mut fast, mut slow) = ([0u8; 512], [0u8; 512]);
            let a = normalize(path, &mut fast);
            let b = normalize_slow(path, &mut slow).0;
            assert_eq!(&fast[..a], &slow[..b], "{:?}", std::str::from_utf8(path));
        }
    }

    #[test]
    fn a_deep_path_takes_a_step_for_every_sixteen_components() {
        let mut ix = crate::index::boxed();
        let mut parent = 0;
        let mut path = std::vec::Vec::new();
        for i in 0..40 {
            let name = std::format!("d{i}");
            parent = ix
                .insert(parent, name.as_bytes(), fields(Kind::Dir, 0o755, 0))
                .unwrap();
            path.extend_from_slice(b"/");
            path.extend_from_slice(name.as_bytes());
        }
        let (outcome, steps) = Walk::new(&path).run(&ix, who(0));
        assert_eq!(outcome, Outcome::Upper(parent));
        // 40 components, 16 a step: three steps, the last one finds the end.
        assert_eq!(steps, 3);
        let mut w = Walk::new(&path);
        assert_eq!(w.advance(&ix, who(0), STEP), Step::More);
        assert_eq!(w.advance(&ix, who(0), STEP), Step::More);
        assert!(matches!(w.advance(&ix, who(0), STEP), Step::Done(_)));
        // 253 components of one letter is 16 steps.
        let mut ix = crate::index::boxed();
        let mut parent = 0;
        for _ in 0..253 {
            parent = ix
                .insert(parent, b"a", fields(Kind::Dir, 0o755, 0))
                .unwrap();
        }
        let long: std::vec::Vec<u8> = (0..253).flat_map(|_| *b"/a").collect();
        assert_eq!(long.len(), 506);
        assert_eq!(
            Walk::new(&long).run(&ix, who(0)),
            (Outcome::Upper(parent), 16)
        );
    }
}
