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
//! A path is made plain before the walk (`normalize`): `.` and empty components go and `..` takes
//! the component before it, lexically, so the walk meets no `..` and the path a redirect carries has
//! none either (a `..` the walk met after it left the index would let `/bin/../etc/x` reach a name
//! the layer deleted or shadowed). The departure: a lower symbolic link to a directory is not
//! looked through for `..` (`/lowlink/..` is the parent of the link's name, not of its target); a
//! later part makes the RAM file service answer `..` with a redirect to route by the path, and
//! removes this.
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

/// The path made plain: `.` and empty components dropped, `..` taking the component before it (at
/// the root it takes nothing), and a slash at the end kept when the path ended with a slash, `.` or
/// `..` (a directory is meant). The bytes at the start of `out` and their count; the result is never
/// longer than `path`, so 512 bytes hold every path of the protocol.
pub fn normalize(path: &[u8], out: &mut [u8; 512]) -> usize {
    let mut len = 0;
    let mut last: &[u8] = b"";
    for part in path.split(|&b| b == b'/') {
        match part {
            b"" => continue,
            b"." => {}
            b".." => len = out[..len].iter().rposition(|&b| b == b'/').unwrap_or(0),
            name => {
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
        return 1;
    }
    let directory = path.last() == Some(&b'/') || last == b"." || last == b"..";
    if directory && len < out.len() {
        out[len] = b'/';
        len += 1;
    }
    len
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The id of a name of the layer: 0 is the root of the layer, any other the entry's id.
    Upper(u32),
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

pub struct Walk<'p> {
    path: &'p [u8],
    pos: usize,
    cur: u32,
}

impl<'p> Walk<'p> {
    /// A walk of the absolute `path`.
    pub fn new(path: &'p [u8]) -> Walk<'p> {
        Walk {
            path,
            pos: 0,
            cur: 0,
        }
    }

    /// Whether the path ends with a slash: the name must be a directory.
    pub fn trailing_slash(&self) -> bool {
        self.path.len() > 1 && self.path.ends_with(b"/")
    }

    /// Takes at most `budget` components (`STEP`).
    pub fn advance(&mut self, index: &Index, who: Identity<'_>, budget: usize) -> Step {
        for _ in 0..budget {
            // The next component: skip slashes, read the name.
            while self.pos < self.path.len() && self.path[self.pos] == b'/' {
                self.pos += 1;
            }
            if self.pos >= self.path.len() {
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
                self.cur = index.entry(self.cur).map_or(0, |e| e.parent());
                continue;
            }
            if self.cur == 0 && proto_fs::names::PASS_THROUGH.contains(&name) {
                return Step::Done(Outcome::PassThrough {
                    data: name == b"data",
                });
            }
            match index.lookup(self.cur, name) {
                Some((_, e)) if e.kind == Kind::Whiteout => return Step::Done(Outcome::Absent),
                Some((id, e)) if last => {
                    return Step::Done(if e.kind == Kind::File && self.trailing_slash() {
                        Outcome::NotDir
                    } else {
                        Outcome::Upper(id)
                    });
                }
                Some((id, e)) if e.kind == Kind::Dir => self.cur = id,
                Some(_) => return Step::Done(Outcome::NotDir),
                None if index.flags(self.cur) & OPAQUE != 0 => return Step::Done(Outcome::Absent),
                None => return Step::Done(Outcome::Lower),
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
    use crate::index::Fields;
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
        let mut ix = Box::new(Index::new());
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
    fn a_path_is_made_plain_before_the_walk() {
        for (path, want) in [
            ("/", "/"),
            ("//", "/"),
            ("/a/b", "/a/b"),
            ("/a//b/./c", "/a/b/c"),
            ("/a/b/..", "/a/"),
            ("/a/b/../c", "/a/c"),
            ("/bin/../etc/x", "/etc/x"),
            ("/..", "/"),
            ("/../a", "/a"),
            ("/a/../..", "/"),
            ("/a/", "/a/"),
            ("/a/.", "/a/"),
            ("/a/./", "/a/"),
            ("/tmp/..", "/"),
        ] {
            assert_eq!(plain(path.as_bytes()), want.as_bytes(), "{path}");
        }
        // Never longer than the path.
        let long: std::vec::Vec<u8> = (0..255).flat_map(|_| *b"/a").collect();
        assert!(plain(&long).len() <= long.len());
    }

    #[test]
    fn a_dot_dot_after_a_lower_name_meets_the_marks_and_the_search_checks_of_the_layer() {
        let ix = world();
        let walk_plain = |path: &[u8], uid: u32| {
            let mut out = [0u8; 512];
            let n = normalize(path, &mut out);
            walk(&ix, &out[..n], uid)
        };
        // /bin is the lower set's; /etc/motd is deleted and /priv is closed in the layer.
        assert_eq!(walk_plain(b"/bin/../etc/motd", 0), Outcome::Absent);
        assert_eq!(walk_plain(b"/bin/../priv/x", 1000), Outcome::Denied);
        assert_eq!(walk_plain(b"/tmp/../etc/motd", 0), Outcome::Absent);
        assert!(matches!(
            walk_plain(b"/data/../etc/hostname", 0),
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

    #[test]
    fn a_deep_path_takes_a_step_for_every_sixteen_components() {
        let mut ix = Box::new(Index::new());
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
        let mut ix = Box::new(Index::new());
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
