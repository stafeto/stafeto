// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The files of the boot image next to the fixed tree of the service: the
//! table `rootfs` (bootimg::rootfs) gives each its path, mode and owner,
//! and the file of the image its bytes, which the service reads where they
//! lie in the mapped image, without a copy. `Index` is the table of the
//! service's `.bss` (the parent, the children and the links of each entry,
//! built once at the start); `Tree` joins it with the image.

#[cfg(test)]
extern crate alloc;

use bootimg::BootImage;
use bootimg::rootfs::{ENTRIES_MAX, Entry, FILES_MAX, Rootfs};

/// The name of the image's file with the table.
pub const ROOTFS: &str = "rootfs";
/// The slot after the last entry stands for `/`.
const ROOT: usize = ENTRIES_MAX;
const NONE: u16 = u16::MAX;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The image has no file `rootfs`.
    Missing,
    /// The image or the table is not well formed.
    Image(bootimg::Error),
    Table(bootimg::rootfs::Error),
    /// An entry lies at or under `/etc` or `/tmp`, which the service owns.
    Reserved(u32),
}

/// What the service keeps of the table: for each entry (and `/`, in the
/// last slot) its parent, the place of its children among `kids`, the
/// entry whose inode it shares, and its link count.
pub struct Index {
    parent: [u16; ENTRIES_MAX + 1],
    first: [u16; ENTRIES_MAX + 1],
    count: [u16; ENTRIES_MAX + 1],
    kids: [u16; ENTRIES_MAX],
    canon: [u16; ENTRIES_MAX],
    links: [u16; ENTRIES_MAX + 1],
    /// Scratch of `fill`: the first entry of each file, and its entries.
    file_first: [u16; FILES_MAX],
    file_links: [u16; FILES_MAX],
}

impl Index {
    pub const fn new() -> Self {
        Self {
            parent: [NONE; ENTRIES_MAX + 1],
            first: [0; ENTRIES_MAX + 1],
            count: [0; ENTRIES_MAX + 1],
            kids: [0; ENTRIES_MAX],
            canon: [0; ENTRIES_MAX],
            links: [0; ENTRIES_MAX + 1],
            file_first: [NONE; FILES_MAX],
            file_links: [0; FILES_MAX],
        }
    }

    /// Fills the index for `table`, whose entries are in the ascending
    /// order of the paths: a parent comes before its children, and the
    /// children of one directory keep that order.
    #[inline(never)]
    fn fill(&mut self, table: &Rootfs<'_>) -> Result<(), Error> {
        let len = table.len();
        for n in 0..len {
            let entry = table.entry(n as u32);
            let reserved = |root: &str| {
                entry.path == root
                    || entry
                        .path
                        .strip_prefix(root)
                        .is_some_and(|rest| rest.starts_with('/'))
            };
            if reserved("/etc") || reserved("/tmp") {
                return Err(Error::Reserved(n as u32));
            }
            let slash = entry.path.rfind('/').unwrap_or(0);
            let parent = match &entry.path[..slash] {
                "" => ROOT,
                path => table.find(path).expect("the table has every parent"),
            };
            self.parent[n] = if parent == ROOT { NONE } else { parent as u16 };
            self.count[parent] += 1;
        }
        // The children of each directory in one run of `kids`, in order.
        let mut next = 0;
        for slot in (0..len).chain([ROOT]) {
            self.first[slot] = next;
            next += self.count[slot];
            self.count[slot] = 0;
        }
        for n in 0..len {
            let slot = match self.parent[n] {
                NONE => ROOT,
                parent => usize::from(parent),
            };
            self.kids[usize::from(self.first[slot] + self.count[slot])] = n as u16;
            self.count[slot] += 1;
        }
        // Hard links: the first entry of a file gives the inode, and the
        // links of a file are the entries that name it; a directory has
        // `.` and its entry in its parent, and `..` of each directory in it.
        self.file_first.fill(NONE);
        self.file_links.fill(0);
        for n in 0..len {
            let entry = table.entry(n as u32);
            if entry.is_directory() {
                self.canon[n] = n as u16;
                self.links[n] = 2 + self.directories(table, n);
            } else {
                let slot = &mut self.file_first[entry.file as usize];
                if *slot == NONE {
                    *slot = n as u16;
                }
                self.canon[n] = *slot;
                self.file_links[entry.file as usize] += 1;
            }
        }
        for n in 0..len {
            let entry = table.entry(n as u32);
            if !entry.is_directory() {
                self.links[n] = self.file_links[entry.file as usize];
            }
        }
        self.links[ROOT] = self.directories(table, ROOT);
        Ok(())
    }

    /// The directories among the children of `slot`.
    fn directories(&self, table: &Rootfs<'_>, slot: usize) -> u16 {
        self.children(slot)
            .iter()
            .filter(|&&kid| table.entry(u32::from(kid)).is_directory())
            .count() as u16
    }

    fn children(&self, slot: usize) -> &[u16] {
        let first = usize::from(self.first[slot]);
        &self.kids[first..first + usize::from(self.count[slot])]
    }
}

impl Default for Index {
    fn default() -> Self {
        Self::new()
    }
}

/// The table and the image it names files of, with the index.
#[derive(Clone, Copy)]
pub struct Tree<'a> {
    image: BootImage<'a>,
    table: Rootfs<'a>,
    index: &'a Index,
}

/// Reads the table of `image` and fills `index` for it.
pub fn load<'a>(image: &'a [u8], index: &'a mut Index) -> Result<Tree<'a>, Error> {
    let image = BootImage::parse(image).map_err(Error::Image)?;
    let table = image
        .files()
        .find(|file| file.name == ROOTFS)
        .ok_or(Error::Missing)?;
    let table = Rootfs::parse(table.data, image.count()).map_err(Error::Table)?;
    index.fill(&table)?;
    Ok(Tree {
        image,
        table,
        index,
    })
}

impl<'a> Tree<'a> {
    pub fn find(&self, path: &str) -> Option<u16> {
        self.table.find(path).map(|n| n as u16)
    }

    /// The entries of the table.
    pub fn len(&self) -> u16 {
        self.table.len() as u16
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn entry(&self, n: u16) -> Entry<'a> {
        self.table.entry(u32::from(n))
    }

    /// The bytes of the file of entry `n`; empty for a directory.
    pub fn data(&self, n: u16) -> &'a [u8] {
        let entry = self.entry(n);
        if entry.is_directory() {
            return &[];
        }
        self.image.file_at(entry.file).map_or(&[], |file| file.data)
    }

    /// The children of directory `n`, or of `/` for `None`, in the order
    /// of their paths.
    pub fn children(&self, n: Option<u16>) -> &'a [u16] {
        let slot = n.map_or(ROOT, usize::from);
        self.index.children(slot)
    }

    /// The directory that holds entry `n`; `None` for `/`.
    pub fn parent(&self, n: u16) -> Option<u16> {
        match self.index.parent[usize::from(n)] {
            NONE => None,
            parent => Some(parent),
        }
    }

    /// The entry whose number the inode of `n` is made of: the first hard
    /// link of its file.
    pub fn canonical(&self, n: u16) -> u16 {
        self.index.canon[usize::from(n)]
    }

    pub fn links(&self, n: u16) -> u16 {
        self.index.links[usize::from(n)]
    }

    /// The directories among the entries at `/`.
    pub fn root_links(&self) -> u16 {
        self.index.links[ROOT]
    }
}

/// An image of the files `init`, `a` (number 1, "alpha bytes"), `b` (2,
/// "beta") and, last, the table `rootfs` of `entries`, for the tests.
#[cfg(test)]
pub(crate) fn test_image(entries: &[Entry<'_>]) -> alloc::vec::Vec<u8> {
    let table = bootimg::rootfs::write::rootfs(entries, 4).unwrap();
    bootimg::write::image(&[
        ("init", b"init"),
        ("a", b"alpha bytes"),
        ("b", b"beta"),
        (ROOTFS, &table),
    ])
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bootimg::rootfs::{DIRECTORY, REGULAR};

    fn entry(path: &str, mode: u32, file: u32) -> Entry<'_> {
        Entry {
            path,
            mode,
            uid: 7,
            gid: 8,
            file,
        }
    }

    #[test]
    fn the_tree_has_children_parents_inodes_links_and_bytes() {
        let bytes = test_image(&[
            entry("/bin", DIRECTORY | 0o755, 0),
            entry("/bin/ash", REGULAR | 0o755, 1),
            entry("/bin/ls", REGULAR | 0o755, 1),
            entry("/bin/sub", DIRECTORY | 0o700, 0),
            entry("/bin/sub/x", REGULAR | 0o644, 2),
            entry("/top", REGULAR | 0o644, 2),
        ]);
        let mut index = Index::new();
        let tree = load(&bytes, &mut index).unwrap();
        assert_eq!(tree.children(None), [0, 5]);
        assert_eq!(tree.children(Some(0)), [1, 2, 3]);
        assert_eq!(tree.children(Some(3)), [4]);
        assert_eq!(tree.children(Some(1)), [] as [u16; 0]);
        assert_eq!(tree.parent(0), None);
        assert_eq!(tree.parent(4), Some(3));
        assert_eq!(tree.find("/bin/sub/x"), Some(4));
        assert_eq!(tree.find("/bin/none"), None);
        // `ash` and `ls` are one file, `x` and `top` another.
        assert_eq!((tree.canonical(1), tree.canonical(2)), (1, 1));
        assert_eq!((tree.canonical(4), tree.canonical(5)), (4, 4));
        assert_eq!((tree.links(1), tree.links(2)), (2, 2));
        assert_eq!((tree.links(4), tree.links(5)), (2, 2));
        // `.`, the entry in the parent, and `..` of `sub`.
        assert_eq!((tree.links(0), tree.links(3)), (3, 2));
        assert_eq!(tree.root_links(), 1);
        assert_eq!(tree.data(1), b"alpha bytes");
        assert_eq!(tree.data(5), b"beta");
        assert_eq!(tree.data(0), b"");
    }

    #[test]
    fn a_missing_or_bad_table_and_the_services_own_paths_are_refused() {
        let no_table = bootimg::write::image(&[("init", b"init")]).unwrap();
        assert!(matches!(
            load(&no_table, &mut Index::new()),
            Err(Error::Missing)
        ));
        assert!(matches!(
            load(b"nothing", &mut Index::new()),
            Err(Error::Image(_))
        ));
        let bad = bootimg::write::image(&[("init", b"init"), (ROOTFS, b"STAFROOT")]).unwrap();
        assert!(matches!(
            load(&bad, &mut Index::new()),
            Err(Error::Table(_))
        ));
        for path in ["/etc", "/tmp"] {
            let bytes = test_image(&[entry(path, DIRECTORY | 0o755, 0)]);
            assert!(matches!(
                load(&bytes, &mut Index::new()),
                Err(Error::Reserved(0))
            ));
        }
        for path in ["/etc/x", "/tmp/y"] {
            let parent = &path[..4];
            let bytes = test_image(&[
                entry(parent, DIRECTORY | 0o755, 0),
                entry(path, REGULAR | 0o644, 1),
            ]);
            assert!(load(&bytes, &mut Index::new()).is_err());
        }
        // Names that only start like them are the image's.
        let bytes = test_image(&[entry("/etcetera", REGULAR | 0o644, 1)]);
        assert!(load(&bytes, &mut Index::new()).is_ok());
    }
}
