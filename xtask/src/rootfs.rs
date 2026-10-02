// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The files of the RAM file service that a boot image carries: the table
//! `rootfs` (lib/bootimg/src/rootfs.rs) names each with its path, mode and
//! owner and takes the bytes from a file of the image, a program's ELF file
//! as the linker wrote it. `table` writes the table of an image, and
//! `tests` checks that each image's list names programs the image has.

use bootimg::rootfs::{self, Entry};

/// A path of the RAM service's tree: a directory (`program` is `None`) or
/// a file whose bytes are the ELF file of the image program `program`.
/// Entries with one program are hard links, so they share mode and owner.
pub struct RootFile {
    pub path: &'static str,
    /// The permission bits and the set-ID and sticky bits.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub program: Option<&'static str>,
}

const fn dir(path: &'static str) -> RootFile {
    RootFile {
        path,
        mode: 0o755,
        uid: 0,
        gid: 0,
        program: None,
    }
}

const fn file(
    path: &'static str,
    mode: u32,
    (uid, gid): (u32, u32),
    program: &'static str,
) -> RootFile {
    RootFile {
        path,
        mode,
        uid,
        gid,
        program: Some(program),
    }
}

const ROOT: (u32, u32) = (0, 0);
/// An owner other than root, for the checks of owners in listings.
const USER: (u32, u32) = (1000, 100);

/// The probe of the RAM service: itself as a program and as a hard link,
/// the service as a set-user-ID file of another owner, and a link of the
/// probe at the longest path (a directory name of 255 bytes, then a file
/// name of 254: 511 bytes; tests/ramfs builds the same path).
fn ramfs() -> Vec<RootFile> {
    let deep_dir: &'static str = Box::leak(format!("/{}", "n".repeat(255)).into_boxed_str());
    let deep: &'static str = Box::leak(format!("{deep_dir}/{}", "m".repeat(254)).into_boxed_str());
    vec![
        dir("/bin"),
        file("/bin/ramfs-probe", 0o755, ROOT, "ramfs-probe"),
        file("/bin/probe", 0o755, ROOT, "ramfs-probe"),
        file("/bin/ramfs", 0o4750, USER, "ramfs"),
        dir(deep_dir),
        file(deep, 0o755, ROOT, "ramfs-probe"),
    ]
}

/// The shell's image: BusyBox with its applet names as hard links, and the
/// service as a set-user-ID file of another owner.
fn dialog() -> Vec<RootFile> {
    vec![
        dir("/bin"),
        file("/bin/busybox", 0o755, ROOT, "busybox-probe"),
        file("/bin/ls", 0o755, ROOT, "busybox-probe"),
        file("/bin/cat", 0o755, ROOT, "busybox-probe"),
        file("/bin/ramfs", 0o4750, USER, "ramfs"),
    ]
}

/// The names of the images that carry a table, which `files_of` lists.
#[cfg(test)]
pub const IMAGES: &[&str] = &["boot-ramfs.img", "boot-ash-dialog.img"];

/// The list of the image `name`: none for an image with no table.
pub fn files_of(name: &str) -> Vec<RootFile> {
    match name {
        "boot-ramfs.img" => ramfs(),
        "boot-ash-dialog.img" => dialog(),
        _ => Vec::new(),
    }
}

/// The programs whose ELF files the table needs, each once, in the order
/// of their first use.
pub fn programs(files: &[RootFile]) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for program in files.iter().filter_map(|f| f.program) {
        if !out.contains(&program) {
            out.push(program);
        }
    }
    out
}

/// The name of the image file that holds the ELF file of `program`.
pub fn elf_name(program: &str) -> String {
    format!("{program}.elf")
}

/// The table for `files`: the ELF file of `programs()[i]` is file `first +
/// i` of an image of `total` files, the table itself the last.
pub fn table(files: &[RootFile], first: u32, total: u32) -> Result<Vec<u8>, String> {
    let wanted = programs(files);
    let entries: Vec<Entry<'_>> = files
        .iter()
        .map(|f| {
            let (kind, file) = match f.program {
                None => (rootfs::DIRECTORY, 0),
                Some(program) => {
                    let n = wanted.iter().position(|p| *p == program).unwrap_or(0);
                    (rootfs::REGULAR, first + n as u32)
                }
            };
            Entry {
                path: f.path,
                mode: kind | f.mode,
                uid: f.uid,
                gid: f.gid,
                file,
            }
        })
        .collect();
    rootfs::write::rootfs(&entries, total).map_err(|e| format!("rootfs: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bootimg::rootfs::Rootfs;

    #[test]
    fn hard_links_of_a_program_share_one_file_and_the_table_reads_back() {
        let bytes = table(&ramfs(), 5, 9).unwrap();
        let read = Rootfs::parse(&bytes, 9).unwrap();
        let find = |path| read.entry(read.find(path).unwrap() as u32);
        let (probe, link, service) = (
            find("/bin/ramfs-probe"),
            find("/bin/probe"),
            find("/bin/ramfs"),
        );
        assert_eq!(probe.file, link.file);
        assert_ne!(probe.file, service.file);
        // The programs are numbered from `first` in order of first use.
        assert_eq!((probe.file, service.file), (5, 6));
        assert_eq!(service.mode, rootfs::REGULAR | 0o4750);
        assert_eq!((service.uid, service.gid), USER);
        assert!(find("/bin").is_directory());
    }

    #[test]
    fn the_table_must_fit_the_image() {
        // One file too few: the second program's number is out of range.
        assert!(table(&ramfs(), 5, 6).is_err());
        // Two links with different modes cannot share a file.
        let bad = [file("/a", 0o755, ROOT, "p"), file("/b", 0o644, ROOT, "p")];
        assert!(table(&bad, 1, 2).is_err());
    }

    #[test]
    fn every_list_names_programs_of_its_image() {
        let programs_of = |image: &str| -> Vec<&str> {
            let list: &[crate::ImageProgram] = match image {
                "boot-ramfs.img" => &crate::RAMFS_PROGRAMS,
                "boot-ash-dialog.img" => &crate::ASH_INTERACTIVE_PROGRAMS,
                other => panic!("no programs known for {other}"),
            };
            list.iter().map(|p| p.0).collect()
        };
        for image in IMAGES {
            let files = files_of(image);
            let have = programs_of(image);
            for program in programs(&files) {
                assert!(have.contains(&program), "{image}: {program}");
            }
            // Every entry has its parent directory in the list.
            for f in &files {
                let parent = &f.path[..f.path.rfind('/').unwrap()];
                assert!(parent.is_empty() || files.iter().any(|d| d.path == parent));
            }
        }
        assert!(files_of("boot.img").is_empty());
        // The longest path of the probe's list is the longest there is.
        let deep = ramfs().iter().map(|f| f.path.len()).max();
        assert_eq!(deep, Some(bootimg::rootfs::PATH_MAX));
    }
}
