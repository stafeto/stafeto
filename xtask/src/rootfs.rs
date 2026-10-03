// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The files of the RAM file service that a boot image carries: the table
//! `rootfs` (lib/bootimg/src/rootfs.rs) names each with its path, mode and
//! owner and takes the bytes from a file of the image: a program's ELF file
//! as the linker wrote it, a variant of one (its own copy, with more
//! memory in its data segment when asked), or bytes of the list itself.
//! `table` writes the table of an image, and `tests` checks that each
//! image's list names programs the image has.

use bootimg::rootfs::{self, Entry};

/// A path of the RAM service's tree: a directory (`source` is `None`) or
/// a file whose bytes `source` gives. Entries with one source are hard
/// links, so they share mode and owner.
pub struct RootFile {
    pub path: &'static str,
    /// The permission bits and the set-ID and sticky bits.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub source: Option<Source>,
}

/// Where the bytes of a file come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The ELF file of the image program, as the linker wrote it.
    Elf(&'static str),
    /// A copy of that ELF file of its own, `tag` naming it, whose data
    /// segment takes `extra` more bytes of memory: a second file of one
    /// program with another mode, or one too big for its quota.
    Variant {
        program: &'static str,
        tag: &'static str,
        extra: u64,
    },
    /// These bytes, in an image file of this name.
    Bytes(&'static str, &'static [u8]),
}

impl Source {
    /// The name of its file in the image.
    pub fn file_name(&self) -> String {
        match *self {
            Source::Elf(program) => elf_name(program),
            Source::Variant { program, tag, .. } => format!("{program}-{tag}.elf"),
            Source::Bytes(name, _) => name.to_string(),
        }
    }

    /// The image program whose ELF file it takes, if any.
    #[cfg(test)]
    pub fn program(&self) -> Option<&'static str> {
        match *self {
            Source::Elf(program) | Source::Variant { program, .. } => Some(program),
            Source::Bytes(..) => None,
        }
    }

    /// Its bytes, the ELF file of a program read with `elf`.
    pub fn bytes(&self, elf: impl Fn(&str) -> Result<Vec<u8>, String>) -> Result<Vec<u8>, String> {
        match *self {
            Source::Elf(program) => elf(program),
            Source::Variant { program, extra, .. } => grow_data(elf(program)?, extra),
            Source::Bytes(_, bytes) => Ok(bytes.to_vec()),
        }
    }
}

/// `elf` with its writable loadable segment `extra` bytes bigger in
/// memory (p_memsz).
fn grow_data(mut elf: Vec<u8>, extra: u64) -> Result<Vec<u8>, String> {
    let u16_at = |b: &[u8], at: usize| u16::from_le_bytes([b[at], b[at + 1]]);
    let u64_at = |b: &[u8], at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
    if elf.len() < 64 || elf[..4] != *b"\x7fELF" {
        return Err("not an ELF file".into());
    }
    let (table, count) = (u64_at(&elf, 32) as usize, usize::from(u16_at(&elf, 56)));
    for i in 0..count {
        let h = table + 56 * i;
        let kind = u32::from_le_bytes(elf[h..h + 4].try_into().unwrap());
        let flags = u32::from_le_bytes(elf[h + 4..h + 8].try_into().unwrap());
        if kind == 1 && flags & 2 != 0 {
            let size = u64_at(&elf, h + 40) + extra;
            elf[h + 40..h + 48].copy_from_slice(&size.to_le_bytes());
            return Ok(elf);
        }
    }
    Err("no writable segment".into())
}

const fn dir(path: &'static str) -> RootFile {
    RootFile {
        path,
        mode: 0o755,
        uid: 0,
        gid: 0,
        source: None,
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
        source: Some(Source::Elf(program)),
    }
}

/// A file of `source`.
const fn of(path: &'static str, mode: u32, (uid, gid): (u32, u32), source: Source) -> RootFile {
    RootFile {
        path,
        mode,
        uid,
        gid,
        source: Some(source),
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

/// `/dev/null`: the RAM service serves the entry of this path as the null
/// device (writes dropped, reads at the end), so the bytes are none.
fn null_device() -> RootFile {
    of("/dev/null", 0o666, ROOT, Source::Bytes("null", b""))
}

/// `/dev/random` and `/dev/urandom` (5e'): the RAM service serves the
/// entries of these paths as random devices (writes dropped; the client's
/// layer reads them from its generator), so the bytes are none. With
/// `/dev/null` they are the device nodes of an image where POSIX programs
/// run, and the image has the entropy service for them.
fn devices() -> [RootFile; 3] {
    [
        null_device(),
        of("/dev/random", 0o666, ROOT, Source::Bytes("random", b"")),
        of("/dev/urandom", 0o666, ROOT, Source::Bytes("urandom", b"")),
    ]
}

/// The shell's image: BusyBox with its applet names (the shell, `ash`,
/// among them) as hard links, and the service as a set-user-ID file of
/// another owner.
fn dialog() -> Vec<RootFile> {
    let mut files = vec![
        dir("/bin"),
        file("/bin/ash", 0o755, ROOT, "busybox-probe"),
        file("/bin/busybox", 0o755, ROOT, "busybox-probe"),
        file("/bin/ls", 0o755, ROOT, "busybox-probe"),
        file("/bin/cat", 0o755, ROOT, "busybox-probe"),
        file("/bin/wc", 0o755, ROOT, "busybox-probe"),
        file("/bin/sleep", 0o755, ROOT, "busybox-probe"),
        file("/bin/head", 0o755, ROOT, "busybox-probe"),
        file("/bin/mktemp", 0o755, ROOT, "busybox-probe"),
        file("/bin/ramfs", 0o4750, USER, "ramfs"),
        dir("/dev"),
    ];
    files.extend(devices());
    files
}

/// The probe of POSIX processes (5c): BusyBox as `/bin/ls`, the probe as
/// a child, a set-user-ID copy of it of root, a copy whose data asks for
/// more memory than a child's quota, a set-user-ID file of root that is
/// no program, a text file with the execute bits, a file without them and
/// a directory only root may search.
fn procs() -> Vec<RootFile> {
    const NOBODY_DIR: u32 = 0o700;
    let mut files = vec![
        dir("/bin"),
        file("/bin/ls", 0o755, ROOT, "busybox-probe"),
        file("/bin/cat", 0o755, ROOT, "busybox-probe"),
        file("/bin/procs-child", 0o755, ROOT, "posix-procs"),
        of(
            "/bin/procs-setid",
            0o4755,
            ROOT,
            Source::Variant {
                program: "posix-procs",
                tag: "setid",
                extra: 0,
            },
        ),
        of(
            "/bin/procs-big",
            0o755,
            ROOT,
            Source::Variant {
                program: "posix-procs",
                tag: "big",
                extra: 24 << 20,
            },
        ),
        of(
            "/bin/setid-junk",
            0o4755,
            ROOT,
            Source::Bytes("setid-junk", b"not a program\n"),
        ),
        of(
            "/bin/script",
            0o755,
            ROOT,
            Source::Bytes("script", b"#!/bin/sh\necho no\n"),
        ),
        of("/bin/data", 0o644, ROOT, Source::Bytes("data", b"data\n")),
        dir("/dev"),
        RootFile {
            mode: NOBODY_DIR,
            ..dir("/sbin")
        },
        file("/sbin/procs-child", 0o755, ROOT, "posix-procs"),
    ];
    files.extend(devices());
    files
}

/// The probe of the terminal (5f): itself as the file its "run" and
/// "spawned" roles start from, and the null device, a character device
/// that is no terminal.
fn posix_tty() -> Vec<RootFile> {
    vec![
        dir("/bin"),
        file("/bin/posix-tty", 0o755, ROOT, "posix-tty"),
        file("/bin/posix-tty-suid", 0o4755, ROOT, "posix-tty-suid"),
        dir("/dev"),
        null_device(),
    ]
}

/// The probe of the longest step of the process service (5c): the probe
/// itself as the file its children run.
fn steps() -> Vec<RootFile> {
    let mut files = vec![
        dir("/bin"),
        file("/bin/procs-child", 0o755, ROOT, "posix-procs"),
        dir("/dev"),
    ];
    files.extend(devices());
    files
}

/// rtbench 2 (5c): the benchmark's children are files of it, the program
/// itself under a role its first argument names; BusyBox gives the `ls` and
/// the `cat` of the pipeline of S22 (5e).
fn rtbench() -> Vec<RootFile> {
    let mut files = vec![
        dir("/bin"),
        file("/bin/rtbench-posix", 0o755, ROOT, "rtbench-posix"),
        file("/bin/ls", 0o755, ROOT, "busybox-probe"),
        file("/bin/cat", 0o755, ROOT, "busybox-probe"),
        dir("/dev"),
    ];
    files.extend(devices());
    files
}

/// The files of an image of os-test (5c): each test `name` (`suite/test`,
/// or `basic/part/test`) a file `/os-test/<name>` with the bytes of its
/// ELF file, in the directory of its suite, and the list the runner reads,
/// `/os-test/list`: a line a test with its name, its directory
/// (`/os-test/<suite>`) and its path from there. Names and bytes live for
/// the rest of the run of xtask.
pub fn os_test(tests: &[(String, Vec<u8>)]) -> Vec<RootFile> {
    fn leak(text: String) -> &'static str {
        Box::leak(text.into_boxed_str())
    }
    let mut files = vec![dir("/dev")];
    files.extend(devices());
    files.push(dir("/os-test"));
    let mut list = String::new();
    for (n, (name, elf)) in tests.iter().enumerate() {
        let parts: Vec<&str> = name.split('/').collect();
        // The directories above the file, from the suite down.
        for depth in 1..parts.len() {
            let path = leak(format!("/os-test/{}", parts[..depth].join("/")));
            if !files.iter().any(|f| f.path == path) {
                files.push(dir(path));
            }
        }
        let suite = parts[0];
        list.push_str(&format!(
            "{name} /os-test/{suite} {}\n",
            parts[1..].join("/")
        ));
        let file_name = leak(format!("t{n}"));
        let bytes: &'static [u8] = Box::leak(elf.clone().into_boxed_slice());
        files.push(of(
            leak(format!("/os-test/{name}")),
            0o755,
            ROOT,
            Source::Bytes(file_name, bytes),
        ));
    }
    let list: &'static [u8] = Box::leak(list.into_bytes().into_boxed_slice());
    files.push(of(
        "/os-test/list",
        0o644,
        ROOT,
        Source::Bytes("list", list),
    ));
    files
}

/// The files of the check of the runner of os-test: two files that are the
/// runner itself, `hang` (never ends) and `quick` (exits with 7), and a
/// list that gives each a second (`limit`).
pub fn runner_check() -> Vec<RootFile> {
    vec![
        dir("/os-test"),
        dir("/os-test/check"),
        file("/os-test/check/hang", 0o755, ROOT, "os-test-run"),
        file("/os-test/check/quick", 0o755, ROOT, "os-test-run"),
        of(
            "/os-test/list",
            0o644,
            ROOT,
            Source::Bytes(
                "list",
                b"limit 1000\ncheck/hang /os-test/check hang\ncheck/quick /os-test/check quick\n",
            ),
        ),
    ]
}

/// The names of the images that carry a table, which `files_of` lists.
#[cfg(test)]
pub const IMAGES: &[&str] = &[
    "boot-ramfs.img",
    "boot-ash-dialog.img",
    "boot-posix-procs.img",
    "boot-posix-steps.img",
    "boot-posix-tty.img",
    "boot-posix-tty-steps.img",
    "boot-posix-tty-vz.img",
    "rtbench-posix.img",
    "rtbench-posix-vz.img",
    "rtbench-posix-short.img",
];

/// The list of the image `name`: none for an image with no table.
pub fn files_of(name: &str) -> Vec<RootFile> {
    match name {
        "boot-ramfs.img" => ramfs(),
        "boot-ash-dialog.img" => dialog(),
        "boot-posix-procs.img" => procs(),
        "boot-posix-poll.img" => vec![
            dir("/bin"),
            file("/bin/posix-poll", 0o755, ROOT, "posix-poll"),
        ],
        "boot-posix-random.img" => {
            let mut files = vec![
                dir("/bin"),
                file("/bin/posix-random", 0o755, ROOT, "posix-random"),
                dir("/dev"),
            ];
            files.extend(devices());
            files
        }
        "boot-loader-channels.img" => {
            let mut files = vec![
                dir("/bin"),
                file("/bin/procs-child", 0o755, ROOT, "posix-procs"),
                dir("/dev"),
            ];
            files.extend(devices());
            files
        }
        "boot-posix-steps.img" => steps(),
        "boot-posix-tty.img" | "boot-posix-tty-steps.img" | "boot-posix-tty-vz.img" => posix_tty(),
        "rtbench-posix.img" | "rtbench-posix-vz.img" | "rtbench-posix-short.img" => rtbench(),
        _ => Vec::new(),
    }
}

/// The sources of the image files the table needs, each once, in the
/// order of their first use.
pub fn sources(files: &[RootFile]) -> Vec<Source> {
    let mut out: Vec<Source> = Vec::new();
    for source in files.iter().filter_map(|f| f.source) {
        if !out.contains(&source) {
            out.push(source);
        }
    }
    out
}

/// The programs whose ELF files the table needs, each once.
#[cfg(test)]
pub fn programs(files: &[RootFile]) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for program in sources(files).iter().filter_map(Source::program) {
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

/// The table for `files`: the file of `sources()[i]` is file `first + i`
/// of an image of `total` files, the table itself the last.
pub fn table(files: &[RootFile], first: u32, total: u32) -> Result<Vec<u8>, String> {
    let wanted = sources(files);
    let entries: Vec<Entry<'_>> = files
        .iter()
        .map(|f| {
            let (kind, file) = match f.source {
                None => (rootfs::DIRECTORY, 0),
                Some(source) => {
                    let n = wanted.iter().position(|s| *s == source).unwrap_or(0);
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
                "boot-posix-procs.img" => &crate::POSIX_PROCS_PROGRAMS,
                "boot-posix-steps.img" => &crate::POSIX_STEPS_PROGRAMS,
                "boot-posix-tty.img" => &crate::POSIX_TTY_PROGRAMS,
                "boot-posix-tty-steps.img" => &crate::POSIX_TTY_STEPS_PROGRAMS,
                "boot-posix-tty-vz.img" => &crate::POSIX_TTY_VZ_PROGRAMS,
                "rtbench-posix.img" | "rtbench-posix-short.img" => &crate::RTBENCH_POSIX_PROGRAMS,
                "rtbench-posix-vz.img" => &crate::RTBENCH_POSIX_VZ_PROGRAMS,
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

    /// The files of an image of os-test: each suite's directory, the tests
    /// below it as files of their own, and the list of the runner with the
    /// directory a test runs in and its path from there.
    #[test]
    fn an_os_test_image_lists_its_tests_and_their_directories() {
        let tests = [
            ("io/open".to_owned(), vec![1, 2, 3]),
            ("basic/spawn/posix_spawn".to_owned(), vec![4, 5]),
            ("basic/unistd/execl".to_owned(), vec![6]),
        ];
        let files = os_test(&tests);
        // The directories are listed once, the runner's list is a file.
        let paths: Vec<&str> = files.iter().map(|f| f.path).collect();
        for dir in [
            "/os-test",
            "/os-test/io",
            "/os-test/basic",
            "/os-test/basic/spawn",
            "/os-test/basic/unistd",
        ] {
            assert_eq!(paths.iter().filter(|p| **p == dir).count(), 1, "{dir}");
        }
        let list = files.iter().find(|f| f.path == "/os-test/list").unwrap();
        let Some(Source::Bytes(_, text)) = list.source else {
            panic!("the list is bytes");
        };
        assert_eq!(
            std::str::from_utf8(text).unwrap(),
            "io/open /os-test/io open\n\
             basic/spawn/posix_spawn /os-test/basic spawn/posix_spawn\n\
             basic/unistd/execl /os-test/basic unistd/execl\n"
        );
        // Each test is a file of its own, and the table reads back with
        // the directories above them (it refuses a file without its
        // parent).
        let wanted = sources(&files);
        assert_eq!(wanted.len(), 7);
        let bytes = table(&files, 3, 3 + wanted.len() as u32 + 1).unwrap();
        let read = Rootfs::parse(&bytes, 3 + wanted.len() as u32 + 1).unwrap();
        for path in [
            "/os-test/io/open",
            "/os-test/basic/spawn/posix_spawn",
            "/os-test/basic/unistd/execl",
        ] {
            let entry = read.entry(read.find(path).unwrap() as u32);
            assert_eq!(entry.mode, rootfs::REGULAR | 0o755, "{path}");
        }
        // The check of the runner has its hung test and its quick one, the
        // runner itself twice, so one image file.
        let check = runner_check();
        assert_eq!(sources(&check).len(), 2);
        assert!(table(&check, 3, 6).is_ok());
    }

    /// Every image where POSIX programs run has the device nodes of the
    /// null and the random devices, in a directory `/dev`.
    #[test]
    fn the_images_of_posix_programs_have_the_device_nodes() {
        for name in [
            "boot-ash-dialog.img",
            "boot-posix-procs.img",
            "boot-posix-random.img",
            "boot-posix-steps.img",
            "rtbench-posix.img",
            "rtbench-posix-vz.img",
            "rtbench-posix-short.img",
        ] {
            let files = files_of(name);
            for path in ["/dev", "/dev/null", "/dev/random", "/dev/urandom"] {
                assert_eq!(
                    files.iter().filter(|f| f.path == path).count(),
                    1,
                    "{name} {path}"
                );
            }
        }
        let os_test = os_test(&[]);
        for path in ["/dev", "/dev/null", "/dev/random", "/dev/urandom"] {
            assert!(os_test.iter().any(|f| f.path == path), "os-test {path}");
        }
    }

    /// A variant is a file of its own, its data segment grown; bytes of the
    /// list are a file of their own too.
    #[test]
    fn variants_and_bytes_are_files_of_their_own() {
        let list = procs();
        let wanted = sources(&list);
        let names: Vec<String> = wanted.iter().map(Source::file_name).collect();
        assert!(names.contains(&"posix-procs.elf".to_string()));
        assert!(names.contains(&"posix-procs-setid.elf".to_string()));
        assert!(names.contains(&"setid-junk".to_string()));
        assert!(names.iter().all(|n| n.len() <= bootimg::NAME_MAX));
        // A file of 56-byte headers: one writable segment of 0x100 bytes.
        let mut elf = vec![0; 64 + 56];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf[56..58].copy_from_slice(&1u16.to_le_bytes());
        elf[64..68].copy_from_slice(&1u32.to_le_bytes());
        elf[68..72].copy_from_slice(&6u32.to_le_bytes());
        elf[104..112].copy_from_slice(&0x100u64.to_le_bytes());
        let big = Source::Variant {
            program: "p",
            tag: "big",
            extra: 0x1000,
        };
        let grown = big.bytes(|_| Ok(elf.clone())).unwrap();
        assert_eq!(
            u64::from_le_bytes(grown[104..112].try_into().unwrap()),
            0x1100
        );
        assert!(Source::Bytes("x", b"y").bytes(|_| Err("no".into())).is_ok());
    }
}
