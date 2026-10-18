// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The files of the RAM file service that a boot image carries: the table
//! `rootfs` (lib/bootimg/src/rootfs.rs) names each with its path, mode and
//! owner and takes the bytes from a file of the image: a program's ELF file
//! as the linker wrote it, a variant of one (its own copy, with more
//! memory in its data segment when asked), bytes of the list itself, or the
//! target of a symbolic link.
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
    /// The compiled terminfo entry of this name, which tools/build-ncurses.py
    /// writes into target/ncurses/terminfo.
    Terminfo(&'static str),
    /// A symbolic link to this target, a name in the directory of the link.
    /// Its bytes are the target; links to one target share the image file.
    Link(&'static str),
}

impl Source {
    /// The name of its file in the image.
    pub fn file_name(&self) -> String {
        match *self {
            Source::Elf(program) => elf_name(program),
            Source::Variant { program, tag, .. } => format!("{program}-{tag}.elf"),
            Source::Bytes(name, _) => name.to_string(),
            Source::Terminfo(entry) => format!("terminfo-{entry}"),
            Source::Link(target) => format!("link-{target}"),
        }
    }

    /// The image program whose ELF file it takes, if any.
    #[cfg(test)]
    pub fn program(&self) -> Option<&'static str> {
        match *self {
            Source::Elf(program) | Source::Variant { program, .. } => Some(program),
            Source::Bytes(..) | Source::Terminfo(_) | Source::Link(_) => None,
        }
    }

    /// Its bytes, the ELF file of a program read with `elf`.
    pub fn bytes(&self, elf: impl Fn(&str) -> Result<Vec<u8>, String>) -> Result<Vec<u8>, String> {
        match *self {
            Source::Elf(program) => elf(program),
            Source::Variant { program, extra, .. } => grow_data(elf(program)?, extra),
            Source::Bytes(_, bytes) => Ok(bytes.to_vec()),
            Source::Link(target) => Ok(target.as_bytes().to_vec()),
            Source::Terminfo(entry) => {
                let path = crate::target_dir()
                    .join("ncurses/terminfo")
                    .join(&entry[..1])
                    .join(entry);
                std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))
            }
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

/// Account databases are ordinary root-owned files in each shipped image.
fn accounts() -> [RootFile; 3] {
    [
        dir("/etc"),
        of(
            "/etc/passwd",
            0o644,
            ROOT,
            Source::Bytes(
                "passwd",
                b"root:x:0:0:root:/root:/bin/ash\nuser:x:1000:100:user:/home/user:/bin/ash\nnobody:x:65534:65534:nobody:/:/bin/ash\n",
            ),
        ),
        of(
            "/etc/group",
            0o644,
            ROOT,
            Source::Bytes("group", b"root:x:0:root\nuser:x:100:user\nnobody:x:65534:nobody\n"),
        ),
    ]
}

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

/// `/dev/pts` is the directory for synthetic PTY slave paths (5f).
/// `/dev/random` and `/dev/urandom` (5e'): the RAM service serves the
/// entries of these paths as random devices (writes dropped; the client's
/// layer reads them from its generator), so the bytes are none. With
/// `/dev/null` they are the device nodes of an image where POSIX programs
/// run, and the image has the entropy service for them.
fn devices() -> [RootFile; 5] {
    [
        dir("/dev/pts"),
        // The names of shm_open: files here are the shared memory objects.
        RootFile {
            path: "/dev/shm",
            mode: 0o1777,
            uid: 0,
            gid: 0,
            source: None,
        },
        null_device(),
        of("/dev/random", 0o666, ROOT, Source::Bytes("random", b"")),
        of("/dev/urandom", 0o666, ROOT, Source::Bytes("urandom", b"")),
    ]
}

/// The user accounting file of the dialog's image: one record of relibc's
/// struct utmpx (96 bytes: user 32, id 4, line 32, pid 4, type 2, padding
/// to 8, the time as two 64-bit words): USER_PROCESS, "user" on the line
/// "console", id "c1", process 1.
static UTMPX: [u8; 96] = {
    let mut record = [0u8; 96];
    let user = b"user";
    let id = b"c1";
    let line = b"console";
    let mut i = 0;
    while i < user.len() {
        record[i] = user[i];
        i += 1;
    }
    i = 0;
    while i < id.len() {
        record[32 + i] = id[i];
        i += 1;
    }
    i = 0;
    while i < line.len() {
        record[36 + i] = line[i];
        i += 1;
    }
    record[68] = 1; // ut_pid
    record[72] = 7; // ut_type: USER_PROCESS
    record
};

/// The files the base system owns in the shell image (init and the
/// services): their directories, the RAM service and the files of the
/// accounts and the device nodes. Every other file belongs to a package.
const SYSTEM_PATHS: [&str; 17] = [
    "/bin",
    "/libexec",
    "/libexec/ramfs",
    "/dev",
    "/proc",
    "/var",
    "/var/log",
    "/var/run",
    "/var/mail",
    "/var/spool",
    "/var/spool/at",
    "/var/spool/lp",
    "/var/run/utmpx",
    "/etc",
    "/etc/mtab",
    "/etc/passwd",
    "/etc/group",
];

/// Whether the base system owns `path`: the paths above and the device
/// nodes below /dev.
fn is_system(path: &str) -> bool {
    SYSTEM_PATHS.contains(&path) || path.starts_with("/dev/")
}

/// The bytes of the files that packages name as `bytes:<name>`.
fn named_bytes(name: &str) -> Result<&'static [u8], String> {
    match name {
        "inputrc" => Ok(INPUTRC),
        "profile" => Ok(b"export TERM=xterm-256color\n"),
        other => Err(format!("no bytes are named {other}")),
    }
}

/// The directories and files of `packages`, with the owner root.
pub fn package_files(packages: &[crate::packages::Package]) -> Result<Vec<RootFile>, String> {
    fn leak(text: &str) -> &'static str {
        Box::leak(text.to_owned().into_boxed_str())
    }
    let mut files = Vec::new();
    for package in packages {
        files.extend(package.dirs.iter().map(|d| dir(leak(d))));
        for (path, from) in &package.files {
            let (kind, name) = from
                .split_once(':')
                .ok_or(format!("{from}: no source kind"))?;
            files.push(match kind {
                "elf" => file(leak(path), 0o755, ROOT, leak(name)),
                "terminfo" => of(leak(path), 0o644, ROOT, Source::Terminfo(leak(name))),
                "link" => of(
                    leak(path),
                    bootimg::rootfs::SYMLINK_MODE,
                    ROOT,
                    Source::Link(leak(name)),
                ),
                "bytes" => of(
                    leak(path),
                    0o644,
                    ROOT,
                    Source::Bytes(leak(name), named_bytes(name)?),
                ),
                other => return Err(format!("{from}: {other} is no source kind")),
            });
        }
    }
    Ok(files)
}

/// How many names of /bin beyond `ash`, `sh` and `busybox` are links to
/// BusyBox in the shell image: the utilities of the packages that BusyBox
/// carries.
pub fn utilities() -> usize {
    files_of("boot-ash-dialog.img")
        .iter()
        .filter(|f| f.source == Some(Source::Link("busybox")))
        .count()
        - 2
}

/// The shell's image: the base system (the RAM service, its directories and
/// files) and the files of the packages in `packages/`: BusyBox with its
/// applet names (the shell, `ash`, among them) as symbolic links, and the
/// add-ons. The service is a set-user-ID file of another owner.
fn dialog() -> Vec<RootFile> {
    shell_files().unwrap_or_else(|e| panic!("the shell image: {e}"))
}

fn shell_files() -> Result<Vec<RootFile>, String> {
    let mut files = vec![
        dir("/bin"),
        dir("/libexec"),
        file("/libexec/ramfs", 0o4750, USER, "ramfs"),
        dir("/dev"),
        dir("/proc"),
        dir("/var"),
        dir("/var/log"),
        dir("/var/run"),
        dir("/var/mail"),
        dir("/var/spool"),
        dir("/var/spool/at"),
        dir("/var/spool/lp"),
        of(
            "/etc/mtab",
            0o644,
            ROOT,
            Source::Bytes("mtab", b"ramfs / ramfs rw 0 0\n"),
        ),
        of(
            "/var/run/utmpx",
            0o644,
            ROOT,
            Source::Bytes("utmpx", &UTMPX),
        ),
    ];
    files.extend(package_files(&crate::packages::of_image(
        "boot-ash-dialog.img",
    )?)?);
    files.extend(devices());
    Ok(files)
}

/// Fails unless each file of the image `name` belongs to exactly one
/// package or to the base system, and each file a package names is in the
/// image. `files` is the list of the image.
pub fn check_owners(
    name: &str,
    files: &[RootFile],
    packages: &[crate::packages::Package],
) -> Result<(), String> {
    let mut wrong = Vec::new();
    for f in files {
        let owners: Vec<&str> = packages
            .iter()
            .filter(|p| {
                p.files.iter().any(|(path, _)| path == f.path) || p.dirs.iter().any(|d| d == f.path)
            })
            .map(|p| p.name.as_str())
            .chain(is_system(f.path).then_some("system"))
            .collect();
        if owners.len() != 1 {
            wrong.push(format!("{} ({})", f.path, owners.join(", ")));
        }
    }
    for p in packages {
        for path in p.files.iter().map(|f| &f.0).chain(&p.dirs) {
            if !files.iter().any(|f| f.path == path) {
                wrong.push(format!("{path} of {} is not in the image", p.name));
            }
        }
    }
    // A link names a file of its own directory that the image has and that
    // is no link itself.
    for f in files {
        if let Some(Source::Link(target)) = f.source {
            let at = f.path.rfind('/').unwrap_or(0);
            let whole = format!("{}/{target}", &f.path[..at]);
            let kind = files.iter().find(|g| g.path == whole).map(|g| g.source);
            if !matches!(kind, Some(Some(source)) if !matches!(source, Source::Link(_))) {
                wrong.push(format!(
                    "{} links to {whole}, which is no file of the image",
                    f.path
                ));
            }
        }
    }
    if wrong.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{name}: files without exactly one owner: {}",
            wrong.join("; ")
        ))
    }
}

/// The table of the packages of the image `name`: name, version, licence,
/// kind, files and bytes, with `size` giving the bytes of a source. A
/// source that several paths name (the hard links of BusyBox) counts once,
/// for the first package that names it.
pub fn package_table(
    name: &str,
    size: impl Fn(&Source) -> Result<u64, String>,
) -> Result<String, String> {
    let packages = crate::packages::of_image(name)?;
    let files = files_of(name);
    check_owners(name, &files, &packages)?;
    let mut counted: Vec<Source> = Vec::new();
    let mut rows = Vec::new();
    let mut tally = |owns: &dyn Fn(&str) -> bool| -> Result<(usize, u64), String> {
        let (mut count, mut bytes) = (0, 0);
        for f in files.iter().filter(|f| owns(f.path)) {
            let Some(source) = f.source else { continue };
            count += 1;
            if !counted.contains(&source) {
                counted.push(source);
                bytes += size(&source)?;
            }
        }
        Ok((count, bytes))
    };
    for p in &packages {
        let owns =
            |path: &str| p.files.iter().any(|(f, _)| f == path) || p.dirs.iter().any(|d| d == path);
        let (count, bytes) = tally(&owns)?;
        let kind = if p.kind == crate::packages::Kind::Base {
            "base"
        } else {
            "addon"
        };
        rows.push((
            p.name.clone(),
            p.version.clone(),
            p.license.clone(),
            kind,
            count,
            bytes,
        ));
    }
    let (count, bytes) = tally(&|path| is_system(path))?;
    rows.push((
        "(system)".into(),
        "-".into(),
        "-".into(),
        "system",
        count,
        bytes,
    ));
    let mut out = format!(
        "{:<12} {:<14} {:<17} {:<7} {:>6} {:>10}\n",
        "package", "version", "license", "kind", "files", "bytes"
    );
    for (name, version, license, kind, count, bytes) in &rows {
        out +=
            &format!("{name:<12} {version:<14} {license:<17} {kind:<7} {count:>6} {bytes:>10}\n");
    }
    let total: u64 = rows.iter().map(|r| r.5).sum();
    out += &format!(
        "{:<12} {:<14} {:<17} {:<7} {:>6} {:>10}\n",
        "total",
        "",
        "",
        "",
        rows.iter().map(|r| r.4).sum::<usize>(),
        total
    );
    Ok(out)
}

/// /etc/inputrc of the shell image.
const INPUTRC: &[u8] = b"\"\\e[1~\": beginning-of-line\n\
\"\\e[H\": beginning-of-line\n\
\"\\eOH\": beginning-of-line\n\
\"\\e[4~\": end-of-line\n\
\"\\e[F\": end-of-line\n\
\"\\eOF\": end-of-line\n\
\"\\e[3~\": delete-char\n";

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

/// Four directories of the boot table for the probe of the change jobs:
/// renames of names that are in the table stage the most the service pays.
fn change_dirs() -> [RootFile; 5] {
    [
        dir("/chg"),
        dir("/chg/a"),
        dir("/chg/b"),
        dir("/chg/c"),
        dir("/chg/d"),
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
    files.extend(change_dirs());
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
    os_test_with_fixtures(tests, &[])
}

/// The databases of `netdb.h` that the images of os-test carry in `/etc`.
fn network_databases() -> [RootFile; 4] {
    [
        of(
            "/etc/hosts",
            0o644,
            ROOT,
            Source::Bytes(
                "hosts",
                b"127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost\n",
            ),
        ),
        of(
            "/etc/services",
            0o644,
            ROOT,
            Source::Bytes(
                "services",
                b"echo\t\t7/tcp\necho\t\t7/udp\nftp\t\t21/tcp\nssh\t\t22/tcp\ntelnet\t\t23/tcp\n\
smtp\t\t25/tcp\t\tmail\ndomain\t\t53/tcp\ndomain\t\t53/udp\nhttp\t\t80/tcp\t\twww\n\
pop3\t\t110/tcp\nntp\t\t123/udp\nimap\t\t143/tcp\nhttps\t\t443/tcp\n",
            ),
        ),
        of(
            "/etc/protocols",
            0o644,
            ROOT,
            Source::Bytes(
                "protocols",
                b"ip\t0\tIP\nicmp\t1\tICMP\ntcp\t6\tTCP\nudp\t17\tUDP\nipv6\t41\tIPv6\n\
ipv6-icmp\t58\tIPv6-ICMP\n",
            ),
        ),
        of(
            "/etc/networks",
            0o644,
            ROOT,
            Source::Bytes("networks", b"loopback\t127\n"),
        ),
    ]
}

/// Source fixtures remain regular data files outside the executable runner list.
pub fn os_test_with_fixtures(
    tests: &[(String, Vec<u8>)],
    fixtures: &[(String, Vec<u8>)],
) -> Vec<RootFile> {
    fn leak(text: String) -> &'static str {
        Box::leak(text.into_boxed_str())
    }
    let mut files = vec![dir("/dev")];
    files.extend(devices());
    files.extend(network_databases());
    files.push(dir("/bin"));
    files.push(of("/bin/sh", 0o755, ROOT, Source::Elf("busybox-probe")));
    // The message catalog compiler of the tests of nl_types.
    files.push(of("/bin/gencat", 0o755, ROOT, Source::Elf("gencat")));
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
    for (n, (name, contents)) in fixtures.iter().enumerate() {
        let parts: Vec<&str> = name.split('/').collect();
        for depth in 1..parts.len() {
            let path = leak(format!("/os-test/{}", parts[..depth].join("/")));
            if !files.iter().any(|f| f.path == path) {
                files.push(dir(path));
            }
        }
        let bytes: &'static [u8] = Box::leak(contents.clone().into_boxed_slice());
        files.push(of(
            leak(format!("/os-test/{name}")),
            0o644,
            ROOT,
            Source::Bytes(leak(format!("fixture{n}")), bytes),
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

/// The files of an image of the Open POSIX Test Suite (Ф12): the tests of
/// `os_test` (`/tmp` is the RAM service's own), and a list that runs each in the directory
/// of its own file with its time limit in milliseconds (`limits`, one for
/// each test).
pub fn open_posix(tests: &[(String, Vec<u8>)], limits: &[u64]) -> Vec<RootFile> {
    /// Tests that print a usage line without an argument: the number of
    /// threads the suite's README gives them.
    const ARGUMENTS: [(&str, &str); 2] = [
        ("stress/mqueues/multi_send_rev_1", "2"),
        ("stress/mqueues/multi_send_rev_2", "2"),
    ];
    assert_eq!(tests.len(), limits.len());
    let mut files = os_test_with_fixtures(tests, &[]);
    files.retain(|f| f.path != "/os-test/list");
    // The suite's helpers read /proc/<pid>/stat to see a child sleep.
    files.push(dir("/proc"));
    // Programs the tests start by name (exec of /bin/sleep and /bin/ls):
    // links of the shell's file, which BusyBox runs as the applet it is
    // named as.
    files.push(of("/bin/sleep", 0o755, ROOT, Source::Elf("busybox-probe")));
    files.push(of("/bin/ls", 0o755, ROOT, Source::Elf("busybox-probe")));
    let mut list = String::new();
    let mut limit = None;
    for ((name, _), ms) in tests.iter().zip(limits) {
        if limit != Some(*ms) {
            list.push_str(&format!("limit {ms}\n"));
            limit = Some(*ms);
        }
        let (directory, file) = name.rsplit_once('/').unwrap_or(("", name));
        let argument = ARGUMENTS
            .iter()
            .find(|(test, _)| test == name)
            .map_or(String::new(), |(_, arg)| format!(" {arg}"));
        list.push_str(&format!("{name} /os-test/{directory} {file}{argument}\n"));
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
    "boot-posix-lifetimes.img",
    "boot-posix-lock-rules.img",
    "boot-posix-lock-core.img",
    "boot-posix-lock-pages.img",
    "boot-posix-lock-fifo.img",
    "boot-posix-spawn-churn.img",
    "boot-posix-sync.img",
    "boot-posix-math.img",
    "boot-posix-park.img",
    "boot-posix-fifo.img",
    "boot-posix-fifo-steps.img",
    "boot-posix-resources.img",
    "boot-posix-map.img",
    "boot-posix-lock-ring.img",
    "boot-posix-native-scopes.img",
    "boot-posix-native-scopes-vz.img",
    "boot-posix-jobs.img",
    "boot-posix-steps.img",
    "boot-posix-tty.img",
    "boot-posix-tty-steps.img",
    "boot-posix-tty-control-steps.img",
    "boot-posix-tty-vz.img",
    "rtbench-posix.img",
    "rtbench-posix-vz.img",
    "rtbench-posix-short.img",
];

/// The list of the image `name`: none for an image with no table.
pub fn files_of(name: &str) -> Vec<RootFile> {
    let mut files = match name {
        "boot-ramfs.img" => ramfs(),
        "boot-ramfs-cleanup.img"
        | "boot-loader-abort.img"
        | "boot-loader-abort-steps.img"
        | "boot-loader-info.img" => {
            let mut files = vec![
                dir("/bin"),
                file("/bin/posix-files", 0o755, ROOT, "posix-files"),
                dir("/dev"),
            ];
            files.extend(devices());
            files
        }
        "boot-posix-files.img" | "boot-posix-files-steps.img" | "boot-posix-data-steps.img" => {
            let mut files = vec![dir("/dev")];
            files.extend(devices());
            files.extend(change_dirs());
            files
        }
        "boot-image-gates.img"
        | "boot-image-gates-steps.img"
        | "boot-image-gates-normal-steps.img" => vec![
            dir("/bin"),
            file("/bin/posix-files", 0o755, ROOT, "posix-files"),
            of(
                "/bin/setid-image",
                0o6755,
                (37, 43),
                Source::Variant {
                    program: "posix-files",
                    tag: "setid",
                    extra: 0,
                },
            ),
        ],
        "boot-ash-dialog.img" => dialog(),
        "boot-posix-native-scopes.img" | "boot-posix-native-scopes-vz.img" => {
            let mut files = procs();
            files.push(file(
                "/bin/native-scopes",
                0o755,
                ROOT,
                "posix-thread-probe",
            ));
            files
        }
        "boot-posix-procs.img"
        | "boot-posix-jobs.img"
        | "boot-posix-lifetimes.img"
        | "boot-posix-lock-rules.img"
        | "boot-posix-lock-core.img"
        | "boot-posix-lock-pages.img"
        | "boot-posix-lock-fifo.img"
        | "boot-posix-spawn-churn.img"
        | "boot-posix-sync.img"
        | "boot-posix-math.img"
        | "boot-posix-park.img"
        | "boot-posix-fifo.img"
        | "boot-posix-fifo-steps.img"
        | "boot-posix-resources.img"
        | "boot-posix-map.img"
        | "boot-posix-lock-ring.img" => procs(),
        "boot-posix-poll.img" => {
            let mut files = vec![
                dir("/bin"),
                file("/bin/posix-poll", 0o755, ROOT, "posix-poll"),
                dir("/dev"),
            ];
            files.extend(devices());
            files
        }
        "boot-posix-sock.img" => {
            let mut files = vec![
                dir("/bin"),
                file("/bin/posix-sock", 0o755, ROOT, "posix-sock"),
                dir("/dev"),
            ];
            files.extend(devices());
            files.extend(network_databases());
            files
        }
        "boot-posix-ipc.img" => {
            let mut files = vec![
                dir("/bin"),
                file("/bin/posix-ipc", 0o755, ROOT, "posix-ipc"),
                dir("/dev"),
            ];
            files.extend(devices());
            files
        }
        "boot-posix-pty.img" | "boot-posix-pty-steps.img" => {
            let mut files = vec![
                dir("/bin"),
                file("/bin/posix-pty", 0o755, ROOT, "posix-pty"),
                file("/bin/ash", 0o755, ROOT, "busybox-probe"),
                file("/bin/sleep", 0o755, ROOT, "busybox-probe"),
                dir("/dev"),
            ];
            files.extend(devices());
            files
        }
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
        "boot-posix-tty.img"
        | "boot-posix-tty-steps.img"
        | "boot-posix-tty-control-steps.img"
        | "boot-posix-tty-vz.img" => posix_tty(),
        "rtbench-posix.img" | "rtbench-posix-vz.img" | "rtbench-posix-short.img" => rtbench(),
        _ => Vec::new(),
    };
    files.extend(accounts());
    files
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

/// A time `set_build_time` fixed for the images built from now on; 0 for none.
static BUILD_TIME: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Fixes the build time of the images built from now on (a dialog that
/// checks the time of the files makes it differ from the time of the boot).
pub fn set_build_time(seconds: u64) {
    BUILD_TIME.store(seconds, std::sync::atomic::Ordering::Relaxed);
}

/// The time the files of an image get: SOURCE_DATE_EPOCH when it is set
/// (seconds since the epoch, so that a build repeats), else the time of the
/// build.
pub fn build_time() -> Result<u64, String> {
    let fixed = BUILD_TIME.load(std::sync::atomic::Ordering::Relaxed);
    if fixed != 0 {
        return Ok(fixed);
    }
    match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(text) => text
            .trim()
            .parse()
            .map_err(|_| format!("SOURCE_DATE_EPOCH={text:?} is no number of seconds")),
        Err(_) => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| format!("the clock of the host is before the epoch: {e}")),
    }
}

/// The table for `files` of a build with no time.
#[cfg(test)]
pub fn table(files: &[RootFile], first: u32, total: u32) -> Result<Vec<u8>, String> {
    table_at(files, first, total, 0)
}

/// The table for `files` of a build at `time`: the file of `sources()[i]` is
/// file `first + i` of an image of `total` files, the table itself the last.
pub fn table_at(files: &[RootFile], first: u32, total: u32, time: u64) -> Result<Vec<u8>, String> {
    let wanted = sources(files);
    let entries: Vec<Entry<'_>> = files
        .iter()
        .map(|f| {
            let (kind, file) = match f.source {
                None => (rootfs::DIRECTORY, 0),
                Some(source) => {
                    let n = wanted.iter().position(|s| *s == source).unwrap_or(0);
                    let kind = match source {
                        Source::Link(_) => rootfs::SYMLINK,
                        _ => rootfs::REGULAR,
                    };
                    (kind, first + n as u32)
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
    rootfs::write::rootfs_at(&entries, total, time).map_err(|e| format!("rootfs: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bootimg::rootfs::Rootfs;

    #[test]
    fn source_fixtures_keep_exact_bytes_and_permissions_without_runner_rows() {
        let tests = vec![
            ("basic/unistd/faccessat".into(), vec![1]),
            ("basic/unistd/fchownat".into(), vec![2]),
        ];
        let fixtures = vec![
            (
                "basic/unistd/faccessat.c".into(),
                b"/* faccessat */\n".to_vec(),
            ),
            (
                "basic/unistd/fchownat.c".into(),
                b"/* fchownat */\n".to_vec(),
            ),
        ];
        let mut files = os_test_with_fixtures(&tests, &fixtures);
        // The accounts bring /etc, as in an image.
        files.extend(accounts());
        let Some(Source::Bytes(_, list)) = files
            .iter()
            .find(|f| f.path == "/os-test/list")
            .unwrap()
            .source
        else {
            panic!("list bytes");
        };
        assert_eq!(
            std::str::from_utf8(list).unwrap(),
            "basic/unistd/faccessat /os-test/basic unistd/faccessat\nbasic/unistd/fchownat /os-test/basic unistd/fchownat\n"
        );
        for (name, expected) in fixtures {
            let path = format!("/os-test/{name}");
            let file = files.iter().find(|f| f.path == path).unwrap();
            assert_eq!(file.mode, 0o644);
            let Some(Source::Bytes(_, bytes)) = file.source else {
                panic!("fixture bytes");
            };
            assert_eq!(bytes, expected);
        }
        let total = sources(&files).len() as u32 + 3;
        assert!(Rootfs::parse(&table(&files, 3, total).unwrap(), total).is_ok());
    }

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
    fn symbolic_links_of_the_shell_image_read_back_as_links_to_busybox() {
        let files = files_of("boot-ash-dialog.img");
        let total = sources(&files).len() as u32 + 3;
        let bytes = table(&files, 3, total).unwrap();
        let read = Rootfs::parse(&bytes, total).unwrap();
        let find = |path| read.entry(read.find(path).unwrap() as u32);
        let (cat, ls, busybox) = (find("/bin/cat"), find("/bin/ls"), find("/bin/busybox"));
        assert!(cat.is_symlink() && ls.is_symlink() && !busybox.is_symlink());
        assert_eq!(cat.file, ls.file);
        assert_eq!(cat.mode, rootfs::SYMLINK | 0o777);
        assert_eq!(
            Source::Link("busybox").bytes(|_| Err("no program".into())),
            Ok(b"busybox".to_vec())
        );
        // The service and the test program are out of /bin.
        assert!(read.find("/bin/ramfs").is_none() && read.find("/bin/login-probe").is_none());
        assert!(find("/libexec/ramfs").mode & 0o4000 != 0);
        assert!(find("/libexec/login-probe").mode & rootfs::FORMAT == rootfs::REGULAR);
    }

    /// A link to a name the image lacks, or to another link, is refused.
    #[test]
    fn a_link_must_name_a_file_of_its_directory() {
        let image = "boot-ash-dialog.img";
        let packages = crate::packages::of_image(image).unwrap();
        let mut dangling = files_of(image);
        dangling.push(of("/bin/ghost", 0o777, ROOT, Source::Link("nothing")));
        let mut owned = packages.clone();
        owned[0]
            .files
            .push(("/bin/ghost".into(), "link:nothing".into()));
        let error = check_owners(image, &dangling, &owned).unwrap_err();
        assert!(
            error.contains("/bin/ghost links to /bin/nothing"),
            "{error}"
        );
        let mut chained = files_of(image);
        chained.push(of("/bin/again", 0o777, ROOT, Source::Link("cat")));
        owned[0].files.pop();
        owned[0]
            .files
            .push(("/bin/again".into(), "link:cat".into()));
        let error = check_owners(image, &chained, &owned).unwrap_err();
        assert!(error.contains("/bin/again links to /bin/cat"), "{error}");
    }

    #[test]
    fn the_table_carries_the_time_of_the_build() {
        let bytes = table_at(&ramfs(), 5, 9, 1_790_000_123).unwrap();
        assert_eq!(Rootfs::parse(&bytes, 9).unwrap().time(), 1_790_000_123);
        assert_eq!(
            Rootfs::parse(&table(&ramfs(), 5, 9).unwrap(), 9)
                .unwrap()
                .time(),
            0
        );
        // SOURCE_DATE_EPOCH is a number of seconds.
        assert!(
            build_time().unwrap() > 1_700_000_000 || std::env::var("SOURCE_DATE_EPOCH").is_ok()
        );
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
    fn lock_probe_images_include_the_mapped_child() {
        for image in [
            "boot-posix-lock-rules.img",
            "boot-posix-lock-core.img",
            "boot-posix-lock-pages.img",
            "boot-posix-lock-fifo.img",
            "boot-posix-spawn-churn.img",
            "boot-posix-sync.img",
            "boot-posix-resources.img",
            "boot-posix-map.img",
        ] {
            let files = files_of(image);
            assert!(
                files.iter().any(|file| file.path == "/bin/procs-child"),
                "{image}"
            );
        }
    }

    /// Each file of the shell image has one owner; a file nobody owns, a
    /// file two packages claim and a file a package lacks are refused.
    #[test]
    fn every_file_of_the_shell_image_has_one_owner() {
        let image = "boot-ash-dialog.img";
        let packages = crate::packages::of_image(image).unwrap();
        let files = files_of(image);
        check_owners(image, &files, &packages).unwrap();
        // A file no package and no system path owns.
        let mut stray = files_of(image);
        stray.push(file("/bin/stray", 0o755, ROOT, "ramfs"));
        let error = check_owners(image, &stray, &packages).unwrap_err();
        assert!(error.contains("/bin/stray"), "{error}");
        // A path two packages name.
        let mut twice = packages.clone();
        let path = twice[1].files[0].clone();
        twice[2].files.push(path.clone());
        let error = check_owners(image, &files, &twice).unwrap_err();
        assert!(error.contains(&path.0), "{error}");
        // A file a package names and the image lacks.
        let mut lacking = packages.clone();
        lacking[1]
            .files
            .push(("/bin/ghost".into(), "elf:busybox-probe".into()));
        let error = check_owners(image, &files, &lacking).unwrap_err();
        assert!(error.contains("/bin/ghost"), "{error}");
        // A package that installs nothing leaves nothing to own: its row
        // has no files.
        assert!(packages.iter().all(|p| !p.files.is_empty()));
    }

    /// The table counts the BusyBox program once for its many names.
    #[test]
    fn the_table_counts_a_shared_program_once() {
        let table = package_table("boot-ash-dialog.img", |source| {
            Ok(match source {
                Source::Elf("busybox-probe") => 1000,
                Source::Elf(_) => 10,
                Source::Link(_) => 0,
                _ => 1,
            })
        })
        .unwrap();
        let row = |name: &str| {
            table
                .lines()
                .find(|l| l.starts_with(name))
                .unwrap_or_else(|| panic!("no row {name}: {table}"))
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        assert_eq!(row("busybox").last().unwrap(), "1000");
        assert_eq!(row("sbase").last().unwrap(), "0");
        assert_eq!(row("nano").last().unwrap(), "10");
    }

    #[test]
    fn every_list_names_programs_of_its_image() {
        let shell = crate::shell_programs();
        let programs_of = |image: &str| -> Vec<&str> {
            let list: &[crate::ImageProgram] = match image {
                "boot-ramfs.img" => &crate::RAMFS_PROGRAMS,
                "boot-ash-dialog.img" => shell,
                "boot-posix-procs.img" | "boot-posix-jobs.img" => &crate::POSIX_PROCS_PROGRAMS,
                "boot-posix-math.img" => &crate::POSIX_MATH_PROGRAMS,
                "boot-posix-park.img" => &crate::POSIX_PARK_PROGRAMS,
                "boot-posix-fifo.img" => &crate::POSIX_FIFO_PROGRAMS,
                "boot-posix-fifo-steps.img" => &crate::POSIX_FIFO_STEPS_PROGRAMS,
                "boot-posix-lifetimes.img" => &crate::POSIX_LIFETIMES_PROGRAMS,
                "boot-posix-lock-rules.img" => &crate::POSIX_LOCK_LIFECYCLE_PROGRAMS,
                "boot-posix-lock-core.img" => &crate::POSIX_LOCK_CORE_PROGRAMS,
                "boot-posix-lock-pages.img" => &crate::POSIX_LOCK_PAGE_PROGRAMS,
                "boot-posix-lock-fifo.img" => &crate::POSIX_LOCK_FIFO_PROGRAMS,
                "boot-posix-spawn-churn.img" => &crate::POSIX_SPAWN_CHURN_PROGRAMS,
                "boot-posix-sync.img" => &crate::POSIX_SYNC_PROGRAMS,
                "boot-posix-resources.img" => &crate::POSIX_RESOURCES_PROGRAMS,
                "boot-posix-map.img" => &crate::POSIX_MAP_PROGRAMS,
                "boot-posix-lock-ring.img" => &crate::POSIX_LOCK_RING_PROGRAMS,
                "boot-posix-native-scopes.img" => &crate::POSIX_NATIVE_SCOPE_PROGRAMS,
                "boot-posix-native-scopes-vz.img" => &crate::POSIX_VZ_NATIVE_SCOPE_PROGRAMS,
                "boot-posix-steps.img" => &crate::POSIX_STEPS_PROGRAMS,
                "boot-posix-tty.img" => &crate::POSIX_TTY_PROGRAMS,
                "boot-posix-tty-steps.img" => &crate::POSIX_TTY_STEPS_PROGRAMS,
                "boot-posix-tty-control-steps.img" => &crate::POSIX_TTY_CONTROL_PROGRAMS,
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
            // Build and parse each image's real file table, including devices.
            let total = sources(&files).len() as u32;
            let bytes = table(&files, 0, total).unwrap_or_else(|error| panic!("{image}: {error}"));
            Rootfs::parse(&bytes, total).unwrap_or_else(|error| panic!("{image}: {error}"));
            // Every entry has its parent directory in the list.
            for f in &files {
                let parent = &f.path[..f.path.rfind('/').unwrap()];
                assert!(parent.is_empty() || files.iter().any(|d| d.path == parent));
            }
        }
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
        let mut files = os_test(&tests);
        // The accounts bring /etc, as in an image.
        files.extend(accounts());
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
        assert_eq!(wanted.len(), 15);
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
            "boot-posix-lifetimes.img",
            "boot-posix-lock-rules.img",
            "boot-posix-lock-core.img",
            "boot-posix-lock-pages.img",
            "boot-posix-lock-fifo.img",
            "boot-posix-spawn-churn.img",
            "boot-posix-sync.img",
            "boot-posix-resources.img",
            "boot-posix-map.img",
            "boot-posix-lock-ring.img",
            "boot-posix-random.img",
            "boot-posix-pty.img",
            "boot-posix-steps.img",
            "rtbench-posix.img",
            "rtbench-posix-vz.img",
            "rtbench-posix-short.img",
        ] {
            let files = files_of(name);
            for path in [
                "/dev",
                "/dev/pts",
                "/dev/shm",
                "/dev/null",
                "/dev/random",
                "/dev/urandom",
            ] {
                assert_eq!(
                    files.iter().filter(|f| f.path == path).count(),
                    1,
                    "{name} {path}"
                );
            }
        }
        let os_test = os_test(&[]);
        for path in [
            "/dev",
            "/dev/pts",
            "/dev/shm",
            "/dev/null",
            "/dev/random",
            "/dev/urandom",
        ] {
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
