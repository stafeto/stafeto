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
fn accounts() -> [RootFile; 4] {
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
        // Every account is locked: `!` in the password field matches no
        // hash, and the image carries no password of any owner.
        of(
            "/etc/shadow",
            0o600,
            ROOT,
            Source::Bytes(
                "shadow",
                b"root:!:20000:0:99999:7:::\nuser:!:20000:0:99999:7:::\nnobody:!:20000:0:99999:7:::\n",
            ),
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
const SYSTEM_PATHS: [&str; 65] = [
    "/bin",
    "/lib",
    "/lib/libc.so",
    "/libexec",
    "/libexec/ramfs",
    "/dev",
    "/proc",
    "/sys",
    "/sys/devices",
    "/sys/devices/system",
    "/sys/devices/system/cpu",
    "/sys/devices/system/cpu/cpu0",
    "/sys/devices/system/cpu/cpu1",
    "/sys/devices/system/cpu/cpu2",
    "/sys/devices/system/cpu/cpu3",
    "/sys/devices/system/cpu/cpu4",
    "/sys/devices/system/cpu/cpu5",
    "/sys/devices/system/cpu/cpu6",
    "/sys/devices/system/cpu/cpu7",
    "/root",
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
    "/etc/shadow",
    "/etc/resolv.conf",
    // The image on VZ with a static address for its second device.
    "/etc/netd.conf",
    // The image with the network service: the page `httpd` serves and the
    // probe of the sockets.
    "/www",
    "/www/index.html",
    // The large file of the probe of TLS (net_tls.rs).
    "/www/256k.bin",
    "/bin/net-sock",
    "/bin/net-dns",
    "/bin/posix-net",
    // The image of the probe of the second network device's owner.
    "/bin/fast-echo",
    // The image of the switch's probe.
    "/bin/switch-probe",
    // The image of the probe of F-Stack on its loopback.
    "/bin/fstack-probe",
    // The probe of the layer's sockets over the stack in a process.
    "/bin/fast-layer",
    // The image of `nginx-probe`: the files it fetches and the setting of
    // nginx with one listening socket for all the workers.
    "/www/10k.bin",
    // ... and the file of 1 MiB of the download of nginx on the stack.
    "/www/1m.bin",
    // ... and the small page whose answer times the wake of the idle loop.
    "/www/tiny.txt",
    "/etc/nginx/exclusive.conf",
    // The images of nginx on the stack: the variant of its settings that
    // runs the worker under nobody.
    "/etc/nginx/nginx-fast-nobody.conf",
    "/etc/nginx/nginx-fast-4.conf",
    "/etc/nginx/nginx-fast-9.conf",
    "/etc/nginx/nginx-fast-b.conf",
    "/etc/nginx/nginx-fast-sndbuf.conf",
    // ... and nginx's server of TLS with the key and the certificate the
    // probe CA made for it.
    "/etc/nginx/tls.conf",
    "/etc/nginx/server.crt",
    "/etc/nginx/server.key",
    // The images of the measurement of stage P7: the settings of W4 and W5,
    // the plain ones with the include of that server.
    "/etc/nginx/nginx-tls.conf",
    "/etc/nginx/nginx-fast-tls.conf",
    // The images of nginx's measurement: the smallest file of the load.
    "/www/1k.bin",
    // The package tool and what it trusts: the official repository's line and the roots
    // of the build (the owner's repositories and keys come from the layer of settings).
    "/bin/pkg",
    "/etc/pkg",
    "/etc/pkg/keys",
    "/etc/pkg/official",
    "/etc/pkg/keys/stafeto.pub",
];

/// Whether the base system owns `path`: the paths above and the device
/// nodes below /dev.
pub fn is_system(path: &str) -> bool {
    SYSTEM_PATHS.contains(&path)
        || path == ENA_NOTICE
        || path == "/usr/share/licenses"
        || path == "/usr/share/licenses/stafeto"
        || path.starts_with("/dev/")
        // The sets W1 and W2 of the load, in the image of the measurement
        // of stage P7 (`net_bench_files`).
        || path == "/www/s"
        || path == "/www/l"
        || path.starts_with("/www/s/")
        || path.starts_with("/www/l/")
        || ZONES
            .iter()
            .any(|(zone, _)| path == format!("{ZONEINFO}/{zone}"))
        || ZONE_DIRS.iter().any(|d| path == format!("{ZONEINFO}/{d}"))
        || path == ZONEINFO
}

/// Where the image keeps its time zones: TZif files, which the C library reads
/// for TZ=<name>. The set is UTC and ten common zones (docs/status.md); the
/// files are `zic -b slim` output of tzdata 2026e (docs/zoneinfo.md).
const ZONEINFO: &str = "/usr/share/zoneinfo";
const ZONE_DIRS: [&str; 5] = ["Etc", "Europe", "America", "Asia", "Australia"];
const ZONES: [(&str, &[u8]); 10] = [
    ("Etc/UTC", include_bytes!("../zoneinfo/Etc/UTC")),
    ("Europe/London", include_bytes!("../zoneinfo/Europe/London")),
    ("Europe/Berlin", include_bytes!("../zoneinfo/Europe/Berlin")),
    ("Europe/Moscow", include_bytes!("../zoneinfo/Europe/Moscow")),
    (
        "America/New_York",
        include_bytes!("../zoneinfo/America/New_York"),
    ),
    (
        "America/Chicago",
        include_bytes!("../zoneinfo/America/Chicago"),
    ),
    (
        "America/Los_Angeles",
        include_bytes!("../zoneinfo/America/Los_Angeles"),
    ),
    ("Asia/Tokyo", include_bytes!("../zoneinfo/Asia/Tokyo")),
    ("Asia/Kolkata", include_bytes!("../zoneinfo/Asia/Kolkata")),
    (
        "Australia/Sydney",
        include_bytes!("../zoneinfo/Australia/Sydney"),
    ),
];

/// The programs of the images that the build of libc.so makes (`cargo xtask
/// libc-so`, spec 2, 3.12.3), each with its file under target/libc-so: the
/// shared library itself, the good dynamic programs of tests/posix-so and the
/// bad ones the loader refuses.
pub const SHARED: [(&str, &str); 16] = [
    ("libc.so", "libc.so"),
    ("so-hello", "probes/so-hello"),
    ("so-image", "probes/so-image"),
    ("bad-interp", "probes/bad-interp"),
    ("bad-copy", "probes/bad-copy"),
    ("bad-tls", "probes/bad-tls"),
    ("bad-needed", "probes/bad-needed"),
    ("bad-symbol", "probes/bad-symbol"),
    ("bad-ifunc", "probes/bad-ifunc"),
    ("bad-pie", "probes/bad-pie"),
    ("display-probe", "probes/display-probe"),
    ("net-sock", "probes/net-sock"),
    ("net-dns", "probes/net-dns"),
    ("posix-net", "probes/posix-net"),
    ("fast-echo", "probes/fast-echo"),
    ("switch-probe", "probes/switch-probe"),
];

/// The path of the library in the images, which the loader opens.
pub const LIBRARY: &str = "/lib/libc.so";

/// The file of `program` the build of libc.so wrote, if it is one of its.
pub fn shared_path(program: &str) -> Option<&'static str> {
    SHARED.iter().find(|(n, _)| *n == program).map(|(_, p)| *p)
}

/// The directory of the library and the library, for an image that has a
/// dynamic program (the loader opens it for every one of them).
fn library() -> Vec<RootFile> {
    vec![dir("/lib"), file(LIBRARY, 0o755, ROOT, "libc.so")]
}

/// The dynamic programs of the probe of tests/posix-so (the library comes
/// with `procs`).
fn shared_files() -> Vec<RootFile> {
    let mut files = Vec::new();
    // The owner of the second network device goes into the image of its
    // probe alone (fast_probe.rs).
    for (name, _) in SHARED[1..]
        .iter()
        .filter(|(n, _)| !matches!(*n, "fast-echo" | "switch-probe"))
    {
        let path: &'static str = match *name {
            "so-hello" => "/bin/so-hello",
            "so-image" => "/bin/so-image",
            "bad-interp" => "/bin/bad-interp",
            "bad-copy" => "/bin/bad-copy",
            "bad-tls" => "/bin/bad-tls",
            "bad-needed" => "/bin/bad-needed",
            "bad-symbol" => "/bin/bad-symbol",
            "bad-ifunc" => "/bin/bad-ifunc",
            "display-probe" => "/bin/display-probe",
            "net-sock" => "/bin/net-sock",
            "net-dns" => "/bin/net-dns",
            "posix-net" => "/bin/posix-net",
            _ => "/bin/bad-pie",
        };
        files.push(file(path, 0o755, ROOT, name));
    }
    files
}

/// The directories and files of the time zones of the image.
fn zoneinfo() -> Vec<RootFile> {
    fn leak(text: String) -> &'static str {
        Box::leak(text.into_boxed_str())
    }
    let mut files = vec![dir(ZONEINFO)];
    files.extend(
        ZONE_DIRS
            .iter()
            .map(|d| dir(leak(format!("{ZONEINFO}/{d}")))),
    );
    files.extend(ZONES.iter().map(|&(zone, bytes)| {
        of(
            leak(format!("{ZONEINFO}/{zone}")),
            0o644,
            ROOT,
            Source::Bytes(leak(format!("zoneinfo-{}", zone.replace('/', "-"))), bytes),
        )
    }));
    files
}

/// The WAD of Freedoom as `tools/build-freedoom.py` unpacked it, read once
/// in a run of xtask. Where the script has not run (the check of the
/// descriptions needs the paths of an image only) the file is empty, and
/// the build of the games image refuses an image that carries it so.
fn freedoom_wad() -> &'static [u8] {
    static WAD: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    WAD.get_or_init(|| {
        let version = crate::packages::value("freedoom", "version").unwrap_or_default();
        let path = crate::target_dir().join(format!("freedoom/freedoom-{version}/freedoom1.wad"));
        std::fs::read(path).unwrap_or_default()
    })
}

/// The bytes of the files that packages name as `bytes:<name>`.
fn named_bytes(name: &str) -> Result<&'static [u8], String> {
    match name {
        "inputrc" => Ok(INPUTRC),
        "htoprc" => Ok(b"hide_userland_threads=1\n"),
        "freedoom1.wad" => Ok(freedoom_wad()),
        "fstack.ini" => Ok(include_bytes!("../../ports/f-stack/fstack.ini")),
        "ca-certificates.crt" => Ok(crate::net_tls::ca_bundle()),
        "mime.types" => Ok(crate::nginx_probe::mime_types()),
        "nginx.conf" => Ok(crate::nginx_probe::NGINX_CONF.as_bytes()),
        "nginx-fast.conf" => Ok(crate::fast_nginx::NGINX_FAST_CONF.as_bytes()),
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
fn dialog(image: &str) -> Vec<RootFile> {
    shell_files(image).unwrap_or_else(|e| panic!("the shell image: {e}"))
}

/// The files of the shell image `image`: the same base system, and the
/// packages the image holds (`packages::of_image`), the games with them in
/// the games image.
fn shell_files(image: &str) -> Result<Vec<RootFile>, String> {
    let mut files = library();
    files.extend([
        dir("/bin"),
        dir("/libexec"),
        file("/libexec/ramfs", 0o4750, USER, "ramfs"),
        dir("/dev"),
        dir("/proc"),
        // The directory of the CPUs, which htop and `nproc --all` count: a
        // directory for each CPU the machine can have, of which the
        // listing (the layer's) names the CPUs that are up.
        dir("/sys"),
        dir("/sys/devices"),
        dir("/sys/devices/system"),
        dir("/sys/devices/system/cpu"),
        dir("/sys/devices/system/cpu/cpu0"),
        dir("/sys/devices/system/cpu/cpu1"),
        dir("/sys/devices/system/cpu/cpu2"),
        dir("/sys/devices/system/cpu/cpu3"),
        dir("/sys/devices/system/cpu/cpu4"),
        dir("/sys/devices/system/cpu/cpu5"),
        dir("/sys/devices/system/cpu/cpu6"),
        dir("/sys/devices/system/cpu/cpu7"),
        // The home of root (the account's directory in /etc/passwd), where
        // htop and the other programs keep their settings.
        RootFile {
            mode: 0o700,
            ..dir("/root")
        },
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
    ]);
    files.extend(package_files(&crate::packages::of_image(image)?)?);
    files.extend(zoneinfo());
    files.extend(devices());
    Ok(files)
}

/// The tree of an image split in two: what the table `rootfs` of the image
/// holds, and the packages whose package files (`.stpkg`) the image holds
/// as layers (docs/packages.md).
pub struct Layered {
    /// The files of the table: the system's, with the directories above
    /// them (a layer's directory merges with the table's).
    pub system: Vec<RootFile>,
    pub packages: Vec<LayerPackage>,
}

/// A package of an image.
pub struct LayerPackage {
    pub package: crate::packages::Package,
    /// The bytes that replace the package's own at paths of the package (a probe's settings, a certificate file with its own
    /// authority): the image holds a variant of the package file.
    pub replaced: Vec<(&'static str, &'static [u8])>,
}

/// The paths `package` names, the files and its directories.
fn owns(package: &crate::packages::Package, path: &str) -> bool {
    package.files.iter().any(|(p, _)| p == path) || package.dirs.iter().any(|d| d == path)
}

/// Splits the list of the image `name` (`files_of`) into its table and its
/// layers: the files a package of the image names are the package's, with
/// the bytes the list gives them when those differ from the package's own;
/// all others are the system's.
pub fn layered(name: &str) -> Result<Layered, String> {
    let packages: Vec<crate::packages::Package> = crate::packages::of_image(name)?
        .into_iter()
        .filter(|p| !(p.files.is_empty() && p.dirs.is_empty()))
        .collect();
    let declared = package_files(&packages)?;
    let mut layers: Vec<LayerPackage> = packages
        .iter()
        .map(|p| LayerPackage {
            package: p.clone(),
            replaced: Vec::new(),
        })
        .collect();
    let mut system = Vec::new();
    for f in files_of(name) {
        let Some(at) = packages.iter().position(|p| owns(p, f.path)) else {
            system.push(f);
            continue;
        };
        let own = declared
            .iter()
            .find(|d| d.path == f.path)
            .ok_or_else(|| format!("{name}: {} is declared by no package", f.path))?;
        if f.source == own.source && (f.mode, f.uid, f.gid) == (own.mode, own.uid, own.gid) {
            continue;
        }
        match (f.source, own.source) {
            (Some(Source::Bytes(_, bytes)), Some(Source::Bytes(..)))
                if (f.mode, f.uid, f.gid) == (own.mode, own.uid, own.gid) =>
            {
                layers[at].replaced.push((f.path, bytes));
            }
            _ => {
                return Err(format!(
                    "{name}: {} of {} differs from the package's in more than its bytes",
                    f.path, packages[at].name
                ));
            }
        }
    }
    // The table holds the directories above its files, as a package that
    // names them would give them.
    let mut have: Vec<&'static str> = system.iter().map(|f| f.path).collect();
    let mut above = Vec::new();
    for f in &system {
        for (i, _) in f.path.match_indices('/').skip(1) {
            let parent = &f.path[..i];
            if !have.contains(&parent) {
                have.push(parent);
                above.push(
                    declared
                        .iter()
                        .find(|d| d.path == parent && d.source.is_none())
                        .map_or(dir(parent), |d| RootFile {
                            path: parent,
                            mode: d.mode,
                            uid: d.uid,
                            gid: d.gid,
                            source: None,
                        }),
                );
            }
        }
    }
    system.extend(above);
    Ok(Layered {
        system,
        packages: layers,
    })
}

/// The notice of the ENA driver (`lib/ena/NOTICE`: the BSD-3-Clause text of the
/// headers whose numbers the driver carries, which its second condition asks
/// every binary distribution to reproduce): the directories and the file an
/// image with `netd` holds under `/usr/share/licenses/stafeto/`.
pub fn ena_notice() -> Vec<RootFile> {
    vec![
        dir("/usr"),
        dir("/usr/share"),
        dir("/usr/share/licenses"),
        dir("/usr/share/licenses/stafeto"),
        of(
            ENA_NOTICE,
            0o644,
            ROOT,
            Source::Bytes("ENA-NOTICE", include_bytes!("../../lib/ena/NOTICE")),
        ),
    ]
}

/// Where the notice of the ENA driver lies in an image.
pub const ENA_NOTICE: &str = "/usr/share/licenses/stafeto/ena-NOTICE";

/// The directories and files of the notices of the system, which an image
/// with layers holds under `/usr/share/licenses/stafeto/`: the licences of
/// the tree, the notices of relibc (the file of the container the image
/// carries for the programs on relibc) and of the crates that programs
/// link (`docs/licenses`).
pub fn system_notices(relibc: &'static [u8]) -> Result<Vec<RootFile>, String> {
    fn leak(text: String) -> &'static str {
        Box::leak(text.into_boxed_str())
    }
    let root = crate::root();
    let base = "/usr/share/licenses/stafeto";
    let mut files = vec![
        dir("/usr"),
        dir("/usr/share"),
        dir("/usr/share/licenses"),
        dir(base),
    ];
    for (n, name) in ["LICENSE", "LICENSE-MIT", "LICENSE-GCC-exception-3.1"]
        .into_iter()
        .enumerate()
    {
        let bytes = std::fs::read(root.join(name)).map_err(|e| format!("{name}: {e}"))?;
        files.push(of(
            leak(format!("{base}/{name}")),
            0o644,
            ROOT,
            Source::Bytes(
                leak(format!("stafeto-notice-{n}")),
                Box::leak(bytes.into_boxed_slice()),
            ),
        ));
    }
    files.push(of(
        leak(format!("{base}/relibc-THIRD-PARTY-NOTICES")),
        0o644,
        ROOT,
        Source::Bytes("THIRD-PARTY-NOTICES", relibc),
    ));
    files.push(dir(leak(format!("{base}/crates"))));
    // The tree of docs/licenses, in order, with the files named by number.
    let mut stack = vec![(root.join("docs/licenses"), format!("{base}/crates"))];
    let mut count = 0;
    while let Some((from, to)) = stack.pop() {
        let mut entries: Vec<_> = std::fs::read_dir(&from)
            .map_err(|e| format!("{}: {e}", from.display()))?
            .flatten()
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let name = e.file_name().to_string_lossy().into_owned();
            let path = format!("{to}/{name}");
            if e.path().is_dir() {
                files.push(dir(leak(path.clone())));
                stack.push((e.path(), path));
            } else {
                let bytes = std::fs::read(e.path()).map_err(|e| e.to_string())?;
                count += 1;
                files.push(of(
                    leak(path),
                    0o644,
                    ROOT,
                    Source::Bytes(
                        leak(format!("crate-licence-{count}")),
                        Box::leak(bytes.into_boxed_slice()),
                    ),
                ));
            }
        }
    }
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
        let kind = p.kind.word();
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
        "{:<12} {:<14} {:<17} {:<8} {:>6} {:>10}\n",
        "package", "version", "license", "kind", "files", "bytes"
    );
    for (name, version, license, kind, count, bytes) in &rows {
        out +=
            &format!("{name:<12} {version:<14} {license:<17} {kind:<8} {count:>6} {bytes:>10}\n");
    }
    let total: u64 = rows.iter().map(|r| r.5).sum();
    out += &format!(
        "{:<12} {:<14} {:<17} {:<8} {:>6} {:>10}\n",
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
    let mut files = library();
    files.extend([
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
    ]);
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
    let mut files = library();
    files.extend([
        dir("/bin"),
        file("/bin/rtbench-posix", 0o755, ROOT, "rtbench-posix"),
        file("/bin/ls", 0o755, ROOT, "busybox-probe"),
        file("/bin/cat", 0o755, ROOT, "busybox-probe"),
        file("/bin/ls-dyn", 0o755, ROOT, "busybox-dyn"),
        file("/bin/cat-dyn", 0o755, ROOT, "busybox-dyn"),
        dir("/dev"),
    ]);
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

/// The files of an image of the Open POSIX Test Suite: the tests of
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

/// `/etc/netd.conf` of the image of the probe with a static address: the
/// QEMU user network's own settings, so that no DHCP frame is needed.
const NETD_CONF_STATIC: &[u8] = b"address 10.0.2.15/24\ngateway 10.0.2.2\ndns 10.0.2.3\n";

/// `/etc/netd.conf` of the VZ image with a static address for the second
/// device: no address for the first, which keeps DHCP.
const NETD_CONF_STATIC1: &[u8] = b"address1 192.168.64.250/24\n";

/// `/etc/netd.conf` of the VZ images with one device: the segmentation offload on.
const NETD_CONF_TSO: &[u8] = b"tso 1\n";

/// The files of the shell images with the network service: the shell's, the
/// page `httpd -h /www` serves, and the probes of the sockets and of the
/// resolver. `/etc/resolv.conf` is the network service's to write.
fn net_files(image: &str) -> Vec<RootFile> {
    let mut files = dialog(image);
    files.push(dir("/www"));
    files.push(of(
        "/www/index.html",
        0o644,
        ROOT,
        Source::Bytes("www-index", www_index()),
    ));
    files.push(file("/bin/net-sock", 0o755, ROOT, "net-sock"));
    files.push(file("/bin/net-dns", 0o755, ROOT, "net-dns"));
    files.push(file("/bin/posix-net", 0o755, ROOT, "posix-net"));
    files
}
/// The files of the images of `nginx-probe`: those of the shell with the
/// network (nginx among them), with the probe's variant of nginx's settings
/// as the package's, the variant with one listening socket, the
/// files of 10 KiB and 256 KiB the probe fetches, `netd.conf` with eight
/// buffers, and the server of TLS (`tls.conf`) with nginx's certificate and
/// key from the probe CA, the key readable by root alone.
fn nginx_files(image: &str) -> Vec<RootFile> {
    let mut files = net_files(image);
    let settings = files
        .iter_mut()
        .find(|f| f.path == "/etc/nginx/nginx.conf")
        .unwrap_or_else(|| panic!("{image}: no /etc/nginx/nginx.conf"));
    settings.source = Some(Source::Bytes(
        "nginx-probe.conf",
        crate::nginx_probe::probe_conf().as_bytes(),
    ));
    files.extend([
        of(
            "/etc/nginx/exclusive.conf",
            0o644,
            ROOT,
            Source::Bytes(
                "nginx-exclusive.conf",
                crate::nginx_probe::exclusive_conf().as_bytes(),
            ),
        ),
        of(
            "/www/10k.bin",
            0o644,
            ROOT,
            Source::Bytes("nginx-10k", crate::nginx_probe::www_10k()),
        ),
        of(
            "/www/256k.bin",
            0o644,
            ROOT,
            Source::Bytes("www-256k", crate::net_tls::big_file()),
        ),
        of(
            "/etc/netd.conf",
            0o644,
            ROOT,
            Source::Bytes("netd.conf", crate::nginx_probe::NETD_CONF),
        ),
        of(
            crate::nginx_probe::TLS_CONF_PATH,
            0o644,
            ROOT,
            Source::Bytes("nginx-tls.conf", crate::nginx_probe::TLS_CONF.as_bytes()),
        ),
        of(
            crate::nginx_probe::SERVER_CRT,
            0o644,
            ROOT,
            Source::Bytes("nginx.crt", crate::probe_ca::nginx_certificate()),
        ),
        of(
            crate::nginx_probe::SERVER_KEY,
            0o600,
            ROOT,
            Source::Bytes("nginx.key", crate::probe_ca::nginx_key()),
        ),
    ]);
    files
}

/// The files of the images of nginx on the stack (`cargo xtask fast-probe
/// nginx`, `net-vz --fast --nginx`): those of the shell with the network, with
/// the probe's variant of the settings of `nginx-fast` as the
/// package's, the variant under nobody, the files of 10 KiB and 256 KiB the
/// probe fetches, the second device's fixed address in `netd.conf`, and the
/// server of TLS with the probe CA's certificate and key.
fn fast_nginx_files(image: &str) -> Vec<RootFile> {
    let mut files = net_files(image);
    let settings = files
        .iter_mut()
        .find(|f| f.path == "/etc/nginx/nginx-fast.conf")
        .unwrap_or_else(|| panic!("{image}: no /etc/nginx/nginx-fast.conf"));
    settings.source = Some(Source::Bytes(
        "nginx-fast-probe.conf",
        crate::fast_nginx::probe_conf().as_bytes(),
    ));
    files.extend([
        of(
            "/etc/nginx/nginx-fast-nobody.conf",
            0o644,
            ROOT,
            Source::Bytes(
                "nginx-fast-nobody.conf",
                crate::fast_nginx::nobody_conf().as_bytes(),
            ),
        ),
        of(
            crate::fast_nginx::SNDBUF_CONF,
            0o644,
            ROOT,
            Source::Bytes(
                "nginx-fast-sndbuf.conf",
                crate::fast_nginx::sndbuf_conf().as_bytes(),
            ),
        ),
        of(
            "/www/10k.bin",
            0o644,
            ROOT,
            Source::Bytes("nginx-10k", crate::nginx_probe::www_10k()),
        ),
        of(
            "/www/256k.bin",
            0o644,
            ROOT,
            Source::Bytes("www-256k", crate::net_tls::big_file()),
        ),
        of(
            "/www/1m.bin",
            0o644,
            ROOT,
            Source::Bytes("www-1m", crate::fast_nginx::one_mib()),
        ),
        of(
            "/www/tiny.txt",
            0o644,
            ROOT,
            Source::Bytes("www-tiny", crate::fast_nginx::TINY),
        ),
        of(
            "/etc/netd.conf",
            0o644,
            ROOT,
            Source::Bytes(
                "netd.conf",
                if image == crate::fast_nginx::VZ_IMAGE
                    || image == crate::fast_nginx::VZ_STEPS_IMAGE
                {
                    crate::fast_probe::NETD_CONF_VZ_STATIC
                } else {
                    crate::fstack_device::NETD_CONF
                },
            ),
        ),
        of(
            crate::nginx_probe::TLS_CONF_PATH,
            0o644,
            ROOT,
            Source::Bytes("nginx-tls.conf", crate::nginx_probe::TLS_CONF.as_bytes()),
        ),
        of(
            crate::nginx_probe::SERVER_CRT,
            0o644,
            ROOT,
            Source::Bytes("nginx.crt", crate::probe_ca::nginx_certificate()),
        ),
        of(
            crate::nginx_probe::SERVER_KEY,
            0o600,
            ROOT,
            Source::Bytes("nginx.key", crate::probe_ca::nginx_key()),
        ),
    ]);
    files
}

/// The files of the images of the switch: those of the images of nginx on
/// the stack with the settings under nobody, `netd.conf` with the switch (and
/// the address of the lease, no second device), and the probe of the ring.
fn switch_files(image: &str) -> Vec<RootFile> {
    let mut files = fast_nginx_files(image);
    for (path, name, bytes) in [
        (
            "/etc/nginx/nginx-fast.conf",
            "nginx-fast-switch.conf",
            crate::fast_nginx::switch_conf().as_bytes(),
        ),
        (
            "/etc/netd.conf",
            "netd-switch.conf",
            crate::fast_nginx::switch_netd_conf(),
        ),
    ] {
        let file = files
            .iter_mut()
            .find(|f| f.path == path)
            .unwrap_or_else(|| panic!("{image}: no {path}"));
        file.source = Some(Source::Bytes(name, bytes));
    }
    files.push(file("/bin/switch-probe", 0o755, ROOT, "switch-probe"));
    files.push(of(
        "/etc/nginx/nginx-fast-4.conf",
        0o644,
        ROOT,
        Source::Bytes("nginx-fast-4.conf", crate::fast_switch::conf4().as_bytes()),
    ));
    files.push(of(
        "/etc/nginx/nginx-fast-9.conf",
        0o644,
        ROOT,
        Source::Bytes("nginx-fast-9.conf", crate::fast_switch::conf9().as_bytes()),
    ));
    files.push(of(
        "/etc/nginx/nginx-fast-b.conf",
        0o644,
        ROOT,
        Source::Bytes("nginx-fast-b.conf", crate::fast_switch::conf_b().as_bytes()),
    ));
    files
}

/// The files of the images of nginx's measurement (`nginx-bench`): those of
/// the shell with the network (nginx with the package's settings among
/// them), the variant of the settings with one listening socket, the files
/// of 1 KiB, 10 KiB and 256 KiB of the load and, in the images without the
/// shared buffers, `netd.conf` with `buffers 0`.
fn nginx_bench_files(image: &str) -> Vec<RootFile> {
    let mut files = net_files(image);
    files.extend([
        of(
            "/etc/nginx/exclusive.conf",
            0o644,
            ROOT,
            Source::Bytes(
                "nginx-bench-exclusive.conf",
                crate::nginx_bench::exclusive_conf().as_bytes(),
            ),
        ),
        of(
            "/www/1k.bin",
            0o644,
            ROOT,
            Source::Bytes("nginx-1k", crate::nginx_bench::www_1k()),
        ),
        of(
            "/www/10k.bin",
            0o644,
            ROOT,
            Source::Bytes("nginx-10k", crate::nginx_probe::www_10k()),
        ),
        of(
            "/www/256k.bin",
            0o644,
            ROOT,
            Source::Bytes("www-256k", crate::net_tls::big_file()),
        ),
    ]);
    if image.ends_with("-nobuf.img") {
        files.push(of(
            "/etc/netd.conf",
            0o644,
            ROOT,
            Source::Bytes("netd.conf", crate::nginx_bench::NO_BUFFERS_CONF),
        ));
    }
    files
}

/// The files of the image of the measurement of stage P7 (`boot-net-bench.img`):
/// those of the images of nginx's measurement and the two sets of the load,
/// W1 under `/www/s/` and W2 under `/www/l/` (`linux_guest::www_files`), the
/// same files as the Linux guest carries.
fn net_bench_files(image: &str) -> Vec<RootFile> {
    let mut files = nginx_bench_files(image);
    files.push(dir("/www/s"));
    files.push(dir("/www/l"));
    // W4 and W5: the settings with the server of TLS (both variants, the
    // row picks its own), the server of TLS, the probe CA's key and
    // certificate, the key readable by root alone.
    files.extend([
        of(
            crate::linux_guest::TLS_CONF,
            0o644,
            ROOT,
            Source::Bytes(
                "nginx-tls.conf",
                crate::linux_guest::nginx_tls_conf().as_bytes(),
            ),
        ),
        of(
            crate::linux_guest::FAST_TLS_CONF,
            0o644,
            ROOT,
            Source::Bytes(
                "nginx-fast-tls.conf",
                crate::linux_guest::nginx_fast_tls_conf().as_bytes(),
            ),
        ),
        of(
            crate::nginx_probe::TLS_CONF_PATH,
            0o644,
            ROOT,
            Source::Bytes(
                "nginx-tls.conf-server",
                crate::nginx_probe::TLS_CONF.as_bytes(),
            ),
        ),
        of(
            crate::nginx_probe::SERVER_CRT,
            0o644,
            ROOT,
            Source::Bytes("nginx.crt", crate::probe_ca::nginx_certificate()),
        ),
        of(
            crate::nginx_probe::SERVER_KEY,
            0o600,
            ROOT,
            Source::Bytes("nginx.key", crate::probe_ca::nginx_key()),
        ),
    ]);
    for (path, bytes) in crate::linux_guest::www_files() {
        if path.starts_with("/www/s/") || path.starts_with("/www/l/") {
            let name: &'static str = Box::leak(path[1..].replace('/', "-").into_boxed_str());
            files.push(of(path, 0o644, ROOT, Source::Bytes(name, bytes)));
        }
    }
    files
}

/// The bytes of `/www/index.html` of the image with the network service: 64
/// KiB of lines from a fixed generator, so that the host knows the page
/// without reading the image (`cargo xtask net-curl`).
pub fn www_index() -> &'static [u8] {
    static PAGE: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    PAGE.get_or_init(|| {
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut page = Vec::with_capacity(WWW_INDEX_LEN);
        let mut line = 0;
        while page.len() < WWW_INDEX_LEN {
            let text = format!("{line:06} {:016x}{:016x}{:016x}\n", next(), next(), next());
            page.extend_from_slice(text.as_bytes());
            line += 1;
        }
        page.truncate(WWW_INDEX_LEN - 1);
        page.push(b'\n');
        page
    })
}

/// The length of the page.
pub const WWW_INDEX_LEN: usize = 64 * 1024;

/// The names of the images that carry a table, which `files_of` lists.
#[cfg(test)]
pub const IMAGES: &[&str] = &[
    "boot-ramfs.img",
    "boot-net.img",
    "boot-net-curl-steps.img",
    "boot-net-tls.img",
    "boot-net-tls-steps.img",
    "boot-posix-net-steps.img",
    "boot-nginx-probe.img",
    "boot-nginx-probe-steps.img",
    "boot-nginx-bench.img",
    "boot-nginx-bench-nobuf.img",
    "boot-nginx-bench-vz.img",
    "boot-nginx-bench-vz-nobuf.img",
    "boot-fast-nginx.img",
    "boot-fast-nginx-crash.img",
    "boot-fast-nginx-steps.img",
    "boot-fast-nginx-vz.img",
    "boot-fast-nginx-vz-steps.img",
    "boot-fast-scale.img",
    "boot-fast-switch.img",
    "boot-fast-switch-steps.img",
    "boot-fast-switch-vz.img",
    "boot-net-vz.img",
    "boot-net-vz2.img",
    "boot-net-vz2-static.img",
    "boot-net-vz-steps.img",
    "boot-net-vz2-steps.img",
    "boot-fast-vz.img",
    "boot-fast-vz-static.img",
    "boot-fast-vz-steps.img",
    "boot-net-probe.img",
    "boot-net-probe-static.img",
    "boot-net-probe-its.img",
    "boot-net-probe-its-static.img",
    "boot-net-its.img",
    "boot-net-steps.img",
    "boot-net-probe-two.img",
    "boot-net-steps-two.img",
    "boot-ash-dialog.img",
    "boot-doom.img",
    "boot-doom-steps.img",
    "boot-base.img",
    "boot-full.img",
    "boot-pkg-probe.img",
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
    "boot-posix-map-big.img",
    "boot-posix-so.img",
    "boot-posix-lock-ring.img",
    "boot-posix-shares.img",
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

/// The official roots, as the file `/etc/pkg/keys/stafeto.pub` of a release holds them: the
/// bytes `pkgfmt::OFFICIAL_ROOTS` bakes into `pkg` and `pkgd`.
fn official_roots() -> Vec<u8> {
    pkgfmt::OFFICIAL_ROOTS.concat().into_bytes()
}

/// The package tool and the files of what it trusts (pk4-design R15): `/bin/pkg`, the
/// directories of `/etc/pkg`, the line of the official repository and the roots.
fn pkg_files(address: &str, roots: &[u8]) -> Vec<RootFile> {
    let leak = |text: String| -> &'static [u8] { Box::leak(text.into_bytes().into_boxed_slice()) };
    let official: &'static [u8] = leak(format!("stafeto {address}\n"));
    let roots: &'static [u8] = Box::leak(roots.to_vec().into_boxed_slice());
    vec![
        file("/bin/pkg", 0o755, ROOT, "pkg"),
        dir("/etc/pkg"),
        dir("/etc/pkg/keys"),
        of(
            "/etc/pkg/official",
            0o444,
            ROOT,
            Source::Bytes("pkg-official", official),
        ),
        of(
            "/etc/pkg/keys/stafeto.pub",
            0o444,
            ROOT,
            Source::Bytes("pkg-roots", roots),
        ),
    ]
}

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
            // The probe of these images runs the Change stages of
            // posix-files too (feature loader-abort takes `files`), whose
            // cancelled renames work on the directories of the boot table.
            if name != "boot-ramfs-cleanup.img" {
                files.extend(change_dirs());
            }
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
        // The layer probe: the directories of its layers (xtask layer_probe adds the layers
        // as files of /test/layers; /etc/passwd comes with the accounts, for a layer to clash with)
        // and the devices the POSIX layer opens.
        "boot-layer-probe.img" | "boot-layer-probe-steps.img" => {
            let mut files = vec![dir("/dev"), dir("/test"), dir("/test/layers")];
            files.extend(devices());
            files
        }
        "boot-ash-dialog.img" | "boot-aws.img" | "boot-doom.img" | "boot-doom-steps.img" => {
            dialog(name)
        }
        // The base image has no package that makes /usr and /usr/share,
        // which the time zones stand in.
        // The probe of the package tool (crate::pkg_probe) is the base image with the probe CA
        // in the certificate file and the mirror of the probe as the official repository,
        // trusting the development root.
        // The full image without a package (`image full --without`) is the full image.
        name if matches!(
            name,
            "boot-base.img" | "boot-full.img" | "boot-pkg-probe.img"
        ) || crate::packages::without_name(name).is_some() =>
        {
            let mut files = dialog(name);
            for d in ["/usr", "/usr/share"] {
                if !files.iter().any(|f| f.path == d) {
                    files.push(dir(d));
                }
            }
            if name == "boot-pkg-probe.img" {
                for f in files
                    .iter_mut()
                    .filter(|f| f.path == crate::net_tls::CA_BUNDLE)
                {
                    f.source = Some(Source::Bytes(
                        "bundle-with-ca.crt",
                        crate::probe_ca::bundle_with_ca(),
                    ));
                }
                files.extend(pkg_files(
                    &crate::pkg_probe::official_address(),
                    &crate::pkg_probe::roots_file(),
                ));
            } else {
                files.extend(pkg_files(
                    &crate::pkg::official_address(),
                    &official_roots(),
                ));
            }
            files
        }
        "boot-net.img"
        | "boot-net-its.img"
        | "boot-net-curl-steps.img"
        | "boot-posix-net-steps.img" => net_files(name),
        // The shell's image with the probe of F-Stack.
        "boot-fstack-probe.img" => {
            let mut files = dialog(name);
            files.push(file("/bin/fstack-probe", 0o755, ROOT, "fstack-probe"));
            files
        }
        // The probe of TLS: the root certificates with the probe's own CA,
        // and a large file for full TLS records.
        "boot-net-tls.img" | "boot-net-tls-steps.img" => {
            let mut files = net_files(name);
            for f in files
                .iter_mut()
                .filter(|f| f.path == crate::net_tls::CA_BUNDLE)
            {
                f.source = Some(Source::Bytes(
                    "bundle-with-ca.crt",
                    crate::probe_ca::bundle_with_ca(),
                ));
            }
            files.push(of(
                crate::net_tls::BIG,
                0o644,
                ROOT,
                Source::Bytes("www-256k", crate::net_tls::big_file()),
            ));
            files
        }
        "boot-nginx-probe.img" | "boot-nginx-probe-steps.img" => nginx_files(name),
        "boot-fast-nginx.img"
        | "boot-fast-nginx-crash.img"
        | "boot-fast-nginx-steps.img"
        | "boot-fast-nginx-vz.img"
        | "boot-fast-nginx-vz-steps.img" => {
            let mut files = fast_nginx_files(name);
            // The method that makes the service fault is `fast-echo`'s.
            if name == crate::fast_nginx::CRASH_IMAGE {
                files.push(file("/bin/fast-echo", 0o755, ROOT, "fast-echo"));
            }
            files
        }
        "boot-fast-scale.img" => crate::fast_scale::files(switch_files(name)),
        "boot-fast-switch.img" | "boot-fast-switch-steps.img" | "boot-fast-switch-vz.img" => {
            switch_files(name)
        }
        "boot-nginx-bench.img"
        | "boot-nginx-bench-nobuf.img"
        | "boot-nginx-bench-vz.img"
        | "boot-nginx-bench-vz-nobuf.img" => nginx_bench_files(name),
        "boot-net-bench.img"
        | "boot-net-bench-profile.img"
        | "boot-net-bench-pinned.img"
        | "boot-net-bench-cpu0.img"
        | "boot-net-bench-trace.img" => net_bench_files(name),
        // The row F1: the files of S4's image and the static address of the
        // second device, the one the stack owns.
        "boot-net-bench-fast.img" | "boot-net-bench-trace-fast.img" => {
            let mut files = net_bench_files(name);
            files.push(of(
                "/etc/netd.conf",
                0o644,
                ROOT,
                Source::Bytes("netd.conf", crate::fast_probe::NETD_CONF_VZ_STATIC),
            ));
            // The second device is claimed by the superuser (CLAIM).
            if let Some(f) = files
                .iter_mut()
                .find(|f| f.path == "/etc/nginx/nginx-fast.conf")
            {
                f.source = Some(Source::Bytes(
                    "nginx-fast-root.conf",
                    crate::fast_nginx::root_conf().as_bytes(),
                ));
            }
            files
        }
        // The row F1s: the files of S4's image, with the package's settings (the worker
        // runs as nobody) and the switch's `netd.conf`; the stack shares the first
        // device's address.
        "boot-net-bench-switch.img"
        | "boot-net-bench-switch-profile.img"
        | "boot-net-bench-switch-pinned.img"
        | "boot-net-bench-trace-switch.img" => {
            let mut files = net_bench_files(name);
            for (path, label, bytes) in [
                (
                    "/etc/nginx/nginx-fast.conf",
                    "nginx-fast.conf",
                    crate::fast_nginx::NGINX_FAST_CONF.as_bytes(),
                ),
                (
                    "/etc/netd.conf",
                    "netd-switch.conf",
                    crate::fast_nginx::switch_netd_conf(),
                ),
            ] {
                match files.iter_mut().find(|f| f.path == path) {
                    Some(f) => f.source = Some(Source::Bytes(label, bytes)),
                    None => files.push(of(path, 0o644, ROOT, Source::Bytes(label, bytes))),
                }
            }
            files
        }
        // The images on Apple VZ: the network service writes `resolv.conf`
        // from the lease. The image with a static address for the second
        // device has the file `netd.conf` too.
        "boot-net-vz2.img" | "boot-net-vz2-steps.img" => net_files(name),
        // One device on VZ with the segmentation offload asked for (`tso 1`): the device merges
        // the segments it receives, and the switch cuts them again.
        "boot-net-vz.img" | "boot-net-vz-steps.img" => {
            let mut files = net_files(name);
            files.push(of(
                "/etc/netd.conf",
                0o644,
                ROOT,
                Source::Bytes("netd.conf", NETD_CONF_TSO),
            ));
            files
        }
        "boot-net-vz2-static.img" => {
            let mut files = net_files(name);
            files.push(of(
                "/etc/netd.conf",
                0o644,
                ROOT,
                Source::Bytes("netd.conf", NETD_CONF_STATIC1),
            ));
            files
        }
        // The shell with both network devices, `handover 1`, and the
        // program that claims the second.
        "boot-fast-probe.img" | "boot-fast-probe-steps.img" | "boot-fast-probe-crash.img" => {
            let mut files = net_files(name);
            files.push(of(
                "/etc/netd.conf",
                0o644,
                ROOT,
                Source::Bytes("netd.conf", crate::fast_probe::NETD_CONF),
            ));
            files.push(file("/bin/fast-echo", 0o755, ROOT, "fast-echo"));
            files
        }
        // The shell with both network devices, `handover 1` and the fixed
        // address of the second, and the probe of the stack on it.
        "boot-fstack-device.img" | "boot-fstack-device-steps.img" => {
            let mut files = net_files(name);
            files.push(of(
                "/etc/netd.conf",
                0o644,
                ROOT,
                Source::Bytes("netd.conf", crate::fstack_device::NETD_CONF),
            ));
            files.push(file("/bin/fstack-probe", 0o755, ROOT, "fstack-probe"));
            files
        }
        // The same, with the program that carries the stack as plain sockets.
        "boot-fast-layer.img" => {
            let mut files = net_files(name);
            files.push(of(
                "/etc/netd.conf",
                0o644,
                ROOT,
                Source::Bytes("netd.conf", crate::fstack_device::NETD_CONF),
            ));
            files.push(file("/bin/fast-layer", 0o755, ROOT, "fast-layer"));
            files
        }
        "boot-fstack-device-dhcp.img" => {
            let mut files = net_files(name);
            files.push(of(
                "/etc/netd.conf",
                0o644,
                ROOT,
                Source::Bytes("netd.conf", crate::fstack_device::NETD_CONF_DHCP),
            ));
            files.push(file("/bin/fstack-probe", 0o755, ROOT, "fstack-probe"));
            files
        }
        // The same on Apple VZ.
        "boot-fast-vz.img" | "boot-fast-vz-steps.img" | "boot-fast-vz-static.img" => {
            let mut files = net_files(name);
            files.push(of(
                "/etc/netd.conf",
                0o644,
                ROOT,
                Source::Bytes(
                    "netd.conf",
                    if name == "boot-fast-vz-static.img" {
                        crate::fast_probe::NETD_CONF_VZ_STATIC
                    } else {
                        crate::fast_probe::NETD_CONF
                    },
                ),
            ));
            files.push(file("/bin/fast-echo", 0o755, ROOT, "fast-echo"));
            files
        }
        "boot-net-probe-static.img" | "boot-net-probe-its-static.img" => vec![of(
            "/etc/netd.conf",
            0o644,
            ROOT,
            Source::Bytes("netd.conf", NETD_CONF_STATIC),
        )],
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
        "boot-posix-so.img" => {
            let mut files = procs();
            files.extend(shared_files());
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
        | "boot-posix-map-big.img"
        | "boot-posix-lock-ring.img"
        | "boot-posix-shares.img" => procs(),
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
        "boot-posix-display.img" => {
            let mut files = vec![
                dir("/bin"),
                file("/bin/posix-display", 0o755, ROOT, "posix-display"),
                // Owned by another user: a spawn of it runs with a real ID
                // that differs from the effective one (AT_SECURE).
                of(
                    "/bin/posix-display-suid",
                    0o4755,
                    (1000, 100),
                    Source::Variant {
                        program: "posix-display",
                        tag: "setid",
                        // A file of its own: equal bytes would be one file.
                        extra: 4096,
                    },
                ),
                dir("/dev"),
            ];
            files.extend(devices());
            files
        }
        "boot-pkg-slot.img" => {
            let mut files = vec![
                dir("/bin"),
                file("/bin/pkg-slot", 0o755, ROOT, "pkg-slot"),
                // Owned by another user: a spawn of it runs with a real ID that differs from the
                // effective one (AT_SECURE).
                of(
                    "/bin/pkg-slot-suid",
                    0o4755,
                    (1000, 100),
                    Source::Variant {
                        program: "pkg-slot",
                        tag: "setid",
                        // A file of its own: equal bytes would be one file.
                        extra: 4096,
                    },
                ),
                dir("/dev"),
            ];
            files.extend(devices());
            files
        }
        "boot-display.img" => {
            let mut files = library();
            files.extend([
                dir("/bin"),
                file("/bin/display-run", 0o755, ROOT, "display-run"),
                file("/bin/display-probe", 0o755, ROOT, "display-probe"),
                dir("/dev"),
            ]);
            files.extend(devices());
            files
        }
        "boot-posix-random.img" | "boot-posix-random-net.img" | "boot-posix-random-net2.img" => {
            let mut files = vec![
                dir("/bin"),
                file("/bin/posix-random", 0o755, ROOT, "posix-random"),
                // Owned by another user: a spawn of it runs with a real ID that
                // differs from the effective one (AT_SECURE).
                of(
                    "/bin/posix-random-suid",
                    0o4755,
                    (1000, 100),
                    Source::Variant {
                        program: "posix-random",
                        tag: "setid",
                        // A file of its own: equal bytes would be one file.
                        extra: 4096,
                    },
                ),
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
pub fn fixed_build_time() -> Option<u64> {
    match BUILD_TIME.load(std::sync::atomic::Ordering::Relaxed) {
        0 => None,
        seconds => Some(seconds),
    }
}

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

    /// stafeto-design#631: no image has an empty or `*` password field. The
    /// field of /etc/passwd is `x`, that of /etc/shadow starts with `!`, and
    /// each name of the one file is in the other.
    #[test]
    fn no_image_has_an_empty_or_star_password_field() {
        for image in IMAGES {
            let files = files_of(image);
            let text = |path: &str| -> String {
                let file = files
                    .iter()
                    .find(|f| f.path == path)
                    .unwrap_or_else(|| panic!("{image}: no {path}"));
                let Some(Source::Bytes(_, bytes)) = file.source else {
                    panic!("{image}: {path} is not bytes");
                };
                String::from_utf8(bytes.to_vec()).unwrap()
            };
            let field = |line: &str| line.split(':').nth(1).unwrap_or("").to_owned();
            let passwd: Vec<(String, String)> = text("/etc/passwd")
                .lines()
                .map(|l| (l.split(':').next().unwrap().to_owned(), field(l)))
                .collect();
            let shadow: Vec<(String, String)> = text("/etc/shadow")
                .lines()
                .map(|l| (l.split(':').next().unwrap().to_owned(), field(l)))
                .collect();
            assert!(!passwd.is_empty(), "{image}");
            for (name, value) in &passwd {
                assert_eq!(value, "x", "{image}: /etc/passwd field of {name}");
            }
            for (name, value) in &shadow {
                assert!(
                    value.starts_with('!') && value != "*",
                    "{image}: /etc/shadow field of {name} is not locked"
                );
            }
            let names =
                |rows: &[(String, String)]| rows.iter().map(|r| r.0.clone()).collect::<Vec<_>>();
            assert_eq!(names(&passwd), names(&shadow), "{image}");
            let shadow_file = files.iter().find(|f| f.path == "/etc/shadow").unwrap();
            assert_eq!(
                shadow_file.mode & 0o077,
                0,
                "{image}: /etc/shadow is open to others"
            );
            assert_eq!(
                (shadow_file.uid, shadow_file.gid),
                ROOT,
                "{image}: /etc/shadow owner"
            );
        }
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
            "boot-posix-map-big.img",
            "boot-posix-so.img",
        ] {
            let files = files_of(image);
            assert!(
                files.iter().any(|file| file.path == "/bin/procs-child"),
                "{image}"
            );
        }
    }

    /// The table of an image and the files of its layers make the tree the
    /// list of the image names: no path of a package is in the table, the
    /// bytes a probe puts at a path of a package are the variant's, the
    /// table alone is a table the file service reads, and the paths the
    /// table gains are the directories above its files.
    #[test]
    fn the_table_and_the_layers_of_an_image_make_the_tree_it_had() {
        let mut layered_images = 0;
        for image in IMAGES {
            let full = files_of(image);
            let split = layered(image).unwrap_or_else(|e| panic!("{image}: {e}"));
            // A directory both name is the table's directory above a file,
            // which merges with the package's.
            for f in &split.system {
                assert!(
                    f.source.is_none() || !split.packages.iter().any(|l| owns(&l.package, f.path)),
                    "{image}: {} is a path of the table and of a package",
                    f.path
                );
            }
            let all: Vec<_> = split.packages.iter().map(|l| l.package.clone()).collect();
            let declared = package_files(&all).unwrap();
            let mut merged: Vec<(&str, u32, u32, u32, Option<Source>)> = Vec::new();
            for f in &split.system {
                merged.push((f.path, f.mode, f.uid, f.gid, f.source));
            }
            for f in &declared {
                let mut source = f.source;
                for l in &split.packages {
                    if let Some((_, bytes)) = l.replaced.iter().find(|(p, _)| *p == f.path) {
                        let was = full.iter().find(|g| g.path == f.path).unwrap();
                        assert!(
                            matches!(was.source, Some(Source::Bytes(_, b)) if b == *bytes),
                            "{image}: {} is not the variant's bytes",
                            f.path
                        );
                        source = was.source;
                    }
                }
                merged.push((f.path, f.mode, f.uid, f.gid, source));
            }
            merged.sort_by(|a, b| a.0.cmp(b.0));
            // A path two sources name is a directory both name, alike.
            for pair in merged.windows(2) {
                if pair[0].0 == pair[1].0 {
                    assert!(
                        pair[0].4.is_none() && pair[0] == pair[1],
                        "{image}: {} is in two sources",
                        pair[0].0
                    );
                }
            }
            merged.dedup_by(|a, b| a.0 == b.0);
            let mut want: Vec<_> = full
                .iter()
                .map(|f| (f.path, f.mode, f.uid, f.gid, f.source))
                .collect();
            want.sort_by(|a, b| a.0.cmp(b.0));
            assert_eq!(merged, want, "{image}");
            // The table alone is a table.
            let total = sources(&split.system).len() as u32;
            let bytes = table(&split.system, 0, total).unwrap_or_else(|e| panic!("{image}: {e}"));
            Rootfs::parse(&bytes, total).unwrap_or_else(|e| panic!("{image}: {e}"));
            // An image with no package has no layer and a table of its list.
            if split.packages.is_empty() {
                assert_eq!(split.system.len(), full.len(), "{image}");
            } else {
                layered_images += 1;
            }
        }
        assert!(layered_images >= 20, "{layered_images} images with layers");
    }

    /// The variants: the certificate file of the probe's authority in the
    /// image of the probe of TLS, the settings of the probes of nginx.
    #[test]
    fn the_probes_put_their_bytes_in_variants_of_packages() {
        let replaced = |image: &str| -> Vec<(String, String)> {
            layered(image)
                .unwrap()
                .packages
                .iter()
                .flat_map(|l| {
                    l.replaced
                        .iter()
                        .map(|(p, _)| (l.package.name.clone(), (*p).to_string()))
                        .collect::<Vec<_>>()
                })
                .collect()
        };
        assert_eq!(
            replaced("boot-net-tls.img"),
            [(
                "ca-bundle".into(),
                "/etc/ssl/certs/ca-certificates.crt".into()
            )]
        );
        assert_eq!(
            replaced("boot-nginx-probe.img"),
            [("nginx".into(), "/etc/nginx/nginx.conf".into())]
        );
        assert_eq!(
            replaced("boot-fast-nginx.img"),
            [("nginx-fast".into(), "/etc/nginx/nginx-fast.conf".into())]
        );
        assert!(replaced("boot-net.img").is_empty());
        assert!(replaced("boot-doom.img").is_empty());
        // The images that ship hold the certificate file of the package, byte for byte: the
        // probe CA is in the probe's image alone (pk4-design R4).
        assert!(replaced("boot-base.img").is_empty());
        assert!(replaced("boot-full.img").is_empty());
        assert_eq!(
            replaced("boot-pkg-probe.img"),
            [(
                "ca-bundle".into(),
                "/etc/ssl/certs/ca-certificates.crt".into()
            )]
        );
    }

    /// The package tool and what it trusts are paths of the system in the base and the full
    /// image: the tool, `/etc/pkg` and its two files, which a package cannot hold. The images
    /// that ship name the official address of the series and the official roots; the probe's
    /// image names its mirror and the development root.
    #[test]
    fn the_images_hold_the_package_tool_and_what_it_trusts() {
        let bytes = |image: &str, path: &str| -> Option<Vec<u8>> {
            match files_of(image).iter().find(|f| f.path == path)?.source? {
                Source::Bytes(_, b) => Some(b.to_vec()),
                _ => None,
            }
        };
        for image in ["boot-base.img", "boot-full.img", "boot-pkg-probe.img"] {
            let files = files_of(image);
            let tool = files.iter().find(|f| f.path == "/bin/pkg").unwrap();
            assert_eq!((tool.mode, tool.uid, tool.gid), (0o755, 0, 0), "{image}");
            assert_eq!(tool.source, Some(Source::Elf("pkg")));
            for path in ["/etc/pkg", "/etc/pkg/keys"] {
                let d = files.iter().find(|f| f.path == path).unwrap();
                assert_eq!((d.mode, d.source), (0o755, None), "{image} {path}");
            }
            for path in ["/etc/pkg/official", "/etc/pkg/keys/stafeto.pub"] {
                let f = files.iter().find(|f| f.path == path).unwrap();
                assert_eq!((f.mode, f.uid, f.gid), (0o444, 0, 0), "{image} {path}");
                assert!(is_system(path));
            }
            assert!(is_system("/bin/pkg"));
        }
        for image in ["boot-base.img", "boot-full.img"] {
            assert_eq!(
                bytes(image, "/etc/pkg/official").unwrap(),
                format!(
                    "stafeto https://stafeto.github.io/packages/{}/aarch64\n",
                    crate::pkg::series()
                )
                .into_bytes(),
                "{image}"
            );
            assert_eq!(
                bytes(image, "/etc/pkg/keys/stafeto.pub").unwrap(),
                pkgfmt::OFFICIAL_ROOTS.concat().into_bytes(),
                "{image}"
            );
        }
        assert_eq!(
            bytes("boot-pkg-probe.img", "/etc/pkg/official").unwrap(),
            format!(
                "stafeto https://10.0.2.2:8443/{}/aarch64\n",
                crate::pkg::series()
            )
            .into_bytes()
        );
        // The shell image without packages tools holds none of it.
        assert!(
            files_of("boot-ash-dialog.img")
                .iter()
                .all(|f| f.path != "/bin/pkg")
        );
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
        let with_files: Vec<usize> = (0..twice.len())
            .filter(|&n| !twice[n].files.is_empty())
            .collect();
        let path = twice[with_files[0]].files[0].clone();
        twice[with_files[1]].files.push(path.clone());
        let error = check_owners(image, &files, &twice).unwrap_err();
        assert!(error.contains(&path.0), "{error}");
        // A file a package names and the image lacks.
        let mut lacking = packages.clone();
        lacking[with_files[0]]
            .files
            .push(("/bin/ghost".into(), "elf:busybox-probe".into()));
        let error = check_owners(image, &files, &lacking).unwrap_err();
        assert!(error.contains("/bin/ghost"), "{error}");
        // A package that installs nothing leaves nothing to own: its row
        // has no files, and some other package links it in (the fts of
        // pax).
        for p in packages.iter().filter(|p| p.files.is_empty()) {
            assert!(
                packages.iter().any(|q| q.build_depends.contains(&p.name)),
                "{} installs nothing and no package links it in",
                p.name
            );
        }
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
                "boot-doom.img" => crate::doom::programs(),
                "boot-doom-steps.img" => crate::doom::steps_programs(),
                "boot-base.img" | "boot-full.img" | "boot-pkg-probe.img" => {
                    crate::base_image::programs(image)
                }
                "boot-net.img" => crate::net::programs(),
                "boot-net-vz.img" => crate::net::vz_programs(false),
                "boot-net-vz-steps.img" => crate::net::vz_steps_programs(false),
                "boot-net-vz2-steps.img" => crate::net::vz_steps_programs(true),
                "boot-net-vz2.img" | "boot-net-vz2-static.img" => crate::net::vz_programs(true),
                "boot-fast-vz.img" | "boot-fast-vz-static.img" => crate::net::vz_programs(true),
                "boot-fast-vz-steps.img" => crate::net::vz_steps_programs(true),
                "boot-net-curl-steps.img" | "boot-net-tls-steps.img" => {
                    crate::net_curl::steps_programs()
                }
                "boot-net-tls.img" => crate::net::programs(),
                "boot-fast-nginx.img" => {
                    crate::fast_nginx::programs(crate::fast_nginx::Kind::Plain)
                }
                "boot-fast-nginx-crash.img" => {
                    crate::fast_nginx::programs(crate::fast_nginx::Kind::Crash)
                }
                "boot-fast-nginx-steps.img" => {
                    crate::fast_nginx::programs(crate::fast_nginx::Kind::Steps)
                }
                "boot-fast-nginx-vz.img" => {
                    crate::fast_nginx::programs(crate::fast_nginx::Kind::Vz)
                }
                "boot-fast-nginx-vz-steps.img" => {
                    crate::fast_nginx::programs(crate::fast_nginx::Kind::VzSteps)
                }
                "boot-fast-scale.img" => {
                    crate::fast_nginx::programs(crate::fast_nginx::Kind::Scale)
                }
                "boot-fast-switch.img" => {
                    crate::fast_nginx::programs(crate::fast_nginx::Kind::Switch)
                }
                "boot-fast-switch-steps.img" => {
                    crate::fast_nginx::programs(crate::fast_nginx::Kind::SwitchSteps)
                }
                "boot-net-bench-switch.img" | "boot-net-bench-trace-switch.img" => {
                    crate::linux_guest::bench_switch_programs()
                }
                "boot-net-bench-trace.img" => crate::linux_guest::bench_programs(),
                "boot-net-bench-trace-fast.img" => crate::linux_guest::bench_fast_programs(),
                "boot-net-bench-switch-profile.img" => {
                    crate::linux_guest::bench_switch_profile_programs()
                }
                "boot-net-bench-switch-pinned.img" => {
                    crate::linux_guest::bench_switch_pinned_programs()
                }
                "boot-fast-switch-vz.img" => {
                    crate::fast_nginx::programs(crate::fast_nginx::Kind::SwitchVz)
                }
                "boot-nginx-probe.img" => crate::nginx_probe::programs(),
                "boot-nginx-probe-steps.img" => crate::nginx_probe::steps_programs(),
                "boot-nginx-bench.img" | "boot-nginx-bench-nobuf.img" => {
                    crate::nginx_bench::programs(false)
                }
                "boot-nginx-bench-vz.img" | "boot-nginx-bench-vz-nobuf.img" => {
                    crate::nginx_bench::programs(true)
                }
                "boot-posix-net-steps.img" => crate::posix_net::steps_programs(),
                "boot-net-probe.img" | "boot-net-probe-static.img" => &crate::net_probe::PROGRAMS,
                "boot-net-probe-its.img" | "boot-net-probe-its-static.img" => {
                    &crate::net_probe::ITS_PROGRAMS
                }
                "boot-net-its.img" => crate::net::its_programs(),
                "boot-net-steps.img" => &crate::net_probe::STEPS_PROGRAMS,
                "boot-net-probe-two.img" => &crate::net_probe::TWO_PROGRAMS,
                "boot-net-steps-two.img" => &crate::net_probe::TWO_STEPS_PROGRAMS,
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
                "boot-posix-map-big.img" => &crate::POSIX_MAP_BIG_PROGRAMS,
                "boot-posix-so.img" => &crate::POSIX_SO_PROGRAMS,
                "boot-posix-lock-ring.img" => &crate::POSIX_LOCK_RING_PROGRAMS,
                "boot-posix-shares.img" => &crate::POSIX_SHARES_PROGRAMS,
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
                assert!(
                    have.contains(&program) || shared_path(program).is_some(),
                    "{image}: {program}"
                );
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
        assert_eq!(wanted.len(), 16);
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
            "boot-doom.img",
            "boot-doom-steps.img",
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
            "boot-posix-map-big.img",
            "boot-posix-so.img",
            "boot-posix-lock-ring.img",
            "boot-posix-shares.img",
            "boot-posix-random.img",
            "boot-posix-display.img",
            "boot-pkg-slot.img",
            "boot-display.img",
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

    /// Fails if the notice of the ENA driver is left out of the files an image with
    /// `netd` holds: the BSD-3-Clause text must go with the binary.
    #[test]
    fn the_notice_of_the_ena_driver_is_a_file_of_the_system_with_its_text() {
        let files = ena_notice();
        let f = files.iter().find(|f| f.path == ENA_NOTICE).unwrap();
        let Some(Source::Bytes(_, bytes)) = &f.source else {
            panic!("the notice is bytes");
        };
        let text = std::str::from_utf8(bytes).unwrap();
        assert!(text.contains("BSD 3-Clause") && text.contains("Redistributions in binary form"));
        assert!(is_system(ENA_NOTICE));
        // The directories come before the file.
        let at = |p: &str| files.iter().position(|f| f.path == p).unwrap();
        assert!(at("/usr/share/licenses/stafeto") < at(ENA_NOTICE));
    }
}
