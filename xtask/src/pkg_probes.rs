// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probes of the packages (docs/packages.md):
//!
//! * `dist-licenses`: the release archive of the shell image carries the
//!   notices of the packages it holds and no others, and no archive carries
//!   the notices of F-Stack unless F-Stack is in it;
//! * `pkg-identity`: the flat images and the packages give the same bytes at
//!   the same paths, the repository is whole and a package builds again to
//!   the same bytes;
//! * `pkg-ci`: `pkg-build`, `repo`, `pkg-identity` and `dist-licenses` in a
//!   row, which is what the job `pkg` of CI runs.
//!
//! `stage_licenses` is also what `cargo xtask dist` uses to give
//! `tools/dist.py` the notices of the packages of the shell image.

use crate::notices;
use crate::packages::{self, Package};
use crate::pkg::{self, Built};
use crate::repo;
use bootimg::BootImage;
use bootimg::rootfs::Rootfs;
use pkgfmt::Package as PackageFile;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

/// What only F-Stack's notices say.
const FSTACK_MARKERS: [&str; 4] = [
    "THL A29 Limited",
    "Files of the build under the four-clause BSD licence ask for these",
    "Henrik Vestergaard Draboel",
    "Jukka Antero Ukkonen",
];
/// The packages whose notices may hold the marks above.
const FSTACK_PACKAGES: [&str; 2] = ["f-stack", "nginx-fast"];
const SHELL_IMAGE: &str = "boot-ash-dialog.img";
const LICENSES: &str = "/usr/share/licenses";

fn has_files(p: &Package) -> bool {
    !(p.files.is_empty() && p.dirs.is_empty())
}

/// The packages of the shell image that have files.
fn shell_packages() -> Result<Vec<Package>, String> {
    Ok(packages::of_image(SHELL_IMAGE)?
        .into_iter()
        .filter(has_files)
        .collect())
}

fn options(names: Vec<String>, out: Option<PathBuf>) -> pkg::Options {
    pkg::Options {
        names,
        key: None,
        cert: None,
        time: None,
        out,
        recipe: false,
        replace: Vec::new(),
    }
}

/// The notices of one package as files: path below
/// `/usr/share/licenses/<name>/` and bytes.
fn notice_files(file: &PackageFile<'_>, name: &str) -> Vec<(String, Vec<u8>)> {
    let base = format!("{LICENSES}/{name}/");
    (0..file.rootfs.len() as u32)
        .filter_map(|n| {
            let e = file.rootfs.entry(n);
            let rest = e.path.strip_prefix(&base)?;
            (!e.is_directory()).then(|| (rest.to_string(), file.content(n).to_vec()))
        })
        .collect()
}

/// Builds the packages of the shell image and lays their notices out in
/// `target/dist-licenses/<name>/`, with `packages.txt` (name, version-release,
/// licence) and `sources.txt` (the packages and those linked into them).
pub fn stage_licenses() -> Result<PathBuf, String> {
    let dir = crate::target_dir().join("dist-licenses");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let wanted = shell_packages()?;
    let built = pkg::build(&options(
        wanted.iter().map(|p| p.name.clone()).collect(),
        None,
    ))?;
    let mut rows = String::new();
    let mut sources: BTreeSet<String> = BTreeSet::new();
    for b in &built {
        let bytes = std::fs::read(&b.path).map_err(|e| format!("{}: {e}", b.path.display()))?;
        let file = PackageFile::parse(&bytes).map_err(|e| format!("{}: {e}", b.path.display()))?;
        for (rest, data) in notice_files(&file, &b.package.name) {
            let path = dir.join(&b.package.name).join(&rest);
            std::fs::create_dir_all(path.parent().expect("has a parent"))
                .map_err(|e| format!("{}: {e}", path.display()))?;
            std::fs::write(&path, data).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        rows += &format!(
            "{}\t{}-{}\t{}\n",
            b.package.name, b.package.version, b.package.release, b.package.license
        );
        sources.insert(b.package.name.clone());
        sources.extend(b.package.build_depends.iter().cloned());
    }
    std::fs::write(dir.join("packages.txt"), rows).map_err(|e| e.to_string())?;
    std::fs::write(
        dir.join("sources.txt"),
        sources.into_iter().collect::<Vec<_>>().join("\n") + "\n",
    )
    .map_err(|e| e.to_string())?;
    Ok(dir)
}

// ---- dist-licenses ----

fn say(check: &str) {
    println!("dist-licenses: {check} ok");
}

fn tar_members(archive: &Path) -> Result<Vec<String>, String> {
    let out = Command::new("tar")
        .arg("-tf")
        .arg(archive)
        .output()
        .map_err(|e| format!("tar: {e}"))?;
    if !out.status.success() {
        return Err(format!("{}: tar failed", archive.display()));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect())
}

fn scan(archive: &Path) -> Result<(), String> {
    let mut cmd = Command::new("python3");
    cmd.arg("-I")
        .arg(crate::root().join("tools/pkg-source.py"))
        .arg("scan")
        .arg(archive);
    for m in FSTACK_MARKERS {
        cmd.args(["--marker", m]);
    }
    for n in ["FSTACK-LICENSE", "f-stack"] {
        cmd.args(["--forbid-name", n]);
    }
    let out = cmd.output().map_err(|e| format!("pkg-source.py: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
}

/// Which packages of a repository hold a mark of F-Stack's notices in any of
/// their files.
fn marked_packages(dir: &Path) -> Result<BTreeSet<String>, String> {
    let mut found = BTreeSet::new();
    for entry in std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .flatten()
    {
        if entry.path().extension().is_none_or(|e| e != "stpkg") {
            continue;
        }
        let bytes = std::fs::read(entry.path()).map_err(|e| e.to_string())?;
        let file =
            PackageFile::parse(&bytes).map_err(|e| format!("{}: {e}", entry.path().display()))?;
        for n in 0..file.rootfs.len() as u32 {
            let content = file.content(n);
            if FSTACK_MARKERS
                .iter()
                .any(|m| content.windows(m.len()).any(|w| w == m.as_bytes()))
            {
                found.insert(file.meta.name.to_string());
            }
        }
    }
    Ok(found)
}

pub fn dist_licenses() -> Result<(), String> {
    let started = std::time::Instant::now();
    crate::dist()?;
    let dir = repo::run(&repo::Options {
        sources: true,
        ..repo::parse_options(&[])?
    })?;
    let version = env!("CARGO_PKG_VERSION");
    let dist = crate::target_dir().join("dist");
    // 1: every mark is in the package of F-Stack, so a mark that has gone
    // from the notices cannot make the probe pass without saying so.
    let marked = marked_packages(&dir)?;
    let fstack = std::fs::read(
        dir.join(pkg::file_name(
            &packages::load()?
                .into_iter()
                .find(|p| p.name == "f-stack")
                .ok_or("no package f-stack")?,
        )),
    )
    .map_err(|e| format!("f-stack package: {e}"))?;
    let file = PackageFile::parse(&fstack).map_err(|e| e.to_string())?;
    let all_text: Vec<u8> = notice_files(&file, "f-stack")
        .into_iter()
        .flat_map(|(_, d)| d)
        .collect();
    for m in FSTACK_MARKERS {
        if !all_text.windows(m.len()).any(|w| w == m.as_bytes()) {
            return Err(format!(
                "dist-licenses: the mark {m:?} is not in the notices of the package f-stack: it no longer marks anything"
            ));
        }
    }
    say("the marks of F-Stack are in its package");
    // 2: the kernel archive and the archive of aarch64-virt.
    for name in [
        format!("stafeto-{version}-kernel.tar.xz"),
        format!("stafeto-{version}-aarch64-virt.tar.xz"),
    ] {
        scan(&dist.join(&name)).map_err(|e| format!("dist-licenses: {e}"))?;
    }
    say("the kernel and aarch64-virt archives carry no notice of F-Stack");
    // 3: LICENSES/packages/ of aarch64-virt are the packages of the shell image.
    let archive = dist.join(format!("stafeto-{version}-aarch64-virt.tar.xz"));
    let mut seen: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for m in tar_members(&archive)? {
        if let Some((_, rest)) = m.split_once("/LICENSES/packages/")
            && let Some((name, file)) = rest.split_once('/')
        {
            seen.entry(name.to_string())
                .or_default()
                .insert(file.to_string());
        }
    }
    let want: BTreeSet<String> = shell_packages()?.into_iter().map(|p| p.name).collect();
    let have: BTreeSet<String> = seen.keys().cloned().collect();
    if want != have {
        return Err(format!(
            "dist-licenses: {} holds LICENSES/packages/ of {have:?}, the packages of {SHELL_IMAGE} are {want:?}",
            archive.display()
        ));
    }
    for (name, files) in &seen {
        for needed in ["LICENSE", "SOURCE"] {
            if !files.contains(needed) {
                return Err(format!(
                    "dist-licenses: {} has no LICENSES/packages/{name}/{needed}",
                    archive.display()
                ));
            }
        }
    }
    say("LICENSES/packages/ of aarch64-virt are the packages of the shell image");
    // 4: the marks stay in F-Stack's packages, and every package passes the policy.
    let stray: Vec<_> = marked
        .iter()
        .filter(|n| !FSTACK_PACKAGES.contains(&n.as_str()))
        .collect();
    if !stray.is_empty() {
        return Err(format!(
            "dist-licenses: the notices of F-Stack are in {stray:?}, which do not link it"
        ));
    }
    let n = repo::check(&dir, &[crate::keys::dev_keys(&crate::root())?.root])?;
    say(&format!(
        "the notices of F-Stack are in {marked:?} alone, {n} packages pass the policy"
    ));
    // The package that links F-Stack carries them with it.
    if !marked.contains("nginx-fast") {
        return Err(
            "dist-licenses: nginx-fast links F-Stack and carries none of its notices".into(),
        );
    }
    // 5: the sources of the GPL packages.
    crate::run_cmd(
        Command::new("python3")
            .arg(crate::root().join("tools/pkg-source.py"))
            .arg("check")
            .arg("--repo")
            .arg(&dir),
    )?;
    say("the GPL packages come with the sources their descriptions pin");
    let cache = crate::target_dir().join("dist-cache");
    let size = dir_size(&cache);
    println!(
        "dist-licenses: {:.0} s, target/dist-cache holds {} bytes",
        started.elapsed().as_secs_f64(),
        size
    );
    Ok(())
}

fn dir_size(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .map(|r| {
            r.flatten()
                .map(|e| {
                    let p = e.path();
                    if p.is_dir() {
                        dir_size(&p)
                    } else {
                        e.metadata().map_or(0, |m| m.len())
                    }
                })
                .sum()
        })
        .unwrap_or(0)
}

// ---- pkg-identity ----

/// How long the machine of the full image has to boot and answer the
/// commands of the probe, on TCG.
const BOOT_WITHIN: std::time::Duration = std::time::Duration::from_secs(120);

/// The package files an image holds in its container: name and bytes.
fn layers_of(image: &BootImage<'_>) -> Vec<(String, Vec<u8>)> {
    image
        .files()
        .filter(|f| f.name.ends_with(".stpkg"))
        .map(|f| (f.name.to_string(), f.data.to_vec()))
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut buf = [0u8; 64];
    pkgfmt::sha::hex(&pkgfmt::sha::sha256(bytes), &mut buf).to_string()
}

/// The package files of the image at `path` are, byte for byte, the files
/// the index of the repository in `dir` names, one for each package that
/// has files; gives their names.
fn same_as_index(name: &str, path: &Path, dir: &Path) -> Result<BTreeSet<String>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let image = BootImage::parse(&bytes).map_err(|e| format!("{name}: {e}"))?;
    let text = std::fs::read_to_string(dir.join("INDEX")).map_err(|e| format!("INDEX: {e}"))?;
    let index = pkgfmt::index::Index::parse(&text).map_err(|e| format!("INDEX: {e}"))?;
    let mut held = BTreeSet::new();
    for (file, data) in layers_of(&image) {
        let entry = index
            .entries()
            .find(|e| e.file == file)
            .ok_or_else(|| format!("{name}: {file} is in no record of the index"))?;
        if entry.sha256 != sha256_hex(&data) {
            return Err(format!(
                "{name}: the SHA-256 of {file} is not the index's: the image holds another build of the package"
            ));
        }
        held.insert(entry.name.to_string());
    }
    Ok(held)
}

/// No file of a package is in the table `rootfs` of the image at `path`; a
/// directory of a package is there only above other entries of the table.
fn table_holds_no_package_path(
    name: &str,
    path: &Path,
    packages: &[Package],
) -> Result<usize, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let image = BootImage::parse(&bytes).map_err(|e| format!("{name}: {e}"))?;
    let table = image
        .files()
        .find(|f| f.name == "rootfs")
        .ok_or_else(|| format!("{name}: no rootfs"))?;
    let table = Rootfs::parse(table.data, image.count()).map_err(|e| format!("{name}: {e}"))?;
    let owned = |path: &str| {
        packages
            .iter()
            .any(|p| p.files.iter().any(|(f, _)| f == path) || p.dirs.iter().any(|d| d == path))
    };
    let mut entries = 0;
    for n in 0..table.len() as u32 {
        let e = table.entry(n);
        entries += 1;
        if !owned(e.path) {
            continue;
        }
        let above = (0..table.len() as u32)
            .any(|m| table.entry(m).path.starts_with(&format!("{}/", e.path)));
        if !e.is_directory() || !above {
            return Err(format!(
                "{name}: the table rootfs holds {}, a path of a package",
                e.path
            ));
        }
    }
    Ok(entries)
}

/// The lines a command of the shell wrote, with the echo of the command and
/// the prompt left out.
fn shell(run: &mut crate::qemu::Run, command: &str) -> Result<Vec<String>, String> {
    let from = run.lines().len();
    run.send(command)?;
    run.expect(command, crate::DIALOG_STEP)?;
    run.expect("# ", crate::DIALOG_STEP)?;
    Ok(run.lines()[from..]
        .iter()
        .filter(|l| !l.contains(command))
        .cloned()
        .collect())
}

/// Boots the image at `path` on the machine of the base and the full image
/// (TCG), runs `check` at the prompt of the shell, and fails when the log
/// of ramfs says a layer was not attached.
fn boot(
    name: &str,
    path: &Path,
    check: impl FnOnce(&mut crate::qemu::Run) -> Result<(), String>,
) -> Result<(f64, f64), String> {
    let kernel = crate::build(crate::Variant::Normal)?;
    let mut cmd = crate::qemu::command(&crate::qemu::VIRT, &kernel.image, Some(path));
    cmd.args(crate::qemu::HEADLESS);
    cmd.args(crate::base_image::machine_args());
    let started = std::time::Instant::now();
    let mut run = crate::qemu::Run::start(cmd, crate::qemu::Input::Pipe)?;
    let mut services = 0.0;
    let talked = (|| {
        run.expect(crate::SERVICES_STARTED, BOOT_WITHIN)?;
        services = started.elapsed().as_secs_f64();
        run.expect("# ", crate::DIALOG_STEP)?;
        check(&mut run)
    })();
    let output = run.stop();
    crate::symbolize::backtrace(&output.lines, &kernel.elf);
    talked.map_err(|e| format!("{name}: {e}"))?;
    if let Some(line) = output.lines.iter().find(|l| l.contains("not attached")) {
        return Err(format!("{name}: {line}"));
    }
    let took = started.elapsed();
    if took > BOOT_WITHIN {
        return Err(format!("{name}: the run took {:.0} s", took.as_secs_f64()));
    }
    Ok((services, took.as_secs_f64()))
}

/// The entries of `/usr/share/licenses`, as `ls -1` lists them.
fn licence_directories(run: &mut crate::qemu::Run) -> Result<BTreeSet<String>, String> {
    Ok(shell(run, "ls -1 /usr/share/licenses")?
        .into_iter()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

/// The blocks of two builds equal in all but the time and the signature.
fn same_but_signature(a: &Built, b: &Built) -> Result<(), String> {
    let (bytes_a, bytes_b) = (
        std::fs::read(&a.path).map_err(|e| e.to_string())?,
        std::fs::read(&b.path).map_err(|e| e.to_string())?,
    );
    let (fa, fb) = (
        PackageFile::parse(&bytes_a).map_err(|e| e.to_string())?,
        PackageFile::parse(&bytes_b).map_err(|e| e.to_string())?,
    );
    let name = &a.package.name;
    if fa.covered() != fb.covered() {
        return Err(format!(
            "pkg-identity: the covered bytes of {name} differ between two builds"
        ));
    }
    let (ta, tb) = (fa.trailer, fb.trailer);
    if (ta.kind, ta.covered, ta.digest, ta.key, ta.certificate)
        != (tb.kind, tb.covered, tb.digest, tb.key, tb.certificate)
    {
        return Err(format!(
            "pkg-identity: the trailers of {name} differ in more than the time and the signature"
        ));
    }
    if ta.time == tb.time || ta.signature == tb.signature {
        return Err(format!(
            "pkg-identity: the two builds of {name} were signed at one time"
        ));
    }
    Ok(())
}

pub fn identity() -> Result<(), String> {
    let started = std::time::Instant::now();
    // 1: the repository and the images: the images take the package files
    // the repository was made of.
    let dir = crate::target_dir().join("repo-identity");
    repo::run(&repo::Options {
        sources: false,
        dir: Some(dir.clone()),
        ..repo::parse_options(&[])?
    })?;
    let full = crate::base_image::build_image(crate::base_image::FULL_IMAGE)?;
    let base = crate::base_image::build_image(crate::base_image::BASE_IMAGE)?;
    let all = packages::load()?;
    let with_files: Vec<Package> = all.iter().filter(|p| has_files(p)).cloned().collect();
    let base_packages: Vec<Package> = with_files
        .iter()
        .filter(|p| p.kind == packages::Kind::Base)
        .cloned()
        .collect();
    // 2: each package file in an image is the file of the index.
    let want =
        |list: &[Package]| -> BTreeSet<String> { list.iter().map(|p| p.name.clone()).collect() };
    for (name, path, list) in [
        (crate::base_image::FULL_IMAGE, &full, &with_files),
        (crate::base_image::BASE_IMAGE, &base, &base_packages),
    ] {
        let held = same_as_index(name, path, &dir)?;
        if held != want(list) {
            return Err(format!(
                "pkg-identity: {name} holds the packages {held:?}, wanted {:?}",
                want(list)
            ));
        }
        println!(
            "pkg-identity: {} package files of {name} are the files of the index, byte for byte",
            held.len()
        );
    }
    // 3: the table of an image holds the paths of the system alone.
    for (name, path) in [
        (crate::base_image::FULL_IMAGE, &full),
        (crate::base_image::BASE_IMAGE, &base),
    ] {
        let n = table_holds_no_package_path(name, path, &with_files)?;
        println!(
            "pkg-identity: the {n} entries of the table rootfs of {name} are paths of the system"
        );
    }
    // 4: the index and the packages.
    let n = repo::check(&dir, &[crate::keys::dev_keys(&crate::root())?.root])?;
    println!("pkg-identity: repo --check: {n} packages whole and signed");
    // 5: the full image in QEMU: the program of a package with its mode, the
    // licence of another in its directory, the directories of the notices.
    let licence = notices::licence_text("freedoom")?;
    let (services, took) = boot(crate::base_image::FULL_IMAGE, &full, |run| {
        let listing = shell(run, "ls -l /bin/doom")?;
        let doom = with_files
            .iter()
            .find(|p| p.name == "doomgeneric")
            .ok_or("no package doomgeneric")?;
        let (_, source) = doom
            .files
            .iter()
            .find(|(path, _)| path == "/bin/doom")
            .ok_or("doomgeneric names no /bin/doom")?;
        let wanted = if source.starts_with("link:") {
            'l'
        } else {
            '-'
        };
        if !listing
            .iter()
            .any(|l| l.starts_with(wanted) && l.contains("rwxr-xr-x") && l.ends_with("/bin/doom"))
        {
            return Err(format!("ls -l /bin/doom gave {listing:?}"));
        }
        let text = shell(run, "cat /usr/share/licenses/freedoom/LICENSE")?;
        let wanted: Vec<&str> = std::str::from_utf8(&licence)
            .map_err(|e| e.to_string())?
            .lines()
            .collect();
        // The terminal turns each LF into CR LF; the file has CR LF itself.
        let got: Vec<&str> = text.iter().map(|l| l.trim_end_matches('\r')).collect();
        if let Some(at) = (0..got.len().max(wanted.len())).find(|&i| got.get(i) != wanted.get(i)) {
            return Err(format!(
                "cat /usr/share/licenses/freedoom/LICENSE gave {} lines, the licence text has {}: line {} is {:?}, wanted {:?}",
                got.len(),
                wanted.len(),
                at + 1,
                got.get(at),
                wanted.get(at)
            ));
        }
        let mut names = want(&with_files);
        names.insert("stafeto".into());
        let held = licence_directories(run)?;
        if held != names {
            return Err(format!(
                "/usr/share/licenses holds {held:?}, the packages of the image and stafeto are {names:?}"
            ));
        }
        Ok(())
    })?;
    println!(
        "pkg-identity: {} in QEMU: ls -l /bin/doom, the licence of freedoom, the directories of the notices, no layer left out (services started after {services:.1} s, the checks done after {took:.1} s)",
        crate::base_image::FULL_IMAGE
    );
    // 6: the base image in QEMU: no game, the notices of the base packages, the screen and the keys.
    let (services, took) = boot(crate::base_image::BASE_IMAGE, &base, |run| {
        // The services of the screen and of the keys came up.
        for line in ["virtio-gpu: screen ready", "input: QEMU Virtio Keyboard"] {
            run.expect_bytes(line.as_bytes(), crate::DIALOG_STEP)?;
        }
        let missing = shell(run, "ls /bin/doom")?;
        if !missing
            .iter()
            .any(|l| l.contains("No such file or directory"))
        {
            return Err(format!("ls /bin/doom gave {missing:?}"));
        }
        let mut names = want(&base_packages);
        names.insert("stafeto".into());
        let held = licence_directories(run)?;
        if held != names {
            return Err(format!(
                "/usr/share/licenses holds {held:?}, the base packages and stafeto are {names:?}"
            ));
        }
        Ok(())
    })?;
    println!(
        "pkg-identity: {} in QEMU: no /bin/doom, the notices of the base packages and of the system, no layer left out (services started after {services:.1} s, the checks done after {took:.1} s)",
        crate::base_image::BASE_IMAGE
    );
    // 7: a package builds again to the same bytes.
    let (first, second) = (
        crate::target_dir().join("pkg-again-1"),
        crate::target_dir().join("pkg-again-2"),
    );
    let names = vec!["freedoom".to_string(), "busybox".to_string()];
    // SAFETY: xtask is one thread here.
    unsafe { std::env::set_var("SOURCE_DATE_EPOCH", "1700000000") };
    // Two times inside the term of the certificate of the development key.
    let today = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        / 86_400
        * 86_400;
    let a = pkg::build(&pkg::Options {
        time: Some(today + 1000),
        ..options(names.clone(), Some(first))
    })?;
    let b = pkg::build(&pkg::Options {
        time: Some(today + 2000),
        ..options(names, Some(second))
    })?;
    for (x, y) in a.iter().zip(&b) {
        same_but_signature(x, y)?;
    }
    println!(
        "pkg-identity: two builds of freedoom and busybox agree byte for byte but for the time and the signature"
    );
    println!("pkg-identity: {:.0} s", started.elapsed().as_secs_f64());
    Ok(())
}

pub fn ci() -> Result<(), String> {
    let started = std::time::Instant::now();
    pkg::command(&[])?;
    repo::command(&[])?;
    identity()?;
    dist_licenses()?;
    println!("pkg-ci: {:.0} s", started.elapsed().as_secs_f64());
    Ok(())
}
