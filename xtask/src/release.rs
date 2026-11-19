// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The release files (docs/release.md). `release-build` is the first half of a
//! release, which runs where the code of the packages is built and holds no
//! secret: the packages (carried from the published index when there is one),
//! the base image, the full image, the kernel and the stage of
//! `tools/dist.py`, all in `target/stafeto-release/`. The second half signs them
//! (`pkg-sign`, `image-repack`, `repo --from`) and `tools/dist.py pack` makes
//! the archives. `cargo xtask dist` runs both halves on a development machine
//! with the development key, so that both ways go through the same code.
//!
//! A packages-only update (`v<series>-pkgs.<k>`, docs/release.md) uses the
//! same halves with `--packages-only`: `release-build` carries and builds the
//! packages of the series and nothing else, `release-check` and `release-pack`
//! take the directory `pkg/` alone, and the tag is read here in its strict form.

use crate::base_image::{BASE_IMAGE, FULL_IMAGE};
use crate::{abi_fingerprint, pkg_probes, pkg_sign, repo};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where `release-build` leaves its output.
pub fn directory() -> PathBuf {
    crate::target_dir().join("stafeto-release")
}

fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The version has no suffix (`0.3.0` is final, `0.3.0-pre.1` is a
/// pre-release): a final release publishes packages.
pub fn is_final(version: &str) -> bool {
    !version.contains('-')
}

/// The storage release of the new packages of this version.
pub fn storage() -> String {
    format!("v{}-aarch64", version())
}

/// The roots the images carry are the official ones: a build that names its
/// own roots (the probes do) is no release.
fn official_roots_only() -> Result<(), String> {
    if std::env::var_os("STAFETO_PKG_ROOTS").is_some() {
        return Err(
            "release-build: STAFETO_PKG_ROOTS is set; a release carries the official roots".into(),
        );
    }
    Ok(())
}

/// A packages-only update: the tag `v<series>-pkgs.<k>` (or the dry run's
/// `v<series>-pkgs.trial`) and the name its files carry.
#[derive(Debug, PartialEq, Eq)]
pub struct Update {
    pub series: String,
    /// `0.5-pkgs.1`: the part of the tag after `v`.
    pub name: String,
}

impl Update {
    /// The text the owner wrote for the update, which the release needs.
    pub fn notes(&self) -> PathBuf {
        crate::root()
            .join("docs/releases")
            .join(format!("{}.md", self.name))
    }
}

fn digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

/// The tag of a packages-only update in its strict form,
/// `v<major>.<minor>-pkgs.<k>` with `k` from 1 and no leading zero, and its
/// series equal to `series`, the series of the version of the workspace at the
/// tagged commit. `trial` is the dry run, which has no tag: it takes the
/// series of the version and the counter `trial`.
pub fn parse_update(tag: Option<&str>, trial: bool, series: &str) -> Result<Update, String> {
    let name = match (tag, trial) {
        (Some(_), true) => return Err("--tag and --trial exclude each other".into()),
        (None, false) => {
            return Err("a packages-only update names its tag: --tag or --trial".into());
        }
        (None, true) => format!("{series}-pkgs.trial"),
        (Some(tag), false) => {
            let bad = || {
                format!(
                    "{tag:?} is no tag of a packages-only update (v<major>.<minor>-pkgs.<k>, k from 1)"
                )
            };
            let name = tag.strip_prefix('v').ok_or_else(bad)?;
            let (of, counter) = name.split_once("-pkgs.").ok_or_else(bad)?;
            let (major, minor) = of.split_once('.').ok_or_else(bad)?;
            if !digits(major) || !digits(minor) || !digits(counter) || counter.starts_with('0') {
                return Err(bad());
            }
            counter.parse::<u64>().map_err(|_| bad())?;
            if of != series {
                return Err(format!(
                    "{tag} is a tag of the series {of} and the version of this commit is of the series {series}"
                ));
            }
            name.to_string()
        }
    };
    Ok(Update {
        series: series.to_string(),
        name,
    })
}

/// `cargo xtask release-build [--previous INDEX_DIR_OR_ADDRESS] [--no-abi]`,
/// or for a packages-only update `release-build --packages-only
/// (--tag TAG | --trial) --previous INDEX_DIR`.
pub fn build_command(args: &[String]) -> Result<(), String> {
    let (mut previous, mut check_abi) = (None, true);
    let (mut only, mut tag, mut trial) = (false, None, false);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--previous" => {
                i += 1;
                previous = Some(
                    args.get(i)
                        .cloned()
                        .ok_or("--previous wants an address or a directory")?,
                );
            }
            "--tag" => {
                i += 1;
                tag = Some(args.get(i).cloned().ok_or("--tag wants a tag")?);
            }
            "--no-abi" => check_abi = false,
            "--packages-only" => only = true,
            "--trial" => trial = true,
            other => {
                return Err(format!(
                    "{other}: unknown argument\nusage: cargo xtask release-build [--previous INDEX] [--no-abi]\n       cargo xtask release-build --packages-only (--tag TAG | --trial) --previous INDEX"
                ));
            }
        }
        i += 1;
    }
    if only {
        if !check_abi {
            return Err("--packages-only and --no-abi exclude each other: the ABI is checked in every update".into());
        }
        let Some(previous) = previous else {
            return Err("--packages-only wants --previous: an update carries the packages of a published series".into());
        };
        let update = parse_update(tag.as_deref(), trial, &crate::pkg::series())?;
        if tag.is_some() && !update.notes().is_file() {
            return Err(format!(
                "release-build: {} is missing; the notes of the update are written before its tag is set",
                update.notes().display()
            ));
        }
        official_roots_only()?;
        crate::pkg::export_commit()?;
        // A frozen series that the version names, whatever suffix the version has.
        abi_fingerprint::command(&["--check".to_string(), "--release".to_string()])?;
        return build_packages(previous);
    }
    if tag.is_some() || trial {
        return Err("--tag and --trial belong to --packages-only".into());
    }
    official_roots_only()?;
    // Before the ABI check: it builds libc.so, once for the whole run, and
    // that build must see the commit.
    crate::pkg::export_commit()?;
    if check_abi {
        let mut abi = vec!["--check".to_string()];
        if is_final(version()) {
            abi.push("--release".into());
        }
        abi_fingerprint::command(&abi)?;
    }
    build(previous)
}

/// The packages of a packages-only update in `target/stafeto-release/pkg`:
/// carried from `previous` when the recipe is that of the index and built
/// otherwise, with the refusals of `carry::packages_only_refusals`. No image,
/// no kernel and no stage.
pub fn build_packages(previous: String) -> Result<(), String> {
    crate::pkg::export_commit()?;
    let out = directory();
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    let packages = out.join("pkg");
    repo::run(&repo::Options {
        previous: Some(previous),
        dir: Some(packages.clone()),
        packages_only: true,
        ..repo::Options::default()
    })?;
    for stale in ["INDEX", "INDEX.sig", "revoked", "revoked.sig"] {
        let _ = std::fs::remove_file(packages.join(stale));
    }
    println!("release-build: {} is ready (packages only)", out.display());
    Ok(())
}

/// The packages, the images, the kernel and the stage in `target/stafeto-release/`.
pub fn build(previous: Option<String>) -> Result<(), String> {
    // The commit goes into the version field of `uname`; the builds below
    // see it through their environment.
    crate::pkg::export_commit()?;
    let out = directory();
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    // All packages, carried or built, with their sources, in one directory.
    let packages = out.join("pkg");
    repo::run(&repo::Options {
        previous,
        dir: Some(packages.clone()),
        ..repo::Options::default()
    })?;
    // The index and the list the build signed with the development keys give
    // way to those of the signing step.
    for stale in ["INDEX", "INDEX.sig", "revoked", "revoked.sig"] {
        let _ = std::fs::remove_file(packages.join(stale));
    }
    for name in [BASE_IMAGE, FULL_IMAGE] {
        let image = crate::base_image::rebuild_image(name)?;
        std::fs::copy(&image, out.join(name)).map_err(|e| format!("{name}: {e}"))?;
    }
    let kernel = crate::build(crate::Variant::Normal)?;
    std::fs::copy(&kernel.image, out.join("Image")).map_err(|e| format!("Image: {e}"))?;
    std::fs::copy(&kernel.elf, out.join("kernel.elf")).map_err(|e| format!("kernel.elf: {e}"))?;
    let base = pkg_probes::stage_licenses(BASE_IMAGE, "base", &packages)?;
    let full = pkg_probes::stage_licenses(FULL_IMAGE, "full", &packages)?;
    python(
        Command::new("python3")
            .arg(crate::root().join("tools/dist.py"))
            .arg("stage")
            .args(["--version", version()])
            .arg("--image")
            .arg(out.join("Image"))
            .arg("--elf")
            .arg(out.join("kernel.elf"))
            .arg("--licenses-base")
            .arg(&base)
            .arg("--licenses-full")
            .arg(&full)
            .arg("--out")
            .arg(out.join("stage")),
    )?;
    println!("release-build: {} is ready", out.display());
    Ok(())
}

/// `cargo xtask release-check [--packages-only [--tag TAG | --trial]] [DIR]`:
/// the signing job runs it before the key is written. What the build job hands
/// over is the files of a release and nothing else, every name in the shape the
/// signing job expects, no link, and `carried.txt` in its strict form. The
/// signing job reads no other file of the directory. With `--packages-only` the
/// files are those of an update, the directory `pkg/` alone, and the tag is read
/// in its strict form.
pub fn check_command(args: &[String]) -> Result<(), String> {
    let (mut only, mut tag, mut trial, mut dir) = (false, None, false, None);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--packages-only" => only = true,
            "--trial" => trial = true,
            "--tag" => {
                i += 1;
                tag = Some(args.get(i).cloned().ok_or("--tag wants a tag")?);
            }
            other if !other.starts_with("--") && dir.is_none() => dir = Some(PathBuf::from(other)),
            other => {
                return Err(format!(
                    "{other}: unknown argument\nusage: cargo xtask release-check [--packages-only [--tag TAG | --trial]] [DIR]"
                ));
            }
        }
        i += 1;
    }
    if !only && (tag.is_some() || trial) {
        return Err("--tag and --trial belong to --packages-only".into());
    }
    if only && (tag.is_some() || trial) {
        parse_update(tag.as_deref(), trial, &crate::pkg::series())?;
    }
    let dir = dir.unwrap_or_else(directory);
    check_directory(&dir, only)?;
    println!(
        "release-check: {} holds the files of {} and no others",
        dir.display(),
        if only {
            "a packages-only update"
        } else {
            "a release"
        }
    );
    Ok(())
}

fn plain_name(name: &str, suffix: &str) -> bool {
    name.strip_suffix(suffix).is_some_and(|stem| {
        !stem.is_empty()
            && stem
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_alphanumeric())
            && stem
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
    })
}

fn entries_of(dir: &Path) -> Result<Vec<(String, std::fs::Metadata)>, String> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let e = e.map_err(|e| e.to_string())?;
        let meta = std::fs::symlink_metadata(e.path()).map_err(|e| e.to_string())?;
        out.push((e.file_name().to_string_lossy().into_owned(), meta));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn check_directory(dir: &Path, packages_only: bool) -> Result<(), String> {
    let refuse = |what: &str| Err(format!("release-check: {}: {what}", dir.display()));
    for (name, meta) in entries_of(dir)? {
        let file = meta.is_file();
        let ok = match name.as_str() {
            "Image" | "kernel.elf" | "boot-base.img" | "boot-full.img" => file && !packages_only,
            "stage" => meta.is_dir() && !packages_only,
            "pkg" => meta.is_dir(),
            _ => false,
        };
        if !ok {
            return refuse(&format!("{name:?} is not a file of a release"));
        }
    }
    let pkg = dir.join("pkg");
    if !pkg.is_dir() {
        return refuse("there is no directory pkg");
    }
    for (name, meta) in entries_of(&pkg)? {
        let ok = (meta.is_file() && (plain_name(&name, ".stpkg") || name == repo::CARRIED))
            || (meta.is_dir() && name == "src");
        if !ok {
            return refuse(&format!("pkg/{name:?} is not a package file"));
        }
    }
    if pkg.join("src").is_dir() {
        for (name, meta) in entries_of(&pkg.join("src"))? {
            if !(meta.is_file() && plain_name(&name, "-src.tar.xz")) {
                return refuse(&format!("pkg/src/{name:?} is not a source archive"));
            }
        }
    }
    // The stage holds archives and trees of notices that only tools/dist.py reads; no link in it.
    let mut stack = if packages_only {
        Vec::new()
    } else {
        vec![dir.join("stage")]
    };
    while let Some(d) = stack.pop() {
        for (name, meta) in entries_of(&d)? {
            if meta.is_dir() {
                stack.push(d.join(&name));
            } else if !meta.is_file() {
                return refuse(&format!("stage {name:?} is no plain file"));
            }
        }
    }
    repo::read_carried(&pkg)?;
    Ok(())
}

fn python(cmd: &mut Command) -> Result<(), String> {
    crate::run_cmd(cmd)
}

/// `cargo xtask release-pack [--packages-only (--tag TAG | --trial)]`: the
/// files of a release, or of a packages-only update, in `target/dist`.
pub fn pack_command(args: &[String]) -> Result<(), String> {
    let out = crate::target_dir().join("dist");
    match args.first().map(String::as_str) {
        None => pack(&out),
        Some("--packages-only") => {
            let (mut tag, mut trial) = (None, false);
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--trial" => trial = true,
                    "--tag" => {
                        i += 1;
                        tag = Some(args.get(i).cloned().ok_or("--tag wants a tag")?);
                    }
                    other => {
                        return Err(format!(
                            "{other}: unknown argument\nusage: cargo xtask release-pack [--packages-only (--tag TAG | --trial)]"
                        ));
                    }
                }
                i += 1;
            }
            let update = parse_update(tag.as_deref(), trial, &crate::pkg::series())?;
            pack_packages(&update, &out)
        }
        Some(other) => Err(format!(
            "{other}: unknown argument\nusage: cargo xtask release-pack [--packages-only (--tag TAG | --trial)]"
        )),
    }
}

/// `tools/dist.py pack-packages` over the signed packages of an update: its
/// index, the SBOM and the sums, into `out`.
pub fn pack_packages(update: &Update, out: &Path) -> Result<(), String> {
    let dir = directory();
    python(
        Command::new("python3")
            .arg(crate::root().join("tools/dist.py"))
            .arg("pack-packages")
            .args(["--name", &update.name])
            .arg("--packages")
            .arg(dir.join("pkg"))
            .arg("--index")
            .arg(dir.join("pkg/INDEX"))
            .arg("--index-sig")
            .arg(dir.join("pkg/INDEX.sig"))
            .arg("--out")
            .arg(out),
    )
}

/// `tools/dist.py pack` over what `release-build` left and the signing
/// step signed, into `out`.
pub fn pack(out: &Path) -> Result<(), String> {
    let dir = directory();
    python(
        Command::new("python3")
            .arg(crate::root().join("tools/dist.py"))
            .arg("pack")
            .args(["--version", version()])
            .arg("--stage")
            .arg(dir.join("stage"))
            .arg("--image")
            .arg(dir.join("Image"))
            .arg("--base-image")
            .arg(dir.join(BASE_IMAGE))
            .arg("--full-image")
            .arg(dir.join(FULL_IMAGE))
            .arg("--packages")
            .arg(dir.join("pkg"))
            .arg("--index")
            .arg(dir.join("pkg/INDEX"))
            .arg("--index-sig")
            .arg(dir.join("pkg/INDEX.sig"))
            .arg("--out")
            .arg(out),
    )
}

/// `cargo xtask dist`: the release files of the workspace's version in
/// `target/dist`, signed with the development key. The second half of a
/// release is the same commands the signing job runs.
pub fn dist() -> Result<(), String> {
    build(None)?;
    let dir = directory();
    let packages = dir.join("pkg");
    let args = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    pkg_sign::sign_command(&["--dir".to_string(), packages.display().to_string()])?;
    for image in [BASE_IMAGE, FULL_IMAGE] {
        pkg_sign::repack_command(&[
            dir.join(image).display().to_string(),
            "--packages".into(),
            packages.display().to_string(),
        ])?;
    }
    repo::command(&{
        let mut a = args(&["--from"]);
        a.push(packages.display().to_string());
        a.extend(args(&["--serial", "1", "--storage"]));
        a.push(storage());
        a
    })?;
    pack(&crate::target_dir().join("dist"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("stafeto-rcheck-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("pkg/src")).unwrap();
        std::fs::create_dir_all(dir.join("stage/base")).unwrap();
        for f in [
            "Image",
            "kernel.elf",
            "boot-base.img",
            "boot-full.img",
            "pkg/a-1-1.stpkg",
            "pkg/src/a-1-1-src.tar.xz",
            "stage/base/x",
        ] {
            std::fs::write(dir.join(f), "x").unwrap();
        }
        dir
    }

    #[test]
    fn the_release_build_sets_the_commit_before_its_first_build() {
        // The check of the ABI builds libc.so, which holds the version field of
        // `uname`; the commit must be set before it.
        let source = include_str!("release.rs");
        let body = &source[source.find("pub fn build_command").unwrap()..];
        let set = body.find("export_commit()").unwrap();
        let first_build = body.find("abi_fingerprint::command").unwrap();
        assert!(set < first_build);
        let build = &source[source.find("pub fn build(").unwrap()..];
        assert!(build.find("export_commit()").unwrap() < build.find("repo::run").unwrap());
    }

    #[test]
    fn the_commit_is_eight_hex_digits_of_head() {
        crate::pkg::export_commit().unwrap();
        let set = std::env::var("STAFETO_COMMIT").unwrap();
        assert_eq!(set.len(), 8);
        assert!(crate::pkg::commit().unwrap().starts_with(&set));
    }

    #[test]
    fn the_signing_job_takes_the_files_of_a_release_and_no_other() {
        let dir = release_dir("ok");
        check_directory(&dir, false).unwrap();
        for (path, text) in [
            // The file the old job read in its shell: a number with a command in it.
            ("previous-serial", "a[$(id)]"),
            ("pkg/a b.stpkg", "x"),
            ("pkg/$(id).stpkg", "x"),
            ("pkg/src/x.sh", "x"),
            ("pkg/README", "x"),
        ] {
            let bad = release_dir("bad");
            std::fs::write(bad.join(path), text).unwrap();
            assert!(check_directory(&bad, false).is_err(), "{path}");
            std::fs::remove_dir_all(&bad).unwrap();
        }
        let linked = release_dir("link");
        std::os::unix::fs::symlink("/etc/passwd", linked.join("stage/base/y")).unwrap();
        assert!(check_directory(&linked, false).is_err());
        let carried = release_dir("carried");
        std::fs::write(
            carried.join("pkg/carried.txt"),
            "a-1-1.stpkg\tnot an address\t-\n",
        )
        .unwrap();
        assert!(check_directory(&carried, false).is_err());
        for d in [dir, linked, carried] {
            std::fs::remove_dir_all(d).unwrap();
        }
    }

    fn words(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_tag_of_an_update_is_read_in_its_strict_form() {
        let ok = parse_update(Some("v0.5-pkgs.3"), false, "0.5").unwrap();
        assert_eq!(ok.series, "0.5");
        assert_eq!(ok.name, "0.5-pkgs.3");
        assert_eq!(
            parse_update(Some("v0.5-pkgs.12"), false, "0.5")
                .unwrap()
                .name,
            "0.5-pkgs.12"
        );
        for bad in [
            "v0.5-pkgs.0",
            "v0.5-pkgs.01",
            "v0.5.1-pkgs.1",
            "v0.5-pkgs.1x",
            "v0.5-pkgs.",
            "v0.5-pkgs.-1",
            "v0.5-pkgs.1 ",
            "v0.5-pkgs.trial",
            "0.5-pkgs.1",
            "vx.5-pkgs.1",
            "v0.5-pkg.1",
            "v0.5",
            "v0.5.1",
            "v0.5-pkgs.99999999999999999999",
            "",
        ] {
            assert!(parse_update(Some(bad), false, "0.5").is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_series_of_the_tag_is_the_series_of_the_version() {
        let e = parse_update(Some("v0.6-pkgs.1"), false, "0.5").unwrap_err();
        assert!(e.contains("series 0.6") && e.contains("series 0.5"), "{e}");
        assert!(parse_update(Some("v0.05-pkgs.1"), false, "0.5").is_err());
        assert_eq!(
            parse_update(Some("v0.5-pkgs.1"), false, &crate::pkg::series())
                .unwrap()
                .series,
            crate::pkg::series()
        );
    }

    #[test]
    fn the_dry_run_has_no_tag_and_a_tag_has_no_dry_run() {
        let trial = parse_update(None, true, "0.5").unwrap();
        assert_eq!(trial.name, "0.5-pkgs.trial");
        assert!(parse_update(Some("v0.5-pkgs.1"), true, "0.5").is_err());
        assert!(parse_update(None, false, "0.5").is_err());
    }

    #[test]
    fn the_arguments_of_a_packages_only_build_are_refused_before_anything_is_built() {
        let tag = format!("v{}-pkgs.9999", crate::pkg::series());
        let refused = |list: &[&str]| build_command(&words(list)).unwrap_err();
        assert!(refused(&["--packages-only", "--trial"]).contains("--previous"));
        assert!(refused(&["--packages-only", "--previous", "x"]).contains("--tag or --trial"));
        assert!(
            refused(&["--packages-only", "--previous", "x", "--trial", "--no-abi"])
                .contains("--no-abi")
        );
        assert!(
            refused(&["--packages-only", "--previous", "x", "--tag", "v0.5-pkgs.0"])
                .contains("no tag")
        );
        assert!(
            refused(&["--packages-only", "--previous", "x", "--tag", "v9.9-pkgs.1"])
                .contains("series 9.9")
        );
        assert!(refused(&["--tag", "v0.5-pkgs.1", "--previous", "x"]).contains("belong"));
        assert!(refused(&["--trial"]).contains("belong"));
        // The notes of the update are written before its tag is set.
        let missing = refused(&["--packages-only", "--previous", "x", "--tag", &tag]);
        assert!(
            missing.contains("docs/releases") && missing.contains("is missing"),
            "{missing}"
        );
    }

    #[test]
    fn the_checks_of_the_tag_come_before_the_files_are_read() {
        assert!(check_command(&words(&["--packages-only", "--tag", "v0.5-pkgs.0"])).is_err());
        assert!(check_command(&words(&["--tag", "v0.5-pkgs.1"])).is_err());
        assert!(check_command(&words(&["--packages-only", "--tag", "v9.9-pkgs.1"])).is_err());
        assert!(pack_command(&words(&["--packages-only", "--tag", "v0.5-pkgs.01"])).is_err());
        assert!(pack_command(&words(&["--packages-only"])).is_err());
        assert!(pack_command(&words(&["--tag", "v0.5-pkgs.1"])).is_err());
    }

    fn update_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("stafeto-rcheck-only-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("pkg/src")).unwrap();
        for f in ["pkg/a-1-1.stpkg", "pkg/src/a-1-1-src.tar.xz"] {
            std::fs::write(dir.join(f), "x").unwrap();
        }
        dir
    }

    #[test]
    fn the_signing_job_takes_the_packages_of_an_update_and_no_other_file() {
        let dir = update_dir("ok");
        check_directory(&dir, true).unwrap();
        std::fs::write(
            dir.join("pkg/carried.txt"),
            "b-2-1.stpkg\thttps://github.com/stafeto/packages/releases/download/v0.5.1-aarch64/b-2-1.stpkg\t-\n",
        )
        .unwrap();
        check_directory(&dir, true).unwrap();
        // The files of a release of the system are no part of an update.
        for (path, text) in [
            ("Image", "x"),
            ("kernel.elf", "x"),
            ("boot-base.img", "x"),
            ("boot-full.img", "x"),
            ("previous-serial", "a[$(id)]"),
            ("pkg/a b.stpkg", "x"),
            ("pkg/$(id).stpkg", "x"),
            ("pkg/src/x.sh", "x"),
            ("pkg/README", "x"),
        ] {
            let bad = update_dir("bad");
            std::fs::write(bad.join(path), text).unwrap();
            assert!(check_directory(&bad, true).is_err(), "{path}");
            std::fs::remove_dir_all(&bad).unwrap();
        }
        let staged = update_dir("stage");
        std::fs::create_dir_all(staged.join("stage/base")).unwrap();
        assert!(check_directory(&staged, true).is_err());
        let linked = update_dir("link");
        std::os::unix::fs::symlink("/etc/passwd", linked.join("pkg/b-1-1.stpkg")).unwrap();
        assert!(check_directory(&linked, true).is_err());
        let carried = update_dir("carried");
        std::fs::write(
            carried.join("pkg/carried.txt"),
            "a-1-1.stpkg\tnot an address\t-\n",
        )
        .unwrap();
        assert!(check_directory(&carried, true).is_err());
        let empty =
            std::env::temp_dir().join(format!("stafeto-rcheck-only-empty-{}", std::process::id()));
        std::fs::create_dir_all(&empty).unwrap();
        assert!(check_directory(&empty, true).is_err());
        for d in [dir, staged, linked, carried, empty] {
            std::fs::remove_dir_all(d).unwrap();
        }
    }

    #[test]
    fn a_packages_only_build_makes_no_image_no_kernel_and_no_stage() {
        let source = include_str!("release.rs");
        let body = &source[source.find("pub fn build_packages").unwrap()..];
        let body = &body[..body.find("\n}\n").unwrap()];
        for word in [
            "rebuild_image",
            "crate::build(",
            "dist.py",
            "stage_licenses",
        ] {
            assert!(!body.contains(word), "{word}");
        }
        assert!(body.contains("packages_only: true"));
        // The ABI is checked with --release before the build, whatever the suffix of the version.
        let command = &source[source.find("pub fn build_command").unwrap()..];
        let only = &command[command.find("if only {").unwrap()
            ..command.find("if tag.is_some() || trial").unwrap()];
        assert!(only.contains("\"--release\""));
        assert!(
            only.find("abi_fingerprint::command").unwrap()
                < only.find("build_packages(previous)").unwrap()
        );
        assert!(
            only.find("export_commit()").unwrap() < only.find("abi_fingerprint::command").unwrap()
        );
    }

    #[test]
    fn a_suffix_makes_a_version_no_final_one() {
        assert!(is_final("0.3.0"));
        assert!(!is_final("0.3.0-pre.1"));
    }

    #[test]
    fn the_storage_is_named_for_the_version() {
        assert_eq!(storage(), format!("v{}-aarch64", env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn a_build_with_roots_of_its_own_is_no_release() {
        // SAFETY: the other tests of this module do not read the variable.
        unsafe { std::env::set_var("STAFETO_PKG_ROOTS", "x") };
        let refused = official_roots_only();
        unsafe { std::env::remove_var("STAFETO_PKG_ROOTS") };
        assert!(refused.unwrap_err().contains("official"));
        assert!(official_roots_only().is_ok());
    }

    /// The option groups of a QEMU command: a flag with its value, the memory
    /// in MiB, the files by role, and no `-smp` (a count of CPUs is the choice
    /// of the one who starts the machine).
    fn groups(arguments: &[String]) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < arguments.len() {
            let flag = arguments[i].clone();
            if flag == "-nographic" {
                out.push((flag, String::new()));
                i += 1;
                continue;
            }
            let mut value = arguments[i + 1].clone();
            i += 2;
            match flag.as_str() {
                "-smp" => continue,
                "-kernel" | "-initrd" => value = "FILE".into(),
                "-m" => {
                    value = match value.split_at(value.len() - 1) {
                        (n, "M") => n.parse::<u64>().unwrap(),
                        (n, "G") => n.parse::<u64>().unwrap() * 1024,
                        _ => panic!("{value}: not in M or G"),
                    }
                    .to_string()
                }
                "-drive" => {
                    let at = value.find("file=").unwrap();
                    let end = value[at..].find(",cache").unwrap() + at;
                    value.replace_range(at..end, "file=STORE");
                }
                _ => {}
            }
            out.push((flag, value));
        }
        out.sort();
        out
    }

    /// `run.sh` of each archive (filled by `tools/dist.py` from its table of
    /// the images) prints the command that xtask builds for the same image
    /// and machine, with the devices of `base_image::machine_args`.
    #[test]
    fn the_run_script_of_an_archive_builds_the_command_xtask_builds_for_its_image() {
        let tree = crate::root();
        let dir = std::env::temp_dir().join(format!("stafeto-dist-run-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (flavour, image) in [("base", BASE_IMAGE), ("full", FULL_IMAGE)] {
            let filled = Command::new("python3")
                .args(["-I", "-c"])
                .arg(
                    "import sys; sys.path.insert(0, sys.argv[1]); import dist; \
                     image, memory, _ = dist.FLAVOURS[sys.argv[2]]; \
                     print(dist.fill(open(sys.argv[1] + '/dist/run.sh').read(), image=image, memory=memory), end='')",
                )
                .arg(tree.join("tools"))
                .arg(flavour)
                .output()
                .unwrap();
            assert!(
                filled.status.success(),
                "{}",
                String::from_utf8_lossy(&filled.stderr)
            );
            let script = dir.join(format!("run-{flavour}.sh"));
            std::fs::write(&script, &filled.stdout).unwrap();
            let printed = Command::new("sh")
                .arg(&script)
                .args(["--print", "--nographic"])
                .output()
                .unwrap();
            assert!(
                printed.status.success(),
                "{}",
                String::from_utf8_lossy(&printed.stderr)
            );
            let text = String::from_utf8(printed.stdout).unwrap();
            let mut got: Vec<String> = text.lines().map(str::to_string).collect();
            assert_eq!(got.remove(0), "qemu-system-aarch64");
            let machine = crate::base_image::machine(image);
            let mut want = crate::qemu::args(machine, Path::new("Image"), Some(Path::new(image)));
            want.push("-nographic".into());
            want.extend(crate::base_image::machine_args(Path::new("store.img")));
            assert_eq!(groups(&got), groups(&want), "{flavour}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
