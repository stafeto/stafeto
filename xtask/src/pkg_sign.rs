// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask pkg-sign` and `cargo xtask image-repack` (docs/packages.md).
//!
//! A release builds its packages with the development key and signs them in
//! a separate job that builds nothing. The trailer of a package is one page
//! and the bytes it covers do not depend on the key, so signing again changes
//! the last page and nothing else:
//!
//! * `pkg-sign --key K.key [--cert K.cert] --dir D [--time T]` signs again
//!   each package of `D` that the development key signed, with the same time
//!   unless `--time` says otherwise. The length of the file and the covered
//!   bytes stay, which the tool checks. A package that is signed by the key
//!   already, or by a key an official root vouches for (a package carried
//!   from a published index), is verified and left as it is. Any other
//!   signer is refused.
//! * `image-repack IMAGE --packages D` writes the files of `D` over
//!   the package files (`*.stpkg`) of a boot image. The length of each file
//!   is the same, so the table, the places and every other file of the image
//!   keep their bytes, which the tool checks again after the write.

use crate::keys::{self, Signing};
use bootimg::BootImage;
use pkgfmt::container::write::sign;
use pkgfmt::{Key, Name, Package, Revocation, Trust, sha};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn sha_hex(data: &[u8]) -> String {
    let mut buf = [0u8; 64];
    sha::hex(&sha::sha256(data), &mut buf).to_string()
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Signed {
    /// Packages signed again.
    pub signed: Vec<String>,
    /// Packages left as they were, verified.
    pub kept: Vec<String>,
}

fn write_through_temp(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let temp = path.with_extension("stpkg.part");
    std::fs::write(&temp, bytes).map_err(|e| format!("{}: {e}", temp.display()))?;
    std::fs::rename(&temp, path).map_err(|e| format!("{}: {e}", path.display()))
}

/// What `sign_dir` needs besides the key.
pub struct Setting<'a> {
    /// The name of the development key: its packages are signed again.
    pub development: Name,
    /// The roots and direct keys that must accept the new signature and the
    /// packages that stay.
    pub roots: &'a [Key],
    pub direct: &'a [Key],
    /// The list of revocations in force, against which every signature is
    /// checked, the new ones and those that stay.
    pub revocations: &'a [Revocation],
    /// The files that `carried.txt` lists: only these may stay as they are (a
    /// build directory may hold any file, and a package that was not carried
    /// has no business with a key but the development key's).
    pub carried: &'a BTreeSet<String>,
    /// The time of the new signatures, for the probes; `None` is the time of
    /// this machine. The time in a trailer the build wrote is never used: the
    /// time decides which revocations reach a signature.
    pub time: Option<u64>,
}

fn clock() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// How far ahead of this machine's clock a trailer of the build may be.
const SKEW: u64 = 300;

/// Signs again the packages of `dir` that the development key signed.
pub fn sign_dir(dir: &Path, signing: &Signing, set: &Setting<'_>) -> Result<Signed, String> {
    let trust = Trust {
        roots: set.roots,
        direct: set.direct,
    };
    let development = set.development;
    let at = set.time.unwrap_or_else(clock);
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".stpkg"))
        .collect();
    names.sort();
    let mut done = Signed::default();
    for name in names {
        let path = dir.join(&name);
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let file = Package::parse(&bytes).map_err(|e| format!("{name}: {e}"))?;
        let signer = file.trailer.key;
        if signer == development && signing.key == development {
            // A development run signs with the development key: nothing to do.
            done.kept.push(name);
            continue;
        }
        if signer != development {
            // A carried package: listed in `carried.txt`, signed by a key the
            // roots vouch for and no revocation reaches.
            if !set.carried.contains(&name) {
                return Err(format!(
                    "{name}: signed by {}, but not listed in {}: only the development key signs a package that was built here",
                    signer.as_str(),
                    crate::repo::CARRIED
                ));
            }
            file.verify(&trust, set.revocations).map_err(|e| {
                format!(
                    "{name}: signed by {}, which is neither the development key nor a key the roots accept: {e}",
                    signer.as_str()
                )
            })?;
            done.kept.push(name);
            continue;
        }
        let covered_digest = sha::sha256(file.covered());
        if file.trailer.time > clock() + SKEW {
            return Err(format!(
                "{name}: the trailer of the build says a time to come"
            ));
        }
        let new = sign(
            file.covered().to_vec(),
            &signing.seed,
            signing.key,
            signing.certificate,
            at,
        )
        .map_err(|e| format!("{name}: {e}"))?;
        if new.len() != bytes.len() {
            return Err(format!(
                "{name}: the file is {} bytes after signing and was {}",
                new.len(),
                bytes.len()
            ));
        }
        let again = Package::parse(&new).map_err(|e| format!("{name}: {e}"))?;
        if sha::sha256(again.covered()) != covered_digest {
            return Err(format!("{name}: the covered bytes changed"));
        }
        again.verify(&trust, set.revocations).map_err(|e| {
            format!(
                "{name}: the new signature of {} is not accepted: {e}",
                signing.key.as_str()
            )
        })?;
        write_through_temp(&path, &new)?;
        done.signed.push(name);
    }
    if done.signed.is_empty() && done.kept.is_empty() {
        return Err(format!("{}: no .stpkg file", dir.display()));
    }
    Ok(done)
}

/// Puts the package files of `dir` into `image` (a file path), in place; the
/// number of files replaced.
pub fn repack(image: &Path, dir: &Path) -> Result<usize, String> {
    let before = std::fs::read(image).map_err(|e| format!("{}: {e}", image.display()))?;
    let mut after = before.clone();
    let parsed = BootImage::parse(&before).map_err(|e| format!("{}: {e}", image.display()))?;
    let mut replaced: Vec<(String, std::ops::Range<usize>, String)> = Vec::new();
    for f in parsed.files().filter(|f| f.name.ends_with(".stpkg")) {
        let from = dir.join(f.name);
        let bytes = std::fs::read(&from).map_err(|e| format!("{}: {e}", from.display()))?;
        if bytes.len() != f.data.len() {
            return Err(format!(
                "{}: {} bytes, the image holds {} (the layout of an image does not move)",
                from.display(),
                bytes.len(),
                f.data.len()
            ));
        }
        let at = f.offset as usize;
        after[at..at + bytes.len()].copy_from_slice(&bytes);
        replaced.push((f.name.to_string(), at..at + bytes.len(), sha_hex(&bytes)));
    }
    if replaced.is_empty() {
        return Err(format!("{}: holds no package file", image.display()));
    }
    // The check, before anything is written: the image still parses, each
    // package file is the one of `dir`, every other file and every byte
    // outside the replaced ranges are as they were.
    let image_after = BootImage::parse(&after).map_err(|e| format!("repacked image: {e}"))?;
    let by_name: BTreeMap<&str, &str> = replaced
        .iter()
        .map(|(n, _, d)| (n.as_str(), d.as_str()))
        .collect();
    let others_before: Vec<(String, String)> = parsed
        .files()
        .filter(|f| !f.name.ends_with(".stpkg"))
        .map(|f| (f.name.to_string(), sha_hex(f.data)))
        .collect();
    let others_after: Vec<(String, String)> = image_after
        .files()
        .filter(|f| !f.name.ends_with(".stpkg"))
        .map(|f| (f.name.to_string(), sha_hex(f.data)))
        .collect();
    if others_before != others_after {
        return Err("repack changed a file that is no package file".into());
    }
    for f in image_after.files().filter(|f| f.name.ends_with(".stpkg")) {
        if by_name.get(f.name) != Some(&sha_hex(f.data).as_str()) {
            return Err(format!("{}: the image does not hold the new file", f.name));
        }
    }
    let inside = |i: usize| replaced.iter().any(|(_, r, _)| r.contains(&i));
    if let Some(i) = (0..before.len()).find(|&i| before[i] != after[i] && !inside(i)) {
        return Err(format!(
            "repack changed the byte {i}, outside the package files"
        ));
    }
    let temp = image.with_extension("img.part");
    std::fs::write(&temp, &after).map_err(|e| format!("{}: {e}", temp.display()))?;
    std::fs::rename(&temp, image).map_err(|e| format!("{}: {e}", image.display()))?;
    Ok(replaced.len())
}

fn value(args: &[String], i: &mut usize) -> Result<String, String> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| format!("{} wants a value", args[*i - 1]))
}

/// `cargo xtask pkg-sign [--key K.key [--cert K.cert]] --dir D [--time T]`.
pub fn sign_command(args: &[String]) -> Result<(), String> {
    let (mut key, mut cert, mut dir, mut time) = (None, None, None, None);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key" => key = Some(PathBuf::from(value(args, &mut i)?)),
            "--cert" => cert = Some(PathBuf::from(value(args, &mut i)?)),
            "--dir" => dir = Some(PathBuf::from(value(args, &mut i)?)),
            "--time" => {
                let t = value(args, &mut i)?;
                time = Some(
                    t.parse::<u64>()
                        .map_err(|_| format!("--time {t}: not a number of seconds"))?,
                );
            }
            other => return Err(format!("{other}: unknown argument\n{}", sign_usage())),
        }
        i += 1;
    }
    let dir = dir.ok_or_else(sign_usage)?;
    let tree = crate::root();
    let signing = keys::signing(key.as_deref(), cert.as_deref(), &tree)?;
    let (mut roots, direct) = keys::trust_of(&signing, &tree)?;
    for r in keys::official_roots()? {
        if !roots.contains(&r) {
            roots.push(r);
        }
    }
    let dev = keys::dev_keys(&tree)?;
    let development_run = signing.key == dev.release.name;
    if !roots.contains(&dev.root) && development_run {
        roots.push(dev.root);
    }
    let revocations = crate::carry::tree_revocations(&tree, development_run)?
        .map(|(_, list)| list)
        .unwrap_or_default();
    let carried: BTreeSet<String> = crate::repo::read_carried(&dir)?.into_keys().collect();
    let done = sign_dir(
        &dir,
        &signing,
        &Setting {
            development: dev.release.name,
            roots: &roots,
            direct: &direct,
            revocations: &revocations,
            carried: &carried,
            time,
        },
    )?;
    println!(
        "pkg-sign: {} signed again by {}, {} left as they were, in {}",
        done.signed.len(),
        signing.key.as_str(),
        done.kept.len(),
        dir.display()
    );
    Ok(())
}

fn sign_usage() -> String {
    "usage: cargo xtask pkg-sign [--key K.key [--cert K.cert]] --dir D [--time SECONDS]".into()
}

/// `cargo xtask image-repack IMAGE --packages D`.
pub fn repack_command(args: &[String]) -> Result<(), String> {
    let usage = || "usage: cargo xtask image-repack IMAGE --packages D".to_string();
    let image = args
        .first()
        .filter(|a| !a.starts_with("--"))
        .ok_or_else(usage)?;
    let mut packages = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--packages" => packages = Some(PathBuf::from(value(args, &mut i)?)),
            other => return Err(format!("{other}: unknown argument\n{}", usage())),
        }
        i += 1;
    }
    let packages = packages.ok_or_else(usage)?;
    let n = repack(Path::new(image), &packages)?;
    println!(
        "image-repack: {n} package files of {image} are those of {}",
        packages.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkgfmt::cert::{Certificate, PURPOSE_PACKAGES};
    use pkgfmt::sig;

    const ROOT: [u8; 32] = [3; 32];
    const DEV: [u8; 32] = [4; 32];
    const REL: [u8; 32] = [5; 32];

    fn n(s: &str) -> Name {
        Name::new(s).unwrap()
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("stafeto-sign-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn root() -> Key {
        Key {
            name: n("t-root"),
            public: sig::public_key(&ROOT),
        }
    }

    fn cert_of(seed: &[u8; 32], name: &str) -> [u8; pkgfmt::cert::SIZE] {
        Certificate::issue(
            &ROOT,
            n("t-root"),
            n(name),
            sig::public_key(seed),
            PURPOSE_PACKAGES,
            0,
            4_000_000_000,
        )
        .to_bytes()
    }

    /// A package signed by the key `key` (seed `seed`).
    fn package(name: &str, seed: &[u8; 32], key: &str) -> Vec<u8> {
        crate::carry::tests::package_with(name, "1.0", "1", &"ab".repeat(32), seed, key, &ROOT)
    }

    fn release_signing() -> Signing {
        Signing {
            seed: REL,
            key: n("t-release-2026"),
            certificate: Some(cert_of(&REL, "t-release-2026")),
        }
    }

    /// Runs `sign_dir` for the release key with the carried names and revocations given.
    fn run(
        dir: &Path,
        carried: &[&str],
        revocations: &[Revocation],
        time: Option<u64>,
    ) -> Result<Signed, String> {
        let carried: BTreeSet<String> = carried.iter().map(|s| s.to_string()).collect();
        sign_dir(
            dir,
            &release_signing(),
            &Setting {
                development: n("t-dev-release"),
                roots: &[root()],
                direct: &[],
                revocations,
                carried: &carried,
                time,
            },
        )
    }

    #[test]
    fn a_development_package_is_signed_again_with_the_time_of_the_signer() {
        let dir = scratch("resign");
        let old = package("demo", &DEV, "t-dev-release");
        std::fs::write(dir.join("demo-1.0-1.stpkg"), &old).unwrap();
        let began = clock();
        let done = run(&dir, &[], &[], None).unwrap();
        assert_eq!(done.signed, ["demo-1.0-1.stpkg"]);
        let new = std::fs::read(dir.join("demo-1.0-1.stpkg")).unwrap();
        assert_eq!(new.len(), old.len());
        let page = pkgfmt::container::TRAILER_SIZE;
        assert_eq!(new[..new.len() - page], old[..old.len() - page]);
        assert_ne!(new[new.len() - page..], old[old.len() - page..]);
        let file = Package::parse(&new).unwrap();
        assert_eq!(file.trailer.key.as_str(), "t-release-2026");
        // The build wrote the time 1000 in its trailer; the new signature has the clock of the signer.
        assert_eq!(Package::parse(&old).unwrap().trailer.time, 1000);
        assert!(file.trailer.time >= began && file.trailer.time <= clock());
        assert!(
            file.verify(
                &Trust {
                    roots: &[root()],
                    direct: &[]
                },
                &[]
            )
            .is_ok()
        );
        // A second run finds a package of the key that is no carried one: refused.
        let err = run(&dir, &[], &[], None).unwrap_err();
        assert!(err.contains("not listed in carried.txt"), "{err}");
        // A time of the probes is taken as given.
        let probe = scratch("resign-time");
        std::fs::write(
            probe.join("d-1.0-1.stpkg"),
            package("d", &DEV, "t-dev-release"),
        )
        .unwrap();
        run(&probe, &[], &[], Some(1_700_000_000)).unwrap();
        let bytes = std::fs::read(probe.join("d-1.0-1.stpkg")).unwrap();
        assert_eq!(Package::parse(&bytes).unwrap().trailer.time, 1_700_000_000);
        for d in [dir, probe] {
            std::fs::remove_dir_all(&d).unwrap();
        }
    }

    #[test]
    fn a_trailer_with_a_time_to_come_is_refused() {
        let dir = scratch("future");
        let future = clock() + 100_000;
        let bytes = {
            let old = package("late", &DEV, "t-dev-release");
            let file = Package::parse(&old).unwrap();
            let cert = cert_of(&DEV, "t-dev-release");
            pkgfmt::container::write::sign(
                file.covered().to_vec(),
                &DEV,
                n("t-dev-release"),
                Some(cert),
                future,
            )
            .unwrap()
        };
        std::fs::write(dir.join("late-1.0-1.stpkg"), bytes).unwrap();
        let err = run(&dir, &[], &[], None).unwrap_err();
        assert!(err.contains("a time to come"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_carried_package_is_checked_and_not_touched() {
        let dir = scratch("carried");
        // Signed by an older release key the root vouches for.
        let carried = package("kept", &[6; 32], "t-release-2025");
        std::fs::write(dir.join("kept-1.0-1.stpkg"), &carried).unwrap();
        std::fs::write(
            dir.join("new-1.0-1.stpkg"),
            package("new", &DEV, "t-dev-release"),
        )
        .unwrap();
        let done = run(&dir, &["kept-1.0-1.stpkg"], &[], None).unwrap();
        assert_eq!(done.signed, ["new-1.0-1.stpkg"]);
        assert_eq!(done.kept, ["kept-1.0-1.stpkg"]);
        assert_eq!(
            std::fs::read(dir.join("kept-1.0-1.stpkg")).unwrap(),
            carried
        );
        // The same package without a line in carried.txt is refused.
        let err = run(&dir, &[], &[], None).unwrap_err();
        assert!(err.contains("not listed in carried.txt"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_package_signed_by_a_revoked_key_is_refused_even_if_carried() {
        let dir = scratch("revoked");
        // The package was signed at the time 1000 by t-release-2025.
        std::fs::write(
            dir.join("kept-1.0-1.stpkg"),
            package("kept", &[6; 32], "t-release-2025"),
        )
        .unwrap();
        let list = [Revocation {
            name: n("t-release-2025"),
            since: 500,
        }];
        let err = run(&dir, &["kept-1.0-1.stpkg"], &list, None).unwrap_err();
        assert!(err.contains("Revoked"), "{err}");
        // A revocation from a later time does not reach it.
        let later = [Revocation {
            name: n("t-release-2025"),
            since: 5000,
        }];
        assert!(run(&dir, &["kept-1.0-1.stpkg"], &later, None).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_package_of_an_unknown_signer_is_refused() {
        let dir = scratch("unknown");
        // A certificate of another root: no root of ours accepts it.
        let stranger = crate::carry::tests::package_with(
            "odd",
            "1.0",
            "1",
            &"ab".repeat(32),
            &[7; 32],
            "t-stranger",
            &[9; 32],
        );
        std::fs::write(dir.join("odd-1.0-1.stpkg"), &stranger).unwrap();
        let err = run(&dir, &["odd-1.0-1.stpkg"], &[], None).unwrap_err();
        assert!(err.contains("neither the development key"), "{err}");
        // An empty directory is refused, and a time outside the certificate too.
        let empty = scratch("empty");
        assert!(run(&empty, &[], &[], None).is_err());
        let ok = scratch("late");
        std::fs::write(
            ok.join("d-1.0-1.stpkg"),
            package("d", &DEV, "t-dev-release"),
        )
        .unwrap();
        let err = run(&ok, &[], &[], Some(5_000_000_000)).unwrap_err();
        assert!(err.contains("not accepted"), "{err}");
        for d in [dir, empty, ok] {
            std::fs::remove_dir_all(&d).unwrap();
        }
    }

    #[test]
    fn a_development_run_leaves_development_packages_alone() {
        let dir = scratch("dev-run");
        let bytes = package("demo", &DEV, "t-dev-release");
        std::fs::write(dir.join("demo-1.0-1.stpkg"), &bytes).unwrap();
        let dev = Signing {
            seed: DEV,
            key: n("t-dev-release"),
            certificate: Some(cert_of(&DEV, "t-dev-release")),
        };
        let none = BTreeSet::new();
        let done = sign_dir(
            &dir,
            &dev,
            &Setting {
                development: n("t-dev-release"),
                roots: &[root()],
                direct: &[],
                revocations: &[],
                carried: &none,
                time: None,
            },
        )
        .unwrap();
        assert_eq!((done.signed.len(), done.kept.len()), (0, 1));
        assert_eq!(std::fs::read(dir.join("demo-1.0-1.stpkg")).unwrap(), bytes);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn image_with(packages: &[(&str, &[u8])]) -> Vec<u8> {
        let mut files: Vec<(&str, &[u8])> =
            vec![("init", b"program"), ("rootfs", b"the table of the system")];
        files.extend_from_slice(packages);
        files.push(("last", b"after the packages"));
        bootimg::write::image(&files).unwrap()
    }

    #[test]
    fn repack_replaces_the_package_files_and_nothing_else() {
        let dir = scratch("repack");
        let a = package("a", &DEV, "t-dev-release");
        let b = package("b", &DEV, "t-dev-release");
        let image_path = dir.join("boot.img");
        std::fs::write(
            &image_path,
            image_with(&[("a-1.0-1.stpkg", &a), ("b-1.0-1.stpkg", &b)]),
        )
        .unwrap();
        let signed = dir.join("signed");
        std::fs::create_dir(&signed).unwrap();
        std::fs::write(signed.join("a-1.0-1.stpkg"), &a).unwrap();
        std::fs::write(signed.join("b-1.0-1.stpkg"), &b).unwrap();
        let done = run(&signed, &[], &[], None).unwrap();
        assert_eq!(done.signed.len(), 2);
        let before = std::fs::read(&image_path).unwrap();
        assert_eq!(repack(&image_path, &signed).unwrap(), 2);
        let after = std::fs::read(&image_path).unwrap();
        assert_eq!(after.len(), before.len());
        let image = BootImage::parse(&after).unwrap();
        for f in image.files() {
            match f.name {
                "a-1.0-1.stpkg" | "b-1.0-1.stpkg" => {
                    assert_eq!(f.data, std::fs::read(signed.join(f.name)).unwrap());
                }
                "init" => assert_eq!(f.data, b"program"),
                "rootfs" => assert_eq!(f.data, b"the table of the system"),
                "last" => assert_eq!(f.data, b"after the packages"),
                other => panic!("{other}"),
            }
        }
        // Only the last page of each package changed, so that is all that differs.
        let page = pkgfmt::container::TRAILER_SIZE;
        let changed = (0..before.len()).filter(|&i| before[i] != after[i]).count();
        assert!(changed > 0 && changed <= 2 * page);
        // A second run changes nothing.
        assert_eq!(repack(&image_path, &signed).unwrap(), 2);
        assert_eq!(std::fs::read(&image_path).unwrap(), after);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn repack_refuses_a_file_of_another_length_a_missing_file_and_an_image_without_packages() {
        let dir = scratch("repack-refuse");
        let a = package("a", &DEV, "t-dev-release");
        let image_path = dir.join("boot.img");
        let original = image_with(&[("a-1.0-1.stpkg", &a)]);
        std::fs::write(&image_path, &original).unwrap();
        let packages = dir.join("p");
        std::fs::create_dir(&packages).unwrap();
        // Missing.
        assert!(repack(&image_path, &packages).is_err());
        // Longer by a page.
        let mut longer = a.clone();
        longer.extend(vec![0u8; 4096]);
        std::fs::write(packages.join("a-1.0-1.stpkg"), longer).unwrap();
        assert!(
            repack(&image_path, &packages)
                .unwrap_err()
                .contains("does not move")
        );
        assert_eq!(std::fs::read(&image_path).unwrap(), original);
        // No package file in the image.
        let bare = dir.join("bare.img");
        std::fs::write(
            &bare,
            bootimg::write::image(&[("init", b"x".as_slice())]).unwrap(),
        )
        .unwrap();
        assert!(
            repack(&bare, &packages)
                .unwrap_err()
                .contains("no package file")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
