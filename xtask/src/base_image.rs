// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The base image and the full image (spec 5, 3.4): the shell with the
//! network service, the screen and the keys, the base packages as layers
//! (`boot-base.img`) or all packages (`boot-full.img`). `cargo xtask image
//! base|full [run]` builds one, and with `run` boots it in QEMU on the
//! machine of `machine_args`. The table of init is `table-base`
//! (services/init/src/table/base.rs).

use crate::*;

pub const BASE_IMAGE: &str = "boot-base.img";
pub const FULL_IMAGE: &str = "boot-full.img";

/// The stack of the package tool, which `apps/pkg/build.rs` asks the linker for (`-zstack-size`): the
/// frames of its requests, the walk of the dependencies and the checks of signatures.
#[cfg(test)]
pub const PKG_STACK_SIZE: u32 = 256 * 1024;

/// The programs of both images: the services of the shell, those of the
/// network, the screen and the keys, and the programs of the packages the
/// image holds (their ELF files are what the packages carry).
pub fn programs(image: &str) -> &'static [ImageProgram] {
    static LISTS: std::sync::Mutex<Vec<(String, &'static [ImageProgram])>> =
        std::sync::Mutex::new(Vec::new());
    let mut lists = LISTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((_, list)) = lists.iter().find(|(name, _)| name == image) {
        return list;
    }
    let packages = packages::of_image(image).unwrap_or_else(|e| panic!("{image}: {e}"));
    // The package service lists this many packages of the image and says `too many packages,
    // skipped` to the rest: the build refuses an image it would fail.
    assert!(
        packages.len() <= pkgd::packages::IMAGE_MAX,
        "{image} holds {} packages, the package service lists {} (pkgd::packages::IMAGE_MAX)",
        packages.len(),
        pkgd::packages::IMAGE_MAX
    );
    let mut programs = SHELL_SERVICES.to_vec();
    programs[0] = ("init", "init", INIT_STACK_SIZE, &["table-base"]);
    programs.extend(package_programs(&packages));
    programs.extend(SHELL_SERVICES_LAST);
    programs.push(("netd", "netd", net::NETD_STACK_SIZE, &[]));
    programs.push(("virtio-blk", "virtio-blk", blk_probe::BLK_STACK_SIZE, &[]));
    programs.push(("pkgd", "pkgd", store_probe::PKGD_STACK_SIZE, &[]));
    // The tool is started from its file `/bin/pkg`: stack 0 keeps it out of the image as a
    // program of the loader, and its stack is the `PT_GNU_STACK` that build.rs asks the linker for.
    programs.push(("pkg", "pkg", 0, &[]));
    programs.push((
        "virtio-input",
        "virtio-input",
        input_probe::INPUT_STACK_SIZE,
        &[],
    ));
    programs.push(("virtio-gpu", "virtio-gpu", gpu_probe::GPU_STACK_SIZE, &[]));
    let list: &'static [ImageProgram] = Box::leak(programs.into_boxed_slice());
    lists.push((image.to_string(), list));
    list
}

/// The devices of the machine of both images: the screen, the keyboard, the
/// network device on user-mode networking, and the disk of the package
/// service, the file `store` (`qemu::store_file` makes it).
pub fn machine_args(store: &Path) -> Vec<String> {
    let mut args: Vec<String> = qemu::GPU.iter().map(|s| (*s).to_owned()).collect();
    args.extend(qemu::KEYBOARD.iter().map(|s| (*s).to_owned()));
    args.extend(qemu::net(&[]));
    args.extend(qemu::store(store, None));
    args
}

/// The machine of an image: the full image runs on 1 GiB, because on 512 MiB
/// its container of 54 MB leaves init 15 837 free pages (the base image, 26 843
/// on 512 MiB, stays there); the archive of the full image names it in its
/// `run.sh` (spec 5, release).
pub fn machine(image: &str) -> &'static qemu::Machine {
    if image == FULL_IMAGE || packages::without_name(image).is_some() {
        &qemu::VIRT_1G
    } else {
        &qemu::VIRT
    }
}

/// What the programs of the base and the full image are built from.
pub fn prepare() -> Result<(), String> {
    relibc()?;
    busybox_build()?;
    nano_build()?;
    bash_build()?;
    doom::build_games()?;
    net_build()
}

/// The image `name` built.
pub fn build_image(name: &'static str) -> Result<PathBuf, String> {
    prepare()?;
    build_boot_image(name, programs(name), BOOT_PROFILE)
}

/// The image `name` built again from the package files of `target/pkg` as they are now: the
/// image of `build_image` is kept for the run, and a run that carries packages (their releases
/// change the names of the files) needs the image with the files it has made since.
pub fn rebuild_image(name: &'static str) -> Result<PathBuf, String> {
    prepare()?;
    crate::write_boot_image(name, programs(name), BOOT_PROFILE)
}

const USAGE: &str = "usage: cargo xtask image base|full [--without PACKAGE] [run]";

/// `cargo xtask image base|full [--without PACKAGE] [run]`. `--without` builds the full
/// image without an optional package and the packages that depend on it, as
/// `target/boot-full-without-<package>.img`.
pub fn command(args: &[String]) -> Result<(), String> {
    let mut rest: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();
    let mut name: &'static str = match args.first().map(String::as_str) {
        Some("base") => BASE_IMAGE,
        Some("full") => FULL_IMAGE,
        _ => return Err(USAGE.to_owned()),
    };
    if let Some(at) = rest.iter().position(|a| *a == "--without") {
        if name != FULL_IMAGE || at + 1 >= rest.len() {
            return Err(USAGE.to_owned());
        }
        let package = rest.remove(at + 1);
        rest.remove(at);
        name = Box::leak(packages::without_image(package).into_boxed_str());
        // The refusal comes before the long build.
        packages::of_image(name)?;
    }
    let args = &rest;
    let image = build_image(name)?;
    let size = std::fs::metadata(&image)
        .map_err(|e| format!("{}: {e}", image.display()))?
        .len();
    println!("image: {} ({size} bytes)", image.display());
    match args.first().copied() {
        None => Ok(()),
        Some("run") => {
            let kernel = build(Variant::Normal)?;
            // The disk of the image: a file of its own, which survives the run.
            let store = store_path(&image);
            qemu::store_file(&store, STORE_BYTES, false)?;
            let mut cmd = qemu::command(machine(name), &kernel.image, Some(&image));
            cmd.args(["-nographic"]);
            cmd.args(machine_args(&store));
            run_interactive_qemu(cmd, &kernel.elf)
        }
        Some(other) => Err(format!("image {name}: unknown argument {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The memory size of the `PT_GNU_STACK` header of a 64-bit little-endian ELF file.
    fn gnu_stack(elf: &[u8]) -> Option<u64> {
        let word = |at: usize, n: usize| -> u64 {
            let mut b = [0u8; 8];
            b[..n].copy_from_slice(&elf[at..at + n]);
            u64::from_le_bytes(b)
        };
        let (off, size, count) = (
            word(32, 8) as usize,
            word(54, 2) as usize,
            word(56, 2) as usize,
        );
        (0..count)
            .map(|i| off + i * size)
            .find(|&h| word(h, 4) == 0x6474_e551)
            .map(|h| word(h + 40, 8))
    }

    /// The package tool is started from its file: it is no program of the loader (a second copy
    /// of 765 KB that nobody starts), and the stack it claims is the one its file asks for.
    #[test]
    fn the_package_tool_is_in_the_image_once_with_the_stack_the_code_claims() {
        for image in [BASE_IMAGE, FULL_IMAGE] {
            let tool: Vec<_> = programs(image).iter().filter(|p| p.1 == "pkg").collect();
            assert_eq!(tool.len(), 1, "{image}");
            assert_eq!(tool[0].2, 0, "{image}: stack 0, the file alone");
            let files = crate::rootfs::files_of(image);
            let n = files.iter().filter(|f| f.path == "/bin/pkg").count();
            assert_eq!(n, 1, "{image}");
        }
        // build.rs asks the linker for the number this file names.
        let build = std::fs::read_to_string(crate::root().join("apps/pkg/build.rs")).unwrap();
        assert!(build.contains(&format!("-zstack-size={PKG_STACK_SIZE}")));
        // When the program and the image were built: the header of the file says it, and the
        // image holds the bytes once.
        let target = crate::target_dir();
        if let (Ok(elf), Ok(img)) = (
            std::fs::read(target.join("images/boot-base/pkg")),
            std::fs::read(target.join(BASE_IMAGE)),
        ) {
            assert_eq!(gnu_stack(&elf), Some(u64::from(PKG_STACK_SIZE)));
            let mid = &elf[elf.len() / 2..elf.len() / 2 + 64];
            let hits = img.windows(64).filter(|w| *w == mid).count();
            assert_eq!(
                hits, 1,
                "the bytes of pkg are in boot-base.img {hits} times"
            );
        }
    }

    /// `--without f-stack` leaves out F-Stack and nginx-fast, which links it,
    /// in the programs, in the files of the image and in the memory it needs.
    #[test]
    fn the_image_without_f_stack_holds_neither_f_stack_nor_what_links_it() {
        let image = packages::without_image("f-stack");
        assert_eq!(image, "boot-full-without-f-stack.img");
        let names: Vec<String> = packages::of_image(&image)
            .unwrap()
            .into_iter()
            .map(|p| p.name)
            .collect();
        let full: Vec<String> = packages::of_image(FULL_IMAGE)
            .unwrap()
            .into_iter()
            .map(|p| p.name)
            .collect();
        assert!(!names.iter().any(|n| n == "f-stack" || n == "nginx-fast"));
        assert_eq!(names.len() + 2, full.len());
        assert!(
            names.iter().any(|n| n == "nginx"),
            "nginx without the stack stays"
        );
        assert!(programs(&image).len() < programs(FULL_IMAGE).len());
        assert!(
            !crate::rootfs::files_of(&image)
                .iter()
                .any(|f| f.path.contains("fstack"))
        );
        assert_eq!(machine(&image).memory, "1G");
        assert_eq!(machine(BASE_IMAGE).memory, "512M");
    }

    #[test]
    fn only_an_optional_package_can_be_left_out() {
        let base = packages::of_image(BASE_IMAGE).unwrap().remove(0).name;
        assert!(
            packages::without(packages::load().unwrap(), &base)
                .unwrap_err()
                .contains("base package")
        );
        assert!(
            packages::without(packages::load().unwrap(), "nosuch")
                .unwrap_err()
                .contains("no such package")
        );
        assert!(command(&["base".into(), "--without".into(), "f-stack".into()]).is_err());
        assert!(command(&["full".into(), "--without".into(), "busybox".into()]).is_err());
    }
}
