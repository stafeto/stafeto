# Releases

A release is a tag `v<version>` on a commit of `main`. The tag starts
`.github/workflows/release.yml`, which builds everything on a clean machine
and leaves a draft GitHub release. The owner reads the draft and publishes it.

## How to release

1. Set the version in one place: `version` under `[workspace.package]` in the
   root `Cargo.toml`. `uname -r` of the shell, the kernel crate and the file
   names of the archives take it from there (`cargo xtask ash-dialog` checks
   the `uname -a` line against it). Run `cargo update --workspace` to refresh
   `Cargo.lock`.
2. Merge the change to `main` and wait for a green `ci`.
3. Tag the merge commit and push the tag:

       git tag -a v0.2.0-pre.1 -m "stafeto 0.2.0-pre.1"
       git push origin v0.2.0-pre.1

4. The workflow runs the nine groups of `ci` on the tagged commit (the same
   workflow file, called from `release.yml`), checks that the tag equals
   `v<version>` of the manifest, runs `cargo xtask dist`, checks
   `SHA256SUMS` and creates the draft with `gh release create --draft`
   (with `--prerelease` for a version that has a `-` suffix).
5. Read the notes, trim the Roadmap if it is long, and publish.

`cargo xtask dist` also runs on a developer machine and writes the same files
to `target/dist/`.

## What the release holds

| File | Content |
| --- | --- |
| `stafeto-<version>-aarch64-virt.tar.xz` | `Image`, `boot.img` of the shell image, `run.sh` (TCG by default, `--hvf`, `--cpus N`), `README.md`, `LICENSES/` |
| `stafeto-<version>-kernel.tar.xz` | the kernel `Image` and `kernel.elf` with symbols |
| `stafeto-<version>-gpl-sources.tar.xz` | the original source archives of the GPL packages (URL and SHA-256 from `packages/*.toml`), the stafeto tree at the release commit with `tools/build-*.py`, the patches and compat files, and relibc at its pin (tag `pin-<commit>`) |
| `stafeto-<version>-sbom.spdx.json` | SPDX 2.3: name, version, licence, URL and SHA-256 of stafeto, relibc and every package |
| `SHA256SUMS` | SHA-256 of every file above |

The notes come from `tools/release-notes.py`: the pull requests merged since
the previous `v*` tag and the Roadmap section of `README.md`.

## Versions

SemVer 0.x. The minor number changes at the close of a subproject, and
`0.2.0` is the release that closes subproject 2 (POSIX and services). Before
it, builds carry `-pre.N` (`0.2.0-pre.1`, `0.2.0-pre.2`, ...). Inside 0.x
any minor release may change interfaces; a patch release (`0.2.1`) only
fixes defects.
