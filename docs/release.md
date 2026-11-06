# Releases

A release is a tag `v<version>` on a commit of `main`. The tag starts
`.github/workflows/release.yml`, which builds everything on clean machines and
leaves draft GitHub releases. The owner reads the drafts and publishes them.
Publishing the release of `stafeto/stafeto` is the approval that starts
`.github/workflows/publish-packages.yml`, which publishes the packages.

## How a release goes

1. Set the version in one place: `version` under `[workspace.package]` in the
   root `Cargo.toml`. `uname -r` of the shell, the kernel crate and the file
   names of the archives take it from there. Run `cargo update --workspace`
   to refresh `Cargo.lock`. For a version without a suffix run
   `cargo xtask abi --freeze` too (see "Series and ABI").
2. Merge the change to `main` and wait for a green `ci`.
3. Tag the merge commit and push the tag:

       git tag -a v0.3.0 -m "stafeto 0.3.0"
       git push origin v0.3.0

4. `release.yml` runs four jobs.
   - `ci`: the groups of `ci` on the tagged commit, called with no secret.
   - `build`: no secret and no environment. It checks that the tag equals
     `v<version>`, runs `cargo xtask release-build` (the check of the ABI
     fingerprint, the packages carried from the signed index in the newest release
     of the series when it is published and built otherwise, both boot images, the kernel and the stage
     of `tools/dist.py`) and keeps the result for the next job. It may run for
     up to 120 minutes.
   - `sign`: a clean machine that builds `xtask` alone (with its crates as
     `Cargo.lock` pins them), in the environment `packages`. It holds the
     release key alone. Nothing from the build job reaches a shell of this
     job: `cargo xtask release-check` refuses every file that is not a file of a
     release before the key is written, the version is that of the checkout,
     and the serial of the index is that of the published index of the
     series plus one (1 for a new series), taken after the roots accepted its
     signature. It signs again
     the packages that the build signed with the development key
     (`cargo xtask pkg-sign`), puts the signed files into both boot images
     (`image-repack`), writes the index (`repo --from`), checks the result with
     the roots of the tree (`repo --check --official`) and packs the archives
     (`tools/dist.py pack`). The key is a file with mode 0600 in the runner's
     temporary directory, and a step that always runs removes it.
   - `draft`: in the environment `packages`, it holds the token of
     `stafeto/packages` alone. It makes the draft release `v<version>` in
     `stafeto/stafeto` and, for a version without a suffix, the draft release
     `v<version>-aarch64` in `stafeto/packages` with the new packages and their
     source archives. The carried packages are not copied: their entries point
     into the storage release they came from. A draft with that name that
     exists already stops the job.
5. Read the notes and the files. Trim the Roadmap if it is long. A version
   with a suffix (`0.3.0-pre.1`) makes a pre-release draft and no packages:
   the promise of a series (below) starts with `0.N.0`, and a pre-release may
   still change the ABI.
6. Publish the release of `stafeto/stafeto` (all its files live in `target/stafeto-release`, apart from the `target/release` of cargo). `publish-packages.yml` starts
   from the event: it checks the signed copy of the index in the release,
   checks every attachment of the draft storage release against that index,
   publishes the storage release, tries every address of the index, writes
   the index into the branch `gh-pages` of `stafeto/packages` with a serial
   above the one on the pages, and waits until the pages answer with the same
   bytes and `cargo xtask repo --check --official --remote` passes over the
   network. A release with a suffix, a pre-release and a release with no
   signed index are skipped with a line in the log.

`cargo xtask dist` runs the same code on a developer machine with the
development key and writes the files to `target/dist/`.

## The dry run

Start `release.yml` by hand from `main`:

    gh workflow run release.yml --repo stafeto/stafeto --ref main

It runs the same four jobs with the real key and makes no draft. The files are
in the artifacts `release-input` and `release-signed` of the run for three days.
It proves the secrets, the environment, the signature, the carrying (from the
published index once there is one) and the content of the archives, and leaves
nothing public. Set no tag before a dry run has passed.

## What the release holds

| File | Content |
| --- | --- |
| `stafeto-<version>-aarch64-virt-base.tar.xz` | `Image`, `boot-base.img`, `run.sh`, `README.md`, `LICENSES/` (the notices of the system and, in `LICENSES/packages/<name>/`, those of the packages of the image) |
| `stafeto-<version>-aarch64-virt-full.tar.xz` | the same with `boot-full.img` and `run.sh` that starts the machine with 1024M |
| `stafeto-<version>-kernel.tar.xz` | the kernel `Image` and `kernel.elf` with symbols |
| `stafeto-<version>-gpl-sources.tar.xz` | the original source archives of the GPL packages of both images and of the packages linked into them (URL and SHA-256 from `packages/*.toml`), the stafeto tree at the release commit with `tools/build-*.py`, the patches and compat files, and relibc at its pin (tag `pin-<commit>`) |
| `stafeto-<version>-sbom.spdx.json` | SPDX 2.3: name, version, licence, URL and SHA-256 of stafeto, relibc and every package of both images and of what is linked into them; a package that has a file in the index carries the SHA-256 of its signed `.stpkg` as a second checksum |
| `stafeto-<version>-INDEX`, `stafeto-<version>-INDEX.sig` | the signed index of the packages on the day of the release |
| `SHA256SUMS` | SHA-256 of every file above |

The archive of the shell image `aarch64-virt` is not part of a release any
longer: the base image has the same shell and the package tool. The Linux guest
of the measurement never ships; `tools/dist.py` stops the release if a file of
it is in an archive.

`run.sh` starts QEMU with the screen (`virtio-gpu`), the keyboard, the
network, the entropy device and the disk `store.img` (512 MiB, sparse, made at
the first run). `--hvf`, `--cpus N`, `--memory SIZE`, `--nographic`,
`--fresh-store` and `--print` (the command, one argument per line) are its
keys. The full image refuses less than 1024M: on 512M its container leaves
init 15 837 free pages, under the 16 384 the images keep. A test of `xtask`
compares `run.sh --print` of both archives with the command that `xtask`
builds for the image.

`LICENSES/relibc-THIRD-PARTY-NOTICES` holds the licence texts of relibc and
of every crate from crates.io that a binary the workspace builds for the
target links. `tools/check-licenses.py` writes it; `--verify`, which
`tools/dist.py stage` runs, fails when the file misses one of those crates.
`cargo xtask dist-licenses` checks that the archives carry the notices of the
packages of their images and no others, and that the notices of F-Stack are
only in the packages `f-stack` and `nginx-fast`. The kernel archive, the base archive and
`boot-base.img` carry none of them, and neither does the full image built
without F-Stack (`cargo xtask image full --without f-stack`).

The notes come from `tools/release-notes.py`: the summary written for the
version in `docs/releases/<version>.md` (a short introduction when there is
none), the table of files and a link to the changes since the previous `v*`
tag. Write the summary before tagging: what the release brings, how to try
it, its limits.

## Series and ABI

The series is `major.minor` of the version. The packages of a series run on
every system of that series, so `packages/abi.txt` holds the fingerprint of
what a package can see: the names `libc.so` exports, the layouts and constants
of its headers, the constants of the loader and the versions of the protocols
of the POSIX layer. `cargo xtask abi --check` runs in the job `pkg` of `ci`
and in `release-build`. Its file has the state `open` (the series is not
published: a difference is printed) or `frozen` (a difference fails the check
and asks for a new minor version). `cargo xtask abi --freeze` sets `frozen`
in the request that sets the version of a release without a suffix, and
`release-build` wants a frozen file of the series of the version for such a
release. After `0.N.0` a change that moves the fingerprint raises `main` to
`0.(N+1).0-pre.0` in the same request; a patch release `0.N.P` comes from a
branch `release-0.N` cut at the tag.

The line `<series> <serial>` in `packages/published-serial.txt` records that a
series is published and the serial of its index at that time. `release-build`
carries from the pages when the line is there, builds everything new when
neither the line nor the pages know the series, and stops when the pages list
a series the file does not record. Add the line in the request after the first
publication of a series.

## What the pages and the weekly signature do

`https://stafeto.github.io/packages/<series>/aarch64/` serves `INDEX`,
`INDEX.sig`, `revoked` and `revoked.sig`; the package files are in the storage
releases of `stafeto/packages` and the index names them by address.
`series.txt` lists the series that get a weekly signature. The pages only
deliver: whoever holds `PACKAGES_TOKEN` can write them. The records of a series
are those of the signed index that its newest release in `stafeto/stafeto`
carries (`stafeto-<version>-INDEX` and `.sig`); the carrying of a build and
the weekly signature take them from there, with the roots accepting that
signature. An index lives 30 days, so a signature every Monday at 03:17 UTC
(`cargo xtask repo resign --anchor COPY`) keeps it valid for three weeks past a
missed run. The signing step refuses an index of the pages whose signature the
roots do not accept (its serial is the number the new one follows) or whose
records differ from the copy, so an old signed index laid into the pages is
not signed again, and it refuses to sign with a key that the list names. It
moves nothing but `serial` and `expires`. The job fails, and GitHub mails the
owner, when the certificate of the release key ends in under 35 days, when a
series of `series.txt` has no release that carries an index, or when the pages
cannot be read. Take a series out of `series.txt` to stop its support: its
index runs out 30 days later. A push to `main` that changes `keys/revoked` runs
the job at once, so the new list reaches every series.

GitHub switches off a schedule after 60 days without activity in a public
repository. A frozen schedule shows as an index that expires and a `pkg` that
says so in one line; start the workflow by hand (`workflow_dispatch`) to sign
again. The group `packages-pages` runs one job at a time and keeps one waiting
run: when a run for a release was cancelled by a later one, press "Re-run" on it.

## Before the owner has set anything up

The workflows are safe to merge at any time. `publish-packages.yml` has a job
`gate` with no secret that ends the run green with a line in the log when no
series is published or when the release has a suffix, is a pre-release or holds
no signed index. A pages site that cannot be reached, or one that lists no series
while `packages/published-serial.txt` records one, fails the gate: only the clean
answer "there is no such file" means that nothing is published. Once the gate
says go, an empty `RELEASE_SIGNING_KEY` or `PACKAGES_TOKEN` fails the run. `packages-token.yml` and
the dry run start by hand only. A test of `xtask` reads the text of the
workflows and fails when a secret is named outside its job, when a step of
the publishing job could run before the secrets are known, when an action is not
pinned by the full commit it was read at, or when this file stops asking the
owner for the rulesets below.

## Who may set a tag

The environment `packages` lets in any run on a tag `v*` and on `main`, and anyone
who may write to the repository can set a tag on a commit of their own branch with
a changed `release.yml`. Before any secret goes into the environment the owner makes
two rulesets: tags `v*` that only the owner may create, change or delete (the owner
is the only actor that bypasses the rule), and `main` that takes changes through a
pull request only, with no force push and no deletion. Replace `OWNER_ID` with the
id of the owner (`gh api user --jq .id`); the role "repository admin" is `5`.

    gh api -X POST repos/stafeto/stafeto/rulesets --input - <<'JSON'
    {"name": "release tags", "target": "tag", "enforcement": "active",
     "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
     "rules": [{"type": "creation"}, {"type": "update"}, {"type": "deletion"}],
     "bypass_actors": [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}]}
    JSON
    gh api -X POST repos/stafeto/stafeto/rulesets --input - <<'JSON'
    {"name": "main", "target": "branch", "enforcement": "active",
     "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
     "rules": [{"type": "pull_request", "parameters": {"required_approving_review_count": 0,
       "dismiss_stale_reviews_on_push": false, "require_code_owner_review": false,
       "require_last_push_approval": false, "required_review_thread_resolution": false}},
       {"type": "non_fast_forward"}, {"type": "deletion"}],
     "bypass_actors": []}
    JSON

The agents that work on the repository push branches and open pull requests, and the
coordinator creates tags only on the word of the owner. A leaked token of the owner's
account is out of this model.

## Keys

The root `stafeto-root-N` signs the certificates of the release keys and the
list of revocations, and nothing else. Its private file lives on two encrypted
removable disks, kept apart, and has never been on a machine with a network.
Its public file is `keys/stafeto-root-N.pub`, and `pkgfmt::OFFICIAL_ROOTS`
includes it into `pkg` and `pkgd`. A new root ships only with a new base
system.

The release key `stafeto-release-<year>` has a certificate for 396 days with
the purpose `packages`. The private file lives only in the secret
`RELEASE_SIGNING_KEY` of the environment `packages`; there is no other copy,
and a lost secret is cured with a new key and a new certificate. The tree has
`keys/stafeto-release-<year>.pub`, `.cert`, and `keys/revoked`, `revoked.sig`.
The workflows read the name of the key from the newest certificate in `keys/`.
Each year make a new key with the next year in its name; the old one lives
until its certificate ends, and the packages signed in time stay valid.

Make the keys at one session with the network off:

    cargo --offline xtask keys root stafeto-root-2 --dir /Volumes/ROOT-A
    cargo --offline xtask keys release stafeto-release-2026 --dir ~/.stafeto-release
    cargo --offline xtask keys certify --root /Volumes/ROOT-A/stafeto-root-2.key \
        --key ~/.stafeto-release/stafeto-release-2026.pub --purpose packages
    cargo --offline xtask keys revoke --root /Volumes/ROOT-A/stafeto-root-2.key --init --out ~/public-keys

Copy the root to the second disk and compare the copies with `cmp`. With the
network on again, put the key into the environment and remove the file:

    gh secret set RELEASE_SIGNING_KEY --repo stafeto/stafeto --env packages < ~/.stafeto-release/stafeto-release-2026.key
    rm -r ~/.stafeto-release

and send the public files (`.pub`, `.cert`, `revoked`, `revoked.sig`) in a
request to `keys/`.

**A leaked release key.** Make a new key and certificate offline. Run
`cargo xtask keys revoke --root R.key --key stafeto-release-2026 --since <time>`
with a time a little before the leak (`--since start` when the time is
unknown: every signature of the key falls). Commit the public files and the new
`keys/revoked`, set the new secret. The push of the list runs the signature of
every series with the new key; the records stay those of the signed copy in the
release, which the old key signed in good time, so the series is not locked.
Packages signed after `since` are refused by `pkg`, and the next patch release
builds them again: carrying does not take a package whose key is revoked, and
it takes the other records from the same copy.

**Changing the root.** The root changes only with a new base system: new
`keys/stafeto-root-N.pub`, a new `OFFICIAL_ROOTS`, and a new series.

## The environment and the secrets

The environment `packages` of `stafeto/stafeto` has the deployment rule "`main`
and tags `v*`". The two secrets live there, and the repository has none at its
own level, so a branch of an agent cannot read them. `PACKAGES_TOKEN` is a
fine-grained token for `stafeto/packages` alone with Contents: Read and write,
valid for one year. Make the environment:

    gh api -X PUT repos/stafeto/stafeto/environments/packages -F 'deployment_branch_policy[protected_branches]=false' -F 'deployment_branch_policy[custom_branch_policies]=true'
    gh api -X POST repos/stafeto/stafeto/environments/packages/deployment-branch-policies -f name=main -f type=branch
    gh api -X POST repos/stafeto/stafeto/environments/packages/deployment-branch-policies -f name='v*' -f type=tag

then `gh secret set PACKAGES_TOKEN --repo stafeto/stafeto --env packages`, and
start `packages-token.yml` by hand from `main`: it reads `stafeto/packages`,
makes a draft release there and deletes it, which proves the right to write
and publishes nothing. Renew the token before its year ends and run the check
again. A leaked token lets someone stop the service and nothing more: `pkg`
checks the signature of the index and the SHA-256 and size of each package.

## If the index has expired

The cause is one of three. The schedule was switched off (start
`publish-packages.yml` by hand). The certificate of the release key ended
(make a new key as above, then start the workflow). The token expired (make a
new one, set the secret, start the workflow). The weekly job writes a new
index whose serial is above the old one and whose records are the old ones.

## The limits of GitHub

A file of a release is at most 2 GiB, a repository of pages is advised to stay
under 1 GB, and the pages are served from a content delivery network that
answers a new index a minute or two after the push (the job waits up to ten
minutes). A schedule may start late. The runner `ubuntu-24.04-arm` of the
build gives 120 minutes at most for the job.

## Versions

SemVer 0.x. The minor number changes at the close of a subproject, and
`0.2.0` is the release that closes subproject 2 (POSIX and services). Before
it, builds carry `-pre.N` (`0.2.0-pre.1`, `0.2.0-pre.2`, ...). Inside 0.x
any minor release may change interfaces; a patch release (`0.2.1`) only
fixes defects.

## Images on layers

The images of the shell, the network, the games and the probes hold their packages as package files
(layers of the RAM file service) and keep the files of their table for the system. `boot-base.img`
holds the base packages and `boot-full.img` every package; both are built by `cargo xtask image
base|full [--without PACKAGE]` and are the images of the two archives that run (docs/packages.md,
"Images on layers"). The full image needs 1024M, which the `run.sh` of its archive passes.
