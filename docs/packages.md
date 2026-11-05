# Packages

Every third-party program of the system is a package. A package has one
description file, `packages/<name>.toml`, and the shell image is built from
the list of these files. This is the build-time half of the packages of the
phone OS: the format and the data are in place, and installing into a
running system belongs to subproject 5.

## Format

A description holds strings and lists of strings, one `key = value` each
(the subset of TOML that Rust's xtask and Python's `tomllib` both read).
Unknown keys are refused.

| Key | Meaning |
| --- | --- |
| `name` | The package name; equals the file name. |
| `version` | The pinned version of the source. |
| `kind` | `base` for the packages every system holds, `optional` for the rest (spec 5, 3.3). The words `addon`, `game` and `net` of earlier descriptions are gone. |
| `image` | The probe images the package goes into: `shell` (the shell image and the images built on it), `games` (the games image besides), `net` (the images with the network service) or `fstack` (F-Stack, in the images with the network service and the image of its probe). |
| `release` | The number of the build of this version, a string of digits (`"1"`). |
| `summary` | One line of up to 80 ASCII characters without `"`: what the package is. |
| `url` | The https URL of the source archive, or of the one file that is the source (the root certificates of `ca-bundle`). |
| `sha256` | SHA-256 of the archive, 64 lowercase hex digits. |
| `license` | SPDX expression of the licence. |
| `depends` | The packages it needs when it runs (nano, htop and ncdu need ncurses; doomgeneric needs freedoom). Only packages that have files; a base package depends on base packages only; an optional package never names a base package, the base is always there. |
| `build_depends` | The packages linked into it when it is built (nginx links openssl and pcre2; BusyBox links the ready-made utilities). Their notices go into its own. |
| `provides` | Other names the package answers to (`doom`): no package has that name and no other package gives it. |
| `needs` | What the device must offer: a subset of `display`, `input`, `net`. |
| `notices` | More notice files for `/usr/share/licenses/<name>/`: `"<file name> = target:<path from target/>"` or `"<file name> = tree:<path from the root of the tree>"` (F-Stack's acknowledgements). |
| `build` | The build script, from the workspace root. |
| `program` | The image program its build links, if it has one of its own. |
| `dirs` | Directories only this package needs. |
| `files` | `"<path in the image> = <source>"`, where the source is `elf:<program>`, `terminfo:<entry>`, `bytes:<name>` or `link:<name>`, a symbolic link to a file of its own directory (`/bin/cat = link:busybox`: `ls -l` shows `cat -> busybox`). Several paths may name one program (hard links), and the links to one name share one file of the image. A link must name a file of the image that is no link itself. The list may be empty for a package whose code another package links (musl-fts gives pax its `fts`); some package must then name it in `build_depends`. A link names a file of the package, of a package in its `depends` or of a base package. |
| `license_file` | Optional: the licence file in the source tree, for tools that read it; empty where the files of the source state their terms in their headers (paxmirabilis). |

Example (`packages/nano.toml`):

```toml
name = "nano"
version = "9.2"
kind = "optional"
image = "shell"
release = "1"
summary = "GNU nano text editor"
url = "https://ftp.gnu.org/gnu/nano/nano-9.2.tar.xz"
sha256 = "05ecb99247b782e8a5b3a25ed4101dd034b0236902f7449bc9795b717642f7e9"
license = "GPL-3.0-or-later"
depends = ["ncurses"]
build_depends = ["ncurses"]
build = "tools/build-nano.py"
program = "nano"
files = [
  "/bin/nano = elf:nano",
]
```

The description is the one place for the version, URL and SHA-256. The
scripts of `tools/` read them through `tools/pkgdesc.py`, and xtask reads
them for the licence notes of the image.

## What xtask does

- The shell image (`boot-ash-dialog.img`) holds the base set and the add-ons.
  Its files and its programs come from the descriptions. The probe images list
  the few files they use and hold no package, so they get no add-on.
- `cargo xtask packages` checks the descriptions: a missing SHA-256, licence,
  version, URL, release, summary or build script, a package without files that
  no package links in, a file that two packages claim, an unknown name in
  `depends`, `build_depends` or `provides`, a runtime dependency on a package
  without files, a dependency that breaks the rules of kinds and images, a
  link to a file of a stranger and a cycle in either list each stop it.
  It also checks that every file of the shell image belongs to exactly one
  package or to the base system (init and the services: `SYSTEM_PATHS` in
  `xtask/src/rootfs.rs`), and that every link names a file of its directory
  in the image. `/bin` holds the programs of the packages; the RAM service
  and the test program `login-probe` are in `/libexec`. `cargo xtask ci` runs this check first.
- `cargo xtask packages table` builds the image and prints a table with the
  name, version, licence, kind, number of files and bytes of each package.
  A program that several paths name counts once, for the first package that
  names it, so the packages linked into BusyBox (sbase, toybox, ncompress, chimerautils,
  nbase, paxmirabilis, util-linux) show 0 bytes (their names are links to `busybox`;
  so are the `tput` and `tabs` of ncurses). It then builds `boot-net.img` and
  prints its table, the network packages among the rows. `cargo xtask
  ash-dialog` prints the table of the shell image.
- The games image (`boot-doom.img`) holds the shell image's packages and the
  games: Doomgeneric (`/bin/doom`, GPL-2.0-or-later) and the Freedoom data
  (`/games/freedoom1.wad`, BSD-3-Clause). The shell image holds no game.
  `cargo xtask doom-headless [MACHINE]` builds the games image and plays the
  demo of Freedoom from ash without a screen (`doom -iwad /games/freedoom1.wad
  -timedemo demo1 -nodraw`). The image carries the licence texts and the notes
  of the sources (`DOOM-LICENSE`, `DOOM-SOURCE`, `FREEDOOM-LICENSE`,
  `FREEDOOM-SOURCE`), and the check of the image compares the WAD with the
  one the build script unpacked.
- F-Stack (`packages/f-stack.toml`, the TCP/IP stack of FreeBSD 15 in user
  space, BSD-2-Clause and BSD-3-Clause with files under BSD-4-Clause,
  RSA-MD, Beerware, MIT-CMU, ISC and MIT) is an optional package of the image kind `fstack` that installs only its
  settings, `/etc/fstack.ini`. `tools/build-fstack.py` builds its library
  `libfstack.a` from the pinned commit with `ports/f-stack` (the patch and
  the host layer of stafeto in place of DPDK) and joins it with the probe
  of `tests/fstack-probe`; `cargo xtask fstack-probe` runs the stack on its
  own loopback in the image `boot-fstack-probe.img`, and `cargo xtask
  fstack-probe device` runs it on the second network device the program
  claims (`libvirtio_net.a`, the images `boot-fstack-device.img` and its
  variants with the shell and the network service); the images carry
  F-Stack's licence and the acknowledgements its four-clause files and its
  MD5 ask for (`FSTACK-LICENSE`, `FSTACK-SOURCE`). The installed headers are
  those of the build without thread-local storage: `ff_api.h` declares
  `pcurthread` a plain variable.
- nginx on the stack (`packages/nginx-fast.toml`, an optional package of the image kind
  `fstack`, BSD-2-Clause) links the object of the package `nginx` with
  `libfstack.a`, the device's driver and the glue of `ports/f-stack` into
  `/bin/nginx-fast` (`tools/build-libc-so.py programs`; `-z nostart-stop-gc`
  keeps the sets of the stack, `-z stack-size=1048576` gives it a main stack
  of 1 MiB) and installs `/etc/nginx/nginx-fast.conf`. It needs the network
  and the second device, so only the images with both devices hold it
  (`boot-fast-nginx.img` and its variants, `Package::needs_network_device`).
  Its `build_depends` are f-stack, openssl and pcre2, so its notice directory
  holds F-Stack's (`/usr/share/licenses/nginx-fast/f-stack/`, with the file
  `NOTICES` of the copyright lines and terms of the files the stack's build
  compiled, which `tools/build-fstack.py` writes). F-Stack's notices are in
  these two packages in the distribution: the kernel archive and the archive of
  the shell image carry none of them (`cargo xtask dist-licenses` checks it).
  The probe images that hold the stack (`fstack-probe`, `fast-layer`,
  `nginx-fast`) carry the same notices at the level of the image, in
  `FSTACK-LICENSE`.
  `cargo xtask fast-probe nginx` runs the pages over HTTP and HTTPS, a reload
  under load, a worker killed, the quit and the worker under nobody; with
  `crash` the network service ends under requests; with `steps` the service
  counts its steps; `cargo xtask net-vz --fast --static1 --nginx` runs it on
  Apple VZ with `wrk`.
- The images with the network service (`boot-net.img` of `cargo xtask net`,
  the images of the network probes) hold the shell image's packages and the
  network packages: OpenSSL 3.5.9 (`/bin/openssl`, Apache-2.0), curl 8.23.0
  (`/bin/curl`, curl) and `ca-bundle`, the root certificates of Mozilla
  (`/etc/ssl/certs/ca-certificates.crt`, MPL-2.0). OpenSSL is built into the
  static archives `libcrypto.a` and `libssl.a`, which curl and `openssl` link
  (the loader opens no library beside libc.so). The source of `ca-bundle` is
  one PEM file put in the image unchanged; the release takes its notice from
  the header of the file and the text of MPL-2.0 from
  `tools/ca-bundle/MPL-2.0.txt`. The images carry the licences and the notes
  of the sources (`OPENSSL-LICENSE`, `OPENSSL-SOURCE`, `CURL-LICENSE`,
  `CURL-SOURCE`, `CA-BUNDLE-LICENSE`, `CA-BUNDLE-SOURCE`). The images of the
  probe of TLS (`cargo xtask net-tls`) replace the bytes of the CA file with
  the same roots plus the probe CA of `cargo xtask probe-ca`.
- nginx 1.30.6 (`/bin/nginx`, BSD-2-Clause, with `/etc/nginx/mime.types` and
  `/etc/nginx/nginx.conf`) and PCRE2 10.49 (BSD-3-Clause with the PCRE2
  exception, linked into nginx, no file of its own) are network packages
  too. An image with nginx carries `NGINX-LICENSE`, `NGINX-SOURCE`,
  `PCRE2-LICENCE` and `PCRE2-SOURCE`. nginx's `configure` runs its probes for
  the target through `tools/nginx/cross-autotest.patch` and
  `tools/nginx/autotest-answer.py`, which answers sizes from the compiler and
  every other run-probe from a table with a reason; a probe it does not know
  stops the build. nginx has the modules of TLS and HTTP/2
  (`--with-http_ssl_module --with-http_v2_module`) and links OpenSSL's static
  archives (`depends` names `openssl`); `nginx -V` lists both modules. The
  package's `nginx.conf` serves HTTP on port 80 alone: a server of TLS needs
  a key and a certificate, which no image of a release carries.
  `tools/nginx/tls.conf` is such a server (port 443, `http2 on`,
  `ssl_protocols TLSv1.3`); it goes, with nginx's key and certificate from
  the probe CA, only into the images of `cargo xtask nginx-probe`
  (`boot-nginx-probe.img` and `boot-nginx-probe-steps.img`), whose settings
  include it. It speaks TLS 1.3 alone, with OpenSSL's default suites of TLS
  1.3; settings that add TLS 1.2 get nginx's default `ssl_ciphers`
  (`HIGH:!aNULL:!MD5`), which still holds the exchange of keys by RSA and
  the CBC mode, and should name `ssl_ciphers`.
- The build scripts of the packages run in build order: the base first, each
  package after the packages it links in (`build_depends`). The build groups
  follow from `kind` and `image`: base and shell, optional and shell,
  F-Stack, games, network.

## Package files and keys

The library `lib/pkgfmt` reads and writes the package file `.stpkg` and what
surrounds it. Reading needs no allocator, so a program on the device can use
it; the writers and the checks that hash whole packages are behind the
feature `write`.

### The package file

A container with the layout of the boot image (a 16-byte header, a table of
48-byte entries, files at 4 KiB boundaries, zeros to the end of the last
page), signature `STAFPKG1`, version 1, read by
`bootimg::BootImage::parse_as(bytes, &pkgfmt::PACKAGE)`. Then one trailer page.

| Part | Content |
|---|---|
| file 0 `meta` | text, at most 4 KiB: the keys `name version release arch series license depends provides needs summary url sha256 recipe commit relibc size`, one `key value` line each, in this order; a list with no members is `-` |
| file 1 `rootfs` | a `STAFROOT` version 2 table; its file numbers are the numbers of the container's files |
| file 2 `manifest` | one line per entry of `rootfs`, in its order: `<sha256 or -> <size> <mode, 6 octal digits> <elf or -> <path>` |
| files 3.. | the contents, each named by its number in decimal digits |
| trailer | 4 096 bytes: the signature block (456 bytes) and zeros |

`Package::parse` checks, each rule with its own error: whole pages and a
trailer that covers everything before it; the file names above; no page after
the last file; at most 1 024 entries; every content file referenced by an
entry; owner 0:0 and no set-ID, set-GID or sticky bit; `meta` and `manifest`
in their strict form, the manifest agreeing with the table in path, mode, size
and the `elf` mark; `size` in `meta` equal to the length of the content files.
`Package::check_policy(name)` adds the rules of official packages: the files
`/usr/share/licenses/<name>/LICENSE` and `SOURCE` exist and nothing else lies
under `/usr/share/licenses/` outside that directory. `Manifest::check`
(feature `write`) hashes every file and compares.

### Signatures

One block, `STAFSIG1`, signs three kinds of data: a package (kind 1), an index
(2) and a revocation list (3).

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | `STAFSIG1` |
| 8 | 4 | version = 1 |
| 12 | 4 | kind |
| 16 | 8 | `covered`: the length of the signed bytes |
| 24 | 32 | SHA-256 of the signed bytes |
| 56 | 8 | time of signing, seconds UTC |
| 64 | 64 | key name: a length byte, 1 to 63 bytes of `[a-z0-9-]`, zeros |
| 128 | 64 | Ed25519 signature |
| 192 | 4 | length of the certificate: 0 or 256 |
| 196 | 4 | zeros |
| 200 | 256 | the certificate or zeros |

The signature covers `stafeto signature v1` and a zero byte, then bytes 8 to
128 of the block. The kind, the length, the hash, the time and the key name are
therefore all signed, and the signature of an index cannot serve as one of a
package. `INDEX.sig` is a block of kind 2 over `INDEX`; `revoked.sig` is a
block of kind 3 signed by a root directly.

The certificate `STAFCRT1` (256 bytes) lets a root vouch for a release key:

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | `STAFCRT1` |
| 8 | 4 | version = 1 |
| 12 | 4 | purposes: bit 0 `packages`, bit 1 `elf` |
| 16 | 64 | key name |
| 80 | 32 | public key |
| 112 | 8 | start of the term, seconds UTC |
| 120 | 8 | end of the term |
| 128 | 64 | name of the issuing root |
| 192 | 64 | the root's signature over `stafeto certificate v1`, a zero byte and bytes 0 to 192 |

`trust::verify(block, kind, digest, covered, trust, revoked)` checks in this
order: kind (`WrongKind`), length (`LengthMismatch`), hash (`BadHash`). Without
a certificate the key must be in `trust.roots` (revocation lists) or
`trust.direct` (packages and indexes of a repository the owner added);
otherwise `UnknownKey`. With a certificate (kinds 1 and 2) its issuer must be
in `roots` with a valid signature and the block's key name (`BadCertificate`),
the `packages` purpose must be set (`WrongPurpose`) and the time of signing
must lie in the term (`OutsideCertificate`). A key named in the revocation
list is refused (`Revoked`) when the block was signed at or after the entry's
time; the clock of the device takes no part. Last the Ed25519 signature is
checked (`BadSignature`). The official repository trusts the roots of
`keys/*.pub` (`pkgfmt::OFFICIAL_ROOTS`) and no direct key.

### Index and revocation list

`INDEX` is a header (`format 1`, `repository`, `series`, `arch`, `serial`,
`expires`), an empty line, then entries separated by one empty line, names
ascending. The fields of an entry come in the order `name version [provides]
[depends] [needs] license size sha256 recipe file [source] summary`. `revoked`
is `format 1`, `serial N` and zero or more `revoke <key name> <time>` lines,
names ascending. Times are `YYYY-MM-DDThh:mm:ssZ`. Both parsers are strict and
name the line of a mistake (`BadIndex(n)`, `BadRevoked(n)`); the writers read
their own output back.

### Keys

A public key is one line, `ed25519 <base64 of 32 bytes> <name>`, in a file
`<name>.pub`; `keys/stafeto-root-1.pub` is the official root. A private key is
an unencrypted PKCS#8 version 1 Ed25519 key in PEM, in `<name>.key` with mode
0600 (the shape `openssl genpkey -algorithm ed25519` writes). A certificate is
the 256 bytes above in `<name>.cert`.

| Command | What |
|---|---|
| `cargo xtask keys root <name> [--dir D]` | a new root key pair, the name `...-root` or `...-root-N`; the private file is created with mode 0600 and never overwritten; only the public line is printed; `D` defaults to `$HOME/.stafeto-keys` |
| `cargo xtask keys release <name> [--dir D]` | the same for a release key, `...-release` or `...-release-YYYY` |
| `cargo xtask keys certify --root R.key --key K.pub [--purpose packages[,elf]] [--from YYYY-MM-DD] [--days N] [--out F]` | the certificate of `K` by the root `R`: purpose `packages`, start today at 00:00 UTC, 396 days, next to `K.pub` by default; the root must match `keys/<root name>.pub` when that file exists |
| `cargo xtask keys show <file>` | what a `.pub`, `.cert`, `.sig` or `.stpkg` file says; it never opens a `.key` file |

A private key is never written into the working tree outside `target/keys/`
(the directory of development keys): `--dir` inside the tree elsewhere is
refused.

### Notices in the package

Every package carries `/usr/share/licenses/<name>/`: `LICENSE` (the licence
text from the outputs of its build, `xtask/src/notices.rs`), `SOURCE` (name,
version, licence, source URL and SHA-256, the script and the commit that built
it, the recipe, the packages linked into it with their versions and licences,
the pin of relibc for a package with programs, and the source archive when it
has one), the files of `notices`, and for each package in `build_depends` a
directory of that name with its `LICENSE` and notices. No path under
`/usr/share/licenses/` belongs to another package's name. The notice files of
the images (`BUSYBOX-LICENSE` and the others) take their licence text from the
same function and are the same bytes as before.

### The recipe

`meta` and the index carry `recipe`, the SHA-256 of the sorted lines
`file <path> <sha256>` (the description of the package and of those built by
the same script; the script, the `tools/*.py` files it names, the files under
`tools/<base>/` for every loaded `tools/build-<base>.py` and under
`ports/<name>/`), `data <path> <sha256>` (every file of the package that is
no program), `tool clang <version>`, `pin relibc <commit>` and the scripts that
link programs (for a package with programs) and `build-depends <name>
<recipe>` for each package linked in. `cargo xtask pkg-build --recipe
<name>` prints the lines.

### Building packages

- `cargo xtask pkg-build [name...] [--key K.key --cert K.cert] [--time SECONDS]
  [--out D] [--recipe]` builds what the packages need and writes
  `target/pkg/<name>-<version>-<release>.stpkg` (the version is cut to its
  first eight digits when it is a commit). The programs are the stripped ELF
  files the images hold, so the bytes are the same. The table `rootfs` has the
  time `SOURCE_DATE_EPOCH` or the time of the commit, so a package builds
  again to the same bytes. A package is read back by the code that reads it
  on the device and passes the policy before it is moved to its place. The
  development keys of `target/keys/` sign (`keys.rs`); the signature block
  holds the certificate of `stafeto-dev-release` from `stafeto-dev-root`.
- `cargo xtask repo [--serial N] [--expires-days D] [--no-sources]
  [--key K.key --cert K.cert] [--dir D] [--check]` builds all packages and lays out
  `target/repo/<series>/aarch64/` (or `D`, which must be new, empty or under `target/`: `repo` deletes only what it made there): the packages, `INDEX` and `INDEX.sig`,
  `revoked` and `revoked.sig` (an empty list signed by the development
  root) and `src/`. An index lives 30 days at most. A package whose licence,
  or the licence of a package linked into it, is a GPL licence gets
  `src/<name>-<version>-<release>-src.tar.xz`
  (`tools/pkg-source.py`): the source archives of the package and of what is
  linked into it as their SHA-256 sums pin them, the files of the tree that the
  recipe names, and a README. `--check` verifies a directory: the signatures,
  the size and SHA-256 and `meta` of every package, the policy, the sources.
- `cargo xtask pkg-identity` checks that the shell, games and network images
  and the packages give the same bytes, modes and owners at the same paths
  (the notices excepted), that the repository is whole and that
  two builds of a package agree but for the time and the signature of the
  trailer. `cargo xtask dist-licenses` builds the release files and the
  repository and checks that the archive of `aarch64-virt` carries the notices
  of the packages of the shell image and no others, that no archive without
  F-Stack holds a mark of F-Stack's notices and that the GPL packages come
  with their sources. `cargo xtask pkg-ci` runs the four commands in a row;
  it is the job `pkg` of the CI.

## Add a package

1. Write the build script in `tools/`, with the version, URL and SHA-256 taken
   from `tools/pkgdesc.py` (`pkgdesc.load("<name>")`).
2. Write `packages/<name>.toml` with the keys above.
3. If the package has a program of its own, add its build (stack size and
   features) to `PACKAGE_PROGRAMS` in `xtask/src/main.rs`.
4. Run `cargo xtask packages`, then `cargo xtask packages table`.

## Layers in the RAM file service

A package file shows its table `rootfs` as names of the tree of the RAM file service, a layer.
Attaching and detaching go through the layer session (`proto_fs::LAYERS`), which init gives to
the one client of `table::LAYER_CLIENTS` that asks for the name `ramfs/layers`. The session
carries `LayerStart` (method 51, with the operation, the layer number and the level the mapping
thread works at) and `LayerStep` (method 53) and nothing else; any other session that sends
them gets PERMISSION. Protocol version 20 adds the codes `CONFLICT` (a path is taken),
`BAD_LAYER` (the table or the container breaks a rule) and `BAD_MODE` (a set-ID, set-GID or
sticky bit, or an owner other than 0:0); the answer names the entry of the table.

An attach takes two descriptors, a memory object with read access and no write access and a
channel with NOTIFY, and runs in phases of bounded steps: the mapping (a thread of the service
maps the object, so no other client waits for it), the check of the table without any visible
change, and the insertion of the names, with a rollback on a conflict. A detach takes the names
out in the opposite order. A file that is still open, or a program that is loading, holds its
place: the open file reads to the end (it behaves as a deleted open file, `st_nlink` 0), and the
layer is unmapped and its client told with `notify(channel, 1)` only when the last holder has
let go. The names and the attributes of a layer are read-only (EROFS); a directory a layer
brings takes files of users, and a directory whose path exists is merged without changing it.

The object of a layer is the client's: the service reads the names and the bytes of files from it each time they are looked at. The check phase copies into the service everything the insertion needs (kinds, modes, file numbers, offsets and lengths, the bucket of each name), so what the client writes to its object after the check changes no mode, no length and no chain of the service. A client that writes into its object between the attach and the notification of the release can only make the names and the bytes of its own layer say something else, and the rule is that it does not. The object must have pages of its own (the window of a device is refused), a link has a target of 1 to 511 bytes without a NUL, and the content of an entry is never one of the package's own files. The tables the kernel prepays for the mappings of the layers are bounded by 160 pages of the quota of the service (2 MiB of a mapping take a page, and a window two more): the service answers NO_SPACE beyond them. One session of the layer client runs a job; another session of it gets BUSY, and the leaving of a session ends only its own job.

The limits: 64 layers, 4 096 entries in all layers, 1 024 in one, 256 directories that layers
create and no other name had. A step takes at most 16 entries of the check (512 bytes of
paths), 4 of the insertion (256 bytes of names, 1 link of a name chain) and 8 of the detach
(256 bytes of names); `cargo xtask layer-probe steps` checks that the longest step of the
service stays under 0.9 B and the longest layer step under 0.8 B on layers with paths of 511
bytes, names of 255 bytes in one bucket and 1 023 short names. The files of the boot image that
end in `.stpkg` are attached before the service registers, as layers 0x8000 and up that cannot
be detached.

## Images on layers

The packages of an image are files of its container, `<name>-<version>-<release>.stpkg`, the files
of `target/pkg/` that the repository of the same run is made of (a run of xtask builds each
package once, so the image, the index and `pkg-identity` see the same bytes). The table `rootfs`
of the image holds the paths of the system alone, the directories above them and the notices of the
system under `/usr/share/licenses/stafeto/` (the licences of the tree, `relibc-THIRD-PARTY-NOTICES`,
which is the file `THIRD-PARTY-NOTICES` of the container, and `crates/`). `rootfs::layered` splits
the list of an image in the table and the packages; a test checks that the two make the list.
`cargo xtask image-listing` writes the tree an image shows (path, mode, owner, SHA-256 of the
content, table and layers merged), so that two builds can be compared.

The name of a package file in a container is at most 32 bytes (`<name>-<version>-<release>.stpkg`);
a longer name stops the build of the image.

A probe that changes the bytes of a path of a package (the settings of nginx and nginx on the
stack, the CA file with the probe's authority in the image of the probe of TLS) gets a variant of
the package file, built for that image into `target/pkg/variants/<image>/` with the development key;
the variants go to no repository. A variant keeps the name, the version and the signature fields of
the package it varies, so it is only for the images of probes: the package service must not take one
for a release. A program that only a package names has no ELF file of its own
in the image, and the files of notices that an image holds for a program of its table
(`BUSYBOX-LICENSE`, `BASH-LICENSE` and the like) stay only where the table names the program;
`notices::image_has_package_notices` checks both cases. The files of a package carry the time of its
package file; a file of a package takes no new name (a hard link to it is EROFS).

`cargo xtask image base` builds `boot-base.img` (the ten base packages) and `cargo xtask image full`
`boot-full.img` (every package with files), both on `table-base` (the games table with the network
service) and on a machine with the network, the screen and the keyboard; `run` boots one in QEMU.
`cargo xtask pkg-identity` checks that each package file of both images is, byte for byte, the file
of the index, that their tables hold no path of a package, and that both boot: `ls -l /bin/doom`
and the text of the licence of freedoom in the full image, no `/bin/doom` in the base image, the
directories of `/usr/share/licenses`, the services of the screen and the keys, and no `not
attached` line of the service (every run of QEMU fails on that line, `qemu::Run`). The notices of
every package are checked whole in its package file (the licences of the packages linked into it
too, `pcre2` and `musl-fts` among them), and the container of an image holds no file of F-Stack's
notices. The full image runs on 1 GiB: on 512 MiB its container of 54 MB leaves init 15 837 free
pages, under the 16 384 that `pkg-identity` keeps (the line `init: free pages` after `init:
services started`); on 1 GiB and for the base image on 512 MiB the numbers are in the report of the
stage. Whoever starts the full image, `run.sh` of its archive among them (stage 5 of subproject 5),
passes `-m 1024`.

## The disk service

The packages of a running system live on a disk. `services/virtio-blk` (the
service `blk`) reads, writes and flushes the Virtio block device of QEMU's
`virt` machine for its clients; `proto/blk` (MIT) is its protocol. On VZ the
service is not built yet.

**Where the disk is.** `qemu::store` (`xtask/src/qemu.rs`) attaches a
`virtio-blk-pci` over a raw file at device 1 of bus 0, modern interface only,
INTx only, `cache=writeback`, `werror=report,rerror=report`. With
`highmem-ecam=off` (on every machine of xtask and in `tools/dist/run.sh`) the
function is at 0x3f00_8000, and its INTA is line 36. No firmware runs under
`-kernel`, so the driver measures BAR 4 (16 KiB), puts it at 0x1000_0000 and
turns decoding on (`virtio_pci::qemu`, `virtio_pci::Bar64`); only after the
reset of the device does it turn bus mastering on. Init gives the record
`blk` (`services/init/src/table/pkg.rs`) the windows `ecam` and `bar`, the
binding `irq` and one DMA object of 32 pages, uncached, and resets the device
itself when an instance ends. The service runs at level 39, above its client
`pkgd`, whose ceiling stays at 38 or less.

**The protocol.** The client makes a memory object of 64 KiB, gives it with
BUFFER (the service maps it for the session's life; one session holds it at
a time) and uses it as four cells of 16 KiB. READ and WRITE name a cell, a
count of 1 to 32 sectors of 512 bytes and a first sector; FLUSH names
nothing. Each answers WAIT k at once, and the device's interrupt brings the
result: the client takes it with TAKE k (READY, ARMED with a handle that
gets a notification, or the refusal `IO`), or drops it with CANCEL k. A cell
is busy from WAIT to TAKE; up to four reads and writes and one flush are
with the device at once. A WRITE is copied out of its cell before WAIT, and
a READ is copied into its cell when TAKE says READY, one copy of 16 KiB at
most in a step. The codes are `RANGE` 1101, `IO` 1102, `UNSUPPORTED` 1103,
`READ_ONLY` 1104, `INVALID` 1105, `NO_BUFFER` 1106, `EXISTS` 1107 and `BUSY`
1108, besides the codes of the wire.

**What FLUSH means.** A WRITE that says READY says that the device took the
data, which may lie in its cache until a power loss. A FLUSH that says READY
says that the device answered OK to a flush, and every write that had its
answer before the service took the FLUSH is on the medium (Virtio 1.2,
5.2.6). The service keeps the order: a FLUSH is refused with `BUSY` while a
write is with the device, and a WRITE while a flush is. A client that must
survive a power loss writes all its data, takes every WRITE, flushes, takes
the FLUSH, and only then writes the next step. A disk without the flush
feature has the flag cleared in INFO and answers `UNSUPPORTED` to FLUSH; a
client that needs durability refuses to write there. The host side must pass
the flush on: `cache=unsafe` swallows it, and the VZ block device needs
`synchronizationMode: .full` for the same reason.

**Running it.** `cargo xtask blk-probe [--hvf]` runs the probe (`tests/blk-probe`) in
three runs of the machine: a pattern of 4 MiB and the last 32 sectors of a
disk of 64 MiB written, flushed and marked; the same file read again after a
new start of QEMU and a restart of the service (CRASH); and the errors of the
host's `blkdebug` (the first flush and the first read of sector 4096 fail)
reaching the client, with a throttle that holds the third write for a second so
that a FLUSH meets a write at the device. Under `-icount` the service prints each new longest step
of its loop, and no kind may pass 18,369 ticks, 0.9 of term B. The jobs of the
CI are `blk-probe`, `blk-probe GICv3` and `blk-faults`.
`cargo xtask run --store` attaches the file `target/store-<image>.img`
(512 MiB, sparse) to the image it boots, and `--fresh-store` makes it new;
only an image whose table has the record `blk` uses it.

## The package service

`services/pkgd` (the service `pkgd`) keeps the packages of a running system on the disk and attaches
them to the RAM file service as layers; `proto/pkg` (MIT) is its protocol. The service starts from
the disk, receives packages, and changes the store with the methods INSTALL_BEGIN, FEED,
INSTALL_COMMIT, INSTALL_CANCEL, REMOVE, SETTINGS_SET, SERIAL_SET and REVOKED_SET.

**Two threads.** The main thread (level 32) is the loop of a service and answers its clients in
steps of a few thousand ticks: the reads (LIST, INFO, SETTINGS_GET, SERIAL, STATUS), CLONE and
BUFFER, the copy of 16 KiB that a FEED brings, and the start and the result (TAKE) of each change
of the store, which is a long operation. The worker thread (level 30, round robin) takes everything
long: it reads the store through the disk service, creates and maps the object of each package,
hashes it as the bytes arrive (SHA-256 in software takes some 690,000 ticks for 16 KiB under `-icount`, so no step
could hold a portion), checks the signature and attaches the object as a layer, and runs the
transactions below. STATUS says `starting` until the worker has read the disk; LIST and INFO show
the packages it has published meanwhile. The main thread gives the worker one job at a time (a
cell with the arguments, a state, a code and a value, and a notification each way). The worker
changes the table, the entries and the blobs the main thread reads only inside a change of the
state (a sequence count that is odd meanwhile), and a read that meets a change, on one CPU or on two, gets `BUSY`. The service never restarts: its layers stay in the
file service when it ends.

**The store.** The whole disk, in blocks of 4 KiB. Blocks 0 and 1 are the two copies of the
superblock (`STAFSTOR`, version 1, the generation, where the table is and its SHA-256, and the
SHA-256 of the superblock itself). The table (`STAFTBL1`, 20,480 bytes, five blocks) has 66 records
of 256 bytes (64 places of packages, one of the settings blob, one of the list of revocations) and
16 repositories with their serials; each record names an extent of the disk, the SHA-256 of its
file, the name and the version. The table is written whole into a free extent, then a superblock
with the next generation goes into the copy that holds the lower one, each followed by a flush;
at a start the good copy with the higher generation wins, so the store is the whole old state or
the whole new one, and the free space is the disk less the extents of the table found. Both
superblocks zero: the service formats the disk (`pkgd: store formatted`); neither good and the disk
not zero: `pkgd: store damaged, no package from the disk`.

**At a start** the worker reads the settings blob and attaches the layer it makes (`/etc`,
`/etc/pkg`, `/etc/pkg/keys`, `repositories`, `keys/<name>.pub`, mode 0644 for the files, as the
file service wants the directory above each entry listed), reads the list of revocations (text,
then the block of a root's signature) and then each package: object created, bytes read four cells
in flight and hashed, the SHA-256 of the file against the table's, `Package::parse`, name, version
and series against the record, the signature against the trust of its repository (the roots of
the build for `stafeto`; for a repository of the owner only the key of his `keys/<repository>.pub`)
and the list, then the attach. A package that fails gets a line (`pkgd: broken: bad signature,
skipped`) and the service goes on. The roots of a development build come from the file named in
`STAFETO_PKG_ROOTS` (xtask gives the root of `target/keys`); otherwise they are
`pkgfmt::OFFICIAL_ROOTS`.

**Changing the store.** Every method that changes it (INSTALL_BEGIN, REMOVE, SETTINGS_SET,
SERIAL_SET, REVOKED_SET) brings a copy of the identity session of the calling process; the service
has the process service vouch for it (`Vouch`, over a notary session it asks `init` for at the
first use) and refuses with `NOT_ALLOWED` unless the effective user is 0, or when the session is
missing or refused. The calls that follow an INSTALL_BEGIN (FEED, INSTALL_COMMIT, INSTALL_CANCEL)
belong to the session that began it and do not ask again. The reply is `DAMAGED` for a damaged
store and `NO_FLUSH` for a disk that cannot flush, and `BUSY` while another session holds the store
or the worker has a job.

*Receiving a package.* INSTALL_BEGIN gives the record of the index (name, version, size, SHA-256),
the repository (which the table must know: the official one always, the others once SERIAL_SET
gave them a place) and the flag for the world. The worker takes the first free place of the table,
the first free extent of the disk that clears the table, the extents of the group so far and the
next table, and creates and maps an object of the size. The long operation ends with the number of
the receipt. FEED names a cell of the client's buffer and a length; the main thread copies the
bytes into the object after those that came and counts them, and the worker hashes the object (in
portions of 16 KiB, taking the SHA-256 of the covered part at the page where it ends, whatever the
sizes of the pieces) and writes whole blocks to the extent. A FEED past the size is `TOO_LONG` and
the receipt goes. INSTALL_COMMIT waits for all of it, then checks, in the order of the codes: the
SHA-256 of the file against the index (`BAD_HASH`), the layout, the name and the version
(`BAD_PACKAGE`), the series (`WRONG_SERIES`), the signature against the trust of the repository and
the list of revocations (`UNTRUSTED_KEY`, `REVOKED`, `BAD_SIGNATURE`) and the SHA-256 of each file
against the manifest (`BAD_MANIFEST`; the check of a start from the disk leaves this one out, the
signature covers the manifest and the bytes). Without the flag "end of the group" the package is
flushed and waits; with it the group becomes the state. A refusal drops the whole group: the
objects close and the extents are free, since only the table holds an extent.

*The transaction* (`commit::transact`, one plan for all kinds): the data are flushed (F1); the
next table goes into a free extent and is flushed (F2); then, for an installation or new
settings, the layers of the replaced packages detach and the new ones attach (a refusal of the
file service, `CONFLICT` with the number of the entry, undoes them in reverse order and brings the
detached ones back, and the old state is still the store's, with nothing to write over); then the
superblock goes into the copy that holds the lower generation and is flushed (F3); a failed write
of it takes the layers back and answers `IO`. A removal and a list of revocations write the
superblock before they detach, since the bytes of the packages are in memory and the disk no
longer matters to them. A serial changes the table alone. `SERIAL_SET` below the held number is
`ROLLBACK`, equal changes nothing; a list of revocations below the held serial is `ROLLBACK`, one
without a root's signature `BAD_SIGNATURE`; REMOVE answers `IN_IMAGE`, `NOT_FOUND` or
`NEEDED_BY`; SETTINGS_SET answers `INVALID` for a blob that breaks the rules (`proto/pkg`, the
blob; `settings.rs`), and the blob is the truth about the keys of the owner's repositories whether
its layer attached or not. SETTINGS_GET carries the generation of the store in each reply, and a
client that reads a blob of several parts starts again when it changes.

*Crash points.* A build with the feature `crash` and `STAFETO_PKGD_CRASH_AT=N` stops for good at
the point `N` of `commit::Point` after the line `pkgd: crash point N <name>`: `begin`, `data`,
`data-flushed`, `table-part`, `table-flushed`, `attached`, `super-torn` (the write of the superblock
is torn inside its first sector: 64 bytes of it reach the disk, which its checksum refuses),
`super-written`, `committed`, `remove-table`, `remove-committed`, `settings-table`, `format-table`.
The same plan runs in the host tests over a model of the disk that loses what was not flushed
(all, none, or any subset of the pending writes, and a write of the superblock torn at 512
bytes), with a crash after every write and every flush of every kind of transaction: the store at
the next start is the whole old state or the whole new one, the data of the new one are whole,
and the free space is the disk less the extents of the table found.

**Running it.** `cargo xtask store-probe` writes a store on the host with the service's own writer
(`pkgd::host`, feature `host`): `hello`, whose program exits with 42, a copy `broken` with a byte
changed after the signing, `revoked` (signed by a second development release key, which the list
names), the settings with the repository `games` and its key, and the list. The service must attach
`hello` and the settings and skip the other two; the probe (`tests/store-probe`) looks at the
answers and at the tree, and runs the program. A second run on a disk of zeros checks the format.
`cargo xtask store-probe steps` adds `big` (16 MiB) and `wide` (1,000 files in a directory) and measures the steps
under `-icount`: no step of the package service, the disk service or the file service's layer calls
passes 18,369 ticks while the worker creates, maps, hashes and attaches.

The full scenario runs on a disk of zeros (the image holds the packages and the blobs under
`/test/packages/`, with an index the probe reads): `hello`, signed by the development key, is
installed, attached and run; each refusal (`BAD_SIGNATURE`, `UNTRUSTED_KEY`, `WRONG_SERIES`,
`BAD_MANIFEST`, `CONFLICT`, `BAD_HASH`, `TOO_LONG`, `NO_MEMORY` for a size of 70 MiB, `NO_SPACE`
for 600 MiB, `INVALID` for an unknown repository) leaves the status and the list as they were;
INSTALL_CANCEL frees the store; a process whose effective user is 1000, or that sends no identity
session, is `NOT_ALLOWED`; a group of `big` and `wide` shows nothing before its end; the settings
of `games` and then of `games2` (a blob of two cells) replace the layer; the serial and the list of
revocations never go back and the list detaches the package of the revoked key; REMOVE gives the
space back. Then the machine starts again on the same disk file and the probe finds the packages,
the settings and the serial in place. `cargo xtask store-crash [N]` builds the service for each
crash point (or for point `N`), kills the machine on the line, starts it again on the same disk and
compares the store with the state before or after the change (point 8 allows either; point 13
checks that the disk is formatted again). `cargo xtask store-probe doom` installs Doom from
`target/pkg` (`cargo xtask pkg-build freedoom doomgeneric`) as a group and prints the memory the
service holds. The jobs of the CI are `store-probe`, `store-probe steps` and `store-crash`.

## What stays for subproject 5

The place of `pkgd` in the images and the order of the start (the clients ask for the place
`Packages`, and the shell waits for the service), delivery (in the image, from a disk, over the
network), dependency resolution at install time, and the sandbox and quotas of an application. Nothing here changes the quotas of
the image.
