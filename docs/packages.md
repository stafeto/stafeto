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

## What stays for subproject 5

Installing and removing packages in a running system, the store and delivery
(in the image, from a disk, over the network), dependency resolution at
install time, and the sandbox and quotas of an application. Nothing here changes the quotas of
the image.
