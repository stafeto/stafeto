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
| `kind` | `base` for the base set of the system, `addon` for the rest of the shell image, `game` for the games image only, `net` for the images with the network service only. A base package depends on base packages only, no package of the shell image depends on a game, and only a network package depends on a network package. |
| `url` | The https URL of the source archive, or of the one file that is the source (the root certificates of `ca-bundle`). |
| `sha256` | SHA-256 of the archive, 64 lowercase hex digits. |
| `license` | SPDX expression of the licence. |
| `depends` | Names of the packages it needs (nano, htop and ncdu need ncurses). |
| `build` | The build script, from the workspace root. |
| `program` | The image program its build links, if it has one of its own. |
| `dirs` | Directories only this package needs. |
| `files` | `"<path in the image> = <source>"`, where the source is `elf:<program>`, `terminfo:<entry>`, `bytes:<name>` or `link:<name>`, a symbolic link to a file of its own directory (`/bin/cat = link:busybox`: `ls -l` shows `cat -> busybox`). Several paths may name one program (hard links), and the links to one name share one file of the image. A link must name a file of the image that is no link itself. The list may be empty for a package whose code another package links (musl-fts gives pax its `fts`); some package must then depend on it. |
| `license_file` | Optional: the licence file in the source tree, for tools that read it; empty where the files of the source state their terms in their headers (paxmirabilis). |

Example (`packages/nano.toml`):

```toml
name = "nano"
version = "9.2"
kind = "addon"
url = "https://ftp.gnu.org/gnu/nano/nano-9.2.tar.xz"
sha256 = "05ecb99247b782e8a5b3a25ed4101dd034b0236902f7449bc9795b717642f7e9"
license = "GPL-3.0-or-later"
depends = ["busybox", "ncurses"]
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
  version, URL or build script, a package without files, a file that two
  packages claim, an unknown dependency or a dependency cycle each stop it.
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
  RSA-MD, Beerware, MIT-CMU, ISC and MIT) is an add-on that installs only its
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
- The build scripts of the packages run in build order: base first, each
  package after its dependencies.

## Add a package

1. Write the build script in `tools/`, with the version, URL and SHA-256 taken
   from `tools/pkgdesc.py` (`pkgdesc.load("<name>")`).
2. Write `packages/<name>.toml` with the keys above.
3. If the package has a program of its own, add its build (stack size and
   features) to `PACKAGE_PROGRAMS` in `xtask/src/main.rs`.
4. Run `cargo xtask packages`, then `cargo xtask packages table`.

## What stays for subproject 5

Installing and removing packages in a running system, the package file
format, signatures and trust in sources, the store and delivery (in the image,
from a disk, over the network), dependency resolution at install time, and
the sandbox and quotas of an application. Nothing here changes the quotas of
the image.
