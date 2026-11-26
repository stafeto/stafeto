# dEQP on stafeto

The test framework dEQP of VK-GL-CTS (Khronos' conformance suite, Apache-2.0)
runs on stafeto against the EGL and OpenGL ES of Mesa's softpipe driver
(`docs/egl.md`). `cargo xtask deqp` builds it, runs the groups `info` and
`create_context` of the module dEQP-EGL in QEMU in batches, and prints the
counts.

## The build

`tools/build-deqp.py` (needs CMake 3.20 or later, ninja and git on the host;
Homebrew `cmake`, apt `cmake`; the build of 2026-11-26 used CMake 4.5.1) does
the following, in order:

1. It fetches VK-GL-CTS at the commit `067e8832315e79817ede1c4863804e440f5d1c80`
   (tag `opengl-es-cts-3.2.14.1`, the release the CI of Mesa 26.3.1 takes) into
   `target/deqp-src/cts` and compares the hash of the checkout.
2. It runs `external/fetch_sources.py` of that tree whole, with `python3 -I`,
   in that fresh directory (the top `CMakeLists.txt` needs the directories of
   SPIRV-Tools, glslang, Amber and jsoncpp and the headers of SPIRV-Headers,
   all excluded from the build). The script clones about ten repositories and
   fetches zlib and libpng with their SHA-256; it takes under a minute. The
   revisions of the five repositories the CMake files need are compared with
   the ones the script pins. `--include-vvl` stays off: `CMakeLists.txt:129`
   adds `external/vulkan-validationlayers` on ARM_64, and its CMake file
   builds the layers only when that directory holds a checkout, which no
   target of ours needs.
3. It copies `tests/deqp/targets/stafeto/stafeto.cmake` (the target) and
   `tests/deqp/platform` (the platform) into the tree and configures CMake with
   a toolchain file for aarch64-linux-gnu against the relibc sysroot, libc++
   and the headers of Mesa, `GLES_ALLOW_DIRECT_LINK=ON` (the framework links
   the entry points of EGL and OpenGL ES from `libmesa.a`; it has no `dlopen`
   of `libEGL.so`) and `DE_CPU=DE_CPU_ARM_64`. The searches of CMake stay in the
   sysroot, so no library of the host is found: zlib and libpng are the ones of
   the tree.
4. It builds the four modules `deqp-egl`, `deqp-gles2`, `deqp-gles3` and
   `deqp-gles31` as static archives (CMake is the generator only: ninja builds
   the objects and archives the link line of each module names) and puts them
   in `target/deqp/lib`; `target/deqp/<module>.link` lists the archives of a
   module in link order. The licence texts of what is linked go to
   `target/deqp/NOTICES` (`tests/deqp/LICENSES.md` has the list).

On an Apple M-series host with six performance cores the four modules take
about 90 seconds after Mesa, libc++ and relibc are built. The script runs on
the arm64 Ubuntu runners the same way: it takes only `cmake`, `ninja`, `git`,
`python3` and the clang of `STAFETO_C_TOOL_DIR` or Homebrew's.

## The program

`tests/deqp` is a Rust start crate like `apps/gles-cube`: `posix_crt::crt_main`,
and `build.rs` links the archives of `deqp-egl.link`, Mesa, libc++ and relibc.
The object of the package entry registers the module by a static object that
nothing refers to, so its archive is linked whole. The program is 20 MB in the
image (29.6 MB with debug information); the archives of the other modules sum
to 61 to 67 MB with debug information, and a program of each is expected to be
about 30 MB in the image.

The platform (`tests/deqp/platform`, 290 lines, MIT) implements `tcu::Platform`,
`glu::Platform` and `eglu::Platform` over `EGL_DEFAULT_DISPLAY`: the display
is linked in, the GL contexts come from `eglu::GLContextFactory`, and a native
window is a window of the composition service (`stafeto_window_open`, two
buffers, the format of the configuration's `EGL_NATIVE_VISUAL_ID`; the handle
is the window number plus 1). The process has one window at a time, so a test
that holds two windows fails with a resource error until the window manager
exists. A window has no resize and no visibility, and those tests are
`NotSupported`. `tcuStafetoMain.cpp` holds the entry: the arguments of a start
are the lines of `/etc/deqp.args` (the table of `init` fixes the arguments of a
program when it is built), and the log of the framework (`/dev/stdout`) is a
stream on a copy of descriptor 1 (the program is linked with `--wrap=fopen`),
so every case is on the console as soon as it ends.

## Where it runs

The image of the probe is the one of `gles-pbuffer` with the program
`deqp-egl`: the services of the POSIX probes, init's table `table-deqp` (quota
256 MiB) and QEMU with 1 GiB. The program is a file of the RAM service, as the
programs of os-test are; the image is 41 MB and the RAM service takes it, so
the data volume `datafs` is not needed for the module dEQP-EGL (the other
modules are 10 MB larger each, and the choice for them waits for their first
run).

## The runner

`xtask/src/deqp.rs`:

- One start of the program with `--deqp-runmode=stdout-caselist` lists the
  cases of the groups (`dEQP-EGL.info.*`, `dEQP-EGL.functional.create_context.*`);
  the list is kept in `target/deqp-src`.
- The cases go in batches of 200, each batch one start with
  `--deqp-caselist-file=/etc/deqp.cases` (a plain list of names, a file of the
  image written for the batch).
- `parse_qpa` reads the log lines of the console (the `#beginTestCaseResult`,
  `<Result StatusCode=...>`, `#endTestCaseResult`, `#terminateTestCaseResult`
  and `#endSession` lines among whatever else the program prints).
- `settle` gives the results of a batch and the cases to run again. The case a
  process died in is `Crash` and is not run again; the cases after it go back
  to the list and run in the next start. A batch that settles no case is an
  error.

The host tests of the parser run on a recorded log (`tests/deqp/recorded/
egl-batch.log`, the console of a real batch of 27 cases) and on the same log cut
inside a case, as the log of a process that crashed there; a `settle` that
drops the cases after the crash fails three of them.

## Result

Two groups of dEQP-EGL, 27 cases, in one start of 200 or fewer:

| Group | Cases | Pass | Fail | NotSupported |
|---|---|---|---|---|
| `dEQP-EGL.info` | 5 | 5 | 0 | 0 |
| `dEQP-EGL.functional.create_context` | 22 | 7 | 0 | 15 |
| together | 27 | 12 | 0 | 15 |

The cases that are `NotSupported` ask for a configuration the configurations
of the platform do not hold: 16-bit colour (`rgb565`, `rgba4444`, `rgba5551`),
an 8-bit colour with a stencil buffer and no depth buffer
(`*_no_depth_stencil`: the configurations hold depth and stencil together as 24
and 8 bits), and the case `other`, which asks for a colour format the
configurations have none of. The comparison with the same Mesa on Linux
is step 8.6.
