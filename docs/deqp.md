# dEQP on stafeto

The test framework dEQP of VK-GL-CTS (Khronos' conformance suite, Apache-2.0)
runs on stafeto against the EGL and OpenGL ES of Mesa's softpipe driver
(`docs/egl.md`). `cargo xtask deqp` builds it and runs sets of cases of the
modules dEQP-EGL, dEQP-GLES2, dEQP-GLES3 and dEQP-GLES31 in QEMU in batches,
prints the counts and compares each case with the same case on Linux (the
baseline, below). `cargo xtask deqp-reference` makes that baseline on an arm64
Linux machine.

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

## The programs

`tests/deqp` (dEQP-EGL), `tests/deqp-gles2`, `tests/deqp-gles3` and
`tests/deqp-gles31` are Rust start crates like `apps/gles-cube`:
`posix_crt::crt_main`, and the `build.rs` of each links the archives of its
`<module>.link`, Mesa, libc++ and relibc (the steps are `tests/deqp/link.rs`,
which the four build scripts include). The object of the package entry
registers the module by a static object that nothing refers to, so its archive
is linked whole. The programs are 20.1 MB (EGL), 23.0 MB (GLES2), 27.9 MB
(GLES3) and 26.9 MB (GLES31) in the image.

The platform (`tests/deqp/platform`, 330 lines, MIT) implements `tcu::Platform`,
`glu::Platform` and `eglu::Platform` over `EGL_DEFAULT_DISPLAY`: the display
is linked in, the GL contexts come from `eglu::GLContextFactory`, and a native
window is a window of the composition service (`stafeto_window_open`, two
buffers, the format of the configuration's `EGL_NATIVE_VISUAL_ID`; the handle
is the window number plus 1). The platform registers a pixmap factory whose
pixmap has the handle `nullptr`, as the platform nullws of dEQP does
(`framework/platform/nullws/tcuNullWSPlatform.cpp`): the platform of EGL
refuses pixmap surfaces, and the tests of the negative API reach EGL with the
stub. This differs from plan 5.1, which names no pixmap factory. The process has one window at a time, so a test
that holds two windows fails with a resource error until the window manager
exists. A window has no resize and no visibility, and those tests are
`NotSupported`. `tcuStafetoMain.cpp` holds the entry: the arguments of a start
are the lines of `/etc/deqp.args` (the table of `init` fixes the arguments of a
program when it is built), and the log of the framework (`/dev/stdout`) is a
stream on a copy of descriptor 1 (the program is linked with `--wrap=fopen`),
so every case is on the console as soon as it ends.

## Where it runs

The image of the probe is the one of `gles-window` with the program of one
module, which the image calls `deqp` (`/bin/deqp`, the record `deqp` of init's
table `table-deqp`, quota 256 MiB): the services of the POSIX probes, the
display driver and the compositor (the record `gpu`, which the place `Display`
of the platform meets) and QEMU with 1 GiB and the display of `qemu::GPU`. The program is a file of the RAM service, as the programs of
os-test are; the images are 41 MB (EGL) to 59 MB (GLES31) and the RAM service
takes them, so the data volume `datafs` is not needed. The modules GLES2,
GLES3 and GLES31 read data files (the shader tests of the GLSL conformance, the
images of the texture tests; 77, 91 and 109 files, 1.1 to 3.7 MB) from
`/data/<module>`, files of the image that `deqp.rs` takes from the build tree
(`--deqp-archive-dir=/data`). The screen of the display driver is 640 by 400
points (a constant of the service), so a window of 480 by 480, which the sync,
preserving-swap and damage tests open, is larger than the screen and the case is
`NotSupported` (departures, class `window`). A resource error ends the process
of the framework, and the runner starts it again. Every run of a GLES module asks for pbuffer surfaces of 256 by 256 and the
configuration `rgba8888d24s8ms0`, as the CI of Mesa does, and the run on Linux
takes the same arguments (`Module::arguments`).

## The runner

`cargo xtask deqp [SET | MODULE | all | smoke | smoke-select]...` (`xtask/src/deqp.rs`):

- A set is a group of dEQP cases of one module, the unit of a run and of a
  baseline file: `egl.info`, `egl.context`, `egl.query`, `egl.config`,
  `egl.sync`, `egl.api`, `egl.negative`, `egl.surface`, `egl.swap`, `gles2.basic`, `gles2.buffer`,
  `gles2.texture`, `gles2.shaders1`, `gles2.shaders2`, `gles2.fragops`,
  `gles2.raster`, `gles3.basic`, `gles3.shaders`, `gles3.texture`,
  `gles3.buffers` and `gles31.compute` (`SETS` in `xtask/src/deqp/baseline.rs`
  holds the patterns of each: the groups of plan G8, 7.4). A module name runs
  its sets. With no argument the command runs `egl.info` and `egl.context`.
  In the sets `gles2.fragops`, `gles2.shaders1` and `gles2.shaders2` the groups
  `fragment_ops.blend`, `fragment_ops.depth_stencil`, `fragment_ops.random`,
  `fragment_ops.interaction`, `shaders.conversions` and `shaders.swizzles` run
  one case in four in the order of names (the field `sample`; the baseline holds
  every case and the comparison takes the cases that ran). The others run in
  full.
- The cases of a set come from its baseline file (it holds every case the set
  has on Linux); a set with no baseline file is listed by one start of the
  program with `--deqp-runmode=stdout-caselist`, and the list is kept in
  `target/deqp-src`.
- The cases go in batches of 200, each batch one start of the program with
  `--deqp-caselist-file=/etc/deqp.cases` (a plain list of names, a file of the
  image written for the batch).
- `parse_qpa` reads the log lines of the console (the `#beginTestCaseResult`,
  `<Result StatusCode=...>`, `#endTestCaseResult`, `#terminateTestCaseResult`
  and `#endSession` lines among whatever else the program prints).
- `settle` gives the results of a batch and the cases to run again. The case a
  process died in is `Crash` and is not run again; the cases after it go back
  to the list and run in the next start. A batch that settles no case is an
  error.
- After a set the run is compared with the baseline and the departures (below);
  the command fails on a case that passes on Linux, does not pass here and has
  no departure.

The host tests of the parser run on a recorded log (`tests/deqp/recorded/
egl-batch.log`, the console of a real batch of 27 cases) and on the same log cut
inside a case, as the log of a process that crashed there; a `settle` that
drops the cases after the crash fails three of them.

## The baseline on Linux

`cargo xtask deqp-reference SET|MODULE|all... [--write] [--no-build]
[--provisional TEXT]` runs on arm64 Linux only and refuses any other machine.
`tools/build-deqp-reference.py` builds, for each platform the sets name, the
same Mesa 26.3.1 as shared libraries with the options of the build for stafeto
(softpipe, no LLVM, no desktop OpenGL; `-Dplatforms=x11` on top for the X11
variant) and the same VK-GL-CTS commit with that platform of its CMake. The
runner is the one above: the same batches and the same `parse_qpa`, so a
crash on Linux costs one case as it does in the guest. The platforms
(plan 7.3):

| Platform | Modules | Sets | Why |
|---|---|---|---|
| `surfaceless` | gles2, gles3, gles31 | the GLES sets | GLES contexts over EGL pbuffers; it has no `eglu::Platform`, so no deqp-egl |
| `nullws` | egl | `egl.info`, `egl.context`, `egl.config`, `egl.api` | deqp-egl with a native window of `nullptr`: the groups that need no window |
| `x11_egl` | egl | `egl.query`, `egl.sync`, `egl.negative`, `egl.surface`, `egl.swap` | deqp-egl on an X server (Xvfb), for the groups that take windows (the negative API opens one) or pass only with them; X11 is on the side of the baseline only |

The baseline of each set goes to `target/deqp-reference/baseline/<set>.txt`,
to the log between the lines `==== BEGIN tests/deqp/baseline/<set>.txt ====` and
`==== END ... ====`, and with `--write` to `tests/deqp/baseline/`. A file has
`#` lines (what made it: the versions, the platform, the arguments, the counts,
the time) and one line `CASE STATUS` for each case. A file that says
`# provisional:` was not made by a probe of a runner; the comparison says so, and the host test refuses such a file.
A platform that does not build costs its sets only; the command prints the
others and fails at the end.

### The probe commands

The probe of the runners (`probe.yml`) installs the packages the X11 variant
needs (`apt` for the headers of X11 and XCB, Xvfb) by itself. The sets split
over three probes, each under the 60 minutes of the job (the builds are the
main cost: Mesa twice and dEQP once per platform):

```
gh workflow run probe.yml --ref BRANCH -f command="deqp-reference egl" -f timeout=60
gh workflow run probe.yml --ref BRANCH -f command="deqp-reference gles2" -f timeout=60
gh workflow run probe.yml --ref BRANCH -f command="deqp-reference gles3 gles31" -f timeout=60
```

The sets `egl.api`, `egl.context`, `egl.query` and `egl.negative` changed after
the first probe runs, so the first command runs again.

Each probe uploads the files as the artifact `deqp-baseline` (30 days) and
prints them in the log. The files replace the ones of `tests/deqp/baseline`;
`cargo xtask deqp smoke-select` then makes `tests/deqp/smoke.txt` again.

## The departures

`tests/deqp/departures.txt` has a line `CASE | STATUS | CLASS | REASON | STEP`
for every case that passes on Linux and does not pass on stafeto:

- CASE is a case name or a pattern: `*` stands for any run of characters in one
  group of the names (no dot), `**` for any run at all;
- STATUS is the status stafeto ends with, usually `NotSupported`;
- CLASS is `posix` (the layer of POSIX under Mesa), `mesa` (Mesa or its
  platform), `window` (the composition service, the window manager), `config`
  (the configurations the platform offers) or `harness` (the test platform or
  the runner);
- STEP is the step of the plan that returns the case (`M<n>`, `G<n>.<m>`) or
  `none` for a difference the plan keeps. `open` is no step: the parser refuses
  it.

The comparison (`compare`):

- a case that passes on Linux (`Pass`, `QualityWarning`,
  `CompatibilityWarning`) and does not pass here, or has no result, needs a
  line, and the line must name the status the case ends with: another status
  is a regression;
- a case that fails on Linux and ends in `Crash`, `Timeout` or `InternalError`
  here is a regression unless a line names that status;
- a line of one case that now passes is stale and fails the run, so a step that
  returns a case drops its line; after a run of every case of its sets, a
  pattern that matches cases passing on Linux and covered none is stale too;
- the run prints how many cases each line covered;
- a case the baseline does not know fails the run.

The host test `the_files_of_the_comparison_agree` checks the files together:
every case of the baselines lies in the patterns of its set, the smoke list
holds 150 to 250 cases that pass on Linux and depart nowhere, every set that
gives to smoke has a case in it, and every line of the departures matches a
case that passes on Linux (a line for a breakdown, one that fails). The constant
`ALLOW_PROVISIONAL` of the test is false: a baseline file that says
`provisional:` fails it.

## deqp-smoke

`tests/deqp/smoke.txt` lists 199 cases: one of each group of the passing cases
of the baselines that gives groups (`cargo xtask deqp smoke-select` cuts the names
at the deepest level that gives at most 250 groups and leaves out the cases a
departure covers), and the first passing case of each set of windows that has
one left (`egl.surface`; every passing case of `egl.swap` departs, see the
results). `cargo xtask deqp smoke` runs them in the three programs and compares
them; `smoke:egl` runs the cases of one module. It is the job `deqp-smoke` of ci.

## Results

Run in QEMU (TCG, 1 GiB, the image with the compositor) on a Mac, against the
the baselines (below):

| Run | Cases | Pass | Fail | NotSupported | Time |
|---|---|---|---|---|---|
| `deqp smoke` (EGL 72, GLES2 71, GLES3 56) | 199 | 199 | 0 | 0 | 91 s + 58 s + 15 s in three starts |
| `deqp gles31.compute` | 41 | 41 | 0 | 0 | 16 s |

With the pbuffer-only configurations of the platform (below) and the windows of
the compositor the smoke list needs no departure to pass. The departures that
stand cover the groups the screen of 640 by 400 keeps out: `fence_sync`,
`preserve_swap` and `swap_buffers_with_damage` open a window of 480 by 480, and
`buffer_age` needs `EGL_EXT_buffer_age`, which the platform does not offer.
Every passing case of `egl.swap` on Linux is in those three groups, so the set
gives nothing to smoke until the screen is taller (the display service has a
fixed screen; a step of the window manager can change it).

The baselines in `tests/deqp/baseline` all come from probes of the runners
(`probe.yml`: runs 45841842144, 45841854088, 45841865612 and 45848607548,
Ubuntu arm64, Linux 7.0 azure). A container run of the same sets (arm64 Ubuntu
24.04 under Docker, the same Mesa and VK-GL-CTS commit) agrees with them on
every case: 17 245 cases, 0 differences in status. No file says `provisional:`,
and the host test refuses one. Linux runs all sets in 3 minutes after the builds.

Window sets in the guest (probes 45848619132, 45848631030 and 45848643875, the
image with the compositor on a runner):

| Set | Cases | Pass | NotSupported | Time | Departures used |
|---|---|---|---|---|---|
| `egl.surface` | 273 | 48 | 225 | 599 s | 12 (`platform_window`, `platform_ext_window`) |
| `egl.swap` | 273 | 0 | 273 | 617 s | 252 (`buffer_age`, `preserve_swap`, `swap_buffers_with_damage`) |
| `egl.sync` | 51 | 21 | 30 | 548 s | 30 (`fence_sync`, two `reusable_sync` cases) |

No case needed two windows at once: none ended in a resource error. The cases
that fail on Linux too (225 and 21 of them) are not compared.

The build of dEQP, with Mesa and libc++, is a step of the group `build` of ci;
the run cache hands `target` (with `target/deqp`) to the group of the job
`deqp-smoke`, which only links the programs. The weight of the job is 150
seconds, from the warm runs of the probe 45841877135 (`deqp smoke` three times
on a runner): the first run took 699 s with the build of dEQP (506 s) in it,
and the second and third 146 s and 143 s.

| Platform | Mesa and dEQP builds in the container (12 cores) |
|---|---|
| `nullws` (egl) | 4.5 minutes, with the checkout of VK-GL-CTS |
| `surfaceless` (gles2, gles3, gles31) | about 5 minutes |
| `x11_egl` (egl, with Mesa for X11) | about 3 minutes |

The comparison fails as it should: with the display of the platform made to
throw `NotSupportedError` (a change of `tcuStafetoPlatform.cpp`, undone), the
five cases of `egl.info` that pass on Linux are `NotSupported` and
`cargo xtask deqp egl.info` ends with `5 regressions`. The host tests do the
same on synthetic results, with the statuses of the departures too.

No multisampling is offered, which rules out a run of the ES 3.0 conformance
runner (`cts_runner`) of the suite: it asks for multisampled configurations.
