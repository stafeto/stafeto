# EGL and OpenGL ES

Programs written in C against `<EGL/egl.h>` and `<GLES2/gl2.h>` or
`<GLES3/gl3.h>` draw with Mesa's softpipe driver, which runs on the
processor. Mesa is built by `tools/build-mesa.py` (`cargo xtask mesa`) into one
static archive, `target/mesa/lib/libmesa.a`, with the headers of Khronos in
`target/mesa/include` (taken from Mesa unchanged). A program links the archive,
the C++ runtime of `tools/build-libcxx.py` (the GLSL compiler of Mesa is C++)
and relibc; `apps/gles-cube` is the model. `libc.so` never exports the
functions of EGL and OpenGL ES: `tools/build-libc-so.py` refuses a build that
defines a name `egl[A-Z]` or `gl[A-Z]`, so the ABI of the series is as it was.

This page describes the platform of EGL for stafeto, the part of Mesa that
`ports/mesa/stafeto/platform_stafeto.c` adds. The rest (the configurations
softpipe offers, the extensions, GLES 2.0, 3.0 and 3.1) is Mesa's own.

## The platform

`eglGetDisplay(EGL_DEFAULT_DISPLAY)` is the display of the platform of
stafeto. It needs no device and no environment variable (the software path of
Mesa is the only one). `eglGetPlatformDisplay(EGL_PLATFORM_SURFACELESS_MESA)`
gives Mesa's surfaceless platform, which makes pbuffers only. Pixmap surfaces
(`eglCreatePixmapSurface`) are refused with `EGL_BAD_MATCH`: no configuration
has `EGL_PIXMAP_BIT`.

| Type of EGL | On stafeto |
|---|---|
| `EGLNativeDisplayType` | `void *`, only `EGL_DEFAULT_DISPLAY` |
| `EGLNativeWindowType` | `khronos_uintptr_t`: the number of a window of `<stafeto/window.h>` plus 1 |
| `EGLNativePixmapType` | `khronos_uintptr_t`, not supported |

The number plus 1 keeps the handle 0 for "no window": Mesa's
`eglCreateWindowSurface` answers `EGL_BAD_NATIVE_WINDOW` for 0 before the
platform is asked, and the window of a process is number 0. `eglplatform.h` is
the file of Khronos, unchanged (stafeto defines `__unix__`, and that branch
gives these types).

### Configurations

The configurations of windows have a color buffer of XRGB8888 (8 bits each of
red, green and blue, none of alpha) or ARGB8888 (8 bits each, with alpha), no
multisampling, and a depth and stencil buffer of 0 and 0, 16 and 0, or 24 and
8 bits. The other formats of the driver (5-6-5, 10-10-10-2, 16 bits a channel
in integers and in floating point) have pbuffer-only configurations with every
depth and stencil of the driver, as Mesa's surfaceless platform has them: their
`EGL_SURFACE_TYPE` is `EGL_PBUFFER_BIT` and their `EGL_NATIVE_VISUAL_ID` is 0.
For a configuration of windows `EGL_NATIVE_VISUAL_ID` is the format of the
window it serves (`STAFETO_WINDOW_XRGB8888` or `STAFETO_WINDOW_ARGB8888`) and
`EGL_SURFACE_TYPE` holds `EGL_WINDOW_BIT`, `EGL_PBUFFER_BIT` and
`EGL_SWAP_BEHAVIOR_PRESERVED_BIT`. `EGL_MIN_SWAP_INTERVAL` is 0 and
`EGL_MAX_SWAP_INTERVAL` is 1. `EGL_RENDERABLE_TYPE` names OpenGL ES 2 and 3.

### Window surfaces

`eglCreateWindowSurface` (and `eglCreatePlatformWindowSurface`, with the same
value) takes a window the program opened with `stafeto_window_open`. The
surface has the size of the window, which never changes (the protocol has no
resize). Errors:

- `EGL_BAD_NATIVE_WINDOW`: the handle is 0, no window has that number, or the
  window has one buffer (a swap needs a free buffer, and the buffer of a window
  with one never comes back: open the window with two or three);
- `EGL_BAD_MATCH`: the format of the window is not the `EGL_NATIVE_VISUAL_ID`
  of the configuration;
- `EGL_BAD_ALLOC`: another surface already shows the window (Mesa checks it,
  EGL 1.5 section 3.5.1).

A window with `ARGB8888` holds colors already multiplied by their alpha; the
program writes them so (the compositor lays the window over what is below).

`stafeto_window_info` gives the platform the size, the format, the buffers and
the generation of the window. The surface keeps the description it saw and
compares the number and the generation at every swap: a window closed (and
opened again, with the same number and another generation) is
`EGL_BAD_NATIVE_WINDOW` from then on. The window must outlive its surface: a
program destroys the surface (or ends EGL, see below) before it closes the
window. A swap after the close fails, a surface made for the window and read
after it gives black.

A program that links `libmesa.a` links the window library too (the feature
`window` of `posix-crt`; `apps/gles-cube/Cargo.toml` is the model), because the
platform calls it. The functions are not weak: a program without the feature
does not link.

### eglSwapBuffers

A swap makes one copy of the frame and one post:

1. It takes a free buffer of the window with `stafeto_window_wait_free`. The
   wait has no limit: it ends when a buffer is free or when the compositor is
   gone (`ENODEV`: the kernel tells the window's channel when the compositor's
   last copy of it goes), which is `EGL_BAD_NATIVE_WINDOW` for that call (the
   surface stays). A signal that runs its handler does not end it. The wait
   takes no bit away from the program's own `stafeto_window_wait`: the events
   bit (keys, pointer, focus) and the buffer bits stay for it through any number
   of swaps, in this thread or in another, which may be asleep in
   `stafeto_window_wait` meanwhile. While another thread sleeps in that wait, the
   swap looks at the channel without blocking and pauses a millisecond between
   looks (it wakes the other thread to look again). The other way round, a
   `stafeto_window_wait` of the program, a poll with a timeout of 0 included,
   that comes while a swap holds the wait looks beside it in the same way and
   gets no `EBUSY` (two waits of the program still exclude each other). The wait
   of a swap has no limit and the swap is not a cancellation point: with a
   compositor that is alive and never frees a buffer it waits for ever, and a
   cancellation of the thread stays pending until it returns.
2. It copies into that buffer what the buffer lacks of the newest frame. The
   driver keeps its own picture of the frame between swaps (the contents of
   the back buffer are kept), so each buffer of the window needs the union of
   the changed areas since the swap that last filled it (`ports/mesa/stafeto/swap.c`,
   tested on the host by `swap_test.c`): the first copy of a buffer is the whole
   window, and the later ones are the bounding box of the damage of the swaps in
   between. The rows are copied as the driver keeps them, top row first. This
   departs from the plan of the step (section 5.3), which asked for a flip in
   the copy: the picture of a window-system framebuffer is top-down in Mesa
   already (`glReadPixels` turns it over), and a flipped copy shows the frame
   upside down. `gles-cube --window` checks it against `glReadPixels` (the
   window's rows must be the frame's, mirrored) and `swap_test.c` holds the same
   fault for the host. Only the rectangles of `eglSwapBuffersWithDamageKHR`
   and `...EXT`, which EGL gives from the bottom up, are turned over, for the
   post and the copy.
3. It posts the buffer with the damage of this swap: up to four rectangles as
   given, more as their bounding box, none (a plain swap) as the whole window,
   and a damage that clips to nothing as one point. The first post of a window
   is the whole window.
4. With a swap interval of 1 (the default) it waits until the compositor has
   taken the frame into one of its own, which frees the buffer the window showed
   before (up to one second; a frame that is late is no error, the compositor
   gone is). An interval of 0 returns at once and the compositor takes the
   latest frame. `eglSwapInterval` clamps an interval above 1 to 1
   (`EGL_MAX_SWAP_INTERVAL`), as EGL 1.5 section 3.10.3 asks.

A failure after the check of the process (the window gone, no buffer, a post
that failed) resets the history of the surface: the next swap copies and posts
the whole window. A swap that succeeds leaves `errno` as it found it. The swap
is not a cancellation point (`pthread_setcancelstate` disables cancellation for
its length), and a thread is not cancelled inside any other call of EGL or
OpenGL either: a program that cancels a thread that draws does it while the
thread is between calls, or lets the thread end itself.

`EGL_SWAP_BEHAVIOR` of a new window surface is `EGL_BUFFER_DESTROYED` (Mesa
sets it so for windows); `eglSurfaceAttrib` accepts `EGL_BUFFER_PRESERVED`
because the configurations say it can be, and the contents are kept in both
cases. `EGL_EXT_buffer_age` is not offered.

Other errors of a swap: `EGL_BAD_SURFACE` when the surface is not the current
draw surface of the thread (EGL 1.5 section 3.10.4) or when the swap is made in
a child of `fork`; `EGL_NOT_INITIALIZED` after `eglTerminate`.

### fork, exec, signals and threads

- A child of `fork` has no window (the window library says so) and its surface
  is the parent's: `eglSwapBuffers` in the child answers `EGL_BAD_SURFACE`.
  The reason for that error and no other: the surface is valid and was made
  by another process, EGL 1.5 has no word on `fork`, and `EGL_BAD_NATIVE_WINDOW`
  would say the window is invalid, which it is not for the parent. The answer
  holds when no other thread was inside EGL at the `fork` (the child's memory is
  a copy, and a lock another thread held stays held there); a program that forks
  from a thread of a program that draws in others calls only functions that are
  safe in a signal handler before `exec`. Fork of a program that holds Mesa is
  charged a full quota for the child (its picture, textures and compiler are in
  memory), so `posix_spawn` is the way to start another program, and the
  program of `gles-cube --window` starts its own file once because a program
  init starts cannot fork at all.
- The surface remembers the process that made it and compares it with
  `getpid()` at every swap and read, where the plan of the step (section 5.4)
  had an atfork handler that marks the surfaces dead. A comparison needs no
  registration, no list of surfaces and no lock in the child, and it covers a
  surface made after the handler would have run.
- `exec` closes the window (the window library does) and the memory of Mesa
  goes with the old image.
- The functions of EGL and OpenGL are not safe in a signal handler, and a
  handler that runs inside a swap must not call them.
- Mesa keeps the current context of a thread in thread-local memory. A second
  thread makes its own context (and pbuffer) and draws. A surface is current in
  one thread: another thread that tries to make it current gets
  `EGL_BAD_ACCESS`, and after the first thread releases it, the second can make
  it current, swap and release, and the first can take it back. A thread that
  used EGL calls `eglReleaseThread` before it ends. `eglTerminate` in another
  thread waits for a swap under way (the swap holds the surface's lock);
  `eglTerminate` with the surface current marks it for deletion, a swap then
  answers `EGL_NOT_INITIALIZED`, and `eglReleaseThread` lets go of it.
  `gles-cube --window` checks each of these.
- A thread that makes GL calls needs a large stack: the compiler of GLSL
  recurses deeper than 64 KiB. The main stack of a program is the size its file
  asks for (`-z stack-size`; a copy a spawn starts gets 64 KiB otherwise), so a
  program that links Mesa asks for 1 MiB (`apps/gles-cube/build.rs`; a host test
  of xtask reads `PT_GNU_STACK` of the built program and compares it with the
  stack the image gives), and a thread that compiles shaders is created with a
  stack of the same size or more (`pthread_attr_setstacksize`).

### Not offered

Pixmap surfaces, `EGL_OPENGL_API` and `EGL_OPENVG_API`, OpenGL ES 1,
multisampling, resizing of a window surface, `EGL_STAFETO_*` extensions, EGL
images as sources of OpenWF Composition, and a number for
`eglGetPlatformDisplay` of the platform of stafeto: until one is registered the
default display is the way in.

## Probes

- `cargo xtask gles-pbuffer`: the cube into a pbuffer (no compositor), ten
  frames read back with `glReadPixels`, their CRC-32 compared with the values
  pinned in `xtask/src/gles_pbuffer.rs` (the ones the same Mesa gives on Linux,
  `cargo xtask mesa-reference`).
- `cargo xtask gles-window`: the cube into a window of the composition service
  under QEMU. The program checks the API of the platform (a display not
  initialized, the configurations, a window of another format, the handles 0
  and 6, a second surface over one window, the swap behaviour and interval, a
  swap with no current context, a swap in a forked child, two threads with two
  contexts), draws six frames, swaps each one (the interval alternates 1 and 0)
  and prints the CRC-32 of the screen it should show at two of them. xtask asks
  QEMU for a screenshot at each and compares. The frames it reads back before
  each swap are compared by xtask with those of the pbuffer probe, so the window
  and the pbuffer give the same pictures. At the third frame the window's
  rows are compared with the readback (the orientation), four swaps with
  damage over a scissored clear leave the window equal to the frame, a surface
  current in one thread is `EGL_BAD_ACCESS` in another and moves between them,
  a thread asleep in `stafeto_window_wait` gets the bits of the swaps, and the
  program ends with `eglTerminate` with the surface current.
- `cargo xtask gles-probe` (the line `gles-probe` of ci, and `gles-probe steps`):
  the graphics of Mesa as a whole, in three boots. First the pbuffer probe
  above. Then the scene (`apps/wfc-demo --gles`, image `boot-gles.img`): the
  demo holds the scene of OpenWF Composition and starts `gles-cube --window-run
  --hold` and `gles3-demo --probe --hold`, and shows their windows as elements
  (the stream of `eglSwapBuffers` as the source of an element of libWFC). The
  cube runs the checks of `gles-window` with its window shown by the scene, and
  the two screenshots at its pauses have the CRC-32 it prints; it then holds its
  last frame (a byte on a pipe tells the demo), and the screenshot has the CRC-32
  it prints once more. `gles3-demo` (`apps/gles3-demo`: a vertex array object, a
  uniform block of 208 bytes in the layout `std140`, one `glDrawElementsInstanced`
  of 64 cubes whose place comes from `gl_InstanceID`, a divisor of 1 for the tint)
  draws three frames into a pbuffer and the same three into a window; each frame
  has the same CRC-32 in both, the rows of the window are the mirror of the
  readback, and its window in the screenshot has the CRC-32 the program prints. The
  CRC-32 of its three frames are pinned in `xtask/src/gles_probe.rs`. Last the demo
  turns the cube's window by 90 degrees and scales it by one half (an element of
  libWFC) beside the field, and xtask compares the screenshot with the frame that
  `tools/wfc-ref` (`gles_frame`) draws point by point from the screenshots of the
  two windows as they are. The third boot is the same scene under `-icount`
  (`boot-gles-steps.img`, no pauses): the steps of the compositor and the driver
  stay under 0.9 of term B and the portions under `PORTION_MAX`. The tables are
  `services/init/src/table/gles.rs` (the demo's record and the process service's
  pool have quotas above 64 MiB for the programs it starts).

## Clock stamps

With the variable `STAFETO_EGL_STAMPS` set in the environment of a program, each
`eglSwapBuffers` of a window surface prints one line to the console:
`egl-stamp: swap wait W draw D copy C post P ifwait I us timeout T`, the microseconds the
swap spent waiting for a free buffer, in the driver's swap (which holds the copy),
in the copy of the frame into the window's buffer (the `putImage` of the platform),
in the post, and in the wait of `eglSwapInterval(1)` for the service to take the
frame, and T, how many times that wait ran out (a second; the probe requires 0). With the variable unset a swap reads no clock and prints nothing.
`gles-cube --stamps` sets the variable and prints the draw and the swap of each
frame; `cargo xtask gles-probe load` (and `--hvf` for the host's processor) prints
them per frame with a summary, beside the numbers of a client with no GLES.

## The level of a client that draws

A client that draws on the CPU is best-effort work and runs below every interactive
level. The demo of scenes (SCHED_RR priority 30 in a caller whose top is 30) starts the
cube and the field with that scheduling: `posix_spawn` puts a child whose level is below
the caller's top at that level, 28, loader included, and that level is the child's top and
its ceiling less one (the ceiling is 29). A record of the tables that runs the cube
directly (the pbuffer and window probes) has priority 28 and ceiling 29. The process
service ends such a process at its base level, so only the stages that stop its threads and
children rise to the ceiling, and the pages of its image are released by the service's
reaper thread at that level, never inside a step of the service's loop. `cargo xtask
gles-probe load` judges the cube at that level under -icount: no late frame of a paced
client beside it when none is late alone, none over two periods, a wake-up at most 2000 us
longer, no wait of the swap interval that ran out and none over two periods.

## Waits and threads

`eglSwapInterval(1)` waits for the compositor to take the frame, a second at most, and
the probe counts the waits that ran out. The wait for a free buffer has no limit: when the
compositor stops answering, init's watchdog restarts it and the wait ends with the
service's end. Mesa holds the display lock across the swap's wait (`eglapi.c`), so a
multi-threaded real-time client makes its EGL calls from one thread.
