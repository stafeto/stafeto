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

Every configuration has a color buffer of XRGB8888 (8 bits each of red, green
and blue, none of alpha) or ARGB8888 (8 bits each, with alpha), no
multisampling, and a depth and stencil buffer of 0 and 0, 16 and 0, or 24 and
8 bits. `EGL_NATIVE_VISUAL_ID` is the format of the window the configuration
serves (`STAFETO_WINDOW_XRGB8888` or `STAFETO_WINDOW_ARGB8888`).
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

`stafeto_window_info` gives the platform the size, the format and the buffers
of the window. The surface keeps the description it saw and checks it at every
swap: a window closed (and opened again, with another shape) is
`EGL_BAD_NATIVE_WINDOW` from then on.

### eglSwapBuffers

A swap makes one copy of the frame and one post:

1. It takes a free buffer of the window (the bits of `stafeto_window_free_buffers`).
   When none is free it waits with `stafeto_window_wait` for up to one second; a
   signal that ends the wait lets it go on until the same time. A time that
   runs out, or a compositor that has gone (`ENODEV`), is
   `EGL_BAD_NATIVE_WINDOW` for that call. The surface stays.
2. It copies into that buffer what the buffer lacks of the newest frame. The
   driver keeps its own picture of the frame between swaps (the contents of
   the back buffer are kept), so each buffer of the window needs the union of
   the changed areas since the swap that last filled it (`ports/mesa/stafeto/swap.c`,
   tested on the host by `swap_test.c`): the first copy of a buffer is the whole
   window, and the later ones are the bounding box of the damage of the swaps in
   between. The rows of the frame are those of the window (top row first); the
   rectangles of `eglSwapBuffersWithDamageKHR` and `...EXT`, which EGL gives
   from the bottom up, are turned over for the post and the copy.
3. It posts the buffer with the damage of this swap: up to four rectangles as
   given, more as their bounding box, none (a plain swap) as the whole window,
   and a damage that clips to nothing as one point. The first post of a window
   is the whole window.
4. With a swap interval of 1 (the default) it waits until the compositor has
   taken the frame into one of its own, which frees the buffer the window showed
   before (up to one second; a frame that is late is no error). An interval of 0
   returns at once and the compositor takes the latest frame. `eglSwapInterval`
   clamps an interval above 1 to 1 (`EGL_MAX_SWAP_INTERVAL`), as EGL 1.5
   section 3.10.3 asks.

`EGL_SWAP_BEHAVIOR` of a new window surface is `EGL_BUFFER_DESTROYED` (Mesa
sets it so for windows); `eglSurfaceAttrib` accepts `EGL_BUFFER_PRESERVED`
because the configurations say it can be, and the contents are kept in both
cases. `EGL_EXT_buffer_age` is not offered.

Other errors of a swap: `EGL_BAD_SURFACE` when the surface is not the current
draw surface of the thread (EGL 1.5 section 3.10.4) or when the swap is made in
a child of `fork`.

### fork, exec, signals and threads

- A child of `fork` has no window (the window library says so) and its surface
  is the parent's: `eglSwapBuffers` in the child answers `EGL_BAD_SURFACE`
  (the surface remembers the process that made it). Contexts and pbuffers in the
  child follow Mesa on Linux: a program that forks from several threads calls
  only functions that are safe in a signal handler before `exec`.
- `exec` closes the window (the window library does) and the memory of Mesa
  goes with the old image.
- The functions of EGL and OpenGL are not safe in a signal handler.
- Mesa keeps the current context of a thread in thread-local memory. A second
  thread makes its own context (and pbuffer) and draws; `gles-cube --window`
  checks it.

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
  each swap are those of the pbuffer probe, so the window and the pbuffer give
  the same pictures.
