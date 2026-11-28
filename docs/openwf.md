# OpenWF for C programs

stafeto gives C programs two Khronos interfaces over its own services:
OpenWF Composition 1.0 (`<WF/wfc.h>`, a scene of elements shown on the
screen) and OpenWF Display 1.0 (`<WF/wfd.h>`, the display controller's ports
and pipelines). Both are static libraries that a program links; `libc.so` has
neither. This page tells what they implement, how a program uses them, where
they differ from the specifications and what a program can count on in time.
The composition service they talk to is described in
[compositor.md](compositor.md) ("The scene" and "OpenWF Composition for C
programs" there are the details of the protocol and the prices).

## What is implemented

| Interface | Specification | Library | Rules | Talks to |
|---|---|---|---|---|
| OpenWF Composition 1.0 | 5 November 2009 | `libWFC`: feature `wfc` of `posix-crt` and `posix-abi` | `lib/wfc` (host tests by clause, table in `lib/wfc/CLAUSES.md`) | the composition service `compositor` (scene session of `proto_comp`) |
| OpenWF Display 1.0 | 1.0 | feature `wfd` of `posix-crt` and `posix-abi` | `lib/wfd` | the display driver `virtio-gpu` (`proto_gpu`, revision 3) |

The Composition functions that exist are: `wfcEnumerateDevices`,
`wfcCreateDevice`, `wfcGetError`, `wfcGetDeviceAttribi`, `wfcDestroyDevice`,
`wfcGetStrings`, `wfcIsExtensionSupported`, `wfcCreateOnScreenContext`,
`wfcCreateOffScreenContext` (it always answers `WFC_ERROR_UNSUPPORTED`), the
context accessors (`wfcGetContextAttribi`, `wfcGetContextAttribfv`,
`wfcSetContextAttribi`, `wfcSetContextAttribfv`), `wfcDestroyContext`,
`wfcCommit`, `wfcActivate`, `wfcDeactivate`, `wfcCompose`, `wfcFence`
(always `WFC_ERROR_ILLEGAL_ARGUMENT`), `wfcCreateSourceFromStream`,
`wfcCreateMaskFromStream`, `wfcDestroySource`, `wfcDestroyMask`, the whole set
of element functions (`wfcCreateElement`, the `Get`/`Set` accessors for
integer, float and vector attributes, `wfcInsertElement`, `wfcRemoveElement`,
`wfcGetElementAbove`, `wfcGetElementBelow`, `wfcDestroyElement`) and the
extension function `wfcNextStreamSTAFETO`. The functions the header declares
for images (`wfcCreateSourceFromImage`, `wfcCreateMaskFromImage`) are not in
the library: an EGL image would have to be a buffer of the composition service,
and the texture of the software driver lives in the memory of its process, so a
program that calls them does not link (`docs/egl.md`, "Not offered").

The Display functions that exist cover devices, events (`wfdCreateEvent`,
`wfdDeviceEventAsync`, `wfdDeviceEventWait`, `wfdDeviceEventFilter`), ports
and port modes, pipelines, sources made of streams, binding and
`wfdDeviceCommit`, with the two extension functions `wfdStafetoStream` and
`wfdStafetoSetCursorHotSpot`. Masks, display data, the transparency colour,
and the sources and masks made of images are present as entry points that
answer as the section "Differences" tells.

## Headers and libraries

The headers lie in `ports/openwf/include/WF`:

| Header | Content |
|---|---|
| `wfc.h`, `wfcext.h` | the Khronos headers of OpenWF Composition, unedited |
| `wfcplatform.h` | the platform types, adapted to stafeto (the EGL types are opaque pointers) |
| `wfcext_stafeto.h` | the extension `WFC_STAFETO_stream` and `wfcNextStreamSTAFETO` |
| `wfd.h`, `wfdext.h` | the Khronos headers of OpenWF Display |
| `wfdplatform.h` | the platform types, adapted to stafeto |
| `wfdext_stafeto.h` | the extensions `WFD_STAFETO_stream` and `WFD_STAFETO_cursor` |

The Khronos notice in the first lines of the unedited headers stays with them.
A program compiles with `-I ports/openwf/include` (and the sysroot headers of
relibc) and links statically: the build script of `apps/wfc-demo` is the
model. A Rust crate that holds the C object depends on
`posix-crt` with `features = ["wfc", "window"]` (the scene demo) or
`["wfd"]` (the display demo) and on `posix-abi` with the same feature.
`tools/build-libc-so.py` refuses a `libc.so` that defines a name `wfc[A-Z]` or
`wfd[A-Z]`, so the ABI of the series 0.6 is unchanged.

A program that holds a scene is started by init with the scene's mark in its
session (the records `COMP_SCENES` of `services/init` name them). A process
that has no mark gets no device from `wfcCreateDevice`. A child made by
`posix_spawn` or `fork` has an ordinary session and makes no device either.

## The model as it is used here

- **Device.** `wfcCreateDevice(WFC_DEFAULT_DEVICE_ID, NULL)` (ids 0 and 1
  name the one device) gives a handle. Up to four devices exist at once; each
  has its own state and its own lock. `wfcGetDeviceAttribi` gives the id (1)
  and the class (`WFC_DEVICE_CLASS_FULLY_CAPABLE`); `wfcGetStrings` gives the
  vendor `stafeto`, the renderer `stafeto-compositor`, the version `1.0` and the
  extension `WFC_STAFETO_stream`.
- **Context.** One on-screen context on the screen number 0, 640 by 400 points
  on `virtio-gpu`. A second context, from the same device or another, is
  `WFC_ERROR_IN_USE`. The context has a rotation (0, 90, 180, 270), a
  background colour (alpha 255) and the lowest element of the scene. The
  rotation is folded into each element at the commit.
- **Streams, sources and masks.** A `WFCNativeStreamType` is the number of a
  window of the composition service. A producer (any client of the service)
  makes the window and draws in it; the holder of the scene learns the number
  with `wfcNextStreamSTAFETO(dev, timeoutMs, &stream)` (windows made before the
  call count, up to 32) and makes a `WFCSource` of it with
  `wfcCreateSourceFromStream`. A mask is a window of the format A8
  (`STAFETO_WINDOW_A8` of `<stafeto/window.h>`), which the holder makes itself
  (a process has up to eight windows, the service gives a context four) and makes a `WFCMask` of with
  `wfcCreateMaskFromStream`. Up to 8 sources and 8 masks live at once.
- **Elements.** Up to 16 elements, each with a source rectangle (floats, in
  the source's points), a destination rectangle (integers), the source
  rotation, the flip (top to bottom), the scale filter, the transparency
  types, the global alpha and a mask. The order of the scene is the order of
  `wfcInsertElement`: an element goes immediately above the subordinate it
  names, 0 puts it at the bottom.
- **Commit and compose.** Every attribute, element and the order live in the
  library and are cached until `wfcCommit`, which sends one SCENE_COMMIT with
  up to 16 elements. `wfcCompose` asks the service for one frame of the last
  committed scene (a context that is not active). `wfcActivate` makes the
  service compose by itself at the start of every period that has a change in
  the scene or in a window it shows; `wfcDeactivate` stops that. `wfcCompose`
  of an active context is `WFC_ERROR_UNSUPPORTED`. With `wait` true,
  `wfcCommit` returns when the service has taken the scene and `wfcCompose`
  when the frame is on the screen.
- **What the service draws.** Each element is the source rectangle turned by
  the rotation and the flip, stretched to the destination rectangle by the
  nearest point (`WFC_SCALE_FILTER_NONE` and `WFC_SCALE_FILTER_FASTER`) or by
  the bilinear mean (`WFC_SCALE_FILTER_BETTER`), and mixed by the transparency
  types: none copies, `WFC_TRANSPARENCY_SOURCE` uses the window's own alpha,
  `WFC_TRANSPARENCY_ELEMENT_GLOBAL_ALPHA` and `WFC_TRANSPARENCY_MASK` multiply.
  The mask is the size of the destination rectangle and is not stretched. The
  meaning of every number, point by point, is `proto_comp::meaning`, which the
  host tests and the probe hold the service to.

The Display device has one port (id 1) with one mode and the pipelines the
driver reports: on `virtio-gpu` pipeline 1 is the primary one (the whole
screen, layer 1) and pipeline 2 the cursor (a picture of 64 by 64 points, layer
2). The device starts in the pre-configured state of the specification
(section 7): the port mode is set, the power mode is on, both pipelines are
bound to the port and the primary pipeline shows the compositing target. The
sources are the three streams of the driver, which `wfdStafetoStream` describes
with the address of their points in the process: the compositing target and
the pool buffer (0x00RRGGBB) and the cursor picture (premultiplied 0xAARRGGBB).
Changes to pipelines are cached until `wfdDeviceCommit`, which sends one LAYERS
request to the driver. A program of this interface talks to the driver alone, so
the image has no composition service.

## Building and running wfc-demo

`apps/wfc-demo` is a C program (`wfc-demo.c`) with a Rust startup crate. It
compiles with the C compiler of the host (`STAFETO_C_TOOL_DIR`, by default
`/opt/homebrew/opt/llvm/bin`) against the sysroot of relibc:

```
cargo xtask relibc            # the sysroot, once
cargo xtask wfc-probe         # builds boot-wfc.img and runs the demo in QEMU
cargo xtask wfc-probe screen  # the screenshots alone
cargo xtask wfc-probe steps   # the run under -icount alone
```

The demo is a program of the probe image: the scene's mark comes from init's
table (`services/init/src/table/wfc.rs`), so a copy started from a shell holds
no scene. It starts three producers (`/bin/wfc-producer`, from
`tests/wfc-producer`) with `posix_spawn`, draws a mask of its own, and shows
four scenes:

| Scene | Elements |
|---|---|
| A | a quarter turn; a stretch with the nearest point and a global alpha; a mask with a global alpha |
| B | a quarter turn; a mask; a flip |
| D | the bilinear filter: a stretch up, a stretch down of a flipped window, a quarter turn with a global alpha |
| C | one element, a window of the first revision on the whole screen, which the service shows straight from its buffer |

A and B are committed 100 times in turn, each composed on request; then the
context is activated and the scene changes 100 times without waiting; then D is
committed once and C is shown. `tools/wfc-ref` draws A, B and D on the host
point by point from the same calls and `meaning`, and the probe compares the
CRC of each of QEMU's screenshots with it. D has its own line with the time of its
frame. With `--quick` (the run under -icount) the demo leaves out the pauses the
screenshots need. The probe also judges the service's counters (no frame failed,
bands grow, C is a frame shown straight), the trace of the display device and,
under -icount, the longest steps of the compositor and the driver.

With `--gles` (`cargo xtask gles-probe`, `table-gles`) the demo shows what Mesa
draws: it starts `gles-cube` and `gles3-demo` (`docs/egl.md`), takes the stream of
each window of EGL as the source of an element (the stream `eglSwapBuffers` fills
is a window of the composition service), and commits the scene that turns the cube's
window by 90 degrees and scales it by one half beside the field of cubes.
`tools/wfc-ref` (`gles_frame`) draws that scene from the two windows' points.

### EGL and the stream of OpenWF Composition

A window surface of EGL is made over a window of the composition service
(`<stafeto/window.h>`), and a window of the service is the stream of libWFC. So
a program draws with `eglSwapBuffers` into a window and another program (or the
same one) calls `wfcCreateSourceFromStream` with the stream of that window and
shows it as an element; the swap posts a buffer and the service takes the latest
one into the scene, as it does for any producer. The two APIs meet at the
window only: libWFC knows nothing of EGL, and an EGL surface over a window that
a scene shows needs no call of libWFC. The cube's window turned by 90 degrees
and scaled by one half is this path, in the probe `cargo xtask gles-probe`.
A client that draws on the processor runs below the interactive clients
(`docs/egl.md`, "The level of a client that draws"), so a scene that transforms
its window adds bands to the frames of the service; `docs/compositor.md` states
the limit.

The demo goes on to check the API on the way: the calls before a device, the
device and its attributes, a second device, the context and its refusals, the
streams and sources, the defaults and refusals of an element, the order of the
scene and a spawned child with no device.

## What is not implemented or differs

Composition:

- No off-screen context: `wfcCreateOffScreenContext` answers
  `WFC_ERROR_UNSUPPORTED`. The device reports the class fully capable, which
  section 4.1.1 of the specification ties to off-screen rendering: a departure.
- No images: EGL exists (Mesa's, `docs/egl.md`) and a window surface of EGL is a
  stream, but an EGL image is memory of its process that the service cannot see,
  so sources and masks come from streams only; `wfcFence` answers
  `WFC_ERROR_ILLEGAL_ARGUMENT` as before, because an asynchronous signal needs
  readiness marks in the service.
- One screen (0) and one context; a second is `WFC_ERROR_IN_USE`.
- Limits: 4 devices, 16 elements, 8 sources, 8 masks. The 17th element is
  `WFC_ERROR_OUT_OF_MEMORY`.
- A transparency pattern other than none, a single bit or the two pairs of
  section 7.1.7 is refused at the setter with `WFC_ERROR_ILLEGAL_ARGUMENT`.
- The service draws a stretch through a transform whose steps are the source
  sides over the destination sides rounded to 16.16, so a ratio that has no
  exact 16.16 step (60 points over 90, for instance) may give points that differ
  from the point-by-point reference by one source point; the host reference
  (`tools/wfc-ref`) and the demo use ratios that are exact (2, 1, one half).
- The flip follows stage 3 of section 3 and section 7.1.4 (top to bottom,
  before the rotation); the introduction of chapter 7 says "vertical axis" and
  contradicts them.
- The service's LIST gives a window's size and no format, so creation accepts a
  stream for a source or a mask and the service checks the kind at the commit;
  a source of an A8 window or a mask of a colour window is refused there.
- A destroyed source or mask stays in its slot while an element refers to it.
- `wfcDestroyContext` of an active context deactivates it first; the last
  image stays on the screen, and the call does not wait for a frame in
  progress.
- The functions are not async-signal-safe. Calling one from a handler that
  interrupted a call of the library, or leaving a call with `siglongjmp`, is
  undefined. A signal that arrives while `wfcCommit` or `wfcCompose` waits runs
  its handler and the wait goes on; `wfcNextStreamSTAFETO` ends with 0.
- After `fork` the child has no device; `exec` closes the channel and drops the
  devices, and the scene the old image committed stays until the new image
  commits its own.
- A stream is a window of the composition service: there is no other kind, and
  a producer has no API in this library (it uses `<stafeto/window.h>`).

Display:

- One port and one mode; `wfdSetPortMode` accepts the mode that exists, and
  `wfdSetDeviceAttribi` answers `WFD_ERROR_BAD_ATTRIBUTE`.
- `wfdGetDisplayDataFormats` gives no format and `wfdGetDisplayData` answers
  `WFD_ERROR_ILLEGAL_ARGUMENT`.
- Masks are not supported: `wfdCreateMaskFromStream` answers
  `WFD_ERROR_NOT_SUPPORTED`, `wfdDestroyMask` answers `WFD_ERROR_BAD_HANDLE`.
  The images are not offered (see the composition part).
- `wfdSetPipelineTSColor` with a valid format answers
  `WFD_ERROR_NOT_SUPPORTED`.
- A pipeline has no flip, mirror or rotation (only 0 is accepted); the filter
  and the global alpha are accepted, the global alpha from 0 to 255.
- `wfdCreatePipeline` of a pipeline already created is `WFD_ERROR_IN_USE`.
- The refresh rate of the mode is 60 Hz, the image's setting.
- The queue of bind events holds up to 128 entries; its default depth is the
  refresh rate times the pipelines.

## Real-time properties

The service that composes the frames runs at a fixed period and is made of
steps that the kernel can preempt; the library adds no thread and no buffer
of its own.

- **Setters and getters** make no system call: they work on the cached state
  under the device's lock and take bounded time (the tables are 16 elements, 8
  sources and 8 masks).
- **The commit.** `wfcCommit` is one request of up to 916 bytes. The service
  keeps it as the pending scene and takes it whole at the start of a frame: a
  commit in the middle of a frame is in the next frame and never half in this
  one.
- **The frame period** is 16 666 667 ns (60 Hz) at the start of each period a
  change is owed. A period holds at most 750 000 millionths of itself in work,
  counted in bands at the gate of a band (16 328 ticks of 16 ns under -icount,
  62.5 MHz), which is 47 bands. A frame larger than that spans several
  periods and shows as `capped` and `late` in the service's counters.
- **Band steps.** A frame is made in bands, each a step of the service with a
  gate of 16 328 ticks (0.8 of term B of the analysis of the waits; the longest
  step of a probe stays under 0.9 of it, 18 369 ticks), so the requests of other
  clients pass between bands. The service sizes a band from a price model of
  each element's kind (the call of pixman, the line, the point; a miss of
  pixman's cache of paths for an element with a transform). A scene whose layers
  cost more than one step holds is drawn in groups of layers, each group a step
  on a place of the frame as big as the dearest group allows, bottom to top; the
  picture is the one of a single step.
- **The cost of an element.** The fast kinds are the copy, the laying over, the
  quarter turn without a stretch, the global alpha and the mask, and a stretch
  with no turn and no flip (the class `Scale`, nearest or bilinear, with a mask
  or a global alpha), which has a NEON path of its own in pixman. A flip or a
  turn by 180 degrees with a stretch uses the general path of pixman (about
  5 700 ticks a call and 94.75 ticks a point). The bands of a group are sized
  from its own dearest element, so a dear element slows its own group and the
  others keep their bands. A scene that needs a frame in each period keeps its
  dear elements few; `compositor stats` tells the bands of a frame.
- **Frame times** of the demo's scenes under -icount, where time is
  instructions: scene A (a quarter turn, a 2x stretch with a global alpha, a
  mask with a global alpha) 0.95 to 0.96 s, scene B (a quarter turn, a mask, a flip of
  50 by 60 points) 1.15 to 1.17 s, scene D (three bilinear elements, a 2x stretch up,
  a half-size flipped window, a quarter turn with a global alpha) 4.1 s. The same
  scenes took 28 to 116 s a frame when the bands were sized from the dearest
  element of the whole frame. On QEMU's own clock (the screenshot run) the frames
  of A and B take about 1 s and D 3.5 s. A flipped element of 100 by 200 points in
  scene B took 7.2 s a frame, so the loop of 100 commits keeps its flip small.
- **Waits.** `wfcCommit(..., WFC_TRUE)` and `wfcCompose(..., WFC_TRUE)` wait
  for the bits COMMITTED and COMPOSED that the service sets on the session's
  channel. The wait polls the channel every 100 ms, so a returned wait can be
  up to 100 ms later than the event, and checks that the service is alive every
  5 polls. When the service answers BUSY to a request with `wait`, the library
  waits a frame (17 ms) and sends again, at most 16 times; after that the call
  stores `WFC_ERROR_BAD_DEVICE` (without `wait` the first BUSY is the result,
  `WFC_ERROR_BUSY`). An interrupted wait goes on at once. A wait ends with an
  error when the service closes its channel, so no wait outlives the service.
  `wfcNextStreamSTAFETO` takes the timeout in milliseconds.
- **Signals.** The lock of a device is held for the whole call, a wait
  included, so a waiting thread blocks the calls on its own device and no other.
  The lock is no critical section of the layer: a signal's handler runs while
  the call waits.
- **The service's own order.** The calls without `wait` return after the
  request is taken; `wfcActivate` and `wfcDeactivate` do not wait for a commit.
  The frame is shown when the device reports it (`FRAME_SHOWN`), and the
  display driver is given the commit of the changed rectangle only.
- **Measures.** `cargo xtask wfc-probe` judges every step of the compositor
  and the driver under -icount against the gates above, and `cargo xtask
  frame-probe` the frame time under load. The prices and the model are in
  [compositor.md](compositor.md), "The frame".
