# The composition service

`compositor` (`services/compositor`) is the one client of the display driver
(`virtio-gpu`, the record `display` of init's table) and the display service
its own clients see: the table gives it the name `gpu`, so the place
`Display` of every POSIX process, the launcher of the games image and the
probes meet it. The driver's buffer of the screen belongs to the compositor
alone; no client maps it.

## What a client sees

Two protocols share the channel, with method numbers apart from each other
and the header version 1 of both.

- `proto_comp` (`proto/comp`): DESCRIBE, WINDOW_CREATE, ATTACH and POST. A
  client makes a window (a place and a size inside the 640 by 400 screen,
  XRGB8888), gives it one to three buffers of memory it made itself with
  `mem_create` (the compositor maps them read-only), draws in a free buffer
  and posts it with the rectangles it changed. The latest posted buffer
  wins. The compositor tells the client by a bit of the channel it gave
  at WINDOW_CREATE (bit 0 to 2, the buffer's number) that a buffer is free
  again, and never waits for the client. Windows lie in the order of their
  making, the newest on top. A window goes when the last copy of its session
  closes or when the context's session does: the end of a process frees its
  windows, and their places are painted again in the next frame.
  A window is XRGB8888 (opaque) or ARGB8888 (the colour already multiplied
  by the alpha, laid over what is below); the format of WINDOW_CREATE and of
  ATTACH must agree. The compositor puts the windows together with pixman
  (below). The pointer's picture is the display's cursor (below, "The
  pointer"); a driver with no cursor pipeline makes the compositor draw the
  picture over the windows once a pointer was seen.
- Events (stage G2). Each window has a ring of 64 events of 16 bytes; EVENTS,
  called on a window's session, takes up to 32 of them without waiting, and
  says LOST when older ones were dropped. The bit 3 of the channel
  WINDOW_CREATE gave says a ring has something. While no manager has subscribed, a window that has its first
  buffer taken into a frame gets the focus and the top place (with a manager
  it is told CREATE and the manager decides, so a client that makes windows
  does not take the keyboard); the window with
  the focus gets the keys; a window gets the pointer's moves and buttons in its
  own coordinates (the window under the pointer, or the one a pressed button
  holds until it is released); a click on a window gives it the focus and the
  top place; FOCUS_IN and FOCUS_OUT tell a window it won or lost the focus,
  and when the window with the focus goes it passes to the one on top. The
  design keeps the rings per context; this stage keeps them per window, which
  is the same for a context with one window and costs a client with several
  windows one EVENTS call each.
- The manager (`MANAGE`, a session whose label init marked MANAGER_MARK: the
  table's `COMP_MANAGERS`) lists the windows, moves them, raises them, shows and
  hides them and gives one the focus, and reads CREATE and CLOSE of every window
  in a ring of its own. While it has subscribed (DESCRIBE's `flags` bit 0), the
  Super keys and the keys pressed with Super held are its alone, so Super and
  Tab can switch the windows without the window with the focus seeing them. The
  Alt, Ctrl and Shift keys stay the windows' (Doom binds all three). The
  program `wm` (`apps/wm`, below) is the manager of the images that have one.
- The input session (`INJECT`, INPUT_MARK, `COMP_INJECTORS`: the probes only)
  injects a key, the pointer's place on the screen or a button, which takes the
  path of the device's own event.
- `proto_gpu` first revision (`proto/gpu`): OPEN, FLUSH, CLOSE and CLONE, as
  `libc.so` speaks them (`stafeto_display_open` and `stafeto_display_flush`).
  OPEN makes a window of the whole screen over the driver's pool, the one
  buffer of the window of the first revision (a source of the driver,
  `SOURCE_KIND_POOL`: 250 pages of the 256 of its object, 640 by 400, XRGB8888,
  asked for when the screen is opened and mapped by the steps of the work, a
  chunk of 32 pages each, so OPEN says CLEARING until that is done); FLUSH
  posts a rectangle of it and its reply comes once the frame that shows it is on
  the screen. Doom runs as it did on the driver, without a rebuild. One such
  window lives at a time; a second OPEN is BUSY, as it was. When the window goes
  the pool is cleared in portions of 16 KiB once the display no longer shows it
  (see "The direct frame": the frame that returns the screen to the service's
  target must be shown first), and OPEN says CLEARING meanwhile. The driver gives
  the owner of the screen a handle of the pool with DUPLICATE (the cursor's
  picture has none), so the compositor hands a copy without it to each window.
  A copy that is out can write into the pool after a clearing passed (a program
  that closed its window and kept its mapping), so the service keeps a `dirty`
  flag: it is set when a copy is given and cleared only by a clearing that ended
  with no copy out; an OPEN that finds the pool dirty and the copies gone starts
  the clearing and answers CLEARING (`compositor::pool_open`). The next window
  therefore finds the pool zero.
  The buffer is shared with its client: CLOSE, or dropping the window's
  session, leaves a client that kept the handle, mapped or not, or sent a copy
  of it to another process, able to read and write the next window of the
  first revision's pixels, and the next window's alone, as the screen is never
  mapped by a client. OPEN therefore says BUSY while the object has more
  references than the compositor had right after it mapped the pool
  (`object_info` of a memory object returns the count in x4: handles in any
  process, mappings, handles in transit and long calls). This closes the
  case of a kept handle, mapped or not, and of a copy handed on. The price
  is availability of the old path alone: a former client that keeps its
  handle blocks the first revision's OPEN until it exits or closes the
  handle, and the second revision (ATTACH) is unaffected. The driver
  (`virtio-gpu`) makes the same check for its `fb` in OPEN, and for the pool
  and the cursor's picture in SOURCE, with three references of its own: its
  handle, its mapping and init's handle. When SOURCE answers BUSY at the
  opening of the screen (the service ended while Doom ran and started again,
  and Doom still holds its copy) the service remembers it, answers BUSY to
  OPEN, and asks SOURCE again at the next OPEN: the driver marks the source as
  given only when it gives it, so the ask succeeds once the program is gone.
  The mapping then starts, and OPEN says CLEARING until it is done and the pool
  is cleared. A driver with no primary pipeline that suits leaves OPEN BUSY.
  The pool's mapping sits at 0x12_0000_0000 and ends at 0x12_000F_A000; the
  cursor's four pages are at 0x12_0010_0000, so six unmapped pages lie between
  them, in the same 2 MiB span and the same page table.

## The window manager

`apps/wm` is the manager as a program of its own: a client of init's table
named `wm` (`table::COMP_MANAGERS`), which gets the manager's session of the
compositor, subscribes, and answers the events of its ring. What it decides is
in its library and tested on the host. A new window (CREATE) gets the focus and
the top place (FOCUS does both). Super and Tab give them to the next shown
window by number, wrapping (Super, Shift and Tab to the previous one: Shift is
pressed after Super); Super and Q end the manager when the chord is released.
It uses the manager requests that exist (SUBSCRIBE, LIST, FOCUS) and adds none.
A click is the compositor's: it gives the window under the pointer the focus and
the top place itself, so the manager does nothing for a click and nothing is
done twice. Super is the modifier because Doom binds Alt, Ctrl and Shift, and
the shell reads the console's keys and never this keyboard's. Tab alone and Q
alone are the windows'. The manager's calls are the compositor's ordinary steps: LIST
has at most MAX_WINDOWS records, no loop is added to a step. When the manager
ends, the compositor goes on by its own rule: the window that has the focus
keeps it, the first window shown takes it when no manager has subscribed, a click
moves it, and a window that goes passes it to the one on top.

## Input

The compositor is the client of two input services of init's table: the
keyboard's (`input`) and the pointer's (`pointer`, a second instance of
`virtio-input` on a virtio-tablet). It asks each for the focus with a channel
of its own in GRANT, and the driver sends that channel the bit 1 whenever a
step put events into the ring; the compositor reads them (READ, up to 32 at a
time, without waiting) in its own step. The keyboard's focus is the
compositor's always. A program of the first revision (Doom) reads its keys
from the session of focus that OPEN gives, which is a session of the
compositor itself: its READ (proto_input's, up to 64 keys at a time) takes the
KEY events of the window's ring, so the keys reach the window while it has the
focus and no other time (a window of the first revision takes no pointer
events, so a stream of moves never pushes a key out of its ring). The keyboard's
driver sees one holder of its focus, the compositor, which routes the keys by
the rule of every window; where the image has no keyboard OPEN says NO_INPUT and
gives no session of focus. A key's release goes where its press went (a window, the
manager or nobody), so a tap of Super while a window holds a key leaves the
release with the window; when the focus leaves a window of the first revision,
which sees no FOCUS_OUT, the keys it still holds are released in its ring first
and their real releases are dropped. When an input driver ends and init starts
it again, the compositor takes its focus again (each grant's label carries a
generation, so the end of an old grant is told from the new one), at its next
own step and at OPEN; the connection to a driver that is starting again waits
for it. The tablet
reports `EV_ABS` `ABS_X` and `ABS_Y` from 0 to 32 767 across the screen and
`BTN_LEFT` as a key; the compositor scales them to the screen's 640 by 400. The
image of the probe (`table::focus`) has the tablet on the transport 13; the
base image has no tablet record yet, so its pointer is stage G2's probe image
only.

## The pointer

At the opening of the screen the compositor asks the driver for PIPELINES
and, when it lists a pipeline of kind CURSOR that takes ARGB8888, for the
SOURCE of kind cursor: a memory object of one 64 by 64 picture (source 3),
which it maps and in which it draws the arrow (`proto_comp::cursor::CURSOR`,
12 by 19 points, ARGB8888 premultiplied, the rest transparent) once. The
arrow's hot spot is its top left point, (0, 0). DESCRIBE's `flags` then has
bit 1, CURSOR_PLANE: the points of the screen (a screenshot, a probe's CRC)
never hold the pointer, because the device draws it.

- Until the pointer is seen the cursor is not bound, so it is hidden. After
  a step of reading input whose events moved the pointer (and after an
  INJECT) the compositor sends one LAYERS with one row of the cursor
  pipeline: source 3 and the pointer's place, whose changed area is empty.
  The driver takes the first such row for the cursor's first update (the
  picture is transferred, then shown) and a later one for a move. However
  many events a step read, one row goes, with the last place; the driver
  merges moves while its cursor queue is busy. The reply comes as soon as
  the command is queued, so a move never waits for the device, and none is
  sent inside a frame's composition, in a band or in the end of a frame.
  A row the driver refused is made again at the next step of input.
- A move of the pointer damages nothing while the cursor is on the pipeline,
  and the cost of a band counts no layer for the pointer: a frame is made
  for the windows alone.
- The cursor stays visible over every window, a window of the first revision
  included: that window takes no pointer events, but the pointer is the
  user's and the picture over it is what the frame showed before. A row of
  source 0 would hide it, which the scene makes (`Scene::cursor_row`) only
  for a pointer that is not seen.
- A driver that has no cursor pipeline (PIPELINES unknown or no record of
  kind CURSOR), refuses SOURCE, or whose picture does not suit leaves the
  compositor drawing the pointer into the frame as before.

## pixman

The windows are put together by pixman 0.46.4 (MIT), built from its pinned
source by `tools/build-pixman.py` (`packages/pixman.toml`: version, URL and
SHA-256 of the archive) as a static library that `lib/pixman` links into the
compositor: its AArch64 NEON paths (`pixman-arm-neon.c` and the two assembly
files of meson's `a64-neon`) over its portable C paths, with no threads and no
timers, over the headers and the shim of `ports/pixman` (an arena of 32 KiB that pixman
allocates from, and the few functions of a C library it calls). Two files of
pixman are left out and replaced by one function each in the shim: the
combiners of the wide formats and the accessors of images, which windows of 8
bits to the channel never reach. The package installs no file: its licence
notice is the one the distribution carries for it
(`/usr/share/licenses/pixman/`), and `xtask packages` accepts it as a library
of a service (`SERVICE_LIBRARIES`). pixman adds its NEON implementation to its
table with no test of the CPU when it is built with `USE_ARM_A64_NEON` (every
AArch64 CPU has the instructions), so nothing reads `/proc` or the auxiliary
vector, and programs may use the FP and SIMD registers: the kernel saves and
loads them at every switch between threads (`karch/src/fpsimd.S`,
`kernel/src/thread.rs`, `run`), and programs are built for
`aarch64-unknown-none`, with FP and SIMD. `STAFETO_PIXMAN_PORTABLE=1` (or
`tools/build-pixman.py --portable`) builds the portable C paths alone. The
copy of a band and the lay of a band over
the screen are pixman's SRC and OVER; the glue is `lib/pixman` and
`services/compositor/src/px.rs`.

## The C library of windows

A C program makes windows of the second revision with the functions of
`<stafeto/window.h>` (`lib/posix-crt/window/stafeto/window.h`). They are a
static library: the Rust crate `posix-crt` with its feature `window` carries
the C functions (`window_c.rs`), `posix-abi` with the same feature the calls
(`window.rs`), and the crate `comp-client` the logic that needs no kernel.
`libc.so` is built without the feature and the header lies outside the libc
sysroot, so the series 0.5 of the ABI is as it was, and `tools/build-libc-so.py`
refuses a build of `libc.so` that defines a name of the library
(`stafeto_window_*`, `stafeto_screen_*`). A program that uses windows is a
statically linked one (`tests/posix-window` is the model); a later series
moves the library into `libc.so` and gives the window's channel to `poll`.

- The process has one window, number 0. `stafeto_window_open` asks DESCRIBE
  for the screen (it waits for a display that is being set up), makes the
  buffers (memory objects of the process, mapped as pieces of the memory map
  of the kind `Window`, a page-rounded `4 w h` bytes each), a channel of its
  own with a timer, WINDOW_CREATE with a copy of the channel (NOTIFY and
  TRANSFER) and ATTACH with a copy of each buffer (MAP_READ and TRANSFER). A
  failure at any step closes what was made, so a failed open leaves nothing.
- The account of the buffers is `comp_client::account`: a buffer is free at
  the start, a POST takes it out before the request goes (a failed POST gives
  it back), and only the service's bit for it brings it back. The service
  sends the bit of a buffer a later POST replaced before it replies to that
  POST, so `stafeto_window_post` takes the bits that wait before and after
  its request and keeps them for the next `stafeto_window_wait`, which a
  thread asleep in it is woken for. Each bit is returned by one wait.
- POST with 5 or more rectangles goes as their bounding box; up to 4 go as
  they are, none means the whole window. Each rectangle is checked against
  the window before anything is sent.
- `stafeto_window_wait` is the wait of `fast::wait`: a try without waiting,
  the signals, the entries deferred, a receive with a timer for the bound.
  A signal with a handler ends it with EINTR. One thread at a time waits and
  one takes events; another gets EBUSY. Events the service gave beyond the
  caller's room wait in the library for the next call.
- `fork` gives the child no window (the state is reset in `after_fork`, and
  the map of the child has no piece of a buffer); `exec` and
  `stafeto_window_close` close the session, which ends the window in the
  service, unmap the buffers and close the channel and the timer (a failed
  unmap is told once on the console). A call that finds the service ended
  (post, events, shown) answers ENODEV, and the calls after it too. A
  `stafeto_window_wait` does not learn of the end by itself, since its check
  runs at entry: it ends with a bit or its time, so a program uses a finite
  timeout.
- `stafeto_window_events` asks the service again while its replies are full
  (32 events) and the caller has room, so a call returns fewer than `max`
  only when the ring is empty; the ring holds 64 and the service sends its
  bit for new events only.
- `stafeto_window_shown` is a helper of the probes: it looks at DESCRIBE
  every 2 ms until `frames` has grown since the last look and `busy` is 0.
  When no POST came since the last look it returns as soon as `busy` is 0.

`cargo xtask posix-window` runs `tests/posix-window` in an image of its own
(`boot-posix-window.img`, the table `table::window`): the screenshots of QEMU
after the first frame, a rectangle of the second buffer and the merge of
five rectangles have the CRC-32 the program computed, and the bits, events,
fork, a signal and close are checked by the program.

## Limits accepted in stage G1

One process can take all 8 window places through clones of its session. A
client at level 1 that posts without pause drives composition at level 32
with no budget; budgets come at stage 5, and until then the interference
reaches the real-time POSIX tasks up to level 31.

## Steps

Every step of the compositor stays under 16 500 ticks. A page costs the kernel
about 200 ticks to map and 80 to unmap, so ATTACH looks at its objects in the
step of the request and maps them a chunk of 32 pages a step, and its reply
comes after the last chunk; a window that went keeps its place, with its
pages, until its chunks are unmapped one step at a time. A buffer is a
megabyte at most.

## The frame

A frame takes the posted buffer of every window at its start, is made in
bands, a step each (the compositor's own bit starts the next band, so requests
of clients pass between bands). A band that only copies is eight lines of the
damage's width under a window that covers the damage, and four where it starts
black (pixman's fill costs about twice its copy). A band that lays something
over others (a window with an alpha, the pointer's picture) holds fewer points:
each shown window that touches the damage is a call of pixman (about 1 500 ticks)
and a number of ticks a point (3 for a copy, 25 for a layer laid over others, 4
for the black), and a band holds the points that 15 000 ticks leave after its
calls, down the damage and across it, so that eight windows in one band stay
under the bound, and then goes to the driver
as COMMIT of the changed rectangle. COMMIT is proto_gpu's second revision:
SUBSCRIBE gives the driver the compositor's channel once, COMMIT answers as
soon as the commands are in the device's queue, and the driver says
`FRAME_SHOWN` (or `FRAME_FAILED`) on that channel when the device is done.
FLUSH of the first revision still waits inside the driver, for the programs
that speak to the driver directly (the image of `gpu-probe`).

## The direct frame

When one window of the first revision covers the whole screen with nothing
above it, the screen needs no composition: its buffer is the pool, and the
service binds the pool to the display's primary pipeline (LAYERS with a row of
source 2 and the changed area) and puts nothing together. The frame has no
band; its one step is the end of the frame, which is the LAYERS call. The
decision is `Scene::plan`, made when a frame starts, after the posted buffers
are taken, and it holds when all of these do:

1. the driver has a primary pipeline that takes the screen's whole size
   (FULL_SCREEN, XRGB8888) and gave the service the pool;
2. the topmost shown window is of the first revision (its buffer is the
   pool), opaque, and covers the whole screen (windows under it are not seen);
3. no shown window is above it (a hidden window, or one with nothing taken
   yet, is not shown);
4. the pointer is not drawn in the frame: it is on the cursor pipeline or not
   seen yet. After the driver refused the cursor row for good
   (`Scene::cursor_refused`) the pointer is back in the frame and this reads
   false from then on.

A frame the rule does not allow is composed as before. The plan once had a
fifth condition, an image flag that forbids the direct frame, so that a probe
could compare the composed and the direct screen; it was dropped. The composed
path from the pool is covered by `comp-probe`'s `above crc` check, where a
window over the pool's window makes the service put its pixels together. The
transitions:

- composed to direct: no band, one LAYERS row with the pool and the changed
  area (the driver transfers the whole pool when the source changes, whatever
  the area says); the target is marked stale, for it is not kept while the pool
  is shown;
- direct to direct: the changed area alone, no band, no copy of the service;
- direct to composed (a window came over it, it was hidden or went, the
  pointer came back into the frame): the area becomes the whole screen, the
  bands put it together in the target, and after the last band LAYERS binds
  the primary pipeline to the target (source 1). The screen shows the last
  frame of the window until the new one is whole, so there is no empty frame,
  and the way back costs one frame of composition, as the design asks. A
  composed frame after a direct one (the target stale) also carries the whole
  screen.

A window of the first revision that goes while the screen shows the pool is
followed by that frame; the pool is cleared in portions only once the frame
that unbound it is shown (`Scene::take_pool_clear`), and a program that reads
the pool at once sees it go to zero then. The driver of a board whose
controller reads memory continuously needs this order; virtio-gpu keeps its own
copy at the host and would not.

DESCRIBE's `bypassed` counts the frames shown directly and `bands` the bands
put together, both since the service started: a probe that finds `bands`
unchanged over a number of FLUSHes while `bypassed` grew by that number knows
they cost the service no copy. The host still copies the pool into its own
image on each transfer (virtio-gpu has no other way without `udmabuf`), so
"no copy" means none by the service.

The header version of proto_gpu stays 1 in revision 2. The loop of a service
takes one version, and the series 0.5 of the ABI (`packages/abi.txt`) holds
the version in the programs built for it. `proto_gpu::REVISION` is 3.

Revision 3 gives the owner of the screen the hardware layers, in the words of
OpenWF Display. PIPELINES (9) lists the display hardware's pipelines: the
virtio device has a primary pipeline that takes a source of the whole screen
(640 by 400, XRGB8888) at 0, 0, and a cursor pipeline that takes a source of
exactly 64 by 64 (ARGB8888, premultiplied) with a hot spot. SOURCE (10) hands
the owner the memory object of a source, once for each kind: 1 is the pool
buffer (source 2), 2 the cursor picture (source 3); source 1 is the
compositing target, the buffer OPEN gave. LAYERS (11) binds up to four rows,
a source to a pipeline with the place, the hot spot and the changed area, and
the rows take effect together. The layouts are in the header of
`proto/gpu/src/lib.rs`: a pipeline's record is 32 bytes, a LAYERS row 40, and
a LAYERS request at most 172 bytes. The three methods belong to the owner's
session alone. Until the driver implements them it answers UNKNOWN_METHOD.
Scaling and cropping (source and destination rectangles, in the words of
OpenWF) come later as a new method with a longer row; LAYERS stays as it is.
The last word of a pipeline record is reserved for a display number, 0 being
the first display, and must be zero.

The driver keeps this order of the device's commands, and the compositor may
rely on it:

- A primary row with a new source: the whole of the source is transferred to
  the host, then the scanout is set to it, then the whole screen is flushed.
  The transfer is complete before the scanout changes. With the bound source
  the row transfers and flushes its changed area, as COMMIT does, and COMMIT
  stays as a LAYERS of one such row.
- A cursor row with a new source: the picture is transferred with a fence, and
  the cursor update is sent after the device answered that transfer. A
  transfer behind the work of a frame waits for it.
- A cursor row of source 0 hides the cursor; a row that only moves is a move.
  For a cursor, `x` and `y` are where the pointer (the hot spot) lies, always
  on the screen, and the hot spot may put the picture partly off an edge; the
  top left point is the place only for overlays.
- The device reads the cursor's points only on its update command. A cursor
  row with the same source and a nonzero changed area therefore makes the
  driver transfer the whole picture again with a fence and then send the
  cursor update; a plain move would never show the new picture.
- A LAYERS of cursor rows alone is always taken. The cursor queue holds one
  chain; the driver keeps the last place given while a chain is out and sends
  that place alone when it returns, so the moves merge.
- A LAYERS with a primary row while the device holds the work of an earlier
  frame is BUSY, and the work ends with FRAME_SHOWN or FRAME_FAILED as for
  COMMIT.

## Checks

`cargo xtask comp-probe` runs three clients on QEMU and compares QEMU's
screenshot with the CRC-32 the guest computed for the screen it should show:
a window, a rectangle of it posted alone, two windows, the black screen after
the first client ended, and a window of the first revision (pattern and a
rectangle), which the display shows from the pool: `bands` stay as they were
over three FLUSHes and `bypassed` grows by three, a third client's window over
it makes the frame composed (its CRC, resource 1 in QEMU's trace of
SET_SCANOUT) and the pool is the screen again when that window goes
(resource 2). Under `-icount` it measures the steps of the compositor and of
the driver: every step stays under 0.9 of term B, and a band of a frame, like
a portion of the driver's clearing, under 16 328 ticks, and tells what each kind of layer costs a point inside
the bands (`service raster` lines of `px::cost`; the constants of
`Scene::tile` are set from them). `cargo xtask
doom-probe` runs Doom through the compositor: the title's CRC is the one of the
direct path, and QEMU's trace shows the scanout on Doom's buffer (resource 2).
`cargo xtask doom-measure` reports Doom's frames a second. The compositor asks PIPELINES
and SOURCE of the driver at the opening of the screen, so the driver's steps
of those kinds are required in `comp-probe`'s table.

`cargo xtask focus-probe` (stage G2) runs the compositor with a tablet, two
clients whose windows overlap (the second with an alpha), a manager and a
program that injects events, and compares QEMU's screenshot with the CRC-32
the guest computed after each step: the overlap with its transparency, a click
that gives the first window the focus and the top place, the manager's switch
on Alt and Tab, and the screen after the second client ended and the first
went on untouched. Each client's events must be exactly the list it expects:
the keys only while it had the focus, the focus changes, the click in its own
coordinates. The pointer is on the cursor pipeline, so no CRC has its picture
(the guest requires CURSOR_PLANE); QEMU's trace of the display
(`virtio_gpu_update_cursor`) must show the cursor's update from resource 3 at
the place of the injected move, then a move with resource 3 to the tablet's
place, and none with resource 0. QEMU's tablet then moves and presses through
the monitor, and the surviving window must see the click. The same command then runs the image of the
window manager (`table::focus::WM_TABLE`: the program `wm`, a keyboard's
driver, a native client and a client of the first revision): the manager gives
each new window the focus, Super and Tab switch the windows twice, and the keys
reach the window with the focus only, the window of the first revision among
them; the manager then ends on Super and Q, the compositor answers and keeps
the focus where it was, and the focus passes to the window on top by the
compositor's own rule when the first client ends. Under `-icount` it measures the steps of
the compositor, of the tablet's driver and of the display driver, whose
PIPELINES, SOURCE and LAYERS steps must come (each under 0.9 of term B, a band
under 16 328 ticks).

`cargo xtask lvgl-probe` (stage G4) runs the LVGL demo in a window of the second
revision and compares each of its two frames three ways: the demo's own CRC-32,
QEMU's screenshot and the host reference program's CRC-32. `docs/lvgl.md` tells
what else it compares and how.

## Not yet

The period of a frame and its counters, a window's resize, the constants of
the bands set from the NEON costs (the probes report them), the window manager
and the keyboard in the base image (the manager's image is the probe's), the
pointer in the base image, the layers of the display
controller, a window of the second revision shown directly (the flag `SCANOUT`
of WINDOW_CREATE is reserved), and the C functions for windows in `libc.so`
(a change of the ABI series, 0.6; the static library above has them now, and
`docs/lvgl.md` tells the program that uses them).
