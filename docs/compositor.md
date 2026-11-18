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
  (below), and draws a pointer's picture over them once a pointer was seen.
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
  Alt keys and the keys pressed with Alt held are its alone, so Alt and Tab can
  switch the windows without the window with the focus seeing them.
- The input session (`INJECT`, INPUT_MARK, `COMP_INJECTORS`: the probes only)
  injects a key, the pointer's place on the screen or a button, which takes the
  path of the device's own event.
- `proto_gpu` first revision (`proto/gpu`): OPEN, FLUSH, CLOSE and CLONE, as
  `libc.so` speaks them (`stafeto_display_open` and `stafeto_display_flush`).
  OPEN makes a window of the whole screen over the one buffer the compositor
  made at its start (it cannot make one in a step: the kernel clears the
  megabyte inside the call); FLUSH posts a rectangle of it and its reply comes
  once the frame that shows it is on the screen. Doom runs as it did on the
  driver, without a rebuild. One such window lives at a time; a second OPEN is
  BUSY, as it was. When the window goes the buffer is cleared in portions of
  16 KiB, OPEN says CLEARING meanwhile, and the next window finds it zero.
  The buffer is shared with its client: CLOSE, or dropping the window's
  session, leaves a client that kept the handle, mapped or not, or sent a copy
  of it to another process, able to read and write the next window of the
  first revision's pixels, and the next window's alone, as the screen is never
  mapped by a client. OPEN therefore says BUSY while the object has more
  references than the compositor's own two, its handle and its mapping
  (`object_info` of a memory object returns the count in x4: handles in any
  process, mappings, handles in transit and long calls). This closes the
  case of a kept handle, mapped or not, and of a copy handed on. The price
  is availability of the old path alone: a former client that keeps its
  handle blocks the first revision's OPEN until it exits or closes the
  handle, and the second revision (ATTACH) is unaffected. The driver
  (`virtio-gpu`) makes the same check for its `fb` in OPEN, with three
  references of its own: its handle, its mapping and init's handle.

## Input

The compositor is the client of two input services of init's table: the
keyboard's (`input`) and the pointer's (`pointer`, a second instance of
`virtio-input` on a virtio-tablet). It asks each for the focus with a channel
of its own in GRANT, and the driver sends that channel the bit 1 whenever a
step put events into the ring; the compositor reads them (READ, up to 32 at a
time, without waiting) in its own step. The keyboard's focus is the first
revision's window's while that window lives: the keyboard then goes straight to
it whatever window has the focus (Doom reads its keys from the service itself,
as before; no image with a manager and a first-revision window exists, and the
base image has no manager) and the compositor's again when it goes. The tablet
reports `EV_ABS` `ABS_X` and `ABS_Y` from 0 to 32 767 across the screen and
`BTN_LEFT` as a key; the compositor scales them to the screen's 640 by 400. The
image of the probe (`table::focus`) has the tablet on the transport 13; the
base image has no tablet record yet, so its pointer is stage G2's probe image
only.

## pixman

The windows are put together by pixman 0.46.4 (MIT), built from its pinned
source by `tools/build-pixman.py` (`packages/pixman.toml`: version, URL and
SHA-256 of the archive) as a static library that `lib/pixman` links into the
compositor: its portable C paths, with no SIMD, no threads and no timers, over
the headers and the shim of `ports/pixman` (an arena of 32 KiB that pixman
allocates from, and the few functions of a C library it calls). Two files of
pixman are left out and replaced by one function each in the shim: the
combiners of the wide formats and the accessors of images, which windows of 8
bits to the channel never reach. The package installs no file: its licence
notice is the one the distribution carries for it
(`/usr/share/licenses/pixman/`), and `xtask packages` accepts it as a library
of a service (`SERVICE_LIBRARIES`). The copy of a band and the lay of a band over
the screen are pixman's SRC and OVER; the glue is `lib/pixman` and
`services/compositor/src/px.rs`.

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

`cargo xtask comp-probe` runs two clients on QEMU and compares QEMU's
screenshot with the CRC-32 the guest computed for the screen it should show:
a window, a rectangle of it posted alone, two windows, the black screen after
the first client ended, and a window of the first revision (pattern and a
rectangle). Under `-icount` it measures the steps of the compositor and of
the driver: every step stays under 0.9 of term B, and a band of a frame, like
a portion of the driver's clearing, under 16 328 ticks. `cargo xtask
doom-probe` runs Doom through the compositor.

`cargo xtask focus-probe` (stage G2) runs the compositor with a tablet, two
clients whose windows overlap (the second with an alpha), a manager and a
program that injects events, and compares QEMU's screenshot with the CRC-32
the guest computed after each step: the overlap with its transparency, a click
that gives the first window the focus and the top place, the manager's switch
on Alt and Tab, and the screen after the second client ended and the first
went on untouched. Each client's events must be exactly the list it expects:
the keys only while it had the focus, the focus changes, the click in its own
coordinates. QEMU's tablet then moves and presses through the monitor, and the
surviving window must see the click. Under `-icount` it measures the steps of
the compositor and of the tablet's driver (each under 0.9 of term B, a band
under 16 328 ticks).

## Not yet

The period of a frame and its counters, a window's resize, NEON paths of
pixman, a window manager as a program of its own (the probe's manager is a role
of `focus-probe`), the pointer in the base image, the layers of the display
controller and the bypass of the composition for one window, and the C
functions for windows in `libc.so` (a change of the ABI series).
