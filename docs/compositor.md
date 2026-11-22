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

- `proto_comp` (`proto/comp`): DESCRIBE, WINDOW_CREATE, ATTACH, POST, SET and
  STATS (the frame clock, "The frame clock" below). A
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
with no budget. On the frame clock the cap bounds the work of a period (the cap
below), so the service leaves the rest of the period to the levels below it, and one
client that posts without pause can still fill every period's cap. The cap is the one
bound of the service's share until the budgets of stage 5. In the free run (the image
of the measures) there is no cap and no period.

## Steps

Every step of the compositor stays under 16 500 ticks. A page costs the kernel
about 200 ticks to map and 80 to unmap, so ATTACH looks at its objects in the
step of the request and maps them a chunk of 32 pages a step, and its reply
comes after the last chunk; a window that went keeps its place, with its
pages, until its chunks are unmapped one step at a time. A buffer is a
megabyte at most.

## Opening the screen

The service opens the screen of the display driver at its start, with up to 150 tries 5 ms apart
while the driver says CLEARING, outside any step: the driver's frame buffer is 256 pages to map.
A driver that did not answer in those tries is asked again at the first request that needs the
screen (OPEN, WINDOW_CREATE or DESCRIBE). That late opening runs in the steps of the work, so no
step maps more than 32 pages (`CHUNK`, a page costs the kernel about 200 ticks).

The phase of the opening is `compositor::ScreenPhase`, a state of the host-tested library:

- `Closed`: no driver session. A request asks the driver (OPEN of `proto_gpu`); when the driver
  gives its buffer the phase becomes `Mapping`, the work bit is set, and the request is answered
  CLEARING.
- `Mapping { done }`: a portion of at most 32 pages is mapped a step, and `done` counts them.
- `Subscribing`, `Planes`, `Cursor`, `Pool`: one step each, after the last portion: SUBSCRIBE with
  the frame bit's handle, PIPELINES, the cursor's source (4 pages, mapped and filled), the pool's
  source (its 250 pages are then mapped by the steps of the pool, as before).
- `Open`: `screen` holds the driver's owner session, and the frame clock and the requests go on.

In every phase but `Closed` and `Open` a request that needs the screen is answered CLEARING (the
status the driver itself says while it sets up; clients ask again, `describe_when_ready` of the
probe does), and the frame clock takes no frame, since `screen` is `Some` only in `Open`. A refusal
of the driver at SUBSCRIBE, a page that cannot be mapped, a driver that went in the middle
(`PeerClosed`: the service ends, as everywhere else), and the stop of the service release the
pages mapped so far and the session (`ScreenPhase::release`), and the next request begins again
from `Closed`. The refusals of PIPELINES, of the cursor and of the pool leave the old ways (the
pointer drawn in the frame, OPEN of the first revision BUSY), as at the start.

`cargo xtask comp-late-probe` runs the probe comp-probe on an image whose compositor is built with
the feature `late-open` (no tries at its start), so the first DESCRIBE of the client opens the
screen from a request under `-icount`. It prints the longest step of the mapping work and the
longest of the finishing steps, and fails when either is past the gate of 16 328 ticks or a step
is past B.

## The frame

A frame takes the posted buffer of every window at its start, is made in
bands, a step each (the compositor's own bit starts the next band, so requests
of clients pass between bands). A band that only copies is eleven lines of the
damage's width under a window that covers the damage (at most 16 lines), and
fewer where it starts black. A band that lays something
over others (a window with an alpha, the pointer's picture) holds fewer points:
each shown window that touches the damage is a call of pixman, a price for each
of its lines and a price for each of its points (`compositor::PRICES`: the call
in ticks, the line and the point in hundredths of a tick, for a copy, a layer
laid over others and the black; the upper fit of the model over the greatest
ticks measured on 26 shapes of operations under -icount, with a margin of 15 %:
the model errs only high), and a band holds the lines of the damage's width that
14 000 ticks (`BAND_TICKS`, the work of a band by the model: the step around it costs about 1 080 ticks more, so a band of eight windows stays under 15 800 of the gate of 16 328) leave after its calls, a fixed term for every band (`BAND_FIXED`, 644 ticks: what `compose` spends around its operations in a band of no layer, 560 measured, with the margin) and a term for every layer (`LAYER`, 288 ticks: 250 measured on the real bands, with the margin), down the damage and across it, so that eight windows in one band stay
under the bound (the shapes measured go up to the width of the screen), and then goes to the driver
as COMMIT of the changed rectangle. COMMIT is proto_gpu's second revision:
SUBSCRIBE gives the driver the compositor's channel once, COMMIT answers as
soon as the commands are in the device's queue, and the driver says
`FRAME_SHOWN` (or `FRAME_FAILED`) on that channel when the device is done.
FLUSH of the first revision still waits inside the driver, for the programs
that speak to the driver directly (the image of `gpu-probe`).

Under a scene each element is charged by its class (`elements::classes`; the rows of
`compositor::PRICES` after the black, the copy and the laying over): a stretch, turn or
reflection with the nearest point or the bilinear mean, a copy or a laying over
(`scale-nearest-copy`, `scale-nearest-over`, `scale-bilinear-copy`,
`scale-bilinear-over`), a turn of a quarter with no stretch (`rotate90`, which pixman has
a path of its own for), and a global alpha, a mask, or both with the points as they are
(`alpha`, `mask`, `mask-alpha`); a stretched or turned element with an alpha or a mask pays
for the stretch as a laying over and for the rows and points of the alpha or the mask
(the sum errs high: both prices carry the combine). The prices are fitted to the shapes
`px::calibration` measures under -icount for each kind (the shapes of the plain kinds
narrower than 160 points, at two offsets of the target for the kinds that have a path of
NEON of their own, with the source in both formats for the kinds that mix), with the margin
of 15 % as for the plain ones; `services/compositor/src/measures.rs` holds the greatest
ticks of every shape, and the test `the_constants_cover_the_measures_with_the_margin` holds
the model at or above each by the margin. The call of the general path of pixman
(`scale-*`, `alpha` and `mask` with a source of XRGB8888) is 5 700 to 6 000 ticks, against
800 for a plain copy: the path clears three scanline buffers of 8 KiB on its stack before
every operation (the shim's `memset` of `ports/pixman` does that in a fifth of the ticks
the compiler's own took, and its allocator keeps the small blocks pixman makes and gives back
with every call, a transform or a solid colour, in lists of their sizes), so a dear element is a part of a line and the dearest (a
bilinear stretch with a mask and an alpha: about 10 000 ticks of calls) fills a step
with the calls alone.

The layers of a band that cost more than a step holds are drawn in groups, a step each
(`Scene::passes`, `Band::pass`): the elements that show something over the damage, in
order, go to a group while its calls come to at most half of BAND_TICKS (`GROUP_CALLS`), a
layer dearer than that is a group of its own, the black of the band is in the first group
and the pointer's picture in the last; a place of the frame is as big as the dearest group
allows, and its groups are drawn one after another on it, in order, so the picture is the
one of the single step. A group with nothing to draw on the place is no step. A step of a
scene also pays `ELEMENT_TERM` ticks (130 with the margin of 15 %) for every element that
shows something over the damage: it makes the groups and asks each element if it has
something on the band. A dear scene is therefore many steps (sixteen of the dearest elements, each a bilinear
stretch with a mask and an alpha, leave a step of one point after the calls of its group
and the terms of the sixteen elements), which shows as `capped` and `late` in STATS; the
cap of 47 bands a period stays.

The calibration of the kinds measures calls that repeat, which find their path in pixman's
cache of 8 resolved paths. A call whose path is not in the cache scans the tables of every
implementation: 4 546 ticks more at the most (`LOOKUP_MISS_MEASURED`, the greatest over the
kinds and over the two variants of the flags, inside the source and at its edge, of a call of
one point after eight calls of other keys less the same call repeated; the line `service
lookup` of the steps build). An element with a transform has two keys, so a scene of 16
has up to 32 and the cache is lost on every band; under a scene every layer of an element
pays `LOOKUP_MISS` (the measure with the margin, 5 228 ticks) with its call, in `Scene::passes`
and so in `tile`, and the alpha or the mask of a stretched element adds its rows and points
to the one call of the stretch. The windows with no scene have three keys and the pointer's,
all warm, and are priced as before. A layer that misses is a step of its own, and the dearest
fits one (a test holds it). The longest steps of `comp-probe` under -icount are 16 289
ticks against the gate of 16 328.

The steps build paints the stack of the service at its start and tells the deepest word
written (`service stack`); the probe's scenes of every kind of element take it to 74 672
bytes of the 131 072 of the stack.

The images pixman wraps around the buffers are kept in a ring of 32 (`lib/pixman`,
`kept.rs`), the oldest going when a new one comes, and each is made when its buffer is
posted (`Pixman::prepare`), so that no band makes it. The table also remembers, for each surface the
service names (`compositor::image_of` for the buffer of a window, `POINTER_IMAGE` for the
pointer's picture, and one slot for the screen), the slot it last found the image in, so
that a lookup in a band is one comparison whatever the table holds. A remembered slot is a
guess: it is used when the key stored in the slot is the one looked for, and otherwise
(another surface took the slot, or the surface is new) the ring is looked through, at most
32 entries, and the slot is remembered again, so a stale slot never gives another buffer's
image. A band can still look through the ring when a surface was not prepared (a window of
the first revision, whose buffer is read by its first band), or when 32 newer images have
pushed one out (a long run of windows made and closed): the step then says the images the
band made in its detail (1000 plus their number). The feature `irq-trace` and the pixman
feature `scan-count` count the entries looked at, for the probes.

The prices are measured under -icount, where time is instructions: there is no
cold cache, no miss of a translation and no first touch of a buffer (the buffers
are mapped in advance), and pixman's table of fast paths, the one cache that can
be cold, is warmed at the start with the three combinations the service uses. On
HVF and on a board a cold cache shows in the measures. The lines `service raster`
of the probes are wall time, and the greatest of them holds the levels above that
ran in the middle and the interrupts (a 640 by 8 copy shown at 3.64 a point is
about 18 600 ticks, while the band step that holds it is at most 10 528 of the
thread's own time): only the lines of the steps judge a band.

## The frame clock

The compositor starts its frames at the periods of a clock, `t0 + k * T`, where
T is 16 666 667 ns (60 Hz) unless the own arguments of its record say another
(two words of 8 bytes: the period in nanoseconds, from 1 ms to 1 s, and the cap in
millionths of the period; anything else is the defaults, and the console says so).
A change (a POST, a window going) waits for the start of the next period: an
absolute timer of the service's own channel fires at it and takes the frame
(`timer_set` on the `clock_now` scale), and a stale expiry (a timer that fires after
the frame it was set for was taken some other way) does nothing. A period holds
at most the cap of work: 750 000 millionths of T, counted in bands at the gate of a
band (`BAND_GATE`, 16 328 ticks of 16 ns, 0.8 of term B, the same number as the portion
gate of the probes), which is 47 bands at 60 Hz (`frame::band_cap`, the one function the
service and the probes use). The service then takes at most 47 bands at their gates and
three steps of 18 369 ticks, 822 523 ticks or about 79 % of a period, and the levels
below it keep the rest. The cap is not in the free run. The band that reaches the cap only says so: the arming of the timer for the next
start is a step of its own (the service's own bit `ARM`), because the kernel call of
`timer_set` would make the longest band longer than its gate. The steps of the service
say what they are in their detail: 1000 plus the images made for a band, 2000 the
taking of a frame, 3000 the commit after the last band, 4000 the end of a frame, 5000
a step of the housekeeping and 6000 the arming after the cap. Between the band and the
arming step nothing takes a frame (a taking needs an expiry, and the timer is not armed
until the step) and a request that comes arms nothing (the bands are put off); a start
that has gone by when the arming step runs is armed as it is and the bands go on at once. The bands the cap puts off go on at the start of the
next period, so a large frame spans several periods and the clients' requests,
and the service's own steps, pass between its bands as before.

A window can promise an interval between its posts with SET (INTERVAL, 0 to 4
periods): its buffer is taken at most once in N periods, and the service counts a
post after the start it was awaited at as late and a window that posted nothing by
the next start as missed (a window of the first revision has no interval). STATS
(a session of the manager or the input service may add RESET) answers the 17
counters of the clock (`proto_comp::Stats`: frames, late, skipped, capped, wakeups,
the longest take, compose, device wait and frame in microseconds, and others; the
definitions are below), a histogram of the time from the start of a period
to the frame shown (33 buckets of T/16, the last for 2T and more) and a record of
32 bytes for each window (its id, interval, posts, takes, replaced buffers, late, missed and the
greatest lateness in microseconds). Both are in `proto/comp` with their layout and the rule for the
client's free buffers: it keeps its own mask for the life of the window and posts
only a buffer whose bit is set.

The counters are these. The time of a frame is the time from the start t(k) of the
period a frame was taken at to the step that sees FRAME_SHOWN; the time to compose is
from t(k) to the commit; the delay of a taking is from t(k) to the step that takes the
frame; the time of the device is from the commit to FRAME_SHOWN. `late` counts frames
shown strictly after t(k+1); `skipped` the periods between the start a change was
owed and the start its frame is taken at, when the taking comes later: a frame was still in
work, the cap had put its bands off, or the service got no CPU at the start (a taking that
finds nothing to take is not a frame and gives its `releases` count back, and the periods it
passed stay counted); `capped` the periods in which the cap put bands off; `wakeups` every
expiry of the frame's timer except a `Fire::Early` one, the expiries that find nothing to do
(`Fire::Idle`) included; `failed` the frames the device failed; `band_max_us`
is the longest step of a band by the wall. `period_us` is the period, 0 in the free
run, and `cap_us` is the value of the model: the cap's bands at their gate, at 16 ns a
tick (the counter of a run under -icount, 62.5 MHz). On HVF and on a board `cap_us`
does not match the wall.

Each STATS tells the phases of the late frames of the count that it has not told yet, two at
most, from the first four late frames of the count, one line each to the console:
`compositor: late frame period K take A us compose B us device C us frame D us (the longest: P)`.
The take is the delay of the taking after the start of the period, the compose the time from the
taking to the commit, the device the time from the commit to FRAME_SHOWN, and the three add up to
the time of the frame; P names the longest of the three. The line tells which phase overran. The
bound `frame::bound` of the scene covers the take and the compose (and the driver's own step in the
term of the display driver). The device's own time is the emulator's: under `-icount` the virtual
time of a wait for an emulated device moves with the host's scheduling of QEMU's main loop (the
device's work is a bottom half there), so the time of the device in a run on a loaded host is
longer than the model's and is the longest phase of a late frame that is late for that reason.

An expiry of the timer that arrives before the time the timer is armed for is
`Fire::Early`: the kernel delivers the expiry of an earlier deadline that `timer_set`
has moved since. The service does nothing, the timer stays armed and no wakeup is
counted.

The free run is a period of 0: no timer, a frame as soon as the device is ready and
no cap, the behaviour before the clock. The record `COMPOSITOR_KEYS_FREE` of
`services/init/src/table/comp.rs` has it, and only the image of the measures
(`boot-doom-steps.img`, the table `table-doom-free` of init, which `doom-measure`
boots) uses it so that the frames a second stay comparable with the series; the
games image of the release (`boot-doom.img`) and every other image run at 60 Hz. The pure part of the clock is `services/compositor/src/frame.rs`
(the periods, the cap, the windows' pace, the histogram and the response-time bound
`frame::bound` with the terms of the tables), which the host tests pin; the wiring is
in `main.rs`.

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

## The scene

A scene session (a label with `SCENE_MARK`, bit 54 of the label, which init gives
the clients that `COMP_SCENES` names, records of POSIX included) is a context
and a manager both, and holds a scene: the windows on the screen are the
elements of the last scene it committed, in its order from the lowest, each
with the window it shows, the rectangle of the window it takes the points from
(16.16 points), the rectangle of the screen it puts them in, the turn and
reflection, the filter, the kind of transparency, a global alpha and a mask
(`proto_comp::Element`, 56 bytes; up to 16 of them in a message of 916 bytes).
The window is the `id` WINDOW_CREATE answers: its place in the table (3 bits)
and the count of windows made at that place (`proto_comp::window_id`), so the id
of a window that went is no window's again. LIST, the events CREATE and CLOSE
(the id is their `value`; `code` is the place) and MANAGE carry the same id. An
element whose id names no live window shows nothing and holds no buffer, also
when the holder commits with the id of a window that went before it read the
CLOSE event; `NO_WINDOW`, 0xFFFFFFFF, names none. A
mask is a window of the new format `FORMAT_A8` (a byte a point, a stride that is
a multiple of 4), the size of the target rectangle; a window of that format is
never shown by itself. `<stafeto/window.h>` has it as `STAFETO_WINDOW_A8`.

How a scene reaches the screen:

- SCENE_COMMIT keeps the scene as the pending one. A taking of a frame makes the
  last pending scene the working one whole, and the bands of a frame read the
  working one alone. A commit that comes in the middle of a frame is in the
  frame after it, never half in this one. The flags: ACTIVE (the scene is
  composed at the start of a period that has a change in it or in a window it
  shows) and ASK_COMMITTED (the bit COMMITTED, bit 4, goes to the channel the
  session subscribed with when the scene is taken; for a scene that is not
  ACTIVE, which only SCENE_COMPOSE composes, at once).
- SCENE_COMPOSE (a scene that is not ACTIVE; UNSUPPORTED for one that is) makes
  one frame at the next taking, and the bit COMPOSED (bit 5) tells the session
  the frame is over; BUSY while an earlier request is not. The buffers of the
  windows the elements show are not taken between requests. With no commit before
  it the scene is the empty one: the background alone.
- The damage of a frame is what changed: the target rectangles of the elements
  that came, went or changed in any field, and for a posted buffer its changed
  rectangles carried through the element (turn, reflection and stretch, a point
  more on every side for the bilinear filter). The whole screen when the
  background changes or the scene is the first.
- A window that no element shows keeps the last buffer it posted as its current
  one at the taking, and the buffer that was current is free at once (the bit of
  its number). An element added later shows that picture in its first frame
  (a static background, a board, a mask). A FLUSH of a window of the first
  revision on such a window is answered at once, so a program of the first
  revision under a scene does not wait for a frame that has none of it.
- The background is a colour: the first thing a band holds where no opaque
  element covers it whole (the same call as the black of a band, so the same
  price).
- The direct frame (above) stays: the topmost element that shows something is
  the whole of a window of the first revision on the whole screen, with no turn,
  reflection, mask or transparency.
- The service draws every element the numbers allow: the source rectangle (16.16
  points of the window, a fraction of a point is fine) turned by the rotation and
  reflected, stretched to the target rectangle, sampled by the nearest point or the
  bilinear mean (the points outside the window are its edge's), and mixed as the
  transparency says: none copies the points (the alpha byte is not read), the
  window's own alpha lays them over, the global alpha and the mask multiply them
  (the window's own alpha counts only when its bit is set), the mask is an A8 window
  of the target rectangle's size and is not stretched. SCENE_COMMIT refuses
  the numbers no drawing could make sense of with INVALID (a source rectangle past
  its window, a mask that is not an A8 window of the target's size, an out of range
  field). The meaning of every field, point by point, is `proto_comp::meaning`,
  which the host tests and the probe hold the drawing to. A plain element (the scale
  of one on whole points, no turn, no reflection, none or the window's alpha) is a
  copy or a laying over as before; the others are one call of pixman through its
  transform (`elements::matrix`: the steps are the source sides over the target
  sides rounded to 16.16, an error of half a unit a point), and a mask with an
  alpha is made in the work band first (an A8 surface of 16 lines of 640 points)
  and laid on as the mask.
- Input: the keys go to the window with the focus (the scene gives it with MANAGE
  FOCUS); the pointer's moves and buttons go to the scene's ring as events of the
  screen's coordinates and to no window. The pointer's picture is the cursor
  pipeline's, as it was.
- While a manager (`MANAGER_MARK`) holds the subscription, the scene session's
  SUBSCRIBE, SCENE_COMMIT and SCENE_COMPOSE are BUSY, so the pointer never goes
  to the manager under a scene. From the scene's first commit, or its
  subscription, a session with `MANAGER_MARK` is NOT_ALLOWED in MANAGE. A second
  CONNECT of the holder (a second session with the mark) is BUSY in SCENE_COMMIT
  and SCENE_COMPOSE while the first holds the scene. A window of FORMAT_A8 gets
  neither the focus nor the top place. When the session ends the windows
  show as the policy of the windows says, from the next frame, the whole screen
  drawn again. The children of a process that holds a scene (a clone of its
  session) get an ordinary context; `exec` keeps the session.

`proto_comp::VERSION` is unchanged: the two methods are new numbers (26, 27) in a
session that only the scene session can use.

## OpenWF Composition for C programs

A C program shows a scene with the functions of `<WF/wfc.h>` (the Khronos
header of OpenWF Composition 1.0, unedited, in `ports/openwf/include/WF`, with
`wfcext.h` unedited, `wfcplatform.h` adapted to this system and
`wfcext_stafeto.h`, the one extension). The functions are a static library, as
those of windows: the Rust crate `lib/wfc` holds the rules (handles,
attributes, the order of the elements, the commit that builds the scene record,
the translation of the service's refusals, 176 host tests by clause of the
specification, the table in `lib/wfc/CLAUSES.md`), `posix-abi` with its feature
`wfc` the calls (`wfc.rs`) and `posix-crt` with the same feature the C functions
(`wfc_c.rs`). `libc.so` is built without the feature, so the ABI of the series 0.6
is as it was, and `tools/build-libc-so.py` refuses a build of `libc.so` that
defines a name `wfc[A-Z]` or `wfd[A-Z]`. A program that uses it is statically
linked (`apps/wfc-demo` is the model) and compiles with `-I ports/openwf/include`.
The headers carry the Khronos notice of the Materials in their first lines, which
stays with them.

- **Who may hold a scene.** The process whose `Display` session has the scene's
  mark: init gives it to the records `COMP_SCENES` names (`wfc-demo` and
  `comp-probe-s`), a record of POSIX included. `wfcCreateDevice` of any other
  process answers no device: its MANAGE is refused. A child of the holder
  (`posix_spawn`, `fork`) has a clone of the session, which has no mark, so it
  makes no device and is an ordinary client. A program that init starts cannot
  fork (the layer answers EAGAIN), so the holder starts the producers with
  `posix_spawn`.
- **Streams.** A `WFCNativeStreamType` is the number of a window of the service,
  the `id` of WINDOW_CREATE. `wfcNextStreamSTAFETO(dev, timeoutMs, &stream)`
  waits for the creation of a window (the scene's ring, up to 32 numbers kept)
  and gives its number. A source is made of the window of a producer, a mask of a
  window of the format A8 (the process has one window; make the mask's window in
  the holder). The service's LIST gives a window's size and no format, so the
  library takes the format as unknown at the creation and the service refuses a
  wrong kind at the commit.
- **Calls.** Every attribute, element and the order of the scene lives in the
  library and is cached until `wfcCommit`, which sends one SCENE_COMMIT (up to 16
  elements, the context's rotation folded into each element). `wfcCompose` sends
  SCENE_COMPOSE for a context that is not active; `wfcActivate` and `wfcDeactivate`
  change the flag of the last committed scene. With `wait` the calls wait for the
  bits COMMITTED and COMPOSED.
- **Limits.** One screen (number 0) and one context, from any device: a second is
  `WFC_ERROR_IN_USE`. No off-screen context (`wfcCreateOffScreenContext` answers
  `WFC_ERROR_UNSUPPORTED`), and `wfcFence` answers `WFC_ERROR_ILLEGAL_ARGUMENT`
  (there is no EGL). Up to four devices, 16 elements, 8 sources and 8 masks for
  each. The device reports the class fully capable, which section 4.1.1 of the
  specification ties to off-screen contexts: a departure.
- **Threads and signals.** Each device has a lock held for a whole call, a wait
  included, so a waiting thread blocks the calls on its own device and no other;
  the lock is no critical section of the layer, so a signal's handler runs while a
  call waits and the wait goes on. The functions are not async-signal-safe: calling
  one from a handler that interrupted a call of the library, or leaving a call with
  `siglongjmp`, is undefined.
- **`fork` and `exec`.** The child of a fork has no device (the table, the locks
  and the handles of the channel are reset). `exec` closes the channel and the
  timer and drops the devices; the session stays with the new image, and so does the
  scene the old image committed, with elements that may name windows that went (they
  show nothing), until the new image commits its own.
- **Cost of a scene.** The layers of a scene are drawn in groups, each with
  bands sized from its own dearest element, and a stretch with no turn and no flip
  has a path of its own in pixman. The elements of the demo's scenes (a stretch, a
  quarter turn, a flip, a global alpha, a mask, the bilinear filter) are therefore
  all in the probe; the times of their frames are in `docs/openwf.md`. A flip or a
  turn by 180 degrees with a stretch still uses the general path of pixman, so a
  large flipped element makes its group's bands a few points wide. A scene that needs
  a frame in each period keeps its dear elements few (`compositor stats` tells the
  bands of a frame).

`cargo xtask wfc-probe` runs `apps/wfc-demo` in `boot-wfc.img` (the table
`table::wfc`: the services of the POSIX probes, the driver, the compositor and the
demo, which starts `tests/wfc-producer` three times). Two scenes of three elements
(a stretch, quarter turns, a flip, a global alpha and a mask) over two patterns and a
mask are committed in turn 100 times and each composed on request, and QEMU's screenshot has the CRC of `tools/wfc-ref`, the host's frame of
the same calls drawn point by point from `proto_comp::meaning`; then the context
is active and the scene changes 100 times while screenshots are each one of the
two; then scene D (the bilinear filter) is committed once and its frame time is
printed; then scene C shows the window of the first revision straight from its buffer
(the screenshot is the producer's gradient, and the trace of the device shows the
scanout on resource 2). The second half runs under -icount and judges the steps of
the compositor and the driver. The demo is a program of the probe image and has no package:
the scene's mark comes from init's table, so a copy started from a shell holds no
scene.

## Not yet

A window's resize, a frame clock that follows the display's own vertical blank
(the period is the service's, and the free run is the only way without it), the
sharing of the cap between clients, a call of pixman for the parts of windows that
do not overlap (eight translucent windows on one place cost eight calls a band, and
the worst scene, eight of them over the whole screen, is 15 bands a line and 6 000 bands
a frame: 128 periods at the cap of 47, 2.1 s at 60 Hz under -icount; eight of 320 by
200 points are 1 600 bands and 35 periods; a copy of the whole screen that no window
covers is 50 bands and 2 periods), the window manager
and the keyboard in the base image (the manager's image is the probe's), the
pointer in the base image, the layers of the display
controller, a window of the second revision shown directly (the flag `SCANOUT`
of WINDOW_CREATE is reserved), and the C functions for windows in `libc.so`
(a change of the ABI series, 0.6; the static library above has them now, and
`docs/lvgl.md` tells the program that uses them). `docs/openwf.md` is the page
for the OpenWF interfaces.
