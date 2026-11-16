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
bands of eight lines, a step each (the compositor's own bit starts the next
band, so requests of clients pass between bands), and then goes to the driver
as COMMIT of the changed rectangle. COMMIT is proto_gpu's second revision:
SUBSCRIBE gives the driver the compositor's channel once, COMMIT answers as
soon as the commands are in the device's queue, and the driver says
`FRAME_SHOWN` (or `FRAME_FAILED`) on that channel when the device is done.
FLUSH of the first revision still waits inside the driver, for the programs
that speak to the driver directly (the image of `gpu-probe`).

The header version of proto_gpu stays 1 in revision 2. The loop of a service
takes one version, and the series 0.5 of the ABI (`packages/abi.txt`) holds
the version in the programs built for it. `proto_gpu::REVISION` is 2.

## Checks

`cargo xtask comp-probe` runs two clients on QEMU and compares QEMU's
screenshot with the CRC-32 the guest computed for the screen it should show:
a window, a rectangle of it posted alone, two windows, the black screen after
the first client ended, and a window of the first revision (pattern and a
rectangle). Under `-icount` it measures the steps of the compositor and of
the driver: every step stays under 0.9 of term B, and a band of a frame, like
a portion of the driver's clearing, under 16 328 ticks. `cargo xtask
doom-probe` runs Doom through the compositor.

## Not yet

The pointer and the keyboard focus of several windows, events in the client's
ring, the period of a frame and its counters, pixman, transparency, a window's
move and resize, the layers of the display controller and the bypass of the
composition for one window, and the C functions for windows in `libc.so`
(a change of the ABI series).
