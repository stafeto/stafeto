# Text and widgets: LVGL, FreeType and the windows of C programs

The demo `lvgl-demo` draws a screen of widgets with text from a TrueType font
in a window of the composition service (`docs/compositor.md`). It is a
statically linked C program on relibc: the library of windows
(`<stafeto/window.h>`) gives it the window, FreeType rasterizes the glyphs,
LVGL lays out and draws the widgets. Every pixel of a frame comes from integer
arithmetic on one thread, so the same sources give the same frame on every
run and on every machine, and a probe can hold the guest's frames to a
reference program on the host.

## The window library for C programs

A C program makes windows of the second revision of the display interface with
the functions of `<stafeto/window.h>` (`lib/posix-crt/window/stafeto/window.h`):
`stafeto_screen_describe`, `stafeto_window_open`, `_post`, `_free_buffers`,
`_wait`, `_events`, `_shown` and `_close`. The header and the rules of each call
are in `docs/compositor.md`, "The C library of windows". In the series 0.5 of
the ABI the functions are a static library: the Rust crate `posix-crt` carries
them under its feature `window`, `libc.so` has none of them, and the header lies
outside the sysroot of `libc.so`, so the ABI fingerprint is as it was
(`cargo xtask abi --check`: "series 0.5 frozen, no change"). A program that
uses windows is linked statically with relibc's `libc.a`. The series 0.6 moves
the library into `libc.so`, adds the descriptor for `poll` and lets a program
be dynamic; the source of the demo does not change, only the way it is linked.

## The ports

**FreeType 2.14.3** (`packages/freetype.toml`, the FreeType Licence, FTL;
`tools/build-freetype.py`, `ports/freetype/{ftoption.h,ftmodule.h}`). Built:
the TrueType driver with its byte-code interpreter (version 40 rules), the
sfnt container and the smooth rasterizer, from eleven files of the source into
`libfreetype.a`. Left out: the automatic hinter, the other font formats
(Type 1, CFF, PCF, BDF, PFR, Windows), the other renderers (the monochrome
one, SDF, SVG), the compressed fonts (gzip, bzip2, LZW), PNG, HarfBuzz,
Brotli, the LCD filter, variable fonts, the properties read from the
environment, the debug and trace code.

**LVGL 9.6.0** (`packages/lvgl.toml`, MIT; `tools/build-lvgl.py`,
`ports/lvgl/lv_conf.h`). Built: every C file of `src` but
`osal/lv_linux.c` into `liblvgl.a`, with one thread, integer drawing into
XRGB8888, LVGL's own allocator over a pool of 512 KiB in `.bss`, only the
widgets of the demo (label, button, check box, switch, slider, text area,
image for the theme), the default theme and FreeType for text. Left out: all
drivers and boards, the file systems, the image decoders, vector graphics,
the system monitors, the profiler, flex and grid layouts, and the demos and
examples of LVGL.

**Determinism.** The glyph path is integer arithmetic: the outline of a glyph,
the scale by `FT_MulFix` in 64-bit integers with no assembler, the hinting by
the interpreter's integer machine, the smooth rasterizer's 8-bit coverage,
and in LVGL no floating point (`LV_USE_FLOAT` 0) and no assembler
(`LV_USE_DRAW_SW_ASM` none). The builds use `-funsigned-char` (the `char` of
AArch64 Linux), `-fwrapv` and `-ffp-contract=off`. The build scripts guard
this after each build and stop with the names they found:

- the archive's SHA-256 is the one of the package record;
- the macros the compiler ends up with (the defaults of LVGL included) are the
  settings that fix what is drawn: one thread, no floating point, no
  assembler, no file system, no monitor, only the widgets of the demo;
- the names the objects leave undefined are an exact list of relibc's
  functions (each defined in relibc's `libc.a`) and the functions of
  `libfreetype.a`; no thread, loader, mapper or libm function, no `getenv`,
  no call of `FT_Property_Set` or of the LCD filter, and no text
  `FREETYPE_PROPERTIES` is in an object;
- no object holds the build directory's path (the sources are built with
  `-fmacro-prefix-map`).

`tests/` of the scripts (`tools/test_build_freetype.py`,
`tools/test_build_lvgl.py`) check the configuration files and these rules on
samples and on planted faults. The licences and the records are in
`docs/packages.md`.

## The demo and its contract

`ports/lvgl` holds the demo as plain C over a small contract (`demo.h`): the
host program supplies two XRGB8888 buffers of 640 by 400 points, a post of a
finished frame with the rectangles that changed, a wait for a free buffer, the
events that arrived, the time and a log line. The demo never names a window.
`scene.h` fixes the places of the widgets and the 22 events of the scenario,
and is the one source of both for the demo, the reference program and the
injector (a host test of xtask compares the injector's rows with it).

The screen: a title (FreeType, 22 pixels), a paragraph of two lines (16
pixels), a button with a counter, a check box, a switch, a slider with its
value and a one-line text area (placeholder "Type here", the cursor does not
blink). LVGL draws in the direct mode with two buffers: it copies the areas of
the last frame into the buffer it is about to use, posts the areas of the
current frame, and before drawing waits for the buffer the service gives back
at the end of the frame that replaced it.

Drivers over the window library: `stafeto_display.c` posts a frame and waits
while the library's mask of free buffers lacks the buffer LVGL will draw into
(a wait of at most one second at a time, and a line only when a wait runs out
of its second), `stafeto_input.c` takes the events of the window's ring
without waiting, and `main.c` runs the loop. In normal mode the clock is the
monotonic clock, input goes to LVGL as it comes and the program sleeps in the
wait for the service's bits.

In probe mode (`lvgl-demo --probe`) the pixels must not depend on timing:

- the clock of LVGL is virtual, 16 ms for each turn of the loop;
- the program collects all the changes of the scenario (the 16 keys and
  buttons going down or up) before the clock runs, waiting through the host's
  idle against a real-time deadline; the compositor delivers no move to the
  place the pointer is at, so the wait ends when the changes have come, whatever
  the count of events, and when the deadline passes the demo lists the events that did
  come, in order;
- `schedule.c` hands LVGL one input change at a time, the next only after
  the frame has settled: a turn with no frame drawn, no redraw pending and no
  animation running, after one more read of the same device. A button stays
  down for about 100 ms of the virtual clock, under the 400 ms of a long
  press, whatever the speed of the machine.

The scenario (`scene.h`): click the button twice (at two points of it), the
check box, the switch, the slider (to three quarters), the text area, then
type `h` and `i`. After it the state is `presses 2 option 1 switch 1 slider 75
text hi`.

## The host reference

`tools/lvgl-ref` is the same demo, LVGL and FreeType code compiled for the host
(`python3 tools/build-lvgl.py --host`, into `target/lvgl-host/`) with memory
buffers. It prints the CRC-32 of the R, G, B bytes of the first settled frame
and of the frame after the scenario, the state, the turns and frames of the
loop and the largest use of LVGL's pool; with `--evidence` also the
determinism evidence of the glyph path (for `a g W 0` at 16 pixels the number
of points and the CRC of the hinted outline after `FT_Load_Glyph` with no
rendering, the bitmap's width, rows, pitch, left, top, advance and the CRC of
its buffer; the multiple-masters flag; the kerning of `AV`; and, on the host
alone, the interpreter version, 40) and the CRC of each of the 25 bands of 16
rows of both frames. The glyph flags are those of LVGL: `FT_LOAD_NO_AUTOHINT`
with `FT_LOAD_TARGET_NORMAL` and `FT_RENDER_MODE_NORMAL`.

The events can be fed in several ways, and the frames must not change:
`--feed batch` (all at once), `--feed single` (one at each look of the demo),
`--feed gap N` (one at every Nth look, a slow injector), `--drop-same-move`
(leave out a move to where the pointer is, as the compositor does) and
`--merge-moves` (merge adjacent moves into the later one). The reference opens
the font under a relative path as long as the guest's, because LVGL keeps the
path in its pool and the pool's largest use is compared exactly.
`tools/test_lvgl_port.py` pins the values below, runs every feed mode and shows
planted faults failing: a change handed out before the frame settled, x and y
swapped in the hand-out of the pointer, and events not collected before the
clock runs (a slow injector then makes key repeats: `text hhii`, `text
hhhiii`).

## The probe

`cargo xtask lvgl-probe` boots `boot-lvgl.img` (the shell, the compositor with
the tablet's driver and the injector `lvgl-inject`), types `lvgl-demo --probe
--evidence` into the shell and takes QEMU's screenshot after each of the demo's
two CRC lines. For each frame three CRC-32 must be equal: the demo's, the
screenshot's (the path from the demo's buffer through the service and the
driver to the screen) and the host reference's (the arithmetic of LVGL and
FreeType). Besides the frames the probe compares exactly the state line, the
turns and frames, the glyph evidence lines (all but the interpreter's, which
the guest cannot print), the CRC of every band of both frames (a difference
names the bands that differ and says whether the evidence agrees), the largest
use of LVGL's pool, and the events the demo took by kind (4 keys, 6 moves, 12
buttons, none lost). A fault line, an unknown line or a doubled line fails it,
and so does a missing screenshot anchor, with the lines of the demo. On QEMU's
own emulation a second run under `-icount` on `boot-lvgl-steps.img` repeats the
comparison and holds the steps of the compositor, the display driver and the
tablet's driver to the bounds (0.9 of term B per step, 16 328 ticks per
portion). The probe's tests (`xtask/src/lvgl.rs`) run on sample logs.

## By hand

```sh
cargo xtask lvgl                  # QEMU's own emulation
cargo xtask lvgl --machine hvf    # Apple's Hypervisor, on a Mac
```

QEMU opens a window for the screen and keeps the console in the terminal. At
the prompt of ash type `lvgl-demo`; the injector of the probe plays the
scenario once when the window opens. Click the button, the check box, the
switch and the slider with the mouse (the tablet). The keyboard of the window
does not reach the demo: the image has no keyboard's driver, because the
keyboard and the tablet share a page of transports. Ctrl-C in the terminal
ends the demo; Ctrl-A X quits QEMU.

## Licences

The program links the demo's own files and LVGL (MIT), FreeType (the FreeType
Licence; its credit line, "Portions of this software are copyright © 2026 The
FreeType Project (https://freetype.org). All rights reserved.", is in the
notices of the package and in the notes of a release), relibc (MIT) and the
POSIX layer (GPL-3.0-or-later with the GCC Runtime Library Exception, which
lets a program of any licence link it). The font, Liberation Sans Regular, is a
data file under the SIL Open Font License 1.1, installed as
`/usr/share/fonts/LiberationSans-Regular.ttf` with its licence text in the
notices. FTL is not compatible with GPL-2.0-only, so no GPL-2.0-only program
links FreeType.

## Figures

The first green run of the probe (the third run on GitHub's runners):

| What | Value |
| --- | --- |
| first frame, CRC-32 | `450D7460` (demo, screenshot and host reference) |
| frame after the scenario | `DDBD81B9` (the same three) |
| loop | 111 turns, 64 frames |
| LVGL's pool, largest use | 70 120 bytes |
| events taken | 4 keys, 6 moves, 12 buttons, focus in 1, lost 0 |
| memory of the process | 515 pages in objects of their own, heap 196 608 bytes, against the quota of 3 072 pages of a shell child in the games table (the plan estimated about 1 650 pages in all) |
| steps under `-icount` | the compositor's longest step 9 571 ticks, under the bound |

The program `lvgl-demo` (release build, measured on the main of the merge of
stage G4): text 1 074 604, data 39 504, bss 645 849 bytes (the bss holds the
512 KiB pool); the file the image carries, stripped, 1 121 784 bytes; no
`DT_NEEDED`; `PT_GNU_STACK` 256 KiB. `liblvgl.a` 1 988 180 bytes, `libfreetype.a`
362 120. The package `lvgl-9.6.0-1.stpkg` is 1 585 152 bytes (the program, the
font of 410 820 bytes, the licences and the notices). The games image grows by
that much; `boot-lvgl.img` is 10.5 MB.
