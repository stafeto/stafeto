# Playing Doom

The games image (`boot-doom.img`) is the shell image with Doomgeneric
(`/bin/doom`), the Freedoom data (`/games/freedoom1.wad`) and the services
of the screen and the keys: `virtio-gpu` (a 640 by 400 screen, XRGB8888)
and `virtio-input` (the keyboard). The game is a program on `libc.so` that
calls `stafeto_display_open`, `stafeto_display_flush` and
`stafeto_input_read` (`<stafeto/display.h>`); the screen and the keys belong
to the process that owns the screen.

## Play by hand

```sh
cargo xtask doom                  # QEMU's own emulation
cargo xtask doom --machine hvf    # Apple's Hypervisor, much faster on a Mac
```

QEMU opens a window (cocoa on a Mac) for the screen and keeps the console
in the terminal, where ash prompts. Type

```sh
doom -iwad /games/freedoom1.wad
```

and the game opens in the window, which takes the keys: arrows move and
turn, Ctrl fires, Space opens doors, Shift runs, Alt strafes, Esc opens the
menu (Quit Game and `y` leave Doom with code 0). Ctrl-C in the terminal
ends Doom too. The screen goes back when Doom ends and `doom` can run
again. Ctrl-A X in the terminal quits QEMU. There is no sound, network or
saved game.

## The probe of the goal

`cargo xtask doom-probe [MACHINE]` runs the same image without a window:
the title screen on the screen has the CRC-32 the game printed
(`doom: title crc32 X`), the keys of the menu (`sendkey` of QEMU's
monitor) lead to the first level (`doom: level 1 1`), a turn changes the
view, the menu leaves with code 0, and a second run ends by Ctrl-C. GitHub
runs it as the job `doom-probe` next to the groups of `cargo xtask ci`.

`cargo xtask doom-headless` plays the demo without looking at the screen
(`-timedemo demo1 -nodraw`).
