# The window manager `desk`

`desk` is the window manager of the desk image (`boot-desk.img`, `cargo xtask
desk-probe`). It is a statically linked C program on relibc, a process of POSIX
that holds the manager's mark (`<stafeto/manager.h>`, `docs/compositor.md`, "The
window manager"), and it draws with LVGL and FreeType (`docs/lvgl.md`). The
sources are in `ports/desk` and `apps/desk`.

## What it does

* **Frames.** Each window of a client gets a frame: a window of the manager's
  own, tied under the client's window with `stafeto_manager_link`, 4 points wider
  on each side and below it and 24 points above it (the bar). The service moves,
  raises, hides and shows the two as one in a single frame of its own, so a frame
  never lies apart from its window. The bar has the title and, at its right end,
  the close button. A window that has no title shows its application id.
* **No frame.** A window of the first revision (`<stafeto/display.h>`), a window
  too big to carry a frame below the panel (the whole screen, say) and a window
  whose frame the program could not make (the quota or the manager's eight
  windows ran out) are shown as they are.
* **Panel.** A strip of 24 points at the top with a cell for each window, up to 160
  points wide; the window with the focus has the colour of the focus. A click on
  a cell gives its window the focus. The panel is hidden while the window with
  the focus has no frame and covers the screen or is of the first revision.
* **Moving.** A press on the bar and a move drag the window; the frame follows.
  The window stays inside the screen with its frame, and below the panel.
* **Focus.** A new window has the focus and the top place (a subscribed manager
  decides that, the service does not). A click on a frame or on a window gives
  the window the focus and the top place (the service does that). When the window
  with the focus goes, the focus goes to the window that had it last.
* **Keys.** Super and Tab give the focus to the next window in the order the
  windows were made, Super, Shift and Tab to the one before it, round the ends,
  skipping a hidden window. Super and Q ask the window with the focus to close. Super
  and Escape end the manager. The service sends the manager the Super keys and the
  keys pressed with Super held, and nothing else, so Shift must be pressed after
  Super to count.
* **Closing.** The close button (pressed and released on it) and Super and Q send
  the window a request (`CLOSE_REQUEST`); the program decides. A program that the
  manager started and whose window is still there after 5 s gets SIGTERM. A
  window of a program the manager did not start stays.
* **A restart.** The record `desk` of `table::desk` has `Restart::Always`. A manager that
  starts finds the windows that are open (the service lists them and tells a
  CREATE for each) and frames them as new ones. The old manager's frames and panel
  go with its session and the windows of the clients stay where they were. A manager
  that restarts waits (EBUSY) until the service has seen the old session go.

## Files

* `ports/desk/policy.c`, `policy.h`: what to do for each event, with no call to the
  service. An event goes in, a queue of actions comes out (`FOCUS`, `MOVE`,
  `CLOSE`, `TERM`, `FRAME`, `UNFRAME`, redraws, panel shown or hidden, `QUIT`).
  The geometry of frames and panel is here too, so the drawing and the hit tests
  agree. `policy_test.c` is its host test (`tools/test_desk_port.py` builds and
  runs it and plants faults in copies of the source to show the tests catch them).
* `ports/desk/draw.c`, `draw.h`: the LVGL objects of a frame and of the panel. Flat
  rectangles and clipped text, no radius, shadow or opacity. It knows nothing of
  windows, so a reference program on the host can draw the same pixels.
* `ports/desk/desk_io.c`, `desk_io.h`: a surface is a window of the manager with an
  LVGL display over its two buffers. LVGL draws into the buffer that is free and
  posts the rectangles it redrew; the wait for the next buffer is
  `stafeto_window_wait_free`, which leaves the other bits of the channel to
  `stafeto_windows_wait`.
* `ports/desk/main.c`: the loop. It waits across all windows and the manager's
  ring, reads the service's list at each turn (windows made or gone, places and the
  focus come from it, so a lost event costs nothing), feeds the policy, carries out
  its actions, and draws the surfaces that changed. The moves of the pointer in
  one batch are one: the policy moves a window by the pointer's distance from where the
  press was, so only the last counts.
* `apps/desk`: the Rust crate that links the C program (`build.rs`) with LVGL,
  FreeType and relibc, and starts the layer.

## Arguments

`desk [--trace] [--spawn APPID,PATH[,ARG...]]...` The image's record gives
`--trace`, which prints a line `desk: state ...` for each change of the service's
list (the windows from the lowest, each `name@x,y/WxH/flags`, flags `s` shown and
`f` focus; a frame is `frame(name)`), and three `--spawn` of `desk-client`
(`tests/desk-client`), the third of which ignores a request to close. A program of
the list starts when the one before it has a window, and only when the manager
finds no client window at its start. The list is what the probe needs;
`/etc/desk.conf` will take its place.

## Memory

The panel is 45 pages of the manager's own memory with what it holds at the start,
and each frame 262 pages for a client of 400 by 300 points (a frame of 408 by 328
points, two buffers of 131 pages): the `desk: memory` lines of the probe show 45,
307, 569, 831 and 1 093 pages with the panel and one to four frames. Frames are
made the size they have, so their buffers are as big as the window and its edges.
The record's quota is 2 200 pages, which holds the panel and seven frames (1 879)
with the layer, LVGL and FreeType; a frame the quota does not hold is left out and
the window stays without one (measured: `ENOMEM` for the fourth frame under a quota of 1 000 pages). A
child of the manager gets the manager's quota, so the process service's pool is
sized for it and four children.

## Not yet

Changing the size of a window by its frame, maximizing and minimizing, a list of
programs to start from the panel and the clock are part B of the plan of M1.
A window that changes its own size leaves its frame as it was.
