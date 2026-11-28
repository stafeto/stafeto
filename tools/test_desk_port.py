#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The host tests of the policy of the window manager `desk` (ports/desk/policy.c):
what the manager does when a window is made or goes, a title changes, a key or the
pointer comes, and the time passes. ports/desk/policy_test.c runs every event and
compares the actions it queues; this script builds and runs it, and shows that the
tests catch faults, each planted in a changed copy of the source:

  - Super and Tab not skipping a hidden window;
  - a window dragged out of the screen at the right (the clamp too wide);
  - a window dragged under the panel (the clamp has no panel);
  - SIGTERM sent after 4 s (the limit is 5);
  - the close button asking at the press (it asks at the release);
  - a window of the first revision given a frame;
  - a frame left behind when its window goes;
  - Super and Q asking the first window (the one with the focus is asked);
  - a click on the panel's cell not giving the focus back to the window.

One real run of each: each gave a line "check failed" and exit code 1."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
PORT = HERE.parent / "ports" / "desk"
CC = shutil.which("clang") or shutil.which("cc") or "cc"


def build(port: Path, out: Path) -> Path:
    exe = out / "policy_test"
    subprocess.run([CC, "-std=gnu11", "-O1", "-Wall", "-Wextra", "-Werror", f"-I{port}",
                    str(port / "policy_test.c"), str(port / "policy.c"), "-o", str(exe)], check=True)
    return exe


def run(exe: Path) -> subprocess.CompletedProcess:
    return subprocess.run([str(exe)], capture_output=True, text=True)


def mutated(into: Path, name: str, old: str, new: str) -> Path:
    """A copy of the port directory with `old` replaced by `new` in `name`."""
    copy = into / "port"
    shutil.copytree(PORT, copy)
    text = (copy / name).read_text()
    assert text.count(old) == 1, f"{old!r} is not once in {name}"
    (copy / name).write_text(text.replace(old, new))
    return copy


class PolicyTests(unittest.TestCase):
    def test_the_policy_passes_its_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            done = run(build(PORT, Path(tmp)))
        self.assertEqual(done.returncode, 0, done.stdout)
        self.assertRegex(done.stdout, r"policy_test: \d+ checks passed")
        count = int(done.stdout.split()[1])
        self.assertGreater(count, 150)

    def planted(self, name: str, old: str, new: str) -> str:
        """The output of the test over a copy with the fault; it must fail."""
        with tempfile.TemporaryDirectory() as tmp:
            port = mutated(Path(tmp), name, old, new)
            done = run(build(port, Path(tmp)))
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn("check failed", done.stdout)
        return done.stdout

    def test_super_and_tab_that_do_not_skip_a_hidden_window_fail(self):
        self.planted("policy.c", "if (w->used && !w->hidden) {\n            if (w->id != p->focus)",
                     "if (w->used) {\n            if (w->id != p->focus)")

    def test_a_drag_with_no_clamp_fails(self):
        self.planted("policy.c", "    *x = clamp(*x, DESK_BORDER, p->screen_w - w - DESK_BORDER);\n",
                     "    *x = clamp(*x, DESK_BORDER, p->screen_w + w * 0 - w - DESK_BORDER + 1000);\n")

    def test_a_clamp_with_no_panel_fails(self):
        self.planted("policy.c", "clamp(*y, DESK_PANEL_H + DESK_BAR,", "clamp(*y, DESK_BAR,")

    def test_sigterm_after_four_seconds_fails(self):
        self.planted("policy.h", "#define DESK_CLOSE_MS 5000", "#define DESK_CLOSE_MS 4000")

    def test_the_close_on_the_press_fails(self):
        self.planted("policy.c", "        p->press.id = id;\n        p->press.zone = zone;\n",
                     "        p->press.id = id;\n        p->press.zone = zone;\n"
                     "        if (zone == DESK_ZONE_CLOSE) {\n            request_close(p, w);\n        }\n")

    def test_a_frame_for_a_window_of_the_first_revision_fails(self):
        self.planted("policy.c", "return !legacy && w > 0", "return (legacy || legacy == 0) && w > 0")

    def test_a_frame_left_behind_fails(self):
        self.planted("policy.c", "    if (w->framed) {\n        act(p, DESK_ACT_UNFRAME, id, 0, 0);\n    }\n",
                     "")

    def test_super_and_q_that_ask_the_wrong_window_fail(self):
        self.planted("policy.c", "desk_win *w = p->focus == DESK_NO_WINDOW ? NULL : find(p, p->focus);\n        if (w) {\n            request_close",
                     "desk_win *w = p->win[0].used ? &p->win[0] : NULL;\n        if (w) {\n            request_close")

    def test_a_panel_click_that_gives_no_focus_fails(self):
        self.planted("policy.c", "        focus_to(p, (desk_win *)w, 0);\n        act(p, DESK_ACT_FOCUS, w->id, 0, 0);\n    }\n}",
                     "        focus_to(p, (desk_win *)w, 0);\n    }\n}")


if __name__ == "__main__":
    unittest.main()
