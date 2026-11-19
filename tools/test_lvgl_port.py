#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The host tests of the pure logic of the LVGL demo (ports/lvgl) and of the
reference program that runs the demo on the host (tools/lvgl-ref):

  - crc.c against the CRC-32 of Python's zlib;
  - keys.c: Linux key codes to characters, Shift, the key of an up;
  - schedule.c: a MOVE moves the point and is not a change; the next change
    waits until the frame has settled; all the events at once and the same
    events one by one give the same changes in the same order;
  - the reference program: the pinned CRCs, turns, frames and state line in
    every run and with every way of feeding the events (all at once, one at a
    time, a slow injector), and the pinned evidence lines of the glyph path.

Three planted faults are shown to fail, each by a changed copy of the source:
a change handed out before the frame settled (the test of all events at once
fails), x and y swapped in the hand-out of the point (the state line of the
reference is not "presses 2 option 1 switch 1 ..."), and the events not
collected before the clock runs (a slow injector gives key repeats).

One real run of each fault: with the first, the changes of the scenario were
handed out 1 turn apart (0 once) where the model needs 11 to settle,
and the test of all events at once failed; with the second, the reference
printed "presses 0 option 0 switch 0 slider 20 text hi" (and a different
second CRC), and the test of the state line failed; with the third, feeding one
event every 20, 30 and 40 looks gave "text hi", "text hhii" and "text hhhiii"
and other CRCs, turns and frames (the first frame is the same). With a
wait that counts events (22) and a service that delivers 21, the reference
failed at the deadline after listing the 21 events in order."""

import importlib.util
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zlib


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PORT = ROOT / "ports" / "lvgl"
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("build_lvgl", HERE / "build-lvgl.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

CC = shutil.which("clang") or shutil.which("cc") or "cc"
STATE = "presses 2 option 1 switch 1 slider 75 text hi"
BUSY = 10
# The second click of the scenario, as an earlier header had it (at the point of
# the first, so that the second move is a duplicate), for the tests of a service
# that drops duplicate moves.
DUPLICATE_ROW = (
    "{2, 0, 0, 100, 146}, {3, 0x110, 1, 100, 146}, {3, 0x110, 0, 100, 146}",
    "{2, 0, 0, 90, 142}, {3, 0x110, 1, 90, 142}, {3, 0x110, 0, 90, 142}",
)
# The values of the reference, pinned: a difference between the machine of the
# CI (arm64 Linux) and a developer's Mac shows in the host job.
FIRST_CRC = "450D7460"
AFTER_CRC = "DDBD81B9"
TURNS, FRAMES = "111", "64"
EVIDENCE = [
    "evidence glyph a outline points 49 contours 2 crc EFEA584D",
    "evidence glyph a bitmap width 9 rows 9 pitch 9 left 0 top 9 advance 576 crc DEA4419D",
    "evidence glyph g outline points 47 contours 2 crc 085C25DD",
    "evidence glyph g bitmap width 8 rows 12 pitch 8 left 0 top 9 advance 576 crc 399C66AA",
    "evidence glyph W outline points 26 contours 1 crc 5D6492C1",
    "evidence glyph W bitmap width 16 rows 12 pitch 16 left 0 top 12 advance 960 crc CE9F7BE4",
    "evidence glyph 0 outline points 24 contours 2 crc 1AB06B25",
    "evidence glyph 0 bitmap width 9 rows 12 pitch 9 left 0 top 12 advance 576 crc B9D6844A",
    "evidence multiple-masters 0",
    "evidence kerning AV x -64 y 0",
    "evidence truetype interpreter-version 40",
]


def compile_test(name: str, port: Path, out: Path) -> Path:
    """Build the host test `name` (a C file of ports/lvgl) from the sources of
    `port`, with the files it tests."""
    sources = {"crc_test": ["crc.c"], "keys_test": ["keys.c"],
               "schedule_test": ["schedule.c", "keys.c"]}[name]
    exe = out / name
    subprocess.run([CC, "-std=gnu11", "-O1", "-Wall", "-Werror", f"-I{port}", str(port / f"{name}.c"),
                    *[str(port / s) for s in sources], "-o", str(exe)], check=True)
    return exe


def run(exe: Path, *args: str, stdin: bytes = b"") -> str:
    return subprocess.run([str(exe), *args], input=stdin, capture_output=True, check=True).stdout.decode()


def handouts(output: str) -> list[tuple]:
    """The lines `P`/`K` of schedule_test: (turn, rest...)."""
    rows = []
    for line in output.splitlines():
        parts = line.split()
        if parts[0] in ("P", "K"):
            rows.append((parts[0], int(parts[1]), *parts[2:]))
    return rows


def mutated(port: Path, name: str, old: str, new: str, into: Path, *more: str) -> Path:
    """A copy of the port directory with `old` replaced by `new` in `name`
    (and further pairs of `more` after them)."""
    copy = into / "port"
    shutil.copytree(port, copy)
    text = (copy / name).read_text()
    pairs = [(old, new), *zip(more[::2], more[1::2])]
    for was, now in pairs:
        assert was in text, f"{was!r} is not in {name}"
        text = text.replace(was, now)
    (copy / name).write_text(text)
    return copy


class CrcTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.exe = compile_test("crc_test", PORT, Path(cls.tmp.name))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_the_crc_is_that_of_zlib(self):
        for data in (b"", b"a", b"123456789", bytes(range(256)) * 7):
            block, pieces = run(self.exe, stdin=data).split()
            want = f"{zlib.crc32(data):08X}"
            self.assertEqual((block, pieces), (want, want), data[:8])

    def test_the_check_value(self):
        self.assertEqual(run(self.exe, stdin=b"123456789").split()[0], "CBF43926")

    def test_the_frame_crc_takes_r_g_b_of_each_point(self):
        w, h = 5, 3
        frame = bytearray()
        want = bytearray()
        for i in range(w * h):
            b, g, r, x = (i * 7) & 255, (i * 13 + 5) & 255, (i * 29 + 1) & 255, 0xAB
            frame += bytes([b, g, r, x])
            want += bytes([r, g, b])
        self.assertEqual(run(self.exe, "xrgb", str(w), str(h), stdin=bytes(frame)).strip(),
                         f"{zlib.crc32(bytes(want)):08X}")


class KeysTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.exe = compile_test("keys_test", PORT, Path(cls.tmp.name))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def feed(self, *events: tuple[int, int]) -> list[str]:
        text = "".join(f"{c} {v}\n" for c, v in events)
        return run(self.exe, stdin=text.encode()).splitlines()

    def test_h_and_i(self):
        self.assertEqual(self.feed((35, 1), (35, 0), (23, 1), (23, 0)),
                         [f"{ord('h')} 1", f"{ord('h')} 0", f"{ord('i')} 1", f"{ord('i')} 0"])

    def test_letters_and_digits(self):
        letters = "qwertyuiop"
        got = self.feed(*[(c, 1) for c in range(16, 26)])
        self.assertEqual(got, [f"{ord(c)} 1" for c in letters])
        got = self.feed(*[(c, 1) for c in range(2, 12)])
        self.assertEqual(got, [f"{ord(c)} 1" for c in "1234567890"])

    def test_shift_gives_capitals_and_symbols(self):
        self.assertEqual(self.feed((42, 1), (30, 1), (30, 0), (2, 1), (2, 0), (42, 0), (30, 1)),
                         ["-", f"{ord('A')} 1", f"{ord('A')} 0", f"{ord('!')} 1", f"{ord('!')} 0",
                          "-", f"{ord('a')} 1"])

    def test_an_up_gives_the_key_of_its_down_even_after_shift_changed(self):
        self.assertEqual(self.feed((42, 1), (30, 1), (42, 0), (30, 0)),
                         ["-", f"{ord('A')} 1", "-", f"{ord('A')} 0"])

    def test_the_right_shift_works_too(self):
        self.assertEqual(self.feed((54, 1), (44, 1)), ["-", f"{ord('Z')} 1"])

    def test_control_keys(self):
        want = {28: 10, 14: 8, 15: 9, 1: 27, 103: 17, 108: 18, 106: 19, 105: 20,
                102: 2, 107: 3, 111: 127, 57: 32}
        for code, key in want.items():
            self.assertEqual(self.feed((code, 1)), [f"{key} 1"], code)

    def test_a_code_with_no_translation_gives_nothing(self):
        self.assertEqual(self.feed((29, 1), (200, 1), (58, 1), (99, 0)), ["-"] * 4)


class ScheduleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.exe = compile_test("schedule_test", PORT, Path(cls.tmp.name))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_the_scenario_has_sixteen_changes_and_twenty_two_events(self):
        out = run(self.exe, "batch")
        rows = handouts(out)
        self.assertEqual(len(rows), 16)
        self.assertIn("changes 16 lost 0", out)

    def test_a_move_is_no_change_and_moves_the_point(self):
        rows = handouts(run(self.exe, "batch"))
        # The first change is the button going down at the point of the move before it.
        self.assertEqual(rows[0][0], "P")
        self.assertEqual(rows[0][2:], ("90", "142", "1"))
        self.assertEqual(rows[1][2:], ("90", "142", "0"))
        # The keys come last, as h and i.
        self.assertEqual([r[0] for r in rows[-4:]], ["K"] * 4)
        self.assertEqual([r[2] for r in rows[-4:]], [str(ord("h")), str(ord("h")), str(ord("i")), str(ord("i"))])

    def test_the_next_change_waits_for_the_frame_to_settle(self):
        rows = handouts(run(self.exe, "batch"))
        turns = [r[1] for r in rows]
        for a, b in zip(turns, turns[1:]):
            self.assertGreater(b - a, BUSY, turns)

    def test_all_events_at_once_and_one_by_one_give_the_same_changes(self):
        batch = handouts(run(self.exe, "batch"))
        single = handouts(run(self.exe, "single"))
        self.assertEqual([r[0:1] + r[2:] for r in batch], [r[0:1] + r[2:] for r in single])
        self.assertEqual([r[1] for r in batch], [r[1] for r in single])

    def test_planted_fault_a_change_handed_out_before_the_frame_settled(self):
        with tempfile.TemporaryDirectory() as tmp:
            port = mutated(PORT, "schedule.c", "if (s->hold == HOLD_NONE) {", "if (1) {", Path(tmp))
            exe = compile_test("schedule_test", port, Path(tmp))
            turns = [r[1] for r in handouts(run(exe, "batch"))]
            gaps = [b - a for a, b in zip(turns, turns[1:])]
            self.assertTrue(any(g <= BUSY for g in gaps), gaps)
            # The order stays; the spacing is what the test of the batch checks.


class ReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run([sys.executable, str(HERE / "build-lvgl.py"), "--host"], check=True,
                       stdout=subprocess.DEVNULL)
        cls.ref = builder.REFERENCE
        cls.font = builder.HOST_DIR / builder.SOURCE_DIR / builder.FONT

    def lines(self, *args: str, ref: Path | None = None) -> dict[str, str]:
        out = subprocess.run([str(ref or self.ref), *args, str(self.font)], capture_output=True,
                             check=True, text=True).stdout
        return {m.group(1): m.group(2) for m in re.finditer(
            r"^lvgl-ref: (first crc|after crc|state|turns) (.*)$", out, re.M)}

    def test_the_state_after_the_scenario(self):
        self.assertEqual(self.lines()["state"], STATE)

    def test_the_crcs_the_turns_and_the_frames_are_the_pinned_ones(self):
        got = self.lines()
        self.assertEqual(got["first crc"], FIRST_CRC)
        self.assertEqual(got["after crc"], AFTER_CRC)
        self.assertEqual(got["turns"], f"{TURNS} frames {FRAMES}")

    def test_the_two_crcs_repeat(self):
        first = self.lines()
        for _ in range(2):
            self.assertEqual(self.lines(), first)

    def test_feeding_the_events_one_by_one_gives_the_same_frames(self):
        self.assertEqual(self.lines("--feed", "single"), self.lines("--feed", "batch"))

    def test_a_slow_injector_gives_the_same_frames_turns_and_state(self):
        batch = self.lines("--feed", "batch")
        for gap in ("20", "30", "40"):
            self.assertEqual(self.lines("--feed", "gap", gap), batch, gap)

    def test_a_service_that_merges_moves_gives_the_same_frames(self):
        batch = self.lines("--feed", "batch")
        for extra in (["--drop-same-move"], ["--merge-moves"],
                      ["--drop-same-move", "--merge-moves", "--feed", "gap", "30"]):
            self.assertEqual(self.lines(*extra), batch, extra)

    def test_a_duplicate_move_the_service_drops_changes_nothing(self):
        # The scenario has no such row (the compositor makes no event for a
        # move to the place the pointer is at). A copy of the header with the
        # old second click, at the same point as the first, has one; the
        # service's 21 events give the frames of the 22.
        with tempfile.TemporaryDirectory() as tmp:
            port = mutated(PORT, "scene.h", DUPLICATE_ROW[0], DUPLICATE_ROW[1], Path(tmp))
            ref = builder.build_reference(port, Path(tmp) / "ref")
            batch = self.lines("--feed", "batch", ref=ref)
            self.assertEqual(batch["first crc"], FIRST_CRC)
            self.assertEqual(batch["after crc"], AFTER_CRC)
            for extra in (["--drop-same-move"], ["--drop-same-move", "--feed", "gap", "40"]):
                self.assertEqual(self.lines(*extra, ref=ref), batch, extra)

    def test_the_evidence_of_the_glyph_path_is_the_pinned_one(self):
        def evidence():
            out = subprocess.run([str(self.ref), "--evidence", str(self.font)], capture_output=True,
                                 check=True, text=True).stdout
            return [l.removeprefix("lvgl-ref: ") for l in out.splitlines()
                    if "evidence" in l and "bands" not in l]
        first = evidence()
        self.assertEqual(first, EVIDENCE)
        self.assertEqual(first, evidence())

    def test_the_bands_of_the_two_frames_are_printed_with_the_evidence(self):
        out = subprocess.run([str(self.ref), "--evidence", str(self.font)], capture_output=True,
                             check=True, text=True).stdout
        bands = [l.split() for l in out.splitlines() if "evidence bands" in l]
        self.assertEqual([b[3] for b in bands], ["first", "after"])
        for row in bands:
            self.assertEqual(len(row[4:]), 25)
        # The first frame is the whole screen; the scenario changes the lower
        # bands and the bands of the controls; the title's bands stay as they were.
        self.assertEqual(bands[0][4], bands[1][4])
        self.assertNotEqual(bands[0][4:], bands[1][4:])

    def test_planted_fault_the_events_are_not_collected_before_the_clock_runs(self):
        # The old way: pull events in each turn of the clock. A late key-up
        # then becomes a long press with repeats.
        with tempfile.TemporaryDirectory() as tmp:
            port = mutated(PORT, "demo.c", "if (collect_inputs(d) != 0) {", "if (0) {", Path(tmp),
                           "settle(d, 0, scenario_done)", "settle(d, 1, scenario_done)")
            ref = builder.build_reference(port, Path(tmp) / "ref")
            got = self.lines("--feed", "gap", "40", ref=ref)
            self.assertNotEqual(got["state"], STATE)
            self.assertIn("text hhhiii", got["state"])
            self.assertNotEqual(got["after crc"], AFTER_CRC)

    def test_planted_fault_the_wait_ends_on_the_number_of_events_and_lists_what_came(self):
        # The end condition that counts all 22 events: with a duplicate move
        # the compositor delivers 21, so the wait ends at the deadline
        # (shortened here), and the demo lists the events that did come, in
        # order.
        with tempfile.TemporaryDirectory() as tmp:
            port = mutated(PORT, "scene.h", DUPLICATE_ROW[0], DUPLICATE_ROW[1], Path(tmp))
            (port / "demo.c").write_text((port / "demo.c").read_text()
                .replace("if (changes >= SCENE_CHANGES) {", "if (changes >= SCENE_EVENTS) {")
                .replace("#define COLLECT_MS 30000", "#define COLLECT_MS 200"))
            ref = builder.build_reference(port, Path(tmp) / "ref")
            done = subprocess.run([str(ref), "--drop-same-move", str(self.font)],
                                  capture_output=True, text=True)
            self.assertNotEqual(done.returncode, 0)
            self.assertIn("received 21 events", done.stdout)
            self.assertIn("M90,142 B110/1 B110/0 B110/1 B110/0 M30,200", done.stdout)

    def test_planted_fault_x_and_y_swapped_in_the_hand_out_of_the_point(self):
        with tempfile.TemporaryDirectory() as tmp:
            port = mutated(PORT, "schedule.c", "*x = s->x;\n    *y = s->y;", "*x = s->y;\n    *y = s->x;", Path(tmp))
            ref = builder.build_reference(port, Path(tmp) / "ref")
            state = self.lines(ref=ref)["state"]
            self.assertNotEqual(state, STATE)
            self.assertFalse(state.startswith("presses 2 option 1 switch 1"), state)


if __name__ == "__main__":
    unittest.main()
