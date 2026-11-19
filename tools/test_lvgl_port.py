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
  - the reference program: the same CRCs and state line in every run and with
    either way of feeding the events, and the evidence lines of the glyph path.

Two planted faults are shown to fail, each by a changed copy of the source:
a change handed out before the frame settled (the test of all events at once
fails) and x and y swapped in the hand-out of the point (the state line of the
reference is not "presses 2 option 1 switch 1 ...").

One real run of each fault: with the first, the changes of the scenario were
handed out 1 turn apart (0 once) where the model needs 11 to settle,
and the test of all events at once failed; with the second, the reference
printed "presses 0 option 0 switch 0 slider 20 text hi" (and a different
second CRC), and the test of the state line failed."""

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


def mutated(port: Path, name: str, old: str, new: str, into: Path) -> Path:
    """A copy of the port directory with `old` replaced by `new` in `name`."""
    copy = into / "port"
    shutil.copytree(port, copy)
    text = (copy / name).read_text()
    assert old in text, f"{old!r} is not in {name}"
    (copy / name).write_text(text.replace(old, new))
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
        return {m.group(1): m.group(2) for m in re.finditer(r"^lvgl-ref: (first crc|after crc|state) (.*)$", out, re.M)}

    def test_the_state_after_the_scenario(self):
        self.assertEqual(self.lines()["state"], STATE)

    def test_the_two_crcs_repeat(self):
        first = self.lines()
        self.assertEqual(len(first["first crc"]), 8)
        self.assertEqual(len(first["after crc"]), 8)
        self.assertNotEqual(first["first crc"], first["after crc"])
        for _ in range(2):
            self.assertEqual(self.lines(), first)

    def test_feeding_the_events_one_by_one_gives_the_same_frames(self):
        self.assertEqual(self.lines("--feed", "single"), self.lines("--feed", "batch"))

    def test_the_evidence_of_the_glyph_path_repeats(self):
        def evidence():
            out = subprocess.run([str(self.ref), "--evidence", str(self.font)], capture_output=True,
                                 check=True, text=True).stdout
            return [l for l in out.splitlines() if "evidence" in l]
        first = evidence()
        self.assertEqual(first, evidence())
        text = "\n".join(first)
        for glyph in "agW0":
            self.assertIn(f"evidence glyph {glyph} outline points", text)
            self.assertIn(f"evidence glyph {glyph} bitmap width", text)
        self.assertIn("evidence multiple-masters 0", text)
        self.assertIn("evidence kerning AV x ", text)
        self.assertIn("evidence truetype interpreter-version 40", text)

    def test_planted_fault_x_and_y_swapped_in_the_hand_out_of_the_point(self):
        with tempfile.TemporaryDirectory() as tmp:
            port = mutated(PORT, "schedule.c", "*x = s->x;\n    *y = s->y;", "*x = s->y;\n    *y = s->x;", Path(tmp))
            ref = builder.build_reference(port, Path(tmp) / "ref")
            state = self.lines(ref=ref)["state"]
            self.assertNotEqual(state, STATE)
            self.assertFalse(state.startswith("presses 2 option 1 switch 1"), state)


if __name__ == "__main__":
    unittest.main()
