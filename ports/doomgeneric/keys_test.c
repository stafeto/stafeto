// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

// The test of keys.c on the host (cargo test -p xtask runs it).

#include <stdio.h>

#include "keys.h"

static int failures;

static void expect(const char *what, int got, int want)
{
    if (got != want) {
        printf("%s: %d, %d expected\n", what, got, want);
        failures++;
    }
}

int main(void)
{
    // The keys of the menu and the quit dialog: sendkey ret, esc, up, y.
    expect("enter", stafeto_doom_key(28), SK_ENTER);
    expect("esc", stafeto_doom_key(1), SK_ESCAPE);
    expect("up", stafeto_doom_key(103), SK_UPARROW);
    expect("down", stafeto_doom_key(108), SK_DOWNARROW);
    expect("left", stafeto_doom_key(105), SK_LEFTARROW);
    expect("right", stafeto_doom_key(106), SK_RIGHTARROW);
    expect("y", stafeto_doom_key(21), 'y');
    expect("n", stafeto_doom_key(49), 'n');
    // The keys of play: fire, use, run, strafe.
    expect("left ctrl", stafeto_doom_key(29), SK_RCTRL);
    expect("right ctrl", stafeto_doom_key(97), SK_RCTRL);
    expect("space", stafeto_doom_key(57), ' ');
    expect("left shift", stafeto_doom_key(42), SK_RSHIFT);
    expect("right shift", stafeto_doom_key(54), SK_RSHIFT);
    expect("left alt", stafeto_doom_key(56), SK_RALT);
    expect("right alt", stafeto_doom_key(100), SK_RALT);
    // Letters, digits and signs.
    expect("a", stafeto_doom_key(30), 'a');
    expect("m", stafeto_doom_key(50), 'm');
    expect("q", stafeto_doom_key(16), 'q');
    expect("1", stafeto_doom_key(2), '1');
    expect("0", stafeto_doom_key(11), '0');
    expect("minus", stafeto_doom_key(12), '-');
    expect("equals", stafeto_doom_key(13), '=');
    expect("comma", stafeto_doom_key(51), ',');
    expect("period", stafeto_doom_key(52), '.');
    expect("tab", stafeto_doom_key(15), SK_TAB);
    expect("backspace", stafeto_doom_key(14), SK_BACKSPACE);
    // The function keys are consecutive in Doom's table.
    expect("f1", stafeto_doom_key(59), SK_F1);
    expect("f5", stafeto_doom_key(63), SK_F1 + 4);
    expect("f9", stafeto_doom_key(67), SK_F1 + 8);
    expect("f10", stafeto_doom_key(68), SK_F10);
    expect("f11", stafeto_doom_key(87), SK_F11);
    expect("f12", stafeto_doom_key(88), SK_F12);
    // Keys Doom does not use, and codes past the table.
    expect("reserved 0", stafeto_doom_key(0), 0);
    expect("left meta", stafeto_doom_key(125), 0);
    expect("unmapped 55", stafeto_doom_key(55), 0);
    expect("past the table", stafeto_doom_key(128), 0);
    expect("far past the table", stafeto_doom_key(0xffff), 0);
    // Only presses and releases of keys.
    expect("press", stafeto_key_event_wanted(1, 1), 1);
    expect("release", stafeto_key_event_wanted(1, 0), 1);
    expect("repeat", stafeto_key_event_wanted(1, 2), 0);
    expect("negative", stafeto_key_event_wanted(1, -1), 0);
    expect("sync", stafeto_key_event_wanted(0, 0), 0);
    expect("relative", stafeto_key_event_wanted(2, 1), 0);
    if (failures == 0)
        printf("keys: ok\n");
    return failures != 0;
}
