// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

#include "keys.h"

#define LINUX_KEYS 128

// Indexed by the Linux key code. The keypad has Enter, minus and plus (the
// size of the view: Doom's minus and equals). Letters are lower case, as Doom's menus and
// bindings have them; both Ctrl, Shift and Alt keys are Doom's right ones,
// the keys of fire, run and strafe.
static const unsigned char doom_keys[LINUX_KEYS] = {
    [1] = SK_ESCAPE,
    [2] = '1', [3] = '2', [4] = '3', [5] = '4', [6] = '5',
    [7] = '6', [8] = '7', [9] = '8', [10] = '9', [11] = '0',
    [12] = '-', [13] = '=', [14] = SK_BACKSPACE, [15] = SK_TAB,
    [16] = 'q', [17] = 'w', [18] = 'e', [19] = 'r', [20] = 't',
    [21] = 'y', [22] = 'u', [23] = 'i', [24] = 'o', [25] = 'p',
    [26] = '[', [27] = ']', [28] = SK_ENTER, [29] = SK_RCTRL,
    [30] = 'a', [31] = 's', [32] = 'd', [33] = 'f', [34] = 'g',
    [35] = 'h', [36] = 'j', [37] = 'k', [38] = 'l', [39] = ';',
    [40] = '\'', [41] = '`', [42] = SK_RSHIFT, [43] = '\\',
    [44] = 'z', [45] = 'x', [46] = 'c', [47] = 'v', [48] = 'b',
    [49] = 'n', [50] = 'm', [51] = ',', [52] = '.', [53] = '/',
    [54] = SK_RSHIFT, [56] = SK_RALT, [57] = ' ', [58] = SK_CAPSLOCK,
    [59] = SK_F1, [60] = SK_F1 + 1, [61] = SK_F1 + 2, [62] = SK_F1 + 3,
    [63] = SK_F1 + 4, [64] = SK_F1 + 5, [65] = SK_F1 + 6, [66] = SK_F1 + 7,
    [67] = SK_F1 + 8, [68] = SK_F10,
    [87] = SK_F11, [88] = SK_F12,
    [74] = '-', [78] = '=', [96] = SK_ENTER,
    [97] = SK_RCTRL, [100] = SK_RALT,
    [102] = SK_HOME, [103] = SK_UPARROW, [104] = SK_PGUP,
    [105] = SK_LEFTARROW, [106] = SK_RIGHTARROW, [107] = SK_END,
    [108] = SK_DOWNARROW, [109] = SK_PGDN, [110] = SK_INS, [111] = SK_DEL,
    [119] = SK_PAUSE,
};

int stafeto_doom_key(unsigned int code)
{
    return code < LINUX_KEYS ? doom_keys[code] : 0;
}

int stafeto_key_event_wanted(unsigned int type, int value)
{
    return type == 1 && (value == 0 || value == 1);
}
