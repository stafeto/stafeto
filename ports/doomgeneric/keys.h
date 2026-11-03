// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

// The keys of the platform: Linux key codes (input-event-codes.h), which the
// keyboard of stafeto delivers, into the keys of Doom (doomkeys.h). The
// values below are Doom's; doomgeneric_stafeto.c asserts at compile time
// that they are the engine's. This file has no dependencies, so that the
// host can test the table (xtask doom).

#ifndef STAFETO_KEYS_H
#define STAFETO_KEYS_H

#define SK_RIGHTARROW 0xae
#define SK_LEFTARROW 0xac
#define SK_UPARROW 0xad
#define SK_DOWNARROW 0xaf
#define SK_ESCAPE 27
#define SK_ENTER 13
#define SK_TAB 9
#define SK_BACKSPACE 0x7f
#define SK_PAUSE 0xff
#define SK_RSHIFT (0x80 + 0x36)
#define SK_RCTRL (0x80 + 0x1d)
#define SK_RALT (0x80 + 0x38)
#define SK_CAPSLOCK (0x80 + 0x3a)
#define SK_F1 (0x80 + 0x3b)
#define SK_F10 (0x80 + 0x44)
#define SK_F11 (0x80 + 0x57)
#define SK_F12 (0x80 + 0x58)
#define SK_HOME (0x80 + 0x47)
#define SK_END (0x80 + 0x4f)
#define SK_PGUP (0x80 + 0x49)
#define SK_PGDN (0x80 + 0x51)
#define SK_INS (0x80 + 0x52)
#define SK_DEL (0x80 + 0x53)

// The key of Doom for the Linux key code `code`, 0 for a key Doom does not
// use.
int stafeto_doom_key(unsigned int code);

// Whether a key event is one to pass on: EV_KEY (type 1) with value 0 (the
// release) or 1 (the press). A repeat (value 2), which another host may
// send, is dropped: Doom keeps the state of a key by its press and release.
int stafeto_key_event_wanted(unsigned int type, int value);

#endif
