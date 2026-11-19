// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The scenario of the LVGL demo as the injector has it
//! (tests/lvgl-inject/src/scenario.rs, included here) against its one source,
//! `ports/lvgl/scene.h`, which the demo and the reference program on the host
//! read: every place, the number of events and each row of them must be equal,
//! so a widget moved in the header without the injector (or the injector
//! without the header) fails in this test, before any run of QEMU.

#[path = "../../tests/lvgl-inject/src/scenario.rs"]
#[allow(dead_code)]
mod scenario;

use std::collections::BTreeMap;
use std::path::Path;

/// The numbers `#define NAME value` of the header, and the text of the
/// `SCENE_EVENT_ROWS` macro with its comments and continuations removed.
fn parse(text: &str) -> (BTreeMap<String, i64>, String) {
    let mut numbers = BTreeMap::new();
    let mut rows = String::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let Some(rest) = line.trim().strip_prefix("#define ") else {
            continue;
        };
        let (name, value) = rest.split_once(' ').unwrap_or((rest, ""));
        if name == "SCENE_EVENT_ROWS" {
            let mut all = value.to_owned();
            let mut line = value.to_owned();
            while line.trim_end().ends_with('\\') {
                line = lines.next().unwrap_or("").to_owned();
                all.push(' ');
                all.push_str(&line);
            }
            rows = all.replace('\\', " ");
            continue;
        }
        let value = value.trim();
        let parsed = match value.strip_prefix("0x") {
            Some(hex) => i64::from_str_radix(hex, 16).ok(),
            None => value.parse().ok(),
        };
        if let Some(n) = parsed {
            numbers.insert(name.to_owned(), n);
        }
    }
    // The comments of the rows go.
    let mut plain = String::new();
    let mut rest = rows.as_str();
    while let Some(start) = rest.find("/*") {
        plain.push_str(&rest[..start]);
        let end = rest[start..].find("*/").expect("a comment that ends") + start + 2;
        rest = &rest[end..];
    }
    plain.push_str(rest);
    (numbers, plain)
}

/// The rows `{kind, code, value, x, y}` of the macro's text.
fn rows(text: &str) -> Vec<[i64; 5]> {
    text.split('{')
        .skip(1)
        .map(|group| {
            let inside = group.split('}').next().unwrap();
            let numbers: Vec<i64> = inside
                .split(',')
                .map(|n| {
                    let n = n.trim();
                    match n.strip_prefix("0x") {
                        Some(hex) => i64::from_str_radix(hex, 16).unwrap(),
                        None => n.parse().unwrap(),
                    }
                })
                .collect();
            numbers.try_into().expect("five numbers in a row")
        })
        .collect()
}

fn header() -> (BTreeMap<String, i64>, Vec<[i64; 5]>) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../ports/lvgl/scene.h");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let (numbers, rows_text) = parse(&text);
    (numbers, rows(&rows_text))
}

#[test]
fn the_places_of_the_injector_are_those_of_the_header() {
    let (numbers, _) = header();
    use scenario::*;
    for (name, mine) in [
        ("SCENE_BUTTON_X", BUTTON_X),
        ("SCENE_BUTTON_Y", BUTTON_Y),
        ("SCENE_BUTTON_W", BUTTON_W),
        ("SCENE_BUTTON_H", BUTTON_H),
        ("SCENE_CHECK_X", CHECK_X),
        ("SCENE_CHECK_Y", CHECK_Y),
        ("SCENE_SWITCH_X", SWITCH_X),
        ("SCENE_SWITCH_Y", SWITCH_Y),
        ("SCENE_SWITCH_W", SWITCH_W),
        ("SCENE_SWITCH_H", SWITCH_H),
        ("SCENE_SLIDER_X", SLIDER_X),
        ("SCENE_SLIDER_Y", SLIDER_Y),
        ("SCENE_SLIDER_W", SLIDER_W),
        ("SCENE_SLIDER_H", SLIDER_H),
        ("SCENE_AREA_X", AREA_X),
        ("SCENE_AREA_Y", AREA_Y),
        ("SCENE_AREA_W", AREA_W),
        ("SCENE_AREA_H", AREA_H),
    ] {
        assert_eq!(numbers.get(name), Some(&i64::from(mine)), "{name}");
    }
}

#[test]
fn the_scenario_is_the_22_events_of_the_header_row_by_row() {
    let (numbers, header_rows) = header();
    assert_eq!(numbers["SCENE_EVENTS"], 22);
    assert_eq!(scenario::EVENTS, 22);
    assert_eq!(scenario::ROWS.len(), 22);
    assert_eq!(header_rows.len(), 22);
    assert_eq!(numbers["SCENE_CHANGES"], scenario::CHANGES as i64);
    assert_eq!(scenario::changes(), scenario::CHANGES);
    // A MOVE only moves the point: the rows that are not MOVE are the changes.
    assert_eq!(
        header_rows.iter().filter(|r| r[0] != 2).count() as i64,
        numbers["SCENE_CHANGES"]
    );
    for (i, (mine, theirs)) in scenario::ROWS.iter().zip(&header_rows).enumerate() {
        let row = [
            i64::from(mine.kind),
            i64::from(mine.code),
            i64::from(mine.value),
            i64::from(mine.x),
            i64::from(mine.y),
        ];
        assert_eq!(&row, theirs, "row {i}");
    }
}

/// Each click lands inside its widget, and the slider's at three quarters.
#[test]
fn the_clicks_land_inside_their_widgets() {
    use scenario::*;
    let inside = |at: (i32, i32), x: i32, y: i32, w: i32, h: i32| {
        at.0 >= x && at.0 < x + w && at.1 >= y && at.1 < y + h
    };
    assert!(inside(BUTTON_AT, BUTTON_X, BUTTON_Y, BUTTON_W, BUTTON_H));
    assert!(inside(SWITCH_AT, SWITCH_X, SWITCH_Y, SWITCH_W, SWITCH_H));
    assert!(inside(SLIDER_AT, SLIDER_X, SLIDER_Y, SLIDER_W, SLIDER_H));
    assert!(inside(AREA_AT, AREA_X, AREA_Y, AREA_W, AREA_H));
    assert_eq!(SLIDER_AT.0 - SLIDER_X, SLIDER_W * 3 / 4);
    assert_eq!(CHECK_AT, (30, 200));
}
