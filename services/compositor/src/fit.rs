// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The upper fit of the price model of a band (`compositor::PRICES`): what one
//! operation of `w` by `h` points costs is `call + h * row + w * h * point`,
//! and given the greatest ticks measured on each of several shapes this finds
//! the call (ticks), the row and the point (hundredths of a tick) that keep the
//! model at or above every measure and cost the least over all of them (the
//! least sum of what the model overstates). A model of three terms that errs
//! only high is what the sizing of a band needs: the band may be smaller than
//! the ticks allow, never larger.
//!
//! The fit is a small linear program in three unknowns, solved exactly in
//! integers: its optimum is at a vertex, where three of its constraints (a
//! shape's `model >= measure`, or an unknown `>= 0`) are tight, so every triple
//! of constraints is solved by Cramer's rule, the triples that satisfy all the
//! constraints are kept, and the one with the least sum wins. The parameters are
//! then rounded up, which keeps every constraint.

/// A measure: the greatest ticks of an operation of `w` by `h` points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    pub w: u32,
    pub h: u32,
    pub ticks: u64,
}

/// The fitted prices: the call in ticks, the row and the point in hundredths
/// of a tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fit {
    pub call: u64,
    pub row: u64,
    pub point: u64,
}

impl Fit {
    /// The ticks the model gives a shape, rounded up.
    pub fn ticks(&self, w: u32, h: u32) -> u64 {
        let centi = u128::from(self.row) * u128::from(h)
            + u128::from(self.point) * u128::from(w) * u128::from(h);
        self.call + centi.div_ceil(100) as u64
    }

    /// What the model overstates a measure by (0 when it does not).
    pub fn slack(&self, s: Shape) -> u64 {
        self.ticks(s.w, s.h).saturating_sub(s.ticks)
    }
}

/// `a x + b y + c z >= d`, in the units of the model: the unknowns are the
/// call in hundredths of a tick (so that all are hundredths), the row and the
/// point.
#[derive(Clone, Copy)]
struct Row {
    a: i128,
    b: i128,
    c: i128,
    d: i128,
}

fn det(m: [[i128; 3]; 3]) -> i128 {
    m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1])
        - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0])
        + m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0])
}

/// The vertex where the three constraints are equalities: the three unknowns
/// over a common denominator (made positive), or None when they are dependent.
fn vertex(t: [Row; 3]) -> Option<([i128; 3], i128)> {
    let m = [
        [t[0].a, t[0].b, t[0].c],
        [t[1].a, t[1].b, t[1].c],
        [t[2].a, t[2].b, t[2].c],
    ];
    let d = det(m);
    if d == 0 {
        return None;
    }
    let col = |k: usize| {
        let mut x = m;
        for (i, row) in x.iter_mut().enumerate() {
            row[k] = t[i].d;
        }
        det(x)
    };
    let (n, den) = ([col(0), col(1), col(2)], d);
    Some(if den < 0 {
        ([-n[0], -n[1], -n[2]], -den)
    } else {
        (n, den)
    })
}

/// The least-overstating model that keeps every measure; None for fewer than
/// three shapes that tell the three unknowns apart.
pub fn envelope(shapes: &[Shape]) -> Option<Fit> {
    if shapes.len() < 3 {
        return None;
    }
    // The constraints in hundredths of a tick: C + h R + w h P >= 100 T with
    // C the call in hundredths; then the three unknowns >= 0.
    let get = |i: usize| -> Row {
        match shapes.get(i) {
            Some(s) => Row {
                a: 1,
                b: i128::from(s.h),
                c: i128::from(s.w) * i128::from(s.h),
                d: 100 * i128::from(s.ticks),
            },
            None => Row {
                a: i128::from(i - shapes.len() == 0),
                b: i128::from(i - shapes.len() == 1),
                c: i128::from(i - shapes.len() == 2),
                d: 0,
            },
        }
    };
    let count = shapes.len() + 3;
    // The sum of what the model overstates is, up to a constant, the sum of the
    // left sides: the objective is (n C + sh R + swh P) over the shapes.
    let n = shapes.len() as i128;
    let sh: i128 = shapes.iter().map(|s| i128::from(s.h)).sum();
    let swh: i128 = shapes
        .iter()
        .map(|s| i128::from(s.w) * i128::from(s.h))
        .sum();
    let mut best: Option<([i128; 3], i128, i128)> = None;
    for i in 0..count {
        for j in i + 1..count {
            for k in j + 1..count {
                let Some((x, den)) = vertex([get(i), get(j), get(k)]) else {
                    continue;
                };
                // Every constraint holds: a x/den + b y/den + c z/den >= d.
                let ok = (0..count).all(|m| {
                    let r = get(m);
                    r.a * x[0] + r.b * x[1] + r.c * x[2] >= r.d * den
                });
                if !ok {
                    continue;
                }
                let value = n * x[0] + sh * x[1] + swh * x[2];
                let better = match &best {
                    None => true,
                    // value/den < best value/best den
                    Some((_, bden, bvalue)) => value * bden < bvalue * den,
                };
                if better {
                    best = Some((x, den, value));
                }
            }
        }
    }
    let (x, den, _) = best?;
    let up =
        |v: i128, unit: i128| -> u64 { (v + den * unit - 1).div_euclid(den * unit).max(0) as u64 };
    // The call came in hundredths of a tick: ticks, rounded up; the row and
    // the point stay in hundredths, rounded up. Rounding up keeps the model
    // at or above every measure.
    Some(Fit {
        call: up(x[0], 100),
        row: up(x[1], 1),
        point: up(x[2], 1),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shapes(call: u64, row: u64, point: u64, list: &[(u32, u32)]) -> Vec<Shape> {
        list.iter()
            .map(|&(w, h)| Shape {
                w,
                h,
                ticks: call
                    + (row * u64::from(h) + point * u64::from(w) * u64::from(h)).div_ceil(100),
            })
            .collect()
    }

    const LIST: [(u32, u32); 8] = [
        (1, 1),
        (8, 1),
        (8, 8),
        (16, 16),
        (4, 32),
        (152, 8),
        (76, 32),
        (150, 16),
    ];

    #[test]
    fn exact_measures_give_their_own_prices() {
        let measured = shapes(800, 2_500, 200, &LIST);
        let fit = envelope(&measured).unwrap();
        assert_eq!(
            fit,
            Fit {
                call: 800,
                row: 2_500,
                point: 200
            }
        );
        for s in &measured {
            assert!(fit.ticks(s.w, s.h) >= s.ticks);
        }
    }

    /// A shape dearer than the model of the others (a stray, or an edge cost of
    /// a narrow shape) is covered, never undershot, and the fit stays as cheap
    /// as the covering allows.
    #[test]
    fn a_dear_shape_is_covered() {
        let mut measured = shapes(800, 2_500, 150, &LIST);
        measured[3].ticks += 700;
        let fit = envelope(&measured).unwrap();
        for s in &measured {
            assert!(fit.ticks(s.w, s.h) >= s.ticks, "{s:?} {fit:?}");
        }
        // It overstates the others by less than the stray's excess, in sum.
        let slack: u64 = measured.iter().map(|s| fit.slack(*s)).sum();
        assert!(slack <= 700 * measured.len() as u64);
        assert!(fit.call >= 800 || fit.row >= 2_500 || fit.point >= 150);
    }

    #[test]
    fn a_fit_never_has_a_negative_price_and_too_few_shapes_give_none() {
        // Cheaper tall shapes would pull a row price below zero: it stays 0.
        let measured = vec![
            Shape {
                w: 8,
                h: 1,
                ticks: 1_000,
            },
            Shape {
                w: 8,
                h: 8,
                ticks: 1_100,
            },
            Shape {
                w: 64,
                h: 8,
                ticks: 1_300,
            },
        ];
        let fit = envelope(&measured).unwrap();
        for s in &measured {
            assert!(fit.ticks(s.w, s.h) >= s.ticks);
        }
        assert!(envelope(&measured[..2]).is_none());
        assert!(envelope(&[]).is_none());
    }

    #[test]
    fn the_rounding_keeps_every_measure() {
        // Odd numbers that do not divide: the rounded prices still cover.
        let measured = vec![
            Shape {
                w: 3,
                h: 1,
                ticks: 777,
            },
            Shape {
                w: 7,
                h: 9,
                ticks: 1_013,
            },
            Shape {
                w: 151,
                h: 13,
                ticks: 1_879,
            },
            Shape {
                w: 29,
                h: 31,
                ticks: 1_433,
            },
        ];
        let fit = envelope(&measured).unwrap();
        for s in &measured {
            assert!(fit.ticks(s.w, s.h) >= s.ticks, "{s:?} {fit:?}");
        }
    }
}
