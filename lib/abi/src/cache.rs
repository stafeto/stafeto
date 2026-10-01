// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The data cache lines a maintenance by address covers [G18], for the
//! kernel's cache maintenance and for programs' DMA buffers (rt::dma): a
//! line is `4 << CTR_EL0.DminLine` bytes, read from the processor, never
//! assumed.

use core::iter::StepBy;
use core::ops::Range;

/// The addresses of the lines of `line` bytes, a power of two, that cover
/// `range`: its start rounds down to a line and its end up; none for an
/// empty range.
pub fn lines(range: Range<usize>, line: usize) -> StepBy<Range<usize>> {
    let start = range.start & !(line - 1);
    let end = if range.is_empty() {
        start
    } else {
        range.end.next_multiple_of(line)
    };
    (start..end).step_by(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_round_the_start_down_and_the_end_up() {
        for line in [32, 64, 128] {
            let start = 0x1000 + line + 1;
            let got: Vec<usize> = lines(start..start + 2 * line, line).collect();
            assert_eq!(
                got,
                [0x1000 + line, 0x1000 + 2 * line, 0x1000 + 3 * line],
                "{line}"
            );
            let one: Vec<usize> = lines(0x2000..0x2001, line).collect();
            assert_eq!(one, [0x2000], "{line}");
            let whole: Vec<usize> = lines(0x2000..0x2000 + line, line).collect();
            assert_eq!(whole, [0x2000], "{line}");
            assert_eq!(lines(0x2003..0x2003, line).count(), 0, "{line}");
        }
    }
}
