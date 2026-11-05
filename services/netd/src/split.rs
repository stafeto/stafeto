// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The breakdown of the step of the stack by parts (the feature `split`,
//! which only the images of the measurement turn on): the marks of the
//! counter at the borders of the parts, a histogram of 64 buckets of 256
//! ticks for each part, and the lines `net: split <part> n <..> p50 <..>
//! p90 <..> max <..>` that CONFIG of the probe prints. The preemption of the service
//! by others only adds time, so p50 and p90 say more than the maximum.
//!
//! The parts: `fixed` what a step costs besides the frames and the passes of
//! groups; `frame_rx` a received frame, from the ring to the stack's answer,
//! without the frames the stack sent in it; `frame_tx` a frame sent; `group`
//! the pass of sending over one group and its deadline, without the frames it
//! sent; `kernel` the calls of the kernel at the end of the step. The parts
//! `frame_rx_wire` and `frame_tx_wire` are the frames of the wire (sums
//! checked or made, up to 1 514 bytes), which `frame_rx` and `frame_tx` leave
//! to the frames of the loopback. The parts `buf_copy_tx` and `buf_copy_rx`
//! are the copies of a request with a cell of a shared buffer, from the cell
//! to the queue of sending and from the queue of receiving to the cell.

#[cfg(feature = "split")]
mod on {
    use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

    pub const FIXED_RX: usize = 0;
    pub const FIXED_TX: usize = 5;
    pub const FRAME_RX: usize = 1;
    pub const FRAME_TX: usize = 2;
    pub const GROUP: usize = 3;
    pub const KERNEL: usize = 4;
    pub const FRAME_RX_WIRE: usize = 6;
    pub const FRAME_TX_WIRE: usize = 7;
    pub const BUF_COPY_TX: usize = 8;
    pub const BUF_COPY_RX: usize = 9;
    const NAMES: [&str; 10] = [
        "fixed_rx",
        "frame_rx",
        "frame_tx",
        "group",
        "kernel",
        "fixed_tx",
        "frame_rx_wire",
        "frame_tx_wire",
        "buf_copy_tx",
        "buf_copy_rx",
    ];
    // Buckets of 64 ticks up to 16 384: the rule of the frames of a step
    // reads a p90 that is the top of its bucket, and a wider bucket moved it
    // across the budget by its width alone.
    const BUCKETS: usize = 256;
    const WIDTH: u64 = 64;

    static HIST: [[AtomicU64; BUCKETS]; 10] =
        [const { [const { AtomicU64::new(0) }; BUCKETS] }; 10];
    static MAX: [AtomicU64; 10] = [const { AtomicU64::new(0) }; 10];
    /// The ticks of the frames sent in the step so far, of the frames
    /// received (the whole turn of the loop) and of the passes of groups
    /// (the whole pass).
    pub static TX: AtomicU64 = AtomicU64::new(0);
    pub static RX_TURNS: AtomicU64 = AtomicU64::new(0);
    pub static PASSES: AtomicU64 = AtomicU64::new(0);

    pub fn now() -> u64 {
        rt::time::now()
    }

    pub fn record(part: usize, ticks: u64) {
        let bucket = ((ticks / WIDTH) as usize).min(BUCKETS - 1);
        HIST[part][bucket].fetch_add(1, Relaxed);
        MAX[part].fetch_max(ticks, Relaxed);
    }

    pub fn begin_step() {
        TX.store(0, Relaxed);
        RX_TURNS.store(0, Relaxed);
        PASSES.store(0, Relaxed);
    }

    pub fn add(counter: &AtomicU64, ticks: u64) {
        counter.fetch_add(ticks, Relaxed);
    }

    pub fn get(counter: &AtomicU64) -> u64 {
        counter.load(Relaxed)
    }

    fn total(part: usize) -> u64 {
        HIST[part].iter().map(|b| b.load(Relaxed)).sum()
    }

    fn percentile(part: usize, percent: u64) -> u64 {
        let total = total(part);
        if total == 0 {
            return 0;
        }
        let want = (total * percent).div_ceil(100);
        let mut seen = 0;
        for (i, b) in HIST[part].iter().enumerate() {
            seen += b.load(Relaxed);
            if seen >= want {
                return (i as u64 + 1) * WIDTH;
            }
        }
        BUCKETS as u64 * WIDTH
    }

    pub fn report() {
        for (part, name) in NAMES.iter().enumerate() {
            rt::println!(
                "net: split {} n {} p50 {} p90 {} max {}",
                name,
                total(part),
                percentile(part, 50),
                percentile(part, 90),
                MAX[part].load(Relaxed)
            );
        }
    }
}

#[cfg(feature = "split")]
pub use on::*;

#[cfg(not(feature = "split"))]
mod off {
    use core::sync::atomic::AtomicU64;

    pub const FIXED_RX: usize = 0;
    pub const FIXED_TX: usize = 5;
    pub const FRAME_RX: usize = 1;
    pub const FRAME_TX: usize = 2;
    pub const GROUP: usize = 3;
    pub const KERNEL: usize = 4;
    pub const FRAME_RX_WIRE: usize = 6;
    pub const FRAME_TX_WIRE: usize = 7;
    pub const BUF_COPY_TX: usize = 8;
    pub const BUF_COPY_RX: usize = 9;
    pub static TX: AtomicU64 = AtomicU64::new(0);
    pub static RX_TURNS: AtomicU64 = AtomicU64::new(0);
    pub static PASSES: AtomicU64 = AtomicU64::new(0);

    #[inline(always)]
    pub fn now() -> u64 {
        0
    }
    #[inline(always)]
    pub fn record(_: usize, _: u64) {}
    #[inline(always)]
    pub fn begin_step() {}
    #[inline(always)]
    pub fn add(_: &AtomicU64, _: u64) {}
    #[inline(always)]
    pub fn get(_: &AtomicU64) -> u64 {
        0
    }
    #[inline(always)]
    #[allow(dead_code)]
    pub fn report() {}
}

#[cfg(not(feature = "split"))]
pub use off::*;
