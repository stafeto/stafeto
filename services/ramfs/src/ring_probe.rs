// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Read-only actual proof and existing-stack measurements, lifetime image only.
pub struct RingProbe {
    pub proved: [u32; 3],
    pub ticks: u64,
    pub visited: u32,
    paint_low: usize,
    paint_high: usize,
    pub stack_peak: u32,
    scan: usize,
    scan_lowest: usize,
}
impl RingProbe {
    pub const fn new() -> Self {
        Self {
            proved: [0; 3],
            ticks: 0,
            visited: 0,
            paint_low: 0,
            paint_high: 0,
            stack_peak: 0,
            scan: 0,
            scan_lowest: 0,
        }
    }
    /// Paint only free mapped memory, leaving two KiB below this live SP untouched.
    ///
    /// # Safety
    /// Sole RAM thread, actual 48 KiB initial stack mapped under INIT_STACK_TOP.
    pub unsafe fn paint(&mut self) {
        if self.paint_low != 0 {
            return;
        }
        let sp: usize;
        // SAFETY: reading SP has no memory effect.
        unsafe {
            core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack, preserves_flags))
        };
        let low = rt::abi::INIT_STACK_TOP as usize - 48 * 1024;
        let high = sp.saturating_sub(2048) & !7;
        if high <= low || high >= rt::abi::INIT_STACK_TOP as usize {
            return;
        }
        for address in (low..high).step_by(8) {
            // SAFETY: caller guarantees this interval is mapped and free stack.
            unsafe { (address as *mut u64).write_volatile(0xded1_cafe_52aa_7e19) };
        }
        self.paint_low = low;
        self.paint_high = high;
    }
    pub fn part(&mut self, ticks: u64, visited: usize) {
        self.ticks = self.ticks.max(ticks);
        self.visited = self.visited.max(visited as u32);
    }
    pub fn proved(&mut self, snapshot: [u32; 3]) {
        if snapshot[0] >= self.proved[0] {
            self.proved = snapshot;
            self.scan = self.paint_low;
            self.scan_lowest = self.paint_high;
            self.stack_peak = 0;
        }
    }
    /// At most eight volatile reads in a test observation after canonical proof.
    pub fn measure_stack(&mut self) {
        if self.paint_low == 0 || self.scan == 0 || self.scan >= self.paint_high {
            return;
        }
        let end = (self.scan + 8 * 8).min(self.paint_high);
        for address in (self.scan..end).step_by(8) {
            // SAFETY: paint retained this sole-thread mapped stack interval.
            if unsafe { (address as *const u64).read_volatile() } != 0xded1_cafe_52aa_7e19 {
                self.scan_lowest = self.scan_lowest.min(address);
            }
        }
        self.scan = end;
        if self.scan == self.paint_high {
            self.stack_peak = (rt::abi::INIT_STACK_TOP as usize - self.scan_lowest) as u32;
        }
    }
}
