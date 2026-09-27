// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The output of the shell's commands of facts (spec 13.6): `uptime` as
//! seconds with milliseconds, the table of `ps`, the pages of `mem`, the
//! line of `bench`, and the records of init's LIST, which `ps` and `mem`
//! read a page at a time (proto_init). Times come in counter ticks and
//! go out in nanoseconds on the scale of the system (abi::time::Scale).

use crate::text::Text;
use abi::time::Scale;
use core::fmt::{self, Write};
use proto_init::{ListReply, Record, State, Stats};

/// The records of LIST the shell keeps at most: init and the sixteen of
/// a table.
pub const RECORDS_MAX: usize = 17;

/// The records of LIST, in its order.
pub struct Records {
    rows: [Option<Record>; RECORDS_MAX],
    len: usize,
}

impl Records {
    pub const fn new() -> Records {
        Records {
            rows: [None; RECORDS_MAX],
            len: 0,
        }
    }

    /// Adds `r`; false, with nothing kept, when RECORDS_MAX are there.
    pub fn push(&mut self, r: Record) -> bool {
        let Some(row) = self.rows.get_mut(self.len) else {
            return false;
        };
        *row = Some(r);
        self.len += 1;
        true
    }

    pub fn iter(&self) -> impl Iterator<Item = &Record> {
        self.rows[..self.len].iter().flatten()
    }
}

impl Default for Records {
    fn default() -> Records {
        Records::new()
    }
}

/// Reads LIST into `records`, a page at a time from `page`, which gives
/// the page from record `first` on: the next page starts after the last,
/// until the records in all came, a page came empty or `records` is full.
/// The errors are those of `page`.
pub fn list<E>(
    mut page: impl FnMut(u16) -> Result<ListReply, E>,
    records: &mut Records,
) -> Result<(), E> {
    let mut first: u16 = 0;
    loop {
        let reply = page(first)?;
        for r in reply.records() {
            if !records.push(*r) {
                return Ok(());
            }
        }
        first = first.saturating_add(reply.len() as u16);
        if reply.is_empty() || first >= reply.total {
            return Ok(());
        }
    }
}

/// `up <seconds>.<milliseconds> s` for `ticks` of the counter since boot.
pub fn uptime(out: &mut impl Write, ticks: u64, scale: Scale) -> fmt::Result {
    let ms = scale.ticks_to_ns(ticks) / 1_000_000;
    writeln!(out, "up {}.{:03} s", ms / 1000, ms % 1000)
}

/// How LIST names a state.
pub fn state_name(state: State) -> &'static str {
    match state {
        State::Starting => "starting",
        State::Running => "running",
        State::Loading => "loading",
        State::Paused => "paused",
        State::Quota => "quota",
        State::Stopping => "stopping",
        State::Broken => "broken",
        State::Ended => "ended",
    }
}

/// The name of `r` as text; "?" for one that is no UTF-8.
fn name(r: &Record) -> &str {
    core::str::from_utf8(r.name.as_bytes()).unwrap_or("?")
}

/// What `args` formats, right-aligned in `width` bytes.
fn cell(out: &mut impl Write, width: usize, args: fmt::Arguments<'_>) -> fmt::Result {
    let mut text = Text::<24>::new();
    text.write_fmt(args)?;
    write!(out, "{:>width$}", text.as_str())
}

/// The table of `ps`: a header, then a line for each of `records`: its
/// name, state, priority/ceiling, failures in the last 60 s, restarts,
/// handles live/retired/limit and pages used/quota.
pub fn ps(out: &mut impl Write, records: &Records) -> fmt::Result {
    writeln!(
        out,
        "{:<16} {:<8} {:>5} {:>5} {:>8} {:>14} {:>11}",
        "name", "state", "prio", "fails", "restarts", "handles", "pages"
    )?;
    for r in records.iter() {
        write!(out, "{:<16} {:<8} ", name(r), state_name(r.state))?;
        cell(out, 5, format_args!("{}/{}", r.priority, r.ceiling))?;
        write!(out, " {:>5} {:>8} ", r.failures, r.restarts)?;
        cell(
            out,
            14,
            format_args!("{}/{}/{}", r.live, r.retired, r.limit),
        )?;
        out.write_char(' ')?;
        cell(out, 11, format_args!("{}/{}", r.used_pages, r.quota_pages))?;
        out.write_char('\n')?;
    }
    Ok(())
}

/// The pages of `mem`: a line for each of `records` with the pages it
/// uses and its quota; a line of the pages in use in all, of init's quota,
/// where a child's quota, which counts whole in what init uses (spec 7.5),
/// counts by what the child uses; then the kernel's free frames and pages
/// of pools and the free pages of init's quota from `stats`. The first
/// record is init's (LIST).
pub fn mem(out: &mut impl Write, records: &Records, stats: &Stats) -> fmt::Result {
    let (mut root, mut unused) = ((0u64, 0u64), 0u64);
    for (i, r) in records.iter().enumerate() {
        writeln!(
            out,
            "{:<16} {:>6} of {:>6} pages",
            name(r),
            r.used_pages,
            r.quota_pages
        )?;
        let (used, quota) = (u64::from(r.used_pages), u64::from(r.quota_pages));
        if i == 0 {
            root = (used, quota);
        } else {
            unused += quota.saturating_sub(used);
        }
    }
    let used = root.0.saturating_sub(unused);
    writeln!(out, "{:<16} {:>6} of {:>6} pages", "total", used, root.1)?;
    writeln!(
        out,
        "kernel: {} frames free, {} pages in pools; init: {} pages of quota free",
        stats.kernel.free_frames, stats.kernel.pool_pages, stats.free_pages
    )
}

/// The times of the round trips of `bench`, in counter ticks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rounds {
    count: u64,
    min: u64,
    total: u64,
    max: u64,
}

impl Rounds {
    pub const fn new() -> Rounds {
        Rounds {
            count: 0,
            min: u64::MAX,
            total: 0,
            max: 0,
        }
    }

    /// One round trip of `ticks`.
    pub fn add(&mut self, ticks: u64) {
        self.count += 1;
        self.min = self.min.min(ticks);
        self.total = self.total.saturating_add(ticks);
        self.max = self.max.max(ticks);
    }
}

/// The line of `bench`: the least, mean and most of `rounds` and, from
/// `stats`, the longest latencies of a timer that woke the kernel from
/// `wfi` (x2 of KERNEL_STATS) and of one that came while a thread or the
/// kernel ran (x3), all in nanoseconds on `scale`.
pub fn bench(out: &mut impl Write, rounds: &Rounds, stats: &Stats, scale: Scale) -> fmt::Result {
    let ns = |ticks| scale.ticks_to_ns(ticks);
    let min = if rounds.count == 0 { 0 } else { rounds.min };
    let mean = ns(rounds.total) / rounds.count.max(1);
    writeln!(
        out,
        "bench: ping round trip over {} rounds: min {} ns, mean {mean} ns, max {} ns; timer latency max {} ns; interrupt latency max {} ns",
        rounds.count,
        ns(min),
        ns(rounds.max),
        ns(stats.kernel.idle_latency),
        ns(stats.kernel.irq_latency)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::KernelStats;
    use proto_init::{LIST_PAGE, ListReply};
    use proto_wire::Name;

    /// 62.5 MHz, QEMU's counter: 16 ns a tick; 24 MHz, Apple's.
    fn qemu() -> Scale {
        Scale::new(62_500_000).unwrap()
    }

    fn record(
        name: &str,
        state: State,
        levels: (u8, u8),
        handles: [u32; 3],
        pages: [u32; 2],
    ) -> Record {
        Record {
            name: Name::new(name.as_bytes()).unwrap(),
            state,
            priority: levels.0,
            ceiling: levels.1,
            client: false,
            failures: 0,
            restarts: 0,
            live: handles[0],
            retired: handles[1],
            limit: handles[2],
            quota_pages: pages[1],
            used_pages: pages[0],
        }
    }

    /// Init, the driver and the shell, as LIST of the image that ships
    /// gives them.
    fn three() -> Records {
        let mut records = Records::new();
        records.push(record(
            "init",
            State::Running,
            (63, 63),
            [14, 2, 64],
            [40, 1000],
        ));
        records.push(Record {
            failures: 1,
            restarts: 2,
            ..record("uart", State::Running, (60, 60), [9, 1, 32], [18, 32])
        });
        records.push(record("shell", State::Paused, (30, 30), [0, 0, 0], [0, 0]));
        records
    }

    fn stats(kernel: KernelStats) -> Stats {
        Stats {
            kernel,
            job: None,
            worker_priority: 1,
            worker_effective: 1,
            worker_state: 0,
            pending: 0,
            begun: false,
            free_pages: 900,
            labels: 7,
        }
    }

    fn text(f: impl FnOnce(&mut Text) -> fmt::Result) -> String {
        let mut t = Text::new();
        f(&mut t).unwrap();
        t.as_str().to_string()
    }

    #[test]
    fn ps_rows_show_state_handles_and_memory() {
        let table = text(|t| ps(t, &three()));
        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(
            lines,
            [
                "name             state     prio fails restarts        handles       pages",
                "init             running  63/63     0        0        14/2/64     40/1000",
                "uart             running  60/60     1        2         9/1/32       18/32",
                "shell            paused   30/30     0        0          0/0/0         0/0",
            ]
        );
        for (i, state) in State::ALL.into_iter().enumerate() {
            let names = State::ALL.map(state_name);
            assert!(!names[..i].contains(&state_name(state)), "{state:?}");
        }
    }

    #[test]
    fn ps_asks_for_every_page() {
        // Pages of `size` of `total` records, whatever LIST_PAGE is.
        let source = |total: u16, size: u16, asked: &mut Vec<u16>| {
            let mut records = Records::new();
            let mut page = |first: u16| {
                asked.push(first);
                let mut reply = ListReply::new(total);
                for n in first..total.min(first + size) {
                    let name = format!("r{n}");
                    let _ = reply.push(record(&name, State::Running, (1, 1), [0; 3], [0; 2]));
                }
                Ok::<_, ()>(reply)
            };
            list(&mut page, &mut records).unwrap();
            records
                .iter()
                .map(|r| name(r).to_string())
                .collect::<Vec<_>>()
        };
        let mut asked = Vec::new();
        assert_eq!(
            source(7, 3, &mut asked),
            ["r0", "r1", "r2", "r3", "r4", "r5", "r6"]
        );
        assert_eq!(asked, [0, 3, 6]);
        // Fewer records than a full page, a page at a time.
        asked.clear();
        assert_eq!(source(2, 1, &mut asked), ["r0", "r1"]);
        assert_eq!(asked, [0, 1]);
        asked.clear();
        assert_eq!(source(3, LIST_PAGE as u16, &mut asked).len(), 3);
        assert_eq!(asked, [0]);
        // An empty page ends the reading, whatever the count in all says.
        asked.clear();
        assert_eq!(source(5, 0, &mut asked).len(), 0);
        assert_eq!(asked, [0]);
        // An error of a page is the error of the reading.
        let mut records = Records::new();
        assert_eq!(list(|_| Err::<ListReply, _>(7), &mut records), Err(7));
    }

    /// Spec 7.5: a child's quota comes off init's and counts whole in
    /// what init uses; the total counts it by what the child uses.
    #[test]
    fn mem_counts_a_childs_quota_once() {
        let kernel = KernelStats {
            free_frames: 120_000,
            pool_pages: 45,
            ..KernelStats::from_words([0; 8])
        };
        let lines = text(|t| mem(t, &three(), &stats(kernel)));
        assert_eq!(
            lines.lines().collect::<Vec<_>>(),
            [
                "init                 40 of   1000 pages",
                "uart                 18 of     32 pages",
                "shell                 0 of      0 pages",
                "total                26 of   1000 pages",
                "kernel: 120000 frames free, 45 pages in pools; init: 900 pages of quota free",
            ]
        );
    }

    #[test]
    fn bench_line_names_min_mean_max_in_ns() {
        let mut rounds = Rounds::new();
        for ticks in [100, 300, 200] {
            rounds.add(ticks);
        }
        let kernel = KernelStats {
            idle_latency: 10,
            irq_latency: 20,
            ..KernelStats::from_words([0; 8])
        };
        assert_eq!(
            text(|t| bench(t, &rounds, &stats(kernel), qemu())),
            "bench: ping round trip over 3 rounds: min 1600 ns, mean 3200 ns, max 4800 ns; timer latency max 160 ns; interrupt latency max 320 ns\n"
        );
        // At 24 MHz a tick is 41.67 ns, and the scale rounds down.
        let mut apple = Rounds::new();
        apple.add(24);
        let line = text(|t| bench(t, &apple, &stats(kernel), Scale::new(24_000_000).unwrap()));
        assert!(
            line.contains(" min 999 ns, mean 999 ns, max 999 ns;"),
            "{line}"
        );
        assert!(
            line.contains("timer latency max 416 ns; interrupt latency max 833 ns"),
            "{line}"
        );
        // No rounds: zeros.
        let none = text(|t| bench(t, &Rounds::new(), &stats(kernel), qemu()));
        assert!(
            none.starts_with(
                "bench: ping round trip over 0 rounds: min 0 ns, mean 0 ns, max 0 ns;"
            ),
            "{none}"
        );
    }

    #[test]
    fn uptime_is_seconds_with_milliseconds() {
        let at = |ns: u64| text(|t| uptime(t, ns / 16, qemu()));
        assert_eq!(at(12_345_678_912), "up 12.345 s\n");
        assert_eq!(at(0), "up 0.000 s\n");
        assert_eq!(at(1_005_000_000), "up 1.005 s\n");
        assert_eq!(at(60_000_000_000), "up 60.000 s\n");
        let apple = text(|t| uptime(t, 24_000_000 * 3 + 36_000, Scale::new(24_000_000).unwrap()));
        assert_eq!(apple, "up 3.001 s\n");
    }
}
