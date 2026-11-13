// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The places a table names by PCI function (`At::Bar`, `At::Config`,
//! `Binding::msi_of`), found when init starts: init walks the buses the
//! platform's MCFG names (`pci::scan`), reads each BAR as the firmware set
//! it, measures its size once (`pci::measure`: never on a serial function,
//! which may be the console) and writes the result into a copy of the
//! table, which every later step of init reads (`table::table`). A record
//! whose function is not found stops the start with one line of the cause,
//! unless the platform lists it as optional: that record is left out and the
//! line says so.

use crate::PAGE;
use crate::table::{At, Binding, MAX_RECORDS, MSI_EVENT, Record, Window};
use core::fmt;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use pci::{Config, Ecam, Kind, Refused};

/// The windows and bindings of a resolved table at most.
pub const MAX_WINDOWS: usize = 24;
pub const MAX_BINDINGS: usize = 24;
/// The records an optional rule may leave out of a table at most.
pub const MAX_SKIPPED: usize = 4;

/// What the platform gives the walk: the ECAM of the MCFG, the last bus
/// init walks (the buses of the firmware's numbering that hold functions;
/// a bridge to a further bus would be a function of class 0x0604 in the
/// walk, which the platform's test checks is not there), the shift from a
/// BAR's address to the CPU's for an I/O BAR (the host bridge's window), and
/// the records that may be left out.
#[derive(Clone, Copy, Debug)]
pub struct Platform {
    pub ecam: Ecam,
    pub scan_last_bus: u8,
    pub io_shift: u64,
    pub optional: &'static [&'static str],
}

impl Platform {
    /// The bytes of ECAM init maps for the walk.
    pub const fn window_len(&self) -> u64 {
        ((self.scan_last_bus - self.ecam.first_bus) as u64 + 1) << 20
    }
}

/// Why a record's function was not found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    NoFunction {
        id: u32,
        index: u8,
    },
    NoBar {
        id: u32,
        bar: u8,
    },
    /// The BAR is smaller than the window wants.
    Short {
        bar: u8,
        size: u64,
        wants: u64,
    },
    Measure {
        bar: u8,
        why: Refused,
    },
}

/// A record that cannot have its places.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub record: &'static str,
    pub window: &'static str,
    pub cause: Cause,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Refusal {
            record,
            window,
            cause,
        } = self;
        match cause {
            Cause::NoFunction { id, index } => {
                write!(
                    f,
                    "{record} needs function {id:08x} #{index} for {window}: the walk found none"
                )
            }
            Cause::NoBar { id, bar } => {
                write!(
                    f,
                    "{record}: function {id:08x} has no BAR {bar} placed by the firmware for {window}"
                )
            }
            Cause::Short { bar, size, wants } => {
                write!(
                    f,
                    "{record}: BAR {bar} for {window} is {size:#x} bytes, the window wants {wants:#x}"
                )
            }
            Cause::Measure { bar, why } => {
                write!(f, "{record}: BAR {bar} for {window} not measured: {why:?}")
            }
        }
    }
}

/// The room a resolved table is built in.
pub struct Store {
    pub records: [Record; MAX_RECORDS],
    pub windows: [Window; MAX_WINDOWS],
    pub bindings: [Binding; MAX_BINDINGS],
}

impl Store {
    pub const EMPTY: Store = Store {
        records: [Record::EMPTY; MAX_RECORDS],
        windows: [Window::fixed("", 0, 0, false); MAX_WINDOWS],
        bindings: [Binding::msi("", 0, 0); MAX_BINDINGS],
    };
}

/// Whether `table` names any place by function.
pub fn needs(table: &[Record]) -> bool {
    table.iter().any(|r| {
        r.windows.iter().any(|w| w.at != At::Fixed) || r.bindings.iter().any(|b| b.of.is_some())
    })
}

/// A resolved table, and the records the platform left out with their cause.
pub struct Resolved {
    pub table: &'static [Record],
    pub skipped: [Option<Refusal>; MAX_SKIPPED],
}

/// `table` with each place found, built in `store`, which lives on.
/// `platform` says where to walk; `config` reads and writes the words of the
/// functions (a window over ECAM in init).
pub fn resolve(
    table: &[Record],
    platform: &Platform,
    config: &mut impl Config,
    store: &'static mut Store,
) -> Result<Resolved, Refusal> {
    let Store {
        records,
        windows,
        bindings,
    } = store;
    let (mut r_at, mut w_at, mut b_at) = (0, 0, 0);
    let mut ranges = [(0, 0, 0, 0); MAX_RECORDS];
    let mut skipped = [None; MAX_SKIPPED];
    let mut left_out = 0;
    for r in table {
        let (w_from, b_from) = (w_at, b_at);
        match place(r, platform, config, windows, &mut w_at, bindings, &mut b_at) {
            Ok(()) => {
                records[r_at] = *r;
                ranges[r_at] = (w_from, w_at, b_from, b_at);
                r_at += 1;
            }
            Err(refusal) if platform.optional.contains(&r.name) && left_out < MAX_SKIPPED => {
                skipped[left_out] = Some(refusal);
                left_out += 1;
                (w_at, b_at) = (w_from, b_from);
            }
            Err(refusal) => return Err(refusal),
        }
    }
    // The buffers are done with: from here they are shared and live on.
    let windows: &'static [Window] = windows;
    let bindings: &'static [Binding] = bindings;
    for (record, (w_from, w_to, b_from, b_to)) in records.iter_mut().zip(ranges) {
        record.windows = &windows[w_from..w_to];
        record.bindings = &bindings[b_from..b_to];
    }
    let records: &'static [Record] = records;
    Ok(Resolved {
        table: &records[..r_at],
        skipped,
    })
}

/// The `index`-th function with PCI id `id` in the walk the platform names.
fn locate(
    config: &mut impl Config,
    platform: &Platform,
    id: u32,
    index: u8,
) -> Option<pci::Function> {
    pci::find(
        config,
        platform.ecam.first_bus,
        platform.scan_last_bus,
        id,
        index as usize,
    )
}

fn place(
    r: &Record,
    platform: &Platform,
    config: &mut impl Config,
    windows: &mut [Window; MAX_WINDOWS],
    w_at: &mut usize,
    bindings: &mut [Binding; MAX_BINDINGS],
    b_at: &mut usize,
) -> Result<(), Refusal> {
    let refuse = |window, cause| Refusal {
        record: r.name,
        window,
        cause,
    };
    for w in r.windows {
        let found = match w.at {
            At::Fixed => *w,
            At::Config { id, index } => {
                let f = locate(config, platform, id, index)
                    .ok_or(refuse(w.name, Cause::NoFunction { id, index }))?;
                Window {
                    base: platform.ecam.address(f.at).unwrap_or(0),
                    len: PAGE,
                    at: At::Fixed,
                    ..*w
                }
            }
            At::Bar { id, index, bar } => {
                let f = locate(config, platform, id, index)
                    .ok_or(refuse(w.name, Cause::NoFunction { id, index }))?;
                let b = pci::bar(config, f.at, bar as usize)
                    .filter(|b| b.base != 0)
                    .ok_or(refuse(w.name, Cause::NoBar { id, bar }))?;
                let size = pci::measure(config, &f, &b)
                    .map_err(|why| refuse(w.name, Cause::Measure { bar, why }))?;
                if size < w.base + w.len && !cfg!(feature = "break-bar-size") {
                    return Err(refuse(
                        w.name,
                        Cause::Short {
                            bar,
                            size,
                            wants: w.base + w.len,
                        },
                    ));
                }
                let shift = if b.kind == Kind::Io {
                    platform.io_shift
                } else {
                    0
                };
                Window {
                    base: b.base
                        + shift
                        + if cfg!(feature = "break-bar-offset") {
                            0
                        } else {
                            w.base
                        },
                    at: At::Fixed,
                    ..*w
                }
            }
        };
        windows[*w_at] = found;
        *w_at += 1;
    }
    for b in r.bindings {
        let mut found = *b;
        if let Some((id, index)) = b.of {
            let f = locate(config, platform, id, index)
                .ok_or(refuse(b.name, Cause::NoFunction { id, index }))?;
            found.line = MSI_EVENT | f.at.rid() << 8 | (b.line & 0xFF);
            found.of = None;
        }
        bindings[*b_at] = found;
        *b_at += 1;
    }
    Ok(())
}

static INSTALLED: AtomicPtr<Record> = AtomicPtr::new(core::ptr::null_mut());
static INSTALLED_LEN: AtomicUsize = AtomicUsize::new(0);

/// Makes `table`, resolved, the table of init (`table`). Init does it once,
/// on its main thread, before the worker starts.
pub fn install(table: &'static [Record]) {
    INSTALLED_LEN.store(table.len(), Ordering::Release);
    INSTALLED.store(table.as_ptr().cast_mut(), Ordering::Release);
}

/// The table init runs: the resolved one once installed, `TABLE` otherwise.
pub fn table() -> &'static [Record] {
    let at = INSTALLED.load(Ordering::Acquire);
    if at.is_null() {
        return crate::table::TABLE;
    }
    // SAFETY: `install` stores a `'static` slice, its length first; the
    // pointer is read first with Acquire, so the length is the slice's.
    unsafe { core::slice::from_raw_parts(at, INSTALLED_LEN.load(Ordering::Acquire)) }
}

/// What the walk shows of one function: who it is, its BARs as the firmware
/// set them with their sizes (measured here, once, so `None` for the console
/// function and for a BAR that failed), and its MSI-X capability.
pub struct Line {
    pub function: pci::Function,
    pub bars: [Option<(pci::Bar, Option<u64>)>; pci::BARS],
    pub msix: Option<pci::Msix>,
}

impl fmt::Display for Line {
    /// `pci 00:05.0 1d0f:ec20 rev 00 class 020000 bar0 0x80004000+0x4000
    /// msix 9 bir 4 table 0x0 pba 0x1000`; a BAR of unknown size shows `+?`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Function { at, .. } = self.function;
        write!(
            f,
            "pci {:02x}:{:02x}.{} {:04x}:{:04x} rev {:02x} class {:06x}",
            at.bus,
            at.device,
            at.function,
            self.function.vendor,
            self.function.device,
            self.function.revision,
            self.function.class
        )?;
        for (n, bar) in self.bars.iter().enumerate() {
            if let Some((bar, size)) = bar {
                let kind = if bar.kind == Kind::Io { "io " } else { "" };
                write!(f, " bar{n} {kind}{:#x}", bar.base)?;
                match size {
                    Some(size) => write!(f, "+{size:#x}")?,
                    None => write!(f, "+?")?,
                }
            }
        }
        if let Some(m) = self.msix {
            write!(
                f,
                " msix {} bir {} table {:#x} pba {:#x}",
                m.vectors, m.bar, m.offset, m.pba_offset
            )?;
        }
        Ok(())
    }
}

use pci::Function;

/// Walks the buses of `platform` once and gives `show` a `Line` for each
/// function: the lines init prints at its start, so that the console shows
/// every function of the instance with its BARs. Each BAR is measured
/// here, before any driver runs, except on a serial function.
pub fn list(config: &mut impl Config, platform: &Platform, mut show: impl FnMut(&Line)) {
    let mut found = [None; 32 * 8];
    let mut count = 0;
    pci::scan(
        config,
        platform.ecam.first_bus,
        platform.scan_last_bus,
        |f| {
            if count < found.len() {
                found[count] = Some(f);
                count += 1;
            }
            true
        },
    );
    for function in found.iter().flatten() {
        let mut bars = [None; pci::BARS];
        let mut n = 0;
        while n < pci::BARS {
            let Some(bar) = pci::bar(config, function.at, n) else {
                break;
            };
            let registers = bar.registers();
            let empty = bar.base == 0;
            if !empty {
                bars[n] = Some((bar, pci::measure(config, function, &bar).ok()));
            }
            n += registers;
        }
        let at = function.at;
        let msix = pci::msix(|offset| config.read(at, offset));
        show(&Line {
            function: *function,
            bars,
            msix,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::table::{Kind, Restart, Shares};
    use pci::fake::{ENA, Fake, t4g};
    use pci::{Address, Ecam};

    const PLATFORM: Platform = Platform {
        ecam: Ecam {
            base: 0x2000_0000,
            first_bus: 0,
            last_bus: 255,
        },
        scan_last_bus: 0,
        io_shift: 0x3eff_0000,
        optional: &["optional"],
    };

    fn window(name: &'static str, base: u64, len: u64, at: At) -> Window {
        Window {
            name,
            base,
            len,
            duplicate: false,
            at,
        }
    }

    fn record(
        name: &'static str,
        windows: &'static [Window],
        bindings: &'static [Binding],
    ) -> Record {
        Record {
            name,
            kind: Kind::Client,
            restart: Restart::Never,
            shares: Shares::CREATOR,
            windows,
            bindings,
            ..Record::EMPTY
        }
    }

    fn resolve_one(table: &[Record], config: &mut Fake) -> Result<Resolved, Refusal> {
        let store: &'static mut Store = Box::leak(Box::new(Store::EMPTY));
        resolve(table, &PLATFORM, config, store)
    }

    const NVME: u32 = 0x1d0f_8061;

    #[test]
    fn a_window_in_a_bar_starts_at_the_bar_plus_its_offset() {
        let w: &'static [Window] = Box::leak(Box::new([window(
            "doorbells",
            0x1000,
            0x1000,
            At::Bar {
                id: NVME,
                index: 0,
                bar: 0,
            },
        )]));
        let t = [record("nvme", w, &[])];
        let found = resolve_one(&t, &mut t4g()).unwrap();
        let w = found.table[0].windows[0];
        // The first NVMe of the walk is at 80008000 (device 4).
        assert_eq!(
            (w.base, w.len, w.at),
            (0x8000_8000 + 0x1000, 0x1000, At::Fixed)
        );
    }

    #[test]
    fn the_index_picks_the_function_in_the_order_of_the_walk() {
        let w: &'static [Window] = Box::leak(Box::new([window(
            "regs",
            0,
            0x4000,
            At::Bar {
                id: NVME,
                index: 1,
                bar: 0,
            },
        )]));
        let t = [record("nvme", w, &[])];
        let found = resolve_one(&t, &mut t4g()).unwrap();
        // The second NVMe is device 0x1f.
        assert_eq!(found.table[0].windows[0].base, 0x8000_0000);
    }

    #[test]
    fn a_window_longer_than_the_bar_is_refused() {
        let w: &'static [Window] = Box::leak(Box::new([window(
            "regs",
            0x2000,
            0x4000,
            At::Bar {
                id: NVME,
                index: 0,
                bar: 0,
            },
        )]));
        let t = [record("nvme", w, &[])];
        let e = resolve_one(&t, &mut t4g()).err().unwrap();
        assert_eq!(
            e.cause,
            Cause::Short {
                bar: 0,
                size: 0x4000,
                wants: 0x6000
            }
        );
        assert!(e.to_string().contains("BAR 0 for regs is 0x4000 bytes"));
    }

    #[test]
    fn a_bar_the_firmware_left_empty_or_missing_is_refused() {
        let w: &'static [Window] = Box::leak(Box::new([window(
            "regs",
            0,
            0x1000,
            At::Bar {
                id: NVME,
                index: 0,
                bar: 3,
            },
        )]));
        let t = [record("nvme", w, &[])];
        let e = resolve_one(&t, &mut t4g()).err().unwrap();
        assert_eq!(e.cause, Cause::NoBar { id: NVME, bar: 3 });
    }

    #[test]
    fn the_console_function_is_not_measured_and_nothing_is_written_to_it() {
        let w: &'static [Window] = Box::leak(Box::new([window(
            "regs",
            0,
            0x1000,
            At::Bar {
                id: 0x1d0f_8250,
                index: 0,
                bar: 0,
            },
        )]));
        let t = [record("console", w, &[])];
        let mut config = t4g();
        config.log.clear();
        let e = resolve_one(&t, &mut config).err().unwrap();
        assert_eq!(
            e.cause,
            Cause::Measure {
                bar: 0,
                why: Refused::Console
            }
        );
        assert!(config.log.is_empty());
    }

    #[test]
    fn a_missing_function_stops_the_start_unless_its_record_is_optional() {
        let w: &'static [Window] = Box::leak(Box::new([window(
            "regs",
            0,
            0x1000,
            At::Config {
                id: 0x1234_5678,
                index: 0,
            },
        )]));
        let e = resolve_one(&[record("needed", w, &[])], &mut t4g())
            .err()
            .unwrap();
        assert_eq!(
            e.cause,
            Cause::NoFunction {
                id: 0x1234_5678,
                index: 0
            }
        );
        let t = [record("optional", w, &[]), record("kept", &[], &[])];
        let found = resolve_one(&t, &mut t4g()).unwrap();
        assert_eq!(found.table.len(), 1);
        assert_eq!(found.table[0].name, "kept");
        assert_eq!(found.skipped[0].unwrap().record, "optional");
        assert!(
            found.skipped[0]
                .unwrap()
                .to_string()
                .contains("walk found none")
        );
    }

    #[test]
    fn an_msi_binding_takes_the_rid_of_the_function() {
        let b: &'static [Binding] =
            Box::leak(Box::new([Binding::msi_of("vector0", 0x1d0f_ec20, 0, 3)]));
        let t = [record("ena", &[], b)];
        let found = resolve_one(&t, &mut t4g()).unwrap();
        let got = found.table[0].bindings[0];
        // Device 5, function 0: RID 0x28.
        assert_eq!(got.event(), Some((ENA.rid(), 3)));
        assert_eq!(ENA.rid(), 0x28);
        assert_eq!(got.of, None);
        assert_eq!(crate::table::msi_events(&found.table[0], 0x28), 1);
    }

    #[test]
    fn an_io_bar_gets_the_shift_of_the_bridge_window_and_a_memory_bar_none() {
        let mut config = Fake::default();
        let at = Address::new(0, 7, 0);
        config.function(at, 0x1b36, 0x0002, 0x078000, false);
        config.mem32(at, 0, 0x1000_0000, 0x1000);
        config.io(at, 1, 0x2000, 0x20);
        let w: &'static [Window] = Box::leak(Box::new([
            window(
                "mem",
                0,
                0x1000,
                At::Bar {
                    id: 0x1b36_0002,
                    index: 0,
                    bar: 0,
                },
            ),
            window(
                "io",
                0,
                0x20,
                At::Bar {
                    id: 0x1b36_0002,
                    index: 0,
                    bar: 1,
                },
            ),
        ]));
        // A class 0x07 function is refused: pretend it is a network one.
        config.words.insert((at, pci::CLASS), 0x0200_0000);
        let t = [record("both", w, &[])];
        let found = resolve_one(&t, &mut config).unwrap();
        let bases: Vec<u64> = found.table[0].windows.iter().map(|w| w.base).collect();
        assert_eq!(bases, [0x1000_0000, 0x2000 + 0x3eff_0000]);
    }

    #[test]
    fn only_a_table_that_names_places_needs_resolving() {
        let w: &'static [Window] = Box::leak(Box::new([window("a", 0x1000, 0x1000, At::Fixed)]));
        assert!(!needs(&[record("fixed", w, &[])]));
        assert!(!needs(crate::table::normal::TABLE));
        assert!(needs(crate::table::aws::TABLE));
    }

    #[test]
    fn the_walk_lists_every_function_with_its_bars_and_measures_all_but_the_console() {
        let mut config = t4g();
        let mut lines = Vec::new();
        list(&mut config, &PLATFORM, |l| lines.push(l.to_string()));
        assert_eq!(
            lines,
            [
                "pci 00:00.0 1d0f:0200 rev 05 class 060000",
                "pci 00:01.0 1d0f:8250 rev 05 class 070003 bar0 0x8000c000+?",
                "pci 00:04.0 1d0f:8061 rev 05 class 010802 bar0 0x80008000+0x4000",
                "pci 00:05.0 1d0f:ec20 rev 05 class 020000 bar0 0x80004000+0x4000",
                "pci 00:1f.0 1d0f:8061 rev 05 class 010802 bar0 0x80000000+0x4000",
            ]
        );
    }

    #[test]
    fn the_walk_shows_the_msix_capability() {
        let mut config = t4g();
        // MSI-X with 9 vectors at 0x50: the table in BAR 4 at 0, the pending array at 0x1000.
        config.words.insert((ENA, pci::CAPABILITIES), 0x50);
        config.words.insert((ENA, 0x50), 0x0008_0011);
        config.words.insert((ENA, 0x54), 0x4);
        config.words.insert((ENA, 0x58), 0x1004);
        let mut lines = Vec::new();
        list(&mut config, &PLATFORM, |l| lines.push(l.to_string()));
        assert!(
            lines[3].ends_with("msix 9 bir 4 table 0x0 pba 0x1000"),
            "{}",
            lines[3]
        );
    }
}
