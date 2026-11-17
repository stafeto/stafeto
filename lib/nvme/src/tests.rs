// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The driver against the model of the controller. Each test says which
//! deliberate break (`break-nvme-*`, `cargo xtask nvme-breaks`) it makes fail.

use crate::cmd;
use crate::device::{
    ADMIN_DEPTH, CELL, CELLS, CELLS_BYTES, ENTRY_STORES_PER_STEP, FLUSH_TAG, IO_DEPTH, MAX_PARTS,
    MEM_BYTES, REG_ACCESSES_PER_STEP, SLOW_IO_NS, ZERO_STORES_PER_STEP,
};
use crate::model::{Model, Scenario, region};
use crate::regs;
use crate::{Cause, Completion, Config, Event, Failure, Nvme, Outcome, Reject, Unsupported};

const MS: u64 = 1_000_000;
const S: u64 = 1_000 * MS;
const WRITE: u8 = cmd::NVM_WRITE;
const READ: u8 = cmd::NVM_READ;

struct Rig {
    model: Model,
    dev: Nvme<Model>,
}

fn rig_with(scenario: Scenario, cfg: Config) -> Rig {
    let mem = region(MEM_BYTES, 0x4_0000_0000);
    let cells = region(CELLS_BYTES, 0x4_0001_0000);
    let model = Model::new(mem, cells, scenario);
    // SAFETY: the regions are the model's heap blocks, which live on.
    let dev = unsafe { Nvme::open(model.platform(), mem, cells, cfg) }.unwrap();
    Rig { model, dev }
}

fn rig(scenario: Scenario) -> Rig {
    rig_with(scenario, Config::default())
}

fn up(scenario: Scenario) -> Rig {
    let mut r = rig(scenario);
    r.up();
    r
}

/// A pattern that differs from block to block and from seed to seed.
fn pat(seed: u8, n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| ((i.wrapping_mul(2_654_435_761) >> 13) as u8) ^ seed ^ (i / 512) as u8)
        .collect()
}

impl Rig {
    /// One step, which makes at most the register accesses a step may.
    fn step(&mut self) -> Event {
        let before = self.model.reg_accesses();
        let e = self.dev.poll();
        let made = self.model.reg_accesses() - before;
        assert!(
            made <= REG_ACCESSES_PER_STEP as u64,
            "{made} accesses in {e:?}"
        );
        e
    }

    /// Runs for `ns` of the model's time: steps while there is progress, then
    /// lets a millisecond pass. The events that mattered.
    fn pump(&mut self, ns: u64) -> Vec<Event> {
        let end = self.model.now() + ns;
        let mut events = Vec::new();
        while self.model.now() < end {
            for _ in 0..1000 {
                match self.step() {
                    Event::Idle => break,
                    Event::Working => {}
                    e => events.push(e),
                }
            }
            self.model.advance(MS);
        }
        events
    }

    /// Runs until `stop` is true of an event, at most `limit` ns.
    fn until(&mut self, limit: u64, stop: impl Fn(&Event) -> bool) -> Vec<Event> {
        let end = self.model.now() + limit;
        let mut events = Vec::new();
        while self.model.now() < end {
            for _ in 0..1000 {
                match self.step() {
                    Event::Idle => break,
                    Event::Working => {}
                    e => {
                        let done = stop(&e);
                        events.push(e);
                        if done {
                            return events;
                        }
                    }
                }
            }
            self.model.advance(MS);
        }
        panic!("no such event in {limit} ns: {events:?}");
    }

    fn up(&mut self) {
        self.until(30 * S, |e| *e == Event::Up);
    }

    /// The completions of the next `n` requests, in the order they came.
    fn done(&mut self, n: usize) -> Vec<Completion> {
        let mut got = Vec::new();
        let end = self.model.now() + 5 * S;
        while got.len() < n {
            assert!(self.model.now() < end, "only {got:?} of {n} requests ended");
            for _ in 0..1000 {
                match self.step() {
                    Event::Idle => break,
                    Event::Done(c) => got.push(c),
                    Event::Working => {}
                    e => panic!("unexpected {e:?}"),
                }
            }
            self.model.advance(MS);
        }
        got
    }

    fn cell(&self, k: u8) -> &'static mut [u8] {
        // SAFETY: the cell is the model's leaked block of CELL bytes.
        unsafe { std::slice::from_raw_parts_mut(self.dev.cell_va(k) as *mut u8, CELL) }
    }

    /// A submission makes at most one register access.
    fn submit(
        &mut self,
        f: impl FnOnce(&mut Nvme<Model>) -> Result<(), Reject>,
    ) -> Result<(), Reject> {
        let before = self.model.reg_accesses();
        let r = f(&mut self.dev);
        assert!(self.model.reg_accesses() - before <= REG_ACCESSES_PER_STEP as u64);
        r
    }

    fn write(&mut self, cell: u8, lba: u64, blocks: u32) -> Result<(), Reject> {
        self.submit(|d| d.write(cell, lba, blocks))
    }

    fn read(&mut self, cell: u8, lba: u64, blocks: u32) -> Result<(), Reject> {
        self.submit(|d| d.read(cell, lba, blocks))
    }

    fn flush(&mut self) -> Result<(), Reject> {
        self.submit(|d| d.flush())
    }

    /// Fills the cell with `pat(seed)`, writes it, waits.
    fn put(&mut self, cell: u8, lba: u64, blocks: u32, seed: u8) -> Vec<u8> {
        let bytes = blocks as usize * (1 << self.dev.info().unwrap().block_shift);
        let data = pat(seed, bytes);
        self.cell(cell)[..bytes].copy_from_slice(&data);
        self.write(cell, lba, blocks).unwrap();
        let done = self.done(1);
        assert_eq!(
            done,
            [Completion {
                tag: cell,
                outcome: Outcome::Ok
            }]
        );
        data
    }

    fn clean(&self) {
        assert_eq!(self.model.violations(), Vec::<String>::new());
        assert_eq!(self.dev.stray(), 0);
    }
}

type Tweak = Box<dyn Fn(&mut Scenario)>;

fn s() -> Scenario {
    Scenario::default()
}

// ----- the numbers -----

#[test]
fn cap_fields_are_decoded_from_the_two_halves() {
    // MQES 1023, TO 20 (10 s), DSTRD 2, CSS 1, MPSMIN 0, MPSMAX 4.
    let cap = regs::Cap::decode(1023 | 1 << 16 | 20 << 24, 2 | 1 << 5 | 4 << 20);
    assert_eq!((cap.mqes, cap.to, cap.dstrd, cap.css), (1023, 20, 2, 1));
    assert_eq!((cap.mpsmin, cap.mpsmax), (0, 4));
    assert_eq!(cap.timeout_ns(), 10 * S);
    // A TO of 0 still waits one unit.
    assert_eq!(regs::Cap::decode(0, 0).timeout_ns(), 500 * MS);
}

#[test]
fn the_enable_word_selects_what_the_driver_runs() {
    let cc = regs::cc_enable();
    assert_eq!(cc & regs::CC_EN, 1);
    assert_eq!(cc >> regs::CC_IOSQES_SHIFT & 0xf, 6);
    assert_eq!(cc >> regs::CC_IOCQES_SHIFT & 0xf, 4);
    // NVM command set, 4 KiB pages, round robin, no shutdown.
    assert_eq!(cc & !(regs::CC_EN | 0xff << 16), 0);
}

#[test]
fn doorbells_follow_the_stride_of_cap() {
    assert_eq!(regs::sq_tail_db(0, 0), 0x1000);
    assert_eq!(regs::cq_head_db(0, 0), 0x1004);
    assert_eq!(regs::sq_tail_db(1, 0), 0x1008);
    assert_eq!(regs::cq_head_db(1, 0), 0x100c);
    // DSTRD 2: 16 bytes between doorbells.
    assert_eq!(regs::sq_tail_db(1, 2), 0x1020);
    assert_eq!(regs::cq_head_db(1, 2), 0x1030);
}

#[test]
fn the_entries_have_the_layout_of_the_specification() {
    let mut e = cmd::sqe(cmd::NVM_READ, 0x1234, 1);
    cmd::set_prp(&mut e, 0x1_2345_6000, 0x7_8000);
    cmd::set_rw(&mut e, 0x2_0000_0005, 8);
    assert_eq!(e[0], 0x1234_0002);
    assert_eq!(e[1], 1);
    assert_eq!((e[6], e[7], e[8], e[9]), (0x2345_6000, 1, 0x7_8000, 0));
    assert_eq!((e[10], e[11], e[12]), (5, 2, 7));
    // Dword 3: CID 7, phase 1, SC 0x80, SCT 2.
    let q = cmd::Cqe::decode([9, 0, 3 | 1 << 16, 7 | 1 << 16 | 0x80 << 17 | 2 << 25]);
    assert_eq!((q.result, q.sq_head, q.sq_id, q.cid), (9, 3, 1, 7));
    assert_eq!((q.phase, q.sc, q.sct), (true, 0x80, 2));
    assert!(!q.ok());
    assert!(cmd::Cqe::decode([0, 0, 0, 1 << 16]).ok());
}

#[test]
fn prp_entries_follow_the_pages_of_a_part() {
    let (first, list) = (0x8_0000u64, 0x9_0100u64);
    assert_eq!(cmd::prps(first, 512, list), (first, 0));
    assert_eq!(cmd::prps(first, 4096, list), (first, 0));
    // Two pages: PRP2 is the second page. Break prp2 does it for more too.
    assert_eq!(cmd::prps(first, 8192, list), (first, first + 4096));
    assert_eq!(cmd::prps(first, 4097, list), (first, first + 4096));
    // Three and four pages: PRP2 is the list.
    assert_eq!(cmd::prps(first, 12288, list), (first, list));
    assert_eq!(cmd::prps(first, 16384, list), (first, list));
}

#[test]
fn the_bounds_of_a_step_are_the_ones_the_comments_state() {
    assert_eq!(REG_ACCESSES_PER_STEP, 1);
    assert_eq!(ZERO_STORES_PER_STEP, 256);
    assert_eq!(ENTRY_STORES_PER_STEP, 16);
    assert_eq!(MAX_PARTS, 2);
    assert_eq!((CELL, CELLS, IO_DEPTH, ADMIN_DEPTH), (16384, 4, 32, 16));
    // At most MAX_PARTS commands a cell, and a Flush: the queue holds them.
    const { assert!(CELLS * MAX_PARTS + 1 < IO_DEPTH as usize) };
}

// ----- the bring-up -----

#[test]
fn a_controller_comes_up_and_identify_is_read() {
    let mut s = s();
    s.vwc = true;
    s.mdts = 3;
    s.blocks = 4096;
    let r = up(s);
    let i = r.dev.info().unwrap();
    assert_eq!(i.version, 0x0002_0000);
    assert_eq!(&i.serial[..17], b"MODEL-SERIAL-0001");
    assert!(i.model.starts_with(b"stafeto model controller"));
    assert!(i.firmware.starts_with(b"1.0 "));
    assert!(i.vendor_name.starts_with(b"/dev/sdf\0"));
    assert_eq!((i.nn, i.vwc, i.mdts), (1, true, 3));
    // 4 KiB << 3 is more than a cell.
    assert_eq!(i.max_transfer, CELL);
    assert_eq!((i.nsid, i.blocks, i.block_shift), (1, 4096, 9));
    assert!(r.dev.is_up());
    assert_eq!(r.dev.blocks(), 4096);
    r.clean();
}

#[test]
fn the_registers_are_written_in_the_order_the_specification_gives() {
    let r = up(s());
    let log = r.model.reg_log();
    let first_db = log.iter().position(|(o, _)| *o >= regs::DB_BASE).unwrap();
    // The queue registers, then CC, before the first doorbell.
    let pa = 0x4_0000_0000u64;
    assert_eq!(
        &log[..first_db],
        &[
            (regs::AQA, 15 | 15 << 16),
            (regs::ASQ_LO, pa as u32),
            (regs::ASQ_HI, (pa >> 32) as u32),
            (regs::ACQ_LO, (pa + 0x1000) as u32),
            (regs::ACQ_HI, ((pa + 0x1000) >> 32) as u32),
            (regs::CC, regs::cc_enable()),
        ]
    );
    r.clean();
}

#[test]
fn an_enabled_controller_is_disabled_and_waited_for_before_it_is_set_up() {
    // Catches break-nvme-reset-wait.
    let mut s = s();
    s.initially_enabled = true;
    s.clear_delay_ns = 300 * MS;
    let r = up(s);
    let log = r.model.reg_log();
    assert_eq!(log[0], (regs::CC, 0));
    assert_eq!(log[1].0, regs::AQA);
    // The model saw no enable before RDY fell.
    r.clean();
}

#[test]
fn the_admin_commands_come_in_order_and_one_queue_pair_is_made() {
    let r = up(s());
    assert_eq!(
        r.model.commands(),
        [
            (0, cmd::ADMIN_SET_FEATURES),
            (0, cmd::ADMIN_IDENTIFY),
            (0, cmd::ADMIN_IDENTIFY),
            (0, cmd::ADMIN_CREATE_CQ),
            (0, cmd::ADMIN_CREATE_SQ),
        ]
    );
    // Polled: no interrupt on the I/O queue.
    assert_eq!(r.model.created(), [(1, IO_DEPTH, false, 0)]);
    let mut v = rig_with(
        s(),
        Config {
            vector: Some(1),
            ..Config::default()
        },
    );
    v.up();
    assert_eq!(v.model.created(), [(1, IO_DEPTH, true, 1)]);
    v.clean();
}

#[test]
fn a_deep_admin_wrap_is_followed_with_a_queue_of_two() {
    // Five commands through two entries: the phase flips twice.
    let mut r = rig_with(
        s(),
        Config {
            admin_depth: 2,
            ..Config::default()
        },
    );
    r.up();
    assert_eq!(r.model.commands().len(), 5);
    r.clean();
}

#[test]
fn a_block_size_of_4096_is_taken() {
    let mut s = s();
    s.lba_shift = 12;
    s.blocks = 1024;
    let r = up(s);
    assert_eq!(r.dev.info().unwrap().block_shift, 12);
    r.clean();
}

#[test]
fn a_namespace_the_driver_cannot_run_ends_the_bring_up() {
    let cases: [Tweak; 3] = [
        Box::new(|s| s.metadata = true),
        Box::new(|s| s.odd_shift = Some(10)),
        Box::new(|s| s.no_namespace = true),
    ];
    for c in cases {
        let mut s = s();
        c(&mut s);
        let mut r = rig(s);
        let e = r.until(30 * S, |e| matches!(e, Event::Failed(_)));
        assert_eq!(e, [Event::Failed(Failure::Namespace)]);
        assert!(!r.dev.is_up());
        assert_eq!(r.write(0, 0, 1), Err(Reject::NotUp));
    }
}

#[test]
fn what_cap_lacks_ends_the_bring_up_before_a_queue_is_set_up() {
    let cases: [(Tweak, Unsupported); 3] = [
        (Box::new(|s| s.css = 0), Unsupported::CommandSet),
        (Box::new(|s| s.mpsmin = 1), Unsupported::PageSize),
        (Box::new(|s| s.mqes = 15), Unsupported::QueueSize),
    ];
    for (c, what) in cases {
        let mut s = s();
        c(&mut s);
        let mut r = rig(s);
        let e = r.until(S, |e| matches!(e, Event::Failed(_)));
        assert_eq!(e, [Event::Failed(Failure::Unsupported(what))]);
        // Only the disable of the quiesce: no queue was set up.
        assert!(r.model.reg_log().iter().all(|w| *w == (regs::CC, 0)));
    }
}

#[test]
fn an_admin_error_status_ends_the_bring_up_with_the_opcode_and_the_status() {
    let mut s = s();
    s.admin_error = Some((cmd::ADMIN_IDENTIFY, 0, cmd::SC_INVALID_FIELD));
    let mut r = rig(s);
    let e = r.until(30 * S, |e| matches!(e, Event::Failed(_)));
    assert_eq!(
        e,
        [Event::Failed(Failure::Admin {
            opcode: cmd::ADMIN_IDENTIFY,
            sct: 0,
            sc: cmd::SC_INVALID_FIELD
        })]
    );
}

#[test]
fn a_slow_ready_is_waited_for_within_cap_to() {
    let mut s = s();
    s.to = 2;
    s.rdy_delay_ns = 900 * MS;
    let r = up(s);
    assert_eq!(r.dev.resets(), 0);
    r.clean();
}

#[test]
fn a_controller_that_is_never_ready_is_reset_and_given_up_after_three() {
    let mut s = s();
    s.never_ready = true;
    let mut r = rig(s);
    let e = r.until(60 * S, |e| matches!(e, Event::Failed(_)));
    assert_eq!(
        e,
        [
            Event::Reset(Cause::NotReady),
            Event::Reset(Cause::NotReady),
            Event::Reset(Cause::NotReady),
            Event::Failed(Failure::TooManyResets)
        ]
    );
    assert_eq!(r.dev.resets(), 3);
}

#[test]
fn a_controller_that_never_clears_ready_is_reset_by_the_deadline() {
    let mut s = s();
    s.initially_enabled = true;
    s.never_clear = true;
    let mut r = rig(s);
    let t0 = r.model.now();
    let e = r.until(60 * S, |e| matches!(e, Event::Reset(_)));
    assert_eq!(e, [Event::Reset(Cause::NotCleared)]);
    // After CAP.TO x 500 ms (1 s here) and no sooner.
    assert!(r.model.now() - t0 >= S);
}

#[test]
fn an_admin_command_without_an_answer_resets_after_cap_to_and_the_next_try_comes_up() {
    let mut s = s();
    s.admin_dead = true;
    let mut r = rig(s);
    let t0 = r.model.now();
    r.until(30 * S, |e| *e == Event::Reset(Cause::AdminTimeout));
    assert!(r.model.now() - t0 >= S);
    r.model.set(|s| s.admin_dead = false);
    r.up();
    assert_eq!(r.dev.resets(), 1);
    r.clean();
}

#[test]
fn a_function_that_is_gone_at_the_start_ends_the_bring_up() {
    let mut r = rig(s());
    r.model.set_gone(true);
    let e = r.until(S, |e| matches!(e, Event::Failed(_)));
    assert_eq!(e, [Event::Failed(Failure::Gone)]);
}

#[test]
fn the_regions_are_checked_when_the_driver_opens() {
    let mem = region(MEM_BYTES, 0x4_0000_0000);
    let small = region(MEM_BYTES - 4096, 0x4_0000_0000);
    let cells = region(CELLS_BYTES, 0x4_0001_0000);
    let odd = region(CELLS_BYTES, 0x4_0001_0200);
    let m = Model::new(mem, cells, s());
    // SAFETY: heap blocks that live on.
    unsafe {
        assert!(matches!(
            Nvme::open(m.platform(), small, cells, Config::default()),
            Err(Failure::Region)
        ));
        assert!(matches!(
            Nvme::open(m.platform(), mem, odd, Config::default()),
            Err(Failure::Region)
        ));
        let c = Config {
            admin_depth: 1,
            ..Config::default()
        };
        assert!(matches!(
            Nvme::open(m.platform(), mem, cells, c),
            Err(Failure::Region)
        ));
    }
}

// ----- reads and writes -----

#[test]
fn a_write_then_a_read_returns_the_data_for_every_size_and_block_size() {
    // Catches break-nvme-prp2 (the sizes over two pages).
    for shift in [9u8, 12] {
        let mut sc = s();
        sc.lba_shift = shift;
        sc.blocks = 1024;
        let mut r = up(sc);
        let bs = 1u32 << shift;
        // One block, one page, two pages, three, four, and a part page.
        for (n, bytes) in [1u32, 4096, 8192, 12288, 16384, 4096 + bs.min(512)]
            .iter()
            .enumerate()
        {
            let blocks = bytes.div_ceil(bs).max(1);
            let lba = 16 + 20 * n as u64;
            let data = r.put(0, lba, blocks, n as u8 + 1);
            assert_eq!(
                r.model.media(lba, blocks as u64),
                data,
                "shift {shift} bytes {bytes}"
            );
            r.cell(1).fill(0xEE);
            r.read(1, lba, blocks).unwrap();
            assert_eq!(
                r.done(1),
                [Completion {
                    tag: 1,
                    outcome: Outcome::Ok
                }]
            );
            assert_eq!(&r.cell(1)[..data.len()], &data[..]);
            // Nothing past the transfer was touched.
            assert!(r.cell(1)[data.len()..].iter().all(|b| *b == 0xEE));
        }
        r.clean();
    }
}

#[test]
fn four_cells_in_flight_complete_in_the_order_the_controller_chooses() {
    let mut r = up(s());
    r.model.push_delays(&[30 * MS, 10 * MS, 20 * MS, 5 * MS]);
    let data: Vec<Vec<u8>> = (0..4).map(|k| pat(k as u8 + 1, CELL)).collect();
    for k in 0..4u8 {
        r.cell(k).copy_from_slice(&data[k as usize]);
        r.write(k, 64 * k as u64, 32).unwrap();
    }
    let tags: Vec<u8> = r.done(4).iter().map(|c| c.tag).collect();
    assert_eq!(tags, [3, 1, 2, 0]);
    for k in 0..4u64 {
        assert_eq!(r.model.media(64 * k, 32), data[k as usize]);
    }
    r.clean();
}

#[test]
fn a_part_of_a_cell_is_cut_at_mdts() {
    for (mdts, blocks, commands) in [
        (1u8, 32u32, 2usize),
        (1, 24, 2),
        (1, 16, 1),
        (2, 32, 1),
        (0, 32, 1),
    ] {
        let mut sc = s();
        sc.mdts = mdts;
        let mut r = up(sc);
        let data = r.put(0, 8, blocks, 9);
        assert_eq!(
            r.model.count_commands(1, WRITE),
            commands,
            "mdts {mdts} blocks {blocks}"
        );
        assert_eq!(r.model.media(8, blocks as u64), data);
        r.read(2, 8, blocks).unwrap();
        // One completion for the request, whatever the parts.
        assert_eq!(
            r.done(1),
            [Completion {
                tag: 2,
                outcome: Outcome::Ok
            }]
        );
        assert_eq!(&r.cell(2)[..data.len()], &data[..]);
        r.clean();
    }
}

#[test]
fn the_phase_and_the_heads_wrap_many_times() {
    // Catches break-nvme-cq-phase, break-nvme-cq-head and break-nvme-sq-head:
    // 200 requests through 32 entries.
    let mut r = up(s());
    for n in 0..200u64 {
        let cell = (n % 4) as u8;
        let data = r.put(cell, n % 100, 8, n as u8);
        r.read((cell + 1) % 4, n % 100, 8).unwrap();
        assert_eq!(r.done(1)[0].outcome, Outcome::Ok);
        assert_eq!(&r.cell((cell + 1) % 4)[..data.len()], &data[..]);
    }
    r.clean();
}

#[test]
fn requests_with_parts_and_flushes_wrap_the_submission_queue_off_its_alignment() {
    // Nine commands a round (four cells in two parts, one Flush) through 32
    // entries: the tail wraps in the middle of a request.
    let mut sc = s();
    sc.mdts = 1;
    sc.vwc = true;
    let mut r = up(sc);
    for round in 0..20u8 {
        let data: Vec<Vec<u8>> = (0..4).map(|k| pat(round + k, CELL)).collect();
        for k in 0..4u8 {
            r.cell(k).copy_from_slice(&data[k as usize]);
            r.write(k, 32 * k as u64, 32).unwrap();
        }
        let mut seen = r.done(4);
        seen.sort_by_key(|c| c.tag);
        assert!(seen.iter().all(|c| c.outcome == Outcome::Ok));
        r.flush().unwrap();
        assert_eq!(
            r.done(1),
            [Completion {
                tag: FLUSH_TAG,
                outcome: Outcome::Ok
            }]
        );
        for k in 0..4u64 {
            assert_eq!(r.model.media(32 * k, 32), data[k as usize], "round {round}");
        }
    }
    r.clean();
}

#[test]
fn a_doorbell_stride_other_than_4_is_followed() {
    // Catches break-nvme-dstrd.
    let mut sc = s();
    sc.dstrd = 3;
    let mut r = up(sc);
    let data = r.put(0, 4, 8, 3);
    assert_eq!(r.model.media(4, 8), data);
    r.clean();
}

#[test]
fn the_barrier_comes_before_every_submission_doorbell() {
    // Catches break-nvme-wmb: the model notes a doorbell with no barrier.
    let mut r = up(s());
    r.put(0, 0, 8, 1);
    r.put(1, 8, 8, 2);
    let log = r.model.reg_log();
    let doorbells = log
        .iter()
        .filter(|(o, _)| *o == regs::sq_tail_db(1, 0))
        .count();
    assert_eq!(doorbells, 2);
    r.clean();
}

#[test]
fn each_completion_is_acknowledged_with_a_head_doorbell() {
    // Catches break-nvme-cq-head.
    let mut r = up(s());
    for n in 0..5u8 {
        r.put(0, n as u64, 1, n);
    }
    let heads: Vec<u32> = r
        .model
        .reg_log()
        .iter()
        .filter(|(o, _)| *o == regs::cq_head_db(1, 0))
        .map(|(_, v)| *v)
        .collect();
    assert_eq!(heads, [1, 2, 3, 4, 5]);
}

#[test]
fn an_error_status_is_reported_and_the_cell_can_be_used_again() {
    let mut r = up(s());
    r.model.set(|s| s.io_error = Some((READ, 2, 0x81)));
    r.read(0, 0, 8).unwrap();
    assert_eq!(
        r.done(1),
        [Completion {
            tag: 0,
            outcome: Outcome::Error {
                sct: 2,
                sc: 0x81,
                dnr: false
            }
        }]
    );
    r.model.set(|s| s.io_error = None);
    r.put(0, 0, 8, 5);
    r.clean();
}

#[test]
fn requests_that_cannot_be_taken_say_why() {
    let mut r = rig(s());
    assert_eq!(r.write(0, 0, 1), Err(Reject::NotUp));
    assert_eq!(r.flush(), Err(Reject::NotUp));
    r.up();
    assert_eq!(r.write(4, 0, 1), Err(Reject::Invalid));
    assert_eq!(r.write(0, 0, 0), Err(Reject::Invalid));
    assert_eq!(r.write(0, 0, 33), Err(Reject::Invalid));
    assert_eq!(r.read(0, 8192, 1), Err(Reject::Range));
    assert_eq!(r.read(0, 8191, 2), Err(Reject::Range));
    assert_eq!(r.read(0, u64::MAX, 2), Err(Reject::Range));
    assert_eq!(r.read(0, 8191, 1), Ok(()));
    assert_eq!(r.read(0, 0, 1), Err(Reject::Busy));
    assert_eq!(r.flush(), Ok(()));
    assert_eq!(r.flush(), Err(Reject::Busy));
}

#[test]
fn a_window_confines_the_requests_and_moves_their_origin() {
    // Catches break-nvme-partition.
    let mut r = up(s());
    assert!(!r.dev.set_window(8000, 500));
    assert!(r.dev.set_window(100, 50));
    assert_eq!(r.dev.blocks(), 50);
    let data = r.put(0, 49, 1, 7);
    assert_eq!(r.model.media(149, 1), data);
    assert_eq!(r.write(0, 50, 1), Err(Reject::Range));
    assert_eq!(r.write(0, 49, 2), Err(Reject::Range));
    assert_eq!(r.model.media(150, 1), vec![0; 512]);
    r.clean();
}

// ----- flush -----

#[test]
fn a_volatile_cache_loses_what_was_not_flushed_and_keeps_what_was() {
    let mut sc = s();
    sc.vwc = true;
    let mut r = up(sc);
    assert!(r.dev.info().unwrap().vwc);
    let a = r.put(0, 0, 8, 1);
    r.model.power_loss();
    assert_eq!(r.model.media(0, 8), vec![0; 4096]);
    let b = r.put(0, 8, 8, 2);
    r.flush().unwrap();
    assert_eq!(
        r.done(1),
        [Completion {
            tag: FLUSH_TAG,
            outcome: Outcome::Ok
        }]
    );
    r.model.power_loss();
    assert_eq!(r.model.media(8, 8), b);
    // The cache was whole when it was flushed: `a` is in the media too
    // (it was lost before, so it is zero).
    assert_ne!(r.model.media(0, 8), a);
    assert_eq!(r.model.flush_commands(), 1);
    r.clean();
}

#[test]
fn a_flush_waits_for_the_writes_in_work_before_the_command_is_sent() {
    // Catches break-nvme-flush-early.
    let mut sc = s();
    sc.vwc = true;
    let mut r = up(sc);
    r.model.push_delays(&[20 * MS, 40 * MS]);
    r.cell(0).fill(1);
    r.cell(1).fill(2);
    r.write(0, 0, 8).unwrap();
    r.write(1, 8, 8).unwrap();
    r.flush().unwrap();
    let tags: Vec<u8> = r.done(3).iter().map(|c| c.tag).collect();
    assert_eq!(tags, [0, 1, FLUSH_TAG]);
    // The Flush was taken after both writes completed (else the model notes it).
    r.clean();
    r.model.power_loss();
    assert_eq!(r.model.media(0, 8), vec![1; 4096]);
    assert_eq!(r.model.media(8, 8), vec![2; 4096]);
}

#[test]
fn without_a_volatile_cache_flush_sends_nothing_and_ends_after_the_writes() {
    // Catches break-nvme-flush-early.
    let mut r = up(s());
    assert!(!r.dev.info().unwrap().vwc);
    r.model.push_delays(&[25 * MS, 5 * MS]);
    r.cell(0).fill(3);
    r.cell(1).fill(4);
    r.write(0, 0, 8).unwrap();
    r.write(1, 8, 8).unwrap();
    r.flush().unwrap();
    let tags: Vec<u8> = r.done(3).iter().map(|c| c.tag).collect();
    // Cell 1 first (shorter delay), then cell 0, then the Flush.
    assert_eq!(tags, [1, 0, FLUSH_TAG]);
    assert_eq!(r.model.flush_commands(), 0);
    r.model.power_loss();
    assert_eq!(r.model.media(0, 8), vec![3; 4096]);
    r.clean();
}

#[test]
fn a_flush_with_nothing_in_work_ends_at_once() {
    for vwc in [false, true] {
        let mut sc = s();
        sc.vwc = vwc;
        let mut r = up(sc);
        r.flush().unwrap();
        assert_eq!(
            r.done(1),
            [Completion {
                tag: FLUSH_TAG,
                outcome: Outcome::Ok
            }]
        );
        assert_eq!(r.model.flush_commands(), vwc as u32);
        r.clean();
    }
}

// ----- timeouts and reset -----

#[test]
fn a_fatal_status_resets_the_controller_ends_the_requests_and_comes_up_again() {
    let mut sc = s();
    sc.vwc = true;
    let mut r = up(sc);
    let kept = r.put(0, 0, 8, 1);
    r.flush().unwrap();
    r.done(1);
    r.model.set(|s| s.io_delay_ns = 5 * S);
    r.cell(1).fill(9);
    r.write(1, 8, 8).unwrap();
    r.flush().unwrap();
    r.model.inject_fatal();
    let e = r.until(30 * S, |e| *e == Event::Up);
    assert_eq!(
        e,
        [
            Event::Reset(Cause::Fatal),
            Event::Done(Completion {
                tag: 1,
                outcome: Outcome::Aborted
            }),
            Event::Done(Completion {
                tag: FLUSH_TAG,
                outcome: Outcome::Aborted
            }),
            Event::Up
        ]
    );
    assert_eq!(r.dev.resets(), 1);
    assert_eq!(r.model.controller_resets(), 1);
    // The queues are made again, the cells are free, the flushed data is there.
    r.model.set(|s| s.io_delay_ns = 0);
    r.read(2, 0, 8).unwrap();
    assert_eq!(r.done(1)[0].outcome, Outcome::Ok);
    assert_eq!(&r.cell(2)[..4096], &kept[..]);
    assert_eq!(r.model.count_commands(0, cmd::ADMIN_CREATE_SQ), 2);
    r.clean();
}

#[test]
fn a_function_that_goes_away_ends_the_requests_and_stops_the_driver() {
    let mut r = up(s());
    r.model.set(|s| s.io_delay_ns = 5 * S);
    r.write(0, 0, 8).unwrap();
    r.model.set_gone(true);
    let e = r.until(30 * S, |e| matches!(e, Event::Failed(_)));
    assert_eq!(
        e,
        [
            Event::Reset(Cause::Gone),
            Event::Done(Completion {
                tag: 0,
                outcome: Outcome::Aborted
            }),
            Event::Failed(Failure::Gone)
        ]
    );
    assert_eq!(r.write(0, 0, 1), Err(Reject::NotUp));
}

#[test]
fn a_command_that_waits_a_long_time_is_noted_once_and_never_cut_off() {
    let mut r = up(s());
    r.model.set(|s| s.io_delay_ns = 45 * S);
    r.cell(0).fill(6);
    r.write(0, 0, 8).unwrap();
    let e = r.until(60 * S, |e| matches!(e, Event::Done(_) | Event::Reset(_)));
    assert_eq!(
        e,
        [Event::Done(Completion {
            tag: 0,
            outcome: Outcome::Ok
        })]
    );
    let noted: Vec<String> = r
        .model
        .log_lines()
        .into_iter()
        .filter(|l| l.contains("waits for over 30 s"))
        .collect();
    assert_eq!(noted.len(), 1, "{noted:?}");
    assert_eq!(r.dev.resets(), 0);
    assert_eq!(SLOW_IO_NS, 30 * S);
    r.clean();
}

#[test]
fn resets_spaced_out_are_each_recovered() {
    let mut r = up(s());
    for n in 1..=5u64 {
        r.pump(70 * S);
        r.model.inject_fatal();
        r.until(30 * S, |e| *e == Event::Up);
        assert_eq!(r.dev.resets(), n);
        r.put(0, n, 1, n as u8);
    }
    r.clean();
}

#[test]
fn three_resets_inside_a_minute_end_the_recovery() {
    let mut r = up(s());
    let mut events = Vec::new();
    for _ in 0..3 {
        r.model.inject_fatal();
        events.extend(r.until(30 * S, |e| matches!(e, Event::Up | Event::Failed(_))));
    }
    assert_eq!(events.last(), Some(&Event::Failed(Failure::TooManyResets)));
    assert!(!r.dev.is_up());
}

#[test]
fn a_shutdown_ends_the_requests_then_notifies_then_disables() {
    let mut r = up(s());
    r.model.set(|s| {
        s.io_delay_ns = 5 * S;
        s.shutdown_delay_ns = 30 * MS;
    });
    r.write(0, 0, 8).unwrap();
    let before = r.model.reg_log().len();
    r.dev.shutdown();
    let e = r.until(10 * S, |e| *e == Event::Stopped);
    assert_eq!(
        e,
        [
            Event::Done(Completion {
                tag: 0,
                outcome: Outcome::Aborted
            }),
            Event::Stopped
        ]
    );
    let log = r.model.reg_log();
    assert_eq!(
        &log[before..],
        &[
            (regs::CC, regs::cc_enable() | regs::CC_SHN_NORMAL),
            (regs::CC, 0)
        ]
    );
    assert_eq!(r.write(0, 0, 1), Err(Reject::NotUp));
}

#[test]
fn a_shutdown_the_controller_never_finishes_is_a_failure_after_five_seconds() {
    let mut r = up(s());
    r.model.set(|s| s.shutdown_never = true);
    r.dev.shutdown();
    let t0 = r.model.now();
    let e = r.until(30 * S, |e| matches!(e, Event::Failed(_)));
    assert_eq!(e, [Event::Failed(Failure::Shutdown)]);
    assert!(r.model.now() - t0 >= 5 * S);
}

#[test]
fn the_steps_of_a_long_run_make_one_register_access_at_most() {
    // `step` and `submit` assert it on every call: a bring-up, a reset, a
    // run with parts and a flush.
    let mut sc = s();
    sc.mdts = 1;
    sc.vwc = true;
    let mut r = up(sc);
    for n in 0..30u8 {
        r.put(n % 4, n as u64, 32, n);
        r.flush().unwrap();
        r.done(1);
    }
    r.model.inject_fatal();
    r.until(30 * S, |e| *e == Event::Up);
    r.clean();
}

// ----- the review's fixes -----

#[test]
fn the_window_survives_a_reset_in_place() {
    let mut r = up(s());
    assert!(r.dev.set_window(100, 50));
    r.model.inject_fatal();
    r.until(30 * S, |e| *e == Event::Up);
    assert_eq!(r.dev.blocks(), 50);
    let data = r.put(0, 49, 1, 7);
    assert_eq!(r.model.media(149, 1), data);
    assert_eq!(r.write(0, 50, 1), Err(Reject::Range));
    r.clean();
}

#[test]
fn a_shutdown_before_the_controller_is_up_only_disables_it() {
    for polls in [0, 3, 8, 12] {
        let mut r = rig(s());
        for _ in 0..polls {
            r.step();
        }
        r.dev.shutdown();
        let e = r.until(10 * S, |e| *e == Event::Stopped);
        assert_eq!(e, [Event::Stopped]);
        // CC is never written with EN and SHN: no queues exist to shut down.
        assert!(
            r.model
                .reg_log()
                .iter()
                .all(|(o, v)| *o != regs::CC || *v & regs::CC_SHN_MASK == 0),
            "{polls}: {:?}",
            r.model.reg_log()
        );
        assert_eq!(r.model.reg_log().last().unwrap(), &(regs::CC, 0));
        r.clean();
    }
}

#[test]
fn a_shutdown_during_a_reset_ends_in_stopped() {
    let mut r = up(s());
    r.model.inject_fatal();
    r.step();
    r.dev.shutdown();
    r.until(10 * S, |e| *e == Event::Stopped);
}

#[test]
fn requests_are_handed_back_only_after_the_controller_stopped() {
    // Catches break-nvme-abort-early: the controller keeps its commands, and
    // may still move data into a cell, until CSTS.RDY falls.
    let mut sc = s();
    sc.clear_delay_ns = 300 * MS;
    let mut r = up(sc);
    r.model.set(|s| s.io_delay_ns = 200 * MS);
    r.cell(0).fill(0);
    r.read(0, 0, 8).unwrap();
    r.model.inject_fatal();
    r.until(30 * S, |e| matches!(e, Event::Done(_)));
    assert_eq!(r.model.in_work(), 0);
    let dma = r.model.dma_count();
    r.pump(S);
    assert_eq!(r.model.dma_count(), dma);
    r.clean();
}

#[test]
fn a_controller_that_is_still_becoming_ready_is_waited_for_before_it_is_disabled() {
    let mut sc = s();
    sc.initially_enabled = true;
    sc.initial_rdy_after_ns = 300 * MS;
    let mut r = rig(sc);
    let t0 = r.model.now();
    r.up();
    assert_eq!(r.model.reg_log()[0], (regs::CC, 0));
    // The model notes an EN cleared before RDY rose.
    r.clean();
    assert!(r.model.now() - t0 >= 300 * MS);
}

#[test]
fn a_controller_that_never_becomes_ready_is_disabled_after_cap_to() {
    let mut sc = s();
    sc.initially_enabled = true;
    sc.initial_rdy_after_ns = 10 * S;
    let mut r = rig(sc);
    let t0 = r.model.now();
    while r.model.reg_log().is_empty() {
        r.step();
        r.model.advance(MS);
        assert!(r.model.now() - t0 < 5 * S);
    }
    assert!(r.model.now() - t0 >= S);
}

#[test]
fn the_do_not_retry_bit_is_reported() {
    let mut sc = s();
    sc.dnr = true;
    let mut r = up(sc);
    r.model.set(|s| s.io_error = Some((READ, 2, 0x81)));
    r.read(0, 0, 8).unwrap();
    assert_eq!(
        r.done(1)[0].outcome,
        Outcome::Error {
            sct: 2,
            sc: 0x81,
            dnr: true
        }
    );
    assert!(cmd::Cqe::decode([0, 0, 0, 1 << 31]).dnr);
}

#[test]
fn the_reset_window_grows_with_cap_to() {
    // CAP.TO of 200 is 100 s: three resets 70 s apart are inside 3 x 100 s.
    let mut sc = s();
    sc.to = 200;
    let mut r = up(sc);
    let mut last = None;
    for _ in 0..3 {
        r.pump(70 * S);
        r.model.inject_fatal();
        let e = r.until(30 * S, |e| matches!(e, Event::Up | Event::Failed(_)));
        last = e.last().copied();
    }
    assert_eq!(last, Some(Event::Failed(Failure::TooManyResets)));
}
