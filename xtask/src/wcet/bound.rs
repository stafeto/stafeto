// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The computed bound of `wcet bound`: the longest path of a function in
//! instructions, from the control-flow graph of its basic blocks and the call
//! graph (both from the disassembly, `Image`), with a bound for every loop
//! and the paths that cannot run from the annotations in tools/wcet/bounds.toml.
//!
//! The cost of a block is its number of instructions plus the bound of every
//! function it calls. At a branch the path takes the longer way. A loop costs
//! (B - 1) times its longest pass from the header back to the header, plus the
//! longest way from the header to the place the path leaves the loop at, B
//! being the bound of the annotation: the most times the header runs for one
//! entry into the loop. A path that ends in a call that does not return (a
//! panic, which stops the machine) is no path of the analysis.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use super::{Flow, Image, parse_hex};

// ---- the annotations ----

/// A value of the subset of TOML the annotation file uses.
#[derive(Debug, Clone, PartialEq)]
enum Value {
    Text(String),
    Number(i64),
    List(Vec<String>),
}

type Table = BTreeMap<String, Value>;

/// `line` without its comment: a `#` outside a quoted string starts one.
fn strip_comment(line: &str) -> &str {
    let mut quoted = false;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        match c {
            '\\' if quoted => escaped = !escaped,
            '"' if !escaped => quoted = !quoted,
            '#' if !quoted => return &line[..i],
            _ => escaped = false,
        }
    }
    line
}

fn parse_text(text: &str) -> Result<String, String> {
    let inner = text
        .strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .ok_or_else(|| format!("{text:?} is no string"))?;
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some(other) => out.push(other),
                None => return Err(format!("{text:?} ends in a backslash")),
            }
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

fn parse_value(text: &str) -> Result<Value, String> {
    let text = text.trim();
    if text.starts_with('"') {
        return parse_text(text).map(Value::Text);
    }
    if let Some(list) = text.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
        let mut items = Vec::new();
        let mut rest = list.trim();
        while !rest.is_empty() {
            // The end of the next string: the first quote that no backslash escapes.
            let mut end = None;
            let mut escaped = false;
            for (i, c) in rest.char_indices().skip(1) {
                match c {
                    '\\' => escaped = !escaped,
                    '"' if !escaped => {
                        end = Some(i);
                        break;
                    }
                    _ => escaped = false,
                }
            }
            let end = end.ok_or_else(|| format!("{text:?}: a string does not end"))?;
            items.push(parse_text(&rest[..=end])?);
            rest = rest[end + 1..].trim_start();
            rest = rest.strip_prefix(',').unwrap_or(rest).trim_start();
        }
        return Ok(Value::List(items));
    }
    text.replace('_', "")
        .parse()
        .map(Value::Number)
        .map_err(|_| format!("{text:?} is no string, number or list of strings"))
}

/// The tables of `[name]` and `[[name]]` headers in the order they come:
/// `(name, key = value pairs)`.
fn parse_tables(text: &str) -> Result<Vec<(String, Table)>, String> {
    let mut tables: Vec<(String, Table)> = Vec::new();
    let mut pending = String::new();
    for (n, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim();
        let at = |e: String| format!("line {}: {e}", n + 1);
        if line.is_empty() {
            continue;
        }
        // A list of strings may continue over several lines.
        if !pending.is_empty() {
            pending.push(' ');
            pending.push_str(line);
            if !line.ends_with(']') {
                continue;
            }
            let (key, value) = pending.split_once('=').ok_or_else(|| at("no `=`".into()))?;
            let value = parse_value(value).map_err(at)?;
            tables
                .last_mut()
                .ok_or_else(|| at("a key before any table".into()))?
                .1
                .insert(key.trim().to_owned(), value);
            pending.clear();
            continue;
        }
        if let Some(name) = line
            .strip_prefix("[[")
            .and_then(|l| l.strip_suffix("]]"))
            .or_else(|| line.strip_prefix('[').and_then(|l| l.strip_suffix(']')))
        {
            tables.push((name.trim().to_owned(), Table::new()));
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| at(format!("{line:?} is no `key = value`")))?;
        if value.trim().starts_with('[') && !value.trim().ends_with(']') {
            pending = line.to_owned();
            continue;
        }
        let value = parse_value(value).map_err(at)?;
        tables
            .last_mut()
            .ok_or_else(|| at("a key before any table".into()))?
            .1
            .insert(key.trim().to_owned(), value);
    }
    if !pending.is_empty() {
        return Err("the file ends inside a list".to_owned());
    }
    Ok(tables)
}

fn text_of(t: &Table, key: &str, what: &str) -> Result<String, String> {
    match t.get(key) {
        Some(Value::Text(s)) => Ok(s.clone()),
        _ => Err(format!("{what}: `{key}` must be a string")),
    }
}

fn number_of(t: &Table, key: &str, what: &str) -> Result<i64, String> {
    match t.get(key) {
        Some(Value::Number(n)) => Ok(*n),
        _ => Err(format!("{what}: `{key}` must be a number")),
    }
}

fn list_of(t: &Table, key: &str) -> Vec<String> {
    match t.get(key) {
        Some(Value::List(l)) => l.clone(),
        Some(Value::Text(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

/// `0x1c` or `+0x1c` as the offset of a block or an instruction from the
/// start of its function.
fn offset_of(t: &Table, what: &str) -> Result<u64, String> {
    let text = text_of(t, "at", what)?;
    // `*`: every loop of the function.
    if text == "*" {
        return Ok(ANY);
    }
    parse_hex(text.trim_start_matches('+'))
        .ok_or_else(|| format!("{what}: `at` {text:?} is no offset"))
}

/// The offset of a loop annotation that names every loop of the function.
const ANY: u64 = u64::MAX;

pub struct LoopBound {
    pub function: String,
    pub at: u64,
    pub bound: u64,
    pub why: String,
}

pub struct Located {
    pub function: String,
    pub at: u64,
}

pub struct Indirect {
    pub function: String,
    pub at: u64,
    pub targets: Vec<String>,
}

/// A system call and the functions that carry it out.
pub struct CallEntry {
    pub name: String,
    pub handlers: Vec<String>,
    /// The call can be a restart of a long call: `go_on` then runs.
    pub long: bool,
    /// The rows (`<what> ticks: <row>`) that measure one portion of the call,
    /// when the longest call of the kernel tests is the sum of its portions.
    pub portions: Vec<String>,
}

/// An entry that is no system call: a path with its own measurement.
pub struct PathEntry {
    pub name: String,
    pub symbol: String,
    /// `<what> ticks: <row>` of the lines a kernel test prints: the longest.
    pub measured: Vec<String>,
    /// More functions the path runs after `symbol`, such as a turn of the
    /// loop of the way out of the kernel (which the analysis prices at
    /// nothing): their bounds add to the path's.
    pub plus: Vec<String>,
    /// `complete = "yes"`: every loop and call on the path has a bound or a
    /// target, and `wcet bound` refuses the kernel when one has not.
    pub complete: bool,
}

#[derive(Default)]
pub struct Annotations {
    /// What the measuring code adds to the interval of a measurement, in
    /// instructions: the counter read that ends it.
    pub calibration: i64,
    /// The function of the system call dispatch and the one it restarts a
    /// long call in.
    pub dispatch: String,
    pub restart: String,
    pub loops: Vec<LoopBound>,
    pub unreachable: Vec<Located>,
    pub indirect: Vec<Indirect>,
    pub noreturn: Vec<Located>,
    pub calls: Vec<CallEntry>,
    pub paths: Vec<PathEntry>,
    /// Name prefixes of functions that cost nothing: code of the test builds
    /// that the kernel which ships does not have.
    pub free: Vec<String>,
    /// The bound of a loop whose body holds an exclusive or acquiring access
    /// of a lock word, or a wait for an event: a retry of a store-exclusive, a
    /// turn of a ticket lock. Another CPU causes each pass past the first.
    pub atomic: Option<(u64, String)>,
    /// Copies and fills of a size that the call site does not set to a constant.
    pub copies: Vec<Copy>,
    /// Functions that begin a stretch of their own: a poll for an interrupt
    /// comes before every call of them. The count of takes of OBJ leaves them
    /// out of their callers (a [[path]] of theirs counts them).
    pub stretches: Vec<String>,
}

pub struct Copy {
    pub function: String,
    pub bytes: u64,
}

impl Annotations {
    pub fn parse(text: &str) -> Result<Annotations, String> {
        let mut a = Annotations::default();
        for (kind, t) in parse_tables(text)? {
            let what = format!("[{kind}]");
            let why = || text_of(&t, "why", &what);
            match kind.as_str() {
                "calibration" => a.calibration = number_of(&t, "counter_read", &what)?,
                "dispatch" => {
                    a.dispatch = text_of(&t, "function", &what)?;
                    a.restart = text_of(&t, "restart", &what)?;
                }
                "loop" => a.loops.push(LoopBound {
                    function: text_of(&t, "function", &what)?,
                    at: offset_of(&t, &what)?,
                    bound: u64::try_from(number_of(&t, "bound", &what)?)
                        .ok()
                        .filter(|&b| b >= 1)
                        .ok_or_else(|| format!("{what}: `bound` must be at least 1"))?,
                    why: why()?,
                }),
                "unreachable" => {
                    why()?;
                    a.unreachable.push(Located {
                        function: text_of(&t, "function", &what)?,
                        at: offset_of(&t, &what)?,
                    });
                }
                "noreturn" => {
                    why()?;
                    a.noreturn.push(Located {
                        function: text_of(&t, "function", &what)?,
                        at: 0,
                    });
                }
                "indirect" => {
                    why()?;
                    a.indirect.push(Indirect {
                        function: text_of(&t, "function", &what)?,
                        at: offset_of(&t, &what)?,
                        targets: list_of(&t, "targets"),
                    });
                }
                "call" => a.calls.push(CallEntry {
                    name: text_of(&t, "name", &what)?,
                    handlers: list_of(&t, "handlers"),
                    long: matches!(t.get("long"), Some(Value::Text(s)) if s == "yes"),
                    portions: list_of(&t, "portions"),
                }),
                "copy" => {
                    why()?;
                    a.copies.push(Copy {
                        function: text_of(&t, "function", &what)?,
                        bytes: u64::try_from(number_of(&t, "bytes", &what)?)
                            .map_err(|_| format!("{what}: `bytes` must not be negative"))?,
                    });
                }
                "atomic" => {
                    a.atomic = Some((
                        u64::try_from(number_of(&t, "bound", &what)?)
                            .ok()
                            .filter(|&b| b >= 1)
                            .ok_or_else(|| format!("{what}: `bound` must be at least 1"))?,
                        why()?,
                    ));
                }
                "free" => {
                    why()?;
                    a.free.push(text_of(&t, "prefix", &what)?);
                }
                "stretch" => {
                    why()?;
                    a.stretches.push(text_of(&t, "function", &what)?);
                }
                "path" => a.paths.push(PathEntry {
                    name: text_of(&t, "name", &what)?,
                    symbol: text_of(&t, "symbol", &what)?,
                    measured: list_of(&t, "measured"),
                    plus: list_of(&t, "plus"),
                    complete: matches!(t.get("complete"), Some(Value::Text(s)) if s == "yes"),
                }),
                other => return Err(format!("unknown table [{other}]")),
            }
        }
        if a.dispatch.is_empty() {
            return Err("no [dispatch] table".to_owned());
        }
        Ok(a)
    }
}

// ---- the control-flow graph of a function ----

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Exit {
    /// `ret`, `eret`.
    Return,
    /// A tail call of function `.0`.
    Tail(usize),
    /// A jump into the middle of another function (a veneer).
    Veneer,
    /// An instruction that stops (`udf`, `brk`).
    Stop,
    /// A jump through a register that is no table of a `match` and no function
    /// whose address was just taken; the address of the instruction.
    Computed(u64),
}

#[derive(Clone, Debug)]
enum CallSite {
    Direct(usize),
    /// A call of memcpy, memmove or memset with the size in bytes when the
    /// call site sets it to a constant.
    Copy(usize, Option<u64>),
    /// A call through a register that the annotations resolve.
    Choice(Vec<usize>),
    /// A call through a register, address of the instruction.
    Indirect(u64),
    /// A call whose target is in no function, address of the instruction.
    Stray(u64),
}

struct Block {
    start: u64,
    /// The index of the first instruction in the function, and how many.
    first: usize,
    len: usize,
    succ: Vec<usize>,
    exits: Vec<Exit>,
    calls: Vec<CallSite>,
}

pub struct Cfg {
    blocks: Vec<Block>,
}

impl Cfg {
    fn build(image: &Image, f: usize, ann: &Annotations) -> Cfg {
        let function = &image.functions[f];
        let jumps = decode_jumps(image, f);
        let mut leaders: BTreeSet<u64> = image.blocks(f).into_iter().collect();
        for j in jumps.values() {
            if let Jump::Table(targets) = j {
                leaders.extend(targets.iter().copied());
            }
        }
        let leaders: Vec<u64> = leaders.into_iter().collect();
        let index: HashMap<u64, usize> = leaders.iter().enumerate().map(|(i, &a)| (a, i)).collect();
        let first_of = |addr: u64| function.insns.partition_point(|i| i.addr < addr);
        let hidden: HashSet<u64> = ann
            .unreachable
            .iter()
            .filter(|u| function.name == u.function)
            .map(|u| function.start + u.at)
            .collect();
        let mut blocks: Vec<Block> = Vec::new();
        for (bi, &start) in leaders.iter().enumerate() {
            let first = first_of(start);
            let end = leaders
                .get(bi + 1)
                .map_or(function.insns.len(), |&a| first_of(a));
            let mut b = Block {
                start,
                first,
                len: end - first,
                succ: Vec::new(),
                exits: Vec::new(),
                calls: Vec::new(),
            };
            let next = (bi + 1 < leaders.len()).then_some(bi + 1);
            for insn in &function.insns[first..end] {
                match insn.flow() {
                    Flow::Call => match insn
                        .target
                        .and_then(|t| image.containing(t).map(|g| (t, g)))
                    {
                        Some((t, g)) if t == image.functions[g].start => {
                            if is_copy(&image.functions[g].name) {
                                let before = &function.insns[first..];
                                let at =
                                    before.iter().position(|i| i.addr == insn.addr).unwrap_or(0);
                                b.calls
                                    .push(CallSite::Copy(g, constant_size(&before[..at])));
                            } else {
                                b.calls.push(CallSite::Direct(g));
                            }
                        }
                        _ => b.calls.push(CallSite::Stray(insn.addr)),
                    },
                    Flow::IndirectCall => {
                        let named = ann.indirect.iter().find(|i| {
                            i.function == function.name && function.start + i.at == insn.addr
                        });
                        match named {
                            Some(i) => {
                                let targets: Vec<usize> =
                                    i.targets.iter().filter_map(|n| image.by_name(n)).collect();
                                b.calls.push(CallSite::Choice(targets));
                            }
                            None => b.calls.push(CallSite::Indirect(insn.addr)),
                        }
                    }
                    _ => {}
                }
            }
            if let Some(last) = function.insns[first..end].last() {
                let inside = |t: u64| index.get(&t).copied();
                match last.flow() {
                    Flow::Plain | Flow::Call | Flow::IndirectCall => {
                        if matches!(last.mnemonic.as_str(), "udf" | "brk" | "hlt") {
                            b.exits.push(Exit::Stop);
                        } else if let Some(n) = next {
                            b.succ.push(n);
                        }
                    }
                    Flow::Branch => {
                        if let Some(n) = next {
                            b.succ.push(n);
                        }
                        branch_edge(image, f, last.target, &inside, &mut b);
                    }
                    Flow::Jump => branch_edge(image, f, last.target, &inside, &mut b),
                    Flow::Return => b.exits.push(Exit::Return),
                    Flow::IndirectJump => match jumps.get(&last.addr) {
                        Some(Jump::Table(targets)) => {
                            for t in targets {
                                if let Some(s) = inside(*t) {
                                    b.succ.push(s);
                                }
                            }
                        }
                        Some(Jump::Function(g)) => b.exits.push(Exit::Tail(*g)),
                        None => b.exits.push(Exit::Computed(last.addr)),
                    },
                }
            }
            blocks.push(b);
        }
        // A block that cannot run takes no edge in.
        for b in &mut blocks {
            b.succ.retain(|&s| !hidden.contains(&leaders[s]));
        }
        Cfg { blocks }
    }
}

/// Whether `name` is one of the functions that copy or fill bytes.
fn is_copy(name: &str) -> bool {
    matches!(
        name,
        "memcpy" | "memset" | "memmove" | "compiler_builtins::mem::memmove"
    )
}

/// The size a call of memcpy gets when the last write of x2 before it
/// is `mov x2, #n`.
fn constant_size(before: &[super::Insn]) -> Option<u64> {
    let last = before
        .iter()
        .rev()
        .find(|i| reg(operand_list(&i.operands)[0]) == Some(2))?;
    if !matches!(last.mnemonic.as_str(), "mov" | "movz") {
        return None;
    }
    super::immediate(operand_list(&last.operands).get(1)?)
}

/// The instructions of a copy or fill of `bytes` bytes by the functions of the
/// kernel's builtins, on the longest of their paths: the head and the tail by
/// bytes (at most 15 each), the middle by words at the most 22 instructions
/// for a word (a source that is not aligned).
fn copy_cost(bytes: u64) -> u64 {
    100 + 22 * (bytes / 8 + 1)
}

/// Where a jump through a register goes.
enum Jump {
    /// The targets of a table of a `match`.
    Table(Vec<u64>),
    /// The function whose address the register holds.
    Function(usize),
}

/// The number of register `r` (`x12`, `w12`), none for `sp` and `xzr`.
fn reg(r: &str) -> Option<u32> {
    let r = r.trim().trim_start_matches('[').trim_end_matches(']');
    r.strip_prefix(['x', 'w'])?.parse().ok()
}

fn operand_list(operands: &str) -> Vec<&str> {
    operands
        .split(',')
        .map(|o| o.trim().trim_start_matches('[').trim_end_matches(']'))
        .collect()
}

/// The shift of an operand list's last element, `lsl #2` or `sxtw #2`.
fn shift_of(list: &[&str]) -> u32 {
    list.iter()
        .rev()
        .find_map(|o| {
            o.split_once('#')
                .filter(|(k, _)| {
                    k.trim().ends_with("sl") || k.trim().ends_with('w') || k.trim().ends_with("sl")
                })
                .and_then(|(_, n)| n.trim().parse().ok())
        })
        .unwrap_or(0)
}

/// What the table of a `match` looks like in code: an `adr` of the base, an
/// `adr` (or `adrp` and `add`) of the table, a load of an entry and an `add`
/// of it to the base before the `br`.
struct TableSpec {
    table: u64,
    base: u64,
    size: usize,
    signed: bool,
    shift: u32,
}

/// The address that register `reg_no` holds before `window[before]`, when an
/// `adr`, or an `adrp` and an `add`, put it there.
fn address_in(window: &[super::Insn], reg_no: u32, before: usize) -> Option<u64> {
    let (i, insn) = window[..before].iter().enumerate().rev().find(|(_, i)| {
        reg(operand_list(&i.operands)[0]) == Some(reg_no)
            && matches!(
                i.mnemonic.as_str(),
                "adr" | "adrp" | "add" | "ldr" | "mov" | "ldrb" | "ldrh" | "ldrsw"
            )
    })?;
    match insn.mnemonic.as_str() {
        "adr" | "adrp" => super::branch_target(&insn.operands),
        "add" => {
            let l = operand_list(&insn.operands);
            let imm = super::immediate(l.get(2)?)?;
            Some(address_in(window, reg_no, i)? + imm)
        }
        _ => None,
    }
}

fn table_spec(insns: &[super::Insn], at: usize) -> Option<TableSpec> {
    let target = reg(insns[at].operands.as_str())?;
    let window = &insns[at.saturating_sub(14)..at];
    let (add_at, add) =
        window.iter().enumerate().rev().find(|(_, i)| {
            i.mnemonic == "add" && reg(operand_list(&i.operands)[0]) == Some(target)
        })?;
    let l = operand_list(&add.operands);
    if reg(l.get(1)?) != Some(target) {
        return None;
    }
    let entry = reg(l.get(2)?)?;
    let shift = shift_of(&l[3..]);
    let base = address_in(window, target, add_at)?;
    let (load_at, load) = window[..add_at].iter().enumerate().rev().find(|(_, i)| {
        i.mnemonic.starts_with("ldr") && reg(operand_list(&i.operands)[0]) == Some(entry)
    })?;
    let (size, signed) = match load.mnemonic.as_str() {
        "ldrb" => (1, false),
        "ldrsb" => (1, true),
        "ldrh" => (2, false),
        "ldrsh" => (2, true),
        "ldrsw" => (4, true),
        "ldr" => (4, false),
        _ => return None,
    };
    let l = operand_list(&load.operands);
    let table_reg = reg(l.get(1)?)?;
    let table = address_in(window, table_reg, load_at)?;
    Some(TableSpec {
        table,
        base,
        size,
        signed,
        shift,
    })
}

/// The jumps through a register of function `f` that go through a table or
/// to a function, by the address of the `br`.
fn decode_jumps(image: &Image, f: usize) -> BTreeMap<u64, Jump> {
    let function = &image.functions[f];
    let mut specs: Vec<(u64, TableSpec)> = Vec::new();
    let mut jumps = BTreeMap::new();
    for (i, insn) in function.insns.iter().enumerate() {
        if insn.flow() != Flow::IndirectJump {
            continue;
        }
        if let Some(spec) = table_spec(&function.insns, i) {
            specs.push((insn.addr, spec));
            continue;
        }
        // `adr x0, function; br x0`
        let r = reg(&insn.operands);
        let named = function.insns[i.saturating_sub(10)..i]
            .iter()
            .rev()
            .find(|p| r.is_some() && reg(operand_list(&p.operands)[0]) == r && p.mnemonic == "adr");
        if let Some(g) = named
            .and_then(|p| super::branch_target(&p.operands))
            .and_then(|t| {
                image
                    .containing(t)
                    .filter(|&g| image.functions[g].start == t)
            })
        {
            jumps.insert(insn.addr, Jump::Function(g));
        }
    }
    // A table of this function ends where the next table of the image
    // begins, a table of another function included: the entries that follow
    // the last one are another table's, which only read as targets of this
    // function by the luck of the layout of the data.
    let starts = image.table_starts.get_or_init(|| {
        let mut starts: Vec<u64> = Vec::new();
        for function in &image.functions {
            for (i, insn) in function.insns.iter().enumerate() {
                if insn.flow() == Flow::IndirectJump
                    && let Some(spec) = table_spec(&function.insns, i)
                {
                    starts.push(spec.table);
                }
            }
        }
        starts.sort_unstable();
        starts.dedup();
        starts
    });
    for (at, spec) in specs {
        let limit = starts
            .iter()
            .copied()
            .find(|&s| s > spec.table)
            .unwrap_or(u64::MAX);
        let mut targets = Vec::new();
        let mut addr = spec.table;
        while addr + spec.size as u64 <= limit {
            let Some(bytes) = image.bytes_at(addr, spec.size) else {
                break;
            };
            let raw = bytes.iter().rev().fold(0u64, |a, &x| a << 8 | u64::from(x));
            let value = if spec.signed {
                let bits = 8 * spec.size as u32;
                (((raw << (64 - bits)) as i64) >> (64 - bits)) << spec.shift
            } else {
                (raw << spec.shift) as i64
            };
            let t = spec.base.wrapping_add(value as u64);
            let valid = image.containing(t) == Some(f)
                && t % 4 == 0
                && function.insns.binary_search_by_key(&t, |i| i.addr).is_ok();
            if !valid {
                break;
            }
            targets.push(t);
            addr += spec.size as u64;
        }
        targets.sort_unstable();
        targets.dedup();
        jumps.insert(at, Jump::Table(targets));
    }
    jumps
}

/// The edge of a jump or a conditional branch of block `b` in function `f`:
/// to a block of `f`, or a tail call of another function.
fn branch_edge(
    image: &Image,
    f: usize,
    target: Option<u64>,
    inside: &dyn Fn(u64) -> Option<usize>,
    b: &mut Block,
) {
    let Some(t) = target else {
        b.exits.push(Exit::Stop);
        return;
    };
    if let Some(s) = inside(t) {
        b.succ.push(s);
        return;
    }
    match image.containing(t) {
        Some(g) if g != f && t == image.functions[g].start => b.exits.push(Exit::Tail(g)),
        Some(_) => b.exits.push(Exit::Veneer),
        None => b.exits.push(Exit::Stop),
    }
}

// ---- loops ----

/// The strongly connected components of the graph of `nodes` under `edges`,
/// a component's blocks in the order of their numbers, the components in an
/// order where each comes before every component it leads to.
fn components(nodes: &BTreeSet<usize>, edges: &dyn Fn(usize) -> Vec<usize>) -> Vec<Vec<usize>> {
    let mut index: HashMap<usize, usize> = HashMap::new();
    let mut low: HashMap<usize, usize> = HashMap::new();
    let mut on_stack: HashSet<usize> = HashSet::new();
    let mut stack: Vec<usize> = Vec::new();
    let mut found: Vec<Vec<usize>> = Vec::new();
    for &root in nodes {
        if index.contains_key(&root) {
            continue;
        }
        // Depth-first search with its own stack: a node, its edges and the next one to take.
        let mut work: Vec<(usize, Vec<usize>, usize)> = Vec::new();
        index.insert(root, index.len());
        low.insert(root, index[&root]);
        stack.push(root);
        on_stack.insert(root);
        work.push((root, edges(root), 0));
        while let Some((v, next, at)) = work.last_mut() {
            let v = *v;
            if let Some(&w) = next.get(*at) {
                *at += 1;
                if !nodes.contains(&w) {
                    continue;
                }
                if !index.contains_key(&w) {
                    index.insert(w, index.len());
                    low.insert(w, index[&w]);
                    stack.push(w);
                    on_stack.insert(w);
                    work.push((w, edges(w), 0));
                } else if on_stack.contains(&w) {
                    let l = low[&v].min(index[&w]);
                    low.insert(v, l);
                }
            } else {
                work.pop();
                if let Some((u, _, _)) = work.last() {
                    let l = low[u].min(low[&v]);
                    low.insert(*u, l);
                }
                if low[&v] == index[&v] {
                    let mut comp = Vec::new();
                    while let Some(w) = stack.pop() {
                        on_stack.remove(&w);
                        comp.push(w);
                        if w == v {
                            break;
                        }
                    }
                    comp.sort_unstable();
                    found.push(comp);
                }
            }
        }
    }
    found.reverse();
    found
}

// ---- the analysis ----

/// The bound of a function: instructions, and whether every loop and call
/// on its paths is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wcet {
    pub insns: u64,
    pub complete: bool,
}

/// What the analysis could not resolve, by function index and address.
#[derive(Default)]
pub struct Issues {
    /// Loops without a bound: (function, header address, blocks in the loop).
    pub loops: BTreeSet<(usize, u64)>,
    pub indirect: BTreeSet<(usize, u64)>,
    pub stray: BTreeSet<(usize, u64)>,
    pub recursion: BTreeSet<(usize, usize)>,
    pub irreducible: BTreeSet<(usize, u64)>,
    pub veneers: BTreeSet<usize>,
    /// Functions with a copy or fill whose size no call site sets to a constant
    /// and no annotation gives: the loops of the copy count at their bounds.
    pub unsized_copies: BTreeSet<usize>,
    pub open_jumps: BTreeSet<(usize, u64)>,
    /// Counting the takes of OBJ: loops with no bound whose blocks take it,
    /// so that the count of a path through them is a lower bound.
    pub take_loops: BTreeSet<(usize, u64)>,
}

struct Window {
    function: usize,
}

pub struct Analyzer<'a> {
    pub image: &'a Image,
    ann: &'a Annotations,
    /// Functions priced at 0, with what they call.
    zero: BTreeSet<usize>,
    window: Option<Window>,
    cfgs: BTreeMap<usize, Cfg>,
    noreturn: BTreeSet<usize>,
    memo: BTreeMap<usize, Wcet>,
    open: Vec<usize>,
    pub issues: Issues,
    /// The loops the annotations bounded and the blocks they matched.
    pub used: BTreeSet<(usize, u64)>,
    /// The blocks of each loop that no annotation bounded, for the report.
    pub bodies: BTreeMap<(usize, u64), BTreeSet<usize>>,
    /// Every loop on the paths analysed: its bound (1 for none), the header of
    /// the loop it is in, and its blocks.
    pub seen: BTreeMap<(usize, u64), Seen>,
    /// The function whose calls the analysis counts in place of instructions
    /// (`Analyzer::counting`): the bound of a function is the most calls of
    /// it on a path.
    takes: Option<usize>,
}

#[derive(Clone)]
pub struct Seen {
    pub bound: u64,
    pub parent: Option<u64>,
    pub blocks: usize,
    pub bounded: bool,
}

impl<'a> Analyzer<'a> {
    pub fn new(image: &'a Image, ann: &'a Annotations) -> Analyzer<'a> {
        let zero = (0..image.functions.len())
            .filter(|&f| {
                ann.free
                    .iter()
                    .any(|p| image.functions[f].name.starts_with(p.as_str()))
            })
            .collect();
        Analyzer {
            image,
            ann,
            zero,
            window: None,
            cfgs: BTreeMap::new(),
            noreturn: BTreeSet::new(),
            memo: BTreeMap::new(),
            open: Vec::new(),
            issues: Issues::default(),
            used: BTreeSet::new(),
            bodies: BTreeMap::new(),
            seen: BTreeMap::new(),
            takes: None,
        }
    }

    /// An analysis that counts the calls of `target` on the longest path in
    /// place of instructions: the takes of OBJ (`kernel::obj::acquire`, which
    /// the kernel keeps out of line for this). A loop costs its bound times
    /// the calls in one pass, as it costs instructions; the copies and fills
    /// of the builtins call it nowhere.
    pub fn counting(image: &'a Image, ann: &'a Annotations, target: usize) -> Analyzer<'a> {
        let mut a = Analyzer::new(image, ann);
        a.takes = Some(target);
        a
    }

    /// Prices the functions in `zero` at nothing and cuts `function` to the
    /// instructions between its first and its last counter read.
    pub fn frame_of(&mut self, function: usize, zero: BTreeSet<usize>) {
        self.zero.extend(zero);
        self.window = Some(Window { function });
    }

    /// Prices more functions at nothing.
    pub fn free_functions(&mut self, zero: impl IntoIterator<Item = usize>) {
        self.zero.extend(zero);
    }

    fn cfg(&mut self, f: usize) -> &Cfg {
        if !self.cfgs.contains_key(&f) {
            let cfg = Cfg::build(self.image, f, self.ann);
            self.cfgs.insert(f, cfg);
        }
        &self.cfgs[&f]
    }

    fn calls_of(&mut self, f: usize, b: usize) -> Vec<CallSite> {
        self.cfg(f).blocks[b].calls.clone()
    }

    /// The functions that return, and so the others: a block whose call never
    /// returns has no successor. `reach` is the functions to look at.
    pub fn find_noreturn(&mut self, reach: &BTreeSet<usize>) {
        self.noreturn = self
            .ann
            .noreturn
            .iter()
            .filter_map(|n| self.image.by_name(&n.function))
            .collect();
        loop {
            let mut added = false;
            for &f in reach {
                if self.noreturn.contains(&f) || self.returns(f) {
                    continue;
                }
                self.noreturn.insert(f);
                added = true;
            }
            if !added {
                break;
            }
        }
    }

    fn calls_noreturn(&self, calls: &[CallSite]) -> bool {
        calls.iter().any(|c| match c {
            CallSite::Direct(g) => self.noreturn.contains(g),
            CallSite::Choice(gs) => !gs.is_empty() && gs.iter().all(|g| self.noreturn.contains(g)),
            _ => false,
        })
    }

    fn returns(&mut self, f: usize) -> bool {
        let cfg = self.cfg(f);
        let mut seen = vec![false; cfg.blocks.len()];
        let mut work = vec![0usize];
        seen[0] = true;
        let blocks: Vec<(Vec<usize>, Vec<Exit>, Vec<CallSite>)> = cfg
            .blocks
            .iter()
            .map(|b| (b.succ.clone(), b.exits.clone(), b.calls.clone()))
            .collect();
        while let Some(b) = work.pop() {
            let (succ, exits, calls) = &blocks[b];
            if self.calls_noreturn(calls) {
                continue;
            }
            for e in exits {
                match e {
                    Exit::Return | Exit::Veneer | Exit::Computed(_) => return true,
                    Exit::Tail(g) if !self.noreturn.contains(g) => return true,
                    _ => {}
                }
            }
            for &s in succ {
                if !seen[s] {
                    seen[s] = true;
                    work.push(s);
                }
            }
        }
        false
    }

    /// The longest path of `f`, in instructions.
    pub fn wcet(&mut self, f: usize) -> Wcet {
        if self.zero.contains(&f) {
            return Wcet {
                insns: 0,
                complete: true,
            };
        }
        if let Some(w) = self.memo.get(&f) {
            return *w;
        }
        if self.open.contains(&f) {
            let caller = self.open.last().copied().unwrap_or(f);
            self.issues.recursion.insert((caller, f));
            return Wcet {
                insns: 0,
                complete: false,
            };
        }
        self.open.push(f);
        let result = self.of_function(f);
        self.open.pop();
        self.memo.insert(f, result);
        result
    }

    fn call_cost(&mut self, f: usize, site: &CallSite, complete: &mut bool) -> u64 {
        if self.takes.is_some() {
            match site {
                CallSite::Copy(..) => return 0,
                CallSite::Direct(g) if Some(*g) == self.takes => return 1,
                _ => {}
            }
        }
        match site {
            CallSite::Copy(g, size) => {
                if let Some(n) = size {
                    return copy_cost(*n);
                }
                let name = &self.image.functions[f].name;
                if let Some(c) = self.ann.copies.iter().find(|c| &c.function == name) {
                    return copy_cost(c.bytes);
                }
                self.issues.unsized_copies.insert(f);
                let w = self.wcet(*g);
                *complete &= w.complete;
                w.insns
            }
            CallSite::Direct(g) if self.noreturn.contains(g) => 0,
            CallSite::Direct(g) => {
                let w = self.wcet(*g);
                *complete &= w.complete;
                w.insns
            }
            CallSite::Choice(gs) => {
                let mut longest = 0;
                let returning: Vec<usize> = gs
                    .iter()
                    .copied()
                    .filter(|g| !self.noreturn.contains(g))
                    .collect();
                for g in returning {
                    let w = self.wcet(g);
                    *complete &= w.complete;
                    longest = longest.max(w.insns);
                }
                longest
            }
            CallSite::Indirect(at) => {
                self.issues.indirect.insert((f, *at));
                *complete = false;
                0
            }
            CallSite::Stray(at) => {
                self.issues.stray.insert((f, *at));
                *complete = false;
                0
            }
        }
    }

    fn of_function(&mut self, f: usize) -> Wcet {
        let image = self.image;
        let function = &image.functions[f];
        let cfg_len = self.cfg(f).blocks.len();
        let mut complete = true;
        // Each block's own cost: its instructions and what it calls.
        let mut cost = vec![0u64; cfg_len];
        let mut dead = vec![false; cfg_len];
        let mut tails = vec![0u64; cfg_len];
        let counting = self.takes.is_some();
        let window = !counting && self.window.as_ref().is_some_and(|w| w.function == f);
        let reads = if window {
            counter_reads(function)
        } else {
            Vec::new()
        };
        let cut = if window {
            self.cut_costs(f, &reads)
        } else {
            None
        };
        for b in 0..cfg_len {
            let calls = self.calls_of(f, b);
            let (len, exits) = {
                let blk = &self.cfg(f).blocks[b];
                (blk.len as u64, blk.exits.clone())
            };
            let mut own = if counting {
                0
            } else {
                cut.as_ref().map_or(len, |c| c[b])
            };
            if cut.as_ref().is_none_or(|c| c[b] > 0 || len == 0) {
                for site in &calls {
                    own += self.call_cost(f, site, &mut complete);
                }
            }
            cost[b] = own;
            dead[b] = self.calls_noreturn(&calls);
            for e in exits {
                match e {
                    Exit::Tail(g) if self.takes == Some(g) => tails[b] = tails[b].max(1),
                    Exit::Tail(g) if !self.noreturn.contains(&g) => {
                        let w = self.wcet(g);
                        complete &= w.complete;
                        tails[b] = tails[b].max(w.insns);
                    }
                    Exit::Veneer => {
                        self.issues.veneers.insert(f);
                    }
                    Exit::Computed(at) => {
                        let offset = at - function.start;
                        let named = self
                            .ann
                            .indirect
                            .iter()
                            .find(|i| i.function == function.name && i.at == offset);
                        match named {
                            Some(i) => {
                                for g in i.targets.iter().filter_map(|n| image.by_name(n)) {
                                    let w = self.wcet(g);
                                    complete &= w.complete;
                                    tails[b] = tails[b].max(w.insns);
                                }
                            }
                            None => {
                                self.issues.indirect.insert((f, at));
                                complete = false;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        let all: BTreeSet<usize> = (0..cfg_len).collect();
        let mut ctx = Solve {
            f,
            cost: &cost,
            dead: &dead,
            tails: &tails,
            complete: &mut complete,
        };
        let region = self.solve(&mut ctx, 0, &all, None);
        let insns = region
            .outs
            .iter()
            .filter(|o| matches!(o.kind, Out::Leave))
            .map(|o| o.cost)
            .max()
            .unwrap_or(0);
        Wcet { insns, complete }
    }

    /// With the window of a measurement: the instructions of each block that
    /// the interval between the first and the last counter read counts.
    fn cut_costs(&mut self, f: usize, reads: &[u64]) -> Option<Vec<u64>> {
        let [first, last] = *reads else { return None };
        let cfg = &self.cfgs[&f];
        let at = |addr: u64| {
            cfg.blocks
                .iter()
                .position(|b| b.start <= addr && addr < b.start + 4 * b.len as u64)
        };
        let (b1, b2) = (at(first)?, at(last)?);
        let n = cfg.blocks.len();
        let reach = |from: usize| {
            let mut seen = vec![false; n];
            let mut work = vec![from];
            while let Some(b) = work.pop() {
                for &s in &cfg.blocks[b].succ {
                    if !seen[s] {
                        seen[s] = true;
                        work.push(s);
                    }
                }
            }
            seen
        };
        let after_first = reach(b1);
        let after_last = reach(b2);
        let index = |blk: &Block, addr: u64| (addr - blk.start) / 4;
        let cost = cfg
            .blocks
            .iter()
            .enumerate()
            .map(|(b, blk)| {
                let len = blk.len as u64;
                match (b == b1, b == b2) {
                    (true, true) => index(blk, last).saturating_sub(index(blk, first)),
                    (true, false) => len - index(blk, first),
                    (false, true) => index(blk, last),
                    _ if after_first[b] && !after_last[b] => len,
                    _ => 0,
                }
            })
            .collect();
        Some(cost)
    }

    /// The longest ways through the blocks of a region: the function, or
    /// the body of the loop that begins at `header`.
    fn solve(
        &mut self,
        ctx: &mut Solve,
        entry: usize,
        members: &BTreeSet<usize>,
        header: Option<usize>,
    ) -> Region {
        let succ: Vec<Vec<usize>> = (0..self.cfg(ctx.f).blocks.len())
            .map(|b| self.cfg(ctx.f).blocks[b].succ.clone())
            .collect();
        // A block that calls a function that never returns has no way on: the
        // blocks the compiler put after the call (the landing pads of a panic
        // that join the code again) make no loop.
        let dead = ctx.dead;
        let inside = |b: usize| -> Vec<usize> {
            if dead[b] {
                return Vec::new();
            }
            succ[b]
                .iter()
                .copied()
                .filter(|t| members.contains(t) && Some(*t) != header)
                .collect()
        };
        let mut arrive: HashMap<usize, u64> = HashMap::from([(entry, 0)]);
        let mut outs: Vec<Out2> = Vec::new();
        let mut latch = 0u64;
        for comp in components(members, &inside) {
            let looped = comp.len() > 1 || inside(comp[0]).contains(&comp[0]);
            if !looped {
                let b = comp[0];
                let Some(&a) = arrive.get(&b) else { continue };
                let d = a + ctx.cost[b];
                if ctx.dead[b] {
                    continue;
                }
                for &t in &succ[b] {
                    self.leave(
                        Out::Edge(t),
                        d,
                        members,
                        header,
                        &mut arrive,
                        &mut outs,
                        &mut latch,
                    );
                }
                self.leave_by_exit(ctx, b, d, &mut outs);
                continue;
            }
            let entries: Vec<usize> = comp
                .iter()
                .copied()
                .filter(|b| arrive.contains_key(b))
                .collect();
            let Some(a) = entries.iter().map(|b| arrive[b]).max() else {
                continue;
            };
            let set: BTreeSet<usize> = comp.iter().copied().collect();
            let key = entries
                .iter()
                .map(|&b| self.cfg(ctx.f).blocks[b].start)
                .min()
                .unwrap_or(0);
            let bound = self.bound_of(ctx, key, &set, entries.len() > 1);
            let parent = header.map(|h| self.cfg(ctx.f).blocks[h].start);
            let bounded = !self.bodies.contains_key(&(ctx.f, key));
            self.seen.insert(
                (ctx.f, key),
                Seen {
                    bound,
                    parent,
                    blocks: set.len(),
                    bounded,
                },
            );
            if let [h] = entries[..] {
                // One way in: the loop of the header `h`; its passes and its exits.
                let inner = self.solve(ctx, h, &set, Some(h));
                for out in &inner.outs {
                    let cost = a + (bound - 1) * inner.latch + out.cost;
                    self.leave(
                        out.kind,
                        cost,
                        members,
                        header,
                        &mut arrive,
                        &mut outs,
                        &mut latch,
                    );
                }
                if inner.outs.is_empty() {
                    outs.push(Out2 {
                        kind: Out::Leave,
                        cost: a + bound * inner.latch,
                    });
                }
                continue;
            }
            // Several ways in: every block of it runs at most `bound` times.
            let total = a + bound * set.iter().map(|&b| ctx.cost[b]).sum::<u64>();
            for &b in &set {
                if ctx.dead[b] {
                    continue;
                }
                for &t in succ[b].iter().filter(|t| !set.contains(t)) {
                    self.leave(
                        Out::Edge(t),
                        total,
                        members,
                        header,
                        &mut arrive,
                        &mut outs,
                        &mut latch,
                    );
                }
                self.leave_by_exit(ctx, b, total, &mut outs);
            }
        }
        Region { outs, latch }
    }

    /// The paths of block `b` that leave the function, at `cost`.
    fn leave_by_exit(&mut self, ctx: &Solve, b: usize, cost: u64, outs: &mut Vec<Out2>) {
        for e in self.cfg(ctx.f).blocks[b].exits.clone() {
            let extra = match e {
                Exit::Return | Exit::Veneer => 0,
                Exit::Tail(_) | Exit::Computed(_) => ctx.tails[b],
                Exit::Stop => continue,
            };
            outs.push(Out2 {
                kind: Out::Leave,
                cost: cost + extra,
            });
        }
    }

    /// The bound of the loop at `key` (the address of its header, of the
    /// first of its ways in when it has several) over the blocks `set`: the
    /// annotation of the loop or of the whole function, or the one that
    /// stands for a lock word's protocol; 1 and a name in the issues when none.
    fn bound_of(&mut self, ctx: &mut Solve, key: u64, set: &BTreeSet<usize>, several: bool) -> u64 {
        let function = &self.image.functions[ctx.f];
        let offset = key - function.start;
        let named = |at: u64| {
            self.ann
                .loops
                .iter()
                .find(|l| l.function == function.name && l.at == at)
                .map(|l| l.bound)
        };
        // The loop's own annotation, then the one for a lock word's protocol,
        // then the one for the whole function.
        let found = named(offset)
            .or_else(|| {
                let (n, _) = self.ann.atomic.as_ref()?;
                self.holds_atomic(ctx.f, set).then_some(*n)
            })
            .or_else(|| named(ANY));
        if found.is_some() {
            self.used.insert((ctx.f, key));
            return found.unwrap_or(1);
        }
        self.issues.loops.insert((ctx.f, key));
        if self.takes.is_some() && set.iter().any(|&b| ctx.cost[b] > 0) {
            self.issues.take_loops.insert((ctx.f, key));
        }
        if several {
            self.issues.irreducible.insert((ctx.f, key));
        }
        self.bodies.insert((ctx.f, key), set.clone());
        *ctx.complete = false;
        1
    }

    /// Whether the blocks are no more than the protocol of a lock word or the
    /// retry of a compare-and-swap: at most six blocks that call nothing, one
    /// of which has a store-exclusive or a wait for an event.
    fn holds_atomic(&mut self, f: usize, blocks: &BTreeSet<usize>) -> bool {
        let function = &self.image.functions[f];
        let cfg = self.cfg(f);
        if blocks.len() > 6 || blocks.iter().any(|&b| !cfg.blocks[b].calls.is_empty()) {
            return false;
        }
        blocks.iter().any(|&b| {
            let blk = &cfg.blocks[b];
            function.insns[blk.first..blk.first + blk.len]
                .iter()
                .any(|i| {
                    let m = i.mnemonic.as_str();
                    m.starts_with("ldx")
                        || m.starts_with("ldax")
                        || m.starts_with("stx")
                        || m.starts_with("stlx")
                        || m == "wfe"
                })
        })
    }

    /// The path reaches block `t` with `cost`, or `Leave`s: inside the region it
    /// arrives, at the header it is a pass of the loop, elsewhere it leaves.
    #[allow(clippy::too_many_arguments)]
    fn leave(
        &self,
        kind: Out,
        cost: u64,
        members: &BTreeSet<usize>,
        header: Option<usize>,
        arrive: &mut HashMap<usize, u64>,
        outs: &mut Vec<Out2>,
        latch: &mut u64,
    ) {
        match kind {
            Out::Edge(t) if Some(t) == header => *latch = (*latch).max(cost),
            Out::Edge(t) if members.contains(&t) => {
                let e = arrive.entry(t).or_insert(0);
                *e = (*e).max(cost);
            }
            kind => outs.push(Out2 { kind, cost }),
        }
    }

    #[cfg(test)]
    pub fn is_noreturn(&self, f: usize) -> bool {
        self.noreturn.contains(&f)
    }

    /// The functions that `f` can run: its callees through the graphs of the
    /// analysis, which leave out the calls that do not return.
    pub fn reach(&mut self, f: usize) -> BTreeSet<usize> {
        let mut seen = BTreeSet::from([f]);
        let mut work = vec![f];
        while let Some(x) = work.pop() {
            if self.zero.contains(&x) && x != f {
                continue;
            }
            let mut next: Vec<usize> = Vec::new();
            for b in &self.cfg(x).blocks {
                for c in &b.calls {
                    match c {
                        CallSite::Direct(g) => next.push(*g),
                        CallSite::Copy(..) => {}
                        CallSite::Choice(gs) => next.extend(gs.iter().copied()),
                        _ => {}
                    }
                }
                for e in &b.exits {
                    if let Exit::Tail(g) = e {
                        next.push(*g);
                    }
                }
            }
            for g in next {
                if !self.noreturn.contains(&g) && seen.insert(g) {
                    work.push(g);
                }
            }
        }
        seen
    }

    /// As `reach`, without the functions priced at nothing (their bodies are
    /// not on the paths of this analysis), `f` itself excepted.
    pub fn reach_counted(&mut self, f: usize) -> BTreeSet<usize> {
        let mut seen = self.reach(f);
        seen.retain(|g| *g == f || !self.zero.contains(g));
        seen
    }

    pub fn analysed(&self) -> BTreeSet<usize> {
        self.memo.keys().copied().collect()
    }
}

#[derive(Clone, Copy, Debug)]
enum Out {
    Edge(usize),
    Leave,
}

struct Out2 {
    kind: Out,
    cost: u64,
}

struct Region {
    outs: Vec<Out2>,
    latch: u64,
}

struct Solve<'a> {
    f: usize,
    cost: &'a [u64],
    dead: &'a [bool],
    tails: &'a [u64],
    complete: &'a mut bool,
}

/// The addresses of the counter reads (`mrs ..., CNTVCT_EL0`) of a function.
fn counter_reads(function: &super::Function) -> Vec<u64> {
    function
        .insns
        .iter()
        .filter(|i| i.mnemonic == "mrs" && i.operands.to_ascii_uppercase().contains("CNTVCT_EL0"))
        .map(|i| i.addr)
        .collect()
}

/// A call number as the name of its `Call` variant.
pub fn call_name(number: u16) -> Option<String> {
    abi::Call::from_number(number).map(|c| format!("{c:?}"))
}

/// `(number, name)` of every system call there is.
pub fn all_calls() -> Vec<(u16, String)> {
    (1..abi::KERNEL_CALL_SLOTS as u16)
        .filter_map(|n| call_name(n).map(|name| (n, name)))
        .collect()
}

// ---- wcet bound ----

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::{PLUGIN, TRACING, Traced, build_plugin, read_traces, short};
use crate::{root, target_dir};

/// The lines the kernel tests print, by the file stem of the kernel image
/// that printed them, while `wcet bound` runs them.
static RECORD: Mutex<Option<Vec<Run>>> = Mutex::new(None);

/// The lines of a run of the kernel tests of one image, by its file stem.
type Run = (String, Vec<String>);

/// A run of the kernel tests of the image `elf` printed `lines`.
pub fn note_run(elf: &Path, lines: &[String]) {
    let stem = elf
        .file_stem()
        .map_or_else(String::new, |s| s.to_string_lossy().into_owned());
    if let Ok(mut record) = RECORD.lock()
        && let Some(runs) = record.as_mut()
    {
        runs.push((stem, lines.to_vec()));
    }
}

/// `call maximum ticks: N=M` of the kernel tests: the longest of each call, in
/// ticks of the counter (instructions under -icount). A call that no test made
/// is not in the map.
fn call_maxima(lines: &[String]) -> BTreeMap<u16, u64> {
    let mut maxima: BTreeMap<u16, u64> = BTreeMap::new();
    for l in lines {
        let Some(l) = l.strip_prefix("call maximum ticks: ") else {
            continue;
        };
        let Some((n, m)) = l.split_once('=') else {
            continue;
        };
        if let (Ok(n), Ok(m)) = (n.trim().parse::<u16>(), m.trim().parse::<u64>()) {
            let e = maxima.entry(n).or_default();
            *e = (*e).max(m);
        }
    }
    maxima
}

/// The row `row` of the line `<what> ticks: row=N ...`.
fn row_ticks(lines: &[String], spec: &str) -> Option<u64> {
    let (what, row) = spec.split_once(" ticks: ")?;
    let prefix = format!("{what} ticks: ");
    let key = format!("{row}=");
    lines
        .iter()
        .filter_map(|l| l.strip_prefix(prefix.as_str()))
        .filter_map(|l| {
            l.split_whitespace()
                .find_map(|f| f.strip_prefix(key.as_str()))
                .and_then(|n| n.parse::<u64>().ok())
        })
        .max()
}

struct Row {
    name: String,
    estimate: Option<Wcet>,
    measured: Option<u64>,
    /// Loops without a bound in the functions the entry can run.
    open: usize,
    /// Those loops: the function and the address of the header.
    open_loops: Vec<(usize, u64)>,
    /// The most takes of OBJ on a path of the entry (k_static): the count of
    /// the calls of `kernel::obj::acquire`, with the loops at their bounds.
    takes: Option<Wcet>,
    /// Loops with no bound that take OBJ on the counted paths of the entry.
    hidden: Vec<(usize, u64)>,
}

impl Row {
    /// k_static for the report: the count, with a plus when a loop or a call
    /// the count could not resolve may hide more.
    fn takes_text(&self) -> String {
        match self.takes {
            Some(k) if k.complete => k.insns.to_string(),
            Some(k) => format!("{}+", k.insns),
            None => "-".to_owned(),
        }
    }
}

impl Row {
    fn status(&self) -> &'static str {
        match (self.estimate, self.measured) {
            (None, _) => "no function",
            (Some(e), _) if !e.complete => "incomplete",
            (Some(e), Some(m)) if e.insns < m => "BELOW THE MEASURE",
            (_, None) => "not measured",
            _ => "ok",
        }
    }
}

struct Report {
    text: String,
    summary: String,
    below: Vec<String>,
    /// The entries whose path takes OBJ more than once, or through a loop with
    /// no bound: the refusals of `wcet bound`.
    refused: Vec<String>,
}

/// The most takes of OBJ on any path of an entry that `wcet bound` accepts:
/// every stretch between two polls for an interrupt takes it once
/// (docs/smp.md).
const TAKES_MAX: u64 = 1;

/// The name of the function the kernel takes OBJ through.
const ACQUIRE: &str = "kernel::obj::acquire";

fn locate(image: &Image, f: usize, addr: u64) -> String {
    format!(
        "{} +{:#x} ({addr:#x})",
        short(&image.functions[f].name),
        addr - image.functions[f].start
    )
}

fn analyse(
    stem: &str,
    image: &Image,
    ann: &Annotations,
    lines: &[String],
    traced: Option<&Traced>,
) -> Result<Report, String> {
    let named = |name: &str| {
        image.by_name(name).ok_or_else(|| {
            format!("{stem}: the annotations name {name:?}, which is in no function")
        })
    };
    let dispatch = named(&ann.dispatch)?;
    let restart = named(&ann.restart)?;
    let mut handlers: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for c in &ann.calls {
        let list = c
            .handlers
            .iter()
            .map(|h| named(h))
            .collect::<Result<Vec<_>, _>>()?;
        handlers.insert(c.name.clone(), list);
    }
    let mut reach = image.reachable(dispatch);
    for p in &ann.paths {
        reach.extend(image.reachable(named(&p.symbol)?));
    }
    // The system calls: the frame of the dispatch between the two counter
    // reads, with the handlers priced at nothing, and the longest handler.
    let zero: BTreeSet<usize> = handlers
        .values()
        .flatten()
        .copied()
        .chain([restart])
        .collect();
    let mut frame = Analyzer::new(image, ann);
    frame.find_noreturn(&reach);
    frame.frame_of(dispatch, zero);
    let frame_cost = frame.wcet(dispatch);
    if std::env::var_os("WCET_DEBUG").is_some() {
        let mut rows: Vec<(u64, String)> = frame
            .analysed()
            .into_iter()
            .map(|f| (frame.wcet(f).insns, image.functions[f].name.clone()))
            .collect();
        rows.sort_by(|a, b| b.cmp(a));
        for (n, name) in rows.iter().take(25) {
            eprintln!("frame callee {n:>8} {name}");
        }
    }

    let mut plain = Analyzer::new(image, ann);
    // A restart of a long call with the number of another call goes through
    // `dispatch` again, which measures that call as an entry of its own.
    plain.free_functions([dispatch]);
    plain.find_noreturn(&reach);
    let restart_cost = plain.wcet(restart);
    // The same paths, counting the takes of OBJ.
    let acquire = named(ACQUIRE)?;
    let stretches: BTreeSet<usize> = ann
        .stretches
        .iter()
        .map(|n| named(n))
        .collect::<Result<_, _>>()?;
    let mut frame_takes = Analyzer::counting(image, ann, acquire);
    frame_takes.free_functions(
        handlers
            .values()
            .flatten()
            .copied()
            .chain([restart])
            .chain(stretches.iter().copied()),
    );
    frame_takes.find_noreturn(&reach);
    let frame_k = frame_takes.wcet(dispatch);
    // The handlers of the calls: a stretch function is left out, a poll
    // comes before each call of it.
    let mut plain_takes = Analyzer::counting(image, ann, acquire);
    plain_takes.free_functions([dispatch].into_iter().chain(stretches.iter().copied()));
    plain_takes.find_noreturn(&reach);
    let restart_k = plain_takes.wcet(restart);
    // The entries that are no call, and the stretch functions themselves.
    let mut path_takes = Analyzer::counting(image, ann, acquire);
    path_takes.free_functions([dispatch]);
    path_takes.find_noreturn(&reach);
    let maxima = call_maxima(lines);
    let mut calls: Vec<Row> = Vec::new();
    let mut reaches: Vec<BTreeSet<usize>> = Vec::new();
    let mut path_reaches: Vec<BTreeSet<usize>> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for (number, name) in all_calls() {
        let Some(list) = handlers.get(&name) else {
            missing.push(name);
            continue;
        };
        let entry = ann.calls.iter().find(|c| c.name == name);
        let mut longest = Wcet {
            insns: 0,
            complete: true,
        };
        let mut costs: Vec<Wcet> = list.iter().map(|&h| plain.wcet(h)).collect();
        let mut takes: Vec<Wcet> = list.iter().map(|&h| plain_takes.wcet(h)).collect();
        if entry.is_some_and(|c| c.long) {
            costs.push(restart_cost);
            takes.push(restart_k);
        }
        // An arm of `dispatch` that takes OBJ hands its section to a handler
        // that takes none, and a handler that takes it itself sits in an arm
        // that does not: the larger of the two is the call's count.
        let k = takes.iter().fold(frame_k, |k, t| Wcet {
            insns: k.insns.max(t.insns),
            complete: k.complete && t.complete,
        });
        let mut hidden: BTreeSet<(usize, u64)> = BTreeSet::new();
        let counted = frame_takes.reach_counted(dispatch);
        hidden.extend(
            frame_takes
                .issues
                .take_loops
                .iter()
                .filter(|(f, _)| counted.contains(f)),
        );
        let mut starts: Vec<usize> = list.clone();
        if entry.is_some_and(|c| c.long) {
            starts.push(restart);
        }
        for h in starts {
            let counted = plain_takes.reach_counted(h);
            hidden.extend(
                plain_takes
                    .issues
                    .take_loops
                    .iter()
                    .filter(|(f, _)| counted.contains(f)),
            );
        }
        for c in costs {
            longest.insns = longest.insns.max(c.insns);
            longest.complete &= c.complete;
        }
        let insns = (frame_cost.insns + longest.insns).saturating_add_signed(ann.calibration);
        calls.push(Row {
            name: format!("{name} ({number})"),
            estimate: Some(Wcet {
                insns,
                complete: longest.complete && frame_cost.complete,
            }),
            measured: {
                let rows = entry
                    .map(|c| c.portions.iter().filter_map(|r| row_ticks(lines, r)).max())
                    .unwrap_or(None);
                if entry.is_some_and(|c| c.long) {
                    rows
                } else {
                    maxima.get(&number).copied().max(rows)
                }
            },
            open: 0,
            open_loops: Vec::new(),
            takes: Some(k),
            hidden: hidden.into_iter().collect(),
        });
        let mut reached = frame.reach(dispatch);
        for &h in list {
            reached.extend(plain.reach(h));
        }
        if entry.is_some_and(|c| c.long) {
            reached.extend(plain.reach(restart));
        }
        reaches.push(reached);
    }
    if !missing.is_empty() {
        return Err(format!(
            "{stem}: the annotations have no [[call]] for {}",
            missing.join(", ")
        ));
    }
    let mut paths: Vec<Row> = Vec::new();
    for p in &ann.paths {
        let mut w = plain.wcet(named(&p.symbol)?);
        for more in &p.plus {
            let m = plain.wcet(named(more)?);
            w.insns += m.insns;
            w.complete &= m.complete;
        }
        paths.push(Row {
            name: p.name.clone(),
            estimate: Some(Wcet {
                insns: w.insns.saturating_add_signed(ann.calibration),
                complete: w.complete,
            }),
            measured: p.measured.iter().filter_map(|r| row_ticks(lines, r)).max(),
            open: 0,
            open_loops: Vec::new(),
            takes: Some(path_takes.wcet(named(&p.symbol)?)),
            hidden: {
                let counted = path_takes.reach_counted(named(&p.symbol)?);
                path_takes
                    .issues
                    .take_loops
                    .iter()
                    .filter(|(f, _)| counted.contains(f))
                    .copied()
                    .collect()
            },
        });
        let mut reached = plain.reach(named(&p.symbol)?);
        for more in &p.plus {
            reached.extend(plain.reach(named(more)?));
        }
        path_reaches.push(reached);
    }
    let mut text = String::new();
    let mut summary = String::new();
    let mut below = Vec::new();
    let mut refused = Vec::new();
    for (row, reached) in calls
        .iter_mut()
        .zip(&reaches)
        .chain(paths.iter_mut().zip(&path_reaches))
    {
        let open: BTreeSet<(usize, u64)> = [&frame.issues, &plain.issues]
            .iter()
            .flat_map(|i| i.loops.iter().copied())
            .filter(|(f, _)| reached.contains(f))
            .collect();
        row.open = open.len();
        row.open_loops = open.into_iter().collect();
        // A loop with no bound that takes OBJ hides more takes than the count
        // shows: it is refused as a take more than once.
        for &(f, at) in &row.hidden {
            let body = [&frame_takes, &plain_takes, &path_takes]
                .iter()
                .find_map(|a| a.bodies.get(&(f, at)));
            refused.push(format!(
                "{stem}: {} runs a loop that takes OBJ and has no bound in tools/wcet/bounds.toml: {}{}",
                row.name,
                locate(image, f, at),
                loop_hint(image, f, body)
            ));
        }
    }
    for (p, row) in ann.paths.iter().zip(&paths) {
        if p.complete && row.estimate.is_some_and(|e| !e.complete) {
            refused.push(format!(
                "{stem}: {} is incomplete: {} loops without a bound or calls through a register nothing resolves lie on the path (tools/wcet/bounds.toml)",
                row.name, row.open
            ));
        }
    }
    let _ = writeln!(text, "kernel {stem}");
    let _ = writeln!(
        text,
        "calibration: {:+} instructions on every estimate; frame of a call (dispatch between its two counter reads): {} instructions{}",
        ann.calibration,
        frame_cost.insns,
        if frame_cost.complete {
            ""
        } else {
            " (incomplete)"
        }
    );
    let _ = writeln!(
        summary,
        "kernel {stem}: calibration {:+}, frame of a call {}",
        ann.calibration, frame_cost.insns
    );
    for (title, rows) in [
        ("system calls", &calls),
        ("interrupt and other paths", &paths),
    ] {
        let _ = writeln!(text, "\n== {title}: estimate and measure, instructions");
        let _ = writeln!(summary, "  {title}: estimate / measure / margin");
        for r in rows {
            let (est, margin) = match (r.estimate, r.measured) {
                (Some(e), Some(m)) => (
                    e.insns.to_string(),
                    format!("{:+}", e.insns as i64 - m as i64),
                ),
                (Some(e), None) => (e.insns.to_string(), "-".to_owned()),
                _ => ("-".to_owned(), "-".to_owned()),
            };
            let meas = r.measured.map_or("-".to_owned(), |m| m.to_string());
            let _ = writeln!(
                text,
                "{:<34} estimate {est:>8}  measure {meas:>8}  margin {margin:>8}  open loops {:>3}  takes {:>3}  {}",
                r.name,
                r.open,
                r.takes_text(),
                r.status()
            );
            if r.takes.is_some_and(|k| k.insns > TAKES_MAX) {
                refused.push(format!(
                    "{stem}: {} takes OBJ {} times on a path, {TAKES_MAX} allowed (k_static)",
                    r.name,
                    r.takes_text()
                ));
            }
            if r.status() == "BELOW THE MEASURE" {
                below.push(format!(
                    "{stem}: {} estimate {est} is below the measure {meas}: the analysis misses a path or the trace is incomplete",
                    r.name
                ));
            }
            if r.measured.is_some() || title != "system calls" {
                let _ = writeln!(
                    summary,
                    "      {:<30} {est:>8} {meas:>8} {margin:>8}  k {:>2}  {}",
                    r.name,
                    r.takes_text(),
                    r.status()
                );
            }
        }
    }
    // The loops that keep an interrupt path or a portion from being complete.
    for r in &paths {
        if r.open_loops.is_empty() {
            continue;
        }
        let _ = writeln!(text, "\nopen loops of {}:", r.name);
        for &(f, at) in &r.open_loops {
            let _ = writeln!(text, "  {}", locate(image, f, at));
        }
    }
    // How far the calibration can move before an estimate is below its measure.
    let slack = calls
        .iter()
        .chain(&paths)
        .filter_map(|r| match (r.estimate, r.measured) {
            (Some(e), Some(m)) if e.complete => Some(e.insns as i64 - m as i64),
            _ => None,
        })
        .min();
    if let Some(slack) = slack {
        let line = format!(
            "calibration margin: the estimate of the tightest entry is {slack:+} instructions from its measure"
        );
        let _ = writeln!(text, "\n{line}");
        let _ = writeln!(summary, "  {line}");
    }
    // What could not be resolved on the analysed paths.
    let issues = [&frame.issues, &plain.issues];
    let bodies: BTreeMap<(usize, u64), BTreeSet<usize>> = frame
        .bodies
        .iter()
        .chain(plain.bodies.iter())
        .map(|(k, v)| (*k, v.clone()))
        .collect();
    let loops: BTreeSet<(usize, u64)> = issues
        .iter()
        .flat_map(|i| i.loops.iter().copied())
        .collect();
    let _ = writeln!(
        text,
        "\n== loops without a bound in tools/wcet/bounds.toml: {}",
        loops.len()
    );
    for &(f, at) in &loops {
        let hint = loop_hint(image, f, bodies.get(&(f, at)));
        let ran = traced
            .and_then(|t| t.blocks.get(&at))
            .map_or(String::new(), |r| {
                format!(", the header ran {} times in the traces", r.count)
            });
        let _ = writeln!(text, "  {}{ran}{hint}", locate(image, f, at));
    }
    let _ = writeln!(summary, "  loops without a bound: {}", loops.len());
    for &(f, at) in &loops {
        let _ = writeln!(summary, "      {}", locate(image, f, at));
    }
    let mut section = |title: &str, items: Vec<String>| {
        let _ = writeln!(text, "\n== {title}: {}", items.len());
        for i in &items {
            let _ = writeln!(text, "  {i}");
        }
        if !items.is_empty() {
            let _ = writeln!(summary, "  {title}: {}", items.len());
        }
    };
    section(
        "calls through a register that nothing resolves",
        issues
            .iter()
            .flat_map(|i| i.indirect.iter())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|&(f, at)| locate(image, f, at))
            .collect(),
    );
    section(
        "calls to no function",
        issues
            .iter()
            .flat_map(|i| i.stray.iter())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|&(f, at)| locate(image, f, at))
            .collect(),
    );
    section(
        "recursion (the cycle's second call counts nothing)",
        issues
            .iter()
            .flat_map(|i| i.recursion.iter())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|&(a, b)| {
                format!(
                    "{} calls {}",
                    short(&image.functions[a].name),
                    short(&image.functions[b].name)
                )
            })
            .collect(),
    );
    section(
        "functions that copy or fill a size no call site sets and no annotation gives",
        issues
            .iter()
            .flat_map(|i| i.unsized_copies.iter())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|&f| short(&image.functions[f].name))
            .collect(),
    );
    section(
        "loops with a second way in",
        issues
            .iter()
            .flat_map(|i| i.irreducible.iter())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|&(f, at)| locate(image, f, at))
            .collect(),
    );
    section(
        "jumps through a register with no target",
        issues
            .iter()
            .flat_map(|i| i.open_jumps.iter())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|&(f, at)| locate(image, f, at))
            .collect(),
    );
    let used: BTreeSet<(usize, u64)> = frame.used.union(&plain.used).copied().collect();
    let unused: Vec<String> = ann
        .loops
        .iter()
        .filter(|l| {
            !used.iter().any(|&(f, at)| {
                image.functions[f].name == l.function
                    && (l.at == ANY || at - image.functions[f].start == l.at)
            })
        })
        .map(|l| format!("loop {} +{:#x}: {}", short(&l.function), l.at, l.why))
        .collect();
    section("bounds that no loop on the analysed paths matched", unused);
    let mut seen: BTreeMap<(usize, u64), Seen> = frame.seen.clone();
    seen.extend(plain.seen.clone());
    let _ = writeln!(
        text,
        "\n== loops on the analysed paths, with their bounds: {}",
        seen.len()
    );
    for (&(f, at), s) in &seen {
        let inside = s.parent.map_or(String::new(), |p| {
            format!(", inside the loop at +{:#x}", p - image.functions[f].start)
        });
        let _ = writeln!(
            text,
            "  {} bound {}{inside}, {} blocks{}",
            locate(image, f, at),
            s.bound,
            s.blocks,
            if s.bounded { "" } else { " (no bound)" }
        );
    }
    if let Some(t) = traced {
        let mut agree = 0usize;
        let mut off_image = 0usize;
        let mut hottest = (0u64, 0u64);
        for (&start, ran) in &t.blocks {
            let Some(f) = image.containing(start) else {
                off_image += 1;
                continue;
            };
            // A translation block ends at a branch: none inside it.
            let function = &image.functions[f];
            let at = function.insns.partition_point(|i| i.addr < start);
            let body = function.insns.get(at..at + ran.insns as usize);
            if body.is_some_and(|b| {
                b.iter()
                    .rev()
                    .skip(1)
                    .all(|i| !i.ends_block() && i.flow() != Flow::Call)
            }) {
                agree += 1;
            }
            if ran.count > hottest.1 {
                hottest = (start, ran.count);
            }
        }
        let line = format!(
            "trace: {} translation blocks, {agree} agree with the disassembly, {off_image} lie in no function; the hottest ran {} times at {:#x}",
            t.blocks.len(),
            hottest.1,
            hottest.0
        );
        let _ = writeln!(text, "\n{line}");
        let _ = writeln!(summary, "  {line}");
    }
    let longest: Vec<(u64, usize)> = {
        let mut all: Vec<(u64, usize)> = plain
            .analysed()
            .into_iter()
            .map(|f| (plain.wcet(f).insns, f))
            .collect();
        all.sort_by_key(|&(n, f)| (std::cmp::Reverse(n), f));
        all.truncate(25);
        all
    };
    let _ = writeln!(text, "\n== the longest functions, with what they call");
    for (n, f) in longest {
        let _ = writeln!(text, "{n:>8}  {}", short(&image.functions[f].name));
    }
    Ok(Report {
        text,
        summary,
        below,
        refused,
    })
}

/// What a loop does, for the line that names it: its size, the constants it
/// compares against and the functions it calls.
fn loop_hint(image: &Image, f: usize, body: Option<&BTreeSet<usize>>) -> String {
    let function = &image.functions[f];
    let cfg = Cfg::build(image, f, &Annotations::default());
    let Some(body) = body else {
        return String::new();
    };
    let mut constants = BTreeSet::new();
    let mut callees = BTreeSet::new();
    let mut insns = 0;
    for &b in body {
        let Some(blk) = cfg.blocks.get(b) else {
            continue;
        };
        insns += blk.len;
        for i in &function.insns[blk.first..blk.first + blk.len] {
            if matches!(i.mnemonic.as_str(), "cmp" | "cmn" | "subs" | "ands" | "tst")
                && let Some(c) = i.operands.split('#').nth(1)
            {
                constants.insert(c.split_whitespace().next().unwrap_or("").to_owned());
            }
        }
        for c in &blk.calls {
            if let CallSite::Direct(g) = c {
                callees.insert(short(&image.functions[*g].name));
            }
        }
    }
    let blocks = if std::env::var_os("WCET_BLOCKS").is_some() {
        let starts: Vec<String> = body
            .iter()
            .filter_map(|&b| cfg.blocks.get(b))
            .map(|blk| {
                let to: Vec<String> = blk
                    .succ
                    .iter()
                    .map(|&t| format!("{:#x}", cfg.blocks[t].start - function.start))
                    .collect();
                format!("+{:#x}->[{}]", blk.start - function.start, to.join(","))
            })
            .collect();
        format!(" blocks {}", starts.join(" "))
    } else {
        String::new()
    };
    format!(
        "  [{} blocks, {insns} insns; compares {:?}; calls {:?}]{blocks}",
        body.len(),
        constants,
        callees
    )
}

struct Options {
    from: Option<PathBuf>,
    out: String,
    annotations: PathBuf,
}

fn parse_options(args: &[String]) -> Result<Options, String> {
    let usage = "usage: cargo xtask wcet bound [--from OUT-DIR] [--out DIR] [--annotations FILE]";
    let mut o = Options {
        from: None,
        out: "wcet".to_owned(),
        annotations: root().join("tools/wcet/bounds.toml"),
    };
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it.next().ok_or(usage)?;
        match flag.as_str() {
            "--from" => o.from = Some(value.into()),
            "--out" => o.out = value.clone(),
            "--annotations" => o.annotations = value.into(),
            _ => return Err(usage.to_owned()),
        }
    }
    Ok(o)
}

/// The images whose kernel tests `wcet bound` reads: the file stems of the two
/// images of the icount build.
const IMAGES: [&str; 2] = ["stafeto-ktest-icount", "stafeto-ktest-icount-el0"];

pub fn run(args: &[String]) -> Result<(), String> {
    let o = parse_options(args)?;
    let ann_text = std::fs::read_to_string(&o.annotations)
        .map_err(|e| format!("{}: {e}", o.annotations.display()))?;
    let ann =
        Annotations::parse(&ann_text).map_err(|e| format!("{}: {e}", o.annotations.display()))?;
    let out = target_dir().join(&o.out);
    let (traces, measured) = match &o.from {
        Some(dir) => (dir.join("bound-traces"), dir.join("measured")),
        None => {
            let traces = out.join("bound-traces");
            let measured = out.join("measured");
            for d in [&traces, &measured] {
                if d.exists() {
                    std::fs::remove_dir_all(d).map_err(|e| e.to_string())?;
                }
                std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
            }
            let so = build_plugin()?;
            let _ = PLUGIN.set(so);
            *RECORD.lock().map_err(|e| e.to_string())? = Some(Vec::new());
            TRACING.with(|t| {
                *t.borrow_mut() = Some((traces.clone(), "kernel tests icount".to_owned()))
            });
            let machine = crate::qemu::machine(Some(&"512M".to_owned()))?;
            let ran = crate::kernel_tests(machine, crate::Variant::TestIcount);
            TRACING.with(|t| *t.borrow_mut() = None);
            let runs = RECORD
                .lock()
                .map_err(|e| e.to_string())?
                .take()
                .unwrap_or_default();
            ran?;
            for (stem, lines) in runs {
                let file = measured.join(format!("{stem}.txt"));
                std::fs::write(&file, lines.join("\n") + "\n")
                    .map_err(|e| format!("{}: {e}", file.display()))?;
            }
            (traces, measured)
        }
    };
    let kernels = read_traces(&traces, &[])?;
    let mut text = String::new();
    let mut summary = String::new();
    let mut below = Vec::new();
    // The kernel of the second image is the same code with other tests: the
    // first image gives the graph, and the measures of both are the longest.
    let mut lines: Vec<String> = Vec::new();
    for stem in IMAGES {
        let file = measured.join(format!("{stem}.txt"));
        lines.extend(
            std::fs::read_to_string(&file)
                .map_err(|e| format!("{}: {e}", file.display()))?
                .lines()
                .map(str::to_owned),
        );
    }
    let stem = IMAGES[0];
    let elf = target_dir().join(format!("{stem}.elf"));
    let image = Image::load(&elf)?;
    let report = analyse(stem, &image, &ann, &lines, kernels.get(stem))?;
    text += &report.text;
    summary += &report.summary;
    below.extend(report.below);
    let refused = report.refused;
    std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let file = out.join("bound.txt");
    std::fs::write(&file, &text).map_err(|e| format!("{}: {e}", file.display()))?;
    print!("{summary}");
    for b in &below {
        println!("WARNING {b}");
    }
    println!("the full report: {}", file.display());
    if refused.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "wcet bound refuses the kernel:\n  {}",
            refused.join("\n  ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LISTING: &str = "\
ffffffffc0000000 <looped>:
ffffffffc0000000:      \tmov\tx0, #0x0
ffffffffc0000004:      \tadd\tx0, x0, #0x1
ffffffffc0000008:      \tcmp\tx0, #0x8
ffffffffc000000c:      \tb.lo\t0xffffffffc0000004 <looped+0x4>
ffffffffc0000010:      \tbl\t0xffffffffc0000030 <leaf>
ffffffffc0000014:      \tcbz\tx1, 0xffffffffc000001c <looped+0x1c>
ffffffffc0000018:      \tnop
ffffffffc000001c:      \tret
ffffffffc0000030 <leaf>:
ffffffffc0000030:      \tmov\tx0, #0x1
ffffffffc0000034:      \tret
ffffffffc0000040 <stops>:
ffffffffc0000040:      \tcbz\tx0, 0xffffffffc000004c <stops+0xc>
ffffffffc0000044:      \tbl\t0xffffffffc0000050 <halt>
ffffffffc0000048:      \tnop
ffffffffc000004c:      \tret
ffffffffc0000050 <halt>:
ffffffffc0000050:      \twfe
ffffffffc0000054:      \tb\t0xffffffffc0000050 <halt>
";

    const BOUNDS: &str = "\
[dispatch]
function = \"looped\"
restart = \"leaf\"

[[loop]]
function = \"looped\"
at = \"+0x4\"
bound = 8
why = \"a test\"
";

    /// Two functions that jump through a table each, the tables one after
    /// the other in the data: the first ends where the second begins. The
    /// entries of the second, read as offsets from the base of the first,
    /// land on instructions of its function as well, so a table that ran on
    /// until an entry did not (the way a table ended before) would take them.
    const TWO_TABLES: &str = "\
ffffffffc0000000 <f>:
ffffffffc0000000:      \tadr\tx9, 0xffffffffc0001000 <tf>
ffffffffc0000004:      \tadr\tx10, 0xffffffffc0000004 <f+0x4>
ffffffffc0000008:      \tldrsw\tx11, [x9, x15, lsl #2]
ffffffffc000000c:      \tadd\tx10, x10, x11
ffffffffc0000010:      \tbr\tx10
ffffffffc0000014:      \tret
ffffffffc0000018:      \tret
ffffffffc000001c:      \tret
ffffffffc0000030 <g>:
ffffffffc0000030:      \tadr\tx9, 0xffffffffc0001008 <tg>
ffffffffc0000034:      \tadr\tx10, 0xffffffffc0000034 <g+0x4>
ffffffffc0000038:      \tldrsw\tx11, [x9, x15, lsl #2]
ffffffffc000003c:      \tadd\tx10, x10, x11
ffffffffc0000040:      \tbr\tx10
ffffffffc0000044:      \tret
ffffffffc0000048:      \tret
ffffffffc000004c:      \tret
";

    #[test]
    fn a_table_ends_where_the_next_table_of_the_image_begins() {
        let mut image = Image::parse(TWO_TABLES).unwrap();
        // The table of f: offsets 0x10 and 0x14 from 0x4, the targets 0x14
        // and 0x18. The table of g follows: offsets 0xc and 0x18 from 0x34,
        // the targets 0x40 and 0x4c of g; read from the base of f they are
        // 0x10 and 0x1c, which are instructions of f.
        let words: [i32; 4] = [0x10, 0x14, 0x0c, 0x18];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        image.sections = vec![(0xffff_ffff_c000_1000, bytes)];
        let f = image.by_name("f").unwrap();
        let jumps = decode_jumps(&image, f);
        let tables: Vec<&Vec<u64>> = jumps
            .values()
            .filter_map(|j| match j {
                Jump::Table(targets) => Some(targets),
                _ => None,
            })
            .collect();
        assert_eq!(
            tables,
            [&vec![0xffff_ffff_c000_0014, 0xffff_ffff_c000_0018]]
        );
        let g = image.by_name("g").unwrap();
        let jumps = decode_jumps(&image, g);
        assert!(jumps.values().any(
            |j| matches!(j, Jump::Table(targets) if *targets == [0xffff_ffff_c000_0040, 0xffff_ffff_c000_004c])
        ));
    }

    #[test]
    fn annotations_parse_the_subset_of_toml() {
        let a = Annotations::parse(BOUNDS).unwrap();
        assert_eq!(a.loops.len(), 1);
        assert_eq!((a.loops[0].at, a.loops[0].bound), (4, 8));
        assert_eq!(a.dispatch, "looped");
        let list = parse_tables("a = [\"x, y\", \"z\"] # c\nb = -3\n[t]\nc = \"q#r\"\n");
        assert!(list.is_err(), "a key before any table");
        let t = parse_tables("[[t]]\nl = [\n \"a\",\n \"b\",\n]\nn = 1_000\ns = \"q#r\" # c\n")
            .unwrap();
        assert_eq!(t[0].1["l"], Value::List(vec!["a".into(), "b".into()]));
        assert_eq!(t[0].1["n"], Value::Number(1000));
        assert_eq!(t[0].1["s"], Value::Text("q#r".into()));
        assert!(Annotations::parse("[[loop]]\nfunction = \"f\"\n").is_err());
    }

    #[test]
    fn a_loop_costs_its_passes_and_a_branch_its_longer_way() {
        let image = Image::parse(LISTING).unwrap();
        let ann = Annotations::parse(BOUNDS).unwrap();
        let mut a = Analyzer::new(&image, &ann);
        let f = image.by_name("looped").unwrap();
        // mov, 7 passes of add, cmp, b.lo and the last of three, bl and cbz
        // with the leaf's two, nop, ret.
        let w = a.wcet(f);
        assert_eq!(
            w,
            Wcet {
                insns: 1 + 7 * 3 + 3 + 2 + 2 + 1 + 1,
                complete: true
            }
        );
        assert!(a.issues.loops.is_empty());
    }

    #[test]
    fn a_loop_without_a_bound_is_named_and_makes_the_bound_incomplete() {
        let image = Image::parse(LISTING).unwrap();
        let ann =
            Annotations::parse("[dispatch]\nfunction = \"looped\"\nrestart = \"leaf\"\n").unwrap();
        let mut a = Analyzer::new(&image, &ann);
        let f = image.by_name("looped").unwrap();
        let w = a.wcet(f);
        assert!(!w.complete);
        assert_eq!(a.issues.loops, BTreeSet::from([(f, 0xffffffffc0000004)]));
    }

    #[test]
    fn a_call_that_never_returns_ends_the_path() {
        let image = Image::parse(LISTING).unwrap();
        let ann = Annotations::parse(BOUNDS).unwrap();
        let mut a = Analyzer::new(&image, &ann);
        let all: BTreeSet<usize> = (0..image.functions.len()).collect();
        a.find_noreturn(&all);
        let (stops, halt) = (
            image.by_name("stops").unwrap(),
            image.by_name("halt").unwrap(),
        );
        assert!(a.is_noreturn(halt));
        assert!(!a.is_noreturn(stops));
        // The call to `halt` ends its path: nothing of `halt` is counted, and
        // its loop is no loop of the analysis. The other way counts.
        assert_eq!(a.wcet(stops).insns, 2);
        assert!(a.issues.loops.is_empty());
    }

    #[test]
    fn the_blocks_after_a_call_that_never_returns_make_no_loop() {
        // A landing pad of a panic that joins the code again: `pad` calls
        // `halt`, and the compiler put a jump back to the top after the call.
        let listing = "\
ffffffffc0000000 <pad>:
ffffffffc0000000:      \tcbz\tx0, 0xffffffffc0000010 <pad+0x10>
ffffffffc0000004:      \tbl\t0xffffffffc0000020 <halt>
ffffffffc0000008:      \tnop
ffffffffc000000c:      \tb\t0xffffffffc0000000 <pad>
ffffffffc0000010:      \tret
ffffffffc0000020 <halt>:
ffffffffc0000020:      \twfe
ffffffffc0000024:      \tb\t0xffffffffc0000020 <halt>
";
        let image = Image::parse(listing).unwrap();
        let ann =
            Annotations::parse("[dispatch]\nfunction = \"pad\"\nrestart = \"pad\"\n").unwrap();
        let mut a = Analyzer::new(&image, &ann);
        let all: BTreeSet<usize> = (0..image.functions.len()).collect();
        a.find_noreturn(&all);
        let pad = image.by_name("pad").unwrap();
        let w = a.wcet(pad);
        assert!(w.complete, "no loop to bound");
        assert!(a.issues.loops.is_empty());
        assert_eq!(w.insns, 2);
    }

    /// A listing of `acquire`, a function that takes it twice in a row, one
    /// that takes it in a loop of eight passes, and one that takes it in a
    /// loop nobody bounded.
    const TAKES: &str = "\
ffffffffc0000000 <acquire>:
ffffffffc0000000:      \tret
ffffffffc0000010 <twice>:
ffffffffc0000010:      \tstp\tx29, x30, [sp, #-16]!
ffffffffc0000014:      \tbl\t0xffffffffc0000000 <acquire>
ffffffffc0000018:      \tbl\t0xffffffffc0000000 <acquire>
ffffffffc000001c:      \tldp\tx29, x30, [sp], #16
ffffffffc0000020:      \tret
ffffffffc0000030 <looped>:
ffffffffc0000030:      \tstp\tx29, x30, [sp, #-16]!
ffffffffc0000034:      \tmov\tx19, #0x0
ffffffffc0000038:      \tbl\t0xffffffffc0000000 <acquire>
ffffffffc000003c:      \tadd\tx19, x19, #0x1
ffffffffc0000040:      \tcmp\tx19, #0x8
ffffffffc0000044:      \tb.lo\t0xffffffffc0000038 <looped+0x8>
ffffffffc0000048:      \tldp\tx29, x30, [sp], #16
ffffffffc000004c:      \tret
ffffffffc0000050 <unbounded>:
ffffffffc0000050:      \tstp\tx29, x30, [sp, #-16]!
ffffffffc0000054:      \tbl\t0xffffffffc0000000 <acquire>
ffffffffc0000058:      \tcbnz\tx0, 0xffffffffc0000054 <unbounded+0x4>
ffffffffc000005c:      \tldp\tx29, x30, [sp], #16
ffffffffc0000060:      \tret
ffffffffc0000070 <once>:
ffffffffc0000070:      \tstp\tx29, x30, [sp, #-16]!
ffffffffc0000074:      \tcbz\tx0, 0xffffffffc0000080 <once+0x10>
ffffffffc0000078:      \tbl\t0xffffffffc0000000 <acquire>
ffffffffc000007c:      \tb\t0xffffffffc0000084 <once+0x14>
ffffffffc0000080:      \tbl\t0xffffffffc0000000 <acquire>
ffffffffc0000084:      \tldp\tx29, x30, [sp], #16
ffffffffc0000088:      \tret
";

    #[test]
    fn the_takes_of_a_path_count_the_calls_of_acquire_with_the_loops_at_their_bounds() {
        let image = Image::parse(TAKES).unwrap();
        let ann = Annotations::parse(
            "[dispatch]\nfunction = \"once\"\nrestart = \"once\"\n\
             [[loop]]\nfunction = \"looped\"\nat = \"+0x8\"\nbound = 8\nwhy = \"a test\"\n",
        )
        .unwrap();
        let acquire = image.by_name("acquire").unwrap();
        let count = |name: &str| {
            let mut a = Analyzer::counting(&image, &ann, acquire);
            let f = image.by_name(name).unwrap();
            (a.wcet(f), a.issues.take_loops.len())
        };
        // Two takes in a row are two; a branch with a take on either side is
        // one; a loop of eight passes that takes once a pass is eight.
        assert_eq!(count("twice").0.insns, 2);
        assert_eq!(count("once").0.insns, 1);
        let (looped, open) = count("looped");
        assert_eq!((looped.insns, looped.complete, open), (8, true, 0));
        // A loop with no bound that takes counts one pass, is named, and
        // makes the count a lower bound.
        let (unbounded, open) = count("unbounded");
        assert_eq!((unbounded.insns, unbounded.complete, open), (1, false, 1));
    }

    #[test]
    fn the_window_of_a_measurement_counts_between_two_counter_reads() {
        let listing = "\
ffffffffc0000000 <timed>:
ffffffffc0000000:      \tnop
ffffffffc0000004:      \tmrs\tx8, CNTVCT_EL0
ffffffffc0000008:      \tnop
ffffffffc000000c:      \tnop
ffffffffc0000010:      \tmrs\tx9, CNTVCT_EL0
ffffffffc0000014:      \tnop
ffffffffc0000018:      \tret
";
        let image = Image::parse(listing).unwrap();
        let ann =
            Annotations::parse("[dispatch]\nfunction = \"timed\"\nrestart = \"timed\"\n").unwrap();
        let mut a = Analyzer::new(&image, &ann);
        a.frame_of(0, BTreeSet::new());
        // From the first read up to, and not with, the second: mrs, nop, nop.
        assert_eq!(a.wcet(0).insns, 3);
    }
}
