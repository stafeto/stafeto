// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Two genuine initial roots use loaded factories and ordinary fork actors.
use posix_abi::{
    capacity_probe as paid,
    capacity_snapshot::{self as meter, Snapshot},
    constants::*,
};
use posix_fs::{Target, Transport};
use rt::sys;
unsafe extern "C" {
    fn capacity_spawn_factory(role: i32, command: i32, response: i32, a: i32, b: i32) -> i32;
    fn capacity_wait_child(pid: i32, killed: i32) -> i32;
    fn capacity_stat(fd: i32, out: *mut u64) -> i32;
}
fn require(ok: bool) -> Result<(), i32> {
    if ok { Ok(()) } else { Err(EIO) }
}
#[derive(Clone, Copy)]
struct Pipe {
    end: u32,
    transport: Transport,
}
impl Pipe {
    fn capture(fd: i32) -> Result<Self, i32> {
        posix_abi::shared::with_files(|f| match f.target(fd as u32).map_err(posix_abi::error)? {
            Target::Pipe(end) => Ok(Self {
                end,
                transport: f.transport(),
            }),
            _ => Err(EIO),
        })
    }
    fn read_exact(self, out: &mut [u8]) -> Result<(), i32> {
        let mut at = 0;
        while at != out.len() {
            let n = posix_abi::pipes::read(self.transport, self.end, &mut out[at..])?;
            require(n != 0 && n <= out.len() - at)?;
            at += n;
        }
        Ok(())
    }
    fn write(self, bytes: &[u8]) -> Result<(), i32> {
        require(bytes.len() <= proto_pipe::ATOMIC)?;
        require(posix_abi::pipes::write(self.transport, self.end, bytes)? == bytes.len())
    }
}
fn command(pipe: Pipe, seq: u32, action: u32) -> Result<(), i32> {
    let mut b = [0; 8];
    b[..4].copy_from_slice(&seq.to_le_bytes());
    b[4..].copy_from_slice(&action.to_le_bytes());
    pipe.write(&b)
}
fn receive_command(pipe: Pipe) -> Result<(u32, u32), i32> {
    let mut b = [0; 8];
    pipe.read_exact(&mut b)?;
    Ok((
        u32::from_le_bytes(b[..4].try_into().unwrap()),
        u32::from_le_bytes(b[4..].try_into().unwrap()),
    ))
}
fn response(pipe: Pipe, actor: u32, seq: u32, value: u32) -> Result<(), i32> {
    let mut b = [0; 16];
    for (chunk, v) in b
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip([actor, seq, 16, value])
    {
        chunk.copy_from_slice(&v.to_le_bytes());
    }
    pipe.write(&b)
}
fn receive_response(pipe: Pipe, seq: u32) -> Result<(u32, u32), i32> {
    let mut b = [0; 16];
    pipe.read_exact(&mut b)?;
    let mut v = [0; 4];
    for (out, chunk) in v.iter_mut().zip(b.as_chunks::<4>().0.iter()) {
        *out = u32::from_le_bytes(*chunk);
    }
    require(v[1] == seq && v[2] == 16)?;
    Ok((v[0], v[3]))
}
fn resident_fds() -> Result<usize, i32> {
    posix_abi::shared::with_files(|f| Ok((0..32).filter(|fd| f.target(*fd).is_ok()).count()))
}
fn exact_target(fd: i32) -> Result<Target, i32> {
    posix_abi::shared::with_files(|f| f.target(fd as u32).map_err(posix_abi::error))
}
fn attributes(fd: i32) -> Result<[u64; 13], i32> {
    let mut fields = [0; 13];
    // SAFETY: the C bridge writes exactly thirteen scalar fields from actual fstat.
    let error = unsafe { capacity_stat(fd, fields.as_mut_ptr()) };
    if error == 0 { Ok(fields) } else { Err(error) }
}
fn duplicate(input: Pipe, output: Pipe, seq: u32, count: u32) -> Result<(), i32> {
    let before = meter::snapshot()?;
    ask(input, output, seq, 2, count)?;
    let after = meter::snapshot()?;
    require(
        before.jobs == after.jobs
            && before.preparations == after.preparations
            && before.root_preparations == after.root_preparations
            && before.usage == after.usage
            && before.available == after.available,
    )
}
fn wait_child(pid: i32, killed: bool) -> Result<(), i32> {
    // SAFETY: the C bridge observes the actual child status through ordinary waitpid.
    let e = unsafe { capacity_wait_child(pid, i32::from(killed)) };
    if e == 0 { Ok(()) } else { Err(e) }
}
fn close_except(keep: &[i32]) -> Result<(), i32> {
    for fd in 3..32 {
        if !keep.contains(&fd)
            && posix_abi::shared::with_files(|f| Ok(f.target(fd as u32).is_ok()))?
        {
            posix_abi::close(fd)?;
        }
    }
    Ok(())
}
fn actor(
    id: usize,
    command_fd: i32,
    response_fd: i32,
    fd: i32,
    expected: u8,
    root: [u64; 2],
) -> Result<(), i32> {
    // Every close and native fork precedes the first retained result.
    close_except(&[command_fd, response_fd, fd])?;
    let input = Pipe::capture(command_fd)?;
    let output = Pipe::capture(response_fd)?;
    require(meter::snapshot()?.root == root && resident_fds()? == 6)?;
    let mut sequence = 0;
    loop {
        let (seq, action) = receive_command(input)?;
        require(seq == sequence + 1)?;
        sequence = seq;
        let count = match action {
            1 => {
                for n in 0..16 {
                    let result = paid::retain_read(fd as u32, ((id * 16 + n) * 4096) as u64);
                    if let Err(error) = result {
                        rt::println!(
                            "capacity-diag: actor={} seq={} n={} retain_errno={}",
                            id,
                            seq,
                            n,
                            error
                        );
                    }
                    result?;
                }
                let count = paid::retained_count(expected);
                rt::println!(
                    "capacity-diag: actor={} seq={} retained={} errno={}",
                    id,
                    seq,
                    count.unwrap_or(0),
                    count.err().unwrap_or(0)
                );
                require(count? == 16)?;
                16
            }
            2 => {
                require(paid::repeat_first()? && paid::retained_count(expected)? == 16)?;
                16
            }
            3 => {
                for _ in 0..16 {
                    require(paid::release_first(expected)?)?;
                }
                require(!paid::release_first(expected)? && paid::retained_count(expected)? == 0)?;
                0
            }
            _ => return Err(EINVAL),
        };
        response(output, id as u32, seq, count)?;
        if action == 3 {
            return Ok(());
        }
    }
}
struct Children {
    pids: [i32; 6],
}
impl Drop for Children {
    fn drop(&mut self) {
        for pid in self.pids.iter().copied().filter(|pid| *pid > 0) {
            let _ = posix_abi::process::kill(pid, SIGKILL);
            let _ = wait_child(pid, true);
        }
    }
}
fn factory(role: i32, command_fd: i32, response_fd: i32, data: i32, data1: i32) -> Result<(), i32> {
    close_except(&[command_fd, response_fd, data, data1])?;
    let root = meter::snapshot()?.root;
    require(root[0] != posix_abi::process::getpid() as u64)?;
    let n = if role == 3 { 6 } else { 2 };
    let expected = if role == 3 { b'A' } else { b'B' };
    let mut channels = [[-1; 2]; 6];
    for pair in channels.iter_mut().take(n) {
        *pair = posix_abi::pipe2(0)?;
    }
    let replies = posix_abi::pipe2(0)?;
    require(resident_fds()? == if role == 3 { 21 } else { 12 })?;
    let mut children = Children { pids: [0; 6] };
    for (id, pair) in channels.iter().enumerate().take(n) {
        let pid = posix_abi::fork::fork(None)?;
        if pid == 0 {
            let result = actor(
                id,
                pair[0],
                replies[1],
                if role == 3 && id % 2 != 0 {
                    data1
                } else {
                    data
                },
                expected,
                root,
            );
            sys::process_exit(if result.is_ok() { 0 } else { 32 });
        }
        children.pids[id] = pid;
    }
    for pair in channels.iter().take(n) {
        posix_abi::close(pair[0])?;
    }
    posix_abi::close(replies[1])?;
    let root_commands = Pipe::capture(command_fd)?;
    let root_responses = Pipe::capture(response_fd)?;
    let responses = Pipe::capture(replies[0])?;
    let mut sequence = 0;
    let mut actor_sequence = [0u32; 6];
    loop {
        let (seq, action) = receive_command(root_commands)?;
        require(seq == sequence + 1)?;
        sequence = seq;
        if action == 4 {
            require(role == 3 && children.pids[0] > 0)?;
            posix_abi::process::kill(children.pids[0], SIGKILL)?;
            wait_child(children.pids[0], true)?;
            children.pids[0] = 0;
            response(root_responses, 0, seq, 5)?;
            continue;
        }
        require((1..=3).contains(&action))?;
        let mut mask = 0u32;
        let mut live = 0;
        for id in 0..n {
            if children.pids[id] != 0 {
                actor_sequence[id] += 1;
                command(Pipe::capture(channels[id][1])?, actor_sequence[id], action)?;
                live += 1;
            }
        }
        for _ in 0..live {
            let mut b = [0; 16];
            responses.read_exact(&mut b)?;
            let id = u32::from_le_bytes(b[..4].try_into().unwrap()) as usize;
            rt::println!("capacity-diag: factory={} mask={} id={}", role, mask, id);
            require(id < n && children.pids[id] != 0 && mask & (1 << id) == 0)?;
            let seq = u32::from_le_bytes(b[4..8].try_into().unwrap());
            let len = u32::from_le_bytes(b[8..12].try_into().unwrap());
            let count = u32::from_le_bytes(b[12..].try_into().unwrap());
            rt::println!(
                "capacity-diag: factory={} seq={} len={} count={}",
                role,
                seq,
                len,
                count
            );
            require(
                seq == actor_sequence[id] && len == 16 && count == if action == 3 { 0 } else { 16 },
            )?;
            mask |= 1 << id;
        }
        if action == 3 {
            for id in 0..n {
                if children.pids[id] != 0 {
                    wait_child(children.pids[id], false)?;
                    children.pids[id] = 0;
                }
            }
        }
        response(
            root_responses,
            0,
            sequence,
            if action == 3 { 0 } else { live as u32 * 16 },
        )?;
        if action == 3 {
            return Ok(());
        }
    }
}
fn await_snapshot(predicate: impl Fn(&Snapshot) -> bool) -> Result<Snapshot, i32> {
    for _ in 0..200_000 {
        let s = meter::snapshot()?;
        if predicate(&s) {
            return Ok(s);
        }
        sys::yield_now().map_err(|_| EIO)?;
    }
    Err(EIO)
}
fn empty_file(path: &[u8]) -> Result<i32, i32> {
    let fd = posix_abi::open_policy(path, O_RDWR | O_CREAT | O_EXCL, 0o600, 0)?;
    let result = posix_abi::ftruncate(fd, 0);
    rt::println!(
        "capacity-diag: empty pid={} fd={} truncate_errno={}",
        posix_abi::process::getpid(),
        fd,
        result.err().unwrap_or(0)
    );
    result?;
    Ok(fd)
}
struct GateEvent(core::cell::UnsafeCell<Option<posix_abi::data_probe::Event>>);
// SAFETY: one original leader's main thread registers and invokes the callback;
// disable completes before it reads or clears the saved value.
unsafe impl Sync for GateEvent {}
static GATE_EVENT: GateEvent = GateEvent(core::cell::UnsafeCell::new(None));
fn arm_retired(event: posix_abi::data_probe::Event) -> Result<(), i32> {
    meter::retired_arm(event)?;
    meter::retired_arm(event)?;
    // SAFETY: only the registered main-thread owner enters this callback once.
    unsafe {
        *GATE_EVENT.0.get() = Some(event);
    }
    Ok(())
}
fn observe_truncate(fd: i32, size: i64, pages: u32) -> Result<Snapshot, i32> {
    let owner = posix_abi::relibc::open_owner()?;
    // SAFETY: previous disable/snapshot completed on the same main thread.
    unsafe {
        *GATE_EVENT.0.get() = None;
    }
    posix_abi::data_probe::register(
        owner,
        posix_abi::data_probe::Stage::ReadyBeforeCommit,
        arm_retired,
    )?;
    let result = posix_abi::ftruncate(fd, size);
    posix_abi::data_probe::disable(owner)?;
    // SAFETY: the synchronous callback completed and registration is disabled.
    let event = unsafe { (*GATE_EVENT.0.get()).take() };
    if let Err(error) = result {
        if let Some(event) = event {
            let _ = meter::retired_disarm(event);
        }
        return Err(error);
    }
    require(event.is_some())?;
    let snapshot = meter::snapshot()?;
    require(
        snapshot.available[2] == 0
            && snapshot.usage[2] == pages
            && snapshot.jobs == 0
            && snapshot.root_preparations == 0,
    )?;
    require(attributes(fd)?[0] == size as u64)?;
    rt::println!(
        "capacity: retired root={}:{} size={} paid_pages={} free={}",
        snapshot.root[0],
        snapshot.root[1],
        size,
        snapshot.usage[2],
        snapshot.available[2]
    );
    Ok(snapshot)
}
fn fill(fd: i32, pages: usize, byte: u8) -> Result<(), i32> {
    posix_abi::ftruncate(fd, (pages * 4096) as i64)?;
    for page in 0..pages {
        let at = (page * 4096) as i64;
        require(posix_abi::pwrite(fd, &[byte], at)? == 1)?;
        let mut seen = [0];
        require(posix_abi::pread(fd, &mut seen, at)? == 1 && seen == [byte])?;
    }
    Ok(())
}
fn collect_failed() {
    for _ in 0..32 {
        posix_abi::shared::help_open_recovery();
    }
}
#[inline(never)]
fn refusal_snapshot(stage: u32, snapshot: &Snapshot) {
    rt::println!(
        "capacity-diag: refusal stage={} jobs={} preparations={} root_preparations={}",
        stage,
        snapshot.jobs,
        snapshot.preparations,
        snapshot.root_preparations
    );
    for (index, value) in snapshot.usage.iter().enumerate() {
        rt::println!(
            "capacity-diag: refusal stage={} usage_index={} value={}",
            stage,
            index,
            value
        );
    }
    for (index, value) in snapshot.available.iter().enumerate() {
        rt::println!(
            "capacity-diag: refusal stage={} available_index={} value={}",
            stage,
            index,
            value
        );
    }
}
fn refusing(fd: i32, expected: i32) -> Result<(), i32> {
    let before = meter::snapshot()?;
    refusal_snapshot(0, &before);
    let result = paid::retain_read(fd as u32, 0);
    rt::println!(
        "capacity-diag: refusal expected={} actual_errno={} retained={}",
        expected,
        result.err().unwrap_or(0),
        u32::from(result.is_ok())
    );
    require(result == Err(expected))?;
    collect_failed();
    let after = meter::snapshot()?;
    refusal_snapshot(1, &after);
    require(
        after.jobs == before.jobs
            && after.preparations == before.preparations
            && after.root_preparations == before.root_preparations
            && after.usage == before.usage
            && after.available == before.available,
    )
}
fn ask(input: Pipe, output: Pipe, seq: u32, action: u32, expected: u32) -> Result<(), i32> {
    command(output, seq, action)?;
    let (id, count) = receive_response(input, seq)?;
    require(id == 0 && count == expected)
}
fn leader(role: i32) -> Result<(), i32> {
    let a = role == 1;
    let cold = meter::snapshot()?;
    rt::println!(
        "capacity-diag: role={} uid={} euid={} pid={} coldroot={}:{}",
        role,
        posix_abi::process::getuid(),
        posix_abi::process::geteuid(),
        posix_abi::process::getpid(),
        cold.root[0],
        cold.root[1]
    );
    require(
        posix_abi::process::getuid() == if a { 0 } else { 65534 }
            && posix_abi::process::geteuid() == if a { 0 } else { 65534 },
    )?;
    let expected = if a { b'A' } else { b'B' };
    let f0 = empty_file(if a {
        b"/tmp/capacity-a0"
    } else {
        b"/tmp/capacity-b0"
    })?;
    let f1 = if a {
        empty_file(b"/tmp/capacity-a1")?
    } else {
        -1
    };
    meter::control(0, 1)?;
    if a {
        loop {
            match meter::control(1, 0) {
                Ok(()) => break,
                Err(EINVAL) => sys::yield_now().map_err(|_| EIO)?,
                Err(e) => return Err(e),
            }
        }
    }
    let warm = await_snapshot(|s| s.meter[1] != 0)?;
    rt::println!(
        "capacity-diag: role={} pid={} root={}:{} jobs={} free={} used={} quota={} phase={} registered={}/{}",
        role,
        posix_abi::process::getpid(),
        warm.root[0],
        warm.root[1],
        warm.jobs,
        warm.available[2],
        warm.memory.used,
        warm.memory.quota,
        warm.phases.own,
        warm.phases.registered[0],
        warm.phases.registered[1]
    );
    require(
        warm.root[0] == posix_abi::process::getpid() as u64
            && warm.jobs == 0
            && warm.available[2] == 4096
            && warm.memory.used <= warm.memory.quota,
    )?;
    rt::println!(
        "capacity: cold root={}:{} used={} pages={} nodes={} descriptions={} live={} warm_used={} warm_nodes={} warm_descriptions={}",
        cold.root[0],
        cold.root[1],
        cold.memory.used,
        cold.available[2],
        cold.usage[0],
        cold.usage[3],
        cold.handles.live,
        warm.memory.used,
        warm.usage[0],
        warm.usage[3]
    );
    fill(f0, if a { 2048 } else { 1024 }, expected)?;
    if a {
        fill(f1, 1024, expected)?;
    }
    meter::control(0, 2)?;
    await_snapshot(|s| s.available[2] == 0 && s.phases.other_at_least(2))?;
    let full = meter::snapshot()?;
    require(full.usage[2] == if a { 3072 } else { 1024 })?;
    // A non-aligned shrink needs a private tail page while the physical pool is full.
    let before = meter::snapshot()?;
    let target = exact_target(f0)?;
    let attrs = attributes(f0)?;
    let offset = posix_abi::lseek(f0, 0, SEEK_CUR)?;
    require(posix_abi::ftruncate(f0, 4096 * 512 + 1) == Err(ENOSPC))?;
    require(
        attributes(f0)? == attrs
            && exact_target(f0)? == target
            && posix_abi::lseek(f0, 0, SEEK_CUR)? == offset,
    )?;
    let after = meter::snapshot()?;
    require(after.usage == before.usage && after.available == before.available)?;
    let mut marker = [0];
    require(posix_abi::pread(f0, &mut marker, 512 * 4096)? == 1 && marker == [expected])?;
    let commands = posix_abi::pipe2(0)?;
    let replies = posix_abi::pipe2(0)?;
    // SAFETY: ordinary posix_spawn inherits the actual descriptors without file actions.
    let pid = unsafe { capacity_spawn_factory(role, commands[0], replies[1], f0, f1) };
    require(pid > 0)?;
    posix_abi::close(commands[0])?;
    posix_abi::close(replies[1])?;
    let input = Pipe::capture(replies[0])?;
    let output = Pipe::capture(commands[1])?;
    if !a {
        await_snapshot(|s| s.phases.other_at_least(3) && s.jobs == 96)?;
    }
    rt::println!("capacity-diag: leader={} stage=1", role);
    let result = ask(input, output, 1, 1, if a { 96 } else { 32 });
    rt::println!(
        "capacity-diag: leader={} stage=2 errno={}",
        role,
        result.err().unwrap_or(0)
    );
    result?;
    let result = await_snapshot(|s| s.jobs == if a { 96 } else { 128 });
    rt::println!(
        "capacity-diag: leader={} stage=3 errno={}",
        role,
        result.err().unwrap_or(0)
    );
    result?;
    let refusal = meter::snapshot()?;
    require(
        refusal.jobs == if a { 96 } else { 128 }
            && refusal.root_preparations == if a { 96 } else { 32 },
    )?;
    rt::println!(
        "capacity-diag: leader={} stage=4 jobs={} root_preparations={}",
        role,
        refusal.jobs,
        refusal.root_preparations
    );
    let result = refusing(f0, if a { ENOSPC } else { EMFILE });
    rt::println!(
        "capacity-diag: leader={} stage=5 errno={}",
        role,
        result.err().unwrap_or(0)
    );
    result?;
    meter::control(0, 3)?;
    if a {
        let result = await_snapshot(|s| s.phases.other_at_least(3) && s.jobs == 128);
        rt::println!(
            "capacity-diag: leader={} stage=6 errno={}",
            role,
            result.err().unwrap_or(0)
        );
        result?;
        duplicate(input, output, 2, 96)?;
        ask(input, output, 3, 4, 5)?;
        let gone = await_snapshot(|s| s.jobs == 112 && s.root_preparations == 80)?;
        require(gone.usage[2] == 3072)?;
        require(exact_target(f0)? == target)?;
        let mut marker = [0];
        require(posix_abi::pread(f0, &mut marker, 0)? == 1 && marker == [expected])?;
        duplicate(input, output, 4, 80)?;
        meter::control(0, 4)?;
        await_snapshot(|s| s.phases.other_at_least(4))?;
        ask(input, output, 5, 3, 0)?;
    } else {
        await_snapshot(|s| s.phases.other_at_least(4) && s.jobs == 112)?;
        for _ in 0..16 {
            paid::retain_read(f0 as u32, 0)?;
        }
        require(paid::retained_count(expected)? == 16)?;
        let reused = meter::snapshot()?;
        require(reused.jobs == 128 && reused.root_preparations == 48)?;
        for _ in 0..16 {
            require(paid::release_first(expected)?)?;
        }
        require(paid::retained_count(expected)? == 0)?;
        duplicate(input, output, 2, 32)?;
        await_snapshot(|s| s.jobs == 112)?;
        meter::control(0, 4)?;
        // RootA has observed the reuse barrier before releasing its surviving 80.
        await_snapshot(|s| s.jobs == 32 && s.root_preparations == 32)?;
        ask(input, output, 3, 3, 0)?;
    }
    wait_child(pid, false)?;
    posix_abi::close(replies[0])?;
    posix_abi::close(commands[1])?;
    await_snapshot(|s| s.jobs == 0 && s.preparations == 0)?;
    if a {
        // The first shrink commits at physical free0; retired pages stay paid until GC.
        observe_truncate(f0, 512 * 4096, 3072)?;
        await_snapshot(|s| s.available[2] == 1536 && s.usage[2] == 1536)?;
        posix_abi::ftruncate(f0, 2048 * 4096)?;
        for page in 512..2048 {
            let offset = page * 4096;
            require(posix_abi::pwrite(f0, &[expected], offset)? == 1)?;
            let mut byte = [0];
            require(posix_abi::pread(f0, &mut byte, offset)? == 1 && byte == [expected])?;
        }
        let refilled = meter::snapshot()?;
        require(refilled.available[2] == 0 && refilled.usage[2] == 3072)?;
        rt::println!("capacity: actual refill1536 returned physical free0");
        observe_truncate(f1, 0, 3072)?;
        await_snapshot(|s| s.available[2] == 1024 && s.usage[2] == 2048)?;
        posix_abi::ftruncate(f0, 0)?;
    } else {
        // Both full-pool cases belong to A; B keeps its 1024 actual pages until A's GC.
        await_snapshot(|s| s.available[2] == 3072 && s.usage[2] == 1024)?;
        posix_abi::ftruncate(f0, 0)?;
    }
    let final_state = await_snapshot(|s| {
        s.available[2] == 4096 && s.usage == warm.usage && s.jobs == 0 && s.preparations == 0
    })?;
    require(
        final_state.memory.used == warm.memory.used
            && final_state.handles.live == warm.handles.live
            && final_state.backing == warm.backing
            && final_state.meter[1] == warm.meter[1],
    )?;
    meter::control(0, 5)?;
    await_snapshot(|s| s.phases.other_at_least(5))?;
    posix_abi::close(f0)?;
    if a {
        posix_abi::close(f1)?;
    }
    let closed = await_snapshot(|s| s.usage[3] == cold.usage[3] && s.root_preparations == 0)?;
    require(closed.usage[0] == warm.usage[0] && closed.usage[1] == warm.usage[1])?;
    rt::println!(
        "capacity: root={}:{} pid={} pages={} jobs={} warm={} peak={} live={} limit={}",
        final_state.root[0],
        final_state.root[1],
        final_state.pid,
        final_state.available[2],
        final_state.jobs,
        final_state.meter[1],
        final_state.meter[2],
        final_state.handles.live,
        final_state.handles.limit
    );
    Ok(())
}
#[unsafe(no_mangle)]
extern "C" fn files_capacity_run(
    role: i32,
    command: i32,
    response: i32,
    data0: i32,
    data1: i32,
) -> i32 {
    let result = match role {
        1 | 2 => leader(role),
        3 | 4 => factory(role, command, response, data0, data1),
        _ => Err(EINVAL),
    };
    result.err().unwrap_or(0)
}
