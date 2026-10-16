// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The dialogs of GNU bash in the shell image (`/bin/bash`, started from
//! ash): bash's own properties (version, history, completion, interruption,
//! jobs, command substitution, exit status) and the checks of the ash dialog
//! that do not depend on ash (builtins, line editing, the console, external
//! programs, pipelines, the random devices, the utilities).

use super::*;

/// bash's prompt in these dialogs (set by `PS1` for the shell it starts).
const PROMPT: &str = "B# ";
/// What `$BASH_VERSION` of the shell in the image says.
const BASH_VERSION: &str = "5.3.0(1)-release";

/// Types `command`, expects `lines` (as `dialog_command` reads them) and the
/// prompt.
fn say(run: &mut qemu::Run, command: &str, lines: &[&str]) -> Result<(), String> {
    run.send(command)?;
    for expected in lines {
        if let Some(text) = expected.strip_prefix('=') {
            run.expect_line(expected, |line| line.trim() == text, DIALOG_STEP)?;
        } else if let Some(text) = expected.strip_prefix('~') {
            run.expect_line(expected, |line| line.contains(text), DIALOG_STEP)?;
        } else {
            run.expect_line(expected, |line| line == *expected, DIALOG_STEP)?;
        }
    }
    run.expect(PROMPT, DIALOG_STEP)
}

/// Keys sent as a terminal sends them; the line the shell ran ends the probe.
fn keys(run: &mut qemu::Run, bytes: &[u8], line: &str) -> Result<(), String> {
    run.type_raw(bytes)?;
    run.expect_line(line, |l| l == line, DIALOG_STEP)?;
    run.expect(PROMPT, DIALOG_STEP)
}

/// bash's properties.
fn properties(run: &mut qemu::Run) -> Result<(), String> {
    // History: Up brings the last command back.
    say(run, "echo history-one", &["history-one"])?;
    keys(run, b"\x1b[A\r", "history-one")?;
    // Completion of a name with Tab.
    keys(run, b"ls -1 /bin/mkt\t\r", "/bin/mktemp")?;
    // Command substitution and a pipeline.
    say(run, "echo $(echo sub) | cat", &["sub"])?;
    say(run, "echo [$(echo a b c | wc -w)]", &["[3]"])?;
    // INTR reaches the foreground job and not the shell.
    run.send("echo sleeping; sleep 100")?;
    run.expect_line("sleeping", |l| l == "sleeping", DIALOG_STEP)?;
    std::thread::sleep(Duration::from_secs(2));
    run.type_raw(b"\x03")?;
    run.expect("^C", DIALOG_STEP)?;
    run.expect(PROMPT, DIALOG_STEP)?;
    say(run, "echo rc=$?", &["rc=130"])?;
    // Jobs: a background job, `jobs`, `fg`, INTR.
    run.send("sleep 100 &")?;
    run.expect(PROMPT, DIALOG_STEP)?;
    run.send("jobs")?;
    run.expect_line(
        "the job",
        |l| l.starts_with("[1]+") && l.contains("Running"),
        DIALOG_STEP,
    )?;
    run.expect(PROMPT, DIALOG_STEP)?;
    run.send("fg")?;
    run.expect("sleep 100", DIALOG_STEP)?;
    std::thread::sleep(Duration::from_millis(500));
    run.type_raw(b"\x03")?;
    run.expect(PROMPT, DIALOG_STEP)?;
    say(run, "echo fg=$?", &["fg=130"])?;
    // Stop with Ctrl-Z, `jobs`, `bg`, `fg`, INTR.
    run.send("sleep 100")?;
    std::thread::sleep(Duration::from_secs(1));
    run.type_raw(b"\x1a")?;
    run.expect("Stopped", DIALOG_STEP)?;
    run.expect(PROMPT, DIALOG_STEP)?;
    run.send("jobs")?;
    run.expect_line(
        "stopped job",
        |l| l.starts_with("[1]+") && l.contains("Stopped"),
        DIALOG_STEP,
    )?;
    run.expect(PROMPT, DIALOG_STEP)?;
    run.send("bg")?;
    run.expect("sleep 100 &", DIALOG_STEP)?;
    run.expect(PROMPT, DIALOG_STEP)?;
    run.send("fg")?;
    run.expect("sleep 100", DIALOG_STEP)?;
    std::thread::sleep(Duration::from_millis(500));
    run.type_raw(b"\x03")?;
    run.expect(PROMPT, DIALOG_STEP)?;
    say(run, "echo stopped-job=$?", &["stopped-job=130"])?;
    // `wait` gives the status of a background job.
    say(run, "(exit 5) & wait $!; echo waited=$?", &["waited=5"])?;
    Ok(())
}

/// The checks of the ash dialog that do not depend on ash.
fn shared(run: &mut qemu::Run, bin_count: &str) -> Result<(), String> {
    // Ctrl-C at the prompt drops the line and gives a fresh prompt: the
    // text typed with it never runs (the check of the whole output below).
    std::thread::sleep(Duration::from_secs(1));
    run.type_raw(b"echo dropped\x03")?;
    run.expect("^C", DIALOG_STEP)?;
    std::thread::sleep(Duration::from_secs(1));
    say(run, "echo fresh", &["fresh"])?;
    let builtins: &[(&str, &[&str])] = &[
        ("echo arithmetic:$((6 * 7))", &["arithmetic:42"]),
        (
            "test 7 -eq 7; echo test-true:$?; test 7 -eq 8; echo test-false:$?",
            &["test-true:0", "test-false:1"],
        ),
        (
            "[ word = word ]; echo bracket-true:$?; [ word = other ]; echo bracket-false:$?",
            &["bracket-true:0", "bracket-false:1"],
        ),
        (
            "printf 'formatted:%04d:%s\\n' 7 word",
            &["formatted:0007:word"],
        ),
        (
            "set -- -a -b value; while getopts 'ab:' opt; do echo option:$opt:$OPTARG; done; echo option-index:$OPTIND",
            &["option:a:", "option:b:value", "option-index:4"],
        ),
        ("alias hello='echo alias-ready'", &[]),
        ("hello", &["alias-ready"]),
        (
            "unalias hello; command -v hello >/dev/null; echo unalias:$?",
            &["unalias:1"],
        ),
        (
            "echo() { printf 'function:%s\\n' \"$1\"; }; echo called; command echo bypassed; unset -f echo",
            &["function:called", "bypassed"],
        ),
        ("type -t printf", &["builtin"]),
        (
            "[[ abc == a* ]] && echo pattern; a=(x y z); echo ${#a[@]}:${a[1]}",
            &["pattern", "3:y"],
        ),
        (
            "declare -A m; m[k]=v; echo ${m[k]}; echo ${BASH_VERSINFO[0]}",
            &["v", "5"],
        ),
    ];
    for (command, lines) in builtins {
        say(run, command, lines)?;
    }
    // The keys of the line editor.
    keys(run, b"echo ac\x1b[Db\r", "abc")?;
    keys(
        run,
        b"echo xy\x1b[H\x1b[C\x1b[C\x1b[C\x1b[C\x1b[CZ\x1b[F\x1b[D\x1b[3~\r",
        "Zx",
    )?;
    keys(run, b"two\x01echo \x05 words\r", "two words")?;
    keys(
        run,
        b"echo drop one\x15echo kept\x01\x0b\x15echo edited\r",
        "edited",
    )?;
    keys(run, b"echo keep drop\x17\r", "keep")?;
    keys(run, b"echo /et\t\x7f\x7f\r", "/et")?;
    // The name of the terminal is the layer's to resolve.
    say(run, "echo console >/dev/console", &["console"])?;
    say(run, "/bin/ls -1 /etc >/dev/console", &["motd"])?;
    say(run, "ls -1 /etc", &["motd"])?;
    say(run, "ls -la", &["~dr-xr-xr-x"])?;
    say(run, "le /?; echo $?", &["~le: command not found", "127"])?;
    say(
        run,
        "/bin/x; echo $?",
        &["~/bin/x: No such file or directory", "127"],
    )?;
    say(run, "/bin/ls -la", &["~dr-xr-xr-x"])?;
    say(run, "echo hi && ls -1 /etc", &["hi", "motd"])?;
    say(run, "/bin/ash -c 'exit 3'; echo $?", &["3"])?;
    say(
        run,
        "/bin/bash -c '/bin/bash -c \"exit 4\"; echo inner $?'",
        &["inner 4"],
    )?;
    say(
        run,
        "ls /missing; echo $?",
        &["~No such file or directory", "1"],
    )?;
    say(run, "cd etc; pwd", &["/etc"])?;
    say(run, "cd ..; ls tmp", &["probe"])?;
    say(
        run,
        "cd /missing; echo after-cd-error",
        &["~No such file or directory", "after-cd-error"],
    )?;
    // Pipelines and the shell of `system`, `popen`.
    say(run, "ls /etc | cat", &["motd"])?;
    say(run, "echo hello | cat | cat", &["hello"])?;
    say(
        run,
        "/bin/sh -c 'echo shell-ran $0 $((6*7))'",
        &["shell-ran ash 42"],
    )?;
    say(run, "echo 'echo piped-sh' | /bin/sh", &["piped-sh"])?;
    say(run, "ls /bin | wc -l", &[&format!("={bin_count}")])?;
    // The 112 utilities of XCU answer `command -v`, 28 names a line.
    for names in XCU_UTILITIES.chunks(28) {
        let command = format!(
            "n=0; for u in {}; do command -v $u >/dev/null && n=$((n+1)); done; echo found:$n",
            names.join(" ")
        );
        let missing = names.iter().filter(|n| XCU_MISSING.contains(n)).count();
        let expected = format!("found:{}", names.len() - missing);
        say(run, &command, &[&expected])?;
    }
    for (command, lines) in UTILITY_DIALOG {
        // `time` is a keyword of bash, which reports on the shell's own
        // standard error and not through the pipe the line gives it.
        if command.contains("time true") {
            continue;
        }
        say(run, command, lines)?;
    }
    // Background jobs, `wait`, the null device, the random devices.
    say(
        run,
        "echo job-ended & wait; echo wait $?",
        &["job-ended", "wait 0"],
    )?;
    say(
        run,
        "echo lost > /dev/null && echo gone; cat < /dev/null; echo null $?",
        &["gone", "null 0"],
    )?;
    say(run, "head -c 4096 /dev/urandom | wc -c", &["=4096"])?;
    say(run, "cat /dev/urandom | head -c 100 | wc -c", &["=100"])?;
    say(
        run,
        "a=$RANDOM; b=$RANDOM; case $a in $b) echo same-random;; *) echo differ-random;; esac",
        &["differ-random"],
    )?;
    say(
        run,
        "RANDOM=7; a=$RANDOM; RANDOM=7; b=$RANDOM; case $a in $b) echo repeats;; *) echo no-repeat;; esac",
        &["repeats"],
    )?;
    // Forty searches through PATH with three misses each.
    say(
        run,
        "saved=$PATH; PATH=/miss1:/miss2:/miss3:$saved; i=0; while [ $i -lt 40 ]; do uname > /dev/null || break; i=$((i+1)); done; PATH=$saved; echo path-misses $i",
        &["path-misses 40"],
    )?;
    Ok(())
}

pub fn bash_dialog() -> Result<(), String> {
    relibc()?;
    busybox_build()?;
    bash_build()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(
        "boot-ash-dialog.img",
        &ASH_INTERACTIVE_PROGRAMS,
        BOOT_PROFILE,
    )?;
    image_has_bash_terms(&image)?;
    // The entries of /bin: the table of the image lists them (rootfs.rs).
    let bin_count = (rootfs::UTILITIES.len() + 5).to_string();
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let talked = (|| {
        run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
        run.expect("# ", DIALOG_STEP)?;
        // The version, and the status of a shell that ends with `exit 3`,
        // both from ash.
        run.send("bash -c 'echo $BASH_VERSION'")?;
        run.expect_line("the version", |l| l == BASH_VERSION, DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("bash -c 'exit 3'; echo status:$?")?;
        run.expect_line("the status", |l| l == "status:3", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        // The interactive shell, with a prompt of its own.
        run.send("PS1='B# ' bash")?;
        run.expect(PROMPT, DIALOG_STEP)?;
        properties(&mut run)?;
        shared(&mut run, &bin_count)?;
        // `exit 3` hands ash the status.
        run.send("exit 3")?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("echo ash-got:$?")?;
        run.expect_line("ash got the status", |l| l == "ash-got:3", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        // Ctrl-D on an empty line ends ash.
        run.type_raw(b"\x04")?;
        run.expect(
            "init: busybox-probe ended: exit code 0, not restarted",
            DIALOG_STEP,
        )
    })();
    let output = run.stop();
    symbolize::backtrace(&output.lines, &kernel.elf);
    talked?;
    if output.lines.iter().any(|line| {
        line.contains("process fault:")
            || line.contains("KERNEL PANIC")
            || line.contains("out of memory")
            || line.contains("I/O error")
            || line.contains("xmalloc")
    }) {
        return Err("bash dialog faulted".into());
    }
    if output.lines.iter().any(|line| line == "dropped") {
        return Err("bash ran the line that Ctrl-C dropped".into());
    }
    let elf = image_elf(&target_dir(), "boot-ash-dialog.img", "bash");
    let size = std::fs::metadata(&elf)
        .map_err(|e| format!("{}: {e}", elf.display()))?
        .len();
    println!("GNU bash {BASH_VERSION} interactive guest dialog passed; ELF {size} bytes");
    Ok(())
}

/// `exit 3` typed at the prompt of bash, which replaced ash (`exec bash`),
/// ends the machine and the run gives 3.
pub fn bash_shell_exit() -> Result<(), String> {
    relibc()?;
    busybox_build()?;
    bash_build()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(
        "boot-ash-dialog.img",
        &ASH_INTERACTIVE_PROGRAMS,
        BOOT_PROFILE,
    )?;
    let cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    let feed = Box::new(
        |mut pipe: std::process::ChildStdin, prompt: &std::sync::atomic::AtomicBool| {
            use std::io::Write;
            let began = std::time::Instant::now();
            while !prompt.load(std::sync::atomic::Ordering::SeqCst) {
                if began.elapsed() > BOOT_TIMEOUT {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = pipe.write_all(b"exec bash\r").and_then(|()| pipe.flush());
            std::thread::sleep(Duration::from_secs(5));
            let _ = pipe.write_all(b"exit 3\r").and_then(|()| pipe.flush());
            // Keep the pipe open: the machine ends by the shell's end.
            std::thread::sleep(Duration::from_secs(600));
        },
    );
    let limit = Some(BOOT_TIMEOUT + DIALOG_STEP * 4);
    match interactive_qemu(cmd, &kernel.elf, Stdio::piped(), Some(feed), true, limit)? {
        Some(3) => {
            println!("GNU bash shell end probe passed: exit 3 ended the machine");
            Ok(())
        }
        other => Err(format!(
            "the shell's status was {other:?}, expected Some(3)"
        )),
    }
}
