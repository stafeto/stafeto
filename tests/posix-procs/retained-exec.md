# Retained exec fixture

The `lock-full-exec-pid` and `lock-full-exec-ofd` features are experimental.
Their source and host contract checks are available. Guest linkage, actual ELF
stack and resource admission, and native execution remain unverified.

Each mode retains one descriptor across `execve` and the ordinary C runtime.
The resident RAM service exports its authenticated Active binding and the
current credentials generation. A stable observer keeps the original capture;
the new image must reject access to that capture, preserve the description,
PID, Root, descriptor number and flags, and report a new image number.

The state file is initialized to 4096 bytes before capture begins. Its 2816-byte
protocol uses a static buffer and separate receipt and observer-control regions.
The new image cannot close or unlock its retained descriptor before the
observer stops the original capture and commits an exact acknowledgement.
The second receipt slot is reserved and must remain zero in these modes.

The command selections are `cargo xtask posix-lock-full 4|7 exec-pid|exec-ofd`.
They require the same dedicated-image prerequisites and actual-image checks
as the other full-table fixtures. These selections do not imply successful
native execution or coverage of CLOEXEC aliases and failed exec.

The host oracle tests live in `src/lock_full_exec_wire.rs` and are also included
by xtask. A standalone host check can run without a guest build:

```sh
rustc --edition=2024 --test tests/posix-procs/src/lock_full_exec_wire.rs -o /tmp/retained-exec-tests
/tmp/retained-exec-tests
clang -Wall -Wextra -Werror tests/posix-procs/lock-full-exec-io-test.c -o /tmp/retained-exec-io-tests
/tmp/retained-exec-io-tests
```
