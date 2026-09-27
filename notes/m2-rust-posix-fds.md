# Rust POSIX descriptor ownership

The GPL-3.0-or-later `posix-fd` crate provides a bounded, host-testable
process descriptor table. `posix-fs` owns a table of 32 entries, including
standard streams. A descriptor contains a backend open-description key
and separate close-on-exec and close-on-fork flags. Multiple descriptors
can share one RAM service key, hence their offset and access mode.
Independent opens still have independent offsets.

The API provides `dup`, minimum-based `dup_from`, `dup2`, `dup3`, descriptor
flags, and closing. Allocation chooses the lowest available number. `dup2`
validates the source first; releasing the last reference to the previous
target happens before installing the new one. A failed release preserves
the target. Same-descriptor `dup2` preserves flags; other duplications
clear flags unless explicitly supplied. Same-descriptor `dup3` fails.
These rules follow
[POSIX.1-2024 dup](https://pubs.opengroup.org/onlinepubs/9799919799/functions/dup.html).

Closing a duplicate releases the service description only after the last
local reference. Dropping `PosixFs` ends the session and releases all RAM
opens. Console descriptors use the same local table and can be replaced
with files; closing or replacing one console entry retains the process's
console transport for remaining streams. A file allocated at descriptor
zero routes to RAM instead of accidentally invoking console input.
Console metadata reports a character device; seeking returns `NotSeekable`.

RAM sessions now permit 32 open descriptions so all 32 local slots can be
reached with distinct opens. Exhaustion has a separate `TooManyOpenFiles`
status, translated to EMFILE by the existing MIT C bridge. The C probe
exhausts all 32 descriptions, checks EMFILE, closes them, and reopens a file. File capacity
errors remain `NoSpace`. BusyBox does not link the new GPL crate.

Four host descriptor tests cover allocation/reuse, shared ownership,
failed target release, invalid sources, same-descriptor cases, and flags.
A fifth RAM regression verifies description exhaustion and recovery.
The guest probe additionally verifies shared and independent offsets,
read-only access after duplication, repeated replacement without leaking
service slots (64 replacements), stdout redirection and restoration,
file descriptor zero, and limits reached by both copies and distinct opens.
A mutation that released a shared backend on the first close deliberately
failed the ownership test; restoring the last-reference check passed.

The table has one mutable owner and cannot be cloned. Multi-process
inheritance requires service-level sharing of open descriptions; thread
synchronization, actual exec/fork flag handling, pipes, directory
descriptors, a C ABI, and the remaining POSIX families are still required.
The Rust guest exercises redirection independently of BusyBox.
