# Shared process credentials for Rust POSIX

## Behavior

The GPL-3.0-or-later C ABI now exports getuid, geteuid, getgid,
getegid, setuid, seteuid, setgid and setegid through unistd.h.
UID/GID are unsigned 32-bit values; UINT32_MAX is reserved.
Getters preserve errno. Successful setters preserve errno; invalid IDs
return EINVAL and permission failures return EPERM without an effect.
Storage exhaustion returns ENOMEM and transport failures return EIO.

A pure GPL Rust model owns the real/effective/saved ID transition rules.
Effective UID zero grants credential-changing privilege. Privileged
setuid/setgid replace the corresponding three IDs; effective-only calls
change just the effective ID. Unprivileged changes require the real or
saved ID. Dropping effective root can be reversed through a saved/real
root ID; a privileged setuid to an ordinary user drops all three IDs.

## Authenticated owner

The GPL posix-process-service stores one record per native PID, shared
by every application thread and connection. Each request obtains its
sender identity from the kernel token. Enroll accepts only the sender's
own live process handle. Initial enrollment assigns root only to direct
init children under the current explicit single-user bootstrap policy.
Repeated enrollment returns the current state and cannot reset rights.

The parent can register a stopped native child before starting its
threads. The child receives a snapshot of all six parent IDs. Native
parent identity is checked before accepting any existing child record;
retrying never replaces the child's snapshot after the parent changes.
The registry has 64 slots and reaps dead processes before new requests.
Session disconnect preserves the credentials of a live process.
Restart is disabled because restoring an empty registry could incorrectly
assign root to a process that had already dropped privileges.

The MIT startup process handle gains DUPLICATE in addition to MANAGE
and TRANSFER. The client sends a TRANSFER-only copy to the owner;
the service receives no process-management authority. MIT protocol/client
packages carry values and handles; credential policy remains GPL.
BusyBox still uses its existing bridge and has no GPLv3 dependency.

## Retained outcomes

Every mutation reserves its result before changing the record. Results
include failures and are keyed by authenticated PID, session label and
nonce. A retry returns the old outcome without repeating an effect.
Changing the body under the same key fails. ACK removes only that key;
an ACK from another session cannot remove it. ACK and replay need no
new allocation. Disconnect frees replies without resetting credentials.

The client retries native Interrupted with the same mutation nonce and
acknowledges the retained result before returning to C. Getter replies
and all process-protocol responses fit in the 64-byte inline IPC area.
The credential test is kept out of line so its temporary registry array
does not remain in the caller's frame during later pthread tests.

## Verification

Five host tests cover permanent/temporary drops, real/saved transitions,
UID-based group privilege and the reserved/largest valid ID boundaries.
The C and standalone probes call all eight functions and check errno,
invalid IDs, privilege restoration and irreversible UID/GID changes.
The pthread probe checks shared state, handler calls, independent peers,
foreign enrollment, child snapshots and 64-record exhaustion/reuse.
It interrupts mutation and ACK after the effect, checks saved success
and failure, mismatched bodies and independent session acknowledgments.
It grows 2000 retained results, fills native handles and rejects a new
reservation; every old replay/ACK succeeds and used storage returns.
Another 100 unacknowledged replies are reclaimed on disconnect.

Ten deliberate mutations were caught: real UID as privilege, lost saved
UID, group mutation changing real GID, accepted reserved ID, re-enrollment
reset, foreign child acceptance, overwritten child snapshot, cross-session
ACK, leaked disconnected replies and accepted changed request body.
Sources were restored before the final checks. Full cargo xtask ci passed
on 686ddda: kcore 402, init 224, kernel 166/177, all POSIX/BusyBox probes,
licenses and shipping hot paths. Separate Apple VZ completed exit 0.
Normal/VZ kernels remain 154708/171076 bytes, below 204800.
Thread/C/standalone images are 716800/573440/589824 bytes.
Normal ticks remain 237/296/361/842/1761; icount IPC remains
245/467/1936/2125/3034/4209. Driver is 673, bind 726/762, ack 205,
portion 247. These kernel timings match #65. Credential service latency
and a new global blocking bound were not measured.

## Remaining work

Supplementary groups, file permission enforcement, set-ID exec,
setreuid/setregid/setresuid/setresgid, orphan adoption and fork/exec remain.
The process registry provides authenticated credentials for subsequent
process-directed signals and sigqueue; those routes and queues still
require implementation. Full mandatory POSIX.1-2024 remains the target.
