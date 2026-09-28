# Authenticated IPC sender identity for Rust POSIX

## Behavior

RequestIdentity (35) reads the native sender's PID and parent PID from
an accepted reply token. The receiving process can inspect that identity
through any of its threads. User-supplied message fields and channel
labels do not determine the returned identity.

The MIT native rt interface exposes Token::sender_identity(&self).
It borrows the token, so repeated reads leave the reply right available.
The kernel remains GPL-3.0-or-later; Rust POSIX keeps that same license.
The shared MIT ABI carries native identity without defining Unix policy.

## Authority and lifetime

The kernel checks the token generation and the sender's current Reply
wait under the existing scheduler lock. That wait must name the caller's
process. Another process cannot inspect a live request accepted elsewhere,
even if it knows the raw token. No process handle has to travel with a
message, and the service does not trust a client-supplied PID.

Zero, invalid, stale, consumed and foreign live tokens return BAD_STATE.
The last abandoned request returns PEER_CLOSED, following the existing
token-table contract, until generation change or number reuse invalidates
it. An error changes only x0; success writes x0, x1 and x2.

An accepted request remains inspectable after its channel closes.
Reading does not dequeue the client, consume its token, allocate memory,
wait, or end the service's priority boost. Lookup and checks take O(1).
No UID, permission decision or POSIX process registry is fabricated.

## Verification

The existing ABI tests now cover dense call numbers through 35, the new
fixed number and rejection of the next number. Unknown-call EL0 tests
advance to 36. Kernel statistics size follows Call::ALL automatically.

Two new init tests inspect real accepted requests: invalid tokens and
register preservation; repeated reads; another service thread; channel
closure; a consumed token; interruption; repeated abandoned-token reads;
a new accepted generation; and the stale previous generation.

Existing cross-process init tests now compare against a real child's
native PID/PPID, ask another child to inspect the service's token, and
confirm that rejection preserves the original request and reply. The
dead-client test also verifies PEER_CLOSED and unchanged error registers.

The pthread probe compares a live native request against Rust getpid and
the process's native PID/PPID. Repeated reads must leave the empty reply
and pthread_join result intact on QEMU and Apple Virtualization.framework.

Targeted ABI tests, all 224 init tests and the Apple VZ pthread probe pass.
Six mutations are caught: missing ownership check, receiver-as-sender,
lost parent, boost removal, x3 clobber and acceptance of a stale generation.
Sources were restored after each run. Complete CI follows the code commit.

## Cost and compatibility

Call numbers 1..34 and receive/reply register layouts remain unchanged.
The stats maximum array gains one slot through its shared declaration.
The read uses the existing token table and immutable process identity;
it adds no sender credential storage or global process search.
See docs/non-preemptible-paths.md for its bounded kernel work.
Final image sizes and existing path measurements follow the complete CI.
No new request latency or global non-preemptible bound is claimed.

## Remaining POSIX work

POSIX.1-2024 requires the actual sender PID and real UID for SI_QUEUE:
https://pubs.opengroup.org/onlinepubs/9799919799/functions/V2_chap02.html
This native primitive supplies authenticated PID for a future shared
GPL Rust POSIX service. That service must own credentials, registration,
target routing and source/value queues before sigqueue can be exported.
Real-time FIFO signals, process delivery, credentials, orphan lifecycle,
and the remaining mandatory POSIX interfaces remain active work.
