# CLOEXEC exec fixture

The `lock-full-exec-cloexec-pid`, `lock-full-exec-cloexec-surviving` and
`lock-full-exec-cloexec-last` features are experimental. Source and shared host
contract checks are available. Guest linkage, actual ELF stack and resource
admission, packed images and native execution remain unverified.

Each case starts with 256 published segments, 128 common slots and eight payers.
The PID case retains T and closes U. The surviving OFD case retains T and closes
U without releasing the OFD group. The last OFD case closes T and U in numeric
order and releases the group on the second close. The state file occupies an
existing prepaid 4096-byte page on a separate inode and stays open across exec.
Its 2816-byte protocol buffer, frozen header and receipt scalars use static BSS.

The old image records each actual full CloseKey and successful event receipt.
A feature-only accepted-receipt hook discards the first real Ok response for each
key. The ordinary Event and Physical observers keep their previous meanings.
The post-public-Ok observer commits a receipt and waits for the stable observer's
exact ACK before the next close, detach, clone or Loader transfer. The final
close waits for Stop and all twenty saved row pages. The old receipts remain
immutable when the fresh image reports its authenticated binding and new local
EntryToken. A final observer ACK follows the real refill and full payer census.

Commands select a profile and case:

```sh
cargo xtask posix-lock-full 4 exec-cloexec-pid
cargo xtask posix-lock-full 4 exec-cloexec-surviving
cargo xtask posix-lock-full 4 exec-cloexec-last
```

Profile 7 has the same selections. Actual-image admission is required before
running either profile. These commands do not imply successful native execution
or completion of failed-exec, CLOFORK or post-waitpid lifetime coverage.

The guest calls the shared decoder in `src/lock_full_cloexec_wire.rs` and the
same decoder is included in xtask host tests. The actual accepted-receipt guard
in `lib/posix-abi/src/exec_receipt_probe.rs` has a host test which verifies that
an error receipt cannot consume the first successful discard. Exact bounded
state I/O uses `lock-full-exec-io.h` and its existing host fault injection test.
