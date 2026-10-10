# Byte ranges and owners of file locks

The first lock stage adds the service's internal range algebra. Public fcntl
commands keep their previous behavior while the paid table, descriptor
lifecycle and request driver are built in the following stages.

Ranges contain their first and last byte in the signed 64-bit offset domain.
Normalization captures the chosen seek origin before any wait and computes
with i128. Positive and negative lengths include exactly the requested bytes;
zero length reaches the greatest representable offset. A byte before zero is
Invalid, and a byte beyond the offset domain is Overflow. A negative length
can describe valid bytes even when its intermediate anchor exceeds off_t.
Canonical output uses SEEK_SET and zero length for the final offset.

Process owners carry the full PID, including its process record generation.
OFD owners carry the slot and exact shared-description generation. Different
owner kinds remain independent, and overlapping regions conflict when at least
one lock is exclusive. Regions of the same exact owner are replaced. Shared
regions of different owners coexist.

Subtracting a region returns at most two retained edges. The old owner and lock
type survive on both edges; other owners keep their complete region. Joining
regions requires adjacent or overlapping bytes, identical owners and identical
types. These operations use fixed arrays and constant work with no allocation.
The paid table must reserve the output before publishing a new region list.

Nine host tests cover offset boundaries, negative lengths, distinct owners,
inclusive overlap, both retained edges and canonical coalescing. An independent
16-byte bitmap checks 18,496 pairs of regions. Deliberate changes to negative
length direction, the last byte, OFD generation, owner kind, the right edge,
gaps and lock type each fail a focused test. The full RAM suite grows from 289
to 298 tests. No kernel or protocol change belongs to this stage.
