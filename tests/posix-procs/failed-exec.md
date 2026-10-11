# Experimental failed-exec fixture

This source checkpoint extends the full-table fixture with `exec-failed-pid`
and `exec-failed-ofd` for profiles 4 and 7. A direct `execve("/bin/script", ...)`
returns ENOEXEC before file transfer. The fixture captures the old descriptors,
flags, offsets, signal mask and an authenticated refreshed Active binding,
then permits one genuine successful exec with an acknowledged CLOEXEC replay.

The wire layout is version 3, 352 words in the existing static 4096-byte state
page. Immutable failed-attempt evidence remains separate from the refreshed
binding used by the next exec. The observer owns the capture and its final
Stop. The fixture checks its full 256/common128/eight-payer baseline.

This is an unfinished source and host checkpoint. Guest linkage, callback type
checking, native build, actual stack and resource admission, packed images,
positive guests and production mutations have not been run. Shared decoder
checks and host C syntax checks do not establish those properties. Resume with
an independent source review and the remaining host oracle removal tests before
requesting a fresh native build gate. Existing stack and resource limits apply.
