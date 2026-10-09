# E3 directory progress and cleanup followups

Directory walks keep sending bounded ReadDirFd portions through RESOLVING.
Removing the currently scanned child can restart a walk arbitrarily often.
A transport failure or interruption terminates the walk with its original status.
The host probe exercises 64 restarts followed by a result or terminal error.

Control records have sixteen independent custody slots. The ordinary I/O,
Open and Scalar hold array keeps its original size. Open, Scalar and Control
records still share the session limit of sixteen outstanding jobs. When a
job place exists and an Open cannot allocate its ordinary hold, admission
returns EAGAIN. Waiting on I/O that depends on the calling thread can deadlock.
The host probe occupies all 32 I/O holds, completes sixteen Control outcomes,
and checks acknowledgement, cleanup and reuse. Fork discards both arrays of
resident records while preserving published descriptor references.

Control wire keys use places 32 through 47. Original Open and Scalar keys
retain places 0 through 31. FS version 14 and 48 service watermarks keep
simultaneous Open and Control generations distinct. Each session or retained
birth has 128 additional watermark bytes. Custody slots retain their existing
payload union and initialization rules.

Maintenance has 1,792 consecutive own dispatches without confirmed progress:
four orphan-table scans and two session/birth scans fit in that bound. Returning
a page or retiring an orphan proves progress. A cancellation attempt alone
does not. A full paid page pool can drain across multiple bursts through real
page releases. After exhaustion the service stops posting own notifications;
external requests, session closure and external notifications restart the burst.
The retained job and its resource charges remain available for later cleanup.

The kernel interval probe records the observation time before entry_started
at both checkpoints. Kernel implementation and timing limits are unchanged.
A deliberate old-order delay fails the interval assertion under icount.

Focused mutations restore the 32-directory-reply limit, route Control custody
through occupied I/O slots, collide Open/Control wire keys, count a failed
cancellation attempt as progress, and move the interval observation after its
start. Every mutation fails its corresponding probe.
