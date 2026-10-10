# E3 directory progress and cleanup followups

Directory walks keep sending bounded ReadDirFd portions through RESOLVING.
Removing the currently scanned child can restart a walk arbitrarily often.
A transport failure or interruption terminates the walk with its original status.
The host probe exercises 64 restarts followed by a result or terminal error.

Open, Scalar and Control records share sixteen resident custody slots,
independent of the 32 ordinary I/O holds. All job kinds retain the session
limit of sixteen outstanding jobs. A free job place permits an Open or Scalar
record while all I/O holds are occupied. The host probe occupies 32 I/O holds
and allocates sixteen Open or Scalar records in separate runs. A full resident
budget retains acknowledged cleanup debt until remote confirmation. Fork
clears resident recovery while preserving published descriptor references.

Resident wire keys use places 32 through 47. Recoverable I/O retains places
0 through 31. The shared resident array assigns distinct keys and generations
across Open, Scalar and Control. FS version 14, the 48 service watermarks,
the table size and the allocation size remain unchanged.

Maintenance has 1,792 consecutive own dispatches without confirmed progress:
four turns per orphan slot and two per session/birth slot fit in that bound. Returning
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
