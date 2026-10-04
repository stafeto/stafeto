# Terminals, jobs and descriptor readiness

The terminal service provides one console and eight PTY pairs.
`/dev/ptmx` allocates a locked pair; `grantpt` assigns the caller's real UID
and mode 0620, `unlockpt` enables the slave, and `ptsname` names `/dev/pts/N`.
Each session holds up to 32 of the service's 256 open descriptions.
`dup` shares one description and its flags; children inherit open descriptions.
Termios and the window size are shared by the two PTY sides.
Description and instance generations protect operations across reuse.

Canonical editing, echo, input mapping and output processing share the
console's bounded discipline. Master writes apply backpressure at its
capacity; long reads, writes and drains have Start, Take and Cancel phases.
Long operations and readiness watches keep their own generation pins.
Closing the final real master disconnects the line while these pins remain.
Slave reads return EOF, writes return EIO, and poll reports IN/ERR/HUP.
Input is discarded. With CLOCAL clear, the current session leader receives
SIGHUP before EOF readiness is published. CLOCAL suppresses this signal.

Process groups, controlling terminals and foreground checks implement
Ctrl-C, Ctrl-Z, background TTIN/TTOU, STOP/CONT and wait status reports.
Each process keeps its own controlling attachment; children inherit it at birth.
Explicit late TIOCSCTTY attaches the session leader.
Window changes through TIOCSWINSZ notify the current foreground group.
`poll`, `ppoll`, `select` and `pselect` watch pipes and terminal descriptions;
the timed mask variants restore the calling thread's mask on completion.
C probes use `-fno-builtin` and real fork, exec, dup, close and signals.
PTY tests cover disconnect, armed I/O, shared flags, window sizes and reuse.
Interactive ash tests cover builtins, Ctrl-C/Ctrl-Z, jobs/bg/fg and HUP traps.
Loader file actions check ordered Open/Close, aliases and bounded rollback.
