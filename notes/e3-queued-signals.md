# E3 genuine cancellation of a queued name request

The POSIX process image builds RAM with `signal-probe`. Method 0xfff4 accepts
no arguments or handles and requires an authenticated session. It creates a
private channel and a timer for 20 ms, acknowledges its caller through the
real deferred reply, then receives only from the private channel. Normal RAM
requests stay queued in the kernel until the timer wakes the service.

The diagnostic is absent from ordinary RAM builds. Enabling `steps` also
disables it, including when `signal-probe` is present. Timing measurements
continue to exercise the production methods and their original budgets.

The C name probe creates its signal sender, requests the pause, and enters
rename. Acquire/release atomics tell the sender when the operation has begun;
the sender waits another 2 ms and sends SIGALRM to that thread. The handler,
installed without SA_RESTART, performs mkdir and rmdir. The operation must
finish with zero, preserve exactly one name, release its custody record, and
increase the count of genuine Interrupted replies. Eight attempts bound a
failure to reach the queued interval. The driver hooks remain disabled during
this scenario, and fake lost replies never increase its genuine counter.

Failure output includes the rename result, errno and the genuine counter.
The QEMU process runner observes any termination of its initial process and
checks the required exit code 42, ending promptly on a failed probe.

Mutations turn a genuine Interrupted into a terminal status and remove the
receive pause. The first fails the rename assertion with one cancelled request;
the second fails the mandatory counter increase. Disabling orphan cancellation
also verifies the existing owner-death failure output and bounded stage runner.
No kernel, relibc or production name-operation implementation changes are needed.
