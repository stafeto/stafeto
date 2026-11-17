# Service budgets (0.5.1)

The RAM file, pipe and terminal services each run their request thread under one budget `serve` of C per T = 5 ms on CPU 0 (250, 75 and 75 us). With the budget spent the thread works at level 1 until the next replenishment. The three together take 23.3 % of the CPU at most from every level above 1, and the levels of the POSIX processes keep the rest.

## Rule for the work of a service

- Work that a blocked client waits on is done in the notice or the request that unblocks it: end of file and a broken pipe, the hang-up of a terminal, waking the waiters of a lock and handing a lock on. The process service names the terminals of a departure in the bits of its notice (bit `terminal`), the terminal service takes all of them in the notice of its main thread, and a client that asks the service next lifts the holder of the notice.
- Work that frees a resource someone needs is done by the client that needs it. A request refused for a table of descriptions, pages, or a place in the table of sessions first makes up to 3 steps (8 000 ticks) of the cleanup after departed sessions on the time the request lends (`Service::settle`, `proto_wire::settle`). If the resource is free the request goes on. If cleanup is left, the service answers `proto_wire::TRY_AGAIN` and `rt::sys::send` sends the request again without showing the answer to the program, up to 4 096 times. Every answer follows at least one step of progress, so the debt of a departed session of 1 000 descriptions is gone after about 350 answers.
- The rest of the work (cleaning of caches) is optional.

## Deferred

- A thread of its own for the services' work under a budget of its own. At level 1 its turns wait for the main thread to be idle, and the kernel charges a loan to the lender's budget only at the end of the request, so a second budget carved out of `serve` isolates nothing and cleanup could not keep up with departures.
- Stopping a loan when the lender's budget runs out. A loan is charged at its end (`settle_loan`, `pay_loan`), so a request overruns by one step, 135 to 160 us at budgets of 25 and 50 us. A timer on the remaining budget and the release of the level a lender holds need support in the kernel.
