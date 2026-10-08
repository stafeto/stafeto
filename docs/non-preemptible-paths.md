# Non-preemptible kernel paths

Interrupts are masked inside the kernel (spec 8.1), so each path below
entirely counts toward the blocking time of any thread, even the
highest-priority one. Resource bounds below include the 128-thread and
128-mapping limits added for the Rust POSIX 64-thread capacity. Current
measurements and their limits are in
[notes/m2-rust-posix-thread-capacity.md](../notes/m2-rust-posix-thread-capacity.md). Existing
cycle figures remain historical measurements; the capacity note records
the new kernel measurements. The table collects such paths with a work estimate
for response-time analysis (spec 15.3). A path whose work grows with the
size of an object is split into chunks with a resume point inside the
object and polling for pending interrupts between chunks
(`arch::irq_pending`, spec 7.7). As of stage 1.3a, the last reference only
puts the object on the cleanup queue, process termination only stops its
threads and puts it on the queue (from stage 3 on, it stops only the
running thread when that is one of the process's, and the Threads stage
stops the others), and the kernel-exit loop
(`sched::resume`) does one chunk between two interrupt polls. A process is
torn down in stages; progress (stage, number of remaining table chunks,
page-table walk path) is stored in the process itself, and a process with
work left goes to the head of its level after a chunk. From part 1.3b on,
teardown runs in two waves: the Stop stage terminates the children, one a
chunk, at level S (the greater of the process's ceiling and the teardown
level R), and the other stages run at R. From stage 3 on, the Threads
stage runs before it at S, 64 units a chunk (a thread waiting in IPC 2,
any other 1): no thread of the process runs between its chunks, since
none has an effective priority above the ceiling, the cleanup queue wins
over threads of its level, and the fast path of `send` hands off to none
of them. Levels between R and S get a one-time interference of at most
N x C_stop, N being the number of descendants (at most Q / 8 KB) and
C_stop the longest chunk of the Stop stage (it counts in `x5`), plus the
Threads chunks of the process and of its descendants, at most 4 each,
none longer than B; levels above S see one chunk. Descendants are
torn down before the parent, in depth-first order through the head of the
queue, and the kernel stack does not depend on tree depth. Quota
accounting (spec 7.5) adds one addition and one comparison against the
process's counter to each kernel-memory allocation and release; a child's
quota is returned to the parent in two parts, at the Quota stage and with
the shell, each in O(1). From part 1.3b on, the pools live with their
payer (spec 7.8): a pool's growth charges a page against the payer's
quota, freeing a slot returns nothing to the quota, and the pages of the
pools go back to the allocator together with the payer's shell, in chunks.
From the same part on, a channel holds one queue on 64 levels with a bit
mask (spec 6.3): notification slots, or the receivers waiting in
`receive` through slots of their own, never both; enqueuing, delivery,
and taking a waiter off cost O(1), and every change to the queue happens
under the scheduler's lock. From part 1.3c on, each level is a ring
whose head the queue keeps, so a queue of 64 levels takes 520 bytes.
Closing the last handle with `RECEIVE` only marks the channel closed and
puts it on the cleanup queue; the Close stage wakes the waiters, in
chunks. From part 1.3e on, the queue counts what stands in it, one more
at each insert and one less at each removal, which `object_info` reads in
O(1). A handle's label lives in a session object (spec 5.3): when the
last copy goes, `CLIENT_GONE` goes into the session's slot, allocated
beforehand, in O(1); the session itself goes in a chunk of its own once
`receive` or the Close stage took its slot.

From part 1.3c on, a thread that waits in `send` stands in the channel's
queue through its own slot, as a request among the notification slots,
and a request a service took waits for its reply in a queue of the same
kind in the service's process, which takes a slot out wherever it
stands. A reply finds its client through a token, a word of the table of
thread numbers: 1024 entries of 16 bytes in memory the kernel takes at
boot, one per thread, which `thread_create` takes and the thread gives
back as it ends, or its chunk when it never started. The meeting of a
request with its receiver, the reply and every wait cost O(1). Bytes 0-63
of a message travel in registers; bytes 64 up to its length, at most 960,
go from the frame of the sender's message buffer into the receiver's
through the linear map, under the scheduler's lock and no other, and the
kernel reads no table of a program for them. A message carries up to
four handles: their values lie in the sender's buffer and are read once;
the room in the receiver's table, at most one new chunk of it, is made
outside the scheduler's lock before the meeting, and the handles then move
from table to table with their references, their values and info words
going into the receiver's buffer. A request that waits in a queue keeps
its handles in the sender's thread; they go, as closed handles do, when a
meeting finds no room for them, at the Close stage, or with the sender's
buffer when it ends. The Close and Buffers stages count each such handle
as one more unit of their chunk's work. When a side goes, the call does
O(1): a thread that ends leaves the queue its slot stands in, and a
client that ends while it waits for its reply leaves a mark in its entry,
which gives the reply `PEER_CLOSED`. The Replies stage of a service's
process wakes its clients with `PEER_CLOSED`, and the Close stage of a
channel the threads that wait in it, 32 of one level a chunk; each stands
at the higher of its cause and its top waiter (spec 7.7), and follows a
waiter whose priority rises. A request in registers alone to a receiver
that waits takes the fast path of `send` (spec 6.4): the same meeting, and
the receiver runs at once, when its level after the boost is above the
cleanup queue's and every ready thread's and no interrupt is pending; the
state is the one the slow path leaves.

ThreadInterrupt withdraws a live thread's current send or receive and wakes
it with Interrupted, keeping its thread number and message buffer. Queue
removal and wakeup take O(1) under the scheduler lock. After the lock it
releases the wait reference and up to four transit handles at the caller's
effective priority. Closing a transferred RECEIVE handle can queue bounded
cleanup as described above. No queue is scanned and no memory is allocated.
A thread whose request a service accepted is not interrupted: BAD_STATE, as
for a thread that waits for nothing, and the reply comes once (spec 6.1).
The interrupt path neither leaves the queue of accepted requests nor marks a
token abandoned any more; only the exit of a thread does both (`sched::exit`,
`channel::cancel`), so that the reply finds PEER_CLOSED and a new owner of
the number never takes the old token.

ThreadUpcallRequest adds one coalesced pending bit and applies that same bounded
interruption to an enabled thread waiting in send or receive. A thread that
waits for a reply keeps its wait, and the entry comes on its way to EL0 after
the reply. A ready target keeps its scheduling level.
Before EL0 return, a constant state check selects the registered user entry;
a pending entry waits for an existing long-call continuation to finish.
ThreadUpcallReturn validates and copies a fixed 816-byte saved context from the
held buffer mapping, and explicitly reloads 528 bytes of FP/SIMD state. No user
pointer is dereferenced, no memory is allocated and no thread queue is scanned.
The user trampoline saves/restores its stack and 1088-byte IPC area at EL0;
that work can be preempted. Nesting consumes user stack, with entry masked during
the fixed scratch-area copy. Upcall path latency has not been measured.

From part 1.3b on, the timers of programs stand in binary heaps, their
nodes inside the timer objects (spec 10), and from part 1.3e on in a heap
for each level of 1-63, the priority of the timer's slot: arming, moving,
and cancelling a timer take O(log n) and allocate nothing, and the nearest
deadline of the levels whose firing is not queued is kept ready and read
in O(1); it is walked again, up to 63 levels, only when the top of a level
or the set of queued levels changes. The kernel's timer is armed for the
nearer of the end of the running thread's quantum and that deadline. Its
interrupt takes no timer off: each level whose top expired puts its own
item, one of 63 in memory the kernel takes at boot, at the tail of that
level of the cleanup queue, and a chunk of that item takes up to 16
expired timers of the level off its heap; with more left the item goes to
the head of its level, otherwise the level's next top counts for the
kernel's timer again. Firings thus run at the level of their timers'
slots, as any chunk of cleanup at that level does, and delay a thread
above that level by one chunk at most. The lock of the timers and the
scheduler's lock are never held together: a timer posts its notification
only once the lock of the timers is released. A timer whose last reference
went is dying: it fires no more, and its own chunk takes it off its heap.
Here n is the number of armed timers of one level, at most 64 per process.

From part 1.3e on, `irq_bind` ties a shared line of the GIC to a channel,
one binding a line (spec 9). A table of 988 entries in memory the kernel
takes at boot names the binding of each line, so an interrupt finds it in
O(1): the kernel masks the line at the distributor, posts bit 0 into the
binding's slot at the slot's priority, as `notify` does, and ends the
interrupt; the line stays masked until `irq_ack`, and a closed channel
keeps it masked. An interrupt of a line no binding holds is masked and
ended. The kind of trigger goes into `GICD_ICFGR` at each `irq_bind`,
while the line is masked. The last handle to a binding masks its line and
frees its entry in O(1), even while a notification of it still waits in
the channel's queue, and a chunk of its own, after its last reference,
gives the channel's slot back. No work of an interrupt is deferred. The
latency of an interrupt of a device is the entry, the blocking time B, the
timers' part of a timer interrupt pending at the same time (the timers'
row), and the path of the delivery to the driver's first instruction.

From the same part on, `device_window_create` makes a device window: a
memory object over a physical range of device registers, rounded out to
whole pages, which touches no page of RAM or of any region of the GIC's
node; the list of those ranges comes from the device tree at boot, 16
regions at most. From part 1.4d on, a window over a page of the
console's port takes the port from the kernel, from its making to its
last chunk of cleanup: a counter goes up and down there, two range
compares and a branch. A window owns no frame: its
pages come from its base without a read of a list, and its chunk only
gives its place back. `mem_map` shows it as `Device-nGnRE`, R or RW,
never executable, in the chunks of any memory object. An SError taken at
EL0 still stops the machine; its report walks the running process's 128
mappings at most for the windows among them.

From part 1.3d on, a memory object takes all its frames when it is made,
up to 8 pages a chunk of `mem_create`: after a chunk that leaves pages and
finds an interrupt pending, the call starts over at its `svc`, with how
far it came kept in the object, which the calling thread holds meanwhile,
and its next entry goes on with no check made again. The handle goes into
the caller's table after the last chunk. The creator's quota pays for the
pages and the nodes of their list at once, into the object's own budget,
which goes back whole with the object. A memory object goes back to the
allocator 32 frames a chunk, two units of work each. The chunks of long calls count toward the
longest chunk (`x5` of `KERNEL_STATS`) as the chunks of cleanup do, each
from one poll for interrupts to the next, the checks of the first entry
and the end of the call included. An entry of the thread with another
call gives the long call up first, as the thread's end does, in a stretch
of its own that counts the same way: with an interrupt pending the entry
starts over at its `svc`, and the other call runs on the next entry, so
giving up and the first entry of a new long call are never one stretch.
`mem_map`, `mem_unmap` and
`mem_protect` change one mapping of a process, up to 32 pages a chunk, 8
when the pages become executable, with how far they came kept in the
calling thread and the mapping marked busy meanwhile, so that other calls
on it fail with `BAD_STATE`; each chunk first checks that the process
lives. A process has at most 128 mappings in one paid page of its page log.
A check of a range walks them and the message buffers of at most 128 threads. `mem_map` charges the process whose space it is
for the most tables its range may take up front, and gives back what its
chunks did not take at its end, so its chunks never fail; tables stay
until the space goes. A chunk that makes pages executable first makes the
instruction cache coherent for their frames through the linear map; a
chunk of `mem_unmap` or `mem_protect` drops the TLB entries of its pages
with one `tlbi vale1is` a page between one `dsb ishst` and one `dsb ish`,
and none of these paths takes an `isb`, since the way back to EL0
synchronizes. A caller that ends midway leaves the mapping with what its
chunks did, in O(1); the stage Mappings of a process lets its mappings go,
after the stage Space took its ASID. The segments and the stack of `init`
are memory objects that `init` pays for and its mappings hold, and the boot
image is a memory object over frames the allocator never gets, whose chunk
gives back only its place. From the same part on, a frame that goes back
to the allocator is two units of work of a chunk, since its free may merge
free blocks up to the highest order and costs about two releases of a
handle: the Buffers stage gives back the buffers of 32 threads with no
handles a chunk, and the Shell stage eight pages; a thread goes into a chunk
of the Buffers stage only when its units fit, so that a chunk does at
most 64 units. The chunks that give frames back are measured with each
frame alone in its free block of 4 MiB, which it merges back up to. The
Buffers chunk is measured with the threads whose units fill it with the
most handles: eleven threads, ten with four handles on their way and one
with two, each handle the last copy of a session whose receiver waits.

Part 1.4e adds in-tree `icount` cases for 11 buffers with 42 handles in
transit, 32 charged shell pages, a 64-thread stop, a first `mem_create`
from a highest-order free block, and `thread_exit` after closing the last
channel handle. On 512 MB their measured costs are 5,116, 15,030, 8,368,
11,368 and 1,032 ticks respectively. The buffer fixture uses resource
handles; the earlier 20,069-tick bound includes sessions whose
`CLIENT_GONE` wakes receivers, so it remains the bounding case. The
shell's former 32-page chunk took 58,634 ticks with test-build poisoning;
its eight-page chunk takes 15,030. The normal build's null call is 271
ticks after adding entry-to-poll timing, while the `icount` build's null
call is 277 ticks with per-call maxima enabled.

The cleanup after audit 3 brings the session cases of the out-of-tree
measurement into the tree, as rows of the line `teardown portions ticks` of
the `icount` build: `session_buffers`, a Buffers chunk of 11 frames each
merging up to the highest order and 42 handles in transit each the last
copy of a session whose receiver waits, 20,079; `session_handles`, a
Handles chunk of 64 such last copies, 20,536; and `stop_senders`, the end
of a process with 128 threads each waiting in `send` through the last
copy of a session of a channel of its own, 42,539 (`stop_threads`, the
same with 128 ready threads, is 24,367); in both the kernel holds the
last reference to each thread, as when the program closed its handle to
it, so that each thread also goes on the cleanup queue. The out-of-tree
measurement itself, run on the same code, gives 19,928 for its Buffers chunk
and 19,767 for its Handles chunk: its receivers wait above the level of
the sessions' slots, while those of the tree wait below it and each wakes
boosted to the slot's level, some 7 ticks a wakeup (with its receivers at
11, the tree gives 19,785 and 20,088). The same build measures the calls
of upcalls and of a request's identity (the line `upcall ticks`); xtask
prints the longest row of the lines of portions and short calls
(memory, timer, interrupt path, device window, upcall and teardown, the
count `threads` aside)
as `B on <machine>`, with the line it comes from.

Stage 3 takes the stopping of the threads out of the call: the rows
`stop_threads` and `stop_senders` give way to `end_call`, the call part of
the end of a process with 128 threads, the running one, as in
`process_exit` or a fault, and 127 waiting in `send` through the last
copies of sessions of channels of their own, 335 (174 with no running
thread to take off); `threads_ready`, the longest Threads chunk of a
process with 128 ready threads (64 threads), 12,189 with the threads on
a level each, 1-63 in turn, 12,127 with all on one level (the line
`threads ready ticks`); `teardown_threads`, the same with the 127
senders (32 threads), 10,747; and `child_threads`, the longest chunk of
the teardown of a parent whose child has the 127 senders, 10,747. In all
these teardowns the kernel holds the last reference to each thread, and
the measurement fails when any chunk of them, the threads' own cleanup
included, is longer than the `session_handles` of the same run
(`KERNEL_STATS` `x5`). B stays 20,536 (`session_handles`). A process
whose only thread ends it skips the Threads stage.

Between the end and its Threads chunks, a thread of the ended process
that waits in `receive` stays in the channel's queue: on a channel that
a live process receives on too, it takes requests and notifications as
any receiver does (spec 6.8, 7.7). Its client wakes with `PEER_CLOSED`
at the Replies stage, and a notification goes with the process. Keeping
`post` O(1) leaves this so: a handle with `RECEIVE` goes to a new
instance of a service only after the end notification of the old one,
which comes after the Threads stage; init never holds one (`REGISTER`
refuses it). The `thread_exit` that ends a process with 8 stopped
threads (`thread exit after close`) falls from 1,135 to 351, since the
Threads stage stops them.

The last column holds instruction counts of the kernel built at
opt-level 2 (spec 14), measured after stage 1.3 (the lines xtask
prints after part 1.4a), in QEMU
11.1 (`virt`, `cortex-a72`, 512 MB; the stages Buffers and Shell on
`cortex-a53` with 2 GB, whose free blocks of 4 MiB their measurement
needs) under `-icount shift=4,sleep=off`, where
one tick of `CNTVCT_EL0` is one instruction: calls from EL0 round trip,
1000 times each, less the empty measurement; chunks as the longest time
`KERNEL_STATS` records (`x5`, `x8`). The counts see no
barriers, exclusive accesses, `TTBR0` switches or cache misses, which cost
several times more on hardware; they compare versions of the kernel, and
bounds in time come from hardware (spec 15.3). An empty cell is a path not
measured yet. Counts marked "test build" come from the kernel's own tests
under -icount, whose hooks change the shape of the code. The build that
ships is measured by the test init under -icount, which prints
`normal build ticks: null=271 clock=314 yield=384 notify=890
round_trip=1825`: call 0, `clock_now`, `yield` with no other thread at
the caller's level, `notify` with the `try_receive` that takes the slot
back, and a round trip of 8 bytes to a thread of the same process. Both
sides make raw calls, so the line counts the kernel and not the code of
`rt` or the profile the test init builds with. The
kernel test `ipc_round_trip_is_measured` prints the round trip of a
request in the test build, `ipc round trip ticks: null=277 switch=493
fast=1990 slow=2216 buffer=3116 handles=4418`: an empty call, one switch between
threads of two processes (half of a yield there and back), and a request
answered by a service of another process that waits in `receive`: on the
fast path, with the fast path off, with 1024 bytes each way, and with four
handles each way. The lower bound of a round trip, two switches and one
empty call, is 1263 there; the fast path saves 226, and the two copies of
960 bytes cost 1126. The chunks of the stages that release handles are
measured at the costliest unit, where the last copy of a session wakes a
receiver of its own channel with `CLIENT_GONE`. The kernel test
`memory_portions_are_measured` prints the longest entries of the long
calls of memory objects in their worst cases there (spec 15.3), each from
the kernel's dispatch of the call to its end with an interrupt pending all
along, so that an entry takes one chunk: `memory portions ticks:
create=11172 map=5573 map_exec=8063 unmap=2706 protect=2847
protect_exec=6287 release=16183 first_map=13825`. On the `cortex-a53`,
whose instruction cache the kernel flushes whole, `map_exec` is 5,880,
`protect_exec` 4,139 and `first_map` 11,767. Allocations are measured
with free blocks of lower orders at hand. The Shell stage of
the test build also fills each page it gives back with poison; its count
here is without the poison, as in the normal build. The kernel test
`timer_firing_is_measured` prints the timers of programs in their worst
cases there (spec 15.3), `timer portions ticks: interrupt=4323 fire=13276
set=2122 timers_8192=2690`: the timers' part of an interrupt that finds the
tops of all 63 levels expired, a chunk of firings that takes 16 timers off
a heap of 8,130 of one level, each waking a receiver of its own channel,
`timer_set` of the top of that heap to a deadline before every other,
among 63 levels with timers, and `timer_cancel` of that timer, the root
then, whose place the last node takes, 13 steps down. The system then
holds `abi::MAX_SYSTEM_TIMERS`, 8,192 timers, and the next `timer_create`
fails with `LIMIT_REACHED`: no heap is deeper than 13. The kernel test
`interrupt_path_is_measured` prints the paths of interrupt bindings there,
`interrupt path ticks: driver=687 bind=693 ack=126 portion=252`: the
delivery of an interrupt of a bound line to a driver of another process
that waits in `receive`, from the `svc` of a thread below it that makes
the line pending to the driver's first instruction, with no timer armed;
the first entry of `irq_bind` whose pool of bindings takes a page;
`irq_ack` of a masked line; and the chunk of a binding that goes. The
kernel test `device_windows_are_measured` prints device windows there,
`device window ticks: create=734 map=7280 release=237`: the first entry
of `device_window_create` whose pool of memory objects takes a page; the
longest entry of `mem_map` of 64 pages of a window into a new process,
the first with its checks and the tables of the range; and the chunk of a
window that goes.

| Path | What it does | Estimate | Instructions under -icount |
|---|---|---|---|
| entry and exit (`vectors.S`, `handle_exception`, `sched::resume`, `thread::run`) | saves the thread's registers, decodes ESR and the call number, writes the result, polls for pending interrupts, decides who runs, and returns to EL0; every entry pays it, an interrupt too | constant | 271: call 0 from EL0, which fails with `INVALID_ARGS`, in the normal build |
| `AddressSpace::retire` and `SpaceRelease::step` | `retire` moves `TTBR0` off the tables and drops their TLB entries together with the ASID (`tlbi aside1is`); a step reads up to 512 words of one level 0-2 table and returns at most one table to the allocator, the root last | constant: `retire`; a step: up to 512 reads and one table; `AddressSpace::destroy` (tests, and `process::create` that ran out of pool space, with a single root table) does all steps back to back |  |
| issuing an ASID (`tlb::switch_to`, `AsidAllocator::activate`) | looks for a free number in the generation map; runs on every `thread::run` into a process whose space has no ASID of the current generation: the space's first run and the first run after a generation change | constant: up to 1024 map words with 16-bit ASIDs, up to 4 with 8-bit |  |
| ASID generation change (`tlb::switch_to`) | when no free numbers are left: zeroes the number map (8 KB), flushes the TLB (`tlbi vmalle1`), then issues a number as in the row above | constant: zeroing 8 KB, a TLB flush, and issuing a number |  |
| loading `init` at startup (`init::load`, `memory::create_whole`, `process::map_whole`) | each segment and the stack go into a memory object of their own, made whole with every chunk of `mem_create` in a row, the bytes of the file copied into its frames through the linear map, and mapped with every chunk of `mem_map` in a row | the size of `init`'s program and stack, with interrupts masked; only at startup, before the scheduler runs, and in the kernel's tests |  |
| `arch::cache::sync_icache_frames` | `dc cvau` and `ic ivau` over the cache lines of whole frames through the linear map, with one set of barriers; on a VIPT instruction cache (A53), a flush of the whole instruction cache (`ic ialluis`) takes the place of `ic ivau` | frames / line size; a chunk of an executable mapping: 8 pages |  |
| FP/SIMD switch in `thread::run` | saves the outgoing thread's registers and loads the incoming thread's (528 bytes each) | constant: 1056 bytes |  |
| `debug_write` | puts up to 64 bytes into the kernel log as one record (a read of the counter, a copy of 64 bytes, two counters); while no device window covers the console's page, also writes them to the PL011 synchronously, waiting for room in the transmit queue, with a CR before every LF | with a window: constant; without one, up to 128 characters: on hardware at 115,200 baud and 10 bits per character, about 11 ms; instant in QEMU; after 1.4d only early boot, time with no driver and the test images print this way | 499 under -icount (normal build, `log ticks` of the test init): the whole call of 64 bytes behind a window |
| `object_info` | reads process fields (state, quota count, three handle-table numbers), a thread's state, what it waits for, its priorities and policy under the scheduler's lock, a channel's counts of its queue under the scheduler's lock, its sources and whether it is closed, a memory object's or a device window's size, pages and mappings, a binding's line, mask and trigger, the label of a labelled copy of a channel for `LABEL` (two lookups and a compare), the actual calling Thread for `THREAD_CURRENT` (one lookup and object comparison), inserts one owned NONE handle for `SELF_THREAD` using the paid handle table, or kernel counters for `KERNEL_STATS`: the scheduler's and frame allocator's under their locks, the queue length and the longest chunk under the queue lock taken twice, and the atomic pool page counter; for `LOG`, a walk of the 64 records of the kernel log and a copy of up to 12 records, 960 bytes, into the caller's message buffer through the linear map | constant with bounded paid handle-table insertion for `SELF_THREAD`; for `KERNEL_STATS`, four lock acquisitions, one at a time; for `LOG`, 64 records and 960 bytes | 810 under -icount (normal build, `log ticks` of the test init): the whole call of `LOG` that takes a full batch |
| the last reference to an object (`object::release`, `process::release`, `thread::release`, `memory::release`) | puts the object at the tail of the cleanup queue at the level of the cause: the effective priority of the thread whose call or fault released the reference, or the level of the object whose chunk released it; a live process is terminated in the process, as in the process termination row, without threads | constant: insertion at the tail of a level and a mask bit; no nested teardown |  |
| pool growth (`kcore::slab::PaidPages`: the payer's pools of threads, blocks (the chunks and the directory of its handle table), child shells, channels, sessions, timers, memory objects, and interrupt bindings) | only when the pool has no free slot: charges a page against the payer's quota, takes an order-0 frame, and lays the page out into slots; when the entries of the payer's page log have run out, first takes a list page the same way | constant: up to two charges and two order-0 frames (each at most `MAX_ORDER` = 10 splits in `FRAMES`) and laying a page out into slots; freeing a slot is O(1) and does not call the allocator |  |
| a chunk of the Threads stage (`process::clean`, `stop_threads`) | from the `threads_next` cursor on, each thread of the list leaves the scheduler for good (`sched::exit`) at level R: a thread that waits in `send`, `receive` or for a reply first leaves its queue and lets go what its wait held (2 units), any other thread 1 unit, 64 units a chunk; the kernel's reference goes, which may queue the thread; the process goes to the head of level S, and after the last thread moves on to the Stop or the Replies stage; a thread that leaves the list moves the cursor on | up to 64 units: 32 threads in IPC or 64 others, each O(1); a sender through the last copy of a session posts `CLIENT_GONE` as `notify` does | 12,189 (test build, `threads_ready`): 64 ready threads on a level each, 1-63 in turn, the kernel's reference the last of each (12,127 on one level); 10,747 (`teardown_threads`): 32 threads waiting in `send`, each through the last copy of a session of a channel of its own |
| a chunk of the Stop stage (`process::clean`, `stop_child`) | the child at the `stop_next` cursor: if it is alive, terminating it as killed at level R (the process termination row); the cursor moves on; the process goes to the head of level S, and after the last child moves on to the Replies stage | constant: the child's termination and up to three O(1) queue operations; no longer than the former Children chunk | 10,747 (test build, `child_threads`) is the longest chunk of the teardown of a parent whose child has 128 senders: a Threads chunk of the child |
| a chunk of the Replies stage (`process::clean`, `wake_clients`) | up to 32 clients of the top level of the queue of requests the process's threads accepted, under one hold of the scheduler's lock: each leaves the queue and gets `PEER_CLOSED` in `x0`, and goes to the tail of its level with a new quantum; with clients left, the process goes to the head of the higher of R and their new top level, otherwise on to the Children stage at the head of level R; with no client, one chunk that only moves on. The stage stands at the higher of R and the top client | up to 32 clients at O(1) each | 2,686 (test build): 32 clients |
| a chunk of the Children stage (`process::clean`) | the first child in the list, terminated by the Stop stage: the process goes to the head of level R, and the child to the head of its stage's level right before it (`process::hasten`) | constant: an insertion at the head and a raise |  |
| `process::hasten` (the Children stage, `process_kill` of a terminated process) | R grows to the level of the call; a process in its stages goes to the head of its stage's level (`cleanup::raise`); a shell has nothing to raise | constant: a removal from a list and an insertion at the head |  |
| a chunk of the Handles stage (`process::clean`) | `HandleTable::release_step`: one table chunk; each entry's object is released in O(1): the last copy of a session posts `CLIENT_GONE` as `notify` does, and the last handle with `RECEIVE` closes its channel; the chunk directory goes with the last chunk | up to 64 entries, each no costlier than `notify` | 20,538 (test build, `session_handles`, since process suspension): 64 last copies of sessions, each `CLIENT_GONE` waking a receiver of its own channel; 19,960 after stage 1.3 by the out-of-tree measurement after stage 1.3; 8,166 when nobody waits |
| a chunk of the Space stage (`process::clean`) | the first chunk takes the space away from the process and does `AddressSpace::retire`; each following one does `SpaceRelease::step` | see the `AddressSpace::retire` row | 4,264 (test build): a step |
| a chunk of the Buffers stage (`process::clean`) | returns the message-buffer frames of threads stopped by termination, releases the handles of the requests of those that waited in `send`, up to 4 each, as `handle_close` does (the last copy of a session posts `CLIENT_GONE` as `notify` does), and what a long call a thread was making held: the object of a `mem_create`, whose last reference puts it on the cleanup queue, or a mapping a change left midway, which keeps what its chunks did; and removes the threads from the process's list; 64 units of work a chunk, a frame two and each handle or object one more, a thread going into a chunk only when its units fit, so the frames of 32 threads with no handles take one chunk | up to 32 frames, each through merging free blocks in `FRAMES` up to the highest order and returning the frame to the quota, and with handles up to 64 units, since a thread goes into a chunk only when its units fit, each handle no costlier than `notify`: under -icount within 3 % of a Handles chunk of 64 last copies of sessions, the longest teardown chunk measured; the first measurement on hardware should record which stage set the longest time (the `KERNEL_STATS` kind in `x5`), so the limit of 64 units in Buffers is tuned separately from the handle-table chunk size | 19,354 (test build): 32 frames, each merging up to the highest order; 20,079 (test build, `session_buffers`): 11 frames, each merging up to the highest order, and 42 handles, each the last copy of a session whose `CLIENT_GONE` wakes a receiver (20,069 after stage 1.3 by the out-of-tree measurement after stage 1.3) |
| a chunk of the Mappings stage (`process::clean`, `maps::release_all`) | every mapping of the process's table, busy or not, leaves it and releases its memory object, whose last reference puts it on the cleanup queue; the paid table page stays in the page log until shell cleanup | up to 128 mappings at O(1) each | 4,221 (test build): 64 mappings, 62 of them the last references to their objects |
| a chunk of the Quota stage (`process::clean`) | returns the free part of the quota to the parent (`Account::return_free`) and removes the process from the parent's list of children | constant |  |
| a chunk of the Notify stage (`process::clean`, `notify_exit`) | if the process has an exit channel, posts bit 0 into the slot in its shell as `notify` does: delivery to a waiting receiver, or enqueuing in the channel's queue, where the slot holds the shell; a closed channel gets nothing | constant: as `notify` |  |
| a chunk of the Shell stage (`process::clean`) | `PageLog::release_step`: up to eight pages of the process's pools and of its log go back to the allocator, each returned to the quota (the test build first fills the page with poison); the last chunk returns the shell's slot to the parent's pool, the slot in the exit channel's limit and the reference to that channel, and the rest of the quota to the parent (`Account::return_rest`), and releases the reference to the parent's shell (the last one enqueues it) | up to eight frames, each through merging free blocks in `FRAMES` up to the highest order; in the test build, also writing 4096 bytes of poison per frame; the rest is constant | 15,030 (test build): eight pages with poison; the former 32-page chunk took 58,634 |
| the last channel handle with `RECEIVE` (`channel::release`: `handle_close`, the Handles stage) | marks the channel closed; if threads wait in it or slots stand in it, puts the channel at the tail of the cleanup queue at the higher of the level of the cause and the top level of its queue, with the queue's reference (the Close stage) | constant: checking the queue's mask and one enqueue |  |
| a chunk of the Close stage (`channel::clean`) | heads of the top level of the channel's queue, 32 units of work (below), each under its own hold of the scheduler's lock: the threads waiting in `receive` or in `send`, each of which gets `PEER_CLOSED` in `x0`, goes to the tail of its level with a new quantum, and lets go of what its wait held, the channel or a copy of a session (the last copy posts `CLIENT_GONE`, which a closed channel refuses), and a sender of the handles of its request, up to 4, each released as `handle_close` does; or the slots, each emptied and letting go of its owner after the lock (a session with no copies goes on the cleanup queue); what the heads held goes at the level of the cause; with heads left, the channel goes to the head of the higher of the cause and their new top level, otherwise the queue's reference goes | 32 units of work: a head one, and each handle of a sender's request one more, no costlier than `notify`; up to 32 heads at O(1) each and 34 holds of the lock, or fewer heads with their handles, up to 36 units | 3,844 (test build): the first of the two chunks of a channel with 60 waiting receivers; 10,166 (test build): 8 senders with 32 handles, each the last copy of a session whose `CLIENT_GONE` wakes a receiver; 5,581 when nobody waits, with the copies of the sessions the requests went through |
| a chunk of the channel shell (`channel::clean`) | returns the channel's slot to the payer's pool of channels (nothing goes back to the quota) and releases the reference to the payer's shell | constant |  |
| a thread-cleanup chunk (`thread::clean`) | unmaps the message-buffer page if it is still there, with the handles of a request the thread made, up to 4, released as `handle_close` does, and what a long call it was making held: the object of a `mem_create`, or, for a change of a mapping, the mapping keeps what the chunks did and the rest of the prepaid tables goes back (`process::abandon_change`); gives the number of a thread that never started back to the table of thread numbers (its count stays, and an entry at the end of its count retires), removes the thread from the process's list, returns the slot to the process's pool of threads (nothing goes back to the quota), and releases the reference to the process | constant: up to 4 handles, each no costlier than `notify` |  |
| the kernel-exit loop (`sched::resume`) | on the empty kernel stack: polling `ISR_EL1.I`, acknowledging and handling an interrupt, a scheduling decision, then a thread, one cleanup chunk, or `wfi` | constant without a chunk; at most one chunk between two interrupt polls, and a chunk only starts with no interrupt pending, so the blocking time of any thread gains the longest chunk, of cleanup or of a long call (the kernel measures both and returns the longest in `x5` of the `KERNEL_STATS` kind from `object_info`) |  |
| a scheduler decision (`sched::resume` and the events `sched::{start, exit, yield_running, set_priority, timer_fired}`) | `kcore::sched` operations: inserting at the head or tail of a level, removing from a ring, picking a level from the mask via `clz` with the cleanup queue's level at the top on entry, the timer deadline; `sched::exit` of a waiting thread first takes its slot off the channel's queue, or off the queue of accepted requests of the process that took its request and marks its entry of the table of thread numbers, gives the thread's number back, and lets go of what the wait held after the lock (the last copy of a session posts `CLIENT_GONE` as `notify` does); `set_priority` of a waiting thread moves its slot within that queue, and after the lock raises a channel at its Close stage or a process at its Replies stage to its new top waiter (`cleanup::raise`) | constant, independent of the number of threads; `sched::exit` with the last reference to a thread or to a channel puts it on the cleanup queue |  |
| a timer write (`Armed::set`, `sched::timer_fired`) | `CNTV_CVAL_EL0` and `CNTV_CTL_EL0`, then `isb`, only when the needed deadline changed: the nearer of the end of the running round-robin thread's quantum and the nearest deadline of the levels of timers whose firing is not queued, which `sched::decide` reads in O(1) before it takes the scheduler's lock; returning to the same thread leaves the timer untouched; a timer interrupt disarms it until EOI | constant: three system-register writes and two `isb`s per deadline |  |
| the timers' part of the timer interrupt (`timer::expire` in `sched::timer_fired`, before the EOI) | walks the levels that have timers and whose firing is not queued, marks those whose top expired as queued and finds the nearest deadline of the rest in the same walk, and puts the item of each expired level at the tail of its level of the cleanup queue; no timer leaves its heap | constant: a walk of up to 63 levels and 63 enqueues | 4,323 (test build): all 63 levels expired |
| a chunk of firings (`timer::fire`) | reads the counter once; up to 16 timers of the item's level that expired by then leave its heap, the earliest first, each under its own hold of the lock of the timers; each that is not dying posts bit 0 into its slot at that level, as `notify` does: the top waiting receiver gets it, or the slot goes into the channel's queue and holds its timer; a dying timer posts nothing; with expired timers left the item goes back to the head of its level, otherwise the level settles and the nearest deadline is walked again; the chunk's time goes into `x8` of `KERNEL_STATS` | 16 steps of O(log n), 16 posts of O(1) and a walk of 63 levels | 13,276 (test build): 16 timers off a heap of 8,130, each waking a receiver of its own channel |
| process termination (`process::end`: `process_kill`, `process_exit`, the last running thread exiting, a fault at EL0) | records the reason, after which `thread_start`, `thread_create` and `mem_map` of the process give `BAD_STATE`; removes the running thread from the scheduler when it is one of the process's (the kernel reference goes, and the thread may land on the cleanup queue); then puts the process at the tail of the cleanup queue with the queue's reference: at level S if it has threads (the Threads stage) or children (the Stop stage), otherwise at the level of the Replies stage, the higher of R and the top client of the requests its threads accepted; R is at least the cause and the priority of the exit notification (`x4` of `process_create`) | constant: one thread and one enqueue; the other threads, up to 128 (`abi::MAX_THREADS`), and the descendants go with the teardown stages; `process_kill` of a terminated process calls `process::hasten` instead | 335 (test build, `end_call`): a process with 128 threads, the running one, whose kernel reference is its last, and 127 waiting in `send` (174 with none running); 42,539 before stage 3, when the call stopped every thread |
| `process_kill` (`syscall::process_kill`) | checks the level (0-63), the handle, and a level of 1-63 against the caller's effective priority; then process termination (the row above) with the level as its cause, or the caller's effective priority for level 0, so R = max(level, the exit notification's priority); below the caller's priority the call returns once the part in the call is done, and the teardown runs at R after it, except its Threads and Stop stages, which run at S, the higher of the victim's ceiling and R: when the victim's ceiling is above the caller, the caller waits for them (at most 4 Threads chunks and one Stop chunk for each child, on levels where the victim could run anyway) | constant: one comparison besides process termination | 427 (test build, `process kill ticks`): a child with a running thread killed at level 1 from a caller at 10, the part in the call; its teardown waits in the cleanup queue |
| an SError at EL0 (`exceptions::system_error`) | counts the device windows among the running process's mappings, prints them and the program's registers, and stops the machine | up to 128 mappings, then the report; the machine does not go on |  |
| a fault at EL0 (`exceptions::user_fault`) | formats one cause line into the kernel log, two records; while no device window covers the console's page, also writes it to the port synchronously; then process termination | with a window: the formatting and two records; without one, up to 110 characters: on hardware at 115,200 baud, about 9.5 ms; instant in QEMU; no rights needed, any program can cause a fault; for `init` this is followed by the program's registers (up to 900 characters, 15 records), after which the machine stops; then the process termination row |  |
| `process_create` | checks that the caller's table has room for a handle (spec 11: the allocation-free limit is checked first), with `x3` takes a slot in the exit channel, then charges the child's quota against the caller's account, takes a frame for the root table of an empty address space and zeroes it, takes a slot in the caller's pool of shells (the pool growth row; a shell takes 1,384 bytes, two to a page), puts the child at the head of the caller's list of children (`adopt`), inserts into entry 0 of the child's table the start channel `x5` or a placeholder that goes at once, and inserts the child's handle into the caller's table; then the notification slot in the child's shell, and the `x5` handle leaves the caller's table | constant: zeroing 512 root words, at most one growth of the caller's pool of shells, of the child's pool of blocks, and of the caller's pool of blocks; a full caller table keeps the child from starting to build; if the handle still does not fit (out of memory for a new chunk), the child goes onto the cleanup queue, the slot in the channel comes back, and `x5` stays with the caller |  |
| `thread_create` | checks that the buffer's page lies in none of the target's mappings (up to 128) and that the caller's table has room for a handle (spec 11), then the process's number of not-yet-dead threads against the limit and the free entries of the table of thread numbers, with `x7` takes a slot in the exit channel, then takes a slot in the process's pool of threads (the pool growth row; a thread takes 1,296 bytes with the source of its end, three to a page), charges a buffer frame against the process's quota, takes a frame for the message buffer, zeroes it, maps the page into the process and writes its address into the thread's `TPIDRRO_EL0`, and takes a thread number, the first never handed out or the first given back | constant: 512 entries of 8 bytes and up to three new tables; a full caller table keeps the thread from starting to build |  |
| `mem_create` (`syscall::mem_create`, `memory::create`, `memory::fill`) | the first entry checks the size and the flags, makes room for the handle in the caller's table (`HandleTable::reserve`, at most one chunk), takes a place in the caller's pool of memory objects (the pool growth row), and charges the object's pages and the nodes of their list to the caller's quota at once; then chunks of up to 8 pages: a frame from the object's budget, zeroed, its address into the list of pages, and a node of the list when one is due; after a chunk that leaves pages, a pending interrupt makes the call start over at its `svc`, and the next entry goes on with the object the thread holds; the last chunk inserts the handle, or, when other threads of the process took the room meanwhile, fails with `LIMIT_REACHED` or `NO_MEMORY` and puts the object on the cleanup queue | a chunk: up to 8 frames, each zeroed (4096 bytes), and 2 nodes of the list; the first entry adds at most one chunk of the table and one page of the pool before its first chunk; the whole call is bounded only by the quota, a chunk at a time | 11,172 (test build): the first entry of a new process, with the directory and the first chunk of its table, a page of its pool of memory objects, and a chunk with the node of nodes and a leaf |
| `mem_create` contiguous (`MEM_CONTIGUOUS`, `memory::create_contiguous`, `memory::fill`) | the first entry checks the size, the flags and the resource with `DEVICE`, makes room for the handle, takes a place in the pool, charges the 2^k pages to the caller's quota and takes the whole block from the frame allocator (`FrameAllocator::alloc`, splitting down from the highest order), or refunds the charge when no block is big enough; then chunks of 8 pages: each page zeroed through the linear map, then `dc civac` over every line of the chunk and one `dsb sy`; the last chunk inserts the handle with the block's address in `x2`; only while a driver starts, off every real-time path | a chunk: 8 frames zeroed (4096 bytes each) and 8 x 4096 / line `dc civac`; the first entry adds the block's split, up to 10 steps | 9,248 (test build): the longest entry of an uncached object of 1,024 pages, the first with the block; under HVF the line `dma portions ticks` gives it in counter ticks with real caches |
| `mem_map` (`syscall::mem_map`, `process::add_mapping`, `process::step_change`) | the first entry checks the values, the two handles, the target's life, the range against the object's size, the target's mappings and the message buffers of its threads (`process::check_free`), then takes a place among the target's 128 mappings, a paid page for its table at its first mapping, and charges the target's quota for the most tables the range may take (`tables_bound`); the mapping goes in, busy, with a reference to the object; then chunks of up to 32 pages, 8 with execution: the frames of the object's pages from its list of pages, or from the base of a device window, for executable pages the instruction cache made coherent for them, the descriptors written with tables from the prepaid charge, and one `dsb ishst`; after a chunk that leaves pages, a pending interrupt makes the call start over at its `svc`; the last chunk makes the mapping idle and gives back what the tables did not take | the first entry: up to 128 mappings, 128 threads and one paid table page before its first chunk; a chunk: 32 pages, each two reads of the list and a walk of the tables, and up to 6 new zeroed tables when the range crosses 2 MB, 1 GB and 512 GB bounds; with execution 8 pages and `dc cvau` and `ic ivau` over them | 13,825 (test build): the first entry of the 64th mapping of a process with 64 threads, of 8 pages RX across a bound of 512 GB with no table on either side, 6 tables; the entries after the first, across a bound of 512 GB with 3 new tables: 5,573 with 32 pages, 8,063 with 8 pages RX |
| `mem_unmap` and `mem_protect` (`syscall::mem_unmap`, `syscall::mem_protect`, `process::step_change`) | the first entry checks the values, the handle, the target's life, finds the one mapping that is the range, idle, and for `mem_protect` the rights it was mapped with; the mapping is marked busy; then chunks of up to 32 pages, 8 when `mem_protect` makes them executable (the instruction cache made coherent first): each descriptor cleared or given the new permissions in place, then `dsb ishst`, a `tlbi vale1is` a page and one `dsb ish` when the space has an ASID of the current generation; the last chunk of `mem_unmap` takes the mapping out and releases its memory object, that of `mem_protect` makes it idle | a chunk: 32 pages, each a walk of the tables and a TLBI; the first entry walks up to 128 mappings | 2,706 (test build): the first entry of `mem_unmap` of 64 pages among 64 mappings of a process with an ASID; `mem_protect` to R 2,847, to RX 6,287 with 8 pages |
| `device_window_create` | rounds the range out to whole pages and checks the length, the end and the size, then the handle, then the pages against the list of RAM and the kernel's devices (17 regions), then the room in the caller's table (spec 11); takes a place in the caller's pool of memory objects (the pool growth row) and inserts a handle with the window's rights | constant: 17 comparisons, at most one growth of the caller's pool of memory objects and of its pool of blocks | 734 (test build): the pool of memory objects taking a page |
| a chunk of a memory object (`memory::clean`) | `PageList::release_step`: up to 32 frames, the pages and then the nodes of the object's list, go back to the allocator, each refunded to the object's budget; with frames left the object goes to the head of its level; the last chunk returns the object's place to its payer's pool and its budget to the payer's quota, and releases the reference to the payer's shell | up to 32 frames, each through merging free blocks in `FRAMES` up to the highest order; a device window or the object over the boot image, one chunk that only gives the place back | 16,183 (test build): the last chunk, 31 pages and the node of their list, each merging up to the highest order, with the object's place and budget; 237 a device window |
| a contiguous object's chunk (`memory::clean`, `MEM_CONTIGUOUS`) | gives the block back in one free to the allocator, refunded to the object's budget, then the place, the budget and the reference to the payer's shell as in the row above; no cache maintenance (the next holder zeroes the frames through the cache) | constant: one free, merging up to the highest order | 457 (test build): an object of one page |
| `channel_create` | checks the room in the caller's table (spec 11), takes a slot in the caller's pool of channels (the pool growth row; a channel takes about 650 bytes, six to a page), and inserts a handle with the channel's rights | constant: at most one growth of the caller's pool of channels and of its pool of blocks |  |
| `notify` | ORs the bits in and counts with saturation in the slot of label 0, or through a labelled handle in its session's slot; a slot that was not queued goes to the top waiting receiver (its `x0`-`x11`, a boost to the slot's priority under the ceiling, the tail of the boosted level with a new quantum, and letting go of the wait reference) or to the tail of its level in the queue of slots, where it holds its owner; a closed channel returns `PEER_CLOSED` and gets nothing | constant: the level mask, doubly linked lists, and writing 12 words | 848 into an empty channel, with the `try_receive` that takes the slot back |
| `receive` | before queue consumption, rejects a blocking wait when entry deferral holds an enabled pending upcall; nonblocking polling remains available; drops the caller's boost; takes the head of the top level of the channel's queue: a slot, which it empties into `x0`-`x11` and whose priority boosts the caller, letting go of the slot's owner after the lock (a session with no copies goes on the cleanup queue); or a request, which it takes as in the `send` row, letting go of what the sender's wait held after the lock (the last copy of a session posts `CLIENT_GONE` as `notify` does); a request with handles first gets room for them in the caller's table outside the lock (`HandleTable::reserve`, at most one chunk: the pool growth row), and without room its sender wakes with the error, its handles are released, up to 4, and the call starts over at its `svc` for the next head, after a poll for interrupts; with nothing queued, returns `WOULD_BLOCK` for "do not wait" or puts the thread to wait, its own slot at the tail of its level in the channel's queue | constant: with handles, at most one chunk, 4 inserts and 4 releases, each no costlier than `notify` |  |
| `send` | checks the description and the values of up to 4 handles, read once from the caller's buffer, the handle, then each handle of the message (a lookup each), the count of the caller's thread number, the channel's state, and "do not wait" without a waiting receiver; a closed channel releases the handles; an enabled pending upcall under entry deferral returns `INTERRUPTED` before queuing or fast handoff, releasing up to four transferred handles; with a waiting receiver, room for the handles in its table first, outside the lock (`HandleTable::reserve`, at most one chunk: the pool growth row), and without room the handles are released and the call fails; the handles leave the caller's table; then under the scheduler's lock the caller waits: its request goes to the top waiting receiver at once (the count grows by 1 for the token, the caller's slot goes to the tail of its level in the queue of accepted requests of the receiver's process, the receiver gets `x0`-`x11` from the caller's registers with the bytes past the length zeroed and bytes 64 up to the length from the caller's buffer frame into its own, a boost to the caller's level under its ceiling, and the tail of its level with a new quantum, the handles going into its table, their values and info words into its buffer), or its slot goes to the tail of its level in the channel's queue, holding the channel or a copy of the session and the handles; the receiver's wait reference goes after the lock | constant: the level mask, rings, writing 12 words, copying at most 960 bytes, and with handles 4 lookups, at most one chunk, 4 removals and 4 inserts | a round trip with the service's `reply` and `receive` (test build): 2,093 in registers, 2,993 with 1024 bytes each way, 4,295 with four handles each way; 1,773 in the build that ships, 8 bytes to a thread of the same process, raw calls on both sides |
| the fast path of `send` (`channel::fast_send`, `sched::hand_off`) | a request of up to 64 bytes and no handles to a receiver that waits: reads the top of the cleanup queue and the nearest deadline of the timers before the scheduler's lock; under it checks that the receiver's level after the boost is above the cleanup's and every ready thread's and that no interrupt is pending (`ISR_EL1`), makes the meeting as `send` does, puts the receiver on the CPU with a new quantum (`Scheduler::hand_off`) and arms the timer for the deadline it needs; the receiver's wait reference goes after the lock, and the receiver runs (`thread::run`) | constant: no memory of a program is touched | a round trip with the service's `reply` and `receive` (test build): 1,895 |
| `reply` | checks the description and the values of up to 4 handles, read once from the caller's buffer, then each handle; drops the caller's boost when the token is the boost's; then checks the token: the entry of the table of thread numbers, with its mark of a client that ended while it waited (`PEER_CLOSED`, and the handles are released), and a client waiting for this process's reply; room for the handles in the client's table outside the lock (`HandleTable::reserve`, at most one chunk), and the handles leave the caller's table; takes the client's slot off the queue of accepted requests, writes its `x0`-`x9` from the caller's registers with the bytes past the length zeroed and bytes 64 up to the length from the caller's buffer frame into the client's, the handles into its table and their values and info words into its buffer, or without room the error into its `x0` and releases the handles, and puts it at the tail of its level with a new quantum | constant: a ring, writing 10 words, copying at most 960 bytes, and with handles 4 lookups, at most one chunk, 4 removals and 4 inserts or releases |  |
| `handle_duplicate` | without a label: inserts a copy of the handle with narrowed rights and adds a reference to the object (to a session, a copy too); with a label: checks the room in the caller's table (spec 11), takes one of the channel's 1024 slots, takes a slot in the caller's pool of sessions (the pool growth row), and inserts the session's handle | constant: at most one growth of the caller's pool of sessions and of its pool of blocks |  |
| the last copy of a session goes (`session::release`: `handle_close`, the Handles stage) | with the channel open, posts the bit `CLIENT_GONE` into the session's slot as `notify` does (delivery to a waiter or enqueuing); then releases the copy's reference, and the last one puts the session on the cleanup queue | constant: as `notify`; takes no memory, the slot was allocated with the session |  |
| a session chunk (`session::clean`) | returns the session's slot to the channel's limit and the object's slot to the payer's pool of sessions (nothing goes back to the quota), and releases the references to the channel and to the payer's shell | constant |  |
| `thread_interrupt` | checks a thread handle with MANAGE; withdraws its current send or receive and wakes the live thread with Interrupted under the scheduler lock, BAD_STATE for a thread that waits for the reply to an accepted request; after the lock releases its wait reference and up to four queued transfer handles at the caller's effective priority | constant: one lookup, one queue removal, one wake and at most four handle releases; closing a session can post CLIENT_GONE as above | 1,655 (test build): a thread in `send` through the last copy of a session with four handles in transit, each the last copy of a session whose receiver waits |
| `thread_upcall_bind/control` | changes current-thread registration, mask, nested entry deferral or entry bookkeeping; checks the bound address and active-handler state, and rejects an unbalanced deferral | constant; no allocation or scan | 94 and 112 (test build): a bind; the longer of Enable and Take |
| `thread_upcall_request` | checks MANAGE, target lifecycle and registration; sets pending; an enabled thread waiting in send or receive follows the thread_interrupt path, one waiting for a reply keeps its wait | constant plus the same bounded wait/transit releases as thread_interrupt | 1,673 (test build): a thread in `send` as in the `thread_interrupt` row, its entry enabled; 270 for one waiting in `receive` |
| `thread_upcall_return` | validates mode/flags, PC/SP and the retained buffer pointer before restoring 31 GPRs, system state and 528 FP/SIMD bytes from a fixed reserved buffer area; retains original x0 | constant: 816 bytes, with no user pointer dereference or allocation | 999 (test build) |
| `thread_exit` | unmaps the message-buffer page, flushing its TLB entry, and returns the frame (a running thread carries no handles of a request); gives the thread's number back; removes the thread from the process's list; the last running thread terminates the process, as in the process termination row; otherwise a thread made with an exit channel (`thread_create` `x7`) posts bit 0 into its slot at `x8` as `notify` does, once it left the scheduler, and the queued slot holds the thread | constant: process termination is too | 483 (test build, `thread exit notice`): a thread whose end wakes a receiver of its process waiting on the exit channel |
| `clock_now` | reads the counter and turns ticks into nanoseconds, rounded down | constant: one 64-by-64-bit multiplication and a shift (`abi::time::Scale`) | 293 |
| `timer_create` | checks the room in the caller's table (spec 11), the caller's 192 timers (`abi::MAX_TIMERS`) and the system's 8,192 (`abi::MAX_SYSTEM_TIMERS`, one count), takes one of the channel's 1024 slots, then a slot in the caller's pool of timers (the pool growth row), and inserts the handle | constant: at most one growth of the caller's pool of timers and of its pool of blocks; the timer is not armed |  |
| `timer_set` | on a closed channel returns `PEER_CLOSED` and changes nothing; otherwise turns the deadline into ticks by `abi::time::Scale` (an estimate and at most two steps up for counters up to 1 GHz, three for deadlines past 2^62 ns, about hz / 10^9 + 2 for a faster counter), takes an armed timer off the heap of its level, then posts bit 0 at once for a deadline the counter reached, as `notify` does, or puts the timer into that heap; the nearest deadline is walked again when the top of the level changed | O(log n): a removal and an insertion, or a removal and a post of O(1); and a walk of 63 levels | 2,122 (test build): the top of a heap of 8,130, the system's 8,192 timers (`abi::MAX_SYSTEM_TIMERS`) in all, moved before every other timer, among 63 levels with timers |
| `timer_cancel` | takes an armed timer off the heap of its level, and walks the levels when its top changed; bits it posted stay in its slot | O(log n), at most 13 steps with the system's 8,192 timers, and a walk of 63 levels | 2,690 (test build, `timers_8192`): the root of a heap of 8,130, the system's 8,192 timers in all, whose place the last node takes |
| the last reference to a timer (`timer::release`: `handle_close`, the Handles stage, or `receive` or the Close stage that took its slot) | marks the timer dying and puts it at the tail of the cleanup queue at the level of the cause; it stays in the heap of its level until its chunk or a chunk of firings takes it off | constant |  |
| a timer chunk (`timer::clean`) | takes the timer off the heap of its level if it is armed, returns its slot to the channel's limit and its place to its payer's pool of timers (nothing goes back to the quota), and releases the references to the channel and to the payer's shell | O(log n) for the heap and a walk of 63 levels, the rest constant |  |
| `irq_bind` | checks the line, the priority and the flags, the two handles, the caller's ceiling, the line's entry of the table of bindings and the channel's state, then the room in the caller's table (spec 11), takes one of the channel's 1024 slots and a place in the caller's pool of bindings (the pool growth row), writes the entry, the line's bit of `GICD_ICFGR` and its bit of `GICD_ISENABLER`, and inserts the handle | constant: at most one growth of the caller's pool of bindings and of its pool of blocks | 693 (test build): the first entry, the pool of bindings taking a page |
| `irq_ack` | on a closed channel returns `PEER_CLOSED`; opens a line a delivery masked (`GICD_ISENABLER`) | constant | 126 (test build): a masked line |
| an interrupt of a bound line (`interrupt::handle`, `irq::deliver`, before the EOI) | looks the line up in the table of bindings; a line masked already gets nothing more; otherwise masks the line (`GICD_ICENABLER`) and posts bit 0 into the binding's slot at the slot's priority, as `notify` does: the top waiting receiver gets it, or the slot goes into the channel's queue and holds the binding; a closed channel gets nothing | constant: a table read, a write to the distributor (on a GICv3 and the wait for its `RWP`, at most 1 000 000 polls), as `notify` | 687 (test build): from the `svc` that makes the line pending to the first instruction of the driver it wakes, the acknowledgement, the post, the decision and the switch included |
| an interrupt of a line no binding holds (`interrupt::handle`) | masks the line and ends the interrupt | constant: a table read and a write to the distributor (on a GICv3 and the wait for its `RWP`, at most 1 000 000 polls) |  |
| the last handle to a binding (`irq::release_handle`: `handle_close`, the Handles stage, or a message dropped with it) | masks the line and frees its entry of the table of bindings, so that `irq_bind` of the line succeeds from then on, though a notification of the binding may still wait in the channel's queue | constant |  |
| the last reference to a binding (`irq::release`: the last handle, or `receive` or the Close stage that took its slot) | puts the binding at the tail of the cleanup queue at the level of the cause | constant |  |
| a binding chunk (`irq::clean`) | returns its slot to the channel's limit and its place to its payer's pool of bindings (nothing goes back to the quota), and releases the references to the channel and to the payer's shell | constant | 252 (test build) |
| a teardown that a thread at a high level starts (`process_kill`, the last handle to a big process or to a channel with many waiters) | runs at the level of its cause (spec 7.7), the Close and Replies stages at the higher of the cause and their top waiter: the chunks of the whole teardown follow one another at that level, with interrupt polls between them, and no thread at or below that level runs until they end | each chunk as in its row; in all, the sum of the object's chunks | no single number since stage 3, which took the end into chunks: the call part, 350 (`end_call`), then the Threads chunks at S, the longest 13,213 (`threads_ready`), then the chunks of the later stages, each at most B (the rows above); in stage 1.3c, when the call stopped the threads, `process_kill` of a child with 64 threads that never ran took 42,961 with its whole teardown; closing a channel with 60 waiting receivers is no single path: two chunks of the Close stage at their level, the longer 3,844 (test build), then each of the 60 receivers it wakes runs above the closer and exits on its own, about 1,100 instructions each |
| B, the blocking time of any thread, level 63 included (spec 15.3) | the longest row above, which a pending interrupt waits for; firings of timers are chunks of their levels, and no series of them blocks a higher level | the longest row | 20,538 under -icount (test build) since process suspension (20,536 after stage 3): a Handles chunk of 64 last copies of sessions each waking a receiver (42,539 after the cleanup of audit 3, the end of a process with 128 threads waiting in `send` through the last copies of sessions, until the Threads stage took that end into chunks); of the chunks, 20,536, a Handles chunk of 64 last copies of sessions each waking a receiver, then 20,079, a Buffers chunk whose 11 frames each merge up to the highest order and whose 42 handles each wake a receiver (20,069 after stage 1.3 by the out-of-tree measurement after stage 1.3), and 19,354, a Buffers chunk of 32 frames; printing costs nothing there; B does not grow with the number of timers, bindings, slots or threads of an ending process; the longest Threads chunk is 13,213; on hardware `debug_write` and the fault line are longer (their rows); a chunk of firings, 13,276 since the timer heap of 8,192 timers (depth 13), stays below it |

## Process suspension

`process_control` (call 36, MANAGE) sets or clears the process flag in O(1).
Every selected suspended thread parks before EL0, including fast `send`;
the exit loop polls interrupts again after that single thread. A continuation
uses the process's cleanup item and returns at most 64 parked threads to
the tails of their current levels with fresh quanta. A new stop cancels the
queued work, and process termination gives the same item to the Threads stage.
The scheduler link holds the parked ring; priority changes and IPC inheritance
change its level while it stays in that ring. No new object is allocated.

The 128-thread measurement uses 64 threads per portion over all 63 legal
levels, with one repeat. `kernel-test 512M icount` measures the scoped
components below. The control scopes call `process::control` directly and
exclude syscall validation, exception entry and EL0 return. The parking
scope locks the scheduler, calls `pick` and then `park_selected`; the
surrounding exit-loop poll and decision setup are excluded. The first
stop has no queued continuation. A separate stop cancels the remaining
queued portion and releases its process reference.

The continuation stays below B=20,538. The previous B=20,536 grew by two
instructions in the Handles chunk when the process-cleanup dispatch
acquired its continuation case. The process shell is 1264 bytes and keeps
three slots per pool page. The normal build reports null=262, clock=315,
yield=380, notify=1018, round_trip=2004 ticks in `init-test 512M icount`
after the EL0 gate. The base commit reports 254, 310, 375, 1010 and 1993;
the increases are 8, 5, 5, 8 and 11 ticks, respectively.

| Operation | Measured scope | Instructions under -icount |
|---|---|---|
| first stop, 128 threads | internal `process::control`, no queued continuation | 33 |
| stop with a queued continuation | internal `process::control`, item removal and queue reference release | 99 |
| select and park one suspended thread | locked `pick` + `park_selected` test scope | 80 |
| continue, 128 threads | internal `process::control`, flag write and enqueue | 96 |
| continuation portion | `cleanup::portion`, 64 removals and ready inserts over levels 1–63 | 3731 |

These readings cover the specified test scopes. The complete exception
entry, syscall or exit-loop interval requires its own measurement boundaries.

## Steps of the process service

The rows above bound what a pending interrupt waits for. A step of a
service is user-space work at the service's level, and a request that waits
for the service waits for the steps ahead of it. `cargo xtask
process-steps` (4 branches in `ci`) measures them under -icount with a
crowd of children from files (the same ticks as B; `rt` feature
`step-stats` and the process service's feature `steps` in that image
only, and the RAM file service's feature `steps`; the clock service is the shipping one). The longest
step of each kind, with 32, 128 and 248 children:

| Step | 32 | 128 | 248 |
|---|---|---|---|
| SpawnStart | 87,579 | 87,784 | 87,950 |
| Create | 59,806 | 59,806 | 59,605 |
| ExecStart | 46,721 | 47,001 | 47,402 |
| a notification (an end, a step of the walk of `kill(-1)`) | up to 11,768 | up to 11,768 | up to 11,768 |
| WaitStart, WaitTake | 6,432, 7,141 | 6,634, 7,122 | 7,518, 7,137 |
| Boot, Take | 6,853, 4,917 | 7,241, 5,128 | 6,882, 5,439 |
| ExecCommit, SpawnCommit | 4,200, 2,610 | 4,200, 2,222 | 4,360, 2,588 |
| ForkStart, ForkCommit | | | 50,596, 2,296 |
| Vouch | 2,837 | 2,837 | 2,798 |
| Kill (one step of its walk) | 1,204 | 1,204 | 1,188 |

The `fork` rows come from the same probe with a forking child among the
248 (role `stepfork`: five forks of a parent whose heap grew by 128 KiB).
ForkStart makes a process in the kernel as SpawnStart does but starts no
loader program from a file, so it stays within SpawnStart (50,596 against
89,344 in that run; `process-steps` fails when it does not) and does not
grow with the processes either; ForkCommit is a constant 2,296 ticks.
ForkAbort has no row: no probe takes the path in this crowd.

No step grows with the number of processes. Vouch reads the label of the
copy it was given from the kernel (`object_info` LABEL, the row of
`object_info` above) and takes nothing off the identity channel; the ends
of identity sessions and the notifications through them go to a thread of
the service of their own, one `receive` each, at the loop's level, so no
step of the loop empties that channel (until step 5c's fix wave, Vouch,
SpawnStart, ExecStart and Create did, 539 ticks an entry: a Vouch with 252
entries took 140,188 ticks, about 279,000 extrapolated to 510). The end of
a process walks the children of its record, 32 at most: the notification
row grows with them and stops at 11,768 ticks, the walk of a record with 32 children. SpawnStart, Create and ExecStart are
fixed costs above B: they make a process in the kernel, a call at a time
(its space, the record's page, the loader's code, data and stack and its
thread), each call bounded on its own. `process-steps` fails when the
longest Vouch passes 6,000 ticks. Details are in
[notes/m5c-spawn-exec.md](../notes/m5c-spawn-exec.md).

A thread below the service's level waits for at most one step that has
begun, whatever the thread asks of the service (the ceiling protocol), so
the longest step is a blocking time for every thread below level 52: 87,950
ticks, 4.3 times B, and it does not grow with the number of processes.
Nothing of real time runs below level 52 yet; SpawnStart, ExecStart,
ForkStart and Create are to be split into steps no longer than B before
step 5h.

### The loader's copy of a `fork`

The copy runs in the child's loader at the level of the forking thread, so
a thread above that level preempts it and no step of the process service
lasts through it. What the kernel sees of it is calls: `mem_create` of the
group's whole length (zeroing in portions of 8 pages, `CREATE_PORTION`),
`mem_map` of the new object, `mem_map` of the parent's object by pieces of
4 MiB (portions of 32 pages), a `memcpy` through the window, `mem_unmap`
of each piece, and a remap with the segment's access for code and read-only
data (portions of 8 pages with the instruction cache cleaned). A call
takes ticks in proportion to the pages it covers and is preemptible between
its portions, and a portion is one of the rows above (the memory portions
are at most B). `process-steps` boots the loader with its feature `steps`:
a loader that finished a copy prints the longest of each kind of its steps
through the console the service gave the program. The longest of each kind
in the run above (the copy of 70 pages, 286,720 bytes, in the largest
group; the loader's printing and the timing are in the feature alone):

| Step | Ticks | Pages or detail |
|---|---|---|
| `mem_create` of a group | 80,108 | 82 pages (about 977 a page, 7,800 for a portion of 8) |
| `mem_map` of the new object, writable | 13,078 | 82 pages |
| `mem_map` of a piece of the parent's object | 10,308 | 70 pages (147 a page, 4,700 for a portion of 32) |
| `memcpy` of a piece | 143,797 | 286,720 bytes, user code at the forking level |
| `mem_unmap` of a piece | 4,414 | 70 pages |
| remap of code or read-only data with its access | 55,102 | 70 pages (`mem_unmap` and `mem_map` with the cache clean) |
| `handle_duplicate` of the new object | 457 | constant |
| Regions (the parent's handles into the loader's scratch) | 2,719 | 4 handles |
| Go, the whole copy | 858,824 | 8 regions |

Each call is bounded in portions and the copy of a piece is user code, so
no row adds a path to the table above and B stays 20,536. A parent with
8 MiB of heap makes the same calls over more pages: 623 us p50 on HVF in
`rtbench` against 102 us for a small parent (S15). Details are in
[notes/m5d-fork.md](../notes/m5d-fork.md).

### The RAM file service

Its steps run at level 40 with a copy in them. READ_INTO fills a memory
object of the caller from the service's read-only mapping of the boot image
(the loader reads an image in pieces of `proto_fs::READ_INTO_MAX`, 12 KiB);
the service maps the object, copies, unmaps and answers. Longest steps under
-icount with 128 children, ticks:

| Step | Ticks |
|---|---|
| ReadInto, 12 KiB | 18,212 |
| OpenExec (path lookup, the Vouch round trip, the set-ID message) | 28,241 |
| Clone | 17,437 (a fork's, with the descriptions of the table; 10,659 for a spawn's in the first run) |
| ReadAt (up to 1,016 bytes) | 8,545 |
| Open | 5,488 |
| a notification | 4,424 |

One READ_INTO stays under B by its limit: at 64 KiB it took 46,982 ticks
(2.3 B) and at 16 KiB 20,407; the fixed part is about 11,600 ticks and each
KiB takes about 550. `process-steps` fails when a READ_INTO passes
20,536. The checks of a READ_INTO (descriptor 0, count within the limit,
place on a page boundary, one memory object with `MAP_READ` and `MAP_WRITE`,
room in the object) are `ramfs::read_into_valid`, with a host test that
fails when any check goes.

### The entropy service

It runs at level 36, below the services at 40, and its CLONE walks the
table of live clones (`proto_wire::clones`, 320 places), as Clone of the
clock and pipe services does: its longest step under -icount, with the
table full (`cargo xtask entropy`, role `x` of tests/entropy), is 14,398
ticks of term B 20,536. SEED is 5,623 ticks; its own step with 64 seeds
waiting for the first bytes, 8 told a step, is 10,684. Making the walks of
the clone tables O(1) in the three services is a task of its own.

### The pipe service

Its steps run at level 40, beside the RAM file service, and the service
sends requests to nobody. `cargo xtask process-steps` boots it with the
feature `steps` and the role `steppipes` of the probe makes each kind of
step at its longest: 8 waiters on each end, a Clone of 28 ends, a session
that goes with 28 ends. Longest steps under -icount, ticks, with 128 and
248 children live (term B is 20,536):

| Step | 128 | 248 |
|---|---|---|
| Clone (up to 32 ends) | 12,914 | 17,382 |
| WriteStart (a copy of one message, up to 8 notifications) | 9,047 | 9,047 |
| ReadStart | 8,625 | 8,625 |
| ReadTake | 7,211 | 7,211 |
| Close | 6,148 | 6,148 |
| Abandon (up to 16 operations) | 4,904 | 5,372 |
| own step (one description let go of, 8 wakes at most) | 3,894 | 5,682 |
| WriteTake | 3,922 | 3,922 |
| Create | 5,141 | 5,141 |
| ReadCancel, WriteCancel | 2,130, 2,175 | 2,130, 2,175 |
| Stat, GetFlags, SetFlags | 1,432, 1,360, 1,360 | 1,432, 1,360, 1,360 |
| heartbeat (a send to init and its reply) | 5,630 | 403,468 |

Every step of the service is below B, and none grows with the number of
processes: the Clone and own-step rows differ between the columns by the
spread of the volleys of the crowd (they interleave with the step in
progress), and `process-steps` fails when any of them passes 20,536. Clone has the least
margin: 17,382 ticks with 248 children, 85 % of B, since it goes through
the 320 places of the births and of the clones; it is the first to split
when the tables grow (with the steps of the process service, 5h). The
heartbeat is the loop's wait for init's reply, in which processes of higher
levels run (the volley of 248 children); it is no work of the service, and
the check bounds it at 500,000 ticks apart from B. A thread below level 40
waits for at most one step of the service's own work that has begun; the
wait for init's reply goes to threads above the client's level, so it adds
nothing to the client's delay. No step allocates memory: the
rings, the descriptions, the sessions and the waiters live in the
service's `.bss`. The kernel did not change, and B stays 20,536. Details
are in [notes/m5e-pipes.md](../notes/m5e-pipes.md).

### Terminal control with live clients

`cargo xtask posix-tty-control-steps` uses a PTY in memory and sixteen live
clients of the terminal service. The quiet feature collects the full
service interval from the return of receive through reply and dispatch;
decode, identity checks and synchronous process-service requests are
included. All five snapshots are read before any measurement is printed.
The diagnostic group-scan print is disabled by this quiet feature.

There are two phases. Fifteen existing members stay alive for the
leader's first Acquire. The accepted late-attach rule keeps their absent
personal controlling-terminal pair; the probe checks that result.
After they are reaped, fifteen new members inherit the pair and exercise
SetPgrp, GetPgrp, GetSid and Controlling while all sixteen clients remain
alive. Pipe gates keep at most eight waiting readers per pipe. The
maxima persist across both phases. The C probe uses `-fno-builtin`.

On integrated wiring `11275b9`, all complete intervals remain below B=20,538:

| Terminal method | Full interval under -icount |
|---|---:|
| Acquire (16) | 7,410 |
| SetPgrp (17) | 3,506 |
| GetPgrp (18) | 3,440 |
| GetSid (19) | 9,600 |
| Controlling (20) | 3,389 |

Omitting Controlling deliberately produces a zero snapshot and fails the
probe. The restored probe passes. Its log is
`target/measure/posix-tty-control-steps.log`; the command is a CI gate.

### PTY inheritance at the session limit

`cargo xtask posix-pty-steps` holds 32 real slave descriptions and fills a
root's 255 clone places with the initial child and 254 further sessions.
It checks the limit, releases one place, then performs a real fork and
checks all 32 descriptors in the grandchild. After retirement completes,
it snapshots Clone (7) and the service's own step (65) before printing.
The measured interval includes receive return, dispatch, identity checks
and reply, with B fixed at 20,538 and no overhead subtracted.

On the implementation accepted at `76fa4b2`, Clone takes at most 17,670
and the own step 7,138 ticks. Exact ID selection checks the complete
generation and side, deduplicates selected slots, and preserves request
order. Clone reservation counts the root and finds its first free place
in one pass. Retired descriptions close one per step; each cleanup phase
finishes its step before UART work starts.

### Terminal latency scenarios

`cargo xtask rtbench --short` checks the complete terminal scenarios on
TCG; `cargo xtask rtbench --minutes 10` measures them on HVF and VZ.
Existing entropy rows S23–S25 remain. The added rows are:

| Scenario | Measured interval |
|---|---|
| S26 PTY echo | writing a byte to the master through reading its echo; the slave consumes and checks the same byte outside the sample |
| S27 Ctrl-C idle/busy25 | master write through the first counter read in the foreground child's signal handler, with an optional busy thread at 25 |
| S28 STOP/CONT 128 | kill through the verified wait report; 127 native workers plus the child main fill the kernel limit, and every worker executes an acknowledgement after CONT outside the sample |
| S29 pipe poll | the lower-priority writer's timestamp before write through the higher-priority reader's return from poll; the byte and POLLIN are checked |

The parser requires all six terminal histograms and the exact 128-thread
readiness record. Replacing each WatchTake notification session makes
S29 fail; omitting the native worker notices makes S28 fail. Hardware
rows retain n, minimum, p50, p99, maximum and the full histogram in
`target/measure/rtbench-hvf.txt` and `rtbench-vz.txt`.
