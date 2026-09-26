# Non-preemptible kernel paths

Interrupts are masked inside the kernel (spec 8.1), so each path below
entirely counts toward the blocking time of any thread, even the
highest-priority one. The table collects such paths with a work estimate
for response-time analysis (spec 15.3). A path whose work grows with the
size of an object is split into chunks with a resume point inside the
object and polling for pending interrupts between chunks
(`arch::irq_pending`, spec 7.7). As of stage 1.3a, the last reference only
puts the object on the cleanup queue, process termination only stops its
threads and puts it on the queue, and the kernel-exit loop
(`sched::resume`) does one chunk between two interrupt polls. A process is
torn down in stages; progress (stage, number of remaining table chunks,
page-table walk path) is stored in the process itself, and a process with
work left goes to the head of its level after a chunk. From part 1.3b on,
teardown runs in two waves: the Stop stage terminates the children, one a
chunk, at level S (the greater of the process's ceiling and the teardown
level R), and the other stages run at R. Levels between R and S get a
one-time interference of at most N x C_stop, N being the number of
descendants (at most Q / 8 KB) and C_stop the longest chunk of the Stop
stage (it counts in `x5`); levels above S see one chunk. Descendants are
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
chunks. A handle's label lives in a session object (spec 5.3): when the
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
lives. A process has at most 64 mappings, in one block of its pool of
blocks, and a check of a range walks them and the message buffers of its
threads, at most 64 each. `mem_map` charges the process whose space it is
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
handles a chunk, and the Shell stage 32 pages; a thread goes into a chunk
of the Buffers stage only when its units fit, so that a chunk does at
most 64 units. The chunks that give frames back are measured with each
frame alone in its free block of 4 MiB, which it merges back up to. The
Buffers chunk is measured with the threads whose units fill it with the
most handles: eleven threads, ten with four handles on their way and one
with two, each handle the last copy of a session whose receiver waits.

The last column holds instruction counts of the kernel built at
opt-level 2 (spec 14), measured at the end of parts 1.3c and 1.3d in QEMU
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
under -icount, whose hooks cost a few dozen instructions more a call: the
kernel test `ipc_round_trip_is_measured` prints the round trip of a
request there, `ipc round trip ticks: null=304 switch=637 fast=2285
slow=2478 buffer=3364 handles=4784`: an empty call, one switch between
threads of two processes (half of a yield there and back), and a request
answered by a service of another process that waits in `receive`: on the
fast path, with the fast path off, with 1024 bytes each way, and with four
handles each way. The lower bound of a round trip, two switches and one
empty call, is 1578 there; the fast path saves 193, and the two copies of
960 bytes cost 886. The chunks of the stages that release handles are
measured at the costliest unit, where the last copy of a session wakes a
receiver of its own channel with `CLIENT_GONE`. The kernel test
`memory_portions_are_measured` prints the longest entries of the long
calls of memory objects in their worst cases there (spec 15.3), each from
the kernel's dispatch of the call to its end with an interrupt pending all
along, so that an entry takes one chunk: `memory portions ticks:
create=19118 map=5632 map_exec=8028 unmap=2770 protect=2869
protect_exec=6338 release=16179 first_map=13844`. On the `cortex-a53`,
whose instruction cache the kernel flushes whole, `map_exec` is 5,845,
`protect_exec` 4,190 and `first_map` 11,786. Allocations are measured
with free blocks of lower orders at hand; with only blocks of the highest
order free, the first entry of `mem_create` is 19,300. The Shell stage of
the test build also fills each page it gives back with poison; its count
here is without the poison, as in the normal build. The kernel test
`timer_firing_is_measured` prints the timers of programs in their worst
cases there (spec 15.3), `timer portions ticks: interrupt=4388 fire=12773
set=2241`: the timers' part of an interrupt that finds the tops of all 63
levels expired, a chunk of firings that takes 16 timers off a heap of
4,096 of one level, each waking a receiver of its own channel, and
`timer_set` of the top of that heap to a deadline before every other,
among 63 levels with timers.

| Path | What it does | Estimate | Instructions under -icount |
|---|---|---|---|
| entry and exit (`vectors.S`, `handle_exception`, `sched::resume`, `thread::run`) | saves the thread's registers, decodes ESR and the call number, writes the result, polls for pending interrupts, decides who runs, and returns to EL0; every entry pays it, an interrupt too | constant | 239: call 0 from EL0, which fails with `INVALID_ARGS` |
| `AddressSpace::retire` and `SpaceRelease::step` | `retire` moves `TTBR0` off the tables and drops their TLB entries together with the ASID (`tlbi aside1is`); a step reads up to 512 words of one level 0-2 table and returns at most one table to the allocator, the root last | constant: `retire`; a step: up to 512 reads and one table; `AddressSpace::destroy` (tests, and `process::create` that ran out of pool space, with a single root table) does all steps back to back |  |
| issuing an ASID (`tlb::switch_to`, `AsidAllocator::activate`) | looks for a free number in the generation map; runs on every `thread::run` into a process whose space has no ASID of the current generation: the space's first run and the first run after a generation change | constant: up to 1024 map words with 16-bit ASIDs, up to 4 with 8-bit |  |
| ASID generation change (`tlb::switch_to`) | when no free numbers are left: zeroes the number map (8 KB), flushes the TLB (`tlbi vmalle1`), then issues a number as in the row above | constant: zeroing 8 KB, a TLB flush, and issuing a number |  |
| loading `init` at startup (`init::load`, `memory::create_whole`, `process::map_whole`) | each segment and the stack go into a memory object of their own, made whole with every chunk of `mem_create` in a row, the bytes of the file copied into its frames through the linear map, and mapped with every chunk of `mem_map` in a row | the size of `init`'s program and stack, with interrupts masked; only at startup, before the scheduler runs, and in the kernel's tests |  |
| `arch::cache::sync_icache_frames` | `dc cvau` and `ic ivau` over the cache lines of whole frames through the linear map, with one set of barriers; on a VIPT instruction cache (A53), a flush of the whole instruction cache (`ic ialluis`) instead of `ic ivau` | frames / line size; a chunk of an executable mapping: 8 pages |  |
| FP/SIMD switch in `thread::run` | saves the outgoing thread's registers and loads the incoming thread's (528 bytes each) | constant: 1056 bytes |  |
| `debug_write` | writes up to 64 bytes to the PL011 synchronously, waiting for room in the transmit queue; inserts a CR before every LF | up to 128 characters: on hardware at 115,200 baud and 10 bits per character, about 11 ms; instant in QEMU; in 1.2c only `init` holds the `DEBUG` right |  |
| `object_info` | reads process fields (state, quota count, three handle-table numbers), a memory object's size, pages and mappings, or kernel counters for `KERNEL_STATS`: the scheduler's and frame allocator's under their locks, the queue length and the longest chunk under the queue lock taken twice, and the atomic pool page counter | constant: for `KERNEL_STATS`, four lock acquisitions, one at a time |  |
| the last reference to an object (`object::release`, `process::release`, `thread::release`, `memory::release`) | puts the object at the tail of the cleanup queue at the level of the cause: the effective priority of the thread whose call or fault released the reference, or the level of the object whose chunk released it; a live process is terminated in the process, as in the process termination row, without threads | constant: insertion at the tail of a level and a mask bit; no nested teardown |  |
| pool growth (`kcore::slab::PaidPages`: the payer's pools of threads, blocks (the chunks and the directory of its handle table, and the table of its mappings), child shells, channels, sessions, timers, and memory objects) | only when the pool has no free slot: charges a page against the payer's quota, takes an order-0 frame, and lays the page out into slots; when the entries of the payer's page log have run out, first takes a list page the same way | constant: up to two charges and two order-0 frames (each at most `MAX_ORDER` = 10 splits in `FRAMES`) and laying a page out into slots; freeing a slot is O(1) and does not call the allocator |  |
| a chunk of the Stop stage (`process::clean`, `stop_child`) | the child at the `stop_next` cursor: if it is alive, terminating it as killed at level R (the process termination row); the cursor moves on; the process goes to the head of level S, and after the last child moves on to the Replies stage | up to 64 of the child's threads at O(1) each and up to three O(1) queue operations beyond the enqueues done by the released thread references; no longer than the former Children chunk |  |
| a chunk of the Replies stage (`process::clean`, `wake_clients`) | up to 32 clients of the top level of the queue of requests the process's threads accepted, under one hold of the scheduler's lock: each leaves the queue and gets `PEER_CLOSED` in `x0`, and goes to the tail of its level with a new quantum; with clients left, the process goes to the head of the higher of R and their new top level, otherwise on to the Children stage at the head of level R; with no client, one chunk that only moves on. The stage stands at the higher of R and the top client | up to 32 clients at O(1) each | 2,686 (test build): 32 clients |
| a chunk of the Children stage (`process::clean`) | the first child in the list, terminated by the Stop stage: the process goes to the head of level R, and the child to the head of its stage's level right before it (`process::hasten`) | constant: an insertion at the head and a raise |  |
| `process::hasten` (the Children stage, `process_kill` of a terminated process) | R grows to the level of the call; a process in its stages goes to the head of its stage's level (`cleanup::raise`); a shell has nothing to raise | constant: a removal from a list and an insertion at the head |  |
| a chunk of the Handles stage (`process::clean`) | `HandleTable::release_step`: one table chunk; each entry's object is released in O(1): the last copy of a session posts `CLIENT_GONE` as `notify` does, and the last handle with `RECEIVE` closes its channel; the chunk directory goes with the last chunk | up to 64 entries, each no costlier than `notify` | 19,318 (test build): 63 last copies of sessions, each `CLIENT_GONE` waking a receiver of its own channel; 8,166 when nobody waits |
| a chunk of the Space stage (`process::clean`) | the first chunk takes the space away from the process and does `AddressSpace::retire`; each following one does `SpaceRelease::step` | see the `AddressSpace::retire` row |  |
| a chunk of the Buffers stage (`process::clean`) | returns the message-buffer frames of threads stopped by termination, releases the handles of the requests of those that waited in `send`, up to 4 each, as `handle_close` does (the last copy of a session posts `CLIENT_GONE` as `notify` does), and what a long call a thread was making held: the object of a `mem_create`, whose last reference puts it on the cleanup queue, or a mapping a change left midway, which keeps what its chunks did; and removes the threads from the process's list; 64 units of work a chunk, a frame two and each handle or object one more, a thread going into a chunk only when its units fit, so the frames of 32 threads with no handles take one chunk | up to 32 frames, each through merging free blocks in `FRAMES` up to the highest order and returning the frame to the quota, and with handles up to 64 units, since a thread goes into a chunk only when its units fit, each handle no costlier than `notify`: of the rows measured under -icount, the longest teardown chunk, costlier than the Handles stage (64 entries at O(1)); the first measurement on hardware should record which stage set the longest time (the `KERNEL_STATS` kind in `x5`), so the limit of 64 units in Buffers is tuned separately from the handle-table chunk size | 19,354 (test build): 32 frames, each merging up to the highest order; 19,749 (test build): 11 frames, each merging up to the highest order, and 42 handles, each the last copy of a session whose `CLIENT_GONE` wakes a receiver |
| a chunk of the Mappings stage (`process::clean`, `maps::release_all`) | every mapping of the process's table, busy or not, leaves it and releases its memory object, whose last reference puts it on the cleanup queue; the block of the table goes back to the pool of blocks | up to 64 mappings at O(1) each | 4,221 (test build): 64 mappings, 62 of them the last references to their objects |
| a chunk of the Quota stage (`process::clean`) | returns the free part of the quota to the parent (`Account::return_free`) and removes the process from the parent's list of children | constant |  |
| a chunk of the Notify stage (`process::clean`, `notify_exit`) | if the process has an exit channel, posts bit 0 into the slot in its shell as `notify` does: delivery to a waiting receiver, or enqueuing in the channel's queue, where the slot holds the shell; a closed channel gets nothing | constant: as `notify` |  |
| a chunk of the Shell stage (`process::clean`) | `PageLog::release_step`: up to 32 pages of the process's pools and of its log go back to the allocator, each returned to the quota (the test build first fills the page with poison); the last chunk returns the shell's slot to the parent's pool, the slot in the exit channel's limit and the reference to that channel, and the rest of the quota to the parent (`Account::return_rest`), and releases the reference to the parent's shell (the last one enqueues it) | up to 32 frames, each through merging free blocks in `FRAMES` up to the highest order; in the test build, also writing 4096 bytes of poison per frame; the rest is constant | 16,087 (test build without its poison): 32 pages, each merging up to the highest order |
| the last channel handle with `RECEIVE` (`channel::release`: `handle_close`, the Handles stage) | marks the channel closed; if threads wait in it or slots stand in it, puts the channel at the tail of the cleanup queue at the higher of the level of the cause and the top level of its queue, with the queue's reference (the Close stage) | constant: checking the queue's mask and one enqueue |  |
| a chunk of the Close stage (`channel::clean`) | heads of the top level of the channel's queue, 32 units of work (below), each under its own hold of the scheduler's lock: the threads waiting in `receive` or in `send`, each of which gets `PEER_CLOSED` in `x0`, goes to the tail of its level with a new quantum, and lets go of what its wait held, the channel or a copy of a session (the last copy posts `CLIENT_GONE`, which a closed channel refuses), and a sender of the handles of its request, up to 4, each released as `handle_close` does; or the slots, each emptied and letting go of its owner after the lock (a session with no copies goes on the cleanup queue); what the heads held goes at the level of the cause; with heads left, the channel goes to the head of the higher of the cause and their new top level, otherwise the queue's reference goes | 32 units of work: a head one, and each handle of a sender's request one more, no costlier than `notify`; up to 32 heads at O(1) each and 34 holds of the lock, or fewer heads with their handles, up to 36 units | 3,675: 32 receivers; 9,894 (test build): 7 senders with 28 handles, each the last copy of a session whose `CLIENT_GONE` wakes a receiver; 5,581 when nobody waits, with the copies of the sessions the requests went through |
| a chunk of the channel shell (`channel::clean`) | returns the channel's slot to the payer's pool of channels (nothing goes back to the quota) and releases the reference to the payer's shell | constant |  |
| a thread-cleanup chunk (`thread::clean`) | unmaps the message-buffer page if it is still there, with the handles of a request the thread made, up to 4, released as `handle_close` does, and what a long call it was making held: the object of a `mem_create`, or, for a change of a mapping, the mapping keeps what the chunks did and the rest of the prepaid tables goes back (`process::abandon_change`); gives the number of a thread that never started back to the table of thread numbers (its count stays, and an entry at the end of its count retires), removes the thread from the process's list, returns the slot to the process's pool of threads (nothing goes back to the quota), and releases the reference to the process | constant: up to 4 handles, each no costlier than `notify` |  |
| the kernel-exit loop (`sched::resume`) | on the empty kernel stack: polling `ISR_EL1.I`, acknowledging and handling an interrupt, a scheduling decision, then a thread, one cleanup chunk, or `wfi` | constant without a chunk; at most one chunk between two interrupt polls, and a chunk only starts with no interrupt pending, so the blocking time of any thread gains the longest chunk, of cleanup or of a long call (the kernel measures both and returns the longest in `x5` of the `KERNEL_STATS` kind from `object_info`) |  |
| a scheduler decision (`sched::resume` and the events `sched::{start, exit, yield_running, set_priority, timer_fired}`) | `kcore::sched` operations: inserting at the head or tail of a level, removing from a ring, picking a level from the mask via `clz` with the cleanup queue's level at the top on entry, the timer deadline; `sched::exit` of a waiting thread first takes its slot off the channel's queue, or off the queue of accepted requests of the process that took its request and marks its entry of the table of thread numbers, gives the thread's number back, and lets go of what the wait held after the lock (the last copy of a session posts `CLIENT_GONE` as `notify` does); `set_priority` of a waiting thread moves its slot within that queue, and after the lock raises a channel at its Close stage or a process at its Replies stage to its new top waiter (`cleanup::raise`) | constant, independent of the number of threads; `sched::exit` with the last reference to a thread or to a channel puts it on the cleanup queue |  |
| a timer write (`Armed::set`, `sched::timer_fired`) | `CNTV_CVAL_EL0` and `CNTV_CTL_EL0`, then `isb`, only when the needed deadline changed: the nearer of the end of the running round-robin thread's quantum and the nearest deadline of the levels of timers whose firing is not queued, which `sched::decide` reads in O(1) before it takes the scheduler's lock; returning to the same thread leaves the timer untouched; a timer interrupt disarms it until EOI | constant: three system-register writes and two `isb`s per deadline |  |
| the timers' part of the timer interrupt (`timer::expire` in `sched::timer_fired`, before the EOI) | walks the levels that have timers and whose firing is not queued, marks those whose top expired as queued and finds the nearest deadline of the rest in the same walk, and puts the item of each expired level at the tail of its level of the cleanup queue; no timer leaves its heap | constant: a walk of up to 63 levels and 63 enqueues | 4,388 (test build): all 63 levels expired |
| a chunk of firings (`timer::fire`) | reads the counter once; up to 16 timers of the item's level that expired by then leave its heap, the earliest first, each under its own hold of the lock of the timers; each that is not dying posts bit 0 into its slot at that level, as `notify` does: the top waiting receiver gets it, or the slot goes into the channel's queue and holds its timer; a dying timer posts nothing; with expired timers left the item goes back to the head of its level, otherwise the level settles and the nearest deadline is walked again; the chunk's time goes into `x8` of `KERNEL_STATS` | 16 steps of O(log n), 16 posts of O(1) and a walk of 63 levels | 12,773 (test build): 16 timers off a heap of 4,096, each waking a receiver of its own channel |
| process termination (`process::end`: `process_kill`, `process_exit`, the last running thread exiting, a fault at EL0) | removes every not-yet-dead thread of the process from the scheduler (the kernel reference goes, and the thread may land on the cleanup queue), then puts the process at the tail of the cleanup queue with the queue's reference: at level S if it has children (the Stop stage), otherwise at the level of the Replies stage, the higher of R and the top client of the requests its threads accepted; R is at least the cause and the priority of the exit notification (`x4` of `process_create`) | up to 64 threads (`abi::MAX_THREADS`) at O(1) each, plus one enqueue; a thread that waits in `send` lets go the copy of the session its request went through, whose last copy posts `CLIENT_GONE` as `notify` does; the shells of already-exited threads are not in the list; the rest, including terminating descendants, is done by the teardown stages; `process_kill` of a terminated process calls `process::hasten` instead | 15,918 (test build): 64 threads waiting in `send`, each through the last copy of its session |
| a fault at EL0 (`exceptions::user_fault`) | prints one cause line to the port synchronously, then process termination | up to 110 characters: on hardware at 115,200 baud, about 9.5 ms; instant in QEMU; no rights needed, any program can cause a fault; in 1.4 printing moves to the UART driver; for `init` this is followed by the program's registers (up to 900 characters), after which the machine stops; then the process termination row |  |
| `process_create` | checks that the caller's table has room for a handle (spec 11: the allocation-free limit is checked first), with `x3` takes a slot in the exit channel, then charges the child's quota against the caller's account, takes a frame for the root table of an empty address space and zeroes it, takes a slot in the caller's pool of shells (the pool growth row; a shell takes 1,384 bytes, two to a page), puts the child at the head of the caller's list of children (`adopt`), inserts into entry 0 of the child's table the start channel `x5` or a placeholder that goes at once, and inserts the child's handle into the caller's table; then the notification slot in the child's shell, and the `x5` handle leaves the caller's table | constant: zeroing 512 root words, at most one growth of the caller's pool of shells, of the child's pool of blocks, and of the caller's pool of blocks; a full caller table keeps the child from starting to build; if the handle still does not fit (out of memory for a new chunk), the child goes onto the cleanup queue, the slot in the channel comes back, and `x5` stays with the caller |  |
| `thread_create` | checks that the buffer's page lies in none of the target's mappings (up to 64) and that the caller's table has room for a handle (spec 11), then the process's number of not-yet-dead threads against the limit and the free entries of the table of thread numbers, takes a slot in the process's pool of threads (the pool growth row; a thread takes 1,152 bytes, three to a page), charges a buffer frame against the process's quota, takes a frame for the message buffer, zeroes it, maps the page into the process and writes its address into the thread's `TPIDRRO_EL0`, and takes a thread number, the first never handed out or the first given back | constant: 512 entries of 8 bytes and up to three new tables; a full caller table keeps the thread from starting to build | 3,068; 5,717 with new tables for the buffer |
| `mem_create` (`syscall::mem_create`, `memory::create`, `memory::fill`) | the first entry checks the size and the flags, makes room for the handle in the caller's table (`HandleTable::reserve`, at most one chunk), takes a place in the caller's pool of memory objects (the pool growth row), and charges the object's pages and the nodes of their list to the caller's quota at once; then chunks of up to 8 pages: a frame from the object's budget, zeroed, its address into the list of pages, and a node of the list when one is due; after a chunk that leaves pages, a pending interrupt makes the call start over at its `svc`, and the next entry goes on with the object the thread holds; the last chunk inserts the handle, or, when other threads of the process took the room meanwhile, fails with `LIMIT_REACHED` or `NO_MEMORY` and puts the object on the cleanup queue | a chunk: up to 8 frames, each zeroed (4096 bytes), and 2 nodes of the list; the first entry adds at most one chunk of the table and one page of the pool before its first chunk; the whole call is bounded only by the quota, a chunk at a time | 19,118 (test build): the first entry of a new process, with the directory and the first chunk of its table, a page of its pool of memory objects, and a chunk with the node of nodes and a leaf; 19,300 with only blocks of the highest order free; 15,753 the entries after it |
| `mem_map` (`syscall::mem_map`, `process::add_mapping`, `process::step_change`) | the first entry checks the values, the two handles, the target's life, the range against the object's size, the target's mappings and the message buffers of its threads (`process::check_free`), then takes a place among the target's 64 mappings, the block of its table at its first mapping (the pool growth row), and charges the target's quota for the most tables the range may take (`tables_bound`); the mapping goes in, busy, with a reference to the object; then chunks of up to 32 pages, 8 with execution: the frames of the object's pages from its list of pages, for executable pages the instruction cache made coherent for them, the descriptors written with tables from the prepaid charge, and one `dsb ishst`; after a chunk that leaves pages, a pending interrupt makes the call start over at its `svc`; the last chunk makes the mapping idle and gives back what the tables did not take | the first entry: up to 64 mappings, 64 threads and one block of the pool before its first chunk; a chunk: 32 pages, each two reads of the list and a walk of the tables, and up to 6 new zeroed tables when the range crosses 2 MB, 1 GB and 512 GB bounds; with execution 8 pages and `dc cvau` and `ic ivau` over them | 13,844 (test build): the first entry of the 64th mapping of a process with 64 threads, of 8 pages RX across a bound of 512 GB with no table on either side, 6 tables; 12,932 the same as the first mapping of a new process, with the block of its table; the entries after the first, across a bound of 512 GB with 3 new tables: 5,632 with 32 pages, 8,028 with 8 pages RX |
| `mem_unmap` and `mem_protect` (`syscall::mem_unmap`, `syscall::mem_protect`, `process::step_change`) | the first entry checks the values, the handle, the target's life, finds the one mapping that is the range, idle, and for `mem_protect` the rights it was mapped with; the mapping is marked busy; then chunks of up to 32 pages, 8 when `mem_protect` makes them executable (the instruction cache made coherent first): each descriptor cleared or given the new permissions in place, then `dsb ishst`, a `tlbi vale1is` a page and one `dsb ish` when the space has an ASID of the current generation; the last chunk of `mem_unmap` takes the mapping out and releases its memory object, that of `mem_protect` makes it idle | a chunk: 32 pages, each a walk of the tables and a TLBI; the first entry walks up to 64 mappings | 2,770 (test build): the first entry of `mem_unmap` of 64 pages among 64 mappings of a process with an ASID, 1,866 the next; `mem_protect` to R 2,869 and 1,938, to RX 6,338 and 5,407 with 8 pages |
| a chunk of a memory object (`memory::clean`) | `PageList::release_step`: up to 32 frames, the pages and then the nodes of the object's list, go back to the allocator, each refunded to the object's budget; with frames left the object goes to the head of its level; the last chunk returns the object's place to its payer's pool and its budget to the payer's quota, and releases the reference to the payer's shell | up to 32 frames, each through merging free blocks in `FRAMES` up to the highest order | 16,179 (test build): the last chunk, 31 pages and the node of their list, each merging up to the highest order, with the object's place and budget; 8,455 when the frames lie in a row |
| `channel_create` | checks the room in the caller's table (spec 11), takes a slot in the caller's pool of channels (the pool growth row; a channel takes about 650 bytes, six to a page), and inserts a handle with the channel's rights | constant: at most one growth of the caller's pool of channels and of its pool of blocks |  |
| `notify` | ORs the bits in and counts with saturation in the slot of label 0, or through a labelled handle in its session's slot; a slot that was not queued goes to the top waiting receiver (its `x0`-`x11`, a boost to the slot's priority under the ceiling, the tail of the boosted level with a new quantum, and letting go of the wait reference) or to the tail of its level in the queue of slots, where it holds its owner; a closed channel returns `PEER_CLOSED` and gets nothing | constant: the level mask, doubly linked lists, and writing 12 words | 846 into an empty channel, with the `try_receive` that takes the slot back; 1,137 waking a higher thread, with the switch to it, its `receive` that waits again, and the switch back |
| `receive` | drops the caller's boost; takes the head of the top level of the channel's queue: a slot, which it empties into `x0`-`x11` and whose priority boosts the caller, letting go of the slot's owner after the lock (a session with no copies goes on the cleanup queue); or a request, which it takes as in the `send` row, letting go of what the sender's wait held after the lock (the last copy of a session posts `CLIENT_GONE` as `notify` does); a request with handles first gets room for them in the caller's table outside the lock (`HandleTable::reserve`, at most one chunk: the pool growth row), and without room its sender wakes with the error, its handles are released, up to 4, and the call starts over at its `svc` for the next head, after a poll for interrupts; with nothing queued, returns `WOULD_BLOCK` for "do not wait" or puts the thread to wait, its own slot at the tail of its level in the channel's queue | constant: with handles, at most one chunk, 4 inserts and 4 releases, each no costlier than `notify` | 348: an empty channel with `NO_WAIT` |
| `send` | checks the description and the values of up to 4 handles, read once from the caller's buffer, the handle, then each handle of the message (a lookup each), the count of the caller's thread number, the channel's state, and "do not wait" without a waiting receiver; a closed channel releases the handles; with a waiting receiver, room for the handles in its table first, outside the lock (`HandleTable::reserve`, at most one chunk: the pool growth row), and without room the handles are released and the call fails; the handles leave the caller's table; then under the scheduler's lock the caller waits: its request goes to the top waiting receiver at once (the count grows by 1 for the token, the caller's slot goes to the tail of its level in the queue of accepted requests of the receiver's process, the receiver gets `x0`-`x11` from the caller's registers with the bytes past the length zeroed and bytes 64 up to the length from the caller's buffer frame into its own, a boost to the caller's level under its ceiling, and the tail of its level with a new quantum, the handles going into its table, their values and info words into its buffer), or its slot goes to the tail of its level in the channel's queue, holding the channel or a copy of the session and the handles; the receiver's wait reference goes after the lock | constant: the level mask, rings, writing 12 words, copying at most 960 bytes, and with handles 4 lookups, at most one chunk, 4 removals and 4 inserts | a round trip with the service's `reply` and `receive` (test build): 2,478 in registers, 3,364 with 1024 bytes each way, 4,784 with four handles each way |
| the fast path of `send` (`channel::fast_send`, `sched::hand_off`) | a request of up to 64 bytes and no handles to a receiver that waits: reads the top of the cleanup queue and the nearest deadline of the timers before the scheduler's lock; under it checks that the receiver's level after the boost is above the cleanup's and every ready thread's and that no interrupt is pending (`ISR_EL1`), makes the meeting as `send` does, puts the receiver on the CPU with a new quantum (`Scheduler::hand_off`) and arms the timer for the deadline it needs; the receiver's wait reference goes after the lock, and the receiver runs (`thread::run`) | constant: no memory of a program is touched | a round trip with the service's `reply` and `receive` (test build): 2,285 |
| `reply` | checks the description and the values of up to 4 handles, read once from the caller's buffer, then each handle; drops the caller's boost when the token is the boost's; then checks the token: the entry of the table of thread numbers, with its mark of a client that ended while it waited (`PEER_CLOSED`, and the handles are released), and a client waiting for this process's reply; room for the handles in the client's table outside the lock (`HandleTable::reserve`, at most one chunk), and the handles leave the caller's table; takes the client's slot off the queue of accepted requests, writes its `x0`-`x9` from the caller's registers with the bytes past the length zeroed and bytes 64 up to the length from the caller's buffer frame into the client's, the handles into its table and their values and info words into its buffer, or without room the error into its `x0` and releases the handles, and puts it at the tail of its level with a new quantum | constant: a ring, writing 10 words, copying at most 960 bytes, and with handles 4 lookups, at most one chunk, 4 removals and 4 inserts or releases |  |
| `handle_duplicate` | without a label: inserts a copy of the handle with narrowed rights and adds a reference to the object (to a session, a copy too); with a label: checks the room in the caller's table (spec 11), takes one of the channel's 1024 slots, takes a slot in the caller's pool of sessions (the pool growth row), and inserts the session's handle | constant: at most one growth of the caller's pool of sessions and of its pool of blocks |  |
| the last copy of a session goes (`session::release`: `handle_close`, the Handles stage) | with the channel open, posts the bit `CLIENT_GONE` into the session's slot as `notify` does (delivery to a waiter or enqueuing); then releases the copy's reference, and the last one puts the session on the cleanup queue | constant: as `notify`; takes no memory, the slot was allocated with the session |  |
| a session chunk (`session::clean`) | returns the session's slot to the channel's limit and the object's slot to the payer's pool of sessions (nothing goes back to the quota), and releases the references to the channel and to the payer's shell | constant |  |
| `thread_exit` | unmaps the message-buffer page, flushing its TLB entry, and returns the frame (a running thread carries no handles of a request); gives the thread's number back; removes the thread from the process's list; the last running thread terminates the process, as in the process termination row | constant, except for process termination |  |
| `clock_now` | reads the counter and turns ticks into nanoseconds, rounded down | constant: one 128-bit multiplication and division | 370 |
| `timer_create` | checks the room in the caller's table (spec 11) and the caller's 64 timers, takes one of the channel's 1024 slots, then a slot in the caller's pool of timers (the pool growth row), and inserts the handle | constant: at most one growth of the caller's pool of timers and of its pool of blocks; the timer is not armed |  |
| `timer_set` | on a closed channel returns `PEER_CLOSED` and changes nothing; otherwise takes an armed timer off the heap of its level, then posts bit 0 at once for a deadline the counter reached, as `notify` does, or puts the timer into that heap; the nearest deadline is walked again when the top of the level changed | O(log n): a removal and an insertion, or a removal and a post of O(1); and a walk of 63 levels | 2,241 (test build): the top of a heap of 4,096 moved before every other timer, among 63 levels with timers |
| `timer_cancel` | takes an armed timer off the heap of its level, and walks the levels when its top changed; bits it posted stay in its slot | O(log n) and a walk of 63 levels |  |
| the last reference to a timer (`timer::release`: `handle_close`, the Handles stage, or `receive` or the Close stage that took its slot) | marks the timer dying and puts it at the tail of the cleanup queue at the level of the cause; it stays in the heap of its level until its chunk or a chunk of firings takes it off | constant |  |
| a timer chunk (`timer::clean`) | takes the timer off the heap of its level if it is armed, returns its slot to the channel's limit and its place to its payer's pool of timers (nothing goes back to the quota), and releases the references to the channel and to the payer's shell | O(log n) for the heap and a walk of 63 levels, the rest constant |  |
| a teardown that a thread at a high level starts (`process_kill`, the last handle to a big process or to a channel with many waiters) | runs at the level of its cause (spec 7.7), the Close and Replies stages at the higher of the cause and their top waiter: the chunks of the whole teardown follow one another at that level, with interrupt polls between them, and no thread at or below that level runs until they end | each chunk as in its row; in all, the sum of the object's chunks | 42,961: `process_kill` of a child with 64 threads that never ran, with its whole teardown; 75,124: closing a channel with 60 waiting receivers, with its two chunks at their level, and the 60 receivers that wake, run above the closer and exit |
| B, the blocking time of any thread, level 63 included (spec 15.3) | the longest row above, which a pending interrupt waits for; firings of timers are chunks of their levels, and no series of them blocks a higher level | the longest row | 19,749 under -icount (test build), a chunk of the Buffers stage whose 11 frames each merge up to the highest order and whose 42 handles each wake a receiver, the longest of the rows measured, where printing costs nothing; then 19,354, a Buffers chunk of 32 frames, 19,318, a Handles chunk of the same kind, and 19,300, the first entry of `mem_create` with only blocks of the highest order free; on hardware `debug_write` and the fault line are longer (their rows); a chunk of firings, 12,773, stays below it |
