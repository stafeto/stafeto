// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
//
// Programs for the kernel tests at EL0 (ktest::el0). They lie in a
// page-aligned section of the kernel image that the kernel never runs: a
// test copies the section into a frame of its process and maps it there. On
// entry x0 holds the test's argument: the address of a register pattern,
// or an address to load from. A program ends with `svc #SVC_DONE`, where
// the kernel judges its registers.

.equ SVC_NOP, 0xFF00                    // ktest::el0::SVC_NOP
.equ SVC_DONE, 0xFF01                   // ktest::el0::SVC_DONE
.equ SVC_SNAP, 0xFF02                   // ktest::el0::SVC_SNAP
.equ SVC_SLOW, 0xFF03                   // ktest::el0::SVC_SLOW
.equ SVC_RELEASE, 0xFF04                // ktest::el0::SVC_RELEASE
.equ SVC_PENDING, 0xFF05                // ktest::el0::SVC_PENDING
.equ CALL_HANDLE_CLOSE, 1               // abi::Call::HandleClose
.equ CALL_SEND, 4                       // abi::Call::Send
.equ CALL_RECEIVE, 5                    // abi::Call::Receive
.equ CALL_REPLY, 6                      // abi::Call::Reply
.equ CALL_NOTIFY, 7                     // abi::Call::Notify
.equ CALL_PROCESS_KILL, 13              // abi::Call::ProcessKill
.equ CALL_PROCESS_EXIT, 14              // abi::Call::ProcessExit
.equ CALL_THREAD_CREATE, 15             // abi::Call::ThreadCreate
.equ CALL_THREAD_START, 16              // abi::Call::ThreadStart
.equ CALL_THREAD_EXIT, 17               // abi::Call::ThreadExit
.equ CALL_THREAD_SET_PRIORITY, 18       // abi::Call::ThreadSetPriority
.equ CALL_YIELD, 19                     // abi::Call::Yield
.equ CALL_OBJECT_INFO, 27               // abi::Call::ObjectInfo
.equ CALL_DEBUG_WRITE, 28               // abi::Call::DebugWrite
.equ P_SP, 248                          // offsets in ktest::el0::Pattern; x0-x30 come first
.equ P_NZCV, 256
.equ P_TPIDR, 264
.equ P_FPCR, 272
.equ P_FPSR, 280
.equ P_V, 288
.equ DATA_VA, 0x800000                  // ktest::el0::DATA_VA
.equ FIFO, 1                            // abi::Policy::Fifo
.equ NO_WAIT, 0x10000                   // abi::NO_WAIT

.arch_extension fp
.arch_extension simd

// Loads every register from the pattern at x0: v0-v31, FPCR, FPSR, SP,
// TPIDR_EL0, the flags, then x0-x30. x30 holds the pattern's address until
// the last load replaces it.
.macro LOAD_PATTERN
    mov     x30, x0
    ldp     q0, q1, [x30, #(P_V + 32 * 0)]
    ldp     q2, q3, [x30, #(P_V + 32 * 1)]
    ldp     q4, q5, [x30, #(P_V + 32 * 2)]
    ldp     q6, q7, [x30, #(P_V + 32 * 3)]
    ldp     q8, q9, [x30, #(P_V + 32 * 4)]
    ldp     q10, q11, [x30, #(P_V + 32 * 5)]
    ldp     q12, q13, [x30, #(P_V + 32 * 6)]
    ldp     q14, q15, [x30, #(P_V + 32 * 7)]
    ldp     q16, q17, [x30, #(P_V + 32 * 8)]
    ldp     q18, q19, [x30, #(P_V + 32 * 9)]
    ldp     q20, q21, [x30, #(P_V + 32 * 10)]
    ldp     q22, q23, [x30, #(P_V + 32 * 11)]
    ldp     q24, q25, [x30, #(P_V + 32 * 12)]
    ldp     q26, q27, [x30, #(P_V + 32 * 13)]
    ldp     q28, q29, [x30, #(P_V + 32 * 14)]
    ldp     q30, q31, [x30, #(P_V + 32 * 15)]
    ldr     x0, [x30, #P_FPCR]
    msr     fpcr, x0
    ldr     x0, [x30, #P_FPSR]
    msr     fpsr, x0
    ldr     x0, [x30, #P_SP]
    mov     sp, x0
    ldr     x0, [x30, #P_TPIDR]
    msr     tpidr_el0, x0
    ldr     x0, [x30, #P_NZCV]
    msr     nzcv, x0
    ldp     x0, x1, [x30, #(8 * 0)]
    ldp     x2, x3, [x30, #(8 * 2)]
    ldp     x4, x5, [x30, #(8 * 4)]
    ldp     x6, x7, [x30, #(8 * 6)]
    ldp     x8, x9, [x30, #(8 * 8)]
    ldp     x10, x11, [x30, #(8 * 10)]
    ldp     x12, x13, [x30, #(8 * 12)]
    ldp     x14, x15, [x30, #(8 * 14)]
    ldp     x16, x17, [x30, #(8 * 16)]
    ldp     x18, x19, [x30, #(8 * 18)]
    ldp     x20, x21, [x30, #(8 * 20)]
    ldp     x22, x23, [x30, #(8 * 22)]
    ldp     x24, x25, [x30, #(8 * 24)]
    ldp     x26, x27, [x30, #(8 * 26)]
    ldp     x28, x29, [x30, #(8 * 28)]
    ldr     x30, [x30, #(8 * 30)]
.endm

.section .rodata.el0_programs, "a"
.balign 4096
.global el0_programs, el0_programs_end
el0_programs:

// Reads the virtual counter and its frequency, as EL0 may (CNTKCTL_EL1).
.global el0_read_counter
el0_read_counter:
    mrs     x0, cntvct_el0
    mrs     x1, cntfrq_el0
    svc     #SVC_DONE

// Fills every register, makes a system call that changes x0 alone.
.global el0_pattern_nop
el0_pattern_nop:
    LOAD_PATTERN
    svc     #SVC_NOP
    svc     #SVC_DONE

// Fills every register and waits in a loop for the timer's interrupt;
// the kernel moves the thread past the loop once it has come.
.global el0_pattern_loop, el0_wait_loop
el0_pattern_loop:
    LOAD_PATTERN
el0_wait_loop:
    b       el0_wait_loop
    svc     #SVC_DONE

// Fills every register from a pattern whose x0 and x1 hold a channel and
// flags, and waits in receive: the kernel checks that the wait changed
// x0-x11 alone.
.global el0_pattern_receive
el0_pattern_receive:
    LOAD_PATTERN
    svc     #CALL_RECEIVE
    svc     #SVC_DONE

// Fills every register and yields to the test's other thread, a FIFO
// thread at the same level, which fills them with its own pattern.
.global el0_pattern_yield
el0_pattern_yield:
    LOAD_PATTERN
    svc     #CALL_YIELD
    svc     #SVC_DONE

// Loads from the kernel address in x0, which must fault.
.global el0_load
el0_load:
    ldr     x1, [x0]
    svc     #SVC_DONE

// Ends at once: the kernel checks the FP and SIMD registers a new thread
// finds, after tests that left their patterns in them.
.global el0_done_at_once
el0_done_at_once:
    svc     #SVC_DONE

// Fill every register from a pattern whose x0-x9 hold a call's arguments,
// make the call and end: the kernel checks what the call wrote.
.global el0_pattern_close
el0_pattern_close:
    LOAD_PATTERN
    svc     #CALL_HANDLE_CLOSE
    svc     #SVC_DONE

.global el0_pattern_object_info
el0_pattern_object_info:
    LOAD_PATTERN
    svc     #CALL_OBJECT_INFO
    svc     #SVC_DONE

.global el0_pattern_debug_write
el0_pattern_debug_write:
    LOAD_PATTERN
    svc     #CALL_DEBUG_WRITE
    svc     #SVC_DONE

// Scheduling tests (ktest::el0). The threads of a test share the words of
// one data page and take their arguments in x0 and up. Counter readings
// follow an ISB, so that they are not taken early.

// Adds 1 to the word at x0 and ends: a mark that the thread ran.
.global el0_mark
el0_mark:
    ldr     x1, [x0]
    add     x1, x1, #1
    str     x1, [x0]
    svc     #SVC_DONE

// Adds 1 to the word at x0 over and over until the word at x1 is set.
.global el0_count_until
el0_count_until:
1:  ldr     x2, [x0]
    add     x2, x2, #1
    str     x2, [x0]
    ldr     x3, [x1]
    cbz     x3, 1b
    svc     #SVC_DONE

// Spins until x1 counter ticks have passed, then yields. Ends with the
// word at x0 read before the yield in x3, after it in x4, and the yield's
// result in x0.
.global el0_spin_then_yield
el0_spin_then_yield:
    mov     x2, x0
    isb
    mrs     x5, cntvct_el0
    add     x5, x5, x1
1:  isb
    mrs     x6, cntvct_el0
    cmp     x6, x5
    b.lo    1b
    ldr     x3, [x2]
    svc     #CALL_YIELD
    ldr     x4, [x2]
    svc     #SVC_DONE

// thread_set_priority(x0 thread, x1 priority, x2 policy), with the word at
// x3 read before the call into x4 and after it into x5.
.global el0_set_priority
el0_set_priority:
    ldr     x4, [x3]
    svc     #CALL_THREAD_SET_PRIORITY
    ldr     x5, [x3]
    svc     #SVC_DONE

// The same once the word at x3, a peer's count, has moved: the peer at
// the same level ran, after this thread's quantum ended, and the call
// comes at the start of the new quantum this thread gets back after the
// peer's. Afterwards sets the word at x6, which lets the peer end.
.global el0_set_priority_after_peer
el0_set_priority_after_peer:
    ldr     x4, [x3]
1:  ldr     x5, [x3]
    cmp     x5, x4
    b.eq    1b
    mov     x4, x5
    svc     #CALL_THREAD_SET_PRIORITY
    ldr     x5, [x3]
    mov     x7, #1
    str     x7, [x6]
    svc     #SVC_DONE

// Process and thread tests (ktest::el0). A call that must not return is
// followed by `svc #SVC_DONE`, where the kernel fails the test.

// WFI traps at EL0 (SCTLR_EL1.nTWI is clear): the program's fault.
.global el0_wfi
el0_wfi:
    wfi
    svc     #SVC_DONE

// process_kill with the handle in x0.
.global el0_kill
el0_kill:
    svc     #CALL_PROCESS_KILL
    svc     #SVC_DONE

// process_exit with the code in x0.
.global el0_exit_process
el0_exit_process:
    svc     #CALL_PROCESS_EXIT
    svc     #SVC_DONE

// thread_create with the arguments in x0-x6, then thread_exit: the new
// thread stays stopped.
.global el0_create_then_exit
el0_create_then_exit:
    svc     #CALL_THREAD_CREATE
    svc     #CALL_THREAD_EXIT
    svc     #SVC_DONE

// object_info with the arguments in x0-x2, then thread_exit.
.global el0_info_then_exit
el0_info_then_exit:
    svc     #CALL_OBJECT_INFO
    svc     #CALL_THREAD_EXIT
    svc     #SVC_DONE

// thread_create with the arguments in x0-x6 and thread_start of the new
// thread. Ends with the last call's x0 and the handle in x19.
.global el0_create_and_start
el0_create_and_start:
    svc     #CALL_THREAD_CREATE
    cbnz    x0, 1f
    mov     x19, x1
    mov     x0, x19
    svc     #CALL_THREAD_START
1:  svc     #SVC_DONE

// The thread el0_create_and_start makes: adds 1 to the first word of its
// message buffer, at x0, and stores the word in word 0 of the shared page,
// so that word holds 1 when the buffer read as zero and took the write;
// then exits.
.global el0_buffer_mark
el0_buffer_mark:
    ldr     x1, [x0]
    add     x1, x1, #1
    str     x1, [x0]
    ldr     x1, [x0]
    mov     x2, #DATA_VA
    str     x1, [x2]
    svc     #CALL_THREAD_EXIT

// thread_start of the thread in x0, then handle_close of x0 and of x1.
// Ends with the last call's x0.
.global el0_start_then_close
el0_start_then_close:
    mov     x19, x0
    mov     x20, x1
    svc     #CALL_THREAD_START
    cbnz    x0, 1f
    mov     x0, x19
    svc     #CALL_HANDLE_CLOSE
    cbnz    x0, 1f
    mov     x0, x20
    svc     #CALL_HANDLE_CLOSE
1:  svc     #SVC_DONE

// Channel tests (ktest::el0).

// receive(x0 channel, x1 flags); the kernel judges its result.
.global el0_receive
el0_receive:
    svc     #CALL_RECEIVE
    svc     #SVC_DONE

// notify(x0 channel, x1 bits); the kernel judges its result.
.global el0_notify
el0_notify:
    svc     #CALL_NOTIFY
    svc     #SVC_DONE

// receive(x0 channel, x1 flags), then thread_exit: the result stays in
// the thread's registers for the test.
.global el0_receive_then_exit
el0_receive_then_exit:
    svc     #CALL_RECEIVE
    svc     #CALL_THREAD_EXIT
    svc     #SVC_DONE

// process_kill(x0 process), notify(x1 channel, x2 bits), then receive(x1,
// NO_WAIT). Ends with the kill's x0 in x19, notify's in x20 and the
// result of receive in x0-x11.
.global el0_kill_notify_receive
el0_kill_notify_receive:
    mov     x21, x1
    mov     x22, x2
    svc     #CALL_PROCESS_KILL
    mov     x19, x0
    mov     x0, x21
    mov     x1, x22
    svc     #CALL_NOTIFY
    mov     x20, x0
    mov     x0, x21
    mov     x1, #NO_WAIT
    svc     #CALL_RECEIVE
    svc     #SVC_DONE

// thread_set_priority(x0 thread, x1 priority, x2 policy), then notify(x3
// channel, x4 bits). Ends with the first call's x0 in x19 and notify's in
// x0.
.global el0_raise_then_notify
el0_raise_then_notify:
    mov     x21, x3
    mov     x22, x4
    svc     #CALL_THREAD_SET_PRIORITY
    mov     x19, x0
    mov     x0, x21
    mov     x1, x22
    svc     #CALL_NOTIFY
    svc     #SVC_DONE

// The test's alarm: waits in receive(x0 channel, x1 flags) until a timer
// on the channel fires, then goes on at the program x2 with x3-x5 in
// x0-x2 and the result of receive in x23. receive changes x0-x11 alone.
.global el0_alarm_then
el0_alarm_then:
    mov     x19, x2
    mov     x20, x3
    mov     x21, x4
    mov     x22, x5
    svc     #CALL_RECEIVE
    mov     x23, x0
    mov     x0, x20
    mov     x1, x21
    mov     x2, x22
    br      x19

// Requests (ktest::el0).

// send(x0 channel, x1 description, x2-x9); the kernel judges the reply
// in x0-x9.
.global el0_send
el0_send:
    svc     #CALL_SEND
    svc     #SVC_DONE

// A service of one request: receive(x0 channel, 0), the message kept in
// x19-x29 (x1-x11 of the result: the description, the data, the label
// and the token), then reply with the token, the request's description
// and its data: the client gets its request back. Ends with the last
// call's x0.
.global el0_serve
el0_serve:
    mov     x1, #0
    svc     #CALL_RECEIVE
    cbnz    x0, 1f
    mov     x19, x1
    mov     x20, x2
    mov     x21, x3
    mov     x22, x4
    mov     x23, x5
    mov     x24, x6
    mov     x25, x7
    mov     x26, x8
    mov     x27, x9
    mov     x28, x10
    mov     x29, x11
    mov     x0, x29
    mov     x1, x19
    svc     #CALL_REPLY
1:  svc     #SVC_DONE

// As el0_serve, with receive(x2 another channel, 0) between the request
// and the reply: the service holds the request until a peer notifies it.
// Ends with the last call's x0.
.global el0_serve_after_notice
el0_serve_after_notice:
    mov     x12, x2
    mov     x1, #0
    svc     #CALL_RECEIVE
    cbnz    x0, 1f
    mov     x19, x1
    mov     x20, x2
    mov     x21, x3
    mov     x22, x4
    mov     x23, x5
    mov     x24, x6
    mov     x25, x7
    mov     x26, x8
    mov     x27, x9
    mov     x28, x10
    mov     x29, x11
    mov     x0, x12
    mov     x1, #0
    svc     #CALL_RECEIVE
    cbnz    x0, 1f
    mov     x0, x29
    mov     x1, x19
    mov     x2, x20
    mov     x3, x21
    mov     x4, x22
    mov     x5, x23
    mov     x6, x24
    mov     x7, x25
    mov     x8, x26
    mov     x9, x27
    svc     #CALL_REPLY
1:  svc     #SVC_DONE

// reply(x0 token, x1 description), then notify(x2 channel, x3 bits).
// Ends with reply's x0 in x19 and notify's in x0.
.global el0_reply_then_notify
el0_reply_then_notify:
    mov     x20, x2
    mov     x21, x3
    svc     #CALL_REPLY
    mov     x19, x0
    mov     x0, x20
    mov     x1, x21
    svc     #CALL_NOTIFY
    svc     #SVC_DONE

// thread_set_priority(x0 own thread, x1 priority, FIFO), then
// thread_set_priority(x2 another thread, x3 priority, FIFO), then
// send(x4 channel, an empty request). Ends with the first call's x0 in
// x19, the second's in x20 and the reply in x0-x9.
.global el0_raise_then_send
el0_raise_then_send:
    mov     x21, x2
    mov     x22, x3
    mov     x23, x4
    mov     x2, #FIFO
    svc     #CALL_THREAD_SET_PRIORITY
    mov     x19, x0
    mov     x0, x21
    mov     x1, x22
    mov     x2, #FIFO
    svc     #CALL_THREAD_SET_PRIORITY
    mov     x20, x0
    mov     x0, x23
    mov     x1, #0
    svc     #CALL_SEND
    svc     #SVC_DONE

// The departure of a side (ktest::el0).

// send(x0 channel, x1 description, x2-x9), then thread_exit: the reply
// stays in the thread's registers for the test.
.global el0_send_then_exit
el0_send_then_exit:
    svc     #CALL_SEND
    svc     #CALL_THREAD_EXIT
    svc     #SVC_DONE

// A service that takes x1 requests, at least 1, with receive(x0 channel,
// 0) and answers none; then process_exit(0).
.global el0_take_then_exit
el0_take_then_exit:
    mov     x19, x0
    mov     x20, x1
1:  mov     x0, x19
    mov     x1, #0
    svc     #CALL_RECEIVE
    subs    x20, x20, #1
    b.ne    1b
    mov     x0, #0
    svc     #CALL_PROCESS_EXIT
    svc     #SVC_DONE

// As el0_take_then_exit, but instead of the exit receive(x2 another
// channel, 0), where nothing comes: the service waits until it is killed.
.global el0_take_then_wait
el0_take_then_wait:
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
1:  mov     x0, x19
    mov     x1, #0
    svc     #CALL_RECEIVE
    subs    x20, x20, #1
    b.ne    1b
    mov     x0, x21
    mov     x1, #0
    svc     #CALL_RECEIVE
    svc     #SVC_DONE

// A service that outlives its client: receive(x0 channel, 0), the token
// kept in x19; notify(x1 channel, x2 bits); then reply(x19, x3) twice, x3
// the description of both replies. Ends with the first reply's x0 in x20
// and the second's in x0.
.global el0_take_notify_reply
el0_take_notify_reply:
    mov     x21, x1
    mov     x22, x2
    mov     x23, x3
    mov     x1, #0
    svc     #CALL_RECEIVE
    mov     x19, x11
    mov     x0, x21
    mov     x1, x22
    svc     #CALL_NOTIFY
    mov     x0, x19
    mov     x1, x23
    svc     #CALL_REPLY
    mov     x20, x0
    mov     x0, x19
    mov     x1, x23
    svc     #CALL_REPLY
    svc     #SVC_DONE

// A service that holds a request until a notice: receive(x0 channel, 0),
// the token kept in x19; receive(x1 another channel, 0); then reply(x19,
// 0) twice. Ends with the first reply's x0 in x20 and the second's in x0.
.global el0_reply_after_notice
el0_reply_after_notice:
    mov     x21, x1
    mov     x1, #0
    svc     #CALL_RECEIVE
    mov     x19, x11
    mov     x0, x21
    mov     x1, #0
    svc     #CALL_RECEIVE
    mov     x0, x19
    mov     x1, #0
    svc     #CALL_REPLY
    mov     x20, x0
    mov     x0, x19
    mov     x1, #0
    svc     #CALL_REPLY
    svc     #SVC_DONE

// A service that looks at its channels once the threads it knew are
// gone: receive(x0 channel, 0), the token kept in x19; receive(x1 another
// channel, 0), a notice; reply(x19, 0) into x20; receive(x2 a third
// channel, NO_WAIT) into x21; notify(x3 a fourth channel, x4 bits) into
// x22, and receive(x3, NO_WAIT), whose result stays in x0-x11.
.global el0_check_after_notice
el0_check_after_notice:
    mov     x21, x1
    mov     x22, x2
    mov     x23, x3
    mov     x24, x4
    mov     x1, #0
    svc     #CALL_RECEIVE
    mov     x19, x11
    mov     x0, x21
    mov     x1, #0
    svc     #CALL_RECEIVE
    mov     x0, x19
    mov     x1, #0
    svc     #CALL_REPLY
    mov     x20, x0
    mov     x0, x22
    mov     x1, #NO_WAIT
    svc     #CALL_RECEIVE
    mov     x21, x0
    mov     x0, x23
    mov     x1, x24
    svc     #CALL_NOTIFY
    mov     x22, x0
    mov     x0, x23
    mov     x1, #NO_WAIT
    svc     #CALL_RECEIVE
    svc     #SVC_DONE

// process_kill(x0 process), handle_close(x0), then notify(x1 channel, x2
// bits). Ends with the kill's x0 in x19, the close's in x20 and notify's
// in x0.
.global el0_kill_close_notify
el0_kill_close_notify:
    mov     x21, x0
    mov     x22, x1
    mov     x23, x2
    svc     #CALL_PROCESS_KILL
    mov     x19, x0
    mov     x0, x21
    svc     #CALL_HANDLE_CLOSE
    mov     x20, x0
    mov     x0, x22
    mov     x1, x23
    svc     #CALL_NOTIFY
    svc     #SVC_DONE

// thread_set_priority(x0 thread, x1 priority, FIFO), then process_kill(x2
// process). Ends with the first call's x0 in x19 and the kill's in x0.
.global el0_raise_then_kill
el0_raise_then_kill:
    mov     x21, x2
    mov     x2, #FIFO
    svc     #CALL_THREAD_SET_PRIORITY
    mov     x19, x0
    mov     x0, x21
    svc     #CALL_PROCESS_KILL
    svc     #SVC_DONE

// Handles in messages (ktest::el0).

// handle_close(x0); the kernel judges its result.
.global el0_close
el0_close:
    svc     #CALL_HANDLE_CLOSE
    svc     #SVC_DONE

// send(x0 channel, x1 description, x2-x9), then handle_close(x0). Ends
// with send's x0 in x19 and the close's in x0.
.global el0_send_close
el0_send_close:
    mov     x20, x0
    svc     #CALL_SEND
    mov     x19, x0
    mov     x0, x20
    svc     #CALL_HANDLE_CLOSE
    svc     #SVC_DONE

// A service that looks at a channel once a notice came: receive(x0
// channel, 0) into x19; then receive(x1 another channel, NO_WAIT) twice,
// the bits and the label of each notification kept in x20, x21 and x22,
// x23; then once more, whose result stays in x0-x11.
.global el0_notice_then_take
el0_notice_then_take:
    mov     x24, x1
    mov     x1, #0
    svc     #CALL_RECEIVE
    mov     x19, x0
    mov     x0, x24
    mov     x1, #NO_WAIT
    svc     #CALL_RECEIVE
    mov     x20, x2
    mov     x21, x10
    mov     x0, x24
    mov     x1, #NO_WAIT
    svc     #CALL_RECEIVE
    mov     x22, x2
    mov     x23, x10
    mov     x0, x24
    mov     x1, #NO_WAIT
    svc     #CALL_RECEIVE
    svc     #SVC_DONE

// The fast path of send and the round trip (ktest::el0).

// A service of x1 requests, at least 1, on channel x0: it takes each in
// receive, notes the scheduler's state (svc #SVC_SNAP), and answers with
// the request itself. Ends with the last call's x0.
.global el0_serve_snap
el0_serve_snap:
    mov     x19, x0
    mov     x20, x1
1:  mov     x0, x19
    mov     x1, #0
    svc     #CALL_RECEIVE
    cbnz    x0, 2f
    svc     #SVC_SNAP
    mov     x0, x11
    svc     #CALL_REPLY
    subs    x20, x20, #1
    b.ne    1b
2:  svc     #SVC_DONE

// send(x0 channel, x1 description, x2 data) twice, with the fast path off
// (svc #SVC_SLOW) for the second when x3 is not 0; the counter read right
// before each send goes to x20 and x21. Ends with the first send's x0 in
// x22 and the second's result in x0-x9.
.global el0_send_twice
el0_send_twice:
    mov     x24, x0
    mov     x25, x1
    mov     x26, x2
    mov     x27, x3
    isb
    mrs     x20, cntvct_el0
    svc     #CALL_SEND
    mov     x22, x0
    cbz     x27, 1f
    svc     #SVC_SLOW
1:  mov     x0, x24
    mov     x1, x25
    mov     x2, x26
    isb
    mrs     x21, cntvct_el0
    svc     #CALL_SEND
    svc     #SVC_DONE

// svc #SVC_RELEASE of thread x0 of the test's crowd at level x1, then
// send(x2 channel, 8 bytes of zeros); the kernel judges the reply.
.global el0_release_then_send
el0_release_then_send:
    mov     x19, x2
    svc     #SVC_RELEASE
    mov     x0, x19
    mov     x1, #8
    mov     x2, #0
    svc     #CALL_SEND
    svc     #SVC_DONE

// send(x0 channel, x1 description, x2-x9) made once an interrupt is
// pending (svc #SVC_PENDING); the kernel judges the reply.
.global el0_pending_send
el0_pending_send:
    svc     #SVC_PENDING
    svc     #SVC_DONE

// A service that answers every request on channel x0 with the request
// itself, for ever: receive, then reply with its token, description and
// data, then receive again. Ends at an error with its x0.
.global el0_serve_loop
el0_serve_loop:
    mov     x19, x0
1:  mov     x0, x19
    mov     x1, #0
    svc     #CALL_RECEIVE
    cbnz    x0, 2f
    mov     x0, x11
    svc     #CALL_REPLY
    b       1b
2:  svc     #SVC_DONE

// Yields for ever.
.global el0_yield_loop
el0_yield_loop:
    svc     #CALL_YIELD
    b       el0_yield_loop

// The round trips of ipc_round_trip_is_measured. x0: a channel whose
// service answers every request; x1: the process of a thread that yields
// for ever at this thread's level; x2: rounds; x3: where the times go; x4:
// the description of a request with four handles, whose values the buffer
// holds. Each row times x2 rounds of a call, each between two readings of
// the counter, and stores the sum and the longest at x3 and on: an empty
// round, svc #0, a yield to the other thread and back, then, once
// process_kill ended that thread, send of 8 bytes on the fast path, of 8
// bytes with the fast path off (svc #SVC_SLOW), of 1024 bytes, and of 8
// bytes with four handles. Ends with 0 in x0, or with the first error.
.global el0_measure
el0_measure:
    mov     x24, x0
    mov     x25, x1
    mov     x26, x2
    mov     x27, x3
    mov     x28, x4
    adr     x23, 5f
    bl      6f
    adr     x23, 7f
    bl      6f
    adr     x23, 8f
    bl      6f
    mov     x0, x25
    svc     #CALL_PROCESS_KILL
    cbnz    x0, 4f
    adr     x23, 9f
    mov     x25, #8
    bl      6f
    svc     #SVC_SLOW
    bl      6f
    mov     x25, #1024
    bl      6f
    mov     x25, x28
    bl      6f
    mov     x0, #0
4:  svc     #SVC_DONE
// x26 rounds of the call at x23, each between two readings of the
// counter; the sum and the longest go to x27, which moves on. A call that
// fails ends the program with its x0.
6:  mov     x22, x30
    mov     x19, x26
    mov     x20, #0
    mov     x21, #0
1:  isb
    mrs     x12, cntvct_el0
    blr     x23
    isb
    mrs     x13, cntvct_el0
    cbnz    x0, 4b
    sub     x13, x13, x12
    add     x20, x20, x13
    cmp     x13, x21
    csel    x21, x13, x21, hi
    subs    x19, x19, #1
    b.ne    1b
    stp     x20, x21, [x27], #16
    ret     x22
// The calls: none, svc #0, a yield, send of x25 as its description
// through x24.
5:  mov     x0, #0
    ret
7:  svc     #0
    mov     x0, #0
    ret
8:  svc     #CALL_YIELD
    ret
9:  mov     x0, x24
    mov     x1, x25
    svc     #CALL_SEND
    ret

el0_programs_end:
