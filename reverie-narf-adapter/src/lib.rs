//! Narf kernel side of the one-address-space Reverie backend.
//!
//! Narf calls its syscall interceptor on the trapping task's own kernel
//! stack, with the task's address space active and the Tool's state in the
//! same kernel address space. This crate turns that call into a callback of an
//! unmodified [`reverie::Tool`] hosted by [`reverie_narf_core::NarfToolHost`]:
//!
//! * [`NarfKernelServices`] is the per-entry
//!   [`reverie_narf_core::KernelServices`]: the task's root-namespace Linux
//!   IDs, its entry registers, its memory, and the kernel-owned native
//!   transition of the one intercepted syscall;
//! * [`IrqSpinTaskLock`] is the host's task-table lock;
//! * [`ReverieInterceptor`] is the [`narf_userspace::syscall::SyscallInterceptor`]
//!   that owns the host and forwards syscall entries and task lifecycle
//!   events to it;
//! * [`RdtscInterceptor`] is the [`narf_userspace::InstructionInterceptor`]
//!   that forwards hosted tasks' `rdtsc` and `rdtscp` to the same host, for
//!   a Tool that subscribes to RDTSC events (see "RDTSC events" below).
//!
//! There is no IPC, ptrace emulation, signal or binary rewriting: the kernel
//! calls the interceptor, the interceptor polls the Tool's future on the
//! trapping task's own stack, and every Tool-to-kernel operation is a direct
//! call. A Tool whose inject parks the task (a blocking read, say) keeps its
//! future in the host, which polls it again, on the task's own stack, when
//! the kernel re-executes the parked syscall. A Tool future pending for any
//! other reason is waiting for another task (through the global state, say):
//! the task yields to its peers, and the host polls the future again each
//! time the task runs (see "Waiting callbacks" below).
//!
//! The crate is x86_64-only because Reverie's syscall layer is defined
//! without `std` only for x86_64; on any other target it is empty.
//!
//! # Backend contract: what is not supported, and what happens instead
//!
//! Where this backend cannot do what reverie-ptrace does, it should refuse by
//! name rather than guess. Each item below says whether it is refused (fails
//! closed), silently absent, or different in order or value.
//!
//! ## Refused when the run is configured
//!
//! * **CPUID subscriptions, and RDTSC subscriptions outside
//!   [`ReverieInterceptor::with_rdtsc`].** `NarfToolHost::new` returns
//!   `NarfFatal::UnsupportedSubscription`, so [`ReverieInterceptor::new`]
//!   fails and no guest runs. Host-owned threads
//!   (`UnsupportedThreadOwnership`) and signal-dequeue observation
//!   (`UnsupportedSignalDequeues`) are refused the same way.
//!
//! ## Signal events
//!
//! A hosted task's signal reaches the Tool's `handle_signal_event`
//! (`NarfToolHost::handle_signal`) only where the task returns from a
//! `syscall` instruction, the one delivery point where the task can wait for
//! the Tool. The kernel delivers it once the Tool answers with the same
//! signal, and discards it if the Tool suppresses it. A Tool that answers
//! with another signal aborts the run. At every other delivery point (a
//! timer interrupt that hit user mode, a page fault, a park in `poll` or
//! `epoll`, an `int 0x80` return) the signal stays pending until the task's
//! next syscall returns, so:
//!
//! * A hosted task that makes no syscalls receives no signal but `SIGKILL`,
//!   which never goes to the Tool.
//! * A native blocking syscall the signal interrupts returns `EINTR` before
//!   the handler runs, at that syscall's own return.
//! * Real-time signals, which Reverie's `Signal` cannot name, and
//!   synchronous fault signals (`SIGSEGV` from a fault, say) are delivered
//!   without the Tool, as before signal events existed.
//!
//! ## Silently absent (not fail-closed)
//!
//! * **fs_base and gs_base.** `KernelServices::regs` reports `fs_base`,
//!   `gs_base` and the `ds`/`es`/`fs`/`gs` selectors as 0. A Tool that
//!   reads them gets 0, not the guest's TLS base.
//! * **RDTSC events, when the [`RdtscInterceptor`] is not installed.**
//!   [`ReverieInterceptor::with_rdtsc`] returns it for a Tool that
//!   subscribed, and the caller must install it before the guest runs.
//!   Nothing checks that it did, or that the install succeeded; if not,
//!   the Tool gets no RDTSC event, and every `rdtsc` reads the hardware
//!   counter. The kernel keeps an installed interceptor for its lifetime,
//!   so only the first such run of a boot can install one.
//!
//! ## Refused inside a callback
//!
//! * **Task creation from `handle_thread_start` or `handle_post_exec`.** An
//!   injected `fork`, `vfork`, `clone` or `clone3` returns `-ENOSYS` without
//!   running. A lifecycle callback has no user frame for a child to start
//!   from (`creates_task` in `narf_userspace::syscall`). An injected `exit`,
//!   `exit_group`, `execve` or `execveat` there is refused the same way.
//!
//! ## Run aborts
//!
//! Every `NarfFatal` returned to either interceptor goes to their shared
//! `fatal` (`interceptor.rs`), which sorts it with `fatal_kind` (an
//! exhaustive match, so a new variant must be sorted before the adapter
//! builds).
//!
//! **Contained: the run is aborted, the kernel keeps running.** A fatal that
//! a Tool, or a guest driving a Tool, can cause stops only the hosted process
//! tree, as Linux kills a tracee whose tracer dies (`PTRACE_O_EXITKILL`).
//! The interceptor logs `reverie-narf: aborting the hosted process tree
//! after <callback>: <fatal>` on the console, keeps that first reason
//! (`ReverieInterceptor::abort_reason`), and sends `SIGKILL` to every hosted
//! process (`tool_view::kill_process_sigkill`). A hosted task that reaches
//! the interceptor again, or is created later, is killed there and runs no
//! Tool callback (`kill_if_aborted`); a syscall that the abort interrupted
//! returns `-EINTR`, which the task never sees because its `SIGKILL` is
//! delivered first. Each hosted process is reaped with wait status 9
//! (`SIGKILL`), and every exit still reaches the host, so the Tool's exit
//! hooks run. No other process is signalled.
//!
//! | Fatal | Cause | Can the guest trigger it? |
//! |---|---|---|
//! | `Tool(Error)` | The Tool returned an error that is not an errno. | Only through a Tool that turns guest input into such an error. |
//! | `InvalidErrno` | The Tool returned an errno outside `1..=4095`. | No; Tool only. |
//! | `PostExec(Errno)` | `handle_post_exec` failed. | Only through a Tool that fails on guest input. |
//! | `InjectParked`, in a lifecycle callback | A non-tail inject parked the task (a blocking `poll`, say). No guest syscall exists to re-execute. | Yes, given a Tool that makes a blocking inject there, because the guest controls whether the call would block (`reverie_narf_parked_inject_in_thread_start_aborts_the_tree`). |
//! | `ToolSuspended` | The Tool's future was pending without a terminal transition and without a parked inject, where the kernel cannot let the task wait: in a hook that is polled once, or outside the own-stack execution model (see "Waiting callbacks"). | No; Tool only. |
//! | `TransitionAfterInterruption` | After a signal interrupted its parked inject (which returned `ERESTARTSYS`), the Tool ran another syscall. | Yes, given such a Tool: a signal sent during the parked inject is enough (`reverie_narf_transition_after_interruption_aborts_the_tree`). |
//! | `TransitionAfterTerminal` | The Tool ran a syscall after its callback's terminal transition. | No; Tool only. |
//! | `TailInjectOutsideSyscall` | A lifecycle or RDTSC callback tail-injected a syscall that returned. | No; Tool only. |
//! | `DaemonizeRefused(Errno)` | The kernel refused the Tool's daemonize request. | No; Tool only. |
//! | `Rdtsc(Errno)` | `handle_rdtsc_event` failed with an errno while the task was not ending. | Only through a Tool that fails on guest input (`reverie_narf_rdtsc_tool_errno_aborts_the_tree`). |
//! | `RdtscContextManaged` | An RDTSC callback's transition took the task's context although the task was not killed (`KernelServices::killed`, which answers only for `SIGKILL`): a tail inject parked it, or an inject ended its context, as an injected `rt_sigreturn` does: with no signal frame to restore, the kernel stages a `SIGSEGV`. | Only through a Tool that makes such a transition. |
//! | `InjectParked`, in an RDTSC callback | As in a lifecycle callback: no guest syscall exists to re-execute. | Yes, given a Tool that makes a blocking inject there (`reverie_narf_parked_inject_in_rdtsc_aborts_the_tree`). |
//! | `Signal(Errno)` | `handle_signal_event` failed with an errno while the task was not ending. | Only through a Tool that fails on guest input. |
//! | `SignalContextManaged` | A signal callback's transition took the task's context although the task was not killed, as for `RdtscContextManaged`. | Only through a Tool that makes such a transition. |
//!
//! **Invariant: the kernel panics.** A fatal that means the kernel or the
//! host broke its own contract leaves no state that can be trusted, so
//! `fatal` panics (`reverie-narf fatal in <callback>: <fatal>`). The panic
//! handler (`console::panic_sink`) logs it and halts the panicking CPU
//! (`halt_forever`). It does not stop the other CPUs, so on an SMP boot
//! they keep running around the halted one, and any task or lock that
//! CPU held is never released; a later panic on another CPU halts that
//! CPU without logging (`IN_PANIC`). The kernel-test runners therefore
//! stop after the current test once a panic is reported
//! (`console::panic_reported`, `verification`'s `stop_after_panic`), and
//! the hosted-test waiter stops waiting for the guest's tasks, so such a
//! run ends in bounded time with a named `[FAIL]`. It does not if the
//! panic halted the CPU that runs the test runner, or if that CPU then
//! waits for the halted one, on a lock it held or on a rendezvous of every
//! online CPU (which is why `run_rdtsc` skips its interceptor clear after
//! a panic): such a run ends only at the QEMU timeout. These are
//! `OriginalAlreadyExecuted`, `ContinuationKernelMismatch` (this adapter has
//! one memory type, `NarfMemory`), `UnexpectedReexecution`,
//! `ReexecutionMismatch`, `RecursiveEntry`, `UnknownTask`, `DuplicateTask`,
//! `CreatedTaskMismatch`, `ExitDuringCallback`, `ProcessToolShared` and
//! `UnexpectedRdtsc` (an RDTSC event reached a host that does not deliver
//! them, which [`ReverieInterceptor::with_rdtsc`] rules out).
//! `UnsupportedSubscription`, `UnsupportedThreadOwnership` and
//! `UnsupportedSignalDequeues` are refused by `NarfToolHost::new`, before
//! any guest runs; `ReverieInterceptor::new` returns them as errors.
//!
//! ## RDTSC events
//!
//! A Tool that subscribes to RDTSC events (`Subscription::rdtsc`) runs under
//! [`ReverieInterceptor::with_rdtsc`], which also returns the
//! [`RdtscInterceptor`] for the kernel's instruction interceptor slot. The
//! caller installs it with
//! [`narf_userspace::try_install_instruction_interceptor`] before any guest
//! task exists; the kernel refuses while a user task is live, once an
//! interceptor is installed, and on SMP without a remote barrier.
//! Installing it sets CR4.TSD on every CPU, so every task's `rdtsc` and
//! `rdtscp` traps, and routes the vDSO's clock reads through their
//! syscalls, so no guest reads the native counter through the vDSO while
//! its `rdtsc` is the Tool's. The kernel keeps the slot, and the host with
//! it, for its lifetime; a normal boot installs none.
//!
//! * A task the host does not track executes the instruction natively.
//! * A hosted task's `rdtsc` or `rdtscp` becomes `handle_rdtsc_event`
//!   (`Rdtsc::Tsc` or `Rdtsc::Tscp`), run on the task's own kernel stack. The
//!   Tool may inject syscalls and wait for other tasks, as in a syscall
//!   callback, a kill during the wait included
//!   (`reverie_narf_kill_ends_a_waiting_rdtsc_callback`). The Tool's value
//!   completes the instruction: `tsc` in EDX:EAX, and for `rdtscp` also `aux`
//!   in ECX, or 0 if it gave none, as reverie-ptrace does
//!   (`reverie_narf_rdtsc_values_come_from_the_tool`).
//! * An injected `fork`, `vfork`, `clone`, `clone3`, `exit`, `exit_group`,
//!   `execve` or `execveat` returns `-ENOSYS` without running, as in a
//!   lifecycle callback. An inject that blocks aborts the run: with
//!   `InjectParked` if it is not a tail inject, because there is no guest
//!   syscall to re-execute, and with `RdtscContextManaged` if it is. An
//!   injected `rt_sigreturn`, tail or not, also aborts the run with
//!   `RdtscContextManaged`: the callback has no signal frame to restore, so
//!   the kernel stages a `SIGSEGV` and the inject ends the task's context.
//! * A task that is killed during the callback, by its own injected `kill`
//!   or by another task, dies before it returns to user mode, so the guest
//!   never sees the instruction's result
//!   (`reverie_narf_kill_injected_in_rdtsc_ends_the_task`). The kernel
//!   answers `KernelServices::killed` there, which the core asks before it
//!   treats a callback without a value, or a Tool errno, as a failure.
//!
//! ## Differences from reverie-ptrace
//!
//! **Waiting callbacks.** A syscall callback whose Tool future is pending
//! without a terminal transition, a parked inject or a failure is taken to
//! wait for another task. Under reverie-ptrace its tracer task would sleep
//! until the future's waker fires; here the host asks the kernel to let
//! other tasks run (`NativeSyscallTransition::wait_for_repoll`) and polls the
//! future again each time the task runs, woken or not, with no bound of its
//! own (`reverie_narf_waiting_callbacks_meet_through_global_state`).
//! * The wait is a busy yield. The task stays runnable, and the scheduler
//!   runs it again after its peers, possibly on another CPU, so a CPU with
//!   a waiting callback never idles.
//! * Only `SIGKILL` ends a wait, including the one a sibling's `exit_group`
//!   leaves pending. The kernel checks for it each time the task runs again,
//!   so a kill that lands while the task is switched out ends the wait before
//!   the Tool is polled again, even if what the Tool waited for came true
//!   meanwhile (`reverie_narf_kill_while_switched_out_ends_a_released_wait`);
//!   one that lands while the Tool is being polled ends the wait after the
//!   task's next switch-out, unless that poll finishes the callback. The host
//!   then drops the future at once, before the exit hooks run, and the task
//!   dies of the signal once the interceptor has returned, without running
//!   the syscall the callback was entered for
//!   (`reverie_narf_kill_ends_a_wait_without_running_its_syscall`).
//!   reverie-ptrace also drops it before the exit hooks, once its tracer sees
//!   the task exit, because it races the Tool's run loop against the exit
//!   event and takes the exit first when it sees both
//!   (`reverie_narf_kill_ends_a_waiting_callback`); its task is stopped at
//!   the syscall's entry, so the syscall does not run there either. Every
//!   other signal stays pending until the callback has returned.
//! * A task that a callback created is held off the run queues
//!   (`SpawnHold`) until the callback returns or, if it waits after creating
//!   the task, until it first waits. The core has registered the task by
//!   then, and the wait adopts it into the host before letting it start
//!   (`NarfKernelServices::wait_for_repoll`). So a callback may wait for its
//!   own child, as Detcore's parent waits in `create_child_thread` for a
//!   scheduler turn that needs the child's thread start
//!   (`reverie_narf_fork_callback_waits_for_its_child`). Under
//!   reverie-ptrace the child's thread start can run as soon as the fork has
//!   returned to the tracer, beside the rest of the parent's callback.
//! * `handle_thread_start` and `handle_post_exec` wait the same way, as
//!   Detcore's thread start waits for its scheduler to admit the thread
//!   (`reverie_narf_thread_start_waits_for_another_task`). A task killed
//!   while its thread start waits is not stopped before its first user
//!   instruction: it dies of the signal at its next entry to the kernel.
//! * Callbacks wait only in the own-stack execution model, which production
//!   enables in `install_user_task_hooks`. Elsewhere the callback ends as
//!   `ToolSuspended` (see "Run aborts"): in the legacy model, and in the
//!   hooks that are polled once, which are the exit hooks, the poll after a
//!   signal interrupted a parked inject, and `init_global_state`.
//!
//! **Background futures.** Under reverie-ptrace, a global state with work
//! of its own spawns it on the tracer's tokio runtime, as Detcore's
//! scheduler does (`tokio::spawn(sched_loop(..))` in
//! `detcore/src/tool_global.rs`). There is no such runtime here:
//! `ReverieInterceptor::spawn_background` starts a kernel task that polls
//! the future, the backend executor Detcore's `run_external_scheduler`
//! expects.
//! * The task polls with a no-op waker and yields between two polls, as
//!   detcore-dbt's `run_cooperative` does. The yield is busy: the task stays
//!   runnable, pinned to the boot CPU, which does not idle while it runs
//!   (`reverie_narf_background_future_releases_a_waiting_callback`).
//! * The task stops, dropping the future unfinished, once the run is over:
//!   the root was hosted and no hosted task is left. A future started after
//!   that is never polled, though the closure that makes it still runs once
//!   (`reverie_narf_background_future_ends_with_the_run`).
//!   An aborted run ends this way too, once the abort's `SIGKILL` has ended
//!   every hosted process.
//! * The task also stops once every handle to the interceptor is gone, the
//!   only rule before a root is hosted
//!   (`reverie_narf_background_future_ends_when_every_handle_is_dropped`).
//!   Nothing else can stop it: a caller whose root is never hosted must drop
//!   every handle, or the task keeps the boot CPU busy for good, and the
//!   boot host keeps one for the life of the boot.
//! * No user task is running while the future is polled, so every access
//!   through a `NarfMemory` used there is refused with `EFAULT`, touching no
//!   memory (`reverie_narf_memory_outside_a_task_is_refused`).
//!
//! **vDSO calls.** Installing the interceptor for a Tool subscribed to any
//! one of `clock_gettime`, `gettimeofday`, `time` or `getcpu` routes all four
//! vDSO entries through syscalls. The route is one vvar clock-mode word, so
//! it covers every process in the kernel from the table's publication on (the
//! mode is sticky in production; only the test reset clears it).
//! Unsubscribed entries then run natively as syscalls, which costs time but
//! returns the same values.
//!
//! **Exit statuses.**
//! * `on_exit_thread` gets the thread's own status. `on_exit_process` gets
//!   the process's `wait4` status: the first group exit's code, or else the
//!   last exiting thread's own code.
//! * When two threads of a process exit concurrently, the thread
//!   reverie-narf-core treats as last can differ from the thread whose
//!   exit the kernel counts as ending the group. So the reported process
//!   status can be the other thread's code.
//! * Each thread's `on_exit_thread` runs when that thread exits. So a
//!   leader that exits before its threads is reported first. reverie-ptrace
//!   reports the leader last.
//!
//! **vfork.**
//! * `vfork` (58) is `fork` in Narf (`install_raw(Syscall::Vfork, ..,
//!   sys_fork)` in `handlers/compat.inc.rs`). The child gets a
//!   copy-on-write copy of memory, and the parent does not wait. This is
//!   guest-visible: the parent does not see the child's writes, and parent
//!   and child run concurrently. Under Linux, and so under reverie-ptrace,
//!   the parent is suspended until the child execs or exits, and the two
//!   share memory.
//! * `clone(CLONE_VFORK)` run inside a Tool callback, whether as the original
//!   or as an inject, holds the child off the run queues until the callback
//!   returns or first waits (see "Waiting callbacks"). The parent's vfork
//!   wait is deferred until the callback returns (`defer_vfork_wait`). So
//!   the parent's inject returns the child's TID immediately, and the rest
//!   of the parent's callback, up to its first wait, runs before the child's
//!   `handle_thread_start` and before any of the child's syscalls.
//!   Under reverie-ptrace the inject returns only after
//!   `PTRACE_EVENT_VFORK_DONE`, which comes after the child's thread start
//!   and its syscalls up to its exec or exit. The guest-visible order is
//!   the same in both: the parent returns to user mode after the child
//!   execs or exits.
//!
//! **Signals raised inside a callback.** A pending, unmasked signal whose
//! default action terminates the task makes the next requested transition
//! return `-ERESTARTSYS` without running. The signal is withheld until the
//! callback returns. A pending SIGKILL refuses every later transition. These
//! match reverie-ptrace (`reverie-ptrace/tests/inject_signal_parity.rs`).
//! Where they differ:
//! 1. A signal that arrives during a blocking inject is staged as a
//!    termination by the in-syscall delivery hook. Narf never produces
//!    ptrace's `-514` followed by a single `-512`.
//! 2. Handled, ignored and stop signals, and signals to a traced task, are
//!    not withheld.
//! 3. `poll` with `nfds == 0` ignores signals, unlike Linux.
//! 4. If the Tool blocks the withheld signal, `-512` can reach a guest
//!    result.
//! 5. Raising the withheld signal again returns `-512` again.
//! 6. Queued real-time signal payloads stay queued while their bit is
//!    withheld.
//! 7. Lifecycle callbacks (thread start, post-exec, exits) are not gated.
//!    A SIGKILL there does not stop the inject from running.
//! 8. Exit and exec transitions are never withheld. After an injected
//!    `kill(self, SIGTERM)`, an injected `exit_group(7)` runs: it does not
//!    return, nothing after it runs, and the task exits with code 7
//!    (`reverie_narf_exit_group_with_sigterm_pending_runs`). Under
//!    reverie-ptrace the same `exit_group` returns `-ERESTARTSYS` without
//!    running, the next inject runs, and the task dies of `SIGTERM`.
//!
//! **Signals during a parked inject.** A Tool's non-tail inject that blocks
//! parks the task, and the host resumes the Tool only if the task's next
//! entry re-executes exactly that syscall: same instruction pointer, number
//! and arguments (`take_park_reexecution` in `narf_userspace::syscall`).
//! What a signal does to the park depends on its disposition:
//! * **Handled.** The park ends and the handler runs on the syscall's
//!   return path, with no user code in between. The handler's first syscall (at the latest its
//!   `rt_sigreturn`) is another entry, so the inject returns `-ERESTARTSYS`,
//!   as under ptrace, and the Tool gets one more poll in which it must
//!   finish without running a syscall (reverie-narf-core `interrupt`); a
//!   syscall there aborts the run with `TransitionAfterInterruption` (see
//!   "Run aborts"). Whatever the callback then returns is discarded. After
//!   the handler, the guest's syscall runs again and the Tool sees it as a
//!   new syscall, so its callback runs again and repeats any side effects it
//!   made before the inject. The syscall runs again even without
//!   `SA_RESTART`: the park rewound the instruction pointer to the `syscall`
//!   instruction (`park_reexecute_on_io_until`), and handler delivery on
//!   that return path keeps that pointer (`deliver_signal_into_state`). Under Linux, and so under reverie-ptrace, a `read`
//!   interrupted without `SA_RESTART` returns `-EINTR` instead, and the
//!   callback does not run again.
//! * **Ignored** (`SIG_IGN`, or `SIG_DFL` with an Ignore default such as
//!   `SIGCHLD`). A pending ignored signal does not end the park
//!   (`has_interrupting_signal`). One raised after that check can end it
//!   once, through the raw pending recheck that follows the waker
//!   registration (`park_should_block_decide`); the return path then
//!   discards the signal, the task re-enters the same syscall, and the
//!   inject continues. The Tool sees nothing.
//! * **Stop** (default action). The park ends, and the task stops on the
//!   syscall's return path before it runs any user code
//!   (`enter_stopped`). While stopped it stays parked until `SIGCONT`,
//!   unless `SIGKILL` is pending (`park_should_block_decide`).
//!   `enter_stopped` stores 0 as the syscall's return value, which on the
//!   rewound frame is the syscall-number register, so after `SIGCONT` the
//!   task enters syscall 0 (`read`) with the parked call's arguments. For a
//!   parked `read` that is the parked syscall, and the inject continues.
//!   For any other parked syscall the entry does not match, the inject
//!   returns `-ERESTARTSYS`, and a `read` with the other call's arguments
//!   runs. This follows from the code; no test exercises a stop during a
//!   parked inject.
//!
//! ## Limits of the in-kernel tests
//!
//! * **`signal_init()`.** Kernel-test boots do not set up the signal tables,
//!   so a raise there is silently dropped. The five signal tests create them
//!   with `narf_userspace::signal_init()` through a guard (`SignalTables`)
//!   that removes, on every return path, the tables it created. The one
//!   whose guest installs a handler also creates the handler tables
//!   (`SignalTables::init_with_handlers`, `narf_userspace::sigaction_init()`);
//!   without them `rt_sigaction` returns `EINVAL`. Other
//!   reverie-narf tests run without signal delivery, unless an earlier
//!   subsystem's test in the same boot left the tables set up.
//! * **Leak check.** Every reverie-narf test is registered through
//!   `reverie_narf_test!`, which fails the test by name if it left the signal
//!   tables, the vDSO clock routing, the vDSO image registration, user-task
//!   SMP placement or work stealing different from how it found them. The
//!   vDSO test registers the image itself (kernel-test boots skip the boot
//!   registration) and unregisters it afterwards, because every process
//!   loaded while it is registered maps the vDSO, which changes the loader
//!   tests' stack and region layout.
//! * **Reclaim scope.** After each run, the test harness's `reclaim_run`
//!   checks two things: every address space the guest's tasks exited from
//!   was dropped, and the root image's private frames reached a COW count of
//!   0. Shared regions are left out, and so is the vDSO region at and above
//!   `VDSO_MAP_BASE`, whose masters hold a permanent reference. Frames that
//!   forked children or exec'd images allocate are not checked, so a leak
//!   there goes unnoticed.
//! * **Placement.** Kernel-test boots turn on neither user-task SMP nor work
//!   stealing. Each guest run turns both on for its length, as a production
//!   boot does (`ProductionPlacement`), so the root starts where
//!   `TaskSpec::user_task` prefers (an application processor; on a two-CPU
//!   machine, either CPU), a fork child goes where `fork_cpu` puts it, and
//!   idle CPUs steal runnable guest tasks. Each run prints the CPUs its tasks
//!   exited on. A test whose guest's tasks must share one CPU sets
//!   `BOOT_CPU_PLACEMENT` and keeps the kernel-test placement, every guest
//!   task pinned to the boot CPU, and checks that its tasks exited on one
//!   CPU. The pipe tests open their gate from the kernel's
//!   descriptor-park observer, once the write has parked, so they do not
//!   depend on where the parent and child run.
//! * **Reclaim timing.** With guest tasks on several CPUs, a peer CPU can
//!   still be running an address space's destructor when `reclaim_run`
//!   checks: the space's `Weak` count reads 0 once `Drop` starts, and its
//!   frames' COW counts fall while `Drop` runs. `reclaim_run` therefore
//!   drives grace periods until everything is reclaimed, within 4 s of wall
//!   time, not for a fixed number of grace periods, which complete at once
//!   when every peer is idle.
//! * **The `cow::__test_clear` guard.** It refuses to wipe the COW count of
//!   a frame that some address space still maps, but it finds such frames
//!   only through the reverse map. If the reverse map misses a mapping (an
//!   undercount), that frame's count is wiped without the panic.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

#[cfg(target_arch = "x86_64")]
pub mod boot;
#[cfg(target_arch = "x86_64")]
mod interceptor;
#[cfg(target_arch = "x86_64")]
mod services;
#[cfg(all(target_arch = "x86_64", feature = "kernel-test"))]
mod tests;

#[cfg(target_arch = "x86_64")]
pub use interceptor::{
    BackgroundEnd, BackgroundFuture, BackgroundTask, ConsoleSink, IrqSpinTaskLock,
    RdtscInterceptor, ReverieInterceptor, TaskExitRecord,
};
#[cfg(target_arch = "x86_64")]
pub use services::{map_native_outcome, NarfKernelServices, NarfMemory};
