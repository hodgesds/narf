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
//!   events to it.
//!
//! There is no IPC, ptrace emulation, signal, binary rewriting or polling: the
//! kernel calls the interceptor, the interceptor polls the Tool's future once
//! per kernel entry, and every Tool-to-kernel operation is a direct call. A
//! Tool whose inject parks the task (a blocking read, say) keeps its future in
//! the host, which polls it again, on the task's own stack, when the kernel
//! re-executes the parked syscall.
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
//! * **CPUID and RDTSC subscriptions.** `NarfToolHost::new` returns
//!   `NarfFatal::UnsupportedSubscription`, so [`ReverieInterceptor::new`]
//!   fails and no guest runs. Host-owned threads
//!   (`UnsupportedThreadOwnership`) and signal-dequeue observation
//!   (`UnsupportedSignalDequeues`) are refused the same way.
//!
//! ## Silently absent (not fail-closed)
//!
//! * **Signal events.** The Tool's `handle_signal_event` is never called.
//!   The kernel delivers every signal natively, and the Tool never sees it.
//! * **fs_base and gs_base.** `KernelServices::regs` reports `fs_base`,
//!   `gs_base` and the `ds`/`es`/`fs`/`gs` selectors as 0. A Tool that
//!   reads them gets 0, not the guest's TLS base.
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
//! Every `NarfFatal` returned to the interceptor goes to `fatal`, which
//! **panics the kernel**. The panic handler (`console::panic_sink`) logs the
//! panic and halts, so it stops the kernel, not just the hosted process
//! tree. The kinds that a Tool or a guest can reach:
//!
//! | Fatal | Cause | Can the guest trigger it? |
//! |---|---|---|
//! | `Tool(Error)` | The Tool returned an error that is not an errno. | Only through a Tool that turns guest input into such an error. |
//! | `InvalidErrno` | The Tool returned an errno outside `1..=4095`. | No; Tool only. |
//! | `InjectParked`, in a lifecycle callback | A non-tail inject parked the task (a blocking `read`, say). No guest syscall exists to re-execute. | Yes, given a Tool that makes a blocking inject there, because the guest controls whether the call would block. |
//! | `ToolSuspended` | The Tool's future was pending without a terminal transition and without a parked inject. | No; Tool only. |
//! | `TransitionAfterInterruption` | After a signal interrupted its parked inject (which returned `ERESTARTSYS`), the Tool ran another syscall. | Yes, given such a Tool: a signal sent during the parked inject is enough. |
//! | `ContinuationKernelMismatch` | A continuation resumed with a different memory type. | No. This adapter has one memory type (`NarfMemory`). |
//!
//! The other variants (`UnknownTask`, `DuplicateTask`, `RecursiveEntry`,
//! `ExitDuringCallback`, re-execution mismatches, and so on) are kernel/host
//! invariant violations, not guest or Tool inputs.
//!
//! ## Differences from reverie-ptrace
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
//!   returns. The parent's vfork wait is deferred until then
//!   (`defer_vfork_wait`). So the parent's inject returns the child's TID
//!   immediately, and the rest of the parent's callback runs before the
//!   child's `handle_thread_start` and before any of the child's syscalls.
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
//! ## Limits of the in-kernel tests
//!
//! * **`signal_init()`.** Kernel-test boots do not set up the signal tables,
//!   so a raise there is silently dropped. The three signal tests create them
//!   with `narf_userspace::signal_init()` through a guard (`SignalTables`)
//!   that removes, on every return path, the tables it created. Other
//!   reverie-narf tests run without signal delivery, unless an earlier
//!   subsystem's test in the same boot left the tables set up.
//! * **Leak check.** Every reverie-narf test is registered through
//!   `reverie_narf_test!`, which fails the test by name if it left the signal
//!   tables, the vDSO clock routing, user-task SMP placement or work stealing
//!   different from how it found them.
//! * **Reclaim scope.** After each run, the test harness's `reclaim_run`
//!   checks two things: every address space the guest's tasks exited from
//!   was dropped, and the root image's private frames reached a COW count of
//!   0. Shared regions are left out, and so is the vDSO region at and above
//!   `VDSO_MAP_BASE`, whose masters hold a permanent reference. Frames that
//!   forked children or exec'd images allocate are not checked, so a leak
//!   there goes unnoticed.
//! * **`reclaim_run` waits on one CPU.** `narf_rcu::sync_until` waits for
//!   every CPU to pass the grace period, but it drains only the calling
//!   CPU's drop bucket. A continuation retired on another CPU is freed only
//!   at that CPU's next quiescent point. With more than one CPU, the 4 x 1 s
//!   budget can expire first, which fails the test. This is a flake risk,
//!   not a leak.
//! * **The `cow::__test_clear` guard.** It refuses to wipe the COW count of
//!   a frame that some address space still maps, but it finds such frames
//!   only through the reverse map. If the reverse map misses a mapping (an
//!   undercount), that frame's count is wiped without the panic.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

#[cfg(target_arch = "x86_64")]
mod interceptor;
#[cfg(target_arch = "x86_64")]
mod services;
#[cfg(all(target_arch = "x86_64", feature = "kernel-test"))]
mod tests;

#[cfg(target_arch = "x86_64")]
pub use interceptor::{ConsoleSink, IrqSpinTaskLock, ReverieInterceptor, TaskExitRecord};
#[cfg(target_arch = "x86_64")]
pub use services::{map_native_outcome, NarfKernelServices, NarfMemory};
