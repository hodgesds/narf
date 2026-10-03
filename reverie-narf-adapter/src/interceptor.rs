//! The syscall interceptor that hosts one Reverie Tool for one run.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Waker};

use narf_lib::sync::IrqSafeSpinLock;
use narf_userspace::handlers::tool_view;
use narf_userspace::syscall::{
    NativeSyscallTransition, SyscallInterception, SyscallInterceptor, SyscallInvocation,
    SyscallReturn,
};
use narf_userspace::{
    DeferredInstruction, InstructionInterception, InstructionInterceptor, InstructionInvocation,
    InstructionResult, InstructionSubscriptions, NondeterministicInstruction,
};
use reverie::syscalls::Sysno;
use reverie::{ExitStatus, GlobalTool, Pid, Rdtsc, Tool};
use reverie_narf_core::{
    Disposition, NarfFatal, NarfSyscallRequest, NarfToolHost, RdtscOutcome, SyscallEntry, TaskLock,
    TaskTable,
};
use reverie_narf_tools::LineSink;

use crate::services::NarfKernelServices;

/// The host's task-table lock: an interrupt-safe spin lock.
///
/// The host holds it only for table lookups and updates, never while a Tool
/// callback runs, so no callback can spin on it.
pub struct IrqSpinTaskLock<V>(IrqSafeSpinLock<V>);

// SAFETY: `IrqSafeSpinLock` serializes every access to the wrapped value, so
// sharing the lock across CPUs is sound whenever the value itself may move
// between them.
unsafe impl<V: Send> Sync for IrqSpinTaskLock<V> {}

impl<V> core::fmt::Debug for IrqSpinTaskLock<V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IrqSpinTaskLock").finish_non_exhaustive()
    }
}

impl<V: Send> TaskLock<V> for IrqSpinTaskLock<V> {
    fn new(value: V) -> Self {
        Self(IrqSafeSpinLock::new(value))
    }

    fn with<R>(&self, f: impl FnOnce(&mut V) -> R) -> R {
        f(&mut self.0.lock())
    }
}

/// One finished task, as the interceptor reported it to the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskExitRecord {
    /// Scheduler task id.
    pub task_id: u64,
    /// Root-namespace Linux thread ID.
    pub tid: Pid,
    /// The thread's own wait status, as the kernel reported it.
    pub wstatus: i32,
    /// The process's `wait4` status as staged when the thread exited; final
    /// for its last thread.
    pub process_wstatus: i32,
    /// Whether this was its process's last thread.
    pub process_exited: bool,
}

type Host<T> = NarfToolHost<T, IrqSpinTaskLock<TaskTable<T>>>;
type Config<T> = <<T as Tool>::GlobalState as GlobalTool>::Config;

struct Inner<T: Tool> {
    host: Host<T>,
    /// Scheduler task id to Linux thread ID of every task the host tracks.
    hosted: IrqSafeSpinLock<BTreeMap<u64, Pid>>,
    /// Set once the root is in `hosted` (see [`ReverieInterceptor::host_root`]).
    root_hosted: AtomicBool,
    exits: IrqSafeSpinLock<Vec<TaskExitRecord>>,
    /// Set once a contained fatal has aborted the run (see [`FatalKind`]).
    aborted: AtomicBool,
    /// The first abort's reason, as logged.
    abort_reason: IrqSafeSpinLock<Option<String>>,
}

impl<T: Tool> Inner<T> {
    /// Why a background task must stop now, if it must (see
    /// [`ReverieInterceptor::spawn_background`]).
    fn background_stop(&self, handles: &Weak<()>) -> Option<BackgroundEnd> {
        if self.root_hosted.load(Ordering::Acquire) && self.hosted.lock().is_empty() {
            return Some(BackgroundEnd::RunOver);
        }
        if handles.strong_count() == 0 {
            return Some(BackgroundEnd::HandlesDropped);
        }
        None
    }

    /// Handles a fatal the host returned for `context`: aborts the run for a
    /// [`FatalKind::Contained`] one, panics for an invariant violation.
    fn fatal(&self, context: &str, error: NarfFatal) {
        match fatal_kind(&error) {
            FatalKind::Invariant => panic!("reverie-narf fatal in {context}: {error:?}"),
            FatalKind::Contained => self.abort(context, error),
        }
    }

    /// Aborts the run: logs the reason, and kills every hosted process with
    /// `SIGKILL`, as Linux kills a tracee whose tracer dies. Tasks the host
    /// adopts later are killed when they next reach the interceptor (see
    /// [`Self::kill_if_aborted`]). The host keeps tracking every task, so each
    /// exit still reaches [`NarfToolHost::task_exited`].
    fn abort(&self, context: &str, error: NarfFatal) {
        let reason = alloc::format!(
            "reverie-narf: aborting the hosted process tree after {context}: {error:?}"
        );
        let mut line = reason.clone();
        line.push('\n');
        narf_console::write_str(&line);
        {
            let mut slot = self.abort_reason.lock();
            if slot.is_none() {
                *slot = Some(reason);
            }
        }
        self.aborted.store(true, Ordering::Release);
        // Copy the task ids out first: the identity lookup takes the
        // kernel's task maps, which must not nest inside `hosted`.
        let tasks: Vec<u64> = self.hosted.lock().keys().copied().collect();
        let mut pids: Vec<u64> = tasks
            .into_iter()
            .filter_map(|task_id| tool_view::linux_task_ids(task_id).map(|ids| ids.pid))
            .collect();
        pids.sort_unstable();
        pids.dedup();
        for pid in pids {
            tool_view::kill_process_sigkill(pid);
        }
    }

    /// After an abort, kills hosted task `task_id`'s process and reports
    /// `true`, so the caller runs nothing of the Tool's for it. This covers a
    /// task created after the abort's kill; a task that was in user mode on
    /// another CPU when the kill was sent, which the kill does not
    /// interrupt, if its next kernel entry is a trapped `rdtsc`; and a task
    /// whose own `exit` would otherwise still run (the dispatcher never
    /// withholds an exit unless `SIGKILL` is already pending on the task).
    fn kill_if_aborted(&self, task_id: u64) -> bool {
        if !self.aborted.load(Ordering::Acquire) {
            return false;
        }
        if let Some(ids) = tool_view::linux_task_ids(task_id) {
            tool_view::kill_process_sigkill(ids.pid);
        }
        true
    }

    fn hosted_tid(&self, task_id: u64) -> Option<Pid> {
        self.hosted.lock().get(&task_id).copied()
    }

    fn services<'a>(
        &self,
        task_id: u64,
        native: &'a mut dyn NativeSyscallTransition,
        raw_number: Option<u32>,
    ) -> NarfKernelServices<'a> {
        let ids = tool_view::linux_task_ids(task_id)
            .expect("reverie-narf hosted task lost its Linux identity");
        NarfKernelServices::new(native, task_id, ids, raw_number)
    }
}

/// Hosts Tool `T` for one run at Narf's syscall dispatcher.
///
/// Only tasks the host tracks are forwarded: the root registered with
/// [`Self::host_root`] and, transitively, every task a hosted task creates.
/// All other tasks pass through untouched. Cloning shares the same host, so
/// the kernel's syscall table can own one handle while the caller keeps
/// another to inspect the Tool's global state.
pub struct ReverieInterceptor<T: Tool> {
    inner: Arc<Inner<T>>,
    /// Shared by every handle and held by nothing else: a background task
    /// keeps only a [`Weak`] to it, so it can tell when the last handle is
    /// gone (see [`Self::spawn_background`]).
    handles: Arc<()>,
}

impl<T: Tool> Clone for ReverieInterceptor<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            handles: self.handles.clone(),
        }
    }
}

impl<T: Tool> core::fmt::Debug for ReverieInterceptor<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReverieInterceptor")
            .field("hosted", &*self.inner.hosted.lock())
            .field("exits", &*self.inner.exits.lock())
            .finish_non_exhaustive()
    }
}

/// Why a task started by [`ReverieInterceptor::spawn_background`] ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackgroundEnd {
    /// Its future completed.
    Completed,
    /// The run was over first; the future was dropped unfinished.
    RunOver,
    /// Every handle to the interceptor was gone first; the future was
    /// dropped unfinished.
    HandlesDropped,
}

/// The future a background task polls, borrowing the run's global state.
pub type BackgroundFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// A task started by [`ReverieInterceptor::spawn_background`]. The task runs
/// on whether or not this is kept.
#[derive(Clone, Debug)]
pub struct BackgroundTask {
    end: Arc<IrqSafeSpinLock<Option<BackgroundEnd>>>,
}

impl BackgroundTask {
    /// Why the task ended, or `None` while it runs.
    pub fn end(&self) -> Option<BackgroundEnd> {
        *self.end.lock()
    }
}

/// The syscalls Narf's vDSO answers without entering the kernel unless its
/// clock mode routes them through syscalls (`verification/data/vdso/vdso.c`).
const VDSO_SYSCALLS: [Sysno; 4] = [
    Sysno::clock_gettime,
    Sysno::gettimeofday,
    Sysno::time,
    Sysno::getcpu,
];

/// Linux `EINTR`: what a hosted syscall of an aborted run returns. The
/// task never sees it, because its pending `SIGKILL` is delivered first on
/// the syscall's return path.
const LINUX_EINTR: i64 = 4;

/// What a [`NarfFatal`] stops.
///
/// Every `NarfFatal` means the core refused to guess what the Tool or the
/// kernel meant, so no hosted task may resume as if nothing had happened.
/// What a Tool or a guest can cause stops only the hosted process tree; a
/// broken kernel or host invariant stops the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FatalKind {
    /// The Tool misbehaved, or the guest drove a Tool into a state the
    /// backend cannot host. The run is aborted: every hosted process is
    /// killed with `SIGKILL`, and the kernel keeps running.
    Contained,
    /// The kernel or the host broke an invariant, so no state can be
    /// trusted. The kernel panics.
    Invariant,
}

/// Sorts each [`NarfFatal`] into what it stops. The match is exhaustive, so a
/// new variant must be sorted here before the adapter builds.
fn fatal_kind(error: &NarfFatal) -> FatalKind {
    match error {
        NarfFatal::ToolSuspended
        | NarfFatal::Tool(_)
        | NarfFatal::InvalidErrno(_)
        | NarfFatal::TransitionAfterTerminal
        | NarfFatal::InjectParked { .. }
        | NarfFatal::TransitionAfterInterruption
        | NarfFatal::DaemonizeRefused(_)
        | NarfFatal::PostExec(_)
        | NarfFatal::TailInjectOutsideSyscall
        | NarfFatal::Rdtsc(_)
        | NarfFatal::RdtscContextManaged => FatalKind::Contained,
        NarfFatal::OriginalAlreadyExecuted
        | NarfFatal::ContinuationKernelMismatch
        | NarfFatal::UnexpectedReexecution
        | NarfFatal::ReexecutionMismatch { .. }
        | NarfFatal::RecursiveEntry(_)
        | NarfFatal::UnknownTask(_)
        | NarfFatal::DuplicateTask(_)
        | NarfFatal::CreatedTaskMismatch(_)
        | NarfFatal::ExitDuringCallback(_)
        | NarfFatal::ProcessToolShared(_)
        // Only a host built with `NarfToolHost::new_delivering_rdtsc`, whose
        // Tool subscribed, gets RDTSC events (`ReverieInterceptor::with_rdtsc`).
        | NarfFatal::UnexpectedRdtsc
        // Refused by `NarfToolHost::new`, before any guest runs.
        | NarfFatal::UnsupportedSubscription
        | NarfFatal::UnsupportedThreadOwnership
        | NarfFatal::UnsupportedSignalDequeues => FatalKind::Invariant,
    }
}

/// The result a hosted syscall of an aborted run returns (see
/// [`LINUX_EINTR`]).
fn aborted_return() -> SyscallInterception {
    SyscallInterception::Complete(SyscallReturn::ok((-LINUX_EINTR) as u64))
}

fn request_of(invocation: &SyscallInvocation) -> NarfSyscallRequest {
    let args = invocation.args;
    NarfSyscallRequest {
        number: invocation.raw_number,
        args: [
            args.arg0, args.arg1, args.arg2, args.arg3, args.arg4, args.arg5,
        ],
    }
}

impl<T: Tool + 'static> ReverieInterceptor<T> {
    /// Creates the run's host and the Tool's global state from `config`,
    /// exactly once for the run.
    pub fn new(config: Config<T>) -> Result<Self, NarfFatal> {
        Self::with_tool_constructor(config, T::new)
    }

    /// [`Self::new`], with every hosted process's Tool built by `new_tool`
    /// instead of `T::new` (see [`NarfToolHost::with_tool_constructor`]).
    pub fn with_tool_constructor(
        config: Config<T>,
        new_tool: fn(Pid, &Config<T>) -> T,
    ) -> Result<Self, NarfFatal> {
        Ok(Self::from_host(
            Host::<T>::new(config)?.with_tool_constructor(new_tool),
        ))
    }

    /// [`Self::with_tool_constructor`], for a Tool that may subscribe to
    /// RDTSC events. The host is built with
    /// [`NarfToolHost::new_delivering_rdtsc`]. If the Tool's subscription for
    /// `config` includes RDTSC events, the second value is the
    /// [`RdtscInterceptor`] that delivers them; otherwise it is `None`, and
    /// the host delivers none.
    ///
    /// The caller installs the interceptor with
    /// [`narf_userspace::try_install_instruction_interceptor`] before any
    /// guest task exists, and must not run the guest if that fails: the
    /// Tool would then miss every event it subscribed to. Nothing checks
    /// either (see "Silently absent" in the crate documentation). The
    /// kernel keeps an installed interceptor for its lifetime, so only the
    /// first such run of a boot can install one.
    pub fn with_rdtsc(
        config: Config<T>,
        new_tool: fn(Pid, &Config<T>) -> T,
    ) -> Result<(Self, Option<RdtscInterceptor<T>>), NarfFatal> {
        let delivers = T::subscriptions(&config).has_rdtsc();
        let host = Host::<T>::new_delivering_rdtsc(config)?;
        Ok(Self::delivering_rdtsc(
            host.with_tool_constructor(new_tool),
            delivers,
        ))
    }

    /// [`Self::with_rdtsc`], hosting `global`, a global state the caller
    /// created for `config`, instead of creating one (see
    /// [`NarfToolHost::with_global_state`]): for a Tool whose global state
    /// is made another way, such as Detcore's, whose scheduler runs in a
    /// future beside the callbacks ([`Self::spawn_background`]). Refuses the
    /// same Tools as [`Self::with_rdtsc`], dropping `global`.
    pub fn with_global_state_and_rdtsc(
        config: Config<T>,
        global: T::GlobalState,
        new_tool: fn(Pid, &Config<T>) -> T,
    ) -> Result<(Self, Option<RdtscInterceptor<T>>), NarfFatal> {
        let delivers = T::subscriptions(&config).has_rdtsc();
        let host = Host::<T>::with_global_state_delivering_rdtsc(config, global)?;
        Ok(Self::delivering_rdtsc(
            host.with_tool_constructor(new_tool),
            delivers,
        ))
    }

    /// The interceptor for `host`, built to deliver RDTSC events, and, if
    /// `delivers` (the Tool subscribed to them), the [`RdtscInterceptor`]
    /// that delivers them.
    fn delivering_rdtsc(host: Host<T>, delivers: bool) -> (Self, Option<RdtscInterceptor<T>>) {
        let this = Self::from_host(host);
        let rdtsc = delivers.then(|| RdtscInterceptor {
            inner: this.inner.clone(),
        });
        (this, rdtsc)
    }

    fn from_host(host: Host<T>) -> Self {
        Self {
            inner: Arc::new(Inner {
                host,
                hosted: IrqSafeSpinLock::new(BTreeMap::new()),
                root_hosted: AtomicBool::new(false),
                exits: IrqSafeSpinLock::new(Vec::new()),
                aborted: AtomicBool::new(false),
                abort_reason: IrqSafeSpinLock::new(None),
            }),
            handles: Arc::new(()),
        }
    }

    /// Why the run was aborted, if it was: the reason logged for the first
    /// contained fatal.
    pub fn abort_reason(&self) -> Option<String> {
        self.inner.abort_reason.lock().clone()
    }

    /// Registers the run's root task, which must already have its Linux
    /// identity and must not have run yet (call between preparing and
    /// spawning it).
    pub fn host_root(&self, task_id: u64) -> Result<(), NarfFatal> {
        let ids = tool_view::linux_task_ids(task_id)
            .expect("reverie-narf root task has no Linux identity");
        let tid = Pid::from_raw(ids.tid as i32);
        self.inner
            .host
            .register_root(tid, Pid::from_raw(ids.pid as i32))?;
        self.inner.hosted.lock().insert(task_id, tid);
        // After the insert, so a background task never sees the root hosted
        // and `hosted` still empty.
        self.inner.root_hosted.store(true, Ordering::Release);
        Ok(())
    }

    /// Starts a kernel task that polls the future `start` makes from the
    /// run's global state, for a Tool whose global state does its work in a
    /// future of its own beside the callbacks. Detcore's scheduler, which
    /// runs that way on an external executor (`run_external_scheduler` in
    /// `detcore/src/tool_global.rs`), is the intended user.
    ///
    /// The task polls as detcore-dbt's `run_cooperative`
    /// (`detcore-dbt/src/lib.rs`) does: with a no-op waker, and, while the
    /// future is pending, yielding to the other tasks between two polls. The
    /// yield is busy: the task stays runnable, and `narf_scheduler::spawn`
    /// pins it to the boot CPU, which does not idle while it runs.
    ///
    /// `start` is called once, when the task first runs, whatever the rules
    /// below say; they apply to the future it returns. Before each poll, the
    /// task stops, dropping the future unfinished, if either holds:
    /// * the run is over: the root was hosted (see [`Self::host_root`]) and
    ///   no hosted task is left. The last task's exit hooks may still be
    ///   running on another CPU; they are polled once, so none can wait for
    ///   the future.
    /// * every handle to this interceptor is gone, the syscall table's
    ///   included.
    ///
    /// An aborted run needs no rule of its own: the abort kills every hosted
    /// process, so the run is over once they have exited.
    ///
    /// Until a root is hosted only the second rule applies, so a caller that
    /// starts a background future and then hosts no root, because
    /// [`Self::host_root`] failed say, must drop every handle to this
    /// interceptor; otherwise the task keeps the boot CPU busy for good. The
    /// boot host (`boot.rs`) keeps a handle in the syscall table for the
    /// life of the boot, so boot code may start a background future only
    /// after `host_root` has succeeded.
    ///
    /// No user task is running while the future is polled: it runs on the
    /// kernel's own page tables, not on any hosted task's, and every access
    /// through a [`crate::NarfMemory`] it uses is refused with `EFAULT`.
    pub fn spawn_background<F>(&self, start: F) -> BackgroundTask
    where
        F: for<'a> FnOnce(&'a T::GlobalState) -> BackgroundFuture<'a> + Send + 'static,
    {
        let end = Arc::new(IrqSafeSpinLock::new(None));
        let task = BackgroundTask { end: end.clone() };
        let inner = self.inner.clone();
        let handles = Arc::downgrade(&self.handles);
        narf_scheduler::spawn(async move {
            let reason = run_background(&inner, &handles, start).await;
            *end.lock() = Some(reason);
        });
        task
    }

    /// The run's host.
    pub fn host(&self) -> &Host<T> {
        &self.inner.host
    }

    /// Tasks the host is tracking now.
    pub fn hosted_tasks(&self) -> usize {
        self.inner.hosted.lock().len()
    }

    /// Every task exit reported so far, in order.
    pub fn exits(&self) -> Vec<TaskExitRecord> {
        self.inner.exits.lock().clone()
    }

    /// A handle for [`narf_userspace::syscall::SyscallTable::install_interceptor`].
    pub fn boxed(&self) -> Box<dyn SyscallInterceptor> {
        Box::new(self.clone())
    }

    fn adopt_created(&self, kernel: &mut NarfKernelServices<'_>) {
        let created = kernel.take_created();
        if !created.is_empty() {
            let mut hosted = self.inner.hosted.lock();
            for (task_id, tid) in created {
                hosted.insert(task_id, tid);
            }
        }
    }
}

/// The body of a background task (see [`ReverieInterceptor::spawn_background`]).
/// The future is dropped here, before the task releases `inner`.
async fn run_background<T, F>(inner: &Inner<T>, handles: &Weak<()>, start: F) -> BackgroundEnd
where
    T: Tool,
    F: for<'a> FnOnce(&'a T::GlobalState) -> BackgroundFuture<'a>,
{
    let mut future = start(inner.host.global());
    loop {
        if let Some(end) = inner.background_stop(handles) {
            return end;
        }
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return BackgroundEnd::Completed;
        }
        narf_scheduler::yield_now().await;
    }
}

impl<T: Tool + 'static> SyscallInterceptor for ReverieInterceptor<T> {
    /// A Tool subscribed to a syscall the vDSO answers (`clock_gettime`,
    /// `gettimeofday`, `time`, `getcpu`) must see the guest's vDSO calls to it,
    /// which would otherwise never enter the kernel. reverie-ptrace rewrites
    /// the subscribed vDSO entry points into syscalls for the same reason
    /// (`reverie-ptrace/src/vdso.rs`, `is_patch_required` and `vdso_patch`,
    /// re-exported as `patch_current_vdso` at `reverie-ptrace/src/lib.rs:76`).
    /// Narf's switch is the vvar clock mode, which covers all four entry
    /// points at once: a subscription to any one makes the others syscalls
    /// too, which the Tool does not see and whose results are unchanged.
    /// `clock_getres` already uses its syscall in Narf's vDSO.
    fn intercepts_vdso_calls(&self) -> bool {
        VDSO_SYSCALLS
            .iter()
            .any(|&sysno| self.inner.host.is_subscribed(sysno))
    }

    fn on_syscall_enter(
        &self,
        invocation: &SyscallInvocation,
        native: &mut dyn NativeSyscallTransition,
    ) -> SyscallInterception {
        if self.inner.hosted_tid(invocation.task_id).is_none() {
            return SyscallInterception::Continue;
        }
        if self.inner.kill_if_aborted(invocation.task_id) {
            return aborted_return();
        }
        let request = request_of(invocation);
        let entry = if invocation.park_reexecution {
            SyscallEntry::reexecution(request)
        } else {
            SyscallEntry::new(request)
        };
        let mut kernel =
            self.inner
                .services(invocation.task_id, native, Some(invocation.raw_number));
        let disposition = self.inner.host.handle_syscall(&mut kernel, entry);
        // A created task is held back from the scheduler until this callback
        // returns, so adopting it here precedes its first instruction.
        self.adopt_created(&mut kernel);
        match disposition {
            Ok(Disposition::Complete(value)) => {
                SyscallInterception::Complete(SyscallReturn::ok(value as u64))
            }
            // The transition that took the context already ran through the
            // kernel-owned capability; the dispatcher publishes its outcome.
            Ok(Disposition::ContextManaged) => SyscallInterception::Continue,
            Err(error) => {
                self.inner.fatal("handle_syscall", error);
                // The task's `SIGKILL` is delivered on this syscall's return
                // path. If a transition of the callback took the context (a
                // parked inject, say), the dispatcher keeps that instead.
                aborted_return()
            }
        }
    }

    fn on_task_start(&self, task_id: u64, native: &mut dyn NativeSyscallTransition) {
        if self.inner.hosted_tid(task_id).is_none() || self.inner.kill_if_aborted(task_id) {
            return;
        }
        let mut kernel = self.inner.services(task_id, native, None);
        let outcome = self.inner.host.handle_thread_start(&mut kernel);
        self.adopt_created(&mut kernel);
        if let Err(error) = outcome {
            self.inner.fatal("handle_thread_start", error);
        }
    }

    fn on_task_exec(&self, task_id: u64, native: &mut dyn NativeSyscallTransition) {
        if self.inner.hosted_tid(task_id).is_none() || self.inner.kill_if_aborted(task_id) {
            return;
        }
        let mut kernel = self.inner.services(task_id, native, None);
        let outcome = self.inner.host.handle_post_exec(&mut kernel);
        self.adopt_created(&mut kernel);
        if let Err(error) = outcome {
            self.inner.fatal("handle_post_exec", error);
        }
    }

    fn on_task_exit(&self, task_id: u64, _pid: u64, wstatus: i32, process_wstatus: i32) {
        let Some(tid) = self.inner.hosted.lock().remove(&task_id) else {
            return;
        };
        match self.inner.host.task_exited(
            tid,
            ExitStatus::from_raw(wstatus),
            ExitStatus::from_raw(process_wstatus),
        ) {
            Ok(exit) => self.inner.exits.lock().push(TaskExitRecord {
                task_id,
                tid,
                wstatus,
                process_wstatus,
                process_exited: exit.process_exited,
            }),
            Err(error) => self.inner.fatal("task_exited", error),
        }
    }
}

/// Delivers the `rdtsc` and `rdtscp` instructions of hosted tasks to the Tool
/// of a [`ReverieInterceptor`] built with [`ReverieInterceptor::with_rdtsc`],
/// as Narf's [`InstructionInterceptor`].
///
/// Once the interceptor is installed
/// ([`narf_userspace::try_install_instruction_interceptor`]), the kernel traps
/// every task's `rdtsc` and `rdtscp`, hosted or not, and calls it. Every trap
/// is deferred, because finding the trapping task among the hosted ones takes
/// a spin lock, which the masked [`InstructionInterceptor::on_instruction_enter`]
/// must not take. The deferred callback runs on the trapping task's own
/// kernel stack, as a syscall callback does.
///
/// A task the host does not track executes the instruction natively. A
/// hosted task's event goes to [`NarfToolHost::handle_rdtsc`], and the Tool's
/// value completes the instruction: the counter in EDX:EAX and, for `rdtscp`,
/// the Tool's `aux` in ECX, or 0 if it gave none, as reverie-ptrace does.
///
/// If the task is ending (the host answers `RdtscOutcome::ContextManaged`),
/// the guest never sees the answer, because the task dies before it returns
/// to user mode: if a transition of the callback took the task's context,
/// the kernel writes nothing and leaves RIP on the instruction; otherwise
/// it executes the instruction natively and then delivers the pending
/// `SIGKILL`. A fatal the host returns is handled as in a syscall callback:
/// a contained one aborts the run, and the instruction executes natively
/// unless a transition took the task's context. The task never sees a
/// result either way, because the abort's `SIGKILL` is delivered first.
///
/// The kernel keeps an installed interceptor for its lifetime, and with it
/// the run's host.
pub struct RdtscInterceptor<T: Tool> {
    inner: Arc<Inner<T>>,
}

impl<T: Tool> core::fmt::Debug for RdtscInterceptor<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RdtscInterceptor").finish_non_exhaustive()
    }
}

// SAFETY: `on_instruction_enter` and `on_instruction_return`, the two
// callbacks under the masked contract, keep the trait's defaults or return a
// constant: neither allocates, takes a lock or touches the guest. Everything
// else runs in `on_instruction_deferred`, which the contract exempts.
unsafe impl<T: Tool + 'static> InstructionInterceptor for RdtscInterceptor<T> {
    fn subscriptions(&self) -> InstructionSubscriptions {
        InstructionSubscriptions::RDTSC.union(InstructionSubscriptions::RDTSCP)
    }

    fn on_instruction_enter(&self, _: &InstructionInvocation) -> InstructionInterception {
        InstructionInterception::Defer
    }

    fn on_instruction_deferred(
        &self,
        invocation: &InstructionInvocation,
        native: &mut dyn NativeSyscallTransition,
    ) -> DeferredInstruction {
        let task_id = invocation.task_id;
        if self.inner.hosted_tid(task_id).is_none() || self.inner.kill_if_aborted(task_id) {
            return DeferredInstruction::Native;
        }
        let request = match invocation.instruction {
            NondeterministicInstruction::Rdtsc => Rdtsc::Tsc,
            NondeterministicInstruction::Rdtscp => Rdtsc::Tscp,
            // Not subscribed; the kernel delivers only what the interceptor
            // subscribed to.
            _ => return DeferredInstruction::Native,
        };
        // The kernel refuses a task-creating inject here with `-ENOSYS`, so
        // there is no created task to adopt.
        let mut kernel = self.inner.services(task_id, native, None);
        match self.inner.host.handle_rdtsc(&mut kernel, request) {
            Ok(RdtscOutcome::Complete(result)) => DeferredInstruction::Complete(match request {
                Rdtsc::Tsc => InstructionResult::Rdtsc { value: result.tsc },
                Rdtsc::Tscp => InstructionResult::Rdtscp {
                    value: result.tsc,
                    aux: result.aux.unwrap_or(0),
                },
            }),
            // The task is ending and dies before it returns to user mode, so
            // the guest never sees the answer.
            Ok(RdtscOutcome::ContextManaged) => DeferredInstruction::Native,
            Err(error) => {
                self.inner.fatal("handle_rdtsc", error);
                DeferredInstruction::Native
            }
        }
    }
}

/// A [`LineSink`] that writes each line to the kernel console with one
/// console write, so lines from different CPUs never interleave.
#[derive(Debug)]
pub struct ConsoleSink;

impl LineSink for ConsoleSink {
    fn emit(line: &str) {
        let mut buffer = String::with_capacity(line.len() + 1);
        buffer.push_str(line);
        buffer.push('\n');
        narf_console::write_str(&buffer);
    }
}
