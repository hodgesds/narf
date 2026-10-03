//! The syscall interceptor that hosts one Reverie Tool for one run.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;
use narf_userspace::handlers::tool_view;
use narf_userspace::syscall::{
    NativeSyscallTransition, SyscallInterception, SyscallInterceptor, SyscallInvocation,
    SyscallReturn,
};
use reverie::syscalls::Sysno;
use reverie::{ExitStatus, GlobalTool, Pid, Tool};
use reverie_narf_core::{
    Disposition, NarfFatal, NarfSyscallRequest, NarfToolHost, SyscallEntry, TaskLock, TaskTable,
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
    /// The `wait4` status the kernel reported.
    pub wstatus: i32,
    /// Whether this was its process's last thread.
    pub process_exited: bool,
}

type Host<T> = NarfToolHost<T, IrqSpinTaskLock<TaskTable<T>>>;
type Config<T> = <<T as Tool>::GlobalState as GlobalTool>::Config;

struct Inner<T: Tool> {
    host: Host<T>,
    /// Scheduler task id to Linux thread ID of every task the host tracks.
    hosted: IrqSafeSpinLock<BTreeMap<u64, Pid>>,
    exits: IrqSafeSpinLock<Vec<TaskExitRecord>>,
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
}

impl<T: Tool> Clone for ReverieInterceptor<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
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

/// The syscalls Narf's vDSO answers without entering the kernel unless its
/// clock mode routes them through syscalls (`verification/data/vdso/vdso.c`).
const VDSO_SYSCALLS: [Sysno; 4] = [
    Sysno::clock_gettime,
    Sysno::gettimeofday,
    Sysno::time,
    Sysno::getcpu,
];

/// Stops the run on a fatal host error.
///
/// Every [`NarfFatal`] means the core refused to guess what the Tool or the
/// kernel meant; resuming the task could let it observe a result the Tool did
/// not produce, so the kernel stops instead.
fn fatal(context: &str, error: NarfFatal) -> ! {
    panic!("reverie-narf fatal in {context}: {error:?}")
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
        Ok(Self {
            inner: Arc::new(Inner {
                host: Host::<T>::new(config)?,
                hosted: IrqSafeSpinLock::new(BTreeMap::new()),
                exits: IrqSafeSpinLock::new(Vec::new()),
            }),
        })
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
        Ok(())
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

    fn hosted_tid(&self, task_id: u64) -> Option<Pid> {
        self.inner.hosted.lock().get(&task_id).copied()
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
        if self.hosted_tid(invocation.task_id).is_none() {
            return SyscallInterception::Continue;
        }
        let request = request_of(invocation);
        let entry = if invocation.park_reexecution {
            SyscallEntry::reexecution(request)
        } else {
            SyscallEntry::new(request)
        };
        let mut kernel = self.services(invocation.task_id, native, Some(invocation.raw_number));
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
            Err(error) => fatal("handle_syscall", error),
        }
    }

    fn on_task_start(&self, task_id: u64, native: &mut dyn NativeSyscallTransition) {
        if self.hosted_tid(task_id).is_none() {
            return;
        }
        let mut kernel = self.services(task_id, native, None);
        let outcome = self.inner.host.handle_thread_start(&mut kernel);
        self.adopt_created(&mut kernel);
        if let Err(error) = outcome {
            fatal("handle_thread_start", error);
        }
    }

    fn on_task_exec(&self, task_id: u64, native: &mut dyn NativeSyscallTransition) {
        if self.hosted_tid(task_id).is_none() {
            return;
        }
        let mut kernel = self.services(task_id, native, None);
        let outcome = self.inner.host.handle_post_exec(&mut kernel);
        self.adopt_created(&mut kernel);
        if let Err(error) = outcome {
            fatal("handle_post_exec", error);
        }
    }

    fn on_task_exit(&self, task_id: u64, _pid: u64, wstatus: i32) {
        let Some(tid) = self.inner.hosted.lock().remove(&task_id) else {
            return;
        };
        match self
            .inner
            .host
            .task_exited(tid, ExitStatus::from_raw(wstatus))
        {
            Ok(exit) => self.inner.exits.lock().push(TaskExitRecord {
                task_id,
                tid,
                wstatus,
                process_exited: exit.process_exited,
            }),
            Err(error) => fatal("task_exited", error),
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
