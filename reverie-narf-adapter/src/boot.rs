//! Boot-time hosting of one Reverie Tool over Narf's login session.
//!
//! A build with frame's `reverie-narf-poc` feature reads the kernel command
//! line `reverie_tool=<name>` in boot-init. With it, frame calls [`install`]
//! while it assembles the syscall table and then spawns getty through
//! [`BootHost::host_root`], so getty, the shell getty execs and every command
//! typed into that shell are hosted by the Tool. Without it frame calls
//! nothing here, and the syscall table has no interceptor.
//!
//! The Tools are `counter1` and `counter2`, compiled unmodified from
//! `reverie-examples` (`reverie_narf_tools::counter1` and
//! `reverie_narf_tools::counter2`). counter2 also keeps a count per thread
//! and one per process, which reach its global totals through its exit
//! hooks. When each hosted thread exits it prints the line it prints on
//! Linux, where it writes it to stderr:
//!
//! ```text
//! counter2-local thread=<tid> syscalls=<n>
//! ```
//!
//! # The tally
//!
//! [`install`] wraps the [`ReverieInterceptor`] in a `Tally` that counts the
//! syscall entries the dispatcher delivers for the hosted tree. It keeps its
//! own membership and counters and reads neither the adapter's task table nor
//! the Tool's state until it reports:
//!
//! * A task is a member if it is the root, or if a member's `fork`, `vfork`,
//!   `clone` or `clone3` returned its Linux thread ID. The dispatcher keeps a
//!   task created during an interceptor call off the run queues until that
//!   call's `on_syscall_return` has run, so the return is always seen before
//!   the child starts. Membership is keyed by scheduler task id, which the
//!   scheduler never reuses; Linux process IDs are reused, because
//!   `alloc_pid` hands out the lowest free one.
//! * Every syscall entry of a member counts. The Tool sees one syscall event
//!   per entry except for two kinds: a park re-execution resumes the Tool call
//!   already in flight, and the core runs a new entry natively, without an
//!   event, when Reverie's `Sysno` does not know its number or the Tool is not
//!   subscribed to it (`NarfToolHost::handle_syscall`). So the Tool should see
//!   `entries - reexecutions - native-only` events. The tally also counts
//!   those events per member task.
//!
//! The dispatcher calls the interceptor for every guest syscall entry, through
//! the `syscall` instruction and `int 0x80` alike. The only entries it does not
//! deliver are the kernel's own re-entries on a task's behalf while an
//! interceptor call is running (`SpawnHold::try_open`), which Linux reports to
//! no tracer either.
//!
//! When the root's process has exited and no member task is live or waiting to
//! start, the tally prints its report, once:
//!
//! ```text
//! counter1-global syscalls=<N>
//! reverie-narf-boot: tally tool=counter1 entries=<E> reexecutions=<R> native-only=<U> expected-events=<E-R-U> ...
//! reverie-narf-boot: events-by-task <tid>:<events> ...
//! reverie-narf-boot: syscalls-by-number <nr>:<count> ... rest:<count>
//! reverie-narf-boot: report end
//! ```
//!
//! The first line is the one the Tool's launcher in `reverie-examples` prints
//! after a run on Linux; for counter2 it is
//!
//! ```text
//!  [counter tool] Total system calls in process tree: <N>, from <P> processes, <T> thread(s).
//! ```
//!
//! A harness compares N with `expected-events`. The events-by-task line has
//! each member task's Linux thread ID and event count, in exit order (`?` for
//! a thread ID the kernel no longer had); for counter2 the harness compares
//! those pairs with the `counter2-local` lines. A number marked `*` in the
//! by-number line runs natively, without a Tool event.
//!
//! A fork inside a nested PID namespace (frame's `container` feature) returns
//! the child's inner PID, which the tally cannot match to the child's task.
//! The child then stays unstarted in the tally's view and the report never
//! prints, rather than printing a count that leaves the child out.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;
use narf_userspace::handlers::tool_view::{self, LinuxTaskIds};
use narf_userspace::syscall::{
    NativeSyscallTransition, SyscallInterception, SyscallInterceptor, SyscallInvocation,
    SyscallReturn, SyscallTable,
};
use reverie::syscalls::Sysno;
use reverie::{GlobalTool, Pid, Tid, Tool};
use reverie_narf_core::NARF_SYSCALL_NUMBER_MASK;
use reverie_narf_tools::{counter1, counter2, LineSink};

use crate::interceptor::{ConsoleSink, ReverieInterceptor};

type Config<T> = <<T as Tool>::GlobalState as GlobalTool>::Config;

/// Syscall numbers below this are counted one by one, the rest together.
const BY_NUMBER: usize = 512;

/// Installs the Tool named `name` as `table`'s interceptor. Frame's boot-init
/// calls it after assembling the table and before publishing it.
///
/// If `name` is not a known Tool, the host refuses the Tool, or the table
/// already has an interceptor, it prints why and returns `None`, and `table`
/// is unchanged.
pub fn install(table: &mut SyscallTable, name: &str) -> Option<BootHost> {
    let installed = match name {
        "counter1" => Tally::<counter1::CounterLocal>::install(
            table,
            "counter1",
            (),
            <counter1::CounterLocal as Tool>::new,
            |host| format!("counter1-global syscalls={}", host.host().global().total()),
        ),
        "counter2" => Tally::<counter2::CounterLocal>::install(
            table,
            "counter2",
            (),
            |pid, config| {
                <counter2::CounterLocal as Tool>::new(pid, config)
                    .with_thread_exit_reporter(print_counter2_thread_exit)
            },
            |host| {
                let (total, processes, threads) = host.host().global().totals();
                format!(
                    " [counter tool] Total system calls in process tree: {total}, from \
                     {processes} processes, {threads} thread(s)."
                )
            },
        ),
        _ => Err(String::from("no such tool (known: counter1, counter2)")),
    };
    match installed {
        Ok(boot) => {
            ConsoleSink::emit(&format!(
                "reverie-narf-boot: {} installed at the syscall dispatcher",
                boot.tool
            ));
            Some(boot)
        }
        Err(reason) => {
            ConsoleSink::emit(&format!(
                "reverie-narf-boot: refused reverie_tool={name}: {reason}"
            ));
            None
        }
    }
}

/// counter2's thread-exit reporter: prints the line counter2 writes to
/// stderr on Linux (`on_exit_thread` in `reverie-examples/counter2_tool.rs`).
fn print_counter2_thread_exit(tid: Tid, syscalls: u64) {
    ConsoleSink::emit(&format!("counter2-local thread={tid} syscalls={syscalls}"));
}

/// The handle [`install`] returns, with which frame hosts the boot's root
/// process under the installed Tool.
pub struct BootHost {
    tool: &'static str,
    root: Box<dyn Root>,
}

impl core::fmt::Debug for BootHost {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BootHost")
            .field("tool", &self.tool)
            .finish_non_exhaustive()
    }
}

impl BootHost {
    /// The installed Tool's name.
    pub fn tool(&self) -> &'static str {
        self.tool
    }

    /// Makes task `task_id` the root of the hosted tree. The task must
    /// already have its Linux identity (`register_pid_task_mapping`) and must
    /// not have run yet: call this between preparing and spawning it.
    pub fn host_root(&self, task_id: u64) -> Result<(), String> {
        let pid = self.root.host_root(task_id)?;
        ConsoleSink::emit(&format!(
            "reverie-narf-boot: {} hosts the process tree of pid {pid} (task {task_id})",
            self.tool
        ));
        Ok(())
    }
}

/// [`BootHost::host_root`] for any Tool.
trait Root: Send + Sync {
    /// Registers the root and returns its Linux process ID.
    fn host_root(&self, task_id: u64) -> Result<u64, String>;
}

/// A live member task.
struct Live {
    /// Its Linux process ID.
    pid: u64,
    /// The syscall events the Tool should have seen from it so far: its new
    /// entries that do not run natively.
    events: u64,
}

/// The hosted tree as the tally sees it.
#[derive(Default)]
struct Members {
    /// The root's scheduler task id and Linux process ID, once registered.
    root: Option<(u64, u64)>,
    /// Whether every task of the root's process has exited.
    root_exited: bool,
    /// Linux thread IDs that a member's fork-like syscall returned, whose
    /// task has neither started nor exited yet.
    unstarted: BTreeSet<u64>,
    /// Live member tasks by scheduler task id.
    live: BTreeMap<u64, Live>,
    /// Live member tasks per Linux process ID.
    live_per_process: BTreeMap<u64, usize>,
    /// Each exited member task's Linux thread ID, if the kernel still had it,
    /// and its event count, in exit order.
    exited: Vec<(Option<u64>, u64)>,
    tasks_started: u64,
    tasks_exited: u64,
    /// Member tasks that exited without starting (killed before their first
    /// instruction); included in `tasks_exited`.
    exited_unstarted: u64,
    /// Member processes: counted when their first task starts, or, for a
    /// forked child killed before it started, when it exits. A process is
    /// counted again if its PID is reused by a later member process.
    processes: u64,
}

impl Members {
    fn start(&mut self, task_id: u64, pid: u64) {
        self.live.insert(task_id, Live { pid, events: 0 });
        let tasks = self.live_per_process.entry(pid).or_insert(0);
        if *tasks == 0 {
            self.processes += 1;
        }
        *tasks += 1;
        self.tasks_started += 1;
    }

    /// Records the exit of task `task_id`, whose Linux identity is `ids`,
    /// and returns whether it was a member.
    fn exit(&mut self, task_id: u64, ids: Option<LinuxTaskIds>) -> bool {
        if let Some(task) = self.live.remove(&task_id) {
            self.tasks_exited += 1;
            self.exited.push((ids.map(|ids| ids.tid), task.events));
            if let Some(tasks) = self.live_per_process.get_mut(&task.pid) {
                *tasks -= 1;
                if *tasks == 0 {
                    self.live_per_process.remove(&task.pid);
                    if self.root.is_some_and(|(_, root_pid)| root_pid == task.pid) {
                        self.root_exited = true;
                    }
                }
            }
            true
        } else if let Some(ids) = ids.filter(|ids| self.unstarted.remove(&ids.tid)) {
            self.tasks_exited += 1;
            self.exited_unstarted += 1;
            self.exited.push((Some(ids.tid), 0));
            // A process's first task has its process ID as its thread ID.
            if ids.tid == ids.pid {
                self.processes += 1;
            }
            true
        } else {
            false
        }
    }

    /// Whether the hosted tree has ended: the root's process has exited and
    /// no member task is live or waiting to start.
    fn ended(&self) -> bool {
        self.root_exited && self.live.is_empty() && self.unstarted.is_empty()
    }
}

struct TallyState {
    members: IrqSafeSpinLock<Members>,
    entries: AtomicU64,
    reexecutions: AtomicU64,
    native_only: AtomicU64,
    /// New (not re-executed) entries by Linux syscall number.
    by_number: [AtomicU64; BY_NUMBER],
    /// New entries whose number is `BY_NUMBER` or more.
    by_number_rest: AtomicU64,
    /// Whether the wait for the tree's last tasks has been printed.
    waiting_printed: AtomicBool,
}

/// A [`ReverieInterceptor`] with its own count of the syscall entries of the
/// tree it hosts (see the module documentation).
struct Tally<T: Tool> {
    host: ReverieInterceptor<T>,
    state: Arc<TallyState>,
    tool: &'static str,
    /// Formats the Tool's own report line from the host.
    report: fn(&ReverieInterceptor<T>) -> String,
}

impl<T: Tool> Clone for Tally<T> {
    fn clone(&self) -> Self {
        Self {
            host: self.host.clone(),
            state: self.state.clone(),
            tool: self.tool,
            report: self.report,
        }
    }
}

/// Whether the syscall `raw_number` creates a task and returns its thread ID.
fn creates_task(raw_number: u32) -> bool {
    matches!(
        Sysno::new((raw_number & NARF_SYSCALL_NUMBER_MASK) as usize),
        Some(Sysno::fork | Sysno::vfork | Sysno::clone | Sysno::clone3)
    )
}

impl<T: Tool + 'static> Tally<T> {
    /// Installs a tally around a host whose processes' Tools `new_tool`
    /// builds, and whose report line `report` formats.
    fn install(
        table: &mut SyscallTable,
        tool: &'static str,
        config: Config<T>,
        new_tool: fn(Pid, &Config<T>) -> T,
        report: fn(&ReverieInterceptor<T>) -> String,
    ) -> Result<BootHost, String> {
        let host = ReverieInterceptor::<T>::with_tool_constructor(config, new_tool)
            .map_err(|error| format!("the host refused the tool: {error:?}"))?;
        let tally = Self {
            host,
            state: Arc::new(TallyState {
                members: IrqSafeSpinLock::new(Members::default()),
                entries: AtomicU64::new(0),
                reexecutions: AtomicU64::new(0),
                native_only: AtomicU64::new(0),
                by_number: [const { AtomicU64::new(0) }; BY_NUMBER],
                by_number_rest: AtomicU64::new(0),
                waiting_printed: AtomicBool::new(false),
            }),
            tool,
            report,
        };
        table
            .install_interceptor(Box::new(tally.clone()))
            .map_err(|_| String::from("the syscall table already has an interceptor"))?;
        Ok(BootHost {
            tool,
            root: Box::new(tally),
        })
    }

    /// Whether the core runs a new entry of Linux syscall `number` natively,
    /// without a Tool event.
    fn runs_natively(&self, number: u32) -> bool {
        !Sysno::new(number as usize).is_some_and(|sysno| self.host.host().is_subscribed(sysno))
    }

    /// Counts `invocation` if its task is a member.
    fn count_entry(&self, invocation: &SyscallInvocation) {
        let number = invocation.raw_number & NARF_SYSCALL_NUMBER_MASK;
        let native = !invocation.park_reexecution && self.runs_natively(number);
        {
            let mut members = self.state.members.lock();
            let Some(task) = members.live.get_mut(&invocation.task_id) else {
                return;
            };
            if !invocation.park_reexecution && !native {
                task.events += 1;
            }
        }
        // A member's entries are counted before its exit takes `members`, and
        // the report reads the counters after the last member's exit has
        // taken it, so relaxed updates suffice.
        let state = &*self.state;
        state.entries.fetch_add(1, Ordering::Relaxed);
        if invocation.park_reexecution {
            state.reexecutions.fetch_add(1, Ordering::Relaxed);
            return;
        }
        match state.by_number.get(number as usize) {
            Some(count) => count.fetch_add(1, Ordering::Relaxed),
            None => state.by_number_rest.fetch_add(1, Ordering::Relaxed),
        };
        if native {
            state.native_only.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Prints, once, which member tasks the tree is still waiting for after
    /// the root's process has exited.
    fn print_waiting(&self, live: Vec<u64>, unstarted: Vec<u64>) {
        if self.state.waiting_printed.swap(true, Ordering::AcqRel) {
            return;
        }
        ConsoleSink::emit(&format!(
            "reverie-narf-boot: the root's process has exited; waiting for {} live member \
             tasks (pids {live:?}) and {} unstarted children (tids {unstarted:?})",
            live.len(),
            unstarted.len()
        ));
    }

    fn print_report(&self, members: &Members) {
        let state = &*self.state;
        let entries = state.entries.load(Ordering::Relaxed);
        let reexecutions = state.reexecutions.load(Ordering::Relaxed);
        let native_only = state.native_only.load(Ordering::Relaxed);
        let expected = entries.saturating_sub(reexecutions + native_only);
        let mut report = (self.report)(&self.host);
        let _ = write!(
            report,
            "\nreverie-narf-boot: tally tool={} entries={entries} reexecutions={reexecutions} \
             native-only={native_only} expected-events={expected} tasks-started={} \
             tasks-exited={} exited-unstarted={} processes={} adapter-exits={} \
             adapter-hosted={} aborted={}",
            self.tool,
            members.tasks_started,
            members.tasks_exited,
            members.exited_unstarted,
            members.processes,
            self.host.exits().len(),
            self.host.hosted_tasks(),
            if self.host.abort_reason().is_some() {
                "yes"
            } else {
                "no"
            },
        );
        report.push_str("\nreverie-narf-boot: events-by-task");
        for (tid, events) in &members.exited {
            match tid {
                Some(tid) => {
                    let _ = write!(report, " {tid}:{events}");
                }
                None => {
                    let _ = write!(report, " ?:{events}");
                }
            }
        }
        report.push_str("\nreverie-narf-boot: syscalls-by-number");
        for (number, count) in state.by_number.iter().enumerate() {
            let count = count.load(Ordering::Relaxed);
            if count != 0 {
                let native = if self.runs_natively(number as u32) {
                    "*"
                } else {
                    ""
                };
                let _ = write!(report, " {number}:{count}{native}");
            }
        }
        let _ = write!(
            report,
            " rest:{}\nreverie-narf-boot: report end",
            state.by_number_rest.load(Ordering::Relaxed)
        );
        // One console write, so no other CPU's output lands inside it.
        ConsoleSink::emit(&report);
    }
}

impl<T: Tool + 'static> Root for Tally<T> {
    fn host_root(&self, task_id: u64) -> Result<u64, String> {
        let ids = tool_view::linux_task_ids(task_id)
            .ok_or_else(|| String::from("the root task has no Linux identity"))?;
        self.host
            .host_root(task_id)
            .map_err(|error| format!("the host refused the root: {error:?}"))?;
        self.state.members.lock().root = Some((task_id, ids.pid));
        Ok(ids.pid)
    }
}

impl<T: Tool + 'static> SyscallInterceptor for Tally<T> {
    fn intercepts_vdso_calls(&self) -> bool {
        self.host.intercepts_vdso_calls()
    }

    fn on_syscall_enter(
        &self,
        invocation: &SyscallInvocation,
        native: &mut dyn NativeSyscallTransition,
    ) -> SyscallInterception {
        self.count_entry(invocation);
        self.host.on_syscall_enter(invocation, native)
    }

    fn on_syscall_return(
        &self,
        invocation: &SyscallInvocation,
        result: SyscallReturn,
    ) -> SyscallReturn {
        let result = self.host.on_syscall_return(invocation, result);
        let child = result.linux_abi_result();
        if child > 0 && creates_task(invocation.raw_number) {
            let mut members = self.state.members.lock();
            if members.live.contains_key(&invocation.task_id) {
                members.unstarted.insert(child as u64);
            }
        }
        result
    }

    fn on_syscall_context_managed(&self, invocation: &SyscallInvocation) {
        self.host.on_syscall_context_managed(invocation);
    }

    fn on_task_start(&self, task_id: u64, native: &mut dyn NativeSyscallTransition) {
        // The identity lookup takes the kernel's task maps, which must not
        // nest inside `members`.
        if let Some(ids) = tool_view::linux_task_ids(task_id) {
            let mut members = self.state.members.lock();
            let is_root = members.root.is_some_and(|(root, _)| root == task_id);
            if is_root || members.unstarted.remove(&ids.tid) {
                members.start(task_id, ids.pid);
            }
        }
        self.host.on_task_start(task_id, native);
    }

    fn on_task_exec(&self, task_id: u64, native: &mut dyn NativeSyscallTransition) {
        self.host.on_task_exec(task_id, native);
    }

    fn on_task_exit(&self, task_id: u64, pid: u64, wstatus: i32, process_wstatus: i32) {
        let ids = tool_view::linux_task_ids(task_id);
        // The adapter records the exit first, so once the tree has ended here
        // every member's exit has reached it.
        self.host
            .on_task_exit(task_id, pid, wstatus, process_wstatus);
        let mut members = self.state.members.lock();
        if !members.exit(task_id, ids) {
            return;
        }
        if members.ended() {
            // Taking the members ends the tree, so this runs once. Print
            // outside the lock: other CPUs take it on every syscall.
            let ended = core::mem::take(&mut *members);
            drop(members);
            self.print_report(&ended);
        } else if members.root_exited {
            let live = members.live.values().map(|task| task.pid).collect();
            let unstarted = members.unstarted.iter().copied().collect();
            drop(members);
            self.print_waiting(live, unstarted);
        }
    }
}
