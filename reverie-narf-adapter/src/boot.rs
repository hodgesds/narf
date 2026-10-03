//! Boot-time hosting of one Reverie Tool over Narf's login session.
//!
//! A build with frame's `reverie-narf-poc` feature reads the kernel command
//! line `reverie_tool=<name>` in boot-init. With it, frame calls [`install`]
//! while it assembles the syscall table and then spawns getty through
//! [`BootHost::host_root`], so getty, the shell getty execs and every command
//! typed into that shell are hosted by the Tool. Without it frame calls
//! nothing here, and the syscall table has no interceptor.
//!
//! The Tools are `counter1`, `counter2`, `strace` and `chaos`, compiled from
//! the source files `reverie-examples` builds its Linux binaries from
//! (`reverie_narf_tools::counter1`, `reverie_narf_tools::counter2`,
//! `reverie_narf_tools::strace` and `reverie_narf_tools::chaos`). counter2
//! also keeps a count per thread and one per process, which reach its global
//! totals through its exit hooks. When each hosted thread exits it prints the
//! line it prints on Linux, where it writes it to stderr:
//!
//! ```text
//! counter2-local thread=<tid> syscalls=<n>
//! ```
//!
//! strace runs with no filter, as the Linux binary does without `--trace`, so
//! it handles every syscall Reverie's `Sysno` knows. It prints, with
//! `eprintln!`, a line for each syscall event and one for each thread's and
//! each process's exit, which the report holds (see below).
//!
//! chaos fails the first read of each thread, and every other read after it,
//! with `EINTR` without running it, cuts the reads in between and every
//! `recvfrom` to at most one byte, and prints a line for each syscall event
//! with `eprintln!`, which the report holds as it holds strace's. Its options
//! are the Linux binary's flags, given after the name as comma-separated
//! words: `reverie_tool=chaos:skip=<N>,no-read,no-recv,no-interrupt` in any
//! order and any subset, for `--skip <N>`, `--no-read`, `--no-recv` and
//! `--no-interrupt`. `reverie_tool=chaos` runs it with the binary's defaults.
//! The other Tools take no options. After the installed line, chaos's options
//! are printed as its `ChaosOpts`:
//!
//! ```text
//! reverie-narf-boot: chaos options ChaosOpts { skip: <N>, no_read: <bool>, no_recv: <bool>, no_interrupt: <bool> }
//! ```
//!
//! # Detcore
//!
//! `reverie_tool=detcore` hosts the tree under Detcore, the Tool Hermit runs
//! programs under, built without std from Hermit's sources (the `detcore`
//! dependency in this crate's manifest). It takes no options. Its
//! configuration is `detcore-config.json`, next to this file: Hermit's
//! `Config::default()` (`detcore-model/src/config.rs`) as the host build
//! writes it out, with these changes for this backend:
//!
//! * `sequentialize_threads`: Detcore's scheduler runs one hosted thread at a
//!   time. It runs in a kernel task beside the callbacks
//!   ([`ReverieInterceptor::spawn_background`]), started once the root is
//!   hosted, which Detcore's `init_for_external_scheduler` requires.
//! * `virtualize_cpuid` off: Narf cannot deliver CPUID events, and the host
//!   refuses a Tool that subscribes to them
//!   (`NarfFatal::UnsupportedSubscription`). With it and
//!   `cpuid_virtualized_by_backend` off, Detcore does not subscribe to CPUID
//!   (`subscriptions` in `detcore/src/lib.rs`), and the guest's `cpuid` runs
//!   natively and sees the host's values.
//! * `max_timeslice` none: Narf gives Detcore no performance counter to
//!   preempt a thread with, so a thread runs until its next event.
//! * `cancel_killed_thread_rpcs` on, as for Hermit's DBT and KVM backends:
//!   Detcore answers a killed thread's pending request itself instead of
//!   relying on ptrace's exit-group teardown.
//! * `backend_runs_exit_robust_list` and
//!   `backend_supports_parked_write_signal_interruption` off: Hermit sets
//!   them only for backends that do those things for Detcore.
//! * `backend_reports_physical_process_exits` and
//!   `backend_delivers_child_exit_signals` on: Narf's kernel is the only
//!   source of a child's `SIGCHLD`. Detcore synthesizes none at a group
//!   exit. The boot reports each hosted process to Detcore once the kernel
//!   has published its exit and raised its parent's `SIGCHLD`
//!   ([`ReverieInterceptor::report_reapable_processes`]), and Detcore grants
//!   no turn until then. The parent's `SIGCHLD` then reaches Detcore through
//!   the signal hook at the parent's next syscall return (see "Signal
//!   events" in the crate documentation), and Detcore orders its delivery.
//!
//! `passthru_opt` stays off, the library default, so Detcore fails closed: it
//! subscribes to every syscall and to RDTSC, and every syscall of a hosted
//! task whose number Reverie's `Sysno` knows reaches Detcore and is charged
//! virtual time.
//!
//! The epoch stays fixed at the library default, 2026-01-01T00:00:00Z, on
//! purpose. `hermit run` samples the host's wall clock when the run starts
//! instead; this backend keeps the fixed value so that every boot starts the
//! guest's clock at the same time and two runs of the same commands can be
//! compared byte for byte. Determinism matters more here than matching
//! `hermit run`'s clock.
//!
//! Detcore virtualizes time, so the boot also installs the host's
//! [`crate::RdtscInterceptor`] as the kernel's instruction interceptor, and
//! every hosted `rdtsc` and `rdtscp` goes to Detcore.
//!
//! Detcore prints no count of its own. Its scheduler reports its milestones
//! to the boot, which prints each as
//! `reverie-narf-boot: detcore scheduler: <milestone>` except one, which it
//! counts. The scheduler reports that one once, after its first completed
//! scheduling turn, so the count is 1 once a turn has completed and 0
//! before; it is not the number of turns. Its line in the report is that
//! count, as it stands when the report is printed:
//!
//! ```text
//! detcore-scheduler turns=<N>
//! ```
//!
//! Detcore's `eprintln!` output, such as the report of a terminal deadlock
//! that it prints before it stops the run, goes to the console one line at
//! a time as `detcore-stderr: <line>`. Without a sink it would be dropped.
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
//!   call's `on_syscall_return` has run, so the return is seen before the
//!   child starts, unless the callback waits after creating the child, as
//!   Detcore's does: the wait lets the child start. A task that starts, or
//!   exits, before the syscall that created it has returned is a member if
//!   the kernel reports it as a thread of a live member process or a child
//!   process of one, and that return then adds nothing. Membership is keyed
//!   by scheduler task id, which the scheduler never reuses; Linux process
//!   IDs are reused once `alloc_pid`'s cyclic search wraps past `PID_MAX`.
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
//! strace's and chaos's launchers print no such line. In its place the report
//! has every line the Tool printed, in the order it printed them, formatted
//! by the same code as on Linux. For strace:
//!
//! ```text
//! reverie-narf-boot: strace output lines=<L> dropped=<D>
//! [pid <tid>] <syscall>(<arguments>) = <value>
//! ...
//! Thread <tid> exited with status Exited(<code>)
//! Process <pid> exited with status Exited(<code>)
//! reverie-narf-boot: strace output end
//! ```
//!
//! and for chaos, where `<n>` counts the syscall events of process `<pid>`
//! from 0:
//!
//! ```text
//! reverie-narf-boot: chaos output lines=<L> dropped=<D>
//! [pid=<pid>, n=<n>] <syscall>(<arguments>)
//! [pid=<pid>, n=<n>] read(<arguments>) = <value>
//! SKIPPED [pid=<pid>, n=<n>] <syscall>(<arguments>)
//! ...
//! reverie-narf-boot: chaos output end
//! ```
//!
//! strace prints a syscall's line after the syscall has run, so the line for
//! a command's `write` would follow the written bytes at once and, printed
//! then, land inside the command's unfinished line of output. Held until the
//! report, the Tool's output stays out of the console stream the shell and
//! the commands write to, and a harness finds it whole. The buffer's capacity
//! is reserved when the Tool is installed, so recording a line never
//! allocates; once a line does not fit, it and every later line are dropped
//! and counted in `D`, so the `L` lines printed are the first `L` the Tool
//! printed.
//!
//! A harness compares N with `expected-events`; for strace, N is its syscall
//! lines, all but the second line a failed `execve` prints, and for chaos,
//! which prints one line per event, all its lines. Detcore has no N. The
//! events-by-task line
//! has each member task's Linux thread ID and event count, in exit order (`?`
//! for a thread ID the kernel no longer had); for counter2 the harness
//! compares those pairs with the `counter2-local` lines, and for strace with
//! its lines per thread ID. A number marked `*` in the by-number line runs
//! natively, without a Tool event.
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
    NativeSyscallTransition, SignalDelivery, SyscallInterception, SyscallInterceptor,
    SyscallInvocation, SyscallReturn, SyscallTable,
};
use reverie::syscalls::Sysno;
use reverie::{GlobalTool, Pid, Tid, Tool};
use reverie_narf_core::NARF_SYSCALL_NUMBER_MASK;
use reverie_narf_tools::{chaos, counter1, counter2, strace, LineSink};

use crate::interceptor::{BackgroundFuture, ConsoleSink, ReverieInterceptor};

type Config<T> = <<T as Tool>::GlobalState as GlobalTool>::Config;

/// Syscall numbers below this are counted one by one, the rest together.
const BY_NUMBER: usize = 512;

/// Installs the Tool named `name` as `table`'s interceptor. Frame's boot-init
/// calls it after assembling the table and before publishing it. `name` is
/// the value of `reverie_tool=`: a Tool's name, and for chaos optionally a
/// colon and its options ([`chaos_options`]).
///
/// If `name` is not a known Tool, its options are not ones the Tool takes,
/// the host refuses the Tool, or the table already has an interceptor, it
/// prints why and returns `None`, and `table` is unchanged. For Detcore the
/// kernel may also refuse its RDTSC interceptor ([`install_detcore`]).
pub fn install(table: &mut SyscallTable, name: &str) -> Option<BootHost> {
    let (tool, options) = match name.split_once(':') {
        Some((tool, options)) => (tool, Some(options)),
        None => (name, None),
    };
    // The options a Tool runs with, printed once it is installed.
    let mut options_line = None;
    let installed = match (tool, options) {
        ("counter1" | "counter2" | "strace" | "detcore", Some(_)) => {
            Err(format!("{tool} takes no options"))
        }
        ("counter1", None) => Tally::<counter1::CounterLocal>::install(
            table,
            "counter1",
            (),
            <counter1::CounterLocal as Tool>::new,
            |host| format!("counter1-global syscalls={}", host.host().global().total()),
        ),
        ("counter2", None) => Tally::<counter2::CounterLocal>::install(
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
        ("strace", None) => {
            open_tool_output();
            Tally::<strace::Strace>::install(
                table,
                "strace",
                strace::Config::default(),
                <strace::Strace as Tool>::new,
                |_| take_tool_output("strace"),
            )
        }
        ("chaos", options) => chaos_options(options).and_then(|config| {
            options_line = Some(format!("{config:?}"));
            open_tool_output();
            Tally::<chaos::ChaosTool>::install(
                table,
                "chaos",
                config,
                <chaos::ChaosTool as Tool>::new,
                |_| take_tool_output("chaos"),
            )
        }),
        ("detcore", None) => install_detcore(table),
        _ => Err(String::from(
            "no such tool (known: counter1, counter2, strace, chaos, detcore)",
        )),
    };
    match installed {
        Ok(boot) => {
            ConsoleSink::emit(&format!(
                "reverie-narf-boot: {} installed at the syscall dispatcher",
                boot.tool
            ));
            if let Some(options) = options_line {
                ConsoleSink::emit(&format!(
                    "reverie-narf-boot: {} options {options}",
                    boot.tool
                ));
            }
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

/// Detcore's configuration (see the module documentation).
const DETCORE_CONFIG: &str = include_str!("detcore-config.json");

/// Installs Detcore as [`install`] installs the other Tools, with the host's
/// RDTSC interceptor installed in the kernel, and Detcore's scheduler started
/// once the root is hosted.
///
/// The RDTSC interceptor is installed before the table's interceptor, so if
/// the kernel refuses it the table is unchanged. If the table then refused
/// its interceptor, the kernel would keep the RDTSC interceptor, with a host
/// that hosts no task: each `rdtsc` would trap and then run natively.
fn install_detcore(table: &mut SyscallTable) -> Result<BootHost, String> {
    detcore_std::io::set_stderr_sink(detcore_stderr);
    let mut config: detcore::Config = serde_json::from_str(DETCORE_CONFIG)
        .map_err(|error| format!("its configuration does not parse: {error}"))?;
    // As `hermit run` does with the configuration it parses.
    config.validate();
    let global = detcore::GlobalState::init_for_external_scheduler(&config);
    let (host, rdtsc) = ReverieInterceptor::<detcore::Detcore>::with_global_state_and_rdtsc(
        config,
        global,
        <detcore::Detcore as Tool>::new,
    )
    .map_err(|error| format!("the host refused the tool: {error:?}"))?;
    // The configuration sets `backend_reports_physical_process_exits`, so
    // Detcore waits for this report before a reaped child's `wait4`
    // completes, and with `backend_delivers_child_exit_signals` grants no
    // turn while one is outstanding.
    host.report_reapable_processes(report_detcore_reapable);
    // Detcore subscribes to RDTSC when it virtualizes time. No user task
    // exists yet, so the kernel refuses only if it already has an
    // instruction interceptor, or has several CPUs and no rendezvous to arm
    // the trap on all of them.
    if let Some(rdtsc) = rdtsc {
        narf_userspace::try_install_instruction_interceptor(Box::new(rdtsc))
            .map_err(|_| String::from("the kernel refused Detcore's RDTSC interceptor"))?;
    }
    Tally::install_host(
        table,
        "detcore",
        host,
        |_| {
            format!(
                "detcore-scheduler turns={}",
                DETCORE_TURNS.load(Ordering::Relaxed)
            )
        },
        Some(start_detcore_scheduler),
    )
}

/// Tells Detcore that hosted process `pid` is reapable: its exit is
/// published and its parent's `SIGCHLD` is pending in the kernel.
fn report_detcore_reapable(global: &detcore::GlobalState, pid: Pid) {
    global.complete_physical_process_exit(pid.as_raw());
}

/// The milestone Detcore's scheduler reports once, after its first
/// completed scheduling turn (`sched_loop_inner` in
/// `detcore/src/scheduler.rs`).
const DETCORE_TURN: &str = "completed a deterministic scheduling turn";

/// How many times Detcore's scheduler has reported [`DETCORE_TURN`]: 0 or 1.
static DETCORE_TURNS: AtomicU64 = AtomicU64::new(0);

/// The sink behind Detcore's `eprintln!`: prints each line on the console as
/// `detcore-stderr: <line>`.
fn detcore_stderr(args: core::fmt::Arguments<'_>) {
    let text = format!("{args}");
    for line in text.lines() {
        ConsoleSink::emit(&format!("detcore-stderr: {line}"));
    }
}

/// The observer of Detcore's scheduler: counts [`DETCORE_TURN`] and prints
/// its other milestones.
fn observe_detcore_scheduler(milestone: &'static str) {
    if milestone == DETCORE_TURN {
        DETCORE_TURNS.fetch_add(1, Ordering::Relaxed);
    } else {
        ConsoleSink::emit(&format!(
            "reverie-narf-boot: detcore scheduler: {milestone}"
        ));
    }
}

/// Starts Detcore's scheduler in a background task. The boot's host keeps a
/// handle in the syscall table for good, so this runs only once the root is
/// hosted (see [`ReverieInterceptor::spawn_background`]).
fn start_detcore_scheduler(host: &ReverieInterceptor<detcore::Detcore>) {
    host.spawn_background(run_detcore_scheduler);
}

/// Detcore's scheduler, on the run's global state. When the scheduler stops
/// the run (a `--stop-after-*` limit, a deadlock report, a replay stop), where
/// the std build exits the process, the future fails with
/// `DETCORE_FATAL_EXIT: <reason>` and the background task aborts the hosted
/// tree with it.
fn run_detcore_scheduler(global: &detcore::GlobalState) -> BackgroundFuture<'_> {
    Box::pin(async move {
        global
            .run_external_scheduler(Arc::new(observe_detcore_scheduler))
            .await;
        match global.fatal_exit_reason() {
            Some(reason) => Err(format!("DETCORE_FATAL_EXIT: {reason}")),
            None => Ok(()),
        }
    })
}

/// counter2's thread-exit reporter: prints the line counter2 writes to
/// stderr on Linux (`on_exit_thread` in `reverie-examples/counter2_tool.rs`).
fn print_counter2_thread_exit(tid: Tid, syscalls: u64) {
    ConsoleSink::emit(&format!("counter2-local thread={tid} syscalls={syscalls}"));
}

/// chaos's options from `<options>` in `reverie_tool=chaos:<options>`, or the
/// Linux binary's defaults without them.
///
/// `<options>` is one or more comma-separated words, each at most once:
/// `skip=<N>` with `<N>` in decimal digits, `no-read`, `no-recv` and
/// `no-interrupt`, for the binary's `--skip <N>`, `--no-read`, `--no-recv`
/// and `--no-interrupt`. Anything else, an empty word included, is refused.
pub(crate) fn chaos_options(options: Option<&str>) -> Result<chaos::ChaosOpts, String> {
    let mut config = chaos::ChaosOpts::default();
    let Some(options) = options else {
        return Ok(config);
    };
    let mut given = BTreeSet::new();
    for word in options.split(',') {
        let (name, value) = match word.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (word, None),
        };
        match (name, value) {
            ("skip", Some(n)) if !n.is_empty() && n.bytes().all(|byte| byte.is_ascii_digit()) => {
                config.skip = n
                    .parse()
                    .map_err(|_| format!("chaos option {word} is out of range"))?;
            }
            ("no-read", None) => config.no_read = true,
            ("no-recv", None) => config.no_recv = true,
            ("no-interrupt", None) => config.no_interrupt = true,
            _ => {
                return Err(format!(
                    "no chaos option {word:?} (known: skip=<N>, no-read, no-recv, no-interrupt)"
                ));
            }
        }
        if !given.insert(name) {
            return Err(format!("chaos option {name} given twice"));
        }
    }
    Ok(config)
}

/// The bytes of a Tool's lines, newlines included, that the report can hold.
const TOOL_OUTPUT_CAPACITY: usize = 256 << 10;

/// The lines of a Tool that prints with `eprintln!` (strace, chaos), held
/// until the report.
struct ToolOutput {
    /// The lines recorded, in order, each followed by a newline.
    text: String,
    /// The lines in `text`.
    lines: u64,
    /// The lines dropped: the first that did not fit and every one after it.
    dropped: u64,
}

impl ToolOutput {
    const fn new(text: String) -> Self {
        Self {
            text,
            lines: 0,
            dropped: 0,
        }
    }
}

static TOOL_OUTPUT: IrqSafeSpinLock<ToolOutput> =
    IrqSafeSpinLock::new(ToolOutput::new(String::new()));

/// Reserves the buffer and makes it the sink of the Tools' `eprintln!`.
fn open_tool_output() {
    let text = String::with_capacity(TOOL_OUTPUT_CAPACITY);
    *TOOL_OUTPUT.lock() = ToolOutput::new(text);
    reverie_narf_tools::set_eprintln_sink(record_tool_line);
}

/// The Tools' `eprintln!` sink: records `line` if it and every line before it
/// fit in the reserved capacity, and otherwise counts it dropped.
fn record_tool_line(line: &str) {
    let mut output = TOOL_OUTPUT.lock();
    if output.dropped == 0 && output.text.capacity() - output.text.len() > line.len() {
        output.text.push_str(line);
        output.text.push('\n');
        output.lines += 1;
    } else {
        output.dropped += 1;
    }
}

/// The Tool's part of the report: the lines recorded, between a line with
/// their count and a closing line, both naming `tool`.
fn take_tool_output(tool: &str) -> String {
    let output = core::mem::replace(&mut *TOOL_OUTPUT.lock(), ToolOutput::new(String::new()));
    format!(
        "reverie-narf-boot: {tool} output lines={} dropped={}\n{}reverie-narf-boot: {tool} \
         output end",
        output.lines, output.dropped, output.text
    )
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
    /// Linux thread IDs of member tasks that started or exited before the
    /// fork-like syscall that created them returned, which must not then
    /// count them as unstarted. One stays here if that return is never seen.
    early: BTreeSet<u64>,
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
            self.exit_unstarted(ids);
            true
        } else if let Some(ids) = ids.filter(|ids| self.created_by_member(ids)) {
            // Exited before the syscall that created it returned.
            self.early.insert(ids.tid);
            self.exit_unstarted(ids);
            true
        } else {
            false
        }
    }

    /// Records the exit of a member task, whose Linux identity is `ids`,
    /// that never started.
    fn exit_unstarted(&mut self, ids: LinuxTaskIds) {
        self.tasks_exited += 1;
        self.exited_unstarted += 1;
        self.exited.push((Some(ids.tid), 0));
        // A process's first task has its process ID as its thread ID.
        if ids.tid == ids.pid {
            self.processes += 1;
        }
    }

    /// Whether the kernel reports the task whose Linux identity is `ids` as
    /// a thread of a live member process or a child process of one. A task
    /// that starts or exits before the fork-like syscall that created it has
    /// returned is a member if so.
    fn created_by_member(&self, ids: &LinuxTaskIds) -> bool {
        self.live_per_process.contains_key(&ids.pid)
            || ids
                .ppid
                .is_some_and(|ppid| self.live_per_process.contains_key(&ppid))
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
    /// Runs once the root is hosted.
    after_root: Option<fn(&ReverieInterceptor<T>)>,
}

impl<T: Tool> Clone for Tally<T> {
    fn clone(&self) -> Self {
        Self {
            host: self.host.clone(),
            state: self.state.clone(),
            tool: self.tool,
            report: self.report,
            after_root: self.after_root,
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
        Self::install_host(table, tool, host, report, None)
    }

    /// [`Self::install`] around `host`, which the caller built, with
    /// `after_root` run once the root is hosted.
    fn install_host(
        table: &mut SyscallTable,
        tool: &'static str,
        host: ReverieInterceptor<T>,
        report: fn(&ReverieInterceptor<T>) -> String,
        after_root: Option<fn(&ReverieInterceptor<T>)>,
    ) -> Result<BootHost, String> {
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
            after_root,
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
        if let Some(after_root) = self.after_root {
            after_root(&self.host);
        }
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
            if !members.early.remove(&(child as u64))
                && members.live.contains_key(&invocation.task_id)
            {
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
            } else if members.created_by_member(&ids) {
                // Started before the syscall that created it returned.
                members.early.insert(ids.tid);
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

    fn on_process_reapable(&self, pid: u64) {
        self.host.on_process_reapable(pid);
    }

    fn on_signal_delivery(
        &self,
        task_id: u64,
        signum: u32,
        native: Option<&mut dyn NativeSyscallTransition>,
    ) -> SignalDelivery {
        self.host.on_signal_delivery(task_id, signum, native)
    }
}
