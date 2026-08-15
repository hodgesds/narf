use crate::fd::{self, FdEntry};
use crate::handlers::{copy_from_user, copy_to_user, current_task_id};
use crate::syscall::{SyscallReturn, TrapContext};
use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use narf_filesystem::{FileOps, FileType, FsError, FsFuture, Mode, Stat};
use narf_lib::sync::IrqSafeSpinLock;
use narf_linux_perf_uapi::{
    PerfEventAttr, PERF_ATTR_FLAG_BPF_EVENT, PERF_ATTR_FLAG_BUILD_ID, PERF_ATTR_FLAG_COMM,
    PERF_ATTR_FLAG_COMM_EXEC, PERF_ATTR_FLAG_DISABLED, PERF_ATTR_FLAG_ENABLE_ON_EXEC,
    PERF_ATTR_FLAG_EXCLUDE_GUEST, PERF_ATTR_FLAG_EXCLUDE_HV, PERF_ATTR_FLAG_EXCLUDE_KERNEL,
    PERF_ATTR_FLAG_EXCLUDE_USER, PERF_ATTR_FLAG_EXCLUSIVE, PERF_ATTR_FLAG_FREQ,
    PERF_ATTR_FLAG_INHERIT, PERF_ATTR_FLAG_KSYMBOL, PERF_ATTR_FLAG_MMAP, PERF_ATTR_FLAG_MMAP2,
    PERF_ATTR_FLAG_MMAP_DATA, PERF_ATTR_FLAG_PINNED, PERF_ATTR_FLAG_REMOVE_ON_EXEC,
    PERF_ATTR_FLAG_SAMPLE_ID_ALL, PERF_ATTR_FLAG_SIGTRAP, PERF_ATTR_FLAG_TASK,
    PERF_ATTR_FLAG_WATERMARK, PERF_ATTR_SIZE_VER0, PERF_COUNT_HW_BRANCH_INSTRUCTIONS,
    PERF_COUNT_HW_BRANCH_MISSES, PERF_COUNT_HW_CACHE_MISSES, PERF_COUNT_HW_CPU_CYCLES,
    PERF_COUNT_HW_INSTRUCTIONS, PERF_COUNT_SW_CPU_CLOCK, PERF_COUNT_SW_DUMMY,
    PERF_COUNT_SW_TASK_CLOCK, PERF_FORMAT_GROUP, PERF_FORMAT_ID, PERF_FORMAT_LOST,
    PERF_FORMAT_TOTAL_TIME_ENABLED, PERF_FORMAT_TOTAL_TIME_RUNNING, PERF_RECORD_COMM,
    PERF_RECORD_EXIT, PERF_RECORD_FORK, PERF_RECORD_LOST, PERF_RECORD_MISC_COMM_EXEC,
    PERF_RECORD_MISC_MMAP_DATA, PERF_RECORD_MMAP, PERF_RECORD_MMAP2, PERF_RECORD_SAMPLE,
    PERF_SAMPLE_ADDR, PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_CODE_PAGE_SIZE, PERF_SAMPLE_CPU,
    PERF_SAMPLE_DATA_PAGE_SIZE, PERF_SAMPLE_DATA_SRC, PERF_SAMPLE_ID, PERF_SAMPLE_IDENTIFIER,
    PERF_SAMPLE_IP, PERF_SAMPLE_PERIOD, PERF_SAMPLE_PHYS_ADDR, PERF_SAMPLE_RAW, PERF_SAMPLE_READ,
    PERF_SAMPLE_REGS_USER, PERF_SAMPLE_STACK_USER, PERF_SAMPLE_STREAM_ID, PERF_SAMPLE_TID,
    PERF_SAMPLE_TIME, PERF_SAMPLE_TRANSACTION, PERF_SAMPLE_WEIGHT, PERF_SAMPLE_WEIGHT_STRUCT,
    PERF_TYPE_HARDWARE, PERF_TYPE_RAW, PERF_TYPE_SOFTWARE, PERF_TYPE_TRACEPOINT,
};
#[cfg(target_arch = "x86_64")]
use narf_linux_perf_uapi::{
    PERF_COUNT_HW_CACHE_L1D, PERF_COUNT_HW_CACHE_LL, PERF_COUNT_HW_CACHE_OP_READ,
    PERF_COUNT_HW_CACHE_REFERENCES, PERF_COUNT_HW_CACHE_RESULT_ACCESS,
    PERF_COUNT_HW_CACHE_RESULT_MISS, PERF_TYPE_HW_CACHE,
};

static ACTIVE_PERF_EVENTS: AtomicUsize = AtomicUsize::new(0);
static NEXT_PERF_EVENT_ID: AtomicU64 = AtomicU64::new(1);
static PERF_EVENT_REGISTRY: IrqSafeSpinLock<Vec<Weak<PerfEventFile>>> =
    IrqSafeSpinLock::new(Vec::new());
static PERF_LAST_SELECTED_TASK: [AtomicU64; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicU64::new(u64::MAX) }; narf_lib::percpu::MAX_CPUS];
static PERF_LAST_MULTIPLEX_NS: [AtomicU64; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; narf_lib::percpu::MAX_CPUS];
const PERF_MULTIPLEX_QUANTUM_NS: u64 = 1_000_000;
#[cfg(target_arch = "x86_64")]
static PMI_VECTOR: IrqSafeSpinLock<Option<u8>> = IrqSafeSpinLock::new(None);
#[cfg(target_arch = "x86_64")]
static PMI_ROUTED_CPUS: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static REMOTE_PMU_VECTOR: IrqSafeSpinLock<Option<u8>> = IrqSafeSpinLock::new(None);
#[cfg(target_arch = "x86_64")]
static REMOTE_PMU_MAILBOXES: [RemotePmuMailbox; narf_lib::percpu::MAX_CPUS] =
    [const { RemotePmuMailbox::new() }; narf_lib::percpu::MAX_CPUS];
const SAMPLE_CPU_SLOTS: usize = narf_lib::percpu::MAX_CPUS;
const PENDING_SAMPLE_DEPTH: usize = 64;
const PENDING_LOSS_BUCKETS: usize = 16;
const PENDING_TRACE_DEPTH: usize = 64;
const PENDING_TRACE_BYTES: usize = 256;
static PENDING_SAMPLES: [[PendingSample; PENDING_SAMPLE_DEPTH]; SAMPLE_CPU_SLOTS] =
    [const { [const { PendingSample::new() }; PENDING_SAMPLE_DEPTH] }; SAMPLE_CPU_SLOTS];
static PENDING_SAMPLE_CURSOR: [AtomicUsize; SAMPLE_CPU_SLOTS] =
    [const { AtomicUsize::new(0) }; SAMPLE_CPU_SLOTS];
static PENDING_LOSSES: [[PendingLoss; PENDING_LOSS_BUCKETS]; SAMPLE_CPU_SLOTS] =
    [const { [const { PendingLoss::new() }; PENDING_LOSS_BUCKETS] }; SAMPLE_CPU_SLOTS];
static PENDING_TRACES: [[PendingTrace; PENDING_TRACE_DEPTH]; SAMPLE_CPU_SLOTS] =
    [const { [const { PendingTrace::new() }; PENDING_TRACE_DEPTH] }; SAMPLE_CPU_SLOTS];
static PENDING_TRACE_CURSOR: [AtomicUsize; SAMPLE_CPU_SLOTS] =
    [const { AtomicUsize::new(0) }; SAMPLE_CPU_SLOTS];
static PENDING_TRACE_LOSSES: [[PendingLoss; PENDING_LOSS_BUCKETS]; SAMPLE_CPU_SLOTS] =
    [const { [const { PendingLoss::new() }; PENDING_LOSS_BUCKETS] }; SAMPLE_CPU_SLOTS];
static TRACE_OBSERVERS_INSTALLED: AtomicBool = AtomicBool::new(false);
static ACTIVE_SAMPLE_IDS: [[AtomicU64; 8]; SAMPLE_CPU_SLOTS] =
    [const { [const { AtomicU64::new(0) }; 8] }; SAMPLE_CPU_SLOTS];
static ACTIVE_SAMPLE_STACK_BYTES: [[AtomicU32; 8]; SAMPLE_CPU_SLOTS] =
    [const { [const { AtomicU32::new(0) }; 8] }; SAMPLE_CPU_SLOTS];
const PERF_MAX_USER_STACK_SAMPLE: usize = 8192;
static CPU_USER_NS: [AtomicU64; SAMPLE_CPU_SLOTS] = [const { AtomicU64::new(0) }; SAMPLE_CPU_SLOTS];
static CPU_USER_SLICE_START_NS: [AtomicU64; SAMPLE_CPU_SLOTS] =
    [const { AtomicU64::new(0) }; SAMPLE_CPU_SLOTS];
static CPU_USER_DEPTH: [AtomicU32; SAMPLE_CPU_SLOTS] =
    [const { AtomicU32::new(0) }; SAMPLE_CPU_SLOTS];

#[inline]
fn rotation_index(start: usize, offset: usize, len: usize) -> usize {
    debug_assert!(len != 0);
    start.wrapping_add(offset) % len
}

pub(crate) fn rotation_index_for_test(start: usize, offset: usize, len: usize) -> usize {
    rotation_index(start, offset, len)
}

#[inline]
fn advance_rotation_cursor(previous_task: u64, task: u64, cursor: usize) -> usize {
    if previous_task != u64::MAX && previous_task != task {
        cursor.wrapping_add(1)
    } else {
        cursor
    }
}

pub(crate) fn advance_rotation_cursor_for_test(
    previous_task: u64,
    task: u64,
    cursor: usize,
) -> usize {
    advance_rotation_cursor(previous_task, task, cursor)
}

#[inline]
fn multiplex_quantum_due(last_ns: u64, now_ns: u64) -> bool {
    last_ns == 0 || now_ns.saturating_sub(last_ns) >= PERF_MULTIPLEX_QUANTUM_NS
}

#[inline]
fn remaining_sample_period(loaded: u64, consumed: u64) -> u64 {
    loaded.saturating_sub(consumed).max(1)
}

fn unwind_user_callchain(
    ip: u64,
    state: Option<&narf_interrupts::InterruptedUserState>,
    stack: &[u8],
    max_frames: usize,
) -> Vec<u64> {
    let mut chain = Vec::with_capacity(max_frames.min(128));
    if max_frames == 0 {
        return chain;
    }
    chain.push(ip);
    let Some(state) = state else {
        return chain;
    };
    #[cfg(target_arch = "x86_64")]
    let mut frame_pointer = state.regs[6];
    #[cfg(target_arch = "aarch64")]
    let mut frame_pointer = state.regs[29];
    let stack_end = state.sp.saturating_add(stack.len() as u64);
    while chain.len() < max_frames
        && frame_pointer >= state.sp
        && frame_pointer.saturating_add(16) <= stack_end
        && frame_pointer & 7 == 0
    {
        let offset = (frame_pointer - state.sp) as usize;
        let previous = u64::from_ne_bytes(stack[offset..offset + 8].try_into().unwrap());
        let return_ip = u64::from_ne_bytes(stack[offset + 8..offset + 16].try_into().unwrap());
        if return_ip == 0 {
            break;
        }
        chain.push(return_ip);
        if previous <= frame_pointer {
            break;
        }
        frame_pointer = previous;
    }
    chain
}

pub(crate) fn unwind_user_callchain_for_test(
    ip: u64,
    state: &narf_interrupts::InterruptedUserState,
    stack: &[u8],
) -> Vec<u64> {
    unwind_user_callchain(ip, Some(state), stack, 127)
}

pub(crate) fn remaining_sample_period_for_test(loaded: u64, consumed: u64) -> u64 {
    remaining_sample_period(loaded, consumed)
}

pub(crate) fn multiplex_quantum_due_for_test(last_ns: u64, now_ns: u64) -> bool {
    multiplex_quantum_due(last_ns, now_ns)
}

fn publish_active_sample(cpu: usize, slot: usize, event: &PerfEventFile) {
    let stack_bytes = if event.attr.sample_type & PERF_SAMPLE_CALLCHAIN != 0 {
        event
            .attr
            .sample_stack_user
            .max(PERF_MAX_USER_STACK_SAMPLE as u32)
    } else {
        event.attr.sample_stack_user
    };
    ACTIVE_SAMPLE_STACK_BYTES[cpu][slot].store(stack_bytes, Ordering::Relaxed);
    ACTIVE_SAMPLE_IDS[cpu][slot].store(event.id, Ordering::Release);
}

fn clear_active_sample(cpu: usize, slot: usize) {
    ACTIVE_SAMPLE_IDS[cpu][slot].store(0, Ordering::Release);
    ACTIVE_SAMPLE_STACK_BYTES[cpu][slot].store(0, Ordering::Relaxed);
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
enum RemotePmuCommand {
    Allocate(narf_arch::x86_64::pmu::PmuEvent, bool, bool),
    Read(narf_arch::x86_64::pmu::PmuCounter),
    Arm(narf_arch::x86_64::pmu::PmuCounter, u64),
    Pause(narf_arch::x86_64::pmu::PmuCounter),
    Residual(narf_arch::x86_64::pmu::PmuCounter, u64),
    RoutePmi(u8),
    Release(narf_arch::x86_64::pmu::PmuCounter),
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
enum RemotePmuReply {
    Counter(Result<narf_arch::x86_64::pmu::PmuCounter, narf_arch::x86_64::pmu::PmuError>),
    Value(u64),
    Result(Result<(), narf_arch::x86_64::pmu::PmuError>),
    Residual(Result<u64, narf_arch::x86_64::pmu::PmuError>),
    Released,
}

#[cfg(target_arch = "x86_64")]
struct RemotePmuMailbox {
    state: AtomicU8,
    command: IrqSafeSpinLock<Option<RemotePmuCommand>>,
    reply: IrqSafeSpinLock<Option<RemotePmuReply>>,
}

#[cfg(target_arch = "x86_64")]
impl RemotePmuMailbox {
    const IDLE: u8 = 0;
    const RESERVED: u8 = 1;
    const READY: u8 = 2;
    const DONE: u8 = 3;

    const fn new() -> Self {
        Self {
            state: AtomicU8::new(Self::IDLE),
            command: IrqSafeSpinLock::new(None),
            reply: IrqSafeSpinLock::new(None),
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn execute_pmu_command(command: RemotePmuCommand) -> RemotePmuReply {
    match command {
        RemotePmuCommand::Allocate(event, kernel, user) => {
            // SAFETY: this function executes at CPL0 on the CPU whose PMU bank
            // is being allocated.
            RemotePmuReply::Counter(unsafe {
                narf_arch::x86_64::pmu::alloc_counter_filtered(event, kernel, user)
            })
        }
        RemotePmuCommand::Read(counter) => {
            // SAFETY: the synchronous mailbox preserves the live allocation
            // and executes this command on `counter.cpu`.
            RemotePmuReply::Value(unsafe { narf_arch::x86_64::pmu::read(&counter) })
        }
        RemotePmuCommand::Arm(counter, period) => {
            // SAFETY: command executes on the allocation's owning CPU.
            RemotePmuReply::Result(unsafe {
                narf_arch::x86_64::pmu::arm_sampling(&counter, period)
            })
        }
        RemotePmuCommand::Pause(counter) => {
            // SAFETY: command executes on the allocation's owning CPU.
            RemotePmuReply::Result(unsafe { narf_arch::x86_64::pmu::pause_sampling(&counter) })
        }
        RemotePmuCommand::Residual(counter, period) => {
            // SAFETY: command executes on the allocation's owning CPU.
            RemotePmuReply::Residual(unsafe {
                narf_arch::x86_64::pmu::sampling_residual(&counter, period)
            })
        }
        RemotePmuCommand::RoutePmi(vector) => {
            // SAFETY: APIC bring-up is complete and this writes only this
            // CPU's LVT-PC entry.
            unsafe { narf_arch::x86_64::pmi::program_current_lvt_pc(vector, false) };
            RemotePmuReply::Result(Ok(()))
        }
        RemotePmuCommand::Release(counter) => {
            // SAFETY: the synchronous mailbox executes on `counter.cpu` and
            // consumes the still-live allocation exactly once.
            unsafe { narf_arch::x86_64::pmu::release(counter) };
            RemotePmuReply::Released
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn remote_pmu_handler(_cookie: u64) -> narf_interrupts::IrqStatus {
    let cpu = narf_lib::percpu::current_cpu();
    let Some(mailbox) = REMOTE_PMU_MAILBOXES.get(cpu) else {
        return narf_interrupts::IrqStatus::None;
    };
    if mailbox
        .state
        .compare_exchange(
            RemotePmuMailbox::READY,
            RemotePmuMailbox::RESERVED,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return narf_interrupts::IrqStatus::None;
    }
    let command = mailbox
        .command
        .lock()
        .take()
        .expect("remote PMU mailbox READY without a command");
    *mailbox.reply.lock() = Some(execute_pmu_command(command));
    mailbox
        .state
        .store(RemotePmuMailbox::DONE, Ordering::Release);
    narf_interrupts::IrqStatus::Handled
}

#[cfg(target_arch = "x86_64")]
fn ensure_remote_pmu_vector() -> Result<u8, narf_arch::x86_64::pmu::PmuError> {
    if !narf_interrupts::x86_64::apic::x2apic_active() {
        return Err(narf_arch::x86_64::pmu::PmuError::NoPmu);
    }
    let mut slot = REMOTE_PMU_VECTOR.lock();
    if let Some(vector) = *slot {
        return Ok(vector);
    }
    let vector = narf_interrupts::vector::alloc()
        .map_err(|_| narf_arch::x86_64::pmu::PmuError::NoFreeCounter)?;
    narf_interrupts::install_handler_named(vector, "perf-remote-pmu", 0, remote_pmu_handler);
    *slot = Some(vector);
    Ok(vector)
}

#[cfg(target_arch = "x86_64")]
fn remote_pmu_call(
    cpu: usize,
    command: RemotePmuCommand,
) -> Result<RemotePmuReply, narf_arch::x86_64::pmu::PmuError> {
    if cpu == narf_lib::percpu::current_cpu() {
        return Ok(execute_pmu_command(command));
    }
    if cpu >= narf_lib::percpu::MAX_CPUS || !narf_lib::smp::is_online(cpu as u32) {
        return Err(narf_arch::x86_64::pmu::PmuError::NoPmu);
    }
    let vector = ensure_remote_pmu_vector()?;
    let mailbox = &REMOTE_PMU_MAILBOXES[cpu];
    while mailbox
        .state
        .compare_exchange_weak(
            RemotePmuMailbox::IDLE,
            RemotePmuMailbox::RESERVED,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        core::hint::spin_loop();
    }
    *mailbox.command.lock() = Some(command);
    *mailbox.reply.lock() = None;
    mailbox
        .state
        .store(RemotePmuMailbox::READY, Ordering::Release);
    narf_interrupts::x86_64::apic::send_fixed_ipi(1u64 << cpu, vector);
    while mailbox.state.load(Ordering::Acquire) != RemotePmuMailbox::DONE {
        core::hint::spin_loop();
    }
    let reply = mailbox
        .reply
        .lock()
        .take()
        .expect("remote PMU mailbox DONE without a reply");
    mailbox
        .state
        .store(RemotePmuMailbox::IDLE, Ordering::Release);
    Ok(reply)
}

#[cfg(target_arch = "x86_64")]
fn allocate_pmu_on(
    cpu: usize,
    event: narf_arch::x86_64::pmu::PmuEvent,
    kernel: bool,
    user: bool,
) -> Result<narf_arch::x86_64::pmu::PmuCounter, narf_arch::x86_64::pmu::PmuError> {
    match remote_pmu_call(cpu, RemotePmuCommand::Allocate(event, kernel, user))? {
        RemotePmuReply::Counter(result) => result,
        _ => unreachable!("allocate PMU command returned the wrong reply"),
    }
}

#[cfg(target_arch = "x86_64")]
fn read_pmu_on(counter: narf_arch::x86_64::pmu::PmuCounter) -> u64 {
    match remote_pmu_call(counter.cpu as usize, RemotePmuCommand::Read(counter)) {
        Ok(RemotePmuReply::Value(value)) => value,
        _ => unreachable!("live remote PMU allocation became unreachable"),
    }
}

#[cfg(target_arch = "x86_64")]
fn arm_pmu_on(
    counter: narf_arch::x86_64::pmu::PmuCounter,
    period: u64,
) -> Result<(), narf_arch::x86_64::pmu::PmuError> {
    match remote_pmu_call(counter.cpu as usize, RemotePmuCommand::Arm(counter, period))? {
        RemotePmuReply::Result(result) => result,
        _ => unreachable!("arm PMU command returned the wrong reply"),
    }
}

#[cfg(target_arch = "x86_64")]
fn pause_pmu_on(
    counter: narf_arch::x86_64::pmu::PmuCounter,
) -> Result<(), narf_arch::x86_64::pmu::PmuError> {
    match remote_pmu_call(counter.cpu as usize, RemotePmuCommand::Pause(counter))? {
        RemotePmuReply::Result(result) => result,
        _ => unreachable!("pause PMU command returned the wrong reply"),
    }
}

#[cfg(target_arch = "x86_64")]
fn sampling_residual_on(
    counter: narf_arch::x86_64::pmu::PmuCounter,
    period: u64,
) -> Result<u64, narf_arch::x86_64::pmu::PmuError> {
    match remote_pmu_call(
        counter.cpu as usize,
        RemotePmuCommand::Residual(counter, period),
    )? {
        RemotePmuReply::Residual(result) => result,
        _ => unreachable!("residual PMU command returned the wrong reply"),
    }
}

#[cfg(target_arch = "x86_64")]
fn release_pmu_on(counter: narf_arch::x86_64::pmu::PmuCounter) {
    match remote_pmu_call(counter.cpu as usize, RemotePmuCommand::Release(counter)) {
        Ok(RemotePmuReply::Released) => {}
        _ => unreachable!("live remote PMU allocation became unreachable"),
    }
}

#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy)]
enum AarchPmuEvent {
    Cycle,
    Programmable(u16),
}

#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy)]
enum AarchCounter {
    Cycle(narf_arch::aarch64::pmu::CycleCounter),
    Programmable(narf_arch::aarch64::pmu::ProgrammableCounter),
}

#[cfg(target_arch = "aarch64")]
impl AarchPmuEvent {
    unsafe fn allocate(
        self,
        kernel: bool,
        user: bool,
    ) -> Result<AarchCounter, narf_arch::aarch64::pmu::PmuError> {
        match self {
            Self::Cycle => {
                // SAFETY: caller guarantees EL1 execution pinned to this CPU.
                unsafe { narf_arch::aarch64::pmu::alloc_cycle_counter_filtered(kernel, user) }
                    .map(AarchCounter::Cycle)
            }
            Self::Programmable(event) => {
                // SAFETY: caller guarantees EL1 execution pinned to this CPU.
                unsafe { narf_arch::aarch64::pmu::alloc_programmable_filtered(event, kernel, user) }
                    .map(AarchCounter::Programmable)
            }
        }
    }
}

#[cfg(target_arch = "aarch64")]
impl AarchCounter {
    fn sample_slot(self) -> usize {
        match self {
            Self::Cycle(_) => 0,
            Self::Programmable(counter) => counter.idx as usize + 1,
        }
    }

    unsafe fn read(self) -> Result<u64, narf_arch::aarch64::pmu::PmuError> {
        match self {
            // SAFETY: caller guarantees this counter remains live and current-CPU-owned.
            Self::Cycle(counter) => unsafe { narf_arch::aarch64::pmu::read(&counter) },
            // SAFETY: caller guarantees this counter remains live and current-CPU-owned.
            Self::Programmable(counter) => unsafe {
                narf_arch::aarch64::pmu::read_programmable(&counter)
            },
        }
    }

    unsafe fn arm(self, period: u64) -> Result<(), narf_arch::aarch64::pmu::PmuError> {
        // SAFETY: forwarded caller contract.
        unsafe { self.arm_with_reload(period, period) }
    }

    unsafe fn arm_with_reload(
        self,
        initial_period: u64,
        reload_period: u64,
    ) -> Result<(), narf_arch::aarch64::pmu::PmuError> {
        match self {
            // SAFETY: caller guarantees ownership and a routed current-CPU PMU PPI.
            Self::Cycle(counter) => unsafe {
                narf_arch::aarch64::pmu::arm_sampling_with_reload(
                    &counter,
                    initial_period,
                    reload_period,
                )
            },
            // SAFETY: caller guarantees ownership and a routed current-CPU PMU PPI.
            Self::Programmable(counter) => unsafe {
                narf_arch::aarch64::pmu::arm_programmable_with_reload(
                    &counter,
                    initial_period,
                    reload_period,
                )
            },
        }
    }

    unsafe fn period_left(self) -> Result<u64, narf_arch::aarch64::pmu::PmuError> {
        match self {
            // SAFETY: caller guarantees live current-CPU ownership.
            Self::Cycle(counter) => unsafe {
                narf_arch::aarch64::pmu::sampling_period_left(&counter)
            },
            // SAFETY: caller guarantees live current-CPU ownership.
            Self::Programmable(counter) => unsafe {
                narf_arch::aarch64::pmu::programmable_period_left(&counter)
            },
        }
    }

    unsafe fn start(self) -> Result<(), narf_arch::aarch64::pmu::PmuError> {
        match self {
            // SAFETY: caller guarantees this counter remains live and current-CPU-owned.
            Self::Cycle(counter) => unsafe { narf_arch::aarch64::pmu::start(&counter) },
            // SAFETY: caller guarantees this counter remains live and current-CPU-owned.
            Self::Programmable(counter) => unsafe {
                narf_arch::aarch64::pmu::start_programmable(&counter)
            },
        }
    }

    unsafe fn pause(self) -> Result<(), narf_arch::aarch64::pmu::PmuError> {
        match self {
            // SAFETY: caller guarantees this counter remains live and current-CPU-owned.
            Self::Cycle(counter) => unsafe { narf_arch::aarch64::pmu::pause_sampling(&counter) },
            // SAFETY: caller guarantees this counter remains live and current-CPU-owned.
            Self::Programmable(counter) => unsafe {
                narf_arch::aarch64::pmu::pause_programmable(&counter)
            },
        }
    }

    unsafe fn release(self) -> Result<(), narf_arch::aarch64::pmu::PmuError> {
        match self {
            // SAFETY: caller guarantees this counter remains live and current-CPU-owned.
            Self::Cycle(counter) => unsafe { narf_arch::aarch64::pmu::release(counter) },
            // SAFETY: caller guarantees this counter remains live and current-CPU-owned.
            Self::Programmable(counter) => unsafe {
                narf_arch::aarch64::pmu::release_programmable(counter)
            },
        }
    }

    fn update_period(self, period: u64) {
        match self {
            Self::Cycle(counter) => {
                narf_arch::aarch64::pmu::update_sampling_period(&counter, period);
            }
            Self::Programmable(counter) => {
                narf_arch::aarch64::pmu::update_programmable_period(&counter, period);
            }
        }
    }
}

pub(crate) fn frequency_period(current: u64, frequency: u64, elapsed_ns: u64) -> u64 {
    let current = current.max(1);
    let target_ns = 1_000_000_000u64
        .checked_div(frequency.max(1))
        .unwrap_or(1)
        .max(1);
    let calculated = (current as u128)
        .saturating_mul(target_ns as u128)
        .checked_div(elapsed_ns.max(1) as u128)
        .unwrap_or(1)
        .min(u64::MAX as u128) as u64;
    calculated
        .clamp((current / 4).max(1), current.saturating_mul(4))
        .max(1)
}

struct PendingSample {
    state: AtomicU8,
    task: AtomicU64,
    ip: AtomicU64,
    time: AtomicU64,
    counters: AtomicU8,
    user_regs_valid: AtomicBool,
    user_regs_abi: AtomicU64,
    user_sp: AtomicU64,
    user_regs: [AtomicU64; 34],
    user_stack_size: AtomicU32,
    user_stack: PendingStack,
    event_ids: [AtomicU64; 8],
    periods: [AtomicU64; 8],
}

impl PendingSample {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(0),
            task: AtomicU64::new(0),
            ip: AtomicU64::new(0),
            time: AtomicU64::new(0),
            counters: AtomicU8::new(0),
            user_regs_valid: AtomicBool::new(false),
            user_regs_abi: AtomicU64::new(0),
            user_sp: AtomicU64::new(0),
            user_regs: [const { AtomicU64::new(0) }; 34],
            user_stack_size: AtomicU32::new(0),
            user_stack: PendingStack::new(),
            event_ids: [const { AtomicU64::new(0) }; 8],
            periods: [const { AtomicU64::new(0) }; 8],
        }
    }
}

struct PendingStack([UnsafeCell<u8>; PERF_MAX_USER_STACK_SAMPLE]);

// SAFETY: PendingSample::state grants one producer or consumer exclusive
// access; bytes are published by its Release transition to state 2.
unsafe impl Sync for PendingStack {}

impl PendingStack {
    const fn new() -> Self {
        Self([const { UnsafeCell::new(0) }; PERF_MAX_USER_STACK_SAMPLE])
    }

    fn as_mut_ptr(&self) -> *mut u8 {
        self.0.as_ptr().cast_mut().cast::<u8>()
    }

    unsafe fn slice(&self, len: usize) -> &[u8] {
        // SAFETY: caller owns the surrounding pending slot in state 1 after
        // acquiring the producer's state-2 publication.
        unsafe { core::slice::from_raw_parts(self.0.as_ptr().cast::<u8>(), len) }
    }
}

struct PendingLoss {
    state: AtomicU8,
    event_id: AtomicU64,
    count: AtomicU64,
}

impl PendingLoss {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(0),
            event_id: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }
}

struct PendingTrace {
    state: AtomicU8,
    type_id: AtomicU64,
    task: AtomicU64,
    ip: AtomicU64,
    time: AtomicU64,
    len: AtomicU32,
    bytes: PendingTraceBytes,
}

impl PendingTrace {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(0),
            type_id: AtomicU64::new(0),
            task: AtomicU64::new(0),
            ip: AtomicU64::new(0),
            time: AtomicU64::new(0),
            len: AtomicU32::new(0),
            bytes: PendingTraceBytes([const { UnsafeCell::new(0) }; PENDING_TRACE_BYTES]),
        }
    }
}

struct PendingTraceBytes([UnsafeCell<u8>; PENDING_TRACE_BYTES]);

// SAFETY: PendingTrace::state serializes its sole producer and consumer.
unsafe impl Sync for PendingTraceBytes {}

const PERF_FORMAT_SUPPORTED: u64 = (1 << 5) - 1;

const PERF_ATTR_IMPLEMENTED: u64 = PERF_ATTR_FLAG_DISABLED
    | PERF_ATTR_FLAG_PINNED
    | PERF_ATTR_FLAG_EXCLUSIVE
    | PERF_ATTR_FLAG_ENABLE_ON_EXEC
    | PERF_ATTR_FLAG_COMM
    | PERF_ATTR_FLAG_TASK
    | PERF_ATTR_FLAG_SAMPLE_ID_ALL
    | PERF_ATTR_FLAG_COMM_EXEC
    | PERF_ATTR_FLAG_MMAP
    | PERF_ATTR_FLAG_MMAP_DATA
    | PERF_ATTR_FLAG_MMAP2
    | PERF_ATTR_FLAG_FREQ
    | PERF_ATTR_FLAG_WATERMARK
    | PERF_ATTR_FLAG_INHERIT
    | PERF_ATTR_FLAG_EXCLUDE_USER
    | PERF_ATTR_FLAG_EXCLUDE_KERNEL
    | PERF_ATTR_FLAG_REMOVE_ON_EXEC
    | PERF_ATTR_FLAG_SIGTRAP
    // NARF does not execute nested guests and currently has no BPF VM or
    // runtime kernel-symbol loader. These selectors therefore describe empty
    // event domains, rather than requests whose records are being suppressed.
    | PERF_ATTR_FLAG_EXCLUDE_GUEST
    | PERF_ATTR_FLAG_EXCLUDE_HV
    | PERF_ATTR_FLAG_KSYMBOL
    | PERF_ATTR_FLAG_BPF_EVENT
    // Linux permits an MMAP2_BUILD_ID request to fall back to the inode
    // layout when no build ID is available for a mapping.
    | PERF_ATTR_FLAG_BUILD_ID;

const PERF_EVENT_IOC_ENABLE: u32 = 0x2400;
const PERF_EVENT_IOC_DISABLE: u32 = 0x2401;
const PERF_EVENT_IOC_REFRESH: u32 = 0x2402;
const PERF_EVENT_IOC_RESET: u32 = 0x2403;
const PERF_EVENT_IOC_PERIOD: u32 = 0x4008_2404;
const PERF_EVENT_IOC_SET_OUTPUT: u32 = 0x2405;
const PERF_EVENT_IOC_ID: u32 = 0x8008_2407;
/// `_IOW('$', 8, __u32)` — attach a BPF program to this event.
///
/// `observability/PERF_LINUX_COMPAT_AUDIT.md` recorded this as returning
/// ENOTTY, with the note that BPF should land only once its capability and
/// safety story existed. It does now (`bpf/specification/spec.md` §4).
const PERF_EVENT_IOC_SET_BPF: u32 = 0x4004_2408;
const PERF_EVENT_IOC_PAUSE_OUTPUT: u32 = 0x4004_2409;
const PERF_IOC_FLAG_GROUP: usize = 1;
const PERF_MMAP_PAGE_BYTES: usize = 4096;
const PERF_MMAP_MAX_DATA_PAGES: usize = 256;
const PERF_MMAP_LOCK_OFFSET: usize = 8;
const PERF_MMAP_OFFSET_OFFSET: usize = 16;
const PERF_MMAP_TIME_ENABLED_OFFSET: usize = 24;
const PERF_MMAP_TIME_RUNNING_OFFSET: usize = 32;
const PERF_MMAP_DATA_HEAD_OFFSET: usize = 1024;
const PERF_MMAP_DATA_TAIL_OFFSET: usize = 1032;
const PERF_MMAP_DATA_OFFSET_OFFSET: usize = 1040;
const PERF_MMAP_DATA_SIZE_OFFSET: usize = 1048;
const PERF_SAMPLE_SUPPORTED: u64 = PERF_SAMPLE_IP
    | PERF_SAMPLE_TID
    | PERF_SAMPLE_TIME
    | PERF_SAMPLE_ADDR
    | PERF_SAMPLE_READ
    | PERF_SAMPLE_CALLCHAIN
    | PERF_SAMPLE_RAW
    | PERF_SAMPLE_REGS_USER
    | PERF_SAMPLE_STACK_USER
    | PERF_SAMPLE_ID
    | PERF_SAMPLE_CPU
    | PERF_SAMPLE_PERIOD
    | PERF_SAMPLE_STREAM_ID
    | PERF_SAMPLE_IDENTIFIER
    | PERF_SAMPLE_WEIGHT
    | PERF_SAMPLE_DATA_SRC
    | PERF_SAMPLE_TRANSACTION
    | PERF_SAMPLE_PHYS_ADDR
    | PERF_SAMPLE_DATA_PAGE_SIZE
    | PERF_SAMPLE_CODE_PAGE_SIZE
    | PERF_SAMPLE_WEIGHT_STRUCT;

struct InheritedTaskState {
    live: Vec<u64>,
    /// Software-clock time captured before an inherited task's per-task
    /// ledgers are swept at exit. Keeping it here makes the event's raw count
    /// monotonic after the task disappears.
    retired_software_ns: u64,
    /// The target task is retired through the same thread-exit path before
    /// its kernel-time row is removed. Once set, its final contribution lives
    /// in `retired_software_ns` and must not be read from the task tables.
    target_software_retired: bool,
}

struct PerfEventFile {
    attr: PerfEventAttr,
    id: u64,
    target_task: u64,
    target_pid: u64,
    target_cpu: i32,
    inherited_tasks: IrqSafeSpinLock<InheritedTaskState>,
    enabled: AtomicBool,
    scheduling_error: AtomicBool,
    count_base: AtomicU64,
    count_accumulated: AtomicU64,
    enabled_at_ns: AtomicU64,
    time_enabled_ns: AtomicU64,
    running_at_ns: [AtomicU64; narf_lib::percpu::MAX_CPUS],
    time_running_ns: AtomicU64,
    multiplex_cursor: AtomicUsize,
    registered: AtomicBool,
    sample_lost: AtomicU64,
    output_paused: AtomicBool,
    refresh_hup: AtomicBool,
    refresh_limit: AtomicU32,
    wakeup_pending: AtomicU32,
    sample_period: AtomicU64,
    sample_period_left: AtomicU64,
    last_sample_period: AtomicU64,
    sample_frequency: u64,
    last_sample_ns: AtomicU64,
    #[cfg(target_arch = "x86_64")]
    pmu_event: Option<narf_arch::x86_64::pmu::PmuEvent>,
    #[cfg(target_arch = "x86_64")]
    active_task_counters:
        IrqSafeSpinLock<[Option<narf_arch::x86_64::pmu::PmuCounter>; narf_lib::percpu::MAX_CPUS]>,
    #[cfg(target_arch = "aarch64")]
    active_task_counters: IrqSafeSpinLock<[Option<AarchCounter>; narf_lib::percpu::MAX_CPUS]>,
    mmap_seq: AtomicU32,
    mmap: IrqSafeSpinLock<Option<PerfMmap>>,
    output_target: IrqSafeSpinLock<Option<Arc<dyn FileOps>>>,
    /// A BPF program attached with `PERF_EVENT_IOC_SET_BPF`.
    ///
    /// Consulted in the tracepoint *drain*, not in the sample producer. The
    /// producers (`capture_pending_sample`, `capture_trace`) run in PMI and IRQ
    /// context and only stage into lock-free per-CPU rings; `drain_irq_samples`
    /// runs from the syscall-return path, which is where a BPF program can be
    /// run without inheriting NMI-safety constraints (spec §6.1).
    bpf_prog: IrqSafeSpinLock<Option<Arc<narf_bpf::prog::BpfProg>>>,
    group_members: IrqSafeSpinLock<Vec<Weak<dyn FileOps>>>,
    // A member keeps its leader's open-file description alive. The leader
    // holds only weak member links, so this cannot form a reference cycle.
    _group_leader: Option<Arc<dyn FileOps>>,
    #[cfg(target_arch = "x86_64")]
    pmu_counter: Option<narf_arch::x86_64::pmu::PmuCounter>,
    #[cfg(target_arch = "aarch64")]
    pmu_counter: Option<AarchCounter>,
    #[cfg(target_arch = "aarch64")]
    pmu_event: Option<AarchPmuEvent>,
}

struct PerfMmap {
    frames: Vec<narf_memory::PhysFrame>,
    len: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RecordPush {
    Committed,
    Suppressed,
    Full,
    Unmapped,
}

impl PerfMmap {
    fn allocate(len: usize) -> Result<Self, FsError> {
        let pages = len / PERF_MMAP_PAGE_BYTES;
        let data_pages = pages.saturating_sub(1);
        if len < PERF_MMAP_PAGE_BYTES * 2
            || len % PERF_MMAP_PAGE_BYTES != 0
            || !data_pages.is_power_of_two()
            || data_pages > PERF_MMAP_MAX_DATA_PAGES
        {
            return Err(FsError::InvalidData);
        }
        let mut frames = Vec::with_capacity(pages);
        while frames.len() < pages {
            let frame = match narf_memory::alloc_frame() {
                Ok(frame) => frame,
                Err(_) => {
                    for frame in frames.drain(..) {
                        narf_memory::free_frame(frame);
                    }
                    return Err(FsError::NoSpace);
                }
            };
            // SAFETY: `frame` is freshly allocated, owned here, and identity
            // mapped for the full 4 KiB page.
            unsafe {
                core::ptr::write_bytes(
                    frame.start_address().raw() as *mut u8,
                    0,
                    PERF_MMAP_PAGE_BYTES,
                );
            }
            frames.push(frame);
        }
        let mapping = Self { frames, len };
        mapping.write_u64(PERF_MMAP_DATA_OFFSET_OFFSET, PERF_MMAP_PAGE_BYTES as u64);
        mapping.write_u64(
            PERF_MMAP_DATA_SIZE_OFFSET,
            (len - PERF_MMAP_PAGE_BYTES) as u64,
        );
        Ok(mapping)
    }

    fn write_u32(&self, offset: usize, value: u32) {
        // SAFETY: the metadata frame is a live identity-mapped 4 KiB frame and
        // every call site uses a naturally aligned in-page u32 field.
        unsafe {
            core::ptr::write_volatile(
                (self.frames[0].start_address().raw() as usize + offset) as *mut u32,
                value,
            );
        }
    }

    fn write_u64(&self, offset: usize, value: u64) {
        // SAFETY: same as write_u32, for naturally aligned u64 fields.
        unsafe {
            core::ptr::write_volatile(
                (self.frames[0].start_address().raw() as usize + offset) as *mut u64,
                value,
            );
        }
    }

    fn raw_frames(&self) -> Vec<u64> {
        self.frames
            .iter()
            .map(|frame| frame.start_address().raw())
            .collect()
    }

    fn read_u64_acquire(&self, offset: usize) -> u64 {
        // SAFETY: Linux perf metadata indices are naturally aligned u64
        // locations shared atomically between kernel and userspace.
        let atomic = unsafe {
            &*((self.frames[0].start_address().raw() as usize + offset) as *const AtomicU64)
        };
        atomic.load(Ordering::Acquire)
    }

    fn write_u64_release(&self, offset: usize, value: u64) {
        // SAFETY: same shared-index contract as read_u64_acquire.
        let atomic = unsafe {
            &*((self.frames[0].start_address().raw() as usize + offset) as *const AtomicU64)
        };
        atomic.store(value, Ordering::Release);
    }

    fn write_ring(&self, head: u64, bytes: &[u8]) {
        let data_len = self.len - PERF_MMAP_PAGE_BYTES;
        for (i, byte) in bytes.iter().copied().enumerate() {
            let ring_offset = (head as usize + i) & (data_len - 1);
            let page = 1 + ring_offset / PERF_MMAP_PAGE_BYTES;
            let in_page = ring_offset % PERF_MMAP_PAGE_BYTES;
            // SAFETY: page and in_page are bounded by the allocated data
            // frames; the mapping lock gives this writer exclusive access.
            unsafe {
                core::ptr::write_volatile(
                    (self.frames[page].start_address().raw() as usize + in_page) as *mut u8,
                    byte,
                );
            }
        }
    }
}

impl Drop for PerfMmap {
    fn drop(&mut self) {
        for frame in self.frames.drain(..) {
            narf_memory::free_frame(frame);
        }
    }
}

impl core::fmt::Debug for PerfEventFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PerfEventFile")
            .field("id", &self.id)
            .field("target_task", &self.target_task)
            .field("target_pid", &self.target_pid)
            .field("target_cpu", &self.target_cpu)
            .field("enabled", &self.enabled.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl PerfEventFile {
    fn is_group_leader(&self) -> bool {
        self._group_leader.is_none()
    }

    fn is_pinned(&self) -> bool {
        self.attr.flags & PERF_ATTR_FLAG_PINNED != 0
    }

    fn is_exclusive(&self) -> bool {
        self.attr.flags & PERF_ATTR_FLAG_EXCLUSIVE != 0
    }

    fn counts_kernel(&self) -> bool {
        self.attr.flags & PERF_ATTR_FLAG_EXCLUDE_KERNEL == 0
    }

    fn counts_user(&self) -> bool {
        self.attr.flags & PERF_ATTR_FLAG_EXCLUDE_USER == 0
    }

    fn is_task_hardware_event(&self) -> bool {
        !matches!(self.attr.type_, PERF_TYPE_SOFTWARE | PERF_TYPE_TRACEPOINT)
            && self.target_task != u64::MAX
    }

    fn start_running_at(&self, cpu: usize, now: u64) {
        let _ = self.running_at_ns[cpu].compare_exchange(
            0,
            now.max(1),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn start_running(&self, cpu: usize) {
        self.start_running_at(cpu, narf_time::monotonic_ns());
    }

    fn stop_running(&self, cpu: usize) {
        let since = self.running_at_ns[cpu].swap(0, Ordering::AcqRel);
        if since != 0 {
            self.time_running_ns.fetch_add(
                narf_time::monotonic_ns().saturating_sub(since),
                Ordering::AcqRel,
            );
        }
    }

    fn tracks_task(&self, task: u64) -> bool {
        self.target_task == task || self.inherited_tasks.lock().live.contains(&task)
    }

    fn accepts_sample_from(&self, source_cpu: usize, task: u64) -> bool {
        if self.target_task == u64::MAX {
            return self.target_cpu >= 0 && self.target_cpu as usize == source_cpu;
        }
        self.tracks_task(task)
    }

    fn raw_count(&self) -> u64 {
        if self.attr.type_ == PERF_TYPE_SOFTWARE {
            return match self.attr.config {
                PERF_COUNT_SW_CPU_CLOCK => {
                    if self.target_task != u64::MAX {
                        self.task_software_count()
                    } else {
                        let cpu = self.target_cpu as usize;
                        let user = cpu_user_time_ns(cpu);
                        let total = narf_time::monotonic_ns()
                            .saturating_sub(narf_scheduler::cpu_idle_ns(cpu));
                        if !self.counts_kernel() {
                            user
                        } else if !self.counts_user() {
                            total.saturating_sub(user)
                        } else {
                            total
                        }
                    }
                }
                PERF_COUNT_SW_TASK_CLOCK => self.task_software_count(),
                _ => 0,
            };
        }
        #[cfg(target_arch = "x86_64")]
        if let Some(counter) = self.pmu_counter {
            let period = self.sample_period.load(Ordering::Acquire);
            if period != 0 {
                return sampling_residual_on(counter, period)
                    .expect("live sampled PMU counter rejected its configured period");
            }
            return read_pmu_on(counter);
        }
        #[cfg(target_arch = "x86_64")]
        {
            let cpu = narf_lib::percpu::current_cpu();
            if let Some(counter) = self.active_task_counters.lock()[cpu] {
                // SAFETY: this entry can only be populated while its target is
                // executing on this CPU; syscall reads run in that continuation.
                return unsafe { narf_arch::x86_64::pmu::read(&counter) };
            }
        }
        #[cfg(target_arch = "aarch64")]
        if let Some(counter) = self.pmu_counter {
            // SAFETY: this file owns the live current-CPU counter until Drop.
            return unsafe { counter.read() }.unwrap_or(0);
        }
        #[cfg(target_arch = "aarch64")]
        {
            let cpu = narf_lib::percpu::current_cpu();
            if let Some(counter) = self.active_task_counters.lock()[cpu] {
                // SAFETY: scheduler switch-in allocated this counter on this CPU.
                return unsafe { counter.read() }.unwrap_or(0);
            }
        }

        // PERF_COUNT_SW_DUMMY is the only software event admitted until
        // scheduler-owned, per-target software accounting exists. Its specified
        // count is exactly zero.
        0
    }

    #[cfg(target_arch = "x86_64")]
    fn task_switch(&self, cpu: usize, running: bool) -> bool {
        if self.target_task == u64::MAX || self.pmu_event.is_none() {
            return true;
        }
        let mut active = self.active_task_counters.lock();
        if self.target_cpu >= 0 && cpu != self.target_cpu as usize {
            return true;
        }
        if running {
            if active[cpu].is_some() || !self.enabled.load(Ordering::Acquire) {
                return true;
            }
            // SAFETY: the scheduler invokes this on the current logical CPU in
            // executor context. The returned slot belongs to this CPU.
            let Ok(counter) = (unsafe {
                narf_arch::x86_64::pmu::alloc_counter_filtered(
                    self.pmu_event.unwrap(),
                    self.counts_kernel(),
                    self.counts_user(),
                )
            }) else {
                return false;
            };
            let sample_period = self.sample_period.load(Ordering::Acquire);
            if sample_period != 0 {
                if ensure_pmi_route().is_err() {
                    // SAFETY: same current-CPU allocation.
                    unsafe { narf_arch::x86_64::pmu::release(counter) };
                    return false;
                }
                // SAFETY: freshly allocated current-CPU counter.
                let period_left = self
                    .sample_period_left
                    .load(Ordering::Acquire)
                    .clamp(1, sample_period);
                // SAFETY: freshly allocated current-CPU counter; the first
                // preload and subsequent reload are backend-validated.
                if unsafe {
                    narf_arch::x86_64::pmu::arm_sampling_with_reload(
                        &counter,
                        period_left,
                        sample_period,
                    )
                }
                .is_err()
                {
                    // SAFETY: same current-CPU allocation.
                    unsafe { narf_arch::x86_64::pmu::release(counter) };
                    return false;
                }
                publish_active_sample(cpu, counter.idx as usize, self);
            }
            active[cpu] = Some(counter);
            self.start_running(cpu);
        } else if let Some(counter) = active[cpu].take() {
            let sample_period = self.sample_period.load(Ordering::Acquire);
            if sample_period != 0 {
                clear_active_sample(cpu, counter.idx as usize);
                // SAFETY: current-CPU live sampled allocation. Capture the
                // exact remaining distance before disarming the slot.
                if let Ok(left) = unsafe { narf_arch::x86_64::pmu::sampling_period_left(&counter) }
                {
                    self.sample_period_left.store(left, Ordering::Release);
                }
                // SAFETY: current-CPU live allocation.
                let _ = unsafe { narf_arch::x86_64::pmu::pause_sampling(&counter) };
            }
            // SAFETY: current-CPU live allocation.
            let value = if sample_period == 0 {
                // SAFETY: current-CPU live allocation.
                unsafe { narf_arch::x86_64::pmu::read(&counter) }
            } else {
                // SAFETY: current-CPU sampled allocation.
                unsafe { narf_arch::x86_64::pmu::sampling_residual(&counter, sample_period) }
                    .unwrap_or(0)
            };
            self.count_accumulated.fetch_add(value, Ordering::AcqRel);
            // SAFETY: current-CPU live allocation.
            unsafe { narf_arch::x86_64::pmu::release(counter) };
            self.stop_running(cpu);
        }
        true
    }

    #[cfg(target_arch = "aarch64")]
    fn task_switch(&self, cpu: usize, running: bool) -> bool {
        if self.target_task == u64::MAX || self.pmu_event.is_none() {
            return true;
        }
        let mut active = self.active_task_counters.lock();
        if self.target_cpu >= 0 && cpu != self.target_cpu as usize {
            return true;
        }
        if running {
            if active[cpu].is_some() || !self.enabled.load(Ordering::Acquire) {
                return true;
            }
            // SAFETY: scheduler invokes this hook on the current CPU at EL1.
            let Ok(counter) = (unsafe {
                self.pmu_event
                    .unwrap()
                    .allocate(self.counts_kernel(), self.counts_user())
            }) else {
                return false;
            };
            let period = self.sample_period.load(Ordering::Acquire);
            if period != 0 {
                let route_failed = ensure_pmi_route().is_err();
                let period_left = self
                    .sample_period_left
                    .load(Ordering::Acquire)
                    .clamp(1, period);
                // SAFETY: freshly allocated current-CPU counter and routed PPI.
                let arm_failed = unsafe { counter.arm_with_reload(period_left, period) }.is_err();
                if route_failed || arm_failed {
                    // SAFETY: the fresh allocation is still owned on this CPU.
                    let _ = unsafe { counter.release() };
                    return false;
                }
                publish_active_sample(cpu, counter.sample_slot(), self);
            // SAFETY: freshly allocated current-CPU counter.
            } else if unsafe { counter.start() }.is_err() {
                // SAFETY: the fresh allocation is still owned on this CPU.
                let _ = unsafe { counter.release() };
                return false;
            }
            active[cpu] = Some(counter);
            self.start_running(cpu);
        } else if let Some(counter) = active[cpu].take() {
            clear_active_sample(cpu, counter.sample_slot());
            if self.sample_period.load(Ordering::Acquire) != 0 {
                // SAFETY: switch-out runs on the CPU owning this live counter.
                if let Ok(left) = unsafe { counter.period_left() } {
                    self.sample_period_left.store(left, Ordering::Release);
                }
            }
            // SAFETY: switch-out runs on the CPU owning this active counter.
            let _ = unsafe { counter.pause() };
            // SAFETY: the paused counter remains owned on this CPU.
            let value = unsafe { counter.read() }.unwrap_or(0);
            self.count_accumulated.fetch_add(value, Ordering::AcqRel);
            // SAFETY: the paused counter remains owned on this CPU.
            let _ = unsafe { counter.release() };
            self.stop_running(cpu);
        }
        true
    }

    fn enable(&self) {
        self.scheduling_error.store(false, Ordering::Release);
        if !self.enabled.swap(true, Ordering::AcqRel) {
            let raw = self.raw_count();
            let now = narf_time::monotonic_ns();
            self.count_base.store(raw, Ordering::Release);
            self.enabled_at_ns.store(now, Ordering::Release);
            if !self.is_task_hardware_event() {
                let cpu = if self.target_cpu >= 0 {
                    self.target_cpu as usize
                } else {
                    narf_lib::percpu::current_cpu()
                };
                self.start_running_at(cpu, now);
            }
            self.last_sample_ns.store(0, Ordering::Release);
            #[cfg(target_arch = "x86_64")]
            {
                self.last_sample_ns.store(0, Ordering::Release);
                let sample_period = self.sample_period.load(Ordering::Acquire);
                if sample_period != 0 {
                    if let Some(counter) = self.pmu_counter {
                        publish_active_sample(counter.cpu as usize, counter.idx as usize, self);
                        let _ = arm_pmu_on(counter, sample_period);
                    }
                }
            }
            #[cfg(target_arch = "x86_64")]
            if self.tracks_task(crate::handlers::current_task_id()) {
                self.task_switch(narf_lib::percpu::current_cpu(), true);
            }
            #[cfg(target_arch = "aarch64")]
            {
                let period = self.sample_period.load(Ordering::Acquire);
                if let Some(counter) = self.pmu_counter.as_ref() {
                    if period != 0 {
                        publish_active_sample(
                            self.target_cpu as usize,
                            counter.sample_slot(),
                            self,
                        );
                        // SAFETY: this per-CPU file owns the current-CPU counter.
                        let _ = unsafe { (*counter).arm(period) };
                    } else {
                        // SAFETY: this per-CPU file owns the current-CPU counter.
                        let _ = unsafe { (*counter).start() };
                    }
                }
                if self.tracks_task(crate::handlers::current_task_id()) {
                    self.task_switch(narf_lib::percpu::current_cpu(), true);
                }
            }
        }
        self.publish_mmap_state();
    }

    fn disable(&self) {
        if self.enabled.swap(false, Ordering::AcqRel) {
            #[cfg(target_arch = "x86_64")]
            if self.tracks_task(crate::handlers::current_task_id()) {
                self.task_switch(narf_lib::percpu::current_cpu(), false);
            }
            #[cfg(target_arch = "aarch64")]
            if self.tracks_task(crate::handlers::current_task_id()) {
                self.task_switch(narf_lib::percpu::current_cpu(), false);
            }
            #[cfg(target_arch = "x86_64")]
            if self.sample_period.load(Ordering::Acquire) != 0 {
                if let Some(counter) = self.pmu_counter {
                    clear_active_sample(counter.cpu as usize, counter.idx as usize);
                    let _ = pause_pmu_on(counter);
                }
            }
            #[cfg(target_arch = "aarch64")]
            if let Some(counter) = self.pmu_counter.as_ref() {
                if self.sample_period.load(Ordering::Acquire) != 0 {
                    clear_active_sample(self.target_cpu as usize, counter.sample_slot());
                }
                // SAFETY: this per-CPU file owns the current-CPU counter.
                let _ = unsafe { (*counter).pause() };
            }
            let raw = self.raw_count();
            let base = self.count_base.load(Ordering::Acquire);
            self.count_accumulated
                .fetch_add(raw.wrapping_sub(base), Ordering::AcqRel);
            let now = narf_time::monotonic_ns();
            let since = self.enabled_at_ns.load(Ordering::Acquire);
            self.time_enabled_ns
                .fetch_add(now.saturating_sub(since), Ordering::AcqRel);
            if !self.is_task_hardware_event() {
                let cpu = if self.target_cpu >= 0 {
                    self.target_cpu as usize
                } else {
                    narf_lib::percpu::current_cpu()
                };
                self.stop_running(cpu);
            }
        }
        self.publish_mmap_state();
    }

    #[cfg(target_arch = "x86_64")]
    fn set_sample_period(&self, period: u64) -> Result<(), FsError> {
        if period == 0 {
            return Err(FsError::InvalidData);
        }
        if self.enabled.load(Ordering::Acquire)
            || self.pmu_event.is_none()
            || self.sample_period.load(Ordering::Acquire) == 0
            || self.active_task_counters.lock().iter().any(Option::is_some)
        {
            return Err(FsError::Unsupported);
        }

        if let Some(counter) = self.pmu_counter {
            arm_pmu_on(counter, period).map_err(|_| FsError::InvalidData)?;
            pause_pmu_on(counter).map_err(|_| FsError::InvalidData)?;
        } else {
            // Task events allocate counters at switch-in. Allocate a temporary
            // current-CPU slot to validate the backend's real width/preload.
            // SAFETY: ioctl runs at CPL0 on the current CPU.
            let counter = unsafe {
                narf_arch::x86_64::pmu::alloc_counter_filtered(
                    self.pmu_event.unwrap(),
                    self.counts_kernel(),
                    self.counts_user(),
                )
                .map_err(|_| FsError::Unsupported)?
            };
            // SAFETY: the temporary slot is live and current-CPU-owned.
            let armed = unsafe { narf_arch::x86_64::pmu::arm_sampling(&counter, period) };
            if armed.is_ok() {
                // SAFETY: same temporary live counter.
                let _ = unsafe { narf_arch::x86_64::pmu::pause_sampling(&counter) };
            }
            // SAFETY: same temporary live counter.
            unsafe { narf_arch::x86_64::pmu::release(counter) };
            armed.map_err(|_| FsError::InvalidData)?;
        }
        self.sample_period.store(period, Ordering::Release);
        self.sample_period_left.store(period, Ordering::Release);
        self.last_sample_period.store(period, Ordering::Release);
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn set_sample_period(&self, period: u64) -> Result<(), FsError> {
        if period == 0
            || self.pmu_event.is_none()
            || self.sample_period.load(Ordering::Acquire) == 0
        {
            return Err(FsError::InvalidData);
        }
        let cpu = narf_lib::percpu::current_cpu();
        let active = self.active_task_counters.lock();
        if active
            .iter()
            .enumerate()
            .any(|(idx, counter)| idx != cpu && counter.is_some())
        {
            // Reprogramming another CPU's PMU requires a synchronous IPI
            // rendezvous; never report success without it.
            return Err(FsError::Unsupported);
        }
        let live = self.pmu_counter.or(active[cpu]);
        if let Some(counter) = live {
            if counter.sample_slot() >= 8 {
                return Err(FsError::Unsupported);
            }
            // SAFETY: the only live counter is owned by this file on the
            // current CPU. Re-arming takes effect before ioctl returns.
            unsafe { counter.arm(period) }.map_err(|_| FsError::InvalidData)?;
        } else {
            // Disabled or switched-out task event: validate the real backend
            // synchronously with a temporary current-CPU allocation.
            // SAFETY: ioctl executes at EL1 on the current CPU.
            let counter = unsafe {
                self.pmu_event
                    .unwrap()
                    .allocate(self.counts_kernel(), self.counts_user())
            }
            .map_err(|_| FsError::Unsupported)?;
            // SAFETY: freshly allocated current-CPU counter and routed PPI.
            let armed = unsafe { counter.arm(period) };
            if armed.is_ok() {
                // SAFETY: same live current-CPU temporary counter.
                let _ = unsafe { counter.pause() };
            }
            // SAFETY: same live current-CPU temporary counter.
            let _ = unsafe { counter.release() };
            armed.map_err(|_| FsError::InvalidData)?;
        }
        drop(active);
        self.sample_period.store(period, Ordering::Release);
        self.sample_period_left.store(period, Ordering::Release);
        self.last_sample_period.store(period, Ordering::Release);
        Ok(())
    }

    fn reset(&self) {
        self.count_accumulated.store(0, Ordering::Release);
        self.time_enabled_ns.store(0, Ordering::Release);
        self.time_running_ns.store(0, Ordering::Release);
        self.sample_period_left.store(
            self.sample_period.load(Ordering::Acquire),
            Ordering::Release,
        );
        if self.enabled.load(Ordering::Acquire) {
            let now = narf_time::monotonic_ns();
            self.count_base.store(self.raw_count(), Ordering::Release);
            self.enabled_at_ns.store(now, Ordering::Release);
            for running_at in &self.running_at_ns {
                if running_at.load(Ordering::Acquire) != 0 {
                    running_at.store(now.max(1), Ordering::Release);
                }
            }
        }
        self.publish_mmap_state();
    }

    fn snapshot(&self) -> (u64, u64, u64) {
        let mut value = self.count_accumulated.load(Ordering::Acquire);
        let mut time_enabled = self.time_enabled_ns.load(Ordering::Acquire);
        let mut time_running = self.time_running_ns.load(Ordering::Acquire);
        let now = narf_time::monotonic_ns();
        if self.enabled.load(Ordering::Acquire) {
            value = value.wrapping_add(
                self.raw_count()
                    .wrapping_sub(self.count_base.load(Ordering::Acquire)),
            );
            time_enabled = time_enabled
                .saturating_add(now.saturating_sub(self.enabled_at_ns.load(Ordering::Acquire)));
        }
        for running_at in &self.running_at_ns {
            let running_since = running_at.load(Ordering::Acquire);
            if running_since != 0 {
                time_running = time_running.saturating_add(now.saturating_sub(running_since));
            }
        }
        (value, time_enabled, time_running.min(time_enabled))
    }

    fn publish_mmap_state(&self) {
        let (value, time_enabled, time_running) = self.snapshot();
        let mapping = self.mmap.lock();
        let Some(mapping) = mapping.as_ref() else {
            return;
        };
        let sequence = self.mmap_seq.fetch_add(2, Ordering::Relaxed);
        mapping.write_u32(PERF_MMAP_LOCK_OFFSET, sequence.wrapping_add(1));
        core::sync::atomic::compiler_fence(Ordering::Release);
        // `index == 0` (the zeroed default) tells userspace that direct RDPMC
        // is unavailable; Linux then treats `offset` as the count snapshot.
        mapping.write_u64(PERF_MMAP_OFFSET_OFFSET, value);
        mapping.write_u64(PERF_MMAP_TIME_ENABLED_OFFSET, time_enabled);
        mapping.write_u64(PERF_MMAP_TIME_RUNNING_OFFSET, time_running);
        core::sync::atomic::compiler_fence(Ordering::Release);
        mapping.write_u32(PERF_MMAP_LOCK_OFFSET, sequence.wrapping_add(2));
    }

    fn push_record_here(&self, record: &[u8]) -> RecordPush {
        if self.output_paused.load(Ordering::Acquire) {
            return RecordPush::Suppressed;
        }
        let mapping = self.mmap.lock();
        let Some(mapping) = mapping.as_ref() else {
            return RecordPush::Unmapped;
        };
        let data_size = (mapping.len - PERF_MMAP_PAGE_BYTES) as u64;
        let head = mapping.read_u64_acquire(PERF_MMAP_DATA_HEAD_OFFSET);
        let tail = mapping.read_u64_acquire(PERF_MMAP_DATA_TAIL_OFFSET);
        if head.wrapping_sub(tail) > data_size
            || record.len() as u64 > data_size.saturating_sub(head.wrapping_sub(tail))
        {
            return RecordPush::Full;
        }
        mapping.write_ring(head, record);
        let new_head = head.wrapping_add(record.len() as u64);
        mapping.write_u64_release(PERF_MMAP_DATA_HEAD_OFFSET, new_head);
        let threshold = self.attr.wakeup_events_or_watermark;
        if threshold != 0 {
            if self.attr.flags & PERF_ATTR_FLAG_WATERMARK != 0 {
                // In watermark mode the union member is a byte threshold over
                // unread ring data, not a record count.
                if new_head.wrapping_sub(tail) >= u64::from(threshold) {
                    narf_net::readiness::notify(0);
                }
            } else if self
                .wakeup_pending
                .fetch_add(1, Ordering::AcqRel)
                .wrapping_add(1)
                >= threshold
            {
                self.wakeup_pending.store(0, Ordering::Release);
                narf_net::readiness::notify(0);
            }
        }
        RecordPush::Committed
    }

    fn push_record(&self, record: &[u8]) -> bool {
        let target = self.output_target.lock().clone();
        let result = if let Some(target) = target {
            target
                .as_any()
                .and_then(|any| any.downcast_ref::<PerfEventFile>())
                .map_or(RecordPush::Unmapped, |event| event.push_record_here(record))
        } else {
            self.push_record_here(record)
        };
        if result == RecordPush::Full {
            self.sample_lost.fetch_add(1, Ordering::Relaxed);
        }
        result == RecordPush::Committed
    }

    #[allow(clippy::too_many_arguments)] // Linux sample fields are independent ABI columns.
    fn sample_record(
        &self,
        ip: u64,
        pid: u32,
        tid: u32,
        now: u64,
        user_state: Option<&narf_interrupts::InterruptedUserState>,
        user_stack: &[u8],
        raw: &[u8],
    ) -> bool {
        let sample_type = self.attr.sample_type;
        let mut payload = Vec::with_capacity(80);
        let push_u32 = |payload: &mut Vec<u8>, value: u32| {
            payload.extend_from_slice(&value.to_ne_bytes());
        };
        let push_u64 = |payload: &mut Vec<u8>, value: u64| {
            payload.extend_from_slice(&value.to_ne_bytes());
        };
        if sample_type & PERF_SAMPLE_IDENTIFIER != 0 {
            push_u64(&mut payload, self.id);
        }
        if sample_type & PERF_SAMPLE_IP != 0 {
            push_u64(&mut payload, ip);
        }
        if sample_type & PERF_SAMPLE_TID != 0 {
            push_u32(&mut payload, pid);
            push_u32(&mut payload, tid);
        }
        if sample_type & PERF_SAMPLE_TIME != 0 {
            push_u64(&mut payload, now);
        }
        if sample_type & PERF_SAMPLE_ADDR != 0 {
            // Counting PMUs do not report a sampled data address.
            push_u64(&mut payload, 0);
        }
        if sample_type & PERF_SAMPLE_READ != 0 {
            self.append_sample_read(&mut payload);
        }
        if sample_type & PERF_SAMPLE_CALLCHAIN != 0 {
            let max_stack = if self.attr.sample_max_stack == 0 {
                127
            } else {
                usize::from(self.attr.sample_max_stack)
            };
            let callchain = unwind_user_callchain(ip, user_state, user_stack, max_stack);
            push_u64(&mut payload, callchain.len() as u64);
            for address in callchain {
                push_u64(&mut payload, address);
            }
        }
        if sample_type & PERF_SAMPLE_ID != 0 {
            push_u64(&mut payload, self.id);
        }
        if sample_type & PERF_SAMPLE_STREAM_ID != 0 {
            push_u64(&mut payload, self.id);
        }
        if sample_type & PERF_SAMPLE_CPU != 0 {
            push_u32(&mut payload, narf_lib::percpu::current_cpu() as u32);
            push_u32(&mut payload, 0);
        }
        if sample_type & PERF_SAMPLE_PERIOD != 0 {
            push_u64(
                &mut payload,
                self.last_sample_period.load(Ordering::Acquire),
            );
        }
        if sample_type & PERF_SAMPLE_RAW != 0 {
            push_u32(&mut payload, raw.len() as u32);
            payload.extend_from_slice(raw);
            while payload.len() & 7 != 0 {
                payload.push(0);
            }
        }
        if sample_type & PERF_SAMPLE_REGS_USER != 0 {
            let Some(state) = user_state else {
                return false;
            };
            push_u64(&mut payload, state.abi);
            for index in 0..64 {
                if self.attr.sample_regs_user & (1 << index) != 0 {
                    let Some(value) = state.regs.get(index) else {
                        return false;
                    };
                    push_u64(&mut payload, *value);
                }
            }
        }
        if sample_type & PERF_SAMPLE_STACK_USER != 0 {
            push_u64(&mut payload, user_stack.len() as u64);
            payload.extend_from_slice(user_stack);
            while payload.len() & 7 != 0 {
                payload.push(0);
            }
            push_u64(&mut payload, user_stack.len() as u64);
        }
        if sample_type & PERF_SAMPLE_WEIGHT != 0 {
            push_u64(&mut payload, 0);
        }
        if sample_type & PERF_SAMPLE_DATA_SRC != 0 {
            push_u64(&mut payload, 0);
        }
        if sample_type & PERF_SAMPLE_TRANSACTION != 0 {
            push_u64(&mut payload, 0);
        }
        if sample_type & PERF_SAMPLE_PHYS_ADDR != 0 {
            push_u64(&mut payload, 0);
        }
        if sample_type & PERF_SAMPLE_DATA_PAGE_SIZE != 0 {
            push_u64(&mut payload, 0);
        }
        if sample_type & PERF_SAMPLE_CODE_PAGE_SIZE != 0 {
            let task = u64::from(tid);
            let page_size = narf_scheduler::address_space_of(narf_scheduler::TaskId(task))
                .or_else(|| {
                    (task == current_task_id()).then(narf_scheduler::current_address_space)?
                })
                .and_then(|space| space.mapped_page_size(narf_memory::VirtAddr::new(ip)))
                .unwrap_or(0);
            push_u64(&mut payload, page_size);
        }
        if sample_type & PERF_SAMPLE_WEIGHT_STRUCT != 0 {
            push_u64(&mut payload, 0);
        }
        let lost = self.sample_lost.swap(0, Ordering::AcqRel);
        if lost != 0 {
            let mut record = Vec::with_capacity(64);
            push_u32(&mut record, PERF_RECORD_LOST);
            record.extend_from_slice(&0u16.to_ne_bytes());
            record.extend_from_slice(&0u16.to_ne_bytes());
            push_u64(&mut record, self.id);
            push_u64(&mut record, lost);
            // PERF_RECORD_LOST is a non-sample record. When sample_id_all is
            // requested, Linux appends the selected sample identity fields;
            // perf uses that trailer to associate the loss with an evsel.
            self.append_sample_id(&mut record, pid, tid, now);
            if !Self::finish_record(&mut record, 0) || !self.push_record(&record) {
                self.sample_lost.fetch_add(lost, Ordering::Relaxed);
            }
        }

        let size = 8usize.saturating_add(payload.len());
        let Ok(size) = u16::try_from(size) else {
            return false;
        };
        let mut record = Vec::with_capacity(size as usize);
        push_u32(&mut record, PERF_RECORD_SAMPLE);
        record.extend_from_slice(&0u16.to_ne_bytes());
        record.extend_from_slice(&size.to_ne_bytes());
        record.extend_from_slice(&payload);
        self.push_record(&record)
    }

    fn append_sample_read(&self, payload: &mut Vec<u8>) {
        let push = |payload: &mut Vec<u8>, value: u64| {
            payload.extend_from_slice(&value.to_ne_bytes());
        };
        let (value, time_enabled, time_running) = self.snapshot();
        let format = self.attr.read_format;
        if format & PERF_FORMAT_GROUP != 0 {
            let members = self.member_files();
            push(payload, 1 + members.len() as u64);
            if format & PERF_FORMAT_TOTAL_TIME_ENABLED != 0 {
                push(payload, time_enabled);
            }
            if format & PERF_FORMAT_TOTAL_TIME_RUNNING != 0 {
                push(payload, time_running);
            }
            push(payload, value);
            if format & PERF_FORMAT_ID != 0 {
                push(payload, self.id);
            }
            if format & PERF_FORMAT_LOST != 0 {
                push(payload, self.sample_lost.load(Ordering::Acquire));
            }
            for file in members {
                let event = file
                    .as_any()
                    .and_then(|any| any.downcast_ref::<PerfEventFile>())
                    .expect("perf group contains a non-perf member");
                let (member_value, _, _) = event.snapshot();
                push(payload, member_value);
                if format & PERF_FORMAT_ID != 0 {
                    push(payload, event.id);
                }
                if format & PERF_FORMAT_LOST != 0 {
                    push(payload, event.sample_lost.load(Ordering::Acquire));
                }
            }
        } else {
            push(payload, value);
            if format & PERF_FORMAT_TOTAL_TIME_ENABLED != 0 {
                push(payload, time_enabled);
            }
            if format & PERF_FORMAT_TOTAL_TIME_RUNNING != 0 {
                push(payload, time_running);
            }
            if format & PERF_FORMAT_ID != 0 {
                push(payload, self.id);
            }
            if format & PERF_FORMAT_LOST != 0 {
                push(payload, self.sample_lost.load(Ordering::Acquire));
            }
        }
    }

    fn selected_task_time(&self, task: u64) -> u64 {
        let current = task == crate::handlers::current_task_id();
        let slice = crate::handlers::cpu_time_ns_of(task).saturating_add(if current {
            narf_scheduler::stackful::current_slice_elapsed_ns()
        } else {
            0
        });
        // Linux software CPU/task clocks count scheduled task time regardless
        // of exclude_user/exclude_kernel (perf's :u/:k modifiers produce the
        // same value for these software events). x86's own-stack ledger is
        // already total time; aarch64's legacy ledger needs its syscall time.
        #[cfg(target_arch = "x86_64")]
        return slice;
        #[cfg(not(target_arch = "x86_64"))]
        return slice
            .saturating_add(crate::handlers::kern_time_ns_of(task))
            .saturating_add(if current {
                crate::handlers::current_kernel_span_elapsed_ns()
            } else {
                0
            });
    }

    fn is_task_software_clock(&self) -> bool {
        self.attr.type_ == PERF_TYPE_SOFTWARE
            && self.target_task != u64::MAX
            && matches!(
                self.attr.config,
                PERF_COUNT_SW_CPU_CLOCK | PERF_COUNT_SW_TASK_CLOCK
            )
    }

    fn task_software_count(&self) -> u64 {
        // Serialize the live-task snapshot with exit retirement. Otherwise a
        // concurrent exit could be counted once from its live ledger and once
        // from the retired total, or disappear between those two reads.
        let state = self.inherited_tasks.lock();
        let mut total = state.retired_software_ns;
        if !state.target_software_retired {
            total = total.saturating_add(self.selected_task_time(self.target_task));
        }
        for task in &state.live {
            total = total.saturating_add(self.selected_task_time(*task));
        }
        total
    }

    /// Consume one genuine sampling overflow from an ioctl refresh budget.
    fn consume_refresh(&self) -> bool {
        let mut limit = self.refresh_limit.load(Ordering::Acquire);
        while limit != 0 {
            match self.refresh_limit.compare_exchange_weak(
                limit,
                limit - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) if limit == 1 => {
                    self.disable();
                    self.refresh_hup.store(true, Ordering::Release);
                    return true;
                }
                Ok(_) => return false,
                Err(observed) => limit = observed,
            }
        }
        false
    }

    fn adjust_frequency_period(&self, now: u64) {
        if self.sample_frequency == 0 {
            return;
        }
        let previous = self.last_sample_ns.swap(now, Ordering::AcqRel);
        if previous == 0 {
            return;
        }
        let elapsed = now.saturating_sub(previous).max(1);
        let current = self.sample_period.load(Ordering::Acquire).max(1);
        // Linux derives the next hardware period from observed event count
        // over elapsed time. Bound each correction to 4x so scheduler jitter
        // or a delayed drain cannot collapse the period into an IRQ storm.
        let next = frequency_period(current, self.sample_frequency, elapsed);
        #[cfg(target_arch = "aarch64")]
        let next = next.max(narf_arch::aarch64::pmu::minimum_sample_period());
        self.sample_period.store(next, Ordering::Release);
        #[cfg(target_arch = "x86_64")]
        {
            if let Some(counter) = &self.pmu_counter {
                narf_arch::x86_64::pmu::update_sampling_period(counter, next);
            }
            for counter in self.active_task_counters.lock().iter().flatten() {
                narf_arch::x86_64::pmu::update_sampling_period(counter, next);
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            if let Some(counter) = self.pmu_counter {
                counter.update_period(next);
            }
            for counter in self.active_task_counters.lock().iter().flatten() {
                counter.update_period(next);
            }
        }
    }

    fn append_sample_id(&self, record: &mut Vec<u8>, pid: u32, tid: u32, now: u64) {
        if self.attr.flags & PERF_ATTR_FLAG_SAMPLE_ID_ALL == 0 {
            return;
        }
        if self.attr.sample_type & PERF_SAMPLE_TID != 0 {
            record.extend_from_slice(&pid.to_ne_bytes());
            record.extend_from_slice(&tid.to_ne_bytes());
        }
        if self.attr.sample_type & PERF_SAMPLE_TIME != 0 {
            record.extend_from_slice(&now.to_ne_bytes());
        }
        if self.attr.sample_type & PERF_SAMPLE_ID != 0 {
            record.extend_from_slice(&self.id.to_ne_bytes());
        }
        if self.attr.sample_type & PERF_SAMPLE_STREAM_ID != 0 {
            record.extend_from_slice(&self.id.to_ne_bytes());
        }
        if self.attr.sample_type & PERF_SAMPLE_CPU != 0 {
            record.extend_from_slice(&(narf_lib::percpu::current_cpu() as u32).to_ne_bytes());
            record.extend_from_slice(&0u32.to_ne_bytes());
        }
        if self.attr.sample_type & PERF_SAMPLE_IDENTIFIER != 0 {
            record.extend_from_slice(&self.id.to_ne_bytes());
        }
    }

    fn finish_record(record: &mut [u8], misc: u16) -> bool {
        let Ok(size) = u16::try_from(record.len()) else {
            return false;
        };
        record[4..6].copy_from_slice(&misc.to_ne_bytes());
        record[6..8].copy_from_slice(&size.to_ne_bytes());
        true
    }

    fn comm_record(&self, pid: u32, tid: u32, comm: &str, exec: bool) -> bool {
        let mut record = Vec::with_capacity(64);
        record.extend_from_slice(&PERF_RECORD_COMM.to_ne_bytes());
        record.extend_from_slice(&0u16.to_ne_bytes());
        record.extend_from_slice(&0u16.to_ne_bytes());
        record.extend_from_slice(&pid.to_ne_bytes());
        record.extend_from_slice(&tid.to_ne_bytes());
        record.extend_from_slice(comm.as_bytes());
        record.push(0);
        while record.len() & 7 != 0 {
            record.push(0);
        }
        self.append_sample_id(&mut record, pid, tid, narf_time::monotonic_ns());
        let misc = if exec && self.attr.flags & PERF_ATTR_FLAG_COMM_EXEC != 0 {
            PERF_RECORD_MISC_COMM_EXEC
        } else {
            0
        };
        Self::finish_record(&mut record, misc) && self.push_record(&record)
    }

    fn task_record(&self, record_type: u32, pid: u32, ppid: u32, tid: u32, ptid: u32) -> bool {
        let now = narf_time::monotonic_ns();
        let mut record = Vec::with_capacity(64);
        record.extend_from_slice(&record_type.to_ne_bytes());
        record.extend_from_slice(&0u16.to_ne_bytes());
        record.extend_from_slice(&0u16.to_ne_bytes());
        record.extend_from_slice(&pid.to_ne_bytes());
        record.extend_from_slice(&ppid.to_ne_bytes());
        record.extend_from_slice(&tid.to_ne_bytes());
        record.extend_from_slice(&ptid.to_ne_bytes());
        record.extend_from_slice(&now.to_ne_bytes());
        self.append_sample_id(&mut record, pid, tid, now);
        Self::finish_record(&mut record, 0) && self.push_record(&record)
    }

    fn mmap_record(&self, mapping: &PerfMapping<'_>) -> bool {
        let executable = mapping.prot & 4 != 0;
        if (executable && self.attr.flags & (PERF_ATTR_FLAG_MMAP | PERF_ATTR_FLAG_MMAP2) == 0)
            || (!executable && self.attr.flags & PERF_ATTR_FLAG_MMAP_DATA == 0)
        {
            return false;
        }

        let mmap2 = self.attr.flags & PERF_ATTR_FLAG_MMAP2 != 0;
        let record_type = if mmap2 {
            PERF_RECORD_MMAP2
        } else {
            PERF_RECORD_MMAP
        };
        let now = narf_time::monotonic_ns();
        let mut record = Vec::with_capacity(96);
        record.extend_from_slice(&record_type.to_ne_bytes());
        record.extend_from_slice(&0u16.to_ne_bytes());
        record.extend_from_slice(&0u16.to_ne_bytes());
        record.extend_from_slice(&mapping.pid.to_ne_bytes());
        record.extend_from_slice(&mapping.tid.to_ne_bytes());
        record.extend_from_slice(&mapping.addr.to_ne_bytes());
        record.extend_from_slice(&mapping.len.to_ne_bytes());
        record.extend_from_slice(&mapping.pgoff.to_ne_bytes());
        if mmap2 {
            // NARF currently has one VFS device namespace (dev 0:0) and no
            // inode-generation counter. `ino` is the backing FileOps' stable
            // filesystem identity, or zero for an anonymous/synthetic map.
            record.extend_from_slice(&0u32.to_ne_bytes());
            record.extend_from_slice(&0u32.to_ne_bytes());
            record.extend_from_slice(&mapping.ino.to_ne_bytes());
            record.extend_from_slice(&0u64.to_ne_bytes());
            record.extend_from_slice(&mapping.prot.to_ne_bytes());
            record.extend_from_slice(&mapping.flags.to_ne_bytes());
        }
        record.extend_from_slice(mapping.filename.as_bytes());
        record.push(0);
        while record.len() & 7 != 0 {
            record.push(0);
        }
        self.append_sample_id(&mut record, mapping.pid, mapping.tid, now);
        let misc = if executable {
            0
        } else {
            PERF_RECORD_MISC_MMAP_DATA
        };
        Self::finish_record(&mut record, misc) && self.push_record(&record)
    }

    fn member_files(&self) -> Vec<Arc<dyn FileOps>> {
        self.group_members
            .lock()
            .iter()
            .filter_map(Weak::upgrade)
            .collect()
    }

    fn add_group_member(&self, member: &Arc<dyn FileOps>) {
        self.group_members.lock().push(Arc::downgrade(member));
    }

    fn for_group(&self, flags: usize, mut op: impl FnMut(&PerfEventFile)) -> Result<(), FsError> {
        if flags & !PERF_IOC_FLAG_GROUP != 0 {
            return Err(FsError::InvalidData);
        }
        op(self);
        if flags & PERF_IOC_FLAG_GROUP != 0 {
            for file in self.member_files() {
                if let Some(event) = file
                    .as_any()
                    .and_then(|any| any.downcast_ref::<PerfEventFile>())
                {
                    op(event);
                }
            }
        }
        Ok(())
    }

    fn push_word(buf: &mut [u8], cursor: &mut usize, value: u64) -> Result<(), FsError> {
        let end = cursor.saturating_add(8);
        let dst = buf.get_mut(*cursor..end).ok_or(FsError::InvalidData)?;
        dst.copy_from_slice(&value.to_ne_bytes());
        *cursor = end;
        Ok(())
    }
}

struct PerfMapping<'a> {
    pid: u32,
    tid: u32,
    addr: u64,
    len: u64,
    pgoff: u64,
    ino: u64,
    prot: u32,
    flags: u32,
    filename: &'a str,
}

/// `enum { … } fd_type` for `BPF_TASK_FD_QUERY`. NARF's
/// `PERF_EVENT_IOC_SET_BPF` attaches to tracepoint-shaped events, so a queried
/// fd that has a program is a tracepoint.
const BPF_FD_TYPE_TRACEPOINT: u32 = 1;

/// For `BPF_TASK_FD_QUERY`: if `fd` in the current task is a perf event with a
/// BPF program attached, report `(prog_id, fd_type)`.
///
/// The name buffer the query also carries comes back empty — NARF names its
/// probes by id, not by string (see `sys_bpf_attach.rs`), so there is no
/// tracepoint name to report. // LINUX-GAP: no tracepoint-name string.
pub(crate) fn bpf_task_fd_query(fd: u32) -> Option<(u32, u32)> {
    let ops = fd::with_table(current_task_id(), |t| t.get(fd).map(|e| e.ops.clone()))??;
    let event = ops.as_any()?.downcast_ref::<PerfEventFile>()?;
    let prog = event.bpf_prog.lock().clone()?;
    Some((prog.id, BPF_FD_TYPE_TRACEPOINT))
}

/// Apply Linux `enable_on_exec` at the point a task commits a new image.
///
/// Events are owned by the monitoring process but keyed by the target task,
/// matching the way the upstream perf CLI opens events for its stopped child.
pub(crate) fn on_exec(task: u64, mappings: &[crate::process::LoadedMapping], program_path: &str) {
    let pid = crate::handlers::task_to_pid_raw(task).unwrap_or(task);
    let comm = crate::handlers::proc_comm_of(task);
    let resolved: Vec<(&crate::process::LoadedMapping, &str, u64)> = mappings
        .iter()
        .map(|mapping| {
            let filename = mapping.filename.as_deref().unwrap_or(program_path);
            let ino = if filename.starts_with('[') {
                0
            } else {
                let path = crate::handlers::apply_chroot(filename);
                narf_filesystem::registry()
                    .resolve_absolute(&path, |fs, rel| {
                        crate::handlers::poll_blocking(narf_filesystem::resolve_async(
                            fs.root(),
                            rel,
                        ))
                    })
                    .and_then(|result| result)
                    .and_then(Result::ok)
                    .map(|ops| ops.ino())
                    .unwrap_or(0)
            };
            (mapping, filename, ino)
        })
        .collect();
    let mut registry = PERF_EVENT_REGISTRY.lock();
    registry.retain(|weak| {
        let Some(event) = weak.upgrade() else {
            return false;
        };
        if event.tracks_task(task) && event.attr.flags & PERF_ATTR_FLAG_REMOVE_ON_EXEC != 0 {
            event.disable();
            event.registered.store(false, Ordering::Release);
            if ACTIVE_PERF_EVENTS.fetch_sub(1, Ordering::Relaxed) == 1 {
                narf_lib::perf::set_enabled(false);
            }
            return false;
        }
        if event.tracks_task(task)
            && event.attr.flags & PERF_ATTR_FLAG_ENABLE_ON_EXEC != 0
            && event._group_leader.is_none()
        {
            let _ = event.for_group(PERF_IOC_FLAG_GROUP, PerfEventFile::enable);
        }
        if event.tracks_task(task) {
            for (loaded, filename, ino) in &resolved {
                let mapping = PerfMapping {
                    pid: pid as u32,
                    tid: task as u32,
                    addr: loaded.addr,
                    len: loaded.len,
                    pgoff: loaded.pgoff,
                    ino: *ino,
                    prot: loaded.prot,
                    flags: 2, // loader VMAs are MAP_PRIVATE
                    filename,
                };
                let _ = event.mmap_record(&mapping);
            }
        }
        if event.tracks_task(task) && event.attr.flags & PERF_ATTR_FLAG_COMM != 0 {
            if let Some(comm) = comm.as_deref() {
                let _ = event.comm_record(pid as u32, task as u32, comm, true);
            }
        }
        true
    });
}

pub(crate) fn on_comm(task: u64, comm: &str) {
    let pid = crate::handlers::task_to_pid_raw(task).unwrap_or(task);
    let mut registry = PERF_EVENT_REGISTRY.lock();
    registry.retain(|weak| {
        let Some(event) = weak.upgrade() else {
            return false;
        };
        if event.tracks_task(task) && event.attr.flags & PERF_ATTR_FLAG_COMM != 0 {
            let _ = event.comm_record(pid as u32, task as u32, comm, false);
        }
        true
    });
}

/// Publish a mapping only after its PTE materialization has committed.
pub(crate) fn on_mmap(task: u64, fd: i32, addr: u64, len: u64, pgoff: u64, prot: u32, flags: u32) {
    const MAP_SHARED: u32 = 0x01;
    const MAP_PRIVATE: u32 = 0x02;
    let pid = crate::handlers::task_to_pid_raw(task).unwrap_or(task);
    let file = if fd >= 0 {
        fd::with_table(task, |table| {
            table
                .get(fd as u32)
                .map(|entry| (entry.ops.ino(), crate::mqueue::fd_path(task, fd as u32)))
        })
        .flatten()
    } else {
        None
    };
    let (ino, filename) = match file {
        Some((ino, Some(path))) => (ino, path),
        Some((ino, None)) => (ino, alloc::string::String::from("//unknown")),
        None => (0, alloc::string::String::from("//anon")),
    };
    let mapping = PerfMapping {
        pid: pid as u32,
        tid: task as u32,
        addr,
        len,
        pgoff,
        ino,
        prot,
        // Linux records VMA semantics, not transient mmap request controls
        // such as MAP_FIXED or MAP_ANONYMOUS.
        flags: if flags & MAP_SHARED != 0 {
            MAP_SHARED
        } else {
            MAP_PRIVATE
        },
        filename: &filename,
    };
    let mut registry = PERF_EVENT_REGISTRY.lock();
    registry.retain(|weak| {
        let Some(event) = weak.upgrade() else {
            return false;
        };
        if event.tracks_task(task) {
            let _ = event.mmap_record(&mapping);
        }
        true
    });
}

pub(crate) fn on_fork(parent_pid: u64, child_pid: u64, parent_tid: u64, child_tid: u64) {
    let mut registry = PERF_EVENT_REGISTRY.lock();
    registry.retain(|weak| {
        let Some(event) = weak.upgrade() else {
            return false;
        };
        let inherits_parent = event.tracks_task(parent_tid);
        if inherits_parent && event.attr.flags & PERF_ATTR_FLAG_INHERIT != 0 {
            let mut inherited = event.inherited_tasks.lock();
            if !inherited.live.contains(&child_tid) {
                inherited.live.push(child_tid);
            }
        }
        if inherits_parent && event.attr.flags & PERF_ATTR_FLAG_TASK != 0 {
            let _ = event.task_record(
                PERF_RECORD_FORK,
                child_pid as u32,
                parent_pid as u32,
                child_tid as u32,
                parent_tid as u32,
            );
        }
        true
    });
}

/// Stop task-targeted events when the target process becomes group-dead.
pub(crate) fn on_process_exit(pid: u64, tid: u64) {
    let parent_pid = crate::handlers::parent_of_get(pid).unwrap_or(0);
    let mut registry = PERF_EVENT_REGISTRY.lock();
    registry.retain(|weak| {
        let Some(event) = weak.upgrade() else {
            return false;
        };
        if event.target_pid == pid {
            if event.attr.flags & PERF_ATTR_FLAG_TASK != 0 {
                let _ = event.task_record(
                    PERF_RECORD_EXIT,
                    pid as u32,
                    parent_pid as u32,
                    tid as u32,
                    parent_pid as u32,
                );
            }
            if event._group_leader.is_none() {
                let _ = event.for_group(PERF_IOC_FLAG_GROUP, PerfEventFile::disable);
            }
        }
        true
    });
}

pub(crate) fn on_thread_exit(_pid: u64, tid: u64) {
    let mut registry = PERF_EVENT_REGISTRY.lock();
    registry.retain(|weak| {
        let Some(event) = weak.upgrade() else {
            return false;
        };
        let mut inherited = event.inherited_tasks.lock();
        if event.is_task_software_clock()
            && event.target_task == tid
            && !inherited.target_software_retired
        {
            inherited.retired_software_ns = inherited
                .retired_software_ns
                .saturating_add(event.selected_task_time(tid));
            inherited.target_software_retired = true;
        }
        if let Some(index) = inherited.live.iter().position(|task| *task == tid) {
            if event.is_task_software_clock() {
                inherited.retired_software_ns = inherited
                    .retired_software_ns
                    .saturating_add(event.selected_task_time(tid));
            }
            inherited.live.swap_remove(index);
        }
        true
    });
}

fn record_pending_loss(cpu: usize, counters: u8) {
    for (counter, active_id) in ACTIVE_SAMPLE_IDS[cpu].iter().enumerate() {
        if counters & (1 << counter) == 0 {
            continue;
        }
        let event_id = active_id.load(Ordering::Acquire);
        if event_id == 0 {
            continue;
        }
        let buckets = &PENDING_LOSSES[cpu];
        for bucket in buckets {
            let state = bucket.state.load(Ordering::Acquire);
            if state == 2
                && bucket.event_id.load(Ordering::Relaxed) == event_id
                && bucket
                    .state
                    .compare_exchange(2, 1, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            {
                bucket.count.fetch_add(1, Ordering::Relaxed);
                bucket.state.store(2, Ordering::Release);
                break;
            }
            if state == 0
                && bucket
                    .state
                    .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            {
                bucket.event_id.store(event_id, Ordering::Relaxed);
                bucket.count.store(1, Ordering::Relaxed);
                bucket.state.store(2, Ordering::Release);
                break;
            }
        }
    }
}

fn capture_trace(type_id: u64, bytes: &[u8]) {
    let cpu = narf_lib::percpu::current_cpu().min(SAMPLE_CPU_SLOTS - 1);
    if bytes.len() > PENDING_TRACE_BYTES {
        record_trace_loss(cpu, type_id);
        return;
    }
    let start = PENDING_TRACE_CURSOR[cpu].fetch_add(1, Ordering::Relaxed);
    for offset in 0..PENDING_TRACE_DEPTH {
        let pending = &PENDING_TRACES[cpu][rotation_index(start, offset, PENDING_TRACE_DEPTH)];
        if pending
            .state
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            continue;
        }
        // SAFETY: state 1 grants this producer exclusive byte access.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                pending.bytes.0.as_ptr().cast_mut().cast::<u8>(),
                bytes.len(),
            );
        }
        pending.type_id.store(type_id, Ordering::Relaxed);
        pending
            .task
            .store(crate::handlers::current_task_id(), Ordering::Relaxed);
        pending
            .ip
            .store(narf_interrupts::interrupted_ip(), Ordering::Relaxed);
        pending
            .time
            .store(narf_time::monotonic_ns(), Ordering::Relaxed);
        pending.len.store(bytes.len() as u32, Ordering::Relaxed);
        pending.state.store(2, Ordering::Release);
        return;
    }
    record_trace_loss(cpu, type_id);
}

fn record_trace_loss(cpu: usize, type_id: u64) {
    for bucket in &PENDING_TRACE_LOSSES[cpu] {
        let state = bucket.state.load(Ordering::Acquire);
        if state == 2
            && bucket.event_id.load(Ordering::Relaxed) == type_id
            && bucket
                .state
                .compare_exchange(2, 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            bucket.count.fetch_add(1, Ordering::Relaxed);
            bucket.state.store(2, Ordering::Release);
            return;
        }
        if state == 0
            && bucket
                .state
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            bucket.event_id.store(type_id, Ordering::Relaxed);
            bucket.count.store(1, Ordering::Relaxed);
            bucket.state.store(2, Ordering::Release);
            return;
        }
    }
}

fn capture_dynamic_probe(probe_id: u32, args: narf_tracing::ProbeArgs) {
    let mut bytes = [0; 32];
    for (chunk, value) in bytes.chunks_exact_mut(8).zip(args.words()) {
        chunk.copy_from_slice(&value.to_ne_bytes());
    }
    capture_trace(u64::from(probe_id), &bytes);
}

fn ensure_trace_observers() {
    if TRACE_OBSERVERS_INSTALLED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        narf_tracing::install_event_observer(capture_trace);
        narf_tracing::install_probe_observer(capture_dynamic_probe);
    }
}

fn deliver_sigtrap(event: &PerfEventFile, task: u64) {
    if event.attr.flags & PERF_ATTR_FLAG_SIGTRAP == 0 {
        return;
    }
    const SIGTRAP: u32 = 5;
    const TRAP_PERF: i32 = 6;
    if crate::handlers::store_sigqueue_info(task, SIGTRAP, TRAP_PERF, event.attr.sig_data, 0) {
        crate::handlers::raise_signal_pending(task, SIGTRAP);
    }
}

fn capture_pending_sample(cpu: usize, counters: u8) -> bool {
    let start = PENDING_SAMPLE_CURSOR[cpu].fetch_add(1, Ordering::Relaxed);
    let mut claimed = None;
    for offset in 0..PENDING_SAMPLE_DEPTH {
        let pending = &PENDING_SAMPLES[cpu][rotation_index(start, offset, PENDING_SAMPLE_DEPTH)];
        if pending
            .state
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            claimed = Some(pending);
            break;
        }
    }
    let Some(pending) = claimed else {
        record_pending_loss(cpu, counters);
        return false;
    };

    pending
        .task
        .store(crate::handlers::current_task_id(), Ordering::Relaxed);
    pending
        .ip
        .store(narf_interrupts::interrupted_ip(), Ordering::Relaxed);
    pending
        .time
        .store(narf_time::monotonic_ns(), Ordering::Relaxed);
    pending.counters.store(counters, Ordering::Relaxed);
    if let Some(state) = narf_interrupts::interrupted_user_state() {
        pending.user_regs_abi.store(state.abi, Ordering::Relaxed);
        pending.user_sp.store(state.sp, Ordering::Relaxed);
        for (dst, value) in pending.user_regs.iter().zip(state.regs) {
            dst.store(value, Ordering::Relaxed);
        }
        let stack_bytes = (0..8)
            .filter(|idx| counters & (1 << idx) != 0)
            .map(|idx| ACTIVE_SAMPLE_STACK_BYTES[cpu][idx].load(Ordering::Relaxed) as usize)
            .max()
            .unwrap_or(0)
            .min(PERF_MAX_USER_STACK_SAMPLE);
        let copied = if stack_bytes == 0 {
            0
        } else if let Some(address_space) = narf_scheduler::current_address_space() {
            // SAFETY: this producer exclusively owns the claimed state-1 slot.
            let stack = unsafe {
                core::slice::from_raw_parts_mut(pending.user_stack.as_mut_ptr(), stack_bytes)
            };
            address_space.copy_user_bytes_nofault(narf_memory::VirtAddr::new(state.sp), stack)
        } else {
            0
        };
        pending
            .user_stack_size
            .store(copied as u32, Ordering::Relaxed);
        pending.user_regs_valid.store(true, Ordering::Relaxed);
    } else {
        pending.user_regs_valid.store(false, Ordering::Relaxed);
        pending.user_stack_size.store(0, Ordering::Relaxed);
    }
    for (idx, active_id) in ACTIVE_SAMPLE_IDS[cpu].iter().enumerate() {
        if counters & (1 << idx) == 0 {
            continue;
        }
        pending.event_ids[idx].store(active_id.load(Ordering::Acquire), Ordering::Relaxed);
        #[cfg(target_arch = "x86_64")]
        let period = narf_arch::x86_64::pmu::last_overflow_period(cpu, idx);
        #[cfg(target_arch = "aarch64")]
        let period = if idx == 0 {
            narf_arch::aarch64::pmu::last_overflow_period(cpu)
        } else {
            narf_arch::aarch64::pmu::programmable_period(cpu, idx - 1)
        };
        pending.periods[idx].store(period, Ordering::Relaxed);
    }
    pending.state.store(2, Ordering::Release);
    true
}

#[cfg(target_arch = "x86_64")]
fn pmi_handler(_cookie: u64) -> narf_interrupts::IrqStatus {
    // SAFETY: this handler is installed only on LVT-PC and runs at CPL0.
    let counters = unsafe { narf_arch::x86_64::pmu::handle_sampling_overflow() };
    if counters == 0 {
        return narf_interrupts::IrqStatus::None;
    }
    let cpu = narf_lib::percpu::current_cpu().min(SAMPLE_CPU_SLOTS - 1);
    let _ = capture_pending_sample(cpu, counters);
    // Wake a parked poll/epoll task so its syscall re-enters normal context
    // and drains this allocation-free IRQ snapshot into the mmap ring.
    narf_net::readiness::notify(0);
    narf_interrupts::IrqStatus::Handled
}

#[cfg(target_arch = "aarch64")]
fn pmi_handler(_cookie: u64) -> narf_interrupts::IrqStatus {
    // SAFETY: this handler is invoked by the firmware-routed current-CPU PMU PPI.
    let cycle = unsafe { narf_arch::aarch64::pmu::handle_sampling_overflow() };
    // SAFETY: same current-CPU PMU interrupt context.
    let programmable = unsafe { narf_arch::aarch64::pmu::handle_programmable_overflows() };
    let mut counters = u8::from(cycle);
    for idx in 0..7 {
        if programmable & (1 << idx) != 0 {
            counters |= 1 << (idx + 1);
        }
    }
    if counters == 0 {
        return narf_interrupts::IrqStatus::None;
    }
    let cpu = narf_lib::percpu::current_cpu().min(SAMPLE_CPU_SLOTS - 1);
    let _ = capture_pending_sample(cpu, counters);
    narf_net::readiness::notify(0);
    narf_interrupts::IrqStatus::Handled
}

#[cfg(target_arch = "x86_64")]
fn ensure_pmi_route() -> Result<(), ()> {
    ensure_pmi_route_on(narf_lib::percpu::current_cpu())
}

#[cfg(target_arch = "x86_64")]
fn ensure_pmi_route_on(cpu: usize) -> Result<(), ()> {
    let mut slot = PMI_VECTOR.lock();
    let vector = if let Some(vector) = *slot {
        vector
    } else {
        let vector = narf_interrupts::vector::alloc().map_err(|_| ())?;
        narf_interrupts::install_handler_named(vector, "perf-pmi", 0, pmi_handler);
        *slot = Some(vector);
        vector
    };
    drop(slot);
    let cpu_bit = 1u64.checked_shl(cpu as u32).ok_or(())?;
    if PMI_ROUTED_CPUS.fetch_or(cpu_bit, Ordering::AcqRel) & cpu_bit != 0 {
        return Ok(());
    }
    match remote_pmu_call(cpu, RemotePmuCommand::RoutePmi(vector)).map_err(|_| ())? {
        RemotePmuReply::Result(result) => result.map_err(|_| ()),
        _ => unreachable!("route-PMI command returned the wrong reply"),
    }
}

#[cfg(target_arch = "aarch64")]
fn ensure_pmi_route() -> Result<(), ()> {
    let intid = narf_interrupts::aarch64::gic::pmu_ppi().ok_or(())?;
    let vector = (intid & 0xff) as u8;
    narf_interrupts::install_handler_named(vector, "perf-pmuv3", 0, pmi_handler);
    Ok(())
}

/// Drain allocation-free PMI snapshots into userspace mmap rings from normal
/// syscall context. The IRQ handler captures IP/task/time and rearms hardware;
/// record encoding and readiness wakeups happen here where allocation is safe.
pub(crate) fn drain_irq_samples() {
    // Fast path: with no perf event attached anywhere, no producer can stage a
    // sample, so the per-CPU pending rings are all empty. Skip before touching
    // the registry lock or scanning MAX_CPUS * ring-depth slots — this runs on
    // every syscall dispatch, so an unconditional scan taxes the whole system
    // (and monopolizes the CPU) even when nobody is profiling. `enabled()` is a
    // single read-mostly load flipped only on the first attach / last detach.
    if !narf_lib::perf::enabled() {
        return;
    }
    let mut notify = false;
    {
        let registry = PERF_EVENT_REGISTRY.lock();
        for buckets in &PENDING_LOSSES {
            for bucket in buckets {
                if bucket
                    .state
                    .compare_exchange(2, 1, Ordering::AcqRel, Ordering::Relaxed)
                    .is_err()
                {
                    continue;
                }
                let event_id = bucket.event_id.load(Ordering::Relaxed);
                let lost = bucket.count.swap(0, Ordering::Relaxed);
                if lost != 0 {
                    for weak in registry.iter() {
                        let Some(event) = weak.upgrade() else {
                            continue;
                        };
                        if event.id == event_id {
                            event.sample_lost.fetch_add(lost, Ordering::Relaxed);
                            break;
                        }
                    }
                }
                bucket.event_id.store(0, Ordering::Relaxed);
                bucket.state.store(0, Ordering::Release);
            }
        }
    }
    for (source_cpu, pending_ring) in PENDING_SAMPLES.iter().enumerate() {
        for pending in pending_ring {
            if pending
                .state
                .compare_exchange(2, 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
            {
                continue;
            }
            let task = pending.task.load(Ordering::Relaxed);
            let ip = pending.ip.load(Ordering::Relaxed);
            let now = pending.time.load(Ordering::Relaxed);
            let counters = pending.counters.load(Ordering::Relaxed);
            let user_state = pending.user_regs_valid.load(Ordering::Relaxed).then(|| {
                let mut regs = [0; 34];
                for (dst, source) in regs.iter_mut().zip(pending.user_regs.iter()) {
                    *dst = source.load(Ordering::Relaxed);
                }
                narf_interrupts::InterruptedUserState {
                    user: true,
                    abi: pending.user_regs_abi.load(Ordering::Relaxed),
                    ip,
                    sp: pending.user_sp.load(Ordering::Relaxed),
                    regs,
                }
            });
            let stack_size = pending.user_stack_size.load(Ordering::Relaxed) as usize;
            // SAFETY: this consumer exclusively owns the acquired state-1 slot.
            let user_stack = unsafe { pending.user_stack.slice(stack_size) };
            {
                let registry = PERF_EVENT_REGISTRY.lock();
                for weak in registry.iter() {
                    let Some(event) = weak.upgrade() else {
                        continue;
                    };
                    let matched_counter = (0..8).find(|&idx| {
                        counters & (1 << idx) != 0
                            && pending.event_ids[idx].load(Ordering::Relaxed) == event.id
                    });
                    if let Some(matched_counter) = matched_counter {
                        if !event.enabled.load(Ordering::Acquire)
                            || !event.accepts_sample_from(source_cpu, task)
                        {
                            continue;
                        }
                        let period = pending.periods[matched_counter].load(Ordering::Relaxed);
                        event.last_sample_period.store(period, Ordering::Release);
                        event.count_accumulated.fetch_add(period, Ordering::AcqRel);
                        let pid = crate::handlers::task_to_pid_raw(task).unwrap_or(task) as u32;
                        notify |= event.sample_record(
                            ip,
                            pid,
                            task as u32,
                            now,
                            user_state.as_ref(),
                            user_stack,
                            &[],
                        );
                        deliver_sigtrap(&event, task);
                        event.adjust_frequency_period(now);
                        notify |= event.consume_refresh();
                    }
                }
            }
            pending.state.store(0, Ordering::Release);
        }
    }
    for buckets in &PENDING_TRACE_LOSSES {
        for bucket in buckets {
            if bucket
                .state
                .compare_exchange(2, 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
            {
                continue;
            }
            let type_id = bucket.event_id.load(Ordering::Relaxed);
            let lost = bucket.count.swap(0, Ordering::Relaxed);
            let registry = PERF_EVENT_REGISTRY.lock();
            for weak in registry.iter() {
                if let Some(event) = weak.upgrade() {
                    if event.attr.type_ == PERF_TYPE_TRACEPOINT && event.attr.config == type_id {
                        event.sample_lost.fetch_add(lost, Ordering::Relaxed);
                    }
                }
            }
            bucket.event_id.store(0, Ordering::Relaxed);
            bucket.state.store(0, Ordering::Release);
        }
    }
    for (source_cpu, pending_ring) in PENDING_TRACES.iter().enumerate() {
        for pending in pending_ring {
            if pending
                .state
                .compare_exchange(2, 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
            {
                continue;
            }
            let type_id = pending.type_id.load(Ordering::Relaxed);
            let task = pending.task.load(Ordering::Relaxed);
            let ip = pending.ip.load(Ordering::Relaxed);
            let now = pending.time.load(Ordering::Relaxed);
            let len = pending.len.load(Ordering::Relaxed) as usize;
            // SAFETY: this consumer owns the acquired state-1 slot.
            let raw =
                unsafe { core::slice::from_raw_parts(pending.bytes.0.as_ptr().cast::<u8>(), len) };
            let registry = PERF_EVENT_REGISTRY.lock();
            for weak in registry.iter() {
                let Some(event) = weak.upgrade() else {
                    continue;
                };
                if event.attr.type_ != PERF_TYPE_TRACEPOINT
                    || event.attr.config != type_id
                    || !event.enabled.load(Ordering::Acquire)
                    || !event.accepts_sample_from(source_cpu, task)
                {
                    continue;
                }
                event.count_accumulated.fetch_add(1, Ordering::AcqRel);
                event.last_sample_period.store(1, Ordering::Release);
                let pid = crate::handlers::task_to_pid_raw(task).unwrap_or(task) as u32;
                // An attached BPF program filters the sample. A non-zero return
                // means "keep it", matching Linux, where a zero return from a
                // perf-attached program drops the record.
                //
                // Here rather than in the producer: `capture_trace` runs in IRQ
                // context and only stages into a lock-free per-CPU ring, while
                // this drain runs from the syscall-return path. Running the
                // program here is what keeps NMI-safety out of the picture
                // entirely (spec §6.1) — and the `raw` slice is already exactly
                // the tracepoint argument blob a program expects as its context.
                if let Some(prog) = event.bpf_prog.lock().as_ref() {
                    let mut ctx = [0u64; narf_bpf::interp::MAX_CTX_WORDS];
                    let words = raw.len() / 8;
                    for (i, w) in ctx
                        .iter_mut()
                        .enumerate()
                        .take(words.min(narf_bpf::interp::MAX_CTX_WORDS))
                    {
                        let mut b = [0u8; 8];
                        b.copy_from_slice(&raw[i * 8..i * 8 + 8]);
                        *w = u64::from_le_bytes(b);
                    }
                    // Only a program that *returned* filters. `Outcome::value()`
                    // is 0 for a trap, so testing it discarded the sample on
                    // every trap — the opposite of the policy stated below, and
                    // silently. An unbounded loop verifies (fuel bounds it at
                    // run time), so a program that exhausted fuel would have
                    // dropped every sample it was attached to.
                    let keep =
                        match prog.run_atomic(ctx, words.min(narf_bpf::interp::MAX_CTX_WORDS)) {
                            Some(narf_bpf::interp::Outcome::Returned(v)) => v != 0,
                            // Declined or trapped: keep the sample. Dropping data
                            // because a filter could not run would silently lose
                            // records, which is worse than an unfiltered one.
                            Some(narf_bpf::interp::Outcome::Trapped(_)) | None => true,
                        };
                    if !keep {
                        continue;
                    }
                }
                notify |= event.sample_record(ip, pid, task as u32, now, None, &[], raw);
                notify |= event.consume_refresh();
            }
            drop(registry);
            pending.state.store(0, Ordering::Release);
        }
    }
    if notify {
        narf_net::readiness::notify(0);
    }
}

pub(crate) fn sample_from_irq_for_test(task: u64, ip: u64) {
    let now = narf_time::monotonic_ns();
    let registry = PERF_EVENT_REGISTRY.lock();
    for weak in registry.iter() {
        let Some(event) = weak.upgrade() else {
            continue;
        };
        if event.enabled.load(Ordering::Acquire) && event.tracks_task(task) {
            let pid = crate::handlers::task_to_pid_raw(task).unwrap_or(task) as u32;
            let _ = event.sample_record(ip, pid, task as u32, now, None, &[], &[]);
            deliver_sigtrap(&event, task);
            if event.consume_refresh() {
                narf_net::readiness::notify(0);
            }
        }
    }
}

pub(crate) fn sample_fd_for_test(fd_num: u32, task: u64, ip: u64) -> bool {
    let now = narf_time::monotonic_ns();
    let owner = crate::handlers::current_task_id();
    fd::with_table(owner, |table| {
        if let Some(event) = table
            .get(fd_num)
            .and_then(|entry| entry.ops.as_any())
            .and_then(|any| any.downcast_ref::<PerfEventFile>())
        {
            if !event.enabled.load(Ordering::Acquire) || !event.tracks_task(task) {
                return false;
            }
            let pid = crate::handlers::task_to_pid_raw(task).unwrap_or(task) as u32;
            let _ = event.sample_record(ip, pid, task as u32, now, None, &[], &[]);
            deliver_sigtrap(event, task);
            if event.consume_refresh() {
                narf_net::readiness::notify(0);
            }
            return true;
        }
        false
    })
    .unwrap_or(false)
}

pub(crate) fn event_tracks_task_for_test(fd_num: u32, task: u64) -> bool {
    let owner = crate::handlers::current_task_id();
    fd::with_table(owner, |table| {
        table
            .get(fd_num)
            .and_then(|entry| entry.ops.as_any())
            .and_then(|any| any.downcast_ref::<PerfEventFile>())
            .is_some_and(|event| event.tracks_task(task))
    })
    .unwrap_or(false)
}

pub(crate) fn event_refresh_state_for_test(fd_num: u32) -> Option<(bool, u32, bool)> {
    let owner = crate::handlers::current_task_id();
    fd::with_table(owner, |table| {
        table
            .get(fd_num)
            .and_then(|entry| entry.ops.as_any())
            .and_then(|any| any.downcast_ref::<PerfEventFile>())
            .map(|event| {
                (
                    event.enabled.load(Ordering::Acquire),
                    event.refresh_limit.load(Ordering::Acquire),
                    event.refresh_hup.load(Ordering::Acquire),
                )
            })
    })
    .flatten()
}

fn event_group_id(event: &PerfEventFile) -> u64 {
    event
        ._group_leader
        .as_ref()
        .and_then(|leader| leader.as_any())
        .and_then(|any| any.downcast_ref::<PerfEventFile>())
        .map_or(event.id, |leader| leader.id)
}

fn event_active_on_cpu(event: &PerfEventFile, cpu: usize) -> bool {
    if event.pmu_counter.is_some() {
        return event.enabled.load(Ordering::Acquire);
    }
    event.active_task_counters.lock()[cpu].is_some()
}

fn schedule_group(leader: &PerfEventFile, cpu: usize, registry: &[Weak<PerfEventFile>]) -> bool {
    debug_assert!(leader.is_group_leader());
    if registry.iter().filter_map(Weak::upgrade).any(|event| {
        event_group_id(&event) != leader.id
            && event_active_on_cpu(&event, cpu)
            && (leader.is_exclusive() || event.is_exclusive())
    }) {
        return false;
    }

    if !leader.task_switch(cpu, true) {
        return false;
    }
    let members = leader.group_members.lock();
    for weak in members.iter() {
        let Some(file) = weak.upgrade() else {
            continue;
        };
        let Some(event) = file
            .as_any()
            .and_then(|any| any.downcast_ref::<PerfEventFile>())
        else {
            continue;
        };
        if !event.task_switch(cpu, true) {
            leader.task_switch(cpu, false);
            for rollback in members.iter() {
                if let Some(file) = rollback.upgrade() {
                    if let Some(member) = file
                        .as_any()
                        .and_then(|any| any.downcast_ref::<PerfEventFile>())
                    {
                        member.task_switch(cpu, false);
                    }
                }
            }
            return false;
        }
    }
    true
}

/// Scheduler PMU context hook. Runs outside scheduler queue locks and brackets
/// the matching task continuation on the current logical CPU.
pub(crate) fn on_task_switch(task: u64, running: bool) {
    account_cpu_user_switch(running);
    if !narf_lib::perf::enabled() {
        return;
    }
    let cpu = narf_lib::percpu::current_cpu();
    let mut registry = PERF_EVENT_REGISTRY.lock();
    registry.retain(|weak| weak.strong_count() != 0);
    if registry.is_empty() {
        return;
    }

    if !running {
        for weak in registry.iter() {
            if let Some(event) = weak.upgrade() {
                if event.tracks_task(task) {
                    event.task_switch(cpu, false);
                }
            }
        }
        return;
    }

    // Record every selected task, including one without a perf event. Otherwise
    // A -> unmonitored B -> A would look like immediate re-entry into A.
    let previous_task = PERF_LAST_SELECTED_TASK[cpu].swap(task, Ordering::Relaxed);

    // Pinned groups have priority over every flexible group. Failure is
    // observable through EOF on read, matching PERF_EVENT_STATE_ERROR.
    for weak in registry.iter() {
        let Some(event) = weak.upgrade() else {
            continue;
        };
        if event.enabled.load(Ordering::Acquire)
            && event.is_task_hardware_event()
            && event.tracks_task(task)
            && event.is_group_leader()
            && event.is_pinned()
            && !schedule_group(&event, cpu, &registry)
        {
            event.scheduling_error.store(true, Ordering::Release);
        }
    }

    // Allocation failures are expected when a task has more enabled flexible
    // events than physical counters. Rotate across that eligible set only:
    // perf also opens software dummy/metadata events, and including those in
    // the cursor would starve hardware events at stable registry positions.
    let mut anchor = None;
    let eligible = registry
        .iter()
        .filter_map(Weak::upgrade)
        .filter(|event| {
            event.enabled.load(Ordering::Acquire)
                && event.is_task_hardware_event()
                && event.tracks_task(task)
                && event.is_group_leader()
                && !event.is_pinned()
        })
        .inspect(|event| {
            if anchor.is_none() {
                anchor = Some(event.clone());
            }
        })
        .count();
    if eligible == 0 {
        return;
    }
    // `poll_to_yield` brackets every stackful execution interval, including a
    // syscall that returns to and immediately reselects the same task. That
    // boundary must stop the PMU so executor time is not charged, but it is not
    // a task/context switch and therefore must not advance the multiplex epoch.
    // The first live eligible event owns the task's cursor. Keeping it with an
    // event rather than a CPU preserves rotation progress when the task
    // migrates; the registry's stable creation order makes every CPU select the
    // same anchor.
    let anchor = anchor.expect("eligible perf event has an anchor");
    let cursor = anchor.multiplex_cursor.load(Ordering::Relaxed);
    let next_cursor = advance_rotation_cursor(previous_task, task, cursor);
    if next_cursor != cursor {
        anchor
            .multiplex_cursor
            .store(next_cursor, Ordering::Relaxed);
    }
    let start = next_cursor % eligible;

    // Two passes implement a circular walk without allocating in the scheduler
    // context: [start, eligible), then [0, start).
    for pass in 0..2 {
        let mut ordinal = 0;
        for weak in registry.iter() {
            let Some(event) = weak.upgrade() else {
                continue;
            };
            if !event.enabled.load(Ordering::Acquire)
                || !event.is_task_hardware_event()
                || !event.tracks_task(task)
                || !event.is_group_leader()
                || event.is_pinned()
            {
                continue;
            }
            let selected = if pass == 0 {
                ordinal >= start
            } else {
                ordinal < start
            };
            ordinal += 1;
            if selected {
                let _ = schedule_group(&event, cpu, &registry);
            }
        }
    }
}

/// Rotate oversubscribed task hardware events from the user-mode timer tick.
///
/// This is allocation-free and uses only IRQ-safe locks. Sampled events carry
/// their exact hardware `period_left` through the stop/reallocate path.
pub(crate) fn on_multiplex_tick(task: u64) {
    if ACTIVE_PERF_EVENTS.load(Ordering::Relaxed) == 0 {
        return;
    }
    let cpu = narf_lib::percpu::current_cpu();
    let now = narf_time::monotonic_ns();
    let last = PERF_LAST_MULTIPLEX_NS[cpu].load(Ordering::Relaxed);
    if !multiplex_quantum_due(last, now)
        || PERF_LAST_MULTIPLEX_NS[cpu]
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
    {
        return;
    }

    let mut registry = PERF_EVENT_REGISTRY.lock();
    registry.retain(|weak| weak.strong_count() != 0);

    let is_eligible = |event: &PerfEventFile| {
        event.enabled.load(Ordering::Acquire)
            && event.is_task_hardware_event()
            && event.tracks_task(task)
            && event.is_group_leader()
            && !event.is_pinned()
    };
    let mut anchor = None;
    let eligible = registry
        .iter()
        .filter_map(Weak::upgrade)
        .filter(|event| is_eligible(event))
        .inspect(|event| {
            if anchor.is_none() {
                anchor = Some(event.clone());
            }
        })
        .count();
    if eligible < 2 {
        return;
    }
    let waiting = registry
        .iter()
        .filter_map(Weak::upgrade)
        .any(|event| is_eligible(&event) && event.active_task_counters.lock()[cpu].is_none());
    if !waiting {
        return;
    }

    for weak in registry.iter() {
        if let Some(event) = weak.upgrade() {
            if is_eligible(&event) {
                event.task_switch(cpu, false);
                for member in event.group_members.lock().iter() {
                    if let Some(file) = member.upgrade() {
                        if let Some(member) = file
                            .as_any()
                            .and_then(|any| any.downcast_ref::<PerfEventFile>())
                        {
                            member.task_switch(cpu, false);
                        }
                    }
                }
            }
        }
    }

    let start = anchor
        .expect("eligible perf event has an anchor")
        .multiplex_cursor
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1)
        % eligible;
    for pass in 0..2 {
        let mut ordinal = 0;
        for weak in registry.iter() {
            let Some(event) = weak.upgrade() else {
                continue;
            };
            if !is_eligible(&event) {
                continue;
            }
            let selected = if pass == 0 {
                ordinal >= start
            } else {
                ordinal < start
            };
            ordinal += 1;
            if selected {
                let _ = schedule_group(&event, cpu, &registry);
            }
        }
    }
}

fn account_cpu_user_switch(running: bool) {
    let cpu = narf_lib::percpu::current_cpu();
    let Some(depth) = CPU_USER_DEPTH.get(cpu) else {
        return;
    };
    if running {
        if depth.fetch_add(1, Ordering::AcqRel) == 0 {
            CPU_USER_SLICE_START_NS[cpu].store(narf_time::monotonic_ns(), Ordering::Release);
        }
        return;
    }
    let mut current = depth.load(Ordering::Acquire);
    while current != 0 {
        match depth.compare_exchange_weak(current, current - 1, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) if current == 1 => {
                let start = CPU_USER_SLICE_START_NS[cpu].swap(0, Ordering::AcqRel);
                if start != 0 {
                    CPU_USER_NS[cpu].fetch_add(
                        narf_time::monotonic_ns().saturating_sub(start),
                        Ordering::AcqRel,
                    );
                }
                return;
            }
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn cpu_user_time_ns(cpu: usize) -> u64 {
    let Some(total) = CPU_USER_NS.get(cpu) else {
        return 0;
    };
    let mut value = total.load(Ordering::Acquire);
    if CPU_USER_DEPTH[cpu].load(Ordering::Acquire) != 0 {
        let start = CPU_USER_SLICE_START_NS[cpu].load(Ordering::Acquire);
        if start != 0 {
            value = value.saturating_add(narf_time::monotonic_ns().saturating_sub(start));
        }
    }
    value
}

impl Drop for PerfEventFile {
    fn drop(&mut self) {
        #[cfg(target_arch = "x86_64")]
        {
            let cpu = narf_lib::percpu::current_cpu();
            if let Some(counter) = self.active_task_counters.lock()[cpu].take() {
                // SAFETY: a task can close its own event only while executing
                // on this CPU; no other CPU can simultaneously run that task.
                unsafe { narf_arch::x86_64::pmu::release(counter) };
            }
        }
        #[cfg(target_arch = "x86_64")]
        if let Some(counter) = self.pmu_counter {
            release_pmu_on(counter);
        }
        #[cfg(target_arch = "aarch64")]
        {
            let cpu = narf_lib::percpu::current_cpu();
            if let Some(counter) = self.active_task_counters.lock()[cpu].take() {
                // SAFETY: a task can close its own event only while executing
                // on this CPU; no other CPU can simultaneously run that task.
                let _ = unsafe { counter.release() };
            }
            if let Some(counter) = self.pmu_counter {
                // SAFETY: releasing the cycle counter allocated by this file.
                let _ = unsafe { counter.release() };
            }
        }
        if self.registered.load(Ordering::Acquire)
            && ACTIVE_PERF_EVENTS.fetch_sub(1, Ordering::Relaxed) == 1
        {
            narf_lib::perf::set_enabled(false);
        }
    }
}

impl FileOps for PerfEventFile {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            // Linux exposes a pinned group which could not be scheduled as
            // EOF, rather than returning a fabricated zero count.
            if self.scheduling_error.load(Ordering::Acquire) {
                return Ok(0);
            }
            let (value, time_enabled, time_running) = self.snapshot();
            let format = self.attr.read_format;
            let mut cursor = 0;

            if format & PERF_FORMAT_GROUP != 0 {
                let members = self.member_files();
                Self::push_word(buf, &mut cursor, 1 + members.len() as u64)?;
                if format & PERF_FORMAT_TOTAL_TIME_ENABLED != 0 {
                    Self::push_word(buf, &mut cursor, time_enabled)?;
                }
                if format & PERF_FORMAT_TOTAL_TIME_RUNNING != 0 {
                    Self::push_word(buf, &mut cursor, time_running)?;
                }
                Self::push_word(buf, &mut cursor, value)?;
                if format & PERF_FORMAT_ID != 0 {
                    Self::push_word(buf, &mut cursor, self.id)?;
                }
                if format & PERF_FORMAT_LOST != 0 {
                    Self::push_word(buf, &mut cursor, self.sample_lost.load(Ordering::Acquire))?;
                }
                for file in members {
                    let event = file
                        .as_any()
                        .and_then(|any| any.downcast_ref::<PerfEventFile>())
                        .ok_or(FsError::InvalidData)?;
                    let (member_value, _, _) = event.snapshot();
                    Self::push_word(buf, &mut cursor, member_value)?;
                    if format & PERF_FORMAT_ID != 0 {
                        Self::push_word(buf, &mut cursor, event.id)?;
                    }
                    if format & PERF_FORMAT_LOST != 0 {
                        Self::push_word(
                            buf,
                            &mut cursor,
                            event.sample_lost.load(Ordering::Acquire),
                        )?;
                    }
                }
            } else {
                Self::push_word(buf, &mut cursor, value)?;
                if format & PERF_FORMAT_TOTAL_TIME_ENABLED != 0 {
                    Self::push_word(buf, &mut cursor, time_enabled)?;
                }
                if format & PERF_FORMAT_TOTAL_TIME_RUNNING != 0 {
                    Self::push_word(buf, &mut cursor, time_running)?;
                }
                if format & PERF_FORMAT_ID != 0 {
                    Self::push_word(buf, &mut cursor, self.id)?;
                }
                if format & PERF_FORMAT_LOST != 0 {
                    Self::push_word(buf, &mut cursor, self.sample_lost.load(Ordering::Acquire))?;
                }
            }
            Ok(cursor)
        })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }

    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, FsError> {
        match cmd {
            PERF_EVENT_IOC_ENABLE => {
                self.for_group(arg, PerfEventFile::enable)?;
                Ok(0)
            }
            PERF_EVENT_IOC_DISABLE => {
                self.for_group(arg, PerfEventFile::disable)?;
                Ok(0)
            }
            PERF_EVENT_IOC_REFRESH => {
                if self.attr.flags & PERF_ATTR_FLAG_INHERIT != 0
                    || self.sample_period.load(Ordering::Acquire) == 0
                {
                    return Err(FsError::InvalidData);
                }
                self.refresh_limit.fetch_add(arg as u32, Ordering::AcqRel);
                self.refresh_hup.store(false, Ordering::Release);
                self.enable();
                Ok(0)
            }
            PERF_EVENT_IOC_RESET => {
                self.for_group(arg, PerfEventFile::reset)?;
                Ok(0)
            }
            PERF_EVENT_IOC_PERIOD => {
                let mut bytes = [0u8; 8];
                // SAFETY: copy_from_user validates and SMAP-brackets the
                // caller-provided pointer to Linux's u64 period argument.
                unsafe { copy_from_user(&mut bytes, arg as u64) }
                    .map_err(|_| FsError::InvalidData)?;
                #[cfg(target_arch = "x86_64")]
                {
                    self.set_sample_period(u64::from_ne_bytes(bytes))?;
                    Ok(0)
                }
                #[cfg(target_arch = "aarch64")]
                {
                    self.set_sample_period(u64::from_ne_bytes(bytes))?;
                    Ok(0)
                }
                #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
                {
                    let _ = bytes;
                    Err(FsError::Unsupported)
                }
            }
            PERF_EVENT_IOC_SET_OUTPUT => {
                if arg == usize::MAX || arg == u32::MAX as usize {
                    *self.output_target.lock() = None;
                    return Ok(0);
                }
                let target = fd::with_table(current_task_id(), |table| {
                    table.get(arg as u32).map(|entry| Arc::clone(&entry.ops))
                })
                .flatten()
                .ok_or(FsError::InvalidData)?;
                let target_event = target
                    .as_any()
                    .and_then(|any| any.downcast_ref::<PerfEventFile>())
                    .ok_or(FsError::InvalidData)?;
                if target_event.id == self.id
                    || target_event.target_task != self.target_task
                    || target_event.target_cpu != self.target_cpu
                    || target_event.mmap.lock().is_none()
                    || target_event.output_target.lock().is_some()
                {
                    return Err(FsError::InvalidData);
                }
                *self.output_target.lock() = Some(target);
                Ok(0)
            }
            PERF_EVENT_IOC_ID => {
                // SAFETY: ioctl's user pointer is validated and SMAP-bracketed by
                // copy_to_user; a bad pointer is reported as InvalidData/EINVAL.
                unsafe { copy_to_user(arg as u64, &self.id.to_ne_bytes()) }
                    .map_err(|_| FsError::InvalidData)?;
                Ok(0)
            }
            PERF_EVENT_IOC_PAUSE_OUTPUT => {
                if self.mmap.lock().is_none() {
                    return Err(FsError::InvalidData);
                }
                self.output_paused.store(arg != 0, Ordering::Release);
                Ok(0)
            }
            PERF_EVENT_IOC_SET_BPF => {
                // Privilege gate, before anything else — spec §4.10's "one
                // privilege regime" covers *running* a program, not just
                // loading one, and this is the other way to make one run.
                //
                // Without it a prog fd that leaves its root loader — inherited
                // across `fork` (FD_CLOEXEC is only consumed on the exec path)
                // or passed deliberately over SCM_RIGHTS — let any task attach
                // it to a tracepoint it opened (`perf_event_open` takes no
                // credential) and then fire it at will: each drain runs up to
                // `DEFAULT_FUEL` instructions with IRQs masked and two locks
                // held. The clear arm below is gated too, or an unprivileged
                // holder of the *event* fd could silently remove a filter a
                // privileged task installed.
                if !crate::handlers::task_may_use_bpf() {
                    return Err(FsError::PermissionDenied);
                }
                // `arg` is a BPF program fd. Same shape as SET_OUTPUT above:
                // resolve it in the caller's table and downcast.
                if arg == usize::MAX || arg == u32::MAX as usize {
                    *self.bpf_prog.lock() = None;
                    return Ok(0);
                }
                // Linux permits SET_BPF only on tracepoint, kprobe and uprobe
                // events. NARF has only the tracepoint type wired to its trace
                // events, so anything else would attach a program that could
                // never run — reported rather than accepted silently.
                if self.attr.type_ != PERF_TYPE_TRACEPOINT {
                    return Err(FsError::InvalidData);
                }
                let ops = fd::with_table(current_task_id(), |table| {
                    table.get(arg as u32).map(|entry| Arc::clone(&entry.ops))
                })
                .flatten()
                .ok_or(FsError::InvalidData)?;
                let prog = ops
                    .as_any()
                    .and_then(narf_bpf::prog_from_file_ops)
                    .ok_or(FsError::InvalidData)?;
                // An atomic-context program only: the drain holds
                // PERF_EVENT_REGISTRY, so a sleepable program would be
                // awaiting with a lock held (spec §4.4).
                if prog.context() != narf_bpf_verifier::kfunc::Context::Atomic {
                    return Err(FsError::InvalidData);
                }
                *self.bpf_prog.lock() = Some(prog);
                Ok(0)
            }
            _ => Err(FsError::Unsupported),
        }
    }

    fn mmap_frames(&self, offset: u64, len: usize) -> Result<Vec<u64>, FsError> {
        if offset != 0 {
            return Err(FsError::InvalidData);
        }

        let frames = {
            let mut slot = self.mmap.lock();
            if let Some(mapping) = slot.as_ref() {
                if mapping.len != len {
                    return Err(FsError::InvalidData);
                }
                mapping.raw_frames()
            } else {
                let mapping = PerfMmap::allocate(len)?;
                let frames = mapping.raw_frames();
                *slot = Some(mapping);
                frames
            }
        };
        self.publish_mmap_state();
        Ok(frames)
    }

    fn poll_readiness(&self) -> u32 {
        let mut readiness =
            u32::from(self.refresh_hup.load(Ordering::Acquire)) * narf_filesystem::POLL_HUP;
        let mapping = self.mmap.lock();
        let Some(mapping) = mapping.as_ref() else {
            return readiness;
        };
        if mapping.read_u64_acquire(PERF_MMAP_DATA_HEAD_OFFSET)
            != mapping.read_u64_acquire(PERF_MMAP_DATA_TAIL_OFFSET)
        {
            readiness |= narf_filesystem::POLL_IN;
        }
        readiness
    }

    fn readiness_notifies(&self) -> bool {
        true
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

pub fn sys_perf_event_open(ctx: &mut dyn TrapContext) {
    let attr_ptr = ctx.args().arg0;
    let pid = ctx.args().arg1 as i32;
    let cpu = ctx.args().arg2 as i32;
    let group_fd = ctx.args().arg3 as i32;
    let flags = ctx.args().arg4;

    // Reject unknown flags per Linux
    // PERF_FLAG_FD_NO_GROUP = 1, PERF_FLAG_FD_OUTPUT = 2, PERF_FLAG_PID_CGROUP = 4, PERF_FLAG_FD_CLOEXEC = 8
    if (flags & !15) != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    // Redirected output and cgroup attachment require the mmap/sampling and
    // cgroup implementations. Do not silently create a differently scoped event.
    if flags & (2 | 4) != 0 {
        ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
        return;
    }

    if attr_ptr == 0 {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }

    let mut attr = PerfEventAttr::default();

    // We need to read the size first (u32 at offset 4).
    let mut size: u32 = 0;
    // SAFETY: getting mutable slice of local size variable
    let size_slice =
        unsafe { core::slice::from_raw_parts_mut(&mut size as *mut u32 as *mut u8, 4) };

    // SAFETY: `size_slice` is a 4-byte view of the local `size` u32 (live for this
    // call); `attr_ptr` is the user-supplied pointer and was checked non-null above.
    // `copy_from_user` validates the user range and SMAP-brackets the read, so a bad
    // user address yields Err rather than faulting the kernel.
    if unsafe { copy_from_user(size_slice, attr_ptr + 4) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }

    if size == 0 {
        size = PERF_ATTR_SIZE_VER0;
    }

    if !(PERF_ATTR_SIZE_VER0..=4096).contains(&size) {
        ctx.set_return(SyscallReturn::ok((-7i64) as u64)); // E2BIG
        return;
    }

    // Read the attr structure
    let to_read = core::cmp::min(size as usize, core::mem::size_of::<PerfEventAttr>());

    // Since PerfEventAttr has padding/not perfectly transparent, we read bytes
    // SAFETY: `attr` is a live local `PerfEventAttr`; we form a byte view spanning
    // exactly its `size_of` so the slice stays within the object. It is only used as
    // the destination of `copy_from_user` below, which writes at most `to_read` bytes.
    let attr_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            &mut attr as *mut _ as *mut u8,
            core::mem::size_of::<PerfEventAttr>(),
        )
    };

    // SAFETY: `attr_bytes[..to_read]` is a sub-slice of the live `attr` byte view
    // (`to_read <= size_of::<PerfEventAttr>()`); `attr_ptr` is the non-null user
    // pointer. `copy_from_user` validates the user range and SMAP-brackets the read.
    if unsafe { copy_from_user(&mut attr_bytes[..to_read], attr_ptr) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }

    // If user passed a larger struct, the extra bytes must be zero
    if size as usize > core::mem::size_of::<PerfEventAttr>() {
        let mut extra_byte: u8 = 0;
        for i in core::mem::size_of::<PerfEventAttr>()..(size as usize) {
            let extra_slice = core::slice::from_mut(&mut extra_byte);
            // SAFETY: `extra_slice` is a 1-byte view of the live local `extra_byte`;
            // `attr_ptr + i` stays within the user-declared `size` window (i < size).
            // `copy_from_user` validates the user range and SMAP-brackets the read.
            if unsafe { copy_from_user(extra_slice, attr_ptr + i as u64) }.is_err() {
                ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
                return;
            }
            if extra_byte != 0 {
                ctx.set_return(SyscallReturn::ok((-7i64) as u64)); // E2BIG
                return;
            }
        }
    }

    if attr.__reserved_2 != 0 || attr.__reserved_3 != 0 || attr.config3 != 0 || attr.config4 != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }

    if attr.read_format & !PERF_FORMAT_SUPPORTED != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }

    // Every accepted attribute bit must have its Linux meaning. In particular,
    // frequency mode needs a feedback controller and exclude/inherit/metadata
    // bits need scheduler/process integration; ignoring them would fabricate
    // compatibility.
    let unsupported_attr_flags = attr.flags & !PERF_ATTR_IMPLEMENTED;
    if unsupported_attr_flags != 0 {
        ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
        return;
    }

    if attr.sample_period_or_freq != 0
        && (attr.sample_type == 0 || attr.sample_type & !PERF_SAMPLE_SUPPORTED != 0)
    {
        ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
        return;
    }
    if attr.flags & PERF_ATTR_FLAG_FREQ != 0
        && (attr.sample_period_or_freq == 0 || attr.sample_period_or_freq > 1_000_000)
    {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    if attr.flags & PERF_ATTR_FLAG_SAMPLE_ID_ALL != 0
        && attr.sample_type & !PERF_SAMPLE_SUPPORTED != 0
    {
        ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
        return;
    }
    if attr.flags & PERF_ATTR_FLAG_EXCLUDE_KERNEL != 0
        && attr.flags & PERF_ATTR_FLAG_EXCLUDE_USER != 0
    {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    if attr.flags & PERF_ATTR_FLAG_SIGTRAP != 0
        && (pid == -1 || attr.flags & PERF_ATTR_FLAG_REMOVE_ON_EXEC == 0)
    {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    if attr.flags & PERF_ATTR_FLAG_REMOVE_ON_EXEC != 0
        && attr.flags & PERF_ATTR_FLAG_ENABLE_ON_EXEC != 0
    {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    #[cfg(target_arch = "x86_64")]
    let supported_user_regs = (1u64 << 20) - 1;
    #[cfg(target_arch = "aarch64")]
    let supported_user_regs = (1u64 << 34) - 1;
    if attr.sample_type & PERF_SAMPLE_REGS_USER != 0
        && attr.sample_regs_user & !supported_user_regs != 0
    {
        ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
        return;
    }
    if attr.sample_type & PERF_SAMPLE_STACK_USER != 0
        && attr.sample_stack_user as usize > PERF_MAX_USER_STACK_SAMPLE
    {
        ctx.set_return(SyscallReturn::ok((-7i64) as u64)); // E2BIG
        return;
    }
    // Linux overlays these two fields in a union; requesting both is
    // ambiguous and rejected by the kernel rather than serialized twice.
    if attr.sample_type & PERF_SAMPLE_WEIGHT != 0
        && attr.sample_type & PERF_SAMPLE_WEIGHT_STRUCT != 0
    {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }

    if !is_supported_event(&attr) {
        ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
        return;
    }
    if attr.type_ == PERF_TYPE_TRACEPOINT {
        ensure_trace_observers();
    }
    let task = current_task_id();
    let count_kernel = attr.flags & PERF_ATTR_FLAG_EXCLUDE_KERNEL == 0;
    let count_user = attr.flags & PERF_ATTR_FLAG_EXCLUDE_USER == 0;

    // A positive pid is in the CALLER's pid namespace (Linux
    // kernel/events/core.c find_task_by_vpid). Translate inner -> outer once;
    // the raw inner pid resolved to whatever ROOT-namespace task owned the
    // same number, so `perf record -p <inner>` in a container profiled the
    // wrong host task. An inner pid not bound in the caller's namespace is
    // ESRCH. `target_outer` is the OUTER ProcessId, kept for the sample-record
    // rendering below.
    let target_outer = if pid > 0 {
        match crate::handlers::accept_pid_from(task, pid as u64) {
            Some(outer) => outer,
            None => {
                ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
                return;
            }
        }
    } else {
        0
    };
    let target_task = if pid == 0 {
        task
    } else if pid > 0 {
        match crate::handlers::pid_to_task_raw(target_outer) {
            Some(target) => target,
            None if target_outer == task => task,
            None => {
                ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
                return;
            }
        }
    } else {
        // pid == -1 denotes a per-CPU event with no task target.
        u64::MAX
    };
    let target_pid = if pid == 0 {
        crate::handlers::task_to_pid_raw(task).unwrap_or(task)
    } else if pid > 0 {
        target_outer
    } else {
        u64::MAX
    };

    if cpu != -1 && (cpu < 0 || !narf_lib::smp::is_online(cpu as u32)) {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    if pid == -1 && cpu == -1 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let group_leader = if group_fd != -1 {
        let leader =
            fd::with_table(task, |t| t.get(group_fd as u32).map(|e| Arc::clone(&e.ops))).flatten();
        let Some(leader) = leader else {
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF
            return;
        };
        let Some(leader_event) = leader
            .as_any()
            .and_then(|any| any.downcast_ref::<PerfEventFile>())
        else {
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF
            return;
        };
        if leader_event.target_task != target_task || leader_event.target_cpu != cpu {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
            return;
        }
        // Linux permits these scheduling constraints only on the leader; the
        // complete group inherits them and is scheduled atomically.
        if attr.flags & (PERF_ATTR_FLAG_PINNED | PERF_ATTR_FLAG_EXCLUSIVE) != 0 {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
            return;
        }
        Some(leader)
    } else {
        None
    };

    // CPU-scoped counters remain physically allocated for the fd lifetime.
    // Enforce exclusive ownership before touching the PMU. A sibling of the
    // exclusive leader belongs to the same atomic group and is the sole
    // exception.
    if pid == -1 && !matches!(attr.type_, PERF_TYPE_SOFTWARE | PERF_TYPE_TRACEPOINT) {
        let requested_group = group_leader
            .as_ref()
            .and_then(|leader| leader.as_any())
            .and_then(|any| any.downcast_ref::<PerfEventFile>())
            .map(|leader| leader.id);
        let conflict = PERF_EVENT_REGISTRY
            .lock()
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|event| {
                event.target_task == u64::MAX
                    && event.target_cpu == cpu
                    && event.attr.type_ != PERF_TYPE_SOFTWARE
                    && Some(event_group_id(event)) != requested_group
            })
            .any(|event| {
                attr.flags & PERF_ATTR_FLAG_EXCLUSIVE != 0
                    || event.attr.flags & PERF_ATTR_FLAG_EXCLUSIVE != 0
            });
        if conflict {
            ctx.set_return(SyscallReturn::ok((-16i64) as u64)); // EBUSY
            return;
        }
    }

    // Try to allocate PMU counter if target_arch is x86_64
    #[cfg(target_arch = "x86_64")]
    let (pmu_event, pmu_counter) = {
        let event_opt = match attr.type_ {
            // PERF_TYPE_HARDWARE
            PERF_TYPE_HARDWARE => match attr.config {
                PERF_COUNT_HW_CPU_CYCLES => Some(narf_arch::x86_64::pmu::PmuEvent::Cycles),
                PERF_COUNT_HW_INSTRUCTIONS => Some(narf_arch::x86_64::pmu::PmuEvent::Instructions),
                PERF_COUNT_HW_CACHE_REFERENCES => {
                    Some(narf_arch::x86_64::pmu::PmuEvent::CacheReferences)
                }
                PERF_COUNT_HW_CACHE_MISSES => Some(narf_arch::x86_64::pmu::PmuEvent::CacheMisses),
                PERF_COUNT_HW_BRANCH_INSTRUCTIONS => {
                    Some(narf_arch::x86_64::pmu::PmuEvent::BranchInstructions)
                }
                PERF_COUNT_HW_BRANCH_MISSES => Some(narf_arch::x86_64::pmu::PmuEvent::BranchMisses),
                _ => None,
            },
            // PERF_TYPE_HW_CACHE
            PERF_TYPE_HW_CACHE => {
                let cache_id = attr.config & 0xFF;
                let op_id = (attr.config >> 8) & 0xFF;
                let result_id = (attr.config >> 16) & 0xFF;
                match (cache_id, op_id, result_id) {
                    (
                        PERF_COUNT_HW_CACHE_L1D,
                        PERF_COUNT_HW_CACHE_OP_READ,
                        PERF_COUNT_HW_CACHE_RESULT_ACCESS,
                    ) => Some(narf_arch::x86_64::pmu::PmuEvent::L1dAccesses),
                    (
                        PERF_COUNT_HW_CACHE_L1D,
                        PERF_COUNT_HW_CACHE_OP_READ,
                        PERF_COUNT_HW_CACHE_RESULT_MISS,
                    ) => Some(narf_arch::x86_64::pmu::PmuEvent::L1dMisses),
                    (
                        PERF_COUNT_HW_CACHE_LL,
                        PERF_COUNT_HW_CACHE_OP_READ,
                        PERF_COUNT_HW_CACHE_RESULT_ACCESS,
                    ) => Some(narf_arch::x86_64::pmu::PmuEvent::LlcReferences),
                    (
                        PERF_COUNT_HW_CACHE_LL,
                        PERF_COUNT_HW_CACHE_OP_READ,
                        PERF_COUNT_HW_CACHE_RESULT_MISS,
                    ) => Some(narf_arch::x86_64::pmu::PmuEvent::LlcMisses),
                    _ => None,
                }
            }
            // PERF_TYPE_RAW
            PERF_TYPE_RAW => Some(narf_arch::x86_64::pmu::PmuEvent::Raw(
                attr.config | (1 << 16) | (1 << 17),
            )),
            _ => None,
        };

        if let Some(event) = event_opt {
            if pid != -1 {
                // Validate that this CPU exposes a real backend and mapping.
                // The actual counter is allocated on each task switch-in.
                // SAFETY: syscall context at CPL0 on the current CPU.
                let probe = match unsafe {
                    narf_arch::x86_64::pmu::alloc_counter_filtered(event, count_kernel, count_user)
                } {
                    Ok(counter) => counter,
                    Err(narf_arch::x86_64::pmu::PmuError::NoFreeCounter) => {
                        ctx.set_return(SyscallReturn::ok((-16i64) as u64)); // EBUSY
                        return;
                    }
                    Err(_) => {
                        ctx.set_return(SyscallReturn::ok((-95i64) as u64));
                        return;
                    }
                };
                // SAFETY: release the current-CPU validation allocation.
                unsafe { narf_arch::x86_64::pmu::release(probe) };
                (Some(event), None)
            } else {
                match allocate_pmu_on(cpu as usize, event, count_kernel, count_user) {
                    Ok(counter) => (Some(event), Some(counter)),
                    Err(narf_arch::x86_64::pmu::PmuError::NoFreeCounter) => {
                        ctx.set_return(SyscallReturn::ok((-16i64) as u64)); // EBUSY
                        return;
                    }
                    Err(_) => {
                        ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
                        return;
                    }
                }
            }
        } else if matches!(attr.type_, PERF_TYPE_SOFTWARE | PERF_TYPE_TRACEPOINT) {
            (None, None)
        } else {
            ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
            return;
        }
    };

    #[cfg(target_arch = "aarch64")]
    let (pmu_event, pmu_counter) = if let Some(event) = aarch_pmu_event(&attr) {
        if pid != -1 {
            // SAFETY: syscall runs at EL1 on the current CPU; probe is released below.
            let probe = match unsafe { event.allocate(count_kernel, count_user) } {
                Ok(counter) => counter,
                Err(narf_arch::aarch64::pmu::PmuError::NoFreeCounter) => {
                    ctx.set_return(SyscallReturn::ok((-16i64) as u64));
                    return;
                }
                Err(_) => {
                    ctx.set_return(SyscallReturn::ok((-95i64) as u64));
                    return;
                }
            };
            // SAFETY: probe remains live and current-CPU-owned.
            let _ = unsafe { probe.release() };
            (Some(event), None)
        } else {
            // SAFETY: syscall runs at EL1 on the current CPU.
            match unsafe { event.allocate(count_kernel, count_user) } {
                Ok(counter) => (Some(event), Some(counter)),
                Err(narf_arch::aarch64::pmu::PmuError::NoFreeCounter) => {
                    ctx.set_return(SyscallReturn::ok((-16i64) as u64));
                    return;
                }
                Err(_) => {
                    ctx.set_return(SyscallReturn::ok((-95i64) as u64));
                    return;
                }
            }
        }
    } else if matches!(attr.type_, PERF_TYPE_SOFTWARE | PERF_TYPE_TRACEPOINT) {
        (None, None)
    } else {
        ctx.set_return(SyscallReturn::ok((-95i64) as u64));
        return;
    };

    #[cfg(target_arch = "x86_64")]
    let sample_period = if attr.sample_period_or_freq != 0 {
        if let Some(pmu_event) = pmu_event {
            let period = if attr.flags & PERF_ATTR_FLAG_FREQ != 0 {
                narf_arch::x86_64::tsc::frequency_hz()
                    .max(1_000_000_000)
                    .checked_div(attr.sample_period_or_freq)
                    .unwrap_or(1)
                    .max(1)
            } else {
                attr.sample_period_or_freq
            };
            let route_cpu = pmu_counter
                .map(|counter| counter.cpu as usize)
                .unwrap_or_else(narf_lib::percpu::current_cpu);
            if ensure_pmi_route_on(route_cpu).is_err() {
                if let Some(counter) = pmu_counter {
                    release_pmu_on(counter);
                }
                ctx.set_return(SyscallReturn::ok((-95i64) as u64));
                return;
            }
            let validation_counter;
            let counter = if let Some(counter) = pmu_counter.as_ref() {
                counter
            } else {
                // Task-scoped counters are allocated on switch-in, but validate
                // overflow support and the requested period synchronously.
                // SAFETY: syscall context at CPL0.
                validation_counter = match unsafe {
                    narf_arch::x86_64::pmu::alloc_counter_filtered(
                        pmu_event,
                        count_kernel,
                        count_user,
                    )
                } {
                    Ok(counter) => counter,
                    Err(_) => {
                        ctx.set_return(SyscallReturn::ok((-95i64) as u64));
                        return;
                    }
                };
                &validation_counter
            };
            let armed = arm_pmu_on(*counter, period);
            if armed.is_err() {
                release_pmu_on(*counter);
                ctx.set_return(SyscallReturn::ok((-95i64) as u64));
                return;
            }
            let _ = pause_pmu_on(*counter);
            if pmu_counter.is_none() {
                release_pmu_on(*counter);
            }
            period
        } else if (attr.type_ == PERF_TYPE_SOFTWARE && attr.config == PERF_COUNT_SW_DUMMY)
            || attr.type_ == PERF_TYPE_TRACEPOINT
        {
            attr.sample_period_or_freq
        } else {
            ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
            return;
        }
    } else {
        0
    };

    #[cfg(target_arch = "aarch64")]
    let sample_period = if attr.sample_period_or_freq != 0 {
        if attr.type_ == PERF_TYPE_TRACEPOINT {
            attr.sample_period_or_freq
        } else {
            if pmu_event.is_none() || ensure_pmi_route().is_err() {
                if let Some(counter) = pmu_counter {
                    // SAFETY: open still exclusively owns this current-CPU allocation.
                    let _ = unsafe { counter.release() };
                }
                ctx.set_return(SyscallReturn::ok((-95i64) as u64));
                return;
            }
            let validation;
            let counter = if let Some(counter) = pmu_counter.as_ref() {
                counter
            } else {
                // SAFETY: syscall runs at EL1 on the current CPU.
                validation = match unsafe { pmu_event.unwrap().allocate(count_kernel, count_user) }
                {
                    Ok(counter) => counter,
                    Err(_) => {
                        ctx.set_return(SyscallReturn::ok((-95i64) as u64));
                        return;
                    }
                };
                &validation
            };
            let period = if attr.flags & PERF_ATTR_FLAG_FREQ != 0 {
                // Start from the architectural counter clock. Feedback from real
                // overflow timing refines this initial estimate.
                match pmu_event.unwrap() {
                    AarchPmuEvent::Cycle => narf_arch::aarch64::timer::frequency_hz()
                        .checked_div(attr.sample_period_or_freq)
                        .unwrap_or(1)
                        .max(narf_arch::aarch64::pmu::minimum_sample_period()),
                    AarchPmuEvent::Programmable(_) => 100_000,
                }
            } else {
                attr.sample_period_or_freq
            };
            // SAFETY: open owns this current-CPU counter and the PMU PPI is routed.
            let arm_failed = unsafe { (*counter).arm(period) }.is_err();
            if counter.sample_slot() >= 8 || arm_failed {
                if pmu_counter.is_none() {
                    // SAFETY: validation counter remains live and current-CPU-owned.
                    let _ = unsafe { (*counter).release() };
                }
                ctx.set_return(SyscallReturn::ok((-95i64) as u64));
                return;
            }
            // SAFETY: the live current-CPU counter remains owned by this open path.
            let _ = unsafe { (*counter).pause() };
            if pmu_counter.is_none() {
                // SAFETY: validation counter remains live and current-CPU-owned.
                let _ = unsafe { (*counter).release() };
            }
            period
        }
    } else {
        0
    };

    // Allocate an fd
    let cloexec = (flags & 8) != 0; // PERF_FLAG_FD_CLOEXEC
    let install_flags = if cloexec { fd::FD_CLOEXEC } else { 0 };

    let mut opened_file = None;
    let fd_num_opt = fd::with_table(task, |t| {
        // A group member is scheduled only through its leader even when its
        // own disabled bit is clear (the upstream CLI relies on this).
        let initially_enabled = group_leader.is_none() && attr.flags & PERF_ATTR_FLAG_DISABLED == 0;
        let file = Arc::new(PerfEventFile {
            attr,
            id: NEXT_PERF_EVENT_ID.fetch_add(1, Ordering::Relaxed),
            target_task,
            target_pid,
            target_cpu: cpu,
            inherited_tasks: IrqSafeSpinLock::new(InheritedTaskState {
                live: Vec::new(),
                retired_software_ns: 0,
                target_software_retired: false,
            }),
            enabled: AtomicBool::new(false),
            scheduling_error: AtomicBool::new(false),
            count_base: AtomicU64::new(0),
            count_accumulated: AtomicU64::new(0),
            enabled_at_ns: AtomicU64::new(0),
            time_enabled_ns: AtomicU64::new(0),
            running_at_ns: [const { AtomicU64::new(0) }; narf_lib::percpu::MAX_CPUS],
            time_running_ns: AtomicU64::new(0),
            multiplex_cursor: AtomicUsize::new(0),
            registered: AtomicBool::new(false),
            sample_lost: AtomicU64::new(0),
            output_paused: AtomicBool::new(false),
            refresh_hup: AtomicBool::new(false),
            refresh_limit: AtomicU32::new(0),
            wakeup_pending: AtomicU32::new(0),
            sample_period: AtomicU64::new(sample_period),
            sample_period_left: AtomicU64::new(sample_period),
            last_sample_period: AtomicU64::new(sample_period),
            sample_frequency: if attr.flags & PERF_ATTR_FLAG_FREQ != 0 {
                attr.sample_period_or_freq
            } else {
                0
            },
            last_sample_ns: AtomicU64::new(0),
            #[cfg(target_arch = "x86_64")]
            pmu_event,
            #[cfg(target_arch = "x86_64")]
            active_task_counters: IrqSafeSpinLock::new([None; narf_lib::percpu::MAX_CPUS]),
            #[cfg(target_arch = "aarch64")]
            active_task_counters: IrqSafeSpinLock::new([None; narf_lib::percpu::MAX_CPUS]),
            bpf_prog: IrqSafeSpinLock::new(None),
            mmap_seq: AtomicU32::new(0),
            mmap: IrqSafeSpinLock::new(None),
            output_target: IrqSafeSpinLock::new(None),
            group_members: IrqSafeSpinLock::new(Vec::new()),
            _group_leader: group_leader.clone(),
            #[cfg(target_arch = "x86_64")]
            pmu_counter,
            #[cfg(target_arch = "aarch64")]
            pmu_counter,
            #[cfg(target_arch = "aarch64")]
            pmu_event,
        });
        if initially_enabled {
            file.enable();
        }
        let ops: Arc<dyn FileOps> = file.clone();
        if let Some(leader) = &group_leader {
            if let Some(event) = leader
                .as_any()
                .and_then(|any| any.downcast_ref::<PerfEventFile>())
            {
                event.add_group_member(&ops);
            }
        }
        let result = t.open(FdEntry {
            ops,
            offset: 0,
            flags: install_flags,
            status_flags: 0,
        });
        opened_file = Some(file);
        result
    });

    if let Some(fd_num) = fd_num_opt {
        // Mark registration before publishing the global enabled bit. The fd table
        // owns another Arc, so this file remains alive after `opened_file` drops.
        if let Some(file) = opened_file {
            file.registered.store(true, Ordering::Release);
            PERF_EVENT_REGISTRY.lock().push(Arc::downgrade(&file));
        }
        if ACTIVE_PERF_EVENTS.fetch_add(1, Ordering::Relaxed) == 0 {
            narf_lib::perf::set_enabled(true);
        }
        ctx.set_return(SyscallReturn::ok(fd_num as u64));
    } else {
        // No fd table exists for the current task, so the closure never took
        // ownership of the allocated counter.
        #[cfg(target_arch = "x86_64")]
        if let Some(counter) = pmu_counter {
            release_pmu_on(counter);
        }
        ctx.set_return(SyscallReturn::ok((-24i64) as u64)); // EMFILE
    }
}

#[cfg(target_arch = "aarch64")]
fn aarch_pmu_event(attr: &PerfEventAttr) -> Option<AarchPmuEvent> {
    let event = match attr.type_ {
        PERF_TYPE_HARDWARE => match attr.config {
            PERF_COUNT_HW_CPU_CYCLES => return Some(AarchPmuEvent::Cycle),
            PERF_COUNT_HW_INSTRUCTIONS => 0x08,
            PERF_COUNT_HW_CACHE_MISSES => 0x03,
            PERF_COUNT_HW_BRANCH_INSTRUCTIONS => 0x0c,
            PERF_COUNT_HW_BRANCH_MISSES => 0x10,
            _ => return None,
        },
        PERF_TYPE_RAW if attr.config <= u16::MAX as u64 => attr.config as u16,
        _ => return None,
    };
    narf_arch::aarch64::pmu::event_supported(event).then_some(AarchPmuEvent::Programmable(event))
}

fn is_supported_event(attr: &PerfEventAttr) -> bool {
    match attr.type_ {
        // PERF_TYPE_HARDWARE
        #[cfg(target_arch = "x86_64")]
        PERF_TYPE_HARDWARE => matches!(
            attr.config,
            PERF_COUNT_HW_CPU_CYCLES
                | PERF_COUNT_HW_INSTRUCTIONS
                | PERF_COUNT_HW_CACHE_REFERENCES
                | PERF_COUNT_HW_CACHE_MISSES
                | PERF_COUNT_HW_BRANCH_INSTRUCTIONS
                | PERF_COUNT_HW_BRANCH_MISSES
        ),
        #[cfg(target_arch = "aarch64")]
        PERF_TYPE_HARDWARE | PERF_TYPE_RAW => aarch_pmu_event(attr).is_some(),
        // PERF_TYPE_SOFTWARE
        PERF_TYPE_SOFTWARE => matches!(
            attr.config,
            PERF_COUNT_SW_DUMMY | PERF_COUNT_SW_CPU_CLOCK | PERF_COUNT_SW_TASK_CLOCK
        ),
        PERF_TYPE_TRACEPOINT => attr.config != 0,
        // PERF_TYPE_HW_CACHE (3)
        #[cfg(target_arch = "x86_64")]
        PERF_TYPE_HW_CACHE => {
            let cache_id = attr.config & 0xFF;
            let op_id = (attr.config >> 8) & 0xFF;
            let result_id = (attr.config >> 16) & 0xFF;
            matches!(
                (cache_id, op_id, result_id),
                (
                    PERF_COUNT_HW_CACHE_L1D,
                    PERF_COUNT_HW_CACHE_OP_READ,
                    PERF_COUNT_HW_CACHE_RESULT_ACCESS | PERF_COUNT_HW_CACHE_RESULT_MISS,
                ) | (
                    PERF_COUNT_HW_CACHE_LL,
                    PERF_COUNT_HW_CACHE_OP_READ,
                    PERF_COUNT_HW_CACHE_RESULT_ACCESS | PERF_COUNT_HW_CACHE_RESULT_MISS,
                )
            )
        }
        // PERF_TYPE_RAW (4)
        #[cfg(target_arch = "x86_64")]
        PERF_TYPE_RAW => true,
        _ => false,
    }
}

/// The syscall-return drain must be a no-op when no perf event is attached.
///
/// `drain_irq_samples` runs on every syscall dispatch. With the `enabled()`
/// gate it returns before locking the registry or scanning MAX_CPUS * depth
/// pending slots when nobody is profiling; without it, that scan taxes every
/// syscall and monopolizes the CPU. This proves a staged slot is left
/// untouched while perf is disabled and is consumed once perf is enabled.
fn smoke_perf_drain_skips_when_disabled() -> narf_kernel_test::TestResult {
    let cpu = narf_lib::percpu::current_cpu().min(SAMPLE_CPU_SLOTS - 1);
    // Use a quiescent slot so a concurrently-staged real sample is never eaten.
    let ring = &PENDING_TRACES[cpu];
    let Some(slot) = ring.iter().find(|s| s.state.load(Ordering::Acquire) == 0) else {
        // Whole ring busy (not expected at rest) — nothing safe to probe.
        return narf_kernel_test::TestResult::Skip("PENDING_TRACES ring busy");
    };

    let saved_enabled = narf_lib::perf::enabled();

    // Stage a bogus trace whose type_id matches no event.
    slot.type_id.store(0xDEAD_BEEF_0000_0001, Ordering::Relaxed);
    slot.len.store(0, Ordering::Relaxed);
    slot.state.store(2, Ordering::Release);

    // Disabled: the fast path must return before touching the rings.
    narf_lib::perf::set_enabled(false);
    drain_irq_samples();
    let after_disabled = slot.state.load(Ordering::Acquire);

    // Enabled: the same drain must consume the slot (no matching event, so it
    // is simply cleared to state 0).
    narf_lib::perf::set_enabled(true);
    drain_irq_samples();
    let after_enabled = slot.state.load(Ordering::Acquire);

    // Restore global + slot state regardless of the outcome.
    slot.state.store(0, Ordering::Release);
    slot.type_id.store(0, Ordering::Relaxed);
    narf_lib::perf::set_enabled(saved_enabled);

    if after_disabled != 2 {
        return narf_kernel_test::TestResult::Fail("disabled drain consumed a pending slot");
    }
    if after_enabled != 0 {
        return narf_kernel_test::TestResult::Fail(
            "enabled drain did not consume the pending slot",
        );
    }
    narf_kernel_test::TestResult::Pass
}
narf_kernel_test::kernel_test_in!("syscall_abi", smoke_perf_drain_skips_when_disabled);
