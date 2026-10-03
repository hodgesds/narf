//! First-class interception for nondeterministic user instructions.
//!
//! The architecture trap path remains the sole owner of register mutation and
//! instruction advancement. An interceptor receives an immutable invocation,
//! may select native emulation or a typed completed value, and may replace only
//! the result of that same instruction kind. It may also defer that decision
//! to a callback that runs off the masked entry path and can inject syscalls,
//! as a syscall interceptor's entry callback can.

use crate::syscall::{NativeSyscallTransition, TrapContext};
use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

/// User instruction families whose results may vary independently of guest
/// memory and registers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NondeterministicInstruction {
    /// x86 `RDTSC` (`0f 31`).
    Rdtsc,
    /// x86 `RDTSCP` (`0f 01 f9`): a timestamp plus the `IA32_TSC_AUX` value.
    Rdtscp,
}

/// Immutable instruction-family subscription captured at installation.
///
/// The kernel records this value once and never calls tool code to decide trap
/// ownership. That keeps hardware activation and trap dispatch tied to the
/// same decision even when an interceptor has mutable internal state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct InstructionSubscriptions(u64);

impl InstructionSubscriptions {
    pub const NONE: Self = Self(0);
    pub const RDTSC: Self = Self(1 << 0);
    pub const RDTSCP: Self = Self(1 << 1);

    /// Union of two subscription sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, instruction: NondeterministicInstruction) -> bool {
        let bit = match instruction {
            NondeterministicInstruction::Rdtsc => Self::RDTSC.0,
            NondeterministicInstruction::Rdtscp => Self::RDTSCP.0,
        };
        self.0 & bit != 0
    }

    /// Whether any subscribed family needs x86 CR4.TSD.
    ///
    /// CR4.TSD makes both `RDTSC` and `RDTSCP` fault at CPL>0, so subscribing
    /// to either one arms the trap for both. The family that is not subscribed
    /// then completes through native emulation without entering the tool; see
    /// [`dispatch_instruction`].
    pub const fn requires_timestamp_trap(self) -> bool {
        self.0 & (Self::RDTSC.0 | Self::RDTSCP.0) != 0
    }
}

/// Immutable state captured before emulating a trapped instruction.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct InstructionInvocation {
    pub instruction: NondeterministicInstruction,
    pub task_id: u64,
    pub instruction_pointer: u64,
}

/// Typed value written back by the architecture trap owner.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InstructionResult {
    Rdtsc {
        value: u64,
    },
    /// `value` is written to EDX:EAX and `aux` to ECX. Natively, `aux` is
    /// `IA32_TSC_AUX`, which NARF programs with the logical CPU number (the
    /// value the vDSO `getcpu` path reads).
    Rdtscp {
        value: u64,
        aux: u32,
    },
}

impl InstructionResult {
    fn instruction(self) -> NondeterministicInstruction {
        match self {
            Self::Rdtsc { .. } => NondeterministicInstruction::Rdtsc,
            Self::Rdtscp { .. } => NondeterministicInstruction::Rdtscp,
        }
    }
}

/// Entry decision for one trapped instruction.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InstructionInterception {
    /// Execute the kernel's native emulation exactly once.
    Continue,
    /// Skip native emulation and use this typed result.
    Complete(InstructionResult),
    /// Decide later, in [`InstructionInterceptor::on_instruction_deferred`],
    /// after this entry callback has returned and the CPU's instruction flag
    /// is released.
    Defer,
}

/// Decision of [`InstructionInterceptor::on_instruction_deferred`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeferredInstruction {
    /// Execute the kernel's native emulation exactly once.
    Native,
    /// Skip native emulation and use this typed result.
    Complete(InstructionResult),
}

/// An interceptor returned a value for a different instruction family.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct InstructionResultMismatch {
    pub expected: NondeterministicInstruction,
    pub actual: NondeterministicInstruction,
}

/// A trapped instruction could not complete through its interceptor.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InstructionDispatchError {
    /// The interceptor recursively entered instruction dispatch on this CPU.
    Reentrant,
    /// The interceptor returned a result for a different instruction family.
    ResultMismatch(InstructionResultMismatch),
    /// The interceptor deferred an instruction where the kernel cannot run a
    /// deferred callback: the own-stack execution model is off, or no user
    /// task is current.
    DeferUnsupported,
}

/// Process-global nondeterministic-instruction policy.
///
/// One object is published for the kernel lifetime. It is shared directly by
/// every CPU and must synchronize its own mutable state. It never receives a
/// mutable trap frame; register writes and instruction advancement remain
/// architecture-owned.
/// # Safety
///
/// Methods other than
/// [`on_instruction_deferred`](Self::on_instruction_deferred) execute
/// synchronously from an architecture exception handler with ordinary
/// interrupts masked and the executing CPU's instruction flag held.
/// Implementations must not allocate, park, await, take a sleepable lock,
/// re-enter guest execution, or recursively dispatch an intercepted
/// instruction there. Mutable state they use must be preallocated IRQ-safe,
/// lock-free storage. Violating these requirements can deadlock or corrupt the
/// interrupted task. `on_instruction_deferred` has its own contract, stated on
/// the method.
pub unsafe trait InstructionInterceptor: Send + Sync {
    /// Instruction families this interceptor owns for its entire lifetime.
    ///
    /// Called exactly once by installation. The returned value is frozen in
    /// the published kernel slot and is never queried from a trap handler.
    fn subscriptions(&self) -> InstructionSubscriptions;

    /// Select native emulation or a completed value, or defer the choice to
    /// [`on_instruction_deferred`](Self::on_instruction_deferred).
    fn on_instruction_enter(&self, _invocation: &InstructionInvocation) -> InstructionInterception {
        InstructionInterception::Continue
    }

    /// Complete an instruction that
    /// [`on_instruction_enter`](Self::on_instruction_enter) deferred.
    ///
    /// Exempt from the masked contract above. This runs after
    /// `on_instruction_enter` has returned and the CPU's instruction flag is
    /// released, on the trapping task's own kernel stack, as
    /// [`SyscallInterceptor::on_syscall_enter`](crate::SyscallInterceptor::on_syscall_enter)
    /// does, with IRQs still masked. It may allocate, inject syscalls through
    /// `native`, and wait (through
    /// [`NativeSyscallTransition::wait_for_repoll`] or an inject that blocks),
    /// so it may resume on another CPU. It must not call
    /// [`dispatch_instruction`].
    ///
    /// `native` has no syscall of its own:
    /// [`execute_original`](NativeSyscallTransition::execute_original) returns
    /// [`AlreadyExecuted`](crate::NativeSyscallOriginalError::AlreadyExecuted);
    /// an inject that would exit the task, replace its image or create a task
    /// returns `-ENOSYS` without running;
    /// [`entry_user_state`](NativeSyscallTransition::entry_user_state) is the
    /// register file at the trap; and
    /// [`task_killed`](NativeSyscallTransition::task_killed) answers.
    ///
    /// If a transition took the task's context (it returned
    /// [`ContextManaged`](crate::NativeSyscallOutcome::ContextManaged)), the
    /// answer is ignored: no register is written, the instruction pointer is
    /// not advanced, `on_instruction_return` is not called, and the task
    /// executes the instruction again if it returns to user mode at all.
    /// Otherwise `on_instruction_return` follows, under the masked contract.
    fn on_instruction_deferred(
        &self,
        _invocation: &InstructionInvocation,
        _native: &mut dyn NativeSyscallTransition,
    ) -> DeferredInstruction {
        DeferredInstruction::Native
    }

    /// Observe and optionally replace a result of the same typed family.
    fn on_instruction_return(
        &self,
        _invocation: &InstructionInvocation,
        result: InstructionResult,
    ) -> InstructionResult {
        result
    }
}

struct InstructionInterceptorSlot {
    interceptor: Box<dyn InstructionInterceptor>,
    subscriptions: InstructionSubscriptions,
}

static GLOBAL_INTERCEPTOR: AtomicPtr<InstructionInterceptorSlot> =
    AtomicPtr::new(core::ptr::null_mut());

static IN_INSTRUCTION_CALLBACK: [AtomicBool; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; narf_lib::percpu::MAX_CPUS];

/// The executing CPU's instruction flag, held while a masked callback runs.
struct CallbackGuard(&'static AtomicBool);

impl CallbackGuard {
    /// Take the executing CPU's flag, or `None` if a callback on this CPU
    /// already holds it.
    fn try_take() -> Option<Self> {
        let cpu = narf_lib::percpu::current_cpu().min(narf_lib::percpu::MAX_CPUS - 1);
        let flag = &IN_INSTRUCTION_CALLBACK[cpu];
        flag.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        Some(Self(flag))
    }
}

impl Drop for CallbackGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Publish the kernel-lifetime instruction interceptor exactly once.
///
/// Installation is a pre-guest operation. Publication, the vDSO clock-mode
/// switch, and the per-CPU trap activation are separate steps, so a guest
/// running during them could see some CPUs trapping and others not, or a vDSO
/// clock read that began before the switch. Installation therefore holds the
/// scheduler's [`narf_scheduler::UserAdmissionExclusion`] from before
/// [`InstructionInterceptor::subscriptions`] until every step is complete on
/// every online CPU: a user task spawned in that window, including by the
/// interceptor itself, is created but not made runnable until installation
/// returns, so no guest observes any intermediate combination.
///
/// Returns the interceptor when another one is already published, when a user
/// task is live or another admission exclusion is held, or when a multi-CPU
/// timestamp trap has no SMP rendezvous. Whether a spawn racing this call is
/// deferred or makes it refuse depends on host timing, and after a refusal
/// that task runs uninstrumented; a deterministic caller installs before
/// creating any guest and treats an `Err` as fatal. Schedulers must additionally call
/// [`activate_current_cpu_instruction_interception`] before a newly-online CPU
/// can return an instrumented task to user mode.
pub fn try_install_instruction_interceptor(
    interceptor: Box<dyn InstructionInterceptor>,
) -> Result<(), Box<dyn InstructionInterceptor>> {
    let Some(exclusion) = narf_scheduler::try_exclude_user_admission() else {
        return Err(interceptor);
    };
    let admitted = narf_scheduler::user_tasks_admitted();
    let subscriptions = interceptor.subscriptions();
    #[cfg(target_arch = "x86_64")]
    if subscriptions.requires_timestamp_trap()
        && narf_lib::smp::online_count() > 1
        && !narf_lib::smp::remote_barrier_available()
    {
        return Err(interceptor);
    }

    let slot = Box::into_raw(Box::new(InstructionInterceptorSlot {
        interceptor,
        subscriptions,
    }));
    match GLOBAL_INTERCEPTOR.compare_exchange(
        core::ptr::null_mut(),
        slot,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => {
            // Route vDSO clock reads through syscalls before arming the trap:
            // the vDSO would otherwise convert a (virtualized) counter read
            // with the host scale, while the clock syscalls read the native
            // counter, giving the guest two unrelated time bases.
            if subscriptions.requires_timestamp_trap() {
                crate::vdso::route_clocks_through_syscalls();
            }
            #[cfg(target_arch = "x86_64")]
            if subscriptions.requires_timestamp_trap() {
                narf_arch::x86_64::cr::request_user_rdtsc_interception();
                // SAFETY: this action only reads a monotonic atomic request and
                // updates the executing CPU's CR4 through the architecture
                // wrapper. It allocates and blocks nowhere and is safe in IPI
                // context on all online CPUs.
                let armed = unsafe {
                    narf_lib::smp::remote_call(
                        narf_lib::smp::online_bitmap(),
                        narf_arch::x86_64::cr::activate_requested_user_instruction_interception,
                    )
                };
                assert!(
                    armed,
                    "instruction interception rendezvous disappeared after preflight"
                );
            }
            // Every step above is complete on every online CPU. The exclusion
            // kept any user task from becoming runnable meanwhile; check that
            // it did, then admit the deferred tasks onto the installed state.
            core::sync::atomic::fence(Ordering::SeqCst);
            assert!(
                narf_scheduler::user_tasks_admitted() == admitted,
                "a user task was admitted during instruction interceptor installation"
            );
            drop(exclusion);
            Ok(())
        }
        Err(_) => {
            // SAFETY: failed publication leaves this fresh allocation
            // unreachable by every other thread.
            let slot = unsafe { Box::from_raw(slot) };
            Err(slot.interceptor)
        }
    }
}

fn global_interceptor() -> Option<&'static InstructionInterceptorSlot> {
    let pointer = GLOBAL_INTERCEPTOR.load(Ordering::Acquire);
    if pointer.is_null() {
        None
    } else {
        // SAFETY: successful publication leaks the slot for the kernel
        // lifetime; test retirement likewise never reclaims it.
        Some(unsafe { &*pointer })
    }
}

/// Whether the published interceptor subscribes to this instruction family.
pub fn instruction_interception_enabled(instruction: NondeterministicInstruction) -> bool {
    global_interceptor().is_some_and(|slot| slot.subscriptions.contains(instruction))
}

/// Activate requested hardware trapping on the executing CPU.
///
/// x86 CR4.TSD is per-CPU. Setting it makes ring-3 `RDTSC` raise #GP while
/// retaining native kernel access, which the frame trap path uses for
/// `Continue`. This is a hardware/kernel interception mechanism: no signal,
/// ptrace stop, binary rewrite, polling loop, or userspace trampoline is used.
pub fn activate_current_cpu_instruction_interception() {
    #[cfg(target_arch = "x86_64")]
    narf_arch::x86_64::cr::activate_requested_user_instruction_interception();
}

/// `result` if it belongs to the `expected` family.
fn check_family(
    expected: NondeterministicInstruction,
    result: InstructionResult,
) -> Result<InstructionResult, InstructionDispatchError> {
    if result.instruction() == expected {
        Ok(result)
    } else {
        Err(InstructionDispatchError::ResultMismatch(
            InstructionResultMismatch {
                expected,
                actual: result.instruction(),
            },
        ))
    }
}

/// How [`dispatch_instruction`] handled a trapped instruction.
#[derive(Debug)]
#[must_use]
pub enum InstructionDispatch {
    /// No interceptor subscribed to this family, and no tool code ran.
    Unsubscribed,
    /// The interceptor completed the instruction with this result.
    Completed(InstructionResult),
    /// The interceptor deferred the instruction, and the CPU's instruction
    /// flag is released. The architecture completes it with
    /// [`DeferredInstructionCall::complete`].
    Deferred(DeferredInstructionCall),
}

/// An instruction whose interceptor deferred its decision to
/// [`InstructionInterceptor::on_instruction_deferred`].
///
/// The architecture trap owner must [`complete`](Self::complete) it before the
/// task returns to user mode.
#[must_use = "a deferred instruction must be completed"]
pub struct DeferredInstructionCall {
    invocation: InstructionInvocation,
    slot: &'static InstructionInterceptorSlot,
}

impl core::fmt::Debug for DeferredInstructionCall {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeferredInstructionCall")
            .field("invocation", &self.invocation)
            .finish_non_exhaustive()
    }
}

/// How [`DeferredInstructionCall::complete`] ended.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeferredCompletion {
    /// Write this result back and advance past the instruction.
    Completed(InstructionResult),
    /// A transition of the deferred callback took the task's context. Write
    /// nothing and leave the instruction pointer at the instruction, which the
    /// task executes again if it returns to user mode.
    Reexecute,
}

impl DeferredInstructionCall {
    /// The invocation the interceptor deferred.
    pub fn invocation(&self) -> &InstructionInvocation {
        &self.invocation
    }

    /// Run [`InstructionInterceptor::on_instruction_deferred`], then
    /// [`InstructionInterceptor::on_instruction_return`] unless a transition
    /// took the task's context.
    ///
    /// `ctx` is the trap's own context. The callback's transitions never see
    /// it: the kernel only saves the task's registers from it and, when a
    /// transition staged the task's termination, terminates the task through
    /// it, in which case this call does not return in the own-stack model.
    /// `native` runs at most once, only after [`DeferredInstruction::Native`],
    /// on the CPU the task runs on by then.
    pub fn complete<F>(
        self,
        ctx: &mut dyn TrapContext,
        native: F,
    ) -> Result<DeferredCompletion, InstructionDispatchError>
    where
        F: FnOnce() -> InstructionResult,
    {
        let interceptor = self.slot.interceptor.as_ref();
        let invocation = self.invocation;
        let (decision, context_managed) =
            crate::syscall::run_instruction_callback(ctx, invocation.task_id, |transition| {
                interceptor.on_instruction_deferred(&invocation, transition)
            })?;
        if context_managed {
            return Ok(DeferredCompletion::Reexecute);
        }
        let result = match decision {
            DeferredInstruction::Native => native(),
            DeferredInstruction::Complete(result) => result,
        };
        let result = check_family(invocation.instruction, result)?;
        // The callback may have waited and resumed on another CPU: take the
        // flag of the CPU the task runs on now.
        let Some(_callback_guard) = CallbackGuard::try_take() else {
            return Err(InstructionDispatchError::Reentrant);
        };
        let result = interceptor.on_instruction_return(&invocation, result);
        check_family(invocation.instruction, result).map(DeferredCompletion::Completed)
    }
}

/// Dispatch a trapped instruction through the installed interceptor.
///
/// Returns [`InstructionDispatch::Unsubscribed`] without entering the tool
/// when no interceptor subscribed to this family. The architecture then
/// completes the instruction natively: x86 CR4.TSD traps `RDTSC` and `RDTSCP`
/// together, and NARF never disables the user TSC, so an unsubscribed
/// timestamp family behaves as if untrapped. `native` runs at most once and
/// only after `Continue`. After `Defer` the CPU's flag is released before this
/// returns [`InstructionDispatch::Deferred`], whose
/// [`complete`](DeferredInstructionCall::complete) takes its own native
/// emulation.
pub fn dispatch_instruction<F>(
    instruction: NondeterministicInstruction,
    instruction_pointer: u64,
    native: F,
) -> Result<InstructionDispatch, InstructionDispatchError>
where
    F: FnOnce() -> InstructionResult,
{
    let Some(slot) = global_interceptor() else {
        return Ok(InstructionDispatch::Unsubscribed);
    };
    if !slot.subscriptions.contains(instruction) {
        return Ok(InstructionDispatch::Unsubscribed);
    }
    let Some(callback_guard) = CallbackGuard::try_take() else {
        return Err(InstructionDispatchError::Reentrant);
    };
    let interceptor = slot.interceptor.as_ref();
    let invocation = InstructionInvocation {
        instruction,
        task_id: crate::handlers::current_task_id(),
        instruction_pointer,
    };
    let result = match interceptor.on_instruction_enter(&invocation) {
        InstructionInterception::Continue => native(),
        InstructionInterception::Complete(result) => result,
        InstructionInterception::Defer => {
            // The deferred callback may wait and resume on another CPU, so it
            // must not run under this CPU's flag.
            drop(callback_guard);
            return Ok(InstructionDispatch::Deferred(DeferredInstructionCall {
                invocation,
                slot,
            }));
        }
    };
    let result = check_family(instruction, result)?;
    let result = interceptor.on_instruction_return(&invocation, result);
    check_family(instruction, result).map(InstructionDispatch::Completed)
}

#[doc(hidden)]
#[cfg(feature = "verification-test-reset")]
pub(crate) fn __test_clear_instruction_interceptor() {
    #[cfg(target_arch = "x86_64")]
    {
        // Keep the slot published until every online CPU has stopped trapping.
        // The verification harness owns the machine while resetting this
        // singleton, so no user task can cross this teardown boundary.
        // SAFETY: the reset harness is single-owner and quiescent, and the
        // callback only clears CR4.TSD on each selected online CPU.
        let cleared = unsafe {
            narf_lib::smp::remote_call(
                narf_lib::smp::online_bitmap(),
                narf_arch::x86_64::cr::__verification_clear_user_rdtsc_interception,
            )
        };
        assert!(
            cleared,
            "verification instruction-reset rendezvous unavailable"
        );
    }
    // A CPU may already hold the loaded pointer, so test retirement never
    // reclaims the old allocation. Production has no public reset operation.
    let _retired = GLOBAL_INTERCEPTOR.swap(core::ptr::null_mut(), Ordering::AcqRel);
    crate::vdso::__test_restore_counter_clocks();
}

#[cfg(feature = "verification-test-reset")]
#[doc(hidden)]
pub fn __verification_clear_instruction_interceptor() {
    __test_clear_instruction_interceptor();
}
