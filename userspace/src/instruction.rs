//! First-class interception for nondeterministic user instructions.
//!
//! The architecture trap path remains the sole owner of register mutation and
//! instruction advancement. An interceptor receives an immutable invocation,
//! may select native emulation or a typed completed value, and may replace only
//! the result of that same instruction kind.

use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

/// User instruction families whose results may vary independently of guest
/// memory and registers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NondeterministicInstruction {
    /// x86 `RDTSC` (`0f 31`).
    Rdtsc,
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

    pub const fn contains(self, instruction: NondeterministicInstruction) -> bool {
        let bit = match instruction {
            NondeterministicInstruction::Rdtsc => Self::RDTSC.0,
        };
        self.0 & bit != 0
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
    Rdtsc { value: u64 },
}

impl InstructionResult {
    fn instruction(self) -> NondeterministicInstruction {
        match self {
            Self::Rdtsc { .. } => NondeterministicInstruction::Rdtsc,
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
}

/// Process-global nondeterministic-instruction policy.
///
/// One object is published for the kernel lifetime. It is shared directly by
/// every CPU and must synchronize its own mutable state. It never receives a
/// mutable trap frame; register writes and instruction advancement remain
/// architecture-owned.
/// # Safety
///
/// Methods execute synchronously from an architecture exception handler with
/// ordinary interrupts masked. Implementations must not allocate, park, await,
/// take a sleepable lock, re-enter guest execution, or recursively dispatch an
/// intercepted instruction. Mutable state must use preallocated IRQ-safe,
/// lock-free storage. Violating these requirements can deadlock or corrupt the
/// interrupted task.
pub unsafe trait InstructionInterceptor: Send + Sync {
    /// Instruction families this interceptor owns for its entire lifetime.
    ///
    /// Called exactly once by installation. The returned value is frozen in
    /// the published kernel slot and is never queried from a trap handler.
    fn subscriptions(&self) -> InstructionSubscriptions;

    /// Select native emulation or a completed value.
    fn on_instruction_enter(&self, _invocation: &InstructionInvocation) -> InstructionInterception {
        InstructionInterception::Continue
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

/// Publish the kernel-lifetime instruction interceptor exactly once.
///
/// A losing concurrent caller retains ownership of its interceptor. Successful
/// publication also activates the requested trap mechanism on every currently
/// online CPU before returning. Schedulers must additionally call
/// [`activate_current_cpu_instruction_interception`] before a newly-online CPU
/// can return an instrumented task to user mode.
pub fn try_install_instruction_interceptor(
    interceptor: Box<dyn InstructionInterceptor>,
) -> Result<(), Box<dyn InstructionInterceptor>> {
    let subscriptions = interceptor.subscriptions();
    #[cfg(target_arch = "x86_64")]
    if subscriptions.contains(NondeterministicInstruction::Rdtsc)
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
            #[cfg(target_arch = "x86_64")]
            if subscriptions.contains(NondeterministicInstruction::Rdtsc) {
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

/// Dispatch a trapped instruction through the installed interceptor.
///
/// Returns `None` when no interceptor subscribed to this family, allowing the
/// architecture to retain its ordinary fault behavior. `native` runs at most
/// once and only after `Continue`.
pub fn dispatch_instruction<F>(
    instruction: NondeterministicInstruction,
    instruction_pointer: u64,
    native: F,
) -> Result<Option<InstructionResult>, InstructionDispatchError>
where
    F: FnOnce() -> InstructionResult,
{
    let Some(slot) = global_interceptor() else {
        return Ok(None);
    };
    if !slot.subscriptions.contains(instruction) {
        return Ok(None);
    }
    let cpu = narf_lib::percpu::current_cpu().min(narf_lib::percpu::MAX_CPUS - 1);
    if IN_INSTRUCTION_CALLBACK[cpu]
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(InstructionDispatchError::Reentrant);
    }
    struct CallbackGuard(&'static AtomicBool);
    impl Drop for CallbackGuard {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }
    let _callback_guard = CallbackGuard(&IN_INSTRUCTION_CALLBACK[cpu]);
    let interceptor = slot.interceptor.as_ref();
    let invocation = InstructionInvocation {
        instruction,
        task_id: crate::handlers::current_task_id(),
        instruction_pointer,
    };
    let result = match interceptor.on_instruction_enter(&invocation) {
        InstructionInterception::Continue => native(),
        InstructionInterception::Complete(result) => result,
    };
    if result.instruction() != instruction {
        return Err(InstructionDispatchError::ResultMismatch(
            InstructionResultMismatch {
                expected: instruction,
                actual: result.instruction(),
            },
        ));
    }
    let result = interceptor.on_instruction_return(&invocation, result);
    if result.instruction() != instruction {
        return Err(InstructionDispatchError::ResultMismatch(
            InstructionResultMismatch {
                expected: instruction,
                actual: result.instruction(),
            },
        ));
    }
    Ok(Some(result))
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
}

#[cfg(feature = "verification-test-reset")]
#[doc(hidden)]
pub fn __verification_clear_instruction_interceptor() {
    __test_clear_instruction_interceptor();
}
