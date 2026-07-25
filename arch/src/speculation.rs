//! Per-CPU speculative-execution control.
//!
//! Policy is applied by code executing on the target CPU. This is
//! intentionally not a boot-global switch: a future policy manager can
//! rendezvous a selected CPU and call [`configure_current_cpu`] there.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use narf_lib::percpu::MAX_CPUS;

/// Speculation-control policy for one logical CPU.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Policy {
    /// Remove the controls owned by this module.
    Disabled,
    /// Enable every supported baseline control.
    Protected,
}

/// Last observed state for one logical CPU.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum State {
    Unconfigured = 0,
    Disabled = 1,
    Protected = 2,
    Unsupported = 3,
    Failed = 4,
}

static STATES: [AtomicU8; MAX_CPUS] =
    [const { AtomicU8::new(State::Unconfigured as u8) }; MAX_CPUS];
static TRANSITIONING: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];

/// Owns one current-CPU transition and restores the caller's IRQ state.
///
/// The flag also makes an accidental nested/NMI transition fail without
/// touching hardware. It is not a remote-CPU lock: remote mutation is not
/// supported by this API.
pub(crate) struct TransitionGuard {
    cpu: usize,
    restore_irqs: bool,
}

impl TransitionGuard {
    pub(crate) fn acquire(cpu: usize) -> Option<Self> {
        if cpu >= MAX_CPUS
            || TRANSITIONING[cpu]
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
        {
            return None;
        }
        let restore_irqs = crate::interrupts_enabled();
        // SAFETY: the transition is bounded and Drop restores the exact entry
        // state; it never blocks while IRQs are masked.
        unsafe { crate::disable_interrupts() };
        Some(Self { cpu, restore_irqs })
    }
}

impl Drop for TransitionGuard {
    fn drop(&mut self) {
        TRANSITIONING[self.cpu].store(false, Ordering::Release);
        if self.restore_irqs {
            // SAFETY: IRQs were enabled on entry, so the surrounding context
            // had a valid interrupt table and permitted delivery.
            unsafe { crate::enable_interrupts() };
        }
    }
}

/// Apply `policy` to the CPU currently executing this function.
///
/// This function never writes another CPU's registers. Callers that want
/// to change a remote CPU must arrange an IPI/rendezvous and execute this
/// function on that CPU.
///
/// # Safety
///
/// Must execute at CPL0/EL1 on a pinned, non-preemptible current CPU during
/// bring-up or under a rendezvous. The function masks ordinary IRQs and
/// restores their exact entry state. NMI/SError handlers may observe either
/// the old or new hardware policy and must not call this function recursively.
///
/// `Policy::Disabled` additionally requires policy-layer authorisation and a
/// proof that the CPU cannot cross a boundary requiring protection until a
/// later successful `Policy::Protected` transition.
pub unsafe fn configure_current_cpu(policy: Policy) -> State {
    let cpu = crate::narf_arch_cpu_id();
    let _guard = match TransitionGuard::acquire(cpu) {
        Some(guard) => guard,
        None => return State::Failed,
    };
    let new_state = {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: inherited from this function's contract.
            unsafe { configure_x86(policy) }
        }
        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: inherited from this function's contract.
            unsafe { configure_aarch64(policy) }
        }
    };

    // Publish only after the hardware operation and read-back complete.
    STATES[cpu].store(new_state as u8, Ordering::Release);
    new_state
}

/// Return the last observed state for `cpu`.
pub fn state(cpu: usize) -> State {
    if cpu >= MAX_CPUS {
        return State::Failed;
    }
    match STATES[cpu].load(Ordering::Acquire) {
        1 => State::Disabled,
        2 => State::Protected,
        3 => State::Unsupported,
        4 => State::Failed,
        _ => State::Unconfigured,
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn configure_x86(policy: Policy) -> State {
    let enable = matches!(policy, Policy::Protected);
    // SAFETY: inherited from configure_current_cpu.
    match unsafe { crate::x86_64::spec_ctrl::apply_default_controls(enable) } {
        crate::x86_64::spec_ctrl::ApplyResult::Applied => {
            if enable {
                State::Protected
            } else {
                State::Disabled
            }
        }
        crate::x86_64::spec_ctrl::ApplyResult::Unsupported => State::Unsupported,
        crate::x86_64::spec_ctrl::ApplyResult::Fault => State::Failed,
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn configure_aarch64(policy: Policy) -> State {
    if crate::aarch64::ssbs::caps() < 2 {
        return State::Unsupported;
    }
    let expected = matches!(policy, Policy::Protected);
    if expected {
        // SAFETY: capability checked above; inherited EL1 contract.
        unsafe { crate::aarch64::ssbs::enable() };
    } else {
        // SAFETY: capability checked above; inherited EL1 contract.
        unsafe { crate::aarch64::ssbs::disable() };
    }
    // SAFETY: same capability and EL1 contract as the write above.
    if unsafe { crate::aarch64::ssbs::is_enabled() } != expected {
        State::Failed
    } else if expected {
        State::Protected
    } else {
        State::Disabled
    }
}
