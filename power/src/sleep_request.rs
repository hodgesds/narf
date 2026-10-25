//! Userspace sleep-request intake — the seam between trigger
//! surfaces and the power policy service.
//!
//! Trigger surfaces (today: the `/sys/power/state` store in
//! [`crate::sysfs_bridge`]) parse a user request into a
//! [`SleepState`] and hand it to [`request_sleep`]. The composition
//! root installs a [`SleepRequestHook`] that forwards the request
//! into the policy path — the power service's cap-gated action
//! queue, whose executor owns the `Cap<Power, Invoke>` and calls
//! [`crate::suspend::s3_enter`] / [`crate::s2idle::suspend_to_idle`]
//! from task context.
//!
//! Why the indirection: the store callback runs in the *writer's*
//! syscall context, and the writer holds no Power capability — in
//! this kernel, holding the cap is what authorises execution, so a
//! trigger must never execute a sleep transition itself. It can
//! only *request* one. The hook is the single, replaceable point
//! where requests enter the policy path; until the composition
//! installs it, [`request_sleep`] fails with
//! [`SleepRequestError::NoConsumer`] rather than dropping the
//! request on the floor.
//!
//! One honest divergence from Linux falls out of this: Linux's
//! `state_store` blocks in the write until the machine resumes,
//! because the kernel executes the transition in the writer's
//! context. Here the write returns once the request is queued with
//! the policy service. The cap discipline is the reason, and it is
//! not negotiable — the alternative (the sysfs layer minting or
//! borrowing a Power cap) would break the authority model.

use core::sync::atomic::{AtomicUsize, Ordering};

/// A system sleep state a user can request by name — the subset of
/// Linux's `pm_state` table this kernel implements. (`standby` and
/// `disk` are absent: no S1 platform path, no hibernation image
/// writer — writing either name is an error, as on a Linux built
/// without those configurations.)
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SleepState {
    /// Suspend-to-idle: [`crate::s2idle::suspend_to_idle`].
    Freeze,
    /// Suspend-to-RAM (S3): [`crate::suspend::s3_enter`].
    Mem,
}

impl SleepState {
    /// The `/sys/power/state` token for this state.
    pub fn name(self) -> &'static str {
        match self {
            SleepState::Freeze => "freeze",
            SleepState::Mem => "mem",
        }
    }

    /// Parse one whitespace-delimited token from a `state` write.
    /// Exact match, like Linux's `decode_state`.
    pub fn parse(token: &str) -> Option<SleepState> {
        match token {
            "freeze" => Some(SleepState::Freeze),
            "mem" => Some(SleepState::Mem),
            _ => None,
        }
    }

    /// Whether this state exists on the running platform right now.
    /// The trigger refuses unsupported states at write time with
    /// `EINVAL`, matching Linux (a state missing from the `show`
    /// list cannot be written either).
    pub fn supported(self) -> bool {
        match self {
            SleepState::Freeze => crate::s2idle::s2idle_supported(),
            SleepState::Mem => crate::suspend::s3_supported(),
        }
    }
}

/// Why a sleep request did not reach the policy path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SleepRequestError {
    /// No hook installed: the composition root has not wired the
    /// policy service (or it has not started yet).
    NoConsumer,
    /// The installed consumer declined the request (policy refusal,
    /// e.g. the active power policy forbids sleep on this event).
    Refused,
}

/// The composition-installed request consumer. Called synchronously
/// from the trigger's context; implementations must only *queue*
/// the request for their worker (the power service's
/// `request_action` shape) — never execute a sleep transition
/// inline, for the cap reasons in the module docs.
pub type SleepRequestHook = fn(SleepState) -> Result<(), SleepRequestError>;

static SLEEP_REQUEST_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install the sleep-request consumer. Called once by the
/// composition root alongside the power service's executor install;
/// a second install replaces the first.
pub fn set_sleep_request_hook(hook: SleepRequestHook) {
    SLEEP_REQUEST_HOOK.store(hook as usize, Ordering::Release);
}

/// Whether a request consumer is installed. Diagnostic.
pub fn sleep_request_hook_installed() -> bool {
    SLEEP_REQUEST_HOOK.load(Ordering::Acquire) != 0
}

/// Forward one parsed sleep request to the policy path.
pub fn request_sleep(state: SleepState) -> Result<(), SleepRequestError> {
    let h = SLEEP_REQUEST_HOOK.load(Ordering::Acquire);
    if h == 0 {
        return Err(SleepRequestError::NoConsumer);
    }
    // SAFETY: the slot only ever holds a `SleepRequestHook` stored
    // by `set_sleep_request_hook`.
    let f: SleepRequestHook = unsafe { core::mem::transmute(h) };
    f(state)
}

#[doc(hidden)]
pub fn __test_reset_sleep_request_hook() {
    SLEEP_REQUEST_HOOK.store(0, Ordering::Release);
}
