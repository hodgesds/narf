//! Runtime selection of ordinary futex wake ordering.
//!
//! Policies rank eligible registrations; the futex core owns matching,
//! cancellation and dequeue. FIFO is always available and is the default.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use narf_capabilities::{Cap, CapError, Grant, NoopOp};
use narf_lib::sync::IrqSafeSpinLock;
use narf_scheduler::SchedPolicy;

/// Immutable identity of a registration, supplied only after key/bitset matching.
/// Task IDs are kernel task IDs, not namespace-visible Linux TIDs.
#[derive(Clone, Copy, Debug)]
pub struct FutexWaiterInfo {
    pub task_id: u64,
    /// None for the legacy park loop; otherwise the futex_waitv entry index
    /// (zero for a single-word handler-driven wait).
    pub wait_index: Option<usize>,
}

/// An ordering preference, never authority to wake an ineligible registration.
/// Higher ranks wake first; equal ranks preserve FIFO registration order.
///
/// `rank` runs under a futex bucket lock with IRQs disabled. It must be bounded,
/// allocation-free and nonblocking, and must not enter the scheduler, futex
/// operations or policy configuration. It may read its own immutable/atomic
/// metadata. Raw per-CPU virtual runtimes are not comparable ranks. Ranking
/// does not provide priority inheritance or override PI protocol requirements.
pub trait FutexWakePolicy: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn rank(&self, waiter: FutexWaiterInfo) -> i64;
}

#[derive(Debug)]
pub struct FifoWakePolicy;

impl FutexWakePolicy for FifoWakePolicy {
    fn name(&self) -> &'static str {
        "fifo"
    }

    fn rank(&self, _waiter: FutexWaiterInfo) -> i64 {
        0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FutexPolicyError {
    Capability(CapError),
    InvalidName,
    AlreadyRegistered,
    UnknownPolicy,
}

struct Registry {
    policies: BTreeMap<&'static str, Arc<dyn FutexWakePolicy>>,
    current: &'static str,
}

// Only configuration takes this lock. Wakes read their bucket's resident policy.
static REGISTRY: IrqSafeSpinLock<Registry> = IrqSafeSpinLock::new(Registry {
    policies: BTreeMap::new(),
    current: "fifo",
});

/// Register a kernel policy for later selection. Names are unique, 1..=32
/// ASCII lowercase letters/digits/underscores/hyphens; `fifo` is reserved.
/// Registrations live for the kernel's lifetime. No callback runs while the
/// registry is locked. Registration does not change the active policy.
pub fn register_policy<P: FutexWakePolicy>(
    cap: &Cap<SchedPolicy, Grant>,
    policy: P,
) -> Result<(), FutexPolicyError> {
    cap.invoke(NoopOp).map_err(FutexPolicyError::Capability)?;
    let name = policy.name();
    if name.is_empty()
        || name.len() > 32
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return Err(FutexPolicyError::InvalidName);
    }
    let policy: Arc<dyn FutexWakePolicy> = Arc::new(policy);
    let mut registry = REGISTRY.lock();
    if name == "fifo" || registry.policies.contains_key(name) {
        return Err(FutexPolicyError::AlreadyRegistered);
    }
    registry.policies.insert(name, policy);
    Ok(())
}

/// Replace the active ordering without moving or re-registering any waiter.
/// Publication rolls across buckets while configuration writers are serialized.
/// Each dequeue batch sees one policy; after return every bucket has the new
/// policy. Already selected wakers may still be delivered after replacement.
pub fn select_policy(cap: &Cap<SchedPolicy, Grant>, name: &str) -> Result<(), FutexPolicyError> {
    cap.invoke(NoopOp).map_err(FutexPolicyError::Capability)?;
    select_authorized(name)
}

fn select_authorized(name: &str) -> Result<(), FutexPolicyError> {
    let mut registry = REGISTRY.lock();
    let (name, policy) = if name == "fifo" {
        ("fifo", None)
    } else {
        let (&name, policy) = registry
            .policies
            .get_key_value(name)
            .ok_or(FutexPolicyError::UnknownPolicy)?;
        (name, Some(policy.clone()))
    };
    if registry.current != name {
        crate::handlers::publish_futex_wake_policy(policy);
        registry.current = name;
    }
    Ok(())
}

pub fn current_policy_name() -> &'static str {
    REGISTRY.lock().current
}

fn available_policies() -> String {
    let registry = REGISTRY.lock();
    let mut names = String::from("fifo");
    for name in registry.policies.keys() {
        names.push(' ');
        names.push_str(name);
    }
    names.push('\n');
    names
}

fn write_policy(name: &str) -> Result<(), narf_filesystem::FsError> {
    // A system-wide setting: capable checks the initial user namespace.
    if !crate::handlers::capable(crate::handlers::CAP_SYS_NICE) {
        return Err(narf_filesystem::FsError::OperationNotPermitted);
    }
    select_authorized(name).map_err(|_| narf_filesystem::FsError::InvalidData)
}

pub(crate) fn register_sysctls() {
    use narf_filesystem::procfs::sys::{register_sysctl, SysctlEntry};
    register_sysctl(SysctlEntry {
        path: "kernel/futex_wake_policy",
        read: || alloc::format!("{}\n", current_policy_name()),
        write: Some(write_policy),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "kernel/futex_wake_policies",
        read: available_policies,
        write: None,
        perms: 0o444,
    });
}
