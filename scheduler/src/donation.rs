//! Pluggable donation-policy seam — Wave E of the modular-cores plan
//! (`docs/PLUGGABILITY.md`). Mirrors the `policy::Scheduler` shape one
//! wave earlier:
//!
//! - `pub trait DonationPolicy: Send + Sync + 'static` defines the
//!   policy that decides (a) where to place the donee on the donor's
//!   CPU's runqueue and (b) the hard cycle ceiling on a single
//!   donation.
//! - `static DONATION` slot holds one boxed impl.
//! - `install_donation_policy(&cap, impl)` swaps it under a
//!   `Cap<Donation, Grant>` check.
//! - Default `HeadQueueDonation` matches the pre-Wave-E hardcoded
//!   `push_front` + 1_000_000-cycle behaviour byte-for-byte.
//! - Alternative `BackQueueDonation` lands the donee at the back of
//!   the queue (FIFO-respecting, lower priority-inversion risk,
//!   slower hand-off) while keeping the same cycle ceiling.
//!
//! Lock discipline: the executor mutates the per-CPU `READY[cpu]`
//! VecDeque under `IrqSafeSpinLock`. The donation-policy slot has its
//! own lock; impls must NOT be invoked while the queue lock is held
//! across the placement act, because the policy returns a placement
//! intent (`EnqueueDonee::HeadOfQueue` / `BackOfQueue` / `Refuse`)
//! and the executor then performs the actual `push_front` /
//! `push_back` under the queue lock. The donation lock is dropped
//! before re-taking the queue lock.

use alloc::boxed::Box;
use alloc::sync::Arc;

use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant};
use narf_lib::sync::IrqSafeSpinLock;

use crate::policy::{RunQueue, TaskHandle, TaskMeta};

/// Authority to install a donation policy. Cap-gated via
/// `install_donation_policy`; revocation is observed lazily on the
/// next install attempt.
#[derive(Copy, Clone, Debug)]
pub struct Donation;

impl CapType for Donation {
    const KIND: CapKind = CapKind::DonationPolicy;
}

/// Errors `install_donation_policy` can return.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DonationError {
    /// The install cap has been revoked.
    CapRevoked,
}

impl From<CapError> for DonationError {
    fn from(_: CapError) -> Self {
        DonationError::CapRevoked
    }
}

/// Where the policy wants the donee placed on the donor's CPU's
/// runqueue. The executor performs the actual `push_front` /
/// `push_back` after the donation lock is dropped — the policy only
/// reports its intent.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EnqueueDonee {
    /// Donee skips ahead of every other ready task. The pre-Wave-E
    /// default — matches the priority-boost semantics callers came
    /// to rely on.
    HeadOfQueue,
    /// Donee waits at the back. FIFO peers run first; the donor's
    /// boost only affects budget, not dispatch order.
    BackOfQueue,
    /// Donation is rejected. The executor restores the donor's
    /// budget and returns `DonateError::PolicyRefused` to the
    /// caller. The donee is left untouched.
    Refuse,
}

/// Pluggable donation policy. Implementors decide donee placement,
/// the per-donation cycle ceiling, and what to do when a donation is
/// revoked after settle.
///
/// **Hot-path constraint**: every method is called from the donation
/// fast path. Impls must not allocate, must not re-enter the
/// scheduler, and must not touch any `IrqSafeSpinLock` that an IRQ
/// handler could be waiting on.
pub trait DonationPolicy: Send + Sync + 'static {
    /// Stable identifier — surfaced by
    /// `current_donation_policy_name`.
    fn name(&self) -> &'static str;

    /// Where to place a donee on the donor's CPU's runqueue.
    /// `donor_meta` is a read-only snapshot (priority / class / id).
    /// The default impl's `RunQueue` argument is *not* mutated — the
    /// projection is passed so future policies can inspect queue
    /// occupancy (e.g. "head-of-queue if backlog < N else
    /// back-of-queue") without re-plumbing the trait surface.
    fn enqueue_donee(
        &self,
        queue: &RunQueue<'_>,
        donor_meta: &TaskMeta,
        donee: TaskHandle,
    ) -> EnqueueDonee;

    /// Maximum cycles a single donation may transfer. The donor's
    /// budget is pre-deducted by this amount before the donee runs.
    fn cycle_ceiling(&self, donor_meta: &TaskMeta) -> u64;

    /// Called when the donor's cap is revoked between donate and
    /// settle. `refund_cycles` is the unspent credit the donee gave
    /// back; the policy may use this for accounting or telemetry.
    /// The executor still performs the structural refund
    /// (re-crediting the donor's `BudgetAccount` or cancelling its
    /// pending debit) — this hook is informational. Default impls
    /// leave it as a no-op.
    fn on_revoke(&self, donor_meta: &TaskMeta, refund_cycles: u64) {
        let _ = donor_meta;
        let _ = refund_cycles;
    }
}

/// Head-of-queue donation — the pre-Wave-E default. Matches the
/// previously hardcoded `push_front` + 1_000_000-cycle behaviour
/// byte-for-byte.
#[derive(Copy, Clone, Debug, Default)]
pub struct HeadQueueDonation;

impl DonationPolicy for HeadQueueDonation {
    fn name(&self) -> &'static str {
        "head-queue"
    }

    fn enqueue_donee(
        &self,
        _queue: &RunQueue<'_>,
        _donor_meta: &TaskMeta,
        _donee: TaskHandle,
    ) -> EnqueueDonee {
        EnqueueDonee::HeadOfQueue
    }

    fn cycle_ceiling(&self, _donor_meta: &TaskMeta) -> u64 {
        DEFAULT_CYCLE_CEILING
    }
}

/// Back-of-queue donation. Donee receives the donor's cycle budget
/// boost but waits its FIFO turn — useful for systems that want the
/// budget transfer without the priority-inversion risk of a
/// head-of-queue jump.
#[derive(Copy, Clone, Debug, Default)]
pub struct BackQueueDonation;

impl DonationPolicy for BackQueueDonation {
    fn name(&self) -> &'static str {
        "back-queue"
    }

    fn enqueue_donee(
        &self,
        _queue: &RunQueue<'_>,
        _donor_meta: &TaskMeta,
        _donee: TaskHandle,
    ) -> EnqueueDonee {
        EnqueueDonee::BackOfQueue
    }

    fn cycle_ceiling(&self, _donor_meta: &TaskMeta) -> u64 {
        DEFAULT_CYCLE_CEILING
    }
}

/// Hard ceiling on a single donation. 1M cycles is a few hundred µs
/// at multi-GHz: large enough to be a real boost, small enough that
/// an unthrottled donor's `u64::MAX - cycles_spent` doesn't transfer
/// the universe. Both default impls return this; alternative policies
/// can override via `cycle_ceiling`.
pub const DEFAULT_CYCLE_CEILING: u64 = 1_000_000;

/// `Box<dyn DonationPolicy>` slot. Init wires a `HeadQueueDonation`
/// so behaviour out of the box matches the pre-Wave-E inline
/// `push_front` + 1M-cycle cap byte-for-byte.
static DONATION: [IrqSafeSpinLock<Option<Arc<dyn DonationPolicy>>>; narf_lib::percpu::MAX_CPUS] =
    [const { IrqSafeSpinLock::new(None) }; narf_lib::percpu::MAX_CPUS];

#[inline]
fn local_slot() -> &'static IrqSafeSpinLock<Option<Arc<dyn DonationPolicy>>> {
    &DONATION[narf_lib::percpu::current_cpu().min(narf_lib::percpu::MAX_CPUS - 1)]
}

/// Install a donation policy. Cap-gated on `Cap<Donation, Grant>`.
/// Replaces the previous active policy; the displaced `Box` is
/// dropped.
pub fn install_donation_policy<D: DonationPolicy>(
    cap: &Cap<Donation, Grant>,
    d: D,
) -> Result<(), DonationError> {
    cap.check_live()?;
    let replacement: Arc<dyn DonationPolicy> = Arc::from(Box::new(d) as Box<dyn DonationPolicy>);
    for slot in &DONATION {
        *slot.lock() = Some(replacement.clone());
    }
    Ok(())
}

/// Snapshot the active donation policy's name. Returns `None` if
/// `init()` hasn't run yet.
pub fn current_donation_policy_name() -> Option<&'static str> {
    let slot = local_slot().lock();
    slot.as_ref().map(|d| d.name())
}

/// Install the default `HeadQueueDonation` if no donation policy is
/// yet installed. Idempotent — re-calling after an explicit
/// `install_donation_policy` is a no-op. Called from `crate::init`.
pub(crate) fn install_default_if_unset() {
    let replacement: Arc<dyn DonationPolicy> =
        Arc::from(Box::new(HeadQueueDonation) as Box<dyn DonationPolicy>);
    for slot in &DONATION {
        let mut slot = slot.lock();
        if slot.is_none() {
            *slot = Some(replacement.clone());
        }
    }
}

/// Executor entry: consult the active policy for a placement intent
/// and cycle ceiling. Returns `(EnqueueDonee, ceiling)`. Falls back
/// to `HeadQueueDonation` semantics when nothing is installed (very
/// early boot / smoke teardown). The donation lock is dropped before
/// returning, so the caller is free to take the per-CPU queue lock
/// without nesting.
pub(crate) fn placement_and_ceiling(
    queue: &RunQueue<'_>,
    donor_meta: &TaskMeta,
    donee: TaskHandle,
) -> (EnqueueDonee, u64) {
    let slot = local_slot().lock();
    match slot.as_ref() {
        Some(p) => (
            p.enqueue_donee(queue, donor_meta, donee),
            p.cycle_ceiling(donor_meta),
        ),
        None => {
            let fallback = HeadQueueDonation;
            (
                fallback.enqueue_donee(queue, donor_meta, donee),
                fallback.cycle_ceiling(donor_meta),
            )
        }
    }
}

/// Executor entry: notify the active policy that a donation was
/// revoked between donate and settle. The structural refund (
/// re-crediting the donor's budget, cancelling pending debit) is
/// performed by the caller; this hook is informational. Falls back
/// to a no-op when nothing is installed.
pub(crate) fn notify_revoke(donor_meta: &TaskMeta, refund_cycles: u64) {
    let slot = local_slot().lock();
    if let Some(p) = slot.as_ref() {
        p.on_revoke(donor_meta, refund_cycles);
    }
}
