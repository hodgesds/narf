//! narf-drivers — driver framework.
//!
//! Spec: `drivers/specification/spec.md`. Stage-3 Wave-3a scope: the
//! driver contract + lifecycle + cap-gated registration — everything
//! needed to *load* a driver and drive its async lifetime. Concrete
//! drivers (virtio-console, virtio-blk, etc.) layer over this in
//! Wave 3b and later.
//!
//! What exists in Wave 3a:
//! - `Driver` trait — async `start` / `quiesce` via `Pin<Box<dyn Future>>`
//!   so the registry can hold heterogeneous drivers behind one type.
//! - `DriverManifest` — Rust-level manifest value (static metadata
//!   describing a driver: name, domain policy, `CapKind`s required).
//!   The `#[driver(...)]` proc-macro + TOML parser sketched in the
//!   spec is Wave-3b work; Wave 3a drivers hand-roll the manifest
//!   value.
//! - `DriverEnv<'_>` — handed to `start`. Carries the driver's own
//!   cap handle and the domain the kernel assigned. `bus/` claim
//!   handles + `io/` DMA contexts + `interrupts/` bindings are
//!   Wave-3b additions.
//! - `DriverRegistry` — global singleton holding registered drivers;
//!   registration is gated on a `Cap<DriverHandle, Grant>` so only
//!   authorised callers can load drivers. Each registered driver gets
//!   its own `Cap<DriverHandle, Write>`.
//! - `NoopDriver` — in-tree example that records its lifecycle calls
//!   via atomics. Primary use: exercising the framework from tests.
//!
//! Non-goals for Wave 3a:
//! - `#[driver(...)]` attribute-macro + TOML manifest parser.
//! - Concrete drivers (virtio-blk, virtio-console). Wave 3b.
//! - Panic containment (driver panics terminating only the driver's
//!   domain) — needs `frame/` trap-prologue cooperation. Flagged.
//! - Driver hot-reload.
//! - Manifest signing / measured-load path (awaits `crypto/`
//!   Stage-2 AEAD + signature-verify surface).
//! - IRQ binding + MMIO region mapping (needs `interrupts/` + `io/`
//!   surfaces the main agent will wire in Wave 3b).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod bound;
pub mod domain_alloc;
pub mod params;

mod tests;
pub use bound::{
    domain_of as driver_domain, firmware_of as bound_firmware_of,
    firmware_snapshot as bound_firmware_snapshot, record as record_bound,
    set_domain as set_driver_domain, set_firmware as set_bound_firmware, snapshot as bound_drivers,
    BoundDriver, BoundFirmware, BoundKind,
};
#[cfg(target_arch = "x86_64")]
pub use domain_alloc::claim_mmio_for_driver;
pub use domain_alloc::{
    claim_mmio_in_domain, claimed_in_domain, free_chunks_in_domain, release as release_domain_mmio,
    DomainAllocError,
};
pub use params::{DriverParams, ParamError, ParamSlot};

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;

use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant, Write};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

// ── Reclaim tokens ──────────────────────────────────────────────────
//
// A driver records the resources it claimed (IDT vectors, MMIO ranges,
// DMA buffer slots) so `unbind_named` can give them back without the
// driver code itself having to expose a teardown ritual. The tokens
// are vendored in this crate — driver code calls `track_reclaim()`
// during `start`, and the framework executes the matching release in
// reverse-registration order during unbind.

/// One owned resource the driver wants the framework to release on
/// unbind. Variants stay narrow on purpose: the framework knows how
/// to free exactly these kinds because each maps onto a public API in
/// `interrupts/`, `drivers/domain_alloc`, or `io/`. Anything more
/// exotic (custom IPC channels, driver-private slabs) the driver
/// should free in its own `quiesce` and not park in the registry.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ReclaimToken {
    /// IDT vector returned by `narf_interrupts::vector::alloc`. Freed
    /// after a one-epoch quarantine so an in-flight IRQ raised before
    /// `clear_handler` cannot race a fresh allocation.
    IdtVector(u8),
    /// VA range returned by `claim_mmio_in_domain`. Released
    /// immediately — the page tables come down synchronously.
    MmioRange {
        domain: u8,
        va_base: u64,
        len: usize,
    },
    /// Object-table slot of a `Cap<DmaBuffer, _>` previously minted
    /// via `narf_io::register_with_cap`. The matching backing buffer
    /// is dropped via `narf_io::unregister_by_index`.
    DmaCapSlot(u32),
}

/// Vectors held in quarantine for one unbind cycle before being
/// returned to the IDT allocator. A new unbind drains the previous
/// epoch's quarantine and parks its own freshly-released vectors.
static VECTOR_QUARANTINE: IrqSafeSpinLock<Vec<u8>> = IrqSafeSpinLock::new(Vec::new());

fn quarantine_swap(new: Vec<u8>) -> Vec<u8> {
    let mut q = VECTOR_QUARANTINE.lock();
    core::mem::replace(&mut *q, new)
}

/// Test-only: drain the vector quarantine immediately, releasing
/// every parked vector to the IDT allocator. Hermetic unbind smokes
/// use this to assert end-state without spinning a second unbind.
#[doc(hidden)]
pub fn __drain_vector_quarantine_for_test() {
    let drained = quarantine_swap(Vec::new());
    for v in drained {
        let _ = narf_interrupts::vector::free(v);
    }
}

// ── Cap marker ──────────────────────────────────────────────────────

/// Cap-type marker for driver-framework administrative + per-driver
/// caps. The same `CapKind::Driver` covers both uses; rights + badging
/// discriminate:
/// - `Cap<DriverHandle, Grant>`: registry authority (who may load
///   drivers). Bootstrapped once at boot by the TCB.
/// - `Cap<DriverHandle, Write>`: a specific driver's own handle,
///   returned from `DriverRegistry::register`. The driver uses it
///   to prove authority over its own lifecycle.
#[derive(Debug)]
pub struct DriverHandle;
impl CapType for DriverHandle {
    const KIND: CapKind = CapKind::Driver;
}

// ── Manifest ────────────────────────────────────────────────────────

/// Domain placement policy for a driver.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DomainPolicy {
    /// Share the default driver domain. Lower isolation, cheaper
    /// domain-switch cost — appropriate for low-risk chatty drivers
    /// (early console before a dedicated-domain pool exists).
    Shared,
    /// Claim a dedicated PKS/MTE domain from `memory/`'s free pool.
    /// Hard error (`RegistrationError::NoDomain`) if exhausted.
    Dedicated,
}

/// Static manifest describing a driver. Wave-3a is the Rust-level
/// value; the TOML-driven `#[driver(...)]` macro is Wave 3b.
#[derive(Debug)]
pub struct DriverManifest {
    pub name: &'static str,
    pub domain_policy: DomainPolicy,
    /// `CapKind`s the driver requires. `capabilities/` §3.1 defines
    /// the enum; a manifest naming any `CapKind` outside the enum is
    /// a compile error because this is a typed `&[CapKind]`, not a
    /// string list.
    pub caps_required: &'static [CapKind],
}

// ── DriverEnv ───────────────────────────────────────────────────────

/// Environment handed to `Driver::start`. Wave-3a fields are the
/// minimum needed to prove identity + domain. Wave 3b extends this
/// with bus-device claims, DMA contexts, IRQ receivers.
#[derive(Debug)]
pub struct DriverEnv<'a> {
    /// This driver's own handle — use it for subsequent cap-gated ops
    /// (registering IRQ receivers, claiming bus devices, etc.).
    pub self_cap: Cap<DriverHandle, Write>,
    /// Domain the driver runs in.
    pub domain: DomainId,
    /// Reference to the driver's manifest (the registry owns it).
    pub manifest: &'a DriverManifest,
}

// ── Driver trait ────────────────────────────────────────────────────

/// Boxed, pinned future used by the async lifecycle hooks. The box is
/// the price of dynamic dispatch: the registry holds `Box<dyn Driver>`
/// and needs a concrete future type in return.
pub type DriverFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// The contract every driver implements. `start` runs to completion
/// (the driver's main event loop); `quiesce` is called when the
/// framework wants the driver to shut down cleanly; `reset` is the
/// recovery hook the framework calls when the device is wedged
/// (timeout, AER fatal, hot-unplug-then-replug) — the driver throws
/// away any in-flight state, brings the device back to a known
/// post-reset register layout, and is ready for `start` again.
pub trait Driver: Send + 'static {
    /// Spin up the driver. Runs as a scheduler task.
    fn start<'a>(&'a mut self, env: DriverEnv<'a>) -> DriverFuture<'a>;

    /// Quiesce — the framework asks the driver to finish outstanding
    /// work and release its resources. A well-behaved driver returns
    /// in bounded time.
    fn quiesce<'a>(&'a mut self) -> DriverFuture<'a>;

    /// Reset — discard in-flight state and bring the device back to
    /// post-power-on register defaults. Called on:
    /// - Test teardown between hermetic smokes (one device, many
    ///   probe cycles in the same QEMU boot).
    /// - PCIe AER fatal recovery, after the bus crate has issued
    ///   FLR (function-level reset) on the device.
    /// - Hot-unplug-then-replug, where the device is the same
    ///   physical part but driver state was for a now-dead session.
    ///
    /// Default implementation is a no-op so existing drivers stay
    /// compatible — they get the documentation invariant ("reset
    /// must restore post-POR state") for free, and recovery hooks
    /// silently no-op until each driver fills it in. Cap-revocation
    /// drivers and tightly-coupled stubs that don't hold device
    /// state can leave it at the default.
    fn reset<'a>(&'a mut self) -> DriverFuture<'a> {
        Box::pin(async move {})
    }
}

// ── Registry ────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RegistrationError {
    /// The registration-authority cap has been revoked since it was
    /// minted.
    AuthorityRevoked,
    /// The manifest named a `CapKind` the current build doesn't know
    /// about. The typed-manifest compile check normally prevents
    /// this; reserved for hot-load paths that parse untrusted input.
    UnknownCap,
    /// `DomainPolicy::Dedicated` + no free domain slot.
    NoDomain,
    /// A driver with this `name` is already registered.
    DuplicateName,
}

impl From<CapError> for RegistrationError {
    fn from(_: CapError) -> Self {
        RegistrationError::AuthorityRevoked
    }
}

/// Per-entry lifecycle phase. The "is anyone inside start/quiesce
/// right now?" exclusivity check happens under the registry lock
/// atomically — no extra per-entry mutex needed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DriverPhase {
    /// Never started.
    Loaded,
    /// A task is currently running `Driver::start`. Further calls to
    /// `start_named` / `quiesce_named` return without re-entering.
    Starting,
    /// `start` completed.
    Started,
    /// A task is currently running `Driver::quiesce`.
    Quiescing,
    /// `quiesce` completed.
    Quiesced,
    /// A task is currently running `unbind_named`. The reclaim list
    /// is being drained and the per-driver cap is about to be
    /// revoked. No new lifecycle calls are accepted.
    Unbinding,
    /// Unbind completed. The registry entry has been removed; this
    /// phase is observable only in the brief window between the
    /// reclaim drain and the registry erase, plus via any
    /// `DriverStatus` snapshot a caller stashed before unbind.
    Unbound,
}

/// An entry in the registry.
struct Registered {
    manifest: &'static DriverManifest,
    driver: Box<dyn Driver>,
    handle: Cap<DriverHandle, Write>,
    domain: DomainId,
    phase: DriverPhase,
    /// Resources the driver asked the framework to reclaim on unbind.
    /// Released in reverse-registration order so dependencies (e.g.
    /// vector handler vs. vector itself) come down in the right
    /// sequence.
    reclaim: Vec<ReclaimToken>,
}

impl core::fmt::Debug for Registered {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Registered")
            .field("name", &self.manifest.name)
            .field("domain", &self.domain)
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

/// Global registry. Wave 3a keeps everything under a single
/// `IrqSafeSpinLock` — fine because registration is a boot-time event
/// and lifecycle calls run as their own tasks.
#[derive(Debug)]
pub struct DriverRegistry {
    inner: IrqSafeSpinLock<Vec<Registered>>,
}

static REGISTRY: DriverRegistry = DriverRegistry {
    inner: IrqSafeSpinLock::new(Vec::new()),
};

/// Reference the global registry.
#[inline]
pub fn registry() -> &'static DriverRegistry {
    &REGISTRY
}

impl DriverRegistry {
    /// Register a driver. The `authority` cap is checked live; a
    /// revoked authority fails before any side effect. Domain count,
    /// duplicate-name check, and push happen under one critical
    /// section so two concurrent registers can't exceed the §4.1
    /// cap or collide on the same `DomainId`.
    pub fn register<D: Driver>(
        &self,
        authority: &Cap<DriverHandle, Grant>,
        manifest: &'static DriverManifest,
        driver: D,
    ) -> Result<Cap<DriverHandle, Write>, RegistrationError> {
        authority.check_live()?;

        let mut q = self.inner.lock();
        if q.iter().any(|r| r.manifest.name == manifest.name) {
            return Err(RegistrationError::DuplicateName);
        }

        // Wave-3a domain selection. Stubbed — real allocator lands
        // with memory/'s domain manager. Held under the same lock as
        // the push to avoid a TOCTOU between count and insert.
        let domain = match manifest.domain_policy {
            DomainPolicy::Shared => DomainId::new(1), // DRIVER_0 placeholder
            DomainPolicy::Dedicated => {
                let count = q
                    .iter()
                    .filter(|r| r.manifest.domain_policy == DomainPolicy::Dedicated)
                    .count();
                // security-model/ §4.1 caps dedicated-domain drivers at 5
                // (DRIVER_0..=DRIVER_4; the former DRIVER_5 is now
                // DomainId::BPF, the BPF runtime's confinement domain).
                if count >= 5 {
                    return Err(RegistrationError::NoDomain);
                }
                DomainId::new((1 + count) as u8)
            }
        };

        let handle: Cap<DriverHandle, Write> = Cap::<DriverHandle, Write>::bootstrap();
        q.push(Registered {
            manifest,
            driver: Box::new(driver),
            handle,
            domain,
            phase: DriverPhase::Loaded,
            reclaim: Vec::new(),
        });
        Ok(handle)
    }

    /// Number of registered drivers.
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// `true` iff the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }

    /// Drive the named driver's `start` future to completion. The
    /// `DriverPhase::Starting` gate is exclusive: a concurrent `start_named`
    /// or `quiesce_named` against the same entry returns `Ok(())`
    /// without re-entering the driver — essential so the
    /// `&mut dyn Driver` we hold across the await cannot alias.
    pub async fn start_named(&self, name: &str) -> Result<(), ()> {
        let (driver_ptr, env_pieces) = {
            let mut q = self.inner.lock();
            let entry = q.iter_mut().find(|r| r.manifest.name == name).ok_or(())?;
            // Only Loaded → Starting is a fresh start. Any other phase
            // means someone else already claimed exclusivity.
            if entry.phase != DriverPhase::Loaded {
                return Ok(());
            }
            entry.phase = DriverPhase::Starting;
            (
                (&mut *entry.driver) as *mut dyn Driver,
                (
                    entry.handle,
                    entry.domain,
                    entry.manifest as &'static DriverManifest,
                ),
            )
        };
        let env = DriverEnv {
            self_cap: env_pieces.0,
            domain: env_pieces.1,
            manifest: env_pieces.2,
        };
        // SAFETY: the phase gate above is the exclusivity proof — no
        // other caller can transition Loaded → Starting until we set
        // Started below, and the Wave-3a framework has no unregister
        // path, so the `Box<dyn Driver>` is kept alive by the
        // registry's Vec for the raw pointer's lifetime.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let driver: &mut dyn Driver = unsafe { &mut *driver_ptr };
        driver.start(env).await;
        // Transition Starting → Started under the lock so a following
        // quiesce_named observes the new phase.
        if let Some(e) = self
            .inner
            .lock()
            .iter_mut()
            .find(|r| r.manifest.name == name)
        {
            e.phase = DriverPhase::Started;
        }
        Ok(())
    }

    /// Drive the named driver's `quiesce` future. Exclusive via
    /// `DriverPhase::Quiescing` — a concurrent `quiesce_named` or a
    /// `start_named` against an already-quiescing entry returns
    /// `Ok(())` without re-entering.
    pub async fn quiesce_named(&self, name: &str) -> Result<(), ()> {
        let driver_ptr = {
            let mut q = self.inner.lock();
            let entry = q.iter_mut().find(|r| r.manifest.name == name).ok_or(())?;
            // Only Started → Quiescing (and the Loaded corner case
            // where a driver was never started) is valid. Re-entry
            // or already-quiesced is a no-op.
            match entry.phase {
                DriverPhase::Started | DriverPhase::Loaded => {
                    entry.phase = DriverPhase::Quiescing;
                }
                _ => return Ok(()),
            }
            (&mut *entry.driver) as *mut dyn Driver
        };
        // SAFETY: same phase-gate exclusivity as start_named.
        let driver: &mut dyn Driver = unsafe { &mut *driver_ptr };
        driver.quiesce().await;
        if let Some(e) = self
            .inner
            .lock()
            .iter_mut()
            .find(|r| r.manifest.name == name)
        {
            e.phase = DriverPhase::Quiesced;
        }
        Ok(())
    }

    /// Drive the named driver's `reset` future. Restores the device
    /// to post-POR state so the driver is ready for a fresh `start`
    /// after recovery. Phase tracking does NOT enter Loaded again on
    /// its own — the caller (test harness, AER recovery, hot-replug
    /// path) decides whether to invoke `start_named` afterward.
    /// Idempotent: multiple resets in a row reach the same state.
    pub async fn reset_named(&self, name: &str) -> Result<(), ()> {
        let driver_ptr = {
            let mut q = self.inner.lock();
            let entry = q.iter_mut().find(|r| r.manifest.name == name).ok_or(())?;
            // Reset is legal from any phase except in-flight start /
            // quiesce — those would corrupt the &mut driver alias —
            // and is meaningless once unbind has begun (no driver to
            // reset).
            match entry.phase {
                DriverPhase::Starting
                | DriverPhase::Quiescing
                | DriverPhase::Unbinding
                | DriverPhase::Unbound => return Ok(()),
                _ => {}
            }
            (&mut *entry.driver) as *mut dyn Driver
        };
        // SAFETY: phase gate above proves no concurrent start /
        // quiesce holds the &mut alias. Reset itself doesn't change
        // phase (the caller decides what comes next), so no post-
        // await store is needed.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let driver: &mut dyn Driver = unsafe { &mut *driver_ptr };
        driver.reset().await;
        Ok(())
    }

    /// Record a reclaim token against the named driver. Drivers call
    /// this from `start` (or any helper invoked therein) so the
    /// framework can release the resource on `unbind_named`. Returns
    /// `Err(())` if no entry by that name exists or the entry is
    /// already past Quiesced — at that point the driver no longer
    /// owns its resources.
    pub fn track_reclaim(&self, name: &str, token: ReclaimToken) -> Result<(), ()> {
        let mut q = self.inner.lock();
        let entry = q.iter_mut().find(|r| r.manifest.name == name).ok_or(())?;
        match entry.phase {
            DriverPhase::Unbinding | DriverPhase::Unbound => return Err(()),
            _ => {}
        }
        entry.reclaim.push(token);
        Ok(())
    }

    /// Tear the driver down: revoke its self-cap, drain reclaim
    /// tokens, and remove the registry entry. The driver must be
    /// past `Started` (i.e. Loaded → straight unbind, or Quiesced).
    /// Calls against an in-flight start/quiesce return `Err(())`
    /// so the caller can re-poll after the lifecycle settles.
    ///
    /// Released in reverse-registration order — drivers add resources
    /// in dependency order, so reverse order is the natural teardown.
    /// IDT vectors are quarantined for one unbind cycle so an in-
    /// flight IRQ that races `clear_handler` cannot dispatch into a
    /// freshly-allocated vector slot.
    pub fn unbind_named(&self, name: &str) -> Result<(), ()> {
        let (handle_to_revoke, reclaim_tokens) = {
            let mut q = self.inner.lock();
            let pos = q.iter().position(|r| r.manifest.name == name).ok_or(())?;
            let entry = &mut q[pos];
            match entry.phase {
                DriverPhase::Loaded | DriverPhase::Quiesced => {}
                DriverPhase::Starting | DriverPhase::Quiescing | DriverPhase::Unbinding => {
                    return Err(());
                }
                DriverPhase::Started => {
                    // Caller must quiesce first. We refuse rather than
                    // silently quiescing because the quiesce future
                    // may be long-running and shouldn't sneak through
                    // a synchronous unbind path.
                    return Err(());
                }
                DriverPhase::Unbound => return Ok(()),
            }
            entry.phase = DriverPhase::Unbinding;
            let tokens = core::mem::take(&mut entry.reclaim);
            let handle = entry.handle;
            (handle, tokens)
        };

        // Drain reclaim tokens outside the registry lock so the
        // releases (some of which themselves take internal locks)
        // can't deadlock. Per the doc, reverse order.
        let mut quarantine_new: Vec<u8> = Vec::new();
        for token in reclaim_tokens.into_iter().rev() {
            match token {
                ReclaimToken::IdtVector(v) => {
                    narf_interrupts::dispatch::clear_handler(v);
                    // Driver unbind: the vector itself is being
                    // released, so every waker still parked on it
                    // is about to lose its device. Wipe the lot via
                    // the tear-down helper.
                    narf_interrupts::dispatch::clear_all_wakers(v);
                    quarantine_new.push(v);
                }
                ReclaimToken::MmioRange {
                    domain,
                    va_base,
                    len,
                } => {
                    // SAFETY: the driver registered the same range
                    // via claim_mmio_in_domain; the ownership chain
                    // is the registration itself.
                    // SAFETY: Valid MMIO bounds or trusted driver environment
                    let _ = unsafe { domain_alloc::release(domain, va_base, len) };
                }
                ReclaimToken::DmaCapSlot(idx) => {
                    narf_io::unregister_by_index(idx);
                }
            }
        }

        // Swap our new quarantine in; previous epoch's vectors are
        // returned to the IDT allocator now (one-epoch delay).
        let drained_prev = quarantine_swap(quarantine_new);
        for v in drained_prev {
            let _ = narf_interrupts::vector::free(v);
        }

        // Revoke the per-driver cap. Every outstanding clone observes
        // Err(Revoked) on its next check_live — the driver instance
        // is finished even if some component held onto the handle.
        handle_to_revoke.revoke();

        // Erase the entry and finalise phase. Held under the lock so
        // a concurrent `with_entry` either sees the Unbinding state
        // or no entry at all — never a partially-torn-down record.
        let mut q = self.inner.lock();
        if let Some(pos) = q.iter().position(|r| r.manifest.name == name) {
            // Mark Unbound for any test snapshot taken between phases.
            q[pos].phase = DriverPhase::Unbound;
            q.remove(pos);
        }
        Ok(())
    }

    /// `true` iff a driver with this `name` is currently registered.
    /// After `unbind_named` succeeds this returns `false`.
    pub fn is_registered(&self, name: &str) -> bool {
        self.inner.lock().iter().any(|r| r.manifest.name == name)
    }

    /// Read-only accessor: run `f` against the named driver's phase +
    /// domain while holding the registry lock. Lets tests observe
    /// lifecycle state without exposing `&mut dyn Driver`.
    pub fn with_entry<R>(&self, name: &str, f: impl FnOnce(DriverStatus) -> R) -> Option<R> {
        let q = self.inner.lock();
        q.iter().find(|r| r.manifest.name == name).map(|r| {
            f(DriverStatus {
                phase: r.phase,
                domain: r.domain,
                handle: r.handle,
            })
        })
    }
}

/// Read-only view of a registered driver for observers — returned by
/// `DriverRegistry::with_entry` while the registry lock is held, so
/// the fields are a consistent snapshot at that instant.
#[derive(Copy, Clone, Debug)]
pub struct DriverStatus {
    pub phase: DriverPhase,
    pub domain: DomainId,
    pub handle: Cap<DriverHandle, Write>,
}

// Public re-export of the lifecycle phase for observers.

// ── NoopDriver ──────────────────────────────────────────────────────

/// Zero-behaviour driver used by tests + as the reference impl of the
/// Driver trait. Records its lifecycle calls via atomics so a test can
/// observe them without building a full side-channel.
#[derive(Debug, Default)]
pub struct NoopDriver {
    pub starts: core::sync::atomic::AtomicU32,
    pub quiesces: core::sync::atomic::AtomicU32,
}

impl NoopDriver {
    pub const fn new() -> Self {
        Self {
            starts: core::sync::atomic::AtomicU32::new(0),
            quiesces: core::sync::atomic::AtomicU32::new(0),
        }
    }
}

impl Driver for NoopDriver {
    fn start<'a>(&'a mut self, _env: DriverEnv<'a>) -> DriverFuture<'a> {
        Box::pin(async move {
            self.starts
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        })
    }
    fn quiesce<'a>(&'a mut self) -> DriverFuture<'a> {
        Box::pin(async move {
            self.quiesces
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        })
    }
}

/// Bootstrap the registration authority cap. TCB-only path — the
/// kernel calls this exactly once at boot and hands the result to
/// whatever subsystem actually loads drivers. Wave 3b adds a
/// `Cap<Task, Create>`-gated form.
pub fn bootstrap_authority() -> Cap<DriverHandle, Grant> {
    Cap::<DriverHandle, Grant>::bootstrap()
}
