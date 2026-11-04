//! Display runtime-PM wakerefs and the display half of integrated runtime
//! suspend/resume (MTL/Arrow display 14 and Gen12 TGL/ADL).
//!
//! MIT Linux b90c984d615e:
//!
//! - `display/xe_display_rpm.c`: `intel_display_rpm_get` is
//!   `xe_pm_runtime_resume_and_get`, `get_if_in_use` / `get_noresume` / `put`
//!   the matching xe_pm helpers. `intel_display_power.c::
//!   intel_display_power_get` takes one per power-domain reference, so every
//!   held display power domain is a PCI runtime-PM usage reference.
//! - A lit pipe holds its crtc power domains from
//!   `modeset_get_crtc_power_domains` (before `hsw_crtc_enable`, whose first
//!   step is `intel_dmc_enable_pipe`) to `modeset_put_crtc_power_domains`
//!   (after `hsw_crtc_disable`, whose last step is `intel_dmc_disable_pipe`).
//!   A lit panel therefore keeps the function out of runtime suspend.
//! - `intel_display_power.c::__intel_display_power_put_async` keeps
//!   `async_put_wakeref` until the delayed `DC_off` release (the 17 ms DC
//!   re-entry) has run.
//! - `xe_pm.c::xe_pm_runtime_suspend` (D3hot, `d3cold.allowed == false`):
//!   `xe_display_pm_runtime_suspend` → `intel_hpd_poll_enable`;
//!   `xe_display_pm_runtime_suspend_late` → `intel_dmc_wl_flush_release_work`.
//!   The DMC program and the DC target stay as they are across D3hot.
//! - `xe_pm.c::xe_pm_runtime_resume`: `xe_display_pm_runtime_resume` →
//!   `intel_hpd_init`, `intel_hpd_poll_disable`, `skl_watermark_ipc_update`.
//! - `intel_hotplug.c::i915_hpd_poll_init_work` switches HPD connectors to
//!   `DRM_CONNECTOR_POLL_CONNECT | DISCONNECT` while polling is enabled, and
//!   `drm_probe_helper.c` polls every `DRM_OUTPUT_POLL_PERIOD` (10 s); each
//!   detect takes a display power reference and so resumes the function.
//! - `xe_bo.c::__xe_bo_cpu_fault` adds a BO to `vram_userfault` only when
//!   `mem_type_is_vram` (VRAM0/1, never STOLEN), `xe_bo_cpu_fault` takes a
//!   runtime-PM reference only for `XE_BO_FLAG_VRAM_MASK`, and
//!   `xe_pm_runtime_suspend` revokes CPU mmaps only on that list. System-
//!   memory BO mappings stay valid across D3hot: integrated functions never
//!   revoke CPU mappings and never refuse runtime suspend because of them.
//!
//! In this driver the wakerefs are usage references on the function's PCI
//! runtime-PM device, bound when the GT owner starts:
//!
//! - every pipe reported lit holds one (`pipe_lit` / `pipe_dark`, reported
//!   by `intel_gpu_dc_states::pipe_lit_for_bar` / `pipe_dark_for_bar` at the
//!   Linux call sites; KMS install reports the owned Pipe A);
//! - every display-14 `DC_off` reference holds one, taken only while the
//!   function is runtime-active, so no display conversation can start while
//!   the function is suspending or suspended (it fails closed instead);
//! - the deferred DC re-entry task holds one until it finishes.
//!
//! Gen12 has no `DC_off` service and no pipe-dark report: its Pipe A,
//! reported lit at KMS install, holds its wakeref for the card's lifetime.

use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;
use narf_power::runtime_pm::{RpmStatus, RuntimePmDevice};

use crate::intel_gpu::Generation;
use crate::intel_gpu_gt::GtPlatform;

/// `DRM_OUTPUT_POLL_PERIOD`, in ns.
pub(crate) const HPD_POLL_PERIOD_NS: u64 = 10_000_000_000;

// ── Runtime-PM profile ──────────────────────────────────────────

/// How a GT owner takes part in PCI runtime PM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Profile {
    /// A display-less discrete function (DG2/BMG outside the small-BAR
    /// takeover): idle D3hot once no local-memory object exists.
    DisplayLess,
    /// An integrated MTL/Arrow or Gen12 function with an owned display:
    /// runtime PM is allowed and the display's wakerefs decide, as
    /// `xe_pm_runtime_init` allows every non-VF function.
    Display,
}

/// Why a GT owner never allows runtime PM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProfileRefusal {
    /// Not an admitted GuC platform.
    Unsupported,
    /// The opted-in BMG small-BAR whole-device takeover is D0-only: no
    /// repeated driver FLR may wipe retained BO/fd/VM state.
    SmallBar,
    /// An Arc display is not driven by this owner.
    DiscreteDisplay,
    /// LNL/PTL: every cold start needs a client-free driver FLR, so no
    /// runtime-parked epoch can continue across a resume.
    HeadlessTakeover,
    /// An integrated GT owner starts only with an owned display.
    NoDisplayOwner,
}

/// The runtime-PM profile of a GT owner.
pub(crate) fn profile(
    platform: Option<GtPlatform>,
    has_display: bool,
    smallbar: bool,
) -> Result<Profile, ProfileRefusal> {
    let platform = platform.ok_or(ProfileRefusal::Unsupported)?;
    if smallbar {
        return Err(ProfileRefusal::SmallBar);
    }
    if platform.is_discrete() {
        return if has_display {
            Err(ProfileRefusal::DiscreteDisplay)
        } else {
            Ok(Profile::DisplayLess)
        };
    }
    if platform.is_headless_integrated() {
        return Err(ProfileRefusal::HeadlessTakeover);
    }
    let display_platform =
        platform.is_gen12() || matches!(platform, GtPlatform::Integrated(Generation::MeteorLake));
    if !display_platform || platform.guc().is_none() {
        return Err(ProfileRefusal::Unsupported);
    }
    if has_display {
        Ok(Profile::Display)
    } else {
        Err(ProfileRefusal::NoDisplayOwner)
    }
}

// ── Display holds ───────────────────────────────────────────────

/// A display wakeref that keeps the function in D0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Hold {
    /// Pipes reported lit (bit per pipe): their crtc power domains.
    PipesLit(u32),
    /// `DC_off` references held by display conversations.
    DcOff(u32),
    /// The deferred DC re-entry has not run yet (`async_put_wakeref`).
    DcReentry,
    /// An external route is live, quarantined or between passes.
    ExternalRoute,
    /// The KMS owner presents, has cursor or colour work in flight, or is
    /// paused, failed or reset-lost.
    Kms,
}

/// The display state a runtime-suspend decision reads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Facts {
    pub lit: u32,
    pub dc_refs: u32,
    pub dc_reentry: bool,
    pub external: bool,
    pub kms: bool,
}

/// The first hold in `facts`, in the order the hardware would be touched.
pub(crate) fn classify(facts: Facts) -> Option<Hold> {
    if facts.lit != 0 {
        Some(Hold::PipesLit(facts.lit))
    } else if facts.dc_refs != 0 {
        Some(Hold::DcOff(facts.dc_refs))
    } else if facts.dc_reentry {
        Some(Hold::DcReentry)
    } else if facts.external {
        Some(Hold::ExternalRoute)
    } else if facts.kms {
        Some(Hold::Kms)
    } else {
        None
    }
}

/// Production facts for the display of `bar` (card `index`). Reads only
/// in-memory state; never touches a register or waits for a lock.
pub(crate) fn hold(index: u32, bar: &narf_bus::MmioRegion) -> Option<Hold> {
    let (dc_refs, dc_reentry) = crate::intel_gpu_dc_states::busy_for_bar(bar);
    classify(Facts {
        lit: REGISTRY.lit(bar.phys.raw()),
        dc_refs,
        dc_reentry,
        external: !crate::intel_gpu::external_routes_stopped(bar)
            || crate::intel_gpu_dc_states::external_live(),
        kms: crate::intel_gpu_kms::active(index),
    })
}

/// Why a runtime park is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ParkRefusal {
    /// A system sleep owns the function.
    SystemSuspend,
    /// The GT is not running (booting, resuming, failed or stopped).
    NotRunning,
    /// The owner never allows runtime PM.
    Profile(ProfileRefusal),
    /// Local-memory bytes are allocated: CPU BAR mappings of VRAM cannot be
    /// revoked and refaulted here (see the module header for the API).
    LocalMemory(u64),
    /// A display wakeref is held.
    Display(Hold),
}

/// The runtime-park admission. CPU mappings of system-memory objects are
/// never an input: they stay valid across D3hot (`xe_bo.c`, module header).
pub(crate) fn park_refusal(
    system_suspended: bool,
    running: bool,
    profile: Result<Profile, ProfileRefusal>,
    local_used: Option<u64>,
    display: Option<Hold>,
) -> Option<ParkRefusal> {
    if system_suspended {
        return Some(ParkRefusal::SystemSuspend);
    }
    if !running {
        return Some(ParkRefusal::NotRunning);
    }
    let profile = match profile {
        Ok(profile) => profile,
        Err(refusal) => return Some(ParkRefusal::Profile(refusal)),
    };
    if let Some(used) = local_used.filter(|used| *used != 0) {
        return Some(ParkRefusal::LocalMemory(used));
    }
    if profile == Profile::Display {
        if let Some(hold) = display {
            return Some(ParkRefusal::Display(hold));
        }
    }
    None
}

// ── Wakerefs ────────────────────────────────────────────────────

/// One display wakeref: a usage reference on the function's runtime-PM
/// device. Dropping it marks the function busy and puts it with autosuspend
/// (`xe_pm_runtime_put`).
#[derive(Debug)]
pub(crate) struct Wakeref(Arc<RuntimePmDevice>);

impl Drop for Wakeref {
    fn drop(&mut self) {
        let _ = self.0.put_autosuspend();
    }
}

/// The function is runtime-suspending, suspended or resuming: no display
/// register may be touched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Suspended;

#[derive(Debug)]
struct Entry {
    bar: u64,
    lit: u32,
    device: Option<Arc<RuntimePmDevice>>,
}

/// Per-function display wakeref state, keyed by BAR0 physical address.
#[derive(Debug)]
pub(crate) struct Registry {
    entries: IrqSafeSpinLock<Vec<Entry>>,
}

static REGISTRY: Registry = Registry::new();

impl Registry {
    pub(crate) const fn new() -> Self {
        Self {
            entries: IrqSafeSpinLock::new(Vec::new()),
        }
    }

    fn with_entry<R>(&self, bar: u64, f: impl FnOnce(&mut Entry) -> R) -> R {
        let mut entries = self.entries.lock();
        let index = match entries.iter().position(|entry| entry.bar == bar) {
            Some(index) => index,
            None => {
                entries.push(Entry {
                    bar,
                    lit: 0,
                    device: None,
                });
                entries.len() - 1
            }
        };
        f(&mut entries[index])
    }

    /// A pipe's crtc power domains are taken: record it lit and, once the
    /// function is bound, hold one usage reference for it. The caller is
    /// lighting the pipe and so already holds the function in D0.
    pub(crate) fn pipe_lit(&self, bar: u64, pipe: u32) {
        if pipe >= 32 {
            return;
        }
        self.with_entry(bar, |entry| {
            if entry.lit & (1 << pipe) == 0 {
                entry.lit |= 1 << pipe;
                if let Some(device) = &entry.device {
                    device.get_noresume();
                }
            }
        });
    }

    /// A pipe's crtc power domains are released after its disable: forget
    /// it and put its usage reference with autosuspend.
    pub(crate) fn pipe_dark(&self, bar: u64, pipe: u32) {
        if pipe >= 32 {
            return;
        }
        let device = self.with_entry(bar, |entry| {
            if entry.lit & (1 << pipe) == 0 {
                return None;
            }
            entry.lit &= !(1 << pipe);
            entry.device.clone()
        });
        if let Some(device) = device {
            let _ = device.put_autosuspend();
        }
    }

    /// Pipes reported lit for `bar`.
    pub(crate) fn lit(&self, bar: u64) -> u32 {
        self.entries
            .lock()
            .iter()
            .find(|entry| entry.bar == bar)
            .map_or(0, |entry| entry.lit)
    }

    /// Bind the function's runtime-PM device: every pipe already lit takes
    /// its usage reference now. A different device bound earlier gives its
    /// references back. Returns the number of references taken.
    pub(crate) fn bind(&self, bar: u64, device: Arc<RuntimePmDevice>) -> u32 {
        let (taken, old) = self.with_entry(bar, |entry| {
            if entry
                .device
                .as_ref()
                .is_some_and(|old| Arc::ptr_eq(old, &device))
            {
                return (0, None);
            }
            let old = entry
                .device
                .replace(device.clone())
                .map(|old| (old, entry.lit));
            for _ in 0..entry.lit.count_ones() {
                device.get_noresume();
            }
            (entry.lit.count_ones(), old)
        });
        if let Some((old, lit)) = old {
            for _ in 0..lit.count_ones() {
                old.put_noidle();
            }
        }
        taken
    }

    /// `intel_display_rpm_get_if_in_use` for a synchronous display path: a
    /// wakeref while the function is runtime-active. `Ok(None)` before the
    /// function is bound, or with runtime PM disabled on an active function
    /// (nothing can suspend it then); `Err` while it is suspending, suspended
    /// or resuming, before any register is touched.
    pub(crate) fn wakeref_if_active(&self, bar: u64) -> Result<Option<Wakeref>, Suspended> {
        let device = self
            .entries
            .lock()
            .iter()
            .find(|entry| entry.bar == bar)
            .and_then(|entry| entry.device.clone());
        let Some(device) = device else {
            return Ok(None);
        };
        match device.get_if_active() {
            Ok(true) => Ok(Some(Wakeref(device))),
            Ok(false) => Err(Suspended),
            Err(_) if device.status() == RpmStatus::Active => Ok(None),
            Err(_) => Err(Suspended),
        }
    }

    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn forget(&self, bar: u64) {
        self.entries.lock().retain(|entry| entry.bar != bar);
    }
}

/// [`Registry::pipe_lit`] on the production registry.
pub(crate) fn pipe_lit(bar: u64, pipe: u32) {
    REGISTRY.pipe_lit(bar, pipe);
}
/// [`Registry::pipe_dark`] on the production registry.
pub(crate) fn pipe_dark(bar: u64, pipe: u32) {
    REGISTRY.pipe_dark(bar, pipe);
}
/// [`Registry::bind`] on the production registry.
pub(crate) fn bind(bar: u64, device: Arc<RuntimePmDevice>) -> u32 {
    REGISTRY.bind(bar, device)
}
/// [`Registry::wakeref_if_active`] on the production registry.
pub(crate) fn wakeref_if_active(bar: u64) -> Result<Option<Wakeref>, Suspended> {
    REGISTRY.wakeref_if_active(bar)
}

// ── Hotplug polling while runtime-suspended ─────────────────────

/// `intel_hpd_poll_enable` while the function is runtime-suspended: one
/// detect pass per [`HPD_POLL_PERIOD_NS`], each under a wakeref (which
/// resumes the function). The first pass is one period after suspend.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct HpdPoll {
    since: Option<u64>,
}

impl HpdPoll {
    /// `intel_hpd_poll_disable`: the function is active and the card worker
    /// runs its hotplug pass every iteration.
    pub(crate) fn active(&mut self) {
        self.since = None;
    }
    /// Whether a polled detect is due at `now` (runtime-suspended).
    pub(crate) fn due(&mut self, now: u64) -> bool {
        match self.since {
            None => {
                self.since = Some(now);
                false
            }
            Some(since) if now.saturating_sub(since) >= HPD_POLL_PERIOD_NS => {
                self.since = Some(now);
                true
            }
            Some(_) => false,
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_display_rpm_tests.rs"]
mod tests;
