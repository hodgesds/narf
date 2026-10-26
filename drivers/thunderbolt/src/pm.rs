//! Device power-management participation for the native connection
//! manager.
//!
//! The CM registers one handler pair under `"usb4-native-cm"` when
//! it starts (see `runtime::start`). The handlers are state-checked:
//! they replaced an unconditional `Busy` veto that made system
//! suspend impossible for the rest of the boot once any native CM
//! had started (#1028).
//!
//! Suspend contract, by CM state:
//!
//! - **No live tunnels** (CM idle, stopped, or exited after a clean
//!   teardown): `Ok`. No router paths need preserving, and nothing
//!   the CM owns can be mid-transfer — the only in-flight work
//!   possible is a CM-driven control transaction, which surfaces to
//!   the CM as an ordinary transport error if a power transition
//!   interrupts it.
//! - **Live tunnels** (`tunnel::live_tunnel_count() > 0`): `Busy`.
//!   Tunnel suspend/replay is not implemented, so powering down
//!   would silently drop live DisplayPort/USB3 paths. Once the
//!   tunnels are gone (hot-unplug, teardown) suspend can proceed —
//!   that retry-later state is exactly what `Busy` means. The veto
//!   is attributed to `"usb4-native-cm"` in the fan-out report.
//! - **Orphaned paths** (`tunnel::orphaned_path_domains()`
//!   non-empty): `Busy`. A CM exited with tunnel writes
//!   unrolled-back (a poisoned channel can prevent teardown), so
//!   its routers may still carry programmed paths with no owner
//!   able to roll them back. Unlike the old blanket veto, this
//!   refusal is earned by an actual failed teardown and scoped to
//!   the affected domain.
//!
//! Resume is unconditionally `Ok`: suspend quiesces nothing (it
//! only checks state), so there is nothing to replay or restore.
//! If a real quiesce lands with tunnel suspend/replay, resume must
//! mirror it.
//!
//! Both handlers honour the `device_pm` contract: they run with
//! interrupts gated, never schedule or sleep, and only take the
//! tunnel registries' spinlocks for bounded, await-free reads.

use narf_power::device_pm::DeviceSuspendError;

/// Registration name in the device-PM registry. The fan-out report
/// attributes outcomes to this name; fixtures pin the literal.
pub(crate) const PM_NAME: &str = "usb4-native-cm";

/// Register the CM's suspend/resume handlers with the system
/// device-PM fan-out. Called from `runtime::start` once firmware
/// has granted native control and at least one NHI is present.
/// Registration is idempotent on the name (registry semantics) and
/// persists for the boot; the handlers are pure state reads, so a
/// registration that outlives the CM task is harmless — it reports
/// `Ok` for as long as no paths are live or orphaned.
pub(crate) fn register() {
    narf_power::device_pm::register_device_pm(PM_NAME, suspend, resume);
}

fn suspend() -> Result<(), DeviceSuspendError> {
    if super::tunnel::live_tunnel_count() == 0 && super::tunnel::orphaned_path_domains().is_empty()
    {
        return Ok(());
    }
    Err(DeviceSuspendError::Busy)
}

fn resume() -> Result<(), DeviceSuspendError> {
    Ok(())
}

#[cfg(feature = "kernel-test")]
#[path = "pm_tests.rs"]
mod tests;
