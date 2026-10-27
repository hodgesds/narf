//! Device power-management participation for the native connection
//! manager.
//!
//! The CM registers one handler pair under `"usb4-native-cm"` when
//! it starts (see `runtime::start`). The handlers are state-checked:
//! they replaced an unconditional `Busy` veto that made system
//! suspend impossible for the rest of the boot once any native CM
//! had started (#1028), and they now drive tunnel suspend/replay
//! (#1035) through the latch in `tunnel.rs`.
//!
//! The handlers run on the boot CPU with interrupts gated and may
//! not schedule, sleep, or await config transactions — but
//! quiescing a tunnel *is* config transactions, performed by the
//! per-domain CM task. The handlers therefore only read and latch
//! state (bounded, await-free spinlock access, honouring the
//! `device_pm` contract); the CM task services the latch from its
//! own loop and does the async work. `Busy` carries its documented
//! retry-later meaning in this protocol: the first suspend attempt
//! with live tunnels latches the quiesce and is refused, the CM
//! drains the paths in the background, and the orchestrator's
//! retry proceeds once every domain is quiesced.
//!
//! Suspend contract, by CM state:
//!
//! - **No live tunnels** (CM idle, stopped, or exited after a clean
//!   teardown): `Ok`. Nothing the CM owns can be mid-transfer — the
//!   only in-flight work possible is a CM-driven control
//!   transaction, which surfaces to the CM as an ordinary transport
//!   error if a power transition interrupts it.
//! - **Live tunnels, not yet quiesced**: latch a quiesce request
//!   for each affected domain and return `Busy`. The CM task
//!   drains each path through the journaled teardown (hop drain
//!   before credit release) and records the tunnel's identity for
//!   replay.
//! - **Live tunnels recorded quiesced** (every domain's tunnels
//!   drained into the replay records): `Ok`. A later resume
//!   replays the records against the re-scanned topology.
//! - **Orphaned paths** (`tunnel::orphaned_path_domains()`
//!   non-empty): `Busy`. A CM exited with tunnel writes
//!   unrolled-back (a poisoned channel can prevent teardown), so
//!   its routers may still carry programmed paths with no owner
//!   able to roll them back. This refusal is earned by an actual
//!   failed teardown and scoped to the affected domain.
//! - **Replay failures outstanding**
//!   (`tunnel::replay_failures()` non-empty): `Busy`. A tunnel
//!   could not be restored on the last wake; suspending again
//!   would strand it further.
//! - **Live XDomain links** (`xdomain::live_link_count() > 0`):
//!   `Busy`, checked before any tunnel quiesce is latched (tunnels
//!   are not drained for a suspend the link will refuse anyway). A
//!   host-to-host link with a completed ThunderboltIP login holds
//!   fabric state; powering down would silently drop the peer's
//!   network link. An XDomain session's replay record is a
//!   re-login — after resume the engine re-reads the peer's
//!   properties (its generation rule treats the re-read as a fresh
//!   fetch) and logs in again, mirroring the reference CM's XDomain
//!   restore flow, so no extra journal state is needed beyond the
//!   peer registry this count reads.
//!
//! Resume contract:
//!
//! - Latches a replay request for every domain holding quiesced
//!   tunnels (and cancels a suspend latch that never reached a
//!   quiesce, e.g. the orchestrator's abort rollback). The CM task
//!   re-scans, then replays each record through the original
//!   activation path; a peer that vanished across the sleep is
//!   torn down, not replayed.
//! - Returns `DriverError` when replay failures are outstanding at
//!   call time, so a failed replay is named in the fan-out report;
//!   the same call re-queues the failed tunnels for one retry.

use narf_power::device_pm::DeviceSuspendError;

/// Registration name in the device-PM registry. The fan-out report
/// attributes outcomes to this name; fixtures pin the literal.
pub(crate) const PM_NAME: &str = "usb4-native-cm";

/// Register the CM's suspend/resume handlers with the system
/// device-PM fan-out. Called from `runtime::start` once firmware
/// has granted native control and at least one NHI is present.
/// Registration is idempotent on the name (registry semantics) and
/// persists for the boot; the handlers are pure state reads and
/// latch writes, so a registration that outlives the CM task is
/// harmless — it reports `Ok` for as long as no paths are live,
/// orphaned, or awaiting replay.
pub(crate) fn register() {
    narf_power::device_pm::register_device_pm(PM_NAME, suspend, resume);
}

fn suspend() -> Result<(), DeviceSuspendError> {
    if super::xdomain::live_link_count() > 0 {
        return Err(DeviceSuspendError::Busy);
    }
    super::tunnel::pm_on_suspend()
}

fn resume() -> Result<(), DeviceSuspendError> {
    super::tunnel::pm_on_resume()
}

#[cfg(feature = "kernel-test")]
#[path = "pm_tests.rs"]
mod tests;
