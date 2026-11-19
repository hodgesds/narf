// SPDX-License-Identifier: GPL-2.0-or-later
//! Unassociated IPS: a durable original-function worker owns actual native
//! stop/off/fresh-start receipts. Foreground cancellation requests resume.
use super::system_pm_worker::{self, Control, Phase};
use alloc::sync::Arc;
use narf_bus::BusAddr;
use narf_power::device_pm::DevicePmError;
use narf_time::Deadline;

/// A completed unassociated native card-off operation. This handle is a
/// resume request/status channel, not a PCI/RF or DMA ownership capability.
/// Dropping it requests fresh startup; the worker retains the real hardware
/// receipts even when the caller cancels while retirement is pending.
pub struct RuntimeIdle {
    control: Arc<Control>,
}
impl core::fmt::Debug for RuntimeIdle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw88RuntimeIdle")
            .field("phase", &self.control.phase())
            .finish_non_exhaustive()
    }
}
impl RuntimeIdle {
    pub(super) fn new(control: Arc<Control>) -> Self {
        Self { control }
    }
    /// Observation only; no old station/key/endpoint may be reactivated.
    pub fn suspended(&self) -> bool {
        self.control.phase() == Phase::Suspended
    }
    /// Await fresh ordinary provisioning on the same interface name/ifindex.
    /// Association remains an explicit new request with fresh credentials.
    /// Poll from normal executor context: this waits on another scheduler
    /// worker and cannot be bridged with `block_on` or `block_on_spin`.
    pub async fn resume(self) -> Result<(), DevicePmError> {
        self.control.request_resume();
        let deadline = Deadline::after_ms(30_000);
        loop {
            match self.control.phase() {
                Phase::Resumed => return Ok(()),
                Phase::Failed => return Err(self.control.error()),
                _ if deadline.expired() => return Err(DevicePmError::Busy),
                _ => pause().await,
            }
        }
    }
}
impl Drop for RuntimeIdle {
    fn drop(&mut self) {
        self.control.request_resume();
    }
}
async fn pause() {
    narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
}
/// Enter native IPS on an actual unassociated passive C21/C22 station.
/// Busy/unsupported paths issue no card-off operation. A failed hardware
/// retirement/power/identity transition quarantines that exact function.
/// Poll from normal executor context; neither `block_on` variant drives the
/// background worker on which this Future depends.
pub async fn idle_function(address: BusAddr) -> Result<RuntimeIdle, DevicePmError> {
    let owner = super::functions::get(address).ok_or(DevicePmError::Busy)?;
    if owner.firmware.is_none() && owner.sibling.is_none() {
        return Err(DevicePmError::NotImplemented);
    }
    let control = Control::new();
    let idle = RuntimeIdle::new(control.clone());
    narf_scheduler::spawn(system_pm_worker::run(
        super::system_pm_native::Native::idle(owner),
        control,
    ));
    // Construct the rollback guard before the first await. The uncancelled
    // worker, rather than this foreground Future, owns every hardware step.
    let deadline = Deadline::after_ms(10_000);
    loop {
        match idle.control.phase() {
            Phase::Suspended => return Ok(idle),
            Phase::Failed => return Err(idle.control.error()),
            _ if deadline.expired() => return Err(DevicePmError::Busy),
            _ => pause().await,
        }
    }
}
