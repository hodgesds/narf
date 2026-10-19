//! Serialized fault recovery receipts, retained by the platform across awaits.
use super::*;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

/// Dropping this receipt leaves the monitor Recovering and retirement blocked.
pub(crate) struct Recovery {
    generation: u64,
    mark: u64,
    retired: u8,
    handles: Vec<dispatch::Handle>,
}
impl Recovery {
    /// # Safety
    /// This ring has reset and passed its new fence test under the platform
    /// owner, while every client ledger remains frozen. No replay has begun.
    pub(crate) unsafe fn retired(&mut self, ring: usize) {
        assert!(ring < self.handles.len() && self.retired & (1 << ring) == 0);
        self.retired |= 1 << ring;
    }
}
pub(crate) async fn recovery_needed() -> bool {
    let slot = SERVICE.lock().await;
    slot.as_ref()
        .is_some_and(|s| s.faults.status().state == faults::State::Contained)
        && dispatch::summary().terminal.is_none()
        && !HALTED.load(Ordering::Acquire)
}
fn drain_before_rearm(service: &mut Service) -> Result<(), ih::Error> {
    // Finite batches only. A continuing producer is not a quiescence proof.
    for _ in 0..8 {
        if !service.drain()? {
            return Ok(());
        }
    }
    Err(ih::Error::Busy)
}
/// # Safety
/// OWNER excludes submissions, reset and PM, and all client ledgers are
/// frozen before this await. They remain frozen after any error/cancellation.
pub(crate) async unsafe fn begin_recovery(
    media: Option<dispatch::Handle>,
) -> Result<Recovery, ih::Error> {
    let mut slot = SERVICE.lock().await;
    let service = slot.as_mut().ok_or(ih::Error::Busy)?;
    drain_before_rearm(service)?;
    let handles = service.kernel.map(|h| h.ok_or(ih::Error::Protocol));
    let mut handles = alloc::vec![handles[0]?, handles[1]?, handles[2]?];
    if let Some(handle) = media {
        handles.push(handle);
    }
    {
        let table = dispatch::TABLE.lock();
        table
            .recovery_owners(&handles)
            .map_err(|_| ih::Error::Protocol)?;
        let keys = KERNEL
            .into_iter()
            .chain(media.map(|_| dispatch::Key::Vcn { instance: 0 }));
        for (&h, key) in handles.iter().zip(keys) {
            if table
                .endpoint(h)
                .map_err(|_| ih::Error::Protocol)?
                .owner
                .key
                != key
            {
                return Err(ih::Error::Protocol);
            }
        }
    }
    let mark = service
        .faults
        .begin_recovery()
        .map_err(|_| ih::Error::Protocol)?;
    Ok(Recovery {
        generation: GENERATION.load(Ordering::Acquire),
        mark,
        retired: 0,
        handles,
    })
}
/// # Safety
/// All owned rings retired through new fence tests; all client and clear
/// submissions remain excluded under OWNER. Keep ledgers frozen until replay
/// has assigned every healthy job a new physical fence.
pub(crate) async unsafe fn finish_recovery(
    receipt: Recovery,
) -> Result<(faults::RecoveryScope, Option<dispatch::Handle>), ih::Error> {
    let mut slot = SERVICE.lock().await;
    if !(3..=4).contains(&receipt.handles.len())
        || receipt.retired != (1 << receipt.handles.len()) - 1
        || receipt.generation != GENERATION.load(Ordering::Acquire)
    {
        return Err(ih::Error::Protocol);
    }
    let service = slot.as_mut().ok_or(ih::Error::Busy)?;
    let result = (|| {
        drain_before_rearm(service)?;
        let found = service.faults.sweep().map_err(|_| ih::Error::Protocol)?;
        let mut table = dispatch::TABLE.lock();
        for (mm_hub, vmid) in [false, true].into_iter().zip(found) {
            if let Some(vmid) = vmid {
                table.latched(vmid, mm_hub);
            }
        }
        table
            .recovery_owners(&receipt.handles)
            .map_err(|_| ih::Error::Protocol)?;
        // SAFETY: receipt records all owned proven retirements, OWNER still
        // excludes submission; old vectors and both latches were captured.
        let scope =
            unsafe { service.faults.rearm(receipt.mark) }.map_err(|_| ih::Error::Protocol)?;
        let handles = table
            .reset_owners(receipt.handles)
            .map_err(|_| ih::Error::Protocol)?;
        service.kernel = core::array::from_fn(|i| Some(handles[i]));
        Ok((scope, handles.get(3).copied()))
    })();
    if result.is_ok() {
        BLOCKED.store(false, Ordering::Release);
    } else {
        service.stop(dispatch::Terminal::Interrupts(ih::Error::Protocol));
    }
    result
}
/// Replay failure after re-arm must close sources and retain every ledger.
pub(crate) async fn quarantine() {
    FAILED.store(true, Ordering::Release);
    BLOCKED.store(true, Ordering::Release);
    if let Some(service) = SERVICE.lock().await.as_mut() {
        service.stop(dispatch::Terminal::Interrupts(ih::Error::Protocol));
    }
}
