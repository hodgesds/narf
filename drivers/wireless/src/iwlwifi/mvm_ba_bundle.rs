//! Complete original API4 MPDUs enter sequence reorder as one item. Linux
//! rxmq.c forbids using a non-LAST A-MSDU's NSSN: it can already name a later
//! SN while native deaggregation still owns suffixes of this SN.
use super::super::super::scan_api::Mpdu;
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};

/// A station-wide bound includes partial, reordered and released raw copies.
/// Ordinary and nested packets share it; Reorder's duplicate/old-item drops
/// release storage through Raw::drop without a parallel accounting oracle.
pub(super) const MAX_RAW_BYTES: usize = 512 * 1024;
const MAX_AMSDU: usize = 3839;
const MAX_SUBFRAMES: usize = 128;
const PARTIAL_NS: u64 = 100_000_000;

pub(super) struct Raw {
    bytes: Vec<u8>,
    size: usize,
    budget: Arc<AtomicUsize>,
}
impl Raw {
    pub fn new(bytes: &[u8], budget: &Arc<AtomicUsize>) -> Result<Self, &'static str> {
        budget
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes.len())
                    .filter(|n| *n <= MAX_RAW_BYTES)
            })
            .map_err(|_| "MVM BA retained raw packet bound")?;
        Ok(Self {
            bytes: bytes.to_vec(),
            size: bytes.len(),
            budget: budget.clone(),
        })
    }
    pub fn into_bytes(mut self) -> Vec<u8> {
        core::mem::take(&mut self.bytes)
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl Drop for Raw {
    fn drop(&mut self) {
        self.budget.fetch_sub(self.size, Ordering::AcqRel);
    }
}

#[derive(Default)]
pub(super) struct Bundle(pub VecDeque<Raw>);
impl Bundle {
    pub fn one(raw: Raw) -> Self {
        let mut packets = VecDeque::new();
        packets.push_back(raw);
        Self(packets)
    }
}
pub(super) struct Partial {
    pub sn: u16,
    identity: (u8, u8, [u8; 8]),
    next: u8,
    extent: usize,
    deadline: u64,
    packets: Bundle,
}
impl Partial {
    #[cfg(any(test, feature = "kernel-test"))]
    pub fn model_expire(&mut self) {
        self.deadline = 0;
    }
    pub fn expired(&self, clock: u64) -> bool {
        clock >= self.deadline
    }
    pub fn passed(&self, head: u16) -> bool {
        let delta = head.wrapping_sub(self.sn) & 4095;
        delta != 0 && delta < 2048
    }
}

/// Accept only an explicit zero-index prefix in API4's SUBFRAME_IDX field.
/// rxmq.c::iwl_mvm_is_dup permits same-PN continuations only for increasing
/// indices of the same sequence; a suffix cannot establish completeness here.
/// One incomplete aggregate per TID/BAID is independent of other TIDs.
pub(super) fn capture(
    pending: &mut Option<Partial>,
    m: &Mpdu<'_>,
    raw: Raw,
    clock: u64,
) -> Option<Bundle> {
    let f = m.frame;
    let sn = u16::from_le_bytes([f[22], f[23]]) >> 4;
    let iv = if f[1] & 0x40 != 0 {
        <[u8; 8]>::try_from(f.get(26..34)?).ok()?
    } else {
        [0; 8]
    };
    let identity = (f[1], f[24], iv);
    if pending.as_ref().is_some_and(|p| {
        p.expired(clock) || p.sn != sn || p.identity != identity || p.next != m.amsdu_index
    }) {
        *pending = None;
    }
    if pending.is_none() {
        if m.amsdu_index != 0 {
            return None;
        }
        *pending = Some(Partial {
            sn,
            identity,
            next: 0,
            extent: 0,
            deadline: clock.saturating_add(PARTIAL_NS),
            packets: Bundle::default(),
        });
    }
    let p = pending.as_mut().unwrap();
    let Some(body) = m.body(26, if f[1] & 0x40 != 0 { 8 } else { 0 }) else {
        *pending = None;
        return None;
    };
    // API4 payload is LLC+MSDU. Restore only the length accounting of its
    // original 14-byte A-MSDU subheader; original bytes are never rewritten.
    let extent = body.len() + 14;
    let extent = if m.amsdu_last {
        extent
    } else {
        extent.next_multiple_of(4)
    };
    if p.packets.0.len() == MAX_SUBFRAMES
        || p.extent.checked_add(extent).is_none_or(|n| n > MAX_AMSDU)
        || !m.amsdu_last && m.amsdu_index == 127
    {
        *pending = None;
        return None;
    }
    p.extent += extent;
    p.packets.0.push_back(raw);
    p.next = p.next.saturating_add(1);
    if m.amsdu_last {
        Some(pending.take().unwrap().packets)
    } else {
        None
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::vec;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_mvm_nested_raw_budget_follows_reorder_duplicate_and_drop_ownership() -> TestResult {
        (|| {
            let budget = Arc::new(AtomicUsize::new(0));
            let bytes = vec![0; 256 * 1024];
            let mut reorder = narf_wireless::reorder::Reorder::new(4, 100)
                .map_err(|_| "native bundle budget reorder")?;
            reorder
                .advance(100, 0)
                .map_err(|_| "native bundle budget seed")?;
            reorder
                .push(103, 0, Bundle::one(Raw::new(&bytes, &budget)?))
                .map_err(|_| "native bundle budget insertion")?;
            reorder
                .push(103, 0, Bundle::one(Raw::new(&bytes, &budget)?))
                .map_err(|_| "native bundle budget duplicate")?;
            if budget.load(Ordering::Acquire) != 256 * 1024 {
                return Err("reorder duplicate retained phantom raw ownership");
            }
            let pending = Raw::new(&bytes, &budget)?;
            if Raw::new(&[1], &budget).is_ok() {
                return Err("station raw packet storage exceeded512KiB");
            }
            reorder.clear();
            drop(pending);
            if budget.load(Ordering::Acquire) != 0 {
                return Err("native bundle drop failed to release complete raw accounting");
            }
            Ok(())
        })()
        .map_or_else(TestResult::Fail, |()| TestResult::Pass)
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/gen2/nested",
        smoke_mvm_nested_raw_budget_follows_reorder_duplicate_and_drop_ownership
    );
}
