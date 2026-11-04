//! Boot-lifetime exclusion between the GuC owner and legacy production glue.
//!
//! Neither owner has a detach protocol for its exposed GGTT/engine state.
//! Claims therefore survive failed startup, loss, reset and dropped callers.
//! The registry lock serializes claims only; no MMIO or wait runs under it.

use alloc::vec::Vec;
use narf_bus::{bar::MmioRegion, BusAddr};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClaimError {
    Invalid,
    Busy,
    Allocation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Bar {
    start: u64,
    end: u64,
}
impl Bar {
    fn new(bar: MmioRegion) -> Result<Self, ClaimError> {
        let start = bar.phys.raw();
        let end = start.checked_add(bar.len).ok_or(ClaimError::Invalid)?;
        if start == 0 || start % 4096 != 0 || bar.len == 0 {
            return Err(ClaimError::Invalid);
        }
        Ok(Self { start, end })
    }
    fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

#[derive(Debug)]
enum Owner {
    Legacy,
    GuC,
}
#[derive(Debug)]
struct Entry {
    function: BusAddr,
    bar: Bar,
    owner: Owner,
}
#[derive(Debug)]
struct Registry(Vec<Entry>);
impl Registry {
    const fn new() -> Self {
        Self(Vec::new())
    }
    fn legacy(&mut self, function: BusAddr, bar: MmioRegion) -> Result<LegacyLease, ClaimError> {
        if !matches!(function, BusAddr::Pcie(_)) {
            return Err(ClaimError::Invalid);
        }
        let key = Bar::new(bar)?;
        for entry in &self.0 {
            if entry.function == function || entry.bar.overlaps(key) {
                return if entry.function == function
                    && entry.bar == key
                    && matches!(entry.owner, Owner::Legacy)
                {
                    Ok(LegacyLease { function, bar: key })
                } else {
                    Err(ClaimError::Busy)
                };
            }
        }
        self.0.try_reserve(1).map_err(|_| ClaimError::Allocation)?;
        self.0.push(Entry {
            function,
            bar: key,
            owner: Owner::Legacy,
        });
        Ok(LegacyLease { function, bar: key })
    }
    fn guc(&mut self, function: BusAddr, bar: MmioRegion) -> Result<(), ClaimError> {
        if !matches!(function, BusAddr::Pcie(_)) {
            return Err(ClaimError::Invalid);
        }
        let key = Bar::new(bar)?;
        if self
            .0
            .iter()
            .any(|entry| entry.function == function || entry.bar.overlaps(key))
        {
            return Err(ClaimError::Busy);
        }
        self.0.try_reserve(1).map_err(|_| ClaimError::Allocation)?;
        self.0.push(Entry {
            function,
            bar: key,
            owner: Owner::GuC,
        });
        Ok(())
    }
}

static OWNERS: IrqSafeSpinLock<Registry> = IrqSafeSpinLock::new(Registry::new());

/// An unforgeable legacy attachment token. Its persistent registry entry is
/// the exclusion proof; dropping this token does not release hardware state.
#[derive(Debug)]
pub(crate) struct LegacyLease {
    function: BusAddr,
    bar: Bar,
}
impl LegacyLease {
    pub(crate) fn matches_function(&self, function: BusAddr, bar: MmioRegion) -> bool {
        self.function == function && self.matches(bar)
    }
    pub(crate) fn matches(&self, bar: MmioRegion) -> bool {
        Bar::new(bar) == Ok(self.bar)
    }
}

pub(crate) fn claim_legacy(function: BusAddr, bar: MmioRegion) -> Result<LegacyLease, ClaimError> {
    OWNERS.lock().legacy(function, bar)
}

/// Reserve before staging or advertising the GuC owner, never by readiness.
/// A failed owner keeps this claim: reset cannot make legacy state coexist.
pub(crate) fn claim_guc(function: BusAddr, bar: MmioRegion) -> Result<(), ClaimError> {
    OWNERS.lock().guc(function, bar)
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_bus::PcieAddr;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn bar(start: u64) -> MmioRegion {
        MmioRegion {
            phys: narf_memory::PhysAddr::new(start),
            virt: start,
            len: 16 * 1024 * 1024,
            kind: narf_bus::bar::BarKind::Mmio64 {
                prefetchable: false,
            },
        }
    }
    fn function(device: u8) -> BusAddr {
        BusAddr::Pcie(PcieAddr::new(0, 0, device, 0))
    }

    fn smoke_gt_ownership_claim_order_lifetime_alias_and_independent_cards() -> TestResult {
        let a = bar(0x80000000);
        let b = bar(0x90000000);
        let mut owners = Registry::new();
        {
            let lease = owners.legacy(function(2), a).unwrap();
            assert!(lease.matches(a));
            assert!(!lease.matches(b));
            assert!(!lease.matches_function(function(3), a));
            assert!(owners.legacy(function(2), a).is_ok());
            assert!(matches!(
                owners.legacy(function(2), b),
                Err(ClaimError::Busy)
            ));
            assert!(matches!(
                owners.legacy(function(3), a),
                Err(ClaimError::Busy)
            ));
            assert_eq!(owners.guc(function(2), a), Err(ClaimError::Busy));
            assert_eq!(owners.guc(function(2), b), Err(ClaimError::Busy));
        }
        assert_eq!(owners.guc(function(2), a), Err(ClaimError::Busy));
        assert_eq!(owners.guc(function(3), b), Ok(()));
        assert!(matches!(
            owners.legacy(function(3), b),
            Err(ClaimError::Busy)
        ));
        assert_eq!(owners.guc(function(3), b), Err(ClaimError::Busy));
        assert_eq!(
            owners.guc(function(3), bar(0xa0000000)),
            Err(ClaimError::Busy)
        );
        assert_eq!(owners.guc(function(4), b), Err(ClaimError::Busy));
        assert_eq!(
            owners.guc(function(4), bar(0x90800000)),
            Err(ClaimError::Busy)
        );
        assert_eq!(owners.guc(function(4), bar(0xa0000000)), Ok(()));
        assert!(owners.legacy(function(5), bar(0xb0000000)).is_ok());
        assert!(matches!(
            owners.legacy(function(6), bar(0)),
            Err(ClaimError::Invalid)
        ));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gt",
        smoke_gt_ownership_claim_order_lifetime_alias_and_independent_cards
    );

    fn smoke_gt_ownership_public_legacy_wrappers_refuse_without_controller() -> TestResult {
        // Never create a fake physical controller or touch a real GPU in a
        // fixture. Both actual public wrappers must refuse before attachment.
        if crate::intel_gpu::with_controller(|_| ()).is_none() {
            assert!(matches!(
                crate::intel_gpu_rcs::submit_dwords(&[0x05000000]),
                Err(crate::intel_gpu_rcs::SubmitError::NoEngine
                    | crate::intel_gpu_rcs::SubmitError::Suspended)
            ));
            assert!(matches!(
                crate::intel_gpu_media::submit_media_dwords(
                    crate::intel_gpu_media::MediaEngineId::Vcs0,
                    &[0x05000000],
                ),
                Err(crate::intel_gpu_media::MediaError::Submit(
                    crate::intel_gpu_rcs::SubmitError::NoEngine
                ))
            ));
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gt",
        smoke_gt_ownership_public_legacy_wrappers_refuse_without_controller
    );
}
