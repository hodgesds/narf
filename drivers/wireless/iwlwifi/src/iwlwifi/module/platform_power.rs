//! BIOS power preparation, module build (`runtime_mld_power.rs` built in).
//!
//! Built in, the MLD owner reads the platform's optional ACPI WRDS/EWRD/WGDS
//! and PPAG objects (through the delegated power owner) and SMBIOS vendor
//! approval, then publishes PPAG, SAR and geographic SAR before the first
//! emission. Linux treats every one of those tables as optional: absent
//! tables publish nothing and the firmware keeps its own limits. A module has
//! no KABI to evaluate the device's ACPI objects, so the module build takes
//! that absent-tables path: preparation succeeds without publishing a
//! command, once per firmware generation, exactly as built in on a platform
//! without the tables.
use super::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Phase {
    #[default]
    Initial,
    Ready,
}

#[derive(Default, Debug)]
pub(super) struct State {
    phase: Phase,
}
impl Hardware {
    pub(in crate::iwlwifi) fn current_policy_domain(
        &self,
    ) -> Result<alloc::sync::Arc<narf_wireless::reg::RegulatoryDomain>, &'static str> {
        self.rf_policy
            .as_ref()
            .ok_or("Intel power update has no current RF authority")?
            .domain()
    }
    pub(in crate::iwlwifi) async fn ensure_platform_power(&mut self) -> Result<(), &'static str> {
        if self.platform_power.phase == Phase::Ready {
            return Ok(());
        }
        if self.format == rx_rfh::CompletionFormat::Qu {
            return Err("MLD platform owner cannot replace Gen2 signed power preparation");
        }
        if self.failed {
            return Err("MLD platform power is already applied, pending or failed");
        }
        self.source_fence()?.invoke(|| Ok(()))?;
        self.platform_power.phase = Phase::Ready;
        Ok(())
    }
}
