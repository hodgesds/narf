//! Roles the module build does not carry, as uninhabited types.
//!
//! The shared station code (`connection`, `mld_policy`, `runtime`) names the
//! P2P-client role and the Gen2 MVM power owners in fields, parameters and
//! match arms. Built in, those are live owners. The module carries neither, so
//! here every such type is uninhabited: a value can never exist, every field
//! of that type is always `None`, and each method body is an empty match.
//! The shared code is the same text in both builds, and the compiler proves
//! the role paths unreachable in the `.ko` instead of a runtime flag.
//!
//! Where the station path consults a role on every operation (TX publication
//! fences, power servicing, RX epoch selection) the module answers exactly
//! what the built-in answers with no such role installed.

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_wireless::reg::RegulatoryDomain;

use super::super::native_band::Channel;
use super::super::runtime::Hardware;
use super::kernel::narf_net::native_emission::Lifetime;

/// No value: the role does not exist in the module build.
#[derive(Clone, Copy, Debug)]
pub(in crate::iwlwifi) enum Never {}

/// The P2P client role (`p2p_client.rs` built in).
pub(in crate::iwlwifi) mod p2p_client {
    use super::*;

    /// Built in: a native NoA/CTWindow update awaits its receipt.
    pub(in crate::iwlwifi) const UPDATE_REQUIRED: &str =
        "P2P client native CTWindow receipt required";

    /// A P2P client association plan. Never constructed in the module.
    pub(in crate::iwlwifi) struct Plan {
        pub channel: Channel,
        pub elements: Vec<u8>,
        never: Never,
    }
    impl Plan {
        pub fn binding(&self) -> [u8; 32] {
            match self.never {}
        }
        pub fn response(&self, _ies: &[u8]) -> Result<(), &'static str> {
            match self.never {}
        }
    }

    /// The live P2P client owner. Never constructed in the module.
    pub(in crate::iwlwifi) struct Native {
        pub plan: Plan,
    }
    impl Native {
        pub fn current(&self) -> Result<(), &'static str> {
            match self.plan.never {}
        }
        pub fn retire(&self) {
            match self.plan.never {}
        }
        pub fn pending(&self) -> bool {
            match self.plan.never {}
        }
        pub fn desired(&self) -> u32 {
            match self.plan.never {}
        }
        pub fn associated(&self, _aid: u16) -> Result<(), &'static str> {
            match self.plan.never {}
        }
        pub fn commit_window(&self, _value: u32, _probe: bool) -> Result<(), &'static str> {
            match self.plan.never {}
        }
        pub fn mac(
            &self,
            _action: u32,
            _aid: Option<u16>,
            _window: u32,
        ) -> Result<[u8; 52], &'static str> {
            match self.plan.never {}
        }
    }
}

/// The P2P GO host-policy check (`p2p_go::host_allows` built in). The module
/// has no P2P role, so P2P is never permitted on any channel.
pub(in crate::iwlwifi) mod p2p_go {
    use super::*;
    pub(in crate::iwlwifi) fn host_allows(_domain: &RegulatoryDomain, _channel: Channel) -> bool {
        false
    }
}

/// The Gen2 MVM power owners (`mvm_boot` built in): the module runs the MLD
/// (Sc) profile only.
pub(in crate::iwlwifi) mod mvm_boot {
    use super::*;

    pub(in crate::iwlwifi) struct ApPower(Never);
    impl ApPower {
        pub fn check_role(&self, _go: bool) -> Result<(), &'static str> {
            match self.0 {}
        }
        pub fn check(&self, _domain: &RegulatoryDomain) -> Result<(), &'static str> {
            match self.0 {}
        }
        pub fn ready(&self) -> Result<(), &'static str> {
            match self.0 {}
        }
        pub fn radiated_dbm(&self) -> Result<i8, &'static str> {
            match self.0 {}
        }
    }

    pub(in crate::iwlwifi) struct P2pPower(Never);
    impl P2pPower {
        pub fn check(&self, _domain: &RegulatoryDomain) -> Result<(), &'static str> {
            match self.0 {}
        }
        pub fn ready(&self) -> Result<(), &'static str> {
            match self.0 {}
        }
        pub fn radiated_dbm(&self) -> Result<i8, &'static str> {
            match self.0 {}
        }
    }

    pub(in crate::iwlwifi) struct PowerFence(Never);
    impl PowerFence {
        pub fn invoke<T>(
            &self,
            _domain: &RegulatoryDomain,
            _operation: impl FnOnce() -> Result<T, &'static str>,
        ) -> Result<T, &'static str> {
            match self.0 {}
        }
        pub fn radiated_dbm(&self) -> Result<i8, &'static str> {
            match self.0 {}
        }
    }
}

/// The transport's role hooks (`runtime_ap.rs`, `runtime_p2p.rs`,
/// `runtime_p2p_client.rs` built in), as the built-in answers them with no
/// AP, GO, P2P device or P2P client owner installed.
impl Hardware {
    /// No API77 AP consumer is selected.
    pub(in crate::iwlwifi) fn ap_legacy_selected(&self) -> bool {
        false
    }
    /// No P2P session holds a closing Gen2 receive prefix.
    pub(in crate::iwlwifi) fn p2p_gen2_prefix(&self) -> bool {
        false
    }
    /// No P2P session is started.
    pub(in crate::iwlwifi) fn p2p_started(&self) -> bool {
        false
    }
    /// No P2P session gates TX publication.
    pub(in crate::iwlwifi) fn check_p2p_tx_publication(&mut self) -> Result<(), &'static str> {
        Ok(())
    }
    /// No P2P client gates TX publication.
    pub(in crate::iwlwifi) fn check_client_tx_publication(&mut self) -> Result<(), &'static str> {
        Ok(())
    }
    /// No P2P client NoA to service.
    pub(in crate::iwlwifi) async fn service_p2p_client(&mut self) -> Result<(), &'static str> {
        Ok(())
    }
    /// No GO rewrites probe responses.
    pub(in crate::iwlwifi) fn project_go_probe(
        &mut self,
        _frame: &[u8],
    ) -> Result<Option<Vec<u8>>, &'static str> {
        Ok(None)
    }
    /// A P2P client plan cannot exist in the module build.
    pub(in crate::iwlwifi) fn install_p2p_client(
        &mut self,
        plan: p2p_client::Plan,
        role: Lifetime,
    ) -> Result<Arc<p2p_client::Native>, &'static str> {
        let _ = plan;
        match role {}
    }
    pub(in crate::iwlwifi) async fn prepare_p2p_client(&mut self) -> Result<(), &'static str> {
        Err("P2P client is built-in only")
    }
    pub(in crate::iwlwifi) async fn restore_p2p_client_default(
        &mut self,
    ) -> Result<(), &'static str> {
        Ok(())
    }
    /// Further MLD links are not requested by the module build (the `WIFI`
    /// v2 `CONNECT` carries no MLO request), so no further firmware link or
    /// station id is ever allocated.
    pub(in crate::iwlwifi) fn mld_fw_ids(
        &self,
    ) -> Result<super::super::sc_mlo::FwIds, &'static str> {
        Err("further MLD links are built-in only")
    }
    /// The association link's PHY only (no P2P DEVICE session holds PHY1).
    pub(in crate::iwlwifi) fn mld_phy_ids(&self) -> super::super::sc_mlo::PhyIds {
        super::super::sc_mlo::PhyIds::station()
    }
}
