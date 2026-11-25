//! `narf_wireless` for the module: the kernel-free protocol crate, plus the
//! kernel-resident items the station shell names.
//!
//! - **Regulatory database** ([`reg::db`]): built in, the driver reads the
//!   kernel's installed domain and refuses signed per-board records whose
//!   country it does not match. The module reads that same domain through
//!   `narf_wireless_regdomain` (an NRGD v1 record, decoded by the shared
//!   `narf_wireless::reg::parse_domain_record`) once per probe; the module
//!   cannot install or change it.
//! - **`WirelessNetIface`**: the station shell's cfg80211-shaped surface.
//!   Built in, nl80211 calls it; in the module `iface_module.rs` does, for
//!   the `WIFI` family host's events.
//! - **nl80211 / wiphy registry**: the shell's disconnect report and
//!   withdrawal land on the module netdev.

pub use ::narf_wireless::*;

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::narf_net::Interface;

/// Regulatory rules (kernel-free) and the module's view of the database.
pub mod reg {
    pub use ::narf_wireless::reg::*;

    /// The kernel's installed regulatory domain, as the module sees it.
    pub mod db {
        use alloc::sync::Arc;

        use super::RegulatoryDomain;
        use crate::rtw88::platform::narf_lib::sync::IrqSafeSpinLock;

        unsafe extern "C" {
            fn narf_wireless_regdomain(buf: *mut u8, len: usize, out_len: *mut usize) -> i32;
        }

        /// Why no domain is available.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Error {
            /// The kernel has no installed domain or refused the read.
            Unavailable,
            /// The record did not decode.
            Format,
        }

        /// The installed domain (`get_domain` / `snapshot`), fetched by
        /// [`refresh`].
        static DOMAIN: IrqSafeSpinLock<Option<Arc<RegulatoryDomain>>> = IrqSafeSpinLock::new(None);

        /// The domain database type the built-in signatures name. Never
        /// constructed in the module (only the kernel-test models build one).
        #[derive(Debug)]
        pub enum Database {}

        /// Read the kernel's installed domain again.
        pub fn refresh() -> Result<Arc<RegulatoryDomain>, Error> {
            let mut buf = alloc::vec![0u8; 12 + 64 * 16];
            let mut len = 0usize;
            // SAFETY: `buf` names `buf.len()` writable bytes; `len` is a
            // live local.
            let rc = unsafe { narf_wireless_regdomain(buf.as_mut_ptr(), buf.len(), &mut len) };
            if rc != 0 || len > buf.len() {
                return Err(Error::Unavailable);
            }
            let domain =
                Arc::new(super::parse_domain_record(&buf[..len]).map_err(|_| Error::Format)?);
            *DOMAIN.lock() = Some(domain.clone());
            Ok(domain)
        }

        pub fn snapshot() -> Option<Arc<RegulatoryDomain>> {
            DOMAIN.lock().clone()
        }

        pub fn get_domain() -> Option<RegulatoryDomain> {
            snapshot().map(|d| d.as_ref().clone())
        }

        /// The installed domain; the module cannot bootstrap one, so a
        /// kernel without one stays without one.
        pub fn ensure_domain() -> Result<RegulatoryDomain, Error> {
            if let Some(domain) = get_domain() {
                return Ok(domain);
            }
            refresh().map(|d| d.as_ref().clone())
        }
    }
}

/// The station shell's cfg80211 surface (the kernel trait's methods the
/// shell implements, without defaults).
#[async_trait::async_trait]
pub trait WirelessNetIface: Interface {
    fn rts_threshold(&self) -> Option<u32>;
    fn set_rts_threshold(&self, threshold: u32) -> Result<(), i32>;
    fn supports_handshake_offload(&self) -> bool;
    fn reports_disconnect_events(&self) -> bool;
    fn supports_scan_random_mac(&self) -> bool;
    fn supports_scan_dwell(&self) -> bool;
    fn max_scan_ssids(&self) -> u8;
    fn max_scan_ie_len(&self) -> u16;
    fn wowlan_support(&self) -> Option<WowlanSupport>;
    fn set_wowlan(&self, config: Option<WowlanConfig>) -> Result<(), i32>;
    fn wowlan_config(&self) -> Option<WowlanConfig>;
    fn power_save_default(&self) -> Option<bool>;
    fn set_power_save(&self, enabled: bool) -> Result<(), i32>;
    fn connected_bssid(&self) -> Option<[u8; 6]>;
    fn cipher_suites(&self) -> &'static [u32];
    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>>;
    fn get_wireless_info(&self) -> WirelessIfaceInfo;
    fn phy_capabilities(&self, band_mhz: u32) -> Option<iface::PhyCapabilities>;
    async fn scan(&self, req: ScanRequest) -> Result<Vec<BssInfo>, WirelessError>;
    async fn associate(&self, req: AssociateRequest) -> Result<(), WirelessError>;
    async fn disassociate(&self) -> Result<(), WirelessError>;
    async fn set_config(&self, cfg: WirelessConfig) -> Result<(), WirelessError>;
}

/// nl80211 notifications, delivered as `WIFI` host reports.
pub mod nl80211 {
    /// The station lost its association (`cfg80211_disconnected`).
    pub fn notify_disconnect(name: &str, reason: u16, from_ap: bool) {
        crate::rtw88::iface_module::disconnected(name, reason, from_ap);
    }
}

/// The wiphy registry: the module netdev is the one registration.
pub mod registry {
    pub fn unregister(name: &str) {
        crate::rtw88::iface_module::withdraw(name);
    }
}
