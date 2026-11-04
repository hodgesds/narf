// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192EU production admission: after the owner reaches `RadioReady`
//! (`rtl8xxxu_probe` → `rtl8xxxu_init_device`), the signed `N92P` record,
//! the signed deployment regulatory policy and the network authority must
//! all be present before any station capability exists. Missing assets keep
//! the radio unadmitted and retry; invalid/unsigned assets are terminal.
use super::firmware_transport::{ControlIo, Owner as Firmware, Stage};
use super::rtl8192e_policy::{Calibration, Error as PolicyError, Permission};
use super::rtl8192e_radio::Width;
use super::service_runtime::Error;
use alloc::sync::Arc;
use narf_firmware::FirmwareError;

/// The initial operating channel, as the RTL8188EU station starts.
pub const INITIAL_PRIMARY: u8 = 1;
pub const INITIAL_WIDTH: Width = Width::Ht20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Ready,
    PendingAssets,
}

/// Same retry/terminal split as the RTL8188EU `classify_attach_admission`.
pub(super) fn classify(
    has_net_authority: bool,
    has_loader_authority: bool,
    domain: &Result<narf_wireless::reg::RegulatoryDomain, narf_wireless::reg::policy::Error>,
    record: &Result<Calibration, PolicyError>,
) -> Result<Admission, Error> {
    let domain = match domain {
        Ok(_) => true,
        Err(narf_wireless::reg::policy::Error::Firmware(FirmwareError::NotFound)) => false,
        Err(narf_wireless::reg::policy::Error::Authority) if !has_loader_authority => false,
        Err(_) => return Err(Error::Profile),
    };
    let record = match record {
        Ok(_) => true,
        Err(PolicyError::Firmware(FirmwareError::NotFound)) => false,
        Err(PolicyError::Firmware(FirmwareError::AuthorityRevoked)) if !has_loader_authority => {
            false
        }
        Err(_) => return Err(Error::Profile),
    };
    if has_net_authority && domain && record {
        Ok(Admission::Ready)
    } else {
        Ok(Admission::PendingAssets)
    }
}

/// Everything the 8192E station needs from deployment: the exact-device
/// record, the authenticated domain and the initial channel permission.
pub struct Admitted {
    pub record: Calibration,
    pub domain: narf_wireless::reg::RegulatoryDomain,
    pub permission: Permission,
}

impl core::fmt::Debug for Admitted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8192euAdmitted")
            .field("record", &self.record)
            .field("country", &self.domain.country_code)
            .field("permission", &self.permission)
            .finish()
    }
}

/// One admission attempt over supplied inputs (production and fixtures).
pub(super) fn admit<I: ControlIo>(
    firmware: &Firmware<I>,
    domain: narf_wireless::reg::RegulatoryDomain,
    record: Calibration,
) -> Result<Admitted, Error> {
    let factory = firmware.factory_8192e().ok_or(Error::State)?;
    let (vid, pid) = firmware.usb_identity().ok_or(Error::State)?;
    if firmware.status().stage != Stage::RadioReady || firmware.radio_8192e().is_none() {
        return Err(Error::State);
    }
    let permission = record
        .permission(&domain, INITIAL_PRIMARY, INITIAL_WIDTH)
        .map_err(|_| Error::Profile)?;
    permission
        .check(&factory, vid, pid, INITIAL_PRIMARY, INITIAL_WIDTH)
        .map_err(|_| Error::Profile)?;
    Ok(Admitted {
        record,
        domain,
        permission,
    })
}

/// Production gate: poll the registry until the record and policy exist.
/// No station or netdev exists before this returns `Ok`.
pub async fn wait_admit<I: ControlIo>(firmware: Arc<Firmware<I>>) -> Result<Admitted, Error> {
    loop {
        if firmware.status().stage != Stage::RadioReady || firmware.radio_8192e().is_none() {
            return Err(Error::State);
        }
        let factory = firmware.factory_8192e().ok_or(Error::State)?;
        let (vid, pid) = firmware.usb_identity().ok_or(Error::State)?;
        let has_loader = narf_firmware::trusted_loader_authority().is_some();
        let has_net = narf_net::trusted_net_authority().is_some();
        // A fresh signed deployment artifact per attempt (as RTL8188EU).
        let domain = narf_wireless::reg::policy::load();
        let record = Calibration::load_registered(&factory, vid, pid);
        match classify(has_net, has_loader, &domain, &record)? {
            Admission::Ready => {
                let (Ok(domain), Ok(record)) = (domain, record) else {
                    return Err(Error::State);
                };
                return admit(&firmware, domain, record);
            }
            Admission::PendingAssets => {
                narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(500_000_000)).await;
            }
        }
    }
}

impl<I: ControlIo> Firmware<I> {
    /// `rtl8xxxu_config` `IEEE80211_CONF_CHANGE_CHANNEL`:
    /// `rtl8192e_set_tx_power(primary, ht40)` then
    /// `rtl8xxxu_gen2_config_channel`, only for the exact channel/width the
    /// signed permission qualifies for this retained device. Returns the
    /// admitted RA mask. A mismatch is refused before any transfer.
    pub(super) async fn tune_8192e(
        &self,
        permission: &Permission,
        primary: u8,
        width: Width,
    ) -> Result<u32, super::firmware_transport::Error> {
        use super::firmware_transport::Error as FwError;
        let factory = self.factory_8192e().ok_or(FwError::RuntimeState)?;
        let (vid, pid) = self.usb_identity().ok_or(FwError::RuntimeState)?;
        if self.status().stage != Stage::RadioReady {
            return Err(FwError::RuntimeState);
        }
        let admitted = permission
            .check(&factory, vid, pid, primary, width)
            .map_err(|_| FwError::RuntimeState)?;
        let ht40 = matches!(width, Width::Ht40Above | Width::Ht40Below);
        super::rtl8192e_phy::set_tx_power(self, &factory, primary, ht40).await?;
        super::rtl8192e_radio::config_channel(self, primary, width).await?;
        Ok(admitted)
    }

    /// `rtl8xxxu_start` RF half: `rtl8192e_enable_rf`, then the admitted
    /// initial channel. MAC TX/RX gates belong to the station owner.
    pub(super) async fn start_8192e(
        &self,
        permission: &Permission,
    ) -> Result<u32, super::firmware_transport::Error> {
        if self.status().stage != Stage::RadioReady {
            return Err(super::firmware_transport::Error::RuntimeState);
        }
        super::rtl8192e_power::enable_rf(self).await?;
        self.tune_8192e(permission, permission.primary(), permission.width())
            .await
    }
}

#[cfg(feature = "kernel-test")]
#[path = "rtl8192e_admission_tests.rs"]
mod tests;
