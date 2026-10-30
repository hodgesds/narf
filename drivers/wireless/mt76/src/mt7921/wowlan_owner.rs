//! Retained public-owner WoW entry points over the concrete transport.
use super::*;
use narf_power::system_pm::SystemSleepState;
use narf_wireless::{GtkRekeyData, WowlanConfig};

/// Query actual endpoint/firmware-owned ACPI routing under current caps.
/// This neither enables PME/GPE nor makes a capability from PCI identity.
pub fn boot_wake_route_available() -> Result<bool, Error> {
    let owner = BOOT_OWNER.try_lock().ok_or(Error::Busy)?;
    owner
        .as_ref()
        .ok_or(Error::DeviceGone)?
        .wake_route_available()
}

/// A delegated nl80211 rekey request can only confirm the current RSNA.
/// The native owner reads its authenticated keys again when suspend starts.
pub fn boot_validate_rekey_data(data: &GtkRekeyData) -> Result<(), Error> {
    let owner = BOOT_OWNER.try_lock().ok_or(Error::Busy)?;
    owner
        .as_ref()
        .ok_or(Error::DeviceGone)?
        .validate_rekey_data(data)
}

/// The existing retained work slot owns the complete handoff across caller
/// cancellation; it never leaves DMA/PMCSR cleanup in a dropped waiter.
pub async fn suspend_boot_wowlan(
    config: WowlanConfig,
    target: SystemSleepState,
) -> Result<(), Error> {
    retained_owner_work(false, move |mut transport| {
        alloc::boxed::Box::pin(async move {
            let result = transport.suspend_wowlan(&config, target).await;
            (transport, result)
        })
    })
    .await
}
