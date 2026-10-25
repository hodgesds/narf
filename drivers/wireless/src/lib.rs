#![no_std]

extern crate alloc;

pub mod ath10k;
pub mod ath11k;
pub mod ath9k;
pub mod brcmfmac;
pub mod cyw43439;
mod firmware_asset;
pub mod iwlwifi;
mod qualcomm_pci;
mod qualcomm_regulatory;
pub mod rtl8xxxu;
pub mod rtlwifi;
pub mod rtw88;
pub mod rtw89;

// MediaTek CONNAC2 Wi-Fi (MT7921/MT7922/MT7961/MT7920). Promoted out of the
// former `src/mt7921/` module into the standalone dual-build crate
// `narf-drivers-wireless-mt76` (see drivers/wireless/mt76/). Re-exported here
// as `mt76` so existing `wireless::mt76::…` references keep resolving; the
// former dead MT7615 `mt76.rs` stub was deleted.
pub use narf_drivers_wireless_mt76 as mt76;

#[cfg(feature = "kernel-test")]
mod e2e_tests;

use narf_init::{InitResult, Stage};

pub fn register_initcalls() {
    // Register wireless drivers with the bus dispatcher.
    narf_init::register(Stage::Subsys, "iwlwifi", || {
        iwlwifi::register();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "mt76", || {
        mt76::register();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "cyw43439", || {
        cyw43439::register();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "rtl8xxxu", || {
        rtl8xxxu::register();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "rtlwifi", || {
        rtlwifi::register();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "rtw88", || {
        rtw88::register();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "rtw89", || {
        rtw89::register();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "brcmfmac", || {
        brcmfmac::register();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "ath11k", || {
        ath11k::register();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "ath10k", || {
        ath10k::register();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "ath9k", || {
        ath9k::register();
        InitResult::Ok
    });
}
