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

/// Async system-PM bridge for the mt76 crate (`mt7921_pci_suspend` /
/// `mt7921_pci_resume` firmware exchanges run before/after the
/// interrupt-gated device fan-out).
struct Mt76SystemPm;

impl narf_power::system_pm::AsyncSystemPm for Mt76SystemPm {
    fn prepare_suspend<'a>(&'a self) -> narf_power::system_pm::SystemPmFuture<'a> {
        alloc::boxed::Box::pin(async {
            mt76::iface::system_prepare_suspend()
                .await
                .map_err(|error| match error {
                    narf_wireless::WirelessError::Busy | narf_wireless::WirelessError::Timeout => {
                        narf_power::device_pm::DevicePmError::Busy
                    }
                    _ => narf_power::device_pm::DevicePmError::DriverError,
                })
        })
    }

    fn resume_from_suspend<'a>(&'a self) -> narf_power::system_pm::SystemPmFuture<'a> {
        alloc::boxed::Box::pin(async {
            mt76::iface::system_resume()
                .await
                .map_err(|_| narf_power::device_pm::DevicePmError::DriverError)
        })
    }
}

pub fn register_initcalls() {
    // Register wireless drivers with the bus dispatcher.
    narf_init::register(Stage::Subsys, "iwlwifi", || {
        iwlwifi::register();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "mt76", || {
        mt76::register();
        // The mt76 crate does not depend on narf-power; its async system-PM
        // phases are bridged here (Linux mt7921_pm_ops).
        narf_power::system_pm::register_async_system_pm(
            "mt76",
            alloc::sync::Arc::new(Mt76SystemPm),
        );
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
    // ath11k AHB (IPQ8074/6018/5018, WCN6750): bind the DT nodes the
    // Subsys initcall's `register_dt_driver` claims.
    narf_init::register(Stage::Device, "ath11k-ahb", || {
        if narf_bus::probe_all_dt() == 0 {
            InitResult::NotPresent
        } else {
            InitResult::Ok
        }
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
