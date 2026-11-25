#![no_std]

extern crate alloc;

// Shared, driver-agnostic helpers promoted to `narf-drivers-wireless-core`.
// Re-exported at the crate root so the still-inlined drivers' existing
// `crate::firmware_asset` / `crate::future_heap` references keep resolving.
pub use narf_drivers_wireless_core::{firmware_asset, future_heap, watchdog_work};

// Qualcomm Atheros ath9k PCIe Wi-Fi. Promoted out of the former
// `src/ath9k{.rs,/}` module into the standalone dual-build crate
// `narf-drivers-wireless-ath9k` (see drivers/wireless/ath9k/). Its inner
// driver module is re-exported here as `ath9k` so existing `crate::ath9k::{…}`
// references and the `ath9k::register()` initcall keep resolving.
pub use narf_drivers_wireless_ath9k::ath9k;

// Qualcomm ath11k Wi-Fi 6. Promoted out of the former `src/ath11k/` module into
// the standalone dual-build crate `narf-drivers-wireless-ath11k` (see
// drivers/wireless/ath11k/). Its inner driver module is re-exported here as
// `ath11k` so existing `crate::ath11k::{…}` references (brcmfmac, cyw43439,
// rtlwifi, e2e_tests) and the `ath11k::register()` initcall keep resolving.
pub use narf_drivers_wireless_ath11k::ath11k;

// Qualcomm Atheros ath10k. Promoted out of the former `src/ath10k/` module into
// the standalone dual-build crate `narf-drivers-wireless-ath10k` (see
// drivers/wireless/ath10k/). Its inner driver module is re-exported here as
// `ath10k` so existing `crate::ath10k::{hw,register,…}` references keep
// resolving.
pub use narf_drivers_wireless_ath10k::ath10k;
// Broadcom/Infineon FullMAC Wi-Fi family. Promoted out of the former
// `src/{brcmfmac,cyw43439}/` modules into the standalone dual-build family
// crate `narf-drivers-wireless-brcm` (see drivers/wireless/brcm/). The two
// drivers are a bidirectionally-coupled Broadcom FullMAC pair, so they share a
// crate; their inner modules are re-exported here as `brcmfmac`/`cyw43439` so
// existing `crate::brcmfmac::{…}` / `crate::cyw43439::{…}` references (each
// other, e2e_tests, firmware_asset_tests) and the `brcmfmac::register()` /
// `cyw43439::register()` initcalls keep resolving.
pub use narf_drivers_wireless_brcm::{brcmfmac, cyw43439};
// Shared Atheros/Qualcomm code promoted to `narf-drivers-wireless-ath-core`.
// Re-exported at the crate root so the still-inlined ath9k/ath10k/ath11k
// drivers' `crate::qualcomm_pci` / `crate::qualcomm_regulatory` references
// keep resolving.
pub use narf_drivers_wireless_ath_core::{qualcomm_pci, qualcomm_regulatory};
// Legacy Realtek Wi-Fi family. Promoted out of the former
// `src/{rtl8xxxu,rtlwifi}/` modules into the standalone dual-build family
// crate `narf-drivers-wireless-rtl` (see drivers/wireless/rtl/). rtl8xxxu (USB)
// reuses rtlwifi's (PCIe) `wmm::priority`, so they share a crate; their inner
// modules are re-exported here as `rtl8xxxu`/`rtlwifi` so existing
// `crate::rtl8xxxu::{…}` / `crate::rtlwifi::{…}` references and the
// `rtl8xxxu::register()` / `rtlwifi::register()` initcalls keep resolving.
pub use narf_drivers_wireless_rtl::{rtl8xxxu, rtlwifi};

// MediaTek CONNAC2 Wi-Fi (MT7921/MT7922/MT7961/MT7920). Promoted out of the
// former `src/mt7921/` module into the standalone dual-build crate
// `narf-drivers-wireless-mt76` (see drivers/wireless/mt76/). Re-exported here
// as `mt76` so existing `wireless::mt76::…` references keep resolving; the
// former dead MT7615 `mt76.rs` stub was deleted.
pub use narf_drivers_wireless_mt76 as mt76;

// Intel iwlwifi PCIe Wi-Fi. Promoted out of the former `src/iwlwifi/` module
// into the standalone dual-build crate `narf-drivers-wireless-iwlwifi` (see
// drivers/wireless/iwlwifi/). Its inner driver module is re-exported here as
// `iwlwifi` so existing `crate::iwlwifi::{mlme,wpa,rekey,mac_ctx,…}` and
// `iwlwifi::register()` references keep resolving.
pub use narf_drivers_wireless_iwlwifi::iwlwifi;

// Realtek RTW88/RTW89 PCIe Wi-Fi. Promoted out of the former
// `src/{rtw88,rtw89}/` modules into the standalone dual-build family crate
// `narf-drivers-wireless-rtw` (see drivers/wireless/rtw/). Inner driver
// modules re-exported here as `rtw88`/`rtw89` so existing
// `crate::rtw88::{pci_park,efuse,regs,…}` / `crate::rtw89::{…}` and
// `rtw88::register()` / `rtw89::register()` references keep resolving.
pub use narf_drivers_wireless_rtw::{rtw88, rtw89};

#[cfg(feature = "kernel-test")]
mod e2e_tests;

#[cfg(feature = "kernel-test")]
mod firmware_asset_tests;

use narf_init::{InitResult, Stage};

/// Async system-PM bridge for the mt76 crate (`mt7921_pci_suspend` /
/// `mt7921_pci_resume` firmware exchanges run before/after the
/// interrupt-gated device fan-out).
struct Mt76SystemPm;

impl narf_power::system_pm::AsyncSystemPm for Mt76SystemPm {
    fn prepare_suspend<'a>(&'a self) -> narf_power::system_pm::SystemPmFuture<'a> {
        self.prepare_suspend_target(narf_power::system_pm::SystemSleepState::S3)
    }

    fn prepare_suspend_target<'a>(
        &'a self,
        target: narf_power::system_pm::SystemSleepState,
    ) -> narf_power::system_pm::SystemPmFuture<'a> {
        alloc::boxed::Box::pin(async move {
            mt76::iface::system_prepare_suspend_for(target)
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
    // cfg80211's per-wiphy rfkill: every wiphy is one `wlan` radio of the
    // rfkill core, so `/dev/rfkill`, the sysfs class and the airplane key
    // block and unblock it.
    narf_wireless::rfkill::install(narf_wireless::rfkill::Backend {
        register: |name| {
            narf_drivers_platform::rfkill::register_radio_indexed(
                name,
                narf_drivers_platform::rfkill::RadioType::Wlan,
                narf_wireless::rfkill::set_soft_blocked,
            )
        },
        unregister: narf_drivers_platform::rfkill::unregister_radio,
    });
    // Register wireless drivers with the bus dispatcher.
    narf_init::register(Stage::Subsys, "iwlwifi", || {
        iwlwifi::register();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "mt76", || {
        mt76::register();
        // Actual S0Idle/S3 targets reach the retained mt76 wake owner.
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
        #[cfg(not(feature = "ath11k-module-only"))]
        ath11k::register();
        // ath11k.ko owns the PCI ids; the AHB binder stays built in.
        #[cfg(feature = "ath11k-module-only")]
        ath11k::ahb_probe::register_dt_driver();
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
        // With `ath9k-module-only`, ath9k.ko owns every ath9k PCI id.
        #[cfg(not(feature = "ath9k-module-only"))]
        ath9k::register();
        InitResult::Ok
    });
}
