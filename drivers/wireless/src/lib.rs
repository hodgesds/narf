#![no_std]

extern crate alloc;

pub mod ath10k;
pub mod ath11k;
pub mod ath9k;
pub mod brcmfmac;
pub mod cyw43439;
pub mod iwlwifi;
pub mod mt76;
pub mod mt7921;
pub mod rtl8xxxu;
pub mod rtlwifi;
pub mod rtw88;
pub mod rtw89;

#[cfg(feature = "kernel-test")]
mod e2e_tests;

use narf_init::{InitResult, Stage};

pub fn register_initcalls() {
    // Register wireless drivers with the bus dispatcher.
    narf_init::register(Stage::Subsys, "iwlwifi", || {
        iwlwifi::register();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "mt7921", || {
        mt7921::register();
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
    narf_init::register(Stage::Subsys, "mt76", || {
        mt76::register();
        InitResult::Ok
    });
}
