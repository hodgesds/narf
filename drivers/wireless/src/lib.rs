#![no_std]

extern crate alloc;

pub mod ath10k;
pub mod ath11k;
pub mod brcmfmac;
pub mod cyw43439;
pub mod iwlwifi;
pub mod mt7921;
pub mod rtw88;
pub mod rtw89;

pub fn register_initcalls() {
    // Register wireless drivers with the bus dispatcher.
    iwlwifi::register();
    mt7921::register();
    cyw43439::register();
    rtw88::register();
    rtw89::register();
    brcmfmac::register();
    ath11k::register();
    ath10k::register();
}
