#![no_std]

extern crate alloc;

pub mod cyw43439;
pub mod iwlwifi;
pub mod mt7921;
pub mod rtw88;

pub fn register_initcalls() {
    // Register wireless drivers with the bus dispatcher.
    iwlwifi::register();
    mt7921::register();
    cyw43439::register();
    rtw88::register();
}
