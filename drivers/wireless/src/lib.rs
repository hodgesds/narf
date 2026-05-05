#![no_std]

extern crate alloc;

pub mod mt7921;

use narf_drivers::core::{Driver, DriverEnv, DriverError};
use narf_bus::{register_driver, MatchEntry};
use async_trait::async_trait;

pub fn init() {
    // Register wireless drivers with the bus dispatcher.
    mt7921::register();
}
