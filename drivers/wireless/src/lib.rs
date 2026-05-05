#![no_std]

extern crate alloc;

pub mod mt7921;

pub fn register_initcalls() {
    // Register wireless drivers with the bus dispatcher.
    mt7921::register();
}
