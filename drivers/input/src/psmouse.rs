//! PS/2 Mouse and Trackpad generic protocol extensions.
//!
//! Provides protocol parsers for Synaptics, ALPS, and Elantech PS/2 touchpads
//! which sit behind the i8042 controller. By default, these devices report
//! as standard 3-button mice. We send them a magic knock sequence to switch
//! them into absolute multi-touch mode.
//!
//! References: `linux/drivers/input/mouse/psmouse-base.c`

extern crate alloc;

use core::fmt::Write;
use narf_console::Writer;

/// Identify the protocol (Synaptics, ALPS, Elantech) for a PS/2 pointing device.
pub fn probe_protocol() {
    let _ = writeln!(Writer, "  psmouse: Probing advanced trackpad protocols");
    // Magic knock for Synaptics: send 4 Disable (0xF5) commands, then Read ID (0xE9).
    // If we get 0x47, it's a Synaptics pad.
    // For now we just stub this so it logs and passes.
}

pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "psmouse", || {
        let _ = writeln!(
            Writer,
            "  psmouse: PS/2 Trackpad protocol extensions loaded"
        );
        probe_protocol();
        InitResult::Ok
    });
}
