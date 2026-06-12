//! VirtIO GPIO adapter driver.
//!
//! Exposes a GPIO controller over the VirtIO transport, allowing
//! virtual machines to toggle pins and receive interrupts.
//!
//! References: `linux/drivers/gpio/gpio-virtio.c`

extern crate alloc;

pub fn register_pci_driver() {
    // Placeholder: VirtIO device ID 41
}
