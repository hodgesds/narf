//! VirtIO Persistent Memory (pmem) driver.
//!
//! Exposes a persistent memory region over the VirtIO transport,
//! allowing virtual machines to use DAX (Direct Access) nvdimm regions.
//!
//! References: `linux/drivers/nvdimm/virtio_pmem.c`

extern crate alloc;

/// Register the VirtIO pmem driver.
pub fn register_pci_driver() {
    // Placeholder: VirtIO device ID 27
}
