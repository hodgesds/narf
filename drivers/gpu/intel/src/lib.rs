//! Intel GPU PCI registration for the built-in driver and the NARF module ABI.
#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(feature = "module")]
#[path = "../../src/intel_gpu_pci_ids.rs"]
pub mod pci;

narf_driver_macros::narf_driver! {
    name: "intel_gpu",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "Intel GPU PCI registration",
        target_domain: "graphics",
    },
    register: register_driver => i32,
}

#[cfg(feature = "builtin")]
fn register_driver() -> i32 {
    narf_drivers_gpu::intel_gpu::register_pci_driver();
    0
}

#[cfg(feature = "module")]
unsafe extern "C" {
    fn narf_register_pci_driver(
        name: *const u8,
        name_len: usize,
        vendor: u16,
        device: u16,
        probe: usize,
    ) -> i32;
}

#[cfg(feature = "module")]
extern "C" fn probe(_device: u64, _reserved: u64) -> i32 {
    // The native KMS/GT services still live in the kernel. Leave the device
    // available to another matching driver until this image can drive it.
    -19 // ENODEV
}

#[cfg(feature = "module")]
fn register_driver() -> i32 {
    // A distinct name lets the built-in match coexist through load and unload.
    const NAME: &[u8] = b"intel-gpu-module";
    for (_, device) in pci::pci_matches() {
        // SAFETY: NAME and the C probe remain mapped through loader teardown.
        let status = unsafe {
            narf_register_pci_driver(
                NAME.as_ptr(),
                NAME.len(),
                pci::INTEL_VENDOR,
                device,
                probe as usize,
            )
        };
        if status != 0 {
            // Failed init makes the loader withdraw this owner's earlier rows.
            return status;
        }
    }
    0
}
