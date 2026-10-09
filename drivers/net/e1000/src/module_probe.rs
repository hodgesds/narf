//! Loadable-module registration path for e1000.
//!
//! Registration-only: the probe thunk returns `-ENOSYS` because the device
//! datapath ABI (BAR mapping, DMA pools, MSI-X, net-iface registration) is not
//! yet exported as stable C ABI. This proves the loadable-driver *mechanism* —
//! the `.ko` builds with only KSYMTAB-resolvable undefined symbols, loads,
//! fires `narf_module_init`, and lands a `PciMatch` in the bus registry — while
//! a bound, working NIC from a `.ko` waits on that larger ABI.
//!
//! The built-in build registers the full `SUPPORTED_DEVICE_IDS` table through
//! `e1000::register_pci_driver`; the module proof registers the primary id
//! (QEMU's 82540EM). Both are the same mechanism; only the id breadth differs.

/// Intel.
const E1000_VENDOR: u16 = 0x8086;
/// 82540EM — QEMU's default e1000.
const E1000_DEV_82540EM: u16 = 0x100E;

unsafe extern "C" {
    /// KSYMTAB export (`modules/src/kabi.rs`). `probe` is a `ModuleProbeFn`
    /// address: `extern "C" fn(dev_token: u64, reserved: u64) -> i32`.
    fn narf_register_pci_driver(
        name: *const u8,
        name_len: usize,
        vendor: u16,
        device: u16,
        probe: usize,
    ) -> i32;
}

/// C-ABI probe thunk. `-ENOSYS` until the datapath ABI is exported.
extern "C" fn probe_c(_dev_token: u64, _reserved: u64) -> i32 {
    -38
}

/// Register e1000's primary match through the kernel ABI.
pub fn register() {
    const NAME: &[u8] = b"e1000-82540em";
    // SAFETY: `NAME` is a 'static byte string; `probe_c` is a valid
    // `extern "C"` function for the module's lifetime.
    unsafe {
        narf_register_pci_driver(
            NAME.as_ptr(),
            NAME.len(),
            E1000_VENDOR,
            E1000_DEV_82540EM,
            probe_c as usize,
        );
    }
}
