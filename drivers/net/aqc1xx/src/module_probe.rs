//! Loadable-module registration path for the AQC1xx family.
//!
//! Registration-only: the probe thunk returns `-ENOSYS` because the device
//! datapath ABI is not yet exported. The built-in build registers the
//! full AQC113-family id table; this registers one representative id
//! (AQC113) as the module-build proof.

unsafe extern "C" {
    fn narf_register_pci_driver(
        name: *const u8,
        name_len: usize,
        vendor: u16,
        device: u16,
        probe: usize,
    ) -> i32;
}

extern "C" fn probe_c(_dev_token: u64, _reserved: u64) -> i32 {
    -38
}

/// `(vendor, device, name)` representative: AQC113.
const IDS: &[(u16, u16, &[u8])] = &[(0x1D6A, 0x04C0, b"aqc113")];

pub fn register() {
    for &(vendor, device, name) in IDS {
        // SAFETY: each `name` is a 'static byte string; `probe_c` is a valid
        // extern "C" fn.
        unsafe {
            narf_register_pci_driver(name.as_ptr(), name.len(), vendor, device, probe_c as usize);
        }
    }
}
