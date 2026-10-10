//! Loadable-module registration path for bochs-display (registration-only).
//!
//! The probe thunk returns `-ENOSYS` because the device datapath ABI is not
//! yet exported; this proves the `.ko` builds, loads and registers its PCI
//! match through the KSYMTAB export. See `narf-drivers-net-e1000`.

const VENDOR: u16 = 0x1234;
const DEVICE: u16 = 0x1111;

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

pub fn register() {
    const NAME: &[u8] = b"bochs-display";
    // SAFETY: `NAME` is 'static; `probe_c` is a valid extern "C" fn.
    unsafe {
        narf_register_pci_driver(NAME.as_ptr(), NAME.len(), VENDOR, DEVICE, probe_c as usize);
    }
}
