//! Loadable-module registration path for mpt3sas (registration-only, -ENOSYS).
//! See narf-drivers-net-e1000. Built-in registers the full match; this
//! registers the primary id as the module-build proof.
const VENDOR: u16 = 0x1000;
const DEVICE: u16 = 0x0097;
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
    const NAME: &[u8] = b"mpt3sas-sas3008";
    // SAFETY: `NAME` is 'static; `probe_c` is a valid extern "C" fn.
    unsafe {
        narf_register_pci_driver(NAME.as_ptr(), NAME.len(), VENDOR, DEVICE, probe_c as usize);
    }
}
