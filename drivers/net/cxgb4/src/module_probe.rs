//! Loadable-module registration path for cxgb4.
//!
//! Refusal-only (issue #799): cxgb4 is explicitly not implemented —
//! the Chelsio T4/T5/T6 datapath is out of this program's desktop
//! scope — so the probe thunk returns `-ENOSYS` for every device.
//! This registers the primary id (`0x4401`) as the module-build
//! proof; the built-in build registers a vendor-wide refusal match.
//! See `narf-drivers-net-e1000` for the rationale.

const VENDOR: u16 = 0x1425;
const DEVICE: u16 = 0x4401;

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
    const NAME: &[u8] = b"cxgb4-t4";
    // SAFETY: `NAME` is 'static; `probe_c` is a valid extern "C" fn.
    unsafe {
        narf_register_pci_driver(NAME.as_ptr(), NAME.len(), VENDOR, DEVICE, probe_c as usize);
    }
}
