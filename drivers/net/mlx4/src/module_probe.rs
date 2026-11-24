//! Loadable-module registration path for mlx4.
//!
//! Registration-only: the probe thunk returns `-ENOSYS` because the device
//! datapath ABI is not yet exported to modules. The built-in build registers
//! the full id table and drives the device; this registers the primary
//! ConnectX-3 id as the module-build proof. See `narf-drivers-net-e1000` for
//! the rationale and `narf-drivers-net-mlx5` for the identical sibling shape.

const VENDOR: u16 = 0x15B3;
/// ConnectX-3 (MT27500).
const DEVICE: u16 = 0x1003;

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
    // -ENOSYS: module build carries no datapath yet.
    -38
}

pub fn register() {
    const NAME: &[u8] = b"mlx4-connectx3";
    // SAFETY: `NAME` is 'static; `probe_c` is a valid extern "C" fn.
    unsafe {
        narf_register_pci_driver(NAME.as_ptr(), NAME.len(), VENDOR, DEVICE, probe_c as usize);
    }
}
