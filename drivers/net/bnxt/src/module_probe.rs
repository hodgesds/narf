//! Loadable-module registration path for bnxt.
//!
//! Registration-only: the probe thunk returns `-ENOSYS` because the device
//! datapath is explicitly not implemented (issue #798 — deferred out of
//! desktop scope), not merely unexported. The built-in build registers the
//! full id table and declines the same way via `ProbeError::NotForThisDriver`;
//! this registers the primary id as the module-build proof. See
//! `narf-drivers-net-e1000` for the rationale.

const VENDOR: u16 = 0x14E4;
const DEVICE: u16 = 0x16D7;

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
    const NAME: &[u8] = b"bnxt-bcm57414";
    // SAFETY: `NAME` is 'static; `probe_c` is a valid extern "C" fn.
    unsafe {
        narf_register_pci_driver(NAME.as_ptr(), NAME.len(), VENDOR, DEVICE, probe_c as usize);
    }
}
