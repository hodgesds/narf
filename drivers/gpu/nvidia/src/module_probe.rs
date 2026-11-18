//! Loadable-module registration path for the NVIDIA driver
//! (registration-only).
//!
//! The probe thunk returns `-ENOSYS`: the GPU datapath ABI (BAR
//! mapping, DMA, GSP firmware handoff) is not yet exported to loadable
//! modules, so the `.ko` proves it builds, loads, and registers its PCI
//! match through the KSYMTAB export. The match is the Turing TU102
//! (RTX 2080 Ti), the card the GSP display stack targets. See
//! `narf-drivers-net-e1000`.

/// `NVIDIA_VENDOR`.
const VENDOR: u16 = 0x10de;
/// `TU102_RTX_2080_TI` — representative GSP-class Turing device.
const DEVICE: u16 = 0x1e04;

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
    // -ENOSYS: datapath ABI not yet exported to modules.
    -38
}

pub fn register() {
    const NAME: &[u8] = b"nvidia";
    // SAFETY: `NAME` is 'static; `probe_c` is a valid extern "C" fn.
    unsafe {
        narf_register_pci_driver(NAME.as_ptr(), NAME.len(), VENDOR, DEVICE, probe_c as usize);
    }
}
