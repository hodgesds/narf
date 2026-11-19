//! Loadable-module registration path for the HD Audio controller driver.
//!
//! Registration-only: the probe thunk returns `-ENOSYS` because the device
//! datapath ABI does not yet cover a PCM device. It registers every id in
//! [`crate::ids`] — the same table the built-in driver binds — so the two
//! builds cannot drift. See `narf-drivers-net-tg3` for the registration-only
//! shape.
//!
//! A module build links ONLY the `narf_register_pci_driver` KSYMTAB import —
//! no kernel crates — so the `.ko`'s undefined-symbol set stays within the
//! exported ABI (xtask's `nm -u` gate enforces it).

use crate::ids::{HDA_AMD_RADEON_VENDOR, HDA_ATI_HDMI_NS_DEVICES, HDA_PCI_IDS};

const ATI_HDMI_NAME: &str = "hda-ati-hdmi";

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
    // -ENOSYS: the PCM device datapath ABI is not yet exported.
    -38
}

fn register_one(name: &'static str, vendor: u16, device: u16) {
    // SAFETY: `name` is 'static; `probe_c` is a valid extern "C" fn.
    // The loader unregisters every match before unmapping this image.
    unsafe {
        narf_register_pci_driver(name.as_ptr(), name.len(), vendor, device, probe_c as usize);
    }
}

pub fn register() {
    for &(name, vendor, device) in HDA_PCI_IDS {
        register_one(name, vendor, device);
    }
    for &device in HDA_ATI_HDMI_NS_DEVICES {
        register_one(ATI_HDMI_NAME, HDA_AMD_RADEON_VENDOR, device);
    }
}
