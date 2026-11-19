//! AMD Audio Co-Processor — dual-build (built-in or loadable `.ko`).
//!
//! The driver body compiles only for the built-in build: ACP 3.x and 6.3 PDM
//! DMIC capture ([`acp63`], [`acp3x`], the [`acp6`] compatibility surface),
//! and the ACP 6.3 SoundWire manager ([`acp63_sdw`], [`acp63_sdw_dma`]) with
//! its bus core ([`soundwire`]) and RT711 / RT1316 codecs. `narf-audio`
//! re-exports every module.
//!
//! The `module` build registers the shared ACP PCI id (1022:15E2; the PCI
//! revision selects the register map at probe) through the
//! `narf_register_pci_driver` KSYMTAB export — registration-only until the
//! device datapath ABI covers a PCM device. See `narf-drivers-net-tg3` for
//! the registration-only shape.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

use narf_driver_macros::narf_driver;

#[cfg(feature = "builtin")]
extern crate alloc;

#[cfg(feature = "builtin")]
#[allow(unused_imports)]
use narf_drivers_audio_core::{native_firmware, native_irq, native_pci, native_pcm};

#[cfg(feature = "builtin")]
pub mod acp3x;
#[cfg(feature = "builtin")]
pub mod acp6;
#[cfg(feature = "builtin")]
pub mod acp63;
#[cfg(feature = "builtin")]
pub mod acp63_sdw;
#[cfg(feature = "builtin")]
pub mod acp63_sdw_dma;
#[cfg(feature = "builtin")]
pub mod soundwire;
#[cfg(feature = "builtin")]
pub mod soundwire_rt1316;
#[cfg(feature = "builtin")]
pub mod soundwire_rt711;

narf_driver! {
    name: "acp",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "AMD Audio Co-Processor (PDM + SoundWire)",
        target_domain: "scratch",
    },
    register: do_register,
}

/// Built-in: the PDM probe first, then the SoundWire manager, which wins
/// only for the pin configurations the PDM probe declines (`probe_all`
/// tries candidates by specificity until one binds; audio spec §3.2).
#[cfg(feature = "builtin")]
fn do_register() {
    acp6::register_pci_driver();
    acp63_sdw::register_pci_driver();
}

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}

/// Loadable-module registration path (registration-only; `-ENOSYS` probe).
/// Links only the `narf_register_pci_driver` KSYMTAB import.
#[cfg(feature = "module")]
mod module_probe {
    /// AMD.
    const VENDOR: u16 = 0x1022;
    /// `acp63::DEVICE`: shared by ACP 3.x (Renoir) and 6.3 (Phoenix).
    const DEVICE: u16 = 0x15E2;
    const NAME: &[u8] = b"acp-module";

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

    pub fn register() {
        // SAFETY: `NAME` is 'static; `probe_c` is a valid extern "C" fn.
        // The loader unregisters the match before unmapping this image.
        unsafe {
            narf_register_pci_driver(NAME.as_ptr(), NAME.len(), VENDOR, DEVICE, probe_c as usize);
        }
    }
}
