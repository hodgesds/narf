//! MT7921 MCU (firmware-loader + command mailbox) scaffold.
//!
//! Stage-1 wires up the patch + RAM-code blob resolution against
//! `narf-firmware` and exposes a single `load_firmware_stub` entry
//! that Stage-2 will lift to a real patch-apply path once the DMA
//! rings are present.
//!
//! Reference: Linux `drivers/net/wireless/mediatek/mt76/mt76_connac_mcu.c`:
//!
//!   - `mt76_connac2_load_patch` (~L2900) — sends the ROM-patch blob
//!     to the MCU one chunk at a time over the FWDL TX queue.
//!   - `mt76_connac2_load_ram` (~L3050) — same for the RAM-code blob.
//!   - `mt76_connac_mcu_get_eeprom` (~L1400) — EFUSE read via the
//!     MCU mailbox (`MCU_EXT_CMD_EFUSE_ACCESS`), reading one 16-byte
//!     block at a time and assembling the logical EFUSE map.
//!
//! All three sit on top of the WFDMA0 TX/RX rings (queues `FWDL` +
//! `MCU_WM` in `mt7921.h::enum mt7921_txq_id`). Stage-1 stops at the
//! firmware-resolve step and returns `NotImplemented` because no
//! ring infrastructure exists yet.

#![allow(dead_code)]

use core::fmt::Write as _;

use narf_bus::MmioRegion;

use super::pci::firmware_blobs_for;
use super::regs::*;

/// Errors raised by the MCU path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum McuError {
    /// One of the required firmware blobs (`patch` or `ram_code`)
    /// is not registered in `narf-firmware`. Surface this as a
    /// non-fatal probe outcome: the device still gets bound, just
    /// without an alive MCU.
    BlobMissing,
    /// MCU mailbox poll wedged. Always coupled with a timeout in
    /// the caller — this is the typed error you get back when the
    /// chip never asserts the response-ready bit.
    Timeout,
    /// The MCU command path is still unimplemented (no DMA rings).
    /// Returned by all the actual command-issuing entry points so
    /// callers can degrade gracefully.
    NotImplemented,
}

/// Firmware-load orchestrator.
///
/// Resolves the (patch, ram_code) blob names for the matched device
/// id, attempts to open them through the trusted-loader authority,
/// and **stops** at the actual MCU patch-apply step — that path
/// needs the FWDL TX queue from Stage-2.
///
/// Returns `Ok(())` on the happy path where blobs are present (so
/// that probe knows it can attempt an EFUSE read) and `Err(McuError)`
/// when blobs are missing or the path is otherwise unimplemented.
///
/// # Safety
/// `mmio` is the live BAR0 region; driver-own already taken.
pub unsafe fn load_firmware_stub(_mmio: &MmioRegion, effective_did: u16) -> Result<(), McuError> {
    let (patch_name, ram_name) = firmware_blobs_for(effective_did);

    let _ = writeln!(
        narf_console::Writer,
        "  mt7921: firmware resolve patch={} ram={}",
        patch_name,
        ram_name,
    );

    // Try to open both blobs via the trusted-loader authority.
    // Either both must be present or we treat this as "no firmware
    // available" — patching half the MCU bricks it.
    let auth = match narf_firmware::trusted_loader_authority() {
        Some(a) => a.derive().ok(),
        None => None,
    };
    let auth = match auth {
        Some(a) => a,
        None => {
            let _ = writeln!(
                narf_console::Writer,
                "  mt7921: no trusted-loader authority — skipping firmware load"
            );
            return Err(McuError::BlobMissing);
        }
    };

    let patch_present = narf_firmware::open(patch_name, &auth).is_ok();
    let ram_present = narf_firmware::open(ram_name, &auth).is_ok();
    if !(patch_present && ram_present) {
        let _ = writeln!(
            narf_console::Writer,
            "  mt7921: firmware missing (patch={}, ram={})",
            patch_present,
            ram_present,
        );
        return Err(McuError::BlobMissing);
    }

    // Both blobs are resolvable. Stage-2 lifts this to a real
    // `mt76_connac2_load_patch` + `mt76_connac2_load_ram` flow over
    // the FWDL queue.
    let _ = writeln!(
        narf_console::Writer,
        "  mt7921: firmware blobs present — patch-apply deferred to Stage-2"
    );
    Err(McuError::NotImplemented)
}

/// Read the 6-byte factory MAC out of EFUSE.
///
/// Linux reaches EFUSE via the MCU mailbox: it issues
/// `MCU_EXT_CMD_EFUSE_ACCESS` for a 16-byte block at the desired
/// logical offset, then reads the response over the MCU event ring.
/// Both legs require the firmware to be alive, so this function is
/// strictly post-`load_firmware_stub`.
///
/// # Safety
/// BAR0 mapped + owned; firmware loaded.
pub unsafe fn read_efuse_mac(_mmio: &MmioRegion) -> Result<[u8; MAC_ADDR_LEN], McuError> {
    // Stage-1 stops here: no DMA rings, no MCU command path. The
    // probe orchestrator wraps this in an `if firmware_outcome.is_ok()`
    // guard so we only reach here when the firmware actually loaded
    // — which Stage-1 never does.
    Err(McuError::NotImplemented)
}

/// Build an `MCU_EXT_CMD` header byte for the given opcode. Returned
/// for the encoder unit tests; the real TX path lands in Stage-2.
pub const fn mcu_ext_cmd_header(opcode: u8) -> u8 {
    // Linux `mt76_connac2_mcu_set_cmd` packs the EXT opcode into the
    // first byte of the command payload. We model the same layout
    // so the Stage-2 wiring is just a copy-paste of the encoder.
    opcode
}

/// Length of the EFUSE per-MCU-command response block. Linux reads
/// 16 bytes at a time via `mt76_connac_mcu_get_eeprom`.
pub const EFUSE_BLOCK_LEN: usize = 16;
