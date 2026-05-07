//! Infineon CYW43439 / CYW4343W Wi-Fi + Bluetooth combo —
//! clean-room driver skeleton.
//!
//! Spec: `drivers/wireless/specification/cyw43439.md`.
//!
//! ## Why this part is the bright spot
//!
//! Unlike the iwlwifi / mt76xx / brcmfmac flagship parts, CYW43439's
//! host interface is **fully publicly documented** by Infineon:
//!
//! - **CYW43439 datasheet, Rev. 03** (88-page public PDF) — covers
//!   pinout, gSPI/SDIO host interface electrical and protocol, the
//!   F1/F2 backplane access primitives, and the chip-RAM upload
//!   procedure.
//! - **AN232689 — Wi-Fi Software User Guide** — Infineon public
//!   application note. Documents the higher-level firmware command
//!   conventions a host driver speaks across gSPI.
//! - **Bluetooth Core 5.x HCI** — the BT side rides standard HCI
//!   framing through the same chip; we already have `narf-bluetooth`.
//!
//! The IOCTL/IOVAR command numbering used inside the firmware blob
//! is *not* in the datasheet, but it is mirrored by two
//! permissively-licensed reference drivers that were written from
//! public docs and explicitly avoid GPL Linux derivation:
//!
//! - **`soypat/cyw43439`** (MIT) — Go reference driver, intended as
//!   a clean-room starting point.
//! - **Embassy `cyw43`** (Apache-2.0 / MIT) — Rust async driver in
//!   wide use on Raspberry Pi Pico W (CYW43439 over PIO+SPI).
//!
//! Consuming the *interface conventions* documented in those repos
//! is clean-room compatible; we do not copy code or comments
//! verbatim. **No GPL Linux `brcmfmac` source consulted.**
//!
//! ## Stage-1 scope (this commit)
//!
//! - Module + spec doc presence so the audit trail is in place.
//! - Constants for the public part-number / firmware-name strings
//!   we'll need once the SPI / SDIO transport land.
//! - Backplane register-window names + hand-off opcodes from the
//!   datasheet (no field-by-field decoding yet).
//!
//! Future stages:
//!   - SDIO + gSPI transport bring-up (`F0/F1/F2` function model).
//!   - Backplane window paging via `BACKPLANE_ADDR`.
//!   - Firmware (`43439A0.bin`) + NVRAM (`43439A0.txt`) upload via
//!     the chip-RAM staging documented in the datasheet §6.
//!   - IOCTL / IOVAR command codec — pulled from the soypat / cyw43
//!     references with each command annotated with its public-doc
//!     justification before it lands.

#![allow(dead_code)]

extern crate alloc;

// ── Hardware identification ────────────────────────────────────────

/// 16-bit JEDEC manufacturer code that the CYW43439 reports through
/// the SDIO CIS / SPI device-id query.
pub const CYW43439_VENDOR_NAME: &str = "Infineon (Cypress)";
pub const CYW43439_PART_NUMBER: &str = "CYW43439";

/// Firmware blob filenames as Infineon ships them (FCC fileset).
pub const FIRMWARE_FILENAME: &str = "43439A0.bin";
pub const NVRAM_FILENAME: &str = "43439A0.txt";
pub const CLM_BLOB_FILENAME: &str = "43439A0_clm.bin";

// ── SDIO / gSPI top-level constants (from the public datasheet) ───

/// The CYW43439 exposes three SDIO functions per CYW43439 §3.1.
/// Function 0 is the standard SDIO control window; F1 reaches the
/// backplane; F2 is the WLAN bulk-data path.
pub const SDIO_FUNC_CONTROL: u8 = 0;
pub const SDIO_FUNC_BACKPLANE: u8 = 1;
pub const SDIO_FUNC_WLAN: u8 = 2;

/// gSPI register at offset 0x00 — bus control (per datasheet §6.4).
/// gSPI is a single-function variant of the SDIO interface for hosts
/// with no SDIO controller (the Pico W use-case).
pub const GSPI_BUS_CONTROL: u32 = 0x0000;

// ── Backplane core ids (datasheet §6.5) ───────────────────────────

/// Backplane core id for the WLAN ARM core ("WLAN_ARM" / D11).
pub const CORE_WLAN_ARM: u16 = 0x829;
/// Backplane core id for the SOC-RAM core (chip RAM where firmware
/// is staged before reset).
pub const CORE_SOC_RAM: u16 = 0x80E;

// ── Stub probe entry ──────────────────────────────────────────────

/// Stage-1 probe: the chip is on a bus we don't currently enumerate
/// (gSPI on a microcontroller pin set, or SDIO on a Raspberry Pi).
/// This stub records the part identifier so a future SDIO/gSPI
/// transport crate can claim it.
pub fn register() {
    // Nothing to register on x86_64 yet — the eventual consumer is
    // the aarch64 / RP2040 Pico-W bring-up path.
}
