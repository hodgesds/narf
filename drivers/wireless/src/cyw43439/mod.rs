//! Infineon (Cypress) CYW43439 Wi-Fi 4 + Bluetooth 5 combo —
//! clean-room driver.
//!
//! Spec: `drivers/wireless/specification/cyw43439.md`.
//!
//! ## Why this part is the bright spot
//!
//! Unlike the iwlwifi / mt76xx / brcmfmac flagships, CYW43439's
//! host interface is **fully publicly documented** by Infineon:
//!
//! - **CYW43439 datasheet, Rev. 03 (88-page public PDF)** —
//!   pinout, gSPI/SDIO host-interface electrical and protocol, the
//!   F0/F1/F2 SDIO function model, the backplane access primitives
//!   (§6.5), and the chip-RAM upload procedure (§6.6).
//! - **AN232689 — Wi-Fi Software User Guide** — Infineon public
//!   application note, documents the IOCTL/IOVAR conventions a host
//!   driver speaks across the link.
//! - **SD Specifications, Part E1: SDIO Simplified Specification
//!   v3.00** — the SD Association's public spec for CMD52 / CMD53
//!   and the F0 CCCR layout.
//!   <https://www.sdcard.org/downloads/pls/>
//! - **Bluetooth Core 5.x HCI** — the BT side rides standard HCI
//!   framing through the same chip; we already have
//!   `narf-bluetooth`.
//!   <https://www.bluetooth.com/specifications/specs/core-specification/>
//!
//! The IOCTL/IOVAR command numbering used inside the firmware blob
//! is not in the datasheet, but is mirrored by two
//! permissively-licensed reference drivers explicitly written from
//! public docs and avoiding GPL Linux derivation:
//!
//! - **`soypat/cyw43439`** (MIT) — Go reference driver.
//! - **Embassy `cyw43`** (Apache-2.0 / MIT) — Rust async driver in
//!   wide use on Raspberry Pi Pico W (CYW43439 over PIO+SPI).
//!
//! Consuming the *interface conventions* documented in those repos
//! is clean-room compatible. **No GPL `brcmfmac` / `bcmdhd` source
//! consulted.**
//!
//! ## Stage progression
//!
//! - **Stage 1 (landed)** — module + spec presence, public part-
//!   number / firmware-name constants, SDIO function-model
//!   constants.
//! - **Stage 2 (this commit)** — transport-codec layer:
//!   - [`gspi`] — 32-bit gSPI command-word codec (datasheet §6.4).
//!   - [`sdio`] — CMD52 / CMD53 argument-word codec + F0/F1
//!     register addresses (SDIO Simplified Spec + datasheet §6.5).
//!   - [`backplane`] — F1 window paging codec (datasheet §6.5).
//!   - [`transport`] — the [`Transport`](transport::Transport) trait
//!     gSPI / SDIO host adapters implement.
//! - **Stage 3 (future)** — chip-RAM firmware staging: load
//!   `43439A0.bin` to the SOC-RAM core, push `43439A0.txt` NVRAM,
//!   deassert WLAN_ARM reset.
//! - **Stage 4 (future)** — IOCTL / IOVAR codec, with each command
//!   number annotated by its public-doc justification before it
//!   lands.

#![allow(dead_code)]

extern crate alloc;

pub mod backplane;
pub mod chipclk;
pub mod core;
pub mod events;
pub mod firmware;
pub mod gspi;
pub mod ioctl;
pub mod iovar;
pub mod sdio;
pub mod sdio_bridge;
pub mod sdpcm;
pub mod transport;

pub use firmware::{build_nvram_blob, FirmwareLoader, LoadError, LoadStep};
pub use ioctl::{build_request, parse_response, Direction, ParseError, Response};
pub use iovar::{build_region_cmd, COUNTRY_WORLDWIDE, VAR_COUNTRY, WL_COUNTRY_T_SIZE};
pub use transport::{Function, Transport, TransportError};

// ── Hardware identification (public datasheet cover sheet) ─────────

/// Vendor as reported on Infineon's public collateral.
pub const CYW43439_VENDOR_NAME: &str = "Infineon (Cypress)";
/// The Infineon part number this driver covers.
pub const CYW43439_PART_NUMBER: &str = "CYW43439";

/// Firmware blob filenames as Infineon ships them in the FCC
/// fileset. The blobs themselves are vendor-distributed binaries
/// the boot path supplies through the firmware-cap surface.
pub const FIRMWARE_FILENAME: &str = "43439A0.bin";
pub const NVRAM_FILENAME: &str = "43439A0.txt";
pub const CLM_BLOB_FILENAME: &str = "43439A0_clm.bin";

// ── SDIO bus identification ────────────────────────────────────────
//
// The CYW43439 presents as an SDIO combo device. These are the
// Function 0 CCCR-reported vendor / device IDs as listed in the
// Broadcom/Cypress driver trees and the Raspberry Pi Pico W schematic.

/// Broadcom / Infineon SDIO vendor ID (matches the vendor field
/// in the CCCR SDIO Vendor Specific bytes or the card function
/// product identifier register per SDIO Spec Part E1 §6.9).
pub const CYW43439_SDIO_VENDOR: u16 = 0x02D0;

/// CYW43439 SDIO device/product ID.
pub const CYW43439_SDIO_DEVICE: u16 = 0xA9A6;

/// Stage-1 register stub — kept so existing call-sites (e.g. the
/// wireless crate's `register_initcalls`) link cleanly. The chip
/// is not exposed on PCI; the eventual integration hooks into the
/// gSPI / SDIO transport adapters described in [`transport`].
pub fn register() {
    // Intentional no-op for now: the bus through which the chip is
    // reached (gSPI on a microcontroller pin set, or SDIO on a
    // Raspberry Pi) is not part of the PCI dispatch table. Once the
    // SDIO host-controller interface lands, this will register a
    // CYW43439 SDIO match instead.
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_firmware_filenames_present() -> TestResult {
        // Cheap sanity check: the public FCC fileset always uses
        // these three names. Regressions here typically mean
        // someone patched the constants without updating the
        // loader expectations.
        if !FIRMWARE_FILENAME.ends_with(".bin") {
            return TestResult::Fail("firmware filename should end .bin");
        }
        if !NVRAM_FILENAME.ends_with(".txt") {
            return TestResult::Fail("NVRAM filename should end .txt");
        }
        if !CLM_BLOB_FILENAME.ends_with(".bin") {
            return TestResult::Fail("CLM filename should end .bin");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439",
        smoke_firmware_filenames_present
    );

    fn smoke_cyw43439_probe_sdio_id_match() -> TestResult {
        // Verify the vendor / device IDs match those documented in
        // the Broadcom Cypress driver trees and the RPi Pico W
        // schematic for the CYW43439 SDIO combo chip.
        if CYW43439_SDIO_VENDOR != 0x02D0 {
            return TestResult::Fail("SDIO vendor should be 0x02D0 (Broadcom/Infineon)");
        }
        if CYW43439_SDIO_DEVICE != 0xA9A6 {
            return TestResult::Fail("SDIO device should be 0xA9A6 (CYW43439)");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439",
        smoke_cyw43439_probe_sdio_id_match
    );

    fn smoke_cyw43439_sdpcm_region_cmd_encode() -> TestResult {
        // build_region_cmd("XX") must produce a well-formed IOVAR SET
        // frame whose country-value payload encodes wl_country_t as:
        //   bytes 0-1 = 'X','X'
        //   bytes 2-3 = 0,0  (NUL pad)
        //   bytes 4-7 = 0,0,0,0  (revision = 0)
        //   bytes 8-9 = 'X','X'  (ccode)
        //   bytes 10-11 = 0,0  (NUL pad)
        use super::ioctl::WLC_SET_VAR;
        use super::sdpcm::{BcdcHeader, BCDC_HEADER_LEN, HW_HEADER_LEN, SW_HEADER_LEN};

        let frame = match build_region_cmd(1, 0, 0, b"XX") {
            Some(f) => f,
            None => return TestResult::Fail("build_region_cmd returned None for valid code"),
        };

        // Decode the BCDC header.
        let bcdc_start = HW_HEADER_LEN + SW_HEADER_LEN;
        if frame.len() < bcdc_start + BCDC_HEADER_LEN {
            return TestResult::Fail("frame too short for BCDC header");
        }
        let bcdc = match BcdcHeader::decode(&frame[bcdc_start..]) {
            Ok(b) => b,
            Err(_) => return TestResult::Fail("BCDC decode failed"),
        };
        if bcdc.cmd != WLC_SET_VAR {
            return TestResult::Fail("region cmd must use WLC_SET_VAR");
        }
        if !bcdc.is_set() {
            return TestResult::Fail("SET flag must be set");
        }

        // Locate the payload: after BCDC header.
        let payload_start = bcdc_start + BCDC_HEADER_LEN;
        // Payload = "country\0" (8 bytes) + wl_country_t (12 bytes).
        let var_name = b"country\x00";
        let expected_payload_len = var_name.len() + WL_COUNTRY_T_SIZE;
        if (bcdc.len as usize) < expected_payload_len {
            return TestResult::Fail("BCDC payload length too short for country iovar");
        }
        // Verify var name.
        if &frame[payload_start..payload_start + var_name.len()] != var_name {
            return TestResult::Fail("country var name not at payload start");
        }
        // Verify wl_country_t.
        let ct = &frame
            [payload_start + var_name.len()..payload_start + var_name.len() + WL_COUNTRY_T_SIZE];
        if ct[0] != b'X' || ct[1] != b'X' {
            return TestResult::Fail("country abbreviation bytes 0-1 must be 'XX'");
        }
        if ct[2] != 0 || ct[3] != 0 {
            return TestResult::Fail("country abbreviation NUL pad wrong");
        }
        let rev = u32::from_le_bytes([ct[4], ct[5], ct[6], ct[7]]);
        if rev != 0 {
            return TestResult::Fail("country revision must be 0 for worldwide");
        }
        if ct[8] != b'X' || ct[9] != b'X' {
            return TestResult::Fail("ccode bytes 8-9 must be 'XX'");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439",
        smoke_cyw43439_sdpcm_region_cmd_encode
    );
}
