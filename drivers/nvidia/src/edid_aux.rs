//! EDID read over DP AUX (DDC/CI-style).
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/nouveau_connector.c`**
//!   `nouveau_connector_get_edid` — re-probes EDID after HPD.
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/dispnv50/disp.c`**
//!   `nv50_disp_dp_aux_xfer` — AUX-channel transactions.
//! - Linux's `drm_edid.c` for the 128-byte EDID v1.4 layout.
//!
//! ## Concept
//!
//! Over DP/eDP, EDID lives on I²C address 0x50 reached via the
//! AUX channel's I²C-over-AUX transport. The host writes a
//! "segment select" to 0x30 (for blocks past the first 256
//! bytes) then reads 128 bytes per block from 0x50.

#![allow(dead_code)]

use crate::disp::nv50::{aux_header, AuxCommand};

/// I²C address of the EDID EEPROM (DDC2B).
pub const DDC_ADDR_EDID: u32 = 0x50;
/// I²C address of the segment register for EDID 2.0+ (E-EDID).
pub const DDC_ADDR_SEGMENT: u32 = 0x30;

/// Size of one EDID block.
pub const EDID_BLOCK_SIZE: usize = 128;

/// Build the AUX header for "read N bytes from EDID at offset
/// `byte_offset`". Caller does the actual AUX transaction; we
/// only encode the command framing.
pub fn aux_header_for_edid_read(byte_offset: u8, len: u8) -> u32 {
    // I²C-over-AUX read at address 0x50.
    // The driver typically writes the byte_offset to register
    // 0x50 first (i.e. an I2C write of one byte), then reads.
    // This helper produces the *read* phase header.
    let _ = byte_offset; // address-latch is a separate AUX call
    aux_header(AuxCommand::I2cRead, DDC_ADDR_EDID, len)
}

/// Build the AUX header for the segment-select write (E-EDID, > 256
/// bytes). Each AUX-write writes one byte to address 0x30.
pub fn aux_header_for_segment_select() -> u32 {
    aux_header(AuxCommand::I2cWrite, DDC_ADDR_SEGMENT, 1)
}

/// Validate an EDID v1.x block: 8-byte signature (00 FF…00),
/// version + checksum.
///
/// Cite Linux `drm_edid.c::edid_block_valid`.
pub fn validate_block(block: &[u8; EDID_BLOCK_SIZE]) -> Result<(), EdidError> {
    const HEADER: [u8; 8] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];
    if block[..8] != HEADER {
        return Err(EdidError::BadSignature);
    }
    // Sum of all 128 bytes must be 0 mod 256.
    let sum = block.iter().fold(0u8, |a, b| a.wrapping_add(*b));
    if sum != 0 {
        return Err(EdidError::Checksum);
    }
    Ok(())
}

/// EDID block validation errors.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EdidError {
    BadSignature,
    Checksum,
}
